import asyncio, json, base64, datetime, warnings, sys, types
from typing import Optional, List, Dict, Any, Union

import binascii # for PyJWS error compatibility

# -- Load Rust Core

import os, importlib.util    

toke_rs = None

def _load_rust_module(path):
    spec = importlib.util.spec_from_file_location("toke", path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return None

for file in os.listdir(__file__.rsplit('/', 1)[0]):
    if file.startswith("toke") and file.endswith((".so", ".pyd", ".dylib", 'dll')):
        toke_rs = _load_rust_module(f'{__file__.rsplit('/', 1)[0]}/{file}')
        break
else:
    _dev_path_linux = "target/release/libtoke.so"
    if os.path.exists(_dev_path_linux):
        toke_rs = _load_rust_module(_dev_path_linux)
        print(f'## loaded from dev path: {_dev_path_linux}')

if toke_rs is None: 
    raise ImportError("Could not find toke Rust binary")

_rust_encode, _rust_decode, _rust_decode_complete = toke_rs.encode, toke_rs.decode, toke_rs.decode_complete

PyJWK = toke_rs.api_jwk.PyJWK
PyJWKSet = toke_rs.api_jwk.PyJWKSet
PyJWKError = toke_rs.api_jwk.PyJWKError
PyJWKSetError = toke_rs.api_jwk.PyJWKSetError

# --- Helpers 

def _prepare_token(token: Union[str, bytes]) -> str:

    if isinstance(token, bytes): return token.decode("utf-8")
    return token


def _merge_options(options: Optional[Dict], kwargs: Dict) -> Dict:
    '''  PyJWT treats options["verify_signature"] as the source of truth if it exists '''

    opts = options.copy() if options else {}

    if opts.get("verify_signature") is False:
        for k in ["verify_exp", "verify_nbf", "verify_iat", "verify_aud", "verify_iss", "verify_sub", "verify_jti"]:
            if k not in opts: opts[k] = False
    return opts


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:

    new_payload = payload.copy()
    for key in ["exp", "iat", "nbf"]:
        val = new_payload.get(key)
        if isinstance(val, datetime.datetime):
            if val.tzinfo is None: val = val.replace(tzinfo=datetime.timezone.utc)
            new_payload[key] = int(val.timestamp())
        elif isinstance(val, float): new_payload[key] = int(val)
    return new_payload


_sentinel = object()


# --- Sync methods 

def encode(payload: Dict[str, Any], key: Union[str, bytes] = b'', algorithm: str = "HS256", headers: Optional[Dict[str, Any]] = None, json_encoder: Optional[Any] = None) -> str:
    
    if "iss" in payload and not isinstance(payload["iss"], str): raise TypeError("Issuer must be a string")
    key = key or b''
    if json_encoder: payload = json.loads(json.dumps(payload, cls=json_encoder))
    payload = _normalize_payload(payload)
    return _rust_encode(payload, key, algorithm, headers)


def decode(token: str, key: Union[str, bytes] = None, algorithms: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None, audience: Optional[Union[str, List[str]]] = None, issuer: Optional[str] = None, subject: Optional[str] = None, verify: Any = _sentinel, content: Optional[bytes] = None, leeway: Union[int, float, datetime.timedelta] = 0, **kwargs) -> Dict[str, Any]:
    
    options = options or {}
    token = _prepare_token(token)
    
    # 1. Handle Verify Arg
    if verify is not _sentinel:
        warnings.warn("The 'verify' argument is deprecated.", DeprecationWarning, stacklevel=2)
        if "verify_signature" not in options:
            options["verify_signature"] = verify

    # 2. Merge Options
    options = _merge_options(options, kwargs)
    effective_verify = options.get("verify_signature", True)
    
    if isinstance(leeway, datetime.timedelta): leeway = leeway.total_seconds()
    leeway = int(leeway)
    options["leeway"] = leeway

    # 3. Validation
    if isinstance(audience, bytes): raise toke_rs.InvalidAudienceError("Invalid audience") 
    if audience is not None and not isinstance(audience, (str, list, tuple, set)): raise TypeError("audience must be a string, iterable or None")
    if effective_verify and not algorithms: raise toke_rs.DecodeError('It is required that you pass in a value for the "algorithms" argument when calling decode().')

    try:
        # Call Rust
        payload = _rust_decode(token, key, algorithms, options, audience, issuer, subject, effective_verify, content)
    except toke_rs.MissingRequiredClaimError as e:
        msg = str(e)
        if "Missing required claim: " in msg: e.claim = msg.split(": ")[1]
        raise e
    except toke_rs.DecodeError as e:
        msg = str(e)
        if "JSON error" in msg:
            if "expected value" in msg or "invalid type" in msg: raise toke_rs.DecodeError("Invalid payload string: must be a json object")
            raise toke_rs.DecodeError("Invalid payload string")
        raise e
    except toke_rs.InvalidAudienceError:
        if options.get("strict_aud"): raise toke_rs.InvalidAudienceError("Audience doesn't match (strict)")
        raise

    # 4. Strict Aud Logic
    if options.get("strict_aud", False):
        aud_claim = payload.get("aud")
        if audience is not None:
            if isinstance(audience, (list, tuple, set)): raise toke_rs.InvalidAudienceError("Invalid audience (strict)")
            if isinstance(aud_claim, list): raise toke_rs.InvalidAudienceError("Invalid claim format in token (strict)")
            if aud_claim != audience: raise toke_rs.InvalidAudienceError("Audience doesn't match (strict)")

    # 5. Strict Types
    for claim, exc in [("exp", toke_rs.DecodeError), ("iat", toke_rs.InvalidIssuedAtError), ("nbf", toke_rs.DecodeError)]:
        val = payload.get(claim)
        if val is not None:
            if isinstance(val, (int, float)): continue
            if isinstance(val, str) and val.isdigit(): continue
            raise exc(f"{claim} must be a number")
            
    if "sub" in payload and not isinstance(payload["sub"], str): raise toke_rs.InvalidSubjectError("Invalid subject: must be a string")
    if "jti" in payload and not isinstance(payload["jti"], str): raise toke_rs.InvalidJTIError("Invalid jti: must be a string")

    return payload


def decode_complete(token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=_sentinel, content=None, leeway=0, **kwargs):
    
    # Just forward to decode wrapper to ensure all Python-side validation logic runs
    # This might double-parse in Rust (decode vs decode_complete_impl), but ensures consistency
    
    # Actually, better to replicate the Python logic and call _rust_decode_complete
    options = options or {}
    token = _prepare_token(token)
    if verify is not _sentinel:
        warnings.warn("The 'verify' argument is deprecated.", DeprecationWarning, stacklevel=2)
        if "verify_signature" not in options: options["verify_signature"] = verify
    options = _merge_options(options, kwargs)
    effective_verify = options.get("verify_signature", True)
    if isinstance(leeway, datetime.timedelta): leeway = leeway.total_seconds()
    leeway = int(leeway)
    options["leeway"] = leeway
    if isinstance(audience, bytes): raise toke_rs.InvalidAudienceError("Invalid audience") 
    if audience is not None and not isinstance(audience, (str, list, tuple, set)): raise TypeError("audience must be a string, iterable or None")
    if effective_verify and not algorithms: raise toke_rs.DecodeError('It is required that you pass in a value for the "algorithms" argument when calling decode().')

    try:
        return _rust_decode_complete(token, key, algorithms, options, audience, issuer, subject, effective_verify, content)
    except toke_rs.MissingRequiredClaimError as e:
        msg = str(e)
        if "Missing required claim: " in msg: e.claim = msg.split(": ")[1]
        raise e
    except toke_rs.DecodeError as e:
        msg = str(e)
        if "JSON error" in msg: raise toke_rs.DecodeError("Invalid payload string")
        raise e
    except Exception as e:
        raise toke_rs.DecodeError(str(e))


# --- Async Wrappers 

async def encode_async(
    payload: Dict[str, Any], 
    key: Union[str, bytes], 
    algorithm: str = "HS256", 
    headers: Optional[Dict[str, Any]] = None
) -> str:
    # We use 'encode' which was injected from Rust above
    return await asyncio.to_thread(encode, payload, key, algorithm, headers)


async def decode_async(
    token: str,
    key: Union[str, bytes],
    algorithms: Optional[List[str]] = None,
    options: Optional[Dict[str, Any]] = None,
    audience: Optional[Union[str, List[str]]] = None,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
    verify: bool = True,
    content: Optional[bytes] = None,
) -> Dict[str, Any]:

    return await asyncio.to_thread(
        decode, token, key, algorithms, options, audience, issuer, subject, verify, content
    )


def _validate_iss(payload, issuer):

    if issuer is None: return
    if "iss" not in payload: raise toke_rs.MissingRequiredClaimError("iss")
    if payload["iss"] != issuer:
        if isinstance(issuer, (list, tuple, set)) and payload["iss"] in issuer: return
        raise toke_rs.InvalidIssuerError("Invalid issuer")


class WebToken:
    """ A jwt.PyJWT-like interface. Allows users to store default options in the instance """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.default_options = options or {}


    def encode(self, payload: Dict[str, Any], key: Union[str, bytes], algorithm: str = "HS256", headers: Optional[Dict[str, Any]] = None, json_encoder: Optional[Any] = None) -> str:
        ''' PyJWT encode() doesn't use self.options significantly, it just forwards '''

        return encode(payload, key, algorithm, headers, json_encoder)


    def decode(self, token: str, key: Union[str, bytes] = None, algorithms: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        
        return decode(token, key, algorithms, {**self.default_options, **(options or {})}, **kwargs)


    def decode_complete(self, token: str, key: Union[str, bytes] = None, algorithms: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        
        merged_options = {**self.default_options, **(options or {})}
        return decode_complete(token, key, algorithms, merged_options, **kwargs)


class PyJWS:

    header_typ = "JWT"

    def __init__(self, algorithms=None, options=None):
        self._algorithms = {}
        
        self.options = {"verify_signature": True}
        if options:
            self.options.update(options)
        
        # Defaults
        defaults = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
                    "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "none"]
        defaults.extend(["ES256K", "ML-DSA-65", "EdDSA"])
        
        allowed = algorithms if algorithms is not None else defaults
        for alg in allowed:
            self._algorithms[alg] = True # Mark as present


    def _validate_headers(self, headers):
        if "kid" in headers and not isinstance(headers["kid"], str):
             raise toke_rs.InvalidTokenError("Key ID header parameter must be a string")


    def register_algorithm(self, alg_id, alg_obj):
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")
        
        # [FIX] Strict Type Check
        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")
            
        self._algorithms[alg_id] = alg_obj


    def unregister_algorithm(self, alg_id):
        if alg_id not in self._algorithms:
            raise KeyError("The specified algorithm could not be removed because it is not registered.")
        del self._algorithms[alg_id]


    def get_algorithms(self):
        return list(self._algorithms.keys())


    def get_unverified_header(self, token):

        header = self._load(token)[2]
        self._validate_headers(header)

        return header



    def decode(self, token, key='', algorithms=None, options=None, detached_payload=None, **kwargs):
        decoded = self.decode_complete(token, key, algorithms, options, detached_payload=detached_payload, **kwargs)
        return decoded["payload"]


    def _load(self, jwt):

        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise toke_rs.DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise toke_rs.DecodeError("Not enough segments") from err

        try:
            header_data = toke_rs.base64url_decode(header_segment)
        except (TypeError, binascii.Error, ValueError) as err:
            raise toke_rs.DecodeError("Invalid header padding") from err

        try:
            header = json.loads(header_data)
        except ValueError as e:
            raise toke_rs.DecodeError(f"Invalid header string: {e}") from e

        if not isinstance(header, dict):
            raise toke_rs.DecodeError("Invalid header string: must be a json object")

        # Check b64 header
        if header.get("b64", True) is False:
            payload = payload_segment # Raw bytes
        else:
            try:
                payload = toke_rs.base64url_decode(payload_segment)
            except (TypeError, binascii.Error, ValueError) as err:
                raise toke_rs.DecodeError("Invalid payload padding") from err

        try:
            signature = toke_rs.base64url_decode(crypto_segment)
        except (TypeError, binascii.Error, ValueError) as err:
            raise toke_rs.DecodeError("Invalid crypto padding") from err

        return (payload, signing_input, header, signature)


    def encode(self, payload, key, algorithm="HS256", headers=None, json_encoder=None, is_payload_detached=False, sort_headers=False):
        
        if headers and "alg" in headers:
            algorithm = headers["alg"]

        if algorithm not in self._algorithms:
            raise NotImplementedError("Algorithm not supported")
            
        # Handle 'none' key
        if algorithm == "none" and key is None:
            key = b""

        # Normalize payload
        if isinstance(payload, dict):
            payload = json.dumps(payload, cls=json_encoder, separators=(",", ":")).encode("utf-8")
        elif isinstance(payload, str):
            payload = payload.encode("utf-8")
        
        # Prepare Headers
        final_headers = {"alg": algorithm, "typ": "JWT"}
        if headers:
            final_headers.update(headers)
            
        if "typ" in final_headers and not final_headers["typ"]:
            del final_headers["typ"]
        
        # handle b64=False (Unencoded) -> Detached
        if final_headers.get("b64") is False:
            is_payload_detached = True
        elif "b64" in final_headers:
            # True is standard, remove to save space (matches PyJWT)
            del final_headers["b64"]
            
        # Validate KID
        if "kid" in final_headers and not isinstance(final_headers["kid"], str):
             raise toke_rs.InvalidTokenError("Key ID header parameter must be a string")

        headers_json = json.dumps(final_headers, cls=json_encoder, separators=(",", ":"), sort_keys=sort_headers)

        # Handle "none" manually to avoid Rust error
        if algorithm == "none":
             header_b64 = toke_rs.base64url_encode(headers_json.encode('utf-8')).decode('utf-8')
             if is_payload_detached:
                 return f"{header_b64}.."
             payload_b64 = toke_rs.base64url_encode(payload).decode('utf-8')
             return f"{header_b64}.{payload_b64}."

        token = toke_rs.sign(payload, key, algorithm, headers_json) 
        
        if is_payload_detached:
            header, _, signature = token.split(".")
            return f"{header}..{signature}"

        return token


    def decode_complete(self, token, key="", algorithms=None, options=None, detached_payload=None, **kwargs):
        
        # 1. Merge Options
        merged_ops = self.options.copy()
        if options: merged_ops.update(options)
        
        verify_sig = merged_ops.get("verify_signature", True)

        # 2. Check Algorithms
        if verify_sig and not algorithms:
            if not isinstance(key, PyJWK):
                raise toke_rs.DecodeError('It is required that you pass in a value for the "algorithms" argument when calling decode().')

        # 3. Load & Parse
        payload, signing_input, header, signature = self._load(token)

        # 4. Handle Detached
        if header.get("b64", True) is False:
            if detached_payload is None:
                raise toke_rs.DecodeError('It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.')
            payload = detached_payload
            header_part = signing_input.rsplit(b".", 1)[0]
            signing_input = header_part + b"." + payload
        
        elif detached_payload:
             payload = detached_payload
             payload_b64 = toke_rs.base64url_encode(payload)
             signing_input = signing_input.split(b".")[0] + b"." + payload_b64

        # 5. Verify
        if verify_sig:
            alg = header.get("alg")
            if alg is None:
                raise toke_rs.InvalidAlgorithmError("Algorithm not specified")
            
            if alg == "none":
                if algorithms and "none" in algorithms:
                    raise toke_rs.InvalidSignatureError("Signature verification failed")
                else:
                    raise toke_rs.InvalidAlgorithmError("Algorithm not supported")

            if algorithms and alg not in algorithms:
                raise toke_rs.InvalidAlgorithmError("The specified alg value is not allowed")

            if isinstance(key, PyJWK):
                if key.algorithm_name and key.algorithm_name != alg:
                     raise toke_rs.InvalidAlgorithmError("The specified alg value is not allowed")
                key_bytes = key
            else:
                key_bytes = key

            # Reconstruct token string for Rust
            sig_b64 = toke_rs.base64url_encode(signature).decode('utf-8')
            token_str = signing_input.decode('utf-8') + "." + sig_b64
            
            verify_key = key_bytes if key_bytes is not None else b""
            
            try:
                # [FIX] Use token_str instead of raw token
                _, _ = toke_rs.verify(token_str, verify_key, alg)
            except toke_rs.InvalidSignatureError:
                raise toke_rs.InvalidSignatureError("Signature verification failed")
            except ValueError as e:
                # [FIX] Convert Rust unsupported alg error to PyJWT exception
                if "Algorithm" in str(e) and "not supported" in str(e):
                     raise toke_rs.InvalidAlgorithmError("Algorithm not supported")
                raise e

        return {
            "payload": payload,
            "header": header,
            "signature": signature
        }



# -- Bind to main module, so it's not under toke.toke
toke_rs.encode = encode
toke_rs.decode = decode
toke_rs.decode_complete = decode_complete
toke_rs.encode_async = encode_async
toke_rs.decode_async = decode_async
toke_rs._validate_iss = _validate_iss
toke_rs.WebToken = WebToken

toke_rs.PyJWT = WebToken
toke_rs.PyJWS = PyJWS
toke_rs.PyJWK = PyJWK
toke_rs.PyJWKSet = PyJWKSet
toke_rs.PyJWKError = PyJWKError
toke_rs.PyJWKSetError = PyJWKSetError

api_jws = types.ModuleType("toke.c")
api_jws.PyJWS = PyJWS
sys.modules["toke.api_jws"] = api_jws

# algorithms_mod = types.ModuleType("toke.algorithms")
# algorithms_mod.Algorithm = Algorithm # Export the shim
# algorithms_mod.has_crypto = True 
# sys.modules["toke.algorithms"] = algorithms_mod

# toke_rs.api_jws = api_jws
# toke_rs.algorithms = algorithms_mod

