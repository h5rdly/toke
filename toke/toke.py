import asyncio, json, base64, datetime, warnings, sys
from typing import Optional, List, Dict, Any, Union


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


# --- Helpers 

def _prepare_token(token: Union[str, bytes]) -> str:

    if isinstance(token, bytes): return token.decode("utf-8")
    return token


def _merge_options(options: Optional[Dict], kwargs: Dict) -> Dict:

    opts = options.copy() if options else {}
    # PyJWT treats options["verify_signature"] as the source of truth if it exists.
    
    # Defaults if verify_signature is explicitly False
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


class Toke:
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


# -- Bind to main module, so it's not under toke.toke
toke_rs.encode = encode
toke_rs.decode = decode
toke_rs.decode_complete = decode_complete
toke_rs.encode_async = encode_async
toke_rs.decode_async = decode_async
toke_rs._validate_iss = _validate_iss
toke_rs.Toke = Toke
toke_rs.PyJWT = Toke