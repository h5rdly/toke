import os, sys, types, importlib.util, datetime, warnings, json
from typing import Optional, List, Dict, Any, Union, Iterable

# --- 1. Load Rust Core ---

rust_lib = None
_rust_lib_name = 'webtoken'
py_dir = __file__.rsplit('/', 1)[0]

def _load_rust_module(path):
    spec = importlib.util.spec_from_file_location(_rust_lib_name, path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return None

for file in os.listdir(py_dir):
    if file.startswith(f'lib{_rust_lib_name}') and file.endswith((".so", ".pyd", ".dylib", 'dll')):
        rust_lib = _load_rust_module(f'{py_dir}/{file}')
        break
else:
    _dev_path_linux = f'target/release/lib{_rust_lib_name}.so'
    if os.path.exists(_dev_path_linux):
        rust_lib = _load_rust_module(_dev_path_linux)

if rust_lib is None:
    raise ImportError("Could not find Rust binary")

# Capture Rust functions
_rust_sign = rust_lib.sign
_rust_encode = rust_lib.encode_fast
_rust_decode_complete = rust_lib.decode_complete
_rust_get_header = rust_lib.get_unverified_header
_rust_load_jwk = rust_lib.load_jwk
_rust_pem_to_jwk = rust_lib.pem_to_jwk
_rust_raw_sign = rust_lib.raw_sign
_rust_raw_verify = rust_lib.raw_verify
_rust_b64_decode = rust_lib.base64url_decode
_rust_b64_encode = rust_lib.base64url_encode
_rust_digest = getattr(rust_lib, "digest", None)
_rust_json_loads = rust_lib.json_loads
_rust_json_dumps = rust_lib.json_dumps
_rust_validate_claims = rust_lib.validate_claims

# Expose Types
PyJWK = rust_lib.api_jwk.PyJWK
InvalidKeyError = rust_lib.InvalidKeyError 

# --- Constants & Helpers ---

_sentinel = object()

class InsecureKeyLengthWarning(UserWarning): 
    pass

class RemovedInPyjwt3Warning(DeprecationWarning): 
    pass

rust_lib.InsecureKeyLengthWarning = InsecureKeyLengthWarning
rust_lib.RemovedInPyjwt3Warning = RemovedInPyjwt3Warning


class PyJWTError(Exception):
    pass

# Inherit from both Rust's error (for catchability) and PyJWTError (for isinstance checks)
class InvalidTokenError(rust_lib.InvalidTokenError, PyJWTError):
    pass

class DecodeError(rust_lib.DecodeError, InvalidTokenError):
    pass

class InvalidSignatureError(rust_lib.InvalidSignatureError, DecodeError):
    pass

class ExpiredSignatureError(rust_lib.ExpiredSignatureError, InvalidTokenError):
    pass

class InvalidAudienceError(rust_lib.InvalidAudienceError, InvalidTokenError):
    pass

class InvalidIssuerError(rust_lib.InvalidIssuerError, InvalidTokenError):
    pass

class ImmatureSignatureError(rust_lib.ImmatureSignatureError, InvalidTokenError):
    pass

class InvalidAlgorithmError(rust_lib.InvalidAlgorithmError, InvalidTokenError):
    pass

class MissingRequiredClaimError(rust_lib.InvalidTokenError):
    ''' Wrapper to match PyJWT claim errors '''

    def __init__(self, claim: str):
        self.claim = claim
        super().__init__(f'Token is missing the "{claim}" claim')


exceptions_module = types.ModuleType("webtoken.exceptions")
exceptions_module.PyJWTError = PyJWTError
exceptions_module.InvalidTokenError = InvalidTokenError
exceptions_module.DecodeError = DecodeError
exceptions_module.InvalidSignatureError = InvalidSignatureError
exceptions_module.ExpiredSignatureError = ExpiredSignatureError
exceptions_module.InvalidAudienceError = InvalidAudienceError
exceptions_module.InvalidIssuerError = InvalidIssuerError
exceptions_module.ImmatureSignatureError = ImmatureSignatureError
exceptions_module.InvalidAlgorithmError = InvalidAlgorithmError
exceptions_module.MissingRequiredClaimError = MissingRequiredClaimError
sys.modules["webtoken.exceptions"] = exceptions_module


def _merge_options(default_options: Optional[Dict], options: Optional[Dict], kwargs: Dict) -> Dict:

    merged = default_options.copy() if default_options else {}
    if options: merged.update(options)
    if kwargs.get("verify") is False: merged["verify_signature"] = False
    if merged.get("verify_signature") is False:
        for k in ["verify_exp", "verify_nbf", "verify_iat", "verify_aud", "verify_iss", "verify_sub", "verify_jti"]:
            if k not in merged: merged[k] = False
    return merged


def _validate_key_length(key, algorithm, enforce):

    if algorithm.startswith("HS"):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        
        if isinstance(key_bytes, bytes):
            min_len = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm, 0)
            
            if len(key_bytes) < min_len:
                msg = f"The specified key is {len(key_bytes)} bytes long, which is below the minimum recommended length of {min_len} bytes."
                if enforce:
                    raise rust_lib.InvalidKeyError(msg)
                else:
                    warnings.warn(msg, InsecureKeyLengthWarning)


def _validate_iss(payload, issuer):

    if issuer is None: 
        return

    if "iss" not in payload: 
        raise rust_lib.MissingRequiredClaimError("iss")

    if payload["iss"] != issuer:
        if isinstance(issuer, (list, tuple, set)) and payload["iss"] in issuer: 
            return

        raise rust_lib.InvalidIssuerError("Invalid issuer")


# --- Internal Shared Logic ---

def _decode_jws_struct(
    token: Union[str, bytes], key: Union[str, bytes, PyJWK, None], algorithms: Optional[List[str]],
    merged_options: Dict[str, Any], audience: Optional[Union[str, Iterable[str]]], issuer: Optional[str],
    subject: Optional[str], verify_sig: bool, content: Optional[bytes], return_dict: bool = True
) -> Dict[str, Any]:

    try:
        return _rust_decode_complete(
            token, key, algorithms, merged_options, audience, issuer, subject, verify_sig, content, return_dict)
    except rust_lib.MissingRequiredClaimError as e:
        # PyJWT expects the exception instance to have a .claim attribute
        if ": " in (msg := str(e)): 
            e.claim = msg.split(": ")[1]
        raise e


# -- Crypto helpers
# _rust_generate_key_pair = rust_lib.generate_key_pair

# def generate_key_pair(algorithm: str, key_size: int = None):
#     return _rust_generate_key_pair(algorithm, key_size)

# rust_lib.generate_key_pair = generate_key_pair

# --- Core Global Functions 

def encode(
    payload: Union[Dict[str, Any], bytes], 
    key: Union[str, bytes, PyJWK], 
    algorithm: str = "HS256", 
    headers: Optional[Dict[str, Any]] = None, 
    json_encoder: Optional[Any] = None, 
    sort_headers: bool = True
) -> str:
    
    if not isinstance(payload, (dict, bytes)):
        raise TypeError("Expecting a dict or bytes object")

    headers_to_pass = headers
    if headers and json_encoder:
        try:
            # Execute the user's encoder 
            serialized_headers = json.dumps(headers, separators=(",", ":"), cls=json_encoder)
            headers_to_pass = json.loads(serialized_headers)
        except Exception as e:
            # Match PyJWT behavior: raise TypeError on header serialization failure
            raise TypeError(f"Header serialization failed: {e}")

    # standard path, no custom encoder
    if isinstance(payload, dict) and json_encoder is None:
        try:
            return _rust_encode(payload, key, algorithm, headers_to_pass, sort_headers)
        except TypeError:
            pass # Fallback to slow path for complex types
        except Exception as e:
            raise e

    # Custom rncoders or raw bytes (PyJWS)
    json_payload = payload
    if isinstance(payload, dict):
        payload_copy = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            val = payload_copy.get(time_claim)
            if isinstance(val, datetime.datetime):
                payload_copy[time_claim] = int(val.replace(tzinfo=datetime.timezone.utc).timestamp())
        
        if "iss" in payload_copy and not isinstance(payload_copy["iss"], str):
            raise TypeError("Issuer (iss) must be a string.")

        json_payload = json.dumps(payload_copy, separators=(",", ":"), cls=json_encoder).encode("utf-8")
    
    # Headers & Signing (Delegated to Rust)
    return _rust_sign(json_payload, key, algorithm, headers_to_pass, sort_headers)


def decode(
    token: str, key: Union[str, bytes, PyJWK] = None, algorithms: Optional[List[str]] = None, 
    options: Optional[Dict[str, Any]] = None, **kwargs
) -> Dict[str, Any]:

    decoded = decode_complete(token, key, algorithms, options, **kwargs)
    return decoded["payload"]


def decode_complete(
    token: str, key: Union[str, bytes, PyJWK] = None, algorithms: Optional[List[str]] = None,
    options: Optional[Dict[str, Any]] = None, audience: Optional[Union[str, List[str]]] = None, 
    issuer: Optional[str] = None, subject: Optional[str] = None, verify: Any = _sentinel, 
    content: Optional[bytes] = None, leeway: Union[int, float, datetime.timedelta] = 0, **kwargs
) -> Dict[str, Any]:
    
    merged_options = options.copy() if options else {}
    if verify is not _sentinel:
        warnings.warn("The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer.", DeprecationWarning, stacklevel=2)
        if verify is False: merged_options["verify_signature"] = False
    
    if merged_options.get("verify_signature") is False:
        for k in ["verify_exp", "verify_nbf", "verify_iat", "verify_aud", "verify_iss", "verify_sub", "verify_jti"]:
            if k not in merged_options: merged_options[k] = False
    
    verify_sig = merged_options.get("verify_signature", True)
    
    if isinstance(leeway, datetime.timedelta): leeway = leeway.total_seconds()
    leeway = int(leeway)
    merged_options["leeway"] = leeway
    
    decoded_struct = _decode_jws_struct(token, key, algorithms, merged_options, audience, issuer, subject, verify_sig, content)
    payload_data = decoded_struct["payload"]
    
    if isinstance(payload_data, dict):
        payload = payload_data
    else:
        try:
            payload = _rust_json_loads(payload_data)
        except Exception:
            raise rust_lib.DecodeError("Invalid payload string: must be a json object")
        
        try:
            _rust_validate_claims(payload, merged_options, audience, issuer, subject, leeway)
        except rust_lib.MissingRequiredClaimError as e:
            msg = str(e)
            if ": " in msg: 
                e.claim = msg.split(": ")[1]
            else:        
                if (start := msg.find('"')) != -1:
                    if (end := msg.find('"', start + 1)) != -1:
                        e.claim = msg[start + 1 : end]

    decoded_struct["payload"] = payload

    return decoded_struct


# -- Curves shim  

class Curve:
    name: str

class SECP256R1(Curve):
    name = "P-256"

class SECP384R1(Curve):
    name = "P-384"

class SECP521R1(Curve):
    name = "P-521"

class SECP256K1(Curve):
    name = "secp256k1"


# --- Algorithms Shim ---

class Algorithm:

    def sign(self, msg, key): raise NotImplementedError
    def verify(self, msg, key, sig): raise NotImplementedError
    def check_key_length(self, key): return None
    def check_crypto_key_type(self, key): pass

    def prepare_key(self, key): 
        if key is None: raise TypeError("Key cannot be None")
        return key

    def compute_hash_digest(self, bytes_data):
        alg = getattr(self, "alg", "SHA256")
        return bytes(_rust_digest(alg, bytes_data))


    def _load_pem_to_pyjwk(self, key):
        """Shared helper to safely load PEM bytes/str into a PyJWK."""
        if isinstance(key, (str, bytes)):
            try:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                # Use the Native Rust function directly! 
                # It goes Bytes -> Internal Rust Struct -> PyJWK (No JSON overhead)
                return rust_lib.load_key_from_pem(key_bytes)
            except Exception:
                pass
        return None


    def validate_jwk(self, jwk, kty=None, crv=None):
        """Consolidated validation logic."""
        # Convert dict to PyJWK if needed, or validate dict fields directly
        # This assumes jwk is a dict or PyJWK object wrapper
        data = jwk if isinstance(jwk, dict) else jwk.as_dict()
        
        if kty and data.get("kty") != kty:
            raise rust_lib.InvalidKeyError(f"Invalid key type: {data.get('kty')}. Expected {kty}.")
        
        if crv:
            if "crv" not in data:
                raise rust_lib.InvalidKeyError(f"Key must be {kty} and have 'crv'")
            if data["crv"] != crv:
                 # Check for mapped names (P-256 vs secp256r1)
                 # ... (Shared mapping logic can go here)
                 raise rust_lib.InvalidKeyError(f"Unsupported curve: {data['crv']}")
        return data


    @staticmethod
    def from_jwk(jwk):
        try: return _rust_load_jwk(_rust_json_dumps(jwk) if isinstance(jwk, dict) else jwk)
        except Exception as e: 
             if "Key type" in str(e): raise rust_lib.InvalidKeyError("Key type (kty) not found") 
             raise rust_lib.InvalidKeyError("Invalid key")
             
    
    def to_jwk(self, key, as_dict=False):

        if isinstance(key, dict): 
            raise rust_lib.InvalidKeyError("Invalid key: dict is not a supported key type for to_jwk")
            
        jwk_data = None

        # 1. Extract data from PyJWK or Object with as_dict
        if isinstance(key, PyJWK):
            jwk_data = key.as_dict()
        elif hasattr(key, "as_dict"):
            jwk_data = key.as_dict()
        else:
            # 2. Fallback: Parse from PEM bytes
            try:
                key_bytes = key if isinstance(key, bytes) else key.encode()
                json_str = _rust_pem_to_jwk(key_bytes)
                jwk_data = _rust_json_loads(json_str)
            except Exception:
                raise rust_lib.InvalidKeyError("Invalid key")

        # 3. Validate Curve for EC Keys
        if jwk_data.get("kty") == "EC":
            crv = jwk_data.get("crv")
            if crv not in ("P-256", "P-384", "P-521", "secp256k1"):
                raise rust_lib.InvalidKeyError(f"Invalid curve: {crv}")

        if as_dict:
            return jwk_data
        
        return _rust_json_dumps(jwk_data)



class NoneAlgorithm(Algorithm):

    def prepare_key(self, key): 
        if key is not None: raise rust_lib.InvalidKeyError("Key must be None for NoneAlgorithm")
        return None
    def sign(self, msg, key): return b""
    def verify(self, msg, key, sig): return True
    def check_crypto_key_type(self, key): raise ValueError("NoneAlgorithm does not support cryptographic keys")
    def to_jwk(self, key, as_dict=False): raise NotImplementedError
    def from_jwk(self, jwk): raise NotImplementedError


class HMACAlgorithm(Algorithm):
    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"
    
    def __init__(self, alg): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        # Map hash alg to JWS alg for Rust and Lookups
        self.alg = {
            "SHA256": "HS256",
            "SHA384": "HS384",
            "SHA512": "HS512"
        }.get(self.hash_alg, "HS256")
    
    
    def sign(self, msg, key): return bytes(_rust_raw_sign(msg, key, self.alg))

    def verify(self, msg, key, sig): return _rust_raw_verify(msg, bytes(sig), key, self.alg)
    

    def prepare_key(self, key):
        if key is None: raise TypeError("Key cannot be None")
        if not isinstance(key, (str, bytes, PyJWK)): raise TypeError("Expected a string value")

        if isinstance(key, (str, bytes)):
            try:
                key_text = key.decode("utf-8") if isinstance(key, bytes) else key
                
                if ("-----BEGIN PUBLIC KEY-----" in key_text or 
                    "-----BEGIN RSA PUBLIC KEY-----" in key_text or 
                    "-----BEGIN CERTIFICATE-----" in key_text or 
                    "ssh-rsa" in key_text):
                    raise rust_lib.InvalidKeyError(
                        "The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret."
                    )
            except UnicodeDecodeError:
                # If it's not valid UTF-8, it's likely a binary secret, which is allowed.
                pass

        return key


    def check_key_length(self, key):
        if isinstance(key, (str, bytes)):

            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            # [FIX] Use self.alg (which is now HS256/etc) for lookup
            req = {"HS256": 32, "HS384": 48, "HS512": 64}.get(self.alg, 0)
            if len(key_bytes) < req: 
                return f"The specified key is {len(key_bytes)} bytes long, which is below the minimum recommended length of {req} bytes."
        return None
    

    @staticmethod
    def from_jwk(jwk):
        key = Algorithm.from_jwk(jwk)
        if key.key_type != "oct": raise rust_lib.InvalidKeyError("Not an HMAC key")
        return key


    def to_jwk(self, key, as_dict=False):
        
        if isinstance(key, dict):
             raise rust_lib.InvalidKeyError("Invalid key: dict is not a supported key type for to_jwk")

        # Handle PyJWK
        if isinstance(key, PyJWK):
            data = key.as_dict()
            if data.get("kty") != "oct":
                 raise rust_lib.InvalidKeyError("Invalid key type for HMAC")
            if as_dict: return data
            return _rust_json_dumps(data)

        # Handle raw bytes/string
        if isinstance(key, (str, bytes)):
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            data = {"kty": "oct", "k": _rust_b64_encode(key_bytes).decode("utf-8")}
            return data if as_dict else _rust_json_dumps(data)
            
        # Fallback to base implementation (unlikely to reach here for HMAC)
        return super().to_jwk(key, as_dict)


class RSAAlgorithm(Algorithm):

    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"

    def __init__(self, alg): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        # Simple mapping for standard RSA
        self.alg = {
            "SHA256": "RS256",
            "SHA384": "RS384",
            "SHA512": "RS512"
        }.get(self.hash_alg, "RS256")


    def sign(self, msg, key): 
        return bytes(_rust_raw_sign(msg, key, self.alg))


    def verify(self, msg, key, sig): 
        return _rust_raw_verify(msg, bytes(sig), key, self.alg)
    

    def to_jwk(self, key, as_dict=False):
        
        if isinstance(key, PyJWK):
            jwk_dict = key.as_dict()
        else:
            jwk_dict = super().to_jwk(key, as_dict=True)

        if "key_ops" not in jwk_dict:
            # RSA Private keys have 'd', 'p', 'q', etc.
            if "d" in jwk_dict:
                jwk_dict["key_ops"] = ["sign"]
            else:
                jwk_dict["key_ops"] = ["verify"]

        if as_dict:
            return jwk_dict
        return _rust_json_dumps(jwk_dict)


    @staticmethod
    def from_jwk(jwk):
        try:
            d = jwk if isinstance(jwk, dict) else _rust_json_loads(jwk)
        except (ValueError, TypeError):
            raise rust_lib.InvalidKeyError("Invalid JWK")

        if d.get("kty") != "RSA": 
            raise rust_lib.InvalidKeyError("Key must be RSA")
        
        if "n" not in d or "e" not in d:
            raise rust_lib.InvalidKeyError("Missing RSA public key components")

        if "oth" in d:
            raise rust_lib.InvalidKeyError("RSA keys with 'oth' (other primes) are not supported")
            
        if "d" in d:
            crt_params = ["p", "q", "dp", "dq", "qi"]
            # Enforce All or Nothing for CRT parameters
            if 0 < sum(p in d for p in crt_params) < len(crt_params):
                missing = [p for p in crt_params if p not in d]
                raise rust_lib.InvalidKeyError(f"Missing RSA private key component: {missing}")
        
        return super(RSAAlgorithm, RSAAlgorithm).from_jwk(jwk)
    
    
    def prepare_key(self, key):

        if key is None:
            raise TypeError("Key cannot be None")
        
        jwk = None
        if isinstance(key, (str, bytes)):
            try:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                jwk_json = _rust_pem_to_jwk(key_bytes)
                jwk = _rust_load_jwk(jwk_json)
            except Exception:
                pass
        
        if jwk:
            if jwk.key_type != "RSA":
                 raise rust_lib.InvalidKeyError(f"Invalid key type: {jwk.key_type}. Expected RSA.")
            return jwk
        
        # If we failed to parse as PEM, throw error for RSA (unlike generic Algorithm which might allow raw bytes)
        if isinstance(key, (str, bytes)):
             raise rust_lib.InvalidKeyError("Could not parse the provided public key.")

        return key
        

    def check_key_length(self, key):
        try:
            # 1. Handle "cryptography" style keys (objects with key_size)
            if hasattr(key, "key_size"):
                bit_len = key.key_size
                if bit_len < 2048:
                    return f"The specified key is {bit_len} bits, which is below the minimum recommended length of 2048 bits."
                return None

            jwk_obj = None
            if isinstance(key, (str, bytes)):
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                try:
                    # Returns a dict
                    jwk_obj = rust_lib.load_key_from_pem(key_bytes)
                except Exception:
                    pass
            elif isinstance(key, PyJWK):
                jwk_obj = key
            elif isinstance(key, dict):
                jwk_obj = key
            
            if jwk_obj:
                # [FIX] Handle Dictionary (Standard JWK format)
                if isinstance(jwk_obj, dict):
                    if "n" in jwk_obj:
                        n_b64 = jwk_obj["n"]
                        try:
                            # Decode Base64URL to bytes
                            n_bytes = _rust_b64_decode(n_b64)
                            # Convert to integer to get accurate bit length
                            bit_len = int.from_bytes(n_bytes, byteorder='big').bit_length()
                            
                            if bit_len < 2048:
                                return f"The specified key is {bit_len} bits, which is below the minimum recommended length of 2048 bits."
                        except Exception:
                            pass

                # Handle PyJWK (if applicable in future) or objects with public_numbers
                elif hasattr(jwk_obj, 'public_numbers'):
                    pub_nums = jwk_obj.public_numbers()
                    if pub_nums and hasattr(pub_nums, 'n'):
                        bit_len = pub_nums.n.bit_length()
                        if bit_len < 2048:
                            return f"The specified key is {bit_len} bits, which is below the minimum recommended length of 2048 bits."

        except Exception:
            pass
        return None


class RSAPSSAlgorithm(RSAAlgorithm):

    def __init__(self, alg):
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        self.alg = {
            "SHA256": "PS256",
            "SHA384": "PS384",
            "SHA512": "PS512"
        }.get(self.hash_alg, "PS256")


# For PyJWT compatibility when throwing errors
cryptography_curve_names = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1", "P-192": "secp192r1"}

class ECAlgorithm(Algorithm):
    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"
    
    def __init__(self, alg, curve=None): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        self.alg = {
            "SHA256": "ES256",
            "SHA384": "ES384",
            "SHA512": "ES512"
        }.get(self.hash_alg, "ES256")
        self.expected_curve = curve
    
    def sign(self, msg, key): 
        return bytes(_rust_raw_sign(msg, key, self.alg))

    def verify(self, msg, key, sig): 
        return _rust_raw_verify(msg, bytes(sig), key, self.alg)



        
    @staticmethod
    def from_jwk(jwk):
        try:
            d = jwk if isinstance(jwk, dict) else _rust_json_loads(jwk)
        except ValueError:
            raise rust_lib.InvalidKeyError("Invalid Key: Invalid JSON")

        if d.get("kty") != "EC": raise rust_lib.InvalidKeyError("Key must be EC")
        if "crv" not in d: raise rust_lib.InvalidKeyError("Key must be EC and have 'crv'")
        
        return super(ECAlgorithm, ECAlgorithm).from_jwk(jwk)


    def prepare_key(self, key):

        if key is None:
            raise TypeError("Key cannot be None")
            
        jwk = None
        if isinstance(key, PyJWK):
            jwk = key
        elif isinstance(key, (str, bytes)):
            try:
                # Attempt to load PEM/Byte key
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                jwk_json = _rust_pem_to_jwk(key_bytes)
                jwk = _rust_load_jwk(jwk_json)
            except Exception:
                # If loading fails (not a valid key format), we fall through 
                # and return the original key (for raw byte keys/HMAC cases).
                pass

        if jwk:
            expected_name = None
            if self.expected_curve:
                expected_name = getattr(self.expected_curve, "name", None)
                if not expected_name:
                    expected_name = str(self.expected_curve)

            # [FIX] Offload validation to Rust (Performance + Consistency)
            # This replaces the dictionary lookup, try/catch, and manual string mapping logic
            rust_lib.validate_key_properties(jwk, "EC", expected_name)
            
            return jwk

        return key


class OKPAlgorithm(Algorithm):

    def sign(self, msg, key): return bytes(_rust_raw_sign(msg, key, "EdDSA"))
    def verify(self, msg, key, sig): return _rust_raw_verify(msg, bytes(sig), key, "EdDSA")

    
    @staticmethod
    def from_jwk(jwk):
        try:
            d = jwk if isinstance(jwk, dict) else _rust_json_loads(jwk)
        except (ValueError, TypeError):
            # Catch JSON decode errors (ValueError) and type errors (e.g. int passed)
            raise rust_lib.InvalidKeyError("Invalid JWK")

        if d.get("kty") != "OKP": 
            raise rust_lib.InvalidKeyError("Not an Octet Key Pair")
        
        # [FIX] Added validation for 'crv' and 'x' (public key component)
        # The test checks for invalid crv ("P-256", "Ed448") and invalid 'x'
        if d.get("crv") != "Ed25519":
             raise rust_lib.InvalidKeyError(f"Unsupported curve: {d.get('crv')}")
        
        if "x" not in d:
             raise rust_lib.InvalidKeyError("Missing x component")

        # Validate base64 of 'x' and 'd' if present
        try:
             _rust_b64_decode(d["x"])
             if "d" in d:
                 _rust_b64_decode(d["d"])
        except Exception:
             raise rust_lib.InvalidKeyError("Invalid base64 encoding")

        return super(OKPAlgorithm, OKPAlgorithm).from_jwk(jwk)

    
    def prepare_key(self, key):

        if key is None:
             raise rust_lib.InvalidKeyError("Key cannot be None")
        
        jwk = None
        
        # 1. Normalize input to PyJWK
        if isinstance(key, PyJWK):
            jwk = key
        elif isinstance(key, (str, bytes)):
            try:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                # Attempt to parse as PEM using native Rust function
                jwk = rust_lib.load_key_from_pem(key_bytes)
            except Exception:
                # If it fails to parse as a valid PEM key, reject it
                raise rust_lib.InvalidKeyError("Invalid key: failed to parse PEM")

        # 2. Validate Properties using Rust Helper
        if jwk:
            # Checks kty="OKP" and crv="Ed25519"
            # This replaces the manual dictionary lookups and inconsistent error messages
            rust_lib.validate_key_properties(jwk, "OKP", "Ed25519")
            return jwk
        
        return key
        


def get_default_algorithms():
    return {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm("SHA256"), "HS384": HMACAlgorithm("SHA384"), "HS512": HMACAlgorithm("SHA512"),
        "RS256": RSAAlgorithm("SHA256"), "RS384": RSAAlgorithm("SHA384"), "RS512": RSAAlgorithm("SHA512"),
        "PS256": RSAAlgorithm("SHA256"), "PS384": RSAAlgorithm("SHA384"), "PS512": RSAAlgorithm("SHA512"),
        
        # [FIX] Use our own internal constants
        "ES256": ECAlgorithm("SHA256", SECP256R1), 
        "ES384": ECAlgorithm("SHA384", SECP384R1), 
        "ES512": ECAlgorithm("SHA512", SECP521R1), 
        "ES521": ECAlgorithm("SHA512", SECP521R1),  # Alias to ES512
        "ES256K": ECAlgorithm("SHA256", SECP256K1),
        
        "EdDSA": OKPAlgorithm(),
    }

    
# ... (Wrapper Classes) ...
class PyJWS:

    header_typ = "JWT"

    def __init__(self, algorithms=None, options=None):

        self._algorithms = get_default_algorithms()
        self.options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "require": [],
        }
        
        if options:
            if not isinstance(options, dict):
                raise TypeError("options must be a dict")
            self.options.update(options)

        if algorithms:
            allowed = set(algorithms)
            for k in list(self._algorithms.keys()):
                if k not in allowed: del self._algorithms[k]


    def register_algorithm(self, alg_id, alg_obj):
        if alg_id in self._algorithms: raise ValueError("Algorithm already has a handler.")
        if not isinstance(alg_obj, Algorithm): raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
    

    def unregister_algorithm(self, alg_id):
        if alg_id not in self._algorithms: raise KeyError("The specified algorithm could not be removed because it is not registered.")
        del self._algorithms[alg_id]
    

    def get_algorithms(self): return list(self._algorithms.keys())
    

    def get_algorithm_by_name(self, alg_name):
        try: return self._algorithms[alg_name]
        except KeyError: raise NotImplementedError("Algorithm not supported")


    def get_unverified_header(self, token): 
        return _rust_get_header(token)


    def encode(self, payload, key, algorithm="HS256", headers=None, json_encoder=None, is_payload_detached=False, sort_headers=False):
        
        if headers and "alg" in headers: 
            algorithm = headers["alg"]

        if algorithm not in self._algorithms: 
            raise NotImplementedError("Algorithm not supported")
        
        _validate_key_length(key, algorithm, self.options.get("enforce_minimum_key_length"))

        return encode(payload, key, algorithm, headers, json_encoder, sort_headers)
    

    def decode(
        self,
        token: Union[str, bytes],
        key: Union[str, bytes, PyJWK] = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        detached_payload: Optional[bytes] = None,
        **kwargs: Any,
    ) -> Union[Dict[str, Any], bytes]:
        
        decoded = self.decode_complete(token, key, algorithms, options, detached_payload=detached_payload, **kwargs)
        return decoded["payload"]
    

    def decode_complete(
        self,
        token: Union[str, bytes],
        key: Union[str, bytes, PyJWK] = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        detached_payload: Optional[bytes] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        
        pyjwt_allowed_kwargs = {"verify", "audience", "issuer", "subject", "leeway"}
        for k in kwargs:
            if k not in pyjwt_allowed_kwargs:
                # To pass PyJWT compat tests, dump at some point
                warnings.warn(
                    f"Argument '{k}' is not supported and will be removed in a future version",
                    category=RemovedInPyjwt3Warning,
                    stacklevel=2,
                )

        merged_ops = self.options.copy()
        if options: merged_ops.update(options)

        verify_sig = merged_ops.get("verify_signature", True)
        
        return _decode_jws_struct(
            token, key, algorithms, merged_ops, None, None, None, verify_sig, detached_payload, return_dict=False)
    


class PyJWT:

    def __init__(self, options=None):
        self.options = {"verify_signature": True, "verify_exp": True, "verify_nbf": True, "verify_iat": True, "verify_aud": True, "verify_iss": True, "verify_sub": True, "verify_jti": True, "require": []}
        if options: self.options.update(options)
    
    def encode(self, payload, key, algorithm="HS256", headers=None, json_encoder=None, sort_headers=True):
        
        if algorithm.startswith("HS"):
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            if isinstance(key_bytes, bytes):
                min_len = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm, 0)
                if len(key_bytes) < min_len:
                    msg = f"The specified key is {len(key_bytes)} bytes long, which is below the minimum recommended length of {min_len} bytes."
                    if self.options.get("enforce_minimum_key_length"):
                        raise rust_lib.InvalidKeyError(msg)
                    else:
                        warnings.warn(msg, InsecureKeyLengthWarning)

        return encode(payload, key, algorithm, headers, json_encoder, sort_headers)
    

    def decode(self, token, key="", algorithms=None, options=None, **kwargs):
        merged = _merge_options(self.options, options, kwargs)
        return decode(token, key, algorithms, merged, **kwargs)
    

    def decode_complete(self, token, key="", algorithms=None, options=None, **kwargs):

        merged = _merge_options(self.options, options, kwargs)

        if hasattr(self, "_decode_payload") and getattr(self._decode_payload, "__func__", None) is not PyJWT._decode_payload:
             decoded_struct = _decode_jws_struct(
                token, key, algorithms, merged, None, None, None, merged.get("verify_signature", True), 
                None, return_dict=True)

             payload_data = decoded_struct["payload"]
             if isinstance(payload_data, dict):
                 decoded_struct["payload"] = _rust_json_dumps(payload_data).encode("utf-8")
             payload = self._decode_payload(decoded_struct)
             _rust_validate_claims(payload, merged, **kwargs)
             decoded_struct["payload"] = payload

             return decoded_struct

        return decode_complete(token, key, algorithms, merged, **kwargs)
    

    def _decode_payload(self, decoded):
        try:
            val = decoded["payload"]
            if isinstance(val, bytes): val = val.decode('utf-8')
            return _rust_json_loads(val)
        except Exception as e: raise rust_lib.DecodeError(f"Invalid payload string: {e}")


rust_lib.encode = encode
rust_lib.decode = decode
rust_lib.decode_complete = decode_complete

rust_lib._validate_iss = _validate_iss
rust_lib.json_loads = _rust_json_loads
rust_lib.json_dumps = _rust_json_dumps

rust_lib.PyJWT = PyJWT

rust_lib.PyJWKError = rust_lib.api_jwk.PyJWKError
rust_lib.PyJWKSetError = rust_lib.api_jwk.PyJWKSetError

rust_lib.PyJWS = PyJWS
api_jws = types.ModuleType("webtoken.api_jws")
api_jws.PyJWS = PyJWS

curves = types.ModuleType("webtoken.curves")
curves.SECP256R1 = SECP256R1
curves.SECP384R1 = SECP384R1
curves.SECP521R1 = SECP521R1
curves.SECP256K1 = SECP256K1

algorithms = types.ModuleType("webtoken.algorithms")
rust_lib.algorithms = algorithms
algorithms.Algorithm = Algorithm
algorithms.NoneAlgorithm = NoneAlgorithm
algorithms.HMACAlgorithm = HMACAlgorithm
algorithms.RSAAlgorithm = RSAAlgorithm
algorithms.ECAlgorithm = ECAlgorithm
algorithms.RSAPSSAlgorithm = RSAPSSAlgorithm 
algorithms.OKPAlgorithm = OKPAlgorithm
algorithms.get_default_algorithms = get_default_algorithms

sys.modules["webtoken.api_jws"] = api_jws
sys.modules["webtoken.algorithms"] = algorithms
sys.modules["webtoken.curves"] = curves
