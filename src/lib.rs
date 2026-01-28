use std::str::FromStr;
use std::collections::{HashSet, HashMap};
use std::sync::{OnceLock, RwLock};

use jsonwebtoken::{
    crypto::{sign, verify},
    decode as jwt_decode, encode as jwt_encode, decode_header as jwt_decode_header, dangerous::insecure_decode, 
    Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::Error,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use pyo3::prelude::*;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{PyDict, };
use pyo3::{wrap_pyfunction, create_exception}; 
use pythonize::{depythonize, pythonize};

use serde_json::{Value, Map};
use serde::{Serialize, Deserialize};

mod algorithms; 
mod keygen;  // Export some convenience crypto logic for testing
pub mod jwk_api;

use crate::algorithms::ExternalAlgorithm;
use crate::jwk_api::{PyJwk, PyJwkSet};


// --- Exception Definitions ---
create_exception!(toke, PyJWTError, pyo3::exceptions::PyException);
create_exception!(toke, InvalidTokenError, PyJWTError);
create_exception!(toke, DecodeError, InvalidTokenError);
create_exception!(toke, InvalidSignatureError, DecodeError);
create_exception!(toke, ExpiredSignatureError, InvalidTokenError);
create_exception!(toke, InvalidAudienceError, InvalidTokenError);
create_exception!(toke, InvalidIssuerError, InvalidTokenError);
create_exception!(toke, ImmatureSignatureError, InvalidTokenError);
create_exception!(toke, MissingRequiredClaimError, InvalidTokenError);
create_exception!(toke, InvalidIssuedAtError, InvalidTokenError);
create_exception!(toke, InvalidJTIError, InvalidTokenError);
create_exception!(toke, InvalidSubjectError, InvalidTokenError);
create_exception!(toke, InvalidAlgorithmError, InvalidTokenError);
create_exception!(toke, InvalidKeyError, PyJWTError);


// -- Debug helper macros

// Prepend file and line number to error messages. 
#[macro_export]
macro_rules! err_loc {
    ($($arg:tt)*) => {
        format!("[{}:{}] {}", file!(), line!(), format!($($arg)*))
    };
}


#[derive(Deserialize)]
struct PartialHeader {
    alg: String,
}


#[derive(Debug)]
enum TokeError {
    Jwt(jsonwebtoken::errors::Error),
    Generic(String),
    Custom { exc: String, msg: String },
}

#[derive(Debug, Serialize)]
struct CompleteToken {
    header: Value,
    payload: Value,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

impl From<TokeError> for PyErr {
    fn from(err: TokeError) -> PyErr {
        match err {
            TokeError::Generic(s) => PyValueError::new_err(s),
            TokeError::Custom { exc, msg } => {
                match exc.as_str() {
                    "InvalidAudienceError" => InvalidAudienceError::new_err(msg),
                    "MissingRequiredClaimError" => MissingRequiredClaimError::new_err(msg),
                    "InvalidIssuerError" => InvalidIssuerError::new_err(msg),
                    _ => PyJWTError::new_err(msg),
                }
            },
            TokeError::Jwt(jwt_err) => {
                use jsonwebtoken::errors::ErrorKind;
                let msg = jwt_err.to_string();
                if msg.starts_with("JSON error") { return DecodeError::new_err(msg); }
                match jwt_err.kind() {
                    ErrorKind::ExpiredSignature => ExpiredSignatureError::new_err(msg),
                    ErrorKind::InvalidToken => DecodeError::new_err(msg),
                    ErrorKind::InvalidSignature => InvalidSignatureError::new_err(msg),
                    ErrorKind::InvalidAudience => InvalidAudienceError::new_err(msg),
                    ErrorKind::InvalidIssuer => InvalidIssuerError::new_err(msg),
                    ErrorKind::ImmatureSignature => ImmatureSignatureError::new_err(msg),
                    ErrorKind::MissingRequiredClaim(_) => MissingRequiredClaimError::new_err(msg),
                    ErrorKind::InvalidSubject => InvalidSubjectError::new_err("Invalid subject"),
                    _ => PyJWTError::new_err(msg),
                }
            }
        }
    }
}


// --- Low level JWS signing initial prep - in case someone wants JWS signing prom PyJWT

fn sign_raw_bytes(payload: &[u8], secret: &[u8]) -> Result<String, Error> {

    // 1. Manually construct the Header
    // We can use the library's Header struct to ensure JSON correctness
    let header = Header::new(Algorithm::HS256);
    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);

    // 2. Manually Base64 Encode the Payload (Skipping JSON serialization)
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

    // 3. Create the Signing Input (Header.Payload)
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // 4. Sign the input using the library's crypto primitive
    let key = EncodingKey::from_secret(secret);
    
    // `crypto::sign` returns the signature already base64 encoded
    let signature_b64 = sign(signing_input.as_bytes(), &key, Algorithm::HS256)?;

    // 5. Assemble
    Ok(format!("{}.{}", signing_input, signature_b64))
}


fn verify_raw_bytes(token: &str, secret: &[u8]) -> Result<bool, Error> {

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Ok(false); }

    let signature_b64 = parts[2];
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let key = DecodingKey::from_secret(secret);

    // `crypto::verify` expects:
    // 1. The signature string (b64 encoded)
    // 2. The raw bytes that were signed (header.payload)
    verify(signature_b64, signing_input.as_bytes(), &key, Algorithm::HS256).map_err(|e| e.into())
}


// -- Custom algorithm usage setup

static ALGORITHM_REGISTRY: OnceLock<RwLock<HashMap<String, Py<PyAny>>>> = OnceLock::new();

fn get_registry() -> &'static RwLock<HashMap<String, Py<PyAny>>> {
    ALGORITHM_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

#[pyfunction]
pub fn register_algorithm(name: &str, provider: Py<PyAny>) {
    let map_lock = get_registry();
    // We unwrap here because if the lock is poisoned, the app is already broken
    let mut map = map_lock.write().unwrap(); 
    map.insert(name.to_uppercase(), provider);
}

#[pyfunction]
pub fn unregister_algorithm(name: &str) {
    let map_lock = get_registry();
    let mut map = map_lock.write().unwrap();
    map.remove(&name.to_uppercase());
}


pub fn get_algorithm(py: Python, name: &str) -> Option<Py<PyAny>> {
    let map_lock = get_registry();
    let map = map_lock.read().unwrap();
    map.get(&name.to_uppercase()).map(|obj| obj.clone_ref(py))
}


// --- Helpers ---

fn is_hmac(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}


fn is_pem(key: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(key) {
        s.contains("-----BEGIN")
    } else { false }
}


fn ensure_key_is_private(key_bytes: &[u8]) -> PyResult<()> {
    // We check for standard PEM headers that indicate a Public Key
    if let Ok(s) = std::str::from_utf8(key_bytes) {
        if s.contains("BEGIN PUBLIC KEY") || s.contains("BEGIN RSA PUBLIC KEY") {
            return Err(PyValueError::new_err(
                "InvalidKeyError: You passed a Public Key to encode(). \
                 Signing requires a Private Key."
            ));
        }
    }
    Ok(())
}


fn handle_detached_content(token: &str, content: Option<&[u8]>) -> PyResult<String> {

    if let Some(content_bytes) = content {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { return Err(DecodeError::new_err("Invalid token format")); }
        if !parts[1].is_empty() { return Err(DecodeError::new_err("Expected detached payload but token has payload")); }
        
        let encoded_payload = URL_SAFE_NO_PAD.encode(content_bytes);
        Ok(format!("{}.{}.{}", parts[0], encoded_payload, parts[2]))
    } else {
        Ok(token.to_string())
    }
}


fn peek_algorithm(token: &str) -> PyResult<String> {
    let part = token.split('.').next()
        .ok_or_else(|| PyValueError::new_err("Invalid Token Format"))?;
    
    let bytes = URL_SAFE_NO_PAD.decode(part)
        .map_err(|_| PyValueError::new_err("Invalid Header Encoding"))?;
        
    let header: PartialHeader = serde_json::from_slice(&bytes)
        .map_err(|_| PyValueError::new_err("Invalid Header JSON"))?;
        
    Ok(header.alg)
}


fn get_key_bytes(py: Python, key: &Bound<'_, PyAny>, alg_name: &str, is_signing: bool) -> PyResult<Vec<u8>> {
    
    // 1. Extract Raw Bytes (Python -> Rust)
    let key_bytes = if let Ok(s) = key.extract::<String>() {
        s.into_bytes()
    } else if let Ok(b) = key.extract::<Vec<u8>>() {
        b
    } else {
        return Err(PyTypeError::new_err("Key must be string or bytes"));
    };

    // 2. Check Routing
    let is_plugin = get_algorithm(py, alg_name).is_some();
    let is_external = ExternalAlgorithm::from_str(alg_name).is_some();
    
    if is_plugin || is_external {
        // Return raw bytes immediately. Plugins/External verify keys themselves.
        return Ok(key_bytes);
    }

    // 3. Standard Algorithm Checks
    let alg = Algorithm::from_str(alg_name)
        .map_err(|_| PyValueError::new_err(format!("Algorithm '{}' not supported", alg_name)))?;

    // Safety: Don't use PEM for HMAC
    if is_hmac(alg) && is_pem(&key_bytes) {
        return Err(InvalidKeyError::new_err(
            "The specified key is an asymmetric key... should not be used as an HMAC secret."
        ));
    }

    // Safety: Don't use Public Key for Signing (Encode)
    if is_signing && !is_hmac(alg) {
        ensure_key_is_private(&key_bytes)?;
    }

    Ok(key_bytes)
}


fn extract_aud_iss(
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>
) -> PyResult<(Option<HashSet<String>>, Option<HashSet<String>>)> {
    
    let expected_aud = if let Some(aud) = audience {
        let mut s = HashSet::new();
        if let Ok(aud_str) = aud.extract::<String>() { 
            s.insert(aud_str); 
        } else if let Ok(aud_list) = aud.extract::<Vec<String>>() { 
            for a in aud_list { s.insert(a); } 
        }
        Some(s)
    } else { None };

    let expected_iss = if let Some(iss) = issuer {
        let mut s = HashSet::new();
        if let Ok(iss_str) = iss.extract::<String>() { 
            s.insert(iss_str); 
        } else if let Ok(iss_list) = iss.extract::<Vec<String>>() { 
            for i in iss_list { s.insert(i); } 
        }
        Some(s)
    } else { None };

    Ok((expected_aud, expected_iss))
}

// --- Validation Logic ---

fn prepare_validation(
    algorithms: Option<Vec<String>>,
    options: Option<&Bound<'_, PyDict>>,
    subject: Option<String>,
) -> PyResult<(Validation, bool, bool)> { 

    let alg_strs = algorithms.unwrap_or_else(|| vec!["HS256".to_string()]);
    let standard_algs: Vec<Algorithm> = alg_strs.iter().map(|s| Algorithm::from_str(s)).filter_map(Result::ok).collect();
    
    let mut validation = Validation::new(standard_algs.first().cloned().unwrap_or(Algorithm::HS256));
    validation.algorithms = standard_algs;
    validation.leeway = 0; 
    validation.validate_nbf = true; 
    validation.required_spec_claims.remove("exp"); 
    
    // Disable crate's internal checks for aud/iss so we can do it manually.
    // NOTE: validate_iss does not exist in standard jsonwebtoken struct, relying on iss=None default.
    validation.validate_aud = false; 
    validation.aud = None;
    validation.iss = None;

    // Track user preference
    let mut check_aud = true;
    let mut check_iss = true;

    if let Some(opts) = options {
        if let Ok(Some(v)) = opts.get_item("verify_exp") { validation.validate_exp = v.extract()?; }
        if let Ok(Some(v)) = opts.get_item("verify_nbf") { validation.validate_nbf = v.extract()?; }
        if let Ok(Some(v)) = opts.get_item("verify_aud") { check_aud = v.extract()?; } 
        if let Ok(Some(v)) = opts.get_item("verify_iss") { check_iss = v.extract()?; } 
        if let Ok(Some(v)) = opts.get_item("leeway") { validation.leeway = v.extract()?; }
        if let Ok(Some(req_list)) = opts.get_item("require") {
            if let Ok(reqs) = req_list.extract::<Vec<String>>() {
                for r in reqs { validation.required_spec_claims.insert(r); }
            }
        }
    }
    
    if let Some(sub) = subject { validation.sub = Some(sub); }
    Ok((validation, check_aud, check_iss))
}


fn validate_claims_content(
    claims: &Value, 
    validation: &Validation, 
    check_aud: bool,
    check_iss: bool,
    expected_aud: &Option<HashSet<String>>,
    expected_iss: &Option<HashSet<String>>
) -> Result<(), TokeError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    
    if validation.validate_exp {
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            if (exp as u64) < (now - validation.leeway) {
                return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature)));
            }
        } else if validation.required_spec_claims.contains("exp") {
             return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("exp".to_string()))));
        }
    }

    if validation.validate_nbf {
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if (nbf as u64) > (now + validation.leeway) {
                return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ImmatureSignature)));
            }
        }
    }

    if check_iss {
        if let Some(expected_issuers) = expected_iss {
            let token_iss_val = claims.get("iss");
            match token_iss_val {
                Some(Value::String(iss)) => {
                    if !expected_issuers.contains(iss) {
                        return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer)));
                    }
                },
                Some(_) => return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer))), 
                None => {
                    return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iss".to_string()))));
                }
            }
        } else if claims.get("iss").is_none() && validation.required_spec_claims.contains("iss") {
             return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iss".to_string()))));
        } else if let Some(iss_val) = claims.get("iss") {
             if !iss_val.is_string() {
                 return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer)));
             }
        }
    }

    if check_aud {
        let token_aud_val = claims.get("aud");
        
        //-- Handle Expected Audience Check (We know who we are)
        if let Some(expected_auds) = expected_aud {
            // Check Missing or Null
            if token_aud_val.is_none() || token_aud_val == Some(&Value::Null) {
                return Err(TokeError::Custom{ exc: "MissingRequiredClaimError".into(), msg: "Missing required claim: aud".into() });
            }

            // Check Types
            let token_auds: Vec<String> = match token_aud_val {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(arr)) => {
                    let mut strs = Vec::new();
                    for v in arr {
                        if let Some(s) = v.as_str() { strs.push(s.to_string()); } 
                        else { 
                            return Err(TokeError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() });
                        }
                    }
                    strs
                },
                Some(_) => {
                    return Err(TokeError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() });
                },
                None => Vec::new(), 
            };
            
            if !token_auds.iter().any(|ta| expected_auds.contains(ta)) {
                return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAudience)));
            }
        }

        //-- Handle No Expected Audience (We didn't say who we are)
        else if let Some(val) = token_aud_val {
             // PyJWT Rule: If aud is present and "truthy", but no audience was specified, FAIL.
             let is_truthy = match val {
                 Value::Null => false,
                 Value::String(s) => !s.is_empty(),
                 Value::Array(a) => !a.is_empty(),
                 Value::Bool(b) => *b, // Uncommon but possible in JSON
                 _ => true, // Numbers, Objects are truthy
             };

             if is_truthy {
                 return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAudience)));
             }
        } else if validation.required_spec_claims.contains("aud") {
             return Err(TokeError::Custom{ exc: "MissingRequiredClaimError".into(), msg: "Missing required claim: aud".into() });
        }
    }
    
    // Check explicitly required claims
    for req in &validation.required_spec_claims {
        if !claims.get(req).is_some() {
             return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(req.clone()))));
        }
    }
    Ok(())
}


// --- Rust level Encode / Decode implementations (no GIL parts)

fn decode_impl(
    token: String,
    key_bytes: Vec<u8>,
    validation: Validation,
    verify: bool,
    check_iat: bool,
    check_aud: bool,
    check_iss: bool,
    expected_aud: Option<HashSet<String>>,
    expected_iss: Option<HashSet<String>>,
) -> Result<Value, TokeError> {

    let claims = if !verify {
        let token_data = insecure_decode::<Value>(&token)
            .map_err(|e| TokeError::Generic(format!("Invalid token: {}", e)))?;
        token_data.claims
    } else {
        let decoding_key = if is_hmac(validation.algorithms[0]) {
            DecodingKey::from_secret(&key_bytes)
        } else {
            DecodingKey::from_rsa_pem(&key_bytes)
                .or_else(|_| DecodingKey::from_ec_pem(&key_bytes))
                .or_else(|_| DecodingKey::from_ed_pem(&key_bytes))
                .map_err(|e| TokeError::Generic(format!("Invalid PEM key: {}", e)))?
        };
        let token_data = jwt_decode::<Value>(&token, &decoding_key, &validation).map_err(TokeError::Jwt)?;
        token_data.claims
    };

    validate_claims_content(&claims, &validation, check_aud, check_iss, &expected_aud, &expected_iss)?;

    if check_iat {
        if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            if iat as u64 > (now + validation.leeway) {
                return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ImmatureSignature)));
            }
        }
    }

    Ok(claims)
}


fn encode_none_impl(payload: Value, headers: Option<Value>) -> Result<String, TokeError> {
    
    let mut header_map = match headers { Some(Value::Object(map)) => map, _ => Map::new(), };
    header_map.insert("typ".to_string(), Value::String("JWT".to_string()));
    header_map.insert("alg".to_string(), Value::String("none".to_string()));
    let header_val = Value::Object(header_map);
    let header_json = serde_json::to_vec(&header_val).map_err(|e| TokeError::Generic(format!("Header serialization failed: {}", e)))?;
    let payload_json = serde_json::to_vec(&payload).map_err(|e| TokeError::Generic(format!("Payload serialization failed: {}", e)))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    Ok(format!("{}.{}.", header_b64, payload_b64))
}


fn encode_impl(payload_val: Value, key_bytes: Vec<u8>, algorithm: &str, headers: Option<Value>) -> Result<String, TokeError> {
    
    // -- Check if internal non jsonwebtoken supported algos (ML-DSA, ES512)
    if let Some(ext_alg) = ExternalAlgorithm::from_str(algorithm) {
        
        // Manual JSON Header Construction
        let mut header_map = match headers { Some(Value::Object(map)) => map, _ => Map::new() };
        header_map.insert("alg".to_string(), Value::String(algorithm.to_string()));
        header_map.insert("typ".to_string(), Value::String("JWT".to_string()));
        
        // Serialization
        let header_json = serde_json::to_vec(&header_map).map_err(|e| TokeError::Generic(e.to_string()))?;
        let payload_json = serde_json::to_vec(&payload_val).map_err(|e| TokeError::Generic(e.to_string()))?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let signature = ext_alg.sign(signing_input.as_bytes(), &key_bytes)?;
        
        return Ok(format!("{}.{}", signing_input, signature));
    }

    // -- Check if standard jsonwebtoken supported algos (The ones in Algorithm)
    let alg = Algorithm::from_str(algorithm)
        .map_err(|_| TokeError::Generic(format!("encode_impl() - Algorithm '{}' not supported", algorithm)))?;

    let mut header = Header::new(alg);
    if let Some(h) = headers {
        if let Some(kid) = h.get("kid").and_then(|v| v.as_str()) { header.kid = Some(kid.to_string()); }
        if let Some(typ) = h.get("typ").and_then(|v| v.as_str()) { header.typ = Some(typ.to_string()); }
    }
    let encoding_key = if is_hmac(alg) { EncodingKey::from_secret(&key_bytes) } else {
        EncodingKey::from_rsa_pem(&key_bytes).or_else(|_| EncodingKey::from_ec_pem(&key_bytes))
            .or_else(|_| EncodingKey::from_ed_pem(&key_bytes)).map_err(|e| TokeError::Generic(format!("Invalid PEM key: {}", e)))?
    };
    jwt_encode(&header, &payload_val, &encoding_key).map_err(|e| TokeError::Generic(format!("Encode failed: {}", e)))


}


fn decode_none_impl(token: &str, verify: bool, algorithms: &Option<Vec<String>>) -> Result<Value, TokeError> {
    
    let allowed = if !verify { true } else { match algorithms { Some(algs) => algs.iter().any(|a| a.eq_ignore_ascii_case("none")), None => false, } };
    if !allowed { return Err(TokeError::Generic("Algorithm 'none' is not allowed".to_string())); }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(TokeError::Generic("Invalid token format".to_string())); }
    let header_json = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| TokeError::Generic(format!("Invalid header base64: {}", e)))?;
    let header: Value = serde_json::from_slice(&header_json).map_err(|e| TokeError::Generic(format!("Invalid header json: {}", e)))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("none") { return Err(TokeError::Generic("Header algorithm mismatch".to_string())); }
    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| TokeError::Generic(format!("Invalid payload base64: {}", e)))?;
    let claims: Value = serde_json::from_slice(&payload_json).map_err(|e| TokeError::Generic(format!("Invalid payload json: {}", e)))?;
    Ok(claims)
}


fn decode_complete_impl(token: String, key_bytes: Vec<u8>, validation: Validation, verify: bool, check_iat: bool, check_aud: bool, check_iss: bool, aud: Option<HashSet<String>>, iss: Option<HashSet<String>>) -> Result<CompleteToken, TokeError> {

    let header = jwt_decode_header(&token).map_err(TokeError::Jwt)?;
    let header_val = serde_json::to_value(&header).map_err(|e| TokeError::Generic(format!("Header error: {}", e)))?;
    
    let claims = decode_impl(token.clone(), key_bytes, validation, verify, check_iat, check_aud, check_iss, aud, iss)?;
    let parts: Vec<&str> = token.split('.').collect();
    let signature = if parts.len() == 3 { URL_SAFE_NO_PAD.decode(parts[2]).unwrap_or_default() } else { Vec::new() };
    Ok(CompleteToken { header: header_val, payload: claims, signature })
}


// --- Public Python API 

#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", headers=None))]
fn encode(py: Python, payload: &Bound<'_, PyAny>, key: &Bound<'_, PyAny>, algorithm: &str, headers: Option<&Bound<'_, PyDict>>) -> PyResult<String> {
    
    // 1. Serialization
    let mut claims: Value = depythonize(payload).map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))?;
    if let Some(obj) = claims.as_object_mut() {
        for field in ["exp", "iat", "nbf"] {
            if let Some(val) = obj.get(field).and_then(|v| v.as_f64()) { obj.insert(field.to_string(), serde_json::json!(val as i64)); }
        }
    }

    let header_val: Option<Value> = if let Some(h) = headers { 
        Some(depythonize(h).map_err(|e| PyValueError::new_err(format!("Header error: {}", e)))?) 
    } else { None };
    
    // 2. "None" Algo shortcut
    if algorithm.eq_ignore_ascii_case("none") { return py.detach(move || { encode_none_impl(claims, header_val) }).map_err(Into::into); }
    
    // 3. Unified Key Extraction
    let key_bytes = get_key_bytes(py, key, algorithm, true)?;

    // 4. Dispatch
    py.detach(move || {encode_impl(claims, key_bytes, algorithm, header_val)}).map_err(Into::into)
}


#[pyfunction]
#[pyo3(signature = (token, key, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None))]
fn decode<'py>(
    py: Python<'py>, 
    token: &str, 
    key: Option<&Bound<'py, PyAny>>, 
    algorithms: Option<Vec<String>>, 
    options: Option<&Bound<'py, PyDict>>, 
    audience: Option<&Bound<'py, PyAny>>, 
    issuer: Option<&Bound<'py, PyAny>>, 
    subject: Option<String>, 
    verify: bool, 
    content: Option<&[u8]>
) -> PyResult<Bound<'py, PyAny>> {
    
    // 1. Peek Header
    let alg_str = peek_algorithm(token)?;

    // 2. Allowed Algo Check
    if verify {
        if let Some(algs) = &algorithms {
            if !algs.iter().any(|a| a.eq_ignore_ascii_case(&alg_str)) {
                return Err(PyValueError::new_err(format!("Algorithm '{}' is not allowed", alg_str)));
            }
        }
    }
    
    // 3. Parsing Options
    // (Note: You could move this into prepare_validation too, but keeping it here is fine for now)
    let mut effective_verify = verify;
    let mut check_iat = true;
    if let Some(opts) = options {
        if let Ok(Some(v)) = opts.get_item("verify_signature") { if let Ok(b) = v.extract::<bool>() { effective_verify = b; } }
        if let Ok(Some(v)) = opts.get_item("verify_iat") { if let Ok(b) = v.extract::<bool>() { check_iat = b; } }
    }
    
    let token_string = handle_detached_content(token, content)?;

    // 4. "None" Algo
    if alg_str.eq_ignore_ascii_case("none") {
        let allowed = if !effective_verify { true } else { algorithms.as_ref().map_or(false, |algs| algs.iter().any(|x| x.eq_ignore_ascii_case("none"))) };
        if !allowed { return Err(InvalidTokenError::new_err("Algorithm 'none' is not allowed")); }
        let claims = py.detach(move || { decode_none_impl(&token_string, effective_verify, &algorithms) }).map_err(PyErr::from)?;
        return pythonize(py, &claims).map_err(|e| PyValueError::new_err(format!("Output failed: {}", e)));
    }

    // 5. Get Key (Unified)
    // We handle the "Key required if verify=True" check here
    let key_bytes = if effective_verify {
        match key {
            Some(k) => get_key_bytes(py, k, &alg_str, false)?,
            None => return Err(PyValueError::new_err("Key required for verification")),
        }
    } else {
        Vec::new()
    };

    // 6. Branch: Custom Plugin (Must happen in Python thread)
    // We check registry directly here because plugins need the GIL
    if let Some(plugin) = get_algorithm(py, &alg_str) {
        let claims = py.detach(move || -> PyResult<Value> {
             // ... manual verify flow code (can extract to helper if used in Validator) ...
             // For now, keeping it inline is okay, or move logic to `verifier.rs` as discussed in previous turn
             Err(PyValueError::new_err("Plugin logic")) // Placeholder for brevity
        })?;
        return pythonize(py, &claims).map_err(Into::into);
    } 

    // 7. Branch: Native (External OR Standard)
    // Since we unified key extraction, we can technically push External vs Standard logic 
    // entirely into `decode_impl` if we wanted to, but keeping the setup here is safer for `validation` struct prep.

    let (validation, check_aud, check_iss) = prepare_validation(algorithms, options, subject)?;
    
    // Manual Aud/Iss Extraction
    let (expected_aud, expected_iss) = extract_aud_iss(audience, issuer)?;

    let claims = py.detach(move || {
        decode_impl(token_string, key_bytes, validation, effective_verify, check_iat, check_aud, check_iss, expected_aud, expected_iss)
    }).map_err(PyErr::from)?;
    
    pythonize(py, &claims).map_err(|e| PyValueError::new_err(format!("Output failed: {}", e)))
}


#[pyfunction]
#[pyo3(signature = (token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None))]
fn decode_complete<'py>(py: Python<'py>, token: &str, key: Option<&Bound<'py, PyAny>>, algorithms: Option<Vec<String>>, options: Option<&Bound<'py, PyDict>>, audience: Option<&Bound<'py, PyAny>>, issuer: Option<&Bound<'py, PyAny>>, subject: Option<String>, verify: bool, content: Option<&[u8]>) -> PyResult<Bound<'py, PyAny>> {
    
    let mut effective_verify = verify;
    let mut check_iat = true;
    if let Some(opts) = options {
        if let Ok(Some(v)) = opts.get_item("verify_signature") { if let Ok(b) = v.extract::<bool>() { effective_verify = b; } }
        if let Ok(Some(v)) = opts.get_item("verify_iat") { if let Ok(b) = v.extract::<bool>() { check_iat = b; } }
    }
    let token_string = handle_detached_content(token, content)?;
    
    let (validation, check_aud, check_iss) = prepare_validation(algorithms.clone(), options, subject)?;
    
    let mut expected_aud = None;
    if let Some(aud) = audience {
        let mut s = HashSet::new();
        if let Ok(aud_str) = aud.extract::<String>() { s.insert(aud_str); } 
        else if let Ok(aud_list) = aud.extract::<Vec<String>>() { for a in aud_list { s.insert(a); } }
        expected_aud = Some(s);
    }
    let mut expected_iss = None;
    if let Some(iss) = issuer {
        let mut s = HashSet::new();
        if let Ok(iss_str) = iss.extract::<String>() { s.insert(iss_str); } 
        else if let Ok(iss_list) = iss.extract::<Vec<String>>() { for i in iss_list { s.insert(i); } }
        expected_iss = Some(s);
    }

    let alg_str = peek_algorithm(token).unwrap_or_else(|_| "HS256".to_string());
    let alg = Algorithm::from_str(&alg_str).unwrap_or(Algorithm::HS256);
    let key_bytes = if effective_verify {
        match key {
            Some(k) => get_key_bytes(py, k, &alg_str, false)?,
            None => return Err(PyValueError::new_err("Key required for verification")),
        }
    } else {
        Vec::new()
    };    
    let result = py.detach(move || { 
        decode_complete_impl(token_string, key_bytes, validation, effective_verify, check_iat, check_aud, check_iss, expected_aud, expected_iss) 
    }).map_err(PyErr::from)?;
    pythonize(py, &result).map_err(|e| PyValueError::new_err(format!("Output failed: {}", e)))
}


#[pyfunction]
#[pyo3(signature = (token))]
fn get_unverified_header<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let header = jwt_decode_header(token)
        .map_err(|e| PyValueError::new_err(format!("Invalid header: {}", e)))?;
    pythonize(py, &header).map_err(|e| PyValueError::new_err(format!("Output failed: {}", e)))
}


#[pyfunction]
fn unsafe_peek<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
         return Err(PyValueError::new_err("Invalid Token Format"));
    }
    
    let payload_part = parts[1];
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_part)
         .map_err(|_| PyValueError::new_err("Invalid Payload Base64"))?;
         
    let claims: Value = serde_json::from_slice(&payload_bytes)
         .map_err(|_| PyValueError::new_err("Invalid Payload JSON"))?;
         
    Ok(pythonize(py, &claims).unwrap())
}



#[pymodule]
fn toke(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PyJWTError", py.get_type::<PyJWTError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add("DecodeError", py.get_type::<DecodeError>())?;
    m.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
    m.add("ExpiredSignatureError", py.get_type::<ExpiredSignatureError>())?;
    m.add("InvalidAudienceError", py.get_type::<InvalidAudienceError>())?;
    m.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
    m.add("ImmatureSignatureError", py.get_type::<ImmatureSignatureError>())?;
    m.add("MissingRequiredClaimError", py.get_type::<MissingRequiredClaimError>())?;
    m.add("InvalidIssuedAtError", py.get_type::<InvalidIssuedAtError>())?;
    m.add("InvalidJTIError", py.get_type::<InvalidJTIError>())?;
    m.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;

    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_complete, m)?)?;
    m.add_function(wrap_pyfunction!(get_unverified_header, m)?)?;
    m.add_function(wrap_pyfunction!(unsafe_peek, m)?)?;
    m.add_function(wrap_pyfunction!(register_algorithm, m)?)?;
    m.add_function(wrap_pyfunction!(unregister_algorithm, m)?)?;

    // Testing comfort logic to use from Python
    m.add_function(wrap_pyfunction!(keygen::generate_key_pair, m)?)?;

    m.add_class::<PyJwk>()?;
    m.add_class::<PyJwkSet>()?;
    jwk_api::register_jwk_module(py, m)?;

    Ok(())
}