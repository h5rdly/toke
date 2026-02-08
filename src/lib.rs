use std::str::FromStr;
use std::collections::{HashSet, HashMap};
use std::sync::{OnceLock, RwLock};

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, 
};

use serde_json::{from_str, from_slice, to_vec, Value, Map, map::Entry};
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}};
use time::{OffsetDateTime, PrimitiveDateTime};

use pyo3::prelude::*;
use pyo3::exceptions::{PyTypeError, PyValueError, PyNotImplementedError};
use pyo3::types::{PyBytes, PyDict, PyModule, PyString};
use pyo3::{wrap_pyfunction}; 
use pythonize::{depythonize, pythonize};

mod algorithms; 
mod crypto; 
mod jwk;
mod jws;
mod py_utils;
pub mod pyjwt_jwk_api;

use crate::algorithms::{ExternalAlgorithm, perform_signature, perform_verification};
use crate::pyjwt_jwk_api::{PyJWK, PyJWKSet, perform_signature_jwk, perform_verification_jwk};
use crate::py_utils::decode_base64_permissive;


#[macro_export]
macro_rules! err_loc {
    ($($arg:tt)*) => {
        format!("[{}:{}] {}", file!(), line!(), format!($($arg)*))
    };
}

macro_rules! exc {
    ($name:ident, $base:path) => {
        pyo3::create_exception!(webtoken, $name, $base);
    }
}

exc!(PyJWTError, pyo3::exceptions::PyException);
exc!(InvalidTokenError, PyJWTError);
exc!(DecodeError, InvalidTokenError);
exc!(InvalidSignatureError, DecodeError);
exc!(ExpiredSignatureError, InvalidTokenError);
exc!(InvalidAudienceError, InvalidTokenError);
exc!(InvalidIssuerError, InvalidTokenError);
exc!(ImmatureSignatureError, InvalidTokenError);
exc!(MissingRequiredClaimError, InvalidTokenError);
exc!(InvalidIssuedAtError, InvalidTokenError);
exc!(InvalidJTIError, InvalidTokenError);
exc!(InvalidSubjectError, InvalidTokenError);
exc!(InvalidAlgorithmError, InvalidTokenError);
exc!(InvalidKeyError, PyJWTError);

#[derive(Deserialize)]
struct PartialHeader {
    alg: String,
}

#[derive(Debug)]
pub enum WebtokenError {
    Jwt(jsonwebtoken::errors::Error),
    Generic(String),
    Custom { exc: String, msg: String },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum TokenPayload {
    Claims(Value),
    Raw(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Serialize)]
struct CompleteToken {
    header: Value,
    payload: TokenPayload,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

impl std::fmt::Display for WebtokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebtokenError::Jwt(e) => write!(f, "{}", e),
            WebtokenError::Generic(s) => write!(f, "{}", s),
            WebtokenError::Custom { exc, msg } => write!(f, "{}: {}", exc, msg),
        }
    }
}


impl From<WebtokenError> for PyErr {
    fn from(err: WebtokenError) -> PyErr {
        match err {
            WebtokenError::Generic(s) => PyValueError::new_err(s),
            WebtokenError::Custom { exc, msg } => {
                match exc.as_str() {
                    "InvalidAudienceError" => InvalidAudienceError::new_err(msg),
                    "MissingRequiredClaimError" => MissingRequiredClaimError::new_err(msg),
                    "InvalidIssuerError" => InvalidIssuerError::new_err(msg),
                    "InvalidSignatureError" => InvalidSignatureError::new_err(msg),
                    "DecodeError" => DecodeError::new_err(msg),
                    "InvalidSubjectError" => InvalidSubjectError::new_err(msg),
                    "InvalidIssuedAtError" => InvalidIssuedAtError::new_err(msg),
                    "InvalidJTIError" => InvalidJTIError::new_err(msg),
                    "ExpiredSignatureError" => ExpiredSignatureError::new_err(msg),
                    "ImmatureSignatureError" => ImmatureSignatureError::new_err(msg),
                    "InvalidKeyError" => InvalidKeyError::new_err(msg),
                    "InvalidAlgorithmError" => InvalidAlgorithmError::new_err(msg),
                    _ => PyJWTError::new_err(msg),
                }
            },
            WebtokenError::Jwt(jwt_err) => {
                use jsonwebtoken::errors::ErrorKind;
                let msg = jwt_err.to_string();
                if msg.starts_with("JSON error") { return DecodeError::new_err(msg); }
                match jwt_err.kind() {
                    ErrorKind::ExpiredSignature => ExpiredSignatureError::new_err(msg),
                    ErrorKind::InvalidToken => DecodeError::new_err(msg),
                    ErrorKind::InvalidSignature => InvalidSignatureError::new_err("Signature verification failed"),
                    ErrorKind::InvalidAudience => InvalidAudienceError::new_err(msg),
                    ErrorKind::InvalidIssuer => InvalidIssuerError::new_err(msg),
                    ErrorKind::ImmatureSignature => ImmatureSignatureError::new_err(msg),
                    ErrorKind::MissingRequiredClaim(_) => MissingRequiredClaimError::new_err(msg),
                    ErrorKind::InvalidSubject => InvalidSubjectError::new_err("Invalid subject"),
                    ErrorKind::InvalidAlgorithm => InvalidAlgorithmError::new_err(msg),
                    
                    _ => PyJWTError::new_err(msg),
                }
            }
        }
    }
}


// --- Algorithm Registry ---

static ALGORITHM_REGISTRY: OnceLock<RwLock<HashMap<String, Py<PyAny>>>> = OnceLock::new();

fn get_registry() -> &'static RwLock<HashMap<String, Py<PyAny>>> {
    ALGORITHM_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}


#[pyfunction]
#[pyo3(signature = (message, key, algorithm))]
fn raw_sign(message: &[u8], key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<Vec<u8>> {
    let key_bytes = get_key_bytes(key, algorithm, true, false)?;
    
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        return perform_signature_jwk(message, &jwk, algorithm).map_err(Into::into); 
    }

    perform_signature(message, &key_bytes, algorithm)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}


#[pyfunction]
#[pyo3(signature = (message, signature, key, algorithm))]
fn raw_verify(message: &[u8], signature: &[u8], key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<bool> {
    let key_bytes = get_key_bytes(key, algorithm, false, false)?;
    
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        return perform_verification_jwk(message, signature, &jwk, algorithm).map_err(Into::into); 
    }

    // [FIX] Always use perform_verification.
    perform_verification(message, signature, &key_bytes, algorithm)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}


#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", headers=None, sort_headers=true, check_length=false))] // [FIX] Added arg
fn sign(
    payload: &Bound<'_, PyAny>, 
    key: &Bound<'_, PyAny>, 
    algorithm: &str, 
    headers: Option<&Bound<'_, PyDict>>,
    sort_headers: bool,
    check_length: bool, 
) -> PyResult<String> {
    
    let header_map = prepare_headers(algorithm, headers, sort_headers)?;
    let payload_slice = payload.extract::<&[u8]>().map_err(|_| PyTypeError::new_err("Payload must be string or bytes"))?;

    let (header_b64, payload_b64, signing_input) = jws::prepare_jws_parts(&header_map, &payload_slice).map_err(Into::<PyErr>::into)?;
    let detached = header_map.get("b64") == Some(&Value::Bool(false));
    let key_bytes = get_key_bytes(key, algorithm, true, check_length)?;

    jws::sign_output(&signing_input, &header_b64, &payload_b64, &key_bytes, algorithm, detached)
        .map_err(Into::into)
}


#[pyfunction]
#[pyo3(signature = (token, key, algorithm))]
fn verify(py: Python, token: &Bound<'_, PyAny>, key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<(Py<PyAny>, Py<PyBytes>)> {
    let token_str = extract_token_str(token)?;
    let alg_norm = algorithm.to_uppercase();
    let key_bytes = get_key_bytes(key, &alg_norm, false, false)?;
    
    let (header, payload) = jws::verify_bytes(&token_str, &key_bytes, &alg_norm).map_err(Into::<PyErr>::into)?;
    let py_header = pythonize::pythonize(py, &header).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((py_header.unbind(), PyBytes::new(py, &payload).unbind()))
}


#[pyfunction]
#[pyo3(signature = (key_data, algorithm=None))]
fn load_jwk(key_data: &Bound<'_, PyAny>, algorithm: Option<String>) -> PyResult<PyJWK> {
    crate::pyjwt_jwk_api::from_jwk(key_data, algorithm.as_deref().unwrap_or_default())
}


#[pyfunction]
fn load_jwk_set(data: &Bound<'_, PyAny>) -> PyResult<PyJWKSet> {
    crate::pyjwt_jwk_api::from_jwk_set(data)
}


fn map_curve_name_for_error(name: &str) -> &str {
    match name {
        "P-256" => "secp256r1",
        "P-384" => "secp384r1",
        "P-521" => "secp521r1",
        "P-192" => "secp192r1",
        _ => name
    }
}

#[pyfunction]
#[pyo3(signature = (key, expected_kty, expected_crv=None))]
fn validate_key_properties(key: &PyJWK, expected_kty: &str, expected_crv: Option<&str>) -> PyResult<()> {
    // 1. Validate Key Type (kty)
    let kty = key.inner.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    if kty != expected_kty {
        // e.g. "Invalid key type: RSA. Expected EC."
        return Err(InvalidKeyError::new_err(format!("Invalid key type: {}. Expected {}.", kty, expected_kty)));
    }
    
    // 2. Validate Curve (crv) if expected
    if let Some(req_crv) = expected_crv {
        let crv = key.inner.get("crv").and_then(|v| v.as_str())
            .ok_or_else(|| InvalidKeyError::new_err(format!("{} key missing 'crv'", expected_kty)))?;
        
        if crv != req_crv {
            // Use the mapping helper to generate the specific error message PyJWT tests expect
            let mapped_actual = map_curve_name_for_error(crv);
            let mapped_expected = map_curve_name_for_error(req_crv);
            
            return Err(InvalidKeyError::new_err(format!(
                "Key curve {} does not match algorithm curve {}.", 
                mapped_actual, mapped_expected
            )));
        }
    }
    Ok(())
}

#[pyfunction]
pub fn register_algorithm(name: &str, provider: Py<PyAny>) {
    let map_lock = get_registry();
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


fn sort_map(map: &mut Map<String, Value>) {
    let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in entries {
        map.insert(k, v);
    }
}


fn looks_like_public_key(key: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(key) {
        let s = s.trim();
        s.starts_with("-----BEGIN") 
        || s.starts_with("ssh-") 
        || s.starts_with("ecdsa-")
    } else { 
        false 
    }
}


fn handle_detached_content(token: &str, content: Option<&[u8]>) -> PyResult<String> {
    if let Some(c) = content {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { return Err(DecodeError::new_err("Not enough segments")); }
        Ok(format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(c), parts[2]))
    } else { 
        Ok(token.to_string()) 
    }
}



fn peek_algorithm(token: &str) -> PyResult<String> {
    let part = token.split('.').next()
        .ok_or_else(|| PyValueError::new_err("Invalid Token Format"))?;
    
    let bytes = base64url_decode_inner(part)
        .map_err(|_| PyValueError::new_err("Invalid Header Encoding"))?;
        
    let header: PartialHeader = from_slice(&bytes)
        .map_err(|_| PyValueError::new_err("Invalid Header JSON"))?;
        
    Ok(header.alg)
}


fn extract_token_str(token: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(s) = token.extract::<String>() { Ok(s) }
    else if let Ok(b) = token.extract::<&[u8]>() { std::str::from_utf8(b).map(|s| s.to_string())
        .map_err(|_| DecodeError::new_err("Invalid token type")) }
    else { Err(DecodeError::new_err("Invalid token type. Token must be a <class 'bytes'>")) }
}


fn get_key_bytes(key: &Bound<'_, PyAny>, alg_name: &str, is_signing: bool, check_length: bool) -> PyResult<Vec<u8>> {

    if let Ok(jwk) = key.extract::<PyJWK>() { return jwk.to_key_bytes(!is_signing); }
    
    if alg_name.eq_ignore_ascii_case("none") { return Ok(Vec::new()); }

    let mut key_bytes = if let Ok(s) = key.extract::<String>() { s.into_bytes() }
    else if let Ok(b) = key.extract::<Vec<u8>>() { b }
    else { return Err(PyTypeError::new_err("Key must be string or bytes")); };

    if let Ok(s) = std::str::from_utf8(&key_bytes) {
        if s.starts_with("ssh-") || s.starts_with("ecdsa-") {
            if let Ok(pem) = crate::crypto::ssh_to_pem(&key_bytes) { key_bytes = pem; }
        }
    }
    
    if ExternalAlgorithm::from_str(alg_name).is_some() { return Ok(key_bytes); }
    let alg = Algorithm::from_str(alg_name).map_err(|_| PyNotImplementedError::new_err(format!("Algorithm '{}' not supported", alg_name)))?;
    
    if is_hmac(alg) {
        if looks_like_public_key(&key_bytes) { 
            return Err(InvalidKeyError::new_err("The specified key is an asymmetric key... should not be used as an HMAC secret.")); 
        }
        
        // [NEW] Validation Logic
        if check_length {
            let min_len = match alg {
                Algorithm::HS256 => 32,
                Algorithm::HS384 => 48,
                Algorithm::HS512 => 64,
                _ => 0,
            };
            if key_bytes.len() < min_len {
                return Err(InvalidKeyError::new_err(format!(
                    "The specified key is {} bytes long, which is below the minimum recommended length of {} bytes.",
                    key_bytes.len(), min_len
                )));
            }
        }
    }
    Ok(key_bytes)
}


fn get_decoding_key(key: &Bound<'_, PyAny>, alg_str: &str, check_length: bool) -> PyResult<DecodingKey> {
    
    // 1. Parse Algorithm first (needed for validation)
    let alg = Algorithm::from_str(alg_str)
        .map_err(|_| InvalidAlgorithmError::new_err("Algorithm not supported"))?;

    // 2. Handle PyJWK (Pass alg for validation)
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        return jwk.to_decoding_key(alg).map_err(PyErr::from); 
    }

    // 3. Handle Raw Bytes/PEM
    let key_bytes = get_key_bytes(key, alg_str, false, false)?;
    
    if check_length && is_hmac(alg) {
        let min_len = match alg {
            Algorithm::HS256 => 32, Algorithm::HS384 => 48, Algorithm::HS512 => 64, _ => 0,
        };
        if key_bytes.len() < min_len {
            return Err(InvalidKeyError::new_err(format!(
                "The specified key is {} bytes long, which is below the minimum recommended length of {} bytes.",
                key_bytes.len(), min_len
            )));
        }
    }

    let decoding_key = if is_hmac(alg) { DecodingKey::from_secret(&key_bytes) } else {
        let try_ed = DecodingKey::from_ed_pem(&key_bytes);
        if try_ed.is_ok() { try_ed.unwrap() } else {
            let try_rsa = DecodingKey::from_rsa_pem(&key_bytes);
            if try_rsa.is_ok() { try_rsa.unwrap() } else {
                let try_ec = DecodingKey::from_ec_pem(&key_bytes);
                if try_ec.is_ok() { try_ec.unwrap() } else { return Err(PyValueError::new_err("Invalid PEM key: could not parse as RSA, EC, or EdDSA")); }
            }
        }
    };

    Ok(decoding_key)
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
        } else {
            // [FIX] Distinguish between bytes (InvalidAudience) and other types (TypeError)
            if aud.is_instance_of::<PyBytes>() {
                return Err(InvalidAudienceError::new_err("audience must be a string, iterable or None"));
            }
            return Err(PyTypeError::new_err("audience must be a string, iterable or None"));
        }
        Some(s)
    } else { None };

    let expected_iss = if let Some(iss) = issuer {
        let mut s = HashSet::new();
        if let Ok(iss_str) = iss.extract::<String>() { 
            s.insert(iss_str); 
        } else if let Ok(iss_list) = iss.extract::<Vec<String>>() {
            for i in iss_list { s.insert(i); } 
        } else {
            // [FIX] Distinguish between bytes (InvalidIssuer) and other types (TypeError)
            if iss.is_instance_of::<PyBytes>() {
                return Err(InvalidIssuerError::new_err("issuer must be a string, iterable or None"));
            }
            return Err(PyTypeError::new_err("issuer must be a string, iterable or None"));
        }
        Some(s)
    } else { None };

    Ok((expected_aud, expected_iss))
}


fn is_numeric(v: &Value) -> bool {
    if v.is_number() { return true; }
    if let Some(s) = v.as_str() {
        return s.parse::<f64>().is_ok();
    }
    false
}

fn get_numeric_date(v: &Value) -> Option<f64> {
    if let Some(n) = v.as_f64() { return Some(n); }
    if let Some(s) = v.as_str() { return s.parse::<f64>().ok(); }
    None
}


fn prepare_headers(algorithm: &str, headers: Option<&Bound<'_, PyDict>>, sort_headers: bool) -> PyResult<Map<String, Value>> {

    let mut header_map = match headers {
        Some(h) => depythonize(h).map_err(|e| PyTypeError::new_err(format!("Invalid header: {}", e)))?,
        None => Map::new() 
    };

    if !header_map.contains_key("alg") {
        header_map.insert("alg".to_string(), Value::String(algorithm.to_string()));
    }

    if header_map.get("kid").is_some_and(|kid| !kid.is_string()) {
        return Err(InvalidTokenError::new_err("Key ID header parameter must be a string"));
    }

    if let Some(Value::Bool(true)) = header_map.get("b64") {
        header_map.remove("b64");   // RFC 7797: If b64 is True (default), it can be omitted
    }

    match header_map.entry("typ") {
        Entry::Occupied(entry) => {
            let val = entry.get();
            if val.is_null() || val.as_str().is_some_and(|s| s.is_empty()) {
                entry.remove_entry();
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(Value::String("JWT".to_string()));
        }
    }

    if sort_headers {
        sort_map(&mut header_map);
    }

    Ok(header_map)
}


fn prepare_validation(algorithms: Option<Vec<String>>, options: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<(Validation, bool, bool, bool, bool, bool, bool, bool)> { 

    let alg_strs = algorithms.unwrap_or_else(|| vec!["HS256".to_string()]);
    let mut standard_algs = Vec::new();
    for s in &alg_strs {
        if let Ok(a) = Algorithm::from_str(s) { standard_algs.push(a); }
    }
    
    let base_alg = standard_algs.first().cloned().unwrap_or(Algorithm::HS256);
    let mut validation = Validation::new(base_alg);
    if !standard_algs.is_empty() { validation.algorithms = standard_algs; } 

    validation.leeway = 0; 
    
    validation.validate_exp = false; 
    validation.validate_nbf = false; 
    validation.validate_aud = false; 
    
    validation.required_spec_claims.remove("exp"); 
    validation.aud = None;
    validation.iss = None;

    let mut check_exp = true;
    let mut check_nbf = true;
    let mut check_iat = true;
    let mut check_aud = true;
    let mut check_iss = true;
    let mut check_sub = true;
    let mut strict_aud = false;

    if let Some(opts) = options {
        macro_rules! update {
            ($key:literal, $target:expr) => {
                if let Some(val) = opts.get_item($key)? { $target = val.extract()?; }
            };
        }
        update!("verify_exp", check_exp);
        update!("verify_nbf", check_nbf);
        update!("verify_iat", check_iat);
        update!("verify_aud", check_aud);
        update!("verify_iss", check_iss);
        update!("verify_sub", check_sub);
        update!("strict_aud", strict_aud);
        update!("leeway", validation.leeway);

        if let Some(val) = opts.get_item("require")? {
            validation.required_spec_claims.extend(val.extract::<Vec<String>>()?);
        }
    }
    
    if strict_aud {
        check_aud = true;
    }
    
    Ok((validation, check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud))
}


fn validate_claims_content(
    claims: &Value, 
    validation: &Validation, 
    check_exp: bool,
    check_nbf: bool,
    check_aud: bool,
    check_iss: bool,
    check_sub: bool,
    strict_aud: bool,
    expected_aud: &Option<HashSet<String>>,
    expected_iss: &Option<HashSet<String>>,
    expected_sub: &Option<String>
) -> Result<(), WebtokenError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as f64;
    
    for (claim, err) in [
        ("exp", WebtokenError::Custom{ exc: "DecodeError".into(), msg: "exp must be a number".into() }),
        ("iat", WebtokenError::Custom{ exc: "InvalidIssuedAtError".into(), msg: "iat must be a number".into() }),
        ("nbf", WebtokenError::Custom{ exc: "DecodeError".into(), msg: "nbf must be a number".into() })
    ] {
        if let Some(val) = claims.get(claim) {
            if !is_numeric(val) { return Err(err); }
        }
    }

    if check_exp {
        if let Some(val) = claims.get("exp") {
            if let Some(exp) = get_numeric_date(val) {
                if exp < (now - (validation.leeway as f64)) {
                    return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature)));
                }
            }
        } else if validation.required_spec_claims.contains("exp") {
             return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("exp".to_string()))));
        }
    }

    if check_nbf {
        if let Some(val) = claims.get("nbf") {
            if let Some(nbf) = get_numeric_date(val) {
                if nbf > (now + (validation.leeway as f64)) {
                    return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ImmatureSignature)));
                }
            }
        }
    }

    if check_iss {
        if let Some(expected_issuers) = expected_iss {
            let token_iss_val = claims.get("iss");
            match token_iss_val {
                Some(Value::String(iss)) => {
                    if !expected_issuers.contains(iss) { return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer))); }
                },
                Some(_) => return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer))), 
                None => { return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iss".to_string())))); }
            }
        } else if claims.get("iss").is_none() && validation.required_spec_claims.contains("iss") {
             return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iss".to_string()))));
        } else if let Some(iss_val) = claims.get("iss") {
             if !iss_val.is_string() { return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer))); }
        }
    }

    if check_aud {
        let token_aud_val = claims.get("aud");
        if let Some(expected_auds) = expected_aud {
            
            if strict_aud {
                if expected_auds.len() != 1 {
                     return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid audience (strict)".into() });
                }
                match token_aud_val {
                    Some(Value::Array(_)) => return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token (strict)".into() }),
                    Some(Value::String(s)) => {
                        if !expected_auds.contains(s) { return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Audience doesn't match (strict)".into() }); }
                    },
                    Some(Value::Null) | None => {},
                    _ => return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token (strict)".into() }),
                }
            } else {
                if token_aud_val.is_none() || token_aud_val == Some(&Value::Null) {
                    return Err(WebtokenError::Custom{ exc: "MissingRequiredClaimError".into(), msg: "Missing required claim: aud".into() });
                }
                let token_auds: Vec<String> = match token_aud_val {
                    Some(Value::String(s)) => vec![s.clone()],
                    Some(Value::Array(arr)) => {
                        let mut strs = Vec::new();
                        for v in arr {
                            if let Some(s) = v.as_str() { strs.push(s.to_string()); } 
                            else { return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() }); }
                        }
                        strs
                    },
                    Some(_) => { return Err(WebtokenError::Custom{ exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() }); },
                    None => Vec::new(), 
                };
                if !token_auds.iter().any(|ta| expected_auds.contains(ta)) {
                    return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAudience)));
                }
            }
        } else if let Some(val) = token_aud_val {
             let is_truthy = match val { Value::Null => false, Value::String(s) => !s.is_empty(), Value::Array(a) => !a.is_empty(), Value::Bool(b) => *b, _ => true, };
             if is_truthy { return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAudience))); }
        } else if validation.required_spec_claims.contains("aud") {
             return Err(WebtokenError::Custom{ exc: "MissingRequiredClaimError".into(), msg: "Missing required claim: aud".into() });
        }
    }

    if check_sub {
        let sub_val = claims.get("sub");
        if let Some(expected) = expected_sub {
            match sub_val {
                Some(Value::String(s)) => {
                    if s != expected { return Err(WebtokenError::Custom{ exc: "InvalidSubjectError".into(), msg: "Invalid subject".into() }); }
                },
                Some(_) => return Err(WebtokenError::Custom{ exc: "InvalidSubjectError".into(), msg: "Invalid subject: must be a string".into() }),
                None => {} 
            }
        }
        if let Some(v) = sub_val {
            if !v.is_string() { return Err(WebtokenError::Custom{ exc: "InvalidSubjectError".into(), msg: "Invalid subject: must be a string".into() }); }
        }
    }
    
    if let Some(jti) = claims.get("jti") {
        if !jti.is_string() { return Err(WebtokenError::Custom{ exc: "InvalidJTIError".into(), msg: "Invalid jti: must be a string".into() }); }
    }
    
    for req in &validation.required_spec_claims {
        if !claims.get(req).is_some() { return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(req.clone())))); }
    }
    Ok(())
}


fn decode_impl(
    token: String,
    decoding_key: Option<DecodingKey>, 
    mut validation: Validation,
    verify: bool,
    check_iat: bool,
    check_exp: bool, 
    check_nbf: bool, 
    check_aud: bool,
    check_iss: bool,
    check_sub: bool,
    strict_aud: bool,
    expected_aud: Option<HashSet<String>>,
    expected_iss: Option<HashSet<String>>,
    expected_sub: Option<String>,
    detached_content: Option<&[u8]>,
    convert_to_json: bool,
) -> Result<TokenPayload, WebtokenError> {

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(WebtokenError::Generic("Invalid Token Format".into())); }

    let header_bytes = decode_base64_permissive(parts[0].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid header padding".into() })?;

    let mut header_val: Value = from_slice(&header_bytes)
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;

    if !header_val.is_object() {
        return Err(WebtokenError::Custom { 
            exc: "DecodeError".into(), 
            msg: "Invalid header string: must be a json object".into() 
        });
    }

    if let Some(val) = header_val.get("b64") {
        if let Some(b) = val.as_bool() {
            if !b {
                // If b64 is false, detached_payload is mandatory
                if detached_content.is_none() {
                    return Err(WebtokenError::Custom { 
                        exc: "DecodeError".into(), 
                        msg: "It is required that you pass in a value for the \"detached_payload\" argument to decode a message having the b64 header set to false.".into() 
                    });
                }
                // Remove 'b64' so strict struct deserialization doesn't fail later
                if let Some(obj) = header_val.as_object_mut() {
                    obj.remove("b64");
                }
            }
        } else {
             return Err(WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid b64 header: must be boolean".into() });
        }
    }

    // Check if 'alg' is present
    if header_val.get("alg").is_none() {
        return Err(WebtokenError::Custom { 
            exc: "InvalidAlgorithmError".into(), 
            msg: "Missing 'alg' in header".into() 
        });
    }

    // Now convert to strong Header struct
    let header: Header = serde_json::from_value(header_val)
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;
    
    if verify {
       if !validation.algorithms.contains(&header.alg) {
             return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(
                 jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
             )));
        }
        validation.algorithms = vec![header.alg.clone()];
    }

    let payload_bytes = decode_base64_permissive(parts[1].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid payload padding".into() })?;

    if verify {
        let key = decoding_key.ok_or_else(|| WebtokenError::Generic("Key required for verification".to_string()))?;
        let signature_bytes = decode_base64_permissive(parts[2].as_bytes())
            .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid crypto padding".into() })?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);
        let valid = jsonwebtoken::crypto::verify(&sig_b64, &signing_input.as_bytes(), &key, header.alg)
            .map_err(|e| WebtokenError::Jwt(e))?;

        if !valid {
             return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature)));
        }
    }

    if !convert_to_json {
        // return bytes immediately as per PyJWT. No parsing, JWS only cares about signature
        return Ok(TokenPayload::Raw(payload_bytes));
    }

    if let Ok(claims) = from_slice::<Value>(&payload_bytes) {
        validate_claims_content(&claims, &validation, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud, &expected_aud, &expected_iss, &expected_sub)?;
        
        if check_iat {
             if let Some(val) = claims.get("iat") {
                 if let Some(iat) = get_numeric_date(val) {
                     let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as f64;
                     if iat > (now + (validation.leeway as f64)) {
                         return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ImmatureSignature)));
                     }
                 }
             }
        }
        Ok(TokenPayload::Claims(claims))
    } else {
        Ok(TokenPayload::Raw(payload_bytes))
    }
}


fn decode_complete_impl(
    token: String, 
    decoding_key: Option<DecodingKey>, 
    validation: Validation, 
    verify: bool, 
    check_iat: bool, 
    check_exp: bool, 
    check_nbf: bool, 
    check_aud: bool, 
    check_iss: bool, 
    check_sub: bool,
    strict_aud: bool,
    aud: Option<HashSet<String>>, 
    iss: Option<HashSet<String>>,
    sub: Option<String>,
    detached_content: Option<&[u8]>,
    convert_to_json: bool,
) -> Result<CompleteToken, WebtokenError> {

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { 
        return Err(WebtokenError::Custom { exc: "DecodeError".into(), msg: "Not enough segments".into() }); 
    }
    let header_bytes = decode_base64_permissive(parts[0].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid header padding".into() })?;
    
    let mut header_val: Value = from_slice(&header_bytes)
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;
    
    if let Some(val) = header_val.get("b64") {
         if let Some(b) = val.as_bool() {
             if !b {
                  // Only remove it, don't validate here (decode_impl will validate presence of content)
                  // Or validate here too for safety
                  if detached_content.is_none() {
                       return Err(WebtokenError::Custom { 
                           exc: "DecodeError".into(), 
                           msg: "It is required that you pass in a value for the \"detached_payload\" argument to decode a message having the b64 header set to false.".into() 
                       });
                  }
                  if let Some(obj) = header_val.as_object_mut() { obj.remove("b64"); }
             }
         }
    }
    let payload = decode_impl(token.clone(), decoding_key, validation, verify, check_iat, 
    check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud, aud, iss, sub, detached_content, 
    convert_to_json)?;
    
    let signature = decode_base64_permissive(parts[2].as_bytes()).unwrap_or_default();

    Ok(CompleteToken { 
        header: header_val, 
        payload, 
        signature 
    })
}


#[pyfunction(name = "decode_complete")]
#[pyo3(signature = (token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None, return_dict=true))]
fn decode_complete<'py>(py: Python<'py>, token: &Bound<'py, PyAny>, key: Option<&Bound<'py, PyAny>>, 
                        algorithms: Option<Vec<String>>, options: Option<&Bound<'py, PyDict>>, 
                        audience: Option<&Bound<'py, PyAny>>, issuer: Option<&Bound<'py, PyAny>>, 
                        subject: Option<String>, verify: bool, content: Option<&[u8]>, return_dict: bool,
                    ) -> PyResult<Bound<'py, PyAny>> {
    let token_str = extract_token_str(token)?;
    let alg_str = peek_algorithm(&token_str).unwrap_or_else(|_| "HS256".to_string());
    
    let mut effective_verify = verify;
    let mut check_length = false; // Default false
    if let Some(opts) = options {
        if let Ok(Some(v)) = opts.get_item("verify_signature") { if let Ok(b) = v.extract::<bool>() { effective_verify = b; } }
        // [FIX] Extract check_length
        if let Ok(Some(v)) = opts.get_item("enforce_minimum_key_length") { if let Ok(b) = v.extract::<bool>() { check_length = b; } }
    }

    if effective_verify && algorithms.is_none() {
        let is_jwk = if let Some(k) = key { k.extract::<PyJWK>().is_ok() } else { false };
        if !is_jwk { return Err(DecodeError::new_err("It is required that you pass in a value for the \"algorithms\" argument when calling decode().")); }
    }

    let token_final = handle_detached_content(&token_str, content)?;

    if alg_str.eq_ignore_ascii_case("none") {
        if effective_verify {
            // If verifying, 'none' is invalid because it cannot produce a signature check.
            return Err(DecodeError::new_err("Signature verification failed"));
        }
        // If verify=False, we proceed without checking the 'algorithms' list, as per PyJWT behavior
        let parts: Vec<&str> = token_final.split('.').collect();
        if parts.len() < 2 { return Err(DecodeError::new_err("Invalid Token Format")); }

        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| DecodeError::new_err(format!("Invalid header padding: {}", e)))?;
        let header_val: Value = from_slice(&header_json).map_err(|e| DecodeError::new_err(format!("Invalid header: {}", e)))?;
        
        let payload_bytes = decode_base64_permissive(parts[1].as_bytes()).map_err(|e| DecodeError::new_err(format!("Invalid payload padding: {}", e)))?;
        
        let payload = if let Ok(json) = from_slice(&payload_bytes) { 
            TokenPayload::Claims(json) 
        } else { 
            TokenPayload::Raw(payload_bytes) 
        };
        
        let complete = CompleteToken { header: header_val, payload, signature: Vec::new() };
        return pythonize(py, &complete).map_err(|e| PyValueError::new_err(e.to_string()));
    }

    // [FIX] Renamed output variable to `check_iat` correctly
    let (validation, check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud) = prepare_validation(algorithms.clone(), options)?;
    
    let (expected_aud, expected_iss) = extract_aud_iss(audience, issuer)?;

    if ExternalAlgorithm::from_str(&alg_str).is_some() {
        return Err(PyNotImplementedError::new_err("External algs need struct update in this snippet"));
    }

    let decoding_key = if effective_verify {
        // [FIX] Pass check_length
        match key { Some(k) => Some(get_decoding_key(k, &alg_str, check_length)?), None => return Err(PyValueError::new_err("Key required")) }
    } else { None };

    let result = py.detach(move || {
        decode_complete_impl(token_final, decoding_key, validation, effective_verify, check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud, expected_aud, expected_iss, subject, content, return_dict)
    }).map_err(PyErr::from)?;
    pythonize(py, &result).map_err(|e| PyValueError::new_err(e.to_string()))
}


#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", headers=None, sort_headers=true, check_length=false))] // [FIX] Added arg
fn encode_fast(
    payload: &Bound<'_, PyDict>, 
    key: &Bound<'_, PyAny>, 
    algorithm: &str, 
    headers: Option<&Bound<'_, PyDict>>,
    sort_headers: bool,
    check_length: bool, 
) -> PyResult<String> {
    
    let time_claims = ["exp", "iat", "nbf"];
    let mut claims_map = Map::new();

    for (k_py, v_py) in payload {

        let key_str = k_py.extract::<&str>()?; 
        if key_str == "iss" && !v_py.is_instance_of::<PyString>() { 
            return Err(PyTypeError::new_err("Issuer (iss) must be a string.")); 
        }

        let timestamp = time_claims.contains(&key_str).then(|| {
            v_py.extract::<OffsetDateTime>().map(|dt| dt.unix_timestamp()).or_else(
                |_| v_py.extract::<PrimitiveDateTime>().map(|dt| dt.assume_utc().unix_timestamp())
            ).ok()
        }).flatten();

        let value_json = match timestamp {
            Some(ts) => Value::Number(ts.into()),
            None => depythonize(&v_py).map_err(|e| PyValueError::new_err(
                format!("Serialization failed: {e}")))?,
        };

        claims_map.insert(key_str.to_string(), value_json);
    }

    let header_map = prepare_headers(algorithm, headers, sort_headers)?;
    let payload_bytes = to_vec(&claims_map).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let (header_b64, payload_b64, signing_input) = jws::prepare_jws_parts(&header_map, &payload_bytes)
        .map_err(Into::<PyErr>::into)?;

    if let Ok(jwk) = key.extract::<PyJWK>() {
        let sig_bytes = perform_signature_jwk(signing_input.as_bytes(), &jwk, algorithm).map_err(Into::<PyErr>::into)?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        return Ok(format!("{}.{}", signing_input, sig_b64));
    }

    let key_bytes = get_key_bytes(key, algorithm, true, check_length)?;
    let detached = header_map.get("b64") == Some(&Value::Bool(false));

    jws::sign_output(&signing_input, &header_b64, &payload_b64, &key_bytes, algorithm, detached)
        .map_err(Into::into)
}


#[pyfunction(name = "decode")]
#[pyo3(signature = (token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None, return_dict=true))]
fn py_decode<'py>(
    py: Python<'py>, 
    token: &Bound<'py, PyAny>, 
    key: Option<&Bound<'py, PyAny>>, 
    algorithms: Option<Vec<String>>, 
    options: Option<&Bound<'py, PyDict>>,
    audience: Option<&Bound<'py, PyAny>>, 
    issuer: Option<&Bound<'py, PyAny>>, 
    subject: Option<String>, 
    verify: bool, 
    content: Option<&[u8]>,
    return_dict: bool,
) -> PyResult<Bound<'py, PyAny>> {
    
    let complete = decode_complete(py, token, key, algorithms, options, 
                    audience, issuer, subject, verify, content, return_dict)?;
    
    if let Ok(dict) = complete.cast::<PyDict>() {
        if let Some(payload) = dict.get_item("payload")? {
            return Ok(payload);
        }
    }
    Err(PyValueError::new_err("Failed to extract payload"))
}


fn base64url_decode_inner(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if let Ok(v) = URL_SAFE_NO_PAD.decode(&clean) { return Ok(v); }
    if let Ok(v) = STANDARD.decode(&clean) { return Ok(v); }
    Err("Invalid padding or alphabet".to_string())
}


#[pyfunction]
#[pyo3(signature = (token))]
fn get_unverified_header<'py>(py: Python<'py>, token: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let token_str = extract_token_str(token)?;
    
    let part = token_str.split('.').next().ok_or_else(|| DecodeError::new_err("Invalid Token Format"))?;
    
    let bytes = base64url_decode_inner(part).map_err(|_| DecodeError::new_err("Invalid header padding"))?;
    
    let val: Value = from_slice(&bytes).map_err(|e| DecodeError::new_err(format!("Invalid header string: {}", e)))?;

    // PyJWT wants 'kid' to be a string if present, even for unverified headers
    if let Some(kid) = val.get("kid") {
        if !kid.is_string() {
            return Err(InvalidTokenError::new_err("Key ID header parameter must be a string"));
        }
    }
    pythonize(py, &val).map_err(|e| PyValueError::new_err(e.to_string()))
}


#[pyfunction]
fn unsafe_peek<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { return Err(PyValueError::new_err("Invalid Token Format")); }
    let payload_bytes = base64url_decode_inner(parts[1]).map_err(|_| PyValueError::new_err("Invalid Payload Base64"))?;
    let claims: Value = from_slice(&payload_bytes).map_err(|_| PyValueError::new_err("Invalid Payload JSON"))?;
    Ok(pythonize(py, &claims).unwrap())
}

#[pyfunction]
fn pem_to_jwk(pem: &[u8]) -> PyResult<String> {
    crate::jwk::pem_to_jwk(pem).map_err(|e| PyValueError::new_err(e))
}


#[pyfunction]
#[pyo3(signature = (claims, options=None, audience=None, issuer=None, subject=None, leeway=0))]
fn validate_claims(
    claims: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyDict>>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
    subject: Option<String>,
    leeway: i64
) -> PyResult<()> {
    let claims_val: Value = depythonize(claims).map_err(|e| PyValueError::new_err(e.to_string()))?;
    
    let (mut validation, _, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud) = prepare_validation(None, options)?;
    
    if validation.leeway == 0 && leeway > 0 {
        validation.leeway = leeway as u64; 
    }

    let (expected_aud, expected_iss) = extract_aud_iss(audience, issuer)?;


    validate_claims_content(
        &claims_val, &validation, 
        check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud,
        &expected_aud, &expected_iss, &subject
    ).map_err(Into::into)
}


#[pyfunction]
fn load_key_from_pem(pem: &[u8]) -> PyResult<PyJWK> {
    let json_str = crate::jwk::pem_to_jwk(pem).map_err(|e| PyValueError::new_err(e))?;
    let val: serde_json::Value = from_str(&json_str).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let alg = val.get("alg").and_then(|s| s.as_str()).map(|s| s.to_string());
    Ok(PyJWK { inner: val, algorithm_name: alg })
}

// Register a submodule and add it to sys.modules 
fn add_submodule_with_sys(
    py: Python, 
    parent: &Bound<'_, PyModule>, 
    name: &str, 
    setup_fn: impl FnOnce(Python, &Bound<'_, PyModule>) -> PyResult<()>
) -> PyResult<()> {
    let submod = PyModule::new(py, name)?;
    setup_fn(py, &submod)?;
    parent.add_submodule(&submod)?;

    // Add to sys.modules (allows `from toke.jwk import ...`)
    let parent_name = parent.name()?;
    let full_name = format!("{}.{}", parent_name, name);
    py.import("sys")?.getattr("modules")?.set_item(full_name, &submod)?;

    Ok(())
}

#[pymodule]
fn webtoken(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
    m.add("InvalidAlgorithmError", py.get_type::<InvalidAlgorithmError>())?;

    m.add_function(wrap_pyfunction!(raw_sign, m)?)?;
    m.add_function(wrap_pyfunction!(raw_verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(validate_key_properties, m)?)?;
    m.add_function(wrap_pyfunction!(encode_fast, m)?)?; 
    m.add_function(wrap_pyfunction!(py_decode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_complete, m)?)?;
    m.add_function(wrap_pyfunction!(get_unverified_header, m)?)?;
    m.add_function(wrap_pyfunction!(load_key_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(unsafe_peek, m)?)?;
    m.add_function(wrap_pyfunction!(register_algorithm, m)?)?;
    m.add_function(wrap_pyfunction!(unregister_algorithm, m)?)?;
    m.add_function(wrap_pyfunction!(validate_claims, m)?)?;

    m.add_function(wrap_pyfunction!(load_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(load_jwk_set, m)?)?; 
    m.add_function(wrap_pyfunction!(pem_to_jwk, m)?)?;

    crypto::export_functions(m)?; // Unified crypto export
    py_utils::export_py_utils(m)?;

    add_submodule_with_sys(py, m, "api_jwk", |_py, mod_| {
        pyjwt_jwk_api::register_jwk_module(py, mod_)
    })?;

    add_submodule_with_sys(py, m, "exceptions", |_py, m_exc| {
        m_exc.add("PyJWTError", py.get_type::<PyJWTError>())?;
        m_exc.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
        m_exc.add("DecodeError", py.get_type::<DecodeError>())?;
        m_exc.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
        m_exc.add("ExpiredSignatureError", py.get_type::<ExpiredSignatureError>())?;
        m_exc.add("InvalidAudienceError", py.get_type::<InvalidAudienceError>())?;
        m_exc.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
        m_exc.add("ImmatureSignatureError", py.get_type::<ImmatureSignatureError>())?;
        m_exc.add("MissingRequiredClaimError", py.get_type::<MissingRequiredClaimError>())?;
        m_exc.add("InvalidIssuedAtError", py.get_type::<InvalidIssuedAtError>())?;
        m_exc.add("InvalidJTIError", py.get_type::<InvalidJTIError>())?;
        m_exc.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;
        m_exc.add("InvalidAlgorithmError", py.get_type::<InvalidAlgorithmError>())?;
        m_exc.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
        Ok(())
    })?;
    Ok(())
}