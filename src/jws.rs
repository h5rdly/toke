use std::str::FromStr;

use serde_json::Value;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use jsonwebtoken::{
    crypto::{sign, verify},
    Algorithm, EncodingKey, DecodingKey,
};

use crate::{TokeError, algorithms::ExternalAlgorithm, is_hmac};


/// Signs a payload (bytes) with a specific algorithm and key.
/// Returns a compact JWS string (header.payload.signature).
pub fn sign_bytes(
    payload: &[u8], 
    key: &[u8], 
    alg_name: &str, 
    extra_headers: Option<Value>
) -> Result<String, TokeError> {
    
    // 1. Prepare Header
    let mut header_map = match extra_headers {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    
    header_map.insert("alg".to_string(), Value::String(alg_name.to_string()));
    // if !header_map.contains_key("typ") {
    //     header_map.insert("typ".to_string(), Value::String("JWT".to_string()));
    // }

    // Serialize Header & Payload
    let header_json = serde_json::to_vec(&header_map).map_err(|e| TokeError::Generic(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // 2. Route to Correct Engine
    let signature_b64 = if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_name) {
        // A. External (AWS-LC-RS)
        ext_alg.sign(signing_input.as_bytes(), key)?
    } else {
        // B. Standard (jsonwebtoken)
        let alg = Algorithm::from_str(alg_name)
            .map_err(|_| TokeError::Generic(format!("Algorithm '{}' not supported", alg_name)))?;
        
        let encoding_key = if is_hmac(alg) {
            EncodingKey::from_secret(key)
        } else {
            EncodingKey::from_rsa_pem(key)
                .or_else(|_| EncodingKey::from_ec_pem(key))
                .or_else(|_| EncodingKey::from_ed_pem(key))
                .map_err(|e| TokeError::Generic(format!("Invalid PEM key: {}", e)))?
        };

        sign(signing_input.as_bytes(), &encoding_key, alg).map_err(TokeError::Jwt)?
    };

    Ok(format!("{}.{}", signing_input, signature_b64))
}

/// Verifies a JWS signature.
/// Returns (Header, Payload) if valid, Error otherwise.
pub fn verify_bytes(
    token: &str, 
    key: &[u8], 
    alg_name: &str
) -> Result<(Value, Vec<u8>), TokeError> {
    
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokeError::Generic("Invalid Token Format".into()));
    }

    let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // 1. Verify Signature
    if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_name) {
        // A. External
        let valid = ext_alg.verify(signing_input.as_bytes(), signature_b64, key)?;
        if !valid { return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature))); }
    } else {
        // B. Standard
        let alg = Algorithm::from_str(alg_name)
            .map_err(|_| TokeError::Generic("Unsupported Algorithm".into()))?;
            
        let decoding_key = if is_hmac(alg) {
            DecodingKey::from_secret(key)
        } else {
            DecodingKey::from_rsa_pem(key)
                .or_else(|_| DecodingKey::from_ec_pem(key))
                .or_else(|_| DecodingKey::from_ed_pem(key))
                .map_err(|e| TokeError::Generic(format!("Invalid PEM key: {}", e)))?
        };

        let valid = verify(signature_b64, signing_input.as_bytes(), &decoding_key, alg)
            .map_err(TokeError::Jwt)?;
            
        if !valid {
            return Err(TokeError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature)));
        }
    }

    // 2. Decode Components
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64)
        .map_err(|_| TokeError::Generic("Invalid Header Base64".into()))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| TokeError::Generic("Invalid Header JSON".into()))?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)
        .map_err(|_| TokeError::Generic("Invalid Payload Base64".into()))?;

    Ok((header, payload_bytes))
}