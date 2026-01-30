use serde_json::Value;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{Jwk as RustJwk};

use crate::TokeError;


pub fn parse_json(data: &str) -> Result<Value, String> {
    serde_json::from_str(data).map_err(|e| format!("Invalid JWK JSON: {}", e))
}


pub fn normalize(jwk: Value, algorithm_hint: Option<String>) -> Result<(Value, Option<String>), String> {
    // 1. Basic Structure Validation
    if !jwk.is_object() {
        return Err("JWK must be an object".to_string());
    }
    if jwk.get("kty").is_none() {
        return Err("Key type (kty) not found".to_string());
    }

    // 2. Algorithm Resolution Strategy
    // Priority: Explicit Argument > "alg" field in JSON > Deduction from "kty"/"crv"
    let alg = if let Some(a) = algorithm_hint {
        Some(a)
    } else if let Some(key_alg) = jwk.get("alg").and_then(|v| v.as_str()) {
        Some(key_alg.to_string())
    } else {
        deduce_algorithm(&jwk)?
    };

    Ok((jwk, alg))
}


pub fn normalize_key_set(keys: Vec<Value>) -> Vec<(Value, Option<String>)> {
    keys.into_iter()
        .filter_map(|k| {
            
            // Filter: Skip keys explicitly marked for encryption (PyJWT legacy behavior)
            if let Some("enc") = k.get("use").and_then(|u| u.as_str()) {
                return None;
            }

            // Validate & Resolve: Use the existing normalize() logic
            // We suppress errors for individual keys in a set (just skip them)
            normalize(k, None).ok()
        })
        .collect()
}


pub fn deduce_algorithm(jwk: &Value) -> Result<Option<String>, String> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or("kty missing")?;
    
    match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("crv missing for EC key")?;
            match crv {
                "P-256" => Ok(Some("ES256".to_string())),
                "P-384" => Ok(Some("ES384".to_string())),
                "P-521" => Ok(Some("ES512".to_string())),
                "secp256k1" => Ok(Some("ES256K".to_string())),
                _ => Err(format!("Unsupported crv: {}", crv))
            }
        },
        "RSA" => Ok(Some("RS256".to_string())),
        "oct" => Ok(Some("HS256".to_string())),
        "OKP" => {
             let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("crv missing for OKP")?;
             match crv {
                 "Ed25519" | "Ed448" => Ok(Some("EdDSA".to_string())),
                 _ => Err(format!("Unsupported crv for OKP: {}", crv))
             }
        },
        // We return an error for unknown types to be safe strict parsing
        other => Err(format!("Unknown key type: {}", other))
    }
}


/// Strict conversion for Standard Algorithms (RSA, NIST EC). Uses `jsonwebtoken` crate logic.
pub fn to_decoding_key(jwk: &Value) -> Result<DecodingKey, TokeError> {
    let json_str = serde_json::to_string(jwk).map_err(|e| TokeError::Generic(e.to_string()))?;
    let rust_jwk: RustJwk = serde_json::from_str(&json_str)
        .map_err(|e| TokeError::Generic(format!("JWK parsing failed: {}", e)))?;
    DecodingKey::from_jwk(&rust_jwk).map_err(TokeError::Jwt)
}


/// Manual conversion for External Algorithms (ES256K, EdDSA). Extracts raw bytes directly from the JSON Value.
pub fn extract_key_bytes(jwk: &Value) -> Result<Vec<u8>, String> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or_default();

    match kty {
        "oct" => {
            let k = jwk.get("k").and_then(|v| v.as_str()).ok_or("Missing 'k' parameter")?;
            URL_SAFE_NO_PAD.decode(k).map_err(|e| format!("Invalid base64 k: {}", e))
        },
        "OKP" => {
            if let Some(d) = jwk.get("d").and_then(|v| v.as_str()) {
                 URL_SAFE_NO_PAD.decode(d).map_err(|e| format!("Invalid base64 d: {}", e))
            } else if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                 URL_SAFE_NO_PAD.decode(x).map_err(|e| format!("Invalid base64 x: {}", e))
            } else {
                Err("Missing parameters for OKP".to_string())
            }
        },
        "EC" => {
             // For ES256K/Custom EC, we prioritize the private scalar 'd'
             if let Some(d) = jwk.get("d").and_then(|v| v.as_str()) {
                 URL_SAFE_NO_PAD.decode(d).map_err(|e| format!("Invalid base64 d: {}", e))
             } else {
                 // Public Key extraction from x/y manually is complex without a helper library
                 // for now we error if it's not a private key for external algos.
                 Err("Manual public key extraction for EC not implemented".to_string())
             }
        }
        _ => Err(format!("Unsupported key type for raw extraction: {}", kty))
    }
}

