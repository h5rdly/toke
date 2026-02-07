use serde_json::{Value, Map};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{WebtokenError, algorithms::{perform_signature, perform_verification}};
use crate::py_utils::decode_base64_permissive;


pub fn sign_output(
    payload: &[u8], 
    key: &[u8], 
    alg_name: &str, 
    headers: Map<String, Value>, 
    detached: bool
) -> Result<String, WebtokenError> {
    
    // 1. Serialize and Encode Headers
    let header_json = serde_json::to_vec(&headers).map_err(|e| WebtokenError::Generic(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    
    // 2. Encode Payload
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    
    // 3. Handle "None" (Unsecured)
    // RFC 7515: Unsecured JWS use empty signature.
    if alg_name.eq_ignore_ascii_case("none") {
        if detached {
            return Ok(format!("{}..", header_b64));
        }
        return Ok(format!("{}.{}.", header_b64, payload_b64));
    }

    // 4. Construct Signing Input
    // The input to the signature is ALWAYS "header.payload", even if detached.
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    
    // 5. Calculate Signature (Raw Crypto)
    let sig_bytes = perform_signature(signing_input.as_bytes(), key, alg_name)?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    // 6. Format Output
    if detached {
        Ok(format!("{}..{}", header_b64, sig_b64))
    } else {
        Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
    }
}


pub fn verify_bytes(token: &str, key: &[u8], alg_name: &str) -> Result<(Value, Vec<u8>), WebtokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(WebtokenError::Generic("Invalid Token Format".into())); }

    let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    
    let sig_bytes = decode_base64_permissive(signature_b64.as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid crypto padding".into() })?;

    let valid = perform_verification(signing_input.as_bytes(), &sig_bytes, key, alg_name)?;
    if !valid { 
        return Err(WebtokenError::Jwt(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature))); 
    }

    let header_bytes = decode_base64_permissive(header_b64.as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid header padding".into() })?;
    
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;
    
    let payload_bytes = decode_base64_permissive(payload_b64.as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid payload padding".into() })?;
    
    Ok((header, payload_bytes))
}