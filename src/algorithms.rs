use crate::{WebtokenError, is_hmac};

use base64::{Engine as _, };
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use aws_lc_rs::rand::SystemRandom;

use aws_lc_rs::hmac::{
    self, Key as HmacKey, 
   // HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
};
use aws_lc_rs::signature::{
    // ECDSA
    UnparsedPublicKey, EcdsaSigningAlgorithm, EcdsaKeyPair, 
    // ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED, ECDSA_P521_SHA512_FIXED_SIGNING, // ES512
    ECDSA_P256K1_SHA256_FIXED, ECDSA_P256K1_SHA256_FIXED_SIGNING,
    
    // RSA PKCS#1 v1.5
    RsaKeyPair,
    //RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    //RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,

    // RSA PSS
    //RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
    //RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,

    // EdDSA
    //ED25519
};

use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING
};

// jsonwebtoken imports for the fallback path in lib.rs
use jsonwebtoken::{
    Algorithm, EncodingKey, DecodingKey, 
    crypto::{sign as jwt_sign, verify as jwt_verify}
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExternalAlgorithm {
    // Hs256, Hs384, Hs512,
    // Rs256, Rs384, Rs512,
    // Ps256, Ps384, Ps512,
    // EdDsa,
    // Es256, Es384, 
    Es512, Es256k,
    MlDsa65,          
}
 
// -- Helpers --

fn _sign_hmac(alg: &'static hmac::Algorithm, key: &[u8], payload: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let key = HmacKey::new(*alg, key);
    let tag = hmac::sign(&key, payload);
    Ok(tag.as_ref().to_vec())
}

fn _verify_hmac(alg: &'static hmac::Algorithm, key: &[u8], payload: &[u8], sig: &[u8]) -> Result<bool, WebtokenError> {
    let key = HmacKey::new(*alg, key);
    Ok(hmac::verify(&key, payload, sig).is_ok())
}

fn _sign_rsa(
    alg: &'static aws_lc_rs::signature::RsaSignatureEncoding, 
    key_bytes: &[u8], 
    payload: &[u8]
) -> Result<Vec<u8>, WebtokenError> {
    // Try parsing as PKCS#8 first (standard), then fall back to DER/PKCS#1
    let key_pair = RsaKeyPair::from_pkcs8(key_bytes)
        .or_else(|_| RsaKeyPair::from_der(key_bytes))
        .map_err(|e| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: format!("Invalid RSA private key: {:?}", e) 
        })?;
    
    let rng = SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    
    key_pair.sign(alg, &rng, payload, &mut signature)
        .map_err(|e| WebtokenError::Generic(format!("RSA Signing failed: {:?}", e)))?;
    
    Ok(signature)
}

fn sign_ecdsa(
    alg: &'static EcdsaSigningAlgorithm, 
    key_bytes: &[u8], 
    payload: &[u8], 
    alg_name: &str
) -> Result<Vec<u8>, WebtokenError> {

    // 1. Parse PEM/DER Key
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key_bytes)
        .map_err(|e| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: format!("Invalid {} private key (expected PKCS#8): {:?}", alg_name, e) 
        })?;
    
    // 2. Initialize Randomness
    let rng = SystemRandom::new();

    // 3. Sign
    let sig = key_pair.sign(&rng, payload)
        .map_err(|e| WebtokenError::Generic(format!("Signing failed: {:?}", e)))?;
    
    Ok(sig.as_ref().to_vec())
}

fn decode_maybe_pem(data: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    // 1. Check for PEM header
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim();
        if s.starts_with("-----BEGIN") {
            let lines: Vec<&str> = s.lines()
                .filter(|line| !line.starts_with("-----"))
                .map(|line| line.trim())
                .collect();
            
            let base64_data = lines.join("");
            return STANDARD.decode(&base64_data).map_err(|e| WebtokenError::Custom {
                exc: "InvalidKeyError".into(),
                msg: crate::err_loc!("Failed to base64 decode PEM body: {}", e)
            });
        }
    }
    // 2. Assume it is already DER (or raw bytes for HMAC/Ed25519)
    Ok(data.to_vec())
}


impl ExternalAlgorithm {
    pub fn from_str(alg: &str) -> Option<Self> {
        match alg {
            // HMAC
            // "HS256" => Some(Self::Hs256),
            // "HS384" => Some(Self::Hs384),
            // "HS512" => Some(Self::Hs512),
            // // RSA PKCS#1
            // "RS256" => Some(Self::Rs256),
            // "RS384" => Some(Self::Rs384),
            // "RS512" => Some(Self::Rs512),
            // // RSA PSS
            // "PS256" => Some(Self::Ps256),
            // "PS384" => Some(Self::Ps384),
            // "PS512" => Some(Self::Ps512),
            // // EdDSA
            // "EdDSA" => Some(Self::EdDsa),
            // // ECDSA
            // "ES256" => Some(Self::Es256),
            // "ES384" => Some(Self::Es384),
            "ES512" => Some(Self::Es512),
            "ES256K" => Some(Self::Es256k),

            // PQ
            "ML-DSA-65" => Some(Self::MlDsa65),
            _ => None,
        }
    }

    pub fn sign(&self, payload: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, WebtokenError> {
        // NOTE: For HMAC, key_bytes are the raw secret. For asymmetric, they are DER/PEM.
        let der_bytes = decode_maybe_pem(key_bytes)?;
        
        match self {
            // HMAC
            // Self::Hs256 => sign_hmac(&HMAC_SHA256, &der_bytes, payload),
            // Self::Hs384 => sign_hmac(&HMAC_SHA384, &der_bytes, payload),
            // Self::Hs512 => sign_hmac(&HMAC_SHA512, &der_bytes, payload),

            // // RSA PKCS#1
            // Self::Rs256 => sign_rsa(&RSA_PKCS1_SHA256, &der_bytes, payload),
            // Self::Rs384 => sign_rsa(&RSA_PKCS1_SHA384, &der_bytes, payload),
            // Self::Rs512 => sign_rsa(&RSA_PKCS1_SHA512, &der_bytes, payload),

            // // RSA PSS
            // Self::Ps256 => sign_rsa(&RSA_PSS_SHA256, &der_bytes, payload),
            // Self::Ps384 => sign_rsa(&RSA_PSS_SHA384, &der_bytes, payload),
            // Self::Ps512 => sign_rsa(&RSA_PSS_SHA512, &der_bytes, payload),

            // // EdDSA (Ed25519 only in aws-lc-rs currently)
            // Self::EdDsa => {
            //     // aws-lc-rs Ed25519 requires wrapped KeyPair structure
            //     let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(&der_bytes)
            //         .map_err(|e| WebtokenError::Custom { exc: "InvalidKeyError".into(), msg: format!("Invalid Ed25519 key: {:?}", e) })?;
            //     Ok(key_pair.sign(payload).as_ref().to_vec())
            // },

            // ECDSA
            // Self::Es256 => sign_ecdsa(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes, payload, "ES256"),
            // Self::Es384 => sign_ecdsa(&ECDSA_P384_SHA384_FIXED_SIGNING, &der_bytes, payload, "ES384"),
            Self::Es512 => sign_ecdsa(&ECDSA_P521_SHA512_FIXED_SIGNING, &der_bytes, payload, "ES512"),
            Self::Es256k => sign_ecdsa(&ECDSA_P256K1_SHA256_FIXED_SIGNING, &der_bytes, payload, "ES256K"),

            // PQ
            Self::MlDsa65 => {
                if let Ok(key_pair) = PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig).map_err(|e| WebtokenError::Generic(format!("{:?}", e)))?;
                    Ok(sig)
                } else if let Ok(key_pair) = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig).map_err(|e| WebtokenError::Generic(format!("{:?}", e)))?;
                    Ok(sig)
                } else {
                     Err(WebtokenError::Custom { exc: "InvalidKeyError".into(), msg: "Invalid ML-DSA-65 key".into() })
                }
            },
        }
    }


    pub fn verify(&self, payload: &[u8], sig_bytes: &[u8], key_bytes: &[u8]) -> Result<bool, WebtokenError> {
        let der_bytes = decode_maybe_pem(key_bytes)?;
        
        let valid = match self {
            // HMAC
            // Self::Hs256 => verify_hmac(&HMAC_SHA256, &der_bytes, payload, sig_bytes)?,
            // Self::Hs384 => verify_hmac(&HMAC_SHA384, &der_bytes, payload, sig_bytes)?,
            // Self::Hs512 => verify_hmac(&HMAC_SHA512, &der_bytes, payload, sig_bytes)?,

            // // RSA PKCS#1
            // Self::Rs256 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &der_bytes).verify(payload, sig_bytes).is_ok(),
            // Self::Rs384 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &der_bytes).verify(payload, sig_bytes).is_ok(),
            // Self::Rs512 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // // RSA PSS
            // Self::Ps256 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &der_bytes).verify(payload, sig_bytes).is_ok(),
            // Self::Ps384 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &der_bytes).verify(payload, sig_bytes).is_ok(),
            // Self::Ps512 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // // EdDSA
            // Self::EdDsa => UnparsedPublicKey::new(&ED25519, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // // ECDSA
            // Self::Es256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            // Self::Es384 => UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Es512 => UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Es256k => UnparsedPublicKey::new(&ECDSA_P256K1_SHA256_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // PQ
            Self::MlDsa65 => UnparsedPublicKey::new(&ML_DSA_65, &der_bytes).verify(payload, sig_bytes).is_ok(),
        };
        Ok(valid)
    }
}


// Fallback functions (kept for now, but should become unused if from_str matches all)
pub fn perform_signature(payload: &[u8], key: &[u8], alg_name: &str) -> Result<Vec<u8>, WebtokenError> {
    if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_name) {
        return ext_alg.sign(payload, key);
    }
    
    // Standard (jsonwebtoken) fallback
    use std::str::FromStr;
    let alg = Algorithm::from_str(alg_name)
        .map_err(|_| WebtokenError::Generic(format!("Algorithm '{}' not supported", alg_name)))?;
    
    let encoding_key = if is_hmac(alg) {
        EncodingKey::from_secret(key)
    } else {
            EncodingKey::from_rsa_pem(key)
            .or_else(|_| EncodingKey::from_ec_pem(key))
            .or_else(|_| EncodingKey::from_ed_pem(key))
            .map_err(|e| WebtokenError::Generic(format!("Invalid PEM key: {}", e)))?
    };

    let sig_b64 = jwt_sign(payload, &encoding_key, alg).map_err(WebtokenError::Jwt)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(&sig_b64).map_err(|e| WebtokenError::Generic(e.to_string()))?;
    Ok(sig_bytes)
}

pub fn perform_verification(payload: &[u8], signature: &[u8], key: &[u8], alg_name: &str) -> Result<bool, WebtokenError> {
    if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_name) {
        return ext_alg.verify(payload, signature, key);
    }

    use std::str::FromStr;
    let alg = Algorithm::from_str(alg_name)
        .map_err(|_| WebtokenError::Generic("Unsupported Algorithm".into()))?;
        
    let decoding_key = if is_hmac(alg) {
        DecodingKey::from_secret(key)
    } else {
        DecodingKey::from_ed_pem(key)
            .or_else(|_| DecodingKey::from_rsa_pem(key))
            .or_else(|_| DecodingKey::from_ec_pem(key))
            .map_err(|e| WebtokenError::Generic(format!("Invalid PEM key: {}", e)))?
    };

    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    jwt_verify(&sig_b64, payload, &decoding_key, alg).map_err(WebtokenError::Jwt)
}