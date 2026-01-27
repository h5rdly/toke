use crate::TokeError;

use base64::{Engine as _, };
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    UnparsedPublicKey, EcdsaSigningAlgorithm,
    EcdsaKeyPair, ECDSA_P521_SHA512_FIXED, ECDSA_P521_SHA512_FIXED_SIGNING, ECDSA_P256K1_SHA256_FIXED, 
    ECDSA_P256K1_SHA256_FIXED_SIGNING,
};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING
};


pub enum ExternalAlgorithm {
    MlDsa65,          // Lattice-based (Fast)
    Es512,            // NIST P-521
    Es256k,
}

// -- Helpers

fn sign_ecdsa(
    alg: &'static EcdsaSigningAlgorithm, 
    key_bytes: &[u8], 
    payload: &[u8], 
    alg_name: &str
) -> Result<Vec<u8>, TokeError> {
    // 1. Parse PEM/DER Key
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key_bytes)
        .map_err(|e| TokeError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: format!("Invalid {} private key (expected PKCS#8): {:?}", alg_name, e) 
        })?;
    
    // 2. Initialize Randomness (Required for ECDSA k-value)
    let rng = SystemRandom::new();

    // 3. Sign
    let sig = key_pair.sign(&rng, payload)
        .map_err(|e| TokeError::Generic(format!("Signing failed: {:?}", e)))?;
    
    Ok(sig.as_ref().to_vec())
}


fn decode_maybe_pem(data: &[u8]) -> Result<Vec<u8>, TokeError> {
    // 1. Check for PEM header
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim();
        if s.starts_with("-----BEGIN") {
            // Simple manual PEM parser
            let lines: Vec<&str> = s.lines()
                .filter(|line| !line.starts_with("-----"))
                .map(|line| line.trim())
                .collect();
            
            let base64_data = lines.join("");
            
            return STANDARD.decode(&base64_data).map_err(|e| TokeError::Custom {
                exc: "InvalidKeyError".into(),
                msg: crate::err_loc!("Failed to base64 decode PEM body: {}", e)
            });
        }
    }
    
    // 2. Assume it is already DER
    Ok(data.to_vec())
}


impl ExternalAlgorithm {
    pub fn from_str(alg: &str) -> Option<Self> {
        match alg {
            "ML-DSA-65" => Some(Self::MlDsa65),
            "ES512" => Some(Self::Es512),
            "ES256K" => Some(Self::Es256k),
            _ => None,
        }
    }

    pub fn sign(&self, payload: &[u8], key_bytes: &[u8]) -> Result<String, TokeError> {
        let der_bytes = decode_maybe_pem(key_bytes)?;
        
        let signature_bytes = match self {
            Self::MlDsa65 => {
                if let Ok(key_pair) = PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig)
                        .map_err(|e| TokeError::Generic(crate::err_loc!("Signing failed: {:?}", e)))?;
                    sig
                } 
                else if let Ok(key_pair) = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig)
                        .map_err(|e| TokeError::Generic(crate::err_loc!("Signing failed: {:?}", e)))?;
                    sig
                } else {
                     return Err(TokeError::Custom { 
                        exc: "InvalidKeyError".into(), 
                        msg: crate::err_loc!("Invalid ML-DSA-65 key. Expected PKCS#8 DER/PEM or Raw Seed.")
                    });
                }
            },
            // Unified ECDSA Logic
            Self::Es512 => sign_ecdsa(
                &ECDSA_P521_SHA512_FIXED_SIGNING, 
                &der_bytes, 
                payload, 
                "ES512"
            )?,
            Self::Es256k => sign_ecdsa(
                &ECDSA_P256K1_SHA256_FIXED_SIGNING, 
                &der_bytes, 
                payload, 
                "ES256K"
            )?,
        };

        Ok(URL_SAFE_NO_PAD.encode(signature_bytes))
    }


    pub fn verify(&self, payload: &[u8], signature_b64: &str, key_bytes: &[u8]) -> Result<bool, TokeError> {
        // UnparsedPublicKey works for ALL types (PQ and Classical) because they all 
        // implement the VerificationAlgorithm trait in aws-lc-rs.
        let der_bytes = decode_maybe_pem(key_bytes)?;
        let sig_bytes = URL_SAFE_NO_PAD.decode(signature_b64)
            .map_err(|_| TokeError::Generic("Invalid signature base64".into()))?;

        let valid = match self {
            Self::MlDsa65 => {
                let pk = UnparsedPublicKey::new(&ML_DSA_65, &der_bytes);
                pk.verify(payload, &sig_bytes).is_ok()
            },
            Self::Es512 => {
                let pk = UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &der_bytes);
                pk.verify(payload, &sig_bytes).is_ok()
            }
            Self::Es256k => {
                let pk = UnparsedPublicKey::new(&ECDSA_P256K1_SHA256_FIXED, &der_bytes);
                pk.verify(payload, &sig_bytes).is_ok()
            }
        };

        Ok(valid)
    }
}