use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    KeyPair,
    EcdsaKeyPair,
    RsaKeyPair,
    Ed25519KeyPair,
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED_SIGNING,
    ECDSA_P256K1_SHA256_FIXED_SIGNING,
};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, 
    ML_DSA_65_SIGNING, 
    ML_DSA_44_SIGNING, 
    ML_DSA_87_SIGNING
};


// Wrap DER bytes in PEM format
fn to_pem(tag: &str, data: &[u8]) -> Vec<u8> {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", tag));
    // Line wrapping at 64 chars
    for chunk in STANDARD.encode(data).as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", tag));
    pem.into_bytes()
}


// Returns (private_key_pem, public_key_pem) as bytes.
#[pyfunction]
pub fn generate_key_pair(algorithm: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
    
    enum GeneratedKey {
        Ec(EcdsaKeyPair), Rsa(RsaKeyPair), Ed(Ed25519KeyPair), Pq(PqdsaKeyPair),
    }

    let key = match algorithm.to_uppercase().as_str() {
        // --- ECDSA ---
        "ES256" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES384" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES512" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES256K" | "SECP256K1" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        
        // --- RSA (Default to 2048 for standard testing) ---
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            GeneratedKey::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| PyValueError::new_err("Gen failed"))?)
        },
        
        // --- EdDSA ---
        "EDDSA" | "ED25519" => {
            GeneratedKey::Ed(Ed25519KeyPair::generate().map_err(|_| PyValueError::new_err("Gen failed"))?)
        },

        // --- Post-Quantum ---
        "ML-DSA-44" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ML-DSA-65" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ML-DSA-87" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),

        _ => return Err(PyValueError::new_err(format!("Unsupported key generation algo: {}", algorithm))),
    };


    // to_pkcs8v1() and to_pkcs8() return DER, we wrap that in PEM headers.
    let (priv_der, pub_der) = match key {
        GeneratedKey::Ec(k) => (
            k.to_pkcs8v1().unwrap().as_ref().to_vec(),
            k.public_key().as_der().unwrap().as_ref().to_vec()
        ),
        GeneratedKey::Rsa(k) => (
            k.as_der().unwrap().as_ref().to_vec(),
            k.public_key().as_der().unwrap().as_ref().to_vec()
        ),
        GeneratedKey::Ed(k) => (
            k.to_pkcs8v1().unwrap().as_ref().to_vec(),
            k.public_key().as_der().unwrap().as_ref().to_vec()
        ),
        GeneratedKey::Pq(k) => (
            k.to_pkcs8().unwrap().as_ref().to_vec(),
            k.public_key().as_der().unwrap().as_ref().to_vec()
        ),
    };

    // Standard PKCS#8 headers for Private, SubjectPublicKeyInfo for Public
    Ok((
        to_pem("PRIVATE KEY", &priv_der),
        to_pem("PUBLIC KEY", &pub_der)
    ))
}