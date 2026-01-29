use std::num::NonZeroU32;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use aws_lc_rs::{aead, hkdf, pbkdf2, rand};
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
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65_SIGNING, ML_DSA_44_SIGNING, ML_DSA_87_SIGNING
};


// -- Helpers

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


// -- Python API

/// Generate cryptographically secure random bytes.
#[pyfunction]
fn random_bytes<'py>(py: Python<'py>, length: usize) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = vec![0u8; length];
    rand::fill(&mut out).map_err(|_| PyValueError::new_err("RNG failed"))?;
    Ok(PyBytes::new(py, &out))
}


/// Hash a password using PBKDF2-HMAC-SHA256.
#[pyfunction]
#[pyo3(signature = (password, salt, iterations, length=32))]
fn pbkdf2_hmac_sha256<'py>(py: Python<'py>, password: &[u8], salt: &[u8], iterations: u32, length: usize) -> PyResult<Bound<'py, PyBytes>> {
    
    let mut out = vec![0u8; length];
    let non_zero_iter = NonZeroU32::new(iterations)
        .ok_or_else(|| PyValueError::new_err("Iterations must be > 0"))?;

    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, non_zero_iter, salt, password, &mut out);
    Ok(PyBytes::new(py, &out))
}


/// Derive a key using HKDF-SHA256.
#[pyfunction]
#[pyo3(signature = (secret, salt, info, length=32))]
fn hkdf_sha256<'py>(py: Python<'py>, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> PyResult<Bound<'py, PyBytes>> {
    
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(secret);
    let mut out = vec![0u8; length];
    
    let info_arr = [info];
    let okm = prk.expand(&info_arr, hkdf::HKDF_SHA256)
        .map_err(|_| PyValueError::new_err("HKDF expansion failed"))?;
        
    okm.fill(&mut out).map_err(|_| PyValueError::new_err("HKDF fill failed"))?;
    
    Ok(PyBytes::new(py, &out))
}


/// Encrypt data using AES-256-GCM.
#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None))]
fn encrypt_aes_256_gcm<'py>(
    py: Python<'py>, 
    key: &[u8], 
    plaintext: &[u8], 
    aad: Option<&[u8]>
) -> PyResult<Bound<'py, PyBytes>> {
    
    if key.len() != 32 {
        return Err(PyValueError::new_err("AES-256-GCM key must be exactly 32 bytes"));
    }
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| PyValueError::new_err("Failed to create key"))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    // 1. Generate Nonce
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes).map_err(|_| PyValueError::new_err("RNG failure"))?;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| PyValueError::new_err("Nonce error"))?;

    // 2. Prepare Buffer (Contains ONLY plaintext initially)
    // The sealing function encrypts in-place and appends the tag.
    let mut in_out = plaintext.to_vec();
    let aad_tag = aead::Aad::from(aad.unwrap_or(&[]));
    
    // 3. Encrypt
    sealing_key.seal_in_place_append_tag(nonce, aad_tag, &mut in_out)
        .map_err(|_| PyValueError::new_err("Encryption failed"))?;

    // 4. Construct Final Output: [Nonce (12)] + [Ciphertext + Tag]
    let mut out_buffer = Vec::with_capacity(12 + in_out.len());
    out_buffer.extend_from_slice(&nonce_bytes); // Prepend plain nonce
    out_buffer.append(&mut in_out);             // Append encrypted data

    Ok(PyBytes::new(py, &out_buffer))
}


/// Decrypt data using AES-256-GCM.
#[pyfunction]
#[pyo3(signature = (key, ciphertext, aad=None))]
fn decrypt_aes_256_gcm<'py>(
    py: Python<'py>, 
    key: &[u8], 
    ciphertext: &[u8], 
    aad: Option<&[u8]>
) -> PyResult<Bound<'py, PyBytes>> {
    
    if key.len() != 32 {
        return Err(PyValueError::new_err("AES-256-GCM key must be exactly 32 bytes"));
    }
    
    if ciphertext.len() < 28 { 
        return Err(PyValueError::new_err("Ciphertext too short"));
    }

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| PyValueError::new_err("Failed to create key"))?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| PyValueError::new_err("Invalid nonce"))?;

    let mut in_out = encrypted_data.to_vec();
    let aad_tag = aead::Aad::from(aad.unwrap_or(&[]));

    let plaintext = opening_key.open_in_place(nonce, aad_tag, &mut in_out)
        .map_err(|_| PyValueError::new_err("Decryption failed (auth tag mismatch?)"))?;

    Ok(PyBytes::new(py, plaintext))
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


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Note: We use 'm' (the main module) as the context for wrap_pyfunction
    m.add_function(wrap_pyfunction!(encrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_pair, m)?)?;
    Ok(())
}