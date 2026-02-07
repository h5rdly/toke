use std::num::NonZeroU32;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use aws_lc_rs::{aead, hkdf, pbkdf2, rand, digest as _digest};
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

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::WebtokenError;


fn gen_witness(n: &BigUint) -> Result<BigUint, WebtokenError> {
    let bit_len = n.bits();
    let byte_len = ((bit_len + 7) / 8) as usize;
    let mut bytes = vec![0u8; byte_len];

    // Try a few times to get a valid number (rejection sampling-ish)
    for _ in 0..10 {
        // 1. Fill bytes with secure randomness from AWS-LC
        rand::fill(&mut bytes)
            .map_err(|_| WebtokenError::Generic("AWS-LC RNG failure".into()))?;

        // 2. Convert to BigUint
        let mut g = BigUint::from_bytes_be(&bytes);

        // 3. Ensure it is in range [2, n-1]
        // We use modulo to force it into range. This introduces slight bias 
        // but is acceptable for finding a factorization witness.
        g %= n;

        if g > BigUint::one() {
            return Ok(g);
        }
    }
    
    Err(WebtokenError::Generic("Failed to generate valid witness".into()))
}


pub fn recover_primes(n: &BigUint, e: &BigUint, d: &BigUint) -> Result<(BigUint, BigUint), String> {
    // 1. k = d * e - 1
    let k = d * e - BigUint::one();

    // 2. Extract powers of 2 from k: k = 2^t * r
    let mut r = k.clone();
    let mut t = 0;
    while r.is_even() {
        r >>= 1;
        t += 1;
    }

    // Try up to 100 times (failure is statistically impossible for valid keys)
    for _ in 0..100 {
        // Pick random g in [2, n-1]
        // We simulate this by generating random bytes and modding, ensures uniform distribution enough for this
        let Ok(g) = gen_witness(n) else { continue };
        if g <= BigUint::one() { continue; }

        // y = g^r mod n
        let mut y = g.modpow(&r, n);

        if y.is_one() || y == n - BigUint::one() {
            continue;
        }

        for _ in 1..t {
            let x = y.modpow(&BigUint::from(2u32), n);
            
            if x.is_one() {
                // Found non-trivial square root of 1
                // y is a non-trivial root: y^2 = 1 (mod n) and y != 1, y != -1
                // gcd(y - 1, n) is a factor
                let p = (y - BigUint::one()).gcd(n);
                let q = n / &p;
                return Ok((p, q));
            }
            
            if x == n - BigUint::one() {
                break;
            }
            y = x;
        }
    }
    
    Err("Failed to recover primes (invalid key or bad luck)".into())
}


// Compute CRT parameters: dp, dq, qi
pub fn compute_crt(
    _n: &BigUint, p: &BigUint, q: &BigUint, d: &BigUint
) -> Result<(BigUint, BigUint, BigUint), String> {
    // Determine which is p and q for CRT (usually p > q, but specific libraries vary).
    // OpenSSL/RFC usually expects p and q such that n = p*q.
    // qi = q^-1 mod p.
    
    let p_minus_1 = p - BigUint::one();
    let q_minus_1 = q - BigUint::one();
    
    let dp = d % &p_minus_1;
    let dq = d % &q_minus_1;
    
    // Calculate modular inverse of q mod p
    let qi = mod_inverse(q, p).ok_or("Inverse calculation failed")?;

    Ok((dp, dq, qi))
}

// Extended Euclidean Algorithm for modular inverse
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_signed = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_signed = BigInt::from_biguint(Sign::Plus, m.clone());
    
    let (g, x, _) = extended_gcd(&a_signed, &m_signed);
    if g != BigInt::one() {
        return None;
    }
    
    let result = x % &m_signed;
    if result.sign() == Sign::Minus {
        (result + m_signed).to_biguint()
    } else {
        result.to_biguint()
    }
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (g, x, y) = extended_gcd(b, &(a % b));
        (g, y.clone(), x - (a / b) * y)
    }
}


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


fn der_encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}


// Simple ASN.1 DER Writer for Integers
fn der_encode_int(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(0x02); // INTEGER tag
    
    // Minimal encoding: DER requires strict shortest representation.
    // But for SSH conversion, we trust the input bytes mostly conform to signed big-endian.
    // SSH mpint already includes the leading zero if MSB is set, which matches DER requirements.
    // However, SSH might have extra leading zeros which DER forbids.
    // We'll skip extra leading zeros, but keep one if MSB of next byte is set.
    
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start+1] & 0x80) == 0 {
        start += 1;
    }
    let slice = &bytes[start..];
    
    // Length handling (simple form < 128 bytes, complex otherwise)
    let len = slice.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    
    out.extend_from_slice(slice);
}


fn der_encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE tag
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}


// -- SSH Parsing Logic

pub fn ssh_to_pem(data: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    
    if parts.len() < 2 { return Err("Invalid SSH key format".into()); }
    
    let key_type = parts[0];
    let key_body = parts[1];
    
    let decoded = STANDARD.decode(key_body).map_err(|_| "Invalid Base64")?;
    let mut cursor = &decoded[..];

    let read_string = |buf: &mut &[u8]| -> Result<Vec<u8>, String> {
        if buf.len() < 4 { return Err("Truncated SSH key".into()); }
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        *buf = &buf[4..];
        if buf.len() < len { return Err("Truncated SSH key body".into()); }
        let val = buf[0..len].to_vec();
        *buf = &buf[len..];
        Ok(val)
    };

    let header = read_string(&mut cursor)?;

    if key_type == "ssh-rsa" && header == b"ssh-rsa" {
        let e = read_string(&mut cursor)?;
        let n = read_string(&mut cursor)?;
        
        let mut seq_content = Vec::new();
        der_encode_int(&mut seq_content, &n);
        der_encode_int(&mut seq_content, &e);
        let der = der_encode_sequence(&seq_content);
        return Ok(to_pem("RSA PUBLIC KEY", &der));
    }
    else if key_type == "ssh-ed25519" && header == b"ssh-ed25519" {
        let key = read_string(&mut cursor)?;
        if key.len() != 32 { return Err("Invalid Ed25519 key length".into()); }
        
        // OID: 1.3.101.112 (Ed25519)
        let mut algo_id = Vec::new();
        algo_id.push(0x06); 
        algo_id.push(0x03);
        algo_id.extend_from_slice(&[0x2b, 0x65, 0x70]);
        let algo_seq = der_encode_sequence(&algo_id);
        
        let mut bit_string = Vec::new();
        bit_string.push(0x03); 
        bit_string.push(33);   
        bit_string.push(0x00); 
        bit_string.extend_from_slice(&key);
        
        let mut der = Vec::new();
        der.extend_from_slice(&algo_seq);
        der.extend_from_slice(&bit_string);
        
        return Ok(to_pem("PUBLIC KEY", &der_encode_sequence(&der)));
    }
    else if key_type.starts_with("ecdsa-sha2-nistp") && header.starts_with(b"ecdsa-sha2-nistp") {
        let curve = read_string(&mut cursor)?;
        let key = read_string(&mut cursor)?; // Q point (04 || X || Y)
        
        let mut der = Vec::new();
        
        let mut algo_id = Vec::new();
        algo_id.push(0x06); algo_id.push(0x07);
        algo_id.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // ecPublicKey
        
        if curve == b"nistp256" {
             algo_id.push(0x06); algo_id.push(0x08);
             algo_id.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // prime256v1
        } else {
             return Err("Unsupported SSH curve".into());
        }
        
        let algo_seq = der_encode_sequence(&algo_id);
        
        let mut bit_string = Vec::new();
        bit_string.push(0x03);
        
        // Correct length encoding for BitString
        // key.len() is 65. +1 for padding = 66.
        der_encode_len(&mut bit_string, key.len() + 1);
        bit_string.push(0x00); 
        bit_string.extend_from_slice(&key);
        
        der.extend_from_slice(&algo_seq);
        der.extend_from_slice(&bit_string);
        
        return Ok(to_pem("PUBLIC KEY", &der_encode_sequence(&der)));
    }

    Err(format!("Unsupported SSH key type: {}", key_type))
}


// -- Python API

#[pyfunction]
fn digest(algorithm: &str, data: &[u8]) -> PyResult<Vec<u8>> {
    let alg = match algorithm.to_uppercase().as_str() {
        "SHA256" | "HS256" | "RS256" | "ES256" | "PS256" | "ES256K" => &_digest::SHA256,
        "SHA384" | "HS384" | "RS384" | "ES384" | "PS384" => &_digest::SHA384,
        "SHA512" | "HS512" | "RS512" | "ES512" | "PS512" => &_digest::SHA512,
        _ => return Err(PyValueError::new_err("Unsupported hash algorithm")),
    };
    Ok(_digest::digest(alg, data).as_ref().to_vec())
}


#[pyfunction]
#[pyo3(signature = (data, password=None))]
fn load_pem_private_key(py: Python, data: &[u8], password: Option<&[u8]>) -> PyResult<Py<PyBytes>> {
    if password.is_some() {
        return Err(PyValueError::new_err("Encrypted keys not supported in test utils"));
    }
    
    let s = std::str::from_utf8(data).map_err(|_| PyValueError::new_err("Invalid UTF-8 in PEM"))?;
    let trimmed = s.trim();

    if !trimmed.starts_with("-----BEGIN") {
        return Err(PyValueError::new_err("Invalid PEM format"));
    }

    Ok(PyBytes::new(py, data).into())
}


#[pyfunction]
fn load_pem_public_key(py: Python, data: &[u8]) -> PyResult<Py<PyBytes>> {
    
    let s = std::str::from_utf8(data).map_err(|_| PyValueError::new_err("Invalid UTF-8 in PEM"))?;
    let trimmed = s.trim();

    if !trimmed.starts_with("-----BEGIN") {
        return Err(PyValueError::new_err("Invalid PEM format"));
    }

    Ok(PyBytes::new(py, data).into())
}


#[pyfunction]
fn load_ssh_public_key(py: Python, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let pem = ssh_to_pem(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &pem).into())
}


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
#[pyo3(signature = (algorithm, key_size=None))]
pub fn generate_key_pair(algorithm: &str, key_size: Option<usize>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    
    enum GeneratedKey {
        Ec(EcdsaKeyPair), Rsa(RsaKeyPair), Ed(Ed25519KeyPair), Pq(PqdsaKeyPair),
    }

    let key = match algorithm.to_uppercase().as_str() {
        // ... (ECDSA cases remain same) ...
        "ES256" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES384" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES512" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ES256K" | "SECP256K1" => GeneratedKey::Ec(EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        
        // --- RSA (Handle size) ---
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let size = match key_size.unwrap_or(2048) {
                2048 => KeySize::Rsa2048,
                3072 => KeySize::Rsa3072,
                4096 => KeySize::Rsa4096,
                8192 => KeySize::Rsa8192,
                _ => return Err(PyValueError::new_err("Unsupported RSA key size")),
            };
            GeneratedKey::Rsa(RsaKeyPair::generate(size).map_err(|_| PyValueError::new_err("Gen failed"))?)
        },
        
        // ... (EdDSA / PQ cases remain same) ...
        "EDDSA" | "ED25519" => {
            GeneratedKey::Ed(Ed25519KeyPair::generate().map_err(|_| PyValueError::new_err("Gen failed"))?)
        },
        "ML-DSA-44" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ML-DSA-65" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),
        "ML-DSA-87" => GeneratedKey::Pq(PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).map_err(|_| PyValueError::new_err("Gen failed"))?),

        _ => return Err(PyValueError::new_err(format!("Unsupported key generation algo: {}", algorithm))),
    };

    // ... (DER encoding logic remains same) ...
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

    Ok((
        to_pem("PRIVATE KEY", &priv_der),
        to_pem("PUBLIC KEY", &pub_der)
    ))
}


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Note: We use 'm' (the main module) as the context for wrap_pyfunction

    m.add_function(wrap_pyfunction!(digest, m)?)?;
    m.add_function(wrap_pyfunction!(load_pem_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_pem_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_ssh_public_key, m)?)?;

    m.add_function(wrap_pyfunction!(encrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_pair, m)?)?;
    
    Ok(())
}