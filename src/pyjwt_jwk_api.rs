use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{Jwk as RustJwk, JwkSet as RustJwkSet, AlgorithmParameters, EllipticCurve, };

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyKeyError, PyTypeError};
use pyo3::types::{PyDict, PyList};

use pythonize::depythonize;
use serde_json::Value; 
// [FIX] Added InvalidKeyError to imports
use crate::{TokeError, PyJWKSetError, InvalidKeyError}; 

#[pyclass(name = "PyJWK")]
#[derive(Clone)]
pub struct PyJWK {
    pub inner: Value, 
    pub algorithm_name: Option<String>,
}

#[pymethods]
impl PyJWK {
    #[new]
    #[pyo3(signature = (jwk_data, algorithm=None))]
    fn new(jwk_data: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        let inner: Value = depythonize(jwk_data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK data: {}", e)))?;

        if !inner.is_object() {
             return Err(PyValueError::new_err("JWK must be an object"));
        }
        if inner.get("kty").is_none() {
             return Err(PyValueError::new_err("Key type (kty) not found"));
        }

        let alg = if let Some(a) = algorithm {
            Some(a)
        } else if let Some(key_alg) = inner.get("alg").and_then(|v| v.as_str()) {
            Some(key_alg.to_string()) 
        } else {
            deduce_algorithm(&inner)?
        };

        Ok(PyJWK {
            inner,
            algorithm_name: alg,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (obj, algorithm=None))]
    pub fn from_dict(obj: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        Self::new(obj, algorithm)
    }

    #[staticmethod]
    #[pyo3(signature = (data, algorithm=None))]
    pub fn from_json(data: &str, algorithm: Option<String>) -> PyResult<Self> {
        let inner: Value = serde_json::from_str(data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK JSON: {}", e)))?;
        
        if !inner.is_object() {
             return Err(PyValueError::new_err("JWK must be an object"));
        }
        if inner.get("kty").is_none() {
             return Err(PyValueError::new_err("Key type (kty) not found"));
        }

        let alg = if let Some(a) = algorithm {
            Some(a)
        } else if let Some(key_alg) = inner.get("alg").and_then(|v| v.as_str()) {
            Some(key_alg.to_string())
        } else {
            deduce_algorithm(&inner)?
        };

        Ok(PyJWK { inner, algorithm_name: alg })
    }

    #[getter]
    fn key_type(&self) -> Option<String> {
        self.inner.get("kty").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    #[getter]
    fn key_id(&self) -> Option<String> {
        self.inner.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    #[getter]
    fn public_key_use(&self) -> Option<String> {
        self.inner.get("use").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    #[getter]
    fn algorithm_name(&self) -> Option<String> {
        self.algorithm_name.clone()
    }

    fn __repr__(&self) -> String {
        format!("<PyJWK kid={:?}>", self.key_id())
    }
}

fn deduce_algorithm(jwk: &Value) -> PyResult<Option<String>> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| PyValueError::new_err("kty missing"))?;
    
    match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| PyValueError::new_err("crv missing for EC key"))?;
            match crv {
                "P-256" => Ok(Some("ES256".to_string())),
                "P-384" => Ok(Some("ES384".to_string())),
                "P-521" => Ok(Some("ES512".to_string())),
                "secp256k1" => Ok(Some("ES256K".to_string())),
                _ => Err(PyValueError::new_err(format!("Unsupported crv: {}", crv)))
            }
        },
        "RSA" => Ok(Some("RS256".to_string())),
        "oct" => Ok(Some("HS256".to_string())),
        "OKP" => {
             let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| PyValueError::new_err("crv missing for OKP"))?;
             if crv == "Ed25519" || crv == "Ed448" {
                 Ok(Some("EdDSA".to_string()))
             } else {
                 Err(PyValueError::new_err(format!("Unsupported crv for OKP: {}", crv)))
             }
        },
        // [FIX] Strictly reject unknown key types to match PyJWT tests
        other => Err(InvalidKeyError::new_err(format!("Unknown key type: {}", other)))
    }
}

impl PyJWK {
    pub(crate) fn to_decoding_key(&self) -> Result<DecodingKey, TokeError> {
        // Warning: This will fail for secp256k1 keys because upstream 'jwk' crate is strict.
        // If we need support, we must parse manually or patch upstream.
        // For standard keys, it works via serde roundtrip.
        let json_str = serde_json::to_string(&self.inner).map_err(|e| TokeError::Generic(e.to_string()))?;
        let rust_jwk: RustJwk = serde_json::from_str(&json_str)
            .map_err(|e| TokeError::Generic(format!("JWK parsing failed: {}", e)))?;
        DecodingKey::from_jwk(&rust_jwk).map_err(TokeError::Jwt)
    }
}

#[pyclass(name = "PyJWKSet")]
pub struct PyJWKSet {
    pub keys: Vec<PyJWK>,
}

#[pymethods]
impl PyJWKSet {
    #[new]
    #[pyo3(signature = (keys))]
    fn new(keys: &Bound<'_, PyAny>) -> PyResult<Self> {
        let list = keys.downcast::<PyList>().map_err(|_| {
            PyJWKSetError::new_err("Invalid JWK Set value") 
        })?;

        let mut py_keys = Vec::new();
        for item in list.iter() {
            if let Ok(dict) = item.cast::<PyDict>() {
                // Ignore errors for individual keys in a set (PyJWT behavior)
                if let Ok(jwk) = PyJWK::new(dict, None) {
                    if let Some(u) = jwk.public_key_use() {
                        if u == "enc" { continue; }
                    }
                    py_keys.push(jwk);
                }
            }
        }
        
        if py_keys.is_empty() {
            return Err(PyJWKSetError::new_err("The JWK Set did not contain any usable keys"));
        }

        Ok(PyJWKSet { keys: py_keys })
    }

    #[getter]
    fn keys(&self) -> Vec<PyJWK> {
        self.keys.clone()
    }

    #[staticmethod]
    fn from_dict(obj: &Bound<'_, PyDict>) -> PyResult<Self> {
        let keys = obj.get_item("keys")
            .map_err(|_| PyValueError::new_err("JWK Set must have a 'keys' key"))?
            .ok_or_else(|| PyValueError::new_err("JWK Set 'keys' is None"))?;
            
        Self::new(&keys)
    }

    #[staticmethod]
    fn from_json(data: &str) -> PyResult<Self> {
        let set_val: Value = serde_json::from_str(data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK Set JSON: {}", e)))?;
            
        let keys_array = set_val.get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| PyValueError::new_err("JWK Set must have a 'keys' array"))?;

        let mut keys = Vec::new();
        for k in keys_array {
            let alg = if let Some(ka) = k.get("alg").and_then(|v| v.as_str()) {
                Some(ka.to_string())
            } else {
                deduce_algorithm(k).ok().flatten()
            };
            
            // For Set loading, we often want to skip invalid keys instead of crashing the whole set
            // But if deduce_algorithm fails, we skip this key.
            if let Ok(Some(_)) | Ok(None) = deduce_algorithm(k) {
                 let py_jwk = PyJWK { inner: k.clone(), algorithm_name: alg };
                 
                 if let Some(u) = py_jwk.public_key_use() {
                    if u == "enc" { continue; }
                 }
                 keys.push(py_jwk);
            }
        }

        if keys.is_empty() {
             return Err(PyJWKSetError::new_err("The JWK Set did not contain any usable keys"));
        }

        Ok(PyJWKSet { keys })
    }

    fn __getitem__(&self, kid: String) -> PyResult<PyJWK> {
        for key in &self.keys {
            if let Some(k) = key.key_id() {
                if k == kid {
                    return Ok(key.clone());
                }
            }
        }
        Err(PyKeyError::new_err(format!("keyset has no key for kid: {}", kid)))
    }

    fn __len__(&self) -> usize {
        self.keys.len()
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<Py<PyJWKSetIterator>> {
        let iter = PyJWKSetIterator {
            iter: slf.keys.clone().into_iter(),
        };
        Py::new(slf.py(), iter)
    }
    
    fn __repr__(&self) -> String {
        format!("<PyJWKSet keys_len={}>", self.keys.len())
    }
}

#[pyclass]
struct PyJWKSetIterator {
    iter: std::vec::IntoIter<PyJWK>,
}

#[pymethods]
impl PyJWKSetIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyJWK> {
        slf.iter.next()
    }
}

pub fn register_jwk_module(py: Python, parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyJWKSetIterator>()?;
    let jwk_module = PyModule::new(py, "jwk")?;
    jwk_module.add_class::<PyJWK>()?;
    jwk_module.add_class::<PyJWKSet>()?;
    parent_module.add_submodule(&jwk_module)?;
    Ok(())
}