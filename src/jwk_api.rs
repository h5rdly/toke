use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{Jwk as RustJwk, JwkSet as RustJwkSet, AlgorithmParameters, EllipticCurve, };

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyKeyError, };
use pyo3::types::{PyDict, PyList};

use pythonize::depythonize;
use crate::TokeError;


#[pyclass(name = "PyJWK")]
#[derive(Clone)]
pub struct PyJwk {
    pub inner: RustJwk,
    pub algorithm_name: Option<String>,
}


#[pymethods]
impl PyJwk {
    #[new]
    #[pyo3(signature = (jwk_data, algorithm=None))]
    fn new(jwk_data: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        // 1. Parse Dict -> Rust Jwk Struct
        // We use depythonize to convert Python Dict -> Serde JSON -> Rust Struct
        let inner: RustJwk = depythonize(jwk_data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK data: {}", e)))?;

        // 2. Algorithm Deduction Logic (Matching PyJWT api_jwk.py)
        let alg = if let Some(a) = algorithm {
            Some(a)
        } else if let Some(key_alg) = &inner.common.key_algorithm {
            // If the JWK itself has an "alg" field
            Some(format!("{:?}", key_alg)) // KeyAlgorithm enum Debug impl gives string like "HS256"
        } else {
            // Deduce based on kty/crv
            deduce_algorithm(&inner)?
        };

        Ok(PyJwk {
            inner,
            algorithm_name: alg,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (obj, algorithm=None))]
    fn from_dict(obj: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        Self::new(obj, algorithm)
    }

    #[staticmethod]
    #[pyo3(signature = (data, algorithm=None))]
    fn from_json(data: &str, algorithm: Option<String>) -> PyResult<Self> {
        let inner: RustJwk = serde_json::from_str(data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK JSON: {}", e)))?;
        
        let alg = if let Some(a) = algorithm {
            Some(a)
        } else if let Some(key_alg) = &inner.common.key_algorithm {
            Some(format!("{:?}", key_alg))
        } else {
            deduce_algorithm(&inner)?
        };

        Ok(PyJwk { inner, algorithm_name: alg })
    }

    #[getter]
    fn key_type(&self) -> Option<String> {
        // Map Rust Enum back to string if needed, or rely on how serde serialized it.
        // For simplicity, we assume standard names.
        match &self.inner.algorithm {
            AlgorithmParameters::EllipticCurve(_) => Some("EC".to_string()),
            AlgorithmParameters::RSA(_) => Some("RSA".to_string()),
            AlgorithmParameters::OctetKey(_) => Some("oct".to_string()),
            AlgorithmParameters::OctetKeyPair(_) => Some("OKP".to_string()),
        }
    }

    #[getter]
    fn key_id(&self) -> Option<String> {
        self.inner.common.key_id.clone()
    }

    #[getter]
    fn public_key_use(&self) -> Option<String> {
        self.inner.common.public_key_use.as_ref().map(|u| format!("{:?}", u).to_lowercase())
    }
}

// Helper to deduce algorithm matching PyJWT logic
fn deduce_algorithm(jwk: &RustJwk) -> PyResult<Option<String>> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => {
            match params.curve {
                EllipticCurve::P256 => Ok(Some("ES256".to_string())),
                EllipticCurve::P384 => Ok(Some("ES384".to_string())),
                EllipticCurve::P521 => Ok(Some("ES512".to_string())), // PyJWT maps P-521 to ES512
                _ => Err(PyValueError::new_err(format!("Unsupported crv: {:?}", params.curve)))
            }
        },
        AlgorithmParameters::RSA(_) => Ok(Some("RS256".to_string())),
        AlgorithmParameters::OctetKey(_) => Ok(Some("HS256".to_string())),
        AlgorithmParameters::OctetKeyPair(params) => {
             // Rust crate uses 'Ed25519' curve enum
             if format!("{:?}", params.curve) == "Ed25519" {
                 Ok(Some("EdDSA".to_string()))
             } else {
                 Err(PyValueError::new_err("Unsupported crv for OKP"))
             }
        }
    }
}

impl PyJwk {
    // Internal helper for lib.rs to get a DecodingKey
    pub(crate) fn to_decoding_key(&self) -> Result<DecodingKey, TokeError> {
        DecodingKey::from_jwk(&self.inner).map_err(TokeError::Jwt)
    }
}

#[pyclass(name = "PyJWKSet")]
pub struct PyJwkSet {
    pub keys: Vec<PyJwk>,
}

#[pymethods]
impl PyJwkSet {
    #[new]
    fn new(keys: &Bound<'_, PyList>) -> PyResult<Self> {
        let mut py_keys = Vec::new();
        for item in keys.iter() {
            if let Ok(dict) = item.cast::<PyDict>() {
                // We try to create a PyJwk from the dict. 
                // PyJWT skips unusable keys, we can try the same.
                if let Ok(jwk) = PyJwk::new(dict, None) {
                    py_keys.push(jwk);
                }
            }
        }
        
        if py_keys.is_empty() {
            return Err(PyValueError::new_err("The JWK Set did not contain any usable keys"));
        }

        Ok(PyJwkSet { keys: py_keys })
    }

    #[staticmethod]
    fn from_dict(obj: &Bound<'_, PyDict>) -> PyResult<Self> {
        let keys = obj.get_item("keys")
            .map_err(|_| PyValueError::new_err("JWK Set must have a 'keys' key"))?
            .ok_or_else(|| PyValueError::new_err("JWK Set 'keys' is None"))?;
            
        let list = keys.cast::<PyList>()
            .map_err(|_| PyValueError::new_err("'keys' must be a list"))?;
            
        Self::new(list)
    }

    #[staticmethod]
    fn from_json(data: &str) -> PyResult<Self> {
        let set: RustJwkSet = serde_json::from_str(data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK Set JSON: {}", e)))?;
            
        let keys = set.keys.into_iter().map(|k| {
            // Re-deduce alg for each key if needed
            let alg = if let Some(ka) = &k.common.key_algorithm {
                Some(format!("{:?}", ka))
            } else {
                deduce_algorithm(&k).ok().flatten()
            };
            PyJwk { inner: k, algorithm_name: alg }
        }).collect();

        Ok(PyJwkSet { keys })
    }

    fn __getitem__(&self, kid: String) -> PyResult<PyJwk> {
        for key in &self.keys {
            if let Some(k) = &key.inner.common.key_id {
                if k == &kid {
                    return Ok(key.clone());
                }
            }
        }
        Err(PyKeyError::new_err(format!("keyset has no key for kid: {}", kid)))
    }
}

pub fn register_jwk_module(py: Python, parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let jwk_module = PyModule::new(py, "jwk")?;
    jwk_module.add_class::<PyJwk>()?;
    jwk_module.add_class::<PyJwkSet>()?;
    parent_module.add_submodule(&jwk_module)?;
    Ok(())
}