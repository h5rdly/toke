use pyo3::prelude::*;
use pyo3::{create_exception}; 
use pyo3::types::{PyDict, PyList};
use pyo3::exceptions::{PyValueError, PyKeyError};

use pythonize::depythonize;
use serde_json::Value; 

use crate::{TokeError, PyJWTError};
use crate::jwk; 

create_exception!(toke, PyJWKSetError, PyJWTError); 
create_exception!(toke, PyJWKError, PyJWTError);


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
        let raw: Value = depythonize(jwk_data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK data: {}", e)))?;
        let (inner, alg) = jwk::normalize(raw, algorithm).map_err(PyValueError::new_err)?;

        Ok(PyJWK { inner, algorithm_name: alg })
    }

    #[staticmethod]
    #[pyo3(signature = (data, algorithm=None))]
    pub fn from_json(data: &str, algorithm: Option<String>) -> PyResult<Self> {
        let raw = jwk::parse_json(data).map_err(PyValueError::new_err)?;
        let (inner, alg) = jwk::normalize(raw, algorithm).map_err(PyValueError::new_err)?;

        Ok(PyJWK { inner, algorithm_name: alg })
    }
    
    #[staticmethod]
    #[pyo3(signature = (obj, algorithm=None))]
    pub fn from_dict(obj: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        Self::new(obj, algorithm)
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

// Internal helpers needed by lib.rs (Delegating to core)
impl PyJWK {
    pub(crate) fn to_decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, TokeError> {
        jwk::to_decoding_key(&self.inner)
    }

    pub(crate) fn to_key_bytes(&self) -> PyResult<Vec<u8>> {
        jwk::extract_key_bytes(&self.inner).map_err(PyValueError::new_err)
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
        // Convert Python List -> Rust Vec<Value>
        let raw_list: Vec<Value> = depythonize(keys)
            .map_err(|_| PyJWKSetError::new_err("Invalid JWK Set value"))?;
            
        Self::from_values(raw_list)
    }


    #[getter]
    fn keys(&self) -> Vec<PyJWK> {
        self.keys.clone()
    }


    #[staticmethod]
    fn from_json(data: &str) -> PyResult<Self> {
        let val = jwk::parse_json(data).map_err(PyValueError::new_err)?;
        
        let keys_array = val.get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| PyValueError::new_err("JWK Set must have a 'keys' array"))?
            .clone();

        Self::from_values(keys_array)
    }


    #[staticmethod]
    fn from_dict(obj: &Bound<'_, PyDict>) -> PyResult<Self> {
        let keys = obj.get_item("keys")
            .map_err(|_| PyValueError::new_err("JWK Set must have a 'keys' key"))?
            .ok_or_else(|| PyValueError::new_err("JWK Set 'keys' is None"))?;
            
        // Delegate to new() to handle the list conversion
        Self::new(&keys)
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


impl PyJWKSet {
    fn from_values(values: Vec<Value>) -> PyResult<Self> {
        let valid_keys = jwk::normalize_key_set(values);
        
        if valid_keys.is_empty() {
             return Err(PyJWKSetError::new_err("The JWK Set did not contain any usable keys"));
        }

        let py_keys = valid_keys.into_iter()
            .map(|(inner, alg)| PyJWK { inner, algorithm_name: alg })
            .collect();

        Ok(PyJWKSet { keys: py_keys })
    }
}


pub fn from_jwk(jwk: &Bound<'_, PyAny>, algorithm_hint: &str) -> PyResult<PyJWK> {
    if let Ok(s) = jwk.extract::<String>() {
         PyJWK::from_json(&s, Some(algorithm_hint.to_string()))
    } else if let Ok(d) = jwk.extract::<Bound<'_, PyDict>>() {
         PyJWK::from_dict(&d, Some(algorithm_hint.to_string()))
    } else {
         use pyo3::exceptions::PyTypeError;
         Err(PyTypeError::new_err("Expected string or dict"))
    }
}


pub fn from_jwk_set(data: &Bound<'_, PyAny>) -> PyResult<PyJWKSet> {
    if let Ok(s) = data.extract::<String>() {
        // Handle JSON String
        PyJWKSet::from_json(&s)
    } else if let Ok(d) = data.extract::<Bound<'_, PyDict>>() {
        // Handle Dict (e.g. {"keys": [...]})
        PyJWKSet::from_dict(&d)
    } else if let Ok(_l) = data.extract::<Bound<'_, PyList>>() {
        // Handle List directly (e.g. [key1, key2]) - effectively calling new()
        PyJWKSet::new(data)
    } else {
        use pyo3::exceptions::PyTypeError;
        Err(PyTypeError::new_err("Expected string, dict, or list of keys"))
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
    parent_module.add("PyJWKSetError", py.get_type::<PyJWKSetError>())?; 
    parent_module.add("PyJWKError", py.get_type::<PyJWKError>())?;  

    parent_module.add_class::<PyJWKSetIterator>()?;
    parent_module.add_class::<PyJWK>()?;
    parent_module.add_class::<PyJWKSet>()?;
    
    Ok(())
}