use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value; 
use num_bigint::BigUint;

use jsonwebtoken::{DecodingKey, Algorithm};
use pyo3::prelude::*;
use pyo3::create_exception; 
use pyo3::types::{PyDict, PyList, PyBytes, PyInt};
use pyo3::exceptions::{PyValueError, PyKeyError, PyTypeError};

use pythonize::depythonize;

use crate::{jwk, WebtokenError, PyJWTError, InvalidAlgorithmError}; 
use crate::algorithms::ExternalAlgorithm;
use crate::jwk::{create_decoding_key, extract_or_recover_rsa_components};

create_exception!(toke, PyJWKSetError, PyJWTError); 
create_exception!(toke, PyJWKError, PyJWTError);


#[pyclass(name = "PyJWK")]
#[derive(Clone)]
pub struct PyJWK {
    pub inner: Value, 
    pub algorithm_name: Option<String>,
}


// Helpers needed by lib.rs
impl PyJWK {

    pub(crate) fn to_key_bytes(&self, public_only: bool) -> PyResult<Vec<u8>> {
        jwk::extract_key_bytes(&self.inner, public_only).map_err(PyValueError::new_err)
    }
    
    pub fn to_decoding_key(&self, expected_alg: Algorithm) -> PyResult<DecodingKey> {
        // 1. Enforce 'alg' constraint if present in the JWK
        // This satisfies: test_decodes_with_jwk_and_mismatched_algorithm
        if let Some(ref jwk_alg_str) = self.algorithm_name {
            if let Ok(jwk_alg) = Algorithm::from_str(jwk_alg_str) {
                if jwk_alg != expected_alg {
                    return Err(InvalidAlgorithmError::new_err(format!(
                        "The specified key is for algorithm {:?} but the token is signed with {:?}.",
                        jwk_alg, expected_alg
                    )));
                }
            }
        }

        // 2. Delegate to internal helper for actual key creation
        jwk::create_decoding_key(&self.inner, expected_alg)
            .map_err(Into::into)
    }
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

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAny>> {
        let dict = pythonize::pythonize(py, &self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(dict.unbind())
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

    #[getter]
    fn key_type(&self) -> PyResult<String> {
        self.inner.get("kty")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| PyValueError::new_err("kty missing"))
    }
    
    
    pub fn public_key(&self) -> PyResult<PyJWK> {
        let mut new_val = self.inner.clone();
        
        if let Value::Object(ref mut map) = new_val {
            // Remove generic private parameters
            map.remove("d");
            
            // Remove RSA private parameters
            map.remove("p");
            map.remove("q");
            map.remove("dp");
            map.remove("dq");
            map.remove("qi");
            map.remove("oth");
            
            // Remove Symmetric secrets (though usually not relevant for public_key())
            map.remove("k"); 
        }

        Ok(PyJWK { 
            inner: new_val, 
            algorithm_name: self.algorithm_name.clone() 
        })
    }

    // Helpers for internal use (mimic cryptography interface logic in Python)
    pub fn public_numbers(&self, py: Python) -> PyResult<Py<PyAny>> {
        // Called by check_key_length in Python. Returns a SimpleNamespace or object with 'n', 'e' if RSA
        
        let kty = self.key_type()?;

        if kty == "RSA" {
            let types = pyo3::types::PyModule::import(py, "types")?;             let sn = types.call_method0("SimpleNamespace")?;
             
             if let Some(n_b64) = self.inner.get("n").and_then(|v| v.as_str()) {
                 let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(n_b64)
                    .map_err(|_| PyValueError::new_err("Invalid n base64"))?;
                 let int_cls = py.get_type::<pyo3::types::PyInt>();
                 let py_n = int_cls.call_method1("from_bytes", (n_bytes.as_slice(), "big"))?;
                 sn.setattr("n", py_n)?;
             }
             if let Some(e_b64) = self.inner.get("e").and_then(|v| v.as_str()) {
                 let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(e_b64)
                     .map_err(|_| PyValueError::new_err("Invalid e base64"))?;
                 let int_cls = py.get_type::<pyo3::types::PyInt>();
                 let py_e = int_cls.call_method1("from_bytes", (e_bytes.as_slice(), "big"))?;
                 sn.setattr("e", py_e)?;
             }
             return Ok(sn.into());
        }

        if kty == "EC" {
            // Helper closure to convert b64 -> Python Int
            let b64_to_int = |field: &str| -> PyResult<Py<PyAny>> {
                let val_b64 = self.inner.get(field).and_then(|v| v.as_str())
                    .ok_or_else(|| PyValueError::new_err(format!("Missing '{}'", field)))?;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(val_b64)
                    .map_err(|e| PyValueError::new_err(format!("Invalid base64 for {}: {}", field, e)))?;
                let int_cls = py.get_type::<pyo3::types::PyInt>();
                Ok(int_cls.call_method1("from_bytes", (bytes.as_slice(), "big"))?.into())
            };

            let x_py = b64_to_int("x")?;
            let y_py = b64_to_int("y")?;

            // Return PyEllipticCurvePublicNumbers (already defined in your file)
            // or a SimpleNamespace if you prefer loose typing.
            // Since you have the class defined:
            let obj = Py::new(py, PyEllipticCurvePublicNumbers { x: x_py, y: y_py })?;
            return Ok(obj.into_any());
        }

        Ok(py.None())
    }


    fn private_numbers(&self, py: Python) -> PyResult<Py<PyAny>> {

        let kty = self.key_type()?;

        if kty == "RSA" {
            let comps = extract_or_recover_rsa_components(&self.inner)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            let int_cls = py.get_type::<PyInt>();
            let bn_to_py = |bn: BigUint| -> PyResult<Py<PyAny>> {
                let bytes = bn.to_bytes_be();
                let bytes_obj = PyBytes::new(py, &bytes);
                Ok(int_cls.call_method1("from_bytes", (bytes_obj, "big"))?.into())
            };

            let n_py = bn_to_py(comps.n)?;
            let e_py = bn_to_py(comps.e)?;
            let pub_nums = Py::new(py, PyRSAPublicNumbers { n: n_py, e: e_py })?;

            let obj = Py::new(py, PyRSAPrivateNumbers {
                p: bn_to_py(comps.p)?,
                q: bn_to_py(comps.q)?,
                d: bn_to_py(comps.d)?,
                dmp1: bn_to_py(comps.dp)?,
                dmq1: bn_to_py(comps.dq)?,
                iqmp: bn_to_py(comps.qi)?,
                public_numbers: pub_nums.extract(py)?,
            })?;
            return Ok(obj.into_any());
        }

        if kty == "EC" {
            // 1. Extract private scalar 'd'
            let d_b64 = self.inner.get("d").and_then(|v| v.as_str())
                .ok_or_else(|| PyValueError::new_err("EC private key missing 'd' parameter"))?;
            
            let d_bytes = URL_SAFE_NO_PAD.decode(d_b64)
                .map_err(|e| PyValueError::new_err(format!("Invalid d base64: {}", e)))?;
            
            let int_cls = py.get_type::<PyInt>();
            let d_py = int_cls.call_method1("from_bytes", (d_bytes.as_slice(), "big"))?;

            // 2. Get public numbers (x, y) reusing the public_numbers method
            let pub_nums_any = self.public_numbers(py)?;
            if pub_nums_any.is_none(py) {
                return Err(PyValueError::new_err("EC public numbers (x, y) missing or invalid"));
            }
            
            // Extract the Rust struct from the Python object
            let public_numbers: PyEllipticCurvePublicNumbers = pub_nums_any.extract(py)?;

            // 3. Construct Private Numbers Object
            let obj = Py::new(py, PyEllipticCurvePrivateNumbers {
                private_value: d_py.into(),
                public_numbers,
            })?;
            
            return Ok(obj.into_any());
        }

        Ok(py.None().into())
    }


    fn __getitem__(&self, key: &str) -> PyResult<String> {
        match self.inner.get(key) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(v) => Ok(v.to_string()),
            None => Err(PyKeyError::new_err(key.to_string())),
        }
    }

    fn __repr__(&self) -> String {
        format!("<PyJWK kid={:?}>", self.key_id())
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
        Self::new(&keys)
    }

    fn __getitem__(&self, kid: String) -> PyResult<PyJWK> {
        for key in &self.keys {
            if let Some(k) = key.key_id() {
                if k == kid { return Ok(key.clone()); }
            }
        }
        Err(PyKeyError::new_err(format!("keyset has no key for kid: {}", kid)))
    }

    fn __len__(&self) -> usize {
        self.keys.len()
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<Py<PyJWKSetIterator>> {
        let iter = PyJWKSetIterator { iter: slf.keys.clone().into_iter() };
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

#[pyclass]
struct PyJWKSetIterator {
    iter: std::vec::IntoIter<PyJWK>,
}

#[pymethods]
impl PyJWKSetIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> { slf }
    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyJWK> { slf.iter.next() }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRSAPublicNumbers { #[pyo3(get)] n: Py<PyAny>, #[pyo3(get)] e: Py<PyAny> }
#[pymethods]
impl PyRSAPublicNumbers {
    fn __eq__(&self, other: &PyRSAPublicNumbers, py: Python) -> bool {
        self.n.bind(py).eq(other.n.bind(py)).unwrap_or(false) && 
        self.e.bind(py).eq(other.e.bind(py)).unwrap_or(false)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRSAPrivateNumbers { 
    #[pyo3(get)] p: Py<PyAny>, #[pyo3(get)] q: Py<PyAny>, #[pyo3(get)] d: Py<PyAny>, 
    #[pyo3(get)] dmp1: Py<PyAny>, #[pyo3(get)] dmq1: Py<PyAny>, #[pyo3(get)] iqmp: Py<PyAny>, 
    #[pyo3(get)] public_numbers: PyRSAPublicNumbers,
}
#[pymethods]
impl PyRSAPrivateNumbers {
    fn __eq__(&self, other: &PyRSAPrivateNumbers, py: Python) -> bool {
        self.d.bind(py).eq(other.d.bind(py)).unwrap_or(false) &&
        self.public_numbers.__eq__(&other.public_numbers, py)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEllipticCurvePublicNumbers { #[pyo3(get)] x: Py<PyAny>, #[pyo3(get)] y: Py<PyAny> }
#[pymethods]
impl PyEllipticCurvePublicNumbers {
    fn __eq__(&self, other: &PyEllipticCurvePublicNumbers, py: Python) -> bool {
        self.x.bind(py).eq(other.x.bind(py)).unwrap_or(false) &&
        self.y.bind(py).eq(other.y.bind(py)).unwrap_or(false)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEllipticCurvePrivateNumbers {
    #[pyo3(get)] private_value: Py<PyAny>, #[pyo3(get)] public_numbers: PyEllipticCurvePublicNumbers,
}
#[pymethods]
impl PyEllipticCurvePrivateNumbers {
    fn __eq__(&self, other: &PyEllipticCurvePrivateNumbers, py: Python) -> bool {
        self.private_value.bind(py).eq(other.private_value.bind(py)).unwrap_or(false) &&
        self.public_numbers.__eq__(&other.public_numbers, py)
    }
}


// --- Exposed Functions ---

pub fn from_jwk(jwk: &Bound<'_, PyAny>, algorithm_hint: &str) -> PyResult<PyJWK> {
    if let Ok(s) = jwk.extract::<String>() {
         PyJWK::from_json(&s, Some(algorithm_hint.to_string()))
    } else if let Ok(d) = jwk.extract::<Bound<'_, PyDict>>() {
         PyJWK::from_dict(&d, Some(algorithm_hint.to_string()))
    } else {
         Err(PyTypeError::new_err("Expected string or dict"))
    }
}

pub fn from_jwk_set(data: &Bound<'_, PyAny>) -> PyResult<PyJWKSet> {

    if let Ok(s) = data.extract::<String>() {
        PyJWKSet::from_json(&s)
    } else if let Ok(d) = data.extract::<Bound<'_, PyDict>>() {
        PyJWKSet::from_dict(&d)
    } else if let Ok(_l) = data.extract::<Bound<'_, PyList>>() {
        PyJWKSet::new(data)
    } else {
        Err(PyTypeError::new_err("Expected string, dict, or list of keys"))
    }
}


pub fn perform_signature_jwk(message: &[u8], key: &PyJWK, algorithm: &str) -> Result<Vec<u8>, WebtokenError> {
    
    // [FIX] Auto-detect secp256k1 and override algorithm if necessary
    let mut alg_override = algorithm;
    if algorithm == "ES256" {
        if let Some(crv) = key.inner.get("crv").and_then(|v| v.as_str()) {
            if crv == "secp256k1" {
                alg_override = "ES256K";
            }
        }
    }

    if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_override) {
        // [FIX] Pass public_only=false for signing (we need the private key)
        let key_bytes = key.to_key_bytes(false).map_err(|e| WebtokenError::Generic(e.to_string()))?;
        return ext_alg.sign(message, &key_bytes);
    }

    // Fallback to Standard
    let alg = Algorithm::from_str(algorithm).map_err(|_| WebtokenError::Generic("Unsupported Algorithm".into()))?;
    let enc_key = jwk::create_encoding_key(&key.inner, alg)?;
    let sig = jsonwebtoken::crypto::sign(message, &enc_key, alg).map_err(|e| WebtokenError::Generic(e.to_string()))?;
    URL_SAFE_NO_PAD.decode(&sig).map_err(|e| WebtokenError::Generic(e.to_string()))
}


pub fn perform_verification_jwk(payload: &[u8], signature: &[u8], jwk: &PyJWK, alg_name: &str) -> Result<bool, WebtokenError> {
    
    // [FIX] Auto-detect secp256k1 here too for safety
    let mut alg_override = alg_name;
    if alg_name == "ES256" {
        if let Some(crv) = jwk.inner.get("crv").and_then(|v| v.as_str()) {
            if crv == "secp256k1" {
                alg_override = "ES256K";
            }
        }
    }

    if let Some(ext_alg) = ExternalAlgorithm::from_str(alg_override) {
        // [FIX] Pass public_only=true for verification (extract x/y even if d exists)
        let bytes = jwk.to_key_bytes(true).map_err(|e| WebtokenError::Generic(e.to_string()))?;
        return ext_alg.verify(payload, signature, &bytes);
    }

    let alg = Algorithm::from_str(alg_name).map_err(|_| WebtokenError::Generic(format!("Algorithm '{}' not supported", alg_name)))?;
    let decoding_key = create_decoding_key(&jwk.inner, alg)?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    jsonwebtoken::crypto::verify(&sig_b64, payload, &decoding_key, alg).map_err(WebtokenError::Jwt)
}


pub fn register_jwk_module(py: Python, parent_module: &Bound<'_, PyModule>) -> PyResult<()> {   
    parent_module.add("PyJWKSetError", py.get_type::<PyJWKSetError>())?; 
    parent_module.add("PyJWKError", py.get_type::<PyJWKError>())?;  
    parent_module.add_class::<PyJWKSetIterator>()?;
    parent_module.add_class::<PyJWK>()?;
    parent_module.add_class::<PyJWKSet>()?;
    
    parent_module.add_class::<PyRSAPublicNumbers>()?;
    parent_module.add_class::<PyRSAPrivateNumbers>()?;
    parent_module.add_class::<PyEllipticCurvePublicNumbers>()?;
    parent_module.add_class::<PyEllipticCurvePrivateNumbers>()?;
    Ok(())
}