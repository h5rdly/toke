use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::pyjwt_jwk_api::PyJWK;

// We use string constants for the Hashes. 
// In PyJWT these are hashlib objects, but for compatibility 
// (passing them to __init__), strings are usually sufficient 
// unless the user code explicitly calls .digest() on the class attribute.
// If that becomes necessary, we can upgrade these to simple wrapper classes later.

#[pyclass]
pub struct RSAAlgorithm {}

#[pymethods]
impl RSAAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> Self {
        RSAAlgorithm {}
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        // We reuse your existing PyJwk logic to parse the JWK.
        // This returns a PyJwk object, which allows tests to verify properties.
        if let Ok(s) = jwk.extract::<String>() {
             PyJWK::from_json(&s, Some("RS256".to_string()))
        } else if let Ok(d) = jwk.extract::<Bound<'_, PyDict>>() {
             PyJWK::from_dict(&d, Some("RS256".to_string()))
        } else {
             use pyo3::exceptions::PyTypeError;
             Err(PyTypeError::new_err("Expected string or dict"))
        }
    }
}

#[pyclass]
pub struct ECAlgorithm {}

#[pymethods]
impl ECAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> Self {
        ECAlgorithm {}
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        if let Ok(s) = jwk.extract::<String>() {
             PyJWK::from_json(&s, None)
        } else if let Ok(d) = jwk.downcast::<PyDict>() {
             PyJWK::from_dict(d, None)
        } else {
             use pyo3::exceptions::PyTypeError;
             Err(PyTypeError::new_err("Expected string or dict"))
        }
    }
}

#[pyclass]
pub struct HMACAlgorithm {}

#[pymethods]
impl HMACAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> Self {
        HMACAlgorithm {}
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        if let Ok(s) = jwk.extract::<String>() {
             PyJWK::from_json(&s, Some("HS256".to_string()))
        } else if let Ok(d) = jwk.downcast::<PyDict>() {
             PyJWK::from_dict(d, Some("HS256".to_string()))
        } else {
             use pyo3::exceptions::PyTypeError;
             Err(PyTypeError::new_err("Expected string or dict"))
        }
    }
}

#[pyclass]
pub struct OKPAlgorithm {}

#[pymethods]
impl OKPAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> Self {
        OKPAlgorithm {}
    }

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        if let Ok(s) = jwk.extract::<String>() {
             PyJWK::from_json(&s, Some("EdDSA".to_string()))
        } else if let Ok(d) = jwk.downcast::<PyDict>() {
             PyJWK::from_dict(d, Some("EdDSA".to_string()))
        } else {
             use pyo3::exceptions::PyTypeError;
             Err(PyTypeError::new_err("Expected string or dict"))
        }
    }
}

pub fn register_compat_module(py: Python, parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create the 'algorithms' submodule to mimic jwt.algorithms
    let alg_module = PyModule::new(py, "algorithms")?;
    
    alg_module.add_class::<RSAAlgorithm>()?;
    alg_module.add_class::<ECAlgorithm>()?;
    alg_module.add_class::<HMACAlgorithm>()?;
    alg_module.add_class::<OKPAlgorithm>()?;
    
    parent_module.add_submodule(&alg_module)?;
    Ok(())
}