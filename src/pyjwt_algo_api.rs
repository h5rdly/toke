use pyo3::prelude::*;
use crate::pyjwt_jwk_api::{PyJWK, from_jwk};


#[pyclass(subclass)]
pub struct Algorithm {}

#[pymethods]
impl Algorithm {
    #[new]
    fn new() -> Self { Algorithm {} }
    
    fn compute_hash_digest(&self, _bytes: &[u8]) -> PyResult<Vec<u8>> {
        use pyo3::exceptions::PyNotImplementedError;
        Err(PyNotImplementedError::new_err("Not implemented"))
    }
}


#[pyclass(extends=Algorithm, subclass)]
pub struct NoneAlgorithm {}

#[pymethods]
impl NoneAlgorithm {
    #[new]
    fn new() -> (Self, Algorithm) { (NoneAlgorithm {}, Algorithm{}) }
}

// --- RSA ---
#[pyclass(extends=Algorithm, subclass)]
pub struct RSAAlgorithm {}

#[pymethods]
impl RSAAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> (Self, Algorithm) {
        (RSAAlgorithm {}, Algorithm {})
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        // [FIX] Just call the generic function with the hint
        from_jwk(jwk, "RS256")
    }
    
    fn to_jwk(&self, _key: &Bound<'_, PyAny>) -> PyResult<String> {
        Ok("{}".to_string())
    }
}


#[pyclass(extends=Algorithm, subclass)]
pub struct ECAlgorithm {}

#[pymethods]
impl ECAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> (Self, Algorithm) {
        (ECAlgorithm {}, Algorithm {})
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        from_jwk(jwk, "ES256") 
    }
}


#[pyclass(extends=Algorithm, subclass)]
pub struct HMACAlgorithm {}

#[pymethods]
impl HMACAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> (Self, Algorithm) {
        (HMACAlgorithm {}, Algorithm {})
    }

    #[classattr]
    const SHA256: &'static str = "SHA256";
    #[classattr]
    const SHA384: &'static str = "SHA384";
    #[classattr]
    const SHA512: &'static str = "SHA512";

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        from_jwk(jwk, "HS256")
    }
}


#[pyclass(extends=Algorithm, subclass)]
pub struct OKPAlgorithm {}

#[pymethods]
impl OKPAlgorithm {
    #[new]
    fn new(_hash_alg: Option<&Bound<'_, PyAny>>) -> (Self, Algorithm) {
        (OKPAlgorithm {}, Algorithm {})
    }

    #[staticmethod]
    fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<PyJWK> {
        from_jwk(jwk, "EdDSA")
    }
}


pub fn register_algo_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<Algorithm>()?;
    parent_module.add_class::<NoneAlgorithm>()?;
    parent_module.add_class::<RSAAlgorithm>()?;
    parent_module.add_class::<ECAlgorithm>()?;
    parent_module.add_class::<HMACAlgorithm>()?;
    parent_module.add_class::<OKPAlgorithm>()?;
    parent_module.add("has_crypto", true)?; 
    Ok(())
}