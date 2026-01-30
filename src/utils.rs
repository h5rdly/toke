use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, URL_SAFE}, Engine as _};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::{PyTypeError, PyValueError};


#[pyfunction]
pub fn base64url_encode<'py>(py: Python<'py>, data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    
    // Force Bytes (Handle str -> utf-8 or bytes -> bytes)
    let bytes = if let Ok(s) = data.extract::<String>() {
        s.into_bytes()
    } else if let Ok(b) = data.extract::<Vec<u8>>() {
        b
    } else {
        return Err(PyTypeError::new_err("Expected bytes or string"));
    };

    // Encode directly to unpadded Base64URL
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    
    Ok(PyBytes::new(py, encoded.as_bytes()))
}


#[pyfunction]
pub fn base64url_decode<'py>(py: Python<'py>, data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    
    let input_bytes = if let Ok(s) = data.extract::<String>() {
        s.into_bytes()
    } else if let Ok(b) = data.extract::<Vec<u8>>() {
        b
    } else {
        return Err(PyTypeError::new_err("Expected bytes or string"));
    };

    // Try the NO_PAD engine first (standard JWT format).
    // If that fails, try the PAD engine (in case user provided padded data).
    let decoded = URL_SAFE_NO_PAD.decode(&input_bytes)
        .or_else(|_| URL_SAFE.decode(&input_bytes))
        .map_err(|e| PyValueError::new_err(format!("Invalid base64: {}", e)))?;

    Ok(PyBytes::new(py, &decoded))
}


pub fn export_utils(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(base64url_encode, m.clone())?)?;
    m.add_function(wrap_pyfunction!(base64url_decode, m.clone())?)?;
    Ok(())
}