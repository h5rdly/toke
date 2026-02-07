use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD, STANDARD_NO_PAD, URL_SAFE}, Engine as _};
use serde_json::{Value};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::{PyTypeError, PyValueError};

use pythonize::{depythonize, pythonize};


pub fn decode_base64_permissive(input: &[u8]) -> Result<Vec<u8>, String> {
    // Filter whitespace
    let input_clean: Vec<u8> = input.iter()
        .filter(|&&c| !c.is_ascii_whitespace())
        .cloned()
        .collect();

    // Try all variants
    if let Ok(v) = URL_SAFE_NO_PAD.decode(&input_clean) { return Ok(v); }
    if let Ok(v) = URL_SAFE.decode(&input_clean) { return Ok(v); }
    if let Ok(v) = STANDARD.decode(&input_clean) { return Ok(v); }
    if let Ok(v) = STANDARD_NO_PAD.decode(&input_clean) { return Ok(v); }

    Err("Base64 error: Invalid padding or alphabet".to_string())
}


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

    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    Ok(PyBytes::new(py, encoded.as_bytes()))
}


#[pyfunction]
fn base64url_decode(input: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let input_bytes = if let Ok(s) = input.extract::<String>() { s.into_bytes() }
    else if let Ok(b) = input.extract::<&[u8]>() { b.to_vec() }
    else { return Err(PyValueError::new_err("Invalid input type for base64 decode")); };

    decode_base64_permissive(&input_bytes).map_err(PyValueError::new_err)
}


// [NEW] JSON Utils
#[pyfunction]
fn json_loads(py: Python, data: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let bytes = if let Ok(s) = data.extract::<String>() { s.into_bytes() }
    else if let Ok(b) = data.extract::<Vec<u8>>() { b }
    else { return Err(PyTypeError::new_err("Expected bytes or string")); };
    
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(pythonize(py, &v).map_err(|e| PyValueError::new_err(e.to_string()))?.unbind())
}

#[pyfunction]
fn json_dumps(data: &Bound<'_, PyAny>) -> PyResult<String> {
    let v: Value = depythonize(data).map_err(|e| PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&v).map_err(|e| PyValueError::new_err(e.to_string()))
}


pub fn export_py_utils(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(base64url_encode, m.clone())?)?;
    m.add_function(wrap_pyfunction!(base64url_decode, m.clone())?)?;
    m.add_function(wrap_pyfunction!(json_loads, m)?)?;
    m.add_function(wrap_pyfunction!(json_dumps, m)?)?;
    Ok(())
}