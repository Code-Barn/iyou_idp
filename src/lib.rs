use pyo3::prelude::*;

#[pyfunction]
fn hello_from_bin() -> String {
    "Hello from iyou-idp Rust bridge!".to_string()
}

#[pyfunction]
fn verify_vp(vp_json: String) -> PyResult<String> {
    Ok(did_rust::verify_vp(&vp_json))
}

#[pyfunction]
fn verify_vc(vc_json: String) -> PyResult<String> {
    Ok(did_rust::verify_vc(&vc_json))
}

#[pyfunction]
fn issue_vc(credential_json: String, did: String, key_b58: String) -> PyResult<String> {
    did_rust::issue_vc(&credential_json, &did, &key_b58)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

#[pymodule]
fn _crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_from_bin, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vp, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vc, m)?)?;
    m.add_function(wrap_pyfunction!(issue_vc, m)?)?;
    Ok(())
}

