use pyo3::prelude::*;

#[pyfunction]
fn hello_from_bin() -> String {
    "Hello from iyou-idp Rust bridge!".to_string()
}

#[pyfunction]
fn verify_vp(vp_json: String) -> PyResult<String> {
    Ok(did_rust::verify_vp(&vp_json))
}

#[pymodule]
fn _crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_from_bin, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vp, m)?)?;
    Ok(())
}
