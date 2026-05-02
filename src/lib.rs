use pyo3::prelude::*;
use serde_json::{from_str, Value};

#[pyfunction]
fn hello_from_bin() -> String {
    "Hello from iyou-idp Rust bridge!".to_string()
}

#[pyfunction]
fn verify_signature(did: String, challenge: String, signature: String) -> bool {
    // In a real implementation, this would:
    // 1. Resolve the DID to get the public key
    // 2. Verify the signature against the challenge
    // 3. Return true if valid, false otherwise

    // For now, we'll implement a simple mock that:
    // - Checks all parameters are non-empty
    // - Simulates successful verification for testing

    !did.is_empty() && !challenge.is_empty() && !signature.is_empty()
}

#[pyfunction]
fn verify_vp(vp_json: String, challenge: String) -> PyResult<String> {
    // Parse the Verifiable Presentation JSON
    let vp: Value = from_str(&vp_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JSON: {}", e))
    })?;

    // Check required fields
    if !vp.get("verifiableCredential").is_some() {
        return Ok(r#"{"valid": false, "error": "Missing verifiableCredential"}"#.to_string());
    }

    if !vp.get("proof").is_some() {
        return Ok(r#"{"valid": false, "error": "Missing proof"}"#.to_string());
    }

    if challenge.is_empty() {
        return Ok(r#"{"valid": false, "error": "Empty challenge"}"#.to_string());
    }

    // Extract DID from proof if available
    let did = vp
        .get("holder")
        .or_else(|| vp.get("proof").and_then(|p| p.get("verificationMethod")))
        .and_then(|v| v.as_str())
        .unwrap_or("did:example:123");

    // In a real implementation, this would:
    // 1. Verify the cryptographic proof
    // 2. Check challenge matches
    // 3. Validate expiration
    // 4. Return detailed validation result

    // For now, return a successful mock response
    Ok(format!(
        r#"{{"valid": true, "did": "{}", "expires": "2023-12-31T23:59:59Z"}}"#,
        did
    ))
}

// Fix: Name must be _crypto to match Cargo.toml and pyproject.toml
#[pymodule]
fn _crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_from_bin, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vp, m)?)?;
    Ok(())
}
