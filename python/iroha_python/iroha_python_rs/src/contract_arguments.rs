//! Encode requested arguments from the caller's exact admitted contract artifact.
//!
//! This is a local, pre-signing semantic check. It consumes neither a server's
//! manifest nor its prepared argument record. Callers compare the result with
//! every prepared creation/callback record before signing or recovering a call.

use super::{ChainDiscriminantGuard, exact_chain_discriminant};
use iroha_primitives::json::{Json, MAX_JSON_BYTES};
use pyo3::{
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyString},
};
use std::borrow::Cow;

const MAX_ARTIFACT_BYTES: usize =
    ivm_abi::metadata::HEADER_SIZE + ivm_abi::metadata::MAX_PROGRAM_IMAGE_BYTES_V1;
const MAX_ENTRYPOINT_BYTES: usize = 255;

pub(super) struct ArgumentEncodingRequest<'a> {
    pub artifact: &'a [u8],
    pub entrypoint: &'a str,
    pub payload_json: Option<&'a str>,
    pub expected_code_hash_hex: &'a str,
    pub expected_abi_hash_hex: &'a str,
    pub chain_discriminant: u16,
}

fn exact_hash(raw: &str, field: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be lowercase 32-byte hex"));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(raw, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

pub(super) fn encode(request: ArgumentEncodingRequest<'_>) -> Result<Option<Vec<u8>>, String> {
    if request.artifact.is_empty() || request.artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "artifact must contain 1..={MAX_ARTIFACT_BYTES} bytes"
        ));
    }
    if request.entrypoint.is_empty()
        || request.entrypoint.len() > MAX_ENTRYPOINT_BYTES
        || request.entrypoint.trim() != request.entrypoint
    {
        return Err("entrypoint must contain 1..255 unpadded UTF-8 bytes".into());
    }
    if request
        .payload_json
        .is_some_and(|payload| payload.len() > MAX_JSON_BYTES)
    {
        return Err(format!("payload_json exceeds {MAX_JSON_BYTES} UTF-8 bytes"));
    }
    let expected_code = exact_hash(request.expected_code_hash_hex, "expected_code_hash_hex")?;
    let expected_abi = exact_hash(request.expected_abi_hash_hex, "expected_abi_hash_hex")?;

    // The selected presentation context applies to artifact literals as well as
    // arguments. The verifier authenticates the embedded schema and full image.
    let _guard = ChainDiscriminantGuard::enter(request.chain_discriminant);
    let verified = ivm::verify_contract_artifact(request.artifact)
        .map_err(|error| format!("invalid contract artifact: {error}"))?;
    if verified.code_hash.as_ref() != expected_code {
        return Err("contract artifact does not match expected_code_hash_hex".into());
    }
    if verified.abi_hash.as_ref() != expected_abi {
        return Err("contract artifact does not match expected_abi_hash_hex".into());
    }
    let entrypoint = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == request.entrypoint)
        .ok_or_else(|| "contract artifact does not contain the requested entrypoint".to_owned())?;

    // Match Torii's absent-payload semantics exactly. JSON null is a supplied
    // payload; it cannot impersonate absence for a zero-parameter entrypoint.
    match (entrypoint.argument_schema.as_ref(), request.payload_json) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err("zero-parameter entrypoint must not receive a payload".into()),
        (Some(_), None) => Err("parameterized entrypoint requires a payload".into()),
        (Some(schema), Some(text)) => {
            let payload = Json::from_str_norito(text)
                .map_err(|error| format!("payload_json must be canonical JSON: {error}"))?;
            ivm_abi::arguments::encode_argument_record_from_json_detailed(schema, &payload)
                .map(Some)
                .map_err(|error| format!("payload does not match entrypoint schema: {error}"))
        }
    }
}

fn exact_text<'a>(
    value: &'a Bound<'_, PyAny>,
    field: &str,
    max_bytes: usize,
) -> PyResult<Cow<'a, str>> {
    if !value.is_exact_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(format!(
            "{field} must be an exact string"
        )));
    }
    // ABI3 Python 3.9 can require a UTF-8 copy. Bound code points first so
    // conversion cannot allocate in proportion to an unbounded caller string.
    if value.len()? > max_bytes {
        return Err(PyValueError::new_err(format!(
            "{field} exceeds {max_bytes} UTF-8 bytes"
        )));
    }
    let text = value.cast::<PyString>()?.to_cow()?;
    if text.len() > max_bytes {
        return Err(PyValueError::new_err(format!(
            "{field} exceeds {max_bytes} UTF-8 bytes"
        )));
    }
    Ok(text)
}

#[pyfunction]
#[pyo3(name = "encode_contract_arguments_v1", signature = (artifact, entrypoint, payload_json=None, *, expected_code_hash_hex, expected_abi_hash_hex, chain_discriminant))]
pub(super) fn encode_contract_arguments_v1_py(
    py: Python<'_>,
    artifact: &Bound<'_, PyAny>,
    entrypoint: &Bound<'_, PyAny>,
    payload_json: Option<&Bound<'_, PyAny>>,
    expected_code_hash_hex: &Bound<'_, PyAny>,
    expected_abi_hash_hex: &Bound<'_, PyAny>,
    #[pyo3(from_py_with = exact_chain_discriminant)] chain_discriminant: u16,
) -> PyResult<Option<Py<PyBytes>>> {
    if !artifact.is_exact_instance_of::<PyBytes>() {
        return Err(PyTypeError::new_err(
            "artifact must be exact immutable bytes",
        ));
    }
    let artifact = artifact.cast::<PyBytes>()?.as_bytes();
    // Reject an oversized existing Python buffer before constructing any copy.
    if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(PyValueError::new_err(format!(
            "artifact must contain 1..={MAX_ARTIFACT_BYTES} bytes"
        )));
    }
    let entrypoint = exact_text(entrypoint, "entrypoint", MAX_ENTRYPOINT_BYTES)?;
    let payload_json = payload_json
        .map(|value| exact_text(value, "payload_json", MAX_JSON_BYTES))
        .transpose()?;
    let expected_code_hash_hex = exact_text(expected_code_hash_hex, "expected_code_hash_hex", 64)?;
    let expected_abi_hash_hex = exact_text(expected_abi_hash_hex, "expected_abi_hash_hex", 64)?;
    let result = encode(ArgumentEncodingRequest {
        artifact,
        entrypoint: &entrypoint,
        payload_json: payload_json.as_deref(),
        expected_code_hash_hex: &expected_code_hash_hex,
        expected_abi_hash_hex: &expected_abi_hash_hex,
        chain_discriminant,
    })
    .map_err(PyValueError::new_err)?;
    Ok(result.map(|bytes| PyBytes::new(py, &bytes).unbind()))
}

#[cfg(test)]
mod tests {
    include!("tests/contract_arguments_tests.rs");
}
