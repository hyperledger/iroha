//! Four-buffer FFI coverage backed by genuine executor and certified-chain originals.
//! This is staged source, not a native qualification receipt.

use super::connect_norito_verify_fi_context_assertion_v1;
use crate::fi_context_verification::tests::ffi_fixture;
use base64::{Engine, engine::general_purpose::STANDARD};
use norito::json::{self, Value};
use std::os::raw::{c_int, c_uchar, c_ulong};

fn invoke(
    capsule: &[u8],
    request: &[u8],
    checkpoint: &[u8],
    trust: &[u8],
) -> Result<Vec<u8>, c_int> {
    let mut output: *mut c_uchar = std::ptr::null_mut();
    let mut length: c_ulong = 0;
    let result = unsafe {
        connect_norito_verify_fi_context_assertion_v1(
            capsule.as_ptr(),
            capsule.len() as c_ulong,
            request.as_ptr(),
            request.len() as c_ulong,
            checkpoint.as_ptr(),
            checkpoint.len() as c_ulong,
            trust.as_ptr(),
            trust.len() as c_ulong,
            &mut output,
            &mut length,
        )
    };
    if result != 0 {
        assert!(output.is_null());
        assert_eq!(length, 0);
        return Err(result);
    }
    assert!(!output.is_null() && length > 0 && length <= 512 * 1024);
    let bytes = unsafe { std::slice::from_raw_parts(output, length as usize).to_vec() };
    crate::connect_norito_free(output);
    Ok(bytes)
}

#[test]
fn ffi_preserves_native_snapshot_bytes_and_all_u64_metadata_as_strings() {
    let (capsule, original, checkpoint, trust) = ffi_fixture(false, false);
    let bytes = invoke(&capsule, &original, &checkpoint, &trust).unwrap();
    let value = json::from_slice_value(&bytes).unwrap();
    let fields = value.as_object().unwrap();
    assert_eq!(fields.len(), 6);
    assert!(fields.values().all(Value::is_string));
    assert_eq!(
        value["schema"].as_str(),
        Some("iroha.fi-context-assertion.verified.v1")
    );
    assert_eq!(value["blockHeight"].as_str(), Some("3"));
    let encoded = value["snapshotJsonBase64"].as_str().unwrap();
    let original_snapshot = STANDARD.decode(encoded).unwrap();
    assert_eq!(STANDARD.encode(&original_snapshot), encoded);
    let snapshot = json::from_slice_value(&original_snapshot).unwrap();
    for absent in [
        "binding",
        "policy",
        "fi",
        "attestation",
        "link",
        "controller",
    ] {
        assert!(snapshot[absent].is_null());
    }
    assert_eq!(snapshot.as_object().unwrap().len(), 12);
}

#[test]
fn ffi_rejects_certified_failure_extra_execution_and_independent_target_substitution() {
    for (failed, extra) in [(true, false), (false, true)] {
        let (capsule, original, checkpoint, trust) = ffi_fixture(failed, extra);
        assert!(invoke(&capsule, &original, &checkpoint, &trust).is_err());
    }
    let (capsule, original, checkpoint, trust) = ffi_fixture(false, false);
    for key in [
        "referenceDigest",
        "fiRevision",
        "attestationRevision",
        "revision",
        "expectedPolicyRevision",
        "enabled",
    ] {
        let mut pins = json::from_slice_value(&trust).unwrap();
        let target = pins
            .as_object_mut()
            .unwrap()
            .get_mut("target")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let replacement = if key == "referenceDigest" {
            Value::from("55".repeat(32))
        } else if key == "enabled" {
            Value::from(true)
        } else {
            Value::from(2_u64)
        };
        target.insert(key.into(), replacement);
        assert!(
            invoke(
                &capsule,
                &original,
                &checkpoint,
                &json::to_vec(&pins).unwrap()
            )
            .is_err(),
            "{key}"
        );
    }
    let mut pins = json::from_slice_value(&trust).unwrap();
    pins.as_object_mut()
        .unwrap()
        .insert("requestSha256".into(), Value::from("55".repeat(32)));
    assert!(
        invoke(
            &capsule,
            &original,
            &checkpoint,
            &json::to_vec(&pins).unwrap()
        )
        .is_err()
    );
    let mut altered = original.clone();
    altered.push(b' ');
    assert!(invoke(&capsule, &altered, &checkpoint, &trust).is_err());
    let mut wrong_checkpoint = checkpoint.clone();
    wrong_checkpoint[0] ^= 1;
    assert!(invoke(&capsule, &original, &wrong_checkpoint, &trust).is_err());
}

#[test]
fn ffi_closes_trust_schema_and_refuses_missing_duplicate_or_noncanonical_pins() {
    let (capsule, original, checkpoint, trust) = ffi_fixture(false, false);
    let text = String::from_utf8(trust.clone()).unwrap();
    for invalid in [
        format!(" {text}"),
        text.replacen('{', "{\"unknown\":true,", 1),
        text.replacen('{', "{\"schema\":\"duplicate\",", 1),
    ] {
        assert!(invoke(&capsule, &original, &checkpoint, invalid.as_bytes()).is_err());
    }
    let value = json::from_slice_value(&trust).unwrap();
    for key in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            invoke(
                &capsule,
                &original,
                &checkpoint,
                &json::to_vec(&missing).unwrap()
            )
            .is_err(),
            "{key}"
        );
    }
}

#[test]
fn ffi_rejects_null_and_oversized_buffers_before_dereference_and_clears_outputs() {
    let byte = [1_u8];
    for index in 0..4 {
        let mut pointers = [byte.as_ptr(); 4];
        pointers[index] = std::ptr::null();
        let mut output = 1_usize as *mut c_uchar;
        let mut length = 123;
        let result = unsafe {
            connect_norito_verify_fi_context_assertion_v1(
                pointers[0],
                1,
                pointers[1],
                1,
                pointers[2],
                1,
                pointers[3],
                1,
                &mut output,
                &mut length,
            )
        };
        assert_ne!(result, 0);
        assert!(output.is_null());
        assert_eq!(length, 0);
    }
    for (index, maximum) in [
        (0, 512 * 1024),
        (1, 64 * 1024),
        (
            2,
            iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
        ),
        (3, 32 * 1024),
    ] {
        let mut lengths = [1 as c_ulong; 4];
        lengths[index] = (maximum + 1) as c_ulong;
        let mut output = 1_usize as *mut c_uchar;
        let mut length = 123;
        let result = unsafe {
            connect_norito_verify_fi_context_assertion_v1(
                byte.as_ptr(),
                lengths[0],
                byte.as_ptr(),
                lengths[1],
                byte.as_ptr(),
                lengths[2],
                byte.as_ptr(),
                lengths[3],
                &mut output,
                &mut length,
            )
        };
        assert_ne!(result, 0);
        assert!(output.is_null());
        assert_eq!(length, 0);
    }
    let result = unsafe {
        connect_norito_verify_fi_context_assertion_v1(
            byte.as_ptr(),
            1,
            byte.as_ptr(),
            1,
            byte.as_ptr(),
            1,
            byte.as_ptr(),
            1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_ne!(result, 0);
}
