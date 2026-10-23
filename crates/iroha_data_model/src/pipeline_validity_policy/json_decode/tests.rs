//! Exact scalar field grammar and original escaped-key admission controls.
use super::*;
use crate::amx_prepare_streaming_allocations::{measured, with_nth_exact_allocation_denial};
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, classify_decode_attempt,
};
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<PipelineValidityPolicyV1, PipelinePolicyJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let value = PipelineValidityPolicyV1::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(value)
}
fn reject(source: &str) {
    let pool = AllocationBudget::new(8192);
    assert!(
        json::from_str::<PipelineValidityPolicyV1>(source).is_err(),
        "ordinary {source}"
    );
    assert!(decode(source, &pool).is_err(), "admitted {source}");
    assert_eq!(pool.reserved_bytes(), 0);
}
fn source() -> String {
    json::to_json(&PipelineValidityPolicyV1::protocol_default()).unwrap()
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn complete_plain_record_needs_no_allocation_or_pool_capacity() {
    let source = source();
    let pool = AllocationBudget::new(0);
    let (result, requests) = measured(|| decode(&source, &pool));
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(
        result.unwrap(),
        PipelineValidityPolicyV1::protocol_default()
    );
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        json::from_str::<PipelineValidityPolicyV1>(&source).unwrap(),
        PipelineValidityPolicyV1::protocol_default()
    );
}
#[test]
fn every_field_is_required_and_duplicate_or_unknown_is_rejected() {
    let source = source();
    assert_eq!(PipelineValidityPolicyV1::FIELD_NAMES.len(), 16);
    for field in PipelineValidityPolicyV1::FIELD_NAMES {
        let mut value = json::to_value(&PipelineValidityPolicyV1::protocol_default()).unwrap();
        let json::Value::Object(ref mut map) = value else {
            panic!("fixture object")
        };
        assert!(map.remove(*field).is_some());
        reject(&json::to_json(&value).unwrap());
        let needle = format!("\"{field}\":");
        let default = if *field == "dynamic_prepass" {
            "false"
        } else {
            "1"
        };
        reject(&source.replacen(&needle, &format!("\"{field}\":{default},{needle}"), 1));
        reject(&source.replacen(&needle, &format!("\"unknown_{field}\":"), 1));
    }
    reject("{}");
    reject("[]");
    reject(&(source + " true"));
}
#[test]
fn escaped_key_uses_exact_native_destination_and_refunds_before_retry() {
    let source = source().replace("dynamic_prepass", "dynamic_prepa\\u0073s");
    let expected = PipelineValidityPolicyV1::protocol_default();
    let pool = AllocationBudget::new(0);
    let (result, requests) = measured(|| decode(&source, &pool));
    assert!(matches!(
        result,
        Err(PipelinePolicyJsonAdmissionError::Allocation(
            ChargedBufferError::Admission(_)
        ))
    ));
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(15);
    assert_eq!(decode(&source, &pool).unwrap(), expected);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        json::from_str::<PipelineValidityPolicyV1>(&source).unwrap(),
        expected
    );
    let layout = std::alloc::Layout::array::<u8>(15).unwrap();
    let (result, denied) = with_nth_exact_allocation_denial(layout, 0, || decode(&source, &pool));
    assert!(denied);
    assert!(matches!(
        result,
        Err(PipelinePolicyJsonAdmissionError::Allocation(
            ChargedBufferError::Allocator {
                requested_bytes: 15
            }
        ))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(decode(&source, &pool).unwrap(), expected);
    let duplicate = source.replacen(
        "\"dynamic_prepa\\u0073s\":",
        "\"dynamic_prepass\":false,\"dynamic_prepa\\u0073s\":",
        1,
    );
    reject(&duplicate);
}
#[test]
fn scalar_lexical_errors_preserve_strict_unsigned_and_boolean_rules() {
    let source = source();
    for bad in [
        "-0",
        "-1",
        "1.0",
        "1e0",
        "18446744073709551616",
        "true",
        "null",
        "\"1\"",
    ] {
        reject(&source.replacen(
            "\"overlay_max_instructions\":0",
            &format!("\"overlay_max_instructions\":{bad}"),
            1,
        ));
    }
    reject(&source.replacen("\"dynamic_prepass\":true", "\"dynamic_prepass\":1", 1));
}
#[test]
fn decode_does_not_replace_existing_semantic_validation() {
    let source = source().replacen(
        "\"overlay_chunk_instructions\":256",
        "\"overlay_chunk_instructions\":0",
        1,
    );
    let pool = AllocationBudget::new(0);
    let value = decode(&source, &pool).unwrap();
    assert_eq!(
        value,
        json::from_str::<PipelineValidityPolicyV1>(&source).unwrap()
    );
    assert!(matches!(
        value.validate(),
        Err(super::super::PipelineValidityPolicyError::Zero(
            "overlay_chunk_instructions"
        ))
    ));
}
#[test]
fn escaped_key_refusal_keeps_original_observer_and_saved_replay_invalid() {
    let source = source().replace("dynamic_prepass", "dynamic_prepa\\u0073s");
    let pool = AllocationBudget::new(8192);
    let context = DecodeBudgetContext::new(limits(0));
    let mut seen = None;
    let attempt = context
        .with(|| {
            classify_decode_attempt(|| {
                decode(&source, &pool).map_err(|error| {
                    let PipelinePolicyJsonAdmissionError::Json(json::Error::ScopedDecodeResource(
                        origin,
                    )) = error
                    else {
                        panic!("original observer lost: {error:?}")
                    };
                    seen = Some(origin.clone());
                    norito::Error::ScopedDecodeResource(origin)
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original refusal lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = context
        .with(|| {
            classify_decode_attempt(|| {
                let _ = decode(&source, &pool).unwrap_err();
                Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert_eq!(
        decode(&source, &pool).unwrap(),
        PipelineValidityPolicyV1::protocol_default()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
