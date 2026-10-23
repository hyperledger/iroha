//! Direct map ingress keeps original custody and the original decode observer.

use super::*;

fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<CustomParameters, CustomParametersJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let result = CustomParameters::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(result)
}

const SOURCE: &str = r#"{"alpha_parameter_identity_longer_than_inline_storage":{"id":"alpha_parameter_identity_longer_than_inline_storage","payload":{"a":[1,true],"b":"text"}},"zeta":{"payload":null,"id":"zeta"}}"#;

#[test]
fn direct_ingress_matches_ordinary_model_and_keeps_raw_json_custody() {
    let expected = json::from_str::<CustomParameters>(SOURCE).unwrap();
    let pool = AllocationBudget::new(8192);
    let retained = decode(SOURCE, &pool).unwrap();
    assert_eq!(retained, expected);
    assert!(retained.belongs_to(&pool));
    let raw = retained.values().next().unwrap().payload.clone();
    assert!(raw.belongs_to(&pool));
    assert_eq!(raw.get(), r#"{"a":[1,true],"b":"text"}"#);
    drop(retained);
    assert!(pool.reserved_bytes() > 0);
    drop(raw);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(!expected.belongs_to(&pool));
}

#[test]
fn direct_empty_collection_keeps_zero_pool_identity() {
    let pool = AllocationBudget::new(0);
    let other = AllocationBudget::new(0);
    let retained = decode("{}", &pool).unwrap();
    assert!(retained.belongs_to(&pool));
    assert!(!retained.belongs_to(&other));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn every_refused_prefix_retires_partial_graph_before_retry() {
    let original = SOURCE.as_bytes().to_vec();
    let pool = AllocationBudget::new(0);
    let mut refused = 0;
    let mut succeeded = false;
    for limit in (0..8192).step_by(31) {
        pool.set_limit_bytes(limit);
        match decode(SOURCE, &pool) {
            Err(_) => {
                refused += 1;
                assert_eq!(pool.reserved_bytes(), 0);
            }
            Ok(retained) => {
                assert!(retained.belongs_to(&pool));
                drop(retained);
                assert_eq!(pool.reserved_bytes(), 0);
                succeeded = true;
                break;
            }
        }
        assert_eq!(SOURCE.as_bytes(), original);
    }
    assert!(refused > 2 && succeeded);
    pool.set_limit_bytes(8192);
    assert_eq!(
        decode(SOURCE, &pool).unwrap(),
        json::from_str::<CustomParameters>(SOURCE).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn malformed_records_and_noncanonical_payloads_share_one_rejecting_kernel() {
    let pool = AllocationBudget::new(8192);
    for source in [
        r#"{"a":{"id":"b","payload":1}}"#,
        r#"{"a":{"id":"a","payload":1},"a":{"id":"a","payload":2}}"#,
        r#"{"b":{"id":"b","payload":1},"a":{"id":"a","payload":2}}"#,
        r#"{"a":{"id":"a","id":"a","payload":1}}"#,
        r#"{"a":{"id":"a","payload":1,"payload":1}}"#,
        r#"{"a":{"id":"a","payload":1,"unknown":1}}"#,
        r#"{"a":{"payload":1}}"#,
        r#"{"a":{"id":"a"}}"#,
        r#"{"a":{"id":"a","payload":{"b":1,"a":2}}}"#,
        r#"{"a":{"id":"a","payload":"\u0061"}}"#,
        r#"{"a":{"id":"a","payload":1e0}}"#,
        r#"{"bad id":{"id":"bad id","payload":null}}"#,
        r#"{"a":{"id":"a","payload":null}} trailing"#,
    ] {
        assert!(
            json::from_str::<CustomParameters>(source).is_err(),
            "ordinary: {source}"
        );
        assert!(decode(source, &pool).is_err(), "admitted: {source}");
        assert_eq!(pool.reserved_bytes(), 0, "{source}");
    }
}

#[test]
fn escaped_record_keys_and_non_ascii_canonical_identity_use_original_pool_scratch() {
    let pool = AllocationBudget::new(8192);
    let source = r#"{"é":{"\u0069d":"é","payl\u006fad":{"a":"é"}}}"#;
    let retained = decode(source, &pool).unwrap();
    assert_eq!(
        retained,
        json::from_str::<CustomParameters>(source).unwrap()
    );
    assert!(retained.belongs_to(&pool));
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
    let noncanonical = "{\"e\u{301}\":{\"id\":\"e\u{301}\",\"payload\":null}}";
    assert!(decode(&noncanonical, &pool).is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_array_refusal_identity_survives_and_saved_replay_is_invalid() {
    use norito::core::{DecodeAttemptErrorKind, classify_decode_attempt};
    let pool = AllocationBudget::new(8192);
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let mut seen = None;
    let attempt = zero
        .with(|| {
            classify_decode_attempt(|| {
                decode(SOURCE, &pool).map_err(|error| {
                    let CustomParametersJsonAdmissionError::Json(
                        json::Error::ScopedDecodeResource(origin),
                    ) = error
                    else {
                        panic!("native observer lost: {error:?}")
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
        panic!("original identity lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = zero
        .with(|| {
            classify_decode_attempt(|| {
                let _ = decode(SOURCE, &pool).unwrap_err();
                Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    drop(decode(SOURCE, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}
