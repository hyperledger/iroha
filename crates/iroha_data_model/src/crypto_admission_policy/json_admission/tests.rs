//! Direct crypto-policy destination parity, refusal provenance and lifetime controls.

use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits};

use super::*;

// Captured former derive is only an error-order oracle. Neither shipping decoder
// calls it and it cannot serve as a fallback on resource refusal.
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields, no_fast_from_json)]
struct CapturedFields {
    allowed_algorithms: Vec<Algorithm>,
}
struct CapturedPolicy(CryptoAdmissionPolicyV1);
impl JsonDeserialize for CapturedPolicy {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let fields = CapturedFields::json_deserialize(parser)?;
        CryptoAdmissionPolicyV1::new(fields.allowed_algorithms)
            .map(Self)
            .map_err(|error| json::Error::Message(error.to_string()))
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<AdmittedCryptoAdmissionPolicy, CryptoPolicyJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let owner = AdmittedCryptoAdmissionPolicy::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(owner)
}

#[test]
fn full_registry_direct_destination_matches_ordinary_binary_and_decoder_demand() {
    let expected = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec()).unwrap();
    let source = json::to_json(&expected).unwrap();
    let ordinary_context = DecodeBudgetContext::new(limits(usize::MAX));
    let ordinary = ordinary_context
        .with(|| json::from_str::<CapturedPolicy>(&source))
        .unwrap()
        .0;
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let pool = AllocationBudget::new(4096);
    let owner = context.with(|| decode(&source, &pool)).unwrap();
    assert_eq!(owner.get(), &ordinary);
    assert_eq!(owner.get(), &expected);
    assert_eq!(
        norito::encode_canonical(owner.get()).unwrap(),
        norito::encode_canonical(&expected).unwrap()
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        ordinary_context.consumed_allocated_bytes()
    );
    assert_eq!(
        pool.reserved_bytes(),
        Layout::array::<Algorithm>(Algorithm::ALL.len())
            .unwrap()
            .size()
    );
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&AllocationBudget::new(4096)));
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn ordinary_and_admitted_preserve_captured_field_and_algorithm_errors() {
    let cases = [
        "{}",
        r#"{"unknown":0}"#,
        r#"{"allowed_algorithms":[]}"#,
        r#"{"allowed_algorithms":["ed25519","ed25519"]}"#,
        r#"{"allowed_algorithms":["secp256k1","ed25519"]}"#,
        r#"{"allowed_algorithms":["not-an-algorithm"]}"#,
        r#"{"allowed_algorithms":["ed25519"],"allowed_algorithms":false}"#,
        r#"{"allowed_algorithms":["ed25519"],"extra":false}"#,
        r#"{"allowed_algorithms":["ed25519"],}"#,
        r#"{"allowed_algorithms":["ed25519",]}"#,
        r#"{"allowed_algorithms":["\uD800"]}"#,
        r#"{"\uD800":[]}"#,
        r#"{"allowed_algorithms":[false]}"#,
        r#"{"allowed_algorithms":["ed25519"]} trailing"#,
    ];
    for source in cases {
        let original = json::from_str::<CapturedPolicy>(source)
            .err()
            .expect("captured rejection");
        let ordinary = json::from_str::<CryptoAdmissionPolicyV1>(source).unwrap_err();
        let pool = AllocationBudget::new(4096);
        let admitted = decode(source, &pool).unwrap_err();
        let CryptoPolicyJsonAdmissionError::Json(admitted) = admitted else {
            panic!("ample finite pool: {admitted:?}");
        };
        assert_eq!(
            format!("{ordinary:?}"),
            format!("{original:?}"),
            "ordinary: {source}"
        );
        assert_eq!(
            format!("{admitted:?}"),
            format!("{original:?}"),
            "admitted: {source}"
        );
        assert_eq!(pool.reserved_bytes(), 0, "partial owners refund: {source}");
    }
}

#[test]
fn escaped_key_and_algorithm_share_the_existing_string_kernel() {
    let source = r#"{"allowed_\u0061lgorithms":["ed\u00325519"]}"#;
    let expected = CryptoAdmissionPolicyV1::new(vec![Algorithm::Ed25519]).unwrap();
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let pool = AllocationBudget::new(128);
    let owner = context.with(|| decode(source, &pool)).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(pool.reserved_bytes(), core::mem::size_of::<Algorithm>());
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn initial_and_late_finite_pool_refusal_destroy_partial_owners_and_retry() {
    let source = r#"{"allowed_algorithms":["ed25519"]}"#;
    for capacity in [0, 1, 7] {
        let pool = AllocationBudget::new(capacity);
        let error = decode(source, &pool).unwrap_err();
        assert!(matches!(
            error,
            CryptoPolicyJsonAdmissionError::Allocation(ChargedBufferError::Admission(_))
        ));
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let pool = AllocationBudget::new(8);
    let owner = decode(source, &pool).unwrap();
    assert_eq!(owner.get().allowed_algorithms(), &[Algorithm::Ed25519]);
    assert_eq!(pool.reserved_bytes(), 1);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn exact_original_codec_scope_survives_and_replay_is_not_local() {
    let source = r#"{"allowed_algorithms":["ed25519"]}"#;
    let pool = AllocationBudget::new(128);
    // One byte funds the actual algorithm array; the following scalar string
    // reaches the cumulative limit after that original physical allocation.
    let context = DecodeBudgetContext::new(limits(1));
    let mut original_scope = None;
    let attempt = context
        .with(|| {
            norito::core::classify_decode_attempt(|| {
                decode(source, &pool).map_err(|error| {
                    let CryptoPolicyJsonAdmissionError::Json(error) = error else {
                        panic!("codec capacity is the cause");
                    };
                    let error = error.into_core_error();
                    let norito::Error::ScopedDecodeResource(scope) = &error else {
                        panic!("the actual string kernel preserves scope: {error:?}");
                    };
                    original_scope = Some(scope.clone());
                    error
                })
            })
        })
        .unwrap_err();
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let retained = attempt.into_local_refusal().unwrap().into_error();
    let norito::Error::ScopedDecodeResource(scope) = &retained else {
        panic!("retained original identity");
    };
    assert_eq!(scope, &original_scope.unwrap());
    let replay = norito::core::classify_decode_attempt::<()>(|| Err(retained)).unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(replay.local_refusal().is_none());
    let retry = decode(source, &pool).unwrap();
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn allocation_parts_move_original_array_without_copy_or_refund() {
    let pool = AllocationBudget::new(128);
    let owner = decode(r#"{"allowed_algorithms":["ed25519","secp256k1"]}"#, &pool).unwrap();
    let pointer = owner.get().allowed_algorithms().as_ptr();
    let before = pool.reserved_bytes();
    // SAFETY: test keeps the exact value immutable and destroys it before the
    // returned original charge. No enclosing heap or ledger is allocated here.
    let (value, charge) = unsafe { owner.into_allocation_parts() };
    assert_eq!(value.allowed_algorithms().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), before);
    assert!(charge.belongs_to(&pool));
    drop(value);
    assert_eq!(pool.reserved_bytes(), before);
    drop(charge);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_array_algorithm_and_escaped_key_allocator_refusals_preserve_cause() {
    use crate::amx_prepare_streaming_allocations::with_exact_allocation_denial;
    let ordinary_key = r#"{"allowed_algorithms":["ed25519"]}"#;
    let escaped_key = r#"{"allowed_\u0061lgorithms":["ed25519"]}"#;
    for (source, layout) in [
        (ordinary_key, Layout::array::<Algorithm>(1).unwrap()),
        (ordinary_key, Layout::array::<u8>("ed25519".len()).unwrap()),
        (
            escaped_key,
            Layout::array::<u8>("allowed_algorithms".len()).unwrap(),
        ),
    ] {
        let pool = AllocationBudget::new(256);
        let (failure, allocator_received_request) =
            with_exact_allocation_denial(layout, || decode(source, &pool));
        assert!(
            allocator_received_request,
            "the real allocator must receive the selected layout"
        );
        assert!(
            matches!(failure, Err(CryptoPolicyJsonAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == layout.size())
        );
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "actual partial backing retires before refund"
        );
        let retry = decode(source, &pool).unwrap();
        assert_eq!(retry.get().allowed_algorithms(), &[Algorithm::Ed25519]);
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn physical_array_pointer_is_the_retained_value_and_retires_once() {
    use crate::amx_prepare_streaming_allocations::PhysicalObservation;
    let source = r#"{"allowed_algorithms":["ed25519","secp256k1"]}"#;
    let pool = AllocationBudget::new(256);
    let observation = PhysicalObservation::start();
    let owner = decode(source, &pool).unwrap();
    let pointer = owner.get().allowed_algorithms().as_ptr() as usize;
    assert_eq!(
        observation
            .snapshot()
            .single_live_pointer(Layout::array::<Algorithm>(2).unwrap()),
        Some(pointer)
    );
    assert_eq!(observation.snapshot().retirements(pointer), 0);
    assert_eq!(pool.reserved_bytes(), 2);
    drop(owner);
    assert_eq!(observation.snapshot().retirements(pointer), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}
