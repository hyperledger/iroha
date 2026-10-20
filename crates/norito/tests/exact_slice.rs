//! Exact slice decoding tests for the Norito codec facade.
#[derive(Debug, PartialEq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize)]
#[norito(decode_from_slice)]
struct ExactPayload {
    label: String,
    data: Vec<u8>,
    count: u32,
}
#[test]
fn decode_exact_from_slice_roundtrips() {
    let payload = ExactPayload {
        label: "chain-payload".to_owned(),
        data: vec![1, 2, 3, 5, 8, 13],
        count: 6,
    };
    let bytes = norito::codec::encode_adaptive(&payload);
    let decoded =
        norito::codec::decode_exact_from_slice::<ExactPayload>(&bytes).expect("decode exact");
    assert_eq!(decoded, payload);
}
#[test]
fn decode_exact_from_slice_rejects_trailing_bytes() {
    let payload = ExactPayload {
        label: "chain-payload".to_owned(),
        data: vec![1, 2, 3, 5, 8, 13],
        count: 6,
    };
    let mut bytes = norito::codec::encode_adaptive(&payload);
    bytes.push(0);
    let err = norito::codec::decode_exact_from_slice::<ExactPayload>(&bytes)
        .expect_err("trailing bytes must be rejected");
    assert!(matches!(err, norito::Error::LengthMismatch));
}
#[test]
fn decode_exact_from_slice_rejects_forged_sequence_length_before_allocation() {
    let bytes = u64::MAX.to_le_bytes();
    let err = norito::codec::decode_exact_from_slice::<Vec<u64>>(&bytes)
        .expect_err("a forged sequence count must fail before allocation");
    assert!(matches!(
        err,
        norito::Error::SequenceLengthExceeded { .. }
            | norito::Error::TotalElementsExceeded { .. }
            | norito::Error::TotalAllocationExceeded { .. }
    ));
}
#[test]
fn decode_exact_from_slice_with_limits_enforces_schema_count() {
    let value = vec![1_u64, 2, 3, 4];
    let bytes = norito::codec::encode_adaptive(&value);
    let limits = norito::DecodeLimits::new(3, bytes.len(), 3, bytes.len() * 8, 8);
    let err = norito::codec::decode_exact_from_slice_with_limits::<Vec<u64>>(&bytes, limits)
        .expect_err("schema-specific vector bound must be enforced");
    assert!(matches!(
        err,
        norito::Error::SequenceLengthExceeded {
            length: 4,
            limit: 3
        } | norito::Error::TotalElementsExceeded {
            attempted: 4,
            limit: 3
        }
    ));
}
#[test]
fn explicit_limits_cannot_weaken_payload_derived_defaults() {
    let bytes = u64::MAX.to_le_bytes();
    let permissive =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let err = norito::codec::decode_exact_from_slice_with_limits::<Vec<u64>>(&bytes, permissive)
        .expect_err("caller limits must not disable payload-derived allocation protection");
    assert!(matches!(
        err,
        norito::Error::SequenceLengthExceeded { .. }
            | norito::Error::TotalElementsExceeded { .. }
            | norito::Error::TotalAllocationExceeded { .. }
    ));
}
#[test]
fn nested_exact_decode_cannot_weaken_an_ambient_budget() {
    let value = vec![1_u64, 2, 3, 4];
    let bytes = norito::codec::encode_adaptive(&value);
    let ambient = norito::DecodeLimits::new(3, bytes.len(), 3, bytes.len() * 8, 8);
    let inner = norito::DecodeLimits::new(10, bytes.len(), 10, bytes.len() * 16, 16);
    let err = norito::with_decode_limits(ambient, || {
        norito::codec::decode_exact_from_slice_with_limits::<Vec<u64>>(&bytes, inner)
    })
    .expect_err("an inner exact decoder must inherit the stricter caller budget");
    assert!(matches!(
        err,
        norito::Error::SequenceLengthExceeded {
            length: 4,
            limit: 3
        } | norito::Error::TotalElementsExceeded {
            attempted: 4,
            limit: 3
        }
    ));
}
#[test]
fn failed_limited_exact_decode_does_not_leak_budget_state() {
    let value = vec![1_u64, 2, 3, 4];
    let bytes = norito::codec::encode_adaptive(&value);
    let strict = norito::DecodeLimits::new(3, bytes.len(), 3, bytes.len() * 8, 8);
    norito::codec::decode_exact_from_slice_with_limits::<Vec<u64>>(&bytes, strict)
        .expect_err("strict decode must reject four elements");
    assert_eq!(
        norito::codec::decode_exact_from_slice::<Vec<u64>>(&bytes)
            .expect("default budget must be restored"),
        value
    );
}

fn unrestricted_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX)
}

#[test]
fn exact_slice_decoders_restore_outer_layout_payload_schema_and_root() {
    use norito::core::{self, DecodeFlagsGuard, PayloadCtxGuard};

    let value = ExactPayload {
        label: "inner compact layout".to_owned(),
        data: vec![3, 5, 8],
        count: 3,
    };
    let bytes = norito::codec::encode_adaptive(&value);
    let mut trailing = bytes.clone();
    trailing.push(0);
    let outer_bytes = 17_u32.to_le_bytes();
    let _flags = DecodeFlagsGuard::enter(0);
    let _payload = PayloadCtxGuard::enter_with_schema_and_flags(
        &outer_bytes,
        norito::schema::identity::frame_hash::<u32>(),
        0,
    );
    core::set_decode_root(&outer_bytes);
    let expected_payload = core::payload_ctx();
    let expected_root = core::payload_root_span();
    let expected_frame = core::frame_current_payload_with_default_header::<u32>().unwrap();
    for explicit_limits in [false, true] {
        for input in [bytes.as_slice(), trailing.as_slice()] {
            let decoded = if explicit_limits {
                norito::codec::decode_exact_from_slice_with_limits::<ExactPayload>(
                    input,
                    unrestricted_limits(),
                )
            } else {
                norito::codec::decode_exact_from_slice::<ExactPayload>(input)
            };
            if input.len() == bytes.len() {
                assert_eq!(decoded.unwrap(), value);
            } else {
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
            }
            assert_eq!(core::effective_decode_flags(), Some(0));
            assert_eq!(core::payload_ctx(), expected_payload);
            assert_eq!(core::payload_root_span(), expected_root);
            assert_eq!(
                core::frame_current_payload_with_default_header::<u32>().unwrap(),
                expected_frame,
            );
            assert!(matches!(
                core::frame_current_payload_with_default_header::<u64>(),
                Err(norito::Error::SchemaMismatch),
            ));
        }
    }
    core::clear_decode_root();
}

#[test]
fn exact_slice_state_restoration_keeps_original_enclosing_accounting() {
    use norito::core::{self, DecodeAttemptErrorKind, DecodeResourceError};

    let value = vec![7_u8; 32];
    let bytes = norito::codec::encode_adaptive(&value);
    let decode = |explicit_limits| {
        if explicit_limits {
            norito::codec::decode_exact_from_slice_with_limits::<Vec<u8>>(
                &bytes,
                unrestricted_limits(),
            )
        } else {
            norito::codec::decode_exact_from_slice::<Vec<u8>>(&bytes)
        }
    };
    // The specialized byte-vector decoder charges its count and owned byte storage.
    let one_charge = 2 * value.len();
    let limit = 2 * one_charge - 1;
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, usize::MAX);
    for explicit_limits in [false, true] {
        let (refusal, usage) = core::with_decode_limits_measured(limits, || {
            assert_eq!(decode(explicit_limits).unwrap(), value);
            core::classify_decode_attempt(|| decode(explicit_limits)).unwrap_err()
        });
        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(
            refusal.error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded {
                attempted: (2 * one_charge) as u64,
                limit: limit as u64,
            }),
        );
        assert_eq!(usage.total_allocated_bytes(), one_charge + value.len());
        assert_eq!(usage.total_elements(), 2 * value.len());
        assert_eq!(decode(explicit_limits).unwrap(), value);
    }
}
