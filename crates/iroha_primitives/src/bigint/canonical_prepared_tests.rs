//! Independent signed-byte canonical relation parity before prepared construction.

use super::*;

fn check(payload: &[u8]) {
    let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    // The old sole owned relation, expressed directly for a differential oracle.
    let expected = BigInt::from_twos_bytes(payload).map(|value| value.to_twos_bytes() == payload);
    let actual = canonical_twos_payload(&bytes);
    match (expected, actual) {
        (Ok(true), Ok((borrowed, used))) => {
            assert_eq!(borrowed, payload);
            assert_eq!(used, bytes.len());
        }
        (Ok(false), Err(error)) => {
            assert_eq!(error.to_string(), BigIntError::NonCanonical.to_string())
        }
        (Err(_), Err(error)) => assert_eq!(error.to_string(), "invalid bigint"),
        (expected, actual) => panic!("canonical relation differs: {expected:?} / {actual:?}"),
    }
}
#[test]
fn borrowed_signed_byte_relation_matches_original_zero_negative_minimum_and_sign_extension() {
    check(&[]);
    for first in 0..=u8::MAX {
        check(&[first]);
        for second in 0..=u8::MAX {
            check(&[first, second]);
        }
    }
    for len in [63, 64, 65, 511, 512, 513] {
        for last in [0, 1, 0x7f, 0x80, 0xff] {
            let mut bytes = vec![0; len];
            *bytes.last_mut().unwrap() = last;
            check(&bytes);
            bytes.fill(0xff);
            *bytes.last_mut().unwrap() = last;
            check(&bytes);
        }
    }
}
#[test]
fn borrowed_signed_byte_relation_preserves_length_failure_order_and_complete_prefix() {
    for len in 0..4 {
        assert!(canonical_twos_payload(&[0; 4][..len]).is_err());
    }
    let bytes = [2, 0, 0, 0, 1];
    assert_eq!(
        canonical_twos_payload(&bytes).unwrap_err().to_string(),
        "buffer too short"
    );
    let bytes = [1, 0, 0, 0, 1, 0x42];
    let (payload, used) = canonical_twos_payload(&bytes).unwrap();
    assert_eq!(payload, &[1]);
    assert_eq!(used, 5);
}

#[test]
fn original_nested_bigint_decoder_must_refuse_unadmitted_native_digits() {
    let bytes = [1, 0, 0, 0, 1];
    let outer = ncore::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let inner =
        ncore::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let result = ncore::with_decode_limits(outer, || {
        ncore::with_decode_limits(inner, || BigInt::decode_from_slice(&bytes))
    });
    assert!(
        matches!(result, Err(ncore::Error::TotalAllocationExceeded { .. })),
        "ordinary native digits must consume original enclosing allocation budget before construction"
    );
}

#[test]
fn ordinary_scalar_decoder_probes_exact_native_digits_without_negative_byte_scratch() {
    for value in [
        BigInt::zero(),
        BigInt::one(),
        BigInt::from(-1_i64),
        BigInt::from(1_u128 << 127),
        BigInt::from_inner(-(InnerBigInt::one() << 4095_usize)).unwrap(),
    ] {
        let payload = value.to_twos_bytes();
        let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        let expected = value.admission_clone_layout().unwrap().size();
        let limits =
            ncore::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, expected, usize::MAX);
        let (result, usage) =
            ncore::with_decode_limits_measured(limits, || BigInt::decode_from_slice(&bytes));
        assert_eq!(result.unwrap(), (value, bytes.len()));
        assert_eq!(usage.total_allocated_bytes(), expected);
        if expected != 0 {
            let short = ncore::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                expected - 1,
                usize::MAX,
            );
            assert!(matches!(
                ncore::with_decode_limits(short, || BigInt::decode_from_slice(&bytes)),
                Err(ncore::Error::TotalAllocationExceeded { .. })
            ));
        }
    }
}

#[test]
fn archived_bigint_retains_original_allocation_refusal_and_retries_same_quantity_source() {
    use crate::numeric::{Numeric, Quantity};

    #[repr(align(8))]
    struct AlignedSource([u8; 64]);

    let _flags = ncore::DecodeFlagsGuard::enter(0);
    let mantissa = BigInt::from(1_u128 << 127);
    let native_charge = mantissa.admission_clone_layout().unwrap().size();
    let expected = Quantity::try_from(Numeric::try_new(mantissa, 1).unwrap()).unwrap();
    let mut bytes = Vec::new();
    ncore::serialize_to_buffer(&expected, &mut bytes).unwrap();
    let mut aligned = AlignedSource([0; 64]);
    aligned.0[..bytes.len()].copy_from_slice(&bytes);
    let source = &aligned.0[..bytes.len()];
    let pointer = source.as_ptr();
    assert!(
        (pointer.addr() + core::mem::size_of::<u64>())
            .is_multiple_of(ncore::archived_payload_align::<BigInt>())
    );
    // Borrowed framing charges no storage. Refuse the actual native digits before
    // their allocation; the nested canonical limit must not replenish this scope.
    let limits = ncore::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        native_charge - 1,
        usize::MAX,
    );
    let error = ncore::with_decode_limits_scope(limits, || {
        ncore::classify_decode_attempt(|| {
            ncore::with_decode_limits(norito::canonical_decode_limits(source.len()), || {
                Quantity::decode_from_slice(source)
            })
        })
    })
    .unwrap_err();
    assert_eq!(error.kind(), ncore::DecodeAttemptErrorKind::EnclosingLimit);
    let original = error.into_error();
    assert!(matches!(
        original.decode_resource_error(),
        Some(ncore::DecodeResourceError::TotalAllocationExceeded { attempted, limit })
            if attempted == native_charge as u64 && limit == (native_charge - 1) as u64
    ));
    assert_eq!(source, bytes);
    assert_eq!(source.as_ptr(), pointer);
    let reintroduced = ncore::classify_decode_attempt(|| Err::<(), _>(original)).unwrap_err();
    assert_eq!(reintroduced.kind(), ncore::DecodeAttemptErrorKind::Invalid);
    let (retried, used) =
        ncore::with_decode_limits(norito::canonical_decode_limits(source.len()), || {
            Quantity::decode_from_slice(source)
        })
        .unwrap();
    assert_eq!(retried, expected);
    assert_eq!(used, source.len());
    assert_eq!(source, bytes);
    assert_eq!(source.as_ptr(), pointer);
}
