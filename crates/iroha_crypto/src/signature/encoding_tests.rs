//! Raw encoding parity, physical allocation refusal and independent message verification.

use super::*;
use crate::{
    Algorithm, KeyPair, ed25519_parse_signature, mldsa65_parse_signature,
    test_allocations::{allocations_during, with_allocation_failure, without_allocations},
    verify_signature_borrowed,
};

fn signed(algorithm: Algorithm) -> (KeyPair, Signature) {
    let pair = KeyPair::try_from_seed(vec![0x71; 32], algorithm).unwrap();
    let signature = Signature::try_new(pair.private_key(), b"borrowed encoding").unwrap();
    (pair, signature)
}

#[test]
fn ed25519_encoding_has_zero_allocation_for_valid_and_canonical_rejections() {
    let (_, signature) = signed(Algorithm::Ed25519);
    assert_eq!(
        without_allocations(|| ed25519_validate_signature_encoding(signature.payload())),
        Ok(())
    );
    for (bytes, expected) in [
        (
            &[][..],
            SignatureEncodingError::Payload(SignaturePayloadError::Empty),
        ),
        (
            &[0; 64][..],
            SignatureEncodingError::Payload(SignaturePayloadError::AllZero),
        ),
        (&[1; 63][..], SignatureEncodingError::Malformed),
        (&[1; 65][..], SignatureEncodingError::Malformed),
    ] {
        assert_eq!(
            without_allocations(|| ed25519_validate_signature_encoding(bytes)),
            Err(expected)
        );
        assert_eq!(
            ed25519_parse_signature(bytes).unwrap_err(),
            expected.into_error()
        );
    }
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    let mixed = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
        + curve25519_dalek::constants::EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    for r in [identity, noncanonical, mixed] {
        let mut bytes = signature.payload().to_vec();
        bytes[..32].copy_from_slice(&r);
        assert_eq!(
            without_allocations(|| ed25519_validate_signature_encoding(&bytes)),
            Err(SignatureEncodingError::Malformed)
        );
        assert_eq!(
            ed25519_parse_signature(&bytes).unwrap_err(),
            Error::BadSignature
        );
    }
    assert_eq!(
        ed25519_parse_signature(signature.payload())
            .unwrap()
            .payload(),
        signature.payload()
    );
}

#[test]
fn borrowed_encoding_does_not_request_owned_admission_or_physical_backing() {
    let (_, signature) = signed(Algorithm::Ed25519);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(
            without_allocations(|| ed25519_validate_signature_encoding(signature.payload())),
            Ok(())
        );
        let original = norito::core::classify_decode_attempt(|| {
            Signature::try_from_bytes_for_admission(signature.payload())
        })
        .unwrap_err();
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(original.local_refusal().is_some());
    });
    with_allocation_failure(signature.payload().len(), || {
        assert_eq!(
            without_allocations(|| ed25519_validate_signature_encoding(signature.payload())),
            Ok(())
        );
        let (original, allocations) = allocations_during(|| {
            norito::core::classify_decode_attempt(|| {
                Signature::try_from_bytes_for_admission(signature.payload())
            })
        });
        assert_eq!(allocations, 1);
        let original = original.unwrap_err();
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::Allocator
        );
        assert!(matches!(
            original.error(),
            norito::core::Error::AllocationFailed { bytes: 64 }
        ));
        assert!(original.local_refusal().is_some());
    });
    assert_eq!(
        ed25519_parse_signature(signature.payload())
            .unwrap()
            .payload(),
        signature.payload()
    );
}

#[test]
fn borrowed_ed25519_encoding_does_not_substitute_for_signature_verification() {
    let (pair, signature) = signed(Algorithm::Ed25519);
    assert!(
        without_allocations(|| verify_signature_borrowed(
            &signature,
            pair.public_key(),
            b"borrowed encoding"
        ))
        .is_ok()
    );
    assert!(
        without_allocations(|| verify_signature_borrowed(
            &signature,
            pair.public_key(),
            b"different message"
        ))
        .is_err()
    );
    let mut bytes = signature.payload().to_vec();
    bytes[63] = 0xff;
    assert_eq!(
        without_allocations(|| ed25519_validate_signature_encoding(&bytes)),
        Ok(())
    );
    let invalid_relation = Signature::from_bytes(&bytes);
    assert!(
        without_allocations(|| verify_signature_borrowed(
            &invalid_relation,
            pair.public_key(),
            b"borrowed encoding"
        ))
        .is_err()
    );
}

#[test]
fn mldsa_encoding_has_zero_allocation_and_the_owned_parser_geometry() {
    let bytes = [1; ML_DSA_65_SIGNATURE_BYTES];
    assert_eq!(
        without_allocations(|| mldsa65_validate_signature_encoding(&bytes)),
        Ok(())
    );
    for (payload, expected) in [
        (
            &[][..],
            SignatureEncodingError::Payload(SignaturePayloadError::Empty),
        ),
        (
            &[0; 64][..],
            SignatureEncodingError::Payload(SignaturePayloadError::AllZero),
        ),
        (&bytes[..bytes.len() - 1], SignatureEncodingError::Malformed),
    ] {
        assert_eq!(
            without_allocations(|| mldsa65_validate_signature_encoding(payload)),
            Err(expected)
        );
        assert_eq!(
            mldsa65_parse_signature(payload).unwrap_err(),
            expected.into_error()
        );
    }
    let mut long = bytes.to_vec();
    long.push(1);
    assert_eq!(
        without_allocations(|| mldsa65_validate_signature_encoding(&long)),
        Err(SignatureEncodingError::Malformed)
    );
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(
            without_allocations(|| mldsa65_validate_signature_encoding(&bytes)),
            Ok(())
        );
        let original = norito::core::classify_decode_attempt(|| {
            Signature::try_from_bytes_for_admission(&bytes)
        })
        .unwrap_err();
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
    });
    with_allocation_failure(bytes.len(), || {
        assert_eq!(
            without_allocations(|| mldsa65_validate_signature_encoding(&bytes)),
            Ok(())
        );
        let original = norito::core::classify_decode_attempt(|| {
            Signature::try_from_bytes_for_admission(&bytes)
        })
        .unwrap_err();
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::Allocator
        );
    });
    assert_eq!(mldsa65_parse_signature(&bytes).unwrap().payload(), bytes);
}

#[test]
#[cfg(feature = "pqc")]
fn borrowed_mldsa_encoding_preserves_valid_and_invalid_verification_relations() {
    let (pair, signature) = signed(Algorithm::MlDsa);
    assert_eq!(
        without_allocations(|| mldsa65_validate_signature_encoding(signature.payload())),
        Ok(())
    );
    assert!(
        without_allocations(|| verify_signature_borrowed(
            &signature,
            pair.public_key(),
            b"borrowed encoding"
        ))
        .is_ok()
    );
    assert!(
        without_allocations(|| verify_signature_borrowed(
            &signature,
            pair.public_key(),
            b"different message"
        ))
        .is_err()
    );
    assert_eq!(
        mldsa65_parse_signature(signature.payload())
            .unwrap()
            .payload(),
        signature.payload()
    );
}

#[test]
fn fixed_encoding_error_only_materializes_completed_public_diagnostics() {
    for error in [
        SignatureEncodingError::Payload(SignaturePayloadError::Empty),
        SignatureEncodingError::Payload(SignaturePayloadError::AllZero),
        SignatureEncodingError::Malformed,
    ] {
        assert_eq!(error.to_string(), error.into_error().to_string());
    }
}
