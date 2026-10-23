//! Envelope, error-ordering, and borrowed-material controls for ML-DSA.

use super::*;
use crate::{Algorithm, PublicKey, PublicKeyCompact, PublicKeyMaterial, Signature};

#[test]
fn key_rejection_preserves_exact_diagnostics_and_precedence() {
    let bytes = [0x51; ML_DSA_65_PUBLIC_KEY_BYTES + 1];
    for length in [
        0,
        1,
        ML_DSA_65_PUBLIC_KEY_BYTES - 1,
        ML_DSA_65_PUBLIC_KEY_BYTES + 1,
    ] {
        assert_eq!(
            validate_public_key(&bytes[..length]),
            Err(KeyRejection::Length)
        );
        assert_eq!(
            verify(&bytes[..length], &[], b""),
            Err(Rejection::Key(KeyRejection::Length))
        );
        let malformed = PublicKey(PublicKeyCompact::new(Algorithm::MlDsa, &bytes[..length]));
        let error = Signature::from_bytes(&[])
            .verify(&malformed, b"")
            .unwrap_err();
        assert!(
            matches!(error, Error::Parse(ParseError::Invalid(ref text)) if text == "invalid ML-DSA public key length")
        );
    }
    let zero = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
    assert_eq!(validate_public_key(&zero), Err(KeyRejection::AllZero));
    assert_eq!(
        verify(&zero, &[], b""),
        Err(Rejection::Key(KeyRejection::AllZero))
    );
    assert_eq!(
        KeyRejection::AllZero.into_parse_error().to_string(),
        "invalid ML-DSA public key: all-zero material"
    );
    #[cfg(feature = "pqc")]
    assert_eq!(
        KeyRejection::Encoding.into_parse_error().to_string(),
        "invalid ML-DSA public key"
    );
    assert!(matches!(
        Rejection::Signature.into_error(),
        Error::BadSignature
    ));
}

#[test]
fn canonical_mldsa_material_borrows_original_bytes_and_never_enters_cache() {
    let bytes = [0x51; ML_DSA_65_PUBLIC_KEY_BYTES];
    let material = crate::parse_public_key_material(Algorithm::MlDsa, &bytes).unwrap();
    let PublicKeyMaterial::MlDsa(borrowed) = material else {
        panic!("ML-DSA must remain borrowed")
    };
    assert!(core::ptr::eq(borrowed.as_ptr(), bytes.as_ptr()));
    let key = PublicKeyMaterial::MlDsa(borrowed).into_public_key();
    assert_eq!(key.to_bytes(), (Algorithm::MlDsa, bytes.as_slice()));
    super::super::PUBLIC_KEY_FULL_CACHE.with(|cache| cache.borrow_mut().clear());
    for _ in 0..3 {
        let parsed = super::super::public_key_material_cached(&key).unwrap();
        let PublicKeyMaterial::MlDsa(borrowed) = parsed else {
            panic!("ML-DSA must remain borrowed")
        };
        assert!(core::ptr::eq(borrowed.as_ptr(), key.to_bytes().1.as_ptr()));
        let result = Signature::from_bytes(&[]).verify(&key, b"");
        #[cfg(feature = "pqc")]
        assert_eq!(result, Err(Error::BadSignature));
        #[cfg(not(feature = "pqc"))]
        assert_eq!(
            result,
            Err(Error::UnsupportedImplementation(
                UnsupportedImplementation {
                    algorithm: Algorithm::MlDsa,
                    operation: CryptoOperation::VerifySignature,
                }
            ))
        );
        assert_eq!(
            super::super::PUBLIC_KEY_FULL_CACHE.with(|cache| cache.borrow().len()),
            0
        );
    }
}

#[test]
fn malformed_key_is_rejected_before_keypair_algorithm_mismatch() {
    let pair = crate::KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let malformed = PublicKey(PublicKeyCompact::new(Algorithm::MlDsa, &[]));
    let error = crate::KeyPair::new(malformed, pair.private_key().clone()).unwrap_err();
    assert!(
        matches!(error, Error::Parse(ParseError::Invalid(ref text)) if text == "invalid ML-DSA public key length")
    );
}

#[test]
fn signature_geometry_and_batch_errors_remain_deterministic() {
    let key = [0x51; ML_DSA_65_PUBLIC_KEY_BYTES];
    for signature in [&[][..], &[0x51][..], &[0; 3309][..], &[0x51; 3310][..]] {
        #[cfg(feature = "pqc")]
        {
            assert_eq!(verify(&key, signature, b""), Err(Rejection::Signature));
            assert_eq!(
                crate::pqc_verify_batch_deterministic(&[b""], &[signature], &[&key], [0; 32]),
                Err(Error::BadSignature)
            );
        }
        #[cfg(not(feature = "pqc"))]
        {
            let original = UnsupportedImplementation {
                algorithm: Algorithm::MlDsa,
                operation: CryptoOperation::VerifySignature,
            };
            assert_eq!(
                verify(&key, signature, b""),
                Err(Rejection::UnsupportedImplementation(original))
            );
            assert_eq!(
                crate::pqc_verify_batch_deterministic(&[b""], &[signature], &[&key], [0; 32]),
                Err(Error::UnsupportedImplementation(original))
            );
        }
    }
    assert!(matches!(
        crate::pqc_verify_batch_deterministic(&[], &[], &[], [0; 32]),
        Err(Error::BadSignature)
    ));
    assert!(matches!(
        crate::pqc_verify_batch_deterministic(&[b""], &[], &[&key], [0; 32]),
        Err(Error::BadSignature)
    ));
}
