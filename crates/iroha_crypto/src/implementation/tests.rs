//! Canonical identities and local capability refusals remain distinct across builds.
use super::*;
use crate::{
    Error, KeyPair, ParseError, PrivateKey, PublicKey, PublicKeyCompact, Signature,
    test_allocations::without_allocations, verify_signature_borrowed,
};

#[test]
fn all_canonical_capabilities_report_exact_missing_operation_without_allocation() {
    for &algorithm in Algorithm::ALL {
        for operation in [
            CryptoOperation::ParsePublicKey,
            CryptoOperation::ParsePrivateKey,
            CryptoOperation::GenerateKeyPair,
            CryptoOperation::Sign,
            CryptoOperation::VerifySignature,
        ] {
            let expected = match algorithm {
                Algorithm::Ed25519 | Algorithm::Secp256k1 => true,
                Algorithm::MlDsa => {
                    operation == CryptoOperation::ParsePublicKey || cfg!(feature = "pqc")
                }
                Algorithm::BlsNormal | Algorithm::BlsSmall => cfg!(feature = "bls"),
                Algorithm::Gost3410_2012_256ParamSetA
                | Algorithm::Gost3410_2012_256ParamSetB
                | Algorithm::Gost3410_2012_256ParamSetC
                | Algorithm::Gost3410_2012_512ParamSetA
                | Algorithm::Gost3410_2012_512ParamSetB => cfg!(feature = "gost"),
                Algorithm::Sm2 => cfg!(feature = "sm"),
            };
            let actual = without_allocations(|| algorithm.require_implementation(operation));
            assert_eq!(
                actual,
                if expected {
                    Ok(())
                } else {
                    Err(UnsupportedImplementation {
                        algorithm,
                        operation,
                    })
                }
            );
        }
    }
    assert!(!std::mem::needs_drop::<UnsupportedImplementation>());
}

#[test]
fn missing_backends_preserve_constructor_and_verifier_error_categories() {
    for &algorithm in Algorithm::ALL {
        if algorithm
            .require_implementation(CryptoOperation::GenerateKeyPair)
            .is_ok()
        {
            continue;
        }
        let expected = UnsupportedImplementation {
            algorithm,
            operation: CryptoOperation::GenerateKeyPair,
        };
        let seed = vec![0x79; 32];
        assert_eq!(
            without_allocations(|| KeyPair::try_from_seed(seed, algorithm)).unwrap_err(),
            Error::UnsupportedImplementation(expected)
        );
        assert_eq!(
            without_allocations(|| PrivateKey::from_bytes(algorithm, &[1; 32])).unwrap_err(),
            ParseError::UnsupportedImplementation(UnsupportedImplementation {
                algorithm,
                operation: CryptoOperation::ParsePrivateKey
            })
        );
        // A raw private test fixture exercises dispatch only, never claims a valid key/proof.
        let payload = [1; crate::ML_DSA_65_PUBLIC_KEY_BYTES];
        let key = PublicKey(PublicKeyCompact::new(algorithm, &payload));
        let signature = Signature::from_bytes(&[1; 64]);
        let expected = UnsupportedImplementation {
            algorithm,
            operation: CryptoOperation::VerifySignature,
        };
        let refusal = without_allocations(|| {
            verify_signature_borrowed(&signature, &key, b"capability").unwrap_err()
        });
        assert_eq!(refusal.unsupported_implementation(), Some(expected));
        assert_eq!(
            without_allocations(|| refusal.into_error()),
            Error::UnsupportedImplementation(expected)
        );
        assert_eq!(
            without_allocations(|| signature.verify(&key, b"capability")).unwrap_err(),
            Error::UnsupportedImplementation(expected)
        );
    }
}

#[test]
fn missing_key_decoder_retains_known_feature_across_binary_json_boundary() {
    for &algorithm in Algorithm::ALL {
        if algorithm
            .require_implementation(CryptoOperation::ParsePublicKey)
            .is_ok()
        {
            continue;
        }
        let expected = UnsupportedImplementation {
            algorithm,
            operation: CryptoOperation::ParsePublicKey,
        };
        assert_eq!(
            without_allocations(|| PublicKey::from_bytes(algorithm, &[1; 48])).unwrap_err(),
            ParseError::UnsupportedImplementation(expected)
        );
        let refusal = without_allocations(|| {
            PublicKey::from_bytes_for_decode(algorithm, &[1; 48]).unwrap_err()
        });
        let restored = without_allocations(|| {
            let json = crate::public_key_json_decode_error(refusal);
            assert!(
                matches!(&json, norito::json::Error::UnsupportedFeature(name) if *name == algorithm.as_static_str())
            );
            json.into_core_error()
        });
        assert!(
            matches!(restored, norito::Error::UnsupportedFeature(name) if name == algorithm.as_static_str())
        );
        let source = crate::multihash::encode_public_key_prefixed(algorithm, &[1; 48]);
        let source = norito::json::to_json(&source.split_once(':').unwrap().1).unwrap();
        assert!(
            matches!(norito::json::from_str::<PublicKey>(&source), Err(norito::json::Error::UnsupportedFeature(name)) if name == algorithm.as_static_str())
        );
    }
}

#[test]
fn missing_secret_decoder_retains_known_feature_in_json() {
    for &algorithm in Algorithm::ALL {
        if algorithm
            .require_implementation(CryptoOperation::ParsePrivateKey)
            .is_ok()
        {
            continue;
        }
        let input = crate::multihash::encode_private_key_prefixed(algorithm, &[1; 32]);
        let json = norito::json::to_json(&input).unwrap();
        assert!(
            matches!(norito::json::from_str::<PrivateKey>(&json), Err(norito::json::Error::UnsupportedFeature(name)) if name == algorithm.as_static_str())
        );
        assert!(
            matches!(norito::json::from_str::<crate::ExposedPrivateKey>(&json), Err(norito::json::Error::UnsupportedFeature(name)) if name == algorithm.as_static_str())
        );
        let original = ParseError::UnsupportedImplementation(UnsupportedImplementation {
            algorithm,
            operation: CryptoOperation::ParsePrivateKey,
        });
        assert!(
            matches!(without_allocations(|| original.into_decode_error()), norito::Error::UnsupportedFeature(name) if name == algorithm.as_static_str())
        );
    }
}

#[test]
fn available_verifiers_keep_actual_valid_and_invalid_signature_relations() {
    for &algorithm in Algorithm::ALL {
        if algorithm
            .require_implementation(CryptoOperation::GenerateKeyPair)
            .is_err()
        {
            continue;
        }
        let pair = KeyPair::try_from_seed(vec![0x45 + algorithm as u8; 32], algorithm).unwrap();
        let proof = Signature::try_new(pair.private_key(), b"canonical capabilities").unwrap();
        verify_signature_borrowed(&proof, pair.public_key(), b"canonical capabilities").unwrap();
        proof
            .verify(pair.public_key(), b"canonical capabilities")
            .unwrap();
        let invalid = verify_signature_borrowed(&proof, pair.public_key(), b"changed").unwrap_err();
        assert_eq!(invalid.unsupported_implementation(), None);
        assert_eq!(invalid.into_error(), Error::BadSignature);
        assert_eq!(
            proof.verify(pair.public_key(), b"changed"),
            Err(Error::BadSignature)
        );
    }
}

#[test]
fn available_key_decoder_preserves_original_local_refusal_and_same_source_retry() {
    let pair = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519).unwrap();
    let payload = pair.public_key().to_bytes().1;
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    norito::with_decode_limits_scope(limits, || {
        let refused = norito::core::classify_decode_attempt(|| {
            PublicKey::from_bytes_for_decode(Algorithm::Ed25519, payload)
                .map_err(|original| crate::public_key_json_decode_error(original).into_core_error())
        })
        .unwrap_err();
        assert_eq!(
            refused.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(refused.local_refusal().is_some());
    });
    assert_eq!(
        PublicKey::from_bytes_for_decode(Algorithm::Ed25519, payload).unwrap(),
        *pair.public_key()
    );
}

#[test]
fn public_key_decode_classifier_requires_exact_identity_and_actual_absence() {
    for &algorithm in Algorithm::ALL {
        let error = norito::Error::UnsupportedFeature(algorithm.as_static_str());
        assert_eq!(
            without_allocations(|| UnsupportedImplementation::from_public_key_decode_error(&error)),
            algorithm
                .require_implementation(CryptoOperation::ParsePublicKey)
                .err()
        );
    }
    for error in [
        norito::Error::UnsupportedFeature("unknown-cryptographic-algorithm"),
        norito::Error::UnsupportedFeature("Ed25519"),
        norito::Error::LengthMismatch,
        norito::Error::AllocationFailed { bytes: 17 },
    ] {
        assert_eq!(
            without_allocations(|| UnsupportedImplementation::from_public_key_decode_error(&error)),
            None
        );
    }
}

#[test]
fn original_gost_public_key_decoder_and_json_preserve_actual_capability() {
    let algorithm = Algorithm::Gost3410_2012_256ParamSetA;
    let key =
        hex::decode(include_str!("../../../../fixtures/account/gost256a_public_key.hex").trim())
            .unwrap();
    let decoded = PublicKey::from_bytes_for_decode(algorithm, &key);
    let text = crate::multihash::encode_public_key_prefixed(algorithm, &key);
    let json = norito::json::to_json(&text.split_once(':').unwrap().1).unwrap();
    let from_json = norito::json::from_str::<PublicKey>(&json);
    match algorithm.require_implementation(CryptoOperation::ParsePublicKey) {
        Ok(()) => {
            let decoded =
                decoded.expect("available GOST parser accepts the original valid fixture");
            assert_eq!(decoded.try_to_bytes().unwrap(), (algorithm, key.as_slice()));
            assert_eq!(from_json.unwrap(), decoded);
            eprintln!("actual GOST parser: available; original binary and JSON fixture decoded");
        }
        Err(original) => {
            for error in [
                decoded.unwrap_err(),
                from_json.unwrap_err().into_core_error(),
            ] {
                assert!(matches!(&error, norito::Error::UnsupportedFeature(name)
                    if *name == algorithm.as_static_str()));
                assert_eq!(
                    without_allocations(
                        || UnsupportedImplementation::from_public_key_decode_error(&error)
                    ),
                    Some(original)
                );
            }
            eprintln!(
                "actual GOST parser: absent; original binary and JSON decoder cause preserved"
            );
        }
    }
    let malformed_ed = PublicKey::from_bytes_for_decode(Algorithm::Ed25519, &[0; 1]).unwrap_err();
    assert_eq!(
        UnsupportedImplementation::from_public_key_decode_error(&malformed_ed),
        None
    );
}
