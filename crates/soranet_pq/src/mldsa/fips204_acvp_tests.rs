//! Independent FIPS 204 external pure-message ACVP vectors and rejection checks.

use super::*;
use crate::acvp_tests::{bytes, cases, groups, number, passed, text};
use norito::json::Value;

const KEYGEN: &str = "ML-DSA-keyGen-FIPS204";
const SIGGEN: &str = "ML-DSA-sigGen-FIPS204-tr1";
const SIGVER: &str = "ML-DSA-sigVer-FIPS204";

fn suite(group: &Value) -> MlDsaSuite {
    match text(group, "parameterSet") {
        "ML-DSA-44" => MlDsaSuite::MlDsa44,
        "ML-DSA-65" => MlDsaSuite::MlDsa65,
        "ML-DSA-87" => MlDsaSuite::MlDsa87,
        other => panic!("unexpected ACVP parameter set {other}"),
    }
}

fn assert_external_pure(group: &Value) {
    assert_eq!(text(group, "signatureInterface"), "external");
    assert_eq!(text(group, "preHash"), "pure");
    assert_eq!(
        group.get("externalMu").and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn acvp_keygen_matches_independent_public_and_secret_bytes() {
    for group in groups(KEYGEN) {
        let suite = suite(group);
        for case in cases(group) {
            let id = number(case, "tcId");
            let keypair = generate_mldsa_keypair_from_fips_seed(
                suite,
                &bytes(case, "seed")
                    .try_into()
                    .expect("ACVP seed has 32 bytes"),
            )
            .expect("official seed keygen");
            assert_eq!(
                keypair.public_key(),
                bytes(case, "pk"),
                "{suite:?} tcId={id}"
            );
            assert_eq!(
                keypair.secret_key(),
                bytes(case, "sk"),
                "{suite:?} tcId={id}"
            );
            assert_eq!(
                mldsa_public_key_from_secret_key(suite, keypair.secret_key()).unwrap(),
                bytes(case, "pk"),
                "{suite:?} tcId={id}"
            );
        }
    }
}

#[test]
fn acvp_randomized_signatures_match_independent_bytes_and_verify() {
    for group in groups(SIGGEN) {
        assert_external_pure(group);
        assert_eq!(
            group.get("deterministic").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(text(group, "keyFormat"), "expanded");
        let suite = suite(group);
        let mut context_lengths = std::collections::BTreeSet::new();
        let mut has_one_byte_message = false;
        for case in cases(group) {
            let id = number(case, "tcId");
            let secret = bytes(case, "sk");
            let public = bytes(case, "pk");
            let context = bytes(case, "context");
            let message = bytes(case, "message");
            context_lengths.insert(context.len());
            has_one_byte_message |= message.len() == 1;
            validate_mldsa_secret_key(suite, &secret).expect("official secret decodes strictly");
            assert_eq!(
                mldsa_public_key_from_secret_key(suite, &secret).unwrap(),
                public
            );
            let signature = sign_mldsa_from_coins(
                suite,
                &secret,
                &context,
                &message,
                &bytes(case, "rnd")
                    .try_into()
                    .expect("ACVP rnd has 32 bytes"),
            )
            .expect("ACVP randomized signing");
            assert_eq!(
                signature.as_bytes(),
                bytes(case, "signature"),
                "{suite:?} tcId={id}"
            );
            verify_mldsa(suite, &public, &context, &message, signature.as_bytes())
                .expect("official randomized signature verifies");
        }
        assert!(context_lengths.contains(&0));
        assert!(context_lengths.contains(&255));
        assert!(has_one_byte_message);
    }
}

#[test]
fn acvp_verification_matches_all_five_official_disposition_classes() {
    for group in groups(SIGVER) {
        assert_external_pure(group);
        let suite = suite(group);
        let mut reasons = std::collections::BTreeSet::new();
        for case in cases(group) {
            let id = number(case, "tcId");
            reasons.insert(text(case, "reason"));
            let result = verify_mldsa(
                suite,
                &bytes(case, "pk"),
                &bytes(case, "context"),
                &bytes(case, "message"),
                &bytes(case, "signature"),
            );
            assert_eq!(
                result.is_ok(),
                passed(case),
                "{suite:?} tcId={id}: {result:?}"
            );
            if !passed(case) {
                assert!(matches!(
                    result,
                    Err(MlDsaError::VerificationFailed(
                        VerificationError::InvalidSignature
                    ))
                ));
            }
        }
        assert_eq!(
            reasons,
            [
                "modified message",
                "modified signature - commitment",
                "modified signature - hint",
                "modified signature - z",
                "valid signature and message - signature should verify successfully",
            ]
            .into_iter()
            .collect()
        );
    }
}

#[test]
fn acvp_valid_signatures_reject_message_and_context_substitution() {
    for group in groups(SIGGEN) {
        let suite = suite(group);
        for case in cases(group) {
            let id = number(case, "tcId");
            let public = bytes(case, "pk");
            let signature = bytes(case, "signature");
            let message = bytes(case, "message");
            let context = bytes(case, "context");
            let mut changed_message = message.clone();
            changed_message[0] ^= 1;
            let mut changed_context = context.clone();
            if changed_context.is_empty() {
                changed_context.push(1);
            } else {
                changed_context[0] ^= 1;
            }
            for (ctx, msg) in [(&context, &changed_message), (&changed_context, &message)] {
                assert!(
                    matches!(
                        verify_mldsa(suite, &public, ctx, msg, &signature),
                        Err(MlDsaError::VerificationFailed(
                            VerificationError::InvalidSignature
                        ))
                    ),
                    "{suite:?} tcId={id}: substitution must not verify"
                );
            }
        }
    }
}

#[test]
fn acvp_valid_signatures_reject_wrong_lengths_and_oversized_context() {
    for group in groups(SIGGEN) {
        let suite = suite(group);
        let case = &cases(group)[0];
        let public = bytes(case, "pk");
        let signature = bytes(case, "signature");
        let message = bytes(case, "message");
        let context = bytes(case, "context");
        for extend in [false, true] {
            let changed = |original: &[u8]| {
                let mut changed = original.to_vec();
                if extend {
                    changed.push(0);
                } else {
                    changed.pop();
                }
                changed
            };
            for (pk, sig) in [
                (changed(&public), signature.clone()),
                (public.clone(), changed(&signature)),
            ] {
                assert!(matches!(
                    verify_mldsa(suite, &pk, &context, &message, &sig),
                    Err(MlDsaError::BadEncoding(_))
                ));
            }
        }
        assert!(matches!(
            verify_mldsa(suite, &public, &[0; 256], &message, &signature),
            Err(MlDsaError::ContextTooLong { len: 256 })
        ));
    }
}

#[test]
fn acvp_valid_signatures_reject_noncanonical_hint_encodings() {
    for group in groups(SIGGEN) {
        let suite = suite(group);
        let case = &cases(group)[0];
        let public = bytes(case, "pk");
        let signature = bytes(case, "signature");
        let message = bytes(case, "message");
        let context = bytes(case, "context");
        // FIPS 204 HintBitPack: omega index bytes followed by k cumulative counts.
        let (omega, k) = match suite {
            MlDsaSuite::MlDsa44 => (80, 4),
            MlDsaSuite::MlDsa65 => (55, 6),
            MlDsaSuite::MlDsa87 => (75, 8),
        };
        let start = signature.len() - omega - k;
        let used = usize::from(signature[signature.len() - 1]);
        assert!(
            used < omega,
            "selected official vector has unused hint padding"
        );
        let mut nonzero_padding = signature.clone();
        nonzero_padding[start + used] = 1;
        let mut excessive_count = signature.clone();
        excessive_count[start + omega] = u8::try_from(omega + 1).unwrap();
        let mut repeated_index = signature.clone();
        let mut previous = 0;
        let mut repeated = false;
        for row in 0..k {
            let end = usize::from(signature[start + omega + row]);
            if end >= previous + 2 {
                repeated_index[start + previous + 1] = repeated_index[start + previous];
                repeated = true;
                break;
            }
            previous = end;
        }
        assert!(
            repeated,
            "selected official vector has two hints in one row"
        );
        for changed in [nonzero_padding, excessive_count, repeated_index] {
            assert!(matches!(
                verify_mldsa(suite, &public, &context, &message, &changed),
                Err(MlDsaError::VerificationFailed(
                    VerificationError::InvalidSignature
                ))
            ));
        }
    }
}

#[test]
fn acvp_mldsa65_vectors_reach_the_typed_iroha_and_ivm_verifier() {
    let group = groups(SIGGEN)
        .iter()
        .find(|group| text(group, "parameterSet") == "ML-DSA-65")
        .expect("official ML-DSA-65 group");
    let mut empty = 0;
    let mut nonempty = 0;
    for case in cases(group) {
        let public = mldsa65::PublicKey::from_bytes(&bytes(case, "pk")).unwrap();
        let signature = mldsa65::DetachedSignature::from_bytes(&bytes(case, "signature")).unwrap();
        let mut message = bytes(case, "message");
        // This is the exported typed helper actually called by iroha_crypto
        // (and transitively IVM); its contract fixes the FIPS context to empty.
        let result = crate::verify_mldsa65_detached(&signature, &message, &public);
        if bytes(case, "context").is_empty() {
            empty += 1;
            result.expect("official empty-context signature verifies through consumer API");
            message[0] ^= 1;
            assert!(matches!(
                crate::verify_mldsa65_detached(&signature, &message, &public),
                Err(VerificationError::InvalidSignature)
            ));
        } else {
            nonempty += 1;
            assert!(
                matches!(result, Err(VerificationError::InvalidSignature)),
                "typed empty-context API must not discard signed context"
            );
        }
    }
    assert_eq!((empty, nonempty), (1, 1));
}
