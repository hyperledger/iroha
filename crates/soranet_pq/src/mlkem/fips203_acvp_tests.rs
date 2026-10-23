//! Independent FIPS 203 ACVP answers and strict public entry-point checks.

use super::*;
use crate::acvp_tests::{bytes, cases, groups, number, passed, text};
use norito::json::Value;

const KEYGEN: &str = "ML-KEM-keyGen-FIPS203";
const ENCAP_DECAP: &str = "ML-KEM-encapDecap-FIPS203-tr1";

fn suite(group: &Value) -> MlKemSuite {
    match text(group, "parameterSet") {
        "ML-KEM-512" => MlKemSuite::MlKem512,
        "ML-KEM-768" => MlKemSuite::MlKem768,
        "ML-KEM-1024" => MlKemSuite::MlKem1024,
        other => panic!("unexpected ACVP parameter set {other}"),
    }
}

#[test]
fn acvp_keygen_matches_independent_public_and_secret_bytes() {
    for group in groups(KEYGEN) {
        let suite = suite(group);
        for case in cases(group) {
            let id = number(case, "tcId");
            let mut coins = bytes(case, "d");
            coins.extend(bytes(case, "z"));
            let keypair = generate_mlkem_keypair_from_coins(
                suite,
                &coins.try_into().expect("ACVP d || z has 64 bytes"),
            )
            .expect("ACVP key generation");
            assert_eq!(
                keypair.public_key(),
                bytes(case, "ek"),
                "{suite:?} tcId={id}"
            );
            assert_eq!(
                keypair.secret_key(),
                bytes(case, "dk"),
                "{suite:?} tcId={id}"
            );
            validate_mlkem_key_pair(suite, keypair.public_key(), keypair.secret_key())
                .expect("official key pair is canonical and consistent");
        }
    }
}

#[test]
fn acvp_encapsulation_matches_independent_ciphertext_and_secret() {
    for group in groups(ENCAP_DECAP) {
        if text(group, "function") != "encapsulation" {
            continue;
        }
        let suite = suite(group);
        for case in cases(group) {
            let id = number(case, "tcId");
            let (shared, ciphertext) = encapsulate_mlkem_from_coins(
                suite,
                &bytes(case, "ek"),
                &bytes(case, "m").try_into().expect("ACVP m has 32 bytes"),
            )
            .expect("ACVP encapsulation");
            assert_eq!(
                ciphertext.as_bytes(),
                bytes(case, "c"),
                "{suite:?} tcId={id}"
            );
            assert_eq!(shared.as_bytes(), bytes(case, "k"), "{suite:?} tcId={id}");
        }
    }
}

#[test]
fn acvp_decapsulation_matches_valid_and_implicit_rejection_answers() {
    for group in groups(ENCAP_DECAP) {
        if text(group, "function") != "decapsulation" {
            continue;
        }
        assert_eq!(text(group, "keyFormat"), "expanded");
        let suite = suite(group);
        let mut reasons = std::collections::BTreeSet::new();
        for case in cases(group) {
            let id = number(case, "tcId");
            reasons.insert(text(case, "reason"));
            // A modified length-valid ciphertext returns the official implicit
            // rejection key, not an encoding error or the original shared key.
            let shared = decapsulate_mlkem(suite, &bytes(case, "dk"), &bytes(case, "c"))
                .expect("both valid and implicit-rejection decapsulation return a key");
            assert_eq!(shared.as_bytes(), bytes(case, "k"), "{suite:?} tcId={id}");
        }
        assert_eq!(
            reasons,
            ["modified ciphertext", "valid decapsulation"]
                .into_iter()
                .collect()
        );
    }
}

#[test]
fn acvp_key_checks_preserve_positive_and_negative_dispositions() {
    for group in groups(ENCAP_DECAP) {
        let function = text(group, "function");
        if !function.ends_with("KeyCheck") {
            continue;
        }
        let suite = suite(group);
        let mut dispositions = std::collections::BTreeSet::new();
        for case in cases(group) {
            let id = number(case, "tcId");
            dispositions.insert(passed(case));
            match function {
                "encapsulationKeyCheck" => {
                    let public = bytes(case, "ek");
                    let result = validate_mlkem_public_key(suite, &public);
                    assert_eq!(result.is_ok(), passed(case), "{suite:?} tcId={id}");
                    if !passed(case) {
                        assert!(matches!(
                            result,
                            Err(MlKemError::NonCanonicalEncoding { .. })
                        ));
                        assert!(matches!(
                            encapsulate_mlkem_from_coins(suite, &public, &[1; 32]),
                            Err(MlKemError::NonCanonicalEncoding { .. })
                        ));
                    }
                }
                "decapsulationKeyCheck" => {
                    let secret = bytes(case, "dk");
                    let result = validate_mlkem_secret_key(suite, &secret);
                    assert_eq!(result.is_ok(), passed(case), "{suite:?} tcId={id}");
                    if !passed(case) {
                        assert!(matches!(
                            result,
                            Err(MlKemError::KeyPairPublicHashMismatch { .. })
                        ));
                        let mut output = [0xa5; 32];
                        assert!(matches!(
                            decapsulate_mlkem_into(
                                suite,
                                &secret,
                                &vec![1; suite.ciphertext_len()],
                                &mut output
                            ),
                            Err(MlKemError::KeyPairPublicHashMismatch { .. })
                        ));
                        assert_eq!(output, [0; 32]);
                    }
                }
                other => panic!("unexpected ACVP key check {other}"),
            }
        }
        assert_eq!(dispositions, [false, true].into_iter().collect());
    }
}

#[test]
fn acvp_inputs_reject_truncated_and_extended_key_and_ciphertext_encodings() {
    for group in groups(ENCAP_DECAP) {
        if text(group, "function") != "encapsulation" {
            continue;
        }
        let suite = suite(group);
        let case = &cases(group)[0];
        let public = bytes(case, "ek");
        let secret = bytes(case, "dk");
        let ciphertext = bytes(case, "c");
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
            assert!(matches!(
                encapsulate_mlkem_from_coins(suite, &changed(&public), &[1; 32]),
                Err(MlKemError::BadEncoding { .. })
            ));
            for (sk, ct) in [
                (changed(&secret), ciphertext.clone()),
                (secret.clone(), changed(&ciphertext)),
            ] {
                let mut output = [0xa5; 32];
                assert!(matches!(
                    decapsulate_mlkem_into(suite, &sk, &ct, &mut output),
                    Err(MlKemError::BadEncoding { .. })
                ));
                assert_eq!(output, [0; 32], "{suite:?}: failed decode scrubs output");
            }
        }
    }
}
