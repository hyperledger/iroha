//! All admitted algorithm and compact-envelope allocation/error controls.

use super::*;
use crate::{KeyPair, PublicKeyCompact, test_allocations::without_allocations};
use iroha_primitives::const_vec::ConstVec;

fn algorithms() -> Vec<Algorithm> {
    let algorithms = vec![Algorithm::Ed25519, Algorithm::Secp256k1];
    #[cfg(feature = "pqc")]
    let algorithms = {
        let mut values = algorithms;
        values.push(Algorithm::MlDsa);
        values
    };
    #[cfg(feature = "bls")]
    let algorithms = {
        let mut values = algorithms;
        values.extend([Algorithm::BlsNormal, Algorithm::BlsSmall]);
        values
    };
    #[cfg(feature = "gost")]
    let algorithms = {
        let mut values = algorithms;
        values.extend([
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_256ParamSetB,
            Algorithm::Gost3410_2012_256ParamSetC,
            Algorithm::Gost3410_2012_512ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ]);
        values
    };
    #[cfg(feature = "sm")]
    let algorithms = {
        let mut values = algorithms;
        values.push(Algorithm::Sm2);
        values
    };
    #[cfg(all(feature = "pqc", feature = "bls", feature = "gost", feature = "sm"))]
    assert_eq!(
        algorithms.len(),
        11,
        "every shipping algorithm must execute"
    );
    algorithms
}

fn envelope(bytes: Vec<u8>) -> PublicKey {
    PublicKey(PublicKeyCompact {
        algorithm_and_payload: ConstVec::from(bytes),
    })
}

fn compact(algorithm: Algorithm, bytes: &[u8]) -> PublicKey {
    PublicKey(PublicKeyCompact::new(algorithm, bytes))
}

#[test]
fn compact_envelope_errors_remain_fixed_and_preserve_exact_public_diagnostics() {
    for (bytes, expected) in [
        (vec![], "missing public key algorithm tag"),
        (vec![0xff], "invalid public key algorithm tag 255"),
        (vec![0xff, 1, 2], "invalid public key algorithm tag 255"),
    ] {
        let key = envelope(bytes);
        let proof = Signature::from_bytes(&[]);
        let (parts, algorithm, signature) = without_allocations(|| {
            (
                key.borrowed_parts().unwrap_err(),
                key.borrowed_algorithm().unwrap_err(),
                verify_signature_borrowed(&proof, &key, b"").unwrap_err(),
            )
        });
        assert_eq!(parts, algorithm);
        assert_eq!(parts.into_parse_error().to_string(), expected);
        assert_eq!(key.try_to_bytes().unwrap_err().to_string(), expected);
        assert_eq!(key.try_algorithm().unwrap_err().to_string(), expected);
        assert_eq!(
            signature.into_error().to_string(),
            format!("Key could not be parsed. {expected}")
        );
    }
    for tag in 0..=u8::MAX {
        if Algorithm::try_from(tag).is_ok() {
            continue;
        }
        let key = envelope(vec![tag, 0x31]);
        let rejected = without_allocations(|| key.borrowed_parts().unwrap_err());
        drop(key);
        assert_eq!(
            rejected.into_parse_error().to_string(),
            format!("invalid public key algorithm tag {tag}")
        );
    }
    // A present known tag with an empty payload is an envelope, not a valid key.
    let key = compact(Algorithm::Ed25519, &[]);
    let parts = without_allocations(|| key.borrowed_parts().unwrap());
    assert_eq!(parts, (Algorithm::Ed25519, &[][..]));
    let missing = without_allocations(|| crate::public_key_input::payload(&[]).unwrap_err());
    assert_eq!(
        missing.into_parse_error().to_string(),
        "missing public key payload"
    );
    assert!(!std::mem::needs_drop::<PublicKeyEnvelopeError>());
}

#[test]
fn every_enabled_algorithm_verifies_and_rejects_without_cold_thread_allocations() {
    for algorithm in algorithms() {
        let pair = KeyPair::try_from_seed(vec![algorithm as u8 + 0x31; 32], algorithm).unwrap();
        let message = [0x61_u8; 32];
        let proof = Signature::try_new(pair.private_key(), &message).unwrap();
        let key = pair.public_key().clone();
        let wrong = KeyPair::try_from_seed(vec![algorithm as u8 + 0x51; 32], algorithm)
            .unwrap()
            .public_key()
            .clone();
        // Move ready inputs into a fresh OS thread. Its ordinary TLS key and
        // positive-verdict caches have never been consulted or warmed.
        std::thread::Builder::new()
            .name(format!("signature-admission-{algorithm:?}"))
            .spawn(move || {
                without_allocations(|| verify_signature_borrowed(&proof, &key, &message)).unwrap();
                for (candidate, payload) in [(&wrong, &message[..]), (&key, &b"changed"[..])] {
                    let rejected = without_allocations(|| {
                        verify_signature_borrowed(&proof, candidate, payload).unwrap_err()
                    });
                    assert_eq!(rejected.into_error(), Error::BadSignature);
                }
                for bytes in [vec![], vec![0; proof.payload().len()], vec![1; 1]] {
                    let malformed = Signature::from_bytes(&bytes);
                    let rejected = without_allocations(|| {
                        verify_signature_borrowed(&malformed, &key, &message).unwrap_err()
                    });
                    assert_eq!(rejected.into_error(), Error::BadSignature);
                }
                // Error materialization outside the observation must preserve the
                // pre-existing public admission adapter exactly.
                let malformed = compact(algorithm, &[]);
                let expected = crate::verify_signature_for_admission(&proof, &malformed, &message)
                    .unwrap_err();
                let rejected = without_allocations(|| {
                    verify_signature_borrowed(&proof, &malformed, &message).unwrap_err()
                });
                assert_eq!(rejected.into_error(), expected);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

#[test]
fn every_enabled_algorithm_rejects_malformed_keys_before_signature_with_fixed_custody() {
    for algorithm in algorithms() {
        let pair = KeyPair::try_from_seed(vec![algorithm as u8 + 0x22; 32], algorithm).unwrap();
        let (_, bytes) = pair.public_key().to_bytes();
        let length = bytes.len();
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        let cases = [vec![], vec![0; length], vec![0xff; length], trailing];
        let proof = Signature::from_bytes(&[]);
        for bytes in cases {
            let key = compact(algorithm, &bytes);
            let rejected =
                without_allocations(|| verify_signature_borrowed(&proof, &key, b"").unwrap_err());
            let error = rejected.into_error();
            assert_eq!(
                error,
                crate::verify_signature_for_admission(&proof, &key, b"").unwrap_err()
            );
            // The original ML-DSA batch adapter maps key failures to
            // BadSignature. Every other empty key retains its parse failure
            // before the also-invalid empty signature.
            if bytes.is_empty() && algorithm != Algorithm::MlDsa {
                assert!(matches!(error, Error::Parse(_)), "{algorithm:?}: {error}");
            }
        }
    }
}

#[test]
fn fixed_ed25519_and_secp_key_diagnostics_keep_their_original_text() {
    let proof = Signature::from_bytes(&[]);
    for (algorithm, bytes, expected) in [
        (
            Algorithm::Ed25519,
            &[][..],
            "the payload size is incorrect: expected 32, but got 0",
        ),
        (
            Algorithm::Ed25519,
            &[0; 32][..],
            "ed25519 public key material must not be all zero",
        ),
        (
            Algorithm::Secp256k1,
            &[0; 33][..],
            "secp256k1 public key material must not be all zero",
        ),
    ] {
        let key = compact(algorithm, bytes);
        let rejected =
            without_allocations(|| verify_signature_borrowed(&proof, &key, b"").unwrap_err());
        let Error::Parse(reason) = rejected.into_error() else {
            panic!("canonical key error must precede invalid signature")
        };
        assert_eq!(reason.to_string(), expected);
    }
}

#[cfg(not(feature = "pqc"))]
#[test]
fn mldsa_without_compiled_verifier_preserves_fixed_unsupported_implementation() {
    let key = compact(Algorithm::MlDsa, &[1; crate::ML_DSA_65_PUBLIC_KEY_BYTES]);
    let proof = Signature::from_bytes(&[]);
    let rejected =
        without_allocations(|| verify_signature_borrowed(&proof, &key, b"").unwrap_err());
    let expected = UnsupportedImplementation {
        algorithm: Algorithm::MlDsa,
        operation: crate::CryptoOperation::VerifySignature,
    };
    assert_eq!(rejected.unsupported_implementation(), Some(expected));
    assert_eq!(
        without_allocations(|| rejected.into_error()),
        Error::UnsupportedImplementation(expected)
    );
}

/// Environment selector that routes a fresh test process into its child case.
const COLD_CHILD_SENTINEL: &str = "IROHA_CRYPTO_FIXED_ADMISSION_CHILD";

/// Receipt printed by a child only after its observed relation allocated nothing.
fn cold_receipt(algorithm: Algorithm, mode: &str) -> String {
    format!(
        "FIXED_ADMISSION_COLD_RECEIPT algorithm={} case={mode} rust_allocation_requests=0",
        algorithm as u8
    )
}

/// Child side: run the one environment-selected case in this fresh process.
fn run_cold_admission_child() {
    // Only public bytes cross this test-only subprocess boundary. Building
    // the raw retained inputs does not call a key parser or signature backend.
    let algorithm = Algorithm::try_from(
        std::env::var("IROHA_CRYPTO_FIXED_ALGORITHM")
            .unwrap()
            .parse::<u8>()
            .unwrap(),
    )
    .unwrap();
    let bytes = hex::decode(std::env::var("IROHA_CRYPTO_FIXED_PUBLIC_KEY").unwrap()).unwrap();
    let signature = hex::decode(std::env::var("IROHA_CRYPTO_FIXED_SIGNATURE").unwrap()).unwrap();
    let mode = std::env::var("IROHA_CRYPTO_FIXED_CASE").unwrap();
    let key = compact(algorithm, &bytes);
    let proof = Signature::from_bytes(&signature);
    let message = [0x61_u8; 32];
    match mode.as_str() {
        "valid" => {
            without_allocations(|| verify_signature_borrowed(&proof, &key, &message)).unwrap();
        }
        "key" | "short-key" => {
            let damaged = if mode == "key" {
                vec![0; bytes.len()]
            } else {
                bytes[..bytes.len() - 1].to_vec()
            };
            let malformed = compact(algorithm, &damaged);
            let rejected = without_allocations(|| {
                verify_signature_borrowed(&proof, &malformed, &message).unwrap_err()
            });
            if algorithm == Algorithm::MlDsa {
                assert_eq!(rejected.into_error(), Error::BadSignature);
            } else {
                assert!(matches!(rejected.into_error(), Error::Parse(_)));
            }
        }
        "signature" => {
            let malformed = Signature::from_bytes(&vec![0; signature.len()]);
            let rejected = without_allocations(|| {
                verify_signature_borrowed(&malformed, &key, &message).unwrap_err()
            });
            assert_eq!(rejected.into_error(), Error::BadSignature);
        }
        _ => panic!("unexpected cold-process control"),
    }
    println!("{}", cold_receipt(algorithm, &mode));
}

/// Parent side: run one case in a fresh test process and require its exact receipt.
fn assert_cold_admission_child(
    selector: &str,
    algorithm: Algorithm,
    bytes: &[u8],
    proof: &Signature,
    mode: &str,
) {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env(COLD_CHILD_SENTINEL, selector)
        .env(
            "IROHA_CRYPTO_FIXED_ALGORITHM",
            (algorithm as u8).to_string(),
        )
        .env("IROHA_CRYPTO_FIXED_PUBLIC_KEY", hex::encode(bytes))
        .env("IROHA_CRYPTO_FIXED_SIGNATURE", hex::encode(proof.payload()))
        .env("IROHA_CRYPTO_FIXED_CASE", mode)
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&child.stdout);
    assert!(
        child.status.success(),
        "{algorithm:?}/{mode}: {output}\n{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
            .count(),
        1,
        "child must run exactly the one selected test: {output}"
    );
    let receipt = cold_receipt(algorithm, mode);
    assert_eq!(
        output.matches(&receipt).count(),
        1,
        "actual cold relation receipt required: {output}"
    );
    println!("{receipt}");
}

#[test]
fn every_enabled_algorithm_has_cold_process_valid_key_and_signature_controls() {
    let module = module_path!().split_once("::").unwrap().1;
    let selector = format!(
        "{module}::every_enabled_algorithm_has_cold_process_valid_key_and_signature_controls"
    );
    if std::env::var(COLD_CHILD_SENTINEL).ok().as_deref() == Some(selector.as_str()) {
        run_cold_admission_child();
        return;
    }
    assert!(
        std::env::var_os(COLD_CHILD_SENTINEL).is_none(),
        "unknown child selector must not alter routing"
    );
    for algorithm in algorithms() {
        let pair = KeyPair::try_from_seed(vec![algorithm as u8 + 0x18; 32], algorithm).unwrap();
        let proof = Signature::try_new(pair.private_key(), &[0x61; 32]).unwrap();
        let (_, bytes) = pair.public_key().to_bytes();
        for mode in ["valid", "key", "short-key", "signature"] {
            assert_cold_admission_child(&selector, algorithm, bytes, &proof, mode);
        }
    }
}

#[cfg(feature = "bls")]
#[test]
fn borrowed_pop_keeps_no_cache_owner_on_cold_or_warm_verification() {
    let pair = KeyPair::from_seed(
        b"borrowed-pop-cold-cache-owner-case".to_vec(),
        Algorithm::BlsNormal,
    );
    let proof = crate::bls_normal_pop_prove(pair.private_key()).unwrap();
    let public_key = pair.public_key();
    let (_, payload) = public_key.borrowed_parts().unwrap();
    assert!(!crate::bls_pop_cache().lock().unwrap().contains(
        Algorithm::BlsNormal,
        payload,
        &proof
    ));
    without_allocations(|| verify_bls_normal_pop_borrowed(public_key, &proof)).unwrap();
    assert!(!crate::bls_pop_cache().lock().unwrap().contains(
        Algorithm::BlsNormal,
        payload,
        &proof
    ));
    // Warm the ordinary cache deliberately, then verify the same relation without
    // allocating or depending on that separately owned cache entry.
    crate::bls_normal_pop_verify(public_key, &proof).unwrap();
    assert!(
        crate::bls_pop_cache()
            .lock()
            .unwrap()
            .contains(Algorithm::BlsNormal, payload, &proof)
    );
    without_allocations(|| verify_bls_normal_pop_borrowed(public_key, &proof)).unwrap();
}

#[cfg(feature = "bls")]
#[test]
fn borrowed_pop_preserves_exact_typed_diagnostics_for_malformed_inputs() {
    let pair = KeyPair::from_seed(
        b"borrowed-pop-parser-parity-case".to_vec(),
        Algorithm::BlsNormal,
    );
    let proof = crate::bls_normal_pop_prove(pair.private_key()).unwrap();
    let mut identity = vec![0_u8; 96];
    identity[0] = 0xc0;
    let mut extended = proof.clone();
    extended.push(0);
    let mut changed = proof.clone();
    changed[20] ^= 1;
    let proofs = [
        proof.clone(),
        vec![],
        proof[..95].to_vec(),
        vec![0; 96],
        vec![0xff; 96],
        identity,
        extended,
        changed,
    ];
    let wrong_algorithm =
        KeyPair::from_seed(b"borrowed-pop-wrong-algorithm".to_vec(), Algorithm::Ed25519);
    let keys = [
        pair.public_key().clone(),
        compact(Algorithm::BlsNormal, &[]),
        compact(Algorithm::BlsNormal, &[0; 48]),
        compact(Algorithm::BlsNormal, &[0xff; 48]),
        envelope(vec![]),
        envelope(vec![0xff]),
        wrong_algorithm.public_key().clone(),
    ];
    for key in &keys {
        for proof in &proofs {
            let expected =
                crate::bls_normal_pop_verify(key, proof).map_err(|error| error.to_string());
            let observed = without_allocations(|| verify_bls_normal_pop_borrowed(key, proof))
                .map_err(|error| error.into_error().to_string());
            assert_eq!(observed, expected);
        }
    }
    let foreign = KeyPair::from_seed(
        b"borrowed-pop-foreign-identity".to_vec(),
        Algorithm::BlsNormal,
    );
    let rejected =
        without_allocations(|| verify_bls_normal_pop_borrowed(foreign.public_key(), &proof));
    assert_eq!(
        rejected.unwrap_err().into_error().to_string(),
        crate::Error::BadSignature.to_string()
    );
}

#[cfg(feature = "bls")]
#[test]
fn owned_pop_credential_moves_original_backing_and_returns_it_on_rejection() {
    let pair = KeyPair::from_seed(
        b"owned-pop-credential-source-case".to_vec(),
        Algorithm::BlsNormal,
    );
    let proof = crate::bls_normal_pop_prove(pair.private_key()).unwrap();
    let owned = pair.public_key().clone();
    let original = owned.borrowed_parts().unwrap().1.as_ptr();
    let credential =
        without_allocations(|| crate::BlsNormalPopVerifiedKey::from_owned_uncached(owned, &proof))
            .unwrap();
    assert_eq!(credential.payload().as_ptr(), original);
    assert_eq!(credential.public_key(), pair.public_key());
    let ordinary = crate::BlsNormalPopVerifiedKey::new(pair.public_key(), &proof).unwrap();
    assert_eq!(credential, ordinary);
    assert!(without_allocations(
        || credential.proof_of_possession_matches(&proof)
    ));
    assert!(without_allocations(
        || ordinary.proof_of_possession_matches(&proof)
    ));
    let cloned = credential.clone();
    assert!(without_allocations(
        || cloned.proof_of_possession_matches(&proof)
    ));
    let mut changed = proof.clone();
    changed[17] ^= 1;
    for other in [&[][..], &proof[..95], changed.as_slice()] {
        assert!(!without_allocations(
            || credential.proof_of_possession_matches(other)
        ));
        assert!(!without_allocations(
            || ordinary.proof_of_possession_matches(other)
        ));
    }

    let owned = pair.public_key().clone();
    let original = owned.borrowed_parts().unwrap().1.as_ptr();
    let (returned, rejection) =
        without_allocations(|| crate::BlsNormalPopVerifiedKey::from_owned_uncached(owned, &[]))
            .unwrap_err();
    assert_eq!(returned.borrowed_parts().unwrap().1.as_ptr(), original);
    assert_eq!(&returned, pair.public_key());
    let expected = crate::bls_normal_pop_verify(&returned, &[])
        .unwrap_err()
        .to_string();
    drop(returned);
    assert_eq!(rejection.into_error().to_string(), expected);
}

#[cfg(feature = "bls")]
#[test]
fn borrowed_normal_wire_signature_preserves_facade_verdicts_without_owners_or_caches() {
    let pair = KeyPair::from_seed(
        b"borrowed-normal-wire-verdict".to_vec(),
        Algorithm::BlsNormal,
    );
    let message = b"original normal contextual message";
    let signature = Signature::new(pair.private_key(), message);
    let valid = pair.public_key().borrowed_parts().unwrap().1;
    let mut identity = [0; 48];
    identity[0] = 0xc0;
    for key in [
        valid,
        &valid[..47],
        &[][..],
        &[0; 48],
        &[0xff; 48],
        &identity,
    ] {
        let key_owner = compact(Algorithm::BlsNormal, key);
        for proof in [
            signature.payload(),
            &signature.payload()[..95],
            &[][..],
            &[0; 96],
            &[0xff; 96],
        ] {
            let signature_owner = Signature::from_bytes(proof);
            for message in [message.as_slice(), b"substituted".as_slice()] {
                let expected = signature_owner
                    .verify(&key_owner, message)
                    .map_err(|error| error.to_string());
                let actual = without_allocations(|| {
                    verify_bls_normal_signature_borrowed(key, proof, message)
                })
                .map_err(|error| error.into_error().to_string());
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn raw_ed25519_admission_matches_strict_relation_without_allocations() {
    use curve25519_dalek::{constants::EIGHT_TORSION, scalar::Scalar};
    let message = b"TON original source proof";
    for seed in 1..=4 {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        let key: [u8; 32] = pair.public_key().to_bytes().1.try_into().unwrap();
        let signature: [u8; 64] = Signature::new(pair.private_key(), message)
            .payload()
            .try_into()
            .unwrap();
        let mut candidates = vec![signature, [0; 64], [0xff; 64]];
        for index in 0..64 {
            let mut changed = signature;
            changed[index] ^= 0x80;
            candidates.push(changed);
        }
        // Noncanonical scalar, small-order R and non-prime-order R are all rejected.
        let mut changed = signature;
        changed[32..].fill(0xff);
        candidates.push(changed);
        for torsion in &EIGHT_TORSION {
            let mut changed = signature;
            changed[..32].copy_from_slice(torsion.compress().as_bytes());
            candidates.push(changed);
            let mut changed = signature;
            changed[..32].copy_from_slice(
                &(curve25519_dalek::constants::ED25519_BASEPOINT_POINT * Scalar::from(7_u64)
                    + torsion)
                    .compress()
                    .to_bytes(),
            );
            candidates.push(changed);
        }
        let mut keys = vec![key, [0; 32], [0xff; 32]];
        keys.extend(
            EIGHT_TORSION
                .iter()
                .map(|point| point.compress().to_bytes()),
        );
        keys.extend(EIGHT_TORSION.iter().skip(1).map(|torsion| {
            (curve25519_dalek::constants::ED25519_BASEPOINT_POINT + torsion)
                .compress()
                .to_bytes()
        }));
        for key in keys {
            for signature in &candidates {
                for input in [message.as_slice(), b"changed message".as_slice()] {
                    let expected =
                        ed25519::Ed25519Sha512::parse_public_key_uncached_for_decode(&key)
                            .is_ok_and(|parsed| {
                                ed25519::Ed25519Sha512::verify_uncached(input, signature, &parsed)
                                    .is_ok()
                            });
                    let observed = without_allocations(|| {
                        verify_ed25519_signature_borrowed(&key, signature, input)
                    });
                    assert_eq!(observed.is_ok(), expected);
                    if key == pair.public_key().to_bytes().1
                        && signature == &candidates[0]
                        && input == message
                    {
                        assert!(observed.is_ok());
                    }
                }
            }
        }
    }
}
