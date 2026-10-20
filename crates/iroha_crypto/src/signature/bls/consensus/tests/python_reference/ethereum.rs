//! Imported Ethereum v0.1.2 rows and their explicit consensus API outcomes.
//!
//! The source JSON remains unchanged in the fixture. Consensus admission additionally
//! excludes identity keys/signatures, and fixed-size arguments exclude malformed lengths.
//! Batch verification has no consensus batch API: every member is checked individually.
//! The generic hash-to-G2 suite uses its recorded DST and arbitrary UTF-8 messages;
//! consensus hash-to-G2 over a 32-byte digest is covered separately by the parent module.

use super::*;

const GROUP_COUNTS: [(&str, usize); 9] = [
    ("aggregate", 6),
    ("aggregate_verify", 5),
    ("batch_verify", 4),
    ("deserialization_G1", 13),
    ("deserialization_G2", 15),
    ("fast_aggregate_verify", 12),
    ("hash_to_G2", 4),
    ("sign", 10),
    ("verify", 29),
];

fn imported(reference: &Value) -> &Value {
    field(reference, "ethereum_bls12_381_tests")
}

fn group<'a>(reference: &'a Value, name: &str) -> &'a [Value] {
    rows(field(imported(reference), "groups"), name)
}

/// Upstream deserialization inputs omit `0x`; the other suites include it.
fn upstream_bytes(value: &str) -> Vec<u8> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).expect("upstream hex")
}

/// Refuse malformed lengths at the fixed-size consensus API boundary.
fn upstream_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    upstream_bytes(value).try_into().ok()
}

fn ethereum_keys() -> Vec<(PrivateKey, [u8; 48], BlsNormalPopVerifiedKey)> {
    (0..SECRET_KEYS.len())
        .map(|index| {
            let private = private_key(index);
            let public = bytes::<48>(PUBLIC_KEYS[index]);
            let admission = admitted(&private);
            (private, public, admission)
        })
        .collect()
}

#[test]
fn imported_suite_has_every_pinned_row() {
    let reference = reference();
    let groups = field(imported(&reference), "groups")
        .as_object()
        .expect("upstream groups");
    assert_eq!(groups.len(), GROUP_COUNTS.len());
    let mut count = 0;
    for (name, expected) in GROUP_COUNTS {
        let cases = group(&reference, name);
        assert_eq!(cases.len(), expected, "{name}");
        let labels: BTreeSet<_> = cases.iter().map(label).collect();
        assert_eq!(labels.len(), expected, "duplicate labels in {name}");
        assert!(!labels.contains(""), "missing label in {name}");
        for row in cases {
            assert_eq!(
                std::path::Path::new(string(row, "source_file")).extension(),
                Some(std::ffi::OsStr::new("json"))
            );
            field(row, "input");
            field(row, "output");
        }
        count += cases.len();
    }
    assert_eq!(count, 98);
}

#[test]
fn reproduces_imported_deserialization_and_consensus_admission() {
    let reference = reference();
    for row in group(&reference, "deserialization_G1") {
        let input = field(row, "input");
        let bytes = upstream_fixed::<48>(string(input, "pubkey"));
        let decoded = bytes.and_then(|bytes| G1Affine::from_compressed(&bytes).into_option());
        assert_eq!(decoded.is_some(), boolean(row, "output"), "{}", label(row));
        let expected = boolean(row, "output") && bytes != Some(identity_key());
        assert_eq!(boolean(row, "validate"), expected, "{}", label(row));
        assert_eq!(
            bytes.is_some_and(|bytes| key_validate(&bytes)),
            expected,
            "{}",
            label(row)
        );
    }
    for row in group(&reference, "deserialization_G2") {
        let input = field(row, "input");
        let bytes = upstream_fixed::<96>(string(input, "signature"));
        let decoded = bytes.and_then(|bytes| G2Affine::from_compressed(&bytes).into_option());
        assert_eq!(decoded.is_some(), boolean(row, "output"), "{}", label(row));
        // Generic decoding accepts canonical infinity; no consensus signature may be it.
        let expected = boolean(row, "output") && bytes != Some(identity_signature());
        assert_eq!(boolean(row, "validate"), expected, "{}", label(row));
        assert_eq!(
            bytes.is_some_and(|bytes| parse_signature(&bytes).is_some()),
            expected,
            "{}",
            label(row)
        );
    }
}

#[test]
fn reproduces_imported_sign() {
    let reference = reference();
    for row in group(&reference, "sign") {
        let input = field(row, "input");
        let mut scalar = fixed::<32>(string(input, "privkey"));
        scalar.reverse();
        let key = PrivateKey::from_bytes(Algorithm::BlsNormal, &scalar);
        let Some(output) = field(row, "output").as_str() else {
            assert_eq!(scalar, [0; 32], "{}", label(row));
            assert!(
                key.is_err(),
                "{}: zero secret must not enter Sign",
                label(row)
            );
            continue;
        };
        let key = key.expect("upstream nonzero key");
        let digest = raw_digest(string(input, "message"));
        let signature = sign(&key, &digest).expect("consensus Sign");
        assert_eq!(signature, fixed::<96>(output), "{}", label(row));
        assert!(
            verify(&admitted(&key), &digest, &signature),
            "{}",
            label(row)
        );
    }
}

#[test]
fn reproduces_imported_verify() {
    let reference = reference();
    let mut scratch = ConsensusAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    for row in group(&reference, "verify") {
        let input = field(row, "input");
        let public = fixed::<48>(string(input, "pubkey"));
        let signature = fixed::<96>(string(input, "signature"));
        let digest = raw_digest(string(input, "message"));
        let expected = boolean(row, "output");
        assert_eq!(boolean(row, "consensus_output"), expected, "{}", label(row));
        assert_eq!(
            verify_public_key(&public, &digest, &signature),
            expected,
            "{}",
            label(row)
        );
        assert_eq!(
            verify_fast_aggregate_committed(&[public], &digest, &signature),
            expected,
            "{}",
            label(row)
        );
        assert_eq!(
            scratch.verify_fast_aggregate_committed(&[public], &digest, &signature),
            expected,
            "{} admitted scratch",
            label(row)
        );
    }
}

#[test]
fn reproduces_imported_fast_aggregate_verify() {
    let reference = reference();
    let keys = ethereum_keys();
    let mut scratch = ConsensusAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    for row in group(&reference, "fast_aggregate_verify") {
        let input = field(row, "input");
        let public = fixed_list::<48>(input, "pubkeys");
        let signature = fixed::<96>(string(input, "signature"));
        let digest = raw_digest(string(input, "message"));
        let expected = boolean(row, "output");
        assert_eq!(boolean(row, "consensus_output"), expected, "{}", label(row));
        assert_eq!(
            verify_fast_aggregate_committed(&public, &digest, &signature),
            expected,
            "{}",
            label(row)
        );
        assert_eq!(
            scratch.verify_fast_aggregate_committed(&public, &digest, &signature),
            expected,
            "{} admitted scratch",
            label(row)
        );
        // The admitted-key API rejects duplicate membership; the committed-key API above
        // relies on the authenticated committee's ordering to exclude it.
        let admitted: Option<Vec<_>> = public
            .iter()
            .map(|key| {
                keys.iter()
                    .find(|(_, candidate, _)| candidate == key)
                    .map(|(_, _, admission)| admission)
            })
            .collect();
        if let Some(admitted) = admitted {
            assert_eq!(
                scratch.verify_fast_aggregate(admitted.iter().copied(), &digest, &signature),
                expected,
                "{} admitted scratch",
                label(row)
            );
            assert_eq!(
                verify_fast_aggregate(&admitted, &digest, &signature),
                expected,
                "{}",
                label(row)
            );
        } else {
            assert!(!expected, "{}", label(row));
            assert!(
                public.iter().any(|key| !key_validate(key)),
                "{}",
                label(row)
            );
        }
    }
}

#[test]
fn reproduces_imported_aggregate_with_consensus_identity_refusal() {
    let reference = reference();
    for row in group(&reference, "aggregate") {
        let shares: Vec<[u8; 96]> = field(row, "input")
            .as_array()
            .expect("upstream shares")
            .iter()
            .map(|share| fixed(share.as_str().expect("upstream signature")))
            .collect();
        let expected = field(row, "output").as_str().map(fixed::<96>);
        // The generic Aggregate operation preserves infinity. Consensus shares and their
        // sum must be nonidentity, so this one upstream output has an explicit refusal.
        let consensus_expected = expected.filter(|value| *value != identity_signature());
        assert_eq!(
            aggregate(&shares).ok(),
            consensus_expected,
            "{}",
            label(row)
        );
        if expected == Some(identity_signature()) {
            assert_eq!(shares, [identity_signature()], "{}", label(row));
        }
    }
}

#[test]
fn reproduces_imported_aggregate_verify() {
    let reference = reference();
    let keys = ethereum_keys();
    let mut scratch = ConsensusAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    for row in group(&reference, "aggregate_verify") {
        let input = field(row, "input");
        let public = fixed_list::<48>(input, "pubkeys");
        let messages = fixed_list::<32>(input, "messages");
        assert_eq!(public.len(), messages.len(), "{}", label(row));
        let expected = boolean(row, "output");
        assert_eq!(boolean(row, "consensus_output"), expected, "{}", label(row));
        let all_keys_valid = public.iter().all(key_validate);
        let Some(signature) = upstream_fixed::<96>(string(input, "signature")) else {
            assert!(
                !expected,
                "{}: malformed length cannot enter the API",
                label(row)
            );
            continue;
        };
        if !all_keys_valid {
            assert!(
                !expected,
                "{}: key fails KeyValidate before PoP admission",
                label(row)
            );
            continue;
        }
        let admitted: Vec<[&BlsNormalPopVerifiedKey; 1]> = public
            .iter()
            .map(|key| [admitted_subset(&keys, &[*key]).expect("upstream key with known PoP")[0]])
            .collect();
        let paired: Vec<(&[&BlsNormalPopVerifiedKey], ConsensusDigest)> = admitted
            .iter()
            .zip(messages)
            .map(|(keys, message)| (keys.as_slice(), ConsensusDigest::from_raw_for_test(message)))
            .collect();
        assert_eq!(
            verify_aggregate_multi(&paired, &signature),
            expected,
            "{}",
            label(row)
        );
        assert_eq!(
            scratch.verify_aggregate_multi(
                paired
                    .iter()
                    .map(|(keys, digest)| (keys.iter().copied(), *digest)),
                &signature
            ),
            expected,
            "{} admitted scratch",
            label(row)
        );
    }
}

#[test]
fn reproduces_imported_batch_verify_as_individual_consensus_checks() {
    let reference = reference();
    for row in group(&reference, "batch_verify") {
        let input = field(row, "input");
        let public = fixed_list::<48>(input, "pubkeys");
        let messages = fixed_list::<32>(input, "messages");
        let signatures = fixed_list::<96>(input, "signatures");
        assert_eq!(public.len(), messages.len(), "{}", label(row));
        assert_eq!(public.len(), signatures.len(), "{}", label(row));
        // Evaluate every relation, including the forged-pair cancellation fixture; summing
        // signatures first would incorrectly accept that fixture.
        let outcomes: Vec<bool> = public
            .iter()
            .zip(messages)
            .zip(signatures)
            .map(|((key, message), signature)| {
                verify_public_key(
                    key,
                    &ConsensusDigest::from_raw_for_test(message),
                    &signature,
                )
            })
            .collect();
        assert_eq!(
            outcomes.iter().all(|outcome| *outcome),
            boolean(row, "output"),
            "{}",
            label(row)
        );
    }
}

#[test]
fn reproduces_imported_hash_to_g2_coordinates() {
    let reference = reference();
    for row in group(&reference, "hash_to_G2") {
        let input = field(row, "input");
        let output = field(row, "output");
        let point = G2Projective::hash_to_curve(
            string(input, "msg").as_bytes(),
            string(row, "dst").as_bytes(),
            &[],
        )
        .to_affine();
        let expected: Vec<u8> = ["x", "y"]
            .into_iter()
            .flat_map(|coordinate| {
                let components: Vec<_> = string(output, coordinate)
                    .split(',')
                    .map(fixed::<48>)
                    .collect();
                assert_eq!(components.len(), 2, "{}", label(row));
                // Zcash uncompressed points encode each Fp2 value as imaginary || real;
                // upstream coordinate pairs are real, imaginary.
                components.into_iter().rev()
            })
            .flatten()
            .collect();
        assert_eq!(
            point.to_uncompressed().as_slice(),
            expected,
            "{}",
            label(row)
        );
        assert_eq!(
            point.to_compressed(),
            fixed::<96>(string(field(row, "point"), "compressed")),
            "{}",
            label(row)
        );
    }
}
