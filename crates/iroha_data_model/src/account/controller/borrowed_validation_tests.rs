//! Borrowed multisig validation preserves canonical causes and original key storage.

use super::*;
use iroha_crypto::KeyPair;

fn key(seed: u8, algorithm: Algorithm) -> PublicKey {
    KeyPair::try_from_seed(vec![seed; 32], algorithm)
        .expect("deterministic member key")
        .into_parts()
        .0
}

#[test]
fn borrowed_member_validation_preserves_constructor_causes_and_original_key() {
    for (seed, algorithm) in [(0x61, Algorithm::Ed25519), (0x62, Algorithm::Secp256k1)] {
        let public_key = key(seed, algorithm);
        let original = public_key.clone();
        let address = public_key.to_bytes().1.as_ptr();
        for weight in [0, 1, u16::MAX] {
            let expected = if weight == 0 {
                Err(MultisigPolicyError::MemberWeightZero)
            } else {
                Ok(())
            };
            for _ in 0..2 {
                assert_eq!(
                    MultisigMember::validate_components(&public_key, weight),
                    expected
                );
                assert_eq!(
                    MultisigMember::new(public_key.clone(), weight).map(|_| ()),
                    expected
                );
                assert_eq!(public_key, original);
                assert_eq!(public_key.to_bytes().1.as_ptr(), address);
            }
        }
        let mut malformed = public_key;
        malformed.zeroize_for_confidential_discard();
        let original = malformed.clone();
        for (weight, expected) in [
            (0, MultisigPolicyError::MemberWeightZero),
            (1, MultisigPolicyError::MalformedPublicKey),
        ] {
            assert_eq!(
                MultisigMember::validate_components(&malformed, weight),
                Err(expected)
            );
            assert_eq!(
                MultisigMember::new(malformed.clone(), weight).unwrap_err(),
                expected
            );
            assert_eq!(malformed, original);
        }
    }
}

#[test]
fn borrowed_policy_validation_preserves_canonical_causes_and_member_storage() {
    let policy = MultisigPolicy::new(
        2,
        vec![
            MultisigMember::new(key(0x71, Algorithm::Ed25519), 1).unwrap(),
            MultisigMember::new(key(0x72, Algorithm::Ed25519), 2).unwrap(),
        ],
    )
    .unwrap();
    let members = policy.members();
    let mut reversed = members.to_vec();
    reversed.reverse();
    let duplicates = vec![members[0].clone(), members[0].clone()];
    let mut zero_weight = members.to_vec();
    zero_weight[0].weight = 0;
    let mut malformed = members.to_vec();
    malformed[0].public_key.zeroize_for_confidential_discard();
    let cases = [
        (1, 2, members.to_vec(), Ok(())),
        (
            2,
            0,
            Vec::new(),
            Err(MultisigPolicyError::UnsupportedVersion(2)),
        ),
        (1, 0, Vec::new(), Err(MultisigPolicyError::EmptyMembers)),
        (
            1,
            0,
            members.to_vec(),
            Err(MultisigPolicyError::ZeroThreshold),
        ),
        (
            1,
            4,
            members.to_vec(),
            Err(MultisigPolicyError::ThresholdExceedsTotal {
                threshold: 4,
                total_weight: 3,
            }),
        ),
        (
            1,
            2,
            reversed,
            Err(MultisigPolicyError::NonCanonicalMemberOrder),
        ),
        (1, 1, duplicates, Err(MultisigPolicyError::DuplicateMember)),
        (
            1,
            1,
            zero_weight,
            Err(MultisigPolicyError::MemberWeightZero),
        ),
        (
            1,
            1,
            malformed,
            Err(MultisigPolicyError::MalformedPublicKey),
        ),
    ];
    for (version, threshold, original, expected) in cases {
        let copy = original.clone();
        let address = original.as_ptr();
        for _ in 0..2 {
            assert_eq!(
                MultisigPolicy::validate_canonical_members(
                    version,
                    threshold,
                    original
                        .iter()
                        .map(|member| (member.public_key(), member.weight()))
                ),
                expected
            );
            assert_eq!(
                MultisigPolicy::from_serialized(version, threshold, original.clone()).map(|_| ()),
                expected
            );
            assert_eq!(original, copy);
            assert_eq!(original.as_ptr(), address);
        }
    }
    // The borrowed canonical owner rejects the advertised count before inspecting
    // any member or allocating a parallel Vec of the over-limit input.
    let excessive = usize::from(u16::MAX) + 1;
    assert_eq!(
        MultisigPolicy::validate_canonical_members(
            1,
            1,
            std::iter::repeat_n((members[0].public_key(), 1), excessive)
        ),
        Err(MultisigPolicyError::TooManyMembers(excessive)),
    );
}
