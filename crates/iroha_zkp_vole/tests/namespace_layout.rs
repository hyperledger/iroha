//! The byte layout of every namespaced oracle call, recomputed with the
//! independent `sha3` crate for the table "Transcript binding" in section 6.3 of
//! `specs/parliament_ballot_proof_profile.md`: SHAKE256 over a 77-byte prefix, the
//! body, and one suffix byte, on the FAEST-256f row.
//!
//! Each call is checked in isolation (its inputs are fixed bytes, not outputs of
//! other namespaced calls), so a call site that dropped the prefix, reordered its
//! body or changed its suffix or output length fails here by itself.

use iroha_zkp_vole::{
    bavc::{self, commit_in, leaf_commit, position_in_tree},
    hash::{Hasher, Namespace, Oracle, h5_in},
    params::{FAEST_256F, ProofParams, SecurityLevel},
    randomness::Tape,
    transcript::{Challenge3, challenge_1, challenge_2, derive_iv, message_digest},
    vole::{corrections_bytes, mult_corrections_bytes},
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const LEVEL: SecurityLevel = SecurityLevel::L256;

fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut sponge = Shake256::default();
    parts.iter().for_each(|part| sponge.update(part));
    sponge.finalize_xof().read(&mut out);
    out
}

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|at| u8::try_from(at % 253).expect("below 253").wrapping_mul(41) ^ salt)
        .collect()
}

/// `ASCII("PARL/FAEST/v1") || 64 bytes`, the shape of `PREFIX_R`.
fn prefix(role: u8) -> Vec<u8> {
    let mut prefix = b"PARL/FAEST/v1".to_vec();
    prefix.extend(pattern(64, role));
    assert_eq!(prefix.len(), 77);
    prefix
}

/// The two role prefixes and the empty one: the outputs of each call must be
/// pairwise different.
fn for_each_prefix(mut check: impl FnMut(&[u8], Namespace<'_>) -> Vec<u8>) {
    let (first, second) = (prefix(1), prefix(2));
    let mut outputs: Vec<Vec<u8>> = [&first[..], &second, b""]
        .into_iter()
        .map(|bytes| check(bytes, Namespace::new(bytes).expect("bounded")))
        .collect();
    outputs.sort();
    outputs.dedup();
    assert_eq!(outputs.len(), 3, "every prefix gives a different output");
}

#[test]
fn mu_is_prefix_statement_08_with_64_output_bytes() {
    let statement = pattern(300, 3);
    for_each_prefix(|bytes, namespace| {
        let mu = message_digest(namespace, LEVEL, &[&statement]).expect("valid call");
        assert_eq!(mu, shake256(&[bytes, &statement, &[0x08]], 64));
        mu
    });
}

#[test]
fn h4_is_prefix_iv_pre_mu_04_with_16_output_bytes() {
    let iv_pre: [u8; 16] = pattern(16, 4).try_into().expect("16 bytes");
    let mu = pattern(64, 5);
    for_each_prefix(|bytes, namespace| {
        let iv = derive_iv(namespace, LEVEL, &iv_pre, &mu).expect("valid call");
        assert_eq!(iv[..], shake256(&[bytes, &iv_pre, &mu, &[0x04]], 16)[..]);
        iv.to_vec()
    });
}

#[test]
fn h3_is_prefix_secret_mu_rho_03_with_48_output_bytes() {
    // Ballot proving makes no H_3 call; reference mode does, and the oracle takes
    // the prefix like every other.
    let (secret, mu, rho) = (pattern(32, 6), pattern(64, 7), pattern(16, 8));
    for_each_prefix(|bytes, namespace| {
        let tape = Tape::derive(namespace, LEVEL, &secret, &mu, &rho).expect("valid call");
        let expected = shake256(&[bytes, &secret, &mu, &rho, &[0x03]], 48);
        assert_eq!(tape.root(), &expected[..32]);
        assert_eq!(tape.iv_pre()[..], expected[32..]);
        expected
    });
}

#[test]
fn h0_and_both_levels_of_h1_are_prefix_body_suffix() {
    let vole = FAEST_256F.vole();
    let iv: [u8; 16] = pattern(16, 9).try_into().expect("16 bytes");
    let root = pattern(32, 10);
    let tau = vole.tau();
    for_each_prefix(|bytes, namespace| {
        let commitment = commit_in(namespace, vole, &root, &iv).expect("valid call");
        let keys = commitment.node_keys();
        // H_0: prefix || iv || 00, 96 bytes.
        let uhash = shake256(&[bytes, &iv, &[0x00]], 96);
        // Inner H_1 of vector i: prefix || its leaf commitments in increasing leaf
        // order || 01, 64 bytes.
        let mut digests = Vec::new();
        for vector in 0..tau {
            let mut leaves = Vec::new();
            for index in 0..vole.leaves_of(vector).expect("vector below tau") {
                let node = position_in_tree(vole, vector, index).expect("valid leaf");
                let (mut sd, mut com) = ([0u8; 32], [0u8; 96]);
                let tweak = u32::try_from(vole.leaves() - 1 + vector).expect("small");
                leaf_commit(
                    vole,
                    &keys[32 * node..32 * (node + 1)],
                    &iv,
                    tweak,
                    &uhash,
                    &mut sd,
                    &mut com,
                )
                .expect("valid call");
                leaves.extend_from_slice(&com);
            }
            digests.extend(shake256(&[bytes, &leaves, &[0x01]], 64));
        }
        // Outer H_1: prefix || the vector digests in increasing vector order || 01.
        assert_eq!(digests.len(), 64 * tau);
        let expected = shake256(&[bytes, &digests, &[0x01]], 64);
        assert_eq!(commitment.commitment(), expected);
        assert_eq!(bavc::decommitment_bytes(vole), 10_496);
        expected
    });
}

#[test]
fn the_three_challenges_are_prefix_body_suffix() {
    // The registration witness length of the profile.
    let params = ProofParams::new(*FAEST_256F.vole(), 35_840, 72_576).expect("valid row");
    let vole = params.vole();
    let mu = pattern(64, 11);
    let com = pattern(64, 12);
    let corrections = pattern(corrections_bytes(&params), 13);
    let mult = pattern(mult_corrections_bytes(vole), 14);
    assert_eq!((corrections.len(), mult.len()), (143_360, 880));
    let iv_pre: [u8; 16] = pattern(16, 15).try_into().expect("16 bytes");
    for_each_prefix(|bytes, namespace| {
        let first = challenge_1(namespace, &params, &mu, &com, &corrections, &mult, &iv_pre)
            .expect("valid call");
        assert_eq!(
            first,
            shake256(
                &[bytes, &mu, &com, &corrections, &mult, &iv_pre, &[0x09]],
                264
            )
        );
        first
    });

    let chall_1 = pattern(264, 16);
    let (u_tilde, v_tilde) = (pattern(128, 17), pattern(128, 18));
    let d = pattern(4480, 19);
    for_each_prefix(|bytes, namespace| {
        let second =
            challenge_2(namespace, &params, &chall_1, &u_tilde, &v_tilde, &d).expect("valid call");
        assert_eq!(
            second,
            shake256(&[bytes, &chall_1, &u_tilde, &v_tilde, &d, &[0x0a]], 104)
        );
        second
    });

    let chall_2 = pattern(104, 20);
    let coefficients = pattern(7 * 32, 21);
    for_each_prefix(|bytes, namespace| {
        let grinder =
            Challenge3::new(namespace, vole, &chall_2, &coefficients).expect("valid call");
        let mut third = [0u8; 32];
        for counter in [0u32, 0x0403_0201, u32::MAX] {
            grinder.at(counter, &mut third).expect("valid call");
            assert_eq!(
                third[..],
                shake256(
                    &[
                        bytes,
                        &chall_2,
                        &coefficients,
                        &counter.to_le_bytes(),
                        &[0x0b]
                    ],
                    32
                )[..]
            );
        }
        third.to_vec()
    });
}

#[test]
fn h5_is_prefix_iv_gate_label_05_with_the_low_ten_bits() {
    let iv: [u8; 16] = pattern(16, 22).try_into().expect("16 bytes");
    let label = pattern(32, 23);
    for_each_prefix(|bytes, namespace| {
        let mut all = Vec::new();
        for gate in [0u32, 1, 703, 0x0403_0201] {
            let squeezed = shake256(&[bytes, &iv, &gate.to_le_bytes(), &label, &[0x05]], 2);
            let expected = u16::from_le_bytes([squeezed[0], squeezed[1]]) & 0x03ff;
            assert_eq!(h5_in(namespace, LEVEL, &iv, gate, &label, 10), Ok(expected));
            all.extend(squeezed);
        }
        all
    });
}

#[test]
fn every_oracle_of_the_hasher_takes_the_prefix() {
    for oracle in Oracle::ALL {
        for_each_prefix(|bytes, namespace| {
            let mut hasher = Hasher::new_in(namespace, LEVEL, oracle);
            hasher.update(b"body");
            let mut out = vec![0u8; oracle.output_bytes(LEVEL)];
            hasher.finalize(&mut out).expect("exact length");
            assert_eq!(
                out,
                shake256(&[bytes, b"body", &[oracle.domain_byte()]], out.len())
            );
            out
        });
    }
}
