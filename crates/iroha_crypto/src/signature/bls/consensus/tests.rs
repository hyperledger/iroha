//! Consensus-suite vectors, the allowlist, cross-suite separation and point validation.
//!
//! The standard vectors use the inputs of `ethereum/bls12-381-tests` (its generator's three
//! private keys and three 32-byte messages). Every expected output below was cross-checked
//! against an independent implementation of the IETF min-pk proof-of-possession suite (Apache Milagro via
//! `snowbridge-milagro-bls` 1.5.4).
//! `TODO:` import the complete released `bls12-381-tests` archive once vendoring it is approved.

use super::*;
use crate::{
    Algorithm, KeyPair, PublicKey, Signature, bls_normal_pop_prove, bls_normal_pop_verify,
    signature::bls::{
        signing,
        uncached::{HASH_TO_FIELD_DST, NORMAL_PREFIX},
    },
    test_allocations::{
        observed_deallocations, with_deallocation_observation, without_allocations,
    },
};
use blstrs::{Bls12, G2Prepared, Scalar};
use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
use std::cell::Cell;

/// `ethereum/bls12-381-tests` private keys (big-endian).
const SECRET_KEYS: [&str; 3] = [
    "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
    "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
];
const PUBLIC_KEYS: [&str; 3] = [
    "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
    "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
    "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
];
/// `ethereum/bls12-381-tests` messages.
const MESSAGES: [[u8; 32]; 3] = [[0x00; 32], [0x56; 32], [0xab; 32]];
/// `Sign(SECRET_KEYS[k], MESSAGES[m])` at `[k][m]`.
const SIGNATURES: [[&str; 3]; 3] = [
    [
        "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
    ],
    [
        "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
    ],
    [
        "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
    ],
];
/// `Aggregate` of the three keys' signatures over `MESSAGES[m]` (also the
/// `FastAggregateVerify` signatures).
const AGGREGATES: [&str; 3] = [
    "9683b3e6701f9a4b706709577963110043af78a5b41991b998475a3d3fd62abf35ce03b33908418efc95a058494a8ae504354b9f626231f6b3f3c849dfdeaf5017c4780e2aee1850ceaf4b4d9ce70971a3d2cfcd97b7e5ecf6759f8da5f76d31",
    "ad38fc73846583b08d110d16ab1d026c6ea77ac2071e8ae832f56ac0cbcdeb9f5678ba5ce42bd8dce334cc47b5abcba40a58f7f1f80ab304193eb98836cc14d8183ec14cc77de0f80c4ffd49e168927a968b5cdaa4cf46b9805be84ad7efa77b",
    "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
];
/// `AggregateVerify` signature: key `i` signs `MESSAGES[i]`.
const AGGREGATE_VERIFY: &str = "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244";

/// BLS12-381 base-field modulus `p`, big-endian.
const FIELD_MODULUS: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

fn bytes<const N: usize>(hex_value: &str) -> [u8; N] {
    hex::decode(hex_value)
        .expect("hex vector")
        .try_into()
        .expect("vector length")
}

fn identity_key() -> [u8; 48] {
    let mut key = [0; 48];
    key[0] = 0xc0;
    key
}

fn identity_signature() -> [u8; 96] {
    let mut signature = [0; 96];
    signature[0] = 0xc0;
    signature
}

/// The Iroha BLS-normal private key of a standard (big-endian) secret.
fn private_key(index: usize) -> PrivateKey {
    let mut little_endian = bytes::<32>(SECRET_KEYS[index]);
    little_endian.reverse();
    PrivateKey::from_bytes(Algorithm::BlsNormal, &little_endian).expect("standard secret key")
}

fn public_key(index: usize) -> PublicKey {
    PublicKey::from_private_key(&private_key(index)).expect("public key")
}

fn admitted(private_key: &PrivateKey) -> BlsNormalPopVerifiedKey {
    let public_key = PublicKey::from_private_key(private_key).expect("public key");
    let pop = bls_normal_pop_prove(private_key).expect("pop");
    BlsNormalPopVerifiedKey::new(&public_key, &pop).expect("pop verifies")
}

fn admitted_key(index: usize) -> BlsNormalPopVerifiedKey {
    admitted(&private_key(index))
}

fn standard_digest(message: usize) -> ConsensusDigest {
    ConsensusDigest::from_raw_for_test(MESSAGES[message])
}

/// The independent reference relation `sk · hash_to_curve(m, DST_SIG)` in blstrs.
fn reference_signature(index: usize, message: &[u8; 32]) -> [u8; 96] {
    let mut big_endian = bytes::<32>(SECRET_KEYS[index]);
    big_endian.reverse();
    let scalar = Scalar::from_bytes_le(&big_endian).expect("canonical scalar");
    (G2Projective::hash_to_curve(message, DST_SIG, &[]) * scalar)
        .to_affine()
        .to_compressed()
}

// ---------------------------------------------------------------------------------------------
// Sample allowlisted preimages (`specs/sumeragi.md` §3.3, §12.8)
// ---------------------------------------------------------------------------------------------

const INSTANCE: [u8; 32] = [0x11; 32];
const EPOCH: u64 = 7;
const EPOCH_CONTEXT: [u8; 32] = [0x22; 32];
const HEIGHT: u64 = 100;
const BLOCK_HASH: [u8; 32] = [0x33; 32];

fn sig_prefix(kind: u8) -> Vec<u8> {
    let mut out = TAG_SIG.to_vec();
    out.push(kind);
    out.extend_from_slice(&INSTANCE);
    out.extend_from_slice(&EPOCH.to_be_bytes());
    out.extend_from_slice(&EPOCH_CONTEXT);
    out
}

fn availability_statement(kind: u8) -> Vec<u8> {
    let mut out = TAG_AVAILABILITY_SIGN.to_vec();
    out.push(kind);
    out.extend_from_slice(&INSTANCE);
    out.extend_from_slice(&EPOCH.to_be_bytes());
    out.extend_from_slice(&EPOCH_CONTEXT);
    out.extend_from_slice(&HEIGHT.to_be_bytes());
    out.extend_from_slice(&0_u64.to_be_bytes());
    out.extend_from_slice(&BLOCK_HASH);
    out.extend_from_slice(&[0x66; 32]);
    out
}

/// One sample preimage of every allowlist row, built from the spec formulas.
fn sample_preimage(context: ConsensusContext) -> Vec<u8> {
    match context {
        ConsensusContext::Proposal => {
            let mut out = sig_prefix(0x01);
            out.extend_from_slice(&HEIGHT.to_be_bytes());
            out.extend_from_slice(&2_u64.to_be_bytes());
            out.extend_from_slice(&BLOCK_HASH);
            out.extend_from_slice(&[0x55; 32]);
            out
        }
        ConsensusContext::Prepare | ConsensusContext::Commit => {
            let kind = if context == ConsensusContext::Prepare {
                0x02
            } else {
                0x03
            };
            let mut out = sig_prefix(kind);
            out.extend_from_slice(&HEIGHT.to_be_bytes());
            out.extend_from_slice(&2_u64.to_be_bytes());
            out.extend_from_slice(&BLOCK_HASH);
            out.extend_from_slice(&[0x44; 32]);
            out
        }
        ConsensusContext::TimeoutWithoutHighQc => {
            let mut out = sig_prefix(0x04);
            out.extend_from_slice(&HEIGHT.to_be_bytes());
            out.extend_from_slice(&3_u64.to_be_bytes());
            out.push(0x00);
            out
        }
        ConsensusContext::TimeoutWithHighQc => {
            let mut out = sig_prefix(0x04);
            out.extend_from_slice(&HEIGHT.to_be_bytes());
            out.extend_from_slice(&3_u64.to_be_bytes());
            out.push(0x01);
            out.extend_from_slice(&2_u64.to_be_bytes());
            out
        }
        ConsensusContext::Echo => {
            let mut out = sig_prefix(0x05);
            out.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
            out.extend_from_slice(&(HEIGHT - 1).to_be_bytes());
            out
        }
        ConsensusContext::AvailabilityManifest => availability_statement(0x00),
        ConsensusContext::AvailabilityRow => {
            let mut out = availability_statement(0x01);
            out.extend_from_slice(&5_u32.to_be_bytes());
            out.extend_from_slice(&4096_u32.to_be_bytes());
            out.extend_from_slice(&[0x77; 32]);
            out
        }
    }
}

/// `att_preimage(h, bh, R)` (kind `0x06`): never allowlisted.
fn attestation_preimage() -> Vec<u8> {
    let mut out = sig_prefix(0x06);
    out.extend_from_slice(&HEIGHT.to_be_bytes());
    out.extend_from_slice(&BLOCK_HASH);
    out.extend_from_slice(&[0x44; 32]);
    out
}

fn context_name(context: ConsensusContext) -> &'static str {
    match context {
        ConsensusContext::Proposal => "proposal",
        ConsensusContext::Prepare => "prepare",
        ConsensusContext::Commit => "commit",
        ConsensusContext::TimeoutWithoutHighQc => "timeout_without_high_qc",
        ConsensusContext::TimeoutWithHighQc => "timeout_with_high_qc",
        ConsensusContext::Echo => "echo",
        ConsensusContext::AvailabilityManifest => "availability_manifest",
        ConsensusContext::AvailabilityRow => "availability_row",
    }
}

/// Labelled preimages that the allowlist must refuse.
fn rejected_preimages() -> Vec<(String, Vec<u8>)> {
    let mut cases = Vec::new();
    for context in ConsensusContext::ALL {
        let preimage = sample_preimage(context);
        let name = context_name(context);
        let mut short = preimage.clone();
        short.pop();
        cases.push((format!("{name}_length_{}", short.len()), short));
        let mut long = preimage.clone();
        long.push(0x00);
        cases.push((format!("{name}_length_{}", long.len()), long));
    }
    let attestation = attestation_preimage();
    cases.push(("attestation_kind_0x06".to_owned(), attestation));
    for kind in [0x00_u8, 0x06, 0x07, 0xff] {
        let mut wrong_kind = sample_preimage(ConsensusContext::Prepare);
        wrong_kind[TAG_SIG.len()] = kind;
        cases.push((format!("vote_length_kind_{kind:#04x}"), wrong_kind));
    }
    let mut echo_as_timeout = sample_preimage(ConsensusContext::Echo);
    echo_as_timeout[TAG_SIG.len()] = 0x04;
    cases.push(("timeout_kind_at_echo_length".to_owned(), echo_as_timeout));
    let mut timeout_none_flagged = sample_preimage(ConsensusContext::TimeoutWithoutHighQc);
    timeout_none_flagged[TIMEOUT_HQ_OFFSET] = 0x01;
    cases.push((
        "timeout_length_102_flag_0x01".to_owned(),
        timeout_none_flagged,
    ));
    let mut timeout_some_unflagged = sample_preimage(ConsensusContext::TimeoutWithHighQc);
    timeout_some_unflagged[TIMEOUT_HQ_OFFSET] = 0x00;
    cases.push((
        "timeout_length_110_flag_0x00".to_owned(),
        timeout_some_unflagged,
    ));
    let mut timeout_bad_flag = sample_preimage(ConsensusContext::TimeoutWithoutHighQc);
    timeout_bad_flag[TIMEOUT_HQ_OFFSET] = 0x02;
    cases.push(("timeout_length_102_flag_0x02".to_owned(), timeout_bad_flag));
    let mut manifest_kind_row = sample_preimage(ConsensusContext::AvailabilityManifest);
    manifest_kind_row[TAG_AVAILABILITY_SIGN.len()] = 0x01;
    cases.push((
        "availability_row_kind_at_manifest_length".to_owned(),
        manifest_kind_row,
    ));
    let mut row_kind_manifest = sample_preimage(ConsensusContext::AvailabilityRow);
    row_kind_manifest[TAG_AVAILABILITY_SIGN.len()] = 0x00;
    cases.push((
        "availability_manifest_kind_at_row_length".to_owned(),
        row_kind_manifest,
    ));
    let mut availability_kind_2 = sample_preimage(ConsensusContext::AvailabilityManifest);
    availability_kind_2[TAG_AVAILABILITY_SIGN.len()] = 0x02;
    cases.push(("availability_kind_0x02".to_owned(), availability_kind_2));
    let mut wrong_tag = sample_preimage(ConsensusContext::Commit);
    wrong_tag[0] ^= 0x20;
    cases.push(("vote_tag_case_flipped".to_owned(), wrong_tag));
    let mut block_tag = b"sumeragi/block".to_vec();
    block_tag.extend_from_slice(&sample_preimage(ConsensusContext::Commit)[TAG_SIG.len()..]);
    block_tag.truncate(165);
    cases.push(("block_tag_at_vote_length".to_owned(), block_tag));
    cases.push(("empty".to_owned(), Vec::new()));
    cases.push(("tag_sig_only".to_owned(), TAG_SIG.to_vec()));
    cases.push((
        "availability_tag_only".to_owned(),
        TAG_AVAILABILITY_SIGN.to_vec(),
    ));
    cases.push(("raw_32_byte_digest".to_owned(), vec![0x00; 32]));
    cases
}

// ---------------------------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------------------------

#[test]
fn dst_sig_is_the_ietf_min_pk_pop_suite_tag() {
    assert_eq!(DST_SIG.len(), 43);
    assert_eq!(DST_SIG.as_slice(), crate::ETHEREUM_BLS_POP_DST);
    assert_ne!(DST_SIG.as_slice(), HASH_TO_FIELD_DST);
    assert!(!NORMAL_PREFIX.starts_with(DST_SIG));
    assert_eq!(SIG_PREFIX_LEN, 85);
    assert_eq!(TIMEOUT_HQ_OFFSET, 101);
}

#[test]
fn allowlist_accepts_every_row_at_its_exact_length() {
    for context in ConsensusContext::ALL {
        let preimage = sample_preimage(context);
        assert_eq!(preimage.len(), context.preimage_len(), "{context:?}");
        assert_eq!(ConsensusContext::of_preimage(&preimage), Some(context));
        let digest = ConsensusDigest::from_preimage(&preimage).expect("allowlisted");
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(digest.as_bytes(), &expected, "{context:?}");
    }
}

#[test]
fn allowlist_refuses_lengths_kinds_and_tags_outside_the_table() {
    for (case, preimage) in rejected_preimages() {
        assert_eq!(ConsensusContext::of_preimage(&preimage), None, "{case}");
        assert!(
            ConsensusDigest::from_preimage(&preimage).is_none(),
            "{case}"
        );
    }
}

#[test]
fn vote_kinds_bind_signatures_without_retired_attestation_byte() {
    let key = private_key(0);
    let admitted = admitted(&key);
    let prepare = sample_preimage(ConsensusContext::Prepare);
    let commit = sample_preimage(ConsensusContext::Commit);
    assert_eq!(prepare.len(), 165);
    assert_eq!(commit.len(), 165);
    assert_eq!(&prepare[TAG_SIG.len() + 1..], &commit[TAG_SIG.len() + 1..]);
    let prepare_digest = ConsensusDigest::from_preimage(&prepare).unwrap();
    let commit_digest = ConsensusDigest::from_preimage(&commit).unwrap();
    assert_ne!(prepare_digest, commit_digest);
    for (preimage, digest, other) in [
        (&prepare, prepare_digest, commit_digest),
        (&commit, commit_digest, prepare_digest),
    ] {
        let signature = sign_preimage(&key, preimage).unwrap();
        assert!(verify(&admitted, &digest, &signature));
        assert!(!verify(&admitted, &other, &signature));
        for retired_flag in [0, 1] {
            let mut retired = preimage.clone();
            retired.push(retired_flag);
            assert!(ConsensusDigest::from_preimage(&retired).is_none());
            assert!(sign_preimage(&key, &retired).is_err());
        }
    }
}

#[test]
fn allowlist_admits_only_kinds_one_to_five_at_every_length() {
    for length in TAG_SIG.len() + 1..=256 {
        for kind in 0..=u8::MAX {
            let mut preimage = vec![0x00; length];
            preimage[..TAG_SIG.len()].copy_from_slice(TAG_SIG);
            preimage[TAG_SIG.len()] = kind;
            let context = ConsensusContext::of_preimage(&preimage);
            let expected = match (kind, length) {
                (0x01, 165) => Some(ConsensusContext::Proposal),
                (0x02, 165) => Some(ConsensusContext::Prepare),
                (0x03, 165) => Some(ConsensusContext::Commit),
                (0x04, 102) => Some(ConsensusContext::TimeoutWithoutHighQc),
                (0x05, 101) => Some(ConsensusContext::Echo),
                _ => None,
            };
            assert_eq!(context, expected, "kind {kind:#04x}, length {length}");
        }
    }
}

#[test]
fn availability_allowlist_admits_only_the_manifest_and_row_lengths() {
    for length in TAG_AVAILABILITY_SIGN.len() + 1..=256 {
        for kind in 0..=u8::MAX {
            let mut preimage = vec![0x00; length];
            preimage[..TAG_AVAILABILITY_SIGN.len()].copy_from_slice(TAG_AVAILABILITY_SIGN);
            preimage[TAG_AVAILABILITY_SIGN.len()] = kind;
            let expected = match (kind, length) {
                (0x00, 179) => Some(ConsensusContext::AvailabilityManifest),
                (0x01, 219) => Some(ConsensusContext::AvailabilityRow),
                _ => None,
            };
            assert_eq!(
                ConsensusContext::of_preimage(&preimage),
                expected,
                "kind {kind:#04x}, length {length}"
            );
        }
    }
}

#[test]
fn timeout_allowlist_ties_the_high_qc_flag_to_the_length() {
    for flag in 0..=u8::MAX {
        for (length, accepted_flag, context) in [
            (102, 0x00, ConsensusContext::TimeoutWithoutHighQc),
            (110, 0x01, ConsensusContext::TimeoutWithHighQc),
        ] {
            let mut preimage = sig_prefix(0x04);
            preimage.resize(length, 0x00);
            preimage[TIMEOUT_HQ_OFFSET] = flag;
            let expected = (flag == accepted_flag).then_some(context);
            assert_eq!(
                ConsensusContext::of_preimage(&preimage),
                expected,
                "length {length}, flag {flag:#04x}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Standard IETF min-pk PoP vectors
// ---------------------------------------------------------------------------------------------

#[test]
fn iroha_bls_normal_keys_are_the_standard_public_keys() {
    for (index, expected) in PUBLIC_KEYS.iter().enumerate() {
        let key = public_key(index);
        let (algorithm, payload) = key.to_bytes();
        assert_eq!(algorithm, Algorithm::BlsNormal);
        assert_eq!(hex::encode(payload), *expected);
        assert!(key_validate(&bytes::<48>(expected)));
    }
}

#[test]
fn sign_matches_the_standard_vectors() {
    for (key, signatures) in SIGNATURES.iter().enumerate() {
        let private_key = private_key(key);
        for (message, expected) in signatures.iter().enumerate() {
            let digest = standard_digest(message);
            let signature = sign(&private_key, &digest).expect("sign");
            assert_eq!(
                hex::encode(signature),
                *expected,
                "key {key}, message {message}"
            );
            assert_eq!(signature, reference_signature(key, &MESSAGES[message]));
        }
    }
}

#[test]
fn verify_accepts_the_standard_vectors_and_rejects_substitutions() {
    let keys: Vec<_> = (0..3).map(admitted_key).collect();
    for (key, signatures) in SIGNATURES.iter().enumerate() {
        for (message, expected) in signatures.iter().enumerate() {
            let signature = bytes::<96>(expected);
            assert!(verify(&keys[key], &standard_digest(message), &signature));
            assert!(!verify(
                &keys[(key + 1) % 3],
                &standard_digest(message),
                &signature
            ));
            assert!(!verify(
                &keys[key],
                &standard_digest((message + 1) % 3),
                &signature
            ));
            let mut tampered = signature;
            tampered[95] ^= 0x01;
            assert!(!verify(&keys[key], &standard_digest(message), &tampered));
        }
    }
}

#[test]
fn aggregate_matches_the_standard_vectors() {
    for (message, expected) in AGGREGATES.iter().enumerate() {
        let shares: Vec<[u8; 96]> = (0..3)
            .map(|key| bytes::<96>(SIGNATURES[key][message]))
            .collect();
        let aggregated = aggregate(&shares).expect("aggregate");
        assert_eq!(hex::encode(aggregated), *expected);
        let single = aggregate(&shares[..1]).expect("aggregate of one");
        assert_eq!(single, shares[0]);
    }
    let no_shares: [[u8; 96]; 0] = [];
    assert!(aggregate(no_shares).is_err());
}

#[test]
fn fast_aggregate_verify_matches_the_standard_vectors() {
    let standard: Vec<_> = (0..3).map(admitted_key).collect();
    let all: Vec<&BlsNormalPopVerifiedKey> = standard.iter().collect();
    let committed: Vec<[u8; 48]> = PUBLIC_KEYS.iter().map(|key| bytes::<48>(key)).collect();
    for (message, expected) in AGGREGATES.iter().enumerate() {
        let digest = standard_digest(message);
        let signature = bytes::<96>(expected);
        assert!(verify_fast_aggregate(&all, &digest, &signature));
        assert!(verify_fast_aggregate_committed(
            &committed, &digest, &signature
        ));
        assert!(!verify_fast_aggregate(&all[..2], &digest, &signature));
        assert!(!verify_fast_aggregate_committed(
            &committed[..2],
            &digest,
            &signature
        ));
        let wrong = standard_digest((message + 1) % 3);
        assert!(!verify_fast_aggregate(&all, &wrong, &signature));
        assert!(!verify_fast_aggregate_committed(
            &committed, &wrong, &signature
        ));
        let extra = admitted(
            &KeyPair::from_seed(vec![0x5a; 32], Algorithm::BlsNormal)
                .private_key()
                .clone(),
        );
        let mut with_extra = all.clone();
        with_extra.push(&extra);
        assert!(!verify_fast_aggregate(&with_extra, &digest, &signature));
    }
}

#[test]
fn aggregate_verify_matches_the_standard_vector() {
    let admitted: Vec<_> = (0..3).map(admitted_key).collect();
    let signature = bytes::<96>(AGGREGATE_VERIFY);
    let shares: Vec<[u8; 96]> = (0..3).map(|i| bytes::<96>(SIGNATURES[i][i])).collect();
    assert_eq!(aggregate(&shares).expect("aggregate"), signature);
    let groups: Vec<[&BlsNormalPopVerifiedKey; 1]> = admitted.iter().map(|key| [key]).collect();
    let paired: Vec<(&[&BlsNormalPopVerifiedKey], ConsensusDigest)> = groups
        .iter()
        .enumerate()
        .map(|(i, keys)| (keys.as_slice(), standard_digest(i)))
        .collect();
    assert!(verify_aggregate_multi(&paired, &signature));
    let swapped: Vec<(&[&BlsNormalPopVerifiedKey], ConsensusDigest)> = groups
        .iter()
        .enumerate()
        .map(|(i, keys)| (keys.as_slice(), standard_digest((i + 1) % 3)))
        .collect();
    assert!(!verify_aggregate_multi(&swapped, &signature));
    assert!(!verify_aggregate_multi(&paired[..2], &signature));
}

// ---------------------------------------------------------------------------------------------
// Aggregate preconditions
// ---------------------------------------------------------------------------------------------

#[test]
fn aggregate_multi_requires_groups_distinct_digests_and_distinct_group_keys() {
    let keys: Vec<_> = (0..3).map(admitted_key).collect();
    let digest = standard_digest(0);
    let other = standard_digest(1);
    let same_message = bytes::<96>(AGGREGATES[0]);
    // Two groups over the same digest: mathematically valid, refused by the distinct-message rule.
    let first = [&keys[0], &keys[1]];
    let second = [&keys[2]];
    assert!(verify_aggregate_multi(
        &[(&first[..], digest), (&second[..], other)],
        &aggregate([
            bytes::<96>(SIGNATURES[0][0]),
            bytes::<96>(SIGNATURES[1][0]),
            bytes::<96>(SIGNATURES[2][1]),
        ])
        .unwrap()
    ));
    assert!(!verify_aggregate_multi(
        &[(&first[..], digest), (&second[..], digest)],
        &same_message
    ));
    // A key repeated inside one group.
    let doubled =
        aggregate([bytes::<96>(SIGNATURES[0][0]), bytes::<96>(SIGNATURES[0][0])]).unwrap();
    let repeated = [&keys[0], &keys[0]];
    assert!(!verify_aggregate_multi(
        &[(&repeated[..], digest)],
        &doubled
    ));
    // The same key in different groups is allowed.
    let one = [&keys[0]];
    let across = aggregate([bytes::<96>(SIGNATURES[0][0]), bytes::<96>(SIGNATURES[0][1])]).unwrap();
    assert!(verify_aggregate_multi(
        &[(&one[..], digest), (&one[..], other)],
        &across
    ));
    // Empty inputs.
    assert!(!verify_aggregate_multi(&[], &same_message));
    assert!(!verify_aggregate_multi(&[(&[][..], digest)], &same_message));
}

#[test]
fn fast_aggregate_refuses_empty_repeated_and_cancelling_keys() {
    let key = admitted_key(0);
    let digest = standard_digest(0);
    let signature = bytes::<96>(SIGNATURES[0][0]);
    assert!(!verify_fast_aggregate(&[], &digest, &signature));
    assert!(!verify_fast_aggregate_committed(&[], &digest, &signature));
    let doubled = aggregate([signature, signature]).unwrap();
    // Admitted keys reject repetition; committed keys follow the §3.8 relation verbatim (the
    // committee root's strict ordering excludes repetition before this point).
    assert!(!verify_fast_aggregate(&[&key, &key], &digest, &doubled));
    let committed = bytes::<48>(PUBLIC_KEYS[0]);
    assert!(verify_fast_aggregate_committed(
        &[committed, committed],
        &digest,
        &doubled
    ));
    // apk = O.
    let negated = negated_private_key(0);
    let negated_key = admitted(&negated);
    let negated_bytes: [u8; 48] = negated_key.payload().try_into().unwrap();
    assert!(key_validate(&negated_bytes));
    assert!(!verify_fast_aggregate(
        &[&key, &negated_key],
        &digest,
        &signature
    ));
    assert!(!verify_fast_aggregate_committed(
        &[committed, negated_bytes],
        &digest,
        &signature
    ));
}

/// The private key of `-sk` for standard key `index`.
fn negated_private_key(index: usize) -> PrivateKey {
    let mut little_endian = bytes::<32>(SECRET_KEYS[index]);
    little_endian.reverse();
    let scalar = Scalar::from_bytes_le(&little_endian).expect("scalar");
    let negated = (-scalar).to_bytes_le();
    PrivateKey::from_bytes(Algorithm::BlsNormal, &negated).expect("negated key")
}

#[test]
fn verify_of_one_key_equals_fast_aggregate_of_one() {
    let key = admitted_key(1);
    let committed = [bytes::<48>(PUBLIC_KEYS[1])];
    for (message, expected) in SIGNATURES[1].iter().enumerate() {
        let digest = standard_digest(message);
        let signature = bytes::<96>(expected);
        assert_eq!(
            verify(&key, &digest, &signature),
            verify_fast_aggregate(&[&key], &digest, &signature)
        );
        assert!(verify_fast_aggregate_committed(
            &committed, &digest, &signature
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Points: identity, subgroup, canonical encoding
// ---------------------------------------------------------------------------------------------

/// A compressed G1 point on the curve but outside the prime-order subgroup.
fn non_subgroup_public_key() -> [u8; 48] {
    for x in 0_u8..=u8::MAX {
        let mut candidate = [0_u8; 48];
        candidate[0] = 0x80;
        candidate[47] = x;
        let on_curve = G1Affine::from_compressed_unchecked(&candidate).into_option();
        if on_curve.is_some_and(|point| !bool::from(point.is_torsion_free())) {
            return candidate;
        }
    }
    panic!("no small non-subgroup G1 x coordinate")
}

/// A compressed G2 point on the curve but outside the prime-order subgroup.
fn non_subgroup_signature() -> [u8; 96] {
    for x in 0_u8..=u8::MAX {
        let mut candidate = [0_u8; 96];
        candidate[0] = 0x80;
        candidate[95] = x;
        let on_curve = G2Affine::from_compressed_unchecked(&candidate).into_option();
        if on_curve.is_some_and(|point| !bool::from(point.is_torsion_free())) {
            return candidate;
        }
    }
    panic!("no small non-subgroup G2 x coordinate")
}

/// Labelled public-key encodings that `KeyValidate` refuses.
fn rejected_public_keys() -> Vec<(&'static str, [u8; 48])> {
    let valid = bytes::<48>(PUBLIC_KEYS[0]);
    let mut field_overflow = bytes::<48>(FIELD_MODULUS);
    field_overflow[0] |= 0x80;
    let mut uncompressed_flag = valid;
    uncompressed_flag[0] &= 0x7f;
    let mut infinity_with_x = identity_key();
    infinity_with_x[47] = 0x01;
    let mut infinity_with_sign = identity_key();
    infinity_with_sign[0] |= 0x20;
    vec![
        ("identity", identity_key()),
        ("non_subgroup", non_subgroup_public_key()),
        ("x_equals_field_modulus", field_overflow),
        ("compression_flag_cleared", uncompressed_flag),
        ("infinity_flag_with_nonzero_x", infinity_with_x),
        ("infinity_flag_with_sign_flag", infinity_with_sign),
        ("all_zero", [0; 48]),
        ("all_ones", [0xff; 48]),
    ]
}

/// Labelled signature encodings that every verifier refuses.
fn rejected_signatures() -> Vec<(&'static str, [u8; 96])> {
    let valid = bytes::<96>(SIGNATURES[0][0]);
    let mut c1_overflow = [0_u8; 96];
    c1_overflow[..48].copy_from_slice(&bytes::<48>(FIELD_MODULUS));
    c1_overflow[0] |= 0x80;
    let mut c0_overflow = valid;
    c0_overflow[48..].copy_from_slice(&bytes::<48>(FIELD_MODULUS));
    let mut uncompressed_flag = valid;
    uncompressed_flag[0] &= 0x7f;
    let mut infinity_with_x = identity_signature();
    infinity_with_x[95] = 0x01;
    vec![
        ("identity", identity_signature()),
        ("non_subgroup", non_subgroup_signature()),
        ("c1_equals_field_modulus", c1_overflow),
        ("c0_equals_field_modulus", c0_overflow),
        ("compression_flag_cleared", uncompressed_flag),
        ("infinity_flag_with_nonzero_x", infinity_with_x),
        ("all_zero", [0; 96]),
        ("all_ones", [0xff; 96]),
    ]
}

#[test]
fn key_validate_refuses_identity_non_subgroup_and_non_canonical_keys() {
    for key in PUBLIC_KEYS {
        assert!(key_validate(&bytes::<48>(key)));
    }
    let point = G1Affine::from_compressed_unchecked(&non_subgroup_public_key()).unwrap();
    assert!(bool::from(point.is_on_curve()));
    for (case, key) in rejected_public_keys() {
        assert!(!key_validate(&key), "{case}");
        let signature = bytes::<96>(SIGNATURES[0][0]);
        assert!(
            !verify_fast_aggregate_committed(&[key], &standard_digest(0), &signature),
            "{case}"
        );
        assert!(
            !verify_fast_aggregate_committed(
                &[bytes::<48>(PUBLIC_KEYS[0]), key],
                &standard_digest(0),
                &signature
            ),
            "{case}"
        );
    }
}

#[test]
fn every_verifier_refuses_identity_non_subgroup_and_non_canonical_signatures() {
    let key = admitted_key(0);
    let committed = [bytes::<48>(PUBLIC_KEYS[0])];
    let digest = standard_digest(0);
    let point = G2Affine::from_compressed_unchecked(&non_subgroup_signature()).unwrap();
    assert!(bool::from(point.is_on_curve()));
    for (case, signature) in rejected_signatures() {
        assert!(!verify(&key, &digest, &signature), "{case}");
        assert!(
            !verify_fast_aggregate(&[&key], &digest, &signature),
            "{case}"
        );
        assert!(
            !verify_fast_aggregate_committed(&committed, &digest, &signature),
            "{case}"
        );
        let one = [&key];
        assert!(
            !verify_aggregate_multi(&[(&one[..], digest)], &signature),
            "{case}"
        );
        assert!(aggregate([signature]).is_err(), "{case}");
        assert!(
            aggregate([bytes::<96>(SIGNATURES[0][0]), signature]).is_err(),
            "{case}"
        );
    }
    // A share and its negation sum to the identity.
    let share = bytes::<96>(SIGNATURES[0][0]);
    let negated = (-G2Affine::from_compressed(&share).unwrap()).to_compressed();
    assert!(aggregate([share, negated]).is_err());
}

// ---------------------------------------------------------------------------------------------
// Cross-suite separation
// ---------------------------------------------------------------------------------------------

#[test]
fn generic_signature_api_never_produces_a_consensus_signature() {
    let private_key = private_key(0);
    let key = admitted(&private_key);
    for context in ConsensusContext::ALL {
        let preimage = sample_preimage(context);
        let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
        let consensus = sign(&private_key, &digest).unwrap();
        for message in [preimage.as_slice(), digest.as_bytes().as_slice()] {
            let generic = Signature::new(&private_key, message);
            let generic: [u8; 96] = generic.payload().try_into().expect("BLS-normal signature");
            assert_ne!(generic, consensus, "{context:?}");
            assert!(!verify(&key, &digest, &generic), "{context:?}");
        }
    }
}

#[test]
fn consensus_signature_never_verifies_through_the_generic_api() {
    let private_key = private_key(0);
    let public_key = public_key(0);
    for context in ConsensusContext::ALL {
        let preimage = sample_preimage(context);
        let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
        let consensus = Signature::from_bytes(&sign(&private_key, &digest).unwrap());
        assert!(
            consensus.verify(&public_key, &preimage).is_err(),
            "{context:?}"
        );
        assert!(
            consensus.verify(&public_key, digest.as_bytes()).is_err(),
            "{context:?}"
        );
        assert!(
            crate::verify_bls_normal_signature_borrowed(
                public_key.to_bytes().1,
                consensus.payload(),
                digest.as_bytes()
            )
            .is_err(),
            "{context:?}"
        );
    }
}

#[test]
fn proof_of_possession_and_consensus_signature_never_substitute() {
    for index in 0..3 {
        let private_key = private_key(index);
        let public_key = public_key(index);
        let key = admitted(&private_key);
        let pop: [u8; 96] = bls_normal_pop_prove(&private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let pop_message = crate::bls_pop_message_hash(public_key.to_bytes().1);
        let digest = ConsensusDigest::from_raw_for_test(pop_message);
        assert!(!verify(&key, &digest, &pop));
        let consensus = sign(&private_key, &digest).unwrap();
        assert_ne!(consensus, pop);
        assert!(bls_normal_pop_verify(&public_key, &consensus).is_err());
    }
}

#[test]
fn hash_to_curve_points_differ_between_the_suites() {
    for context in ConsensusContext::ALL {
        let digest = ConsensusDigest::from_preimage(&sample_preimage(context)).unwrap();
        let consensus = message_point(&digest);
        let w3f = G2Projective::hash_to_curve(digest.as_bytes(), HASH_TO_FIELD_DST, NORMAL_PREFIX)
            .to_affine();
        assert_ne!(consensus, w3f, "{context:?}");
        assert!(bool::from(consensus.is_torsion_free()));
    }
}

// ---------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------

#[test]
fn sign_preimage_signs_the_allowlisted_digest_and_refuses_everything_else() {
    let private_key = private_key(2);
    for context in ConsensusContext::ALL {
        let preimage = sample_preimage(context);
        let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
        assert_eq!(
            sign_preimage(&private_key, &preimage).unwrap(),
            sign(&private_key, &digest).unwrap()
        );
    }
    for (case, preimage) in rejected_preimages() {
        assert!(
            matches!(
                sign_preimage(&private_key, &preimage),
                Err(Error::Signing(_))
            ),
            "{case}"
        );
    }
}

#[test]
fn sign_refuses_keys_that_are_not_bls_normal() {
    let digest =
        ConsensusDigest::from_preimage(&sample_preimage(ConsensusContext::Commit)).unwrap();
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::Secp256k1,
        Algorithm::BlsSmall,
    ] {
        let key_pair = KeyPair::from_seed(vec![0x42; 32], algorithm);
        assert!(
            matches!(
                sign(key_pair.private_key(), &digest),
                Err(Error::Signing(_))
            ),
            "{algorithm:?}"
        );
    }
}

#[test]
fn signing_is_unique_blinding_independent_and_allocation_free() {
    let private_key = private_key(0);
    let PrivateKeyInner::BlsNormal(secret) = ({
        use crate::secrecy::ExposeSecret as _;
        private_key.0.expose_secret()
    }) else {
        panic!("BLS-normal key")
    };
    let digest =
        ConsensusDigest::from_preimage(&sample_preimage(ConsensusContext::Commit)).unwrap();
    let expected = reference_signature(0, digest.as_bytes());
    assert_eq!(sign(&private_key, &digest).unwrap(), expected);
    assert_eq!(sign(&private_key, &digest).unwrap(), expected);
    let once = without_allocations(|| signing::sign_consensus_once(secret.as_bytes(), &digest));
    assert_eq!(once.unwrap(), expected);
    #[cfg(feature = "rand")]
    for seed in [1_u64, 2, 0xdead_beef] {
        let mut rng = <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::seed_from_u64(seed);
        let blinded =
            signing::sign_consensus_with_rng(secret.as_bytes(), &digest, &mut rng).unwrap();
        assert_eq!(blinded, expected);
    }
    assert!(verify(&admitted(&private_key), &digest, &expected));
}

// ---------------------------------------------------------------------------------------------
// Pairing scratch: independent relation parity and exact custody
// ---------------------------------------------------------------------------------------------

/// Independent blstrs multi-Miller-loop implementation of `e(g1, σ) = Π e(apk_i, H(m_i))`
/// with the same point preconditions, for parity with the `blst` pairing context.
fn reference_relation(terms: &[(G1Projective, ConsensusDigest)], aggregate: &[u8; 96]) -> bool {
    if terms.is_empty() || terms.iter().any(|(apk, _)| bool::from(apk.is_identity())) {
        return false;
    }
    let Some(signature) = G2Affine::from_compressed(aggregate).into_option() else {
        return false;
    };
    if bool::from(signature.is_identity()) || signature.to_compressed() != *aggregate {
        return false;
    }
    let negated: Vec<(G1Affine, G2Prepared)> = terms
        .iter()
        .map(|(apk, digest)| {
            let message = G2Projective::hash_to_curve(digest.as_bytes(), DST_SIG, &[]);
            ((-apk).to_affine(), G2Prepared::from(message.to_affine()))
        })
        .collect();
    let generator = G1Affine::generator();
    let signature = G2Prepared::from(signature);
    let mut pairs: Vec<(&G1Affine, &G2Prepared)> = vec![(&generator, &signature)];
    pairs.extend(negated.iter().map(|(apk, message)| (apk, message)));
    Bls12::multi_miller_loop(&pairs)
        .final_exponentiation()
        .is_identity()
        .into()
}

fn key_sum(keys: &[&BlsNormalPopVerifiedKey]) -> G1Projective {
    keys.iter()
        .fold(G1Projective::identity(), |sum, key| sum + key.point)
}

#[test]
fn scratch_matches_the_independent_relation_without_allocations() {
    let keys: Vec<_> = (0..3).map(admitted_key).collect();
    let refs: Vec<&BlsNormalPopVerifiedKey> = keys.iter().collect();
    let committed: Vec<[u8; 48]> = PUBLIC_KEYS.iter().map(|key| bytes::<48>(key)).collect();
    let mut scratch = ConsensusAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    let mut fast = |keys: &[&BlsNormalPopVerifiedKey], message: usize, signature: &[u8; 96]| {
        let digest = standard_digest(message);
        let actual = without_allocations(|| {
            scratch.verify_fast_aggregate(keys.iter().copied(), &digest, signature)
        });
        assert_eq!(actual, verify_fast_aggregate(keys, &digest, signature));
        if !keys.is_empty() && !has_duplicate(keys) {
            assert_eq!(
                actual,
                reference_relation(&[(key_sum(keys), digest)], signature)
            );
        }
        actual
    };
    for message in 0..3 {
        let aggregated = bytes::<96>(AGGREGATES[message]);
        assert!(fast(&refs, message, &aggregated));
        assert!(!fast(&refs[..2], message, &aggregated));
        assert!(!fast(&refs, (message + 1) % 3, &aggregated));
        assert!(!fast(&[], message, &aggregated));
        assert!(!fast(&[refs[0], refs[0]], message, &aggregated));
        for (_, rejected) in rejected_signatures() {
            assert!(!fast(&refs, message, &rejected));
        }
        // A rejected proof never poisons the next verdict.
        assert!(fast(&refs, message, &aggregated));
        for key in 0..3 {
            assert!(fast(
                &refs[key..=key],
                message,
                &bytes::<96>(SIGNATURES[key][message])
            ));
        }
    }
    let committed_case =
        |scratch: &mut ConsensusAggregateScratch, keys: &[[u8; 48]], signature: &[u8; 96]| {
            let digest = standard_digest(0);
            let actual = without_allocations(|| {
                scratch.verify_fast_aggregate_committed(keys, &digest, signature)
            });
            assert_eq!(
                actual,
                verify_fast_aggregate_committed(keys, &digest, signature)
            );
            actual
        };
    let aggregated = bytes::<96>(AGGREGATES[0]);
    assert!(committed_case(&mut scratch, &committed, &aggregated));
    assert!(!committed_case(&mut scratch, &committed[..2], &aggregated));
    assert!(!committed_case(&mut scratch, &[], &aggregated));
    for (_, rejected) in rejected_public_keys() {
        assert!(!committed_case(
            &mut scratch,
            &[committed[0], committed[1], rejected],
            &aggregated
        ));
    }
    assert!(committed_case(&mut scratch, &committed, &aggregated));
    // AggregateVerify: key `i` signed message `i`.
    let groups: Vec<[&BlsNormalPopVerifiedKey; 1]> = refs.iter().map(|key| [*key]).collect();
    let signature = bytes::<96>(AGGREGATE_VERIFY);
    let mut multi = |shift: usize, count: usize, signature: &[u8; 96]| {
        let paired: Vec<(&[&BlsNormalPopVerifiedKey], ConsensusDigest)> = groups[..count]
            .iter()
            .enumerate()
            .map(|(i, keys)| (keys.as_slice(), standard_digest((i + shift) % 3)))
            .collect();
        let actual = without_allocations(|| {
            scratch.verify_aggregate_multi(
                paired
                    .iter()
                    .map(|(keys, digest)| (keys.iter().copied(), *digest)),
                signature,
            )
        });
        assert_eq!(actual, verify_aggregate_multi(&paired, signature));
        let terms: Vec<_> = paired
            .iter()
            .map(|(keys, digest)| (key_sum(keys), *digest))
            .collect();
        assert_eq!(actual, reference_relation(&terms, signature));
        actual
    };
    assert!(multi(0, 3, &signature));
    assert!(!multi(1, 3, &signature));
    assert!(!multi(0, 2, &signature));
    assert!(!multi(0, 0, &signature));
    assert!(!multi(0, 3, &identity_signature()));
    assert!(multi(0, 3, &signature));
}

fn has_duplicate(keys: &[&BlsNormalPopVerifiedKey]) -> bool {
    keys.iter()
        .enumerate()
        .any(|(index, key)| keys[..index].contains(key))
}

#[test]
fn scratch_exact_admission_refuses_before_backing_and_drops_backing_before_funding() {
    struct Token<'a> {
        bytes: usize,
        used: &'a Cell<usize>,
    }
    impl Drop for Token<'_> {
        fn drop(&mut self) {
            assert_eq!(
                observed_deallocations(),
                1,
                "backing must be freed before refund"
            );
            self.used.set(self.used.get() - self.bytes);
        }
    }
    let backing = ConsensusAggregateScratch::<()>::backing_bytes();
    assert!(backing > 0);
    assert_eq!(
        backing,
        crate::BlsNormalAggregateScratch::<()>::backing_bytes()
    );
    let used = Cell::new(0);
    let limit = Cell::new(backing - 1);
    let admit = |requested| {
        assert_eq!(requested, backing);
        if used.get() + requested > limit.get() {
            return Err((requested, limit.get()));
        }
        used.set(used.get() + requested);
        Ok(Token {
            bytes: requested,
            used: &used,
        })
    };
    let refusal = without_allocations(|| ConsensusAggregateScratch::new(admit));
    assert!(
        matches!(refusal, Err((requested, ceiling)) if requested == backing && ceiling == backing - 1)
    );
    assert_eq!(used.get(), 0);
    limit.set(backing);
    let mut scratch = ConsensusAggregateScratch::new(admit)
        .unwrap_or_else(|error| panic!("same owner retry: {error:?}"));
    assert_eq!(used.get(), backing);
    let key = admitted_key(0);
    let digest = standard_digest(0);
    let signature = bytes::<96>(SIGNATURES[0][0]);
    assert!(without_allocations(|| scratch.verify_fast_aggregate(
        core::iter::once(&key),
        &digest,
        &signature
    )));
    let ((), frees) = with_deallocation_observation(backing, || drop(scratch));
    assert_eq!(frees, 1);
    assert_eq!(used.get(), 0);
}

// ---------------------------------------------------------------------------------------------
// Shared vector file (`fixtures/sccp/bls_consensus_rust_v1.json`)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "json")]
mod python_reference;

#[cfg(feature = "json")]
mod fixture {
    use super::*;
    use norito::json::{Map, Value};
    use std::path::PathBuf;

    const FIXTURE: &str = "bls_consensus_rust_v1.json";

    fn hex(bytes: &[u8]) -> Value {
        Value::from(format!("0x{}", hex::encode(bytes)))
    }

    fn object(entries: Vec<(&str, Value)>) -> Value {
        let mut map = Map::new();
        for (key, value) in entries {
            map.insert(key.to_owned(), value);
        }
        Value::Object(map)
    }

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sccp")
            .join(FIXTURE)
    }

    fn render(value: &Value) -> String {
        let mut out = norito::json::to_string_pretty(value).expect("render fixture");
        out.push('\n');
        out
    }

    fn keys() -> Value {
        Value::Array(
            (0..3)
                .map(|index| {
                    let private_key = private_key(index);
                    let (_, iroha_private_key) = private_key.to_bytes();
                    let pop = bls_normal_pop_prove(&private_key).unwrap();
                    object(vec![
                        ("index", Value::from(index)),
                        ("secret_key_be", hex(&bytes::<32>(SECRET_KEYS[index]))),
                        ("iroha_private_key", hex(&iroha_private_key)),
                        ("public_key", hex(public_key(index).to_bytes().1)),
                        ("w3f_pop", hex(&pop)),
                    ])
                })
                .collect(),
        )
    }

    fn standard_vectors() -> Value {
        let admitted: Vec<_> = (0..3).map(admitted_key).collect();
        let all: Vec<&BlsNormalPopVerifiedKey> = admitted.iter().collect();
        let mut sign_rows = Vec::new();
        let mut verify_rows = Vec::new();
        for (key, row) in SIGNATURES.iter().enumerate() {
            for (message, expected) in row.iter().enumerate() {
                let digest = standard_digest(message);
                let signature = sign(&private_key(key), &digest).unwrap();
                assert_eq!(hex::encode(signature), *expected);
                sign_rows.push(object(vec![
                    ("key", Value::from(key)),
                    ("message", hex(&MESSAGES[message])),
                    ("signature", hex(&signature)),
                ]));
                for (other_key, other_message) in [
                    (key, message),
                    ((key + 1) % 3, message),
                    (key, (message + 1) % 3),
                ] {
                    let valid = verify(
                        &admitted[other_key],
                        &standard_digest(other_message),
                        &signature,
                    );
                    assert_eq!(valid, other_key == key && other_message == message);
                    verify_rows.push(object(vec![
                        ("key", Value::from(other_key)),
                        ("message", hex(&MESSAGES[other_message])),
                        ("signature", hex(&signature)),
                        ("valid", Value::from(valid)),
                    ]));
                }
            }
        }
        let mut aggregate_rows = Vec::new();
        let mut fast_rows = Vec::new();
        for message in 0..3 {
            let shares: Vec<[u8; 96]> = (0..3)
                .map(|key| bytes::<96>(SIGNATURES[key][message]))
                .collect();
            let output = aggregate(&shares).unwrap();
            assert_eq!(hex::encode(output), AGGREGATES[message]);
            aggregate_rows.push(object(vec![
                (
                    "signatures",
                    Value::Array(shares.iter().map(|s| hex(s)).collect()),
                ),
                ("output", hex(&output)),
            ]));
            for (subset, digest_index) in [
                (vec![0_usize, 1, 2], message),
                (vec![0, 1], message),
                (vec![0, 1, 2], (message + 1) % 3),
            ] {
                let keys: Vec<&BlsNormalPopVerifiedKey> = subset.iter().map(|&i| all[i]).collect();
                let digest = standard_digest(digest_index);
                let valid = verify_fast_aggregate(&keys, &digest, &output);
                assert_eq!(valid, subset.len() == 3 && digest_index == message);
                fast_rows.push(object(vec![
                    (
                        "keys",
                        Value::Array(subset.iter().map(|&i| Value::from(i)).collect()),
                    ),
                    ("message", hex(&MESSAGES[digest_index])),
                    ("signature", hex(&output)),
                    ("valid", Value::from(valid)),
                ]));
            }
        }
        let aggregate_verify = bytes::<96>(AGGREGATE_VERIFY);
        let groups: Vec<[&BlsNormalPopVerifiedKey; 1]> = admitted.iter().map(|key| [key]).collect();
        let mut aggregate_verify_rows = Vec::new();
        for shift in [0_usize, 1] {
            let paired: Vec<(&[&BlsNormalPopVerifiedKey], ConsensusDigest)> = groups
                .iter()
                .enumerate()
                .map(|(i, keys)| (keys.as_slice(), standard_digest((i + shift) % 3)))
                .collect();
            let valid = verify_aggregate_multi(&paired, &aggregate_verify);
            assert_eq!(valid, shift == 0);
            aggregate_verify_rows.push(object(vec![
                (
                    "keys",
                    Value::Array((0..3_usize).map(Value::from).collect()),
                ),
                (
                    "messages",
                    Value::Array((0..3).map(|i| hex(&MESSAGES[(i + shift) % 3])).collect()),
                ),
                ("signature", hex(&aggregate_verify)),
                ("valid", Value::from(valid)),
            ]));
        }
        object(vec![
            (
                "source",
                Value::from(
                    "ethereum/bls12-381-tests standard inputs (generator private keys and 32-byte \
                     messages); outputs cross-checked against Apache Milagro \
                     (snowbridge-milagro-bls 1.5.4). Messages are raw 32-byte m, as for a \
                     consensus digest.",
                ),
            ),
            ("sign", Value::Array(sign_rows)),
            ("verify", Value::Array(verify_rows)),
            ("aggregate", Value::Array(aggregate_rows)),
            ("fast_aggregate_verify", Value::Array(fast_rows)),
            ("aggregate_verify", Value::Array(aggregate_verify_rows)),
        ])
    }

    fn allowlist() -> Value {
        let admitted: Vec<_> = (0..3).map(admitted_key).collect();
        let all: Vec<&BlsNormalPopVerifiedKey> = admitted.iter().collect();
        Value::Array(
            ConsensusContext::ALL
                .into_iter()
                .map(|context| {
                    let preimage = sample_preimage(context);
                    let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
                    let signatures: Vec<[u8; 96]> = (0..3)
                        .map(|key| sign_preimage(&private_key(key), &preimage).unwrap())
                        .collect();
                    let aggregated = aggregate(&signatures).unwrap();
                    assert!(verify_fast_aggregate(&all, &digest, &aggregated));
                    object(vec![
                        ("context", Value::from(context_name(context))),
                        ("length", Value::from(context.preimage_len())),
                        ("preimage", hex(&preimage)),
                        ("digest", hex(digest.as_bytes())),
                        (
                            "signatures",
                            Value::Array(signatures.iter().map(|s| hex(s)).collect()),
                        ),
                        ("aggregate", hex(&aggregated)),
                    ])
                })
                .collect(),
        )
    }

    fn allowlist_rejections() -> Value {
        Value::Array(
            rejected_preimages()
                .into_iter()
                .map(|(case, preimage)| {
                    assert!(ConsensusDigest::from_preimage(&preimage).is_none());
                    object(vec![
                        ("case", Value::from(case)),
                        ("length", Value::from(preimage.len())),
                        ("preimage", hex(&preimage)),
                    ])
                })
                .collect(),
        )
    }

    fn negatives() -> Value {
        let private_key = private_key(0);
        let public_key = public_key(0);
        let key = admitted(&private_key);
        let preimage = sample_preimage(ConsensusContext::Commit);
        let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
        let consensus = sign(&private_key, &digest).unwrap();
        let mut rows = Vec::new();
        for (case, message) in [
            ("w3f_signature_over_consensus_preimage", preimage.as_slice()),
            (
                "w3f_signature_over_consensus_digest",
                digest.as_bytes().as_slice(),
            ),
        ] {
            let generic: [u8; 96] = Signature::new(&private_key, message)
                .payload()
                .try_into()
                .unwrap();
            assert!(!verify(&key, &digest, &generic));
            rows.push(object(vec![
                ("case", Value::from(case)),
                ("key", Value::from(0_u8)),
                ("preimage", hex(&preimage)),
                ("signature", hex(&generic)),
                ("consensus_valid", Value::from(false)),
            ]));
        }
        let generic_preimage = Signature::from_bytes(&consensus)
            .verify(&public_key, &preimage)
            .is_ok();
        let generic_digest = Signature::from_bytes(&consensus)
            .verify(&public_key, digest.as_bytes())
            .is_ok();
        assert!(!generic_preimage && !generic_digest);
        rows.push(object(vec![
            (
                "case",
                Value::from("dst_sig_signature_presented_to_generic_api"),
            ),
            ("key", Value::from(0_u8)),
            ("preimage", hex(&preimage)),
            ("signature", hex(&consensus)),
            ("generic_valid_over_preimage", Value::from(generic_preimage)),
            ("generic_valid_over_digest", Value::from(generic_digest)),
        ]));
        let pop: [u8; 96] = bls_normal_pop_prove(&private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let pop_message = crate::bls_pop_message_hash(public_key.to_bytes().1);
        let pop_valid = verify(&key, &ConsensusDigest::from_raw_for_test(pop_message), &pop);
        assert!(!pop_valid);
        rows.push(object(vec![
            ("case", Value::from("w3f_pop_as_consensus_signature")),
            ("key", Value::from(0_u8)),
            ("message", hex(&pop_message)),
            ("signature", hex(&pop)),
            ("consensus_valid", Value::from(pop_valid)),
        ]));
        for (case, encoded) in rejected_public_keys() {
            assert!(!key_validate(&encoded));
            rows.push(object(vec![
                ("case", Value::from(format!("public_key_{case}"))),
                ("public_key", hex(&encoded)),
                ("key_validate", Value::from(false)),
            ]));
        }
        for (case, encoded) in rejected_signatures() {
            assert!(!verify(&key, &digest, &encoded));
            rows.push(object(vec![
                ("case", Value::from(format!("signature_{case}"))),
                ("key", Value::from(0_u8)),
                ("preimage", hex(&preimage)),
                ("signature", hex(&encoded)),
                ("consensus_valid", Value::from(false)),
            ]));
        }
        let negated = admitted(&negated_private_key(0));
        let negated_bytes: [u8; 48] = negated.payload().try_into().unwrap();
        let committed = bytes::<48>(PUBLIC_KEYS[0]);
        assert!(!verify_fast_aggregate_committed(
            &[committed, negated_bytes],
            &digest,
            &consensus
        ));
        rows.push(object(vec![
            ("case", Value::from("cancelling_keys_aggregate_to_identity")),
            (
                "public_keys",
                Value::Array(vec![hex(&committed), hex(&negated_bytes)]),
            ),
            ("preimage", hex(&preimage)),
            ("signature", hex(&consensus)),
            ("consensus_valid", Value::from(false)),
        ]));
        Value::Array(rows)
    }

    fn generate() -> Value {
        object(vec![
            ("schema", Value::from("iroha.bls_consensus.rust.v1")),
            (
                "spec",
                Value::from("specs/sumeragi.md §1 item 6; specs/sccp.md §3.8"),
            ),
            (
                "generator",
                Value::from(
                    "cargo test -p iroha_crypto --lib \
                     signature::bls::consensus::tests::fixture::regenerate_bls_consensus_rust_v1 \
                     -- --ignored",
                ),
            ),
            (
                "suite",
                object(vec![
                    (
                        "dst_sig",
                        Value::from(core::str::from_utf8(DST_SIG).unwrap()),
                    ),
                    ("dst_sig_hex", hex(DST_SIG)),
                    (
                        "message",
                        Value::from("SHA-256(P) of an allowlisted preimage P"),
                    ),
                    (
                        "hash_to_curve",
                        Value::from("RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_, no augmentation"),
                    ),
                    (
                        "signature",
                        Value::from("sk * hash_to_curve(m, DST_SIG), compressed G2 (96 bytes)"),
                    ),
                    ("public_key_len", Value::from(PUBLIC_KEY_LEN)),
                    ("signature_len", Value::from(SIGNATURE_LEN)),
                ]),
            ),
            (
                "sample_fields",
                object(vec![
                    ("instance", hex(&INSTANCE)),
                    ("epoch", Value::from(EPOCH)),
                    ("epoch_context", hex(&EPOCH_CONTEXT)),
                    ("height", Value::from(HEIGHT)),
                    ("block_hash", hex(&BLOCK_HASH)),
                ]),
            ),
            ("keys", keys()),
            ("standard_vectors", standard_vectors()),
            ("allowlist", allowlist()),
            ("allowlist_rejections", allowlist_rejections()),
            ("negatives", negatives()),
        ])
    }

    #[test]
    fn consensus_vectors_match_committed_fixture() {
        let generated = generate();
        let expected = render(&generated);
        let path = fixture_path();
        let actual = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            actual == expected,
            "{FIXTURE} differs from the generated vectors; after a reviewed change run \
             `cargo test -p iroha_crypto --lib regenerate_bls_consensus_rust_v1 -- --ignored`"
        );
        let parsed: Value = norito::json::from_str(&actual).expect("fixture parses");
        assert_eq!(parsed, generated);
    }

    #[test]
    #[ignore = "rewrites fixtures/sccp/bls_consensus_rust_v1.json"]
    fn regenerate_bls_consensus_rust_v1() {
        let path = fixture_path();
        std::fs::write(&path, render(&generate()))
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    }
}
