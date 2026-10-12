//! Hash conformance: the SHAKE known answer of the upstream `tests/hash_shake.cpp`
//! and the domain separation of the FAEST v3.0 random oracles.

mod common;

use common::{Fixture, hash_array};
use iroha_zkp_vole::{
    hash::{HashError, Hasher, Oracle, Xof, h5, hash},
    params::SecurityLevel,
};

#[test]
fn upstream_shake256_known_answer() {
    let fixture = Fixture::load_extracted();
    let data1 = fixture.bytes("hash_shake.shake_256.data1");
    let data2 = u32::try_from(fixture.integer("hash_shake.shake_256.data2")).expect("32 bits");
    let expected = fixture.bytes("hash_shake.shake_256.expected_output");
    assert_eq!(expected.len(), 32);

    // lambda = 192 and lambda = 256 both select SHAKE256.
    for level in [SecurityLevel::L192, SecurityLevel::L256] {
        let mut xof = Xof::new(level);
        xof.update(&data1);
        xof.update_u32_le(data2);
        let mut output = xof.finalize();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        output.squeeze(&mut first);
        output.squeeze(&mut second);
        assert_eq!(first[..], expected[..]);
        // The upstream test also checks that the stream moves on.
        assert_ne!(second[..], expected[..]);
    }
    // SHAKE128 is a different function.
    let mut xof = Xof::new(SecurityLevel::L128);
    xof.update(&data1);
    xof.update_u32_le(data2);
    let mut first = [0u8; 32];
    xof.finalize().squeeze(&mut first);
    assert_ne!(first[..], expected[..]);
    fixture.assert_consumed("hash_shake.");
}

/// `hash_array`, the digest behind every `hashed_*` fixture entry, is SHAKE256
/// squeezed to 64 bytes without domain separation.
#[test]
fn hash_array_is_plain_shake256() {
    let mut xof = Xof::new(SecurityLevel::L256);
    xof.update(b"hashed buffer");
    let mut expected = [0u8; 64];
    xof.finalize().squeeze(&mut expected);
    assert_eq!(hash_array(b"hashed buffer"), expected);
}

#[test]
fn every_pair_of_functions_and_levels_is_separated() {
    let message = [0x5au8; 40];
    let mut outputs: Vec<Vec<u8>> = Vec::new();
    for level in SecurityLevel::ALL {
        for oracle in Oracle::ALL {
            let mut out = vec![0u8; oracle.output_bytes(level)];
            hash(level, oracle, &message, &mut out).expect("exact length");
            // Compare on the common 16-byte prefix: the functions differ in the
            // sponge input (the domain byte), not merely in output length.
            outputs.push(out[..16].to_vec());
        }
    }
    // SHAKE256 serves lambda = 192 and 256, so those two levels agree on the common
    // prefix; within one level all eight functions differ, and SHAKE128 differs
    // from SHAKE256.
    let (l128, rest) = outputs.split_at(8);
    let (l192, l256) = rest.split_at(8);
    assert_eq!(l192, l256);
    for level in [l128, l192] {
        let mut distinct = level.to_vec();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 8);
    }
    assert!(l128.iter().all(|output| !l192.contains(output)));

    // H_5 uses domain byte 5, distinct from the eight above, and is sensitive to
    // each of its three inputs.
    let iv = [7u8; 16];
    let label = [9u8; 16];
    let base = h5(SecurityLevel::L128, &iv, 3, &label, 16).expect("valid call");
    assert!(Oracle::ALL.iter().all(|oracle| oracle.domain_byte() != 5));
    assert_ne!(h5(SecurityLevel::L128, &[8u8; 16], 3, &label, 16), Ok(base));
    assert_ne!(h5(SecurityLevel::L128, &iv, 4, &label, 16), Ok(base));
    assert_ne!(h5(SecurityLevel::L128, &iv, 3, &[1u8; 16], 16), Ok(base));
}

#[test]
fn piecewise_absorption_equals_one_shot() {
    for level in SecurityLevel::ALL {
        let message: Vec<u8> = (0u8..200).collect();
        let mut expected = vec![0u8; Oracle::H2Chall1.output_bytes(level)];
        hash(level, Oracle::H2Chall1, &message, &mut expected).expect("exact length");
        for split in [0, 1, 135, 136, 137, 199, 200] {
            let mut hasher = Hasher::new(level, Oracle::H2Chall1);
            hasher.update(&message[..split]);
            hasher.update(&message[split..]);
            let mut out = vec![0u8; expected.len()];
            hasher.finalize(&mut out).expect("exact length");
            assert_eq!(out, expected, "{level:?} {split}");
        }
    }
}

#[test]
fn wrong_lengths_are_rejected_with_typed_errors() {
    let mut out = [0u8; 31];
    assert_eq!(
        hash(SecurityLevel::L128, Oracle::H1, b"m", &mut out),
        Err(HashError::InvalidOutputLength {
            oracle: Oracle::H1,
            expected: 32,
            actual: 31
        })
    );
    assert_eq!(
        h5(SecurityLevel::L256, &[0; 16], 0, &[0; 16], 10),
        Err(HashError::InvalidInputLength {
            expected: 32,
            actual: 16
        })
    );
    assert_eq!(
        h5(SecurityLevel::L256, &[0; 16], 0, &[0; 32], 0),
        Err(HashError::InvalidH5Bits { bits: 0 })
    );
}
