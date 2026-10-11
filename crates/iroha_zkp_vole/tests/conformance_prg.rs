//! PRG conformance against the official FAEST v3.0.2 vectors (`prg_tvs`), which the
//! upstream `tests/prg.cpp` checks with `prg(key, iv, tweak, out, lambda, 232)`.

mod common;

use common::Fixture;
use iroha_zkp_vole::{
    params::SecurityLevel,
    prg::{Backend, Prg, PrgError, prg},
};

struct Vector {
    key: Vec<u8>,
    iv: [u8; 16],
    tweak: u32,
    expected: Vec<u8>,
}

fn vector(fixture: &Fixture, level: SecurityLevel) -> Vector {
    let lambda = level.bits();
    Vector {
        key: fixture.bytes(&format!("prg_tvs.key_{lambda}")),
        iv: fixture
            .bytes(&format!("prg_tvs.iv_{lambda}"))
            .try_into()
            .expect("16-byte iv"),
        tweak: u32::try_from(fixture.integer(&format!("prg_tvs.tweak_{lambda}")))
            .expect("32-bit tweak"),
        expected: fixture.bytes(&format!("prg_tvs.expected_{lambda}")),
    }
}

#[test]
fn every_prg_vector_is_reproduced_on_both_backends() {
    let fixture = Fixture::load("prg_tvs");
    for level in SecurityLevel::ALL {
        let tv = vector(&fixture, level);
        assert_eq!(tv.expected.len(), 14 * 16 + 8);
        for generator in [
            Prg::new(&tv.key).expect("valid key"),
            Prg::new_portable(&tv.key).expect("valid key"),
        ] {
            assert_eq!(generator.level(), level);
            let mut out = vec![0u8; tv.expected.len()];
            generator
                .fill(&tv.iv, tv.tweak, &mut out)
                .expect("short output");
            assert_eq!(out, tv.expected, "{level:?} {:?}", generator.backend());
        }
        let mut out = vec![0u8; tv.expected.len()];
        prg(&tv.key, &tv.iv, tv.tweak, 8 * out.len(), &mut out).expect("valid call");
        assert_eq!(out, tv.expected, "{level:?}");
    }
    fixture.assert_consumed("");
}

/// The upstream `test_prg_<lambda>_2_lambda` and `_4_lambda` cases: the dedicated
/// `2 * lambda`- and `4 * lambda`-bit generators are prefixes of the general one.
#[test]
fn vector_prefixes_cover_the_two_and_four_lambda_outputs() {
    let fixture = Fixture::load("prg_tvs");
    for level in SecurityLevel::ALL {
        let tv = vector(&fixture, level);
        let generator = Prg::new(&tv.key).expect("valid key");
        for bits in [2 * level.bits(), 4 * level.bits(), 750, 1070, 1, 129] {
            let mut out = vec![0u8; bits.div_ceil(8)];
            generator
                .fill_bits(&tv.iv, tv.tweak, bits, &mut out)
                .expect("exact buffer");
            let (last, head) = out.split_last().expect("non-empty");
            assert_eq!(head, &tv.expected[..head.len()]);
            let mask = 0xffu8 >> ((8 - bits % 8) % 8);
            assert_eq!(*last, tv.expected[head.len()] & mask, "{level:?} {bits}");
        }
    }
}

/// The vectors separate the specified tweak arithmetic (addition to word 3 modulo
/// `2^32`) from the plausible misreadings.
#[test]
fn the_vectors_pin_the_tweak_and_counter_layout() {
    let fixture = Fixture::load("prg_tvs");
    for level in SecurityLevel::ALL {
        let tv = vector(&fixture, level);
        let generator = Prg::new(&tv.key).expect("valid key");
        let run = |iv: &[u8; 16]| {
            let mut out = vec![0u8; tv.expected.len()];
            generator.fill(iv, 0, &mut out).expect("short output");
            out
        };
        let word = |index: usize| {
            u32::from_le_bytes(tv.iv[4 * index..4 * index + 4].try_into().expect("4 bytes"))
        };
        let with_word = |index: usize, value: u32| {
            let mut iv = tv.iv;
            iv[4 * index..4 * index + 4].copy_from_slice(&value.to_le_bytes());
            iv
        };
        // Specified: little-endian addition into word 3.
        assert_eq!(
            run(&with_word(3, word(3).wrapping_add(tv.tweak))),
            tv.expected
        );
        // Misreadings that the vector rejects: XOR instead of addition (when it
        // differs), big-endian addition, and the tweak in word 0.
        let xored = word(3) ^ tv.tweak;
        if xored != word(3).wrapping_add(tv.tweak) {
            assert_ne!(run(&with_word(3, xored)), tv.expected);
        }
        let big_endian =
            u32::from_be_bytes(tv.iv[12..].try_into().expect("4 bytes")).wrapping_add(tv.tweak);
        let mut iv = tv.iv;
        iv[12..].copy_from_slice(&big_endian.to_be_bytes());
        if iv != with_word(3, word(3).wrapping_add(tv.tweak)) {
            assert_ne!(run(&iv), tv.expected);
        }
        assert_ne!(
            run(&with_word(0, word(0).wrapping_add(tv.tweak))),
            tv.expected
        );
    }
}

#[test]
fn bad_arguments_are_rejected_with_typed_errors() {
    let fixture = Fixture::load("prg_tvs");
    let tv = vector(&fixture, SecurityLevel::L128);
    assert_eq!(
        Prg::new(&tv.key[..15]).map(|_| ()),
        Err(PrgError::InvalidSeedLength { actual: 15 })
    );
    let generator = Prg::new(&tv.key).expect("valid key");
    let mut out = [0u8; 3];
    assert_eq!(
        generator.fill_bits(&tv.iv, tv.tweak, 25, &mut out),
        Err(PrgError::InvalidOutputLength {
            bits: 25,
            expected: 4,
            actual: 3
        })
    );
    assert_eq!(
        Backend::DEFAULT == Backend::Accelerated,
        cfg!(feature = "accel")
    );
}
