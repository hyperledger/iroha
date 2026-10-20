//! BN254 Poseidon vectors regenerated outside this crate.
//!
//! `scripts/zk_bn254_poseidon_reference.py` regenerates the 648 fixed field
//! elements with its own Grain LFSR and Cauchy construction, runs its own
//! permutation over them and writes `bn254_v1_reference_vectors.txt`. These
//! tests run the Rust owner over the same inputs. Agreement shows that the two
//! implementations compute the same function; it does not qualify the parameter
//! set (see `bn254_poseidon` in `specs/zk_primitive_workloads.json`).

use super::*;

const VECTORS: &str = include_str!("bn254_v1_reference_vectors.txt");

fn field(hex: &str) -> Fr {
    Option::<Fr>::from(Fr::from_repr(bytes32(hex).into())).expect("vector field is canonical")
}

fn bytes32(hex: &str) -> [u8; 32] {
    let bytes = bytes(hex);
    bytes
        .as_slice()
        .try_into()
        .expect("vector field has 32 bytes")
}

fn bytes(hex: &str) -> Vec<u8> {
    if hex == "-" {
        return Vec::new();
    }
    assert!(hex.len().is_multiple_of(2), "hex length must be even");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("vector hex is ASCII");
            u8::from_str_radix(text, 16).expect("vector hex digit")
        })
        .collect()
}

fn rows(kind: &str) -> Vec<Vec<&'static str>> {
    VECTORS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split(' ').collect::<Vec<_>>())
        .filter(|row| row[0] == kind)
        .collect()
}

#[test]
fn width3_permutation_matches_the_independent_reference() {
    let rows = rows("permute3");
    let names = rows.iter().map(|row| row[1]).collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "zero",
            "sequential",
            "all_p_minus_one",
            "unit_0",
            "unit_1",
            "unit_2",
            "seeded_0",
            "seeded_1"
        ]
    );
    for row in rows {
        assert_eq!(row.len(), 8, "permute3 row shape");
        let mut state = [field(row[2]), field(row[3]), field(row[4])];
        poseidon3_permute(&mut state);
        assert_eq!(
            state.map(field_to_bytes),
            [bytes32(row[5]), bytes32(row[6]), bytes32(row[7])],
            "permutation vector {}",
            row[1]
        );
    }
}

#[test]
fn two_input_helper_matches_the_independent_reference() {
    let rows = rows("hash2");
    assert_eq!(rows.len(), 4);
    for row in rows {
        let a = row[1].parse::<u64>().expect("hash2 first limb");
        let b = row[2].parse::<u64>().expect("hash2 second limb");
        let expected = bytes32(row[3]);
        assert_eq!(hash2_bytes(a, b), expected, "hash2({a}, {b})");
        assert_eq!(
            hash2_u64(a, b),
            u64::from_le_bytes(expected[..8].try_into().expect("eight bytes")),
            "hash2_u64 is the low limb of hash2_bytes"
        );
    }
}

#[test]
fn six_input_helper_matches_the_independent_reference() {
    let rows = rows("hash6");
    assert_eq!(rows.len(), 6);
    for row in rows {
        let inputs: [u64; 6] =
            core::array::from_fn(|index| row[1 + index].parse::<u64>().expect("hash6 limb"));
        let expected = bytes32(row[7]);
        assert_eq!(hash6_bytes(inputs), expected, "hash6({inputs:?})");
        assert_eq!(
            hash6_u64(inputs),
            u64::from_le_bytes(expected[..8].try_into().expect("eight bytes")),
            "hash6_u64 is the low limb of hash6_bytes"
        );
    }
}

#[test]
fn byte_sponge_matches_the_independent_reference_and_separates_domains() {
    let rows = rows("hash_bytes");
    assert_eq!(rows.len(), 8);
    let mut outputs = Vec::new();
    for row in &rows {
        let input = bytes(row[1]);
        let expected = bytes32(row[2]);
        assert_eq!(hash_bytes(&input), expected, "hash_bytes({})", row[1]);
        let mut streaming = PoseidonByteHasher::new();
        streaming.update(&input);
        assert_eq!(streaming.finalize(), expected, "streaming {}", row[1]);
        outputs.push(expected);
    }
    // The fixture holds two inputs that differ only in their domain suffix and
    // two that differ only by a trailing zero byte; no two outputs may agree.
    for (index, left) in outputs.iter().enumerate() {
        for right in &outputs[index + 1..] {
            assert_ne!(left, right, "distinct inputs must not collide");
        }
    }
}

#[test]
fn non_canonical_field_encodings_are_rejected() {
    let rows = rows("non_canonical");
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert!(
            bool::from(Fr::from_repr(bytes32(row[1]).into()).is_none()),
            "{} is not below the BN254 scalar modulus",
            row[1]
        );
    }
}

/// The selected width-three bank is the published permutation, not an alias.
#[test]
fn selected_width3_table_is_the_published_bn254_instantiation() {
    assert_eq!((FULL_ROUNDS, WIDTH3_PARTIAL_ROUNDS), (8, 57));
    let rows = rows("published_width3_first_round_constant");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        bn254_poseidon_params_width3().round_constants[0][0],
        bytes32(rows[0][1])
    );
}

#[test]
fn fixed_arity_capacity_output_and_second_absorption_are_binding() {
    let inputs = [1, 2, 3, 4, 5, 6];
    let mut wrong_tag = [Fr::ZERO, Fr::from(1), Fr::from(2)];
    poseidon3_permute(&mut wrong_tag);
    assert_ne!(hash2_bytes(1, 2), field_to_bytes(wrong_tag[1]));
    let mut correct = [Fr::from_u128(2_u128 << 64), Fr::from(1), Fr::from(2)];
    poseidon3_permute(&mut correct);
    assert_eq!(hash2_bytes(1, 2), field_to_bytes(correct[1]));
    assert_ne!(hash2_bytes(1, 2), field_to_bytes(correct[0]));
    let mut six = [
        Fr::from_u128(6_u128 << 64),
        Fr::from(1),
        Fr::from(2),
        Fr::from(3),
        Fr::from(4),
        Fr::from(5),
    ];
    poseidon6_permute(&mut six);
    assert_ne!(hash6_bytes(inputs), field_to_bytes(six[1]));
    six[1] += Fr::from(6);
    poseidon6_permute(&mut six);
    assert_eq!(hash6_bytes(inputs), field_to_bytes(six[1]));
    assert_ne!(hash6_bytes(inputs), field_to_bytes(six[0]));
    assert_ne!(hash6_bytes(inputs), hash6_bytes([1, 2, 3, 4, 5, 0]));
    assert_ne!(hash2_bytes(1, 2), hash6_bytes([1, 2, 0, 0, 0, 0]));
}
