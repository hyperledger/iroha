//! Upstream known answers, strict field admission and Core field-library parity.

use super::*;
use halo2curves::ff::Field;
use iroha_pasta::{Fp as CoreFp, Fq as CoreFq};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

thread_local! {
    static CLEARS: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn observe_clear(all_zero: bool) {
    CLEARS.with(|clears| clears.borrow_mut().push(all_zero));
}

fn reset_clears() {
    CLEARS.with(|clears| clears.borrow_mut().clear());
}

fn assert_cleared(minimum: usize) {
    CLEARS.with(|clears| {
        let clears = clears.borrow();
        assert!(clears.len() >= minimum, "missing clearing observation");
        assert!(clears.iter().all(|zero| *zero), "owned field cell retained");
    });
}

fn fields<const N: usize>(bytes: &[u8]) -> [[u8; 32]; N] {
    assert_eq!(bytes.len(), N * 32);
    std::array::from_fn(|i| bytes[32 * i..32 * (i + 1)].try_into().unwrap())
}

fn reference_permutation<F: PrimeField<Repr = [u8; 32]>>(
    input: &[[u8; 32]; 3],
    encoded: &[u8; PARAMETER_LENGTH],
) -> [[u8; 32]; 3] {
    // Uses Core's distinct field implementation and a separate direct loop.
    let constants: Vec<F> = encoded
        .chunks_exact(32)
        .map(|bytes| Option::<F>::from(F::from_repr(bytes.try_into().unwrap())).unwrap())
        .collect();
    let mut state = input.map(|bytes| Option::<F>::from(F::from_repr(bytes)).unwrap());
    for round in 0..64 {
        for column in 0..3 {
            state[column] += constants[round * 3 + column];
            if matches!(round, 0..=3 | 60..=63) || column == 0 {
                state[column] = state[column].pow_vartime([5]);
            }
        }
        state = std::array::from_fn(|row| {
            (0..3).fold(F::ZERO, |sum, col| {
                sum + constants[192 + row * 3 + col] * state[col]
            })
        });
    }
    state.map(|value| value.to_repr())
}

fn reference_hash<F: PrimeField<Repr = [u8; 32]>>(
    input: &[[u8; 32]],
    encoded: &[u8; PARAMETER_LENGTH],
) -> [u8; 32] {
    assert!(!input.is_empty());
    let mut state = [F::ZERO, F::ZERO, F::from_u128((input.len() as u128) << 64)];
    for chunk in input.chunks(2) {
        for (cell, bytes) in state.iter_mut().zip(chunk) {
            *cell += Option::<F>::from(F::from_repr(*bytes)).unwrap();
        }
        state = reference_permutation::<F>(&state.map(|value| value.to_repr()), encoded)
            .map(|bytes| Option::<F>::from(F::from_repr(bytes)).unwrap());
    }
    state[0].to_repr()
}

#[test]
fn canonical_parameter_and_vector_fingerprints_are_pinned() {
    for (bytes, expected) in [
        (
            fp::PARAMETER_BYTES.as_slice(),
            "a9a13cf048dcb1fdc90989307b50514fc8454fc53853f704d4a5b395b9b98812",
        ),
        (
            fq::PARAMETER_BYTES.as_slice(),
            "d9109b12201af2f77bbc633144d986007fcf290ada7bf51cbb1ba79172108a16",
        ),
        (
            include_bytes!("fp_permute_kats.bin").as_slice(),
            "160528fb278c1962889d5a05e705f0ecaaf34c8452297dd44794a7dc412419e6",
        ),
        (
            include_bytes!("fq_permute_kats.bin").as_slice(),
            "ed40801dcf95d2b0ad2fa21a6cf2e9e60f7add5f40146082eae2be40ccbb4245",
        ),
        (
            include_bytes!("fp_hash_kats.bin").as_slice(),
            "d2a6b9e89ae5f3a4d081cc8c7d7832cfffd2697a817c3f737dd50aa5f409c1fe",
        ),
        (
            include_bytes!("fq_hash_kats.bin").as_slice(),
            "29338f2785060486e3619345c7b9b08b58b4c932a4d0f0c0bf971e816c48202e",
        ),
    ] {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
    }
}

#[test]
fn all_upstream_permutation_vectors_match_both_native_field_libraries() {
    for (bytes, parameters, native, reference) in [
        (
            include_bytes!("fp_permute_kats.bin"),
            fp::PARAMETER_BYTES,
            fp::permute as fn(&mut [[u8; 32]; 3]) -> Result<(), Error>,
            reference_permutation::<CoreFp>
                as fn(&[[u8; 32]; 3], &[u8; PARAMETER_LENGTH]) -> [[u8; 32]; 3],
        ),
        (
            include_bytes!("fq_permute_kats.bin"),
            fq::PARAMETER_BYTES,
            fq::permute,
            reference_permutation::<CoreFq>,
        ),
    ] {
        assert_eq!(bytes.len(), 11 * 192);
        for vector in bytes.chunks_exact(192) {
            let input = fields::<3>(&vector[..96]);
            let expected = fields::<3>(&vector[96..]);
            let mut state = input;
            native(&mut state).unwrap();
            assert_eq!(state, expected);
            assert_eq!(reference(&input, parameters), expected);
        }
    }
}

#[test]
fn all_upstream_hash_vectors_match_both_native_field_libraries() {
    for (bytes, parameters, native, reference) in [
        (
            include_bytes!("fp_hash_kats.bin"),
            fp::PARAMETER_BYTES,
            fp::hash::<2> as fn(&[[u8; 32]; 2]) -> Result<[u8; 32], Error>,
            reference_hash::<CoreFp> as fn(&[[u8; 32]], &[u8; PARAMETER_LENGTH]) -> [u8; 32],
        ),
        (
            include_bytes!("fq_hash_kats.bin"),
            fq::PARAMETER_BYTES,
            fq::hash::<2>,
            reference_hash::<CoreFq>,
        ),
    ] {
        assert_eq!(bytes.len(), 11 * 96);
        for vector in bytes.chunks_exact(96) {
            let input = fields::<2>(&vector[..64]);
            let expected: [u8; 32] = vector[64..].try_into().unwrap();
            assert_eq!(native(&input).unwrap(), expected);
            assert_eq!(reference(&input, parameters), expected);
        }
    }
}

fn boundary<F: PrimeField>() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let last = encode(&(-F::ONE));
    let mut modulus = last;
    add_one(&mut modulus);
    let mut past = modulus;
    add_one(&mut past);
    (last, modulus, past)
}

fn add_one(bytes: &mut [u8; 32]) {
    for byte in bytes {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return;
        }
    }
    panic!("test input overflow");
}

#[test]
fn canonical_decode_boundaries_reject_modular_aliases_and_preserve_error_input() {
    assert_eq!(boundary::<Fp>(), boundary::<CoreFp>());
    assert_eq!(boundary::<Fq>(), boundary::<CoreFq>());
    for ((last, modulus, past), native, hashing) in [
        (
            boundary::<Fp>(),
            fp::permute as fn(&mut [[u8; 32]; 3]) -> Result<(), Error>,
            fp::hash::<1> as fn(&[[u8; 32]; 1]) -> Result<[u8; 32], Error>,
        ),
        (boundary::<Fq>(), fq::permute, fq::hash::<1>),
    ] {
        for accepted in [[0; 32], last] {
            let mut values = [accepted; 3];
            native(&mut values).unwrap();
            hashing(&[accepted]).unwrap();
        }
        for bad in [modulus, past, [0xff; 32]] {
            for column in 0..3 {
                let mut state = [[1; 32]; 3];
                state[column] = bad;
                let before = state;
                assert_eq!(native(&mut state), Err(Error::NonCanonicalField));
                assert_eq!(state, before);
            }
            assert_eq!(hashing(&[bad]), Err(Error::NonCanonicalField));
        }
    }
}

fn check_length<const L: usize>() {
    let input = std::array::from_fn(|index| encode(&Fp::from((index as u64) + 17)));
    assert_eq!(
        fp::hash::<L>(&input).unwrap(),
        reference_hash::<CoreFp>(&input, fp::PARAMETER_BYTES)
    );
    assert_eq!(
        fq::hash::<L>(&input).unwrap(),
        reference_hash::<CoreFq>(&input, fq::PARAMETER_BYTES)
    );
}

#[test]
fn odd_even_lengths_padding_and_field_identity_are_distinct() {
    check_length::<1>();
    check_length::<2>();
    check_length::<3>();
    check_length::<4>();
    check_length::<5>();
    check_length::<8>();
    check_length::<9>();
    check_length::<22>();
    check_length::<262>();
    check_length::<2054>();
    assert_eq!(fp::hash(&[]), Err(Error::EmptyInput));
    assert_eq!(fq::hash(&[]), Err(Error::EmptyInput));
    let one = encode(&Fp::ONE);
    let zero = [0; 32];
    assert_ne!(fp::hash(&[one]).unwrap(), fp::hash(&[one, zero]).unwrap());
    assert_ne!(fq::hash(&[one]).unwrap(), fq::hash(&[one, zero]).unwrap());
    assert_ne!(fp::hash(&[one]).unwrap(), fq::hash(&[one]).unwrap());
    assert_ne!(
        fp::hash(&[one, zero]).unwrap(),
        fp::hash(&[zero, one]).unwrap()
    );
}

#[test]
fn owned_field_cells_clear_on_success_partial_decode_error_and_unwind() {
    reset_clears();
    fp::hash(&[encode(&Fp::ONE); 3]).unwrap();
    fq::hash(&[encode(&Fq::ONE); 2]).unwrap();
    assert_cleared(5);

    reset_clears();
    let mut partial = [encode(&Fp::ONE); 4];
    partial[3] = [0xff; 32];
    assert_eq!(fp::hash(&partial), Err(Error::NonCanonicalField));
    let mut permutation = [encode(&Fq::ONE); 3];
    permutation[2] = [0xff; 32];
    assert_eq!(fq::permute(&mut permutation), Err(Error::NonCanonicalField));
    assert_cleared(3);

    reset_clears();
    assert!(
        std::panic::catch_unwind(|| {
            let mut state = OwnedState::<Fp>::zero();
            state.0.0 = [Fp::ONE; 3];
            let mut mixed = OwnedState::<Fq>::zero();
            mixed.0.0 = [Fq::ONE; 3];
            panic!("exercise owned scratch unwinding");
        })
        .is_err()
    );
    assert_cleared(2);
}

#[test]
fn public_errors_are_descriptive_without_exposing_inputs() {
    assert_eq!(
        Error::NonCanonicalField.to_string(),
        "noncanonical Pasta field element"
    );
    assert_eq!(
        Error::EmptyInput.to_string(),
        "Pasta constant-length hashing requires a nonempty input"
    );
    assert_eq!(
        Error::LengthOverflow.to_string(),
        "Pasta constant-length hash input exceeds the u64 domain"
    );
}
