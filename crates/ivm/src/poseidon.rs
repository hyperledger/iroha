//! Lightweight Poseidon hash adapters used by VM opcodes.
//!
//! The permutations operate on BN254 field elements via
//! [`bn254_vec`] which dispatches to SIMD backends when available.
//! The H.2 fixed-arity mode matches the canonical native owner. Tests exercise
//! the complete state on scalar, SSE2, AVX2, AVX-512 and NEON implementations.
//! A native bridge is not a constrained Halo2 proof. Opcode outputs are truncated
//! to 64 bits and must not be used as commitments.
use crate::bn254_vec::{self as field_vec, FieldElem};
use ff::PrimeField;
use halo2curves::bn256::Fr;
use std::sync::OnceLock;
#[cfg(any(feature = "cuda", test))]
pub(crate) mod golden;
fn to_u64(f: Fr) -> u64 {
    let repr = f.to_repr();
    let bytes = repr.as_ref();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
use iroha_zkp_halo2::poseidon::{
    WIDTH3_PARTIAL_ROUNDS, WIDTH3_ROUNDS, WIDTH6_PARTIAL_ROUNDS, WIDTH6_ROUNDS,
};
const FULL_ROUNDS_HALF: usize = 4;
type Parameters<const W: usize, const R: usize> = ([[FieldElem; W]; R], [[FieldElem; W]; W]);
fn fixed_field(bytes: [u8; 32]) -> FieldElem {
    let field = FieldElem(std::array::from_fn(|i| {
        u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("fixed limb"))
    }));
    assert!(field.is_canonical(), "canonical V1 parameter field");
    field
}
fn fixed_parameters<const W: usize, const R: usize>(
    params: iroha_zkp_halo2::poseidon::Bn254PoseidonParams<W, R>,
) -> Parameters<W, R> {
    (
        params.round_constants.map(|row| row.map(fixed_field)),
        params.mds.map(|row| row.map(fixed_field)),
    )
}
pub(crate) fn poseidon2_params() -> (
    &'static [[FieldElem; 3]; WIDTH3_ROUNDS],
    &'static [[FieldElem; 3]; 3],
) {
    static PARAMS: OnceLock<Parameters<3, WIDTH3_ROUNDS>> = OnceLock::new();
    let params = PARAMS.get_or_init(|| {
        fixed_parameters(iroha_zkp_halo2::poseidon::bn254_poseidon_params_width3())
    });
    (&params.0, &params.1)
}
pub(crate) fn poseidon6_params() -> (
    &'static [[FieldElem; 6]; WIDTH6_ROUNDS],
    &'static [[FieldElem; 6]; 6],
) {
    static PARAMS: OnceLock<Parameters<6, WIDTH6_ROUNDS>> = OnceLock::new();
    let params = PARAMS.get_or_init(|| {
        fixed_parameters(iroha_zkp_halo2::poseidon::bn254_poseidon_params_width6())
    });
    (&params.0, &params.1)
}
pub fn poseidon2(a: u64, b: u64) -> u64 {
    poseidon2_impl(a, b)
}
/// Hash a batch of two-input BN254 Poseidon values in order, using CUDA when available.
pub fn poseidon2_many_into(inputs: &[(u64, u64)], destination: &mut [u64]) -> bool {
    if inputs.len() != destination.len() {
        return false;
    }
    batch_into(
        inputs,
        destination,
        crate::cuda::poseidon2_auto_into,
        |(a, b)| poseidon2_impl(a, b),
    )
}
// A refused native attempt may have written nothing or a diagnostic prefix;
// ordinary fallback always recomputes the complete destination from original inputs.
fn batch_into<T: Copy>(
    inputs: &[T],
    destination: &mut [u64],
    attempt: impl FnOnce(&[T], &mut [u64]) -> bool,
    cpu: impl Fn(T) -> u64,
) -> bool {
    if inputs.len() != destination.len() {
        return false;
    }
    if inputs.is_empty() || attempt(inputs, destination) {
        return true;
    }
    for (result, &input) in destination.iter_mut().zip(inputs) {
        *result = cpu(input);
    }
    true
}

#[doc(hidden)]
pub fn poseidon2_simd(a: u64, b: u64) -> u64 {
    poseidon2_impl(a, b)
}
fn poseidon2_impl(a: u64, b: u64) -> u64 {
    let mut state = [
        FieldElem([0, 2, 0, 0]),
        FieldElem::from_u64(a),
        FieldElem::from_u64(b),
    ];
    permute2_with(&mut state, field_vec::add, field_vec::mul);
    to_u64(state[1].to_fr())
}
fn permute2_with(
    state: &mut [FieldElem; 3],
    add: impl Fn(FieldElem, FieldElem) -> FieldElem,
    mul: impl Fn(FieldElem, FieldElem) -> FieldElem,
) {
    let (round_constants, mds) = poseidon2_params();
    let rf_half = FULL_ROUNDS_HALF;
    let rp = WIDTH3_PARTIAL_ROUNDS;
    let sbox = |x: FieldElem| {
        let x2 = mul(x, x);
        let x4 = mul(x2, x2);
        mul(x4, x)
    };
    let apply_mds = |st: &mut [FieldElem; 3]| {
        let mut new_state = [FieldElem([0u64; 4]); 3];
        for (i, row) in mds.iter().enumerate() {
            let mut acc = FieldElem([0u64; 4]);
            for (m, s) in row.iter().zip(st.iter()) {
                let prod = mul(*m, *s);
                acc = add(acc, prod);
            }
            new_state[i] = acc;
        }
        *st = new_state;
    };
    for rc in round_constants.iter().take(rf_half) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = sbox(add(*s, rc[i]));
        }
        apply_mds(state);
    }
    for rc in round_constants.iter().skip(rf_half).take(rp) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = add(*s, rc[i]);
        }
        state[0] = sbox(state[0]);
        apply_mds(state);
    }
    let start = rf_half + rp;
    for rc in round_constants.iter().skip(start).take(rf_half) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = sbox(add(*s, rc[i]));
        }
        apply_mds(state);
    }
}
pub fn poseidon6(inputs: [u64; 6]) -> u64 {
    poseidon6_impl(inputs)
}
/// Hash a batch of Poseidon6 inputs in order, using CUDA acceleration when available.
pub fn poseidon6_many_into(inputs: &[[u64; 6]], destination: &mut [u64]) -> bool {
    if inputs.len() != destination.len() {
        return false;
    }
    batch_into(
        inputs,
        destination,
        crate::cuda::poseidon6_auto_into,
        poseidon6_impl,
    )
}
#[doc(hidden)]
pub fn poseidon6_simd(inputs: [u64; 6]) -> u64 {
    poseidon6_impl(inputs)
}
fn poseidon6_impl(inputs: [u64; 6]) -> u64 {
    let mut state = [
        FieldElem([0, 6, 0, 0]),
        FieldElem::from_u64(inputs[0]),
        FieldElem::from_u64(inputs[1]),
        FieldElem::from_u64(inputs[2]),
        FieldElem::from_u64(inputs[3]),
        FieldElem::from_u64(inputs[4]),
    ];
    permute6_with(&mut state, field_vec::add, field_vec::mul);
    state[1] = field_vec::add(state[1], FieldElem::from_u64(inputs[5]));
    permute6_with(&mut state, field_vec::add, field_vec::mul);
    to_u64(state[1].to_fr())
}
fn permute6_with(
    state: &mut [FieldElem; 6],
    add: impl Fn(FieldElem, FieldElem) -> FieldElem,
    mul: impl Fn(FieldElem, FieldElem) -> FieldElem,
) {
    let (round_constants, mds) = poseidon6_params();
    let rf_half = FULL_ROUNDS_HALF;
    let rp = WIDTH6_PARTIAL_ROUNDS;
    let sbox = |x: FieldElem| {
        let x2 = mul(x, x);
        let x4 = mul(x2, x2);
        mul(x4, x)
    };
    let apply_mds = |st: &mut [FieldElem; 6]| {
        let mut new_state = [FieldElem([0u64; 4]); 6];
        for (i, row) in mds.iter().enumerate() {
            let mut acc = FieldElem([0u64; 4]);
            for (m, s) in row.iter().zip(st.iter()) {
                let prod = mul(*m, *s);
                acc = add(acc, prod);
            }
            new_state[i] = acc;
        }
        *st = new_state;
    };
    for rc in round_constants.iter().take(rf_half) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = sbox(add(*s, rc[i]));
        }
        apply_mds(state);
    }
    for rc in round_constants.iter().skip(rf_half).take(rp) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = add(*s, rc[i]);
        }
        state[0] = sbox(state[0]);
        apply_mds(state);
    }
    let start = rf_half + rp;
    for rc in round_constants.iter().skip(start).take(rf_half) {
        for (i, s) in state.iter_mut().enumerate() {
            *s = sbox(add(*s, rc[i]));
        }
        apply_mds(state);
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn ordinary_batches_preserve_known_answers_and_order() {
        let two = golden::TWO.map(|(a, b, _)| (a, b));
        let six = golden::SIX.map(|(input, _)| input);
        let mut result = [u64::MAX; 5];
        assert!(poseidon2_many_into(&two, &mut result));
        assert_eq!(result, golden::TWO.map(|(_, _, output)| output));
        assert!(poseidon6_many_into(&six, &mut result));
        assert_eq!(result, golden::SIX.map(|(_, output)| output));
        let untouched = result;
        assert!(!poseidon2_many_into(&two, &mut result[..4]));
        assert!(!poseidon6_many_into(&six, &mut result[..4]));
        assert_eq!(result, untouched);
        assert!(poseidon2_many_into(&[], &mut []));
        assert!(poseidon6_many_into(&[], &mut []));
    }

    #[test]
    fn refused_native_prefix_is_entirely_recomputed_from_original_inputs() {
        let inputs = [0u64, 1, u64::MAX];
        let mut output = [7; 3];
        assert!(batch_into(
            &inputs,
            &mut output,
            |original, destination| {
                assert_eq!(original, inputs);
                destination[0] = 999;
                false
            },
            |value| value.wrapping_add(11)
        ));
        assert_eq!(output, [11, 12, 10]);
    }

    #[test]
    fn batch_shape_refusal_and_empty_input_do_not_attempt_native_work() {
        let mut output = [17];
        assert!(!batch_into(
            &[1, 2],
            &mut output,
            |_, _| panic!("shape"),
            |_: u64| panic!("shape")
        ));
        assert_eq!(output, [17]);
        assert!(batch_into::<u64>(
            &[],
            &mut [],
            |_, _| panic!("empty"),
            |_| panic!("empty")
        ));
        assert!(batch_into(
            &[1u64],
            &mut output,
            |_, out| {
                out[0] = 91;
                true
            },
            |_| panic!("already complete")
        ));
        assert_eq!(output, [91]);
    }
}

#[cfg(test)]
#[path = "poseidon/parameter_tests.rs"]
pub(crate) mod parameter_tests;
