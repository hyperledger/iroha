//! Caller-owned BN254 parity, malformed-input and explicit hardware controls.

/// Exact completion increases required by these native parity tests.
#[path = "support/cuda_completion_increase.rs"]
mod cuda_completion_increase;
/// Shared exact-owner CUDA completion controls.
#[path = "support/cuda_completions.rs"]
pub mod cuda_completions;

use halo2curves::{bn256::Fr, ff::Field};
use ivm::bn254_vec::{self, FieldElem};

type Batch = fn(&[[u64; 4]], &[[u64; 4]], &mut [[u64; 4]]) -> bool;
type Relation = fn(Fr, Fr) -> Fr;

fn operands() -> ([[u64; 4]; 257], [[u64; 4]; 257]) {
    let mut left = Fr::from(17);
    let mut right = -Fr::ONE;
    let lhs = std::array::from_fn(|index| {
        left = left.square() + Fr::from(index as u64);
        FieldElem::from_fr(left).0
    });
    let rhs = std::array::from_fn(|index| {
        right = right.square() - Fr::from(index as u64 + 1);
        FieldElem::from_fr(right).0
    });
    (lhs, rhs)
}

fn check_parity(batch: Batch, relation: Relation, native: Option<ivm::CudaKernel>) {
    let (left, right) = operands();
    let before = (left, right);
    let mut output = [[u64::MAX; 4]; 257];
    for count in [0, 1, 127, 128, 129, 257] {
        let dispatches = native.map(|_| cuda_completions::capture());
        assert!(batch(&left[..count], &right[..count], &mut output[..count]));
        if let Some(kernel) = native.filter(|_| count != 0) {
            assert!(
                cuda_completion_increase::increased(dispatches.as_ref().unwrap(), kernel),
                "native parity requires actual completed dispatches"
            );
        }
        for index in 0..count {
            let expected = relation(
                FieldElem(left[index]).to_fr(),
                FieldElem(right[index]).to_fr(),
            );
            assert_eq!(FieldElem(output[index]).to_fr(), expected);
        }
        assert_eq!((left, right), before);
    }
}

#[test]
fn ordinary_batches_match_field_relation_across_launch_boundaries() {
    check_parity(bn254_vec::add_batch_into, |a, b| a + b, None);
    check_parity(bn254_vec::sub_batch_into, |a, b| a - b, None);
    check_parity(bn254_vec::mul_batch_into, |a, b| a * b, None);
}

#[test]
fn every_public_batch_rejects_bad_shapes_and_noncanonical_values_unchanged() {
    for batch in [
        bn254_vec::add_batch_into as Batch,
        bn254_vec::sub_batch_into,
        bn254_vec::mul_batch_into,
        ivm::bn254_add_batch_cuda_into,
        ivm::bn254_sub_batch_cuda_into,
        ivm::bn254_mul_batch_cuda_into,
    ] {
        let valid = [[0; 4]; 2];
        let invalid = [[0; 4], bn254_vec::MODULUS];
        let sentinel = [[u64::MAX; 4]; 2];
        let mut output = sentinel;
        for (left, right) in [
            (&valid[..1], &valid[..]),
            (&valid[..], &valid[..1]),
            (&invalid[..], &valid[..]),
            (&valid[..], &invalid[..]),
        ] {
            assert!(!batch(left, right, &mut output));
            assert_eq!(output, sentinel);
        }
        assert!(!batch(&valid, &valid, &mut output[..1]));
        assert_eq!(output, sentinel);
        assert!(batch(&[], &[], &mut []));
    }
}

#[cfg(feature = "cuda")]
#[test]
#[ignore = "Requires a qualified physical CUDA device; run explicitly on the candidate hardware"]
fn native_batches_execute_each_kernel_and_match_full_width_field_relation() {
    assert!(
        ivm::cuda_available(),
        "CUDA qualification cannot pass on CPU fallback"
    );
    check_parity(
        ivm::bn254_add_batch_cuda_into,
        |a, b| a + b,
        Some(ivm::CudaKernel::BnAdd),
    );
    check_parity(
        ivm::bn254_sub_batch_cuda_into,
        |a, b| a - b,
        Some(ivm::CudaKernel::BnSub),
    );
    check_parity(
        ivm::bn254_mul_batch_cuda_into,
        |a, b| a * b,
        Some(ivm::CudaKernel::BnMul),
    );
}
