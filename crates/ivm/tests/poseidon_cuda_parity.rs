//! Native Poseidon parity probes; mandatory physical qualification uses cuda_hardware.
#![cfg(feature = "cuda")]
/// Exact completion increases required by these native parity tests.
#[path = "support/cuda_completion_increase.rs"]
mod cuda_completion_increase;
/// Shared exact-owner CUDA completion controls.
#[path = "support/cuda_completions.rs"]
pub mod cuda_completions;

use ivm::{
    poseidon2_cuda, poseidon2_cuda_many_into, poseidon2_simd, poseidon6_cuda,
    poseidon6_cuda_many_into, poseidon6_simd,
};
fn ensure_cuda_backend() -> bool {
    if !ivm::cuda_available() {
        eprintln!("CUDA hardware unavailable; skipping Poseidon CUDA parity tests");
        return false;
    }
    true
}
fn unwrap_or_skip<T>(label: &str, value: Option<T>) -> Option<T> {
    match value {
        Some(v) => Some(v),
        None => {
            eprintln!("{label} backend disabled at runtime; skipping remaining checks");
            None
        }
    }
}
#[test]
fn poseidon2_cuda_matches_scalar_vectors() {
    if !ensure_cuda_backend() {
        return;
    }
    let samples = [
        (0u64, 0u64),
        (1u64, 0u64),
        (0u64, 1u64),
        (1u64, 1u64),
        (u64::MAX, u64::MAX),
        (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
    ];
    for &(a, b) in &samples {
        let expected = poseidon2_simd(a, b);
        let Some(actual) = unwrap_or_skip("Poseidon2 CUDA", poseidon2_cuda(a, b)) else {
            return;
        };
        assert_eq!(
            actual, expected,
            "Poseidon2 CUDA mismatch for inputs a={a:#x}, b={b:#x}"
        );
    }
}
#[test]
fn poseidon6_cuda_matches_scalar_vectors() {
    if !ensure_cuda_backend() {
        return;
    }
    let samples = [
        [0u64; 6],
        [1, 2, 3, 4, 5, 6],
        [1, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0],
        [u64::MAX; 6],
        [
            0x0123_4567_89ab_cdef,
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
            0xdddd_eeee_ffff_0001,
            0x1357_9bdf_2468_ace0,
        ],
    ];
    for inputs in samples {
        let expected = poseidon6_simd(inputs);
        let Some(actual) = unwrap_or_skip("Poseidon6 CUDA", poseidon6_cuda(inputs)) else {
            return;
        };
        assert_eq!(
            actual, expected,
            "Poseidon6 CUDA mismatch for inputs {inputs:?}"
        );
    }
}
#[test]
fn poseidon2_cuda_many_matches_scalar_vectors() {
    if !ensure_cuda_backend() {
        return;
    }
    let samples = [
        (0u64, 0u64),
        (1u64, 0u64),
        (0u64, 1u64),
        (1u64, 1u64),
        (0xfeed_beef_dead_cafe, 0xc0de_cafe_dead_beef),
    ];
    let expected: Vec<u64> = samples.iter().map(|&(a, b)| poseidon2_simd(a, b)).collect();
    let mut actual = vec![0; samples.len()];
    let before = cuda_completions::capture();
    if !poseidon2_cuda_many_into(&samples, &mut actual) {
        return;
    }
    assert!(
        cuda_completion_increase::increased(&before, ivm::CudaKernel::Poseidon2),
        "native batch parity requires a completed CUDA kernel"
    );
    assert_eq!(actual, expected, "Poseidon2 CUDA batch mismatch");
}
#[test]
fn poseidon6_cuda_many_matches_scalar_vectors() {
    if !ensure_cuda_backend() {
        return;
    }
    let samples = [
        [0u64; 6],
        [1, 2, 3, 4, 5, 6],
        [
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
            0xdddd_eeee_ffff_0001,
            0x1357_9bdf_2468_ace0,
            0xf0f0_0f0f_f00f_f00f,
        ],
    ];
    let expected: Vec<u64> = samples
        .iter()
        .map(|&inputs| poseidon6_simd(inputs))
        .collect();
    let mut actual = vec![0; samples.len()];
    let before = cuda_completions::capture();
    if !poseidon6_cuda_many_into(&samples, &mut actual) {
        return;
    }
    assert!(
        cuda_completion_increase::increased(&before, ivm::CudaKernel::Poseidon6),
        "native batch parity requires a completed CUDA kernel"
    );
    assert_eq!(actual, expected, "Poseidon6 CUDA batch mismatch");
}
