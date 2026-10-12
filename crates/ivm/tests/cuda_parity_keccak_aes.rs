//! CUDA parity tests: Keccak and AES
//!
//! - Keccak: if CUDA is available, compares `keccak_f1600_cuda` vs scalar `keccak_f1600`.
//! - AES: compares `aesenc_cuda`/`aesdec_cuda` vs CPU round implementations.
/// Exact completion increases required by these native parity tests.
#[cfg(feature = "cuda")]
#[path = "support/cuda_completion_increase.rs"]
mod cuda_completion_increase;
/// Shared exact-owner CUDA completion controls.
#[cfg(feature = "cuda")]
#[path = "support/cuda_completions.rs"]
pub mod cuda_completions;

#[cfg(feature = "cuda")]
#[test]
fn keccak_parity_cuda_vs_scalar() {
    if !ivm::cuda_available() {
        eprintln!("CUDA not available; skipping keccak parity test");
        return;
    }
    let mut s_cpu = [0u64; 25];
    for i in 0..25 {
        s_cpu[i] = (i as u64) * 0x0101_0101_0101_0101u64;
    }
    let mut s_cuda = s_cpu;
    ivm::keccak_f1600(&mut s_cpu);
    assert!(ivm::keccak_f1600_cuda(&mut s_cuda));
    assert_eq!(s_cpu, s_cuda, "CUDA keccak must match scalar");
}
#[cfg(feature = "cuda")]
#[test]
fn aes_parity_cuda_vs_cpu_round() {
    if !ivm::cuda_available() {
        eprintln!("CUDA unavailable; skipping native AES parity test");
        return;
    }
    let before = cuda_completions::capture();
    let state = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let rk = [
        0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67,
        0x98,
    ];
    let cpu_enc = ivm::aesenc(state, rk);
    let cuda_enc = ivm::aesenc_cuda(state, rk).expect("aesenc_cuda should return Some");
    assert_eq!(cpu_enc, cuda_enc, "AESENC parity");
    let cpu_dec = ivm::aesdec(cpu_enc, rk);
    let cuda_dec = ivm::aesdec_cuda(cuda_enc, rk).expect("aesdec_cuda should return Some");
    assert_eq!(cpu_dec, cuda_dec, "AESDEC parity");
    assert!(
        cuda_completion_increase::increased(&before, ivm::CudaKernel::AesEnc)
            && cuda_completion_increase::increased(&before, ivm::CudaKernel::AesDec),
        "native parity requires a completed CUDA dispatch"
    );
}
