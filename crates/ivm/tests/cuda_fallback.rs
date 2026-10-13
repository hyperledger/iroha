//! Ensure CUDA-gated helpers degrade to scalar paths when the `cuda` feature is
//! disabled. This guards the optional backend so non-GPU builds remain stable.
#![cfg(not(feature = "cuda"))]
#[test]
fn cuda_helpers_fall_back_when_disabled() {
    assert_eq!(
        (ivm::cuda_completion_snapshot(0)).expect("expected successful fixture result"),
        None
    );
    assert_eq!(
        (ivm::cuda_completion_snapshot(usize::MAX)).expect("expected successful fixture result"),
        None
    );
    // Poseidon helpers return None without CUDA.
    assert!(ivm::poseidon2_cuda(0, 0).is_none());
    assert!(ivm::poseidon2_cuda_many_into(&[], &mut []));
    assert!(ivm::poseidon6_cuda([0; 6]).is_none());
    assert!(ivm::poseidon6_cuda_many_into(&[], &mut []));
    // Hashing helpers return false/None without CUDA.
    let mut keccak_state = [0u64; 25];
    assert!(!ivm::keccak_f1600_cuda(&mut keccak_state));
    let mut sha_state = [0u32; 8];
    assert!(!ivm::sha256_compress_cuda(&mut sha_state, &[0u8; 64]));
    assert!(!ivm::sha256_leaves_cuda_into(&[[0u8; 64]], &mut [[0; 32]]));
    assert!(ivm::sha256_pairs_reduce_cuda(&[[0u8; 32], [1u8; 32]]).is_none());
    // AES helpers return None without CUDA.
    assert!(ivm::aesenc_cuda([0u8; 16], [0u8; 16]).is_none());
    assert!(ivm::aesdec_cuda([0u8; 16], [0u8; 16]).is_none());
    assert!(!ivm::aesenc_batch_cuda_into(
        &[[0u8; 16]],
        [0u8; 16],
        &mut [[0; 16]]
    ));
    assert!(!ivm::aesdec_batch_cuda_into(
        &[[0u8; 16]],
        [0u8; 16],
        &mut [[0; 16]]
    ));
    // Sorting helper returns None without CUDA.
    let mut hi = [5u64, 3, 5, 3, 3];
    let mut lo = [7u64, 9, 1, 2, 1];
    assert!(ivm::bitonic_sort_pairs(&mut hi, &mut lo).is_none());
    assert_eq!(hi, [5u64, 3, 5, 3, 3]);
    assert_eq!(lo, [7u64, 9, 1, 2, 1]);
    // Vector CUDA entrypoints report no publication without CUDA.
    assert!(!ivm::vadd32_cuda_into(&[1u32, 2], &[3u32, 4], &mut [0; 2]));
    assert!(!ivm::vadd64_cuda_into(&[1u64, 2], &[3u64, 4], &mut [0; 2]));
    assert!(!ivm::vand_cuda_into(&[1u32, 2], &[3u32, 4], &mut [0; 2]));
    assert!(!ivm::vxor_cuda_into(&[1u32, 2], &[3u32, 4], &mut [0; 2]));
    assert!(!ivm::vor_cuda_into(&[1u32, 2], &[3u32, 4], &mut [0; 2]));
    // Explicit native helpers report no execution without a backend. Ordinary
    // batch APIs compute through their CPU fallback independently of this status.
    assert!(ivm::bn254_add_cuda([0; 4], [0; 4]).is_none());
    assert!(ivm::bn254_sub_cuda([0; 4], [0; 4]).is_none());
    assert!(ivm::bn254_mul_cuda([0; 4], [0; 4]).is_none());
    assert_eq!(ivm::ed25519_verify_cuda(&[], &[0; 64], &[0; 32]), None);
    assert_eq!(
        {
            let signatures = &[[0; 64]];
            let public_keys = &[[0; 32]];
            let hrams = &[[0; 32]];
            let mut output = vec![true; signatures.len()];
            if ivm::ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                Some(output)
            } else {
                assert!(
                    output.iter().all(|value| *value),
                    "refusal must preserve destination"
                );
                None
            }
        },
        None
    );
    assert_eq!(
        {
            let signatures = &[];
            let public_keys = &[];
            let hrams = &[];
            let mut output = vec![true; signatures.len()];
            if ivm::ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                Some(output)
            } else {
                assert!(
                    output.iter().all(|value| *value),
                    "refusal must preserve destination"
                );
                None
            }
        },
        Some(Vec::new())
    );
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x53; 32]);
    let message = b"cuda fallback ed25519 valid work";
    let signature = ed25519_dalek::Signer::sign(&signing_key, message).to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();
    let hram = [0xA5; 32];
    assert!(ivm::ed25519_verify_cuda(message, &signature, &public_key).is_none());
    assert!(
        {
            let signatures = &[signature];
            let public_keys = &[public_key];
            let hrams = &[hram];
            let mut output = vec![true; signatures.len()];
            if ivm::ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                Some(output)
            } else {
                assert!(
                    output.iter().all(|value| *value),
                    "refusal must preserve destination"
                );
                None
            }
        }
        .is_none()
    );
}
