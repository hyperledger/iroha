//! Small ordinary workloads use the qualified CPU path without GPU launches.

/// Shared exact-owner CUDA completion controls.
#[path = "support/cuda_completions.rs"]
pub mod cuda_completions;

use ed25519_dalek::{Signer as _, SigningKey};
use ivm::{Ed25519BatchItem, MetalKernel, bn254_vec};

#[test]
fn tiny_crypto_workloads_preserve_results_without_gpu_dispatch() {
    let kernels = [
        MetalKernel::Keccak,
        MetalKernel::AesEnc,
        MetalKernel::AesDec,
        MetalKernel::AesEncBatch,
        MetalKernel::AesDecBatch,
        MetalKernel::AesEncRounds,
        MetalKernel::AesDecRounds,
        MetalKernel::Ed25519,
    ];
    let metal_before = kernels.map(ivm::metal_completed_dispatches);
    let cuda_before = cuda_completions::capture();

    let mut keccak = [0u64; 25];
    ivm::keccak_f1600(&mut keccak);
    assert_eq!(keccak[0], 0xf125_8f79_40e1_dde7);

    let states: Vec<[u8; 16]> = (0..8)
        .map(|index| std::array::from_fn(|lane| (index * 19 + lane) as u8))
        .collect();
    let keys = [[0x15; 16], [0xa7; 16]];
    let mut encrypted = vec![[0; 16]; states.len()];
    assert!(ivm::aesenc_n_rounds_many_into(&states, &[], &mut encrypted));
    assert_eq!(encrypted, states);
    assert!(ivm::aesdec_n_rounds_many_into(&states, &[], &mut encrypted));
    assert_eq!(encrypted, states);
    assert!(ivm::aesenc_n_rounds_many_into(
        &states,
        &keys,
        &mut encrypted
    ));
    let expected_encrypted: Vec<_> = states
        .iter()
        .copied()
        .map(|state| keys.into_iter().fold(state, ivm::aesenc_impl))
        .collect();
    assert_eq!(encrypted, expected_encrypted);
    let mut decrypted = vec![[0; 16]; states.len()];
    assert!(ivm::aesdec_n_rounds_many_into(
        &encrypted,
        &keys,
        &mut decrypted
    ));
    let expected_decrypted: Vec<_> = encrypted
        .iter()
        .copied()
        .map(|state| keys.into_iter().fold(state, ivm::aesdec_impl))
        .collect();
    assert_eq!(decrypted, expected_decrypted);

    let left = bn254_vec::FieldElem::from_u64(29);
    let right = bn254_vec::FieldElem::from_u64(37);
    assert_eq!(
        bn254_vec::add(left, right),
        bn254_vec::add_scalar(left, right)
    );
    assert_eq!(
        bn254_vec::sub(left, right),
        bn254_vec::sub_scalar(left, right)
    );
    assert_eq!(
        bn254_vec::mul(left, right),
        bn254_vec::mul_scalar(left, right)
    );
    assert_eq!(ivm::poseidon2(7, 11), ivm::poseidon2_simd(7, 11));
    assert_eq!(
        ivm::poseidon6([1, 2, 3, 4, 5, 6]),
        ivm::poseidon6_simd([1, 2, 3, 4, 5, 6])
    );
    let poseidon2_inputs = [(7, 11); 8];
    let mut outputs2 = [0; 8];
    assert!(ivm::poseidon2_many_into(&poseidon2_inputs, &mut outputs2));
    assert_eq!(
        outputs2.as_slice(),
        poseidon2_inputs
            .iter()
            .map(|&(a, b)| ivm::poseidon2_simd(a, b))
            .collect::<Vec<_>>()
    );
    let poseidon6_inputs = [[1, 2, 3, 4, 5, 6]; 8];
    let mut outputs6 = [0; 8];
    assert!(ivm::poseidon6_many_into(&poseidon6_inputs, &mut outputs6));
    assert_eq!(
        outputs6.as_slice(),
        poseidon6_inputs
            .iter()
            .map(|&input| ivm::poseidon6_simd(input))
            .collect::<Vec<_>>()
    );

    let signer = SigningKey::from_bytes(&[0x43; 32]);
    let message = b"tiny IVM signature batch";
    let signature = signer.sign(message).to_bytes();
    let public_key = signer.verifying_key().to_bytes();
    let items = vec![
        Ed25519BatchItem {
            message,
            signature,
            public_key,
        };
        8
    ];
    assert_eq!(
        {
            let items = &items;
            let mut output = vec![false; items.len()];
            assert!(ivm::verify_ed25519_batch_items_into(items, &mut output));
            output
        },
        vec![true; 8]
    );

    assert_eq!(kernels.map(ivm::metal_completed_dispatches), metal_before);
    assert!(cuda_completions_unchanged(&cuda_before));
}

/// Verify no kernel gained credit, including policy owners initialized after capture.
fn cuda_completions_unchanged(before: &[Option<ivm::CudaCompletionSnapshot>]) -> bool {
    let after = cuda_completions::capture();
    before.len() == after.len()
        && before
            .iter()
            .zip(after)
            .all(|(previous, current)| match (previous, current) {
                (Some(previous), Some(current)) => previous == &current,
                (None, Some(current)) => ivm::CudaKernel::ALL
                    .into_iter()
                    .all(|kernel| current.completed(kernel) == 0),
                (None, None) => true,
                (Some(_), None) => false,
            })
}
