//! Fresh-process CPU/absence controls for the real source-owned None bundle.
//!
//! This target deliberately requires genuine current absence. A future authentic
//! bundle approval needs a reviewed successor; these controls confer no GPU credit.

use ed25519_dalek::{Signer as _, SigningKey};
use iroha_accel::{GpuResourceLimits, ProcessResources, RegistryLimits, cuda::CudaProcess};
use ivm::bn254_vec::{self, FieldElem};

fn assert_no_native_owner(original: &'static ProcessResources) {
    assert!(std::ptr::eq(ProcessResources::get().unwrap(), original));
    assert!(CudaProcess::get().is_none());
    assert!(!ivm::cuda_available());
    assert_eq!(ivm::cuda_completion_snapshot(0).unwrap(), None);
    assert_eq!(original.usage(), Default::default());
}

fn direct_refusals_preserve_every_family_and_no_work_contract() {
    let left = [u32::MAX, 2, 7];
    let right = [1, 3, 4];
    for operation in [
        ivm::vadd32_cuda_into,
        ivm::vand_cuda_into,
        ivm::vxor_cuda_into,
        ivm::vor_cuda_into,
    ] {
        let mut destination = [0xa5a5_5a5a; 3];
        assert!(!operation(&left, &right, &mut destination));
        assert_eq!(destination, [0xa5a5_5a5a; 3]);
        assert!(operation(&[], &[], &mut []));
        assert!(!operation(&left, &right[..2], &mut destination));
        assert_eq!(destination, [0xa5a5_5a5a; 3]);
    }
    let mut wide = [0xaaaa_bbbb_cccc_dddd; 2];
    assert!(!ivm::vadd64_cuda_into(&[u64::MAX, 2], &[1, 3], &mut wide));
    assert_eq!(wide, [0xaaaa_bbbb_cccc_dddd; 2]);
    assert!(ivm::vadd64_cuda_into(&[], &[], &mut []));
    assert!(!ivm::vadd64_cuda_into(&[1], &[], &mut wide));

    let mut sha = [0x1234_5678; 8];
    assert!(!ivm::sha256_compress_cuda(&mut sha, &[0; 64]));
    assert_eq!(sha, [0x1234_5678; 8]);
    let mut keccak = [0x1234_5678_9abc_def0; 25];
    assert!(!ivm::keccak_f1600_cuda(&mut keccak));
    assert_eq!(keccak, [0x1234_5678_9abc_def0; 25]);

    let mut leaves = [[0xa5; 32]; 2];
    assert!(!ivm::sha256_leaves_cuda_into(&[[0; 64]; 2], &mut leaves));
    assert_eq!(leaves, [[0xa5; 32]; 2]);
    assert!(ivm::sha256_leaves_cuda_into(&[], &mut []));
    assert!(!ivm::sha256_leaves_cuda_into(&[[0; 64]], &mut leaves));
    assert_eq!(leaves, [[0xa5; 32]; 2]);
    assert_eq!(ivm::sha256_pairs_reduce_cuda(&[]), None);
    assert_eq!(ivm::sha256_pairs_reduce_cuda(&[[7; 32]]), Some([7; 32]));
    assert_eq!(ivm::sha256_pairs_reduce_cuda(&[[7; 32], [9; 32]]), None);

    let mut poseidon = [0x1234_5678_9abc_def0; 2];
    assert!(!ivm::poseidon2_cuda_many_into(
        &[(0, 1), (u64::MAX, 7)],
        &mut poseidon
    ));
    assert_eq!(poseidon, [0x1234_5678_9abc_def0; 2]);
    assert!(!ivm::poseidon6_cuda_many_into(
        &[[1, 2, 3, 4, 5, 6]; 2],
        &mut poseidon
    ));
    assert_eq!(poseidon, [0x1234_5678_9abc_def0; 2]);
    assert!(ivm::poseidon2_cuda_many_into(&[], &mut []));
    assert!(ivm::poseidon6_cuda_many_into(&[], &mut []));
    assert!(!ivm::poseidon2_cuda_many_into(&[(1, 2)], &mut poseidon));
    assert!(!ivm::poseidon6_cuda_many_into(&[[0; 6]], &mut poseidon));
    assert_eq!(ivm::poseidon2_cuda(7, 11), None);
    assert_eq!(ivm::poseidon6_cuda([1, 2, 3, 4, 5, 6]), None);

    let states = [[0x53; 16]; 2];
    let mut aes = [[0xa5; 16]; 2];
    for operation in [ivm::aesenc_batch_cuda_into, ivm::aesdec_batch_cuda_into] {
        assert!(!operation(&states, [0xca; 16], &mut aes));
        assert_eq!(aes, [[0xa5; 16]; 2]);
        assert!(operation(&[], [0; 16], &mut []));
        assert!(!operation(&states[..1], [0; 16], &mut aes));
    }
    for operation in [
        ivm::aesenc_rounds_batch_cuda_into,
        ivm::aesdec_rounds_batch_cuda_into,
    ] {
        assert!(!operation(&states, &[[0xca; 16], [0x35; 16]], &mut aes));
        assert_eq!(aes, [[0xa5; 16]; 2]);
        assert!(operation(&[], &[[0; 16]], &mut []));
        assert!(operation(&states, &[], &mut aes));
        assert_eq!(aes, states);
        aes = [[0xa5; 16]; 2];
        assert!(!operation(&states[..1], &[], &mut aes));
    }
    assert_eq!(ivm::aesenc_cuda(states[0], [0xca; 16]), None);
    assert_eq!(ivm::aesdec_cuda(states[0], [0xca; 16]), None);

    let a = [FieldElem::from_u64(17).0; 2];
    let b = [FieldElem::from_u64(29).0; 2];
    for operation in [
        ivm::bn254_add_batch_cuda_into,
        ivm::bn254_sub_batch_cuda_into,
        ivm::bn254_mul_batch_cuda_into,
    ] {
        let mut destination = [[0xa5; 4]; 2];
        assert!(!operation(&a, &b, &mut destination));
        assert_eq!(destination, [[0xa5; 4]; 2]);
        assert!(operation(&[], &[], &mut []));
        assert!(!operation(&a[..1], &b, &mut destination));
        assert!(!operation(&[bn254_vec::MODULUS; 2], &b, &mut destination));
        assert_eq!(destination, [[0xa5; 4]; 2]);
    }
    assert_eq!(ivm::bn254_add_cuda(a[0], b[0]), None);
    assert_eq!(ivm::bn254_sub_cuda(a[0], b[0]), None);
    assert_eq!(ivm::bn254_mul_cuda(a[0], b[0]), None);

    let mut signatures = [true; 2];
    assert!(!ivm::ed25519_verify_batch_cuda_into(
        &[[0; 64]; 2],
        &[[0; 32]; 2],
        &[[0; 32]; 2],
        &mut signatures
    ));
    assert_eq!(signatures, [true; 2]);
    assert!(ivm::ed25519_verify_batch_cuda_into(&[], &[], &[], &mut []));
    assert!(!ivm::ed25519_verify_batch_cuda_into(
        &[[0; 64]],
        &[[0; 32]; 2],
        &[[0; 32]; 2],
        &mut signatures
    ));
    assert_eq!(signatures, [true; 2]);
    assert_eq!(ivm::ed25519_verify_cuda(&[0; 64], &[0; 64], &[0; 32]), None);

    let mut hi = [2, 1, 2];
    let mut lo = [7, 9, 3];
    assert_eq!(ivm::bitonic_sort_pairs(&mut hi, &mut lo), None);
    assert_eq!(hi, [2, 1, 2]);
    assert_eq!(lo, [7, 9, 3]);
    assert_eq!(ivm::bitonic_sort_pairs(&mut [], &mut []), Some(()));
    assert_eq!(ivm::bitonic_sort_pairs(&mut [7], &mut [9]), Some(()));
    assert_eq!(ivm::bitonic_sort_pairs(&mut hi, &mut lo[..2]), None);
    assert_eq!(hi, [2, 1, 2]);
    assert_eq!(lo, [7, 9, 3]);
}

#[derive(Debug, PartialEq)]
struct OrdinaryResults {
    vectors: [[u32; 4]; 6],
    sha: [u32; 8],
    keccak: [u64; 25],
    merkle: [u8; 32],
    poseidon: [u64; 2],
    aes: [[u8; 16]; 2],
    bn254: [[u64; 4]; 3],
    signatures: [bool; 2],
}
fn ordinary_results() -> OrdinaryResults {
    let left = [u32::MAX, 0x8000_0000, 7, 17];
    let right = [1, 0x8000_0000, 4, 11];
    let mut vectors = [[0; 4]; 6];
    for (output, operation) in vectors.iter_mut().zip([
        ivm::vadd32_auto_into,
        ivm::vadd64_auto_into,
        ivm::vand_auto_into,
        ivm::vxor_auto_into,
        ivm::vor_auto_into,
    ]) {
        operation(&left, &right, output);
    }
    ivm::vrot32_auto_into(&left, 31, &mut vectors[5]);
    let mut sha = [0x1234_5678; 8];
    ivm::sha256_compress(&mut sha, &[0x51; 64]);
    let mut keccak = [0; 25];
    ivm::keccak_f1600(&mut keccak);
    let merkle =
        ivm::ByteMerkleTree::root_from_bytes_accel(b"exact original CPU Merkle relation", 7)
            .unwrap();
    let poseidon = [
        ivm::poseidon2(u64::MAX, 11),
        ivm::poseidon6([u64::MAX, 1, 2, 3, 4, 5]),
    ];
    let aes = [
        ivm::aesenc([0x53; 16], [0xca; 16]),
        ivm::aesdec([0x53; 16], [0xca; 16]),
    ];
    let a = FieldElem::from_u64(17);
    let b = FieldElem::from_u64(29);
    let bn254 = [
        bn254_vec::add(a, b).0,
        bn254_vec::sub(a, b).0,
        bn254_vec::mul(a, b).0,
    ];
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let message = b"genuine absence CPU signature";
    let valid = ivm::signature::Ed25519BatchItem {
        message,
        signature: key.sign(message).to_bytes(),
        public_key: key.verifying_key().to_bytes(),
    };
    let mut invalid = valid;
    invalid.signature[40] ^= 1;
    let mut signatures = [false; 2];
    assert!(ivm::signature::verify_ed25519_batch_items_into(
        &[valid, invalid],
        &mut signatures
    ));
    assert_eq!(signatures, [true, false]);
    OrdinaryResults {
        vectors,
        sha,
        keccak,
        merkle,
        poseidon,
        aes,
        bn254,
        signatures,
    }
}

#[test]
fn real_absence_preserves_all_families_cpu_results_original_pool_and_file_policy() {
    assert!(
        CudaProcess::get().is_none(),
        "this target owns one fresh process"
    );
    let scalar = ivm::AccelerationConfig {
        enable_simd: false,
        enable_metal: false,
        enable_cuda: false,
        ..Default::default()
    };
    ivm::set_acceleration_config(scalar);
    let original = ProcessResources::get().expect("original configured shared owner");
    assert_no_native_owner(original);
    let expected = ordinary_results();
    let automatic = ivm::AccelerationConfig {
        enable_metal: false,
        enable_cuda: true,
        ..Default::default()
    };
    for max_gpus in [None, Some(0), Some(1)] {
        ivm::set_acceleration_config(ivm::AccelerationConfig {
            max_gpus,
            ..automatic
        });
        assert!(!ivm::cuda_disabled());
        direct_refusals_preserve_every_family_and_no_work_contract();
        assert_eq!(ordinary_results(), expected);
        assert_no_native_owner(original);
    }
    let zero = RegistryLimits {
        metadata_bytes: 0,
        devices: 0,
        discovery_ordinals: 0,
        modules: 0,
        streams: 0,
        artifact_bytes: 0,
        work: GpuResourceLimits {
            host_bytes: 0,
            pinned_bytes: 0,
            device_bytes: 0,
            in_flight: 0,
        },
    };
    ivm::set_acceleration_config(ivm::AccelerationConfig {
        resource_limits: zero,
        ..automatic
    });
    direct_refusals_preserve_every_family_and_no_work_contract();
    assert_eq!(ordinary_results(), expected);
    assert_no_native_owner(original);
    ivm::set_acceleration_config(scalar);
    assert!(ivm::cuda_disabled());
    assert_eq!(
        ivm::cuda_last_error_message().as_deref(),
        Some("disabled by configuration")
    );
    ivm::set_acceleration_config(automatic);
    ivm::reset_cuda_backend_for_tests();
    assert!(!ivm::cuda_disabled());
    direct_refusals_preserve_every_family_and_no_work_contract();
    assert_eq!(ordinary_results(), expected);
    assert_no_native_owner(original);
}
