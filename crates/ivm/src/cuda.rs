#![cfg_attr(not(feature = "cuda"), allow(dead_code))]
#[cfg(any(feature = "cuda", test))]
#[path = "cuda/output_validation.rs"]
mod output_validation;
#[path = "cuda_policy.rs"]
pub(crate) mod policy;
#[path = "cuda/receipts.rs"]
pub(crate) mod receipts;
pub use policy::Kernel as CudaKernel;
pub use receipts::{CudaCompletionError, CudaCompletionSnapshot};
#[cfg(feature = "cuda")]
#[path = "cuda/vector_api.rs"]
mod vectors;
#[cfg(feature = "cuda")]
pub use vectors::{
    vadd32_cuda_into, vadd64_cuda_into, vand_cuda_into, vor_cuda_into, vxor_cuda_into,
};
#[cfg(feature = "cuda")]
#[path = "cuda/hash_api.rs"]
mod hashes;
#[cfg(feature = "cuda")]
pub use hashes::{keccak_f1600_cuda, sha256_compress_cuda};
#[cfg(feature = "cuda")]
#[path = "cuda/aes_api.rs"]
mod aes_batches;
#[cfg(feature = "cuda")]
pub(crate) use aes_batches::attempt as aes_batch_attempt;
#[cfg(feature = "cuda")]
pub use aes_batches::{
    aesdec_batch_cuda_into, aesdec_cuda, aesdec_rounds_batch_cuda_into, aesenc_batch_cuda_into,
    aesenc_cuda, aesenc_rounds_batch_cuda_into,
};
#[cfg(feature = "cuda")]
#[path = "cuda/merkle_api.rs"]
mod merkle;
#[cfg(feature = "cuda")]
pub(crate) use merkle::{sha256_leaf_chunks_cuda_attempt, sha256_merkle_root_cuda};
#[cfg(feature = "cuda")]
pub use merkle::{sha256_leaves_cuda_into, sha256_pairs_reduce_cuda};
#[cfg(feature = "cuda")]
#[path = "cuda/poseidon_api.rs"]
mod poseidons;
#[cfg(feature = "cuda")]
pub(crate) use poseidons::{poseidon2_auto_into, poseidon6_auto_into};
#[cfg(feature = "cuda")]
pub use poseidons::{
    poseidon2_cuda, poseidon2_cuda_many_into, poseidon6_cuda, poseidon6_cuda_many_into,
};
#[cfg(not(feature = "cuda"))]
pub(crate) fn poseidon2_auto_into(_inputs: &[(u64, u64)], _destination: &mut [u64]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub(crate) fn poseidon6_auto_into(_inputs: &[[u64; 6]], _destination: &mut [u64]) -> bool {
    false
}
#[cfg(feature = "cuda")]
#[path = "cuda/bn254_api.rs"]
mod bn254_batches;
#[cfg(feature = "cuda")]
pub(crate) use bn254_batches::bn254_batch_auto_into;
#[cfg(feature = "cuda")]
pub use bn254_batches::{
    bn254_add_batch_cuda_into, bn254_add_cuda, bn254_mul_batch_cuda_into, bn254_mul_cuda,
    bn254_sub_batch_cuda_into, bn254_sub_cuda,
};
#[cfg(not(feature = "cuda"))]
pub(crate) fn bn254_batch_auto_into(
    _operation: crate::bn254_vec::BatchOperation,
    _left: &[[u64; 4]],
    _right: &[[u64; 4]],
    _destination: &mut [[u64; 4]],
    _cpu: &'static dyn crate::field_dispatch::FieldArithmetic,
) -> bool {
    false
}
#[cfg(feature = "cuda")]
#[path = "cuda/signature_api.rs"]
mod signatures;
#[cfg(feature = "cuda")]
pub(crate) use signatures::ed25519_items_cuda_into;
#[cfg(feature = "cuda")]
pub use signatures::{ed25519_verify_batch_cuda_into, ed25519_verify_cuda};
#[cfg(feature = "cuda")]
#[path = "cuda/bitonic_api.rs"]
mod bitonic;
#[cfg(feature = "cuda")]
pub use bitonic::bitonic_sort_pairs;
#[cfg(feature = "cuda")]
mod imp {
    #[cfg(test)]
    use super::aes_batches::{
        aesdec_batch_cuda_into, aesdec_cuda, aesenc_batch_cuda_into, aesenc_cuda,
    };
    #[cfg(test)]
    use super::bitonic::bitonic_sort_pairs;
    #[cfg(test)]
    use super::bn254_batches::{
        bn254_add_batch_cuda_into, bn254_add_cuda, bn254_mul_batch_cuda_into, bn254_mul_cuda,
        bn254_sub_batch_cuda_into, bn254_sub_cuda,
    };
    #[cfg(test)]
    use super::hashes::{keccak_f1600_cuda, sha256_compress_cuda};
    #[cfg(test)]
    use super::merkle::{sha256_leaves_cuda_into, sha256_pairs_reduce_cuda};
    use super::policy::Kernel;
    #[cfg(test)]
    use super::poseidons::{
        poseidon2_cuda, poseidon2_cuda_many_into, poseidon6_cuda, poseidon6_cuda_many_into,
    };
    #[cfg(test)]
    use super::signatures::{ed25519_verify_batch_cuda_into, ed25519_verify_cuda};
    #[cfg(test)]
    use super::vectors::{
        vadd32_cuda_into, vadd64_cuda_into, vand_cuda_into, vor_cuda_into, vxor_cuda_into,
    };
    #[cfg(test)]
    use crate::sha256_ref::sha256_compress_scalar_ref as sha256_scalar_ref;
    use std::cell::Cell;
    use std::sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    static CUDA_DISABLED: AtomicBool = AtomicBool::new(false);
    static CUDA_FORCED_DISABLED: AtomicBool = AtomicBool::new(false);
    static CUDA_LAST_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    thread_local! {
        static CUDA_SELFTEST_RUNNING: Cell<bool> = const { Cell::new(false) };
        static CUDA_EXECUTION_ATTEMPTS: Cell<u64> = const { Cell::new(0) };
    }
    fn cuda_error_slot() -> &'static Mutex<Option<String>> {
        CUDA_LAST_ERROR.get_or_init(|| Mutex::new(None))
    }
    fn cuda_selftest_running() -> bool {
        CUDA_SELFTEST_RUNNING.with(Cell::get)
    }
    pub(super) struct SelftestRunningGuard;
    impl SelftestRunningGuard {
        pub(super) fn enter() -> Option<Self> {
            let already_running = CUDA_SELFTEST_RUNNING.with(|running| {
                let was_running = running.get();
                if !was_running {
                    running.set(true);
                }
                was_running
            });
            if already_running { None } else { Some(Self) }
        }
    }
    impl Drop for SelftestRunningGuard {
        fn drop(&mut self) {
            CUDA_SELFTEST_RUNNING.with(|running| running.set(false));
        }
    }
    #[cfg(test)]
    fn trace_cuda_selftest(step: &str) {
        if std::env::var_os("IVM_CUDA_SELFTEST_TRACE").is_some() {
            eprintln!("ivm cuda selftest: {step}");
        }
    }
    fn set_cuda_status_message(message: Option<String>) {
        if let Ok(mut guard) = cuda_error_slot().lock() {
            *guard = message;
        }
    }
    fn record_cuda_disable(reason: impl Into<String>) {
        let message = reason.into();
        let scoped = crate::cuda_dispatch::quarantine_current_kernel();
        if !scoped {
            CUDA_DISABLED.store(true, Ordering::SeqCst);
        }
        if let Ok(mut guard) = cuda_error_slot().lock() {
            *guard = Some(message.clone());
        }
        eprintln!("ivm: cuda acceleration quarantined: {message}");
    }
    pub(super) fn record_completed_cuda_dispatch(
        kernel: Kernel,
        artifact: iroha_accel::PtxArtifact,
    ) {
        if !cuda_selftest_running() {
            crate::cuda_dispatch::record_completed(kernel, artifact);
        }
    }
    pub(super) fn record_completed_cuda_compound(
        kernel: Kernel,
        artifact: iroha_accel::PtxArtifact,
        other: Kernel,
        other_artifact: iroha_accel::PtxArtifact,
    ) {
        if !cuda_selftest_running() {
            crate::cuda_dispatch::record_completed_compound(
                kernel,
                artifact,
                other,
                other_artifact,
            );
        }
    }
    pub(crate) fn record_cuda_attempt() {
        if !cuda_selftest_running() {
            CUDA_EXECUTION_ATTEMPTS.with(|count| count.set(count.get().saturating_add(1)));
        }
    }
    #[cfg(test)]
    fn ed25519_cuda_selftest() -> bool {
        super::signatures::admit()
    }
    #[cfg(test)]
    fn bn254_cuda_selftest() -> bool {
        crate::cuda_dispatch::with_task_scope(0x0f0f_0f0f_0000_0060, || {
            [Kernel::BnAdd, Kernel::BnSub, Kernel::BnMul]
                .into_iter()
                .all(super::bn254_batches::admit)
        })
    }
    pub(super) fn cuda_policy_allows_attempt() -> bool {
        if cuda_disabled() {
            return false;
        }
        for name in ["IVM_DISABLE_CUDA", "IVM_FORCE_CUDA_SELFTEST_FAIL"] {
            if crate::dev_env::dev_env_flag(name) && std::env::var(name).as_deref() == Ok("1") {
                record_cuda_disable(format!(
                    "CUDA disabled by developer self-test override {name}"
                ));
                return false;
            }
        }
        true
    }
    pub(super) fn ensure_cuda_kernel(kernel: Kernel) -> bool {
        if cuda_selftest_running() {
            return !cuda_disabled() && crate::cuda_dispatch::current_kernel() == Some(kernel);
        }
        if !cuda_policy_allows_attempt() {
            return false;
        }
        if !crate::cuda_artifact::eligible() {
            return false;
        }
        match kernel {
            Kernel::BnAdd | Kernel::BnSub | Kernel::BnMul => super::bn254_batches::admit(kernel),
            Kernel::AesEnc | Kernel::AesDec | Kernel::AesEncFused | Kernel::AesDecFused => {
                super::aes_batches::admit(kernel)
            }
            Kernel::Ed25519 => super::signatures::admit(),
            Kernel::ShaLeaves | Kernel::ShaPairs => super::merkle::admit(kernel),
            Kernel::Poseidon2 | Kernel::Poseidon6 => super::poseidons::admit(kernel),
            Kernel::Sha256 | Kernel::Keccak => super::hashes::admit(kernel),
            Kernel::Add32 | Kernel::Add64 | Kernel::And | Kernel::Xor | Kernel::Or => {
                super::vectors::admit(kernel)
            }
            Kernel::Bitonic => super::bitonic::admit(),
        }
    }

    // Availability means at least one admitted kernel on a usable device. Every
    // actual operation independently admits its own kernel on the selected device.
    fn ensure_cuda_selftest() -> bool {
        if cuda_selftest_running() {
            return false;
        }
        crate::cuda_dispatch::with_task_scope(0, || Kernel::ALL.into_iter().any(ensure_cuda_kernel))
    }

    pub fn cuda_last_error_message() -> Option<String> {
        cuda_error_slot()
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }
    pub fn cuda_disabled() -> bool {
        CUDA_FORCED_DISABLED.load(Ordering::SeqCst) || CUDA_DISABLED.load(Ordering::SeqCst)
    }
    pub fn cuda_available() -> bool {
        if !ensure_cuda_selftest() {
            return false;
        }
        crate::cuda_dispatch::usable_device_count() > 0
            && !CUDA_FORCED_DISABLED.load(Ordering::SeqCst)
            && !CUDA_DISABLED.load(Ordering::SeqCst)
    }
    pub fn set_cuda_enabled(enabled: bool) {
        CUDA_FORCED_DISABLED.store(!enabled, Ordering::SeqCst);
        if enabled {
            CUDA_DISABLED.store(false, Ordering::SeqCst);

            set_cuda_status_message(None);
        } else {
            CUDA_DISABLED.store(true, Ordering::SeqCst);
            set_cuda_status_message(Some("disabled by configuration".to_owned()));
        }
        let config = crate::acceleration_config();
        crate::cuda_dispatch::configure(!cuda_disabled() && config.enable_cuda, config.max_gpus);
    }
    #[doc(hidden)]
    pub fn reset_cuda_backend_for_tests() {
        CUDA_DISABLED.store(false, Ordering::SeqCst);
        CUDA_FORCED_DISABLED.store(false, Ordering::SeqCst);

        set_cuda_status_message(None);
        let config = crate::acceleration_config();
        crate::cuda_dispatch::configure(!cuda_disabled() && config.enable_cuda, config.max_gpus);
    }

    #[cfg(test)]
    fn vadd64_cuda_selftest() -> bool {
        let a = [0xffff_ffff, (0x8000_0000u64 << 32) | 1];
        let b = [(1u64 << 32) | 1, (0x7fff_ffffu64 << 32) | 0xffff_ffff];
        let expected = [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])];
        let mut output = [0; 2];
        vadd64_cuda_into(&a, &b, &mut output) && output == expected
    }
    #[cfg(test)]
    fn bit_ops_cuda_selftest() -> bool {
        let lhs = [0xffff_0000u32, 0x1234_5678, 0x0f0f_0f0f, 0xaaaa_5555];
        let rhs = [0x00ff_ff00u32, 0xf0f0_f0f0, 0x3333_cccc, 0x5555_aaaa];
        let mut output = [0; 4];
        vand_cuda_into(&lhs, &rhs, &mut output)
            && output == std::array::from_fn(|i| lhs[i] & rhs[i])
            && vxor_cuda_into(&lhs, &rhs, &mut output)
            && output == std::array::from_fn(|i| lhs[i] ^ rhs[i])
            && vor_cuda_into(&lhs, &rhs, &mut output)
            && output == std::array::from_fn(|i| lhs[i] | rhs[i])
    }
    #[cfg(test)]
    fn aes_batch_cuda_selftest() -> bool {
        let states = [
            [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ],
            [
                0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                0x22, 0x11, 0x00,
            ],
        ];
        let rk = [
            0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
            0x67, 0x98,
        ];
        let expected_enc: Vec<[u8; 16]> = states
            .iter()
            .map(|&state| crate::aes::aesenc_impl(state, rk))
            .collect();
        let expected_dec: Vec<[u8; 16]> = states
            .iter()
            .map(|&state| crate::aes::aesdec_impl(state, rk))
            .collect();
        let mut output = [[0; 16]; 2];
        aesenc_batch_cuda_into(&states, rk, &mut output)
            && output.as_slice() == expected_enc
            && aesdec_batch_cuda_into(&states, rk, &mut output)
            && output.as_slice() == expected_dec
    }

    #[cfg(test)]
    fn sha256_leaves_cuda_selftest() -> bool {
        let mut block_a = [0u8; 64];
        block_a[0] = b'a';
        block_a[1] = b'b';
        block_a[2] = b'c';
        block_a[3] = 0x80;
        block_a[63] = 24;
        let mut block_b = [0u8; 64];
        block_b[0] = b'n';
        block_b[1] = b'o';
        block_b[2] = b'r';
        block_b[3] = b'i';
        block_b[4] = b't';
        block_b[5] = b'o';
        block_b[6] = 0x80;
        block_b[63] = 48;
        let blocks = [block_a, block_b];
        let expected: Vec<[u8; 32]> = blocks
            .iter()
            .map(|block| {
                let mut state = [
                    0x6a09e667u32,
                    0xbb67ae85,
                    0x3c6ef372,
                    0xa54ff53a,
                    0x510e527f,
                    0x9b05688c,
                    0x1f83d9ab,
                    0x5be0cd19,
                ];
                sha256_scalar_ref(&mut state, block);
                let mut digest = [0u8; 32];
                for (index, word) in state.iter().enumerate() {
                    digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                digest
            })
            .collect();
        let mut output = [[0; 32]; 2];
        sha256_leaves_cuda_into(&blocks, &mut output) && output.as_slice() == expected
    }
    #[cfg(test)]
    fn sha256_pairs_reduce_cuda_selftest() -> bool {
        fn cpu_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let mut state = [
                0x6a09e667u32,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut block = [0u8; 64];
            block[..32].copy_from_slice(left);
            block[32..].copy_from_slice(right);
            sha256_scalar_ref(&mut state, &block);
            let mut pad = [0u8; 64];
            pad[0] = 0x80;
            pad[62] = 0x02;
            pad[63] = 0x00;
            sha256_scalar_ref(&mut state, &pad);
            let mut out = [0u8; 32];
            for (index, word) in state.iter().enumerate() {
                out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }
        let mut d0 = [0u8; 32];
        let mut d1 = [0u8; 32];
        let mut d2 = [0u8; 32];
        for (index, byte) in d0.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in d1.iter_mut().enumerate() {
            *byte = 0x40 + index as u8;
        }
        for (index, byte) in d2.iter_mut().enumerate() {
            *byte = 0x80 + index as u8;
        }
        let digests = [d0, d1, d2];
        let first = cpu_pair(&digests[0], &digests[1]);
        let expected = cpu_pair(&first, &digests[2]);
        sha256_pairs_reduce_cuda(&digests) == Some(expected)
    }
    #[cfg(all(test, feature = "cuda"))]
    mod tests {
        use super::*;
        use std::sync::atomic::Ordering;
        fn with_cuda_selftest_running_for_tests<T>(func: impl FnOnce() -> T) -> T {
            struct ResetGuard(bool);
            impl Drop for ResetGuard {
                fn drop(&mut self) {
                    CUDA_SELFTEST_RUNNING.with(|running| running.set(self.0));
                }
            }
            let previous = CUDA_SELFTEST_RUNNING.with(|running| {
                let old = running.get();
                running.set(true);
                old
            });
            let _reset = ResetGuard(previous);
            func()
        }
        #[test]
        fn poseidon_kernel_reports_round_errors_without_disabling_backend() {
            let disabled_before = CUDA_DISABLED.load(Ordering::SeqCst);
            if !ensure_cuda_selftest() {
                assert!(super::super::poseidons::fault_probe(false).is_none());
                assert_eq!(CUDA_DISABLED.load(Ordering::SeqCst), disabled_before);
                return;
            }
            let Some(status) = super::super::poseidons::fault_probe(false) else {
                return;
            };
            assert_eq!(status[0], 3, "kernel must report invalid round count");
            assert_eq!(
                CUDA_DISABLED.load(Ordering::SeqCst),
                disabled_before,
                "fault probe must not disable the backend"
            );
        }
        #[test]
        fn nested_cuda_selftest_requests_fail_closed() {
            with_cuda_selftest_running_for_tests(|| {
                assert!(!ensure_cuda_selftest());
                let mut state = [0u64; 25];
                assert!(
                    !keccak_f1600_cuda(&mut state),
                    "nested keccak probe should fail closed during self-test",
                );
                let mut output = [0xa5];
                assert!(!poseidon2_cuda_many_into(&[(0, 1)], &mut output));
                assert_eq!(
                    output,
                    [0xa5],
                    "nested probe must preserve the caller output"
                );
            });
        }
        #[test]
        fn cuda_enable_disable_and_reset_update_status_flags() {
            reset_cuda_backend_for_tests();
            set_cuda_enabled(false);
            assert!(cuda_disabled());
            assert_eq!(
                cuda_last_error_message().as_deref(),
                Some("disabled by configuration")
            );
            assert!(!cuda_available());
            set_cuda_enabled(true);
            assert!(!cuda_disabled());
            assert_eq!(cuda_last_error_message(), None);
            // Only local policy resets. Physical uncertain custody belongs to
            // the process owner and cannot be cleared by this operation.
            record_cuda_disable("coverage explicit disable");
            assert!(cuda_disabled());
            reset_cuda_backend_for_tests();
            assert!(!cuda_disabled());
            assert_eq!(cuda_last_error_message(), None);
        }
        #[test]
        fn explicit_cuda_disable_records_message_and_reset_clears_it() {
            reset_cuda_backend_for_tests();
            record_cuda_disable("coverage explicit disable");
            assert!(cuda_disabled());
            assert_eq!(
                cuda_last_error_message().as_deref(),
                Some("coverage explicit disable")
            );
            reset_cuda_backend_for_tests();
            assert!(!cuda_disabled());
            assert_eq!(cuda_last_error_message(), None);
        }
        #[test]
        fn poseidon_kernel_reports_stride_errors_without_disabling_backend() {
            let disabled_before = CUDA_DISABLED.load(Ordering::SeqCst);
            if !ensure_cuda_selftest() {
                assert!(super::super::poseidons::fault_probe(true).is_none());
                assert_eq!(CUDA_DISABLED.load(Ordering::SeqCst), disabled_before);
                return;
            }
            let Some(status) = super::super::poseidons::fault_probe(true) else {
                return;
            };
            assert_eq!(status[0], 2, "kernel must report invalid stride");
            assert_eq!(
                status[1], 1,
                "reported detail must preserve the supplied stride"
            );
            assert_eq!(
                CUDA_DISABLED.load(Ordering::SeqCst),
                disabled_before,
                "fault probe must not disable the backend"
            );
        }
        #[test]
        fn ed25519_selftest_covers_signature_kernel() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping ed25519 self-test regression");
                return;
            }
            assert!(
                ed25519_cuda_selftest(),
                "ed25519 CUDA self-test must accept the golden truth set",
            );
        }
        #[test]
        fn sha256_merkle_selftest_covers_cuda_kernels() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping SHA-256 merkle self-test regression");
                return;
            }
            assert!(
                sha256_leaves_cuda_selftest(),
                "sha256 leaves CUDA self-test must accept the golden truth set",
            );
            assert!(
                sha256_pairs_reduce_cuda_selftest(),
                "sha256 pairs-reduce CUDA self-test must accept the golden truth set",
            );
        }
        #[test]
        fn vector_selftest_covers_cuda_kernels() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping vector self-test regression");
                return;
            }
            assert!(
                vadd64_cuda_selftest(),
                "vadd64 CUDA self-test must accept the golden truth set",
            );
            assert!(
                bit_ops_cuda_selftest(),
                "bitwise CUDA self-test must accept the golden truth set",
            );
        }
        #[test]
        fn aes_batch_selftest_covers_cuda_kernels() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping AES batch self-test regression");
                return;
            }
            assert!(
                aes_batch_cuda_selftest(),
                "AES batch CUDA self-test must accept the golden truth set",
            );
        }
        #[test]
        fn sha256_merkle_selftest_survives_prior_cuda_truth_sets() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping SHA-256 post-order regression");
                return;
            }
            assert!(
                aes_batch_cuda_selftest(),
                "AES batch CUDA self-test must accept the golden truth set before SHA-256",
            );
            assert!(
                bn254_cuda_selftest(),
                "BN254 CUDA self-test must accept the golden truth set before SHA-256",
            );
            assert!(
                ed25519_cuda_selftest(),
                "Ed25519 CUDA self-test must accept the golden truth set before SHA-256",
            );
            assert!(
                sha256_leaves_cuda_selftest(),
                "sha256 leaves CUDA self-test must remain green after prior truth sets",
            );
            assert!(
                sha256_pairs_reduce_cuda_selftest(),
                "sha256 pairs-reduce CUDA self-test must remain green after prior truth sets",
            );
        }
        #[test]
        fn cached_cuda_selftest_rebinds_context_on_new_thread() {
            reset_cuda_backend_for_tests();
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping cached self-test thread rebind regression");
                return;
            }
            let blocks = std::thread::spawn(|| {
                let mut block_a = [0u8; 64];
                block_a[0] = b'a';
                block_a[1] = b'b';
                block_a[2] = b'c';
                block_a[3] = 0x80;
                block_a[63] = 24;
                let mut block_b = [0u8; 64];
                block_b[0] = b'n';
                block_b[1] = b'o';
                block_b[2] = b'r';
                block_b[3] = b'i';
                block_b[4] = b't';
                block_b[5] = b'o';
                block_b[6] = 0x80;
                block_b[63] = 48;
                sha256_leaves_cuda_into(&[block_a, block_b], &mut [[0; 32]; 2])
            })
            .join()
            .expect("worker thread must complete");
            assert!(
                blocks,
                "cached self-test should rebind a CUDA context on fresh worker threads",
            );
        }
        #[test]
        fn public_bitonic_sort_pairs_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public bitonic-sort parity regression");
                return;
            }
            let mut hi = [5u64, 3, 5, 3, 3];
            let mut lo = [7u64, 9, 1, 2, 1];
            let mut expected: Vec<(u64, u64)> =
                hi.iter().copied().zip(lo.iter().copied()).collect();
            expected.sort_unstable();
            assert_eq!(bitonic_sort_pairs(&mut hi, &mut lo), Some(()));
            assert_eq!(
                hi.into_iter().zip(lo).collect::<Vec<_>>(),
                expected,
                "bitonic_sort_pairs should match scalar lexicographic ordering",
            );
        }
        #[test]
        fn public_vector_helpers_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public vector parity regression");
                return;
            }
            let a32 = [0xffff_0000u32, 0x1234_5678, 0x0f0f_0f0f, 0xaaaa_5555];
            let b32 = [0x00ff_ff00u32, 0xf0f0_f0f0, 0x3333_cccc, 0x5555_aaaa];
            let expected_add32: Vec<u32> = a32
                .iter()
                .zip(b32.iter())
                .map(|(&lhs, &rhs)| lhs.wrapping_add(rhs))
                .collect();
            let expected_and: Vec<u32> = a32
                .iter()
                .zip(b32.iter())
                .map(|(&lhs, &rhs)| lhs & rhs)
                .collect();
            let expected_xor: Vec<u32> = a32
                .iter()
                .zip(b32.iter())
                .map(|(&lhs, &rhs)| lhs ^ rhs)
                .collect();
            let expected_or: Vec<u32> = a32
                .iter()
                .zip(b32.iter())
                .map(|(&lhs, &rhs)| lhs | rhs)
                .collect();
            let mut output = vec![0; a32.len()];
            assert!(vadd32_cuda_into(&a32, &b32, &mut output));
            assert_eq!(output, expected_add32);
            let mut output = vec![0; a32.len()];
            assert!(vand_cuda_into(&a32, &b32, &mut output));
            assert_eq!(output, expected_and);
            let mut output = vec![0; a32.len()];
            assert!(vxor_cuda_into(&a32, &b32, &mut output));
            assert_eq!(output, expected_xor);
            let mut output = vec![0; a32.len()];
            assert!(vor_cuda_into(&a32, &b32, &mut output));
            assert_eq!(output, expected_or);
            let a64 = [0xffff_ffff_ffff_ff00u64, 0x1234_5678_9abc_def0];
            let b64 = [0x0000_0000_0000_0201u64, 0x0fed_cba9_8765_4321];
            let expected_add64: Vec<u64> = a64
                .iter()
                .zip(b64.iter())
                .map(|(&lhs, &rhs)| lhs.wrapping_add(rhs))
                .collect();
            let mut output = vec![0; a64.len()];
            assert!(vadd64_cuda_into(&a64, &b64, &mut output));
            assert_eq!(output, expected_add64);
        }
        #[test]
        fn public_sha256_compress_matches_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public sha256-compress parity regression");
                return;
            }
            let mut block = [0u8; 64];
            block[0] = b'a';
            block[1] = b'b';
            block[2] = b'c';
            block[3] = 0x80;
            block[63] = 24;
            let mut scalar = [
                0x6a09e667u32,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut cuda = scalar;
            sha256_scalar_ref(&mut scalar, &block);
            assert!(sha256_compress_cuda(&mut cuda, &block));
            assert_eq!(cuda, scalar);
        }
        #[test]
        fn public_keccak_matches_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public keccak parity regression");
                return;
            }
            let mut scalar = [0u64; 25];
            for (index, lane) in scalar.iter_mut().enumerate() {
                *lane = index as u64;
            }
            let mut cuda = scalar;
            crate::sha3::keccak_f1600(&mut scalar);
            assert!(keccak_f1600_cuda(&mut cuda));
            assert_eq!(cuda, scalar);
        }
        #[test]
        fn public_poseidon_helpers_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public Poseidon parity regression");
                return;
            }
            let single2 = (1u64, 2u64);
            assert_eq!(
                poseidon2_cuda(single2.0, single2.1),
                Some(crate::poseidon::poseidon2_simd(single2.0, single2.1))
            );
            let single6 = [1u64, 2, 3, 4, 5, 6];
            assert_eq!(
                poseidon6_cuda(single6),
                Some(crate::poseidon::poseidon6_simd(single6))
            );
            let many2 = [(0u64, 1u64), (7, 9), (11, 13), (21, 34)];
            let expected_many2: Vec<u64> = many2
                .iter()
                .map(|&(lhs, rhs)| crate::poseidon::poseidon2_simd(lhs, rhs))
                .collect();
            let mut output = vec![0; many2.len()];
            assert!(poseidon2_cuda_many_into(&many2, &mut output));
            assert_eq!(output, expected_many2);
            let many6 = [
                [1u64, 2, 3, 4, 5, 6],
                [7u64, 8, 9, 10, 11, 12],
                [13u64, 21, 34, 55, 89, 144],
            ];
            let expected_many6: Vec<u64> = many6
                .iter()
                .copied()
                .map(crate::poseidon::poseidon6_simd)
                .collect();
            let mut output = vec![0; many6.len()];
            assert!(poseidon6_cuda_many_into(&many6, &mut output));
            assert_eq!(output, expected_many6);
        }
        #[test]
        fn public_aes_round_helpers_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public AES round parity regression");
                return;
            }
            let state = [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ];
            let rk = [
                0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
                0x67, 0x98,
            ];
            let expected_enc = crate::aes::aesenc_impl(state, rk);
            let expected_dec = crate::aes::aesdec_impl(expected_enc, rk);
            assert_eq!(aesenc_cuda(state, rk), Some(expected_enc));
            assert_eq!(aesdec_cuda(expected_enc, rk), Some(expected_dec));
        }
        #[test]
        fn public_sha256_leaves_matches_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public sha256-leaves parity regression");
                return;
            }
            let mut block_a = [0u8; 64];
            block_a[0] = b'a';
            block_a[1] = b'b';
            block_a[2] = b'c';
            block_a[3] = 0x80;
            block_a[63] = 24;
            let mut block_b = [0u8; 64];
            block_b[0] = b'n';
            block_b[1] = b'o';
            block_b[2] = b'r';
            block_b[3] = b'i';
            block_b[4] = b't';
            block_b[5] = b'o';
            block_b[6] = 0x80;
            block_b[63] = 48;
            let blocks = [block_a, block_b];
            let expected: Vec<[u8; 32]> = blocks
                .iter()
                .map(|block| {
                    let mut state = [
                        0x6a09e667u32,
                        0xbb67ae85,
                        0x3c6ef372,
                        0xa54ff53a,
                        0x510e527f,
                        0x9b05688c,
                        0x1f83d9ab,
                        0x5be0cd19,
                    ];
                    sha256_scalar_ref(&mut state, block);
                    let mut digest = [0u8; 32];
                    for (index, word) in state.iter().enumerate() {
                        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                    }
                    digest
                })
                .collect();
            let mut output = [[0; 32]; 2];
            assert!(sha256_leaves_cuda_into(&blocks, &mut output));
            assert_eq!(output.as_slice(), expected);
        }
        #[test]
        fn public_sha256_pairs_reduce_matches_scalar_when_cuda_available() {
            fn cpu_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
                let mut state = [
                    0x6a09e667u32,
                    0xbb67ae85,
                    0x3c6ef372,
                    0xa54ff53a,
                    0x510e527f,
                    0x9b05688c,
                    0x1f83d9ab,
                    0x5be0cd19,
                ];
                let mut block = [0u8; 64];
                block[..32].copy_from_slice(left);
                block[32..].copy_from_slice(right);
                sha256_scalar_ref(&mut state, &block);
                let mut pad = [0u8; 64];
                pad[0] = 0x80;
                pad[62] = 0x02;
                pad[63] = 0x00;
                sha256_scalar_ref(&mut state, &pad);
                let mut out = [0u8; 32];
                for (index, word) in state.iter().enumerate() {
                    out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                out
            }
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public sha256-pairs parity regression");
                return;
            }
            let mut d0 = [0u8; 32];
            let mut d1 = [0u8; 32];
            let mut d2 = [0u8; 32];
            for (index, byte) in d0.iter_mut().enumerate() {
                *byte = index as u8;
            }
            for (index, byte) in d1.iter_mut().enumerate() {
                *byte = 0x40 + index as u8;
            }
            for (index, byte) in d2.iter_mut().enumerate() {
                *byte = 0x80 + index as u8;
            }
            let digests = [d0, d1, d2];
            let first = cpu_pair(&digests[0], &digests[1]);
            let expected = cpu_pair(&first, &digests[2]);
            assert_eq!(sha256_pairs_reduce_cuda(&digests), Some(expected));
        }
        #[test]
        fn public_aes_batch_matches_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public AES batch regression");
                return;
            }
            let states = [
                [
                    0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
                    0x22, 0x11, 0x00,
                ],
            ];
            let rk = [
                0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
                0x67, 0x98,
            ];
            let expected_enc: Vec<[u8; 16]> = states
                .iter()
                .map(|&state| crate::aes::aesenc_impl(state, rk))
                .collect();
            let expected_dec: Vec<[u8; 16]> = states
                .iter()
                .map(|&state| crate::aes::aesdec_impl(state, rk))
                .collect();
            let mut output = vec![[0; 16]; states.len()];
            assert!(aesenc_batch_cuda_into(&states, rk, &mut output));
            assert_eq!(output, expected_enc);
            assert!(aesdec_batch_cuda_into(&states, rk, &mut output));
            assert_eq!(output, expected_dec);
        }
        #[test]
        fn public_bn254_helpers_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public BN254 parity regression");
                return;
            }
            let add_lhs = crate::bn254_vec::FieldElem::from_u64(0x1234_5678_9abc_def0);
            let add_rhs = crate::bn254_vec::FieldElem::from_u64(0x0fed_cba9_8765_4321);
            let sub_lhs = crate::bn254_vec::FieldElem::from_u64(0x0fff_ffff_ffff_fffb);
            let sub_rhs = crate::bn254_vec::FieldElem::from_u64(0x0000_0000_0000_0011);
            let mul_lhs = crate::bn254_vec::FieldElem::from_u64(0x0102_0304_0506_0708);
            let mul_rhs = crate::bn254_vec::FieldElem::from_u64(0x1112_1314_1516_1718);
            assert_eq!(
                bn254_add_cuda(add_lhs.0, add_rhs.0),
                Some(crate::bn254_vec::add_scalar(add_lhs, add_rhs).0)
            );
            assert_eq!(
                bn254_sub_cuda(sub_lhs.0, sub_rhs.0),
                Some(crate::bn254_vec::sub_scalar(sub_lhs, sub_rhs).0)
            );
            assert_eq!(
                bn254_mul_cuda(mul_lhs.0, mul_rhs.0),
                Some(crate::bn254_vec::mul_scalar(mul_lhs, mul_rhs).0)
            );
        }
        #[test]
        fn public_bn254_batch_helpers_match_scalar_when_cuda_available() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public BN254 batch parity regression");
                return;
            }
            let add_lhs = [
                crate::bn254_vec::FieldElem::from_u64(0x1234_5678_9abc_def0),
                crate::bn254_vec::FieldElem::from_u64(0x2222_3333_4444_5555),
                crate::bn254_vec::FieldElem::from_u64(0x0fff_eeee_dddd_cccc),
            ];
            let add_rhs = [
                crate::bn254_vec::FieldElem::from_u64(0x0fed_cba9_8765_4321),
                crate::bn254_vec::FieldElem::from_u64(0x0101_0101_0101_0101),
                crate::bn254_vec::FieldElem::from_u64(0x1111_0000_ffff_eeee),
            ];
            let sub_lhs = [
                crate::bn254_vec::FieldElem::from_u64(0x0fff_ffff_ffff_fffb),
                crate::bn254_vec::FieldElem::from_u64(0x9999_8888_7777_6666),
                crate::bn254_vec::FieldElem::from_u64(0x1212_1212_1212_1212),
            ];
            let sub_rhs = [
                crate::bn254_vec::FieldElem::from_u64(0x0000_0000_0000_0011),
                crate::bn254_vec::FieldElem::from_u64(0x1111_2222_3333_4444),
                crate::bn254_vec::FieldElem::from_u64(0x0101_0101_0101_0101),
            ];
            let mul_lhs = [
                crate::bn254_vec::FieldElem::from_u64(0x0102_0304_0506_0708),
                crate::bn254_vec::FieldElem::from_u64(0x1112_1314_1516_1718),
                crate::bn254_vec::FieldElem::from_u64(0x2122_2324_2526_2728),
            ];
            let mul_rhs = [
                crate::bn254_vec::FieldElem::from_u64(0x1112_1314_1516_1718),
                crate::bn254_vec::FieldElem::from_u64(0x0102_0304_0506_0708),
                crate::bn254_vec::FieldElem::from_u64(0x3334_3536_3738_393a),
            ];
            let add_lhs_words: Vec<[u64; 4]> = add_lhs.iter().map(|elem| elem.0).collect();
            let add_rhs_words: Vec<[u64; 4]> = add_rhs.iter().map(|elem| elem.0).collect();
            let sub_lhs_words: Vec<[u64; 4]> = sub_lhs.iter().map(|elem| elem.0).collect();
            let sub_rhs_words: Vec<[u64; 4]> = sub_rhs.iter().map(|elem| elem.0).collect();
            let mul_lhs_words: Vec<[u64; 4]> = mul_lhs.iter().map(|elem| elem.0).collect();
            let mul_rhs_words: Vec<[u64; 4]> = mul_rhs.iter().map(|elem| elem.0).collect();
            let expected_add: Vec<[u64; 4]> = add_lhs
                .iter()
                .copied()
                .zip(add_rhs.iter().copied())
                .map(|(lhs, rhs)| crate::bn254_vec::add_scalar(lhs, rhs).0)
                .collect();
            let expected_sub: Vec<[u64; 4]> = sub_lhs
                .iter()
                .copied()
                .zip(sub_rhs.iter().copied())
                .map(|(lhs, rhs)| crate::bn254_vec::sub_scalar(lhs, rhs).0)
                .collect();
            let expected_mul: Vec<[u64; 4]> = mul_lhs
                .iter()
                .copied()
                .zip(mul_rhs.iter().copied())
                .map(|(lhs, rhs)| crate::bn254_vec::mul_scalar(lhs, rhs).0)
                .collect();
            let mut add_output = vec![[0; 4]; add_lhs_words.len()];
            assert!(bn254_add_batch_cuda_into(
                &add_lhs_words,
                &add_rhs_words,
                &mut add_output
            ));
            assert_eq!(add_output, expected_add);
            let mut sub_output = vec![[0; 4]; sub_lhs_words.len()];
            assert!(bn254_sub_batch_cuda_into(
                &sub_lhs_words,
                &sub_rhs_words,
                &mut sub_output
            ));
            assert_eq!(sub_output, expected_sub);
            let mut mul_output = vec![[0; 4]; mul_lhs_words.len()];
            assert!(bn254_mul_batch_cuda_into(
                &mul_lhs_words,
                &mul_rhs_words,
                &mut mul_output
            ));
            assert_eq!(mul_output, expected_mul);
            assert!(bn254_add_batch_cuda_into(&[], &[], &mut []));
            let previous = add_output.clone();
            assert!(!bn254_add_batch_cuda_into(
                &add_lhs_words,
                &add_rhs_words[..2],
                &mut add_output
            ));
            assert_eq!(add_output, previous);
        }
        #[test]
        fn public_ed25519_verify_helpers_match_cpu_when_cuda_available() {
            use ed25519_dalek::{Signature, Signer, SigningKey};
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping public ed25519 parity regression");
                return;
            }
            let signing_key = SigningKey::from_bytes(&[0x11; 32]);
            let msg = b"cuda ed25519 public parity";
            let sig = signing_key.sign(msg).to_bytes();
            let pk_bytes = signing_key.verifying_key().to_bytes();
            let expected_good = signing_key
                .verifying_key()
                .verify_strict(msg, &Signature::from_bytes(&sig))
                .is_ok();
            let mut bad_sig = sig;
            bad_sig[0] ^= 0x42;
            let expected_bad = signing_key
                .verifying_key()
                .verify_strict(msg, &Signature::from_bytes(&bad_sig))
                .is_ok();
            assert_eq!(
                ed25519_verify_cuda(msg, &sig, &pk_bytes),
                Some(expected_good)
            );
            assert_eq!(
                ed25519_verify_cuda(msg, &bad_sig, &pk_bytes),
                Some(expected_bad)
            );
            let singleton_hram =
                crate::signature::ed25519_challenge_scalar_bytes(&sig, &pk_bytes, msg);
            assert_eq!(
                {
                    let signatures = &[sig];
                    let public_keys = &[pk_bytes];
                    let hrams = &[singleton_hram];
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                Some(vec![expected_good])
            );
            let key1 = SigningKey::from_bytes(&[0x22; 32]);
            let key2 = SigningKey::from_bytes(&[0x33; 32]);
            let msg1 = b"cuda batch one";
            let msg2 = b"cuda batch two";
            let sig1 = key1.sign(msg1).to_bytes();
            let sig2_good = key2.sign(msg2).to_bytes();
            let mut sig2_bad = sig2_good;
            sig2_bad[0] ^= 0x11;
            let pks = vec![
                key1.verifying_key().to_bytes(),
                key2.verifying_key().to_bytes(),
            ];
            let sigs = vec![sig1, sig2_bad];
            let hrams = vec![
                crate::signature::ed25519_challenge_scalar_bytes(&sigs[0], &pks[0], msg1),
                crate::signature::ed25519_challenge_scalar_bytes(&sigs[1], &pks[1], msg2),
            ];
            let expected_batch = vec![
                key1.verifying_key()
                    .verify_strict(msg1, &Signature::from_bytes(&sigs[0]))
                    .is_ok(),
                key2.verifying_key()
                    .verify_strict(msg2, &Signature::from_bytes(&sigs[1]))
                    .is_ok(),
            ];
            assert_eq!(
                {
                    let signatures = &sigs;
                    let public_keys = &pks;
                    let hrams = &hrams;
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                Some(expected_batch)
            );
        }
        #[test]
        fn public_ed25519_verify_helpers_reject_all_zero_signature_and_public_key_material() {
            if !ensure_cuda_kernel(Kernel::Ed25519) {
                eprintln!("CUDA unavailable; invalid-input native parity remains unqualified");
                return;
            }
            let zero_sig = [0_u8; 64];
            let nonzero_sig = [0x11_u8; 64];
            let mut small_order_r_sig = [0x22_u8; 64];
            small_order_r_sig[..32].copy_from_slice(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            let public_key = [0x42_u8; 32];
            let zero_public_key = [0_u8; 32];
            let hram = [0x24_u8; 32];
            assert_eq!(
                ed25519_verify_cuda(b"message", &zero_sig, &public_key),
                Some(false)
            );
            assert_eq!(
                ed25519_verify_cuda(b"message", &nonzero_sig, &zero_public_key),
                Some(false)
            );
            assert_eq!(
                ed25519_verify_cuda(b"message", &small_order_r_sig, &public_key),
                Some(false)
            );
            assert_eq!(
                {
                    let signatures = &[zero_sig];
                    let public_keys = &[public_key];
                    let hrams = &[hram];
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                Some(vec![false])
            );
            assert_eq!(
                {
                    let signatures = &[nonzero_sig];
                    let public_keys = &[zero_public_key];
                    let hrams = &[hram];
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                Some(vec![false])
            );
            assert_eq!(
                {
                    let signatures = &[small_order_r_sig];
                    let public_keys = &[public_key];
                    let hrams = &[hram];
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                Some(vec![false])
            );
        }
        #[test]
        fn public_ed25519_single_helper_matches_singleton_batch_when_cuda_available() {
            use ed25519_dalek::{Signer, SigningKey};
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping single-vs-batch ed25519 regression");
                return;
            }
            let signing_key = SigningKey::from_bytes(&[0x44; 32]);
            let msg = b"cuda singletons should follow batch path";
            let sig = signing_key.sign(msg).to_bytes();
            let pk_bytes = signing_key.verifying_key().to_bytes();
            let hram = crate::signature::ed25519_challenge_scalar_bytes(&sig, &pk_bytes, msg);
            let single = ed25519_verify_cuda(msg, &sig, &pk_bytes);
            let batch = {
                let signatures = &[sig];
                let public_keys = &[pk_bytes];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                    Some(output)
                } else {
                    assert!(
                        output.iter().all(|value| *value),
                        "refusal must preserve destination"
                    );
                    None
                }
            }
            .and_then(|mut out| out.pop());
            assert_eq!(single, batch);
        }
        #[test]
        fn cuda_public_helpers_are_repeat_deterministic_against_cpu() {
            use ed25519_dalek::{Signature, Signer, SigningKey};
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping repeated determinism fixture");
                return;
            }
            let a32 = [0x0102_0304u32, 0xffff_ffff, 0x1357_9bdf, 0x2468_ace0];
            let b32 = [0xf0e0_d0c0u32, 1, 0xaaaa_5555, 0x1111_2222];
            let expected_add32: Vec<u32> = a32
                .iter()
                .zip(b32.iter())
                .map(|(&lhs, &rhs)| lhs.wrapping_add(rhs))
                .collect();
            let mut block = [0u8; 64];
            block[..11].copy_from_slice(b"determinism");
            block[11] = 0x80;
            block[63] = 88;
            let initial_sha = [
                0x6a09e667u32,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut expected_sha = initial_sha;
            sha256_scalar_ref(&mut expected_sha, &block);
            let mut keccak_expected = [0u64; 25];
            for (index, lane) in keccak_expected.iter_mut().enumerate() {
                *lane = (index as u64).wrapping_mul(0x0101_0101_0101_0101);
            }
            crate::sha3::keccak_f1600(&mut keccak_expected);
            let state = [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ];
            let rk = [
                0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f,
                0x67, 0x98,
            ];
            let expected_aes = crate::aes::aesenc_impl(state, rk);
            let bn_lhs = crate::bn254_vec::FieldElem::from_u64(0x0102_0304_0506_0708);
            let bn_rhs = crate::bn254_vec::FieldElem::from_u64(0x1112_1314_1516_1718);
            let expected_bn = crate::bn254_vec::mul_scalar(bn_lhs, bn_rhs).0;
            let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
            let msg = b"cuda repeated determinism";
            let sig = signing_key.sign(msg).to_bytes();
            let pk = signing_key.verifying_key().to_bytes();
            let expected_sig = signing_key
                .verifying_key()
                .verify_strict(msg, &Signature::from_bytes(&sig))
                .is_ok();
            let mut previous_tuple = None;
            for iteration in 0..3 {
                if iteration == 0 {
                    trace_cuda_selftest("determinism vadd32");
                }
                let mut add32 = vec![0; a32.len()];
                assert!(vadd32_cuda_into(&a32, &b32, &mut add32));
                assert_eq!(add32, expected_add32);
                if iteration == 0 {
                    trace_cuda_selftest("determinism sha256");
                }
                let mut sha_state = initial_sha;
                assert!(sha256_compress_cuda(&mut sha_state, &block));
                assert_eq!(sha_state, expected_sha);
                if iteration == 0 {
                    trace_cuda_selftest("determinism keccak");
                }
                let mut keccak_state = [0u64; 25];
                for (index, lane) in keccak_state.iter_mut().enumerate() {
                    *lane = (index as u64).wrapping_mul(0x0101_0101_0101_0101);
                }
                assert!(keccak_f1600_cuda(&mut keccak_state));
                assert_eq!(keccak_state, keccak_expected);
                if iteration == 0 {
                    trace_cuda_selftest("determinism aes");
                }
                let aes = aesenc_cuda(state, rk).expect("aes cuda");
                assert_eq!(aes, expected_aes);
                if iteration == 0 {
                    trace_cuda_selftest("determinism bn254");
                }
                let bn = bn254_mul_cuda(bn_lhs.0, bn_rhs.0).expect("bn254 cuda");
                assert_eq!(bn, expected_bn);
                if iteration == 0 {
                    trace_cuda_selftest("determinism ed25519");
                }
                let sig_ok = ed25519_verify_cuda(msg, &sig, &pk).expect("ed25519 cuda");
                assert_eq!(sig_ok, expected_sig);
                let current_tuple = (add32, sha_state, keccak_state, aes, bn, sig_ok);
                if let Some(previous) = &previous_tuple {
                    assert_eq!(
                        &current_tuple, previous,
                        "repeated CUDA helper runs must be byte-stable"
                    );
                }
                previous_tuple = Some(current_tuple);
            }
        }
        #[test]
        fn bn254_selftest_covers_cuda_kernels() {
            if !ensure_cuda_selftest() {
                eprintln!("CUDA unavailable; skipping BN254 self-test regression");
                return;
            }
            assert!(
                bn254_cuda_selftest(),
                "bn254 CUDA self-test must accept the golden truth set",
            );
        }
    }
}
#[cfg(feature = "cuda")]
pub use imp::*;
/// Read the original IVM policy owner without discovering devices or admitting work.
///
/// `Ok(None)` means that this stable slot has no IVM owner and has never received
/// completion credit. Busy registry custody is an error, never a zero baseline.
/// Snapshots remain readable after policy opt-out or kernel/device quarantine.
///
/// # Errors
/// Returns [`CudaCompletionError::Busy`] if another caller borrows the registry.
#[cfg(feature = "cuda")]
pub fn cuda_completion_snapshot(
    slot: usize,
) -> Result<Option<CudaCompletionSnapshot>, CudaCompletionError> {
    crate::cuda_dispatch::completion_snapshot(slot)
}
/// CPU-only builds have no IVM CUDA policy owners or completion credit.
#[cfg(not(feature = "cuda"))]
pub fn cuda_completion_snapshot(
    _slot: usize,
) -> Result<Option<CudaCompletionSnapshot>, CudaCompletionError> {
    Ok(None)
}
#[cfg(not(feature = "cuda"))]
pub fn cuda_available() -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
/// Whether policy or an unscoped fatal error disables the entire CUDA backend.
/// Individual kernel/device quarantine is reflected by operation availability.
pub fn cuda_disabled() -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn cuda_last_error_message() -> Option<String> {
    None
}
#[cfg(not(feature = "cuda"))]
#[doc(hidden)]
pub fn reset_cuda_backend_for_tests() {}
#[cfg(not(feature = "cuda"))]
/// Sort `(hi, lo)` key pairs lexicographically with the CUDA bitonic kernel.
///
/// Returns `None` when the crate is built without CUDA support.
pub fn bitonic_sort_pairs(hi: &mut [u64], lo: &mut [u64]) -> Option<()> {
    (hi.len() == lo.len() && hi.len() < 2).then_some(())
}
#[cfg(not(feature = "cuda"))]
pub fn vadd32_cuda_into(_a: &[u32], _b: &[u32], _destination: &mut [u32]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn vadd64_cuda_into(_a: &[u64], _b: &[u64], _destination: &mut [u64]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn vand_cuda_into(_a: &[u32], _b: &[u32], _destination: &mut [u32]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn vxor_cuda_into(_a: &[u32], _b: &[u32], _destination: &mut [u32]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn vor_cuda_into(_a: &[u32], _b: &[u32], _destination: &mut [u32]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn sha256_compress_cuda(_state: &mut [u32; 8], _block: &[u8; 64]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
/// Empty leaf batches need no device; nonempty CUDA attempts are unavailable.
pub fn sha256_leaves_cuda_into(blocks: &[[u8; 64]], destination: &mut [[u8; 32]]) -> bool {
    blocks.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
pub fn sha256_pairs_reduce_cuda(_digests: &[[u8; 32]]) -> Option<[u8; 32]> {
    None
}
#[cfg(not(feature = "cuda"))]
pub fn poseidon2_cuda(_a: u64, _b: u64) -> Option<u64> {
    None
}
#[cfg(not(feature = "cuda"))]
/// Empty Poseidon batches need no device; nonempty CUDA attempts are unavailable.
pub fn poseidon2_cuda_many_into(inputs: &[(u64, u64)], destination: &mut [u64]) -> bool {
    inputs.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
pub fn poseidon6_cuda(_inputs: [u64; 6]) -> Option<u64> {
    None
}
#[cfg(not(feature = "cuda"))]
/// Empty Poseidon batches need no device; nonempty CUDA attempts are unavailable.
pub fn poseidon6_cuda_many_into(inputs: &[[u64; 6]], destination: &mut [u64]) -> bool {
    inputs.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
pub fn keccak_f1600_cuda(_state: &mut [u64; 25]) -> bool {
    false
}
#[cfg(not(feature = "cuda"))]
pub fn aesenc_cuda(_state: [u8; 16], _rk: [u8; 16]) -> Option<[u8; 16]> {
    None
}
#[cfg(not(feature = "cuda"))]
pub fn aesdec_cuda(_state: [u8; 16], _rk: [u8; 16]) -> Option<[u8; 16]> {
    None
}
#[cfg(not(feature = "cuda"))]
/// An empty AES batch completes without a device; a nonempty CUDA attempt is unavailable.
pub fn aesenc_batch_cuda_into(
    states: &[[u8; 16]],
    _rk: [u8; 16],
    destination: &mut [[u8; 16]],
) -> bool {
    states.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
/// An empty AES batch completes without a device; a nonempty CUDA attempt is unavailable.
pub fn aesdec_batch_cuda_into(
    states: &[[u8; 16]],
    _rk: [u8; 16],
    destination: &mut [[u8; 16]],
) -> bool {
    states.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
/// Empty BN254 batches succeed without hardware; nonempty CUDA attempts refuse.
pub fn bn254_add_batch_cuda_into(
    lhs: &[[u64; 4]],
    rhs: &[[u64; 4]],
    destination: &mut [[u64; 4]],
) -> bool {
    lhs.is_empty() && rhs.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
/// Empty BN254 batches succeed without hardware; nonempty CUDA attempts refuse.
pub fn bn254_sub_batch_cuda_into(
    lhs: &[[u64; 4]],
    rhs: &[[u64; 4]],
    destination: &mut [[u64; 4]],
) -> bool {
    lhs.is_empty() && rhs.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
/// Empty BN254 batches succeed without hardware; nonempty CUDA attempts refuse.
pub fn bn254_mul_batch_cuda_into(
    lhs: &[[u64; 4]],
    rhs: &[[u64; 4]],
    destination: &mut [[u64; 4]],
) -> bool {
    lhs.is_empty() && rhs.is_empty() && destination.is_empty()
}
#[cfg(not(feature = "cuda"))]
pub fn bn254_add_cuda(_a: [u64; 4], _b: [u64; 4]) -> Option<[u64; 4]> {
    None
}
#[cfg(not(feature = "cuda"))]
pub fn bn254_sub_cuda(_a: [u64; 4], _b: [u64; 4]) -> Option<[u64; 4]> {
    None
}
#[cfg(not(feature = "cuda"))]
pub fn bn254_mul_cuda(_a: [u64; 4], _b: [u64; 4]) -> Option<[u64; 4]> {
    None
}
#[cfg(not(feature = "cuda"))]
/// Native signature execution is unavailable without CUDA.
pub fn ed25519_verify_cuda(
    _message: &[u8],
    _signature: &[u8; 64],
    _public_key: &[u8; 32],
) -> Option<bool> {
    None
}
#[cfg(not(feature = "cuda"))]
/// Empty batches need no device; nonempty native attempts preserve the destination.
pub fn ed25519_verify_batch_cuda_into(
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
    destination: &mut [bool],
) -> bool {
    signatures.is_empty() && public_keys.is_empty() && hrams.is_empty() && destination.is_empty()
}
#[cfg(all(test, not(feature = "cuda")))]
mod tests {
    use super::{ed25519_verify_batch_cuda_into, ed25519_verify_cuda};
    use ed25519_dalek::{Signer as _, SigningKey};
    const SMALL_ORDER_ED25519_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const NONCANONICAL_NON_SMALL_ORDER_ED25519_PUBLIC_KEY: [u8; 32] = [
        0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_with_replacement_r(signature: &[u8; 64], replacement_r: &[u8; 32]) -> [u8; 64] {
        let mut malformed = *signature;
        malformed[..replacement_r.len()].copy_from_slice(replacement_r);
        malformed
    }
    #[test]
    fn ed25519_cuda_stubs_reject_invalid_signature_and_public_key_material() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let valid_sig = signing_key.sign(b"message").to_bytes();
        let zero_sig = [0_u8; 64];
        let public_key = signing_key.verifying_key().to_bytes();
        let zero_public_key = [0_u8; 32];
        let weak_public_key = [
            1_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let malformed_public_key = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let hram = [0x24_u8; 32];
        assert_eq!(
            ed25519_verify_cuda(b"message", &zero_sig, &public_key),
            None
        );
        assert_eq!(
            ed25519_verify_cuda(b"message", &valid_sig, &zero_public_key),
            None
        );
        assert_eq!(
            ed25519_verify_cuda(b"message", &valid_sig, &weak_public_key),
            None
        );
        assert_eq!(
            ed25519_verify_cuda(b"message", &valid_sig, &malformed_public_key),
            None
        );
        assert_eq!(
            ed25519_verify_cuda(
                b"message",
                &valid_sig,
                &NONCANONICAL_NON_SMALL_ORDER_ED25519_PUBLIC_KEY,
            ),
            None
        );
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let malformed_sig = signature_with_replacement_r(&valid_sig, &replacement_r);
            assert_eq!(
                ed25519_verify_cuda(b"message", &malformed_sig, &public_key),
                None,
                "{label} signature R must be unavailable in the single stub"
            );
        }
        assert_eq!(
            {
                let signatures = &[zero_sig];
                let public_keys = &[public_key];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
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
                let signatures = &[valid_sig];
                let public_keys = &[zero_public_key];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
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
                let signatures = &[valid_sig];
                let public_keys = &[weak_public_key];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
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
                let signatures = &[valid_sig];
                let public_keys = &[malformed_public_key];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
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
                let signatures = &[valid_sig];
                let public_keys = &[NONCANONICAL_NON_SMALL_ORDER_ED25519_PUBLIC_KEY];
                let hrams = &[hram];
                let mut output = vec![true; signatures.len()];
                if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
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
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let malformed_sig = signature_with_replacement_r(&valid_sig, &replacement_r);
            assert_eq!(
                {
                    let signatures = &[malformed_sig];
                    let public_keys = &[public_key];
                    let hrams = &[hram];
                    let mut output = vec![true; signatures.len()];
                    if ed25519_verify_batch_cuda_into(signatures, public_keys, hrams, &mut output) {
                        Some(output)
                    } else {
                        assert!(
                            output.iter().all(|value| *value),
                            "refusal must preserve destination"
                        );
                        None
                    }
                },
                None,
                "{label} signature R must be unavailable in the batch stub"
            );
        }
    }
}

#[cfg(not(feature = "cuda"))]
/// Fused AESENC rounds are unavailable without CUDA; callers use scalar execution.
pub fn aesenc_rounds_batch_cuda_into(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    destination: &mut [[u8; 16]],
) -> bool {
    if states.len() != destination.len() {
        return false;
    }
    if states.is_empty() {
        return true;
    }
    if keys.is_empty() {
        destination.copy_from_slice(states);
        return true;
    }
    false
}
#[cfg(not(feature = "cuda"))]
/// Fused AESDEC rounds are unavailable without CUDA; callers use scalar execution.
pub fn aesdec_rounds_batch_cuda_into(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    destination: &mut [[u8; 16]],
) -> bool {
    if states.len() != destination.len() {
        return false;
    }
    if states.is_empty() {
        return true;
    }
    if keys.is_empty() {
        destination.copy_from_slice(states);
        return true;
    }
    false
}

/// Observed physical device slots eligible under IVM's current configured cap.
/// A slot can remain quarantined; qualification must require each selected slot.
#[cfg(feature = "cuda")]
pub fn cuda_device_slots() -> usize {
    crate::cuda_dispatch::device_slots()
}
/// CPU-only builds expose no CUDA device slots.
#[cfg(not(feature = "cuda"))]
pub fn cuda_device_slots() -> usize {
    0
}
/// Execute a required hardware control on one persistent physical device.
#[cfg(feature = "cuda-hardware-tests")]
pub fn with_cuda_device_for_qualification<T>(index: usize, call: impl FnOnce() -> T) -> Option<T> {
    crate::cuda_dispatch::with_device_for_qualification(index, call)
}
/// Current qualification pin, for exact nested/unwind restoration controls.
#[cfg(feature = "cuda-hardware-tests")]
pub fn cuda_qualification_device() -> Option<usize> {
    crate::cuda_dispatch::qualification_device()
}

#[cfg(all(test, not(feature = "cuda")))]
mod poseidon_auto_cpu_tests {
    #[test]
    fn absent_compiled_cuda_leaves_both_caller_destinations_unchanged() {
        let mut output = [17, 19];
        assert!(!super::poseidon2_auto_into(
            &[(0, 1), (u64::MAX, 7)],
            &mut output
        ));
        assert!(!super::poseidon6_auto_into(
            &[[0; 6], [u64::MAX; 6]],
            &mut output
        ));
        assert_eq!(output, [17, 19]);
    }
}
