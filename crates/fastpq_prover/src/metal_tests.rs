//! Existing Metal tests qualification controls.

use super::{ensure_multi_queue_env, unwrap_or_skip, *};
use crate::fft::Planner;
use fastpq_isi::{CANONICAL_PARAMETER_SETS, poseidon as cpu_poseidon};
use iroha_crypto::Hash;
use std::{thread, time::Duration};
const SCALAR_PAIR_DOMAIN_FOR_TESTS: &[u8] = b"fastpq:test:scalar-two-word-arithmetic";
const REQUIRED_PIPELINES: &[&str] = &crate::metal_artifact::ENTRY_POINTS;
#[test]
fn private_column_rollback_clears_commit_restore_and_unwind_cells() {
    use crate::gpu_secret::ErasureObservation;
    let observed = ErasureObservation::begin();
    let mut columns = vec![vec![11, 13], vec![17, 19]];
    let mut rollback = ColumnMutationRollback::capture(&columns).unwrap();
    columns[0].copy_from_slice(&[23, 29]);
    rollback.commit();
    assert_eq!(observed.counts(), (4, 0));
    assert_eq!(columns, [vec![23, 29], vec![17, 19]]);

    let mut rollback = ColumnMutationRollback::capture(&columns).unwrap();
    columns[0].copy_from_slice(&[31, 37]);
    columns[1].copy_from_slice(&[41, 43]);
    let error: MetalResult<()> = Err(GpuError::InvalidInput("rollback error fixture"));
    assert!(rollback_columns_on_error(error, &mut columns, &mut rollback).is_err());
    assert_eq!(columns, [vec![23, 29], vec![17, 19]]);
    assert_eq!(observed.counts(), (8, 0));

    let unwind = std::panic::catch_unwind(|| {
        let _rollback = ColumnMutationRollback::capture(&columns).unwrap();
        panic!("rollback snapshot unwind fixture");
    });
    assert!(unwind.is_err());
    assert_eq!(observed.counts(), (12, 0));
}

#[test]
fn private_fft_staging_clears_pages_after_final_owner_drop_and_unwind() {
    use crate::gpu_secret::ErasureObservation;
    let observed = ErasureObservation::begin();
    let columns = vec![vec![11, 13], vec![17, 19]];
    let buffer = flatten_with_stats(&columns, ColumnStagingPhase::Fft).unwrap();
    assert!(buffer.backing.sensitive);
    assert_eq!(buffer.to_vec().unwrap(), [11, 13, 17, 19]);
    let page_words = buffer.backing.pages.len() * METAL_BUFFER_PAGE_WORDS;
    let retained = Arc::clone(&buffer.backing);
    drop(buffer);
    // A device/command owner may retain the backing. Never erase it early.
    assert_eq!(observed.counts(), (0, 0));
    assert_eq!(retained.pages[0].words[0], 11);
    drop(retained);
    assert_eq!(observed.counts(), (page_words, 0));
    let unwind = std::panic::catch_unwind(|| {
        let _buffer = clone_slice_with_stats(&[23, 29], ColumnStagingPhase::Fft).unwrap();
        panic!("private pooled staging unwind fixture");
    });
    assert!(unwind.is_err());
    assert_eq!(observed.counts(), (page_words + METAL_BUFFER_PAGE_WORDS, 0));
    let constants = PooledBuffer::from_slice(&[7, 11, 13]).unwrap();
    assert!(!constants.backing.sensitive);
    drop(constants);
    assert_eq!(observed.counts(), (page_words + METAL_BUFFER_PAGE_WORDS, 0));
}

#[test]
fn admitted_metal_inventory_requires_all_sixteen_shipping_pipelines() {
    assert_eq!(REQUIRED_PIPELINES.len(), 16);
    for name in [
        POSEIDON_PERMUTE_KERNEL,
        POSEIDON_HASH_KERNEL,
        POSEIDON_HASH_ROWS_KERNEL,
        FFT_KERNEL,
        LDE_KERNEL,
        POST_TILE_KERNEL,
        exact_root::BIT_REVERSE_KERNEL,
        exact_root::LOCAL_TILES_KERNEL,
        exact_root::GLOBAL_STAGE_KERNEL,
        BN254_FFT_KERNEL,
        BN254_LDE_KERNEL,
        BN254_POSEIDON_HASH_KERNEL,
        digest384::KERNEL,
        "digest384_hash_frames_v1",
        "digest384_indexed_first_coordinate_v1",
        "fastpq_sha3_256_continuations",
    ] {
        assert!(REQUIRED_PIPELINES.contains(&name));
    }
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn absent_admitted_bundle_refuses_before_device_and_preserves_original_columns() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_QUARANTINE.with(|state| state.set(None));
        }
    }
    TEST_QUARANTINE.with(|state| assert_eq!(state.replace(Some(false)), None));
    let _reset = Reset;
    assert!(matches!(
        crate::metal_artifact::admitted_bundle(),
        Err(crate::metal_artifact::ArtifactRefusal::Absent)
    ));
    assert!(select_metal_device().is_none());
    let observed = crate::gpu_secret::ErasureObservation::begin();
    let original = vec![vec![11, 13]];
    let mut columns = original.clone();
    assert!(matches!(
        fft_columns_async(&mut columns, 1, 1),
        Err(GpuError::Unsupported(GpuBackend::Metal))
    ));
    assert_eq!(columns, original);
    assert_eq!(observed.counts(), (0, 0));
    assert!(!backend_quarantined());
}
#[test]
#[ignore = "requires genuinely admitted compiled bundle and real Metal device"]
fn admitted_compiled_metal_bundle_loads_every_required_pipeline() {
    crate::metal_artifact::admitted_bundle()
        .expect("real native evidence requires independently admitted compiled bytes");
    let device = select_metal_device().expect("real native evidence requires a visible device");
    let library = load_metal_library(&device).expect("admitted compiled Metal library must load");
    for name in REQUIRED_PIPELINES {
        load_pipeline(&device, &library, name).unwrap_or_else(|error| {
            panic!("admitted compiled Metal pipeline {name} failed: {error}")
        });
    }
}
#[test]
fn zero_log_goldilocks_fft_and_ifft_are_identity_without_dispatch() {
    let original = vec![vec![3], vec![7]];
    let mut columns = original.clone();
    fft_columns_async(&mut columns, 0, 1)
        .expect("length-one FFT should be accepted")
        .wait()
        .expect("identity FFT wait should succeed");
    assert_eq!(columns, original);

    ifft_columns_async(&mut columns, 0, 1)
        .expect("length-one IFFT should be accepted")
        .wait()
        .expect("identity IFFT wait should succeed");
    assert_eq!(columns, original);
}
#[test]
fn oversized_metal_domain_logs_return_invalid_input_before_device_setup() {
    let mut columns = vec![vec![1]];
    assert!(matches!(
        fft_columns_async(&mut columns, u32::MAX, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        ifft_columns_async(&mut columns, u32::MAX, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        fft_tuning_snapshot(u32::MAX),
        Err(GpuError::InvalidInput(_))
    ));

    let coeffs = vec![vec![1]];
    assert!(matches!(
        lde_columns_async(&coeffs, u32::MAX, 1, 1, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        lde_columns_async(&coeffs, 0, u32::MAX, 1, 1),
        Err(GpuError::InvalidInput(_))
    ));

    let mut bn254_columns = vec![vec![0; BN254_LIMBS]];
    assert!(matches!(
        bn254_fft_columns_async(&mut bn254_columns, u32::MAX),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        bn254_lde_columns_async(&bn254_columns, u32::MAX, 1, [0; BN254_LIMBS]),
        Err(GpuError::InvalidInput(_))
    ));
}
#[test]
fn empty_metal_inputs_still_validate_domain_parameters() {
    let mut columns = Vec::<Vec<u64>>::new();
    assert!(matches!(
        fft_columns(&mut columns, u32::MAX, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        ifft_columns(&mut columns, u32::MAX, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        lde_columns(&columns, u32::MAX, 1, 1, 1),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        lde_columns(&columns, 0, 0, 1, 1),
        Err(GpuError::InvalidInput(_))
    ));

    assert!(matches!(
        bn254_fft_columns(&mut columns, u32::MAX),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        bn254_fft_columns_async(&mut columns, 0),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        bn254_lde_columns(&columns, 1, 0, [0; BN254_LIMBS]),
        Err(GpuError::InvalidInput(_))
    ));
    assert!(matches!(
        bn254_lde_columns_async(&columns, u32::MAX, 1, [0; BN254_LIMBS]),
        Err(GpuError::InvalidInput(_))
    ));
}
#[test]
fn valid_empty_metal_inputs_complete_without_device_setup() {
    let mut columns = Vec::<Vec<u64>>::new();
    fft_columns(&mut columns, 0, 1).expect("empty Goldilocks FFT should be a no-op");
    ifft_columns(&mut columns, 0, 1).expect("empty Goldilocks IFFT should be a no-op");
    assert_eq!(
        lde_columns(&columns, 0, 1, 1, 1).expect("empty Goldilocks LDE should succeed"),
        Some(Vec::new())
    );

    bn254_fft_columns(&mut columns, 1).expect("empty BN254 FFT should be a no-op");
    bn254_fft_columns_async(&mut columns, 1)
        .expect("empty BN254 async FFT should be accepted")
        .wait()
        .expect("empty BN254 async FFT wait should succeed");
    assert_eq!(
        bn254_lde_columns(&columns, 1, 1, [0; BN254_LIMBS])
            .expect("empty BN254 LDE should succeed"),
        Some(Vec::new())
    );
    assert_eq!(
        bn254_lde_columns_async(&columns, 1, 1, [0; BN254_LIMBS])
            .expect("empty BN254 async LDE should be accepted")
            .wait()
            .expect("empty BN254 async LDE wait should succeed"),
        Some(Vec::new())
    );
}
#[test]
fn goldilocks_lde_rejects_zero_blowup_before_device_setup() {
    let coeffs = vec![vec![1, 2]];
    assert!(matches!(
        lde_columns_async(&coeffs, 1, 0, 1, 1),
        Err(GpuError::InvalidInput(_))
    ));
}
#[test]
fn bn254_transforms_reject_noncanonical_coefficients_before_device_setup() {
    let mut fft_columns = vec![vec![u64::MAX; BN254_LIMBS * 2]];
    assert!(matches!(
        bn254_fft_columns_async(&mut fft_columns, 1),
        Err(GpuError::InvalidInput(_))
    ));

    let lde_columns = vec![vec![u64::MAX; BN254_LIMBS * 2]];
    assert!(matches!(
        bn254_lde_columns_async(&lde_columns, 1, 1, sample_bn254_coset()),
        Err(GpuError::InvalidInput(_))
    ));
}
#[test]
fn bn254_fft_late_batch_failure_restores_every_input_column() {
    if select_metal_device().is_none() {
        return;
    }
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let mut columns = sample_bn254_columns(3, 4);
    let original = columns.clone();
    // Four one-column batches fill both staging slots, commit two prefixes,
    // then inject the failure during PendingColumns::finish.
    let _failure = fail_column_batch_wait_after(2);
    let error = bn254_fft_columns(&mut columns, 3).expect_err("injected failure expected");
    assert!(
        error
            .to_string()
            .contains("injected column batch wait failure")
    );
    assert_eq!(columns, original);
}
#[test]
fn bn254_fft_dispatch_loop_failure_restores_every_input_column() {
    if select_metal_device().is_none() {
        return;
    }
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let mut columns = sample_bn254_columns(3, 4);
    let original = columns.clone();
    // The third batch drains the first staging slot successfully; the
    // fourth drains the second and fails while dispatches are still built.
    let _failure = fail_column_batch_wait_after(1);
    let error = bn254_fft_columns(&mut columns, 3).expect_err("injected failure expected");
    assert!(
        error
            .to_string()
            .contains("injected column batch wait failure")
    );
    assert_eq!(columns, original);
}
#[test]
fn poseidon_late_batch_failure_restores_every_input_state() {
    if select_metal_device().is_none() {
        return;
    }
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let mut states = (0..4_096 * STATE_WIDTH)
        .map(|index| index as u64 % FIELD_MODULUS)
        .collect::<Vec<_>>();
    let original = states.clone();
    let _failure = fail_poseidon_batch_wait_after(1);
    let error = poseidon_permute(&mut states).expect_err("injected failure expected");
    assert!(
        error
            .to_string()
            .contains("injected Poseidon batch wait failure")
    );
    assert_eq!(states, original);
}
fn sample_fft_columns(log_size: u32, column_count: usize) -> Vec<Vec<u64>> {
    let len = 1usize << log_size;
    (0..column_count)
        .map(|col| {
            (0..len)
                .map(|idx| {
                    let seed = ((col as u64 + 1) * 0x9e37_79b9)
                        ^ ((idx as u64).wrapping_mul(0x2545_f491_4f6c_dd1d));
                    seed % cpu_poseidon::FIELD_MODULUS
                })
                .collect::<Vec<u64>>()
        })
        .collect()
}
fn test_domain_seed(domain: &[u8]) -> u64 {
    let digest = Hash::new(domain);
    let bytes = digest.as_ref();
    let mut chunk = [0u8; 8];
    chunk.copy_from_slice(&bytes[..8]);
    u64::try_from(u128::from(u64::from_le_bytes(chunk)) % u128::from(FIELD_MODULUS))
        .expect("Goldilocks reduction fits u64")
}
fn hash_with_domain_for_tests(domain: &[u8], values: &[u64]) -> u64 {
    let mut sponge = cpu_poseidon::PoseidonSponge::new();
    sponge.absorb(test_domain_seed(domain));
    sponge.absorb_slice(values);
    sponge.squeeze()
}
#[test]
fn fft_dispatch_geometry_scales_with_columns() {
    let lanes = 32;
    let (groups, threads, logical) = super::fft_dispatch_geometry(4, lanes);
    assert_eq!(groups.width, 4);
    assert_eq!(threads.width, u64::from(lanes));
    assert_eq!(logical, u64::from(lanes * 4));
}
#[test]
fn fft_and_ifft_match_cpu_reference() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let scenarios = [(3, 2), (10, 2), (14, 1), (18, 1)];
    for (log_size, column_count) in scenarios {
        let mut cpu_columns = sample_fft_columns(log_size, column_count);
        let mut metal_columns = cpu_columns.clone();
        let root = goldilocks_pow(GOLDILOCKS_GENERATOR, (FIELD_MODULUS - 1) >> log_size);
        let domain = crate::cyclotomic::Domain {
            log_size,
            generator: root,
        };
        for column in &mut cpu_columns {
            crate::cyclotomic::fft(column, domain);
        }
        if unwrap_or_skip(
            super::fft_columns(&mut metal_columns, log_size, root),
            "fft",
        )
        .is_none()
        {
            return;
        }
        assert_eq!(cpu_columns, metal_columns);
        for column in &mut cpu_columns {
            crate::cyclotomic::ifft(column, domain);
        }
        if unwrap_or_skip(
            super::ifft_columns(&mut metal_columns, log_size, root),
            "ifft",
        )
        .is_none()
        {
            return;
        }
        assert_eq!(cpu_columns, metal_columns);
    }
}
#[test]
fn lde_matches_cpu_reference() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let params = CANONICAL_PARAMETER_SETS[0];
    let planner = Planner::new(&params);
    // Canonical V1 parameters use blowup_log=3, so this crosses the 256-word
    // threadgroup tile boundary and exercises the post-tile stage.
    let trace_log = 6;
    let trace_len = 1usize << trace_log;
    let coeffs = vec![
        (0..trace_len)
            .map(|idx| (idx as u64).wrapping_mul(13).wrapping_add(3) % cpu_poseidon::FIELD_MODULUS)
            .collect::<Vec<u64>>(),
        (0..trace_len)
            .map(|idx| (idx as u64).wrapping_mul(23).wrapping_add(17) % cpu_poseidon::FIELD_MODULUS)
            .collect::<Vec<u64>>(),
    ];
    let cpu_eval = planner.lde_columns(&coeffs);
    let lde_root = planner
        .lde_domain(trace_log + planner.blowup_log())
        .generator;
    let Some(gpu_eval) = unwrap_or_skip(
        super::lde_columns(
            &coeffs,
            trace_log,
            planner.blowup_log(),
            lde_root,
            params.omega_coset,
        ),
        "lde",
    ) else {
        return;
    };
    let gpu_eval = gpu_eval.expect("Metal backend declined workload");
    assert_eq!(cpu_eval, gpu_eval);
}
#[test]
fn poseidon_matches_cpu_permutation() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let mut cpu_states = Vec::new();
    for idx in 0u64..4 {
        cpu_states.push(idx * 11);
        cpu_states.push(idx * 7 + 3);
        cpu_states.push(idx * 5 + 1);
    }
    let mut metal_states = cpu_states.clone();
    for chunk in cpu_states.chunks_exact_mut(cpu_poseidon::STATE_WIDTH) {
        let mut state = [0u64; cpu_poseidon::STATE_WIDTH];
        state.copy_from_slice(chunk);
        cpu_poseidon::permute_state(&mut state);
        chunk.copy_from_slice(&state);
    }
    if unwrap_or_skip(super::poseidon_permute(&mut metal_states), "poseidon").is_none() {
        return;
    }
    assert_eq!(cpu_states, metal_states);
}
#[test]
fn poseidon_multi_state_chunks_match_cpu_edge_vectors() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let Some(context) = unwrap_or_skip(super::metal_context(), "Poseidon multi-state chunks")
    else {
        return;
    };
    let edge_words = [
        0,
        1,
        cpu_poseidon::FIELD_MODULUS - 1,
        cpu_poseidon::FIELD_MODULUS - 2,
        u64::from(u32::MAX),
        1u64 << 32,
        1u64 << 63,
        cpu_poseidon::FIELD_MODULUS / 2,
    ];
    let pipeline = &context.poseidon_permute;
    let limits = super::pipeline_limits(pipeline);
    for state_count in [1u32, 4, 5, 33, 257] {
        let input: Vec<_> = (0..state_count as usize * cpu_poseidon::STATE_WIDTH)
            .map(|index| edge_words[index % edge_words.len()])
            .collect();
        let mut expected = input.clone();
        for words in expected.chunks_exact_mut(cpu_poseidon::STATE_WIDTH) {
            let mut state = [words[0], words[1], words[2]];
            cpu_poseidon::permute_state(&mut state);
            words.copy_from_slice(&state);
        }
        for states_per_lane in [1, 4, 8] {
            let tuning = super::metal_config::PoseidonTuning {
                threadgroup_lanes: 32,
                states_per_lane,
            };
            let (groups, group, logical_threads, _) =
                super::poseidon_dispatch_geometry(state_count, tuning, &limits);
            for _ in 0..3 {
                let mut buffer =
                    super::clone_slice_with_stats(&input, super::ColumnStagingPhase::Poseidon)
                        .expect("stage edge vectors");
                let metal_buffer = super::shared_pooled_buffer(&context.device, &mut buffer)
                    .expect("shared edge-vector buffer");
                let args = super::PoseidonArgs {
                    state_count,
                    states_per_lane,
                    block_count: 0,
                    _reserved: 0,
                };
                let (queue, queue_index) = context.queues.select(state_count, 0);
                let ticket = super::submit_compute_with_geometry(
                    (queue, queue_index),
                    pipeline,
                    Some((groups, group, logical_threads)),
                    logical_threads,
                    None,
                    false,
                    |encoder| {
                        encoder.set_buffer(0, Some(&metal_buffer), 0);
                        encoder.set_bytes(
                            1,
                            std::mem::size_of::<super::PoseidonArgs>() as u64,
                            std::ptr::from_ref(&args).cast(),
                        );
                    },
                )
                .expect("submit multi-state Poseidon kernel");
                super::wait_for_ticket(ticket).expect("multi-state Poseidon completion");
                let mut actual = vec![0; input.len()];
                buffer.copy_to_slice(&mut actual);
                assert_eq!(
                    actual, expected,
                    "state_count={state_count}, states_per_lane={states_per_lane}"
                );
            }
        }
    }
}
#[test]
fn poseidon_hash_rows_matches_cpu_reference() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let row_count = 64usize;
    let columns = (0..5usize)
        .map(|column| {
            (0..row_count)
                .map(|row| {
                    ((column as u64 + 3) * 97 + (row as u64 * 13)) % cpu_poseidon::FIELD_MODULUS
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected = (0..row_count)
        .map(|row| {
            let mut limbs = Vec::with_capacity(columns.len() + 2);
            limbs.push(row as u64);
            limbs.push(columns.len() as u64);
            for column in &columns {
                limbs.push(column[row]);
            }
            cpu_poseidon::hash_field_elements(&limbs)
        })
        .collect::<Vec<_>>();
    let Some(actual) = unwrap_or_skip(super::poseidon_hash_rows(&columns), "poseidon_hash_rows")
    else {
        return;
    };
    assert_eq!(actual, expected);
}
#[test]
fn poseidon_hash_columns_batches_multi_block_columns() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let domain_names = (0..8usize)
        .map(|idx| format!("fastpq:test:scalar-column:vectorized:{idx}"))
        .collect::<Vec<_>>();
    let domains = domain_names.iter().map(String::as_str).collect::<Vec<_>>();
    let columns = (0..domains.len())
        .map(|column| {
            (0..9usize)
                .map(|row| {
                    ((column as u64 + 5) * 101 + (row as u64 * 17)) % cpu_poseidon::FIELD_MODULUS
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let batch = PoseidonColumnBatch::from_domains_and_columns(&domains, &columns).expect("batch");
    assert!(
        batch.block_count() > 1,
        "test batch must exercise multi-block sponge absorption"
    );
    let expected =
        crate::trace::hash_columns_cpu_batch_inputs(&domains, &columns).expect("cpu reference");
    super::adaptive_scheduler()
        .poseidon
        .record_sample(4, domains.len() as u32, 0.0);
    super::enable_kernel_stats(true);
    let Some(actual) = unwrap_or_skip(
        super::poseidon_hash_columns(&batch),
        "poseidon_hash_columns vectorized",
    ) else {
        super::enable_kernel_stats(false);
        return;
    };
    let stats = super::take_kernel_stats().expect("kernel stats enabled");
    super::enable_kernel_stats(false);
    assert_eq!(actual, expected);
    let sample = stats
        .iter()
        .find(|sample| sample.kind.as_str() == "poseidon" && sample.column_count > 1)
        .unwrap_or_else(|| panic!("expected a vectorized Poseidon dispatch, got {stats:?}"));
    let actual_limits = super::PipelineLimits {
        exec_width: sample.execution_width,
        max_threads: sample.max_threads_per_group,
    };
    let mut expected_tuning =
        crate::metal_config::poseidon_tuning(actual_limits.exec_width, actual_limits.max_threads);
    expected_tuning.states_per_lane = 1;
    let (_, expected_threadgroup, _, _) =
        super::poseidon_dispatch_geometry(sample.column_count, expected_tuning, &actual_limits);
    assert_eq!(
        sample.threadgroup_width, expected_threadgroup.width,
        "Poseidon column geometry must use the limits of the pipeline that was dispatched"
    );
}
#[test]
fn poseidon_hash_columns_batches_two_word_inputs() {
    ensure_multi_queue_env();
    let _gpu_lane = crate::backend::acquire_gpu_lane();
    let pairs = (0..16usize)
        .map(|idx| {
            let left =
                (idx as u64).wrapping_mul(0xd1b5_4a32_d192_ed03) % cpu_poseidon::FIELD_MODULUS;
            let right = (idx as u64)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(7)
                % cpu_poseidon::FIELD_MODULUS;
            [left, right]
        })
        .collect::<Vec<_>>();
    let batch = PoseidonColumnBatch::from_domain_and_pairs(SCALAR_PAIR_DOMAIN_FOR_TESTS, &pairs)
        .expect("batch");
    let expected = pairs
        .iter()
        .map(|pair| hash_with_domain_for_tests(SCALAR_PAIR_DOMAIN_FOR_TESTS, pair))
        .collect::<Vec<_>>();
    super::adaptive_scheduler()
        .poseidon
        .record_sample(8, pairs.len() as u32, 0.0);
    super::enable_kernel_stats(true);
    let Some(actual) = unwrap_or_skip(
        super::poseidon_hash_columns(&batch),
        "poseidon_hash_columns two-word arithmetic",
    ) else {
        super::enable_kernel_stats(false);
        return;
    };
    let stats = super::take_kernel_stats().expect("kernel stats enabled");
    super::enable_kernel_stats(false);
    assert_eq!(actual, expected);
    assert!(
        stats
            .iter()
            .any(|sample| sample.kind.as_str() == "poseidon" && sample.column_count > 1),
        "expected Merkle pair hashing to use a vectorized dispatch, got {stats:?}"
    );
}
#[test]
fn poseidon_dispatch_geometry_uses_actual_work() {
    let limits = super::PipelineLimits {
        exec_width: 32,
        max_threads: 64,
    };
    let tuning = super::metal_config::PoseidonTuning {
        threadgroup_lanes: 32,
        states_per_lane: 4,
    };
    let (groups, group, logical_threads, states_per_lane) =
        super::poseidon_dispatch_geometry(16, tuning, &limits);
    assert_eq!(logical_threads, 4);
    assert_eq!(states_per_lane, 4);
    assert_eq!(group.width, 4);
    assert_eq!(groups.width, 1);
}
#[test]
fn poseidon_tuning_snapshot_reports_effective_parity_shape() {
    if super::select_metal_device().is_none() {
        return;
    }
    let tuning = super::poseidon_tuning_snapshot().expect("Metal Poseidon tuning");
    assert_eq!(tuning.states_per_lane, 1);
}
#[test]
fn bn254_poseidon_dispatch_geometry_uses_actual_work() {
    let limits = super::PipelineLimits {
        exec_width: 32,
        max_threads: 64,
    };
    let tuning = super::metal_config::PoseidonTuning {
        threadgroup_lanes: 32,
        states_per_lane: 4,
    };
    let (groups, group, logical_threads, states_per_lane) =
        super::bn254_poseidon_dispatch_geometry(64, tuning, &limits);
    assert_eq!(logical_threads, 16);
    assert_eq!(states_per_lane, 4);
    assert_eq!(group.width, 16);
    assert_eq!(groups.width, 1);
    let (groups, group, logical_threads, states_per_lane) =
        super::bn254_poseidon_dispatch_geometry(513, tuning, &limits);
    assert_eq!(logical_threads, 129);
    assert_eq!(states_per_lane, 4);
    assert_eq!(group.width, 32);
    assert_eq!(groups.width, 5);
    let wide_tuning = super::metal_config::PoseidonTuning {
        threadgroup_lanes: 256,
        states_per_lane: 2,
    };
    let wide_limits = super::PipelineLimits {
        exec_width: 32,
        max_threads: 512,
    };
    let (groups, group, logical_threads, states_per_lane) =
        super::bn254_poseidon_dispatch_geometry(512, wide_tuning, &wide_limits);
    assert_eq!(logical_threads, 256);
    assert_eq!(states_per_lane, 2);
    assert_eq!(
        group.width,
        u64::from(super::BN254_POSEIDON_THREADGROUP_CAPACITY)
    );
    assert_eq!(groups.width, 2);
}
#[test]
fn column_batch_iterator_chunks_columns() {
    let batches: Vec<_> = super::column_batch_ranges(10, 4).collect();
    assert_eq!(batches, vec![(0, 4), (4, 4), (8, 2)]);
}
#[test]
fn column_batch_iterator_handles_zero_total_and_batch_size() {
    let empty: Vec<_> = super::column_batch_ranges(0, 8).collect();
    assert!(empty.is_empty());
    let singletons: Vec<_> = super::column_batch_ranges(3, 0).collect();
    assert_eq!(singletons, vec![(0, 1), (1, 1), (2, 1)]);
}
#[test]
fn column_batch_iterator_exact_size_handles_u32_max() {
    let mut batches = super::ColumnBatchIter::new(u32::MAX, 2);
    let expected = usize::try_from(u32::MAX.div_ceil(2)).expect("batch count fits usize");
    assert_eq!(batches.len(), expected);
    assert_eq!(batches.size_hint(), (expected, Some(expected)));
    assert_eq!(batches.next(), Some((0, 2)));
    assert_eq!(batches.len(), expected - 1);
}
#[test]
fn column_batch_iterator_reports_exact_len() {
    let mut iter = super::column_batch_ranges(9, 4);
    assert_eq!(iter.len(), 3);
    iter.next();
    assert_eq!(iter.len(), 2);
    let _: Vec<_> = iter.collect();
}
#[test]
fn stage_twiddles_match_reference_values() {
    let expected = vec![
        0xffff_ffff_0000_0000,
        0x0001_0000_0000_0000,
        0xffff_fffe_ff00_0001,
        0xefff_ffff_0000_0001,
        0x0000_0000_3fff_ffff_c000,
    ];
    let root = super::goldilocks_pow(super::GOLDILOCKS_GENERATOR, (FIELD_MODULUS - 1) >> 5);
    let twiddles = super::compute_stage_twiddles(5, root, false);
    assert_eq!(twiddles, expected);
    let inverse_twiddles = super::compute_stage_twiddles(5, root, true);
    for (forward, inverse) in expected.iter().zip(inverse_twiddles.iter()) {
        assert_eq!(*inverse, super::goldilocks_inv(*forward));
    }
}
#[test]
fn digest384_gpu_sensitive_pages_wipe_only_after_exclusive_ownership() {
    let mut buffer = PooledBuffer::sensitive_from_slice(&[17, 23, 91]).unwrap();
    let retained = Arc::clone(&buffer.backing);
    assert!(Arc::get_mut(&mut buffer.backing).is_none());
    assert_eq!(buffer.to_vec().unwrap(), [17, 23, 91]);
    drop(retained);
    let backing = Arc::get_mut(&mut buffer.backing).unwrap();
    backing.pages[0].words[METAL_BUFFER_PAGE_WORDS - 1] = 99;
    backing.wipe_sensitive_pages();
    assert!(
        backing
            .pages
            .iter()
            .all(|page| page.words.iter().all(|word| *word == 0))
    );
    let mut ordinary = PooledBuffer::from_slice(&[17, 23, 91]).unwrap();
    Arc::get_mut(&mut ordinary.backing)
        .unwrap()
        .wipe_sensitive_pages();
    assert_eq!(ordinary.to_vec().unwrap(), [17, 23, 91]);
    let zeroed = PooledBuffer::sensitive_zeroed(3).unwrap();
    assert_eq!(zeroed.to_vec().unwrap(), [0; 3]);
    assert!(zeroed.backing.sensitive);
}

#[test]
fn buffer_pool_recycles_aligned_page_vectors() {
    let mut pool = BufferPool::default();
    assert_eq!(pool.len_for_tests(), 0);
    let buffer = pool.take(2).expect("allocate pages");
    assert!(buffer.capacity() >= 2);
    pool.recycle(buffer);
    assert_eq!(pool.len_for_tests(), 1);
    let buffer = pool.take(1).expect("reuse pages");
    assert!(buffer.capacity() >= 1);
    assert_eq!(pool.len_for_tests(), 0);
}
#[test]
fn digest384_admission_covers_retained_pool_and_oversized_staging_reuse() {
    let mut pool = BufferPool::default();
    let pages_per_entry = MAX_BUFFER_POOL_CACHED_PAGES / MAX_BUFFER_POOL_BUFFERS;
    for _ in 0..MAX_BUFFER_POOL_BUFFERS {
        let mut pages = Vec::new();
        pages.try_reserve_exact(pages_per_entry).unwrap();
        pool.recycle(pages);
    }
    let cached_before = pool.spare.iter().map(Vec::capacity).sum::<usize>();
    assert_eq!(cached_before, MAX_BUFFER_POOL_CACHED_PAGES);
    let jobs: usize = 1024;
    let payload = jobs * 2408;
    let sizes = [192 * jobs, 16 * jobs, payload, 48 * jobs];
    let mut live = Vec::new();
    for bytes in sizes {
        let requested_pages = bytes.div_ceil(METAL_BUFFER_PAGE_BYTES);
        let allocation = pool.take(requested_pages).unwrap();
        assert!(allocation.capacity() > requested_pages);
        live.push(allocation);
    }
    let live_and_idle_pages = live
        .iter()
        .chain(&pool.spare)
        .map(Vec::capacity)
        .sum::<usize>();
    assert_eq!(live_and_idle_pages, cached_before);
    let charged = crate::digest384_batch::last_fields_payload_charge(jobs, payload).unwrap();
    assert!(charged >= live_and_idle_pages * METAL_BUFFER_PAGE_BYTES + jobs * 48);
    assert!(
        charged - crate::gpu_memory::METAL_POOL_MAX_CACHED_BYTES
            < live_and_idle_pages * METAL_BUFFER_PAGE_BYTES,
        "requested staging alone does not charge retained oversized pages"
    );
    for allocation in live {
        pool.recycle(allocation);
    }
    assert!(pool.spare.iter().map(Vec::capacity).sum::<usize>() <= MAX_BUFFER_POOL_CACHED_PAGES);
}

#[test]
fn buffer_pool_rejects_oversized_cached_allocations() {
    assert!(buffer_pool_capacity_is_cacheable(1));
    assert!(buffer_pool_capacity_is_cacheable(
        MAX_BUFFER_POOL_PAGES_PER_BUFFER
    ));
    assert!(!buffer_pool_capacity_is_cacheable(0));
    assert!(!buffer_pool_capacity_is_cacheable(
        MAX_BUFFER_POOL_PAGES_PER_BUFFER + 1
    ));
}
#[test]
fn pooled_buffer_zeroed_is_preinitialized() {
    let buffer = PooledBuffer::zeroed(4).expect("allocate pooled buffer");
    assert_eq!(buffer.to_vec().expect("copy pooled buffer"), [0, 0, 0, 0]);
}
#[test]
fn pooled_buffer_copy_roundtrips_across_page_boundaries() {
    let words = (0..METAL_BUFFER_PAGE_WORDS + 3)
        .map(|index| index as u64)
        .collect::<Vec<_>>();
    let buffer = PooledBuffer::from_slice(&words).expect("allocate pooled buffer");
    assert_eq!(buffer.to_vec().expect("copy pooled buffer"), words);

    let mut boundary = [0; 4];
    buffer.copy_range_to_slice(METAL_BUFFER_PAGE_WORDS - 2, &mut boundary);
    assert_eq!(
        boundary,
        [
            (METAL_BUFFER_PAGE_WORDS - 2) as u64,
            (METAL_BUFFER_PAGE_WORDS - 1) as u64,
            METAL_BUFFER_PAGE_WORDS as u64,
            (METAL_BUFFER_PAGE_WORDS + 1) as u64,
        ]
    );
}
#[test]
fn pooled_buffer_region_is_page_aligned_and_page_rounded() {
    assert_eq!(mem::align_of::<MetalBufferPage>(), METAL_BUFFER_PAGE_BYTES);
    assert_eq!(mem::size_of::<MetalBufferPage>(), METAL_BUFFER_PAGE_BYTES);
    for logical_words in [
        0,
        1,
        METAL_BUFFER_PAGE_WORDS - 1,
        METAL_BUFFER_PAGE_WORDS,
        METAL_BUFFER_PAGE_WORDS + 1,
    ] {
        let mut buffer = PooledBuffer::zeroed(logical_words).expect("allocate pooled buffer");
        let (pointer, byte_len) = buffer.metal_region();
        assert_eq!(pointer as usize % METAL_BUFFER_PAGE_BYTES, 0);
        assert_eq!(byte_len as usize % METAL_BUFFER_PAGE_BYTES, 0);
        assert!(byte_len as usize >= logical_words * mem::size_of::<u64>());
        assert_eq!(
            byte_len as usize,
            metal_buffer_page_count(logical_words) * METAL_BUFFER_PAGE_BYTES
        );
    }
}
#[test]
fn aligned_pooled_buffer_can_back_a_metal_buffer_until_deallocation() {
    let Some(device) = select_metal_device() else {
        return;
    };
    let mut buffer = PooledBuffer::from_slice(&[1, 2, 3, 4]).expect("allocate pooled buffer");
    let metal_buffer = shared_pooled_buffer(&device, &mut buffer)
        .expect("aligned shared buffer should fit the Metal device limit");
    let weak_backing = buffer.weak_backing_for_tests();

    drop(buffer);
    assert!(weak_backing.upgrade().is_some());
    drop(metal_buffer);
    for _ in 0..64 {
        if weak_backing.upgrade().is_none() {
            break;
        }
        thread::yield_now();
    }
    assert!(
        weak_backing.upgrade().is_none(),
        "Metal buffer deallocation must release its aligned backing"
    );
}
#[test]
fn partial_batch_abort_retains_each_backing_until_metal_deallocation() {
    let buffers = [
        PooledBuffer::zeroed(4).expect("allocate first pooled buffer"),
        PooledBuffer::zeroed(8).expect("allocate second pooled buffer"),
    ];
    let weak_backings = buffers
        .iter()
        .map(PooledBuffer::weak_backing_for_tests)
        .collect::<Vec<_>>();
    let retentions = buffers
        .iter()
        .map(|buffer| MetalBufferBackingRetention::new(buffer.backing()))
        .collect::<Vec<_>>();

    drop(buffers);
    assert!(
        weak_backings
            .iter()
            .all(|backing| backing.upgrade().is_some())
    );

    retentions[0].release();
    assert!(weak_backings[0].upgrade().is_none());
    assert!(weak_backings[1].upgrade().is_some());
    retentions[1].release();
    assert!(weak_backings[1].upgrade().is_none());
}
#[test]
fn callback_release_paths_recover_poisoned_locks() {
    let buffer = PooledBuffer::zeroed(4).expect("allocate pooled buffer");
    let weak_backing = buffer.weak_backing_for_tests();
    let retention = MetalBufferBackingRetention::new(buffer.backing());
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = retention.backing.lock().expect("retention lock");
        panic!("poison retention lock for callback regression");
    }));
    assert!(poisoned.is_err());
    drop(buffer);
    retention.release();
    assert!(weak_backing.upgrade().is_none());

    let semaphore = CommandSemaphore::new(1);
    *semaphore.state.lock().expect("semaphore lock") = 1;
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = semaphore.state.lock().expect("semaphore lock");
        panic!("poison semaphore lock for callback regression");
    }));
    assert!(poisoned.is_err());
    semaphore.release();
    let in_flight = *semaphore
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(in_flight, 0);
}
#[test]
fn queue_stats_capture_overlap() {
    let start = Instant::now();
    let mut state = super::QueueStatsState::default();
    state.record_launch(0, start);
    state.record_launch(0, start + Duration::from_millis(1));
    state.record_completion(0, start + Duration::from_millis(2));
    state.record_completion(0, start + Duration::from_millis(3));
    let snapshot = state.snapshot(2);
    assert_eq!(snapshot.dispatch_count, 2);
    assert_eq!(snapshot.max_in_flight, 2);
    assert_eq!(snapshot.overlap_ms, 1.0);
}
#[test]
fn bounded_ticket_window_drains_in_fifo_order() {
    let mut tickets = Vec::with_capacity(2);
    tickets.extend([11, 22]);
    assert_eq!(super::pop_oldest_ticket_if_full(&mut tickets, 2), Some(11));
    tickets.push(33);
    assert_eq!(tickets, [22, 33]);
    assert_eq!(super::pop_oldest_ticket_if_full(&mut tickets, 3), None);
}
#[test]
fn telemetry_sample_retention_is_bounded() {
    let mut samples = Vec::new();
    for sample in 0..=super::MAX_RETAINED_TELEMETRY_SAMPLES {
        super::push_bounded_telemetry_sample(&mut samples, sample);
    }
    assert_eq!(samples.len(), super::MAX_RETAINED_TELEMETRY_SAMPLES);
    assert_eq!(samples.first(), Some(&0));
    assert_eq!(
        samples.last(),
        Some(&(super::MAX_RETAINED_TELEMETRY_SAMPLES - 1))
    );
}
#[test]
fn command_completion_releases_permit_and_queue_stats_once() {
    super::enable_queue_depth_stats(true);
    let semaphore = Box::leak(Box::new(super::CommandSemaphore::new(1)));
    assert!(semaphore.acquire_timeout(Duration::from_millis(1)));
    assert_eq!(semaphore.in_flight_for_tests(), 1);
    let completion = super::CommandPermitCompletion::new(semaphore, 0);
    completion.mark_launched();
    completion.mark_launched();
    completion.complete();
    completion.complete();
    assert_eq!(semaphore.in_flight_for_tests(), 0);
    let stats = super::take_queue_depth_stats().expect("stats captured");
    super::enable_queue_depth_stats(false);
    assert_eq!(stats.dispatch_count, 1);
    assert_eq!(stats.queues[0].dispatch_count, 1);
}
#[test]
fn launched_permit_drop_defers_release_to_completion_handler() {
    let semaphore = Box::leak(Box::new(super::CommandSemaphore::new(1)));
    assert!(semaphore.acquire_timeout(Duration::from_millis(1)));
    let completion = Arc::new(super::CommandPermitCompletion::new(semaphore, 0));
    let mut permit = super::CommandPermit {
        completion: Arc::clone(&completion),
    };
    permit.mark_launched();

    drop(permit);
    assert_eq!(
        semaphore.in_flight_for_tests(),
        1,
        "a timed-out/dropped launched ticket must keep its permit"
    );
    completion.complete();
    assert_eq!(semaphore.in_flight_for_tests(), 0);
}
#[test]
fn unlaunched_permit_drop_releases_immediately() {
    let semaphore = Box::leak(Box::new(super::CommandSemaphore::new(1)));
    assert!(semaphore.acquire_timeout(Duration::from_millis(1)));
    let permit = super::CommandPermit {
        completion: Arc::new(super::CommandPermitCompletion::new(semaphore, 0)),
    };

    drop(permit);
    assert_eq!(semaphore.in_flight_for_tests(), 0);
}
#[test]
fn poseidon_dispatch_staging_uses_deeper_completion_backed_pipe() {
    const {
        assert!(super::POSEIDON_DISPATCH_PIPE_DEPTH > 1);
        assert!(super::POSEIDON_DISPATCH_PIPE_DEPTH <= super::DEFAULT_MAX_COMMAND_BUFFERS);
    }
}
#[test]
fn column_staging_stats_capture_events() {
    super::enable_queue_depth_stats(true);
    super::record_staging_wait(super::ColumnStagingPhase::Fft, Duration::from_millis(2));
    super::record_staging_flatten(super::ColumnStagingPhase::Fft, Duration::from_millis(5));
    super::record_staging_flatten(
        super::ColumnStagingPhase::Poseidon,
        Duration::from_millis(3),
    );
    let stats = super::take_column_staging_stats().expect("staging stats captured");
    super::enable_queue_depth_stats(false);
    let total = stats.total();
    assert_eq!(total.batches, 2);
    assert!((total.flatten_ms - 8.0).abs() < f64::EPSILON);
    assert!((total.wait_ms - 2.0).abs() < f64::EPSILON);
    assert_eq!(stats.fft().batches, 1);
    assert!((stats.fft().flatten_ms - 5.0).abs() < f64::EPSILON);
    assert!((stats.fft().wait_ms - 2.0).abs() < f64::EPSILON);
    assert_eq!(stats.poseidon().batches, 1);
    assert!((stats.poseidon().flatten_ms - 3.0).abs() < f64::EPSILON);
    assert_eq!(stats.poseidon().wait_ms, 0.0);
    assert_eq!(stats.lde().batches, 0);
    let fft_samples = stats.fft_samples();
    assert_eq!(fft_samples.len(), 1);
    assert_eq!(fft_samples[0].batch, 0);
    assert!((fft_samples[0].flatten_ms - 5.0).abs() < f64::EPSILON);
    assert!((fft_samples[0].wait_ms - 2.0).abs() < f64::EPSILON);
    let poseidon_samples = stats.poseidon_samples();
    assert_eq!(poseidon_samples.len(), 1);
    assert_eq!(poseidon_samples[0].batch, 0);
    assert!((poseidon_samples[0].flatten_ms - 3.0).abs() < f64::EPSILON);
    assert_eq!(poseidon_samples[0].wait_ms, 0.0);
    assert!(stats.lde_samples().is_empty());
}
#[test]
fn queue_depth_delta_handles_accumulation() {
    let before = QueueDepthStats {
        limit: 4,
        dispatch_count: 2,
        max_in_flight: 1,
        busy_ms: 0.5,
        overlap_ms: 0.125,
        window_ms: 0.5,
        queues: vec![
            QueueLaneStats {
                index: 0,
                dispatch_count: 1,
                max_in_flight: 1,
                busy_ms: 0.25,
                overlap_ms: 0.0,
            },
            QueueLaneStats {
                index: 1,
                dispatch_count: 1,
                max_in_flight: 1,
                busy_ms: 0.25,
                overlap_ms: 0.125,
            },
        ],
    };
    let after = QueueDepthStats {
        limit: 4,
        dispatch_count: 5,
        max_in_flight: 3,
        busy_ms: 1.5,
        overlap_ms: 0.625,
        window_ms: 1.5,
        queues: vec![
            QueueLaneStats {
                index: 0,
                dispatch_count: 3,
                max_in_flight: 2,
                busy_ms: 1.0,
                overlap_ms: 0.25,
            },
            QueueLaneStats {
                index: 1,
                dispatch_count: 3,
                max_in_flight: 2,
                busy_ms: 0.5,
                overlap_ms: 0.375,
            },
        ],
    };
    let delta = after.delta_since(&before);
    assert_eq!(delta.limit, 4);
    assert_eq!(delta.dispatch_count, 3);
    assert_eq!(delta.max_in_flight, 2);
    assert!((delta.busy_ms - 1.0).abs() < f64::EPSILON);
    assert!((delta.overlap_ms - 0.5).abs() < f64::EPSILON);
    assert!((delta.window_ms - 1.0).abs() < f64::EPSILON);
    assert_eq!(delta.queues.len(), 2);
    assert_eq!(delta.queues[0].dispatch_count, 2);
    assert!((delta.queues[0].busy_ms - 0.75).abs() < f64::EPSILON);
    assert!((delta.queues[1].overlap_ms - 0.25).abs() < f64::EPSILON);
    let mut total = QueueDepthStats::default();
    total.accumulate_delta(&delta);
    assert_eq!(total.dispatch_count, 3);
    assert_eq!(total.max_in_flight, 2);
    assert!((total.busy_ms - 1.0).abs() < f64::EPSILON);
    assert!((total.overlap_ms - 0.5).abs() < f64::EPSILON);
    assert!((total.window_ms - 1.0).abs() < f64::EPSILON);
    assert_eq!(total.queues.len(), 2);
    assert_eq!(total.queues[0].max_in_flight, 2);
    let next = QueueDepthStats {
        limit: 4,
        dispatch_count: 1,
        max_in_flight: 1,
        busy_ms: 0.25,
        overlap_ms: 0.125,
        window_ms: 0.25,
        queues: vec![QueueLaneStats {
            index: 0,
            dispatch_count: 1,
            max_in_flight: 1,
            busy_ms: 0.25,
            overlap_ms: 0.125,
        }],
    };
    total.accumulate_delta(&next);
    assert_eq!(total.dispatch_count, 4);
    assert_eq!(total.max_in_flight, 2);
    assert!((total.busy_ms - 1.25).abs() < f64::EPSILON);
    assert!((total.overlap_ms - 0.625).abs() < f64::EPSILON);
    assert!((total.window_ms - 1.25).abs() < f64::EPSILON);
    assert_eq!(total.queues.len(), 2);
    assert_eq!(total.queues[0].dispatch_count, 3);
    assert_eq!(total.queues[1].dispatch_count, 2);
}
#[test]
fn lde_batch_size_scales_with_domain() {
    assert_eq!(default_lde_columns_per_batch(10, 32), 64);
    assert_eq!(default_lde_columns_per_batch(12, 32), 64);
    assert_eq!(default_lde_columns_per_batch(15, 32), 64);
    assert_eq!(default_lde_columns_per_batch(17, 32), 4);
    assert_eq!(default_lde_columns_per_batch(18, 32), 2);
    assert_eq!(
        default_lde_columns_per_batch(22, 32),
        MIN_LDE_COLUMNS_PER_BATCH
    );
}
#[test]
fn lde_batch_size_scales_with_lane_width() {
    assert_eq!(default_lde_columns_per_batch(10, 32), 64);
    assert_eq!(default_lde_columns_per_batch(10, 128), 32);
    assert_eq!(default_lde_columns_per_batch(10, 256), 16);
    assert_eq!(
        default_lde_columns_per_batch(20, 256),
        DEFAULT_LDE_COLUMNS_PER_BATCH
    );
}
#[test]
fn fft_batch_size_scales_with_lane_width() {
    assert_eq!(default_fft_columns_per_batch(32), MAX_FFT_COLUMNS_PER_BATCH);
    assert_eq!(default_fft_columns_per_batch(64), MAX_FFT_COLUMNS_PER_BATCH);
    assert_eq!(default_fft_columns_per_batch(128), 32);
    assert_eq!(default_fft_columns_per_batch(256), 16);
}
#[test]
fn fft_batch_override_validation() {
    assert_eq!(parse_fft_batch_override("2").unwrap(), 2);
    assert!(parse_fft_batch_override("0").is_err());
    assert!(parse_fft_batch_override("65").is_err());
    assert!(parse_fft_batch_override("abc").is_err());
}
#[test]
fn lde_batch_override_validation() {
    assert_eq!(parse_lde_batch_override("4").unwrap(), 4);
    assert!(parse_lde_batch_override("0").is_err());
    assert!(parse_lde_batch_override("65").is_err());
    assert!(parse_lde_batch_override("abc").is_err());
}
#[test]
fn default_in_flight_limit_scales_with_parallelism() {
    assert_eq!(default_in_flight_limit_for_parallelism(1), 2);
    assert_eq!(default_in_flight_limit_for_parallelism(2), 2);
    assert_eq!(default_in_flight_limit_for_parallelism(4), 2);
    assert_eq!(default_in_flight_limit_for_parallelism(6), 3);
    assert_eq!(default_in_flight_limit_for_parallelism(8), 4);
    assert_eq!(default_in_flight_limit_for_parallelism(12), 6);
    assert_eq!(default_in_flight_limit_for_parallelism(32), 16);
}
#[test]
fn adaptive_batch_doubles_until_target() {
    let state = AdaptiveBatchState::new(1, 2.0);
    let selection = state.select(2, 16, AdaptiveStateId::Fft);
    assert_eq!(selection.columns(), 2);
    state.record_sample(2, 16, 1.0);
    let next = state.select(2, 16, AdaptiveStateId::Fft);
    assert_eq!(next.columns(), 4);
}
#[test]
fn adaptive_batch_backs_off_after_slow_sample() {
    let state = AdaptiveBatchState::new(1, 2.0);
    let selection = state.select(2, 32, AdaptiveStateId::Fft);
    assert_eq!(selection.columns(), 2);
    state.record_sample(2, 32, 1.0);
    let grown = state.select(2, 32, AdaptiveStateId::Fft);
    assert_eq!(grown.columns(), 4);
    state.record_sample(4, 32, 2.0 * ADAPTIVE_BACKOFF_RATIO + 0.1);
    let backoff = state.select(2, 32, AdaptiveStateId::Fft);
    assert_eq!(backoff.columns(), 2);
}
#[test]
fn adaptive_batch_backoff_respects_minimum_floor() {
    let state = AdaptiveBatchState::new(3, 2.0);
    let selection = state.select(4, 64, AdaptiveStateId::Fft);
    assert_eq!(selection.columns(), 4);
    state.record_sample(4, 64, 2.0 * ADAPTIVE_BACKOFF_RATIO + 0.1);
    let next = state.select(4, 64, AdaptiveStateId::Fft);
    assert_eq!(next.columns(), 3);
}
#[test]
fn parse_gpu_core_count_reads_fields() {
    let payload = r#"{"SPDisplaysDataType":[{"sppci_cores":10}]}"#;
    assert_eq!(super::parse_gpu_core_count(payload), Some(10));
    let payload = r#"{"SPDisplaysDataType":[{"spdisplays_cores":"8"}]}"#;
    assert_eq!(super::parse_gpu_core_count(payload), Some(8));
}
#[test]
fn kernel_descriptors_cover_entry_points() {
    let descriptors = super::metal_kernel_descriptors();
    assert_eq!(descriptors.len(), 12);
    for name in [
        exact_root::BIT_REVERSE_KERNEL,
        exact_root::LOCAL_TILES_KERNEL,
        exact_root::GLOBAL_STAGE_KERNEL,
        "fastpq_fft_columns",
        "fastpq_fft_post_tiling",
        "fastpq_lde_columns",
        "poseidon_permute",
        "poseidon_hash_columns",
        "poseidon_hash_rows",
        "bn254_fft_columns",
        "bn254_lde_columns",
        "bn254_poseidon_hash_words",
    ] {
        assert!(
            descriptors
                .iter()
                .any(|descriptor| descriptor.entry_point == name),
            "missing descriptor for {name}"
        );
    }
    let bn254_poseidon = descriptors
        .iter()
        .find(|descriptor| descriptor.entry_point == "bn254_poseidon_hash_words")
        .expect("BN254 Poseidon descriptor");
    assert_eq!(
        bn254_poseidon.threadgroup_cap,
        Some(super::BN254_POSEIDON_THREADGROUP_CAPACITY)
    );
}

#[test]
fn uncertain_completion_blocks_all_new_staging_and_preserves_retained_cells() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_QUARANTINE.with(|state| state.set(None));
        }
    }
    TEST_QUARANTINE.with(|state| assert_eq!(state.replace(Some(false)), None));
    let _reset = Reset;
    let observed = crate::gpu_secret::ErasureObservation::begin();
    let staged = PooledBuffer::sensitive_from_slice(&[31, 37, 41]).unwrap();
    let retained = staged.backing();
    quarantine_backend();
    assert!(backend_quarantined());
    assert!(crate::gpu::transform_completion_uncertain_v1());
    assert!(matches!(
        crate::digest384_batch::preflight_last_fields_execution(crate::DigestExecutionV1::Cpu),
        Err(crate::Error::NativeDigestExecution { details }) if details.contains("completion uncertain")
    ));
    assert!(matches!(
        PooledBuffer::sensitive_zeroed(1),
        Err(GpuError::CompletionUncertain {
            backend: GpuBackend::Metal
        })
    ));
    assert!(matches!(
        CommandPermit::try_new(0),
        Err(GpuError::CompletionUncertain {
            backend: GpuBackend::Metal
        })
    ));
    drop(staged);
    assert_eq!(observed.counts(), (0, 0));
    assert_eq!(&retained.pages[0].words[..3], &[31, 37, 41]);
    drop(retained);
    assert!(observed.counts().0 >= METAL_BUFFER_PAGE_WORDS);
    assert_eq!(observed.counts().1, 0);
    assert!(backend_quarantined());
}

#[test]
fn abandoned_fft_ticket_drains_before_release_and_partial_error_restores_inputs() {
    if select_metal_device().is_none() {
        return;
    }
    let _lane = crate::backend::acquire_gpu_lane();
    let observed = crate::gpu_secret::ErasureObservation::begin();
    let root = goldilocks_pow(GOLDILOCKS_GENERATOR, (FIELD_MODULUS - 1) >> 3);
    let mut columns = sample_fft_columns(3, 2);
    let mut expected = columns.clone();
    for column in &mut expected {
        crate::cyclotomic::fft(
            column,
            crate::cyclotomic::Domain {
                log_size: 3,
                generator: root,
            },
        );
    }
    let weak = autoreleasepool(|| {
        let mut pending = dispatch_fft_columns(&mut columns, 3, root, false).unwrap();
        assert_eq!(pending.pending_batches.len(), 1);
        let batch = &mut pending.pending_batches[0];
        let weak = batch.buffer.weak_backing_for_tests();
        let ticket = batch.tickets.pop().unwrap();
        let command = ticket.command.clone();
        drop(ticket);
        assert_eq!(command.status(), MTLCommandBufferStatus::Completed);
        drop(command);
        pending.wait().unwrap();
        weak
    });
    assert!(weak.upgrade().is_none());
    assert_eq!(columns, expected);
    assert!(observed.counts().0 >= METAL_BUFFER_PAGE_WORDS + 16);
    assert_eq!(observed.counts().1, 0);
    let before = columns.clone();
    {
        let _failure = fail_column_batch_wait_after(0);
        assert!(
            dispatch_fft_columns(&mut columns, 3, root, false)
                .unwrap()
                .wait()
                .is_err()
        );
    }
    assert_eq!(columns, before);
    assert!(!backend_quarantined());
}

/// Explicit hardware qualification: absence or any fallback is a test failure.
/// Ordinary unit runs may ignore this control; the dedicated qualification lane
/// must execute this exact name with `--ignored --exact --test-threads=1`.
#[test]
#[ignore = "requires independently reviewed compiled Metal bytes and a real Metal device"]
fn required_admitted_metal_all_pipelines_and_bn254_word_parity_twice() {
    let admitted = crate::metal_artifact::admitted_bundle()
        .expect("hardware qualification requires an admitted original compiled bundle");
    assert!(!admitted.bytes().is_empty());
    let device = select_metal_device()
        .expect("hardware qualification requires an actual supported Metal device");
    let library = load_metal_library(&device)
        .expect("the actual device must load the same admitted compiled bytes");
    assert_eq!(crate::metal_artifact::ENTRY_POINTS.len(), 16);
    let pipelines = crate::metal_artifact::ENTRY_POINTS
        .iter()
        .map(|name| {
            load_pipeline(&device, &library, name)
                .unwrap_or_else(|error| panic!("actual pipeline {name} failed: {error}"))
        })
        .collect::<Vec<_>>();
    assert_eq!(pipelines.len(), 16);
    assert_eq!(
        crate::backend::current_gpu_backend(),
        Some(GpuBackend::Metal),
        "CPU/CUDA/absent fallback cannot qualify Metal"
    );

    let lengths = [0_usize, 1, 2, 3, 5, 8, 13];
    let input = [
        0,
        u64::MAX,
        1,
        u64::MAX - 1,
        3,
        5,
        8,
        13,
        21,
        34,
        55,
        89,
        144,
    ];
    let mut words = Vec::new();
    let mut slices = Vec::new();
    let mut expected = Vec::new();
    for len in lengths {
        let offset = words.len();
        words.extend_from_slice(&input[..len]);
        slices.push(Bn254PoseidonBatchSlice::new(offset, len));
        expected.push(iroha_zkp_halo2::poseidon::hash_u64_words_bytes(
            &input[..len],
        ));
    }
    assert_eq!(slices.len(), lengths.len());
    assert!(
        !slices.is_empty(),
        "length zero must be an actual dispatch member"
    );
    assert_eq!(slices[0].len(), 0);
    assert!(!words.is_empty());
    for repetition in 0..2 {
        let actual = crate::bn254_poseidon::try_hash_bn254_poseidon_word_batches(&words, &slices)
            .expect("required real Metal submission and completion cannot be skipped or fall back");
        assert_eq!(actual.len(), expected.len());
        for (index, (got, wanted)) in actual.iter().zip(&expected).enumerate() {
            assert_eq!(
                got, wanted,
                "full 32-byte word-mode parity: repetition {repetition}, length {}",
                lengths[index]
            );
        }
        assert_eq!(
            crate::backend::current_gpu_backend(),
            Some(GpuBackend::Metal)
        );
    }
    // Keep every pipeline owner alive through both actual batch completions.
    assert_eq!(pipelines.len(), crate::metal_artifact::ENTRY_POINTS.len());
}

#[test]
fn integer_dispatch_limits_preserve_full_width_and_saturate() {
    assert_eq!(clamp_u128_to_u64(0), 0);
    assert_eq!(clamp_u128_to_u64(u128::from(u64::MAX)), u64::MAX);
    assert_eq!(clamp_u128_to_u64(u128::from(u64::MAX) + 1), u64::MAX);
    assert_eq!(clamp_u128_to_u64(u128::MAX), u64::MAX);
    for fanout in [0, 1] {
        assert_eq!(default_queue_column_threshold(fanout), u32::MAX);
    }
    for fanout in [2_u32, 3, 4] {
        assert_eq!(
            default_queue_column_threshold(usize::try_from(fanout).unwrap()),
            DEFAULT_QUEUE_COLUMN_THRESHOLD.max(fanout * 8)
        );
    }
    assert_eq!(default_queue_column_threshold(usize::MAX), u32::MAX);
    assert_eq!(default_in_flight_limit_for_parallelism(usize::MAX), 16);
    assert_eq!(limit_from_gpu_cores(usize::MAX), 16);
}

#[test]
fn adaptive_backoff_preserves_ceiling_at_maximum_column_count() {
    let state = AdaptiveBatchState::new(1, 1.0);
    state.record_sample(u32::MAX, u32::MAX, 100.0);
    let data = state.data.lock().expect("adaptive scheduler poisoned");
    assert_eq!(data.current_columns, u32::MAX / 2 + 1);
    assert_eq!(data.samples, 1);
}
