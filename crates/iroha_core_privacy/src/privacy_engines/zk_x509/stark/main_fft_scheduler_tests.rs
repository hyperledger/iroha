//! Exact-work checks for the bounded CPU FFT batch scheduling policy.
//!
//! Both scheduling choices share production validation and arithmetic. The
//! diagnostic preserves bit reversal, public windows and starting powers while
//! comparing inner Rayon tasks with outer-column scheduling. Full fastpq CPU
//! transforms and small integer DFTs provide independent arithmetic references.

use super::*;
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_MODULUS_V1, TransparentStarkErrorV1, goldilocks_fft_coarse_v1 as coarse_fft,
    goldilocks_fft_v1, goldilocks_ifft_coarse_v1 as coarse_ifft, goldilocks_ifft_v1,
};
use crate::privacy_engines::zk_x509::private_table::{
    PrivateTableV1, inspection, zeroize_field_rows_v1,
};

use fastpq_prover::goldilocks_transform::transform_goldilocks_columns_v1;

type Matrix = PrivateTableV1<Vec<F>>;

#[derive(Clone, Copy, Debug)]
enum Phase {
    NativeInverse,
    QuotientForward,
    FixedTransition,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::NativeInverse => "native_inverse",
            Self::QuotientForward => "quotient_forward",
            Self::FixedTransition => "fixed_transition",
        }
    }
}

fn apply_batch(
    columns: &mut [Vec<F>],
    root: F,
    diagonal: F,
    phase: Phase,
    coarse: bool,
) -> Result<(), TransparentStarkErrorV1> {
    columns.par_iter_mut().try_for_each(|column| {
        if matches!(phase, Phase::NativeInverse | Phase::FixedTransition) {
            if coarse {
                coarse_ifft(column, root)?;
            } else {
                goldilocks_ifft_v1(column, root)?;
            }
        }
        if matches!(phase, Phase::FixedTransition) {
            let mut power = F::ONE;
            for value in column.iter_mut() {
                *value = value.mul(power);
                power = power.mul(diagonal);
            }
        }
        if matches!(phase, Phase::QuotientForward | Phase::FixedTransition) {
            if coarse {
                coarse_fft(column, root)?;
            } else {
                goldilocks_fft_v1(column, root)?;
            }
        }
        Ok(())
    })
}

fn matrix(rows: usize, width: usize) -> Matrix {
    PrivateTableV1::new(
        (0..width)
            .map(|column| {
                (0..rows)
                    .map(|row| F::reduce((row as u128 + 3).pow(2) + 17 * column as u128))
                    .collect()
            })
            .collect(),
        zeroize_field_rows_v1,
    )
}

fn oracle(source: &[Vec<F>], root: F, diagonal: F, phase: Phase) -> Words {
    let mut words = Words::new(
        source
            .iter()
            .map(|c| c.iter().map(|x| x.0).collect())
            .collect(),
        erase_words_v1,
    );
    if matches!(phase, Phase::NativeInverse | Phase::FixedTransition) {
        assert_eq!(
            transform_goldilocks_columns_v1(
                &mut words,
                root.0,
                Direction::Inverse,
                fastpq_prover::ExecutionMode::Cpu
            )
            .unwrap(),
            Backend::Cpu
        );
    }
    if matches!(phase, Phase::FixedTransition) {
        for column in words.iter_mut() {
            let mut power = F::ONE;
            for value in column {
                *value = F(*value).mul(power).0;
                power = power.mul(diagonal);
            }
        }
    }
    if matches!(phase, Phase::QuotientForward | Phase::FixedTransition) {
        assert_eq!(
            transform_goldilocks_columns_v1(
                &mut words,
                root.0,
                Direction::Forward,
                fastpq_prover::ExecutionMode::Cpu
            )
            .unwrap(),
            Backend::Cpu
        );
    }
    words
}

#[test]
fn coarse_batch_fft_matches_independent_integer_dft_and_inverse() {
    let modulus = u128::from(GOLDILOCKS_MODULUS_V1);
    for log in 1..=7 {
        let root = goldilocks_primitive_root_v1(log).unwrap();
        let rows = 1usize << log;
        let mut actual = matrix(rows, 1);
        let original = actual[0].clone();
        coarse_fft(&mut actual[0], root).unwrap();
        for (index, value) in actual[0].iter().enumerate() {
            let point = u128::from(root.pow(index as u128).0);
            let expected = original.iter().rev().fold(0u128, |sum, coefficient| {
                (sum * point + u128::from(coefficient.0)) % modulus
            });
            assert_eq!(u128::from(value.0), expected);
        }
        coarse_ifft(&mut actual[0], root).unwrap();
        assert_eq!(actual[0], original);
    }
}

#[test]
fn coarse_batch_fft_matches_full_cpu_oracle_across_parallel_boundaries() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    for log in [11, 14, 15] {
        let root = goldilocks_primitive_root_v1(log).unwrap();
        for width in [1, 8] {
            for phase in [
                Phase::NativeInverse,
                Phase::QuotientForward,
                Phase::FixedTransition,
            ] {
                let source = matrix(1usize << log, width);
                let expected = oracle(&source, root, F(7), phase);
                for coarse in [false, true] {
                    let mut actual = PrivateTableV1::new(source.to_vec(), zeroize_field_rows_v1);
                    let identities: Vec<_> = actual
                        .iter()
                        .map(|c| (c.as_ptr(), c.len(), c.capacity()))
                        .collect();
                    pool.install(|| apply_batch(&mut actual, root, F(7), phase, coarse))
                        .unwrap();
                    assert_eq!(
                        identities,
                        actual
                            .iter()
                            .map(|c| (c.as_ptr(), c.len(), c.capacity()))
                            .collect::<Vec<_>>()
                    );
                    for (actual, expected) in actual.iter().zip(expected.iter()) {
                        assert!(actual.iter().zip(expected).all(|(a, b)| a.0 == *b));
                    }
                }
            }
        }
    }
}

#[test]
fn coarse_batch_fft_production_private_batches_preserve_all_workers_and_allocations() {
    for workers in [1, 4, 20] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        for log in [5, 14, 15] {
            let root = goldilocks_primitive_root_v1(log).unwrap();
            for width in [1, 8] {
                for direction in [Direction::Forward, Direction::Inverse] {
                    let source = matrix(1usize << log, width);
                    let phase = if direction == Direction::Inverse {
                        Phase::NativeInverse
                    } else {
                        Phase::QuotientForward
                    };
                    let expected = oracle(&source, root, F::ONE, phase);
                    let mut actual = PrivateTableV1::new(source.to_vec(), zeroize_field_rows_v1);
                    let identities: Vec<_> = actual
                        .iter()
                        .map(|column| (column.as_ptr(), column.len(), column.capacity()))
                        .collect();
                    pool.install(|| {
                        let policy = MainBoundedTransformPolicyV1::cpu_v1();
                        let no_device = |_: &mut [Vec<u64>], _: u64, _: Direction| {
                            panic!("CPU policy must not call the device adapter")
                        };
                        if direction == Direction::Inverse {
                            policy.inverse_with_v1(&mut actual, root, no_device, || false)
                        } else {
                            policy.forward_with_v1(&mut actual, root, no_device, || false)
                        }
                    })
                    .unwrap();
                    assert_eq!(
                        identities,
                        actual
                            .iter()
                            .map(|column| (column.as_ptr(), column.len(), column.capacity()))
                            .collect::<Vec<_>>()
                    );
                    for (column, reference) in actual.iter().zip(expected.iter()) {
                        assert!(
                            column
                                .iter()
                                .zip(reference)
                                .all(|(value, word)| value.0 == *word)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn coarse_batch_fft_preserves_validation_and_clearing_on_all_exits() {
    for rows in [0, 1, 3, 16] {
        for root in [
            F::ZERO,
            F::ONE,
            F(GOLDILOCKS_MODULUS_V1),
            goldilocks_primitive_root_v1(4).unwrap(),
        ] {
            for inverse in [false, true] {
                let mut current = vec![F(7); rows];
                let mut coarse = current.clone();
                let expected = if inverse {
                    goldilocks_ifft_v1(&mut current, root)
                } else {
                    goldilocks_fft_v1(&mut current, root)
                };
                let actual = if inverse {
                    coarse_ifft(&mut coarse, root)
                } else {
                    coarse_fft(&mut coarse, root)
                };
                assert_eq!(expected, actual);
                assert_eq!(current, coarse);
            }
        }
    }
    for malformed in [false, true] {
        for unwind in [false, true] {
            let mut returned_error = None;
            let (outcome, erased) = inspection::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut columns = matrix(32, 2);
                    if malformed {
                        columns[1][31] = F(GOLDILOCKS_MODULUS_V1);
                    }
                    let result = apply_batch(
                        &mut columns,
                        goldilocks_primitive_root_v1(5).unwrap(),
                        F(7),
                        Phase::FixedTransition,
                        true,
                    );
                    // Record the actual return before the deliberate unwind;
                    // assertions belong outside catch_unwind so they cannot be swallowed.
                    returned_error = Some(result.is_err());
                    if unwind {
                        panic!("diagnostic batch FFT cleanup");
                    }
                }))
            });
            assert_eq!(returned_error, Some(malformed));
            assert_eq!(outcome.is_err(), unwind);
            assert_eq!(erased.iter().map(|x| x.cells).sum::<usize>(), 64);
            assert!(erased.iter().any(|x| x.nonzero_before > 0));
            assert!(erased.iter().all(|x| x.nonzero_after == 0));
        }
    }
}

#[test]
#[ignore = "full registered CPU batch FFT schedule parity and same-work costs; run optimized"]
fn registered_batch_fft_scheduler_cost_preserves_native_quotient_and_fixed_work() {
    assert_eq!(rayon::current_num_threads(), 20);
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let native_logs = layout
        .trace_groups
        .iter()
        .map(|g| g.native_trace_log2)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(native_logs, [5, 8, 15, 16, 18, 19].into_iter().collect());
    let mut stripe_logs = std::collections::BTreeSet::new();
    let mut transition_logs = std::collections::BTreeSet::new();
    for registration in &layout.registered_segments {
        let plan = registered_retained_prover_plan_v1(registration.segment, layout.common_lde_log2)
            .unwrap();
        let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
            registration.segment.trace_log2,
            plan.quotient_coset_log2,
            0,
        )
        .unwrap();
        stripe_logs.insert(stripe.rows.ilog2() as u8);
        if stripe.count > 1 {
            transition_logs.insert((stripe.rows.ilog2() as u8, plan.quotient_coset_log2));
        }
    }
    let mut cases = Vec::new();
    for log in native_logs {
        cases.push((Phase::NativeInverse, log, log));
    }
    for log in stripe_logs {
        cases.push((Phase::QuotientForward, log, log));
    }
    for (log, full) in transition_logs {
        cases.push((Phase::FixedTransition, log, full));
    }
    println!(
        "batch_fft_header cases={} widths=1,8 rounds=3 modes=current,coarse workers=20 expected_records={} production_selected=false allocation_copy_oracle_clear_timed=false",
        cases.len(),
        cases.len() * 12
    );
    let mut records = 0;
    for (case, (phase, log, full)) in cases.into_iter().enumerate() {
        let rows = 1usize << log;
        let root = goldilocks_primitive_root_v1(log).unwrap();
        // Consecutive fixed-coset stripe shifts differ by this public full root.
        let diagonal = goldilocks_primitive_root_v1(full).unwrap();
        for width in [1, 8] {
            let source = matrix(rows, width);
            let expected = oracle(&source, root, diagonal, phase);
            let mut current = PrivateTableV1::new(source.to_vec(), zeroize_field_rows_v1);
            let mut candidate = PrivateTableV1::new(source.to_vec(), zeroize_field_rows_v1);
            let named_payload_bytes = 4 * width * rows * core::mem::size_of::<F>();
            for round in 0..3 {
                for coarse in if round % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let target = if coarse { &mut candidate } else { &mut current };
                    for (target, source) in target.iter_mut().zip(source.iter()) {
                        target.copy_from_slice(source);
                    }
                    let started = std::time::Instant::now();
                    apply_batch(target, root, diagonal, phase, coarse).unwrap();
                    let elapsed_ns = started.elapsed().as_nanos();
                    for (actual, expected) in target.iter().zip(expected.iter()) {
                        assert!(actual.iter().zip(expected).all(|(a, b)| a.0 == *b));
                    }
                    println!(
                        "batch_fft_cost case={case} phase={} log={log} full_log={full} width={width} round={round} coarse={coarse} elapsed_ns={elapsed_ns} named_payload_bytes={named_payload_bytes}",
                        phase.name()
                    );
                    records += 1;
                }
            }
        }
    }
    assert!(records > 0 && records % 12 == 0);
}
