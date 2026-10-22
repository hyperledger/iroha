//! Algebra/component models for the beta hoist; full-proof goldens cover production.
//!
//! The two const-generic arms below copy the old/new numerator loop. They do not
//! call `commit`: these checks and timings cannot replace its execution coverage.
use super::ROWS_PER_TASK;
use iroha_pasta::{CancellationToken, Cancelled, Fp, Fq, PastaField, fft::FftDomain};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
fn chunk_model<F: PastaField, const HOIST: bool>(
    output: &mut [F],
    start: usize,
    columns: &[Vec<F>],
    set_delta: F,
    omega: F,
    beta: F,
    gamma: F,
    cancellation: Option<&CancellationToken>,
) -> Result<(), Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    let start_power = omega.pow_vartime([start as u64]);
    let mut column_delta = set_delta;
    for column in columns {
        let mut delta_omega = column_delta * start_power;
        for (offset, value) in output.iter_mut().enumerate() {
            let term = if HOIST {
                delta_omega
            } else {
                delta_omega * beta
            };
            *value *= crate::norm_factor(column[start + offset] + term + gamma);
            delta_omega *= omega;
        }
        column_delta *= F::DELTA;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn numerator_model<F: PastaField, const HOIST: bool>(
    output: &mut [F],
    columns: &[Vec<F>],
    delta_power: F,
    omega: F,
    beta: F,
    gamma: F,
    cancellation: Option<&CancellationToken>,
) -> Result<(), Cancelled> {
    let set_delta = if HOIST {
        delta_power * beta
    } else {
        delta_power
    };
    output
        .par_chunks_mut(ROWS_PER_TASK)
        .enumerate()
        .for_each(|(task, out)| {
            // As in production, cancelled tasks return and all tasks join before
            // the final checkpoint reports cancellation to the caller.
            let _ = chunk_model::<F, HOIST>(
                out,
                task * ROWS_PER_TASK,
                columns,
                set_delta,
                omega,
                beta,
                gamma,
                cancellation,
            );
        });
    CancellationToken::checkpoint(cancellation)
}

fn inputs<F: PastaField>(n: usize, m: usize) -> Vec<Vec<F>> {
    (0..m)
        .map(|column| {
            (0..n)
                .map(|row| F::from(((row * 13 + column * 31 + 3) % 4093) as u64))
                .collect()
        })
        .collect()
}
fn initial<F: PastaField>(n: usize) -> Vec<F> {
    (0..n).map(|row| F::from((row % 19 + 1) as u64)).collect()
}

#[test]
fn beta_hoist_component_models_match_original_and_direct_exponents() {
    fn check<F: PastaField>() {
        let mut rng = ChaCha20Rng::from_seed([67; 32]);
        let challenges = [
            (F::ZERO, F::ZERO),
            (F::ONE, F::random(&mut rng)),
            (-F::ONE, F::ZERO),
            (F::random(&mut rng), F::random(&mut rng)),
        ];
        for (k, m, degree) in [(0, 1, 4), (10, 3, 8), (11, 7, 8), (16, 22, 8)] {
            let domain = FftDomain::<F>::new(k).unwrap();
            let columns = inputs::<F>(domain.n(), m);
            let seed = initial::<F>(domain.n());
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                pool.install(|| {
                    for (beta, gamma) in challenges {
                        let mut delta_power = F::ONE;
                        let mut global_column = 0;
                        for set in columns.chunks((degree - 2) / 2) {
                            let mut reference = seed.clone();
                            let mut candidate = seed.clone();
                            let pointer = candidate.as_ptr();
                            let capacity = candidate.capacity();
                            numerator_model::<F, false>(
                                &mut reference,
                                set,
                                delta_power,
                                domain.omega(),
                                beta,
                                gamma,
                                None,
                            )
                            .unwrap();
                            numerator_model::<F, true>(
                                &mut candidate,
                                set,
                                delta_power,
                                domain.omega(),
                                beta,
                                gamma,
                                None,
                            )
                            .unwrap();
                            assert_eq!(
                                candidate, reference,
                                "k={k} workers={workers} set={global_column}"
                            );
                            assert_eq!(candidate.as_ptr(), pointer);
                            assert_eq!(candidate.capacity(), capacity);
                            // Independent exponent formula, including both sides of task
                            // boundaries and every set's global column offset.
                            for row in [0, 1, 1023, 1024, 1025, domain.n() - 1] {
                                if row >= domain.n() {
                                    continue;
                                }
                                let mut direct = seed[row];
                                for (local, column) in set.iter().enumerate() {
                                    let term = beta
                                        * F::DELTA.pow_vartime([(global_column + local) as u64])
                                        * domain.omega().pow_vartime([row as u64]);
                                    let v = column[row] + term + gamma;
                                    direct *= v.square() - F::from(5);
                                }
                                assert_eq!(candidate[row], direct);
                            }
                            for _ in set {
                                delta_power *= F::DELTA;
                                global_column += 1;
                            }
                            assert_eq!(delta_power, F::DELTA.pow_vartime([global_column as u64]));
                        }
                    }
                });
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn beta_hoist_component_models_cancel_at_chunk_boundaries_and_retry() {
    fn check<F: PastaField, const HOIST: bool>() {
        let domain = FftDomain::<F>::new(12).unwrap();
        let columns = inputs::<F>(domain.n(), 3);
        let seed = initial::<F>(domain.n());
        let delta_power = F::DELTA.pow_vartime([6]);
        for beta in [F::ZERO, F::from(37)] {
            let gamma = F::ZERO;
            let token = CancellationToken::new();
            token.cancel();
            let mut output = seed.clone();
            assert_eq!(
                numerator_model::<F, HOIST>(
                    &mut output,
                    &columns,
                    delta_power,
                    domain.omega(),
                    beta,
                    gamma,
                    Some(&token)
                ),
                Err(Cancelled)
            );
            assert_eq!(output, seed);
            let token = CancellationToken::new();
            let set_delta = if HOIST {
                delta_power * beta
            } else {
                delta_power
            };
            chunk_model::<F, HOIST>(
                &mut output[..ROWS_PER_TASK],
                0,
                &columns,
                set_delta,
                domain.omega(),
                beta,
                gamma,
                Some(&token),
            )
            .unwrap();
            let first = output[..ROWS_PER_TASK].to_vec();
            token.cancel();
            assert_eq!(
                chunk_model::<F, HOIST>(
                    &mut output[ROWS_PER_TASK..2 * ROWS_PER_TASK],
                    ROWS_PER_TASK,
                    &columns,
                    set_delta,
                    domain.omega(),
                    beta,
                    gamma,
                    Some(&token)
                ),
                Err(Cancelled)
            );
            assert_eq!(&output[..ROWS_PER_TASK], &first);
            assert_eq!(&output[ROWS_PER_TASK..], &seed[ROWS_PER_TASK..]);
            // Multiplicative output is operation scratch: retry starts from its
            // original denominator/seed, never from partially updated contents.
            output.copy_from_slice(&seed);
            let fresh = CancellationToken::new();
            numerator_model::<F, HOIST>(
                &mut output,
                &columns,
                delta_power,
                domain.omega(),
                beta,
                gamma,
                Some(&fresh),
            )
            .unwrap();
            let mut expected = seed.clone();
            numerator_model::<F, false>(
                &mut expected,
                &columns,
                delta_power,
                domain.omega(),
                beta,
                gamma,
                None,
            )
            .unwrap();
            assert_eq!(output, expected);
        }
    }
    check::<Fp, false>();
    check::<Fp, true>();
    check::<Fq, false>();
    check::<Fq, true>();
}

#[test]
#[ignore = "copied numerator component only; not production commit, full-proof or phone timing"]
fn beta_hoist_copied_numerator_shape_timing_diagnostic() {
    use std::{hint::black_box, time::Instant};
    assert!(!cfg!(debug_assertions), "run in release");
    fn check<F: PastaField>() {
        for (label, k, m, degree) in [("sigma_shape", 12, 7, 8), ("two_sigma_q_shape", 16, 22, 8)] {
            let domain = FftDomain::<F>::new(k).unwrap();
            let columns = inputs::<F>(domain.n(), m);
            let seed = initial::<F>(domain.n());
            let beta = F::from(37);
            let gamma = F::from(43);
            let run = |hoist: bool| {
                let mut outputs = Vec::new();
                let mut delta_power = F::ONE;
                for set in columns.chunks((degree - 2) / 2) {
                    let mut output = seed.clone();
                    if hoist {
                        numerator_model::<F, true>(
                            &mut output,
                            set,
                            delta_power,
                            domain.omega(),
                            beta,
                            gamma,
                            None,
                        )
                        .unwrap();
                    } else {
                        numerator_model::<F, false>(
                            &mut output,
                            set,
                            delta_power,
                            domain.omega(),
                            beta,
                            gamma,
                            None,
                        )
                        .unwrap();
                    }
                    for _ in set {
                        delta_power *= F::DELTA;
                    }
                    outputs.push(output);
                }
                outputs
            };
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                pool.install(|| {
                    let expected = run(false);
                    assert_eq!(run(true), expected); // One untimed warmup per arm.
                    for (block, order) in [[false,true,true,false],[true,false,false,true]].into_iter().enumerate() {
                        for (position, hoist) in order.into_iter().enumerate() {
                            let start = Instant::now();
                            let output = black_box(run(black_box(hoist)));
                            let elapsed_ns = start.elapsed().as_nanos();
                            assert_eq!(output, expected); // Equality outside timed cut.
                            let drop_start = Instant::now(); drop(output);
                            let drop_ns = drop_start.elapsed().as_nanos();
                            eprintln!("PERMUTATION_BETA_COMPONENT {{\"field\":\"{}\",\"label\":\"{label}\",\"k\":{k},\"columns\":{m},\"degree\":{degree},\"workers\":{workers},\"block\":{block},\"position\":{position},\"arm\":\"{}\",\"elapsed_ns\":{elapsed_ns},\"drop_ns\":{drop_ns}}}",
                                std::any::type_name::<F>(), if hoist {"hoisted"} else {"original"});
                        }
                    }
                });
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}
