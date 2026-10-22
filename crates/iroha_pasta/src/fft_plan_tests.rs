//! Exact arithmetic, ownership and rejection tests for prepared coset transforms.

use super::*;
use crate::field::{Fp, Fq};
use ff::WithSmallOrderMulGroup;
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

fn coefficients<F: PastaField>(n: usize, seed: u64) -> Vec<F> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    (0..n).map(|_| F::random(&mut rng)).collect()
}

#[test]
fn prepared_cosets_reuse_storage_and_match_independent_outputs() {
    fn check<F: PastaField + WithSmallOrderMulGroup<3>>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                for k in [0, 1, 2, 3, 4, 12, 13] {
                    let domain = FftDomain::<F>::new(k).unwrap();
                    let mut powers = vec![F::ZERO; domain.n()];
                    let address = powers.as_ptr();
                    let capacity = powers.capacity();
                    for shift in [F::ONE, F::from(7), <F as WithSmallOrderMulGroup<3>>::ZETA] {
                        {
                            let plan = domain.coset_plan(&mut powers, shift).unwrap();
                            // Internal assertions in the FFT module: the plan borrows
                            // the caller's exact buffer; it does not own another Vec.
                            assert_eq!(plan.powers.as_ptr(), address);
                            let expected_powers: Vec<F> = (0..domain.n())
                                .scan(F::ONE, |power, _| {
                                    let value = *power;
                                    *power *= shift;
                                    Some(value)
                                })
                                .collect();
                            assert_eq!(plan.powers, expected_powers);
                            // Reuse the same plan across differing batch widths and seeds.
                            for (round, count) in [0u64, 1, 3, 17, 1].into_iter().enumerate() {
                                let seed_base = u64::try_from(round).unwrap() * 100;
                                let original: Vec<Vec<F>> = (0..count)
                                    .map(|index| coefficients(domain.n(), seed_base + index))
                                    .collect();
                                let mut batch = original.clone();
                                let pointers: Vec<_> = batch.iter().map(Vec::as_ptr).collect();
                                let mut columns: Vec<_> =
                                    batch.iter_mut().map(Vec::as_mut_slice).collect();
                                plan.fft_many(&mut columns).unwrap();
                                for (index, (actual, source)) in
                                    batch.iter_mut().zip(&original).enumerate()
                                {
                                    let mut expected = source.clone();
                                    domain.coset_fft(&mut expected, shift).unwrap();
                                    assert_eq!(
                                        *actual, expected,
                                        "workers={workers} k={k} count={count}"
                                    );
                                    if k <= 4 {
                                        assert_eq!(
                                            *actual,
                                            naive_coset_dft(source, domain.omega(), shift)
                                        );
                                    }
                                    assert_eq!(actual.as_ptr(), pointers[index]);
                                    domain.coset_ifft(actual, shift).unwrap();
                                    assert_eq!(actual, source);
                                }
                                assert_eq!(plan.powers, expected_powers);
                            }
                        }
                        assert_eq!(powers.as_ptr(), address);
                        assert_eq!(powers.capacity(), capacity);
                    }
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn prepared_coset_construction_and_batches_validate_before_mutation() {
    fn check<F: PastaField>() {
        let domain = FftDomain::<F>::new(3).unwrap();
        for length in [0, 7, 9] {
            let mut powers = vec![F::from(19); length];
            let before = powers.clone();
            assert!(matches!(domain.coset_plan(&mut powers, F::ZERO),
                Err(FftError::WrongLength { expected: 8, actual }) if actual == length));
            assert_eq!(powers, before);
        }
        let mut powers = vec![F::from(19); domain.n()];
        let before = powers.clone();
        assert!(matches!(
            domain.coset_plan(&mut powers, F::ZERO),
            Err(FftError::ZeroShift)
        ));
        assert_eq!(powers, before);
        let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
        for bad_index in 0..3 {
            let mut batch = vec![vec![F::ONE; 8]; 3];
            // A different domain's length must fail even for a valid final column.
            batch[bad_index].resize(16, F::ONE);
            let before = batch.clone();
            let mut columns: Vec<_> = batch.iter_mut().map(Vec::as_mut_slice).collect();
            assert_eq!(
                plan.fft_many(&mut columns),
                Err(FftError::WrongLength {
                    expected: 8,
                    actual: 16
                })
            );
            assert_eq!(batch, before);
        }
        assert_eq!(plan.fft_many(&mut []), Ok(()));
    }
    check::<Fp>();
    check::<Fq>();
}

/// Test-only schedules: no production environment switch or field scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectSchedule {
    Columns,
    Cooperative,
    Adaptive,
}

impl DirectSchedule {
    const ALL: [Self; 3] = [Self::Columns, Self::Cooperative, Self::Adaptive];

    fn name(self) -> &'static str {
        match self {
            Self::Columns => "columns",
            Self::Cooperative => "cooperative",
            Self::Adaptive => "adaptive",
        }
    }
}

/// Explicit test-only schedules using the same direct-input FFT kernels.
///
/// `Columns` retains the historical production policy: parallel kernels for a
/// single column, serial kernels inside each parallel task for wider batches.
/// `Cooperative` always enables the parallel kernels; `Adaptive` does so when
/// width is less than the worker count, while keeping the single-column case.
/// None of these labels silently changes when production scheduling changes.
/// All schedules freeze the same input slices before writing, allocate no field
/// storage, and join every task before the final cancellation check.
fn direct_input_schedule<F: PastaField>(
    plan: &CosetFftPlan<'_, '_, F>,
    coefficients: &[impl AsRef<[F]> + Sync],
    columns: &mut [&mut [F]],
    cancellation: Option<&CancellationToken>,
    schedule: DirectSchedule,
) -> Result<(), FftError> {
    CancellationToken::checkpoint(cancellation)?;
    if coefficients.len() != columns.len() {
        return Err(FftError::WrongColumnCount {
            expected: columns.len(),
            actual: coefficients.len(),
        });
    }
    let sources: Vec<&[F]> = coefficients.iter().map(AsRef::as_ref).collect();
    for (source, output) in sources.iter().zip(columns.iter()) {
        plan.domain.check(source)?;
        plan.domain.check(output)?;
    }
    CancellationToken::checkpoint(cancellation)?;
    let column_policy = schedule == DirectSchedule::Columns
        || (schedule == DirectSchedule::Adaptive && columns.len() >= rayon::current_num_threads());
    if column_policy && columns.len() == 1 {
        // Keep the historical single-column dispatch without an outer task.
        dif_from::<_, true>(
            sources[0],
            columns[0],
            &plan.domain.forward,
            plan.powers,
            cancellation,
        );
        bit_reverse_scale::<_, true>(columns[0], plan.domain.k, None, cancellation);
    } else {
        columns
            .par_iter_mut()
            .zip(sources.par_iter())
            .for_each(|(column, source)| {
                if column_policy {
                    dif_from::<_, false>(
                        source,
                        column,
                        &plan.domain.forward,
                        plan.powers,
                        cancellation,
                    );
                    bit_reverse_scale::<_, false>(column, plan.domain.k, None, cancellation);
                } else {
                    dif_from::<_, true>(
                        source,
                        column,
                        &plan.domain.forward,
                        plan.powers,
                        cancellation,
                    );
                    bit_reverse_scale::<_, true>(column, plan.domain.k, None, cancellation);
                }
            });
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(())
}

/// One selected direct-input case, with paired schedules and nine raw rounds.
/// Only an explicit ignored invocation performs this experiment; there is no
/// default large matrix. All source generation, plan construction, allocation,
/// independent single-column reference transforms and checks are outside each
/// timed cut. Slice freezing and cancellation checks remain inside it.
#[test]
#[ignore = "explicit direct-input FFT experiment; select curve, size, width and workers"]
fn batch_parallelism_diagnostic() {
    use std::{hint::black_box, time::Instant};

    assert!(
        !cfg!(debug_assertions),
        "run this diagnostic with --release"
    );
    fn run<F: PastaField>(curve: &str) {
        let read = |name: &str| std::env::var(name).expect("explicit diagnostic selection");
        let k: u32 = read("FFT_BATCH_K").parse().unwrap();
        let count: usize = read("FFT_BATCH_COLUMNS").parse().unwrap();
        let workers: usize = read("FFT_BATCH_WORKERS").parse().unwrap();
        assert!((12..=16).contains(&k));
        assert!([1, 2, 3, 4, 8, 17].contains(&count));
        assert!([1, 4].contains(&workers));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
            assert_eq!(rayon::current_num_threads(), workers);
            let domain = FftDomain::<F>::new(k).unwrap();
            let mut powers = vec![F::ZERO; domain.n()];
            let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
            let original_powers = plan.powers.to_vec();
            let source: Vec<_> = (0..count)
                .map(|index| coefficients::<F>(domain.n(), 310 + u64::try_from(index).unwrap()))
                .collect();
            let original_source = source.clone();
            let mut expected = source.clone();
            for column in &mut expected {
                domain.coset_fft(column, F::from(7)).unwrap();
            }
            // Reuse one caller-owned destination across arms, with the same
            // initialization before every cut. No previous arm's output is read.
            let mut actual = vec![vec![F::from(19); domain.n()]; count];
            let storage: Vec<_> = actual.iter().map(|v| (v.as_ptr(), v.capacity())).collect();
            // One checked warmup of each arm precedes the nine measured rounds.
            for round in 0..10 {
                let mut observations = Vec::with_capacity(3);
                for position in 0..3 {
                    let schedule = DirectSchedule::ALL[(round + position) % 3];
                    for column in &mut actual {
                        column.fill(F::from(19));
                    }
                    let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
                    let token = CancellationToken::new();
                    let started = Instant::now();
                    let result = direct_input_schedule(
                        &plan,
                        black_box(&source),
                        black_box(&mut columns),
                        Some(&token),
                        schedule,
                    );
                    let elapsed = started.elapsed();
                    result.unwrap();
                    assert_eq!(actual, expected, "{curve}, {schedule:?}, round={round}");
                    assert_eq!(source, original_source);
                    assert_eq!(plan.powers, original_powers);
                    for (column, &(address, capacity)) in actual.iter().zip(&storage) {
                        assert_eq!(column.as_ptr(), address);
                        assert_eq!(column.capacity(), capacity);
                    }
                    observations.push((schedule, position, elapsed.as_nanos()));
                }
                // Do not announce cross-arm equality before all three pass.
                if round != 0 {
                    for (schedule, position, ns) in observations {
                        println!(
                            "FFT_BATCH path=direct_input curve={curve} k={k} columns={count} workers={workers} mode={} sample={} position={position} wall_ns={ns} three_arms_verified=true",
                            schedule.name(), round - 1,
                        );
                    }
                }
            }
        });
    }
    match std::env::var("FFT_BATCH_CURVE").unwrap().as_str() {
        "fp" => run::<Fp>("fp"),
        "fq" => run::<Fq>("fq"),
        _ => panic!("select fp or fq"),
    }
}

/// Small independent DFT checks cover every dispatch width without running the
/// expensive k12-k16 timing matrix as part of the default test suite.
#[test]
fn narrow_batch_direct_input_schedules_preserve_outputs_and_storage() {
    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                for k in [0, 1, 2, 3] {
                    let domain = FftDomain::<F>::new(k).unwrap();
                    let mut powers = vec![F::ZERO; domain.n()];
                    let address = powers.as_ptr();
                    let capacity = powers.capacity();
                    let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
                    let original_powers = plan.powers.to_vec();
                    for count in [0, 1, 2, 3, 4, 8, 17] {
                        let source: Vec<_> = (0..count)
                            .map(|i| coefficients::<F>(domain.n(), 1700 + i as u64))
                            .collect();
                        let original_source = source.clone();
                        let expected: Vec<_> = source
                            .iter()
                            .map(|s| naive_coset_dft(s, domain.omega(), F::from(7)))
                            .collect();
                        let mut actual = vec![vec![F::from(19); domain.n()]; count];
                        let storage: Vec<_> =
                            actual.iter().map(|v| (v.as_ptr(), v.capacity())).collect();
                        for schedule in DirectSchedule::ALL {
                            for column in &mut actual {
                                column.fill(F::from(19));
                            }
                            let mut columns: Vec<_> =
                                actual.iter_mut().map(Vec::as_mut_slice).collect();
                            direct_input_schedule(
                                &plan,
                                &source,
                                &mut columns,
                                Some(&CancellationToken::new()),
                                schedule,
                            )
                            .unwrap();
                            assert_eq!(
                                actual, expected,
                                "{schedule:?}, k={k}, count={count}, workers={workers}"
                            );
                            assert_eq!(source, original_source);
                            assert_eq!(plan.powers, original_powers);
                            assert_eq!(plan.powers.as_ptr(), address);
                            for (column, &(address, capacity)) in actual.iter().zip(&storage) {
                                assert_eq!(column.as_ptr(), address);
                                assert_eq!(column.capacity(), capacity);
                            }
                        }
                    }
                    assert_eq!(powers.as_ptr(), address);
                    assert_eq!(powers.capacity(), capacity);
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

/// A changing AsRef and cancellation during freezing test the exact preflight
/// ordering without timing-dependent sleeps or production observation hooks.
#[test]
fn narrow_batch_direct_input_schedules_preserve_preflight_and_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Watched<'a, F> {
        first: &'a [F],
        later: &'a [F],
        borrows: AtomicUsize,
        cancel: Option<&'a CancellationToken>,
    }
    impl<F> AsRef<[F]> for Watched<'_, F> {
        fn as_ref(&self) -> &[F] {
            if self.borrows.fetch_add(1, Ordering::SeqCst) == 0 {
                if let Some(token) = self.cancel {
                    token.cancel();
                }
                self.first
            } else {
                self.later
            }
        }
    }
    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                let domain = FftDomain::<F>::new(3).unwrap();
                let mut powers = vec![F::ZERO; domain.n()];
                let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
                let original_powers = plan.powers.to_vec();
                let source: Vec<_> = (0..3).map(|i| coefficients::<F>(8, 2100 + i)).collect();
                let original_source = source.clone();
                let expected: Vec<_> = source
                    .iter()
                    .map(|s| naive_coset_dft(s, domain.omega(), F::from(7)))
                    .collect();
                for schedule in DirectSchedule::ALL {
                    for case in 0..7 {
                        let token = CancellationToken::new();
                        if case == 1 {
                            token.cancel();
                        }
                        let watched: Vec<_> = source
                            .iter()
                            .enumerate()
                            .map(|(i, values)| Watched {
                                first: if i == 0 && [3, 6].contains(&case) {
                                    &values[..7]
                                } else {
                                    values
                                },
                                later: &[],
                                borrows: AtomicUsize::new(0),
                                cancel: if i == 1 && [5, 6].contains(&case) {
                                    Some(&token)
                                } else {
                                    None
                                },
                            })
                            .collect();
                        let mut actual =
                            vec![vec![F::from(19); 8]; if [1, 2].contains(&case) { 2 } else { 3 }];
                        if [3, 4].contains(&case) {
                            actual[0].push(F::ONE);
                        }
                        let before = actual.clone();
                        let mut columns: Vec<_> =
                            actual.iter_mut().map(Vec::as_mut_slice).collect();
                        let result = direct_input_schedule(
                            &plan,
                            &watched,
                            &mut columns,
                            Some(&token),
                            schedule,
                        );
                        let expected_result = match case {
                            0 => Ok(()),
                            1 | 5 => Err(FftError::Cancelled),
                            2 => Err(FftError::WrongColumnCount {
                                expected: 2,
                                actual: 3,
                            }),
                            3 | 6 => Err(FftError::WrongLength {
                                expected: 8,
                                actual: 7,
                            }),
                            4 => Err(FftError::WrongLength {
                                expected: 8,
                                actual: 9,
                            }),
                            _ => unreachable!(),
                        };
                        assert_eq!(
                            result, expected_result,
                            "{schedule:?}, case={case}, workers={workers}"
                        );
                        assert_eq!(&actual, if case == 0 { &expected } else { &before });
                        let expected_borrows = usize::from(![1, 2].contains(&case));
                        assert!(
                            watched
                                .iter()
                                .all(|s| s.borrows.load(Ordering::SeqCst) == expected_borrows)
                        );
                        assert_eq!(source, original_source);
                        assert_eq!(plan.powers, original_powers);
                        // Retry the same plan with fresh caller output and signal.
                        let mut retry = vec![vec![F::from(19); 8]; source.len()];
                        let mut columns: Vec<_> = retry.iter_mut().map(Vec::as_mut_slice).collect();
                        direct_input_schedule(
                            &plan,
                            &source,
                            &mut columns,
                            Some(&CancellationToken::new()),
                            schedule,
                        )
                        .unwrap();
                        assert_eq!(retry, expected);
                    }
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn prepared_cosets_from_coefficients_match_in_place_and_naive() {
    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                for k in [0, 1, 2, 3, 4, 12, 13] {
                    let domain = FftDomain::<F>::new(k).unwrap();
                    let mut powers = vec![F::ZERO; domain.n()];
                    for shift in [F::ONE, F::from(7), <F as WithSmallOrderMulGroup<3>>::ZETA] {
                        let plan = domain.coset_plan(&mut powers, shift).unwrap();
                        let original_powers = plan.powers.to_vec();
                        for count in [0u64, 1, 3, 17] {
                            let source: Vec<Vec<F>> = (0..count)
                                .map(|i| coefficients(domain.n(), i + 700))
                                .collect();
                            let original_source = source.clone();
                            let mut expected = source.clone();
                            let mut expected_columns: Vec<_> =
                                expected.iter_mut().map(Vec::as_mut_slice).collect();
                            plan.fft_many(&mut expected_columns).unwrap();
                            let mut actual = vec![vec![F::from(19); domain.n()]; source.len()];
                            let addresses: Vec<_> = actual.iter().map(Vec::as_ptr).collect();
                            let mut columns: Vec<_> =
                                actual.iter_mut().map(Vec::as_mut_slice).collect();
                            plan.fft_many_from_cancellable(&source, &mut columns, None)
                                .unwrap();
                            assert_eq!(actual, expected, "workers={workers} k={k} count={count}");
                            assert_eq!(source, original_source);
                            assert_eq!(plan.powers, original_powers);
                            for (i, (output, input)) in actual.iter_mut().zip(&source).enumerate() {
                                assert_eq!(output.as_ptr(), addresses[i]);
                                if k <= 4 {
                                    assert_eq!(
                                        *output,
                                        naive_coset_dft(input, domain.omega(), shift)
                                    );
                                }
                                domain.coset_ifft(output, shift).unwrap();
                                assert_eq!(output, input);
                            }
                        }
                    }
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn prepared_cosets_from_coefficients_validate_entire_batch_before_writes() {
    fn check<F: PastaField>() {
        let domain = FftDomain::<F>::new(3).unwrap();
        let mut powers = vec![F::ZERO; domain.n()];
        let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
        let source = vec![
            coefficients::<F>(8, 1),
            coefficients(8, 2),
            coefficients(8, 3),
        ];
        let original_powers = plan.powers.to_vec();
        for count in [0, 2, 4] {
            let mut output = vec![vec![F::from(19); 8]; count];
            let before = output.clone();
            let mut columns: Vec<_> = output.iter_mut().map(Vec::as_mut_slice).collect();
            assert_eq!(
                plan.fft_many_from_cancellable(&source, &mut columns, None),
                Err(FftError::WrongColumnCount {
                    expected: count,
                    actual: 3
                })
            );
            assert_eq!(output, before);
        }
        assert_eq!(
            FftError::WrongColumnCount {
                expected: 2,
                actual: 3
            }
            .to_string(),
            "FFT has 3 source columns, expected 2"
        );
        for index in 0..source.len() {
            for length in [0, 7, 9] {
                for change_source in [false, true] {
                    let mut inputs = source.clone();
                    let mut output = vec![vec![F::from(19); 8]; source.len()];
                    if change_source {
                        inputs[index].resize(length, F::ONE);
                    } else {
                        output[index].resize(length, F::ONE);
                    }
                    let before = output.clone();
                    let original_inputs = inputs.clone();
                    let mut columns: Vec<_> = output.iter_mut().map(Vec::as_mut_slice).collect();
                    assert_eq!(
                        plan.fft_many_from_cancellable(&inputs, &mut columns, None),
                        Err(FftError::WrongLength {
                            expected: 8,
                            actual: length
                        })
                    );
                    assert_eq!(output, before);
                    assert_eq!(inputs, original_inputs);
                    assert_eq!(plan.powers, original_powers);
                }
            }
        }
        let empty: Vec<Vec<F>> = Vec::new();
        assert_eq!(
            plan.fft_many_from_cancellable(&empty, &mut [], None),
            Ok(())
        );
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn prepared_cosets_from_coefficients_cancel_during_input_borrow_and_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Request cancellation while freezing the second input view. This must
    // return before writing any output, without a timer or production hook.
    struct CancelOnBorrow<'a, F> {
        values: &'a [F],
        borrows: &'a AtomicUsize,
        token: &'a CancellationToken,
    }
    impl<F> AsRef<[F]> for CancelOnBorrow<'_, F> {
        fn as_ref(&self) -> &[F] {
            if self.borrows.fetch_add(1, Ordering::SeqCst) == 1 {
                self.token.cancel();
            }
            self.values
        }
    }
    fn check<F: PastaField>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        pool.install(|| {
            let domain = FftDomain::<F>::new(12).unwrap();
            let source: Vec<Vec<F>> = (0..3).map(|i| coefficients(domain.n(), i + 900)).collect();
            let original_source = source.clone();
            let mut powers = vec![F::ZERO; domain.n()];
            let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
            let original_powers = plan.powers.to_vec();
            let mut output = vec![vec![F::from(19); domain.n()]; source.len()];
            let before = output.clone();
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            {
                let mut columns: Vec<_> = output.iter_mut().map(Vec::as_mut_slice).collect();
                assert_eq!(
                    plan.fft_many_from_cancellable(&source, &mut columns, Some(&cancelled)),
                    Err(FftError::Cancelled)
                );
            }
            assert_eq!(output, before);
            let token = CancellationToken::new();
            let borrows = AtomicUsize::new(0);
            let watched: Vec<_> = source
                .iter()
                .map(|values| CancelOnBorrow {
                    values,
                    borrows: &borrows,
                    token: &token,
                })
                .collect();
            {
                let mut columns: Vec<_> = output.iter_mut().map(Vec::as_mut_slice).collect();
                assert_eq!(
                    plan.fft_many_from_cancellable(&watched, &mut columns, Some(&token)),
                    Err(FftError::Cancelled)
                );
            }
            assert!(token.is_cancelled());
            assert_eq!(borrows.load(Ordering::SeqCst), source.len());
            assert_eq!(output, before);
            assert_eq!(source, original_source);
            assert_eq!(plan.powers, original_powers);
            let mut expected = source.clone();
            let mut expected_columns: Vec<_> = expected.iter_mut().map(Vec::as_mut_slice).collect();
            plan.fft_many(&mut expected_columns).unwrap();
            let mut columns: Vec<_> = output.iter_mut().map(Vec::as_mut_slice).collect();
            plan.fft_many_from_cancellable(&source, &mut columns, Some(&CancellationToken::new()))
                .unwrap();
            assert_eq!(output, expected);
            assert_eq!(source, original_source);
            assert_eq!(plan.powers, original_powers);
        });
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn prepared_cosets_from_coefficients_freeze_stateful_source_views() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A legal AsRef implementation can return a different slice on each call.
    // The transform must validate and consume the exact first borrowed view.
    struct ChangingSlice<'a, F> {
        first: &'a [F],
        later: &'a [F],
        borrows: AtomicUsize,
    }
    impl<F> AsRef<[F]> for ChangingSlice<'_, F> {
        fn as_ref(&self) -> &[F] {
            if self.borrows.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first
            } else {
                self.later
            }
        }
    }
    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                let domain = FftDomain::<F>::new(3).unwrap();
                let mut powers = vec![F::ZERO; domain.n()];
                let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
                let original_powers = plan.powers.to_vec();
                for count in [1u64, 3] {
                    let source: Vec<Vec<F>> = (0..count)
                        .map(|i| coefficients(domain.n(), i + 1200))
                        .collect();
                    let original_source = source.clone();
                    let mut expected = source.clone();
                    let mut expected_columns: Vec<_> =
                        expected.iter_mut().map(Vec::as_mut_slice).collect();
                    plan.fft_many(&mut expected_columns).unwrap();
                    for length in [0, 7, 9] {
                        let changed = vec![F::ONE; length];
                        for invalid_first in [false, true] {
                            for changed_index in 0..source.len() {
                                let watched: Vec<_> = source
                                    .iter()
                                    .enumerate()
                                    .map(|(i, values)| {
                                        let first: &[F] = if invalid_first && i == changed_index {
                                            &changed
                                        } else {
                                            values
                                        };
                                        let later: &[F] = if !invalid_first && i == changed_index {
                                            &changed
                                        } else {
                                            values
                                        };
                                        ChangingSlice {
                                            first,
                                            later,
                                            borrows: AtomicUsize::new(0),
                                        }
                                    })
                                    .collect();
                                let mut output = vec![vec![F::from(19); domain.n()]; source.len()];
                                let before = output.clone();
                                let result = {
                                    let mut columns: Vec<_> =
                                        output.iter_mut().map(Vec::as_mut_slice).collect();
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        plan.fft_many_from_cancellable(&watched, &mut columns, None)
                                    }))
                                };
                                assert!(result.is_ok(), "stateful source panicked");
                                if invalid_first {
                                    assert_eq!(
                                        result.unwrap(),
                                        Err(FftError::WrongLength {
                                            expected: 8,
                                            actual: length
                                        })
                                    );
                                    assert_eq!(output, before, "validation partially wrote output");
                                } else {
                                    assert_eq!(result.unwrap(), Ok(()));
                                    assert_eq!(output, expected);
                                }
                                assert!(
                                    watched
                                        .iter()
                                        .all(|input| input.borrows.load(Ordering::SeqCst) == 1)
                                );
                                assert_eq!(source, original_source);
                                assert_eq!(plan.powers, original_powers);
                            }
                        }
                    }
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

/// Exercise the exact production scheduling shape against an in-place reference
/// and retain first-borrow semantics and caller-owned storage on both fields.
#[test]
fn prepared_width_two_k16_matches_reference_and_reuses_storage() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FirstView<'a, F> {
        values: &'a [F],
        borrows: AtomicUsize,
    }
    impl<F> AsRef<[F]> for FirstView<'_, F> {
        fn as_ref(&self) -> &[F] {
            if self.borrows.fetch_add(1, Ordering::SeqCst) == 0 {
                self.values
            } else {
                &[]
            }
        }
    }
    fn check<F: PastaField>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        pool.install(|| {
            assert_eq!(rayon::current_num_threads(), 4);
            let domain = FftDomain::<F>::new(16).unwrap();
            let mut powers = vec![F::ZERO; domain.n()];
            let power_storage = (powers.as_ptr(), powers.capacity());
            let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
            let original_powers = plan.powers.to_vec();
            let source: Vec<Vec<F>> = (0..2).map(|i| coefficients(domain.n(), i + 2400)).collect();
            let original_source = source.clone();
            let mut expected = source.clone();
            let mut expected_columns: Vec<_> = expected.iter_mut().map(Vec::as_mut_slice).collect();
            // Independent in-place first pass, retaining serial per-column kernels.
            plan.fft_many(&mut expected_columns).unwrap();
            let watched: Vec<_> = source
                .iter()
                .map(|values| FirstView {
                    values,
                    borrows: AtomicUsize::new(0),
                })
                .collect();
            let mut actual = vec![vec![F::from(19); domain.n()]; 2];
            let storage: Vec<_> = actual.iter().map(|v| (v.as_ptr(), v.capacity())).collect();
            let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
            plan.fft_many_from_cancellable(&watched, &mut columns, Some(&CancellationToken::new()))
                .unwrap();
            assert_eq!(actual, expected);
            assert!(
                watched
                    .iter()
                    .all(|s| s.borrows.load(Ordering::SeqCst) == 1)
            );
            // The diagnostic's historical columns control remains a separate
            // serial-kernel schedule after the production policy changes.
            for schedule in DirectSchedule::ALL {
                for column in &mut actual {
                    column.fill(F::from(19));
                }
                let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
                direct_input_schedule(&plan, &source, &mut columns, None, schedule).unwrap();
                assert_eq!(actual, expected, "{schedule:?}");
            }
            assert_eq!(source, original_source);
            assert_eq!(plan.powers, original_powers);
            for (column, &(address, capacity)) in actual.iter().zip(&storage) {
                assert_eq!(column.as_ptr(), address);
                assert_eq!(column.capacity(), capacity);
            }
            assert_eq!(powers.as_ptr(), power_storage.0);
            assert_eq!(powers.capacity(), power_storage.1);
        });
    }
    check::<Fp>();
    check::<Fq>();
}

/// Cancel deterministically during the second frozen borrow, then retry the
/// exact k16/two-column/four-worker production path without timing assumptions.
#[test]
fn prepared_width_two_k16_cancels_during_borrow_and_retries() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CancelOnSecondBorrow<'a, F> {
        values: &'a [F],
        borrows: &'a AtomicUsize,
        token: &'a CancellationToken,
    }
    impl<F> AsRef<[F]> for CancelOnSecondBorrow<'_, F> {
        fn as_ref(&self) -> &[F] {
            if self.borrows.fetch_add(1, Ordering::SeqCst) == 1 {
                self.token.cancel();
            }
            self.values
        }
    }
    fn check<F: PastaField>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        pool.install(|| {
            assert_eq!(rayon::current_num_threads(), 4);
            let domain = FftDomain::<F>::new(16).unwrap();
            let source: Vec<Vec<F>> = (0..2).map(|i| coefficients(domain.n(), i + 2500)).collect();
            let original_source = source.clone();
            let mut powers = vec![F::ZERO; domain.n()];
            let power_storage = (powers.as_ptr(), powers.capacity());
            let plan = domain.coset_plan(&mut powers, F::from(7)).unwrap();
            let original_powers = plan.powers.to_vec();
            let mut actual = vec![vec![F::from(19); domain.n()]; 2];
            let before = actual.clone();
            let storage: Vec<_> = actual.iter().map(|v| (v.as_ptr(), v.capacity())).collect();
            let token = CancellationToken::new();
            let borrows = AtomicUsize::new(0);
            let watched: Vec<_> = source
                .iter()
                .map(|values| CancelOnSecondBorrow {
                    values,
                    borrows: &borrows,
                    token: &token,
                })
                .collect();
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            {
                let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
                assert_eq!(
                    plan.fft_many_from_cancellable(&watched, &mut columns, Some(&cancelled)),
                    Err(FftError::Cancelled)
                );
            }
            assert_eq!(borrows.load(Ordering::SeqCst), 0);
            assert_eq!(actual, before);
            {
                let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
                assert_eq!(
                    plan.fft_many_from_cancellable(&watched, &mut columns, Some(&token)),
                    Err(FftError::Cancelled)
                );
            }
            assert!(token.is_cancelled());
            assert_eq!(borrows.load(Ordering::SeqCst), 2);
            assert_eq!(actual, before);
            let mut expected = source.clone();
            let mut expected_columns: Vec<_> = expected.iter_mut().map(Vec::as_mut_slice).collect();
            plan.fft_many(&mut expected_columns).unwrap();
            let mut columns: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
            plan.fft_many_from_cancellable(&source, &mut columns, Some(&CancellationToken::new()))
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(source, original_source);
            assert_eq!(plan.powers, original_powers);
            for (column, &(address, capacity)) in actual.iter().zip(&storage) {
                assert_eq!(column.as_ptr(), address);
                assert_eq!(column.capacity(), capacity);
            }
            assert_eq!(powers.as_ptr(), power_storage.0);
            assert_eq!(powers.capacity(), power_storage.1);
        });
    }
    check::<Fp>();
    check::<Fq>();
}

/// Serial-dispatch oracle for scheduling tests. It deliberately shares the
/// unchanged arithmetic kernels, but never enters their parallel branches.
/// Existing small-domain naive-DFT tests remain the independent arithmetic oracle.
fn serial_dispatch_transform<F: PastaField>(
    domain: &FftDomain<F>,
    values: &mut [F],
    shift: Option<F>,
    inverse: bool,
) {
    if inverse {
        let shift_inv = shift.map_or(F::ONE, |value| value.invert().unwrap());
        dif::<_, false>(values, &domain.inverse, None, None);
        bit_reverse_scale::<_, false>(values, domain.k, Some((domain.n_inv, shift_inv)), None);
    } else {
        dif::<_, false>(
            values,
            &domain.forward,
            shift.map(CosetShift::Geometric),
            None,
        );
        bit_reverse_scale::<_, false>(values, domain.k, None, None);
    }
}

/// Exercise singleton production entry points whose later radix-4 passes may
/// otherwise serialize unsplittable inner chunks. k13/workers2,4 and k16/workers4
/// are unchanged-dispatch controls; all comparisons are exact, never timed.
#[test]
fn singleton_block_dispatch_matches_serial_and_reuses_storage() {
    fn check<F: PastaField>() {
        for (k, workers) in [
            (12, 2),
            (12, 4),
            (12, 8),
            (13, 2),
            (13, 4),
            (13, 8),
            (14, 8),
            (16, 4),
        ] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                assert_eq!(rayon::current_num_threads(), workers);
                let domain = FftDomain::<F>::new(k).unwrap();
                let shift = F::from(7);
                let source = coefficients(domain.n(), 2600 + u64::from(k));
                let source_before = source.clone();
                let source_storage = (source.as_ptr(), source.capacity());
                let mut subgroup = source.clone();
                serial_dispatch_transform(&domain, &mut subgroup, None, false);
                let mut coset = source.clone();
                serial_dispatch_transform(&domain, &mut coset, Some(shift), false);
                let mut inverse = subgroup.clone();
                serial_dispatch_transform(&domain, &mut inverse, None, true);
                assert_eq!(inverse, source);
                inverse.copy_from_slice(&coset);
                serial_dispatch_transform(&domain, &mut inverse, Some(shift), true);
                assert_eq!(inverse, source);

                let mut powers = vec![F::ZERO; domain.n()];
                let power_storage = (powers.as_ptr(), powers.capacity());
                let plan = domain.coset_plan(&mut powers, shift).unwrap();
                let powers_before = plan.powers.to_vec();
                assert_eq!(plan.powers.as_ptr(), power_storage.0);
                let mut actual = source.clone();
                let output_storage = (actual.as_ptr(), actual.capacity());
                let check_output = |actual: &Vec<F>, expected: &[F]| {
                    assert_eq!(actual.as_slice(), expected, "k={k} workers={workers}");
                    assert_eq!(actual.as_ptr(), output_storage.0);
                    assert_eq!(actual.capacity(), output_storage.1);
                };
                let fresh = CancellationToken::new();
                domain.fft_cancellable(&mut actual, Some(&fresh)).unwrap();
                check_output(&actual, &subgroup);
                domain.ifft_cancellable(&mut actual, Some(&fresh)).unwrap();
                check_output(&actual, &source);
                domain
                    .coset_fft_cancellable(&mut actual, shift, Some(&fresh))
                    .unwrap();
                check_output(&actual, &coset);
                domain
                    .coset_ifft_cancellable(&mut actual, shift, Some(&fresh))
                    .unwrap();
                check_output(&actual, &source);
                plan.fft_many_cancellable(&mut [actual.as_mut_slice()], Some(&fresh))
                    .unwrap();
                check_output(&actual, &coset);
                domain
                    .coset_ifft_cancellable(&mut actual, shift, Some(&fresh))
                    .unwrap();
                check_output(&actual, &source);
                actual.fill(F::from(19));
                plan.fft_many_from_cancellable(
                    &[source.as_slice()],
                    &mut [actual.as_mut_slice()],
                    Some(&fresh),
                )
                .unwrap();
                check_output(&actual, &coset);
                domain
                    .coset_ifft_cancellable(&mut actual, shift, Some(&fresh))
                    .unwrap();
                check_output(&actual, &source);
                assert!(!fresh.is_cancelled());
                assert_eq!(source, source_before);
                assert_eq!((source.as_ptr(), source.capacity()), source_storage);
                assert_eq!(plan.powers, powers_before.as_slice());
                assert_eq!((powers.as_ptr(), powers.capacity()), power_storage);
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

/// A pre-cancelled operation must not write. A distinct fresh signal then
/// executes the production path successfully in the same caller-owned storage.
fn assert_precancelled_transform_retry<F: PastaField>(
    context: (u32, usize, &str),
    initial: &[F],
    expected: &[F],
    mut operation: impl FnMut(&mut [F], &CancellationToken) -> Result<(), FftError>,
) {
    let mut actual = initial.to_vec();
    let storage = (actual.as_ptr(), actual.capacity());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        operation(&mut actual, &cancelled),
        Err(FftError::Cancelled),
        "{context:?}"
    );
    assert_eq!(actual.as_slice(), initial, "{context:?}");
    assert_eq!((actual.as_ptr(), actual.capacity()), storage);
    let fresh = CancellationToken::new();
    assert_eq!(operation(&mut actual, &fresh), Ok(()), "{context:?}");
    assert_eq!(actual.as_slice(), expected, "{context:?}");
    assert_eq!((actual.as_ptr(), actual.capacity()), storage);
    assert!(cancelled.is_cancelled());
    assert!(!fresh.is_cancelled());
}

/// Cover every changed shape in the bounded matrix. This checks cancellation at
/// entry and fresh retry, not deterministic cancellation during an active pass.
#[test]
fn singleton_block_dispatch_precancel_preserves_storage_and_retries() {
    fn check<F: PastaField>() {
        for (k, workers) in [(12, 2), (12, 4), (12, 8), (13, 8), (14, 8)] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                assert_eq!(rayon::current_num_threads(), workers);
                let domain = FftDomain::<F>::new(k).unwrap();
                let shift = F::from(7);
                let source = coefficients(domain.n(), 2700 + u64::from(k));
                let source_before = source.clone();
                let source_storage = (source.as_ptr(), source.capacity());
                let mut subgroup = source.clone();
                serial_dispatch_transform(&domain, &mut subgroup, None, false);
                let mut coset = source.clone();
                serial_dispatch_transform(&domain, &mut coset, Some(shift), false);
                let mut powers = vec![F::ZERO; domain.n()];
                let power_storage = (powers.as_ptr(), powers.capacity());
                let plan = domain.coset_plan(&mut powers, shift).unwrap();
                let powers_before = plan.powers.to_vec();
                assert_eq!(plan.powers.as_ptr(), power_storage.0);
                assert_precancelled_transform_retry(
                    (k, workers, "fft"),
                    &source,
                    &subgroup,
                    |actual, token| domain.fft_cancellable(actual, Some(token)),
                );
                assert_precancelled_transform_retry(
                    (k, workers, "ifft"),
                    &subgroup,
                    &source,
                    |actual, token| domain.ifft_cancellable(actual, Some(token)),
                );
                assert_precancelled_transform_retry(
                    (k, workers, "geometric"),
                    &source,
                    &coset,
                    |actual, token| domain.coset_fft_cancellable(actual, shift, Some(token)),
                );
                assert_precancelled_transform_retry(
                    (k, workers, "coset_ifft"),
                    &coset,
                    &source,
                    |actual, token| domain.coset_ifft_cancellable(actual, shift, Some(token)),
                );
                assert_precancelled_transform_retry(
                    (k, workers, "prepared"),
                    &source,
                    &coset,
                    |actual, token| plan.fft_many_cancellable(&mut [actual], Some(token)),
                );
                let sentinel = vec![F::from(19); domain.n()];
                assert_precancelled_transform_retry(
                    (k, workers, "direct"),
                    &sentinel,
                    &coset,
                    |actual, token| {
                        plan.fft_many_from_cancellable(
                            &[source.as_slice()],
                            &mut [actual],
                            Some(token),
                        )
                    },
                );
                assert_eq!(source, source_before);
                assert_eq!((source.as_ptr(), source.capacity()), source_storage);
                assert_eq!(plan.powers, powers_before.as_slice());
                assert_eq!((powers.as_ptr(), powers.capacity()), power_storage);
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}
