//! Bounded scheduling diagnostics over the unchanged MSM arithmetic kernels.
//!
//! A and its unchanged control use production waves; B changes only window
//! grouping; C uses the same finer groups with a bounded number of claiming loops.
//! All arms retain the original reservation. No production switch or phone claim.

use super::*;
use crate::msm::{MsmError, ScratchReservation, SharedMemoryBudget};
use crate::{Ep, Eq};
use group::prime::PrimeCurveAffine;
use rand_chacha::ChaCha20Rng;
use rand_core_06::{RngCore, SeedableRng};
use rayon::prelude::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug)]
enum Arm {
    Current,
    FineWaves,
    Dynamic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hook {
    None,
    CancelAfterTask,
    PanicAfterTask,
    PanicWhileMerging,
}

fn task_count(plan: &Plan) -> usize {
    assert!(
        plan.concurrency > 0,
        "zero concurrency is an invalid internal plan"
    );
    assert!(plan.per_group > 0 && plan.chunks > 0 && plan.nw > 0);
    assert_eq!(plan.groups, plan.nw.div_ceil(plan.per_group));
    let count = plan.groups.checked_mul(plan.chunks).unwrap();
    assert!(plan.concurrency <= count);
    count
}

fn fine_plan(n: usize, original: Plan) -> Plan {
    task_count(&original);
    let mut fine = original;
    fine.per_group = original.per_group.min(2);
    fine.groups = original.nw.div_ceil(fine.per_group);
    task_count(&fine);
    let nb = 1usize << (original.c - 1);
    assert!(task_bytes(fine.per_group, nb).unwrap() <= task_bytes(original.per_group, nb).unwrap());
    assert!(payload_bound(n, fine) <= original.bytes);
    // No newly freed scratch is made available to another MSM in this experiment.
    assert_eq!(fine.bytes, original.bytes);
    fine
}

fn payload_bound(n: usize, plan: Plan) -> usize {
    fixed_bytes(n, plan.nw).unwrap()
        + plan.concurrency * task_bytes(plan.per_group, 1usize << (plan.c - 1)).unwrap()
}

/// Source-bound host experiment, not a portable std-layout promise. The
/// accompanying manifest pins Rust1.93.1's pthread OnceBox and Darwin SDK layout.
/// On this target the sole boxed pthread_mutex_t is8-byte long +56 opaque bytes.
/// Independent execution must reject a different compiler/std/SDK identity.
fn verified_mutex_payload_bytes() -> usize {
    assert!(
        cfg!(all(
            target_os = "macos",
            target_arch = "aarch64",
            target_pointer_width = "64"
        )),
        "this isolated mutex-accounting experiment requires the recorded host target"
    );
    assert_eq!(
        size_of::<Mutex<()>>(),
        16,
        "unexpected std Mutex wrapper layout"
    );
    8 + 56
}

fn dynamic_payload_bound(n: usize, plan: Plan) -> usize {
    // C has no wave result Vec: remove its per-callback tuple slots, then
    // charge the one initialized mutex Box. No new windows or heap task list.
    let result_slot = size_of::<(usize, Vec<crate::Ep>)>();
    fixed_bytes(n, plan.nw).unwrap()
        + plan.concurrency
            * (task_bytes(plan.per_group, 1usize << (plan.c - 1)).unwrap() - result_slot)
        + verified_mutex_payload_bytes()
}

/// Test-only public task accounting, absent from all measured calls.
struct Audit {
    claimed: Vec<AtomicUsize>,
    completed: Vec<AtomicUsize>,
    active: AtomicUsize,
    peak: AtomicUsize,
}
impl Audit {
    fn new(tasks: usize) -> Self {
        Self {
            claimed: (0..tasks).map(|_| AtomicUsize::new(0)).collect(),
            completed: (0..tasks).map(|_| AtomicUsize::new(0)).collect(),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
    fn claim(&self, task: usize) -> Active<'_> {
        assert_eq!(self.claimed[task].fetch_add(1, Ordering::Relaxed), 0);
        let live = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(live, Ordering::Relaxed);
        Active(self)
    }
    fn joined(&self, concurrency: usize, all_completed: bool) {
        assert_eq!(self.active.load(Ordering::Relaxed), 0);
        assert!(self.peak.load(Ordering::Relaxed) <= concurrency);
        assert!(self.claimed.iter().all(|v| v.load(Ordering::Relaxed) <= 1));
        assert!(
            self.completed
                .iter()
                .all(|v| v.load(Ordering::Relaxed) <= 1)
        );
        if all_completed {
            assert!(self.claimed.iter().all(|v| v.load(Ordering::Relaxed) == 1));
            assert!(
                self.completed
                    .iter()
                    .all(|v| v.load(Ordering::Relaxed) == 1)
            );
        }
    }
}
struct Active<'a>(&'a Audit);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One admitted operation. Its permit outlives all joined tasks and buffers.
/// Each callback holds at most one existing bucket/result envelope. Only the
/// short merge holds a mutex; it performs no admission, allocation or Rayon work.
fn dynamic_msm<C: PastaCurve, const SECRET: bool>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    plan: Plan,
    reservation: ScratchReservation<'_>,
    cancellation: Option<&CancellationToken>,
    audit: Option<&Audit>,
    hook: Hook,
) -> Result<C, MsmError> {
    let tasks = task_count(&plan);
    assert_eq!(scalars.len(), bases.len());
    assert_eq!(reservation.bytes(), plan.bytes);
    assert!(
        dynamic_payload_bound(scalars.len(), plan) <= reservation.bytes(),
        "this shape has insufficient original scratch for the accounted mutex"
    );
    CancellationToken::checkpoint(cancellation)?;
    let skip: Vec<bool> = bases
        .iter()
        .map(|base| bool::from(base.is_identity()))
        .collect();
    let digits = Digits::new_cancellable(scalars, plan.c, plan.nw, cancellation)?;
    let windows = Mutex::new(Zeroizing::new(vec![C::identity(); plan.nw]));
    // Initialize while this admitted/timed operation has no worker callbacks.
    // This prevents racing OnceBox initializers from allocating losing boxes.
    drop(windows.lock().expect("new reduction mutex"));
    let next = AtomicUsize::new(0);
    (0..plan.concurrency).into_par_iter().for_each(|_| {
        loop {
            if CancellationToken::checkpoint(cancellation).is_err() {
                break;
            }
            let claimed = next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value < tasks { Some(value + 1) } else { None }
            });
            let Ok(task) = claimed else {
                break;
            };
            let active = audit.map(|value| value.claim(task));
            let (w0, sums) = run_task_cancellable::<C, SECRET>(
                bases,
                &skip,
                &digits,
                &plan,
                task / plan.chunks,
                task % plan.chunks,
                cancellation,
            );
            // The unchanged kernel has dropped/wiped its buckets before returning.
            if task == 0 {
                match hook {
                    Hook::CancelAfterTask => {
                        cancellation.expect("test cancellation signal").cancel()
                    }
                    Hook::PanicAfterTask => panic!("test unwind with returned sums still owned"),
                    Hook::None | Hook::PanicWhileMerging => {}
                }
            }
            if CancellationToken::checkpoint(cancellation).is_err() {
                break;
            }
            let expected = plan.per_group.min(plan.nw - w0);
            assert_eq!(sums.len(), expected, "no silently skipped uncancelled task");
            {
                let mut guard = windows
                    .lock()
                    .expect("poisoned reduction is a failed operation");
                if task == 0 && hook == Hook::PanicWhileMerging {
                    panic!("test unwind with merge guard and returned sums owned");
                }
                for (index, sum) in sums.iter().enumerate() {
                    guard[w0 + index] += sum;
                }
            }
            if let Some(value) = audit {
                assert_eq!(value.completed[task].fetch_add(1, Ordering::Relaxed), 0);
            }
            // Zeroizing covers every mode and unwind, including cancellation.
            drop(sums);
            drop(active);
        }
    });
    CancellationToken::checkpoint(cancellation)?;
    let mut windows = windows
        .into_inner()
        .expect("poisoned reduction is a failed operation");
    let result = combine(&windows, plan.c);
    if SECRET {
        windows.zeroize();
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(result)
}

fn execute<C: PastaCurve, const SECRET: bool>(
    arm: Arm,
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    original: Plan,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
    audit: Option<&Audit>,
    hook: Hook,
) -> Result<C, MsmError> {
    task_count(&original);
    let selected = match arm {
        Arm::Current => original,
        _ => fine_plan(scalars.len(), original),
    };
    let reservation = shared
        .try_reserve(original.bytes)
        .expect("explicit test reservation fits");
    match arm {
        Arm::Current | Arm::FineWaves => {
            assert!(audit.is_none() && hook == Hook::None);
            super::super::planned_msm::<C, SECRET>(
                scalars,
                bases,
                selected,
                reservation,
                cancellation,
            )
        }
        Arm::Dynamic => dynamic_msm::<C, SECRET>(
            scalars,
            bases,
            selected,
            reservation,
            cancellation,
            audit,
            hook,
        ),
    }
}

/// Known public generator multiples give an independent exact group oracle.
/// Only synthetic scalars are secret-mode inputs, and their owner wipes on drop.
fn inputs<C: PastaCurve>(
    n: usize,
    bounded: bool,
    edge_cases: bool,
) -> (Zeroizing<Vec<C::ScalarExt>>, Vec<C::AffineExt>, C) {
    let mut rng = ChaCha20Rng::seed_from_u64(0x7363_6865_6475_6c65);
    let mut scalars = Zeroizing::new(Vec::with_capacity(n));
    let mut points = Vec::with_capacity(n);
    let mut point = C::identity();
    let mut total = Zeroizing::new(C::ScalarExt::ZERO);
    for i in 0..n {
        point += C::generator();
        let scalar = if bounded {
            C::ScalarExt::from(u64::from(rng.next_u32() & 255))
        } else if edge_cases {
            match i % 7 {
                0 => C::ScalarExt::ZERO,
                1 => C::ScalarExt::ONE,
                2 => -C::ScalarExt::ONE,
                _ => C::ScalarExt::random(&mut rng),
            }
        } else {
            C::ScalarExt::random(&mut rng)
        };
        let (base, weight) = if edge_cases {
            match i % 5 {
                0 => (C::identity(), C::ScalarExt::ZERO),
                1 | 3 => (C::generator(), C::ScalarExt::ONE),
                2 => (-C::generator(), -C::ScalarExt::ONE),
                _ => (point, C::ScalarExt::from((i + 1) as u64)),
            }
        } else {
            (point, C::ScalarExt::from((i + 1) as u64))
        };
        *total += scalar * weight;
        scalars.push(scalar);
        points.push(base);
    }
    let mut bases = vec![C::AffineExt::identity(); n];
    C::batch_normalize(&points, &mut bases);
    (scalars, bases, C::generator() * *total)
}

fn assert_group<C: PastaCurve>(actual: C, expected: C) {
    // Point chunks may finish in a different order. Internal projective
    // coordinates need not match; the canonical affine group element must.
    assert_eq!(actual.to_affine(), expected.to_affine());
}

fn check_modes<C: PastaCurve, const SECRET: bool>(
    n: usize,
    workers: usize,
    bits: usize,
    bounded: bool,
) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    let (scalars, bases, expected) = inputs::<C>(n, bounded, true);
    let scalar_before = Zeroizing::new(scalars.to_vec());
    let bases_before = bases.clone();
    let original = plan(n, bits, workers, 64 << 20).unwrap();
    if bounded {
        crate::msm::BoundedSecretScalars::new(&scalars, bits, None).unwrap();
        assert!(original.chunks > 1);
    }
    pool.install(|| {
        for concurrency in [1, original.concurrency]
            .into_iter()
            .take(if original.concurrency == 1 { 1 } else { 2 })
        {
            let mut original = original;
            original.concurrency = concurrency;
            for arm in [Arm::Current, Arm::FineWaves, Arm::Dynamic] {
                let shared = SharedMemoryBudget::new(original.bytes);
                let audit = Audit::new(task_count(&fine_plan(n, original)));
                let result = execute::<C, SECRET>(
                    arm,
                    &scalars,
                    &bases,
                    original,
                    &shared,
                    None,
                    matches!(arm, Arm::Dynamic).then_some(&audit),
                    Hook::None,
                )
                .unwrap();
                assert_group(result, expected);
                assert_eq!(shared.in_use_bytes(), 0);
                assert_eq!(shared.peak_bytes(), original.bytes);
                if matches!(arm, Arm::Dynamic) {
                    audit.joined(concurrency, true);
                }
                assert_eq!(scalars.as_slice(), scalar_before.as_slice());
                assert_eq!(bases, bases_before);
            }
        }
    });
}

#[test]
fn bounded_schedules_match_exact_groups_and_task_accounting() {
    for workers in [1, 4] {
        check_modes::<Ep, true>(65, workers, 255, false);
        check_modes::<Eq, true>(65, workers, 255, false);
        check_modes::<Ep, false>(65, workers, 255, false);
        check_modes::<Eq, false>(65, workers, 255, false);
    }
}

#[test]
fn bounded_schedules_handle_point_chunks_and_zero_scalars() {
    check_modes::<Ep, true>(8192, 4, 8, true);
    check_modes::<Eq, true>(8192, 4, 8, true);
    fn zero<C: PastaCurve>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let (_, bases, _) = inputs::<C>(65, false, true);
        let scalars = Zeroizing::new(vec![C::ScalarExt::ZERO; bases.len()]);
        let original = plan(scalars.len(), 255, 4, 64 << 20).unwrap();
        pool.install(|| {
            for arm in [Arm::Current, Arm::FineWaves, Arm::Dynamic] {
                let shared = SharedMemoryBudget::new(original.bytes);
                assert_group(
                    execute::<C, true>(
                        arm,
                        &scalars,
                        &bases,
                        original,
                        &shared,
                        None,
                        None,
                        Hook::None,
                    )
                    .unwrap(),
                    C::identity(),
                );
                assert_eq!(shared.in_use_bytes(), 0);
            }
        });
    }
    zero::<Ep>();
    zero::<Eq>();
}

#[test]
fn bounded_scheduling_plan_payload_stays_within_original_reservation() {
    let mut rejected_dynamic_shapes = 0;
    for n in [17, 65, 4096, 65536] {
        for bits in [8, 255] {
            for workers in [1, 4, 8] {
                for budget in [1 << 20, 64 << 20] {
                    if let Some(original) = plan(n, bits, workers, budget) {
                        let fine = fine_plan(n, original);
                        assert!(payload_bound(n, fine) <= original.bytes);
                        assert_eq!(fine.bytes, original.bytes);
                        if dynamic_payload_bound(n, fine) > original.bytes {
                            // Fine waves still fit; this exact reservation does
                            // not admit C's mutex. No operation is launched.
                            rejected_dynamic_shapes += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(
        rejected_dynamic_shapes > 0,
        "tight shapes must not get an uncharged mutex"
    );
    assert_eq!(size_of::<Ep>(), 96);
    assert_eq!(size_of::<Eq>(), 96);
    assert_eq!(size_of::<(usize, Vec<Ep>)>(), size_of::<(usize, Vec<Eq>)>());
}

#[test]
fn bounded_schedules_cancel_unwind_and_retry() {
    fn check<C: PastaCurve>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let (scalars, bases, expected) = inputs::<C>(65, false, true);
        let original = plan(scalars.len(), 255, 4, 64 << 20).unwrap();
        let fine = fine_plan(scalars.len(), original);
        let shared = SharedMemoryBudget::new(original.bytes);
        pool.install(|| {
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            for arm in [Arm::Current, Arm::FineWaves, Arm::Dynamic] {
                assert_eq!(
                    execute::<C, true>(
                        arm,
                        &scalars,
                        &bases,
                        original,
                        &shared,
                        Some(&cancelled),
                        None,
                        Hook::None
                    ),
                    Err(MsmError::Cancelled)
                );
                assert_eq!(shared.in_use_bytes(), 0);
            }
            let token = CancellationToken::new();
            let audit = Audit::new(task_count(&fine));
            assert_eq!(
                execute::<C, true>(
                    Arm::Dynamic,
                    &scalars,
                    &bases,
                    original,
                    &shared,
                    Some(&token),
                    Some(&audit),
                    Hook::CancelAfterTask
                ),
                Err(MsmError::Cancelled)
            );
            assert!(token.is_cancelled());
            audit.joined(fine.concurrency, false);
            assert_eq!(shared.in_use_bytes(), 0);
            assert_eq!(audit.claimed[0].load(Ordering::Relaxed), 1);
            assert_eq!(audit.completed[0].load(Ordering::Relaxed), 0);
            assert_group(
                execute::<C, true>(
                    Arm::Dynamic,
                    &scalars,
                    &bases,
                    original,
                    &shared,
                    Some(&CancellationToken::new()),
                    None,
                    Hook::None,
                )
                .unwrap(),
                expected,
            );
            assert_eq!(shared.in_use_bytes(), 0);
            for hook in [Hook::PanicAfterTask, Hook::PanicWhileMerging] {
                let audit = Audit::new(task_count(&fine));
                let result = catch_unwind(AssertUnwindSafe(|| {
                    execute::<C, true>(
                        Arm::Dynamic,
                        &scalars,
                        &bases,
                        original,
                        &shared,
                        None,
                        Some(&audit),
                        hook,
                    )
                }));
                assert!(result.is_err());
                audit.joined(fine.concurrency, false);
                assert_eq!(shared.in_use_bytes(), 0);
                let fresh = CancellationToken::new();
                assert_group(
                    execute::<C, true>(
                        Arm::Dynamic,
                        &scalars,
                        &bases,
                        original,
                        &shared,
                        Some(&fresh),
                        None,
                        Hook::None,
                    )
                    .unwrap(),
                    expected,
                );
            }
            // Invalid internal plans must fail, not silently run zero callbacks.
            let mut invalid = fine;
            invalid.concurrency = 0;
            let permit = shared.try_reserve(original.bytes).unwrap();
            assert!(
                catch_unwind(AssertUnwindSafe(|| dynamic_msm::<C, true>(
                    &scalars,
                    &bases,
                    invalid,
                    permit,
                    None,
                    None,
                    Hook::None
                )))
                .is_err()
            );
            assert_eq!(shared.in_use_bytes(), 0);
            assert_group(
                execute::<C, true>(
                    Arm::Dynamic,
                    &scalars,
                    &bases,
                    original,
                    &shared,
                    Some(&CancellationToken::new()),
                    None,
                    Hook::None,
                )
                .unwrap(),
                expected,
            );
        });
        assert_eq!(shared.in_use_bytes(), 0);
        assert_eq!(shared.peak_bytes(), original.bytes);
        assert!(
            SharedMemoryBudget::new(0)
                .try_reserve(original.bytes)
                .is_none()
        );
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn bounded_dynamic_nested_workers_join_without_new_admission() {
    fn check<C: PastaCurve>() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let (scalars, bases, expected) = inputs::<C>(65, false, true);
        let original = plan(scalars.len(), 255, 4, 64 << 20).unwrap();
        let fine = fine_plan(scalars.len(), original);
        let shared = SharedMemoryBudget::new(2 * original.bytes);
        let left = shared.try_reserve(original.bytes).unwrap();
        let right = shared.try_reserve(original.bytes).unwrap();
        assert!(shared.try_reserve(1).is_none());
        let results = pool.install(|| {
            rayon::join(
                || dynamic_msm::<C, true>(&scalars, &bases, fine, left, None, None, Hook::None),
                || dynamic_msm::<C, true>(&scalars, &bases, fine, right, None, None, Hook::None),
            )
        });
        assert_group(results.0.unwrap(), expected);
        assert_group(results.1.unwrap(), expected);
        assert_eq!(shared.in_use_bytes(), 0);
        assert_eq!(shared.peak_bytes(), 2 * original.bytes);
    }
    check::<Ep>();
    check::<Eq>();
}

/// Synthetic exact MSM component. All scheduling, allocation, recoding,
/// reduction and owner destruction are timed; inputs/oracle and checks are not.
#[test]
#[ignore = "bounded explicit scheduler comparison; synthetic MSM component only"]
fn bounded_window_scheduling_component_diagnostic() {
    fn measure<C: PastaCurve>(curve: &str) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let (scalars, bases, expected) = inputs::<C>(65536, false, false);
        let scalar_before = Zeroizing::new(scalars.to_vec());
        let bases_before = bases.clone();
        let original = plan(scalars.len(), 255, 4, 64 << 20).unwrap();
        assert_eq!(
            (
                original.c,
                original.nw,
                original.per_group,
                original.chunks,
                original.concurrency
            ),
            (12, 22, 6, 1, 4)
        );
        assert_eq!(original.bytes, 11_416_000);
        let fine = fine_plan(scalars.len(), original);
        assert_eq!(payload_bound(scalars.len(), fine), 5_974_976);
        assert_eq!(dynamic_payload_bound(scalars.len(), fine), 5_974_912);
        assert_eq!(batch_cap_experiment::cap(4096, 1024), 1024);
        let shared = SharedMemoryBudget::new(original.bytes);
        let arms = [Arm::Current, Arm::FineWaves, Arm::Dynamic, Arm::Current];
        let names = ["current", "fine_waves", "fine_dynamic", "current_control"];
        let order = [[0, 1, 2, 3, 3, 2, 1, 0], [1, 0, 3, 2, 2, 3, 0, 1]];
        pool.install(|| {
            for arm in arms {
                assert_group(execute::<C, true>(arm, &scalars, &bases, original, &shared, None, None, Hook::None).unwrap(), expected);
            }
            for (block, sequence) in order.iter().enumerate() {
                for (position, &index) in sequence.iter().enumerate() {
                    let start = Instant::now();
                    let actual = execute::<C, true>(arms[index], &scalars, &bases, original, &shared, None, None, Hook::None).unwrap();
                    let elapsed_ns = start.elapsed().as_nanos();
                    assert_group(actual, expected);
                    assert_eq!(shared.in_use_bytes(), 0);
                    assert_eq!(shared.peak_bytes(), original.bytes);
                    let selected = if matches!(arms[index], Arm::Current) { original } else { fine };
                    println!("MSM_SCHEDULING_COMPONENT curve={curve} n=65536 workers=4 block={block} position={position} arm={} elapsed_ns={elapsed_ns} reserved_bytes={} reserved_peak={} modeled_payload_upper_bytes={} mutex_heap_payload_bytes={} window={} windows={} windows_per_group={} point_chunks={} task_count={} callbacks={} equality=canonical_affine_true scope=synthetic_msm_only", names[index], original.bytes, shared.peak_bytes(), if matches!(arms[index], Arm::Dynamic) { dynamic_payload_bound(scalars.len(), selected) } else { payload_bound(scalars.len(), selected) }, if matches!(arms[index], Arm::Dynamic) { verified_mutex_payload_bytes() } else { 0 }, selected.c, selected.nw, selected.per_group, selected.chunks, task_count(&selected), selected.concurrency);
                }
            }
        });
        assert_eq!(scalars.as_slice(), scalar_before.as_slice());
        assert_eq!(bases, bases_before);
        assert_eq!(shared.in_use_bytes(), 0);
    }
    measure::<Ep>("pallas");
    measure::<Eq>("vesta");
}
