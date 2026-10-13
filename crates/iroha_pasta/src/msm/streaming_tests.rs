//! Forced scratch contention, exact streaming arithmetic and release controls.

use super::*;
use crate::{Ep, Eq};
use ff::Field;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

fn mixed_inputs<C: PastaCurve>(n: usize) -> (Vec<C::ScalarExt>, Vec<C::AffineExt>) {
    let scalars = (0..n)
        .map(|i| match i % 4 {
            0 => C::ScalarExt::ZERO,
            1 => -C::ScalarExt::ONE,
            2 => C::ScalarExt::ONE,
            _ => C::ScalarExt::from((i + 1) as u64),
        })
        .collect();
    let bases = (0..n)
        .map(|i| match i % 5 {
            0 => C::AffineExt::identity(),
            1 | 3 => C::generator().to_affine(),
            2 => (-C::generator()).to_affine(),
            _ => (C::generator() * C::ScalarExt::from((i + 1) as u64)).to_affine(),
        })
        .collect();
    (scalars, bases)
}

fn streaming_parity<C: PastaCurve>() {
    for n in [17, 65, 257] {
        let (scalars, bases) = mixed_inputs::<C>(n);
        let expected = msm_naive::<C>(&scalars, &bases);
        // Every full-input window fails. This forces the fallback through
        // the production entry point, including an odd tiny-tail boundary.
        let free = pippenger::min_plan_bytes(n, 255) - 1;
        for workers in [1, 4] {
            assert!(pippenger::plan(n, 255, workers, free).is_none());
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            let shared = SharedMemoryBudget::new(free * 2);
            let held = shared.try_reserve(free).unwrap();
            pool.install(|| {
                assert_eq!(rayon::current_num_threads(), workers);
                let bounded = BoundedSecretScalars::new(&scalars, 255, None).unwrap();
                // Nested calls share admission and cannot wait for this stack
                // frame (which owns held) or each other to release scratch.
                let (public, secret) = rayon::join(
                    || {
                        msm_public_with_shared_budget::<C>(
                            &scalars,
                            &bases,
                            MemoryBudget::DEFAULT,
                            &shared,
                        )
                    },
                    || {
                        msm_secret_with_shared_budget::<C>(
                            &scalars,
                            &bases,
                            MemoryBudget::DEFAULT,
                            &shared,
                        )
                    },
                );
                assert_eq!(public.unwrap(), expected);
                assert_eq!(secret.unwrap(), expected);
                assert_eq!(
                    msm_secret_bounded_cancellable::<C>(
                        &bounded,
                        &bases,
                        MemoryBudget::DEFAULT,
                        &shared,
                        None
                    )
                    .unwrap(),
                    expected
                );
            });
            assert_eq!(shared.in_use_bytes(), held.bytes());
            if n > 17 {
                assert!(
                    shared.peak_bytes() > held.bytes(),
                    "must admit streamed scratch"
                );
            }
            assert!(shared.peak_bytes() <= shared.limit_bytes());
            drop(held);
            assert_eq!(shared.in_use_bytes(), 0);
        }
    }
}

#[test]
fn streaming_preserves_public_secret_bounded_and_exceptional_points() {
    streaming_parity::<Ep>();
    streaming_parity::<Eq>();
}

fn bounded_streaming<C: PastaCurve>() {
    let n = 257;
    let scalars = (0..n)
        .map(|i| C::ScalarExt::from((i * 127 % 32768) as u64))
        .collect::<Vec<_>>();
    let (_, bases) = mixed_inputs::<C>(n);
    let expected = msm_naive::<C>(&scalars, &bases);
    let shared = SharedMemoryBudget::new(pippenger::min_plan_bytes(n, 15) - 1);
    let bounded = BoundedSecretScalars::new(&scalars, 15, None).unwrap();
    assert_eq!(
        msm_secret_bounded_cancellable::<C>(&bounded, &bases, MemoryBudget::DEFAULT, &shared, None)
            .unwrap(),
        expected
    );
    assert_eq!(shared.in_use_bytes(), 0);
    assert!(
        shared.peak_bytes() > 0,
        "must admit bounded streamed scratch"
    );
    assert!(shared.peak_bytes() <= shared.limit_bytes());
    assert!(matches!(
        BoundedSecretScalars::new(&scalars, 0, None),
        Err(MsmError::ScalarBound)
    ));
    assert!(matches!(
        msm_secret_bounded_cancellable::<C>(
            &bounded,
            &bases[..n - 1],
            MemoryBudget::DEFAULT,
            &shared,
            None
        ),
        Err(MsmError::LengthMismatch(_))
    ));
    assert!(matches!(
        msm_secret_bounded_cancellable::<C>(&bounded, &bases, MemoryBudget::new(0), &shared, None),
        Err(MsmError::Budget(_))
    ));
}

#[test]
fn streaming_keeps_public_width_and_input_errors() {
    bounded_streaming::<Ep>();
    bounded_streaming::<Eq>();
}

#[test]
fn streaming_admission_is_smaller_charged_and_finite_at_zero_fit() {
    let n = 65536;
    let shared = SharedMemoryBudget::new(128 << 10);
    assert!(pippenger::plan(n, 255, 4, shared.limit_bytes()).is_none());
    let (length, plan, permit) =
        streaming_plan(n / 2, 255, 4, MemoryBudget::DEFAULT, &shared).unwrap();
    assert!(length > SMALL_MSM && length < n);
    assert_eq!(permit.bytes(), plan.bytes);
    assert_eq!(shared.in_use_bytes(), plan.bytes);
    assert!(plan.bytes <= shared.limit_bytes());
    drop(permit);
    assert_eq!(shared.in_use_bytes(), 0);
    let held = shared.try_reserve(shared.limit_bytes()).unwrap();
    assert!(streaming_plan(n / 2, 255, 4, MemoryBudget::DEFAULT, &shared).is_none());
    assert!(streaming_plan(SMALL_MSM, 255, 4, MemoryBudget::DEFAULT, &shared).is_none());
    assert_eq!(shared.in_use_bytes(), held.bytes());
}

fn zero_fit<C: PastaCurve>() {
    let (scalars, bases) = mixed_inputs::<C>(65);
    let expected = msm_naive::<C>(&scalars, &bases);
    let shared = SharedMemoryBudget::new(0);
    assert_eq!(
        msm_public_with_shared_budget::<C>(&scalars, &bases, MemoryBudget::DEFAULT, &shared)
            .unwrap(),
        expected
    );
    assert_eq!(
        msm_secret_with_shared_budget::<C>(&scalars, &bases, MemoryBudget::DEFAULT, &shared)
            .unwrap(),
        expected
    );
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        msm_secret_cancellable::<C>(
            &scalars,
            &bases,
            MemoryBudget::DEFAULT,
            &shared,
            Some(&token)
        ),
        Err(MsmError::Cancelled)
    );
    assert_eq!(shared.peak_bytes(), 0);
}

#[test]
fn streaming_zero_fit_uses_exact_stack_fallback_and_cancels() {
    zero_fit::<Ep>();
    zero_fit::<Eq>();
}

fn cancellation<C: PastaCurve>() {
    let scalars = vec![C::ScalarExt::from(1_234_567); 65536];
    let bases = vec![C::generator().to_affine(); scalars.len()];
    let shared = SharedMemoryBudget::new(pippenger::min_plan_bytes(scalars.len(), 255) - 1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let token = CancellationToken::new();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let task = scope.spawn(|| {
            let result = pool.install(|| {
                msm_secret_cancellable::<C>(
                    &scalars,
                    &bases,
                    MemoryBudget::DEFAULT,
                    &shared,
                    Some(&token),
                )
            });
            done.store(true, Ordering::Release);
            result
        });
        let until = Instant::now() + Duration::from_secs(20);
        while shared.in_use_bytes() == 0 && !done.load(Ordering::Acquire) && Instant::now() < until
        {
            std::thread::yield_now();
        }
        let admitted = shared.in_use_bytes() > 0;
        token.cancel();
        assert_eq!(task.join().unwrap(), Err(MsmError::Cancelled));
        assert!(
            admitted,
            "cancel an active streaming kernel, not just its entry"
        );
    });
    assert_eq!(shared.in_use_bytes(), 0);
    assert!(shared.peak_bytes() <= shared.limit_bytes());
    let expected =
        C::generator() * (C::ScalarExt::from(1_234_567) * C::ScalarExt::from(scalars.len() as u64));
    assert_eq!(
        pool.install(|| msm_secret_with_shared_budget::<C>(
            &scalars,
            &bases,
            MemoryBudget::DEFAULT,
            &shared
        ))
        .unwrap(),
        expected
    );
    assert_eq!(shared.in_use_bytes(), 0);
}

#[test]
fn streaming_cancellation_joins_releases_and_retries_both_curves() {
    cancellation::<Ep>();
    cancellation::<Eq>();
}

fn unwind<C: PastaCurve>() {
    let (scalars, bases) = mixed_inputs::<C>(65);
    let shared = SharedMemoryBudget::new(1 << 20);
    let mut plan = pippenger::plan(scalars.len(), 255, 1, shared.limit_bytes()).unwrap();
    let permit = shared.try_reserve(plan.bytes).unwrap();
    // An internal invalid plan deliberately panics at step_by after digit and
    // window allocation. Production plans never have zero concurrency.
    plan.concurrency = 0;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        planned_msm::<C, true>(&scalars, &bases, plan, permit, None)
    }));
    assert!(outcome.is_err());
    assert_eq!(shared.in_use_bytes(), 0);
    assert_eq!(
        msm_secret_with_shared_budget::<C>(&scalars, &bases, MemoryBudget::DEFAULT, &shared)
            .unwrap(),
        msm_naive::<C>(&scalars, &bases)
    );
}

#[test]
fn admitted_kernel_unwind_releases_permit_before_retry() {
    unwind::<Ep>();
    unwind::<Eq>();
}

#[path = "streaming_experiment.rs"]
mod experiment;
