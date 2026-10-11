//! Cooperative kernel cancellation, scratch release and exact retry tests.

use crate::msm::{
    FixedBaseTable, MemoryBudget, MsmError, SharedMemoryBudget, msm_public_cancellable,
    msm_secret_cancellable,
};
use crate::{CancellationToken, Ep, Eq, Fp, PastaCurve};
use ff::Field;
use group::{Curve, Group};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

fn cancelled_msm_releases_scratch<C: PastaCurve>() {
    let scalars = vec![C::ScalarExt::from(1_234_567); 1 << 16];
    let bases = vec![C::generator().to_affine(); scalars.len()];
    let shared = SharedMemoryBudget::new(64 << 20);
    let token = CancellationToken::new();
    let done = Arc::new(AtomicBool::new(false));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
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
        let observed_live_scratch = shared.in_use_bytes() > 0;
        token.cancel();
        assert_eq!(task.join().unwrap(), Err(MsmError::Cancelled));
        assert!(
            observed_live_scratch,
            "must cancel an admitted, active kernel"
        );
    });
    assert_eq!(
        shared.in_use_bytes(),
        0,
        "all workers released their permits"
    );
    assert!(shared.peak_bytes() <= shared.limit_bytes());
    let fresh = CancellationToken::new();
    let expected =
        C::generator() * (C::ScalarExt::from(1_234_567) * C::ScalarExt::from(scalars.len() as u64));
    assert_eq!(
        pool.install(|| msm_secret_cancellable::<C>(
            &scalars,
            &bases,
            MemoryBudget::DEFAULT,
            &shared,
            Some(&fresh)
        ))
        .unwrap(),
        expected
    );
    assert_eq!(shared.in_use_bytes(), 0);
    assert_eq!(
        msm_public_cancellable::<C>(
            &scalars[..8],
            &bases[..8],
            MemoryBudget::DEFAULT,
            &shared,
            Some(&token)
        ),
        Err(MsmError::Cancelled)
    );
    let fallback = SharedMemoryBudget::new(0);
    assert_eq!(
        msm_secret_cancellable::<C>(
            &scalars[..9],
            &bases[..9],
            MemoryBudget::DEFAULT,
            &fallback,
            Some(&token)
        ),
        Err(MsmError::Cancelled)
    );
}

#[test]
fn cancelled_msm_joins_wipes_releases_and_retry_is_exact_on_both_curves() {
    cancelled_msm_releases_scratch::<Ep>();
    cancelled_msm_releases_scratch::<Eq>();
}

#[test]
fn cancelled_fixed_transform_and_fold_return_no_completed_result() {
    let token = CancellationToken::new();
    let shared = SharedMemoryBudget::new(64 << 20);
    let bases = vec![Eq::generator().to_affine(); 16];
    let table = FixedBaseTable::<Eq>::new(&bases, MemoryBudget::DEFAULT).unwrap();
    let scalar = vec![Fp::from(9); bases.len()];
    token.cancel();
    assert_eq!(
        table.msm_secret_cancellable(&scalar, MemoryBudget::DEFAULT, &shared, Some(&token)),
        Err(MsmError::Cancelled)
    );
    assert_eq!(
        table.msm_public_cancellable(&scalar, MemoryBudget::DEFAULT, &shared, Some(&token)),
        Err(MsmError::Cancelled)
    );
    assert_eq!(shared.in_use_bytes(), 0);
    let domain = crate::fft::FftDomain::new(4).unwrap();
    let mut values = scalar.clone();
    assert_eq!(
        domain.fft_cancellable(&mut values, Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    );
    assert_eq!(
        domain.ifft_cancellable(&mut values, Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    );
    assert_eq!(
        domain.coset_fft_cancellable(&mut values, Fp::from(7), Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    );
    assert_eq!(
        domain.coset_ifft_cancellable(&mut values, Fp::from(7), Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    );
    assert_eq!(
        domain.coset_fft_many_cancellable(&mut [&mut values], Fp::from(7), Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    );
    assert!(matches!(
        domain.coset_plan_cancellable(&mut values, Fp::from(7), Some(&token)),
        Err(crate::fft::FftError::Cancelled)
    ));
    assert_eq!(
        values, scalar,
        "pre-cancelled transforms never mutate input"
    );
    let mut points = bases.clone();
    assert_eq!(
        crate::fold::fold_generators_cancellable::<Eq>(&mut points, &Fp::ONE, Some(&token)),
        Err(crate::Cancelled)
    );
    assert_eq!(points, bases);
    let fresh = CancellationToken::new();
    domain.fft_cancellable(&mut values, Some(&fresh)).unwrap();
    domain.ifft_cancellable(&mut values, Some(&fresh)).unwrap();
    assert_eq!(values, scalar);
}
