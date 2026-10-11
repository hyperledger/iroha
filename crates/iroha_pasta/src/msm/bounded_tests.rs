//! Public-bound validation and parity against full-width and independent MSMs.

use super::*;
use crate::{Ep, Eq};
use ff::Field;
use group::{Curve, Group};

fn bound_edges<F: PastaField>() {
    for bits in 0..=254 {
        let power = (0..bits).fold(F::ONE, |value, _| value.double());
        let values = [F::ZERO, power - F::ONE];
        assert!(BoundedSecretScalars::new(&values, bits, None).is_ok());
        assert!(matches!(
            BoundedSecretScalars::new(&[power], bits, None),
            Err(MsmError::ScalarBound)
        ));
        // Every accepted width must retain the signed recoder's carry window,
        // including widths exactly divisible by the chosen window size.
        for width in pippenger::MIN_WINDOW..=pippenger::MAX_WINDOW {
            let mut digits = vec![0; pippenger::num_windows(bits, width)];
            pippenger::recode_into(&(power - F::ONE).to_canonical_limbs(), width, &mut digits);
            let radix = F::from(1_u64 << width);
            let recovered = digits.iter().rev().fold(F::ZERO, |acc, &digit| {
                let magnitude = F::from(u64::from(digit.unsigned_abs()));
                acc * radix + if digit < 0 { -magnitude } else { magnitude }
            });
            assert_eq!(recovered, power - F::ONE, "bits={bits}, window={width}");
        }
    }
    assert!(BoundedSecretScalars::new(&[-F::ONE], 255, None).is_ok());
    assert!(matches!(
        BoundedSecretScalars::<F>::new(&[], 256, None),
        Err(MsmError::ScalarBound)
    ));
    let mut values = vec![F::ZERO; 2051];
    values[2050] = F::from(1_u64 << 15);
    assert!(matches!(
        BoundedSecretScalars::new(&values, 15, None),
        Err(MsmError::ScalarBound)
    ));
}

#[test]
fn public_bounds_and_signed_carries_cover_every_bit_on_both_fields() {
    bound_edges::<crate::Fp>();
    bound_edges::<crate::Fq>();
}

fn parity<C: PastaCurve>() {
    for count in [0, 1, SMALL_MSM, SMALL_MSM + 1, 33] {
        let bases = (0..count)
            .map(|i| match i % 4 {
                0 => C::AffineExt::identity(),
                1 => C::generator().to_affine(),
                2 => (-C::generator()).to_affine(),
                _ => (C::generator() * C::ScalarExt::from(i as u64 + 1)).to_affine(),
            })
            .collect::<Vec<_>>();
        for bits in [0, 1, 15, 64, 128, 254, 255] {
            let high = if bits == 255 {
                -C::ScalarExt::ONE
            } else {
                (0..bits).fold(C::ScalarExt::ONE, |v, _| v.double()) - C::ScalarExt::ONE
            };
            let scalars = (0..count)
                .map(|i| if i % 3 == 0 { C::ScalarExt::ZERO } else { high })
                .collect::<Vec<_>>();
            let checked = BoundedSecretScalars::new(&scalars, bits, None).unwrap();
            let expected = msm_naive::<C>(&scalars, &bases).to_affine();
            let shared = SharedMemoryBudget::new(128 << 10);
            for threads in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                pool.install(|| {
                    let result = msm_secret_bounded_cancellable::<C>(
                        &checked,
                        &bases,
                        MemoryBudget::DEFAULT,
                        &shared,
                        None,
                    )
                    .unwrap();
                    assert_eq!(result.to_affine(), expected);
                    assert_eq!(
                        msm_secret_cancellable::<C>(
                            &scalars,
                            &bases,
                            MemoryBudget::DEFAULT,
                            &shared,
                            None
                        )
                        .unwrap()
                        .to_affine(),
                        expected
                    );
                    let held = shared.try_reserve(shared.limit_bytes()).unwrap();
                    // Contention selects the unchanged allocation-free secret path.
                    assert_eq!(
                        msm_secret_bounded_cancellable::<C>(
                            &checked,
                            &bases,
                            MemoryBudget::DEFAULT,
                            &shared,
                            None
                        )
                        .unwrap()
                        .to_affine(),
                        expected
                    );
                    drop(held);
                    assert_eq!(shared.in_use_bytes(), 0);
                });
            }
        }
    }
}

#[test]
fn bounded_secret_msm_matches_full_width_and_naive_on_both_curves() {
    parity::<Ep>();
    parity::<Eq>();
}

#[test]
fn bounded_msm_refuses_bad_lengths_budgets_and_cancellation() {
    let values = [crate::Fq::from(32767); 33];
    let bases = [Ep::generator().to_affine(); 33];
    let checked = BoundedSecretScalars::new(&values, 15, None).unwrap();
    let shared = SharedMemoryBudget::new(128 << 10);
    assert!(matches!(
        msm_secret_bounded_cancellable::<Ep>(
            &checked,
            &bases[..32],
            MemoryBudget::DEFAULT,
            &shared,
            None
        ),
        Err(MsmError::LengthMismatch(_))
    ));
    assert!(matches!(
        msm_secret_bounded_cancellable::<Ep>(&checked, &bases, MemoryBudget::new(0), &shared, None),
        Err(MsmError::Budget(_))
    ));
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        BoundedSecretScalars::new(&values, 15, Some(&cancellation)),
        Err(MsmError::Cancelled)
    ));
    assert_eq!(
        msm_secret_bounded_cancellable::<Ep>(
            &checked,
            &bases,
            MemoryBudget::DEFAULT,
            &shared,
            Some(&cancellation)
        ),
        Err(MsmError::Cancelled)
    );
    assert_eq!(shared.in_use_bytes(), 0);
    assert_eq!(
        MsmError::ScalarBound.to_string(),
        "msm: scalar exceeds the public bit bound"
    );
}
