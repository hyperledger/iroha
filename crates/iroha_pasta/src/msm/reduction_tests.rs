//! Independent group checks for sparse bucket reduction and centered carries.

use super::*;
use crate::{Ep, Eq};
use ff::PrimeField;

fn sparse_windows<C: PastaCurve, const SECRET: bool>() {
    let generator = C::generator();
    let bases = [
        generator.to_affine(),
        (-generator).to_affine(),
        generator.double().to_affine(),
    ];
    for start in [0, 7, 16] {
        let mut buckets = Buckets::<C, SECRET>::new(&bases, 32);
        // A neighboring window must not affect this entirely empty one.
        buckets.insert(31, 0, false);
        buckets.flush();
        assert_eq!(buckets.reduce(start, 8), C::identity());
        assert_eq!(buckets.reduce(start, 0), C::identity());

        // This bucket cancels in its affine part while retaining an overflow
        // contribution. Looking only at `has` would incorrectly skip it.
        buckets.insert(start + 3, 0, false);
        buckets.insert(start + 3, 1, false);
        buckets.insert(start + 3, 2, false);
        buckets.flush();
        assert!(!buckets.has[start + 3]);
        assert!(buckets.overflow_used[start + 3]);
        assert_eq!(buckets.reduce(start, 8), generator * C::ScalarExt::from(8));

        // Weight is relative to the window start, and the empty low prefix
        // must still be counted after the first nonempty high bucket.
        buckets.insert(start + 6, 0, true);
        buckets.flush();
        assert_eq!(buckets.reduce(start, 8), generator);

        // A cancelled high bucket must not hide a lower live bucket.
        buckets.insert(start + 7, 0, false);
        buckets.insert(start + 7, 1, false);
        buckets.flush();
        assert_eq!(buckets.reduce(start, 8), generator);

        // Populate all positions, including the final one: 1+...+8 = 36.
        for bucket in start..start + 8 {
            buckets.insert(bucket, 0, false);
        }
        buckets.flush();
        assert_eq!(buckets.reduce(start, 8), generator * C::ScalarExt::from(37));
    }
}

#[test]
fn leading_empty_and_overflow_only_windows_match_both_curves() {
    sparse_windows::<Ep, false>();
    sparse_windows::<Ep, true>();
    sparse_windows::<Eq, false>();
    sparse_windows::<Eq, true>();
}

fn centered_carries<C: PastaCurve, const SECRET: bool>() {
    let scalars = [
        C::ScalarExt::ZERO,
        C::ScalarExt::ONE,
        -C::ScalarExt::ONE,
        C::ScalarExt::from(8),
        C::ScalarExt::from(9),
        C::ScalarExt::from(15),
        C::ScalarExt::from_u128(u128::MAX),
        -C::ScalarExt::from_u128(u128::MAX),
    ];
    let generator = C::generator();
    let bases: Vec<_> = (1..=scalars.len())
        .map(|weight| (generator * C::ScalarExt::from(weight as u64)).to_affine())
        .collect();
    let expected_scalar = scalars
        .iter()
        .enumerate()
        .fold(C::ScalarExt::ZERO, |acc, (index, scalar)| {
            acc + *scalar * C::ScalarExt::from((index + 1) as u64)
        });
    for width in [2, 4, 8, 15] {
        let nw = num_windows(255, width);
        let digits = Digits::new(&scalars, width, nw);
        assert!(digits.data.iter().any(|digit| *digit < 0));
        // Recoding 2^128-1 propagates the low negative digit through the
        // magnitude's high window. The 255-bit plan can legitimately retain
        // empty windows above it, including a spare top carry window.
        assert_eq!(digits.row(6)[0], -1);
        assert_eq!(digits.row(6)[128 / width], 1 << (128 % width));
        let plan = Plan {
            c: width,
            nw,
            groups: nw,
            per_group: 1,
            chunks: 1,
            concurrency: 1,
            bytes: 0,
        };
        let skip = vec![false; bases.len()];
        let windows: Vec<_> = (0..nw)
            .map(|window| {
                let (start, sums) = run_task::<C, SECRET>(&bases, &skip, &digits, &plan, window, 0);
                assert_eq!(start, window);
                assert_eq!(sums.len(), 1);
                sums[0]
            })
            .collect();
        assert_eq!(combine(&windows, width), generator * expected_scalar);
    }
}

#[test]
fn negative_centered_digits_and_magnitude_carry_match_both_curves() {
    centered_carries::<Ep, false>();
    centered_carries::<Ep, true>();
    centered_carries::<Eq, false>();
    centered_carries::<Eq, true>();
}
