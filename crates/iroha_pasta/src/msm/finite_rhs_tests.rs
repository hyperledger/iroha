//! Finite-RHS mixed-addition invariants and a bounded public component diagnostic.
use super::*;
use crate::{Ep, Eq};
use group::prime::PrimeCurveAffine;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::{hint::black_box, time::Instant};

fn cases<C: PastaCurve>(count: usize) -> Vec<(C, C::AffineExt)> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6669_6e69_7465_7273);
    (0..count)
        .map(|index| {
            let mut rhs = C::random(&mut rng).to_affine();
            if bool::from(rhs.is_identity()) {
                rhs = C::generator().to_affine();
            }
            let left = match index % 5 {
                0 => C::identity(),
                1 => rhs.to_curve(),
                2 => -rhs.to_curve(),
                3 => C::generator() * C::ScalarExt::ZERO,
                _ => C::random(&mut rng),
            };
            // Preserve the point while exercising nonunit homogeneous Z and
            // noncanonical projective representatives of the identity.
            let scale = C::Base::from(index as u64 + 2);
            let (x, y, z) = left.projective_coordinates();
            let left = C::from_projective_coordinates(x * scale, y * scale, z * scale).unwrap();
            (left, rhs)
        })
        .collect()
}

fn parity<C: PastaCurve>() {
    for (left, right) in cases::<C>(128) {
        assert!(!bool::from(right.is_identity()));
        let finite = crate::curve::add_mixed_finite(&left, &right);
        // The separate projective complete-add formula is the group oracle.
        let expected = left + right.to_curve();
        assert_eq!(finite.to_bytes(), expected.to_bytes());
        assert_eq!((left + right).to_bytes(), expected.to_bytes());
        assert_eq!(left + C::AffineExt::identity(), left);
        assert!(bool::from(PastaCurve::is_on_curve(&finite)));
    }
}

#[test]
fn finite_rhs_matches_complete_addition_both_curves() {
    parity::<Ep>();
    parity::<Eq>();
}

fn bucket_parity<C: PastaCurve, const SECRET: bool>() {
    let g = C::generator();
    let weights = [1_i64, 2, -1, -2, 3];
    let scalars: Vec<_> = weights
        .iter()
        .map(|w| {
            let magnitude = C::ScalarExt::from(w.unsigned_abs());
            if *w < 0 { -magnitude } else { magnitude }
        })
        .collect();
    let bases: Vec<_> = scalars.iter().map(|s| (g * *s).to_affine()).collect();
    // Sparse and dense reductions, an adjacent excluded window, cancellation
    // followed by insertion, and overflow that itself reaches the identity.
    for positions in [vec![0, 95], (0..96).collect()] {
        let mut buckets = Buckets::<C, SECRET>::new(&bases, 104);
        buckets.insert(103, 0, false);
        let mut expected = C::ScalarExt::ZERO;
        for position in positions {
            for (base, negative) in [(0, false), (2, false), (1, false)] {
                buckets.insert(position + 7, base, negative);
                expected += scalars[base] * C::ScalarExt::from(position as u64 + 1);
            }
            buckets.flush();
            assert!(!buckets.has[position + 7]);
            assert!(buckets.overflow_used[position + 7]);
            for (base, negative) in [(1, true), (4, false), (3, false), (0, false)] {
                buckets.insert(position + 7, base, negative);
                let value = if negative {
                    -scalars[base]
                } else {
                    scalars[base]
                };
                expected += value * C::ScalarExt::from(position as u64 + 1);
            }
            buckets.flush();
            for index in 0..buckets.has.len() {
                if buckets.has[index] {
                    let point = crate::curve::affine_unchecked::<C::AffineExt>(
                        buckets.x[index],
                        buckets.y[index],
                    );
                    assert!(!bool::from(point.is_identity()));
                    assert!(bool::from(PastaAffine::is_on_curve(&point)));
                }
            }
        }
        assert_eq!(buckets.reduce(7, 96), g * expected);
        if SECRET {
            buckets.wipe();
            assert!(buckets.has.iter().all(|used| !used));
            assert!(buckets.overflow_used.iter().all(|used| !used));
            assert!(
                buckets
                    .overflow
                    .iter()
                    .all(|point| bool::from(point.is_identity()))
            );
            assert_eq!(buckets.reduce(7, 96), C::identity());
        }
    }
}

#[test]
fn finite_bucket_rhs_survives_cancel_overflow_and_reuse_both_curves() {
    bucket_parity::<Ep, false>();
    bucket_parity::<Ep, true>();
    bucket_parity::<Eq, false>();
    bucket_parity::<Eq, true>();
}

fn timed<C: PastaCurve, const FINITE: bool>(pairs: &[(C, C::AffineExt)], out: &mut [C]) -> u128 {
    let start = Instant::now();
    for _ in 0..16 {
        for ((left, right), result) in black_box(pairs).iter().zip(black_box(&mut *out).iter_mut())
        {
            *result = black_box(if FINITE {
                crate::curve::add_mixed_finite(left, right)
            } else {
                *left + *right
            });
        }
    }
    black_box(&*out);
    start.elapsed().as_nanos()
}

fn diagnostic<C: PastaCurve>(curve: &str) {
    parity::<C>();
    let pairs = cases::<C>(4096);
    let expected: Vec<_> = pairs
        .iter()
        .map(|(left, right)| *left + right.to_curve())
        .collect();
    let mut out = vec![C::identity(); pairs.len()];
    let pointer = out.as_ptr();
    let capacity = out.capacity();
    // Public seeded inputs, all setup/oracles and one warm-up per arm excluded.
    timed::<C, false>(&pairs, &mut out);
    assert_eq!(out, expected);
    timed::<C, true>(&pairs, &mut out);
    assert_eq!(out, expected);
    for (block, order, arms) in [
        (0, "ABBA", [false, true, true, false]),
        (1, "BAAB", [true, false, false, true]),
    ] {
        for (position, finite) in arms.into_iter().enumerate() {
            let elapsed = if finite {
                timed::<C, true>(&pairs, &mut out)
            } else {
                timed::<C, false>(&pairs, &mut out)
            };
            assert_eq!(out, expected);
            assert_eq!(out.as_ptr(), pointer);
            assert_eq!(out.capacity(), capacity);
            let arm = if finite { "finite" } else { "reference" };
            println!(
                "FINITE_RHS_MIXED_DIAGNOSTIC curve={curve} block={block} position={position} order={order} arm={arm} pairs=4096 rounds=16 elapsed_ns={elapsed} outputs_equal=true scope=public_component_only"
            );
        }
    }
}

#[test]
#[ignore = "balanced public mixed-addition component diagnostic; no proof or phone latency claim"]
fn finite_rhs_mixed_addition_diagnostic() {
    // Sequential component arithmetic; no Rayon pool or MSM plan is changed.
    // The measured cut includes black boxes, input traversal and reused output
    // writes. Allocation, correctness comparisons, logging and drops are outside.
    diagnostic::<Ep>("pallas");
    diagnostic::<Eq>("vesta");
}
