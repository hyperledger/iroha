//! Independent weighted-generator checks for sparse and cancelled bucket gaps.
use super::*;
use crate::{Ep, Eq};

fn gaps<C: PastaCurve, const SECRET: bool>() {
    let g = C::generator();
    let weights = [
        C::ScalarExt::ONE,
        C::ScalarExt::from(2),
        -C::ScalarExt::ONE,
        -C::ScalarExt::from(2),
    ];
    let bases: Vec<_> = weights
        .iter()
        .map(|weight| (g * *weight).to_affine())
        .collect();
    let patterns = [
        vec![],
        vec![0],
        vec![8191],
        vec![0, 8191],
        vec![5, 500, 519, 8000],
        vec![511, 512, 513],
        (0..128).collect(),
    ];
    for start in [0, 7] {
        for pattern in &patterns {
            let mut buckets = Buckets::<C, SECRET>::new(&bases, start + 8193);
            let mut expected = C::ScalarExt::ZERO;
            // A neighboring window must be excluded from the gap weights.
            buckets.insert(start + 8192, 1, false);
            for (index, &position) in pattern.iter().enumerate() {
                let base = index % bases.len();
                let negative = index % 3 == 0;
                for repeat in 0..5 {
                    // Repeated and opposite points exercise batch overflow,
                    // cancellation and running sums that become the identity.
                    let sign = negative ^ (repeat == 2 || repeat == 4);
                    buckets.insert(start + position, base, sign);
                    let value = if sign { -weights[base] } else { weights[base] };
                    expected += value * C::ScalarExt::from(position as u64 + 1);
                }
            }
            buckets.flush();
            assert_eq!(buckets.reduce(start, 8192), g * expected);
            assert_eq!(buckets.reduce(start, 0), C::identity());
        }
    }
    for gap in [0, 1, 2, 3, 4, 7, 511, 512, 513, 8191, 8192, 16_383, 16_384] {
        for point in [C::identity(), g, -g, g.double()] {
            assert_eq!(
                multiply_gap_vartime(point, gap),
                point * C::ScalarExt::from(gap as u64)
            );
        }
    }
}

#[test]
fn sparse_gap_weights_match_independent_group_products() {
    gaps::<Ep, false>();
    gaps::<Ep, true>();
    gaps::<Eq, false>();
    gaps::<Eq, true>();
}

fn density_boundary<C: PastaCurve, const SECRET: bool>() {
    let g = C::generator();
    let bases = [g.to_affine(), (-g).to_affine(), g.double().to_affine()];
    for start in [0, 7] {
        let mut buckets = Buckets::<C, SECRET>::new(&bases, start + 97);
        buckets.insert(start + 96, 0, false);
        // The top bucket has no affine value, but its overflow is 2G.
        buckets.insert(start + 95, 0, false);
        buckets.insert(start + 95, 1, false);
        buckets.insert(start + 95, 2, false);
        // This completely cancelled bucket is not occupied.
        buckets.insert(start + 63, 0, false);
        buckets.insert(start + 63, 1, false);
        buckets.insert(start + 31, 1, false);
        buckets.flush();
        assert!(!buckets.has[start + 95]);
        assert!(buckets.overflow_used[start + 95]);
        assert!(!buckets.has[start + 63]);
        assert!(!buckets.overflow_used[start + 63]);
        // The span is 96 and the cutoff is three. Two occupied buckets
        // must take the sparse path, including its overflow-only top.
        assert_eq!(
            (start..start + 96)
                .filter(|&j| buckets.has[j] || buckets.overflow_used[j])
                .count(),
            2
        );
        assert_eq!(buckets.reduce(start, 96), g * C::ScalarExt::from(160));

        // A third occupied position lies exactly at the density cutoff;
        // its weight is one and the dense branch must give the same sum.
        buckets.insert(start, 0, false);
        buckets.flush();
        assert_eq!(
            (start..start + 96)
                .filter(|&j| buckets.has[j] || buckets.overflow_used[j])
                .count(),
            3
        );
        assert_eq!(buckets.reduce(start, 96), g * C::ScalarExt::from(161));

        // Cancel the new affine bucket and the existing overflow while
        // retaining overflow occupancy. Sparse reduction must handle an
        // identity running sum above the remaining lower live bucket.
        buckets.insert(start, 1, false);
        buckets.insert(start + 95, 2, true);
        buckets.flush();
        assert!(!buckets.has[start]);
        // The affine -2G and overflow 2G sum to the identity here.
        assert!(buckets.has[start + 95]);
        assert!(buckets.overflow_used[start + 95]);
        assert_eq!(buckets.reduce(start, 96), -(g * C::ScalarExt::from(32)));
    }
}

#[test]
fn sparse_overflow_cancellation_and_density_cutoff_match_both_curves() {
    density_boundary::<Ep, false>();
    density_boundary::<Ep, true>();
    density_boundary::<Eq, false>();
    density_boundary::<Eq, true>();
}
