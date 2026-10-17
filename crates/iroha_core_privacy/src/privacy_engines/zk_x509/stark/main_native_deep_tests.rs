//! Independent interpolation, original-claim, allocation and erasure controls.

use super::*;
use crate::privacy_engines::transparent_stark::{
    goldilocks_ifft_v1, masked_trace_coefficients_with_mask_v1,
};

fn extension(seed: u64) -> E {
    E::from_coefficients([F(seed + 1), F(seed + 3), F(seed + 5), F(seed + 7)]).unwrap()
}
fn rows(log: u8, column: usize) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(
        (0..1_usize << log)
            .map(|index| {
                F::reduce((index as u128 + 3) * (index as u128 + 7) + (column as u128 + 1) * 1009)
            })
            .collect(),
    )
}
fn mask(column: usize) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(
        (0..MASK_LENGTH)
            .map(|index| F::reduce((index as u128 + 5) * (column as u128 + 13)))
            .collect(),
    )
}
fn horner(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .fold(E::ZERO, |sum, &coefficient| {
            sum.mul(point).add(E::from_base(coefficient))
        })
}
fn old_coefficients(native: &[F], log: u8, mask: &[F]) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(masked_trace_coefficients_with_mask_v1(native, log, mask).unwrap())
}
fn original_quotient(
    log: u8,
    native: &[ZeroizingMainTraceColumnV1],
    masks: &[ZeroizingMainTraceColumnV1],
    points: [E; 2],
    scales: &[[E; 2]],
) -> ExtensionColumn {
    let mut result = zero_column_v1((1 << log) + MASK_LENGTH).unwrap();
    for ((native, mask), scales) in native.iter().zip(masks).zip(scales) {
        let coefficients = old_coefficients(native, log, mask);
        for side in 0..2 {
            accumulate_base_deep_quotient_v1(
                &coefficients,
                points[side],
                horner(&coefficients, points[side]),
                scales[side],
                &mut result,
            )
            .unwrap();
        }
    }
    result
}

#[test]
fn native_lagrange_openings_match_original_interpolation_and_every_subgroup_shift() {
    for log in [1, 3, 5, 8] {
        let native = rows(log, 3);
        let mask = mask(7);
        let coefficients = old_coefficients(&native, log, &mask);
        let root = goldilocks_primitive_root_v1(log).unwrap();
        for point in [
            extension(31),
            E::from_base(F(29)),
            E::ONE,
            E::from_base(root),
            E::from_base(root.pow(((1 << log) - 1) as u128)),
        ] {
            let points = MainNativeDeepPointsV1::new_v1(log, point).unwrap();
            assert_eq!(
                points.evaluate_v1(&native, &mask).unwrap(),
                points.points.map(|point| horner(&coefficients, point))
            );
            if point.pow((1 << log) as u128) == E::ONE {
                assert_eq!(
                    points
                        .weights
                        .iter()
                        .filter(|&&weight| weight == E::ONE)
                        .count(),
                    1
                );
                assert!(
                    points
                        .weights
                        .iter()
                        .all(|&weight| weight == E::ZERO || weight == E::ONE)
                );
            }
        }
        // Independently invert each Lagrange denominator, rather than using the
        // production batch-inversion recurrence, and check every weight.
        let points = MainNativeDeepPointsV1::new_v1(log, extension(47)).unwrap();
        let n = 1_usize << log;
        let inverse_n = F::reduce(n as u128).inv().unwrap();
        let mut root_power = F::ONE;
        for &weight in points.weights.iter() {
            let expected = points.vanishing.mul_base(root_power.mul(inverse_n)).mul(
                points.points[0]
                    .sub(E::from_base(root_power))
                    .inv()
                    .unwrap(),
            );
            assert_eq!(weight, expected);
            root_power = root_power.mul(root);
        }
    }
}

#[test]
fn native_mask_tail_handles_terms_below_at_above_native_degree_and_highest_original_mask() {
    for log in [3, 5, 8] {
        let n = 1_usize << log;
        for degree in [0, n - 1, n, n + 1, MASK_LENGTH - 1] {
            let native = rows(log, degree);
            let mut mask = ZeroizingMainTraceColumnV1(vec![F::ZERO; MASK_LENGTH]);
            mask.0[degree] = F(127);
            let points = MainNativeDeepPointsV1::new_v1(log, extension(71)).unwrap();
            let values = points.evaluate_v1(&native, &mask).unwrap();
            let coefficients = old_coefficients(&native, log, &mask);
            assert_eq!(
                values,
                points.points.map(|point| horner(&coefficients, point))
            );
            let scales = [extension(83), extension(97)];
            let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
            weighted
                .add_batch_v1(&points, &[(&native, &mask, values, scales)])
                .unwrap();
            let mut actual = zero_column_v1(n + MASK_LENGTH).unwrap();
            weighted.accumulate_v1(1, &mut actual).unwrap();
            let expected = original_quotient(log, &[native], &[mask], points.points, &[scales]);
            assert_eq!(&*actual, &*expected);
        }
    }
}

#[test]
fn native_weighted_batches_match_each_original_quotient_in_fixed_column_order() {
    for width in 1..=BATCH {
        let log = 5;
        let native = (0..width)
            .map(|column| rows(log, column))
            .collect::<Vec<_>>();
        let masks = (0..width).map(mask).collect::<Vec<_>>();
        let points = MainNativeDeepPointsV1::new_v1(log, extension(113)).unwrap();
        let scales = (0..width)
            .map(|column| {
                [
                    extension(column as u64 + 131),
                    extension(column as u64 + 149),
                ]
            })
            .collect::<Vec<_>>();
        let inputs = (0..width)
            .map(|column| {
                (
                    &*native[column],
                    &*masks[column],
                    points.evaluate_v1(&native[column], &masks[column]).unwrap(),
                    scales[column],
                )
            })
            .collect::<Vec<_>>();
        let expected = original_quotient(log, &native, &masks, points.points, &scales);
        for split in 1..=width {
            let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
            weighted.add_batch_v1(&points, &inputs[..split]).unwrap();
            if split < width {
                weighted.add_batch_v1(&points, &inputs[split..]).unwrap();
            }
            let mut actual = zero_column_v1((1 << log) + MASK_LENGTH).unwrap();
            weighted.accumulate_v1(width, &mut actual).unwrap();
            assert_eq!(&*actual, &*expected);
        }
    }
}

#[test]
fn native_each_changed_claim_foreign_mask_and_cancelling_pair_refuse_before_mutation() {
    let native = (0..BATCH).map(|column| rows(5, column)).collect::<Vec<_>>();
    let masks = (0..BATCH).map(mask).collect::<Vec<_>>();
    let points = MainNativeDeepPointsV1::new_v1(5, extension(167)).unwrap();
    let inputs = (0..BATCH)
        .map(|column| {
            (
                &*native[column],
                &*masks[column],
                points.evaluate_v1(&native[column], &masks[column]).unwrap(),
                [E::ONE; 2],
            )
        })
        .collect::<Vec<_>>();
    let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
    for column in 0..BATCH {
        for side in 0..2 {
            let mut bad = inputs.clone();
            bad[column].2[side] = bad[column].2[side].add(E::ONE);
            assert!(matches!(
                weighted.add_batch_v1(&points, &bad),
                Err(ZkX509StarkErrorV1::ConstraintOpening)
            ));
            // The paired error has zero aggregate at exactly the same scale.
            let other = (column + 1) % BATCH;
            bad[other].2[side] = bad[other].2[side].sub(E::ONE);
            assert!(matches!(
                weighted.add_batch_v1(&points, &bad),
                Err(ZkX509StarkErrorV1::ConstraintOpening)
            ));
            assert_eq!(weighted.columns, 0);
            assert_eq!(weighted.values, [E::ZERO; 2]);
            assert!(
                weighted
                    .coefficients
                    .iter()
                    .flat_map(|column| column.iter())
                    .all(|&cell| cell == E::ZERO)
            );
        }
    }
    let mut foreign = inputs.clone();
    foreign[0].1 = &masks[1];
    assert!(weighted.add_batch_v1(&points, &foreign).is_err());
    let other_points = MainNativeDeepPointsV1::new_v1(5, extension(173)).unwrap();
    assert!(weighted.add_batch_v1(&other_points, &inputs).is_err());
    let other_group = MainNativeDeepPointsV1::new_v1(8, points.points[0]).unwrap();
    assert!(weighted.add_batch_v1(&other_group, &inputs).is_err());
    weighted.add_batch_v1(&points, &inputs).unwrap();
    assert_eq!(weighted.columns, BATCH);
}

#[test]
fn native_shapes_counter_and_both_accumulator_owners_fail_closed() {
    let native = rows(5, 0);
    let mask = mask(0);
    let points = MainNativeDeepPointsV1::new_v1(5, extension(191)).unwrap();
    let values = points.evaluate_v1(&native, &mask).unwrap();
    assert!(MainNativeDeepPointsV1::new_v1(0, points.points[0]).is_err());
    assert!(
        MainNativeDeepPointsV1::new_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1 + 1, points.points[0])
            .is_err()
    );
    assert!(MainNativeDeepPointsV1::new_v1(5, E::ZERO).is_err());
    for bad in [
        vec![],
        vec![F::ONE; 31],
        vec![F::ONE; 33],
        vec![F(u64::MAX); 32],
    ] {
        assert!(points.evaluate_v1(&bad, &mask).is_err());
    }
    for bad in [
        vec![],
        vec![F::ONE; MASK_LENGTH - 1],
        vec![F::ONE; MASK_LENGTH + 1],
        vec![F(u64::MAX); MASK_LENGTH],
    ] {
        assert!(points.evaluate_v1(&native, &bad).is_err());
    }
    let input = (&*native, &*mask, values, [E::ONE; 2]);
    let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
    assert!(weighted.add_batch_v1(&points, &[]).is_err());
    assert!(weighted.add_batch_v1(&points, &[input; BATCH + 1]).is_err());
    weighted.columns = usize::MAX;
    assert!(weighted.add_batch_v1(&points, &[input]).is_err());
    for side in 0..2 {
        let mut malformed = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
        malformed.coefficients[side].pop();
        assert!(malformed.add_batch_v1(&points, &[input]).is_err());
        assert_eq!(malformed.columns, 0);
        assert!(
            malformed
                .accumulate_v1(1, &mut vec![E::ZERO; 32 + MASK_LENGTH])
                .is_err()
        );
    }
    for (expected, size) in [
        (0, 32 + MASK_LENGTH),
        (2, 32 + MASK_LENGTH),
        (1, 32 + MASK_LENGTH - 2),
    ] {
        let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
        weighted.add_batch_v1(&points, &[input]).unwrap();
        let mut accumulator = vec![extension(211); size];
        let original = accumulator.clone();
        assert!(weighted.accumulate_v1(expected, &mut accumulator).is_err());
        assert_eq!(accumulator, original);
    }
}

#[test]
fn native_allocation_census_uses_actual_capacities_and_old_fixed_allowance() {
    let mut points = MainNativeDeepPointsV1::new_v1(5, extension(223)).unwrap();
    let mut weighted = vec![MainNativeDeepQuotientV1::new_v1(&points).unwrap()];
    weighted[0].coefficients[1].try_reserve_exact(79).unwrap();
    points.weights.try_reserve_exact(67).unwrap();
    points.mask_powers[0].try_reserve_exact(73).unwrap();
    let mut native = vec![rows(5, 0)];
    native[0].0.try_reserve_exact(71).unwrap();
    points
        .check_workspace_v1(&weighted, weighted.capacity(), &native, native.capacity())
        .unwrap();
    let extension_capacity = weighted[0].extension_capacity_v1().unwrap();
    let bytes = (points.weights.capacity()
        + points
            .mask_powers
            .iter()
            .map(|column| column.capacity())
            .sum::<usize>()
        + extension_capacity)
        * core::mem::size_of::<E>()
        + native[0].0.capacity() * core::mem::size_of::<F>()
        + METADATA_BYTES
        + weighted.capacity() * core::mem::size_of::<MainNativeDeepQuotientV1>()
        + native.capacity() * core::mem::size_of::<ZeroizingMainTraceColumnV1>();
    assert!(native[0].0.capacity() > native[0].len());
    assert!(bytes < points.allowance);
    points.allowance = bytes;
    points
        .check_workspace_v1(&weighted, weighted.capacity(), &native, native.capacity())
        .unwrap();
    points.allowance -= 1;
    assert!(matches!(
        points.check_workspace_v1(&weighted, weighted.capacity(), &native, native.capacity()),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert!(points.check_live_v1(usize::MAX, 0, 0).is_err());
    assert!(
        points
            .check_workspace_v1(&weighted, 0, &native, native.capacity())
            .is_err()
    );
    assert!(
        points
            .check_workspace_v1(&weighted, weighted.capacity(), &native, 0)
            .is_err()
    );
}

#[test]
fn native_private_and_public_owners_clear_on_success_claim_error_late_error_and_unwind() {
    for mode in 0..5 {
        let (result, erased) = observations::observe_v1(|| {
            std::panic::catch_unwind(|| {
                let points = MainNativeDeepPointsV1::new_v1(5, extension(239)).unwrap();
                let native = rows(5, 3);
                let mask = mask(5);
                let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
                let mut values = points.evaluate_v1(&native, &mask).unwrap();
                if mode == 1 {
                    values[1] = values[1].add(E::ONE);
                }
                weighted.add_batch_v1(&points, &[(&native, &mask, values, [extension(251); 2])])?;
                if mode == 3 {
                    panic!("injected native DEEP unwind");
                }
                if mode == 4 {
                    weighted.values[1] = weighted.values[1].add(E::ONE);
                }
                let size = if mode == 2 { 1 } else { 32 + MASK_LENGTH };
                weighted.accumulate_v1(1, &mut vec![E::ZERO; size])
            })
        });
        match mode {
            0 => assert!(result.unwrap().is_ok()),
            1 | 2 | 4 => assert!(result.unwrap().is_err()),
            _ => assert!(result.is_err()),
        }
        assert!(erased.iter().map(|entry| entry.1).sum::<usize>() > 0);
        assert!(erased.iter().all(|entry| entry.2 == 0));
        // Prefix + weights + two mask-power + two weighted allocations, even
        // when the first claim refuses before it can mutate a weighted cell.
        assert_eq!(erased.len(), 6);
        assert_eq!(
            erased.iter().map(|entry| entry.0).sum::<usize>(),
            4 * 32 + 4 * MASK_LENGTH
        );
    }
}

#[test]
fn native_long_mask_wrong_descending_overlap_is_detected_by_independent_polynomial() {
    let n = 32;
    let native = rows(5, 1);
    let mask = mask(2);
    let expected = old_coefficients(&native, 5, &mask);
    let mut incorrect = native.0.clone();
    goldilocks_ifft_v1(&mut incorrect, goldilocks_primitive_root_v1(5).unwrap()).unwrap();
    incorrect.extend_from_slice(&mask);
    for degree in (0..MASK_LENGTH).rev() {
        incorrect[degree] = incorrect[degree].sub(incorrect[n + degree]);
    }
    assert_ne!(&incorrect, &*expected);
    let mut correct = native.0.clone();
    goldilocks_ifft_v1(&mut correct, goldilocks_primitive_root_v1(5).unwrap()).unwrap();
    correct.extend_from_slice(&mask);
    for degree in 0..MASK_LENGTH {
        correct[degree] = correct[degree].sub(correct[n + degree]);
    }
    assert_eq!(&correct, &*expected);
}

#[test]
#[ignore = "optimized all-six-native-domain eight-column exact parity and timing; run --release"]
fn native_all_registered_domains_eight_column_original_openings_and_fri_bytes() {
    use std::time::Instant;
    crate::test_support::require_no_debug_assertions("run this diagnostic with --release");
    for log in [5, 8, 15, 16, 18, 19] {
        let native = (0..BATCH)
            .map(|column| rows(log, column))
            .collect::<Vec<_>>();
        let masks = (0..BATCH).map(mask).collect::<Vec<_>>();
        let point = extension(271);
        let next = point.mul_base(goldilocks_primitive_root_v1(log).unwrap());
        let scales = (0..BATCH)
            .map(|column| {
                [
                    extension(column as u64 + 283),
                    extension(column as u64 + 307),
                ]
            })
            .collect::<Vec<_>>();
        let start = Instant::now();
        let original_values = native
            .iter()
            .zip(&masks)
            .map(|(native, mask)| {
                let coefficients = old_coefficients(native, log, mask);
                [horner(&coefficients, point), horner(&coefficients, next)]
            })
            .collect::<Vec<_>>();
        let original_opening_time = start.elapsed();
        let start = Instant::now();
        let points = MainNativeDeepPointsV1::new_v1(log, point).unwrap();
        let actual_values = native
            .par_iter()
            .zip(&masks)
            .map(|(native, mask)| points.evaluate_v1(native, mask).unwrap())
            .collect::<Vec<_>>();
        let native_opening_time = start.elapsed();
        assert_eq!(actual_values, original_values);
        let start = Instant::now();
        let expected = original_quotient(log, &native, &masks, points.points, &scales);
        let original_quotient_time = start.elapsed();
        let start = Instant::now();
        let inputs = (0..BATCH)
            .map(|column| {
                (
                    &*native[column],
                    &*masks[column],
                    actual_values[column],
                    scales[column],
                )
            })
            .collect::<Vec<_>>();
        let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
        weighted.add_batch_v1(&points, &inputs).unwrap();
        let mut actual = zero_column_v1((1 << log) + MASK_LENGTH).unwrap();
        weighted.accumulate_v1(BATCH, &mut actual).unwrap();
        let native_quotient_time = start.elapsed();
        assert_eq!(&*actual, &*expected);
        eprintln!(
            "native DEEP exact log={log}, columns={BATCH}, original_openings={original_opening_time:?}, native_openings={native_opening_time:?}, original_quotients={original_quotient_time:?}, native_quotients={native_quotient_time:?}; no complete-proof speed claim"
        );
    }
}

#[test]
#[ignore = "release-only malformed internal extension-field owner controls; run --release"]
fn native_noncanonical_points_claims_scales_and_accumulator_refuse_both_sides() {
    crate::test_support::require_no_debug_assertions(
        "from_base deliberately asserts canonicality in debug builds",
    );
    let invalid = E::from_raw_coefficients_for_testing([F(u64::MAX), F::ZERO, F::ZERO, F::ZERO]);
    assert!(!invalid.is_canonical());
    assert!(MainNativeDeepPointsV1::new_v1(5, invalid).is_err());
    let points = MainNativeDeepPointsV1::new_v1(5, extension(331)).unwrap();
    let native = rows(5, 1);
    let mask = mask(3);
    let input = (
        &*native,
        &*mask,
        points.evaluate_v1(&native, &mask).unwrap(),
        [E::ONE; 2],
    );
    for side in 0..2 {
        for is_scale in [false, true] {
            let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
            let mut bad = input;
            if is_scale {
                bad.3[side] = invalid;
            } else {
                bad.2[side] = invalid;
            }
            assert!(matches!(
                weighted.add_batch_v1(&points, &[bad]),
                Err(ZkX509StarkErrorV1::ProfileMismatch)
            ));
            assert_eq!(weighted.columns, 0);
            assert!(
                weighted
                    .coefficients
                    .iter()
                    .flat_map(|column| column.iter())
                    .all(|&cell| cell == E::ZERO)
            );
        }
    }
    for side in 0..2 {
        let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
        weighted.add_batch_v1(&points, &[input]).unwrap();
        weighted.coefficients[side][32 + MASK_LENGTH - 1] = invalid;
        let mut accumulator = vec![extension(359); 32 + MASK_LENGTH];
        let old = accumulator.clone();
        assert!(weighted.accumulate_v1(1, &mut accumulator).is_err());
        assert_eq!(accumulator, old);
    }
    let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
    weighted.add_batch_v1(&points, &[input]).unwrap();
    let mut accumulator = vec![E::ZERO; 32 + MASK_LENGTH];
    accumulator[17] = invalid;
    let old = accumulator.clone();
    assert!(weighted.accumulate_v1(1, &mut accumulator).is_err());
    assert_eq!(accumulator, old);
}

#[test]
fn native_mixed_malformed_and_false_claims_have_deterministic_error_precedence() {
    let points = MainNativeDeepPointsV1::new_v1(5, extension(347)).unwrap();
    let native = rows(5, 1);
    let mask = mask(3);
    let values = points.evaluate_v1(&native, &mask).unwrap();
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        for malformed_first in [false, true] {
            let mut inputs = [(&*native, &*mask, values, [E::ONE; 2]); 2];
            let malformed = usize::from(malformed_first);
            inputs[malformed].0 = &native[..31];
            inputs[1 - malformed].2[0] = values[0].add(E::ONE);
            let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
            let result = pool.install(|| weighted.add_batch_v1(&points, &inputs));
            assert!(matches!(result, Err(ZkX509StarkErrorV1::ProfileMismatch)));
            assert_eq!(weighted.columns, 0);
            assert!(
                weighted
                    .coefficients
                    .iter()
                    .flat_map(|column| column.iter())
                    .all(|&cell| cell == E::ZERO)
            );
        }
    }
}

#[test]
fn native_weighted_mask_slot_clears_each_read_and_on_late_division_or_ifft_error() {
    let points = MainNativeDeepPointsV1::new_v1(5, extension(367)).unwrap();
    let native = rows(5, 3);
    let mask = mask(5);
    let values = points.evaluate_v1(&native, &mask).unwrap();
    for mode in 0..3 {
        let (result, cleared) = stack_observations::observe_v1(|| {
            let mut weighted = MainNativeDeepQuotientV1::new_v1(&points).unwrap();
            weighted
                .add_batch_v1(&points, &[(&native, &mask, values, [extension(379); 2])])
                .unwrap();
            if mode == 1 {
                weighted.values[1] = weighted.values[1].add(E::ONE);
            }
            if mode == 2 {
                weighted.root = F::ZERO;
            }
            weighted.accumulate_v1(1, &mut vec![E::ZERO; 32 + MASK_LENGTH])
        });
        assert_eq!(result.is_ok(), mode == 0);
        assert!(cleared.iter().all(|entry| entry.0 == 1 && entry.2 == 0));
        if mode == 2 {
            assert_eq!(cleared, vec![(1, 0, 0)]);
        } else {
            assert_eq!(cleared.len(), 2 * MASK_LENGTH + 1);
            assert!(cleared.iter().map(|entry| entry.1).sum::<usize>() > 0);
            assert_eq!(cleared.last(), Some(&(1, 0, 0)));
        }
    }
}
