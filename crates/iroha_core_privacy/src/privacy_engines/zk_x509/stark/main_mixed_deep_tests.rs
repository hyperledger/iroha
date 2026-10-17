//! Original polynomial, routing, claim-precedence and clearing controls for mixed DEEP.
use super::*;
use crate::privacy_engines::transparent_stark::masked_trace_coefficients_with_mask_v1;

fn extension(seed: u64) -> E {
    E::from_coefficients([F(seed + 1), F(seed + 3), F(seed + 5), F(seed + 7)]).unwrap()
}
fn native(log: u8, column: usize) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(
        (0..1usize << log)
            .map(|i| F((i * i + 7 * column + 13) as u64))
            .collect(),
    )
}
fn masks(column: usize) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(
        (0..MASK_LENGTH)
            .map(|i| F((i * 7 + column * 17 + 1) as u64))
            .collect(),
    )
}
fn horner(coefficients: &[F], point: E) -> E {
    coefficients.iter().rev().fold(E::ZERO, |sum, &value| {
        sum.mul(point).add(E::from_base(value))
    })
}
fn originals(
    log: u8,
    width: usize,
) -> (
    Vec<ZeroizingMainTraceColumnV1>,
    Vec<ZeroizingMainTraceColumnV1>,
) {
    let masks: Vec<_> = (0..width).map(masks).collect();
    let coefficients = masks
        .iter()
        .enumerate()
        .map(|(column, mask)| {
            ZeroizingMainTraceColumnV1(
                masked_trace_coefficients_with_mask_v1(&native(log, column), log, mask).unwrap(),
            )
        })
        .collect();
    (masks, coefficients)
}
fn gather<'a>(
    log: u8,
    retained: u8,
    coefficients: &'a [ZeroizingMainTraceColumnV1],
    seen: &mut Vec<usize>,
) -> MainDeepReplayBatchV1<'a> {
    MainDeepReplayBatchV1::gather_v1(
        0..coefficients.len(),
        |first, end| {
            let cached = retained & (1 << first) != 0;
            let next = (first + 1..end)
                .find(|&index| (retained & (1 << index) != 0) != cached)
                .unwrap_or(end);
            Ok((next, cached))
        },
        |range| {
            let mut result = Vec::with_capacity(range.len());
            for column in range {
                seen.push(column);
                result.push(native(log, column));
            }
            Ok(result)
        },
        |column| Ok(&coefficients[column]),
    )
    .unwrap()
}

#[test]
fn every_public_eight_column_partition_preserves_original_order_without_cached_source_work() {
    let (masks, coefficients) = originals(3, BATCH);
    for retained in 0..=u8::MAX {
        let mut seen = Vec::new();
        let batch = gather(3, retained, &coefficients, &mut seen);
        assert_eq!(
            seen,
            (0..BATCH)
                .filter(|&i| retained & (1 << i) == 0)
                .collect::<Vec<_>>()
        );
        for i in 0..BATCH {
            match batch.input_v1(i, &masks[i]).unwrap() {
                MainMixedInputV1::Native(rows, mask) => {
                    assert_eq!(rows, &*native(3, i));
                    assert_eq!(mask, &*masks[i]);
                }
                MainMixedInputV1::Retained(column) => {
                    assert_eq!(column.as_ptr(), coefficients[i].as_ptr());
                    assert_eq!(column, &*coefficients[i]);
                }
            }
        }
        assert!(batch.input_v1(BATCH, &[]).is_err());
    }
    for range in [0..0, 0..9] {
        assert!(
            MainDeepReplayBatchV1::gather_v1(
                range,
                |_, _| panic!("invalid range before dispatch"),
                |_| panic!("invalid range before source"),
                |_| panic!("invalid range before retained")
            )
            .is_err()
        );
    }
    for bad_end in [0, 9] {
        assert!(
            MainDeepReplayBatchV1::gather_v1(
                0..8,
                |_, _| Ok((bad_end, false)),
                |_| panic!("bad public run before source"),
                |_| panic!("bad public run before retained")
            )
            .is_err()
        );
    }
    assert!(
        MainDeepReplayBatchV1::gather_v1(
            0..2,
            |_, end| Ok((end, false)),
            |_| Ok(vec![native(3, 0)]),
            |_| panic!("not retained")
        )
        .is_err()
    );
}

#[test]
fn mixed_openings_and_weighted_quotients_match_each_original_horner_and_division() {
    for log in [3, 8] {
        for width in [1, 3, BATCH] {
            let (masks, coefficients) = originals(log, width);
            for retained in [0u8, 1, 0x55, 0xaa, 0x7f, 0x80, 0xfe, 0xff] {
                let retained_count = (0..width).filter(|&i| retained & (1 << i) != 0).count();
                for point in [extension(31), E::ONE] {
                    let points =
                        MainMixedDeepPointsV1::new_v1(log, point, retained_count != 0, 310_494_720)
                            .unwrap();
                    let mut weighted = MainMixedDeepQuotientV1::new_v1(&points).unwrap();
                    let mut seen = Vec::new();
                    let batch = gather(log, retained, &coefficients, &mut seen);
                    points
                        .check_workspace_v1(
                            core::slice::from_ref(&weighted),
                            1,
                            &batch.native,
                            batch.native.capacity(),
                        )
                        .unwrap();
                    let mut descriptors: [MainMixedColumnV1<'_>; BATCH] =
                        core::array::from_fn(|_| {
                            (
                                MainMixedInputV1::Native(&[], &[]),
                                [E::ZERO; 2],
                                [E::ZERO; 2],
                            )
                        });
                    let mut expected = zero_column_v1((1 << log) + MASK_LENGTH).unwrap();
                    for i in 0..width {
                        let values = points
                            .native
                            .points
                            .map(|point| horner(&coefficients[i], point));
                        let input = batch.input_v1(i, &masks[i]).unwrap();
                        assert_eq!(points.evaluate_v1(input).unwrap(), values);
                        let scales = [extension(i as u64 + 41), extension(i as u64 + 61)];
                        descriptors[i] = (input, values, scales);
                        for side in 0..2 {
                            accumulate_base_deep_quotient_v1(
                                &coefficients[i],
                                points.native.points[side],
                                values[side],
                                scales[side],
                                &mut expected,
                            )
                            .unwrap();
                        }
                    }
                    weighted
                        .add_batch_v1(&points, &descriptors[..width])
                        .unwrap();
                    let mut actual = zero_column_v1(expected.len()).unwrap();
                    weighted
                        .accumulate_v1(width - retained_count, retained_count, &mut actual)
                        .unwrap();
                    assert_eq!(&*actual, &*expected);
                }
            }
        }
    }
}

fn unchanged(owner: &MainMixedDeepQuotientV1) {
    assert_eq!(owner.native.columns, 0);
    assert!(
        owner
            .native
            .coefficients
            .iter()
            .flat_map(|column| column.iter())
            .all(|&x| x == E::ZERO)
    );
    let retained = owner.retained.as_ref().unwrap();
    assert_eq!(retained.columns, 0);
    assert!(
        retained
            .coefficients
            .iter()
            .flat_map(|column| column.iter())
            .all(|&x| x == E::ZERO)
    );
}
#[test]
fn original_shape_precedence_and_cancelling_false_claims_refuse_before_either_weighted_owner_changes()
 {
    let (masks, coefficients) = originals(3, 2);
    let rows = native(3, 0);
    let points = MainMixedDeepPointsV1::new_v1(3, extension(37), true, 310_494_720).unwrap();
    let values = coefficients
        .iter()
        .map(|column| points.native.points.map(|point| horner(column, point)))
        .collect::<Vec<_>>();
    let valid = [
        (
            MainMixedInputV1::Native(&rows, &masks[0]),
            values[0],
            [E::ONE; 2],
        ),
        (
            MainMixedInputV1::Retained(&coefficients[1]),
            values[1],
            [E::ONE; 2],
        ),
    ];
    let invalid = E::from_raw_coefficients_for_testing([F(u64::MAX), F::ZERO, F::ZERO, F::ZERO]);
    let noncanonical = [F(u64::MAX)];
    for swap in [false, true] {
        for mode in 0..5 {
            let mut batch = valid;
            if swap {
                batch.swap(0, 1);
            }
            batch[0].1[0] = batch[0].1[0].add(E::ONE);
            match mode {
                0 => batch[1].1[1] = invalid,
                1 => batch[1].2[0] = invalid,
                2 => batch[1].0 = MainMixedInputV1::Native(&noncanonical, &masks[1]),
                3 => batch[1].0 = MainMixedInputV1::Retained(&noncanonical),
                _ => batch[1].1[0] = batch[1].1[0].sub(E::ONE),
            }
            let mut weighted = MainMixedDeepQuotientV1::new_v1(&points).unwrap();
            assert_eq!(
                weighted.add_batch_v1(&points, &batch),
                Err(if mode == 4 {
                    ZkX509StarkErrorV1::ConstraintOpening
                } else {
                    ZkX509StarkErrorV1::ProfileMismatch
                })
            );
            unchanged(&weighted);
        }
    }
    let mut weighted = MainMixedDeepQuotientV1::new_v1(&points).unwrap();
    assert!(weighted.add_batch_v1(&points, &[]).is_err());
    let other = MainMixedDeepPointsV1::new_v1(3, extension(39), true, 310_494_720).unwrap();
    assert!(weighted.add_batch_v1(&other, &valid).is_err());
    unchanged(&weighted);
    weighted.add_batch_v1(&points, &valid).unwrap();
    let mut scratch = vec![E::ZERO; 1824].into_boxed_slice();
    assert!(weighted.accumulate_v1(2, 0, &mut scratch).is_err());
}

#[test]
fn combined_replay_budget_admits_exact_capacity_and_refuses_one_byte_short_before_allocations() {
    let n = 1usize << 19;
    let length = n + MASK_LENGTH;
    let expected = (n + 2 * MASK_LENGTH + (2 + 4 * SECURITY_LANES) * length)
        * core::mem::size_of::<E>()
        + BATCH * n * core::mem::size_of::<F>()
        + 32 * 1024;
    assert_eq!(
        MainMixedDeepPointsV1::forecast_v1(19, true).unwrap(),
        expected
    );
    assert!(
        expected
            < main_resources::MainProverBufferPlanV1::new_v1(
                &AggregateProofLayoutV1::for_full_profile_v1().unwrap()
            )
            .unwrap()
            .replay_batch
    );
    let (result, cleared) = observations::observe_v1(|| {
        MainMixedDeepPointsV1::new_v1(19, extension(71), true, expected - 1)
    });
    assert!(matches!(result, Err(ZkX509StarkErrorV1::ProofTooLarge)));
    assert!(cleared.is_empty());
    for log in [3, 8, 19] {
        let budget = MainMixedDeepPointsV1::forecast_v1(log, true).unwrap();
        let points = MainMixedDeepPointsV1::new_v1(log, extension(73), true, budget).unwrap();
        let weighted = MainMixedDeepQuotientV1::new_v1(&points).unwrap();
        let native: Vec<_> = (0..BATCH).map(|column| native(log, column)).collect();
        points
            .check_workspace_v1(
                core::slice::from_ref(&weighted),
                1,
                &native,
                native.capacity(),
            )
            .unwrap();
        assert!(
            points
                .check_workspace_v1(
                    core::slice::from_ref(&weighted),
                    2,
                    &native,
                    native.capacity()
                )
                .is_err()
        );
        assert!(
            points
                .check_workspace_v1(core::slice::from_ref(&weighted), 1, &native, BATCH + 1)
                .is_err()
        );
    }
}

#[test]
fn mixed_original_and_retained_owners_clear_on_success_error_and_unwind() {
    let (masks, coefficients) = originals(3, 2);
    let rows = native(3, 0);
    for mode in 0..3 {
        let (result, cleared) = observations::observe_v1(|| {
            std::panic::catch_unwind(|| {
                let points =
                    MainMixedDeepPointsV1::new_v1(3, extension(83), true, 310_494_720).unwrap();
                let mut weighted = MainMixedDeepQuotientV1::new_v1(&points).unwrap();
                let inputs = [
                    MainMixedInputV1::Native(&rows, &masks[0]),
                    MainMixedInputV1::Retained(&coefficients[1]),
                ];
                let batch =
                    inputs.map(|input| (input, points.evaluate_v1(input).unwrap(), [E::ONE; 2]));
                weighted.add_batch_v1(&points, &batch).unwrap();
                match mode {
                    0 => {
                        let mut result = zero_column_v1(8 + MASK_LENGTH).unwrap();
                        weighted.accumulate_v1(1, 1, &mut result)
                    }
                    1 => weighted.accumulate_v1(2, 0, &mut [E::ZERO; 1]),
                    _ => panic!("injected mixed DEEP unwind"),
                }
            })
        });
        match mode {
            0 => assert!(result.unwrap().is_ok()),
            1 => assert!(result.unwrap().is_err()),
            _ => assert!(result.is_err()),
        }
        // Native weights+mask powers, two coefficient-power arrays, four
        // weighted arrays, and the transient native inversion prefix.
        let expected = 2 * 8
            + 2 * MASK_LENGTH
            + 6 * (8 + MASK_LENGTH)
            + if mode == 0 { 8 + MASK_LENGTH } else { 0 };
        assert_eq!(cleared.iter().map(|entry| entry.0).sum::<usize>(), expected);
        assert!(cleared.iter().any(|entry| entry.1 > 0));
        assert!(cleared.iter().all(|entry| entry.2 == 0));
    }
}

#[test]
fn production_lane_constructor_matches_exact_workspace_and_preserves_capacity_refusals() {
    for retained in [false, true] {
        let points =
            MainMixedDeepPointsV1::new_v1(3, extension(97), retained, 310_494_720).unwrap();
        let lanes = MainMixedDeepQuotientV1::new_lanes_v1(&points).unwrap();
        assert_eq!(lanes.len(), SECURITY_LANES);
        assert_eq!(lanes.capacity(), SECURITY_LANES);
        points
            .check_workspace_v1(&lanes, lanes.capacity(), &[], 0)
            .unwrap();
        assert!(matches!(
            points.check_workspace_v1(&lanes, lanes.capacity() + 1, &[], 0),
            Err(ZkX509StarkErrorV1::ProfileMismatch)
        ));
        for lane in &lanes {
            assert_eq!(lane.native.columns, 0);
            assert_eq!(lane.retained.is_some(), retained);
            assert!(
                lane.native
                    .coefficients
                    .iter()
                    .flat_map(|c| c.iter())
                    .all(|&v| v == E::ZERO)
            );
        }
    }
}

#[test]
fn production_lane_constructor_clears_partial_error_and_dirty_owners_on_drop_and_unwind() {
    let length = 8 + MASK_LENGTH;
    for retained in [false, true] {
        let mut points =
            MainMixedDeepPointsV1::new_v1(3, extension(101), retained, 310_494_720).unwrap();
        points.native.allowance = 0;
        let (result, cleared) =
            observations::observe_v1(|| MainMixedDeepQuotientV1::new_lanes_v1(&points));
        assert!(matches!(result, Err(ZkX509StarkErrorV1::ProofTooLarge)));
        // The first native owner created its two clearing arrays before its
        // unchanged capacity check failed; no retained owner was constructed.
        assert_eq!(cleared.len(), 2);
        assert_eq!(cleared.iter().map(|row| row.0).sum::<usize>(), 2 * length);
        assert!(cleared.iter().all(|row| row.2 == 0));
        for unwind in [false, true] {
            let points =
                MainMixedDeepPointsV1::new_v1(3, extension(103), retained, 310_494_720).unwrap();
            let populated = std::cell::Cell::new(false);
            let (result, cleared) = observations::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut lanes = MainMixedDeepQuotientV1::new_lanes_v1(&points).unwrap();
                    for lane in &mut lanes {
                        for column in &mut lane.native.coefficients {
                            column.fill(E::ONE);
                        }
                        if let Some(owner) = &mut lane.retained {
                            for column in &mut owner.coefficients {
                                column.fill(E::ONE);
                            }
                        }
                    }
                    populated.set(true);
                    if unwind {
                        panic!("injected production lane unwind");
                    }
                }))
            });
            assert!(populated.get());
            assert_eq!(result.is_err(), unwind);
            let arrays = SECURITY_LANES * if retained { 4 } else { 2 };
            assert_eq!(cleared.len(), arrays);
            assert_eq!(
                cleared.iter().map(|row| row.0).sum::<usize>(),
                arrays * length
            );
            assert!(cleared.iter().all(|row| row.1 == length && row.2 == 0));
        }
    }
}
