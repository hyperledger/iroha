//! Independent polynomial and ownership controls for grouped DEEP replay.

use super::*;

fn extension(seed: u64) -> E {
    E::from_coefficients([F(seed + 1), F(seed + 3), F(seed + 5), F(seed + 7)]).unwrap()
}

fn horner(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| {
            value.mul(point).add(E::from_base(coefficient))
        })
}

fn columns() -> Vec<Vec<F>> {
    [1, 2, 5, 17, 33]
        .into_iter()
        .enumerate()
        .map(|(column, length)| {
            (0..length)
                .map(|degree| F((3 + column * 19 + degree * degree * 11) as u64))
                .collect()
        })
        .collect()
}

#[test]
fn powers_match_independent_horner_at_distinct_native_points_and_long_mask_extent() {
    for native_log in [3, 8, 19] {
        let current = extension(13);
        let next = current.mul_base(goldilocks_primitive_root_v1(native_log).unwrap());
        let powers = MainDeepPointPowersV1::new_v1([current, next], MASK_DEGREE + 34).unwrap();
        let mut coefficients = vec![F::ZERO; MASK_DEGREE + 34];
        for (index, value) in coefficients.iter_mut().enumerate() {
            *value = F((index * index + 23) as u64);
        }
        assert_eq!(
            powers.evaluate_v1(&coefficients).unwrap(),
            [horner(&coefficients, current), horner(&coefficients, next)]
        );
        for coefficients in columns() {
            assert_eq!(
                powers.evaluate_v1(&coefficients).unwrap(),
                [horner(&coefficients, current), horner(&coefficients, next)]
            );
        }
    }
}

#[test]
fn grouped_division_matches_each_original_division_and_independent_polynomial_identity() {
    for native_log in [3, 8, 19] {
        let points = [
            extension(31),
            extension(31).mul_base(goldilocks_primitive_root_v1(native_log).unwrap()),
        ];
        let powers = MainDeepPointPowersV1::new_v1(points, 33).unwrap();
        let mut grouped = MainGroupedDeepQuotientV1::new_v1(&powers).unwrap();
        let mut original = vec![extension(43); 40];
        let initial = original.clone();
        let columns = columns();
        let mut inputs = Vec::new();
        for (index, coefficients) in columns.iter().enumerate() {
            let values = points.map(|point| horner(coefficients, point));
            let scales = [extension(index as u64 + 61), extension(index as u64 + 83)];
            grouped
                .add_v1(&powers, coefficients, values, scales)
                .unwrap();
            for lane in 0..2 {
                accumulate_base_deep_quotient_v1(
                    coefficients,
                    points[lane],
                    values[lane],
                    scales[lane],
                    &mut original,
                )
                .unwrap();
            }
            inputs.push((values, scales));
        }
        let mut actual = initial.clone();
        grouped.accumulate_v1(columns.len(), &mut actual).unwrap();
        assert_eq!(actual, original);
        for x in [extension(101), extension(117), E::from_base(F(23))] {
            let polynomial = actual
                .iter()
                .zip(&initial)
                .rev()
                .fold(E::ZERO, |value, (&after, &before)| {
                    value.mul(x).add(after.sub(before))
                });
            let expected = columns.iter().zip(&inputs).fold(
                E::ZERO,
                |sum, (coefficients, (values, scales))| {
                    (0..2).fold(sum, |sum, lane| {
                        sum.add(
                            horner(coefficients, x)
                                .sub(values[lane])
                                .mul(x.sub(points[lane]).inv().unwrap())
                                .mul(scales[lane]),
                        )
                    })
                },
            );
            assert_eq!(polynomial, expected);
        }
    }
}

#[test]
fn individual_claims_and_context_are_checked_before_weighted_mutation() {
    let points = [extension(17), extension(29)];
    let powers = MainDeepPointPowersV1::new_v1(points, 33).unwrap();
    let mut grouped = MainGroupedDeepQuotientV1::new_v1(&powers).unwrap();
    let coefficients = &columns()[4];
    let values = points.map(|point| horner(coefficients, point));
    let scales = [extension(41), extension(53)];
    for lane in 0..2 {
        let mut wrong = values;
        wrong[lane] = wrong[lane].add(E::ONE);
        assert!(matches!(
            grouped.add_v1(&powers, coefficients, wrong, scales),
            Err(ZkX509StarkErrorV1::ConstraintOpening)
        ));
    }
    // These errors would cancel if only the aggregate claim were checked.
    let mut wrong = values;
    wrong[0] = wrong[0].add(E::ONE);
    assert!(
        grouped
            .add_v1(&powers, coefficients, wrong, [E::ONE; 2])
            .is_err()
    );
    wrong[0] = values[0].sub(E::ONE);
    assert!(
        grouped
            .add_v1(&powers, coefficients, wrong, [E::ONE; 2])
            .is_err()
    );
    assert_eq!(grouped.columns, 0);
    assert!(
        grouped
            .coefficients
            .iter()
            .flat_map(|column| column.iter())
            .all(|value| *value == E::ZERO)
    );
    let other = MainDeepPointPowersV1::new_v1([points[1], points[0]], 33).unwrap();
    assert!(
        grouped
            .add_v1(&other, coefficients, values, scales)
            .is_err()
    );
    assert!(powers.evaluate_v1(&[]).is_err());
    assert!(powers.evaluate_v1(&[F::ZERO; 34]).is_err());
    assert!(powers.evaluate_v1(&[F(u64::MAX)]).is_err());
    assert!(MainDeepPointPowersV1::new_v1(points, 0).is_err());
    assert!(MainDeepPointPowersV1::new_v1(points, (1 << 19) + MASK_DEGREE + 2).is_err());
    assert!(MainDeepPointPowersV1::new_v1([E::ZERO, points[1]], 33).is_err());
    grouped
        .add_v1(&powers, coefficients, values, scales)
        .unwrap();
    assert!(grouped.accumulate_v1(2, &mut [E::ZERO; 40]).is_err());
}

#[test]
fn power_and_weighted_allocations_clear_live_cells_on_success_error_and_unwind() {
    for mode in 0..3 {
        let (result, cleared) = observations::observe_v1(|| {
            std::panic::catch_unwind(|| {
                let points = [extension(19), extension(37)];
                let powers = MainDeepPointPowersV1::new_v1(points, 33).unwrap();
                let mut grouped = MainGroupedDeepQuotientV1::new_v1(&powers).unwrap();
                let coefficients = &columns()[4];
                let values = points.map(|point| horner(coefficients, point));
                grouped
                    .add_v1(
                        &powers,
                        coefficients,
                        values,
                        [extension(61), extension(71)],
                    )
                    .unwrap();
                match mode {
                    0 => grouped.accumulate_v1(1, &mut [E::ZERO; 40]),
                    1 => grouped.accumulate_v1(1, &mut [E::ZERO; 2]),
                    _ => panic!("injected grouped DEEP unwind"),
                }
            })
        });
        match mode {
            0 => assert!(result.unwrap().is_ok()),
            1 => assert!(result.unwrap().is_err()),
            _ => assert!(result.is_err()),
        }
        assert_eq!(cleared.iter().map(|value| value.0).sum::<usize>(), 4 * 33);
        assert!(cleared.iter().map(|value| value.1).sum::<usize>() > 0);
        assert!(cleared.iter().all(|value| value.2 == 0));
    }
}

#[test]
#[ignore = "optimized eight-column native19 DEEP arithmetic diagnostic; run --release"]
fn native19_eight_column_deep_grouping_parity_and_timing() {
    use std::time::Instant;
    crate::test_support::require_no_debug_assertions("run this diagnostic with --release");
    let length = (1 << 19) + MASK_DEGREE + 1;
    let points = [
        extension(113),
        extension(113).mul_base(goldilocks_primitive_root_v1(19).unwrap()),
    ];
    let columns = (0..8)
        .map(|column| {
            ZeroizingMainTraceColumnV1(
                (0..length)
                    .map(|degree| {
                        F::reduce(
                            (degree as u128 + 3) * (degree as u128 + 7) + (column + 1) * 1_000_003,
                        )
                    })
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    let start = Instant::now();
    let original_values = columns
        .iter()
        .map(|coefficients| points.map(|point| horner(coefficients, point)))
        .collect::<Vec<_>>();
    let original_horner = start.elapsed();
    let start = Instant::now();
    let powers = MainDeepPointPowersV1::new_v1(points, length).unwrap();
    let power_setup = start.elapsed();
    let start = Instant::now();
    let values = columns
        .iter()
        .map(|coefficients| powers.evaluate_v1(coefficients).unwrap())
        .collect::<Vec<_>>();
    let dot_products = start.elapsed();
    assert_eq!(values, original_values);
    let mut original = zero_column_v1(length).unwrap();
    let start = Instant::now();
    for (column, coefficients) in columns.iter().enumerate() {
        for lane in 0..2 {
            accumulate_base_deep_quotient_v1(
                coefficients,
                points[lane],
                values[column][lane],
                extension((column * 2 + lane) as u64 + 127),
                &mut original,
            )
            .unwrap();
        }
    }
    let original_divisions = start.elapsed();
    let mut actual = zero_column_v1(length).unwrap();
    let start = Instant::now();
    let mut grouped = MainGroupedDeepQuotientV1::new_v1(&powers).unwrap();
    for (column, coefficients) in columns.iter().enumerate() {
        grouped
            .add_v1(
                &powers,
                coefficients,
                values[column],
                [
                    extension((column * 2) as u64 + 127),
                    extension((column * 2 + 1) as u64 + 127),
                ],
            )
            .unwrap();
    }
    grouped.accumulate_v1(columns.len(), &mut actual).unwrap();
    let grouped_divisions = start.elapsed();
    assert_eq!(&*actual, &*original);
    eprintln!(
        "native19 DEEP exact eight-column diagnostic: coefficients_per_column={length}, original_horner={original_horner:?}, power_setup={power_setup:?}, power_dot_products={dot_products:?}, original_divisions={original_divisions:?}, grouped_with_individual_checks={grouped_divisions:?}; no source replay/FFT/commitment/full-proof work included, shared host load must be recorded"
    );
}
