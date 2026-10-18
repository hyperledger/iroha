//! Native and adversarial controls of the same production window owner.
use super::super::super::private_table::inspection;
use super::inverse_window::{
    DENOMINATOR, GATE, InverseWindowV1, NEUTRAL, PAIRS, fill_with_v1, pairs_for_column_v1,
    step_window_v1,
};
pub(in super::super) use super::inverse_window::{fill_columns_v1, scratch_payload_bytes_v1};
use super::*;

fn challenges_v1() -> ZkX509Rfc5280StarkChallengesV1 {
    ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|slot| F(7 + (12 * lane + slot) as u64))
        }),
    }
}
fn der_v1() -> ZkX509DerStarkChallengesV1 {
    ZkX509DerStarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|slot| F(101 + (13 * lane + slot) as u64))
        }),
        byte_lookup: core::array::from_fn(|lane| F(301 + lane as u64)),
    }
}
fn row_v1() -> RowContextV1 {
    let mut row = RowContextV1 {
        base: [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1],
        fixed: [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1],
        family: ZkX509Rfc5280StarkFamilyV1::Padding,
    };
    row.base[BASE_DOCUMENT] = F(73);
    row
}

#[test]
fn private_inverse_window_preserves_zero_any_nonzero_gate_and_canonical_domain() {
    let modulus = crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
    let cases = [
        (F::ZERO, F::ZERO),
        (F::ZERO, F(u64::MAX)),
        (F::ZERO, F(modulus)),
        (F::ZERO, F(modulus + 1)),
        (F::ONE, F::ZERO),
        (F(2), F::ZERO),
        (F(u64::MAX), F::ZERO),
        (F::ONE, F::ONE),
        (F(2), F(2)),
        (F(modulus - 1), F(modulus - 1)),
        (F(u64::MAX), F(257)),
    ];
    for count in 1..=PAIRS {
        for shift in 0..cases.len() {
            let mut window = InverseWindowV1::new_v1();
            for index in 0..count {
                let (gate, denominator) = cases[(index + shift) % cases.len()];
                assert_eq!(window.collect_v1(gate, denominator), (F::ZERO, F::ZERO));
                assert_eq!(window.count, index + 1);
                assert_eq!(window.cursor, 0);
                assert_eq!(window.pairs[index][GATE], gate);
                assert_eq!(window.pairs[index][DENOMINATOR], denominator);
                assert_eq!(
                    window.pairs[index][NEUTRAL],
                    if gate == F::ZERO {
                        F::ZERO
                    } else {
                        denominator
                    }
                );
            }
            window.invert_v1();
            for index in 0..count {
                let (gate, denominator) = cases[(index + shift) % cases.len()];
                assert_eq!(
                    window.replay_v1(gate, denominator),
                    zero_safe_inverse_v1(gate, denominator)
                );
            }
            window.finish_v1();
        }
    }
    for gate in [F::ONE, F(2), F(u64::MAX)] {
        for denominator in [F(modulus), F(u64::MAX)] {
            assert!(std::panic::catch_unwind(|| zero_safe_inverse_v1(gate, denominator)).is_err());
            let (result, observed) = inspection::observe_v1(|| {
                std::panic::catch_unwind(|| {
                    let mut window = InverseWindowV1::new_v1();
                    window.collect_v1(F::ONE, F(19));
                    window.collect_v1(gate, denominator);
                })
            });
            assert!(result.is_err());
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
            assert!(
                observed
                    .iter()
                    .any(|item| item.cells == 8 && item.nonzero_before > 0)
            );
        }
    }
}

#[test]
fn private_inverse_window_all_widths_descriptors_and_resource_cells_match() {
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    for width in 1..=BATCH {
        for first in 0..=ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 - width {
            let pairs = (first..first + width)
                .map(pairs_for_column_v1)
                .sum::<usize>();
            assert!(pairs <= PAIRS);
            let mut expected = vec![vec![F(91); 3]; width];
            let mut actual = vec![vec![F(91); 3]; width];
            let mut expected_refs: Vec<_> = expected.iter_mut().map(Vec::as_mut_slice).collect();
            let mut actual_refs: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
            super::fill_with_v1(
                3,
                first,
                &mut expected_refs,
                der_v1(),
                &challenges_v1(),
                &centers,
                |_| Ok(row_v1()),
            )
            .unwrap();
            fill_with_v1(
                3,
                first,
                &mut actual_refs,
                der_v1(),
                &challenges_v1(),
                &centers,
                |_| Ok(row_v1()),
            )
            .unwrap();
            assert_eq!(actual, expected, "first{first} width{width}");
        }
    }
    assert_eq!((0..280).map(pairs_for_column_v1).sum::<usize>(), 304);
    assert_eq!(
        core::mem::size_of::<InverseWindowV1>(),
        (PAIRS * 8 + 4) * core::mem::size_of::<F>() + 2 * core::mem::size_of::<usize>()
    );
    assert_eq!(
        scratch_payload_bytes_v1() - super::scalar_scratch_payload_bytes_v1(),
        core::mem::size_of::<InverseWindowV1>() + 4 * core::mem::size_of::<F>()
    );
    assert!(scratch_payload_bytes_v1() < 8192);
}

#[test]
fn private_inverse_window_active_recurrences_and_numeric_validation_match() {
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    for family in [
        ZkX509Rfc5280StarkFamilyV1::SourceByte,
        ZkX509Rfc5280StarkFamilyV1::SourceNode,
        ZkX509Rfc5280StarkFamilyV1::FixedByte,
        ZkX509Rfc5280StarkFamilyV1::NameValue,
        ZkX509Rfc5280StarkFamilyV1::SerialSource,
    ] {
        for active in [F::ZERO, F::ONE, F(2)] {
            for last in [false, true] {
                let mut context = row_v1();
                context.family = family;
                context.base[BASE_ACTIVE] = active;
                context.fixed[family as usize] = F::ONE;
                for first in (0..280).step_by(BATCH) {
                    let count = (280 - first).min(BATCH);
                    let mut expected = [F::ZERO; BATCH];
                    let mut actual = vec![vec![F::ZERO; 1]; count];
                    let mut states: [ColumnStateV1; BATCH] =
                        core::array::from_fn(|_| ColumnStateV1 {
                            product: F(17),
                            sums: [F(19), F(23)],
                        });
                    let mut originals: [ColumnStateV1; BATCH] =
                        core::array::from_fn(|_| ColumnStateV1 {
                            product: F(17),
                            sums: [F(19), F(23)],
                        });
                    let mut reference = Ok(());
                    for offset in 0..count {
                        match originals[offset].step_v1(
                            first + offset,
                            &context,
                            last,
                            der_v1(),
                            &challenges_v1(),
                            &centers,
                        ) {
                            Ok(value) => expected[offset] = value,
                            Err(error) => {
                                reference = Err(error);
                                break;
                            }
                        }
                    }
                    let mut refs: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
                    let result = step_window_v1(
                        &mut states,
                        first,
                        &mut refs,
                        0,
                        &context,
                        last,
                        der_v1(),
                        &challenges_v1(),
                        &centers,
                    );
                    assert_eq!(
                        result, reference,
                        "first{first} active{active:?} family{family:?}"
                    );
                    if result.is_ok() {
                        for offset in 0..count {
                            assert_eq!(actual[offset][0], expected[offset]);
                            assert_eq!(states[offset].sums, originals[offset].sums);
                            assert_eq!(states[offset].product, originals[offset].product);
                        }
                    }
                }
            }
        }
    }
    for mutation in 0..5 {
        let mut event = numeric::NumericLookupEventV1 {
            source: F::ONE,
            query: F::ZERO,
            multiplicity: F::ONE,
            tuple: [F::ZERO; 12],
        };
        match mutation {
            0 => event.source = F(2),
            1 => event.query = F::ONE,
            2 => event.multiplicity = F(u64::MAX),
            3 => event.tuple[5] = F(u64::MAX),
            _ => {}
        }
        let mut scalar = [F::ZERO; 2];
        let mut candidate = [F::ZERO; 2];
        let mut calls = 0;
        let duplicate = numeric::NumericLookupEventV1 {
            source: event.source,
            query: event.query,
            multiplicity: event.multiplicity,
            tuple: event.tuple,
        };
        let expected = numeric_replay::step_v1(duplicate, &challenges_v1(), 0, &mut scalar);
        let actual = numeric_replay::step_with_inverse_v1(
            event,
            &challenges_v1(),
            0,
            &mut candidate,
            &mut |gate, factor| {
                calls += 1;
                zero_safe_inverse_v1(gate, factor)
            },
        );
        assert_eq!(actual, expected);
        assert_eq!(scalar, candidate);
        assert_eq!(calls, usize::from(mutation == 4));
    }
}

#[test]
fn private_inverse_window_clears_owned_pairs_outputs_and_state_on_failure_unwind_success() {
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    for unwind in [false, true] {
        let mut columns = vec![vec![F(91); 4]; BATCH];
        let mut refs: Vec<_> = columns.iter_mut().map(Vec::as_mut_slice).collect();
        let mut calls = 0;
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fill_with_v1(
                    4,
                    AUX_PROFILE_LOOKUP_ACCUMULATOR,
                    &mut refs,
                    der_v1(),
                    &challenges_v1(),
                    &centers,
                    |index| {
                        calls += 1;
                        if index == 2 {
                            assert!(!unwind, "synthetic late source unwind");
                            return Err(ZkX509Rfc5280StarkErrorV1::Source);
                        }
                        Ok(row_v1())
                    },
                )
            }))
        });
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(ZkX509Rfc5280StarkErrorV1::Source));
        }
        drop(refs);
        assert_eq!(calls, 3);
        assert!(columns.iter().flatten().all(|x| *x == F::ZERO));
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 8 && item.nonzero_before > 0)
        );
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 4 && item.nonzero_before > 0)
        );
    }
    let ((), observed) = inspection::observe_v1(|| {
        let mut window = InverseWindowV1::new_v1();
        for _ in 0..PAIRS {
            window.collect_v1(F(2), F(19));
        }
        window.invert_v1();
        for _ in 0..PAIRS {
            assert_eq!(
                window.replay_v1(F(2), F(19)),
                zero_safe_inverse_v1(F(2), F(19))
            );
        }
        window.finish_v1();
    });
    assert_eq!(
        observed
            .iter()
            .filter(|item| item.cells == 8 && item.nonzero_before > 0)
            .count(),
        PAIRS
    );
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
    for malformed in [0, 1, 2] {
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(|| {
                let mut window = InverseWindowV1::new_v1();
                window.collect_v1(F::ONE, F(19));
                window.invert_v1();
                match malformed {
                    0 => {
                        window.replay_v1(F::ONE, F(23));
                    }
                    1 => {
                        window.finish_v1();
                    }
                    _ => {
                        for _ in 0..PAIRS {
                            window.collect_v1(F::ONE, F(19));
                        }
                    }
                }
            })
        });
        assert!(result.is_err());
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn private_inverse_window_preserves_geometry_and_earliest_original_error() {
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    for (first, count, rows, actual_rows) in [
        (0, 0, 3, 3),
        (0, 9, 3, 3),
        (280, 1, 3, 3),
        (usize::MAX, 1, 3, 3),
        (279, 2, 3, 3),
        (0, 1, 0, 0),
        (0, 1, 3, 2),
    ] {
        let mut columns = vec![vec![F(91); actual_rows]; count];
        let mut refs: Vec<_> = columns.iter_mut().map(Vec::as_mut_slice).collect();
        assert_eq!(
            fill_with_v1(
                rows,
                first,
                &mut refs,
                der_v1(),
                &challenges_v1(),
                &centers,
                |_| panic!("invalid geometry before source")
            ),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        assert!(columns.iter().flatten().all(|value| *value == F(91)));
    }
    // The last output-role product precedes numeric columns in this window.
    // Both are malformed, but the original TerminalClaim must win before the
    // later numeric Semantic failure; both variants clear every output.
    for window in [false, true] {
        let mut columns = vec![vec![F(91); 1]; 8];
        let mut refs: Vec<_> = columns.iter_mut().map(Vec::as_mut_slice).collect();
        let row = |_| {
            let mut row = row_v1();
            row.base[BASE_ACTIVE] = F(2);
            row.base[BASE_NUMERIC_SOURCE] = F(2);
            let (role, consumer, _) = output_role_aux_column_descriptor_v1(260).unwrap();
            row.fixed[output_role_fixed_selector_column_v1(role, consumer)] = F::ONE;
            Ok(row)
        };
        let result = if window {
            fill_with_v1(1, 260, &mut refs, der_v1(), &challenges_v1(), &centers, row)
        } else {
            super::fill_with_v1(1, 260, &mut refs, der_v1(), &challenges_v1(), &centers, row)
        };
        assert_eq!(result, Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim));
        assert!(columns.iter().flatten().all(|value| *value == F::ZERO));
    }
}

#[test]
fn private_inverse_window_public_noninverse_spans_skip_window_owners() {
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    // Every admitted public span, including all mixed and constant-center boundaries.
    for width in 1..=BATCH {
        for first in 0..=ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 - width {
            let rows = 3;
            let mut actual = vec![vec![F(91); rows]; width];
            let mut expected = actual.clone();
            let mut expected_refs: Vec<_> = expected.iter_mut().map(Vec::as_mut_slice).collect();
            super::fill_with_v1(
                rows,
                first,
                &mut expected_refs,
                der_v1(),
                &challenges_v1(),
                &centers,
                |_| Ok(row_v1()),
            )
            .unwrap();
            let mut actual_refs: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
            let (result, observed) = inspection::observe_v1(|| {
                fill_with_v1(
                    rows,
                    first,
                    &mut actual_refs,
                    der_v1(),
                    &challenges_v1(),
                    &centers,
                    |_| Ok(row_v1()),
                )
            });
            result.unwrap();
            assert_eq!(actual, expected, "public first{first}");
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
            let pairs = (first..first + width)
                .map(pairs_for_column_v1)
                .sum::<usize>();
            let owned_pairs = observed.iter().filter(|item| item.cells == 8).count();
            assert_eq!(
                owned_pairs,
                if pairs == 0 { 0 } else { rows * PAIRS },
                "public first{first} width{width}"
            );
        }
    }
}
