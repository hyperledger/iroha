//! Closed MAIN/CA source mapping, full OODS algebra and ordered value binding.

use super::super::super::super::sha_call_bus_stark::{
    ZkX509ShaCallBusLaneChallengesV1, ZkX509ShaCallPublicShapeV1,
};
use super::*;

fn plan_v1() -> (AggregateProofLayoutV1, MainCaPrivatePlanV1) {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 4,
    })
    .unwrap();
    let challenges = ZkX509ShaCallBusChallengesV1 {
        lanes: core::array::from_fn(|lane| ZkX509ShaCallBusLaneChallengesV1 {
            terms: core::array::from_fn(|term| F((2 + lane * 7 + term) as u64)),
        }),
    };
    let plan = MainCaPrivatePlanV1::new_v1(&layout, &schedule, challenges).unwrap();
    (layout, plan)
}
fn transcript_v1() -> TransparentTranscriptV1 {
    TransparentTranscriptV1::new(
        ZK_X509_DIGEST_CONTEXT_V1,
        b"main-ca-source-test",
        &PrivacyOuterDigestV1::default(),
        &PrivacyOuterDigestV1::default(),
    )
    .unwrap()
}

#[test]
fn main_ca_mapping_uses_28_original_auxiliary_columns_and_24_exact_translates() {
    let (layout, plan) = plan_v1();
    let unique = plan
        .current
        .iter()
        .map(|source| (source.group, source.column))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 28);
    for (index, link) in plan.shared.links_v1().iter().enumerate() {
        let (adapter, instance, local) = match link.main {
            MainCaColumnV1::Sha { segment, column } => (
                SegmentAdapterIdV1::Sha256CallBus,
                u16::from(segment),
                usize::from(column),
            ),
            MainCaColumnV1::Rfc { column } => (SegmentAdapterIdV1::Rfc5280, 0, usize::from(column)),
        };
        let registered = layout.registered_segment(adapter, instance).unwrap();
        assert_eq!(plan.current[index].group, registered.trace_group);
        assert_eq!(plan.current[index].column, registered.aux_start + local);
        assert!(local < registered.segment.aux_width);
        assert_eq!(registered.segment.trace_log2, 19);
    }
    let point = E::canonical([31, 5, 17, 2]).unwrap();
    let values = [E::ONE; 24];
    let mixes = [E::from_base(F(19)); 24];
    let extras = plan.supplemental_v1(point, &values, &mixes).unwrap();
    assert_eq!(extras.len(), 24);
    assert_eq!(extras.capacity(), 24);
    assert_eq!(
        plan.extra
            .iter()
            .map(|c| (c.group, c.column))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        24
    );
    for (index, extra) in extras.iter().enumerate() {
        assert_eq!(extra.group, plan.extra[index].group);
        assert_eq!(
            extra.column,
            aggregate::AggregateSupplementalColumnV1::Auxiliary(plan.extra[index].column)
        );
        assert_eq!(
            extra.point,
            point.mul_base(plan.shared.main_openings_v1()[index].multiplier)
        );
        assert_eq!(extra.value, values[index]);
        assert_eq!(extra.mix, mixes[index]);
    }
    assert!(plan.supplemental_v1(point, &values[..23], &mixes).is_err());
    assert!(plan.supplemental_v1(point, &values, &mixes[..23]).is_err());
    assert!(plan.supplemental_v1(E::ONE, &values, &mixes).is_err());
}

#[test]
fn every_main_ca_quotient_binds_its_actual_current_auxiliary_opening() {
    let (layout, plan) = plan_v1();
    let groups = layout
        .trace_groups
        .iter()
        .map(|group| aggregate::AggregateOpenedDeepTraceGroupV1 {
            base_current: vec![E::ONE; group.base_width],
            base_next: vec![E::ONE; group.base_width],
            aux_current: vec![E::ONE; group.aux_width],
            aux_next: vec![E::ONE; group.aux_width],
        })
        .collect::<Vec<_>>();
    let point = E::canonical([31, 5, 17, 2]).unwrap();
    let starts = [E::ONE; 24];
    let ca: [E; 108] = core::array::from_fn(|index| {
        E::from_base(plan.shared.links_v1()[index].public_factor.inv().unwrap())
    });
    for equation in 0..108 {
        let mut alphas = [E::ZERO; 108];
        alphas[equation] = E::ONE;
        assert_eq!(
            plan.evaluate_v1(&groups, point, &alphas, &starts, &ca)
                .unwrap(),
            E::ZERO
        );
        let column = plan.current[equation];
        let mut changed = groups.clone();
        changed[column.group].aux_current[column.column] = E::from_base(F(2));
        let inverse = point
            .sub(E::from_base(plan.shared.links_v1()[equation].endpoint))
            .inv()
            .unwrap();
        assert_eq!(
            plan.evaluate_v1(&changed, point, &alphas, &starts, &ca)
                .unwrap(),
            inverse
        );
        assert!(plan.evaluate_v1(&[], point, &alphas, &starts, &ca).is_err());
    }
}

#[test]
fn main_ca_all_mapped_coordinates_and_all_ordered_values_bind_before_mixing() {
    let (_, plan) = plan_v1();
    let expected = plan.derive_alphas_v1(&mut transcript_v1()).unwrap();
    for index in 0..132 {
        for field in 0..2 {
            let mut changed = plan.clone();
            let target = if index < 108 {
                &mut changed.current[index]
            } else {
                &mut changed.extra[index - 108]
            };
            if field == 0 {
                target.group += 1;
            } else {
                target.column += 1;
            }
            assert_ne!(
                changed.derive_alphas_v1(&mut transcript_v1()).unwrap(),
                expected
            );
        }
    }
    let main = [E::ONE; 24];
    let ca = [E::ONE; 108];
    let derive = |main: &[E], ca: &[E]| {
        let mut transcript = transcript_v1();
        MainCaPrivatePlanV1::absorb_openings_v1(main, ca, &mut transcript).unwrap();
        MainCaPrivatePlanV1::derive_mixes_v1(&mut transcript).unwrap()
    };
    let expected = derive(&main, &ca);
    assert_eq!(expected.0.len(), 24);
    assert_eq!(expected.1.len(), 108);
    for index in 0..132 {
        let mut a = main;
        let mut b = ca;
        if index < 24 {
            a[index] = E::from_base(F(2));
        } else {
            b[index - 24] = E::from_base(F(2));
        }
        assert_ne!(derive(&a, &b), expected);
    }
    assert!(
        MainCaPrivatePlanV1::absorb_openings_v1(&main[..23], &ca, &mut transcript_v1()).is_err()
    );
    assert!(
        MainCaPrivatePlanV1::absorb_openings_v1(&main, &ca[..107], &mut transcript_v1()).is_err()
    );
}

#[test]
fn two_public_denominator_tables_cover_all_108_native_endpoints() {
    let (_, plan) = plan_v1();
    for ordinal in 0..2 {
        let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(19, 20, ordinal).unwrap();
        let table = CaEndpointDenominatorsV1::new_v1(stripe).unwrap();
        assert_eq!(table.values.len(), 1 << 19);
        assert_eq!(table.values.capacity(), 1 << 19);
        for (index, link) in plan.shared.links_v1().iter().enumerate() {
            assert_eq!(
                stripe.root.pow(plan.endpoint_rows[index] as u128),
                link.endpoint
            );
            for row in [0, 1, 17, 524_287] {
                let actual = link.endpoint.inv().unwrap().mul(
                    table.values
                        [(row + NATIVE_ROWS_V1 - plan.endpoint_rows[index]) % NATIVE_ROWS_V1],
                );
                let expected = stripe
                    .shift
                    .mul(stripe.root.pow(row as u128))
                    .sub(link.endpoint)
                    .inv()
                    .unwrap();
                assert_eq!(actual, expected);
            }
        }
        for field in 0..5 {
            let mut invalid = stripe;
            match field {
                0 => invalid.rows += 1,
                1 => invalid.count += 1,
                2 => invalid.next_stride += 1,
                3 => invalid.root = invalid.root.add(F::ONE),
                _ => invalid.shift = invalid.shift.add(F::ONE),
            }
            assert!(CaEndpointDenominatorsV1::new_v1(invalid).is_err());
        }
    }
    let expected = plan.derive_alphas_v1(&mut transcript_v1()).unwrap();
    for index in 0..108 {
        let mut changed = plan.clone();
        changed.endpoint_rows[index] += 1;
        assert_ne!(
            changed.derive_alphas_v1(&mut transcript_v1()).unwrap(),
            expected
        );
    }
}

#[test]
fn ca_link_replay_transform_degree_and_owner_census_is_source_derived() {
    let (_, plan) = plan_v1();
    let mut uses = std::collections::BTreeMap::new();
    for column in &plan.current {
        *uses.entry((column.group, column.column)).or_insert(0_usize) += 1;
    }
    assert_eq!(uses.len(), 28);
    assert_eq!(uses.values().sum::<usize>(), 108);
    assert_eq!(uses.values().filter(|count| **count == 1).count(), 4);
    assert_eq!(uses.values().filter(|count| **count == 3).count(), 8);
    assert_eq!(uses.values().filter(|count| **count == 5).count(), 16);
    assert_eq!(uses.values().map(|calls| calls + 2).max(), Some(7));
    assert_eq!(2 * uses.values().map(|calls| calls + 2).sum::<usize>(), 328);
    let retained = plan
        .extra
        .iter()
        .map(|column| (column.group, column.column))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(retained.len(), 24);
    assert_eq!(
        uses.keys()
            .filter(|column| !retained.contains(column))
            .count(),
        4
    );
    //24 retained originals,4 streamed RFC originals, no opening/DEEP source replay.
    assert_eq!(
        retained.len()
            + uses
                .keys()
                .filter(|column| !retained.contains(column))
                .count(),
        28
    );
    assert_eq!(MainCaPrivatePlanV1::COEFFICIENT_COUNT_V1, 526_104);
    assert_eq!(MainCaPrivatePlanV1::CA_COEFFICIENT_COUNT_V1, 6_196);
    assert_eq!(MainCaPrivatePlanV1::MAXIMUM_QUOTIENT_DEGREE_V1, 532_297);
    const {
        assert!(
            MainCaPrivatePlanV1::MAXIMUM_QUOTIENT_DEGREE_V1 < MainCaPrivatePlanV1::QUOTIENT_ROWS_V1
        )
    };
    assert_eq!(
        MainCaOriginalAuxiliaryV1::payload_bound_v1(),
        24 * (526_104 * 8 + core::mem::size_of::<Vec<F>>())
            + core::mem::size_of::<MainCaOriginalAuxiliaryV1>()
    );
    assert_eq!(
        MainCaPrivatePlanV1::quotient_private_bytes_v1(),
        109_074_624
    );
}

#[test]
fn retained_main_ca_coefficients_bind_deep_remainders_and_clear_owned_storage() {
    use super::super::super::super::private_table::inspection;
    let (layout, plan) = plan_v1();
    let mut columns = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1::<Vec<F>>);
    columns.try_reserve_exact(24).unwrap();
    for index in 0..24 {
        let mut column = Vec::new();
        column.try_reserve_exact(526_104).unwrap();
        column.resize(526_104, F::ZERO);
        column[0] = F(index as u64 + 3);
        column[1] = F(5);
        column[2] = F(7);
        columns.push(column);
    }
    let retained = MainCaOriginalAuxiliaryV1 {
        coordinates: plan.extra,
        columns,
    };
    retained.validate_v1(&plan).unwrap();
    assert!(format!("{retained:?}").contains("<original coefficients redacted>"));
    let point = E::canonical([31, 5, 17, 2]).unwrap();
    let values = plan.open_v1(&retained, point).unwrap();
    for (index, value) in values.iter().enumerate() {
        let target = point.mul_base(plan.shared.main_openings_v1()[index].multiplier);
        assert_eq!(
            *value,
            E::from_base(F(index as u64 + 3))
                .add(target.mul_base(F(5)))
                .add(target.mul(target).mul_base(F(7)))
        );
    }
    let mixes: [E; 24] = core::array::from_fn(|index| E::from_base(F(index as u64 + 13)));
    let policy =
        main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(&layout, 0).unwrap();
    let mut accumulator = vec![E::ZERO; 589_824];
    plan.accumulate_deep_v1(&retained, point, &values, &mixes, policy, &mut accumulator)
        .unwrap();
    let expected_constant = (0..24).fold(E::ZERO, |sum, index| {
        let target = point.mul_base(plan.shared.main_openings_v1()[index].multiplier);
        sum.add(
            E::from_base(F(5))
                .add(target.mul_base(F(7)))
                .mul(mixes[index]),
        )
    });
    assert_eq!(accumulator[0], expected_constant);
    assert_eq!(
        accumulator[1],
        mixes
            .iter()
            .fold(E::ZERO, |sum, mix| sum.add(mix.mul_base(F(7))))
    );
    assert!(accumulator[2..].iter().all(|value| *value == E::ZERO));
    let before = accumulator.clone();
    let mut changed = values;
    changed[0] = changed[0].add(E::ONE);
    assert!(
        plan.accumulate_deep_v1(&retained, point, &changed, &mixes, policy, &mut accumulator)
            .is_err()
    );
    assert_eq!(
        accumulator, before,
        "bad remainder must not publish any partial coefficient"
    );
    let mut changed_plan = plan.clone();
    changed_plan.extra.swap(0, 1);
    assert!(retained.validate_v1(&changed_plan).is_err());
    let ((), cleared) = inspection::observe_v1(|| drop(retained));
    assert_eq!(
        cleared.len(),
        1,
        "the table clears all columns as one owner"
    );
    assert_eq!(cleared[0].cells, 24 * 526_104);
    assert_eq!(cleared[0].nonzero_before, 24 * 3);
    assert_eq!(cleared[0].nonzero_after, 0);
}

#[test]
fn ca_low_degree_chunk_transfer_preserves_recomposition_and_rejects_atomically() {
    let (layout, _) = plan_v1();
    let shared = layout.as_shared().unwrap();
    let count = MainCaPrivatePlanV1::MAXIMUM_QUOTIENT_DEGREE_V1 + 1;
    let make = || {
        let mut values = Vec::new();
        values
            .try_reserve_exact(MainCaPrivatePlanV1::QUOTIENT_ROWS_V1)
            .unwrap();
        values.resize(MainCaPrivatePlanV1::QUOTIENT_ROWS_V1, E::ZERO);
        values[0] = E::from_base(F(7));
        values[91] = E::from_base(F(13));
        values[count - 1] = E::canonical([11, 3, 5, 17]).unwrap();
        ZeroizingExtensionColumnV1(values)
    };
    let initial: Vec<Vec<Vec<E>>> = vec![
        (0..6)
            .map(|index| vec![E::from_base(F(index + 19))])
            .collect(),
    ];
    let mut actual = initial.clone();
    MainCaPrivatePlanV1::add_original_first_chunk_v1(make(), &shared, &mut actual).unwrap();
    assert_eq!(actual[0][0].len(), count);
    assert_eq!(actual[0][0][0], E::from_base(F(26)));
    assert_eq!(actual[0][0][91], E::from_base(F(13)));
    assert_eq!(
        actual[0][0][count - 1],
        E::canonical([11, 3, 5, 17]).unwrap()
    );
    assert_eq!(&actual[0][1..], &initial[0][1..]);
    let geometry =
        super::super::super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
            &shared,
            AGGREGATE_PARAMETERS_V1,
        )
        .unwrap();
    for point in [E::from_base(F(7)), E::canonical([31, 5, 17, 2]).unwrap()] {
        let eval = |chunks: &[Vec<E>]| {
            chunks
                .iter()
                .enumerate()
                .fold(E::ZERO, |sum, (chunk, values)| {
                    let local = values
                        .iter()
                        .rev()
                        .fold(E::ZERO, |sum, coefficient| sum.mul(point).add(*coefficient));
                    sum.add(local.mul(point.pow((chunk * geometry.stride_v1()) as u128)))
                })
        };
        let expected = E::from_base(F(7)).add(point.pow(91).mul_base(F(13))).add(
            point
                .pow((count - 1) as u128)
                .mul(E::canonical([11, 3, 5, 17]).unwrap()),
        );
        assert_eq!(eval(&actual[0]).sub(eval(&initial[0])), expected);
    }
    for mutation in 0..6 {
        let mut candidate = initial.clone();
        let mut coefficients = make();
        match mutation {
            0 => coefficients.0[count] = E::ONE,
            1 => coefficients.0[MainCaPrivatePlanV1::QUOTIENT_ROWS_V1 - 1] = E::ONE,
            2 => {
                coefficients.0.pop();
            }
            3 => {
                candidate[0].pop();
            }
            4 => candidate.push(vec![]),
            5 => candidate[0][5] = vec![E::ZERO; 589_825],
            _ => unreachable!(),
        }
        let before = candidate.clone();
        assert!(
            MainCaPrivatePlanV1::add_original_first_chunk_v1(coefficients, &shared, &mut candidate)
                .is_err()
        );
        assert_eq!(
            candidate, before,
            "mutation {mutation} must not publish any coefficient"
        );
    }
}

#[test]
fn admitted_joint_point_uses_the_closed_original_ca_and_main_domain_exclusions() {
    let (_, plan) = plan_v1();
    for point in [
        E::ZERO,
        E::ONE,
        E::from_base(F(7)),
        E::canonical([19, 2, 3, 5]).unwrap(),
    ] {
        assert_eq!(
            plan.admissible_v1(point).unwrap(),
            plan.shared.admissible_v1(point).unwrap()
        );
    }
    assert!(!plan.admissible_v1(E::ZERO).unwrap());
    assert!(!plan.admissible_v1(E::ONE).unwrap());
    assert!(
        plan.admissible_v1(E::canonical([19, 2, 3, 5]).unwrap())
            .unwrap()
    );
}

#[test]
fn ca_original_coefficient_transfer_clears_full_initialized_allocation_on_success_and_error() {
    use super::super::super::super::private_table::inspection;
    let (layout, _) = plan_v1();
    let shared = layout.as_shared().unwrap();
    let rows = MainCaPrivatePlanV1::QUOTIENT_ROWS_V1;
    let count = MainCaPrivatePlanV1::MAXIMUM_QUOTIENT_DEGREE_V1 + 1;
    for outcome in 0..3 {
        let mut values = Vec::new();
        values.try_reserve_exact(rows).unwrap();
        values.resize(rows, E::ZERO);
        assert_eq!(values.len(), rows);
        assert_eq!(values.capacity(), rows);
        for index in [0, 91, count - 1] {
            values[index] = E::from_base(F(17));
        }
        if outcome == 1 {
            values[count] = E::ONE;
        }
        let coefficients = ZeroizingExtensionColumnV1(values);
        let mut accumulator = ZeroizingExtensionLanesV1::new(
            (0..SECURITY_LANES)
                .map(|_| (0..COMPOSITION_DEGREE_CHUNKS).map(|_| Vec::new()).collect())
                .collect(),
            zeroize_extension_lanes_v1,
        );
        // Reserve the destination before inspection so no displaced allocation
        // contributes to the census of the single original coefficient owner.
        accumulator[0][0].try_reserve_exact(count).unwrap();
        let address = accumulator[0][0].as_ptr();
        let capacity = accumulator[0][0].capacity();
        if outcome == 2 {
            accumulator[0].pop();
        }
        let (result, erased) = inspection::observe_v1(|| {
            MainCaPrivatePlanV1::add_original_first_chunk_v1(
                coefficients,
                &shared,
                &mut accumulator,
            )
        });
        assert_eq!(result.is_ok(), outcome == 0);
        assert_eq!(accumulator[0][0].as_ptr(), address);
        assert_eq!(accumulator[0][0].capacity(), capacity);
        assert_eq!(
            erased.iter().map(|record| record.cells).sum::<usize>(),
            rows
        );
        assert!(erased.iter().all(|record| record.nonzero_after == 0));
        let populated = erased
            .iter()
            .filter(|record| record.cells != 0)
            .collect::<Vec<_>>();
        if outcome == 1 {
            assert!(matches!(result, Err(ZkX509StarkErrorV1::ConstraintOpening)));
            assert_eq!(populated.len(), 1);
            assert_eq!(populated[0].cells, rows);
            assert_eq!(populated[0].nonzero_before, 4);
        } else {
            // Tail erasure happens while the original full-length owner is
            // alive; the same allocation's retained prefix clears on transfer Drop.
            assert_eq!(populated.len(), 2);
            assert_eq!(populated[0].cells, rows - count);
            assert_eq!(populated[0].nonzero_before, 0);
            assert_eq!(populated[1].cells, count);
            assert_eq!(populated[1].nonzero_before, 3);
        }
        if outcome == 0 {
            assert_eq!(accumulator[0][0].len(), count);
            for index in [0, 91, count - 1] {
                assert_eq!(accumulator[0][0][index], E::from_base(F(17)));
            }
            assert!(accumulator[0][1..].iter().all(Vec::is_empty));
        } else {
            assert!(accumulator.iter().flatten().all(Vec::is_empty));
        }
    }
}
