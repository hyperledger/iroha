//! Independent interpolation, registration slicing and quotient controls.

use super::*;
use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;

#[test]
fn fixed_oods_matches_independent_ifft_and_rotated_polynomials() {
    let root = goldilocks_primitive_root_v1(3).unwrap();
    let native: Vec<[F; 2]> = (0..8).map(|row| [F(row * row + 3), F(19 - row)]).collect();
    for point in [E::canonical([3, 5, 7, 11]).unwrap(), E::from_base(F(7))] {
        let actual = fixed_rows_at_point_v1(3, 2, point, |row| Ok(native[row])).unwrap();
        let next =
            fixed_rows_at_point_v1(3, 2, point.mul_base(root), |row| Ok(native[row])).unwrap();
        for column in 0..2 {
            let mut coefficients = native.iter().map(|row| row[column]).collect::<Vec<_>>();
            goldilocks_ifft_v1(&mut coefficients, root).unwrap();
            let evaluate = |x| {
                coefficients
                    .iter()
                    .rev()
                    .fold(E::ZERO, |sum, value| sum.mul(x).add(E::from_base(*value)))
            };
            assert_eq!(actual[column], evaluate(point));
            assert_eq!(next[column], evaluate(point.mul_base(root)));
        }
    }
    assert!(lagrange_weights_v1(0, E::ONE).is_err());
    assert!(lagrange_weights_v1(20, E::ONE).is_err());
    assert!(lagrange_weights_v1(3, E::from_base(root)).is_err());
    let point = E::canonical([1, 2, 3, 4]).unwrap();
    assert!(fixed_rows_at_point_v1(3, 0, point, |_| Ok([F::ZERO; 2])).is_err());
    assert!(fixed_rows_at_point_v1(3, 2, point, |_| Ok([F::ZERO; 1])).is_err());
    assert!(fixed_rows_at_point_v1(3, 2, point, |_| Ok([F(GOLDILOCKS_MODULUS_V1); 2])).is_err());
}

#[test]
fn public_affine_oods_preserves_current_next_and_der_boundaries() {
    let schedule = MainLog19PublicFixedAffineScheduleV1 {
        segments: vec![MainLog19PublicFixedAffineSegmentV1 {
            column: 0,
            start: 3,
            end: 11,
            start_value: F(13),
            step: F(7),
        }],
    };
    let point = E::canonical([2, 3, 5, 7]).unwrap();
    let rows = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    let root = goldilocks_primitive_root_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1).unwrap();
    let actual = log19_public_at_point_v1(&schedule, point).unwrap();
    // Both independently checked openings travel together as one heap owner;
    // returning the pair must not materialize another large stack array.
    assert_eq!(
        core::mem::size_of_val(&actual),
        core::mem::size_of::<usize>()
    );
    assert_eq!(actual.len(), 2);
    for (shift, actual) in actual.iter().enumerate() {
        let x = point.mul_base(root.pow(shift as u128));
        let scale = x
            .pow(rows as u128)
            .sub(E::ONE)
            .mul_base(F(rows as u64).inv().unwrap());
        let lagrange = |row: usize| {
            let native = root.pow(row as u128);
            scale
                .mul_base(native)
                .mul(x.sub(E::from_base(native)).inv().unwrap())
        };
        let expected = (3..11).fold(E::ZERO, |sum, row| {
            sum.add(lagrange(row).mul_base(F(13 + 7 * (row as u64 - 3))))
        });
        assert_eq!(actual.rfc[0], expected);
        assert!(actual.rfc[1..].iter().all(|value| *value == E::ZERO));
        assert!(
            actual
                .sha_public
                .iter()
                .flatten()
                .all(|value| *value == E::ZERO)
        );
        assert_eq!(actual.der[FIX_FIRST_AGGREGATE], lagrange(0));
        assert_eq!(actual.der[FIX_LAST_AGGREGATE], lagrange(rows - 1));
        assert_eq!(
            actual.der[FIX_FIRST_COMPARATOR],
            lagrange(super::super::super::super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1)
        );
    }
    let malformed = MainLog19PublicFixedAffineScheduleV1 {
        segments: Vec::new(),
    };
    assert!(log19_public_at_point_v1(&malformed, point).is_err());
}

#[test]
fn all_main_oods_registration_slices_are_exact_and_bounded() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let groups = layout
        .trace_groups
        .iter()
        .enumerate()
        .map(|(group, shape)| {
            let values = |width: usize, kind: usize| {
                (0..width)
                    .map(|column| {
                        E::from_base(F((1 + group * 100_000 + kind * 10_000 + column) as u64))
                    })
                    .collect()
            };
            aggregate::AggregateOpenedDeepTraceGroupV1 {
                base_current: values(shape.base_width, 0),
                base_next: values(shape.base_width, 1),
                aux_current: values(shape.aux_width, 2),
                aux_next: values(shape.aux_width, 3),
            }
        })
        .collect::<Vec<_>>();
    for registration in &layout.registered_segments {
        let actual = opened_rows_v1(*registration, &groups).unwrap();
        assert_eq!(actual.base_current.len(), registration.segment.base_width);
        assert_eq!(actual.aux_next.len(), registration.segment.aux_width);
        assert_eq!(
            actual.base_current[0],
            E::from_base(F(
                (1 + registration.trace_group * 100_000 + registration.base_start) as u64
            ))
        );
        assert_eq!(
            actual.aux_next[0],
            E::from_base(F((1
                + registration.trace_group * 100_000
                + 30_000
                + registration.aux_start) as u64))
        );
        let mut malformed = *registration;
        malformed.trace_group = groups.len();
        assert!(opened_rows_v1(malformed, &groups).is_err());
        malformed = *registration;
        malformed.base_start = groups[registration.trace_group].base_current.len();
        assert!(opened_rows_v1(malformed, &groups).is_err());
    }
}

#[test]
fn mixed_native_quotients_and_every_composition_chunk_are_bound() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let shared = layout.as_shared().unwrap();
    let point = E::canonical([13, 17, 19, 23]).unwrap();
    let mut total = E::ZERO;
    for (index, registration) in layout.registered_segments.iter().enumerate() {
        let expected = E::canonical([index as u64 + 1, 2, 3, 4]).unwrap();
        let mut residues = vec![E::ZERO; registration.segment.constraint_count];
        let mut alphas = residues.clone();
        alphas[0] = E::ONE;
        residues[0] = expected.mul(
            point
                .pow(registration.segment.trace_size() as u128)
                .sub(E::ONE),
        );
        assert_eq!(
            quotient_v1(registration.segment, point, &residues, &alphas).unwrap(),
            expected
        );
        assert!(quotient_v1(registration.segment, point, &residues[1..], &alphas).is_err());
        total = total.add(expected);
    }
    let mut deep = aggregate::AggregateDeepProofV1 {
        trace_groups: Vec::new(),
        composition_values: vec![vec![[0; 4]; COMPOSITION_DEGREE_CHUNKS]],
    };
    deep.composition_values[0][0] = total.coefficients().map(|value| value.0);
    assert!(verify_composition_v1(&shared, &deep, point, total).is_ok());
    let degree =
        crate::privacy_engines::zk_x509::composition_masking::QuotientChunkGeometryV1::new_v1(
            &shared,
            AGGREGATE_PARAMETERS_V1,
        )
        .unwrap()
        .stride_v1();
    for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
        deep.composition_values[0][chunk][0] += 1;
        assert!(verify_composition_v1(&shared, &deep, point, total).is_err());
        let expected = total.add(point.pow((degree * chunk) as u128));
        assert!(verify_composition_v1(&shared, &deep, point, expected).is_ok());
        deep.composition_values[0][chunk][0] -= 1;
    }
    deep.composition_values[0].pop();
    assert!(verify_composition_v1(&shared, &deep, point, total).is_err());
    deep.composition_values.clear();
    assert!(verify_composition_v1(&shared, &deep, point, total).is_err());
}

fn native_value(value: E) -> F {
    let [base, x, y, z] = value.coefficients();
    assert_eq!([x, y, z], [F::ZERO; 3], "base-field embedding");
    base
}

/// The established scalar dispatch, independent of the typed Fp4 capability
/// enum and its registration/context routing. Fixed interpolation is separately
/// checked against IFFT/Horner; this reference isolates complete AIR dispatch.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn scalar_dispatch_residues(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_>,
    fixed: &[F],
    prepared: &MainDeepFixedV1,
    p256: &MainP256Log5VerifierConstraintSourceV1<'_>,
    projection: &MainProjectionVerifierConstraintSourceV1,
    io: &MainIoVerifierConstraintSourceV1,
    log19: &MainLog19VerifierConstraintSourceV1,
) -> Vec<F> {
    match registration.segment.adapter {
        SegmentAdapterIdV1::Projection => projection_constraint_residues_v1(
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            projection.challenges,
        )
        .unwrap(),
        SegmentAdapterIdV1::ByteMemory => io_constraint_residues_v1(
            registration.segment,
            io.fixed_schedule.logical_active_rows,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            io.challenges,
        )
        .unwrap(),
        SegmentAdapterIdV1::StrictDer => {
            crate::privacy_engines::zk_x509::der_stark::evaluate_zk_x509_der_stark_local_residues_v1(
                opening.base_current.try_into().unwrap(),
                opening.base_next.try_into().unwrap(),
                opening.aux_current.try_into().unwrap(),
                opening.aux_next.try_into().unwrap(),
                fixed.try_into().unwrap(),
                &prepared.public[1].der.map(native_value),
                log19.post_base.der(),
                log19.der_public,
            )
            .unwrap()
        }
        SegmentAdapterIdV1::Rfc5280 => evaluate_zk_x509_rfc5280_local_residues_v1(
            opening.base_current.try_into().unwrap(),
            opening.base_next.try_into().unwrap(),
            opening.aux_current.try_into().unwrap(),
            opening.aux_next.try_into().unwrap(),
            fixed.try_into().unwrap(),
            log19.post_base.der(),
            log19.post_base.rfc5280(),
        )
        .unwrap(),
        SegmentAdapterIdV1::Sha256CallBus => {
            let segment = usize::from(registration.segment.instance);
            let current = ZkX509ShaBatchRowV1 {
                base: opening.base_current.try_into().unwrap(),
                aux: opening.aux_current.try_into().unwrap(),
                fixed: prepared.sha_current[segment].map(native_value),
            };
            let next = ZkX509ShaBatchRowV1 {
                base: opening.base_next.try_into().unwrap(),
                aux: opening.aux_next.try_into().unwrap(),
                fixed: prepared.sha_next[segment].map(native_value),
            };
            evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
                &current,
                &next,
                log19.post_base.sha_word(),
                log19.post_base.sha(),
                log19.post_base.rfc5280(),
                segment as u8,
            )
            .unwrap()
        }
        _ => {
            let (_signature, _) = p256_instance_parts_v1(registration.segment.instance).unwrap();
            p256_opened_residues_v1(registration, opening, fixed, p256.challenges).unwrap()
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_49_main_oods_dispatches_match_scalar_relations_and_bind_each_registration() {
    use super::super::super::tests::{
        main_log19_statement_fixture_v1, p256_main_provider_post_base_fixture_v1,
    };

    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let shared = layout.as_shared().unwrap();
    assert_eq!(layout.registered_segments.len(), 49);
    // An admissible base embedding exercises all typed Fp4 paths while allowing
    // an independent comparison to existing native scalar relation dispatch.
    let x = (2_u64..100)
        .map(F)
        .find(|x| {
            aggregate::deep_point_is_admissible_v1(
                E::from_base(*x),
                AGGREGATE_PARAMETERS_V1,
                &shared,
            )
            .unwrap()
        })
        .unwrap();
    let point = E::from_base(x);
    let post_base = p256_main_provider_post_base_fixture_v1();
    let statement =
        crate::privacy_engines::zk_x509::main_io::tests::statement_with_disclosures_v1(0);
    let key_plan = main_key_joins::MainKeyJoinPlanV1::new_v1(
        &layout,
        &statement,
        ZkX509Rfc5280StarkShapeV1::from_statement(&main_log19_statement_fixture_v1()).unwrap(),
    )
    .unwrap();
    assert!(key_plan.admissible_v1(point, &shared).unwrap());
    let fixed_source = P256MainVerifierFixedSourceV1::new_v1().unwrap();
    let p256 =
        MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed_source, post_base)
            .unwrap();
    let projection =
        MainProjectionVerifierConstraintSourceV1::for_main_v1(&layout, &statement, post_base)
            .unwrap();
    let io = MainIoVerifierConstraintSourceV1::for_main_v1(&layout, &statement, post_base).unwrap();
    let mut log19 = MainLog19VerifierConstraintSourceV1::for_main_v1(
        &layout,
        &main_log19_statement_fixture_v1(),
        post_base,
    )
    .unwrap();
    // The production preparer compiles public fixed context without creating
    // query caches or accepting any proof-derived fixed values.
    log19.prepare_complete_oods_fixed_v1().unwrap();
    let prepared =
        prepare_main_deep_fixed_v1(&layout, point, &p256, &projection, &io, &log19).unwrap();
    let mut deep = aggregate::AggregateDeepProofV1 {
        trace_groups: layout
            .trace_groups
            .iter()
            .enumerate()
            .map(|(group, shape)| {
                let values = |width: usize, kind: usize| {
                    (0..width)
                        .map(|column| {
                            [
                                (3 + group * 100_000 + kind * 10_000 + column) as u64,
                                0,
                                0,
                                0,
                            ]
                        })
                        .collect()
                };
                aggregate::AggregateDeepTraceGroupOpeningV1 {
                    base_current: values(shape.base_width, 0),
                    base_next: values(shape.base_width, 1),
                    aux_current: values(shape.aux_width, 2),
                    aux_next: values(shape.aux_width, 3),
                }
            })
            .collect(),
        composition_values: vec![vec![[0; 4]; COMPOSITION_DEGREE_CHUNKS]],
    };
    let groups =
        aggregate::canonical_deep_trace_groups_v1(&deep, AGGREGATE_PARAMETERS_V1, &shared).unwrap();
    let mut alphas = layout
        .registered_segments
        .iter()
        .enumerate()
        .map(|(registration, shape)| {
            vec![
                (0..shape.segment.constraint_count)
                    .map(|column| {
                        E::canonical([
                            1 + registration as u64 * 3 + column as u64,
                            2 + column as u64,
                            3 + registration as u64,
                            5,
                        ])
                        .unwrap()
                    })
                    .collect::<Vec<_>>(),
            ]
        })
        .collect::<Vec<_>>();
    let mut expected = E::ZERO;
    let mut native_residues = Vec::new();
    for (index, registration) in layout.registered_segments.iter().copied().enumerate() {
        let opening = opened_rows_v1(registration, &groups).unwrap();
        let current = opening
            .base_current
            .iter()
            .copied()
            .map(native_value)
            .collect::<Vec<_>>();
        let next = opening
            .base_next
            .iter()
            .copied()
            .map(native_value)
            .collect::<Vec<_>>();
        let aux = opening
            .aux_current
            .iter()
            .copied()
            .map(native_value)
            .collect::<Vec<_>>();
        let aux_next = opening
            .aux_next
            .iter()
            .copied()
            .map(native_value)
            .collect::<Vec<_>>();
        let fixed = prepared.rows[index]
            .iter()
            .copied()
            .map(native_value)
            .collect::<Vec<_>>();
        let residues = scalar_dispatch_residues(
            registration,
            RegisteredOpenedRowsV1 {
                base_current: &current,
                base_next: &next,
                aux_current: &aux,
                aux_next: &aux_next,
            },
            &fixed,
            &prepared,
            &p256,
            &projection,
            &io,
            &log19,
        );
        assert_eq!(residues.len(), registration.segment.constraint_count);
        expected = expected.add(
            accumulator_quotient_value_v1(registration.segment, x, &residues, &alphas[index][0])
                .unwrap(),
        );
        native_residues.push(residues);
    }
    let evaluate = |alphas: &[Vec<Vec<E>>], p256: &MainP256Log5VerifierConstraintSourceV1<'_>| {
        main_deep_composition_v1(
            &layout,
            &groups,
            point,
            alphas,
            &[E::ONE; 192],
            p256,
            &projection,
            &io,
            &log19,
            &prepared,
        )
    };
    let expected = expected.add(
        main_terminal_links::MainTerminalLinkPlanV1::new_v1(&layout)
            .unwrap()
            .evaluate_v1(&groups, point, &[E::ONE; 192])
            .unwrap(),
    );
    assert_eq!(evaluate(&alphas, &p256).unwrap(), expected);
    // Include every key and digest relation with nonzero coefficients. The
    // scalar comparison above independently checks all 49 local registrations;
    // dedicated join controls check the key/digest algebra and owner mapping.
    let key_alphas: [E; main_key_joins::BLOCKS_V1] =
        core::array::from_fn(|i| E::canonical([i as u64 + 2, 3, 5, 7]).unwrap());
    let key_openings: [E; main_key_joins::OPENINGS_V1] =
        core::array::from_fn(|i| E::canonical([i as u64 + 11, 13, 17, 19]).unwrap());
    let key_contribution = key_plan
        .evaluate_v1(&groups, point, &key_openings, &key_alphas)
        .unwrap();
    assert_ne!(key_contribution, E::ZERO);
    let sha_union_plan = main_sha_union::MainShaUnionPlanV1::new_v1(&layout).unwrap();
    let sha_union_alphas: [E; main_sha_union::UNION_QUOTIENTS_V1] =
        core::array::from_fn(|i| E::canonical([i as u64 + 37, 41, 43, 47]).unwrap());
    let sha_union_contribution = sha_union_plan
        .evaluate_v1(&groups, point, &sha_union_alphas)
        .unwrap();
    assert_ne!(sha_union_contribution, E::ZERO);
    let complete_expected = expected.add(key_contribution).add(sha_union_contribution);
    // Nonzero higher chunks exercise reconstruction, rather than accepting a
    // sole constant composition opening.
    let power = point.pow(
        crate::privacy_engines::zk_x509::composition_masking::QuotientChunkGeometryV1::new_v1(
            &shared,
            AGGREGATE_PARAMETERS_V1,
        )
        .unwrap()
        .stride_v1() as u128,
    );
    let mut constant = complete_expected;
    for chunk in 1..COMPOSITION_DEGREE_CHUNKS {
        let value = E::canonical([chunk as u64 + 17, 19, 23, 29]).unwrap();
        deep.composition_values[0][chunk] = value.coefficients().map(|coefficient| coefficient.0);
        constant = constant.sub(value.mul(power.pow(chunk as u128)));
    }
    deep.composition_values[0][0] = constant.coefficients().map(|coefficient| coefficient.0);
    verify_main_deep_constraints_v1(
        &layout,
        &deep,
        point,
        &alphas,
        &[E::ONE; 192],
        &key_plan,
        &key_alphas,
        &key_openings,
        &sha_union_plan,
        &sha_union_alphas,
        &p256,
        &projection,
        &io,
        &log19,
    )
    .unwrap();

    // Every registration contributes a nonzero, independently computed native
    // quotient. Alter one mixing coefficient at a time without repeating fixed
    // preprocessing; neither a missing registration nor a wrong denominator
    // can silently pass the complete dispatch comparison.
    for (index, registration) in layout.registered_segments.iter().enumerate() {
        let (column, residue) = native_residues[index]
            .iter()
            .copied()
            .enumerate()
            .find(|(_, residue)| *residue != F::ZERO)
            .unwrap();
        alphas[index][0][column] = alphas[index][0][column].add(E::ONE);
        let delta = E::from_base(
            residue.mul(
                x.pow(registration.segment.trace_size() as u128)
                    .sub(F::ONE)
                    .inv()
                    .unwrap(),
            ),
        );
        let changed = evaluate(&alphas, &p256).unwrap();
        assert_eq!(changed, expected.add(delta), "registration {index}");
        assert!(
            verify_composition_v1(
                &shared,
                &deep,
                point,
                changed.add(key_contribution).add(sha_union_contribution)
            )
            .is_err()
        );
        alphas[index][0][column] = alphas[index][0][column].sub(E::ONE);
    }
    // Every join alpha and all 31 supplemental values affect the same complete
    // composition. Keep the independently checked local part fixed here.
    for block in 0..main_key_joins::BLOCKS_V1 {
        let mut changed = key_alphas;
        changed[block] = changed[block].add(E::ONE);
        let value = key_plan
            .evaluate_v1(&groups, point, &key_openings, &changed)
            .unwrap();
        assert_ne!(value, key_contribution, "join block {block}");
        assert!(
            verify_composition_v1(
                &shared,
                &deep,
                point,
                expected.add(value).add(sha_union_contribution)
            )
            .is_err()
        );
    }
    for opening in 0..main_key_joins::OPENINGS_V1 {
        let mut changed = key_openings;
        changed[opening] = changed[opening].add(E::ONE);
        let value = key_plan
            .evaluate_v1(&groups, point, &changed, &key_alphas)
            .unwrap();
        assert_ne!(value, key_contribution, "join opening {opening}");
        assert!(
            verify_composition_v1(
                &shared,
                &deep,
                point,
                expected.add(value).add(sha_union_contribution)
            )
            .is_err()
        );
    }
    for equation in 0..main_sha_union::UNION_QUOTIENTS_V1 {
        let mut changed = sha_union_alphas;
        changed[equation] = changed[equation].add(E::ONE);
        let value = sha_union_plan
            .evaluate_v1(&groups, point, &changed)
            .unwrap();
        assert_ne!(value, sha_union_contribution, "SHA union alpha {equation}");
        assert!(
            verify_composition_v1(
                &shared,
                &deep,
                point,
                expected.add(key_contribution).add(value)
            )
            .is_err()
        );
    }
    for (group, column) in sha_union_plan.source_coordinates_for_test_v1() {
        let mut changed = groups.clone();
        changed[group].aux_current[column] = changed[group].aux_current[column].add(E::ONE);
        let value = sha_union_plan
            .evaluate_v1(&changed, point, &sha_union_alphas)
            .unwrap();
        assert_ne!(
            value, sha_union_contribution,
            "SHA union source {group}/{column}"
        );
        assert!(
            verify_composition_v1(
                &shared,
                &deep,
                point,
                expected.add(key_contribution).add(value)
            )
            .is_err()
        );
    }
    // Private terminal mutations are exercised by the closed link-plan tests;
    // the verifier context no longer has private scalar claims to mutate.
    assert!(
        main_deep_composition_v1(
            &layout,
            &groups,
            point.add(E::ONE),
            &alphas,
            &[E::ONE; 192],
            &p256,
            &projection,
            &io,
            &log19,
            &prepared,
        )
        .is_err()
    );
    deep.trace_groups[0].base_current[0][0] = GOLDILOCKS_MODULUS_V1;
    assert!(
        verify_main_deep_constraints_v1(
            &layout,
            &deep,
            point,
            &alphas,
            &[E::ONE; 192],
            &key_plan,
            &key_alphas,
            &key_openings,
            &sha_union_plan,
            &sha_union_alphas,
            &p256,
            &projection,
            &io,
            &log19
        )
        .is_err()
    );
}

#[test]
#[ignore = "maximum public fixture: all 49 production fixed polynomials at a non-base OOD point"]
#[allow(clippy::too_many_lines)]
fn maximum_fixed_polynomials_match_verifier_at_extension_point_and_native_shifts() {
    use crate::privacy_engines::zk_x509::{
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };

    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum signed public credential fixture");
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .unwrap();
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    assert_eq!(layout.registered_segments.len(), 49);

    // Fixed-schedule parity needs one consistent bound native source, not a
    // Merkle/FRI proof. These test roots never claim authenticated commitments.
    let digest = |seed| PrivacyOuterDigestV1::from_bytes([seed; 48]);
    let pre_aux = ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
        [0x81; 32],
        assembly.verifier_profile.compiled_profile_digest,
        core::array::from_fn(|index| digest(index as u8 + 1)),
    );
    let binding = derive_zk_x509_credential_pre_aux_binding_v1(
        pre_aux,
        digest(0x91),
        digest(0xA1),
        digest(0xB1),
    )
    .unwrap();
    let sha = core::array::from_fn(|segment| {
        ZkX509ShaBatchSegmentBaseSourceV1::new_v1(
            &assembly.sha_schedule,
            &assembly.sha_witnesses,
            segment,
        )
        .unwrap()
    });
    let p256 = P256MainBaseSourceV1::new_v1(&assembly).unwrap();
    let bound = MainLog19BoundTraceGroupSourceV1::bind_from_phase_v1(
        &layout, &assembly, sha, p256, binding,
    )
    .unwrap();
    let post_base = binding.main_post_base();
    let fixed_source = P256MainVerifierFixedSourceV1::new_v1().unwrap();
    let verifier_p256 =
        MainP256Log5VerifierConstraintSourceV1::for_main_v1(&layout, &fixed_source, post_base)
            .unwrap();
    let projection = MainProjectionVerifierConstraintSourceV1::for_main_v1(
        &layout,
        &fixture.statement,
        post_base,
    )
    .unwrap();
    let io = MainIoVerifierConstraintSourceV1::for_main_v1(&layout, &fixture.statement, post_base)
        .unwrap();
    let mut log19 = MainLog19VerifierConstraintSourceV1::for_main_v1(
        &layout,
        &assembly.rfc_trace.statement,
        post_base,
    )
    .unwrap();
    log19.prepare_complete_oods_fixed_v1().unwrap();
    let point = E::canonical([13, 17, 19, 23]).unwrap();
    assert!(
        aggregate::deep_point_is_admissible_v1(
            point,
            AGGREGATE_PARAMETERS_V1,
            &layout.as_shared().unwrap(),
        )
        .unwrap()
    );
    let prepared =
        prepare_main_deep_fixed_v1(&layout, point, &verifier_p256, &projection, &io, &log19)
            .unwrap();
    let providers = [
        MainProverConstraintProviderV1::Log5(
            MainP256Log5ProverConstraintSourceV1::for_main_v1(&layout, &bound.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::P256Scalar(
            MainP256ScalarProverConstraintSourceV1::for_main_v1(&layout, &bound.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::Projection(
            MainProjectionProverConstraintSourceV1::for_main_v1(
                &layout,
                &fixture.statement,
                post_base,
            )
            .unwrap(),
        ),
        MainProverConstraintProviderV1::Log16(
            MainP256Log16ProverConstraintSourceV1::for_main_v1(&layout, &bound.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::Io(
            MainIoProverConstraintSourceV1::for_main_v1(
                &layout,
                &fixture.statement,
                &assembly.io,
                post_base,
            )
            .unwrap(),
        ),
        MainProverConstraintProviderV1::Log19(
            MainLog19ProverConstraintSourceV1::for_main_v1(&layout, &bound).unwrap(),
        ),
    ];
    let mut seen = vec![0_usize; layout.registered_segments.len()];
    let mut columns_checked = 0;
    let mut next_columns_checked = 0;
    for provider in &providers {
        let native_log = provider.native_trace_log2_v1();
        let next = point.mul_base(goldilocks_primitive_root_v1(native_log).unwrap());
        // Evaluate actual production coefficient vectors by scalar products
        // with powers. The verifier independently uses Lagrange weights and
        // algebraic schedules, so this is not a comparison to its own replay.
        let powers =
            main_deep_replay::MainDeepPointPowersV1::new_v1([point, next], 1_usize << native_log)
                .unwrap();
        stream_main_fixed_polynomial_sets_v1(provider, |set| {
            let registration = set.registration;
            let index = canonical_main_registration_index_v1(&layout, registration)?;
            assert_eq!(registration.segment.trace_log2, native_log);
            assert_eq!(set.columns.len(), prepared.rows[index].len());
            for (column, coefficients) in set.columns.iter().enumerate() {
                let [actual, shifted] = powers.evaluate_v1(coefficients)?;
                assert_eq!(
                    actual, prepared.rows[index][column],
                    "fixed OOD mismatch: registration={registration:?}, column={column}"
                );
                let expected_next = match registration.segment.adapter {
                    SegmentAdapterIdV1::StrictDer => Some(prepared.public[1].der[column]),
                    SegmentAdapterIdV1::Sha256CallBus => {
                        Some(prepared.sha_next[usize::from(registration.segment.instance)][column])
                    }
                    _ => None,
                };
                if let Some(expected) = expected_next {
                    assert_eq!(
                        shifted, expected,
                        "fixed next OOD mismatch: registration={registration:?}, column={column}"
                    );
                    next_columns_checked += 1;
                }
                columns_checked += 1;
            }
            seen[index] += 1;
            Ok(())
        })
        .unwrap();
    }
    assert!(seen.iter().all(|count| *count == 1), "{seen:?}");
    assert_eq!(
        columns_checked,
        layout
            .registered_segments
            .iter()
            .map(|row| row.segment.fixed_width)
            .sum::<usize>()
    );
    assert_eq!(
        next_columns_checked,
        layout
            .registered_segments
            .iter()
            .filter(|row| matches!(
                row.segment.adapter,
                SegmentAdapterIdV1::StrictDer | SegmentAdapterIdV1::Sha256CallBus
            ))
            .map(|row| row.segment.fixed_width)
            .sum::<usize>()
    );
    eprintln!(
        "fixed_oods_registrations=49 fixed_columns={columns_checked} shifted_columns={next_columns_checked}"
    );
}
