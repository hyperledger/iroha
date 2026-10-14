//! Source-plan, endpoint-algebra and public-denominator adversarial controls.

use super::*;

fn plan_v1() -> (AggregateProofLayoutV1, MainShaUnionPlanV1) {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = MainShaUnionPlanV1::new_v1(&layout).unwrap();
    (layout, plan)
}

#[test]
fn union_plan_uses_exact_existing_roles_streams_and_five_native_endpoints() {
    let (layout, plan) = plan_v1();
    let rfc = layout
        .registered_segment(SegmentAdapterIdV1::Rfc5280, 0)
        .unwrap();
    let root = goldilocks_primitive_root_v1(19).unwrap();
    let (bridge, consumers) = zk_x509_rfc_sha_union_columns_v1();
    assert_eq!(
        bridge,
        [
            [32, 33, 34, 35],
            [36, 37, 38, 39],
            [40, 41, 42, 43],
            [44, 45, 46, 47]
        ]
    );
    assert_eq!(
        consumers,
        [
            [204, 205, 206, 207],
            [212, 213, 214, 215],
            [220, 221, 222, 223],
            [244, 245, 246, 247]
        ]
    );
    let mut distinct = std::collections::BTreeSet::new();
    for segment in 0..4 {
        let sha = layout
            .registered_segment(SegmentAdapterIdV1::Sha256CallBus, segment as u16)
            .unwrap();
        for lane in 0..4 {
            assert_eq!(
                plan.bridges[segment][lane].column,
                rfc.aux_start + bridge[segment][lane]
            );
            assert_eq!(
                plan.consumers[segment][lane].column,
                rfc.aux_start + consumers[segment][lane]
            );
            for stream in 0..4 {
                let source = plan.streams[segment][stream][lane];
                assert_eq!(source.group, sha.trace_group);
                assert_eq!(source.column, sha.aux_start + 62 + 4 * stream + lane);
                assert!(distinct.insert((source.group, source.column)));
            }
        }
        assert_eq!(
            plan.points[segment],
            root.pow((ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[segment] - 1) as u128)
        );
    }
    assert_eq!(distinct.len(), 64);
    assert_eq!(plan.points[4], root.pow((NATIVE_ROWS_V1 - 1) as u128));
    assert!(
        plan.points
            .iter()
            .all(|point| point.pow(NATIVE_ROWS_V1 as u128) == F::ONE)
    );
    assert!(MainShaUnionPlanV1::public_owner_charge_v1() < 8192);
    let mut changed = layout;
    changed.registered_segments[0].segment.aux_width += 1;
    assert!(MainShaUnionPlanV1::new_v1(&changed).is_err());
}

#[test]
fn each_union_equation_binds_every_source_and_accepts_zero_products() {
    let (_, plan) = plan_v1();
    let z = E::canonical([31, 5, 17, 2]).unwrap();
    for equation in 0..UNION_QUOTIENTS_V1 {
        let mut alphas = [E::ZERO; UNION_QUOTIENTS_V1];
        alphas[equation] = E::ONE;
        assert_eq!(
            plan.evaluate_with_v1(z, &alphas, |_| Ok(E::ONE)).unwrap(),
            E::ZERO
        );
        assert_eq!(
            plan.evaluate_with_v1(z, &alphas, |_| Ok(E::ZERO)).unwrap(),
            E::ZERO
        );
        let (positive, negative, point) = if equation < 16 {
            let segment = equation / 4;
            let lane = equation % 4;
            (
                vec![plan.bridges[segment][lane]],
                (0..4)
                    .map(|stream| plan.streams[segment][stream][lane])
                    .collect::<Vec<_>>(),
                plan.points[segment],
            )
        } else {
            let lane = equation - 16;
            (
                (0..4)
                    .map(|index| plan.consumers[index][lane])
                    .collect::<Vec<_>>(),
                (0..4)
                    .map(|index| plan.bridges[index][lane])
                    .collect::<Vec<_>>(),
                plan.points[4],
            )
        };
        let inverse = z.sub(E::from_base(point)).inv().unwrap();
        for (sources, sign) in [(positive, E::ONE), (negative, E::ZERO.sub(E::ONE))] {
            for selected in sources {
                let actual = plan
                    .evaluate_with_v1(z, &alphas, |column| {
                        Ok(if column == selected {
                            E::from_base(F(2))
                        } else {
                            E::ONE
                        })
                    })
                    .unwrap();
                assert_eq!(
                    actual,
                    sign.mul(inverse),
                    "equation {equation}, source {selected:?}"
                );
            }
        }
    }
}

#[test]
fn union_openings_reject_wrong_counts_noncanonical_missing_and_singular_values() {
    let (_, plan) = plan_v1();
    let z = E::canonical([31, 5, 17, 2]).unwrap();
    let alphas = [E::ONE; UNION_QUOTIENTS_V1];
    for count in 0..UNION_QUOTIENTS_V1 {
        assert!(
            plan.evaluate_with_v1(z, &alphas[..count], |_| panic!("validated before access"))
                .is_err()
        );
    }
    let mut malformed = alphas;
    malformed[19] = E::from_raw_coefficients_for_testing([F(u64::MAX), F::ZERO, F::ZERO, F::ZERO]);
    assert!(
        plan.evaluate_with_v1(z, &malformed, |_| Ok(E::ONE))
            .is_err()
    );
    assert!(
        plan.evaluate_with_v1(
            E::from_raw_coefficients_for_testing([F(u64::MAX), F::ZERO, F::ZERO, F::ZERO]),
            &alphas,
            |_| Ok(E::ONE)
        )
        .is_err()
    );
    assert!(
        plan.evaluate_with_v1(z, &alphas, |_| Ok(E::from_raw_coefficients_for_testing([
            F(u64::MAX),
            F::ZERO,
            F::ZERO,
            F::ZERO
        ])))
        .is_err()
    );
    assert!(plan.evaluate_v1(&[], z, &alphas).is_err());
    for point in plan.points {
        assert!(
            plan.evaluate_with_v1(E::from_base(point), &alphas, |_| Ok(E::ONE))
                .is_err()
        );
    }
}

#[test]
fn union_transcript_binds_every_endpoint_and_ordered_source_coordinate() {
    let (_, plan) = plan_v1();
    let fresh = || {
        new_main_transcript_after_profile_validation_v1(TEST_PROOF_INSTANCE_V1, &[7; 32], [8; 32])
            .unwrap()
    };
    let expected = plan.derive_alphas_v1(&mut fresh()).unwrap();
    assert_eq!(expected.len(), UNION_QUOTIENTS_V1);
    assert_eq!(expected.capacity(), UNION_QUOTIENTS_V1);
    assert_eq!(expected, plan.derive_alphas_v1(&mut fresh()).unwrap());
    for index in 0..5 {
        let mut changed = plan.clone();
        changed.points[index] = changed.points[index].add(F::ONE);
        assert_ne!(expected, changed.derive_alphas_v1(&mut fresh()).unwrap());
    }
    for index in 0..96 {
        for coordinate in 0..2 {
            let mut changed = plan.clone();
            let target = if index < 16 {
                &mut changed.bridges[index / 4][index % 4]
            } else if index < 32 {
                &mut changed.consumers[(index - 16) / 4][index % 4]
            } else {
                &mut changed.streams[(index - 32) / 16][((index - 32) / 4) % 4][index % 4]
            };
            if coordinate == 0 {
                target.group += 1;
            } else {
                target.column += 1;
            }
            assert_ne!(expected, changed.derive_alphas_v1(&mut fresh()).unwrap());
        }
    }
    let mut swapped = plan.clone();
    swapped.streams.swap(0, 1);
    assert_ne!(expected, swapped.derive_alphas_v1(&mut fresh()).unwrap());
}

#[test]
fn one_public_inverse_table_matches_every_shifted_endpoint_directly() {
    for log in 3..=8 {
        let rows = 1_usize << log;
        let root = goldilocks_primitive_root_v1(log).unwrap();
        let points = [0, 1, rows / 2, rows - 2, rows - 1];
        for ordinal in 0..8 {
            let full_root = goldilocks_primitive_root_v1(log + 3).unwrap();
            let shift = F(7).mul(full_root.pow(ordinal));
            let table =
                ShaUnionEndpointDenominatorsV1::from_public_coset_v1(rows, root, shift, points)
                    .unwrap();
            assert_eq!(table.inverses.len(), rows);
            assert_eq!(table.inverses.capacity(), rows);
            let mut x = shift;
            for row in 0..rows {
                for (endpoint, native_row) in points.iter().enumerate() {
                    assert_eq!(
                        table.at_v1(endpoint, row).unwrap(),
                        x.sub(root.pow(*native_row as u128)).inv().unwrap()
                    );
                }
                x = x.mul(root);
            }
            assert!(table.at_v1(5, 0).is_err());
            assert!(table.at_v1(0, rows).is_err());
        }
    }
    let root = goldilocks_primitive_root_v1(3).unwrap();
    for shift in [F::ZERO, F::ONE, root, F(u64::MAX)] {
        assert!(
            ShaUnionEndpointDenominatorsV1::from_public_coset_v1(8, root, shift, [0; 5]).is_err()
        );
    }
    assert!(ShaUnionEndpointDenominatorsV1::from_public_coset_v1(8, root, F(7), [8; 5]).is_err());
    assert!(ShaUnionEndpointDenominatorsV1::from_public_coset_v1(8, F::ONE, F(7), [0; 5]).is_err());
}

#[test]
fn actual_stripe_inverse_plan_is_canonical_and_bounded() {
    let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(19, 22, 7).unwrap();
    let table = ShaUnionEndpointDenominatorsV1::new_v1(stripe).unwrap();
    assert_eq!(
        table.inverses.capacity() * core::mem::size_of::<F>() + core::mem::size_of_val(&table),
        ShaUnionEndpointDenominatorsV1::payload_charge_v1()
    );
    for row in [0, 1, 137, 480_287, 521_951, NATIVE_ROWS_V1 - 1] {
        let x = stripe.shift.mul(stripe.root.pow(row as u128));
        for endpoint in 0..5 {
            assert_eq!(
                table.at_v1(endpoint, row).unwrap(),
                x.sub(stripe.root.pow(table.endpoint_rows[endpoint] as u128))
                    .inv()
                    .unwrap()
            );
        }
    }
    for variant in 0..5 {
        let mut invalid = stripe;
        match variant {
            0 => invalid.rows /= 2,
            1 => invalid.root = F::ONE,
            2 => invalid.shift = F::ONE,
            3 => invalid.count *= 2,
            _ => invalid.next_stride += 1,
        }
        assert!(ShaUnionEndpointDenominatorsV1::new_v1(invalid).is_err());
    }
}

#[test]
fn centered_registration_contributions_recompose_and_cancel_each_private_center() {
    let (layout, plan) = plan_v1();
    let rows = 8;
    let root = goldilocks_primitive_root_v1(3).unwrap();
    let table =
        ShaUnionEndpointDenominatorsV1::from_public_coset_v1(rows, root, F(7), [0, 1, 2, 3, 7])
            .unwrap();
    let centers: [[F; 4]; 4] =
        core::array::from_fn(|s| core::array::from_fn(|l| F(3 + (s * 4 + l) as u64)));
    let alphas: [E; 20] = core::array::from_fn(|i| E::canonical([i as u64 + 1, 2, 3, 4]).unwrap());
    let rfc = layout
        .registered_segment(SegmentAdapterIdV1::Rfc5280, 0)
        .unwrap();
    let rfc_aux = vec![vec![F(19); rows]; rfc.segment.aux_width];
    for row in 0..rows {
        let rfc_value = plan
            .local_value_v1(rfc, row, &rfc_aux, &centers, &alphas, &table)
            .unwrap();
        let mut complete = rfc_value;
        let mut expected = E::ZERO;
        for segment in 0..4 {
            let sha = layout
                .registered_segment(SegmentAdapterIdV1::Sha256CallBus, segment as u16)
                .unwrap();
            let sha_aux = vec![vec![F(23 + segment as u64); rows]; sha.segment.aux_width];
            let actual = plan
                .local_value_v1(sha, row, &sha_aux, &centers, &alphas, &table)
                .unwrap();
            complete = complete.add(actual);
            for lane in 0..4 {
                expected = expected.add(
                    alphas[4 * segment + lane].mul_base(
                        F(19)
                            .sub(F(23 + segment as u64).pow(4))
                            .mul(table.at_v1(segment, row).unwrap()),
                    ),
                );
                let mut changed = centers;
                changed[segment][lane] = changed[segment][lane].add(F::ONE);
                let changed_rfc = plan
                    .local_value_v1(rfc, row, &rfc_aux, &changed, &alphas, &table)
                    .unwrap();
                let changed_sha = plan
                    .local_value_v1(sha, row, &sha_aux, &changed, &alphas, &table)
                    .unwrap();
                assert_ne!(changed_rfc, rfc_value);
                assert_ne!(changed_sha, actual);
                assert_eq!(changed_rfc.add(changed_sha), rfc_value.add(actual));
            }
        }
        assert_eq!(complete, expected);
    }
    assert!(
        plan.local_value_v1(rfc, 0, &rfc_aux, &centers, &alphas[..19], &table)
            .is_err()
    );
    assert!(
        plan.local_value_v1(rfc, rows, &rfc_aux, &centers, &alphas, &table)
            .is_err()
    );
    assert!(
        plan.local_value_v1(rfc, 0, &[], &centers, &alphas, &table)
            .is_err()
    );
    let wrong = layout
        .registered_segment(SegmentAdapterIdV1::StrictDer, 0)
        .unwrap();
    assert!(
        plan.local_value_v1(wrong, 0, &rfc_aux, &centers, &alphas, &table)
            .is_err()
    );
}

#[test]
fn lane_streamed_quartic_matches_dense_original_masks_and_atomic_chunk_sink() {
    fn mul(a: &[F], b: &[F]) -> Vec<F> {
        let mut result = vec![F::ZERO; a.len() + b.len() - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                result[i + j] = result[i + j].add(x.mul(*y));
            }
        }
        result
    }
    for log in 3..=5 {
        let n = 1_usize << log;
        let full_log = log + 3;
        let full_rows = 8 * n;
        let root = goldilocks_primitive_root_v1(log).unwrap();
        let full_root = goldilocks_primitive_root_v1(full_log).unwrap();
        let endpoint = root.pow((n - 1) as u128);
        // Each original column is its native constant plus (X^N-1)R(X).
        // Consumer constants are a permutation of bridge constants per lane.
        let coefficients: Vec<Vec<F>> = (0..32)
            .map(|index| {
                let mut c = vec![F::ZERO; n + 3];
                let lane = index % 4;
                let factor = if index < 16 {
                    index / 4
                } else {
                    3 - (index - 16) / 4
                };
                c[0] = F((lane * 5 + factor + 2) as u64);
                for power in 0..3 {
                    let mask = F((index * 13 + power + 1) as u64);
                    c[power] = c[power].sub(mask);
                    c[n + power] = c[n + power].add(mask);
                }
                c
            })
            .collect();
        let alphas: [E; 4] =
            core::array::from_fn(|lane| E::canonical([2 + lane as u64, 3, 5, 7]).unwrap());
        let mut dense = vec![E::ZERO; 4 * (n + 2)];
        for lane in 0..4 {
            let mut bridge = vec![F::ONE];
            let mut consumer = vec![F::ONE];
            for role in 0..4 {
                bridge = mul(&bridge, &coefficients[4 * role + lane]);
                consumer = mul(&consumer, &coefficients[16 + 4 * role + lane]);
            }
            let numerator: Vec<F> = consumer
                .iter()
                .zip(&bridge)
                .map(|(c, b)| c.sub(*b))
                .collect();
            let mut quotient = vec![F::ZERO; numerator.len() - 1];
            for degree in (1..numerator.len()).rev() {
                quotient[degree - 1] = numerator[degree].add(if degree < quotient.len() {
                    endpoint.mul(quotient[degree])
                } else {
                    F::ZERO
                });
            }
            assert_eq!(numerator[0].add(endpoint.mul(quotient[0])), F::ZERO);
            for (target, value) in dense.iter_mut().zip(quotient) {
                *target = target.add(alphas[lane].mul_base(value));
            }
        }
        let mut values = vec![E::ZERO; full_rows];
        for lane in 0..4 {
            for ordinal in 0..8 {
                let stripe = main_quotient_stripes::MainQuotientStripeV1 {
                    rows: n,
                    count: 8,
                    ordinal,
                    next_stride: 1,
                    root,
                    shift: F(7).mul(full_root.pow(ordinal as u128)),
                };
                let denominator = ShaUnionEndpointDenominatorsV1::from_public_coset_v1(
                    n,
                    root,
                    stripe.shift,
                    [n - 1; 5],
                )
                .unwrap();
                let mut products = [vec![F::ONE; n], vec![F::ONE; n]];
                for (index, source) in (0..4)
                    .map(|role| &coefficients[4 * role + lane])
                    .chain((0..4).map(|role| &coefficients[16 + 4 * role + lane]))
                    .enumerate()
                {
                    let evaluated = stripe.evaluate_v1(source).unwrap();
                    for row in 0..n {
                        let x = stripe.shift.mul(root.pow(row as u128));
                        let expected = source
                            .iter()
                            .rev()
                            .fold(F::ZERO, |value, c| value.mul(x).add(*c));
                        assert_eq!(evaluated[row], expected);
                        products[index / 4][row] = products[index / 4][row].mul(evaluated[row]);
                    }
                }
                for row in 0..n {
                    let at = ordinal + 8 * row;
                    values[at] = values[at].add(
                        alphas[lane].mul_base(
                            products[1][row]
                                .sub(products[0][row])
                                .mul(denominator.at_v1(4, row).unwrap()),
                        ),
                    );
                }
            }
        }
        let recovered = fp4_coset_coefficients_v1(&values, full_log).unwrap();
        assert_eq!(&recovered[..dense.len()], dense.as_slice());
        assert!(
            recovered[dense.len()..]
                .iter()
                .all(|value| *value == E::ZERO)
        );
        let layout = AggregateProofLayoutV1::for_full_profile_v1()
            .unwrap()
            .as_shared()
            .unwrap();
        let chunks =
            composition_coefficient_chunks_v1(&recovered, dense.len() - 1, &layout).unwrap();
        let cap = layout.fri_degree_cap(AGGREGATE_PARAMETERS_V1).unwrap();
        let mut accumulator = vec![vec![Vec::new(); COMPOSITION_DEGREE_CHUNKS]; SECURITY_LANES];
        add_main_composition_coefficient_chunks_v1(&mut accumulator, &[chunks.clone()], cap)
            .unwrap();
        assert_eq!(accumulator[0][0].as_slice(), &recovered[..]);
        assert_eq!(&accumulator[0][0][..dense.len()], dense.as_slice());
        assert!(
            accumulator[0][0][dense.len()..]
                .iter()
                .all(|value| *value == E::ZERO)
        );
        assert!(accumulator[0][1..].iter().all(Vec::is_empty));
        // A false final endpoint leaves a remainder and exceeds the declared
        // quotient degree; changing a mask tail also changes the real quotient.
        let mut bad_values = values;
        for (index, value) in bad_values.iter_mut().enumerate() {
            let x = F(7).mul(full_root.pow(index as u128));
            *value = value.add(E::from_base(x.sub(endpoint).inv().unwrap()));
        }
        let bad_coefficients = fp4_coset_coefficients_v1(&bad_values, full_log).unwrap();
        assert!(
            composition_coefficient_chunks_v1(&bad_coefficients, dense.len() - 1, &layout).is_err()
        );
        let before = accumulator.clone();
        let mut bad_chunks = chunks;
        bad_chunks[COMPOSITION_DEGREE_CHUNKS - 1] = vec![E::from_raw_coefficients_for_testing([
            F(u64::MAX),
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])];
        assert!(
            add_main_composition_coefficient_chunks_v1(&mut accumulator, &[bad_chunks], cap)
                .is_err()
        );
        assert_eq!(accumulator, before);
    }
}

#[test]
fn quartic_replay_degree_work_and_scoped_residency_fit_unchanged_limits() {
    let n = 1_usize << 19;
    assert_eq!(MainShaUnionPlanV1::COEFFICIENT_COUNT_V1, 526_104);
    assert_eq!(MainShaUnionPlanV1::UNION_DEGREE_V1, 2_104_411);
    assert!(MainShaUnionPlanV1::UNION_DEGREE_V1 < 2_155_224);
    assert_eq!(4 * 8, 32); // original columns generated and IFFT'd once
    assert_eq!(4 * 8 * 8, 256); // lanes, stripes, original columns
    assert_eq!(32 * (n / 2) * 19, 159_383_552);
    assert_eq!(256 * (n / 2) * 19, 1_275_068_416);
    assert_eq!(((1_usize << 22) / 2) * 22, 46_137_344);
    // Four RFC stripes plus eight stripes for each SHA registration, then
    // eight global stripes for each of four streamed compression lanes.
    assert_eq!(4 + 4 * 8 + 4 * 8, 68);
    assert_eq!(
        16 * (1_usize << 21) + 4 * 4 * (1_usize << 22) + 4 * (1_usize << 22),
        117_440_512
    );
    assert_eq!(MainShaUnionPlanV1::private_owner_charge_v1(), 268_444_160);
    let policy = main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(
        &AggregateProofLayoutV1::for_full_profile_v1().unwrap(),
        288_345_698,
    )
    .unwrap();
    assert!(
        policy
            .reserve_additional_v1(MainShaUnionPlanV1::private_owner_charge_v1())
            .is_ok()
    );
    assert_eq!(MainShaUnionPlanV1::public_owner_charge_v1(), 6_416);
}
