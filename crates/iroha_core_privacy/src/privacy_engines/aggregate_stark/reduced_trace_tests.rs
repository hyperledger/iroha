//! Exact reduced-row codec, ordered physical roots and fail-closed relation tests.

use super::tests::{
    DOMAINS, PARAMETERS, ZeroEvaluator, deep_fixture, fixture_with_parameters, transcript,
};
use super::*;

fn fixture(
    trace_layout: AggregateTraceLayoutV1,
    fri_layout: AggregateFriCommitmentLayoutV1,
) -> (
    AggregateProofLayoutV1,
    AggregateStarkProofV1,
    AggregateStarkParametersV1,
) {
    let parameters = AggregateStarkParametersV1 {
        fri_commitment_layout: fri_layout,
        ..PARAMETERS
    };
    let (_, mut proof, _, _) = fixture_with_parameters(parameters);
    let layout = AggregateProofLayoutV1::new_with_trace_layout_v1(
        parameters,
        vec![
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            },
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 2,
                aux_width: 2,
            },
        ],
        trace_layout,
    )
    .unwrap();
    for query in &mut proof.queries {
        let index = u64::from(query.index);
        query.trace_groups[0].base_next.clear();
        query.trace_groups[0].aux_next.clear();
        query.trace_groups.push(AggregateTraceGroupQueryV1 {
            base_current: vec![index + 10, index + 20],
            base_next: Vec::new(),
            aux_current: vec![index + 30, index + 40],
            aux_next: Vec::new(),
        });
    }
    let rows = layout.common_lde_size();
    let indices = composition_opening_indices_v1(&proof.queries, &layout).unwrap();
    proof.trace_groups.clear();
    for physical in 0..layout.trace_commitment_count_v1() {
        let tree = |base| {
            let leaves = (0..rows)
                .map(|index| {
                    let index_field = F(index as u64);
                    let mut values = vec![if base {
                        index_field
                    } else {
                        index_field.mul(F(3))
                    }];
                    let offset = if base { 10 } else { 30 };
                    let second = [F(index as u64 + offset), F(index as u64 + offset + 10)];
                    let group = if trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
                        values.extend(second);
                        JOINED_TRACE_GROUP_MARKER_V1
                    } else {
                        if physical == 1 {
                            values = second.to_vec();
                        }
                        physical
                    };
                    row_leaf_hash_v1(
                        DOMAINS.digest_context,
                        if base {
                            DOMAINS.base_leaf
                        } else {
                            DOMAINS.aux_leaf
                        },
                        group,
                        index,
                        &values,
                    )
                    .unwrap()
                })
                .collect();
            PrivacyOuterMerkleTreeV1::from_leaves(
                leaves,
                DOMAINS.digest_context,
                if base {
                    DOMAINS.base_node
                } else {
                    DOMAINS.aux_node
                },
            )
            .unwrap()
        };
        let base = tree(true);
        let aux = tree(false);
        proof.trace_groups.push(AggregateTraceGroupProofV1 {
            base_root: base.root(),
            aux_root: aux.root(),
            base_frontier: canonical_multiproof_frontier_v1(&base, rows, &indices).unwrap(),
            aux_frontier: canonical_multiproof_frontier_v1(&aux, rows, &indices).unwrap(),
        });
    }
    // Composition/FRI fixture leaves remain authenticated; this fixture does
    // not claim a valid relation or transcript for the substituted trace.
    (layout, proof, parameters)
}

#[test]
fn reduced_trace_codec_authenticates_exact_roots_slices_and_full_deep_payload() {
    for trace_layout in [
        AggregateTraceLayoutV1::GroupedCurrent,
        AggregateTraceLayoutV1::JoinedCurrent,
    ] {
        for fri_layout in [
            AggregateFriCommitmentLayoutV1::Scalar,
            AggregateFriCommitmentLayoutV1::Paired,
        ] {
            let (layout, proof, parameters) = fixture(trace_layout, fri_layout);
            let indices = proof
                .queries
                .iter()
                .map(|query| query.index as usize)
                .collect::<Vec<_>>();
            verify_all_merkle_openings_v1(&proof, parameters, &DOMAINS, &layout, &indices).unwrap();
            let deep = deep_fixture(&layout);
            let encoded = encode_proof_with_deep_v1(&proof, &deep, parameters, &layout).unwrap();
            assert_eq!(
                encoded.len(),
                maximum_encoded_proof_with_deep_bytes_v1(parameters, &layout).unwrap()
            );
            assert_eq!(
                decode_proof_with_deep_v1(&encoded, parameters, &layout).unwrap(),
                (proof.clone(), deep.clone())
            );
            let grouped =
                AggregateProofLayoutV1::new(parameters, layout.trace_groups.clone()).unwrap();
            assert_eq!(
                exact_deep_opening_bytes_v1(parameters, &layout).unwrap(),
                exact_deep_opening_bytes_v1(parameters, &grouped).unwrap()
            );
            assert!(decode_proof_with_deep_v1(&encoded, parameters, &grouped).is_err());
            assert_eq!(
                verify_opened_query_relations_v1(
                    &proof,
                    parameters,
                    &layout,
                    &indices,
                    &[],
                    &[],
                    &mut ZeroEvaluator
                ),
                Err(AggregateStarkErrorV1::ConstraintOpening)
            );
            assert_eq!(
                verify_opened_query_relations_with_deep_v1(
                    &proof,
                    &deep,
                    E::ONE,
                    &[],
                    parameters,
                    &layout,
                    &indices,
                    &[],
                    &[],
                    &mut ZeroEvaluator
                ),
                Err(AggregateStarkErrorV1::ConstraintOpening)
            );
            for field in 0..4 {
                let mut changed = proof.clone();
                if field < 2 {
                    changed.queries[0].trace_groups[field].base_current[0] += 1;
                } else {
                    changed.queries[0].trace_groups[field - 2].aux_current[0] += 1;
                }
                assert!(
                    verify_all_merkle_openings_v1(
                        &changed, parameters, &DOMAINS, &layout, &indices
                    )
                    .is_err()
                );
            }
            let mut changed = proof.clone();
            changed.queries[0].trace_groups[0].base_next.push(0);
            assert!(encode_proof_with_deep_v1(&changed, &deep, parameters, &layout).is_err());
            let mut omitted = deep.clone();
            omitted.trace_groups[0].base_next.clear();
            assert!(encode_proof_with_deep_v1(&proof, &omitted, parameters, &layout).is_err());
            let mut extra_root = proof.clone();
            extra_root.trace_groups.push(proof.trace_groups[0].clone());
            assert!(encode_proof_with_deep_v1(&extra_root, &deep, parameters, &layout).is_err());
            for length in [0, 7, encoded.len() - 1] {
                assert!(
                    decode_proof_with_deep_v1(&encoded[..length], parameters, &layout).is_err()
                );
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(decode_proof_with_deep_v1(&trailing, parameters, &layout).is_err());
        }
    }
}

#[test]
fn trace_layout_is_bound_before_roots_and_joined_scalar_savings_are_exact() {
    let (current, proof, parameters) = fixture(
        AggregateTraceLayoutV1::GroupedCurrent,
        AggregateFriCommitmentLayoutV1::Scalar,
    );
    let joined = AggregateProofLayoutV1::new_with_trace_layout_v1(
        parameters,
        current.trace_groups.clone(),
        AggregateTraceLayoutV1::JoinedCurrent,
    )
    .unwrap();
    let full = AggregateProofLayoutV1::new(parameters, current.trace_groups.clone()).unwrap();
    let state = |layout| {
        let mut transcript = transcript();
        absorb_layout_v1(
            &mut transcript,
            parameters,
            &DOMAINS,
            b"layout-separation-test",
            layout,
        )
        .unwrap();
        transcript.state()
    };
    assert_ne!(state(&full), state(&current));
    assert_ne!(state(&current), state(&joined));
    let before = maximum_encoded_proof_with_deep_bytes_v1(parameters, &full).unwrap();
    let middle = maximum_encoded_proof_with_deep_bytes_v1(parameters, &current).unwrap();
    let after = maximum_encoded_proof_with_deep_bytes_v1(parameters, &joined).unwrap();
    let q = parameters.query_count;
    let frontier =
        |opened| maximum_multiproof_frontier_len_v1(full.common_lde_size(), opened).unwrap();
    assert_eq!(
        before - middle,
        q * 6 * 8 + 4 * (frontier(2 * q) - frontier(q)) * PRIVACY_OUTER_DIGEST_BYTES_V1
    );
    assert_eq!(
        middle - after,
        2 * (frontier(q) + 1) * PRIVACY_OUTER_DIGEST_BYTES_V1
    );
    // Scalar FRI continues disclosing both pair members; trace compression
    // must not accidentally halve its frontier accounting.
    let indices = proof
        .queries
        .iter()
        .map(|query| query.index as usize)
        .collect::<Vec<_>>();
    verify_all_merkle_openings_v1(&proof, parameters, &DOMAINS, &current, &indices).unwrap();
}

#[test]
fn complete_oods_current_rows_bind_both_deep_points_through_real_fri() {
    complete_oods_fixture_with_supplemental_v1(None);
}

#[test]
fn supplemental_openings_of_nonconstant_columns_bind_through_real_fri() {
    complete_oods_fixture_with_supplemental_v1(Some(AggregateSupplementalColumnV1::Base(0)));
}

#[test]
fn supplemental_openings_of_original_auxiliary_columns_bind_through_real_fri() {
    complete_oods_fixture_with_supplemental_v1(Some(AggregateSupplementalColumnV1::Auxiliary(0)));
}

fn complete_oods_fixture_with_supplemental_v1(selected: Option<AggregateSupplementalColumnV1>) {
    let with_supplemental = selected.is_some();
    use rand::{SeedableRng as _, rngs::StdRng};
    for trace_layout in [
        AggregateTraceLayoutV1::GroupedCurrent,
        AggregateTraceLayoutV1::JoinedCurrent,
    ] {
        let parameters = AggregateStarkParametersV1 {
            fri_commitment_layout: AggregateFriCommitmentLayoutV1::Paired,
            security_lanes: if with_supplemental {
                1
            } else {
                PARAMETERS.security_lanes
            },
            ..PARAMETERS
        };
        let groups = vec![AggregateTraceGroupLayoutV1 {
            native_trace_log2: 8,
            segment_instances: 1,
            base_width: 1,
            aux_width: 1,
        }];
        let layout = AggregateProofLayoutV1::new_with_trace_layout_v1(
            parameters,
            groups.clone(),
            trace_layout,
        )
        .unwrap();
        let grouped = AggregateProofLayoutV1::new_with_trace_layout_v1(
            parameters,
            groups,
            AggregateTraceLayoutV1::GroupedCurrent,
        )
        .unwrap();
        let rows = layout.common_lde_size();
        let group_marker = if trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
            JOINED_TRACE_GROUP_MARKER_V1
        } else {
            0
        };
        let domain_root = goldilocks_primitive_root_v1(layout.common_lde_log2).unwrap();
        let base_polynomial = |point: E| {
            if selected == Some(AggregateSupplementalColumnV1::Base(0)) {
                E::from_base(F(7))
                    .add(point.mul_base(F(13)))
                    .add(point.mul(point).mul_base(F(17)))
            } else {
                E::from_base(F(7))
            }
        };
        let base = vec![
            (0..rows)
                .map(|index| {
                    let x = F(GOLDILOCKS_GENERATOR_V1).mul(domain_root.pow(index as u128));
                    base_polynomial(E::from_base(x)).coefficients()[0]
                })
                .collect::<Vec<_>>(),
        ];
        let aux_polynomial = |point: E| {
            if selected == Some(AggregateSupplementalColumnV1::Auxiliary(0)) {
                E::from_base(F(11))
                    .add(point.mul_base(F(19)))
                    .add(point.mul(point).mul_base(F(23)))
            } else {
                E::from_base(F(11))
            }
        };
        let aux = vec![
            (0..rows)
                .map(|index| {
                    let x = F(GOLDILOCKS_GENERATOR_V1).mul(domain_root.pow(index as u128));
                    aux_polynomial(E::from_base(x)).coefficients()[0]
                })
                .collect::<Vec<_>>(),
        ];
        let material = vec![AggregateTraceGroupMaterialV1 {
            base_tree: row_tree_v1(
                DOMAINS.digest_context,
                DOMAINS.base_leaf,
                DOMAINS.base_node,
                group_marker,
                &base,
                rows,
            )
            .unwrap(),
            aux_tree: row_tree_v1(
                DOMAINS.digest_context,
                DOMAINS.aux_leaf,
                DOMAINS.aux_node,
                group_marker,
                &aux,
                rows,
            )
            .unwrap(),
            base_lde: base,
            aux_lde: aux,
        }];
        let mut trace_groups = vec![AggregateTraceGroupProofV1 {
            base_root: material[0].base_tree.root(),
            aux_root: material[0].aux_tree.root(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }];
        let compositions = vec![
            vec![vec![E::ZERO; rows]; parameters.composition_degree_chunks];
            parameters.security_lanes
        ];
        let trees = compositions
            .iter()
            .enumerate()
            .map(|(lane, values)| composition_tree_v1(&DOMAINS, lane, values).unwrap())
            .collect::<Vec<_>>();
        let composition_roots = trees
            .iter()
            .map(PrivacyOuterMerkleTreeV1::root)
            .collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(0x44_45_45_50);
        let masks = build_fri_mask_oracles_v1(parameters, &DOMAINS, &layout, &mut rng).unwrap();
        let fri_mask_roots = masks
            .iter()
            .map(|mask| mask.tree.root())
            .collect::<Vec<_>>();
        let mut transcript = transcript();
        absorb_layout_v1(
            &mut transcript,
            parameters,
            &DOMAINS,
            b"complete-oods-fixture",
            &layout,
        )
        .unwrap();
        absorb_base_roots_v1(&mut transcript, &DOMAINS, &trace_groups).unwrap();
        absorb_aux_roots_v1(&mut transcript, &DOMAINS, &trace_groups).unwrap();
        absorb_composition_roots_v1(&mut transcript, parameters, &DOMAINS, &composition_roots)
            .unwrap();
        absorb_fri_mask_roots_v1(&mut transcript, parameters, &DOMAINS, &fri_mask_roots).unwrap();
        let point = derive_deep_point_v1(&mut transcript, parameters, &layout).unwrap();
        let deep = AggregateDeepProofV1 {
            trace_groups: vec![AggregateDeepTraceGroupOpeningV1 {
                base_current: vec![base_polynomial(point).coefficients().map(F::value)],
                base_next: vec![
                    base_polynomial(point.mul_base(goldilocks_primitive_root_v1(8).unwrap()))
                        .coefficients()
                        .map(F::value),
                ],
                aux_current: vec![aux_polynomial(point).coefficients().map(F::value)],
                aux_next: vec![
                    aux_polynomial(point.mul_base(goldilocks_primitive_root_v1(8).unwrap()))
                        .coefficients()
                        .map(F::value),
                ],
            }],
            composition_values: vec![
                vec![[0; 4]; parameters.composition_degree_chunks];
                parameters.security_lanes
            ],
        };
        absorb_deep_openings_v1(&mut transcript, &deep, parameters, &layout).unwrap();
        let supplemental = if with_supplemental {
            let target = point.pow(2).mul_base(F(13));
            assert!(deep_point_is_admissible_v1(target, parameters, &layout).unwrap());
            let (column, family, value) = match selected.unwrap() {
                AggregateSupplementalColumnV1::Base(index) => (
                    AggregateSupplementalColumnV1::Base(index),
                    0_u8,
                    base_polynomial(target),
                ),
                AggregateSupplementalColumnV1::Auxiliary(index) => (
                    AggregateSupplementalColumnV1::Auxiliary(index),
                    1_u8,
                    aux_polynomial(target),
                ),
            };
            transcript
                .absorb(
                    b"public-test-supplemental-values",
                    &[
                        &[family],
                        &0_u64.to_be_bytes(),
                        &target.to_be_bytes(),
                        &value.to_be_bytes(),
                    ],
                )
                .unwrap();
            let mix = transcript
                .challenge_fp4(b"public-test-supplemental-mix")
                .unwrap();
            vec![AggregateSupplementalDeepOpeningV1 {
                group: 0,
                column,
                point: target,
                value,
                mix,
            }]
        } else {
            Vec::new()
        };

        // Only the selected original commitment family is nonconstant. The
        // independent closed divided-difference polynomial below binds that
        // family's current, next and supplemental openings through real FRI.
        let mixes = vec![
            AggregateDeepLaneMixV1 {
                trace_groups: vec![AggregateDeepTraceGroupMixV1 {
                    base_current: vec![E::from_base(F(2))],
                    base_next: vec![E::from_base(F(3))],
                    aux_current: vec![E::from_base(F(5))],
                    aux_next: vec![E::from_base(F(7))],
                }],
                composition: vec![E::ONE; parameters.composition_degree_chunks]
            };
            parameters.security_lanes
        ];
        let mut verifier_transcript = transcript.clone();
        let lanes = masks
            .iter()
            .enumerate()
            .map(|(lane, mask)| {
                build_fri_lane_v1(
                    parameters,
                    &DOMAINS,
                    &layout,
                    lane,
                    if with_supplemental {
                        mask.evaluations
                            .iter()
                            .enumerate()
                            .map(|(index, masked)| {
                                let x = E::from_base(
                                    F(GOLDILOCKS_GENERATOR_V1).mul(domain_root.pow(index as u128)),
                                );
                                // For P(X)=a+bX+cX², the divided difference is
                                // b+c(X+t). This independent polynomial never
                                // calls the verifier quotient helper.
                                let (linear, quadratic, current_mix, next_mix) = match selected
                                    .unwrap()
                                {
                                    AggregateSupplementalColumnV1::Base(_) => (13, 17, 2, 3),
                                    AggregateSupplementalColumnV1::Auxiliary(_) => (19, 23, 5, 7),
                                };
                                let divided = |t| {
                                    E::from_base(F(linear)).add(x.add(t).mul_base(F(quadratic)))
                                };
                                masked
                                    .add(divided(point).mul_base(F(current_mix)))
                                    .add(
                                        divided(
                                            point
                                                .mul_base(goldilocks_primitive_root_v1(8).unwrap()),
                                        )
                                        .mul_base(F(next_mix)),
                                    )
                                    .add(divided(supplemental[0].point).mul(supplemental[0].mix))
                            })
                            .collect()
                    } else {
                        mask.evaluations.clone()
                    },
                    &mut transcript,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let indices = query_indices_v1(&transcript, parameters, &DOMAINS, &layout).unwrap();
        // The materialized current-row assembler is identical for one logical
        // group; the tree already carries the selected layout's leaf marker.
        let queries = indices
            .iter()
            .map(|&index| {
                build_query_v1(
                    parameters,
                    &grouped,
                    index,
                    &material,
                    &compositions,
                    &masks,
                    &lanes,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let (trace, composition_frontiers, fri_mask_frontiers, frontiers) = build_all_frontiers_v1(
            parameters, &grouped, &queries, &material, &trees, &masks, &lanes,
        )
        .unwrap();
        for (group, (base, aux)) in trace_groups.iter_mut().zip(trace) {
            group.base_frontier = base;
            group.aux_frontier = aux;
        }
        let proof = AggregateStarkProofV1 {
            version: parameters.proof_version,
            trace_groups,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes: lanes
                .into_iter()
                .zip(frontiers)
                .map(|(lane, round_frontiers)| AggregateFriLaneProofV1 {
                    roots: lane.roots,
                    terminal_values: lane
                        .terminal_values
                        .iter()
                        .map(|value| value.coefficients().map(F::value))
                        .collect(),
                    round_frontiers,
                })
                .collect(),
            queries,
            grinding_nonce: 0,
        };
        let (betas, terminals) = verify_fri_commitments_v1(
            &proof,
            parameters,
            &DOMAINS,
            &layout,
            &mut verifier_transcript,
        )
        .unwrap();
        assert_eq!(
            query_indices_v1(&verifier_transcript, parameters, &DOMAINS, &layout).unwrap(),
            indices
        );
        verify_all_merkle_openings_v1(&proof, parameters, &DOMAINS, &layout, &indices).unwrap();
        let verify = |proof: &AggregateStarkProofV1,
                      deep: &AggregateDeepProofV1,
                      betas: &[Vec<E>],
                      terminals: &[Vec<E>]| {
            verify_opened_query_relations_after_complete_oods_v1(
                proof,
                deep,
                point,
                &mixes,
                parameters,
                &layout,
                &indices,
                betas,
                terminals,
                &supplemental,
            )
        };
        verify(&proof, &deep, &betas, &terminals).unwrap();
        if with_supplemental {
            for variant in 0..7 {
                let mut changed = supplemental.clone();
                match variant {
                    0 => changed[0].value = changed[0].value.add(E::ONE),
                    1 => changed[0].point = changed[0].point.add(E::ONE),
                    2 => changed[0].mix = changed[0].mix.add(E::ONE),
                    3 => changed[0].group = 1,
                    4 => {
                        changed[0].column = match selected.unwrap() {
                            AggregateSupplementalColumnV1::Base(_) => {
                                AggregateSupplementalColumnV1::Base(1)
                            }
                            AggregateSupplementalColumnV1::Auxiliary(_) => {
                                AggregateSupplementalColumnV1::Auxiliary(1)
                            }
                        }
                    }
                    5 => changed[0].point = E::ZERO,
                    _ => {
                        changed[0].column = match selected.unwrap() {
                            AggregateSupplementalColumnV1::Base(index) => {
                                AggregateSupplementalColumnV1::Auxiliary(index)
                            }
                            AggregateSupplementalColumnV1::Auxiliary(index) => {
                                AggregateSupplementalColumnV1::Base(index)
                            }
                        }
                    }
                }
                assert!(
                    verify_opened_query_relations_after_complete_oods_v1(
                        &proof, &deep, point, &mixes, parameters, &layout, &indices, &betas,
                        &terminals, &changed
                    )
                    .is_err()
                );
            }
            assert!(
                verify_opened_query_relations_after_complete_oods_v1(
                    &proof,
                    &deep,
                    point,
                    &mixes,
                    parameters,
                    &layout,
                    &indices,
                    &betas,
                    &terminals,
                    &[]
                )
                .is_err()
            );
        }

        for coordinate in 0..4 {
            let mut changed = deep.clone();
            let group = &mut changed.trace_groups[0];
            let target = match coordinate {
                0 => &mut group.base_current,
                1 => &mut group.base_next,
                2 => &mut group.aux_current,
                _ => &mut group.aux_next,
            };
            target[0][1] = 1;
            assert_eq!(
                verify(&proof, &changed, &betas, &terminals),
                Err(AggregateStarkErrorV1::FriOpening)
            );
        }
        let mut changed = proof.clone();
        changed.queries[0].composition_values[0][0][1] = 1;
        assert_eq!(
            verify(&changed, &deep, &betas, &terminals),
            Err(AggregateStarkErrorV1::FriOpening)
        );
        let mut changed = terminals.clone();
        changed[0][0] = changed[0][0].add(E::ONE);
        assert!(verify(&proof, &deep, &betas, &changed).is_err());
        let mut changed = betas.clone();
        changed[0][0] = changed[0][0].add(E::ONE);
        assert!(verify(&proof, &deep, &changed, &terminals).is_err());
    }
}
