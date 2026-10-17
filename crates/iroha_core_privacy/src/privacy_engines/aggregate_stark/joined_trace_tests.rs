//! Independent common-domain row, frontier, ordering and rejection checks.

use super::*;

fn fixture() -> (
    AggregateStarkParametersV1,
    AggregateStarkDomainsV1,
    AggregateProofLayoutV1,
) {
    let parameters = AggregateStarkParametersV1 {
        proof_magic: *b"JON1",
        proof_version: 1,
        fri_commitment_layout: AggregateFriCommitmentLayoutV1::Paired,
        security_lanes: 2,
        query_count: FASTPQ_QUERY_COUNT_V1 as usize,
        blowup_log2: 3,
        terminal_log2: 3,
        terminal_degree_bound: 3,
        composition_degree_chunks: 3,
        minimum_trace_log2: 5,
        maximum_trace_log2: 8,
        maximum_trace_groups: 4,
        maximum_segment_instances: 4,
        maximum_base_columns_per_instance: 16,
        maximum_aux_columns_per_instance: 16,
        maximum_proof_bytes: 1 << 20,
    };
    let domains = AggregateStarkDomainsV1 {
        digest_context: TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            b"joined-trace-tests-v1",
        ),
        base_leaf: b"joined-test-base-leaf",
        base_node: b"joined-test-base-node",
        aux_leaf: b"joined-test-aux-leaf",
        aux_node: b"joined-test-aux-node",
        composition_leaf: b"joined-test-composition-leaf",
        composition_node: b"joined-test-composition-node",
        fri_leaf: b"joined-test-fri-leaf",
        fri_node: b"joined-test-fri-node",
        layout_label: b"joined-test-layout",
        base_root_label: b"joined-test-base-root",
        aux_root_label: b"joined-test-aux-root",
        composition_root_label: b"joined-test-composition-root",
        fri_root_label: b"joined-test-fri-root",
        fri_beta_label: b"joined-test-fri-beta",
        query_seed: b"joined-test-query",
    };
    let layout = AggregateProofLayoutV1::new(
        parameters,
        vec![
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 5,
                segment_instances: 1,
                base_width: 9,
                aux_width: 2,
            },
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 3,
                aux_width: 4,
            },
        ],
    )
    .unwrap();
    (parameters, domains, layout)
}

fn polynomial_groups(plan: &JoinedTraceCommitmentPlanV1) -> Vec<MaskedTracePolynomialSetV1> {
    plan.groups
        .iter()
        .enumerate()
        .map(|(group, (native, range))| {
            let count = (1_usize << *native) + 4;
            MaskedTracePolynomialSetV1 {
                native_trace_log2: *native,
                commitment_lde_log2: plan.commitment_lde_log2,
                columns: (0..range.len())
                    .map(|column| {
                        ZeroizingFieldColumnV1(
                            (0..count)
                                .map(|coefficient| {
                                    F((1 + group * 100_000 + column * 1_000 + coefficient) as u64)
                                })
                                .collect(),
                        )
                    })
                    .collect(),
            }
        })
        .collect()
}

fn materialized_rows(
    plan: &JoinedTraceCommitmentPlanV1,
    polynomials: &[MaskedTracePolynomialSetV1],
) -> Vec<Vec<F>> {
    let root = goldilocks_primitive_root_v1(plan.commitment_lde_log2).unwrap();
    (0..(1 << plan.commitment_lde_log2))
        .map(|index| {
            let x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(index as u128));
            polynomials
                .iter()
                .flat_map(|group| {
                    group.columns.iter().map(|column| {
                        column
                            .iter()
                            .rev()
                            .fold(F::ZERO, |value, &coefficient| value.mul(x).add(coefficient))
                    })
                })
                .collect()
        })
        .collect()
}

#[test]
fn joined_mixed_native_commitment_matches_independent_horner_rows_and_frontier() {
    let (parameters, domains, layout) = fixture();
    for kind in [JoinedTraceColumnKindV1::Base, JoinedTraceColumnKindV1::Aux] {
        let plan = JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, kind).unwrap();
        let polynomials = polynomial_groups(&plan);
        let borrowed = polynomials.iter().collect::<Vec<_>>();
        let rows = materialized_rows(&plan, &polynomials);
        let (leaf, node) = plan.roles_v1(&domains);
        let leaves = rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                row_leaf_hash_v1(
                    domains.digest_context,
                    leaf,
                    JOINED_TRACE_GROUP_MARKER_V1,
                    index,
                    row,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let tree =
            PrivacyOuterMerkleTreeV1::from_leaves(leaves, domains.digest_context, node).unwrap();
        let root_only = plan.commit_v1(&domains, &borrowed, &[]).unwrap();
        assert_eq!(root_only.commitment.root, tree.root());
        assert!(root_only.opened_rows.is_empty());
        let indices = [0, 1, 7, 63, 1024, 2047];
        let opened = plan.commit_v1(&domains, &borrowed, &indices).unwrap();
        let replayed = plan
            .commit_replayed_v1(
                &domains,
                &indices,
                |group, column| Ok(polynomials[group].column_coefficients_v1(column)?.to_vec()),
                evaluate_replayed_cpu_v1,
            )
            .unwrap();
        assert_eq!(replayed.commitment.root, opened.commitment.root);
        assert_eq!(replayed.commitment.frontier, opened.commitment.frontier);
        assert_eq!(replayed.opened_rows, opened.opened_rows);
        assert_eq!(opened.commitment.root, root_only.commitment.root);
        assert_eq!(
            opened.commitment.frontier,
            canonical_multiproof_frontier_v1(&tree, rows.len(), &indices).unwrap()
        );
        let mut authenticated = BTreeMap::new();
        for &index in &indices {
            assert_eq!(opened.opened_rows[&index], rows[index]);
            assert_eq!(rows[index].len(), plan.width_v1());
            let slices = (0..polynomials.len())
                .map(|group| &rows[index][plan.group_range_v1(group).unwrap()])
                .collect::<Vec<_>>();
            authenticated.insert(index, plan.leaf_hash_v1(&domains, index, &slices).unwrap());
        }
        verify_canonical_multiproof_v1(
            domains.digest_context,
            node,
            &tree.root(),
            rows.len(),
            &authenticated,
            &opened.commitment.frontier,
        )
        .unwrap();
        authenticated.insert(
            0,
            plan.leaf_hash_v1(
                &domains,
                1,
                &(0..polynomials.len())
                    .map(|group| &rows[0][plan.group_range_v1(group).unwrap()])
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        assert!(
            verify_canonical_multiproof_v1(
                domains.digest_context,
                node,
                &tree.root(),
                rows.len(),
                &authenticated,
                &opened.commitment.frontier
            )
            .is_err()
        );
        assert_ne!(
            row_leaf_hash_v1(domains.digest_context, leaf, 0, 0, &rows[0]).unwrap(),
            plan.leaf_hash_v1(
                &domains,
                0,
                &(0..polynomials.len())
                    .map(|group| &rows[0][plan.group_range_v1(group).unwrap()])
                    .collect::<Vec<_>>()
            )
            .unwrap()
        );
    }
}

#[test]
fn joined_trace_rejects_group_width_domain_order_field_and_index_substitution() {
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let mut polynomials = polynomial_groups(&plan);
    assert!(plan.group_range_v1(2).is_err());
    assert!(plan.commit_v1(&domains, &[&polynomials[0]], &[]).is_err());
    assert!(
        plan.commit_v1(&domains, &[&polynomials[1], &polynomials[0]], &[])
            .is_err()
    );
    for indices in [&[2, 1][..], &[1, 1], &[2048]] {
        assert!(
            plan.commit_v1(&domains, &polynomials.iter().collect::<Vec<_>>(), indices)
                .is_err()
        );
    }
    polynomials[0].commitment_lde_log2 += 1;
    assert!(
        plan.commit_v1(&domains, &polynomials.iter().collect::<Vec<_>>(), &[])
            .is_err()
    );
    polynomials[0].commitment_lde_log2 -= 1;
    polynomials[0].columns[0].0[0] =
        F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    assert!(
        plan.commit_v1(&domains, &polynomials.iter().collect::<Vec<_>>(), &[])
            .is_err()
    );
    assert!(
        plan.leaf_hash_v1(&domains, 0, &[&[F::ZERO; 8], &[F::ZERO; 3]])
            .is_err()
    );
    assert!(
        plan.leaf_hash_v1(&domains, 2048, &[&[F::ZERO; 9], &[F::ZERO; 3]])
            .is_err()
    );
    assert!(
        plan.leaf_hash_v1(
            &domains,
            0,
            &[
                &[F::ZERO; 9],
                &[F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1); 3]
            ]
        )
        .is_err()
    );
}

#[test]
fn joined_replayed_columns_reject_indices_before_source_and_abort_failed_batches() {
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let polynomials = polynomial_groups(&plan);
    let mut calls = 0;
    assert!(
        plan.commit_replayed_v1(
            &domains,
            &[2048],
            |_, _| {
                calls += 1;
                unreachable!()
            },
            evaluate_replayed_cpu_v1
        )
        .is_err()
    );
    assert_eq!(calls, 0);
    assert!(
        plan.commit_replayed_v1(
            &domains,
            &[0],
            |group, column| {
                calls += 1;
                if group == 0 && column == 8 {
                    return Err(AggregateStarkErrorV1::AllocationFailure);
                }
                Ok(polynomials[group].column_coefficients_v1(column)?.to_vec())
            },
            evaluate_replayed_cpu_v1
        )
        .is_err()
    );
    assert_eq!(calls, 9);
    assert!(
        plan.commit_replayed_v1(
            &domains,
            &[0],
            |group, column| {
                let mut values = polynomials[group].column_coefficients_v1(column)?.to_vec();
                if group == 1 && column == 2 {
                    values[0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
                }
                Ok(values)
            },
            evaluate_replayed_cpu_v1
        )
        .is_err()
    );
}

#[test]
fn joined_trace_rejects_total_width_overflow_at_the_exact_u16_boundary() {
    let (mut parameters, _, layout) = fixture();
    parameters.maximum_base_columns_per_instance = usize::from(u16::MAX);
    parameters.maximum_aux_columns_per_instance = usize::from(u16::MAX);
    for kind in [JoinedTraceColumnKindV1::Base, JoinedTraceColumnKindV1::Aux] {
        let mut groups = layout.trace_groups().to_vec();
        for (index, group) in groups.iter_mut().enumerate() {
            let width = 32_767 + index;
            match kind {
                JoinedTraceColumnKindV1::Base => group.base_width = width,
                JoinedTraceColumnKindV1::Aux => group.aux_width = width,
            }
        }
        let boundary = AggregateProofLayoutV1::new_with_trace_layout_v1(
            parameters,
            groups.clone(),
            AggregateTraceLayoutV1::JoinedCurrent,
        )
        .unwrap();
        let plan = JoinedTraceCommitmentPlanV1::new_v1(parameters, &boundary, kind).unwrap();
        assert_eq!(plan.width_v1(), usize::from(u16::MAX));
        assert_eq!(plan.group_range_v1(0).unwrap(), 0..32_767);
        assert_eq!(plan.group_range_v1(1).unwrap(), 32_767..65_535);
        match kind {
            JoinedTraceColumnKindV1::Base => groups[0].base_width += 1,
            JoinedTraceColumnKindV1::Aux => groups[0].aux_width += 1,
        }
        // Each logical width remains encodable. Only their joined sum overflows.
        let separate = AggregateProofLayoutV1::new(parameters, groups.clone()).unwrap();
        assert_eq!(
            JoinedTraceCommitmentPlanV1::new_v1(parameters, &separate, kind),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(
            AggregateProofLayoutV1::new_with_trace_layout_v1(
                parameters,
                groups,
                AggregateTraceLayoutV1::JoinedCurrent
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
    }
}

#[test]
fn joined_trace_authentication_rejects_swapped_equal_width_native_group_slices() {
    let (parameters, domains, layout) = fixture();
    let groups = layout
        .trace_groups()
        .iter()
        .map(|group| AggregateTraceGroupLayoutV1 {
            base_width: 2,
            aux_width: 2,
            ..*group
        })
        .collect();
    let layout = AggregateProofLayoutV1::new_with_trace_layout_v1(
        parameters,
        groups,
        AggregateTraceLayoutV1::JoinedCurrent,
    )
    .unwrap();
    for kind in [JoinedTraceColumnKindV1::Base, JoinedTraceColumnKindV1::Aux] {
        let plan = JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, kind).unwrap();
        let polynomials = polynomial_groups(&plan);
        let indices = [0, 31, 2047];
        let opened = plan
            .commit_v1(&domains, &polynomials.iter().collect::<Vec<_>>(), &indices)
            .unwrap();
        let (_, node) = plan.roles_v1(&domains);
        let mut authenticated = BTreeMap::new();
        for &index in &indices {
            let row = &opened.opened_rows[&index];
            let slices = [&row[0..2], &row[2..4]];
            assert_ne!(slices[0], slices[1]);
            authenticated.insert(index, plan.leaf_hash_v1(&domains, index, &slices).unwrap());
        }
        verify_canonical_multiproof_v1(
            domains.digest_context,
            node,
            &opened.commitment.root,
            layout.common_lde_size(),
            &authenticated,
            &opened.commitment.frontier,
        )
        .unwrap();
        let row = &opened.opened_rows[&31];
        // Equal widths pass shape validation, so this rejection requires the
        // joined leaf to authenticate the canonical native-group column order.
        let swapped = plan
            .leaf_hash_v1(&domains, 31, &[&row[2..4], &row[0..2]])
            .unwrap();
        assert_ne!(authenticated[&31], swapped);
        authenticated.insert(31, swapped);
        assert!(
            verify_canonical_multiproof_v1(
                domains.digest_context,
                node,
                &opened.commitment.root,
                layout.common_lde_size(),
                &authenticated,
                &opened.commitment.frontier
            )
            .is_err()
        );
    }
}

#[test]
fn joined_trace_commitment_is_identical_across_worker_counts() {
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let polynomials = polynomial_groups(&plan);
    let run = |workers| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                plan.commit_v1(
                    &domains,
                    &polynomials.iter().collect::<Vec<_>>(),
                    &[0, 17, 2047],
                )
                .unwrap()
            })
    };
    assert_eq!(run(1), run(4));
}

#[test]
fn streamed_private_row_scratch_clears_and_invalid_columns_leave_no_partial_absorption() {
    let (_, domains, _) = fixture();
    let create = || {
        StreamingRowCommitmentV1::new(
            domains.digest_context,
            domains.base_leaf,
            domains.base_node,
            JOINED_TRACE_GROUP_MARKER_V1,
            8,
            2,
            &[0, 7],
        )
        .unwrap()
    };
    let mut commitment = create();
    let first = [F(17); 8];
    let second = [F(23); 8];
    commitment.absorb_column(&first).unwrap();
    let mut malformed = second;
    malformed[7] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
    assert_eq!(
        commitment.absorb_column(&malformed),
        Err(AggregateStarkErrorV1::NonCanonicalField)
    );
    assert_eq!(commitment.received_columns, 1);
    assert_eq!(commitment.opened_rows[&0], vec![F(17)]);
    commitment.absorb_column(&second).unwrap();
    let result = commitment.finish().unwrap();
    let mut expected = create();
    expected.absorb_column(&first).unwrap();
    expected.absorb_column(&second).unwrap();
    assert_eq!(result, expected.finish().unwrap());
    assert_eq!(result.opened_rows[&7], vec![F(17), F(23)]);

    let mut aborted = create();
    aborted.absorb_column(&first).unwrap();
    aborted.clear_private_opened_rows_v1();
    assert!(
        aborted
            .opened_rows
            .values()
            .flatten()
            .all(|&value| value == F::ZERO)
    );
    // The same routine runs from Drop, including finish's incomplete error.
    assert_eq!(aborted.finish(), Err(AggregateStarkErrorV1::InvalidLayout));
}

#[test]
fn sampling_before_join_preserves_masks_source_order_and_early_rejection() {
    use rand::{SeedableRng as _, rngs::StdRng};
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let mut sampled = Vec::new();
    for (group, (native, range)) in plan.groups.iter().enumerate() {
        let source = |column| {
            (0..(1 << *native))
                .map(|row| F((1 + 100_000 * group + 1_000 * column + row) as u64))
                .collect::<Vec<_>>()
        };
        let mut first_rng = StdRng::from_seed([0x49; 32]);
        let mut next_column = 0;
        let polynomials = MaskedTracePolynomialSetV1::sample_columns_v1(
            *native,
            plan.commitment_lde_log2,
            range.len(),
            3,
            &mut first_rng,
            |column| {
                assert_eq!(column, next_column);
                next_column += 1;
                Ok(source(column))
            },
        )
        .unwrap();
        assert_eq!(next_column, range.len());
        let mut reference_rng = StdRng::from_seed([0x49; 32]);
        let (_, reference) = commit_masked_trace_polynomial_columns_v1(
            domains.digest_context,
            domains.base_leaf,
            domains.base_node,
            group,
            *native,
            plan.commitment_lde_log2,
            range.len(),
            3,
            &[],
            &mut reference_rng,
            |column| Ok(source(column)),
        )
        .unwrap();
        for column in 0..range.len() {
            assert_eq!(
                polynomials.column_coefficients_v1(column).unwrap(),
                reference.column_coefficients_v1(column).unwrap()
            );
        }
        sampled.push(polynomials);
    }
    assert!(
        plan.commit_v1(&domains, &sampled.iter().collect::<Vec<_>>(), &[0, 2047])
            .is_ok()
    );
    for (native, common, width, mask) in [
        (8, 8, 1, 3),
        (8, 11, 0, 3),
        (8, 11, 1, usize::MAX),
        (8, 11, usize::MAX, 3),
    ] {
        let mut calls = 0;
        let mut rng = StdRng::from_seed([3; 32]);
        assert!(
            MaskedTracePolynomialSetV1::sample_columns_v1(
                native,
                common,
                width,
                mask,
                &mut rng,
                |_| {
                    calls += 1;
                    Ok(vec![F::ONE; 256])
                }
            )
            .is_err()
        );
        assert_eq!(calls, 0);
    }
    let mut calls = 0;
    let mut rng = StdRng::from_seed([7; 32]);
    assert!(
        MaskedTracePolynomialSetV1::sample_columns_v1(5, 11, 3, 3, &mut rng, |column| {
            calls += 1;
            if column == 1 {
                Err(AggregateStarkErrorV1::InvalidLayout)
            } else {
                Ok(vec![F::ONE; 32])
            }
        })
        .is_err()
    );
    assert_eq!(calls, 2);
}

fn evaluate_replayed_cpu_v1(
    columns: &[ZeroizingFieldColumnV1],
    native: u8,
    common: u8,
) -> Result<Vec<ZeroizingFieldColumnV1>, AggregateStarkErrorV1> {
    columns
        .iter()
        .map(|column| {
            masked_trace_coefficients_on_coset_v1(column, native, common)
                .map(ZeroizingFieldColumnV1)
                .map_err(map_transparent_error_v1)
        })
        .collect()
}

#[test]
fn joined_replay_rejects_wrong_evaluator_shapes_before_commitment_publication() {
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let polynomials = polynomial_groups(&plan);
    for wrong_width in [true, false] {
        assert!(
            plan.commit_replayed_v1(
                &domains,
                &[0],
                |group, column| { Ok(polynomials[group].column_coefficients_v1(column)?.to_vec()) },
                |columns, native, common| {
                    let mut evaluated = evaluate_replayed_cpu_v1(columns, native, common)?;
                    if wrong_width {
                        evaluated.pop();
                    } else {
                        evaluated[0].0.pop();
                    }
                    Ok(evaluated)
                }
            )
            .is_err()
        );
    }
}

#[test]
fn retained_initial_and_selected_replay_preserve_both_joined_phase_roots_rows_and_frontiers() {
    let (parameters, domains, layout) = fixture();
    for kind in [JoinedTraceColumnKindV1::Base, JoinedTraceColumnKindV1::Aux] {
        let plan = JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, kind).unwrap();
        let polynomials = polynomial_groups(&plan);
        let borrowed = polynomials.iter().collect::<Vec<_>>();
        let rows = 1usize << plan.commitment_lde_log2;
        let queries = [0, 15, 16, 17, rows - 1];
        let expected = plan.commit_v1(&domains, &borrowed, &queries).unwrap();
        let evaluate =
            |columns: &[ZeroizingFieldColumnV1], native, common, selected: Option<&[usize]>| {
                columns
                    .iter()
                    .map(|column| {
                        masked_trace_coefficients_on_coset_v1(column, native, common)
                            .map(ZeroizingFieldColumnV1)
                            .map(|full| match selected {
                                Some(indices) => ZeroizingFieldColumnV1(
                                    indices.iter().map(|&row| full[row]).collect(),
                                ),
                                None => full,
                            })
                            .map_err(map_transparent_error_v1)
                    })
                    .collect::<Result<Vec<_>, _>>()
            };
        let mut calls = Vec::new();
        let (initial, cut) = plan
            .commit_retained_replayed_v1(
                &domains,
                &[],
                None,
                |group, column| {
                    calls.push((group, column));
                    Ok(polynomials[group].columns[column].to_vec())
                },
                evaluate,
            )
            .unwrap();
        assert_eq!(initial.commitment.root, expected.commitment.root);
        assert!(initial.opened_rows.is_empty());
        assert!(initial.commitment.frontier.is_empty());
        let cut = cut.unwrap();
        cut.check_root_v1(rows, expected.commitment.root).unwrap();
        let initial_calls = calls.clone();
        calls.clear();
        let (replayed, absent_cut) = plan
            .commit_retained_replayed_v1(
                &domains,
                &queries,
                Some(&cut),
                |group, column| {
                    calls.push((group, column));
                    Ok(polynomials[group].columns[column].to_vec())
                },
                evaluate,
            )
            .unwrap();
        assert!(absent_cut.is_none());
        assert_eq!(calls, initial_calls);
        assert_eq!(calls.len(), plan.width);
        assert_eq!(replayed, expected);
        assert!(
            cut.check_root_v1(rows / 2, expected.commitment.root)
                .is_err()
        );
        assert!(
            cut.check_root_v1(rows, PrivacyOuterDigestV1::default())
                .is_err()
        );
        let changed = plan.commit_retained_replayed_v1(
            &domains,
            &queries,
            Some(&cut),
            |group, column| {
                let mut coefficients = polynomials[group].columns[column].to_vec();
                if group == 0 && column == 0 {
                    coefficients[0] = coefficients[0].add(F::ONE);
                }
                Ok(coefficients)
            },
            evaluate,
        );
        assert!(changed.is_err());
    }
}

#[test]
fn retained_replay_rejects_inconsistent_root_only_queries_and_source_failure_without_result() {
    let (parameters, domains, layout) = fixture();
    let plan =
        JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, JoinedTraceColumnKindV1::Base)
            .unwrap();
    let mut source_calls = 0;
    let result = plan.commit_retained_replayed_v1(
        &domains,
        &[0],
        None,
        |_, _| {
            source_calls += 1;
            Err(AggregateStarkErrorV1::InternalInvariant)
        },
        |_, _, _, _| panic!("inconsistent root-only request must reject before evaluation"),
    );
    assert!(result.is_err());
    assert_eq!(source_calls, 0);
    let result = plan.commit_retained_replayed_v1(
        &domains,
        &[],
        None,
        |_, _| {
            source_calls += 1;
            Err(AggregateStarkErrorV1::InternalInvariant)
        },
        |_, _, _, _| panic!("source failure must reject before evaluation"),
    );
    assert!(result.is_err());
    assert_eq!(source_calls, 1);
}
