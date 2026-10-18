// Independent prechange scalar oracle for the bounded auxiliary replay optimization.
//
// This test-only oracle preserves the source13 recurrences verbatim. It is not
// a production compatibility path. The saved numeric recurrence is also independent
// of the new step kernel, including the material-owned event extraction.

fn scalar_reference_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    column: usize,
    sha_union: &ZkX509ShaUnionCentersV1,
) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
    der_challenges.validate()?;
    challenges.validate()?;
    sha_union.validate_v1()?;
    if column >= ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    if (AUX_NUMERIC_INVERSE..AUX_NUMERIC_ZERO_SUM + numeric::LOOKUP_LANES_V1).contains(&column) {
        return numeric_scalar_reference_v1(
            ZK_X509_RFC5280_STARK_TRACE_SIZE_V1,
            column - AUX_NUMERIC_INVERSE,
            challenges,
            |row_index| {
                let row = material.base_row(row_index)?;
                let fixed = material.fixed_row(row_index)?;
                Ok(numeric_lookup_event_v1(&row, &fixed))
            },
        );
    }
    let mut values = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    values
        .try_reserve_exact(ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    if (AUX_SHA_UNION_CENTERS..AUX_SERIAL_SOURCE_BEFORE).contains(&column) {
        let index = column - AUX_SHA_UNION_CENTERS;
        values.resize(
            ZK_X509_RFC5280_STARK_TRACE_SIZE_V1,
            sha_union.products[index / 4][index % 4],
        );
        return Ok(values.into_vec());
    }
    if let Some((relation, lane, after_column)) = product_aux_column_descriptor_v1(column) {
        let family = product_relation_family_v1(relation)?;
        let mut product = F::ONE;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let before = product;
            let gate = row_family_gate_v1(material, row_index, family)?;
            if gate == F::ONE {
                product = product.mul(product_relation_factor_v1(
                    relation,
                    &row,
                    lane,
                    der_challenges,
                )?);
            }
            values.push(if after_column { product } else { before });
        }
        return Ok(values.into_vec());
    }
    if let Some((role_index, consumer, lane)) = output_role_aux_column_descriptor_v1(column) {
        let mut product = F::ONE;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let fixed = material.fixed_row(row_index)?;
            values.push(product);
            let gate = row[BASE_ACTIVE]
                .mul(fixed[output_role_fixed_selector_column_v1(role_index, consumer)]);
            if gate == F::ONE {
                product = product.mul(output_role_product_factor_v1(
                    &row, role_index, consumer, lane, challenges,
                ));
            } else if gate != F::ZERO {
                return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
            }
        }
        return Ok(values.into_vec());
    }
    if let Some((consumer, lane, after_column)) = serial_product_aux_column_descriptor_v1(column) {
        let mut product = F::ONE;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let before = product;
            let gate = if consumer {
                row[BASE_COPY_CONSUMER_ACTIVE]
            } else {
                row[BASE_COPY_SOURCE_ACTIVE]
            };
            if gate == F::ONE {
                product = product.mul(normalized_copy_factor_v1(&row, lane, challenges));
            }
            values.push(if after_column { product } else { before });
        }
        return Ok(values.into_vec());
    }
    if let Some((table, lane, after_column)) =
        grammar_ordinal_product_aux_column_descriptor_v1(column)
    {
        let mut product = F::ONE;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let fixed = material.fixed_row(row_index)?;
            let before = product;
            let gate = if table {
                row[BASE_ACTIVE].mul(fixed[FIX_GRAMMAR_ORDINAL_TABLE])
            } else {
                row[BASE_ACTIVE].mul(fixed[FIX_SOURCE_NODE_NON_ROOT])
            };
            if gate == F::ONE {
                let child_count = if table { row[BASE_D] } else { row[BASE_G] };
                product = product.mul(grammar_ordinal_factor_v1(
                    row[BASE_DOCUMENT],
                    row[BASE_PARENT],
                    row[BASE_CHILD],
                    child_count,
                    lane,
                    challenges,
                ));
            }
            values.push(if after_column { product } else { before });
        }
        return Ok(values.into_vec());
    }
    if let Some((kind, lane)) = profile_lookup_aux_column_descriptor_v1(column) {
        let mut accumulator = F::ZERO;
        let mut zero_accumulator = F::ZERO;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let fixed = material.fixed_row(row_index)?;
            let table_gate = row[BASE_PROFILE_TABLE_ACTIVE];
            let table_factor = fixed[FIX_PROFILE_TABLE]
                .mul(profile_byte_factor_v1(&row, lane, challenges))
                .add(
                    fixed[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                        .mul(profile_topology_source_factor_v1(&row, lane, challenges)),
                );
            let multiplicity = row[BASE_PROFILE_TABLE_MULTIPLICITY];
            let query_gate =
                row_family_gate_v1(material, row_index, ZkX509Rfc5280StarkFamilyV1::FixedByte)?
                    .add(row_family_gate_v1(
                        material,
                        row_index,
                        ZkX509Rfc5280StarkFamilyV1::NameValue,
                    )?);
            let query_factor = profile_byte_factor_v1(&row, lane, challenges);
            let topology_query_gate = row[BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE];
            let topology_query_factor = profile_topology_query_factor_v1(&row, lane, challenges);
            let (table_zero, table_inverse) = zero_safe_inverse_v1(table_gate, table_factor);
            let (query_zero, query_inverse) = zero_safe_inverse_v1(query_gate, query_factor);
            let (topology_query_zero, topology_query_inverse) =
                zero_safe_inverse_v1(topology_query_gate, topology_query_factor);
            values.push(match kind {
                0 => accumulator,
                1 => table_inverse,
                2 => query_inverse,
                3 => zero_accumulator,
                4 => table_zero,
                5 => query_zero,
                6 => topology_query_inverse,
                7 => topology_query_zero,
                _ => return Err(ZkX509Rfc5280StarkErrorV1::Shape),
            });
            if row_index + 1 != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
                accumulator = accumulator
                    .add(table_gate.mul(multiplicity).mul(table_inverse))
                    .sub(query_gate.mul(query_inverse))
                    .sub(topology_query_gate.mul(topology_query_inverse));
                zero_accumulator = zero_accumulator
                    .add(table_gate.mul(multiplicity).mul(table_zero))
                    .sub(query_gate.mul(query_zero))
                    .sub(topology_query_gate.mul(topology_query_zero));
            }
        }
        if matches!(kind, 0 | 3)
            && values
                .last()
                .copied()
                .is_none_or(|terminal| terminal != F::ZERO)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        return Ok(values.into_vec());
    }
    if let Some(lookup) = grammar_lookup_aux_column_descriptor_v1(column) {
        let mut accumulator = F::ZERO;
        let mut zero_accumulator = F::ZERO;
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let row = material.base_row(row_index)?;
            let fixed = material.fixed_row(row_index)?;
            let source_node_gate =
                row_family_gate_v1(material, row_index, ZkX509Rfc5280StarkFamilyV1::SourceNode)?;
            let (table_gate, query_gate, table_factor, query_factor, multiplicity) =
                if lookup.parent {
                    (
                        source_node_gate,
                        row[BASE_ACTIVE].mul(fixed[FIX_SOURCE_NODE_NON_ROOT]),
                        grammar_parent_table_factor_v1(&row, lookup.lane, challenges),
                        grammar_parent_query_factor_v1(&row, lookup.lane, challenges),
                        row[BASE_D],
                    )
                } else {
                    (
                        row[BASE_ACTIVE].mul(fixed[FIX_GRAMMAR_RULE_TABLE]),
                        source_node_gate,
                        grammar_rule_table_factor_v1(&fixed, lookup.lane, challenges),
                        grammar_rule_query_factor_v1(&row, lookup.lane, challenges),
                        row[BASE_A],
                    )
                };
            let (table_zero, table_inverse) = zero_safe_inverse_v1(table_gate, table_factor);
            let (query_zero, query_inverse) = zero_safe_inverse_v1(query_gate, query_factor);
            values.push(match lookup.kind {
                0 => accumulator,
                1 => table_inverse,
                2 => query_inverse,
                3 => zero_accumulator,
                4 => table_zero,
                5 => query_zero,
                _ => return Err(ZkX509Rfc5280StarkErrorV1::Shape),
            });
            if row_index + 1 != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
                accumulator = accumulator
                    .add(table_gate.mul(multiplicity).mul(table_inverse))
                    .sub(query_gate.mul(query_inverse));
                zero_accumulator = zero_accumulator
                    .add(table_gate.mul(multiplicity).mul(table_zero))
                    .sub(query_gate.mul(query_zero));
            }
        }
        if matches!(lookup.kind, 0 | 3)
            && values
                .last()
                .copied()
                .is_none_or(|terminal| terminal != F::ZERO)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
        }
        return Ok(values.into_vec());
    }
    let lookup = lookup_aux_column_descriptor_v1(column).ok_or(ZkX509Rfc5280StarkErrorV1::Shape)?;
    let mut accumulator = F::ZERO;
    let mut zero_accumulator = F::ZERO;
    for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        let row = material.base_row(row_index)?;
        let table_family = if lookup.node {
            ZkX509Rfc5280StarkFamilyV1::SourceNode
        } else {
            ZkX509Rfc5280StarkFamilyV1::SourceByte
        };
        let table_gate = row_family_gate_v1(material, row_index, table_family)?;
        let serial_gate = row_family_gate_v1(
            material,
            row_index,
            ZkX509Rfc5280StarkFamilyV1::SerialSource,
        )?;
        let fixed = material.fixed_row(row_index)?;
        let query_gate = if lookup.node {
            serial_gate
                .add(output_source_node_query_gate_v1(&row, &fixed))
                .add(path_len::node_query_gate(&row, &fixed))
                .add(copy_census::node_query_gate(&row, &fixed))
        } else {
            row[BASE_SERIAL_BYTE_QUERY_ACTIVE]
        };
        let table_factor = if lookup.node {
            serial_node_lookup_factor_v1(&row, lookup.lane, challenges)
        } else {
            serial_byte_lookup_factor_v1(
                row[BASE_DOCUMENT],
                row[BASE_ADDRESS],
                row[BASE_VALUE],
                lookup.lane,
                challenges,
            )
        };
        let query_factor = if lookup.node {
            node_query_factor_v1(&row, &fixed, lookup.lane, challenges)
        } else {
            serial_byte_lookup_factor_v1(
                row[BASE_DOCUMENT],
                row[BASE_ADDRESS],
                row[BASE_SERIAL_BYTE_QUERY_VALUE],
                lookup.lane,
                challenges,
            )
        };
        let (table_zero, table_inverse) = zero_safe_inverse_v1(table_gate, table_factor);
        let (query_zero, query_inverse) = zero_safe_inverse_v1(query_gate, query_factor);
        values.push(match lookup.kind {
            0 => accumulator,
            1 => table_inverse,
            2 => query_inverse,
            3 => zero_accumulator,
            4 => table_zero,
            5 => query_zero,
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Shape),
        });
        if row_index + 1 != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let multiplicity = if lookup.node {
                row[SERIAL_NODE_TABLE_MULTIPLICITY]
            } else {
                row[SERIAL_BYTE_TABLE_MULTIPLICITY]
            };
            accumulator = accumulator
                .add(table_gate.mul(multiplicity).mul(table_inverse))
                .sub(query_gate.mul(query_inverse));
            zero_accumulator = zero_accumulator
                .add(table_gate.mul(multiplicity).mul(table_zero))
                .sub(query_gate.mul(query_zero));
        }
    }
    if matches!(lookup.kind, 0 | 3)
        && values
            .last()
            .copied()
            .is_none_or(|terminal| terminal != F::ZERO)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Source);
    }
    Ok(values.into_vec())
}

#[test]
#[ignore = "complete280-column prechange scalar/batch parity; run optimized"]
fn rfc_auxiliary_batch_matches_independent_scalar_for_all_280_columns() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let der = der_challenges_v1();
    let challenges = challenges_v1();
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    let provider = ZkX509Rfc5280StarkColumnProviderV1::with_centers_v1(
        &material,
        der,
        &challenges,
        ZkX509ShaUnionCentersV1::identity_fixture_v1(),
    )
    .unwrap();
    for first in (0..ZK_X509_RFC5280_STARK_AUX_WIDTH_V1).step_by(8) {
        let count = (ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 - first).min(8);
        let mut batch: Vec<_> = (0..count)
            .map(|_| {
                PrivateTableV1::new(
                    vec![F::ZERO; ZK_X509_RFC5280_STARK_TRACE_SIZE_V1],
                    zeroize_fields_v1,
                )
            })
            .collect();
        let mut targets: Vec<_> = batch.iter_mut().map(|column| &mut column[..]).collect();
        provider.fill_aux_columns_v1(first, &mut targets).unwrap();
        drop(targets);
        for (offset, actual) in batch.iter().enumerate() {
            let reference = PrivateTableV1::new(
                scalar_reference_v1(&material, der, &challenges, first + offset, &centers).unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(
                actual.as_slice(),
                reference.as_slice(),
                "column{}",
                first + offset
            );
        }
    }
    // Non-aligned spans cross before/after, center/noncenter, lookup/output,
    // and ordinary/numeric boundaries without dropping or reordering a column.
    for first in [3, 13, 29, 45, 109, 125, 173, 189, 261, 273] {
        let count = (ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 - first).min(7);
        let mut batch: Vec<_> = (0..count)
            .map(|_| {
                PrivateTableV1::new(
                    vec![F::ZERO; ZK_X509_RFC5280_STARK_TRACE_SIZE_V1],
                    zeroize_fields_v1,
                )
            })
            .collect();
        let mut targets: Vec<_> = batch.iter_mut().map(|column| &mut column[..]).collect();
        provider.fill_aux_columns_v1(first, &mut targets).unwrap();
        drop(targets);
        for (offset, actual) in batch.iter().enumerate() {
            let reference = PrivateTableV1::new(
                scalar_reference_v1(&material, der, &challenges, first + offset, &centers).unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(
                actual.as_slice(),
                reference.as_slice(),
                "unaligned column{}",
                first + offset
            );
        }
    }
}

// Exact source13 numeric recurrence used only as an independent test oracle.
/// Emit a prefix column without retaining another event or column matrix.
fn numeric_scalar_reference_v1(
    rows: usize,
    offset: usize,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    mut event_at: impl FnMut(
        usize,
    ) -> Result<numeric::NumericLookupEventV1<F>, ZkX509Rfc5280StarkErrorV1>,
) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
    challenges.validate()?;
    if rows == 0
        || rows > ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
        || offset >= numeric::LOOKUP_AUX_WIDTH_V1
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let kind = offset / numeric::LOOKUP_LANES_V1;
    let lane = offset % numeric::LOOKUP_LANES_V1;
    let mut values = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    values
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut sum = F::ZERO;
    let mut zero_sum = F::ZERO;
    for index in 0..rows {
        let event = event_at(index)?;
        if ![event.source, event.query, event.multiplicity]
            .into_iter()
            .chain(event.tuple)
            .all(|value| F::canonical(value.0).is_some())
            || !matches!(event.source, F::ZERO | F::ONE)
            || !matches!(event.query, F::ZERO | F::ONE)
            || event.source == F::ONE && event.query == F::ONE
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        let active = event.source.add(event.query);
        let factor = numeric::lookup_factor_v1(event.tuple, challenges.tuple[lane]);
        let (zero, inverse) = zero_safe_inverse_v1(active, factor);
        values.push(match kind {
            0 => inverse,
            1 => zero,
            2 => sum,
            3 => zero_sum,
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Shape),
        });
        let weight = event.source.mul(event.multiplicity).sub(event.query);
        sum = sum.add(weight.mul(inverse));
        zero_sum = zero_sum.add(weight.mul(zero));
    }
    // The final row is included: the AIR terminal checks prefix + final delta.
    // This also catches a malformed census while replaying inverse/zero columns.
    if sum != F::ZERO || zero_sum != F::ZERO {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(values.into_vec())
}

#[test]
#[ignore = "complete maximum-material280-column inverse-window parity and interleaved same-shape costs; run optimized"]
fn rfc_private_inverse_window_matches_full_maximum_material_and_reports_both_costs() {
    use super::super::relation::release_fixture::{
        build_zk_x509_release_fixture_v1, reference_statement_context_v1,
    };
    use super::super::verifier_profile::compile_zk_x509_rfc_statement_from_authoritative_state_v1;
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true).unwrap();
    let trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        compile_zk_x509_rfc_statement_from_authoritative_state_v1(
            &fixture.statement,
            &fixture.authoritative_state,
        ),
    )
    .unwrap();
    assert_eq!(trace.certificates.len(), 3);
    assert_eq!(trace.statement.disclosed_attribute_indices, [0, 1, 2, 3]);
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let rows = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1;
    let der = der_challenges_v1();
    let challenges = challenges_v1();
    let centers = ZkX509ShaUnionCentersV1::identity_fixture_v1();
    let scalar_scratch = aux_replay::scalar_scratch_payload_bytes_v1();
    let window_scratch = aux_replay::inverse_window_tests::scratch_payload_bytes_v1();
    println!(
        "rfc_inverse_window_header rows={rows} columns=280 max_width=8 rounds=3 expected_records=210 scalar_scratch_bytes={scalar_scratch} window_scratch_bytes={window_scratch} material=maximum_depth3_disclosures4 public_pair_capacity=24 production_selected=true"
    );
    let mut records = 0;
    for first in (0..280).step_by(8) {
        let count = (280 - first).min(8);
        let mut baseline: Vec<_> = (0..count)
            .map(|_| PrivateTableV1::new(vec![F::ZERO; rows], zeroize_fields_v1))
            .collect();
        let mut candidate: Vec<_> = (0..count)
            .map(|_| PrivateTableV1::new(vec![F::ZERO; rows], zeroize_fields_v1))
            .collect();
        // Both full output batches and the transient independent column are
        // included in this experiment's peak payload; source material remains
        // separately owned and visible to the process-wide resource observer.
        let output_payload_bytes = (2 * count + 1) * rows * core::mem::size_of::<F>();
        let experiment_payload_bytes = output_payload_bytes + window_scratch.max(scalar_scratch);
        for round in 0..3 {
            for window in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let target = if window {
                    &mut candidate
                } else {
                    &mut baseline
                };
                for column in target.iter_mut() {
                    zeroize_fields_v1(column);
                }
                let mut refs: Vec<_> = target.iter_mut().map(|column| &mut column[..]).collect();
                let started = std::time::Instant::now();
                if window {
                    aux_replay::inverse_window_tests::fill_columns_v1(
                        &material, der, &challenges, first, &mut refs, &centers,
                    )
                    .unwrap();
                } else {
                    aux_replay::fill_scalar_columns_for_testing_v1(
                        &material, der, &challenges, first, &mut refs, &centers,
                    )
                    .unwrap();
                }
                let elapsed_ns = started.elapsed().as_nanos();
                drop(refs);
                println!(
                    "rfc_inverse_window_cost first={first} width={count} rows={rows} round={round} window={window} elapsed_ns={elapsed_ns} output_payload_bytes={output_payload_bytes} experiment_payload_bytes={experiment_payload_bytes}"
                );
                records += 1;
            }
            for offset in 0..count {
                assert_eq!(
                    candidate[offset].as_slice(),
                    baseline[offset].as_slice(),
                    "first{first} offset{offset} round{round}"
                );
            }
            if round == 0 {
                for (offset, column) in candidate.iter().enumerate() {
                    let reference = PrivateTableV1::new(
                        scalar_reference_v1(&material, der, &challenges, first + offset, &centers)
                            .unwrap(),
                        zeroize_fields_v1,
                    );
                    assert_eq!(
                        column.as_slice(),
                        reference.as_slice(),
                        "independent full scalar column{}",
                        first + offset
                    );
                }
            }
        }
    }
    assert_eq!(records, 210);
}
