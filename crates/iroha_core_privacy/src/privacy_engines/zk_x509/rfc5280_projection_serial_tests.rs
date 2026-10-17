// Native Projection serial controls included in the RFC test module.

#[test]
fn projection_serial_fixed_schedule_binds_exact_length_before_twenty_bytes() {
    for count in 0..=4 {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = count;
        for i in 0..count as usize {
            shape.disclosed_attribute_indices[i] = i as u8;
        }
        let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let mut counts = [0; 2];
        for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
            for family in [
                ZkX509Rfc5280StarkFamilyV1::OutputProducer,
                ZkX509Rfc5280StarkFamilyV1::OutputConsumer,
            ] {
                let fixed = schedule
                    .fixed_row(schedule.starts[family as usize] + ordinal)
                    .unwrap();
                let selected = projection_serial::slot(entry.channel);
                assert_eq!(
                    fixed[projection_serial::FIX_SERIAL],
                    F(u64::from(
                        selected.is_some() && family == ZkX509Rfc5280StarkFamilyV1::OutputProducer
                    ))
                );
                if family == ZkX509Rfc5280StarkFamilyV1::OutputProducer
                    && let Some(length) = selected
                {
                    counts[usize::from(!length)] += 1;
                }
            }
        }
        assert_eq!(counts, [8, 20]);
    }
    assert_eq!(projection_serial::FIX_END, 130);
}

#[test]
fn projection_serial_actual_material_matches_original_integer_and_all_io_bytes() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let source = projection_serial::source(&trace).unwrap();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let io = rfc5280_io_witnesses_v1(&trace, 0).unwrap();
        assert_eq!(
            u64::from_be_bytes(io[3].producer_value.as_slice().try_into().unwrap()),
            source.magnitude.len() as u64
        );
        let mut node_queries = F::ZERO;
        let mut byte_queries = F::ZERO;
        for (ordinal, entry) in material.schedule.output_topology.iter().enumerate() {
            if projection_serial::slot(entry.channel).is_none() {
                continue;
            }
            let index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                + ordinal;
            let row = material.base_row(index).unwrap();
            let next = material.base_row(index + 1).unwrap();
            let fixed = material.fixed_row(index).unwrap();
            assert_eq!(
                row[BASE_VALUE],
                F(u64::from(
                    io[entry.channel as usize].producer_value[entry.offset as usize]
                ))
            );
            assert_eq!(
                projection_serial::residues(&row, &next, &fixed),
                [F::ZERO; projection_serial::RESIDUES]
            );
            assert_eq!(
                projection_serial::residues(
                    &row.map(E::from_base),
                    &next.map(E::from_base),
                    &fixed.map(E::from_base)
                ),
                [E::ZERO; projection_serial::RESIDUES]
            );
            node_queries = node_queries.add(output_source_node_query_gate_v1(&row, &fixed));
            byte_queries = byte_queries.add(row[BASE_SERIAL_BYTE_QUERY_ACTIVE]);
            if row[BASE_SERIAL_BYTE_QUERY_ACTIVE] == F::ONE {
                assert_eq!(
                    trace.documents[0].bytes[row[BASE_ADDRESS].0 as usize]
                        .value
                        .value,
                    row[BASE_SERIAL_BYTE_QUERY_VALUE]
                );
            }
        }
        assert_eq!(
            node_queries,
            F(u64::from(
                source.node.content_end - source.node.content_start + 1
            ))
        );
        assert_eq!(
            byte_queries,
            F(u64::from(
                source.node.content_end - source.node.content_start
            ))
        );
    }
}

#[test]
fn projection_serial_sign_padding_full_width_and_every_metadata_mutation_are_constrained() {
    let schedule =
        compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
            .unwrap();
    let entries = schedule
        .output_topology
        .iter()
        .enumerate()
        .filter(|(_, entry)| projection_serial::slot(entry.channel).is_some())
        .collect::<Vec<_>>();
    for magnitude in [
        vec![1],
        vec![0x7f],
        vec![0x80],
        vec![0xff],
        vec![0xff; 20],
        vec![0x7f; 20],
    ] {
        let fixture = serial_source_fixture_v1(0, &magnitude);
        let source = projection_serial::Source {
            node: &fixture.node,
            magnitude: &magnitude,
        };
        let mut rows = Vec::new();
        let mut fixed_rows = Vec::new();
        for (ordinal, entry) in &entries {
            let length = projection_serial::slot(entry.channel).unwrap();
            let offset = entry.offset as usize;
            let value = if length {
                (magnitude.len() as u64).to_be_bytes()[offset]
            } else {
                magnitude.get(offset).copied().unwrap_or(0)
            };
            let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
            row[BASE_VALUE] = F(u64::from(value));
            write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
            projection_serial::populate_row(&mut row, &source, length, offset).unwrap();
            rows.push(row);
            fixed_rows.push(
                schedule
                    .fixed_row(
                        schedule.starts[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                            + ordinal,
                    )
                    .unwrap(),
            );
        }
        for i in 0..28 {
            let next = rows
                .get(i + 1)
                .copied()
                .unwrap_or([F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
            assert_eq!(
                projection_serial::residues(&rows[i], &next, &fixed_rows[i]),
                [F::ZERO; projection_serial::RESIDUES],
                "length={} row={i}",
                magnitude.len()
            );
            for column in [
                BASE_DOCUMENT,
                BASE_G,
                BASE_H,
                BASE_TAG_CLASS,
                BASE_CONSTRUCTED,
                BASE_TAG_NUMBER,
                BASE_A,
                BASE_PARENT,
                BASE_STRICT,
                BASE_D,
                BASE_INVERSE,
            ] {
                let mut changed = rows[i];
                changed[column] = changed[column].add(F::ONE);
                assert!(
                    projection_serial::residues(&changed, &next, &fixed_rows[i])
                        .iter()
                        .any(|r| *r != F::ZERO),
                    "length={} row={i} column={column}",
                    magnitude.len()
                );
            }
            if rows[i][BASE_D] == F::ONE {
                let address =
                    rows[i][BASE_ADDRESS].0 as usize - fixture.node.content_start as usize;
                assert_eq!(
                    rows[i][BASE_VALUE],
                    F(u64::from(fixture.encoded_contents[address].value))
                );
            }
        }
        assert_eq!(rows[0][BASE_D], F(u64::from(magnitude[0] & 0x80 != 0)));
        assert_eq!(
            output_source_node_query_gate_v1(&rows[7], &fixed_rows[7]),
            F::ONE
        );
    }
}

#[test]
fn projection_serial_source_rejects_wrong_leaf_integer_and_noncanonical_magnitude() {
    let mut trace = canonical_trace_v1();
    let node_index = trace.semantic_provenance[0]
        .nodes
        .iter()
        .position(|n| n.role == ZkX509Rfc5280GrammarRoleV1::CertificateSerial)
        .unwrap();
    let original = trace.semantic_provenance[0].nodes[node_index];
    for field in 0..8 {
        let node = &mut trace.semantic_provenance[0].nodes[node_index];
        *node = original;
        match field {
            0 => node.document = 1,
            1 => node.role_instance = 1,
            2 => node.tag_number = 3,
            3 => node.tag_class = 1,
            4 => node.constructed = true,
            5 => node.content_end += 1,
            6 => node.content_start += 1,
            _ => node.role = ZkX509Rfc5280GrammarRoleV1::CrlEntrySerial,
        }
        assert!(projection_serial::source(&trace).is_err());
    }
    trace.semantic_provenance[0].nodes[node_index] = original;
    let original_first = trace.certificates[0].serial[0];
    for first in [0, original_first ^ 0x80, original_first ^ 2] {
        trace.certificates[0].serial[0] = first;
        assert!(projection_serial::source(&trace).is_err());
    }
}

#[test]
fn projection_serial_coherent_output_shadow_changes_authenticated_der_lookup_endpoint() {
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let ordinal = material
            .schedule
            .output_topology
            .iter()
            .position(|entry| entry.channel == 4 && entry.offset == 0)
            .unwrap();
        let index =
            material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] + ordinal;
        let row = material.base_row(index).unwrap();
        let next = material.base_row(index + 1).unwrap();
        let fixed = material.fixed_row(index).unwrap();
        let role = ZkX509Rfc5280OutputRoleV1::Projection;
        let (aux, after) = spki_output_aux_fixture_v1(&row, &fixed, role);
        let evaluate = |row: &ZkX509Rfc5280StarkBaseRowV1,
                        aux: &ZkX509Rfc5280StarkAuxRowV1,
                        after: &ZkX509Rfc5280StarkAuxRowV1| {
            evaluate_zk_x509_rfc5280_local_residues_v1(
                row,
                &next,
                aux,
                after,
                &fixed,
                der_challenges_v1(),
                &challenges_v1(),
            )
            .unwrap()
        };
        assert!(evaluate(&row, &aux, &after).iter().all(|v| *v == F::ZERO));
        let mut changed = row;
        let original = row[BASE_VALUE].0 as u8;
        let value = (original & 0x80) | if original & 0x7f == 1 { 2 } else { 1 };
        assert_ne!(value, 0);
        changed[BASE_VALUE] = F(u64::from(value));
        changed[BASE_INVERSE] = changed[BASE_VALUE].inv().unwrap();
        write_u8_bits_v1(&mut changed, BASE_BYTE_BITS, value);
        populate_degree_normalization_helpers_v1(&mut changed, &fixed);
        let (repaired_aux, repaired_after) = spki_output_aux_fixture_v1(&changed, &fixed, role);
        let mut products_only = after;
        for lane in 0..4 {
            let column = output_role_aux_column_v1(output_role_index_v1(role), false, lane);
            products_only[column] = repaired_after[column];
        }
        assert!(
            evaluate(&changed, &aux, &products_only)
                .iter()
                .any(|v| *v != F::ZERO)
        );
        assert!(
            evaluate(&changed, &repaired_aux, &repaired_after)
                .iter()
                .all(|v| *v == F::ZERO)
        );
        for lane in 0..4 {
            assert_ne!(
                (
                    after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                    after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                ),
                (
                    repaired_after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                    repaired_after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                )
            );
        }
    }
}

#[test]
fn projection_serial_affine_degree_is_at_most_four_for_every_opened_input() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for seed in [1, 7, 19] {
        let samples = (0..9)
            .map(|point| {
                let row = core::array::from_fn(|i| affine_value_v1(seed, 1, i, point));
                let next = core::array::from_fn(|i| affine_value_v1(seed, 3, i, point));
                let fixed = core::array::from_fn(|i| affine_value_v1(seed, 5, i, point));
                let result = projection_serial::residues(&row, &next, &fixed);
                assert_eq!(
                    projection_serial::residues(
                        &row.map(E::from_base),
                        &next.map(E::from_base),
                        &fixed.map(E::from_base)
                    ),
                    result.map(E::from_base)
                );
                result
            })
            .collect::<Vec<_>>();
        for column in 0..projection_serial::RESIDUES {
            assert!(
                finite_difference_degree_v1(samples.iter().map(|r| r[column]).collect()) <= 4,
                "seed={seed} column={column}"
            );
        }
    }
    assert_eq!(ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1, 39);
}
