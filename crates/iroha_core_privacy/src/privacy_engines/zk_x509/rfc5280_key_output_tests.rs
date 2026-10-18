// Focused source-owner controls, included in the RFC test module. These are
// local relation and construction controls, not accepted-credential experiments.

fn key_row_fixture_v1(
    slot: usize,
    cert2: u64,
    offset: usize,
) -> (ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkFixedRowV1) {
    let shape = ZkX509Rfc5280StarkShapeV1::default();
    let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
    let channel = [14_u32, 17, 20, 27, 28][slot];
    let ordinal = schedule
        .output_topology
        .iter()
        .position(|entry| entry.channel == channel && entry.offset == offset as u32)
        .unwrap();
    let fixed = schedule
        .fixed_row(schedule.starts[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] + ordinal)
        .unwrap();
    let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
    row[BASE_ACTIVE] = F::ONE;
    row[BASE_CERT2_ACTIVE] = F(cert2);
    for (i, column) in metadata_columns_v1().into_iter().enumerate() {
        row[column] = fixed[FIX_EXPECTED + i];
    }
    let (optional, document, coefficient) = KEY_OUTPUT_SOURCES_V1[slot];
    if optional == 0 || cert2 == 1 {
        row[BASE_VALUE] = F(if offset == 0 { 4 } else { (17 + offset) as u64 });
        write_u8_bits_v1(&mut row, BASE_BYTE_BITS, row_value_for_bits_v1(offset));
        row[BASE_D] = F::ONE;
        row[BASE_A] = F(66);
        row[BASE_G] = F(16);
        row[BASE_H] = F(document + coefficient * cert2);
        row[BASE_DOCUMENT] = row[BASE_H];
        row[BASE_NODE] = F(7);
        row[BASE_START] = F(100);
        row[BASE_CONTENT_START] = F(102);
        row[BASE_CONTENT_END] = F(168);
        row[BASE_ADDRESS] = F(103 + offset as u64);
        row[BASE_TAG_NUMBER] = F(3);
    }
    (normalized_row_v1(row, &fixed), fixed)
}
fn row_value_for_bits_v1(offset: usize) -> u8 {
    if offset == 0 { 4 } else { (17 + offset) as u8 }
}

#[test]
fn key_output_fixed_schedule_covers_exact_five_channels_and_all65_offsets() {
    for disclosed in 0..=4_u8 {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = disclosed;
        for i in 0..usize::from(disclosed) {
            shape.disclosed_attribute_indices[i] = i as u8;
        }
        let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let mut counts = [0_usize; 5];
        for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
            let fixed = schedule
                .fixed_row(
                    schedule.starts[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] + ordinal,
                )
                .unwrap();
            let consumer = schedule
                .fixed_row(
                    schedule.starts[ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize] + ordinal,
                )
                .unwrap();
            assert_eq!(
                &consumer[FIX_EXPECTED + 6..FIX_EXPECTED + 10],
                &[F::ZERO; 4]
            );
            if let Some(slot) = key_output_slot_v1(shape, entry.channel) {
                counts[slot] += 1;
                let (optional, document, coefficient) = KEY_OUTPUT_SOURCES_V1[slot];
                assert_eq!(entry.role, ZkX509Rfc5280OutputRoleV1::P256PublicKey);
                assert!(entry.offset < 65);
                assert_eq!(
                    &fixed[FIX_EXPECTED + 6..FIX_EXPECTED + 10],
                    &[F::ONE, F(optional), F(document), F(coefficient)]
                );
            } else if let Some(slot) = spki_output_slot_v1(shape, entry.channel) {
                let (optional, document, coefficient) = SPKI_OUTPUT_SOURCES_V1[slot];
                assert_eq!(
                    &fixed[FIX_EXPECTED + 6..FIX_EXPECTED + 10],
                    &[F::ONE, F(optional), F(document), F(coefficient)]
                );
                assert_eq!(fixed[FIX_OUTPUT_SOURCE_SPKI], F::ONE);
            } else if let Some((slot, _)) = variable_output::slot(shape, entry.channel) {
                // Independent public map: key gate, optional slot, document base,
                // and private-depth coefficient for all nine data/length pairs.
                let expected: [[u64; 4]; 9] = [
                    [0, 0, 0, 0],
                    [0, 0, 1, 0],
                    [0, 1, 0, 2],
                    [0, 0, 2, 1],
                    [0, 0, 2, 1],
                    [0, 0, 0, 0],
                    [0, 0, 1, 0],
                    [0, 1, 0, 2],
                    [0, 0, 2, 1],
                ];
                assert_eq!(
                    &fixed[FIX_EXPECTED + 6..FIX_EXPECTED + 10],
                    &expected[slot].map(F)
                );
                assert_eq!(fixed[variable_output::FIX_VARIABLE], F::ONE);
                assert_eq!(fixed[FIX_OUTPUT_SOURCE_SPKI], F::ZERO);
            } else {
                assert_eq!(&fixed[FIX_EXPECTED + 6..FIX_EXPECTED + 10], &[F::ZERO; 4]);
            }
        }
        assert_eq!(counts, [65; 5]);
        assert_eq!(key_output_slot_v1(shape, u32::MAX), None);
    }
}

#[test]
fn key_output_local_relation_covers_both_depths_all_slots_and_fp4_lift() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for cert2 in 0..=1 {
        let mut live = 0;
        for slot in 0..5 {
            for offset in 0..65 {
                let (row, fixed) = key_row_fixture_v1(slot, cert2, offset);
                assert_eq!(
                    output_source_residues_v1(&row, &fixed),
                    [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                assert_eq!(
                    output_source_residues_v1(&row.map(E::from_base), &fixed.map(E::from_base)),
                    [E::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                assert_eq!(output_metadata_residues_v1(&row, &fixed), [F::ZERO; 6]);
                assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], row[BASE_D]);
                assert_eq!(row[BASE_SERIAL_BYTE_QUERY_VALUE], row[BASE_VALUE]);
                assert_eq!(output_source_query_gate_v1(&row, &fixed), row[BASE_D]);
                live += usize::from(row[BASE_D] == F::ONE);
                let aux = neutral_aux_v1();
                let all = evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &row,
                    &row,
                    &aux,
                    &aux,
                    &fixed,
                    der_challenges_v1(),
                    &challenges_v1(),
                    terminal_claims_v1(),
                )
                .unwrap();
                let begin = RFC5280_RESIDUE_SECTIONS_V1[..11]
                    .iter()
                    .map(|s| s.1)
                    .sum::<usize>()
                    + 6;
                assert_eq!(
                    &all[begin..begin + OUTPUT_SOURCE_RESIDUES_V1],
                    &[F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                assert_eq!(all.len(), 2_149);
            }
        }
        assert_eq!(live, if cert2 == 0 { 260 } else { 325 });
    }
}

#[test]
fn key_output_mutations_cannot_change_authenticated_byte_node_or_offset() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    let (row, fixed) = key_row_fixture_v1(1, 1, 64);
    let challenges = challenges_v1();
    let mut table = row;
    table[BASE_ROLE] = row[BASE_G];
    table[BASE_INSTANCE] = row[BASE_H];
    for lane in 0..4 {
        assert_eq!(
            node_query_factor_v1(&row, &fixed, lane, &challenges),
            serial_node_lookup_factor_v1(&table, lane, &challenges)
        );
    }
    // Node fields can be changed coherently in current and next; the fixed
    // source table is still independent. Test all eleven authenticated fields.
    for column in [
        BASE_DOCUMENT,
        BASE_NODE,
        BASE_START,
        BASE_CONTENT_START,
        BASE_CONTENT_END,
        BASE_TAG_CLASS,
        BASE_CONSTRUCTED,
        BASE_TAG_NUMBER,
        BASE_G,
        BASE_H,
        BASE_A,
    ] {
        let mut changed = row;
        changed[column] = changed[column].add(F::ONE);
        for lane in 0..4 {
            assert_ne!(
                node_query_factor_v1(&changed, &fixed, lane, &challenges),
                serial_node_lookup_factor_v1(&table, lane, &challenges),
                "node field {column}"
            );
            let mut changed_e = row.map(E::from_base);
            changed_e[column] = changed_e[column].add(E::canonical([0, 1, 3, 5]).unwrap());
            assert_ne!(
                node_query_factor_v1(&changed_e, &fixed.map(E::from_base), lane, &challenges),
                E::from_base(serial_node_lookup_factor_v1(&table, lane, &challenges))
            );
        }
    }
    for column in [BASE_DOCUMENT, BASE_ADDRESS, BASE_VALUE] {
        let mut changed = row;
        changed[column] = changed[column].add(F::ONE);
        changed = normalized_row_v1(changed, &fixed);
        for lane in 0..4 {
            let source = serial_byte_lookup_factor_v1(
                row[BASE_DOCUMENT],
                row[BASE_ADDRESS],
                row[BASE_VALUE],
                lane,
                &challenges,
            );
            let query = serial_byte_lookup_factor_v1(
                changed[BASE_DOCUMENT],
                changed[BASE_ADDRESS],
                changed[BASE_SERIAL_BYTE_QUERY_VALUE],
                lane,
                &challenges,
            );
            assert_ne!(query, source, "byte field {column}");
        }
    }
    for column in [
        BASE_D,
        BASE_G,
        BASE_H,
        BASE_DOCUMENT,
        BASE_ADDRESS,
        BASE_CONTENT_START,
        BASE_CONTENT_END,
        BASE_A,
        BASE_TAG_CLASS,
        BASE_CONSTRUCTED,
        BASE_TAG_NUMBER,
    ] {
        let mut changed = row;
        changed[column] = changed[column].add(F::ONE);
        assert!(
            output_source_residues_v1(&changed, &fixed)
                .iter()
                .any(|r| *r != F::ZERO),
            "local field {column}"
        );
    }
    let mut wrong_offset = fixed;
    wrong_offset[FIX_EXPECTED + 4] = F(65);
    assert_ne!(output_source_residues_v1(&row, &wrong_offset)[9], F::ZERO);
}

#[test]
fn key_output_optional_padding_and_nonkey_queries_are_canonical() {
    let (row, fixed) = key_row_fixture_v1(2, 0, 64);
    assert_eq!(row[BASE_D], F::ZERO);
    for column in OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1
        .into_iter()
        .chain([BASE_D, BASE_VALUE])
    {
        let mut changed = row;
        changed[column] = F::ONE;
        assert!(
            output_source_residues_v1(&changed, &fixed)
                .iter()
                .any(|r| *r != F::ZERO)
        );
    }
    let mut nonkey = fixed;
    nonkey[FIX_EXPECTED + 6..FIX_EXPECTED + 10].fill(F::ZERO);
    assert_eq!(
        output_source_residues_v1(&row, &nonkey),
        [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
    );
    let mut changed = row;
    changed[BASE_D] = F::ONE;
    assert_ne!(output_source_residues_v1(&changed, &nonkey)[0], F::ZERO);
    let mut padding = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
    padding[ZkX509Rfc5280StarkFamilyV1::Padding as usize] = F::ONE;
    let zero = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
    for column in OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1
        .into_iter()
        .chain([BASE_D])
    {
        let mut changed = zero;
        changed[column] = F::ONE;
        assert!(
            private_geometry_residues_v1(&changed, &changed, &padding)
                .iter()
                .any(|r| *r != F::ZERO)
        );
    }
}

#[test]
fn key_output_arbitrary_selectors_and_complete_degree_inventory_are_polynomial() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    let current = core::array::from_fn(|i| E::canonical([i as u64 + 1, 3, 5, 7]).unwrap());
    let fixed = core::array::from_fn(|i| E::canonical([i as u64 + 11, 13, 17, 19]).unwrap());
    let producer = fixed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize];
    assert_eq!(
        output_source_query_gate_v1(&current, &fixed),
        producer.mul(current[BASE_D])
    );
    let residues = output_source_residues_v1(&current, &fixed);
    assert_eq!(
        residues[0],
        producer
            .sub(fixed[variable_output::FIX_VARIABLE])
            .sub(fixed[projection_serial::FIX_SERIAL])
            .sub(fixed[projection_disclosure::FIX_DISCLOSURE])
            .mul(
                current[BASE_D].sub(
                    fixed[FIX_EXPECTED + 6].mul(
                        E::ONE
                            .sub(fixed[FIX_EXPECTED + 7])
                            .add(fixed[FIX_EXPECTED + 7].mul(current[BASE_CERT2_ACTIVE]))
                    )
                )
            )
    );
    let mut suppressed = fixed;
    suppressed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] = E::ZERO;
    suppressed[variable_output::FIX_VARIABLE] = E::ZERO;
    suppressed[projection_serial::FIX_SERIAL] = E::ZERO;
    suppressed[projection_disclosure::FIX_DISCLOSURE] = E::ZERO;
    assert_eq!(
        output_source_residues_v1(&current, &suppressed),
        [E::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
    );
    assert_eq!(
        node_query_factor_v1(&current, &suppressed, 0, &challenges_v1()),
        serial_node_lookup_factor_v1(&current, 0, &challenges_v1())
    );
    let samples = (0..9)
        .map(|point| {
            let row = core::array::from_fn(|i| affine_value_v1(7, 1, i, point));
            let fixed = core::array::from_fn(|i| affine_value_v1(7, 5, i, point));
            output_source_residues_v1(&row, &fixed)
        })
        .collect::<Vec<_>>();
    for i in 0..OUTPUT_SOURCE_RESIDUES_V1 {
        assert_eq!(
            finite_difference_degree_v1(samples.iter().map(|r| r[i]).collect()),
            if i < 2 || i == 9 || i == 23 { 4 } else { 3 }
        );
    }
    assert_eq!(
        (
            ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
            ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
            ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1,
            ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1,
            ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1
        ),
        (285, 280, 147, 2149, 4)
    );
}

#[test]
fn key_output_lookup_zero_denominators_remain_total_and_singular_counts_bind() {
    for denominator in [F::ZERO, F::ONE, F(17)] {
        let (zero, inverse) = zero_safe_inverse_v1(F::ONE, denominator);
        let mut residues = Vec::new();
        push_gated_zero_safe_inverse_v1(&mut residues, F::ONE, denominator, zero, inverse);
        assert!(residues.iter().all(|r| *r == F::ZERO));
        let (inactive_zero, inactive_inverse) = zero_safe_inverse_v1(F::ZERO, denominator);
        assert_eq!((inactive_zero, inactive_inverse), (F::ZERO, F::ZERO));
        // One authenticated table event and its one query cancel in both
        // accumulators, including the singular case. Omitting the query fails.
        assert_eq!(inverse.sub(inverse), F::ZERO);
        assert_eq!(zero.sub(zero), F::ZERO);
        assert!(inverse != F::ZERO || zero != F::ZERO);
        let mut changed = Vec::new();
        push_gated_zero_safe_inverse_v1(
            &mut changed,
            F::ONE,
            denominator,
            F::ONE.sub(zero),
            inverse,
        );
        assert!(changed.iter().any(|r| *r != F::ZERO));
    }
}

#[test]
fn key_output_constructor_borrows_exact_source_and_rejects_bad_lengths_offsets_and_bytes() {
    let mut trace = canonical_trace_v1();
    {
        let nodes = key_output_nodes_v1(&trace).unwrap();
        assert_eq!(
            core::mem::size_of_val(&nodes),
            5 * core::mem::size_of::<&ZkX509Rfc5280NodeProvenanceV1>()
        );
        for node in nodes.into_iter().flatten() {
            for offset in [0, 1, 64] {
                let value = trace.documents[usize::from(node.document)].bytes
                    [usize::from(node.content_start) + 1 + offset]
                    .value
                    .value;
                let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
                row[BASE_VALUE] = value;
                populate_der_output_row_v1(&mut row, &trace, Some(node), offset, false).unwrap();
                assert!(OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1.iter().all(|i| *i < 66));
                let before = row;
                assert!(
                    populate_der_output_row_v1(&mut row, &trace, Some(node), 65, false).is_err()
                );
                assert_eq!(row, before);
                row[BASE_VALUE] = value.add(F::ONE);
                assert!(
                    populate_der_output_row_v1(&mut row, &trace, Some(node), offset, false)
                        .is_err()
                );
            }
        }
        let mut absent = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        populate_der_output_row_v1(&mut absent, &trace, None, 64, false).unwrap();
        absent[BASE_VALUE] = F::ONE;
        assert!(populate_der_output_row_v1(&mut absent, &trace, None, 64, false).is_err());
    }
    let key_index = trace.semantic_provenance[0]
        .nodes
        .iter()
        .position(|n| n.role == ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey)
        .unwrap();
    let original = trace.semantic_provenance[0].nodes[key_index];
    for field in 0..7 {
        let node = &mut trace.semantic_provenance[0].nodes[key_index];
        *node = original;
        match field {
            0 => node.content_end -= 1,
            1 => node.content_start = node.content_end + 1,
            2 => node.tag_class = 1,
            3 => node.constructed = true,
            4 => node.tag_number = 4,
            5 => node.document = 1,
            _ => node.role_instance = 1,
        }
        assert!(
            key_output_nodes_v1(&trace).is_err(),
            "source metadata field {field}"
        );
    }
    trace.semantic_provenance[0].nodes[key_index] = original;
    // A second existing node cannot masquerade as the unique selected key.
    let duplicate_index = usize::from(key_index == 0);
    trace.semantic_provenance[0].nodes[duplicate_index].role =
        ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey;
    trace.semantic_provenance[0].nodes[duplicate_index].role_instance = 0;
    assert!(key_output_nodes_v1(&trace).is_err());
}

#[test]
fn key_output_source_rows_compact_without_new_capacity_and_clear_on_error_and_unwind() {
    use crate::privacy_engines::zk_x509::private_table::inspection::observe_v1;
    for fail in [false, true] {
        let ((), observed) = observe_v1(|| {
            let (mut row, _) = key_row_fixture_v1(1, 1, 64);
            // Deterministic replay helpers are populated after compact storage.
            row[66..].fill(F::ZERO);
            let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
            rows.try_reserve_exact(1).unwrap();
            rows.push(row);
            let family = ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize;
            let full_bytes = rows.capacity() * core::mem::size_of::<ZkX509Rfc5280StarkBaseRowV1>();
            let mut families =
                core::array::from_fn(|_| PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1));
            families[family] = rows;
            if fail {
                families[family][0][66] = F::ONE;
            }
            let result = source_rows::compact_families_v1(families, 0);
            if fail {
                assert!(result.is_err());
            } else {
                let compact = result.unwrap();
                assert_eq!(compact[family].initialized_cells_v1(), 66);
                assert_eq!(compact[family].get(0).unwrap(), row);
                assert!(compact[family].allocated_heap_bytes_v1() < full_bytes);
                let _ = std::panic::catch_unwind(|| {
                    let _owner = compact;
                    panic!("key owner unwind");
                });
            }
        });
        assert!(!observed.is_empty());
        assert!(observed.iter().all(|entry| entry.nonzero_after == 0));
    }
}

#[test]
#[ignore = "complete native RFC material and sixteen lookup accumulator columns; run after coordinated adoption"]
fn key_output_complete_source_multiplicity_and_auxiliary_replay_closes() {
    let trace = canonical_trace_v1();
    let nodes = key_output_nodes_v1(&trace).unwrap();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    for node in nodes.iter().flatten() {
        let expected = nodes
            .iter()
            .flatten()
            .filter(|other| other.document == node.document && other.node == node.node)
            .count()
            * 65;
        let source_row = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
            + usize::from(node.document) * 2048
            + usize::from(node.node);
        let row = material.base_row(source_row).unwrap();
        // Serial source nodes have a different fixed grammar role, so this
        // key node has precisely the key-output multiplicity, not an estimate.
        assert_eq!(row[SERIAL_NODE_TABLE_MULTIPLICITY], F(expected as u64));
    }
    let mut table = [F::ZERO; 2];
    let mut queries = [F::ZERO; 2];
    let mut added_node_queries = [F::ZERO; 2];
    let mut key_rows = 0;
    for family in 0..FAMILY_COUNT_V1 {
        for ordinal in 0..material.family_rows[family].len() {
            let index = material.schedule.starts[family] + ordinal;
            let row = material.base_row(index).unwrap();
            let fixed = material.fixed_row(index).unwrap();
            table[0] = table[0].add(
                active_family_gate_v1(&row, &fixed, ZkX509Rfc5280StarkFamilyV1::SourceByte)
                    .mul(row[SERIAL_BYTE_TABLE_MULTIPLICITY]),
            );
            table[1] = table[1].add(
                active_family_gate_v1(&row, &fixed, ZkX509Rfc5280StarkFamilyV1::SourceNode)
                    .mul(row[SERIAL_NODE_TABLE_MULTIPLICITY]),
            );
            queries[0] = queries[0].add(row[BASE_SERIAL_BYTE_QUERY_ACTIVE]);
            let basic_constraints_query = path_len::node_query_gate(&row, &fixed);
            let complete_copy_query = copy_census::node_query_gate(&row, &fixed);
            added_node_queries[0] = added_node_queries[0].add(basic_constraints_query);
            added_node_queries[1] = added_node_queries[1].add(complete_copy_query);
            queries[1] = queries[1]
                .add(active_family_gate_v1(
                    &row,
                    &fixed,
                    ZkX509Rfc5280StarkFamilyV1::SerialSource,
                ))
                .add(output_source_node_query_gate_v1(&row, &fixed))
                .add(basic_constraints_query)
                .add(complete_copy_query);
            if fixed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] == F::ONE {
                assert_eq!(
                    output_source_residues_v1(&row, &fixed),
                    [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                key_rows += usize::from(
                    row[BASE_D] == F::ONE
                        && fixed[FIX_OUTPUT_SOURCE_SPKI] == F::ZERO
                        && fixed[variable_output::FIX_VARIABLE] == F::ZERO
                        && fixed[projection_serial::FIX_SERIAL] == F::ZERO
                        && fixed[projection_disclosure::FIX_DISCLOSURE] == F::ZERO,
                );
            }
        }
    }
    let depth = trace.certificates.len();
    assert!((2..=3).contains(&depth));
    // One signed BC parent per certificate. Equality has 2 * (depth + 1) pairs;
    // each pair and each of the 4 * depth + 3 embedded payloads has two endpoints.
    let equality_endpoints = 4 * (depth + 1);
    let embedded_endpoints = 2 * (4 * depth + 3);
    assert_eq!(
        added_node_queries,
        [
            F(u64::try_from(depth).unwrap()),
            F(u64::try_from(equality_endpoints + embedded_endpoints).unwrap()),
        ]
    );
    assert_eq!(table, queries);
    assert_eq!(
        key_rows,
        if trace.certificates.len() == 3 {
            325
        } else {
            260
        }
    );
    for start in [
        AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR,
        AUX_SERIAL_BYTE_ZERO_ACCUMULATOR,
        AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR,
        AUX_SERIAL_NODE_ZERO_ACCUMULATOR,
    ] {
        for lane in 0..4 {
            let column = PrivateTableV1::new(
                build_zk_x509_rfc5280_stark_aux_column_v1(
                    &material,
                    der_challenges_v1(),
                    &challenges_v1(),
                    start + lane,
                    &ZkX509ShaUnionCentersV1::identity_fixture_v1(),
                )
                .unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(column.len(), 1 << 19);
            assert_eq!(column.first(), Some(&F::ZERO));
            assert_eq!(column.last(), Some(&F::ZERO));
        }
    }
}
