// Complete SPKI source controls, included in the RFC test module. These exercise
// the local AIR and authenticated lookup boundary, not a complete forged proof.

fn spki_maximum_release_trace_v1() -> ZkX509Rfc5280TraceV1 {
    use crate::privacy_engines::zk_x509::{
        relation::release_fixture::{
            build_zk_x509_release_fixture_v1, reference_statement_context_v1,
        },
        verifier_profile::rfc_statement_with_crl_number_v1,
    };
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true).unwrap();
    assert_eq!(fixture.witness.certificate_chain_der.len(), 3);
    assert_eq!(fixture.crl_entry_count, 64);
    assert_eq!(fixture.statement.disclosed_attributes.len(), 4);
    let trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        rfc_statement_with_crl_number_v1(
            &fixture.statement,
            fixture.authoritative_state.crl_record().crl_number,
        ),
    )
    .unwrap();
    assert_eq!(trace.certificates.len(), 3);
    assert_eq!(trace.statement.disclosed_attribute_indices.len(), 4);
    trace
}

fn spki_row_fixture_v1(
    slot: usize,
    cert2: u64,
    offset: usize,
) -> (ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkFixedRowV1) {
    let shape = ZkX509Rfc5280StarkShapeV1::default();
    let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
    let channel = [0_u32, 1, 2, 29, 30][slot];
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
    for (index, column) in metadata_columns_v1().into_iter().enumerate() {
        row[column] = fixed[FIX_EXPECTED + index];
    }
    let (optional, document, coefficient) = SPKI_OUTPUT_SOURCES_V1[slot];
    if optional == 0 || cert2 == 1 {
        let value = if offset == 0 {
            0x30
        } else {
            (55 + offset) as u8
        };
        row[BASE_VALUE] = F(u64::from(value));
        write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
        row[BASE_D] = F::ONE;
        row[BASE_A] = F(89);
        row[BASE_G] = F(14);
        row[BASE_H] = F(document + coefficient * cert2);
        row[BASE_DOCUMENT] = row[BASE_H];
        row[BASE_NODE] = F(6);
        row[BASE_START] = F(100);
        row[BASE_CONTENT_START] = F(102);
        row[BASE_CONTENT_END] = F(191);
        row[BASE_ADDRESS] = F(100 + offset as u64);
        row[BASE_CONSTRUCTED] = F::ONE;
        row[BASE_TAG_NUMBER] = F(16);
    }
    (normalized_row_v1(row, &fixed), fixed)
}

#[test]
fn spki_output_schedule_binds_all_five_channels_offsets_and_source_documents() {
    for disclosed in 0..=4_u8 {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = disclosed;
        for i in 0..usize::from(disclosed) {
            shape.disclosed_attribute_indices[i] = i as u8;
        }
        let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let mut counts = [0_usize; 5];
        for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
            for consumer in [false, true] {
                let family = if consumer {
                    ZkX509Rfc5280StarkFamilyV1::OutputConsumer
                } else {
                    ZkX509Rfc5280StarkFamilyV1::OutputProducer
                };
                let fixed = schedule
                    .fixed_row(schedule.starts[family as usize] + ordinal)
                    .unwrap();
                let slot = spki_output_slot_v1(shape, entry.channel);
                assert_eq!(
                    fixed[FIX_OUTPUT_SOURCE_SPKI],
                    F(u64::from(slot.is_some() && !consumer))
                );
                if let Some(slot) = slot
                    && !consumer
                {
                    counts[slot] += 1;
                    assert!(entry.offset < 91);
                    assert_eq!(
                        entry.role,
                        if slot < 3 {
                            ZkX509Rfc5280OutputRoleV1::Projection
                        } else if slot == 3 {
                            ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha
                        } else {
                            ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor
                        }
                    );
                    let (optional, document, coefficient) = SPKI_OUTPUT_SOURCES_V1[slot];
                    assert_eq!(
                        &fixed[FIX_EXPECTED + 6..FIX_EXPECTED + 10],
                        &[F::ONE, F(optional), F(document), F(coefficient)]
                    );
                }
            }
        }
        assert_eq!(counts, [91; 5]);
        assert_eq!(spki_output_slot_v1(shape, u32::MAX), None);
    }
    assert_eq!(FIX_OUTPUT_SOURCE_SPKI + 1, variable_output::FIX_VARIABLE);
    const { assert!(FIX_OUTPUT_SOURCE_SPKI > FIX_RANGE_HIGH_BITS_ZERO) };
}

#[test]
fn spki_output_local_air_all_bytes_both_depths_and_fp4_are_exact() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for cert2 in 0..=1 {
        let mut live = 0;
        for slot in 0..5 {
            for offset in 0..91 {
                let (row, fixed) = spki_row_fixture_v1(slot, cert2, offset);
                assert_eq!(
                    output_source_residues_v1(&row, &fixed),
                    [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                assert_eq!(
                    output_source_residues_v1(&row.map(E::from_base), &fixed.map(E::from_base)),
                    [E::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
                );
                assert_eq!(output_metadata_residues_v1(&row, &fixed), [F::ZERO; 6]);
                assert_eq!(output_source_query_gate_v1(&row, &fixed), row[BASE_D]);
                assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], row[BASE_D]);
                assert_eq!(row[BASE_SERIAL_BYTE_QUERY_VALUE], row[BASE_VALUE]);
                live += usize::from(row[BASE_D] == F::ONE);
            }
        }
        assert_eq!(live, if cert2 == 0 { 364 } else { 455 });
    }
    let (absent, fixed) = spki_row_fixture_v1(2, 0, 90);
    for column in OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1
        .into_iter()
        .chain([BASE_D, BASE_VALUE])
    {
        let mut changed = absent;
        changed[column] = F::ONE;
        assert!(
            output_source_residues_v1(&changed, &fixed)
                .iter()
                .any(|value| *value != F::ZERO)
        );
    }
}

#[test]
fn spki_output_node_length_role_and_address_cannot_redirect_source() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    let (row, fixed) = spki_row_fixture_v1(4, 1, 90);
    for column in [
        BASE_D,
        BASE_DOCUMENT,
        BASE_G,
        BASE_H,
        BASE_TAG_CLASS,
        BASE_CONSTRUCTED,
        BASE_TAG_NUMBER,
        BASE_A,
        BASE_CONTENT_START,
        BASE_CONTENT_END,
        BASE_START,
        BASE_ADDRESS,
    ] {
        let mut changed = row;
        changed[column] = changed[column].add(F::ONE);
        assert!(
            output_source_residues_v1(&changed, &fixed)
                .iter()
                .any(|value| *value != F::ZERO),
            "local source column {column}"
        );
        let mut changed = row.map(E::from_base);
        changed[column] = changed[column].add(E::canonical([0, 1, 3, 5]).unwrap());
        assert!(
            output_source_residues_v1(&changed, &fixed.map(E::from_base))
                .iter()
                .any(|value| *value != E::ZERO)
        );
    }
    let mut redirected = row;
    for column in [
        BASE_START,
        BASE_CONTENT_START,
        BASE_CONTENT_END,
        BASE_ADDRESS,
    ] {
        redirected[column] = redirected[column].add(F(91));
    }
    assert_eq!(
        output_source_residues_v1(&redirected, &fixed),
        [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
    );
    // Coherent local address shifts must still authenticate the original DER node.
    for lane in 0..4 {
        assert_ne!(
            node_query_factor_v1(&redirected, &fixed, lane, &challenges_v1()),
            node_query_factor_v1(&row, &fixed, lane, &challenges_v1())
        );
        assert_ne!(
            serial_byte_lookup_factor_v1(
                redirected[BASE_DOCUMENT],
                redirected[BASE_ADDRESS],
                redirected[BASE_VALUE],
                lane,
                &challenges_v1()
            ),
            serial_byte_lookup_factor_v1(
                row[BASE_DOCUMENT],
                row[BASE_ADDRESS],
                row[BASE_VALUE],
                lane,
                &challenges_v1()
            )
        );
    }
}

#[test]
fn spki_output_constructor_reads_complete_der_and_rejects_noncanonical_sources() {
    let ordinary = canonical_trace_v1();
    assert_eq!(ordinary.certificates.len(), 2);
    assert_spki_constructor_sources_v1(ordinary);
    assert_spki_constructor_sources_v1(spki_maximum_release_trace_v1());
}

fn assert_spki_constructor_sources_v1(mut trace: ZkX509Rfc5280TraceV1) {
    {
        let nodes = spki_output_nodes_v1(&trace).unwrap();
        let cert2 = usize::from(trace.certificates.len() == 3);
        assert_eq!(
            nodes.map(|node| node.map(|node| usize::from(node.document))),
            [
                Some(0),
                Some(1),
                (cert2 == 1).then_some(2),
                Some(1),
                Some(1 + cert2)
            ]
        );
        assert_eq!(
            core::mem::size_of_val(&nodes),
            5 * core::mem::size_of::<&ZkX509Rfc5280NodeProvenanceV1>()
        );
        for node in nodes.into_iter().flatten() {
            for offset in 0..91 {
                let value = trace.documents[usize::from(node.document)].bytes
                    [usize::from(node.start) + offset]
                    .value
                    .value;
                let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
                row[BASE_VALUE] = value;
                populate_der_output_row_v1(&mut row, &trace, Some(node), offset, true).unwrap();
                assert_eq!(row[BASE_ADDRESS], F(u64::from(node.start) + offset as u64));
                assert_eq!(row[BASE_A], F(89));
                let before = row;
                assert!(
                    populate_der_output_row_v1(&mut row, &trace, Some(node), 91, true).is_err()
                );
                assert_eq!(row, before);
                row[BASE_VALUE] = value.add(F::ONE);
                assert!(
                    populate_der_output_row_v1(&mut row, &trace, Some(node), offset, true).is_err()
                );
            }
        }
        let mut absent = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        populate_der_output_row_v1(&mut absent, &trace, None, 90, true).unwrap();
        absent[BASE_VALUE] = F::ONE;
        assert!(populate_der_output_row_v1(&mut absent, &trace, None, 90, true).is_err());
    }
    let index = trace.semantic_provenance[0]
        .nodes
        .iter()
        .position(|node| node.role == ZkX509Rfc5280GrammarRoleV1::CertificateSpki)
        .unwrap();
    let original = trace.semantic_provenance[0].nodes[index];
    for field in 0..8 {
        let node = &mut trace.semantic_provenance[0].nodes[index];
        *node = original;
        match field {
            0 => node.start += 1,
            1 => node.content_start += 1,
            2 => node.content_end -= 1,
            3 => node.tag_class = 1,
            4 => node.constructed = false,
            5 => node.tag_number = 17,
            6 => node.document = 1,
            _ => node.role_instance = 1,
        }
        assert!(
            spki_output_nodes_v1(&trace).is_err(),
            "source field {field}"
        );
    }
    trace.semantic_provenance[0].nodes[index] = original;
    let duplicate = usize::from(index == 0);
    trace.semantic_provenance[0].nodes[duplicate].role =
        ZkX509Rfc5280GrammarRoleV1::CertificateSpki;
    trace.semantic_provenance[0].nodes[duplicate].role_instance = 0;
    assert!(spki_output_nodes_v1(&trace).is_err());
}

fn spki_output_aux_fixture_v1(
    row: &ZkX509Rfc5280StarkBaseRowV1,
    fixed: &ZkX509Rfc5280StarkFixedRowV1,
    role: ZkX509Rfc5280OutputRoleV1,
) -> (ZkX509Rfc5280StarkAuxRowV1, ZkX509Rfc5280StarkAuxRowV1) {
    let challenges = challenges_v1();
    let mut current = neutral_aux_v1();
    let mut next = neutral_aux_v1();
    for lane in 0..4 {
        next[output_role_aux_column_v1(output_role_index_v1(role), false, lane)] =
            output_role_product_factor_v1(row, output_role_index_v1(role), false, lane, &challenges);
        for (factor, zero, inverse, sum, zero_sum) in [
            (
                serial_byte_lookup_factor_v1(
                    row[BASE_DOCUMENT],
                    row[BASE_ADDRESS],
                    row[BASE_SERIAL_BYTE_QUERY_VALUE],
                    lane,
                    &challenges,
                ),
                AUX_SERIAL_BYTE_QUERY_ZERO,
                AUX_SERIAL_BYTE_QUERY_INVERSE,
                AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR,
                AUX_SERIAL_BYTE_ZERO_ACCUMULATOR,
            ),
            (
                node_query_factor_v1(row, fixed, lane, &challenges),
                AUX_SERIAL_NODE_QUERY_ZERO,
                AUX_SERIAL_NODE_QUERY_INVERSE,
                AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR,
                AUX_SERIAL_NODE_ZERO_ACCUMULATOR,
            ),
        ] {
            let (z, inv) = zero_safe_inverse_v1(row[BASE_D], factor);
            current[zero + lane] = z;
            current[inverse + lane] = inv;
            next[sum + lane] = F::ZERO.sub(inv);
            next[zero_sum + lane] = F::ZERO.sub(z);
        }
    }
    (current, next)
}

#[test]
fn spki_shadow_products_cannot_preserve_original_authenticated_der_lookup_boundary() {
    let ordinary = canonical_trace_v1();
    assert_eq!(ordinary.certificates.len(), 2);
    assert_spki_coherent_shadow_v1(ordinary);
    assert_spki_coherent_shadow_v1(spki_maximum_release_trace_v1());
}

fn assert_spki_coherent_shadow_v1(trace: ZkX509Rfc5280TraceV1) {
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let shift = u32::from(material.schedule.shape.disclosed_attribute_count) * 2;
    for channel in [0_u32, 1, 2, 29 + shift, 30 + shift] {
        for offset in [0_u32, 2, 90] {
            let ordinal = material
                .schedule
                .output_topology
                .iter()
                .position(|entry| entry.channel == channel && entry.offset == offset)
                .unwrap();
            let entry = material.schedule.output_topology[ordinal];
            let index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                + ordinal;
            let row = material.base_row(index).unwrap();
            let next = material.base_row(index + 1).unwrap();
            let fixed = material.fixed_row(index).unwrap();
            if row[BASE_D] == F::ZERO {
                continue;
            }
            assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], F::ONE);
            assert_eq!(output_source_query_gate_v1(&row, &fixed), F::ONE);
            let (aux, after) = spki_output_aux_fixture_v1(&row, &fixed, entry.role);
            let baseline = evaluate_zk_x509_rfc5280_local_residues_v1(
                &row,
                &next,
                &aux,
                &after,
                &fixed,
                der_challenges_v1(),
                &challenges_v1(),
            )
            .unwrap();
            assert!(
                baseline.iter().all(|value| *value == F::ZERO),
                "baseline channel={channel} offset={offset}"
            );
            let mut changed = row;
            let value = u8::try_from(row[BASE_VALUE].0).unwrap() ^ 1;
            changed[BASE_VALUE] = F(u64::from(value));
            write_u8_bits_v1(&mut changed, BASE_BYTE_BITS, value);
            populate_degree_normalization_helpers_v1(&mut changed, &fixed);
            let (repaired_aux, repaired_after) =
                spki_output_aux_fixture_v1(&changed, &fixed, entry.role);
            let mut products_only = after;
            for lane in 0..4 {
                let product =
                    output_role_aux_column_v1(output_role_index_v1(entry.role), false, lane);
                products_only[product] = repaired_after[product];
            }
            let residues = evaluate_zk_x509_rfc5280_local_residues_v1(
                &changed,
                &next,
                &aux,
                &products_only,
                &fixed,
                der_challenges_v1(),
                &challenges_v1(),
            )
            .unwrap();
            assert!(
                residues.iter().any(|value| *value != F::ZERO),
                "shadow channel={channel} offset={offset}"
            );
            // Repairing the reciprocal can satisfy this local row, but changes
            // the original source-authenticated endpoint. It cannot be hidden
            // solely by changing matching producer/consumer output products.
            let local = evaluate_zk_x509_rfc5280_local_residues_v1(
                &changed,
                &next,
                &repaired_aux,
                &repaired_after,
                &fixed,
                der_challenges_v1(),
                &challenges_v1(),
            )
            .unwrap();
            assert!(local.iter().all(|value| *value == F::ZERO));
            let consumer_index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize]
                + ordinal;
            let mut consumer = material.base_row(consumer_index).unwrap();
            let consumer_fixed = material.fixed_row(consumer_index).unwrap();
            consumer[BASE_VALUE] = changed[BASE_VALUE];
            write_u8_bits_v1(&mut consumer, BASE_BYTE_BITS, value);
            populate_degree_normalization_helpers_v1(&mut consumer, &consumer_fixed);
            assert_eq!(
                output_metadata_residues_v1(&consumer, &consumer_fixed),
                [F::ZERO; 6]
            );
            for lane in 0..4 {
                assert_ne!(
                    (
                        repaired_after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                        repaired_after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                    ),
                    (
                        after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                        after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                    )
                );
                assert_eq!(
                    repaired_after[AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR + lane],
                    after[AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR + lane]
                );
                assert_eq!(
                    output_role_product_factor_v1(
                        &changed,
                        output_role_index_v1(entry.role),
                        false,
                        lane,
                        &challenges_v1()
                    ),
                    output_role_product_factor_v1(
                        &consumer,
                        output_role_index_v1(entry.role),
                        true,
                        lane,
                        &challenges_v1()
                    )
                );
            }
        }
    }
}

#[test]
fn spki_complete_source_multiplicity_counts_exact_shared_node_and_byte_owners() {
    let ordinary = canonical_trace_v1();
    assert_eq!(ordinary.certificates.len(), 2);
    assert_spki_complete_multiplicities_v1(ordinary);
    assert_spki_complete_multiplicities_v1(spki_maximum_release_trace_v1());
}

fn assert_spki_complete_multiplicities_v1(trace: ZkX509Rfc5280TraceV1) {
    let nodes = spki_output_nodes_v1(&trace).unwrap();
    let key_nodes = key_output_nodes_v1(&trace).unwrap();
    let variable_nodes = variable_output::nodes(&trace).unwrap();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    for node in nodes.iter().flatten() {
        let count = nodes
            .iter()
            .flatten()
            .filter(|other| other.document == node.document && other.node == node.node)
            .count();
        let index = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
            + usize::from(node.document) * 2048
            + usize::from(node.node);
        assert_eq!(
            material.base_row(index).unwrap()[SERIAL_NODE_TABLE_MULTIPLICITY],
            F((count * 91) as u64)
        );
    }
    // These whole-SPKI header bytes are outside public-key, serial, name and
    // semantic fixed-content queries. The two typed SPKI header bytes are
    // authenticated by the DER node relation; complete TBS outputs also query them.
    for node in nodes.iter().flatten() {
        let document = usize::from(node.document);
        let address = usize::from(node.start);
        assert!(key_nodes.iter().flatten().all(
            |key| key.document != node.document || address < usize::from(key.content_start) + 1
        ));
        let expected = nodes
            .iter()
            .flatten()
            .filter(|other| other.document == node.document && other.start == node.start)
            .count();
        let index = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceByte as usize]
            + document * 4096
            + address;
        assert_eq!(
            material.base_row(index).unwrap()[SERIAL_BYTE_TABLE_MULTIPLICITY],
            F(
                (expected + variable_output::byte_multiplicity(&variable_nodes, document, address))
                    as u64
            )
        );
    }
}
