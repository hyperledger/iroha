// Real-material variable DER source controls included in the RFC test module.

const VARIABLE_CHANNELS: [u32; 9] = [5, 7, 9, 21, 23, 12, 15, 18, 25];

#[test]
fn variable_output_public_pair_geometry_covers_every_disclosure_shape() {
    for disclosed in 0..=4 {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = disclosed;
        for i in 0..usize::from(disclosed) {
            shape.disclosed_attribute_indices[i] = i as u8;
        }
        let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let shift = u32::from(disclosed) * 2;
        let mut counts = [[0usize; 2]; 9];
        for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
            let selected = variable_output::slot(shape, entry.channel);
            for (side, family) in [
                ZkX509Rfc5280StarkFamilyV1::OutputProducer,
                ZkX509Rfc5280StarkFamilyV1::OutputConsumer,
            ]
            .into_iter()
            .enumerate()
            {
                let fixed = schedule
                    .fixed_row(schedule.starts[family as usize] + ordinal)
                    .unwrap();
                assert_eq!(
                    fixed[variable_output::FIX_VARIABLE],
                    F(u64::from(side == 0 && selected.is_some()))
                );
                if side == 0
                    && let Some((index, length)) = selected
                {
                    assert_eq!(
                        entry.channel,
                        VARIABLE_CHANNELS[index] + shift + u32::from(length)
                    );
                    assert_eq!(fixed[FIX_OUTPUT_SOURCE_SPKI], F::ZERO);
                    assert_eq!(fixed[FIX_EXPECTED + 6], F::ZERO);
                    counts[index][usize::from(length)] += 1;
                }
            }
        }
        for (index, count) in counts.into_iter().enumerate() {
            assert_eq!(count, [if index < 5 { 4096 } else { 72 }, 8]);
        }
        assert_eq!(variable_output::slot(shape, u32::MAX), None);
    }
    assert_eq!(variable_output::FIX_END, 119);
    assert_eq!(ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1, 147);
}

#[test]
fn variable_output_actual_pairs_bind_counts_lengths_metadata_and_fp4_at_both_depths() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let mut counts = [0usize; 9];
        for (ordinal, entry) in material.schedule.output_topology.iter().enumerate() {
            let Some((slot, length)) =
                variable_output::slot(material.schedule.shape, entry.channel)
            else {
                continue;
            };
            let index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                + ordinal;
            let row = material.base_row(index).unwrap();
            let next = material.base_row(index + 1).unwrap();
            let fixed = material.fixed_row(index).unwrap();
            assert_eq!(
                variable_output::residues(&row, &next, &fixed),
                [F::ZERO; variable_output::RESIDUES],
                "slot={slot} length={length} offset={}",
                entry.offset
            );
            assert_eq!(
                variable_output::residues(
                    &row.map(E::from_base),
                    &next.map(E::from_base),
                    &fixed.map(E::from_base)
                ),
                [E::ZERO; variable_output::RESIDUES]
            );
            assert_eq!(
                output_source_residues_v1(&row, &fixed),
                [F::ZERO; OUTPUT_SOURCE_RESIDUES_V1]
            );
            assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], row[BASE_D]);
            if !length {
                counts[slot] += usize::from(row[BASE_D] == F::ONE);
            }
            if length && entry.offset == 7 {
                assert_eq!(row[BASE_F].0 as usize, counts[slot]);
            }
        }
        for (index, count) in counts.into_iter().enumerate() {
            if trace.certificates.len() == 2 && [2, 7].contains(&index) {
                assert_eq!(count, 0);
            } else {
                assert!(count > 0 && count <= if index < 5 { 4096 } else { 72 });
            }
        }
    }
}

#[test]
fn variable_output_length_padding_prefix_and_node_metadata_mutations_fail_closed() {
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let shift = u32::from(material.schedule.shape.disclosed_attribute_count) * 2;
        for base in VARIABLE_CHANNELS {
            for (channel, offset) in [
                (base, 0),
                (
                    base,
                    if base < 12 || [21, 23].contains(&base) {
                        4095
                    } else {
                        71
                    },
                ),
                (base + 1, 0),
                (base + 1, 1),
                (base + 1, 2),
                (base + 1, 6),
                (base + 1, 7),
            ] {
                let ordinal = material
                    .schedule
                    .output_topology
                    .iter()
                    .position(|e| e.channel == channel + shift && e.offset == offset)
                    .unwrap();
                let index = material.schedule.starts
                    [ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                    + ordinal;
                let row = material.base_row(index).unwrap();
                let next = material.base_row(index + 1).unwrap();
                let fixed = material.fixed_row(index).unwrap();
                for column in [
                    BASE_D,
                    BASE_C,
                    BASE_G,
                    BASE_H,
                    BASE_DOCUMENT,
                    BASE_PARENT,
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
                        variable_output::residues(&changed, &next, &fixed)
                            .iter()
                            .any(|r| *r != F::ZERO),
                        "base={base} channel={channel} offset={offset} column={column}"
                    );
                }
                let (slot, length) =
                    variable_output::slot(material.schedule.shape, channel + shift).unwrap();
                if length || row[BASE_D] == F::ZERO {
                    let mut changed = row;
                    changed[BASE_VALUE] = changed[BASE_VALUE].add(F::ONE);
                    assert!(
                        variable_output::residues(&changed, &next, &fixed)
                            .iter()
                            .any(|r| *r != F::ZERO),
                        "slot={slot} length={length} offset={offset}"
                    );
                }
            }
        }
    }
}

#[test]
fn variable_output_constructors_and_multiplicities_read_original_der_at_both_depths() {
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let nodes = variable_output::nodes(&trace).unwrap();
        assert_eq!(
            core::mem::size_of_val(&nodes),
            9 * core::mem::size_of::<&ZkX509Rfc5280NodeProvenanceV1>()
        );
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        for (index, node) in nodes.into_iter().enumerate() {
            let signature = index >= 5;
            let capacity = if signature { 72 } else { 4096 };
            let (start, length) = node
                .map(|n| {
                    let s = if signature {
                        usize::from(n.content_start) + 1
                    } else {
                        usize::from(n.start)
                    };
                    (s, usize::from(n.content_end) - s)
                })
                .unwrap_or((0, 0));
            for length_row in [false, true] {
                for offset in 0..if length_row { 8 } else { capacity } {
                    let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
                    row[BASE_VALUE] = F(if length_row {
                        u64::from((length as u64).to_be_bytes()[offset])
                    } else if offset < length {
                        trace.documents[usize::from(node.unwrap().document)].bytes[start + offset]
                            .value
                            .value
                            .0
                    } else {
                        0
                    });
                    variable_output::populate_row(
                        &mut row, &trace, node, index, length_row, offset,
                    )
                    .unwrap();
                    assert_eq!(row[BASE_D], F(u64::from(!length_row && offset < length)));
                    row[BASE_VALUE] = row[BASE_VALUE].add(F::ONE);
                    assert!(
                        variable_output::populate_row(
                            &mut row, &trace, node, index, length_row, offset
                        )
                        .is_err()
                    );
                }
            }
            let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
            assert!(
                variable_output::populate_row(&mut row, &trace, node, index, false, capacity)
                    .is_err()
            );
            assert!(variable_output::populate_row(&mut row, &trace, node, index, true, 8).is_err());
            if let Some(node) = node {
                let document = usize::from(node.document);
                let ordinal = usize::from(node.node);
                assert_eq!(
                    variable_output::node_multiplicity(&nodes, document, ordinal),
                    length as u16
                );
                let row_index = material.schedule.starts
                    [ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                    + document * 2048
                    + ordinal;
                assert_eq!(
                    material.base_row(row_index).unwrap()[SERIAL_NODE_TABLE_MULTIPLICITY],
                    F(length as u64)
                );
                for address in [start, usize::from(node.content_end) - 1] {
                    let expected = nodes
                        .iter()
                        .enumerate()
                        .filter(|(i, n)| {
                            n.is_some_and(|n| {
                                let start = if *i >= 5 {
                                    usize::from(n.content_start) + 1
                                } else {
                                    usize::from(n.start)
                                };
                                usize::from(n.document) == document
                                    && start <= address
                                    && address < usize::from(n.content_end)
                            })
                        })
                        .count();
                    assert_eq!(
                        variable_output::byte_multiplicity(&nodes, document, address),
                        expected
                    );
                }
            }
        }
    }
    let mut trace = canonical_trace_v1();
    let index = trace.semantic_provenance[0]
        .nodes
        .iter()
        .position(|n| n.role == ZkX509Rfc5280GrammarRoleV1::CertificateTbs)
        .unwrap();
    let original = trace.semantic_provenance[0].nodes[index];
    for field in 0..7 {
        let node = &mut trace.semantic_provenance[0].nodes[index];
        *node = original;
        match field {
            0 => node.content_end = node.start,
            1 => node.document = 1,
            2 => node.role_instance = 1,
            3 => node.constructed = false,
            4 => node.tag_class = 1,
            5 => node.tag_number = 3,
            _ => node.content_start = node.content_end + 1,
        }
        assert!(variable_output::nodes(&trace).is_err());
    }
}

#[test]
fn variable_output_affine_degree_audit_includes_arbitrary_fixed_selectors() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for seed in [1, 7, 19] {
        let samples = (0..9)
            .map(|point| {
                let row = core::array::from_fn(|i| affine_value_v1(seed, 1, i, point));
                let next = core::array::from_fn(|i| affine_value_v1(seed, 3, i, point));
                let fixed = core::array::from_fn(|i| affine_value_v1(seed, 5, i, point));
                let result = variable_output::residues(&row, &next, &fixed);
                assert_eq!(
                    variable_output::residues(
                        &row.map(E::from_base),
                        &next.map(E::from_base),
                        &fixed.map(E::from_base)
                    ),
                    result.map(E::from_base)
                );
                result
            })
            .collect::<Vec<_>>();
        for column in 0..variable_output::RESIDUES {
            assert!(
                finite_difference_degree_v1(samples.iter().map(|r| r[column]).collect()) <= 4,
                "seed={seed} residue={column}"
            );
        }
    }
    assert_eq!(ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1, 39);
    assert_eq!(
        (
            ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
            ZK_X509_RFC5280_STARK_AUX_WIDTH_V1
        ),
        (285, 280)
    );
}

#[test]
fn variable_output_coherent_shadow_products_cannot_preserve_authenticated_der_boundary() {
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let shift = u32::from(material.schedule.shape.disclosed_attribute_count) * 2;
        for channel in VARIABLE_CHANNELS.map(|channel| channel + shift) {
            let ordinal = material
                .schedule
                .output_topology
                .iter()
                .position(|e| e.channel == channel && e.offset == 0)
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
            let (aux, after) = spki_output_aux_fixture_v1(&row, &fixed, entry.role);
            let evaluate = |current: &ZkX509Rfc5280StarkBaseRowV1,
                            current_aux: &ZkX509Rfc5280StarkAuxRowV1,
                            after: &ZkX509Rfc5280StarkAuxRowV1| {
                evaluate_zk_x509_rfc5280_local_residues_v1(
                    current,
                    &next,
                    current_aux,
                    after,
                    &fixed,
                    der_challenges_v1(),
                    &challenges_v1(),
                )
                .unwrap()
            };
            assert!(evaluate(&row, &aux, &after).iter().all(|v| *v == F::ZERO));
            let mut changed = row;
            let value = u8::try_from(row[BASE_VALUE].0).unwrap() ^ 1;
            changed[BASE_VALUE] = F(u64::from(value));
            write_u8_bits_v1(&mut changed, BASE_BYTE_BITS, value);
            populate_degree_normalization_helpers_v1(&mut changed, &fixed);
            let (repaired_aux, repaired_after) =
                spki_output_aux_fixture_v1(&changed, &fixed, entry.role);
            let mut products_only = after;
            for lane in 0..4 {
                let column =
                    output_role_aux_column_v1(output_role_index_v1(entry.role), false, lane);
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
            let consumer_index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize]
                + ordinal;
            let mut consumer = material.base_row(consumer_index).unwrap();
            let consumer_fixed = material.fixed_row(consumer_index).unwrap();
            consumer[BASE_VALUE] = changed[BASE_VALUE];
            write_u8_bits_v1(&mut consumer, BASE_BYTE_BITS, value);
            populate_degree_normalization_helpers_v1(&mut consumer, &consumer_fixed);
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
fn variable_output_lengths_match_canonical_big_endian_io_at_both_depths() {
    let mut saw_long = false;
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let shape = ZkX509Rfc5280StarkShapeV1::from_statement(&trace.statement).unwrap();
        let channels = rfc5280_io_witnesses_v1(&trace, 0).unwrap();
        let nodes = variable_output::nodes(&trace).unwrap();
        let shift = u32::from(shape.disclosed_attribute_count) * 2;
        for (index, base) in VARIABLE_CHANNELS.into_iter().enumerate() {
            let expected_length = nodes[index].map_or(0, |node| {
                usize::from(node.content_end)
                    - if index >= 5 {
                        usize::from(node.content_start) + 1
                    } else {
                        usize::from(node.start)
                    }
            });
            let data = &channels[(base + shift) as usize];
            let length = &channels[(base + shift + 1) as usize];
            assert_eq!(data.declaration.channel, base + shift);
            assert_eq!(length.declaration.channel, base + shift + 1);
            assert_eq!(data.producer_value.len(), if index < 5 { 4096 } else { 72 });
            assert_eq!(length.producer_value.len(), 8);
            assert_eq!(
                u64::from_be_bytes(length.producer_value.as_slice().try_into().unwrap()),
                expected_length as u64
            );
            assert_eq!(length.producer_value[..6], [0; 6]);
            assert_eq!(length.producer_value[6], (expected_length / 256) as u8);
            assert_eq!(length.producer_value[7], (expected_length % 256) as u8);
            saw_long |= expected_length >= 256;
            for (offset, &value) in length.producer_value.iter().enumerate() {
                let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
                row[BASE_VALUE] = F(u64::from(value));
                variable_output::populate_row(&mut row, &trace, nodes[index], index, true, offset)
                    .unwrap();
            }
        }
    }
    assert!(
        saw_long,
        "real canonical producer fixtures cross the one-byte boundary"
    );
}

#[test]
fn variable_output_big_endian_length_boundary_255_256_257_preserves_every_byte() {
    let trace = spki_maximum_release_trace_v1();
    let nodes = variable_output::nodes(&trace).unwrap();
    let original = *nodes[0].unwrap();
    for length in [255usize, 256, 257] {
        // Constructor-level span fixture only; the real canonical channel test above
        // independently checks complete DER parser output and both chain depths.
        let mut node = original;
        node.content_end = node.start + length as u16;
        assert!(node.content_end > node.content_start);
        let bytes = [0, 0, 0, 0, 0, 0, (length / 256) as u8, (length % 256) as u8];
        let mut rows = vec![[F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]; 8];
        for (offset, row) in rows.iter_mut().enumerate() {
            row[BASE_VALUE] = F(u64::from(bytes[offset]));
            variable_output::populate_row(row, &trace, Some(&node), 0, true, offset).unwrap();
            assert_eq!(
                row[BASE_E],
                F(if offset == 7 {
                    (length / 256 * 256) as u64
                } else {
                    0
                })
            );
            assert_eq!(
                row[BASE_F],
                F(if offset == 6 {
                    (length / 256 * 256) as u64
                } else if offset == 7 {
                    length as u64
                } else {
                    0
                })
            );
            let mut changed = *row;
            changed[BASE_VALUE] = changed[BASE_VALUE].add(F::ONE);
            assert_eq!(
                variable_output::populate_row(&mut changed, &trace, Some(&node), 0, true, offset),
                Err(ZkX509Rfc5280StarkErrorV1::Output)
            );
        }
    }
}
