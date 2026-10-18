// Complete original Name-value census, canonical strings, and coherent shadows.

fn name_value_accepts(mode: u16, bytes: &[u8]) -> bool {
    let mut state = 0;
    for byte in bytes {
        let Some(next) = name_values::transition(mode, state, *byte) else {
            return false;
        };
        state = next;
    }
    state == 0
}

#[test]
fn name_values_transition_matches_independent_unicode_and_printable_policy() {
    for code in 0..=0x0010_ffff {
        let Some(character) = char::from_u32(code) else {
            continue;
        };
        let mut bytes = [0; 4];
        let encoded = character.encode_utf8(&mut bytes).as_bytes();
        assert_eq!(
            name_value_accepts(2, encoded),
            !matches!(code, 0..=31 | 127..=159),
            "{code:x}"
        );
    }
    for first in 0..=255u8 {
        for bytes in [&[first][..], &[first, 0][..]] {
            for last in 0..if bytes.len() == 1 { 1 } else { 256 } {
                let pair = [first, last as u8];
                let input = &pair[..bytes.len()];
                let expected = core::str::from_utf8(input).is_ok_and(|s| {
                    !s.chars()
                        .any(|c| matches!(u32::from(c), 0..=31 | 127..=159))
                });
                assert_eq!(name_value_accepts(2, input), expected, "{input:?}");
            }
        }
        let printable = first.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&first);
        assert_eq!(name_value_accepts(0, &[first]), first.is_ascii_uppercase());
        assert_eq!(name_value_accepts(1, &[first]), printable);
        assert_eq!(name_values::transition(3, 0, first), None);
    }
    for bad in [
        &[0xe0, 0x9f, 0xbf][..],
        &[0xed, 0xa0, 0x80],
        &[0xf0, 0x8f, 0xbf, 0xbf],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xf5, 0x80, 0x80, 0x80],
        &[0xc2, 0x9f],
        &[0xe1, 0x80],
    ] {
        assert!(!name_value_accepts(2, bad), "{bad:?}");
    }
    let mut entries = Vec::new();
    name_values::append_table(&mut entries);
    for mode in 0..3 {
        for before in 0..9 {
            for byte in 0..=255u8 {
                let found = entries
                    .iter()
                    .filter(|e| e.variant == mode && e.offset == before && e.expected == byte)
                    .collect::<Vec<_>>();
                match name_values::transition(mode, before, byte) {
                    Some(after) => {
                        assert_eq!(found.len(), 1);
                        assert_eq!(found[0].length, after);
                        assert_eq!(found[0].purpose, name_values::PURPOSE);
                        assert_eq!(
                            found[0].source_role,
                            ZkX509Rfc5280GrammarRoleV1::NameAttributeValue as u16
                        );
                        assert!(found[0].contents_only && found[0].exact_end);
                    }
                    None => assert!(found.is_empty()),
                }
            }
        }
    }
}

#[test]
fn name_values_actual_complete_census_binds_bytes_nodes_oid_and_profile_at_both_depths() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let nodes = role_nodes_v1(&trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeValue)
            .collect::<Vec<_>>();
        let count: usize = nodes
            .iter()
            .map(|n| usize::from(n.content_end - n.content_start))
            .sum();
        assert_eq!(name_values::private_count(&trace).unwrap(), count);
        let family = ZkX509Rfc5280StarkFamilyV1::NameValue as usize;
        assert_eq!(material.family_rows[family].len(), count);
        let mut original = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
        name_values::populate_rows(&trace, &mut original).unwrap();
        let mut first_count = 0;
        let mut queries = 0;
        for entry in &material.schedule.profile_byte_table {
            queries += name_values::profile_multiplicity(&original, *entry);
        }
        assert_eq!(queries, count);
        for ordinal in 0..count {
            let position = material.schedule.starts[family] + ordinal;
            let row = material.base_row(position).unwrap();
            let next = material.base_row(position + 1).unwrap();
            let fixed = material.fixed_row(position).unwrap();
            assert_eq!(
                name_values::residues(&row, &next, &fixed),
                [F::ZERO; name_values::RESIDUES],
                "{ordinal}"
            );
            assert_eq!(
                name_values::residues(
                    &row.map(E::from_base),
                    &next.map(E::from_base),
                    &fixed.map(E::from_base)
                ),
                [E::ZERO; name_values::RESIDUES]
            );
            let source = trace.documents[row[BASE_DOCUMENT].0 as usize].bytes
                [row[BASE_ADDRESS].0 as usize]
                .value
                .value;
            assert_eq!(row[BASE_VALUE], source);
            // Independently retain the old mathematical zero/inverse values at
            // the actual private country, first-byte and last-byte boundaries.
            let offset = row[BASE_ADDRESS].sub(row[BASE_DEPTH]);
            let remaining = row[BASE_TAG_NUMBER].sub(row[BASE_ADDRESS]).sub(F::ONE);
            assert_eq!(row[BASE_A], row[BASE_G].inv().unwrap_or(F::ZERO));
            assert_eq!(row[BASE_D], remaining.inv().unwrap_or(F::ZERO));
            assert_eq!(row[BASE_INVERSE], offset.inv().unwrap_or(F::ZERO));
            assert_eq!(row[BASE_SERIAL_BYTE_QUERY_VALUE], source);
            assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], F::ONE);
            assert_eq!(
                name_values::byte_multiplicity(
                    &trace,
                    row[BASE_DOCUMENT].0 as usize,
                    row[BASE_ADDRESS].0 as usize
                ),
                1
            );
            assert!(
                material
                    .schedule
                    .profile_byte_table
                    .iter()
                    .any(|e| e.purpose == name_values::PURPOSE
                        && e.variant == row[BASE_ENDPOINT_ROLE].0 as u16
                        && e.offset == row[BASE_OFFSET].0 as u16
                        && e.length == row[BASE_B].0 as u16
                        && e.expected == row[BASE_VALUE].0 as u8)
            );
            if row[BASE_IS_WRITE] == F::ONE {
                first_count += 1;
                let node_position = material.schedule.starts
                    [ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                    + row[BASE_DOCUMENT].0 as usize * 2048
                    + row[BASE_NODE].0 as usize;
                let node = material.base_row(node_position).unwrap();
                assert_eq!(node[BASE_INVERSE], F::ONE);
                let oid = (0..material.family_rows[ZkX509Rfc5280StarkFamilyV1::FixedByte as usize]
                    .len())
                    .find_map(|i| {
                        let r = material
                            .base_row(
                                material.schedule.starts
                                    [ZkX509Rfc5280StarkFamilyV1::FixedByte as usize]
                                    + i,
                            )
                            .unwrap();
                        (r[BASE_E] == F::ONE
                            && r[BASE_DOCUMENT] == row[BASE_DOCUMENT]
                            && r[BASE_H] == row[BASE_H])
                            .then_some(r)
                    })
                    .unwrap();
                for lane in 0..4 {
                    assert_eq!(
                        profile_topology_source_factor_v1(&node, lane, &challenges_v1()),
                        profile_topology_query_factor_v1(&row, lane, &challenges_v1())
                    );
                    assert_eq!(
                        normalized_copy_factor_v1(&oid, lane, &challenges_v1()),
                        normalized_copy_factor_v1(&row, lane, &challenges_v1())
                    );
                }
            }
        }
        assert_eq!(first_count, nodes.len());
        original.clear();
        assert!(original.is_empty());
    }
    assert_eq!(ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1, 147);
    assert_eq!(ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1, 39);
}

#[test]
fn name_values_constructor_rejects_original_country_control_tag_length_and_oid_changes() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let family = ZkX509Rfc5280StarkFamilyV1::NameValue as usize;
    let first = (0..material.family_rows[family].len())
        .map(|i| {
            material
                .base_row(material.schedule.starts[family] + i)
                .unwrap()
        })
        .find(|r| r[BASE_IS_WRITE] == F::ONE && r[BASE_G] == F::ZERO)
        .unwrap();
    let document = first[BASE_DOCUMENT].0 as usize;
    let node_id = first[BASE_NODE].0 as u16;
    for mutation in 0..7 {
        let mut changed = trace.clone();
        let node = changed.semantic_provenance[document]
            .nodes
            .iter_mut()
            .find(|n| n.node == node_id)
            .unwrap();
        match mutation {
            0 => {
                changed.documents[document].bytes[usize::from(node.content_start)]
                    .value
                    .value = F(u64::from(b'a'))
            }
            1 => {
                changed.documents[document].bytes[usize::from(node.content_start)]
                    .value
                    .value = F(0x7f)
            }
            2 => node.tag_number = 12,
            3 => node.content_end = node.content_start,
            4 => node.content_end = node.content_start + 257,
            5 => node.role_instance += 1,
            6 => node.parent_node += 1,
            _ => unreachable!(),
        }
        let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
        assert!(
            name_values::populate_rows(&changed, &mut rows).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn name_values_boundaries_metadata_and_coherent_byte_node_oid_shadows_are_rejected() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let family = ZkX509Rfc5280StarkFamilyV1::NameValue as usize;
    let position = material.schedule.starts[family];
    let row = material.base_row(position).unwrap();
    let next = material.base_row(position + 1).unwrap();
    let fixed = material.fixed_row(position).unwrap();
    assert_eq!(row[BASE_IS_WRITE], F::ONE);
    assert_eq!(row[BASE_STRICT], F::ZERO);
    for column in [
        BASE_ROLE,
        BASE_A,
        BASE_PARENT,
        BASE_ENDPOINT_INSTANCE,
        BASE_CHILD,
        BASE_INSTANCE,
        BASE_IS_WRITE,
        BASE_STRICT,
        BASE_OFFSET,
        BASE_TAG_CLASS,
        BASE_E,
        BASE_SMALL_BITS,
    ] {
        let mut changed = row;
        changed[column] = changed[column].add(F::ONE);
        assert!(
            name_values::residues(&changed, &next, &fixed)
                .iter()
                .any(|r| *r != F::ZERO),
            "column={column}"
        );
    }
    for column in [
        BASE_DOCUMENT,
        BASE_NODE,
        BASE_H,
        BASE_G,
        BASE_CONTENT_START,
        BASE_DEPTH,
        BASE_TAG_NUMBER,
        BASE_TAG_CLASS,
        BASE_ENDPOINT_ROLE,
        BASE_INSTANCE,
        BASE_ADDRESS,
        BASE_OFFSET,
    ] {
        let mut changed = next;
        changed[column] = changed[column].add(F::ONE);
        assert!(
            name_values::residues(&row, &changed, &fixed)
                .iter()
                .any(|r| *r != F::ZERO),
            "next={column}"
        );
    }
    // A different valid uppercase byte preserves all local DFA equations and
    // every surrounding witness, but cannot match the original source byte.
    let mut shadow = row;
    shadow[BASE_VALUE] = if row[BASE_VALUE] == F(u64::from(b'X')) {
        F(u64::from(b'Y'))
    } else {
        F(u64::from(b'X'))
    };
    let shadow_byte = shadow[BASE_VALUE].0 as u8;
    write_u8_bits_v1(&mut shadow, BASE_BYTE_BITS, shadow_byte);
    populate_degree_normalization_helpers_v1(&mut shadow, &fixed);
    assert_eq!(
        name_values::residues(&shadow, &next, &fixed),
        [F::ZERO; name_values::RESIDUES]
    );
    for lane in 0..4 {
        assert_ne!(
            serial_byte_lookup_factor_v1(
                row[BASE_DOCUMENT],
                row[BASE_ADDRESS],
                row[BASE_VALUE],
                lane,
                &challenges_v1()
            ),
            serial_byte_lookup_factor_v1(
                shadow[BASE_DOCUMENT],
                shadow[BASE_ADDRESS],
                shadow[BASE_VALUE],
                lane,
                &challenges_v1()
            )
        );
        for column in [BASE_NODE, BASE_H, BASE_TAG_CLASS] {
            let mut changed = row;
            changed[column] = changed[column].add(F::ONE);
            assert_ne!(
                profile_topology_query_factor_v1(&row, lane, &challenges_v1()),
                profile_topology_query_factor_v1(&changed, lane, &challenges_v1())
            );
        }
        let mut changed = row;
        changed[BASE_G] = changed[BASE_G].add(F::ONE);
        populate_degree_normalization_helpers_v1(&mut changed, &fixed);
        assert_ne!(
            normalized_copy_factor_v1(&row, lane, &challenges_v1()),
            normalized_copy_factor_v1(&changed, lane, &challenges_v1())
        );
    }
}

#[test]
fn name_values_every_opened_input_has_affine_degree_at_most_four() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    for seed in [2, 7, 23] {
        let samples = (0..9)
            .map(|point| {
                let row = core::array::from_fn(|i| affine_value_v1(seed, 1, i, point));
                let next = core::array::from_fn(|i| affine_value_v1(seed, 3, i, point));
                let fixed = core::array::from_fn(|i| affine_value_v1(seed, 5, i, point));
                let result = name_values::residues(&row, &next, &fixed);
                assert_eq!(
                    name_values::residues(
                        &row.map(E::from_base),
                        &next.map(E::from_base),
                        &fixed.map(E::from_base)
                    ),
                    result.map(E::from_base)
                );
                result
            })
            .collect::<Vec<_>>();
        for column in 0..name_values::RESIDUES {
            assert!(
                finite_difference_degree_v1(samples.iter().map(|r| r[column]).collect()) <= 4,
                "column={column}"
            );
        }
    }
}

#[test]
fn name_values_new_private_count_and_stored_rows_are_cleared() {
    let trace = canonical_trace_v1();
    let mut material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    assert!(material.private_shape.name_value_rows > 0);
    assert!(!material.family_rows[ZkX509Rfc5280StarkFamilyV1::NameValue as usize].is_empty());
    material.zeroize_private_v1();
    assert_eq!(material.private_shape.name_value_rows, 0);
    assert!(material.private_is_zeroized_v1());
    material.private_shape.name_value_rows = 1;
    assert!(!material.private_is_zeroized_v1());
}

#[test]
fn name_values_public_boundaries_do_not_replace_private_string_boundaries() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let family = ZkX509Rfc5280StarkFamilyV1::NameValue as usize;
    let count = material.family_rows[family].len();
    assert!(count > 2 && count < name_values::ROWS);
    for ordinal in 0..name_values::ROWS {
        let position = material.schedule.starts[family] + ordinal;
        let fixed = material.fixed_row(position).unwrap();
        assert_eq!(fixed[FIX_LOCAL_FIRST], F(u64::from(ordinal == 0)));
        assert_eq!(
            fixed[FIX_LOCAL_LAST],
            F(u64::from(ordinal + 1 == name_values::ROWS))
        );
        assert_eq!(
            fixed[FIX_ACTIVATION_CONTINUE],
            F(u64::from(ordinal + 1 != name_values::ROWS))
        );
        if [0, 1, count - 1, count, name_values::ROWS - 1].contains(&ordinal) {
            let row = material.base_row(position).unwrap();
            let next = material.base_row(position + 1).unwrap();
            assert_eq!(
                name_values::residues(&row, &next, &fixed),
                [F::ZERO; name_values::RESIDUES]
            );
            assert_eq!(row[BASE_ACTIVE], F(u64::from(ordinal < count)));
        }
    }
    let first = material.base_row(material.schedule.starts[family]).unwrap();
    assert_eq!(first[BASE_IS_WRITE], F::ONE);
    assert_eq!(first[BASE_STRICT], F::ZERO);
}
