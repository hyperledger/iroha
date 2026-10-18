//! Canonical-u32, source provenance and adversarial row controls for `BasicConstraints`.
use super::*;

const BOUNDARIES: [u32; 19] = [
    0,
    1,
    2,
    127,
    128,
    255,
    256,
    32_767,
    32_768,
    65_535,
    65_536,
    0x7f_ffff,
    0x80_0000,
    0xff_ffff,
    0x100_0000,
    0x7fff_ffff,
    0x8000_0000,
    u32::MAX - 1,
    u32::MAX,
];
type Rows = [ZkX509Rfc5280StarkBaseRowV1; ROWS_PER_SLOT];
type Fixed = [ZkX509Rfc5280StarkFixedRowV1; ROWS_PER_SLOT];

// Local algebra fixtures deliberately bypass signatures/source lookup. The
// separate genuine-source and signed release tests cover those obligations.
fn local_rows(slot: usize, value: Option<u32>, present: bool) -> (Rows, Fixed, Vec<u8>) {
    let encoded = encode_basic_constraints_v1(slot != 0, value).unwrap();
    let number = value.unwrap_or(0);
    let bytes = number.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let magnitude = 4 - first;
    let sign = usize::from(bytes[first] & 0x80 != 0);
    let length = if slot == 0 { 0 } else { magnitude + sign };
    let slack = number.wrapping_sub(slot.saturating_sub(1) as u32);
    let fixed = core::array::from_fn(|offset| {
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize] = F::ONE;
        populate_fixed(&mut fixed, slot * ROWS_PER_SLOT + offset);
        fixed
    });
    let rows = core::array::from_fn(|offset| {
        let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        row[BASE_CERT2_ACTIVE] = F(u64::from(slot == 2 && present));
        if !present {
            return row;
        }
        row[BASE_ACTIVE] = F::ONE;
        row[BASE_DOCUMENT] = F(slot as u64);
        row[BASE_NODE] = F(37);
        row[BASE_START] = F(71);
        row[BASE_CONTENT_START] = F(73);
        row[BASE_CONTENT_END] = F(73 + encoded.len() as u64);
        row[BASE_A] = F(encoded.len() as u64);
        row[BASE_B] = F(length as u64);
        row[BASE_E] = F(u64::from(number));
        row[BASE_F] = F(u64::from(slack));
        row[BASE_ROLE] = F(ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue as u64);
        row[BASE_INSTANCE] = F(3);
        row[BASE_TAG_NUMBER] = F(4);
        row[BASE_IS_WRITE] = F(u64::from(offset == 0));
        for bit in 0..32 {
            row[VALUE_BITS + bit] = F(u64::from((number >> bit) & 1));
            row[SLACK_BITS + bit] = F(u64::from((slack >> bit) & 1));
        }
        if slot != 0 {
            row[VARIANTS + (magnitude - 1) * 2 + sign] = F::ONE;
            row[BASE_G] = F(u64::from(bytes[first]));
            if magnitude > 1 {
                row[BASE_INVERSE] = row[BASE_G].inv().unwrap();
            }
        }
        let relative = if slot == 0 {
            (offset < 2).then_some(offset)
        } else if offset < 7 {
            Some(offset)
        } else if offset >= 12 - length {
            Some(offset - 5 + length)
        } else {
            None
        };
        if let Some(relative) = relative {
            let value = encoded[relative];
            row[BASE_D] = F::ONE;
            row[BASE_ADDRESS] = F(73 + relative as u64);
            row[BASE_VALUE] = F(u64::from(value));
            write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
        }
        row
    });
    (rows, fixed, encoded)
}

fn valid(rows: &Rows, fixed: &Fixed) -> bool {
    (0..ROWS_PER_SLOT).all(|offset| {
        let next = rows.get(offset + 1).unwrap_or(&rows[offset]);
        let mut residues = Vec::new();
        append_residues(&rows[offset], next, &fixed[offset], &mut residues);
        assert_eq!(residues.len(), RESIDUES);
        residues.extend(private_geometry_residues_v1(
            &rows[offset],
            next,
            &fixed[offset],
        ));
        residues.into_iter().all(|value| value == F::ZERO)
    })
}

#[test]
fn every_u32_der_boundary_has_exact_complete_private_bytes_and_slack() {
    let (leaf, fixed, encoded) = local_rows(0, None, true);
    assert_eq!(encoded, [0x30, 0]);
    assert!(valid(&leaf, &fixed));
    for slot in [1, 2] {
        for value in BOUNDARIES {
            let (rows, fixed, encoded) = local_rows(slot, Some(value), true);
            assert_eq!(
                valid(&rows, &fixed),
                value >= slot as u32 - 1,
                "slot={slot},value={value}"
            );
            let actual = rows
                .iter()
                .filter(|row| row[BASE_D] == F::ONE)
                .map(|row| {
                    (
                        row[BASE_ADDRESS].0 - 73,
                        u8::try_from(row[BASE_VALUE].0).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                encoded
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(offset, byte)| (offset as u64, byte))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                rows.iter()
                    .filter(|row| row[BASE_IS_WRITE] == F::ONE)
                    .count(),
                1
            );
        }
    }
}

#[test]
fn every_value_slack_and_variant_bit_is_constrained() {
    let (original, fixed, _) = local_rows(2, Some(u32::MAX), true);
    assert!(valid(&original, &fixed));
    for column in (VALUE_BITS..VALUE_BITS + 32)
        .chain(SLACK_BITS..SLACK_BITS + 32)
        .chain(VARIANTS..VARIANTS + 8)
    {
        let mut rows = original;
        rows[5][column] = F::ONE.sub(rows[5][column]);
        assert!(!valid(&rows, &fixed), "flipped column {column}");
        rows[5][column] = F(2);
        assert!(!valid(&rows, &fixed), "nonboolean column {column}");
    }
    for column in [BASE_E, BASE_F, BASE_B, BASE_G, BASE_INVERSE] {
        let mut rows = original;
        for row in &mut rows {
            row[column] = row[column].add(F::ONE);
        }
        assert!(!valid(&rows, &fixed), "changed whole-block scalar {column}");
    }
}

#[test]
fn malformed_integer_variants_and_unsigned_wrap_are_rejected() {
    for value in BOUNDARIES {
        let (original, fixed, _) = local_rows(1, Some(value), true);
        for chosen in 0..8 {
            let mut rows = original;
            for row in &mut rows {
                row[VARIANTS..VARIANTS + 8].fill(F::ZERO);
                row[VARIANTS + chosen] = F::ONE;
            }
            if rows[0][VARIANTS..VARIANTS + 8] != original[0][VARIANTS..VARIANTS + 8] {
                assert!(
                    !valid(&rows, &fixed),
                    "value={value},wrong variant={chosen}"
                );
            }
        }
    }
    let (rows, fixed, _) = local_rows(2, Some(0), true);
    assert!(
        !valid(&rows, &fixed),
        "u32::MAX slack must not wrap to negative one"
    );
    let (mut rows, fixed, _) = local_rows(2, Some(1), true);
    for row in &mut rows {
        row[BASE_F] = F(GOLDILOCKS_MODULUS_V1 - 1);
    }
    assert!(!valid(&rows, &fixed), "field-negative slack is not a u32");
}

#[test]
fn every_slot_row_and_inactive_operand_is_forced() {
    let (original, fixed, _) = local_rows(2, Some(1), false);
    assert!(valid(&original, &fixed));
    for offset in 0..ROWS_PER_SLOT {
        for column in 0..PREFIX_END {
            if matches!(column, BASE_CERT2_ACTIVE) {
                continue;
            }
            let mut rows = original;
            rows[offset][column] = F::ONE;
            assert!(
                !valid(&rows, &fixed),
                "inactive row={offset},column={column}"
            );
        }
    }
    let (original, fixed, _) = local_rows(2, Some(1), true);
    for offset in 0..ROWS_PER_SLOT {
        let mut rows = original;
        rows[offset].fill(F::ZERO);
        rows[offset][BASE_CERT2_ACTIVE] = F::ONE;
        assert!(!valid(&rows, &fixed), "erased active row={offset}");
    }
    for ordinal in ROWS..FIXED_BASIC_CONSTRAINTS_ROWS_V1 {
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize] = F::ONE;
        fixed[FIX_LOCAL_FIRST] = F::ONE;
        fixed[FIX_LOCAL_LAST] = F::ONE;
        populate_fixed(&mut fixed, ordinal);
        let row = active_zero_row_v1();
        let mut residues = Vec::new();
        append_residues(&row, &row, &fixed, &mut residues);
        assert!(residues.iter().any(|value| *value != F::ZERO));
    }
}

#[test]
fn complete_bytes_and_all_metadata_continuity_are_constrained() {
    let (original, fixed, _) = local_rows(2, Some(0x8000_0000), true);
    for offset in 0..ROWS_PER_SLOT {
        for column in [BASE_D, BASE_VALUE, BASE_ADDRESS, BASE_IS_WRITE] {
            let mut rows = original;
            rows[offset][column] = rows[offset][column].add(F::ONE);
            assert!(!valid(&rows, &fixed), "query row={offset},column={column}");
        }
    }
    for column in METADATA.into_iter().chain(VARIANTS..VARIANTS + 8) {
        let mut rows = original;
        rows[6][column] = rows[6][column].add(F::ONE);
        assert!(!valid(&rows, &fixed), "continuity column={column}");
    }
}

#[test]
fn complete_path_len_kernel_has_total_degree_four() {
    let mut degrees = [0_usize; RESIDUES];
    for seed in [3_u64, 5, 11] {
        let mut samples: [Vec<F>; RESIDUES] = core::array::from_fn(|_| Vec::new());
        for point in 0..9 {
            let affine = |domain: u64, column: usize| {
                F(seed * 1009 + domain * 131 + column as u64 * 17 + 1)
                    .add(F(seed * 313 + domain * 29 + column as u64 * 43 + 7).mul(F(point)))
            };
            let row = core::array::from_fn(|column| affine(1, column));
            let next = core::array::from_fn(|column| affine(2, column));
            let fixed = core::array::from_fn(|column| affine(3, column));
            let mut residues = Vec::new();
            append_residues(&row, &next, &fixed, &mut residues);
            for (samples, value) in samples.iter_mut().zip(residues) {
                samples.push(value);
            }
        }
        for (degree, mut sample) in degrees.iter_mut().zip(samples) {
            for order in 0..9 {
                if sample.iter().any(|value| *value != F::ZERO) {
                    *degree = (*degree).max(order);
                }
                sample = sample.windows(2).map(|pair| pair[1].sub(pair[0])).collect();
            }
        }
    }
    assert_eq!(degrees.iter().copied().max(), Some(4));
    assert!(degrees.iter().all(|degree| *degree <= 4));
    let inventory: [usize; 5] =
        core::array::from_fn(|degree| degrees.iter().filter(|actual| **actual == degree).count());
    assert_eq!(inventory, [0, 0, 10, 114, 2]);
}

#[test]
fn genuine_sources_bind_signed_parent_nodes_and_complete_byte_queries() {
    use crate::privacy_engines::zk_x509::{
        der_air::build_zk_x509_rfc5280_trace_v1,
        relation::release_fixture::{
            build_zk_x509_copy_capacity_fixture_v1, build_zk_x509_release_fixture_v1,
            reference_statement_context_v1,
        },
        verifier_profile::rfc_statement_with_crl_number_v1,
    };
    let challenges = ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|cell| F(1 + lane as u64 * 100 + cell as u64))
        }),
    };
    for (maximum, capacity) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = if capacity {
            build_zk_x509_copy_capacity_fixture_v1(maximum)
        } else {
            build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum)
        }
        .unwrap();
        let trace = build_zk_x509_rfc5280_trace_v1(
            &fixture.witness.certificate_chain_der,
            &fixture.witness.crl_der,
            rfc_statement_with_crl_number_v1(
                &fixture.statement,
                fixture.authoritative_state.crl_record().crl_number,
            ),
        )
        .unwrap();
        let sources = sources(&trace).unwrap();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let family = ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize;
        assert_eq!(
            material.family_rows[family].len(),
            trace.certificates.len() * ROWS_PER_SLOT
        );
        assert_eq!(
            material.private_shape.basic_constraints_rows as usize,
            trace.certificates.len() * ROWS_PER_SLOT
        );
        for (slot, source) in sources
            .iter()
            .enumerate()
            .filter_map(|(slot, source)| source.as_ref().map(|source| (slot, source)))
        {
            let rows: Rows = core::array::from_fn(|offset| {
                material
                    .base_row(material.schedule.starts[family] + slot * ROWS_PER_SLOT + offset)
                    .unwrap()
            });
            let fixed: Fixed = core::array::from_fn(|offset| {
                material
                    .fixed_row(material.schedule.starts[family] + slot * ROWS_PER_SLOT + offset)
                    .unwrap()
            });
            assert!(valid(&rows, &fixed));
            if capacity && slot != 0 {
                assert_eq!(
                    usize::from(source.node.content_end - source.node.content_start),
                    ROWS_PER_SLOT
                );
                for row in &rows {
                    assert_ne!(row[BASE_G], F::ZERO);
                    assert_eq!(row[BASE_INVERSE], row[BASE_G].inv().unwrap());
                }
            }
            let source_ordinal = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                + slot * 2048
                + usize::from(source.node.node);
            let table = material.base_row(source_ordinal).unwrap();
            for lane in 0..4 {
                assert_eq!(
                    node_query_factor_v1(&rows[0], &fixed[0], lane, &challenges),
                    serial_node_lookup_factor_v1(&table, lane, &challenges)
                );
            }
            assert_eq!(
                node_multiplicity(&sources, slot, usize::from(source.node.node)),
                1
            );
            let actual = rows
                .iter()
                .filter(|row| row[BASE_D] == F::ONE)
                .map(|row| {
                    let address = usize::try_from(row[BASE_ADDRESS].0).unwrap();
                    assert_eq!(
                        row[BASE_VALUE],
                        trace.documents[slot].bytes[address].value.value
                    );
                    assert_eq!(byte_multiplicity(&sources, slot, address), 1);
                    address
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                (usize::from(source.node.content_start)..usize::from(source.node.content_end))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn canonical_comparison_frame_matches_independent_encoder_and_clears_on_drop() {
    use super::super::super::private_table::inspection;
    for value in core::iter::once(None).chain(BOUNDARIES.into_iter().map(Some)) {
        let expected = encode_basic_constraints_v1(value.is_some(), value).unwrap();
        let frame = CanonicalFrame::new(value);
        assert_eq!(frame.as_slice(), expected);
        assert!(
            frame.bytes[usize::from(frame.length)..]
                .iter()
                .all(|byte| *byte == 0)
        );
        let ((), observations) = inspection::observe_v1(|| drop(frame));
        assert_eq!(
            observations.iter().map(|item| item.cells).sum::<usize>(),
            ROWS_PER_SLOT + 1
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    let ((), observations) = inspection::observe_v1(|| {
        let fail = || -> Result<(), ()> {
            let _frame = CanonicalFrame::new(Some(u32::MAX));
            Err(())
        };
        assert_eq!(fail(), Err(()));
    });
    assert_eq!(
        observations.iter().map(|item| item.cells).sum::<usize>(),
        ROWS_PER_SLOT + 1
    );
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn genuine_source_selection_rejects_missing_duplicate_metadata_and_byte_mutations() {
    use crate::privacy_engines::zk_x509::{
        der_air::build_zk_x509_rfc5280_trace_v1,
        relation::release_fixture::{
            build_zk_x509_release_fixture_v1, reference_statement_context_v1,
        },
        verifier_profile::rfc_statement_with_crl_number_v1,
    };
    let fixture =
        build_zk_x509_release_fixture_v1(reference_statement_context_v1(), false).unwrap();
    let mut trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        rfc_statement_with_crl_number_v1(
            &fixture.statement,
            fixture.authoritative_state.crl_record().crl_number,
        ),
    )
    .unwrap();
    assert!(sources(&trace).is_ok());
    let index = trace.semantic_provenance[1]
        .nodes
        .iter()
        .position(|node| {
            node.role == ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue
                && node.role_instance == 3
        })
        .unwrap();
    let original = trace.semantic_provenance[1].nodes[index];
    trace.semantic_provenance[1].nodes[index].role_instance = 7;
    assert!(sources(&trace).is_err(), "missing required source");
    trace.semantic_provenance[1].nodes[index] = original;
    trace.semantic_provenance[1].nodes.push(original);
    assert!(sources(&trace).is_err(), "duplicate required source");
    trace.semantic_provenance[1]
        .nodes
        .pop()
        .unwrap()
        .zeroize_private_v1();
    for mutation in 0..7 {
        let node = &mut trace.semantic_provenance[1].nodes[index];
        match mutation {
            0 => node.document = 0,
            1 => node.tag_class = 1,
            2 => node.constructed = true,
            3 => node.tag_number = 3,
            4 => node.content_start += 1,
            5 => node.content_end -= 1,
            6 => node.content_end = u16::MAX,
            _ => unreachable!(),
        }
        assert!(sources(&trace).is_err(), "metadata mutation {mutation}");
        trace.semantic_provenance[1].nodes[index] = original;
    }
    for address in usize::from(original.content_start)..usize::from(original.content_end) {
        let previous = trace.documents[1].bytes[address].value.value;
        trace.documents[1].bytes[address].value.value = previous.add(F::ONE);
        assert!(sources(&trace).is_err(), "signed contents byte {address}");
        trace.documents[1].bytes[address].value.value = previous;
    }
    trace.certificates[1].extensions.basic_constraints_path_len = Some(1);
    assert!(
        sources(&trace).is_err(),
        "parsed value differs from original signed bytes"
    );
    trace.certificates[1].extensions.basic_constraints_path_len = Some(0);
    trace.certificates[1].extensions.basic_constraints_ca = false;
    assert!(sources(&trace).is_err(), "CA role must match fixed slot");
    trace.certificates[1].extensions.basic_constraints_ca = true;
    assert!(sources(&trace).is_ok());
}
