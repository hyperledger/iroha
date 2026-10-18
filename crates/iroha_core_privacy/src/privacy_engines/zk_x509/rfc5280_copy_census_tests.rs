//! Complete fixed copy-slot census, original-source joins and adversarial controls.
use super::*;
use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;

fn trace(maximum: bool, capacity: bool) -> ZkX509Rfc5280TraceV1 {
    use crate::privacy_engines::zk_x509::{
        der_air::build_zk_x509_rfc5280_trace_v1,
        relation::release_fixture::{
            build_zk_x509_copy_capacity_fixture_v1, build_zk_x509_release_fixture_v1,
            reference_statement_context_v1,
        },
        verifier_profile::rfc_statement_with_crl_number_v1,
    };
    let fixture = if capacity {
        build_zk_x509_copy_capacity_fixture_v1(maximum)
    } else {
        build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum)
    }
    .unwrap();
    build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        rfc_statement_with_crl_number_v1(
            &fixture.statement,
            fixture.authoritative_state.crl_record().crl_number,
        ),
    )
    .unwrap()
}
fn challenges() -> ZkX509Rfc5280StarkChallengesV1 {
    ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|slot| F(7 + (12 * lane + slot) as u64))
        }),
    }
}
fn rejects(
    row: &ZkX509Rfc5280StarkBaseRowV1,
    next: &ZkX509Rfc5280StarkBaseRowV1,
    fixed: &ZkX509Rfc5280StarkFixedRowV1,
) -> bool {
    residues(row, next, fixed)
        .into_iter()
        .chain(private_geometry_residues_v1(row, next, fixed))
        .any(|r| r != F::ZERO)
}

#[test]
fn genuine_endpoints_cover_every_original_byte_node_and_typed_copy_tuple() {
    for (maximum, capacity) in [(false, false), (true, false), (false, true), (true, true)] {
        let trace = trace(maximum, capacity);
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let sources = Sources::new(&trace).unwrap();
        let mut left = [F::ONE; 4];
        let mut right = left;
        let mut seen_nodes = 0;
        let mut live_bytes = 0;
        let mut padding = 0;
        for family in [
            ZkX509Rfc5280StarkFamilyV1::EqualByte,
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
            ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
        ] {
            assert_eq!(material.family_rows[family as usize].len(), rows(family));
            let mut active_count = 0;
            for ordinal in 0..rows(family) {
                let index = material.schedule.starts[family as usize] + ordinal;
                let row = material.base_row(index).unwrap();
                let next = material.base_row(index + 1).unwrap();
                let fixed = material.fixed_row(index).unwrap();
                assert!(!rejects(&row, &next, &fixed), "{family:?}:{ordinal}");
                assert_eq!(
                    residues(
                        &row.map(E::from_base),
                        &next.map(E::from_base),
                        &fixed.map(E::from_base)
                    ),
                    [E::ZERO; RESIDUES]
                );
                assert_eq!(row[BASE_COPY_START], F::ZERO);
                assert_eq!(row[BASE_COPY_GENERALIZED], F::ZERO);
                active_count += usize::from(row[BASE_ACTIVE] == F::ONE);
                let slot = slot(family, ordinal).unwrap();
                let Some(node) = sources.node(slot) else {
                    assert_eq!(row[BASE_ACTIVE], F::ZERO);
                    continue;
                };
                assert_eq!(row[BASE_B].mul(row[BASE_G]), F::ONE);
                if capacity && !slot.embedded {
                    assert_eq!(
                        row[BASE_B],
                        F(slot.capacity as u64),
                        "actual maximum original endpoint {slot:?}"
                    );
                }
                assert_eq!(row[BASE_DOCUMENT], F(u64::from(node.document)));
                if slot.offset == 0 {
                    seen_nodes += 1;
                    assert_eq!(node_query_gate(&row, &fixed), F::ONE);
                    let original = material
                        .base_row(
                            material.schedule.starts
                                [ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                                + usize::from(node.document) * 2048
                                + usize::from(node.node),
                        )
                        .unwrap();
                    for lane in 0..4 {
                        assert_eq!(
                            serial_node_lookup_factor_v1(&row, lane, &challenges()),
                            serial_node_lookup_factor_v1(&original, lane, &challenges())
                        );
                    }
                } else {
                    assert_eq!(node_query_gate(&row, &fixed), F::ZERO);
                }
                if row[BASE_D] == F::ONE {
                    live_bytes += 1;
                    let document = source_documents_v1(&trace)
                        .nth(usize::from(node.document))
                        .unwrap();
                    assert_eq!(
                        row[BASE_VALUE],
                        document.bytes[row[BASE_ADDRESS].0 as usize].value.value
                    );
                    assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], F::ONE);
                    assert_eq!(row[BASE_SERIAL_BYTE_QUERY_VALUE], row[BASE_VALUE]);
                    for lane in 0..4 {
                        let factor = normalized_copy_factor_v1(&row, lane, &challenges());
                        if slot.consumer {
                            right[lane] = right[lane].mul(factor);
                        } else {
                            left[lane] = left[lane].mul(factor);
                        }
                    }
                } else {
                    padding += 1;
                    assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], F::ZERO);
                    assert_eq!(row[BASE_COPY_SOURCE_ACTIVE], F::ZERO);
                    assert_eq!(row[BASE_COPY_CONSUMER_ACTIVE], F::ZERO);
                }
            }
            assert_eq!(active_count, active_rows(family, maximum));
            assert!(!rejects(
                &material
                    .base_row(material.schedule.starts[family as usize] + rows(family))
                    .unwrap(),
                &material
                    .base_row(material.schedule.starts[family as usize] + rows(family) + 1)
                    .unwrap(),
                &material
                    .fixed_row(material.schedule.starts[family as usize] + rows(family))
                    .unwrap()
            ));
        }
        assert_eq!(seen_nodes, if maximum { 46 } else { 34 });
        assert!(live_bytes > 0 && padding > 0);
        assert_eq!(left, right);
    }
}

#[test]
fn complete_slot_equations_reject_erasure_shortening_holes_identity_and_inverse_mutations() {
    let trace = trace(false, false);
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    for family in [
        ZkX509Rfc5280StarkFamilyV1::EqualByte,
        ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
        ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
    ] {
        let start = material.schedule.starts[family as usize];
        let row = material.base_row(start).unwrap();
        let next = material.base_row(start + 1).unwrap();
        let fixed = material.fixed_row(start).unwrap();
        for column in [
            BASE_ACTIVE,
            BASE_B,
            BASE_C,
            BASE_D,
            BASE_E,
            BASE_F,
            BASE_G,
            BASE_H,
            BASE_DOCUMENT,
            BASE_ROLE,
            BASE_INSTANCE,
            BASE_TAG_CLASS,
            BASE_CONSTRUCTED,
            BASE_TAG_NUMBER,
            BASE_OFFSET,
            BASE_IS_WRITE,
            BASE_CONTENT_END,
        ] {
            let mut changed = row;
            changed[column] = changed[column].add(F::ONE);
            assert!(rejects(&changed, &next, &fixed), "{family:?}:{column}");
        }
        let mut erased = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        erased[BASE_CERT2_ACTIVE] = row[BASE_CERT2_ACTIVE];
        assert!(rejects(&erased, &erased, &fixed));
        let length = row[BASE_B].0 as usize;
        assert!(length > 1 && length < slot(family, 0).unwrap().capacity);
        let mut hole = material.base_row(start + 1).unwrap();
        let after = material.base_row(start + 2).unwrap();
        let hole_fixed = material.fixed_row(start + 1).unwrap();
        hole[BASE_D] = F::ZERO;
        hole[BASE_E] = hole[BASE_C];
        assert!(rejects(&hole, &after, &hole_fixed));
        let index = start + length;
        let mut padded = material.base_row(index).unwrap();
        let after = material.base_row(index + 1).unwrap();
        let fixed = material.fixed_row(index).unwrap();
        padded[BASE_VALUE] = F::ONE;
        assert!(rejects(&padded, &after, &fixed));
        let mut zero_length = row;
        zero_length[BASE_B] = F::ZERO;
        zero_length[BASE_G] = F::ZERO;
        assert!(rejects(
            &zero_length,
            &next,
            &material.fixed_row(start).unwrap()
        ));
        let mut broken = next;
        broken[BASE_G] = broken[BASE_G].add(F::ONE);
        assert!(rejects(&row, &broken, &material.fixed_row(start).unwrap()));
    }
}

#[test]
fn optional_slots_cannot_alias_ordinary_crl_documents_or_activate_reserved_tail() {
    for (maximum, capacity) in [(false, false), (true, false), (false, true), (true, true)] {
        let trace = trace(maximum, capacity);
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        for family in [
            ZkX509Rfc5280StarkFamilyV1::EqualByte,
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
            ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
        ] {
            let mut optional = 0;
            for ordinal in 0..rows(family) {
                let slot = slot(family, ordinal).unwrap();
                if !slot.optional {
                    continue;
                }
                optional += 1;
                let index = material.schedule.starts[family as usize] + ordinal;
                let row = material.base_row(index).unwrap();
                let next = material.base_row(index + 1).unwrap();
                let fixed = material.fixed_row(index).unwrap();
                assert_eq!(row[BASE_ACTIVE], F(u64::from(maximum)));
                let mut changed = row;
                changed[BASE_ACTIVE] = F::ONE.sub(changed[BASE_ACTIVE]);
                assert!(rejects(&changed, &next, &fixed));
                if !maximum {
                    for column in [BASE_DOCUMENT, BASE_NODE, BASE_START, BASE_G, BASE_VALUE] {
                        let mut changed = row;
                        changed[column] = F::ONE;
                        assert!(rejects(&changed, &next, &fixed));
                    }
                }
            }
            assert!(optional > 0);
            // Every verifier-reserved tail row is zero, independently of the
            // optional interior holes. The mandatory post-hole CRL slots were
            // checked above against their original source nodes and activity.
            for ordinal in rows(family)..material.schedule.counts[family as usize] {
                let index = material.schedule.starts[family as usize] + ordinal;
                let row = material.base_row(index).unwrap();
                let next = material.base_row(index + 1).unwrap();
                let fixed = material.fixed_row(index).unwrap();
                assert_eq!(row[BASE_ACTIVE], F::ZERO);
                assert_eq!(row[BASE_D], F::ZERO);
                assert_eq!(node_query_gate(&row, &fixed), F::ZERO);
                assert!(!rejects(&row, &next, &fixed));
            }
            let index = material.schedule.starts[family as usize] + rows(family);
            let mut row = material.base_row(index).unwrap();
            row[BASE_ACTIVE] = F::ONE;
            assert!(rejects(
                &row,
                &material.base_row(index + 1).unwrap(),
                &material.fixed_row(index).unwrap()
            ));
        }
    }
}

#[test]
fn endpoint_resolver_rejects_missing_duplicate_wrong_root_and_tag_sources() {
    let mut trace = trace(false, false);
    assert!(Sources::new(&trace).is_ok());
    let doc = equality_slot(1, 0, false).unwrap().document as usize;
    assert_eq!(
        doc, 3,
        "depth-two leaf AKI follows three top-level documents"
    );
    let index = trace.semantic_provenance[doc]
        .nodes
        .iter()
        .position(|n| n.role == ZkX509Rfc5280GrammarRoleV1::EmbeddedAki)
        .unwrap();
    let original = trace.semantic_provenance[doc].nodes[index];
    for case in 0..6 {
        let node = &mut trace.semantic_provenance[doc].nodes[index];
        match case {
            0 => node.role_instance = 1,
            1 => node.node = 1,
            2 => node.start = 1,
            3 => node.tag_number = 4,
            4 => node.tag_class = 2,
            5 => node.constructed = false,
            _ => unreachable!(),
        };
        assert!(Sources::new(&trace).is_err(), "case{case}");
        trace.semantic_provenance[doc].nodes[index] = original;
    }
    trace.semantic_provenance[doc].nodes.push(original);
    assert!(Sources::new(&trace).is_err());
    trace.semantic_provenance[doc]
        .nodes
        .pop()
        .unwrap()
        .zeroize_private_v1();
    assert!(Sources::new(&trace).is_ok());
}

#[test]
fn copy_equations_and_normalization_are_fp4_generic_and_degree_at_most_four() {
    for seed in [1_u64, 7, 19] {
        let samples = (0..7)
            .map(|point| {
                let affine = |kind: u64, i: usize| {
                    F((seed + kind * 13 + i as u64 * 17) % 1009 + 1)
                        .add(F((seed * 7 + kind * 19 + i as u64 * 29) % 997 + 1).mul(F(point)))
                };
                let row = core::array::from_fn(|i| affine(1, i));
                let next = core::array::from_fn(|i| affine(2, i));
                let fixed = core::array::from_fn(|i| affine(3, i));
                let result = residues(&row, &next, &fixed);
                assert_eq!(
                    residues(
                        &row.map(E::from_base),
                        &next.map(E::from_base),
                        &fixed.map(E::from_base)
                    ),
                    result.map(E::from_base)
                );
                let mut normalized = row;
                normalize(&mut normalized, &fixed);
                let mut extended = row.map(E::from_base);
                normalize(&mut extended, &fixed.map(E::from_base));
                assert_eq!(extended, normalized.map(E::from_base));
                result.into_iter().chain(normalized).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for column in 0..samples[0].len() {
            let mut values = samples.iter().map(|r| r[column]).collect::<Vec<_>>();
            for _ in 0..5 {
                values = values.windows(2).map(|p| p[1].sub(p[0])).collect();
            }
            assert!(values.iter().all(|v| *v == F::ZERO), "{seed}:{column}");
        }
    }
}

#[test]
fn both_new_copy_domains_are_typed_and_total_at_an_admitted_zero_factor() {
    // Synthetic tuple algebra only; genuine source coverage is tested above.
    // A zero product is a completeness case, not unconditional binding evidence.
    for embedded in [false, true] {
        let mut source = active_zero_row_v1();
        source[BASE_D] = F::ONE;
        source[BASE_VALUE] = F(48);
        let mut consumer = source;
        let mut source_fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        source_fixed[if embedded {
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy as usize
        } else {
            ZkX509Rfc5280StarkFamilyV1::EqualByte as usize
        }] = F::ONE;
        source_fixed[FIX_ADDRESS_FIXED] = F(u64::from(embedded));
        let mut consumer_fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        consumer_fixed[ZkX509Rfc5280StarkFamilyV1::SemanticConsumer as usize] = F::ONE;
        consumer_fixed[FIX_ADDRESS_FIXED] = F(u64::from(embedded));
        normalize(&mut source, &source_fixed);
        normalize(&mut consumer, &consumer_fixed);
        assert_eq!(source[BASE_COPY_SOURCE_ACTIVE], F::ONE);
        assert_eq!(consumer[BASE_COPY_CONSUMER_ACTIVE], F::ONE);
        assert_eq!(
            source[BASE_COPY_DOMAIN],
            F(if embedded { 104 } else { 103 })
        );
        let mut challenges = challenges();
        let factor = normalized_copy_factor_v1(&source, 0, &challenges);
        challenges.tuple[0][0] =
            challenges.tuple[0][0].sub(factor.mul(source[BASE_COPY_DOMAIN].inv().unwrap()));
        challenges.validate().unwrap();
        assert_eq!(normalized_copy_factor_v1(&source, 0, &challenges), F::ZERO);
        assert_eq!(
            normalized_copy_factor_v1(&consumer, 0, &challenges),
            F::ZERO
        );
        for lane in 0..4 {
            assert_eq!(
                normalized_copy_factor_v1(&source, lane, &challenges),
                normalized_copy_factor_v1(&consumer, lane, &challenges)
            );
        }
        for column in [
            BASE_COPY_DOMAIN,
            BASE_COPY_KEY_1,
            BASE_COPY_KEY_2,
            BASE_COPY_VALUE,
        ] {
            let mut changed = consumer;
            changed[column] = changed[column].add(F::ONE);
            for lane in 0..4 {
                assert_ne!(
                    normalized_copy_factor_v1(&source, lane, &challenges),
                    normalized_copy_factor_v1(&changed, lane, &challenges)
                );
            }
        }
    }
}
