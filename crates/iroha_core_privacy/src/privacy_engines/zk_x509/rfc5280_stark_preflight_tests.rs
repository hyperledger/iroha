// Complete native-column preflight for the actual release witnesses. These
// controls stop before masking, commitment construction, or proof generation.

fn assert_release_fixture_rfc_column_preflight_v1(maximum: bool) {
    use crate::privacy_engines::zk_x509::{
        der_stark::{build_zk_x509_der_stark_trace_v1, zk_x509_der_stark_terminal_claims_v1},
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };

    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum)
        .expect("actual release witness");
    assert_eq!(
        fixture.witness.certificate_chain_der.len(),
        if maximum { 3 } else { 2 }
    );
    assert_eq!(fixture.crl_entry_count, if maximum { 64 } else { 0 });
    assert_eq!(
        fixture.statement.disclosed_attributes.len(),
        if maximum { 4 } else { 1 }
    );
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .expect("actual release MAIN source assembly");
    eprintln!(
        "maximum={maximum} complete MAIN assembly owned payload bytes={}",
        assembly.allocated_payload_bytes_v1()
    );
    let material = &assembly.rfc_base;
    assert_source_node_root_base_rows_v1(material);
    eprintln!(
        "maximum={maximum} RFC native owned payload bytes={}",
        material.allocated_heap_bytes_v1()
    );
    let der_challenges = der_challenges_v1();
    let challenges = challenges_v1();
    let provider =
        ZkX509Rfc5280StarkColumnProviderV1::fixture_v1(material, der_challenges, &challenges)
            .expect("release RFC column provider and terminal claims");
    let der_trace = build_zk_x509_der_stark_trace_v1(assembly.der_base.clone(), der_challenges)
        .expect("release DER complete native trace");
    let der_terminals =
        zk_x509_der_stark_terminal_claims_v1(&der_trace).expect("DER terminal claims");
    let claims = provider
        .terminal_claims_v1()
        .expect("valid RFC fixture private products");
    let private_der_fields = [der_terminals.input_byte, der_terminals.node].concat();

    // The first twelve sections constrain base/fixed rows independently of
    // auxiliary columns. Check every populated row before replaying columns,
    // so a missing witness bit fails without expensive mask/FFT work.
    let base_residue_count = RFC5280_RESIDUE_SECTIONS_V1[..12]
        .iter()
        .map(|(_, count)| count)
        .sum::<usize>();
    let unused_aux = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    let mut base_failures = Vec::new();
    for family in 0..FAMILY_COUNT_V1 {
        for offset in 0..material.family_rows[family].len() {
            let row = material.schedule.starts[family] + offset;
            let residues = PrivateTableV1::new(
                evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &material.base_row(row).unwrap(),
                    &material
                        .base_row((row + 1) % ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
                        .unwrap(),
                    &unused_aux,
                    &unused_aux,
                    &material.fixed_row(row).unwrap(),
                    der_challenges,
                    &challenges,
                    claims,
                )
                .expect("complete RFC base-row evaluator"),
                zeroize_fields_v1,
            );
            for (index, residue) in residues[..base_residue_count].iter().enumerate() {
                if *residue != F::ZERO && base_failures.len() < 16 {
                    base_failures.push((row, index));
                }
            }
        }
    }
    assert!(
        base_failures.is_empty(),
        "maximum={maximum} base row/residue failures={base_failures:?}"
    );

    // Keep only boundary rows while visiting every full native column. This
    // avoids retaining a 264-column auxiliary matrix merely for a preflight.
    let last = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1;
    let mut checkpoints = vec![0, last];
    for family in 0..FAMILY_COUNT_V1 {
        let start = material.schedule.starts[family];
        let extent = material.schedule.counts[family];
        for boundary in [
            start,
            start + extent,
            start + material.family_rows[family].len(),
        ] {
            checkpoints.extend(
                [
                    boundary.saturating_sub(1),
                    boundary,
                    boundary.saturating_add(1),
                ]
                .into_iter()
                .filter(|row| *row <= last),
            );
        }
    }
    // A compact source family stops at its last populated document. Visit every
    // verifier-fixed root, including roots beyond that retained extent.
    let source_start = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize];
    for document in 0..MAX_SOURCE_DOCUMENTS_V1 {
        let root = source_start + document * 2_048;
        checkpoints.extend([root - 1, root, root + 1]);
    }
    checkpoints.sort_unstable();
    checkpoints.dedup();
    let mut current_aux = PrivateTableV1::new(
        vec![[F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1]; checkpoints.len()],
        zeroize_field_rows_v1,
    );
    let mut next_aux = PrivateTableV1::new(
        vec![[F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1]; checkpoints.len()],
        zeroize_field_rows_v1,
    );
    for column in 0..ZK_X509_RFC5280_STARK_BASE_WIDTH_V1 {
        let values = PrivateTableV1::new(
            provider
                .build_base_column_v1(column)
                .unwrap_or_else(|error| {
                    panic!("maximum={maximum} base column {column}: {error:?}")
                }),
            zeroize_fields_v1,
        );
        assert_eq!(values.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
        assert!(values.iter().all(|value| F::canonical(value.0).is_some()));
        for &row in &checkpoints {
            assert_eq!(values[row], material.base_row(row).unwrap()[column]);
        }
    }
    for column in 0..ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 {
        let values = PrivateTableV1::new(
            provider
                .build_aux_column_v1(column)
                .unwrap_or_else(|error| {
                    panic!("maximum={maximum} auxiliary column {column}: {error:?}")
                }),
            zeroize_fields_v1,
        );
        assert_eq!(values.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
        assert!(values.iter().all(|value| F::canonical(value.0).is_some()));
        for (index, &row) in checkpoints.iter().enumerate() {
            current_aux[index][column] = values[row];
            next_aux[index][column] = values[(row + 1) % ZK_X509_RFC5280_STARK_TRACE_SIZE_V1];
        }
    }
    for (index, &row) in checkpoints.iter().enumerate() {
        let residues = PrivateTableV1::new(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &material.base_row(row).unwrap(),
                &material
                    .base_row((row + 1) % ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
                    .unwrap(),
                &current_aux[index],
                &next_aux[index],
                &material.fixed_row(row).unwrap(),
                der_challenges,
                &challenges,
                claims,
            )
            .expect("complete RFC boundary-row AIR"),
            zeroize_fields_v1,
        );
        assert_eq!(residues.len(), ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1);
        assert!(
            residues.iter().all(|residue| *residue == F::ZERO),
            "maximum={maximum} native row {row}, nonzero residue indices={:?}",
            residues
                .iter()
                .enumerate()
                .filter_map(|(index, residue)| (*residue != F::ZERO).then_some(index))
                .collect::<Vec<_>>()
        );
    }
    let terminal_aux = &current_aux[checkpoints.binary_search(&last).unwrap()];
    assert!(
        evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, terminal_aux, claims)
            .unwrap()
            .iter()
            .all(|residue| *residue == F::ZERO)
    );
    let private_columns = zk_x509_rfc_der_terminal_columns_v1();
    let rfc_private_fields = private_columns.map(|column| terminal_aux[column]);
    assert_eq!(
        rfc_private_fields.as_slice(),
        private_der_fields.as_slice(),
        "actual strict-DER and RFC native owners have identical private endpoints"
    );
    for slot in 0..private_columns.len() {
        let mut wrong_der = private_der_fields.clone();
        wrong_der[slot] = wrong_der[slot].add(F::ONE);
        assert_ne!(rfc_private_fields.as_slice(), wrong_der.as_slice());
        zeroize_fields_v1(&mut wrong_der);
    }
    let mut wrong_terminal_aux = *terminal_aux;
    wrong_terminal_aux[AUX_DER_NODE_AFTER] = wrong_terminal_aux[AUX_DER_NODE_AFTER].add(F::ONE);
    assert!(
        evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, &wrong_terminal_aux, claims)
            .unwrap()
            .iter()
            .all(|residue| *residue == F::ZERO),
        "private DER endpoints are not carried by the public output frame"
    );
    assert!(
        evaluate_zk_x509_rfc5280_stark_residues_v1(
            &material.base_row(last).unwrap(),
            &material.base_row(0).unwrap(),
            &wrong_terminal_aux,
            &next_aux[checkpoints.binary_search(&last).unwrap()],
            &material.fixed_row(last).unwrap(),
            der_challenges,
            &challenges,
            claims,
        )
        .unwrap()
        .iter()
        .any(|residue| *residue != F::ZERO),
        "changing the private DER endpoint still violates the unchanged local AIR"
    );
    zeroize_fields_v1(&mut wrong_terminal_aux);
}

#[test]
fn ordinary_release_fixture_replays_every_rfc_native_column_before_masking() {
    assert_release_fixture_rfc_column_preflight_v1(false);
}

#[test]
fn maximum_release_fixture_replays_every_rfc_native_column_before_masking() {
    assert_release_fixture_rfc_column_preflight_v1(true);
}

#[test]
fn crl_number_profile_lookup_requires_the_exact_embedded_der_extent() {
    let trace = canonical_trace_v1();
    let mut material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let column = AUX_PROFILE_LOOKUP_ACCUMULATOR;
    let values = PrivateTableV1::new(
        build_zk_x509_rfc5280_stark_aux_column_v1(
            &material,
            der_challenges_v1(),
            &challenges_v1(),
            column,
            &ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
        .expect("complete profile lookup includes the CRL-number INTEGER"),
        zeroize_fields_v1,
    );
    assert_eq!(values.last(), Some(&F::ZERO));
    let mut changed = 0;
    for row in material.family_rows[ZkX509Rfc5280StarkFamilyV1::FixedByte as usize].iter_mut() {
        if row[BASE_ROLE] == F(13) {
            assert_eq!(row[BASE_CHILD], F::ONE);
            row[BASE_CHILD] = F::ZERO;
            changed += 1;
        }
    }
    assert!(
        changed > 0,
        "fixture must contain the complete CRL-number encoding"
    );
    let (result, erased) = super::super::private_table::inspection::observe_v1(|| {
        build_zk_x509_rfc5280_stark_aux_column_v1(
            &material,
            der_challenges_v1(),
            &challenges_v1(),
            column,
            &ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
    });
    assert_eq!(
        result,
        Err(ZkX509Rfc5280StarkErrorV1::Semantic),
        "the old prefix-only producer flag cannot match the verifier's exact-end table"
    );
    // The production window clears each row's copied two-sum state, all 24
    // eight-cell pairs (including 21 unused pairs), and four working cells.
    // The original row contexts and eight final states still clear once each.
    // On refusal the output guard clears the failed column, then its outer
    // owned table clears that already-zero backing a second time. These are
    // repeated clearing events, not simultaneously resident allocations.
    let mut ownership_census = std::collections::BTreeMap::new();
    for entry in &erased {
        let counts = ownership_census.entry(entry.cells).or_insert((0, 0));
        counts.0 += 1;
        counts.1 += usize::from(entry.nonzero_before > 0);
        assert_eq!(entry.nonzero_after, 0);
    }
    let rows = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1;
    let batch = crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1;
    let pairs = 3 * batch;
    let mut expected_clears = [
        (2, rows + batch),
        (4, rows),
        (8, pairs * rows),
        (16, 1),
        (ZK_X509_RFC5280_STARK_BASE_WIDTH_V1, rows),
        (ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1, rows),
        (rows, 2),
    ];
    expected_clears.sort_unstable();
    assert_eq!(
        ownership_census
            .iter()
            .map(|(&cells, &(count, _))| (cells, count))
            .collect::<Vec<_>>(),
        expected_clears,
        "every stack context, column state and failed output owner must clear"
    );
    assert_eq!(ownership_census[&rows].1, 1, "failed output is dirty once");
    // Per-row copies precede the eight final-state drops. Preserve the
    // original assertion on those final owners, separately from the copies.
    assert_eq!(
        erased
            .iter()
            .filter(|entry| entry.cells == 2)
            .skip(rows)
            .filter(|entry| entry.nonzero_before > 0)
            .count(),
        1,
        "only the requested final state is active"
    );
    assert_eq!(
        erased
            .iter()
            .find(|entry| entry.cells == 2)
            .unwrap()
            .nonzero_before,
        0,
        "the first copied recurrence starts with zero sums"
    );
    assert!(
        erased
            .iter()
            .filter(|entry| entry.cells == 2)
            .take(rows)
            .any(|entry| entry.nonzero_before > 0),
        "later copied recurrences carry private prefix sums"
    );
    // The profile descriptor requests exactly three factors on every row.
    // All remaining pairs are zero but must still be erased by the same owner.
    for (index, entry) in erased.iter().filter(|entry| entry.cells == 8).enumerate() {
        assert_eq!(entry.nonzero_before > 0, index % pairs < 3);
    }
    assert_eq!(
        ownership_census[&4].1, rows,
        "every product workspace is live"
    );
    assert!(ownership_census[&ZK_X509_RFC5280_STARK_BASE_WIDTH_V1].1 > 0);
    assert!(ownership_census[&ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1].1 > 0);
    assert_eq!(
        erased.iter().map(|entry| entry.cells).sum::<usize>(),
        2 * rows
            + 16
            + rows * (ZK_X509_RFC5280_STARK_BASE_WIDTH_V1 + ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1)
            + 2 * batch
            + rows * (2 + 4 + pairs * 8)
    );
    assert_eq!(
        erased
            .iter()
            .find(|entry| entry.cells == 16)
            .unwrap()
            .nonzero_before,
        16
    );
}

#[test]
fn decimal_source_rows_bind_their_nonzero_digit_decomposition() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let family = ZkX509Rfc5280StarkFamilyV1::Decimal as usize;
    let offset = material.family_rows[family]
        .iter()
        .position(|row| row[BASE_A] != F::ZERO)
        .expect("fixture has a nonzero time digit");
    let row = material.schedule.starts[family] + offset;
    let mut current = material.base_row(row).unwrap();
    let next = material.base_row(row + 1).unwrap();
    let fixed = material.fixed_row(row).unwrap();
    let unused_aux = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    let claims = compile_zk_x509_rfc5280_stark_terminal_claims_v1(
        &material,
        der_challenges_v1(),
        &challenges_v1(),
    )
    .unwrap();
    let count = RFC5280_RESIDUE_SECTIONS_V1[..12]
        .iter()
        .map(|(_, count)| count)
        .sum::<usize>();
    let evaluate = |current: &ZkX509Rfc5280StarkBaseRowV1| {
        PrivateTableV1::new(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                current,
                &next,
                &unused_aux,
                &unused_aux,
                &fixed,
                der_challenges_v1(),
                &challenges_v1(),
                claims,
            )
            .unwrap(),
            zeroize_fields_v1,
        )
    };
    assert!(
        evaluate(&current)[..count]
            .iter()
            .all(|value| *value == F::ZERO)
    );
    current[BASE_SMALL_BITS..BASE_SMALL_BITS + 4].fill(F::ZERO);
    assert!(
        evaluate(&current)[..count]
            .iter()
            .any(|value| *value != F::ZERO),
        "the old omitted digit decomposition must fail the unchanged AIR"
    );
    zeroize_fields_v1(&mut current);
}

#[test]
fn rfc_column_replay_erases_populated_cells_on_error_and_unwind() {
    use super::super::private_table::inspection;
    for panic in [false, true] {
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(|| {
                build_zk_x509_rfc5280_stark_column_v1(1, 0, |row, _| {
                    if row == 3 {
                        assert!(!panic, "injected source failure");
                        return Err(ZkX509Rfc5280StarkErrorV1::Source);
                    }
                    Ok(F(u64::try_from(row + 1).unwrap()))
                })
            })
        });
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(ZkX509Rfc5280StarkErrorV1::Source));
        }
        assert_eq!(observed.iter().map(|entry| entry.cells).sum::<usize>(), 3);
        assert_eq!(
            observed
                .iter()
                .map(|entry| entry.nonzero_before)
                .sum::<usize>(),
            3
        );
        assert!(observed.iter().all(|entry| entry.nonzero_after == 0));
    }
}

fn assert_bound_numeric_census_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    // Visit every retained SourceNode, Calendar and Relation position, including
    // inactive fixed holes. Omitted authenticated time nodes cannot disappear
    // from the source side when the private entry count changes.
    let positions = [
        ZkX509Rfc5280StarkFamilyV1::SourceNode,
        ZkX509Rfc5280StarkFamilyV1::Calendar,
        ZkX509Rfc5280StarkFamilyV1::Relation,
    ]
    .into_iter()
    .flat_map(|family| {
        let index = family as usize;
        (0..material.family_rows[index].len())
            .map(move |offset| material.schedule.starts[index] + offset)
    })
    .collect::<Vec<_>>();
    let _column = PrivateTableV1::new(
        numeric_replay::build_column_v1(positions.len(), 8, &challenges_v1(), |index| {
            let position = positions[index];
            Ok(numeric_lookup_event_v1(
                &material.base_row(position)?,
                &material.fixed_row(position)?,
            ))
        })?,
        zeroize_fields_v1,
    );
    Ok(())
}

fn local_base_prefix_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    position: usize,
    mut mutate: impl FnMut(&mut ZkX509Rfc5280StarkBaseRowV1),
) -> Vec<F> {
    let fixed = material.fixed_row(position).unwrap();
    let mut row = material.base_row(position).unwrap();
    mutate(&mut row);
    populate_degree_normalization_helpers_v1(&mut row, &fixed);
    let next = material
        .base_row((position + 1) % ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
        .unwrap();
    let unused = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    let mut residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
        &row,
        &next,
        &unused,
        &unused,
        &fixed,
        der_challenges_v1(),
        &challenges_v1(),
        ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1(),
    )
    .unwrap();
    residues.truncate(
        RFC5280_RESIDUE_SECTIONS_V1[..12]
            .iter()
            .map(|(_, count)| count)
            .sum(),
    );
    residues
}

#[test]
fn authenticated_temporal_census_rejects_omission_duplication_and_changed_timestamps() {
    use crate::privacy_engines::zk_x509::{
        relation::release_fixture::{
            build_zk_x509_release_fixture_v1, reference_statement_context_v1,
        },
        verifier_profile::compile_zk_x509_rfc_statement_from_authoritative_state_v1,
    };

    // The ordinary canonical trace has no revoked entries. Use the real
    // maximum fixture so omission actually removes authenticated time nodes.
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum release fixture with revoked entries");
    assert_eq!(fixture.crl_entry_count, 64);
    let trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        compile_zk_x509_rfc_statement_from_authoritative_state_v1(
            &fixture.statement,
            &fixture.authoritative_state,
        ),
    )
    .expect("complete maximum RFC trace");
    let original = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    assert_eq!(original.private_shape.crl_entries, 64);
    assert!(original.private_shape.crl_entries > 0);
    assert_bound_numeric_census_v1(&original).unwrap();
    let mut omitted = original.clone();
    for (family, start) in [
        (
            ZkX509Rfc5280StarkFamilyV1::Calendar,
            8 * numeric::CALENDAR_PHASES_V1,
        ),
        (
            ZkX509Rfc5280StarkFamilyV1::Decimal,
            8 * numeric::DECIMAL_ROWS_PER_TIME_V1,
        ),
        (
            ZkX509Rfc5280StarkFamilyV1::Relation,
            9 * numeric::RELATION_PHASES_V1,
        ),
    ] {
        for row in omitted.family_rows[family as usize].iter_mut().skip(start) {
            zeroize_fields_v1(row);
        }
    }
    omitted.private_shape.crl_entries = 0;
    assert_eq!(
        assert_bound_numeric_census_v1(&omitted),
        Err(ZkX509Rfc5280StarkErrorV1::Semantic)
    );
    for field in [
        BASE_DOCUMENT,
        BASE_PARENT,
        BASE_ENDPOINT_ROLE,
        BASE_NODE,
        BASE_TAG_NUMBER,
        BASE_CONTENT_START,
        BASE_CONTENT_END,
        BASE_G,
    ] {
        let mut changed = original.clone();
        for row in changed.family_rows[ZkX509Rfc5280StarkFamilyV1::Calendar as usize]
            .iter_mut()
            .take(numeric::CALENDAR_PHASES_V1)
        {
            row[field] = row[field].add(F::ONE);
        }
        assert_eq!(
            assert_bound_numeric_census_v1(&changed),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic),
            "field={field}"
        );
    }
    let mut duplicated = original.clone();
    for phase in 0..numeric::CALENDAR_PHASES_V1 {
        duplicated.family_rows[ZkX509Rfc5280StarkFamilyV1::Calendar as usize]
            .iter_mut()
            .nth(numeric::CALENDAR_PHASES_V1 + phase)
            .unwrap()
            .copy_from_slice(
                &original.family_rows[ZkX509Rfc5280StarkFamilyV1::Calendar as usize]
                    .get(phase)
                    .unwrap(),
            );
    }
    assert_eq!(
        assert_bound_numeric_census_v1(&duplicated),
        Err(ZkX509Rfc5280StarkErrorV1::Semantic)
    );
}

#[test]
fn temporal_byte_positions_and_integer_slack_reject_unbound_local_mutations() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let decimal = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Decimal as usize];
    for column in [
        BASE_DOCUMENT,
        BASE_ADDRESS,
        BASE_CONTENT_START,
        BASE_PARENT,
        BASE_INSTANCE,
        BASE_ROLE,
        BASE_OFFSET,
        BASE_B,
        CALENDAR_COLUMNS + calendar::GENERALIZED,
    ] {
        assert!(
            local_base_prefix_v1(&material, decimal, |row| row[column] =
                row[column].add(F::ONE))
            .iter()
            .any(|value| *value != F::ZERO),
            "decimal field={column}"
        );
    }
    assert!(
        local_base_prefix_v1(&material, decimal, |_| {})
            .iter()
            .all(|value| *value == F::ZERO)
    );
    let z = decimal + 12;
    assert!(
        local_base_prefix_v1(&material, z, |_| {})
            .iter()
            .all(|value| *value == F::ZERO)
    );
    assert!(
        local_base_prefix_v1(&material, z, |row| {
            row[BASE_VALUE] = F(89);
            write_u8_bits_v1(row, BASE_BYTE_BITS, 89);
        })
        .iter()
        .any(|value| *value != F::ZERO)
    );
    let relation = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Relation as usize];
    assert!(
        local_base_prefix_v1(&material, relation, |row| {
            row[BASE_A] = row[BASE_A].add(F::ONE);
            row[BASE_B] = row[BASE_B].add(F::ONE);
            row[BASE_G] = row[BASE_G].add(F::ONE);
        })
        .iter()
        .any(|value| *value != F::ZERO),
        "equal shifts must remain bound to the public window"
    );
    assert!(
        local_base_prefix_v1(&material, relation, |_| {})
            .iter()
            .all(|value| *value == F::ZERO)
    );
    for column in [BASE_ROLE, BASE_INSTANCE, BASE_STRICT] {
        assert!(
            local_base_prefix_v1(&material, relation, |row| row[column] =
                row[column].add(F::ONE))
            .iter()
            .any(|value| *value != F::ZERO),
            "relation field={column}"
        );
    }
    // The fixed optional certificate slot must agree with the globally bound
    // certificate-count bit even if its normalization helpers are repaired.
    let calendar = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Calendar as usize];
    let optional = calendar + 2 * numeric::CALENDAR_PHASES_V1;
    assert!(
        local_base_prefix_v1(&material, optional, |_| {})
            .iter()
            .all(|value| *value == F::ZERO)
    );
    assert!(
        local_base_prefix_v1(&material, optional, |row| row[BASE_ACTIVE] =
            F::ONE.sub(row[BASE_ACTIVE]))
        .iter()
        .any(|value| *value != F::ZERO)
    );
    let source = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize];
    let source_time = material.family_rows[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
        .iter()
        .position(|row| {
            row[BASE_ROLE] == F(ZkX509Rfc5280GrammarRoleV1::CertificateNotBefore as u64)
        })
        .unwrap()
        + source;
    assert!(
        local_base_prefix_v1(&material, source_time, |_| {})
            .iter()
            .all(|value| *value == F::ZERO)
    );
    assert!(
        local_base_prefix_v1(&material, source_time, |row| row[CALENDAR_COLUMNS] =
            F::ZERO)
        .iter()
        .any(|value| *value != F::ZERO),
        "authenticated time node cannot erase its temporal classification"
    );
    let range = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::RangeByte as usize];
    for offset in 0..4 {
        assert!(
            local_base_prefix_v1(&material, range + offset, |_| {})
                .iter()
                .all(|value| *value == F::ZERO)
        );
    }
    assert!(
        local_base_prefix_v1(&material, range + 3, |row| {
            row[BASE_STATE_AFTER] = row[BASE_STATE_AFTER].add(F::ONE);
        })
        .iter()
        .any(|value| *value != F::ZERO),
        "middle range accumulator cannot disconnect from its successor"
    );
    for (offset, value) in F::ZERO.sub(F::ONE).0.to_be_bytes().into_iter().enumerate() {
        if offset < 4 {
            assert!(
                local_base_prefix_v1(&material, range + offset, |row| {
                    row[BASE_VALUE] = F(u64::from(value));
                    write_u8_bits_v1(row, BASE_BYTE_BITS, value);
                })
                .iter()
                .any(|field| *field != F::ZERO),
                "field-wrapped negative slack must exceed the38-bit bound"
            );
        }
    }
}

// Check genuinely admitted material, including each unretained document root.
// These are base constraints; no auxiliary column, mask or proof is constructed.
fn assert_source_node_root_base_rows_v1(material: &ZkX509Rfc5280StarkBaseMaterialV1) {
    let source_start = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize];
    let document_count = usize::from(material.private_shape.top_document_count)
        + usize::from(material.private_shape.embedded_document_count);
    let cert2 = material.private_shape.certificate_slot_2_active == F::ONE;
    let unused = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    for document in 0..MAX_SOURCE_DOCUMENTS_V1 {
        let position = source_start + document * 2_048;
        let current = material.base_row(position).unwrap();
        let next = material.base_row(position + 1).unwrap();
        let fixed = material.fixed_row(position).unwrap();
        let present = document < document_count;
        assert_eq!(current[BASE_ACTIVE], F(u64::from(present)));
        let kind = if !present {
            0
        } else if document < 2 || (document == 2 && cert2) {
            1
        } else if document == 2 || (document == 3 && cert2) {
            2
        } else {
            3
        };
        assert_eq!(
            current[BASE_EXPECTED_ROOT_KIND],
            F(kind),
            "source document {document}, present={present}"
        );
        for row in [position - 1, position, position + 1] {
            let residues = local_base_prefix_v1(material, row, |_| {});
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "source document {document}, row {row}, nonzero base residues={:?}",
                residues
                    .iter()
                    .enumerate()
                    .filter_map(|(index, residue)| (*residue != F::ZERO).then_some(index))
                    .collect::<Vec<_>>()
            );
        }
        // Use the actual shared evaluator without normalizing the mutation.
        // The original helper-defining constraint must remain mandatory.
        let mut mutated = current;
        mutated[BASE_EXPECTED_ROOT_KIND] = mutated[BASE_EXPECTED_ROOT_KIND].add(F::ONE);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &mutated,
            &next,
            &unused,
            &unused,
            &fixed,
            der_challenges_v1(),
            &challenges_v1(),
            ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1(),
        )
        .unwrap();
        assert_ne!(residues[14], F::ZERO, "root-kind helper definition");
    }
}

#[test]
fn admitted_release_source_node_roots_cover_both_depths_and_unused_documents() {
    use crate::privacy_engines::zk_x509::{
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };

    for maximum in [false, true] {
        let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum)
            .expect("actual admitted release witness");
        let trust_anchor = fixture.authoritative_state.trust_anchor();
        let crl = fixture.authoritative_state.crl_record();
        let assembly = build_zk_x509_main_trace_assembly_v1(
            &fixture.statement,
            ZkX509GovernanceV1 {
                trust_anchor: &trust_anchor,
                certificate_policy: fixture.authoritative_state.certificate_policy(),
                crl: &crl,
            },
            &fixture.witness,
        )
        .expect("complete reference-admitted MAIN assembly");
        let material = &assembly.rfc_base;
        assert_eq!(
            material.private_shape.chain_depth,
            if maximum { 3 } else { 2 }
        );
        assert_eq!(
            material.private_shape.top_document_count,
            if maximum { 4 } else { 3 }
        );
        assert_eq!(
            material.private_shape.embedded_document_count,
            if maximum { 15 } else { 11 }
        );
        assert_source_node_root_base_rows_v1(material);
    }
}

#[test]
fn canonical_profile_eku_subsets_compile_exact_complete_fixed_patterns() {
    let oids = [
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02][..],
        crate::privacy_engines::zk_x509::profile::ZK_X509_DOCUMENT_SIGNING_EKU_DER_VALUE_V1,
        crate::privacy_engines::zk_x509::profile::ZK_X509_WALLET_IDENTITY_EKU_DER_VALUE_V1,
    ];
    for mask in 1_u8..8 {
        let mut shape = ZkX509Rfc5280StarkShapeV1 {
            leaf_extended_key_usages: [0; 3],
            leaf_extended_key_usage_count: 0,
            ..ZkX509Rfc5280StarkShapeV1::default()
        };
        let mut body = Vec::new();
        for (index, oid) in oids.iter().enumerate() {
            if mask & (1_u8 << index) != 0 {
                let count = usize::from(shape.leaf_extended_key_usage_count);
                shape.leaf_extended_key_usages[count] = u8::try_from(index + 1).unwrap();
                shape.leaf_extended_key_usage_count += 1;
                body.extend_from_slice(&[0x06, u8::try_from(oid.len()).unwrap()]);
                body.extend_from_slice(oid);
            }
        }
        let mut expected = vec![0x30, u8::try_from(body.len()).unwrap()];
        expected.extend_from_slice(&body);
        let table = compile_profile_byte_table_v1(shape).unwrap();
        assert!(table.len() <= FIXED_SEMANTIC_SOURCE_ROWS_V1);
        let entries: Vec<_> = table.iter().filter(|entry| entry.purpose == 12).collect();
        assert_eq!(entries.len(), expected.len());
        assert_eq!(
            encode_eku_v1(&shape.leaf_extended_key_usages().unwrap()).unwrap(),
            expected
        );
        for (offset, entry) in entries.iter().enumerate() {
            assert_eq!(entry.variant, 0);
            assert_eq!(
                entry.source_role,
                ZkX509Rfc5280GrammarRoleV1::EmbeddedEku as u16
            );
            assert_eq!(usize::from(entry.offset), offset);
            assert_eq!(usize::from(entry.length), expected.len());
            assert_eq!(entry.expected, expected[offset]);
            assert!(!entry.contents_only);
            assert!(entry.exact_end);
        }
        if mask == 7 {
            assert_eq!(expected.len(), 55);
            assert!(expected.len() <= copy_census::EMBEDDED_BYTES);
        }
    }
}
