// Cyclic native boundaries of the complete SHA call and RFC product AIR.

fn assert_actual_sha_cyclic_boundaries_v1(
    segment: usize,
    rows: &[ZkX509ShaBatchRowV1; 7],
    binding: ZkX509CredentialPreAuxBindingV1,
    terminal: u8,
    ca_calls: &[ZkX509ShaCallBoundaryTerminalV1; ZK_X509_SHA_CA_CALL_COUNT_V1],
) {
    let evaluate = |current: &ZkX509ShaBatchRowV1, next: &ZkX509ShaBatchRowV1, terminal: u8| {
        evaluate_zk_x509_sha_batch_residues_v1(
            current,
            next,
            binding.sha_word(),
            binding.sha(),
            binding.rfc5280(),
            terminal,
            ca_calls,
        )
        .unwrap()
    };
    // First live edge, final live edge, live-to-padding, padding-to-padding,
    // and native cyclic wrap, from actual maximum-credential source columns.
    for (current, next) in [(0, 1), (2, 3), (3, 4), (4, 5), (6, 0)] {
        let residues = evaluate(&rows[current], &rows[next], terminal);
        assert!(
            residues.iter().all(|value| *value == F::ZERO),
            "segment {segment}, boundary {current}->{next}, failing residue indices {:?}",
            residues
                .iter()
                .enumerate()
                .filter_map(|(i, value)| (*value != F::ZERO).then_some(i))
                .collect::<Vec<_>>()
        );
    }
    // The four carried word-memory terminal products and the three private
    // capacity counters must still reject altered successors on live edges.
    for column in SHA_WORD_CAPACITY_MESSAGE_COUNT_V1 - ZK_X509_SHA_BUS_LANES_V1
        ..SHA_WORD_CAPACITY_AUX_WIDTH_V1
    {
        let mut wrong_next = rows[1];
        wrong_next.aux[column] = wrong_next.aux[column].add(F::ONE);
        assert!(
            evaluate(&rows[0], &wrong_next, terminal)
                .iter()
                .any(|value| *value != F::ZERO),
            "segment {segment}, live word carry {column}"
        );
    }
    for column in ZK_X509_SHA_INPUT_PRODUCTS_V1..ZK_X509_SHA_BATCH_AUX_WIDTH_V1 {
        let mut wrong_first = rows[0];
        wrong_first.aux[column] = wrong_first.aux[column].add(F::ONE);
        assert!(
            evaluate(&wrong_first, &rows[1], terminal)
                .iter()
                .any(|value| *value != F::ZERO),
            "segment {segment}, initial product {column}"
        );
        let mut wrong_next = rows[3];
        wrong_next.aux[column] = wrong_next.aux[column].add(F::ONE);
        assert!(
            evaluate(&rows[2], &wrong_next, terminal)
                .iter()
                .any(|value| *value != F::ZERO),
            "segment {segment}, live product {column}"
        );
    }
    // The eight source/digest totals are private. Changing their final live
    // value still violates the preceding live recurrence in every segment.
    for column in ZK_X509_SHA_INPUT_PRODUCTS_V1..ZK_X509_SHA_RFC_CONSUMER_PRODUCTS_V1 {
        let mut wrong_last = rows[3];
        wrong_last.aux[column] = wrong_last.aux[column].add(F::ONE);
        assert!(
            evaluate(&rows[2], &wrong_last, terminal)
                .iter()
                .any(|value| *value != F::ZERO),
            "segment {segment}, private final product {column}"
        );
    }
    // All16 RFC stream endpoints are private; every changed final live
    // value is still rejected by its actual preceding-row recurrence.
    for product in 0..16 {
        let mut wrong = rows[3];
        let column = ZK_X509_SHA_RFC_CONSUMER_PRODUCTS_V1 + product;
        wrong.aux[column] = wrong.aux[column].add(F::ONE);
        assert!(
            evaluate(&rows[2], &wrong, terminal)
                .iter()
                .any(|value| *value != F::ZERO),
            "segment {segment}, private RFC endpoint product {product}"
        );
    }
}

#[test]
fn sha_fixed_recurrence_selector_is_disjoint_for_every_native_row() {
    use super::super::sha_word_stark::SHA_WORD_CAPACITY_MEMORY_SELECTOR_V1;

    let provider = ZkX509ShaBatchFixedProviderV1::new_v1(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 4,
    })
    .unwrap();
    for (segment, active_rows) in ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1.into_iter().enumerate() {
        for row in 0..ZK_X509_SHA_SEGMENT_ROWS_V1 {
            let fixed = provider.fixed_row_v1(segment, row).unwrap();
            let terminal = fixed[ZK_X509_SHA_FIXED_SEGMENT_LAST_V1];
            let padding = fixed[ZK_X509_SHA_FIXED_PHYSICAL_PADDING_V1];
            assert_eq!(terminal, F(u64::from(row + 1 == active_rows)));
            assert_eq!(padding, F(u64::from(row >= active_rows)));
            assert_eq!(terminal.mul(padding), F::ZERO);
            let row_kind = fixed[..=SHA_WORD_CAPACITY_MEMORY_SELECTOR_V1]
                .iter()
                .copied()
                .fold(F::ZERO, F::add);
            assert_eq!(row_kind, F(u64::from(row < active_rows)));
            let call_last = fixed[SHA_WORD_CAPACITY_CALL_LAST_V1];
            assert_eq!(call_last.mul(padding), F::ZERO);
            assert_eq!(
                row_kind.sub(call_last),
                F::ONE.sub(call_last).sub(padding),
                "segment {segment}, word continuation row {row}",
            );
            assert_eq!(
                F::ONE.sub(terminal).sub(padding),
                F(u64::from(row + 1 < active_rows)),
                "segment {segment}, row {row}",
            );
        }
    }
    // Disclosure count changes public call activity, never the physical
    // boundary. Exercise each public shape at both sides of every boundary.
    for disclosed_attributes in 0..4 {
        let other = ZkX509ShaBatchFixedProviderV1::new_v1(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes,
        })
        .unwrap();
        for (segment, active_rows) in ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1.into_iter().enumerate() {
            for row in [
                0,
                1,
                active_rows - 2,
                active_rows - 1,
                active_rows,
                ZK_X509_SHA_SEGMENT_ROWS_V1 - 1,
            ] {
                let actual = other.fixed_row_v1(segment, row).unwrap();
                let expected = provider.fixed_row_v1(segment, row).unwrap();
                for column in [
                    ZK_X509_SHA_FIXED_SEGMENT_FIRST_V1,
                    ZK_X509_SHA_FIXED_SEGMENT_LAST_V1,
                    ZK_X509_SHA_FIXED_PHYSICAL_PADDING_V1,
                ] {
                    assert_eq!(actual[column], expected[column]);
                }
            }
        }
    }
}

#[test]
fn sha_physical_padding_wrap_has_zero_residues_and_rejects_nonzero_cells() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;

    let provider = ZkX509ShaBatchFixedProviderV1::new_v1(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 4,
    })
    .unwrap();
    for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
        let padding = physical_padding_row_v1(ZK_X509_SHA_SEGMENT_ROWS_V1 - 1);
        assert_eq!(
            padding.fixed,
            provider
                .fixed_row_v1(segment, ZK_X509_SHA_SEGMENT_ROWS_V1 - 1)
                .unwrap()
        );
        let (manifest, local) = provider
            .schedule()
            .logical_row(segment * ZK_X509_SHA_SEGMENT_ROWS_V1)
            .unwrap();
        assert_eq!(local, 0);
        let call = build_zk_x509_sha_batch_call_trace_v1(
            manifest,
            &witness_for(manifest),
            word_challenges(),
            challenges(),
            &rfc_challenges(),
            4,
        )
        .unwrap();
        let mut first = call.row(0).unwrap();
        first.fixed = provider.fixed_row_v1(segment, 0).unwrap();
        assert!(
            first.aux[ZK_X509_SHA_INPUT_PRODUCTS_V1..]
                .iter()
                .all(|value| *value == F::ONE)
        );
        // These are the original failing recurrence values: every native
        // product is zero in padding and starts at one at the cyclic successor.
        let old_gate = F::ONE.sub(padding.fixed[ZK_X509_SHA_FIXED_SEGMENT_LAST_V1]);
        assert_eq!(
            first.aux[ZK_X509_SHA_INPUT_PRODUCTS_V1..]
                .iter()
                .map(|value| old_gate.mul(*value))
                .filter(|value| *value != F::ZERO)
                .count(),
            24
        );
        let terminal = segment as u8;
        let boundaries = neutral_ca_call_boundaries();
        let evaluate = |current: &ZkX509ShaBatchRowV1| {
            evaluate_zk_x509_sha_batch_residues_v1(
                current,
                &first,
                word_challenges(),
                challenges(),
                &rfc_challenges(),
                terminal,
                &boundaries,
            )
            .unwrap()
        };
        let residues = evaluate(&padding);
        assert!(
            residues.iter().all(|value| *value == F::ZERO),
            "segment {segment}, failing cyclic residue indices {:?}",
            residues
                .iter()
                .enumerate()
                .filter_map(|(index, value)| (*value != F::ZERO).then_some(index))
                .collect::<Vec<_>>()
        );
        let lift = |row: &ZkX509ShaBatchRowV1| ZkX509ShaBatchRowV1 {
            base: row.base.map(E::from_base),
            aux: row.aux.map(E::from_base),
            fixed: row.fixed.map(E::from_base),
        };
        assert!(
            evaluate_zk_x509_sha_batch_residues_over_field_v1(
                &lift(&padding),
                &lift(&first),
                word_challenges(),
                challenges(),
                &rfc_challenges(),
                terminal,
                &boundaries
            )
            .unwrap()
            .iter()
            .all(|value| *value == E::ZERO)
        );
        for column in 0..ZK_X509_SHA_BATCH_BASE_WIDTH_V1 {
            let mut changed = padding;
            changed.base[column] = F::ONE;
            assert!(
                evaluate(&changed).iter().any(|value| *value != F::ZERO),
                "segment {segment}, padding base column {column}"
            );
        }
        for column in 0..ZK_X509_SHA_BATCH_AUX_WIDTH_V1 {
            let mut changed = padding;
            changed.aux[column] = F::ONE;
            assert!(
                evaluate(&changed).iter().any(|value| *value != F::ZERO),
                "segment {segment}, padding auxiliary column {column}"
            );
        }
    }
}
