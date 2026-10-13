//! Scoped leaf controls; these roots have no complete-State or finalized authority.

use super::*;
use iroha_crypto::HashOf;
use iroha_data_model::{
    consensus::{ConsensusKeyId, ConsensusKeyRole},
    nexus::{DomainEndorsement, UniversalAccountId},
};
use iroha_model_base::domain::DomainId;

const TABLES: [&str; 3] = [
    "world.consensus_keys_by_pk",
    "world.domain_endorsements_by_domain",
    "world.twitter_bindings_by_uaid",
];

fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 3,
        max_rows: 3,
        max_payload_bytes: 8 * 1024,
        max_ordered_table_bytes: MAX_NORITO_TREE_PAYLOAD_BYTES,
        max_streamed_value_bytes: 8 * 1024 * 1024,
    }
}

#[test]
fn typed_table_rows_bind_raw_norito_key_order_schema_and_exact_range() {
    let keys = ["aaaa".to_owned(), "bbbb".to_owned(), "cccc".to_owned()];
    let values = [
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "second")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "third")],
    ];
    let table = TABLES[0];
    let rows = [(2, 2), (0, 0), (1, 1)]
        .into_iter()
        .map(|(key, value)| (&keys[key], &values[value]));
    let ordered = CanonicalTableLeafSet::ordered_table_from_rows(table, limits(), rows).unwrap();
    assert_eq!(ordered.len(), 3);
    let selection = CanonicalTableLeafSet::new(&[table], limits(), &fixture_budget()).unwrap();
    let start = norito::codec::encode_adaptive(&keys[0]);
    let end = norito::codec::encode_adaptive(&keys[2]);
    let proof = ordered.prove_range(&start, &end, 2, 8 * 1024).unwrap();
    let verified = proof
        .verify(NoritoKeyRangeVerifyRequestV1 {
            expected_root: &ordered.root(),
            schema_hash: &selection.selection.schema,
            domain: table.as_bytes(),
            start: &start,
            end: &end,
            max_rows: 2,
            max_bytes: 8 * 1024,
        })
        .unwrap();
    assert_eq!(verified.len(), 2);
    assert_eq!(
        verified
            .rows()
            .map(|(key, _)| key.to_vec())
            .collect::<Vec<_>>(),
        vec![
            norito::codec::encode_adaptive(&keys[0]),
            norito::codec::encode_adaptive(&keys[1]),
        ]
    );
    assert!(
        proof
            .verify(NoritoKeyRangeVerifyRequestV1 {
                expected_root: &Hash::new(b"wrong State claim"),
                schema_hash: &selection.selection.schema,
                domain: table.as_bytes(),
                start: &start,
                end: &end,
                max_rows: 2,
                max_bytes: 8 * 1024,
            })
            .is_err()
    );
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        let rebuilt = CanonicalTableLeafSet::ordered_table_from_rows(
            table,
            limits(),
            keys.iter().zip(values.iter()),
        )
        .unwrap();
        assert_eq!(ordered.root(), rebuilt.root());
    }
}

#[test]
fn typed_ordered_rows_reject_wrong_types_duplicate_keys_and_budgets() {
    let table = TABLES[0];
    let key = "aaaa".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    assert!(matches!(
        CanonicalTableLeafSet::ordered_table_from_rows(table, limits(), [(&42_u64, &value)]),
        Err(LeafError::TypeMismatch(id)) if id == table
    ));
    assert!(matches!(
        CanonicalTableLeafSet::ordered_table_from_rows(
            table,
            limits(),
            [(&key, &value), (&key, &value)],
        ),
        Err(LeafError::OrderedRange(NoritoKeyRangeError::UnsortedKeys))
    ));
    assert!(matches!(
        CanonicalTableLeafSet::ordered_table_from_rows(
            table,
            LeafLimits {
                max_rows: 1,
                ..limits()
            },
            [(&key, &value), (&"bbbb".to_owned(), &value)],
        ),
        Err(LeafError::RowLimit)
    ));
    assert!(matches!(
        CanonicalTableLeafSet::ordered_table_from_rows(
            table,
            LeafLimits {
                max_payload_bytes: 1,
                ..limits()
            },
            [(&key, &value)],
        ),
        Err(LeafError::PayloadLimit)
    ));
    assert!(matches!(
        CanonicalTableLeafSet::ordered_table_from_rows(
            table,
            LeafLimits {
                max_ordered_table_bytes: 1,
                ..limits()
            },
            [(&key, &value)],
        ),
        Err(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))
    ));
}

#[test]
fn paired_table_indexes_commit_the_same_retained_norito_rows() {
    let table = TABLES[0];
    let keys = ["aaaa".to_owned(), "bbbb".to_owned()];
    let values = [
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "second")],
    ];
    let paired = CanonicalTableLeafSet::paired_table_from_rows(
        table,
        limits(),
        &capture_budget(),
        [(&keys[1], &values[1]), (&keys[0], &values[0])],
    )
    .unwrap();
    let same_rows = CanonicalTableLeafSet::paired_table_from_rows(
        table,
        limits(),
        &capture_budget(),
        keys.iter().zip(values.iter()),
    )
    .unwrap();
    assert_eq!(paired.root(), same_rows.root());
    assert_eq!(paired.ordered.len(), 2);

    let mut streamed = CanonicalTableLeafSet::new(&[table], limits(), &fixture_budget()).unwrap();
    for (key, value) in keys.iter().zip(values.iter()) {
        streamed.insert(table, key, value).unwrap();
    }
    assert_eq!(paired.lookup_root(), streamed.root());
    let proof = paired.prove_lookup(table, &keys[0]).unwrap();
    let expected_value = typed_payload_hash(
        table,
        paired.lookup.selection.table(table).unwrap().1.1,
        &values[0],
        VALUE_PAYLOAD,
        limits().max_payload_bytes,
    )
    .unwrap();
    assert_eq!(
        CanonicalTableLeafSet::verify_paired_lookup(
            table,
            limits(),
            &paired.root(),
            &paired.ordered_root(),
            &keys[0],
            &proof,
        ),
        Ok(Some(expected_value))
    );
    assert!(matches!(
        CanonicalTableLeafSet::verify_paired_lookup(
            table,
            limits(),
            &paired.root(),
            &Hash::new(b"wrong ordered component"),
            &keys[0],
            &proof,
        ),
        Err(LeafError::RootMismatch)
    ));
    let start = norito::codec::encode_adaptive(&keys[0]);
    let end = norito::codec::encode_adaptive(&keys[1]);
    let range = paired.prove_raw_range(&start, &end, 1, 8 * 1024).unwrap();
    let verified = CanonicalTableLeafSet::verify_paired_raw_range(
        table,
        limits(),
        &paired.root(),
        &paired.lookup_root(),
        &paired.ordered_root(),
        &start,
        &end,
        1,
        8 * 1024,
        &range,
    )
    .unwrap();
    assert_eq!(
        verified.rows().map(|(key, _)| key).collect::<Vec<_>>(),
        vec![start.as_slice()]
    );
    assert!(matches!(
        CanonicalTableLeafSet::verify_paired_raw_range(
            table,
            limits(),
            &paired.root(),
            &Hash::new(b"wrong lookup component"),
            &paired.ordered_root(),
            &start,
            &end,
            1,
            8 * 1024,
            &range,
        ),
        Err(LeafError::RootMismatch)
    ));
    assert_eq!(
        paired
            .ordered
            .digest_rows()
            .map(|(key, _)| key.to_vec())
            .collect::<Vec<_>>(),
        keys.iter()
            .map(norito::codec::encode_adaptive)
            .collect::<Vec<_>>()
    );

    let mut changed_values = values.clone();
    changed_values[1].push(ConsensusKeyId::new(ConsensusKeyRole::Validator, "third"));
    let changed = CanonicalTableLeafSet::paired_table_from_rows(
        table,
        limits(),
        &capture_budget(),
        keys.iter().zip(changed_values.iter()),
    )
    .unwrap();
    assert_ne!(paired.root(), changed.root());
    assert_ne!(paired.lookup_root(), changed.lookup_root());
    assert_ne!(paired.ordered_root(), changed.ordered_root());

    let omitted = CanonicalTableLeafSet::paired_table_from_rows(
        table,
        limits(),
        &capture_budget(),
        [(&keys[0], &values[0])],
    )
    .unwrap();
    assert_ne!(paired.root(), omitted.root());
    assert_ne!(paired.lookup_root(), omitted.lookup_root());
    assert_ne!(paired.ordered_root(), omitted.ordered_root());
}

#[test]
fn typed_preimage_rejects_verified_digest_from_another_table() {
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 1,
        max_payload_bytes: 1024,
        max_ordered_table_bytes: 1024,
        max_streamed_value_bytes: 8 * 1024 * 1024,
    };
    let source_table = "world.contract_code_upload_chunks";
    let source = CanonicalTableLeafSet::new(&[source_table], limits, &fixture_budget()).unwrap();
    let target_table = "world.contract_code";
    let key = Hash::new(b"same raw key");
    let raw_key = norito::codec::encode_adaptive(&key);
    let value = vec![1_u8, 2, 3];
    let raw_value = norito::codec::encode_adaptive(&value);
    let value_digest = digest_norito_value_frame_v1(
        u32::try_from(raw_value.len()).expect("fixture value fits u32"),
        |writer| writer.write_all(&raw_value),
    )
    .unwrap();
    let tree = NoritoKeyDigestRangeTreeV1::from_sorted_digests(
        source.selection.schema,
        source_table.as_bytes(),
        [(raw_key.as_slice(), value_digest)],
        1024,
        &capture_budget(),
    )
    .unwrap();
    let mut end = raw_key.clone();
    end.push(0xff);
    let proof = tree.prove_range(&raw_key, &end, 1, 1024).unwrap();
    let verified = proof
        .verify(NoritoKeyRangeVerifyRequestV1 {
            expected_root: &tree.root(),
            schema_hash: &source.selection.schema,
            domain: source_table.as_bytes(),
            start: &raw_key,
            end: &end,
            max_rows: 1,
            max_bytes: 1024,
        })
        .unwrap();
    assert_eq!(
        verified.rows().next(),
        Some((raw_key.as_slice(), value_digest))
    );
    assert_eq!(
        CanonicalTableLeafSet::verify_paired_value_preimage(
            target_table,
            limits,
            &verified,
            &raw_key,
            &value,
        ),
        Err(LeafError::RootMismatch)
    );
}

#[test]
fn paired_table_streaming_budget_counts_both_passes_across_all_rows() {
    let table = TABLES[0];
    let keys = ["first".to_owned(), "second".to_owned()];
    let values = [
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "a")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "b")],
    ];
    let length = norito::codec::encode_adaptive(&values[0]).len();
    assert_eq!(length, norito::codec::encode_adaptive(&values[1]).len());
    let exact = LeafLimits {
        max_streamed_value_bytes: (4 * length) as u64,
        ..limits()
    };
    let captured = CanonicalTableLeafSet::paired_table_from_rows(
        table,
        exact,
        &capture_budget(),
        keys.iter().zip(&values),
    )
    .expect("exact two-pass budget covers both full values");
    assert_eq!(captured.row_count(), 2);
    assert!(matches!(
        CanonicalTableLeafSet::paired_table_from_rows(
            table,
            LeafLimits {
                max_streamed_value_bytes: exact.max_streamed_value_bytes - 1,
                ..exact
            },
            &capture_budget(),
            keys.iter().zip(&values),
        ),
        Err(LeafError::StreamedTableLimit)
    ));
    assert!(matches!(
        CanonicalTableLeafSet::paired_table_from_rows(
            table,
            LeafLimits {
                max_payload_bytes: length - 1,
                ..exact
            },
            &capture_budget(),
            keys.iter().zip(&values),
        ),
        Err(LeafError::PayloadLimit)
    ));
    assert_eq!(
        value_stream_bound(exact, exact.max_streamed_value_bytes + 1),
        Err(LeafError::StreamedTableLimit)
    );
    let mut spent = exact.max_streamed_value_bytes;
    assert_eq!(
        charge_streamed_value(&mut spent, 1, exact),
        Err(LeafError::StreamedTableLimit)
    );
}

fn root_with_order(reverse: Option<usize>, insertion_order: &[usize]) -> Hash {
    let mut keys = vec![
        ConsensusKeyId::new(ConsensusKeyRole::Validator, "first"),
        ConsensusKeyId::new(ConsensusKeyRole::Validator, "second"),
    ];
    let mut endorsements = vec![
        HashOf::<DomainEndorsement>::from_untyped_unchecked(Hash::new(b"first endorsement")),
        HashOf::<DomainEndorsement>::from_untyped_unchecked(Hash::new(b"second endorsement")),
    ];
    let mut bindings = vec![Hash::new(b"first binding"), Hash::new(b"second binding")];
    match reverse {
        Some(0) => keys.reverse(),
        Some(1) => endorsements.reverse(),
        Some(2) => bindings.reverse(),
        None => {}
        _ => unreachable!(),
    }
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid"));
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    for table in insertion_order {
        match table {
            0 => set
                .insert(TABLES[0], &"public-key".to_owned(), &keys)
                .unwrap(),
            1 => set.insert(TABLES[1], &domain, &endorsements).unwrap(),
            2 => set.insert(TABLES[2], &uaid, &bindings).unwrap(),
            _ => unreachable!(),
        }
    }
    set.root()
}

#[test]
fn three_independent_ordered_authorities_change_scoped_root() {
    let original = root_with_order(None, &[0, 1, 2]);
    assert_eq!(original, root_with_order(None, &[2, 0, 1]));
    for index in 0..3 {
        assert_ne!(original, root_with_order(Some(index), &[0, 1, 2]));
    }
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(original, root_with_order(None, &[0, 1, 2]));
    }
}

#[test]
fn field_selection_and_nominal_types_fail_closed() {
    let empty = CanonicalTableLeafSet::new(&[], limits(), &fixture_budget())
        .unwrap()
        .root();
    let selected = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget())
        .unwrap()
        .root();
    assert_ne!(empty, selected, "empty table declarations bind the root");
    assert!(matches!(
        CanonicalTableLeafSet::new(&["world.proofs_by_tag"], limits(), &fixture_budget()),
        Err(LeafError::NotCanonicalTable("world.proofs_by_tag"))
    ));
    // A declared semantic schema binds the empty table too. Selecting it
    // grants no authority to bypass its owner's projection validation.
    let semantic = CanonicalTableLeafSet::new(
        &["world.musubi_resolver_index"],
        limits(),
        &fixture_budget(),
    )
    .unwrap();
    assert_ne!(empty, semantic.root());
    assert!(matches!(
        CanonicalTableLeafSet::new(&["world.parameters"], limits(), &fixture_budget()),
        Err(LeafError::NotCanonicalTable("world.parameters"))
    ));
    assert!(matches!(
        CanonicalTableLeafSet::new(&["world.unknown"], limits(), &fixture_budget()),
        Err(LeafError::UnknownField)
    ));
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    let keys = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    assert!(matches!(
        set.insert(TABLES[0], &42_u64, &keys),
        Err(LeafError::TypeMismatch(id)) if id == TABLES[0]
    ));
    assert!(matches!(
        set.insert("world.accounts", &42_u64, &keys),
        Err(LeafError::TableNotSelected)
    ));
    assert_eq!(set.root(), selected);
}

#[test]
fn row_and_payload_limits_reject_without_changing_root() {
    let one_row = LeafLimits {
        max_rows: 1,
        ..limits()
    };
    let mut set = CanonicalTableLeafSet::new(&TABLES, one_row, &fixture_budget()).unwrap();
    let keys = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    set.insert(TABLES[0], &"public-key".to_owned(), &keys)
        .unwrap();
    let before = set.root();
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let endorsements = vec![HashOf::<DomainEndorsement>::from_untyped_unchecked(
        Hash::new(b"endorsement"),
    )];
    assert!(matches!(
        set.insert(TABLES[1], &domain, &endorsements),
        Err(LeafError::RowLimit)
    ));
    assert_eq!(set.root(), before);

    let tiny = LeafLimits {
        max_payload_bytes: 1,
        ..limits()
    };
    let mut set = CanonicalTableLeafSet::new(&TABLES, tiny, &fixture_budget()).unwrap();
    let before = set.root();
    assert!(matches!(
        set.insert(TABLES[0], &"public-key".to_owned(), &keys),
        Err(LeafError::PayloadLimit)
    ));
    assert_eq!(set.root(), before);
}

#[test]
fn duplicate_row_and_selected_table_limit_reject() {
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    let keys = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    set.insert(TABLES[0], &"public-key".to_owned(), &keys)
        .unwrap();
    let before = set.root();
    assert!(matches!(
        set.insert(TABLES[0], &"public-key".to_owned(), &keys),
        Err(LeafError::DuplicateRow(id)) if id == TABLES[0]
    ));
    assert_eq!(set.root(), before);
    assert!(matches!(
        CanonicalTableLeafSet::new(
            &TABLES,
            LeafLimits {
                max_tables: 2,
                ..limits()
            },
            &fixture_budget()
        ),
        Err(LeafError::TableLimit)
    ));
    assert!(matches!(
        CanonicalTableLeafSet::new(&[TABLES[0], TABLES[0]], limits(), &fixture_budget()),
        Err(LeafError::DuplicateTable(id)) if id == TABLES[0]
    ));
}

#[test]
fn selected_table_lookup_authenticates_row_absence_and_value_digest() {
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    let key = "public-key".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    set.insert(TABLES[0], &key, &value).unwrap();
    let root = set.root();
    let present = set.prove_lookup(TABLES[0], &key).unwrap();
    let (_, (_, value_schema)) = set.selection.table(TABLES[0]).unwrap();
    let expected_value = typed_payload_hash(
        TABLES[0],
        value_schema,
        &value,
        VALUE_PAYLOAD,
        limits().max_payload_bytes,
    )
    .unwrap();
    assert_eq!(
        CanonicalTableLeafSet::verify_lookup(&TABLES, limits(), &root, TABLES[0], &key, &present),
        Ok(Some(expected_value))
    );
    let mut altered = value.clone();
    altered.push(ConsensusKeyId::new(ConsensusKeyRole::Validator, "second"));
    assert_ne!(
        expected_value,
        typed_payload_hash(
            TABLES[0],
            value_schema,
            &altered,
            VALUE_PAYLOAD,
            limits().max_payload_bytes,
        )
        .unwrap(),
        "an altered supplied value cannot match the authenticated digest"
    );

    let absent_key = "another-public-key".to_owned();
    let absent = set.prove_lookup(TABLES[0], &absent_key).unwrap();
    assert_eq!(
        CanonicalTableLeafSet::verify_lookup(
            &TABLES,
            limits(),
            &root,
            TABLES[0],
            &absent_key,
            &absent,
        ),
        Ok(None)
    );
    assert_eq!(present.entry_count(), 1);
    assert_eq!(present.claimed_root(), absent.claimed_root());
}

#[test]
fn selected_table_lookup_rejects_wrong_selection_root_and_bounds() {
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    let key = "public-key".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "first")];
    set.insert(TABLES[0], &key, &value).unwrap();
    let root = set.root();
    let proof = set.prove_lookup(TABLES[0], &key).unwrap();
    assert!(matches!(
        CanonicalTableLeafSet::verify_lookup(
            &TABLES[1..],
            limits(),
            &root,
            TABLES[0],
            &key,
            &proof,
        ),
        Err(LeafError::TableNotSelected)
    ));
    assert_eq!(
        CanonicalTableLeafSet::verify_lookup(
            &TABLES[..2],
            limits(),
            &root,
            TABLES[0],
            &key,
            &proof,
        ),
        Err(LeafError::RootMismatch)
    );
    assert_eq!(
        CanonicalTableLeafSet::verify_lookup(
            &TABLES,
            limits(),
            &Hash::new(b"wrong owner root"),
            TABLES[0],
            &key,
            &proof,
        ),
        Err(LeafError::RootMismatch)
    );
    assert_eq!(
        CanonicalTableLeafSet::verify_lookup(
            &TABLES,
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            &root,
            TABLES[0],
            &key,
            &proof,
        ),
        Err(LeafError::RowLimit)
    );
    assert!(matches!(
        set.prove_lookup(TABLES[0], &42_u64),
        Err(LeafError::TypeMismatch(_))
    ));
}

struct ThreeHashedRows {
    set: CanonicalTableLeafSet,
    keys: Vec<String>,
    values: Vec<Vec<ConsensusKeyId>>,
    expected: Vec<(Hash, Hash)>,
}

fn three_hashed_key_rows() -> ThreeHashedRows {
    let mut set = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    let keys = ["alpha", "beta", "gamma"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let values = ["first", "second", "third"]
        .into_iter()
        .map(|name| vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, name)])
        .collect::<Vec<_>>();
    let (_, (_, value_schema)) = set.selection.table(TABLES[0]).unwrap();

    let mut expected = Vec::new();
    for (key, value) in keys.iter().zip(&values) {
        let path = set.key_path(TABLES[0], key).unwrap();
        let value_hash = typed_payload_hash(
            TABLES[0],
            value_schema,
            value,
            VALUE_PAYLOAD,
            limits().max_payload_bytes,
        )
        .unwrap();
        set.insert(TABLES[0], key, value).unwrap();
        expected.push((path, value_hash));
    }
    expected.sort_unstable_by_key(|&(path, _)| path);
    ThreeHashedRows {
        set,
        keys,
        values,
        expected,
    }
}

#[test]
fn selected_table_hashed_key_range_authenticates_complete_interval_and_empty_gap() {
    let ThreeHashedRows { set, expected, .. } = three_hashed_key_rows();
    let root = set.root();
    let start = expected[0].0;
    let end = expected[2].0;
    let proof = set.prove_hashed_key_range(&start, &end, 2).unwrap();
    assert_eq!(
        CanonicalTableLeafSet::verify_hashed_key_range(
            &TABLES,
            limits(),
            &root,
            &start,
            &end,
            2,
            &proof,
        ),
        Ok(expected[..2].to_vec())
    );
    let empty_start = Hash::prehashed([0; 32]);
    assert!(empty_start < start);
    let empty = set.prove_hashed_key_range(&empty_start, &start, 0).unwrap();
    assert_eq!(
        CanonicalTableLeafSet::verify_hashed_key_range(
            &TABLES,
            limits(),
            &root,
            &empty_start,
            &start,
            0,
            &empty,
        ),
        Ok(Vec::new())
    );
}

#[test]
fn selected_table_hashed_key_range_rejects_wrong_root_omission_and_limits() {
    let ThreeHashedRows {
        set,
        keys,
        values,
        expected,
    } = three_hashed_key_rows();
    let root = set.root();
    let start = expected[0].0;
    let end = expected[2].0;
    let proof = set.prove_hashed_key_range(&start, &end, 2).unwrap();
    let verify = |ids: &[&str], root: &Hash, range: &CanonicalTableHashRangeProof, max_rows| {
        CanonicalTableLeafSet::verify_hashed_key_range(
            ids,
            limits(),
            root,
            &start,
            &end,
            max_rows,
            range,
        )
    };
    assert_eq!(
        verify(&TABLES[..2], &root, &proof, 2),
        Err(LeafError::RootMismatch)
    );
    assert_eq!(
        verify(&TABLES, &Hash::new(b"foreign selected root"), &proof, 2),
        Err(LeafError::RootMismatch)
    );
    assert!(matches!(
        verify(&TABLES, &root, &proof, 1),
        Err(LeafError::InvalidRange(MerkleMapRangeError::Capacity))
    ));
    assert_eq!(
        CanonicalTableLeafSet::verify_hashed_key_range(
            &TABLES,
            LeafLimits {
                max_rows: 2,
                ..limits()
            },
            &root,
            &start,
            &end,
            2,
            &proof,
        ),
        Err(LeafError::RowLimit)
    );
    assert!(matches!(
        set.prove_hashed_key_range(&start, &end, 1),
        Err(LeafError::InvalidRange(MerkleMapRangeError::Capacity))
    ));
    assert_eq!(
        set.prove_hashed_key_range(&start, &end, 4).err(),
        Some(LeafError::RowLimit)
    );
    assert_eq!(
        set.prove_hashed_key_range(&end, &start, 2).err(),
        Some(LeafError::InvalidRange(MerkleMapRangeError::InvalidBounds))
    );

    let mut omitted = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    for (key, value) in keys.iter().zip(&values) {
        if set.key_path(TABLES[0], key).unwrap() != start {
            omitted.insert(TABLES[0], key, value).unwrap();
        }
    }
    let mut forged = omitted.prove_hashed_key_range(&start, &end, 2).unwrap();
    assert_eq!(
        verify(&TABLES, &root, &forged, 2),
        Err(LeafError::RootMismatch),
        "a dropped in-range row changes the selected root"
    );
    forged.map_root = proof.map_root;
    assert_eq!(
        verify(&TABLES, &root, &forged, 2),
        Err(LeafError::RootMismatch),
        "the scoped root also binds the total row count"
    );

    let mut altered = CanonicalTableLeafSet::new(&TABLES, limits(), &fixture_budget()).unwrap();
    for (index, (key, value)) in keys.iter().zip(&values).enumerate() {
        let mut value = value.clone();
        if index == 0 {
            value.push(ConsensusKeyId::new(ConsensusKeyRole::Validator, "altered"));
        }
        altered.insert(TABLES[0], key, &value).unwrap();
    }
    let mut forged = altered.prove_hashed_key_range(&start, &end, 2).unwrap();
    forged.map_root = proof.map_root;
    assert!(matches!(
        verify(&TABLES, &root, &forged, 2),
        Err(LeafError::InvalidRange(MerkleMapRangeError::RootMismatch))
    ));
}

fn capture_budget() -> iroha_allocation::AllocationBudget {
    iroha_allocation::AllocationBudget::new(64 * 1024 * 1024)
}

fn fixture_budget() -> iroha_allocation::AllocationBudget {
    iroha_allocation::AllocationBudget::new(64 * 1024 * 1024)
}
