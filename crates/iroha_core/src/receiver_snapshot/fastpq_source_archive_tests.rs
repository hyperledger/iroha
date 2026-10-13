//! Shared FASTPQ archive construction preserves bounded opening semantics.
//! Synthetic source leaves exercise codec/membership binding; no native execution or finality is claimed.

use super::*;
use iroha_crypto::{HashOf, MerkleTree};
use iroha_data_model::{
    NetworkId,
    block::consensus::ExecKv,
    execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
    fastpq::{
        FastpqOrdinarySourceStatementLeafV1, FastpqOrdinarySourceStatementManifestV1,
        FastpqOrdinarySourceStatementOpeningV1, FastpqSourceExecutionEntryV1,
        FastpqSourceExecutionKindV1, FastpqSourceRouteV1, FastpqSourceStatementContextV1,
        build_fastpq_ordinary_source_statement_manifest_v1,
        fastpq_ordinary_source_statement_leaf_hash_v1,
        verify_fastpq_ordinary_source_statement_manifest_write_v1,
        verify_fastpq_ordinary_source_statement_opening_v1,
    },
};
use iroha_model_base::topology::DataSpaceId;

fn source() -> FastpqSourceStatementContextV1 {
    FastpqSourceStatementContextV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"source archive network",
        ))),
        height: 19,
    }
}

fn source_entries(count: u32) -> Vec<FastpqSourceExecutionEntryV1> {
    // Independent complete execution inventory: positions 1 and 3 have no transfer
    // leaves, but their identities still contribute to the source commitment.
    (0..count)
        .map(|index| FastpqSourceExecutionEntryV1 {
            entry_hash: match index {
                0 => Hash::new(b"first"),
                2 => Hash::new(b"second"),
                4 => Hash::new(b"third"),
                _ => Hash::new(index.to_le_bytes()),
            },
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Unrouted,
            dataspace_id: DataSpaceId::new(4),
        })
        .collect()
}

fn leaves() -> Vec<FastpqOrdinarySourceStatementLeafV1> {
    (0..3)
        .map(|index| FastpqOrdinarySourceStatementLeafV1 {
            source: source(),
            statement_index: index,
            entry_index: index * 2,
            effect_count: if index < 2 { 2 } else { 1 },
            entry_hash: source_entries(5)[(index * 2) as usize].entry_hash,
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Unrouted,
            dataspace_id: DataSpaceId::new(4),
            effects_digest: [u8::try_from(index).expect("fixture value fits u8") + 9; 32],
            slot: 19_000_000,
            perm_root: Hash::new(b"synthetic source permission root").into(),
            tx_set_hash: Hash::new(b"synthetic ordered source transactions").into(),
        })
        .collect()
}

fn limits() -> FastpqSourceOpeningBuildLimits {
    FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: 16,
        max_ordinary_write_bytes: 64 * 1024,
        max_executed_entries: 8,
        max_statements: 8,
        manifest_decode: norito::DecodeLimits::new(1024, 32 * 1024, 64 * 1024, 512 * 1024, 32),
    }
}

fn fixture(
    leaves: &[FastpqOrdinarySourceStatementLeafV1],
    executed_entries: u32,
) -> (ExecWitness, FastpqOrdinarySourceStatementManifestV1) {
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        source(),
        &source_entries(executed_entries),
        leaves,
        8,
        8,
    )
    .unwrap();
    let witness = ExecWitness {
        reads: Vec::new(),
        writes: vec![
            ExecKv {
                key: vec![0x10],
                value: b"first".to_vec(),
            },
            ExecKv {
                key: vec![0x20],
                value: b"neighbor".to_vec(),
            },
            ExecKv {
                key: FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1.to_vec(),
                value: norito::encode_canonical(&manifest).unwrap(),
            },
            ExecKv {
                key: vec![0x10],
                value: b"last".to_vec(),
            },
        ],
        fastpq_transcripts: Vec::new(),
        fastpq_batches: Vec::new(),
    };
    (witness, manifest)
}

fn expected_root(manifest: &FastpqOrdinarySourceStatementManifestV1) -> Hash {
    crate::exec_witness::smt::compute_post_state_root(
        &[],
        &[
            KvPair::new(vec![0x10], b"last".to_vec()),
            KvPair::new(vec![0x20], b"neighbor".to_vec()),
            KvPair::new(
                FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
                norito::encode_canonical(manifest).unwrap(),
            ),
        ],
    )
}

#[test]
fn empty_archives_keep_the_real_manifest_path_without_a_leaf_opening() {
    for executed_entries in [0, 5] {
        let (witness, manifest) = fixture(&[], executed_entries);
        let archive = prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            source(),
            &source_entries(executed_entries),
            &[],
            limits(),
        )
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(archive.manifest, manifest);
        assert!(archive.leaves.is_empty());
        assert_eq!(archive.manifest_siblings.len(), 256);
        assert_eq!(archive.ordinary_root, expected_root(&manifest));
        assert!(verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &archive.manifest,
            source(),
            &archive.manifest_siblings,
            archive.ordinary_root,
            8,
            8,
        ));
        assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &archive.manifest,
            source(),
            &archive.manifest_siblings,
            Hash::new(b"another ordinary root"),
            8,
            8,
        ));
        assert_eq!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                source(),
                &source_entries(executed_entries),
                &[],
                0,
                limits()
            ),
            Err("FASTPQ source statement index is absent".to_owned()),
        );
    }
}

#[test]
fn shared_archive_borrows_leaves_after_the_witness_is_released() {
    let leaves = leaves();
    let archive = {
        let (witness, _) = fixture(&leaves, 5);
        prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            source(),
            &source_entries(5),
            &leaves,
            limits(),
        )
        .unwrap()
        .build()
        .unwrap()
    };
    assert_eq!(archive.leaves.as_ptr(), leaves.as_ptr());
    assert_eq!(archive.leaves, leaves.as_slice());
    assert_eq!(archive.ordinary_root, expected_root(&archive.manifest));
}

#[test]
fn shared_archive_and_existing_openings_have_identical_manifest_path_and_membership_bytes() {
    let leaves = leaves();
    let (witness, manifest) = fixture(&leaves, 5);
    let archive = prepare_fastpq_ordinary_source_archive_v1(
        &witness,
        source(),
        &source_entries(5),
        &leaves,
        limits(),
    )
    .unwrap()
    .build()
    .unwrap();
    let tree: MerkleTree<_> = leaves
        .iter()
        .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
        .collect();
    for index in 0..3 {
        let (opening, root) = fastpq_ordinary_source_statement_opening_v1(
            &witness,
            source(),
            &source_entries(5),
            &leaves,
            index,
            limits(),
        )
        .unwrap();
        let expected = FastpqOrdinarySourceStatementOpeningV1 {
            manifest,
            leaf: leaves[index as usize],
            membership: tree.get_proof(index).unwrap(),
            manifest_siblings: archive.manifest_siblings.clone(),
        };
        assert_eq!(opening, expected);
        assert_eq!(
            norito::encode_canonical(&opening).unwrap(),
            norito::encode_canonical(&expected).unwrap()
        );
        assert_eq!(root, archive.ordinary_root);
        assert_eq!(root, expected_root(&manifest));
        assert!(verify_fastpq_ordinary_source_statement_opening_v1(
            &opening,
            &leaves[index as usize],
            root,
            8,
            8,
        ));
    }
}

#[test]
fn shared_archive_rejects_the_entire_malformed_or_duplicate_reserved_key_family() {
    let leaves = leaves();
    let (witness, _) = fixture(&leaves, 5);
    for mutation in 0..4 {
        let mut changed = witness.clone();
        match mutation {
            0 => changed.writes.push(changed.writes[2].clone()),
            1 => changed.writes[2].key.push(0),
            2 => changed.writes[2].key.truncate(1),
            3 => {
                let mut malformed = changed.writes[2].clone();
                malformed.key.push(1);
                changed.writes.push(malformed);
            }
            _ => unreachable!(),
        }
        let archive_error = prepare_fastpq_ordinary_source_archive_v1(
            &changed,
            source(),
            &source_entries(5),
            &leaves,
            limits(),
        )
        .err()
        .unwrap();
        assert!(archive_error.contains("malformed or duplicate reserved key"));
        assert_eq!(
            fastpq_ordinary_source_statement_opening_v1(
                &changed,
                source(),
                &source_entries(5),
                &leaves,
                99,
                limits()
            ),
            Err(archive_error),
            "reserved key validation precedes absent position {mutation}",
        );
    }
}

#[test]
fn shared_archive_requires_exact_complete_leaves_and_manifest_counts() {
    let leaves = leaves();
    let (witness, manifest) = fixture(&leaves, 5);
    for mutation in 0..7 {
        let mut changed = leaves.clone();
        match mutation {
            0 => {
                changed.pop();
            }
            1 => changed[0].effects_digest[0] ^= 1,
            2 => changed.swap(0, 1),
            3 => changed[1].effect_count += 1,
            4 => changed[0].slot += 1,
            5 => changed[0].perm_root[0] ^= 1,
            6 => changed[0].tx_set_hash[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            prepare_fastpq_ordinary_source_archive_v1(
                &witness,
                source(),
                &source_entries(5),
                &changed,
                limits(),
            )
            .is_err()
        );
    }
    for mutation in 0..3 {
        let mut changed = manifest;
        match mutation {
            0 => changed.statement_count -= 1,
            1 => changed.statement_root = Hash::new(b"another leaf root"),
            2 => changed.executed_entry_count = 4,
            _ => unreachable!(),
        }
        let mut changed_witness = witness.clone();
        changed_witness.writes[2].value = norito::encode_canonical(&changed).unwrap();
        assert!(
            prepare_fastpq_ordinary_source_archive_v1(
                &changed_witness,
                source(),
                &source_entries(5),
                &leaves,
                limits(),
            )
            .is_err()
        );
    }
    let mut wrong_source = source();
    wrong_source.height += 1;
    assert!(
        prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            wrong_source,
            &source_entries(5),
            &leaves,
            limits(),
        )
        .is_err()
    );
}

#[test]
fn shared_archive_preserves_exact_caps_and_rejects_one_below_before_position_checks() {
    let leaves = leaves();
    let (witness, manifest) = fixture(&leaves, 5);
    let exact = FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: witness.writes.len(),
        max_ordinary_write_bytes: witness
            .writes
            .iter()
            .map(|write| write.key.len() + write.value.len())
            .sum(),
        max_executed_entries: manifest.executed_entry_count,
        max_statements: manifest.statement_count,
        ..limits()
    };
    prepare_fastpq_ordinary_source_archive_v1(
        &witness,
        source(),
        &source_entries(5),
        &leaves,
        exact,
    )
    .unwrap()
    .build()
    .unwrap();
    for boundary in 0..4 {
        let mut changed = exact;
        match boundary {
            0 => changed.max_ordinary_writes -= 1,
            1 => changed.max_ordinary_write_bytes -= 1,
            2 => changed.max_executed_entries -= 1,
            3 => changed.max_statements -= 1,
            _ => unreachable!(),
        }
        let error = prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            source(),
            &source_entries(5),
            &leaves,
            changed,
        )
        .err()
        .unwrap();
        assert_eq!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                source(),
                &source_entries(5),
                &leaves,
                99,
                changed
            ),
            Err(error),
        );
    }
}

#[test]
fn empty_and_nonempty_shared_archives_restore_every_supported_ambient_layout() {
    for leaves in [Vec::new(), leaves()] {
        let (witness, _) = fixture(&leaves, 5);
        let expected = prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            source(),
            &source_entries(5),
            &leaves,
            limits(),
        )
        .unwrap()
        .build()
        .unwrap();
        for flags in
            (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            let actual = prepare_fastpq_ordinary_source_archive_v1(
                &witness,
                source(),
                &source_entries(5),
                &leaves,
                limits(),
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(actual.manifest, expected.manifest);
            assert_eq!(actual.leaves, expected.leaves);
            assert_eq!(actual.manifest_siblings, expected.manifest_siblings);
            assert_eq!(actual.ordinary_root, expected.ordinary_root);
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
    }
}

#[test]
fn d7_only_empty_archive_accepts_exact_zero_entry_and_statement_caps() {
    let (mut witness, manifest) = fixture(&[], 0);
    witness
        .writes
        .retain(|write| write.key == FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1);
    assert_eq!(witness.writes.len(), 1);
    let exact = FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: 1,
        max_ordinary_write_bytes: witness.writes[0].key.len() + witness.writes[0].value.len(),
        max_executed_entries: 0,
        max_statements: 0,
        ..limits()
    };
    let archive = prepare_fastpq_ordinary_source_archive_v1(&witness, source(), &[], &[], exact)
        .unwrap()
        .build()
        .unwrap();
    let expected = crate::exec_witness::smt::compute_post_state_root(
        &[],
        &[KvPair::new(
            FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
            norito::encode_canonical(&manifest).unwrap(),
        )],
    );
    assert_eq!(archive.manifest, manifest);
    assert!(archive.leaves.is_empty());
    assert_eq!(archive.ordinary_root, expected);
    assert_ne!(
        archive.ordinary_root,
        crate::exec_witness::smt::compute_post_state_root(&[], &[]),
        "an explicit empty manifest remains an ordinary write",
    );
    assert_eq!(archive.manifest_siblings, vec![Hash::new([]); 256]);
    assert!(verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &archive.manifest,
        source(),
        &archive.manifest_siblings,
        archive.ordinary_root,
        0,
        0,
    ));
    assert_eq!(
        fastpq_ordinary_source_statement_opening_v1(&witness, source(), &[], &[], 0, exact),
        Err("FASTPQ source statement index is absent".to_owned()),
    );
}

#[test]
fn empty_archive_preparation_rejects_absent_or_corrupted_manifest() {
    for executed_entries in [0, 5] {
        let (witness, manifest) = fixture(&[], executed_entries);
        let mut absent = witness.clone();
        absent
            .writes
            .retain(|write| write.key != FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1);
        assert_eq!(
            prepare_fastpq_ordinary_source_archive_v1(
                &absent,
                source(),
                &source_entries(executed_entries),
                &[],
                limits()
            )
            .err()
            .unwrap(),
            "FASTPQ source manifest write is absent",
        );
        for mutation in 0..7 {
            let mut changed = manifest;
            match mutation {
                0 => {
                    changed.source.network_id = NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"another empty archive network")),
                    );
                }
                1 => changed.source.height += 1,
                2 => changed.source.height = 0,
                3 => changed.statement_count = 1,
                4 => changed.statement_root = Hash::new(b"nonempty root for empty archive"),
                5 => changed.executed_entry_count = limits().max_executed_entries + 1,
                6 => {}
                _ => unreachable!(),
            }
            let mut changed_witness = witness.clone();
            changed_witness.writes[2].value = if mutation == 6 {
                vec![0xFF]
            } else {
                norito::encode_canonical(&changed).unwrap()
            };
            let error = prepare_fastpq_ordinary_source_archive_v1(
                &changed_witness,
                source(),
                &source_entries(executed_entries),
                &[],
                limits(),
            )
            .err()
            .unwrap_or_else(|| {
                panic!("empty archive with {executed_entries} entries accepted mutation {mutation}")
            });
            assert_eq!(
                fastpq_ordinary_source_statement_opening_v1(
                    &changed_witness,
                    source(),
                    &source_entries(executed_entries),
                    &[],
                    0,
                    limits(),
                ),
                Err(error),
                "empty manifest validation must precede absent-position rejection",
            );
        }
    }
}

#[test]
fn archive_preparation_keeps_stricter_and_repeated_outer_decode_budgets() {
    for leaves in [Vec::new(), leaves()] {
        let (witness, _) = fixture(&leaves, 5);
        let run = || {
            prepare_fastpq_ordinary_source_archive_v1(
                &witness,
                source(),
                &source_entries(5),
                &leaves,
                limits(),
            )
            .map(|_| ())
        };
        let local = limits().manifest_decode;
        let (result, measured) = norito::core::with_decode_limits_measured(local, run);
        result.unwrap();
        let charged = measured.total_allocated_bytes();
        assert!(
            charged > 0,
            "canonical manifest decoding must charge its owned allocations"
        );
        let exact = norito::DecodeLimits::new(
            local.max_sequence_elements(),
            local.max_field_bytes(),
            local.max_total_elements(),
            charged,
            local.max_nesting_depth(),
        );
        norito::core::with_decode_limits_scope(exact, || {
            run().unwrap();
            let error = run().expect_err("later preparation cannot reset its caller's charges");
            assert!(
                error.starts_with("FASTPQ source manifest is not bounded canonical Norito:"),
                "repeated preparation must fail at manifest decode: {error}",
            );
        });
        let short = norito::DecodeLimits::new(
            local.max_sequence_elements(),
            local.max_field_bytes(),
            local.max_total_elements(),
            charged - 1,
            local.max_nesting_depth(),
        );
        let error = norito::core::with_decode_limits_scope(short, run)
            .expect_err("local manifest limits cannot relax a stricter enclosing byte budget");
        assert!(
            error.starts_with("FASTPQ source manifest is not bounded canonical Norito:"),
            "short outer budget must fail at manifest decode: {error}",
        );
        run().expect("failed outer budget scopes must not leak into later preparation");
    }
}

#[test]
fn shared_archive_binds_complete_entries_without_transfer_leaves() {
    for leaves in [Vec::new(), leaves()] {
        let entries = source_entries(5);
        let (witness, _) = fixture(&leaves, 5);
        prepare_fastpq_ordinary_source_archive_v1(&witness, source(), &entries, &leaves, limits())
            .unwrap();
        for mutation in 0..5 {
            let mut changed = entries.clone();
            match mutation {
                0 => changed[1].entry_hash = Hash::new(b"changed non-transfer entry"),
                1 => changed.swap(1, 3),
                2 => changed[1].execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
                3 => changed[1].dataspace_id = DataSpaceId::new(9),
                4 => {
                    changed.remove(1);
                }
                _ => unreachable!(),
            }
            assert!(
                prepare_fastpq_ordinary_source_archive_v1(
                    &witness,
                    source(),
                    &changed,
                    &leaves,
                    limits(),
                )
                .is_err(),
                "complete entry expectation mutation {mutation} was accepted",
            );
        }
        let mut malformed_witness = witness.clone();
        malformed_witness.writes[2].value = vec![0xFF];
        let short = FastpqSourceOpeningBuildLimits {
            max_executed_entries: 4,
            ..limits()
        };
        assert_eq!(
            prepare_fastpq_ordinary_source_archive_v1(
                &malformed_witness,
                source(),
                &entries,
                &leaves,
                short,
            )
            .err()
            .unwrap(),
            "FASTPQ source opening exceeds its write or entry count cap",
            "entry cap must be checked before manifest decode or tree allocation",
        );
    }
}

#[test]
fn shared_archive_refuses_unsupported_coverage_even_with_exact_source_and_leaves() {
    for leaves in [Vec::new(), leaves()] {
        let (mut witness, mut manifest) = fixture(&leaves, 5);
        manifest.coverage = iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Unsupported;
        let frame = norito::encode_canonical(&manifest).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&frame).unwrap(),
            manifest
        );
        witness.writes[2].value = frame;
        let original = witness.clone();
        assert!(
            prepare_fastpq_ordinary_source_archive_v1(
                &witness,
                source(),
                &source_entries(5),
                &leaves,
                limits()
            )
            .is_err()
        );
        assert_eq!(witness, original);
    }
}
