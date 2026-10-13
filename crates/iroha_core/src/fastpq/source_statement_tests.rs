//! Cross-crate FASTPQ source-opening parity against the actual ordinary-write tree.
//! Synthetic source leaves exercise codec/membership binding; no native execution or finality is claimed.

use super::{FastpqSourceOpeningBuildLimits, fastpq_ordinary_source_statement_opening_v1};
use iroha_crypto::{Hash, HashOf, MerkleTree};
use iroha_data_model::{
    NetworkId, execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1, fastpq::*,
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
fn network(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([seed])))
}

fn entries() -> Vec<FastpqSourceExecutionEntryV1> {
    (0..5)
        .map(|i| FastpqSourceExecutionEntryV1 {
            entry_hash: if i % 2 == 0 {
                Hash::new([i / 2])
            } else {
                Hash::new([100 + i])
            },
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::new(2),
                lane_incarnation: Hash::new(b"source lane incarnation"),
            }),
            dataspace_id: DataSpaceId::new(4),
        })
        .collect()
}

fn leaves() -> Vec<FastpqOrdinarySourceStatementLeafV1> {
    (0..3)
        .map(|i| FastpqOrdinarySourceStatementLeafV1 {
            source: FastpqSourceStatementContextV1 {
                network_id: network(7),
                height: 19,
            },
            statement_index: i,
            entry_index: i * 2,
            effect_count: 1,
            entry_hash: Hash::new([u8::try_from(i).expect("fixture value fits u8")]),
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::new(2),
                lane_incarnation: Hash::new(b"source lane incarnation"),
            }),
            dataspace_id: DataSpaceId::new(4),
            effects_digest: [u8::try_from(i).expect("fixture value fits u8") + 9; 32],
            slot: 19_000_000,
            perm_root: Hash::new(b"synthetic source permission root").into(),
            tx_set_hash: Hash::new(b"synthetic ordered source transactions").into(),
        })
        .collect()
}

#[test]
fn manifest_write_matches_existing_core_sparse_tree_and_rejects_substitution() {
    let leaves = leaves();
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        leaves[0].source,
        &entries(),
        &leaves,
        5,
        5,
    )
    .unwrap();
    let encoded = norito::encode_canonical(&manifest).unwrap();
    assert!(encoded.len() < 512);
    let writes = [crate::exec_witness::smt::KvPair::new(
        FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
        encoded,
    )];
    let root = crate::exec_witness::smt::compute_post_state_root(&[], &writes);
    let siblings = [Hash::new([]); 256];
    assert!(verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &manifest,
        manifest.source,
        &siblings,
        root,
        5,
        5
    ));
    for mutation in 0..6 {
        let mut tampered_value = manifest;
        match mutation {
            0 => tampered_value.source.network_id = network(8),
            1 => tampered_value.source.height += 1,
            2 => tampered_value.executed_entry_count += 1,
            3 => tampered_value.statement_count -= 1,
            4 => tampered_value.statement_root = Hash::new(b"another statement tree"),
            5 => tampered_value.source_entries_digest = Hash::new(b"another source inventory"),
            _ => unreachable!(),
        }
        assert!(
            !verify_fastpq_ordinary_source_statement_manifest_write_v1(
                &tampered_value,
                tampered_value.source,
                &siblings,
                root,
                6,
                6
            ),
            "field {mutation}"
        );
    }
    for level in [0, 1, 127, 255] {
        let mut tampered_value = siblings;
        tampered_value[level] = Hash::new([u8::try_from(level).expect("fixture value fits u8")]);
        assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &manifest,
            manifest.source,
            &tampered_value,
            root,
            5,
            5
        ));
    }
    for len in [0, 255, 257] {
        assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &manifest,
            manifest.source,
            &vec![Hash::new([]); len],
            root,
            5,
            5
        ));
    }
    assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &manifest,
        manifest.source,
        &siblings,
        Hash::new(b"other root"),
        5,
        5
    ));
    assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &manifest,
        manifest.source,
        &siblings,
        root,
        4,
        4
    ));
}

#[test]
fn empty_manifest_write_is_present_and_layout_invariant() {
    let source = leaves()[0].source;
    let manifest =
        build_fastpq_ordinary_source_statement_manifest_v1(source, &entries(), &[], 5, 5).unwrap();
    let writes = [crate::exec_witness::smt::KvPair::new(
        FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
        norito::encode_canonical(&manifest).unwrap(),
    )];
    let root = crate::exec_witness::smt::compute_post_state_root(&[], &writes);
    let siblings = [Hash::new([]); 256];
    for flags in (u8::MIN..=u8::MAX).filter(|&f| norito::core::validate_header_flags(f).is_ok()) {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert!(verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &manifest, source, &siblings, root, 5, 5
        ));
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
    assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &manifest,
        source,
        &siblings,
        crate::exec_witness::smt::compute_post_state_root(&[], &[]),
        5,
        5
    ));
    let mut tampered_value = manifest;
    tampered_value.statement_root = Hash::new(b"nonempty root with zero count");
    assert!(!verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &tampered_value,
        source,
        &siblings,
        root,
        5,
        5
    ));
}
fn opening_fixture() -> (FastpqOrdinarySourceStatementOpeningV1, Hash) {
    let leaves = leaves();
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        leaves[0].source,
        &entries(),
        &leaves,
        5,
        5,
    )
    .unwrap();
    let tree: MerkleTree<_> = leaves
        .iter()
        .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
        .collect();
    let writes = [crate::exec_witness::smt::KvPair::new(
        FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
        norito::encode_canonical(&manifest).unwrap(),
    )];
    let root = crate::exec_witness::smt::compute_post_state_root(&[], &writes);
    (
        FastpqOrdinarySourceStatementOpeningV1 {
            manifest,
            leaf: leaves[2],
            membership: tree.get_proof(2).unwrap(),
            manifest_siblings: vec![Hash::new([]); 256],
        },
        root,
    )
}

fn opening_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(1_024, 32 * 1_024, 64 * 1_024, 512 * 1_024, 32)
}

#[test]
fn bounded_opening_roundtrip_and_both_inclusions_require_expected_context() {
    let (opening, root) = opening_fixture();
    let bytes = norito::encode_canonical(&opening).unwrap();
    let decoded =
        decode_fastpq_ordinary_source_statement_opening_v1(&bytes, bytes.len(), opening_limits())
            .unwrap();
    assert_eq!(decoded, opening);
    assert!(verify_fastpq_ordinary_source_statement_opening_v1(
        &decoded,
        &opening.leaf,
        root,
        5,
        5
    ));
    let mut tampered_value = decoded.clone();
    tampered_value.leaf.entry_hash = Hash::new(b"another entry");
    assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
        &tampered_value,
        &tampered_value.leaf,
        root,
        5,
        5
    ));
    let mut tampered_value = decoded.clone();
    tampered_value.manifest.source.network_id = network(8);
    assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
        &tampered_value,
        &opening.leaf,
        root,
        5,
        5
    ));
    assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
        &decoded,
        &opening.leaf,
        Hash::new(b"another finalized root"),
        5,
        5
    ));
    assert!(
        decode_fastpq_ordinary_source_statement_opening_v1(
            &bytes,
            bytes.len() - 1,
            opening_limits()
        )
        .is_err()
    );
    assert!(matches!(
        decode_fastpq_ordinary_source_statement_opening_v1(&[0xff], 0, opening_limits()),
        Err(norito::Error::Message(message)) if message == "source opening exceeds wire-byte limit"
    ));
    let wrong_schema = norito::encode_canonical(&opening.manifest).unwrap();
    assert!(
        decode_fastpq_ordinary_source_statement_opening_v1(
            &wrong_schema,
            bytes.len(),
            opening_limits()
        )
        .is_err()
    );
}

#[test]
fn bounded_opening_keeps_enclosing_cumulative_allocation_limits() {
    let (opening, _) = opening_fixture();
    let bytes = norito::encode_canonical(&opening).unwrap();
    let run = || {
        decode_fastpq_ordinary_source_statement_opening_v1(&bytes, bytes.len(), opening_limits())
    };
    let (result, measured) = norito::core::with_decode_limits_measured(opening_limits(), run);
    result.unwrap();
    let charged = measured.total_allocated_bytes();
    assert!(charged > 0);
    let exact = norito::DecodeLimits::new(1_024, 32 * 1_024, 64 * 1_024, charged, 32);
    norito::core::with_decode_limits_scope(exact, || {
        run().unwrap();
        assert!(
            run().is_err(),
            "a second opening cannot reset the caller budget"
        );
    });
    let short = norito::DecodeLimits::new(1_024, 32 * 1_024, 64 * 1_024, charged - 1, 32);
    assert!(norito::core::with_decode_limits_scope(short, run).is_err());
    for count in [255, 257] {
        let mut tampered_value = opening.clone();
        tampered_value
            .manifest_siblings
            .resize(count, Hash::new([]));
        let bytes = norito::encode_canonical(&tampered_value).unwrap();
        assert!(
            decode_fastpq_ordinary_source_statement_opening_v1(
                &bytes,
                bytes.len(),
                opening_limits()
            )
            .is_err()
        );
    }
}

fn witness_fixture() -> (
    iroha_data_model::block::consensus::ExecWitness,
    Vec<FastpqOrdinarySourceStatementLeafV1>,
) {
    use iroha_data_model::block::consensus::{ExecKv, ExecWitness};
    let leaves = leaves();
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        leaves[0].source,
        &entries(),
        &leaves,
        5,
        5,
    )
    .unwrap();
    let witness = ExecWitness {
        reads: vec![ExecKv {
            key: b"irrelevant read".to_vec(),
            value: b"read value".to_vec(),
        }],
        writes: vec![
            ExecKv {
                key: b"ordinary write".to_vec(),
                value: b"first".to_vec(),
            },
            ExecKv {
                key: FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1.to_vec(),
                value: norito::encode_canonical(&manifest).unwrap(),
            },
            ExecKv {
                key: b"another ordinary write".to_vec(),
                value: b"other value".to_vec(),
            },
            ExecKv {
                key: b"ordinary write".to_vec(),
                value: b"last".to_vec(),
            },
        ],
        ..ExecWitness::default()
    };
    (witness, leaves)
}

fn source_build_limits() -> FastpqSourceOpeningBuildLimits {
    FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: 16,
        max_ordinary_write_bytes: 64 * 1024,
        max_executed_entries: 8,
        max_statements: 8,
        manifest_decode: opening_limits(),
    }
}

#[test]
fn source_opening_producer_matches_mixed_write_tree_and_every_ragged_leaf() {
    let (witness, leaves) = witness_fixture();
    let ordinary = witness
        .writes
        .iter()
        .map(|write| crate::exec_witness::smt::KvPair::new(write.key.clone(), write.value.clone()))
        .collect::<Vec<_>>();
    let expected = crate::exec_witness::smt::compute_post_state_root(&[], &ordinary);
    for index in 0..3 {
        let (opening, root) = fastpq_ordinary_source_statement_opening_v1(
            &witness,
            leaves[0].source,
            &entries(),
            &leaves,
            index,
            source_build_limits(),
        )
        .unwrap();
        assert_eq!(root, expected);
        assert_eq!(opening.manifest_siblings.len(), 256);
        assert!(
            opening
                .manifest_siblings
                .iter()
                .any(|sibling| *sibling != Hash::new([]))
        );
        assert!(verify_fastpq_ordinary_source_statement_opening_v1(
            &opening,
            &leaves[index as usize],
            root,
            5,
            5
        ));
        let frame = norito::encode_canonical(&opening).unwrap();
        assert_eq!(
            decode_fastpq_ordinary_source_statement_opening_v1(
                &frame,
                frame.len(),
                opening_limits()
            )
            .unwrap(),
            opening
        );
    }
}

#[test]
fn source_opening_producer_rejects_entire_malformed_or_duplicate_reserved_family() {
    let (original, leaves) = witness_fixture();
    for mutation in 0..5 {
        let mut witness = original.clone();
        match mutation {
            0 => {
                witness.writes.remove(1);
            }
            1 => witness.writes.push(witness.writes[1].clone()),
            2 => witness.writes[1].key.truncate(1),
            3 => witness.writes[1].key.push(0),
            4 => {
                let mut malformed = witness.writes[1].clone();
                malformed.key.truncate(1);
                witness.writes.push(malformed);
            }
            _ => unreachable!(),
        }
        assert!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                leaves[0].source,
                &entries(),
                &leaves,
                0,
                source_build_limits()
            )
            .is_err(),
            "reserved family mutation {mutation}"
        );
    }
}

#[test]
fn source_opening_producer_requires_exact_complete_archive_source_and_position() {
    let (witness, leaves) = witness_fixture();
    for mutation in 0..9 {
        let mut tampered_value = leaves.clone();
        match mutation {
            0 => tampered_value.swap(0, 1),
            1 => {
                tampered_value.remove(1);
                tampered_value[1].statement_index = 1;
            }
            2 => tampered_value[1].effects_digest[0] ^= 1,
            3 => {
                tampered_value[1].route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id: LaneId::new(2),
                    lane_incarnation: Hash::new(b"another incarnation"),
                })
            }
            4 => tampered_value[1].route = FastpqSourceRouteV1::Unrouted,
            5 => tampered_value[1].execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
            6 => tampered_value[1].slot += 1,
            7 => tampered_value[1].perm_root[0] ^= 1,
            8 => tampered_value[1].tx_set_hash[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                leaves[0].source,
                &entries(),
                &tampered_value,
                0,
                source_build_limits()
            )
            .is_err()
        );
    }
    for source in [
        FastpqSourceStatementContextV1 {
            network_id: network(9),
            ..leaves[0].source
        },
        FastpqSourceStatementContextV1 {
            height: 20,
            ..leaves[0].source
        },
    ] {
        assert!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                source,
                &entries(),
                &leaves,
                0,
                source_build_limits()
            )
            .is_err()
        );
    }
    assert!(
        fastpq_ordinary_source_statement_opening_v1(
            &witness,
            leaves[0].source,
            &entries(),
            &leaves,
            3,
            source_build_limits()
        )
        .is_err()
    );
}

#[test]
fn source_opening_producer_enforces_write_entry_byte_and_decode_budgets() {
    let (witness, leaves) = witness_fixture();
    let mut limits = source_build_limits();
    limits.max_ordinary_writes = witness.writes.len();
    limits.max_executed_entries = 5;
    limits.max_ordinary_write_bytes = witness
        .writes
        .iter()
        .map(|write| write.key.len() + write.value.len())
        .sum();
    assert!(
        fastpq_ordinary_source_statement_opening_v1(
            &witness,
            leaves[0].source,
            &entries(),
            &leaves,
            0,
            limits
        )
        .is_ok()
    );
    for mutation in 0..4 {
        let mut tampered_value = limits;
        match mutation {
            0 => tampered_value.max_ordinary_writes -= 1,
            1 => tampered_value.max_ordinary_write_bytes -= 1,
            2 => tampered_value.max_executed_entries -= 1,
            3 => tampered_value.manifest_decode = norito::DecodeLimits::new(1, 1, 1, 1, 1),
            _ => unreachable!(),
        }
        assert!(
            fastpq_ordinary_source_statement_opening_v1(
                &witness,
                leaves[0].source,
                &entries(),
                &leaves,
                0,
                tampered_value
            )
            .is_err(),
            "budget mutation {mutation}"
        );
    }
}

#[test]
fn source_opening_producer_rejects_wrong_schema_and_oversized_manifest_values() {
    let (witness, leaves) = witness_fixture();
    for value in [
        norito::encode_canonical(&leaves[0]).unwrap(),
        vec![0xff; FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1 + 1],
    ] {
        let mut tampered_value = witness.clone();
        tampered_value.writes[1].value = value;
        assert!(
            fastpq_ordinary_source_statement_opening_v1(
                &tampered_value,
                leaves[0].source,
                &entries(),
                &leaves,
                0,
                source_build_limits()
            )
            .is_err()
        );
    }
}

#[test]
fn ordinary_recorder_cannot_alias_the_protected_source_manifest_key() {
    use crate::exec_witness;
    use iroha_data_model::execution_witness::ExecutionWitnessKeyTagV1;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    let _guard = exec_witness::exec_witness_guard();
    exec_witness::start_block();
    let key: Name = "fastpq_source_statements".parse().unwrap();
    let value = Json::new("iroha:fastpq:ordinary-source-statements:v1");
    exec_witness::record_write_account_kv(&iroha_test_samples::ALICE_ID, &key, &value);
    exec_witness::record_read_account_kv(&iroha_test_samples::ALICE_ID, &key, Some(&value));
    let captured = exec_witness::drain_exec_witness();
    assert_eq!(captured.reads.len(), 1);
    assert_eq!(captured.writes.len(), 1);
    for entry in captured.reads.iter().chain(&captured.writes) {
        assert_eq!(
            entry.key[0],
            ExecutionWitnessKeyTagV1::AccountMetadata as u8
        );
        assert_ne!(
            entry.key[0],
            FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1[0]
        );
    }
}

#[test]
fn complete_effect_source_context_fields_and_coverage_are_bound_by_both_inclusions() {
    let (opening, root) = opening_fixture();
    for mutation in 0..3 {
        let mut tampered_value = opening.clone();
        match mutation {
            0 => tampered_value.leaf.slot += 1,
            1 => tampered_value.leaf.perm_root[0] ^= 1,
            2 => tampered_value.leaf.tx_set_hash[0] ^= 1,
            _ => unreachable!(),
        }
        // Even an offered matching expected leaf cannot replace the original Merkle member.
        assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
            &tampered_value,
            &tampered_value.leaf,
            root,
            5,
            5
        ));
        assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
            &opening,
            &tampered_value.leaf,
            root,
            5,
            5
        ));
    }
    let mut unsupported = opening;
    unsupported.manifest.coverage = FastpqSourceEffectCoverageV1::Unsupported;
    let bytes = norito::encode_canonical(&unsupported.manifest).unwrap();
    assert_eq!(
        norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&bytes).unwrap(),
        unsupported.manifest
    );
    let writes = [crate::exec_witness::smt::KvPair::new(
        FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
        bytes,
    )];
    let matching_root = crate::exec_witness::smt::compute_post_state_root(&[], &writes);
    assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
        &unsupported,
        &unsupported.leaf,
        matching_root,
        5,
        5
    ));
}

#[test]
fn complete_effect_count_remains_independent_of_statement_capacity() {
    let mut leaves = leaves();
    leaves[0].effect_count = 17;
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        leaves[0].source,
        &entries(),
        &leaves,
        5,
        3,
    )
    .unwrap();
    assert_eq!(manifest.statement_count, 3);
    assert!(leaves[0].effect_count > manifest.statement_count);
    assert_eq!(manifest.coverage, FastpqSourceEffectCoverageV1::Complete);
    leaves[0].effect_count = 0;
    assert!(
        build_fastpq_ordinary_source_statement_manifest_v1(
            leaves[0].source,
            &entries(),
            &leaves,
            5,
            3
        )
        .is_none()
    );
}
