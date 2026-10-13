//! Core-built complete archives roundtrip through the model using real ordinary keys.
//! Synthetic source leaves exercise codec/membership binding; no native execution or finality is claimed.

use super::prepare_fastpq_ordinary_source_archive_v1;
use crate::{
    exec_witness,
    fastpq::{
        FastpqSourceOpeningBuildLimits,
        fastpq_ordinary_source_statement_archive_v1 as build_archive,
        fastpq_ordinary_source_statement_opening_v1,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::{AssetDefinitionId, AssetId},
    block::consensus::{ExecKv, ExecWitness},
    execution_witness::{
        ExecutionWitnessKeyTagV1, FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
    },
    fastpq::{
        FASTPQ_ORDINARY_SOURCE_STATEMENT_ARCHIVE_VERSION_V1,
        FastpqOrdinarySourceStatementArchiveV1, FastpqOrdinarySourceStatementLeafV1,
        FastpqSourceArchiveDecodeLimits, FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1,
        FastpqSourceRouteV1, FastpqSourceStatementContextV1,
        build_fastpq_ordinary_source_statement_manifest_v1,
        decode_fastpq_ordinary_source_statement_archive_v1,
        verify_fastpq_ordinary_source_statement_archive_v1,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};

fn source() -> FastpqSourceStatementContextV1 {
    FastpqSourceStatementContextV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"core archive bridge network",
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

fn codec_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(1024, 1024 * 1024, 1024 * 1024, 4 * 1024 * 1024, 64)
}

fn build_limits() -> FastpqSourceOpeningBuildLimits {
    // Fixture-only limits, not a source policy or a production transport profile.
    FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: 16,
        max_ordinary_write_bytes: 64 * 1024,
        max_executed_entries: 5,
        max_statements: 3,
        manifest_decode: codec_limits(),
    }
}

fn decode_limits(bytes: usize, entries: u32, statements: u32) -> FastpqSourceArchiveDecodeLimits {
    FastpqSourceArchiveDecodeLimits {
        max_wire_bytes: bytes,
        max_executed_entries: entries,
        max_statements: statements,
        norito: codec_limits(),
    }
}

fn fixture(count: u32, entries: u32) -> (ExecWitness, Vec<FastpqOrdinarySourceStatementLeafV1>) {
    let leaves = (0..count)
        .map(|index| FastpqOrdinarySourceStatementLeafV1 {
            source: source(),
            statement_index: index,
            entry_index: index * 2,
            effect_count: if index < 2 { count.min(2) } else { 1 },
            entry_hash: source_entries(5)[(index * 2) as usize].entry_hash,
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Unrouted,
            dataspace_id: DataSpaceId::new(4),
            effects_digest: [u8::try_from(index).expect("fixture value fits u8") + 9; 32],
            slot: 19_000_000,
            perm_root: Hash::new(b"synthetic source permission root").into(),
            tx_set_hash: Hash::new(b"synthetic ordered source transactions").into(),
        })
        .collect::<Vec<_>>();
    let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
        source(),
        &source_entries(entries),
        &leaves,
        5,
        3,
    )
    .unwrap();
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let alice_asset = AssetId::of(definition.clone(), (*ALICE_ID).clone());
    let bob_asset = AssetId::of(definition.clone(), (*BOB_ID).clone());
    exec_witness::start_block();
    exec_witness::record_read_asset(&bob_asset, Some(&Quantity::from(3_u32)));
    exec_witness::record_write_asset(&alice_asset, &Quantity::from(9_u32));
    exec_witness::record_write_asset_def_total(&definition, &Quantity::from(12_u32));
    let mut witness = exec_witness::drain_exec_witness();
    assert_eq!(witness.reads.len(), 1);
    assert_eq!(witness.writes.len(), 2);
    assert!(witness.writes.iter().any(|write| write.key.first() == Some(&(ExecutionWitnessKeyTagV1::AssetBalance as u8))));
    assert!(witness.writes.iter().any(|write| write.key.first()
        == Some(&(ExecutionWitnessKeyTagV1::AssetDefinitionTotalSupply as u8))));
    // This fixture inserts D7 explicitly; the bridge never inserts it for a caller.
    witness.writes.push(ExecKv {
        key: FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1.to_vec(),
        value: norito::encode_canonical(&manifest).unwrap(),
    });
    (witness, leaves)
}

fn execution_ordinary_root(witness: &ExecWitness) -> Hash {
    // Use the same canonical witness projection as native execution commitments.
    let (reads, writes) = crate::exec_witness::roots::witness_pairs(witness);
    crate::exec_witness::smt::compute_post_state_root(&reads, &writes)
}

fn exact_build_limits(
    witness: &ExecWitness,
    entries: u32,
    statements: u32,
) -> FastpqSourceOpeningBuildLimits {
    FastpqSourceOpeningBuildLimits {
        max_ordinary_writes: witness.writes.len(),
        max_ordinary_write_bytes: witness
            .writes
            .iter()
            .map(|write| write.key.len() + write.value.len())
            .sum(),
        max_executed_entries: entries,
        max_statements: statements,
        ..build_limits()
    }
}

#[test]
fn public_bridge_moves_complete_leaves_and_roundtrips_the_real_ordinary_root() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [1, 2, 3] {
        let (archive, root) = {
            let (witness, leaves) = fixture(count, 5);
            let original_witness = witness.clone();
            let original_leaves = leaves.clone();
            let allocation = leaves.as_ptr();
            let capacity = leaves.capacity();
            let expected_root = execution_ordinary_root(&witness);
            let (archive, root) = build_archive(
                &witness,
                source(),
                &source_entries(5),
                leaves,
                exact_build_limits(&witness, 5, count),
            )
            .unwrap();
            assert_eq!(archive.leaves.as_ptr(), allocation);
            assert_eq!(archive.leaves.capacity(), capacity);
            assert_eq!(archive.leaves, original_leaves);
            assert_eq!(witness, original_witness);
            assert_eq!(root, expected_root);
            (archive, root)
        };
        assert_eq!(
            archive.version,
            FASTPQ_ORDINARY_SOURCE_STATEMENT_ARCHIVE_VERSION_V1
        );
        assert_eq!(archive.manifest.executed_entry_count, 5);
        assert_eq!(archive.manifest.statement_count, count);
        assert_eq!(archive.manifest_siblings.len(), 256);
        assert!(
            archive
                .manifest_siblings
                .iter()
                .any(|sibling| *sibling != Hash::new([]))
        );
        let bytes = norito::encode_canonical(&archive).unwrap();
        assert!(verify_fastpq_ordinary_source_statement_archive_v1(
            &archive,
            source(),
            &source_entries(5),
            root,
            5,
            count
        ));
        let decoded = decode_fastpq_ordinary_source_statement_archive_v1(
            &bytes,
            source(),
            &source_entries(5),
            root,
            decode_limits(bytes.len(), 5, count),
        )
        .unwrap();
        assert_eq!(decoded, archive, "transport outlives the borrowed witness");
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), bytes);
    }
}

#[test]
fn empty_transport_keeps_the_real_manifest_path_at_zero_statement_caps() {
    let _guard = exec_witness::exec_witness_guard();
    for entries in [0, 5] {
        let (witness, leaves) = fixture(0, entries);
        let expected_root = execution_ordinary_root(&witness);
        let (archive, root) = build_archive(
            &witness,
            source(),
            &source_entries(entries),
            leaves,
            exact_build_limits(&witness, entries, 0),
        )
        .unwrap();
        assert_eq!(root, expected_root);
        assert_eq!(archive.manifest.executed_entry_count, entries);
        assert_eq!(archive.manifest.statement_count, 0);
        assert!(archive.leaves.is_empty());
        assert!(
            archive
                .manifest_siblings
                .iter()
                .any(|sibling| *sibling != Hash::new([]))
        );
        let bytes = norito::encode_canonical(&archive).unwrap();
        let mut limits = decode_limits(bytes.len(), entries, 0);
        limits.norito = norito::DecodeLimits::new(0, 1024 * 1024, 1024 * 1024, 4 * 1024 * 1024, 64);
        assert_eq!(
            decode_fastpq_ordinary_source_statement_archive_v1(
                &bytes,
                source(),
                &source_entries(entries),
                root,
                limits
            )
            .unwrap(),
            archive
        );
        let mut no_d7 = witness.clone();
        no_d7
            .writes
            .retain(|write| write.key != FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1);
        assert_ne!(root, execution_ordinary_root(&no_d7));
        assert_eq!(
            build_archive(
                &no_d7,
                source(),
                &source_entries(entries),
                Vec::new(),
                build_limits()
            )
            .unwrap_err(),
            "FASTPQ source manifest write is absent"
        );
    }
}

#[test]
fn bridge_preserves_all_preparation_caps_and_does_not_modify_the_witness() {
    let _guard = exec_witness::exec_witness_guard();
    let (witness, leaves) = fixture(3, 5);
    let original = witness.clone();
    let exact = exact_build_limits(&witness, 5, 3);
    build_archive(
        &witness,
        source(),
        &source_entries(5),
        leaves.clone(),
        exact,
    )
    .unwrap();
    for cap in 0..5 {
        let mut short = exact;
        match cap {
            0 => short.max_ordinary_writes -= 1,
            1 => short.max_ordinary_write_bytes -= 1,
            2 => short.max_executed_entries -= 1,
            3 => short.max_statements -= 1,
            4 => short.manifest_decode = norito::DecodeLimits::new(0, 0, 0, 0, 0),
            _ => unreachable!(),
        }
        let expected = prepare_fastpq_ordinary_source_archive_v1(
            &witness,
            source(),
            &source_entries(5),
            &leaves,
            short,
        )
        .err()
        .unwrap();
        assert_eq!(
            build_archive(
                &witness,
                source(),
                &source_entries(5),
                leaves.clone(),
                short
            )
            .unwrap_err(),
            expected,
            "cap {cap}"
        );
        assert_eq!(witness, original);
    }
}

#[test]
fn bridge_preserves_reserved_key_canonical_manifest_and_completeness_rejections() {
    let _guard = exec_witness::exec_witness_guard();
    let (witness, leaves) = fixture(3, 5);
    for mutation in 0..12 {
        let mut changed_witness = witness.clone();
        let mut changed_leaves = leaves.clone();
        let mut expected_source = source();
        match mutation {
            0 => {
                changed_witness.writes.pop();
            }
            1 => changed_witness
                .writes
                .push(changed_witness.writes[2].clone()),
            2 => changed_witness.writes[2].key.push(0),
            3 => changed_witness.writes[2].value.push(0),
            4 => {
                changed_leaves.pop();
            }
            5 => changed_leaves.swap(0, 1),
            6 => changed_leaves[1].effect_count += 1,
            7 => changed_leaves[0].effects_digest[0] ^= 1,
            8 => expected_source.height += 1,
            9 => changed_leaves[0].slot += 1,
            10 => changed_leaves[0].perm_root[0] ^= 1,
            11 => changed_leaves[0].tx_set_hash[0] ^= 1,
            _ => unreachable!(),
        }
        let expected = prepare_fastpq_ordinary_source_archive_v1(
            &changed_witness,
            expected_source,
            &source_entries(5),
            &changed_leaves,
            build_limits(),
        )
        .err()
        .unwrap();
        let original = changed_witness.clone();
        assert_eq!(
            build_archive(
                &changed_witness,
                expected_source,
                &source_entries(5),
                changed_leaves,
                build_limits()
            )
            .unwrap_err(),
            expected,
            "mutation {mutation}"
        );
        assert_eq!(changed_witness, original);
    }
}

#[test]
fn bridge_and_one_existing_opening_share_the_same_ordinary_manifest_path() {
    let _guard = exec_witness::exec_witness_guard();
    let (mut witness, leaves) = fixture(3, 5);
    // The actual asset key keeps ordinary last-write-wins behavior at the bridge boundary.
    let mut last = witness.writes[0].clone();
    last.value = norito::json::to_vec(&Quantity::from(8_u32)).unwrap();
    witness.writes.push(last.clone());
    let (opening, opening_root) = fastpq_ordinary_source_statement_opening_v1(
        &witness,
        source(),
        &source_entries(5),
        &leaves,
        2,
        build_limits(),
    )
    .unwrap();
    let (archive, root) = build_archive(
        &witness,
        source(),
        &source_entries(5),
        leaves,
        build_limits(),
    )
    .unwrap();
    assert_eq!(archive.manifest, opening.manifest);
    assert_eq!(
        archive.manifest_siblings.as_slice(),
        opening.manifest_siblings.as_slice()
    );
    assert_eq!(archive.leaves[2], opening.leaf);
    assert_eq!(root, opening_root);
    assert_eq!(root, execution_ordinary_root(&witness));
    let mut collapsed = witness.clone();
    collapsed.writes.retain(|write| write.key != last.key);
    collapsed.writes.push(last);
    assert_eq!(root, execution_ordinary_root(&collapsed));
    let bytes = norito::encode_canonical(&archive).unwrap();
    assert_eq!(
        decode_fastpq_ordinary_source_statement_archive_v1(
            &bytes,
            source(),
            &source_entries(5),
            root,
            decode_limits(bytes.len(), 5, 3)
        )
        .unwrap(),
        archive
    );
}

#[test]
fn model_decoder_enforces_exact_transport_caps_for_core_built_payloads() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [0, 3] {
        let (witness, leaves) = fixture(count, 5);
        let (archive, root) = build_archive(
            &witness,
            source(),
            &source_entries(5),
            leaves,
            build_limits(),
        )
        .unwrap();
        let bytes = norito::encode_canonical(&archive).unwrap();
        let exact = decode_limits(bytes.len(), 5, count);
        assert_eq!(
            decode_fastpq_ordinary_source_statement_archive_v1(
                &bytes,
                source(),
                &source_entries(5),
                root,
                exact
            )
            .unwrap(),
            archive
        );
        for cap in 0..if count == 0 { 2 } else { 4 } {
            let mut short = exact;
            match cap {
                0 => short.max_wire_bytes -= 1,
                1 => short.max_executed_entries -= 1,
                2 => short.max_statements -= 1,
                3 => {
                    short.norito =
                        norito::DecodeLimits::new(2, 1024 * 1024, 1024 * 1024, 4 * 1024 * 1024, 64)
                }
                _ => unreachable!(),
            }
            assert!(
                decode_fastpq_ordinary_source_statement_archive_v1(
                    &bytes,
                    source(),
                    &source_entries(5),
                    root,
                    short
                )
                .is_err(),
                "count {count}, cap {cap}"
            );
        }
    }
}

#[test]
fn model_rejects_tampered_core_built_path_content_and_independent_expectations() {
    let _guard = exec_witness::exec_witness_guard();
    let (witness, leaves) = fixture(3, 5);
    let (archive, root) = build_archive(
        &witness,
        source(),
        &source_entries(5),
        leaves,
        build_limits(),
    )
    .unwrap();
    for mutation in 0..16 {
        let mut changed = archive.clone();
        let mut expected_source = source();
        let mut expected_root = root;
        let mut expected_entries = source_entries(5);
        match mutation {
            0 => changed.version += 1,
            1 => changed.manifest_siblings[128] = Hash::new(b"corrupt real ordinary path"),
            2 => {
                changed.leaves.pop();
            }
            3 => changed.leaves.swap(0, 1),
            4 => changed.leaves[0].effects_digest[0] ^= 1,
            5 => changed.manifest.statement_count -= 1,
            6 => changed.manifest.executed_entry_count += 1,
            7 => expected_source.height += 1,
            8 => {
                expected_source.network_id = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"wrong bridge network")),
                )
            }
            9 => expected_root = Hash::new(b"unauthenticated replacement root"),
            10 => expected_entries[1].entry_hash = Hash::new(b"wrong non-transfer source"),
            11 => {
                expected_entries.remove(1);
            }
            12 => changed.leaves[0].slot += 1,
            13 => changed.leaves[0].perm_root[0] ^= 1,
            14 => changed.leaves[0].tx_set_hash[0] ^= 1,
            15 => {
                changed.manifest.coverage =
                    iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Unsupported
            }
            _ => unreachable!(),
        }
        assert!(
            !verify_fastpq_ordinary_source_statement_archive_v1(
                &changed,
                expected_source,
                &expected_entries,
                expected_root,
                8,
                3
            ),
            "mutation {mutation}"
        );
        let bytes = norito::encode_canonical(&changed).unwrap();
        assert!(
            decode_fastpq_ordinary_source_statement_archive_v1(
                &bytes,
                expected_source,
                &expected_entries,
                expected_root,
                decode_limits(bytes.len(), 8, 3)
            )
            .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn bridge_and_model_decode_preserve_one_cumulative_outer_allocation_budget() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [0, 3] {
        let (witness, leaves) = fixture(count, 5);
        let expected_root = execution_ordinary_root(&witness);
        let run = || -> Result<FastpqOrdinarySourceStatementArchiveV1, String> {
            let (archive, root) = build_archive(
                &witness,
                source(),
                &source_entries(5),
                leaves.clone(),
                build_limits(),
            )?;
            assert_eq!(root, expected_root);
            let bytes = norito::encode_canonical(&archive).map_err(|error| error.to_string())?;
            decode_fastpq_ordinary_source_statement_archive_v1(
                &bytes,
                source(),
                &source_entries(5),
                expected_root,
                decode_limits(bytes.len(), 5, count),
            )
            .map_err(|error| error.to_string())
        };
        let (first, measured) = norito::core::with_decode_limits_measured(codec_limits(), run);
        let expected = first.unwrap();
        let charged = measured.total_allocated_bytes();
        assert!(charged > 0);
        let exact = norito::DecodeLimits::new(1024, 1024 * 1024, 1024 * 1024, charged, 64);
        norito::core::with_decode_limits_scope(exact, || {
            assert_eq!(run().unwrap(), expected);
            assert!(
                run().is_err(),
                "a repeated bridge/decode cannot reset its caller's charges"
            );
        });
        let short = norito::DecodeLimits::new(1024, 1024 * 1024, 1024 * 1024, charged - 1, 64);
        assert!(norito::core::with_decode_limits_scope(short, run).is_err());
        assert_eq!(run().unwrap(), expected);
    }
}

#[test]
fn core_bridge_and_model_roundtrip_preserve_every_supported_ambient_layout() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [0, 3] {
        let (witness, leaves) = fixture(count, 5);
        let (expected, root) = build_archive(
            &witness,
            source(),
            &source_entries(5),
            leaves.clone(),
            build_limits(),
        )
        .unwrap();
        let canonical = norito::encode_canonical(&expected).unwrap();
        for flags in
            (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            let (archive, actual_root) = build_archive(
                &witness,
                source(),
                &source_entries(5),
                leaves.clone(),
                build_limits(),
            )
            .unwrap();
            assert_eq!(actual_root, root);
            assert_eq!(archive, expected);
            assert_eq!(norito::encode_canonical(&archive).unwrap(), canonical);
            assert_eq!(
                decode_fastpq_ordinary_source_statement_archive_v1(
                    &canonical,
                    source(),
                    &source_entries(5),
                    root,
                    decode_limits(canonical.len(), 5, count)
                )
                .unwrap(),
                expected
            );
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
    }
}

#[test]
fn bridge_requires_independent_nontransfer_entries_for_empty_and_nonempty_archives() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [0, 3] {
        let (witness, leaves) = fixture(count, 5);
        let expected_entries = source_entries(5);
        let (archive, root) = build_archive(
            &witness,
            source(),
            &expected_entries,
            leaves.clone(),
            build_limits(),
        )
        .unwrap();
        let bytes = norito::encode_canonical(&archive).unwrap();
        let mut changed = expected_entries.clone();
        changed[2].entry_hash = Hash::new(b"unrelated non-transfer entry");
        assert!(build_archive(&witness, source(), &changed, leaves, build_limits(),).is_err());
        assert!(!verify_fastpq_ordinary_source_statement_archive_v1(
            &archive,
            source(),
            &changed,
            root,
            5,
            count,
        ));
        assert!(
            decode_fastpq_ordinary_source_statement_archive_v1(
                &bytes,
                source(),
                &changed,
                root,
                decode_limits(bytes.len(), 5, count),
            )
            .is_err()
        );
    }
}

#[test]
fn bridge_refuses_unsupported_coverage_without_claiming_source_finality() {
    let _guard = exec_witness::exec_witness_guard();
    for count in [0, 3] {
        let (mut witness, leaves) = fixture(count, 5);
        let (mut archive, _) = build_archive(
            &witness,
            source(),
            &source_entries(5),
            leaves.clone(),
            build_limits(),
        )
        .unwrap();
        archive.manifest.coverage =
            iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Unsupported;
        witness.writes[2].value = norito::encode_canonical(&archive.manifest).unwrap();
        let root = execution_ordinary_root(&witness);
        let frame = norito::encode_canonical(&archive).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementArchiveV1>(&frame).unwrap(),
            archive
        );
        assert!(!verify_fastpq_ordinary_source_statement_archive_v1(
            &archive,
            source(),
            &source_entries(5),
            root,
            5,
            count
        ));
        assert!(
            decode_fastpq_ordinary_source_statement_archive_v1(
                &frame,
                source(),
                &source_entries(5),
                root,
                decode_limits(frame.len(), 5, count)
            )
            .is_err()
        );
        let original = witness.clone();
        assert!(
            build_archive(
                &witness,
                source(),
                &source_entries(5),
                leaves,
                build_limits()
            )
            .is_err()
        );
        assert_eq!(witness, original);
    }
}
