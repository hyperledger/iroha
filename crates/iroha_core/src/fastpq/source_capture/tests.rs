//! Complete source-archive derivation, immutable input and exact budget regressions.

use super::*;
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    asset::AssetDefinitionId,
    fastpq::{FastpqSourceLaneV1, TransferDeltaTranscript, TransferSmtWitness},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};

// The synthetic source entries are internally derived calls; this fixture has no
// external transaction wires. Source identities are committed separately.
pub(super) fn transaction_wire_hash() -> [u8; 32] {
    iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
        &iroha_data_model::transaction::TransactionEntrypoint,
    >())
    .unwrap()
    .into()
}

fn fixture() -> (
    FastpqSourceStatementContextV1,
    Vec<FastpqSourceExecutionEntryV1>,
    BTreeMap<Hash, Vec<TransferTranscript>>,
) {
    let source = FastpqSourceStatementContextV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"genesis",
        ))),
        height: 19,
    };
    let entries = (0..3)
        .map(|i| FastpqSourceExecutionEntryV1 {
            entry_hash: Hash::new([i]),
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::new(2),
                lane_incarnation: Hash::new(b"full lane incarnation"),
            }),
            dataspace_id: DataSpaceId::new(4),
        })
        .collect::<Vec<_>>();
    let transcript = |entry_hash, occurrence: u32| {
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            amount: Quantity::from(10u32),
            from_balance_before: Quantity::from(100 - occurrence * 10),
            from_balance_after: Quantity::from(90 - occurrence * 10),
            to_balance_before: Quantity::from(occurrence * 10),
            to_balance_after: Quantity::from((occurrence + 1) * 10),
            from_smt_witness: TransferSmtWitness::default(),
            to_smt_witness: TransferSmtWitness::default(),
        };
        TransferTranscript {
            batch_hash: entry_hash,
            poseidon_preimage_digest: Some(crate::fastpq::poseidon_preimage_digest(
                &delta,
                &entry_hash,
            )),
            deltas: vec![delta],
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        }
    };
    let transcripts = BTreeMap::from([
        (
            entries[1].entry_hash,
            vec![
                transcript(entries[1].entry_hash, 0),
                transcript(entries[1].entry_hash, 1),
            ],
        ),
        (
            entries[2].entry_hash,
            vec![transcript(entries[2].entry_hash, 2)],
        ),
    ]);
    (source, entries, transcripts)
}

fn limits() -> FastpqSourceStatementBuildLimits {
    FastpqSourceStatementBuildLimits {
        max_executed_entries: 3,
        max_transcripts: 3,
        max_deltas: 3,
        max_input_transcript_bytes: 1_000_000,
        max_statement_bytes: 1_000_000,
        max_total_statement_bytes: 2_000_000,
    }
}

#[test]
fn archive_preflight_enforces_exact_input_caps_before_public_construction() {
    let (_, entries, transcripts) = fixture();
    let original = norito::encode_canonical(&transcripts).unwrap();
    let exact = FastpqSourceStatementBuildLimits {
        max_input_transcript_bytes: transcripts
            .values()
            .flatten()
            .map(|transcript| norito::encode_canonical(transcript).unwrap().len())
            .sum(),
        // These output bounds are deliberately zero: preflight does no statement/tree work.
        max_statement_bytes: 0,
        max_total_statement_bytes: 0,
        ..limits()
    };
    assert_eq!(
        preflight_fastpq_source_transcripts(&transcripts, exact).unwrap(),
        3
    );
    for changed in [
        FastpqSourceStatementBuildLimits {
            max_transcripts: 2,
            ..exact
        },
        FastpqSourceStatementBuildLimits {
            max_deltas: 2,
            ..exact
        },
        FastpqSourceStatementBuildLimits {
            max_input_transcript_bytes: exact.max_input_transcript_bytes - 1,
            ..exact
        },
    ] {
        assert!(preflight_fastpq_source_transcripts(&transcripts, changed).is_err());
        assert_eq!(norito::encode_canonical(&transcripts).unwrap(), original);
    }
    if let Ok(over_limit) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert!(
            preflight_fastpq_source_transcripts(
                &transcripts,
                FastpqSourceStatementBuildLimits {
                    max_transcripts: over_limit,
                    ..exact
                },
            )
            .is_err()
        );
    }
    for mutation in 0..3 {
        let mut changed = transcripts.clone();
        let bundle = changed.get_mut(&entries[1].entry_hash).unwrap();
        match mutation {
            0 => bundle.clear(),
            1 => bundle[0].deltas.clear(),
            2 => bundle[0].batch_hash = Hash::new(b"wrong source"),
            _ => unreachable!(),
        }
        assert!(preflight_fastpq_source_transcripts(&changed, exact).is_err());
    }
    assert_eq!(
        preflight_fastpq_source_transcripts(&BTreeMap::new(), exact).unwrap(),
        0
    );
}

#[test]
fn derived_preparation_and_tree_limit_overflows_reject_without_changing_input() {
    let (source, entries, transcripts) = fixture();
    let before = norito::encode_canonical(&transcripts).unwrap();
    for changed in [
        FastpqSourceStatementBuildLimits {
            max_deltas: usize::MAX,
            ..limits()
        },
        FastpqSourceStatementBuildLimits {
            max_statement_bytes: usize::MAX,
            ..limits()
        },
        FastpqSourceStatementBuildLimits {
            max_deltas: usize::MAX / 3,
            ..limits()
        },
        FastpqSourceStatementBuildLimits {
            max_deltas: usize::MAX / 16,
            ..limits()
        },
    ] {
        assert!(
            prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                changed
            )
            .is_err()
        );
        assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    }
}

fn statement_bytes(
    entries: &[FastpqSourceExecutionEntryV1],
    entry_index: usize,
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> Vec<u8> {
    let entry = entries[entry_index];
    let inputs = FastpqPublicInputsTemplate {
        dsid: dataspace_id_bytes(entry.dataspace_id),
        slot: 123,
        perm_root: [9; 32],
        old_root: [0; 32],
        new_root: [0; 32],
    }
    .with_tx_set_hash(transaction_wire_hash());
    let produced = quantity_statement_from_finalized_transcripts_for_testing(
        inputs,
        &transcripts[&entry.entry_hash],
        PublicTransferLimits::default(),
        TransferSmtBuildLimits::for_update_limit(6).unwrap(),
    )
    .unwrap();
    let statement = produced.statement();
    assert_eq!(statement.public_inputs.slot, 123);
    assert_eq!(statement.public_inputs.perm_root, [9; 32]);
    assert_eq!(
        statement.public_inputs.dsid,
        dataspace_id_bytes(entry.dataspace_id)
    );
    norito::encode_canonical(statement).unwrap()
}

#[test]
fn prepares_complete_ordered_diagnostics_and_exact_canonical_statement_digests() {
    let (source, mut entries, transcripts) = fixture();
    // Execution order intentionally differs from transcript-map key order.
    entries[1..].sort_by(|left, right| right.entry_hash.cmp(&left.entry_hash));
    let before = norito::encode_canonical(&transcripts).unwrap();
    let (manifest, leaves) = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap();
    assert_eq!(manifest.executed_entry_count, 3);
    assert_eq!(manifest.statement_count, 2);
    let expected = entries
        .iter()
        .enumerate()
        .filter_map(|(entry_index, entry)| {
            transcripts
                .get(&entry.entry_hash)
                .map(|bundle| (entry_index, bundle.len()))
        })
        .collect::<Vec<_>>();
    for (statement_index, leaf) in leaves.iter().enumerate() {
        assert_eq!(
            leaf.statement_index,
            u32::try_from(statement_index).expect("fixture value fits u32")
        );
        let (entry_index, transcript_count) = expected[statement_index];
        assert_eq!(
            leaf.entry_index,
            u32::try_from(entry_index).expect("fixture value fits u32")
        );
        assert_eq!(leaves.len(), expected.len());
        assert_eq!(
            leaf.entry_transcript_count,
            u32::try_from(transcript_count).expect("fixture value fits u32")
        );
        assert_eq!(leaf.entry_hash, entries[entry_index].entry_hash);
        assert_eq!(leaf.route, entries[entry_index].route);
        assert_eq!(leaf.execution_kind, entries[entry_index].execution_kind);
        assert_eq!(
            leaf.statement_digest,
            <[u8; 32]>::from(Hash::new(statement_bytes(
                &entries,
                entry_index,
                &transcripts
            )))
        );
    }
    assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    // D7 inclusion is exercised with the genuine complete-effect journal in
    // witness_custody::genuine_complete_effect_openings_keep_whole_entries.
    // This diagnostic summary deliberately has no Norito encoding or D7 projection.
}

#[test]
fn supplied_native_and_call_routes_bind_transfer_diagnostics() {
    let (source, original_entries, transcripts) = fixture();
    let incarnation = Hash::new(b"full lane incarnation");
    let context = crate::fastpq::FastpqBlockStartSourceContext {
        source,
        lane_incarnations: BTreeMap::from([(LaneId::new(2), Some(incarnation))]),
    };
    let mut roots = BTreeSet::new();
    for native in [false, true] {
        for lane_id in [None, Some(LaneId::new(2))] {
            let mut entries = original_entries.clone();
            for (index, entry) in entries.iter_mut().enumerate().skip(1) {
                let captured = context
                    .capture_transcript(
                        (!native).then_some(entry.entry_hash),
                        entry.entry_hash,
                        lane_id,
                        Some(entry.dataspace_id),
                        index,
                    )
                    .unwrap();
                assert_eq!(captured.source(), source);
                assert_eq!(captured.is_protocol_purpose(), native);
                *entry = FastpqSourceExecutionEntryV1 {
                    entry_hash: captured.entry_hash(),
                    execution_kind: captured.execution_kind(),
                    route: captured.route(),
                    dataspace_id: captured.dataspace_id(),
                };
            }
            let (manifest, leaves) = prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                limits(),
            )
            .unwrap();
            assert!(roots.insert(manifest.diagnostic_digest));
            for leaf in &leaves {
                assert_eq!(
                    leaf.execution_kind,
                    entries[leaf.entry_index as usize].execution_kind
                );
                assert_eq!(leaf.route, entries[leaf.entry_index as usize].route);
                assert_eq!(
                    leaf.statement_digest,
                    <[u8; 32]>::from(Hash::new(statement_bytes(
                        &original_entries,
                        leaf.entry_index as usize,
                        &transcripts
                    )))
                );
                // Actual route/context membership uses the native call/protocol
                // controls; supplied diagnostics cannot create that authority.
            }
        }
    }
}

#[test]
fn empty_diagnostics_include_nontransfer_entries_without_statement_budget() {
    let (source, entries, _) = fixture();
    let bounds = FastpqSourceStatementBuildLimits {
        max_transcripts: 0,
        max_deltas: 0,
        max_input_transcript_bytes: 0,
        max_statement_bytes: 0,
        max_total_statement_bytes: 0,
        ..limits()
    };
    for count in [0, 3] {
        let (manifest, leaves) = prepare_transfer_archive_diagnostic(
            source,
            &entries[..count],
            123,
            [9; 32],
            transaction_wire_hash(),
            &BTreeMap::new(),
            bounds,
        )
        .unwrap();
        assert_eq!(
            manifest.executed_entry_count,
            u32::try_from(count).expect("fixture value fits u32")
        );
        assert_eq!(manifest.statement_count, 0);
        assert!(leaves.is_empty());
        assert_eq!(
            manifest.diagnostic_digest,
            transfer_diagnostic::empty_diagnostic_digest()
        );
    }
}

#[test]
fn one_entry_prepares_its_whole_bundle_with_independent_statement_limit() {
    let (source, entries, mut transcripts) = fixture();
    let entry = entries[1];
    let entries = [entry];
    transcripts.retain(|hash, _| *hash == entry.entry_hash);
    let (manifest, leaves) = prepare_transfer_archive_diagnostic(
        source,
        &[entry],
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(
        (manifest.executed_entry_count, manifest.statement_count),
        (1, 1)
    );
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].entry_transcript_count, 2);
    for changed in [
        FastpqSourceStatementBuildLimits {
            max_executed_entries: 0,
            ..limits()
        },
        FastpqSourceStatementBuildLimits {
            max_transcripts: 0,
            ..limits()
        },
    ] {
        assert!(
            prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                changed,
            )
            .is_err()
        );
    }
    // Exact one-entry D7 membership and zero leaf caps are covered by the
    // genuine original-source opening control, never by this unanchored summary.
}

#[test]
fn atomic_multi_delta_occurrences_remain_whole_and_reject_internal_discontinuity() {
    let (source, entries, mut transcripts) = fixture();
    let bundle = transcripts.get_mut(&entries[1].entry_hash).unwrap();
    let second = bundle.pop().unwrap();
    bundle[0].deltas.extend(second.deltas);
    bundle[0].poseidon_preimage_digest = None;
    assert_eq!(bundle[0].deltas.len(), 2);
    let before = norito::encode_canonical(&transcripts).unwrap();
    let (manifest, leaves) = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap();
    assert_eq!(manifest.statement_count, 2);
    assert_eq!(leaves[0].entry_transcript_count, 1);
    assert_eq!(
        leaves[0].statement_digest,
        <[u8; 32]>::from(Hash::new(statement_bytes(&entries, 1, &transcripts)))
    );
    assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    let delta = &mut transcripts.get_mut(&entries[1].entry_hash).unwrap()[0].deltas[1];
    delta.from_balance_before = Quantity::from(95_u32);
    delta.from_balance_after = Quantity::from(85_u32);
    let invalid = norito::encode_canonical(&transcripts).unwrap();
    let error = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap_err();
    assert!(
        error.contains("public repeated-key balances do not chain"),
        "{error}"
    );
    assert_eq!(norito::encode_canonical(&transcripts).unwrap(), invalid);
}

#[test]
fn rejects_omissions_duplicate_execution_calls_and_inconsistent_bundles() {
    let (source, entries, transcripts) = fixture();
    for mutation in 0..7 {
        let mut entries = entries.clone();
        let mut transcripts = transcripts.clone();
        let mut source = source;
        match mutation {
            0 => {
                entries.remove(1);
            }
            1 => {
                entries[0] = entries[1];
            }
            2 => {
                let bundle = transcripts.remove(&entries[1].entry_hash).unwrap();
                transcripts.insert(Hash::new(b"unexecuted"), bundle);
            }
            3 => transcripts.get_mut(&entries[1].entry_hash).unwrap().clear(),
            4 => {
                transcripts.get_mut(&entries[1].entry_hash).unwrap()[0].batch_hash =
                    entries[2].entry_hash
            }
            5 => transcripts.get_mut(&entries[1].entry_hash).unwrap()[0]
                .deltas
                .clear(),
            6 => source.height = 0,
            _ => unreachable!(),
        }
        let before = norito::encode_canonical(&transcripts).unwrap();
        assert!(
            prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                limits()
            )
            .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    }
}

#[test]
fn accepts_exact_cumulative_limits_and_rejects_each_one_below() {
    let (source, entries, transcripts) = fixture();
    let frames = [
        statement_bytes(&entries, 1, &transcripts),
        statement_bytes(&entries, 2, &transcripts),
    ];
    let exact = FastpqSourceStatementBuildLimits {
        max_input_transcript_bytes: transcripts
            .values()
            .flatten()
            .map(|transcript| norito::encode_canonical(transcript).unwrap().len())
            .sum(),
        max_statement_bytes: frames.iter().map(Vec::len).max().unwrap(),
        max_total_statement_bytes: frames.iter().map(Vec::len).sum(),
        ..limits()
    };
    prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        exact,
    )
    .unwrap();
    for boundary in 0..6 {
        let mut changed = exact;
        match boundary {
            0 => changed.max_executed_entries -= 1,
            1 => changed.max_transcripts -= 1,
            2 => changed.max_deltas -= 1,
            3 => changed.max_input_transcript_bytes -= 1,
            4 => changed.max_statement_bytes -= 1,
            5 => changed.max_total_statement_bytes -= 1,
            _ => unreachable!(),
        }
        assert!(
            prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                changed
            )
            .is_err(),
            "boundary {boundary}"
        );
    }
}

#[test]
fn binds_full_source_route_order_slot_permission_and_nontransfer_identity() {
    let (source, entries, transcripts) = fixture();
    let original = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap()
    .0;
    let FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
        lane_id,
        lane_incarnation,
    }) = entries[1].route
    else {
        unreachable!()
    };
    for mutation in 0..12 {
        let mut source = source;
        let mut entries = entries.clone();
        let mut slot = 123;
        let mut perm_root = [9; 32];
        let mut tx_set_hash = transaction_wire_hash();
        match mutation {
            0 => {
                source.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"other genesis"),
                ))
            }
            1 => source.height += 1,
            2 => {
                entries[1].route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id: LaneId::new(3),
                    lane_incarnation,
                })
            }
            3 => {
                let mut bytes: [u8; 32] = lane_incarnation.into();
                bytes[20] ^= 1;
                entries[1].route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id,
                    lane_incarnation: Hash::prehashed(bytes),
                });
            }
            4 => entries[1].dataspace_id = DataSpaceId::new(5),
            5 => entries.swap(1, 2),
            6 => slot += 1,
            7 => perm_root[0] ^= 1,
            8 => entries[0].entry_hash = Hash::new(b"different nontransfer execution"),
            9 => entries[1].route = FastpqSourceRouteV1::Unrouted,
            10 => entries[1].execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
            11 => tx_set_hash[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = prepare_transfer_archive_diagnostic(
            source,
            &entries,
            slot,
            perm_root,
            tx_set_hash,
            &transcripts,
            limits(),
        )
        .unwrap()
        .0;
        assert_ne!(changed, original, "mutation {mutation}");
        if mutation == 8 {
            // A non-transfer source is bound by the complete inventory digest,
            // independently of the unchanged transaction wires and statement tree.
            assert_eq!(changed.diagnostic_digest, original.diagnostic_digest);
            assert_ne!(
                changed.source_entries_digest,
                original.source_entries_digest
            );
        } else {
            assert_ne!(
                changed.diagnostic_digest, original.diagnostic_digest,
                "mutation {mutation}"
            );
        }
        if mutation == 11 {
            assert_eq!(
                changed.source_entries_digest,
                original.source_entries_digest
            );
        }
    }
}

#[test]
fn rejects_public_repair_and_missing_finalized_digest_without_mutating_archive() {
    let (source, entries, transcripts) = fixture();
    for mutation in 0..2 {
        let mut transcripts = transcripts.clone();
        let bundle = transcripts.get_mut(&entries[1].entry_hash).unwrap();
        match mutation {
            0 => bundle[1].deltas[0].from_balance_before = Quantity::from(100u32),
            1 => bundle[0].poseidon_preimage_digest = None,
            _ => unreachable!(),
        }
        let before = norito::encode_canonical(&transcripts).unwrap();
        let error = prepare_transfer_archive_diagnostic(
            source,
            &entries,
            123,
            [9; 32],
            transaction_wire_hash(),
            &transcripts,
            limits(),
        )
        .unwrap_err();
        assert!(error.contains("not finalized"), "{error}");
        assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    }
}

#[test]
fn canonical_source_derivation_restores_ambient_codec_flags() {
    let (source, entries, transcripts) = fixture();
    let original = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap();
    for flags in
        (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            prepare_transfer_archive_diagnostic(
                source,
                &entries,
                123,
                [9; 32],
                transaction_wire_hash(),
                &transcripts,
                limits()
            )
            .unwrap(),
            original
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
}

#[test]
fn counted_preflight_matches_buffered_canonical_frames_for_transcript_encodings() {
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};

    let (_, _, original) = fixture();
    let template = original.values().next().unwrap()[0].clone();
    for variant in 0..7 {
        let mut transcript = template.clone();
        match variant {
            0 => {}
            1 => transcript.poseidon_preimage_digest = None,
            2 => {
                transcript.deltas.push(transcript.deltas[0].clone());
                transcript.poseidon_preimage_digest = None;
            }
            3 => {
                // Preflight measures supplied private data even when its path shape would not
                // be reused by the public statement producer.
                transcript.deltas[0].from_smt_witness =
                    TransferSmtWitness::new([3; 32], [5; 32], vec![0xA5; 33], vec![[7; 32]; 65]);
                transcript.deltas[0].to_smt_witness =
                    TransferSmtWitness::new([11; 32], [13; 32], vec![0x5A; 32], vec![[17; 32]; 64]);
            }
            4 => {
                transcript.deltas[0].amount = "340282366920938463463374607431768211456.125"
                    .parse()
                    .unwrap();
                transcript.deltas[0].from_balance_before = "0.000000000000000001".parse().unwrap();
            }
            5 => {
                let policy = MultisigPolicy::new(
                    2,
                    vec![
                        MultisigMember::new(
                            ALICE_ID.controller().expect_single_signatory().clone(),
                            1,
                        )
                        .unwrap(),
                        MultisigMember::new(
                            BOB_ID.controller().expect_single_signatory().clone(),
                            1,
                        )
                        .unwrap(),
                    ],
                )
                .unwrap();
                transcript.deltas[0].from_account = AccountId::new_multisig(policy);
            }
            6 => {
                use iroha_primitives::{bigint::BigInt, numeric::Numeric};

                let mut maximum_bytes = [0xff; 64];
                maximum_bytes[63] = 0x7f;
                let maximum = BigInt::from_twos_bytes(&maximum_bytes).unwrap();
                transcript.deltas[0].amount =
                    Quantity::from_canonical_numeric(Numeric::try_new(maximum.clone(), 0).unwrap())
                        .unwrap();
                transcript.deltas[0].from_balance_before =
                    Quantity::from_canonical_numeric(Numeric::try_new(maximum, 28).unwrap())
                        .unwrap();
                transcript.deltas[0].to_balance_after =
                    Quantity::from_canonical_numeric(Numeric::try_new(1_u32, 28).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        let expected = norito::encode_canonical(&transcript).unwrap();
        let delta_count = transcript.deltas.len();
        let archive = BTreeMap::from([(transcript.batch_hash, vec![transcript.clone()])]);
        let exact = FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            max_transcripts: 1,
            max_deltas: delta_count,
            max_input_transcript_bytes: expected.len(),
            max_statement_bytes: 0,
            max_total_statement_bytes: 0,
        };
        let expected_error = {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let error =
                norito::core::to_bytes_bounded(&transcript, expected.len() - 1).unwrap_err();
            format!("FASTPQ canonical input transcript exceeds construction budget: {error}")
        };
        for flags in
            (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                preflight_fastpq_source_transcripts(&archive, exact),
                Ok(1),
                "variant {variant}, flags {flags}",
            );
            assert_eq!(
                preflight_fastpq_source_transcripts(
                    &archive,
                    FastpqSourceStatementBuildLimits {
                        max_input_transcript_bytes: exact.max_input_transcript_bytes - 1,
                        ..exact
                    },
                ),
                Err(expected_error.clone()),
                "variant {variant}, flags {flags}",
            );
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
        assert_eq!(
            norito::encode_canonical(&archive.values().next().unwrap()[0]).unwrap(),
            expected
        );
    }
}

#[test]
fn counted_preflight_preserves_the_first_cumulative_byte_failure() {
    let (_, _, archive) = fixture();
    let frames: Vec<_> = archive.values().flatten().collect();
    let lengths: Vec<_> = frames
        .iter()
        .map(|transcript| norito::encode_canonical(*transcript).unwrap().len())
        .collect();
    let mut accepted_prefix_bytes = 0;
    for (index, transcript) in frames.iter().enumerate() {
        let remaining = lengths[index] - 1;
        let expected_error = {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let error = norito::core::to_bytes_bounded(*transcript, remaining).unwrap_err();
            format!("FASTPQ canonical input transcript exceeds construction budget: {error}")
        };
        assert_eq!(
            preflight_fastpq_source_transcripts(
                &archive,
                FastpqSourceStatementBuildLimits {
                    max_input_transcript_bytes: accepted_prefix_bytes + remaining,
                    ..limits()
                },
            ),
            Err(expected_error),
            "first rejected occurrence {index}",
        );
        accepted_prefix_bytes += lengths[index];
    }
    assert_eq!(
        preflight_fastpq_source_transcripts(
            &archive,
            FastpqSourceStatementBuildLimits {
                max_input_transcript_bytes: accepted_prefix_bytes,
                ..limits()
            },
        ),
        Ok(frames.len()),
    );
    assert_eq!(
        preflight_fastpq_source_transcripts(
            &archive,
            FastpqSourceStatementBuildLimits {
                max_input_transcript_bytes: usize::MAX,
                ..limits()
            },
        ),
        Ok(frames.len()),
    );
}

#[test]
fn counted_preflight_preserves_shape_count_and_byte_error_order() {
    let (_, _, original) = fixture();
    let first_key = *original.keys().next().unwrap();
    let last_key = *original.keys().next_back().unwrap();
    let zero_bytes = FastpqSourceStatementBuildLimits {
        max_input_transcript_bytes: 0,
        ..limits()
    };
    let first_byte_error = preflight_fastpq_source_transcripts(&original, zero_bytes).unwrap_err();
    assert!(first_byte_error.contains("encoded frame requires"));

    let mut later_empty = original.clone();
    later_empty.get_mut(&last_key).unwrap().clear();
    assert_eq!(
        preflight_fastpq_source_transcripts(&later_empty, zero_bytes),
        Err(first_byte_error),
        "an earlier occurrence's byte failure precedes a later bundle's shape failure",
    );
    let mut first_empty = original.clone();
    first_empty.get_mut(&first_key).unwrap().clear();
    assert_eq!(
        preflight_fastpq_source_transcripts(&first_empty, zero_bytes),
        Err("FASTPQ transcript bundle is empty".to_owned()),
    );
    let mut wrong_identity = original.clone();
    wrong_identity.get_mut(&first_key).unwrap()[0].batch_hash = Hash::new(b"unmatched identity");
    assert_eq!(
        preflight_fastpq_source_transcripts(&wrong_identity, zero_bytes),
        Err("FASTPQ transcript call identity differs from its bundle or has no deltas".to_owned()),
    );
    assert_eq!(
        preflight_fastpq_source_transcripts(
            &wrong_identity,
            FastpqSourceStatementBuildLimits {
                max_transcripts: 0,
                ..zero_bytes
            },
        ),
        Err("FASTPQ transcript occurrence limit exceeded".to_owned()),
        "the enclosing bundle occurrence cap precedes its first inner identity",
    );
    assert_eq!(
        preflight_fastpq_source_transcripts(
            &original,
            FastpqSourceStatementBuildLimits {
                max_deltas: 0,
                ..zero_bytes
            },
        ),
        Err("FASTPQ transfer-delta limit exceeded".to_owned()),
    );
    if let Ok(unrepresentable_cap) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert_eq!(
            preflight_fastpq_source_transcripts(
                &BTreeMap::new(),
                FastpqSourceStatementBuildLimits {
                    max_transcripts: unrepresentable_cap,
                    ..zero_bytes
                },
            ),
            Err("FASTPQ source transcript limit exceeds u32".to_owned()),
            "portable occurrence-cap validation still precedes even an empty archive",
        );
    }
}

#[test]
fn missing_canonical_wire_commitment_rejects_before_private_construction() {
    use crate::fastpq::quantity_statement::quantity_materializer_invocations_for_testing;

    let (source, entries, transcripts) = fixture();
    let before = norito::encode_canonical(&transcripts).unwrap();
    let calls = quantity_materializer_invocations_for_testing();
    let error = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        [0; 32],
        &transcripts,
        limits(),
    )
    .unwrap_err();
    assert!(
        error.contains("ordered transaction-wire commitment"),
        "{error}"
    );
    assert_eq!(quantity_materializer_invocations_for_testing(), calls);
    assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
}

#[test]
fn empty_statement_archive_commits_complete_nontransfer_inventory() {
    let (source, entries, _) = fixture();
    let limits = FastpqSourceStatementBuildLimits {
        max_transcripts: 0,
        max_deltas: 0,
        max_input_transcript_bytes: 0,
        max_statement_bytes: 0,
        max_total_statement_bytes: 0,
        ..limits()
    };
    let derive = |entries: &[FastpqSourceExecutionEntryV1]| {
        prepare_transfer_archive_diagnostic(
            source,
            entries,
            123,
            [9; 32],
            transaction_wire_hash(),
            &BTreeMap::new(),
            limits,
        )
        .unwrap()
    };
    let (original, leaves) = derive(&entries);
    assert!(leaves.is_empty());
    for mutation in 0..6 {
        let mut changed = entries.clone();
        match mutation {
            0 => changed.swap(0, 1),
            1 => changed[0].entry_hash = Hash::new(b"changed nontransfer source"),
            2 => changed[0].execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
            3 => changed[0].route = FastpqSourceRouteV1::Unrouted,
            4 => changed[0].dataspace_id = DataSpaceId::new(5),
            _ => {
                changed.pop();
            }
        }
        let (manifest, leaves) = derive(&changed);
        assert!(leaves.is_empty());
        assert_eq!(manifest.diagnostic_digest, original.diagnostic_digest);
        assert_ne!(
            manifest.source_entries_digest, original.source_entries_digest,
            "mutation {mutation}"
        );
    }
}

#[test]
fn whole_entry_binds_cross_transcript_scales_and_independent_assets() {
    let (source, entries, mut transcripts) = fixture();
    let entry = entries[1];
    transcripts.retain(|hash, _| *hash == entry.entry_hash);
    let bundle = transcripts.get_mut(&entry.entry_hash).unwrap();
    let second = &mut bundle[1];
    second.deltas[0].amount = "0.25".parse().unwrap();
    second.deltas[0].from_balance_before = Quantity::from(90_u32);
    second.deltas[0].from_balance_after = "89.75".parse().unwrap();
    second.deltas[0].to_balance_before = Quantity::from(10_u32);
    second.deltas[0].to_balance_after = "10.25".parse().unwrap();
    second.poseidon_preimage_digest = Some(crate::fastpq::poseidon_preimage_digest(
        &second.deltas[0],
        &entry.entry_hash,
    ));
    let mut independent = bundle[0].clone();
    independent.deltas[0].asset_definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "tulip".parse().unwrap(),
    );
    independent.poseidon_preimage_digest = Some(crate::fastpq::poseidon_preimage_digest(
        &independent.deltas[0],
        &entry.entry_hash,
    ));
    bundle.push(independent);
    let expected_transcripts = bundle
        .iter()
        .map(iroha_data_model::fastpq::FastpqPublicTransferTranscriptV1::from)
        .collect::<Vec<_>>();
    let before = norito::encode_canonical(&transcripts).unwrap();
    let (manifest, leaves) = prepare_transfer_archive_diagnostic(
        source,
        &[entry],
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap();
    assert_eq!(
        (manifest.executed_entry_count, manifest.statement_count),
        (1, 1)
    );
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].entry_transcript_count, 3);
    let bytes = statement_bytes(&[entry], 0, &transcripts);
    let statement = norito::decode_canonical::<
        iroha_data_model::fastpq::FastpqPublicTransferStatementV1,
    >(&bytes)
    .unwrap();
    assert_eq!(statement.transcripts, expected_transcripts);
    assert_eq!(statement.transitions.len(), 6);
    assert_eq!(
        leaves[0].statement_digest,
        <[u8; 32]>::from(Hash::new(&bytes))
    );
    assert_eq!(norito::encode_canonical(&transcripts).unwrap(), before);
    let mut changed = transcripts.clone();
    changed.get_mut(&entry.entry_hash).unwrap().swap(1, 2);
    let reordered = prepare_transfer_archive_diagnostic(
        source,
        &[entry],
        123,
        [9; 32],
        transaction_wire_hash(),
        &changed,
        limits(),
    )
    .unwrap();
    // Independent-asset reordering is arithmetically valid but retains a distinct full statement.
    assert_ne!(reordered.1[0].statement_digest, leaves[0].statement_digest);
    assert_ne!(reordered.0.diagnostic_digest, manifest.diagnostic_digest);
}

#[test]
fn valid_whole_entry_occurrence_tampering_changes_committed_statement() {
    let (source, entries, transcripts) = fixture();
    let baseline = prepare_transfer_archive_diagnostic(
        source,
        &entries,
        123,
        [9; 32],
        transaction_wire_hash(),
        &transcripts,
        limits(),
    )
    .unwrap();
    for mutation in 0..4 {
        let mut changed = transcripts.clone();
        let bundle = changed.get_mut(&entries[1].entry_hash).unwrap();
        match mutation {
            0 => bundle[1].authority_digest = Hash::new(b"different authority fact"),
            1 => {
                bundle.pop();
            }
            2 => {
                bundle.remove(0);
            }
            _ => {
                let second = bundle.pop().unwrap();
                bundle[0].deltas.extend(second.deltas);
                bundle[0].poseidon_preimage_digest = None;
            }
        }
        let actual = prepare_transfer_archive_diagnostic(
            source,
            &entries,
            123,
            [9; 32],
            transaction_wire_hash(),
            &changed,
            limits(),
        )
        .unwrap();
        assert_ne!(
            actual.1[0].statement_digest, baseline.1[0].statement_digest,
            "mutation {mutation}"
        );
        assert_ne!(
            actual.0.diagnostic_digest, baseline.0.diagnostic_digest,
            "mutation {mutation}"
        );
        assert_eq!(
            actual.0.source_entries_digest,
            baseline.0.source_entries_digest
        );
    }
}
