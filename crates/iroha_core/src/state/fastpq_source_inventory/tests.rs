//! Owned inventory completeness, canonical ordering and runtime context regressions.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::BlockHeader,
    fastpq::{
        FastpqSourceExecutionKindV1, FastpqSourceRouteV1, TransferDeltaTranscript,
        TransferSmtWitness, TransferTranscript,
    },
    isi::Log,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_logger::Level;
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID, gen_account_in};
use nonzero_ext::nonzero;

pub(super) fn state() -> State {
    State::new(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

/// Acquire State first, then bind the real original recorder before any block effects.
/// These component fixtures have no signed carrier; their transcript/output mutations
/// remain test inputs and do not manufacture a publishable execution source owner.
pub(super) fn recorded_block(
    state: &State,
    header: BlockHeader,
) -> (Box<StateBlock<'_>>, crate::exec_witness::ExecWitnessGuard) {
    let (block, recording) = state
        .block_with_owned_start_stages(
            header,
            |block| {
                let recording = crate::exec_witness::begin_exec_witness_capture()?;
                block.bind_original_execution_recorder()?;
                Ok::<_, String>(recording)
            },
            |_, recording| Ok(recording),
        )
        .expect("record the pristine component scope before block effects");
    block.require_original_execution_recorder().unwrap();
    (block, recording)
}

/// Supply the explicit canonical wire commitment owned by this test's block fixture.
pub(super) fn cache_canonical_test_transaction_set(
    block: &mut StateBlock<'_>,
    external: &[TransactionEntrypoint],
) -> [u8; 32] {
    let hash: [u8; 32] =
        iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(external.iter())
            .expect("canonical fixture transaction wires")
            .into();
    assert_ne!(hash, [0; 32]);
    block.set_fastpq_tx_set_hash(hash);
    hash
}

pub(super) fn header() -> BlockHeader {
    BlockHeader::new(nonzero!(1_u64), None, None, 7, 0)
}

fn external(state: &State, label: &str) -> TransactionEntrypoint {
    let (authority, keypair) = gen_account_in("wonderland");
    TransactionEntrypoint::External(
        TransactionBuilder::new(
            state.network_id,
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, label.to_owned())])
        .sign(keypair.private_key()),
    )
}

pub(super) fn delta() -> TransferDeltaTranscript {
    TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        amount: Quantity::from(1_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(9_u32),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(1_u32),
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    }
}

pub(super) fn apply_source(
    block: &mut StateBlock<'_>,
    hash: Hash,
    native: bool,
    route: Option<RoutingDecision>,
) {
    let mut tx = if native {
        block.transaction_for_fastpq_protocol_testing()
    } else {
        block.transaction_for_fastpq_testing(hash)
    };
    tx.current_lane_id = route.map(|route| route.lane_id);
    tx.current_dataspace_id = route.map(|route| route.dataspace_id);
    tx.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
    tx.apply();
}

fn limits() -> FastpqSourceStatementBuildLimits {
    FastpqSourceStatementBuildLimits {
        max_executed_entries: 16,
        max_transcripts: 16,
        max_deltas: 16,
        max_input_transcript_bytes: 1_000_000,
        max_statement_bytes: 1_000_000,
        max_total_statement_bytes: 4_000_000,
    }
}

fn apply_ordered_source(block: &mut StateBlock<'_>, hash: Hash) {
    let mut tx = block.transaction_for_fastpq_testing(hash);
    for before in [10_u32, 9] {
        let mut occurrence = delta();
        occurrence.from_balance_before = Quantity::from(before);
        occurrence.from_balance_after = Quantity::from(before - 1);
        occurrence.to_balance_before = Quantity::from(10 - before);
        occurrence.to_balance_after = Quantity::from(11 - before);
        tx.record_test_transfer_transcripts(&ALICE_ID, hash, vec![occurrence]);
    }
    tx.apply();
}

fn canonical_transcript_bytes(transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>) -> usize {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    transcripts
        .values()
        .flatten()
        .map(|transcript| norito::core::encoded_frame_len(transcript).unwrap())
        .sum()
}

#[test]
fn inventory_covers_nontransfer_calls_and_every_applied_source() {
    let state = state();
    let external = [
        external(&state, "transfer"),
        external(&state, "no transfer"),
    ];
    let routes = [RoutingDecision::default(); 2];
    let calls = external
        .iter()
        .map(|entry| Hash::from(entry.execution_call_hash()))
        .collect::<Vec<_>>();
    let time_calls = [
        Hash::new(b"successful invocation"),
        Hash::new(b"failed invocation"),
    ];
    let extras = [Hash::new(b"native purpose"), Hash::new(b"internal call")];
    let (mut block, _recording) = recorded_block(&state, header());
    cache_canonical_test_transaction_set(&mut block, &external);
    assert!(block.fastpq_source_inventory().unwrap().is_none());
    for hash in [calls[1], time_calls[1]] {
        block.admit_fastpq_source_for_testing(hash);
    }
    apply_source(&mut block, extras[0], true, None);
    apply_source(&mut block, calls[0], false, Some(routes[0]));
    apply_source(&mut block, time_calls[0], false, None);
    apply_source(
        &mut block,
        extras[1],
        false,
        Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::new(9))),
    );
    block
        .finalize_fastpq_source_inventory(&external, &routes, &time_calls)
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let mut sorted_extras = extras;
    sorted_extras.sort_unstable();
    let expected = calls
        .iter()
        .chain(&time_calls)
        .chain(&sorted_extras)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        inventory
            .entries()
            .iter()
            .map(|entry| entry.entry_hash)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(inventory.source().network_id, state.network_id);
    assert_eq!(inventory.source().height, 1);
    assert_eq!(inventory.transcript_entry_hashes().len(), 4);
    let native = inventory
        .entries()
        .iter()
        .find(|entry| entry.entry_hash == extras[0])
        .unwrap();
    assert_eq!(
        native.execution_kind,
        FastpqSourceExecutionKindV1::ProtocolPurpose
    );
    assert_eq!(native.route, FastpqSourceRouteV1::Unrouted);
    assert_eq!(block.fastpq_entry_dataspaces.len(), 6);
    assert_eq!(
        block.fastpq_entry_dataspaces[&extras[1]],
        DataSpaceId::new(9)
    );
    let canonical_wire_hash: [u8; 32] =
        iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(external.iter())
            .unwrap()
            .into();
    assert_eq!(inventory.tx_set_hash(), canonical_wire_hash);
    assert_eq!(block.fastpq_tx_set_hash, Some(inventory.tx_set_hash()));
    let transcripts = block.drain_transfer_transcripts();
    let (manifest, leaves) = inventory
        .prepare_transfer_diagnostic(7, [3; 32], &transcripts, limits())
        .unwrap();
    assert_eq!(manifest.executed_entry_count, 6);
    assert_eq!(manifest.statement_count, 4);
    assert_eq!(
        leaves
            .iter()
            .map(|leaf| leaf.entry_index)
            .collect::<Vec<_>>(),
        vec![0, 2, 4, 5]
    );
    assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
    assert_eq!(block.fastpq_tx_set_hash, Some(inventory.tx_set_hash()));
    assert_eq!(block.fastpq_entry_dataspaces.len(), 6);
    // The supplied-array component source has no mandatory completed-effect journal.
    // Genuine capture/context retention is exercised by native_capture_fixture and
    // witness_custody; this local diagnostic grants neither D7 nor publication.
    assert!(block.capture_exec_witness().is_err());
    assert!(block.take_exec_witness().is_none());
    assert!(block.take_fastpq_witness_context().is_none());
}

#[test]
fn owned_inventory_prevents_joint_entry_and_bundle_omission() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"native source");
    apply_source(&mut block, hash, true, None);
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let mut transcripts = block.drain_transfer_transcripts();
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &transcripts, limits())
            .is_ok()
    );
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &BTreeMap::new(), limits())
            .unwrap_err()
            .contains("owned inventory")
    );
    let mut extra = transcripts.clone();
    extra.insert(Hash::new(b"extra"), transcripts[&hash].clone());
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &extra, limits())
            .is_err()
    );
    // Missing finalized digests cannot be repaired by the source producer.
    transcripts.get_mut(&hash).unwrap()[0].poseidon_preimage_digest = None;
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &transcripts, limits())
            .is_err()
    );
    let mut too_small = limits();
    too_small.max_executed_entries = 0;
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &transcripts, too_small)
            .is_err()
    );
}

#[test]
fn empty_inventory_is_explicit_and_cannot_be_resealed() {
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    assert!(inventory.entries().is_empty());
    assert!(inventory.transcript_entry_hashes().is_empty());
    let (manifest, leaves) = inventory
        .prepare_transfer_diagnostic(7, [0; 32], &BTreeMap::new(), limits())
        .unwrap();
    assert_eq!(manifest.executed_entry_count, 0);
    assert_eq!(manifest.statement_count, 0);
    assert!(leaves.is_empty());
    assert!(
        block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .is_err()
    );
    assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
}

#[test]
fn missing_extra_empty_and_misidentified_transcripts_latch_failure() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    for mutation in 0..5 {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        let hash = Hash::new(b"applied source");
        apply_source(&mut block, hash, true, None);
        match mutation {
            0 => {
                block.fastpq_transcripts.clear();
            }
            1 => {
                block.fastpq_source_captures =
                    crate::fastpq::FastpqSourceCaptureAccumulator::default();
            }
            2 => {
                block.fastpq_transcripts.get_mut(&hash).unwrap().clear();
            }
            3 => {
                block.fastpq_transcripts.get_mut(&hash).unwrap()[0].batch_hash =
                    Hash::new(b"wrong key");
            }
            _ => {
                block.fastpq_transcripts.get_mut(&hash).unwrap()[0]
                    .deltas
                    .clear();
            }
        }
        let error = block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .unwrap_err();
        assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
        block.fastpq_transcripts.clear();
        block.fastpq_source_captures = crate::fastpq::FastpqSourceCaptureAccumulator::default();
        assert!(
            block
                .finalize_fastpq_source_inventory(&[], &[], &[])
                .is_err()
        );
        assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
        assert_eq!(
            block.fastpq_tx_set_hash,
            Some(
                iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
                    &TransactionEntrypoint,
                >(),)
                .unwrap()
                .into()
            )
        );
        assert!(block.fastpq_entry_dataspaces.is_empty());
    }
}

#[test]
fn duplicate_external_time_and_cross_class_identities_are_rejected() {
    let state = state();
    let entry = external(&state, "duplicate");
    let hash = Hash::from(entry.execution_call_hash());
    for (entries, routes, calls) in [
        (
            vec![entry.clone(), entry.clone()],
            vec![RoutingDecision::default(); 2],
            vec![],
        ),
        (vec![], vec![], vec![hash, hash]),
        (vec![entry], vec![RoutingDecision::default()], vec![hash]),
    ] {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, &entries);
        assert!(
            block
                .finalize_fastpq_source_inventory(&entries, &routes, &calls)
                .unwrap_err()
                .contains("duplicate")
        );
    }
}

#[test]
fn invalid_routes_and_capture_origin_conflicts_are_rejected() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let entry = external(&state, "route");
    let hash = Hash::from(entry.execution_call_hash());
    for mutation in 0..8 {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, std::slice::from_ref(&entry));
        let actual = match mutation {
            0 => None,
            1 => Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::new(5))),
            _ => Some(RoutingDecision::default()),
        };
        apply_source(&mut block, hash, mutation == 2, actual);
        if mutation == 3 {
            Arc::make_mut(block.fastpq_source_context.as_mut().unwrap())
                .source
                .height += 1;
        }
        if mutation == 6 {
            apply_source(&mut block, hash, false, None);
        }
        if mutation == 7 {
            block.fastpq_source_context = None;
        }
        let routes = if mutation == 4 {
            vec![]
        } else if mutation == 5 {
            vec![RoutingDecision::new(
                LaneId::new(999),
                DataSpaceId::UNIVERSAL,
            )]
        } else {
            vec![RoutingDecision::default()]
        };
        assert!(
            block
                .finalize_fastpq_source_inventory(std::slice::from_ref(&entry), &routes, &[])
                .is_err(),
            "mutation {mutation}"
        );
        assert!(block.fastpq_source_inventory().is_err());
    }
}

#[test]
fn additional_source_order_does_not_depend_on_fragment_order() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let hashes = [Hash::new(b"source one"), Hash::new(b"source two")];
    let mut inventories = Vec::new();
    for order in [hashes, [hashes[1], hashes[0]]] {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        for hash in order {
            apply_source(&mut block, hash, true, None);
        }
        block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .unwrap();
        inventories.push(block.fastpq_source_inventory().unwrap().unwrap().clone());
    }
    assert_eq!(inventories[0], inventories[1]);
}

#[test]
fn invalid_source_capture_poison_survives_transaction_rollback() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"rolled back");
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_lane_id = Some(LaneId::new(999));
        tx.record_transfer_transcript(&ALICE_ID, delta())
            .expect_err("an unknown lane cannot prepare a source occurrence");
    }
    let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
    assert_eq!(ordinary.executed_entries, 1);
    assert_eq!(ordinary.transcripts, 0);
    assert_eq!(
        mandatory,
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .finalize_fastpq_source_inventory(&[], &[], &[hash])
            .is_err()
    );
    assert!(block.fastpq_source_inventory().is_err());
}

#[test]
fn owned_public_seal_rejects_valid_archive_replacement_and_regrouping() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"ordered sealed operations");
    apply_ordered_source(&mut block, hash);
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let original = block.drain_transfer_transcripts();
    let expected = inventory
        .prepare_transfer_diagnostic(7, [3; 32], &original, limits())
        .unwrap();
    assert_eq!(expected.0.statement_count, 1);
    assert_eq!(expected.1[0].entry_transcript_count, 2);
    assert_eq!(inventory.transcript_seal.transcript_count, 2);
    assert_eq!(inventory.transcript_seal.delta_count, 2);

    for mutation in 0..7 {
        let mut changed = original.clone();
        let bundle = changed.get_mut(&hash).unwrap();
        match mutation {
            0 => {
                bundle.pop();
            }
            1 => bundle.push(bundle[0].clone()),
            2 => bundle.swap(0, 1),
            3 => bundle[0].authority_digest = Hash::new(b"replacement authority"),
            4 => {
                let transcript = &mut bundle[0];
                let occurrence = &mut transcript.deltas[0];
                occurrence.amount = Quantity::from(2_u32);
                occurrence.from_balance_after = Quantity::from(8_u32);
                occurrence.to_balance_after = Quantity::from(2_u32);
                transcript.poseidon_preimage_digest = Some(
                    crate::fastpq::poseidon_preimage_digest(occurrence, &transcript.batch_hash),
                );
            }
            5 => {
                let second = bundle.pop().unwrap();
                bundle[0].deltas.extend(second.deltas);
                bundle[0].poseidon_preimage_digest = None;
            }
            _ => {
                bundle.remove(0);
            }
        }
        let unchanged_input = changed.clone();
        // The whole-entry relation rejects broken chronology. Even alterations that
        // remain valid complete bundles must fail against the unchanged execution seal.
        let supplied = prepare_transfer_archive_diagnostic(
            inventory.source(),
            inventory.entries(),
            7,
            [3; 32],
            inventory.tx_set_hash(),
            &changed,
            limits(),
        );
        if matches!(mutation, 1 | 2 | 4) {
            assert!(
                supplied
                    .unwrap_err()
                    .contains("public repeated-key balances do not chain"),
                "mutation {mutation}"
            );
        } else {
            let supplied = supplied.unwrap_or_else(|error| {
                panic!("mutation {mutation} remains a valid complete bundle: {error}")
            });
            assert_ne!(
                supplied.1[0].statement_digest,
                expected.1[0].statement_digest
            );
        }
        assert!(
            inventory
                .prepare_transfer_diagnostic(7, [3; 32], &changed, limits())
                .unwrap_err()
                .contains("owned inventory seal"),
            "mutation {mutation}"
        );
        assert_eq!(changed, unchanged_input);
        assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
    }
    assert_eq!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &original, limits())
            .unwrap(),
        expected
    );
}

#[test]
fn owned_public_seal_excludes_private_paths_but_preserves_input_caps() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"private paths are not source facts");
    apply_ordered_source(&mut block, hash);
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let original = block.drain_transfer_transcripts();
    let expected = inventory
        .prepare_transfer_diagnostic(7, [3; 32], &original, limits())
        .unwrap();
    let mut changed = original.clone();
    for transcript in changed.values_mut().flatten() {
        for occurrence in &mut transcript.deltas {
            occurrence.from_smt_witness =
                TransferSmtWitness::new([11; 32], [12; 32], vec![0xAA; 64], vec![[13; 32]; 70]);
            occurrence.to_smt_witness =
                TransferSmtWitness::new([21; 32], [22; 32], vec![0x55; 65], vec![[23; 32]; 71]);
        }
    }
    let unchanged_input = changed.clone();
    let exact = FastpqSourceStatementBuildLimits {
        max_input_transcript_bytes: canonical_transcript_bytes(&changed),
        ..limits()
    };
    assert!(exact.max_input_transcript_bytes > canonical_transcript_bytes(&original));
    assert_eq!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &changed, exact)
            .unwrap(),
        expected
    );
    let too_small = FastpqSourceStatementBuildLimits {
        max_input_transcript_bytes: exact.max_input_transcript_bytes - 1,
        ..exact
    };
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &changed, too_small)
            .unwrap_err()
            .contains("canonical input transcript")
    );
    assert_eq!(changed, unchanged_input);
}

#[test]
fn owned_public_seal_preflights_resources_before_rejecting_substitution() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    let hash = Hash::new(b"preflight before public seal");
    apply_ordered_source(&mut block, hash);
    block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap();
    let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
    let original = block.drain_transfer_transcripts();
    let exact = FastpqSourceStatementBuildLimits {
        max_executed_entries: 1,
        max_transcripts: 2,
        max_deltas: 2,
        max_input_transcript_bytes: canonical_transcript_bytes(&original),
        ..limits()
    };
    inventory
        .prepare_transfer_diagnostic(7, [3; 32], &original, exact)
        .unwrap();
    let mut changed = original.clone();
    changed.get_mut(&hash).unwrap()[0].authority_digest = Hash::new(b"substituted authority");
    for (small, expected_error) in [
        (
            FastpqSourceStatementBuildLimits {
                max_transcripts: 1,
                ..exact
            },
            "transcript occurrence limit",
        ),
        (
            FastpqSourceStatementBuildLimits {
                max_deltas: 1,
                ..exact
            },
            "transfer-delta limit",
        ),
        (
            FastpqSourceStatementBuildLimits {
                max_input_transcript_bytes: exact.max_input_transcript_bytes - 1,
                ..exact
            },
            "canonical input transcript",
        ),
    ] {
        assert!(
            inventory
                .prepare_transfer_diagnostic(7, [3; 32], &changed, small)
                .unwrap_err()
                .contains(expected_error)
        );
    }
    assert!(
        inventory
            .prepare_transfer_diagnostic(7, [3; 32], &changed, exact)
            .unwrap_err()
            .contains("owned inventory seal")
    );
}

#[test]
fn pending_entrypoint_and_synchronous_sealing_commit_finalized_digests() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let hash = Hash::new(b"finalized before public seal");
    let mut results = Vec::new();
    for pending_entrypoint in [false, true] {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        // Record both complete occurrences before publication so quota reconciliation
        // sees the real three-delta source, rather than a forged later enlargement.
        let mut transaction = block.transaction_for_fastpq_testing(hash);
        transaction.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
        let later = [9_u32, 8].map(|before| {
            let mut transfer = delta();
            transfer.from_balance_before = Quantity::from(before);
            transfer.from_balance_after = Quantity::from(before - 1);
            transfer.to_balance_before = Quantity::from(10 - before);
            transfer.to_balance_after = Quantity::from(11 - before);
            transfer
        });
        transaction.record_test_transfer_transcripts(&ALICE_ID, hash, later.into());
        transaction.apply();
        let bundle = block.fastpq_transcripts.get_mut(&hash).unwrap();
        let expected_digest = bundle[0].poseidon_preimage_digest.unwrap();
        bundle[0].poseidon_preimage_digest = None;
        assert!(bundle[1].poseidon_preimage_digest.is_none());
        if pending_entrypoint {
            // This small fixture exercises the optional pending-batch interface's
            // deterministic fallback; it does not qualify a GPU pending batch.
            let pending = block.submit_transfer_transcript_digest_batch();
            block
                .finalize_fastpq_source_inventory_with_pending(&[], &[], &[], pending)
                .unwrap();
        } else {
            block
                .finalize_fastpq_source_inventory(&[], &[], &[])
                .unwrap();
        }
        let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
        assert_eq!(
            block.fastpq_transcripts[&hash][0].poseidon_preimage_digest,
            Some(expected_digest)
        );
        assert!(
            block.fastpq_transcripts[&hash][1]
                .poseidon_preimage_digest
                .is_none()
        );
        let transcripts = block.drain_transfer_transcripts_with_pending(None);
        let manifest = inventory
            .prepare_transfer_diagnostic(7, [3; 32], &transcripts, limits())
            .unwrap();
        assert_eq!(inventory.transcript_seal.transcript_count, 2);
        assert_eq!(inventory.transcript_seal.delta_count, 3);
        results.push((inventory, transcripts, manifest));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn resealing_preserves_latched_result_before_any_digest_mutation() {
    let _guard = crate::exec_witness::exec_witness_guard();
    let state = state();
    let hash = Hash::new(b"one shot public seal");
    for initial_failure in [false, true] {
        let mut block = state.block(header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        apply_ordered_source(&mut block, hash);
        let mut restored = block.fastpq_transcripts.clone();
        if initial_failure {
            block.fastpq_transcripts.get_mut(&hash).unwrap()[0]
                .deltas
                .clear();
        }
        assert_eq!(
            block
                .finalize_fastpq_source_inventory(&[], &[], &[])
                .is_err(),
            initial_failure
        );
        let sealed_result = block.fastpq_source_inventory.clone();
        restored.get_mut(&hash).unwrap()[0].poseidon_preimage_digest = None;
        block.fastpq_transcripts = restored.clone();
        assert!(
            block
                .finalize_fastpq_source_inventory_with_pending(&[], &[], &[], None)
                .unwrap_err()
                .contains("already been finalized")
        );
        assert_eq!(block.fastpq_transcripts, restored);
        assert_eq!(block.fastpq_source_inventory, sealed_result);
    }
}

#[test]
fn nontransfer_time_sources_change_entry_digest_without_replacing_wire_commitment() {
    let state = state();
    let mut results = Vec::new();
    for time_calls in [vec![], vec![Hash::new(b"nontransfer time invocation")]] {
        let mut block = state.block(header());
        let wire_hash = cache_canonical_test_transaction_set(&mut block, &[]);
        for hash in &time_calls {
            block.admit_fastpq_source_for_testing(*hash);
        }
        block
            .finalize_fastpq_source_inventory(&[], &[], &time_calls)
            .unwrap();
        let inventory = block.fastpq_source_inventory().unwrap().unwrap();
        let (manifest, leaves) = inventory
            .prepare_transfer_diagnostic(7, [0; 32], &BTreeMap::new(), limits())
            .unwrap();
        assert!(leaves.is_empty());
        assert_eq!(inventory.tx_set_hash(), wire_hash);
        assert_eq!(block.fastpq_tx_set_hash, Some(wire_hash));
        results.push((manifest, wire_hash));
    }
    assert_eq!(results[0].1, results[1].1);
    assert_eq!(
        results[0].0.diagnostic_digest,
        results[1].0.diagnostic_digest
    );
    assert_eq!(results[0].0.statement_count, 0);
    assert_eq!(results[1].0.statement_count, 0);
    assert_eq!(results[0].0.executed_entry_count, 0);
    assert_eq!(results[1].0.executed_entry_count, 1);
    assert_ne!(
        results[0].0.source_entries_digest,
        results[1].0.source_entries_digest
    );
}
