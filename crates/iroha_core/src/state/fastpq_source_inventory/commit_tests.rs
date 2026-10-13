//! Finalized source ownership remains mandatory through state publication.

use super::{
    tests::{
        apply_source, cache_canonical_test_transaction_set, delta, header, recorded_block, state,
    },
    *,
};
use crate::state::{State, TransactionsBlockError};
use iroha_crypto::HashOf;
use iroha_data_model::fastpq::TransferTranscript;
use iroha_model_base::state_path::StatePath;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;

fn marker() -> StatePath {
    "fastpq/commit-seal-marker".parse().unwrap()
}

fn state_with_marker() -> State {
    let state = state();
    {
        let mut storage = state.world.smart_contract_state.block();
        storage.insert(marker(), vec![0]);
        storage.commit();
    }
    state
}

fn apply_marker(block: &mut StateBlock<'_>, value: u8, source: Option<Hash>) {
    // This direct component fixture must retain its bounded invocation before
    // borrowing the transaction; assigning tx_call_hash alone grants no owner.
    let mut tx = match source {
        Some(hash) => block.transaction_for_fastpq_testing(hash),
        None => block.transaction(),
    };
    tx.world.smart_contract_state.insert(marker(), vec![value]);
    if let Some(hash) = source {
        tx.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
    }
    tx.apply();
}

fn stage_membership(block: &mut StateBlock<'_>, source: Option<Hash>) {
    block
        .stage_canonical_carrier_membership(
            source
                .map(HashOf::<TransactionEntrypoint>::from_untyped_unchecked)
                .into_iter()
                .collect(),
            nonzero!(1_usize),
        )
        .unwrap();
    let block_hash = block._curr_block.hash();
    block.block_hashes.push(block_hash);
}

fn assert_unpublished(state: &State) {
    assert_eq!(
        state.world.smart_contract_state.view().get(&marker()),
        Some(&vec![0]),
        "rejected commit must preserve the previously stored value"
    );
    assert_eq!(state.committed_height(), 0);
    assert_eq!(state.transactions.latest_height(), 0);
    assert!(state.latest_block_hash_fast().is_none());
}

// The first-release source owner cannot be published through a component-only
// commit. These controls use actual signed account-metadata instructions and
// native quorum publication; the former raw marker checks remain below for the
// explicit component-refusal/setup tests.
fn publication_marker() -> iroha_model_base::name::Name {
    "fastpq_commit_seal_marker".parse().unwrap()
}

#[test]
fn intact_finalized_inventory_commits_after_all_cached_outputs_are_taken() {
    use crate::sumeragi::test_chain::Signers;
    use iroha_data_model::{isi::SetKeyValue, prelude::*};
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_KEYPAIR, BOB_ID};
    for with_transfer in [false, true] {
        let (mut chain, asset) = super::native_capture_fixture::native_publication_chain();
        let state = Arc::clone(chain.state());
        let created = chain.committed(1).block_time_ms();
        let mut body = vec![InstructionBox::from(SetKeyValue::account(
            ALICE_ID.clone(),
            publication_marker(),
            Json::new(1_u32),
        ))];
        if with_transfer {
            body.push(Transfer::asset_quantity(asset, 1_u32, BOB_ID.clone()).into());
        }
        let tx = chain.sign(&ALICE_KEYPAIR, body, created);
        let proposal = chain.proposal(None, vec![tx]);
        let expected_hash = proposal.hash();
        let mut pending = chain
            .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
            .unwrap();
        pending
            .inspect(move |original| {
                assert!(
                    original
                        .state
                        .take_parliament_timed_ovn_casting_bindings()
                        .is_some()
                );
                assert_eq!(
                    original.state.take_fastpq_witness_context().is_some(),
                    with_transfer
                );
                assert!(original.state.exec_witness.is_none());
                assert!(original.state.fastpq_witness_context.is_none());
                assert!(
                    original
                        .state
                        .parliament_timed_ovn_casting_bindings
                        .is_none()
                );
                assert_eq!(
                    !original.witness.fastpq_transcripts.is_empty(),
                    with_transfer
                );
                original
                    .state
                    .verify_sumeragi_execution_witness(
                        original.block.as_ref(),
                        original.witness.wire(),
                    )
                    .unwrap();
                assert_eq!(
                    original
                        .state
                        .world
                        .accounts
                        .get(&ALICE_ID)
                        .unwrap()
                        .metadata
                        .get(&publication_marker()),
                    Some(&Json::new(1_u32))
                );
            })
            .unwrap();
        pending.prepare(Signers::Quorum).unwrap();
        pending.publish(Signers::Quorum).unwrap();
        let retained = pending.take_finalized_fastpq_source().unwrap();
        assert_eq!(retained.manifest().executed_entry_count, 1);
        assert_eq!(
            retained.manifest().statement_count,
            u32::from(with_transfer)
        );
        drop(pending);
        assert_eq!(
            state
                .world
                .accounts
                .view()
                .get(&ALICE_ID)
                .unwrap()
                .metadata
                .get(&publication_marker()),
            Some(&Json::new(1_u32))
        );
        assert_eq!(state.committed_height(), 2);
        assert_eq!(state.transactions.latest_height(), 2);
        assert_eq!(state.latest_block_hash_fast(), Some(expected_hash));
        assert_eq!(chain.kura().blocks_count(), 2);
    }
}

#[test]
fn late_applied_source_cannot_commit_after_all_cached_outputs_are_taken() {
    for same_key in [false, true] {
        for drain_late in [false, true] {
            super::native_capture_fixture::assert_native_publication_refuses(
                true,
                move |original| {
                    assert!(
                        original
                            .state
                            .take_parliament_timed_ovn_casting_bindings()
                            .is_some()
                    );
                    assert!(original.state.take_fastpq_witness_context().is_some());
                    assert!(original.state.exec_witness.is_none());
                    assert!(original.state.fastpq_witness_context.is_none());
                    assert!(
                        original
                            .state
                            .parliament_timed_ovn_casting_bindings
                            .is_none()
                    );
                    let original_hash = original.witness.fastpq_transcripts[0].entry_hash;
                    let late = if same_key {
                        original_hash
                    } else {
                        Hash::new(b"late source after actual extraction")
                    };
                    // Explicit adversarial field mutation, not an authorized
                    // post-seal application or component-owner substitution.
                    let captured = original
                        .state
                        .fastpq_source_context
                        .as_ref()
                        .unwrap()
                        .capture_transcript(
                            Some(late),
                            late,
                            None,
                            Some(DataSpaceId::UNIVERSAL),
                            original.state.committed_fragment_count(),
                        );
                    original.state.fastpq_source_captures.record(captured);
                    assert_eq!(
                        original
                            .state
                            .fastpq_source_captures
                            .sealed_sources()
                            .unwrap_err(),
                        crate::fastpq::FastpqSourceCaptureError::AppliedAfterSeal
                    );
                    let delta = delta();
                    let poseidon_preimage_digest =
                        crate::fastpq::poseidon_preimage_digest(&delta, &late);
                    let transcript = TransferTranscript {
                        batch_hash: late,
                        deltas: vec![delta],
                        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
                        poseidon_preimage_digest: Some(poseidon_preimage_digest),
                    };
                    assert!(
                        original
                            .state
                            .fastpq_transcripts
                            .insert(late, vec![transcript])
                            .is_none()
                    );
                    original
                        .state
                        .world
                        .smart_contract_state
                        .insert(marker(), vec![2]);
                    assert_eq!(
                        original.state.world.smart_contract_state.get(&marker()),
                        Some(&vec![2])
                    );
                    if drain_late {
                        let archive = original.state.drain_transfer_transcripts_with_pending(None);
                        assert_eq!(archive.len(), 1);
                        assert!(archive.contains_key(&late));
                        assert!(original.state.fastpq_transcripts.is_empty());
                    }
                    // No second capture/getter repairs the immutable native witness.
                    assert!(
                        original
                            .state
                            .verified_fastpq_source_inventory_for_capture()
                            .is_err()
                    );
                },
            );
        }
    }
}

#[test]
fn failed_inventory_construction_prevents_commit_without_publishing_overlay() {
    {
        let state = state_with_marker();
        let (mut block, _recording) = recorded_block(&state, header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        let source = Hash::new(b"failed inventory construction");
        apply_source(&mut block, source, false, None);
        apply_marker(&mut block, 2, None);
        block.fastpq_transcripts.get_mut(&source).unwrap().clear();
        let error = block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .unwrap_err();
        assert!(
            block
                .finalize_fastpq_source_inventory(&[], &[], &[])
                .unwrap_err()
                .contains("already been finalized"),
        );
        assert_eq!(
            block.fastpq_source_inventory(),
            Err(error.as_str()),
            "failed inventory construction must remain latched"
        );
        assert_eq!(
            block.verified_fastpq_source_inventory_for_capture(),
            Err("FASTPQ witness capture refuses a poisoned carrier".into()),
        );
        assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
        stage_membership(&mut block, Some(source));
        // Inventory construction poisoned the carrier, so the earlier output
        // publication guard refuses it before the inventory-specific commit gate.
        assert!(matches!(
            block.commit(),
            Err(TransactionsBlockError::ExecutionOutputCapacity)
        ));
        assert_unpublished(&state);
    }
}

#[test]
fn unfinalized_fixture_commit_does_not_require_source_inventory() {
    let state = state_with_marker();
    let mut block = state.block(header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    apply_marker(&mut block, 1, None);
    assert!(block.fastpq_source_inventory.is_none());
    stage_membership(&mut block, None);
    block.commit().unwrap();
    assert_eq!(
        state.world.smart_contract_state.view().get(&marker()),
        Some(&vec![1]),
    );
    assert_eq!(state.committed_height(), 1);
    assert_eq!(state.transactions.latest_height(), 1);
}
