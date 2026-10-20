//! Exact source ownership, intrinsic admission and whole-overlay rollback.

use super::*;
use crate::query::store::LiveQueryStore;
use iroha_data_model::{block::BlockHeader, fastpq::TransferSmtWitness};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use nonzero_ext::nonzero;

fn state() -> State {
    State::new(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(nonzero!(1_u64), None, None, 7, 0)
}

fn delta() -> TransferDeltaTranscript {
    TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        amount: Quantity::from(3_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(7_u32),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(3_u32),
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    }
}

#[test]
fn preparation_finalizes_exact_transcript_without_staging_and_moves_its_storage() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"prepared execution call");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    tx.current_lane_id = Some(LaneId::SINGLE);
    tx.current_dataspace_id = Some(DataSpaceId::new(7));
    let deltas = vec![delta()];
    let allocation = deltas.as_ptr();
    let expected = TransferTranscript {
        batch_hash: hash,
        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        poseidon_preimage_digest: Some(crate::fastpq::poseidon_preimage_digest(&deltas[0], &hash)),
        deltas: deltas.clone(),
    };
    let occurrence = tx
        .prepare_transfer_occurrence(&ALICE_ID, hash, deltas)
        .unwrap();
    assert_eq!(occurrence.transcript, expected);
    assert_eq!(occurrence.transcript.deltas.as_ptr(), allocation);
    let captured = occurrence.capture.unwrap();
    assert_eq!(captured.entry_hash(), hash);
    assert_eq!(captured.dataspace_id(), DataSpaceId::new(7));
    assert_eq!(
        captured.first_fragment_index(),
        *tx.committed_fragments as u64
    );
    assert!(!captured.is_protocol_purpose());
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
    tx.stage_transfer_occurrence(Some(occurrence));
    assert_eq!(tx.pending_transfer_transcripts, vec![expected]);
    assert_eq!(
        tx.pending_transfer_transcripts[0].deltas.as_ptr(),
        allocation
    );
    assert_eq!(
        tx.pending_fastpq_source_captures.sources().unwrap()[&hash],
        captured
    );
}

#[test]
fn successful_callback_stages_one_exact_occurrence_after_the_movement() {
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"successful movement");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    let applied = tx
        .apply_with_prepared_transfer_transcripts(&ALICE_ID, hash, vec![delta()], |tx| {
            assert!(tx.pending_transfer_transcripts.is_empty());
            assert!(
                tx.pending_fastpq_source_captures
                    .sources()
                    .unwrap()
                    .is_empty()
            );
            Ok(37_u32)
        })
        .unwrap();
    assert_eq!(applied, 37);
    let expected = tx.pending_transfer_transcripts[0].clone();
    tx.apply();
    assert_eq!(block.fastpq_transcripts[&hash], vec![expected.clone()]);
    assert_eq!(block.captured_fastpq_transcript_sources().unwrap().len(), 1);
    let witness = crate::exec_witness::drain_exec_witness();
    assert_eq!(witness.fastpq_transcripts.len(), 1);
    assert_eq!(witness.fastpq_transcripts[0].entry_hash, hash);
    assert_eq!(witness.fastpq_transcripts[0].transcripts, vec![expected]);
}

#[test]
fn failed_callback_drops_prepared_transcript_and_does_not_latch_capture_error() {
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"failed movement");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    let result: Result<(), Error> =
        tx.apply_with_prepared_transfer_transcripts(&ALICE_ID, hash, vec![delta()], |_| {
            Err(Error::InvariantViolation("movement failed".into()))
        });
    assert!(result.unwrap_err().to_string().contains("movement failed"));
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
    tx.apply();
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::exec_witness::drain_exec_witness()
            .fastpq_transcripts
            .is_empty()
    );
}

#[test]
fn unresolved_source_rejects_before_callback_and_refuses_ignored_error_apply() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"unresolved source lane");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let usage = block.fastpq_source_usage_for_testing();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    tx.current_lane_id = Some(LaneId::new(999));
    let mut called = false;
    let result =
        tx.apply_with_prepared_transfer_transcripts(&ALICE_ID, hash, vec![delta()], |_| {
            called = true;
            Ok(())
        });
    assert!(result.is_err());
    assert!(!called);
    assert!(tx.fastpq_source_quota.intrinsic_rejected().is_err());
    assert!(tx.pending_transfer_transcripts.is_empty());
    tx.apply();
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert_eq!(block.fastpq_source_usage_for_testing(), usage);
}

#[test]
fn empty_occurrence_keeps_legacy_no_identity_no_op_and_runs_callback() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let mut tx = block.transaction();
    assert!(tx.tx_call_hash.is_none());
    tx.record_transfer_transcripts(&ALICE_ID, Vec::new())
        .unwrap();
    assert_eq!(
        tx.apply_with_prepared_transfer_transcripts(
            &ALICE_ID,
            Hash::new(b"empty"),
            Vec::new(),
            |_| Ok(11_u32)
        )
        .unwrap(),
        11
    );
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn immediate_multi_delta_recording_preserves_one_occurrence_and_absent_digest() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"multi delta occurrence");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    let deltas = vec![delta(), delta()];
    let allocation = deltas.as_ptr();
    tx.record_transfer_transcripts(&ALICE_ID, deltas).unwrap();
    assert_eq!(tx.pending_transfer_transcripts.len(), 1);
    assert_eq!(
        tx.pending_transfer_transcripts[0].deltas.as_ptr(),
        allocation
    );
    assert_eq!(
        tx.pending_transfer_transcripts[0].deltas,
        vec![delta(), delta()]
    );
    assert_eq!(
        tx.pending_transfer_transcripts[0].poseidon_preimage_digest,
        None
    );
    assert_eq!(
        tx.pending_fastpq_source_captures.sources().unwrap().len(),
        1
    );
}

#[test]
fn discarded_successful_movement_keeps_block_capture_and_transcripts_empty() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    {
        let hash = Hash::new(b"rolled back movement");
        block.retain_fastpq_source_invocation(hash).unwrap();
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(hash);
        tx.apply_with_prepared_transfer_transcripts(&ALICE_ID, hash, vec![delta()], |_| Ok(()))
            .unwrap();
        assert_eq!(tx.pending_transfer_transcripts.len(), 1);
    }
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn incremental_singleton_matches_the_fixed_prepared_occurrence() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"incremental singleton");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    tx.current_lane_id = Some(LaneId::SINGLE);
    tx.current_dataspace_id = Some(DataSpaceId::new(7));
    let expected = tx
        .prepare_transfer_occurrence(&ALICE_ID, hash, vec![delta()])
        .unwrap();
    tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 3, |tx, append| {
        append(tx, delta())?;
        assert!(tx.pending_transfer_transcripts.is_empty());
        assert!(
            tx.pending_fastpq_source_captures
                .sources()
                .unwrap()
                .is_empty()
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(tx.pending_transfer_transcripts, vec![expected.transcript]);
    assert_eq!(
        tx.pending_fastpq_source_captures.sources().unwrap()[&hash],
        expected.capture.unwrap()
    );
}

#[test]
fn incremental_empty_discards_initial_capture_error_and_multi_preserves_one_group() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"incremental group");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    tx.current_lane_id = Some(LaneId::new(999));
    tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 3, |_, _| Ok(()))
        .unwrap();
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
    tx.current_lane_id = Some(LaneId::SINGLE);
    let expected = tx
        .prepare_transfer_occurrence(&ALICE_ID, hash, vec![delta(), delta()])
        .unwrap();
    tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 3, |tx, append| {
        append(tx, delta())?;
        append(tx, delta())?;
        assert!(tx.pending_transfer_transcripts.is_empty());
        Ok(())
    })
    .unwrap();
    assert_eq!(tx.pending_transfer_transcripts, vec![expected.transcript]);
    assert_eq!(
        tx.pending_transfer_transcripts[0].poseidon_preimage_digest,
        None
    );
    assert_eq!(
        tx.pending_fastpq_source_captures.sources().unwrap()[&hash],
        expected.capture.unwrap()
    );
}

#[test]
fn incremental_whole_callback_error_discards_all_accepted_occurrences() {
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"incremental failed body");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    let result: Result<(), Error> =
        tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 3, |tx, append| {
            append(tx, delta())?;
            append(tx, delta())?;
            assert!(tx.pending_transfer_transcripts.is_empty());
            Err(Error::InvariantViolation(
                "later movement or outcome failed".into(),
            ))
        });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("later movement or outcome failed")
    );
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
    tx.apply();
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::exec_witness::drain_exec_witness()
            .fastpq_transcripts
            .is_empty()
    );
}

#[test]
fn incremental_preparation_limit_rejects_before_the_next_movement() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"incremental preparation bound");
    block.retain_fastpq_source_invocation(hash).unwrap();
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(hash);
    let mut movements = 0;
    let result =
        tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 1, |tx, append| {
            append(tx, delta())?;
            movements += 1;
            append(tx, delta())?;
            movements += 1;
            Ok(())
        });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("declared entry bound")
    );
    assert_eq!(movements, 1);
    assert!(tx.pending_transfer_transcripts.is_empty());
    assert!(
        tx.pending_fastpq_source_captures
            .sources()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn incremental_ignored_preparation_error_cannot_publish_a_partial_occurrence() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let state = state();
    let hash = Hash::new(b"ignored incremental preparation error");
    for limit in [0, 1] {
        // Each refused occurrence poisons its original carrier. The next limit
        // must acquire a fresh overlay rather than mutate that failed owner.
        let mut block = state.block(header());
        block.retain_fastpq_source_invocation(hash).unwrap();
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(hash);
        let result =
            tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, limit, |tx, append| {
                let _ = append(tx, delta());
                assert!(append(tx, delta()).is_err());
                Ok(())
            });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("declared entry bound")
        );
        assert!(tx.pending_transfer_transcripts.is_empty());
        assert!(
            tx.pending_fastpq_source_captures
                .sources()
                .unwrap()
                .is_empty()
        );
        drop(tx);
        assert!(matches!(
            block.execution_output_plan,
            Some(crate::state::output_capacity::ExecutionOutputPlanState::Poisoned)
        ));
        assert!(block.fastpq_transcripts.is_empty());
    }
}

#[test]
fn incremental_preparation_failure_rolls_back_real_transfers_with_the_entry() {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::isi::Transfer;

    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let definition_id = delta().asset_definition;
    let source = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let destination = AssetId::new(definition_id.clone(), BOB_ID.clone());
    let world = World::with_assets(
        [Domain::new(domain_id).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [AssetDefinition::numeric(
            definition_id,
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID)],
        [
            Asset::new(source.clone(), Quantity::from(10_u32)),
            Asset::new(destination.clone(), Quantity::zero()),
        ],
        [],
    );
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(header());
    let prior_hash = Hash::new(b"prior accepted transfer");
    block.retain_fastpq_source_invocation(prior_hash).unwrap();
    {
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(prior_hash);
        Transfer::asset_quantity(source.clone(), 1_u32, BOB_ID.clone())
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        tx.apply();
    }
    let prior_events = block.world.external_event_buf.clone();
    let prior_transcripts = block.fastpq_transcripts.clone();
    let prior_captures = block.captured_fastpq_transcript_sources().unwrap().clone();
    let prior_fragments = block.committed_fragment_count();
    let prior_usage = block.fastpq_source_usage_for_testing();
    {
        let hash = Hash::new(b"entry rejected during preparation");
        block.retain_fastpq_source_invocation(hash).unwrap();
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(hash);
        let result =
            tx.apply_with_incremental_transfer_transcripts(&ALICE_ID, hash, 1, |tx, append| {
                let mut accepted = delta();
                accepted.from_balance_before = Quantity::from(9_u32);
                accepted.from_balance_after = Quantity::from(6_u32);
                accepted.to_balance_before = Quantity::from(1_u32);
                accepted.to_balance_after = Quantity::from(4_u32);
                append(tx, accepted.clone())?;
                Transfer::asset_quantity(source.clone(), 3_u32, BOB_ID.clone())
                    .execute(&ALICE_ID, tx)?;
                assert_eq!(
                    tx.world.assets().get(&source).unwrap().0,
                    Quantity::from(6_u32)
                );
                append(tx, accepted)?;
                Ok(())
            });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("declared entry bound")
        );
        // The entry owner discards its complete physical transaction, including
        // real movements made before a later preparation failure.
        drop(tx);
    }
    assert_eq!(
        block.world.assets().get(&source).unwrap().0,
        Quantity::from(9_u32)
    );
    assert_eq!(
        block.world.assets().get(&destination).unwrap().0,
        Quantity::from(1_u32)
    );
    assert_eq!(block.world.external_event_buf, prior_events);
    assert_eq!(block.fastpq_transcripts, prior_transcripts);
    assert_eq!(
        block.captured_fastpq_transcript_sources().unwrap(),
        &prior_captures
    );
    assert_eq!(block.committed_fragment_count(), prior_fragments);
    let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
    let mut expected = prior_usage.0;
    expected.executed_entries += 1;
    assert_eq!(ordinary, expected);
    assert_eq!(mandatory, prior_usage.1);
}
