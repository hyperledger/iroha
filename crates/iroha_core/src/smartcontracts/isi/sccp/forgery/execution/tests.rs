//! Genuine signed-parent execution components; direct calls grant no network-entrypoint authority.

use super::*;
use crate::smartcontracts::isi::sccp::{
    forgery::tests::{active_chain, active_member_chain, future, partial_member_chain, resign},
    test_support::{blank_state, sample_route},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{EvidencePenaltyStatus, EvidenceScope},
    },
    bridge::SccpNetworkV1,
    events::{EventBox, data::DataEvent},
};
use iroha_sccp::v1::finality::QcFixedV1;
use std::num::NonZeroU64;

fn next_header(chain: &crate::sumeragi::test_chain::CertifiedTestChain) -> BlockHeader {
    let parent = chain.state().view().native_execution_tip().unwrap();
    BlockHeader::new(
        NonZeroU64::new(parent.height() + 1).unwrap(),
        Some(parent.iroha_hash()),
        None,
        parent.creation_time_ms() + 1_000,
        0,
    )
}

fn sccp_events(stx: &mut StateTransaction<'_, '_>) -> Vec<SccpEvent> {
    stx.world
        .take_external_events()
        .into_iter()
        .filter_map(|event| match event {
            EventBox::Data(event) => match event.as_ref() {
                DataEvent::Sccp(e) => Some(e.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[test]
fn authentic_parent_records_exact_g6_id_pending_delay_and_same_child_hold() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    // Registry DATA only tests the event/hold projection; RegisterRoute remains separately gated.
    let route = sample_route(SccpNetworkV1::EthereumMainnet);
    store::routes::insert(&mut stx, route.network, route).unwrap();
    let prepared = prepare_execution(&evidence, &stx).unwrap();
    let id = prepared.evidence_id;
    let original = prepared.record.canonical_projection();
    publish(prepared, &mut stx).unwrap();
    let retained = stx
        .world
        .consensus_evidence
        .get(&Hash::prehashed(id))
        .unwrap();
    assert_eq!(retained.canonical_projection(), original);
    assert_eq!(retained.recorded_at_height, header.height().get());
    assert_eq!(retained.recorded_at_ms, header.creation_time_ms);
    assert_eq!(retained.recorded_at_view, header.view_change_index);
    assert_eq!(retained.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(
        retained.attribution.scope,
        EvidenceScope::SccpGeneration { generation: 1 }
    );
    assert_eq!(
        retained.attribution.height, 1,
        "liability start, never attacker-claimed height"
    );
    assert_eq!(retained.sccp_evidence_id(), Some(id));
    let RecordedEvidenceV1::SccpForgery(record) = &retained.evidence else {
        panic!("closed SCCP record")
    };
    assert_eq!(record.evidence, evidence);
    assert_eq!(record.offenders.len(), 3);
    assert!(record.offenders.iter().all(|m| m.activation_height == 1));
    for offender in &record.offenders {
        let key = OffenceKey::try_copy(
            1,
            offender.lane_id,
            &offender.validator,
            stx.world.sccp_forgery_offences.allocation_budget(),
        )
        .unwrap();
        assert_eq!(store::forgery_offences::get(&*stx.world, &key), Some(&id));
    }
    assert_eq!(store::forgery_max_generation(&*stx.world), Some(1));
    let events = sccp_events(&mut stx);
    assert!(
        matches!(&events[0], SccpEvent::ForgeryEvidenceRecorded(e) if e.evidence_id == id && e.offenders.len() == 3)
    );
    assert!(
        matches!(&events[1], SccpEvent::RevisionForgeryHeld(e) if e.generation == 1 && e.forgery_floor == 1)
    );
    assert_eq!(events.len(), 2);
    stx.apply();
    assert_eq!(block.world.consensus_evidence.len(), 1);
    assert_eq!(block.world.sccp_forgery_offences.len(), 3);
    // The component block is intentionally discarded: this does not forge an output seal.
    drop(block);
    let view = chain.state().view();
    assert!(view.world().consensus_evidence().is_empty());
    assert!(view.world().sccp_forgery_offences().is_empty());
    assert_eq!(store::forgery_max_generation(view.world()), None);
}

#[test]
fn duplicate_is_no_write_and_overlapping_quorum_records_only_new_registration() {
    let (chain, keys) = active_member_chain();
    let mut evidence = future(&chain, &keys);
    let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
    qc.signers = 0b0111;
    evidence.qc = qc.encode();
    resign(&mut evidence, &keys, chain.instance());
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    execute_forgery(&evidence, &mut stx).unwrap();
    let first = *stx.world.consensus_evidence.iter().next().unwrap().0;
    assert_eq!(sccp_events(&mut stx).len(), 1);
    assert!(matches!(
        execute_forgery(&evidence, &mut stx),
        Err(ForgeryExecutionError::EvidenceDuplicate)
    ));
    assert!(sccp_events(&mut stx).is_empty());
    assert_eq!(stx.world.consensus_evidence.len(), 1);
    qc.signers = 0b1011;
    evidence.qc = qc.encode();
    resign(&mut evidence, &keys, chain.instance());
    execute_forgery(&evidence, &mut stx).unwrap();
    assert_eq!(stx.world.consensus_evidence.len(), 2);
    assert_eq!(stx.world.sccp_forgery_offences.len(), 4);
    let events = sccp_events(&mut stx);
    assert!(
        matches!(&events[0], SccpEvent::ForgeryEvidenceRecorded(e) if e.offenders.len() == 1 && e.offenders[0].signer == 3)
    );
    assert_eq!(events.len(), 1);
    assert_eq!(
        stx.world
            .sccp_forgery_offences
            .iter()
            .filter(|(_, id)| Hash::prehashed(**id) == first)
            .count(),
        3,
        "existing permanent offences never rebind to the second certificate"
    );
}

#[test]
fn unslashable_signer_is_reported_without_inventing_member_or_penalty() {
    let (chain, keys) = partial_member_chain();
    let mut evidence = future(&chain, &keys);
    let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
    qc.signers = 0b0111;
    evidence.qc = qc.encode();
    resign(&mut evidence, &keys, chain.instance());
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    execute_forgery(&evidence, &mut stx).unwrap();
    assert_eq!(stx.world.sccp_forgery_offences.len(), 2);
    let events = sccp_events(&mut stx);
    assert!(
        matches!(&events[0], SccpEvent::ForgeryOffenderUnslashable(e) if e.generation == 1 && e.signer == 2)
    );
    assert!(matches!(&events[1], SccpEvent::ForgeryEvidenceRecorded(e) if e.offenders.len() == 2));
    assert_eq!(events.len(), 2);
}

#[test]
fn wholly_unslashable_claim_cannot_publish_a_success_or_hold() {
    let (chain, keys) = active_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    assert!(matches!(
        execute_forgery(&evidence, &mut stx),
        Err(ForgeryExecutionError::EvidenceDuplicate)
    ));
    assert!(stx.world.consensus_evidence.is_empty());
    assert!(stx.world.sccp_forgery_offences.is_empty());
    assert_eq!(store::forgery_max_generation(&*stx.world), None);
    assert!(sccp_events(&mut stx).is_empty());
}

#[test]
fn missing_s0_and_changed_header_are_source_refusals_before_publication() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let parent_clock = *store::liability_clock::get(&stx.sccp_parent_world_view());
    let expected_clock = {
        let parent = stx.sccp_parent_world_view();
        let parameters = params::parameters(&parent).unwrap();
        let (tip, _) = original_source(&stx).unwrap();
        super::super::super::generation::advance_liability_clock(
            parent_clock,
            tip.creation_time_ms(),
            header.creation_time_ms,
            parameters.committee_heartbeat_ms,
        )
    };
    // State::block already runs S0. Remove only its local child-clock effect to
    // test a missing S0 result without altering the genuine committed parent.
    assert_ne!(expected_clock, parent_clock);
    assert_eq!(*store::liability_clock::get(&*stx.world), expected_clock);
    store::liability_clock::set(&mut stx, parent_clock);
    let error = execute_forgery(&evidence, &mut stx).err().unwrap();
    assert!(matches!(
        error,
        ForgeryExecutionError::Verification(ForgeryVerificationError::Unavailable(
            "original S0 liability clock is absent or changed"
        ))
    ));
    let _ = error.into_instruction_error(&mut stx);
    assert_eq!(
        stx.require_storage_admission(),
        Err(StateStorageAdmissionError::SccpForgery(
            ForgeryStorageError::Invalid
        ))
    );
    assert!(stx.world.consensus_evidence.is_empty());
    assert!(stx.world.sccp_forgery_offences.is_empty());
    assert_eq!(store::forgery_max_generation(&*stx.world), None);
    assert!(sccp_events(&mut stx).is_empty());
    drop(stx);
    drop(block);
    assert_eq!(
        *store::liability_clock::get(chain.state().view().world()),
        parent_clock,
        "local negative control leaves the authenticated parent unchanged"
    );
    let mut bad = header;
    bad.creation_time_ms = 2_000;
    let mut block = chain.state().block(bad);
    let stx = block.transaction_for_callback_testing();
    assert!(matches!(
        prepare_execution(&evidence, &stx),
        Err(ForgeryExecutionError::Verification(
            ForgeryVerificationError::Unavailable("execution header differs from original parent")
        ))
    ));
}

#[test]
fn execution_rechecks_advanced_original_parent_instead_of_trusting_old_e2() {
    let (mut chain, keys) = active_member_chain();
    let previous = future(&chain, &keys);
    // Replace the hypothetical future with the genuine next block. Its original certificate
    // could have passed E2 at a lagging node, but it is not evidence at this parent.
    chain.commit_at(3_000, Vec::new());
    let evidence = super::super::tests::original(&chain);
    assert_ne!(evidence.header, previous.header);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    assert!(matches!(
        execute_forgery(&evidence, &mut stx),
        Err(ForgeryExecutionError::Verification(
            ForgeryVerificationError::NotEvidence
        ))
    ));
    assert!(stx.world.consensus_evidence.is_empty());
}

#[test]
fn permanent_storage_refusal_is_sticky_and_does_not_publish_record_or_events() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let prepared = prepare_execution(&evidence, &stx).unwrap();
    let pool = stx.world.sccp_forgery_offences.allocation_budget().clone();
    let limit = pool.limit_bytes();
    pool.set_limit_bytes(pool.reserved_bytes());
    let error = publish(prepared, &mut stx)
        .err()
        .expect("map write needs admitted original backing");
    pool.set_limit_bytes(limit);
    assert!(matches!(
        error,
        ForgeryExecutionError::Storage(ForgeryStorageError::Storage(_))
    ));
    assert!(stx.require_storage_admission().is_err());
    assert!(stx.world.consensus_evidence.is_empty());
    assert!(sccp_events(&mut stx).is_empty());
    drop(stx);
    assert!(
        block.require_storage_admission().is_err(),
        "discard cannot clear first refusal"
    );
    drop(block);
    assert!(
        chain
            .state()
            .view()
            .world()
            .sccp_forgery_offences()
            .is_empty()
    );
}

#[test]
fn exact_local_refusal_survives_instruction_mapping_and_protocol_error_does_not_poison() {
    let state = blank_state();
    let mut block = state.block(crate::smartcontracts::isi::sccp::test_support::header(2));
    let mut stx = block.transaction();
    let _ = ForgeryExecutionError::EvidenceDuplicate.into_instruction_error(&mut stx);
    assert!(stx.require_storage_admission().is_ok());
    let pool = AllocationBudget::new(1);
    let held = pool.try_reserve_bytes(1).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    assert!(matches!(&original, AllocationRefusal::Capacity { .. }));
    let error = EvidencePreparationError::Admission(original.clone());
    let _ = ForgeryExecutionError::Preparation(error.clone()).into_instruction_error(&mut stx);
    assert_eq!(
        stx.require_storage_admission(),
        Err(StateStorageAdmissionError::SccpEvidence(error))
    );
    drop(held);
}

#[test]
fn event_hold_transitions_respect_floor_and_emit_once_in_canonical_revision_order() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let mut route = sample_route(SccpNetworkV1::EthereumMainnet);
    let mut future_revision = route.revisions.get(&1).unwrap().clone();
    future_revision.revision = 2;
    future_revision.forgery_floor = 2;
    route.revisions.insert(2, future_revision);
    store::routes::insert(&mut stx, route.network, route).unwrap();
    execute_forgery(&evidence, &mut stx).unwrap();
    let events = sccp_events(&mut stx);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, SccpEvent::RevisionForgeryHeld(_)))
            .count(),
        1
    );
    assert!(
        matches!(&events[1], SccpEvent::RevisionForgeryHeld(e) if e.revision == 1 && e.forgery_floor == 1)
    );
}

#[test]
fn prepared_record_cannot_change_execution_clock_between_verification_and_conversion() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let prepared = {
        let parent = stx.sccp_parent_world_view();
        let (tip, instance) = original_source(&stx).unwrap();
        let checked = verify_observation(
            &parent,
            &evidence,
            SccpFinalityHeaderV1::parse(&evidence.header).unwrap(),
            Observation {
                parent: tip,
                instance,
                execution_height: header.height().get(),
                liability_clock: *store::liability_clock::get(&*stx.world),
            },
            stx.sccp_evidence_preparation_budget(),
            VerificationControl::Synchronous,
        )
        .unwrap();
        prepare_sccp_claim(
            &checked,
            checked.qc().signers,
            stx.sccp_evidence_preparation_budget(),
        )
        .unwrap()
    };
    let clock = *store::liability_clock::get(&*stx.world);
    store::liability_clock::set(&mut stx, clock + 1);
    assert!(matches!(
        prepared.into_record(&stx),
        Err(EvidencePreparationError::Invariant)
    ));
    assert!(stx.world.consensus_evidence.is_empty());
    assert!(stx.world.sccp_forgery_offences.is_empty());
}

#[test]
fn genuine_prepared_publication_late_map_refusal_discards_first_offence_and_max() {
    // This is a deliberately split private-publication component, not injected Network
    // execution: the genuine prepared owner provides every key and record. The same
    // first insertion used by publish completes before a real second insertion refuses.
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let header = next_header(&chain);
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let mut prepared = prepare_execution(&evidence, &stx).unwrap();
    let id = prepared.evidence_id;
    let first = prepared.keys.iter_mut().find_map(Option::take).unwrap();
    assert!(store::forgery_offences::insert_new(&mut stx, first, id).unwrap());
    assert_eq!(stx.world.sccp_forgery_offences.len(), 1);
    assert_eq!(store::forgery_max_generation(&*stx.world), Some(1));
    let pool = stx.world.sccp_forgery_offences.allocation_budget().clone();
    let occupied = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let error = publish(prepared, &mut stx).unwrap_err();
    assert!(
        matches!(
            &error,
            ForgeryExecutionError::Storage(ForgeryStorageError::Storage(
                mv::storage::AdmittedStorageError::Allocation(AllocationRefusal::Capacity { .. })
            ))
        ),
        "{error:?}"
    );
    let original = stx.require_storage_admission().unwrap_err();
    assert!(original.release_wait().is_some());
    assert_eq!(
        stx.world.sccp_forgery_offences.len(),
        1,
        "later insertion did not partially apply"
    );
    assert_eq!(store::forgery_max_generation(&*stx.world), Some(1));
    assert!(stx.world.consensus_evidence.is_empty());
    assert!(sccp_events(&mut stx).is_empty());
    drop(occupied);
    drop(stx);
    assert_eq!(block.require_storage_admission(), Err(original.clone()));
    assert!(block.world.sccp_forgery_offences.is_empty());
    assert_eq!(store::forgery_max_generation(&block.world), None);
    assert!(
        matches!(block.commit(), Err(crate::state::storage_transactions::TransactionsBlockError::LocalStateStorage(error))
        if error == original)
    );
    let view = chain.state().view();
    assert!(view.world().sccp_forgery_offences().is_empty());
    assert!(view.world().consensus_evidence().is_empty());
    assert_eq!(store::forgery_max_generation(view.world()), None);
}
