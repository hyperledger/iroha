//! Signed sole-forgery Network output controls over genuine initialized native parents.
//! These exercise the real producer and rollback owner, not new finality or a network gate.

use super::*;
use crate::{
    smartcontracts::isi::sccp::{
        forgery::tests::{active_member_chain_with_output_policy, future},
        store,
    },
    state::{EvidencePreparationError, WorldReadOnly, sccp_forgery_custody::OffenceKey},
    sumeragi::test_chain::CertifiedTestChain,
};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::{
        BlockExecutionContextBundle, ExternalExecutionContext,
        consensus::{EvidencePenaltyStatus, EvidenceScope, RecordedEvidenceV1},
    },
    events::{EventBox, data::DataEvent},
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::events::SccpEvent,
    trigger::action::Repeats,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};

fn output_policy(bytes: u64) -> ExecutionOutputPolicyV1 {
    let mut policy = ExecutionOutputPolicyV1::bootstrap();
    policy.max_output_bytes = bytes;
    policy.max_pipeline_triggers = 0;
    policy.max_time_invocations = 1;
    policy.validate().unwrap();
    policy
}

fn signed_carrier(
    chain: &CertifiedTestChain,
    committee_key: &KeyPair,
    ordinary_signer: &KeyPair,
    evidence: &SubmitSccpForgeryEvidenceV1,
    copies: usize,
) -> SignedBlock {
    assert_eq!(committee_key.public_key().algorithm(), Algorithm::BlsNormal);
    assert_eq!(ordinary_signer.public_key().algorithm(), Algorithm::Ed25519);
    assert_eq!(
        chain.genesis_account(),
        &iroha_data_model::account::AccountId::new(ordinary_signer.public_key().clone())
    );
    let tip = chain.state().view().native_execution_tip().unwrap();
    let inputs = (0..copies)
        .map(|index| {
            TransactionEntrypoint::External(chain.sign(
                ordinary_signer,
                [InstructionBox::from(evidence.clone())],
                tip.creation_time_ms() + 1 + u64::try_from(index).unwrap(),
            ))
        })
        .collect::<Vec<_>>();
    let context = BlockExecutionContextBundle::new(
        inputs
            .iter()
            .map(|input| {
                ExternalExecutionContext::new(input.hash(), LaneId::SINGLE, DataSpaceId::UNIVERSAL)
            })
            .collect(),
    );
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(tip.height() + 1).unwrap(),
        Some(tip.iroha_hash()),
        None,
        tip.creation_time_ms() + 1_000,
        0,
    ));
    for input in inputs {
        let TransactionEntrypoint::External(signed) = input else {
            unreachable!()
        };
        builder.push_transaction(signed);
    }
    builder.set_execution_context(Some(context));
    builder.build_with_signature(0, committee_key.private_key())
}

fn recorded<'state>(
    state: &'state State,
    source: &SignedBlock,
) -> (
    Box<StateBlock<'state>>,
    crate::exec_witness::ExecWitnessGuard,
) {
    state
        .block_with_recorded_pristine_carrier_stage(
            source,
            |block| {
                crate::smartcontracts::ivm::active_runtime_abi_hash(
                    &block.world,
                    source.header().height().get(),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
            },
            |error| error,
        )
        .expect("original signed carrier, pristine S0 and recorder")
}

fn execute(
    block: &mut StateBlock<'_>,
    source: &SignedBlock,
) -> Result<(), ExecutionOutputAttemptError> {
    block.reserve_ordinary_execution_outputs(source)?;
    block.produce_ordinary_execution_outputs(source, |producer| {
        producer.execute_network_sources(None)?;
        finish_empty_internal(producer)
    })
}

fn evidence_events<'a>(block: &'a StateBlock<'_>) -> Vec<&'a SccpEvent> {
    block
        .world
        .external_event_buf
        .iter()
        .filter_map(|event| match event {
            EventBox::Data(event) => match event.as_ref() {
                DataEvent::Sccp(event) => Some(event),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn assert_unpublished(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    assert!(view.world().consensus_evidence().is_empty());
    assert!(view.world().sccp_forgery_offences().is_empty());
    assert_eq!(store::forgery_max_generation(view.world()), None);
    assert_eq!(
        view.height(),
        2,
        "no partial carrier advanced the original journal"
    );
}

fn assert_success_record(
    block: &StateBlock<'_>,
    source: &SignedBlock,
    evidence: &SubmitSccpForgeryEvidenceV1,
) {
    let rows = &retained(block).rows;
    assert_eq!(rows.len(), 1);
    let ExecutionOutputV1::Network(row) = &rows[0] else {
        panic!("actual Network row")
    };
    assert!(row.result.is_ok(), "{:?}", row.result);
    assert!(
        row.result.nexus_fee_receipt().is_none(),
        "exempt original source"
    );
    assert!(!rows[0].is_output_limit_rejection());
    assert_eq!(block.world.consensus_evidence.len(), 1);
    assert_eq!(block.world.sccp_forgery_offences.len(), 3);
    let (id, retained) = block.world.consensus_evidence.iter().next().unwrap();
    assert_eq!(retained.sccp_evidence_id(), Some((*id).into()));
    assert_eq!(retained.recorded_at_height, source.header().height().get());
    assert_eq!(retained.recorded_at_ms, source.header().creation_time_ms);
    assert_eq!(retained.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(
        retained.attribution.scope,
        EvidenceScope::SccpGeneration { generation: 1 }
    );
    assert_eq!(retained.attribution.height, 1);
    let RecordedEvidenceV1::SccpForgery(record) = &retained.evidence else {
        panic!("closed evidence")
    };
    assert_eq!(&record.evidence, evidence);
    assert_eq!(record.offenders.len(), 3);
    for offender in &record.offenders {
        assert_eq!(offender.activation_height, 1);
        let key = OffenceKey::try_copy(
            1,
            offender.lane_id,
            &offender.validator,
            block.world.sccp_forgery_offences.allocation_budget(),
        )
        .unwrap();
        assert_eq!(
            store::forgery_offences::get(&block.world, &key),
            Some(id.as_ref())
        );
    }
    assert_eq!(store::forgery_max_generation(&block.world), Some(1));
    let events = evidence_events(block);
    assert_eq!(
        events.len(),
        1,
        "no routes are invented to manufacture a held event"
    );
    assert!(
        matches!(events[0], SccpEvent::ForgeryEvidenceRecorded(event)
        if event.evidence_id == <[u8; 32]>::from(*id)
            && event.generation == 1 && event.offenders == record.offenders)
    );
}

#[test]
fn signed_sole_forgery_records_exact_original_g6_under_network_owner() {
    let (chain, keys, ordinary_signer) =
        active_member_chain_with_output_policy(output_policy(65_536), None);
    let evidence = future(&chain, &keys);
    let source = signed_carrier(&chain, &keys[0], &ordinary_signer, &evidence, 1);
    let (mut block, recording) = recorded(chain.state(), &source);
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    assert_success_record(&block, &source, &evidence);
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    // A producer component is not a seal/finality grant. Dropping it cannot publish State.
    drop(block);
    drop(recording);
    assert_unpublished(&chain);
}

#[test]
fn signed_duplicate_second_source_poison_discards_first_success_without_rejected_row() {
    let (chain, keys, ordinary_signer) =
        active_member_chain_with_output_policy(output_policy(65_536), None);
    let evidence = future(&chain, &keys);
    let source = signed_carrier(&chain, &keys[0], &ordinary_signer, &evidence, 2);
    let (mut block, recording) = recorded(chain.state(), &source);
    let error = execute(&mut block, &source).unwrap_err();
    assert!(
        matches!(error, ExecutionOutputAttemptError::Owner(ref message)
        if message.starts_with("SCCP forgery evidence failed at execution (R-EX): ")
            && message.contains("SCCP forgery evidence duplicate")),
        "{error:?}"
    );
    assert!(block.retained_execution_outputs_for_test().is_err());
    assert!(matches!(
        block.execution_output_plan.as_ref(),
        Some(ExecutionOutputPlanState::Poisoned)
    ));
    assert_eq!(
        block.world.consensus_evidence.len(),
        1,
        "only first child completed locally"
    );
    assert_eq!(block.world.sccp_forgery_offences.len(), 3);
    assert_eq!(
        evidence_events(&block).len(),
        1,
        "duplicate added no events"
    );
    assert!(
        block.require_storage_admission().is_ok(),
        "duplicate is a protocol verdict"
    );
    assert!(matches!(
        block.commit(),
        Err(TransactionsBlockError::ExecutionOutputCapacity)
    ));
    drop(recording);
    assert_unpublished(&chain);
}

#[test]
fn signed_forgery_original_pairing_pool_refusal_survives_discard_and_can_retry() {
    let (chain, keys, ordinary_signer) =
        active_member_chain_with_output_policy(output_policy(65_536), None);
    let evidence = future(&chain, &keys);
    let source = signed_carrier(&chain, &keys[0], &ordinary_signer, &evidence, 1);
    let (mut block, recording) = recorded(chain.state(), &source);
    let pool = chain.state().evidence_preparation_budget();
    let occupied = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let error = execute(&mut block, &source).unwrap_err();
    assert!(!error.to_string().contains("R-EX"), "{error:?}");
    let original = block.require_storage_admission().unwrap_err();
    assert!(
        matches!(&original, StateStorageAdmissionError::SccpEvidence(
        EvidencePreparationError::Admission(AllocationRefusal::Capacity { reserved_bytes, limit_bytes, .. })
    ) if *reserved_bytes == pool.limit_bytes() && *limit_bytes == pool.limit_bytes()),
        "{original:?}"
    );
    assert!(original.release_wait().is_some());
    assert!(block.retained_execution_outputs_for_test().is_err());
    assert!(block.world.consensus_evidence.is_empty());
    assert!(block.world.sccp_forgery_offences.is_empty());
    assert!(evidence_events(&block).is_empty());
    drop(occupied);
    assert_eq!(
        block.require_storage_admission(),
        Err(original),
        "release never clears the old refusal"
    );
    drop(block);
    drop(recording);
    assert_unpublished(&chain);
    let (mut retry, recording) = recorded(chain.state(), &source);
    execute(&mut retry, &source).unwrap();
    assert_success_record(&retry, &source, &evidence);
    drop(retry);
    drop(recording);
    assert_unpublished(&chain);
}

#[test]
fn signed_forgery_successful_callback_overflow_invalidates_whole_network_attempt() {
    let mut measured = None;
    for case in 0..3 {
        let bytes = match case {
            0 => 65_536,
            1 => measured.unwrap(),
            _ => measured.unwrap() - 1,
        };
        let (chain, keys, ordinary_signer) =
            active_member_chain_with_output_policy(output_policy(bytes), Some(32_768));
        let evidence = future(&chain, &keys);
        let source = signed_carrier(&chain, &keys[0], &ordinary_signer, &evidence, 1);
        let (mut block, recording) = recorded(chain.state(), &source);
        let fragments = block.committed_fragment_count();
        let gas = block.gas_used_in_block;
        let result = execute(&mut block, &source);
        if case < 2 {
            result.unwrap();
            assert_success_record(&block, &source, &evidence);
            let row = &retained(&block).rows[0];
            assert_eq!(row.completions().len(), 1);
            assert_eq!(
                block
                    .world
                    .account(chain.genesis_account())
                    .unwrap()
                    .metadata()
                    .get("forgery_callback_write"),
                Some(&Json::new(7))
            );
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            let actual = u64::try_from(norito::canonical_frame_len(row).unwrap()).unwrap();
            if let Some(previous) = measured {
                assert_eq!(actual, previous);
            }
            measured = Some(actual);
            drop(block);
        } else {
            let error = result.unwrap_err();
            assert!(
                matches!(error, ExecutionOutputAttemptError::Owner(ref message)
                if message == "SCCP forgery output failed at execution (R-EX)"),
                "{error:?}"
            );
            assert!(
                block.require_storage_admission().is_ok(),
                "completed deterministic output refusal"
            );
            assert!(
                block.retained_execution_outputs_for_test().is_err(),
                "no failed Network row or fee receipt"
            );
            assert!(matches!(
                block.execution_output_plan.as_ref(),
                Some(ExecutionOutputPlanState::Poisoned)
            ));
            assert!(block.world.consensus_evidence.is_empty());
            assert!(block.world.sccp_forgery_offences.is_empty());
            assert_eq!(store::forgery_max_generation(&block.world), None);
            assert!(evidence_events(&block).is_empty());
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(
                block.gas_used_in_block, gas,
                "no output work accounted after late R-EX"
            );
            assert!(
                block
                    .world
                    .account(chain.genesis_account())
                    .unwrap()
                    .metadata()
                    .get("forgery_callback_write")
                    .is_none()
            );
            assert_eq!(
                block
                    .world
                    .triggers
                    .data_triggers()
                    .get(&"forgery_output_callback".parse().unwrap())
                    .unwrap()
                    .repeats,
                Repeats::Exactly(1)
            );
            assert!(
                !block
                    .world
                    .external_event_buf
                    .iter()
                    .any(|event| matches!(event, EventBox::TriggerCompleted(_)))
            );
            assert!(matches!(
                block.commit(),
                Err(TransactionsBlockError::ExecutionOutputCapacity)
            ));
        }
        drop(recording);
        assert_unpublished(&chain);
    }
}
