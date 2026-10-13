//! Source-shape and unavailable-evidence regressions; no fixture forges successful finality.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::consensus::HeightContextId,
    sorafs::stream_token_authority::{
        StreamTokenAuthorityRequestV1, StreamTokenOperationV1, StreamTokenReviewedV1,
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use sorafs_manifest::signer::{
    protocol::{
        SignerOperationActionV1, SignerOperationAuditHeadV1, SignerOperationCustodyV1,
        SignerOperationIntentV1, SignerOperationReservationV1,
    },
    stream_token::SignerStreamTokenRequestV1,
};

fn key() -> KeyPair {
    KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519).unwrap()
}

fn source_fixture() -> (
    State,
    ProviderId,
    OperationRecordV1,
    MutateSorafsStreamTokenAuthority,
    TransactionEntrypoint,
) {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let provider = ProviderId::new([0x72; 32]);
    let account = AccountId::new(key().public_key().clone());
    let request = SignerStreamTokenRequestV1 {
        operation_id: [0x73; 32],
        binding_digest: [0x74; 32],
        original_custody: SignerOperationCustodyV1 {
            record_digest: [0x75; 32],
            control_state_digest: [0x76; 32],
        },
        signing_payload_digest: [0x77; 32],
        signing_payload_size: 256,
        issued_at_unix_ms: 500,
        expires_at_unix_ms: 2_000,
    };
    let reviewed = StreamTokenReviewedV1 {
        request,
        intent: SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: request.digest().unwrap(),
            previous_audit: SignerOperationAuditHeadV1 {
                sequence: 0,
                digest: [0; 32],
            },
        },
    };
    let instruction = MutateSorafsStreamTokenAuthority {
        request: StreamTokenAuthorityRequestV1 {
            network_id: *state.network_id_ref().as_bytes(),
            provider_id: provider,
            expected_control_revision: 1,
            expected_control_digest: [0x76; 32],
            action: Action::Reserve(reviewed),
        },
    };
    let signed = TransactionBuilder::new(
        *state.network_id_ref(),
        account.clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([instruction.clone()])
    .sign(key().private_key());
    let entry = TransactionEntrypoint::External(signed);
    let record = OperationRecordV1 {
        revision: 1,
        predecessor_digest: [0; 32],
        request_digest: request_digest(&instruction, &account).unwrap(),
        operation: super::super::StreamTokenNativeOperationV1 {
            provider_id: provider,
            custody_control_revision: 1,
            custody_control_digest: [0x76; 32],
            operation: StreamTokenOperationV1 {
                reviewed,
                reservation: SignerOperationReservationV1 {
                    reservation_id: [0x78; 32],
                    fence: 1,
                    expires_at_unix_ms: 1_500,
                },
                outcome: StreamTokenOutcomeV1::Reserved,
            },
            reserved_execution: StreamTokenExecutionV1 {
                height: 1,
                transaction_hash: *entry.hash().as_ref(),
                entry_index: 0,
                instruction_index: 0,
                recorded_at_unix_ms: 1_000,
                authority: account,
            },
            terminal_execution: None,
        },
    };
    (state, provider, record, instruction, entry)
}

#[test]
fn exact_signed_source_requires_direct_role11_action_digest_index_and_time() {
    let (state, _, record, instruction, entry) = source_fixture();
    let network = *state.network_id_ref().as_bytes();
    assert!(matches!(
        signed_source_matches(&record, TargetKind::Reserved, &entry, network, 1_000),
        Ok(())
    ));
    let mut changed = record.clone();
    changed.operation.reserved_execution.instruction_index = 1;
    assert!(
        matches!(signed_source_matches(&changed, TargetKind::Reserved, &entry, network, 1_000), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Execution
        ))
    );
    changed = record.clone();
    changed.request_digest = [0x99; 32];
    assert!(
        matches!(signed_source_matches(&changed, TargetKind::Reserved, &entry, network, 1_000), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Execution
        ))
    );
    assert!(
        matches!(signed_source_matches(&record, TargetKind::Reserved, &entry, network, 1_001), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Execution
        ))
    );
    assert!(
        matches!(signed_source_matches(&record, TargetKind::Terminal, &entry, network, 1_000), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::CorruptHistory
        ))
    );

    let mut other_action = instruction;
    other_action.request.expected_control_digest = [0x98; 32];
    let signed = TransactionBuilder::new(
        *state.network_id_ref(),
        record.operation.reserved_execution.authority.clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([other_action.clone()])
    .sign(key().private_key());
    let changed_entry = TransactionEntrypoint::External(signed);
    let mut changed = record;
    changed.operation.reserved_execution.transaction_hash = *changed_entry.hash().as_ref();
    changed.request_digest = request_digest(
        &other_action,
        &changed.operation.reserved_execution.authority,
    )
    .unwrap();
    assert!(matches!(signed_source_matches(
        &changed,
        TargetKind::Reserved,
        &changed_entry,
        network,
        1_000
    ), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::Execution
    )));
}

#[test]
fn historical_budget_accepts_exact_edge_and_rejects_one_more() {
    assert_eq!(
        bound_history_span(1, STREAM_TOKEN_HISTORY_MAX_BLOCKS_V1),
        Ok(())
    );
    assert_eq!(
        bound_history_span(1, STREAM_TOKEN_HISTORY_MAX_BLOCKS_V1 + 1),
        Err(Error::CheckUnavailable)
    );
    assert_eq!(bound_history_span(2, 1), Err(Error::Finality));
    let mut total = STREAM_TOKEN_HISTORY_FINALITY_MAX_BYTES_V1 - 1;
    assert_eq!(charge_finality_len(&mut total, 1), Ok(()));
    assert_eq!(total, STREAM_TOKEN_HISTORY_FINALITY_MAX_BYTES_V1);
    assert_eq!(
        charge_finality_len(&mut total, 1),
        Err(Error::CheckUnavailable)
    );
}

#[test]
fn expiry_source_keeps_original_slot_under_new_current_custody() {
    let (state, _, original, mut instruction, _) = source_fixture();
    let mut terminal = original.clone();
    terminal.revision = 2;
    terminal.predecessor_digest = super::super::record_digest(&original).unwrap();
    terminal.operation.operation.outcome = StreamTokenOutcomeV1::Expired;
    instruction.request.expected_control_revision = 2;
    instruction.request.expected_control_digest = [0xa1; 32];
    instruction.request.action = Action::Expire(
        iroha_data_model::sorafs::stream_token_authority::StreamTokenExpireV1 {
            operation_id: original.operation.operation.reviewed.request.operation_id,
            reservation: original.operation.operation.reservation,
        },
    );
    let signed = TransactionBuilder::new(
        *state.network_id_ref(),
        original.operation.reserved_execution.authority.clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([instruction.clone()])
    .sign(key().private_key());
    let entry = TransactionEntrypoint::External(signed);
    terminal.request_digest = request_digest(
        &instruction,
        &original.operation.reserved_execution.authority,
    )
    .unwrap();
    let mut execution = original.operation.reserved_execution.clone();
    execution.height = 2;
    execution.transaction_hash = *entry.hash().as_ref();
    execution.recorded_at_unix_ms = 1_100;
    terminal.operation.terminal_execution = Some(execution);
    assert!(matches!(
        signed_source_matches(
            &terminal,
            TargetKind::Terminal,
            &entry,
            *state.network_id_ref().as_bytes(),
            1_100,
        ),
        Ok(())
    ));
    // A certified block at the terminal's height that does not carry the terminal entry.
    let mut chain = crate::query::signer_check::fixture::chain(World::new());
    chain.commit_at(1_050, Vec::new());
    let view = chain.state().view();
    let target = CertifiedChain::new(&view)
        .unwrap()
        .certified(2)
        .expect("certified height 2");
    assert!(
        matches!(authenticate_target(&view, &terminal, TargetKind::Terminal, &target), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Execution
        ))
    );
    // A target of another height than the recorded execution.
    let genesis = CertifiedChain::new(&view).unwrap().certified(1).unwrap();
    assert!(
        matches!(authenticate_target(&view, &terminal, TargetKind::Terminal, &genesis), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Execution
        ))
    );
}

#[test]
fn historical_reader_requires_retained_row_and_committed_finality() {
    let (state, provider, record, _, _) = source_fixture();
    let floor = StreamTokenFinalityFloorV1 {
        height: 1,
        block_hash: [0x81; 32],
        context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
            b"pinned role11 floor",
        ))),
    };
    assert!(matches!(authenticate_stream_token_history_to_floor_v1(
        &state.view(),
        provider,
        record.operation.operation.reviewed.request.operation_id,
        floor,
    )
    .err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::Conflict
    )));
    let mut world = World::new();
    let id = record.operation.operation.reviewed.request.operation_id;
    world.smart_contract_state.insert(
        super::super::record_key(provider, 1),
        super::super::encode(&record).unwrap(),
    );
    world.smart_contract_state.insert(
        super::super::admission_key(provider, id),
        super::super::encode(&1_u64).unwrap(),
    );
    world.smart_contract_state.insert(
        super::super::slot_key(provider, id),
        super::super::encode(&1_u64).unwrap(),
    );
    world.smart_contract_state.insert(
        super::super::head_key(provider),
        super::super::encode(&super::super::OperationHeadV1 {
            revision: 1,
            digest: super::super::record_digest(&record).unwrap(),
            fence: 1,
            audit: record.operation.operation.reviewed.intent.previous_audit,
            active_operation: Some(id),
            total_admissions: 1,
        })
        .unwrap(),
    );
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    assert!(
        matches!(authenticate_stream_token_history_to_floor_v1(&state.view(), provider, id, floor).err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            Error::Finality
        ))
    );
}

#[test]
fn actual_signed_history_source_preserves_local_codec_refusal() {
    let (state, _, record, _, entry) = source_fixture();
    let network = *state.network_id_ref().as_bytes();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failed = norito::with_decode_limits_scope(zero, || {
        signed_source_matches(&record, TargetKind::Reserved, &entry, network, 1_000)
    });
    assert!(
        matches!(
            failed,
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
        ),
        "original codec refusal must not become successful proof rejection: {failed:?}"
    );
    assert!(matches!(
        signed_source_matches(&record, TargetKind::Reserved, &entry, network, 1_000),
        Ok(())
    ));
}
