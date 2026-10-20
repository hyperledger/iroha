// Typed-output event projection controls; these fixtures do not claim execution or finality.
use super::*;
use iroha_data_model::{
    block::{
        BlockPayload, BlockResult,
        execution_output::{
            ExecutionOutputV1, InvocationCompletionV1, NetworkExecutionOutputV1,
            PipelineEventPositionV1, PipelineExecutionOutputV1, PipelineInvocationV1,
            TimeInvocationV1, TriggerUseV1,
        },
        output_budget::ExecutionOutputLimits,
    },
    events::{
        time::{TimeEvent, TimeInterval},
        trigger_completed::TriggerCompletedOutcome,
    },
    transaction::{
        TransactionResult,
        error::TransactionRejectionReason,
        signed::{
            ExecutionStep, SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, TransactionBuilder,
            compute_sealed_transaction_commitment,
        },
    },
    trigger::DataTriggerStep,
};
use norito::codec::DecodeAll as _;

#[test]
fn local_storage_recovery_emits_no_block_rejection() {
    use crate::state::{
        BlockHashAdmissionError, LaneLifecycleError, MembershipAdmissionError,
        MergeLedgerCommitError,
    };
    use iroha_allocation::AllocationRefusal;
    use iroha_data_model::block::error::BlockRejectionReason;

    let header = BlockHeader::new(
        nonzero_ext::nonzero!(2_u64),
        Some(HashOf::from_untyped_unchecked(Hash::prehashed(
            [7; Hash::LENGTH],
        ))),
        None,
        10,
        0,
    );
    let diagnostic = "retained drain evidence requires local recovery";
    let local_errors = [
        BlockValidationError::from_autoscale_lifecycle_error(LaneLifecycleError::Storage(
            diagnostic.to_owned(),
        )),
        BlockValidationError::from_certified_merge_stage_error(
            MergeLedgerCommitError::LocalDrainObservation(Box::new(
                MergeLedgerCommitError::ExecutionMarkerConflict(diagnostic.to_owned()),
            )),
        ),
        BlockValidationError::from_certified_merge_stage_error(
            MergeLedgerCommitError::MembershipAdmission(MembershipAdmissionError::Capacity(
                AllocationRefusal::DemandOverflow,
            )),
        ),
        BlockValidationError::from_certified_merge_stage_error(
            MergeLedgerCommitError::BlockHashAdmission(BlockHashAdmissionError::ReadOnly),
        ),
        BlockValidationError::EvidencePreparation(
            crate::state::EvidencePreparationError::Admission(AllocationRefusal::DemandOverflow),
        ),
    ];
    let mut events = Vec::new();
    for error in local_errors {
        assert_eq!(map_block_err_to_reason(&error), None);
        emit_block_rejection(header, &error, |event| events.push(event));
        assert!(
            events.is_empty(),
            "a local refusal must not publish rejection"
        );
    }

    let deterministic = BlockValidationError::from_certified_merge_stage_error(
        MergeLedgerCommitError::ExecutionBatchInvalid(diagnostic.to_owned()),
    );
    emit_block_rejection(header, &deterministic, |event| events.push(event));
    assert_eq!(events.len(), 1);
    let PipelineEventBox::Block(event) = &events[0] else {
        panic!("deterministic invalidity must emit the exact block rejection");
    };
    assert_eq!(event.header, header);
    assert_eq!(
        event.status,
        BlockStatus::Rejected(BlockRejectionReason::TransactionValidationFailed)
    );
}

#[test]
fn npos_local_admission_keeps_all_resource_refusals_out_of_rejection() {
    use crate::state::{
        BlockHashAdmissionError, MembershipAdmissionError, StateAdmissionError,
        StateStorageAdmissionError,
    };
    use concread::bptree::PlanningError;
    use iroha_allocation::AllocationRefusal;
    use mv::storage::AdmittedStorageError;

    let refusals = [
        StateAdmissionError::Storage(StateStorageAdmissionError::World(
            AdmittedStorageError::Planning(PlanningError::Overflow),
        )),
        StateAdmissionError::History(BlockHashAdmissionError::ReadOnly),
        StateAdmissionError::Membership(MembershipAdmissionError::Capacity(
            AllocationRefusal::DemandOverflow,
        )),
    ];
    for refusal in refusals {
        let error = BlockValidationError::from_npos_application_error(
            eyre::Report::new(refusal),
            "NPoS preflight",
        );
        assert!(map_block_err_to_reason(&error).is_none());
    }
}

fn event_signed_transaction(network_seed: u8) -> (SignedTransaction, iroha_crypto::KeyPair) {
    let keypair = iroha_crypto::KeyPair::try_random().expect("generate event fixture signer");
    let authority = iroha_data_model::account::AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new(
        deterministic_test_network_id(network_seed),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    (tx, keypair)
}

fn event_network_output(
    index: u32,
    error: Option<TransactionRejectionReason>,
) -> ExecutionOutputV1 {
    ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: index,
        result: TransactionResult::new(error.map_or_else(|| Ok(Vec::new()), Err)),
        completions: Vec::new(),
    })
}

fn event_fixture_block(
    entries: Vec<TransactionEntrypoint>,
    routes: Option<Vec<ExternalExecutionContext>>,
    outputs: Vec<ExecutionOutputV1>,
    keypair: &iroha_crypto::KeyPair,
) -> SignedBlock {
    let mut builder = iroha_data_model::block::builder::BlockBuilder::new(BlockHeader::new(
        nonzero_ext::nonzero!(1_u64),
        None,
        None,
        0,
        0,
    ));
    for entry in entries {
        match entry {
            TransactionEntrypoint::External(tx) => {
                builder.push_transaction(tx);
            }
            TransactionEntrypoint::AnonymousBallot(envelope) => {
                builder.push_anonymous_ballot(envelope);
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                builder.push_sealed_transaction_commitment(commitment);
            }
            TransactionEntrypoint::SealedReveal(reveal) => {
                builder.push_sealed_transaction_reveal(reveal);
            }
        }
    }
    builder.set_execution_context(routes.map(BlockExecutionContextBundle::new));
    let mut block = builder.build_with_signature(0, keypair.private_key());
    let proposal = block
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    let fragments = u64::try_from(
        outputs
            .iter()
            .filter(|output| output.result().is_ok())
            .count(),
    )
    .unwrap();
    block
        .set_execution_outputs(
            outputs,
            fragments,
            std::collections::BTreeMap::default(),
            Vec::new(),
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &ExecutionOutputLimits {
                max_outputs: 16,
                max_output_bytes: 65_536,
                max_total_output_bytes: 262_144,
                max_executed_wire_bytes: 1_048_576,
            },
        )
        .expect("complete fixture outputs must satisfy their explicit finite policy");
    assert_eq!(
        block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
        proposal
    );
    block
        .signatures()
        .next()
        .unwrap()
        .signature()
        .verify_hash(keypair.public_key(), block.hash())
        .unwrap();
    block
}

fn peer_received_valid_block_with_committed_route(
    network_seed: u8,
    committed_route: Option<crate::queue::RoutingDecision>,
) -> (ValidBlock, HashOf<SignedTransaction>) {
    let (tx, keypair) = event_signed_transaction(network_seed);
    let hash = tx.hash();
    let entry_hash = tx.hash_as_entrypoint();
    let routes = committed_route.map(|route| {
        vec![ExternalExecutionContext::new(
            entry_hash,
            route.lane_id,
            route.dataspace_id,
        )]
    });
    let block = event_fixture_block(
        vec![TransactionEntrypoint::External(tx)],
        routes,
        vec![event_network_output(0, None)],
        &keypair,
    );
    (ValidBlock::new_unverified_for_tests(block), hash)
}

fn only_transaction_event(events: &[PipelineEventBox]) -> &TransactionEvent {
    let mut events = events.iter().filter_map(|event| match event {
        PipelineEventBox::Transaction(event) => Some(event),
        _ => None,
    });
    let event = events.next().expect("one transaction event");
    assert!(
        events.next().is_none(),
        "internal outputs are not Network transactions"
    );
    event
}

fn internal_event_outputs() -> Vec<ExecutionOutputV1> {
    let pipeline = TriggerUseV1 {
        trigger_id: "event_pipeline".parse().unwrap(),
        registered_at_height: 0,
        action_hash: iroha_crypto::Hash::new(b"event pipeline action"),
    };
    let time = TriggerUseV1 {
        trigger_id: "event_time".parse().unwrap(),
        registered_at_height: 0,
        action_hash: iroha_crypto::Hash::new(b"event time action"),
    };
    vec![
        ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
            result: TransactionResult::new(Ok(vec![DataTriggerStep {
                id: pipeline.trigger_id.clone(),
                instructions: ExecutionStep(Vec::new().into()),
            }])),
            completions: vec![InvocationCompletionV1 {
                callback_index: 0,
                trigger_id: pipeline.trigger_id.clone(),
                outcome: TriggerCompletedOutcome::Success,
            }],
            invocation: PipelineInvocationV1 {
                event: PipelineEventPositionV1::BlockApproved,
                candidate_index: 0,
                trigger: pipeline,
            },
            failure_root: None,
        }),
        ExecutionOutputV1::time_output_limit_rejection(TimeInvocationV1 {
            schedule_index: 0,
            event: TimeEvent {
                interval: TimeInterval {
                    since_ms: 0,
                    length_ms: 1,
                },
            },
            trigger: time,
        }),
    ]
}

#[test]
fn valid_block_transaction_events_use_entrypoint_index_after_sealed_commitment() {
    let (rejected_tx, keypair) = event_signed_transaction(0x05);
    let network_id = deterministic_test_network_id(0x05);
    let signed_hash = rejected_tx.hash();
    let commitment = SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload {
            network_id,
            authority: rejected_tx.authority().clone(),
            commitment: compute_sealed_transaction_commitment(
                &network_id,
                &rejected_tx,
                [0x59; 32],
                5,
            ),
            reveal_after_height: 2,
            reveal_deadline_height: 5,
            nonce: None,
        },
        keypair.private_key(),
    );
    let entries = vec![
        TransactionEntrypoint::SealedCommitment(commitment),
        TransactionEntrypoint::External(rejected_tx),
    ];
    let route = crate::queue::RoutingDecision::new(LaneId::new(7), DataSpaceId::new(70));
    let routes = vec![
        ExternalExecutionContext::new(entries[0].hash(), LaneId::new(3), DataSpaceId::new(30)),
        ExternalExecutionContext::new(entries[1].hash(), route.lane_id, route.dataspace_id),
    ];
    let reason = TransactionRejectionReason::Validation(
        iroha_data_model::ValidationFail::NotPermitted("failed event fixture".to_owned()),
    );
    let block = event_fixture_block(
        entries,
        Some(routes),
        vec![
            event_network_output(0, None),
            event_network_output(1, Some(reason.clone())),
        ],
        &keypair,
    );
    let valid = ValidBlock::new_unverified_for_tests(block);
    let events = valid.produce_events().collect::<Vec<_>>();
    let event = only_transaction_event(&events);
    assert_eq!(event.hash, signed_hash);
    assert_eq!(event.status, TransactionStatus::Rejected(Box::new(reason)));
    assert_eq!(event.lane_id, route.lane_id);
    assert_eq!(event.dataspace_id, route.dataspace_id);
}

#[test]
fn peer_received_block_events_use_committed_route_without_local_routing_state() {
    let route = crate::queue::RoutingDecision::new(LaneId::new(7), DataSpaceId::new(70));
    let (valid, hash) = peer_received_valid_block_with_committed_route(0x06, Some(route));
    let events = valid.produce_events().collect::<Vec<_>>();
    let event = only_transaction_event(&events);
    assert_eq!(event.hash, hash);
    assert_eq!(event.status, TransactionStatus::Approved);
    assert_eq!(event.lane_id, route.lane_id);
    assert_eq!(event.dataspace_id, route.dataspace_id);
}

#[test]
fn genesis_transaction_events_fail_closed_without_committed_route() {
    let (valid, _) = peer_received_valid_block_with_committed_route(0x08, None);
    assert!(valid.as_ref().header().is_genesis());
    let events = valid.produce_events().collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, PipelineEventBox::Transaction(_))),
        "a validated block must not fabricate a default route when its committed route is missing"
    );
}

#[test]
fn reveal_event_joins_outer_source_and_preserves_inner_signed_identity() {
    let (tx, keypair) = event_signed_transaction(0x09);
    let hash = tx.hash();
    let entry = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        iroha_crypto::Hash::new(b"event sealed commitment"),
        tx,
        [0xA5; 32],
    ));
    let route = crate::queue::RoutingDecision::new(LaneId::new(9), DataSpaceId::new(90));
    let context = ExternalExecutionContext::new(entry.hash(), route.lane_id, route.dataspace_id);
    let mut outputs = vec![event_network_output(0, None)];
    outputs.extend(internal_event_outputs());
    let block = event_fixture_block(vec![entry], Some(vec![context]), outputs, &keypair);
    assert_eq!(block.network_entrypoint_count(), 1);
    assert_eq!(block.execution_outputs().len(), 3);
    let valid = ValidBlock::new_unverified_for_tests(block);
    let events = valid.produce_events().collect::<Vec<_>>();
    let event = only_transaction_event(&events);
    assert_eq!(event.hash, hash);
    assert_eq!(event.status, TransactionStatus::Approved);
    assert_eq!(event.lane_id, route.lane_id);
    assert_eq!(event.dataspace_id, route.dataspace_id);
    assert_eq!(
        events.len(),
        2,
        "only the Network event and BlockApproved are projected"
    );
}

#[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
#[norito_schema(name = "iroha_core::block::event::tests::MutableEventBlockWire")]
struct MutableEventBlockWire {
    signatures: iroha_data_model::block::BlockSignatures,
    payload: BlockPayload,
    result: Option<BlockResult>,
    commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
}

fn mutate_event_body(
    block: &SignedBlock,
    mutate: impl FnOnce(&mut MutableEventBlockWire),
) -> SignedBlock {
    let mut wire = MutableEventBlockWire::decode_all(&mut block.encode().as_slice()).unwrap();
    mutate(&mut wire);
    SignedBlock::decode_all(&mut wire.encode().as_slice()).unwrap()
}

#[test]
fn events_validate_the_complete_body_before_projecting_any_network_status() {
    let (tx, keypair) = event_signed_transaction(0x0A);
    let route = ExternalExecutionContext::new(
        tx.hash_as_entrypoint(),
        LaneId::new(7),
        DataSpaceId::new(70),
    );
    let mut outputs = vec![event_network_output(0, None)];
    outputs.extend(internal_event_outputs());
    let block = event_fixture_block(
        vec![TransactionEntrypoint::External(tx)],
        Some(vec![route]),
        outputs,
        &keypair,
    );
    for mutation in 0..6 {
        let malformed = mutate_event_body(&block, |wire| match mutation {
            0 => wire.result = None,
            1 => {
                wire.result.as_mut().unwrap().outputs.remove(0);
            }
            2 => {
                let result = wire.result.as_mut().unwrap();
                let ExecutionOutputV1::Network(row) = &mut result.outputs[0] else {
                    unreachable!()
                };
                row.input_index = 1;
                result.output_merkle = result.outputs.iter().map(HashOf::new).collect();
            }
            3 => wire.result.as_mut().unwrap().output_merkle = iroha_crypto::MerkleTree::default(),
            4 => wire.payload.header.merkle_root = None,
            5 => {
                let ExecutionOutputV1::Pipeline(row) =
                    &mut wire.result.as_mut().unwrap().outputs[1]
                else {
                    unreachable!()
                };
                row.invocation.trigger.action_hash =
                    iroha_crypto::Hash::new(b"foreign internal action");
            }
            _ => unreachable!(),
        });
        assert!(malformed.validate_output_merkle_cache().is_err());
        let valid = ValidBlock::new_unverified_for_tests(malformed);
        assert_eq!(
            valid.produce_events().count(),
            0,
            "mutation {mutation} cannot expose a partial approved body"
        );
    }
}

#[test]
fn transaction_event_refuses_a_route_bound_to_the_inner_reveal_hash() {
    let (tx, keypair) = event_signed_transaction(0x0B);
    let wrong_hash = tx.hash_as_entrypoint();
    let entry = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        iroha_crypto::Hash::new(b"outer event source"),
        tx,
        [0xB5; 32],
    ));
    assert_ne!(entry.hash(), wrong_hash);
    let block = event_fixture_block(
        vec![entry],
        Some(vec![ExternalExecutionContext::new(
            wrong_hash,
            LaneId::new(9),
            DataSpaceId::new(90),
        )]),
        vec![event_network_output(0, None)],
        &keypair,
    );
    let valid = ValidBlock::new_unverified_for_tests(block);
    assert!(
        valid
            .produce_events()
            .all(|event| !matches!(event, PipelineEventBox::Transaction(_))),
        "the inner signed identity cannot authenticate an outer reveal route"
    );
}

#[test]
fn original_npos_lifecycle_read_refusal_cannot_emit_block_rejection() {
    use crate::{
        state::WorldReadOnly,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    let mut config = TestChainConfig::new(crate::state::World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    let chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    let policy = view.world().sumeragi_npos_parameters().unwrap();
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || view.world().sumeragi_npos_parameters(),
    )
    .unwrap_err();
    let crate::execution_attempt::ExecutionAttemptError::Deferred(expected) = &error else {
        panic!("original decoder must refuse: {error:?}");
    };
    let expected_reason = expected.reason();
    let expected_phase = expected.phase();
    let original_observation = expected
        .decode_refusal()
        .expect("actual NPoS JSON owner")
        .clone();
    assert!(expected.allocation_refusal().is_none());
    assert!(expected.verification_refusal().is_none());
    let boundary = BlockValidationError::from_autoscale_lifecycle_error(
        crate::state::LaneLifecycleError::NposPolicy(error),
    );
    assert!(
        matches!(&boundary, BlockValidationError::ExecutionDeferred(actual) if actual.reason() == expected_reason
            && actual.decode_refusal() == Some(&original_observation)
            && actual.allocation_refusal().is_none()
            && actual.verification_refusal().is_none()
            && actual.phase() == expected_phase),
        "local policy refusal was changed: {boundary:?}"
    );
    assert!(map_block_err_to_reason(&boundary).is_none());
    let mut events = Vec::new();
    emit_block_rejection(chain.genesis().header(), &boundary, |event| {
        events.push(event)
    });
    assert!(events.is_empty());
    assert_eq!(view.world().sumeragi_npos_parameters().unwrap(), policy);
}

#[test]
fn canonical_json_allocation_report_conversion_preserves_reported_size_without_pool() {
    // This is a precise conversion control, not physical allocator-denial evidence.
    // JSON's size-less allocator report uses the canonical zero unavailable-size marker.
    for (json_error, bytes) in [
        (norito::json::Error::AllocationFailed, 0),
        (
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::AllocationFailed { bytes: 37 },
            ),
            37,
        ),
    ] {
        let captured =
            norito::core::classify_decode_attempt(|| Err::<(), _>(json_error.into_core_error()))
                .unwrap_err();
        let attempt = crate::execution_attempt::canonical_decode_attempt_error(captured, |_| ());
        let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = attempt else {
            panic!("a canonical allocator report must not become malformed JSON");
        };
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::AllocationUnavailable
        );
        assert_eq!(
            original.decode_refusal().unwrap().allocation_bytes(),
            Some(bytes)
        );
        assert!(original.allocation_refusal().is_none());
        assert!(original.verification_refusal().is_none());
        assert!(original.phase().is_none());
    }
}
