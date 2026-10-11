//! Structural display projections retain typed joins and sealed outer identity.
//! Exact storage/finality and byte admission are exercised by Core's reader tests.
use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::{builder::BlockBuilder, execution_output::*, output_budget::ExecutionOutputLimits},
    events::{
        time::{TimeEvent, TimeInterval},
        trigger_completed::TriggerCompletedOutcome,
    },
    transaction::{
        FeePaymentIntent, TransactionBuilder,
        signed::{ExecutionStep, SealedTransactionReveal},
    },
    trigger::DataTriggerStep,
};

/// Signer, network and invoked contract of the carrier's sealed contract call.
fn carrier_identity() -> (
    KeyPair,
    iroha_data_model::NetworkId,
    iroha_data_model::smart_contract::ContractAddress,
) {
    let key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519).unwrap();
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"routing query fixture"),
    ));
    let contract = iroha_data_model::smart_contract::ContractAddress::derive(
        &network,
        &AccountId::new(key.public_key().clone()),
        1,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    (key, network, contract)
}

fn carrier() -> SignedBlock {
    carrier_with_context(None)
}

fn carrier_with_context(
    context: Option<iroha_data_model::block::BlockExecutionContextBundle>,
) -> SignedBlock {
    let (key, network, contract) = carrier_identity();
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        "contract_address".parse().unwrap(),
        iroha_primitives::json::Json::new(contract.to_string()),
    );
    metadata.insert(
        "contract_entrypoint".parse().unwrap(),
        iroha_primitives::json::Json::new("submit"),
    );
    let mut tx = TransactionBuilder::new(
        network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(Duration::from_millis(900));
    let signed = tx
        .with_metadata(metadata)
        .with_executable(Executable::ContractCall(
            iroha_data_model::transaction::executable::ContractInvocation {
                contract_address: contract,
                expected_code_hash: Hash::new(b"routing contract"),
                entrypoint: "submit".to_owned(),
                arguments: None,
            },
        ))
        .sign(key.private_key());
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        Some(HashOf::from_untyped_unchecked(Hash::new(b"routing parent"))),
        None,
        1000,
        0,
    );
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(context);
    builder.push_sealed_transaction_reveal(SealedTransactionReveal::new(
        Hash::new(b"routing commitment"),
        signed,
        [0x36; 32],
    ));
    let mut block = builder.build_with_signature(0, key.private_key());
    let id: iroha_data_model::trigger::TriggerId = "clock".parse().unwrap();
    let rows = vec![
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: TransactionResult::new(Err(
                iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                    iroha_data_model::ValidationFail::NotPermitted("business rejection".into()),
                ),
            )),
            completions: vec![],
        }),
        ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: TimeInvocationV1 {
                schedule_index: 0,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 999,
                        length_ms: 1,
                    },
                },
                trigger: TriggerUseV1 {
                    trigger_id: id.clone(),
                    registered_at_height: 1,
                    action_hash: Hash::new(b"structural clock action"),
                },
            },
            result: TransactionResult::new(Ok(vec![DataTriggerStep {
                id: id.clone(),
                instructions: ExecutionStep(iroha_primitives::const_vec::ConstVec::new_empty()),
            }])),
            failure_root: None,
            completions: vec![InvocationCompletionV1 {
                callback_index: 0,
                trigger_id: id,
                outcome: TriggerCompletedOutcome::Success,
            }],
        }),
    ];
    block
        .set_execution_outputs(
            rows,
            1,
            Default::default(),
            vec![],
            Default::default(),
            Default::default(),
            &ExecutionOutputLimits {
                max_outputs: 4,
                max_output_bytes: 65536,
                max_total_output_bytes: 262144,
                max_executed_wire_bytes: 1048576,
            },
        )
        .unwrap();
    block.validate_output_merkle_cache().unwrap();
    block
}

#[test]
fn borrowed_history_projection_matches_real_typed_proof_dto_and_sealed_identity() {
    let block = carrier();
    let source = block.network_entrypoint_at(0).unwrap();
    let (_, output) = block.network_output_at(0).unwrap();
    let borrowed = BorrowedNetworkTransaction {
        entrypoint: source,
        entrypoint_hash: source.hash(),
        result: &output.result,
        block_hash: block.hash(),
    };
    let owned = iroha_data_model::query::CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: source.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint: source.clone(),
        output_hash: HashOf::new(&block.execution_outputs()[0]),
        output_proof: block.output_proof(0).unwrap(),
        output: block.execution_outputs()[0].clone(),
    };
    assert!(owned.verify_inclusion_in_block(&block));
    assert_eq!(
        tx_field_value(&borrowed, "entrypoint_kind"),
        Some("sealed_reveal".into())
    );
    for field in [
        "authority",
        "timestamp_ms",
        "entrypoint_hash",
        "result_ok",
        "metadata.contract_address",
    ] {
        assert_eq!(
            tx_field_value(&borrowed, field),
            tx_field_value(&owned, field)
        );
    }
    let a = contract_activity_projection_from_tx(2, &borrowed).unwrap();
    let b = contract_activity_projection_from_tx(2, &owned).unwrap();
    assert_eq!(a.entrypoint_hash, b.entrypoint_hash);
    assert_eq!(a.contract_address, carrier_identity().2.to_string());
    assert_eq!(a.contract_entrypoint, "submit");
    assert!(!a.result_ok);
    assert!(
        output.result.contract_events().is_empty(),
        "call metadata never becomes an emitted event"
    );
    let calls = external_signed_transaction_results(&block).collect::<Vec<_>>();
    assert_eq!(block.execution_outputs().len(), 2);
    assert_eq!(
        calls.len(),
        1,
        "the internal Time output has no Network transaction position"
    );
    assert_eq!(calls[0].0, 0);
    assert_eq!(calls[0].1, source.hash());
    assert_ne!(calls[0].1, calls[0].2.hash_as_entrypoint());
    assert!(calls[0].3.is_err());
    assert!(external_signed_transaction_result_at(&block, 1).is_none());
}

#[test]
fn history_range_missing_canonical_prefix_returns_no_projected_rows() {
    let state = CoreState::new_for_testing(
        iroha_core::state::World::default(),
        Kura::blank_kura_for_testing(),
        iroha_core::query::store::LiveQueryStore::start_test(),
    );
    let mut visited = 0;
    let result = project_finalized_network_range(
        &state,
        1,
        1,
        false,
        HashOf::from_untyped_unchecked(Hash::new(b"missing tip")),
        |_, _| {
            visited += 1;
            vec![()]
        },
    );
    assert!(result.is_err());
    assert_eq!(visited, 0);
    assert!(
        project_finalized_network_range(
            &state,
            1,
            0,
            true,
            HashOf::from_untyped_unchecked(Hash::new(b"unused empty tip")),
            |_, _| vec![()]
        )
        .unwrap()
        .is_empty()
    );
    check_history_retention(2, 2).unwrap();
    assert!(check_history_retention(3, 2).is_err());
}

#[test]
fn history_cache_anchor_requires_the_captured_tip_identity() {
    let hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"captured cache tip"));
    assert_eq!(history_cache_anchor(0, &None).unwrap(), None);
    assert!(history_cache_anchor(0, &Some(hash.to_string())).is_err());
    assert!(history_cache_anchor(1, &None).is_err());
    assert!(history_cache_anchor(1, &Some("bad".into())).is_err());
    assert_eq!(
        history_cache_anchor(1, &Some(hash.to_string())).unwrap(),
        Some(hash)
    );
    let state = CoreState::new_for_testing(
        iroha_core::state::World::default(),
        Kura::blank_kura_for_testing(),
        iroha_core::query::store::LiveQueryStore::start_test(),
    );
    assert!(require_history_anchor(&state, 1, hash).is_err());
}

#[test]
fn visibility_refusal_is_sticky_until_consuming_finish() {
    let state = Arc::new(CoreState::new_for_testing(
        iroha_core::state::World::default(),
        Kura::blank_kura_for_testing(),
        iroha_core::query::store::LiveQueryStore::start_test(),
    ));
    let restricted = DataspaceReadVisibility::new(BTreeSet::new(), false);
    let source = HashOf::from_untyped_unchecked(Hash::new(b"unavailable source"));
    let owner = HistoryVisibilityReads::new(Arc::clone(&state));
    assert!(!owner.allows(&restricted, 1, None, source));
    assert!(!owner.allows(&restricted, 1, None, source));
    assert!(owner.reads.lock().unwrap().block.is_none());
    // A later globally visible row cannot erase the earlier admission refusal.
    assert!(owner.allows(&DataspaceReadVisibility::all_for_tests(), 1, None, source));
    assert!(owner.finish().is_err());
    HistoryVisibilityReads::new(state).finish().unwrap();
}

fn emission_fixture(
    dataspace: DataSpaceId,
) -> iroha_data_model::smart_contract::event::ContractEmissionV1 {
    use iroha_data_model::smart_contract::{entrypoint::*, event::*};
    let (key, network, _) = carrier_identity();
    let caller = AccountId::new(key.public_key().clone());
    let payload_type = EntrypointValueTypeV1 {
        nodes: vec![
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: "Fixture::Accepted".into(),
                fields: vec!["active".into()],
            }),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
        ],
    };
    let payload = EntrypointReturnRecordV1 {
        schema_hash: entrypoint_return_schema_hash_v1(
            &norito::encode_canonical(&payload_type).unwrap(),
        ),
        atoms: vec![EntrypointValueAtomV1::Bool(true)],
    };
    ContractEmissionV1 {
        contract: iroha_data_model::smart_contract::ContractAddress::derive(
            &network, &caller, 2, dataspace,
        )
        .unwrap(),
        code_hash: Hash::new(b"actual immutable event artifact"),
        entrypoint: 1,
        event: 0,
        caller,
        definition: ContractEventDescriptorV1 {
            name: "Accepted".parse().unwrap(),
            payload_type,
        },
        payload,
    }
}

#[test]
fn native_emission_visibility_preserves_emitter_and_network_callback_route_scopes() {
    use iroha_data_model::block::{
        BlockExecutionContextBundle, ExternalExecutionContext, ExternalExecutionRouteLeg,
        ExternalExecutionRouteRole,
    };
    let block = carrier();
    let visible = DataSpaceId::new(7);
    let hidden = DataSpaceId::new(8);
    let reader = DataspaceReadVisibility::new(BTreeSet::from([visible]), false);
    let emission = emission_fixture(visible);
    let time = block.execution_outputs()[1].clone();
    assert!(native_contract_emission_source_is_visible(
        &reader, &block, &time, &emission
    ));
    assert!(!native_contract_emission_source_is_visible(
        &reader,
        &block,
        &time,
        &emission_fixture(hidden)
    ));
    let ExecutionOutputV1::Time(time) = time else {
        unreachable!()
    };
    let mut pipeline = PipelineExecutionOutputV1 {
        invocation: PipelineInvocationV1 {
            event: PipelineEventPositionV1::BlockApproved,
            candidate_index: 0,
            trigger: time.invocation.trigger,
        },
        result: time.result,
        failure_root: None,
        completions: time.completions,
    };
    assert!(native_contract_emission_source_is_visible(
        &reader,
        &block,
        &ExecutionOutputV1::Pipeline(pipeline.clone()),
        &emission
    ));
    assert!(!native_contract_emission_source_is_visible(
        &reader,
        &block,
        &ExecutionOutputV1::Pipeline(pipeline.clone()),
        &emission_fixture(hidden)
    ));
    pipeline.invocation.event = PipelineEventPositionV1::Network(0);
    let entrypoint = block.network_entrypoint_at(0).unwrap().hash();
    // Bind each route before installing outputs: changing the durable context
    // correctly invalidates all results attached to the previous block identity.
    let block = carrier_with_context(Some(BlockExecutionContextBundle::new(vec![
        ExternalExecutionContext::new(entrypoint, LaneId::new(7), visible),
    ])));
    assert!(native_contract_emission_source_is_visible(
        &reader,
        &block,
        &ExecutionOutputV1::Pipeline(pipeline.clone()),
        &emission
    ));
    assert!(native_contract_emission_source_is_visible(
        &reader,
        &block,
        &block.execution_outputs()[0],
        &emission
    ));
    let block = carrier_with_context(Some(BlockExecutionContextBundle::new(vec![
        ExternalExecutionContext::with_routing_plan(
            entrypoint,
            LaneId::new(7),
            visible,
            Hash::new(b"mixed emission root route"),
            vec![
                ExternalExecutionRouteLeg::new(
                    LaneId::new(7),
                    visible,
                    ExternalExecutionRouteRole::Coordinator,
                ),
                ExternalExecutionRouteLeg::new(
                    LaneId::new(8),
                    hidden,
                    ExternalExecutionRouteRole::Participant,
                ),
            ],
        ),
    ])));
    assert!(!native_contract_emission_source_is_visible(
        &reader,
        &block,
        &ExecutionOutputV1::Pipeline(pipeline),
        &emission
    ));
    assert!(!native_contract_emission_source_is_visible(
        &reader,
        &block,
        &block.execution_outputs()[0],
        &emission
    ));
}

#[test]
fn native_emission_projection_binds_full_historical_record_and_coordinates() {
    use iroha_data_model::smart_contract::event::ContractEmissionsV1;
    let mut block = carrier();
    let mut rows = block.execution_outputs().to_vec();
    let first = emission_fixture(DataSpaceId::new(7));
    let mut second = first.clone();
    second.event = 1;
    second.entrypoint = 2;
    let ExecutionOutputV1::Time(time) = &mut rows[1] else {
        unreachable!()
    };
    time.result
        .set_contract_events(ContractEmissionsV1::from_untrusted(vec![
            first.clone(),
            second,
        ]));
    block
        .set_execution_outputs(
            rows,
            1,
            Default::default(),
            vec![],
            Default::default(),
            Default::default(),
            &ExecutionOutputLimits {
                max_outputs: 4,
                max_output_bytes: 65536,
                max_total_output_bytes: 262144,
                max_executed_wire_bytes: 1048576,
            },
        )
        .unwrap();
    let output = &block.execution_outputs()[1];
    let hash = output.execution_call_hash(block.hash(), &block).unwrap();
    let mut projection =
        contract_event_projection(2, block.hash(), 1000, 1, 0, hash, &first, None).unwrap();
    assert_eq!(projection.event_kind, "Accepted");
    assert_eq!(projection.provenance, "emitted");
    assert_eq!(
        projection.payload.as_ref().unwrap()["active"],
        Value::Bool(true)
    );
    assert_eq!(
        projection.emission["definition"]["name"],
        Value::from("Accepted")
    );
    let reader = DataspaceReadVisibility::new(BTreeSet::from([DataSpaceId::new(7)]), false);
    assert!(native_contract_emission_is_visible_in_block(&reader, &projection, &block).unwrap());
    assert!(
        !native_contract_emission_is_visible_in_block(
            &DataspaceReadVisibility::default(),
            &projection,
            &block
        )
        .unwrap()
    );
    projection.emission_index = 1;
    assert!(native_contract_emission_is_visible_in_block(&reader, &projection, &block).is_err());
    projection.emission_index = 0;
    projection.execution_hash_hex = Hash::new(b"forged root").to_string();
    assert!(
        native_contract_emission_is_visible_in_block(
            &DataspaceReadVisibility::all_for_tests(),
            &projection,
            &block
        )
        .is_err()
    );
    projection.execution_hash_hex = hash.to_string();
    projection.emission = Value::Null;
    assert!(native_contract_emission_is_visible_in_block(&reader, &projection, &block).is_err());
}
