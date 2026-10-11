//! Actual signed Network execution under the private output owner.
//! These unit fixtures establish execution behavior, not carrier finality or DA.

use super::*;
use crate::exec_witness;
use crate::state::WorldReadOnly;
use iroha_data_model::{
    account::Account,
    events::{EventBox, execute_trigger::ExecuteTriggerEventFilter},
    isi::{ExecuteTrigger, Register, SetKeyValue, Unregister},
    transaction::{Executable, ExecutableBatchItem},
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};
use iroha_model_base::domain::DomainId;
use std::time::Duration;

fn fixture(row_bytes: u64, callback_bytes: Option<usize>) -> State {
    fixture_with_fee_asset(row_bytes, callback_bytes, None)
}

fn fixture_with_fee_asset(
    row_bytes: u64,
    callback_bytes: Option<usize>,
    fee_asset: Option<iroha_data_model::asset::AssetDefinitionId>,
) -> State {
    let mut state = state(row_bytes);
    if let Some(asset) = &fee_asset {
        use iroha_primitives::numeric::Quantity;
        let fees = &mut state.nexus.get_mut().fees;
        fees.base_fee = Quantity::from(1_u32);
        fees.per_byte_fee = Quantity::zero();
        fees.per_instruction_fee = Quantity::zero();
        fees.per_gas_unit_fee = Quantity::zero();
        fees.fee_asset_id = asset.to_string();
        fees.fee_sink_account_id = iroha_test_samples::BOB_ID.to_string();
    }
    let state = authenticate_output_state(state);
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        if let Some(asset) = fee_asset {
            use iroha_data_model::{
                asset::{AssetBalancePolicy, AssetDefinition, AssetId},
                isi::Mint,
            };
            use iroha_primitives::numeric::Quantity;
            Register::account(Account::new(iroha_test_samples::BOB_ID.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
            // Global fee assets have no owning domain or alias; their custody
            // uses universal accounts and the exact canonical asset definition.
            Register::asset_definition(AssetDefinition::numeric(
                asset.clone(),
                "Network fee".to_owned(),
                AssetBalancePolicy::Global,
                None,
            ))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
            Mint::asset_quantity(Quantity::from(10_u32), AssetId::of(asset, ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        if let Some(bytes) = callback_bytes {
            let id: TriggerId = "network_callback".parse().unwrap();
            let action = Action::new(
                vec![
                    InstructionBox::from(SetKeyValue::account(
                        ALICE_ID.clone(),
                        "callback_write".parse().unwrap(),
                        Json::new(7),
                    )),
                    Log::new(Level::DEBUG, "x".repeat(bytes)).into(),
                ],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .unwrap();
            Register::trigger(Trigger::new(id, action))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    state
}

fn input(
    state: &State,
    instructions: Vec<InstructionBox>,
    fee: FeePaymentIntent,
    batch: bool,
) -> TransactionEntrypoint {
    let mut tx = TransactionBuilder::new(state.network_id, ALICE_ID.clone(), fee);
    tx.set_creation_time(output_fixture_input_time(state));
    let executable = if batch {
        Executable::Batch(
            instructions
                .into_iter()
                .map(ExecutableBatchItem::Instruction)
                .collect::<Vec<_>>()
                .into(),
        )
    } else {
        Executable::Instructions(instructions.into())
    };
    TransactionEntrypoint::External(
        tx.with_executable(executable)
            .sign(ALICE_KEYPAIR.private_key()),
    )
}

fn carrier(state: &State, inputs: Vec<TransactionEntrypoint>) -> SignedBlock {
    // These component fixtures use the singleton route. Bind every original input before
    // signing so the producer validates the same source identity as native execution.
    let context = iroha_data_model::block::BlockExecutionContextBundle::new(
        inputs
            .iter()
            .map(|input| {
                iroha_data_model::block::ExternalExecutionContext::new(
                    input.hash(),
                    iroha_model_base::topology::LaneId::SINGLE,
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                )
            })
            .collect(),
    );
    let mut builder = BlockBuilder::new(output_fixture_header(state));
    for input in inputs {
        match input {
            TransactionEntrypoint::External(tx) => {
                builder.push_transaction(tx);
            }
            TransactionEntrypoint::SealedCommitment(tx) => {
                builder.push_sealed_transaction_commitment(tx);
            }
            TransactionEntrypoint::SealedReveal(tx) => {
                builder.push_sealed_transaction_reveal(tx);
            }
        }
    }
    builder.set_execution_context(Some(context));
    builder.build_with_signature(0, ALICE_KEYPAIR.private_key())
}

/// Acquire the exact carrier and original recorder before any block-start effects.
fn recorded_network_block<'state>(
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
        .expect("original carrier captures its pristine physical policy and recorder")
}

fn execute(
    block: &mut StateBlock<'_>,
    source: &SignedBlock,
) -> Result<(), ExecutionOutputAttemptError> {
    block.reserve_ordinary_execution_outputs(source)?;
    block.produce_ordinary_execution_outputs(source, |producer| {
        producer.execute_network_sources(None)?;
        for index in 0..source.network_entrypoint_count() {
            assert!(producer.network_route(index).is_some());
        }
        assert!(
            producer
                .network_route(source.network_entrypoint_count())
                .is_none()
        );
        finish_empty_internal(producer)
    })
}

fn network_row<'a>(block: &'a StateBlock<'_>, index: usize) -> &'a NetworkExecutionOutputV1 {
    let ExecutionOutputV1::Network(row) = &retained(block).rows[index] else {
        panic!("Network row")
    };
    row
}

#[test]
fn output_fixture_retains_original_genesis_and_successor_source() {
    let unprepared = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut unprepared_block = unprepared.block(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        2,
        0,
    ));
    assert!(
        crate::executor::root_scope::execution_root_scope(&mut unprepared_block.transaction())
            .is_err()
    );
    drop(unprepared_block);
    let state = fixture(65_536, Some(1024));
    let parent = state.view().latest_block_hash().expect("original genesis");
    assert_eq!(state.view().height(), 1);
    assert_eq!(state.network_id_ref().into_genesis_hash(), parent);
    let parameters = state.view().world.parameters.get().block();
    assert_eq!(parameters.execution_output().max_output_bytes, 65_536);
    assert_eq!(parameters.execution_output().max_pipeline_triggers, 0);
    assert_eq!(parameters.execution_output().max_time_invocations, 1);
    assert_eq!(parameters.max_time_trigger_invocations(), NonZeroU32::MIN);
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![Log::new(Level::INFO, "original output source".into()).into()],
            FeePaymentIntent::authority(vec![], None),
            false,
        )],
    );
    assert_eq!(source.header().prev_block_hash(), Some(parent));
    assert!(source.header().creation_time() > output_fixture_input_time(&state));
    let (mut block, _recording) = recorded_network_block(&state, &source);
    assert!(crate::executor::root_scope::execution_root_scope(&mut block.transaction()).is_ok());
    drop(block);
    drop(_recording);
    assert_eq!(state.view().latest_block_hash(), Some(parent));
}

#[test]
fn actual_signed_sources_apply_once_in_original_output_positions() {
    let state = fixture(65_536, None);
    let source = carrier(
        &state,
        (0..2)
            .map(|index| {
                input(
                    &state,
                    vec![
                        SetKeyValue::account(
                            ALICE_ID.clone(),
                            format!("network_{index}").parse().unwrap(),
                            Json::new(index),
                        )
                        .into(),
                    ],
                    FeePaymentIntent::authority(vec![], None),
                    false,
                )
            })
            .collect(),
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    assert_eq!(block.committed_fragment_count(), fragments + 2);
    for index in 0..2 {
        let row = network_row(&block, index);
        assert_eq!(row.input_index as usize, index);
        assert!(row.result.is_ok(), "{:?}", row.result);
        assert!(row.completions.is_empty());
        let key: Name = format!("network_{index}").parse().unwrap();
        assert_eq!(
            block.world.account(&ALICE_ID).unwrap().metadata().get(&key),
            Some(&Json::new(index as i32))
        );
    }
    let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
    assert_eq!(ordinary.executed_entries, 2);
    assert_eq!(
        (
            ordinary.transcripts,
            ordinary.deltas,
            ordinary.input_transcript_bytes,
            ordinary.max_statement_bytes,
            ordinary.total_statement_bytes
        ),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(
        mandatory,
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
    assert!(block.gas_used_in_block > 0);
    assert!(execute(&mut block, &source).is_err());
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn actual_callback_fits_exactly_or_rolls_back_before_applying() {
    let mut exact = None;
    for case in 0..3 {
        let bytes = match case {
            0 => 65_536,
            1 => exact.unwrap(),
            _ => exact.unwrap() - 1,
        };
        let state = fixture(bytes, Some(32_768));
        let source = carrier(
            &state,
            vec![input(
                &state,
                vec![ExecuteTrigger::new("network_callback".parse().unwrap()).into()],
                FeePaymentIntent::authority(vec![], None),
                false,
            )],
        );
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let fragments = block.committed_fragment_count();
        execute(&mut block, &source).unwrap();
        let row = network_row(&block, 0);
        let key: Name = "callback_write".parse().unwrap();
        if case < 2 {
            assert!(row.result.is_ok(), "{:?}", row.result);
            assert_eq!(row.result.as_ref().unwrap().len(), 1);
            assert_eq!(row.completions.len(), 1);
            assert_eq!(
                block.world.account(&ALICE_ID).unwrap().metadata().get(&key),
                Some(&Json::new(7))
            );
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            let measured = norito::canonical_frame_len(&retained(&block).rows[0]).unwrap() as u64;
            if let Some(expected) = exact {
                assert_eq!(measured, expected);
            } else {
                exact = Some(measured);
            }
        } else {
            assert!(retained(&block).rows[0].is_output_limit_rejection());
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert_eq!(block.committed_fragment_count(), fragments);
            assert!(
                block
                    .world
                    .external_event_buf
                    .iter()
                    .all(|event| !matches!(event, EventBox::TriggerCompleted(_)))
            );
            assert_eq!(
                block
                    .world
                    .triggers
                    .by_call_triggers()
                    .get(&"network_callback".parse().unwrap())
                    .unwrap()
                    .repeats,
                Repeats::Exactly(1)
            );
            assert!(exec_witness::snapshot_exec_witness().writes.is_empty());
        }
        assert!(block.gas_used_in_block > 0);
    }
}

#[test]
fn real_business_rejection_wins_after_oversized_callback_and_discards_capture() {
    let missing = DomainId::try_new("missing-network-domain", "universal").unwrap();
    for bytes in [16_384, 65_536] {
        let state = fixture(bytes, Some(32_768));
        let source = carrier(
            &state,
            vec![input(
                &state,
                vec![
                    ExecuteTrigger::new("network_callback".parse().unwrap()).into(),
                    Unregister::domain(missing.clone()).into(),
                ],
                FeePaymentIntent::authority(vec![], None),
                false,
            )],
        );
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let fragments = block.committed_fragment_count();
        execute(&mut block, &source).unwrap();
        let row = network_row(&block, 0);
        assert!(
            matches!(row.result.as_ref(), Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(iroha_data_model::isi::error::InstructionExecutionError::Find(
                iroha_data_model::query::error::FindError::Domain(id)))
        )) if id == &missing),
            "{:?}",
            row.result
        );
        assert!(!retained(&block).rows[0].is_output_limit_rejection());
        assert!(row.completions.is_empty());
        assert!(row.result.batch_transfer_outcomes().is_empty());
        let key: Name = "callback_write".parse().unwrap();
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&key)
                .is_none()
        );
        assert_eq!(block.committed_fragment_count(), fragments);
        assert!(
            block
                .world
                .external_event_buf
                .iter()
                .all(|event| !matches!(event, EventBox::TriggerCompleted(_)))
        );
        assert_eq!(
            block
                .world
                .triggers
                .by_call_triggers()
                .get(&"network_callback".parse().unwrap())
                .unwrap()
                .repeats,
            Repeats::Exactly(1)
        );
        assert!(exec_witness::snapshot_exec_witness().writes.is_empty());
    }
}

#[test]
fn block_gas_admission_rejects_before_business_or_transaction_gas() {
    let state = fixture(65_536, Some(1024));
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![ExecuteTrigger::new("network_callback".parse().unwrap()).into()],
            FeePaymentIntent::authority(vec![], None),
            false,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    // ExecuteTrigger is rejected by the real pre-body gas admission guard.
    // This does not exercise the owner's final post-success gas fallback.
    block.gas_limit_per_block = 1;
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    assert!(
        matches!(network_row(&block, 0).result.as_ref(), Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
        iroha_data_model::ValidationFail::NotPermitted(reason))) if reason.starts_with("block gas limit exceeded:"))
    );
    assert_eq!(block.gas_used_in_block, 0);
    assert_eq!(block.committed_fragment_count(), fragments);
    let key: Name = "callback_write".parse().unwrap();
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert!(network_row(&block, 0).completions.is_empty());
}

#[test]
fn stateless_rejection_does_not_execute_its_business_instructions() {
    let state = fixture(65_536, None);
    let mut tx = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(Duration::from_secs(1_000_000));
    let source = carrier(
        &state,
        vec![TransactionEntrypoint::External(
            tx.with_instructions([SetKeyValue::account(
                ALICE_ID.clone(),
                "future_write".parse().unwrap(),
                Json::new(1),
            )])
            .sign(ALICE_KEYPAIR.private_key()),
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    assert!(
        matches!(network_row(&block, 0).result.as_ref(), Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
        iroha_data_model::ValidationFail::NotPermitted(reason))) if reason == &format!("transaction creation time 1000000000 is not earlier than block creation time {}", source.header().creation_time().as_millis()))
    );
    let key: Name = "future_write".parse().unwrap();
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(block.gas_used_in_block, 0);
    let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
    assert_eq!(ordinary.executed_entries, 1);
    assert_eq!(ordinary.transcripts, 0);
    assert_eq!(
        mandatory,
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
}

#[test]
fn rejected_live_batch_rolls_back_business_and_applies_only_its_actual_fee_fragment() {
    use iroha_data_model::{
        asset::{AssetDefinitionId, AssetId},
        transaction::{FeeChargeKind, FeeChargeLimit},
    };
    use iroha_primitives::numeric::Quantity;
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    crate::status::reset_nexus_economics_for_tests();
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR fee asset");
    let state = fixture_with_fee_asset(65_536, None, Some(asset.clone()));
    let missing = DomainId::try_new("missing-network-fee-domain", "universal").unwrap();
    let fee = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![
                SetKeyValue::account(
                    ALICE_ID.clone(),
                    "fee_business_write".parse().unwrap(),
                    Json::new(1),
                )
                .into(),
                Unregister::domain(missing.clone()).into(),
            ],
            fee,
            true,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    let row = network_row(&block, 0);
    assert!(
        matches!(row.result.as_ref(), Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
        iroha_data_model::ValidationFail::InstructionFailed(iroha_data_model::isi::error::InstructionExecutionError::Find(
            iroha_data_model::query::error::FindError::Domain(id)))
    )) if id == &missing),
        "{:?}",
        row.result
    );
    assert!(row.completions.is_empty());
    assert!(row.result.batch_transfer_outcomes().is_empty());
    let key: Name = "fee_business_write".parse().unwrap();
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert_eq!(
        block
            .world
            .assets()
            .get(&AssetId::of(asset, ALICE_ID.clone()))
            .unwrap()
            .0,
        Quantity::from(9_u32)
    );
    assert_eq!(
        block.committed_fragment_count(),
        fragments + 1,
        "only the independently applied fee fragment survives"
    );
    assert!(block.gas_used_in_block > 0);
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[path = "output_network_penalty_tests.rs"]
mod penalties;

#[path = "output_pipeline_tests.rs"]
mod pipeline;

#[path = "output_seal_tests.rs"]
mod seal;

#[path = "output_network_fee_tests.rs"]
mod fees;

#[path = "output_network_source_tail_tests.rs"]
mod source_tail;

#[path = "output_network_effect_tests.rs"]
mod effects;

#[path = "output_network_quarantine_tests.rs"]
mod quarantine;

#[test]
fn frozen_fraud_admission_refuses_before_business_work_and_grace_preserves_execution() {
    for grace in [Duration::ZERO, Duration::from_secs(1)] {
        let mut state = fixture(65_536, None);
        state.fraud_monitoring.enabled = true;
        state.fraud_monitoring.required_minimum_band =
            Some(iroha_config::parameters::actual::FraudRiskBand::Low);
        state.fraud_monitoring.missing_assessment_grace = grace;
        let source = carrier(
            &state,
            vec![input(
                &state,
                vec![
                    SetKeyValue::account(
                        ALICE_ID.clone(),
                        "fraud_effect".parse().unwrap(),
                        Json::new(1_u32),
                    )
                    .into(),
                ],
                FeePaymentIntent::authority(vec![], None),
                false,
            )],
        );
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let before = block.committed_fragment_count();
        execute(&mut block, &source).unwrap();
        let result = network_row(&block, 0);
        if grace.is_zero() {
            assert!(
                matches!(result.result.as_ref(), Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted(reason))) if reason == "fraud monitoring requires an attached assessment")
            );
            assert_eq!(block.committed_fragment_count(), before);
            assert_eq!(block.gas_used_in_block, 0);
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("fraud_effect")
                    .is_none()
            );
        } else {
            assert!(result.result.is_ok());
            assert_eq!(block.committed_fragment_count(), before + 1);
            assert_eq!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("fraud_effect"),
                Some(&Json::new(1_u32))
            );
        }
    }
}

#[test]
fn ordinary_signed_creation_time_must_precede_its_actual_carrier() {
    for created_at in [1_u64, 2, 3] {
        let state = fixture(65_536, None);
        let mut builder = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        let actual_created_at = output_fixture_parent_time(&state) + created_at;
        builder.set_creation_time(Duration::from_millis(actual_created_at));
        let source = carrier(
            &state,
            vec![TransactionEntrypoint::External(
                builder
                    .with_instructions([SetKeyValue::account(
                        ALICE_ID.clone(),
                        "source_time_effect".parse().unwrap(),
                        Json::new(1_u32),
                    )])
                    .sign(ALICE_KEYPAIR.private_key()),
            )],
        );
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let fragments = block.committed_fragment_count();
        execute(&mut block, &source).unwrap();
        let row = network_row(&block, 0);
        assert_eq!(row.input_index, 0);
        assert!(row.completions.is_empty());
        assert!(row.result.batch_transfer_outcomes().is_empty());
        if created_at == 1 {
            assert!(row.result.is_ok());
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            assert_eq!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("source_time_effect"),
                Some(&Json::new(1_u32))
            );
        } else {
            assert!(matches!(row.result.as_ref(),
                Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                    iroha_data_model::ValidationFail::NotPermitted(reason)))
                if reason == &format!("transaction creation time {actual_created_at} is not earlier than block creation time {}", source.header().creation_time().as_millis())));
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(block.gas_used_in_block, 0);
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("source_time_effect")
                    .is_none()
            );
        }
    }
}

#[test]
fn intrinsic_source_rejection_rolls_back_movements_and_witness_but_keeps_e_and_fee() {
    use iroha_data_model::{
        asset::{AssetDefinitionId, AssetId},
        isi::Transfer,
        parameter::FastpqSourcePolicyV1,
        transaction::{FeeChargeKind, FeeChargeLimit},
    };
    use iroha_primitives::numeric::Quantity;
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    crate::status::reset_nexus_economics_for_tests();
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR fee asset");
    let state = fixture_with_fee_asset(65_536, None, Some(asset.clone()));
    let mut parameters = state.world.parameters.block();
    let previous = parameters.get().block().fastpq_source();
    let mut intrinsic = previous.intrinsic;
    intrinsic.max_transcripts = 1;
    intrinsic.max_deltas = 1;
    let profile = FastpqSourcePolicyV1::from_sizing(
        parameters.get().block().execution_output(),
        intrinsic,
        previous.mandatory,
        1,
    )
    .unwrap();
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::FastpqSource(profile)));
    parameters.commit();
    let alice = AssetId::of(asset.clone(), ALICE_ID.clone());
    let bob = AssetId::of(asset.clone(), iroha_test_samples::BOB_ID.clone());
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![
                Transfer::asset_quantity(alice.clone(), 1_u32, iroha_test_samples::BOB_ID.clone())
                    .into(),
                Transfer::asset_quantity(alice.clone(), 1_u32, iroha_test_samples::BOB_ID.clone())
                    .into(),
            ],
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset,
                    Quantity::from(1_u32),
                )],
                None,
            ),
            true,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let before_fragments = block.committed_fragment_count();
    let receiver_before = block.world.assets().get(&bob).cloned();
    execute(&mut block, &source).unwrap();
    assert!(matches!(network_row(&block, 0).result.as_ref(),
        Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted(reason)
        )) if reason == crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION));
    assert_eq!(
        block.world.assets().get(&alice).unwrap().0,
        Quantity::from(9_u32)
    );
    assert_eq!(block.world.assets().get(&bob).cloned(), receiver_before);
    assert_eq!(block.committed_fragment_count(), before_fragments + 1);
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
    assert_eq!(
        ordinary,
        crate::fastpq::source_reservation::SourceUsage {
            executed_entries: 1,
            ..crate::fastpq::source_reservation::SourceUsage::ZERO
        }
    );
    assert_eq!(
        mandatory,
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
    assert!(
        crate::exec_witness::drain_exec_witness()
            .fastpq_transcripts
            .is_empty()
    );
}

#[test]
fn local_refusal_after_native_work_restores_direct_transaction_and_witness() {
    use iroha_data_model::{isi::Grant, transaction::IvmBytecode};
    use ivm::error::ExecutionDeferral;
    let state = fixture(65_536, None);
    let id: TriggerId = "direct_deferred_callback".parse().unwrap();
    let key: Name = "deferred_native_write".parse().unwrap();
    let mut program = ivm::ProgramMetadata {
        max_cycles: 100,
        ..Default::default()
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut tx = setup.transaction_for_callback_testing();
        Grant::account_permission(
            iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                authority: ALICE_ID.clone(),
            },
            ALICE_ID.clone(),
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        Register::trigger(Trigger::new(
            id.clone(),
            Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(program)),
                Repeats::Exactly(2),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .unwrap(),
        ))
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        tx.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let entry = input(
        &state,
        vec![
            SetKeyValue::account(ALICE_ID.clone(), key.clone(), Json::new(7)).into(),
            ExecuteTrigger::new(id.clone()).into(),
        ],
        FeePaymentIntent::authority(vec![], None),
        false,
    );
    let source = carrier(&state, vec![entry.clone()]);
    let cache_owner = state.trigger_ivm_cache.lock().prepared_contract_cache();
    let reason = ExecutionDeferral::AllocationUnavailable;
    cache_owner.set_checkout_refusal_for_test(Some(reason));
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let before = exec_witness::snapshot_exec_witness();
    assert_eq!(
        execute(&mut block, &source),
        Err(ExecutionOutputAttemptError::Deferred(reason.into()))
    );
    assert_eq!(exec_witness::snapshot_exec_witness(), before);
    assert_eq!(block.gas_used_in_block, 0);
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert_eq!(
        block
            .world
            .triggers
            .by_call_triggers()
            .get(&id)
            .unwrap()
            .repeats,
        Repeats::Exactly(2)
    );
    cache_owner.set_checkout_refusal_for_test(None);
    drop(_recording);
    drop(block);
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).expect("same original source succeeds after local recovery");
    let callbacks = network_row(&block, 0)
        .result
        .as_ref()
        .expect("source succeeds");
    assert_eq!(
        callbacks.len(),
        1,
        "direct replay retains the by-call trace"
    );
    assert_eq!(callbacks[0].id, id);
    assert!(block.gas_used_in_block > 0);
    assert_eq!(
        block.world.account(&ALICE_ID).unwrap().metadata().get(&key),
        Some(&Json::new(7))
    );
    assert_eq!(
        block
            .world
            .triggers
            .by_call_triggers()
            .get(&id)
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
}

#[path = "output_network_nexus_receipt_tests.rs"]
mod nexus_receipts;

#[path = "output_contract_event_tests.rs"]
mod contract_events;
