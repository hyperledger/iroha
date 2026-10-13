//! Actual constructor and parameter controls for frozen output capacity.

use std::num::{NonZeroU32, NonZeroU64};

use iroha_data_model::events::pipeline::BlockEventFilter;
use iroha_data_model::{
    block::BlockHeader,
    isi::SetParameter,
    parameter::{BlockParameter, Parameter},
};
use iroha_model_base::metadata::Metadata;
use iroha_test_samples::ALICE_ID;

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};

fn parameter(maximum: u32) -> Parameter {
    Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
        NonZeroU32::new(maximum).expect("positive fixture limit"),
    ))
}

fn state(maximum: u32) -> State {
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(parameter(maximum))
        .expect("valid fixture parameters");
    parameters.commit();
    state
}

fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0)
}

fn set_parameter(block: &mut StateBlock<'_>, maximum: u32) {
    let mut transaction = block.transaction();
    SetParameter::new(parameter(maximum))
        .execute(&ALICE_ID, &mut transaction)
        .expect("actual native parameter instruction");
    transaction.apply();
}

#[test]
fn captured_time_count_is_independent_from_network_transaction_limit() {
    let state = state(17);
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::MaxTransactions(
            NonZeroU64::new(u64::MAX).unwrap(),
        )))
        .expect("valid fixture parameters");
    parameters.commit();
    let block = state.block(header());
    assert_eq!(block.time_trigger_invocation_limit().unwrap(), 17);
}

#[test]
fn after_start_limit_survives_actual_same_carrier_parameter_writes() {
    let state = state(1);
    let (block, ()) = state
        .block_with_owned_start_stages(
            header(),
            |block| {
                assert!(block.time_trigger_invocation_limit().is_err());
                set_parameter(block, 3);
                Ok::<(), String>(())
            },
            |block, ()| {
                assert!(block.start_of_block_effects_applied);
                assert_eq!(block.time_trigger_invocation_limit()?, 3);
                for later in [1, 7, 512] {
                    set_parameter(block, later);
                    assert_eq!(
                        block
                            .world
                            .parameters
                            .get()
                            .block()
                            .max_time_trigger_invocations()
                            .get(),
                        later
                    );
                    block.capture_execution_output_capacity();
                    assert_eq!(block.time_trigger_invocation_limit()?, 3);
                }
                Ok(())
            },
        )
        .expect("actual constructor captures after its start stage");
    drop(block);
    assert_eq!(
        state
            .world
            .parameters
            .view()
            .block()
            .max_time_trigger_invocations()
            .get(),
        1
    );
}

#[test]
fn later_carrier_uses_published_parameter_change() {
    let state = state(2);
    {
        let mut block = state.block(header());
        set_parameter(&mut block, 5);
        assert_eq!(block.time_trigger_invocation_limit().unwrap(), 2);
        // Publish only fixture world state, not a consensus block/finality claim.
        block.commit_world_overlay_for_testing().unwrap();
    }
    let later = state.block(header());
    assert_eq!(later.time_trigger_invocation_limit().unwrap(), 5);
}

#[test]
fn replacement_limit_comes_from_reverted_world_and_its_own_stage() {
    let state = state(2);
    {
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(parameter(9))
            .expect("valid fixture parameters");
        world.commit();
    }
    let mut replacement = state
        .block_and_revert_with_pristine_stage(header(), |block| {
            assert_eq!(
                block
                    .world
                    .parameters
                    .get()
                    .block()
                    .max_time_trigger_invocations()
                    .get(),
                2
            );
            assert!(block.time_trigger_invocation_limit().is_err());
            set_parameter(block, 4);
            Ok::<(), String>(())
        })
        .expect("replacement constructor uses its actual reverted initialization");
    assert!(!replacement.start_of_block_effects_applied);
    assert_eq!(replacement.time_trigger_invocation_limit().unwrap(), 4);
    set_parameter(&mut replacement, 8);
    assert_eq!(replacement.time_trigger_invocation_limit().unwrap(), 4);
    drop(replacement);
    assert_eq!(
        state
            .world
            .parameters
            .view()
            .block()
            .max_time_trigger_invocations()
            .get(),
        9
    );
}

#[test]
fn no_hook_probe_refuses_time_before_event_or_maintenance_effects() {
    let state = state(2);
    let mut probe = state.consensus_effects_probe_block(header()).unwrap();
    let events = probe.world.external_event_buf.len();
    assert!(probe.time_trigger_invocation_limit().is_err());
    let error = probe.prepare_owned_time_phase(&header()).unwrap_err();
    assert!(
        matches!(error, super::ExecutionOutputAttemptError::Owner(reason)
            if reason.contains("captured carrier output capacity"))
    );
    assert_eq!(probe.world.external_event_buf.len(), events);
    assert_eq!(
        probe
            .world
            .parameters
            .get()
            .block()
            .max_time_trigger_invocations()
            .get(),
        2
    );
}

fn signed_source(state: &State) -> SignedBlock {
    use iroha_data_model::{
        block::builder::BlockBuilder, prelude::*, transaction::FeePaymentIntent,
    };
    let transaction = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([Log::new(Level::INFO, "owned output source".to_owned())])
    .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let mut builder = BlockBuilder::new(header());
    builder.push_transaction(transaction);
    builder.build_with_signature(0, iroha_test_samples::ALICE_KEYPAIR.private_key())
}

#[test]
fn ordinary_source_mints_one_plan_and_unfinished_plan_cannot_publish() {
    let state = state(2);
    let source = signed_source(&state);
    let mut block = state.block(source.header());
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    assert_eq!(block.reserved_output_input_count_for_test(), Some(1));
    let Some(ExecutionOutputPlanState::Reserved(plan)) = block.execution_output_plan.as_ref()
    else {
        panic!("source must retain a reserved plan");
    };
    assert_eq!(plan.proposal, source.hash());
    assert!(plan.input_root.is_some());
    assert!(block.reserve_ordinary_execution_outputs(&source).is_err());
    assert!(matches!(
        block.commit().unwrap_err(),
        super::super::TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn foreign_source_or_invalid_restored_capacity_cannot_mint_a_plan() {
    let state = state(2);
    let source = signed_source(&state);
    let mut wrong_header = source.header();
    wrong_header.creation_time_ms += 1;
    let mut block = state.block(wrong_header);
    assert!(block.reserve_ordinary_execution_outputs(&source).is_err());
    assert!(block.execution_output_plan.is_none());
    drop(block);
    {
        // A malformed restored value cannot become a matching/output capability.
        let mut parameters = state.world.parameters.block();
        let mut policy = ExecutionOutputPolicyV1::bootstrap();
        policy.max_outputs = 1;
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let mut block = state.block(source.header());
    let events = block.world.external_event_buf.len();
    assert!(block.reserve_ordinary_execution_outputs(&source).is_err());
    assert!(block.prepare_owned_time_phase(&source.header()).is_err());
    assert_eq!(block.world.external_event_buf.len(), events);
    assert!(matches!(
        block.execution_output_plan,
        Some(super::ExecutionOutputPlanState::Poisoned)
    ));
    let mut tx = block.transaction();
    SetParameter::new(Parameter::Block(BlockParameter::ExecutionOutput(
        ExecutionOutputPolicyV1::bootstrap(),
    )))
    .execute(&ALICE_ID, &mut tx)
    .unwrap();
    tx.apply();
    block.capture_execution_output_capacity();
    assert!(
        block.time_trigger_invocation_limit().is_err(),
        "a later repair cannot replace this carrier's frozen refusal"
    );
    assert!(block.reserve_ordinary_execution_outputs(&source).is_err());
}

#[test]
fn actual_parameter_instruction_enforces_genesis_envelope_and_later_time_bound() {
    let state = state(2);
    let mut block = state.block(header());
    let mut policy = ExecutionOutputPolicyV1::bootstrap();
    policy.max_time_invocations = 4;
    {
        let mut tx = block.transaction();
        SetParameter::new(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        tx.apply();
    }
    // Genesis instructions install the following carriers' policy; this carrier
    // still holds its original constructor-owned plan.
    assert_eq!(block.time_trigger_invocation_limit().unwrap(), 2);
    block.commit_world_overlay_for_testing().unwrap();
    let later_header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 2, 0);
    let mut later = state.block(later_header);
    let mut tx = later.transaction();
    let before = tx.world.parameters.get().clone();
    let events = tx.world.external_event_buf.len();
    assert!(
        SetParameter::new(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .execute(&ALICE_ID, &mut tx)
            .is_err()
    );
    assert!(
        SetParameter::new(parameter(5))
            .execute(&ALICE_ID, &mut tx)
            .is_err()
    );
    assert_eq!(*tx.world.parameters.get(), before);
    assert_eq!(tx.world.external_event_buf.len(), events);
    SetParameter::new(parameter(4))
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    tx.apply();
    assert_eq!(later.time_trigger_invocation_limit().unwrap(), 2);
    assert_eq!(
        later
            .world
            .parameters
            .get()
            .block()
            .max_time_trigger_invocations()
            .get(),
        4
    );
}

#[test]
fn actual_register_counts_disabled_pipeline_and_time_actions_before_loading() {
    use iroha_data_model::prelude::*;
    use iroha_primitives::json::Json;
    let state = state(2);
    let mut block = state.block(header());
    let mut tx = block.transaction();
    Register::account(Account::new(ALICE_ID.clone()))
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    let mut policy = ExecutionOutputPolicyV1::bootstrap();
    policy.max_pipeline_triggers = 1;
    policy.max_time_triggers = 1;
    SetParameter::new(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    for pipeline in [false, true] {
        let filter: EventFilterBox = if pipeline {
            BlockEventFilter::new()
                .for_status(BlockStatus::Approved)
                .into()
        } else {
            TimeEventFilter::new(ExecutionTime::PreCommit).into()
        };
        let action = Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter,
        )
        .unwrap();
        let mut metadata = Metadata::default();
        metadata.insert("__enabled".parse().unwrap(), Json::from(false));
        let first = Trigger::new(
            format!("capacity-{pipeline}-first").parse().unwrap(),
            action.clone().with_metadata(metadata),
        );
        Register::trigger(first)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        let second = Trigger::new(
            format!("capacity-{pipeline}-second").parse().unwrap(),
            action,
        );
        let events = tx.world.external_event_buf.len();
        let error = Register::trigger(second)
            .execute(&ALICE_ID, &mut tx)
            .unwrap_err();
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) = error
        else {
            panic!("expected typed output capacity refusal, got {error:?}");
        };
        assert!(message.contains("agreed execution capacity"));
        assert_eq!(tx.world.external_event_buf.len(), events);
    }
    assert_eq!(tx.world.triggers.pipeline_triggers().len(), 1);
    assert_eq!(tx.world.triggers.time_triggers().len(), 1);
    tx.apply();
    drop(block);
    assert_eq!(state.world.triggers.view().pipeline_triggers().len(), 0);
    assert_eq!(state.world.triggers.view().time_triggers().len(), 0);
}

#[test]
fn gas_limit_is_frozen_from_the_actual_world_before_start_effects() {
    use iroha_data_model::parameter::{CustomParameter, CustomParameterId};
    let state = state(2);
    let gas = |limit: u64| {
        Parameter::Custom(CustomParameter::new(
            CustomParameterId::new("ivm_gas_limit_per_block".parse().unwrap()),
            iroha_primitives::json::Json::new(limit),
        ))
    };
    {
        let mut parameters = state.world.parameters.block();
        parameters
            .set_parameter(gas(11))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let block = state
        .block_with_pristine_stage(header(), |block| {
            assert_eq!(block.gas_limit_per_block, 11);
            block
                .world
                .parameters
                .get_mut()
                .set_parameter(gas(22))
                .expect("valid fixture parameters");
            Ok::<(), core::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(block.gas_limit_per_block, 11);
    assert_eq!(
        crate::state::gas_limit_from_parameters(block.world.parameters.get()),
        22
    );
    drop(block);
    assert_eq!(state.block(header()).gas_limit_per_block, 11);
}

#[test]
fn replacement_gas_limit_comes_from_the_reverted_world() {
    use iroha_data_model::parameter::{CustomParameter, CustomParameterId};
    let state = state(2);
    let gas = |limit: u64| {
        Parameter::Custom(CustomParameter::new(
            CustomParameterId::new("ivm_gas_limit_per_block".parse().unwrap()),
            iroha_primitives::json::Json::new(limit),
        ))
    };
    {
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(gas(11))
            .expect("valid fixture parameters");
        world.commit();
    }
    let mut tip = state.block(header());
    assert_eq!(tip.gas_limit_per_block, 11);
    tip.world
        .parameters
        .get_mut()
        .set_parameter(gas(22))
        .expect("valid fixture parameters");
    tip.commit_world_overlay_for_testing().unwrap();
    assert_eq!(state.block(header()).gas_limit_per_block, 22);
    let replacement = state.block_and_revert(header());
    assert_eq!(
        crate::state::gas_limit_from_parameters(replacement.world.parameters.get()),
        11
    );
    assert_eq!(replacement.gas_limit_per_block, 11);
    drop(replacement);
    assert_eq!(state.block(header()).gas_limit_per_block, 22);
}

#[test]
fn try_block_rejects_invalid_acquired_abi_and_releases_the_overlay() {
    use iroha_data_model::{
        executor::IvmAdmissionError,
        runtime::{
            RuntimeUpgradeId, RuntimeUpgradeManifest, RuntimeUpgradeRecord, RuntimeUpgradeStatus,
        },
    };
    let state = state(2);
    let id = RuntimeUpgradeId([7; 32]);
    {
        let mut upgrades = state.world.runtime_upgrades.block();
        upgrades.insert(
            id,
            RuntimeUpgradeRecord {
                manifest: RuntimeUpgradeManifest {
                    name: "invalid-window".into(),
                    description: "fixture".into(),
                    abi_version: 1,
                    abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
                    added_syscalls: vec![],
                    added_pointer_types: vec![],
                    start_height: 1,
                    end_height: 1,
                    sbom_digests: vec![],
                    slsa_attestation: vec![],
                    provenance: vec![],
                },
                status: RuntimeUpgradeStatus::Proposed,
                proposer: ALICE_ID.clone(),
                created_height: 0,
            },
        );
        upgrades.commit();
    }
    assert!(matches!(
        state.try_block(header()),
        Err(crate::state::StateBlockStartError::Stage(
            IvmAdmissionError::ManifestMalformed
        ))
    ));
    // A failed constructor releases every acquired guard and leaves the input
    // unchanged; repairing the actual fixture store permits a fresh constructor.
    let mut upgrades = state.world.runtime_upgrades.block();
    assert!(upgrades.get(&id).is_some());
    upgrades.remove(id);
    upgrades.commit();
    let block = state.try_block(header()).unwrap();
    assert!(block.start_of_block_effects_applied);
    assert!(block.world.runtime_upgrades.is_empty());
    assert!(block.execution_output_plan.is_none());
}

#[test]
fn same_genesis_parameter_writes_cannot_replace_either_frozen_profile() {
    use nonzero_ext::nonzero;
    let state = state(512);
    let initial = state.world.parameters.view().get().block();
    let ((source, output), block) = {
        let block = state
            .block_with_pristine_stage(header(), |block| {
                let mut changed_output = initial.execution_output();
                changed_output.max_pipeline_triggers = 0;
                changed_output.max_time_invocations = 1;
                let mut transaction = block.transaction();
                transaction
                    .world
                    .parameters
                    .get_mut()
                    .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(
                        changed_output,
                    )))
                    .expect("valid fixture parameters");
                transaction
                    .world
                    .parameters
                    .get_mut()
                    .set_parameter(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
                        nonzero!(1_u32),
                    )))
                    .expect("valid fixture parameters");
                transaction.apply();
                Ok::<(), String>(())
            })
            .unwrap();
        (block.fastpq_source_policy_at_block_start(), block)
    };
    assert_eq!(source, initial.fastpq_source());
    assert_eq!(output, initial.execution_output());
    let frozen = block
        .frozen_execution_output_capacity
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(frozen.policy, output);
    assert_eq!(frozen.time_invocations, 1);
    assert_ne!(
        block.world.parameters.get().block().execution_output(),
        output
    );
}
