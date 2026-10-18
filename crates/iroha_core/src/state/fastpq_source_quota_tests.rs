//! Frozen source policy, fail-closed construction, and exact admission ownership.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore};
use iroha_data_model::{
    block::BlockHeader,
    parameter::{BlockParameter, Parameter},
};
use nonzero_ext::nonzero;

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(nonzero!(1_u64), None, None, 1, 0)
}

#[test]
fn invalid_source_policy_is_retained_without_lifecycle_or_publication() {
    let state = state();
    let mut parameters = state.world.parameters.block();
    let mut profile = parameters.get().block().fastpq_source();
    profile.block.max_executed_entries = 0;
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::FastpqSource(profile)))
        .expect("valid fixture parameters");
    parameters.commit();
    let mut block = state.merge_preexecution_block(header());
    assert!(!block.start_of_block_effects_applied);
    assert!(matches!(
        block.execution_output_plan,
        Some(output_capacity::ExecutionOutputPlanState::Poisoned)
    ));
    assert!(matches!(block.fastpq_source_inventory, Some(Err(_))));
    let before = block.world.parameters.get().clone();
    let Some(Err(original_error)) = &block.fastpq_source_quota else {
        panic!("original source policy refuses preparation");
    };
    let original_error = original_error.clone();
    let unavailable =
        crate::fastpq::source_reservation::admission::SourceQuotaTransaction::unavailable(
            original_error.clone(),
        );
    assert!(!unavailable.allows_apply());
    assert_eq!(
        unavailable.intrinsic_rejected(),
        Err(original_error.clone())
    );
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut transaction = block.transaction();
        transaction
            .world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
                nonzero!(1_u32),
            )))
            .expect("valid fixture parameters");
        transaction.apply();
    }));
    assert!(
        refused.is_err(),
        "poisoned original refuses child acquisition"
    );
    assert_eq!(
        block.fastpq_source_inventory(),
        Err(original_error.as_str())
    );
    assert_eq!(block.world.parameters.get(), &before);
    assert!(block.capture_exec_witness().is_err());
}

#[test]
fn invalid_source_policy_refuses_both_result_constructors_before_pristine_callbacks() {
    let state = state();
    let valid = state.world.parameters.view().get().block().fastpq_source();
    let mut invalid = valid;
    invalid.block.max_executed_entries = 0;
    let expected = invalid
        .validate(
            state
                .world
                .parameters
                .view()
                .get()
                .block()
                .execution_output(),
        )
        .unwrap_err();
    // Retain the malformed policy as both current and predecessor, so the
    // replacement constructor validates its own actual reverted source too.
    for _ in 0..2 {
        let mut parameters = state.world.parameters.block();
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::FastpqSource(invalid)))
            .unwrap();
        parameters.commit();
    }
    let before = std::cell::Cell::new(false);
    let after = std::cell::Cell::new(false);
    let outcome = state.block_with_owned_start_stages(
        header(),
        |_| {
            before.set(true);
            Ok::<(), String>(())
        },
        |_, ()| {
            after.set(true);
            Ok::<(), String>(())
        },
    );
    assert!(matches!(outcome, Err(StateBlockStartError::Policy(reason)) if reason == expected));
    assert!(!before.get());
    assert!(!after.get());
    let replacement_called = std::cell::Cell::new(false);
    let outcome = state.block_and_revert_with_pristine_stage(header(), |_| {
        replacement_called.set(true);
        Ok::<(), String>(())
    });
    assert!(matches!(outcome, Err(StateBlockStartError::Policy(reason)) if reason == expected));
    assert!(!replacement_called.get());
    assert_eq!(
        state.world.parameters.view().get().block().fastpq_source(),
        invalid
    );
    // Both failed owners release their writers; a corrected committed source
    // acquires a fresh block rather than reopening either poisoned attempt.
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::FastpqSource(valid)))
        .unwrap();
    parameters.commit();
    let fresh = state.try_block(header()).unwrap();
    assert!(fresh.execution_output_plan.is_none());
    assert!(fresh.start_of_block_effects_applied);
}

#[test]
fn set_parameter_installs_source_policy_and_emits_exact_change() {
    use crate::smartcontracts::Execute;
    use iroha_data_model::{
        events::data::prelude::{ConfigurationEvent, DataEvent},
        isi::SetParameter,
        parameter::FastpqSourcePolicyV1,
    };
    use iroha_test_samples::ALICE_ID;

    let state = state();
    let mut block = state.block(header());
    let old = block.world.parameters.get().block().fastpq_source();
    let next = FastpqSourcePolicyV1::from_sizing(
        block.world.parameters.get().block().execution_output(),
        old.intrinsic,
        old.mandatory,
        10,
    )
    .unwrap();
    assert_ne!(old, next);
    let mut transaction = block.transaction();
    let event_count = transaction.world.external_event_buf.len();
    SetParameter::new(Parameter::Block(BlockParameter::FastpqSource(next)))
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
    assert_eq!(
        transaction.world.parameters.get().block().fastpq_source(),
        next
    );
    assert_eq!(transaction.world.external_event_buf.len(), event_count + 1);
    let Some(iroha_data_model::events::EventBox::Data(event)) =
        transaction.world.external_event_buf.last()
    else {
        panic!("source policy change must emit a data event");
    };
    let DataEvent::Configuration(ConfigurationEvent::Changed(change)) = event.as_ref() else {
        panic!("source policy change must emit a configuration event");
    };
    assert_eq!(
        change.old_value,
        Parameter::Block(BlockParameter::FastpqSource(old))
    );
    assert_eq!(
        change.new_value,
        Parameter::Block(BlockParameter::FastpqSource(next))
    );
    transaction.apply();
    assert_eq!(block.world.parameters.get().block().fastpq_source(), next);
    // The current carrier retains its original admission ceiling.
    assert_eq!(block.fastpq_source_policy_at_block_start().0, old);
}
