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
    let mut block = state.block(header());
    assert!(!block.start_of_block_effects_applied);
    assert!(matches!(
        block.execution_output_plan,
        Some(output_capacity::ExecutionOutputPlanState::Poisoned)
    ));
    assert!(matches!(block.fastpq_source_inventory, Some(Err(_))));
    let before = block.world.parameters.get().clone();
    let mut transaction = block.transaction();
    transaction
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
            nonzero!(1_u32),
        )))
        .expect("valid fixture parameters");
    assert!(!transaction.fastpq_source_quota.allows_apply());
    assert!(
        transaction
            .fastpq_source_quota
            .intrinsic_rejected()
            .is_err()
    );
    transaction.apply();
    assert_eq!(block.world.parameters.get(), &before);
    assert!(block.capture_exec_witness().is_err());
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
