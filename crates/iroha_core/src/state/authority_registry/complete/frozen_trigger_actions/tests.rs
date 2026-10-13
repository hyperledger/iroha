//! Actual State frozen targets, modes, original pool, dispatch and canonical action parity.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::triggers::{
        set::{CheckedActions, action_source_work},
        specialized::{SpecializedAction, SpecializedTrigger},
    },
    state::{
        State, World,
        authority_registry::complete::table_capture::frozen::capture_original_table_once,
    },
};
use iroha_data_model::{block::BlockHeader, prelude::*};
use iroha_test_samples::ALICE_ID;
use mv::BlockRetirement as _;
use std::num::NonZeroU64;
fn state(world: World) -> State {
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0)
}
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131072,
        max_streamed_value_bytes: 131072,
    }
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn populated() -> World {
    let world = World::new();
    let mut block = world.triggers.block();
    let mut transaction = block.transaction();
    let action = SpecializedAction::new(
        Executable::Instructions(Vec::<InstructionBox>::new().into()),
        Repeats::Indefinitely,
        ALICE_ID.clone(),
        ExecuteTriggerEventFilter::new(),
    )
    .unwrap();
    assert!(
        transaction
            .add_by_call_trigger(SpecializedTrigger::new("call".parse().unwrap(), action))
            .unwrap()
    );
    transaction.apply();
    block.commit();
    world
}
fn choices() -> [(ActionTable, &'static str); 4] {
    [
        (ActionTable::Data, "triggers.data"),
        (ActionTable::Pipeline, "triggers.pipeline"),
        (ActionTable::Time, "triggers.time"),
        (ActionTable::ByCall, "triggers.by_call"),
    ]
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
fn committed(state: &State, table: ActionTable) -> CanonicalTablePairedSnapshot {
    let pool = state.ivm_execution_budget();
    let mut checked =
        CheckedActions::capture(&state.world.triggers, action_source_work(limits()), &pool)
            .unwrap();
    let outcome = checked.encode(table, limits());
    let current = checked.matches_current();
    drop(checked);
    assert!(current.expect("original action source identities"));
    outcome.unwrap()
}
#[test]
fn ordinary_and_replace_empty_actions_match_all_four_original_committed_frames() {
    let state = state(World::new());
    for (table, id) in choices() {
        let expected = committed(&state, table);
        for replace in [false, true] {
            let mut block = if replace {
                state.block_and_revert(header())
            } else {
                state.block(header())
            };
            freeze(&mut block);
            let actual = capture(&block, table, limits(), u64::MAX).unwrap().unwrap();
            equal(&actual, &expected);
            assert_eq!(actual.table_id(), id);
            assert_eq!(actual.row_count(), 0);
        }
    }
}
#[test]
fn real_action_registration_and_original_predecessor_admit_the_same_four_dispatches() {
    let state = state(populated());
    let mut block = state.block(header());
    freeze(&mut block);
    for (table, id) in choices() {
        let expected = committed(&state, table);
        let actual = capture(&block, table, limits(), u64::MAX).unwrap().unwrap();
        equal(&actual, &expected);
        let routed = capture_original_table_once(&block, id, limits(), u64::MAX)
            .unwrap()
            .unwrap();
        equal(&routed, &actual);
        assert_eq!(
            actual.row_count(),
            if table == ActionTable::ByCall { 1 } else { 0 }
        );
    }
}
#[test]
fn executing_partial_foreign_and_released_set_contexts_return_absence_without_charge() {
    let state = state(World::new());
    let foreign = self::state(World::new());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let baseline = pool.reserved_bytes();
    assert!(
        capture(&block, ActionTable::Data, limits(), 0)
            .unwrap()
            .is_none()
    );
    block.world.triggers.begin_freeze();
    block.world.triggers.finish_freeze();
    assert!(
        capture(&block, ActionTable::Data, limits(), 0)
            .unwrap()
            .is_none()
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(block);
    let mut block = state.block(header());
    block.world.triggers = foreign.world.triggers.block();
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    assert!(
        capture(&block, ActionTable::Data, limits(), u64::MAX)
            .unwrap()
            .is_none()
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    block.world.release_writers();
    assert!(
        capture(&block, ActionTable::Data, limits(), u64::MAX)
            .unwrap()
            .is_none()
    );
}
#[test]
fn work_pool_and_encoding_refusals_keep_the_actual_frozen_state_available_for_retry() {
    let state = state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    assert!(matches!(
        capture(&block, ActionTable::ByCall, limits(), 0),
        Err(LeafError::TriggerContracts(
            crate::smartcontracts::triggers::set::TriggerContractError::WorkLimit
        ))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(
        capture(
            &block,
            ActionTable::ByCall,
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            u64::MAX
        )
        .is_err()
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    let original_limit = pool.limit_bytes();
    pool.set_limit_bytes(baseline);
    assert!(capture(&block, ActionTable::ByCall, limits(), u64::MAX).is_err());
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(original_limit);
    let actual = capture(&block, ActionTable::ByCall, limits(), u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(actual.row_count(), 1);
    drop(actual);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn unchanged_frozen_action_context_retains_original_frames_after_a_row_bound_refusal() {
    let state = state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let actual = capture(&block, ActionTable::ByCall, limits(), u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(actual.row_count(), 1);
    // Equal-value publication remains a separate actual owner; this block keeps its original journals.
    let expected = committed(&state, ActionTable::ByCall);
    equal(&actual, &expected);
    drop(actual);
    drop(expected);
    let baseline = pool.reserved_bytes();
    assert!(
        capture(
            &block,
            ActionTable::ByCall,
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            u64::MAX
        )
        .is_err()
    );
    assert_eq!(pool.reserved_bytes(), baseline);
}

#[test]
fn original_state_publication_fence_defers_all_four_action_outputs_before_admission() {
    let state = state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    let mut notice = state.state_view_publication();
    let guard = notice.begin();
    for (table, _) in choices() {
        assert!(
            capture(&block, table, limits(), u64::MAX)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(guard);
    drop(notice);
    let actual = capture(&block, ActionTable::ByCall, limits(), u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(actual.row_count(), 1);
    drop(actual);
    assert_eq!(pool.reserved_bytes(), baseline);
}

#[test]
fn actual_trigger_removal_keeps_the_predecessor_inverse_and_rollback_original_intact() {
    let state = state(populated());
    let pool = state.ivm_execution_budget();
    let baseline = pool.reserved_bytes();
    let expected = committed(&state, ActionTable::ByCall);
    assert_eq!(expected.row_count(), 1);
    let mut block = state.block(header());
    let mut tx = block.world.triggers.transaction();
    assert!(tx.remove(&"call".parse().unwrap()));
    tx.apply();
    freeze(&mut block);
    for (table, _) in choices() {
        let snapshot = capture(&block, table, limits(), u64::MAX).unwrap().unwrap();
        assert_eq!(snapshot.row_count(), 0);
    }
    drop(block);
    let recovered = committed(&state, ActionTable::ByCall);
    equal(&recovered, &expected);
    drop(recovered);
    drop(expected);
    assert_eq!(pool.reserved_bytes(), baseline);
}
