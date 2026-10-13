//! Genuine frozen State ownership, dispatch, original pool and canonical trigger bytecode parity.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::triggers::{
        set::{CheckedContracts, SetReadOnly, contract_source_work},
        specialized::{SpecializedAction, SpecializedTrigger},
    },
    state::{
        State, World,
        authority_registry::complete::table_capture::frozen::capture_original_table_once,
    },
};
use iroha_data_model::{block::BlockHeader, prelude::*, transaction::IvmBytecode};
use iroha_test_samples::ALICE_ID;
use mv::BlockRetirement as _;
use std::num::NonZeroU64;
fn new_state(world: World) -> State {
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
        Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
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
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
#[test]
fn real_ordinary_and_replace_empty_originals_match_the_committed_encoder() {
    let state = new_state(World::new());
    let pool = state.ivm_execution_budget();
    let expected = {
        let mut checked =
            CheckedContracts::capture(&state.world.triggers, contract_source_work(limits()), &pool)
                .unwrap();
        let outcome = checked.encode(limits());
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original contract source identities"));
        outcome.unwrap()
    };
    for replace in [false, true] {
        let mut block = if replace {
            state.block_and_revert(header())
        } else {
            state.block(header())
        };
        freeze(&mut block);
        let actual = capture(&block, limits(), 1_000_000).unwrap().unwrap();
        equal(&actual, &expected);
        assert_eq!(actual.row_count(), 0);
    }
}
#[test]
fn real_populated_current_and_predecessor_use_the_exact_original_bytecode_projection() {
    let state = new_state(populated());
    let pool = state.ivm_execution_budget();
    let expected = {
        let mut checked =
            CheckedContracts::capture(&state.world.triggers, contract_source_work(limits()), &pool)
                .unwrap();
        let outcome = checked.encode(limits());
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original contract source identities"));
        outcome.unwrap()
    };
    assert_eq!(expected.row_count(), 1);
    let mut block = state.block(header());
    freeze(&mut block);
    let actual = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    equal(&actual, &expected);
    let dispatched = capture_original_table_once(&block, "triggers.contracts", limits(), 1_000_000)
        .unwrap()
        .unwrap();
    equal(&actual, &dispatched);
    assert_eq!(
        state.world.triggers.view().validate_world_contract_rows(),
        Ok(())
    );
}
#[test]
fn executing_partial_foreign_and_released_state_set_never_admit_a_counter() {
    let state = new_state(World::new());
    let foreign = new_state(World::new());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let baseline = pool.reserved_bytes();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
    block.world.triggers.begin_freeze();
    block.world.triggers.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(block);
    let mut block = state.block(header());
    block.world.triggers = foreign.world.triggers.block();
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    assert!(capture(&block, limits(), 1_000_000).unwrap().is_none());
    assert_eq!(pool.reserved_bytes(), baseline);
    block.world.release_writers();
    assert!(capture(&block, limits(), 1_000_000).unwrap().is_none());
}
#[test]
fn frozen_relation_work_and_encoding_failures_return_without_partial_roots_or_leaked_charge() {
    let state = new_state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    let error = capture(&block, limits(), 0).err().unwrap();
    assert!(matches!(
        error,
        LeafError::TriggerContracts(
            crate::smartcontracts::triggers::set::TriggerContractError::WorkLimit
        )
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(
        capture(
            &block,
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            1_000_000
        )
        .is_err()
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    let actual = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    assert_eq!(actual.row_count(), 1);
    assert!(pool.reserved_bytes() > baseline);
    drop(actual);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn frozen_state_uses_the_original_pool_and_refuses_a_full_counter_before_leaf_encoding() {
    let state = new_state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    let original = pool.limit_bytes();
    pool.set_limit_bytes(baseline);
    let result = capture(&block, limits(), 1_000_000);
    assert!(matches!(
        result,
        Err(LeafError::TriggerContracts(
            crate::smartcontracts::triggers::set::TriggerContractError::Admission(_)
        ))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(original);
    assert_eq!(
        capture(&block, limits(), 1_000_000)
            .unwrap()
            .unwrap()
            .row_count(),
        1
    );
}
#[test]
fn original_state_generation_fence_defers_without_encoding_during_publication() {
    let state = new_state(populated());
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    let mut notice = state.state_view_publication();
    let guard = notice.begin();
    assert!(capture(&block, limits(), 1_000_000).unwrap().is_none());
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(guard);
    drop(notice);
    let snapshot = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 1);
    drop(snapshot);
    assert_eq!(pool.reserved_bytes(), baseline);
}
