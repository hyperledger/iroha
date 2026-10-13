//! Scoped preparation from actual State-owned frozen World journals, without finality claims.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_verifying_keys_once,
            grouped_ownership::{GroupImage, GroupMismatch},
        },
        verifying_key_index_validation::test_support as fixture,
    },
    test_allocations::allocations_during,
};
use iroha_data_model::{block::BlockHeader, confidential::ConfidentialStatus};
use mv::{BlockRetirement as _, storage::StorageReadOnly};
use std::num::NonZeroU64;

fn new_state() -> State {
    State::new_for_testing(
        fixture::world(),
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
        max_rows: 2,
        max_payload_bytes: 8192,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 32768,
    }
}
fn stage_version(block: &mut StateBlock<'_>, version: u32) {
    let before = block
        .world
        .verifying_keys
        .get(&fixture::id())
        .unwrap()
        .version;
    let mut value = fixture::record();
    value.version = version;
    value.status = ConfidentialStatus::Withdrawn;
    value.key = None;
    block.world.verifying_keys.insert(fixture::id(), value);
    block
        .world
        .verifying_keys_by_circuit
        .remove(("circuit".into(), before));
    block
        .world
        .verifying_keys_by_circuit
        .insert(("circuit".into(), version), fixture::id());
}
fn freeze_world(block: &mut StateBlock<'_>) {
    // Exercise the real native World capture without asserting that the remaining
    // State tables/cells, execution outputs or finality have been published.
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}

#[test]
fn executing_and_partial_world_freeze_never_yield_an_independent_table_source() {
    let state = new_state();
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header());
    budget.set_limit_bytes(0);
    assert!(capture(&block, limits(), u64::MAX).unwrap().is_none());
    // Even two individually complete fields do not substitute for the original
    // exhaustive World freeze phase owned by the State execution scope.
    block.world.verifying_keys.begin_freeze();
    block.world.verifying_keys_by_circuit.begin_freeze();
    block.world.verifying_keys.finish_freeze();
    block.world.verifying_keys_by_circuit.finish_freeze();
    assert!(capture(&block, limits(), u64::MAX).unwrap().is_none());
}

#[test]
fn exact_original_pool_refusal_and_retry_keep_private_rows_and_encoder_parity() {
    // Pin before owner construction so later global collector progress cannot
    // refund unrelated retired State children across this exact pool baseline.
    // The scoped table's own charged owners still refund on their final drop.
    let _retirement_pin = crossbeam_epoch::pin();
    let state = new_state();
    let budget = state.ivm_execution_budget();
    let mut block = state.block(header());
    stage_version(&mut block, 2);
    let identity = block.world.verifying_keys.publication_identity();
    let inverse_identity = block.world.verifying_keys_by_circuit.publication_identity();
    let pointer = block
        .world
        .verifying_keys
        .get(&fixture::id())
        .unwrap()
        .circuit_id
        .as_ptr();
    freeze_world(&mut block);
    assert_eq!(
        allocations_during(|| {
            let original = Original::retain(&block).unwrap();
            assert_eq!(
                relation::validate(&original.rows, &original.index, &mut Work::bounded(100_000)),
                Ok(())
            );
        }),
        0
    );
    let retained = budget.reserved_bytes();
    let previous_limit = budget.limit_bytes();
    budget.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), 100_000),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(block.world.verifying_keys.publication_identity(), identity);
    assert_eq!(
        block.world.verifying_keys_by_circuit.publication_identity(),
        inverse_identity
    );
    assert_eq!(
        block
            .world
            .verifying_keys
            .get(&fixture::id())
            .unwrap()
            .circuit_id
            .as_ptr(),
        pointer
    );
    budget.set_limit_bytes(previous_limit);
    for (small, expected) in [
        (
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            LeafError::RowLimit,
        ),
        (
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            LeafError::PayloadLimit,
        ),
    ] {
        assert_eq!(capture(&block, small, 100_000).err(), Some(expected));
        assert_eq!(budget.reserved_bytes(), retained);
        assert_eq!(block.world.verifying_keys.publication_identity(), identity);
        assert_eq!(
            block.world.verifying_keys_by_circuit.publication_identity(),
            inverse_identity
        );
    }
    let snapshot = capture(&block, limits(), 100_000).unwrap().unwrap();
    assert_eq!(snapshot.table_id(), "world.verifying_keys");
    assert_eq!(snapshot.row_count(), 1);
    assert!(budget.reserved_bytes() > retained);
    let expected = new_state();
    {
        let mut rows = expected.world.verifying_keys.block();
        let mut value = fixture::record();
        value.version = 2;
        value.status = ConfidentialStatus::Withdrawn;
        value.key = None;
        rows.insert(fixture::id(), value);
        rows.commit();
        let mut index = expected.world.verifying_keys_by_circuit.block();
        index.remove(("circuit".into(), 1));
        index.insert(("circuit".into(), 2), fixture::id());
        index.commit();
    }
    let control = capture_verifying_keys_once(&expected, limits())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.root(), control.root());
    assert_eq!(snapshot.lookup_root(), control.lookup_root());
    assert_eq!(snapshot.ordered_root(), control.ordered_root());
    assert_eq!(
        state
            .world
            .verifying_keys
            .view()
            .get(&fixture::id())
            .unwrap()
            .version,
        1
    );
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn corrupt_current_and_predecessor_refuse_before_any_encoding_budget() {
    // Pin before owner construction so later global collector progress cannot
    // refund unrelated retired State children across this exact pool baseline.
    // The scoped table's own charged owners still refund on their final drop.
    let _retirement_pin = crossbeam_epoch::pin();
    for prior in [false, true] {
        let state = new_state();
        if prior {
            let mut index = state.world.verifying_keys_by_circuit.block();
            index.remove(("circuit".into(), 1));
            index.commit();
        }
        let mut block = state.block(header());
        if prior {
            block
                .world
                .verifying_keys_by_circuit
                .insert(("circuit".into(), 1), fixture::id());
        } else {
            block
                .world
                .verifying_keys_by_circuit
                .remove(("circuit".into(), 1));
        }
        freeze_world(&mut block);
        let source_identity = block.world.verifying_keys.publication_identity();
        let inverse_identity = block.world.verifying_keys_by_circuit.publication_identity();
        let budget = state.ivm_execution_budget();
        let retained = budget.reserved_bytes();
        budget.set_limit_bytes(0);
        assert!(
            matches!(capture(&block, limits(), 100_000), Err(LeafError::GroupedOwnership(GroupedOwnershipError::Corrupt { index: "world.verifying_keys_by_circuit", image, mismatch: GroupMismatch::MissingMember })) if image == if prior { GroupImage::Predecessor } else { GroupImage::Current })
        );
        assert_eq!(
            block.world.verifying_keys.publication_identity(),
            source_identity
        );
        assert_eq!(
            block.world.verifying_keys_by_circuit.publication_identity(),
            inverse_identity
        );
        assert_eq!(budget.reserved_bytes(), retained);
    }
}

#[test]
fn physical_work_refusal_retries_same_original_with_an_explicit_larger_allowance() {
    // Pin before owner construction so later global collector progress cannot
    // refund unrelated retired State children across this exact pool baseline.
    // The scoped table's own charged owners still refund on their final drop.
    let _retirement_pin = crossbeam_epoch::pin();
    let state = new_state();
    let mut block = state.block(header());
    for ordinal in 0..128 {
        block
            .world
            .verifying_keys
            .remove(VerifyingKeyId::new("zz absent", format!("key-{ordinal}")));
    }
    freeze_world(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.current_entries().len(), 1);
    assert_eq!(original.rows.undo_entries().len(), 128);
    let identity = original.rows.publication_identity();
    let budget = state.ivm_execution_budget();
    let retained = budget.reserved_bytes();
    assert!(matches!(
        capture(&block, limits(), 64),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    ));
    assert_eq!(original.rows.publication_identity(), identity);
    assert_eq!(budget.reserved_bytes(), retained);
    let snapshot = capture(&block, limits(), 100_000).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 1);
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn equal_foreign_native_fields_do_not_substitute_for_either_state_source_owner() {
    for foreign_source in [false, true] {
        let state = new_state();
        let foreign = new_state();
        let mut block = state.block(header());
        if foreign_source {
            block.world.verifying_keys.release_writers();
            block.world.verifying_keys =
                crate::state::block_field::BlockField::new(foreign.world.verifying_keys.block());
        } else {
            block.world.verifying_keys_by_circuit.release_writers();
            block.world.verifying_keys_by_circuit = crate::state::block_field::BlockField::new(
                foreign.world.verifying_keys_by_circuit.block(),
            );
        }
        freeze_world(&mut block);
        state.ivm_execution_budget().set_limit_bytes(0);
        // Equal valid row bytes cannot bless a foreign owner or adopt its pool.
        assert!(capture(&block, limits(), u64::MAX).unwrap().is_none());
    }
}
