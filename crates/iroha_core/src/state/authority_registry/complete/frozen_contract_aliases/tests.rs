//! Real original alias/lease images, bounded refusals and retained encoding custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_contract_alias_bindings_once,
                table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                contract_alias_test_support::{address, fixture, record},
            },
        },
        block_field::BlockField,
    },
    test_allocations::allocations_during,
};
use iroha_data_model::block::BlockHeader;
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
use std::num::NonZeroU64;

fn world() -> World {
    let mut world = fixture();
    world
        .contract_alias_bindings
        .insert(address(1), record("removed"));
    world
        .contract_alias_bindings
        .insert(address(2), record("untouched"));
    world.rebuild_contract_alias_indexes().unwrap();
    world
}
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
        max_rows: 64,
        max_payload_bytes: 65_536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn stage(block: &mut StateBlock<'_>) {
    let mut renamed = record("renamed");
    renamed.lease_expiry_ms = Some(2);
    renamed.grace_until_ms = Some(3);
    block
        .world
        .contract_alias_bindings
        .insert(address(0), renamed);
    block.world.contract_alias_bindings.remove(address(1));
    block
        .world
        .contract_alias_bindings
        .insert(address(2), record("untouched"));
    block
        .world
        .contract_alias_bindings
        .insert(address(3), record("inserted"));
    block.world.contract_alias_bindings.remove(address(9));
    for name in ["router", "removed"] {
        block.world.contract_aliases.remove(record(name).alias);
    }
    for (name, nonce) in [("renamed", 0), ("untouched", 2), ("inserted", 3)] {
        block
            .world
            .contract_aliases
            .insert(record(name).alias, address(nonce));
    }
    block.world.contract_aliases.remove(record("absent").alias);
}
fn expected_world() -> World {
    let mut world = fixture();
    let mut renamed = record("renamed");
    renamed.lease_expiry_ms = Some(2);
    renamed.grace_until_ms = Some(3);
    world.contract_alias_bindings = Storage::from_iter([
        (address(0), renamed),
        (address(2), record("untouched")),
        (address(3), record("inserted")),
    ]);
    world.rebuild_contract_alias_indexes().unwrap();
    world
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
fn exact_work(original: &Original<'_>) -> u64 {
    let mut low = 0;
    let mut high = 1_000_000;
    validate_original_contract_aliases(&original.rows, &original.index, high).unwrap();
    while low < high {
        let allowance = low + (high - low) / 2;
        match validate_original_contract_aliases(&original.rows, &original.index, allowance) {
            Ok(()) => high = allowance,
            Err(GroupedOwnershipError::WorkLimit) => low = allowance + 1,
            Err(error) => panic!("valid original relation: {error}"),
        }
    }
    low
}

#[test]
fn rename_expired_lease_delete_insert_noop_and_absent_rows_keep_both_original_images() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.contract_alias_bindings.publication_identity();
    let index_identity = block.world.contract_aliases.publication_identity();
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.index.mode(), mv::BlockMode::Ordinary);
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &address(9))
            .unwrap()
            .1
            .is_none()
    );
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &address(2))
            .unwrap()
            .1
            .is_some()
    );
    let exact = exact_work(&original);
    assert_eq!(
        validate_original_contract_aliases(&original.rows, &original.index, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        allocations_during(|| validate_original_contract_aliases(
            &original.rows,
            &original.index,
            exact
        )
        .unwrap()),
        0
    );
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 3);
    let expected = self::state(expected_world());
    assert_equal(
        &snapshot,
        &capture_contract_alias_bindings_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    assert_equal(
        &snapshot,
        &capture_original_table_once(&block, "world.contract_alias_bindings", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        block.world.contract_alias_bindings.publication_identity(),
        row_identity
    );
    assert_eq!(
        block.world.contract_aliases.publication_identity(),
        index_identity
    );
}

#[test]
fn inverse_and_duplicate_defects_reject_current_and_repaired_current_predecessor() {
    for previous in [false, true] {
        for defect in 0..4 {
            let mut state = state(fixture());
            let router = record("router").alias;
            let foreign = record("foreign").alias;
            if previous {
                match defect {
                    0 => state.world.contract_aliases = Storage::new(),
                    1 => {
                        state.world.contract_aliases =
                            Storage::from_iter([(router.clone(), address(1))])
                    }
                    2 => {
                        state
                            .world
                            .contract_aliases
                            .insert(foreign.clone(), address(0));
                    }
                    3 => {
                        state
                            .world
                            .contract_alias_bindings
                            .insert(address(1), record("router"));
                    }
                    _ => unreachable!(),
                }
            }
            let mut block = state.block(header());
            if previous {
                if defect < 2 {
                    block
                        .world
                        .contract_aliases
                        .insert(router.clone(), address(0));
                }
                if defect == 2 {
                    block.world.contract_aliases.remove(foreign);
                }
                if defect == 3 {
                    block.world.contract_alias_bindings.remove(address(1));
                }
            } else {
                match defect {
                    0 => {
                        block.world.contract_aliases.remove(router);
                    }
                    1 => {
                        block.world.contract_aliases.insert(router, address(1));
                    }
                    2 => {
                        block.world.contract_aliases.insert(foreign, address(0));
                    }
                    3 => {
                        block
                            .world
                            .contract_alias_bindings
                            .insert(address(1), record("router"));
                    }
                    _ => unreachable!(),
                }
            }
            freeze(&mut block);
            assert_eq!(
                capture(&block, limits(), 1_000_000).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: "world.contract_aliases",
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: if defect == 2 {
                            GroupMismatch::ForeignMember
                        } else {
                            GroupMismatch::MissingMember
                        },
                    }
                ))
            );
        }
    }
}

#[test]
fn every_malformed_lease_window_rejects_either_original_image_without_cleanup() {
    for previous in [false, true] {
        for (expiry, grace, bound) in [
            (None, Some(2), 1),
            (Some(1), None, 1),
            (Some(2), Some(1), 1),
        ] {
            let mut state = state(fixture());
            let mut invalid = record("router");
            invalid.lease_expiry_ms = expiry;
            invalid.grace_until_ms = grace;
            invalid.bound_at_ms = bound;
            if previous {
                state
                    .world
                    .contract_alias_bindings
                    .insert(address(0), invalid.clone());
            }
            let mut block = state.block(header());
            block.world.contract_alias_bindings.insert(
                address(0),
                if previous {
                    record("router")
                } else {
                    invalid.clone()
                },
            );
            freeze(&mut block);
            assert_eq!(
                capture(&block, limits(), 1_000_000).err(),
                Some(LeafError::GroupedOwnership(GroupedOwnershipError::Source {
                    table: "world.contract_alias_bindings",
                    image: if previous {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    reason: crate::state::alias_lease::violation(expiry, grace, bound).unwrap(),
                }))
            );
            let original = Original::retain(&block).unwrap();
            let stored = if previous {
                original
                    .rows
                    .undo_entries()
                    .find(|(key, _)| *key == &address(0))
                    .unwrap()
                    .1
                    .as_ref()
                    .unwrap()
            } else {
                original
                    .rows
                    .current_entries()
                    .find(|(key, _)| *key == &address(0))
                    .unwrap()
                    .1
            };
            assert_eq!(stored, &invalid);
        }
    }
}

#[test]
fn incomplete_foreign_released_and_mixed_acquisition_sources_refuse() {
    for replacement in 0..4 {
        let state = state(world());
        let foreign = self::state(world());
        let mut block = state.block(header());
        assert!(capture(&block, limits(), 0).unwrap().is_none());
        if replacement == 0 {
            block.world.contract_alias_bindings.begin_freeze();
            block.world.contract_alias_bindings.finish_freeze();
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            continue;
        }
        match replacement {
            1 => {
                block.world.contract_alias_bindings.release_writers();
                block.world.contract_alias_bindings =
                    BlockField::new(foreign.world.contract_alias_bindings.block());
            }
            2 => {
                block.world.contract_aliases.release_writers();
                block.world.contract_aliases =
                    BlockField::new(foreign.world.contract_aliases.block());
            }
            3 => {
                block.world.contract_aliases.release_writers();
                block.world.contract_aliases =
                    BlockField::new(state.world.contract_aliases.block_and_revert());
            }
            _ => unreachable!(),
        }
        freeze(&mut block);
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    for release_index in [false, true] {
        let state = state(world());
        let mut block = state.block(header());
        freeze(&mut block);
        if release_index {
            block.world.contract_aliases.release_writers();
        } else {
            block.world.contract_alias_bindings.release_writers();
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn original_pool_refusal_retry_and_last_snapshot_owner_refund_keep_same_rows() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(world());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.contract_alias_bindings.publication_identity();
    let index_identity = block.world.contract_aliases.publication_identity();
    let pointer = core::ptr::from_ref(
        block
            .world
            .contract_alias_bindings
            .get(&address(0))
            .unwrap(),
    );
    freeze(&mut block);
    let baseline = budget.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), 1_000_000),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    for (small, error) in [
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
        assert_eq!(capture(&block, small, 1_000_000).err(), Some(error));
        assert_eq!(budget.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(capture(&block, limits(), 1_000_000).unwrap().unwrap());
    assert!(budget.reserved_bytes() > baseline);
    assert_eq!(
        block.world.contract_alias_bindings.publication_identity(),
        row_identity
    );
    assert_eq!(
        block.world.contract_aliases.publication_identity(),
        index_identity
    );
    assert_eq!(
        core::ptr::from_ref(
            block
                .world
                .contract_alias_bindings
                .get(&address(0))
                .unwrap()
        ),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(budget.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn later_equal_and_changed_target_publications_cannot_refresh_either_original() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    for changed in [false, true] {
        let mut rows = state.world.contract_alias_bindings.block();
        let mut aliases = state.world.contract_aliases.block();
        if changed {
            rows.insert(address(7), record("later"));
            aliases.insert(record("later").alias, address(7));
        }
        rows.commit();
        aliases.commit();
        assert_equal(
            &original,
            &capture(&block, limits(), 1_000_000).unwrap().unwrap(),
        );
    }
    assert_ne!(
        original.root(),
        capture_contract_alias_bindings_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn real_replacement_preserves_rewound_aliases_and_both_original_modes() {
    let state = state(world());
    {
        let mut rows = state.world.contract_alias_bindings.block();
        rows.insert(address(0), record("replacement"));
        rows.commit();
        let mut aliases = state.world.contract_aliases.block();
        aliases.remove(record("router").alias);
        aliases.insert(record("replacement").alias, address(0));
        aliases.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block
            .world
            .contract_alias_bindings
            .get(&address(0))
            .unwrap(),
        &record("router")
    );
    block.world.contract_alias_bindings.remove(address(9));
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Replace);
    assert_eq!(original.index.mode(), mv::BlockMode::Replace);
    let exact = exact_work(&original);
    assert_eq!(
        validate_original_contract_aliases(&original.rows, &original.index, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        allocations_during(|| validate_original_contract_aliases(
            &original.rows,
            &original.index,
            exact
        )
        .unwrap()),
        0
    );
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    let expected = self::state(world());
    assert_equal(
        &snapshot,
        &capture_contract_alias_bindings_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn unadmitted_lease_work_defers_latent_inverse_corruption_without_a_verdict() {
    let state = state(fixture());
    let mut block = state.block(header());
    block.world.contract_aliases.remove(record("router").alias);
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), 32).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(
        capture(&block, limits(), 33).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                index: "world.contract_aliases",
                image: GroupImage::Current,
                mismatch: GroupMismatch::MissingMember,
            }
        ))
    );
}
