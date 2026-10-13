//! Real original domain/bucket images, prepaid relation work and retained encoding custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_domains_table_once, table_capture::frozen::capture_original_table_once,
            },
            domain_ownership::{
                DomainOwnershipError, OwnershipImage, OwnershipMismatch,
                test_support::{exact_work, fixture, id, without_allocations},
            },
        },
        block_field::BlockField,
    },
};
use iroha_data_model::{block::BlockHeader, prelude::Registrable};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
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
    block
        .world
        .domains
        .insert(id("moving"), Domain::new(id("moving")).build(&BOB_ID));
    block
        .world
        .domains
        .insert(id("added"), Domain::new(id("added")).build(&ALICE_ID));
    block.world.domains.remove(id("removed"));
    block
        .world
        .domains
        .insert(id("shared"), Domain::new(id("shared")).build(&ALICE_ID));
    block
        .world
        .domains
        .insert(id("untouched"), Domain::new(id("untouched")).build(&BOB_ID));
    block.world.domains.remove(id("absent"));
    block.world.domains_by_owner.insert(
        ALICE_ID.clone(),
        BTreeSet::from([id("added"), id("shared")]),
    );
    block.world.domains_by_owner.insert(
        BOB_ID.clone(),
        BTreeSet::from([id("moving"), id("untouched")]),
    );
}
fn expected_world() -> World {
    let mut world = fixture();
    world.domains = Storage::from_iter([
        (id("moving"), Domain::new(id("moving")).build(&BOB_ID)),
        (id("added"), Domain::new(id("added")).build(&ALICE_ID)),
        (id("shared"), Domain::new(id("shared")).build(&ALICE_ID)),
        (id("untouched"), Domain::new(id("untouched")).build(&BOB_ID)),
    ]);
    world.rebuild_domain_owner_index();
    world
}
fn one_domain() -> World {
    let mut world = World::default();
    world
        .domains
        .insert(id("live"), Domain::new(id("live")).build(&ALICE_ID));
    world.rebuild_domain_owner_index();
    world
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}

#[test]
fn changed_owner_delete_insert_noop_and_absent_rows_keep_both_original_images() {
    let state = state(fixture());
    let mut block = state.block(header());
    stage(&mut block);
    let rows = block.world.domains.publication_identity();
    let index = block.world.domains_by_owner.publication_identity();
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.index.mode(), mv::BlockMode::Ordinary);
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &id("absent"))
            .unwrap()
            .1
            .is_none()
    );
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &id("shared"))
            .unwrap()
            .1
            .is_some()
    );
    let exact = exact_work(&original.rows, &original.index);
    assert_eq!(
        without_allocations(|| validate_original_domain_ownership(
            &original.rows,
            &original.index,
            exact - 1
        )),
        Err(DomainOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_domain_ownership(&original.rows, &original.index, exact)
    })
    .unwrap();
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 4);
    let expected = self::state(expected_world());
    assert_equal(
        &snapshot,
        &capture_domains_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    assert_equal(
        &snapshot,
        &capture_original_table_once(&block, "world.domains", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(block.world.domains.publication_identity(), rows);
    assert_eq!(block.world.domains_by_owner.publication_identity(), index);
}

#[test]
fn missing_wrong_foreign_empty_and_wrong_owner_reject_either_original_image() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut state = state(one_domain());
            if previous {
                match defect {
                    0 => state.world.domains_by_owner = Storage::new(),
                    1 => {
                        state.world.domains_by_owner =
                            Storage::from_iter([(BOB_ID.clone(), BTreeSet::from([id("live")]))])
                    }
                    2 => {
                        state.world.domains_by_owner = Storage::from_iter([(
                            ALICE_ID.clone(),
                            BTreeSet::from([id("live"), id("ghost")]),
                        )])
                    }
                    3 => {
                        state
                            .world
                            .domains_by_owner
                            .insert(BOB_ID.clone(), BTreeSet::new());
                    }
                    4 => {
                        state
                            .world
                            .domains
                            .insert(id("live"), Domain::new(id("live")).build(&BOB_ID));
                    }
                    _ => unreachable!(),
                }
            }
            let mut block = state.block(header());
            if previous {
                match defect {
                    0..=2 => {
                        block
                            .world
                            .domains_by_owner
                            .insert(ALICE_ID.clone(), BTreeSet::from([id("live")]));
                        if defect == 1 {
                            block.world.domains_by_owner.remove(BOB_ID.clone());
                        }
                    }
                    3 => {
                        block.world.domains_by_owner.remove(BOB_ID.clone());
                    }
                    4 => {
                        block
                            .world
                            .domains
                            .insert(id("live"), Domain::new(id("live")).build(&ALICE_ID));
                    }
                    _ => unreachable!(),
                }
            } else {
                match defect {
                    0 => {
                        block.world.domains_by_owner.remove(ALICE_ID.clone());
                    }
                    1 => {
                        block.world.domains_by_owner.remove(ALICE_ID.clone());
                        block
                            .world
                            .domains_by_owner
                            .insert(BOB_ID.clone(), BTreeSet::from([id("live")]));
                    }
                    2 => {
                        block
                            .world
                            .domains_by_owner
                            .insert(ALICE_ID.clone(), BTreeSet::from([id("live"), id("ghost")]));
                    }
                    3 => {
                        block
                            .world
                            .domains_by_owner
                            .insert(BOB_ID.clone(), BTreeSet::new());
                    }
                    4 => {
                        block
                            .world
                            .domains
                            .insert(id("live"), Domain::new(id("live")).build(&BOB_ID));
                    }
                    _ => unreachable!(),
                }
            }
            freeze(&mut block);
            let original = Original::retain(&block).unwrap();
            let error = without_allocations(|| {
                validate_original_domain_ownership(&original.rows, &original.index, 1_000_000)
            })
            .unwrap_err();
            assert_eq!(
                error,
                DomainOwnershipError::Corrupt {
                    image: if previous {
                        OwnershipImage::Predecessor
                    } else {
                        OwnershipImage::Current
                    },
                    mismatch: match defect {
                        2 => OwnershipMismatch::ForeignDomain,
                        3 => OwnershipMismatch::EmptyBucket,
                        _ => OwnershipMismatch::MissingDomain,
                    },
                }
            );
            assert_eq!(
                capture(&block, limits(), 1_000_000).err(),
                Some(LeafError::DomainOwnership(error))
            );
        }
    }
}

#[test]
fn exact_storage_key_owner_relation_has_no_account_or_embedded_id_predicate() {
    let mut world = one_domain();
    world.domains =
        Storage::from_iter([(id("live"), Domain::new(id("different")).build(&ALICE_ID))]);
    assert!(world.accounts.view().is_empty());
    let state = state(world);
    let mut block = state.block(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    without_allocations(|| {
        validate_original_domain_ownership(&original.rows, &original.index, 388)
    })
    .unwrap();
    let snapshot = capture(&block, limits(), 388).unwrap().unwrap();
    assert_equal(
        &snapshot,
        &capture_domains_table_once(&state, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn malformed_typed_owner_equality_is_allocation_free_in_both_original_images() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let owner = AccountId::new(key);
    for previous in [false, true] {
        let mut state = state(one_domain());
        // Build malformed fixture storage outside the measured relation; the
        // relation itself never orders, reparses or clones either retained key.
        if previous {
            state.world.domains =
                Storage::from_iter([(id("live"), Domain::new(id("live")).build(&owner))]);
            state.world.domains_by_owner =
                Storage::from_iter([(owner.clone(), BTreeSet::from([id("live"), id("ghost")]))]);
        }
        let mut block = state.block(header());
        if previous {
            block
                .world
                .domains_by_owner
                .insert(owner.clone(), BTreeSet::from([id("live")]));
        } else {
            // Use the same retained malformed owner for both tables, never parse it.
            block
                .world
                .domains
                .insert(id("live"), Domain::new(id("live")).build(&owner));
            block.world.domains_by_owner.remove(ALICE_ID.clone());
            block
                .world
                .domains_by_owner
                .insert(owner.clone(), BTreeSet::from([id("live"), id("ghost")]));
        }
        freeze(&mut block);
        let original = Original::retain(&block).unwrap();
        assert_eq!(
            without_allocations(|| validate_original_domain_ownership(
                &original.rows,
                &original.index,
                1_000_000
            )),
            Err(DomainOwnershipError::Corrupt {
                image: if previous {
                    OwnershipImage::Predecessor
                } else {
                    OwnershipImage::Current
                },
                mismatch: OwnershipMismatch::ForeignDomain,
            })
        );
    }
}

#[test]
fn incomplete_foreign_released_and_mixed_acquisition_sources_refuse() {
    for replacement in 0..4 {
        let state = state(fixture());
        let foreign = self::state(fixture());
        let mut block = state.block(header());
        assert!(capture(&block, limits(), 0).unwrap().is_none());
        if replacement == 0 {
            block.world.domains.begin_freeze();
            block.world.domains.finish_freeze();
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            continue;
        }
        match replacement {
            1 => {
                block.world.domains.release_writers();
                block.world.domains = BlockField::new(foreign.world.domains.block());
            }
            2 => {
                block.world.domains_by_owner.release_writers();
                block.world.domains_by_owner =
                    BlockField::new(foreign.world.domains_by_owner.block());
            }
            3 => {
                block.world.domains_by_owner.release_writers();
                block.world.domains_by_owner =
                    BlockField::new(state.world.domains_by_owner.block_and_revert());
            }
            _ => unreachable!(),
        }
        freeze(&mut block);
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    for release_index in [false, true] {
        let state = state(fixture());
        let mut block = state.block(header());
        freeze(&mut block);
        if release_index {
            block.world.domains_by_owner.release_writers();
        } else {
            block.world.domains.release_writers();
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn original_pool_refusal_retry_and_last_snapshot_owner_refund_keep_same_rows() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(fixture());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let rows = block.world.domains.publication_identity();
    let index = block.world.domains_by_owner.publication_identity();
    let pointer = core::ptr::from_ref(block.world.domains.get(&id("moving")).unwrap());
    freeze(&mut block);
    let baseline = budget.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::DomainOwnership(DomainOwnershipError::WorkLimit))
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
    assert_eq!(block.world.domains.publication_identity(), rows);
    assert_eq!(block.world.domains_by_owner.publication_identity(), index);
    assert_eq!(
        core::ptr::from_ref(block.world.domains.get(&id("moving")).unwrap()),
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
    let state = state(fixture());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    for changed in [false, true] {
        let mut rows = state.world.domains.block();
        let mut owners = state.world.domains_by_owner.block();
        if changed {
            rows.insert(id("later"), Domain::new(id("later")).build(&ALICE_ID));
            owners.insert(
                ALICE_ID.clone(),
                BTreeSet::from([id("later"), id("moving"), id("removed"), id("shared")]),
            );
        }
        rows.commit();
        owners.commit();
        assert_equal(
            &original,
            &capture(&block, limits(), 1_000_000).unwrap().unwrap(),
        );
    }
    assert_ne!(
        original.root(),
        capture_domains_table_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn real_replacement_preserves_rewound_domains_and_both_original_modes() {
    let state = state(fixture());
    {
        let mut rows = state.world.domains.block();
        rows.insert(id("moving"), Domain::new(id("moving")).build(&BOB_ID));
        rows.commit();
        let mut owners = state.world.domains_by_owner.block();
        owners.insert(
            ALICE_ID.clone(),
            BTreeSet::from([id("removed"), id("shared")]),
        );
        owners.insert(
            BOB_ID.clone(),
            BTreeSet::from([id("moving"), id("untouched")]),
        );
        owners.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block.world.domains.get(&id("moving")).unwrap().owned_by(),
        &*ALICE_ID
    );
    block.world.domains.remove(id("absent"));
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Replace);
    assert_eq!(original.index.mode(), mv::BlockMode::Replace);
    let exact = exact_work(&original.rows, &original.index);
    assert_eq!(
        without_allocations(|| validate_original_domain_ownership(
            &original.rows,
            &original.index,
            exact - 1
        )),
        Err(DomainOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_domain_ownership(&original.rows, &original.index, exact)
    })
    .unwrap();
    let expected = self::state(fixture());
    assert_equal(
        &capture(&block, limits(), exact).unwrap().unwrap(),
        &capture_domains_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn unadmitted_physical_work_defers_latent_missing_bucket_without_a_verdict() {
    let state = state(one_domain());
    let mut block = state.block(header());
    block.world.domains_by_owner.remove(ALICE_ID.clone());
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::DomainOwnership(DomainOwnershipError::WorkLimit))
    );
    assert_eq!(
        capture(&block, limits(), 1).err(),
        Some(LeafError::DomainOwnership(DomainOwnershipError::Corrupt {
            image: OwnershipImage::Current,
            mismatch: OwnershipMismatch::MissingDomain,
        }))
    );
}
