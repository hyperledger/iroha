//! Real fee-proposal/index originals, bounded refusals and retained encoding custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_governance_proposals_once,
                table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                validation_fee_proposal_test_support::{fixture, proposal},
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
    world.governance_proposals.insert([4; 32], proposal(0, 41));
    world.governance_proposals.insert([5; 32], proposal(2, 41));
    world.rebuild_governance_read_indexes().unwrap();
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
    block
        .world
        .governance_proposals
        .insert([0; 32], proposal(0, 42));
    block
        .world
        .governance_proposals
        .insert([1; 32], proposal(2, 43));
    block
        .world
        .governance_proposals
        .insert([2; 32], proposal(1, 44));
    block
        .world
        .governance_proposals
        .insert([3; 32], proposal(0, 45));
    block.world.governance_proposals.remove([4; 32]);
    // A no-op and an absent removal are still physical original work.
    block
        .world
        .governance_proposals
        .insert([5; 32], proposal(2, 41));
    block.world.governance_proposals.remove([9; 32]);
    for tag in [0, 1, 4] {
        block
            .world
            .validation_fee_proposal_index
            .remove((41, [tag; 32]));
    }
    for (height, tag) in [(42, 0), (44, 2), (45, 3)] {
        block
            .world
            .validation_fee_proposal_index
            .insert((height, [tag; 32]), ());
    }
    block
        .world
        .validation_fee_proposal_index
        .remove((99, [9; 32]));
}
fn expected_world() -> World {
    let mut world = World::default();
    for (tag, kind, height) in [(0, 0, 42), (1, 2, 43), (2, 1, 44), (3, 0, 45), (5, 2, 41)] {
        world
            .governance_proposals
            .insert([tag; 32], proposal(kind, height));
    }
    world.rebuild_governance_read_indexes().unwrap();
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
    validate_original_validation_fee_proposals(&original.rows, &original.index, high).unwrap();
    while low < high {
        let allowance = low + (high - low) / 2;
        match validate_original_validation_fee_proposals(&original.rows, &original.index, allowance)
        {
            Ok(()) => high = allowance,
            Err(GroupedOwnershipError::WorkLimit) => low = allowance + 1,
            Err(error) => panic!("valid original relation: {error}"),
        }
    }
    low
}

#[test]
fn moved_retyped_deleted_inserted_noop_and_absent_rows_encode_the_checked_originals() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.governance_proposals.publication_identity();
    let index_identity = block
        .world
        .validation_fee_proposal_index
        .publication_identity();
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.index.mode(), mv::BlockMode::Ordinary);
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &[9; 32])
            .unwrap()
            .1
            .is_none()
    );
    assert!(
        original
            .rows
            .undo_entries()
            .find(|(key, _)| *key == &[5; 32])
            .unwrap()
            .1
            .is_some()
    );
    let exact = exact_work(&original);
    assert_eq!(exact, 7_416);
    assert_eq!(
        validate_original_validation_fee_proposals(&original.rows, &original.index, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        allocations_during(|| validate_original_validation_fee_proposals(
            &original.rows,
            &original.index,
            exact
        )
        .unwrap()),
        0
    );
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 5);
    let expected = self::state(expected_world());
    assert_equal(
        &snapshot,
        &capture_governance_proposals_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    assert_equal(
        &snapshot,
        &capture_original_table_once(&block, "world.governance_proposals", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        block.world.governance_proposals.publication_identity(),
        row_identity
    );
    assert_eq!(
        block
            .world
            .validation_fee_proposal_index
            .publication_identity(),
        index_identity
    );
}

#[test]
fn all_five_membership_defects_reject_current_and_repaired_current_predecessor() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut state = state(fixture());
            let extra = match defect {
                0 => None,
                1 | 2 => Some((42, [0; 32])),
                3 => Some((41, [2; 32])),
                4 => Some((41, [99; 32])),
                _ => unreachable!(),
            };
            // State construction rebuilds projections. Establish the bad original
            // predecessor only after that constructor has completed.
            if previous {
                if defect < 2 {
                    state.world.validation_fee_proposal_index =
                        Storage::from_iter([((41, [1; 32]), ())]);
                }
                if let Some(key) = extra {
                    state.world.validation_fee_proposal_index.insert(key, ());
                }
            }
            let mut block = state.block(header());
            if previous {
                block
                    .world
                    .validation_fee_proposal_index
                    .insert((41, [0; 32]), ());
                if let Some(key) = extra {
                    block.world.validation_fee_proposal_index.remove(key);
                }
            } else {
                if defect < 2 {
                    block
                        .world
                        .validation_fee_proposal_index
                        .remove((41, [0; 32]));
                }
                if let Some(key) = extra {
                    block.world.validation_fee_proposal_index.insert(key, ());
                }
            }
            freeze(&mut block);
            assert_eq!(
                capture(&block, limits(), 1_000_000).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: "world.validation_fee_proposal_index",
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: if defect < 2 {
                            GroupMismatch::MissingMember
                        } else {
                            GroupMismatch::ForeignMember
                        },
                    }
                ))
            );
        }
    }
}

#[test]
fn incomplete_either_foreign_or_released_and_mixed_mode_sources_refuse() {
    for replacement in 0..4 {
        let state = state(world());
        let foreign = self::state(world());
        let mut block = state.block(header());
        assert!(capture(&block, limits(), 0).unwrap().is_none());
        if replacement == 0 {
            block.world.governance_proposals.begin_freeze();
            block.world.governance_proposals.finish_freeze();
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            continue;
        }
        match replacement {
            1 => {
                block.world.governance_proposals.release_writers();
                block.world.governance_proposals =
                    BlockField::new(foreign.world.governance_proposals.block());
            }
            2 => {
                block.world.validation_fee_proposal_index.release_writers();
                block.world.validation_fee_proposal_index =
                    BlockField::new(foreign.world.validation_fee_proposal_index.block());
            }
            3 => {
                block.world.validation_fee_proposal_index.release_writers();
                block.world.validation_fee_proposal_index =
                    BlockField::new(state.world.validation_fee_proposal_index.block_and_revert());
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
            block.world.validation_fee_proposal_index.release_writers();
        } else {
            block.world.governance_proposals.release_writers();
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn original_pool_refusal_retry_and_final_snapshot_reclamation_preserve_bytes_and_identities() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(world());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.governance_proposals.publication_identity();
    let index_identity = block
        .world
        .validation_fee_proposal_index
        .publication_identity();
    let pointer = std::ptr::from_ref::<GovernanceProposalRecord>(
        block.world.governance_proposals.get(&[0; 32]).unwrap(),
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
        block.world.governance_proposals.publication_identity(),
        row_identity
    );
    assert_eq!(
        block
            .world
            .validation_fee_proposal_index
            .publication_identity(),
        index_identity
    );
    assert_eq!(
        std::ptr::from_ref::<GovernanceProposalRecord>(
            block.world.governance_proposals.get(&[0; 32]).unwrap()
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
fn later_target_publications_cannot_replace_either_original_checked_image() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = capture(&block, limits(), 1_000_000).unwrap().unwrap();
    {
        let mut rows = state.world.governance_proposals.block();
        rows.insert([7; 32], proposal(0, 41));
        rows.commit();
        let mut index = state.world.validation_fee_proposal_index.block();
        index.insert((41, [7; 32]), ());
        index.commit();
    }
    assert_equal(
        &original,
        &capture(&block, limits(), 1_000_000).unwrap().unwrap(),
    );
    assert_ne!(
        original.root(),
        capture_governance_proposals_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn real_replacement_retains_rewound_proposals_modes_and_exact_physical_work() {
    let state = state(world());
    {
        let mut rows = state.world.governance_proposals.block();
        rows.insert([0; 32], proposal(0, 42));
        rows.commit();
        let mut index = state.world.validation_fee_proposal_index.block();
        index.remove((41, [0; 32]));
        index.insert((42, [0; 32]), ());
        index.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block
            .world
            .governance_proposals
            .get(&[0; 32])
            .unwrap()
            .created_height,
        41
    );
    block.world.governance_proposals.remove([9; 32]);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Replace);
    assert_eq!(original.index.mode(), mv::BlockMode::Replace);
    let exact = exact_work(&original);
    assert_eq!(exact, 5_188);
    assert_eq!(
        validate_original_validation_fee_proposals(&original.rows, &original.index, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        allocations_during(|| validate_original_validation_fee_proposals(
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
        &capture_governance_proposals_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn inadequate_scan_admission_defers_latent_corruption_without_reporting_success() {
    let state = state(fixture());
    let mut block = state.block(header());
    block
        .world
        .validation_fee_proposal_index
        .remove((41, [0; 32]));
    freeze(&mut block);
    // One source visit, one remaining index visit and a complete 80-byte tuple
    // comparison precede the missing-member verdict; the ID difference cannot
    // bypass charging the complete height/id geometry.
    assert_eq!(
        capture(&block, limits(), 81).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(
        capture(&block, limits(), 82).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                index: "world.validation_fee_proposal_index",
                image: GroupImage::Current,
                mismatch: GroupMismatch::MissingMember,
            }
        ))
    );
}
