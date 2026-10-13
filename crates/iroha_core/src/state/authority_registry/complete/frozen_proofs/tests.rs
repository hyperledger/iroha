//! Real proof/status originals, both-image refusals and retained encoding custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{capture_proofs_once, table_capture::frozen::capture_original_table_once},
            grouped_ownership::{GroupImage, GroupMismatch, GroupedOwnershipError},
        },
        block_field::BlockField,
        proof_status_restore,
    },
    test_allocations::allocations_during,
};
use iroha_data_model::block::BlockHeader;
use mv::{BlockRetirement as _, storage::StorageReadOnly};
use std::num::NonZeroU64;

fn id(tag: u8) -> ProofId {
    ProofId {
        backend: "stark/fri".into(),
        proof_hash: [tag; 32],
    }
}
fn record(tag: u8, status: ProofStatus) -> ProofRecord {
    ProofRecord {
        id: id(tag),
        vk_ref: None,
        vk_commitment: None,
        status,
        verified_at_height: None,
        bridge: None,
    }
}
fn world() -> World {
    let mut world = World::default();
    for (tag, status) in [
        ProofStatus::Submitted,
        ProofStatus::Verified,
        ProofStatus::Rejected,
    ]
    .into_iter()
    .enumerate()
    {
        let tag = u8::try_from(tag).expect("fixture value fits u8");
        world.proofs.insert(id(tag), record(tag, status));
    }
    proof_status_restore::rebuild(&mut world);
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
        max_rows: 8,
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
        .proofs
        .insert(id(0), record(0, ProofStatus::Verified));
    block.world.proofs.remove(id(1));
    block
        .world
        .proofs
        .insert(id(3), record(3, ProofStatus::Submitted));
    // A redundant missing removal remains physical predecessor work.
    block.world.proofs.remove(id(9));
    block
        .world
        .proofs_by_status
        .insert(ProofStatus::Submitted, BTreeSet::from([id(3)]));
    block
        .world
        .proofs_by_status
        .insert(ProofStatus::Verified, BTreeSet::from([id(0)]));
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
fn restore_current_index(block: &mut StateBlock<'_>) {
    for (tag, status) in [
        ProofStatus::Submitted,
        ProofStatus::Verified,
        ProofStatus::Rejected,
    ]
    .into_iter()
    .enumerate()
    {
        block.world.proofs_by_status.insert(
            status,
            BTreeSet::from([id(u8::try_from(tag).expect("fixture value fits u8"))]),
        );
    }
}

#[test]
fn moved_deleted_inserted_and_absent_rows_use_one_bounded_original_relation() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.proofs.publication_identity();
    let index_identity = block.world.proofs_by_status.publication_identity();
    freeze(&mut block);
    assert_eq!(
        allocations_during(|| {
            let original = Original::retain(&block).unwrap();
            validate_original_proofs(&original.rows, &original.index, 100_000).unwrap();
        }),
        0
    );
    let original = capture(&block, limits(), 100_000).unwrap().unwrap();
    assert_eq!(original.row_count(), 3);
    let mut expected = World::default();
    for (tag, status) in [
        (0, ProofStatus::Verified),
        (2, ProofStatus::Rejected),
        (3, ProofStatus::Submitted),
    ] {
        expected.proofs.insert(id(tag), record(tag, status));
    }
    proof_status_restore::rebuild(&mut expected);
    let expected = self::state(expected);
    assert_equal(
        &original,
        &capture_proofs_once(&expected, limits()).unwrap().unwrap(),
    );
    let dispatched = capture_original_table_once(&block, "world.proofs", limits(), 100_000)
        .unwrap()
        .unwrap();
    assert_equal(&original, &dispatched);
    assert_eq!(block.world.proofs.publication_identity(), row_identity);
    assert_eq!(
        block.world.proofs_by_status.publication_identity(),
        index_identity
    );
    assert_eq!(
        block
            .world
            .proofs
            .frozen_images()
            .unwrap()
            .undo_entries()
            .find(|(key, _)| *key == &id(9))
            .unwrap()
            .1,
        &None
    );
}

#[test]
fn missing_foreign_empty_and_wrong_status_members_fail_in_both_original_images() {
    for previous in [false, true] {
        for mutation in 0..4 {
            let mut world = world();
            if previous {
                match mutation {
                    0 => {
                        world.proofs_by_status = [
                            (ProofStatus::Verified, BTreeSet::from([id(1)])),
                            (ProofStatus::Rejected, BTreeSet::from([id(2)])),
                        ]
                        .into_iter()
                        .collect();
                    }
                    1 => {
                        world
                            .proofs_by_status
                            .insert(ProofStatus::Verified, BTreeSet::new());
                    }
                    2 => {
                        world
                            .proofs_by_status
                            .insert(ProofStatus::Submitted, BTreeSet::from([id(0), id(9)]));
                    }
                    3 => {
                        world.proofs_by_status = [
                            (ProofStatus::Verified, BTreeSet::from([id(1)])),
                            (ProofStatus::Rejected, BTreeSet::from([id(0), id(2)])),
                        ]
                        .into_iter()
                        .collect();
                    }
                    _ => unreachable!(),
                }
            }
            let state = state(world);
            let mut block = state.block(header());
            if previous {
                restore_current_index(&mut block);
            } else {
                match mutation {
                    0 => {
                        block.world.proofs_by_status.remove(ProofStatus::Submitted);
                    }
                    1 => {
                        block
                            .world
                            .proofs_by_status
                            .insert(ProofStatus::Verified, BTreeSet::new());
                    }
                    2 => {
                        block
                            .world
                            .proofs_by_status
                            .insert(ProofStatus::Submitted, BTreeSet::from([id(0), id(9)]));
                    }
                    3 => {
                        block.world.proofs_by_status.remove(ProofStatus::Submitted);
                        block
                            .world
                            .proofs_by_status
                            .insert(ProofStatus::Rejected, BTreeSet::from([id(0), id(2)]));
                    }
                    _ => unreachable!(),
                }
            }
            freeze(&mut block);
            let expected = GroupedOwnershipError::Corrupt {
                index: "world.proofs_by_status",
                image: if previous {
                    GroupImage::Predecessor
                } else {
                    GroupImage::Current
                },
                mismatch: match mutation {
                    0 | 3 => GroupMismatch::MissingMember,
                    1 => GroupMismatch::EmptyGroup,
                    2 => GroupMismatch::ForeignMember,
                    _ => unreachable!(),
                },
            };
            assert_eq!(
                capture(&block, limits(), 100_000).err(),
                Some(LeafError::GroupedOwnership(expected))
            );
        }
    }
}

#[test]
fn incomplete_foreign_released_and_mixed_mode_pairs_refuse_before_encoding() {
    for replacement in 0..4 {
        let state = state(world());
        let foreign = self::state(world());
        let mut block = state.block(header());
        assert!(capture(&block, limits(), 0).unwrap().is_none());
        if replacement == 0 {
            block.world.proofs.begin_freeze();
            block.world.proofs.finish_freeze();
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            continue;
        }
        match replacement {
            1 => {
                block.world.proofs.release_writers();
                block.world.proofs = BlockField::new(foreign.world.proofs.block());
            }
            2 => {
                block.world.proofs_by_status.release_writers();
                block.world.proofs_by_status =
                    BlockField::new(foreign.world.proofs_by_status.block());
            }
            3 => {
                block.world.proofs_by_status.release_writers();
                block.world.proofs_by_status =
                    BlockField::new(state.world.proofs_by_status.block_and_revert());
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
            block.world.proofs_by_status.release_writers();
        } else {
            block.world.proofs.release_writers();
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn original_pool_and_work_refusals_keep_same_rows_then_refund_final_snapshot() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(world());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let row_identity = block.world.proofs.publication_identity();
    let index_identity = block.world.proofs_by_status.publication_identity();
    let pointer = block.world.proofs.get(&id(0)).unwrap().id.backend.as_ptr();
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
        capture(&block, limits(), 100_000),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    let snapshot = capture(&block, limits(), 100_000).unwrap().unwrap();
    assert!(budget.reserved_bytes() > baseline);
    assert_eq!(block.world.proofs.publication_identity(), row_identity);
    assert_eq!(
        block.world.proofs_by_status.publication_identity(),
        index_identity
    );
    assert_eq!(
        block.world.proofs.get(&id(0)).unwrap().id.backend.as_ptr(),
        pointer
    );
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn later_target_changes_cannot_replace_either_original_checked_image() {
    let state = state(world());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = capture(&block, limits(), 100_000).unwrap().unwrap();
    {
        let mut rows = state.world.proofs.block();
        rows.insert(id(4), record(4, ProofStatus::Submitted));
        rows.commit();
    }
    {
        let mut index = state.world.proofs_by_status.block();
        index.insert(ProofStatus::Submitted, BTreeSet::from([id(0), id(4)]));
        index.commit();
    }
    assert_equal(
        &original,
        &capture(&block, limits(), 100_000).unwrap().unwrap(),
    );
    assert_ne!(
        original.root(),
        capture_proofs_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn real_replacement_retains_rewound_proofs_and_exact_physical_work() {
    let state = state(world());
    {
        let mut rows = state.world.proofs.block();
        rows.insert(id(0), record(0, ProofStatus::Verified));
        rows.commit();
        let mut index = state.world.proofs_by_status.block();
        index.remove(ProofStatus::Submitted);
        index.insert(ProofStatus::Verified, BTreeSet::from([id(0), id(1)]));
        index.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block.world.proofs.get(&id(0)).unwrap().status,
        ProofStatus::Submitted
    );
    block.world.proofs.remove(id(9));
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Replace);
    assert_eq!(original.index.mode(), mv::BlockMode::Replace);
    let mut exact = None;
    for work in 0..10_000 {
        match validate_original_proofs(&original.rows, &original.index, work) {
            Ok(()) => {
                exact = Some(work);
                break;
            }
            Err(GroupedOwnershipError::WorkLimit) => {}
            Err(error) => panic!("valid original replacement relation: {error}"),
        }
    }
    let exact = exact.expect("finite complete original work");
    assert!(exact > 0);
    assert_eq!(
        validate_original_proofs(&original.rows, &original.index, exact - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        allocations_during(
            || validate_original_proofs(&original.rows, &original.index, exact).unwrap()
        ),
        0
    );
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    let expected = self::state(world());
    assert_equal(
        &snapshot,
        &capture_proofs_once(&expected, limits()).unwrap().unwrap(),
    );
}

#[test]
fn original_index_admission_can_defer_empty_bucket_diagnosis_without_success() {
    for previous in [false, true] {
        let mut world = world();
        if previous {
            world
                .proofs_by_status
                .insert(ProofStatus::Submitted, BTreeSet::new());
        }
        let state = state(world);
        let mut block = state.block(header());
        if previous {
            restore_current_index(&mut block);
        } else {
            block
                .world
                .proofs_by_status
                .insert(ProofStatus::Submitted, BTreeSet::new());
        }
        freeze(&mut block);
        let row_identity = block.world.proofs.publication_identity();
        let index_identity = block.world.proofs_by_status.publication_identity();
        // The valid current image costs 264. The predecessor then admits three
        // current plus three undo index rows before inspecting its empty bucket.
        let diagnosis_work = if previous { 264 + 6 } else { 3 };
        let corruption = || GroupedOwnershipError::Corrupt {
            index: "world.proofs_by_status",
            image: if previous {
                GroupImage::Predecessor
            } else {
                GroupImage::Current
            },
            mismatch: GroupMismatch::EmptyGroup,
        };
        for allowance in [diagnosis_work - 1, diagnosis_work, 100_000] {
            assert_eq!(
                capture(&block, limits(), allowance).err(),
                Some(LeafError::GroupedOwnership(if allowance < diagnosis_work {
                    GroupedOwnershipError::WorkLimit
                } else {
                    corruption()
                }))
            );
            assert_eq!(block.world.proofs.publication_identity(), row_identity);
            assert_eq!(
                block.world.proofs_by_status.publication_identity(),
                index_identity
            );
        }
    }
}
