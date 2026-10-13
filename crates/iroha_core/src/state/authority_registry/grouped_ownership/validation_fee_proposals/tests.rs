//! Original fee-index projection, both images, work and identity regressions.

use super::test_support::{fixture, proposal};
use super::*;
use crate::{state::GovernanceProposalStatus, test_allocations::allocations_during};
use mv::storage::Storage;

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedValidationFeeProposals::capture(world, work).map(|_| ()));
        }),
        0,
        "the original source and lookup require no scratch allocations"
    );
    result.unwrap()
}

fn corrupt(previous: bool, mismatch: GroupMismatch) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index: INDEX,
        image: if previous {
            GroupImage::Predecessor
        } else {
            GroupImage::Current
        },
        mismatch,
    }
}

#[test]
fn both_fee_kinds_keep_every_status_and_non_fee_rows_are_excluded() {
    let mut world = Box::new(World::default());
    let statuses = [
        GovernanceProposalStatus::Proposed,
        GovernanceProposalStatus::Rejected,
        GovernanceProposalStatus::Enacted,
        GovernanceProposalStatus::Superseded,
        GovernanceProposalStatus::ExecutionFailed,
    ];
    for (ordinal, status) in statuses.into_iter().enumerate() {
        for kind in 0..3 {
            let mut row = proposal(kind, 41 + ordinal as u64);
            row.status = status;
            world.governance_proposals.insert(
                [3 * u8::try_from(ordinal).expect("fixture value fits u8") + kind; 32],
                row,
            );
        }
    }
    world.rebuild_governance_read_indexes().unwrap();
    assert_eq!(world.validation_fee_proposal_index.view().len(), 10);
    assert_eq!(check(&world, 40_550), Ok(()));
    assert_eq!(check(&world, 40_549), Err(GroupedOwnershipError::WorkLimit));
}

#[test]
fn moved_removed_retyped_inserted_and_redundant_rows_keep_exact_both_images() {
    let mut world = fixture();
    {
        let mut block = world.governance_proposals.block();
        block.insert([0; 32], proposal(0, 42));
        block.insert([1; 32], proposal(2, 43));
        block.insert([2; 32], proposal(1, 44));
        block.insert([3; 32], proposal(0, 45));
        block.remove([99; 32]);
        block.commit();
    }
    world.rebuild_governance_read_indexes().unwrap();
    assert_eq!(check(&world, 100_000), Ok(()));
    {
        let checked = CheckedValidationFeeProposals::capture(&world, 100_000).unwrap();
        for (key, current, previous) in [([0; 32], 42, 41), ([1; 32], 43, 41), ([2; 32], 44, 41)] {
            assert_eq!(
                get_at(checked.rows(), GroupImage::Current, &key)
                    .unwrap()
                    .created_height,
                current
            );
            assert_eq!(
                get_at(checked.rows(), GroupImage::Predecessor, &key)
                    .unwrap()
                    .created_height,
                previous
            );
        }
        assert!(get_at(checked.rows(), GroupImage::Predecessor, &[3; 32]).is_none());
        assert!(checked.rows().undo().contains_key(&[99; 32]));
        assert!(checked.matches_current().unwrap());
    }
    world.block_and_revert().commit();
    assert_eq!(check(&world, 100_000), Ok(()));
    {
        let mut block = world.governance_proposals.block();
        block.remove([0; 32]);
        block.insert([1; 32], proposal(1, 41));
        block.commit();
    }
    world.rebuild_governance_read_indexes().unwrap();
    assert_eq!(check(&world, 100_000), Ok(()));
}

#[test]
fn omitted_wrong_height_duplicate_non_fee_and_orphan_members_reject_in_both_images() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut world = fixture();
            if defect < 2 {
                world.validation_fee_proposal_index = Storage::from_iter([((41, [1; 32]), ())]);
            }
            let extra = match defect {
                0 => None,
                1 | 2 => Some((42, [0; 32])),
                3 => Some((41, [2; 32])),
                4 => Some((41, [99; 32])),
                _ => unreachable!(),
            };
            if let Some(key) = extra {
                world.validation_fee_proposal_index.insert(key, ());
            }
            if previous {
                let mut block = world.validation_fee_proposal_index.block();
                block.insert((41, [0; 32]), ());
                if let Some(key) = extra {
                    block.remove(key);
                }
                block.commit();
            }
            assert_eq!(
                check(&world, 100_000),
                Err(corrupt(
                    previous,
                    if defect < 2 {
                        GroupMismatch::MissingMember
                    } else {
                        GroupMismatch::ForeignMember
                    }
                ))
            );
        }
    }
}

#[test]
fn omitted_non_fee_rows_and_physical_tombstones_still_consume_exact_work() {
    let world = fixture();
    assert_eq!(check(&world, 1_629), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 1_630), Ok(()));
    {
        let mut block = world.governance_proposals.block();
        block.insert([2; 32], proposal(2, 41));
        block.remove([99; 32]);
        block.commit();
    }
    assert_eq!(check(&world, 2_211), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 2_212), Ok(()));
    {
        let mut block = world.validation_fee_proposal_index.block();
        block.insert((41, [0; 32]), ());
        block.remove((99, [99; 32]));
        block.commit();
    }
    assert_eq!(check(&world, 2_697), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 2_698), Ok(()));
}

#[test]
fn either_original_reader_change_overrides_success_corruption_and_work_refusal() {
    for changed in 0..2 {
        for error in [
            None,
            Some(GroupedOwnershipError::WorkLimit),
            Some(corrupt(false, GroupMismatch::MissingMember)),
        ] {
            let world = fixture();
            let checked = CheckedValidationFeeProposals::retain(&world).unwrap();
            checked.validate(&mut Work(100_000)).unwrap();
            match changed {
                0 => world.governance_proposals.block().commit(),
                1 => world.validation_fee_proposal_index.block().commit(),
                _ => unreachable!(),
            }
            assert!(!checked.matches_current().unwrap());
            assert_eq!(
                checked.finish_validation(error.map_or(Ok(()), Err)).err(),
                Some(GroupedOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}

#[test]
fn one_indexed_row_without_undo_costs_the_named_descriptor_unit() {
    let mut world = World::default();
    world.governance_proposals.insert([0; 32], proposal(0, 41));
    world.rebuild_governance_read_indexes().unwrap();
    assert_eq!(VALIDATION_FEE_PROPOSAL_WORK_PER_ROW, 328);
    assert_eq!(check(&world, 327), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 328), Ok(()));
}

#[test]
fn fixed_comparisons_admit_both_complete_keys_and_physical_refusal_does_not_advance() {
    let mut work = Work(63);
    assert_eq!(
        compare_keys(&[0_u8; 32], &[1_u8; 32], &mut work),
        Err(GroupedOwnershipError::WorkLimit)
    );
    let mut work = Work(64);
    assert_eq!(
        compare_keys(&[0_u8; 32], &[1_u8; 32], &mut work),
        Ok(Ordering::Less)
    );
    assert_eq!(work.0, 0);
    // Height differences cannot skip the ID bytes; ID differences cannot skip
    // the height bytes. Both directions admit the same complete tuple geometry.
    for right in [(42_u64, [0_u8; 32]), (41_u64, [1_u8; 32])] {
        let mut work = Work(79);
        assert_eq!(
            compare_keys(&(41_u64, [0_u8; 32]), &right, &mut work),
            Err(GroupedOwnershipError::WorkLimit)
        );
        let mut work = Work(80);
        assert_eq!(
            compare_keys(&(41_u64, [0_u8; 32]), &right, &mut work),
            Ok(Ordering::Less)
        );
        assert_eq!(work.0, 0);
    }
    let physical = [([0_u8; 32], ())];
    let mut rows = physical.iter().map(|(key, value)| (key, value));
    assert_eq!(
        next_physical(&mut rows, &mut Work(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        next_physical(&mut rows, &mut Work(1)),
        Ok(Some((&[0; 32], &())))
    );
    assert_eq!(next_physical(&mut rows, &mut Work(0)), Ok(None));
}
