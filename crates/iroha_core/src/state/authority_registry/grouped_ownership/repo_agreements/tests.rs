//! Repo participant grouping, retained rollback and original publication custody.

use super::test_support::*;
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_repo_agreements_once,
            leaf::{LeafError, LeafLimits},
        },
    },
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;

#[test]
fn optional_custodian_changes_and_rollback_preserve_exact_original_images() {
    for initial_custodian in [false, true] {
        let mut world = fixture(initial_custodian);
        let original = world.repo_agreements.view().get(&id()).unwrap().clone();
        let mut replacement = original.clone();
        replacement.initiator = BOB_ID.clone();
        replacement.custodian = (!initial_custodian).then(|| ALICE_ID.clone());
        replacement.counterparty = ALICE_ID.clone();
        {
            let mut block = world.block();
            let mut tx =
                block.transaction_without_telemetry(crate::state::LaneConfig::default(), 0);
            tx.insert_repo_agreement_entry(replacement.clone());
            tx.apply();
            block.commit();
        }
        assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
        let mut source_snapshot = String::new();
        crate::state::snapshot_storage::serialize(&world.repo_agreements, &mut source_snapshot);
        world.repo_agreements = norito::json::from_str::<
            crate::state::snapshot_storage::SnapshotStorage,
        >(&source_snapshot)
        .unwrap()
        .decode("repo ownership fixture", |_, _| true)
        .unwrap();
        // Decode the actual canonical snapshot before rebuilding. Keep the real
        // predecessor, including a custodian appearing or disappearing, for rollback.
        world.rebuild_repo_agreement_indexes();
        assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
        let checked = CheckedRepoAgreements::capture(&world, TEST_WORK_ALLOWANCE).unwrap();
        assert_eq!(checked.rows().get(&id()), Some(&replacement));
        assert_eq!(
            get_at(checked.rows(), GroupImage::Predecessor, &id()),
            Some(&original)
        );
        assert!(checked.matches_current().unwrap());
        drop(checked);
        world.block_and_revert().commit();
        assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
        assert_eq!(world.repo_agreements.view().get(&id()), Some(&original));
    }
}

#[test]
fn restored_groups_keep_untouched_members_across_insert_remove_and_rollback() {
    let mut world = fixture(true);
    let original = world.repo_agreements.view().get(&id()).unwrap().clone();
    let mut untouched = original.clone();
    untouched.id = "untouched".parse().unwrap();
    world
        .repo_agreements
        .insert(untouched.id.clone(), untouched.clone());
    world.rebuild_repo_agreement_indexes();
    let mut inserted = original.clone();
    inserted.id = "inserted".parse().unwrap();
    inserted.custodian = None;
    {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(crate::state::LaneConfig::default(), 0);
        tx.remove_repo_agreement_entry(&id());
        tx.insert_repo_agreement_entry(inserted.clone());
        tx.apply();
        block.commit();
    }
    world.rebuild_repo_agreement_indexes();
    assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
    assert_eq!(
        world.repo_agreements_by_initiator.view().get(&ALICE_ID),
        Some(&BTreeSet::from([untouched.id.clone(), inserted.id]))
    );
    world.block_and_revert().commit();
    assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
    assert_eq!(
        world.repo_agreements_by_initiator.view().get(&ALICE_ID),
        Some(&BTreeSet::from([untouched.id, original.id]))
    );
}

#[test]
fn every_group_rejects_missing_members_in_both_native_images() {
    for index in 0..3 {
        for previous in [false, true] {
            let mut world = fixture(true);
            macro_rules! remove {
                ($field:ident, $key:expr) => {{
                    world.$field = Storage::default();
                    if previous {
                        let mut block = world.$field.block();
                        block.insert($key, BTreeSet::from([id()]));
                        block.commit();
                    }
                }};
            }
            let name = match index {
                0 => {
                    remove!(repo_agreements_by_initiator, ALICE_ID.clone());
                    "world.repo_agreements_by_initiator"
                }
                1 => {
                    remove!(repo_agreements_by_custodian, BOB_ID.clone());
                    "world.repo_agreements_by_custodian"
                }
                2 => {
                    remove!(repo_agreements_by_counterparty, BOB_ID.clone());
                    "world.repo_agreements_by_counterparty"
                }
                _ => unreachable!(),
            };
            assert_eq!(
                check(&world, TEST_WORK_ALLOWANCE),
                Err(corrupt(name, previous, GroupMismatch::MissingMember))
            );
        }
    }
}

#[test]
fn absent_custodians_cannot_have_empty_foreign_or_deleted_source_membership() {
    for previous in [false, true] {
        for case in 0..3 {
            let mut world = fixture(false);
            let members = match case {
                0 => BTreeSet::new(),
                1 => BTreeSet::from([id()]),
                _ => BTreeSet::from(["absentrepo".parse().unwrap()]),
            };
            world
                .repo_agreements_by_custodian
                .insert(BOB_ID.clone(), members);
            if previous {
                let mut block = world.repo_agreements_by_custodian.block();
                block.remove(BOB_ID.clone());
                block.commit();
            }
            assert_eq!(
                check(&world, TEST_WORK_ALLOWANCE),
                Err(corrupt(
                    "world.repo_agreements_by_custodian",
                    previous,
                    if case == 0 {
                        GroupMismatch::EmptyGroup
                    } else {
                        GroupMismatch::ForeignMember
                    },
                ))
            );
        }
    }
}

#[test]
fn local_work_counts_custodianless_sources_and_absent_undo_rows() {
    for (custodian, exact, absent_work) in [(false, 816, 140), (true, 1222, 168)] {
        let world = fixture(custodian);
        assert_eq!(check(&world, exact), Ok(()));
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        {
            let mut block = world.repo_agreements.block();
            block.remove("absentundo".parse().unwrap());
            block.commit();
        }
        assert_eq!(
            check(&world, exact + absent_work - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, exact + absent_work), Ok(()));
    }
}

#[test]
fn every_original_reader_detects_even_an_empty_index_publication() {
    for index in 0..4 {
        let world = fixture(false);
        let checked = CheckedRepoAgreements::capture(&world, TEST_WORK_ALLOWANCE).unwrap();
        match index {
            0 => world.repo_agreements.block().commit(),
            1 => world.repo_agreements_by_initiator.block().commit(),
            2 => world.repo_agreements_by_custodian.block().commit(),
            3 => world.repo_agreements_by_counterparty.block().commit(),
            _ => unreachable!(),
        }
        assert!(!checked.matches_current().unwrap());
    }
}

#[test]
fn state_capture_checks_undo_indexes_before_encoding_and_preserves_pool_refusal() {
    let mut world = fixture(false);
    world
        .repo_agreements_by_custodian
        .insert(BOB_ID.clone(), BTreeSet::from([id()]));
    {
        let mut block = world.repo_agreements_by_custodian.block();
        block.remove(BOB_ID.clone());
        block.commit();
    }
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 16,
        max_payload_bytes: 16384,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 131_072,
    };
    let pool = state.ivm_execution_budget();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_repo_agreements_once(&state, limits),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                image: GroupImage::Predecessor,
                mismatch: GroupMismatch::ForeignMember,
                ..
            }
        ))
    ));
    state.world.rebuild_repo_agreement_indexes();
    assert!(matches!(
        capture_repo_agreements_once(
            &state,
            LeafLimits {
                max_rows: 0,
                ..limits
            }
        ),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    ));
    assert!(matches!(
        capture_repo_agreements_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_repo_agreements_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.repo_agreements");
    assert_eq!(snapshot.row_count(), 1);
}
