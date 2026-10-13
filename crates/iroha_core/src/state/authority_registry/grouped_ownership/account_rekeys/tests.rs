//! Live rekey checks preserve original images, work bounds and State funding.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, account_rekey_occurrence_index,
        authority_registry::{
            complete::capture_account_rekey_records_once,
            leaf::{LeafError, LeafLimits},
        },
        rebuild_derived_storage_with_previous,
    },
    test_allocations::allocations_during,
};
use iroha_data_model::{
    IntoKeyValue,
    account::{Account, AccountRekeyTransitionProvenance as Provenance},
    prelude::Registrable,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID};
use mv::storage::Storage;
use std::collections::BTreeMap;

fn alias(name: &str) -> AccountAlias {
    AccountAlias::domainless(name.parse().unwrap(), DataSpaceId::UNIVERSAL)
}

fn record() -> AccountRekeyRecord {
    AccountRekeyRecord::new(alias("wallet"), ALICE_ID.clone())
        .reassign_alias_to_account(BOB_ID.clone())
        .unwrap()
}

fn fixture() -> World {
    let mut world = World::default();
    for owner in [&*ALICE_ID, &*BOB_ID] {
        let (id, account) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, account);
    }
    world
        .account_rekey_records
        .insert(alias("wallet"), record());
    world
        .account_aliases
        .insert(alias("wallet"), BOB_ID.clone());
    world.rebuild_account_rekey_records().unwrap();
    world
}

fn reindex(world: &mut World) {
    let (current, previous) = {
        let rows = world
            .account_rekey_records
            .try_committed_view_nonblocking()
            .unwrap();
        let current = account_rekey_occurrence_index(rows.current().iter());
        let mut prior: BTreeMap<_, _> = rows
            .current()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, value) in rows.undo().iter() {
            if let Some(value) = value {
                prior.insert(key.clone(), value.clone());
            } else {
                prior.remove(key);
            }
        }
        (current, account_rekey_occurrence_index(prior.iter()))
    };
    world.account_rekey_records_by_account =
        rebuild_derived_storage_with_previous(current, previous);
}

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedAccountRekeys::capture(world, work).map(|_| ()));
        }),
        0
    );
    result.unwrap()
}

fn image(previous: bool) -> GroupImage {
    if previous {
        GroupImage::Predecessor
    } else {
        GroupImage::Current
    }
}

fn malformed(world: &mut World, bad: AccountRekeyRecord, previous: bool) {
    world.account_rekey_records.insert(alias("wallet"), bad);
    if previous {
        let mut block = world.account_rekey_records.block();
        block.insert(alias("wallet"), record());
        block.commit();
    }
    reindex(world);
}

#[test]
fn reassignment_breaks_lineage_and_deduplicates_all_historical_occurrences() {
    let mut world = fixture();
    let mut history = record();
    history.previous_account_ids = vec![
        BOB_ID.clone(),
        ALICE_ID.clone(),
        ALICE_ID.clone(),
        CARPENTER_ID.clone(),
    ];
    history.transition_provenance = vec![
        Provenance::AccountIdRekey,
        Provenance::AliasReassignment,
        Provenance::AliasReassignment,
        Provenance::AccountIdRekey,
    ];
    world
        .account_rekey_records
        .insert(alias("wallet"), history.clone());
    // A record can outlive the binding; old reassigned controllers can be live
    // and can recur, while only CARPENTER is in the active, retired suffix.
    world.account_aliases = Storage::new();
    world.rebuild_account_rekey_records().unwrap();
    assert_eq!(check(&world, test_support::world_work(&world)), Ok(()));
    let checked = CheckedAccountRekeys::capture(&world, test_support::world_work(&world)).unwrap();
    assert_eq!(
        checked.rows().current().get(&alias("wallet")),
        Some(&history)
    );
    assert_eq!(checked.occurrences.current().len(), 3);
    for (_, labels) in checked.occurrences.current().iter() {
        assert_eq!(labels, &BTreeSet::from([alias("wallet")]));
    }
}

#[test]
fn same_retired_predecessor_can_support_multiple_aliases_for_one_active_account() {
    let mut world = fixture();
    for name in ["wallet", "savings"] {
        let record = AccountRekeyRecord::new(alias(name), CARPENTER_ID.clone())
            .repoint_for_account_id_rekey(BOB_ID.clone())
            .unwrap();
        world.account_rekey_records.insert(alias(name), record);
    }
    world.rebuild_account_rekey_records().unwrap();
    assert_eq!(check(&world, test_support::world_work(&world)), Ok(()));
}

#[test]
fn source_label_account_and_provenance_failures_reject_in_either_image() {
    for previous in [false, true] {
        for defect in 0..3 {
            let mut world = fixture();
            let mut bad = record();
            let reason = match defect {
                0 => {
                    bad.label = alias("other");
                    "record label differs from its storage key"
                }
                1 => {
                    bad.active_account_id = CARPENTER_ID.clone();
                    "active account is absent"
                }
                2 => {
                    bad.transition_provenance.clear();
                    "transition provenance length differs from account history"
                }
                _ => unreachable!(),
            };
            malformed(&mut world, bad.clone(), previous);
            assert_eq!(
                check(&world, test_support::world_work(&world)),
                Err(source(image(previous), reason))
            );
            let rows = world
                .account_rekey_records
                .try_committed_view_nonblocking()
                .unwrap();
            assert_eq!(get_at(&rows, image(previous), &alias("wallet")), Some(&bad));
        }
    }
}

#[test]
fn phone_like_labels_reject_without_allocating_or_repairing_either_image() {
    for previous in [false, true] {
        let mut world = fixture();
        world.account_aliases = Storage::new();
        world.account_rekey_records = Storage::new();
        let phone = alias("+819398553445");
        world.account_rekey_records.insert(
            phone.clone(),
            AccountRekeyRecord::new(phone.clone(), BOB_ID.clone()),
        );
        if previous {
            let mut block = world.account_rekey_records.block();
            block.remove(phone);
            block.insert(alias("wallet"), record());
            block.commit();
        }
        reindex(&mut world);
        assert_eq!(
            check(&world, test_support::world_work(&world)),
            Err(source(image(previous), "record label looks like raw PII"))
        );
    }
}

#[test]
fn active_suffix_requires_retirement_and_no_repeated_predecessors() {
    for previous in [false, true] {
        for defect in 0..3 {
            let mut world = fixture();
            let mut bad = record();
            let reason = if defect == 2 {
                bad.previous_account_ids = vec![CARPENTER_ID.clone(), CARPENTER_ID.clone()];
                bad.transition_provenance = vec![Provenance::AccountIdRekey; 2];
                "active rekey predecessor is repeated"
            } else {
                bad.previous_account_ids = vec![if defect == 0 {
                    ALICE_ID.clone()
                } else {
                    BOB_ID.clone()
                }];
                bad.transition_provenance = vec![Provenance::AccountIdRekey];
                "active rekey predecessor remains live"
            };
            malformed(&mut world, bad, previous);
            assert_eq!(
                check(&world, test_support::world_work(&world)),
                Err(source(image(previous), reason))
            );
        }
    }
}

#[test]
fn cross_record_cycles_and_ambiguous_retired_targets_reject_at_both_cuts() {
    for previous in [false, true] {
        for cycle in [false, true] {
            let mut world = fixture();
            let first = AccountRekeyRecord::new(
                alias("wallet"),
                if cycle {
                    ALICE_ID.clone()
                } else {
                    CARPENTER_ID.clone()
                },
            )
            .repoint_for_account_id_rekey(BOB_ID.clone())
            .unwrap();
            let second = AccountRekeyRecord::new(
                alias("second"),
                if cycle {
                    BOB_ID.clone()
                } else {
                    CARPENTER_ID.clone()
                },
            )
            .repoint_for_account_id_rekey(ALICE_ID.clone())
            .unwrap();
            world.account_rekey_records.insert(alias("wallet"), first);
            world.account_rekey_records.insert(alias("second"), second);
            if previous {
                let mut block = world.account_rekey_records.block();
                block.insert(alias("wallet"), record());
                block.remove(alias("second"));
                block.commit();
            }
            reindex(&mut world);
            assert_eq!(
                check(&world, test_support::world_work(&world)),
                Err(source(
                    image(previous),
                    if cycle {
                        "active rekey predecessor remains live"
                    } else {
                        "active rekey predecessor has ambiguous targets"
                    }
                ))
            );
        }
    }
}

#[test]
fn alias_bindings_require_live_matching_continuity_in_either_image() {
    for previous in [false, true] {
        for defect in 0..3 {
            let mut world = fixture();
            let (key, value, reason) = match defect {
                0 => (
                    alias("wallet"),
                    CARPENTER_ID.clone(),
                    "alias target account is absent",
                ),
                1 => (
                    alias("missing"),
                    BOB_ID.clone(),
                    "alias has no continuity record",
                ),
                2 => (
                    alias("wallet"),
                    ALICE_ID.clone(),
                    "alias target differs from the active account",
                ),
                _ => unreachable!(),
            };
            world.account_aliases.insert(key.clone(), value);
            if previous {
                let mut block = world.account_aliases.block();
                block.remove(alias("missing"));
                block.insert(alias("wallet"), BOB_ID.clone());
                block.commit();
            }
            assert_eq!(
                check(&world, test_support::world_work(&world)),
                Err(source(image(previous), reason))
            );
        }
    }
}

#[test]
fn omitted_empty_and_foreign_occurrence_buckets_reject_at_both_cuts() {
    for previous in [false, true] {
        for defect in 0..4 {
            let mut world = fixture();
            let mut current = BTreeMap::from([
                (ALICE_ID.clone(), BTreeSet::from([alias("wallet")])),
                (BOB_ID.clone(), BTreeSet::from([alias("wallet")])),
            ]);
            let mismatch = match defect {
                0 => {
                    current.remove(&*ALICE_ID);
                    GroupMismatch::MissingMember
                }
                1 => {
                    current.insert(CARPENTER_ID.clone(), BTreeSet::new());
                    GroupMismatch::EmptyGroup
                }
                2 => {
                    current.get_mut(&*BOB_ID).unwrap().insert(alias("missing"));
                    GroupMismatch::ForeignMember
                }
                3 => {
                    current.insert(CARPENTER_ID.clone(), BTreeSet::from([alias("wallet")]));
                    GroupMismatch::ForeignMember
                }
                _ => unreachable!(),
            };
            world.account_rekey_records_by_account = current.into_iter().collect();
            if previous {
                let mut block = world.account_rekey_records_by_account.block();
                block.insert(ALICE_ID.clone(), BTreeSet::from([alias("wallet")]));
                block.insert(BOB_ID.clone(), BTreeSet::from([alias("wallet")]));
                block.remove(CARPENTER_ID.clone());
                block.commit();
            }
            assert_eq!(
                check(&world, test_support::world_work(&world)),
                Err(corrupt(image(previous), mismatch))
            );
        }
    }
}

#[test]
fn record_rename_deletion_and_insertion_keep_exact_original_predecessor() {
    let mut world = fixture();
    world.account_aliases = Storage::new();
    {
        let mut block = world.account_rekey_records.block();
        block.remove(alias("wallet"));
        block.insert(
            alias("renamed"),
            AccountRekeyRecord::new(alias("renamed"), ALICE_ID.clone()),
        );
        block.remove(alias("absent"));
        block.commit();
    }
    reindex(&mut world);
    assert_eq!(check(&world, test_support::world_work(&world)), Ok(()));
    let checked = CheckedAccountRekeys::capture(&world, test_support::world_work(&world)).unwrap();
    assert_eq!(
        get_at(checked.rows(), GroupImage::Predecessor, &alias("wallet")),
        Some(&record())
    );
    assert!(get_at(checked.rows(), GroupImage::Current, &alias("wallet")).is_none());
    assert!(get_at(checked.rows(), GroupImage::Predecessor, &alias("renamed")).is_none());
    assert!(checked.rows().undo().contains_key(&alias("absent")));
}

#[test]
fn every_original_native_reader_participates_in_the_final_identity_check() {
    for owner in 0..4 {
        let world = fixture();
        let checked =
            CheckedAccountRekeys::capture(&world, test_support::world_work(&world)).unwrap();
        match owner {
            0 => world.account_rekey_records.block().commit(),
            1 => world.accounts.block().commit(),
            2 => world.account_aliases.block().commit(),
            3 => world.account_rekey_records_by_account.block().commit(),
            _ => unreachable!(),
        }
        assert!(!checked.matches_current().unwrap());
    }
}

#[test]
fn exact_work_limit_charges_masked_rows_and_absent_undo_before_filtering() {
    let world = fixture();
    assert_eq!(check(&world, 2451), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 2452), Ok(()));
    {
        let mut block = world.account_rekey_records.block();
        block.insert(alias("wallet"), record());
        block.remove(alias("absent"));
        block.commit();
    }
    assert_eq!(check(&world, 2847), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 2848), Ok(()));
}

#[test]
fn history_searches_are_funded_before_inspection_even_on_invalid_records() {
    let mut bad = record();
    bad.transition_provenance = vec![Provenance::AccountIdRekey; 4096];
    assert_eq!(
        funded_predecessors(&bad, GroupImage::Current, &mut RekeyWork(20495)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        funded_predecessors(&bad, GroupImage::Current, &mut RekeyWork(20496)),
        Err(source(
            GroupImage::Current,
            "transition provenance length differs from account history"
        ))
    );
    let world = fixture();
    let checked = CheckedAccountRekeys::capture(&world, test_support::world_work(&world)).unwrap();
    let record = checked.rows().current().get(&alias("wallet")).unwrap();
    assert_eq!(
        contains_account(
            record.previous_account_ids.iter(),
            &ALICE_ID,
            &mut RekeyWork(0)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        contains_account(
            record.previous_account_ids.iter(),
            &ALICE_ID,
            &mut RekeyWork(69)
        ),
        Ok(true)
    );
    assert_eq!(
        contains_account(
            record.previous_account_ids.iter(),
            &BOB_ID,
            &mut RekeyWork(69)
        ),
        Ok(false)
    );
}

#[test]
fn dense_reassignment_history_defers_locally_then_retries_without_source_mutation() {
    let mut world = fixture();
    let mut dense = record();
    dense.previous_account_ids = vec![ALICE_ID.clone(); 128];
    dense.transition_provenance = vec![Provenance::AliasReassignment; 128];
    world
        .account_rekey_records
        .insert(alias("wallet"), dense.clone());
    world.rebuild_account_rekey_records().unwrap();
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state
        .ivm_execution_budget()
        .set_limit_bytes(16 * 1024 * 1024);
    let checked =
        CheckedAccountRekeys::capture(&state.world, test_support::world_work(&state.world))
            .unwrap();
    let mut limits = LeafLimits {
        max_tables: 1,
        max_rows: 1,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 262_144,
    };
    // The one canonical row fits retention, but its repeated audit history
    // requires more local inspection work. This is not a validity failure.
    assert!(matches!(
        capture_account_rekey_records_once(&state, limits),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    ));
    limits.max_rows = 16;
    let snapshot = capture_account_rekey_records_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.row_count(), 1);
    assert!(checked.matches_current().unwrap());
    assert_eq!(checked.rows().current().get(&alias("wallet")), Some(&dense));
}

#[test]
fn checked_catalog_capture_retains_original_state_pool_refusal_and_retry() {
    let state = State::new_for_testing(
        fixture(),
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
        capture_account_rekey_records_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_account_rekey_records_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), TABLE);
    assert_eq!(snapshot.row_count(), 1);
}
