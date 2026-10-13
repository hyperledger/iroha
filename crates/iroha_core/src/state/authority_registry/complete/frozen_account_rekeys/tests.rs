//! Genuine four-owner frozen rekey cuts, canonical restoration and original-pool lifetime.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_account_rekey_records_once,
                table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                account_rekey_test_support as fixture,
            },
        },
        block_field::BlockField,
        snapshot_storage,
    },
};
use iroha_data_model::{
    account::AccountRekeyTransitionProvenance as Provenance, block::BlockHeader,
};
use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID};
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
use norito::codec::{DecodeAll, Encode};
use std::{collections::BTreeMap, num::NonZeroU64};
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
        max_rows: 16,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
fn exact(original: &Original<'_>) -> u64 {
    fixture::full_work(
        &original.rows,
        &original.accounts,
        &original.aliases,
        &original.occurrences,
    )
}
fn replacement() -> AccountRekeyRecord {
    fixture::record()
        .reassign_alias_to_account(ALICE_ID.clone())
        .unwrap()
}
fn initial() -> World {
    let mut world = fixture::fixture();
    for name in ["delete", "noop", "untouched"] {
        let alias = fixture::alias(name);
        let mut record = fixture::record();
        record.label = alias.clone();
        world.account_rekey_records.insert(alias.clone(), record);
        world.account_aliases.insert(alias, BOB_ID.clone());
    }
    world.rebuild_account_rekey_records().unwrap();
    world
}
fn expected() -> World {
    let mut world = initial();
    let mut rows: BTreeMap<_, _> = world
        .account_rekey_records
        .view()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    rows.insert(fixture::alias("wallet"), replacement());
    rows.remove(&fixture::alias("delete"));
    rows.insert(
        fixture::alias("insert"),
        AccountRekeyRecord::new(fixture::alias("insert"), BOB_ID.clone()),
    );
    world.account_rekey_records = rows.into_iter().collect();
    let mut aliases: BTreeMap<_, _> = world
        .account_aliases
        .view()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    aliases.insert(fixture::alias("wallet"), ALICE_ID.clone());
    aliases.remove(&fixture::alias("delete"));
    aliases.insert(fixture::alias("insert"), BOB_ID.clone());
    world.account_aliases = aliases.into_iter().collect();
    world.rebuild_account_rekey_records().unwrap();
    world
}
fn stage(block: &mut StateBlock<'_>) {
    let noop = block
        .world
        .account_rekey_records
        .get(&fixture::alias("noop"))
        .unwrap()
        .clone();
    let account = block.world.accounts.get(&ALICE_ID).unwrap().clone();
    block.world.accounts.insert(ALICE_ID.clone(), account);
    block.world.accounts.remove(CARPENTER_ID.clone());
    block
        .world
        .account_rekey_records
        .insert(fixture::alias("wallet"), replacement());
    block
        .world
        .account_rekey_records
        .remove(fixture::alias("delete"));
    block
        .world
        .account_rekey_records
        .insert(fixture::alias("noop"), noop);
    block.world.account_rekey_records.insert(
        fixture::alias("insert"),
        AccountRekeyRecord::new(fixture::alias("insert"), BOB_ID.clone()),
    );
    block
        .world
        .account_rekey_records
        .remove(fixture::alias("absent"));
    block
        .world
        .account_aliases
        .insert(fixture::alias("wallet"), ALICE_ID.clone());
    block.world.account_aliases.remove(fixture::alias("delete"));
    block
        .world
        .account_aliases
        .insert(fixture::alias("noop"), BOB_ID.clone());
    block
        .world
        .account_aliases
        .insert(fixture::alias("insert"), BOB_ID.clone());
    block.world.account_aliases.remove(fixture::alias("absent"));
    block.world.account_rekey_records_by_account.insert(
        ALICE_ID.clone(),
        BTreeSet::from([
            fixture::alias("wallet"),
            fixture::alias("noop"),
            fixture::alias("untouched"),
        ]),
    );
    block.world.account_rekey_records_by_account.insert(
        BOB_ID.clone(),
        BTreeSet::from([
            fixture::alias("wallet"),
            fixture::alias("noop"),
            fixture::alias("untouched"),
            fixture::alias("insert"),
        ]),
    );
    block
        .world
        .account_rekey_records_by_account
        .remove(CARPENTER_ID.clone());
}
#[test]
fn ordinary_reassignment_insert_delete_noop_absent_and_untouched_rows_keep_four_originals() {
    let state = state(initial());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.accounts.mode(),
        original.aliases.mode(),
        original.occurrences.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(original.rows.undo_entries().any(|(k, v)| {
        k == &fixture::alias("noop")
            && v.as_ref()
                .is_some_and(|r| r == &fixture::record_with_label("noop"))
    }));
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(k, v)| k == &fixture::alias("absent") && v.is_none())
    );
    assert!(
        original
            .accounts
            .undo_entries()
            .any(|(k, v)| k == &*CARPENTER_ID && v.is_none())
    );
    assert!(
        original
            .occurrences
            .undo_entries()
            .any(|(k, v)| k == &*BOB_ID && v.as_ref().is_some_and(|v| v.len() == 4))
    );
    let work = exact(&original);
    assert_eq!(
        capture(&block, limits(), work - 1).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    let snapshot = capture(&block, limits(), work).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 4);
    let control = self::state(expected());
    equal(
        &snapshot,
        &capture_account_rekey_records_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.account_rekey_records", limits(), work)
            .unwrap()
            .unwrap(),
    );
    let actual: Vec<_> = original
        .rows
        .current_entries()
        .map(|(k, v)| (k.encode(), v.encode()))
        .collect();
    assert_eq!(
        actual,
        control
            .world
            .account_rekey_records
            .view()
            .iter()
            .map(|(k, v)| (k.encode(), v.encode()))
            .collect::<Vec<_>>()
    );
}
#[test]
fn replace_rewinds_actual_four_modes_and_complete_canonical_history_bytes() {
    let mut world = fixture::fixture();
    {
        let mut rows = world.account_rekey_records.block();
        rows.insert(fixture::alias("wallet"), replacement());
        rows.commit();
    }
    {
        let mut aliases = world.account_aliases.block();
        aliases.insert(fixture::alias("wallet"), ALICE_ID.clone());
        aliases.commit();
    }
    world.accounts.block().commit();
    world.rebuild_account_rekey_records().unwrap();
    let state = state(world);
    let mut block = state.block_and_revert(header());
    block
        .world
        .account_rekey_records
        .remove(fixture::alias("absent"));
    block.world.accounts.remove(CARPENTER_ID.clone());
    block.world.account_aliases.remove(fixture::alias("absent"));
    block
        .world
        .account_rekey_records_by_account
        .remove(CARPENTER_ID.clone());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.accounts.mode(),
        original.aliases.mode(),
        original.occurrences.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(k, v)| k == &fixture::alias("absent") && v.is_none())
    );
    let snapshot = capture(&block, limits(), exact(&original))
        .unwrap()
        .unwrap();
    let control = self::state(fixture::fixture());
    equal(
        &snapshot,
        &capture_account_rekey_records_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    assert_ne!(
        snapshot.root(),
        capture_account_rekey_records_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
    assert_eq!(
        original
            .rows
            .current_entries()
            .map(|(k, v)| (k.encode(), v.encode()))
            .collect::<Vec<_>>(),
        control
            .world
            .account_rekey_records
            .view()
            .iter()
            .map(|(k, v)| (k.encode(), v.encode()))
            .collect::<Vec<_>>()
    );
}
macro_rules! alter {
    ($world:expr,tip,$field:ident,$key:expr,$value:expr) => {{
        let mut field = $world.$field.block();
        match $value {
            Some(value) => {
                field.insert($key, value);
            }
            None => {
                field.remove($key);
            }
        }
        field.commit();
    }};
    ($world:expr,journal,$field:ident,$key:expr,$value:expr) => {{
        match $value {
            Some(value) => {
                $world.$field.insert($key, value);
            }
            None => {
                $world.$field.remove($key);
            }
        }
    }};
}
macro_rules! defect {
    ($world:expr,$kind:ident,$case:expr,$restore:expr) => {{
        let mut row = fixture::record();
        let restore = $restore;
        match $case {
            0 => {
                if !restore {
                    row.label = fixture::alias("other");
                }
                alter!(
                    $world,
                    $kind,
                    account_rekey_records,
                    fixture::alias("wallet"),
                    Some(row)
                );
            }
            1 => {
                if !restore {
                    row.active_account_id = CARPENTER_ID.clone();
                }
                alter!(
                    $world,
                    $kind,
                    account_rekey_records,
                    fixture::alias("wallet"),
                    Some(row)
                );
            }
            2 => {
                if !restore {
                    row.transition_provenance.clear();
                }
                alter!(
                    $world,
                    $kind,
                    account_rekey_records,
                    fixture::alias("wallet"),
                    Some(row)
                );
            }
            3 => alter!(
                $world,
                $kind,
                account_rekey_records_by_account,
                ALICE_ID.clone(),
                if restore {
                    Some(BTreeSet::from([fixture::alias("wallet")]))
                } else {
                    None
                }
            ),
            4 => alter!(
                $world,
                $kind,
                account_rekey_records_by_account,
                CARPENTER_ID.clone(),
                if restore { None } else { Some(BTreeSet::new()) }
            ),
            5 => alter!(
                $world,
                $kind,
                account_rekey_records_by_account,
                BOB_ID.clone(),
                Some(if restore {
                    BTreeSet::from([fixture::alias("wallet")])
                } else {
                    BTreeSet::from([fixture::alias("wallet"), fixture::alias("missing")])
                })
            ),
            _ => unreachable!(),
        }
    }};
}
#[test]
fn frozen_source_and_exact_occurrence_categories_reject_in_either_image_before_allocation() {
    for previous in [false, true] {
        for case in 0..6 {
            let state = state(fixture::fixture());
            if previous {
                defect!(state.world, tip, case, false);
            }
            let mut block = state.block(header());
            defect!(block.world, journal, case, previous);
            freeze(&mut block);
            let original = Original::retain(&block).unwrap();
            let work = exact(&original);
            let pool = state.ivm_execution_budget();
            let baseline = pool.reserved_bytes();
            pool.set_limit_bytes(0);
            let image = if previous {
                GroupImage::Predecessor
            } else {
                GroupImage::Current
            };
            let error = if case < 3 {
                GroupedOwnershipError::Source {
                    table: "world.account_rekey_records",
                    image,
                    reason: [
                        "record label differs from its storage key",
                        "active account is absent",
                        "transition provenance length differs from account history",
                    ][case],
                }
            } else {
                GroupedOwnershipError::Corrupt {
                    index: "world.account_rekey_records_by_account",
                    image,
                    mismatch: [
                        GroupMismatch::MissingMember,
                        GroupMismatch::EmptyGroup,
                        GroupMismatch::ForeignMember,
                    ][case - 3],
                }
            };
            let mut actual = None;
            assert_eq!(
                crate::test_allocations::allocations_during(
                    || actual = Some(capture(&block, limits(), work))
                ),
                0
            );
            assert_eq!(
                actual.unwrap().err(),
                Some(LeafError::GroupedOwnership(error))
            );
            assert_eq!(pool.reserved_bytes(), baseline);
        }
    }
}
#[test]
fn every_foreign_released_partial_and_mixed_field_refuses_without_refresh() {
    for source in 0..4 {
        for mixed in [false, true] {
            let state = state(fixture::fixture());
            let foreign = self::state(fixture::fixture());
            let mut block = state.block(header());
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            let target = if mixed { &state } else { &foreign };
            macro_rules! replace {
                ($field:ident) => {{
                    block.world.$field.release_writers();
                    block.world.$field = BlockField::new(if mixed {
                        target.world.$field.block_and_revert()
                    } else {
                        target.world.$field.block()
                    });
                }};
            }
            match source {
                0 => replace!(account_rekey_records),
                1 => replace!(accounts),
                2 => replace!(account_aliases),
                3 => replace!(account_rekey_records_by_account),
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    for source in 0..4 {
        let state = state(fixture::fixture());
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.account_rekey_records.release_writers(),
            1 => block.world.accounts.release_writers(),
            2 => block.world.account_aliases.release_writers(),
            3 => block
                .world
                .account_rekey_records_by_account
                .release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    let state = state(fixture::fixture());
    let mut block = state.block(header());
    block.world.account_rekey_records.begin_freeze();
    block.world.account_rekey_records.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
}
fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut result = String::new();
    snapshot_storage::serialize(store, &mut result);
    result
}
fn restored<K: mv::Key + Encode + DecodeAll, V: mv::Value + Encode + DecodeAll>(
    store: &Storage<K, V>,
) -> Storage<K, V> {
    norito::json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("account rekey originals", |_, _| true)
        .unwrap()
}
fn canonical(world: &World) -> [String; 4] {
    [
        encoded(&world.account_rekey_records),
        encoded(&world.accounts),
        encoded(&world.account_aliases),
        encoded(&world.account_rekey_records_by_account),
    ]
}
fn restored_world(world: &World) -> World {
    let mut recovered = World::default();
    recovered.account_rekey_records = restored(&world.account_rekey_records);
    recovered.accounts = restored(&world.accounts);
    recovered.account_aliases = restored(&world.account_aliases);
    recovered.account_rekey_records_by_account = restored(&world.account_rekey_records_by_account);
    recovered
}
#[test]
fn canonical_four_map_snapshot_restoration_keeps_current_undo_and_both_modes() {
    let mut world = fixture::fixture();
    {
        let mut rows = world.account_rekey_records.block();
        rows.insert(fixture::alias("wallet"), replacement());
        rows.remove(fixture::alias("absent"));
        rows.commit();
    }
    {
        let mut aliases = world.account_aliases.block();
        aliases.insert(fixture::alias("wallet"), ALICE_ID.clone());
        aliases.commit();
    }
    world.accounts.block().commit();
    world.rebuild_account_rekey_records().unwrap();
    let recovered = restored_world(&world);
    assert_eq!(canonical(&recovered), canonical(&world));
    for replace in [false, true] {
        let state = state(restored_world(&recovered));
        let mut block = if replace {
            state.block_and_revert(header())
        } else {
            state.block(header())
        };
        freeze(&mut block);
        let original = Original::retain(&block).unwrap();
        assert_eq!(
            original.rows.mode(),
            if replace {
                mv::BlockMode::Replace
            } else {
                mv::BlockMode::Ordinary
            }
        );
        assert!(original.budget.same_pool(&state.ivm_execution_budget()));
        let snapshot = capture(&block, limits(), exact(&original))
            .unwrap()
            .unwrap();
        let control = self::state(if replace {
            fixture::fixture()
        } else {
            restored_world(&recovered)
        });
        equal(
            &snapshot,
            &capture_account_rekey_records_once(&control, limits())
                .unwrap()
                .unwrap(),
        );
    }
}
#[test]
fn actual_original_pool_work_row_payload_pointer_and_last_owner_refund_are_retained() {
    let _pin = crossbeam_epoch::pin();
    let state = state(initial());
    let pool = state.ivm_execution_budget();
    let limit = pool.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(
        block
            .world
            .account_rekey_records
            .get(&fixture::alias("wallet"))
            .unwrap(),
    );
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert!(original.budget.same_pool(&pool));
    let work = exact(&original);
    let baseline = pool.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), work - 1).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), work),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(limit);
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
        assert_eq!(capture(&block, small, work).err(), Some(error));
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(capture(&block, limits(), work).unwrap().unwrap());
    assert!(pool.reserved_bytes() > baseline);
    assert_eq!(
        core::ptr::from_ref(
            block
                .world
                .account_rekey_records
                .get(&fixture::alias("wallet"))
                .unwrap()
        ),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(pool.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn later_equal_or_changed_native_publications_keep_all_originals_without_refresh() {
    for source in 0..4 {
        for changed in [false, true] {
            let state = state(fixture::fixture());
            let mut block = state.block(header());
            freeze(&mut block);
            let original = Original::retain(&block).unwrap();
            let identity = original.rows.publication_identity();
            let snapshot = capture(&block, limits(), exact(&original))
                .unwrap()
                .unwrap();
            macro_rules! publish {
                ($field:ident,$key:expr,$value:expr) => {{
                    let mut target = state.world.$field.block();
                    if changed {
                        target.insert($key, $value);
                    }
                    target.commit();
                }};
            }
            match source {
                0 => publish!(
                    account_rekey_records,
                    fixture::alias("later"),
                    fixture::record()
                ),
                1 => {
                    let account = state.world.accounts.view().get(&ALICE_ID).unwrap().clone();
                    publish!(accounts, CARPENTER_ID.clone(), account);
                }
                2 => publish!(account_aliases, fixture::alias("later"), BOB_ID.clone()),
                3 => publish!(
                    account_rekey_records_by_account,
                    CARPENTER_ID.clone(),
                    BTreeSet::from([fixture::alias("wallet")])
                ),
                _ => unreachable!(),
            }
            assert_eq!(original.rows.publication_identity(), identity);
            equal(
                &capture(&block, limits(), exact(&original))
                    .unwrap()
                    .unwrap(),
                &snapshot,
            );
        }
    }
}
#[test]
fn frozen_record_may_outlive_alias_and_reassignment_keeps_audit_without_rekey_authority() {
    let mut world = fixture::fixture();
    world.account_aliases = Storage::new();
    let mut row = fixture::record();
    row.previous_account_ids = vec![BOB_ID.clone(), ALICE_ID.clone(), ALICE_ID.clone()];
    row.transition_provenance = vec![
        Provenance::AccountIdRekey,
        Provenance::AliasReassignment,
        Provenance::AliasReassignment,
    ];
    world
        .account_rekey_records
        .insert(fixture::alias("wallet"), row.clone());
    world.rebuild_account_rekey_records().unwrap();
    let state = state(world);
    let mut block = state.block(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    let snapshot = capture(&block, limits(), exact(&original))
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.row_count(), 1);
    assert_eq!(original.rows.current_entries().next().unwrap().1, &row);
    assert_eq!(row.active_account_id_rekey_predecessors().unwrap(), &[][..]);
    equal(
        &snapshot,
        &capture_account_rekey_records_once(&state, limits())
            .unwrap()
            .unwrap(),
    );
}
