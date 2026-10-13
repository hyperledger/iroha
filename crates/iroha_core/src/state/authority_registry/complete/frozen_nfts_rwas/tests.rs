//! Actual NFT/RWA frozen histories, canonical restoration and original-pool custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        LaneConfig, State, World, WorldBlock,
        authority_registry::{
            complete::{
                capture_nfts_once, capture_rwas_once,
                table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError, nft_rwa_test_support as fixture,
            },
        },
        block_field::BlockField,
        snapshot_storage,
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{block::BlockHeader, nft::NftValue, rwa::RwaValue};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
use norito::codec::{DecodeAll, Encode};
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
        max_rows: 16,
        max_payload_bytes: 16384,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 131_072,
    }
}
fn nft(label: &str) -> NftId {
    NftId::new(fixture::domain(), label.parse().unwrap())
}
fn rwa(label: &str) -> RwaId {
    RwaId::generated(fixture::domain(), Hash::new(label.as_bytes()))
}
fn absent_account() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(b"NFT RWA absent owner".to_vec(), Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn other_domain() -> DomainId {
    DomainId::try_new("other", "universal").unwrap()
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
fn nft_work(original: &OriginalNfts<'_>) -> u64 {
    fixture::full_nft_work(&original.rows, &original.owners, &original.domains)
}
fn rwa_work(original: &OriginalRwas<'_>) -> u64 {
    fixture::full_rwa_work(
        &original.rows,
        &original.owners,
        &original.statuses,
        &original.frozen,
    )
}
fn initial() -> World {
    let mut world = fixture::fixture();
    let n = world.nfts.view().get(&fixture::nft_id()).unwrap().clone();
    let r = world.rwas.view().get(&fixture::rwa_id()).unwrap().clone();
    for label in ["deleted", "noop", "untouched"] {
        world.nfts.insert(nft(label), n.clone());
        world.rwas.insert(rwa(label), r.clone());
    }
    world.rebuild_nft_owner_index();
    world.rebuild_rwa_indexes();
    world
}
fn replacement_nft() -> NftValue {
    let world = fixture::fixture();
    let mut value = world.nfts.view().get(&fixture::nft_id()).unwrap().clone();
    value.owned_by = BOB_ID.clone();
    value
}
fn replacement_rwa() -> RwaValue {
    let world = fixture::fixture();
    let mut value = world.rwas.view().get(&fixture::rwa_id()).unwrap().clone();
    value.owned_by = BOB_ID.clone();
    value.status = Some("active".parse().unwrap());
    value.is_frozen = true;
    value
}
fn expected() -> World {
    let before = initial();
    let mut world = fixture::fixture();
    world.nfts = before
        .nfts
        .view()
        .iter()
        .filter(|(id, _)| *id != &nft("deleted"))
        .map(|(id, value)| (id.clone(), value.clone()))
        .collect();
    world.rwas = before
        .rwas
        .view()
        .iter()
        .filter(|(id, _)| *id != &rwa("deleted"))
        .map(|(id, value)| (id.clone(), value.clone()))
        .collect();
    world.nfts.insert(fixture::nft_id(), replacement_nft());
    world.rwas.insert(fixture::rwa_id(), replacement_rwa());
    let inserted_nft = before.nfts.view().get(&fixture::nft_id()).unwrap().clone();
    let inserted_rwa = before.rwas.view().get(&fixture::rwa_id()).unwrap().clone();
    world.nfts.insert(nft("inserted"), inserted_nft);
    world.rwas.insert(rwa("inserted"), inserted_rwa);
    world.rebuild_nft_owner_index();
    world.rebuild_rwa_indexes();
    world
}
/// Use the original live index mutators; redundant and absent touches remain real journals.
fn change(block: &mut WorldBlock<'_>) {
    let n = block.nfts.get(&fixture::nft_id()).unwrap().clone();
    let r = block.rwas.get(&fixture::rwa_id()).unwrap().clone();
    let no_op_nft = block.nfts.get(&nft("noop")).unwrap().clone();
    let no_op_rwa = block.rwas.get(&rwa("noop")).unwrap().clone();
    {
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        tx.insert_nft_entry(fixture::nft_id(), replacement_nft());
        tx.insert_rwa_entry(fixture::rwa_id(), replacement_rwa());
        tx.insert_nft_entry(nft("inserted"), n);
        tx.insert_rwa_entry(rwa("inserted"), r);
        tx.insert_nft_entry(nft("noop"), no_op_nft);
        tx.insert_rwa_entry(rwa("noop"), no_op_rwa);
        tx.remove_nft_entry(&nft("deleted")).unwrap();
        let removed_id = rwa("deleted");
        let removed = tx.rwas.remove(removed_id.clone()).unwrap();
        tx.untrack_rwa_owner(&removed_id, &removed.owned_by);
        tx.untrack_rwa_status(&removed_id, &removed.status);
        tx.untrack_rwa_frozen(&removed_id, removed.is_frozen);
        tx.apply();
    }
    block.nfts.remove(nft("absent"));
    block.rwas.remove(rwa("absent"));
    block.nfts_by_owner.remove(absent_account());
    block.nfts_by_domain.remove(other_domain());
    block.rwas_by_owner.remove(absent_account());
    block.rwas_by_status.remove(Some("absent".parse().unwrap()));
}

#[test]
fn ordinary_nft_owner_history_keeps_insert_delete_noop_absence_and_untouched_originals() {
    let state = state(initial());
    let mut block = state.block(header());
    change(&mut block.world);
    freeze(&mut block);
    let original = OriginalNfts::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.owners.mode(),
        original.domains.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &nft("noop")
                && prior.as_ref().is_some_and(|r| r.owned_by == *ALICE_ID))
    );
    assert!(
        !original
            .rows
            .undo_entries()
            .any(|(id, _)| id == &nft("untouched"))
    );
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &nft("absent") && prior.is_none())
    );
    assert!(
        original
            .owners
            .undo_entries()
            .any(|(id, prior)| id == &absent_account() && prior.is_none())
    );
    assert!(
        original
            .domains
            .undo_entries()
            .any(|(id, prior)| id == &other_domain() && prior.is_none())
    );
    let snapshot = capture_nfts(&block, limits(), nft_work(&original))
        .unwrap()
        .unwrap();
    let control = self::state(expected());
    equal(
        &snapshot,
        &capture_nfts_once(&control, limits()).unwrap().unwrap(),
    );
    assert_eq!(snapshot.row_count(), 4);
}

#[test]
fn ordinary_rwa_owner_status_and_frozen_history_retains_none_and_all_original_touches() {
    let state = state(initial());
    let mut block = state.block(header());
    change(&mut block.world);
    freeze(&mut block);
    let original = OriginalRwas::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.owners.mode(),
        original.statuses.mode(),
        original.frozen.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(original.rows.undo_entries().any(|(id, prior)| {
        id == &rwa("noop")
            && prior
                .as_ref()
                .is_some_and(|r| r.status.is_none() && !r.is_frozen)
    }));
    assert!(
        !original
            .rows
            .undo_entries()
            .any(|(id, _)| id == &rwa("untouched"))
    );
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &rwa("absent") && prior.is_none())
    );
    assert!(
        original
            .statuses
            .current_entries()
            .any(|(status, members)| status.is_none() && members.contains(&rwa("untouched")))
    );
    assert!(
        original
            .statuses
            .undo_entries()
            .any(|(status, prior)| status.is_none()
                && prior.as_ref().is_some_and(|members| members.len() == 4))
    );
    let snapshot = capture_rwas(&block, limits(), rwa_work(&original))
        .unwrap()
        .unwrap();
    let control = self::state(expected());
    equal(
        &snapshot,
        &capture_rwas_once(&control, limits()).unwrap().unwrap(),
    );
    assert_eq!(snapshot.row_count(), 4);
}

#[test]
fn replacement_retains_all_seven_rewound_owners_modes_and_original_canonical_rows() {
    let world = initial();
    {
        let mut block = world.block();
        change(&mut block);
        block.commit();
    }
    let state = state(world);
    let mut block = state.block_and_revert(header());
    block.world.nfts.remove(nft("absent"));
    block.world.rwas.remove(rwa("absent"));
    freeze(&mut block);
    let n = OriginalNfts::retain(&block).unwrap();
    let r = OriginalRwas::retain(&block).unwrap();
    for mode in [
        n.rows.mode(),
        n.owners.mode(),
        n.domains.mode(),
        r.rows.mode(),
        r.owners.mode(),
        r.statuses.mode(),
        r.frozen.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    let control = self::state(initial());
    let ns = capture_nfts(&block, limits(), nft_work(&n))
        .unwrap()
        .unwrap();
    let rs = capture_rwas(&block, limits(), rwa_work(&r))
        .unwrap()
        .unwrap();
    equal(
        &ns,
        &capture_nfts_once(&control, limits()).unwrap().unwrap(),
    );
    equal(
        &rs,
        &capture_rwas_once(&control, limits()).unwrap().unwrap(),
    );
    assert_ne!(
        ns.root(),
        capture_nfts_once(&state, limits()).unwrap().unwrap().root()
    );
    assert_ne!(
        rs.root(),
        capture_rwas_once(&state, limits()).unwrap().unwrap().root()
    );
    assert_eq!(
        n.rows
            .current_entries()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>(),
        control
            .world
            .nfts
            .view()
            .iter()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        r.rows
            .current_entries()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>(),
        control
            .world
            .rwas
            .view()
            .iter()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>()
    );
}

macro_rules! alter {
    ($world:expr, tip, $field:ident, $key:expr, $value:expr) => {{
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
    ($world:expr, journal, $field:ident, $key:expr, $value:expr) => {{
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
    ($world:expr, $kind:ident, $case:expr, $restore:expr) => {{
        let case = $case;
        let restore = $restore;
        macro_rules! group {
            ($field:ident, $valid:expr, $foreign:expr, $id:expr) => {{
                let key = if case % 3 == 0 { $valid } else { $foreign };
                let value = if restore {
                    if case % 3 == 0 {
                        Some(BTreeSet::from([$id]))
                    } else {
                        None
                    }
                } else if case % 3 == 0 {
                    None
                } else {
                    Some(if case % 3 == 1 {
                        BTreeSet::new()
                    } else {
                        BTreeSet::from([$id])
                    })
                };
                alter!($world, $kind, $field, key, value);
            }};
        }
        match case / 3 {
            0 => group!(
                nfts_by_owner,
                ALICE_ID.clone(),
                BOB_ID.clone(),
                fixture::nft_id()
            ),
            1 => group!(
                nfts_by_domain,
                fixture::domain(),
                other_domain(),
                fixture::nft_id()
            ),
            2 => group!(
                rwas_by_owner,
                ALICE_ID.clone(),
                BOB_ID.clone(),
                fixture::rwa_id()
            ),
            3 => group!(
                rwas_by_status,
                None,
                Some("foreign".parse().unwrap()),
                fixture::rwa_id()
            ),
            4 => group!(rwas_by_frozen, false, true, fixture::rwa_id()),
            _ => unreachable!(),
        }
    }};
}

#[test]
fn every_five_index_error_keeps_exact_current_or_predecessor_category_before_allocation() {
    for previous in [false, true] {
        for case in 0..15 {
            let state = state(fixture::fixture());
            if previous {
                defect!(state.world, tip, case, false);
            }
            let mut block = state.block(header());
            defect!(block.world, journal, case, previous);
            freeze(&mut block);
            let work = if case < 6 {
                nft_work(&OriginalNfts::retain(&block).unwrap())
            } else {
                rwa_work(&OriginalRwas::retain(&block).unwrap())
            };
            let pool = state.ivm_execution_budget();
            let baseline = pool.reserved_bytes();
            pool.set_limit_bytes(0);
            let actual = fixture::without_allocations(|| {
                if case < 6 {
                    capture_nfts(&block, limits(), work).err()
                } else {
                    capture_rwas(&block, limits(), work).err()
                }
            });
            assert_eq!(
                actual,
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: [
                            "world.nfts_by_owner",
                            "world.nfts_by_domain",
                            "world.rwas_by_owner",
                            "world.rwas_by_status",
                            "world.rwas_by_frozen"
                        ][case / 3],
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: match case % 3 {
                            0 => GroupMismatch::MissingMember,
                            1 => GroupMismatch::EmptyGroup,
                            _ => GroupMismatch::ForeignMember,
                        },
                    }
                ))
            );
            assert_eq!(pool.reserved_bytes(), baseline);
        }
    }
}

#[test]
fn every_foreign_partial_released_and_mixed_original_nft_rwa_owner_refuses() {
    for source in 0..7 {
        for mixed in [false, true] {
            let state = state(fixture::fixture());
            let foreign = self::state(fixture::fixture());
            let mut block = state.block(header());
            assert!(capture_nfts(&block, limits(), 0).unwrap().is_none());
            assert!(capture_rwas(&block, limits(), 0).unwrap().is_none());
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
                0 => replace!(nfts),
                1 => replace!(nfts_by_owner),
                2 => replace!(nfts_by_domain),
                3 => replace!(rwas),
                4 => replace!(rwas_by_owner),
                5 => replace!(rwas_by_status),
                6 => replace!(rwas_by_frozen),
                _ => unreachable!(),
            }
            freeze(&mut block);
            if source < 3 {
                assert!(capture_nfts(&block, limits(), 0).unwrap().is_none());
            } else {
                assert!(capture_rwas(&block, limits(), 0).unwrap().is_none());
            }
        }
        let state = state(fixture::fixture());
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.nfts.release_writers(),
            1 => block.world.nfts_by_owner.release_writers(),
            2 => block.world.nfts_by_domain.release_writers(),
            3 => block.world.rwas.release_writers(),
            4 => block.world.rwas_by_owner.release_writers(),
            5 => block.world.rwas_by_status.release_writers(),
            6 => block.world.rwas_by_frozen.release_writers(),
            _ => unreachable!(),
        }
        if source < 3 {
            assert!(capture_nfts(&block, limits(), 0).unwrap().is_none());
        } else {
            assert!(capture_rwas(&block, limits(), 0).unwrap().is_none());
        }
    }
    let state = state(fixture::fixture());
    let mut block = state.block(header());
    block.world.nfts.begin_freeze();
    block.world.nfts.finish_freeze();
    block.world.rwas.begin_freeze();
    block.world.rwas.finish_freeze();
    assert!(capture_nfts(&block, limits(), 0).unwrap().is_none());
    assert!(capture_rwas(&block, limits(), 0).unwrap().is_none());
}

fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut result = String::new();
    snapshot_storage::serialize(store, &mut result);
    result
}
fn restored<K, V>(store: &Storage<K, V>) -> Storage<K, V>
where
    K: mv::Key + Encode + DecodeAll,
    V: mv::Value + Encode + DecodeAll,
{
    norito::json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("NFT RWA originals", |_, _| true)
        .unwrap()
}
fn canonical_storages(world: &World) -> [String; 7] {
    [
        encoded(&world.nfts),
        encoded(&world.nfts_by_owner),
        encoded(&world.nfts_by_domain),
        encoded(&world.rwas),
        encoded(&world.rwas_by_owner),
        encoded(&world.rwas_by_status),
        encoded(&world.rwas_by_frozen),
    ]
}
fn restored_world(world: &World) -> World {
    let mut recovered = World::default();
    recovered.nfts = restored(&world.nfts);
    recovered.nfts_by_owner = restored(&world.nfts_by_owner);
    recovered.nfts_by_domain = restored(&world.nfts_by_domain);
    recovered.rwas = restored(&world.rwas);
    recovered.rwas_by_owner = restored(&world.rwas_by_owner);
    recovered.rwas_by_status = restored(&world.rwas_by_status);
    recovered.rwas_by_frozen = restored(&world.rwas_by_frozen);
    recovered
}

#[test]
fn canonical_snapshot_storage_restore_keeps_all_current_and_undo_images_and_modes() {
    let world = initial();
    {
        let mut block = world.block();
        change(&mut block);
        block.commit();
    }
    let before = canonical_storages(&world);
    let recovered = restored_world(&world);
    assert_eq!(canonical_storages(&recovered), before);
    assert_eq!(fixture::check(&recovered, false), Ok(()));
    assert_eq!(fixture::check(&recovered, true), Ok(()));
    for replace in [false, true] {
        let state = self::state(restored_world(&recovered));
        let mut block = if replace {
            state.block_and_revert(header())
        } else {
            state.block(header())
        };
        freeze(&mut block);
        let n = OriginalNfts::retain(&block).unwrap();
        let r = OriginalRwas::retain(&block).unwrap();
        let control = self::state(if replace { initial() } else { expected() });
        equal(
            &capture_nfts(&block, limits(), nft_work(&n))
                .unwrap()
                .unwrap(),
            &capture_nfts_once(&control, limits()).unwrap().unwrap(),
        );
        equal(
            &capture_rwas(&block, limits(), rwa_work(&r))
                .unwrap()
                .unwrap(),
            &capture_rwas_once(&control, limits()).unwrap().unwrap(),
        );
        assert_eq!(
            n.rows.mode(),
            if replace {
                mv::BlockMode::Replace
            } else {
                mv::BlockMode::Ordinary
            }
        );
        assert_eq!(
            r.rows.mode(),
            if replace {
                mv::BlockMode::Replace
            } else {
                mv::BlockMode::Ordinary
            }
        );
    }
    assert_eq!(canonical_storages(&recovered), before);
}

#[test]
fn exact_raw_shapes_and_independent_work_callbacks_cover_both_complete_images() {
    let state = state(fixture::fixture());
    let mut block = state.block(header());
    freeze(&mut block);
    let n = OriginalNfts::retain(&block).unwrap();
    let r = OriginalRwas::retain(&block).unwrap();
    assert_eq!(nft_work(&n), 732);
    assert_eq!(rwa_work(&r), 1482);
    assert_eq!(
        capture_nfts(&block, limits(), 731).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(
        capture_rwas(&block, limits(), 1481).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert!(capture_nfts(&block, limits(), 732).unwrap().is_some());
    assert!(capture_rwas(&block, limits(), 1482).unwrap().is_some());
    let state = self::state(initial());
    let mut block = state.block(header());
    change(&mut block.world);
    freeze(&mut block);
    let n = OriginalNfts::retain(&block).unwrap();
    let r = OriginalRwas::retain(&block).unwrap();
    assert_eq!(
        (
            n.rows.current_entries().count(),
            n.rows.undo_entries().count()
        ),
        (4, 5)
    );
    assert_eq!(
        (
            n.owners.current_entries().count(),
            n.owners.undo_entries().count()
        ),
        (2, 3)
    );
    assert_eq!(
        (
            n.domains.current_entries().count(),
            n.domains.undo_entries().count()
        ),
        (1, 2)
    );
    assert_eq!(
        (
            r.rows.current_entries().count(),
            r.rows.undo_entries().count()
        ),
        (4, 5)
    );
    assert_eq!(
        (
            r.owners.current_entries().count(),
            r.owners.undo_entries().count()
        ),
        (2, 3)
    );
    assert_eq!(
        (
            r.statuses.current_entries().count(),
            r.statuses.undo_entries().count()
        ),
        (2, 3)
    );
    assert_eq!(
        (
            r.frozen.current_entries().count(),
            r.frozen.undo_entries().count()
        ),
        (2, 2)
    );
    let nw = nft_work(&n);
    let rw = rwa_work(&r);
    assert_eq!(
        fixture::without_allocations(|| capture_nfts(&block, limits(), nw - 1).err()),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(
        fixture::without_allocations(|| capture_rwas(&block, limits(), rw - 1).err()),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert!(capture_nfts(&block, limits(), nw).unwrap().is_some());
    assert!(capture_rwas(&block, limits(), rw).unwrap().is_some());
}

#[test]
fn full_canonical_rows_and_all_three_roots_match_existing_raw_and_committed_encoders() {
    let state = state(initial());
    let mut block = state.block(header());
    change(&mut block.world);
    freeze(&mut block);
    let n = OriginalNfts::retain(&block).unwrap();
    let r = OriginalRwas::retain(&block).unwrap();
    let control = self::state(expected());
    let ns = capture_nfts(&block, limits(), nft_work(&n))
        .unwrap()
        .unwrap();
    let rs = capture_rwas(&block, limits(), rwa_work(&r))
        .unwrap()
        .unwrap();
    equal(
        &ns,
        &capture_original_table_once(&block, "world.nfts", limits(), nft_work(&n))
            .unwrap()
            .unwrap(),
    );
    equal(
        &rs,
        &capture_original_table_once(&block, "world.rwas", limits(), rwa_work(&r))
            .unwrap()
            .unwrap(),
    );
    equal(
        &ns,
        &capture_nfts_once(&control, limits()).unwrap().unwrap(),
    );
    equal(
        &rs,
        &capture_rwas_once(&control, limits()).unwrap().unwrap(),
    );
    assert_eq!(
        n.rows
            .current_entries()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>(),
        control
            .world
            .nfts
            .view()
            .iter()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        r.rows
            .current_entries()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>(),
        control
            .world
            .rwas
            .view()
            .iter()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn both_original_pools_work_rows_payload_retry_and_last_snapshot_owner_refund() {
    let _pin = crossbeam_epoch::pin();
    for rwa in [false, true] {
        let state = state(initial());
        let pool = state.ivm_execution_budget();
        let original_limit = pool.limit_bytes();
        let mut block = state.block(header());
        change(&mut block.world);
        freeze(&mut block);
        let nft_pointer = core::ptr::from_ref(block.world.nfts.get(&fixture::nft_id()).unwrap());
        let rwa_pointer = core::ptr::from_ref(block.world.rwas.get(&fixture::rwa_id()).unwrap());
        assert!(
            OriginalNfts::retain(&block)
                .unwrap()
                .budget
                .same_pool(&pool)
        );
        assert!(
            OriginalRwas::retain(&block)
                .unwrap()
                .budget
                .same_pool(&pool)
        );
        let work = if rwa {
            rwa_work(&OriginalRwas::retain(&block).unwrap())
        } else {
            nft_work(&OriginalNfts::retain(&block).unwrap())
        };
        let capture = |limits, work| {
            if rwa {
                capture_rwas(&block, limits, work)
            } else {
                capture_nfts(&block, limits, work)
            }
        };
        let baseline = pool.reserved_bytes();
        assert_eq!(
            capture(limits(), 0).err(),
            Some(LeafError::GroupedOwnership(
                GroupedOwnershipError::WorkLimit
            ))
        );
        assert_eq!(pool.reserved_bytes(), baseline);
        pool.set_limit_bytes(0);
        assert!(matches!(
            capture(limits(), work),
            Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
        ));
        assert_eq!(pool.reserved_bytes(), baseline);
        pool.set_limit_bytes(original_limit);
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
            assert_eq!(capture(small, work).err(), Some(error));
            assert_eq!(pool.reserved_bytes(), baseline);
        }
        let snapshot = std::sync::Arc::new(capture(limits(), work).unwrap().unwrap());
        assert!(pool.reserved_bytes() > baseline);
        assert_eq!(
            core::ptr::from_ref(block.world.nfts.get(&fixture::nft_id()).unwrap()),
            nft_pointer
        );
        assert_eq!(
            core::ptr::from_ref(block.world.rwas.get(&fixture::rwa_id()).unwrap()),
            rwa_pointer
        );
        let retained = snapshot.clone();
        drop(snapshot);
        assert!(pool.reserved_bytes() > baseline);
        drop(retained);
        assert_eq!(pool.reserved_bytes(), baseline);
    }
}

#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_original_nft_rwa_owner() {
    for source in 0..7 {
        for changed in [false, true] {
            let state = state(initial());
            let mut block = state.block(header());
            change(&mut block.world);
            freeze(&mut block);
            let n = OriginalNfts::retain(&block).unwrap();
            let r = OriginalRwas::retain(&block).unwrap();
            let n_identity = n.rows.publication_identity();
            let r_identity = r.rows.publication_identity();
            let ns = capture_nfts(&block, limits(), nft_work(&n))
                .unwrap()
                .unwrap();
            let rs = capture_rwas(&block, limits(), rwa_work(&r))
                .unwrap()
                .unwrap();
            macro_rules! publish {
                ($field:ident, $key:expr, $value:expr) => {{
                    let mut target = state.world.$field.block();
                    if changed {
                        target.insert($key, $value);
                    }
                    target.commit();
                }};
            }
            match source {
                0 => publish!(nfts, nft("later"), replacement_nft()),
                1 => publish!(
                    nfts_by_owner,
                    absent_account(),
                    BTreeSet::from([fixture::nft_id()])
                ),
                2 => publish!(
                    nfts_by_domain,
                    other_domain(),
                    BTreeSet::from([fixture::nft_id()])
                ),
                3 => publish!(rwas, rwa("later"), replacement_rwa()),
                4 => publish!(
                    rwas_by_owner,
                    absent_account(),
                    BTreeSet::from([fixture::rwa_id()])
                ),
                5 => publish!(
                    rwas_by_status,
                    Some("later".parse().unwrap()),
                    BTreeSet::from([fixture::rwa_id()])
                ),
                6 => publish!(rwas_by_frozen, false, BTreeSet::from([rwa("later")])),
                _ => unreachable!(),
            }
            assert_eq!(n.rows.publication_identity(), n_identity);
            assert_eq!(r.rows.publication_identity(), r_identity);
            equal(
                &capture_nfts(&block, limits(), nft_work(&n))
                    .unwrap()
                    .unwrap(),
                &ns,
            );
            equal(
                &capture_rwas(&block, limits(), rwa_work(&r))
                    .unwrap()
                    .unwrap(),
                &rs,
            );
        }
    }
}
