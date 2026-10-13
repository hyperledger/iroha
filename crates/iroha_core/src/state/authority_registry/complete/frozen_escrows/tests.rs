//! Actual four-owner escrow histories, exact errors, encoding and retained custody.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{capture_escrows_once, table_capture::frozen::capture_original_table_once},
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError, escrow_test_support as fixture,
            },
        },
        block_field::BlockField,
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::block::BlockHeader;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{BlockRetirement as _, storage::StorageReadOnly};
use norito::codec::Encode;
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
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn named(label: &[u8]) -> EscrowId {
    EscrowId::new(Hash::new(label))
}
fn absent_account() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(b"escrow absent account".to_vec(), Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
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
        &original.sellers,
        &original.buyers,
        &original.statuses,
    )
}
fn initial() -> World {
    let mut world = fixture::fixture(true);
    let record = world
        .asset_escrows
        .view()
        .get(&fixture::id())
        .unwrap()
        .clone();
    for key in [
        named(b"escrow delete"),
        named(b"escrow noop"),
        named(b"escrow untouched"),
    ] {
        let mut record = record.clone();
        record.id = key;
        world.asset_escrows.insert(key, record);
    }
    world.rebuild_escrow_indexes();
    world
}
fn replacement() -> AssetEscrowRecord {
    let world = fixture::fixture(true);
    let mut record = world
        .asset_escrows
        .view()
        .get(&fixture::id())
        .unwrap()
        .clone();
    record.seller = BOB_ID.clone();
    record.buyer = None;
    record.status = AssetEscrowStatus::Accepted;
    record
}
fn insertion() -> AssetEscrowRecord {
    let mut record = replacement();
    record.id = named(b"escrow insert");
    record.seller = ALICE_ID.clone();
    record.buyer = Some(ALICE_ID.clone());
    record.status = AssetEscrowStatus::Locked;
    record
}
fn expected() -> World {
    let mut world = initial();
    world.asset_escrows.insert(fixture::id(), replacement());
    fixture::omit_initial(&mut world.asset_escrows, &named(b"escrow delete"));
    world
        .asset_escrows
        .insert(named(b"escrow insert"), insertion());
    world.rebuild_escrow_indexes();
    world
}
fn stage(block: &mut StateBlock<'_>) {
    let noop = block
        .world
        .asset_escrows
        .get(&named(b"escrow noop"))
        .unwrap()
        .clone();
    block
        .world
        .asset_escrows
        .insert(fixture::id(), replacement());
    block.world.asset_escrows.remove(named(b"escrow delete"));
    block
        .world
        .asset_escrows
        .insert(named(b"escrow noop"), noop);
    block
        .world
        .asset_escrows
        .insert(named(b"escrow insert"), insertion());
    block.world.asset_escrows.remove(named(b"escrow absent"));
    let open = BTreeSet::from([named(b"escrow noop"), named(b"escrow untouched")]);
    let alice = BTreeSet::from([
        named(b"escrow noop"),
        named(b"escrow untouched"),
        named(b"escrow insert"),
    ]);
    block
        .world
        .asset_escrows_by_seller
        .insert(ALICE_ID.clone(), alice);
    block
        .world
        .asset_escrows_by_seller
        .insert(BOB_ID.clone(), BTreeSet::from([fixture::id()]));
    block.world.asset_escrows_by_seller.remove(absent_account());
    block
        .world
        .asset_escrows_by_buyer
        .insert(BOB_ID.clone(), open.clone());
    block
        .world
        .asset_escrows_by_buyer
        .insert(ALICE_ID.clone(), BTreeSet::from([named(b"escrow insert")]));
    block.world.asset_escrows_by_buyer.remove(absent_account());
    block
        .world
        .asset_escrows_by_status
        .insert(AssetEscrowStatus::Open, open);
    block
        .world
        .asset_escrows_by_status
        .insert(AssetEscrowStatus::Accepted, BTreeSet::from([fixture::id()]));
    block.world.asset_escrows_by_status.insert(
        AssetEscrowStatus::Locked,
        BTreeSet::from([named(b"escrow insert")]),
    );
    block
        .world
        .asset_escrows_by_status
        .remove(AssetEscrowStatus::Expired);
}
#[test]
fn ordinary_buyer_migrations_insert_delete_noop_absence_and_untouched_members_retain_originals() {
    let state = state(initial());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.sellers.mode(),
        original.buyers.mode(),
        original.statuses.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(original.rows.undo_entries().any(|(id, prior)| {
        id == &named(b"escrow noop")
            && prior
                .as_ref()
                .is_some_and(|r| r.buyer == Some(BOB_ID.clone()))
    }));
    assert!(
        !original
            .rows
            .undo_entries()
            .any(|(id, _)| id == &named(b"escrow untouched"))
    );
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &named(b"escrow absent") && prior.is_none())
    );
    assert!(
        original
            .buyers
            .undo_entries()
            .any(|(id, prior)| id == &*BOB_ID
                && prior.as_ref().is_some_and(|members| members.len() == 4))
    );
    assert!(
        original
            .sellers
            .undo_entries()
            .any(|(id, prior)| id == &absent_account() && prior.is_none())
    );
    assert!(
        original
            .statuses
            .undo_entries()
            .any(|(id, prior)| id == &AssetEscrowStatus::Expired && prior.is_none())
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
        &capture_escrows_once(&control, limits()).unwrap().unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.asset_escrows", limits(), work)
            .unwrap()
            .unwrap(),
    );
    let actual: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.asset_escrows.view();
    let expected: Vec<_> = view
        .iter()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    assert_eq!(actual, expected);
}
#[test]
fn replacement_keeps_exact_rewound_four_images_modes_and_canonical_bytes() {
    let mut world = fixture::fixture(true);
    {
        let mut rows = world.asset_escrows.block();
        rows.insert(fixture::id(), replacement());
        let mut added = insertion();
        added.id = named(b"discarded tip escrow");
        rows.insert(added.id, added);
        rows.commit();
    }
    world.rebuild_escrow_indexes();
    let state = state(world);
    let mut block = state.block_and_revert(header());
    block.world.asset_escrows.remove(named(b"escrow absent"));
    block.world.asset_escrows_by_seller.remove(absent_account());
    block.world.asset_escrows_by_buyer.remove(absent_account());
    block
        .world
        .asset_escrows_by_status
        .remove(AssetEscrowStatus::Expired);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.sellers.mode(),
        original.buyers.mode(),
        original.statuses.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &named(b"escrow absent") && prior.is_none())
    );
    let control = self::state(fixture::fixture(true));
    let snapshot = capture(&block, limits(), exact(&original))
        .unwrap()
        .unwrap();
    equal(
        &snapshot,
        &capture_escrows_once(&control, limits()).unwrap().unwrap(),
    );
    assert_ne!(
        snapshot.root(),
        capture_escrows_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
    let actual: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.asset_escrows.view();
    assert_eq!(
        actual,
        view.iter()
            .map(|(id, value)| (id.encode(), value.encode()))
            .collect::<Vec<_>>()
    );
}
macro_rules! alter {
    ($target:expr,tip,$field:ident,$key:expr,$value:expr) => {{
        let mut field = $target.$field.block();
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
    ($target:expr,journal,$field:ident,$key:expr,$value:expr) => {{
        match $value {
            Some(value) => {
                $target.$field.insert($key, value);
            }
            None => {
                $target.$field.remove($key);
            }
        }
    }};
}
macro_rules! defect {
    ($world:expr,$kind:ident,$case:expr,$restore:expr) => {{
        let case = $case;
        let restore = $restore;
        macro_rules! group {
            ($field:ident,$valid:expr,$foreign:expr) => {{
                let key = if case % 3 == 0 { $valid } else { $foreign };
                let value = if restore {
                    if case % 3 == 0 {
                        Some(BTreeSet::from([fixture::id()]))
                    } else {
                        None
                    }
                } else {
                    if case % 3 == 0 {
                        None
                    } else {
                        Some(if case % 3 == 1 {
                            BTreeSet::new()
                        } else {
                            BTreeSet::from([fixture::id()])
                        })
                    }
                };
                alter!($world, $kind, $field, key, value);
            }};
        }
        match case / 3 {
            0 => group!(asset_escrows_by_seller, ALICE_ID.clone(), BOB_ID.clone()),
            1 => group!(asset_escrows_by_buyer, BOB_ID.clone(), ALICE_ID.clone()),
            2 => group!(
                asset_escrows_by_status,
                AssetEscrowStatus::Open,
                AssetEscrowStatus::Accepted
            ),
            _ => unreachable!(),
        }
    }};
}
#[test]
fn every_escrow_index_mismatch_rejects_either_original_image_before_allocation() {
    for previous in [false, true] {
        for case in 0..9 {
            let state = state(fixture::fixture(true));
            if previous {
                defect!(state.world, tip, case, false);
            }
            let mut block = state.block(header());
            defect!(block.world, journal, case, previous);
            freeze(&mut block);
            let pool = state.ivm_execution_budget();
            let baseline = pool.reserved_bytes();
            pool.set_limit_bytes(0);
            assert_eq!(
                capture(&block, limits(), 0).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::WorkLimit
                ))
            );
            assert_eq!(
                capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: [
                            "world.asset_escrows_by_seller",
                            "world.asset_escrows_by_buyer",
                            "world.asset_escrows_by_status"
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
fn buyerless_frozen_rows_cannot_have_any_buyer_inverse_membership() {
    let state = state(fixture::fixture(false));
    let mut block = state.block(header());
    block
        .world
        .asset_escrows_by_buyer
        .insert(BOB_ID.clone(), BTreeSet::from([fixture::id()]));
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                index: "world.asset_escrows_by_buyer",
                image: GroupImage::Current,
                mismatch: GroupMismatch::ForeignMember
            }
        ))
    );
}
#[test]
fn each_foreign_released_partial_and_mixed_original_escrow_field_refuses() {
    for source in 0..4 {
        for mixed in [false, true] {
            let state = state(fixture::fixture(true));
            let foreign = self::state(fixture::fixture(true));
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
                0 => replace!(asset_escrows),
                1 => replace!(asset_escrows_by_seller),
                2 => replace!(asset_escrows_by_buyer),
                3 => replace!(asset_escrows_by_status),
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    for source in 0..4 {
        let state = state(fixture::fixture(true));
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.asset_escrows.release_writers(),
            1 => block.world.asset_escrows_by_seller.release_writers(),
            2 => block.world.asset_escrows_by_buyer.release_writers(),
            3 => block.world.asset_escrows_by_status.release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    let state = state(fixture::fixture(true));
    let mut block = state.block(header());
    block.world.asset_escrows.begin_freeze();
    block.world.asset_escrows.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
}
#[test]
fn original_escrow_pool_work_row_payload_retry_and_last_output_owner_refund() {
    let _pin = crossbeam_epoch::pin();
    let state = state(initial());
    let pool = state.ivm_execution_budget();
    let limit = pool.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(block.world.asset_escrows.get(&fixture::id()).unwrap());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE),
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
        assert_eq!(
            capture(&block, small, fixture::TEST_WORK_ALLOWANCE).err(),
            Some(error)
        );
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(
        capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE)
            .unwrap()
            .unwrap(),
    );
    assert!(pool.reserved_bytes() > baseline);
    assert_eq!(
        core::ptr::from_ref(block.world.asset_escrows.get(&fixture::id()).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(pool.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_escrow_original() {
    for source in 0..4 {
        for changed in [false, true] {
            let state = state(initial());
            let mut block = state.block(header());
            stage(&mut block);
            freeze(&mut block);
            let snapshot = capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE)
                .unwrap()
                .unwrap();
            let original = Original::retain(&block).unwrap();
            let identity = original.rows.publication_identity();
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
                0 => publish!(asset_escrows, named(b"later escrow"), replacement()),
                1 => publish!(
                    asset_escrows_by_seller,
                    absent_account(),
                    BTreeSet::from([fixture::id()])
                ),
                2 => publish!(
                    asset_escrows_by_buyer,
                    absent_account(),
                    BTreeSet::from([fixture::id()])
                ),
                3 => publish!(
                    asset_escrows_by_status,
                    AssetEscrowStatus::Expired,
                    BTreeSet::from([fixture::id()])
                ),
                _ => unreachable!(),
            }
            assert_eq!(original.rows.publication_identity(), identity);
            equal(
                &capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE)
                    .unwrap()
                    .unwrap(),
                &snapshot,
            );
        }
    }
}
