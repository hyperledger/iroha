//! Actual four-owner repo_agreement histories, exact errors, encoding and retained custody.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_repo_agreements_once, table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                repo_agreement_test_support as fixture,
            },
        },
        block_field::BlockField,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
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
fn named(label: &str) -> RepoAgreementId {
    label.parse().unwrap()
}
fn absent_account() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(
            b"repo_agreement absent account".to_vec(),
            Algorithm::Ed25519,
        )
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
        &original.initiators,
        &original.counterparties,
        &original.custodians,
    )
}
fn initial() -> World {
    let mut world = fixture::fixture(true);
    let record = world
        .repo_agreements
        .view()
        .get(&fixture::id())
        .unwrap()
        .clone();
    for key in [
        named("repo_agreement_delete"),
        named("repo_agreement_noop"),
        named("repo_agreement_untouched"),
    ] {
        let mut record = record.clone();
        record.id = key.clone();
        world.repo_agreements.insert(key, record);
    }
    world.rebuild_repo_agreement_indexes();
    world
}
fn replacement() -> RepoAgreement {
    let world = fixture::fixture(true);
    let mut record = world
        .repo_agreements
        .view()
        .get(&fixture::id())
        .unwrap()
        .clone();
    record.initiator = BOB_ID.clone();
    record.counterparty = ALICE_ID.clone();
    record.custodian = None;
    record
}
fn insertion() -> RepoAgreement {
    let mut record = replacement();
    record.id = named("repo_agreement_insert");
    record.initiator = ALICE_ID.clone();
    record.custodian = Some(ALICE_ID.clone());
    record
}
fn expected() -> World {
    let mut world = initial();
    world.repo_agreements.insert(fixture::id(), replacement());
    fixture::omit_initial(&mut world.repo_agreements, &named("repo_agreement_delete"));
    world
        .repo_agreements
        .insert(named("repo_agreement_insert"), insertion());
    world.rebuild_repo_agreement_indexes();
    world
}
fn stage(block: &mut StateBlock<'_>) {
    let noop = block
        .world
        .repo_agreements
        .get(&named("repo_agreement_noop"))
        .unwrap()
        .clone();
    block
        .world
        .repo_agreements
        .insert(fixture::id(), replacement());
    block
        .world
        .repo_agreements
        .remove(named("repo_agreement_delete"));
    block
        .world
        .repo_agreements
        .insert(named("repo_agreement_noop"), noop);
    block
        .world
        .repo_agreements
        .insert(named("repo_agreement_insert"), insertion());
    block
        .world
        .repo_agreements
        .remove(named("repo_agreement_absent"));
    let open = BTreeSet::from([
        named("repo_agreement_noop"),
        named("repo_agreement_untouched"),
    ]);
    let alice = BTreeSet::from([
        named("repo_agreement_noop"),
        named("repo_agreement_untouched"),
        named("repo_agreement_insert"),
    ]);
    block
        .world
        .repo_agreements_by_initiator
        .insert(ALICE_ID.clone(), alice);
    block
        .world
        .repo_agreements_by_initiator
        .insert(BOB_ID.clone(), BTreeSet::from([fixture::id()]));
    block
        .world
        .repo_agreements_by_initiator
        .remove(absent_account());
    block
        .world
        .repo_agreements_by_counterparty
        .insert(BOB_ID.clone(), open.clone());
    block.world.repo_agreements_by_counterparty.insert(
        ALICE_ID.clone(),
        BTreeSet::from([fixture::id(), named("repo_agreement_insert")]),
    );
    block
        .world
        .repo_agreements_by_counterparty
        .remove(absent_account());
    block
        .world
        .repo_agreements_by_custodian
        .insert(BOB_ID.clone(), open);
    block.world.repo_agreements_by_custodian.insert(
        ALICE_ID.clone(),
        BTreeSet::from([named("repo_agreement_insert")]),
    );
    block
        .world
        .repo_agreements_by_custodian
        .remove(absent_account());
}
#[test]
fn ordinary_custodian_migrations_insert_delete_noop_absence_and_untouched_members_retain_originals()
{
    let state = state(initial());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.initiators.mode(),
        original.counterparties.mode(),
        original.custodians.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(original.rows.undo_entries().any(|(id, prior)| {
        id == &named("repo_agreement_noop")
            && prior
                .as_ref()
                .is_some_and(|r| r.custodian == Some(BOB_ID.clone()))
    }));
    assert!(
        !original
            .rows
            .undo_entries()
            .any(|(id, _)| id == &named("repo_agreement_untouched"))
    );
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &named("repo_agreement_absent") && prior.is_none())
    );
    assert!(
        original
            .counterparties
            .undo_entries()
            .any(|(id, prior)| id == &*BOB_ID
                && prior.as_ref().is_some_and(|members| members.len() == 4))
    );
    assert!(
        original
            .initiators
            .undo_entries()
            .any(|(id, prior)| id == &absent_account() && prior.is_none())
    );
    assert!(
        original
            .custodians
            .undo_entries()
            .any(|(id, prior)| id == &absent_account() && prior.is_none())
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
        &capture_repo_agreements_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.repo_agreements", limits(), work)
            .unwrap()
            .unwrap(),
    );
    let actual: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.repo_agreements.view();
    let expected: Vec<_> = view
        .iter()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    assert_eq!(actual, expected);
}
#[test]
fn replacement_keeps_exact_rewound_four_repo_images_modes_and_canonical_bytes() {
    let mut world = fixture::fixture(true);
    {
        let mut rows = world.repo_agreements.block();
        rows.insert(fixture::id(), replacement());
        let mut added = insertion();
        added.id = named("discarded_tip_repo_agreement");
        rows.insert(added.id.clone(), added);
        rows.commit();
    }
    world.rebuild_repo_agreement_indexes();
    let state = state(world);
    let mut block = state.block_and_revert(header());
    block
        .world
        .repo_agreements
        .remove(named("repo_agreement_absent"));
    block
        .world
        .repo_agreements_by_initiator
        .remove(absent_account());
    block
        .world
        .repo_agreements_by_counterparty
        .remove(absent_account());
    block
        .world
        .repo_agreements_by_custodian
        .remove(absent_account());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.initiators.mode(),
        original.counterparties.mode(),
        original.custodians.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &named("repo_agreement_absent") && prior.is_none())
    );
    let control = self::state(fixture::fixture(true));
    let snapshot = capture(&block, limits(), exact(&original))
        .unwrap()
        .unwrap();
    equal(
        &snapshot,
        &capture_repo_agreements_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    assert_ne!(
        snapshot.root(),
        capture_repo_agreements_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
    let actual: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.repo_agreements.view();
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
            0 => group!(
                repo_agreements_by_initiator,
                ALICE_ID.clone(),
                BOB_ID.clone()
            ),
            1 => group!(
                repo_agreements_by_counterparty,
                BOB_ID.clone(),
                ALICE_ID.clone()
            ),
            2 => group!(
                repo_agreements_by_custodian,
                BOB_ID.clone(),
                ALICE_ID.clone()
            ),
            _ => unreachable!(),
        }
    }};
}
#[test]
fn every_repo_index_mismatch_rejects_either_original_image_before_allocation() {
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
                            "world.repo_agreements_by_initiator",
                            "world.repo_agreements_by_counterparty",
                            "world.repo_agreements_by_custodian"
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
fn custodianless_frozen_rows_cannot_have_any_inverse_custodian_membership() {
    let state = state(fixture::fixture(false));
    let mut block = state.block(header());
    block
        .world
        .repo_agreements_by_custodian
        .insert(BOB_ID.clone(), BTreeSet::from([fixture::id()]));
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), fixture::TEST_WORK_ALLOWANCE).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                index: "world.repo_agreements_by_custodian",
                image: GroupImage::Current,
                mismatch: GroupMismatch::ForeignMember
            }
        ))
    );
}
#[test]
fn each_foreign_released_partial_and_mixed_original_repo_field_refuses() {
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
                0 => replace!(repo_agreements),
                1 => replace!(repo_agreements_by_initiator),
                2 => replace!(repo_agreements_by_counterparty),
                3 => replace!(repo_agreements_by_custodian),
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
            0 => block.world.repo_agreements.release_writers(),
            1 => block.world.repo_agreements_by_initiator.release_writers(),
            2 => block
                .world
                .repo_agreements_by_counterparty
                .release_writers(),
            3 => block.world.repo_agreements_by_custodian.release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    let state = state(fixture::fixture(true));
    let mut block = state.block(header());
    block.world.repo_agreements.begin_freeze();
    block.world.repo_agreements.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
}
#[test]
fn original_repo_pool_work_row_payload_retry_and_last_output_owner_refund() {
    let _pin = crossbeam_epoch::pin();
    let state = state(initial());
    let pool = state.ivm_execution_budget();
    let limit = pool.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(block.world.repo_agreements.get(&fixture::id()).unwrap());
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
        core::ptr::from_ref(block.world.repo_agreements.get(&fixture::id()).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(pool.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_repo_original() {
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
                0 => publish!(
                    repo_agreements,
                    named("later_repo_agreement"),
                    replacement()
                ),
                1 => publish!(
                    repo_agreements_by_initiator,
                    absent_account(),
                    BTreeSet::from([fixture::id()])
                ),
                2 => publish!(
                    repo_agreements_by_counterparty,
                    absent_account(),
                    BTreeSet::from([fixture::id()])
                ),
                3 => publish!(
                    repo_agreements_by_custodian,
                    absent_account(),
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
