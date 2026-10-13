//! Actual eight-original balance histories, error phases and retained output custody.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{capture_assets_once, table_capture::frozen::capture_original_table_once},
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                asset_balance_test_support as fixture,
            },
        },
        block_field::BlockField,
    },
};
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope},
    block::BlockHeader,
    prelude::Registrable,
};
use iroha_model_base::topology::DataSpaceId;
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
        max_rows: 64,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn other_domain() -> DomainId {
    fixture::domain("other")
}
fn scoped(account: AccountId) -> AssetId {
    AssetId::with_scope(
        fixture::definition("coin"),
        account,
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    )
}
fn spare() -> AssetId {
    AssetId::new(fixture::definition("spare"), BOB_ID.clone())
}
fn definition(domain: Option<DomainId>) -> AssetDefinition {
    AssetDefinition::numeric(
        fixture::definition("coin"),
        "coin",
        AssetBalancePolicy::Global,
        domain,
    )
    .build(&ALICE_ID)
}
fn initial() -> World {
    let mut world = fixture::fixture(true);
    world.asset_definitions.insert(
        fixture::definition("spare"),
        AssetDefinition::numeric(
            fixture::definition("spare"),
            "spare",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&BOB_ID),
    );
    for (id, amount) in [
        (scoped(ALICE_ID.clone()), 0),
        (AssetId::new(fixture::definition("coin"), BOB_ID.clone()), 0),
        (spare(), 13),
    ] {
        world.assets.insert(id.clone(), fixture::value(&id, amount));
    }
    world.rebuild_asset_definition_indexes().unwrap();
    world
}
fn expected() -> World {
    let mut world = initial();
    world.asset_definitions.insert(
        fixture::definition("coin"),
        definition(Some(other_domain())),
    );
    world
        .domains
        .insert(other_domain(), Domain::new(other_domain()).build(&ALICE_ID));
    for (id, amount) in [
        (fixture::id(), 0),
        (scoped(ALICE_ID.clone()), 7),
        (scoped(BOB_ID.clone()), 11),
    ] {
        world.assets.insert(id.clone(), fixture::value(&id, amount));
    }
    fixture::omit_initial(
        &mut world.assets,
        &AssetId::new(fixture::definition("coin"), BOB_ID.clone()),
    );
    world.rebuild_asset_definition_indexes().unwrap();
    world
}
fn stage(block: &mut StateBlock<'_>) {
    block.world.asset_definitions.insert(
        fixture::definition("coin"),
        definition(Some(other_domain())),
    );
    block.world.asset_definitions.insert(
        fixture::definition("spare"),
        AssetDefinition::numeric(
            fixture::definition("spare"),
            "spare",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&BOB_ID),
    );
    block
        .world
        .asset_definitions
        .remove(fixture::definition("absent"));
    block.world.domains.insert(
        fixture::domain("balances"),
        Domain::new(fixture::domain("balances")).build(&ALICE_ID),
    );
    block
        .world
        .domains
        .insert(other_domain(), Domain::new(other_domain()).build(&ALICE_ID));
    block.world.domains.remove(fixture::domain("unused"));
    for (id, amount) in [
        (fixture::id(), 0),
        (scoped(ALICE_ID.clone()), 7),
        (scoped(BOB_ID.clone()), 11),
        (spare(), 13),
    ] {
        block
            .world
            .assets
            .insert(id.clone(), fixture::value(&id, amount));
    }
    block
        .world
        .assets
        .remove(AssetId::new(fixture::definition("coin"), BOB_ID.clone()));
    block.world.assets.remove(AssetId::new(
        fixture::definition("absent"),
        ALICE_ID.clone(),
    ));
    let coin = BTreeSet::from([
        fixture::id(),
        scoped(ALICE_ID.clone()),
        scoped(BOB_ID.clone()),
    ]);
    block
        .world
        .asset_definition_assets
        .insert(fixture::definition("coin"), coin.clone());
    block
        .world
        .asset_definition_assets
        .insert(fixture::definition("spare"), BTreeSet::from([spare()]));
    block
        .world
        .asset_definition_assets
        .remove(fixture::definition("absent"));
    block.world.assets_by_account.insert(
        ALICE_ID.clone(),
        BTreeSet::from([fixture::id(), scoped(ALICE_ID.clone())]),
    );
    block.world.assets_by_account.insert(
        BOB_ID.clone(),
        BTreeSet::from([scoped(BOB_ID.clone()), spare()]),
    );
    block
        .world
        .assets_by_domain
        .remove(fixture::domain("balances"));
    block.world.assets_by_domain.insert(other_domain(), coin);
    block
        .world
        .assets_by_domain
        .remove(fixture::domain("unused"));
    block.world.asset_definition_holders.insert(
        fixture::definition("coin"),
        BTreeSet::from([ALICE_ID.clone(), BOB_ID.clone()]),
    );
    block.world.asset_definition_holders.insert(
        fixture::definition("spare"),
        BTreeSet::from([BOB_ID.clone()]),
    );
    block
        .world
        .asset_definition_holders
        .remove(fixture::definition("absent"));
    block.world.asset_definition_nonzero_holders.insert(
        fixture::definition("coin"),
        BTreeSet::from([ALICE_ID.clone(), BOB_ID.clone()]),
    );
    block.world.asset_definition_nonzero_holders.insert(
        fixture::definition("spare"),
        BTreeSet::from([BOB_ID.clone()]),
    );
    block
        .world
        .asset_definition_nonzero_holders
        .remove(fixture::definition("absent"));
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn exact(original: &Original<'_>) -> u64 {
    fixture::full_work(
        &original.rows,
        &original.definitions,
        &original.domains,
        &original.by_definition,
        &original.by_account,
        &original.by_domain,
        &original.holders,
        &original.nonzero,
    )
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
#[test]
fn ordinary_partition_domain_migration_insert_delete_noop_and_absent_history_retains_originals() {
    let state = state(initial());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Ordinary);
    assert!(original.rows.undo_entries().any(|(id, prior)| {
        id == &spare()
            && prior
                .as_ref()
                .is_some_and(|value| value.as_ref() == fixture::value(&spare(), 13).as_ref())
    }));
    assert!(
        original
            .rows
            .undo_entries()
            .any(
                |(id, prior)| id.definition() == &fixture::definition("absent") && prior.is_none()
            )
    );
    assert!(
        original
            .by_definition
            .undo_entries()
            .any(|(id, prior)| id == &fixture::definition("absent") && prior.is_none())
    );
    assert!(
        original
            .by_domain
            .undo_entries()
            .any(|(id, prior)| id == &other_domain() && prior.is_none())
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
        &capture_assets_once(&control, limits()).unwrap().unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.assets", limits(), work)
            .unwrap()
            .unwrap(),
    );
    let current: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.assets.view();
    let bytes: Vec<_> = view
        .iter()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    assert_eq!(current, bytes);
}
#[test]
fn replace_retains_exact_rewound_eight_owner_images_and_modes() {
    let mut world = initial();
    {
        let mut rows = world.assets.block();
        rows.insert(fixture::id(), fixture::value(&fixture::id(), 9));
        rows.insert(
            scoped(BOB_ID.clone()),
            fixture::value(&scoped(BOB_ID.clone()), 11),
        );
        rows.commit();
    }
    {
        let mut definitions = world.asset_definitions.block();
        definitions.insert(
            fixture::definition("coin"),
            definition(Some(other_domain())),
        );
        definitions.commit();
    }
    {
        let mut domains = world.domains.block();
        domains.insert(other_domain(), Domain::new(other_domain()).build(&ALICE_ID));
        domains.commit();
    }
    world.rebuild_asset_definition_indexes().unwrap();
    let state = state(world);
    let mut block = state.block_and_revert(header());
    block.world.assets.remove(AssetId::new(
        fixture::definition("absent"),
        ALICE_ID.clone(),
    ));
    block
        .world
        .asset_definition_assets
        .remove(fixture::definition("absent"));
    block
        .world
        .asset_definition_holders
        .remove(fixture::definition("absent"));
    block
        .world
        .asset_definition_nonzero_holders
        .remove(fixture::definition("absent"));
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.definitions.mode(),
        original.domains.mode(),
        original.by_definition.mode(),
        original.by_account.mode(),
        original.by_domain.mode(),
        original.holders.mode(),
        original.nonzero.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(
                |(id, prior)| id.definition() == &fixture::definition("absent") && prior.is_none()
            )
    );
    let control = self::state(initial());
    equal(
        &capture(&block, limits(), exact(&original))
            .unwrap()
            .unwrap(),
        &capture_assets_once(&control, limits()).unwrap().unwrap(),
    );
    assert_ne!(
        capture_assets_once(&state, limits())
            .unwrap()
            .unwrap()
            .root(),
        capture(&block, limits(), 16_777_216)
            .unwrap()
            .unwrap()
            .root()
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
            ($field:ident,$key:expr,$foreign:expr,$valid:expr) => {{
                let key = if case % 3 == 0 { $key } else { $foreign };
                let value = if restore {
                    if case % 3 == 0 { Some($valid) } else { None }
                } else {
                    if case % 3 == 0 {
                        None
                    } else {
                        Some(if case % 3 == 1 {
                            BTreeSet::new()
                        } else {
                            $valid
                        })
                    }
                };
                alter!($world, $kind, $field, key, value);
            }};
        }
        match case / 3 {
            0 => group!(
                asset_definition_assets,
                fixture::definition("coin"),
                fixture::definition("absent"),
                BTreeSet::from([fixture::id()])
            ),
            1 => group!(
                assets_by_account,
                ALICE_ID.clone(),
                BOB_ID.clone(),
                BTreeSet::from([fixture::id()])
            ),
            2 => group!(
                assets_by_domain,
                fixture::domain("balances"),
                other_domain(),
                BTreeSet::from([fixture::id()])
            ),
            3 => group!(
                asset_definition_holders,
                fixture::definition("coin"),
                fixture::definition("absent"),
                BTreeSet::from([ALICE_ID.clone()])
            ),
            4 => group!(
                asset_definition_nonzero_holders,
                fixture::definition("coin"),
                fixture::definition("absent"),
                BTreeSet::from([ALICE_ID.clone()])
            ),
            _ => unreachable!(),
        }
    }};
}
#[test]
fn all_five_balance_index_defects_reject_either_original_image_before_allocation() {
    for previous in [false, true] {
        for case in 0..15 {
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
            let index = [
                "world.asset_definition_assets",
                "world.assets_by_account",
                "world.assets_by_domain",
                "world.asset_definition_holders",
                "world.asset_definition_nonzero_holders",
            ][case / 3];
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index,
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: match case % 3 {
                            0 => GroupMismatch::MissingMember,
                            1 => GroupMismatch::EmptyGroup,
                            _ => GroupMismatch::ForeignMember,
                        }
                    }
                ))
            );
            assert_eq!(pool.reserved_bytes(), baseline);
        }
    }
}
macro_rules! source_defect {
    ($world:expr,$kind:ident,$case:expr,$restore:expr) => {{
        match $case {
            0 => alter!(
                $world,
                $kind,
                asset_definitions,
                fixture::definition("coin"),
                $restore.then(|| definition(Some(fixture::domain("balances"))))
            ),
            1 => alter!(
                $world,
                $kind,
                domains,
                fixture::domain("balances"),
                $restore.then(|| Domain::new(fixture::domain("balances")).build(&ALICE_ID))
            ),
            2 => alter!(
                $world,
                $kind,
                asset_definitions,
                fixture::definition("coin"),
                Some(if $restore {
                    definition(Some(fixture::domain("balances")))
                } else {
                    AssetDefinition::numeric(
                        fixture::definition("coin"),
                        "coin",
                        AssetBalancePolicy::DataspaceRestricted,
                        None,
                    )
                    .build(&ALICE_ID)
                })
            ),
            _ => unreachable!(),
        }
    }};
}
#[test]
fn matching_image_definition_domain_and_restricted_source_errors_remain_exact() {
    for previous in [false, true] {
        for case in 0..3 {
            let state = state(fixture::fixture(true));
            if previous {
                source_defect!(state.world, tip, case, false);
            }
            let mut block = state.block(header());
            source_defect!(block.world, journal, case, previous);
            freeze(&mut block);
            let reason = [
                "asset definition is absent",
                "owning domain is absent",
                "restricted definition has no owning domain",
            ][case];
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::GroupedOwnership(GroupedOwnershipError::Source {
                    table: if case == 0 {
                        "world.assets"
                    } else {
                        "world.asset_definitions"
                    },
                    image: if previous {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    reason
                }))
            );
        }
    }
}
#[test]
fn each_of_eight_foreign_released_partial_and_mixed_balance_sources_refuses() {
    for source in 0..8 {
        for mixed in [false, true] {
            let state = state(initial());
            let foreign = self::state(initial());
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
                0 => replace!(assets),
                1 => replace!(asset_definitions),
                2 => replace!(domains),
                3 => replace!(asset_definition_assets),
                4 => replace!(assets_by_account),
                5 => replace!(assets_by_domain),
                6 => replace!(asset_definition_holders),
                7 => replace!(asset_definition_nonzero_holders),
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    for source in 0..8 {
        let state = state(initial());
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.assets.release_writers(),
            1 => block.world.asset_definitions.release_writers(),
            2 => block.world.domains.release_writers(),
            3 => block.world.asset_definition_assets.release_writers(),
            4 => block.world.assets_by_account.release_writers(),
            5 => block.world.assets_by_domain.release_writers(),
            6 => block.world.asset_definition_holders.release_writers(),
            7 => block
                .world
                .asset_definition_nonzero_holders
                .release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    let state = state(initial());
    let mut block = state.block(header());
    block.world.assets.begin_freeze();
    block.world.assets.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
}
#[test]
fn original_asset_pool_work_row_payload_retry_and_final_output_owner_refund() {
    let _pin = crossbeam_epoch::pin();
    let state = state(initial());
    let pool = state.ivm_execution_budget();
    let limit = pool.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(block.world.assets.get(&fixture::id()).unwrap());
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
        capture(&block, limits(), 16_777_216),
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
        assert_eq!(capture(&block, small, 16_777_216).err(), Some(error));
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(capture(&block, limits(), 16_777_216).unwrap().unwrap());
    assert!(pool.reserved_bytes() > baseline);
    assert_eq!(
        core::ptr::from_ref(block.world.assets.get(&fixture::id()).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(pool.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_asset_original() {
    for source in 0..8 {
        for changed in [false, true] {
            let state = state(initial());
            let mut block = state.block(header());
            stage(&mut block);
            freeze(&mut block);
            let snapshot = capture(&block, limits(), 16_777_216).unwrap().unwrap();
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
                    assets,
                    AssetId::new(fixture::definition("absent"), ALICE_ID.clone()),
                    fixture::value(&fixture::id(), 99)
                ),
                1 => publish!(
                    asset_definitions,
                    fixture::definition("absent"),
                    definition(None)
                ),
                2 => publish!(
                    domains,
                    other_domain(),
                    Domain::new(other_domain()).build(&ALICE_ID)
                ),
                3 => publish!(
                    asset_definition_assets,
                    fixture::definition("absent"),
                    BTreeSet::from([fixture::id()])
                ),
                4 => publish!(
                    assets_by_account,
                    BOB_ID.clone(),
                    BTreeSet::from([fixture::id()])
                ),
                5 => publish!(
                    assets_by_domain,
                    other_domain(),
                    BTreeSet::from([fixture::id()])
                ),
                6 => publish!(
                    asset_definition_holders,
                    fixture::definition("absent"),
                    BTreeSet::from([ALICE_ID.clone()])
                ),
                7 => publish!(
                    asset_definition_nonzero_holders,
                    fixture::definition("absent"),
                    BTreeSet::from([ALICE_ID.clone()])
                ),
                _ => unreachable!(),
            }
            let retained = Original::retain(&block).unwrap();
            assert_eq!(retained.rows.publication_identity(), identity);
            equal(
                &snapshot,
                &capture(&block, limits(), 16_777_216).unwrap().unwrap(),
            );
        }
    }
}
#[test]
fn canonical_balance_rows_roots_and_zero_nonzero_partitions_match_original_committed_capture() {
    let state = state(initial());
    let mut block = state.block(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    let snapshot = capture(&block, limits(), exact(&original))
        .unwrap()
        .unwrap();
    equal(
        &snapshot,
        &capture_assets_once(&state, limits()).unwrap().unwrap(),
    );
    assert_eq!(snapshot.row_count(), 4);
    assert_eq!(
        original
            .nonzero
            .current_entries()
            .find(|(id, _)| *id == &fixture::definition("coin"))
            .unwrap()
            .1,
        &BTreeSet::from([ALICE_ID.clone()])
    );
}
