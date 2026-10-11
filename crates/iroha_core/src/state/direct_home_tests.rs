//! Direct dataspace home table: native writers, block invariant and fixtures.

use super::*;
use iroha_data_model::{asset::AssetDefinitionHome, prelude::Registrable};
use iroha_test_samples::ALICE_ID;

fn id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("homes", "universal").unwrap(),
        "coin".parse().unwrap(),
    )
}

fn definition() -> AssetDefinition {
    AssetDefinition::numeric(id(), "Direct home", AssetBalancePolicy::Global, None).build(&ALICE_ID)
}

fn world() -> World {
    World::with(
        [],
        [iroha_data_model::account::Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [definition()],
    )
}

fn incarnation(seed: u8) -> AxtAssetIncarnationV1 {
    AxtAssetIncarnationV1::try_from_bytes(Hash::new([seed]).into()).unwrap()
}

fn state_with(world: World) -> State {
    State::new_for_testing(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(core::num::NonZeroU64::MIN, None, None, 0, 0)
}

fn row(seed: u8, dataspace: u64) -> AssetDefinitionDirectHomeV1 {
    AssetDefinitionDirectHomeV1 {
        incarnation: incarnation(seed),
        dataspace_id: DataSpaceId::new(dataspace),
    }
}

fn add_native(tx: &mut StateTransaction<'_, '_>, ds: DataSpaceId, seed: u8) {
    tx.world.insert_asset_definition_entry(id(), definition());
    tx.world
        .axt_asset_incarnations
        .insert(id(), incarnation(seed));
    tx.register_direct_asset_definition_home(&id(), incarnation(seed), ds)
        .unwrap();
}

#[test]
fn restricted_direct_fixture_preserves_home_bucket_alias_and_supply() {
    let owner = (*ALICE_ID).clone();
    let home = DataSpaceId::new(7);
    let mut definition = AssetDefinition::numeric(
        id(),
        "Direct home",
        AssetBalancePolicy::DataspaceRestricted,
        None,
    )
    .build(&owner);
    let alias: AssetDefinitionAlias = "coin#universal".parse().unwrap();
    definition.alias = Some(alias.clone());
    let asset_id = AssetId::with_scope(id(), owner.clone(), AssetBalanceScope::Dataspace(home));
    let mut world = World::with(
        [],
        [iroha_data_model::account::Account::new(owner.clone()).build(&owner)],
        [],
    );
    world
        .insert_direct_asset_definition_with_assets_for_testing(
            definition.clone(),
            home,
            [Asset::new(asset_id.clone(), Quantity::from(3_u32))],
        )
        .unwrap();
    let view = world.view();
    let stored = view.asset_definition(&id()).unwrap();
    assert!(stored.owning_domain().is_none());
    assert_eq!(
        stored.balance_scope_policy(),
        AssetBalancePolicy::DataspaceRestricted
    );
    assert_eq!(stored.total_quantity(), &Quantity::from(3_u32));
    assert_eq!(
        view.asset_definition_home(&id()).unwrap(),
        Some(AssetDefinitionHome::Dataspace(home))
    );
    assert_eq!(view.asset_definition_id_by_alias(&alias), Some(id()));
    assert_eq!(
        view.asset(&asset_id).unwrap().value().as_ref(),
        &Quantity::from(3_u32)
    );
    drop(view);
    world.validate_numeric_asset_invariants().unwrap();
    world.validate_quantity_ledger_invariants().unwrap();
    world.rebuild_asset_definition_indexes().unwrap();
    let parameters = (*world.parameters.view()).clone();
    assert!(
        world
            .insert_direct_asset_definition_with_assets_for_testing(
                definition,
                DataSpaceId::new(9),
                [],
            )
            .is_err()
    );
    assert_eq!(*world.parameters.view(), parameters);
    assert_eq!(
        world.view().asset_definition_dataspace(&id()).unwrap(),
        Some(home)
    );
}

#[test]
fn restricted_direct_fixture_rejects_invalid_home_and_rolls_back_partial_setup() {
    let owner = (*ALICE_ID).clone();
    let mut definition = AssetDefinition::numeric(
        id(),
        "Direct home",
        AssetBalancePolicy::DataspaceRestricted,
        None,
    )
    .build(&owner);
    let alias: AssetDefinitionAlias = "coin#universal".parse().unwrap();
    definition.alias = Some(alias.clone());
    let mut world = World::default();
    assert!(
        world
            .insert_direct_asset_definition_with_assets_for_testing(
                definition.clone(),
                DataSpaceId::UNIVERSAL,
                [],
            )
            .is_err()
    );
    // The absent holder fails after the new definition, alias and home are staged.
    let asset_id = AssetId::with_scope(
        id(),
        owner.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    assert!(
        world
            .insert_direct_asset_definition_with_assets_for_testing(
                definition.clone(),
                DataSpaceId::new(7),
                [Asset::new(asset_id, Quantity::from(1_u32))],
            )
            .is_err()
    );
    assert!(world.view().asset_definition(&id()).is_err());
    assert_eq!(world.view().asset_definition_id_by_alias(&alias), None);
    assert!(world.axt_asset_incarnations.view().get(&id()).is_none());
    assert!(
        world
            .asset_definition_direct_homes
            .view()
            .get(&id())
            .is_none()
    );
    // A global balance scope never matches a restricted definition.
    let global = AssetId::with_scope(id(), owner, AssetBalanceScope::Global);
    assert!(
        world
            .insert_direct_asset_definition_with_assets_for_testing(
                definition.clone(),
                DataSpaceId::new(7),
                [Asset::new(global, Quantity::from(1_u32))],
            )
            .is_err()
    );
    world
        .insert_direct_asset_definition_with_assets_for_testing(definition, DataSpaceId::new(7), [])
        .unwrap();
    assert_eq!(
        world.view().asset_definition_dataspace(&id()).unwrap(),
        Some(DataSpaceId::new(7))
    );
}

#[test]
fn absent_home_lookup_preserves_parameter_bytes_and_world_root() {
    use super::world_projection::world_state_accumulator::WorldStateAccumulator;
    use norito::codec::Encode;
    let world = world();
    let parameters = world.parameters.view().encode();
    let root = WorldStateAccumulator::capture(&world.block())
        .unwrap()
        .root()
        .unwrap();
    assert_eq!(
        world.view().asset_definition_dataspace(&id()).unwrap(),
        None
    );
    assert_eq!(
        world.view().asset_definition_home(&id()).unwrap(),
        Some(AssetDefinitionHome::Global)
    );
    assert_eq!(parameters, world.parameters.view().encode());
    assert_eq!(
        root,
        WorldStateAccumulator::capture(&world.block())
            .unwrap()
            .root()
            .unwrap()
    );
}

#[test]
fn direct_home_is_exact_changes_world_root_and_leaves_parameters_unchanged() {
    use super::world_projection::world_state_accumulator::WorldStateAccumulator;
    let mut world = world();
    let before = WorldStateAccumulator::capture(&world.block())
        .unwrap()
        .root()
        .unwrap();
    let parameters = (*world.parameters.view()).clone();
    let ds = DataSpaceId::new((1_u64 << 53) + 7);
    world
        .set_asset_definition_dataspace_for_testing(id(), ds)
        .unwrap();
    assert_eq!(
        world.view().asset_definition_dataspace(&id()).unwrap(),
        Some(ds)
    );
    assert_eq!(
        world
            .asset_definition_direct_homes
            .view()
            .get(&id())
            .copied(),
        Some(AssetDefinitionDirectHomeV1 {
            incarnation: *world.axt_asset_incarnations.view().get(&id()).unwrap(),
            dataspace_id: ds,
        })
    );
    // The home lives in its own table; the public Parameters cell is untouched.
    assert_eq!(*world.parameters.view(), parameters);
    assert_ne!(
        before,
        WorldStateAccumulator::capture(&world.block())
            .unwrap()
            .root()
            .unwrap()
    );
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(
        world.view().asset_definition_home(&id()).unwrap(),
        Some(AssetDefinitionHome::Dataspace(ds))
    );
    assert!(
        world
            .set_asset_definition_dataspace_for_testing(id(), DataSpaceId::new(9))
            .is_err()
    );
}

#[test]
fn foreign_incarnation_or_orphan_row_never_falls_back_to_global() {
    let mut world = world();
    world
        .set_asset_definition_dataspace_for_testing(id(), DataSpaceId::new(7))
        .unwrap();
    let mut incarnations = world.axt_asset_incarnations.block();
    incarnations.insert(id(), incarnation(42));
    incarnations.commit();
    assert!(world.view().asset_definition_home(&id()).is_err());
    assert!(world.rebuild_asset_definition_indexes().is_err());

    let mut orphan = World::default();
    let mut homes = orphan.asset_definition_direct_homes.block();
    homes.insert(id(), row(3, 7));
    homes.commit();
    assert!(orphan.view().asset_definition_dataspace(&id()).is_err());
    assert!(orphan.rebuild_asset_definition_indexes().is_err());
}

#[test]
fn native_home_rolls_back_with_transaction_drop() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    {
        let mut tx = block.transaction();
        add_native(&mut tx, DataSpaceId::new(7), 1);
        assert_eq!(
            tx.world.asset_definition_dataspace(&id()).unwrap(),
            Some(DataSpaceId::new(7))
        );
    }
    assert!(block.world.asset_definitions.get(&id()).is_none());
    assert!(
        block
            .world
            .asset_definition_direct_homes
            .get(&id())
            .is_none()
    );
    block.validate_direct_home_rows().unwrap();
}

#[test]
fn native_registration_refuses_existing_row_universal_home_and_foreign_incarnation() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    let mut tx = block.transaction();
    tx.world.insert_asset_definition_entry(id(), definition());
    tx.world.axt_asset_incarnations.insert(id(), incarnation(1));
    assert!(
        tx.register_direct_asset_definition_home(&id(), incarnation(2), DataSpaceId::new(7))
            .is_err()
    );
    assert!(
        tx.register_direct_asset_definition_home(&id(), incarnation(1), DataSpaceId::UNIVERSAL)
            .is_err()
    );
    tx.register_direct_asset_definition_home(&id(), incarnation(1), DataSpaceId::new(7))
        .unwrap();
    assert!(
        tx.register_direct_asset_definition_home(&id(), incarnation(1), DataSpaceId::new(8))
            .is_err()
    );
    assert_eq!(
        tx.world.asset_definition_direct_homes.get(&id()).copied(),
        Some(row(1, 7))
    );
}

#[test]
fn native_retirement_removes_row_and_requires_matching_incarnation() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    let mut tx = block.transaction();
    add_native(&mut tx, DataSpaceId::new(7), 1);
    tx.world.axt_asset_incarnations.insert(id(), incarnation(9));
    assert!(tx.retire_direct_asset_definition_home(&id()).is_err());
    tx.world.axt_asset_incarnations.insert(id(), incarnation(1));
    tx.retire_direct_asset_definition_home(&id()).unwrap();
    assert!(tx.world.asset_definition_direct_homes.get(&id()).is_none());
    // Retiring an absent home is a no-op.
    tx.retire_direct_asset_definition_home(&id()).unwrap();
}

#[test]
fn removing_a_definition_entry_removes_its_direct_home() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    let mut tx = block.transaction();
    add_native(&mut tx, DataSpaceId::new(7), 1);
    tx.world.remove_asset_definition_entry(&id());
    assert!(tx.world.axt_asset_incarnations.get(&id()).is_none());
    assert!(tx.world.asset_definition_direct_homes.get(&id()).is_none());
}

fn homed_state() -> (State, AxtAssetIncarnationV1) {
    let mut world = world();
    world
        .set_asset_definition_dataspace_for_testing(id(), DataSpaceId::new(7))
        .unwrap();
    let live = *world.axt_asset_incarnations.view().get(&id()).unwrap();
    (state_with(world), live)
}

#[test]
fn block_invariant_accepts_new_homes_and_reregistration() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    block.world.asset_definitions.insert(id(), definition());
    block
        .world
        .axt_asset_incarnations
        .insert(id(), incarnation(1));
    block
        .world
        .asset_definition_direct_homes
        .insert(id(), row(1, 7));
    block.validate_direct_home_rows().unwrap();
    drop(block);

    // Unregistering removes the row with its incarnation.
    let (state, _) = homed_state();
    let mut block = state.block(header());
    block.world.asset_definitions.remove(id());
    block.world.axt_asset_incarnations.remove(id());
    block.world.asset_definition_direct_homes.remove(id());
    block.validate_direct_home_rows().unwrap();
    drop(block);

    // A new incarnation may carry a new home.
    let mut block = state.block(header());
    block
        .world
        .axt_asset_incarnations
        .insert(id(), incarnation(2));
    block
        .world
        .asset_definition_direct_homes
        .insert(id(), row(2, 8));
    block.validate_direct_home_rows().unwrap();
}

#[test]
fn block_invariant_refuses_in_place_change_live_removal_and_foreign_incarnation() {
    let (state, live) = homed_state();

    // A row modified in place for the same live incarnation.
    let mut block = state.block(header());
    block.world.asset_definition_direct_homes.insert(
        id(),
        AssetDefinitionDirectHomeV1 {
            incarnation: live,
            dataspace_id: DataSpaceId::new(8),
        },
    );
    assert!(block.validate_direct_home_rows().is_err());
    drop(block);

    // A row removed while its incarnation stays live.
    let mut block = state.block(header());
    block.world.asset_definition_direct_homes.remove(id());
    assert!(block.validate_direct_home_rows().is_err());
    drop(block);

    // A foreign incarnation swapped under an unchanged row.
    let mut block = state.block(header());
    block
        .world
        .axt_asset_incarnations
        .insert(id(), incarnation(77));
    assert!(block.validate_direct_home_rows().is_err());
    drop(block);

    // A definition removed while its row stays behind as an orphan.
    let mut block = state.block(header());
    block.world.asset_definitions.remove(id());
    block.world.axt_asset_incarnations.remove(id());
    assert!(block.validate_direct_home_rows().is_err());
    drop(block);

    let block = state.block(header());
    block.validate_direct_home_rows().unwrap();
}

#[test]
fn block_invariant_refuses_a_home_added_to_an_existing_incarnation() {
    let mut world = world();
    world.axt_asset_incarnations.insert(id(), incarnation(5));
    let state = state_with(world);
    let mut block = state.block(header());
    block
        .world
        .asset_definition_direct_homes
        .insert(id(), row(5, 7));
    assert!(block.validate_direct_home_rows().is_err());
}

#[test]
fn row_transitions_are_immutable_for_one_incarnation() {
    let live = row(1, 7);
    let moved = row(1, 8);
    let reincarnated = row(2, 8);
    let one = incarnation(1);
    let two = incarnation(2);
    // Insert for a new incarnation; refuse for a pre-existing one.
    validate_direct_home_transition(None, Some(&live), None, Some(&one)).unwrap();
    assert!(validate_direct_home_transition(None, Some(&live), Some(&one), Some(&one)).is_err());
    // Remove only once the incarnation is gone.
    validate_direct_home_transition(Some(&live), None, Some(&one), None).unwrap();
    validate_direct_home_transition(Some(&live), None, Some(&one), Some(&two)).unwrap();
    assert!(validate_direct_home_transition(Some(&live), None, Some(&one), Some(&one)).is_err());
    // Modify only to a new incarnation.
    assert!(
        validate_direct_home_transition(Some(&live), Some(&moved), Some(&one), Some(&one)).is_err()
    );
    validate_direct_home_transition(Some(&live), Some(&reincarnated), Some(&one), Some(&two))
        .unwrap();
    assert!(
        validate_direct_home_transition(Some(&live), Some(&reincarnated), Some(&two), Some(&two))
            .is_err()
    );
    validate_direct_home_transition(Some(&live), Some(&live), Some(&one), Some(&one)).unwrap();
}

#[test]
fn block_invariant_rejects_a_new_restricted_definition_without_its_home() {
    let state = state_with(World::default());
    let mut block = state.block(header());
    block.world.asset_definitions.insert(
        id(),
        AssetDefinition::numeric(id(), "Kina", AssetBalancePolicy::DataspaceRestricted, None)
            .build(&ALICE_ID),
    );
    block
        .world
        .axt_asset_incarnations
        .insert(id(), incarnation(1));
    assert!(block.validate_direct_home_rows().is_err());
    block
        .world
        .asset_definition_direct_homes
        .insert(id(), row(1, 5));
    block.validate_direct_home_rows().unwrap();
}

#[test]
fn tiered_direct_home_changes_retain_insertions_and_removals() {
    let world = World::default();
    let mut block = world.block();
    block.asset_definition_direct_homes.insert(id(), row(1, 5));
    for diff in [
        block.tiered_snapshot_diff(),
        TieredSnapshotDiff::from(&block.tiered_snapshot_payload()),
    ] {
        assert!(diff.entries().iter().any(|entry| {
            matches!(entry, TieredKeyHandle::AssetDefinitionDirectHome(key) if *key == id())
        }));
    }
    block.commit();
    let mut block = world.block();
    block.asset_definition_direct_homes.remove(id());
    for diff in [
        block.tiered_snapshot_diff(),
        TieredSnapshotDiff::from(&block.tiered_snapshot_payload()),
    ] {
        assert!(diff.entries().iter().any(|entry| {
            matches!(entry, TieredKeyHandle::AssetDefinitionDirectHome(key) if *key == id())
        }));
    }
}

#[test]
fn snapshot_restore_rejects_a_row_moved_for_the_same_incarnation() {
    let mut world = world();
    world
        .set_asset_definition_dataspace_for_testing(id(), DataSpaceId::new(7))
        .unwrap();
    world.rebuild_asset_definition_indexes().unwrap();
    let mut moved = *world
        .asset_definition_direct_homes
        .view()
        .get(&id())
        .unwrap();
    moved.dataspace_id = DataSpaceId::new(8);
    let mut homes = world.asset_definition_direct_homes.block();
    homes.insert(id(), moved);
    homes.commit();
    assert_eq!(
        world.view().asset_definition_dataspace(&id()).unwrap(),
        Some(DataSpaceId::new(8))
    );
    assert!(world.rebuild_asset_definition_indexes().is_err());
}

#[test]
fn snapshot_restore_rejects_a_missing_row_for_a_restricted_definition() {
    let mut world = World::default();
    let mut definitions = world.asset_definitions.block();
    definitions.insert(
        id(),
        AssetDefinition::numeric(
            id(),
            "Direct home",
            AssetBalancePolicy::DataspaceRestricted,
            None,
        )
        .build(&ALICE_ID),
    );
    definitions.commit();
    assert!(world.view().asset_definition_home(&id()).is_err());
    assert!(world.rebuild_asset_definition_indexes().is_err());
}

#[test]
fn confined_definitions_resolve_only_their_home_bucket_on_their_home_route() {
    let home = DataSpaceId::new(5);
    let owner = (*ALICE_ID).clone();
    let mut world = World::with(
        [],
        [iroha_data_model::account::Account::new(owner.clone()).build(&owner)],
        [],
    );
    world
        .insert_direct_asset_definition_with_assets_for_testing(
            AssetDefinition::numeric(id(), "Kina", AssetBalancePolicy::DataspaceRestricted, None)
                .build(&owner),
            home,
            [],
        )
        .unwrap();
    let state = state_with(world);
    let mut block = state.block(header());
    let mut tx = block.transaction();
    let bare = AssetId::of(id(), owner.clone());
    let scoped = |dataspace| {
        AssetId::with_scope(id(), owner.clone(), AssetBalanceScope::Dataspace(dataspace))
    };
    let home_id = scoped(home);
    for route in [None, Some(home)] {
        tx.world.current_dataspace_id = route;
        assert_eq!(
            tx.world.resolve_asset_balance_scope(&id()).unwrap(),
            AssetBalanceScope::Dataspace(home)
        );
        assert_eq!(
            tx.world
                .resolve_asset_id_for_scope_hint(&bare, None)
                .unwrap(),
            home_id
        );
        assert_eq!(
            tx.world
                .resolve_asset_id_for_scope_hint(&home_id, Some(home))
                .unwrap(),
            home_id
        );
        for foreign in [DataSpaceId::UNIVERSAL, DataSpaceId::new(9)] {
            assert!(
                tx.world
                    .resolve_asset_id_for_scope_hint(&scoped(foreign), None)
                    .is_err()
            );
            assert!(
                tx.world
                    .resolve_asset_id_for_scope_hint(&bare, Some(foreign))
                    .is_err()
            );
        }
    }
    // Neither the universal coordinator nor another route may touch a confined balance.
    for route in [DataSpaceId::UNIVERSAL, DataSpaceId::new(9)] {
        tx.world.current_dataspace_id = Some(route);
        assert!(tx.world.resolve_asset_balance_scope(&id()).is_err());
        assert!(
            tx.world
                .resolve_asset_id_for_scope_hint(&home_id, None)
                .is_err()
        );
    }
}

#[test]
fn lifecycle_keeps_dataspace_classes_and_lanes_for_homed_dataspaces() {
    use iroha_data_model::nexus::{LaneConfig as CatalogLane, LaneVisibility};
    let lane = |id: u32, alias: &str, dataspace: u64, visibility| CatalogLane {
        id: LaneId::new(id),
        alias: alias.to_owned(),
        dataspace_id: DataSpaceId::new(dataspace),
        visibility,
        ..CatalogLane::default()
    };
    let previous = LaneCatalog::new(
        core::num::NonZeroU32::new(3).unwrap(),
        vec![
            lane(0, "core", 0, LaneVisibility::Public),
            lane(1, "bpng", 5, LaneVisibility::Public),
            lane(2, "cbsi", 6, LaneVisibility::Restricted),
        ],
    )
    .unwrap();
    // Retiring and re-adding the only cbsi lane cannot flip the dataspace's class.
    let flipped = previous
        .apply_lifecycle(&LaneLifecyclePlan {
            additions: vec![lane(2, "cbsi", 6, LaneVisibility::Public)],
            retire: vec![LaneId::new(2)],
        })
        .unwrap();
    assert!(matches!(
        ensure_dataspace_classes_preserved(&previous, &flipped),
        Err(LaneLifecycleError::DataspaceVisibilityChanged { dataspace_id })
            if dataspace_id == DataSpaceId::new(6)
    ));
    // Retiring every lane of a dataspace is not itself a class change ...
    let retired = previous
        .apply_lifecycle(&LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![LaneId::new(2)],
        })
        .unwrap();
    ensure_dataspace_classes_preserved(&previous, &retired).unwrap();
    // ... but a dataspace that homes a definition must keep at least one lane.
    let mut world = World::default();
    world
        .insert_direct_asset_definition_with_assets_for_testing(
            AssetDefinition::numeric(id(), "sbd", AssetBalancePolicy::DataspaceRestricted, None)
                .build(&ALICE_ID),
            DataSpaceId::new(6),
            [],
        )
        .unwrap();
    let view = world.view();
    ensure_homed_dataspaces_keep_lanes(&view, &previous).unwrap();
    ensure_homed_dataspaces_keep_lanes(&view, &flipped).unwrap();
    assert!(matches!(
        ensure_homed_dataspaces_keep_lanes(&view, &retired),
        Err(LaneLifecycleError::HomedDataspaceWithoutLanes { dataspace_id, .. })
            if dataspace_id == DataSpaceId::new(6)
    ));
}
