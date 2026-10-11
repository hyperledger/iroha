//! Asset index recovery preserves complete current and predecessor projections.

use super::*;
use iroha_data_model::{account::Account, asset::AssetBalanceScope, prelude::Registrable};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::codec::DecodeAll;

fn domain(name: &str) -> DomainId {
    DomainId::try_new(name, "universal").unwrap()
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain("assets"), name.parse().unwrap())
}

fn value(name: &str, owner: &AccountId, domain: Option<DomainId>) -> AssetDefinition {
    AssetDefinition::numeric(definition(name), name, AssetBalancePolicy::Global, domain)
        .build(owner)
}

fn balance(name: &str, owner: &AccountId, amount: u32) -> (AssetId, AssetValue) {
    Asset::new(AssetId::new(definition(name), owner.clone()), amount).into_key_value()
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
    json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("asset index source", |_, _| true)
        .unwrap()
}

fn image<K: mv::Key + Encode, V: mv::Value + Encode>(store: &impl StorageReadOnly<K, V>) -> String {
    encoded(
        &store
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

macro_rules! images {
    ($world:expr) => {{
        let world = &$world;
        [
            image(&world.asset_definition_domains),
            image(&world.domain_asset_definitions),
            image(&world.asset_definitions_by_owner),
            image(&world.asset_definition_holders),
            image(&world.asset_definition_assets),
            image(&world.assets_by_account),
            image(&world.assets_by_domain),
            image(&world.asset_definition_nonzero_holders),
        ]
    }};
}

fn indexes(world: &World) -> [String; 8] {
    [
        encoded(&world.asset_definition_domains),
        encoded(&world.domain_asset_definitions),
        encoded(&world.asset_definitions_by_owner),
        encoded(&world.asset_definition_holders),
        encoded(&world.asset_definition_assets),
        encoded(&world.assets_by_account),
        encoded(&world.assets_by_domain),
        encoded(&world.asset_definition_nonzero_holders),
    ]
}

fn sources(world: &World) -> [String; 3] {
    [
        encoded(&world.domains),
        encoded(&world.asset_definitions),
        encoded(&world.assets),
    ]
}

fn fixture() -> Box<World> {
    let mut world = Box::new(World::default());
    for owner in [&*ALICE_ID, &*BOB_ID] {
        let (id, value) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, value);
    }
    for name in ["assets", "next"] {
        let id = domain(name);
        world
            .domains
            .insert(id.clone(), Domain::new(id).build(&ALICE_ID));
    }
    for name in ["coin", "spare"] {
        world.asset_definitions.insert(
            definition(name),
            value(name, &ALICE_ID, Some(domain("assets"))),
        );
    }
    for (name, owner, amount) in [
        ("coin", &*ALICE_ID, 5),
        ("coin", &*BOB_ID, 0),
        ("spare", &*BOB_ID, 7),
    ] {
        let (id, value) = balance(name, owner, amount);
        world.assets.insert(id, value);
    }
    assets(&mut world).unwrap();
    world
}

fn change_sources(world: &World) {
    let mut definitions = world.asset_definitions.block();
    definitions.insert(definition("coin"), value("coin", &BOB_ID, None));
    definitions.insert(
        definition("new"),
        value("new", &ALICE_ID, Some(domain("next"))),
    );
    // Retain redundant touches without losing untouched members of the bucket.
    definitions.insert(
        definition("spare"),
        value("spare", &ALICE_ID, Some(domain("assets"))),
    );
    definitions.commit();
    let mut balances = world.assets.block();
    balances.remove(AssetId::new(definition("coin"), ALICE_ID.clone()));
    for (name, owner, amount) in [
        ("coin", &*BOB_ID, 3),
        ("new", &*ALICE_ID, 4),
        ("spare", &*BOB_ID, 7),
    ] {
        let (id, value) = balance(name, owner, amount);
        balances.insert(id, value);
    }
    balances.commit();
}

#[test]
fn all_eight_indexes_restore_both_images_through_canonical_snapshot_and_replacement() {
    let mut world = fixture();
    let before = images!(world.view());
    change_sources(&world);
    let original = sources(&world);
    world.domains = restored(&world.domains);
    world.asset_definitions = restored(&world.asset_definitions);
    world.assets = restored(&world.assets);
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(
        sources(&world),
        original,
        "derived recovery never rewrites canonical undo"
    );
    let view = world.view();
    assert_eq!(view.asset_definition_domains.get(&definition("coin")), None);
    assert_eq!(
        view.asset_definitions_by_owner.get(&BOB_ID),
        Some(&BTreeSet::from([definition("coin")]))
    );
    assert_eq!(
        view.asset_definition_holders.get(&definition("coin")),
        Some(&BTreeSet::from([BOB_ID.clone()]))
    );
    assert_eq!(
        view.asset_definition_nonzero_holders
            .get(&definition("coin")),
        Some(&BTreeSet::from([BOB_ID.clone()]))
    );
    assert_eq!(
        view.assets_by_domain.get(&domain("assets")),
        Some(&BTreeSet::from([AssetId::new(
            definition("spare"),
            BOB_ID.clone()
        )]))
    );
    assert_eq!(
        view.assets_by_domain.get(&domain("next")),
        Some(&BTreeSet::from([AssetId::new(
            definition("new"),
            ALICE_ID.clone()
        )]))
    );
    drop(view);
    {
        let replacement = world.block_and_revert();
        assert_eq!(images!(replacement), before);
        replacement.commit();
    }
    assert_eq!(images!(world.view()), before);
    let replaced = sources(&world);
    assets(&mut world).unwrap();
    assert_eq!(images!(world.view()), before);
    assert_eq!(sources(&world), replaced);
}

#[test]
fn definition_only_domain_changes_move_untouched_balances_in_both_images() {
    let mut world = fixture();
    let before = images!(world.view());
    {
        let mut definitions = world.asset_definitions.block();
        definitions.insert(
            definition("coin"),
            value("coin", &ALICE_ID, Some(domain("next"))),
        );
        definitions.commit();
    }
    assert!(world.assets.history().revert_map().is_empty());
    assets(&mut world).unwrap();
    assert_eq!(
        world.assets_by_domain.view().get(&domain("next")),
        Some(&BTreeSet::from([
            AssetId::new(definition("coin"), ALICE_ID.clone()),
            AssetId::new(definition("coin"), BOB_ID.clone()),
        ]))
    );
    assert_eq!(images!(world.block_and_revert()), before);
}

#[test]
fn failures_in_either_image_leave_every_derived_index_and_source_unchanged() {
    for (previous, missing_definition, restricted) in
        [false, true].into_iter().flat_map(|previous| {
            [
                (previous, false, false),
                (previous, true, false),
                (previous, false, true),
            ]
        })
    {
        let mut world = fixture();
        if missing_definition {
            let mut current = world
                .asset_definitions
                .view()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>();
            let undo = if previous {
                BTreeMap::from([(definition("coin"), None)])
            } else {
                current.remove(&definition("coin"));
                BTreeMap::new()
            };
            world.asset_definitions = Storage::from_snapshot_parts(current, undo);
        } else {
            let bad = if restricted {
                AssetDefinition::numeric(
                    definition("coin"),
                    "coin",
                    AssetBalancePolicy::DataspaceRestricted,
                    None,
                )
                .build(&ALICE_ID)
            } else {
                value("coin", &ALICE_ID, Some(domain("absent")))
            };
            let mut current = world
                .asset_definitions
                .view()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>();
            let undo = if previous {
                BTreeMap::from([(definition("coin"), Some(bad))])
            } else {
                current.insert(definition("coin"), bad);
                BTreeMap::new()
            };
            world.asset_definitions = Storage::from_snapshot_parts(current, undo);
        }
        let original = sources(&world);
        let derived = indexes(&world);
        let error = assets(&mut world).unwrap_err();
        assert!(error.contains(if missing_definition {
            "missing asset definition"
        } else if restricted {
            "requires an immutable home"
        } else {
            "missing owning domain"
        }));
        assert_eq!(sources(&world), original);
        assert_eq!(indexes(&world), derived);
    }
}

#[test]
fn redundant_touches_preserve_complete_members_and_explicit_absence() {
    let mut world = fixture();
    {
        let mut definitions = world.asset_definitions.block();
        definitions.insert(
            definition("coin"),
            value("coin", &ALICE_ID, Some(domain("assets"))),
        );
        definitions.insert(definition("domainless"), value("domainless", &BOB_ID, None));
        definitions.commit();
    }
    assets(&mut world).unwrap();
    let owners = world.asset_definitions_by_owner.history();
    assert_eq!(
        owners.revert_map().get(&ALICE_ID),
        Some(&Some(BTreeSet::from([
            definition("coin"),
            definition("spare")
        ])))
    );
    assert_eq!(owners.revert_map().get(&BOB_ID), Some(&None));
    let domains = world.asset_definition_domains.history();
    assert_eq!(
        domains.revert_map().get(&definition("domainless")),
        Some(&None)
    );
    assert!(domains.current().get(&definition("domainless")).is_none());
}

#[test]
fn holders_deduplicate_partitions_and_keep_any_nonzero_predecessor() {
    let mut world = fixture();
    let partition = AssetId::with_scope(
        definition("coin"),
        BOB_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    world.assets.insert(
        partition.clone(),
        Asset::new(partition.clone(), 2_u32).into_key_value().1,
    );
    assets(&mut world).unwrap();
    let before = images!(world.view());
    {
        let mut balances = world.assets.block();
        balances.insert(
            partition.clone(),
            Asset::new(partition, 0_u32).into_key_value().1,
        );
        balances.commit();
    }
    assets(&mut world).unwrap();
    assert_eq!(
        world
            .asset_definition_holders
            .view()
            .get(&definition("coin")),
        Some(&BTreeSet::from([ALICE_ID.clone(), BOB_ID.clone()]))
    );
    assert_eq!(
        world
            .asset_definition_nonzero_holders
            .view()
            .get(&definition("coin")),
        Some(&BTreeSet::from([ALICE_ID.clone()]))
    );
    assert_eq!(images!(world.block_and_revert()), before);
}
