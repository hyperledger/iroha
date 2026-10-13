//! Alias restoration uses live writes as the oracle for both retained images.

use super::*;
use iroha_data_model::{account::Account, prelude::Registrable};
use norito::codec::DecodeAll;

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
        .decode("alias fixture", |_, _| true)
        .unwrap()
}

fn domain() -> DomainId {
    DomainId::try_new("issuer", "universal").unwrap()
}

fn definition(i: u8) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), format!("coin{i}").parse().unwrap())
}

fn contract(i: u8) -> ContractAddress {
    ContractAddress::derive(
        &DEFAULT_TEST_NETWORK_ID,
        &iroha_test_samples::ALICE_ID,
        u64::from(i),
        DataSpaceId::UNIVERSAL,
    )
    .unwrap()
}

fn asset_alias(name: &str) -> AssetDefinitionAlias {
    format!("{name}#issuer.universal").parse().unwrap()
}

fn contract_alias(name: &str) -> ContractAlias {
    format!("{name}::universal").parse().unwrap()
}

fn indexes(world: &World) -> [String; 2] {
    [
        encoded(&world.asset_definition_aliases),
        encoded(&world.contract_aliases),
    ]
}

fn sources(world: &World) -> [String; 4] {
    [
        encoded(&world.asset_definition_alias_bindings),
        encoded(&world.contract_alias_bindings),
        encoded(&world.asset_definitions),
        encoded(&world.domains),
    ]
}

fn rebuild(world: &mut World) {
    world.rebuild_asset_definition_alias_indexes().unwrap();
    world.rebuild_contract_alias_indexes().unwrap();
}

fn fixture() -> World {
    let mut world = World::default();
    let alice = &*iroha_test_samples::ALICE_ID;
    let (id, value) = Account::new(alice.clone()).build(alice).into_key_value();
    world.accounts.insert(id, value);
    world
        .domains
        .insert(domain(), Domain::new(domain()).build(alice));
    for i in 0..5 {
        world.asset_definitions.insert(
            definition(i),
            AssetDefinition::numeric(
                definition(i),
                format!("coin{i}"),
                AssetBalancePolicy::Global,
                None,
            )
            .build(alice),
        );
        if i < 3 {
            world.asset_definition_alias_bindings.insert(
                definition(i),
                AssetDefinitionAliasBindingRecord {
                    alias: asset_alias(&format!("coin{i}")),
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 1,
                },
            );
            world.contract_alias_bindings.insert(
                contract(i),
                ContractAliasBindingRecord {
                    alias: contract_alias(&format!("router{i}")),
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 1,
                },
            );
        }
    }
    rebuild(&mut world);
    world
}

fn restart(world: &World) -> World {
    let mut copy = World::new();
    copy.accounts = restored(&world.accounts);
    copy.domains = restored(&world.domains);
    copy.asset_definitions = restored(&world.asset_definitions);
    copy.asset_definition_alias_bindings = restored(&world.asset_definition_alias_bindings);
    copy.contract_alias_bindings = restored(&world.contract_alias_bindings);
    rebuild(&mut copy);
    copy
}

fn change(block: &mut WorldBlock<'_>, replacement: bool) {
    let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
    for (i, name) in [
        (
            0,
            if replacement {
                "replacement"
            } else {
                "renamed"
            },
        ),
        (2, "coin2"),
        (3, "added"),
    ] {
        tx.bind_asset_definition_alias(&definition(i), asset_alias(name), None, None, 1)
            .unwrap();
        let name = if i == 2 { "router2" } else { name };
        tx.bind_contract_alias(&contract(i), contract_alias(name), None, None, 1)
            .unwrap();
    }
    tx.clear_asset_definition_alias(&definition(1));
    tx.clear_contract_alias(&contract(1));
    tx.clear_asset_definition_alias(&definition(4));
    tx.clear_contract_alias(&contract(4));
    tx.apply();
}

#[test]
fn alias_indexes_restore_live_rename_remove_insert_and_redundant_touches() {
    let live = fixture();
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let recovered = restart(&live);
    assert_eq!(sources(&recovered), sources(&live));
    assert_eq!(indexes(&recovered), indexes(&live));
    assert!(
        recovered
            .asset_definition_aliases
            .snapshot()
            .revert_map()
            .contains_key(&asset_alias("coin2"))
    );
    assert!(
        recovered
            .contract_aliases
            .snapshot()
            .revert_map()
            .contains_key(&contract_alias("router2"))
    );
    let before = indexes(&recovered);
    {
        let block = recovered.block_and_revert();
        for i in 0..3 {
            assert_eq!(
                block
                    .asset_definition_aliases
                    .get(&asset_alias(&format!("coin{i}"))),
                Some(&definition(i))
            );
            assert_eq!(
                block
                    .contract_aliases
                    .get(&contract_alias(&format!("router{i}"))),
                Some(&contract(i))
            );
        }
        assert!(
            block
                .asset_definition_aliases
                .get(&asset_alias("renamed"))
                .is_none()
        );
        assert!(
            block
                .contract_aliases
                .get(&contract_alias("added"))
                .is_none()
        );
    }
    assert_eq!(
        indexes(&recovered),
        before,
        "abandoned replacement must not publish"
    );
}

#[test]
fn alias_indexes_follow_committed_replacement_and_second_restart() {
    let live = fixture();
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let recovered = restart(&live);
    for world in [&live, &recovered] {
        let mut block = world.block_and_revert();
        change(&mut block, true);
        block.commit();
    }
    assert_eq!(sources(&recovered), sources(&live));
    assert_eq!(indexes(&recovered), indexes(&live));
    let again = restart(&recovered);
    assert_eq!(indexes(&again), indexes(&live));
    assert_eq!(sources(&again), sources(&live));
    let block = again.block_and_revert();
    assert_eq!(
        block.asset_definition_aliases.get(&asset_alias("coin0")),
        Some(&definition(0))
    );
    assert_eq!(
        block.contract_aliases.get(&contract_alias("router0")),
        Some(&contract(0))
    );
    assert!(
        block
            .asset_definition_aliases
            .get(&asset_alias("replacement"))
            .is_none()
    );
}

#[test]
fn invalid_asset_predecessor_rejects_before_sources_or_index_change() {
    for kind in ["lease", "duplicate", "definition", "domain"] {
        let mut world = fixture();
        let current = world
            .asset_definition_alias_bindings
            .view()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut prior = world
            .asset_definition_alias_bindings
            .view()
            .get(&definition(0))
            .unwrap()
            .clone();
        match kind {
            "lease" => prior.grace_until_ms = Some(10),
            "duplicate" => prior.alias = asset_alias("coin1"),
            "definition" => {
                let current = world
                    .asset_definitions
                    .view()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                world.asset_definitions =
                    Storage::from_snapshot_parts(current, BTreeMap::from([(definition(0), None)]));
            }
            "domain" => {
                let current = world
                    .domains
                    .view()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                world.domains =
                    Storage::from_snapshot_parts(current, BTreeMap::from([(domain(), None)]));
            }
            _ => unreachable!(),
        }
        world.asset_definition_alias_bindings =
            Storage::from_snapshot_parts(current, BTreeMap::from([(definition(0), Some(prior))]));
        let before_sources = sources(&world);
        let before_indexes = indexes(&world);
        let error = world.rebuild_asset_definition_alias_indexes().unwrap_err();
        let expected = match kind {
            "lease" => "invalid lease",
            "duplicate" => "multiple targets",
            "definition" => "missing asset definition",
            "domain" => "missing domain",
            _ => unreachable!(),
        };
        assert!(error.contains(expected), "{kind}: {error}");
        assert_eq!(sources(&world), before_sources);
        assert_eq!(indexes(&world), before_indexes);
    }
}

#[test]
fn removed_alias_dependencies_are_valid_in_the_retained_predecessor() {
    let live = fixture();
    {
        let mut block = live.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        for i in 0..3 {
            tx.clear_asset_definition_alias(&definition(i));
            tx.asset_definitions.remove(definition(i));
        }
        tx.domains.remove(domain());
        tx.apply();
        block.commit();
    }
    let recovered = restart(&live);
    assert_eq!(sources(&recovered), sources(&live));
    assert_eq!(indexes(&recovered), indexes(&live));
    assert!(recovered.asset_definition_aliases.view().is_empty());
    let block = recovered.block_and_revert();
    assert!(block.domains.get(&domain()).is_some());
    for i in 0..3 {
        assert!(block.asset_definitions.get(&definition(i)).is_some());
        assert_eq!(
            block
                .asset_definition_aliases
                .get(&asset_alias(&format!("coin{i}"))),
            Some(&definition(i))
        );
    }
}

#[test]
fn invalid_contract_predecessor_rejects_before_sources_or_index_change() {
    for duplicate in [false, true] {
        let mut world = fixture();
        let current = world
            .contract_alias_bindings
            .view()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut prior = world
            .contract_alias_bindings
            .view()
            .get(&contract(0))
            .unwrap()
            .clone();
        if duplicate {
            prior.alias = contract_alias("router1");
        } else {
            prior.grace_until_ms = Some(10);
        }
        world.contract_alias_bindings =
            Storage::from_snapshot_parts(current, BTreeMap::from([(contract(0), Some(prior))]));
        let before_sources = sources(&world);
        let before_indexes = indexes(&world);
        let error = world.rebuild_contract_alias_indexes().unwrap_err();
        assert!(
            error.contains(if duplicate {
                "multiple targets"
            } else {
                "invalid lease"
            }),
            "{error}"
        );
        assert_eq!(sources(&world), before_sources);
        assert_eq!(indexes(&world), before_indexes);
    }
}
