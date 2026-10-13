//! Ownership projections retain the same replacement history as live index writes.

use super::*;
use iroha_data_model::{account::Account, nft::Nft, prelude::Registrable, rwa::RwaControlPolicy};
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
        .decode("ownership fixture", |_, _| true)
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

macro_rules! index_images {
    ($world:expr) => {{
        let world = &$world;
        [
            image(&world.domains_by_owner),
            image(&world.nfts_by_owner),
            image(&world.nfts_by_domain),
            image(&world.rwas_by_owner),
            image(&world.rwas_by_status),
            image(&world.rwas_by_frozen),
        ]
    }};
}

fn indexes(world: &World) -> [String; 6] {
    [
        encoded(&world.domains_by_owner),
        encoded(&world.nfts_by_owner),
        encoded(&world.nfts_by_domain),
        encoded(&world.rwas_by_owner),
        encoded(&world.rwas_by_status),
        encoded(&world.rwas_by_frozen),
    ]
}

fn sources(world: &World) -> [String; 3] {
    [
        encoded(&world.domains),
        encoded(&world.nfts),
        encoded(&world.rwas),
    ]
}

fn rebuild(world: &mut World) {
    world.rebuild_domain_owner_index();
    world.rebuild_nft_owner_index();
    world.rebuild_rwa_indexes();
}

fn restart(world: &World) -> World {
    let mut result = World::new();
    result.accounts = restored(&world.accounts);
    result.domains = restored(&world.domains);
    result.nfts = restored(&world.nfts);
    result.rwas = restored(&world.rwas);
    rebuild(&mut result);
    result
}

fn domain(name: &str) -> DomainId {
    DomainId::try_new(name, "universal").unwrap()
}

fn nft_id(name: &str) -> NftId {
    NftId::new(domain(name), "lot".parse().unwrap())
}

fn rwa_id(name: &str) -> RwaId {
    RwaId::generated(domain(name), Hash::new(name.as_bytes()))
}

fn rwa(name: &str, owner: &AccountId, status: Option<&str>, frozen: bool) -> RwaValue {
    let mut lot = iroha_data_model::rwa::Rwa::new(
        rwa_id(name),
        "5".parse::<Quantity>().unwrap(),
        NumericSpec::integer(),
        format!("https://example.test/{name}"),
        status.map(|status| status.parse().unwrap()),
        Metadata::default(),
        Vec::new(),
        RwaControlPolicy {
            freeze_enabled: true,
            ..RwaControlPolicy::default()
        },
        owner.clone(),
    );
    lot.is_frozen = frozen;
    lot.into_key_value().1
}

fn third_owner() -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![0x38; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}

fn fixture() -> World {
    let mut world = World::default();
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let third = third_owner();
    for owner in [&alice, &bob, &third] {
        let (id, value) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, value);
    }
    for (name, owner, status, frozen) in [
        ("moving", &alice, None, false),
        ("removed", &alice, Some("retired"), true),
        ("untouched", &third, Some("unchanged"), false),
        ("shared", &alice, None, false),
    ] {
        world
            .domains
            .insert(domain(name), Domain::new(domain(name)).build(owner));
        let (id, value) = Nft::new(nft_id(name), Metadata::default())
            .build(owner)
            .into_key_value();
        world.nfts.insert(id, value);
        world
            .rwas
            .insert(rwa_id(name), rwa(name, owner, status, frozen));
    }
    rebuild(&mut world);
    world
}

/// Exercise the existing live index mutators as the independent restore oracle.
fn change(block: &mut WorldBlock<'_>, replacement: bool) {
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let third = third_owner();
    let next = if replacement { &third } else { &bob };
    let added = if replacement { &bob } else { &alice };
    let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
    for (name, owner, status, frozen) in [
        (
            "moving",
            next,
            Some(if replacement { "replacement" } else { "active" }),
            !replacement,
        ),
        ("added", added, None, false),
        // Redundant touches must survive even though this bucket does not change.
        ("untouched", &third, Some("unchanged"), false),
    ] {
        tx.insert_domain_entry(domain(name), Domain::new(domain(name)).build(owner));
        let (id, value) = Nft::new(nft_id(name), Metadata::default())
            .build(owner)
            .into_key_value();
        tx.insert_nft_entry(id, value);
        tx.insert_rwa_entry(rwa_id(name), rwa(name, owner, status, frozen));
    }
    tx.remove_domain_entry(&domain("removed")).unwrap();
    tx.remove_nft_entry(&nft_id("removed")).unwrap();
    let id = rwa_id("removed");
    let removed = tx.rwas.remove(id.clone()).unwrap();
    tx.untrack_rwa_owner(&id, &removed.owned_by);
    tx.untrack_rwa_status(&id, &removed.status);
    tx.untrack_rwa_frozen(&id, removed.is_frozen);
    tx.apply();
}

#[test]
fn ownership_indexes_restore_both_images_and_redundant_touches() {
    let live = fixture();
    let before = index_images!(live.view());
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let authoritative = sources(&live);
    let expected = indexes(&live);
    let mut recovered = restart(&live);
    assert_eq!(sources(&recovered), authoritative);
    assert_eq!(indexes(&recovered), expected);
    assert_eq!(index_images!(recovered.view()), index_images!(live.view()));
    let third = third_owner();
    assert!(
        recovered
            .domains_by_owner
            .snapshot()
            .revert_map()
            .contains_key(&third),
        "unchanged owner bucket retains the source touch"
    );
    assert!(
        recovered
            .nfts_by_domain
            .snapshot()
            .revert_map()
            .contains_key(&domain("moving")),
        "NFT ownership change still touches the unchanged domain bucket"
    );
    assert_eq!(
        recovered
            .rwas_by_status
            .snapshot()
            .revert_map()
            .get(&Some("active".parse().unwrap())),
        Some(&None),
        "new status bucket retains prior absence"
    );
    {
        let mut replacement = recovered.block_and_revert();
        assert_eq!(index_images!(replacement), before);
        assert_eq!(
            replacement.rwas_by_status.get(&None),
            Some(&BTreeSet::from([rwa_id("moving"), rwa_id("shared")]))
        );
        change(&mut replacement, true);
        // Dropping a replacement must leave current rows and undo maps untouched.
    }
    assert_eq!(sources(&recovered), authoritative);
    assert_eq!(indexes(&recovered), expected);
    rebuild(&mut recovered);
    assert_eq!(indexes(&recovered), expected);
    let second = restart(&recovered);
    assert_eq!(indexes(&second), expected);
    assert_eq!(index_images!(second.block_and_revert()), before);
}

#[test]
fn ownership_indexes_follow_committed_replacement_and_second_restore() {
    let mut live = fixture();
    let before = index_images!(live.view());
    {
        let mut block = live.block();
        change(&mut block, false);
        block.commit();
    }
    let mut recovered = restart(&live);
    for world in [&mut live, &mut recovered] {
        let mut replacement = world.block_and_revert();
        assert_eq!(index_images!(replacement), before);
        change(&mut replacement, true);
        replacement.commit();
    }
    assert_eq!(sources(&recovered), sources(&live));
    assert_eq!(indexes(&recovered), indexes(&live));
    let expected = indexes(&live);
    rebuild(&mut recovered);
    assert_eq!(indexes(&recovered), expected);
    let mut second = restart(&recovered);
    assert_eq!(indexes(&second), expected);
    {
        let previous = second.block_and_revert();
        assert_eq!(index_images!(previous), before);
        previous.commit();
    }
    rebuild(&mut second);
    assert_eq!(index_images!(second.view()), before);
    assert!(second.domains_by_owner.snapshot().revert_map().is_empty());
    assert!(second.nfts_by_owner.snapshot().revert_map().is_empty());
    assert!(second.nfts_by_domain.snapshot().revert_map().is_empty());
    assert!(second.rwas_by_owner.snapshot().revert_map().is_empty());
    assert!(second.rwas_by_status.snapshot().revert_map().is_empty());
    assert!(second.rwas_by_frozen.snapshot().revert_map().is_empty());
}

#[test]
fn grouped_projection_keeps_complete_buckets_and_ignores_absent_records() {
    let mut source: Storage<u8, u8> = [(1, 7), (2, 7), (3, 9)].into_iter().collect();
    {
        let mut block = source.block();
        block.insert(1, 8);
        block.insert(3, 9);
        block.insert(4, 8);
        block.remove(5);
        block.commit();
    }
    let original = encoded(&source);
    let projected = grouped(&source.history(), |_, value| Some(*value));
    assert_eq!(encoded(&source), original);
    assert_eq!(
        projected
            .snapshot()
            .revert_map()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            (7, Some(BTreeSet::from([1, 2]))),
            (8, None),
            (9, Some(BTreeSet::from([3]))),
        ])
    );
    let previous = projected.block_and_revert();
    assert_eq!(previous.get(&7), Some(&BTreeSet::from([1, 2])));
    assert_eq!(previous.get(&8), None);
    assert_eq!(previous.get(&9), Some(&BTreeSet::from([3])));
}
