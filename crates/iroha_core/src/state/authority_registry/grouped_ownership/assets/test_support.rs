//! Real balance fixtures and independent original-row work equations.
use super::*;
use crate::test_allocations::allocations_during;
use iroha_data_model::{
    IntoKeyValue,
    account::{Account, AccountController},
    asset::Asset,
    prelude::Registrable,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::{Storage, StorageReadOnly};

pub(in crate::state) fn domain(name: &str) -> DomainId {
    DomainId::try_new(name, "universal").unwrap()
}

pub(in crate::state) fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain("balances"), name.parse().unwrap())
}

pub(in crate::state) fn id() -> AssetId {
    AssetId::new(definition("coin"), ALICE_ID.clone())
}

pub(in crate::state) fn value(id: &AssetId, amount: u32) -> AssetValue {
    Asset::new(id.clone(), amount).into_key_value().1
}

pub(in crate::state) fn fixture(context: bool) -> Box<World> {
    let mut world = Box::new(World::default());
    for owner in [&*ALICE_ID, &*BOB_ID] {
        let (id, account) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, account);
    }
    world.domains.insert(
        domain("balances"),
        Domain::new(domain("balances")).build(&ALICE_ID),
    );
    let record = AssetDefinition::numeric(
        definition("coin"),
        "coin",
        AssetBalancePolicy::Global,
        context.then(|| domain("balances")),
    )
    .build(&ALICE_ID);
    world.asset_definitions.insert(definition("coin"), record);
    world.assets.insert(id(), value(&id(), 5));
    world.rebuild_asset_definition_indexes().unwrap();
    world
}

pub(in crate::state) fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(CheckedAssets::capture(world, work).map(|_| ()))),
        0
    );
    result.unwrap()
}

pub(in crate::state) fn omit_initial<K: mv::Key, V: mv::Value>(
    store: &mut Storage<K, V>,
    key: &K,
) -> V {
    let (replacement, removed) = {
        let view = store.view();
        let removed = view.get(key).unwrap().clone();
        let replacement = view
            .iter()
            .filter(|(candidate, _)| *candidate != key)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        (replacement, removed)
    };
    *store = replacement;
    removed
}

pub(in crate::state) fn corrupt(
    index: &'static str,
    previous: bool,
    mismatch: GroupMismatch,
) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index,
        image: if previous {
            GroupImage::Predecessor
        } else {
            GroupImage::Current
        },
        mismatch,
    }
}

// Independent source-geometry arithmetic, never production work/equality/scan/validator helpers.
trait Geometry: mv::Key {
    fn units(&self) -> u64;
}
impl Geometry for AssetDefinitionId {
    fn units(&self) -> u64 {
        16
    }
}
impl Geometry for DomainId {
    fn units(&self) -> u64 {
        (self.name().as_ref().len() + self.dataspace().as_ref().len()) as u64
    }
}
impl Geometry for AccountId {
    fn units(&self) -> u64 {
        match self.controller() {
            AccountController::Single(key) => 2 + key.input_payload_len() as u64,
            AccountController::Multisig(policy) => {
                12 + policy.members().len() as u64
                    + policy
                        .members()
                        .iter()
                        .map(|m| 3 + m.public_key().input_payload_len() as u64)
                        .sum::<u64>()
            }
        }
    }
}
impl Geometry for AssetId {
    fn units(&self) -> u64 {
        self.account().units()
            + 16
            + 1
            + if matches!(self.scope(), AssetBalanceScope::Dataspace(_)) {
                8
            } else {
                0
            }
    }
}
fn logical<K: mv::Key, V: mv::Value>(
    rows: &impl RawStorageImages<K, V>,
    image: GroupImage,
) -> Vec<(&K, &V)> {
    match image {
        GroupImage::Current => rows.current_entries().collect(),
        GroupImage::Predecessor => rows
            .current_entries()
            .filter(|(key, _)| !rows.undo_entries().any(|(prior, _)| *key == prior))
            .chain(
                rows.undo_entries()
                    .filter_map(|(key, prior)| prior.as_ref().map(|value| (key, value))),
            )
            .collect(),
    }
}
fn visit_cost<K: Geometry, V: mv::Value>(
    rows: &impl RawStorageImages<K, V>,
    image: GroupImage,
) -> u64 {
    let current = rows.current_entries().len() as u64;
    if image == GroupImage::Current {
        return current;
    }
    current
        + rows
            .current_entries()
            .map(|(key, _)| {
                rows.undo_entries()
                    .map(|(prior, _)| 1 + key.units() + prior.units())
                    .sum::<u64>()
            })
            .sum::<u64>()
        + 2 * rows.undo_entries().len() as u64
}
fn lookup_cost<'a, K: Geometry, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    key: &K,
) -> (u64, Option<&'a V>) {
    let candidates = logical(rows, image);
    let work = visit_cost(rows, image)
        + candidates
            .iter()
            .map(|(candidate, _)| key.units() + candidate.units())
            .sum::<u64>();
    let value = candidates
        .into_iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value);
    (work, value)
}
fn member_cost<K: Geometry>(members: &BTreeSet<K>, member: &K) -> u64 {
    members
        .iter()
        .map(|candidate| 1 + member.units() + candidate.units())
        .sum()
}
fn require_cost<G: Geometry, K: Geometry>(
    groups: &impl RawStorageImages<G, BTreeSet<K>>,
    image: GroupImage,
    group: &G,
    member: &K,
) -> u64 {
    let (work, members) = lookup_cost(groups, image, group);
    work + members.map_or(0, |members| member_cost(members, member))
}
fn group_cost<G: Geometry>(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    groups: &impl RawStorageImages<G, BTreeSet<AssetId>>,
    projection: impl Fn(&AssetId) -> &G,
) -> u64 {
    let mut total = 0;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, _) in logical(rows, image) {
            total += require_cost(groups, image, projection(id), id);
        }
        total += visit_cost(groups, image);
        for (group, members) in logical(groups, image) {
            total += 1;
            for id in members {
                let (work, value) = lookup_cost(rows, image, id);
                total += 1 + work;
                if value.is_some() {
                    total += projection(id).units() + group.units();
                }
            }
        }
    }
    total
}
fn partition_cost(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    image: GroupImage,
    account: &AccountId,
    definition: &AssetDefinitionId,
    nonzero: bool,
) -> u64 {
    visit_cost(rows, image)
        + logical(rows, image)
            .into_iter()
            .map(|(id, _)| {
                id.account().units()
                    + account.units()
                    + 32
                    + u64::from(nonzero && id.account() == account && id.definition() == definition)
            })
            .sum::<u64>()
}
pub(in crate::state) fn full_work(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    definitions: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    domains: &impl RawStorageImages<DomainId, Domain>,
    by_definition: &impl RawStorageImages<AssetDefinitionId, BTreeSet<AssetId>>,
    by_account: &impl RawStorageImages<AccountId, BTreeSet<AssetId>>,
    by_domain: &impl RawStorageImages<DomainId, BTreeSet<AssetId>>,
    holders: &impl RawStorageImages<AssetDefinitionId, BTreeSet<AccountId>>,
    nonzero: &impl RawStorageImages<AssetDefinitionId, BTreeSet<AccountId>>,
) -> u64 {
    let mut total = group_cost(rows, by_definition, AssetId::definition)
        + group_cost(rows, by_account, AssetId::account);
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, value) in logical(rows, image) {
            let (cost, definition) = lookup_cost(definitions, image, id.definition());
            total += cost;
            if let Some(definition) = definition {
                total += 2 + u64::from(
                    definition.balance_scope_policy() == AssetBalancePolicy::DataspaceRestricted,
                );
                if let Some(domain) = definition.owning_domain() {
                    total += lookup_cost(domains, image, domain).0
                        + require_cost(by_domain, image, domain, id);
                }
                total += require_cost(holders, image, id.definition(), id.account()) + 1;
                if !value.as_ref().is_zero() {
                    total += require_cost(nonzero, image, id.definition(), id.account());
                }
            }
        }
        total += visit_cost(by_domain, image);
        for (domain, members) in logical(by_domain, image) {
            total += 1;
            for id in members {
                let (cost, row) = lookup_cost(rows, image, id);
                total += 1 + cost;
                if row.is_some() {
                    let (cost, definition) = lookup_cost(definitions, image, id.definition());
                    total += cost;
                    if let Some(definition) = definition {
                        total += 1;
                        if let Some(actual) = definition.owning_domain() {
                            total += actual.units() + domain.units();
                        }
                    }
                }
            }
        }
        total += holder_cost(rows, holders, image, false) + holder_cost(rows, nonzero, image, true);
    }
    total
}
fn holder_cost(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    groups: &impl RawStorageImages<AssetDefinitionId, BTreeSet<AccountId>>,
    image: GroupImage,
    nonzero: bool,
) -> u64 {
    visit_cost(groups, image)
        + logical(groups, image)
            .into_iter()
            .map(|(definition, members)| {
                1 + members
                    .iter()
                    .map(|account| 1 + partition_cost(rows, image, account, definition, nonzero))
                    .sum::<u64>()
            })
            .sum::<u64>()
}
pub(in crate::state) fn world_work(world: &World) -> u64 {
    full_work(
        &world.assets.try_committed_view_nonblocking().unwrap(),
        &world
            .asset_definitions
            .try_committed_view_nonblocking()
            .unwrap(),
        &world.domains.try_committed_view_nonblocking().unwrap(),
        &world
            .asset_definition_assets
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .assets_by_account
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .assets_by_domain
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .asset_definition_holders
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .asset_definition_nonzero_holders
            .try_committed_view_nonblocking()
            .unwrap(),
    )
}
