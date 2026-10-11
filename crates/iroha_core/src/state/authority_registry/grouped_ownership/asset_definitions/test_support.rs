//! Independent actual-original geometry equations and universal-account fixtures.

use super::*;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::{Account, AccountController},
    asset::definition::{
        AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
    },
    prelude::Registrable,
};
use iroha_test_samples::ALICE_ID;

pub(in crate::state) fn domain() -> DomainId {
    DomainId::try_new("definitiongroups", "universal").unwrap()
}
pub(in crate::state) fn id(number: usize) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), format!("coin{number}").parse().unwrap())
}
pub(in crate::state) fn definition(
    number: usize,
    owner: &AccountId,
    context: bool,
    height: Option<u64>,
) -> AssetDefinition {
    let mut value = AssetDefinition::numeric(
        id(number),
        format!("coin{number}"),
        AssetBalancePolicy::Global,
        context.then(domain),
    )
    .build(owner);
    let mut policy = AssetConfidentialPolicy::convertible();
    policy.pending_transition = height.map(|height| ConfidentialPolicyTransition {
        new_mode: ConfidentialPolicyMode::ShieldedOnly,
        effective_height: height,
        previous_mode: ConfidentialPolicyMode::Convertible,
        transition_id: Hash::new(number.to_le_bytes()),
        conversion_window: Some(1),
    });
    value.set_confidential_policy(policy);
    value
}
pub(in crate::state) fn world(context: bool, height: Option<u64>) -> World {
    let mut world = World::with(
        [Domain::new(domain()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [definition(0, &ALICE_ID, context, height)],
    );
    world.rebuild_asset_definition_indexes().unwrap();
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    world
}

// The reference computes independent equations over all original rows; it never
// calls production Work, equality, visit, lookup, policy preflight or validation.
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
                        .map(|member| 3 + member.public_key().input_payload_len() as u64)
                        .sum::<u64>()
            }
        }
    }
}
impl Geometry for u64 {
    fn units(&self) -> u64 {
        8
    }
}
impl Geometry for (u64, AssetDefinitionId) {
    fn units(&self) -> u64 {
        24
    }
}
fn logical<'a, K: mv::Key, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
) -> Vec<(&'a K, &'a V)> {
    match image {
        GroupImage::Current => rows.current_entries().collect(),
        GroupImage::Predecessor => rows
            .current_entries()
            .filter(|(key, _)| !rows.undo_entries().any(|(prior, _)| *key == prior))
            .chain(
                rows.undo_entries()
                    .filter_map(|(key, value)| value.as_ref().map(|value| (key, value))),
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
    let cost = visit_cost(rows, image)
        + candidates
            .iter()
            .map(|(candidate, _)| key.units() + candidate.units())
            .sum::<u64>();
    let found = candidates
        .into_iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value);
    (cost, found)
}
fn membership_cost(members: &BTreeSet<AssetDefinitionId>, id: &AssetDefinitionId) -> u64 {
    members
        .iter()
        .map(|candidate| 1 + id.units() + candidate.units())
        .sum()
}
fn optional_cost(left: Option<&DomainId>, right: Option<&DomainId>) -> u64 {
    2 + match (left, right) {
        (Some(left), Some(right)) => left.units() + right.units(),
        _ => 0,
    }
}
fn policy_cost(policy: &AssetConfidentialPolicy) -> u64 {
    2 + policy
        .pending_transition()
        .as_ref()
        .map_or(0, |transition| {
            43 + if transition.conversion_window().is_some() {
                8
            } else {
                0
            }
        })
}

pub(in crate::state) fn policy_work(
    definitions: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    transitions: &impl RawStorageImages<(u64, AssetDefinitionId), ()>,
    counts: &impl RawStorageImages<u64, u32>,
) -> u64 {
    let mut total = 0;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(definitions, image);
        for (id, definition) in logical(definitions, image) {
            let policy = definition.confidential_policy();
            total += policy_cost(policy);
            if let Some(transition) = policy.pending_transition() {
                let height = transition.effective_height();
                total += lookup_cost(transitions, image, &(height, id.clone())).0;
                let (cost, count) = lookup_cost(counts, image, &height);
                total += cost;
                if count.is_some() {
                    total += 4;
                }
            }
        }
        total += visit_cost(transitions, image);
        for ((_, id), ()) in logical(transitions, image) {
            let (cost, definition) = lookup_cost(definitions, image, id);
            total += cost;
            if let Some(definition) = definition {
                let policy = definition.confidential_policy();
                total += policy_cost(policy);
                if policy.pending_transition().is_some() {
                    total += 16;
                }
            }
        }
        total += visit_cost(counts, image);
        for (height, _) in logical(counts, image) {
            total += 4 + 4 + visit_cost(definitions, image);
            for (_, definition) in logical(definitions, image) {
                let policy = definition.confidential_policy();
                total += policy_cost(policy);
                if let Some(transition) = policy.pending_transition() {
                    total += 16;
                    if transition.effective_height() == *height {
                        total += 4;
                    }
                }
            }
            total += 8;
        }
    }
    total
}

pub(in crate::state) fn full_work(
    rows: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    domains: &impl RawStorageImages<DomainId, Domain>,
    contexts: &impl RawStorageImages<AssetDefinitionId, DomainId>,
    by_domain: &impl RawStorageImages<DomainId, BTreeSet<AssetDefinitionId>>,
    by_owner: &impl RawStorageImages<AccountId, BTreeSet<AssetDefinitionId>>,
    transitions: &impl RawStorageImages<(u64, AssetDefinitionId), ()>,
    counts: &impl RawStorageImages<u64, u32>,
) -> u64 {
    let mut total = 0;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, definition) in logical(rows, image) {
            total += 2;
            let domain = definition.owning_domain().as_ref();
            if let Some(domain) = domain {
                total += lookup_cost(domains, image, domain).0;
            }
            let (cost, context) = lookup_cost(contexts, image, id);
            total += cost + optional_cost(domain, context);
        }
        total += visit_cost(contexts, image);
        for (id, domain) in logical(contexts, image) {
            let (cost, definition) = lookup_cost(rows, image, id);
            total += cost;
            if let Some(definition) = definition {
                total += optional_cost(definition.owning_domain().as_ref(), Some(domain));
            }
        }
    }
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, definition) in logical(rows, image) {
            let (cost, members) = lookup_cost(by_owner, image, definition.owned_by());
            total += cost;
            if let Some(members) = members {
                total += membership_cost(members, id);
            }
        }
        total += visit_cost(by_owner, image);
        for (owner, members) in logical(by_owner, image) {
            total += 1;
            for id in members {
                total += 1;
                let (cost, definition) = lookup_cost(rows, image, id);
                total += cost;
                if let Some(definition) = definition {
                    total += definition.owned_by().units() + owner.units();
                }
            }
        }
    }
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, definition) in logical(rows, image) {
            total += 1;
            if let Some(domain) = definition.owning_domain().as_ref() {
                let (cost, members) = lookup_cost(by_domain, image, domain);
                total += cost;
                if let Some(members) = members {
                    total += membership_cost(members, id);
                }
            }
        }
        total += visit_cost(by_domain, image);
        for (domain, members) in logical(by_domain, image) {
            total += 1;
            for id in members {
                total += 1;
                let (cost, definition) = lookup_cost(rows, image, id);
                total += cost;
                if let Some(definition) = definition {
                    total += optional_cost(definition.owning_domain().as_ref(), Some(domain));
                }
            }
        }
    }
    total + policy_work(rows, transitions, counts)
}
pub(in crate::state) fn world_work(world: &World) -> u64 {
    let rows = world
        .asset_definitions
        .try_committed_view_nonblocking()
        .unwrap();
    let domains = world.domains.try_committed_view_nonblocking().unwrap();
    let contexts = world
        .asset_definition_domains
        .try_committed_view_nonblocking()
        .unwrap();
    let by_domain = world
        .domain_asset_definitions
        .try_committed_view_nonblocking()
        .unwrap();
    let by_owner = world
        .asset_definitions_by_owner
        .try_committed_view_nonblocking()
        .unwrap();
    let transitions = world
        .confidential_policy_transition_index
        .try_committed_view_nonblocking()
        .unwrap();
    let counts = world
        .confidential_policy_transition_counts
        .try_committed_view_nonblocking()
        .unwrap();
    full_work(
        &rows,
        &domains,
        &contexts,
        &by_domain,
        &by_owner,
        &transitions,
        &counts,
    )
}
pub(in crate::state) fn world_policy_work(world: &World) -> u64 {
    let rows = world
        .asset_definitions
        .try_committed_view_nonblocking()
        .unwrap();
    let transitions = world
        .confidential_policy_transition_index
        .try_committed_view_nonblocking()
        .unwrap();
    let counts = world
        .confidential_policy_transition_counts
        .try_committed_view_nonblocking()
        .unwrap();
    policy_work(&rows, &transitions, &counts)
}
