//! Original repo fixtures and independent complete-cut work arithmetic.
use super::*;
use crate::test_allocations::allocations_during;
use iroha_data_model::{
    account::{Account, AccountController},
    asset::{AssetDefinitionId, AssetId},
    prelude::Registrable,
    repo::{RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::{Storage, StorageReadOnly};
/// Local comparison allowance for original semantic fixtures, never a physical pool limit.
pub(in crate::state) const TEST_WORK_ALLOWANCE: u64 = 1_048_576;
pub(in crate::state) fn id() -> RepoAgreementId {
    "exactrepogroups".parse().unwrap()
}

pub(in crate::state) fn fixture(custodian: bool) -> World {
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("repogroups", "universal").unwrap(),
        "token".parse().unwrap(),
    );
    let record = RepoAgreement::new(
        id(),
        ALICE_ID.clone(),
        BOB_ID.clone(),
        RepoCashLeg::new(definition.clone(), Quantity::one()),
        AssetId::of(definition.clone(), BOB_ID.clone()),
        RepoCollateralLeg::new(definition.clone(), Quantity::one()),
        AssetId::of(definition, BOB_ID.clone()),
        100,
        1_000,
        1,
        RepoGovernance::new(1_000, 60, false),
        custodian.then(|| BOB_ID.clone()),
    );
    world.repo_agreements.insert(id(), record);
    world.rebuild_repo_agreement_indexes();
    world
}

pub(in crate::state) fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(
            || result = Some(CheckedRepoAgreements::capture(world, work).map(|_| ()))
        ),
        0
    );
    result.unwrap()
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

// Independent geometry/costs; never call production work, equality, scan or validator helpers.
trait Geometry: mv::Key {
    fn units(&self) -> u64;
}
impl Geometry for RepoAgreementId {
    fn units(&self) -> u64 {
        self.name().as_ref().len() as u64
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
    (
        work,
        candidates
            .into_iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, value)| value),
    )
}
fn member_cost(members: &BTreeSet<RepoAgreementId>, key: &RepoAgreementId) -> u64 {
    members
        .iter()
        .map(|candidate| 1 + key.units() + candidate.units())
        .sum()
}
fn group_cost<G: Geometry>(
    rows: &impl RawStorageImages<RepoAgreementId, RepoAgreement>,
    groups: &impl RawStorageImages<G, BTreeSet<RepoAgreementId>>,
    projection: impl for<'a> Fn(&'a RepoAgreement) -> Option<&'a G>,
    option: u64,
) -> u64 {
    let mut total = 0;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, record) in logical(rows, image) {
            total += option;
            if let Some(group) = projection(record) {
                let (cost, members) = lookup_cost(groups, image, group);
                total += cost + members.map_or(0, |members| member_cost(members, id));
            }
        }
        total += visit_cost(groups, image);
        for (group, members) in logical(groups, image) {
            total += 1;
            for id in members {
                let (cost, record) = lookup_cost(rows, image, id);
                total += 1 + cost;
                if let Some(record) = record {
                    total += option;
                    if let Some(projected) = projection(record) {
                        total += projected.units() + group.units();
                    }
                }
            }
        }
    }
    total
}
pub(in crate::state) fn full_work(
    rows: &impl RawStorageImages<RepoAgreementId, RepoAgreement>,
    initiators: &impl RawStorageImages<AccountId, BTreeSet<RepoAgreementId>>,
    counterparties: &impl RawStorageImages<AccountId, BTreeSet<RepoAgreementId>>,
    custodians: &impl RawStorageImages<AccountId, BTreeSet<RepoAgreementId>>,
) -> u64 {
    group_cost(rows, initiators, |r| Some(r.initiator()), 0)
        + group_cost(rows, counterparties, |r| Some(r.counterparty()), 0)
        + group_cost(rows, custodians, |r| r.custodian().as_ref(), 1)
}
pub(in crate::state) fn world_work(world: &World) -> u64 {
    full_work(
        &world
            .repo_agreements
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .repo_agreements_by_initiator
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .repo_agreements_by_counterparty
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .repo_agreements_by_custodian
            .try_committed_view_nonblocking()
            .unwrap(),
    )
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
