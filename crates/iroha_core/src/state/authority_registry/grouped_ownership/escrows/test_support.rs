//! Original escrow fixtures and independent complete-cut work arithmetic.
use super::*;
use crate::test_allocations::allocations_during;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::{Account, AccountController},
    asset::AssetDefinitionId,
    escrow::AssetEscrowKind,
    prelude::Registrable,
};
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::{Storage, StorageReadOnly};

/// Ample local comparison work for the finite original semantic fixtures, not a pool limit.
pub(in crate::state) const TEST_WORK_ALLOWANCE: u64 = 1_048_576;

pub(in crate::state) fn id() -> EscrowId {
    EscrowId::new(Hash::new(b"exact escrow groups"))
}

pub(in crate::state) fn fixture(buyer: bool) -> World {
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let record = AssetEscrowRecord {
        id: id(),
        seller: ALICE_ID.clone(),
        buyer: buyer.then(|| BOB_ID.clone()),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrowgroups", "universal").unwrap(),
            "token".parse().unwrap(),
        ),
        amount: Quantity::one(),
        custody: ALICE_ID.clone(),
        status: AssetEscrowStatus::Open,
        kind: AssetEscrowKind::Marketplace,
        remaining_amount: Quantity::one(),
        release_authority: None,
        expires_at_ms: None,
        evidence_hashes: Vec::new(),
        conditions: Vec::new(),
        created_at_ms: 1,
        accepted_at_ms: None,
        payment_sent_at_ms: None,
        disputed_at_ms: None,
        closed_at_ms: None,
        resolution: None,
    };
    world.asset_escrows.insert(id(), record);
    world.rebuild_escrow_indexes();
    world
}

pub(in crate::state) fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(CheckedEscrows::capture(world, work).map(|_| ()))),
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
impl Geometry for EscrowId {
    fn units(&self) -> u64 {
        32
    }
}
impl Geometry for AssetEscrowStatus {
    fn units(&self) -> u64 {
        1
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
fn member_cost(members: &BTreeSet<EscrowId>, key: &EscrowId) -> u64 {
    members
        .iter()
        .map(|candidate| 1 + key.units() + candidate.units())
        .sum()
}
fn group_cost<G: Geometry>(
    rows: &impl RawStorageImages<EscrowId, AssetEscrowRecord>,
    groups: &impl RawStorageImages<G, BTreeSet<EscrowId>>,
    projection: impl for<'a> Fn(&'a AssetEscrowRecord) -> Option<&'a G>,
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
    rows: &impl RawStorageImages<EscrowId, AssetEscrowRecord>,
    sellers: &impl RawStorageImages<AccountId, BTreeSet<EscrowId>>,
    buyers: &impl RawStorageImages<AccountId, BTreeSet<EscrowId>>,
    statuses: &impl RawStorageImages<AssetEscrowStatus, BTreeSet<EscrowId>>,
) -> u64 {
    group_cost(rows, sellers, |r| Some(&r.seller), 0)
        + group_cost(rows, buyers, |r| r.buyer.as_ref(), 1)
        + group_cost(rows, statuses, |r| Some(&r.status), 0)
}
pub(in crate::state) fn world_work(world: &World) -> u64 {
    full_work(
        &world
            .asset_escrows
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .asset_escrows_by_seller
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .asset_escrows_by_buyer
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .asset_escrows_by_status
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
