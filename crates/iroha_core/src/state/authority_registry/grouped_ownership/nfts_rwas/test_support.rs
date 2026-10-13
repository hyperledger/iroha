//! Original NFT/RWA fixtures and independent complete-cut work geometry.
/// The original allocation observer owner retained in the six original tests.
pub(in crate::state) use super::super::tests::without_allocations;
use super::*;
use iroha_crypto::Hash;
use iroha_data_model::{
    IntoKeyValue,
    account::AccountController,
    nft::Nft,
    prelude::Registrable,
    rwa::{Rwa, RwaControlPolicy},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::NumericSpec;
use iroha_test_samples::ALICE_ID;

/// Canonical original domain fixture.
pub(in crate::state) fn domain() -> DomainId {
    DomainId::try_new("grouped", "universal").unwrap()
}

/// Canonical original nft_id fixture.
pub(in crate::state) fn nft_id() -> NftId {
    NftId::new(domain(), "lot".parse().unwrap())
}

/// Canonical original rwa_id fixture.
pub(in crate::state) fn rwa_id() -> RwaId {
    RwaId::generated(domain(), Hash::new(b"grouped source"))
}

/// Canonical original combined NFT/RWA singleton fixture.
pub(in crate::state) fn fixture() -> World {
    let mut world = World::default();
    let (id, value) = Nft::new(nft_id(), Metadata::default())
        .build(&ALICE_ID)
        .into_key_value();
    world.nfts.insert(id, value);
    let (id, value) = Rwa::new(
        rwa_id(),
        iroha_primitives::numeric::Quantity::from(5_u32),
        NumericSpec::integer(),
        "https://example.test/grouped".into(),
        None,
        Metadata::default(),
        Vec::new(),
        RwaControlPolicy {
            freeze_enabled: true,
            ..RwaControlPolicy::default()
        },
        ALICE_ID.clone(),
    )
    .into_key_value();
    world.rwas.insert(id, value);
    world.rebuild_nft_owner_index();
    world.rebuild_rwa_indexes();
    world
}

/// Check the selected complete original cut using independently computed work.
pub(in crate::state) fn check(world: &World, rwa: bool) -> Result<(), GroupedOwnershipError> {
    let max_work = world_work(world, rwa);
    without_allocations(|| {
        if rwa {
            CheckedRwas::capture(world, max_work).map(|_| ())
        } else {
            CheckedNfts::capture(world, max_work).map(|_| ())
        }
    })
}
// Independent test geometry: never call production prepay/equality/visit/validator helpers.
trait Geometry: mv::Key {
    fn units(&self) -> u64;
}
impl Geometry for DomainId {
    fn units(&self) -> u64 {
        self.name().as_ref().len() as u64 + self.dataspace().as_ref().len() as u64
    }
}
impl Geometry for NftId {
    fn units(&self) -> u64 {
        self.domain().units() + self.name().as_ref().len() as u64
    }
}
impl Geometry for RwaId {
    fn units(&self) -> u64 {
        self.domain().units() + 32
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
impl Geometry for Option<Name> {
    fn units(&self) -> u64 {
        1 + self.as_ref().map_or(0, |name| name.as_ref().len() as u64)
    }
}
impl Geometry for bool {
    fn units(&self) -> u64 {
        1
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
fn group_cost<K: Geometry, V: mv::Value, G: Geometry>(
    rows: &impl RawStorageImages<K, V>,
    groups: &impl RawStorageImages<G, BTreeSet<K>>,
    project: impl for<'a> Fn(&'a K, &'a V) -> &'a G,
) -> u64 {
    let mut total = 0;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        total += visit_cost(rows, image);
        for (id, value) in logical(rows, image) {
            let (work, members) = lookup_cost(groups, image, project(id, value));
            total += work
                + members.map_or(0, |members| {
                    members
                        .iter()
                        .map(|candidate| 1 + id.units() + candidate.units())
                        .sum::<u64>()
                });
        }
        total += visit_cost(groups, image);
        for (group, members) in logical(groups, image) {
            total += 1;
            for id in members {
                let (work, value) = lookup_cost(rows, image, id);
                total += 1 + work;
                if let Some(value) = value {
                    total += project(id, value).units() + group.units();
                }
            }
        }
    }
    total
}
/// Independent complete-cut NFT work, using original typed geometry and full tails.
pub(in crate::state) fn full_nft_work(
    rows: &impl RawStorageImages<NftId, NftValue>,
    owners: &impl RawStorageImages<AccountId, BTreeSet<NftId>>,
    domains: &impl RawStorageImages<DomainId, BTreeSet<NftId>>,
) -> u64 {
    group_cost(rows, owners, |_, value| &value.owned_by)
        + group_cost(rows, domains, |id, _| id.domain())
}
/// Independent complete-cut RWA work, including real None/Some status and bool keys.
pub(in crate::state) fn full_rwa_work(
    rows: &impl RawStorageImages<RwaId, RwaValue>,
    owners: &impl RawStorageImages<AccountId, BTreeSet<RwaId>>,
    statuses: &impl RawStorageImages<Option<Name>, BTreeSet<RwaId>>,
    frozen: &impl RawStorageImages<bool, BTreeSet<RwaId>>,
) -> u64 {
    group_cost(rows, owners, |_, value| &value.owned_by)
        + group_cost(rows, statuses, |_, value| &value.status)
        + group_cost(rows, frozen, |_, value| &value.is_frozen)
}
/// Independent test scheduling; allocate scratch before the original allocation observation.
pub(in crate::state) fn world_work(world: &World, rwa: bool) -> u64 {
    if rwa {
        full_rwa_work(
            &world.rwas.try_committed_view_nonblocking().unwrap(),
            &world
                .rwas_by_owner
                .try_committed_view_nonblocking()
                .unwrap(),
            &world
                .rwas_by_status
                .try_committed_view_nonblocking()
                .unwrap(),
            &world
                .rwas_by_frozen
                .try_committed_view_nonblocking()
                .unwrap(),
        )
    } else {
        full_nft_work(
            &world.nfts.try_committed_view_nonblocking().unwrap(),
            &world
                .nfts_by_owner
                .try_committed_view_nonblocking()
                .unwrap(),
            &world
                .nfts_by_domain
                .try_committed_view_nonblocking()
                .unwrap(),
        )
    }
}
