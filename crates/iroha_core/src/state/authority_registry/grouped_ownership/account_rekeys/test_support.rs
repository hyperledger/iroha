//! Original rekey fixtures and independent complete physical-cut scheduling arithmetic.
//! This allocating test model runs before allocation observers, never in production.
use super::*;
use iroha_data_model::{
    IntoKeyValue,
    account::{Account, AccountController, AccountRekeyTransitionProvenance as Provenance},
    prelude::Registrable,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
pub(in crate::state) fn alias(name: &str) -> AccountAlias {
    AccountAlias::domainless(name.parse().unwrap(), DataSpaceId::UNIVERSAL)
}
pub(in crate::state) fn record() -> AccountRekeyRecord {
    AccountRekeyRecord::new(alias("wallet"), ALICE_ID.clone())
        .reassign_alias_to_account(BOB_ID.clone())
        .unwrap()
}
pub(in crate::state) fn record_with_label(name: &str) -> AccountRekeyRecord {
    let mut row = record();
    row.label = alias(name);
    row
}
pub(in crate::state) fn fixture() -> World {
    let mut world = World::default();
    for owner in [&*ALICE_ID, &*BOB_ID] {
        let (id, account) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, account);
    }
    world
        .account_rekey_records
        .insert(alias("wallet"), record());
    world
        .account_aliases
        .insert(alias("wallet"), BOB_ID.clone());
    world.rebuild_account_rekey_records().unwrap();
    world
}
pub(in crate::state) trait Geometry: mv::Key {
    fn units(&self) -> u64;
}
impl Geometry for AccountAlias {
    fn units(&self) -> u64 {
        self.label.as_ref().len() as u64
            + 1
            + self
                .domain
                .as_ref()
                .map_or(0, |d| d.name().as_ref().len() as u64)
            + 8
    }
}
impl Geometry for AccountId {
    fn units(&self) -> u64 {
        match self.controller() {
            AccountController::Single(k) => 2 + k.input_payload_len() as u64,
            AccountController::Multisig(p) => {
                12 + p.members().len() as u64
                    + p.members()
                        .iter()
                        .map(|m| 3 + m.public_key().input_payload_len() as u64)
                        .sum::<u64>()
            }
        }
    }
}
pub(in crate::state) fn logical<'a, K: mv::Key, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
) -> Vec<(&'a K, &'a V)> {
    if image == GroupImage::Current {
        rows.current_entries().collect()
    } else {
        rows.current_entries()
            .filter(|(key, _)| !rows.undo_entries().any(|(prior, _)| *key == prior))
            .chain(
                rows.undo_entries()
                    .filter_map(|(key, prior)| prior.as_ref().map(|value| (key, value))),
            )
            .collect()
    }
}
pub(in crate::state) fn visit_cost<K: Geometry, V: mv::Value>(
    rows: &impl RawStorageImages<K, V>,
    image: GroupImage,
) -> u64 {
    let c = rows.current_entries().len() as u64;
    if image == GroupImage::Current {
        return c;
    }
    c + rows
        .current_entries()
        .map(|(key, _)| {
            rows.undo_entries()
                .map(|(prior, _)| 1 + key.units() + prior.units())
                .sum::<u64>()
        })
        .sum::<u64>()
        + 2 * rows.undo_entries().len() as u64
}
pub(in crate::state) fn lookup_cost<'a, K: Geometry, V: mv::Value>(
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
    (
        cost,
        candidates
            .into_iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, value)| value),
    )
}
fn member_cost(members: &BTreeSet<AccountAlias>, key: &AccountAlias) -> u64 {
    members
        .iter()
        .map(|candidate| 1 + key.units() + candidate.units())
        .sum()
}
fn history_cost(history: &[AccountId], account: &AccountId) -> u64 {
    history
        .iter()
        .map(|candidate| 1 + candidate.units() + account.units())
        .sum()
}
// Independently express the test suffix: no production funding/equality/validator helper.
fn predecessors(record: &AccountRekeyRecord) -> &[AccountId] {
    if record.previous_account_ids.len() != record.transition_provenance.len() {
        return &[];
    }
    let start = record
        .transition_provenance
        .iter()
        .rposition(|p| *p != Provenance::AccountIdRekey)
        .map_or(0, |i| i + 1);
    &record.previous_account_ids[start..]
}
/// Independent costs of records, bindings, inverse occurrences and ambiguity at one image.
pub(in crate::state) fn phase_work(
    rows: &impl RawStorageImages<AccountAlias, AccountRekeyRecord>,
    accounts: &impl RawStorageImages<AccountId, AccountValue>,
    aliases: &impl RawStorageImages<AccountAlias, AccountId>,
    occurrences: &impl RawStorageImages<AccountId, BTreeSet<AccountAlias>>,
    image: GroupImage,
) -> [u64; 4] {
    let mut cost = [
        visit_cost(rows, image),
        visit_cost(aliases, image),
        visit_cost(occurrences, image),
        visit_cost(occurrences, image),
    ];
    for (label, record) in logical(rows, image) {
        cost[0] += label.units()
            + record.label.units()
            + label.label.as_ref().len() as u64
            + lookup_cost(accounts, image, &record.active_account_id).0
            + 16
            + 5 * record.transition_provenance.len() as u64;
        let ps = predecessors(record);
        for (position, p) in ps.iter().enumerate() {
            cost[0] += 1 + lookup_cost(accounts, image, p).0;
            cost[0] += ps[..position]
                .iter()
                .map(|previous| 1 + previous.units() + p.units())
                .sum::<u64>();
        }
        for account in
            core::iter::once(&record.active_account_id).chain(record.previous_account_ids.iter())
        {
            let (lookup, members) = lookup_cost(occurrences, image, account);
            cost[0] += 1 + lookup + members.map_or(0, |members| member_cost(members, label));
        }
    }
    for (label, account) in logical(aliases, image) {
        cost[1] += lookup_cost(accounts, image, account).0;
        let (lookup, record) = lookup_cost(rows, image, label);
        cost[1] += lookup;
        if let Some(record) = record {
            cost[1] += record.active_account_id.units() + account.units();
        }
    }
    for (account, members) in logical(occurrences, image) {
        cost[2] += 1;
        let mut target: Option<&AccountId> = None;
        for label in members {
            let (lookup, record) = lookup_cost(rows, image, label);
            cost[2] += 1 + lookup;
            cost[3] += 1 + lookup;
            if let Some(record) = record {
                cost[2] += 1
                    + record.active_account_id.units()
                    + account.units()
                    + history_cost(&record.previous_account_ids, account);
                let ps = predecessors(record);
                cost[3] +=
                    16 + 5 * record.transition_provenance.len() as u64 + history_cost(ps, account);
                if ps.iter().any(|candidate| candidate == account) {
                    cost[3] += 1;
                    if let Some(previous) = target {
                        cost[3] += previous.units() + record.active_account_id.units();
                    }
                    target = Some(&record.active_account_id);
                }
            }
        }
    }
    cost
}
pub(in crate::state) fn full_work(
    rows: &impl RawStorageImages<AccountAlias, AccountRekeyRecord>,
    accounts: &impl RawStorageImages<AccountId, AccountValue>,
    aliases: &impl RawStorageImages<AccountAlias, AccountId>,
    occurrences: &impl RawStorageImages<AccountId, BTreeSet<AccountAlias>>,
) -> u64 {
    [GroupImage::Current, GroupImage::Predecessor]
        .into_iter()
        .map(|image| {
            phase_work(rows, accounts, aliases, occurrences, image)
                .into_iter()
                .sum::<u64>()
        })
        .sum()
}
pub(in crate::state) fn world_work(world: &World) -> u64 {
    full_work(
        &world
            .account_rekey_records
            .try_committed_view_nonblocking()
            .unwrap(),
        &world.accounts.try_committed_view_nonblocking().unwrap(),
        &world
            .account_aliases
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .account_rekey_records_by_account
            .try_committed_view_nonblocking()
            .unwrap(),
    )
}
