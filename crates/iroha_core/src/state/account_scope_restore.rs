//! Derive account visibility and its inverse from matching authoritative MV cuts.

use super::*;

type Directory = BTreeMap<AccountId, AccountScopeDirectoryEntry>;
type ScopeKey = (DataSpaceId, AccountAliasDomain);
type AccountsIndex = BTreeMap<(ScopeKey, AccountId), ()>;
type AccountCounts = BTreeMap<ScopeKey, u64>;
type RestoredIndex = (Storage<(ScopeKey, AccountId), ()>, Storage<ScopeKey, u64>);

/// Shared pure semantics for live refresh and both restored source images.
pub(super) fn entry<'a>(
    account_id: &AccountId,
    account: &'a AccountValue,
    bindings: Option<&UaidDataspaceBindings>,
    aliases: impl Iterator<Item = &'a AccountAlias>,
) -> AccountScopeDirectoryEntry {
    let mut entry = AccountScopeDirectoryEntry::default();
    let primary_dataspace = account.as_ref().label().map(|label| {
        entry.ensure_dataspace(label.dataspace);
        if let Some(domain) = &label.domain {
            entry.bind_domain(label.dataspace, domain.clone());
        }
        label.dataspace
    });
    if let Some(bindings) = bindings {
        for (dataspace, accounts) in bindings.iter() {
            if accounts.contains(account_id) {
                entry.ensure_dataspace(*dataspace);
            }
        }
    }
    for alias in aliases {
        entry.ensure_dataspace(alias.dataspace);
        if let Some(domain) = &alias.domain {
            entry.bind_domain(alias.dataspace, domain.clone());
        }
    }
    if primary_dataspace.is_none_or(|dataspace| dataspace == DataSpaceId::UNIVERSAL) {
        entry.ensure_dataspace(DataSpaceId::UNIVERSAL);
    }
    entry
}

fn directory<'a>(
    accounts: impl Iterator<Item = (&'a AccountId, &'a AccountValue)>,
    aliases: impl Iterator<Item = (&'a AccountAlias, &'a AccountId)>,
    bindings: impl Iterator<Item = (&'a UniversalAccountId, &'a UaidDataspaceBindings)>,
) -> Result<Directory, String> {
    // Borrow source records. Only the derived result owns cloned account keys.
    let accounts: BTreeMap<_, _> = accounts.collect();
    let aliases: BTreeMap<_, _> = aliases.collect();
    let bindings: BTreeMap<_, _> = bindings.collect();
    let mut by_account = BTreeMap::<&AccountId, Vec<&AccountAlias>>::new();
    for (&alias, &owner) in &aliases {
        if account_label_is_pii(alias) {
            return Err(format!(
                "Account alias {alias:?} looks like raw PII; use UAID/opaque identifiers"
            ));
        }
        if !accounts.contains_key(owner) {
            return Err(format!(
                "Account alias {alias:?} references missing account {owner}"
            ));
        }
        by_account.entry(owner).or_default().push(alias);
    }
    let mut result = BTreeMap::new();
    for (account_id, account) in accounts {
        if let Some(primary) = account.as_ref().label()
            && aliases.get(primary).copied() != Some(account_id)
        {
            return Err(format!(
                "Account primary label {primary:?} is not bound to account {account_id}"
            ));
        }
        let account_bindings = account
            .as_ref()
            .uaid()
            .and_then(|uaid| bindings.get(uaid).copied());
        result.insert(
            account_id.clone(),
            entry(
                account_id,
                account,
                account_bindings,
                by_account
                    .get(account_id)
                    .into_iter()
                    .flat_map(|aliases| aliases.iter().copied()),
            ),
        );
    }
    Ok(result)
}

fn accounts_index<'a>(
    directory: impl Iterator<Item = (&'a AccountId, &'a AccountScopeDirectoryEntry)>,
) -> AccountsIndex {
    let mut index = AccountsIndex::new();
    for (account_id, entry) in directory {
        for key in account_scope_index_keys(entry) {
            index.insert((key, account_id.clone()), ());
        }
    }
    index
}

fn index_with_history(
    current: &Directory,
    previous: &Directory,
    touched: &BTreeSet<AccountId>,
) -> RestoredIndex {
    let index = accounts_index(current.iter());
    let prior_index = accounts_index(previous.iter());
    let mut touched_keys = BTreeSet::new();
    for account in touched {
        for entry in [current.get(account), previous.get(account)]
            .into_iter()
            .flatten()
        {
            touched_keys.extend(
                account_scope_index_keys(entry)
                    .into_iter()
                    .map(|key| (key, account.clone())),
            );
        }
    }
    for key in index.keys().chain(prior_index.keys()) {
        if index.get(key) != prior_index.get(key) {
            touched_keys.insert(key.clone());
        }
    }
    let counts = |index: &AccountsIndex| {
        let mut counts = AccountCounts::new();
        for (scope, _) in index.keys() {
            *counts.entry(scope.clone()).or_default() += 1;
        }
        counts
    };
    let current_counts = counts(&index);
    let previous_counts = counts(&prior_index);
    let count_undo = touched_keys
        .iter()
        .map(|(scope, _)| (scope.clone(), previous_counts.get(scope).copied()))
        .collect();
    let undo = touched_keys
        .into_iter()
        .map(|key| {
            let previous = prior_index.get(&key).copied();
            (key, previous)
        })
        .collect();
    (
        Storage::from_snapshot_parts(index, undo),
        Storage::from_snapshot_parts(current_counts, count_undo),
    )
}

/// Validate both authoritative cuts before replacing either derived owner.
pub(super) fn rebuild(world: &mut World) -> Result<(), String> {
    let (current, previous, mut touched) = {
        let accounts = world.0.accounts.history();
        let aliases = world.0.account_aliases.history();
        let bindings = world.0.uaid_dataspaces.history();
        let current = directory(
            accounts.current().iter(),
            aliases.current().iter(),
            bindings.current().iter(),
        )?;
        let previous = directory(
            accounts.iter_before_block(),
            aliases.iter_before_block(),
            bindings.iter_before_block(),
        )
        .map_err(|error| format!("invalid predecessor account scope: {error}"))?;
        let mut touched: BTreeSet<_> = accounts.revert_map().keys().cloned().collect();
        for (alias, prior) in aliases.revert_map().iter() {
            touched.extend(prior.iter().cloned());
            touched.extend(aliases.current().get(alias).cloned());
        }
        for (uaid, prior) in bindings.revert_map().iter() {
            for value in [prior.as_ref(), bindings.current().get(uaid)]
                .into_iter()
                .flatten()
            {
                for (_, members) in value.iter() {
                    touched.extend(members.iter().cloned());
                }
            }
        }
        (current, previous, touched)
    };
    for account in current.keys().chain(previous.keys()) {
        if current.get(account) != previous.get(account) {
            touched.insert(account.clone());
        }
    }
    let (index, counts) = index_with_history(&current, &previous, &touched);
    let undo = touched
        .into_iter()
        .map(|account| {
            let prior = previous.get(&account).cloned();
            (account, prior)
        })
        .collect();
    let directory = Storage::from_snapshot_parts(current, undo);
    world.account_scope_directory = directory;
    world.account_scope_accounts = index;
    world.account_scope_account_counts = counts;
    Ok(())
}

/// Catalog pruning already publishes directory MV history; preserve it in the inverse.
pub(super) fn rebuild_accounts_index(world: &mut World) {
    let (index, counts) = {
        let history = world.account_scope_directory.history();
        let current = history
            .current()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let previous = history
            .iter_before_block()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let touched = history.revert_map().keys().cloned().collect();
        index_with_history(&current, &previous, &touched)
    };
    world.account_scope_accounts = index;
    world.account_scope_account_counts = counts;
}

#[cfg(test)]
#[path = "account_scope_restore_tests.rs"]
mod tests;
