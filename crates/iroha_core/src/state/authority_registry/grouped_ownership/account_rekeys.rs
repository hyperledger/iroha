//! Exact account-history occurrence checks over both sealed original native images.
//! Alias reassignment retains audit occurrences but breaks controller continuity.
//! Source work supplies neither physical allocation custody nor finalized authority.
use super::*;
use crate::state::{
    account_label_is_pii,
    authority_registry::{
        borrowed_controller_work::prepay_account_id, original_images::RawStorageImages,
    },
};
use iroha_data_model::account::{AccountAlias, AccountRekeyRecord, AccountValue};
const TABLE: &str = "world.account_rekey_records";
const INDEX: &str = "world.account_rekey_records_by_account";
/// Local reference: two Single accounts, label255/domain255 and one reassignment, no undo.
/// This is neither a worst-case bound, physical allowance nor a validity rule.
pub(in crate::state) const ACCOUNT_REKEY_WORK_PER_ROW: u64 = 19_078;
/// Canonical histories with their original four reference/occurrence owners.
pub(in super::super) struct CheckedAccountRekeys<'world> {
    world: &'world World,
    rows: CommittedStorageView<'world, AccountAlias, AccountRekeyRecord>,
    accounts: CommittedStorageView<'world, AccountId, AccountValue>,
    aliases: CommittedStorageView<'world, AccountAlias, AccountId>,
    occurrences: CommittedStorageView<'world, AccountId, BTreeSet<AccountAlias>>,
}
impl<'world> CheckedAccountRekeys<'world> {
    /// Check both original images without allocating, repairing or refreshing storage.
    pub(in super::super) fn capture(
        world: &'world World,
        max_work: u64,
    ) -> Result<Self, GroupedOwnershipError> {
        let checked = Self {
            world,
            rows: world
                .account_rekey_records
                .try_committed_view_nonblocking()?,
            accounts: world.accounts.try_committed_view_nonblocking()?,
            aliases: world.account_aliases.try_committed_view_nonblocking()?,
            occurrences: world
                .account_rekey_records_by_account
                .try_committed_view_nonblocking()?,
        };
        let result = validate_original_account_rekeys(
            &checked.rows,
            &checked.accounts,
            &checked.aliases,
            &checked.occurrences,
            max_work,
        );
        checked.finish_validation(result)
    }
    fn finish_validation(
        self,
        result: Result<(), GroupedOwnershipError>,
    ) -> Result<Self, GroupedOwnershipError> {
        if !self.matches_current()? {
            return Err(PublicationPreparationError::Changed.into());
        }
        result?;
        Ok(self)
    }
    /// Borrow the original rows whose complete relation was checked.
    pub(in super::super) fn rows(
        &self,
    ) -> &CommittedStorageView<'world, AccountAlias, AccountRekeyRecord> {
        &self.rows
    }
    /// Materialize every original native probe before propagating a refusal.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows = self
            .rows
            .try_matches_current(&self.world.account_rekey_records);
        let accounts = self.accounts.try_matches_current(&self.world.accounts);
        let aliases = self
            .aliases
            .try_matches_current(&self.world.account_aliases);
        let occurrences = self
            .occurrences
            .try_matches_current(&self.world.account_rekey_records_by_account);
        let rows = rows?;
        let accounts = accounts?;
        let aliases = aliases?;
        let occurrences = occurrences?;
        Ok(rows && accounts && aliases && occurrences)
    }
}
struct RekeyWork(u64);
impl RekeyWork {
    fn prepay(&mut self, amount: usize) -> Result<(), GroupedOwnershipError> {
        let amount = u64::try_from(amount).map_err(|_| GroupedOwnershipError::WorkLimit)?;
        self.0 = self
            .0
            .checked_sub(amount)
            .ok_or(GroupedOwnershipError::WorkLimit)?;
        Ok(())
    }
}
trait RekeyKey: mv::Key {
    fn prepay(&self, work: &mut RekeyWork) -> Result<(), GroupedOwnershipError>;
}
impl RekeyKey for AccountId {
    fn prepay(&self, work: &mut RekeyWork) -> Result<(), GroupedOwnershipError> {
        prepay_account_id(self, |amount| work.prepay(amount))
    }
}
impl RekeyKey for AccountAlias {
    fn prepay(&self, work: &mut RekeyWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(self.label.as_ref().len())?;
        work.prepay(1)?;
        if let Some(domain) = &self.domain {
            work.prepay(domain.name().as_ref().len())?;
        }
        work.prepay(8)
    }
}
fn equal<K: RekeyKey>(
    left: &K,
    right: &K,
    work: &mut RekeyWork,
) -> Result<bool, GroupedOwnershipError> {
    left.prepay(work)?;
    right.prepay(work)?;
    Ok(left == right)
}
fn next_physical<I: ExactSizeIterator>(
    rows: &mut I,
    work: &mut RekeyWork,
) -> Result<Option<I::Item>, GroupedOwnershipError> {
    if rows.len() == 0 {
        return Ok(None);
    }
    work.prepay(1)?;
    Ok(rows.next())
}
fn visit_original<'a, K: RekeyKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    work: &mut RekeyWork,
    mut inspect: impl FnMut(&'a K, &'a V, &mut RekeyWork) -> Result<(), GroupedOwnershipError>,
) -> Result<(), GroupedOwnershipError> {
    let mut current = rows.current_entries();
    while let Some((key, value)) = next_physical(&mut current, work)? {
        let mut masked = false;
        if image == GroupImage::Predecessor {
            let mut undo = rows.undo_entries();
            while let Some((prior, _)) = next_physical(&mut undo, work)? {
                masked |= equal(key, prior, work)?;
            }
        }
        if !masked {
            inspect(key, value, work)?;
        }
    }
    if image == GroupImage::Predecessor {
        let mut undo = rows.undo_entries();
        while let Some((key, prior)) = next_physical(&mut undo, work)? {
            work.prepay(1)?;
            if let Some(value) = prior {
                inspect(key, value, work)?;
            }
        }
    }
    Ok(())
}
fn lookup<'a, K: RekeyKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    key: &K,
    work: &mut RekeyWork,
) -> Result<Option<&'a V>, GroupedOwnershipError> {
    let mut found = None;
    visit_original(rows, image, work, |candidate, value, work| {
        if equal(key, candidate, work)? {
            found = Some(value);
        }
        Ok(())
    })?;
    Ok(found)
}
fn contains_alias(
    members: &BTreeSet<AccountAlias>,
    key: &AccountAlias,
    work: &mut RekeyWork,
) -> Result<bool, GroupedOwnershipError> {
    let mut members = members.iter();
    let mut found = false;
    while let Some(candidate) = next_physical(&mut members, work)? {
        found |= equal(key, candidate, work)?;
    }
    Ok(found)
}
fn funded_predecessors<'a>(
    record: &'a AccountRekeyRecord,
    image: GroupImage,
    work: &mut RekeyWork,
) -> Result<&'a [AccountId], GroupedOwnershipError> {
    work.prepay(16)?; // both logical u64 length metadata values
    let count = record
        .transition_provenance
        .len()
        .checked_mul(5)
        .ok_or(GroupedOwnershipError::WorkLimit)?;
    work.prepay(count)?; // every maximum reverse advance and complete V1 u32 tag
    record.active_account_id_rekey_predecessors().map_err(|_| {
        source(
            image,
            "transition provenance length differs from account history",
        )
    })
}
#[expect(
    single_use_lifetimes,
    reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
)]
fn contains_account<'a>(
    mut accounts: impl ExactSizeIterator<Item = &'a AccountId>,
    account: &AccountId,
    work: &mut RekeyWork,
) -> Result<bool, GroupedOwnershipError> {
    let mut found = false;
    while let Some(candidate) = next_physical(&mut accounts, work)? {
        found |= equal(candidate, account, work)?;
    }
    Ok(found)
}
/// Sole both-image relation over four sealed original sources, committed or frozen.
/// Preserve Current's records/aliases/occurrences/ambiguity phases before Predecessor.
pub(in crate::state) fn validate_original_account_rekeys(
    rows: &impl RawStorageImages<AccountAlias, AccountRekeyRecord>,
    accounts: &impl RawStorageImages<AccountId, AccountValue>,
    aliases: &impl RawStorageImages<AccountAlias, AccountId>,
    occurrences: &impl RawStorageImages<AccountId, BTreeSet<AccountAlias>>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    let work = &mut RekeyWork(max_work);
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        visit_original(rows, image, work, |label, record, work| {
            if !equal(label, &record.label, work)? {
                return Err(source(image, "record label differs from its storage key"));
            }
            work.prepay(label.label.as_ref().len())?;
            if account_label_is_pii(label) {
                return Err(source(image, "record label looks like raw PII"));
            }
            if lookup(accounts, image, &record.active_account_id, work)?.is_none() {
                return Err(source(image, "active account is absent"));
            }
            let predecessors = funded_predecessors(record, image, work)?;
            let mut predecessors_iter = predecessors.iter();
            let mut position = 0;
            while let Some(predecessor) = next_physical(&mut predecessors_iter, work)? {
                if lookup(accounts, image, predecessor, work)?.is_some() {
                    return Err(source(image, "active rekey predecessor remains live"));
                }
                let mut previous = predecessors[..position].iter();
                while let Some(previous) = next_physical(&mut previous, work)? {
                    if equal(previous, predecessor, work)? {
                        return Err(source(image, "active rekey predecessor is repeated"));
                    }
                }
                position += 1;
            }
            // The active id is a separately prepaid logical row; the history uses its finite slice.
            work.prepay(1)?;
            let present = if let Some(members) =
                lookup(occurrences, image, &record.active_account_id, work)?
            {
                contains_alias(members, label, work)?
            } else {
                false
            };
            if !present {
                return Err(corrupt(image, GroupMismatch::MissingMember));
            }
            let mut history = record.previous_account_ids.iter();
            while let Some(account) = next_physical(&mut history, work)? {
                let present = if let Some(members) = lookup(occurrences, image, account, work)? {
                    contains_alias(members, label, work)?
                } else {
                    false
                };
                if !present {
                    return Err(corrupt(image, GroupMismatch::MissingMember));
                }
            }
            Ok(())
        })?;
        visit_original(aliases, image, work, |label, account, work| {
            if lookup(accounts, image, account, work)?.is_none() {
                return Err(source(image, "alias target account is absent"));
            }
            let record = lookup(rows, image, label, work)?
                .ok_or_else(|| source(image, "alias has no continuity record"))?;
            if !equal(&record.active_account_id, account, work)? {
                return Err(source(
                    image,
                    "alias target differs from the active account",
                ));
            }
            Ok(())
        })?;
        visit_original(occurrences, image, work, |account, aliases, work| {
            work.prepay(1)?;
            if aliases.is_empty() {
                return Err(corrupt(image, GroupMismatch::EmptyGroup));
            }
            let mut aliases = aliases.iter();
            while let Some(label) = next_physical(&mut aliases, work)? {
                let record = lookup(rows, image, label, work)?
                    .ok_or_else(|| corrupt(image, GroupMismatch::ForeignMember))?;
                work.prepay(1)?;
                let active = equal(&record.active_account_id, account, work)?;
                let historical =
                    contains_account(record.previous_account_ids.iter(), account, work)?;
                if !(active | historical) {
                    return Err(corrupt(image, GroupMismatch::ForeignMember));
                }
            }
            Ok(())
        })?;
        visit_original(occurrences, image, work, |account, aliases, work| {
            let mut target = None;
            let mut aliases = aliases.iter();
            while let Some(label) = next_physical(&mut aliases, work)? {
                let record = lookup(rows, image, label, work)?
                    .ok_or_else(|| corrupt(image, GroupMismatch::ForeignMember))?;
                let predecessors = funded_predecessors(record, image, work)?;
                if contains_account(predecessors.iter(), account, work)? {
                    work.prepay(1)?;
                    if let Some(previous) = target {
                        if !equal(previous, &record.active_account_id, work)? {
                            return Err(source(
                                image,
                                "active rekey predecessor has ambiguous targets",
                            ));
                        }
                    }
                    target = Some(&record.active_account_id);
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn source(image: GroupImage, reason: &'static str) -> GroupedOwnershipError {
    GroupedOwnershipError::Source {
        table: TABLE,
        image,
        reason,
    }
}
fn corrupt(image: GroupImage, mismatch: GroupMismatch) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index: INDEX,
        image,
        mismatch,
    }
}
#[cfg(test)]
pub(in crate::state) mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod work_tests;
