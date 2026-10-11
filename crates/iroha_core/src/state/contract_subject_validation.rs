//! Shared borrowed subject-ledger relation over original current and undo images.
//!
//! Live capture supplies finite local work. Startup retains its existing infallible
//! admission boundary; restore allocation/work custody is a separate open gate.

use crate::{
    smartcontracts::code::ContractSubjectBinding,
    state::authority_registry::borrowed_controller_work::prepay_account_id,
};
use iroha_crypto::{Algorithm, Hash};
use iroha_data_model::{
    account::{AccountId, AccountValue},
    smart_contract::{
        ContractAddress, ContractDeploymentOriginV1, ContractLifecycleControlV1,
        ContractLifecycleOwnerV1,
    },
};
use mv::storage::{
    CommittedStorageView, FrozenStorageImages, History, StorageMode, StorageReadOnly,
};

/// Which original logical image is being inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Image {
    Current,
    Predecessor,
}

/// Compact classification, separate from the uniformly inline borrowed diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ErrorKind {
    WorkLimit,
    Source,
    MissingIndex,
    ForeignIndex,
}

/// Fixed rejection custody with borrowed diagnostic subjects for the restore edge.
#[derive(Debug)]
pub(super) struct Error<'a> {
    pub(super) kind: ErrorKind,
    pub(super) image: Image,
    pub(super) table: &'static str,
    address: Option<&'a ContractAddress>,
    account: Option<&'a AccountId>,
    pub(super) reason: &'static str,
}
impl<'a> Error<'a> {
    fn work_limit() -> Self {
        Self {
            kind: ErrorKind::WorkLimit,
            image: Image::Current,
            table: "",
            address: None,
            account: None,
            reason: "",
        }
    }
    fn source(
        image: Image,
        table: &'static str,
        address: &'a ContractAddress,
        account: Option<&'a AccountId>,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: ErrorKind::Source,
            image,
            table,
            address: Some(address),
            account,
            reason,
        }
    }
    fn index(image: Image, missing: bool) -> Self {
        Self {
            kind: if missing {
                ErrorKind::MissingIndex
            } else {
                ErrorKind::ForeignIndex
            },
            image,
            ..Self::work_limit()
        }
    }
}

/// Local work only, never a gas charge or consensus validity limit.
pub(super) struct Work(Option<u64>);
impl Work {
    pub(super) fn bounded(limit: u64) -> Self {
        Self(Some(limit))
    }
    pub(super) fn startup() -> Self {
        Self(None)
    }
    pub(super) fn charge<'a>(&mut self, amount: usize) -> Result<(), Error<'a>> {
        if let Some(remaining) = &mut self.0 {
            let amount = u64::try_from(amount).map_err(|_| Error::work_limit())?;
            *remaining = remaining.checked_sub(amount).ok_or(Error::work_limit())?;
        }
        Ok(())
    }
}

mod sealed {
    pub trait Native {}
    impl<K: mv::Key, V: mv::Value, M: super::StorageMode<K, V>> Native
        for super::CommittedStorageView<'_, K, V, M>
    {
    }
    impl<K: mv::Key, V: mv::Value, M: super::StorageMode<K, V>> Native
        for super::FrozenStorageImages<'_, K, V, M>
    {
    }
    impl<K: mv::Key, V: mv::Value, M: super::StorageMode<K, V>> Native for super::History<'_, K, V, M> {}
}

/// Only original committed/frozen maps or the existing exclusive startup history.
///
/// This closed surface never reacquires, copies or reconstructs a source. Its
/// exact-size native iterators permit admission before every actual advance.
/// Each owning consumer still owes its State provenance, mode and final fence.
pub(super) trait Images<K: mv::Key, V: mv::Value>: sealed::Native {
    fn current_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator;
    fn undo_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &Option<V>)> + ExactSizeIterator;
}
impl<K: mv::Key, V: mv::Value, M: StorageMode<K, V>> Images<K, V>
    for CommittedStorageView<'_, K, V, M>
{
    fn current_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator {
        self.current().iter()
    }
    fn undo_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &Option<V>)> + ExactSizeIterator {
        self.undo().iter()
    }
}
impl<K: mv::Key, V: mv::Value, M: StorageMode<K, V>> Images<K, V>
    for FrozenStorageImages<'_, K, V, M>
{
    fn current_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator {
        self.current_entries()
    }
    fn undo_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &Option<V>)> + ExactSizeIterator {
        self.undo_entries()
    }
}
impl<K: mv::Key, V: mv::Value, M: StorageMode<K, V>> Images<K, V> for History<'_, K, V, M> {
    fn current_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator {
        self.current().iter()
    }
    fn undo_rows(&self) -> impl DoubleEndedIterator<Item = (&K, &Option<V>)> + ExactSizeIterator {
        self.revert_map().iter()
    }
}

/// Pay complete equality geometry before any potentially nested key comparison.
pub(super) trait WorkKey: mv::Key {
    fn prepay<'a>(&self, work: &mut Work) -> Result<(), Error<'a>>;
}
impl WorkKey for ContractAddress {
    fn prepay<'a>(&self, work: &mut Work) -> Result<(), Error<'a>> {
        work.charge(self.as_str().len())
    }
}
impl WorkKey for AccountId {
    fn prepay<'a>(&self, work: &mut Work) -> Result<(), Error<'a>> {
        prepay_account_id(self, |amount| work.charge(amount))
    }
}

pub(super) fn equal<'a, K: WorkKey>(
    left: &K,
    right: &K,
    work: &mut Work,
) -> Result<bool, Error<'a>> {
    left.prepay(work)?;
    right.prepay(work)?;
    // AccountId equality compares compact bytes directly. Unlike Ord it cannot
    // format a ParseError for an in-memory malformed compact key.
    Ok(left == right)
}

fn next_physical<'a, I: ExactSizeIterator>(
    rows: &mut I,
    work: &mut Work,
) -> Result<Option<I::Item>, Error<'a>> {
    if rows.len() == 0 {
        return Ok(None);
    }
    work.charge(1)?;
    Ok(rows.next())
}

/// Complete equality scans retain a match until every original candidate is funded.
pub(super) fn lookup<'a, K: WorkKey, V: mv::Value>(
    rows: &'a impl Images<K, V>,
    image: Image,
    wanted: &K,
    work: &mut Work,
) -> Result<Option<&'a V>, Error<'a>> {
    let mut found = None;
    visit(rows, image, work, |key, value, work| {
        if equal(key, wanted, work)? {
            found = Some(value);
        }
        Ok(())
    })?;
    Ok(found)
}

/// Admit every actual advance and full masking tail, including absent preimages.
pub(super) fn visit<'a, K: WorkKey, V: mv::Value>(
    rows: &'a impl Images<K, V>,
    image: Image,
    work: &mut Work,
    mut visitor: impl FnMut(&'a K, &'a V, &mut Work) -> Result<(), Error<'a>>,
) -> Result<(), Error<'a>> {
    let mut current = rows.current_rows();
    while let Some((key, value)) = next_physical(&mut current, work)? {
        let mut masked = false;
        if image == Image::Predecessor {
            let mut undo = rows.undo_rows();
            while let Some((prior_key, _)) = next_physical(&mut undo, work)? {
                masked |= equal(key, prior_key, work)?;
            }
        }
        if !masked {
            visitor(key, value, work)?;
        }
    }
    if image == Image::Predecessor {
        let mut undo = rows.undo_rows();
        while let Some((key, value)) = next_physical(&mut undo, work)? {
            if let Some(value) = value {
                visitor(key, value, work)?;
            }
        }
    }
    Ok(())
}

fn prepay_owner<'a>(owner: &ContractLifecycleOwnerV1, work: &mut Work) -> Result<(), Error<'a>> {
    work.charge(1)?; // owner discriminant
    if let ContractLifecycleOwnerV1::Account(account) = owner {
        account.prepay(work)?;
    }
    Ok(())
}

// Admit the exact retained inputs which the unchanged lifecycle predicate can
// inspect. Historical origin accounts are not inspected or required to be live.
fn prepay_lifecycle<'a>(
    lifecycle: &ContractLifecycleControlV1,
    work: &mut Work,
) -> Result<(), Error<'a>> {
    work.charge(core::mem::size_of::<u16>() + core::mem::size_of::<u64>())?;
    prepay_optional_hash(&lifecycle.active_code_hash, work)?;
    prepay_optional_hash(&lifecycle.retained_code_hash, work)?;
    prepay_owner(&lifecycle.owner, work)?;
    work.charge(1)?; // pending-owner option
    if let Some(owner) = &lifecycle.pending_owner {
        prepay_owner(owner, work)?;
    }
    work.charge(1)?; // Parliament delegation
    work.charge(1)?; // origin discriminant
    if let ContractDeploymentOriginV1::Parliament(_) = &lifecycle.origin {
        work.charge(2 * Hash::LENGTH)?;
    }
    work.charge(1)?; // emergency-hold option
    if let Some(hold) = &lifecycle.emergency_hold {
        work.charge(3 * Hash::LENGTH + 2 * core::mem::size_of::<u64>())?;
        work.charge(hold.reason.len())?;
    }
    Ok(())
}

fn prepay_optional_hash<'a, T>(hash: &Option<T>, work: &mut Work) -> Result<(), Error<'a>> {
    work.charge(1)?;
    if hash.is_some() {
        work.charge(Hash::LENGTH)?;
    }
    Ok(())
}

/// Existing source invariants, applied to matching accounts and active-code images.
pub(super) fn validate_sources<'a>(
    rows: &'a impl Images<ContractAddress, ContractSubjectBinding>,
    accounts: &'a impl Images<AccountId, AccountValue>,
    instances: &'a impl Images<ContractAddress, Hash>,
    work: &mut Work,
) -> Result<(), Error<'a>> {
    for image in [Image::Current, Image::Predecessor] {
        visit(rows, image, work, |address, binding, work| {
            let source = |account, reason| {
                Error::source(
                    image,
                    "world.contract_subject_bindings",
                    address,
                    account,
                    reason,
                )
            };
            let expected = address.try_subject_key_bytes(|bytes| {
                // One fixed strict curve check in addition to the exact hash bytes.
                work.charge(bytes.checked_add(1).ok_or(Error::work_limit())?)
            })?;
            binding.subject.prepay(work)?;
            let stored = binding
                .subject
                .try_signatory()
                .and_then(|key| key.borrowed_parts().ok());
            work.charge(expected.len())?;
            if !matches!(stored, Some((Algorithm::Ed25519, payload)) if payload == expected.as_slice())
            {
                return Err(source(None, "contract subject binding mismatch"));
            }
            prepay_lifecycle(&binding.lifecycle, work)?;
            binding
                .lifecycle
                .validate()
                .map_err(|reason| source(None, reason))?;
            if lookup(accounts, image, &binding.subject, work)?.is_none() {
                return Err(source(Some(&binding.subject), "subject account is absent"));
            }
            let indexed = lookup(instances, image, address, work)?;
            prepay_optional_hash(&binding.lifecycle.active_code_hash, work)?;
            prepay_optional_hash(&indexed, work)?;
            if binding.lifecycle.active_code_hash != indexed.copied() {
                return Err(source(
                    None,
                    "contract lifecycle active code hash does not match the active-instance index",
                ));
            }
            // The already admitted pending option determines the two fixed
            // owner advances; reserve them all before entering the iterator.
            work.charge(1 + usize::from(binding.lifecycle.pending_owner.is_some()))?;
            for owner in core::iter::once(&binding.lifecycle.owner)
                .chain(binding.lifecycle.pending_owner.as_ref())
            {
                if let ContractLifecycleOwnerV1::Account(account) = owner
                    && lookup(accounts, image, account, work)?.is_none()
                {
                    return Err(source(Some(account), "lifecycle owner account is absent"));
                }
            }
            Ok(())
        })?;
        visit(instances, image, work, |address, _, work| {
            if lookup(rows, image, address, work)?.is_none() {
                return Err(Error::source(
                    image,
                    "world.contract_instances",
                    address,
                    None,
                    "active contract instance has no lifecycle binding",
                ));
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Check both directions using only the already retained source and inverse.
pub(super) fn validate_index<'a>(
    rows: &'a impl Images<ContractAddress, ContractSubjectBinding>,
    reverse: &'a impl Images<AccountId, ContractAddress>,
    work: &mut Work,
) -> Result<(), Error<'a>> {
    for image in [Image::Current, Image::Predecessor] {
        visit(rows, image, work, |address, binding, work| {
            let Some(stored) = lookup(reverse, image, &binding.subject, work)? else {
                return Err(Error::index(image, true));
            };
            if !equal(address, stored, work)? {
                return Err(Error::index(image, true));
            }
            Ok(())
        })?;
        visit(reverse, image, work, |subject, address, work| {
            let Some(binding) = lookup(rows, image, address, work)? else {
                return Err(Error::index(image, false));
            };
            if !equal(subject, &binding.subject, work)? {
                return Err(Error::index(image, false));
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Allocate diagnostic text only at the existing startup error boundary.
pub(super) fn restore_error(error: Error<'_>) -> String {
    match error.kind {
        ErrorKind::WorkLimit => "contract subject startup work admission unavailable".into(),
        ErrorKind::Source => {
            let detail = match (error.address, error.reason, error.account) {
                (Some(address), "subject account is absent", Some(account)) => {
                    format!("contract subject account `{account}` for `{address}` does not exist")
                }
                (Some(address), "lifecycle owner account is absent", Some(account)) => {
                    format!("contract lifecycle owner `{account}` for `{address}` does not exist")
                }
                (Some(address), reason, _) => format!("{reason} for `{address}`"),
                (None, reason, _) => reason.into(),
            };
            format!("invalid {:?} contract subjects: {detail}", error.image)
        }
        ErrorKind::MissingIndex | ErrorKind::ForeignIndex => {
            format!("invalid {:?} contract subject reverse index", error.image)
        }
    }
}

#[cfg(test)]
pub(super) mod test_support;

#[cfg(test)]
mod error_tests {
    use super::*;
    use crate::test_allocations::allocations_during;

    #[test]
    fn inline_error_keeps_all_kinds_and_exact_borrowed_restore_diagnostics() {
        let address = test_support::address();
        let account = &*iroha_test_samples::ALICE_ID;
        let mut errors = None;
        assert_eq!(
            allocations_during(|| {
                errors = Some([
                    Error::work_limit(),
                    Error::source(
                        Image::Predecessor,
                        "world.contract_subject_bindings",
                        &address,
                        Some(account),
                        "subject account is absent",
                    ),
                    Error::index(Image::Current, true),
                    Error::index(Image::Predecessor, false),
                ]);
            }),
            0
        );
        let [work, source, missing, foreign] = errors.unwrap();
        assert_eq!(work.kind, ErrorKind::WorkLimit);
        assert_eq!(source.kind, ErrorKind::Source);
        assert_eq!(source.table, "world.contract_subject_bindings");
        assert!(core::ptr::eq(source.address.unwrap(), &address));
        assert!(core::ptr::eq(source.account.unwrap(), account));
        assert_eq!(missing.kind, ErrorKind::MissingIndex);
        assert_eq!(foreign.kind, ErrorKind::ForeignIndex);
        assert_eq!(
            restore_error(work),
            "contract subject startup work admission unavailable"
        );
        assert_eq!(
            restore_error(source),
            format!(
                "invalid Predecessor contract subjects: contract subject account `{account}` for `{address}` does not exist"
            )
        );
        assert_eq!(
            restore_error(missing),
            "invalid Current contract subject reverse index"
        );
        assert_eq!(
            restore_error(foreign),
            "invalid Predecessor contract subject reverse index"
        );
    }
}

#[cfg(test)]
#[path = "contract_subject_validation/work_tests.rs"]
mod work_tests;
