//! One bounded epoch, replacement-claim and live-clock owner for closed generated dispatches.
//!
//! Retained records bind custody only. Only a newly issued non-decodable Lease carries a live
//! deadline and cancellation; reading these records never renews transaction authorization.
use super::{
    Fees, Terms,
    attempts::{self, BodyReplacementTarget, Origin, Purpose},
    invalid, now_ms, require_deadline,
};
#[cfg(test)]
use crate::managed::stream_token_custody::body_history::finish_timing;
use crate::managed::{ManagedBootstrapFailure, Result};
use iroha_crypto::Hash;
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::AccountService;
use std::{
    cell::Cell,
    ffi::OsString,
    sync::{
        Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

pub(in crate::managed) const MAX_EPOCHS: usize = 64;

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::authorization::Epoch")]
pub(in crate::managed) struct Epoch {
    pub(in crate::managed) ordinal: u8,
    pub(in crate::managed) previous: Option<[u8; 32]>,
    pub(in crate::managed) parent_intent: [u8; 32],
    issued_at_unix_ms: u64,
    pub(in crate::managed) terms: Terms,
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::authorization::Replacement")]
struct Replacement {
    epoch: [u8; 32],
    purpose: Purpose,
    target: ReplacementTarget,
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::authorization::ReplacementTarget")]
enum ReplacementTarget {
    Dispatch {
        previous_attempt: [u8; 32],
    },
    EnrollmentBody {
        outer_intent: [u8; 32],
        previous_body: [u8; 32],
        successor_selection: [u8; 32],
    },
}
impl ReplacementTarget {
    fn validate(&self, purpose: Purpose) -> Result<()> {
        let valid = match self {
            Self::Dispatch { previous_attempt } => *previous_attempt != [0; 32],
            Self::EnrollmentBody {
                outer_intent,
                previous_body,
                successor_selection,
            } => {
                matches!(
                    purpose,
                    Purpose::CustodyEnroll(_) | Purpose::CustodyRenewal { .. }
                ) && *outer_intent != [0; 32]
                    && *previous_body != [0; 32]
                    && *successor_selection != [0; 32]
                    && previous_body != successor_selection
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(
                "unsigned replacement target differs from its closed purpose",
            ))
        }
    }
}

/// Closed local scope. It cannot supply a native policy, current state or successful carrier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::managed) enum Scope {
    Bootstrap([ProviderId; 3]),
    Renewal { provider: ProviderId, sequence: u64 },
}
impl Scope {
    pub(in crate::managed) fn check(self, purpose: Purpose) -> Result<()> {
        let allowed = match (self, purpose) {
            (
                Self::Renewal { provider, sequence },
                Purpose::CustodyRenewal {
                    provider: selected,
                    sequence: next,
                },
            ) => provider == selected && sequence == next && (2..=64).contains(&sequence),
            (Self::Bootstrap(_), Purpose::CustodyRenewal { .. }) => false,
            (Self::Bootstrap(_), Purpose::ReservePolicy | Purpose::Reputation) => true,
            (
                Self::Bootstrap(providers),
                Purpose::CustodyConfigure(p)
                | Purpose::CustodyEnroll(p)
                | Purpose::ReserveAccount(p)
                | Purpose::FundingRequest(p)
                | Purpose::FundingApproval(p)
                | Purpose::FundingCredit(p)
                | Purpose::FundingCapacity(p)
                | Purpose::ProviderIngest(p)
                | Purpose::Gateway(p),
            ) => providers.contains(&p),
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(invalid(
                "generated authorization changed its closed purpose",
            ))
        }
    }
}

/// Held original anchor and newly issued live clocks; no Clone or decode implementation.
pub(in crate::managed) struct Lease {
    pub(in crate::managed) directory: PrivateDirectory,
    original: Vec<u8>,
    original_digest: [u8; 32],
    scope: Scope,
    pub(in crate::managed) epoch: Epoch,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    // Serialize this live owner's epoch census with its sole replacement publication.
    // This is not a retained absence verdict or a lock over another process's writes.
    replacement_gate: RwLock<()>,
}
impl Lease {
    pub(in crate::managed) fn issue(
        directory: PrivateDirectory,
        original: Vec<u8>,
        fees: &Fees,
        scope: Scope,
        expires: u64,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        require_active(&cancelled)?;
        require_deadline(deadline)?;
        fees.validate()?;
        if original.is_empty() || original.len() > super::MAX_CHECKPOINT_BYTES + 128 * 1024 {
            return Err(invalid(
                "generated authorization original exceeds its byte bound",
            ));
        }
        let original_digest = *Hash::new(&original).as_ref();
        if directory.read("original.nrt", original.len())?.as_slice() != original.as_slice() {
            return Err(invalid("generated authorization original changed"));
        }
        let issued_at_unix_ms = now_ms()?;
        let remaining = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| invalid("generated authorization interval exceeds bound"))?;
        let requested = issued_at_unix_ms
            .checked_add(remaining)
            .ok_or_else(|| invalid("generated authorization UTC overflow"))?
            .min(expires.saturating_sub(1));
        if requested <= issued_at_unix_ms {
            return Err(ManagedBootstrapFailure::ProfileExpired.into());
        }
        let terms = Terms::new(requested, &fees.options(deadline))?;
        require_active(&cancelled)?;
        let root = directory.ensure_child("epochs")?;
        let retained = read_epochs(&root, original_digest, fees, scope, Vec::new())?;
        if retained.len() >= MAX_EPOCHS {
            return Err(ManagedBootstrapFailure::EpochLimit.into());
        }
        let epoch = Epoch {
            ordinal: u8::try_from(retained.len() + 1)
                .map_err(|_| invalid("generated epoch ordinal overflow"))?,
            previous: retained
                .last()
                .map(|entry| entry.epoch.digest())
                .transpose()?,
            parent_intent: original_digest,
            issued_at_unix_ms,
            terms,
        };
        require_active(&cancelled)?;
        attempts::write_record(&root, &format!("{:04}.nrt", epoch.ordinal), &epoch)?;
        let after = read_epochs(&root, original_digest, fees, scope, Vec::new())?;
        if after.last().map(|entry| &entry.epoch.value) != Some(&epoch)
            || after.len() != retained.len() + 1
        {
            return Err(invalid("new generated epoch changed during publication"));
        }
        Ok(Self {
            directory,
            original,
            original_digest,
            scope,
            epoch,
            deadline,
            cancelled,
            replacement_gate: RwLock::new(()),
        })
    }
    pub(in crate::managed) fn check(&self, deadline: Instant) -> Result<Instant> {
        let _guard = self.read_guard(deadline)?;
        self.check_locked(deadline)
    }
    // All native and final live checks remain in their original order. The caller owns
    // either the shared census guard or the exclusive replacement guard throughout.
    fn check_locked(&self, deadline: Instant) -> Result<Instant> {
        #[cfg(test)]
        let _closure_timing =
            finish_timing::phase_in_closure(finish_timing::Phase::ClosureLiveCheck);
        require_active(&self.cancelled)?;
        let deadline = deadline.min(self.deadline);
        if deadline <= Instant::now() {
            return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
        }
        self.directory.revalidate()?;
        if self
            .directory
            .read("original.nrt", self.original.len())?
            .as_slice()
            != self.original.as_slice()
        {
            return Err(invalid("generated original changed after authorization"));
        }
        if now_ms()? >= self.epoch.terms.signing_deadline_unix_ms {
            return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
        }
        let retained = read_epochs(
            &self.directory.open_child("epochs")?,
            self.original_digest,
            &self.epoch.terms.fees,
            self.scope,
            Vec::new(),
        )?;
        if retained.last().map(|entry| &entry.epoch.value) != Some(&self.epoch) {
            return Err(invalid(
                "generated capability no longer selects its retained epoch",
            ));
        }
        #[cfg(test)]
        cancellation_tests::after_native_reads();
        let deadline = self.epoch.terms.signing_deadline(deadline).map_err(|_| {
            crate::managed::Error::Bootstrap(ManagedBootstrapFailure::AuthorizationExpired)
        })?;
        // Preserve native/retained and expiry refusals before closing a successful live check.
        require_active(&self.cancelled)?;
        Ok(deadline)
    }
    fn require_lock_budget(&self, deadline: Instant) -> Result<()> {
        require_active(&self.cancelled)?;
        if deadline.min(self.deadline) <= Instant::now() {
            return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
        }
        if now_ms()? >= self.epoch.terms.signing_deadline_unix_ms {
            return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
        }
        Ok(())
    }
    fn read_guard(&self, deadline: Instant) -> Result<RwLockReadGuard<'_, ()>> {
        loop {
            self.require_lock_budget(deadline)?;
            match self.replacement_gate.try_read() {
                Ok(guard) => {
                    self.require_lock_budget(deadline)?;
                    return Ok(guard);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(invalid("generated authorization replacement gate poisoned"));
                }
                Err(TryLockError::WouldBlock) => {
                    #[cfg(test)]
                    parallel_tests::after_contention();
                    std::thread::yield_now();
                }
            }
        }
    }
    fn write_guard(&self, deadline: Instant) -> Result<RwLockWriteGuard<'_, ()>> {
        loop {
            self.require_lock_budget(deadline)?;
            match self.replacement_gate.try_write() {
                Ok(guard) => {
                    self.require_lock_budget(deadline)?;
                    return Ok(guard);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(invalid("generated authorization replacement gate poisoned"));
                }
                Err(TryLockError::WouldBlock) => {
                    #[cfg(test)]
                    parallel_tests::after_contention();
                    std::thread::yield_now();
                }
            }
        }
    }
    fn origin(&self) -> Result<Origin> {
        Ok(Origin::Generated {
            ordinal: self.epoch.ordinal,
            epoch: digest(&self.epoch)?,
            parent_intent: self.original_digest,
        })
    }
    fn claim(&self, purpose: Purpose, target: ReplacementTarget, deadline: Instant) -> Result<()> {
        #[cfg(test)]
        let _closure_timing =
            finish_timing::phase_in_closure(finish_timing::Phase::ClosureLiveClaim);
        let _guard = self.write_guard(deadline)?;
        #[cfg(test)]
        parallel_tests::after_claim_lock();
        self.check_locked(deadline)?;
        self.scope.check(purpose)?;
        target.validate(purpose)?;
        let root = self.directory.open_child("epochs")?;
        let name = format!("{:04}-replacement.nrt", self.epoch.ordinal);
        let selected = Replacement {
            epoch: digest(&self.epoch)?,
            purpose,
            target,
        };
        if let Some(old) = attempts::read_record::<Replacement>(&root, &name)? {
            if old != selected {
                return Err(ManagedBootstrapFailure::ReplacementLimit.into());
            }
        } else {
            self.check_locked(deadline)?;
            attempts::write_record(&root, &name, &selected)?;
        }
        self.check_locked(deadline)?;
        Ok(())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::managed::service_bootstrap::authorization::BootstrapChildAuthorization<'_> {}
    impl Sealed for crate::managed::stream_token_custody::renewal::GeneratedRenewalAuthorization {}
}
/// Only the two closed issuers above may feed the sole generated attempt transition.
pub(in crate::managed) trait DispatchAuthorization: sealed::Sealed {
    fn lease(&self) -> &Lease;
    fn purpose(&self) -> Purpose;
    fn check(&self, purpose: Purpose, deadline: Instant) -> Result<Instant> {
        if purpose != self.purpose() {
            return Err(invalid("generated dispatch changed its authorized purpose"));
        }
        self.lease().scope.check(purpose)?;
        self.lease().check(deadline)
    }
    fn fees(&self) -> &Fees {
        &self.lease().epoch.terms.fees
    }
    fn origin(&self) -> Result<Origin> {
        self.lease().origin()
    }
    fn bind_account(&self, account: AccountService) -> Result<AccountService> {
        account
            .with_cancellation(Arc::clone(&self.lease().cancelled))
            .map_err(|_| invalid("generated wallet cancellation binding changed"))
    }
    fn terms(&self, deadline: Instant, exclusive_ceiling: Option<u64>) -> Result<Terms> {
        self.check(self.purpose(), deadline)?;
        let mut terms = self.lease().epoch.terms.clone();
        if let Some(ceiling) = exclusive_ceiling {
            let end = ceiling
                .checked_sub(1)
                .ok_or(ManagedBootstrapFailure::EnrollmentExpired)?;
            terms.requested_deadline_unix_ms = terms.requested_deadline_unix_ms.min(end);
            terms.signing_deadline_unix_ms = terms.signing_deadline_unix_ms.min(end);
        }
        terms.validate()?;
        if now_ms()? >= terms.signing_deadline_unix_ms {
            return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
        }
        Ok(terms)
    }
    fn claim_replacement(&self, previous_attempt: [u8; 32], deadline: Instant) -> Result<()> {
        self.check(self.purpose(), deadline)?;
        self.lease().claim(
            self.purpose(),
            ReplacementTarget::Dispatch { previous_attempt },
            deadline,
        )
    }
    fn claim_body_replacement(
        &self,
        target: &dyn BodyReplacementTarget,
        deadline: Instant,
    ) -> Result<()> {
        self.check(target.purpose(), deadline)?;
        target.validate_target()?;
        if target.fees() != self.fees() {
            return Err(invalid(
                "body replacement changed original fee authorization",
            ));
        }
        self.lease().claim(
            target.purpose(),
            ReplacementTarget::EnrollmentBody {
                outer_intent: target.outer_intent(),
                previous_body: target.predecessor_body(),
                successor_selection: target.successor_selection(),
            },
            deadline,
        )
    }
}

// Owned once by a lexical read. Ordinary censuses and selected parser references freshly
// observe their bytes; a parser's original complete sequence also closes at full exit.
// These immutable DTOs/digests cannot issue a Lease or survive in BodyHistory.
struct RecordImage<T> {
    bytes: Vec<u8>,
    value: T,
    digest: Cell<Option<[u8; 32]>>,
}
impl<T: norito::NoritoSerialize> RecordImage<T> {
    fn digest(&self) -> Result<[u8; 32]> {
        if let Some(value) = self.digest.get() {
            return Ok(value);
        }
        let value = digest(&self.value)?;
        #[cfg(test)]
        reader_tests::digest_computed();
        self.digest.set(Some(value));
        Ok(value)
    }
}
struct RetainedEpoch {
    epoch: RecordImage<Epoch>,
    claim: Option<RecordImage<Replacement>>,
}

/// One body parser's bounded metadata workspace, never a live authorization verdict.
/// A concrete read-only parser may borrow its exact original source until the full exit;
/// ordinary/effectful readers and active decode budgets retain every complete census.
#[derive(Default)]
pub(in crate::managed) struct EpochReader {
    records: Vec<RetainedEpoch>,
    parser_source: Option<parser::Source>,
}
impl EpochReader {
    fn refresh(
        &mut self,
        directory: &PrivateDirectory,
        original_digest: [u8; 32],
        fees: &Fees,
        scope: Scope,
    ) -> Result<()> {
        // Open the child anew at every original census point. No old native directory or
        // file handle is used to replace the currently named custody observation.
        self.records = match directory.open_child_optional("epochs")? {
            Some(root) => read_epochs(
                &root,
                original_digest,
                fees,
                scope,
                std::mem::take(&mut self.records),
            )?,
            None => Vec::new(),
        };
        Ok(())
    }
    pub(in crate::managed) fn validate_retained(
        &mut self,
        directory: &PrivateDirectory,
        original_digest: [u8; 32],
        fees: &Fees,
        scope: Scope,
    ) -> Result<()> {
        self.refresh(directory, original_digest, fees, scope)?;
        directory.revalidate()?;
        Ok(())
    }
    pub(in crate::managed) fn validate_references<'a>(
        &mut self,
        directory: &PrivateDirectory,
        original_digest: [u8; 32],
        fees: &Fees,
        scope: Scope,
        origins: impl Iterator<Item = &'a Origin>,
    ) -> Result<()> {
        if self.parser_source.is_some() {
            return self.validate_parser_references(
                directory,
                original_digest,
                fees,
                scope,
                origins,
            );
        }
        self.refresh(directory, original_digest, fees, scope)?;
        for origin in origins {
            if let Origin::Generated {
                ordinal,
                epoch,
                parent_intent,
            } = origin
            {
                let selected = self
                    .records
                    .get(
                        usize::from(*ordinal)
                            .checked_sub(1)
                            .ok_or_else(|| invalid("generated epoch ordinal is zero"))?,
                    )
                    .ok_or_else(|| {
                        invalid("retained dispatch lost its original authorization epoch")
                    })?;
                if *parent_intent != original_digest || *epoch != selected.epoch.digest()? {
                    return Err(invalid(
                        "retained dispatch changed its original authorization epoch",
                    ));
                }
            }
        }
        Ok(())
    }
}
pub(in crate::managed) fn validate_retained(
    directory: &PrivateDirectory,
    original_digest: [u8; 32],
    fees: &Fees,
    scope: Scope,
) -> Result<()> {
    EpochReader::default().validate_retained(directory, original_digest, fees, scope)
}

// One physical producer for ordinary imports and exact parser-owned image comparisons.
fn read_source_image(root: &PrivateDirectory, name: &str) -> Result<Option<Vec<u8>>> {
    #[cfg(test)]
    reader_tests::record_read();
    super::read_optional(root, name, attempts::MAX_RECORD_BYTES)
}

fn read_image<T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>>(
    root: &PrivateDirectory,
    name: &str,
    retained: Option<RecordImage<T>>,
    exact: bool,
) -> Result<Option<RecordImage<T>>> {
    let current = read_source_image(root, name)?;
    // Compare before dropping or replacing the original image: absence, a newly appeared
    // claim/epoch, and changed bytes all refuse the exact lexical parser exit.
    if exact && current.as_deref() != retained.as_ref().map(|image| image.bytes.as_slice()) {
        return Err(invalid("original epoch parser image changed"));
    }
    let Some(bytes) = current else {
        return Ok(None);
    };
    // An enclosing decoder owns its current admission, including field/sequence/depth
    // ceilings. Such a caller must independently decode this image even when identical;
    // pure metadata reuse cannot transfer a prior decoder's admission to another scope.
    if let Some(retained) =
        retained.filter(|retained| !norito::core::decode_limits_active() && retained.bytes == bytes)
    {
        return Ok(Some(retained));
    }
    let value = attempts::decode_record(&bytes)?;
    #[cfg(test)]
    reader_tests::record_decoded();
    Ok(Some(RecordImage {
        bytes,
        value,
        digest: Cell::new(None),
    }))
}
fn validate_epoch(
    epoch: &RecordImage<Epoch>,
    ordinal: usize,
    previous: Option<&RecordImage<Epoch>>,
    parent_intent: [u8; 32],
    fees: &Fees,
) -> Result<()> {
    let value = &epoch.value;
    value.terms.validate()?;
    if usize::from(value.ordinal) != ordinal
        || value.parent_intent != parent_intent
        || value.terms.fees != *fees
        || value.issued_at_unix_ms == 0
        || value.issued_at_unix_ms >= value.terms.signing_deadline_unix_ms
        || value.previous != previous.map(RecordImage::digest).transpose()?
    {
        return Err(invalid(
            "generated epoch changed original intent, fees or lineage",
        ));
    }
    Ok(())
}
fn validate_claim(
    claim: &RecordImage<Replacement>,
    epoch: &RecordImage<Epoch>,
    scope: Scope,
) -> Result<()> {
    scope.check(claim.value.purpose)?;
    claim.value.target.validate(claim.value.purpose)?;
    if claim.value.epoch != epoch.digest()? {
        return Err(invalid("generated unsigned replacement claim changed"));
    }
    Ok(())
}

fn read_epochs(
    root: &PrivateDirectory,
    parent_intent: [u8; 32],
    fees: &Fees,
    scope: Scope,
    retained: Vec<RetainedEpoch>,
) -> Result<Vec<RetainedEpoch>> {
    read_epochs_using(root, parent_intent, fees, scope, retained, false)
}

// One canonical sequence reader owns bounds, physical reads, decoding, semantics and
// namespace order. The parser exit moves its original images through this same reader.
fn read_epochs_using(
    root: &PrivateDirectory,
    parent_intent: [u8; 32],
    fees: &Fees,
    scope: Scope,
    retained: Vec<RetainedEpoch>,
    exact: bool,
) -> Result<Vec<RetainedEpoch>> {
    #[cfg(test)]
    reader_tests::namespace_read();
    let names = root.entries(MAX_EPOCHS * 2)?;
    let mut expected = Vec::<OsString>::new();
    let mut epochs: Vec<RetainedEpoch> = Vec::new();
    // Move each already owned image after its fresh observation. Unchanged records keep
    // their original allocation; changed records are dropped before canonical decode.
    // Old unread tails and partial new results are dropped if this census refuses.
    let mut retained = retained.into_iter();
    for index in 1..=MAX_EPOCHS {
        let name = format!("{index:04}.nrt");
        let (old_epoch, old_claim) = retained
            .next()
            .map_or((None, None), |entry| (Some(entry.epoch), entry.claim));
        let Some(epoch): Option<RecordImage<Epoch>> = read_image(root, &name, old_epoch, exact)?
        else {
            break;
        };
        validate_epoch(
            &epoch,
            index,
            epochs.last().map(|entry| &entry.epoch),
            parent_intent,
            fees,
        )?;
        expected.push(name.into());
        let claim_name = format!("{index:04}-replacement.nrt");
        let claim = read_image(root, &claim_name, old_claim, exact)?;
        if let Some(claim) = &claim {
            validate_claim(claim, &epoch, scope)?;
            expected.push(claim_name.into());
        }
        epochs.push(RetainedEpoch { epoch, claim });
    }
    expected.sort();
    // Keep the short-circuit order: a mismatched original inventory refuses before the
    // original final namespace observation is attempted.
    if names != expected || {
        #[cfg(test)]
        reader_tests::namespace_read();
        root.entries(MAX_EPOCHS * 2)? != names
    } {
        return Err(invalid(
            "generated epoch inventory changed or contains gaps or unknown material",
        ));
    }
    Ok(epochs)
}
pub(in crate::managed) fn digest<T: norito::NoritoSerialize>(value: &T) -> Result<[u8; 32]> {
    attempts::semantic_digest(value, attempts::MAX_RECORD_BYTES)
}
pub(in crate::managed) fn require_active(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(ManagedBootstrapFailure::Cancelled.into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "authorization/reader_tests.rs"]
mod reader_tests;

#[cfg(test)]
#[path = "authorization/cancellation_tests.rs"]
mod cancellation_tests;

#[cfg(test)]
#[path = "authorization/parallel_tests.rs"]
mod parallel_tests;

#[path = "authorization/parser.rs"]
mod parser;
pub(in crate::managed) use parser::BodyParserEpochContext;
