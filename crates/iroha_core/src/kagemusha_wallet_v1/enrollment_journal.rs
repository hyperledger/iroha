//! Exclusive node custody for original enrollment attempts and exact-result recovery.
//!
//! This journal establishes durable ordering, not KYC, worker provenance or signer authority.
//! The enrollment service must authenticate its selected scope and recheck current eligibility.
//! `EnrollmentIssuerV1` opens this owner with the approved selection, private worker and
//! rooted signer; Torii's enrollment service dispatches authenticated requests through it.

use iroha_data_model::kagemusha::KagemushaWalletEnrollmentChallengeV1;
use iroha_fs::{FileIdentity, FileSnapshot, PrivateDirectory, PublishMode};
use norito::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use std::{fs::File, io, path::Path};

const SCOPE_MAX: usize = 16 * 1024;
const SCOPE_FRAME_MAX: usize = SCOPE_MAX + 512;
const ORIGINAL_MAX: usize = 768 * 1024;
const RECORD_MAX: usize = 3 * 1024 * 1024;
const PERMIT_RECORD_MAX: usize = 20 * 1024;
const LOCK: &str = "owner.lock";
const SCOPE: &str = "scope.norito";

/// No error establishes absence, rejection of platform evidence, or permission to dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentJournalErrorV1 {
    /// Native custody, lock, I/O or durability could not be established.
    #[error("enrollment journal unavailable")]
    Unavailable,
    /// Invalid or noncanonical original, corrupt phase, or substituted scope.
    #[error("enrollment journal original rejected")]
    Invalid,
    /// The permanent selection or exact original differs.
    #[error("enrollment journal selection conflicts")]
    Conflict,
    /// The authenticated definitive eligibility observation denies this operation, with its
    /// closed reason: `AccountNotApproved` (11) or `AccountFrozen` (12).
    #[error("enrollment eligibility denied: code {}", .0.code())]
    Ineligible(iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1),
    /// This owner observed a failed publication and must reopen and reconcile.
    #[error("enrollment journal outcome is uncertain")]
    Uncertain,
}
type Result<T> = std::result::Result<T, EnrollmentJournalErrorV1>;
use EnrollmentJournalErrorV1::{Conflict, Invalid, Unavailable, Uncertain};

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.journal_scope.v1")]
struct ScopeRecord {
    version: u16,
    original: Vec<u8>,
}
fn scope_frame(original: &[u8]) -> Result<Vec<u8>> {
    scope_digest(original)?;
    let bytes = norito::encode_canonical(&ScopeRecord {
        version: 1,
        original: original.to_vec(),
    })
    .map_err(|_| Invalid)?;
    if bytes.len() > SCOPE_FRAME_MAX {
        return Err(Invalid);
    }
    Ok(bytes)
}

/// Exact immutable issuer selection, made only after independent service authorization.
/// These fields are DATA. Constructing them creates no enrollment or key-generation grant.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.selection.v1")]
pub struct EnrollmentSelectionV1 {
    /// Nonzero index derived from the authenticated subject and Native request identity.
    pub key: [u8; 32],
    /// Original server-generated unpredictable attempt identity.
    pub attempt_id: [u8; 32],
    /// Exact server-selected E1, with its original unpredictable issuer nonce.
    pub challenge: KagemushaWalletEnrollmentChallengeV1,
    /// Genuine positive issuer creation time, never a mobile timestamp.
    pub created_at_ms: u64,
    /// Original checked creation plus approved challenge lifetime; retries never extend it.
    pub expires_at_ms: u64,
    /// Canonical stable selection from the native dispatch, independently compared by service.
    pub stable_selection: Vec<u8>,
}
impl EnrollmentSelectionV1 {
    fn validate(&self) -> Result<()> {
        self.challenge.validate().map_err(|_| Invalid)?;
        if self.key == [0; 32]
            || self.attempt_id == [0; 32]
            || self.created_at_ms == 0
            || self.expires_at_ms <= self.created_at_ms
            || self.stable_selection.is_empty()
            || self.stable_selection.len() > SCOPE_MAX
        {
            return Err(Invalid);
        }
        Ok(())
    }
}

/// Durable progress. `Verifying` always requires recovery after rereading this journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.phase.v1")]
pub enum EnrollmentJournalPhaseV1 {
    /// E1 and all initial selections are durable; verification has not been selected.
    Selected,
    /// Exact E5 and private verifier original were retained before any dispatch.
    Verifying,
    /// Exact original worker evidence is retained; it is not a signing permission.
    Evidence,
    /// Definitive worker rejection was retained; the original attempt remains consumed.
    Rejected,
    /// Exact credential body and its original issue time were retained before signing.
    Signing,
    /// Actual signed E6 original is durable and may be recovered byte for byte.
    Issued,
}

/// Selection of the exact worker exchange whose authenticated reply is the retained terminal
/// refusal. With the retained E5, preparation, configuration and journal incarnation it
/// rebuilds that exchange, so every exposure checks the retained reply against all of its
/// bindings again. The first terminal exchange is kept across every later retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.refusal_exchange.v1")]
struct WorkerRefusalExchange {
    /// 1 Complete, 2 Recover, 3 Inspect.
    action: u8,
    /// Nonzero fresh exchange identifier.
    exchange: [u8; 32],
    /// Trusted dispatch time of that exchange.
    dispatch_time_ms: u64,
}
impl WorkerRefusalExchange {
    fn of(
        exchange: &iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::VerifierExchangeV1,
    ) -> Result<Self> {
        use iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::ActionV1;
        let action = match exchange.action().ok_or(Invalid)? {
            ActionV1::Complete => 1,
            ActionV1::Recover => 2,
            ActionV1::Inspect => 3,
            ActionV1::RecheckRevocation => return Err(Invalid),
        };
        Ok(Self {
            action,
            exchange: exchange.exchange_id(),
            dispatch_time_ms: exchange.dispatch_time_ms().ok_or(Invalid)?,
        })
    }
    fn action(
        self,
    ) -> Result<iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::ActionV1> {
        use iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::ActionV1;
        Ok(match self.action {
            1 => ActionV1::Complete,
            2 => ActionV1::Recover,
            3 => ActionV1::Inspect,
            _ => return Err(Invalid),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.record.v1")]
struct Record {
    version: u16,
    scope: [u8; 32],
    selection: EnrollmentSelectionV1,
    phase: EnrollmentJournalPhaseV1,
    verification_time_ms: u64,
    worker_configuration: [u8; 32],
    worker_preparation: Option<preparation::WorkerPreparationSelection>,
    request: Vec<u8>,
    worker_request: Vec<u8>,
    worker_result: Vec<u8>,
    worker_result_time_ms: u64,
    credential_body: Vec<u8>,
    issued: Vec<u8>,
    eligibility: Vec<eligibility::EligibilityRecord>,
    /// The Enrollment signer was invoked for the frozen credential body. Recovery of a
    /// `Signing` attempt with this set never signs again: the outcome is unknown unless the
    /// exact signed E6 is retained.
    signing_dispatched: bool,
    /// Closed code (11 or 12) of an authenticated eligibility denial retained before any
    /// credential could exist; 0 when none. It is terminal for the attempt: no later approval,
    /// restart or retry resumes it.
    refusal: u16,
    /// Nonce of the exact retained signed denial that `refusal` names; zero when none.
    refusal_nonce: [u8; 32],
    /// Closed code (1-10) of the authenticated worker refusal retained with `Rejected`; 0 in
    /// every other phase. Every retry answers it unchanged without live worker dependencies.
    worker_refusal: u16,
    /// The exchange whose reply `worker_result` is, present exactly with `worker_refusal`.
    worker_refusal_exchange: Option<WorkerRefusalExchange>,
}
impl Record {
    fn validate(&self) -> Result<()> {
        use EnrollmentJournalPhaseV1::*;
        self.selection.validate()?;
        if self.version != 1 || self.scope == [0; 32] {
            return Err(Invalid);
        }
        for original in [
            &self.request,
            &self.worker_request,
            &self.worker_result,
            &self.credential_body,
            &self.issued,
        ] {
            if original.len() > ORIGINAL_MAX {
                return Err(Invalid);
            }
        }
        let selected = self.phase == Selected;
        let verified = matches!(self.phase, Evidence | Rejected | Signing | Issued);
        let signing = matches!(self.phase, Signing | Issued);
        let evidence = matches!(self.phase, Evidence | Signing | Issued);
        if let Some(prepared) = &self.worker_preparation {
            prepared.validate()?;
        }
        if selected != self.request.is_empty()
            || selected != self.worker_request.is_empty()
            || verified == self.worker_result.is_empty()
            || signing == self.credential_body.is_empty()
            || (self.phase == Issued) == self.issued.is_empty()
            || (self.signing_dispatched && !signing)
            || ((self.refusal == 0) != (self.refusal_nonce == [0; 32]))
            || ((self.phase == Rejected) != (self.worker_refusal != 0))
            || ((self.worker_refusal != 0) != self.worker_refusal_exchange.is_some())
            || self.worker_refusal_exchange.is_some_and(|exchange| {
                exchange.action().is_err()
                    || exchange.exchange == [0; 32]
                    || exchange.dispatch_time_ms < self.verification_time_ms
            })
            || (self.worker_refusal != 0
                && iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::from_code(
                    self.worker_refusal,
                )
                .is_none_or(|refusal| refusal.is_eligibility()))
            || (self.refusal != 0
                && (self.signing_dispatched
                    || matches!(self.phase, Issued | Rejected)
                    || iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::from_code(
                        self.refusal,
                    )
                    .is_none_or(|refusal| !refusal.is_eligibility())))
            || (selected && self.verification_time_ms != 0)
            || selected != (self.worker_configuration == [0; 32])
            || (!evidence && self.worker_result_time_ms != 0)
            || (evidence
                && (self.worker_result_time_ms < self.verification_time_ms
                    || self.worker_result_time_ms >= self.selection.expires_at_ms))
            || (!selected
                && self.worker_preparation.as_ref().is_none_or(|prepared| {
                    prepared.ready.is_none() || prepared.configuration != self.worker_configuration
                }))
            || (!selected
                && (self.verification_time_ms < self.selection.created_at_ms
                    || self.verification_time_ms >= self.selection.expires_at_ms))
        {
            return Err(Invalid);
        }
        eligibility::validate_index(self)
    }
}

/// A private journal cursor bound to the exact observed original. It is not a worker capability.
pub struct EnrollmentAttemptV1 {
    record: Record,
    original: Vec<u8>,
}
impl EnrollmentAttemptV1 {
    /// Immutable selected E1 and deadline.
    pub fn selection(&self) -> &EnrollmentSelectionV1 {
        &self.record.selection
    }
    /// Durable phase; an observed `Verifying` permits only recovery of its original E5.
    pub fn phase(&self) -> EnrollmentJournalPhaseV1 {
        self.record.phase
    }
    /// Exact selected E5, private worker request and genuine verification timestamp.
    pub fn verification(&self) -> Option<(&[u8], &[u8], u64)> {
        (self.record.phase != EnrollmentJournalPhaseV1::Selected).then_some((
            self.record.request.as_slice(),
            self.record.worker_request.as_slice(),
            self.record.verification_time_ms,
        ))
    }
    /// Exact authenticated worker configuration selected with the original Complete request.
    /// Recovery cannot replace this pin with a newer or differently configured worker.
    pub fn worker_configuration(&self) -> Option<[u8; 32]> {
        (self.record.phase != EnrollmentJournalPhaseV1::Selected)
            .then_some(self.record.worker_configuration)
    }
    /// Exact retained worker result, including rejection; the phase determines its meaning.
    pub fn worker_result(&self) -> Option<&[u8]> {
        (!self.record.worker_result.is_empty()).then_some(self.record.worker_result.as_slice())
    }
    /// Terminal eligibility refusal retained before any credential could exist. Every later
    /// operation on the attempt returns it unchanged; a new attempt is required.
    pub fn refusal(
        &self,
    ) -> Option<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1> {
        iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::from_code(
            self.record.refusal,
        )
    }
    /// Closed reason of the retained worker refusal (`Rejected`); retries return it unchanged.
    pub fn worker_refusal(
        &self,
    ) -> Option<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1> {
        iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::from_code(
            self.record.worker_refusal,
        )
    }
    /// Whether no credential exists or may exist for the attempt: not issued and the signer was
    /// never invoked. Only then can an eligibility denial be terminal.
    pub fn pre_issuance(&self) -> bool {
        self.record.phase != EnrollmentJournalPhaseV1::Issued && !self.record.signing_dispatched
    }
    /// Exact signed E6 original after durable issuance. Never regenerate it on retry.
    pub fn issued(&self) -> Option<&[u8]> {
        (self.record.phase == EnrollmentJournalPhaseV1::Issued)
            .then_some(self.record.issued.as_slice())
    }
}

/// A one-use dispatch decision returned only by the successful durable transition itself.
/// Holding it proves ordering only; the service must additionally hold its authenticated worker.
pub struct EnrollmentVerificationDispatchV1 {
    request: Vec<u8>,
}
impl EnrollmentVerificationDispatchV1 {
    /// Consume the decision into the exact original private verifier request.
    pub fn into_original(self) -> Vec<u8> {
        self.request
    }
}

/// The sole local journal owner. Its lock is held until drop and rechecked around every access.
/// A privileged rollback of the complete filesystem is outside this local custody primitive;
/// permanent ledger activation claims must remain independently enforced by the service.
pub struct EnrollmentJournalV1 {
    directory: PrivateDirectory,
    lock: File,
    lock_identity: FileIdentity,
    scope_frame: Vec<u8>,
    scope: [u8; 32],
    uncertain: bool,
    /// Digests of the exact bytes this owner published or durably adopted, by name (bounded:
    /// an evicted entry is simply adopted again on its next read). A record read back after a
    /// restart may be visible without being durable (a crash before its directory sync); it is
    /// republished on a fresh inode before any outcome it holds is exposed.
    adopted: std::sync::Mutex<std::collections::BTreeMap<String, [u8; 32]>>,
}
/// Bound of the adoption memo; reaching it clears the memo.
const ADOPTED_MAX: usize = 4_096;
fn adopted_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:issuer-journal-adopted:v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn remember_adopted(
    adopted: &mut std::collections::BTreeMap<String, [u8; 32]>,
    name: &str,
    bytes: &[u8],
) {
    if adopted.len() >= ADOPTED_MAX && !adopted.contains_key(name) {
        adopted.clear();
    }
    adopted.insert(name.to_owned(), adopted_digest(bytes));
}
/// Deterministic test injection around the journal's actual publication and adoption steps;
/// ordering tests only, not a physical power-loss qualification.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;
    thread_local! {
        /// The next publication stages, syncs and renames its record into place but never
        /// synchronizes the parent directory, then reports the uncertainty.
        pub(crate) static UNCERTAIN_AFTER_RENAME: Cell<bool> = const { Cell::new(false) };
        /// Every adoption fails before republication while set.
        pub(crate) static ADOPTION_FAILS: Cell<bool> = const { Cell::new(false) };
    }
    /// Stage, sync and rename `bytes` over `name` without synchronizing the parent directory
    /// (the window a crash or lost writeback leaves visible but not durable), then report it.
    #[cfg(unix)]
    pub(super) fn rename_without_parent_sync(
        directory: &iroha_fs::PrivateDirectory,
        name: &str,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
        let staged = directory.path().join(format!(".injected-{name}"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&staged, directory.path().join(name))?;
        Err(std::io::Error::other("injected parent sync uncertainty"))
    }
}
fn scope_digest(original: &[u8]) -> Result<[u8; 32]> {
    if original.is_empty() || original.len() > SCOPE_MAX {
        return Err(Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:issuer-journal-scope:v1\0");
    hash.update((original.len() as u64).to_le_bytes());
    hash.update(original);
    Ok(hash.finalize().into())
}
fn encode(record: &Record) -> Result<Vec<u8>> {
    record.validate()?;
    let bytes = norito::encode_canonical(record).map_err(|_| Invalid)?;
    if bytes.len() > RECORD_MAX {
        return Err(Invalid);
    }
    Ok(bytes)
}
fn filename(key: &[u8; 32]) -> Result<String> {
    if *key == [0; 32] {
        return Err(Invalid);
    }
    Ok(format!("{}.norito", hex::encode(key)))
}
impl EnrollmentJournalV1 {
    /// Derive the permanent retry index from the independently authenticated account digest
    /// and native request identity within this installed issuer scope. Changing a client nonce
    /// cannot create a second selection under the same retry identity.
    /// # Errors
    /// Refuses zero identities or unavailable current journal custody.
    pub fn request_key(&self, account: &[u8; 32], request: &[u8; 32]) -> Result<[u8; 32]> {
        self.require_custody()?;
        if *account == [0; 32] || *request == [0; 32] {
            return Err(Invalid);
        }
        let mut hash = Sha256::new();
        hash.update(b"iroha:kagemusha:issuer-journal-request:v1\0");
        hash.update(self.scope);
        hash.update(account);
        hash.update(request);
        Ok(hash.finalize().into())
    }
    /// Explicitly initialize a fresh child below an already admitted private directory.
    /// Existing children, including incomplete initialization, are never overwritten.
    /// # Errors
    /// Refuses existing or unsafe custody, invalid scope and incomplete durability.
    pub fn initialize(
        parent: &PrivateDirectory,
        name: &str,
        scope_original: &[u8],
    ) -> Result<Self> {
        let scope_frame = scope_frame(scope_original)?;
        let directory = parent.create_child(name).map_err(|_| Unavailable)?;
        let lock = directory.create_lock(LOCK).map_err(|_| Unavailable)?;
        lock.try_lock().map_err(|_| Unavailable)?;
        lock.sync_all().map_err(|_| Unavailable)?;
        directory
            .write_atomic(SCOPE, &scope_frame, PublishMode::CreateNew)
            .map_err(|_| Uncertain)?;
        Self::from_locked(directory, lock, scope_original)
    }
    /// Open an existing initialized journal. Missing scope, directory or lock fails closed.
    /// # Errors
    /// Refuses a competing owner, substituted scope, corrupt custody or unavailable I/O.
    pub fn open(path: &Path, scope_original: &[u8]) -> Result<Self> {
        scope_digest(scope_original)?;
        let directory = PrivateDirectory::open(path).map_err(|_| Unavailable)?;
        let lock = directory
            .open_existing_lock(LOCK)
            .map_err(|_| Unavailable)?;
        lock.try_lock().map_err(|_| Unavailable)?;
        Self::from_locked(directory, lock, scope_original)
    }
    fn from_locked(directory: PrivateDirectory, lock: File, scope_original: &[u8]) -> Result<Self> {
        let value = Self {
            lock_identity: FileIdentity::of(&lock).map_err(|_| Unavailable)?,
            directory,
            lock,
            scope_frame: scope_frame(scope_original)?,
            scope: scope_digest(scope_original)?,
            uncertain: false,
            adopted: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        };
        value.require_custody()?;
        Ok(value)
    }
    fn require_custody(&self) -> Result<()> {
        if self.uncertain {
            return Err(Uncertain);
        }
        self.directory.revalidate().map_err(|_| Unavailable)?;
        FileSnapshot::private_journal(&self.lock).map_err(|_| Unavailable)?;
        if FileIdentity::of(&self.lock).map_err(|_| Unavailable)? != self.lock_identity {
            return Err(Unavailable);
        }
        self.directory
            .read_scope(|scope| -> io::Result<()> {
                scope.require_same_file(LOCK, &self.lock, || {
                    io::Error::other("journal lock changed")
                })?;
                scope.read(SCOPE, SCOPE_FRAME_MAX, |bytes| {
                    if bytes == self.scope_frame {
                        Ok(())
                    } else {
                        Err(io::Error::other("journal scope changed"))
                    }
                })?
            })
            .map_err(|_| Unavailable)
    }
    /// Read the exact current attempt. Only a genuine missing name returns `None`.
    /// # Errors
    /// Refuses corrupt frames, changed scope, unsafe custody and all other read failures.
    pub fn read(&self, key: &[u8; 32]) -> Result<Option<EnrollmentAttemptV1>> {
        self.require_custody()?;
        let read = self.directory.read_optional(filename(key)?, RECORD_MAX);
        self.require_custody()?;
        let original = match read {
            Ok(Some(bytes)) => bytes.to_vec(),
            Ok(None) => return Ok(None),
            Err(_) => return Err(Unavailable),
        };
        let record: Record = norito::decode_canonical_with_limits(
            &original,
            norito::canonical_decode_limits(RECORD_MAX),
        )
        .map_err(|_| Invalid)?;
        record.validate()?;
        if record.scope != self.scope || record.selection.key != *key {
            return Err(Invalid);
        }
        self.adopt(&filename(key)?, &original)?;
        Ok(Some(EnrollmentAttemptV1 { record, original }))
    }
    /// Durably adopt the exact visible bytes of `name` before exposing anything they hold:
    /// republished on a fresh inode with file and directory synchronization, once per owner.
    /// An unknown adoption stays an error; nothing is exposed and the next read retries.
    fn adopt(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut adopted = self.adopted.lock().map_err(|_| Unavailable)?;
        if adopted
            .get(name)
            .is_some_and(|known| *known == adopted_digest(bytes))
        {
            return Ok(());
        }
        #[cfg(test)]
        if fault::ADOPTION_FAILS.with(std::cell::Cell::get) {
            return Err(Uncertain);
        }
        self.directory
            .write_atomic(name, bytes, PublishMode::Replace)
            .map_err(|_| Uncertain)?;
        self.require_custody()?;
        match self.directory.read_optional(name, bytes.len()) {
            Ok(Some(current)) if current.as_slice() == bytes => {}
            _ => return Err(Uncertain),
        }
        remember_adopted(&mut adopted, name, bytes);
        Ok(())
    }
    /// Permanently select one E1. Exact retries recover it; changed selections conflict.
    /// # Errors
    /// Refuses invalid originals, a prior different selection, or uncertain publication.
    pub fn select(&mut self, selection: EnrollmentSelectionV1) -> Result<EnrollmentAttemptV1> {
        selection.validate()?;
        if let Some(prior) = self.read(&selection.key)? {
            return if prior.record.selection == selection {
                Ok(prior)
            } else {
                Err(Conflict)
            };
        }
        let record = Record {
            version: 1,
            scope: self.scope,
            selection,
            phase: EnrollmentJournalPhaseV1::Selected,
            verification_time_ms: 0,
            worker_configuration: [0; 32],
            worker_preparation: None,
            request: Vec::new(),
            worker_request: Vec::new(),
            worker_result: Vec::new(),
            worker_result_time_ms: 0,
            credential_body: Vec::new(),
            issued: Vec::new(),
            eligibility: Vec::new(),
            signing_dispatched: false,
            refusal: 0,
            refusal_nonce: [0; 32],
            worker_refusal: 0,
            worker_refusal_exchange: None,
        };
        let original = encode(&record)?;
        self.publish(
            &filename(&record.selection.key)?,
            &original,
            PublishMode::CreateNew,
        )?;
        Ok(EnrollmentAttemptV1 { record, original })
    }
    fn require_current(&self, attempt: &EnrollmentAttemptV1) -> Result<()> {
        let current = self.read(&attempt.record.selection.key)?.ok_or(Conflict)?;
        if current.original != attempt.original {
            return Err(Conflict);
        }
        Ok(())
    }
    fn publish(&mut self, name: &str, bytes: &[u8], mode: PublishMode) -> Result<()> {
        self.publish_with(name, bytes, mode, |directory, name, bytes, mode| {
            #[cfg(all(test, unix))]
            if fault::UNCERTAIN_AFTER_RENAME.with(|armed| armed.replace(false)) {
                return fault::rename_without_parent_sync(directory, name, bytes);
            }
            directory.write_atomic(name, bytes, mode)
        })
    }
    /// The authoritative current version of `attempt`: its retained terminal eligibility
    /// refusal, if any, or for a stale cursor its retained worker refusal. Any other cursor older
    /// than the current record is stale.
    /// # Errors
    /// `Conflict` for a stale or missing record; unavailable or uncertain custody.
    pub fn current_refusal(
        &self,
        attempt: &EnrollmentAttemptV1,
    ) -> Result<Option<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1>> {
        let current = self.read(&attempt.record.selection.key)?.ok_or(Conflict)?;
        if let Some(refusal) = current.refusal() {
            return Ok(Some(refusal));
        }
        if current.original != attempt.original {
            // A stale cursor of a rejected attempt answers its verified retained worker refusal;
            // the current cursor lets the operation first check its exact retained E5.
            return self
                .verified_worker_refusal(&current)?
                .map(Some)
                .ok_or(Conflict);
        }
        Ok(None)
    }
    fn publish_with(
        &mut self,
        name: &str,
        bytes: &[u8],
        mode: PublishMode,
        publish: impl FnOnce(&PrivateDirectory, &str, &[u8], PublishMode) -> io::Result<()>,
    ) -> Result<()> {
        self.require_custody()?;
        // Even a failure reported after rename cannot be treated as absence. Poison before
        // the attempt, clear only after successful file + parent durability and custody checks.
        self.uncertain = true;
        publish(&self.directory, name, bytes, mode).map_err(|_| Uncertain)?;
        self.uncertain = false;
        if self.require_custody().is_err() {
            self.uncertain = true;
            return Err(Uncertain);
        }
        remember_adopted(
            &mut *self.adopted.lock().map_err(|_| Unavailable)?,
            name,
            bytes,
        );
        Ok(())
    }
    fn advance(&mut self, attempt: &mut EnrollmentAttemptV1, record: Record) -> Result<()> {
        self.require_current(attempt)?;
        // A terminal eligibility refusal admits no further transition.
        if attempt.record.refusal != 0 {
            return Err(Conflict);
        }
        let original = encode(&record)?;
        self.publish(
            &filename(&record.selection.key)?,
            &original,
            PublishMode::Replace,
        )?;
        attempt.record = record;
        attempt.original = original;
        Ok(())
    }
    /// Validate exact account-signed E5 and build its private worker original from the retained
    /// issuer creation time, before the sole new Complete dispatch. A reread attempt in any later
    /// phase cannot call this successfully, even with identical bytes. The service independently
    /// authenticates the worker configuration pin and rechecks current account eligibility.
    /// # Errors
    /// Refuses stale cursors, consumed attempts, forged or differently scoped requests, a changed
    /// original deadline, invalid worker configuration or non-live trusted verification time.
    pub fn select_verification(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        request: iroha_core_zk::kagemusha_wallet_enrollment_v1::RequestV1,
        configuration: [u8; 32],
        verification_time_ms: u64,
    ) -> Result<EnrollmentVerificationDispatchV1> {
        use iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::VerifierRequestV1;
        if configuration == [0; 32] {
            return Err(Invalid);
        }
        if request.body.challenge != attempt.selection().challenge
            || attempt
                .selection()
                .created_at_ms
                .checked_add(request.body.policy.challenge_lifetime_ms)
                != Some(attempt.selection().expires_at_ms)
        {
            return Err(Conflict);
        }
        let original = request.encode().map_err(|_| Invalid)?;
        let preparation = self.require_worker_prepared(attempt, configuration)?;
        let worker = VerifierRequestV1::from_prepared(request, &preparation, verification_time_ms)
            .map_err(|_| Invalid)?;
        self.select_verification_bound(
            attempt,
            original,
            worker.original().to_vec(),
            verification_time_ms,
            configuration,
        )
    }
    fn select_verification_bound(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        request: Vec<u8>,
        worker_request: Vec<u8>,
        verification_time_ms: u64,
        configuration: [u8; 32],
    ) -> Result<EnrollmentVerificationDispatchV1> {
        if attempt.phase() != EnrollmentJournalPhaseV1::Selected {
            return Err(Conflict);
        }
        let mut record = attempt.record.clone();
        record.phase = EnrollmentJournalPhaseV1::Verifying;
        record.request = request;
        record.worker_request = worker_request;
        record.verification_time_ms = verification_time_ms;
        record.worker_configuration = configuration;
        self.advance(attempt, record)?;
        Ok(EnrollmentVerificationDispatchV1 {
            request: attempt.record.worker_request.clone(),
        })
    }
    /// Retain the exact authenticated worker result before any signing. Unavailable/unknown
    /// results must leave `Verifying` unchanged and may only recover the original request.
    /// # Errors
    /// Refuses changed results, terminal phases, stale cursors or failed durability.
    fn retain_worker_result(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        original: Vec<u8>,
        refusal: Option<(
            iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1,
            WorkerRefusalExchange,
        )>,
        evidence_time_ms: u64,
    ) -> Result<()> {
        use EnrollmentJournalPhaseV1::*;
        let rejected = refusal.is_some();
        let phase = if rejected { Rejected } else { Evidence };
        if attempt.phase() == phase || (!rejected && matches!(attempt.phase(), Signing | Issued)) {
            self.require_current(attempt)?;
            return if attempt.record.worker_result == original
                && attempt.record.worker_result_time_ms == evidence_time_ms
                && attempt.worker_refusal() == refusal.map(|(reason, _)| reason)
                && attempt.record.worker_refusal_exchange == refusal.map(|(_, exchange)| exchange)
            {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        if attempt.phase() != Verifying {
            return Err(Conflict);
        }
        let mut record = attempt.record.clone();
        record.phase = phase;
        record.worker_result = original;
        record.worker_result_time_ms = evidence_time_ms;
        record.worker_refusal = refusal.map_or(0, |(reason, _)| reason.code());
        record.worker_refusal_exchange = refusal.map(|(_, exchange)| exchange);
        self.advance(attempt, record)
    }
    /// Retain an independently checked actual signed E6 before returning any bytes to a client.
    /// This primitive never signs or treats an arbitrary original as a valid credential.
    /// # Errors
    /// Refuses a different retry, absence of retained evidence, stale cursors or storage failure.
    fn retain_issued(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        original: Vec<u8>,
    ) -> Result<()> {
        use EnrollmentJournalPhaseV1::*;
        if attempt.phase() == Issued {
            self.require_current(attempt)?;
            return if attempt.record.issued == original {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        if attempt.phase() != Signing {
            return Err(Conflict);
        }
        let mut record = attempt.record.clone();
        record.phase = Issued;
        record.issued = original;
        self.advance(attempt, record)
    }
}

/// One retained worker-refusal binding replaced by a test.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) enum WorkerRefusalTamperForTests {
    /// Cache another closed code.
    Code(u16),
    /// Replace the exact retained reply frame.
    Reply(Vec<u8>),
    /// Replace the retained exchange identifier.
    Exchange([u8; 32]),
    /// Replace the retained exchange dispatch time.
    DispatchTime(u64),
    /// Replace the retained exchange action tag.
    Action(u8),
}

/// Test-only tampering of retained custody, used by issuer regressions that must observe a
/// canonical record whose cached worker refusal no longer matches its retained original.
#[cfg(test)]
impl EnrollmentJournalV1 {
    /// Republish the record of `attempt` with one retained worker-refusal binding replaced.
    pub(crate) fn tamper_worker_refusal_for_tests(
        &mut self,
        attempt: &EnrollmentAttemptV1,
        tamper: WorkerRefusalTamperForTests,
    ) -> Result<()> {
        let mut record = attempt.record.clone();
        let exchange = record.worker_refusal_exchange.as_mut().ok_or(Invalid)?;
        match tamper {
            WorkerRefusalTamperForTests::Code(code) => record.worker_refusal = code,
            WorkerRefusalTamperForTests::Reply(reply) => record.worker_result = reply,
            WorkerRefusalTamperForTests::Exchange(id) => exchange.exchange = id,
            WorkerRefusalTamperForTests::DispatchTime(time) => exchange.dispatch_time_ms = time,
            WorkerRefusalTamperForTests::Action(action) => exchange.action = action,
        }
        let name = filename(&record.selection.key)?;
        self.publish(&name, &encode(&record)?, PublishMode::Replace)
    }

    /// Republish the exact original bytes of `attempt`.
    pub(crate) fn restore_for_tests(&mut self, attempt: &EnrollmentAttemptV1) -> Result<()> {
        let name = filename(&attempt.record.selection.key)?;
        self.publish(&name, &attempt.original, PublishMode::Replace)
    }
}

mod eligibility;
mod permits;
mod preparation;
mod worker;

#[cfg(test)]
#[path = "enrollment_journal/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "enrollment_journal/permit_tests.rs"]
pub(super) mod permit_tests;

#[cfg(test)]
#[path = "enrollment_journal/worker_tests.rs"]
mod worker_tests;
