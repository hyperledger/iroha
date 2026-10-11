//! Descriptor-anchored immutable operation evidence for native purpose owners.
//!
//! This crate owns bounded canonical JSON records, atomic original publication, retained native
//! directory and lock custody, and immutable pre-dispatch and applied-evidence markers. Wallet,
//! service and daemon callers own request validation, permissions, fees, finality and signing.
//! A stored record or successful local marker grants none of that authority.
//!
//! Native preparation publishes `preparation.json` and the lock atomically, retains exact
//! `payload.json` before signing and `operation.json` before dispatch. Prepared onboarding and
//! session owners publish their complete original with [`Journal::create_prepared`]. Purpose
//! owners retain `submission.json` before their sole dispatch and exact `applied.json` evidence
//! afterward. Request-only retirement appends `retired.json` under the original lock and never
//! removes or renews evidence. Private staging siblings are never authority selectors.
//!
//! Every record is immutable, with one canonical first-release layout and the existing fixed
//! submission-intent schema. Retained descriptors bind the owner-private directory and original
//! exclusive lock; changed ancestry, links, access, identities and record bytes are refused.
use eyre::{Result, WrapErr as _, eyre};
use iroha_fs::{FileIdentity, OwnerDirectory, PrivateDirectory, PrivateReadScope, PublishMode};
use norito::json::{self, JsonDeserialize, JsonSerialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// Maximum canonical byte length of each retained native journal record.
pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const APPLIED_EVIDENCE: &str = "applied.json";

/// Fixed native preparation stages; arbitrary journal names cannot enter this interface.
#[derive(Clone, Copy)]
pub enum NativeRecord {
    /// Original finite request, retained before quotation or signing.
    Request,
    /// Exact quoted unsigned payload, retained before signing.
    Payload,
    /// Exact signed operation, retained before exposure.
    Operation,
    /// Explicit retirement of a request without any payload or exposure.
    Retired,
}
impl NativeRecord {
    const fn name(self) -> &'static str {
        match self {
            Self::Request => "preparation.json",
            Self::Payload => "payload.json",
            Self::Operation => "operation.json",
            Self::Retired => "retired.json",
        }
    }
}

/// Count and charge the exact canonical JSON output before allocating it.
/// This storage encoding grants no request, signing or dispatch authority.
///
/// # Errors
/// Refuses output above the original four-MiB ceiling or inherited allocation budget.
pub fn canonical_bytes<T: JsonSerialize + ?Sized>(value: &T) -> Result<Box<[u8]>> {
    norito::json::to_json_bounded_boxed(value, MAX_JOURNAL_BYTES)
        .map_err(|error| eyre!("bounded journal encoding: {error:?}"))
}

// One pure native-record decode/canonical policy, after the caller's per-record exit custody.
fn decode_native<T: JsonDeserialize + JsonSerialize>(bytes: &[u8]) -> Result<T> {
    let value = json::from_slice(bytes).wrap_err("invalid native preparation evidence")?;
    eyre::ensure!(
        canonical_bytes(&value)?.as_ref() == bytes,
        "noncanonical native preparation evidence"
    );
    Ok(value)
}

/// Retained private operation directory and its exclusive native process lock.
pub struct Journal {
    path: PathBuf,
    directory: PrivateDirectory,
    lock: File,
}

/// Borrowed fixed-record reader inside one closed original journal inspection.
///
/// No descriptor, path, writer or custody verdict is exposed. Each record retains entry/middle/exit
/// original-lock checks before decoding. This view cannot leave [`Journal::read_native_scope`].
pub struct NativeJournalReadScope<'read, 'scope> {
    journal: &'read Journal,
    reader: &'read mut PrivateReadScope<'scope>,
}

impl core::fmt::Debug for NativeJournalReadScope<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeJournalReadScope")
            .finish_non_exhaustive()
    }
}

impl NativeJournalReadScope<'_, '_> {
    fn read_optional(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let journal = self.journal;
        journal.with_read_custody_in_scope(self.reader, |reader| {
            Self::read_optional_body(journal, reader, name)
        })
    }

    fn read_optional_body(
        journal: &Journal,
        reader: &mut PrivateReadScope<'_>,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        reader.read_admitted(
            name,
            MAX_JOURNAL_BYTES,
            (
                |extent| {
                    let length = usize::try_from(extent)?;
                    eyre::ensure!(
                        length <= MAX_JOURNAL_BYTES,
                        "journal evidence exceeds its byte bound"
                    );
                    Ok(length)
                },
                |length| {
                    norito::core::reserve_decode_allocation(length)?;
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(length)?;
                    bytes.resize(length, 0);
                    Ok(bytes)
                },
            ),
            |reader| journal.revalidate_lock_in_scope(reader),
            (
                |error| eyre::Report::new(error).wrap_err("cannot open private journal evidence"),
                |namespace| {
                    eyre!(if namespace {
                        "journal evidence namespace changed"
                    } else {
                        "journal evidence changed during read"
                    })
                },
            ),
        )
    }

    /// Read one fixed canonical record after its ordinary-result original-lock exit.
    /// # Errors
    /// Preserves unsafe native custody, allocation refusal, malformed and noncanonical evidence.
    pub fn read_native<T: JsonDeserialize + JsonSerialize>(
        &mut self,
        record: NativeRecord,
    ) -> Result<Option<T>> {
        let Some(bytes) = self.read_optional(record.name())? else {
            return Ok(None);
        };
        decode_native(&bytes).map(Some)
    }

    /// Observe exposure markers lazily without granting their bytes meaning.
    /// # Errors
    /// Refuses unsafe custody and malformed or excessive native evidence extents.
    pub fn has_dispatch_evidence(&mut self) -> Result<bool> {
        Ok(self.read_optional("submission.json")?.is_some()
            || self.read_optional(APPLIED_EVIDENCE)?.is_some())
    }

    /// Recheck the exact original pre-dispatch marker independently at this read boundary.
    /// # Errors
    /// Preserves encoding limits and refuses a marker for different original bytes.
    pub fn submission_recorded<T: JsonSerialize>(&mut self, operation: &T) -> Result<bool> {
        let bytes = Journal::submission_bytes(operation)?;
        match self.read_optional("submission.json")? {
            Some(existing) if existing == bytes => Ok(true),
            Some(_) => eyre::bail!("submission marker differs from the exact retained operation"),
            None => Ok(false),
        }
    }
}

impl core::fmt::Debug for Journal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Journal")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Journal {
    /// Canonical absolute path of the pinned journal directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reserve an unprepared journal and hold its exclusive lock.
    /// Callers using this reservation API must explicitly recover a provably unprepared journal
    /// after interruption. When the operation already exists, use [`Self::create_prepared`].
    ///
    /// # Errors
    /// Refuses missing or unsafe parents, existing directories, and native custody failures.
    pub fn create(path: &Path) -> Result<Self> {
        Self::acquire(path, true)
    }

    /// Atomically publish the complete original operation and lock, then acquire the journal.
    /// No partial journal can appear at `path` between directory creation and retaining the signed
    /// bytes. An uncertain publication is reconciled by reopening this same path, never preparing
    /// or submitting a replacement transaction. Existing evidence is never overwritten.
    ///
    /// # Errors
    /// Invalid/oversized operation, unsafe or missing parent, existing destination, competing owner,
    /// or native publication failure. Private staging siblings can remain after interruption.
    pub fn create_prepared<T: JsonSerialize>(path: &Path, operation: &T) -> Result<Self> {
        Self::publish_initial(path, "operation.json", operation, None)
    }

    /// Publish the sole native request before any quote, payload or local signature.
    /// This is durable custody only; the purpose owner validates and signs the request.
    ///
    /// # Errors
    /// Refuses oversized encoding, unsafe parents, existing custody, or native publication failure.
    pub fn create_preparation<T: JsonSerialize>(path: &Path, request: &T) -> Result<Self> {
        Self::publish_initial(path, "preparation.json", request, None)
    }

    /// Publish a purpose owner's required bounded custody anchor with the original atomically.
    /// The purpose owner validates the anchor's codec and semantics and authorizes initialization.
    /// Successful publication grants only local durable custody, not purpose or chain authority.
    ///
    /// # Errors
    /// Refuses empty/oversized anchors, invalid/oversized operation encoding, unsafe or missing
    /// parents, existing destinations, competing owners, or native publication failure.
    pub fn create_prepared_with_custody_anchor<T: JsonSerialize>(
        path: &Path,
        operation: &T,
        anchor: &[u8],
    ) -> Result<Self> {
        eyre::ensure!(
            !anchor.is_empty() && anchor.len() <= MAX_JOURNAL_BYTES,
            "custody anchor exceeds its byte bound"
        );
        Self::publish_initial(path, "operation.json", operation, Some(anchor))
    }

    fn publish_initial<T: JsonSerialize>(
        path: &Path,
        record: &str,
        value: &T,
        anchor: Option<&[u8]>,
    ) -> Result<Self> {
        let bytes = canonical_bytes(value)?;
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let name = absolute
            .file_name()
            .ok_or_else(|| eyre!("journal must name a directory"))?;
        let parent = OwnerDirectory::open(
            absolute
                .parent()
                .ok_or_else(|| eyre!("journal has no parent"))?,
        )?;
        let directory = match anchor {
            Some(anchor) => parent.publish_private_child(
                name,
                &[
                    ("lock", &[]),
                    (record, &bytes),
                    ("custody-anchor.nrt", anchor),
                ],
            )?,
            None => parent.publish_private_child(name, &[("lock", &[]), (record, &bytes)])?,
        };
        Self::lock_directory(directory, false)
    }

    /// Distinguish only a missing canonical name under its retained safe parent.
    /// Malformed or incomplete custody is an error; absence grants no preparation authority.
    ///
    /// # Errors
    /// Refuses unsafe or missing parents, invalid existing custody and native observation errors.
    pub fn open_optional(path: &Path) -> Result<Option<Self>> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let name = absolute
            .file_name()
            .ok_or_else(|| eyre!("journal must name a directory"))?;
        let parent = OwnerDirectory::open(
            absolute
                .parent()
                .ok_or_else(|| eyre!("journal has no parent"))?,
        )?;
        Self::open_optional_in_parent(&parent, name)
    }

    /// Open an optional journal child through its original retained private parent.
    ///
    /// The child shares every held ancestor descriptor without reopening an absolute path.
    /// Native child admission, the exclusive original lock and sync remain fresh. Only initial
    /// child absence returns `None`; a missing lock or later custody failure remains an error.
    /// Parent custody closes every ordinary result, including lock admission failures. The
    /// original parent and all of its ancestors remain held for the returned journal lifetime.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed custody, competing locks and native errors.
    pub fn open_optional_child(
        parent: &PrivateDirectory,
        name: impl AsRef<std::ffi::OsStr>,
    ) -> Result<Option<Self>> {
        Self::open_optional_with_parent(|| parent.open_child_optional(name), || parent.revalidate())
    }

    // The original parent remains held through the child lock/sync boundary and every exit.
    // A successful child shares its native ancestry; no second absolute owner is selected.
    fn open_optional_in_parent(
        parent: &OwnerDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<Option<Self>> {
        Self::open_optional_with_parent(
            || parent.open_private_child_optional(name),
            || parent.revalidate(),
        )
    }

    // One child/lock/exit recipe for both legitimate parent admission boundaries. Keep the
    // outcome live until the original parent exit, and release a successful lock on refusal.
    fn open_optional_with_parent(
        open_child: impl FnOnce() -> std::io::Result<Option<PrivateDirectory>>,
        check_parent: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<Option<Self>> {
        let outcome = match open_child() {
            Ok(Some(directory)) => Self::lock_directory(directory, false).map(Some),
            Ok(None) => Ok(None),
            Err(error) => Err(error.into()),
        };
        if let Err(error) = check_parent() {
            drop(outcome);
            return Err(error.into());
        }
        outcome
    }

    /// Require the complete request-only fixed namespace under the original held lock.
    /// Unknown or later-stage material is refused. The purpose owner must still authenticate the
    /// original request and decide whether its exact request may retire; this is storage shape only.
    ///
    /// # Errors
    /// Refuses changed custody, unknown or unsafe entries and excessive inventory size.
    pub fn require_request_only_inventory(&self) -> Result<()> {
        self.revalidate()?;
        self.directory.visit_private_files(3, |name, _| {
            if ["lock", "preparation.json", "retired.json"]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed))
            {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "request retirement refuses unknown or later-stage material",
                ))
            }
        })?;
        self.revalidate()
    }

    /// Read one fixed native preparation record with exact canonical encoding.
    /// Absence is a local file observation, never permission to sign or submit.
    ///
    /// # Errors
    /// Refuses changed custody, malformed or noncanonical evidence, and resource limits.
    pub fn read_native<T: JsonDeserialize + JsonSerialize>(
        &self,
        record: NativeRecord,
    ) -> Result<Option<T>> {
        let Some(bytes) = self.read_optional(record.name())? else {
            return Ok(None);
        };
        decode_native(&bytes).map(Some)
    }

    /// Inspect fixed native records in one read-only original-directory transaction.
    ///
    /// Every record retains fresh original-lock and native leaf admission and closes lock custody
    /// before decode. Whole Journal and directory ancestry bracket all ordinary callback results;
    /// exit refusal dominates body errors. Intermediate ancestry observations consolidate, so a
    /// completely restored transient change may be unobserved. This is neither an atomic snapshot
    /// nor an unwind guarantee. Keep callbacks free of writes, signing and network effects.
    ///
    /// # Errors
    /// Preserves record/decoder errors only after original lock and full ancestry exit succeeds.
    pub fn read_native_scope<T>(
        &self,
        read: impl for<'read, 'scope> FnOnce(&mut NativeJournalReadScope<'read, 'scope>) -> Result<T>,
    ) -> Result<T> {
        self.with_read_custody(|| {
            self.directory.read_scope(|reader| {
                read(&mut NativeJournalReadScope {
                    journal: self,
                    reader,
                })
            })
        })
    }

    fn revalidate_lock_in_scope(&self, reader: &PrivateReadScope<'_>) -> Result<()> {
        reader.require_same_file("lock", &self.lock, || {
            eyre!("journal lock no longer identifies the retained ownership file")
        })
    }

    fn with_read_custody_in_scope<'scope, T>(
        &self,
        reader: &mut PrivateReadScope<'scope>,
        read: impl FnOnce(&mut PrivateReadScope<'scope>) -> Result<T>,
    ) -> Result<T> {
        self.revalidate_lock_in_scope(reader)?;
        let result = read(reader);
        if let Err(error) = self.revalidate_lock_in_scope(reader) {
            drop(result);
            return Err(error);
        }
        result
    }

    /// Append one immutable fixed native preparation record.
    /// The purpose owner enforces stage ordering; this method grants no dispatch authority.
    ///
    /// # Errors
    /// Refuses an existing record, unsafe custody and unavailable durability or resources.
    /// Purpose owners reconcile identical retained bytes before calling this append method.
    pub fn write_native<T: JsonSerialize>(&self, record: NativeRecord, value: &T) -> Result<()> {
        self.install(record.name(), &canonical_bytes(value)?)
    }

    /// Audit the complete fixed native journal namespace under the held operation lock.
    /// Unknown files, directories and unsafe entries are never ignored as absent preparation.
    /// This verifies storage shape only; the purpose owner must validate every present record.
    ///
    /// # Errors
    /// Refuses changed custody, unexpected names, nonregular files or excessive entry count.
    pub fn verify_native_inventory(&self) -> Result<()> {
        self.revalidate()?;
        self.directory.visit_private_files(7, |name, _| {
            if [
                "lock",
                "preparation.json",
                "payload.json",
                "operation.json",
                "retired.json",
                "submission.json",
                APPLIED_EVIDENCE,
            ]
            .iter()
            .any(|allowed| name == std::ffi::OsStr::new(allowed))
            {
                Ok(())
            } else {
                Err(std::io::Error::other("unknown native journal evidence"))
            }
        })?;
        self.revalidate()
    }

    /// Whether either exposure or applied evidence exists, without granting meaning to its bytes.
    /// Purpose owners must verify that evidence against the exact signed original before use.
    ///
    /// # Errors
    /// Refuses changed custody and unsafe or oversized evidence.
    pub fn has_dispatch_evidence(&self) -> Result<bool> {
        Ok(self.read_optional("submission.json")?.is_some()
            || self.read_optional(APPLIED_EVIDENCE)?.is_some())
    }

    /// Reopen an existing journal and hold its exclusive lock.
    ///
    /// # Errors
    /// Refuses missing, unsafe or replaced directories and locks, and competing owners.
    pub fn open(path: &Path) -> Result<Self> {
        Self::acquire(path, false)
    }

    fn acquire(path: &Path, create: bool) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let name = absolute
            .file_name()
            .ok_or_else(|| eyre!("journal must name an operation directory"))?;
        let parent_path = absolute
            .parent()
            .ok_or_else(|| eyre!("journal has no parent directory"))?
            .canonicalize()
            .wrap_err("journal parent must already exist")?;
        let parent = OwnerDirectory::open(&parent_path)?;
        let directory = if create {
            parent.create_private_child(name).wrap_err(
                "journal must be a fresh directory; existing evidence is never replaced",
            )?
        } else {
            parent.open_private_child(name)?
        };
        Self::lock_directory(directory, create)
    }

    fn lock_directory(directory: PrivateDirectory, create: bool) -> Result<Self> {
        let lock = if create {
            directory.create_lock("lock")?
        } else {
            directory.open_existing_lock("lock")?
        };
        lock.try_lock()
            .wrap_err("another account operation holds this journal")?;
        directory.sync()?;
        let result = Self {
            path: directory.path().to_owned(),
            directory,
            lock,
        };
        result.revalidate()?;
        Ok(result)
    }

    /// Retain the exact canonical JSON of a prepared operation, once.
    ///
    /// # Errors
    /// Fails when an operation is already retained or the bytes exceed the bound.
    pub fn write_operation<T: JsonSerialize>(&self, operation: &T) -> Result<()> {
        self.install("operation.json", &canonical_bytes(operation)?)
    }

    /// Read the retained operation, requiring its exact canonical encoding.
    ///
    /// # Errors
    /// Fails when no operation was prepared or the retained bytes are not the
    /// canonical encoding of `T`.
    pub fn read_operation<T: JsonDeserialize + JsonSerialize>(&self) -> Result<T> {
        let bytes = self.read("operation.json")?;
        let operation: T =
            json::from_slice(&bytes).wrap_err("invalid closed account-operation journal")?;
        if canonical_bytes(&operation)?.as_ref() != bytes {
            eyre::bail!("operation journal must retain its exact canonical encoding");
        }
        Ok(operation)
    }

    fn submission_bytes<T: JsonSerialize>(operation: &T) -> Result<Vec<u8>> {
        Ok(json::to_vec(&norito::json!({
            "schema": "iroha.wallet.submission-intent.v1",
            "operation_sha256": (hex::encode(Sha256::digest(json::to_vec(operation)?)))
        }))?)
    }
    /// Whether the durable pre-dispatch marker for exactly `operation` exists.
    ///
    /// # Errors
    /// Fails when a marker exists for different operation bytes.
    pub fn submission_recorded<T: JsonSerialize>(&self, operation: &T) -> Result<bool> {
        let bytes = Self::submission_bytes(operation)?;
        match self.read_optional("submission.json")? {
            Some(existing) if existing == bytes => Ok(true),
            Some(_) => eyre::bail!("submission marker differs from the exact retained operation"),
            None => Ok(false),
        }
    }
    /// Durably record the pre-dispatch marker for `operation`.
    ///
    /// Returns `true` only for the call that created the original local marker. Its purpose
    /// owner may dispatch only after independent protocol and authority checks. `false` means
    /// an earlier attempt exists and the operation must be reconciled, never resubmitted.
    ///
    /// # Errors
    /// Fails when a marker exists for different bytes or cannot be installed.
    pub fn record_submission<T: JsonSerialize>(&self, operation: &T) -> Result<bool> {
        if self.submission_recorded(operation)? {
            return Ok(false);
        }
        self.install("submission.json", &Self::submission_bytes(operation)?)?;
        Ok(true)
    }

    /// Retain the exact committed evidence (`applied.json`); an identical
    /// rewrite is accepted, different bytes are rejected.
    ///
    /// # Errors
    /// Fails when different evidence is retained or the bytes exceed the bound.
    pub fn write_applied_evidence<T: JsonSerialize>(&self, evidence: &T) -> Result<()> {
        let bytes = json::to_vec(evidence)?;
        match self.read_optional(APPLIED_EVIDENCE)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => eyre::bail!("retained wallet evidence differs from the exact operation"),
            None => self.install(APPLIED_EVIDENCE, &bytes),
        }
    }

    fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        let current = self.directory.open_read("lock")?;
        if FileIdentity::of(&current)? != FileIdentity::of(&self.lock)? {
            eyre::bail!("journal lock no longer identifies the retained ownership file");
        }
        Ok(())
    }

    fn read_optional(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.with_read_custody(|| self.read_optional_body(name))
    }

    // Every ordinary result retains the same journal and original lock through exit custody.
    // Exit refusal takes precedence over absence, a body error, or completed evidence bytes.
    // This is a Result boundary; it does not promise a custody check during unwinding.
    fn with_read_custody<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.revalidate()?;
        let result = read();
        if let Err(error) = self.revalidate() {
            drop(result);
            return Err(error);
        }
        result
    }

    fn read_optional_body(&self, name: &str) -> Result<Option<Vec<u8>>> {
        // Standalone and batch reads share first-open-only absence and the same owned recipe.
        // This also consolidates standalone intermediate ancestry observations under this
        // entry/ordinary-result exit bracket; a completely restored transient may be unobserved.
        self.directory.read_scope(|reader| {
            NativeJournalReadScope {
                journal: self,
                reader,
            }
            .read_optional(name)
        })
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        self.read_optional(name)?.ok_or_else(|| {
            eyre!("journal has no completed preparation; no transaction can be submitted")
        })
    }

    fn install(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_JOURNAL_BYTES {
            eyre::bail!("operation evidence exceeds its bounded size");
        }
        self.revalidate()?;
        self.directory
            .write_atomic(name, bytes, PublishMode::CreateNew)
            .wrap_err("immutable journal evidence already exists or could not be installed")?;
        if self.read(name)? != bytes {
            eyre::bail!("saved operation evidence differs from its retained bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fixed_native_preparation_records_reopen_without_renewal_and_reject_unknown_inventory() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("native");
        let request = norito::json!({"deadline_ms": 17, "nonce": 9});
        let payload = norito::json!({"wire": "quoted-original"});
        let signed = norito::json!({"wire": "signed-original"});
        let journal = Journal::create_preparation(&path, &request).unwrap();
        journal.verify_native_inventory().unwrap();
        assert!(
            journal
                .read_native::<norito::json::Value>(NativeRecord::Payload)
                .unwrap()
                .is_none()
        );
        journal
            .write_native(NativeRecord::Payload, &payload)
            .unwrap();
        journal
            .write_native(NativeRecord::Operation, &signed)
            .unwrap();
        assert!(journal.record_submission(&signed).unwrap());
        drop(journal);
        let journal = Journal::open(&path).unwrap();
        journal.verify_native_inventory().unwrap();
        assert_eq!(
            journal
                .read_native::<norito::json::Value>(NativeRecord::Request)
                .unwrap(),
            Some(request)
        );
        assert_eq!(
            journal
                .read_native::<norito::json::Value>(NativeRecord::Payload)
                .unwrap(),
            Some(payload)
        );
        assert_eq!(
            journal
                .read_native::<norito::json::Value>(NativeRecord::Operation)
                .unwrap(),
            Some(signed.clone())
        );
        assert!(!journal.record_submission(&signed).unwrap());
        assert!(
            journal
                .write_native(
                    NativeRecord::Payload,
                    &norito::json!({"wire":"replacement"})
                )
                .is_err()
        );
        journal
            .directory
            .write_atomic("unknown", b"partial", PublishMode::CreateNew)
            .unwrap();
        assert!(journal.verify_native_inventory().is_err());
    }

    #[test]
    fn fixed_native_inventory_rejects_nested_directories_and_missing_original_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("native");
        let journal =
            Journal::create_preparation(&path, &norito::json!({"original":true})).unwrap();
        let unexpected = journal.directory.create_child("unexpected").unwrap();
        assert!(journal.verify_native_inventory().is_err());
        drop(unexpected);
        drop(journal);
        std::fs::remove_file(path.join("lock")).unwrap();
        assert!(Journal::open(&path).is_err());
        assert!(!path.join("lock").exists());
    }

    #[test]
    fn prepared_creation_atomically_retains_original_bytes_and_survives_reopen() {
        let root = tempfile::tempdir().unwrap();
        let parent = OwnerDirectory::open(root.path()).unwrap();
        let interrupted = parent.create_private_child("unpublished").unwrap();
        interrupted.create_lock("lock").unwrap().sync_all().unwrap();
        let path = root.path().join("operation");
        let operation = norito::json!({"signed": "original"});
        let journal = Journal::create_prepared(&path, &operation).unwrap();
        assert_eq!(
            journal.read_operation::<norito::json::Value>().unwrap(),
            operation
        );
        assert!(!journal.submission_recorded(&operation).unwrap());
        assert!(
            Journal::create_prepared(&path, &norito::json!({"signed": "replacement"})).is_err()
        );
        drop(journal);
        let journal = Journal::open(&path).unwrap();
        assert_eq!(
            journal.read_operation::<norito::json::Value>().unwrap(),
            operation
        );
        assert!(journal.record_submission(&operation).unwrap());
        assert!(!journal.record_submission(&operation).unwrap());
        let absent = root.path().join("too-large");
        assert!(Journal::create_prepared(&absent, &"x".repeat(MAX_JOURNAL_BYTES)).is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn journal_open_never_recreates_a_missing_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operation");
        drop(Journal::create(&path).unwrap());
        fs::remove_file(path.join("lock")).unwrap();
        assert!(Journal::open(&path).is_err());
        assert!(!path.join("lock").exists());
    }

    #[test]
    #[cfg(unix)]
    fn retained_journal_refuses_a_replaced_lock_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operation");
        let journal = Journal::create(&path).unwrap();
        fs::rename(path.join("lock"), path.join("old-lock")).unwrap();
        let replacement = journal.directory.create_lock("lock").unwrap();
        assert!(
            journal
                .write_operation(&norito::json!({"wire": "no"}))
                .is_err()
        );
        assert!(!path.join("operation.json").exists());
        drop(replacement);
    }

    #[test]
    fn journal_creation_is_exclusive_and_retained_writes_are_immutable() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operation");
        let journal = Journal::create(&path).unwrap();
        assert!(Journal::create(&path).is_err());
        assert!(Journal::open(&path).is_err());
        journal.install("evidence.json", b"one").unwrap();
        assert!(journal.install("evidence.json", b"two").is_err());
        assert_eq!(journal.read("evidence.json").unwrap(), b"one");
        assert!(journal.read_operation::<norito::json::Value>().is_err());
        drop(journal);
        assert!(Journal::open(&path).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn journal_rejects_links_broad_permissions_and_directory_replacement() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operation");
        let journal = Journal::create(&path).unwrap();
        journal.install("evidence.json", b"one").unwrap();
        symlink(path.join("evidence.json"), path.join("alias.json")).unwrap();
        assert!(journal.read("alias.json").is_err());
        fs::hard_link(path.join("evidence.json"), path.join("hardlink.json")).unwrap();
        assert!(journal.read("evidence.json").is_err());
        fs::remove_file(path.join("hardlink.json")).unwrap();
        fs::set_permissions(
            path.join("evidence.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(journal.read("evidence.json").is_err());
        fs::rename(&path, root.path().join("moved")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(journal.install("later.json", b"two").is_err());
        assert!(!path.join("later.json").exists());
    }

    #[test]
    fn public_protocol_records_one_operation_marker_and_exact_evidence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("canary");
        let journal = Journal::create(&path).unwrap();
        assert!(format!("{journal:?}").contains("canary"));
        let operation = norito::json!({"schema": "test.canary.v1", "wire": "00ff"});
        journal.write_operation(&operation).unwrap();
        assert!(
            journal.write_operation(&operation).is_err(),
            "operations are written once"
        );
        assert_eq!(
            journal.read_operation::<norito::json::Value>().unwrap(),
            operation
        );
        assert!(!journal.submission_recorded(&operation).unwrap());
        assert!(
            journal.record_submission(&operation).unwrap(),
            "first marker owns dispatch"
        );
        assert!(
            !journal.record_submission(&operation).unwrap(),
            "later calls never dispatch"
        );
        assert!(journal.submission_recorded(&operation).unwrap());
        let other = norito::json!({"schema": "test.canary.v1", "wire": "0100"});
        assert!(journal.submission_recorded(&other).is_err());
        let evidence = norito::json!({"height": 7});
        journal.write_applied_evidence(&evidence).unwrap();
        journal.write_applied_evidence(&evidence).unwrap();
        assert!(
            journal
                .write_applied_evidence(&norito::json!({"height": 8}))
                .is_err()
        );
        assert!(path.join(APPLIED_EVIDENCE).is_file());
        drop(journal);
        let reopened = Journal::open(&path).unwrap();
        assert_eq!(reopened.path(), path.canonicalize().unwrap());
        assert!(reopened.submission_recorded(&operation).unwrap());
    }

    #[test]
    fn journal_size_is_bounded_before_creation() {
        let root = tempfile::tempdir().unwrap();
        let journal = Journal::create(&root.path().join("operation")).unwrap();
        assert!(
            journal
                .install("large.json", &vec![0; MAX_JOURNAL_BYTES + 1])
                .is_err()
        );
        assert!(!journal.path().join("large.json").exists());
    }

    #[test]
    #[cfg(unix)]
    fn journal_rejects_a_special_file_substituted_for_its_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operation");
        drop(Journal::create(&path).unwrap());
        fs::remove_file(path.join("lock")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(path.join("lock")).unwrap();
        assert!(Journal::open(&path).is_err());
    }
}

#[cfg(test)]
mod custody_anchor_tests {
    use super::*;
    #[test]
    fn required_custody_anchor_is_published_with_exact_original_once() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("anchored");
        let original = norito::json!({"purpose":"bounded-anchor-owner"});
        assert!(Journal::create_prepared_with_custody_anchor(&path, &original, &[]).is_err());
        assert!(!path.exists());
        let journal =
            Journal::create_prepared_with_custody_anchor(&path, &original, b"exact opaque anchor")
                .unwrap();
        assert_eq!(
            journal.read_operation::<norito::json::Value>().unwrap(),
            original
        );
        assert_eq!(
            journal
                .directory
                .read("custody-anchor.nrt", 64)
                .unwrap()
                .as_slice(),
            b"exact opaque anchor"
        );
        assert!(
            Journal::create_prepared_with_custody_anchor(&path, &original, b"replacement").is_err()
        );
        assert_eq!(journal.directory.entries(3).unwrap().len(), 3);
        drop(journal);
        let reopened = Journal::open(&path).unwrap();
        assert_eq!(
            reopened
                .directory
                .read("custody-anchor.nrt", 64)
                .unwrap()
                .as_slice(),
            b"exact opaque anchor"
        );
    }
}

#[cfg(test)]
mod read_exit_tests;

#[cfg(test)]
mod native_scope_tests;

#[cfg(test)]
mod parent_admission_tests;

#[cfg(test)]
#[path = "borrowed_private_parent_tests.rs"]
mod borrowed_private_parent_tests;
