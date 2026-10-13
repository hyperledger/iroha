//! Immutable private receipt staging pinned through every filesystem ancestor.

use iroha_fs::{FileIdentity, PrivateDirectory, SealedPrivateFile};
mod inventory_pool;
pub use inventory_pool::SignerJournalInventoryPoolV1;
use inventory_pool::{FileLease, OpenLease};
use sorafs_manifest::signer::{
    final_promotion::SIGNER_FINAL_PROMOTION_RECEIPT_MAX_BYTES_V1,
    receipt::SIGNER_RELEASE_MANIFEST_RECEIPT_MAX_BYTES_V1,
    stream_token::SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1,
};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const MAX_RECORDS: usize = 65_536;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const SUFFIX: &str = ".receipt.norito";
const LOCK_NAME: &str = ".signer-journal.lock";
// TODO: Compile the pending-Reserve journal outside tests with its final-promotion producer.
#[cfg(test)]
const PENDING_RESERVE_SUFFIX: &str = ".pending-reserve.norito";
#[cfg(test)]
const PENDING_RESERVE_IN_PROGRESS_SUFFIX: &str = ".pending-reserve.inflight";
#[cfg(test)]
const PENDING_RESERVE_DIRECTORY: &str = "pending-reserve-v1";
#[cfg(test)]
const PENDING_RESERVE_MAX_RECORD_BYTES: usize = 136 * 1024;
// These bounds cap the handles and retained path storage before opening any ancestor.
// TODO: Inject one configured process-lived pool into every production signer
// purpose and retain admission through key use, stage and completion.
const MAX_JOURNAL_PATH_COMPONENTS: usize = 64;
const MAX_JOURNAL_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy)]
struct JournalProfile {
    suffix: &'static str,
    in_progress_suffix: Option<&'static str>,
    required_leaf: Option<&'static str>,
    max_record_bytes: usize,
    max_records: usize,
    max_total_bytes: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingReserveCheckpoint {
    TombstoneDurable,
    SignedBytesDurable,
}
impl JournalProfile {
    const fn receipt(purpose: SignerReceiptPurposeV1) -> Self {
        Self {
            suffix: SUFFIX,
            in_progress_suffix: None,
            required_leaf: None,
            max_record_bytes: purpose.max_bytes(),
            max_records: MAX_RECORDS,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }

    #[cfg(test)]
    const PENDING_RESERVE: Self = Self {
        suffix: PENDING_RESERVE_SUFFIX,
        in_progress_suffix: Some(PENDING_RESERVE_IN_PROGRESS_SUFFIX),
        required_leaf: Some(PENDING_RESERVE_DIRECTORY),
        max_record_bytes: PENDING_RESERVE_MAX_RECORD_BYTES,
        max_records: 4096,
        max_total_bytes: MAX_TOTAL_BYTES,
    };
}

/// Immutable receipt family accepted by one producer's journal.
///
/// This selects the exact shared public receipt ceiling, not an arbitrary caller budget.
/// The owning producer still verifies its full canonical receipt and authoritative completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerReceiptPurposeV1 {
    /// Exact reviewed final production-promotion provenance receipts.
    FinalPromotionProvenance,
    /// Exact reviewed aggregate release-manifest operation receipts.
    ReleaseManifest,
    /// Exact provider-scoped stream-token operation receipts.
    StreamToken,
}
impl SignerReceiptPurposeV1 {
    const fn max_bytes(self) -> usize {
        match self {
            Self::FinalPromotionProvenance => SIGNER_FINAL_PROMOTION_RECEIPT_MAX_BYTES_V1,
            Self::ReleaseManifest => SIGNER_RELEASE_MANIFEST_RECEIPT_MAX_BYTES_V1,
            Self::StreamToken => SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1,
        }
    }
}

/// Payload-free failure of journal content or local resource admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerReceiptJournalErrorV1 {
    /// Invalid content, unsafe identity, storage failure or unsupported configuration.
    Unavailable,
    /// Finite local inventory resources are busy; keep the original operation for recovery.
    Capacity,
}
impl SignerReceiptJournalErrorV1 {
    /// Whether the same unmodified operation may wait for local resource release.
    #[must_use]
    pub const fn is_local_capacity(self) -> bool {
        matches!(self, Self::Capacity)
    }
}
impl std::fmt::Display for SignerReceiptJournalErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("signer private receipt journal unavailable")
    }
}
impl std::error::Error for SignerReceiptJournalErrorV1 {}

fn preflight_journal_path(
    path: &Path,
    profile: JournalProfile,
) -> Result<Vec<OsString>, SignerReceiptJournalErrorV1> {
    let fail = || SignerReceiptJournalErrorV1::Unavailable;
    let encoded = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || profile
            .required_leaf
            .is_some_and(|leaf| path.file_name() != Some(std::ffi::OsStr::new(leaf)))
        || encoded.len() > MAX_JOURNAL_PATH_BYTES
    {
        return Err(fail());
    }
    let count = path
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .count();
    if count == 0 || count > MAX_JOURNAL_PATH_COMPONENTS {
        return Err(fail());
    }
    let mut reconstructed = PathBuf::new();
    reconstructed
        .try_reserve(encoded.len())
        .map_err(|_| fail())?;
    let mut names = Vec::new();
    names.try_reserve_exact(count).map_err(|_| fail())?;
    let mut rooted = false;
    for part in path.components() {
        match part {
            Component::Prefix(prefix) if reconstructed.as_os_str().is_empty() => {
                reconstructed.push(prefix.as_os_str());
            }
            Component::RootDir if !rooted && names.is_empty() => {
                reconstructed.push(part.as_os_str());
                rooted = true;
            }
            Component::Normal(name) if rooted => {
                let mut retained = OsString::new();
                retained
                    .try_reserve(name.as_encoded_bytes().len())
                    .map_err(|_| fail())?;
                retained.push(name);
                reconstructed.push(&retained);
                names.push(retained);
            }
            _ => return Err(fail()),
        }
    }
    if !rooted || reconstructed.as_os_str().as_encoded_bytes() != encoded {
        return Err(fail());
    }
    Ok(names)
}

/// Mandatory durable receipt staging with no key material and no path-following fallback.
///
/// The directory must already exist with private current-owner custody. Its native ancestors
/// remain retained by the writer, read-only capabilities and every pinned receipt. A persistent
/// empty control-file lock excludes independent owners until the final shared capability drops.
/// Records have exact native read-only custody (Unix mode 0400; protected owner-read Windows DACL),
/// one link, and retained identity. Failed partial writes remain fail-closed tombstones. Neither
/// local receipt absence nor this lock replaces finalized operation ownership or rollback checks.
pub struct SignerReceiptJournalV1 {
    reader: SignerReceiptJournalReaderV1,
}

struct JournalInner {
    directory: PrivateDirectory,
    lock: File,
    lock_identity: FileIdentity,
    lineage_len: usize,
    mutation: Mutex<()>,
    profile: JournalProfile,
    pool: SignerJournalInventoryPoolV1,
    _open_lease: OpenLease,
}
impl std::fmt::Debug for SignerReceiptJournalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignerReceiptJournalV1")
            .finish_non_exhaustive()
    }
}
impl SignerReceiptJournalV1 {
    /// Pin an existing canonical private journal directory and its complete ancestor lineage.
    ///
    /// # Errors
    /// Rejects symlinks, unsafe ownership/modes, noncanonical paths and malformed/oversized journals.
    pub fn open(
        path: &Path,
        purpose: SignerReceiptPurposeV1,
        pool: &SignerJournalInventoryPoolV1,
    ) -> Result<Self, SignerReceiptJournalErrorV1> {
        let inner = JournalInner::open(path, JournalProfile::receipt(purpose), pool)?;
        Ok(Self {
            reader: SignerReceiptJournalReaderV1 { inner, purpose },
        })
    }
    /// Immutable receipt purpose, checked by the owning producer before any key operation.
    #[must_use]
    pub fn purpose(&self) -> SignerReceiptPurposeV1 {
        self.reader.purpose()
    }
    /// Grant read-only access to this exact existing lease; never reopen the path.
    pub(super) fn reader(&self) -> SignerReceiptJournalReaderV1 {
        SignerReceiptJournalReaderV1 {
            inner: Arc::clone(&self.reader.inner),
            purpose: self.reader.purpose,
        }
    }
    /// Refuse a second key operation when this immutable receipt identity is already staged.
    /// This local fence does not replace the authoritative operation-ID tombstone.
    pub(super) fn ensure_unstaged(
        &self,
        operation_id: [u8; 32],
    ) -> Result<(), SignerReceiptJournalErrorV1> {
        self.reader.inner.ensure_unstaged(operation_id)
    }
    pub(super) fn stage(
        &self,
        operation_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.reader.inner.stage(operation_id, bytes)
    }
    #[cfg(test)]
    pub(super) fn recover(
        &self,
        operation_id: [u8; 32],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.reader().recover(operation_id)
    }
}

/// Separate pending-Reserve directory lease over the same pinned immutable-file mechanism.
///
/// This is not a receipt purpose and cannot be passed to a receipt producer. Recovery exposes
/// bytes only; it has no signing or transport entry point.
#[cfg(test)]
pub(super) struct SignerPendingReserveFilesV1 {
    inner: Arc<JournalInner>,
}
#[cfg(test)]
impl SignerPendingReserveFilesV1 {
    /// Open the dedicated owner-only `pending-reserve-v1` directory and pin every ancestor.
    pub(super) fn open(
        path: &Path,
        pool: &SignerJournalInventoryPoolV1,
    ) -> Result<Self, SignerReceiptJournalErrorV1> {
        Ok(Self {
            inner: JournalInner::open(path, JournalProfile::PENDING_RESERVE, pool)?,
        })
    }

    /// Durably stage one immutable operation record and retain its exact file identity.
    pub(super) fn stage(
        &self,
        operation_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.inner.stage_pending_reserve(operation_id, bytes)
    }

    /// Read back one already staged operation without creating submission authority.
    pub(super) fn recover(
        &self,
        operation_id: [u8; 32],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.inner.recover(operation_id)
    }
}

impl JournalInner {
    fn open(
        path: &Path,
        profile: JournalProfile,
        pool: &SignerJournalInventoryPoolV1,
    ) -> Result<Arc<Self>, SignerReceiptJournalErrorV1> {
        let fail = || SignerReceiptJournalErrorV1::Unavailable;
        let depth = path
            .components()
            .filter(|part| matches!(part, Component::Normal(_)))
            .count();
        let (open_lease, path_probes) =
            pool.admit_open(path.as_os_str().as_encoded_bytes().len(), depth)?;
        let names = preflight_journal_path(path, profile)?;
        let lineage_len = names.len() + 1;
        drop(names);
        let directory = PrivateDirectory::open_exact(path).map_err(|_| fail())?;
        // The journal admits an exact canonical native path, including its original root. The
        // shared reader's independently permitted operating-system redirects do not relabel it.
        if directory.path() != path {
            return Err(fail());
        }
        let lock = directory
            .open_ownership_lock(LOCK_NAME)
            .map_err(|_| fail())?;
        lock.try_lock().map_err(|_| fail())?;
        let lock_identity = FileIdentity::of(&lock).map_err(|_| fail())?;
        let inner = Arc::new(Self {
            directory,
            lock,
            lock_identity,
            lineage_len,
            mutation: Mutex::new(()),
            profile,
            pool: pool.clone(),
            _open_lease: open_lease,
        });
        inner.verify_lineage()?;
        drop(path_probes);
        inner.inventory()?;
        Ok(inner)
    }
}

/// Read-only capability over an already opened journal's exact directory lease.
///
/// There is no path constructor, write method, dereference, or writer conversion. Only the
/// owning signer-operation module can obtain this capability; receipt bytes remain internal.
pub(super) struct SignerReceiptJournalReaderV1 {
    inner: Arc<JournalInner>,
    purpose: SignerReceiptPurposeV1,
}
impl SignerReceiptJournalReaderV1 {
    /// Exact receipt-family ceiling retained by the original writer's lease.
    pub(super) fn purpose(&self) -> SignerReceiptPurposeV1 {
        self.purpose
    }
    /// Pin bounded untrusted receipt bytes; semantic verification remains the purpose owner.
    pub(super) fn recover(
        &self,
        operation_id: [u8; 32],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.inner.recover(operation_id)
    }
}

impl JournalInner {
    fn ensure_unstaged(&self, operation_id: [u8; 32]) -> Result<(), SignerReceiptJournalErrorV1> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        if operation_id == [0; 32] || self.inventory_for(Some(operation_id))?.2 {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        Ok(())
    }

    fn verify_lineage(&self) -> Result<(), SignerReceiptJournalErrorV1> {
        let fail = || SignerReceiptJournalErrorV1::Unavailable;
        self.directory.revalidate().map_err(|_| fail())?;
        if FileIdentity::of(&self.lock).map_err(|_| fail())? != self.lock_identity
            || self.lock.metadata().map_err(|_| fail())?.len() != 0
        {
            return Err(fail());
        }
        let named = self.directory.open_read(LOCK_NAME).map_err(|_| fail())?;
        if FileIdentity::of(&named).map_err(|_| fail())? != self.lock_identity
            || named.metadata().map_err(|_| fail())?.len() != 0
        {
            return Err(fail());
        }
        self.directory.revalidate().map_err(|_| fail())
    }

    fn inventory(&self) -> Result<(usize, u64), SignerReceiptJournalErrorV1> {
        let (count, size, _) = self.inventory_for(None)?;
        Ok((count, size))
    }

    fn inventory_for(
        &self,
        sought: Option<[u8; 32]>,
    ) -> Result<(usize, u64, bool), SignerReceiptJournalErrorV1> {
        // Admit the entire bounded scan before opening a scan/probe handle or inspecting entries.
        let _scan = self.pool.admit_scan(
            self.profile.max_records,
            self.profile.in_progress_suffix.is_some(),
            self.lineage_len,
        )?;
        self.verify_lineage()?;
        let mut count = 0usize;
        let mut size = 0u64;
        let mut found = false;
        let mut lock_seen = false;
        let mut pending_ids = Vec::new();
        if self.profile.in_progress_suffix.is_some() {
            pending_ids
                .try_reserve_exact(self.profile.max_records)
                .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        }
        self.directory
            .visit_private_files(self.profile.max_records + 1, |name, metadata| {
                let fail = || io::Error::other("invalid signer journal inventory");
                let text = name.to_str().ok_or_else(fail)?;
                if text == LOCK_NAME {
                    if lock_seen || !metadata.is_empty() || metadata.is_read_only() {
                        return Err(fail());
                    }
                    lock_seen = true;
                    return Ok(());
                }
                let (id, in_progress) = if let Some(id) = text.strip_suffix(self.profile.suffix) {
                    (id, false)
                } else if let Some(id) = self
                    .profile
                    .in_progress_suffix
                    .and_then(|suffix| text.strip_suffix(suffix))
                {
                    (id, true)
                } else {
                    return Err(fail());
                };
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    return Err(fail());
                }
                let mut operation = [0; 32];
                hex::decode_to_slice(id, &mut operation).map_err(|_| fail())?;
                if operation == [0; 32]
                    || (!in_progress && (!metadata.is_read_only() || metadata.is_empty()))
                    || metadata.len() > self.profile.max_record_bytes as u64
                {
                    return Err(fail());
                }
                found |= sought == Some(operation);
                if self.profile.in_progress_suffix.is_some() {
                    if pending_ids.len() >= self.profile.max_records {
                        return Err(fail());
                    }
                    pending_ids.push(operation);
                }
                count = count.checked_add(1).ok_or_else(fail)?;
                size = size.checked_add(metadata.len()).ok_or_else(fail)?;
                if count > self.profile.max_records || size > self.profile.max_total_bytes {
                    return Err(fail());
                }
                Ok(())
            })
            .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        pending_ids.sort_unstable();
        if !lock_seen || pending_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        self.verify_lineage()?;
        Ok((count, size, found))
    }

    fn stage(
        self: &Arc<Self>,
        operation_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        let fail = || SignerReceiptJournalErrorV1::Unavailable;
        let _guard = self.mutation.lock().map_err(|_| fail())?;
        self.admit_stage(operation_id, bytes)?;
        let lease = self
            .pool
            .admit_file(self.profile.max_record_bytes, self.lineage_len)?;
        let probes = self.pool.admit_inspection(self.lineage_len, 0)?;
        let name = format!("{}{SUFFIX}", hex::encode(operation_id));
        let mut file = self
            .directory
            .create_retained_private(&name, self.profile.max_record_bytes)
            .map_err(|_| fail())?;
        // Creation durably claims the exact final name before any byte write. Failure leaves that
        // name closed; immutable native operation history independently prevents signing retries.
        file.write_all(bytes).map_err(|_| fail())?;
        let file = file.seal_read_only().map_err(|_| fail())?;
        drop(probes);
        self.pin(file, bytes, lease)
    }

    fn admit_stage(
        &self,
        operation_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), SignerReceiptJournalErrorV1> {
        if operation_id == [0; 32]
            || bytes.is_empty()
            || bytes.len() > self.profile.max_record_bytes
        {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        let (count, size, found) = self.inventory_for(Some(operation_id))?;
        if found
            || count >= self.profile.max_records
            || size
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.profile.max_total_bytes)
        {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        Ok(())
    }

    fn pin(
        self: &Arc<Self>,
        file: SealedPrivateFile,
        bytes: &[u8],
        lease: FileLease,
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        let mut retained = Zeroizing::new(Vec::new());
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        retained.extend_from_slice(bytes);
        let pinned = PinnedReceipt {
            journal: Arc::clone(self),
            file: Mutex::new(file),
            bytes: retained,
            _file_lease: lease,
        };
        pinned.recheck()?;
        Ok(pinned)
    }

    #[cfg(test)]
    fn stage_pending_reserve(
        self: &Arc<Self>,
        operation_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        self.stage_pending_reserve_with(operation_id, bytes, |_| Ok(()))
    }

    #[cfg(test)]
    fn stage_pending_reserve_with(
        self: &Arc<Self>,
        operation_id: [u8; 32],
        bytes: &[u8],
        mut checkpoint: impl FnMut(PendingReserveCheckpoint) -> io::Result<()>,
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        let fail = || SignerReceiptJournalErrorV1::Unavailable;
        if self.profile.in_progress_suffix != Some(PENDING_RESERVE_IN_PROGRESS_SUFFIX) {
            return Err(fail());
        }
        let _guard = self.mutation.lock().map_err(|_| fail())?;
        self.admit_stage(operation_id, bytes)?;
        let lease = self
            .pool
            .admit_file(self.profile.max_record_bytes, self.lineage_len)?;
        let probes = self
            .pool
            .admit_inspection(self.lineage_len, self.profile.max_record_bytes)?;
        let id = hex::encode(operation_id);
        let final_name = format!("{id}{PENDING_RESERVE_SUFFIX}");
        let in_progress = format!("{id}{PENDING_RESERVE_IN_PROGRESS_SUFFIX}");
        let mut file = self
            .directory
            .create_retained_private(&in_progress, self.profile.max_record_bytes)
            .map_err(|_| fail())?;
        checkpoint(PendingReserveCheckpoint::TombstoneDurable).map_err(|_| fail())?;
        file.write_all(bytes).map_err(|_| fail())?;
        let mut file = file.seal_read_only().map_err(|_| fail())?;
        if read_stable(&mut file, self.profile)?.as_slice() != bytes {
            return Err(fail());
        }
        checkpoint(PendingReserveCheckpoint::SignedBytesDurable).map_err(|_| fail())?;
        let file = file.publish_new_name(&final_name).map_err(|_| fail())?;
        drop(probes);
        self.pin(file, bytes, lease)
    }

    fn recover(
        self: &Arc<Self>,
        operation_id: [u8; 32],
    ) -> Result<PinnedReceipt, SignerReceiptJournalErrorV1> {
        let fail = || SignerReceiptJournalErrorV1::Unavailable;
        if operation_id == [0; 32] {
            return Err(fail());
        }
        let lease = self
            .pool
            .admit_file(self.profile.max_record_bytes, self.lineage_len)?;
        let probes = self.pool.admit_inspection(self.lineage_len, 0)?;
        self.verify_lineage()?;
        let name = format!("{}{}", hex::encode(operation_id), self.profile.suffix);
        let mut file = self
            .directory
            .open_retained_read_only(&name, self.profile.max_record_bytes)
            .map_err(|_| fail())?;
        let bytes = read_stable(&mut file, self.profile)?;
        drop(probes);
        let pinned = PinnedReceipt {
            journal: Arc::clone(self),
            file: Mutex::new(file),
            bytes,
            _file_lease: lease,
        };
        pinned.recheck()?;
        Ok(pinned)
    }
}

/// Exact immutable byte snapshot retaining the original journal lease until drop.
pub(super) struct PinnedReceipt {
    journal: Arc<JournalInner>,
    file: Mutex<SealedPrivateFile>,
    bytes: Zeroizing<Vec<u8>>,
    _file_lease: FileLease,
}
impl PinnedReceipt {
    pub(super) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    pub(super) fn recheck(&self) -> Result<(), SignerReceiptJournalErrorV1> {
        let _probes = self.journal.pool.admit_inspection(
            self.journal.lineage_len,
            self.journal.profile.max_record_bytes,
        )?;
        self.journal.verify_lineage()?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        if read_stable(&mut file, self.journal.profile)?.as_slice() != self.bytes.as_slice() {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        self.journal.verify_lineage()
    }
}

fn read_stable(
    file: &mut SealedPrivateFile,
    profile: JournalProfile,
) -> Result<Zeroizing<Vec<u8>>, SignerReceiptJournalErrorV1> {
    let fail = || SignerReceiptJournalErrorV1::Unavailable;
    let before = file.snapshot().map_err(|_| fail())?;
    let length = file.len().map_err(|_| fail())?;
    if length == 0 || length > profile.max_record_bytes as u64 {
        return Err(fail());
    }
    let length = usize::try_from(length).map_err(|_| fail())?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length).map_err(|_| fail())?;
    bytes.resize(length, 0);
    file.seek(SeekFrom::Start(0)).map_err(|_| fail())?;
    file.read_exact(&mut bytes).map_err(|_| fail())?;
    if file.snapshot().map_err(|_| fail())? != before {
        return Err(fail());
    }
    Ok(bytes)
}

#[cfg(test)]
mod portable_tests;
#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
pub(crate) fn test_inventory_pool() -> &'static SignerJournalInventoryPoolV1 {
    static POOL: std::sync::OnceLock<SignerJournalInventoryPoolV1> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        // Test workers share this finite pool without accidental parallel-suite contention.
        // Exact-capacity behavior uses dedicated tiny pools in focused tests.
        SignerJournalInventoryPoolV1::new(
            iroha_config::parameters::actual::SorafsSignerJournalInventory {
                resident_bytes: iroha_config_base::util::Bytes(128 * 1024 * 1024),
                metadata_probes: 8_000_000,
                open_handles: 8_192,
            },
        )
        .expect("valid test inventory pool")
    })
}
#[cfg(test)]
impl SignerReceiptJournalV1 {
    pub(crate) fn open_test(
        path: &Path,
        purpose: SignerReceiptPurposeV1,
    ) -> Result<Self, SignerReceiptJournalErrorV1> {
        Self::open(path, purpose, test_inventory_pool())
    }
}
#[cfg(test)]
impl SignerPendingReserveFilesV1 {
    pub(crate) fn open_test(path: &Path) -> Result<Self, SignerReceiptJournalErrorV1> {
        Self::open(path, test_inventory_pool())
    }
}
#[cfg(test)]
impl JournalInner {
    fn open_test(
        path: &Path,
        profile: JournalProfile,
    ) -> Result<Arc<Self>, SignerReceiptJournalErrorV1> {
        Self::open(path, profile, test_inventory_pool())
    }
}

/// Count every data artifact while independently validating any native lease control file.
#[cfg(test)]
pub(crate) fn test_record_count(path: impl AsRef<Path>) -> usize {
    std::fs::read_dir(path)
        .unwrap()
        .filter(|entry| {
            let entry = entry.as_ref().unwrap();
            if entry.file_name() == LOCK_NAME {
                assert!(iroha_fs::read_private(entry.path(), 1).unwrap().is_empty());
                false
            } else {
                true
            }
        })
        .count()
}
