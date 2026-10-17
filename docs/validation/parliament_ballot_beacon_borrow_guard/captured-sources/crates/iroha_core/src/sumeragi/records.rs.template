//! File-backed safety records of the Sumeragi driver (`specs/sumeragi.md` §7.4, §12.2).
//!
//! Layout:
//!
//! - `<records_dir>/<instance hex>/<H(key) hex>.record`: one file per `(instance, key)` holding
//!   the exact `SafetyRecord::encode` bytes, replaced atomically (temp file, fsync, rename,
//!   directory fsync);
//! - `<records_dir>/store_id`: the random 128-bit store id, written the same way;
//! - the installation log, a separate append-only file **outside** `records_dir` (in the node's
//!   key store): one length-prefixed Norito entry per key installation and per `(instance, key)`
//!   ever started, each with its store id, fsynced on append. A torn or corrupt tail (a crash
//!   during an append) is ignored and cut off before the next append; the store-id check then
//!   sees a mismatch, which is always safe (every key counts as imported).
//!
//! Record files and the store-id file are never backed up or restored (§7.4 rule 1). The
//! provenance rules themselves (store-id check, installation event, never over an existing
//! record) are the driver's [`install_records`]; [`install`] runs them over this store with
//! random store ids and the operator's one-shot [`FreshKeyAssertion`].
//!
//! Every file-system step first asks a [`Faults`] hook, the fault-injection seam of the crash
//! and disk-error tests (a failed step behaves like `ENOSPC`/`EIO` there, or like a kill when
//! the test stops using the store). A failed write is retried by the persistence worker
//! (`specs/sumeragi.md` §12.3 O2) and never leaves a partial record visible.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use iroha_crypto::Hash;
use iroha_sumeragi::{
    crypto::Crypto,
    safety::RecordState,
    types::{EpochId, Hash32, PublicKey},
};
use parking_lot::Mutex;

use super::driver::{
    persist::{install_records, reconcile_store_id},
    traits::{LogEntry, RecordStore},
};

/// Name of the store-id file inside the records directory.
pub const STORE_ID_FILE: &str = "store_id";
/// Extension of a record file.
const RECORD_EXTENSION: &str = "record";
/// Suffix of a temporary file before its rename.
const TEMP_SUFFIX: &str = "tmp";
/// Largest encoded installation-log entry (a key entry is about 100 bytes).
const MAX_LOG_ENTRY_BYTES: usize = 4096;

/// One step of a durable file operation, reported to the [`Faults`] hook before it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FsStep {
    /// Create a directory.
    CreateDir,
    /// Create (truncate) a temporary file.
    CreateTemp,
    /// Write the first half of a temporary file.
    WriteTemp,
    /// Write the rest of a temporary file.
    WriteTempRest,
    /// fsync a temporary file.
    SyncFile,
    /// Rename a temporary file over its target.
    Rename,
    /// fsync a directory.
    SyncDir,
    /// Open the installation log.
    OpenLog,
    /// Cut a torn tail off the installation log.
    TruncateLog,
    /// Append the first half of a log entry.
    AppendLog,
    /// Append the rest of a log entry.
    AppendLogRest,
    /// fsync the installation log.
    SyncLog,
    /// Remove files or directories (body pruning).
    Remove,
}

/// Fault-injection seam: asked before every file-system step; an error aborts the operation
/// at that step, as an I/O error (`ENOSPC`, `EIO`) or a crash would.
pub trait Faults: Send + Sync {
    /// Called before `step` on `path`.
    ///
    /// # Errors
    /// The injected failure.
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()>;
}

/// No fault injection (production).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaults;

impl Faults for NoFaults {
    fn before(&self, _step: FsStep, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// fsync the directory `dir` (makes its entries durable).
///
/// # Errors
/// The injected or I/O failure.
pub fn sync_dir(faults: &dyn Faults, dir: &Path) -> io::Result<()> {
    faults.before(FsStep::SyncDir, dir)?;
    File::open(dir)?.sync_all()
}

/// Create `dir` and its missing ancestors; every directory created is made durable in its
/// parent.
///
/// # Errors
/// The injected or I/O failure.
pub fn create_dir_durable(faults: &dyn Faults, dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let parent = dir.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        create_dir_durable(faults, parent)?;
    }
    faults.before(FsStep::CreateDir, dir)?;
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(error) => return Err(error),
    }
    match parent {
        Some(parent) => sync_dir(faults, parent),
        None => Ok(()),
    }
}

/// Replace `dir/name` with `bytes` atomically and durably: write and fsync `dir/name.tmp`,
/// rename it over `dir/name`, fsync `dir`. A failure at any step leaves the old file (or none)
/// in place, never a partial one.
///
/// # Errors
/// The injected or I/O failure at the step that failed.
pub fn write_atomic(faults: &dyn Faults, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!("{name}.{TEMP_SUFFIX}"));
    let target = dir.join(name);
    faults.before(FsStep::CreateTemp, &temp)?;
    let mut file = File::create(&temp)?;
    let (head, tail) = bytes.split_at(bytes.len() / 2);
    faults.before(FsStep::WriteTemp, &temp)?;
    file.write_all(head)?;
    faults.before(FsStep::WriteTempRest, &temp)?;
    file.write_all(tail)?;
    faults.before(FsStep::SyncFile, &temp)?;
    file.sync_all()?;
    drop(file);
    faults.before(FsStep::Rename, &target)?;
    fs::rename(&temp, &target)?;
    sync_dir(faults, dir)
}

/// The persisted store id (`<records_dir>/store_id`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::sumeragi::records::StoreIdV1")]
struct StoreIdV1 {
    store_id: u128,
}

/// One persisted installation-log entry: a key entry when `instance` is `None`.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::sumeragi::records::LogEntryV1")]
struct LogEntryV1 {
    instance: Option<[u8; 32]>,
    key: Vec<u8>,
    generated: bool,
    store_id: u128,
}

impl LogEntryV1 {
    fn from_entry(entry: &LogEntry) -> Self {
        match entry {
            LogEntry::Key {
                key,
                generated,
                store_id,
            } => Self {
                instance: None,
                key: key.as_bytes().to_vec(),
                generated: *generated,
                store_id: *store_id,
            },
            LogEntry::Instance {
                instance,
                key,
                store_id,
            } => Self {
                instance: Some(instance.0),
                key: key.as_bytes().to_vec(),
                generated: false,
                store_id: *store_id,
            },
        }
    }

    fn into_entry(self) -> Option<LogEntry> {
        let key = PublicKey::new(self.key).ok()?;
        Some(match self.instance {
            None => LogEntry::Key {
                key,
                generated: self.generated,
                store_id: self.store_id,
            },
            Some(instance) => LogEntry::Instance {
                instance: Hash32(instance),
                key,
                store_id: self.store_id,
            },
        })
    }
}

/// Parse an installation log: the entries up to the first torn or corrupt one, and the byte
/// length they span (a tail beyond it is not part of the log).
fn parse_log(bytes: &[u8]) -> (Vec<LogEntry>, u64) {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while let Some(prefix) = bytes.get(offset..offset.saturating_add(4)) {
        let mut len = [0u8; 4];
        len.copy_from_slice(prefix);
        let len = usize::try_from(u32::from_le_bytes(len)).unwrap_or(usize::MAX);
        let start = offset + 4;
        let Some(frame) = (len <= MAX_LOG_ENTRY_BYTES)
            .then(|| bytes.get(start..start + len))
            .flatten()
        else {
            break;
        };
        let Some(entry) = norito::decode_canonical::<LogEntryV1>(frame)
            .ok()
            .and_then(LogEntryV1::into_entry)
        else {
            break;
        };
        entries.push(entry);
        offset = start + len;
    }
    if offset < bytes.len() {
        iroha_logger::warn!(
            valid = offset,
            len = bytes.len(),
            "sumeragi installation log has a torn or corrupt tail; it is ignored"
        );
    }
    (entries, u64::try_from(offset).unwrap_or(u64::MAX))
}

/// Encode one log entry with its length prefix.
fn encode_log_entry(entry: &LogEntry) -> io::Result<Vec<u8>> {
    let frame = norito::encode_canonical(&LogEntryV1::from_entry(entry))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = u32::try_from(frame.len())
        .ok()
        .filter(|len| usize::try_from(*len).is_ok_and(|len| len <= MAX_LOG_ENTRY_BYTES))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log entry too large"))?;
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&frame);
    Ok(out)
}

/// The driver's [`RecordStore`] over files (see the module documentation).
pub struct FileRecordStore {
    records_dir: PathBuf,
    log_path: PathBuf,
    faults: Arc<dyn Faults>,
    /// Serializes installation-log appends.
    log_lock: Mutex<()>,
    /// Directories whose entry in their parent was made durable by this process.
    durable_dirs: Mutex<BTreeSet<PathBuf>>,
}

impl core::fmt::Debug for FileRecordStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileRecordStore")
            .field("records_dir", &self.records_dir)
            .field("log_path", &self.log_path)
            .finish_non_exhaustive()
    }
}

impl FileRecordStore {
    /// Open (creating if needed) the record store in `records_dir` with the installation log
    /// at `log_path`, which must lie outside `records_dir` (§7.4 rule 2).
    ///
    /// # Errors
    /// `InvalidInput` if the log lies inside the records directory; an I/O failure.
    pub fn open(records_dir: impl Into<PathBuf>, log_path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with_faults(records_dir, log_path, Arc::new(NoFaults))
    }

    /// [`FileRecordStore::open`] with a fault-injection hook.
    ///
    /// # Errors
    /// As [`FileRecordStore::open`].
    pub fn open_with_faults(
        records_dir: impl Into<PathBuf>,
        log_path: impl Into<PathBuf>,
        faults: Arc<dyn Faults>,
    ) -> io::Result<Self> {
        let records_dir = records_dir.into();
        let log_path = log_path.into();
        if std::path::absolute(&log_path)?.starts_with(std::path::absolute(&records_dir)?) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the sumeragi installation log must lie outside the records directory",
            ));
        }
        create_dir_durable(&*faults, &records_dir)?;
        if let Some(parent) = log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_dir_durable(&*faults, parent)?;
        }
        Ok(Self {
            records_dir,
            log_path,
            faults,
            log_lock: Mutex::new(()),
            durable_dirs: Mutex::new(BTreeSet::new()),
        })
    }

    /// The records directory.
    pub fn records_dir(&self) -> &Path {
        &self.records_dir
    }

    /// The installation log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// The directory of the records of `instance`.
    pub fn instance_dir(&self, instance: &Hash32) -> PathBuf {
        self.records_dir.join(hex::encode(instance.0))
    }

    /// The file name of the record of `key` (the hex of `H(key)`).
    pub fn record_name(key: &PublicKey) -> String {
        format!(
            "{}.{RECORD_EXTENSION}",
            hex::encode(<[u8; 32]>::from(Hash::new(key.as_bytes())))
        )
    }

    /// The record file of `(instance, key)`.
    pub fn record_path(&self, instance: &Hash32, key: &PublicKey) -> PathBuf {
        self.instance_dir(instance).join(Self::record_name(key))
    }

    /// Make `dir` exist with a durable entry in its parent, once per process (a directory made
    /// by a crashed run may not be durable yet).
    fn durable_dir(&self, dir: &Path) -> io::Result<()> {
        if self.durable_dirs.lock().contains(dir) {
            return Ok(());
        }
        create_dir_durable(&*self.faults, dir)?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(&*self.faults, parent)?;
        }
        self.durable_dirs.lock().insert(dir.to_path_buf());
        Ok(())
    }

    /// The installation log and the byte length of its valid entries.
    fn read_log(&self) -> io::Result<(Vec<LogEntry>, u64)> {
        match fs::read(&self.log_path) {
            Ok(bytes) => Ok(parse_log(&bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((Vec::new(), 0)),
            Err(error) => Err(error),
        }
    }
}

impl RecordStore for FileRecordStore {
    fn load(&self, instance: &Hash32, key: &PublicKey) -> io::Result<RecordState> {
        match fs::read(self.record_path(instance, key)) {
            Ok(bytes) => Ok(RecordState::Present(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(RecordState::Absent),
            Err(error) => Err(error),
        }
    }

    fn write(&self, instance: &Hash32, key: &PublicKey, bytes: &[u8]) -> io::Result<()> {
        let dir = self.instance_dir(instance);
        self.durable_dir(&dir)?;
        write_atomic(&*self.faults, &dir, &Self::record_name(key), bytes)
    }

    fn store_id(&self) -> io::Result<Option<u128>> {
        match fs::read(self.records_dir.join(STORE_ID_FILE)) {
            Ok(bytes) => norito::decode_canonical::<StoreIdV1>(&bytes)
                .map(|id| Some(id.store_id))
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("corrupt sumeragi store-id file: {e}"),
                    )
                }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn set_store_id(&self, id: u128) -> io::Result<()> {
        let bytes = norito::encode_canonical(&StoreIdV1 { store_id: id })
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.durable_dir(&self.records_dir)?;
        write_atomic(&*self.faults, &self.records_dir, STORE_ID_FILE, &bytes)
    }

    fn log(&self) -> io::Result<Vec<LogEntry>> {
        Ok(self.read_log()?.0)
    }

    fn append_log(&self, entry: &LogEntry) -> io::Result<()> {
        let record = encode_log_entry(entry)?;
        let _guard = self.log_lock.lock();
        let (_, valid) = self.read_log()?;
        self.faults.before(FsStep::OpenLog, &self.log_path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.log_path)?;
        if file.metadata()?.len() != valid {
            self.faults.before(FsStep::TruncateLog, &self.log_path)?;
            file.set_len(valid)?;
        }
        file.seek(SeekFrom::Start(valid))?;
        let (head, tail) = record.split_at(record.len() / 2);
        self.faults.before(FsStep::AppendLog, &self.log_path)?;
        file.write_all(head)?;
        self.faults.before(FsStep::AppendLogRest, &self.log_path)?;
        file.write_all(tail)?;
        self.faults.before(FsStep::SyncLog, &self.log_path)?;
        file.sync_all()?;
        drop(file);
        // The log's directory entry (the file may have just been created) and that directory's
        // own entry.
        match self.log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => {
                self.durable_dir(parent)?;
                sync_dir(&*self.faults, parent)
            }
            None => Ok(()),
        }
    }
}

/// The operator's one-shot assertion that the node's keys have never signed for the instances
/// started now (§7.4 rule 2), e.g. at a fresh network's genesis where every key was generated
/// off-node (kagami) and so counts as imported.
///
/// It comes only from the command-line flag of this boot (`--sumeragi-assert-fresh-key`), never
/// from a configuration key, so it cannot outlive the boot it was given for. Without it (or
/// without a key generated on this node) a fresh network never anchors its keys and never
/// commits.
#[derive(Debug)]
#[allow(missing_copy_implementations)] // a one-shot token: never copied or cloned
pub struct FreshKeyAssertion(());

impl FreshKeyAssertion {
    /// The assertion iff the operator passed the flag on this boot.
    pub fn from_operator_flag(asserted: bool) -> Option<Self> {
        asserted.then_some(Self(()))
    }
}

/// A fresh random 128-bit store id (§7.4 rule 3).
pub fn fresh_store_id() -> u128 {
    rand::random()
}

/// The §7.4 record-provenance steps when `instance` starts with `keys` (`(key, retired)`),
/// over `store` with random store ids ([`install_records`]): the store-id check, the
/// installation event of each `(instance, key)` the log lacks — an initial record only for a key
/// generated on this node or under the operator's [`FreshKeyAssertion`], and never over an
/// existing record file — and what is then on disk for each key (for `Init.records`).
///
/// # Errors
/// A store failure; the instance does not start.
pub fn install<R: RecordStore + ?Sized>(
    store: &R,
    crypto: &dyn Crypto,
    instance: &Hash32,
    genesis_epoch: EpochId,
    keys: &[(PublicKey, bool)],
    genesis_height: u64,
    assertion: Option<&FreshKeyAssertion>,
) -> io::Result<Vec<(PublicKey, RecordState, bool)>> {
    if assertion.is_some() {
        iroha_logger::warn!(
            %instance,
            "operator asserts that the node's consensus keys never signed for this instance"
        );
    }
    install_records(
        store,
        crypto,
        instance,
        genesis_epoch,
        keys,
        genesis_height,
        assertion.is_some(),
        &mut fresh_store_id,
    )
}

/// Record that `key` was generated on this node and never exported (§7.4 rule 3), so every
/// instance it starts later gets its initial record automatically. The store-id check runs
/// first, so a stale log is never made to look current.
///
/// # Errors
/// A store failure.
pub fn register_generated_key<R: RecordStore + ?Sized>(
    store: &R,
    key: &PublicKey,
) -> io::Result<()> {
    let mut log = store.log()?;
    reconcile_store_id(store, &mut log, &mut fresh_store_id)?;
    let store_id = fresh_store_id();
    store.set_store_id(store_id)?;
    store.append_log(&LogEntry::Key {
        key: key.clone(),
        generated: true,
        store_id,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use iroha_sumeragi::{safety::SafetyRecord, testing::FakeCrypto};

    use super::*;

    const I: Hash32 = Hash32([0x11; 32]);
    const J: Hash32 = Hash32([0x22; 32]);

    fn key(byte: u8) -> PublicKey {
        PublicKey::new(vec![byte; 48]).unwrap()
    }

    /// A temporary node directory with `records/` and `keys/installation.log`.
    struct Node {
        dir: tempfile::TempDir,
    }

    impl Node {
        /// A node whose directories exist (so a store opens without file-system steps).
        fn new() -> Self {
            let node = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            node.open();
            node
        }

        fn records(&self) -> PathBuf {
            self.dir.path().join("records")
        }

        fn log(&self) -> PathBuf {
            self.dir.path().join("keys").join("installation.log")
        }

        fn open(&self) -> FileRecordStore {
            FileRecordStore::open(self.records(), self.log()).unwrap()
        }

        fn open_faulty(&self, faults: Arc<dyn Faults>) -> FileRecordStore {
            FileRecordStore::open_with_faults(self.records(), self.log(), faults).unwrap()
        }
    }

    /// Fails every step from the `at`-th on (a crash, or a dead disk), or only the `at`-th with
    /// `once` (a transient `ENOSPC`/`EIO`); counts the steps.
    struct CrashAt {
        at: usize,
        once: bool,
        seen: AtomicUsize,
        error: fn() -> io::Error,
    }

    impl CrashAt {
        fn crash(at: usize) -> Arc<Self> {
            Arc::new(Self {
                at,
                once: false,
                seen: AtomicUsize::new(0),
                error: || io::Error::other("crash"),
            })
        }

        fn transient(at: usize, error: fn() -> io::Error) -> Arc<Self> {
            Arc::new(Self {
                at,
                once: true,
                seen: AtomicUsize::new(0),
                error,
            })
        }

        fn steps(&self) -> usize {
            self.seen.load(Ordering::SeqCst)
        }
    }

    impl Faults for CrashAt {
        fn before(&self, _step: FsStep, _path: &Path) -> io::Result<()> {
            let n = self.seen.fetch_add(1, Ordering::SeqCst);
            if n == self.at || (!self.once && n > self.at) {
                return Err((self.error)());
            }
            Ok(())
        }
    }

    fn enospc() -> io::Error {
        io::Error::from_raw_os_error(28)
    }

    fn eio() -> io::Error {
        io::Error::from_raw_os_error(5)
    }

    fn record(instance: Hash32, key: &PublicKey, height: u64) -> Vec<u8> {
        SafetyRecord::fresh(
            instance,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            key.clone(),
            height,
            None,
        )
        .encode(&FakeCrypto::new())
        .unwrap()
    }

    /// The record of `(instance, key)` is absent or a complete, valid record — never torn.
    fn assert_whole(store: &FileRecordStore, instance: &Hash32, key: &PublicKey) -> Option<u64> {
        match store.load(instance, key).unwrap() {
            RecordState::Absent => None,
            RecordState::Present(bytes) => Some(
                SafetyRecord::decode(&FakeCrypto::new(), &bytes)
                    .expect("a record is never torn")
                    .height,
            ),
        }
    }

    fn started(store: &FileRecordStore, instance: &Hash32, k: &PublicKey) -> bool {
        store.log().unwrap().iter().any(
            |e| matches!(e, LogEntry::Instance { instance: i, key, .. } if i == instance && key == k),
        )
    }

    fn generated(store: &FileRecordStore, k: &PublicKey) -> Option<bool> {
        store.log().unwrap().iter().rev().find_map(|e| match e {
            LogEntry::Key { key, generated, .. } if key == k => Some(*generated),
            _ => None,
        })
    }

    #[test]
    fn records_round_trip_and_replace_atomically() {
        let node = Node::new();
        let store = node.open();
        let k = key(1);
        assert_eq!(store.load(&I, &k).unwrap(), RecordState::Absent);
        store.write(&I, &k, &record(I, &k, 3)).unwrap();
        store.write(&I, &k, &record(I, &k, 4)).unwrap();
        assert_eq!(
            store.load(&I, &k).unwrap(),
            RecordState::Present(record(I, &k, 4))
        );
        assert_eq!(store.load(&J, &k).unwrap(), RecordState::Absent);
        let path = store.record_path(&I, &k);
        assert!(path.starts_with(node.records().join(hex::encode(I.0))));
        assert!(path.to_string_lossy().ends_with(".record"));
        assert!(format!("{store:?}").contains("FileRecordStore"));
        assert_eq!(store.records_dir(), node.records());
        assert_eq!(store.log_path(), node.log());
        // Reopening sees the same files.
        assert_eq!(
            node.open().load(&I, &k).unwrap(),
            RecordState::Present(record(I, &k, 4))
        );
    }

    #[test]
    fn store_id_round_trip_and_corruption() {
        let node = Node::new();
        let store = node.open();
        assert_eq!(store.store_id().unwrap(), None);
        store.set_store_id(u128::MAX - 7).unwrap();
        assert_eq!(store.store_id().unwrap(), Some(u128::MAX - 7));
        fs::write(node.records().join(STORE_ID_FILE), b"garbage").unwrap();
        assert_eq!(
            store.store_id().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn log_must_lie_outside_the_records_dir() {
        let node = Node::new();
        let inside = node.records().join("log");
        let err = FileRecordStore::open(node.records(), inside).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let nested = node.records().join("a").join("..").join("log");
        assert!(FileRecordStore::open(node.records(), nested).is_err());
    }

    #[test]
    fn log_appends_and_survives_a_torn_or_corrupt_tail() {
        let node = Node::new();
        let store = node.open();
        let entries = [
            LogEntry::Key {
                key: key(1),
                generated: true,
                store_id: 1,
            },
            LogEntry::Instance {
                instance: I,
                key: key(1),
                store_id: 2,
            },
        ];
        for entry in &entries {
            store.append_log(entry).unwrap();
        }
        assert_eq!(store.log().unwrap(), entries);
        // A torn tail (half an entry) is ignored and cut off by the next append.
        let full = fs::read(node.log()).unwrap();
        let third = encode_log_entry(&LogEntry::Key {
            key: key(2),
            generated: false,
            store_id: 3,
        })
        .unwrap();
        let mut torn = full.clone();
        torn.extend_from_slice(&third[..third.len() / 2]);
        fs::write(node.log(), &torn).unwrap();
        assert_eq!(store.log().unwrap(), entries);
        let next = LogEntry::Key {
            key: key(3),
            generated: false,
            store_id: 4,
        };
        store.append_log(&next).unwrap();
        let mut expected = entries.to_vec();
        expected.push(next);
        assert_eq!(store.log().unwrap(), expected);
        // A corrupt entry ends the log there (every later entry is dropped: the store-id check
        // then sees a mismatch, which is safe).
        let mut corrupt = fs::read(node.log()).unwrap();
        let second_start = full.len() / 2;
        corrupt[second_start + 10] ^= 0xFF;
        fs::write(node.log(), &corrupt).unwrap();
        assert!(store.log().unwrap().len() < expected.len());
        // An absurd length prefix is a corrupt tail too.
        fs::write(node.log(), u32::MAX.to_le_bytes()).unwrap();
        assert!(store.log().unwrap().is_empty());
        assert_eq!(parse_log(&[1, 2]).0, Vec::new());
    }

    #[test]
    fn helpers_create_durable_dirs_and_write_atomically() {
        let node = Node::new();
        let dir = node.dir.path().join("a").join("b");
        create_dir_durable(&NoFaults, &dir).unwrap();
        assert!(dir.is_dir());
        create_dir_durable(&NoFaults, &dir).unwrap();
        write_atomic(&NoFaults, &dir, "f", b"one").unwrap();
        // A failure before the rename keeps the old file.
        let fail = CrashAt::transient(4, enospc);
        assert!(write_atomic(&*fail, &dir, "f", b"two").is_err());
        assert_eq!(fs::read(dir.join("f")).unwrap(), b"one");
        write_atomic(&NoFaults, &dir, "f", b"three").unwrap();
        assert_eq!(fs::read(dir.join("f")).unwrap(), b"three");
        sync_dir(&NoFaults, &dir).unwrap();
        assert!(NoFaults.before(FsStep::Remove, &dir).is_ok());
    }

    /// `ENOSPC` and `EIO` at any step of a record write fail the write without leaving a
    /// partial record; the retry (the persistence worker's) succeeds.
    #[test]
    fn disk_errors_fail_writes_cleanly_and_retries_succeed() {
        let node = Node::new();
        let k = key(4);
        node.open().write(&I, &k, &record(I, &k, 1)).unwrap();
        let probe = CrashAt::crash(usize::MAX);
        node.open_faulty(probe.clone())
            .write(&I, &k, &record(I, &k, 2))
            .unwrap();
        let steps = probe.steps();
        assert!(steps >= 6, "temp, write, rest, sync, rename, dir sync");
        for error in [enospc, eio] {
            for at in 0..steps {
                let store = node.open_faulty(CrashAt::transient(at, error));
                let err = store.write(&I, &k, &record(I, &k, 5)).unwrap_err();
                assert!(matches!(err.raw_os_error(), Some(28 | 5)));
                assert!(matches!(assert_whole(&store, &I, &k), Some(2 | 5)));
                store.write(&I, &k, &record(I, &k, 5)).unwrap();
                assert_eq!(assert_whole(&store, &I, &k), Some(5));
                store.write(&I, &k, &record(I, &k, 2)).unwrap();
            }
        }
    }

    /// Crash matrix of a first boot under the operator's assertion (every key imported): a
    /// kill before each file-system step. Afterwards the record is never torn, an `(I, K)`
    /// entry never exists without the record, and the next boot — with the assertion again or
    /// without it — ends in a safe state: with it the key is installed; without it a record is
    /// present only if the crashed boot wrote it.
    #[test]
    fn crash_matrix_first_boot_with_assertion() {
        let crypto = FakeCrypto::new();
        let k = key(7);
        let keys = [(k.clone(), false)];
        let assertion = FreshKeyAssertion::from_operator_flag(true);
        let probe = CrashAt::crash(usize::MAX);
        {
            let node = Node::new();
            install(
                &node.open_faulty(probe.clone()),
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                assertion.as_ref(),
            )
            .unwrap();
        }
        let steps = probe.steps();
        assert!(steps > 20, "{steps} steps");
        for at in 0..steps {
            for again in [true, false] {
                let node = Node::new();
                let crashed = node.open_faulty(CrashAt::crash(at));
                assert!(
                    install(
                        &crashed,
                        &crypto,
                        &I,
                        iroha_sumeragi::testing::TEST_EPOCH.id,
                        &keys,
                        1,
                        assertion.as_ref()
                    )
                    .is_err()
                );
                drop(crashed);
                let store = node.open();
                let written = assert_whole(&store, &I, &k);
                assert!(
                    !started(&store, &I, &k) || written == Some(1),
                    "crash at {at}: an entry without its record"
                );
                let flag = FreshKeyAssertion::from_operator_flag(again);
                let got = install(
                    &store,
                    &crypto,
                    &I,
                    iroha_sumeragi::testing::TEST_EPOCH.id,
                    &keys,
                    1,
                    flag.as_ref(),
                )
                .unwrap();
                if again || written.is_some() {
                    assert_eq!(got[0].1, RecordState::Present(record(I, &k, 1)), "at {at}");
                } else {
                    assert_eq!(got[0].1, RecordState::Absent, "at {at}");
                }
                assert!(started(&store, &I, &k));
                assert_eq!(generated(&store, &k), Some(false), "an imported key");
            }
        }
    }

    /// Crash matrix of an installation event over a live record (a key store restored from a
    /// backup older than the `(I, K)` entry): whatever step the kill hits, the live record is
    /// never overwritten.
    #[test]
    fn crash_matrix_installation_never_overwrites_a_record() {
        let crypto = FakeCrypto::new();
        let k = key(8);
        let keys = [(k.clone(), false)];
        let live = record(I, &k, 9);
        let setup = |node: &Node| {
            let store = node.open();
            register_generated_key(&store, &k).unwrap();
            store.write(&I, &k, &live).unwrap();
        };
        let probe = CrashAt::crash(usize::MAX);
        {
            let node = Node::new();
            setup(&node);
            let flag = FreshKeyAssertion::from_operator_flag(true);
            install(
                &node.open_faulty(probe.clone()),
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                flag.as_ref(),
            )
            .unwrap();
        }
        for at in 0..probe.steps() {
            let node = Node::new();
            setup(&node);
            let flag = FreshKeyAssertion::from_operator_flag(true);
            let _ = install(
                &node.open_faulty(CrashAt::crash(at)),
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                flag.as_ref(),
            );
            let store = node.open();
            assert_eq!(assert_whole(&store, &I, &k), Some(9), "crash at {at}");
            let got = install(
                &store,
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                flag.as_ref(),
            )
            .unwrap();
            assert_eq!(
                got[0].1,
                RecordState::Present(live.clone()),
                "crash at {at}"
            );
        }
    }

    /// Crash matrix of the store-id check: two keys generated on the node, instance `I`
    /// started, then the record store is replaced (new disk). Whatever step a kill hits while
    /// the keys are marked imported, a later start of a new instance `J` writes no initial
    /// record for either key without the operator's assertion.
    #[test]
    fn crash_matrix_store_id_mismatch_marks_every_key_imported() {
        let crypto = FakeCrypto::new();
        let (a, b) = (key(1), key(2));
        let setup = |node: &Node| {
            let store = node.open();
            register_generated_key(&store, &a).unwrap();
            register_generated_key(&store, &b).unwrap();
            let got = install(
                &store,
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &[(a.clone(), false), (b.clone(), false)],
                1,
                None,
            )
            .unwrap();
            assert!(
                got.iter()
                    .all(|(_, s, _)| matches!(s, RecordState::Present(_)))
            );
            // A new, empty record store (new disk).
            fs::remove_dir_all(node.records()).unwrap();
            node.open();
        };
        let keys = [(a.clone(), false), (b.clone(), false)];
        let probe = CrashAt::crash(usize::MAX);
        {
            let node = Node::new();
            setup(&node);
            let got = install(
                &node.open_faulty(probe.clone()),
                &crypto,
                &J,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                None,
            )
            .unwrap();
            assert!(got.iter().all(|(_, s, _)| *s == RecordState::Absent));
        }
        for at in 0..probe.steps() {
            let node = Node::new();
            setup(&node);
            let _ = install(
                &node.open_faulty(CrashAt::crash(at)),
                &crypto,
                &J,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                None,
            );
            let store = node.open();
            let got = install(
                &store,
                &crypto,
                &J,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                None,
            )
            .unwrap();
            assert!(
                got.iter().all(|(_, s, _)| *s == RecordState::Absent),
                "crash at {at}: {got:?}"
            );
            assert_eq!(generated(&store, &a), Some(false), "crash at {at}");
            assert_eq!(generated(&store, &b), Some(false), "crash at {at}");
            // `I` was started: its records stay Absent (never re-created, rule 4).
            let got = install(
                &store,
                &crypto,
                &I,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &keys,
                1,
                None,
            )
            .unwrap();
            assert!(got.iter().all(|(_, s, _)| *s == RecordState::Absent));
        }
    }

    /// A key generated here gets its initial record at every instance it starts; registering
    /// it never hides a stale log (the store-id check runs first).
    #[test]
    fn generated_keys_install_automatically() {
        let crypto = FakeCrypto::new();
        let node = Node::new();
        let store = node.open();
        let (a, b) = (key(1), key(2));
        register_generated_key(&store, &a).unwrap();
        assert_eq!(generated(&store, &a), Some(true));
        for instance in [I, J] {
            let got = install(
                &store,
                &crypto,
                &instance,
                iroha_sumeragi::testing::TEST_EPOCH.id,
                &[(a.clone(), false)],
                1,
                None,
            )
            .unwrap();
            assert_eq!(got[0].1, RecordState::Present(record(instance, &a, 1)));
        }
        // The record store is replaced; registering another key first marks `a` imported.
        fs::remove_dir_all(node.records()).unwrap();
        let store = node.open();
        assert!(!store.instance_dir(&I).exists());
        register_generated_key(&store, &b).unwrap();
        assert_eq!(generated(&store, &a), Some(false));
        assert_eq!(generated(&store, &b), Some(true));
        let other = Hash32([0x33; 32]);
        let got = install(
            &store,
            &crypto,
            &other,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(a.clone(), false), (b.clone(), true)],
            1,
            None,
        )
        .unwrap();
        assert_eq!(got[0].1, RecordState::Absent);
        assert_eq!(got[1].1, RecordState::Present(record(other, &b, 1)));
        assert!(got[1].2, "retired flag passed through");
        assert_ne!(fresh_store_id(), fresh_store_id());
        assert!(FreshKeyAssertion::from_operator_flag(false).is_none());
    }

    #[test]
    fn log_entries_round_trip_through_norito() {
        for entry in [
            LogEntry::Key {
                key: key(5),
                generated: true,
                store_id: u128::MAX,
            },
            LogEntry::Instance {
                instance: J,
                key: key(6),
                store_id: 0,
            },
        ] {
            let bytes = encode_log_entry(&entry).unwrap();
            assert_eq!(parse_log(&bytes), (vec![entry], bytes.len() as u64));
        }
        let bad_key = LogEntryV1 {
            instance: None,
            key: Vec::new(),
            generated: false,
            store_id: 1,
        };
        assert_eq!(bad_key.into_entry(), None);
    }
}
