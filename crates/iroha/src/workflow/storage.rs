//! Caller-supplied journal storage: the trait, a non-durable memory store and a durable file store.
//!
//! Storage holds one opaque canonical record per workflow. It provides three
//! things the engine relies on: an atomic compare-and-swap keyed by the digest
//! of the record it replaces, an exclusive runner lease so that only one runner
//! owns the side effects of a workflow, and a load that returns exactly what was
//! last stored. Storage never interprets a record and never repairs one. The
//! only thing it reports about a record is that it is larger than any valid one.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::Path,
    sync::{Arc, Mutex},
};

use iroha_fs::{PrivateDirectory, PublishMode};

use super::{
    contract::MAX_WORKFLOW_JOURNAL_BYTES_V1,
    journal::{Digest32, WorkflowId, record_digest},
};

/// Why a storage call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowStorageErrorKind {
    /// The stored record is not the one the caller expected to replace.
    Conflict,
    /// Another runner holds the lease of this workflow.
    Busy,
    /// The store could not be read or written; nothing was changed.
    Unavailable,
    /// A write failed after it may have been published; the stored record is uncertain.
    WriteUncertain,
    /// The stored record is larger than any valid record: it is corrupted, not unreadable.
    Oversized,
}

/// Failure of a storage call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowStorageError {
    /// Failure class.
    pub kind: WorkflowStorageErrorKind,
    /// Diagnostic without record contents.
    pub detail: String,
}

impl WorkflowStorageError {
    /// Create a storage error.
    #[must_use]
    pub fn new(kind: WorkflowStorageErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for WorkflowStorageError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "workflow storage {:?}: {}",
            self.kind, self.detail
        )
    }
}

impl std::error::Error for WorkflowStorageError {}

/// Whether records survive the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowStorageDurability {
    /// Records survive process exit and power loss once a store returns.
    Durable,
    /// Records live only in this process. Suitable for tests, never for real workflows.
    NonDurable,
}

/// Exclusive ownership of one workflow's side effects, released on drop.
pub trait WorkflowRunnerLease: Send {}

/// Journal storage supplied by the caller.
///
/// Implementations must make [`Self::compare_and_store`] atomic against every
/// other process using the same store, must return only after the record is
/// durable (for a durable store), and must never write secret material of their
/// own into the record.
pub trait WorkflowStorage: Send + Sync {
    /// Whether records survive the process.
    fn durability(&self) -> WorkflowStorageDurability;

    /// Return the record last stored for `id`, or `None` when there is none.
    ///
    /// # Errors
    /// `Unavailable` when the store cannot be read and `Oversized` when the stored record
    /// exceeds the journal record bound.
    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError>;

    /// Atomically replace the record of `id`.
    ///
    /// `expected` is the [`record_digest`] of the record being replaced, or `None`
    /// when no record may exist yet.
    ///
    /// # Errors
    /// `Conflict` when the stored record differs from `expected`, `Unavailable` when
    /// nothing was written, `Oversized` when the stored record exceeds the journal record
    /// bound and `WriteUncertain` when the write may have been published.
    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError>;

    /// Take the exclusive runner lease of `id`.
    ///
    /// # Errors
    /// `Busy` when another runner holds it and `Unavailable` when it cannot be taken.
    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError>;
}

/// Process-local store. It is **not durable**: a workflow kept only here cannot
/// be resumed after the process exits, so it is for tests and examples only.
#[derive(Clone, Debug, Default)]
pub struct MemoryWorkflowStorage {
    records: Arc<Mutex<HashMap<Digest32, Vec<u8>>>>,
    runners: Arc<Mutex<HashSet<Digest32>>>,
}

struct MemoryLease {
    runners: Arc<Mutex<HashSet<Digest32>>>,
    id: Digest32,
}

impl WorkflowRunnerLease for MemoryLease {}

impl Drop for MemoryLease {
    fn drop(&mut self) {
        if let Ok(mut runners) = self.runners.lock() {
            runners.remove(&self.id);
        }
    }
}

impl MemoryWorkflowStorage {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored bytes without any check, to model corrupted or foreign storage.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn overwrite_unchecked(&self, id: &WorkflowId, record: Vec<u8>) {
        self.records
            .lock()
            .expect("workflow records lock")
            .insert(*id.as_bytes(), record);
    }
}

fn poisoned(what: &str) -> WorkflowStorageError {
    WorkflowStorageError::new(
        WorkflowStorageErrorKind::Unavailable,
        format!("{what} lock is poisoned"),
    )
}

impl WorkflowStorage for MemoryWorkflowStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        WorkflowStorageDurability::NonDurable
    }

    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| poisoned("records"))?
            .get(id.as_bytes())
            .cloned())
    }

    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        let mut records = self.records.lock().map_err(|_| poisoned("records"))?;
        let current = records.get(id.as_bytes()).map(|bytes| record_digest(bytes));
        if current.as_ref() != expected {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Conflict,
                "the stored record is not the expected one",
            ));
        }
        records.insert(*id.as_bytes(), record.to_vec());
        Ok(())
    }

    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        let mut runners = self.runners.lock().map_err(|_| poisoned("runners"))?;
        if !runners.insert(*id.as_bytes()) {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Busy,
                "another runner owns this workflow",
            ));
        }
        Ok(Box::new(MemoryLease {
            runners: Arc::clone(&self.runners),
            id: *id.as_bytes(),
        }))
    }
}

/// Durable store: one owner-private directory per workflow inside an owner-private root.
///
/// The directory of a workflow is named by its identifier and holds exactly three
/// files: `journal` (the record), `lock` (the interprocess lock around read,
/// compare and publish) and `runner` (the runner lease, held for the lifetime of a
/// run). Records are published atomically through [`iroha_fs::PrivateDirectory`]
/// (staged, synced, renamed, directory synced). A staging file that an interrupted
/// publish left behind is a full copy of a record, so it is removed under the
/// interprocess lock before the next record is read or published. A record
/// contains signed transaction bytes, public transcripts and custody references,
/// never a secret.
// TODO: Run the file store on Linux and on Windows; it has run on macOS only. The
// permission assertion below is `#[cfg(unix)]`, and the Windows paths of `iroha_fs`
// (access-control lists, lock files, replace-by-rename, staging reconciliation) were never
// exercised through this type. Commands, on each platform:
// `cargo test -p iroha --lib workflow::storage` and
// `cargo test -p iroha --lib workflow::engine_tests` (file-backed resume and custody tests).
#[derive(Debug)]
pub struct FileWorkflowStorage {
    directory: Mutex<PrivateDirectory>,
}

/// Name of the record file inside the directory of one workflow.
const JOURNAL_FILE: &str = "journal";
/// Name of the interprocess lock file around read, compare and publish.
const LOCK_FILE: &str = "lock";
/// Name of the runner lease file.
const RUNNER_FILE: &str = "runner";
/// Every name this store creates inside the directory of one workflow.
const WORKFLOW_FILES: [&str; 3] = [JOURNAL_FILE, LOCK_FILE, RUNNER_FILE];
/// Staging files of interrupted publishes that one reconciliation removes at most.
const MAX_STAGED_RECORDS: usize = 16;

struct FileLease {
    _lock: File,
}

impl WorkflowRunnerLease for FileLease {}

fn unavailable(what: &str, error: &io::Error) -> WorkflowStorageError {
    WorkflowStorageError::new(
        WorkflowStorageErrorKind::Unavailable,
        format!("{what}: {error}"),
    )
}

impl FileWorkflowStorage {
    /// Open or create the owner-private journal directory.
    ///
    /// # Errors
    /// Fails when the directory is not private to the current user or cannot be created.
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self, WorkflowStorageError> {
        let directory = PrivateDirectory::open_or_create(path)
            .map_err(|error| unavailable("open workflow journal directory", &error))?;
        Ok(Self {
            directory: Mutex::new(directory),
        })
    }

    /// Open the directory of one workflow, creating it when `create` is set.
    fn workflow_directory(
        &self,
        id: &WorkflowId,
        create: bool,
    ) -> Result<Option<PrivateDirectory>, WorkflowStorageError> {
        let root = self.directory.lock().map_err(|_| poisoned("directory"))?;
        let opened = if create {
            root.ensure_child(id.to_hex())
        } else {
            root.open_child(id.to_hex())
        };
        match opened {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable("open workflow directory", &error)),
        }
    }

    /// Take the interprocess lock of one workflow and remove interrupted staging files.
    ///
    /// The returned handle holds the lock until it is dropped.
    fn lock_and_reconcile(workflow: &PrivateDirectory) -> Result<File, WorkflowStorageError> {
        let lock = workflow
            .open_lock(LOCK_FILE)
            .map_err(|error| unavailable("open workflow journal lock", &error))?;
        lock.lock()
            .map_err(|error| unavailable("lock workflow journal", &error))?;
        Self::reconcile_staging(workflow)?;
        Ok(lock)
    }

    /// Remove the staging files an interrupted atomic publish left behind.
    ///
    /// Must run under the interprocess lock. A staging file is a complete copy of a
    /// record, signed bytes included, and would otherwise outlive the step that
    /// dropped those bytes. A name this store did not create is refused: nothing is
    /// removed and the store reports itself unavailable.
    fn reconcile_staging(workflow: &PrivateDirectory) -> Result<usize, WorkflowStorageError> {
        let names = workflow
            .entries(WORKFLOW_FILES.len() + MAX_STAGED_RECORDS)
            .map_err(|error| unavailable("list workflow directory", &error))?;
        let present = WORKFLOW_FILES
            .into_iter()
            .filter(|known| names.iter().any(|name| name.as_os_str() == *known))
            .collect::<Vec<_>>();
        if present.len() == names.len() {
            return Ok(0);
        }
        workflow
            .reconcile_atomic_staging(&present, MAX_STAGED_RECORDS, MAX_WORKFLOW_JOURNAL_BYTES_V1)
            .map_err(|error| unavailable("remove interrupted workflow journal staging", &error))
    }

    fn read(workflow: &PrivateDirectory) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        // The length is taken from the opened file before anything is allocated: a record
        // above the bound is corruption, never an unreadable store.
        let length = match workflow.open_read(JOURNAL_FILE) {
            Ok(file) => file
                .metadata()
                .map_err(|error| unavailable("inspect workflow journal", &error))?
                .len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable("open workflow journal", &error)),
        };
        if length > MAX_WORKFLOW_JOURNAL_BYTES_V1 as u64 {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Oversized,
                format!(
                    "journal record is {length} bytes, maximum {MAX_WORKFLOW_JOURNAL_BYTES_V1}"
                ),
            ));
        }
        match workflow.read(JOURNAL_FILE, MAX_WORKFLOW_JOURNAL_BYTES_V1) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable("read workflow journal", &error)),
        }
    }
}

impl WorkflowStorage for FileWorkflowStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        WorkflowStorageDurability::Durable
    }

    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        match self.workflow_directory(id, false)? {
            Some(workflow) => Self::read(&workflow),
            None => Ok(None),
        }
    }

    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        let Some(workflow) = self.workflow_directory(id, true)? else {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Unavailable,
                "the workflow directory could not be created",
            ));
        };
        let _lock = Self::lock_and_reconcile(&workflow)?;
        let current = Self::read(&workflow)?;
        if current.as_deref().map(record_digest).as_ref() != expected {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Conflict,
                "the stored record is not the expected one",
            ));
        }
        let mode = if current.is_some() {
            PublishMode::Replace
        } else {
            PublishMode::CreateNew
        };
        // `write_atomic` can fail after the new name is published, so its error does
        // not prove the old record is still there.
        workflow
            .write_atomic(JOURNAL_FILE, record, mode)
            .map_err(|error| {
                WorkflowStorageError::new(
                    WorkflowStorageErrorKind::WriteUncertain,
                    format!("publish workflow journal: {error}"),
                )
            })
    }

    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        let Some(workflow) = self.workflow_directory(id, true)? else {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Unavailable,
                "the workflow directory could not be created",
            ));
        };
        // The lease file is created under the interprocess lock, so the set of files in
        // the directory never changes while another process reconciles staging files.
        let lease = {
            let _lock = Self::lock_and_reconcile(&workflow)?;
            workflow
                .open_lock(RUNNER_FILE)
                .map_err(|error| unavailable("open workflow runner lease", &error))?
        };
        match lease.try_lock() {
            Ok(()) => Ok(Box::new(FileLease { _lock: lease })),
            Err(std::fs::TryLockError::WouldBlock) => Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Busy,
                "another runner owns this workflow",
            )),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(unavailable("take workflow runner lease", &error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> WorkflowId {
        WorkflowId::from_bytes([byte; 32])
    }

    fn exercise(storage: &dyn WorkflowStorage) {
        let workflow = id(7);
        assert_eq!(storage.load(&workflow).expect("load"), None);
        // A first record must not expect a predecessor.
        assert_eq!(
            storage
                .compare_and_store(&workflow, Some(&[1; 32]), b"first")
                .expect_err("no predecessor")
                .kind,
            WorkflowStorageErrorKind::Conflict
        );
        storage
            .compare_and_store(&workflow, None, b"first")
            .expect("create");
        assert_eq!(
            storage.load(&workflow).expect("load"),
            Some(b"first".to_vec())
        );
        // Creating again and replacing a stale record both lose.
        for expected in [None, Some(record_digest(b"stale"))] {
            assert_eq!(
                storage
                    .compare_and_store(&workflow, expected.as_ref(), b"second")
                    .expect_err("stale")
                    .kind,
                WorkflowStorageErrorKind::Conflict
            );
        }
        storage
            .compare_and_store(&workflow, Some(&record_digest(b"first")), b"second")
            .expect("replace");
        assert_eq!(
            storage.load(&workflow).expect("load"),
            Some(b"second".to_vec())
        );
        // Another workflow is independent.
        assert_eq!(storage.load(&id(8)).expect("load"), None);

        let lease = storage.acquire_runner(&workflow).expect("lease");
        assert_eq!(
            storage
                .acquire_runner(&workflow)
                .err()
                .expect("second runner")
                .kind,
            WorkflowStorageErrorKind::Busy
        );
        let _other = storage.acquire_runner(&id(8)).expect("independent lease");
        drop(lease);
        let _again = storage.acquire_runner(&workflow).expect("released lease");
    }

    #[test]
    fn memory_storage_is_a_non_durable_compare_and_swap_store() {
        let storage = MemoryWorkflowStorage::new();
        assert_eq!(storage.durability(), WorkflowStorageDurability::NonDurable);
        exercise(&storage);
        storage.overwrite_unchecked(&id(7), b"foreign".to_vec());
        assert_eq!(
            storage.load(&id(7)).expect("load"),
            Some(b"foreign".to_vec())
        );
    }

    #[test]
    fn file_storage_is_durable_private_and_survives_reopening() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("journals");
        let storage = FileWorkflowStorage::open_or_create(&path).expect("open");
        assert_eq!(storage.durability(), WorkflowStorageDurability::Durable);
        exercise(&storage);
        drop(storage);

        let reopened = FileWorkflowStorage::open_or_create(&path).expect("reopen");
        assert_eq!(
            reopened.load(&id(7)).expect("load"),
            Some(b"second".to_vec())
        );
        // One directory per workflow, holding exactly the record, its lock and the lease.
        let mut names = std::fs::read_dir(workflow_path(&path, 7))
            .expect("workflow directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, WORKFLOW_FILES);
        // TODO: Assert owner-only access on Windows (access-control list of the record,
        // lock and lease files); run `cargo test -p iroha --lib workflow::storage` there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for target in [
                workflow_path(&path, 7),
                workflow_path(&path, 7).join(JOURNAL_FILE),
            ] {
                let mode = std::fs::metadata(target)
                    .expect("metadata")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o077, 0, "journal must be private to its owner");
            }
        }
    }

    fn workflow_path(root: &Path, byte: u8) -> std::path::PathBuf {
        root.join(id(byte).to_hex())
    }

    /// Create a file with owner-only access inside the directory of a workflow.
    fn private_file(path: &Path, bytes: &[u8]) -> File {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).expect("create private file");
        io::Write::write_all(&mut file, bytes).expect("write private file");
        file
    }

    #[test]
    fn a_journal_file_above_the_record_bound_is_oversized_not_unreadable() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("journals");
        let storage = FileWorkflowStorage::open_or_create(&path).expect("open");
        storage
            .compare_and_store(&id(5), None, b"record")
            .expect("create");
        let journal = workflow_path(&path, 5).join(JOURNAL_FILE);
        for excess in [1_u64, 2, 4_096] {
            // A sparse file of the wanted length: nothing above the bound is ever read.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&journal)
                .expect("journal")
                .set_len(MAX_WORKFLOW_JOURNAL_BYTES_V1 as u64 + excess)
                .expect("extend");
            let error = storage.load(&id(5)).expect_err("oversized");
            assert_eq!(error.kind, WorkflowStorageErrorKind::Oversized, "{excess}");
            assert!(error.detail.contains("maximum 16777216"));
            // A compare-and-swap never replaces a record it could not read.
            assert_eq!(
                storage
                    .compare_and_store(&id(5), Some(&record_digest(b"record")), b"next")
                    .expect_err("oversized")
                    .kind,
                WorkflowStorageErrorKind::Oversized
            );
        }
        // Exactly at the bound the record is read and handed to the journal decoder.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .expect("journal")
            .set_len(MAX_WORKFLOW_JOURNAL_BYTES_V1 as u64)
            .expect("shrink");
        assert_eq!(
            storage
                .load(&id(5))
                .expect("at the bound")
                .map(|record| record.len()),
            Some(MAX_WORKFLOW_JOURNAL_BYTES_V1)
        );
    }

    #[test]
    fn staging_files_of_an_interrupted_publish_are_removed_before_the_next_store() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("journals");
        let storage = FileWorkflowStorage::open_or_create(&path).expect("open");
        storage
            .compare_and_store(&id(4), None, b"first")
            .expect("create");
        let workflow = workflow_path(&path, 4);
        // What a process that died inside an atomic publish leaves: complete copies of
        // records, here holding signed bytes of a step that has since dropped them.
        let staged = [
            workflow.join(".iroha-fs-4242-0.tmp"),
            workflow.join(".iroha-fs-4242-7.tmp"),
        ];
        for name in &staged {
            private_file(name, b"signed:stale-transaction-bytes");
        }
        // Reading changes nothing: only the holder of the interprocess lock removes files.
        assert_eq!(storage.load(&id(4)).expect("load"), Some(b"first".to_vec()));
        assert!(staged.iter().all(|name| name.exists()));

        storage
            .compare_and_store(&id(4), Some(&record_digest(b"first")), b"second")
            .expect("replace");
        assert!(staged.iter().all(|name| !name.exists()));
        assert_eq!(
            storage.load(&id(4)).expect("load"),
            Some(b"second".to_vec())
        );
        for entry in std::fs::read_dir(&workflow).expect("workflow directory") {
            let bytes = std::fs::read(entry.expect("entry").path()).expect("file");
            assert!(
                !bytes
                    .windows(b"stale-transaction".len())
                    .any(|window| window == b"stale-transaction")
            );
        }

        // Taking the runner lease reconciles too, and a lost compare-and-swap still cleans.
        private_file(&staged[0], b"signed:stale-transaction-bytes");
        let lease = storage.acquire_runner(&id(4)).expect("lease");
        assert!(!staged[0].exists());
        private_file(&staged[1], b"signed:stale-transaction-bytes");
        assert_eq!(
            storage
                .compare_and_store(&id(4), Some(&record_digest(b"stale")), b"third")
                .expect_err("stale expectation")
                .kind,
            WorkflowStorageErrorKind::Conflict
        );
        assert!(!staged[1].exists());
        drop(lease);
    }

    #[test]
    fn a_file_the_store_did_not_create_is_refused_and_nothing_is_removed() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("journals");
        let storage = FileWorkflowStorage::open_or_create(&path).expect("open");
        storage
            .compare_and_store(&id(6), None, b"first")
            .expect("create");
        let workflow = workflow_path(&path, 6);
        let foreign = workflow.join("notes.txt");
        let staged = workflow.join(".iroha-fs-4242-1.tmp");
        private_file(&foreign, b"not a journal");
        private_file(&staged, b"staged");
        let error = storage
            .compare_and_store(&id(6), Some(&record_digest(b"first")), b"second")
            .expect_err("unknown inventory");
        assert_eq!(error.kind, WorkflowStorageErrorKind::Unavailable);
        assert!(foreign.exists() && staged.exists());
        assert_eq!(storage.load(&id(6)).expect("load"), Some(b"first".to_vec()));
        assert_eq!(
            storage.acquire_runner(&id(6)).err().expect("refused").kind,
            WorkflowStorageErrorKind::Unavailable
        );
        // A name that only resembles a staging name is foreign as well.
        std::fs::remove_file(&foreign).expect("remove");
        std::fs::remove_file(&staged).expect("remove");
        let lookalike = workflow.join(".iroha-fs-0-1.tmp");
        private_file(&lookalike, b"staged");
        assert_eq!(
            storage
                .compare_and_store(&id(6), Some(&record_digest(b"first")), b"second")
                .expect_err("lookalike")
                .kind,
            WorkflowStorageErrorKind::Unavailable
        );
        assert!(lookalike.exists());
    }

    #[test]
    fn file_runner_lease_excludes_a_second_store_on_the_same_directory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("journals");
        let first = FileWorkflowStorage::open_or_create(&path).expect("open");
        let second = FileWorkflowStorage::open_or_create(&path).expect("open again");
        let lease = first.acquire_runner(&id(3)).expect("lease");
        assert_eq!(
            second
                .acquire_runner(&id(3))
                .err()
                .expect("held by the first store")
                .kind,
            WorkflowStorageErrorKind::Busy
        );
        drop(lease);
        let _lease = second.acquire_runner(&id(3)).expect("released");
    }

    #[test]
    fn storage_error_display_names_the_class() {
        let error = WorkflowStorageError::new(WorkflowStorageErrorKind::WriteUncertain, "rename");
        assert_eq!(error.to_string(), "workflow storage WriteUncertain: rename");
        assert_eq!(
            poisoned("records").kind,
            WorkflowStorageErrorKind::Unavailable
        );
        let io_error = io::Error::other("disk");
        assert!(unavailable("read", &io_error).detail.contains("disk"));
    }
}
