//! File-backed body store of the Sumeragi driver (`specs/sumeragi.md` §7.4 body durability,
//! §8.4, §12.3 O2): the bodies of blocks the core accepted and whose height is not applied yet.
//!
//! Layout: `<root>/bodies/<instance hex>/<height, 20 digits>/<block hash hex>`, each file the
//! canonical Norito encoding of the untrusted storage `BodyRecord`, written atomically (temp file,
//! fsync, no-clobber publication, directory fsync). A body already held for a block hash is never replaced.
//! [`BodyStore::prune_through`] drops every height at or below the applied height (the
//! committed body then lives in the block store).
//!
//! The store is bounded by [`BodyLimits::max_bytes`]: a body that would exceed it fails like a
//! full disk and is retried by the persistence worker until pruning frees space. Uncommitted
//! view churn can exhaust this finite capacity. Prepared bodies remain durable because a
//! delayed valid certificate can still require them; deleting superseded in-memory proposals
//! alone is not authority to evict their bodies. Capacity exhaustion stops persistence until
//! storage is recovered, preserving custody rather than silently discarding certified work.

use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use iroha_allocation::AllocationBudget;
use iroha_fs::OwnerDirectory;
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    types::Hash32,
};
use parking_lot::Mutex;
#[cfg(test)]
use std::fs;

use super::{
    body_read::{BodyReadError, BodyReadJob, BodyReader, FileBodyRead},
    body_record::PreparedBodyWrite,
    driver::{SharedCrypto, traits::BodyStore},
    durable_artifact,
    records::{Faults, FsStep, NoFaults},
};

/// Suffix of a temporary file before its rename (left behind only by a crash).
const TEMP_SUFFIX: &str = ".tmp";
const LOCK_NAME: &str = ".custody.lock";

/// Bounds of a body store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLimits {
    /// Largest total size of the stored body files, in bytes.
    pub max_bytes: u64,
}

impl Default for BodyLimits {
    /// Finite 1 GiB custody cap; prolonged uncommitted view churn can exhaust it.
    fn default() -> Self {
        Self { max_bytes: 1 << 30 }
    }
}

/// Largest body file accepted on read (far above the largest block the core accepts).
const MAX_BODY_FILE_BYTES: u64 = 80 * 1024 * 1024;

// The same prepared bytes and admitted height survive every publication refusal. Only an
// explicit local applied-height retirement may release that height while retaining the bytes.
struct PendingBodyPublication {
    prepared: PreparedBodyWrite,
    directory: Option<OwnerDirectory>,
}

/// The driver's [`BodyStore`] over files (see the module documentation).
pub struct FileBodyStore {
    // Configured spelling is diagnostic only; all native operations use original custody.
    dir: PathBuf,
    custody: BodyReadCustody,
    hasher: SharedCrypto,
    faults: Arc<dyn Faults>,
    limits: BodyLimits,
    instance: Hash32,
    execution_budget: AllocationBudget,
    pending_write: Mutex<Option<PendingBodyPublication>>,
    retirement_through: AtomicU64,
}

impl core::fmt::Debug for FileBodyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileBodyStore")
            .field("dir", &self.dir)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// The name of a height directory.
fn height_name(height: u64) -> String {
    format!("{height:020}")
}

/// The height of a height directory's name.
fn parse_height(name: &str) -> Option<u64> {
    (name.len() == 20 && name.bytes().all(|b| b.is_ascii_digit()))
        .then(|| name.parse().ok())
        .flatten()
}

// Retain the original directory and lock identity without holding a cross-operation lock.
// Each writer opens its own descriptor of that exact lock so separate handles serialize.
pub(super) struct BodyReadCustody {
    pub(super) directory: OwnerDirectory,
    lock: File,
}
impl BodyReadCustody {
    pub(super) fn revalidate(&self) -> io::Result<()> {
        self.directory.require_same_lock(LOCK_NAME, &self.lock)
    }
    fn retain(&self) -> io::Result<Self> {
        self.revalidate()?;
        let original = Self {
            directory: self.directory.retain()?,
            lock: self.lock.try_clone()?,
        };
        original.revalidate()?;
        Ok(original)
    }
    fn lock(&self) -> io::Result<File> {
        self.revalidate()?;
        // A new open is required: a duplicate of one locked description would not serialize
        // cooperative operations. Never create or replace this already selected lock file.
        let operation = self.directory.open_existing_lock(LOCK_NAME)?;
        self.directory.require_same_lock(LOCK_NAME, &operation)?;
        self.revalidate()?;
        operation.lock()?;
        self.directory.require_same_lock(LOCK_NAME, &operation)?;
        self.revalidate()?;
        Ok(operation)
    }
}

/// Sum durable body sizes under the original operation lock, streaming every original child.
fn scan(custody: &BodyReadCustody, clean_temps: bool) -> io::Result<u64> {
    let mut total = 0u64;
    custody.directory.visit_entries(|name| {
        custody.revalidate()?;
        if parse_height(&name.to_string_lossy()).is_none() {
            return Ok(());
        }
        let height = custody.directory.open_child(name)?;
        height.visit_entries(|name| {
            custody.revalidate()?;
            let file = height
                .open_regular_optional(name)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let length = file.metadata()?.len();
            height.require_same_regular_file(name, &file)?;
            drop(file);
            if name.to_string_lossy().ends_with(TEMP_SUFFIX) {
                if clean_temps {
                    height.remove_regular(name)?;
                }
            } else {
                total = total.checked_add(length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "body storage size overflow")
                })?;
            }
            Ok(())
        })
    })?;
    custody.revalidate()?;
    Ok(total)
}

impl FileBodyStore {
    /// Open (creating if needed) the body store of `instance` under `root`, hashing blocks
    /// with `hasher` (the node's `H`).
    ///
    /// # Errors
    /// An I/O failure.
    pub fn open(
        root: &Path,
        instance: &Hash32,
        hasher: SharedCrypto,
        limits: BodyLimits,
        execution_budget: AllocationBudget,
    ) -> io::Result<Self> {
        Self::open_with_faults(
            root,
            instance,
            hasher,
            limits,
            execution_budget,
            Arc::new(NoFaults),
        )
    }

    /// [`FileBodyStore::open`] with a fault-injection hook.
    ///
    /// # Errors
    /// An I/O failure.
    pub fn open_with_faults(
        root: &Path,
        instance: &Hash32,
        hasher: SharedCrypto,
        limits: BodyLimits,
        execution_budget: AllocationBudget,
        faults: Arc<dyn Faults>,
    ) -> io::Result<Self> {
        let dir = root.join("bodies").join(hex::encode(instance.0));
        durable_artifact::establish_dir(&*faults, &dir)?;
        let directory = OwnerDirectory::open(&dir)?;
        let lock = directory.open_lock(LOCK_NAME)?;
        let custody = BodyReadCustody { directory, lock };
        // This pin stays unlocked. The distinct operation descriptor owns initialization.
        let _guard = custody.lock()?;
        scan(&custody, true)?;
        custody.revalidate()?;
        Ok(Self {
            dir,
            custody,
            hasher,
            faults,
            limits,
            instance: *instance,
            execution_budget,
            pending_write: Mutex::new(None),
            retirement_through: AtomicU64::new(0),
        })
    }

    /// The directory of this instance's bodies.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file of the body of `(height, block_hash)`.
    pub fn body_path(&self, height: u64, block_hash: &Hash32) -> PathBuf {
        self.dir
            .join(height_name(height))
            .join(hex::encode(block_hash.0))
    }

    /// Total visible body bytes, including publication awaiting a successful durability retry.
    ///
    /// # Errors
    /// A lock or directory-read failure. Accounting errors are never treated as free space.
    pub fn bytes(&self) -> io::Result<u64> {
        let _guard = self.custody.lock()?;
        scan(&self.custody, false)
    }

    /// The heights that hold bodies, ascending.
    ///
    /// # Errors
    /// An I/O failure.
    pub fn heights(&self) -> io::Result<Vec<u64>> {
        let _guard = self.custody.lock()?;
        let mut heights = Vec::new();
        self.custody.directory.visit_entries(|name| {
            self.custody.revalidate()?;
            if let Some(height) = parse_height(&name.to_string_lossy()) {
                self.custody.directory.open_child(name)?.revalidate()?;
                heights.push(height);
            }
            Ok(())
        })?;
        self.custody.revalidate()?;
        heights.sort_unstable();
        Ok(heights)
    }
}

impl BodyStore for FileBodyStore {
    fn put(&self, block_hash: &Hash32, body: &AvailableBody) -> io::Result<()> {
        if body.header().instance != self.instance
            || body.header().hash(&*self.hasher) != *block_hash
            || !body.admitted_to(&self.execution_budget)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "body identity or original pool mismatch",
            ));
        }
        // Preparation and final byte retirement can refund this original pool. Every
        // physical guard must retire before an arbitrary waiter can reenter the store.
        self.execution_budget
            .with_deferred_refund_notifications(|_| {
                self.custody.revalidate()?;
                let mut pending = self.pending_write.lock();
                if let Some(original) = pending.as_ref() {
                    if original.prepared.body() != body {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "another original body awaits durable publication",
                        ));
                    }
                } else {
                    *pending = Some(PendingBodyPublication {
                        prepared: PreparedBodyWrite::new(body.clone()),
                        directory: None,
                    });
                }
                let original = pending.as_mut().expect("original prepared body retained");
                if let Some(directory) = &original.directory {
                    directory.revalidate()?;
                }
                let bytes = original
                    .prepared
                    .prepare(&self.execution_budget)
                    .map_err(io::Error::other)?;
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if len > MAX_BODY_FILE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "body exceeds the read limit",
                    ));
                }
                let _guard = self.custody.lock()?;
                let height = height_name(body.header().height);
                let name = hex::encode(block_hash.0);
                let candidate = if original.directory.is_none() {
                    self.custody.directory.open_child_optional(&height)?
                } else {
                    None
                };
                let held = match original.directory.as_ref().or(candidate.as_ref()) {
                    Some(directory) => durable_artifact::check_exact_in(directory, &name, bytes)?,
                    None => false,
                };
                if !held
                    && scan(&self.custody, false)?
                        .checked_add(len)
                        .is_none_or(|total| total > self.limits.max_bytes)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::StorageFull,
                        "sumeragi body store is full",
                    ));
                }
                let display = self.dir.join(&height);
                if original.directory.is_none() {
                    if let Some(directory) = candidate {
                        original.directory = Some(directory);
                    } else {
                        self.faults.before(FsStep::CreateDir, &display)?;
                        self.custody.revalidate()?;
                        original.directory = Some(self.custody.directory.ensure_child(&height)?);
                        self.faults.before(FsStep::SyncDir, &self.dir)?;
                        self.custody.revalidate()?;
                        self.custody.directory.sync()?;
                    }
                }
                durable_artifact::publish_in(
                    &*self.faults,
                    original
                        .directory
                        .as_ref()
                        .expect("retained publication height"),
                    &display,
                    &name,
                    bytes,
                    || self.custody.revalidate(),
                )?;
                self.custody.revalidate()?;
                *pending = None;
                Ok(())
            })
    }

    fn prune_through(&self, height: u64) -> io::Result<()> {
        // Match put's pending-owner then operation-lock order. Explicit retirement may
        // release a height handle, but never the pending original bytes or their funding.
        let mut pending = self.pending_write.lock();
        let _guard = self.custody.lock()?;
        // Publish local applied-height authority before removing any path. An open
        // read may race with removal, but must still verify the same source again
        // in committed storage. This frontier is never inferred from disk absence.
        self.retirement_through.fetch_max(height, Ordering::Release);
        if let Some(original) = pending.as_mut()
            && original.prepared.body().header().height <= height
        {
            original.directory = None;
        }
        self.custody.directory.visit_entries(|name| {
            self.custody.revalidate()?;
            let Some(h) = parse_height(&name.to_string_lossy()) else {
                return Ok(());
            };
            if h > height {
                return Ok(());
            }
            let directory = self.custody.directory.open_child(name)?;
            self.faults.before(FsStep::Remove, &self.dir.join(name))?;
            self.custody.revalidate()?;
            directory.visit_entries(|body| {
                self.custody.revalidate()?;
                directory.remove_regular(body)?;
                Ok(())
            })?;
            self.custody.revalidate()?;
            directory.remove_empty()
        })?;
        self.faults.before(FsStep::SyncDir, &self.dir)?;
        self.custody.revalidate()?;
        self.custody.directory.sync()?;
        self.custody.revalidate()
    }

    fn retirement_authorized(&self, height: u64) -> bool {
        height > 0 && height <= self.retirement_through.load(Ordering::Acquire)
    }
}

impl BodyReader for FileBodyStore {
    fn begin_read(
        &self,
        source: AvailabilitySource,
    ) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
        if source.instance() != self.instance {
            return Err(BodyReadError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "body read source belongs to another instance",
            )));
        }
        Ok(Box::new(FileBodyRead::open(
            self.custody.retain().map_err(BodyReadError::Io)?,
            source,
            MAX_BODY_FILE_BYTES as usize,
            self.execution_budget.clone(),
        )?))
    }
}

#[cfg(test)]
#[path = "bodies/tests.rs"]
mod tests;
