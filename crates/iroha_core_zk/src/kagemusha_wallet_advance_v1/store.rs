//! Durable custody store: create-new publication, same-content rewrite, removal, syncs and
//! fail-closed listings over one custody root (G2 design rev 2 §2 "Primitives").
//!
//! [`KagemushaWalletDurableStoreV1`] composes the single steps of a
//! [`KagemushaWalletFsV1`] backend into primitives with explicit outcomes. The algorithm is
//! the same for every backend, so the simulator's fault matrices exercise the production
//! publication sequence:
//!
//! - **create-new** ([`KagemushaWalletDurableStoreV1::write_new`]): exclusive staging file,
//!   write, `sync_all`, `RENAME_NOREPLACE`, parent `sync_all`. Failures before the rename are
//!   `NotPublished` (the staging file is discarded); `EEXIST` from the rename is
//!   `DestinationExists`; an indeterminate rename error or any failure after the rename is
//!   `Uncertain`. Staging-name exhaustion is never `DestinationExists`; entropy failure
//!   is `NotPublished` before file creation, with no fallback name.
//! - **pair** ([`KagemushaWalletDurableStoreV1::write_new_pair`]): two staged files, two
//!   syncs, two create-new renames and one parent sync; the outcome is reported per name.
//! - **same-content rewrite** ([`KagemushaWalletDurableStoreV1::rewrite_same`]): publishes
//!   byte-identical content on a fresh inode with an atomic replacing rename, so a file whose
//!   earlier sync reported (and lost) a writeback error becomes durable.
//! - **removal** ([`KagemushaWalletDurableStoreV1::remove_file`]): unlink, then parent sync;
//!   an already-absent name is synced as absent. Empty directories are removed the same way
//!   ([`KagemushaWalletDurableStoreV1::remove_dir`]).
//! - **reads and listings** report only initial native-open absence as `Absent`;
//!   later custody/read failures are unavailable, and any entry error fails a whole listing.
//!
//! The mutating primitives are private to the provider: other code gets custody only through
//! the provider's operations.
//!
//! Every primitive counts its calls, and times its syncs by class, in the calling thread's
//! [`super::KagemushaWalletStorageCountersV1`]. The counters only observe; no outcome reads them.
//!
//! [`KagemushaWalletStdFsV1`] uses retained native Unix/Windows custody. `KagemushaWalletSimFsV1`
//! (tests and the `test-utils` feature) keeps visible and durable state separately for file
//! data and directory entries, injects deterministic faults at every step, and simulates
//! process crashes, restarts and power loss.
// Native descriptor custody is provided by `iroha_fs::PrivateDirectory`; this adapter keeps
// the G2 split write/sync/rename boundaries used by the deterministic fault simulator.

use std::io;

use super::{
    KagemushaWalletProviderErrorV1,
    counters::{self, EventV1, SyncClassV1},
    layout::{
        KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1,
        kagemusha_wallet_is_staging_name_v1, kagemusha_wallet_require_removed_v1,
    },
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletListedEntryV1,
        KagemushaWalletNotPublishedV1, KagemushaWalletProbeV1, KagemushaWalletPublishOutcomeV1,
        KagemushaWalletReadV1, KagemushaWalletRemoveOutcomeV1, KagemushaWalletUnavailableV1,
    },
};

/// Staging-name attempts before a create-new write gives up.
const STAGING_ATTEMPTS: u32 = 8;

/// Format a random candidate only after a successful, fallible entropy read.
/// Exclusive creation and retained descriptors establish custody, not the name itself.
fn staging_name_with_entropy(
    fill: impl FnOnce(&mut [u8; 16]) -> io::Result<()>,
) -> io::Result<String> {
    let mut random = [0_u8; 16];
    fill(&mut random)?;
    Ok(format!(
        "{}{}",
        super::layout::KAGEMUSHA_WALLET_STAGING_PREFIX_V1,
        super::layout::lower_hex(&random)
    ))
}

/// Durable custody store over one filesystem backend.
#[derive(Debug, Clone)]
pub struct KagemushaWalletDurableStoreV1<F> {
    fs: F,
}

/// Rename step of a publication.
enum RenameStepV1 {
    Renamed,
    Done(KagemushaWalletPublishOutcomeV1),
}

/// Failure class of one filesystem error.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureClassV1 {
    Exists,
    Unsupported,
    NoSpace,
    Definitive,
    Indeterminate,
}

fn classify(error: &io::Error) -> FailureClassV1 {
    use io::ErrorKind as K;
    match error.kind() {
        K::AlreadyExists => FailureClassV1::Exists,
        K::Unsupported | K::InvalidInput => FailureClassV1::Unsupported,
        K::StorageFull | K::QuotaExceeded => FailureClassV1::NoSpace,
        K::PermissionDenied
        | K::ReadOnlyFilesystem
        | K::NotFound
        | K::NotADirectory
        | K::IsADirectory
        | K::CrossesDevices
        | K::InvalidFilename
        | K::ResourceBusy
        | K::DirectoryNotEmpty => FailureClassV1::Definitive,
        _ => FailureClassV1::Indeterminate,
    }
}

fn unavailable(error: &io::Error) -> KagemushaWalletUnavailableV1 {
    KagemushaWalletUnavailableV1::from_io(error)
}

fn not_published(error: &io::Error) -> KagemushaWalletNotPublishedV1 {
    if classify(error) == FailureClassV1::NoSpace {
        KagemushaWalletNotPublishedV1::NoSpace
    } else {
        KagemushaWalletNotPublishedV1::Failed(unavailable(error))
    }
}

// Retain the exact writer across the rename boundary. Native publication validates that
// the staging name still identifies this original descriptor, even if a path was replaced.
struct StagedV1<T> {
    name: String,
    _file: T,
}
impl<T> std::ops::Deref for StagedV1<T> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.name
    }
}

impl<F: KagemushaWalletFsV1> KagemushaWalletDurableStoreV1<F> {
    /// Store over `fs`.
    pub(super) fn new(fs: F) -> Self {
        Self { fs }
    }

    /// The filesystem backend (tests).
    #[cfg(test)]
    pub fn fs(&self) -> &F {
        &self.fs
    }

    /// Publish `bytes` under a new `name` in `dir` (create-new; never replaces).
    pub(super) fn write_new(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
        bytes: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        counters::count(EventV1::WriteNew(1));
        let staged = match self.stage(dir, bytes) {
            Ok(staged) => staged,
            Err(reason) => return KagemushaWalletPublishOutcomeV1::NotPublished(reason),
        };
        match self.rename_new(dir, &staged, name.as_str()) {
            RenameStepV1::Renamed => self.sync_after_publish(dir),
            RenameStepV1::Done(outcome) => outcome,
        }
    }

    /// Publish two new names in `dir` with one parent sync; outcomes in argument order.
    pub(super) fn write_new_pair(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        first: (&KagemushaWalletEntryNameV1, &[u8]),
        second: (&KagemushaWalletEntryNameV1, &[u8]),
    ) -> [KagemushaWalletPublishOutcomeV1; 2] {
        counters::count(EventV1::WriteNew(2));
        let first_staged = match self.stage(dir, first.1) {
            Ok(staged) => staged,
            Err(reason) => return [KagemushaWalletPublishOutcomeV1::NotPublished(reason); 2],
        };
        let second_staged = match self.stage(dir, second.1) {
            Ok(staged) => staged,
            Err(reason) => {
                self.discard_staged(dir, &first_staged);
                return [KagemushaWalletPublishOutcomeV1::NotPublished(reason); 2];
            }
        };
        let steps = [
            self.rename_new(dir, &first_staged, first.0.as_str()),
            self.rename_new(dir, &second_staged, second.0.as_str()),
        ];
        let synced = steps
            .iter()
            .any(|step| matches!(step, RenameStepV1::Renamed))
            .then(|| {
                counters::sync(SyncClassV1::Publish, || self.fs.sync_dir(dir))
                    .map_err(|error| unavailable(&error))
            });
        steps.map(|step| match (step, synced) {
            (RenameStepV1::Done(outcome), _) => outcome,
            (RenameStepV1::Renamed, Some(Ok(()))) => KagemushaWalletPublishOutcomeV1::Published,
            (RenameStepV1::Renamed, Some(Err(reason))) => {
                KagemushaWalletPublishOutcomeV1::Uncertain(reason)
            }
            (RenameStepV1::Renamed, None) => {
                KagemushaWalletPublishOutcomeV1::Uncertain(KagemushaWalletUnavailableV1::Io(0))
            }
        })
    }

    /// Republish the byte-identical content of `name` on a fresh inode (atomic replace).
    ///
    /// Refuses (`ContentMismatch`, `DestinationAbsent`) unless `name` currently holds exactly
    /// `bytes`; the name holds those bytes on every outcome.
    pub(super) fn rewrite_same(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
        bytes: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        self.replace_exact(dir, name, bytes, bytes)
    }

    /// Replace the exact current content `expected` of `name` with `bytes` on a fresh inode:
    /// staged, synced, atomically renamed over the name, parent synced (the same sequence as
    /// [`Self::rewrite_same`]). Only the exclusive custody owner calls it, for a replace-only
    /// record whose every version is complete; the name holds `expected` or `bytes` on every
    /// outcome.
    ///
    /// Refuses (`ContentMismatch`, `DestinationAbsent`) unless `name` currently holds exactly
    /// `expected`.
    pub(super) fn replace_exact(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
        expected: &[u8],
        bytes: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        counters::count(if expected == bytes {
            EventV1::RewriteSame
        } else {
            EventV1::ReplaceExact
        });
        match self.read(dir, name, expected.len()) {
            KagemushaWalletReadV1::Present(existing) if existing == expected => {}
            KagemushaWalletReadV1::Present(_) | KagemushaWalletReadV1::Oversized => {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::ContentMismatch,
                );
            }
            KagemushaWalletReadV1::Absent => {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::DestinationAbsent,
                );
            }
            KagemushaWalletReadV1::Unavailable(reason) => {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::Failed(reason),
                );
            }
        }
        let staged = match self.stage(dir, bytes) {
            Ok(staged) => staged,
            Err(reason) => return KagemushaWalletPublishOutcomeV1::NotPublished(reason),
        };
        if let Err(error) = self.fs.rename_replace(dir, &staged, name.as_str()) {
            self.discard_staged(dir, &staged);
            return match classify(&error) {
                FailureClassV1::NoSpace => KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::NoSpace,
                ),
                FailureClassV1::Definitive
                | FailureClassV1::Exists
                | FailureClassV1::Unsupported => KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::Failed(unavailable(&error)),
                ),
                FailureClassV1::Indeterminate => {
                    KagemushaWalletPublishOutcomeV1::Uncertain(unavailable(&error))
                }
            };
        }
        self.sync_after_publish(dir)
    }

    /// Durably remove `name` from `dir`; an absent name is synced as absent.
    pub(super) fn remove_file(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
    ) -> KagemushaWalletRemoveOutcomeV1 {
        counters::count(EventV1::Removal);
        match self.fs.unlink(dir, name.as_str()) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return if classify(&error) == FailureClassV1::Definitive {
                    KagemushaWalletRemoveOutcomeV1::NotRemoved(unavailable(&error))
                } else {
                    KagemushaWalletRemoveOutcomeV1::Uncertain(unavailable(&error))
                };
            }
        }
        match counters::sync(SyncClassV1::Dir, || self.fs.sync_dir(dir)) {
            Ok(()) => KagemushaWalletRemoveOutcomeV1::Removed,
            Err(error) => KagemushaWalletRemoveOutcomeV1::Uncertain(unavailable(&error)),
        }
    }

    /// Durably create directory `name` in `parent`. An existing entry is reported as
    /// `DestinationExists` after the parent is synced.
    pub(super) fn create_dir(
        &self,
        parent: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
    ) -> KagemushaWalletPublishOutcomeV1 {
        match self.fs.mkdir(parent, name.as_str()) {
            Ok(()) => self.sync_after_publish(parent),
            Err(error) => match classify(&error) {
                FailureClassV1::Exists => match counters::sync(SyncClassV1::Dir, || {
                    self.fs.sync_dir(parent)
                }) {
                    Ok(()) => KagemushaWalletPublishOutcomeV1::NotPublished(
                        KagemushaWalletNotPublishedV1::DestinationExists,
                    ),
                    Err(error) => KagemushaWalletPublishOutcomeV1::Uncertain(unavailable(&error)),
                },
                FailureClassV1::NoSpace => KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::NoSpace,
                ),
                FailureClassV1::Definitive | FailureClassV1::Unsupported => {
                    KagemushaWalletPublishOutcomeV1::NotPublished(
                        KagemushaWalletNotPublishedV1::Failed(unavailable(&error)),
                    )
                }
                FailureClassV1::Indeterminate => {
                    KagemushaWalletPublishOutcomeV1::Uncertain(unavailable(&error))
                }
            },
        }
    }

    /// Durably remove the empty directory `name` from `parent`; an absent name is synced as
    /// absent. A directory that holds entries is never removed (`NotRemoved`).
    pub(super) fn remove_dir(
        &self,
        parent: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
    ) -> KagemushaWalletRemoveOutcomeV1 {
        counters::count(EventV1::Removal);
        match self.fs.remove_dir(parent, name.as_str()) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return if classify(&error) == FailureClassV1::Definitive {
                    KagemushaWalletRemoveOutcomeV1::NotRemoved(unavailable(&error))
                } else {
                    KagemushaWalletRemoveOutcomeV1::Uncertain(unavailable(&error))
                };
            }
        }
        match counters::sync(SyncClassV1::Dir, || self.fs.sync_dir(parent)) {
            Ok(()) => KagemushaWalletRemoveOutcomeV1::Removed,
            Err(error) => KagemushaWalletRemoveOutcomeV1::Uncertain(unavailable(&error)),
        }
    }

    /// Sync an existing file's data and metadata.
    ///
    /// # Errors
    ///
    /// Returns the reason; durability is then unknown.
    pub(super) fn sync_file(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
    ) -> Result<(), KagemushaWalletUnavailableV1> {
        counters::sync(SyncClassV1::File, || self.fs.sync_named(dir, name.as_str()))
            .map_err(|error| unavailable(&error))
    }

    /// Sync directory `dir`.
    ///
    /// # Errors
    ///
    /// Returns the reason; durability of its entries is then unknown.
    pub(super) fn sync_dir(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> Result<(), KagemushaWalletUnavailableV1> {
        counters::sync(SyncClassV1::Dir, || self.fs.sync_dir(dir))
            .map_err(|error| unavailable(&error))
    }

    /// Read `name` with a bound of `max` bytes.
    pub fn read(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
        max: usize,
    ) -> KagemushaWalletReadV1 {
        counters::count(EventV1::Read);
        match self.fs.read(dir, name.as_str(), max.saturating_add(1)) {
            Ok(bytes) if bytes.len() > max => KagemushaWalletReadV1::Oversized,
            Ok(bytes) => KagemushaWalletReadV1::Present(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => KagemushaWalletReadV1::Absent,
            Err(error) => KagemushaWalletReadV1::Unavailable(unavailable(&error)),
        }
    }

    /// Complete listing of `dir`, sorted by name; any entry error fails the listing.
    pub fn list(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> KagemushaWalletProbeV1<Vec<KagemushaWalletListedEntryV1>> {
        counters::count(EventV1::Listing);
        match self.fs.list(dir) {
            Ok(mut entries) => {
                entries.sort_by(|left, right| left.name.cmp(&right.name));
                KagemushaWalletProbeV1::Present(entries)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => KagemushaWalletProbeV1::Absent,
            Err(error) => KagemushaWalletProbeV1::Unavailable(unavailable(&error)),
        }
    }

    /// Bytes available on the custody filesystem.
    ///
    /// # Errors
    ///
    /// Returns the reason it cannot be read.
    pub fn available_bytes(&self) -> Result<u64, KagemushaWalletUnavailableV1> {
        self.fs
            .available_bytes()
            .map_err(|error| unavailable(&error))
    }

    /// Take the exclusive custody lock; `Busy` when another opener holds it.
    ///
    /// # Errors
    ///
    /// `Busy` when held elsewhere; `Io` for every other lock error. Never proceeds unlocked.
    pub(super) fn lock_exclusive(&self) -> Result<F::Lock, KagemushaWalletUnavailableV1> {
        self.fs.try_lock().map_err(|error| unavailable(&error))
    }

    /// Durably remove this store's staging files from `dir` (reconcile step R1). Every other
    /// entry is left untouched. Returns the number removed.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the listing or a removal fails and `Uncertain` when a removal's
    /// outcome is unknown.
    pub(super) fn remove_staging(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> Result<usize, KagemushaWalletProviderErrorV1> {
        let Some(entries) = self.list(dir).into_result()? else {
            return Ok(0);
        };
        let mut removed = 0_usize;
        for entry in entries {
            if entry.kind != KagemushaWalletEntryKindV1::File
                || !kagemusha_wallet_is_staging_name_v1(&entry.name)
            {
                continue;
            }
            let name = KagemushaWalletEntryNameV1::new(&entry.name).ok_or(
                KagemushaWalletProviderErrorV1::Invalid {
                    field: "staging name",
                },
            )?;
            kagemusha_wallet_require_removed_v1(self.remove_file(dir, &name))?;
            removed = removed
                .checked_add(1)
                .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                    field: "staging count",
                })?;
        }
        Ok(removed)
    }

    /// Write and sync bytes while retaining the exact staged descriptor through publication.
    fn stage(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        bytes: &[u8],
    ) -> Result<StagedV1<F::StagedFile>, KagemushaWalletNotPublishedV1> {
        let mut collisions = 0_u32;
        let (staged, mut file) = loop {
            let staged = self
                .fs
                .staging_name()
                .map_err(|error| not_published(&error))?;
            match self.fs.create_new(dir, &staged) {
                Ok(file) => break (staged, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    collisions = collisions.saturating_add(1);
                    if collisions >= STAGING_ATTEMPTS {
                        // Exhausted staging names are a failure, never `DestinationExists`.
                        return Err(KagemushaWalletNotPublishedV1::Failed(unavailable(&error)));
                    }
                }
                Err(error) => return Err(not_published(&error)),
            }
        };
        let result = self
            .fs
            .write_all(&mut file, bytes)
            .and_then(|()| counters::sync(SyncClassV1::Staged, || self.fs.sync_staged(&file)))
            .map_err(|error| not_published(&error));
        if let Err(reason) = result {
            drop(file);
            self.discard_staged(dir, &staged);
            return Err(reason);
        }
        Ok(StagedV1 {
            name: staged,
            _file: file,
        })
    }

    fn rename_new(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        staged: &str,
        name: &str,
    ) -> RenameStepV1 {
        let Err(error) = self.fs.rename_noreplace(dir, staged, name) else {
            return RenameStepV1::Renamed;
        };
        let outcome = match classify(&error) {
            FailureClassV1::Exists => KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists,
            ),
            FailureClassV1::Unsupported => KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::NoReplaceUnsupported,
            ),
            FailureClassV1::NoSpace => KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::NoSpace,
            ),
            FailureClassV1::Definitive => KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::Failed(unavailable(&error)),
            ),
            FailureClassV1::Indeterminate => {
                KagemushaWalletPublishOutcomeV1::Uncertain(unavailable(&error))
            }
        };
        // Removing the staging name is safe on every outcome: after a rename it is absent.
        self.discard_staged(dir, staged);
        RenameStepV1::Done(outcome)
    }

    fn sync_after_publish(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> KagemushaWalletPublishOutcomeV1 {
        match counters::sync(SyncClassV1::Publish, || self.fs.sync_dir(dir)) {
            Ok(()) => KagemushaWalletPublishOutcomeV1::Published,
            Err(error) => KagemushaWalletPublishOutcomeV1::Uncertain(unavailable(&error)),
        }
    }

    /// Best-effort removal of a staging file; reconcile removes any that remain.
    fn discard_staged(&self, dir: &KagemushaWalletCustodyDirV1, staged: &str) {
        let _ = self.fs.unlink(dir, staged);
    }
}

// ---------------------------------------------------------------------------------------
// std::fs backend
// ---------------------------------------------------------------------------------------

pub use self::std_fs::{KagemushaWalletStdFsLockV1, KagemushaWalletStdFsV1};

mod std_fs {
    use super::super::{
        layout::{KAGEMUSHA_WALLET_LOCK_NAME_V1, KagemushaWalletCustodyDirV1},
        platform::{
            KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletListedEntryV1,
            KagemushaWalletNotPublishedV1, KagemushaWalletPublishOutcomeV1,
            KagemushaWalletUnavailableV1,
        },
    };
    use iroha_fs::{CustodyEntryKind, OwnerDirectory, PrivateDirectory, PublishMode, RetainedFile};
    use std::{
        collections::BTreeMap,
        fs::{File, TryLockError},
        io::{self, Read as _, Write as _},
        path::{Path, PathBuf},
        sync::{Arc, Mutex, Weak},
    };

    type DirectoryCache = Mutex<BTreeMap<Vec<String>, Arc<PrivateDirectory>>>;
    #[cfg(windows)]
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    type OriginalStaging = Mutex<Option<RetainedFile>>;
    type StagingCache = Mutex<BTreeMap<(Vec<String>, String), Weak<OriginalStaging>>>;
    /// Retained native custody. The root and each visited child retain their exact
    /// ancestor identities across operations; no pathname reopening can adopt a replacement.
    #[derive(Debug, Clone)]
    pub struct KagemushaWalletStdFsV1 {
        root: Arc<PrivateDirectory>,
        path: PathBuf,
        directories: Arc<DirectoryCache>,
        staging: Arc<StagingCache>,
        // A consumed child that failed removal can never be reopened as replacement custody.
        #[cfg(windows)]
        removal_uncertain: Arc<Mutex<BTreeSet<Vec<String>>>>,
    }
    /// Exclusive ownership lock retaining the same root custody for its whole lifetime.
    #[derive(Debug)]
    pub struct KagemushaWalletStdFsLockV1 {
        _file: File,
        _root: Arc<PrivateDirectory>,
    }
    /// Original staged descriptor and identity; publication must still name this exact inode.
    #[derive(Debug)]
    pub struct KagemushaWalletStdFsStagedV1 {
        file: Arc<OriginalStaging>,
    }
    fn custody_changed(error: io::Error) -> io::Error {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::other("retained custody path disappeared")
        } else {
            error
        }
    }
    fn poisoned() -> io::Error {
        io::Error::other("custody handle poisoned")
    }
    fn components(dir: &KagemushaWalletCustodyDirV1) -> Vec<String> {
        dir.components().to_vec()
    }
    impl KagemushaWalletStdFsV1 {
        /// Open one existing owner-private custody root, retaining all native ancestors.
        ///
        /// # Errors
        /// Missing or unsafe roots, symlinks, replaced ancestors and genuine native errors.
        pub fn open(root: impl Into<PathBuf>) -> Result<Self, KagemushaWalletUnavailableV1> {
            let path = root.into();
            #[cfg(unix)]
            {
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|e| KagemushaWalletUnavailableV1::from_io(&e))?;
                if !metadata.is_dir() {
                    return Err(KagemushaWalletUnavailableV1::Io(0));
                }
                if !root_is_private(metadata.uid(), metadata.mode()) {
                    return Err(KagemushaWalletUnavailableV1::Io(
                        rustix::io::Errno::ACCESS.raw_os_error(),
                    ));
                }
            }
            // Windows admission is the existing protected-current-user NTFS native owner;
            // no pathname metadata or caller boolean substitutes for its retained DACL/ID.

            let root = PrivateDirectory::open(&path)
                .map_err(|e| KagemushaWalletUnavailableV1::from_io(&e))?;
            Ok(Self {
                root: Arc::new(root),
                path,
                directories: Arc::default(),
                staging: Arc::default(),
                #[cfg(windows)]
                removal_uncertain: Arc::default(),
            })
        }
        /// Create and sync one private child of a retained safe parent; never harden an existing
        /// object or follow a final symlink. An error after native creation is uncertain.
        #[must_use]
        pub fn create_root(root: &Path) -> KagemushaWalletPublishOutcomeV1 {
            let Some((parent, name)) = root.parent().zip(root.file_name()) else {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::Failed(KagemushaWalletUnavailableV1::Io(0)),
                );
            };
            let parent = match OwnerDirectory::open(parent) {
                Ok(parent) => parent,
                Err(e) => {
                    return KagemushaWalletPublishOutcomeV1::NotPublished(
                        KagemushaWalletNotPublishedV1::Failed(
                            KagemushaWalletUnavailableV1::from_io(&e),
                        ),
                    );
                }
            };
            match parent.create_private_child(name) {
                Ok(child) => match child.sync().and_then(|()| parent.sync()) {
                    Ok(()) => KagemushaWalletPublishOutcomeV1::Published,
                    Err(e) => KagemushaWalletPublishOutcomeV1::Uncertain(
                        KagemushaWalletUnavailableV1::from_io(&e),
                    ),
                },
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    KagemushaWalletPublishOutcomeV1::NotPublished(
                        KagemushaWalletNotPublishedV1::DestinationExists,
                    )
                }
                Err(e) => KagemushaWalletPublishOutcomeV1::Uncertain(
                    KagemushaWalletUnavailableV1::from_io(&e),
                ),
            }
        }
        /// Original spelling for display only; filesystem operations use retained descriptors.
        #[must_use]
        pub fn root(&self) -> &Path {
            &self.path
        }
        fn directory(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
        ) -> io::Result<Arc<PrivateDirectory>> {
            // Serialize cache selection with any consuming child-removal transition.
            let mut cache = self.directories.lock().map_err(|_| poisoned())?;
            #[cfg(windows)]
            if self
                .removal_uncertain
                .lock()
                .map_err(|_| poisoned())?
                .iter()
                .any(|removed| components(dir).starts_with(removed))
            {
                return Err(io::Error::other(
                    "child removal requires fresh runtime reconciliation",
                ));
            }
            if let Some(held) = cache.get(dir.components()) {
                // The retained directory validates its complete native ancestor chain.
                // Revalidate it on every selection without repeating the same walk for
                // each cached prefix; no validation result survives this operation.
                held.revalidate().map_err(custody_changed)?;
                return Ok(Arc::clone(held));
            }
            self.root.revalidate().map_err(custody_changed)?;
            let mut current = Arc::clone(&self.root);
            let mut prefix = Vec::new();
            for component in dir.components() {
                prefix.push(component.to_owned());
                if let Some(held) = cache.get(&prefix) {
                    held.revalidate().map_err(custody_changed)?;
                    current = Arc::clone(held);
                } else {
                    let child = current
                        .open_child_optional(component)
                        .map_err(custody_changed)?
                        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                    let child = Arc::new(child);
                    cache.insert(prefix.clone(), Arc::clone(&child));
                    current = child;
                }
            }
            current.revalidate().map_err(custody_changed)?;
            Ok(current)
        }
        fn rename(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            from: &str,
            to: &str,
            mode: PublishMode,
        ) -> io::Result<()> {
            let original = self
                .staging
                .lock()
                .map_err(|_| poisoned())?
                .get(&(components(dir), from.to_owned()))
                .and_then(Weak::upgrade)
                .ok_or_else(|| {
                    io::Error::other("publication requires the live original staged file")
                })?;
            self.directory(dir)?.revalidate()?;
            let mut held = original.lock().map_err(|_| poisoned())?;
            held.as_mut()
                .ok_or_else(|| io::Error::other("staged original was consumed"))?
                .rename_custody_file(from, to, mode)
        }
    }
    #[cfg(unix)]
    pub(super) fn root_is_private(uid: u32, mode: u32) -> bool {
        uid == rustix::process::geteuid().as_raw() && mode & 0o077 == 0
    }
    #[cfg(all(unix, test))]
    pub(super) const NOFOLLOW: i32 = {
        let bits = rustix::fs::OFlags::NOFOLLOW.bits();
        assert!(bits != 0 && bits <= 0x7fff_ffff);
        i32::from_ne_bytes(bits.to_ne_bytes())
    };
    impl KagemushaWalletFsV1 for KagemushaWalletStdFsV1 {
        type StagedFile = KagemushaWalletStdFsStagedV1;
        type Lock = KagemushaWalletStdFsLockV1;
        fn create_new(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            name: &str,
        ) -> io::Result<Self::StagedFile> {
            let file = Arc::new(Mutex::new(Some(
                self.directory(dir)?.create_custody_writer(name)?,
            )));
            let mut staging = self.staging.lock().map_err(|_| poisoned())?;
            staging.retain(|_, entry| entry.strong_count() > 0);
            staging.insert((components(dir), name.to_owned()), Arc::downgrade(&file));
            Ok(KagemushaWalletStdFsStagedV1 { file })
        }
        fn write_all(&self, file: &mut Self::StagedFile, bytes: &[u8]) -> io::Result<()> {
            let mut held = file.file.lock().map_err(|_| poisoned())?;
            let original = held
                .as_mut()
                .ok_or_else(|| io::Error::other("staged original was consumed"))?;
            original.revalidate()?;
            original.file_mut().write_all(bytes)?;
            original.revalidate()
        }
        fn sync_staged(&self, file: &Self::StagedFile) -> io::Result<()> {
            let held = file.file.lock().map_err(|_| poisoned())?;
            let original = held
                .as_ref()
                .ok_or_else(|| io::Error::other("staged original was consumed"))?;
            original.revalidate()?;
            original.file().sync_all()?;
            original.revalidate()
        }
        fn sync_named(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            self.directory(dir)?.sync_custody_file(name)
        }
        fn rename_noreplace(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            from: &str,
            to: &str,
        ) -> io::Result<()> {
            self.rename(dir, from, to, PublishMode::CreateNew)
        }
        fn rename_replace(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            from: &str,
            to: &str,
        ) -> io::Result<()> {
            self.rename(dir, from, to, PublishMode::Replace)
        }
        fn unlink(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let directory = self.directory(dir)?;
            let original = self
                .staging
                .lock()
                .map_err(|_| poisoned())?
                .get(&(components(dir), name.to_owned()))
                .and_then(Weak::upgrade);
            if let Some(original) = original {
                let file = original
                    .lock()
                    .map_err(|_| poisoned())?
                    .take()
                    .ok_or_else(|| io::Error::other("staged original was consumed"))?;
                file.remove_custody_file(name)
            } else {
                directory.remove_custody_file(name)
            }
        }
        fn sync_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> io::Result<()> {
            self.directory(dir)?.sync()
        }
        fn mkdir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let parent_directory = self.directory(parent)?;
            let mut key = components(parent);
            key.push(name.to_owned());
            let mut cache = self.directories.lock().map_err(|_| poisoned())?;
            #[cfg(windows)]
            if self
                .removal_uncertain
                .lock()
                .map_err(|_| poisoned())?
                .iter()
                .any(|removed| key.starts_with(removed))
            {
                return Err(io::Error::other(
                    "child removal requires fresh runtime reconciliation",
                ));
            }
            let child = Arc::new(parent_directory.create_child(name)?);
            cache.insert(key, child);
            Ok(())
        }
        fn remove_dir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let key_name = super::super::KagemushaWalletEntryNameV1::new(name)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory name"))?;
            let target = parent.child(&key_name);
            let child = self.directory(&target)?;
            #[cfg(unix)]
            {
                self.directory(parent)?
                    .remove_custody_directory(name, child.identity()?)?;
                let key = components(&target);
                self.directories
                    .lock()
                    .map_err(|_| poisoned())?
                    .retain(|candidate, _| !candidate.starts_with(&key));
                Ok(())
            }
            #[cfg(windows)]
            {
                // Refuse before consumption when the directory is nonempty or another
                // original capability is live. Never drop it to make DELETE sharing work.
                if !child.entries(usize::MAX)?.is_empty() {
                    return Err(io::ErrorKind::DirectoryNotEmpty.into());
                }
                let key = components(&target);
                let mut cache = self.directories.lock().map_err(|_| poisoned())?;
                if cache
                    .keys()
                    .any(|candidate| candidate != &key && candidate.starts_with(&key))
                {
                    return Err(io::ErrorKind::ResourceBusy.into());
                }
                let cached = cache
                    .remove(&key)
                    .ok_or_else(|| io::Error::other("child cache changed"))?;
                if !Arc::ptr_eq(&cached, &child) {
                    cache.insert(key, cached);
                    return Err(io::Error::other("child cache changed"));
                }
                drop(cached);
                let original = match Arc::try_unwrap(child) {
                    Ok(original) => original,
                    Err(original) => {
                        cache.insert(key, original);
                        return Err(io::ErrorKind::ResourceBusy.into());
                    }
                };
                self.removal_uncertain
                    .lock()
                    .map_err(|_| poisoned())?
                    .insert(key.clone());
                drop(cache);
                let result = original.remove_custody_empty();
                if result.is_ok() {
                    self.removal_uncertain
                        .lock()
                        .map_err(|_| poisoned())?
                        .remove(&key);
                }
                result
            }
        }
        fn read(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            name: &str,
            limit: usize,
        ) -> io::Result<Vec<u8>> {
            let directory = self.directory(dir)?;
            let original = directory
                .open_retained_private_optional(name)
                .map_err(custody_changed)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let mut bytes = Vec::new();
            let result = original
                .file()
                .take(u64::try_from(limit).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes);
            original.revalidate().map_err(custody_changed)?;
            result.map_err(custody_changed)?;
            Ok(bytes)
        }
        fn list(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
        ) -> io::Result<Vec<KagemushaWalletListedEntryV1>> {
            let directory = self.directory(dir)?;
            let result = (|| {
                let mut entries = Vec::new();
                for name in directory.entries(usize::MAX)? {
                    let kind = match directory.custody_entry_kind(&name)? {
                        CustodyEntryKind::File => KagemushaWalletEntryKindV1::File,
                        CustodyEntryKind::Directory => KagemushaWalletEntryKindV1::Directory,
                        CustodyEntryKind::Other => KagemushaWalletEntryKindV1::Other,
                    };
                    let name = name.into_string().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 custody entry")
                    })?;
                    entries.push(KagemushaWalletListedEntryV1 { name, kind });
                }
                Ok(entries)
            })();
            directory.revalidate().map_err(custody_changed)?;
            result.map_err(custody_changed)
        }
        fn available_bytes(&self) -> io::Result<u64> {
            self.root.available_bytes()
        }
        fn try_lock(&self) -> io::Result<Self::Lock> {
            let file = self
                .root
                .open_ownership_lock(KAGEMUSHA_WALLET_LOCK_NAME_V1)?;
            match file.try_lock() {
                Ok(()) => {
                    self.root.revalidate().map_err(custody_changed)?;
                    Ok(KagemushaWalletStdFsLockV1 {
                        _file: file,
                        _root: Arc::clone(&self.root),
                    })
                }
                Err(TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
                Err(TryLockError::Error(error)) => Err(error),
            }
        }
        fn staging_name(&self) -> io::Result<String> {
            use rand::rand_core::TryRngCore as _;
            super::staging_name_with_entropy(|bytes| {
                rand::rngs::OsRng
                    .try_fill_bytes(bytes)
                    .map_err(io::Error::other)
            })
        }
    }
}

// ---------------------------------------------------------------------------------------
// Simulated filesystem
// ---------------------------------------------------------------------------------------

#[cfg(any(test, feature = "test-utils"))]
pub use self::sim::{
    KagemushaWalletSimFaultV1, KagemushaWalletSimFsV1, KagemushaWalletSimLockV1,
    KagemushaWalletSimPowerLossV1, KagemushaWalletSimStagedFileV1, KagemushaWalletSimStepV1,
};

#[cfg(any(test, feature = "test-utils"))]
mod sim {
    use std::{
        collections::{BTreeMap, BTreeSet},
        io,
        sync::{Arc, Mutex, MutexGuard, PoisonError},
    };

    use super::super::{
        layout::{KAGEMUSHA_WALLET_STAGING_PREFIX_V1, KagemushaWalletCustodyDirV1},
        platform::{KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletListedEntryV1},
    };

    /// One simulated filesystem step, in execution order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum KagemushaWalletSimStepV1 {
        /// Exclusive file creation.
        CreateNew,
        /// File data write.
        Write,
        /// File sync.
        SyncFile,
        /// Create-new rename.
        RenameNoReplace,
        /// Replacing rename.
        RenameReplace,
        /// Unlink.
        Unlink,
        /// Directory sync.
        SyncDir,
        /// Directory creation.
        Mkdir,
        /// Empty-directory removal.
        RemoveDir,
        /// File read.
        Read,
        /// Directory listing.
        List,
        /// Free-space query.
        Statvfs,
        /// Lock acquisition.
        Lock,
    }

    /// Fault injected at one step.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KagemushaWalletSimFaultV1 {
        /// The step fails with an indeterminate I/O error and has no effect.
        Error,
        /// The step fails with this definitive error kind and has no effect.
        ErrorKind(io::ErrorKind),
        /// A write stores half its bytes, then fails with "storage full" (other steps: `Error`).
        PartialWrite,
        /// A sync reports an I/O error and marks its dirty data clean without making it
        /// durable; later syncs succeed vacuously (Linux writeback-error semantics). Other
        /// steps: `Error`.
        LostWriteback,
        /// The process crashes before the step.
        CrashBefore,
        /// The process crashes after the step completes.
        CrashAfter,
    }

    /// Power-loss model applied by [`KagemushaWalletSimFsV1::power_loss`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KagemushaWalletSimPowerLossV1 {
        /// Everything not synced is lost.
        DropUnsynced,
        /// Each unsynced directory operation independently survives or not, and unsynced file
        /// data is kept, lost or torn, all from this seed.
        Seeded(u64),
        /// Unsynced directory operation `i` survives exactly when bit `i` of `mask` is set
        /// (operations are counted across directories in path order, then in execution order;
        /// from the 64th on none survives), so every subset of [`KagemushaWalletSimFsV1::pending_dir_ops`]
        /// can be enumerated. Unsynced file data is kept, lost or torn from `seed`.
        Subset {
            /// Surviving operations.
            mask: u64,
            /// Seed of the file-data choices.
            seed: u64,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SimNodeV1 {
        File(u64),
        Dir,
        Other,
    }

    #[derive(Debug, Clone)]
    enum SimDirOpV1 {
        Link(String, SimNodeV1),
        Unlink(String),
        Rename(String, String),
    }

    impl SimDirOpV1 {
        fn apply(&self, entries: &mut BTreeMap<String, SimNodeV1>) {
            match self {
                Self::Link(name, node) => {
                    entries.entry(name.clone()).or_insert(*node);
                }
                Self::Unlink(name) => {
                    entries.remove(name);
                }
                Self::Rename(from, to) => {
                    if let Some(node) = entries.remove(from) {
                        entries.insert(to.clone(), node);
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    struct SimDirV1 {
        visible: BTreeMap<String, SimNodeV1>,
        durable: BTreeMap<String, SimNodeV1>,
        pending: Vec<SimDirOpV1>,
    }

    #[derive(Debug, Clone, Default)]
    struct SimInodeV1 {
        visible: Vec<u8>,
        durable: Vec<u8>,
        dirty: bool,
    }

    #[derive(Debug, Clone)]
    struct SimStateV1 {
        dirs: BTreeMap<Vec<String>, SimDirV1>,
        inodes: BTreeMap<u64, SimInodeV1>,
        next_inode: u64,
        next_staging: u64,
        staging_name_faults: BTreeMap<u64, io::ErrorKind>,
        steps: u64,
        faults: BTreeMap<u64, KagemushaWalletSimFaultV1>,
        trace: Vec<KagemushaWalletSimStepV1>,
        crashed: bool,
        process: u64,
        lock: Option<(u64, u64)>,
        next_lock: u64,
        noreplace_supported: bool,
        capacity: Option<u64>,
    }

    /// Gate of one step after fault lookup.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum GateV1 {
        Run,
        RunThenCrash,
        PartialWrite,
        LostWriteback,
    }

    fn crashed_error() -> io::Error {
        io::Error::other("simulated process crash")
    }

    fn not_found() -> io::Error {
        io::Error::from(io::ErrorKind::NotFound)
    }

    impl SimStateV1 {
        fn new() -> Self {
            let mut dirs = BTreeMap::new();
            dirs.insert(Vec::new(), SimDirV1::default());
            Self {
                dirs,
                inodes: BTreeMap::new(),
                next_inode: 1,
                next_staging: 0,
                staging_name_faults: BTreeMap::new(),
                steps: 0,
                faults: BTreeMap::new(),
                trace: Vec::new(),
                crashed: false,
                process: 0,
                lock: None,
                next_lock: 0,
                noreplace_supported: true,
                capacity: None,
            }
        }

        fn crash(&mut self) {
            self.crashed = true;
            self.lock = None;
        }

        fn begin(&mut self, step: KagemushaWalletSimStepV1) -> io::Result<GateV1> {
            if self.crashed {
                return Err(crashed_error());
            }
            let index = self.steps;
            self.steps = self.steps.saturating_add(1);
            self.trace.push(step);
            let Some(fault) = self.faults.remove(&index) else {
                return Ok(GateV1::Run);
            };
            match fault {
                KagemushaWalletSimFaultV1::Error => Err(io::Error::other("simulated I/O error")),
                KagemushaWalletSimFaultV1::ErrorKind(kind) => Err(io::Error::from(kind)),
                KagemushaWalletSimFaultV1::CrashBefore => {
                    self.crash();
                    Err(crashed_error())
                }
                KagemushaWalletSimFaultV1::CrashAfter => Ok(GateV1::RunThenCrash),
                KagemushaWalletSimFaultV1::PartialWrite => {
                    if step == KagemushaWalletSimStepV1::Write {
                        Ok(GateV1::PartialWrite)
                    } else {
                        Err(io::Error::other("simulated I/O error"))
                    }
                }
                KagemushaWalletSimFaultV1::LostWriteback => {
                    if matches!(
                        step,
                        KagemushaWalletSimStepV1::SyncFile | KagemushaWalletSimStepV1::SyncDir
                    ) {
                        Ok(GateV1::LostWriteback)
                    } else {
                        Err(io::Error::other("simulated I/O error"))
                    }
                }
            }
        }

        fn finish<T>(&mut self, gate: GateV1, value: T) -> io::Result<T> {
            if gate == GateV1::RunThenCrash {
                self.crash();
                return Err(crashed_error());
            }
            Ok(value)
        }

        fn dir(&self, dir: &[String]) -> io::Result<&SimDirV1> {
            self.dirs.get(dir).ok_or_else(not_found)
        }

        fn dir_mut(&mut self, dir: &[String]) -> io::Result<&mut SimDirV1> {
            self.dirs.get_mut(dir).ok_or_else(not_found)
        }

        /// Visible bytes of every linked file; an unlinked inode frees its space.
        fn used_bytes(&self) -> u64 {
            let linked: BTreeSet<u64> = self
                .dirs
                .values()
                .flat_map(|dir| dir.visible.values())
                .filter_map(|node| match node {
                    SimNodeV1::File(inode) => Some(*inode),
                    SimNodeV1::Dir | SimNodeV1::Other => None,
                })
                .collect();
            linked
                .iter()
                .filter_map(|inode| self.inodes.get(inode))
                .map(|inode| u64::try_from(inode.visible.len()).unwrap_or(u64::MAX))
                .fold(0_u64, u64::saturating_add)
        }

        fn sync_inode(&mut self, inode: u64, gate: GateV1) -> io::Result<()> {
            let inode = self.inodes.get_mut(&inode).ok_or_else(not_found)?;
            if gate == GateV1::LostWriteback {
                inode.dirty = false;
                return Err(io::Error::other("simulated writeback error"));
            }
            if inode.dirty {
                inode.durable = inode.visible.clone();
                inode.dirty = false;
            }
            Ok(())
        }

        fn reachable_dirs(&self) -> BTreeSet<Vec<String>> {
            let mut reachable = BTreeSet::new();
            let mut queue = vec![Vec::new()];
            while let Some(path) = queue.pop() {
                let Some(dir) = self.dirs.get(&path) else {
                    continue;
                };
                for (name, node) in &dir.visible {
                    if *node == SimNodeV1::Dir {
                        let mut child = path.clone();
                        child.push(name.clone());
                        queue.push(child);
                    }
                }
                reachable.insert(path);
            }
            reachable
        }

        /// Give every directory entry without directory state an empty directory: a removal
        /// of an empty directory that did not survive power loss leaves it empty.
        fn restore_empty_dirs(&mut self) {
            let mut queue = vec![Vec::new()];
            while let Some(path) = queue.pop() {
                let children: Vec<Vec<String>> = self
                    .dirs
                    .get(&path)
                    .map(|dir| {
                        dir.visible
                            .iter()
                            .filter(|(_, node)| **node == SimNodeV1::Dir)
                            .map(|(name, _)| {
                                let mut child = path.clone();
                                child.push(name.clone());
                                child
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for child in children {
                    self.dirs.entry(child.clone()).or_default();
                    queue.push(child);
                }
            }
        }

        /// Number of unsynced directory operations.
        fn pending_dir_ops(&self) -> usize {
            self.dirs
                .values()
                .map(|dir| dir.pending.len())
                .fold(0_usize, usize::saturating_add)
        }
    }

    /// Deterministic `SplitMix64` generator for seeded power loss.
    struct SplitMixV1(u64);

    impl SplitMixV1 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            if bound == 0 { 0 } else { self.next() % bound }
        }
    }

    /// In-memory custody filesystem with separate visible and durable state.
    ///
    /// Visible state is what a running process observes (it survives a process crash);
    /// durable state is what survives power loss. File data becomes durable on a file sync;
    /// directory entries on a directory sync, which replays the directory's pending
    /// operations. Clones share state (two handles model two openers); [`Self::fork`] copies
    /// it. Steps are numbered from zero; [`Self::inject`] arms one fault at one step.
    #[derive(Debug, Clone)]
    pub struct KagemushaWalletSimFsV1 {
        state: Arc<Mutex<SimStateV1>>,
    }

    /// Staging file handle of the simulator.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KagemushaWalletSimStagedFileV1 {
        inode: u64,
    }

    /// Held simulator lock; released on drop unless a crash already released it.
    #[derive(Debug)]
    pub struct KagemushaWalletSimLockV1 {
        state: Arc<Mutex<SimStateV1>>,
        token: u64,
    }

    impl Drop for KagemushaWalletSimLockV1 {
        fn drop(&mut self) {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.lock.is_some_and(|(_, token)| token == self.token) {
                state.lock = None;
            }
        }
    }

    impl Default for KagemushaWalletSimFsV1 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl KagemushaWalletSimFsV1 {
        /// Empty filesystem holding only the durable custody root.
        #[must_use]
        pub fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(SimStateV1::new())),
            }
        }

        fn state(&self) -> MutexGuard<'_, SimStateV1> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Independent copy of the current state (faults and trace included).
        #[must_use]
        pub fn fork(&self) -> Self {
            Self {
                state: Arc::new(Mutex::new(self.state().clone())),
            }
        }

        /// Number of steps executed so far; the next step has this index.
        #[must_use]
        pub fn steps(&self) -> u64 {
            self.state().steps
        }

        /// Steps executed since step `from`.
        #[must_use]
        pub fn trace_since(&self, from: u64) -> Vec<KagemushaWalletSimStepV1> {
            let state = self.state();
            let start = usize::try_from(from).unwrap_or(usize::MAX);
            state
                .trace
                .get(start..)
                .map(<[_]>::to_vec)
                .unwrap_or_default()
        }

        /// Arm `fault` at absolute step index `step`.
        pub fn inject(&self, step: u64, fault: KagemushaWalletSimFaultV1) {
            self.state().faults.insert(step, fault);
        }

        /// Fail the staging-name request after `before_error` further name requests.
        /// This is separate from filesystem steps, so existing fault-matrix indices do not move.
        pub fn inject_staging_name_error(&self, before_error: u64, error: io::ErrorKind) {
            let mut state = self.state();
            let index = state.next_staging.saturating_add(before_error);
            state.staging_name_faults.insert(index, error);
        }

        /// Disarm every pending filesystem and staging-name fault.
        pub fn clear_faults(&self) {
            let mut state = self.state();
            state.faults.clear();
            state.staging_name_faults.clear();
        }

        /// Whether the simulated process has crashed (every step fails until a restart).
        #[must_use]
        pub fn crashed(&self) -> bool {
            self.state().crashed
        }

        /// Make create-new renames fail with `EINVAL`, as on a filesystem without
        /// `RENAME_NOREPLACE`.
        pub fn set_noreplace_supported(&self, supported: bool) {
            self.state().noreplace_supported = supported;
        }

        /// Limit total visible file bytes; writes beyond it fail with "storage full".
        pub fn set_capacity(&self, capacity: Option<u64>) {
            self.state().capacity = capacity;
        }

        /// Restart the process: visible state is kept, the lock is released, faults stay.
        pub fn restart(&self) {
            let mut state = self.state();
            state.crashed = false;
            state.process = state.process.saturating_add(1);
            state.lock = None;
        }

        /// Number of unsynced directory operations a power loss would now decide; the operand
        /// space of [`KagemushaWalletSimPowerLossV1::Subset`].
        #[must_use]
        pub fn pending_dir_ops(&self) -> usize {
            self.state().pending_dir_ops()
        }

        /// Lose power, then restart: only durable state survives, as `mode` decides for
        /// unsynced operations. Pending faults are disarmed.
        pub fn power_loss(&self, mode: KagemushaWalletSimPowerLossV1) {
            let mut state = self.state();
            let (seed, mask) = match mode {
                KagemushaWalletSimPowerLossV1::DropUnsynced => (0, None),
                KagemushaWalletSimPowerLossV1::Seeded(seed) => (seed, None),
                KagemushaWalletSimPowerLossV1::Subset { mask, seed } => (seed, Some(mask)),
            };
            let mut rng = SplitMixV1(seed);
            let seeded = !matches!(mode, KagemushaWalletSimPowerLossV1::DropUnsynced);
            let mut index = 0_u32;
            for dir in state.dirs.values_mut() {
                let mut entries = dir.durable.clone();
                if seeded {
                    for operation in &dir.pending {
                        let survives = match mask {
                            Some(mask) => index < 64 && (mask >> index) & 1 == 1,
                            None => rng.below(2) == 1,
                        };
                        index = index.saturating_add(1);
                        if survives {
                            operation.apply(&mut entries);
                        }
                    }
                }
                dir.visible.clone_from(&entries);
                dir.durable = entries;
                dir.pending.clear();
            }
            state.restore_empty_dirs();
            let reachable = state.reachable_dirs();
            state.dirs.retain(|path, _| reachable.contains(path));
            for inode in state.inodes.values_mut() {
                let data = if !seeded || inode.visible == inode.durable {
                    inode.durable.clone()
                } else {
                    match rng.below(3) {
                        0 => inode.durable.clone(),
                        1 => inode.visible.clone(),
                        _ => {
                            let len = u64::try_from(inode.visible.len()).unwrap_or(u64::MAX);
                            let keep = usize::try_from(rng.below(len.saturating_add(1)))
                                .unwrap_or(0)
                                .min(inode.visible.len());
                            inode.visible[..keep].to_vec()
                        }
                    }
                };
                inode.visible.clone_from(&data);
                inode.durable = data;
                inode.dirty = false;
            }
            state.crashed = false;
            state.process = state.process.saturating_add(1);
            state.lock = None;
            state.faults.clear();
            state.staging_name_faults.clear();
        }

        /// Visible bytes of file `name` in `dir`, bypassing steps and faults.
        #[must_use]
        pub fn visible_file(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            name: &str,
        ) -> Option<Vec<u8>> {
            let state = self.state();
            match state.dirs.get(dir.components())?.visible.get(name)? {
                SimNodeV1::File(inode) => {
                    state.inodes.get(inode).map(|inode| inode.visible.clone())
                }
                SimNodeV1::Dir | SimNodeV1::Other => None,
            }
        }

        /// Whether directory `dir` is visible, bypassing steps and faults.
        #[must_use]
        pub fn visible_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> bool {
            let state = self.state();
            state.dirs.contains_key(dir.components())
                && state.reachable_dirs().contains(dir.components())
        }

        /// Visible entry names of `dir`, bypassing steps and faults.
        #[must_use]
        pub fn visible_names(&self, dir: &KagemushaWalletCustodyDirV1) -> Vec<String> {
            self.state()
                .dirs
                .get(dir.components())
                .map(|dir| dir.visible.keys().cloned().collect())
                .unwrap_or_default()
        }

        /// Inode number behind `name`, bypassing steps and faults.
        #[must_use]
        pub fn inode_of(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> Option<u64> {
            match self.state().dirs.get(dir.components())?.visible.get(name)? {
                SimNodeV1::File(inode) => Some(*inode),
                SimNodeV1::Dir | SimNodeV1::Other => None,
            }
        }

        /// Place an unsynced file directly (visible only), bypassing steps; test setup for
        /// states the store itself never produces.
        pub fn place_unsynced(&self, dir: &KagemushaWalletCustodyDirV1, name: &str, bytes: &[u8]) {
            let mut state = self.state();
            let inode = state.next_inode;
            state.next_inode = state.next_inode.saturating_add(1);
            state.inodes.insert(
                inode,
                SimInodeV1 {
                    visible: bytes.to_vec(),
                    durable: Vec::new(),
                    dirty: true,
                },
            );
            if let Some(directory) = state.dirs.get_mut(dir.components()) {
                directory
                    .visible
                    .insert(name.to_owned(), SimNodeV1::File(inode));
                directory
                    .pending
                    .push(SimDirOpV1::Link(name.to_owned(), SimNodeV1::File(inode)));
            }
        }

        /// Place a non-file, non-directory entry (for example a symbolic link), bypassing steps.
        pub fn place_other(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) {
            if let Some(directory) = self.state().dirs.get_mut(dir.components()) {
                directory.visible.insert(name.to_owned(), SimNodeV1::Other);
            }
        }
    }

    impl KagemushaWalletFsV1 for KagemushaWalletSimFsV1 {
        type StagedFile = KagemushaWalletSimStagedFileV1;
        type Lock = KagemushaWalletSimLockV1;

        fn create_new(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            name: &str,
        ) -> io::Result<KagemushaWalletSimStagedFileV1> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::CreateNew)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            if state.dir(dir.components())?.visible.contains_key(name) {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            let inode = state.next_inode;
            state.next_inode = state.next_inode.saturating_add(1);
            state.inodes.insert(inode, SimInodeV1::default());
            let directory = state.dir_mut(dir.components())?;
            directory
                .visible
                .insert(name.to_owned(), SimNodeV1::File(inode));
            directory
                .pending
                .push(SimDirOpV1::Link(name.to_owned(), SimNodeV1::File(inode)));
            state.finish(gate, KagemushaWalletSimStagedFileV1 { inode })
        }

        fn write_all(
            &self,
            file: &mut KagemushaWalletSimStagedFileV1,
            bytes: &[u8],
        ) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Write)?;
            let used = state.used_bytes();
            let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if state
                .capacity
                .is_some_and(|capacity| used.saturating_add(len) > capacity)
            {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            let inode = state.inodes.get_mut(&file.inode).ok_or_else(not_found)?;
            if gate == GateV1::PartialWrite {
                inode.visible.extend_from_slice(&bytes[..bytes.len() / 2]);
                inode.dirty = true;
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            inode.visible.extend_from_slice(bytes);
            inode.dirty = true;
            state.finish(gate, ())
        }

        fn sync_staged(&self, file: &KagemushaWalletSimStagedFileV1) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::SyncFile)?;
            state.sync_inode(file.inode, gate)?;
            state.finish(gate, ())
        }

        fn sync_named(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::SyncFile)?;
            let SimNodeV1::File(inode) = *state
                .dir(dir.components())?
                .visible
                .get(name)
                .ok_or_else(not_found)?
            else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            state.sync_inode(inode, gate)?;
            state.finish(gate, ())
        }

        fn rename_noreplace(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            from: &str,
            to: &str,
        ) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::RenameNoReplace)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            if !state.noreplace_supported {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let directory = state.dir_mut(dir.components())?;
            if !directory.visible.contains_key(from) {
                return Err(not_found());
            }
            if directory.visible.contains_key(to) {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            let node = directory.visible.remove(from).ok_or_else(not_found)?;
            directory.visible.insert(to.to_owned(), node);
            directory
                .pending
                .push(SimDirOpV1::Rename(from.to_owned(), to.to_owned()));
            state.finish(gate, ())
        }

        fn rename_replace(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            from: &str,
            to: &str,
        ) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::RenameReplace)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let directory = state.dir_mut(dir.components())?;
            if directory.visible.get(to) == Some(&SimNodeV1::Dir) {
                return Err(io::Error::from(io::ErrorKind::IsADirectory));
            }
            let node = directory.visible.remove(from).ok_or_else(not_found)?;
            directory.visible.insert(to.to_owned(), node);
            directory
                .pending
                .push(SimDirOpV1::Rename(from.to_owned(), to.to_owned()));
            state.finish(gate, ())
        }

        fn unlink(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Unlink)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let directory = state.dir_mut(dir.components())?;
            match directory.visible.get(name) {
                None => return Err(not_found()),
                Some(SimNodeV1::Dir) => return Err(io::Error::from(io::ErrorKind::IsADirectory)),
                Some(SimNodeV1::File(_) | SimNodeV1::Other) => {}
            }
            directory.visible.remove(name);
            directory.pending.push(SimDirOpV1::Unlink(name.to_owned()));
            state.finish(gate, ())
        }

        fn sync_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::SyncDir)?;
            let directory = state.dir_mut(dir.components())?;
            if gate == GateV1::LostWriteback {
                directory.pending.clear();
                return Err(io::Error::other("simulated writeback error"));
            }
            let pending = std::mem::take(&mut directory.pending);
            for operation in &pending {
                operation.apply(&mut directory.durable);
            }
            state.finish(gate, ())
        }

        fn mkdir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Mkdir)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let directory = state.dir_mut(parent.components())?;
            if directory.visible.contains_key(name) {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            directory.visible.insert(name.to_owned(), SimNodeV1::Dir);
            directory
                .pending
                .push(SimDirOpV1::Link(name.to_owned(), SimNodeV1::Dir));
            let mut child = parent.components().to_vec();
            child.push(name.to_owned());
            state.dirs.insert(child, SimDirV1::default());
            state.finish(gate, ())
        }

        fn remove_dir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::RemoveDir)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let mut child = parent.components().to_vec();
            child.push(name.to_owned());
            match state.dir(parent.components())?.visible.get(name) {
                None => return Err(not_found()),
                Some(SimNodeV1::Dir) => {}
                Some(SimNodeV1::File(_) | SimNodeV1::Other) => {
                    return Err(io::Error::from(io::ErrorKind::NotADirectory));
                }
            }
            if state
                .dirs
                .get(&child)
                .is_some_and(|directory| !directory.visible.is_empty())
            {
                return Err(io::Error::from(io::ErrorKind::DirectoryNotEmpty));
            }
            let directory = state.dir_mut(parent.components())?;
            directory.visible.remove(name);
            directory.pending.push(SimDirOpV1::Unlink(name.to_owned()));
            state.dirs.remove(&child);
            state.finish(gate, ())
        }

        fn read(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
            name: &str,
            limit: usize,
        ) -> io::Result<Vec<u8>> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Read)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let node = *state
                .dir(dir.components())?
                .visible
                .get(name)
                .ok_or_else(not_found)?;
            let SimNodeV1::File(inode) = node else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not a regular file",
                ));
            };
            let data = &state.inodes.get(&inode).ok_or_else(not_found)?.visible;
            let bytes = data[..data.len().min(limit)].to_vec();
            state.finish(gate, bytes)
        }

        fn list(
            &self,
            dir: &KagemushaWalletCustodyDirV1,
        ) -> io::Result<Vec<KagemushaWalletListedEntryV1>> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::List)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let entries = state
                .dir(dir.components())?
                .visible
                .iter()
                .map(|(name, node)| KagemushaWalletListedEntryV1 {
                    name: name.clone(),
                    kind: match node {
                        SimNodeV1::Dir => KagemushaWalletEntryKindV1::Directory,
                        SimNodeV1::Other => KagemushaWalletEntryKindV1::Other,
                        SimNodeV1::File(_) => KagemushaWalletEntryKindV1::File,
                    },
                })
                .collect();
            state.finish(gate, entries)
        }

        fn available_bytes(&self) -> io::Result<u64> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Statvfs)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            let available = state.capacity.map_or(u64::MAX / 2, |capacity| {
                capacity.saturating_sub(state.used_bytes())
            });
            state.finish(gate, available)
        }

        fn try_lock(&self) -> io::Result<KagemushaWalletSimLockV1> {
            let mut state = self.state();
            let gate = state.begin(KagemushaWalletSimStepV1::Lock)?;
            if gate != GateV1::Run && gate != GateV1::RunThenCrash {
                return Err(io::Error::other("simulated I/O error"));
            }
            if state.lock.is_some() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let token = state.next_lock;
            state.next_lock = state.next_lock.saturating_add(1);
            state.lock = Some((state.process, token));
            state.finish(gate, ())?;
            Ok(KagemushaWalletSimLockV1 {
                state: Arc::clone(&self.state),
                token,
            })
        }

        fn staging_name(&self) -> io::Result<String> {
            let mut state = self.state();
            let index = state.next_staging;
            state.next_staging = state.next_staging.saturating_add(1);
            if let Some(error) = state.staging_name_faults.remove(&index) {
                return Err(io::Error::from(error));
            }
            Ok(format!("{KAGEMUSHA_WALLET_STAGING_PREFIX_V1}{index:032x}"))
        }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
