//! Durable query-index status persisted alongside the block store.
//!
//! The aggregate DSL currently executes against live state, but Torii still
//! needs a durable notion of the latest query snapshot that survived restarts.
//! This journal stores the latest indexed block height and hash under the Kura
//! root so aggregate responses can report a stable snapshot marker.
use super::journal_io::{journal_parent, open_journal_parent};
use iroha_crypto::HashOf;
use iroha_data_model::block::BlockHeader;
use norito::{
    codec::{Decode, Encode},
    decode_from_bytes, to_bytes,
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
/// Snapshot of the latest durable query index state.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::index_status::QueryIndexStatus")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
pub struct QueryIndexStatus {
    /// Latest block height covered by the query index.
    pub indexed_height: u64,
    /// Latest block hash covered by the query index.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub indexed_block_hash: Option<HashOf<BlockHeader>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::index_status::PersistedQueryIndexStatus")]
struct PersistedQueryIndexStatus {
    version: u32,
    status: QueryIndexStatus,
}
/// Errors returned when loading or persisting the query-index status journal.
#[derive(Debug, Error)]
pub enum QueryIndexJournalError {
    /// Failed to read the persisted journal.
    #[error("failed to read query index journal {path}: {source}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to decode the persisted journal.
    #[error("failed to decode query index journal {path}: {source}")]
    Decode {
        /// Path that failed.
        path: PathBuf,
        /// Source decode error.
        #[source]
        source: norito::core::Error,
    },
    /// Failed to write the journal to disk.
    #[error("failed to persist query index journal {path}: {source}")]
    Write {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to encode the journal payload.
    #[error("failed to encode query index journal: {0}")]
    Encode(#[source] norito::core::Error),
    /// Persisted journal uses an unsupported version.
    #[error("unsupported query index journal version {version} at {path}")]
    UnsupportedVersion {
        /// Path for the journal.
        path: PathBuf,
        /// Unsupported version encountered.
        version: u32,
    },
}
/// Journal that records the latest query-index snapshot marker.
#[derive(Debug, Clone)]
pub struct QueryIndexJournal {
    path: PathBuf,
    status: QueryIndexStatus,
}
/// Closed deterministic recovery failures used only by real-file regression fixtures.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PromotionFailure {
    /// The initial rename fails while the main destination is absent.
    InitialRename,
    /// Removing an existing destination after a failed rename fails.
    RemoveExisting,
    /// The second rename fails after removing the destination.
    RetryRename,
    /// Opening the parent directory after promotion fails.
    OpenParent,
    /// Synchronizing the parent directory after promotion fails.
    SyncParent,
    /// Fail only the first rename, then execute every real fallback operation.
    InitialRenameForSuccessfulFallback,
}

/// Every recovery failure boundary in deterministic fixture order.
#[cfg(test)]
pub(crate) const PROMOTION_FAILURES: [PromotionFailure; 5] = [
    PromotionFailure::InitialRename,
    PromotionFailure::RemoveExisting,
    PromotionFailure::RetryRename,
    PromotionFailure::OpenParent,
    PromotionFailure::SyncParent,
];

#[cfg(test)]
std::thread_local! {
    static PROMOTION_FAILURE: std::cell::Cell<Option<PromotionFailure>> = const { std::cell::Cell::new(None) };
}

impl QueryIndexJournal {
    /// Filename used to persist query index status next to the block store.
    pub const JOURNAL_FILE: &'static str = "query-index-status.norito";
    const JOURNAL_VERSION: u32 = 1;
    /// Maximum encoded bytes in one persisted status marker.
    pub(crate) const JOURNAL_MAX_BYTES: u64 = 4 * 1024;
    /// Build the canonical journal path under the provided root.
    #[must_use]
    pub fn journal_path(root: &Path) -> PathBuf {
        if root.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            root.join(Self::JOURNAL_FILE)
        }
    }
    /// Construct a fresh journal with no indexed state.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            status: QueryIndexStatus::default(),
        }
    }
    /// Load a journal from disk, preferring a valid temp file when present.
    ///
    /// Missing files are treated as an empty journal.
    ///
    /// # Errors
    ///
    /// Returns [`QueryIndexJournalError`] when persistence fails.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, QueryIndexJournalError> {
        let path = path.into();
        let mut journal = Self::new(path.clone());
        let tmp_path = Self::temp_path(&path);
        if path.as_os_str().is_empty() {
            return Ok(journal);
        }
        let main = if path.exists() {
            Some(Self::load_persisted(&path))
        } else {
            None
        };
        let tmp = if tmp_path.exists() {
            Some(Self::load_persisted(&tmp_path))
        } else {
            None
        };
        let (persisted, read_path) = match (tmp, main) {
            (None, None) => return Ok(journal),
            (Some(Ok(persisted)), _) => (persisted, tmp_path.clone()),
            (Some(Err(tmp_err)), None) => return Err(tmp_err),
            (Some(Err(_)) | None, Some(Ok(persisted))) => (persisted, path.clone()),
            (None | Some(Err(_)), Some(Err(err))) => return Err(err),
        };
        journal.status = persisted.status;
        if read_path != path {
            Self::promote_temp_journal(&read_path, &path)?;
        }
        Ok(journal)
    }
    fn load_persisted(path: &Path) -> Result<PersistedQueryIndexStatus, QueryIndexJournalError> {
        let file = fs::File::open(path).map_err(|source| QueryIndexJournalError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let metadata = file
            .metadata()
            .map_err(|source| QueryIndexJournalError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if !metadata.is_file() || metadata.len() > Self::JOURNAL_MAX_BYTES {
            return Err(QueryIndexJournalError::Read {
                path: path.to_path_buf(),
                source: std::io::Error::other(format!(
                    "journal is not a regular file within the {}-byte limit",
                    Self::JOURNAL_MAX_BYTES
                )),
            });
        }
        let mut bytes = Vec::new();
        file.take(Self::JOURNAL_MAX_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| QueryIndexJournalError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > Self::JOURNAL_MAX_BYTES {
            return Err(QueryIndexJournalError::Read {
                path: path.to_path_buf(),
                source: std::io::Error::other(format!(
                    "journal grew beyond the {}-byte limit while reading",
                    Self::JOURNAL_MAX_BYTES
                )),
            });
        }
        let persisted: PersistedQueryIndexStatus =
            decode_from_bytes(&bytes).map_err(|source| QueryIndexJournalError::Decode {
                path: path.to_path_buf(),
                source,
            })?;
        if persisted.version != Self::JOURNAL_VERSION {
            return Err(QueryIndexJournalError::UnsupportedVersion {
                path: path.to_path_buf(),
                version: persisted.version,
            });
        }
        Ok(persisted)
    }
    fn temp_path(path: &Path) -> PathBuf {
        path.with_extension("norito.tmp")
    }
    fn promote_temp_journal(from: &Path, to: &Path) -> Result<(), QueryIndexJournalError> {
        let rename = {
            #[cfg(test)]
            {
                Self::fail_promotion_step_for_tests(PromotionFailure::InitialRename)
                    .and_then(|()| fs::rename(from, to))
            }
            #[cfg(not(test))]
            {
                fs::rename(from, to)
            }
        };
        if let Err(source) = rename {
            if !to.exists() {
                return Err(QueryIndexJournalError::Write {
                    path: to.to_path_buf(),
                    source,
                });
            }
            // Platforms that cannot replace an existing destination must complete
            // both fallback operations before this recovery can report success.
            {
                #[cfg(test)]
                {
                    Self::fail_promotion_step_for_tests(PromotionFailure::RemoveExisting)
                        .and_then(|()| fs::remove_file(to))
                }
                #[cfg(not(test))]
                {
                    fs::remove_file(to)
                }
            }
            .map_err(|source| QueryIndexJournalError::Write {
                path: to.to_path_buf(),
                source,
            })?;
            {
                #[cfg(test)]
                {
                    Self::fail_promotion_step_for_tests(PromotionFailure::RetryRename)
                        .and_then(|()| fs::rename(from, to))
                }
                #[cfg(not(test))]
                {
                    fs::rename(from, to)
                }
            }
            .map_err(|source| QueryIndexJournalError::Write {
                path: to.to_path_buf(),
                source,
            })?;
        }
        {
            let parent = journal_parent(to);
            let dir = {
                #[cfg(test)]
                {
                    Self::fail_promotion_step_for_tests(PromotionFailure::OpenParent)
                        .and_then(|()| open_journal_parent(to))
                }
                #[cfg(not(test))]
                {
                    open_journal_parent(to)
                }
            }
            .map_err(|source| QueryIndexJournalError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
            {
                #[cfg(test)]
                {
                    Self::fail_promotion_step_for_tests(PromotionFailure::SyncParent)
                        .and_then(|()| dir.sync_all())
                }
                #[cfg(not(test))]
                {
                    dir.sync_all()
                }
            }
            .map_err(|source| QueryIndexJournalError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        Ok(())
    }

    /// Inject exactly one recovery failure; fallback cases also reject the first rename.
    #[cfg(test)]
    pub(crate) fn fail_next_promotion_for_tests(failure: PromotionFailure) {
        PROMOTION_FAILURE.with(|slot| {
            assert!(
                slot.replace(Some(failure)).is_none(),
                "unconsumed journal promotion fault"
            );
        });
    }

    /// Report whether the exact injected recovery boundary has not yet executed.
    #[cfg(test)]
    pub(crate) fn promotion_failure_pending_for_tests() -> bool {
        PROMOTION_FAILURE.with(|slot| slot.get().is_some())
    }

    #[cfg(test)]
    fn fail_promotion_step_for_tests(step: PromotionFailure) -> std::io::Result<()> {
        let failed = PROMOTION_FAILURE.with(|slot| {
            let Some(failure) = slot.get() else {
                return false;
            };
            if failure == PromotionFailure::InitialRenameForSuccessfulFallback
                && step == PromotionFailure::InitialRename
            {
                slot.set(None);
                return true;
            }
            if failure == step {
                slot.set(None);
                return true;
            }
            step == PromotionFailure::InitialRename
                && matches!(
                    failure,
                    PromotionFailure::RemoveExisting | PromotionFailure::RetryRename
                )
        });
        if failed {
            return Err(std::io::Error::other(format!(
                "injected query journal promotion {step:?}"
            )));
        }
        Ok(())
    }
    /// Return the current in-memory snapshot.
    #[must_use]
    pub fn snapshot(&self) -> QueryIndexStatus {
        self.status.clone()
    }
    /// Update the latest indexed height/hash tracked by this journal.
    pub fn set_latest(
        &mut self,
        indexed_height: u64,
        indexed_block_hash: Option<HashOf<BlockHeader>>,
    ) {
        self.status.indexed_height = indexed_height;
        self.status.indexed_block_hash = indexed_block_hash;
    }
    /// Persist the journal atomically to disk.
    ///
    /// # Errors
    ///
    /// Returns [`QueryIndexJournalError`] when encoding or writing fails.
    pub fn persist(&self) -> Result<(), QueryIndexJournalError> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let payload = PersistedQueryIndexStatus {
            version: Self::JOURNAL_VERSION,
            status: self.status.clone(),
        };
        let bytes = to_bytes(&payload).map_err(QueryIndexJournalError::Encode)?;
        let tmp_path = Self::temp_path(&self.path);
        {
            let parent = journal_parent(&self.path);
            fs::create_dir_all(parent).map_err(|source| QueryIndexJournalError::Write {
                path: self.path.clone(),
                source,
            })?;
        }
        {
            let mut file =
                fs::File::create(&tmp_path).map_err(|source| QueryIndexJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            file.write_all(&bytes)
                .map_err(|source| QueryIndexJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            file.sync_all()
                .map_err(|source| QueryIndexJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
        }
        fs::rename(&tmp_path, &self.path).map_err(|source| QueryIndexJournalError::Write {
            path: self.path.clone(),
            source,
        })?;
        {
            let parent = journal_parent(&self.path);
            let dir = open_journal_parent(&self.path).map_err(|source| {
                QueryIndexJournalError::Write {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
            dir.sync_all()
                .map_err(|source| QueryIndexJournalError::Write {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Hash;
    fn sample_hash(byte: u8) -> HashOf<BlockHeader> {
        HashOf::from_untyped_unchecked(Hash::new([byte; Hash::LENGTH]))
    }
    #[test]
    fn load_missing_query_index_journal_returns_empty_snapshot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(QueryIndexJournal::JOURNAL_FILE);
        let journal = QueryIndexJournal::load(path).expect("load empty journal");
        assert_eq!(journal.snapshot(), QueryIndexStatus::default());
    }
    #[test]
    fn query_index_journal_round_trips_latest_snapshot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(QueryIndexJournal::JOURNAL_FILE);
        let mut journal = QueryIndexJournal::new(path.clone());
        journal.set_latest(42, Some(sample_hash(0xAB)));
        journal.persist().expect("persist journal");
        let persisted = PersistedQueryIndexStatus {
            version: QueryIndexJournal::JOURNAL_VERSION,
            status: journal.snapshot(),
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &persisted,
            "iroha_core::query::index_status::PersistedQueryIndexStatus",
        );
        assert_eq!(
            std::fs::read(&path).expect("actual persisted bytes"),
            norito::encode_canonical(&persisted).expect("declared journal owner frame")
        );
        let loaded = QueryIndexJournal::load(path).expect("reload journal");
        assert_eq!(loaded.snapshot(), journal.snapshot());
    }
    #[test]
    fn query_index_journal_promotes_temp_file_on_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(QueryIndexJournal::JOURNAL_FILE);
        let tmp_path = path.with_extension("norito.tmp");
        let payload = PersistedQueryIndexStatus {
            version: QueryIndexJournal::JOURNAL_VERSION,
            status: QueryIndexStatus {
                indexed_height: 7,
                indexed_block_hash: Some(sample_hash(0x11)),
            },
        };
        let bytes = to_bytes(&payload).expect("encode temp journal");
        fs::write(&tmp_path, bytes).expect("write temp journal");
        let loaded = QueryIndexJournal::load(path.clone()).expect("load journal");
        assert_eq!(loaded.snapshot().indexed_height, 7);
        assert!(path.exists(), "temp journal should be promoted");
        assert!(!tmp_path.exists(), "temp journal should be consumed");
    }
    #[test]
    fn query_index_journal_rejects_oversized_file_before_decode() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(QueryIndexJournal::JOURNAL_FILE);
        fs::write(
            &path,
            vec![
                0_u8;
                usize::try_from(QueryIndexJournal::JOURNAL_MAX_BYTES).expect("limit fits") + 1
            ],
        )
        .expect("write oversized journal");
        let error = QueryIndexJournal::load(path).expect_err("oversized journal must fail");
        assert!(
            error.to_string().contains("byte limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn index_status_load_propagates_every_promotion_failure_before_success() {
        for failure in PROMOTION_FAILURES {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(QueryIndexJournal::JOURNAL_FILE);
            let temporary = path.with_extension("norito.tmp");
            let main = PersistedQueryIndexStatus {
                version: QueryIndexJournal::JOURNAL_VERSION,
                status: QueryIndexStatus {
                    indexed_height: 1,
                    indexed_block_hash: None,
                },
            };
            let recovered = PersistedQueryIndexStatus {
                version: QueryIndexJournal::JOURNAL_VERSION,
                status: QueryIndexStatus {
                    indexed_height: 7,
                    indexed_block_hash: Some(sample_hash(0x31)),
                },
            };
            let main_bytes = to_bytes(&main).unwrap();
            let recovered_bytes = to_bytes(&recovered).unwrap();
            if failure != PromotionFailure::InitialRename {
                fs::write(&path, &main_bytes).unwrap();
            }
            fs::write(&temporary, &recovered_bytes).unwrap();
            QueryIndexJournal::fail_next_promotion_for_tests(failure);
            let error = QueryIndexJournal::load(&path)
                .expect_err("injected recovery must not report success");
            assert!(
                matches!(error, QueryIndexJournalError::Write { source, .. }
                if source.to_string() == format!("injected query journal promotion {failure:?}")),
                "{failure:?}"
            );
            assert!(
                !QueryIndexJournal::promotion_failure_pending_for_tests(),
                "{failure:?}"
            );
            match failure {
                PromotionFailure::InitialRename | PromotionFailure::RetryRename => {
                    assert!(!path.exists());
                    assert_eq!(fs::read(&temporary).unwrap(), recovered_bytes);
                }
                PromotionFailure::RemoveExisting => {
                    assert_eq!(fs::read(&path).unwrap(), main_bytes);
                    assert_eq!(fs::read(&temporary).unwrap(), recovered_bytes);
                }
                PromotionFailure::OpenParent | PromotionFailure::SyncParent => {
                    assert_eq!(fs::read(&path).unwrap(), recovered_bytes);
                    assert!(!temporary.exists());
                }
                PromotionFailure::InitialRenameForSuccessfulFallback => {
                    unreachable!("success-only fallback must not appear in PROMOTION_FAILURES");
                }
            }
            assert_eq!(
                QueryIndexJournal::load(&path).unwrap().snapshot(),
                recovered.status
            );
        }
    }

    #[test]
    fn index_status_load_completes_successful_replacement_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(QueryIndexJournal::JOURNAL_FILE);
        let temporary = path.with_extension("norito.tmp");
        let recovered = PersistedQueryIndexStatus {
            version: QueryIndexJournal::JOURNAL_VERSION,
            status: QueryIndexStatus {
                indexed_height: 37,
                indexed_block_hash: Some(sample_hash(0x47)),
            },
        };
        let bytes = to_bytes(&recovered).unwrap();
        fs::write(&path, b"old destination replaced by valid staged journal").unwrap();
        fs::write(&temporary, &bytes).unwrap();
        QueryIndexJournal::fail_next_promotion_for_tests(
            PromotionFailure::InitialRenameForSuccessfulFallback,
        );
        let loaded = QueryIndexJournal::load(&path).unwrap();
        assert!(!QueryIndexJournal::promotion_failure_pending_for_tests());
        assert_eq!(loaded.snapshot(), recovered.status);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!temporary.exists());
        assert_eq!(
            QueryIndexJournal::load(&path).unwrap().snapshot(),
            recovered.status
        );
    }

    #[test]
    fn index_status_relative_filename_recovery_and_persist_keep_directory_durability() {
        // A unique current-directory file permits a true bare filename without
        // mutating the process-wide current directory or sharing fixed names.
        let main_guard = tempfile::Builder::new()
            .prefix(".iroha-query-journal-")
            .suffix(".norito")
            .tempfile_in(".")
            .unwrap()
            .into_temp_path();
        let path = PathBuf::from(main_guard.file_name().unwrap());
        let temporary = path.with_extension("norito.tmp");
        let recovered = PersistedQueryIndexStatus {
            version: QueryIndexJournal::JOURNAL_VERSION,
            status: QueryIndexStatus {
                indexed_height: 37,
                indexed_block_hash: Some(sample_hash(0x47)),
            },
        };
        let bytes = to_bytes(&recovered).unwrap();
        let temporary_guard = {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .unwrap();
            let guard = tempfile::TempPath::try_from_path(temporary.clone()).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            guard
        };
        let loaded = QueryIndexJournal::load(&path).unwrap();
        assert_eq!(loaded.snapshot(), recovered.status);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!temporary.exists());
        loaded.persist().unwrap();
        assert_eq!(
            QueryIndexJournal::load(&path).unwrap().snapshot(),
            recovered.status
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!temporary.exists());
        drop(temporary_guard);
        drop(main_guard);
    }
}
