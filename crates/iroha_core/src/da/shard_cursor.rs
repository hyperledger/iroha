//! Durable shard cursor tracking for DA commitments.
//!
//! Each cursor records the highest `(epoch, sequence)` observed for one
//! `(shard_id, lane_id)` binding along with the block height that advanced it.
//! Sequence numbers are lane-scoped, so lanes mapped to the same storage shard
//! retain independent high-water marks. This index is rebuilt from the Kura
//! block log on startup so it remains consistent with committed history even
//! without a dedicated column family.
//! Durable candidates are rejected before allocation when their encoded size,
//! collection cardinality, or Norito decode budget exceeds protocol bounds.
use iroha_config::parameters::actual::LaneConfig;
use iroha_data_model::{
    da::commitment::{DaCommitmentBundle, DaCommitmentRecord},
    nexus::MAX_ACTIVE_EXECUTION_LANES,
};
use iroha_logger::warn;
use iroha_model_base::{topology::LaneId, topology::ShardId};
use norito::{
    DecodeLimits,
    codec::{Decode, Encode},
    decode_from_bytes_with_limits, to_bytes,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
/// First-release ceiling for cursor/reset records in one durable journal.
const SHARD_CURSOR_JOURNAL_MAX_ENTRIES: usize = MAX_ACTIVE_EXECUTION_LANES;
/// First-release encoded ceiling for one cursor journal candidate.
const SHARD_CURSOR_JOURNAL_MAX_BYTES: usize = 512 * 1024;
const SHARD_CURSOR_JOURNAL_MAX_DECODE_ALLOCATED_BYTES: usize = 1024 * 1024;
const SHARD_CURSOR_JOURNAL_MAX_DECODE_DEPTH: usize = 32;
/// Cursor describing the latest DA commitment accepted for a lane/shard binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaShardCursor {
    /// Shard identifier derived from lane configuration.
    pub shard_id: u32,
    /// Epoch of the last commitment observed for this shard.
    pub epoch: u64,
    /// Sequence of the last commitment observed for this shard.
    pub sequence: u64,
    /// Block height that recorded the cursor advance.
    pub last_block_height: u64,
}
impl DaShardCursor {
    /// Construct a new cursor.
    #[must_use]
    pub fn new(shard_id: u32, epoch: u64, sequence: u64, last_block_height: u64) -> Self {
        Self {
            shard_id,
            epoch,
            sequence,
            last_block_height,
        }
    }
}
/// Errors surfaced when attempting to regress or derive a shard cursor.
#[allow(variant_size_differences)]
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DaShardCursorError {
    /// A commitment failed to advance the cursor.
    #[error(
        "shard {shard_id} cursor regression for lane {lane_id} at block {block_height}: observed epoch {observed_epoch} sequence {observed_sequence} did not advance beyond current epoch {current_epoch} sequence {current_sequence}"
    )]
    Regression {
        /// Shard identifier being advanced.
        shard_id: u32,
        /// Lane identifier tied to the shard.
        lane_id: LaneId,
        /// Epoch advertised by the new commitment.
        observed_epoch: u64,
        /// Sequence advertised by the new commitment.
        observed_sequence: u64,
        /// Current cursor epoch.
        current_epoch: u64,
        /// Current cursor sequence.
        current_sequence: u64,
        /// Block height attempting to advance the cursor.
        block_height: u64,
    },
    /// Shard cursor required for a lane was missing.
    #[error(
        "missing DA shard cursor for lane {lane_id} (shard {shard_id}) at block {block_height}"
    )]
    MissingCursor {
        /// Lane identifier that required a cursor entry.
        lane_id: LaneId,
        /// Shard identifier derived from the lane mapping.
        shard_id: u32,
        /// Block height requiring a cursor advance.
        block_height: u64,
    },
    /// Shard cursor existed but was not advanced for the current block.
    #[error(
        "stale DA shard cursor for lane {lane_id} (shard {shard_id}): last advanced at block {observed_height}, required {required_height}"
    )]
    StaleCursor {
        /// Lane identifier that required a cursor entry.
        lane_id: LaneId,
        /// Shard identifier derived from the lane mapping.
        shard_id: u32,
        /// Block height recorded on the cursor.
        observed_height: u64,
        /// Block height requiring a cursor advance.
        required_height: u64,
    },
    /// Lane was not present in the lane catalog mapping.
    #[error("lane {lane_id} is not present in the shard mapping at block {block_height}")]
    UnknownLane {
        /// Lane identifier with no mapping.
        lane_id: LaneId,
        /// Block height attempting to advance the cursor.
        block_height: u64,
    },
}
/// In-memory lane/shard cursor index reconstructed from committed DA bundles.
#[derive(Debug, Default, Clone)]
pub struct DaShardCursorIndex {
    mapping: BTreeMap<LaneId, ShardId>,
    cursors: BTreeMap<(ShardId, LaneId), DaShardCursor>,
    canonical_reset_heights: BTreeMap<LaneId, u64>,
}
impl DaShardCursorIndex {
    /// Build a cursor index seeded with the current lane mapping.
    #[must_use]
    pub fn new(lane_config: &LaneConfig) -> Self {
        let mut index = Self::default();
        index.sync_mapping(lane_config);
        index
    }
    /// Refresh the lane→shard mapping and drop cursors whose binding disappeared.
    pub fn sync_mapping(&mut self, lane_config: &LaneConfig) {
        self.mapping = lane_config.shard_mapping();
        let mapping = &self.mapping;
        self.cursors
            .retain(|(shard_id, lane_id), _| mapping.get(lane_id) == Some(shard_id));
    }
    /// Return the current cursor for an exact lane/shard binding.
    #[must_use]
    pub fn get(&self, shard_id: u32, lane_id: LaneId) -> Option<&DaShardCursor> {
        self.cursors.get(&(ShardId::new(shard_id), lane_id))
    }
    /// Drop cursors owned by retired or reset lanes.
    pub fn prune_lanes(&mut self, lanes: &BTreeSet<LaneId>) {
        self.cursors
            .retain(|(_, lane_id), _| !lanes.contains(lane_id));
    }
    /// Remember that lane-scoped DA history at or before `reset_height` belongs
    /// to an earlier lane incarnation.
    pub fn mark_lanes_canonically_reset(&mut self, lanes: &BTreeSet<LaneId>, reset_height: u64) {
        for lane_id in lanes {
            self.canonical_reset_heights
                .entry(*lane_id)
                .and_modify(|height| *height = (*height).max(reset_height))
                .or_insert(reset_height);
        }
    }
    /// Replace reset watermarks, preserving any newer in-memory watermark.
    pub fn merge_canonical_reset_heights(
        &mut self,
        canonical_reset_heights: &BTreeMap<LaneId, u64>,
    ) {
        for (lane_id, reset_height) in canonical_reset_heights {
            self.canonical_reset_heights
                .entry(*lane_id)
                .and_modify(|height| *height = (*height).max(*reset_height))
                .or_insert(*reset_height);
        }
    }
    /// Return the last reset height recorded for a lane.
    #[must_use]
    pub fn canonical_reset_height_for_lane(&self, lane_id: LaneId) -> Option<u64> {
        self.canonical_reset_heights.get(&lane_id).copied()
    }
    /// Return all lane reset watermarks.
    #[must_use]
    pub fn canonical_reset_heights(&self) -> &BTreeMap<LaneId, u64> {
        &self.canonical_reset_heights
    }
    /// Advance the shard cursor using the supplied commitment.
    ///
    /// # Errors
    ///
    /// Returns [`DaShardCursorError::Regression`] when the commitment attempts
    /// to move the cursor backwards.
    pub fn advance(
        &mut self,
        shard_id: u32,
        record: &DaCommitmentRecord,
        block_height: u64,
    ) -> Result<(), DaShardCursorError> {
        let key = (ShardId::new(shard_id), record.lane_id);
        if let Some(cursor) = self.cursors.get(&key) {
            let current = (cursor.epoch, cursor.sequence);
            let observed = (record.epoch, record.sequence);
            if observed <= current {
                return Err(DaShardCursorError::Regression {
                    shard_id,
                    lane_id: record.lane_id,
                    observed_epoch: record.epoch,
                    observed_sequence: record.sequence,
                    current_epoch: cursor.epoch,
                    current_sequence: cursor.sequence,
                    block_height,
                });
            }
        }
        let cursor = DaShardCursor::new(shard_id, record.epoch, record.sequence, block_height);
        self.cursors.insert(key, cursor);
        Ok(())
    }
    #[cfg(test)]
    /// Bulk-advance cursors using all commitments in the bundle.
    ///
    /// # Errors
    ///
    /// Returns the first regression encountered.
    pub fn advance_bundle(
        &mut self,
        shard_id_for_lane: impl Fn(LaneId) -> u32,
        records: &[DaCommitmentRecord],
        block_height: u64,
    ) -> Result<(), DaShardCursorError> {
        let mut candidate = self.clone();
        for record in records {
            let shard_id = shard_id_for_lane(record.lane_id);
            candidate.advance(shard_id, record, block_height)?;
        }
        *self = candidate;
        Ok(())
    }
    /// Record all commitments in the bundle against the shard cursor index.
    ///
    /// # Errors
    ///
    /// Returns [`DaShardCursorError::Regression`] if any commitment attempts to regress an existing
    /// cursor or [`DaShardCursorError::UnknownLane`] when a commitment references an unmapped lane.
    pub fn record_bundle(
        &mut self,
        lane_config: &LaneConfig,
        bundle: &DaCommitmentBundle,
        block_height: u64,
    ) -> Result<(), DaShardCursorError> {
        self.record_records(lane_config, bundle.commitments(), block_height)
    }
    /// Record borrowed commitments against the shard cursor index.
    ///
    /// # Errors
    ///
    /// Returns [`DaShardCursorError::Regression`] if any commitment attempts to regress an existing
    /// cursor or [`DaShardCursorError::UnknownLane`] when a commitment references an unmapped lane.
    #[expect(
        single_use_lifetimes,
        reason = "stable Rust requires a named lifetime for borrowed impl Trait items"
    )]
    pub fn record_records<'a>(
        &mut self,
        lane_config: &LaneConfig,
        records: impl IntoIterator<Item = &'a DaCommitmentRecord>,
        block_height: u64,
    ) -> Result<(), DaShardCursorError> {
        let mut candidate = self.clone();
        candidate.sync_mapping(lane_config);
        for record in records {
            let shard_id = candidate.shard_id_for_lane(record.lane_id, block_height)?;
            candidate.advance(shard_id, record, block_height)?;
        }
        *self = candidate;
        Ok(())
    }
    fn shard_id_for_lane(
        &self,
        lane_id: LaneId,
        block_height: u64,
    ) -> Result<u32, DaShardCursorError> {
        self.mapping
            .get(&lane_id)
            .map(|id| id.as_u32())
            .ok_or(DaShardCursorError::UnknownLane {
                lane_id,
                block_height,
            })
    }
    /// Return true when no shard cursors are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursors.is_empty()
    }
    /// Restore a cursor entry sourced from a persisted journal.
    ///
    /// Returns `Ok(true)` when the entry was installed, `Ok(false)` when the entry was skipped
    /// because an equal or newer cursor already exists, or an error when the lane mapping no
    /// longer matches the journal entry.
    ///
    /// # Errors
    ///
    /// Returns [`DaShardCursorError::UnknownLane`] when the lane map no longer matches the stored
    /// shard identifier.
    pub fn restore_from_journal_entry(
        &mut self,
        lane_config: &LaneConfig,
        entry: &LaneShardCursor,
    ) -> Result<bool, DaShardCursorError> {
        self.sync_mapping(lane_config);
        let shard_id = self.shard_id_for_lane(entry.lane_id, entry.last_block_height)?;
        if shard_id != entry.shard_id.as_u32() {
            return Err(DaShardCursorError::UnknownLane {
                lane_id: entry.lane_id,
                block_height: entry.last_block_height,
            });
        }
        let candidate = (entry.epoch, entry.sequence, entry.last_block_height);
        let key = (entry.shard_id, entry.lane_id);
        let should_update = self.cursors.get(&key).is_none_or(|existing| {
            (
                existing.epoch,
                existing.sequence,
                existing.last_block_height,
            ) < candidate
        });
        if should_update {
            self.cursors.insert(
                key,
                DaShardCursor::new(
                    shard_id,
                    entry.epoch,
                    entry.sequence,
                    entry.last_block_height,
                ),
            );
            return Ok(true);
        }
        Ok(false)
    }
}
/// Persisted cursor for a `(shard_id, lane_id)` pair.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::da::shard_cursor::LaneShardCursor")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct LaneShardCursor {
    /// Shard identifier associated with the lane.
    pub shard_id: ShardId,
    /// Lane identifier.
    pub lane_id: LaneId,
    /// Epoch tied to the latest observed commitment.
    pub epoch: u64,
    /// Sequence tied to the latest observed commitment.
    pub sequence: u64,
    /// Block height that last advanced the cursor.
    pub last_block_height: u64,
}
/// Persisted representation of shard cursors.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::da::shard_cursor::PersistedShardCursors")]
struct PersistedShardCursors {
    /// Exact supported journal payload version.
    version: u32,
    /// Per-lane reset watermarks. Records at or before the watermark belong to
    /// an earlier lane incarnation and must not rehydrate active DA indexes.
    canonical_reset_heights: BTreeMap<LaneId, u64>,
    /// Stored cursor entries.
    entries: Vec<LaneShardCursor>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalRelation {
    Equal,
    CandidateAhead,
    CandidateBehind,
    Conflicting,
}
/// Errors returned when loading or persisting shard cursors.
#[derive(Debug, Error)]
pub enum ShardCursorJournalError {
    /// Failed to read the persisted journal.
    #[error("failed to read DA shard cursor journal {path}: {source}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to decode the persisted journal.
    #[error("failed to decode DA shard cursor journal {path}: {source}")]
    Decode {
        /// Path that failed.
        path: PathBuf,
        /// Source decode error.
        #[source]
        source: norito::core::Error,
    },
    /// Failed to write the journal to disk.
    #[error("failed to persist DA shard cursor journal {path}: {source}")]
    Write {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to encode the journal payload.
    #[error("failed to encode DA shard cursor journal: {0}")]
    Encode(#[source] norito::core::Error),
    /// Persisted journal contents were structurally invalid.
    #[error("invalid DA shard cursor journal {path}: {reason}")]
    InvalidEntry {
        /// Path for the journal.
        path: PathBuf,
        /// Structural validation failure.
        reason: String,
    },
    /// Lane was not present in the lane catalog mapping.
    #[error("lane {lane_id} is not present in the shard mapping")]
    UnknownLane {
        /// Lane identifier with no mapping.
        lane_id: LaneId,
    },
    /// A bundle failed to advance a lane-scoped shard cursor.
    #[error(
        "DA shard cursor regression for lane {lane_id} (shard {shard_id}) at block {block_height}: observed epoch {observed_epoch} sequence {observed_sequence} did not advance beyond current epoch {current_epoch} sequence {current_sequence}"
    )]
    Regression {
        /// Lane identifier that failed validation.
        lane_id: LaneId,
        /// Shard identifier tied to the lane.
        shard_id: ShardId,
        /// Epoch advertised by the new commitment.
        observed_epoch: u64,
        /// Sequence advertised by the new commitment.
        observed_sequence: u64,
        /// Current cursor epoch.
        current_epoch: u64,
        /// Current cursor sequence.
        current_sequence: u64,
        /// Block height attempting to advance the cursor.
        block_height: u64,
    },
    /// Persisted journal uses an unsupported version.
    #[error("unsupported DA shard cursor journal version {version} at {path}")]
    UnsupportedVersion {
        /// Path for the journal.
        path: PathBuf,
        /// Unsupported version encountered.
        version: u32,
    },
}
/// Journal that records shard cursors derived from DA commitments.
#[derive(Debug, Clone)]
pub struct DaShardCursorJournal {
    mapping: BTreeMap<LaneId, ShardId>,
    cursors: BTreeMap<(ShardId, LaneId), LaneShardCursor>,
    canonical_reset_heights: BTreeMap<LaneId, u64>,
    path: PathBuf,
}
impl DaShardCursorJournal {
    /// Filename used to persist shard cursor journals next to the DA spool.
    pub const JOURNAL_FILE: &'static str = "da-shard-cursors.norito";
    const JOURNAL_VERSION: u32 = 1;
    /// Build the canonical journal path under the provided root.
    #[must_use]
    pub fn journal_path(root: &Path) -> PathBuf {
        root.join(Self::JOURNAL_FILE)
    }
    /// Construct a fresh journal with an empty cursor set.
    #[must_use]
    pub fn new(lane_config: &LaneConfig, path: impl Into<PathBuf>) -> Self {
        Self {
            mapping: lane_config.shard_mapping(),
            cursors: BTreeMap::new(),
            canonical_reset_heights: BTreeMap::new(),
            path: path.into(),
        }
    }
    /// Load a journal from disk, dropping entries whose lane→shard binding no longer matches.
    ///
    /// Missing files are treated as empty journals.
    ///
    /// # Errors
    ///
    /// Returns [`ShardCursorJournalError::Read`], [`ShardCursorJournalError::Decode`], or
    /// [`ShardCursorJournalError::InvalidEntry`] when persistence cannot be read or trusted, or
    /// [`ShardCursorJournalError::Write`] when a recovered temp journal cannot be promoted durably.
    pub fn load(
        lane_config: &LaneConfig,
        path: impl Into<PathBuf>,
    ) -> Result<Self, ShardCursorJournalError> {
        let path = path.into();
        let mut journal = Self::new(lane_config, path.clone());
        if !Self::validate_journal_parent_for_read(&path)? {
            return Ok(journal);
        }
        let tmp_path = Self::temp_path(&path);
        let persisted = match Self::read_persisted(&path) {
            Ok(Some(persisted)) => match Self::read_persisted(&tmp_path) {
                Ok(Some(tmp_persisted)) => match Self::compare_journals(&persisted, &tmp_persisted)
                {
                    JournalRelation::CandidateAhead => {
                        warn!(
                            path = %tmp_path.display(),
                            "recovering newer DA shard cursor journal temp file"
                        );
                        Self::promote_temp(&tmp_path, &path)?;
                        Some(tmp_persisted)
                    }
                    JournalRelation::Equal | JournalRelation::CandidateBehind => {
                        Self::remove_temp(&tmp_path)?;
                        Some(persisted)
                    }
                    JournalRelation::Conflicting => {
                        warn!(
                            path = %tmp_path.display(),
                            "discarding conflicting DA shard cursor journal temp file"
                        );
                        Self::remove_temp(&tmp_path)?;
                        Some(persisted)
                    }
                },
                Ok(None) => Some(persisted),
                Err(err) => {
                    warn!(
                        ?err,
                        path = %tmp_path.display(),
                        "discarding unreadable DA shard cursor journal temp file"
                    );
                    Self::remove_temp(&tmp_path)?;
                    Some(persisted)
                }
            },
            Ok(None) => match Self::read_persisted(&tmp_path) {
                Ok(Some(persisted)) => {
                    Self::promote_temp(&tmp_path, &path)?;
                    Some(persisted)
                }
                Ok(None) => None,
                Err(err) => {
                    warn!(
                        ?err,
                        path = %tmp_path.display(),
                        "failed to read DA shard cursor journal temp file"
                    );
                    return Err(err);
                }
            },
            Err(err) => match Self::read_persisted(&tmp_path) {
                Ok(Some(persisted)) => {
                    warn!(
                        ?err,
                        path = %path.display(),
                        "DA shard cursor journal invalid; recovering from temp file"
                    );
                    Self::promote_temp(&tmp_path, &path)?;
                    Some(persisted)
                }
                Ok(None) => return Err(err),
                Err(tmp_err) => {
                    warn!(
                        ?tmp_err,
                        path = %tmp_path.display(),
                        "failed to read DA shard cursor journal temp file"
                    );
                    return Err(err);
                }
            },
        };
        if let Some(persisted) = persisted {
            journal.merge_canonical_reset_heights(&persisted.canonical_reset_heights);
            for entry in persisted.entries {
                let Some(expected) = journal.mapping.get(&entry.lane_id).copied() else {
                    warn!(
                        lane = %entry.lane_id.as_u32(),
                        shard = %entry.shard_id.as_u32(),
                        "dropping shard cursor: lane missing from catalog"
                    );
                    continue;
                };
                if expected != entry.shard_id {
                    warn!(
                        lane = %entry.lane_id.as_u32(),
                        stored = %entry.shard_id.as_u32(),
                        expected = %expected.as_u32(),
                        "dropping shard cursor: lane resharded since last run"
                    );
                    continue;
                }
                journal.upsert(entry);
            }
        }
        Ok(journal)
    }
    /// Record cursors for every commitment in the bundle.
    ///
    /// # Errors
    ///
    /// Returns [`ShardCursorJournalError::UnknownLane`] when a commitment references an unmapped
    /// lane, or [`ShardCursorJournalError::Regression`] when a commitment would move that lane's
    /// cursor backwards within its configured shard.
    pub fn record_bundle(
        &mut self,
        block_height: u64,
        bundle: &DaCommitmentBundle,
    ) -> Result<(), ShardCursorJournalError> {
        let mut candidate = self.clone();
        for record in bundle.commitments() {
            candidate.record_commitment(block_height, record)?;
        }
        *self = candidate;
        Ok(())
    }
    /// Record a single commitment against the shard journal.
    ///
    /// # Errors
    ///
    /// Returns [`ShardCursorJournalError::UnknownLane`] when the lane is not present in the catalog,
    /// or [`ShardCursorJournalError::Regression`] when the commitment does not advance the lane's
    /// `(epoch, sequence)` cursor.
    pub fn record_commitment(
        &mut self,
        block_height: u64,
        record: &DaCommitmentRecord,
    ) -> Result<(), ShardCursorJournalError> {
        let shard_id =
            *self
                .mapping
                .get(&record.lane_id)
                .ok_or(ShardCursorJournalError::UnknownLane {
                    lane_id: record.lane_id,
                })?;
        let key = (shard_id, record.lane_id);
        if let Some(current) = self.cursors.get(&key) {
            if (record.epoch, record.sequence) <= (current.epoch, current.sequence) {
                return Err(ShardCursorJournalError::Regression {
                    lane_id: record.lane_id,
                    shard_id,
                    observed_epoch: record.epoch,
                    observed_sequence: record.sequence,
                    current_epoch: current.epoch,
                    current_sequence: current.sequence,
                    block_height,
                });
            }
        }
        let entry = LaneShardCursor {
            shard_id,
            lane_id: record.lane_id,
            epoch: record.epoch,
            sequence: record.sequence,
            last_block_height: block_height,
        };
        self.upsert(entry);
        Ok(())
    }
    #[cfg(test)]
    /// Retrieve the cursor for a lane if present.
    #[must_use]
    pub fn cursor_for_lane(&self, lane_id: LaneId) -> Option<&LaneShardCursor> {
        self.mapping
            .get(&lane_id)
            .and_then(|shard_id| self.cursors.get(&(*shard_id, lane_id)))
    }
    /// Return the last reset height recorded for a lane.
    #[must_use]
    pub fn canonical_reset_height_for_lane(&self, lane_id: LaneId) -> Option<u64> {
        self.canonical_reset_heights.get(&lane_id).copied()
    }
    /// Return all persisted lane reset watermarks.
    #[must_use]
    pub fn canonical_reset_heights(&self) -> &BTreeMap<LaneId, u64> {
        &self.canonical_reset_heights
    }
    /// Merge reset watermarks, preserving the highest known height per lane.
    pub fn merge_canonical_reset_heights(
        &mut self,
        canonical_reset_heights: &BTreeMap<LaneId, u64>,
    ) {
        for (lane_id, reset_height) in canonical_reset_heights {
            self.canonical_reset_heights
                .entry(*lane_id)
                .and_modify(|height| *height = (*height).max(*reset_height))
                .or_insert(*reset_height);
        }
    }
    /// Snapshot the stored cursor entries (deduplicated per lane).
    pub fn entries(&self) -> impl Iterator<Item = &LaneShardCursor> {
        self.cursors.values()
    }
    /// Expose the underlying mapping for diagnostics.
    #[must_use]
    pub fn mapping(&self) -> &BTreeMap<LaneId, ShardId> {
        &self.mapping
    }
    /// Persist the current cursor set to disk.
    ///
    /// # Errors
    ///
    /// Returns [`ShardCursorJournalError::Write`] when the journal cannot be written or
    /// [`ShardCursorJournalError::Encode`] when encoding fails.
    pub fn persist(&self) -> Result<(), ShardCursorJournalError> {
        Self::validate_entry_counts(
            &self.path,
            self.cursors.len(),
            self.canonical_reset_heights.len(),
        )?;
        let entries: Vec<_> = self.cursors.values().copied().collect();
        let payload = PersistedShardCursors {
            version: Self::JOURNAL_VERSION,
            canonical_reset_heights: self.canonical_reset_heights.clone(),
            entries,
        };
        let bytes = to_bytes(&payload).map_err(ShardCursorJournalError::Encode)?;
        if bytes.len() > SHARD_CURSOR_JOURNAL_MAX_BYTES {
            return Err(ShardCursorJournalError::InvalidEntry {
                path: self.path.clone(),
                reason: format!(
                    "encoded journal is {} bytes (maximum {})",
                    bytes.len(),
                    SHARD_CURSOR_JOURNAL_MAX_BYTES
                ),
            });
        }
        Self::create_journal_parent_no_follow(&self.path)?;
        let tmp_path = Self::temp_path(&self.path);
        {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|source| ShardCursorJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            file.write_all(&bytes)
                .map_err(|source| ShardCursorJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            file.sync_all()
                .map_err(|source| ShardCursorJournalError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
        }
        Self::validate_journal_parent_for_write(&self.path)?;
        if let Err(err) = fs::rename(&tmp_path, &self.path) {
            if err.kind() == io::ErrorKind::AlreadyExists {
                fs::remove_file(&self.path).map_err(|source| ShardCursorJournalError::Write {
                    path: self.path.clone(),
                    source,
                })?;
                fs::rename(&tmp_path, &self.path).map_err(|source| {
                    ShardCursorJournalError::Write {
                        path: self.path.clone(),
                        source,
                    }
                })?;
            } else {
                return Err(ShardCursorJournalError::Write {
                    path: self.path.clone(),
                    source: err,
                });
            }
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                Self::validate_journal_parent_for_write(&self.path)?;
                sync_dir(parent).map_err(|source| ShardCursorJournalError::Write {
                    path: self.path.clone(),
                    source,
                })?;
            }
        }
        Ok(())
    }
    /// Build a journal populated from an in-memory cursor index.
    #[must_use]
    pub fn from_index(
        lane_config: &LaneConfig,
        index: &DaShardCursorIndex,
        path: impl Into<PathBuf>,
    ) -> Self {
        let mut journal = Self::new(lane_config, path);
        journal.merge_canonical_reset_heights(index.canonical_reset_heights());
        let mapping = journal.mapping.clone();
        for (lane_id, shard_id) in mapping {
            if let Some(cursor) = index.get(shard_id.as_u32(), lane_id) {
                let entry = LaneShardCursor {
                    shard_id,
                    lane_id,
                    epoch: cursor.epoch,
                    sequence: cursor.sequence,
                    last_block_height: cursor.last_block_height,
                };
                journal.upsert(entry);
            }
        }
        journal
    }
    fn upsert(&mut self, entry: LaneShardCursor) {
        let key = (entry.shard_id, entry.lane_id);
        let should_update = self
            .cursors
            .get(&key)
            .is_none_or(|existing| Self::should_advance(existing, &entry));
        if should_update {
            self.cursors.insert(key, entry);
        }
    }
    fn should_advance(current: &LaneShardCursor, candidate: &LaneShardCursor) -> bool {
        (candidate.epoch, candidate.sequence) > (current.epoch, current.sequence)
    }
    fn temp_path(path: &Path) -> PathBuf {
        path.with_extension("norito.tmp")
    }
    fn validate_journal_parent_for_read(path: &Path) -> Result<bool, ShardCursorJournalError> {
        let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Ok(true);
        };
        let metadata = match fs::symlink_metadata(parent) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(ShardCursorJournalError::Read {
                    path: parent.to_path_buf(),
                    source,
                });
            }
        };
        Self::validate_journal_dir_metadata(parent, &metadata).map_err(|source| {
            ShardCursorJournalError::Read {
                path: parent.to_path_buf(),
                source,
            }
        })?;
        Ok(true)
    }
    fn create_journal_parent_no_follow(path: &Path) -> Result<(), ShardCursorJournalError> {
        let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Ok(());
        };
        fs::create_dir_all(parent).map_err(|source| ShardCursorJournalError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Self::validate_journal_dir_no_follow(parent).map_err(|source| {
            ShardCursorJournalError::Write {
                path: path.to_path_buf(),
                source,
            }
        })
    }
    fn validate_journal_parent_for_write(path: &Path) -> Result<(), ShardCursorJournalError> {
        let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Ok(());
        };
        Self::validate_journal_dir_no_follow(parent).map_err(|source| {
            ShardCursorJournalError::Write {
                path: path.to_path_buf(),
                source,
            }
        })
    }
    fn validate_journal_dir_no_follow(dir: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(dir)?;
        Self::validate_journal_dir_metadata(dir, &metadata)
    }
    fn validate_journal_dir_metadata(dir: &Path, metadata: &fs::Metadata) -> io::Result<()> {
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "DA shard cursor journal directory `{}` is not a directory",
                    dir.display()
                ),
            ));
        }
        Ok(())
    }
    fn read_persisted(
        path: &Path,
    ) -> Result<Option<PersistedShardCursors>, ShardCursorJournalError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ShardCursorJournalError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if !metadata.file_type().is_file() {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DA shard cursor journal is not a regular file",
                ),
            });
        }
        if metadata.len() > u64::try_from(SHARD_CURSOR_JOURNAL_MAX_BYTES).unwrap_or(u64::MAX) {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "DA shard cursor journal exceeds its {SHARD_CURSOR_JOURNAL_MAX_BYTES}-byte hard limit"
                    ),
                ),
            });
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                .expect("NOFOLLOW flag bits fit the platform custom-flags type");
            options.custom_flags(nofollow);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ShardCursorJournalError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let opened_metadata = file
            .metadata()
            .map_err(|source| ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DA shard cursor journal changed while opening",
                ),
            });
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(opened_metadata.len())
                .unwrap_or(SHARD_CURSOR_JOURNAL_MAX_BYTES)
                .min(SHARD_CURSOR_JOURNAL_MAX_BYTES),
        );
        Read::by_ref(&mut file)
            .take(
                u64::try_from(SHARD_CURSOR_JOURNAL_MAX_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|source| ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() > SHARD_CURSOR_JOURNAL_MAX_BYTES {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DA shard cursor journal grew beyond its hard byte limit while reading",
                ),
            });
        }
        Self::revalidate_persisted_read(path, &metadata, bytes.len())?;
        let persisted: PersistedShardCursors =
            decode_from_bytes_with_limits(&bytes, Self::decode_limits()).map_err(|source| {
                ShardCursorJournalError::Decode {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        if persisted.version != Self::JOURNAL_VERSION {
            return Err(ShardCursorJournalError::UnsupportedVersion {
                path: path.to_path_buf(),
                version: persisted.version,
            });
        }
        Self::validate_persisted(path, &persisted)?;
        Ok(Some(persisted))
    }
    fn revalidate_persisted_read(
        path: &Path,
        metadata: &fs::Metadata,
        bytes_len: usize,
    ) -> Result<(), ShardCursorJournalError> {
        let current_metadata =
            fs::symlink_metadata(path).map_err(|source| ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if !current_metadata.file_type().is_file() {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DA shard cursor journal changed to a non-regular file while reading",
                ),
            });
        }
        if current_metadata.len() != metadata.len()
            || u64::try_from(bytes_len).ok() != Some(metadata.len())
        {
            return Err(ShardCursorJournalError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DA shard cursor journal changed while reading",
                ),
            });
        }
        Ok(())
    }
    fn validate_persisted(
        path: &Path,
        persisted: &PersistedShardCursors,
    ) -> Result<(), ShardCursorJournalError> {
        Self::validate_entry_counts(
            path,
            persisted.entries.len(),
            persisted.canonical_reset_heights.len(),
        )?;
        let mut seen_lanes = BTreeMap::new();
        let mut previous_key = None;
        for (index, entry) in persisted.entries.iter().enumerate() {
            let key = (entry.shard_id, entry.lane_id);
            if let Some(previous_shard_id) = seen_lanes.insert(entry.lane_id, entry.shard_id) {
                return Err(ShardCursorJournalError::InvalidEntry {
                    path: path.to_path_buf(),
                    reason: format!(
                        "duplicate cursor entry for lane {} (shards {} and {})",
                        entry.lane_id.as_u32(),
                        previous_shard_id.as_u32(),
                        entry.shard_id.as_u32()
                    ),
                });
            }
            if previous_key.is_some_and(|previous| key < previous) {
                return Err(ShardCursorJournalError::InvalidEntry {
                    path: path.to_path_buf(),
                    reason: format!("non-canonical cursor entry order at index {index}"),
                });
            }
            previous_key = Some(key);
        }
        Ok(())
    }
    fn validate_entry_counts(
        path: &Path,
        entries: usize,
        reset_heights: usize,
    ) -> Result<(), ShardCursorJournalError> {
        if entries > SHARD_CURSOR_JOURNAL_MAX_ENTRIES {
            return Err(ShardCursorJournalError::InvalidEntry {
                path: path.to_path_buf(),
                reason: format!(
                    "journal contains {entries} cursor entries (maximum {SHARD_CURSOR_JOURNAL_MAX_ENTRIES})"
                ),
            });
        }
        if reset_heights > SHARD_CURSOR_JOURNAL_MAX_ENTRIES {
            return Err(ShardCursorJournalError::InvalidEntry {
                path: path.to_path_buf(),
                reason: format!(
                    "journal contains {reset_heights} reset heights (maximum {SHARD_CURSOR_JOURNAL_MAX_ENTRIES})"
                ),
            });
        }
        Ok(())
    }
    fn decode_limits() -> DecodeLimits {
        DecodeLimits::new(
            SHARD_CURSOR_JOURNAL_MAX_ENTRIES,
            SHARD_CURSOR_JOURNAL_MAX_BYTES,
            SHARD_CURSOR_JOURNAL_MAX_ENTRIES.saturating_mul(4),
            SHARD_CURSOR_JOURNAL_MAX_DECODE_ALLOCATED_BYTES,
            SHARD_CURSOR_JOURNAL_MAX_DECODE_DEPTH,
        )
    }
    fn compare_journals(
        current: &PersistedShardCursors,
        candidate: &PersistedShardCursors,
    ) -> JournalRelation {
        let current_entries = Self::journal_entry_map(current);
        let candidate_entries = Self::journal_entry_map(candidate);
        let mut ahead = false;
        let mut behind = false;
        Self::compare_canonical_reset_heights(
            &current.canonical_reset_heights,
            &candidate.canonical_reset_heights,
            &mut ahead,
            &mut behind,
        );
        if ahead && behind {
            return JournalRelation::Conflicting;
        }
        for key in current_entries.keys().chain(candidate_entries.keys()) {
            match (current_entries.get(key), candidate_entries.get(key)) {
                (Some(current), Some(candidate)) if candidate > current => ahead = true,
                (Some(current), Some(candidate)) if candidate < current => behind = true,
                (None, Some(_)) => ahead = true,
                (Some(_), None) => behind = true,
                _ => {}
            }
            if ahead && behind {
                return JournalRelation::Conflicting;
            }
        }
        match (ahead, behind) {
            (false, false) => JournalRelation::Equal,
            (true, false) => JournalRelation::CandidateAhead,
            (false, true) => JournalRelation::CandidateBehind,
            (true, true) => JournalRelation::Conflicting,
        }
    }
    fn compare_canonical_reset_heights(
        current: &BTreeMap<LaneId, u64>,
        candidate: &BTreeMap<LaneId, u64>,
        ahead: &mut bool,
        behind: &mut bool,
    ) {
        for key in current.keys().chain(candidate.keys()) {
            match (current.get(key), candidate.get(key)) {
                (Some(current), Some(candidate)) if candidate > current => *ahead = true,
                (Some(current), Some(candidate)) if candidate < current => *behind = true,
                (None, Some(_)) => *ahead = true,
                (Some(_), None) => *behind = true,
                _ => {}
            }
            if *ahead && *behind {
                return;
            }
        }
    }
    fn journal_entry_map(
        persisted: &PersistedShardCursors,
    ) -> BTreeMap<(ShardId, LaneId), (u64, u64, u64)> {
        let mut entries = BTreeMap::new();
        for entry in &persisted.entries {
            let value = (entry.epoch, entry.sequence, entry.last_block_height);
            entries
                .entry((entry.shard_id, entry.lane_id))
                .and_modify(|current| {
                    if value > *current {
                        *current = value;
                    }
                })
                .or_insert(value);
        }
        entries
    }
    fn remove_temp(tmp_path: &Path) -> Result<(), ShardCursorJournalError> {
        match fs::remove_file(tmp_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ShardCursorJournalError::Write {
                path: tmp_path.to_path_buf(),
                source,
            }),
        }
    }
    fn promote_temp(tmp_path: &Path, path: &Path) -> Result<(), ShardCursorJournalError> {
        match fs::rename(tmp_path, path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(path).map_err(|source| ShardCursorJournalError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
                fs::rename(tmp_path, path).map_err(|source| ShardCursorJournalError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
            }
            Err(err) => {
                return Err(ShardCursorJournalError::Write {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                sync_dir(parent).map_err(|source| ShardCursorJournalError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
            }
        }
        Ok(())
    }
}
fn sync_dir(path: &Path) -> std::io::Result<()> {
    let file = fs::File::open(path)?;
    file.sync_all()
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::LaneConfig as ConfigLaneConfig;
    use iroha_crypto::{Hash, Signature};
    use iroha_data_model::{
        da::{
            commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofScheme, RetentionClass},
            types::{BlobDigest, StorageTicketId},
        },
        nexus::{LaneCatalog, LaneConfig as ModelLaneConfig, LaneStorageProfile, LaneVisibility},
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId, topology::ShardId};
    use std::{
        collections::{BTreeMap, BTreeSet},
        num::NonZeroU32,
        path::{Path, PathBuf},
    };
    use tempfile::tempdir;
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_core::da::shard_cursor::tests::PreReleaseLaneShardCursor")]
    #[derive(Encode)]
    struct PreReleaseLaneShardCursor {
        shard_id: ShardId,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::da::shard_cursor::tests::PreReleaseJournalWithoutCursorHeight"
    )]
    #[derive(Encode)]
    struct PreReleaseJournalWithoutCursorHeight {
        version: u32,
        canonical_reset_heights: BTreeMap<LaneId, u64>,
        entries: Vec<PreReleaseLaneShardCursor>,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::da::shard_cursor::tests::PreReleaseJournalWithoutResetHeights"
    )]
    #[derive(Encode)]
    struct PreReleaseJournalWithoutResetHeights {
        version: u32,
        entries: Vec<LaneShardCursor>,
    }
    fn sample_record(lane_id: u32, epoch: u64, sequence: u64) -> DaCommitmentRecord {
        let lane_byte = u8::try_from(lane_id).expect("lane fits in u8 for test record");
        let epoch_byte = u8::try_from(epoch).expect("epoch fits in u8 for test record");
        let sequence_byte = u8::try_from(sequence).expect("sequence fits in u8 for test record");
        DaCommitmentRecord::new(
            LaneId::new(lane_id),
            epoch,
            sequence,
            BlobDigest::new([lane_byte; 32]),
            ManifestDigest::new([epoch_byte; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([sequence_byte; 32]),
            None,
            RetentionClass::default(),
            StorageTicketId::new([0x22; 32]),
            Signature::try_from_bytes(&[0x33; 64])
                .expect("checked core DA shard cursor acknowledgement signature fixture"),
        )
    }
    fn lane_config_with_mappings(mappings: &[(u32, u32)]) -> ConfigLaneConfig {
        let lane_count = mappings
            .iter()
            .map(|(lane_id, _)| lane_id.saturating_add(1))
            .max()
            .unwrap_or(1);
        let catalog = LaneCatalog::new(
            NonZeroU32::new(lane_count).expect("lane count"),
            mappings
                .iter()
                .map(|(lane_id, shard_id)| ModelLaneConfig {
                    id: LaneId::new(*lane_id),
                    shard_id: Some(ShardId::new(*shard_id)),
                    dataspace_id: DataSpaceId::UNIVERSAL,
                    alias: format!("lane{lane_id}"),
                    ..ModelLaneConfig::default()
                })
                .collect(),
        )
        .expect("lane catalog");
        ConfigLaneConfig::from_catalog(&catalog)
    }
    fn lane_config_with_mapping(lane_id: u32, shard_id: u32) -> ConfigLaneConfig {
        lane_config_with_mappings(&[(lane_id, shard_id)])
    }
    fn journal_entry(
        lane_id: u32,
        shard_id: u32,
        epoch: u64,
        sequence: u64,
        last_block_height: u64,
    ) -> LaneShardCursor {
        LaneShardCursor {
            shard_id: ShardId::new(shard_id),
            lane_id: LaneId::new(lane_id),
            epoch,
            sequence,
            last_block_height,
        }
    }
    fn write_journal_payload(path: &Path, entries: Vec<LaneShardCursor>) {
        let payload = PersistedShardCursors {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            canonical_reset_heights: BTreeMap::new(),
            entries,
        };
        fs::write(path, to_bytes(&payload).expect("encode cursor journal"))
            .expect("write cursor journal");
    }
    #[test]
    fn advances_and_records_height() {
        let mut index = DaShardCursorIndex::default();
        let record = sample_record(1, 2, 3);
        index
            .advance(99, &record, 7)
            .expect("advance should succeed");
        let cursor = index.get(99, LaneId::new(1)).expect("cursor present");
        assert_eq!(cursor.shard_id, 99);
        assert_eq!(cursor.epoch, 2);
        assert_eq!(cursor.sequence, 3);
        assert_eq!(cursor.last_block_height, 7);
    }
    #[test]
    fn rejects_regression() {
        let mut index = DaShardCursorIndex::default();
        let first = sample_record(1, 5, 7);
        index
            .advance(1, &first, 10)
            .expect("first advance should succeed");
        let regressing = sample_record(1, 5, 6);
        let err = index
            .advance(1, &regressing, 11)
            .expect_err("regression should be rejected");
        match err {
            DaShardCursorError::Regression {
                shard_id, lane_id, ..
            } => {
                assert_eq!(shard_id, 1);
                assert_eq!(lane_id, LaneId::new(1));
            }
            other => panic!("expected regression, got {other:?}"),
        }
        let cursor = index
            .get(1, LaneId::new(1))
            .expect("cursor should remain unchanged");
        assert_eq!(cursor.sequence, 7);
        assert_eq!(cursor.last_block_height, 10);
    }
    #[test]
    fn advance_bundle_handles_multiple_lanes() {
        let mut index = DaShardCursorIndex::default();
        let records = vec![
            sample_record(1, 1, 1),
            sample_record(2, 2, 3),
            sample_record(1, 2, 0),
        ];
        index
            .advance_bundle(|lane| lane.as_u32() + 10, &records, 5)
            .expect("bundle should advance cursors");
        let shard_one = index
            .get(11, LaneId::new(1))
            .expect("lane 1 shard cursor present");
        assert_eq!(shard_one.epoch, 2);
        assert_eq!(shard_one.sequence, 0);
        assert_eq!(shard_one.last_block_height, 5);
        let shard_two = index
            .get(12, LaneId::new(2))
            .expect("lane 2 shard cursor present");
        assert_eq!(shard_two.epoch, 2);
        assert_eq!(shard_two.sequence, 3);
        assert_eq!(shard_two.last_block_height, 5);
    }
    #[test]
    fn advance_bundle_rejects_regression_and_rolls_back() {
        let mut index = DaShardCursorIndex::default();
        index
            .advance(11, &sample_record(1, 1, 7), 4)
            .expect("seed shard cursor");
        let records = vec![sample_record(2, 1, 8), sample_record(1, 1, 6)];
        let err = index
            .advance_bundle(|lane| lane.as_u32() + 10, &records, 5)
            .expect_err("later shard regression should reject the whole bundle");
        assert!(matches!(err, DaShardCursorError::Regression { .. }));
        assert!(
            index.get(12, LaneId::new(2)).is_none(),
            "earlier record from rejected bundle must not be retained"
        );
        let cursor = index
            .get(11, LaneId::new(1))
            .expect("seed cursor should remain");
        assert_eq!(cursor.sequence, 7);
        assert_eq!(cursor.last_block_height, 4);
    }
    #[test]
    fn record_bundle_syncs_mapping() {
        let bundle = DaCommitmentBundle::new(vec![sample_record(1, 7, 9)]);
        let mut index = DaShardCursorIndex::new(&ConfigLaneConfig::default());
        let config = lane_config_with_mapping(1, 10);
        index
            .record_bundle(&config, &bundle, 5)
            .expect("record bundle");
        let cursor = index.get(10, LaneId::new(1)).expect("cursor present");
        assert_eq!(cursor.epoch, 7);
        assert_eq!(cursor.sequence, 9);
        assert_eq!(cursor.last_block_height, 5);
    }
    #[test]
    fn bundle_rejects_unknown_lane() {
        let config = ConfigLaneConfig::default();
        let bundle = DaCommitmentBundle::new(vec![sample_record(5, 1, 1)]);
        let mut index = DaShardCursorIndex::default();
        let err = index
            .record_bundle(&config, &bundle, 1)
            .expect_err("lane missing from config");
        assert!(matches!(err, DaShardCursorError::UnknownLane { .. }));
    }
    #[test]
    fn record_records_rejects_unknown_lane() {
        let config = lane_config_with_mapping(0, 1);
        let mut index = DaShardCursorIndex::new(&config);
        let unknown = sample_record(3, 1, 0);
        let err = index
            .record_records(&config, &[unknown], 9)
            .expect_err("lane must be present in mapping");
        assert!(
            matches!(err, DaShardCursorError::UnknownLane { lane_id, .. } if lane_id == LaneId::new(3))
        );
        assert!(
            index.get(3, LaneId::new(3)).is_none(),
            "cursor should remain untouched"
        );
    }
    #[test]
    fn borrowed_bundle_positions_exclude_hidden_rows_and_keep_rollback() {
        let config = lane_config_with_mappings(&[(0, 7), (1, 8)]);
        let records = [
            sample_record(0, 1, 4),
            sample_record(9, 9, 9),
            sample_record(1, 2, 6),
        ];
        let positions = [0, 2];
        let mut index = DaShardCursorIndex::new(&config);
        index
            .record_records(&config, positions.iter().map(|&i| &records[i]), 3)
            .unwrap();
        assert_eq!(index.get(7, LaneId::new(0)).unwrap().sequence, 4);
        assert_eq!(index.get(8, LaneId::new(1)).unwrap().sequence, 6);
        assert!(index.get(9, LaneId::new(9)).is_none());
        let rejected = [
            sample_record(0, 1, 5),
            sample_record(9, 9, 9),
            sample_record(1, 2, 5),
        ];
        assert!(
            index
                .record_records(&config, positions.iter().map(|&i| &rejected[i]), 4)
                .is_err()
        );
        assert_eq!(index.get(7, LaneId::new(0)).unwrap().sequence, 4);
        assert_eq!(index.get(8, LaneId::new(1)).unwrap().sequence, 6);
    }
    #[test]
    fn record_records_rolls_back_when_later_record_regresses() {
        let lane_config = {
            let lanes = (0..=1)
                .map(|lane_id| ModelLaneConfig {
                    id: LaneId::new(lane_id),
                    shard_id: Some(ShardId::new(lane_id)),
                    dataspace_id: DataSpaceId::UNIVERSAL,
                    alias: format!("lane{lane_id}"),
                    ..ModelLaneConfig::default()
                })
                .collect();
            let catalog = LaneCatalog::new(NonZeroU32::new(2).expect("lane count"), lanes)
                .expect("lane catalog");
            ConfigLaneConfig::from_catalog(&catalog)
        };
        let mut index = DaShardCursorIndex::new(&lane_config);
        index
            .record_records(
                &lane_config,
                &[sample_record(0, 1, 1), sample_record(1, 3, 3)],
                1,
            )
            .expect("initial records");
        let err = index
            .record_records(
                &lane_config,
                &[sample_record(0, 2, 0), sample_record(1, 3, 2)],
                2,
            )
            .expect_err("later regression must fail");
        assert!(
            matches!(err, DaShardCursorError::Regression { lane_id, .. } if lane_id == LaneId::new(1))
        );
        let lane0 = index.get(0, LaneId::new(0)).expect("lane 0 cursor remains");
        assert_eq!(
            (lane0.epoch, lane0.sequence, lane0.last_block_height),
            (1, 1, 1),
            "earlier successful candidate advance must roll back"
        );
        let lane1 = index.get(1, LaneId::new(1)).expect("lane 1 cursor remains");
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (3, 3, 1)
        );
    }
    #[test]
    fn record_records_tracks_same_shard_lanes_independently() {
        let config = lane_config_with_mappings(&[(0, 7), (1, 7)]);
        let mut index = DaShardCursorIndex::new(&config);
        index
            .record_records(
                &config,
                &[sample_record(0, 5, 0), sample_record(1, 4, 9)],
                1,
            )
            .expect("lane-scoped sequences may differ inside one shard");

        let lane0 = index
            .get(7, LaneId::new(0))
            .expect("lane 0 cursor in shared shard");
        assert_eq!((lane0.epoch, lane0.sequence), (5, 0));
        let lane1 = index
            .get(7, LaneId::new(1))
            .expect("lane 1 cursor in shared shard");
        assert_eq!((lane1.epoch, lane1.sequence), (4, 9));

        let err = index
            .record_records(&config, &[sample_record(1, 4, 8)], 2)
            .expect_err("a lane must not regress its own shared-shard cursor");
        assert!(
            matches!(err, DaShardCursorError::Regression { lane_id, shard_id: 7, .. }
                if lane_id == LaneId::new(1))
        );
        let lane1 = index
            .get(7, LaneId::new(1))
            .expect("rejected advance leaves lane 1 cursor intact");
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (4, 9, 1)
        );
    }
    #[test]
    fn record_records_respects_reshard_mapping() {
        let initial_config = lane_config_with_mapping(4, 5);
        let mut index = DaShardCursorIndex::new(&initial_config);
        index
            .record_records(&initial_config, &[sample_record(4, 1, 1)], 3)
            .expect("initial record");
        assert!(
            index.get(5, LaneId::new(4)).is_some(),
            "cursor stored under original shard"
        );
        let resharded_config = lane_config_with_mapping(4, 7);
        index
            .record_records(&resharded_config, &[sample_record(4, 2, 0)], 4)
            .expect("reshard record");
        assert!(
            index.get(5, LaneId::new(4)).is_none(),
            "old shard cursor should be removed"
        );
        let cursor = index
            .get(7, LaneId::new(4))
            .expect("cursor stored under new shard id");
        assert_eq!((cursor.epoch, cursor.sequence), (2, 0));
        assert_eq!(cursor.last_block_height, 4);
    }
    #[test]
    fn resharding_one_lane_does_not_drop_shared_shard_peer_cursor() {
        let initial_config = lane_config_with_mappings(&[(0, 5), (1, 5)]);
        let mut index = DaShardCursorIndex::new(&initial_config);
        index
            .record_records(
                &initial_config,
                &[sample_record(0, 3, 4), sample_record(1, 2, 8)],
                3,
            )
            .expect("seed independent cursors in the shared shard");

        let updated_config = lane_config_with_mappings(&[(0, 5), (1, 7)]);
        index
            .record_records(&updated_config, &[sample_record(1, 3, 0)], 4)
            .expect("resharded lane starts its new binding independently");

        let lane0 = index
            .get(5, LaneId::new(0))
            .expect("retained lane keeps its shared-shard cursor");
        assert_eq!(
            (lane0.epoch, lane0.sequence, lane0.last_block_height),
            (3, 4, 3)
        );
        assert!(
            index.get(5, LaneId::new(1)).is_none(),
            "resharded lane must not retain its old binding"
        );
        let lane1 = index
            .get(7, LaneId::new(1))
            .expect("resharded lane cursor uses its new binding");
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (3, 0, 4)
        );
    }
    #[test]
    fn prune_lanes_removes_unshared_reset_shards() {
        let config = lane_config_with_mappings(&[(0, 0), (1, 1)]);
        let mut index = DaShardCursorIndex::new(&config);
        index
            .record_records(
                &config,
                &[sample_record(0, 1, 0), sample_record(1, 1, 0)],
                3,
            )
            .expect("seed lane shard cursors");
        index.prune_lanes(&BTreeSet::from([LaneId::new(1)]));
        assert!(
            index.get(0, LaneId::new(0)).is_some(),
            "retained lane shard should remain"
        );
        assert!(
            index.get(1, LaneId::new(1)).is_none(),
            "reset lane's unshared shard cursor should be cleared"
        );
    }
    #[test]
    fn prune_lanes_removes_only_reset_lane_from_shared_shard() {
        let config = lane_config_with_mappings(&[(0, 7), (1, 7)]);
        let mut index = DaShardCursorIndex::new(&config);
        index
            .record_records(
                &config,
                &[sample_record(0, 1, 0), sample_record(1, 1, 1)],
                3,
            )
            .expect("seed shared shard cursor");
        index.prune_lanes(&BTreeSet::from([LaneId::new(1)]));
        let cursor = index
            .get(7, LaneId::new(0))
            .expect("shared shard cursor must remain for retained lane");
        assert_eq!((cursor.epoch, cursor.sequence), (1, 0));
        assert!(
            index.get(7, LaneId::new(1)).is_none(),
            "reset lane's cursor must be removed without affecting the retained lane"
        );
    }
    #[test]
    fn journal_from_index_preserves_independent_shared_shard_cursors() {
        let config = lane_config_with_mappings(&[(0, 7), (1, 7)]);
        let mut index = DaShardCursorIndex::new(&config);
        index
            .record_records(
                &config,
                &[sample_record(0, 5, 0), sample_record(1, 4, 9)],
                6,
            )
            .expect("seed independent shared-shard cursors");

        let journal = DaShardCursorJournal::from_index(&config, &index, PathBuf::from("unused"));
        let lane0 = journal
            .cursor_for_lane(LaneId::new(0))
            .expect("lane 0 journal cursor");
        assert_eq!((lane0.epoch, lane0.sequence), (5, 0));
        let lane1 = journal
            .cursor_for_lane(LaneId::new(1))
            .expect("lane 1 journal cursor");
        assert_eq!((lane1.epoch, lane1.sequence), (4, 9));
    }
    #[test]
    fn shard_cursor_frame_owner_roundtrips_through_durable_reader() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let payload = PersistedShardCursors {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            canonical_reset_heights: BTreeMap::from([(LaneId::new(0), 4)]),
            entries: vec![journal_entry(0, 0, 2, 3, 5)],
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &payload,
            "iroha_core::da::shard_cursor::PersistedShardCursors",
        );
        let bytes = norito::encode_canonical(&payload).expect("cursor frame");
        fs::write(&path, &bytes).expect("write journal");
        assert_eq!(
            DaShardCursorJournal::read_persisted(&path).expect("durable read"),
            Some(payload)
        );
        let mut wrong_owner = bytes;
        wrong_owner[6] ^= 1;
        fs::write(&path, wrong_owner).expect("write substituted owner");
        assert!(matches!(
            DaShardCursorJournal::read_persisted(&path),
            Err(ShardCursorJournalError::Decode {
                source: norito::Error::SchemaMismatch,
                ..
            })
        ));
    }
    fn frame_cursor_test_payload<T: norito::SerializePayload>(value: &T) -> Vec<u8> {
        let _canonical =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (payload, flags) = norito::codec::encode_with_header_flags(value);
        norito::core::frame_bare_with_header_flags::<PersistedShardCursors>(&payload, flags)
            .expect("frame test payload under the actual cursor owner")
    }
    #[test]
    fn journal_persists_and_recovers_cursors() {
        let dir = tempdir().expect("tempdir");
        let catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("lane count"),
            vec![ModelLaneConfig {
                id: LaneId::new(0),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "lane".to_string(),
                description: None,
                visibility: LaneVisibility::Public,
                lane_type: None,
                governance: None,
                settlement: None,
                storage: LaneStorageProfile::FullReplica,
                proof_scheme: DaProofScheme::default(),
                manifest_policy: iroha_data_model::nexus::DaManifestPolicy::default(),
                confidential_compute: None,
                scheduler: None,
                settlement_buffer: None,
                metadata: BTreeMap::default(),
            }],
        )
        .expect("catalog");
        let lane_config = ConfigLaneConfig::from_catalog(&catalog);
        let path = DaShardCursorJournal::journal_path(dir.path());
        {
            let mut journal = DaShardCursorJournal::new(&lane_config, path.clone());
            let record = DaCommitmentRecord::new(
                LaneId::new(0),
                1,
                2,
                BlobDigest::new([0xAA; 32]),
                ManifestDigest::new([0xBB; 32]),
                DaProofScheme::MerkleSha256,
                Hash::prehashed([0xCC; 32]),
                None,
                RetentionClass::default(),
                StorageTicketId::new([0xEE; 32]),
                Signature::try_from_bytes(&[0x11; 64])
                    .expect("checked core DA shard cursor acknowledgement signature fixture"),
            );
            journal
                .record_commitment(1, &record)
                .expect("record commitment");
            journal.merge_canonical_reset_heights(&BTreeMap::from([(LaneId::new(0), 7)]));
            journal.merge_canonical_reset_heights(&BTreeMap::from([(LaneId::new(0), 5)]));
            journal.persist().expect("persist");
        }
        let loaded = DaShardCursorJournal::load(&lane_config, path).expect("load");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!(cursor.shard_id, ShardId::new(0));
        assert_eq!(cursor.epoch, 1);
        assert_eq!(cursor.sequence, 2);
        assert_eq!(
            loaded.canonical_reset_height_for_lane(LaneId::new(0)),
            Some(7)
        );
    }
    #[test]
    fn journal_persist_rejects_existing_temp_without_truncating() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        fs::write(&tmp_path, b"existing-shard-cursor-temp").expect("seed temp journal");
        let mut journal = DaShardCursorJournal::new(&config, path.clone());
        journal
            .record_commitment(1, &sample_record(0, 1, 1))
            .expect("record commitment");
        let err = journal
            .persist()
            .expect_err("existing temp journal should reject persistence");
        match err {
            ShardCursorJournalError::Write {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, tmp_path);
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(
            fs::read(&tmp_path).expect("read temp journal after failed persist"),
            b"existing-shard-cursor-temp"
        );
        assert!(
            !path.exists(),
            "failed persistence must not promote the temp journal"
        );
    }
    #[cfg(unix)]
    #[test]
    fn journal_persist_rejects_journal_dir_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("cursor-root-target");
        fs::create_dir(&target).expect("create cursor target directory");
        let link = dir.path().join("cursor-root-link");
        symlink(&target, &link).expect("create cursor root symlink");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(&link);
        let mut journal = DaShardCursorJournal::new(&config, path.clone());
        journal
            .record_commitment(1, &sample_record(0, 1, 1))
            .expect("record commitment");
        let err = journal
            .persist()
            .expect_err("symlinked cursor journal root must reject persistence");
        match err {
            ShardCursorJournalError::Write {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, path);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            fs::symlink_metadata(&link)
                .expect("inspect root symlink")
                .file_type()
                .is_symlink(),
            "failed persistence should leave root symlink visible"
        );
        assert!(
            !DaShardCursorJournal::journal_path(&target).exists(),
            "symlink target must not receive cursor journal"
        );
        assert!(
            !DaShardCursorJournal::temp_path(&DaShardCursorJournal::journal_path(&target)).exists(),
            "symlink target must not receive temp cursor journal"
        );
    }
    #[test]
    fn journal_load_promotes_temp_file() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        {
            let mut journal = DaShardCursorJournal::new(&config, path.clone());
            journal
                .record_commitment(1, &sample_record(0, 1, 2))
                .expect("record commitment");
            journal.persist().expect("persist");
        }
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        fs::rename(&path, &tmp_path).expect("move journal to temp");
        let loaded = DaShardCursorJournal::load(&config, path.clone()).expect("load");
        assert!(path.exists(), "expected journal promoted to main");
        assert!(!tmp_path.exists(), "temp journal should be removed");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!((cursor.epoch, cursor.sequence), (1, 2));
    }
    #[test]
    fn journal_load_promotes_newer_temp_when_main_valid() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        write_journal_payload(&path, vec![journal_entry(0, 0, 1, 2, 1)]);
        write_journal_payload(&tmp_path, vec![journal_entry(0, 0, 2, 0, 2)]);
        let loaded = DaShardCursorJournal::load(&config, path.clone()).expect("load");
        assert!(path.exists(), "expected newer temp promoted to main");
        assert!(!tmp_path.exists(), "newer temp should be consumed");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!(
            (cursor.epoch, cursor.sequence, cursor.last_block_height),
            (2, 0, 2)
        );
        let reloaded = DaShardCursorJournal::load(&config, path).expect("reload");
        let persisted = reloaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!(
            (
                persisted.epoch,
                persisted.sequence,
                persisted.last_block_height
            ),
            (2, 0, 2)
        );
    }
    #[test]
    fn journal_load_discards_older_temp_when_main_valid() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        write_journal_payload(&path, vec![journal_entry(0, 0, 3, 1, 4)]);
        write_journal_payload(&tmp_path, vec![journal_entry(0, 0, 2, 9, 3)]);
        let loaded = DaShardCursorJournal::load(&config, path).expect("load");
        assert!(!tmp_path.exists(), "older temp should be removed");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!(
            (cursor.epoch, cursor.sequence, cursor.last_block_height),
            (3, 1, 4)
        );
    }
    #[test]
    fn journal_load_discards_conflicting_temp_when_main_valid() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mappings(&[(0, 0), (1, 1)]);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        write_journal_payload(
            &path,
            vec![journal_entry(0, 0, 4, 0, 4), journal_entry(1, 1, 4, 0, 4)],
        );
        write_journal_payload(
            &tmp_path,
            vec![journal_entry(0, 0, 5, 0, 5), journal_entry(1, 1, 3, 9, 3)],
        );
        let loaded = DaShardCursorJournal::load(&config, path).expect("load");
        assert!(!tmp_path.exists(), "conflicting temp should be removed");
        let lane0 = loaded.cursor_for_lane(LaneId::new(0)).expect("lane 0");
        let lane1 = loaded.cursor_for_lane(LaneId::new(1)).expect("lane 1");
        assert_eq!(
            (lane0.epoch, lane0.sequence, lane0.last_block_height),
            (4, 0, 4)
        );
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (4, 0, 4)
        );
    }
    #[test]
    fn journal_load_removes_corrupt_temp_when_main_valid() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        write_journal_payload(&path, vec![journal_entry(0, 0, 1, 2, 1)]);
        fs::write(&tmp_path, b"corrupt").expect("write corrupt temp");
        let loaded = DaShardCursorJournal::load(&config, path).expect("load");
        assert!(!tmp_path.exists(), "corrupt temp should be removed");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!(
            (cursor.epoch, cursor.sequence, cursor.last_block_height),
            (1, 2, 1)
        );
    }
    #[test]
    fn journal_load_rejects_orphan_corrupt_temp_file() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        fs::write(&tmp_path, b"corrupt").expect("write corrupt temp");
        let err = DaShardCursorJournal::load(&config, path)
            .expect_err("orphan corrupt temp journal should fail closed");
        match err {
            ShardCursorJournalError::Decode { path: err_path, .. } => {
                assert_eq!(err_path, tmp_path)
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            tmp_path.exists(),
            "orphan corrupt temp journal should remain visible for operator repair"
        );
    }
    #[cfg(unix)]
    #[test]
    fn journal_load_rejects_main_journal_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let target = dir.path().join("cursor-target.norito");
        write_journal_payload(&target, vec![journal_entry(0, 0, 1, 2, 1)]);
        symlink(&target, &path).expect("create main cursor journal symlink");
        let err = DaShardCursorJournal::load(&config, path.clone())
            .expect_err("main cursor journal symlink should fail closed");
        match err {
            ShardCursorJournalError::Read {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, path);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            fs::symlink_metadata(&path)
                .expect("inspect symlink")
                .file_type()
                .is_symlink(),
            "failed recovery should leave main symlink visible"
        );
        assert!(target.exists(), "symlink target should not be removed");
    }
    #[cfg(unix)]
    #[test]
    fn journal_load_rejects_journal_dir_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("cursor-root-target");
        fs::create_dir(&target).expect("create cursor target directory");
        let target_path = DaShardCursorJournal::journal_path(&target);
        write_journal_payload(&target_path, vec![journal_entry(0, 0, 1, 2, 1)]);
        let link = dir.path().join("cursor-root-link");
        symlink(&target, &link).expect("create cursor root symlink");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(&link);
        let err = DaShardCursorJournal::load(&config, path)
            .expect_err("symlinked cursor journal root should fail closed");
        match err {
            ShardCursorJournalError::Read {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, link);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            fs::symlink_metadata(&link)
                .expect("inspect root symlink")
                .file_type()
                .is_symlink(),
            "failed recovery should leave root symlink visible"
        );
        assert!(
            target_path.exists(),
            "failed recovery should not remove target cursor journal"
        );
    }
    #[cfg(unix)]
    #[test]
    fn journal_load_rejects_orphan_temp_journal_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        let target = dir.path().join("cursor-temp-target.norito");
        write_journal_payload(&target, vec![journal_entry(0, 0, 1, 2, 1)]);
        symlink(&target, &tmp_path).expect("create temp cursor journal symlink");
        let err = DaShardCursorJournal::load(&config, path)
            .expect_err("orphan temp cursor journal symlink should fail closed");
        match err {
            ShardCursorJournalError::Read {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, tmp_path);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            fs::symlink_metadata(&tmp_path)
                .expect("inspect symlink")
                .file_type()
                .is_symlink(),
            "failed recovery should leave temp symlink visible"
        );
        assert!(target.exists(), "symlink target should not be removed");
    }
    #[test]
    fn journal_read_revalidation_rejects_length_change() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        fs::write(&path, b"old-journal").expect("write initial journal");
        let metadata = fs::symlink_metadata(&path).expect("inspect initial journal");
        fs::write(&path, b"new-journal-with-more-bytes").expect("replace journal bytes");
        let err =
            DaShardCursorJournal::revalidate_persisted_read(&path, &metadata, b"old-journal".len())
                .expect_err("post-read length changes must reject shard cursor journals");
        match err {
            ShardCursorJournalError::Read {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, path);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
                assert!(
                    source.to_string().contains("changed while reading"),
                    "unexpected revalidation error: {source}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn journal_resource_limits_reject_first_overflow_without_allocating_it() {
        let path = Path::new("da-shard-cursors.norito");
        DaShardCursorJournal::validate_entry_counts(
            path,
            SHARD_CURSOR_JOURNAL_MAX_ENTRIES,
            SHARD_CURSOR_JOURNAL_MAX_ENTRIES,
        )
        .expect("exact cursor/reset limits are valid");
        assert!(matches!(
            DaShardCursorJournal::validate_entry_counts(
                path,
                SHARD_CURSOR_JOURNAL_MAX_ENTRIES + 1,
                0,
            ),
            Err(ShardCursorJournalError::InvalidEntry { reason, .. })
                if reason.contains("cursor entries")
        ));
        assert!(matches!(
            DaShardCursorJournal::validate_entry_counts(
                path,
                0,
                SHARD_CURSOR_JOURNAL_MAX_ENTRIES + 1,
            ),
            Err(ShardCursorJournalError::InvalidEntry { reason, .. })
                if reason.contains("reset heights")
        ));
    }
    #[test]
    fn journal_load_rejects_oversized_sparse_file_before_decode() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        fs::File::create(&path)
            .and_then(|file| {
                file.set_len(
                    u64::try_from(SHARD_CURSOR_JOURNAL_MAX_BYTES + 1)
                        .expect("journal byte limit fits u64"),
                )
            })
            .expect("create oversized sparse cursor journal");
        assert!(matches!(
            DaShardCursorJournal::load(&config, &path),
            Err(ShardCursorJournalError::Read { path: failed_path, source })
                if failed_path == path && source.kind() == io::ErrorKind::InvalidData
        ));
    }
    #[cfg(unix)]
    #[test]
    fn journal_read_revalidation_rejects_symlink_replacement() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        fs::write(&path, b"old-journal").expect("write initial journal");
        let metadata = fs::symlink_metadata(&path).expect("inspect initial journal");
        let target = dir.path().join("cursor-replacement-target.norito");
        fs::write(&target, b"old-journal").expect("write symlink target");
        fs::remove_file(&path).expect("remove inspected journal");
        symlink(&target, &path).expect("replace journal with symlink");
        let err =
            DaShardCursorJournal::revalidate_persisted_read(&path, &metadata, b"old-journal".len())
                .expect_err("post-read symlink replacement must reject shard cursor journals");
        match err {
            ShardCursorJournalError::Read {
                path: err_path,
                source,
            } => {
                assert_eq!(err_path, path);
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
                assert!(
                    source.to_string().contains("non-regular file"),
                    "unexpected revalidation error: {source}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(target.exists(), "symlink target should not be removed");
    }
    #[test]
    fn journal_load_rejects_unremovable_bad_temp_when_main_valid() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        write_journal_payload(&path, vec![journal_entry(0, 0, 1, 2, 1)]);
        fs::create_dir(&tmp_path).expect("block temp cleanup");
        let err = DaShardCursorJournal::load(&config, path)
            .expect_err("unremovable bad temp journal should fail closed");
        match err {
            ShardCursorJournalError::Write { path: err_path, .. } => {
                assert_eq!(err_path, tmp_path)
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            tmp_path.exists(),
            "failed temp cleanup should leave path visible for operator repair"
        );
    }
    #[test]
    fn journal_load_falls_back_to_temp_on_corrupt_main() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        {
            let mut journal = DaShardCursorJournal::new(&config, path.clone());
            journal
                .record_commitment(1, &sample_record(0, 2, 3))
                .expect("record commitment");
            journal.persist().expect("persist");
        }
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        fs::copy(&path, &tmp_path).expect("copy journal to temp");
        fs::write(&path, b"corrupt").expect("corrupt main journal");
        let loaded = DaShardCursorJournal::load(&config, path.clone()).expect("load");
        assert!(path.exists(), "expected journal restored to main");
        assert!(!tmp_path.exists(), "temp journal should be removed");
        let cursor = loaded.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!((cursor.epoch, cursor.sequence), (2, 3));
    }
    #[test]
    fn journal_load_rejects_unpromotable_temp_file() {
        let dir = tempdir().expect("tempdir");
        let config = lane_config_with_mapping(0, 0);
        let path = DaShardCursorJournal::journal_path(dir.path());
        let tmp_path = DaShardCursorJournal::temp_path(&path);
        fs::create_dir(&path).expect("block main journal path");
        write_journal_payload(&tmp_path, vec![journal_entry(0, 0, 2, 3, 4)]);
        let err = DaShardCursorJournal::load(&config, path.clone())
            .expect_err("unpromotable temp journal should fail closed");
        match err {
            ShardCursorJournalError::Write { path: err_path, .. } => assert_eq!(err_path, path),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn journal_drops_resharded_entries() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let initial_config = lane_config_with_mapping(1, 2);
        let mut journal = DaShardCursorJournal::new(&initial_config, path.clone());
        journal
            .record_commitment(1, &sample_record(1, 5, 6))
            .expect("record");
        journal.persist().expect("persist");
        let resharded_config = lane_config_with_mapping(1, 3);
        let loaded = DaShardCursorJournal::load(&resharded_config, path).expect("load");
        assert!(loaded.cursor_for_lane(LaneId::new(1)).is_none());
    }
    #[test]
    fn journal_advances_only_forward() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mapping(0, 0);
        let mut journal = DaShardCursorJournal::new(&config, path);
        journal
            .record_commitment(1, &sample_record(0, 1, 1))
            .expect("record");
        let err = journal
            .record_commitment(2, &sample_record(0, 1, 0))
            .expect_err("regression must fail closed");
        assert!(matches!(
            err,
            ShardCursorJournalError::Regression {
                lane_id,
                shard_id,
                observed_epoch: 1,
                observed_sequence: 0,
                current_epoch: 1,
                current_sequence: 1,
                block_height: 2,
            } if lane_id == LaneId::new(0) && shard_id == ShardId::new(0)
        ));
        let cursor = journal.cursor_for_lane(LaneId::new(0)).expect("cursor");
        assert_eq!((cursor.epoch, cursor.sequence), (1, 1));
    }
    #[test]
    fn journal_bundle_updates_multiple_lanes() {
        let catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("lane count"),
            vec![
                ModelLaneConfig {
                    id: LaneId::new(0),
                    alias: "lane0".into(),
                    ..ModelLaneConfig::default()
                },
                ModelLaneConfig {
                    id: LaneId::new(1),
                    alias: "lane1".into(),
                    shard_id: Some(ShardId::new(5)),
                    ..ModelLaneConfig::default()
                },
            ],
        )
        .expect("catalog");
        let config = ConfigLaneConfig::from_catalog(&catalog);
        let mut journal = DaShardCursorJournal::new(&config, PathBuf::from("unused"));
        let bundle = DaCommitmentBundle::new(vec![sample_record(0, 0, 1), sample_record(1, 2, 3)]);
        journal.record_bundle(1, &bundle).expect("record bundle");
        let shard0 = journal
            .cursor_for_lane(LaneId::new(0))
            .expect("lane0 cursor");
        assert_eq!(shard0.shard_id, ShardId::new(0));
        let shard1 = journal
            .cursor_for_lane(LaneId::new(1))
            .expect("lane1 cursor");
        assert_eq!(shard1.shard_id, ShardId::new(5));
        assert_eq!((shard1.epoch, shard1.sequence), (2, 3));
    }
    #[test]
    fn journal_record_bundle_rolls_back_on_unknown_lane() {
        let config = lane_config_with_mapping(0, 0);
        let mut journal = DaShardCursorJournal::new(&config, PathBuf::from("unused"));
        journal
            .record_commitment(1, &sample_record(0, 1, 1))
            .expect("seed cursor");
        let bundle = DaCommitmentBundle::new(vec![sample_record(0, 2, 0), sample_record(1, 0, 0)]);
        let err = journal
            .record_bundle(2, &bundle)
            .expect_err("unknown lane should reject whole bundle");
        assert!(
            matches!(err, ShardCursorJournalError::UnknownLane { lane_id } if lane_id == LaneId::new(1))
        );
        let cursor = journal
            .cursor_for_lane(LaneId::new(0))
            .expect("seed cursor remains");
        assert_eq!(
            (cursor.epoch, cursor.sequence, cursor.last_block_height),
            (1, 1, 1)
        );
        assert!(journal.cursor_for_lane(LaneId::new(1)).is_none());
    }
    #[test]
    fn journal_record_bundle_rejects_regression_and_rolls_back() {
        let config = lane_config_with_mappings(&[(0, 0), (1, 0)]);
        let mut journal = DaShardCursorJournal::new(&config, PathBuf::from("unused"));
        journal
            .record_commitment(1, &sample_record(1, 1, 10))
            .expect("seed cursor");
        let bundle = DaCommitmentBundle::new(vec![sample_record(0, 2, 0), sample_record(1, 1, 9)]);
        let err = journal
            .record_bundle(2, &bundle)
            .expect_err("regression should reject whole bundle");
        assert!(
            matches!(
                err,
                ShardCursorJournalError::Regression {
                    lane_id,
                    shard_id,
                    observed_epoch: 1,
                    observed_sequence: 9,
                    current_epoch: 1,
                    current_sequence: 10,
                    block_height: 2,
                } if lane_id == LaneId::new(1)
                    && shard_id == ShardId::new(0)
            ),
            "unexpected error: {err:?}"
        );
        let cursor = journal
            .cursor_for_lane(LaneId::new(1))
            .expect("seed cursor remains");
        assert_eq!(
            (cursor.epoch, cursor.sequence, cursor.last_block_height),
            (1, 10, 1)
        );
        assert!(
            journal.cursor_for_lane(LaneId::new(0)).is_none(),
            "advanced record from rejected bundle must not be retained"
        );
    }
    #[test]
    fn journal_tracks_same_shard_lanes_independently() {
        let config = lane_config_with_mappings(&[(0, 7), (1, 7)]);
        let mut journal = DaShardCursorJournal::new(&config, PathBuf::from("unused"));
        journal
            .record_commitment(1, &sample_record(0, 5, 0))
            .expect("seed cursor");
        let bundle = DaCommitmentBundle::new(vec![sample_record(1, 4, 9)]);
        journal
            .record_bundle(2, &bundle)
            .expect("lane-scoped sequences may differ inside one shard");
        let lane0 = journal
            .cursor_for_lane(LaneId::new(0))
            .expect("lane 0 cursor remains");
        assert_eq!(
            (lane0.epoch, lane0.sequence, lane0.last_block_height),
            (5, 0, 1)
        );
        let lane1 = journal
            .cursor_for_lane(LaneId::new(1))
            .expect("lane 1 cursor is recorded independently");
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (4, 9, 2)
        );

        let err = journal
            .record_bundle(3, &DaCommitmentBundle::new(vec![sample_record(1, 4, 8)]))
            .expect_err("lane 1 must not regress its own cursor");
        assert!(
            matches!(
                err,
                ShardCursorJournalError::Regression {
                    lane_id,
                    shard_id,
                    observed_epoch: 4,
                    observed_sequence: 8,
                    current_epoch: 4,
                    current_sequence: 9,
                    block_height: 3,
                } if lane_id == LaneId::new(1)
                    && shard_id == ShardId::new(7)
            ),
            "unexpected error: {err:?}"
        );
        let lane1 = journal
            .cursor_for_lane(LaneId::new(1))
            .expect("rejected advance leaves lane 1 cursor intact");
        assert_eq!(
            (lane1.epoch, lane1.sequence, lane1.last_block_height),
            (4, 9, 2)
        );
    }
    #[test]
    fn rejects_unknown_journal_version() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("lane count"),
            vec![ModelLaneConfig {
                id: LaneId::new(0),
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "lane0".into(),
                ..ModelLaneConfig::default()
            }],
        )
        .expect("catalog");
        let config = ConfigLaneConfig::from_catalog(&catalog);
        let payload = PersistedShardCursors {
            version: DaShardCursorJournal::JOURNAL_VERSION + 1,
            canonical_reset_heights: BTreeMap::new(),
            entries: Vec::new(),
        };
        fs::write(&path, to_bytes(&payload).expect("encode")).expect("write");
        match DaShardCursorJournal::load(&config, path).expect_err("version mismatch") {
            ShardCursorJournalError::UnsupportedVersion { version, .. } => {
                assert_eq!(version, DaShardCursorJournal::JOURNAL_VERSION + 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn rejects_pre_release_journal_without_cursor_height() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mapping(0, 0);
        let payload = PreReleaseJournalWithoutCursorHeight {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            canonical_reset_heights: BTreeMap::new(),
            entries: vec![PreReleaseLaneShardCursor {
                shard_id: ShardId::new(0),
                lane_id: LaneId::new(0),
                epoch: 1,
                sequence: 2,
            }],
        };
        let current = PersistedShardCursors {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            canonical_reset_heights: BTreeMap::new(),
            entries: vec![journal_entry(0, 0, 1, 2, 3)],
        };
        let current_frame = frame_cursor_test_payload(&current);
        assert_eq!(
            current_frame,
            norito::encode_canonical(&current).expect("canonical control")
        );
        assert_eq!(
            norito::decode_canonical::<PersistedShardCursors>(&current_frame)
                .expect("same framing method accepts current payload"),
            current
        );
        let malformed = frame_cursor_test_payload(&payload);
        norito::core::from_bytes_view(&malformed).expect("valid envelope and checksum");
        let error = norito::decode_canonical::<PersistedShardCursors>(&malformed)
            .expect_err("missing fields must reach payload validation");
        assert!(!matches!(error, norito::Error::SchemaMismatch));
        fs::write(&path, malformed).expect("write malformed current-owner frame");
        assert!(
            matches!(
                DaShardCursorJournal::load(&config, path),
                Err(ShardCursorJournalError::Decode { .. })
            ),
            "a missing last_block_height must not be defaulted"
        );
    }
    #[test]
    fn rejects_pre_release_journal_without_reset_heights() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mapping(0, 0);
        let payload = PreReleaseJournalWithoutResetHeights {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            entries: vec![journal_entry(0, 0, 1, 2, 3)],
        };
        let current = PersistedShardCursors {
            version: DaShardCursorJournal::JOURNAL_VERSION,
            canonical_reset_heights: BTreeMap::new(),
            entries: vec![journal_entry(0, 0, 1, 2, 3)],
        };
        let current_frame = frame_cursor_test_payload(&current);
        assert_eq!(
            current_frame,
            norito::encode_canonical(&current).expect("canonical control")
        );
        assert_eq!(
            norito::decode_canonical::<PersistedShardCursors>(&current_frame)
                .expect("same framing method accepts current payload"),
            current
        );
        let malformed = frame_cursor_test_payload(&payload);
        norito::core::from_bytes_view(&malformed).expect("valid envelope and checksum");
        let error = norito::decode_canonical::<PersistedShardCursors>(&malformed)
            .expect_err("missing fields must reach payload validation");
        assert!(!matches!(error, norito::Error::SchemaMismatch));
        fs::write(&path, malformed).expect("write malformed current-owner frame");
        assert!(
            matches!(
                DaShardCursorJournal::load(&config, path),
                Err(ShardCursorJournalError::Decode { .. })
            ),
            "missing canonical_reset_heights must not be defaulted"
        );
    }
    #[test]
    fn rejects_duplicate_journal_entries() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mapping(0, 0);
        write_journal_payload(
            &path,
            vec![journal_entry(0, 0, 1, 2, 3), journal_entry(0, 0, 4, 5, 6)],
        );
        match DaShardCursorJournal::load(&config, path.clone()).expect_err("duplicate entry") {
            ShardCursorJournalError::InvalidEntry {
                path: err_path,
                reason,
            } => {
                assert_eq!(err_path, path);
                assert!(
                    reason.contains("duplicate cursor entry"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn rejects_duplicate_lane_journal_entries_across_shards() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mapping(0, 0);
        write_journal_payload(
            &path,
            vec![journal_entry(0, 0, 1, 2, 3), journal_entry(0, 1, 4, 5, 6)],
        );
        match DaShardCursorJournal::load(&config, path.clone())
            .expect_err("one lane cannot have persisted cursors in multiple shards")
        {
            ShardCursorJournalError::InvalidEntry {
                path: err_path,
                reason,
            } => {
                assert_eq!(err_path, path);
                assert!(
                    reason.contains("duplicate cursor entry for lane 0 (shards 0 and 1)"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn rejects_noncanonical_journal_entry_order() {
        let dir = tempdir().expect("tempdir");
        let path = DaShardCursorJournal::journal_path(dir.path());
        let config = lane_config_with_mappings(&[(0, 0), (1, 1)]);
        write_journal_payload(
            &path,
            vec![journal_entry(1, 1, 1, 2, 3), journal_entry(0, 0, 1, 3, 4)],
        );
        match DaShardCursorJournal::load(&config, path.clone())
            .expect_err("non-canonical journal order should reject")
        {
            ShardCursorJournalError::InvalidEntry {
                path: err_path,
                reason,
            } => {
                assert_eq!(err_path, path);
                assert!(
                    reason.contains("non-canonical cursor entry order at index 1"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
