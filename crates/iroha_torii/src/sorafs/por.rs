//! Rebuildable Proof-of-Retrievability projection used by Torii.
//!
//! The storage node checkpoint is the sole authority for PoR challenge lifecycle state. Torii
//! installs that projection at startup, then advances its maps and indexes in place with exact
//! node-authoritative generation updates. Coordinator persistence retains only exact report
//! publication state once the projection has been installed.
#[cfg(feature = "app_api")]
use async_trait::async_trait;
use dashmap::DashMap;
#[cfg(feature = "app_api")]
use iroha_data_model::NetworkId;
use iroha_data_model::sorafs::moderation_ledger::sorafs_repair_task_id_v1;
#[cfg(feature = "app_api")]
use iroha_futures::supervisor::ShutdownSignal;
#[cfg(feature = "app_api")]
use norito::json::{self, Value as JsonValue};
use norito::{
    decode_from_bytes, decode_from_bytes_with_limits,
    derive::{NoritoDeserialize, NoritoSerialize},
    to_bytes,
};
use parking_lot::{MappedRwLockReadGuard, Mutex, RwLock, RwLockReadGuard};
#[cfg(test)]
use sorafs_manifest::por::AuditVerdictV1;
#[cfg(test)]
use sorafs_manifest::por::POR_CHALLENGE_STATUS_VERSION_V1;
use sorafs_manifest::por::{
    AuditOutcomeV1, POR_CHALLENGE_STATUS_PAGE_MAX_RECORD_BYTES_V1,
    POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1, POR_STATUS_CURSOR_VERSION_V1,
    POR_STATUS_EXPORT_PAGE_VERSION_V1, POR_STATUS_PAGE_VERSION_V1, POR_WEEKLY_REPORT_VERSION_V1,
    PorChallengeOutcome, PorChallengePublicationV1, PorChallengePublicationValidationError,
    PorChallengeStatusV1, PorChallengeV1, PorChallengeValidationError, PorProviderSummaryV1,
    PorReportIsoWeek, PorReportIsoWeekValidationError, PorStatusCursorV1, PorStatusExportPageV1,
    PorStatusPageV1, PorWeeklyReportV1, PorWeeklyReportValidationError, ProviderVrfSubmissionV1,
    ProviderVrfSubmissionValidationError, provider_vrf_input,
};
#[cfg(feature = "app_api")]
use sorafs_node::{
    ManifestVrfBundle, ManifestVrfKey, PlannedChallenge, PorChallengePlannerError, PorRandomness,
};
use sorafs_node::{
    PorMutationFailureV1, PorStatusAuthoritySnapshotV1, PorStatusAuthorityUpdateV1,
    por_repair_source_identity_v1,
};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    ops::Bound,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "app_api")]
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    time::Duration as StdDuration,
};
use thiserror::Error;
use time::{Date, Duration, OffsetDateTime, Weekday};
#[cfg(feature = "app_api")]
use tokio::time::{MissedTickBehavior, interval};
/// Maximum sum of canonical status-record bytes returned by one PoR page.
pub(crate) const POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1: usize =
    POR_CHALLENGE_STATUS_PAGE_MAX_RECORD_BYTES_V1;
/// Maximum status records materialized and filter-evaluated by one status query.
pub(crate) const POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1: usize = 512;
const POR_COORDINATOR_SNAPSHOT_VERSION_V1: u8 = 1;
const MAX_POR_COORDINATOR_RECORDS: usize =
    iroha_config::parameters::defaults::sorafs::storage::RUNTIME_STATE_ENTRY_LIMIT_MAX;
const MAX_POR_COORDINATOR_FORCED_PROVIDERS: usize = 4_096;
const MAX_POR_COORDINATOR_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_POR_COORDINATOR_DECODE_ALLOCATED_BYTES: usize = 512 * 1024 * 1024;
const fn por_coordinator_decode_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_POR_COORDINATOR_RECORDS,
        MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
        MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
        MAX_POR_COORDINATOR_DECODE_ALLOCATED_BYTES,
        64,
    )
}
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PorCoordinatorVerdictOutcome {
    Inserted,
    Existing,
}
#[derive(Debug, Clone)]
struct RecordedVerdict {
    outcome: AuditOutcomeV1,
    failure_reason: Option<String>,
    decided_at: u64,
    proof_digest: Option<[u8; 32]>,
    canonical_digest: [u8; 32],
}
impl RecordedVerdict {
    #[cfg(test)]
    fn from_verdict(verdict: &AuditVerdictV1) -> Result<Self, PorCoordinatorError> {
        let canonical = to_bytes(verdict)
            .map_err(|error| PorCoordinatorError::CanonicalVerdictEncoding(error.to_string()))?;
        Ok(Self {
            outcome: verdict.outcome,
            failure_reason: verdict.failure_reason.clone(),
            decided_at: verdict.decided_at,
            proof_digest: verdict.proof_digest,
            canonical_digest: *blake3::hash(&canonical).as_bytes(),
        })
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::RecordedVerdictSnapshot")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct RecordedVerdictSnapshot {
    outcome: u8,
    #[norito(default)]
    failure_reason: Option<String>,
    decided_at: u64,
    #[norito(default)]
    proof_digest: Option<[u8; 32]>,
    canonical_digest: [u8; 32],
}
impl From<&RecordedVerdict> for RecordedVerdictSnapshot {
    fn from(verdict: &RecordedVerdict) -> Self {
        Self {
            outcome: verdict.outcome as u8,
            failure_reason: verdict.failure_reason.clone(),
            decided_at: verdict.decided_at,
            proof_digest: verdict.proof_digest,
            canonical_digest: verdict.canonical_digest,
        }
    }
}
impl RecordedVerdictSnapshot {
    fn into_recorded_verdict(self) -> Result<RecordedVerdict, PorPersistenceError> {
        let outcome = match self.outcome {
            1 => AuditOutcomeV1::Success,
            2 => AuditOutcomeV1::Failed,
            3 => AuditOutcomeV1::Repaired,
            value => return Err(PorPersistenceError::InvalidFlag { value }),
        };
        Ok(RecordedVerdict {
            outcome,
            failure_reason: self.failure_reason,
            decided_at: self.decided_at,
            proof_digest: self.proof_digest,
            canonical_digest: self.canonical_digest,
        })
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RecordedVerdictSnapshot {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        norito::core::decode_field_canonical::<RecordedVerdictSnapshot>(bytes)
    }
}
/// Validated record and canonical-byte ceilings for one PoR status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PorStatusPageLimits {
    records: usize,
    canonical_bytes: usize,
}
impl PorStatusPageLimits {
    /// Validate first-release page limits at the coordinator boundary.
    pub(crate) fn new(records: usize, canonical_bytes: usize) -> Result<Self, PorCoordinatorError> {
        if records == 0 {
            return Err(PorCoordinatorError::InvalidPageLimit {
                field: "limit",
                value: records,
                maximum: POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1,
            });
        }
        if records > POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1 {
            return Err(PorCoordinatorError::InvalidPageLimit {
                field: "limit",
                value: records,
                maximum: POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1,
            });
        }
        if canonical_bytes == 0 || canonical_bytes > POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1 {
            return Err(PorCoordinatorError::InvalidPageLimit {
                field: "max_bytes",
                value: canonical_bytes,
                maximum: POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1,
            });
        }
        Ok(Self {
            records,
            canonical_bytes,
        })
    }
}
/// Opaque, versioned cursor for a PoR status or export page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PorStatusPageCursor {
    /// Start a new snapshot traversal.
    First,
    /// Continue strictly after one consumed index candidate from an exact generation and selection.
    After {
        /// Coordinator generation issued with the cursor.
        snapshot_generation: u64,
        /// Domain-separated digest of the normalized filter or export range.
        selection_digest: [u8; 32],
        /// Epoch anchor, and the leading order-key component for ranged exports.
        last_epoch_id: u64,
        /// Issued-at component of the last consumed candidate's exact order key.
        last_issued_at: u64,
        /// Challenge component of the last consumed candidate's exact order key.
        challenge_id: [u8; 32],
    },
}
impl PorStatusPageCursor {
    /// Decode one canonical URL-safe cursor, or begin at the first page.
    ///
    /// # Errors
    ///
    /// Returns [`PorCoordinatorError`] when the cursor is oversized,
    /// non-canonical, malformed, or uses an unsupported version.
    pub(crate) fn from_opaque(cursor: Option<&str>) -> Result<Self, PorCoordinatorError> {
        let Some(cursor) = cursor else {
            return Ok(Self::First);
        };
        let payload = PorStatusCursorV1::decode_opaque(cursor)
            .map_err(|error| PorCoordinatorError::InvalidPageCursor(error.to_string()))?;
        Ok(Self::After {
            snapshot_generation: payload.snapshot_generation,
            selection_digest: payload.selection_digest,
            last_epoch_id: payload.last_epoch_id,
            last_issued_at: payload.last_issued_at,
            challenge_id: payload.last_challenge_id,
        })
    }
}
/// Durable exact report material and its publication acknowledgement.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::PreparedWeeklyReportV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct PreparedWeeklyReportV1 {
    report: PorWeeklyReportV1,
    published: bool,
}
type PorStatusOrderKey = (u64, [u8; 32]);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PorStatusCursorAnchor {
    epoch_id: u64,
    issued_at: u64,
    challenge_id: [u8; 32],
}
impl PorStatusCursorAnchor {
    fn status_order_key(self) -> PorStatusOrderKey {
        (self.issued_at, self.challenge_id)
    }
    fn epoch_order_key(self) -> (u64, u64, [u8; 32]) {
        (self.epoch_id, self.issued_at, self.challenge_id)
    }
}
fn por_status_selection_digest(filter: &PorStatusFilter) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroha.sorafs.por.status-cursor.selection.v1");
    for value in [filter.manifest, filter.provider] {
        match value {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&value);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    match filter.epoch {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match filter.status {
        Some(value) => {
            hasher.update(&[1, value as u8]);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}
fn por_export_selection_digest(range: Option<(u64, u64)>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroha.sorafs.por.export-cursor.selection.v1");
    match range {
        Some((start, end)) => {
            hasher.update(&[1]);
            hasher.update(&start.to_le_bytes());
            hasher.update(&end.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}
#[derive(Debug, Clone)]
struct PorStatusIndexes {
    generation: u64,
    canonical: BTreeSet<PorStatusOrderKey>,
    by_manifest: BTreeMap<[u8; 32], BTreeSet<PorStatusOrderKey>>,
    by_provider: BTreeMap<[u8; 32], BTreeSet<PorStatusOrderKey>>,
    by_epoch: BTreeMap<u64, BTreeSet<PorStatusOrderKey>>,
    by_outcome: BTreeMap<u8, BTreeSet<PorStatusOrderKey>>,
    epoch_order: BTreeSet<(u64, u64, [u8; 32])>,
}
impl Default for PorStatusIndexes {
    fn default() -> Self {
        Self {
            generation: 1,
            canonical: BTreeSet::new(),
            by_manifest: BTreeMap::new(),
            by_provider: BTreeMap::new(),
            by_epoch: BTreeMap::new(),
            by_outcome: BTreeMap::new(),
            epoch_order: BTreeSet::new(),
        }
    }
}
impl PorStatusIndexes {
    #[cfg(test)]
    fn from_records(records: &DashMap<[u8; 32], ChallengeRecord>, generation: u64) -> Self {
        debug_assert_ne!(generation, 0, "PoR status generation is always non-zero");
        let mut indexes = Self {
            generation,
            ..Self::default()
        };
        for entry in records.iter() {
            indexes.insert_status(&entry.value().to_status());
        }
        indexes
    }
    fn from_statuses(statuses: &BTreeMap<[u8; 32], PorChallengeStatusV1>, generation: u64) -> Self {
        debug_assert_ne!(generation, 0, "PoR status generation is always non-zero");
        let mut indexes = Self {
            generation,
            ..Self::default()
        };
        for status in statuses.values() {
            indexes.insert_status(status);
        }
        indexes
    }
    fn order_key(status: &PorChallengeStatusV1) -> PorStatusOrderKey {
        (status.issued_at, status.challenge_id)
    }
    fn insert_status(&mut self, status: &PorChallengeStatusV1) {
        let key = Self::order_key(status);
        self.canonical.insert(key);
        self.by_manifest
            .entry(status.manifest_digest)
            .or_default()
            .insert(key);
        self.by_provider
            .entry(status.provider_id)
            .or_default()
            .insert(key);
        self.by_epoch
            .entry(status.epoch_id)
            .or_default()
            .insert(key);
        self.by_outcome
            .entry(status.status as u8)
            .or_default()
            .insert(key);
        self.epoch_order
            .insert((status.epoch_id, status.issued_at, status.challenge_id));
    }
    fn remove_status(&mut self, status: &PorChallengeStatusV1) {
        let key = Self::order_key(status);
        self.canonical.remove(&key);
        Self::remove_secondary(&mut self.by_manifest, &status.manifest_digest, &key);
        Self::remove_secondary(&mut self.by_provider, &status.provider_id, &key);
        Self::remove_secondary(&mut self.by_epoch, &status.epoch_id, &key);
        Self::remove_secondary(&mut self.by_outcome, &(status.status as u8), &key);
        self.epoch_order
            .remove(&(status.epoch_id, status.issued_at, status.challenge_id));
    }
    fn remove_secondary<K: Ord + Copy>(
        index: &mut BTreeMap<K, BTreeSet<PorStatusOrderKey>>,
        key: &K,
        order_key: &PorStatusOrderKey,
    ) {
        let remove_bucket = index.get_mut(key).is_some_and(|bucket| {
            bucket.remove(order_key);
            bucket.is_empty()
        });
        if remove_bucket {
            index.remove(key);
        }
    }
    #[cfg(test)]
    fn commit_insert(&mut self, status: &PorChallengeStatusV1, next_generation: u64) {
        self.insert_status(status);
        self.publish_generation(next_generation);
    }
    #[cfg(test)]
    fn commit_replace(
        &mut self,
        previous: &PorChallengeStatusV1,
        current: &PorChallengeStatusV1,
        next_generation: u64,
    ) {
        self.remove_status(previous);
        self.insert_status(current);
        self.publish_generation(next_generation);
    }
    fn publish_generation(&mut self, next_generation: u64) {
        debug_assert_eq!(self.generation.checked_add(1), Some(next_generation));
        self.generation = next_generation;
    }
    #[cfg(test)]
    fn validate_against_records(
        &self,
        records: &DashMap<[u8; 32], ChallengeRecord>,
    ) -> Result<(), String> {
        let rebuilt = Self::from_records(records, self.generation);
        if self.canonical != rebuilt.canonical
            || self.by_manifest != rebuilt.by_manifest
            || self.by_provider != rebuilt.by_provider
            || self.by_epoch != rebuilt.by_epoch
            || self.by_outcome != rebuilt.by_outcome
            || self.epoch_order != rebuilt.epoch_order
        {
            return Err("PoR status indexes do not match persisted challenge records".to_owned());
        }
        Ok(())
    }
}
#[derive(Debug)]
struct AuthoritativePorProjectionV1 {
    statuses: BTreeMap<[u8; 32], PorChallengeStatusV1>,
    indexes: PorStatusIndexes,
    forced_providers: HashMap<[u8; 32], BTreeMap<u64, usize>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthoritativeUpdateAction {
    Insert,
    Replace,
}
fn por_status_identity_is_unchanged(
    previous: &PorChallengeStatusV1,
    current: &PorChallengeStatusV1,
) -> bool {
    previous.version == current.version
        && previous.challenge_id == current.challenge_id
        && previous.manifest_digest == current.manifest_digest
        && previous.provider_id == current.provider_id
        && previous.epoch_id == current.epoch_id
        && previous.drand_round == current.drand_round
        && previous.sample_count == current.sample_count
        && previous.forced == current.forced
        && previous.issued_at == current.issued_at
}
fn por_status_lifecycle_advances(
    previous: &PorChallengeStatusV1,
    current: &PorChallengeStatusV1,
) -> bool {
    if previous == current
        || previous
            .responded_at
            .is_some_and(|value| current.responded_at != Some(value))
        || previous
            .proof_digest
            .is_some_and(|value| current.proof_digest != Some(value))
    {
        return false;
    }
    match previous.status {
        PorChallengeOutcome::AwaitingProof => match current.status {
            PorChallengeOutcome::ProofSubmitted => true,
            PorChallengeOutcome::Failed => {
                // A proof submission is its own durable generation. A direct
                // deadline-failure transition therefore cannot introduce the
                // response material that was absent from `AwaitingProof`.
                current.responded_at.is_none() && current.proof_digest.is_none()
            }
            PorChallengeOutcome::AwaitingProof
            | PorChallengeOutcome::Verified
            | PorChallengeOutcome::Repaired => false,
        },
        PorChallengeOutcome::ProofSubmitted => matches!(
            current.status,
            PorChallengeOutcome::Verified
                | PorChallengeOutcome::Failed
                | PorChallengeOutcome::Repaired
        ),
        PorChallengeOutcome::Verified
        | PorChallengeOutcome::Failed
        | PorChallengeOutcome::Repaired => false,
    }
}
fn remove_forced_status(
    forced_providers: &mut HashMap<[u8; 32], BTreeMap<u64, usize>>,
    status: &PorChallengeStatusV1,
) {
    if !status.forced {
        return;
    }
    let remove_provider = forced_providers
        .get_mut(&status.provider_id)
        .is_some_and(|epochs| {
            let remove_epoch = epochs.get_mut(&status.epoch_id).is_some_and(|count| {
                if *count > 1 {
                    *count -= 1;
                    false
                } else {
                    true
                }
            });
            debug_assert!(
                epochs.contains_key(&status.epoch_id),
                "retained forced-provider provenance must contain the removed status"
            );
            if remove_epoch {
                epochs.remove(&status.epoch_id);
            }
            epochs.is_empty()
        });
    if remove_provider {
        forced_providers.remove(&status.provider_id);
    }
}
fn insert_forced_status(
    forced_providers: &mut HashMap<[u8; 32], BTreeMap<u64, usize>>,
    status: &PorChallengeStatusV1,
) {
    if status.forced {
        let count = forced_providers
            .entry(status.provider_id)
            .or_default()
            .entry(status.epoch_id)
            .or_default();
        *count = count
            .checked_add(1)
            .expect("bounded PoR status retention leaves forced-provenance count headroom");
    }
}
/// Rebuildable PoR read projection and durable weekly-report publisher state.
#[derive(Debug, Clone)]
pub struct PorCoordinator {
    record_limit: usize,
    #[cfg(test)]
    records: Arc<DashMap<[u8; 32], ChallengeRecord>>,
    /// One atomic, rebuildable read projection sourced from the node checkpoint.
    authoritative_projection: Arc<RwLock<Option<AuthoritativePorProjectionV1>>>,
    #[cfg(test)]
    status_indexes: Arc<RwLock<PorStatusIndexes>>,
    /// Tracks recent forced challenges so we can flag providers missing VRFs.
    #[cfg(test)]
    forced_providers: Arc<RwLock<HashMap<[u8; 32], BTreeSet<u64>>>>,
    /// Exact report material prepared before durable Governance DAG publication.
    prepared_weekly_report: Arc<RwLock<Option<PreparedWeeklyReportV1>>>,
    persistence: Option<Arc<PorPersistence>>,
    /// Latches a post-publication persistence fault until disk state is reloaded.
    persistence_fault: Arc<RwLock<Option<String>>>,
    mutation_lock: Arc<Mutex<()>>,
    pipeline_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    weekly_report_projection_lookups: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    status_page_projection_lookups: Arc<std::sync::atomic::AtomicUsize>,
}
include!("por/coordinator_impl.rs");
impl Default for PorCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
struct PorStatusPageAccumulator {
    snapshot_generation: u64,
    selection_digest: [u8; 32],
    limits: PorStatusPageLimits,
    canonical_bytes: usize,
    inspected_candidates: usize,
    last_consumed_candidate: Option<(u64, u64, [u8; 32])>,
    statuses: Vec<PorChallengeStatusV1>,
    has_more: bool,
}
impl PorStatusPageAccumulator {
    fn new(
        snapshot_generation: u64,
        selection_digest: [u8; 32],
        limits: PorStatusPageLimits,
    ) -> Self {
        Self {
            snapshot_generation,
            selection_digest,
            limits,
            canonical_bytes: 0,
            inspected_candidates: 0,
            last_consumed_candidate: None,
            statuses: Vec::with_capacity(limits.records),
            has_more: false,
        }
    }
    fn record_limit_reached(&self) -> bool {
        self.statuses.len() == self.limits.records
    }
    fn note_inspected_candidate(&mut self) -> Result<(), PorCoordinatorError> {
        self.inspected_candidates = self
            .inspected_candidates
            .checked_add(1)
            .ok_or(PorCoordinatorError::StatusPageByteOverflow)?;
        Ok(())
    }
    fn consume_candidate(&mut self, status: &PorChallengeStatusV1) {
        self.last_consumed_candidate =
            Some((status.epoch_id, status.issued_at, status.challenge_id));
    }
    fn mark_has_more(&mut self) {
        self.has_more = true;
    }
    fn accept(&mut self, status: PorChallengeStatusV1) -> Result<bool, PorCoordinatorError> {
        if self.statuses.len() == self.limits.records {
            self.has_more = true;
            return Ok(false);
        }
        let canonical = to_bytes(&status).map_err(PorCoordinatorError::StatusPageEncoding)?;
        let next_bytes = self
            .canonical_bytes
            .checked_add(canonical.len())
            .ok_or(PorCoordinatorError::StatusPageByteOverflow)?;
        if next_bytes > self.limits.canonical_bytes {
            if self.statuses.is_empty() {
                return Err(PorCoordinatorError::StatusRecordExceedsPageByteLimit {
                    challenge_id: status.challenge_id,
                    record_bytes: canonical.len(),
                    byte_limit: self.limits.canonical_bytes,
                });
            }
            self.has_more = true;
            return Ok(false);
        }
        self.canonical_bytes = next_bytes;
        self.statuses.push(status);
        Ok(true)
    }
    fn finish(self) -> Result<PorStatusPageV1, PorCoordinatorError> {
        let record_limit = u32::try_from(self.limits.records)
            .map_err(|_| PorCoordinatorError::StatusPageByteOverflow)?;
        let canonical_byte_limit = u64::try_from(self.limits.canonical_bytes)
            .map_err(|_| PorCoordinatorError::StatusPageByteOverflow)?;
        let canonical_bytes = u64::try_from(self.canonical_bytes)
            .map_err(|_| PorCoordinatorError::StatusPageByteOverflow)?;
        let inspected_candidates = u32::try_from(self.inspected_candidates)
            .map_err(|_| PorCoordinatorError::StatusPageByteOverflow)?;
        let next_cursor = if self.has_more {
            Some(
                self.last_consumed_candidate
                    .ok_or_else(|| {
                        PorCoordinatorError::InvalidAuthoritativeProjection(
                            "bounded status page has no safe continuation anchor".to_owned(),
                        )
                    })
                    .and_then(|(last_epoch_id, last_issued_at, last_challenge_id)| {
                        PorStatusCursorV1 {
                            version: POR_STATUS_CURSOR_VERSION_V1,
                            snapshot_generation: self.snapshot_generation,
                            selection_digest: self.selection_digest,
                            last_epoch_id,
                            last_issued_at,
                            last_challenge_id,
                        }
                        .encode_opaque()
                        .map_err(|error| PorCoordinatorError::InvalidPageCursor(error.to_string()))
                    })?,
            )
        } else {
            None
        };
        Ok(PorStatusPageV1 {
            version: POR_STATUS_PAGE_VERSION_V1,
            snapshot_generation: self.snapshot_generation,
            record_limit,
            canonical_byte_limit,
            canonical_bytes,
            inspected_candidates,
            has_more: self.has_more,
            next_cursor,
            statuses: self.statuses,
        })
    }
}
include!("por/persistence_randomness.rs");
#[cfg(feature = "app_api")]
/// Errors collecting VRF materials required for PoR challenge planning.
#[derive(Debug, Error)]
pub enum VrfError {
    /// Submission fields are structurally invalid.
    #[error("invalid provider VRF submission: {0}")]
    InvalidSubmission(#[from] ProviderVrfSubmissionValidationError),
    /// Provider is not in the current council-approved admission registry.
    #[error("provider is not admitted for PoR VRF submissions")]
    UnadmittedProvider,
    /// Submission targets another exact genesis-derived network.
    #[error("provider VRF submission targets a different network")]
    WrongNetwork,
    /// Ed25519 submission authentication failed or used a stale advert key.
    #[error("provider VRF submission signature is invalid: {0}")]
    InvalidSignature(String),
    /// Target is not an active local manifest for the submitted provider.
    #[error("provider VRF submission targets an unknown, unpinned, or expired manifest")]
    UnknownManifest,
    /// BLS variant/key/proof/output or canonical input binding failed.
    #[error("provider VRF proof verification failed")]
    InvalidProof,
    /// Submission timestamp exceeds the configured skew window.
    #[error("provider VRF submission timestamp is outside the accepted clock window")]
    InvalidTimestamp,
    /// Submission epoch is too old or too far in the future.
    #[error("provider VRF submission epoch is outside the retained window")]
    InvalidEpoch,
    /// Provider sequence did not advance durable replay high-water state.
    #[error("provider VRF sequence replay: received {received}, high-water {high_water}")]
    Replay {
        /// Sequence supplied by the rejected submission.
        received: u64,
        /// Greatest sequence already committed for the provider.
        high_water: u64,
    },
    /// The exact manifest/epoch/round submission was already accepted.
    #[error("provider VRF submission is a duplicate")]
    Duplicate,
    /// Conflicting evidence was submitted for the same manifest/epoch.
    #[error("provider VRF equivocation detected")]
    Equivocation,
    /// Durable entry limit is exhausted after safe pruning.
    #[error("provider VRF state entry limit {limit} reached")]
    Limit {
        /// Maximum number of durable VRF entries permitted by configuration.
        limit: usize,
    },
    /// Durable state failed closed.
    #[error("provider VRF state persistence failure: {0}")]
    Persistence(String),
}
#[cfg(feature = "app_api")]
/// Supplies VRF bundles required to plan PoR challenges.
pub trait VrfProvider: Send + Sync {
    /// Return verified VRF bundles matching the exact drand randomness record.
    ///
    /// # Errors
    ///
    /// Returns [`VrfError`] when durable state cannot be safely queried.
    fn vrf_bundles_for_epoch(
        &self,
        randomness: &PorRandomness,
    ) -> Result<HashMap<ManifestVrfKey, ManifestVrfBundle>, VrfError>;
}
#[cfg(feature = "app_api")]
const VRF_STATE_VERSION_V1: u8 = 1;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::VrfStateKeyV1")]
#[cfg(feature = "app_api")]
#[derive(
    Debug, Clone, Copy, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, PartialOrd, Ord,
)]
struct VrfStateKeyV1 {
    epoch_id: u64,
    provider_id: [u8; 32],
    manifest_digest: [u8; 32],
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::VrfStateEntryV1")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct VrfStateEntryV1 {
    key: VrfStateKeyV1,
    submission: ProviderVrfSubmissionV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::VrfProviderSequenceV1")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct VrfProviderSequenceV1 {
    provider_id: [u8; 32],
    high_water: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::VrfStateSnapshotV1")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct VrfStateSnapshotV1 {
    version: u8,
    network_id: NetworkId,
    entries: Vec<VrfStateEntryV1>,
    sequences: Vec<VrfProviderSequenceV1>,
}
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, Default)]
struct VrfState {
    entries: BTreeMap<VrfStateKeyV1, ProviderVrfSubmissionV1>,
    sequences: BTreeMap<[u8; 32], u64>,
}
#[cfg(feature = "app_api")]
/// Admission-bound, authenticated, bounded, durable provider VRF store.
#[derive(Debug)]
pub struct VerifiedVrfProvider {
    admission: Arc<super::AdmissionRegistry>,
    network_id: NetworkId,
    state_path: PathBuf,
    max_entries: usize,
    retention_epochs: u64,
    max_clock_skew_secs: u64,
    state: Mutex<VrfState>,
}
#[cfg(feature = "app_api")]
impl VerifiedVrfProvider {
    /// Load and fully reverify durable provider VRF state.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty admission registry or invalid capacity and
    /// retention bounds, or if durable VRF state cannot be loaded and reverified.
    pub fn with_persistence(
        admission: Arc<super::AdmissionRegistry>,
        network_id: NetworkId,
        state_path: PathBuf,
        max_entries: usize,
        retention_epochs: u64,
        max_clock_skew_secs: u64,
    ) -> Result<Self, VrfError> {
        if admission.is_empty() {
            return Err(VrfError::Persistence(
                "admission registry is required".to_owned(),
            ));
        }
        if max_entries == 0 || max_entries > 65_536 || retention_epochs == 0 {
            return Err(VrfError::Persistence(
                "VRF bounds must be non-zero and max_entries <= 65536".to_owned(),
            ));
        }
        let state = load_vrf_state(&state_path, max_entries, &admission, &network_id)?;
        Ok(Self {
            admission,
            network_id,
            state_path,
            max_entries,
            retention_epochs,
            max_clock_skew_secs,
            state: Mutex::new(state),
        })
    }
    fn verify_submission(
        &self,
        submission: &ProviderVrfSubmissionV1,
        now_secs: u64,
        current_epoch: u64,
    ) -> Result<(), VrfError> {
        submission.validate()?;
        if submission.network_id != *self.network_id.as_bytes() {
            return Err(VrfError::WrongNetwork);
        }
        if submission.issued_at > now_secs.saturating_add(self.max_clock_skew_secs)
            || now_secs.saturating_sub(submission.issued_at) > self.max_clock_skew_secs
        {
            return Err(VrfError::InvalidTimestamp);
        }
        let oldest = current_epoch.saturating_sub(self.retention_epochs);
        if submission.epoch_id < oldest || submission.epoch_id > current_epoch.saturating_add(1) {
            return Err(VrfError::InvalidEpoch);
        }
        let record = self
            .admission
            .entry(&submission.provider_id)
            .ok_or(VrfError::UnadmittedProvider)?;
        submission
            .verify_signature_for_provider(record.advert_key())
            .map_err(|error| VrfError::InvalidSignature(error.to_string()))?;
        verify_provider_vrf(submission, record.por_vrf_key(), &self.network_id)
    }
    fn accept_verified(
        &self,
        submission: ProviderVrfSubmissionV1,
        current_epoch: u64,
    ) -> Result<(), VrfError> {
        let oldest = current_epoch.saturating_sub(self.retention_epochs);
        let key = VrfStateKeyV1 {
            epoch_id: submission.epoch_id,
            provider_id: submission.provider_id,
            manifest_digest: submission.manifest_digest,
        };
        let mut state = self.state.lock();
        if let Some(existing) = state.entries.get(&key) {
            if existing.drand_round == submission.drand_round
                && existing.output == submission.output
                && existing.proof == submission.proof
            {
                return Err(VrfError::Duplicate);
            }
            return Err(VrfError::Equivocation);
        }
        let high_water = state
            .sequences
            .get(&submission.provider_id)
            .copied()
            .unwrap_or(0);
        if submission.sequence <= high_water {
            return Err(VrfError::Replay {
                received: submission.sequence,
                high_water,
            });
        }
        let retained_entries = state
            .entries
            .keys()
            .filter(|key| key.epoch_id >= oldest)
            .count();
        if retained_entries >= self.max_entries {
            return Err(VrfError::Limit {
                limit: self.max_entries,
            });
        }
        let previous = state.clone();
        state.entries.retain(|key, _| key.epoch_id >= oldest);
        state
            .sequences
            .insert(submission.provider_id, submission.sequence);
        state.entries.insert(key, submission);
        if let Err(error) = persist_vrf_state(&self.state_path, &self.network_id, &state) {
            *state = previous;
            return Err(error);
        }
        Ok(())
    }
    /// Authenticate, verify, replay-check, and durably accept one provider VRF.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, stale, wrong-network, or unauthenticated
    /// submission; an inactive manifest; duplicate, equivocating, or replayed proofs;
    /// exhausted capacity; or failed durable persistence.
    pub fn submit(
        &self,
        submission: ProviderVrfSubmissionV1,
        now_secs: u64,
        current_epoch: u64,
        target_is_active: bool,
    ) -> Result<(), VrfError> {
        self.verify_submission(&submission, now_secs, current_epoch)?;
        if !target_is_active {
            return Err(VrfError::UnknownManifest);
        }
        self.accept_verified(submission, current_epoch)
    }
}
#[cfg(feature = "app_api")]
impl VrfProvider for VerifiedVrfProvider {
    fn vrf_bundles_for_epoch(
        &self,
        randomness: &PorRandomness,
    ) -> Result<HashMap<ManifestVrfKey, ManifestVrfBundle>, VrfError> {
        let state = self.state.lock();
        let mut bundles = HashMap::new();
        for (key, submission) in state.entries.range(
            VrfStateKeyV1 {
                epoch_id: randomness.epoch_id,
                provider_id: [0; 32],
                manifest_digest: [0; 32],
            }..=VrfStateKeyV1 {
                epoch_id: randomness.epoch_id,
                provider_id: [u8::MAX; 32],
                manifest_digest: [u8::MAX; 32],
            },
        ) {
            if submission.drand_round != randomness.drand_round
                || self.admission.entry(&key.provider_id).is_none()
            {
                continue;
            }
            let lookup = ManifestVrfKey {
                provider_id: key.provider_id,
                manifest_digest: key.manifest_digest,
            };
            bundles.insert(
                lookup,
                ManifestVrfBundle {
                    provider_id: key.provider_id,
                    manifest_digest: key.manifest_digest,
                    epoch_id: key.epoch_id,
                    drand_round: submission.drand_round,
                    output: submission.output,
                    proof: submission.proof,
                },
            );
        }
        Ok(bundles)
    }
}
#[cfg(feature = "app_api")]
fn verify_provider_vrf(
    submission: &ProviderVrfSubmissionV1,
    key: &sorafs_manifest::ProviderVrfPublicKeyV1,
    network_id: &NetworkId,
) -> Result<(), VrfError> {
    let input = provider_vrf_input(
        &submission.provider_id,
        &submission.manifest_digest,
        submission.epoch_id,
        submission.drand_round,
    );
    let output = match key {
        sorafs_manifest::ProviderVrfPublicKeyV1::BlsNormal(public_key) => {
            iroha_crypto::vrf::verify_normal_bytes_with_network_id(
                public_key,
                network_id.as_bytes(),
                &input,
                &submission.proof,
            )
        }
        sorafs_manifest::ProviderVrfPublicKeyV1::BlsSmall(public_key) => {
            iroha_crypto::vrf::verify_small_bytes_with_network_id(
                public_key,
                network_id.as_bytes(),
                &input,
                &submission.proof,
            )
        }
    };
    if output.map(|output| output.0) != Some(submission.output) {
        return Err(VrfError::InvalidProof);
    }
    Ok(())
}
#[cfg(feature = "app_api")]
fn persist_vrf_state(
    path: &Path,
    network_id: &NetworkId,
    state: &VrfState,
) -> Result<(), VrfError> {
    let snapshot = VrfStateSnapshotV1 {
        version: VRF_STATE_VERSION_V1,
        network_id: *network_id,
        entries: state
            .entries
            .iter()
            .map(|(key, submission)| VrfStateEntryV1 {
                key: *key,
                submission: submission.clone(),
            })
            .collect(),
        sequences: state
            .sequences
            .iter()
            .map(|(provider_id, high_water)| VrfProviderSequenceV1 {
                provider_id: *provider_id,
                high_water: *high_water,
            })
            .collect(),
    };
    store_secure_state(path, &snapshot, "provider VRF")
        .map_err(|error| VrfError::Persistence(error.to_string()))
}
#[cfg(feature = "app_api")]
fn load_vrf_state(
    path: &Path,
    max_entries: usize,
    admission: &super::AdmissionRegistry,
    network_id: &NetworkId,
) -> Result<VrfState, VrfError> {
    let max_bytes = max_entries
        .checked_mul(768)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(|| VrfError::Persistence("VRF state byte limit overflow".to_owned()))?;
    let Some(bytes) = read_secure_state(path, max_bytes, "provider VRF")
        .map_err(|error| VrfError::Persistence(error.to_string()))?
    else {
        return Ok(VrfState::default());
    };
    let snapshot: VrfStateSnapshotV1 =
        decode_from_bytes(&bytes).map_err(|error| VrfError::Persistence(error.to_string()))?;
    let canonical =
        to_bytes(&snapshot).map_err(|error| VrfError::Persistence(error.to_string()))?;
    if canonical != bytes
        || snapshot.version != VRF_STATE_VERSION_V1
        || snapshot.network_id != *network_id
        || snapshot.entries.len() > max_entries
    {
        return Err(VrfError::Persistence(
            "VRF state is non-canonical, unsupported, or over limit".to_owned(),
        ));
    }
    let mut state = VrfState::default();
    let mut previous_key = None;
    for entry in snapshot.entries {
        if previous_key.is_some_and(|previous| previous >= entry.key)
            || entry.key.epoch_id != entry.submission.epoch_id
            || entry.key.provider_id != entry.submission.provider_id
            || entry.key.manifest_digest != entry.submission.manifest_digest
            || entry.submission.network_id != *network_id.as_bytes()
        {
            return Err(VrfError::Persistence(
                "VRF state entries are duplicate, unordered, or misbound to the network".to_owned(),
            ));
        }
        previous_key = Some(entry.key);
        entry.submission.validate()?;
        let Some(record) = admission.entry(&entry.key.provider_id) else {
            // Revocation deliberately removes the provider's verification keys
            // from the active registry. Drop its expired trust-bound payloads,
            // but retain the separately persisted sequence high-water below so
            // re-admission cannot resurrect an old signed submission.
            iroha_logger::warn!(
                provider_id = %hex::encode(entry.key.provider_id),
                epoch_id = entry.key.epoch_id,
                "dropping persisted PoR VRF entry for a no-longer-admitted provider"
            );
            continue;
        };
        if let Err(error) = entry
            .submission
            .verify_signature_for_provider(record.advert_key())
        {
            // Entries are a rebuildable cache, while the separately persisted sequence
            // high-water below is the replay-security boundary. A governed provider key
            // rotation therefore invalidates old cached signatures without bricking startup.
            iroha_logger::warn!(
                provider_id = %hex::encode(entry.key.provider_id),
                epoch_id = entry.key.epoch_id,
                ?error,
                "dropping persisted PoR VRF entry invalidated by current provider admission"
            );
            continue;
        }
        if let Err(error) = verify_provider_vrf(&entry.submission, record.por_vrf_key(), network_id)
        {
            iroha_logger::warn!(
                provider_id = %hex::encode(entry.key.provider_id),
                epoch_id = entry.key.epoch_id,
                ?error,
                "dropping persisted PoR VRF entry invalidated by current provider VRF policy"
            );
            continue;
        }
        state.entries.insert(entry.key, entry.submission);
    }
    let mut previous_provider = None;
    for sequence in snapshot.sequences {
        if sequence.provider_id.iter().all(|byte| *byte == 0)
            || sequence.high_water == 0
            || previous_provider.is_some_and(|previous| previous >= sequence.provider_id)
        {
            return Err(VrfError::Persistence(
                "VRF replay high-water entries are invalid or unordered".to_owned(),
            ));
        }
        let observed = state
            .entries
            .values()
            .filter(|submission| submission.provider_id == sequence.provider_id)
            .map(|submission| submission.sequence)
            .max()
            .unwrap_or(0);
        if observed > sequence.high_water {
            return Err(VrfError::Persistence(
                "VRF replay high-water regresses below an accepted entry".to_owned(),
            ));
        }
        previous_provider = Some(sequence.provider_id);
        state
            .sequences
            .insert(sequence.provider_id, sequence.high_water);
    }
    if state
        .entries
        .values()
        .any(|submission| !state.sequences.contains_key(&submission.provider_id))
    {
        return Err(VrfError::Persistence(
            "VRF state is missing provider replay high-water".to_owned(),
        ));
    }
    Ok(state)
}
#[cfg(feature = "app_api")]
/// Narrow boundary for durable PoR Governance DAG publication.
trait PorGovernancePublisher: Send + Sync {
    /// Return whether a durable signed Governance DAG publisher is bound.
    fn is_ready(&self) -> bool;
    /// Publish one validated canonical challenge envelope.
    ///
    /// # Errors
    ///
    /// Returns [`sorafs_node::GovernancePublishError`] when durable outbox
    /// enqueueing or publication fails.
    fn publish_challenge(
        &self,
        publication: PorChallengePublicationV1,
    ) -> Result<(), sorafs_node::GovernancePublishError>;
    /// Publish one validated canonical weekly report.
    ///
    /// # Errors
    ///
    /// Returns [`sorafs_node::GovernancePublishError`] when durable outbox
    /// enqueueing or publication fails.
    fn publish_weekly_report(
        &self,
        report: PorWeeklyReportV1,
    ) -> Result<(), sorafs_node::GovernancePublishError>;
}
#[cfg(feature = "app_api")]
impl PorGovernancePublisher for sorafs_node::NodeHandle {
    fn is_ready(&self) -> bool {
        self.has_governance_publisher()
    }
    fn publish_challenge(
        &self,
        publication: PorChallengePublicationV1,
    ) -> Result<(), sorafs_node::GovernancePublishError> {
        self.publish_por_challenge_publication(publication)
    }
    fn publish_weekly_report(
        &self,
        report: PorWeeklyReportV1,
    ) -> Result<(), sorafs_node::GovernancePublishError> {
        self.publish_por_weekly_report(report)
    }
}
#[cfg(feature = "app_api")]
/// Errors that can surface while running the PoR automation workflow.
#[derive(Debug, Error)]
pub enum PorAutomationError {
    /// Randomness provider failed to produce a value.
    #[error("randomness failure: {0}")]
    Randomness(#[from] RandomnessError),
    /// Failed to collect VRF information required for challenge planning.
    #[error("vrf provider failure: {0}")]
    Vrf(#[from] VrfError),
    /// Challenge planner failed to assemble a schedule.
    #[error("challenge planner failure: {0}")]
    Planner(#[from] PorChallengePlannerError),
    /// Storage backend encountered an error.
    #[error("storage error: {0}")]
    Storage(#[from] PorMutationFailureV1),
    /// Coordinator rejected the requested state change.
    #[error("coordinator error: {0}")]
    Coordinator(#[from] PorCoordinatorError),
    /// Governance publication step failed.
    #[error("governance publish failure: {0}")]
    Governance(#[from] sorafs_node::GovernancePublishError),
    /// Planned challenge metadata could not form a canonical publication.
    #[error("invalid challenge publication: {0}")]
    ChallengePublication(#[from] PorChallengePublicationValidationError),
    /// Timestamp arithmetic overflowed the supported range.
    #[error("timestamp overflow")]
    TimestampOverflow,
    /// A physically retained blocking mutation worker failed to join.
    #[error("PoR lifecycle persistence worker failed: {0}")]
    BlockingWorker(String),
}
#[cfg(feature = "app_api")]
/// Runtime wiring PoR challenge scheduling, proof ingestion, and reporting automation.
pub struct PorCoordinatorRuntime {
    /// Storage backend responsible for persisting PoR-related records.
    storage: Arc<dyn PorStorage>,
    /// Atomic read projection rebuilt from node-authoritative lifecycle state.
    coordinator: Arc<PorCoordinator>,
    /// Randomness provider used to derive deterministic challenge seeds.
    randomness: Arc<dyn RandomnessProvider>,
    /// Adapter supplying governance/peer VRF bundle metadata.
    vrf_provider: Arc<dyn VrfProvider>,
    /// Submission-capable verified provider used by the Torii ingest route.
    verified_vrf_provider: Option<Arc<VerifiedVrfProvider>>,
    /// Publisher invoked to emit governance-facing telemetry (reports, exports).
    publisher: Arc<dyn PorGovernancePublisher>,
    /// Torii telemetry handle used for scheduler metrics.
    telemetry: crate::routing::MaybeTelemetry,
    /// Interval between PoR epochs in seconds.
    epoch_interval_secs: u64,
    /// Response window duration granted to providers (seconds).
    response_window_secs: u64,
    /// Epoch-relative deadline before the forced challenge path is permitted.
    vrf_submission_deadline_secs: u64,
    /// Last epoch for which automation was executed successfully.
    last_epoch: AtomicU64,
    /// Marker tracking when weekly reports were last generated.
    last_report_marker: AtomicU64,
    /// Serialises scheduler invocations and their durable side effects.
    run_lock: tokio::sync::Mutex<()>,
}
#[cfg(feature = "app_api")]
impl PorCoordinatorRuntime {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    /// Create a new runtime harness for PoR automation.
    pub fn new(
        storage: Arc<dyn PorStorage>,
        coordinator: Arc<PorCoordinator>,
        randomness: Arc<dyn RandomnessProvider>,
        vrf_provider: Arc<dyn VrfProvider>,
        publisher: Arc<sorafs_node::NodeHandle>,
        epoch_interval_secs: u64,
        response_window_secs: u64,
        vrf_submission_deadline_secs: u64,
    ) -> Self {
        Self::new_with_publisher(
            storage,
            coordinator,
            randomness,
            vrf_provider,
            publisher,
            epoch_interval_secs,
            response_window_secs,
            vrf_submission_deadline_secs,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_with_publisher(
        storage: Arc<dyn PorStorage>,
        coordinator: Arc<PorCoordinator>,
        randomness: Arc<dyn RandomnessProvider>,
        vrf_provider: Arc<dyn VrfProvider>,
        publisher: Arc<dyn PorGovernancePublisher>,
        epoch_interval_secs: u64,
        response_window_secs: u64,
        vrf_submission_deadline_secs: u64,
    ) -> Self {
        assert!(
            publisher.is_ready(),
            "enabled PoR runtime requires the embedded SoraFS node's signed Governance DAG publisher"
        );
        Self {
            storage,
            coordinator,
            randomness,
            vrf_provider,
            verified_vrf_provider: None,
            publisher,
            telemetry: crate::routing::MaybeTelemetry::disabled(),
            epoch_interval_secs: epoch_interval_secs.max(60),
            response_window_secs: response_window_secs.max(60),
            vrf_submission_deadline_secs,
            last_epoch: AtomicU64::new(u64::MAX),
            last_report_marker: AtomicU64::new(0),
            run_lock: tokio::sync::Mutex::new(()),
        }
    }
    /// Attach the authenticated provider VRF ingest store used by this runtime.
    #[must_use]
    pub fn with_verified_vrf_provider(mut self, provider: Arc<VerifiedVrfProvider>) -> Self {
        self.verified_vrf_provider = Some(provider);
        self
    }
    /// Attach Torii telemetry to the runtime.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: crate::routing::MaybeTelemetry) -> Self {
        self.telemetry = telemetry;
        self
    }
    fn record_challenge_metric(&self, challenge: &PorChallengeV1, duplicate_samples: usize) {
        self.telemetry.with_metrics(|tel| {
            tel.record_sorafs_por_scheduler_challenge(challenge.forced, duplicate_samples);
        });
    }
    fn record_scheduler_failure(&self) {
        self.telemetry.with_metrics(|tel| {
            tel.record_sorafs_por_scheduler_failure();
        });
    }
    fn compute_epoch(&self, now_secs: u64) -> u64 {
        now_secs / self.epoch_interval_secs
    }
    /// Compute the ISO week marker for the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`PorAutomationError`] when the timestamp cannot be converted into a valid ISO week.
    fn compute_completed_iso_marker(
        now_secs: u64,
    ) -> Result<(PorReportIsoWeek, u64), PorAutomationError> {
        let ts = i64::try_from(now_secs).map_err(|_| PorAutomationError::TimestampOverflow)?;
        let datetime = OffsetDateTime::from_unix_timestamp(ts)
            .map_err(|_| PorAutomationError::TimestampOverflow)?;
        let (year, week, _) = datetime.to_iso_week_date();
        let year_u16 = u16::try_from(year).map_err(|_| PorAutomationError::TimestampOverflow)?;
        let current_cycle = PorReportIsoWeek {
            year: year_u16,
            week,
        };
        current_cycle
            .validate()
            .map_err(PorCoordinatorError::InvalidIsoWeek)
            .map_err(PorAutomationError::Coordinator)?;
        let (current_cycle_start, _) =
            iso_week_bounds(current_cycle).map_err(PorAutomationError::Coordinator)?;
        let completed_cycle_time = current_cycle_start - Duration::seconds(1);
        let (completed_year, completed_week, _) = completed_cycle_time.to_iso_week_date();
        let cycle = PorReportIsoWeek {
            year: u16::try_from(completed_year)
                .map_err(|_| PorAutomationError::TimestampOverflow)?,
            week: completed_week,
        };
        cycle
            .validate()
            .map_err(PorCoordinatorError::InvalidIsoWeek)
            .map_err(PorAutomationError::Coordinator)?;
        Ok((cycle, iso_week_marker(cycle)))
    }
    /// Publish a weekly report if the ISO week marker has advanced.
    ///
    /// # Errors
    ///
    /// Returns [`PorAutomationError`] when report generation or publishing fails.
    fn publish_weekly_report_if_needed(&self, now_secs: u64) -> Result<(), PorAutomationError> {
        let (cycle, marker) = Self::compute_completed_iso_marker(now_secs)?;
        if self.last_report_marker.load(AtomicOrdering::SeqCst) == marker {
            return Ok(());
        }
        let prepared = self
            .coordinator
            .prepare_weekly_report(cycle)
            .map_err(PorAutomationError::Coordinator)?;
        if !prepared.published {
            self.publisher
                .publish_weekly_report(prepared.report.clone())?;
            self.coordinator
                .mark_weekly_report_published(&prepared.report)
                .map_err(PorAutomationError::Coordinator)?;
        }
        self.last_report_marker.store(
            iso_week_marker(prepared.report.cycle),
            AtomicOrdering::SeqCst,
        );
        Ok(())
    }
    /// Execute automation logic for the specified timestamp (seconds since UNIX epoch).
    ///
    /// # Errors
    ///
    /// Returns [`PorAutomationError`] if randomness, storage, or publishing
    /// backends fail during execution.
    pub async fn run_once_at(&self, now_secs: u64) -> Result<bool, PorAutomationError> {
        let _run = self.run_lock.lock().await;
        let epoch = self.compute_epoch(now_secs);
        if self.last_epoch.load(AtomicOrdering::SeqCst) == epoch {
            self.publish_weekly_report_if_needed(now_secs)?;
            return Ok(false);
        }
        let epoch_start = epoch
            .checked_mul(self.epoch_interval_secs)
            .ok_or(PorAutomationError::TimestampOverflow)?;
        let forced_deadline = epoch_start
            .checked_add(self.vrf_submission_deadline_secs)
            .ok_or(PorAutomationError::TimestampOverflow)?;
        if now_secs < forced_deadline {
            self.publish_weekly_report_if_needed(now_secs)?;
            return Ok(false);
        }
        let mut randomness = self
            .randomness
            .randomness_for_epoch(epoch, now_secs, self.response_window_secs)
            .await?;
        randomness.issued_at_unix = forced_deadline;
        let vrf_map = self.vrf_provider.vrf_bundles_for_epoch(&randomness)?;
        let planned = self.storage.plan_challenges(randomness, &vrf_map, true)?;
        if planned.is_empty() {
            self.last_epoch.store(epoch, AtomicOrdering::SeqCst);
            self.publish_weekly_report_if_needed(now_secs)?;
            return Ok(false);
        }
        for PlannedChallenge {
            challenge,
            duplicate_samples,
        } in planned
        {
            let publication =
                PorChallengePublicationV1::try_new(challenge.clone(), duplicate_samples)?;
            let pipeline = self.coordinator.lock_pipeline().await;
            let storage = Arc::clone(&self.storage);
            let coordinator = Arc::clone(&self.coordinator);
            let challenge_for_worker = challenge.clone();
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    // Cancellation detaches a blocking task. Retain the pipeline
                    // guard in the physical worker so no later delta can overtake
                    // the durable node mutation or its projection update.
                    let _pipeline = pipeline;
                    match storage.record_challenge(&challenge_for_worker) {
                        Ok(update) => coordinator
                            .apply_authoritative_update(update)
                            .map_err(PorAutomationError::Coordinator),
                        Err(error) => {
                            if error.disposition().invalidates_projection() {
                                coordinator.invalidate_authoritative_projection();
                            }
                            Err(PorAutomationError::Storage(error))
                        }
                    }
                }),
            )
            .await
            .map_err(|error| {
                self.coordinator.invalidate_authoritative_projection();
                PorAutomationError::BlockingWorker(error.to_string())
            })??;
            if let Err(err) = self.publisher.publish_challenge(publication) {
                iroha_logger::error!(
                    ?err,
                    provider_id = %hex::encode(challenge.provider_id),
                    challenge_id = %hex::encode(challenge.challenge_id),
                    "failed to publish PoR challenge through the durable Governance DAG outbox"
                );
                return Err(PorAutomationError::Governance(err));
            }
            self.record_challenge_metric(&challenge, duplicate_samples);
        }
        self.last_epoch.store(epoch, AtomicOrdering::SeqCst);
        self.publish_weekly_report_if_needed(now_secs)?;
        Ok(true)
    }
    /// Execute automation logic using the current system clock.
    ///
    /// # Errors
    ///
    /// Propagates [`PorAutomationError`] from [`Self::run_once_at`].
    pub async fn run_once(&self) -> Result<bool, PorAutomationError> {
        self.run_once_at(unix_now()).await
    }
    /// Accept one authenticated provider VRF for an active local manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the submission store is disabled, the proof fails
    /// authentication, freshness, network, replay, or manifest checks, capacity is
    /// exhausted, or durable persistence fails.
    pub fn submit_provider_vrf(
        &self,
        submission: ProviderVrfSubmissionV1,
        now_secs: u64,
    ) -> Result<(), VrfError> {
        let provider = self
            .verified_vrf_provider
            .as_ref()
            .ok_or_else(|| VrfError::Persistence("VRF submission store is disabled".to_owned()))?;
        let current_epoch = self.compute_epoch(now_secs);
        provider.verify_submission(&submission, now_secs, current_epoch)?;
        let target_is_active = self.storage.vrf_target_is_active(
            submission.provider_id,
            submission.manifest_digest,
            now_secs,
        );
        if !target_is_active {
            return Err(VrfError::UnknownManifest);
        }
        provider.accept_verified(submission, current_epoch)
    }
    /// Spawn the supervised Tokio task that periodically runs [`run_once`](Self::run_once) until
    /// shutdown.
    pub(crate) fn spawn(
        self: Arc<Self>,
        shutdown: ShutdownSignal,
    ) -> tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit> {
        const TICK_INTERVAL_SECS: u64 = 60;
        tokio::spawn(async move {
            let mut ticker = interval(StdDuration::from_secs(TICK_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.receive() => {
                        return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    }
                    _ = ticker.tick() => {
                        if shutdown.is_sent() {
                            return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                        }
                        if let Err(err) = self.run_once().await {
                            self.record_scheduler_failure();
                            iroha_logger::error!(%err, "PoR coordinator runtime tick failed");
                        }
                    }
                }
            }
        })
    }
}
#[cfg(feature = "app_api")]
/// Storage abstraction required by the PoR automation runtime.
pub trait PorStorage: Send + Sync {
    /// Produce challenge plans for the supplied randomness and VRF dataset.
    ///
    /// # Errors
    ///
    /// Returns [`PorChallengePlannerError`] when planning fails.
    fn plan_challenges(
        &self,
        randomness: PorRandomness,
        vrf_records: &HashMap<ManifestVrfKey, ManifestVrfBundle>,
        allow_forced: bool,
    ) -> Result<Vec<PlannedChallenge>, PorChallengePlannerError>;
    /// Record the fact that a challenge was issued so providers can submit proofs later.
    ///
    /// # Errors
    ///
    /// Returns a typed mutation failure describing whether authoritative state
    /// changed when the challenge cannot be persisted.
    fn record_challenge(
        &self,
        challenge: &PorChallengeV1,
    ) -> Result<PorStatusAuthorityUpdateV1, PorMutationFailureV1>;
    /// Return whether a provider currently owns the active local manifest target.
    fn vrf_target_is_active(
        &self,
        provider_id: [u8; 32],
        manifest_digest: [u8; 32],
        now_secs: u64,
    ) -> bool;
}
#[cfg(feature = "app_api")]
impl PorStorage for sorafs_node::NodeHandle {
    fn plan_challenges(
        &self,
        randomness: PorRandomness,
        vrf_records: &HashMap<ManifestVrfKey, ManifestVrfBundle>,
        allow_forced: bool,
    ) -> Result<Vec<PlannedChallenge>, PorChallengePlannerError> {
        self.plan_por_challenges_with_forced_policy(randomness, vrf_records, allow_forced)
    }
    fn record_challenge(
        &self,
        challenge: &PorChallengeV1,
    ) -> Result<PorStatusAuthorityUpdateV1, PorMutationFailureV1> {
        self.record_por_challenge_with_authority_update(challenge)
    }
    fn vrf_target_is_active(
        &self,
        provider_id: [u8; 32],
        manifest_digest: [u8; 32],
        now_secs: u64,
    ) -> bool {
        if self.capacity_usage().provider_id != Some(provider_id) {
            return false;
        }
        let Some(storage) = self.storage() else {
            return false;
        };
        let grace = self.gc_config().retention_grace_secs();
        storage.manifests().into_iter().any(|manifest| {
            if manifest.manifest_digest() != &manifest_digest {
                return false;
            }
            let retention = manifest.retention_epoch();
            retention == 0 || now_secs < retention.saturating_add(grace)
        })
    }
}
#[derive(Default)]
struct ProviderStats {
    manifests: HashSet<[u8; 32]>,
    challenges: u32,
    successes: u32,
    failures: u32,
    forced: u32,
    first_failure_at: Option<u64>,
}
/// Parameters used for filtering status queries.
/// Filter parameters for querying recorded PoR status information.
#[derive(Clone, Copy, Debug, Default)]
pub struct PorStatusFilter {
    /// Restrict results to challenges involving this manifest digest.
    pub manifest: Option<[u8; 32]>,
    /// Restrict results to challenges issued to this provider.
    pub provider: Option<[u8; 32]>,
    /// Restrict results to a specific epoch identifier.
    pub epoch: Option<u64>,
    /// Restrict results to a given challenge outcome.
    pub status: Option<PorChallengeOutcome>,
}
impl PorStatusFilter {
    fn matches(&self, status: &PorChallengeStatusV1) -> bool {
        if let Some(manifest) = self.manifest {
            if status.manifest_digest != manifest {
                return false;
            }
        }
        if let Some(provider) = self.provider {
            if status.provider_id != provider {
                return false;
            }
        }
        if let Some(epoch) = self.epoch {
            if status.epoch_id != epoch {
                return false;
            }
        }
        if let Some(outcome) = self.status {
            if status.status != outcome {
                return false;
            }
        }
        true
    }
}
/// Errors returned by the PoR coordinator while processing challenges, proofs, or reports.
#[derive(Debug, Error)]
pub enum PorCoordinatorError {
    /// The node-authoritative lifecycle projection has not been installed.
    #[error("authoritative PoR status projection is unavailable")]
    AuthoritativeProjectionUnavailable,
    /// The storage node supplied a malformed authoritative status projection.
    #[error("invalid authoritative PoR status projection: {0}")]
    InvalidAuthoritativeProjection(String),
    /// Challenge payload failed validation.
    #[error("challenge payload invalid: {0}")]
    InvalidChallenge(#[source] PorChallengeValidationError),
    /// Durable coordinator retention is full.
    #[error("PoR coordinator retention exhausted (limit {limit})")]
    RetentionExhausted {
        /// Configured hard entry limit.
        limit: usize,
    },
    /// Proof payload failed validation.
    #[error("proof payload invalid: {0}")]
    InvalidProof(#[source] sorafs_manifest::por::PorProofValidationError),
    /// Proof signature is invalid or not bound to provider admission.
    #[error("proof signature invalid or unauthorised: {0}")]
    InvalidProofSignature(#[source] sorafs_manifest::por::PorSignatureVerificationError),
    /// Verdict payload failed validation.
    #[error("verdict payload invalid: {0}")]
    InvalidVerdict(#[source] sorafs_manifest::por::AuditVerdictValidationError),
    /// Verdict signatures do not satisfy the configured auditor policy.
    #[error("verdict signatures invalid or unauthorised: {0}")]
    InvalidVerdictSignature(#[source] sorafs_manifest::por::PorSignatureVerificationError),
    /// Weekly report failed validation.
    #[error("weekly report failed validation: {0}")]
    InvalidWeeklyReport(#[source] PorWeeklyReportValidationError),
    /// A required page ceiling is zero or exceeds the protocol maximum.
    #[error("invalid PoR page `{field}` {value}; expected 1..={maximum}")]
    InvalidPageLimit {
        /// Query field containing the invalid ceiling.
        field: &'static str,
        /// Supplied value.
        value: usize,
        /// First-release protocol maximum.
        maximum: usize,
    },
    /// An inclusive export epoch range is reversed.
    #[error("start_epoch {start} must not exceed end_epoch {end}")]
    InvalidEpochRange {
        /// Inclusive lower bound.
        start: u64,
        /// Inclusive upper bound.
        end: u64,
    },
    /// The durable status generation cannot advance without wrapping.
    #[error("PoR status generation is exhausted")]
    StatusGenerationExhausted,
    /// A continuation references a coordinator generation that is no longer current.
    #[error(
        "PoR page generation changed: continuation expected {expected}, current generation is {current}"
    )]
    StalePageGeneration {
        /// Generation carried by the continuation request.
        expected: u64,
        /// Current coordinator generation.
        current: u64,
    },
    /// The cursor does not identify a retained challenge.
    #[error("unknown PoR page cursor anchor {challenge_id:?}")]
    UnknownPageCursorAnchor {
        /// Challenge identifier carried by the cursor.
        challenge_id: [u8; 32],
    },
    /// The opaque page cursor is malformed, non-canonical, oversized, or unsupported.
    #[error("invalid PoR page cursor: {0}")]
    InvalidPageCursor(String),
    /// A continuation was issued for another normalized filter or export range.
    #[error("PoR page cursor does not belong to the requested selection")]
    PageCursorSelectionMismatch,
    /// A cursor's embedded order key does not match its retained challenge.
    #[error("PoR page cursor anchor does not match challenge {challenge_id:?}")]
    PageCursorAnchorMismatch {
        /// Challenge identifier carried by the cursor.
        challenge_id: [u8; 32],
    },
    /// The cursor anchor is not a member of its bound filter or epoch range.
    #[error("PoR page cursor anchor does not belong to its bound selection")]
    PageCursorAnchorSelectionMismatch,
    /// A status index points at a record that is not present.
    #[error("PoR status index references missing challenge {challenge_id:?}")]
    StatusIndexCorrupt {
        /// Missing challenge identifier.
        challenge_id: [u8; 32],
    },
    /// Canonical status encoding failed while enforcing the byte ceiling.
    #[error("failed to encode canonical PoR status: {0}")]
    StatusPageEncoding(#[source] norito::core::Error),
    /// Page byte arithmetic or a deterministic integer conversion overflowed.
    #[error("PoR status page byte accounting overflowed")]
    StatusPageByteOverflow,
    /// The first matching status cannot fit the explicit byte ceiling.
    #[error(
        "PoR status {challenge_id:?} requires {record_bytes} canonical bytes, exceeding page limit {byte_limit}"
    )]
    StatusRecordExceedsPageByteLimit {
        /// Challenge identifier of the oversized record.
        challenge_id: [u8; 32],
        /// Canonical status-record byte length.
        record_bytes: usize,
        /// Caller-supplied byte ceiling.
        byte_limit: usize,
    },
    /// Challenge already exists with different payload.
    #[error("challenge with id {challenge_id_hex} already recorded with different payload")]
    ChallengeConflict {
        /// Binary challenge identifier that conflicts with existing state.
        challenge_id: [u8; 32],
        /// Hexadecimal representation of the conflicting identifier.
        challenge_id_hex: String,
    },
    /// Exact challenge payload was replayed.
    #[error("challenge with id {challenge_id_hex} was already recorded")]
    DuplicateChallenge {
        /// Replayed challenge identifier.
        challenge_id: [u8; 32],
        /// Hexadecimal representation of the replayed identifier.
        challenge_id_hex: String,
    },
    /// Proof already recorded for the given challenge.
    #[error("proof already recorded for challenge {challenge_id_hex}")]
    DuplicateProof {
        /// Challenge identifier receiving duplicate proof.
        challenge_id: [u8; 32],
        /// Hex representation of the challenge identifier.
        challenge_id_hex: String,
    },
    /// A terminal verdict conflicts with the canonical verdict already retained.
    #[error("verdict conflicts with the terminal record for challenge {challenge_id_hex}")]
    VerdictConflict {
        /// Challenge identifier receiving a conflicting verdict.
        challenge_id: [u8; 32],
        /// Hex representation of the challenge identifier.
        challenge_id_hex: String,
    },
    /// Canonical verdict bytes could not be encoded for exact replay binding.
    #[error("failed to encode canonical PoR verdict: {0}")]
    CanonicalVerdictEncoding(String),
    /// A compensating rollback encountered a later or different transition.
    #[error("cannot roll back challenge {challenge_id_hex}; lifecycle state changed")]
    RollbackConflict {
        /// Challenge identifier whose state could not be rolled back.
        challenge_id: [u8; 32],
        /// Hex representation of the challenge identifier.
        challenge_id_hex: String,
    },
    /// Challenge identifier not found.
    #[error("unknown challenge id {challenge_id_hex}")]
    UnknownChallenge {
        /// Missing challenge identifier.
        challenge_id: [u8; 32],
        /// Hex representation of the missing identifier.
        challenge_id_hex: String,
    },
    /// Submitted manifest digest does not match the expected digest.
    #[error("manifest digest mismatch (expected {expected_hex}, got {actual_hex})")]
    ManifestMismatch {
        /// Expected manifest digest.
        expected: [u8; 32],
        /// Actual manifest digest supplied in the proof.
        actual: [u8; 32],
        /// Expected digest as hex.
        expected_hex: String,
        /// Actual digest as hex.
        actual_hex: String,
    },
    /// Submitted provider identifier does not match the challenge metadata.
    #[error("provider id mismatch (expected {expected_hex}, got {actual_hex})")]
    ProviderMismatch {
        /// Expected provider identifier.
        expected: [u8; 32],
        /// Actual provider identifier.
        actual: [u8; 32],
        /// Expected identifier rendered as hex.
        expected_hex: String,
        /// Actual identifier rendered as hex.
        actual_hex: String,
    },
    /// Proof sample indices differ from the governed challenge selection.
    #[error("proof sample indices do not match challenge {challenge_id_hex}")]
    SampleIndicesMismatch {
        /// Challenge identifier whose sample coverage was violated.
        challenge_id: [u8; 32],
        /// Hex representation of the challenge identifier.
        challenge_id_hex: String,
    },
    /// Provider timestamp falls outside the challenge response window.
    #[error(
        "proof submitted_at {submitted_at} is outside challenge window {issued_at}..={deadline_at}"
    )]
    ProofOutsideChallengeWindow {
        /// Provider-supplied proof timestamp.
        submitted_at: u64,
        /// Challenge issue timestamp.
        issued_at: u64,
        /// Inclusive challenge deadline.
        deadline_at: u64,
    },
    /// Verdict proof digest differs from the recorded proof.
    #[error("verdict proof digest mismatch (expected {expected_hex}, got {actual_hex})")]
    ProofDigestMismatch {
        /// Recorded proof digest.
        expected: [u8; 32],
        /// Verdict-supplied proof digest.
        actual: [u8; 32],
        /// Recorded digest in hexadecimal.
        expected_hex: String,
        /// Supplied digest in hexadecimal.
        actual_hex: String,
    },
    /// A proof exists, so the verdict must bind its digest.
    #[error("verdict must include the recorded proof digest")]
    MissingVerdictProofDigest,
    /// Verdict claims a proof digest when no proof was recorded.
    #[error("verdict includes a proof digest but no proof was recorded")]
    UnexpectedVerdictProofDigest,
    /// Successful or repaired verdicts cannot be issued without a proof.
    #[error("successful or repaired verdict requires a recorded proof")]
    MissingProofForSuccessfulVerdict,
    /// Verdict timestamp predates the challenge.
    #[error("verdict decided_at {decided_at} predates challenge issued_at {issued_at}")]
    VerdictBeforeChallenge {
        /// Verdict decision timestamp.
        decided_at: u64,
        /// Challenge issue timestamp.
        issued_at: u64,
    },
    /// Verdict timestamp predates the proof.
    #[error("verdict decided_at {decided_at} predates proof submitted_at {submitted_at}")]
    VerdictBeforeProof {
        /// Verdict decision timestamp.
        decided_at: u64,
        /// Proof submission timestamp.
        submitted_at: u64,
    },
    /// ISO week input could not be parsed.
    #[error("invalid ISO week requested: {0}")]
    InvalidIsoWeek(#[source] PorReportIsoWeekValidationError),
    /// Failed to compute ISO week bounds from the supplied data.
    #[error("failed to compute ISO week bounds")]
    IsoWeekComputation,
    /// A prepared report cannot be replaced by an older reporting cycle.
    #[error(
        "weekly report cycle rollback from prepared {prepared} to requested {requested} is forbidden"
    )]
    WeeklyReportCycleRollback {
        /// Newest cycle whose exact report bytes are already retained.
        prepared: PorReportIsoWeek,
        /// Older cycle requested by the scheduler.
        requested: PorReportIsoWeek,
    },
    /// A later cycle cannot replace report bytes that have not been published.
    #[error("weekly report {prepared} is still pending publication; cannot advance to {requested}")]
    WeeklyReportPublicationPending {
        /// Cycle whose exact prepared bytes still require publication.
        prepared: PorReportIsoWeek,
        /// Newer cycle requested by the scheduler.
        requested: PorReportIsoWeek,
    },
    /// Publication acknowledgement did not match the retained prepared report.
    #[error("weekly report publication acknowledgement for {cycle} has no exact prepared report")]
    WeeklyReportPreparationConflict {
        /// Cycle named by the conflicting acknowledgement.
        cycle: PorReportIsoWeek,
    },
    /// A prior snapshot may have committed despite a post-publication failure.
    #[error(
        "PoR persistence is fail-stopped after an uncertain commit; restart and reconcile before continuing: {reason}"
    )]
    PersistenceFaultLatched {
        /// Post-publication failure that caused the coordinator to fail-stop.
        reason: String,
    },
    /// Underlying persistence failed.
    #[error("persistence failure: {0}")]
    Persistence(#[from] PorPersistenceError),
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
fn iso_week_bounds(
    cycle: PorReportIsoWeek,
) -> Result<(OffsetDateTime, OffsetDateTime), PorCoordinatorError> {
    let date = Date::from_iso_week_date(i32::from(cycle.year), cycle.week, Weekday::Monday)
        .map_err(|_| PorCoordinatorError::IsoWeekComputation)?;
    let start = date
        .with_hms(0, 0, 0)
        .map_err(|_| PorCoordinatorError::IsoWeekComputation)?
        .assume_utc();
    let end = start
        .checked_add(Duration::weeks(1))
        .ok_or(PorCoordinatorError::IsoWeekComputation)?;
    Ok((start, end))
}
fn iso_week_marker(cycle: PorReportIsoWeek) -> u64 {
    (u64::from(cycle.year) << 8) | u64::from(cycle.week)
}
fn next_iso_week(cycle: PorReportIsoWeek) -> Result<PorReportIsoWeek, PorCoordinatorError> {
    cycle
        .validate()
        .map_err(PorCoordinatorError::InvalidIsoWeek)?;
    let (_, next_start) = iso_week_bounds(cycle)?;
    let (year, week, _) = next_start.to_iso_week_date();
    let next = PorReportIsoWeek {
        year: u16::try_from(year).map_err(|_| PorCoordinatorError::IsoWeekComputation)?,
        week,
    };
    next.validate()
        .map_err(PorCoordinatorError::InvalidIsoWeek)?;
    Ok(next)
}
fn canonical_weekly_report_generated_at(
    cycle: PorReportIsoWeek,
) -> Result<u64, PorCoordinatorError> {
    cycle
        .validate()
        .map_err(PorCoordinatorError::InvalidIsoWeek)?;
    let (_, end) = iso_week_bounds(cycle)?;
    u64::try_from(end.unix_timestamp()).map_err(|_| PorCoordinatorError::IsoWeekComputation)
}
// ------------- Tests -------------
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(feature = "app_api")]
    use sorafs_manifest::{ProviderAdmissionCouncilPolicy, ProviderAdmissionEnvelopeV1};
    use sorafs_manifest::{
        por::{
            POR_CHALLENGE_VERSION_V1, POR_PROOF_VERSION_V1, POR_VRF_SUBMISSION_VERSION_V1,
            derive_challenge_id, derive_challenge_seed,
        },
        provider_advert::{AdvertSignature, SignatureAlgorithm},
    };
    use std::sync::{Arc as StdArc, Barrier};
    use tempfile::tempdir;
    fn canonical_temp_root(dir: &tempfile::TempDir) -> PathBuf {
        let root = fs::canonicalize(dir.path()).expect("canonical temp root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("private canonical temp root");
        }
        root
    }
    #[cfg(feature = "app_api")]
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([seed; iroha_crypto::Hash::LENGTH]),
        ))
    }
    fn provider_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0xAB; 32])
    }
    fn auditor_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0xAC; 32])
    }
    fn provider_key() -> Vec<u8> {
        provider_signing_key().verifying_key().to_bytes().to_vec()
    }
    fn auditor_keys() -> Vec<Vec<u8>> {
        vec![auditor_signing_key().verifying_key().to_bytes().to_vec()]
    }
    fn resign_proof(proof: &mut sorafs_manifest::por::PorProofV1) {
        let key = provider_signing_key();
        proof.signature.public_key = key.verifying_key().to_bytes().to_vec();
        let payload = proof
            .signature_payload_bytes()
            .expect("encode proof signing payload");
        proof.signature.signature = key.sign(&payload).to_bytes().to_vec();
    }
    fn resign_verdict(verdict: &mut AuditVerdictV1) {
        let key = auditor_signing_key();
        let payload = verdict
            .signature_payload_bytes()
            .expect("encode verdict signing payload");
        verdict.auditor_signatures = vec![AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(&payload).to_bytes().to_vec(),
        }];
    }
    #[test]
    fn persistence_path_preserves_suffixes_without_predictable_temp_name() {
        let base = PathBuf::from("/tmp/por_snapshot.norito.json");
        let persistence = PorPersistence::new(base.clone());
        assert_eq!(persistence.path, base);
    }
    #[cfg(unix)]
    #[test]
    fn immutable_secure_publication_is_exactly_idempotent_and_conflict_safe() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let path = root.join("challenge.json");
        secure_atomic_write(&path, b"canonical-a", 1_024, false).expect("first publication");
        secure_atomic_write(&path, b"canonical-a", 1_024, false).expect("exact replay");
        assert!(matches!(
            secure_atomic_write(&path, b"canonical-b", 1_024, false),
            Err(SecureFileError::Conflict)
        ));
        assert_eq!(fs::read(&path).expect("published bytes"), b"canonical-a");
        assert_eq!(
            fs::read_dir(&root)
                .expect("list publication root")
                .filter_map(Result::ok)
                .count(),
            1,
            "temporary files must not survive publication or conflict"
        );
    }
    #[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
    #[test]
    fn descriptor_relative_link_publication_is_exclusive_and_unlinks_source() {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let source = root.join(".publication.tmp");
        let destination = root.join("published.json");
        fs::write(&source, b"canonical").expect("write source");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let parent = options.open(&root).expect("open publication directory");
        link_secure_file_noreplace(
            &parent,
            source.file_name().expect("source name"),
            destination.file_name().expect("destination name"),
        )
        .expect("publish through linkat");
        assert!(
            !source.exists(),
            "successful publication must unlink its source"
        );
        assert_eq!(
            fs::read(&destination).expect("published bytes"),
            b"canonical"
        );
        assert_eq!(
            fs::symlink_metadata(&destination)
                .expect("published metadata")
                .nlink(),
            1,
            "published file must not retain the temporary hard link"
        );
        fs::write(&source, b"replacement").expect("write conflicting source");
        let error = link_secure_file_noreplace(
            &parent,
            source.file_name().expect("source name"),
            destination.file_name().expect("destination name"),
        )
        .expect_err("existing destination must reject publication");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).expect("winner bytes"), b"canonical");
        assert_eq!(
            fs::read(&source).expect("rejected source remains for caller cleanup"),
            b"replacement"
        );
    }
    #[cfg(unix)]
    #[test]
    fn descriptor_relative_replace_stays_bound_to_opened_parent() {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let named_parent = root.join("state");
        fs::create_dir(&named_parent).expect("create original parent");
        fs::set_permissions(&named_parent, fs::Permissions::from_mode(0o700))
            .expect("private original parent");
        let source_name = std::ffi::OsStr::new(".state.tmp");
        let destination_name = std::ffi::OsStr::new("state.to");
        fs::write(named_parent.join(source_name), b"canonical").expect("write staged state");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let pinned_parent = options.open(&named_parent).expect("pin original parent");
        let displaced_parent = root.join("displaced-state");
        fs::rename(&named_parent, &displaced_parent).expect("displace original parent");
        fs::create_dir(&named_parent).expect("create path impostor");
        fs::set_permissions(&named_parent, fs::Permissions::from_mode(0o700))
            .expect("private path impostor");
        fs::write(named_parent.join(source_name), b"attacker sentinel")
            .expect("write same-name impostor entry");
        publish_secure_file_replace(
            &pinned_parent,
            source_name,
            destination_name,
            &named_parent.join(source_name),
            &named_parent.join(destination_name),
        )
        .expect("publish through pinned parent");
        assert_eq!(
            fs::read(displaced_parent.join(destination_name)).expect("pinned publication"),
            b"canonical"
        );
        assert!(
            !named_parent.join(destination_name).exists(),
            "path impostor must not receive the replacement"
        );
        assert_eq!(
            fs::read(named_parent.join(source_name)).expect("impostor sentinel survives"),
            b"attacker sentinel",
            "descriptor-relative publication and cleanup must not unlink through a swapped path"
        );
    }
    #[cfg(all(unix, not(target_os = "espidf")))]
    #[test]
    fn descriptor_relative_read_stays_bound_to_opened_parent() {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let named_parent = root.join("state");
        fs::create_dir(&named_parent).expect("create original parent");
        fs::set_permissions(&named_parent, fs::Permissions::from_mode(0o700))
            .expect("private original parent");
        let filename = std::ffi::OsStr::new("state.to");
        let original = named_parent.join(filename);
        fs::write(&original, b"canonical").expect("write original state");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600))
            .expect("private original state");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let pinned_parent = options.open(&named_parent).expect("pin original parent");
        let displaced_parent = root.join("displaced-state");
        fs::rename(&named_parent, &displaced_parent).expect("displace original parent");
        fs::create_dir(&named_parent).expect("create path impostor");
        fs::set_permissions(&named_parent, fs::Permissions::from_mode(0o700))
            .expect("private path impostor");
        let impostor = named_parent.join(filename);
        fs::write(&impostor, b"malicious").expect("write same-size impostor state");
        fs::set_permissions(&impostor, fs::Permissions::from_mode(0o600))
            .expect("private impostor state");
        assert_eq!(
            secure_read_bytes_in_parent(&pinned_parent, filename, &impostor, 1_024)
                .expect("descriptor-relative read")
                .expect("state exists"),
            b"canonical"
        );
        assert_eq!(
            fs::read(&impostor).expect("impostor survives"),
            b"malicious"
        );
    }
    #[cfg(any(not(unix), target_os = "espidf"))]
    #[test]
    fn immutable_publication_fails_closed_without_atomic_noreplace_support() {
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        let destination = root.join("published.json");
        assert!(matches!(
            secure_atomic_write(&destination, b"canonical", 1_024, false),
            Err(SecureFileError::Io(error))
                if error.kind() == std::io::ErrorKind::Unsupported
        ));
        assert!(!destination.exists());
        assert_eq!(
            fs::read_dir(&root)
                .expect("list publication root")
                .filter_map(Result::ok)
                .count(),
            0,
            "unsupported publication must not leave temporary state"
        );
    }
    #[cfg(unix)]
    #[test]
    fn concurrent_immutable_publication_has_one_canonical_winner() {
        use std::os::unix::fs::PermissionsExt as _;
        const WORKERS: usize = 16;
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let path = StdArc::new(root.join("challenge.json"));
        let barrier = StdArc::new(Barrier::new(WORKERS));
        let results = std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(WORKERS);
            for index in 0..WORKERS {
                let path = StdArc::clone(&path);
                let barrier = StdArc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    let body = format!("canonical-{index:02}");
                    barrier.wait();
                    (
                        body.clone(),
                        secure_atomic_write(&path, body.as_bytes(), 1_024, false),
                    )
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().expect("publication worker"))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1,
            "publication results: {results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| matches!(result, Err(SecureFileError::Conflict)))
                .count(),
            WORKERS - 1,
            "publication results: {results:?}"
        );
        let winner = results
            .iter()
            .find(|(_, result)| result.is_ok())
            .map(|(body, _)| body.as_bytes())
            .expect("one winner");
        assert_eq!(fs::read(&*path).expect("winner bytes"), winner);
        assert_eq!(
            fs::read_dir(&root)
                .expect("list publication root")
                .filter_map(Result::ok)
                .count(),
            1,
            "temporary files must not survive concurrent publication"
        );
    }
    #[cfg(unix)]
    #[test]
    fn concurrent_identical_immutable_publication_is_idempotent() {
        use std::os::unix::fs::PermissionsExt as _;
        const WORKERS: usize = 16;
        const CANONICAL: &[u8] = b"one-canonical-publication";
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let path = StdArc::new(root.join("challenge.json"));
        let barrier = StdArc::new(Barrier::new(WORKERS));
        let results = std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(WORKERS);
            // Start every barrier participant before waiting for any worker.
            for _ in 0..WORKERS {
                let path = StdArc::clone(&path);
                let barrier = StdArc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    secure_atomic_write(&path, CANONICAL, 1_024, false)
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().expect("publication worker"))
                .collect::<Vec<_>>()
        });
        assert!(
            results.iter().all(Result::is_ok),
            "identical concurrent publications must be idempotent: {results:?}"
        );
        assert_eq!(fs::read(&*path).expect("canonical bytes"), CANONICAL);
        assert_eq!(
            fs::read_dir(&root)
                .expect("list publication root")
                .filter_map(Result::ok)
                .count(),
            1,
            "temporary files must not survive idempotent publication"
        );
    }
    #[cfg(unix)]
    #[test]
    fn secure_persistence_rejects_parent_traversal_symlinks_and_hardlinks() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        assert!(matches!(
            secure_atomic_write(&root.join("nested/../escape"), b"x", 8, true),
            Err(SecureFileError::UnsafePath(_))
        ));
        let real = root.join("real");
        fs::create_dir(&real).expect("real directory");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("private real dir");
        let linked = root.join("linked");
        symlink(&real, &linked).expect("linked ancestor");
        assert!(matches!(
            secure_atomic_write(&linked.join("state.to"), b"x", 8, true),
            Err(SecureFileError::UnsafePath(_))
        ));
        let destination = real.join("state.to");
        secure_atomic_write(&destination, b"state", 8, true).expect("initial state");
        let alias = real.join("state-alias.to");
        fs::hard_link(&destination, &alias).expect("hard link");
        assert!(matches!(
            secure_read_bytes(&destination, 8),
            Err(SecureFileError::UnsafePath(_))
        ));
        assert!(matches!(
            secure_atomic_write(&destination, b"state", 8, false),
            Err(SecureFileError::UnsafePath(_))
        ));
    }
    #[cfg(all(unix, feature = "app_api"))]
    fn drand_test_provider(state_path: PathBuf) -> DrandHttpRandomnessProvider {
        let state_owner_lock =
            SecureStateOwnerLock::acquire(&state_path, "drand").expect("state owner lock");
        DrandHttpRandomnessProvider {
            public_key: [0; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES],
            genesis_time: 1,
            period_secs: 1,
            epoch_interval_secs: 1,
            quorum: 1,
            max_body_bytes: MIN_DRAND_RESPONSE_BYTES,
            max_beacon_age_secs: 1,
            max_future_skew_secs: 0,
            endpoints: Vec::new(),
            state_path: state_path.clone(),
            state_owner_lock,
            state: Mutex::new(None),
            commit_lock: tokio::sync::Mutex::new(()),
        }
    }
    #[cfg(all(unix, feature = "app_api"))]
    #[tokio::test]
    async fn drand_high_water_commits_atomically_under_concurrency() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private state root");
        let state_path = root.join("drand-state.to");
        let provider = StdArc::new(drand_test_provider(state_path.clone()));
        let lower = VerifiedDrandBeacon {
            round: 10,
            randomness: [0x10; 32],
            signature: [0x11; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
        };
        let higher = VerifiedDrandBeacon {
            round: 11,
            randomness: [0x20; 32],
            signature: [0x21; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
        };
        let lower_provider = StdArc::clone(&provider);
        let higher_provider = StdArc::clone(&provider);
        let (lower_result, higher_result) = tokio::join!(
            async move { lower_provider.commit_high_water(&lower).await },
            async move { higher_provider.commit_high_water(&higher).await },
        );
        assert!(higher_result.is_ok(), "higher round must commit");
        assert!(
            lower_result.is_ok()
                || matches!(
                    lower_result,
                    Err(RandomnessError::Rollback {
                        received: 10,
                        high_water: 11
                    })
                ),
            "the lower round may commit first or be rejected after the higher round"
        );
        let in_memory = provider
            .state
            .lock()
            .clone()
            .expect("in-memory high-water state");
        assert_eq!(in_memory.round, 11);
        assert_eq!(in_memory.randomness, [0x20; 32]);
        let persisted = read_secure_state(&state_path, 4 * 1024, "drand")
            .expect("read persisted high-water state")
            .expect("persisted high-water bytes");
        let persisted: DrandHighWaterStateV1 =
            decode_from_bytes(&persisted).expect("decode persisted high-water state");
        crate::frame_test_support::assert_current_frame(
            &persisted,
            "iroha_torii::sorafs::por::DrandHighWaterStateV1",
        );
        assert_eq!(persisted.round, 11);
        assert_eq!(persisted.randomness, [0x20; 32]);
    }
    #[cfg(all(unix, feature = "app_api"))]
    #[test]
    fn drand_state_owner_lock_is_exclusive_and_recoverable() {
        let dir = tempdir().expect("temp dir");
        let state_path = canonical_temp_root(&dir).join("drand-state.to");
        let first = SecureStateOwnerLock::acquire(&state_path, "drand")
            .expect("first owner acquires the state lock");
        assert!(matches!(
            SecureStateOwnerLock::acquire(&state_path, "drand"),
            Err(RandomnessError::Persistence(message))
                if message.contains("ownership lock is already held")
        ));
        drop(first);
        SecureStateOwnerLock::acquire(&state_path, "drand")
            .expect("ownership lock is released when the provider is dropped");
    }
    #[cfg(all(unix, feature = "app_api"))]
    #[tokio::test]
    async fn drand_persistence_failure_rolls_back_memory_and_retry_succeeds() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("temp dir");
        let state_path = canonical_temp_root(&dir).join("drand-state.to");
        let provider = drand_test_provider(state_path.clone());
        let beacon = VerifiedDrandBeacon {
            round: 10,
            randomness: [0x41; 32],
            signature: [0x42; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
        };
        symlink("missing-target", &state_path).expect("install unsafe destination");
        assert!(matches!(
            provider.commit_high_water(&beacon).await,
            Err(RandomnessError::Persistence(_))
        ));
        assert!(provider.state.lock().is_none());
        fs::remove_file(&state_path).expect("remove unsafe destination");
        provider
            .commit_high_water(&beacon)
            .await
            .expect("retry persists after the filesystem is repaired");
        assert_eq!(
            provider.state.lock().as_ref().map(|state| state.round),
            Some(10)
        );
    }
    #[cfg(all(unix, feature = "app_api"))]
    #[tokio::test]
    async fn drand_same_round_equivocation_never_overwrites_high_water() {
        let dir = tempdir().expect("temp dir");
        let state_path = canonical_temp_root(&dir).join("drand-state.to");
        let provider = drand_test_provider(state_path.clone());
        let accepted = VerifiedDrandBeacon {
            round: 10,
            randomness: [0x51; 32],
            signature: [0x52; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
        };
        provider
            .commit_high_water(&accepted)
            .await
            .expect("commit initial high-water");
        let persisted = fs::read(&state_path).expect("read initial high-water");
        let conflicting = VerifiedDrandBeacon {
            randomness: [0x61; 32],
            signature: [0x62; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
            ..accepted
        };
        assert!(matches!(
            provider.commit_high_water(&conflicting).await,
            Err(RandomnessError::Equivocation { round: 10 })
        ));
        assert_eq!(
            fs::read(&state_path).expect("read retained high-water"),
            persisted
        );
        assert_eq!(
            provider.state.lock().as_ref().unwrap().randomness,
            [0x51; 32]
        );
    }
    #[cfg(all(unix, feature = "app_api"))]
    #[test]
    fn drand_startup_rejects_truncated_and_wrong_key_state() {
        let dir = tempdir().expect("temp dir");
        let state_path = canonical_temp_root(&dir).join("drand-state.to");
        secure_atomic_write(&state_path, &[0x01], 4 * 1024, true).expect("write truncated state");
        assert!(matches!(
            load_drand_state(
                &state_path,
                &[0; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES]
            ),
            Err(RandomnessError::Persistence(_))
        ));
        let quicknet_key: [u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES] = hex::decode(concat!(
            "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c",
            "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb",
            "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
        ))
        .expect("decode quicknet key")
        .try_into()
        .expect("quicknet key length");
        let signature: [u8; iroha_crypto::drand::DRAND_SIGNATURE_BYTES] = hex::decode(concat!(
            "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125",
            "e342b73a8dd2bacbe47e4b6b63ed5e39",
        ))
        .expect("decode quicknet signature")
        .try_into()
        .expect("quicknet signature length");
        let randomness: [u8; 32] =
            hex::decode("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd")
                .expect("decode quicknet randomness")
                .try_into()
                .expect("quicknet randomness length");
        store_secure_state(
            &state_path,
            &DrandHighWaterStateV1 {
                version: DRAND_STATE_VERSION_V1,
                round: 1_000,
                randomness,
                signature,
            },
            "drand",
        )
        .expect("write valid quicknet state");
        load_drand_state(&state_path, &quicknet_key).expect("pinned quicknet state");
        let wrong_form_key_pair = iroha_crypto::KeyPair::try_from_seed(
            vec![0x7A; 32],
            iroha_crypto::Algorithm::BlsNormal,
        )
        .expect("derive a valid G1 key");
        let (_, wrong_form_key_bytes) = wrong_form_key_pair.public_key().to_bytes();
        assert!(
            <[u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES]>::try_from(wrong_form_key_bytes)
                .is_err(),
            "a BLS-normal G1 key must not be accepted as a drand G2 public key"
        );
        let wrong_key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x7A; 32], iroha_crypto::Algorithm::BlsSmall)
                .expect("derive a distinct valid G2 key");
        let (_, wrong_key_bytes) = wrong_key_pair.public_key().to_bytes();
        let wrong_key: [u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES] = wrong_key_bytes
            .try_into()
            .expect("BLS-small G2 public key length");
        assert!(matches!(
            load_drand_state(&state_path, &wrong_key),
            Err(RandomnessError::Persistence(_))
        ));
    }
    #[cfg(feature = "app_api")]
    include!("por/vrf_state_tests.rs");
    fn sample_challenge(forced: bool) -> PorChallengeV1 {
        let manifest_digest = [0x22; 32];
        let provider_id = [0x33; 32];
        let epoch_id = 42;
        let drand_round = 77;
        let drand_randomness = [0x44; 32];
        let vrf_output = if forced { None } else { Some([0x66; 32]) };
        let sample_indices: Vec<u64> = (0..64).collect();
        let seed = derive_challenge_seed(
            &drand_randomness,
            vrf_output.as_ref(),
            &manifest_digest,
            epoch_id,
        );
        let challenge_id =
            derive_challenge_id(&seed, &manifest_digest, &provider_id, epoch_id, drand_round);
        PorChallengeV1 {
            version: POR_CHALLENGE_VERSION_V1,
            challenge_id,
            manifest_digest,
            provider_id,
            epoch_id,
            drand_round,
            drand_randomness,
            drand_signature: [0x55; 48],
            vrf_output,
            vrf_proof: if forced {
                None
            } else {
                Some(iroha_crypto::vrf::VrfProof::SigInG1([0x77; 48]))
            },
            forced,
            chunking_profile: "sorafs.sf1@1.0.0".to_string(),
            seed,
            sample_tier: 1,
            sample_count: 64,
            sample_indices,
            issued_at: 1_700_000_000,
            deadline_at: 1_700_000_900,
        }
    }
    fn authoritative_status_snapshot(marker: u8, generation: u64) -> PorStatusAuthoritySnapshotV1 {
        let mut challenge = sample_challenge(marker.is_multiple_of(2));
        challenge.provider_id = [marker; 32];
        challenge.epoch_id = challenge.epoch_id.saturating_add(u64::from(marker));
        challenge.issued_at = challenge.issued_at.saturating_add(u64::from(marker));
        challenge.deadline_at = challenge.deadline_at.saturating_add(u64::from(marker));
        challenge.seed = derive_challenge_seed(
            &challenge.drand_randomness,
            challenge.vrf_output.as_ref(),
            &challenge.manifest_digest,
            challenge.epoch_id,
        );
        challenge.challenge_id = derive_challenge_id(
            &challenge.seed,
            &challenge.manifest_digest,
            &challenge.provider_id,
            challenge.epoch_id,
            challenge.drand_round,
        );
        challenge.validate().expect("projection challenge");
        PorStatusAuthoritySnapshotV1 {
            generation,
            statuses: vec![ChallengeRecord::from_challenge(challenge).to_status()],
        }
    }
    #[test]
    fn absent_node_authority_is_explicitly_unavailable() {
        let coordinator = PorCoordinator::new();
        assert!(matches!(
            coordinator.require_authoritative_projection(),
            Err(PorCoordinatorError::AuthoritativeProjectionUnavailable)
        ));
        coordinator
            .install_authoritative_projection(authoritative_status_snapshot(0x40, 100))
            .expect("install node-authoritative projection");
        assert!(coordinator.require_authoritative_projection().is_ok());
    }
    #[test]
    fn authoritative_projection_swap_is_generation_record_atomic() {
        let coordinator = StdArc::new(PorCoordinator::new());
        let first = authoritative_status_snapshot(0x41, 100);
        let second = authoritative_status_snapshot(0x42, 200);
        let first_id = first.statuses[0].challenge_id;
        let second_id = second.statuses[0].challenge_id;
        coordinator
            .install_authoritative_projection(first.clone())
            .expect("install initial projection");
        let barrier = StdArc::new(Barrier::new(5));
        let writer = {
            let coordinator = StdArc::clone(&coordinator);
            let barrier = StdArc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    coordinator
                        .install_authoritative_projection(second.clone())
                        .expect("install or exactly replay newer authoritative projection");
                }
            })
        };
        let readers = (0..4)
            .map(|_| {
                let coordinator = StdArc::clone(&coordinator);
                let barrier = StdArc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..500 {
                        let page = coordinator
                            .query_status_page(
                                &PorStatusFilter::default(),
                                PorStatusPageLimits::new(4, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                                    .expect("page limits"),
                                PorStatusPageCursor::First,
                            )
                            .expect("read one atomic projection");
                        assert_eq!(page.statuses.len(), 1);
                        match page.snapshot_generation {
                            100 => assert_eq!(page.statuses[0].challenge_id, first_id),
                            200 => assert_eq!(page.statuses[0].challenge_id, second_id),
                            other => panic!("unexpected projection generation {other}"),
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        writer.join().expect("projection writer joins");
        for reader in readers {
            reader.join().expect("projection reader joins");
        }
        assert!(matches!(
            coordinator.install_authoritative_projection(first),
            Err(PorCoordinatorError::InvalidAuthoritativeProjection(_))
        ));
        assert_eq!(
            coordinator
                .require_authoritative_projection()
                .expect("newer projection remains installed")
                .indexes
                .generation,
            200
        );
    }
    #[test]
    fn authoritative_projection_updates_in_place_and_fail_closed_on_generation_gaps() {
        let coordinator = PorCoordinator::new();
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 1,
                statuses: Vec::new(),
            })
            .expect("install empty authoritative projection");
        let projection_address = {
            let projection = coordinator.authoritative_projection.read();
            std::ptr::from_ref(projection.as_ref().expect("installed projection"))
        };
        let challenge = sample_challenge(false);
        let pending_status = ChallengeRecord::from_challenge(challenge.clone()).to_status();
        let pending_update = PorStatusAuthorityUpdateV1 {
            generation: 2,
            status: pending_status.clone(),
            removed_challenge_ids: Vec::new(),
        };
        coordinator
            .apply_authoritative_update(pending_update.clone())
            .expect("insert one authoritative status in place");
        coordinator
            .apply_authoritative_update(pending_update)
            .expect("same-generation exact update is idempotent");
        let proof = sample_proof(&challenge);
        let mut proof_record = ChallengeRecord::from_challenge(challenge);
        proof_record.proof_digest = Some(proof.proof_digest());
        proof_record.proof_submitted_at = Some(proof.submitted_at);
        proof_record.responded_at = Some(proof.submitted_at);
        let proof_status = proof_record.to_status();
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 3,
                status: proof_status.clone(),
                removed_challenge_ids: Vec::new(),
            })
            .expect("replace one status and its indexes in place");
        let projection = coordinator.authoritative_projection.read();
        assert_eq!(
            std::ptr::from_ref(projection.as_ref().expect("projection remains installed"),),
            projection_address,
            "incremental updates must mutate the installed projection rather than clone history"
        );
        assert_eq!(
            projection
                .as_ref()
                .expect("projection remains installed")
                .statuses
                .get(&proof_status.challenge_id),
            Some(&proof_status)
        );
        drop(projection);
        let gap = coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 5,
                status: proof_status.clone(),
                removed_challenge_ids: Vec::new(),
            })
            .expect_err("a skipped authoritative generation must fail closed");
        assert!(matches!(
            gap,
            PorCoordinatorError::InvalidAuthoritativeProjection(_)
        ));
        assert!(matches!(
            // Paging has a local-record path only in unit tests. The production
            // authority guard must remain closed until the checkpoint is rebuilt.
            coordinator.require_authoritative_projection(),
            Err(PorCoordinatorError::AuthoritativeProjectionUnavailable)
        ));
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 3,
                statuses: vec![proof_status.clone()],
            })
            .expect("reinstall authoritative projection after gap");
        let conflicting_status =
            ChallengeRecord::from_challenge(sample_challenge(true)).to_status();
        let conflict = coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 3,
                status: conflicting_status,
                removed_challenge_ids: Vec::new(),
            })
            .expect_err("only an identical same-generation replay is valid");
        assert!(matches!(
            conflict,
            PorCoordinatorError::InvalidAuthoritativeProjection(_)
        ));
        assert!(coordinator.authoritative_projection.read().is_none());
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 3,
                statuses: vec![proof_status.clone()],
            })
            .expect("reinstall authoritative projection after conflict");
        let rollback = coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 2,
                status: proof_status,
                removed_challenge_ids: Vec::new(),
            })
            .expect_err("an authoritative generation rollback must fail closed");
        assert!(matches!(
            rollback,
            PorCoordinatorError::InvalidAuthoritativeProjection(_)
        ));
        assert!(coordinator.authoritative_projection.read().is_none());
    }
    #[test]
    fn authoritative_projection_rejects_skipped_proof_submission_generation() {
        let coordinator = PorCoordinator::new();
        let awaiting = authoritative_status_snapshot(0x45, 2).statuses.remove(0);
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 2,
                statuses: vec![awaiting.clone()],
            })
            .expect("install awaiting-proof authority");
        let mut skipped = awaiting.clone();
        skipped.status = PorChallengeOutcome::Failed;
        skipped.responded_at = Some(skipped.issued_at.saturating_add(1));
        skipped.proof_digest = Some([0xA5; 32]);
        skipped.repair_task_id = Some([0xB5; 32]);
        skipped.failure_reason = Some("invalid proof".to_owned());
        skipped.validate().expect("locally valid terminal status");
        assert!(matches!(
            coordinator.apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 3,
                status: skipped,
                removed_challenge_ids: Vec::new(),
            }),
            Err(PorCoordinatorError::InvalidAuthoritativeProjection(_))
        ));
        assert!(coordinator.authoritative_projection.read().is_none());
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 2,
                statuses: vec![awaiting.clone()],
            })
            .expect("restore awaiting-proof authority");
        let mut deadline_failure = awaiting;
        deadline_failure.status = PorChallengeOutcome::Failed;
        deadline_failure.repair_task_id = Some([0xC5; 32]);
        deadline_failure.failure_reason = Some("deadline expired".to_owned());
        deadline_failure
            .validate()
            .expect("deadline failure without proof material is valid");
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 3,
                status: deadline_failure,
                removed_challenge_ids: Vec::new(),
            })
            .expect("direct deadline failure is the admitted no-proof transition");
    }
    #[test]
    fn forced_provenance_counts_survive_same_provider_epoch_retention() {
        let coordinator = PorCoordinator::with_record_limit(2);
        let provider_id = [0xD5; 32];
        let epoch_id = 55;
        let mut first = authoritative_status_snapshot(0x52, 10).statuses.remove(0);
        let mut second = authoritative_status_snapshot(0x54, 10).statuses.remove(0);
        for status in [&mut first, &mut second] {
            status.provider_id = provider_id;
            status.epoch_id = epoch_id;
            status.forced = true;
            status.status = PorChallengeOutcome::Verified;
            status.responded_at = Some(status.issued_at.saturating_add(1));
            status.proof_digest = Some([0xA5; 32]);
            status
                .validate()
                .expect("forced terminal authority fixture");
        }
        let mut statuses = vec![first.clone(), second.clone()];
        statuses.sort_by_key(|status| status.challenge_id);
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 10,
                statuses,
            })
            .expect("install two forced challenges for one provider epoch");
        {
            let projection = coordinator.authoritative_projection.read();
            assert_eq!(
                projection
                    .as_ref()
                    .expect("projection")
                    .forced_providers
                    .get(&provider_id)
                    .and_then(|epochs| epochs.get(&epoch_id)),
                Some(&2)
            );
        }
        let replacement = authoritative_status_snapshot(0x56, 11).statuses.remove(0);
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 11,
                status: replacement,
                removed_challenge_ids: vec![first.challenge_id],
            })
            .expect("retire only one same-epoch forced challenge");
        {
            let projection = coordinator.authoritative_projection.read();
            assert_eq!(
                projection
                    .as_ref()
                    .expect("projection")
                    .forced_providers
                    .get(&provider_id)
                    .and_then(|epochs| epochs.get(&epoch_id)),
                Some(&1),
                "retiring one challenge must preserve the surviving provenance"
            );
        }
        let replacement = authoritative_status_snapshot(0x58, 12).statuses.remove(0);
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 12,
                status: replacement,
                removed_challenge_ids: vec![second.challenge_id],
            })
            .expect("retire the final same-epoch forced challenge");
        assert!(
            !coordinator
                .authoritative_projection
                .read()
                .as_ref()
                .expect("projection")
                .forced_providers
                .contains_key(&provider_id)
        );
    }
    #[test]
    fn authoritative_projection_rolls_terminal_retention_and_accepts_archived_replay_noop() {
        let coordinator = PorCoordinator::with_record_limit(1);
        let mut terminal = authoritative_status_snapshot(0x61, 4).statuses.remove(0);
        let proof_digest = [0xA5; 32];
        terminal.status = PorChallengeOutcome::Verified;
        terminal.responded_at = Some(terminal.issued_at.saturating_add(1));
        terminal.proof_digest = Some(proof_digest);
        terminal.validate().expect("terminal authority fixture");
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 4,
                statuses: vec![terminal.clone()],
            })
            .expect("install full bounded projection");
        let replacement = authoritative_status_snapshot(0x62, 5).statuses.remove(0);
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 5,
                status: replacement.clone(),
                removed_challenge_ids: vec![terminal.challenge_id],
            })
            .expect("remove archived terminal and insert replacement atomically");
        coordinator
            .apply_authoritative_update(PorStatusAuthorityUpdateV1 {
                generation: 5,
                status: terminal,
                removed_challenge_ids: Vec::new(),
            })
            .expect("authenticated archived exact replay is a projection no-op");
        let projection = coordinator.authoritative_projection.read();
        let projection = projection.as_ref().expect("projection remains installed");
        assert_eq!(projection.statuses.len(), 1);
        assert_eq!(
            projection.statuses.get(&replacement.challenge_id),
            Some(&replacement)
        );
    }
    #[test]
    fn restart_rebuilds_projection_and_persistence_retires_lifecycle_records() {
        let dir = tempdir().expect("temp dir");
        let path = canonical_temp_root(&dir).join("por-report-state.to");
        let stale_challenge = sample_challenge(false);
        let coordinator = PorCoordinator::with_persistence(path.clone()).expect("coordinator");
        coordinator
            .record_challenge(&stale_challenge)
            .expect("persist legacy lifecycle fixture");
        drop(coordinator);
        let restored = PorCoordinator::with_persistence(path.clone()).expect("restore fixture");
        let authoritative = authoritative_status_snapshot(0x77, 300);
        let authoritative_id = authoritative.statuses[0].challenge_id;
        restored
            .install_authoritative_projection(authoritative.clone())
            .expect("replace stale lifecycle projection");
        restored
            .retire_lifecycle_persistence()
            .expect("persist report-only coordinator state");
        let page = restored
            .query_status_page(
                &PorStatusFilter::default(),
                PorStatusPageLimits::new(4, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                    .expect("page limits"),
                PorStatusPageCursor::First,
            )
            .expect("query rebuilt projection");
        assert_eq!(page.snapshot_generation, 300);
        assert_eq!(page.statuses[0].challenge_id, authoritative_id);
        drop(restored);
        let report_only =
            PorCoordinator::with_persistence(path).expect("restore report-only state");
        let empty = report_only
            .query_status_page(
                &PorStatusFilter::default(),
                PorStatusPageLimits::new(4, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                    .expect("page limits"),
                PorStatusPageCursor::First,
            )
            .expect("lifecycle records were retired");
        assert!(empty.statuses.is_empty());
        report_only
            .install_authoritative_projection(authoritative)
            .expect("rebuild projection after restart");
        let rebuilt = report_only
            .query_status_page(
                &PorStatusFilter::default(),
                PorStatusPageLimits::new(4, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                    .expect("page limits"),
                PorStatusPageCursor::First,
            )
            .expect("query restarted projection");
        assert_eq!(rebuilt.statuses[0].challenge_id, authoritative_id);
    }
    fn sample_proof(challenge: &PorChallengeV1) -> sorafs_manifest::por::PorProofV1 {
        let mut proof = sorafs_manifest::por::PorProofV1 {
            version: POR_PROOF_VERSION_V1,
            challenge_id: challenge.challenge_id,
            manifest_digest: challenge.manifest_digest,
            provider_id: challenge.provider_id,
            samples: (0..64)
                .map(|idx| sorafs_manifest::por::PorProofSampleV1 {
                    sample_index: idx,
                    chunk_offset: 0,
                    chunk_size: 4096,
                    chunk_digest: [0x10; 32],
                    leaf_digest: [0x20; 32],
                })
                .collect(),
            auth_path: vec![[0xAA; 32]],
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
            submitted_at: 1_700_000_500,
        };
        resign_proof(&mut proof);
        proof
    }
    fn sample_verdict(
        challenge: &PorChallengeV1,
        outcome: AuditOutcomeV1,
        proof_digest: Option<[u8; 32]>,
    ) -> AuditVerdictV1 {
        let mut verdict = AuditVerdictV1 {
            version: sorafs_manifest::por::AUDIT_VERDICT_VERSION_V1,
            manifest_digest: challenge.manifest_digest,
            provider_id: challenge.provider_id,
            challenge_id: challenge.challenge_id,
            proof_digest,
            outcome,
            failure_reason: match outcome {
                AuditOutcomeV1::Success => None,
                AuditOutcomeV1::Failed | AuditOutcomeV1::Repaired => {
                    Some("digest mismatch".to_string())
                }
            },
            decided_at: 1_700_000_600,
            auditor_signatures: Vec::new(),
            metadata: Vec::new(),
        };
        resign_verdict(&mut verdict);
        verdict
    }
    #[test]
    fn records_challenge_proof_and_verdict() {
        let coordinator = PorCoordinator::new();
        let challenge = sample_challenge(false);
        coordinator.record_challenge(&challenge).expect("challenge");
        let proof = sample_proof(&challenge);
        let proof_digest = proof.proof_digest();
        coordinator
            .record_proof(&proof, &provider_key())
            .expect("proof");
        let verdict = sample_verdict(&challenge, AuditOutcomeV1::Success, Some(proof_digest));
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("verdict");
        let statuses = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.status, PorChallengeOutcome::Verified);
        assert_eq!(status.proof_digest, Some(proof_digest));
    }
    #[test]
    fn status_query_filters_before_applying_page_limit() {
        fn challenge_for(provider: u8, issued_at: u64) -> PorChallengeV1 {
            let mut challenge = sample_challenge(false);
            challenge.provider_id = [provider; 32];
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.issued_at = issued_at;
            challenge.deadline_at = issued_at + 900;
            challenge
        }
        let coordinator = PorCoordinator::new();
        let page_anchor = challenge_for(0x31, 1_700_000_000);
        let non_matching = challenge_for(0x32, 1_700_001_000);
        let matching = challenge_for(0x33, 1_700_002_000);
        for challenge in [&page_anchor, &non_matching, &matching] {
            coordinator
                .record_challenge(challenge)
                .expect("record distinct challenge");
        }
        let filter = PorStatusFilter {
            provider: Some(matching.provider_id),
            ..PorStatusFilter::default()
        };
        let statuses = coordinator.query_statuses(&filter, Some(1), None);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].challenge_id, matching.challenge_id);
    }
    #[test]
    fn indexed_status_pages_enforce_continuity_and_exact_byte_budget() {
        fn challenge_for(provider: u8, issued_at: u64) -> PorChallengeV1 {
            let mut challenge = sample_challenge(false);
            challenge.provider_id = [provider; 32];
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.issued_at = issued_at;
            challenge.deadline_at = issued_at + 900;
            challenge
        }
        let coordinator = PorCoordinator::new();
        let challenges = [
            challenge_for(0x41, 1_700_000_100),
            challenge_for(0x42, 1_700_000_200),
            challenge_for(0x43, 1_700_000_300),
        ];
        for challenge in &challenges {
            coordinator
                .record_challenge(challenge)
                .expect("record indexed challenge");
        }
        let one_record = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("one-record limits");
        let first = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                one_record,
                PorStatusPageCursor::First,
            )
            .expect("first indexed page");
        crate::frame_test_support::assert_current_frame(
            &first,
            "iroha_torii::sorafs::por::PorStatusPageV1",
        );
        let response = norito::to_bytes(&first).expect("encode status handler response");
        assert_eq!(
            norito::decode_from_bytes::<PorStatusPageV1>(&response)
                .expect("decode status handler response"),
            first
        );
        assert_eq!(first.statuses.len(), 1);
        assert!(first.has_more);
        assert!(first.next_cursor.is_some());
        let second = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                one_record,
                PorStatusPageCursor::from_opaque(first.next_cursor.as_deref())
                    .expect("canonical continuation cursor"),
            )
            .expect("second indexed page");
        assert_eq!(second.statuses[0].challenge_id, challenges[1].challenge_id);
        assert_ne!(
            second.statuses[0].challenge_id,
            first.statuses[0].challenge_id
        );
        let first_record_bytes = to_bytes(&first.statuses[0])
            .expect("encode first status")
            .len();
        let byte_limited = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                PorStatusPageLimits::new(3, first_record_bytes).expect("exact byte limit"),
                PorStatusPageCursor::First,
            )
            .expect("byte-limited page");
        assert_eq!(byte_limited.statuses.len(), 1);
        assert_eq!(
            byte_limited.canonical_bytes,
            u64::try_from(first_record_bytes).expect("status length fits u64")
        );
        assert_eq!(byte_limited.inspected_candidates, 2);
        assert!(byte_limited.has_more);
        let resumed = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                PorStatusPageLimits::new(3, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                    .expect("resumed page limits"),
                PorStatusPageCursor::from_opaque(byte_limited.next_cursor.as_deref())
                    .expect("byte-limited continuation cursor"),
            )
            .expect("resume after the last consumed candidate");
        assert_eq!(
            resumed.statuses[0].challenge_id, challenges[1].challenge_id,
            "the matching record inspected only to discover a byte boundary must be retried"
        );
    }
    #[test]
    fn sparse_status_intersection_is_lookup_bounded_and_cursor_complete() {
        const STATUS_COUNT: usize = 1_027;
        const INTERSECTION_INDEX: usize = 513;
        let selected_manifest = [0xA1; 32];
        let selected_provider = [0xB1; 32];
        let mut statuses = Vec::with_capacity(STATUS_COUNT);
        let mut expected_match = [0_u8; 32];
        let mut first_cursor_anchor = [0_u8; 32];
        for index in 0..STATUS_COUNT {
            let mut challenge = sample_challenge(false);
            challenge.manifest_digest = if index <= INTERSECTION_INDEX {
                selected_manifest
            } else {
                [0xA2; 32]
            };
            challenge.provider_id = if index >= INTERSECTION_INDEX {
                selected_provider
            } else {
                [0xB2; 32]
            };
            challenge.epoch_id = 10_000 + u64::try_from(index).expect("fixture index fits u64");
            challenge.issued_at =
                1_700_000_000 + u64::try_from(index).expect("fixture index fits u64");
            challenge.deadline_at = challenge.issued_at + 900;
            challenge.seed = derive_challenge_seed(
                &challenge.drand_randomness,
                challenge.vrf_output.as_ref(),
                &challenge.manifest_digest,
                challenge.epoch_id,
            );
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.validate().expect("sparse projection challenge");
            if index == INTERSECTION_INDEX {
                expected_match = challenge.challenge_id;
            }
            if index + 1 == POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1 {
                first_cursor_anchor = challenge.challenge_id;
            }
            statuses.push(ChallengeRecord::from_challenge(challenge).to_status());
        }
        statuses.sort_by_key(|status| status.challenge_id);
        let coordinator = PorCoordinator::new();
        coordinator
            .install_authoritative_projection(PorStatusAuthoritySnapshotV1 {
                generation: 2_000,
                statuses,
            })
            .expect("install sparse authoritative projection");
        let filter = PorStatusFilter {
            manifest: Some(selected_manifest),
            provider: Some(selected_provider),
            ..PorStatusFilter::default()
        };
        let limits = PorStatusPageLimits::new(10, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("sparse page limits");
        coordinator
            .status_page_projection_lookups
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let first = coordinator
            .query_status_page(&filter, limits, PorStatusPageCursor::First)
            .expect("first sparse page");
        assert!(first.statuses.is_empty());
        assert_eq!(
            first.inspected_candidates,
            u32::try_from(POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1)
                .expect("inspection limit fits u32")
        );
        assert_eq!(
            coordinator
                .status_page_projection_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            POR_STATUS_PAGE_MAX_INSPECTED_CANDIDATES_V1
        );
        assert!(first.has_more);
        let first_cursor = PorStatusPageCursor::from_opaque(first.next_cursor.as_deref())
            .expect("empty sparse page returns an advancing cursor");
        assert!(matches!(
            first_cursor,
            PorStatusPageCursor::After { challenge_id, .. }
                if challenge_id == first_cursor_anchor
        ));
        coordinator
            .status_page_projection_lookups
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let second = coordinator
            .query_status_page(&filter, limits, first_cursor)
            .expect("continue sparse index traversal");
        assert_eq!(second.inspected_candidates, 2);
        assert_eq!(
            coordinator
                .status_page_projection_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(second.statuses.len(), 1);
        assert_eq!(second.statuses[0].challenge_id, expected_match);
        assert!(!second.has_more);
        assert!(second.next_cursor.is_none());
    }
    #[test]
    fn status_page_continuation_rejects_mutation_and_filter_substitution() {
        let coordinator = PorCoordinator::new();
        let first_challenge = sample_challenge(false);
        coordinator
            .record_challenge(&first_challenge)
            .expect("record first challenge");
        let mut second_challenge = sample_challenge(false);
        second_challenge.provider_id = [0x44; 32];
        second_challenge.challenge_id = derive_challenge_id(
            &second_challenge.seed,
            &second_challenge.manifest_digest,
            &second_challenge.provider_id,
            second_challenge.epoch_id,
            second_challenge.drand_round,
        );
        second_challenge.issued_at += 1;
        second_challenge.deadline_at += 1;
        coordinator
            .record_challenge(&second_challenge)
            .expect("record second challenge");
        let limits = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("page limits");
        let page = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::First,
            )
            .expect("first page");
        let cursor = PorStatusPageCursor::from_opaque(page.next_cursor.as_deref())
            .expect("first page must return a canonical continuation");
        let forged_epoch_cursor = match cursor {
            PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest,
                last_epoch_id,
                last_issued_at,
                challenge_id,
            } => PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest,
                last_epoch_id: last_epoch_id.saturating_add(1),
                last_issued_at,
                challenge_id,
            },
            PorStatusPageCursor::First => panic!("continuation cannot be first page"),
        };
        assert!(matches!(
            coordinator
                .query_status_page(&PorStatusFilter::default(), limits, forged_epoch_cursor,),
            Err(PorCoordinatorError::PageCursorAnchorMismatch { .. })
        ));
        let overlapping_filter = PorStatusFilter {
            status: Some(PorChallengeOutcome::AwaitingProof),
            ..PorStatusFilter::default()
        };
        assert!(matches!(
            coordinator.query_status_page(&overlapping_filter, limits, cursor,),
            Err(PorCoordinatorError::PageCursorSelectionMismatch)
        ));
        let mut third_challenge = sample_challenge(false);
        third_challenge.provider_id = [0x55; 32];
        third_challenge.challenge_id = derive_challenge_id(
            &third_challenge.seed,
            &third_challenge.manifest_digest,
            &third_challenge.provider_id,
            third_challenge.epoch_id,
            third_challenge.drand_round,
        );
        third_challenge.issued_at += 2;
        third_challenge.deadline_at += 2;
        coordinator
            .record_challenge(&third_challenge)
            .expect("mutate coordinator generation");
        assert!(matches!(
            coordinator.query_status_page(&PorStatusFilter::default(), limits, cursor,),
            Err(PorCoordinatorError::StalePageGeneration { .. })
        ));
    }
    #[test]
    fn export_continuation_rejects_overlapping_range_substitution() {
        let coordinator = PorCoordinator::new();
        let mut first = sample_challenge(false);
        first.epoch_id = 41;
        first.seed = derive_challenge_seed(
            &first.drand_randomness,
            first.vrf_output.as_ref(),
            &first.manifest_digest,
            first.epoch_id,
        );
        first.challenge_id = derive_challenge_id(
            &first.seed,
            &first.manifest_digest,
            &first.provider_id,
            first.epoch_id,
            first.drand_round,
        );
        coordinator
            .record_challenge(&first)
            .expect("record first export challenge");
        let mut second = sample_challenge(false);
        second.provider_id = [0x45; 32];
        second.epoch_id = 42;
        second.issued_at += 1;
        second.deadline_at += 1;
        second.seed = derive_challenge_seed(
            &second.drand_randomness,
            second.vrf_output.as_ref(),
            &second.manifest_digest,
            second.epoch_id,
        );
        second.challenge_id = derive_challenge_id(
            &second.seed,
            &second.manifest_digest,
            &second.provider_id,
            second.epoch_id,
            second.drand_round,
        );
        coordinator
            .record_challenge(&second)
            .expect("record second export challenge");
        let limits = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("export page limits");
        let page = coordinator
            .export_status_page(Some((41, 42)), limits, PorStatusPageCursor::First)
            .expect("first export page");
        let cursor = PorStatusPageCursor::from_opaque(page.page.next_cursor.as_deref())
            .expect("export page must return a canonical continuation");
        let forged_epoch_cursor = match cursor {
            PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest,
                last_epoch_id,
                last_issued_at,
                challenge_id,
            } => PorStatusPageCursor::After {
                snapshot_generation,
                selection_digest,
                last_epoch_id: last_epoch_id.saturating_add(1),
                last_issued_at,
                challenge_id,
            },
            PorStatusPageCursor::First => panic!("continuation cannot be first page"),
        };
        assert!(matches!(
            coordinator.export_status_page(Some((41, 42)), limits, forged_epoch_cursor),
            Err(PorCoordinatorError::PageCursorAnchorMismatch { .. })
        ));
        assert!(matches!(
            coordinator.export_status_page(Some((41, 43)), limits, cursor),
            Err(PorCoordinatorError::PageCursorSelectionMismatch)
        ));
    }
    #[test]
    fn outcome_index_tracks_verdict_transition_and_bounded_export() {
        let coordinator = PorCoordinator::new();
        let challenge = sample_challenge(false);
        coordinator
            .record_challenge(&challenge)
            .expect("record challenge");
        let limits = PorStatusPageLimits::new(4, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("page limits");
        let pending_filter = PorStatusFilter {
            status: Some(PorChallengeOutcome::AwaitingProof),
            ..PorStatusFilter::default()
        };
        assert_eq!(
            coordinator
                .query_status_page(&pending_filter, limits, PorStatusPageCursor::First)
                .expect("pending page")
                .statuses
                .len(),
            1
        );
        let proof = sample_proof(&challenge);
        let proof_digest = proof.proof_digest();
        coordinator
            .record_proof(&proof, &provider_key())
            .expect("record proof");
        let verdict = sample_verdict(&challenge, AuditOutcomeV1::Success, Some(proof_digest));
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("record verdict");
        assert!(
            coordinator
                .query_status_page(&pending_filter, limits, PorStatusPageCursor::First)
                .expect("updated pending page")
                .statuses
                .is_empty()
        );
        let verified_filter = PorStatusFilter {
            status: Some(PorChallengeOutcome::Verified),
            ..PorStatusFilter::default()
        };
        assert_eq!(
            coordinator
                .query_status_page(&verified_filter, limits, PorStatusPageCursor::First)
                .expect("verified page")
                .statuses[0]
                .challenge_id,
            challenge.challenge_id
        );
        let export = coordinator
            .export_status_page(
                Some((challenge.epoch_id, challenge.epoch_id)),
                PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
                    .expect("export limits"),
                PorStatusPageCursor::First,
            )
            .expect("bounded export page");
        let frame = crate::frame_test_support::assert_current_frame(
            &export,
            "iroha_torii::sorafs::por::PorStatusExportPageV1",
        );
        assert!(matches!(
            norito::decode_canonical::<PorStatusPageV1>(&frame),
            Err(norito::Error::SchemaMismatch)
        ));
        let response = norito::to_bytes(&export).expect("encode export handler response");
        assert_eq!(
            norito::decode_from_bytes::<PorStatusExportPageV1>(&response)
                .expect("decode export handler response"),
            export
        );
        assert_eq!(export.page.statuses.len(), 1);
        assert!(export.page.canonical_bytes <= export.page.canonical_byte_limit);
        assert_eq!(export.start_epoch, Some(challenge.epoch_id));
        assert_eq!(export.end_epoch, Some(challenge.epoch_id));
    }
    #[test]
    fn page_limit_type_rejects_zero_and_protocol_overflow() {
        assert!(matches!(
            PorStatusPageLimits::new(0, 1),
            Err(PorCoordinatorError::InvalidPageLimit { field: "limit", .. })
        ));
        assert!(matches!(
            PorStatusPageLimits::new(POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1 + 1, 1),
            Err(PorCoordinatorError::InvalidPageLimit { field: "limit", .. })
        ));
        assert!(matches!(
            PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1 + 1),
            Err(PorCoordinatorError::InvalidPageLimit {
                field: "max_bytes",
                ..
            })
        ));
    }
    #[test]
    fn forged_proofs_and_verdicts_leave_coordinator_state_retryable() {
        let coordinator = PorCoordinator::new();
        let challenge = sample_challenge(false);
        coordinator.record_challenge(&challenge).unwrap();
        let proof = sample_proof(&challenge);
        for mutation in 0..4 {
            let mut forged = proof.clone();
            match mutation {
                0 => forged.provider_id[0] ^= 1,
                1 => forged.manifest_digest[0] ^= 1,
                2 => forged.samples.swap(0, 1),
                3 => forged.submitted_at = challenge.deadline_at + 1,
                _ => unreachable!(),
            }
            resign_proof(&mut forged);
            assert!(coordinator.record_proof(&forged, &provider_key()).is_err());
            let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
            assert_eq!(status[0].proof_digest, None);
        }
        coordinator
            .record_proof(&proof, &provider_key())
            .expect("valid proof retry");
        let digest = proof.proof_digest();
        let valid = sample_verdict(&challenge, AuditOutcomeV1::Success, Some(digest));
        for mutation in 0..5 {
            let mut forged = valid.clone();
            match mutation {
                0 => forged.provider_id[0] ^= 1,
                1 => forged.manifest_digest[0] ^= 1,
                2 => forged.proof_digest = Some([0xEE; 32]),
                3 => forged.proof_digest = None,
                4 => forged.decided_at = proof.submitted_at - 1,
                _ => unreachable!(),
            }
            resign_verdict(&mut forged);
            assert!(
                coordinator
                    .record_verdict(&forged, &auditor_keys(), 1)
                    .is_err()
            );
            let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
            assert_eq!(status[0].status, PorChallengeOutcome::ProofSubmitted);
            assert_eq!(status[0].proof_digest, Some(digest));
        }
        coordinator
            .record_verdict(&valid, &auditor_keys(), 1)
            .expect("valid verdict retry");
        assert_eq!(
            coordinator
                .record_verdict(&valid, &auditor_keys(), 1)
                .expect("exact verdict replay"),
            PorCoordinatorVerdictOutcome::Existing
        );
        let mut conflicting = valid.clone();
        conflicting.decided_at = conflicting.decided_at.saturating_add(1);
        resign_verdict(&mut conflicting);
        assert!(matches!(
            coordinator.record_verdict(&conflicting, &auditor_keys(), 1),
            Err(PorCoordinatorError::VerdictConflict { .. })
        ));
    }
    #[test]
    fn coordinator_enforces_admission_key_and_auditor_policy() {
        let coordinator = PorCoordinator::new();
        let challenge = sample_challenge(false);
        coordinator.record_challenge(&challenge).unwrap();
        let proof = sample_proof(&challenge);
        assert!(matches!(
            coordinator.record_proof(&proof, &[0xEE; 32]),
            Err(PorCoordinatorError::InvalidProofSignature(
                sorafs_manifest::por::PorSignatureVerificationError::ProviderSignerMismatch
            ))
        ));
        coordinator
            .record_proof(&proof, &provider_key())
            .expect("admitted provider proof");
        let verdict = sample_verdict(
            &challenge,
            AuditOutcomeV1::Success,
            Some(proof.proof_digest()),
        );
        assert!(matches!(
            coordinator.record_verdict(&verdict, &[vec![0xEF; 32]], 1),
            Err(PorCoordinatorError::InvalidVerdictSignature(
                sorafs_manifest::por::PorSignatureVerificationError::UntrustedAuditorSigner
            ))
        ));
        let mut threshold_keys = auditor_keys();
        threshold_keys.push(vec![0xF0; 32]);
        assert!(matches!(
            coordinator.record_verdict(&verdict, &threshold_keys, 2),
            Err(PorCoordinatorError::InvalidVerdictSignature(
                sorafs_manifest::por::PorSignatureVerificationError::InsufficientTrustedAuditorSignatures {
                    actual: 1,
                    required: 2,
                }
            ))
        ));
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("trusted auditor threshold");
    }
    #[test]
    fn coordinator_rejects_replays_and_supports_compensating_rollbacks() {
        let coordinator = PorCoordinator::new();
        let challenge = sample_challenge(false);
        coordinator.record_challenge(&challenge).unwrap();
        assert!(matches!(
            coordinator.record_challenge(&challenge),
            Err(PorCoordinatorError::DuplicateChallenge { .. })
        ));
        let proof = sample_proof(&challenge);
        coordinator.record_proof(&proof, &provider_key()).unwrap();
        assert!(matches!(
            coordinator.record_proof(&proof, &provider_key()),
            Err(PorCoordinatorError::DuplicateProof { .. })
        ));
        coordinator.rollback_proof(&proof).unwrap();
        let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(status[0].proof_digest, None);
        coordinator.record_proof(&proof, &provider_key()).unwrap();
        let verdict = sample_verdict(
            &challenge,
            AuditOutcomeV1::Success,
            Some(proof.proof_digest()),
        );
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .unwrap();
        assert_eq!(
            coordinator
                .record_verdict(&verdict, &auditor_keys(), 1)
                .expect("exact replay"),
            PorCoordinatorVerdictOutcome::Existing
        );
        coordinator.rollback_verdict(&verdict).unwrap();
        let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(status[0].status, PorChallengeOutcome::ProofSubmitted);
        assert_eq!(status[0].proof_digest, Some(proof.proof_digest()));
    }
    #[test]
    fn concurrent_conflicting_proofs_have_exactly_one_winner() {
        const WORKERS: usize = 16;
        let coordinator = StdArc::new(PorCoordinator::new());
        let challenge = sample_challenge(false);
        coordinator.record_challenge(&challenge).unwrap();
        let barrier = StdArc::new(Barrier::new(WORKERS));
        let results = std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(WORKERS);
            for index in 0..WORKERS {
                let coordinator = StdArc::clone(&coordinator);
                let barrier = StdArc::clone(&barrier);
                let mut proof = sample_proof(&challenge);
                proof.auth_path[0][0] = u8::try_from(index + 1).expect("worker index fits u8");
                resign_proof(&mut proof);
                let provider_key = provider_key();
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    coordinator.record_proof(&proof, &provider_key)
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().expect("proof worker"))
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PorCoordinatorError::DuplicateProof { .. })))
                .count(),
            WORKERS - 1
        );
        let statuses = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert!(statuses[0].proof_digest.is_some());
    }
    #[cfg(unix)]
    #[test]
    fn persistence_failures_roll_back_each_coordinator_transition() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        let blocked_parent = root.join("blocked");
        let snapshot_path = blocked_parent.join("por.to");
        let coordinator = PorCoordinator::with_persistence(&snapshot_path).unwrap();
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o755)).unwrap();
        let challenge = sample_challenge(true);
        assert!(matches!(
            coordinator.record_challenge(&challenge),
            Err(PorCoordinatorError::Persistence(_))
        ));
        assert!(
            coordinator
                .query_statuses(&PorStatusFilter::default(), None, None)
                .is_empty()
        );
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o700)).unwrap();
        coordinator
            .record_challenge(&challenge)
            .expect("challenge succeeds after persistence recovery");
        let proof = sample_proof(&challenge);
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            coordinator.record_proof(&proof, &provider_key()),
            Err(PorCoordinatorError::Persistence(_))
        ));
        let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(status[0].proof_digest, None);
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o700)).unwrap();
        coordinator
            .record_proof(&proof, &provider_key())
            .expect("proof succeeds after persistence recovery");
        let digest = proof.proof_digest();
        let verdict = sample_verdict(&challenge, AuditOutcomeV1::Success, Some(digest));
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            coordinator.record_verdict(&verdict, &auditor_keys(), 1),
            Err(PorCoordinatorError::Persistence(_))
        ));
        let status = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(status[0].status, PorChallengeOutcome::ProofSubmitted);
        assert!(status[0].forced);
        assert_eq!(status[0].proof_digest, Some(digest));
        fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o700)).unwrap();
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("verdict succeeds after persistence recovery");
    }
    #[test]
    fn weekly_report_compiles() {
        let coordinator = PorCoordinator::new();
        let mut challenge = sample_challenge(true);
        challenge.issued_at = 1_700_000_000;
        challenge.deadline_at = challenge.issued_at + 600;
        coordinator.record_challenge(&challenge).expect("challenge");
        let verdict = sample_verdict(&challenge, AuditOutcomeV1::Failed, None);
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("verdict");
        let status = coordinator
            .query_statuses(&PorStatusFilter::default(), None, None)
            .pop()
            .expect("failed challenge status");
        assert_eq!(
            status.repair_task_id,
            Some(sorafs_repair_task_id_v1(por_repair_source_identity_v1(
                challenge.challenge_id
            )))
        );
        assert_eq!(status.responded_at, None);
        assert_eq!(status.proof_digest, None);
        assert_eq!(status.verifier_latency_ms, None);
        status.validate().expect("canonical failed status");
        let cycle = PorReportIsoWeek {
            year: 2023,
            week: 46,
        };
        let report = coordinator.weekly_report(cycle).expect("report");
        assert_eq!(report.challenges_total, 1);
        assert_eq!(report.challenges_failed, 1);
        assert_eq!(report.top_offenders.len(), 1);
        assert_eq!(
            report.generated_at,
            canonical_weekly_report_generated_at(cycle).expect("canonical report boundary")
        );
        assert_eq!(
            norito::to_bytes(&report).expect("encode report"),
            norito::to_bytes(&coordinator.weekly_report(cycle).expect("repeat report"))
                .expect("encode repeated report"),
            "identical coordinator history must produce identical report bytes"
        );
    }
    #[test]
    fn weekly_report_excludes_timestamps_outside_supported_time_domain() {
        let coordinator = PorCoordinator::new();
        let mut challenge = sample_challenge(true);
        challenge.issued_at = u64::MAX - 600;
        challenge.deadline_at = u64::MAX;
        coordinator.record_challenge(&challenge).expect("challenge");
        let report = coordinator
            .weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 46,
            })
            .expect("report");
        assert_eq!(report.challenges_total, 0);
        assert!(report.top_offenders.is_empty());
    }
    #[test]
    fn iso_week_bounds_rejects_unrepresentable_week_end() {
        assert!(matches!(
            iso_week_bounds(PorReportIsoWeek {
                year: 9999,
                week: 52,
            }),
            Err(PorCoordinatorError::IsoWeekComputation)
        ));
        iso_week_bounds(PorReportIsoWeek {
            year: 2026,
            week: 1,
        })
        .expect("a valid follow-up ISO week must still compute");
    }
    fn record_failed_forced_challenge(
        coordinator: &PorCoordinator,
        provider_byte: u8,
        manifest_byte: u8,
        issued_at: u64,
    ) {
        let mut challenge = sample_challenge(true);
        challenge.provider_id = [provider_byte; 32];
        challenge.manifest_digest = [manifest_byte; 32];
        challenge.issued_at = issued_at;
        challenge.deadline_at = issued_at + 600;
        challenge.seed = derive_challenge_seed(
            &challenge.drand_randomness,
            None,
            &challenge.manifest_digest,
            challenge.epoch_id,
        );
        challenge.challenge_id = derive_challenge_id(
            &challenge.seed,
            &challenge.manifest_digest,
            &challenge.provider_id,
            challenge.epoch_id,
            challenge.drand_round,
        );
        coordinator.record_challenge(&challenge).expect("challenge");
        let mut verdict = sample_verdict(&challenge, AuditOutcomeV1::Failed, None);
        verdict.decided_at = issued_at + 500;
        resign_verdict(&mut verdict);
        coordinator
            .record_verdict(&verdict, &auditor_keys(), 1)
            .expect("verdict");
    }
    #[test]
    fn weekly_report_is_byte_stable_across_insertion_orders_and_ties() {
        let entries = [(4_u8, 14_u8), (2, 12), (3, 13), (1, 11)];
        let first = PorCoordinator::new();
        let second = PorCoordinator::new();
        for (index, (provider, manifest)) in entries.iter().copied().enumerate() {
            record_failed_forced_challenge(
                &first,
                provider,
                manifest,
                1_700_000_000 + index as u64,
            );
        }
        for (index, (provider, manifest)) in entries.iter().copied().rev().enumerate() {
            record_failed_forced_challenge(
                &second,
                provider,
                manifest,
                1_700_000_003 - index as u64,
            );
        }
        let cycle = PorReportIsoWeek {
            year: 2023,
            week: 46,
        };
        let generated_at = 1_700_100_000;
        let first_report = first
            .weekly_report_at(cycle, generated_at)
            .expect("first report");
        let second_report = second
            .weekly_report_at(cycle, generated_at)
            .expect("second report");
        assert_eq!(first_report, second_report);
        assert_eq!(first_report.forced_challenges, 4);
        assert_eq!(
            first_report.providers_missing_vrf,
            vec![[1; 32], [2; 32], [3; 32], [4; 32]]
        );
        assert_eq!(
            first_report
                .top_offenders
                .iter()
                .map(|summary| summary.provider_id)
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32], [3; 32], [4; 32]]
        );
        assert!(
            first_report
                .top_offenders
                .iter()
                .all(|summary| summary.forced == 1),
            "forced scheduling must remain visible after a failed verdict"
        );
        assert_eq!(
            to_bytes(&first_report).expect("encode first report"),
            to_bytes(&second_report).expect("encode second report")
        );
    }
    #[test]
    fn weekly_report_projects_only_the_requested_week_from_large_history() {
        let coordinator = PorCoordinator::new();
        let record_at = |epoch_id: u64, issued_at: u64| {
            let mut challenge = sample_challenge(true);
            challenge.epoch_id = epoch_id;
            challenge.issued_at = issued_at;
            challenge.deadline_at = issued_at + 600;
            challenge.seed = derive_challenge_seed(
                &challenge.drand_randomness,
                None,
                &challenge.manifest_digest,
                challenge.epoch_id,
            );
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            coordinator.record_challenge(&challenge).expect("challenge");
        };
        for index in 0..2_048 {
            record_at(index + 1, 1_600_000_000 + index);
            record_at(10_000 + index, 1_800_000_000 + index);
        }
        for index in 0..3 {
            record_at(20_000 + index, 1_700_000_000 + index);
        }
        coordinator
            .weekly_report_projection_lookups
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let report = coordinator
            .weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 46,
            })
            .expect("weekly report");
        assert_eq!(report.challenges_total, 3);
        assert_eq!(coordinator.records.len(), 4_099);
        assert_eq!(
            coordinator
                .weekly_report_projection_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            3,
            "report work must be bounded by the canonical week slice, not total retention"
        );
    }
    #[test]
    fn persistence_round_trip_restores_state() {
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("por_snapshot.to");
        let expected_digest;
        {
            let coordinator =
                PorCoordinator::with_persistence(&snapshot_path).expect("coordinator");
            let challenge = sample_challenge(false);
            coordinator.record_challenge(&challenge).expect("challenge");
            let proof = sample_proof(&challenge);
            let proof_digest = proof.proof_digest();
            coordinator
                .record_proof(&proof, &provider_key())
                .expect("proof");
            let verdict = sample_verdict(&challenge, AuditOutcomeV1::Repaired, Some(proof_digest));
            coordinator
                .record_verdict(&verdict, &auditor_keys(), 1)
                .expect("verdict");
            expected_digest = proof_digest;
        }
        let coordinator =
            PorCoordinator::with_persistence(&snapshot_path).expect("reload coordinator");
        let statuses = coordinator.query_statuses(&PorStatusFilter::default(), None, None);
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.status, PorChallengeOutcome::Repaired);
        assert_eq!(status.proof_digest, Some(expected_digest));
        assert!(status.responded_at.is_some());
        assert_eq!(status.repair_task_id, None);
    }
    #[test]
    fn persisted_generation_rejects_pre_mutation_cursor_after_restart() {
        fn challenge_for(provider: u8, issued_at_offset: u64) -> PorChallengeV1 {
            let mut challenge = sample_challenge(false);
            challenge.provider_id = [provider; 32];
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.issued_at += issued_at_offset;
            challenge.deadline_at += issued_at_offset;
            challenge
        }
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("por_snapshot.to");
        let limits = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("page limits");
        let (cursor, issued_generation) = {
            let coordinator =
                PorCoordinator::with_persistence(&snapshot_path).expect("coordinator");
            for challenge in [challenge_for(0x61, 0), challenge_for(0x62, 1)] {
                coordinator
                    .record_challenge(&challenge)
                    .expect("record initial challenge");
            }
            let page = coordinator
                .query_status_page(
                    &PorStatusFilter::default(),
                    limits,
                    PorStatusPageCursor::First,
                )
                .expect("first page");
            let cursor = page
                .next_cursor
                .expect("two records produce a continuation cursor");
            coordinator
                .record_challenge(&challenge_for(0x63, 2))
                .expect("persist generation-advancing mutation");
            (cursor, page.snapshot_generation)
        };
        let coordinator =
            PorCoordinator::with_persistence(&snapshot_path).expect("reload coordinator");
        let error = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::from_opaque(Some(&cursor)).expect("decode old cursor"),
            )
            .expect_err("pre-mutation cursor must remain stale after restart");
        assert!(matches!(
            error,
            PorCoordinatorError::StalePageGeneration { expected, current }
                if expected == issued_generation && current > expected
        ));
    }
    #[test]
    fn persisted_generation_survives_same_cardinality_mutation_and_rollback() {
        fn challenge_for(provider: u8, issued_at_offset: u64) -> PorChallengeV1 {
            let mut challenge = sample_challenge(false);
            challenge.provider_id = [provider; 32];
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.issued_at += issued_at_offset;
            challenge.deadline_at += issued_at_offset;
            challenge
        }
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("por_snapshot.to");
        let limits = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("page limits");
        let (cursor, issued_generation) = {
            let coordinator =
                PorCoordinator::with_persistence(&snapshot_path).expect("coordinator");
            let first = challenge_for(0x71, 0);
            let second = challenge_for(0x72, 1);
            for challenge in [&first, &second] {
                coordinator
                    .record_challenge(challenge)
                    .expect("record initial challenge");
            }
            let page = coordinator
                .query_status_page(
                    &PorStatusFilter::default(),
                    limits,
                    PorStatusPageCursor::First,
                )
                .expect("first page");
            let cursor = page
                .next_cursor
                .expect("two records produce a continuation cursor");
            let proof = sample_proof(&second);
            coordinator
                .record_proof(&proof, &provider_key())
                .expect("persist same-cardinality proof mutation");
            coordinator
                .rollback_proof(&proof)
                .expect("persist same-cardinality compensating rollback");
            assert_eq!(
                coordinator.status_indexes.read().generation,
                page.snapshot_generation + 2
            );
            (cursor, page.snapshot_generation)
        };
        let coordinator =
            PorCoordinator::with_persistence(&snapshot_path).expect("reload coordinator");
        let restored_generation = coordinator.status_indexes.read().generation;
        assert_eq!(restored_generation, issued_generation + 2);
        let error = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::from_opaque(Some(&cursor)).expect("decode old cursor"),
            )
            .expect_err("a compensated mutation must not revive its old cursor after restart");
        assert!(matches!(
            error,
            PorCoordinatorError::StalePageGeneration { expected, current }
                if expected == issued_generation && current == restored_generation
        ));
    }
    #[test]
    fn post_publication_failure_retains_state_and_fail_stops_until_restart() {
        fn challenge_for(provider: u8, issued_at_offset: u64) -> PorChallengeV1 {
            let mut challenge = sample_challenge(false);
            challenge.provider_id = [provider; 32];
            challenge.challenge_id = derive_challenge_id(
                &challenge.seed,
                &challenge.manifest_digest,
                &challenge.provider_id,
                challenge.epoch_id,
                challenge.drand_round,
            );
            challenge.issued_at += issued_at_offset;
            challenge.deadline_at += issued_at_offset;
            challenge
        }
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("por_snapshot.to");
        let limits = PorStatusPageLimits::new(1, POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1)
            .expect("page limits");
        let coordinator = PorCoordinator::with_persistence(&snapshot_path).expect("coordinator");
        let first = challenge_for(0x81, 0);
        let second = challenge_for(0x82, 1);
        for challenge in [&first, &second] {
            coordinator
                .record_challenge(challenge)
                .expect("record initial challenge");
        }
        let page = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::First,
            )
            .expect("first page");
        let cursor = page
            .next_cursor
            .expect("two records produce a continuation cursor");
        let issued_generation = page.snapshot_generation;
        let proof = sample_proof(&second);
        coordinator.inject_persistence_commit_uncertain_once();
        let error = coordinator
            .record_proof(&proof, &provider_key())
            .expect_err("injected post-publication failure must surface");
        assert!(matches!(
            &error,
            PorCoordinatorError::Persistence(PorPersistenceError::CommitUncertain(_))
        ));
        assert!(
            error.to_string().contains("may already be durable"),
            "the first failure must explicitly disclose uncertain commit state"
        );
        assert_eq!(
            coordinator
                .records
                .get(&second.challenge_id)
                .expect("committed proof remains in memory")
                .proof_digest,
            Some(proof.proof_digest())
        );
        assert_eq!(
            coordinator.status_indexes.read().generation,
            issued_generation + 1
        );
        coordinator
            .status_indexes
            .read()
            .validate_against_records(&coordinator.records)
            .expect("retained memory and indexes remain consistent");
        assert!(matches!(
            coordinator.query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::First,
            ),
            Err(PorCoordinatorError::PersistenceFaultLatched { .. })
        ));
        let third = challenge_for(0x83, 2);
        assert!(matches!(
            coordinator.record_challenge(&third),
            Err(PorCoordinatorError::PersistenceFaultLatched { .. })
        ));
        assert!(!coordinator.records.contains_key(&third.challenge_id));
        drop(coordinator);
        let coordinator =
            PorCoordinator::with_persistence(&snapshot_path).expect("reload coordinator");
        assert_eq!(
            coordinator.status_indexes.read().generation,
            issued_generation + 1
        );
        assert_eq!(
            coordinator
                .records
                .get(&second.challenge_id)
                .expect("published proof reloads")
                .proof_digest,
            Some(proof.proof_digest())
        );
        assert!(!coordinator.records.contains_key(&third.challenge_id));
        let error = coordinator
            .query_status_page(
                &PorStatusFilter::default(),
                limits,
                PorStatusPageCursor::from_opaque(Some(&cursor)).expect("decode old cursor"),
            )
            .expect_err("pre-mutation cursor must not revive after reconciliation");
        assert!(matches!(
            error,
            PorCoordinatorError::StalePageGeneration { expected, current }
                if expected == issued_generation && current == issued_generation + 1
        ));
    }
    #[test]
    fn persistence_rejects_zero_or_missing_status_generation() {
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_torii::sorafs::por::tests::persistence_rejects_zero_or_missing_status_generation::SnapshotWithoutStatusGeneration"
        )]
        #[derive(NoritoSerialize)]
        struct SnapshotWithoutStatusGeneration {
            version: u8,
            records: Vec<ChallengeRecordSnapshot>,
            forced: Vec<ForcedProviderSnapshot>,
            prepared_weekly_report: Option<PreparedWeeklyReportV1>,
        }
        let dir = tempdir().expect("temp dir");
        let root = canonical_temp_root(&dir);
        let current_path = root.join("current-generation.to");
        let current = PorCoordinatorSnapshot {
            version: POR_COORDINATOR_SNAPSHOT_VERSION_V1,
            status_generation: 1,
            records: Vec::new(),
            forced: Vec::new(),
            prepared_weekly_report: None,
        };
        let expected = crate::frame_test_support::assert_current_frame(
            &current,
            "iroha_torii::sorafs::por::PorCoordinatorSnapshot",
        );
        let (current_payload, flags) = {
            let _guard =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::codec::encode_with_header_flags(&current)
        };
        let current_bytes = norito::core::frame_bare_with_header_flags::<PorCoordinatorSnapshot>(
            &current_payload,
            flags,
        )
        .expect("frame current payload under its real owner");
        assert_eq!(current_bytes, expected);
        secure_atomic_write(
            &current_path,
            &current_bytes,
            MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
            true,
        )
        .expect("write valid current snapshot control");
        drop(
            PorCoordinator::with_persistence(&current_path)
                .expect("current shape reopens through production persistence"),
        );
        let zero_path = root.join("zero-generation.to");
        let zero_snapshot = PorCoordinatorSnapshot {
            version: POR_COORDINATOR_SNAPSHOT_VERSION_V1,
            status_generation: 0,
            records: Vec::new(),
            forced: Vec::new(),
            prepared_weekly_report: None,
        };
        let zero_bytes = to_bytes(&zero_snapshot).expect("encode zero-generation snapshot");
        secure_atomic_write(
            &zero_path,
            &zero_bytes,
            MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
            true,
        )
        .expect("write zero-generation snapshot");
        assert!(matches!(
            PorCoordinator::with_persistence(&zero_path),
            Err(PorPersistenceError::Decode(message))
                if message.contains("status generation must be non-zero")
        ));
        let missing_path = root.join("missing-generation.to");
        let missing = SnapshotWithoutStatusGeneration {
            version: POR_COORDINATOR_SNAPSHOT_VERSION_V1,
            records: Vec::new(),
            forced: Vec::new(),
            prepared_weekly_report: None,
        };
        let (missing_payload, missing_flags) = {
            let _guard =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::codec::encode_with_header_flags(&missing)
        };
        let missing_bytes = norito::core::frame_bare_with_header_flags::<PorCoordinatorSnapshot>(
            &missing_payload,
            missing_flags,
        )
        .expect("frame unsupported payload under current snapshot owner");
        let view =
            norito::core::from_bytes_view(&missing_bytes).expect("well-formed hostile envelope");
        assert_eq!(
            view.schema(),
            norito::schema::identity::frame_hash::<PorCoordinatorSnapshot>()
        );
        assert_eq!(view.as_bytes(), missing_payload.as_slice());
        let error = norito::decode_canonical::<PorCoordinatorSnapshot>(&missing_bytes)
            .expect_err("missing generation reaches actual snapshot payload decoder");
        assert!(!matches!(error, norito::Error::SchemaMismatch));
        secure_atomic_write(
            &missing_path,
            &missing_bytes,
            MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
            true,
        )
        .expect("write snapshot without generation");
        assert!(matches!(
            PorCoordinator::with_persistence(&missing_path),
            Err(PorPersistenceError::Decode(_))
        ));
    }
    #[test]
    fn persistence_rejects_status_generation_below_record_floor() {
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("generation-below-record-floor.to");
        let record = ChallengeRecord::from_challenge(sample_challenge(false));
        let snapshot = PorCoordinatorSnapshot {
            version: POR_COORDINATOR_SNAPSHOT_VERSION_V1,
            status_generation: 1,
            records: vec![ChallengeRecordSnapshot::from(&record)],
            forced: Vec::new(),
            prepared_weekly_report: None,
        };
        let bytes = to_bytes(&snapshot).expect("encode malformed-generation snapshot");
        secure_atomic_write(
            &snapshot_path,
            &bytes,
            MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
            true,
        )
        .expect("write malformed-generation snapshot");
        assert!(matches!(
            PorCoordinator::with_persistence(&snapshot_path),
            Err(PorPersistenceError::Decode(message))
                if message.contains("below the record floor")
        ));
    }
    #[test]
    fn status_generation_exhaustion_fails_before_mutation() {
        let coordinator = PorCoordinator::new();
        coordinator.status_indexes.write().generation = u64::MAX;
        let challenge = sample_challenge(false);
        assert!(matches!(
            coordinator.record_challenge(&challenge),
            Err(PorCoordinatorError::StatusGenerationExhausted)
        ));
        assert!(coordinator.records.is_empty());
        assert_eq!(coordinator.status_indexes.read().generation, u64::MAX);
    }
    #[test]
    fn prepared_weekly_report_survives_restart_and_history_changes() {
        let dir = tempdir().expect("temp dir");
        let snapshot_path = canonical_temp_root(&dir).join("por_snapshot.to");
        let cycle = PorReportIsoWeek {
            year: 2023,
            week: 46,
        };
        let prepared = {
            let coordinator =
                PorCoordinator::with_persistence(&snapshot_path).expect("coordinator");
            record_failed_forced_challenge(&coordinator, 1, 11, 1_700_000_000);
            let prepared = coordinator
                .prepare_weekly_report(cycle)
                .expect("prepare report");
            assert_eq!(prepared.report.challenges_total, 1);
            assert!(!prepared.published);
            record_failed_forced_challenge(&coordinator, 2, 12, 1_700_000_100);
            assert_eq!(
                coordinator
                    .weekly_report(cycle)
                    .expect("retained report")
                    .challenges_total,
                1
            );
            assert_eq!(
                coordinator
                    .weekly_report_at(
                        cycle,
                        canonical_weekly_report_generated_at(cycle)
                            .expect("canonical report boundary"),
                    )
                    .expect("recomputed report")
                    .challenges_total,
                2
            );
            prepared
        };
        let coordinator =
            PorCoordinator::with_persistence(&snapshot_path).expect("reload coordinator");
        let replay = coordinator
            .prepare_weekly_report(cycle)
            .expect("retry prepared report");
        assert_eq!(replay, prepared);
        assert_eq!(
            norito::to_bytes(&replay.report).expect("encode replay"),
            norito::to_bytes(&prepared.report).expect("encode prepared")
        );
        assert!(matches!(
            coordinator.prepare_weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 45,
            }),
            Err(PorCoordinatorError::WeeklyReportCycleRollback { .. })
        ));
        assert!(matches!(
            coordinator.prepare_weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 0,
            }),
            Err(PorCoordinatorError::InvalidIsoWeek(_))
        ));
        assert!(matches!(
            coordinator.prepare_weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 48,
            }),
            Err(PorCoordinatorError::WeeklyReportPublicationPending { .. })
        ));
        let mut substituted = replay.report.clone();
        substituted.generated_at = substituted.generated_at.saturating_add(1);
        assert!(matches!(
            coordinator.mark_weekly_report_published(&substituted),
            Err(PorCoordinatorError::WeeklyReportPreparationConflict { .. })
        ));
        coordinator
            .mark_weekly_report_published(&replay.report)
            .expect("persist publication acknowledgement");
        let catch_up = coordinator
            .prepare_weekly_report(PorReportIsoWeek {
                year: 2023,
                week: 48,
            })
            .expect("prepare first missing cycle");
        assert_eq!(
            catch_up.report.cycle,
            PorReportIsoWeek {
                year: 2023,
                week: 47,
            }
        );
        assert!(!catch_up.published);
    }
    #[cfg(feature = "app_api")]
    mod runtime {
        use super::*;
        use crate::sorafs::por::{RandomnessProvider, VrfProvider};
        use std::{collections::HashMap, sync::Arc};
        #[derive(Clone)]
        struct StaticRandomnessProvider {
            randomness: PorRandomness,
        }
        #[async_trait]
        impl RandomnessProvider for StaticRandomnessProvider {
            async fn randomness_for_epoch(
                &self,
                _epoch_id: u64,
                _now_secs: u64,
                _response_window_secs: u64,
            ) -> Result<PorRandomness, RandomnessError> {
                Ok(self.randomness)
            }
        }
        #[derive(Default, Clone)]
        struct StaticVrfProvider {
            map: HashMap<u64, HashMap<ManifestVrfKey, ManifestVrfBundle>>,
        }
        impl VrfProvider for StaticVrfProvider {
            fn vrf_bundles_for_epoch(
                &self,
                randomness: &PorRandomness,
            ) -> Result<HashMap<ManifestVrfKey, ManifestVrfBundle>, VrfError> {
                Ok(self
                    .map
                    .get(&randomness.epoch_id)
                    .cloned()
                    .unwrap_or_default())
            }
        }
        #[derive(Clone)]
        struct ReplaySafeStorage {
            planned: Vec<PlannedChallenge>,
            recorded: Arc<Mutex<Option<PorChallengeV1>>>,
        }
        impl PorStorage for ReplaySafeStorage {
            fn plan_challenges(
                &self,
                _randomness: PorRandomness,
                _vrf_records: &HashMap<ManifestVrfKey, ManifestVrfBundle>,
                _allow_forced: bool,
            ) -> Result<Vec<PlannedChallenge>, PorChallengePlannerError> {
                Ok(self.planned.clone())
            }
            fn record_challenge(
                &self,
                challenge: &PorChallengeV1,
            ) -> Result<PorStatusAuthorityUpdateV1, PorMutationFailureV1> {
                let mut recorded = self.recorded.lock();
                match recorded.as_ref() {
                    Some(existing) if existing == challenge => Ok(PorStatusAuthorityUpdateV1 {
                        generation: 2,
                        status: ChallengeRecord::from_challenge(challenge.clone()).to_status(),
                        removed_challenge_ids: Vec::new(),
                    }),
                    Some(_) => Err(PorMutationFailureV1::no_mutation(
                        sorafs_node::PorTrackerError::ChallengeConflict,
                    )),
                    None => {
                        *recorded = Some(challenge.clone());
                        Ok(PorStatusAuthorityUpdateV1 {
                            generation: 2,
                            status: ChallengeRecord::from_challenge(challenge.clone()).to_status(),
                            removed_challenge_ids: Vec::new(),
                        })
                    }
                }
            }
            fn vrf_target_is_active(
                &self,
                _provider_id: [u8; 32],
                _manifest_digest: [u8; 32],
                _now_secs: u64,
            ) -> bool {
                true
            }
        }
        struct NotReadyPublisher;
        impl PorGovernancePublisher for NotReadyPublisher {
            fn is_ready(&self) -> bool {
                false
            }
            fn publish_challenge(
                &self,
                _publication: PorChallengePublicationV1,
            ) -> Result<(), sorafs_node::GovernancePublishError> {
                unreachable!("constructor rejects a publisher that is not ready")
            }
            fn publish_weekly_report(
                &self,
                _report: PorWeeklyReportV1,
            ) -> Result<(), sorafs_node::GovernancePublishError> {
                unreachable!("constructor rejects a publisher that is not ready")
            }
        }
        #[test]
        #[should_panic(
            expected = "enabled PoR runtime requires the embedded SoraFS node's signed Governance DAG publisher"
        )]
        fn runtime_rejects_missing_signed_governance_publisher() {
            let challenge = sample_challenge(true);
            let storage = Arc::new(ReplaySafeStorage {
                planned: Vec::new(),
                recorded: Arc::new(Mutex::new(None)),
            });
            let randomness = PorRandomness {
                epoch_id: challenge.epoch_id,
                issued_at_unix: challenge.issued_at,
                response_window_secs: challenge.deadline_at - challenge.issued_at,
                drand_round: challenge.drand_round,
                drand_randomness: challenge.drand_randomness,
                drand_signature: challenge.drand_signature,
            };
            let _runtime = PorCoordinatorRuntime::new_with_publisher(
                storage,
                Arc::new(PorCoordinator::new()),
                Arc::new(StaticRandomnessProvider { randomness }),
                Arc::new(StaticVrfProvider::default()),
                Arc::new(NotReadyPublisher),
                3_600,
                900,
                300,
            );
        }
        #[test]
        fn scheduler_reports_only_the_previous_completed_iso_week() {
            let current_cycle = PorReportIsoWeek {
                year: 2025,
                week: 12,
            };
            let (current_start, _) =
                iso_week_bounds(current_cycle).expect("current ISO week bounds");
            let now_secs =
                u64::try_from(current_start.unix_timestamp()).expect("positive timestamp") + 60;
            let (completed, marker) = PorCoordinatorRuntime::compute_completed_iso_marker(now_secs)
                .expect("completed cycle");
            assert_eq!(
                completed,
                PorReportIsoWeek {
                    year: 2025,
                    week: 11,
                }
            );
            assert_eq!(marker, iso_week_marker(completed));
            assert_eq!(
                canonical_weekly_report_generated_at(completed)
                    .expect("canonical completed-cycle timestamp"),
                u64::try_from(current_start.unix_timestamp()).expect("positive timestamp")
            );
        }
        include!("por/runtime_retry_tests.rs");
    }
}
