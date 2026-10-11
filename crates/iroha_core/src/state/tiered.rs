//! Tiered storage backend for the World State View (WSV).
//!
//! The backend promotes frequently updated keys to a hot in-memory tier while demoting colder
//! entries to an on-disk spill. Each snapshot computes recency-based priorities, writes cold
//! payloads using the canonical Norito encoding, and emits a manifest so hosts can hydrate cold
//! shards lazily. Snapshots can be built incrementally from per-block diffs to avoid full WSV
//! scans, and heavy snapshot work can be offloaded after commit to reduce block latency.
#[cfg(test)]
use super::World;
use super::block_field::StorageField;
use crate::telemetry::StateTelemetry;
use eyre::{Context, Result};
use hex::ToHex as _;
use iroha_config::parameters::actual::{LaneConfig, LaneConfigEntry};
use iroha_model_base::state_path::StatePath;
use mv::{Key, Value, storage::StorageReadOnly};
use norito::{
    derive::{JsonDeserialize, JsonSerialize},
    json,
};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::io::ErrorKind;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
mod geometry_attempt;
pub(crate) use geometry_attempt::TieredGeometryAttempt;

const WSV_COLD_COMPONENT: &str = "wsv_cold";
#[cfg(test)]
const DA_CACHE_HIT: &str = "hit";
#[cfg(test)]
const DA_CACHE_MISS: &str = "miss";
const DA_CHURN_EVICTED: &str = "evicted";
#[cfg(test)]
const DA_CHURN_REHYDRATED: &str = "rehydrated";
/// Lightweight handle describing a hot/cold storage split.
#[derive(Debug, Clone, Default)]
pub struct TieredStateBackend {
    /// Enable tiering; when false snapshots are skipped regardless of other knobs.
    enabled: bool,
    /// Maximum number of keys to keep hot (0 = unlimited).
    hot_retained_keys: usize,
    /// Hot-tier byte budget using canonical encoded-key bytes plus measured value bytes.
    hot_retained_bytes: u64,
    /// Minimum snapshots to retain newly hot entries before demotion (0 = disabled).
    hot_retained_grace_snapshots: u64,
    /// Optional on-disk spill root for cold shards.
    cold_store_root: Option<PathBuf>,
    /// Optional on-disk spill root for DA-backed cold shards.
    da_store_root: Option<PathBuf>,
    /// Number of snapshot directories to retain (0 = keep all).
    max_snapshots: usize,
    /// Optional cold-tier byte budget across snapshots (0 = unlimited).
    max_cold_bytes: u64,
    /// Monotonically increasing snapshot counter.
    snapshot_counter: u64,
    /// Whether the snapshot counter has been seeded from disk.
    snapshot_counter_seeded: bool,
    /// A complete retained baseline has been published, including an empty one.
    snapshot_baseline_ready: bool,
    /// Per-entry metadata tracking heat and payload hashes.
    entries: BTreeMap<TieredEntryId, EntryMetadata>,
    /// Stable key metadata required to rebuild snapshot manifests incrementally.
    entry_keys: BTreeMap<TieredEntryId, EntryKey>,
    /// Cached manifest of the latest snapshot for diagnostics.
    last_manifest: Option<TieredSnapshotManifest>,
    /// Optional telemetry sink for DA-backed cold storage activity.
    telemetry: Option<StateTelemetry>,
}
#[derive(Debug)]
struct ColdEntryPlan {
    rel_path: PathBuf,
    entry: EntryScore,
    manifest_index: usize,
    reuse_source: Option<PathBuf>,
}
#[derive(Debug)]
struct TieredSnapshotPlan {
    root: PathBuf,
    snapshot_dir: PathBuf,
    manifest: TieredSnapshotManifest,
    cold_entries: Vec<ColdEntryPlan>,
}
#[derive(Default)]
struct SnapshotPayloadCache {
    payloads: BTreeMap<TieredEntryId, Vec<u8>>,
}
/// Changed WSV keys captured during a block for incremental snapshotting.
#[derive(Debug, Default, Clone)]
#[cfg(test)]
pub(crate) struct TieredSnapshotDiff {
    entries: Vec<TieredKeyHandle>,
}
#[cfg(test)]
impl TieredSnapshotDiff {
    /// Record a touched entry.
    pub(crate) fn push(&mut self, entry: TieredKeyHandle) {
        self.entries.push(entry);
    }
    /// Read the captured entries.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[TieredKeyHandle] {
        &self.entries
    }
}
/// Changed WSV keys captured with their updated payloads for background snapshots.
#[derive(Default)]
pub(crate) struct TieredSnapshotPayload {
    entries: Vec<TieredSnapshotPayloadEntry>,
    complete: bool,
}
struct TieredSnapshotPayloadEntry {
    key: TieredKeyHandle,
    value: Option<Box<dyn TieredSnapshotValue>>,
}
impl TieredSnapshotPayload {
    pub(crate) fn with_scope(complete: bool) -> Self {
        Self {
            entries: Vec::new(),
            complete,
        }
    }
    /// Retain one store's exact original values, including incremental deletions,
    /// through its execution or frozen publication read authority.
    ///
    /// Keep heterogeneous iterators and cloned values in a per-store frame. An
    /// expanded loop for every World field reserves their combined stack space
    /// in debug builds, even when those stores are empty.
    #[inline(never)]
    pub(super) fn collect_storage<K, V, M>(
        &mut self,
        storage: &StorageField<'_, K, V, M>,
        key_handle: impl Fn(K) -> TieredKeyHandle,
    ) where
        K: Key,
        V: Value + json::JsonSerialize + MeasuredBytes,
        M: mv::storage::StorageMode<K, V>,
    {
        if self.complete {
            for (key, value) in storage.iter() {
                self.push_value(key_handle(key.clone()), Some(value.clone()));
            }
        } else {
            for entry in storage.touched_entries() {
                self.push_value(key_handle(entry.key.clone()), entry.after.cloned());
            }
        }
    }
    pub(crate) fn push_value<T>(&mut self, key: TieredKeyHandle, value: Option<T>)
    where
        T: json::JsonSerialize + MeasuredBytes + Send + Sync + 'static,
    {
        let value = value.map(|value| {
            let boxed: Box<dyn TieredSnapshotValue> = Box::new(value);
            boxed
        });
        self.entries.push(TieredSnapshotPayloadEntry { key, value });
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
#[cfg(test)]
impl From<&TieredSnapshotPayload> for TieredSnapshotDiff {
    fn from(payload: &TieredSnapshotPayload) -> Self {
        let mut diff = TieredSnapshotDiff::default();
        for entry in &payload.entries {
            diff.push(entry.key.clone());
        }
        diff
    }
}
trait TieredSnapshotValue: Send + Sync {
    fn measured_bytes(&self) -> usize;
    fn encode_json(&self) -> Result<Vec<u8>>;
}
impl<T> TieredSnapshotValue for T
where
    T: json::JsonSerialize + MeasuredBytes + Send + Sync + 'static,
{
    fn measured_bytes(&self) -> usize {
        MeasuredBytes::measured_bytes(self)
    }
    fn encode_json(&self) -> Result<Vec<u8>> {
        json::to_vec(self).wrap_err("failed to encode snapshot value as JSON")
    }
}
#[cfg(test)]
struct CollectContext<'a> {
    snapshot_idx: u64,
    scores: &'a mut Vec<EntryScore>,
    seen: &'a mut BTreeSet<TieredEntryId>,
}
impl TieredStateBackend {
    /// Construct a backend with explicit limits.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn new(
        enabled: bool,
        hot_retained_keys: usize,
        hot_retained_bytes: u64,
        hot_retained_grace_snapshots: u64,
        cold_store_root: Option<PathBuf>,
        da_store_root: Option<PathBuf>,
        max_snapshots: usize,
        max_cold_bytes: u64,
    ) -> Self {
        let mut backend = Self {
            enabled,
            hot_retained_keys,
            hot_retained_bytes,
            hot_retained_grace_snapshots,
            cold_store_root,
            da_store_root,
            max_snapshots,
            max_cold_bytes,
            snapshot_counter: 0,
            snapshot_counter_seeded: false,
            snapshot_baseline_ready: false,
            entries: BTreeMap::new(),
            entry_keys: BTreeMap::new(),
            last_manifest: None,
            telemetry: None,
        };
        if backend.enabled {
            backend.ensure_cold_roots().ok();
            let _ = backend.seed_snapshot_counter_if_needed();
        }
        backend
    }
    /// Attach a telemetry sink for DA-backed cold storage activity.
    #[cfg(any(test, feature = "telemetry"))]
    pub fn attach_telemetry(&mut self, telemetry: StateTelemetry) {
        self.telemetry = Some(telemetry);
    }
    /// Build the full-World reference snapshot used to check retained-payload snapshots.
    #[cfg(test)]
    pub fn record_world_snapshot(&mut self, world: &World) -> Result<()> {
        if let Some(plan) = self.plan_world_snapshot(world)? {
            self.execute_snapshot_plan(plan, world)?;
            self.snapshot_baseline_ready = true;
        }
        Ok(())
    }
    /// Record a snapshot using a diff of touched entries.
    #[cfg(test)]
    pub(crate) fn record_world_snapshot_with_diff(
        &mut self,
        world: &World,
        diff: &TieredSnapshotDiff,
    ) -> Result<()> {
        if !self.snapshot_baseline_ready {
            return self.record_world_snapshot(world);
        }
        if let Some(plan) = self.plan_world_snapshot_with_diff(world, diff)? {
            self.execute_snapshot_plan(plan, world)?;
        }
        Ok(())
    }
    /// Record a snapshot using a diff payload without accessing the live world.
    pub(crate) fn record_world_snapshot_with_payload(
        &mut self,
        payload: &TieredSnapshotPayload,
    ) -> Result<()> {
        if !payload.complete && !self.snapshot_baseline_ready {
            eyre::bail!("incremental tiered payload has no complete snapshot baseline");
        }
        let Some((root, snapshot_idx, snapshot_dir)) = self.prepare_snapshot()? else {
            return Ok(());
        };
        if payload.complete && !self.snapshot_baseline_ready {
            // An initial or failed baseline has no reusable payload authority.
            self.entries.clear();
            self.entry_keys.clear();
        }
        // Any error below requires another complete retained baseline. A later
        // incremental payload cannot silently continue from partial metadata.
        self.snapshot_baseline_ready = false;
        let payload_cache = if payload.is_empty() {
            SnapshotPayloadCache::default()
        } else {
            self.apply_snapshot_payload(snapshot_idx, payload)?
        };
        if payload.complete {
            self.entries
                .retain(|id, _| payload_cache.payloads.contains_key(id));
            self.entry_keys
                .retain(|id, _| payload_cache.payloads.contains_key(id));
        }
        let scores = self.build_scores_from_keys(snapshot_idx);
        let plan = self.build_snapshot_plan(
            root,
            snapshot_idx,
            snapshot_dir,
            scores,
            Some(&payload_cache.payloads),
        )?;
        self.execute_snapshot_plan_with_payload(plan, &payload_cache.payloads)?;
        self.snapshot_baseline_ready = true;
        Ok(())
    }
    fn seed_snapshot_counter_if_needed(&mut self) -> Result<()> {
        if self.snapshot_counter_seeded {
            return Ok(());
        }
        let roots = self.cold_roots();
        if roots.is_empty() {
            self.snapshot_counter_seeded = true;
            return Ok(());
        }
        self.ensure_cold_roots()
            .wrap_err("failed to prepare cold tier root directory")?;
        for root in &roots {
            if root.exists() {
                self.recover_snapshot_artifacts(root)?;
            }
        }
        let mut max_idx = 0u64;
        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in fs::read_dir(root).wrap_err_with(|| {
                format!(
                    "failed to read cold tier root {path}",
                    path = root.display()
                )
            })? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if !file_type.is_dir() {
                    continue;
                }
                if let Some(idx) = Self::parse_snapshot_dir_name(&entry.file_name()) {
                    max_idx = max_idx.max(idx);
                }
            }
        }
        self.snapshot_counter = max_idx;
        self.snapshot_counter_seeded = true;
        Ok(())
    }
    #[allow(clippy::unused_self)]
    #[allow(clippy::too_many_lines)]
    fn recover_snapshot_artifacts(&self, root: &Path) -> Result<()> {
        #[derive(Default)]
        struct SnapshotArtifacts {
            live: Option<PathBuf>,
            backup: Option<PathBuf>,
            staging: Option<PathBuf>,
        }
        let mut artifacts: BTreeMap<u64, SnapshotArtifacts> = BTreeMap::new();
        for entry in fs::read_dir(root).wrap_err_with(|| {
            format!(
                "failed to read cold tier root {path}",
                path = root.display()
            )
        })? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            if let Some(idx) = Self::parse_snapshot_dir_name(&name) {
                artifacts.entry(idx).or_default().live = Some(path);
                continue;
            }
            let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if ext != "bak" && ext != "staging" {
                continue;
            }
            let Some(stem) = path.file_stem() else {
                continue;
            };
            let Some(idx) = Self::parse_snapshot_dir_name(stem) else {
                continue;
            };
            let entry = artifacts.entry(idx).or_default();
            if ext == "bak" {
                entry.backup = Some(path);
            } else {
                entry.staging = Some(path);
            }
        }
        let mut touched = false;
        for (idx, entry) in artifacts {
            let live_path = root.join(format!("{idx:020}"));
            if entry.live.is_some() {
                if let Some(backup) = entry.backup {
                    if let Err(err) = fs::remove_dir_all(&backup) {
                        iroha_logger::warn!(
                            ?err,
                            path = %backup.display(),
                            "tiered-state: failed to remove stale snapshot backup"
                        );
                    } else {
                        touched = true;
                    }
                }
                if let Some(staging) = entry.staging {
                    if let Err(err) = fs::remove_dir_all(&staging) {
                        iroha_logger::warn!(
                            ?err,
                            path = %staging.display(),
                            "tiered-state: failed to remove stale snapshot staging directory"
                        );
                    } else {
                        touched = true;
                    }
                }
                continue;
            }
            if let Some(backup) = entry.backup {
                match fs::rename(&backup, &live_path) {
                    Ok(()) => {
                        iroha_logger::info!(
                            from = %backup.display(),
                            to = %live_path.display(),
                            "tiered-state: restored snapshot backup"
                        );
                        touched = true;
                    }
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            from = %backup.display(),
                            to = %live_path.display(),
                            "tiered-state: failed to restore snapshot backup"
                        );
                    }
                }
            }
            if let Some(staging) = entry.staging {
                if let Err(err) = fs::remove_dir_all(&staging) {
                    iroha_logger::warn!(
                        ?err,
                        path = %staging.display(),
                        "tiered-state: failed to remove stale snapshot staging directory"
                    );
                } else {
                    touched = true;
                }
            }
        }
        if touched {
            if let Err(err) = Self::sync_dir(root) {
                iroha_logger::warn!(
                    ?err,
                    path = %root.display(),
                    "tiered-state: failed to sync snapshot root after recovery"
                );
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn plan_world_snapshot(&mut self, world: &World) -> Result<Option<TieredSnapshotPlan>> {
        let Some((root, snapshot_idx, snapshot_dir)) = self.prepare_snapshot()? else {
            return Ok(None);
        };
        let mut scores = Vec::new();
        let mut seen = BTreeSet::new();
        self.collect_world_entries(world, snapshot_idx, &mut scores, &mut seen)?;
        self.entries.retain(|id, _| seen.contains(id));
        self.entry_keys.retain(|id, _| seen.contains(id));
        let plan = self.build_snapshot_plan(root, snapshot_idx, snapshot_dir, scores, None)?;
        Ok(Some(plan))
    }
    #[cfg(test)]
    fn plan_world_snapshot_with_diff(
        &mut self,
        world: &World,
        diff: &TieredSnapshotDiff,
    ) -> Result<Option<TieredSnapshotPlan>> {
        let Some((root, snapshot_idx, snapshot_dir)) = self.prepare_snapshot()? else {
            return Ok(None);
        };
        if !diff.entries.is_empty() {
            self.apply_snapshot_diff(world, snapshot_idx, diff)?;
        }
        let scores = self.build_scores_from_keys(snapshot_idx);
        let plan = self.build_snapshot_plan(root, snapshot_idx, snapshot_dir, scores, None)?;
        Ok(Some(plan))
    }
    fn prepare_snapshot(&mut self) -> Result<Option<(PathBuf, u64, PathBuf)>> {
        if !self.enabled {
            return Ok(None);
        }
        if self.hot_retained_keys == 0
            && self.hot_retained_bytes == 0
            && self.primary_cold_root().is_none()
        {
            return Ok(None);
        }
        let Some(root) = self.primary_cold_root().cloned() else {
            if self.hot_retained_keys > 0 || self.hot_retained_bytes > 0 {
                iroha_logger::warn!(
                    "tiered-state: hot tier limit set but cold_store_root/da_store_root missing; skipping snapshot"
                );
            }
            return Ok(None);
        };
        self.seed_snapshot_counter_if_needed()?;
        self.snapshot_counter = self.snapshot_counter.saturating_add(1);
        let snapshot_idx = self.snapshot_counter;
        let snapshot_dir = root.join(format!("{snapshot_idx:020}"));
        Ok(Some((root, snapshot_idx, snapshot_dir)))
    }
    fn build_scores_from_keys(&mut self, snapshot_idx: u64) -> Vec<EntryScore> {
        let mut scores = Vec::with_capacity(self.entry_keys.len());
        for (id, entry_key) in &self.entry_keys {
            let meta = self.entries.get_mut(id).expect("metadata populated");
            meta.last_present_snapshot = snapshot_idx;
            scores.push(entry_key.score(*id));
        }
        scores
    }
    #[allow(clippy::too_many_lines)]
    fn build_snapshot_plan(
        &mut self,
        root: PathBuf,
        snapshot_idx: u64,
        snapshot_dir: PathBuf,
        mut scores: Vec<EntryScore>,
        payloads: Option<&BTreeMap<TieredEntryId, Vec<u8>>>,
    ) -> Result<TieredSnapshotPlan> {
        if scores.is_empty() {
            let manifest = TieredSnapshotManifest {
                snapshot_index: snapshot_idx,
                total_entries: 0,
                hot_entries: Vec::new(),
                cold_entries: Vec::new(),
                cold_bytes_total: 0,
                cold_reused_entries: 0,
                cold_reused_bytes: 0,
                hot_promotions: 0,
                hot_demotions: 0,
                hot_budget_overflow_keys: 0,
                hot_budget_overflow_bytes: 0,
            };
            return Ok(TieredSnapshotPlan {
                root,
                snapshot_dir,
                manifest,
                cold_entries: Vec::new(),
            });
        }
        scores.sort_by(|a, b| {
            let meta_a = self.entries.get(&a.id).expect("metadata populated");
            let meta_b = self.entries.get(&b.id).expect("metadata populated");
            meta_b.cmp(meta_a).then_with(|| a.id.cmp(&b.id))
        });
        let max_keys = if self.hot_retained_keys == 0 {
            usize::MAX
        } else {
            self.hot_retained_keys
        };
        let max_bytes = self.hot_retained_bytes;
        #[allow(clippy::too_many_arguments)]
        fn try_select_entry(
            entry: &EntryScore,
            entries: &BTreeMap<TieredEntryId, EntryMetadata>,
            hot_ids: &mut BTreeSet<TieredEntryId>,
            hot_list: &mut Vec<TieredEntryId>,
            retained_bytes: &mut u64,
            enforce_budget: bool,
            max_keys: usize,
            max_bytes: u64,
        ) {
            let meta = entries.get(&entry.id).expect("metadata populated");
            let entry_bytes = entry.hot_budget_bytes(meta);
            if enforce_budget {
                if hot_ids.len() >= max_keys {
                    return;
                }
                if !hot_budget_has_capacity(*retained_bytes, entry_bytes, max_bytes) {
                    return;
                }
            }
            if hot_ids.insert(entry.id) {
                *retained_bytes = retained_bytes.saturating_add(entry_bytes);
                hot_list.push(entry.id);
            }
        }
        let mut hot_ids = BTreeSet::new();
        let mut hot_list = Vec::new();
        let mut retained_bytes = 0u64;
        if self.hot_retained_grace_snapshots > 0 {
            for entry in &scores {
                let meta = self.entries.get(&entry.id).expect("metadata populated");
                if meta.hot_until_snapshot >= snapshot_idx && meta.hot_until_snapshot > 0 {
                    try_select_entry(
                        entry,
                        &self.entries,
                        &mut hot_ids,
                        &mut hot_list,
                        &mut retained_bytes,
                        false,
                        max_keys,
                        max_bytes,
                    );
                }
            }
        }
        for entry in &scores {
            if !hot_ids.contains(&entry.id) {
                try_select_entry(
                    entry,
                    &self.entries,
                    &mut hot_ids,
                    &mut hot_list,
                    &mut retained_bytes,
                    true,
                    max_keys,
                    max_bytes,
                );
            }
        }
        let mut hot_manifest_entries = Vec::with_capacity(hot_list.len());
        let mut cold_manifest_entries = Vec::with_capacity(scores.len());
        let mut cold_plans = Vec::with_capacity(scores.len());
        for entry in &scores {
            let meta = self.entries.get(&entry.id).expect("metadata populated");
            if hot_ids.contains(&entry.id) {
                hot_manifest_entries.push(entry.manifest_entry(meta, None));
            } else {
                let rel_path = entry.relative_payload_path(snapshot_idx);
                let reuse_source = if meta.last_cold_snapshot > 0
                    && meta.last_cold_snapshot >= meta.last_mutated_snapshot
                {
                    meta.last_cold_rel_path.as_ref().and_then(|rel_path| {
                        let candidate = root
                            .join(format!("{index:020}", index = meta.last_cold_snapshot))
                            .join(rel_path);
                        candidate.exists().then_some(candidate)
                    })
                } else {
                    None
                };
                if let Some(payloads) = payloads
                    && reuse_source.is_none()
                    && !payloads.contains_key(&entry.id)
                {
                    if hot_ids.insert(entry.id) {
                        retained_bytes =
                            retained_bytes.saturating_add(entry.hot_budget_bytes(meta));
                        hot_list.push(entry.id);
                    }
                    hot_manifest_entries.push(entry.manifest_entry(meta, None));
                    continue;
                }
                let manifest_index = cold_manifest_entries.len();
                let mut manifest_entry = entry.manifest_entry(meta, Some((rel_path.clone(), 0)));
                manifest_entry.spill_bytes = None;
                cold_manifest_entries.push(manifest_entry);
                cold_plans.push(ColdEntryPlan {
                    rel_path,
                    entry: entry.clone(),
                    manifest_index,
                    reuse_source,
                });
            }
        }
        let mut hot_promotions = 0usize;
        let mut hot_demotions = 0usize;
        for entry in &scores {
            let meta = self.entries.get(&entry.id).expect("metadata populated");
            let was_hot_last = meta.last_hot_snapshot > 0
                && meta.last_hot_snapshot == snapshot_idx.saturating_sub(1);
            let is_hot_now = hot_ids.contains(&entry.id);
            if was_hot_last && !is_hot_now {
                hot_demotions = hot_demotions.saturating_add(1);
            } else if !was_hot_last && is_hot_now {
                hot_promotions = hot_promotions.saturating_add(1);
            }
        }
        for id in &hot_list {
            if let Some(meta) = self.entries.get_mut(id) {
                let was_hot_last = meta.last_hot_snapshot > 0
                    && meta.last_hot_snapshot == snapshot_idx.saturating_sub(1);
                if self.hot_retained_grace_snapshots > 0 && !was_hot_last {
                    meta.hot_until_snapshot =
                        snapshot_idx.saturating_add(self.hot_retained_grace_snapshots);
                }
                meta.last_hot_snapshot = snapshot_idx;
            }
        }
        let hot_budget_overflow_keys = if self.hot_retained_keys == 0 {
            0
        } else {
            hot_ids.len().saturating_sub(self.hot_retained_keys)
        };
        let hot_budget_overflow_bytes = if self.hot_retained_bytes == 0 {
            0
        } else {
            retained_bytes.saturating_sub(self.hot_retained_bytes)
        };
        if (self.hot_retained_keys > 0 && hot_budget_overflow_keys > 0)
            || (self.hot_retained_bytes > 0 && hot_budget_overflow_bytes > 0)
        {
            iroha_logger::warn!(
                hot_limit_keys = self.hot_retained_keys,
                hot_limit_bytes = self.hot_retained_bytes,
                hot_entries = hot_ids.len(),
                hot_bytes = retained_bytes,
                hot_budget_overflow_keys,
                hot_budget_overflow_bytes,
                "tiered-state: hot tier budget exceeded by grace or unspillable retention"
            );
        }
        let manifest = TieredSnapshotManifest {
            snapshot_index: snapshot_idx,
            total_entries: scores.len(),
            hot_entries: hot_manifest_entries,
            cold_entries: cold_manifest_entries,
            cold_bytes_total: 0,
            cold_reused_entries: 0,
            cold_reused_bytes: 0,
            hot_promotions,
            hot_demotions,
            hot_budget_overflow_keys,
            hot_budget_overflow_bytes,
        };
        Ok(TieredSnapshotPlan {
            root,
            snapshot_dir,
            manifest,
            cold_entries: cold_plans,
        })
    }
    #[cfg(test)]
    fn apply_snapshot_diff(
        &mut self,
        world: &World,
        snapshot_idx: u64,
        diff: &TieredSnapshotDiff,
    ) -> Result<()> {
        for entry in &diff.entries {
            let (id, key_encoded) = entry.entry_id()?;
            let Some((value_hash, value_size_bytes)) = entry.measure_value(world)? else {
                self.entries.remove(&id);
                self.entry_keys.remove(&id);
                continue;
            };
            let meta = self
                .entries
                .entry(id)
                .or_insert_with(|| EntryMetadata::new(snapshot_idx, value_hash, value_size_bytes));
            if meta.last_value_hash != value_hash {
                meta.last_value_hash = value_hash;
                meta.last_mutated_snapshot = snapshot_idx;
            }
            meta.value_size_bytes = value_size_bytes;
            self.entry_keys.insert(
                id,
                EntryKey {
                    key: entry.clone(),
                    key_encoded,
                },
            );
        }
        Ok(())
    }
    fn apply_snapshot_payload(
        &mut self,
        snapshot_idx: u64,
        payload: &TieredSnapshotPayload,
    ) -> Result<SnapshotPayloadCache> {
        let mut cache = SnapshotPayloadCache::default();
        for entry in &payload.entries {
            let (id, key_encoded) = entry.key.entry_id()?;
            let Some(value) = entry.value.as_ref() else {
                self.entries.remove(&id);
                self.entry_keys.remove(&id);
                continue;
            };
            let payload = value.encode_json()?;
            let value_hash = sha256(&payload);
            let value_size_bytes = value.measured_bytes();
            let meta = self
                .entries
                .entry(id)
                .or_insert_with(|| EntryMetadata::new(snapshot_idx, value_hash, value_size_bytes));
            if meta.last_value_hash != value_hash {
                meta.last_value_hash = value_hash;
                meta.last_mutated_snapshot = snapshot_idx;
            }
            meta.value_size_bytes = value_size_bytes;
            self.entry_keys.insert(
                id,
                EntryKey {
                    key: entry.key.clone(),
                    key_encoded,
                },
            );
            cache.payloads.insert(id, payload);
        }
        Ok(cache)
    }
    #[allow(clippy::too_many_lines)]
    #[cfg(test)]
    fn execute_snapshot_plan(&mut self, mut plan: TieredSnapshotPlan, world: &World) -> Result<()> {
        self.ensure_cold_roots()
            .wrap_err("failed to prepare cold tier root directory")?;
        let staging_dir = plan.snapshot_dir.with_extension("staging");
        if staging_dir.exists() {
            fs::remove_dir_all(&staging_dir).wrap_err_with(|| {
                format!(
                    "failed to clear previous staging directory {path}",
                    path = staging_dir.display()
                )
            })?;
        }
        fs::create_dir_all(&staging_dir).wrap_err_with(|| {
            format!(
                "failed to create staging directory {path}",
                path = staging_dir.display()
            )
        })?;
        let mut cold_bytes_total: u64 = 0;
        let mut cold_reused_entries: usize = 0;
        let mut cold_reused_bytes: u64 = 0;
        let mut dirs_to_sync = BTreeSet::new();
        for cold in &plan.cold_entries {
            let abs_path = staging_dir.join(&cold.rel_path);
            let mut parent_dirs = Vec::new();
            if let Some(parent) = abs_path.parent() {
                fs::create_dir_all(parent).wrap_err_with(|| {
                    format!(
                        "failed to create cold shard directory {dir}",
                        dir = parent.display()
                    )
                })?;
                for ancestor in parent.ancestors() {
                    parent_dirs.push(ancestor.to_path_buf());
                    if ancestor == staging_dir {
                        break;
                    }
                }
            }
            let mut payload_len = None;
            let mut reused = false;
            if let Some(source) = cold.reuse_source.as_ref() {
                match Self::try_reuse_cold_payload(source, &abs_path) {
                    Ok(Some(bytes)) => {
                        payload_len = Some(bytes);
                        reused = true;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            source = %source.display(),
                            target = %abs_path.display(),
                            "tiered-state: failed to reuse cold shard payload"
                        );
                    }
                }
            }
            let payload_len = if let Some(bytes) = payload_len {
                bytes
            } else {
                let payload = cold.entry.encode_value(world).with_context(|| {
                    format!(
                        "failed to encode value for cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                let mut file = BufWriter::new(fs::File::create(&abs_path).wrap_err_with(|| {
                    format!(
                        "failed to open cold shard {path} for writing",
                        path = abs_path.display()
                    )
                })?);
                file.write_all(&payload).wrap_err_with(|| {
                    format!(
                        "failed to persist cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                file.flush().wrap_err_with(|| {
                    format!(
                        "failed to flush cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                file.get_ref().sync_all().wrap_err_with(|| {
                    format!(
                        "failed to sync cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                payload.len() as u64
            };
            cold_bytes_total = cold_bytes_total.saturating_add(payload_len);
            if reused {
                cold_reused_entries = cold_reused_entries.saturating_add(1);
                cold_reused_bytes = cold_reused_bytes.saturating_add(payload_len);
            }
            if let Some(entry) = plan.manifest.cold_entries.get_mut(cold.manifest_index) {
                entry.spill_bytes = Some(payload_len);
            }
            if let Some(meta) = self.entries.get_mut(&cold.entry.id) {
                meta.last_cold_snapshot = plan.manifest.snapshot_index;
                meta.last_cold_rel_path = Some(cold.rel_path.clone());
            }
            for dir in parent_dirs {
                dirs_to_sync.insert(dir);
            }
        }
        plan.manifest.cold_bytes_total = cold_bytes_total;
        plan.manifest.cold_reused_entries = cold_reused_entries;
        plan.manifest.cold_reused_bytes = cold_reused_bytes;
        for dir in dirs_to_sync {
            Self::sync_dir(&dir).wrap_err_with(|| {
                format!(
                    "failed to sync cold shard directory {path}",
                    path = dir.display()
                )
            })?;
        }
        Self::write_manifest(&staging_dir, &plan.manifest)?;
        Self::sync_dir(&staging_dir).wrap_err_with(|| {
            format!(
                "failed to sync staging directory {path}",
                path = staging_dir.display()
            )
        })?;
        let backup = if plan.snapshot_dir.exists() {
            let backup_path = plan.snapshot_dir.with_extension("bak");
            if backup_path.exists() {
                fs::remove_dir_all(&backup_path).wrap_err_with(|| {
                    format!(
                        "failed to clear previous backup {path}",
                        path = backup_path.display()
                    )
                })?;
            }
            fs::rename(&plan.snapshot_dir, &backup_path).wrap_err_with(|| {
                format!(
                    "failed to move existing snapshot to backup {path}",
                    path = backup_path.display()
                )
            })?;
            Some(backup_path)
        } else {
            None
        };
        fs::rename(&staging_dir, &plan.snapshot_dir).wrap_err_with(|| {
            format!(
                "failed to promote staging snapshot into place at {path}",
                path = plan.snapshot_dir.display()
            )
        })?;
        Self::sync_dir(&plan.snapshot_dir).wrap_err_with(|| {
            format!(
                "failed to sync snapshot directory {path}",
                path = plan.snapshot_dir.display()
            )
        })?;
        if let Some(parent) = plan.snapshot_dir.parent() {
            Self::sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync snapshot parent {path}",
                    path = parent.display()
                )
            })?;
        }
        if let Some(backup_path) = backup {
            if let Err(err) = fs::remove_dir_all(&backup_path) {
                iroha_logger::warn!(
                    ?err,
                    path = %backup_path.display(),
                    "tiered-state: failed to remove snapshot backup directory"
                );
            }
        }
        self.last_manifest = Some(plan.manifest);
        self.prune_old_snapshots(&plan.root)?;
        self.prune_to_cold_bytes(&plan.root)?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    fn execute_snapshot_plan_with_payload(
        &mut self,
        mut plan: TieredSnapshotPlan,
        payloads: &BTreeMap<TieredEntryId, Vec<u8>>,
    ) -> Result<()> {
        self.ensure_cold_roots()
            .wrap_err("failed to prepare cold tier root directory")?;
        let staging_dir = plan.snapshot_dir.with_extension("staging");
        if staging_dir.exists() {
            fs::remove_dir_all(&staging_dir).wrap_err_with(|| {
                format!(
                    "failed to clear previous staging directory {path}",
                    path = staging_dir.display()
                )
            })?;
        }
        fs::create_dir_all(&staging_dir).wrap_err_with(|| {
            format!(
                "failed to create staging directory {path}",
                path = staging_dir.display()
            )
        })?;
        let mut cold_bytes_total: u64 = 0;
        let mut cold_reused_entries: usize = 0;
        let mut cold_reused_bytes: u64 = 0;
        let mut dirs_to_sync = BTreeSet::new();
        for cold in &plan.cold_entries {
            let abs_path = staging_dir.join(&cold.rel_path);
            let mut parent_dirs = Vec::new();
            if let Some(parent) = abs_path.parent() {
                fs::create_dir_all(parent).wrap_err_with(|| {
                    format!(
                        "failed to create cold shard directory {dir}",
                        dir = parent.display()
                    )
                })?;
                for ancestor in parent.ancestors() {
                    parent_dirs.push(ancestor.to_path_buf());
                    if ancestor == staging_dir {
                        break;
                    }
                }
            }
            let mut payload_len = None;
            let mut reused = false;
            if let Some(source) = cold.reuse_source.as_ref() {
                match Self::try_reuse_cold_payload(source, &abs_path) {
                    Ok(Some(bytes)) => {
                        payload_len = Some(bytes);
                        reused = true;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            source = %source.display(),
                            target = %abs_path.display(),
                            "tiered-state: failed to reuse cold shard payload"
                        );
                    }
                }
            }
            let payload_len = if let Some(bytes) = payload_len {
                bytes
            } else {
                let payload = payloads.get(&cold.entry.id).ok_or_else(|| {
                    eyre::eyre!("tiered-state: missing payload for {}", cold.entry.key)
                })?;
                let mut file = BufWriter::new(fs::File::create(&abs_path).wrap_err_with(|| {
                    format!(
                        "failed to open cold shard {path} for writing",
                        path = abs_path.display()
                    )
                })?);
                file.write_all(payload).wrap_err_with(|| {
                    format!(
                        "failed to persist cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                file.flush().wrap_err_with(|| {
                    format!(
                        "failed to flush cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                file.get_ref().sync_all().wrap_err_with(|| {
                    format!(
                        "failed to sync cold shard {path}",
                        path = abs_path.display()
                    )
                })?;
                payload.len() as u64
            };
            cold_bytes_total = cold_bytes_total.saturating_add(payload_len);
            if reused {
                cold_reused_entries = cold_reused_entries.saturating_add(1);
                cold_reused_bytes = cold_reused_bytes.saturating_add(payload_len);
            }
            if let Some(entry) = plan.manifest.cold_entries.get_mut(cold.manifest_index) {
                entry.spill_bytes = Some(payload_len);
            }
            if let Some(meta) = self.entries.get_mut(&cold.entry.id) {
                meta.last_cold_snapshot = plan.manifest.snapshot_index;
                meta.last_cold_rel_path = Some(cold.rel_path.clone());
            }
            for dir in parent_dirs {
                dirs_to_sync.insert(dir);
            }
        }
        plan.manifest.cold_bytes_total = cold_bytes_total;
        plan.manifest.cold_reused_entries = cold_reused_entries;
        plan.manifest.cold_reused_bytes = cold_reused_bytes;
        for dir in dirs_to_sync {
            Self::sync_dir(&dir).wrap_err_with(|| {
                format!(
                    "failed to sync cold shard directory {path}",
                    path = dir.display()
                )
            })?;
        }
        Self::write_manifest(&staging_dir, &plan.manifest)?;
        Self::sync_dir(&staging_dir).wrap_err_with(|| {
            format!(
                "failed to sync staging directory {path}",
                path = staging_dir.display()
            )
        })?;
        let backup = if plan.snapshot_dir.exists() {
            let backup_path = plan.snapshot_dir.with_extension("bak");
            if backup_path.exists() {
                fs::remove_dir_all(&backup_path).wrap_err_with(|| {
                    format!(
                        "failed to clear previous backup {path}",
                        path = backup_path.display()
                    )
                })?;
            }
            fs::rename(&plan.snapshot_dir, &backup_path).wrap_err_with(|| {
                format!(
                    "failed to move existing snapshot to backup {path}",
                    path = backup_path.display()
                )
            })?;
            Some(backup_path)
        } else {
            None
        };
        fs::rename(&staging_dir, &plan.snapshot_dir).wrap_err_with(|| {
            format!(
                "failed to promote staging snapshot into place at {path}",
                path = plan.snapshot_dir.display()
            )
        })?;
        Self::sync_dir(&plan.snapshot_dir).wrap_err_with(|| {
            format!(
                "failed to sync snapshot directory {path}",
                path = plan.snapshot_dir.display()
            )
        })?;
        if let Some(parent) = plan.snapshot_dir.parent() {
            Self::sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync snapshot parent {path}",
                    path = parent.display()
                )
            })?;
        }
        if let Some(backup_path) = backup {
            if let Err(err) = fs::remove_dir_all(&backup_path) {
                iroha_logger::warn!(
                    ?err,
                    path = %backup_path.display(),
                    "tiered-state: failed to remove snapshot backup directory"
                );
            }
        }
        self.last_manifest = Some(plan.manifest);
        self.prune_old_snapshots(&plan.root)?;
        self.prune_to_cold_bytes(&plan.root)?;
        Ok(())
    }
    /// Returns the currently configured hot byte retention limit.
    #[cfg(any(test, feature = "telemetry"))]
    #[must_use]
    pub fn hot_retained_bytes(&self) -> u64 {
        self.hot_retained_bytes
    }
    /// Returns the currently configured cold snapshot byte budget.
    #[cfg(any(test, feature = "telemetry"))]
    #[must_use]
    pub fn max_cold_bytes(&self) -> u64 {
        self.max_cold_bytes
    }
    fn cold_roots(&self) -> Vec<&PathBuf> {
        let mut roots = Vec::new();
        if let Some(root) = self.cold_store_root.as_ref() {
            roots.push(root);
        }
        if let Some(root) = self.da_store_root.as_ref()
            && !roots.contains(&root)
        {
            roots.push(root);
        }
        roots
    }
    fn da_store_root_for_offload(&self) -> Option<&PathBuf> {
        match (&self.cold_store_root, &self.da_store_root) {
            (Some(cold_root), Some(da_root)) if cold_root != da_root => Some(da_root),
            _ => None,
        }
    }
    fn primary_cold_root(&self) -> Option<&PathBuf> {
        self.cold_store_root
            .as_ref()
            .or(self.da_store_root.as_ref())
    }
    /// Returns whether tiering is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Whether incremental payloads can extend an actual complete baseline.
    pub(crate) fn snapshot_baseline_ready(&self) -> bool {
        self.snapshot_baseline_ready
    }
    /// Returns the cached manifest of the latest snapshot, if any.
    #[cfg(any(test, feature = "telemetry"))]
    #[must_use]
    pub fn last_manifest(&self) -> Option<&TieredSnapshotManifest> {
        self.last_manifest.as_ref()
    }
    /// Return the total cold-tier bytes currently stored on disk.
    pub fn cold_store_bytes(&self) -> Result<Option<u64>> {
        let Some(root) = self.primary_cold_root() else {
            return Ok(None);
        };
        if !root.exists() {
            return Ok(Some(0));
        }
        let mut total = 0u64;
        for entry in fs::read_dir(root).wrap_err_with(|| {
            format!(
                "failed to read tiered snapshot root {path}",
                path = root.display()
            )
        })? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            if Self::parse_snapshot_dir_name(&entry.file_name()).is_some() {
                total = total.saturating_add(Self::snapshot_dir_size(&entry.path())?);
            }
        }
        Ok(Some(total))
    }
    /// Load a cold payload from the configured cold roots.
    #[cfg(test)]
    pub fn read_cold_payload(
        &self,
        snapshot_index: u64,
        entry: &TieredManifestEntry,
    ) -> Result<Option<Vec<u8>>> {
        let Some(rel_path) = entry.spill_path.as_ref() else {
            return Ok(None);
        };
        let cache_enabled = self.da_store_root_for_offload().is_some();
        let cold_root = self.cold_store_root.as_ref();
        if let Some(root) = cold_root {
            let path = root.join(format!("{snapshot_index:020}")).join(rel_path);
            match fs::read(&path) {
                Ok(bytes) => {
                    if cache_enabled {
                        self.record_da_cache(DA_CACHE_HIT);
                    }
                    return Ok(Some(bytes));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).wrap_err_with(|| {
                        format!("failed to read cold payload {path}", path = path.display())
                    });
                }
            }
        }
        let da_root = self.da_store_root.as_ref();
        let same_root = match (cold_root, da_root) {
            (Some(cold), Some(da)) => cold == da,
            _ => false,
        };
        if let Some(root) = da_root
            && !same_root
        {
            let path = root.join(format!("{snapshot_index:020}")).join(rel_path);
            match fs::read(&path) {
                Ok(bytes) => {
                    if cache_enabled {
                        self.record_da_cache(DA_CACHE_MISS);
                        match self.try_rehydrate_cold_payload(snapshot_index, rel_path, &bytes) {
                            Ok(Some(written)) => {
                                self.record_da_churn(DA_CHURN_REHYDRATED, written);
                            }
                            Ok(None) => {}
                            Err(err) => {
                                iroha_logger::warn!(
                                    ?err,
                                    path = %path.display(),
                                    "tiered-state: failed to rehydrate cold payload"
                                );
                            }
                        }
                    }
                    return Ok(Some(bytes));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).wrap_err_with(|| {
                        format!("failed to read cold payload {path}", path = path.display())
                    });
                }
            }
        }
        Ok(None)
    }
    #[cfg(test)]
    fn try_rehydrate_cold_payload(
        &self,
        snapshot_index: u64,
        rel_path: &Path,
        payload: &[u8],
    ) -> Result<Option<u64>> {
        let Some(cold_root) = self.cold_store_root.as_ref() else {
            return Ok(None);
        };
        if let Some(da_root) = self.da_store_root.as_ref()
            && da_root == cold_root
        {
            return Ok(None);
        }
        let snapshot_dir = cold_root.join(format!("{snapshot_index:020}"));
        let dest = snapshot_dir.join(rel_path);
        if dest.exists() {
            return Ok(None);
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!(
                    "failed to create cold shard directory {dir}",
                    dir = parent.display()
                )
            })?;
        }
        let tmp_path = dest.with_extension("rehydrate.tmp");
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => return Ok(None),
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!(
                        "failed to open temp cold shard {path} for rehydration",
                        path = tmp_path.display()
                    )
                });
            }
        };
        file.write_all(payload).wrap_err_with(|| {
            format!(
                "failed to write cold shard {path} during rehydration",
                path = tmp_path.display()
            )
        })?;
        file.flush().wrap_err_with(|| {
            format!(
                "failed to flush cold shard {path} during rehydration",
                path = tmp_path.display()
            )
        })?;
        file.sync_all().wrap_err_with(|| {
            format!(
                "failed to sync cold shard {path} during rehydration",
                path = tmp_path.display()
            )
        })?;
        fs::rename(&tmp_path, &dest).wrap_err_with(|| {
            format!(
                "failed to persist cold shard {path} during rehydration",
                path = dest.display()
            )
        })?;
        if let Some(parent) = dest.parent() {
            Self::sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync cold shard directory {path}",
                    path = parent.display()
                )
            })?;
        }
        Ok(Some(u64::try_from(payload.len()).unwrap_or(u64::MAX)))
    }
    #[cfg(test)]
    fn record_da_cache(&self, outcome: &'static str) {
        if let Some(telemetry) = self.telemetry.as_ref() {
            telemetry.inc_storage_da_cache(WSV_COLD_COMPONENT, outcome);
        }
    }
    fn record_da_churn(&self, event: &'static str, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Some(telemetry) = self.telemetry.as_ref() {
            telemetry.add_storage_da_churn_bytes(WSV_COLD_COMPONENT, event, bytes);
        }
    }
    /// Update configuration knobs at runtime.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn reconfigure(
        &mut self,
        enabled: bool,
        hot_retained_keys: usize,
        hot_retained_bytes: u64,
        hot_retained_grace_snapshots: u64,
        cold_store_root: Option<PathBuf>,
        da_store_root: Option<PathBuf>,
        max_snapshots: usize,
        max_cold_bytes: u64,
    ) {
        let cold_root_changed = self.reconfigure_without_storage_effects(
            enabled,
            hot_retained_keys,
            hot_retained_bytes,
            hot_retained_grace_snapshots,
            cold_store_root,
            da_store_root,
            max_snapshots,
            max_cold_bytes,
        );
        if self.enabled && cold_root_changed {
            if let Err(err) = self.ensure_cold_roots() {
                iroha_logger::warn!(
                    ?err,
                    "tiered-state: failed to prepare cold tier root after reconfigure"
                );
            }
        }
    }
    /// Update in-memory policy and caches without creating or changing storage.
    ///
    /// Returns whether either configured root changed. Startup uses this before
    /// capturing a retained geometry owner so that owner performs every mkdir.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconfigure_without_storage_effects(
        &mut self,
        enabled: bool,
        hot_retained_keys: usize,
        hot_retained_bytes: u64,
        hot_retained_grace_snapshots: u64,
        cold_store_root: Option<PathBuf>,
        da_store_root: Option<PathBuf>,
        max_snapshots: usize,
        max_cold_bytes: u64,
    ) -> bool {
        let cold_root_changed =
            self.cold_store_root != cold_store_root || self.da_store_root != da_store_root;
        let grace_changed = self.hot_retained_grace_snapshots != hot_retained_grace_snapshots;
        self.enabled = enabled;
        self.hot_retained_keys = hot_retained_keys;
        self.hot_retained_bytes = hot_retained_bytes;
        self.hot_retained_grace_snapshots = hot_retained_grace_snapshots;
        self.cold_store_root = cold_store_root;
        self.da_store_root = da_store_root;
        self.max_snapshots = max_snapshots;
        self.max_cold_bytes = max_cold_bytes;
        if grace_changed {
            for meta in self.entries.values_mut() {
                meta.hot_until_snapshot = 0;
            }
        }
        if cold_root_changed {
            self.entries.clear();
            self.entry_keys.clear();
            self.snapshot_counter = 0;
            self.snapshot_counter_seeded = false;
            self.snapshot_baseline_ready = false;
            self.last_manifest = None;
        }
        cold_root_changed
    }
    /// Validate lane snapshot geometry changes that can fail without mutating tiered state.
    ///
    /// # Errors
    /// Returns an error if a required tiered snapshot, replacement, relabel, or retirement path is
    /// blocked by an incompatible filesystem entry.
    pub fn preflight_lane_geometry(
        &self,
        previous: &LaneConfig,
        current: &LaneConfig,
        replacements: &[(&LaneConfigEntry, &LaneConfigEntry)],
        relabelled: &[(&LaneConfigEntry, &LaneConfigEntry)],
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let Some(root) = self.primary_cold_root().cloned() else {
            return Ok(());
        };
        self.preflight_cold_roots()?;
        let mut previous_map = BTreeMap::new();
        for entry in previous.entries() {
            previous_map.insert(entry.lane_id, entry);
        }
        let mut current_map = BTreeMap::new();
        for entry in current.entries() {
            current_map.insert(entry.lane_id, entry);
        }
        let replacement_ids: BTreeSet<_> = replacements
            .iter()
            .map(|(_, current)| current.lane_id)
            .collect();
        let lanes_root = root.join("lanes");
        Self::preflight_dir_path(&lanes_root)?;
        for (id, entry) in &current_map {
            let dir = lane_snapshot_dir(&lanes_root, entry);
            let replaced = replacement_ids.contains(id);
            if !replaced && previous_map.contains_key(id) && dir.exists() {
                Self::preflight_dir_path(&dir)?;
                continue;
            }
            if !replaced
                && previous_map
                    .get(id)
                    .is_some_and(|prev| lane_snapshot_dir(&lanes_root, prev).exists())
            {
                continue;
            }
            if replaced
                && previous_map.get(id).is_some_and(|prev| {
                    let old_dir = lane_snapshot_dir(&lanes_root, prev);
                    old_dir != dir && dir.exists()
                })
            {
                return Err(eyre::eyre!(
                    "tiered-state: lane snapshot replacement target already exists: {path}",
                    path = dir.display()
                ));
            }
            Self::preflight_dir_path(&dir)?;
        }
        let retired_root = root.join("retired").join("lanes");
        for (id, entry) in &previous_map {
            if current_map.contains_key(id) && !replacement_ids.contains(id) {
                continue;
            }
            let dir = lane_snapshot_dir(&lanes_root, entry);
            if dir.exists() {
                Self::preflight_dir_path(&retired_root)?;
            }
        }
        for (previous, current) in relabelled {
            let old_dir = lane_snapshot_dir(&lanes_root, previous);
            let new_dir = lane_snapshot_dir(&lanes_root, current);
            if old_dir == new_dir || !old_dir.exists() {
                continue;
            }
            if let Some(parent) = new_dir.parent() {
                Self::preflight_dir_path(parent)?;
            }
            if new_dir.exists() {
                return Err(eyre::eyre!(
                    "tiered-state: lane snapshot relabel target already exists: {path}",
                    path = new_dir.display()
                ));
            }
            Self::preflight_dir_path(&new_dir)?;
        }
        Ok(())
    }
    /// Test convenience around the same retained production geometry owner.
    #[cfg(test)]
    pub fn reconcile_lane_geometry(
        &mut self,
        previous: &LaneConfig,
        current: &LaneConfig,
        replacements: &[(&LaneConfigEntry, &LaneConfigEntry)],
    ) -> Result<()> {
        self.prepare_lane_geometry_attempt(previous, current, replacements, &[])?
            .resume(self)
    }
    fn ensure_cold_roots(&self) -> Result<()> {
        for root in self.cold_store_root.iter().chain(self.da_store_root.iter()) {
            fs::create_dir_all(root).wrap_err_with(|| {
                format!(
                    "failed to create cold tier root {path}",
                    path = root.display()
                )
            })?;
        }
        Ok(())
    }
    fn preflight_cold_roots(&self) -> Result<()> {
        for root in self.cold_store_root.iter().chain(self.da_store_root.iter()) {
            Self::preflight_dir_path(root)?;
        }
        Ok(())
    }
    fn preflight_dir_path(path: &Path) -> Result<()> {
        if path.exists() && !path.is_dir() {
            return Err(eyre::eyre!(
                "tiered-state: expected directory path: {path}",
                path = path.display()
            ));
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    #[cfg(test)]
    fn collect_world_entries(
        &mut self,
        world: &World,
        snapshot_idx: u64,
        scores: &mut Vec<EntryScore>,
        seen: &mut BTreeSet<TieredEntryId>,
    ) -> Result<()> {
        let mut ctx = CollectContext {
            snapshot_idx,
            scores,
            seen,
        };
        macro_rules! collect_map {
            ($segment:expr, $variant:ident, $storage:expr) => {{
                let view = $storage.view();
                for (key, value) in view.iter() {
                    let key_handle = TieredKeyHandle::$variant((*key).clone());
                    self.collect_entry($segment, &key_handle, key, value, &mut ctx)?;
                }
            }};
        }
        collect_map!(TieredSegment::Domains, Domain, world.domains);
        collect_map!(TieredSegment::Accounts, Account, world.accounts);
        collect_map!(
            TieredSegment::AccountRekeyRecords,
            AccountRekey,
            world.account_rekey_records
        );
        collect_map!(
            TieredSegment::AccountRecoveryPolicies,
            AccountRecoveryPolicy,
            world.account_recovery_policies
        );
        collect_map!(
            TieredSegment::AccountRecoveryRequests,
            AccountRecoveryRequest,
            world.account_recovery_requests
        );
        collect_map!(
            TieredSegment::AssetDefinitions,
            AssetDefinition,
            world.asset_definitions
        );
        collect_map!(
            TieredSegment::AssetDefinitionAliasBindings,
            AssetDefinitionAliasBinding,
            world.asset_definition_alias_bindings
        );
        collect_map!(TieredSegment::Assets, Asset, world.assets);
        collect_map!(
            TieredSegment::AssetMetadata,
            AssetMetadata,
            world.asset_metadata
        );
        collect_map!(TieredSegment::AxtPolicies, AxtPolicy, world.axt_policies);
        collect_map!(
            TieredSegment::AxtHandleCounters,
            AxtHandleCounter,
            world.axt_handle_counters
        );
        collect_map!(
            TieredSegment::AxtAssetIncarnations,
            AxtAssetIncarnation,
            world.axt_asset_incarnations
        );
        collect_map!(
            TieredSegment::AssetDefinitionDirectHomes,
            AssetDefinitionDirectHome,
            world.asset_definition_direct_homes
        );
        collect_map!(
            TieredSegment::AxtReplayLedger,
            AxtReplay,
            world.axt_replay_ledger
        );
        collect_map!(
            TieredSegment::AxtSpendNonceLedger,
            AxtSpendNonce,
            world.axt_spend_nonce_ledger
        );
        collect_map!(
            TieredSegment::AxtSourceTransferReplayLedger,
            AxtSourceTransferReplay,
            world.axt_source_transfer_replay_ledger
        );
        collect_map!(
            TieredSegment::AxtHandleBudgetLedger,
            AxtHandleBudget,
            world.axt_handle_budget_ledger
        );
        collect_map!(TieredSegment::Nfts, Nft, world.nfts);
        collect_map!(TieredSegment::Rwas, Rwa, world.rwas);
        collect_map!(TieredSegment::Roles, Role, world.roles);
        collect_map!(
            TieredSegment::AccountPermissions,
            AccountPermission,
            world.account_permissions
        );
        collect_map!(
            TieredSegment::AccountRoles,
            AccountRole,
            world.account_roles
        );
        collect_map!(TieredSegment::TxSequences, TxSequence, world.tx_sequences);
        collect_map!(
            TieredSegment::VerifyingKeys,
            VerifyingKey,
            world.verifying_keys
        );
        collect_map!(
            TieredSegment::RuntimeUpgrades,
            RuntimeUpgrade,
            world.runtime_upgrades
        );
        collect_map!(
            TieredSegment::PrivacyActivations,
            PrivacyActivation,
            world.privacy_activations
        );
        collect_map!(
            TieredSegment::PrivacyPgcAccounts,
            PrivacyPgcAccount,
            world.privacy_pgc_accounts
        );
        collect_map!(
            TieredSegment::PrivacyPgcPoolInvariants,
            PrivacyPgcPoolInvariant,
            world.privacy_pgc_pool_invariants
        );
        collect_map!(
            TieredSegment::PrivacyNullifiers,
            PrivacyNullifier,
            world.privacy_nullifiers
        );
        collect_map!(
            TieredSegment::PrivacyCommitments,
            PrivacyCommitment,
            world.privacy_commitments
        );
        collect_map!(
            TieredSegment::PrivacyRoots,
            PrivacyRoot,
            world.privacy_roots
        );
        collect_map!(
            TieredSegment::PrivacyRootHeads,
            PrivacyRootHead,
            world.privacy_root_heads
        );
        collect_map!(
            TieredSegment::KagemushaWalletLedger,
            KagemushaWalletLedger,
            world.kagemusha_wallet_ledger
        );
        collect_map!(
            TieredSegment::PrivateSettlementGovernance,
            PrivateSettlementGovernance,
            world.private_settlement_governance
        );
        collect_map!(
            TieredSegment::PrivateSettlementPools,
            PrivateSettlementPool,
            world.private_settlement_pools
        );
        collect_map!(
            TieredSegment::PrivateSettlementRoots,
            PrivateSettlementRoot,
            world.private_settlement_roots
        );
        collect_map!(
            TieredSegment::PrivateSettlementNullifiers,
            PrivateSettlementNullifier,
            world.private_settlement_nullifiers
        );
        collect_map!(
            TieredSegment::PrivateSettlementOutputs,
            PrivateSettlementOutput,
            world.private_settlement_outputs
        );
        collect_map!(
            TieredSegment::PrivateSettlementStagedLocks,
            PrivateSettlementStagedLock,
            world.private_settlement_staged_locks
        );
        collect_map!(
            TieredSegment::PrivateSettlementReceipts,
            PrivateSettlementReceipt,
            world.private_settlement_receipts
        );
        collect_map!(
            TieredSegment::PrivateSettlementAborts,
            PrivateSettlementAbort,
            world.private_settlement_aborts
        );
        collect_map!(TieredSegment::Proofs, Proof, world.proofs);
        collect_map!(TieredSegment::ProofTags, ProofTag, world.proof_tags);
        collect_map!(TieredSegment::ProofsByTag, ProofByTag, world.proofs_by_tag);
        collect_map!(
            TieredSegment::ContractManifests,
            ContractManifest,
            world.contract_manifests
        );
        collect_map!(
            TieredSegment::ContractCode,
            ContractCode,
            world.contract_code
        );
        collect_map!(
            TieredSegment::ContractCodeUploads,
            ContractCodeUpload,
            world.contract_code_uploads
        );
        collect_map!(
            TieredSegment::ContractCodeUploadChunks,
            ContractCodeUploadChunk,
            world.contract_code_upload_chunks
        );
        {
            let view = world.contract_instances.view();
            for (key, value) in view.iter() {
                let key_handle = TieredKeyHandle::ContractInstance((*key).clone());
                let key_payload = norito::codec::Encode::encode(key);
                self.collect_entry_with_encoded_key(
                    TieredSegment::ContractInstances,
                    &key_handle,
                    key_payload,
                    value,
                    &mut ctx,
                )?;
            }
        }
        {
            let view = world.contract_subject_bindings.view();
            for (key, value) in view.iter() {
                let key_handle = TieredKeyHandle::ContractSubjectBinding((*key).clone());
                let key_payload = norito::codec::Encode::encode(key);
                self.collect_entry_with_encoded_key(
                    TieredSegment::ContractSubjectBindings,
                    &key_handle,
                    key_payload,
                    value,
                    &mut ctx,
                )?;
            }
        }
        collect_map!(
            TieredSegment::ContractAliasBindings,
            ContractAliasBinding,
            world.contract_alias_bindings
        );
        collect_map!(
            TieredSegment::SmartContractState,
            SmartContractState,
            world.smart_contract_state
        );
        collect_map!(TieredSegment::ZkAssets, ZkAsset, world.zk_assets);
        collect_map!(TieredSegment::Elections, Election, world.elections);
        collect_map!(
            TieredSegment::MinistryAgendaProposals,
            MinistryAgendaProposal,
            world.ministry_agenda_proposals
        );
        collect_map!(
            TieredSegment::GovernanceProposals,
            GovernanceProposal,
            world.governance_proposals
        );
        collect_map!(
            TieredSegment::GovernanceReferenda,
            GovernanceReferendum,
            world.governance_referenda
        );
        collect_map!(
            TieredSegment::GovernanceLocks,
            GovernanceLock,
            world.governance_locks
        );
        collect_map!(
            TieredSegment::GovernanceSlashes,
            GovernanceSlash,
            world.governance_slashes
        );
        collect_map!(
            TieredSegment::ParliamentAttempts,
            ParliamentAttempt,
            world.parliament_attempts
        );
        collect_map!(
            TieredSegment::TleKeySessions,
            TleKeySession,
            world.tle_key_sessions
        );
        collect_map!(
            TieredSegment::TleKeySessionRosters,
            TleKeySessionRoster,
            world.tle_key_session_rosters
        );
        collect_map!(
            TieredSegment::TleKeySessionLifecycles,
            TleKeySessionLifecycle,
            world.tle_key_session_lifecycles
        );
        collect_map!(
            TieredSegment::TleActiveKeySession,
            TleActiveKeySession,
            world.tle_active_key_session
        );
        collect_map!(
            TieredSegment::TimedOvnEvidence,
            TimedOvnEvidence,
            world.timed_ovn_evidence
        );
        collect_map!(
            TieredSegment::ValidatorCommitteeTransitions,
            ValidatorCommitteeTransition,
            world.validator_committee_transitions
        );
        collect_map!(
            TieredSegment::GlobalBeaconDkg,
            GlobalBeaconDkg,
            world.global_beacon_dkg
        );
        collect_map!(
            TieredSegment::GlobalBeaconKeySessions,
            GlobalBeaconKeySession,
            world.global_beacon_key_sessions
        );
        collect_map!(
            TieredSegment::GlobalBeaconActiveSession,
            GlobalBeaconActiveSession,
            world.global_beacon_active_session
        );
        collect_map!(
            TieredSegment::GlobalBeaconLatestPulse,
            GlobalBeaconLatestPulse,
            world.global_beacon_latest_pulse
        );
        collect_map!(
            TieredSegment::GlobalBeaconPulses,
            GlobalBeaconPulse,
            world.global_beacon_pulses
        );
        Ok(())
    }
    #[cfg(test)]
    fn collect_entry<K, V>(
        &mut self,
        segment: TieredSegment,
        key_handle: &TieredKeyHandle,
        key: &K,
        value: &V,
        ctx: &mut CollectContext,
    ) -> Result<()>
    where
        K: norito::codec::Encode,
        V: json::JsonSerialize + MeasuredBytes,
    {
        let key_encoded = norito::codec::Encode::encode(key);
        self.collect_entry_with_encoded_key(segment, key_handle, key_encoded, value, ctx)
    }
    #[cfg(test)]
    fn collect_entry_with_encoded_key<V>(
        &mut self,
        segment: TieredSegment,
        key_handle: &TieredKeyHandle,
        key_encoded: Vec<u8>,
        value: &V,
        ctx: &mut CollectContext,
    ) -> Result<()>
    where
        V: json::JsonSerialize + MeasuredBytes,
    {
        let key_hash = sha256(&key_encoded);
        let id = TieredEntryId::new(segment, key_hash);
        let (value_hash, _json_len) =
            compute_json_hash(value).wrap_err("failed to encode value for tiered snapshot")?;
        let value_size_bytes =
            compute_hot_bytes(value).wrap_err("failed to compute WSV hot-tier size estimate")?;
        let meta = self
            .entries
            .entry(id)
            .or_insert_with(|| EntryMetadata::new(ctx.snapshot_idx, value_hash, value_size_bytes));
        if meta.last_value_hash != value_hash {
            meta.last_value_hash = value_hash;
            meta.last_mutated_snapshot = ctx.snapshot_idx;
        }
        meta.last_present_snapshot = ctx.snapshot_idx;
        meta.value_size_bytes = value_size_bytes;
        self.entry_keys.insert(
            id,
            EntryKey {
                key: key_handle.clone(),
                key_encoded: key_encoded.clone(),
            },
        );
        ctx.seen.insert(id);
        ctx.scores.push(EntryScore {
            id,
            segment,
            key: key_handle.clone(),
            key_encoded,
        });
        Ok(())
    }
    fn write_manifest(snapshot_dir: &Path, manifest: &TieredSnapshotManifest) -> Result<()> {
        let manifest_bytes = norito::json::to_vec_pretty(manifest)
            .wrap_err("failed to serialize tiered state manifest")?;
        let manifest_path = snapshot_dir.join("manifest.json");
        let temp_path = snapshot_dir.join("manifest.json.tmp");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .wrap_err_with(|| {
                format!(
                    "failed to open manifest temp file {path}",
                    path = temp_path.display()
                )
            })?;
        file.write_all(&manifest_bytes).wrap_err_with(|| {
            format!(
                "failed to write manifest temp file {path}",
                path = temp_path.display()
            )
        })?;
        file.flush().wrap_err_with(|| {
            format!(
                "failed to flush manifest temp file {path}",
                path = temp_path.display()
            )
        })?;
        file.sync_data().wrap_err_with(|| {
            format!(
                "failed to sync manifest temp file {path}",
                path = temp_path.display()
            )
        })?;
        fs::rename(&temp_path, &manifest_path).wrap_err_with(|| {
            format!(
                "failed to promote manifest file {path}",
                path = manifest_path.display()
            )
        })
    }
    /// Prune cold snapshots to fit within an explicit byte budget.
    pub(crate) fn prune_cold_snapshots_to_bytes(&self, max_bytes: u64) -> Result<()> {
        let Some(root) = self.primary_cold_root().cloned() else {
            return Ok(());
        };
        if !root.exists() {
            return Ok(());
        }
        self.prune_snapshots_to_bytes(&root, max_bytes)
    }
    fn prune_old_snapshots(&self, root: &Path) -> Result<()> {
        if self.max_snapshots == 0 {
            return Ok(());
        }
        let mut pruned = false;
        let mut entries = fs::read_dir(root)
            .wrap_err_with(|| {
                format!(
                    "failed to read cold tier root {path}",
                    path = root.display()
                )
            })?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(std::fs::FileType::is_dir)
                    .and_then(|_| Self::parse_snapshot_dir_name(&entry.file_name()))
                    .map(|idx| (idx, entry))
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(idx, _)| *idx);
        while entries.len() > self.max_snapshots {
            if let Some((_, entry)) = entries.first() {
                fs::remove_dir_all(entry.path()).with_context(|| {
                    format!(
                        "failed to prune tiered snapshot directory {path}",
                        path = entry.path().display()
                    )
                })?;
                pruned = true;
            }
            entries.remove(0);
        }
        if pruned {
            Self::sync_dir(root).wrap_err_with(|| {
                format!(
                    "failed to sync tiered snapshot root after prune {path}",
                    path = root.display()
                )
            })?;
        }
        Ok(())
    }
    fn prune_to_cold_bytes(&self, root: &Path) -> Result<()> {
        if self.max_cold_bytes == 0 {
            return Ok(());
        }
        self.prune_snapshots_to_bytes(root, self.max_cold_bytes)
    }
    fn prune_snapshots_to_bytes(&self, root: &Path, max_bytes: u64) -> Result<()> {
        if max_bytes == 0 && !root.exists() {
            return Ok(());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(root).wrap_err_with(|| {
            format!(
                "failed to read tiered snapshot root {path}",
                path = root.display()
            )
        })? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            if let Some(idx) = Self::parse_snapshot_dir_name(&entry.file_name()) {
                entries.push((idx, entry.path()));
            }
        }
        entries.sort_by_key(|(idx, _)| *idx);
        let mut total_bytes = 0u64;
        let mut sizes = Vec::with_capacity(entries.len());
        for (idx, path) in entries {
            let size = Self::snapshot_dir_size(&path)?;
            total_bytes = total_bytes.saturating_add(size);
            sizes.push((idx, path, size));
        }
        let mut pruned = false;
        while total_bytes > max_bytes && sizes.len() > 1 {
            let (idx, path, size) = sizes.remove(0);
            if let Some(da_root) = self.da_store_root_for_offload() {
                Self::offload_snapshot_dir(&path, da_root, idx)?;
                self.record_da_churn(DA_CHURN_EVICTED, size);
            } else {
                fs::remove_dir_all(&path).wrap_err_with(|| {
                    format!(
                        "failed to prune tiered snapshot directory {path}",
                        path = path.display()
                    )
                })?;
            }
            total_bytes = total_bytes.saturating_sub(size);
            pruned = true;
        }
        if total_bytes > max_bytes && sizes.len() == 1 {
            let (_, path, size) = &sizes[0];
            iroha_logger::warn!(
                budget = max_bytes,
                remaining = *size,
                path = %path.display(),
                "tiered-state: cold snapshot exceeds configured byte budget"
            );
        }
        if pruned {
            Self::sync_dir(root).wrap_err_with(|| {
                format!(
                    "failed to sync tiered snapshot root after cold prune {path}",
                    path = root.display()
                )
            })?;
        }
        Ok(())
    }
    fn snapshot_dir_size(path: &Path) -> Result<u64> {
        let mut total = 0u64;
        for entry in fs::read_dir(path).wrap_err_with(|| {
            format!(
                "failed to read snapshot directory {path}",
                path = path.display()
            )
        })? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let entry_path = entry.path();
            if file_type.is_dir() {
                total = total.saturating_add(Self::snapshot_dir_size(&entry_path)?);
            } else if file_type.is_file() {
                total = total.saturating_add(entry.metadata()?.len());
            }
        }
        Ok(total)
    }
    fn copy_dir_recursive(source: &Path, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest).wrap_err_with(|| {
            format!(
                "failed to create snapshot offload directory {path}",
                path = dest.display()
            )
        })?;
        for entry in fs::read_dir(source).wrap_err_with(|| {
            format!(
                "failed to read snapshot directory {path}",
                path = source.display()
            )
        })? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let from = entry.path();
            let to = dest.join(entry.file_name());
            if file_type.is_dir() {
                Self::copy_dir_recursive(&from, &to)?;
            } else if file_type.is_file() {
                if to.exists() {
                    fs::remove_file(&to).wrap_err_with(|| {
                        format!("failed to remove existing file {path}", path = to.display())
                    })?;
                }
                fs::copy(&from, &to).wrap_err_with(|| {
                    format!(
                        "failed to copy snapshot file from {from} to {to}",
                        from = from.display(),
                        to = to.display()
                    )
                })?;
            } else {
                iroha_logger::warn!(
                    path = %from.display(),
                    "tiered-state: skipping unsupported snapshot entry during offload"
                );
            }
        }
        Ok(())
    }
    fn is_cross_device_link(err: &std::io::Error) -> bool {
        #[cfg(unix)]
        {
            err.raw_os_error() == Some(18)
        }
        #[cfg(windows)]
        {
            err.raw_os_error() == Some(17)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = err;
            false
        }
    }
    fn offload_snapshot_dir(source: &Path, dest_root: &Path, idx: u64) -> Result<()> {
        fs::create_dir_all(dest_root).wrap_err_with(|| {
            format!(
                "failed to prepare DA snapshot root {path}",
                path = dest_root.display()
            )
        })?;
        let dest = dest_root.join(format!("{idx:020}"));
        if dest.exists() {
            fs::remove_dir_all(&dest).wrap_err_with(|| {
                format!(
                    "failed to remove existing DA snapshot directory {path}",
                    path = dest.display()
                )
            })?;
        }
        match fs::rename(source, &dest) {
            Ok(()) => {}
            Err(err) if Self::is_cross_device_link(&err) => {
                let staging = dest.with_extension("staging");
                if staging.exists() {
                    fs::remove_dir_all(&staging).wrap_err_with(|| {
                        format!(
                            "failed to clear DA snapshot staging directory {path}",
                            path = staging.display()
                        )
                    })?;
                }
                Self::copy_dir_recursive(source, &staging)?;
                fs::rename(&staging, &dest).wrap_err_with(|| {
                    format!(
                        "failed to promote DA snapshot directory {path}",
                        path = dest.display()
                    )
                })?;
                fs::remove_dir_all(source).wrap_err_with(|| {
                    format!(
                        "failed to remove cold snapshot directory {path}",
                        path = source.display()
                    )
                })?;
            }
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!(
                        "failed to offload snapshot directory {path}",
                        path = source.display()
                    )
                });
            }
        }
        if let Some(parent) = dest.parent() {
            Self::sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync DA snapshot root {path}",
                    path = parent.display()
                )
            })?;
        }
        if let Some(parent) = source.parent() {
            Self::sync_dir(parent).wrap_err_with(|| {
                format!(
                    "failed to sync cold snapshot root {path}",
                    path = parent.display()
                )
            })?;
        }
        Ok(())
    }
    fn try_reuse_cold_payload(source: &Path, dest: &Path) -> Result<Option<u64>> {
        let metadata = match fs::metadata(source) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!(
                        "failed to read cold shard metadata from {path}",
                        path = source.display()
                    )
                });
            }
        };
        if !metadata.is_file() {
            return Ok(None);
        }
        if dest.exists() {
            fs::remove_file(dest).wrap_err_with(|| {
                format!(
                    "failed to remove existing cold shard at {path}",
                    path = dest.display()
                )
            })?;
        }
        match fs::hard_link(source, dest) {
            Ok(()) => {
                let file = fs::File::open(dest).wrap_err_with(|| {
                    format!(
                        "failed to open hard-linked cold shard {path} for syncing",
                        path = dest.display()
                    )
                })?;
                file.sync_all().wrap_err_with(|| {
                    format!(
                        "failed to sync hard-linked cold shard {path}",
                        path = dest.display()
                    )
                })?;
                Ok(Some(metadata.len()))
            }
            Err(link_err) => {
                iroha_logger::debug!(
                    ?link_err,
                    source = %source.display(),
                    dest = %dest.display(),
                    "tiered-state: hard-link reuse failed; falling back to copy"
                );
                let bytes = fs::copy(source, dest).wrap_err_with(|| {
                    format!(
                        "failed to copy cold shard from {source} to {dest}",
                        source = source.display(),
                        dest = dest.display()
                    )
                })?;
                let file = fs::File::open(dest).wrap_err_with(|| {
                    format!(
                        "failed to open copied cold shard {path} for syncing",
                        path = dest.display()
                    )
                })?;
                file.sync_all().wrap_err_with(|| {
                    format!(
                        "failed to sync copied cold shard {path}",
                        path = dest.display()
                    )
                })?;
                Ok(Some(bytes))
            }
        }
    }
    fn parse_snapshot_dir_name(name: &std::ffi::OsStr) -> Option<u64> {
        let name = name.to_str()?;
        if name.len() != 20 || !name.as_bytes().iter().all(u8::is_ascii_digit) {
            return None;
        }
        name.parse::<u64>().ok()
    }
    fn sync_dir(path: &Path) -> Result<()> {
        let file = fs::File::open(path).wrap_err_with(|| {
            format!(
                "failed to open directory {path} for syncing",
                path = path.display()
            )
        })?;
        file.sync_all()
            .wrap_err_with(|| format!("failed to sync directory {path}", path = path.display()))
    }
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}
#[cfg(test)]
fn compute_json_hash(value: &impl json::JsonSerialize) -> Result<([u8; 32], usize)> {
    let encoded = json::to_vec(value).wrap_err("failed to encode snapshot value as JSON")?;
    Ok((sha256(&encoded), encoded.len()))
}
/// Deterministic byte estimate for hot-tier sizing.
pub(crate) trait MeasuredBytes {
    /// Return the total measured byte footprint used for hot-tier budgeting.
    fn measured_bytes(&self) -> usize;
    /// Return bytes beyond the stack size of the value.
    fn measured_bytes_extra(&self) -> usize
    where
        Self: Sized,
    {
        self.measured_bytes()
            .saturating_sub(std::mem::size_of::<Self>())
    }
}
#[allow(clippy::unnecessary_wraps)]
#[cfg(test)]
fn compute_hot_bytes(value: &impl MeasuredBytes) -> Result<usize> {
    Ok(value.measured_bytes())
}
mod measured_bytes_impls {
    use super::MeasuredBytes;
    use crate::state::SmartContractCodeUploadDescriptor;
    use crate::{
        beacon::{
            GlobalThresholdBeaconDkgSnapshotV1, GlobalThresholdBeaconPulseLinkV1,
            RetainedFinalizedGlobalThresholdBeaconSessionV1,
        },
        governance::{parliament::ParliamentAttemptStateV1, timed_ovn::TimedOvnLifecycleStateV1},
        privacy_state::{
            PrivacyPgcAccountProvenanceV1, PrivacyPgcAccountStateV1, PrivacyPgcPoolInvariantV1,
            PrivacyRootHeadRecordV1, PrivacyRootProvenanceV1, PrivacyStateItemRecordV1,
        },
        private_settlement::{
            global_state::{
                PrivateSettlementFinalizationReferenceV1, PrivateSettlementOutputRecordV1,
                PrivateSettlementRootProvenanceV1, PrivateSettlementStagedLockRecordV1,
            },
            state::{PrivateSettlementPoolGovernanceProjectionV1, PrivateSettlementPoolStateV1},
        },
        smartcontracts::code::ContractSubjectBinding,
        state::{
            AssetDefinitionAliasBindingRecord, ConfidentialTreeProfile, ContractAliasBindingRecord,
            ElectionState, FrontierCheckpoint, GovernanceLockCustody, GovernanceLockRecord,
            GovernanceLocksForReferendum, GovernanceProposalRecord, GovernanceProposalStatus,
            GovernanceReferendumMode, GovernanceReferendumRecord, GovernanceReferendumStatus,
            GovernanceSlashEntry, GovernanceSlashLedger, StandaloneBallotCorpusEntryV1,
            ZkAssetState, ZkAssetVerifierBinding,
        },
        tle_release::{TleKeySessionLifecycleV1, TleKeySessionPublicStateV1},
    };
    use iroha_crypto::{
        Hash, HashOf, LaneCommitmentId, MerkleProof, MerkleTree, PublicKey, Signature, SignatureOf,
    };
    use iroha_data_model::{
        account::{
            AccountAlias, AccountController, AccountDetails, AccountId, AccountRecoveryPolicy,
            AccountRecoveryRequest, AccountRecoveryStatus, AccountRekeyRecord,
            AccountRekeyTransitionProvenance, MultisigMember, MultisigPolicy, OpaqueAccountId,
            RecoveryGuardian, rekey::AccountAliasDomain,
        },
        asset::{
            AssetDefinition, AssetDefinitionDirectHomeV1, AssetDefinitionId, AssetId,
            definition::{
                AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
                Mintable,
            },
        },
        bridge::{
            BridgeHashFunction, BridgeIcsProof, BridgeProof, BridgeProofPayload, BridgeProofRange,
            BridgeProofRecord, BridgeTransparentProof,
        },
        common::Owned,
        confidential::ConfidentialStatus,
        consensus::FinalizedGlobalThresholdBeaconPulseV1,
        domain::Domain,
        events::EventFilterBox,
        governance::types::{
            AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ParliamentBody,
            ProposalKind, RuntimeUpgradeProposal, SccpRouteGovernanceProposal,
            SorafsProviderGovernanceProposal, TleKeySessionId,
            ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
        },
        ipfs::IpfsPath,
        nexus::{
            AxtAssetIncarnationV1, AxtHandleBudgetRecord, AxtHandleCounterRecord, AxtPolicyEntry,
            AxtReplayRecord, AxtSourceTransferReplayRecordV1, LanePrivacyMerkleWitness,
            LanePrivacyProof, LanePrivacyWitness, PrivateSettlementAbortReceiptV1,
            PrivateSettlementReceiptV1, UniversalAccountId,
        },
        nft::NftData,
        permission::Permission,
        privacy::PrivacyProtocolActivationRecordV1,
        proof::{
            ProofAttachment, ProofAttachmentList, ProofBox, ProofId, ProofRecord, ProofStatus,
            VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord,
        },
        role::{Role, RoleId},
        runtime::{
            RuntimeUpgradeId, RuntimeUpgradeManifest, RuntimeUpgradeRecord,
            RuntimeUpgradeSbomDigest, RuntimeUpgradeStatus,
        },
        rwa::{RwaControlPolicy, RwaData, RwaId, RwaParentRef},
        smart_contract::ContractAddress,
        smart_contract::manifest::{
            AccessSetHints, ContractErrorTypeDescriptor, ContractManifest,
            ContractPermissionDescriptorV1, ContractPermissionScopeV1, DynamicAccessHint,
            EntryPointKind, EntrypointAuthorizationV1, EntrypointDescriptor,
            EntrypointParamDescriptor, KotobaTranslation, KotobaTranslationEntry,
            ManifestProvenance, StateDescriptor, TriggerCallback, TriggerDescriptor,
        },
        sorafs_uri::SorafsUri,
        trigger::{TriggerId, action::Repeats},
        zk::BackendTag,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_model_base::peer::PeerId;
    use iroha_primitives::{
        bigint::BigInt,
        const_vec::ConstVec,
        conststr::ConstString,
        json::Json,
        numeric::{Numeric, NumericSpec, Quantity},
    };
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        mem::size_of,
        sync::Arc,
    };
    macro_rules! impl_measured_bytes_copy {
        ($($ty:ty),+ $(,)?) => {
            $(
                impl MeasuredBytes for $ty {
                    fn measured_bytes(&self) -> usize {
                        size_of::<$ty>()
                    }
                }
            )+
        };
    }
    fn slice_bytes<T: MeasuredBytes>(slice: &[T]) -> usize {
        let mut total = slice.len().saturating_mul(size_of::<T>());
        for item in slice {
            total = total.saturating_add(item.measured_bytes_extra());
        }
        total
    }
    impl_measured_bytes_copy!(
        (),
        bool,
        char,
        u8,
        u16,
        u32,
        u64,
        u128,
        usize,
        i8,
        i16,
        i32,
        i64,
        i128,
        isize,
        AbiVersion,
        AccountRekeyTransitionProvenance,
        BackendTag,
        BridgeHashFunction,
        ConfidentialPolicyMode,
        ConfidentialPolicyTransition,
        ConfidentialStatus,
        ConfidentialTreeProfile,
        ContractAbiHash,
        ContractCodeHash,
        iroha_data_model::smart_contract::ContractArtifactId,
        EntryPointKind,
        GovernanceReferendumMode,
        GovernanceReferendumStatus,
        GovernanceProposalStatus,
        GlobalThresholdBeaconPulseLinkV1,
        LaneCommitmentId,
        Mintable,
        NumericSpec,
        ParliamentBody,
        ProofStatus,
        Repeats,
        RuntimeUpgradeId,
        RuntimeUpgradeStatus,
        TleKeySessionId,
        TleKeySessionLifecycleV1,
        PrivacyProtocolActivationRecordV1,
        PrivacyPgcAccountProvenanceV1,
        PrivacyPgcAccountStateV1,
        PrivacyPgcPoolInvariantV1,
        PrivacyRootHeadRecordV1,
        PrivacyRootProvenanceV1,
        PrivacyStateItemRecordV1,
        AxtAssetIncarnationV1,
        AssetDefinitionDirectHomeV1,
        AxtHandleCounterRecord,
        AxtPolicyEntry,
        PrivateSettlementFinalizationReferenceV1,
    );
    macro_rules! impl_measured_bytes_canonical {
        ($($ty:ty),+ $(,)?) => {
            $(
                impl MeasuredBytes for $ty {
                    fn measured_bytes(&self) -> usize {
                        size_of::<$ty>().saturating_add(
                            norito::codec::Encode::encode(self).len(),
                        )
                    }
                }
            )+
        };
    }
    impl_measured_bytes_canonical!(
        PrivateSettlementPoolGovernanceProjectionV1,
        PrivateSettlementPoolStateV1,
        PrivateSettlementRootProvenanceV1,
        PrivateSettlementOutputRecordV1,
        PrivateSettlementStagedLockRecordV1,
        PrivateSettlementReceiptV1,
        PrivateSettlementAbortReceiptV1,
    );
    impl<T: MeasuredBytes, const N: usize> MeasuredBytes for [T; N] {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<[T; N]>();
            for item in self {
                total = total.saturating_add(item.measured_bytes_extra());
            }
            total
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for Option<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Option<T>>();
            if let Some(value) = self {
                total = total.saturating_add(value.measured_bytes_extra());
            }
            total
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for Owned<T> {
        fn measured_bytes(&self) -> usize {
            size_of::<Owned<T>>().saturating_add(self.0.measured_bytes_extra())
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for Vec<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Vec<T>>();
            total = total.saturating_add(self.capacity().saturating_mul(size_of::<T>()));
            for item in self {
                total = total.saturating_add(item.measured_bytes_extra());
            }
            total
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for VecDeque<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<VecDeque<T>>();
            total = total.saturating_add(self.capacity().saturating_mul(size_of::<T>()));
            for item in self {
                total = total.saturating_add(item.measured_bytes_extra());
            }
            total
        }
    }
    impl<K: MeasuredBytes, V: MeasuredBytes> MeasuredBytes for BTreeMap<K, V> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BTreeMap<K, V>>();
            for (key, value) in self {
                total = total.saturating_add(size_of::<K>());
                total = total.saturating_add(key.measured_bytes_extra());
                total = total.saturating_add(size_of::<V>());
                total = total.saturating_add(value.measured_bytes_extra());
            }
            total
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for BTreeSet<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BTreeSet<T>>();
            for item in self {
                total = total.saturating_add(size_of::<T>());
                total = total.saturating_add(item.measured_bytes_extra());
            }
            total
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for Box<T> {
        fn measured_bytes(&self) -> usize {
            size_of::<Box<T>>().saturating_add((**self).measured_bytes())
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for Arc<T> {
        fn measured_bytes(&self) -> usize {
            size_of::<Arc<T>>().saturating_add((**self).measured_bytes())
        }
    }
    impl<T: MeasuredBytes> MeasuredBytes for ConstVec<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ConstVec<T>>();
            total = total.saturating_add(self.len().saturating_mul(size_of::<T>()));
            for item in self {
                total = total.saturating_add(item.measured_bytes_extra());
            }
            total
        }
    }
    impl MeasuredBytes for ConstString {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ConstString>();
            if !self.is_inlined() {
                total = total.saturating_add(self.len());
            }
            total
        }
    }
    impl MeasuredBytes for ContractAddress {
        fn measured_bytes(&self) -> usize {
            size_of::<ContractAddress>().saturating_add(self.as_ref().len())
        }
    }
    impl MeasuredBytes for ContractSubjectBinding {
        fn measured_bytes(&self) -> usize {
            use iroha_data_model::smart_contract::{
                ContractDeploymentOriginV1, ContractLifecycleOwnerV1,
            };
            let mut total = size_of::<ContractSubjectBinding>()
                .saturating_add(self.subject.measured_bytes_extra());
            let mut add_owner = |owner: &ContractLifecycleOwnerV1| {
                if let ContractLifecycleOwnerV1::Account(account) = owner {
                    total = total.saturating_add(account.measured_bytes_extra());
                }
            };
            add_owner(&self.lifecycle.owner);
            if let Some(owner) = self.lifecycle.pending_owner.as_ref() {
                add_owner(owner);
            }
            match &self.lifecycle.origin {
                ContractDeploymentOriginV1::Direct(origin) => {
                    total = total.saturating_add(origin.deployer.measured_bytes_extra());
                }
                ContractDeploymentOriginV1::Parliament(origin) => {
                    let deployer = &origin.proposer;
                    total = total.saturating_add(deployer.measured_bytes_extra());
                }
            }
            if let Some(hold) = self.lifecycle.emergency_hold.as_ref() {
                total = total.saturating_add(hold.reason.capacity());
            }
            total
        }
    }
    impl MeasuredBytes for AssetDefinitionAliasBindingRecord {
        fn measured_bytes(&self) -> usize {
            size_of::<AssetDefinitionAliasBindingRecord>().saturating_add(self.alias.as_ref().len())
        }
    }
    impl MeasuredBytes for ContractAliasBindingRecord {
        fn measured_bytes(&self) -> usize {
            size_of::<ContractAliasBindingRecord>().saturating_add(self.alias.as_ref().len())
        }
    }
    impl MeasuredBytes for String {
        fn measured_bytes(&self) -> usize {
            size_of::<String>().saturating_add(self.capacity())
        }
    }
    impl MeasuredBytes for Json {
        fn measured_bytes(&self) -> usize {
            size_of::<Json>().saturating_add(self.get().capacity())
        }
    }
    impl MeasuredBytes for BigInt {
        fn measured_bytes(&self) -> usize {
            let bits = self.bit_len();
            let bytes = bits.saturating_add(7) / 8;
            size_of::<BigInt>().saturating_add(bytes)
        }
    }
    impl MeasuredBytes for Numeric {
        fn measured_bytes(&self) -> usize {
            size_of::<Numeric>().saturating_add(self.mantissa().measured_bytes_extra())
        }
    }
    impl MeasuredBytes for Quantity {
        fn measured_bytes(&self) -> usize {
            size_of::<Quantity>().saturating_add(self.mantissa().measured_bytes_extra())
        }
    }
    impl MeasuredBytes for AxtHandleBudgetRecord {
        fn measured_bytes(&self) -> usize {
            size_of::<AxtHandleBudgetRecord>()
                .saturating_add(self.consumed().measured_bytes_extra())
        }
    }
    impl MeasuredBytes for AxtReplayRecord {
        fn measured_bytes(&self) -> usize {
            size_of::<AxtReplayRecord>().saturating_add(self.budget_key.allocated_heap_bytes())
        }
    }
    impl MeasuredBytes for AxtSourceTransferReplayRecordV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<AxtSourceTransferReplayRecordV1>()
        }
    }
    impl<T> MeasuredBytes for HashOf<T> {
        fn measured_bytes(&self) -> usize {
            size_of::<HashOf<T>>()
        }
    }
    impl MeasuredBytes for Hash {
        fn measured_bytes(&self) -> usize {
            size_of::<Hash>()
        }
    }
    impl MeasuredBytes for OpaqueAccountId {
        fn measured_bytes(&self) -> usize {
            size_of::<OpaqueAccountId>()
        }
    }
    impl MeasuredBytes for PublicKey {
        fn measured_bytes(&self) -> usize {
            let payload_len = self.to_bytes().1.len();
            size_of::<PublicKey>().saturating_add(payload_len)
        }
    }
    impl MeasuredBytes for Signature {
        fn measured_bytes(&self) -> usize {
            size_of::<Signature>().saturating_add(self.payload().len())
        }
    }
    impl<T> MeasuredBytes for SignatureOf<T> {
        fn measured_bytes(&self) -> usize {
            size_of::<SignatureOf<T>>().saturating_add((**self).measured_bytes_extra())
        }
    }
    impl<T> MeasuredBytes for MerkleProof<T> {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<MerkleProof<T>>();
            total = total.saturating_add(
                self.audit_path()
                    .len()
                    .saturating_mul(size_of::<Option<HashOf<T>>>()),
            );
            total
        }
    }
    impl<T> MeasuredBytes for MerkleTree<T> {
        fn measured_bytes(&self) -> usize {
            let depth = self.depth();
            let nodes = if depth as usize >= usize::BITS as usize - 1 {
                usize::MAX
            } else {
                (1_usize << (depth + 1)) - 1
            };
            size_of::<MerkleTree<T>>()
                .saturating_add(nodes.saturating_mul(size_of::<Option<HashOf<T>>>()))
        }
    }
    impl MeasuredBytes for Name {
        fn measured_bytes(&self) -> usize {
            size_of::<Name>().saturating_add(self.as_ref().len())
        }
    }
    impl MeasuredBytes for TriggerId {
        fn measured_bytes(&self) -> usize {
            size_of::<TriggerId>().saturating_add(self.name.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for IpfsPath {
        fn measured_bytes(&self) -> usize {
            size_of::<IpfsPath>().saturating_add(self.as_ref().len())
        }
    }
    impl MeasuredBytes for SorafsUri {
        fn measured_bytes(&self) -> usize {
            size_of::<SorafsUri>().saturating_add(self.as_ref().len())
        }
    }
    impl MeasuredBytes for DomainId {
        fn measured_bytes(&self) -> usize {
            size_of::<DomainId>()
                .saturating_add(self.name().measured_bytes_extra())
                .saturating_add(self.dataspace().measured_bytes_extra())
        }
    }
    impl MeasuredBytes for AccountAliasDomain {
        fn measured_bytes(&self) -> usize {
            size_of::<AccountAliasDomain>().saturating_add(self.0.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for AccountAlias {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountAlias>();
            total = total.saturating_add(self.label.measured_bytes_extra());
            total = total.saturating_add(self.domain.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for UniversalAccountId {
        fn measured_bytes(&self) -> usize {
            size_of::<UniversalAccountId>()
        }
    }
    impl MeasuredBytes for AccountController {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountController>();
            match self {
                AccountController::Single(key) => {
                    total = total.saturating_add(key.measured_bytes_extra());
                }
                AccountController::Multisig(policy) => {
                    total = total.saturating_add(policy.measured_bytes_extra());
                }
            }
            total
        }
    }
    impl MeasuredBytes for MultisigMember {
        fn measured_bytes(&self) -> usize {
            size_of::<MultisigMember>().saturating_add(self.public_key().measured_bytes_extra())
        }
    }
    impl MeasuredBytes for MultisigPolicy {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<MultisigPolicy>();
            total = total.saturating_add(slice_bytes(self.members()));
            total
        }
    }
    impl MeasuredBytes for AccountId {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountId>();
            total = total.saturating_add(self.controller.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AssetDefinitionId {
        fn measured_bytes(&self) -> usize {
            size_of::<AssetDefinitionId>()
        }
    }
    impl MeasuredBytes for AssetId {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AssetId>();
            total = total.saturating_add(self.account.measured_bytes_extra());
            total = total.saturating_add(self.definition.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RoleId {
        fn measured_bytes(&self) -> usize {
            size_of::<RoleId>().saturating_add(self.name.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for PeerId {
        fn measured_bytes(&self) -> usize {
            size_of::<PeerId>().saturating_add(self.public_key.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for Metadata {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Metadata>();
            for (key, value) in self.iter() {
                total = total.saturating_add(size_of::<Name>());
                total = total.saturating_add(key.measured_bytes_extra());
                total = total.saturating_add(size_of::<Json>());
                total = total.saturating_add(value.measured_bytes_extra());
            }
            total
        }
    }
    impl MeasuredBytes for EventFilterBox {
        fn measured_bytes(&self) -> usize {
            size_of::<EventFilterBox>()
        }
    }
    impl MeasuredBytes for Permission {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Permission>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.payload.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AccountDetails {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountDetails>();
            total = total.saturating_add(self.metadata.measured_bytes_extra());
            total = total.saturating_add(self.label.measured_bytes_extra());
            total = total.saturating_add(self.uaid.measured_bytes_extra());
            total = total.saturating_add(self.opaque_ids.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AccountRekeyRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountRekeyRecord>();
            total = total.saturating_add(self.label.measured_bytes_extra());
            total = total.saturating_add(self.active_signatory.measured_bytes_extra());
            total = total.saturating_add(self.previous_account_ids.measured_bytes_extra());
            total = total.saturating_add(self.previous_signatories.measured_bytes_extra());
            total = total.saturating_add(self.transition_provenance.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RecoveryGuardian {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RecoveryGuardian>();
            total = total.saturating_add(self.account.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AccountRecoveryPolicy {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountRecoveryPolicy>();
            total = total.saturating_add(self.guardians.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AccountRecoveryStatus {
        fn measured_bytes(&self) -> usize {
            size_of::<AccountRecoveryStatus>()
        }
    }
    impl MeasuredBytes for AccountRecoveryRequest {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccountRecoveryRequest>();
            total = total.saturating_add(self.alias.measured_bytes_extra());
            total = total.saturating_add(self.active_account_id_at_proposal.measured_bytes_extra());
            total = total.saturating_add(self.proposed_controller.measured_bytes_extra());
            total = total.saturating_add(self.approvals.measured_bytes_extra());
            total = total.saturating_add(self.cancellation_approvals.measured_bytes_extra());
            total = total.saturating_add(self.proposed_by.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AssetConfidentialPolicy {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AssetConfidentialPolicy>();
            total = total.saturating_add(self.mode.measured_bytes_extra());
            total = total.saturating_add(self.vk_set_hash.measured_bytes_extra());
            total = total.saturating_add(self.poseidon_params_id.measured_bytes_extra());
            total = total.saturating_add(self.pedersen_params_id.measured_bytes_extra());
            total = total.saturating_add(self.pending_transition.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AssetDefinition {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AssetDefinition>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.spec.measured_bytes_extra());
            total = total.saturating_add(self.mintable.measured_bytes_extra());
            total = total.saturating_add(self.logo.measured_bytes_extra());
            total = total.saturating_add(self.metadata.measured_bytes_extra());
            total = total.saturating_add(self.owned_by.measured_bytes_extra());
            total = total.saturating_add(self.total_quantity.measured_bytes_extra());
            total = total.saturating_add(self.confidential_policy.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for Domain {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Domain>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.logo.measured_bytes_extra());
            total = total.saturating_add(self.metadata.measured_bytes_extra());
            total = total.saturating_add(self.owned_by.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for NftData {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<NftData>();
            total = total.saturating_add(self.content.measured_bytes_extra());
            total = total.saturating_add(self.owned_by.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RwaParentRef {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RwaParentRef>();
            total = total.saturating_add(self.rwa.measured_bytes_extra());
            total = total.saturating_add(self.quantity.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RwaId {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RwaId>();
            total = total.saturating_add(self.domain.measured_bytes_extra());
            total = total.saturating_add(self.hash.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RwaControlPolicy {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RwaControlPolicy>();
            total = total.saturating_add(self.controller_accounts.measured_bytes_extra());
            total = total.saturating_add(self.controller_roles.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RwaData {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RwaData>();
            total = total.saturating_add(self.quantity.measured_bytes_extra());
            total = total.saturating_add(self.spec.measured_bytes_extra());
            total = total.saturating_add(self.primary_reference.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total = total.saturating_add(self.metadata.measured_bytes_extra());
            total = total.saturating_add(self.parents.measured_bytes_extra());
            total = total.saturating_add(self.controls.measured_bytes_extra());
            total = total.saturating_add(self.owned_by.measured_bytes_extra());
            total = total.saturating_add(self.is_frozen.measured_bytes_extra());
            total = total.saturating_add(self.held_quantity.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for Role {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<Role>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.permissions.measured_bytes_extra());
            total = total.saturating_add(self.permission_epochs.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for VerifyingKeyId {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<VerifyingKeyId>();
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.name.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for VerifyingKeyBox {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<VerifyingKeyBox>();
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.bytes.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for VerifyingKeyRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<VerifyingKeyRecord>();
            total = total.saturating_add(self.circuit_id.measured_bytes_extra());
            total = total.saturating_add(self.owner_manifest_id.measured_bytes_extra());
            total = total.saturating_add(self.namespace.measured_bytes_extra());
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.curve.measured_bytes_extra());
            total = total.saturating_add(self.public_inputs_schema_hash.measured_bytes_extra());
            total = total.saturating_add(self.commitment.measured_bytes_extra());
            total = total.saturating_add(self.vk_len.measured_bytes_extra());
            total = total.saturating_add(self.max_proof_bytes.measured_bytes_extra());
            total = total.saturating_add(self.gas_schedule_id.measured_bytes_extra());
            total = total.saturating_add(self.metadata_uri_cid.measured_bytes_extra());
            total = total.saturating_add(self.vk_bytes_cid.measured_bytes_extra());
            total = total.saturating_add(self.activation_height.measured_bytes_extra());
            total = total.saturating_add(self.withdraw_height.measured_bytes_extra());
            total = total.saturating_add(self.key.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ProofBox {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProofBox>();
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.bytes.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ProofId {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProofId>();
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.proof_hash.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for BridgeIcsProof {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BridgeIcsProof>();
            total = total.saturating_add(self.verifier_manifest_hash.measured_bytes_extra());
            total = total.saturating_add(self.state_root.measured_bytes_extra());
            total = total.saturating_add(self.leaf_hash.measured_bytes_extra());
            total = total.saturating_add(self.proof.measured_bytes_extra());
            total = total.saturating_add(self.hash_function.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for BridgeTransparentProof {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BridgeTransparentProof>();
            total = total.saturating_add(self.verifier_manifest_hash.measured_bytes_extra());
            total = total.saturating_add(self.proof.measured_bytes_extra());
            total = total.saturating_add(self.recursion_depth.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for BridgeProofPayload {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BridgeProofPayload>();
            match self {
                BridgeProofPayload::Ics(proof) => {
                    total = total.saturating_add(proof.measured_bytes_extra());
                }
                BridgeProofPayload::TransparentZk(proof) => {
                    total = total.saturating_add(proof.measured_bytes_extra());
                }
            }
            total
        }
    }
    impl MeasuredBytes for BridgeProofRange {
        fn measured_bytes(&self) -> usize {
            size_of::<BridgeProofRange>()
        }
    }
    impl MeasuredBytes for BridgeProof {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BridgeProof>();
            total = total.saturating_add(self.range.measured_bytes_extra());
            total = total.saturating_add(self.payload.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for BridgeProofRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<BridgeProofRecord>();
            total = total.saturating_add(self.proof.measured_bytes_extra());
            total = total.saturating_add(self.commitment.measured_bytes_extra());
            total = total.saturating_add(self.size_bytes.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ProofRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProofRecord>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.vk_ref.measured_bytes_extra());
            total = total.saturating_add(self.vk_commitment.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total = total.saturating_add(self.verified_at_height.measured_bytes_extra());
            total = total.saturating_add(self.bridge.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RuntimeUpgradeSbomDigest {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RuntimeUpgradeSbomDigest>();
            total = total.saturating_add(self.algorithm.measured_bytes_extra());
            total = total.saturating_add(self.digest.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RuntimeUpgradeManifest {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RuntimeUpgradeManifest>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.description.measured_bytes_extra());
            total = total.saturating_add(self.abi_version.measured_bytes_extra());
            total = total.saturating_add(self.abi_hash.measured_bytes_extra());
            total = total.saturating_add(self.added_syscalls.measured_bytes_extra());
            total = total.saturating_add(self.added_pointer_types.measured_bytes_extra());
            total = total.saturating_add(self.start_height.measured_bytes_extra());
            total = total.saturating_add(self.end_height.measured_bytes_extra());
            total = total.saturating_add(self.sbom_digests.measured_bytes_extra());
            total = total.saturating_add(self.slsa_attestation.measured_bytes_extra());
            total = total.saturating_add(self.provenance.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RuntimeUpgradeRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RuntimeUpgradeRecord>();
            total = total.saturating_add(self.manifest.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total = total.saturating_add(self.proposer.measured_bytes_extra());
            total = total.saturating_add(self.created_height.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for AccessSetHints {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<AccessSetHints>();
            total = total.saturating_add(self.read_keys.measured_bytes_extra());
            total = total.saturating_add(self.write_keys.measured_bytes_extra());
            total = total.saturating_add(self.dynamic_reads.measured_bytes_extra());
            total = total.saturating_add(self.dynamic_writes.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for DynamicAccessHint {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<DynamicAccessHint>();
            total = total.saturating_add(self.base_key.measured_bytes_extra());
            total = total.saturating_add(self.key_type.measured_bytes_extra());
            total = total.saturating_add(self.bound_kind.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for TriggerCallback {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<TriggerCallback>();
            total = total.saturating_add(self.namespace.measured_bytes_extra());
            total = total.saturating_add(self.entrypoint.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for TriggerDescriptor {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<TriggerDescriptor>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.repeats.measured_bytes_extra());
            total = total.saturating_add(self.filter.measured_bytes_extra());
            total = total.saturating_add(self.authority.measured_bytes_extra());
            total = total.saturating_add(self.metadata.measured_bytes_extra());
            total = total.saturating_add(self.callback.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for EntrypointDescriptor {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<EntrypointDescriptor>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.kind.measured_bytes_extra());
            total = total.saturating_add(self.params.measured_bytes_extra());
            total = total.saturating_add(self.return_type.measured_bytes_extra());
            total = total.saturating_add(self.authorization.measured_bytes_extra());
            total = total.saturating_add(self.read_keys.measured_bytes_extra());
            total = total.saturating_add(self.write_keys.measured_bytes_extra());
            total = total.saturating_add(self.access_hints_complete.measured_bytes_extra());
            total = total.saturating_add(self.access_hints_skipped.measured_bytes_extra());
            total = total.saturating_add(self.triggers.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for EntrypointAuthorizationV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>().saturating_add(match self {
                Self::Permission(name) => name.measured_bytes_extra(),
                Self::Anyone | Self::RuntimeLifecycle => 0,
            })
        }
    }
    impl MeasuredBytes for ContractPermissionScopeV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>().saturating_add(match self {
                Self::Chain { permission_name } => permission_name.measured_bytes_extra(),
                Self::Instance => 0,
            })
        }
    }
    impl MeasuredBytes for ContractPermissionDescriptorV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>()
                .saturating_add(self.name.measured_bytes_extra())
                .saturating_add(self.scope.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for EntrypointParamDescriptor {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<EntrypointParamDescriptor>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.type_name.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for StateDescriptor {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<StateDescriptor>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.type_name.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ContractErrorTypeDescriptor {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ContractErrorTypeDescriptor>();
            total = total.saturating_add(self.identity.measured_bytes_extra());
            total = total.saturating_add(self.variants.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::smart_contract::manifest::ContractErrorVariantDescriptor {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>().saturating_add(self.name.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for KotobaTranslation {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<KotobaTranslation>();
            total = total.saturating_add(self.lang.measured_bytes_extra());
            total = total.saturating_add(self.text.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::smart_contract::manifest::ContractErrorMessage {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>()
                .saturating_add(self.error_type.measured_bytes_extra())
                .saturating_add(self.message.measured_bytes_extra())
        }
    }
    impl MeasuredBytes for KotobaTranslationEntry {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<KotobaTranslationEntry>();
            total = total.saturating_add(self.msg_id.measured_bytes_extra());
            total = total.saturating_add(self.translations.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ManifestProvenance {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ManifestProvenance>();
            total = total.saturating_add(self.signer.measured_bytes_extra());
            total = total.saturating_add(self.signature.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ContractManifest {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ContractManifest>();
            total = total.saturating_add(self.seiyaku_name.measured_bytes_extra());
            total = total.saturating_add(self.code_hash.measured_bytes_extra());
            total = total.saturating_add(self.abi_hash.measured_bytes_extra());
            total = total.saturating_add(self.compiler_fingerprint.measured_bytes_extra());
            total = total.saturating_add(self.features_bitmap.measured_bytes_extra());
            total = total.saturating_add(self.access_set_hints.measured_bytes_extra());
            total = total.saturating_add(self.permissions.measured_bytes_extra());
            total = total.saturating_add(self.entrypoints.measured_bytes_extra());
            total = total.saturating_add(self.states.measured_bytes_extra());
            total = total.saturating_add(self.error_types.measured_bytes_extra());
            total = total.saturating_add(self.error_messages.measured_bytes_extra());
            total = total.saturating_add(self.kotoba.measured_bytes_extra());
            total = total.saturating_add(self.provenance.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for SmartContractCodeUploadDescriptor {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>()
        }
    }
    impl MeasuredBytes for ZkAssetVerifierBinding {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ZkAssetVerifierBinding>();
            total = total.saturating_add(self.id.measured_bytes_extra());
            total = total.saturating_add(self.commitment.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for FrontierCheckpoint {
        fn measured_bytes(&self) -> usize {
            size_of::<FrontierCheckpoint>()
        }
    }
    impl MeasuredBytes for ZkAssetState {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ZkAssetState>();
            total = total.saturating_add(self.tree_profile.measured_bytes_extra());
            total = total.saturating_add(self.tree_frontier.measured_bytes_extra());
            total = total.saturating_add(self.persisted_root.measured_bytes_extra());
            total = total.saturating_add(self.commitments.measured_bytes_extra());
            total = total.saturating_add(self.root_history.measured_bytes_extra());
            total = total.saturating_add(self.nullifiers.measured_bytes_extra());
            total = total.saturating_add(self.vk_unshield.measured_bytes_extra());
            total = total.saturating_add(self.frontier_checkpoints.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for StandaloneBallotCorpusEntryV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<Self>()
        }
    }
    impl MeasuredBytes for ElectionState {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ElectionState>();
            total = total.saturating_add(self.options.measured_bytes_extra());
            total = total.saturating_add(self.eligible_root.measured_bytes_extra());
            total = total.saturating_add(self.start_ts.measured_bytes_extra());
            total = total.saturating_add(self.end_ts.measured_bytes_extra());
            total = total.saturating_add(self.finalized.measured_bytes_extra());
            total = total.saturating_add(self.tally.measured_bytes_extra());
            total = total.saturating_add(self.accepted_ballots.measured_bytes_extra());
            total = total.saturating_add(self.vk_ballot.measured_bytes_extra());
            total = total.saturating_add(self.vk_ballot_commitment.measured_bytes_extra());
            total = total.saturating_add(self.vk_tally.measured_bytes_extra());
            total = total.saturating_add(self.vk_tally_commitment.measured_bytes_extra());
            total = total.saturating_add(self.domain_tag.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for DeployContractProposal {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<DeployContractProposal>();
            total = total.saturating_add(self.proposal_operator.measured_bytes_extra());
            total = total.saturating_add(self.contract_address.measured_bytes_extra());
            total = total.saturating_add(self.code_hash.measured_bytes_extra());
            total = total.saturating_add(self.abi_hash.measured_bytes_extra());
            total = total.saturating_add(self.abi_version.measured_bytes_extra());
            total = total.saturating_add(self.manifest_provenance.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for RuntimeUpgradeProposal {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<RuntimeUpgradeProposal>();
            total = total.saturating_add(self.proposal_operator.measured_bytes_extra());
            total = total.saturating_add(self.manifest.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for SccpRouteGovernanceProposal {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<SccpRouteGovernanceProposal>();
            total = total.saturating_add(norito::codec::Encode::encode(&self.proposal).len());
            total
        }
    }
    impl MeasuredBytes for SorafsProviderGovernanceProposal {
        fn measured_bytes(&self) -> usize {
            size_of::<SorafsProviderGovernanceProposal>()
                .saturating_add(norito::codec::Encode::encode(&self.action).len())
        }
    }
    impl MeasuredBytes for ValidationFeePolicyProposal {
        fn measured_bytes(&self) -> usize {
            size_of::<ValidationFeePolicyProposal>()
                .saturating_add(norito::codec::Encode::encode(&self.proposal_operator).len())
                .saturating_add(norito::codec::Encode::encode(&self.policy).len())
        }
    }
    impl MeasuredBytes for ValidationFeePayoutLifecycleProposal {
        fn measured_bytes(&self) -> usize {
            size_of::<ValidationFeePayoutLifecycleProposal>()
                .saturating_add(norito::codec::Encode::encode(&self.proposal_operator).len())
                .saturating_add(norito::codec::Encode::encode(&self.payout_binding).len())
        }
    }
    impl MeasuredBytes for ProposalKind {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProposalKind>();
            match self {
                ProposalKind::DeployContract(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::RuntimeUpgrade(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::SccpRouteGovernance(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::SorafsProviderGovernance(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::ValidationFeePolicy(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::ValidationFeePayoutLifecycle(payload) => {
                    total = total.saturating_add(payload.measured_bytes_extra());
                }
                ProposalKind::MusubiRegistryGovernance(action) => {
                    total = total.saturating_add(norito::codec::Encode::encode(action).len());
                }
                ProposalKind::ContractLifecycleGovernance(payload) => {
                    total = total.saturating_add(norito::codec::Encode::encode(payload).len());
                }
                ProposalKind::ContractEmergencyHold(payload) => {
                    total = total.saturating_add(norito::codec::Encode::encode(payload).len());
                }
                ProposalKind::GlobalDataTriggerPermissionGovernance(payload) => {
                    total = total.saturating_add(norito::codec::Encode::encode(payload).len());
                }
            }
            total
        }
    }
    impl MeasuredBytes for GovernanceProposalRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceProposalRecord>();
            total = total.saturating_add(self.proposer.measured_bytes_extra());
            total = total.saturating_add(self.kind.measured_bytes_extra());
            total = total.saturating_add(self.created_height.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalAction {
        fn measured_bytes(&self) -> usize {
            size_of::<iroha_data_model::ministry::AgendaProposalAction>()
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaEvidenceKind {
        fn measured_bytes(&self) -> usize {
            size_of::<iroha_data_model::ministry::AgendaEvidenceKind>()
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalSummary {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaProposalSummary>();
            total = total.saturating_add(self.title.measured_bytes_extra());
            total = total.saturating_add(self.motivation.measured_bytes_extra());
            total = total.saturating_add(self.expected_impact.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalTarget {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaProposalTarget>();
            total = total.saturating_add(self.label.measured_bytes_extra());
            total = total.saturating_add(self.hash_family.measured_bytes_extra());
            total = total.saturating_add(self.hash_hex.measured_bytes_extra());
            total = total.saturating_add(self.reason.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaEvidenceAttachment {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaEvidenceAttachment>();
            total = total.saturating_add(self.kind.measured_bytes_extra());
            total = total.saturating_add(self.uri.measured_bytes_extra());
            total = total.saturating_add(self.digest_blake3_hex.measured_bytes_extra());
            total = total.saturating_add(self.description.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalSubmitter {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaProposalSubmitter>();
            total = total.saturating_add(self.name.measured_bytes_extra());
            total = total.saturating_add(self.contact.measured_bytes_extra());
            total = total.saturating_add(self.organization.measured_bytes_extra());
            total = total.saturating_add(self.pgp_fingerprint.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalV1 {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaProposalV1>();
            total = total.saturating_add(self.version.measured_bytes_extra());
            total = total.saturating_add(self.proposal_id.measured_bytes_extra());
            total = total.saturating_add(self.submitted_at_unix_ms.measured_bytes_extra());
            total = total.saturating_add(self.language.measured_bytes_extra());
            total = total.saturating_add(self.action.measured_bytes_extra());
            total = total.saturating_add(self.summary.measured_bytes_extra());
            total = total.saturating_add(self.tags.measured_bytes_extra());
            total = total.saturating_add(self.targets.measured_bytes_extra());
            total = total.saturating_add(self.evidence.measured_bytes_extra());
            total = total.saturating_add(self.submitter.measured_bytes_extra());
            total = total.saturating_add(self.duplicates.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for iroha_data_model::ministry::AgendaProposalRecordV1 {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<iroha_data_model::ministry::AgendaProposalRecordV1>();
            total = total.saturating_add(self.proposal.measured_bytes_extra());
            total = total.saturating_add(self.authority.measured_bytes_extra());
            total = total.saturating_add(self.submitted_tx_hash_hex.measured_bytes_extra());
            total = total.saturating_add(self.submitted_height.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for GovernanceReferendumRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceReferendumRecord>();
            total = total.saturating_add(self.h_start.measured_bytes_extra());
            total = total.saturating_add(self.h_end.measured_bytes_extra());
            total = total.saturating_add(self.status.measured_bytes_extra());
            total = total.saturating_add(self.mode.measured_bytes_extra());
            if let iroha_data_model::governance::conviction::PlainVotingContextV1::Conviction(
                policy,
            ) = &self.plain_context
            {
                total = total.saturating_add(policy.minimum_bond.measured_bytes_extra());
                total = total.saturating_add(policy.bond_escrow_account.measured_bytes_extra());
                total = total.saturating_add(policy.slash_receiver_account.measured_bytes_extra());
            }
            total
        }
    }
    impl MeasuredBytes for GovernanceLockRecord {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceLockRecord>();
            total = total.saturating_add(self.owner.measured_bytes_extra());
            total = total.saturating_add(self.amount.measured_bytes_extra());
            total = total.saturating_add(self.slashed.measured_bytes_extra());
            total = total.saturating_add(self.expiry_height.measured_bytes_extra());
            total = total.saturating_add(self.direction.measured_bytes_extra());
            total = total.saturating_add(self.duration_blocks.measured_bytes_extra());
            total = total.saturating_add(self.custody.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for GovernanceLockCustody {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceLockCustody>();
            total = total.saturating_add(self.escrowed.measured_bytes_extra());
            total = total.saturating_add(self.asset_definition_id.measured_bytes_extra());
            total = total.saturating_add(self.bond_escrow_account.measured_bytes_extra());
            total = total.saturating_add(self.slash_receiver_account.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for GovernanceLocksForReferendum {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceLocksForReferendum>();
            total = total.saturating_add(self.locks.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for GovernanceSlashEntry {
        fn measured_bytes(&self) -> usize {
            size_of::<GovernanceSlashEntry>()
        }
    }
    impl MeasuredBytes for GovernanceSlashLedger {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<GovernanceSlashLedger>();
            total = total.saturating_add(self.slashes.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ParliamentAttemptStateV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<ParliamentAttemptStateV1>()
                .saturating_add(norito::codec::Encode::encode(self).len())
        }
    }
    impl MeasuredBytes for TleKeySessionPublicStateV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<TleKeySessionPublicStateV1>()
                .saturating_add(norito::codec::Encode::encode(self).len())
        }
    }
    impl MeasuredBytes for TimedOvnLifecycleStateV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<TimedOvnLifecycleStateV1>()
                .saturating_add(norito::codec::Encode::encode(self).len())
        }
    }
    impl MeasuredBytes for GlobalThresholdBeaconDkgSnapshotV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<GlobalThresholdBeaconDkgSnapshotV1>()
                .saturating_add(norito::codec::Encode::encode(self).len())
        }
    }
    impl MeasuredBytes for iroha_data_model::nexus::ValidatorCommitteeTransitionV1 {
        fn measured_bytes(&self) -> usize {
            let preparation = &self.preparation;
            let mut bytes = size_of::<Self>()
                .saturating_add(
                    preparation.committee.capacity().saturating_mul(size_of::<
                        iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1,
                    >()),
                )
                .saturating_add(
                    preparation
                        .eligibility
                        .xor_asset_definition_id
                        .measured_bytes_extra(),
                )
                .saturating_add(preparation.eligibility.min_self_bond.measured_bytes_extra())
                .saturating_add(
                    preparation
                        .eligibility
                        .min_nomination_bond
                        .measured_bytes_extra(),
                )
                .saturating_add(self.readiness.capacity().saturating_mul(size_of::<
                    iroha_data_model::nexus::ValidatorCommitteeSeatReadinessV1,
                >()));
            for seat in &preparation.committee {
                bytes = bytes
                    .saturating_add(seat.validator.measured_bytes_extra())
                    .saturating_add(seat.proof_of_possession.measured_bytes_extra());
            }
            bytes
        }
    }
    impl MeasuredBytes for RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<RetainedFinalizedGlobalThresholdBeaconSessionV1>()
                .saturating_add(self.session.retained_allocation_bytes())
        }
    }
    impl MeasuredBytes for FinalizedGlobalThresholdBeaconPulseV1 {
        fn measured_bytes(&self) -> usize {
            size_of::<FinalizedGlobalThresholdBeaconPulseV1>()
                .saturating_add(norito::codec::Encode::encode(self).len())
        }
    }
    impl MeasuredBytes for ProofAttachment {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProofAttachment>();
            total = total.saturating_add(self.backend.measured_bytes_extra());
            total = total.saturating_add(self.proof.measured_bytes_extra());
            total = total.saturating_add(self.vk_ref.measured_bytes_extra());
            total = total.saturating_add(self.vk_commitment.measured_bytes_extra());
            total = total.saturating_add(self.envelope_hash.measured_bytes_extra());
            total = total.saturating_add(self.lane_privacy.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for ProofAttachmentList {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<ProofAttachmentList>();
            total =
                total.saturating_add(self.capacity().saturating_mul(size_of::<ProofAttachment>()));
            for attachment in self.as_slice() {
                total = total.saturating_add(attachment.measured_bytes_extra());
            }
            total
        }
    }
    impl MeasuredBytes for LanePrivacyMerkleWitness {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<LanePrivacyMerkleWitness>();
            total = total.saturating_add(self.leaf.measured_bytes_extra());
            total = total.saturating_add(self.proof.measured_bytes_extra());
            total
        }
    }
    impl MeasuredBytes for LanePrivacyWitness {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<LanePrivacyWitness>();
            match self {
                LanePrivacyWitness::Merkle(witness) => {
                    total = total.saturating_add(witness.measured_bytes_extra());
                }
            }
            total
        }
    }
    impl MeasuredBytes for LanePrivacyProof {
        fn measured_bytes(&self) -> usize {
            let mut total = size_of::<LanePrivacyProof>();
            total = total.saturating_add(self.commitment_id.measured_bytes_extra());
            total = total.saturating_add(self.witness.measured_bytes_extra());
            total
        }
    }
}
fn lane_snapshot_dir(root: &Path, entry: &LaneConfigEntry) -> PathBuf {
    root.join(&entry.kura_segment)
}
fn unique_retired_lane_path(base: &Path, stem: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0);
    let mut counter = 0u32;
    loop {
        let name = if counter == 0 {
            format!("{stem}_{stamp}")
        } else {
            format!("{stem}_{stamp}_{counter}")
        };
        let candidate = base.join(&name);
        if !candidate.exists() {
            return candidate;
        }
        counter = counter.saturating_add(1);
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TieredSegment {
    Domains,
    Accounts,
    AccountRekeyRecords,
    AccountRecoveryPolicies,
    AccountRecoveryRequests,
    AssetDefinitions,
    AssetDefinitionAliasBindings,
    Assets,
    AssetMetadata,
    AxtPolicies,
    AxtHandleCounters,
    AxtAssetIncarnations,
    AssetDefinitionDirectHomes,
    AxtReplayLedger,
    AxtSpendNonceLedger,
    AxtSourceTransferReplayLedger,
    AxtHandleBudgetLedger,
    Nfts,
    Rwas,
    Roles,
    AccountPermissions,
    AccountRoles,
    TxSequences,
    VerifyingKeys,
    RuntimeUpgrades,
    PrivacyActivations,
    PrivacyPgcAccounts,
    PrivacyPgcPoolInvariants,
    PrivacyNullifiers,
    PrivacyCommitments,
    PrivacyRoots,
    PrivacyRootHeads,
    KagemushaWalletLedger,
    PrivateSettlementGovernance,
    PrivateSettlementPools,
    PrivateSettlementRoots,
    PrivateSettlementNullifiers,
    PrivateSettlementOutputs,
    PrivateSettlementStagedLocks,
    PrivateSettlementReceipts,
    PrivateSettlementAborts,
    Proofs,
    ProofTags,
    ProofsByTag,
    ContractManifests,
    ContractCode,
    ContractCodeUploads,
    ContractCodeUploadChunks,
    ContractInstances,
    ContractSubjectBindings,
    ContractAliasBindings,
    SmartContractState,
    ZkAssets,
    Elections,
    MinistryAgendaProposals,
    GovernanceProposals,
    GovernanceReferenda,
    GovernanceLocks,
    GovernanceSlashes,
    ParliamentAttempts,
    TleKeySessions,
    TleKeySessionRosters,
    TleKeySessionLifecycles,
    TleActiveKeySession,
    TimedOvnEvidence,
    ValidatorCommitteeTransitions,
    GlobalBeaconDkg,
    GlobalBeaconKeySessions,
    GlobalBeaconActiveSession,
    GlobalBeaconLatestPulse,
    GlobalBeaconPulses,
}
/// Every tiered segment in key-handle declaration order: segment variant, key-handle variant,
/// on-disk directory name and backing `World` storage field. Each consumer expands its own
/// exhaustive `match` from this single table, so the mappings cannot drift apart.
macro_rules! tiered_segment_table {
    ($callback:ident) => {
        $callback! {
            Domains, Domain, "domains", domains;
            Accounts, Account, "accounts", accounts;
            AccountRekeyRecords, AccountRekey, "account_rekey_records", account_rekey_records;
            AccountRecoveryPolicies, AccountRecoveryPolicy, "account_recovery_policies", account_recovery_policies;
            AccountRecoveryRequests, AccountRecoveryRequest, "account_recovery_requests", account_recovery_requests;
            AssetDefinitions, AssetDefinition, "asset_definitions", asset_definitions;
            AssetDefinitionAliasBindings, AssetDefinitionAliasBinding, "asset_definition_alias_bindings", asset_definition_alias_bindings;
            Assets, Asset, "assets", assets;
            AssetMetadata, AssetMetadata, "asset_metadata", asset_metadata;
            AxtPolicies, AxtPolicy, "axt_policies", axt_policies;
            AxtHandleCounters, AxtHandleCounter, "axt_handle_counters", axt_handle_counters;
            AxtAssetIncarnations, AxtAssetIncarnation, "axt_asset_incarnations", axt_asset_incarnations;
            AssetDefinitionDirectHomes, AssetDefinitionDirectHome, "asset_definition_direct_homes", asset_definition_direct_homes;
            AxtReplayLedger, AxtReplay, "axt_replay_ledger", axt_replay_ledger;
            AxtSpendNonceLedger, AxtSpendNonce, "axt_spend_nonce_ledger", axt_spend_nonce_ledger;
            AxtSourceTransferReplayLedger, AxtSourceTransferReplay, "axt_source_transfer_replay_ledger", axt_source_transfer_replay_ledger;
            AxtHandleBudgetLedger, AxtHandleBudget, "axt_handle_budget_ledger", axt_handle_budget_ledger;
            Nfts, Nft, "nfts", nfts;
            Rwas, Rwa, "rwas", rwas;
            Roles, Role, "roles", roles;
            AccountPermissions, AccountPermission, "account_permissions", account_permissions;
            AccountRoles, AccountRole, "account_roles", account_roles;
            TxSequences, TxSequence, "tx_sequences", tx_sequences;
            VerifyingKeys, VerifyingKey, "verifying_keys", verifying_keys;
            RuntimeUpgrades, RuntimeUpgrade, "runtime_upgrades", runtime_upgrades;
            PrivacyActivations, PrivacyActivation, "privacy_activations", privacy_activations;
            PrivacyPgcAccounts, PrivacyPgcAccount, "privacy_pgc_accounts", privacy_pgc_accounts;
            PrivacyPgcPoolInvariants, PrivacyPgcPoolInvariant, "privacy_pgc_pool_invariants", privacy_pgc_pool_invariants;
            PrivacyNullifiers, PrivacyNullifier, "privacy_nullifiers", privacy_nullifiers;
            PrivacyCommitments, PrivacyCommitment, "privacy_commitments", privacy_commitments;
            PrivacyRoots, PrivacyRoot, "privacy_roots", privacy_roots;
            PrivacyRootHeads, PrivacyRootHead, "privacy_root_heads", privacy_root_heads;
            KagemushaWalletLedger, KagemushaWalletLedger, "kagemusha_wallet_ledger", kagemusha_wallet_ledger;
            PrivateSettlementGovernance, PrivateSettlementGovernance, "private_settlement_governance", private_settlement_governance;
            PrivateSettlementPools, PrivateSettlementPool, "private_settlement_pools", private_settlement_pools;
            PrivateSettlementRoots, PrivateSettlementRoot, "private_settlement_roots", private_settlement_roots;
            PrivateSettlementNullifiers, PrivateSettlementNullifier, "private_settlement_nullifiers", private_settlement_nullifiers;
            PrivateSettlementOutputs, PrivateSettlementOutput, "private_settlement_outputs", private_settlement_outputs;
            PrivateSettlementStagedLocks, PrivateSettlementStagedLock, "private_settlement_staged_locks", private_settlement_staged_locks;
            PrivateSettlementReceipts, PrivateSettlementReceipt, "private_settlement_receipts", private_settlement_receipts;
            PrivateSettlementAborts, PrivateSettlementAbort, "private_settlement_aborts", private_settlement_aborts;
            Proofs, Proof, "proofs", proofs;
            ProofTags, ProofTag, "proof_tags", proof_tags;
            ProofsByTag, ProofByTag, "proofs_by_tag", proofs_by_tag;
            ContractManifests, ContractManifest, "contract_manifests", contract_manifests;
            ContractCode, ContractCode, "contract_code", contract_code;
            ContractCodeUploads, ContractCodeUpload, "contract_code_uploads", contract_code_uploads;
            ContractCodeUploadChunks, ContractCodeUploadChunk, "contract_code_upload_chunks", contract_code_upload_chunks;
            ContractInstances, ContractInstance, "contract_instances", contract_instances;
            ContractSubjectBindings, ContractSubjectBinding, "contract_subject_bindings", contract_subject_bindings;
            ContractAliasBindings, ContractAliasBinding, "contract_alias_bindings", contract_alias_bindings;
            SmartContractState, SmartContractState, "smart_contract_state", smart_contract_state;
            ZkAssets, ZkAsset, "zk_assets", zk_assets;
            Elections, Election, "elections", elections;
            MinistryAgendaProposals, MinistryAgendaProposal, "ministry_agenda_proposals", ministry_agenda_proposals;
            GovernanceProposals, GovernanceProposal, "governance_proposals", governance_proposals;
            GovernanceReferenda, GovernanceReferendum, "governance_referenda", governance_referenda;
            GovernanceLocks, GovernanceLock, "governance_locks", governance_locks;
            GovernanceSlashes, GovernanceSlash, "governance_slashes", governance_slashes;
            ParliamentAttempts, ParliamentAttempt, "parliament_attempts", parliament_attempts;
            TleKeySessions, TleKeySession, "tle_key_sessions", tle_key_sessions;
            TleKeySessionRosters, TleKeySessionRoster, "tle_key_session_rosters", tle_key_session_rosters;
            TleKeySessionLifecycles, TleKeySessionLifecycle, "tle_key_session_lifecycles", tle_key_session_lifecycles;
            TleActiveKeySession, TleActiveKeySession, "tle_active_key_session", tle_active_key_session;
            TimedOvnEvidence, TimedOvnEvidence, "timed_ovn_evidence", timed_ovn_evidence;
            ValidatorCommitteeTransitions, ValidatorCommitteeTransition, "validator_committee_transitions", validator_committee_transitions;
            GlobalBeaconDkg, GlobalBeaconDkg, "global_beacon_dkg", global_beacon_dkg;
            GlobalBeaconKeySessions, GlobalBeaconKeySession, "global_beacon_key_sessions", global_beacon_key_sessions;
            GlobalBeaconActiveSession, GlobalBeaconActiveSession, "global_beacon_active_session", global_beacon_active_session;
            GlobalBeaconLatestPulse, GlobalBeaconLatestPulse, "global_beacon_latest_pulse", global_beacon_latest_pulse;
            GlobalBeaconPulses, GlobalBeaconPulse, "global_beacon_pulses", global_beacon_pulses;
        }
    };
}
impl TieredSegment {
    fn dir_name(self) -> &'static str {
        macro_rules! dir_names {
            ($($segment:ident, $handle:ident, $dir:literal, $field:ident;)*) => {
                match self {
                    $(TieredSegment::$segment => $dir,)*
                }
            };
        }
        tiered_segment_table!(dir_names)
    }
}
impl norito::json::JsonSerialize for TieredSegment {
    fn json_serialize(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.dir_name(), out);
    }
}
impl norito::json::JsonDeserialize for TieredSegment {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let name = <String as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        macro_rules! segment_for_dir_name {
            ($($segment:ident, $handle:ident, $dir:literal, $field:ident;)*) => {
                match name.as_str() {
                    $($dir => TieredSegment::$segment,)*
                    other => {
                        return Err(norito::json::Error::InvalidField {
                            field: "segment".into(),
                            message: format!("unknown tiered segment `{other}`"),
                        });
                    }
                }
            };
        }
        let segment = tiered_segment_table!(segment_for_dir_name);
        Ok(segment)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TieredEntryId {
    segment: TieredSegment,
    key_hash: [u8; 32],
}
impl TieredEntryId {
    fn new(segment: TieredSegment, key_hash: [u8; 32]) -> Self {
        Self { segment, key_hash }
    }
}
impl fmt::Display for TieredEntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.segment.dir_name(),
            self.key_hash.encode_hex::<String>()
        )
    }
}
#[derive(Debug, Clone)]
struct EntryMetadata {
    last_present_snapshot: u64,
    last_mutated_snapshot: u64,
    last_hot_snapshot: u64,
    hot_until_snapshot: u64,
    last_cold_snapshot: u64,
    last_cold_rel_path: Option<PathBuf>,
    last_value_hash: [u8; 32],
    value_size_bytes: usize,
}
impl EntryMetadata {
    fn new(snapshot_idx: u64, value_hash: [u8; 32], value_size_bytes: usize) -> Self {
        Self {
            last_present_snapshot: snapshot_idx,
            last_mutated_snapshot: snapshot_idx,
            last_hot_snapshot: 0,
            hot_until_snapshot: 0,
            last_cold_snapshot: 0,
            last_cold_rel_path: None,
            last_value_hash: value_hash,
            value_size_bytes,
        }
    }
}
impl PartialEq for EntryMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.last_present_snapshot == other.last_present_snapshot
            && self.last_mutated_snapshot == other.last_mutated_snapshot
            && self.last_hot_snapshot == other.last_hot_snapshot
            && self.hot_until_snapshot == other.hot_until_snapshot
            && self.last_cold_snapshot == other.last_cold_snapshot
            && self.last_cold_rel_path == other.last_cold_rel_path
            && self.last_value_hash == other.last_value_hash
            && self.value_size_bytes == other.value_size_bytes
    }
}
impl Eq for EntryMetadata {}
impl PartialOrd for EntryMetadata {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EntryMetadata {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.last_mutated_snapshot
            .cmp(&other.last_mutated_snapshot)
            .then_with(|| self.last_present_snapshot.cmp(&other.last_present_snapshot))
            .then_with(|| self.last_hot_snapshot.cmp(&other.last_hot_snapshot))
            .then_with(|| self.hot_until_snapshot.cmp(&other.hot_until_snapshot))
            .then_with(|| other.value_size_bytes.cmp(&self.value_size_bytes))
    }
}
#[derive(Debug, Clone)]
struct EntryKey {
    key: TieredKeyHandle,
    key_encoded: Vec<u8>,
}
impl EntryKey {
    fn score(&self, id: TieredEntryId) -> EntryScore {
        EntryScore {
            id,
            segment: id.segment,
            key: self.key.clone(),
            key_encoded: self.key_encoded.clone(),
        }
    }
}
#[derive(Debug, Clone)]
struct EntryScore {
    id: TieredEntryId,
    segment: TieredSegment,
    key: TieredKeyHandle,
    key_encoded: Vec<u8>,
}
impl EntryScore {
    fn manifest_entry(
        &self,
        meta: &EntryMetadata,
        spill: Option<(PathBuf, u64)>,
    ) -> TieredManifestEntry {
        let (spill_path, spill_bytes) = match spill {
            Some((path, bytes)) => (Some(path), Some(bytes)),
            None => (None, None),
        };
        TieredManifestEntry {
            segment: self.segment,
            key_hash_hex: self.id.key_hash.encode_hex::<String>(),
            key_payload: self.key_encoded.clone(),
            value_size_bytes: meta.value_size_bytes,
            last_present_snapshot: meta.last_present_snapshot,
            last_mutated_snapshot: meta.last_mutated_snapshot,
            value_hash_hex: meta.last_value_hash.encode_hex::<String>(),
            spill_path,
            spill_bytes,
        }
    }
    fn relative_payload_path(&self, snapshot_idx: u64) -> PathBuf {
        let mut path = PathBuf::from(self.segment.dir_name());
        path.push(format!(
            "{}-{}.bin",
            snapshot_idx,
            self.id.key_hash.encode_hex::<String>()
        ));
        path
    }
    #[cfg(test)]
    fn encode_value(&self, world: &World) -> Result<Vec<u8>> {
        self.key.encode_value(world)
    }
}
/// Key handle for tiered snapshot entries.
#[derive(Debug, Clone)]
pub(crate) enum TieredKeyHandle {
    Domain(iroha_model_base::domain::DomainId),
    Account(iroha_data_model::account::AccountId),
    AccountRekey(iroha_data_model::account::rekey::AccountAlias),
    AccountRecoveryPolicy(iroha_data_model::account::AccountAlias),
    AccountRecoveryRequest(iroha_data_model::account::AccountAlias),
    AssetDefinition(iroha_data_model::asset::AssetDefinitionId),
    AssetDefinitionAliasBinding(iroha_data_model::asset::AssetDefinitionId),
    Asset(iroha_data_model::asset::AssetId),
    AssetMetadata(iroha_data_model::asset::AssetId),
    AxtPolicy(iroha_model_base::topology::DataSpaceId),
    AxtHandleCounter(iroha_model_base::topology::DataSpaceId),
    AxtAssetIncarnation(iroha_data_model::asset::AssetDefinitionId),
    AssetDefinitionDirectHome(iroha_data_model::asset::AssetDefinitionId),
    AxtReplay(iroha_data_model::nexus::AxtHandleReplayKey),
    AxtSpendNonce(iroha_data_model::nexus::AxtAnchoredSpendReplayKeyV1),
    AxtSourceTransferReplay(iroha_data_model::nexus::AxtSourceTransferReplayKeyV1),
    AxtHandleBudget(iroha_data_model::nexus::AxtHandleBudgetKey),
    Nft(iroha_data_model::nft::NftId),
    Rwa(iroha_data_model::rwa::RwaId),
    Role(iroha_data_model::role::RoleId),
    AccountPermission(iroha_data_model::account::AccountId),
    AccountRole(crate::role::RoleIdWithOwner),
    TxSequence(iroha_data_model::account::AccountId),
    VerifyingKey(iroha_data_model::proof::VerifyingKeyId),
    RuntimeUpgrade(iroha_data_model::runtime::RuntimeUpgradeId),
    PrivacyActivation(crate::privacy_state::PrivacyActivationKeyV1),
    PrivacyPgcAccount(crate::privacy_state::PrivacyPgcAccountKeyV1),
    PrivacyPgcPoolInvariant(crate::privacy_state::PrivacyPgcPoolInvariantKeyV1),
    PrivacyNullifier(crate::privacy_state::PrivacyNullifierKeyV1),
    PrivacyCommitment(crate::privacy_state::PrivacyCommitmentKeyV1),
    PrivacyRoot(crate::privacy_state::PrivacyRootKeyV1),
    PrivacyRootHead(crate::privacy_state::PrivacyRootHeadKeyV1),
    KagemushaWalletLedger(iroha_data_model::kagemusha::KagemushaWalletLedgerKeyV1),
    PrivateSettlementGovernance(
        crate::private_settlement::global_state::PrivateSettlementPoolKeyV1,
    ),
    PrivateSettlementPool(crate::private_settlement::global_state::PrivateSettlementPoolKeyV1),
    PrivateSettlementRoot(crate::private_settlement::global_state::PrivateSettlementRootKeyV1),
    PrivateSettlementNullifier(
        crate::private_settlement::global_state::PrivateSettlementNullifierKeyV1,
    ),
    PrivateSettlementOutput(crate::private_settlement::global_state::PrivateSettlementOutputKeyV1),
    PrivateSettlementStagedLock(
        crate::private_settlement::global_state::PrivateSettlementStagedLockKeyV1,
    ),
    PrivateSettlementReceipt(iroha_crypto::Hash),
    PrivateSettlementAbort(iroha_crypto::Hash),
    Proof(iroha_data_model::proof::ProofId),
    ProofTag(iroha_data_model::proof::ProofId),
    ProofByTag([u8; 4]),
    ContractManifest(iroha_data_model::smart_contract::ContractArtifactId),
    ContractCode(iroha_data_model::smart_contract::ContractArtifactId),
    ContractCodeUpload(super::SmartContractCodeUploadKey),
    ContractCodeUploadChunk(super::SmartContractCodeUploadChunkKey),
    ContractInstance(iroha_data_model::smart_contract::ContractAddress),
    ContractSubjectBinding(iroha_data_model::smart_contract::ContractAddress),
    ContractAliasBinding(iroha_data_model::smart_contract::ContractAddress),
    SmartContractState(StatePath),
    ZkAsset(iroha_data_model::asset::AssetDefinitionId),
    Election(String),
    MinistryAgendaProposal(String),
    GovernanceProposal([u8; 32]),
    GovernanceReferendum(String),
    GovernanceLock(String),
    GovernanceSlash(String),
    ParliamentAttempt(iroha_data_model::governance::types::GovernanceAttemptId),
    TleKeySession(iroha_data_model::governance::types::TleKeySessionId),
    TleKeySessionRoster(iroha_data_model::governance::types::TleKeySessionId),
    TleKeySessionLifecycle(iroha_data_model::governance::types::TleKeySessionId),
    TleActiveKeySession(u64),
    TimedOvnEvidence(iroha_data_model::governance::types::BallotAttemptId),
    ValidatorCommitteeTransition(u64),
    GlobalBeaconDkg([u8; 32]),
    GlobalBeaconKeySession([u8; 32]),
    GlobalBeaconActiveSession(u64),
    GlobalBeaconLatestPulse(u64),
    GlobalBeaconPulse([u8; 32]),
}
impl TieredKeyHandle {
    fn segment(&self) -> TieredSegment {
        macro_rules! handle_segments {
            ($($segment:ident, $handle:ident, $dir:literal, $field:ident;)*) => {
                match self {
                    $(TieredKeyHandle::$handle(_) => TieredSegment::$segment,)*
                }
            };
        }
        tiered_segment_table!(handle_segments)
    }
    fn encode_key(&self) -> Result<Vec<u8>> {
        match self {
            TieredKeyHandle::ContractInstance(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractSubjectBinding(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractAliasBinding(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Domain(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Account(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AccountRekey(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AccountRecoveryPolicy(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AccountRecoveryRequest(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AssetDefinition(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AssetDefinitionAliasBinding(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::Asset(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AssetMetadata(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtPolicy(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtHandleCounter(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtAssetIncarnation(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AssetDefinitionDirectHome(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::AxtReplay(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtSpendNonce(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtSourceTransferReplay(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AxtHandleBudget(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Nft(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Rwa(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Role(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AccountPermission(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::AccountRole(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TxSequence(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::VerifyingKey(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::RuntimeUpgrade(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyActivation(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyPgcAccount(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyPgcPoolInvariant(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyNullifier(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyCommitment(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyRoot(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivacyRootHead(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::KagemushaWalletLedger(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivateSettlementGovernance(key)
            | TieredKeyHandle::PrivateSettlementPool(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivateSettlementRoot(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivateSettlementNullifier(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::PrivateSettlementOutput(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::PrivateSettlementStagedLock(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::PrivateSettlementReceipt(key)
            | TieredKeyHandle::PrivateSettlementAbort(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::Proof(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ProofTag(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ProofByTag(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractManifest(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractCode(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractCodeUpload(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ContractCodeUploadChunk(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::SmartContractState(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ZkAsset(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::Election(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::MinistryAgendaProposal(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GovernanceProposal(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GovernanceReferendum(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GovernanceLock(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GovernanceSlash(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ParliamentAttempt(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TleKeySession(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TleKeySessionRoster(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TleKeySessionLifecycle(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TleActiveKeySession(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::TimedOvnEvidence(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::ValidatorCommitteeTransition(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::GlobalBeaconDkg(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GlobalBeaconKeySession(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GlobalBeaconActiveSession(key) => {
                Ok(norito::codec::Encode::encode(key))
            }
            TieredKeyHandle::GlobalBeaconLatestPulse(key) => Ok(norito::codec::Encode::encode(key)),
            TieredKeyHandle::GlobalBeaconPulse(key) => Ok(norito::codec::Encode::encode(key)),
        }
    }
    fn entry_id(&self) -> Result<(TieredEntryId, Vec<u8>)> {
        let key_encoded = self.encode_key()?;
        let key_hash = sha256(&key_encoded);
        Ok((TieredEntryId::new(self.segment(), key_hash), key_encoded))
    }
    #[cfg(test)]
    fn measure_value(&self, world: &World) -> Result<Option<([u8; 32], usize)>> {
        macro_rules! fetch {
            ($storage:expr, $key:expr) => {{
                let view = $storage.view();
                let Some(value) = view.get($key) else {
                    return Ok(None);
                };
                let (value_hash, _json_len) = compute_json_hash(value)
                    .wrap_err("failed to encode value for tiered snapshot")?;
                let value_size_bytes = compute_hot_bytes(value)
                    .wrap_err("failed to compute WSV hot-tier size estimate")?;
                Ok(Some((value_hash, value_size_bytes)))
            }};
        }
        macro_rules! fetch_segment_value {
            ($($segment:ident, $handle:ident, $dir:literal, $field:ident;)*) => {
                match self {
                    $(TieredKeyHandle::$handle(key) => fetch!(world.$field, key),)*
                }
            };
        }
        tiered_segment_table!(fetch_segment_value)
    }
    #[cfg(test)]
    fn encode_value(&self, world: &World) -> Result<Vec<u8>> {
        macro_rules! fetch {
            ($storage:expr, $key:expr) => {{
                let view = $storage.view();
                let Some(value) = view.get($key) else {
                    return Err(eyre::eyre!("tiered-state: missing value for {}", self));
                };
                let bytes = json::to_vec(value).wrap_err_with(|| {
                    format!("tiered-state: failed to encode payload for {}", self)
                })?;
                Ok(bytes)
            }};
        }
        macro_rules! fetch_segment_value {
            ($($segment:ident, $handle:ident, $dir:literal, $field:ident;)*) => {
                match self {
                    $(TieredKeyHandle::$handle(key) => fetch!(world.$field, key),)*
                }
            };
        }
        tiered_segment_table!(fetch_segment_value)
    }
}
impl fmt::Display for TieredKeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TieredKeyHandle::Domain(id) => write!(f, "domain:{id}"),
            TieredKeyHandle::Account(id) => write!(f, "account:{id}"),
            TieredKeyHandle::AccountRekey(id) => write!(f, "account_rekey:{id:?}"),
            TieredKeyHandle::AccountRecoveryPolicy(id) => {
                write!(f, "account_recovery_policy:{id:?}")
            }
            TieredKeyHandle::AccountRecoveryRequest(id) => {
                write!(f, "account_recovery_request:{id:?}")
            }
            TieredKeyHandle::AssetDefinition(id) => write!(f, "asset_definition:{id}"),
            TieredKeyHandle::AssetDefinitionAliasBinding(id) => {
                write!(f, "asset_definition_alias_binding:{id}")
            }
            TieredKeyHandle::Asset(id) => write!(f, "asset:{id}"),
            TieredKeyHandle::AssetMetadata(id) => write!(f, "asset_metadata:{id}"),
            TieredKeyHandle::AxtPolicy(id) => write!(f, "axt_policy:{id}"),
            TieredKeyHandle::AxtHandleCounter(id) => write!(f, "axt_handle_counter:{id}"),
            TieredKeyHandle::AxtAssetIncarnation(id) => {
                write!(f, "axt_asset_incarnation:{id}")
            }
            TieredKeyHandle::AssetDefinitionDirectHome(id) => {
                write!(f, "asset_definition_direct_home:{id}")
            }
            TieredKeyHandle::AxtReplay(id) => write!(
                f,
                "axt_replay:{}:{}:{}:{}",
                id.asset_dsid, id.handle_era, id.sub_nonce, id.target_lane
            ),
            TieredKeyHandle::AxtSpendNonce(id) => write!(
                f,
                "axt_spend_nonce:{}:{}",
                id.issuer_context.asset_dsid,
                hex::encode(id.nonce.as_bytes())
            ),
            TieredKeyHandle::AxtSourceTransferReplay(id) => write!(
                f,
                "axt_source_transfer_replay:{}:{}:{}:{}:{}",
                id.dataspace_id,
                id.lane_id,
                id.source_tx_index,
                id.transcript_index,
                id.delta_index
            ),
            TieredKeyHandle::AxtHandleBudget(id) => write!(
                f,
                "axt_handle_budget:{}:{}:{}",
                id.asset_dsid(),
                id.authorization_generation(),
                id.target_lane()
            ),
            TieredKeyHandle::Nft(id) => write!(f, "nft:{id}"),
            TieredKeyHandle::Rwa(id) => write!(f, "rwa:{id}"),
            TieredKeyHandle::Role(id) => write!(f, "role:{id}"),
            TieredKeyHandle::AccountPermission(id) => write!(f, "account_permission:{id}"),
            TieredKeyHandle::AccountRole(id) => write!(f, "account_role:{id}"),
            TieredKeyHandle::TxSequence(id) => write!(f, "tx_sequence:{id}"),
            TieredKeyHandle::VerifyingKey(id) => write!(f, "verifying_key:{id:?}"),
            TieredKeyHandle::RuntimeUpgrade(id) => write!(f, "runtime_upgrade:{id:?}"),
            TieredKeyHandle::PrivacyActivation(id) => {
                write!(f, "privacy_activation:{id:?}")
            }
            TieredKeyHandle::PrivacyPgcAccount(id) => {
                write!(f, "privacy_pgc_account:{id:?}")
            }
            TieredKeyHandle::PrivacyPgcPoolInvariant(id) => {
                write!(f, "privacy_pgc_pool_invariant:{id:?}")
            }
            TieredKeyHandle::PrivacyNullifier(id) => {
                write!(f, "privacy_nullifier:{id:?}")
            }
            TieredKeyHandle::PrivacyCommitment(id) => {
                write!(f, "privacy_commitment:{id:?}")
            }
            TieredKeyHandle::PrivacyRoot(id) => write!(f, "privacy_root:{id:?}"),
            TieredKeyHandle::PrivacyRootHead(id) => {
                write!(f, "privacy_root_head:{id:?}")
            }
            TieredKeyHandle::KagemushaWalletLedger(id) => {
                write!(f, "kagemusha_wallet_ledger:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementGovernance(id) => {
                write!(f, "private_settlement_governance:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementPool(id) => {
                write!(f, "private_settlement_pool:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementRoot(id) => {
                write!(f, "private_settlement_root:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementNullifier(id) => {
                write!(f, "private_settlement_nullifier:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementOutput(id) => {
                write!(f, "private_settlement_output:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementStagedLock(id) => {
                write!(f, "private_settlement_staged_lock:{id:?}")
            }
            TieredKeyHandle::PrivateSettlementReceipt(id) => {
                write!(f, "private_settlement_receipt:{id}")
            }
            TieredKeyHandle::PrivateSettlementAbort(id) => {
                write!(f, "private_settlement_abort:{id}")
            }
            TieredKeyHandle::Proof(id) => write!(f, "proof:{id}"),
            TieredKeyHandle::ProofTag(id) => write!(f, "proof_tag:{id}"),
            TieredKeyHandle::ProofByTag(tag) => write!(f, "proofs_by_tag:{tag:?}"),
            TieredKeyHandle::ContractManifest(hash) => write!(f, "contract_manifest:{hash:?}"),
            TieredKeyHandle::ContractCode(hash) => write!(f, "contract_code:{hash:?}"),
            TieredKeyHandle::ContractCodeUpload(key) => write!(
                f,
                "contract_code_upload:{}:{:?}",
                key.authority, key.artifact_id
            ),
            TieredKeyHandle::ContractCodeUploadChunk(key) => write!(
                f,
                "contract_code_upload_chunk:{}:{:?}:{}",
                key.upload.authority, key.upload.artifact_id, key.chunk_index
            ),
            TieredKeyHandle::ContractInstance(key) => write!(f, "contract_instance:{key:?}"),
            TieredKeyHandle::ContractSubjectBinding(key) => {
                write!(f, "contract_subject_binding:{key:?}")
            }
            TieredKeyHandle::ContractAliasBinding(key) => {
                write!(f, "contract_alias_binding:{key:?}")
            }
            TieredKeyHandle::SmartContractState(key) => write!(f, "smart_contract_state:{key}"),
            TieredKeyHandle::ZkAsset(id) => write!(f, "zk_asset:{id}"),
            TieredKeyHandle::Election(id) => write!(f, "election:{id}"),
            TieredKeyHandle::MinistryAgendaProposal(id) => {
                write!(f, "ministry_agenda_proposal:{id}")
            }
            TieredKeyHandle::GovernanceProposal(id) => write!(f, "gov_proposal:{id:?}"),
            TieredKeyHandle::GovernanceReferendum(id) => write!(f, "gov_referendum:{id}"),
            TieredKeyHandle::GovernanceLock(id) => write!(f, "gov_lock:{id}"),
            TieredKeyHandle::GovernanceSlash(id) => write!(f, "gov_slash:{id}"),
            TieredKeyHandle::ParliamentAttempt(id) => write!(f, "parliament_attempt:{id}"),
            TieredKeyHandle::TleKeySession(id) => write!(f, "tle_key_session:{id}"),
            TieredKeyHandle::TleKeySessionRoster(id) => {
                write!(f, "tle_key_session_roster:{id}")
            }
            TieredKeyHandle::TleKeySessionLifecycle(id) => {
                write!(f, "tle_key_session_lifecycle:{id}")
            }
            TieredKeyHandle::TleActiveKeySession(id) => {
                write!(f, "tle_active_key_session:{id}")
            }
            TieredKeyHandle::TimedOvnEvidence(id) => write!(f, "timed_ovn_evidence:{id}"),
            TieredKeyHandle::ValidatorCommitteeTransition(id) => {
                write!(f, "validator_committee_transitions:{id:?}")
            }
            TieredKeyHandle::GlobalBeaconDkg(id) => {
                write!(f, "global_beacon_dkg:{}", id.encode_hex::<String>())
            }
            TieredKeyHandle::GlobalBeaconKeySession(id) => {
                write!(f, "global_beacon_key_session:{}", id.encode_hex::<String>())
            }
            TieredKeyHandle::GlobalBeaconActiveSession(id) => {
                write!(f, "global_beacon_active_session:{id}")
            }
            TieredKeyHandle::GlobalBeaconLatestPulse(id) => {
                write!(f, "global_beacon_latest_pulse:{id}")
            }
            TieredKeyHandle::GlobalBeaconPulse(id) => {
                write!(f, "global_beacon_pulse:{}", id.encode_hex::<String>())
            }
        }
    }
}
/// Snapshot manifest describing hot/cold partitioning for a single capture.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
pub struct TieredSnapshotManifest {
    /// Monotonic snapshot index.
    pub snapshot_index: u64,
    /// Total number of tracked entries across storages.
    pub total_entries: usize,
    /// Entries retained in the hot tier.
    pub hot_entries: Vec<TieredManifestEntry>,
    /// Entries spilled to disk.
    pub cold_entries: Vec<TieredManifestEntry>,
    /// Total bytes written to the cold tier in the latest snapshot.
    pub cold_bytes_total: u64,
    /// Entries reused from a previous cold snapshot without re-encoding.
    pub cold_reused_entries: usize,
    /// Total bytes reused from a previous cold snapshot.
    pub cold_reused_bytes: u64,
    /// Entries promoted into the hot tier since the previous snapshot.
    pub hot_promotions: usize,
    /// Entries demoted into the cold tier since the previous snapshot.
    pub hot_demotions: usize,
    /// Hot-tier key budget overflow in the latest snapshot.
    pub hot_budget_overflow_keys: usize,
    /// Hot-tier byte budget overflow in the latest snapshot.
    pub hot_budget_overflow_bytes: u64,
}
/// Per-entry metadata persisted in manifests.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
pub struct TieredManifestEntry {
    segment: TieredSegment,
    key_hash_hex: String,
    key_payload: Vec<u8>,
    value_size_bytes: usize,
    last_present_snapshot: u64,
    last_mutated_snapshot: u64,
    value_hash_hex: String,
    spill_path: Option<PathBuf>,
    spill_bytes: Option<u64>,
}
include!("tiered_hot_byte_accounting.rs");
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contract_permission_metadata_accounts_for_every_owned_name() {
        use iroha_data_model::smart_contract::manifest::{
            ContractPermissionDescriptorV1, ContractPermissionScopeV1, EntrypointAuthorizationV1,
        };
        let declaration = ContractPermissionDescriptorV1 {
            name: "Operator".parse().unwrap(),
            scope: ContractPermissionScopeV1::Chain {
                permission_name: "SharedOperations".parse().unwrap(),
            },
        };
        assert_eq!(
            declaration.measured_bytes_extra(),
            "Operator".len() + "SharedOperations".len()
        );
        let policy = EntrypointAuthorizationV1::Permission("Operator".parse().unwrap());
        assert_eq!(policy.measured_bytes_extra(), "Operator".len());
        assert_eq!(EntrypointAuthorizationV1::Anyone.measured_bytes_extra(), 0);
        assert_eq!(
            EntrypointAuthorizationV1::RuntimeLifecycle.measured_bytes_extra(),
            0
        );
        let mut manifest = iroha_data_model::smart_contract::manifest::ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            seiyaku_name: None,
            code_hash: None,
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            permissions: Vec::new(),
            entrypoints: None,
            states: None,
            error_types: None,
            error_messages: None,
            kotoba: None,
            provenance: None,
        };
        let before = MeasuredBytes::measured_bytes(&manifest);
        manifest.permissions = vec![declaration];
        assert_eq!(
            MeasuredBytes::measured_bytes(&manifest) - before,
            manifest.permissions.measured_bytes_extra()
        );
    }
    use iroha_config::parameters::actual::LaneConfig as RuntimeLaneConfig;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        account::OpaqueAccountId,
        asset::AssetDefinitionId,
        block::BlockHeader,
        nexus::{
            AssetHandleIssuerPayloadV1, AxtAssetIncarnationV1, AxtBinding, AxtHandleBudgetKey,
            AxtHandleBudgetRecord, AxtHandleCounterRecord, AxtHandleIssuerContextV1, GroupBinding,
            HandleBudget, HandleSubject, LaneCatalog, LaneConfig,
        },
        proof::{ProofAttachment, ProofAttachmentList, ProofBox, VerifyingKeyId},
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_primitives::numeric::Quantity;
    use nonzero_ext::nonzero;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::{fs, num::NonZeroU32};
    use tempfile::tempdir;

    fn assert_retained_value(backend: &TieredStateBackend, key: &StatePath, value: &[u8]) {
        let encoded_key = TieredKeyHandle::SmartContractState(key.clone())
            .encode_key()
            .unwrap();
        let manifest = backend.last_manifest().expect("retained snapshot manifest");
        let entry = manifest
            .hot_entries
            .iter()
            .chain(&manifest.cold_entries)
            .find(|entry| {
                entry.segment == TieredSegment::SmartContractState
                    && entry.key_payload == encoded_key
            })
            .expect("retained state key");
        assert_eq!(
            entry.value_hash_hex,
            hex::encode(sha256(&json::to_vec(&value.to_vec()).unwrap()))
        );
    }

    fn wait_snapshot_worker_idle(worker: &super::super::TieredSnapshotWorker) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut pending = worker.inner.pending.lock();
        while pending.payload.is_some() || pending.processing {
            assert!(
                !worker
                    .inner
                    .cvar
                    .wait_until(&mut pending, deadline)
                    .timed_out(),
                "snapshot worker did not drain"
            );
        }
    }

    #[test]
    fn snapshot_worker_bounds_pending_work_without_losing_disjoint_or_later_updates() {
        use super::super::TieredSnapshotWorker;
        use std::sync::{Arc, mpsc};
        let temp = tempdir().unwrap();
        let backend = Arc::new(crate::publication_lock::PublicationMutex::new(
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0),
        ));
        backend
            .lock()
            .record_world_snapshot(&World::default())
            .unwrap();
        let worker = TieredSnapshotWorker::new(
            Arc::clone(&backend),
            #[cfg(feature = "telemetry")]
            None,
        );
        assert!(
            worker.enabled(),
            "regression requires a real background worker"
        );
        let (a, b) = (dummy_state_entry(201).0, dummy_state_entry(202).0);
        let payload = |key: &StatePath, value| {
            let mut payload = TieredSnapshotPayload::default();
            payload.push_value(
                TieredKeyHandle::SmartContractState(key.clone()),
                Some(vec![value]),
            );
            payload
        };
        // Holding only the backend blocks its I/O, not dequeue or capacity
        // notification. The worker never needs a State or World lock.
        let blocked_backend = backend.lock();
        assert!(worker.schedule(payload(&a, 1_u8)).is_ok());
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut pending = worker.inner.pending.lock();
            while !pending.processing {
                assert!(
                    !worker
                        .inner
                        .cvar
                        .wait_until(&mut pending, deadline)
                        .timed_out()
                );
            }
            assert!(pending.payload.is_none());
        }
        assert!(worker.schedule(payload(&b, 2_u8)).is_ok());
        std::thread::scope(|scope| {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = &worker;
            let a = &a;
            scope.spawn(move || {
                entered_tx.send(()).unwrap();
                assert!(worker.schedule(payload(a, 3_u8)).is_ok());
                done_tx.send(()).unwrap();
            });
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            {
                let pending = worker.inner.pending.lock();
                let queued = pending
                    .payload
                    .as_ref()
                    .expect("second update remains queued");
                assert_eq!(queued.entries.len(), 1);
                assert!(
                    matches!(&queued.entries[0].key, TieredKeyHandle::SmartContractState(key) if key == &b)
                );
            }
            drop(blocked_backend);
            done_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        });
        wait_snapshot_worker_idle(&worker);
        let backend = backend.lock();
        assert_retained_value(&backend, &a, &[3]);
        assert_retained_value(&backend, &b, &[2]);
        assert_eq!(backend.last_manifest().unwrap().snapshot_index, 4);
    }

    #[test]
    fn complete_empty_payload_establishes_a_valid_cold_baseline() {
        let temp = tempdir().unwrap();
        let mut backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        assert!(!backend.snapshot_baseline_ready());
        assert!(
            backend
                .record_world_snapshot_with_payload(&TieredSnapshotPayload::default())
                .is_err()
        );
        assert!(backend.last_manifest().is_none());
        backend
            .record_world_snapshot_with_payload(&TieredSnapshotPayload::with_scope(true))
            .unwrap();
        assert!(backend.snapshot_baseline_ready());
        assert_eq!(backend.last_manifest().unwrap().total_entries, 0);
        let key = dummy_state_entry(203).0;
        let mut update = TieredSnapshotPayload::default();
        update.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![8_u8]),
        );
        backend.record_world_snapshot_with_payload(&update).unwrap();
        assert_retained_value(&backend, &key, &[8]);
        let mut removal = TieredSnapshotPayload::default();
        removal.push_value::<Vec<u8>>(TieredKeyHandle::SmartContractState(key), None);
        backend
            .record_world_snapshot_with_payload(&removal)
            .unwrap();
        assert!(backend.snapshot_baseline_ready());
        assert_eq!(backend.last_manifest().unwrap().total_entries, 0);
    }

    #[test]
    fn failed_payload_requires_another_complete_baseline_before_incremental_work() {
        let temp = tempdir().unwrap();
        let mut backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        backend
            .record_world_snapshot_with_payload(&TieredSnapshotPayload::with_scope(true))
            .unwrap();
        let key = dummy_state_entry(205).0;
        let mut update = TieredSnapshotPayload::default();
        update.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![5_u8]),
        );
        let next_index = backend.last_manifest().unwrap().snapshot_index + 1;
        let conflict = temp.path().join(format!("{next_index:020}.staging"));
        fs::write(&conflict, b"blocked staging directory").unwrap();
        assert!(backend.record_world_snapshot_with_payload(&update).is_err());
        assert!(!backend.snapshot_baseline_ready());
        fs::remove_file(conflict).unwrap();
        assert!(backend.record_world_snapshot_with_payload(&update).is_err());
        let mut complete = TieredSnapshotPayload::with_scope(true);
        complete.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![6_u8]),
        );
        backend
            .record_world_snapshot_with_payload(&complete)
            .unwrap();
        assert!(backend.snapshot_baseline_ready());
        assert_retained_value(&backend, &key, &[6]);
    }

    #[test]
    fn inert_and_shutdown_workers_return_unmodified_payloads_for_ordered_fallback() {
        use super::super::TieredSnapshotWorker;
        use std::sync::{Arc, atomic::Ordering};
        let temp = tempdir().unwrap();
        let backend = Arc::new(crate::publication_lock::PublicationMutex::new(
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0),
        ));
        let inert = TieredSnapshotWorker::inert(
            Arc::clone(&backend),
            #[cfg(feature = "telemetry")]
            None,
        );
        let key = dummy_state_entry(204).0;
        let mut baseline = TieredSnapshotPayload::with_scope(true);
        baseline.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![1_u8]),
        );
        let baseline = match inert.schedule(baseline) {
            Err(payload) => payload,
            Ok(()) => panic!("inert worker accepted payload"),
        };
        backend
            .lock()
            .record_world_snapshot_with_payload(&baseline)
            .unwrap();
        let worker = TieredSnapshotWorker::new(
            Arc::clone(&backend),
            #[cfg(feature = "telemetry")]
            None,
        );
        assert!(worker.enabled());
        let mut accepted = TieredSnapshotPayload::default();
        accepted.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![2_u8]),
        );
        assert!(worker.schedule(accepted).is_ok());
        {
            let _pending = worker.inner.pending.lock();
            worker.inner.shutdown.store(true, Ordering::Relaxed);
            worker.inner.cvar.notify_all();
        }
        let mut later = TieredSnapshotPayload::default();
        later.push_value(
            TieredKeyHandle::SmartContractState(key.clone()),
            Some(vec![3_u8]),
        );
        let later = match worker.schedule(later) {
            Err(payload) => payload,
            Ok(()) => panic!("shutdown worker accepted payload"),
        };
        // Returning the later payload guarantees all previously accepted work
        // finished, so synchronous fallback cannot be overwritten by the worker.
        assert_retained_value(&backend.lock(), &key, &[2]);
        backend
            .lock()
            .record_world_snapshot_with_payload(&later)
            .unwrap();
        assert_retained_value(&backend.lock(), &key, &[3]);
    }

    #[test]
    fn retired_commit_qc_segment_is_rejected() {
        let error = norito::json::from_str::<TieredSegment>(r#""commit_qcs""#)
            .expect_err("the retired commit-QC segment must fail closed");
        assert!(
            error
                .to_string()
                .contains("unknown tiered segment `commit_qcs`"),
            "unexpected retired-segment rejection: {error}"
        );
    }

    #[test]
    fn private_settlement_projection_persists_in_every_tiered_segment() {
        let temp = tempdir().expect("tmpdir");
        let root = temp.path().to_path_buf();
        let mut backend = TieredStateBackend::new(true, 0, 1, 0, Some(root.clone()), None, 0, 0);
        let (_, _, restricted_fixture) = crate::private_settlement::global_state::tests::fixture();
        let restricted_asset_canary = restricted_fixture
            .pool_governance
            .body
            .asset_definition_id
            .to_string();
        let restricted_salt_canary = restricted_fixture.pool_governance.body.asset_binding_salt;
        let world = crate::private_settlement::global_state::tests::finalized_world_fixture();
        backend
            .record_world_snapshot(&world)
            .expect("persist private-settlement tiered snapshot");
        let manifest = backend.last_manifest().expect("snapshot manifest recorded");
        let snapshot_dir = root.join(format!("{:020}", manifest.snapshot_index));
        let assert_canaries_absent = |bytes: &[u8], context: &str| {
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains("asset_definition_id")
                    && !text.contains("asset_binding_salt")
                    && !text.contains(&restricted_asset_canary)
                    && !text.contains(&hex::encode(restricted_salt_canary))
                    && !text.contains(&hex::encode_upper(restricted_salt_canary))
                    && !bytes
                        .windows(restricted_salt_canary.len())
                        .any(|window| window == restricted_salt_canary),
                "tiered {context} must never contain restricted pool asset/salt canaries"
            );
        };
        assert_canaries_absent(
            &fs::read(snapshot_dir.join("manifest.json")).expect("read tiered manifest"),
            "manifest",
        );
        let expected = [
            TieredSegment::PrivateSettlementGovernance,
            TieredSegment::PrivateSettlementPools,
            TieredSegment::PrivateSettlementRoots,
            TieredSegment::PrivateSettlementNullifiers,
            TieredSegment::PrivateSettlementOutputs,
            TieredSegment::PrivateSettlementReceipts,
            TieredSegment::PrivateSettlementAborts,
        ];
        for segment in expected {
            let entries = manifest
                .cold_entries
                .iter()
                .filter(|entry| entry.segment == segment)
                .collect::<Vec<_>>();
            assert!(
                !entries.is_empty(),
                "private-settlement segment {segment:?} must be represented in the cold manifest"
            );
            for entry in entries {
                let spill = entry
                    .spill_path
                    .as_ref()
                    .expect("cold private-settlement entry has a spill path");
                assert!(
                    snapshot_dir.join(spill).is_file(),
                    "private-settlement cold payload must exist at {}",
                    spill.display()
                );
                assert_canaries_absent(
                    &fs::read(snapshot_dir.join(spill)).expect("read settlement cold payload"),
                    "private-settlement cold payload",
                );
            }
        }

        let prepared_world =
            crate::private_settlement::global_state::tests::prepared_world_fixture();
        backend
            .record_world_snapshot(&prepared_world)
            .expect("persist prepared private-settlement tiered snapshot");
        let prepared_manifest = backend
            .last_manifest()
            .expect("prepared snapshot manifest recorded");
        let prepared_snapshot_dir = root.join(format!("{:020}", prepared_manifest.snapshot_index));
        let staged_entries = prepared_manifest
            .cold_entries
            .iter()
            .filter(|entry| entry.segment == TieredSegment::PrivateSettlementStagedLocks)
            .collect::<Vec<_>>();
        assert!(
            !staged_entries.is_empty(),
            "active private-settlement staged locks must be represented in the cold manifest"
        );
        for entry in staged_entries {
            let spill = entry
                .spill_path
                .as_ref()
                .expect("cold staged-lock entry has a spill path");
            assert_canaries_absent(
                &fs::read(prepared_snapshot_dir.join(spill))
                    .expect("read staged-lock cold payload"),
                "private-settlement staged-lock cold payload",
            );
        }
    }

    include!("tiered_security_and_measured_bytes_tests.rs");
    #[test]
    fn partial_contract_upload_roundtrips_through_cold_tier_disk() {
        let temp = tempdir().expect("tmpdir");
        let root = temp.path().to_path_buf();
        // A one-byte hot budget forces both the descriptor and chunk payload into the
        // persisted cold tier, so the assertions below cannot read in-memory values.
        let mut backend = TieredStateBackend::new(true, 0, 1, 0, Some(root.clone()), None, 0, 0);
        let mut world = World::default();
        let keypair = iroha_crypto::KeyPair::try_from_seed(
            b"tiered partial contract upload".to_vec(),
            iroha_crypto::Algorithm::Ed25519,
        )
        .expect("fixture seed derives a valid keypair");
        let authority = iroha_data_model::account::AccountId::new(keypair.public_key().clone());
        let code_hash = Hash::new(b"partial out-of-order contract upload");
        let upload_key = crate::state::SmartContractCodeUploadKey::new(
            authority,
            iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::new(u64::MAX),
                code_hash,
            ),
        );
        let chunk_key = crate::state::SmartContractCodeUploadChunkKey::new(upload_key.clone(), 2);
        let final_chunk = vec![0xA5; 17];
        let total_size = u64::try_from(
            2 * iroha_data_model::isi::smart_contract_code::SMART_CONTRACT_CODE_CHUNK_BYTES
                + final_chunk.len(),
        )
        .expect("fixture size fits u64");
        let descriptor = crate::state::SmartContractCodeUploadDescriptor {
            total_size,
            chunk_count: 3,
        };
        world
            .contract_code_uploads
            .insert(upload_key.clone(), descriptor);
        world
            .contract_code_upload_chunks
            .insert(chunk_key.clone(), final_chunk.clone());
        backend
            .record_world_snapshot(&world)
            .expect("persist partial upload snapshot");
        let snapshot_index = backend
            .last_manifest()
            .expect("snapshot manifest recorded")
            .snapshot_index;
        drop(backend);
        let snapshot_dir = root.join(format!("{snapshot_index:020}"));
        let manifest_bytes =
            fs::read(snapshot_dir.join("manifest.json")).expect("read persisted tiered manifest");
        let manifest: TieredSnapshotManifest =
            json::from_slice(&manifest_bytes).expect("decode persisted tiered manifest");
        let descriptor_entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == TieredSegment::ContractCodeUploads)
            .expect("pending upload descriptor is persisted in the cold tier");
        let chunk_entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == TieredSegment::ContractCodeUploadChunks)
            .expect("out-of-order pending upload chunk is persisted in the cold tier");
        assert_eq!(
            descriptor_entry.key_payload,
            norito::codec::Encode::encode(&upload_key),
            "descriptor must retain its exact authority/hash consensus key"
        );
        assert_eq!(
            chunk_entry.key_payload,
            norito::codec::Encode::encode(&chunk_key),
            "chunk key must retain the out-of-order index"
        );
        let reader = TieredStateBackend::new(true, 0, 1, 0, Some(root), None, 0, 0);
        let restored_descriptor_bytes = reader
            .read_cold_payload(snapshot_index, descriptor_entry)
            .expect("read descriptor cold payload")
            .expect("descriptor cold payload exists");
        let restored_descriptor: crate::state::SmartContractCodeUploadDescriptor =
            json::from_slice(&restored_descriptor_bytes).expect("decode descriptor cold payload");
        assert_eq!(restored_descriptor, descriptor);
        let restored_chunk_bytes = reader
            .read_cold_payload(snapshot_index, chunk_entry)
            .expect("read chunk cold payload")
            .expect("chunk cold payload exists");
        let restored_chunk: Vec<u8> =
            json::from_slice(&restored_chunk_bytes).expect("decode chunk cold payload");
        assert_eq!(restored_chunk, final_chunk);
        let legacy_descriptor_without_chunk_count = format!(r#"{{"total_size":{total_size}}}"#);
        assert!(
            json::from_str::<crate::state::SmartContractCodeUploadDescriptor>(
                &legacy_descriptor_without_chunk_count
            )
            .is_err(),
            "first-release persistence must not default or migrate missing descriptor fields"
        );
    }
    #[test]
    fn direct_home_row_roundtrips_through_cold_tier_disk() {
        use iroha_data_model::asset::AssetDefinitionDirectHomeV1;
        let temp = tempdir().expect("temporary cold storage");
        let root = temp.path().to_path_buf();
        let mut backend = TieredStateBackend::new(true, 0, 1, 0, Some(root.clone()), None, 0, 0);
        let mut world = World::default();
        let id = AssetDefinitionId::from_uuid_bytes([
            0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x47, 0x98, 0x80, 0x19, 0x2a, 0x3b, 0x4c, 0x5d,
            0x6e, 0x7f,
        ])
        .unwrap();
        let home = AssetDefinitionDirectHomeV1 {
            incarnation: AxtAssetIncarnationV1::try_from_bytes(Hash::new(b"direct home").into())
                .unwrap(),
            dataspace_id: DataSpaceId::new((1_u64 << 53) + 7),
        };
        world.asset_definition_direct_homes.insert(id.clone(), home);
        backend.record_world_snapshot(&world).unwrap();
        let snapshot_index = backend.last_manifest().unwrap().snapshot_index;
        drop(backend);
        let manifest: TieredSnapshotManifest = json::from_slice(
            &fs::read(
                root.join(format!("{snapshot_index:020}"))
                    .join("manifest.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == TieredSegment::AssetDefinitionDirectHomes)
            .expect("direct-home authority is present in the persisted snapshot");
        assert_eq!(entry.key_payload, norito::codec::Encode::encode(&id));
        let reader = TieredStateBackend::new(true, 0, 1, 0, Some(root), None, 0, 0);
        let original = reader
            .read_cold_payload(snapshot_index, entry)
            .unwrap()
            .unwrap();
        assert_eq!(
            json::from_slice::<AssetDefinitionDirectHomeV1>(&original).unwrap(),
            home
        );
    }

    #[test]
    fn alias_binding_records_roundtrip_through_cold_tier_disk() {
        let temp = tempdir().expect("tmpdir");
        let root = temp.path().to_path_buf();
        let mut backend = TieredStateBackend::new(true, 0, 1, 0, Some(root.clone()), None, 0, 0);
        let mut world = World::default();
        let definition_id = iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes([
            0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x47, 0x98, 0x80, 0x19, 0x2a, 0x3b, 0x4c, 0x5d,
            0x6e, 0x7f,
        ])
        .expect("cold-tier fixture UUID is valid");
        let asset_binding = crate::state::AssetDefinitionAliasBindingRecord {
            alias: "tiered_cold_asset#universal".parse().expect("asset alias"),
            lease_expiry_ms: Some(2_000),
            grace_until_ms: Some(2_500),
            bound_at_ms: 1_000,
        };
        world
            .asset_definition_alias_bindings
            .insert(definition_id.clone(), asset_binding.clone());
        let keypair = iroha_crypto::KeyPair::try_from_seed(
            b"tiered contract alias binding".to_vec(),
            iroha_crypto::Algorithm::Ed25519,
        )
        .expect("fixture seed derives a valid keypair");
        let authority = iroha_data_model::account::AccountId::new(keypair.public_key().clone());
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            91,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let contract_binding = crate::state::ContractAliasBindingRecord {
            alias: "tiered_cold_router::universal"
                .parse()
                .expect("contract alias"),
            lease_expiry_ms: Some(3_000),
            grace_until_ms: Some(3_500),
            bound_at_ms: 1_000,
        };
        world
            .contract_alias_bindings
            .insert(contract_address.clone(), contract_binding.clone());
        backend
            .record_world_snapshot(&world)
            .expect("persist alias binding snapshot");
        let snapshot_index = backend
            .last_manifest()
            .expect("snapshot manifest recorded")
            .snapshot_index;
        drop(backend);
        let snapshot_dir = root.join(format!("{snapshot_index:020}"));
        let manifest_bytes =
            fs::read(snapshot_dir.join("manifest.json")).expect("read persisted manifest");
        let manifest: TieredSnapshotManifest =
            json::from_slice(&manifest_bytes).expect("decode persisted manifest");
        let asset_entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == TieredSegment::AssetDefinitionAliasBindings)
            .expect("asset alias binding is persisted in the cold tier");
        let contract_entry = manifest
            .cold_entries
            .iter()
            .find(|entry| entry.segment == TieredSegment::ContractAliasBindings)
            .expect("contract alias binding is persisted in the cold tier");
        assert_eq!(
            asset_entry.key_payload,
            norito::codec::Encode::encode(&definition_id)
        );
        assert_eq!(
            contract_entry.key_payload,
            norito::codec::Encode::encode(&contract_address)
        );
        let reader = TieredStateBackend::new(true, 0, 1, 0, Some(root), None, 0, 0);
        let restored_asset_bytes = reader
            .read_cold_payload(snapshot_index, asset_entry)
            .expect("read asset alias binding")
            .expect("asset alias binding payload exists");
        let restored_asset: crate::state::AssetDefinitionAliasBindingRecord =
            json::from_slice(&restored_asset_bytes).expect("decode asset alias binding");
        assert_eq!(restored_asset, asset_binding);
        let restored_contract_bytes = reader
            .read_cold_payload(snapshot_index, contract_entry)
            .expect("read contract alias binding")
            .expect("contract alias binding payload exists");
        let restored_contract: crate::state::ContractAliasBindingRecord =
            json::from_slice(&restored_contract_bytes).expect("decode contract alias binding");
        assert_eq!(restored_contract, contract_binding);
    }
    #[test]
    fn persists_cold_entries_and_prunes_old_snapshots() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 0, Some(temp.path().to_path_buf()), None, 1, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world
            .smart_contract_state
            .insert(key1.clone(), value1.clone());
        world
            .smart_contract_state
            .insert(key2.clone(), value2.clone());
        backend
            .record_world_snapshot(&world)
            .expect("first snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.cold_entries.len(), 1);
        assert_eq!(manifest.hot_entries.len(), 1);
        assert!(manifest.hot_entries[0].value_size_bytes() > 0);
        assert!(manifest.cold_bytes_total > 0);
        assert!(manifest.cold_entries[0].spill_bytes.is_some());
        let cold_entry = &manifest.cold_entries[0];
        let snapshot_dir = temp
            .path()
            .join(format!("{index:020}", index = manifest.snapshot_index));
        let manifest_path = snapshot_dir.join("manifest.json");
        let manifest_tmp = snapshot_dir.join("manifest.json.tmp");
        assert!(manifest_path.exists(), "manifest should be persisted");
        assert!(
            !manifest_tmp.exists(),
            "manifest temp file should be removed after snapshot"
        );
        let spill_path = cold_entry
            .spill_path
            .as_ref()
            .expect("cold entry has spill path");
        let payload_path = snapshot_dir.join(spill_path);
        assert!(payload_path.exists());
        let encoded = fs::read(&payload_path).expect("payload read");
        let decoded: Vec<u8> = json::from_slice(&encoded).expect("cold payload decodes");
        assert!(decoded == value1 || decoded == value2);
        // Mutate the other record so the hot entry flips on the next snapshot.
        let updated = vec![99; value2.len()];
        world
            .smart_contract_state
            .insert(key2.clone(), updated.clone());
        backend
            .record_world_snapshot(&world)
            .expect("second snapshot");
        let manifest2 = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest2.total_entries, 2);
        assert_eq!(manifest2.cold_entries.len(), 1);
        // Only the latest snapshot directory should be retained (max_snapshots = 1).
        let retained = fs::read_dir(temp.path())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
            .count();
        assert_eq!(retained, 1);
        assert_eq!(manifest2.snapshot_index, 2);
    }
    #[test]
    fn record_world_snapshot_with_diff_updates_touched_entries() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1.clone(), value1);
        world.smart_contract_state.insert(key2.clone(), value2);
        backend
            .record_world_snapshot(&world)
            .expect("initial snapshot");
        let snapshot1 = backend
            .last_manifest()
            .expect("manifest recorded")
            .snapshot_index;
        world
            .smart_contract_state
            .insert(key1.clone(), vec![0xA1; 8]);
        let mut diff = TieredSnapshotDiff::default();
        diff.push(TieredKeyHandle::SmartContractState(key1.clone()));
        backend
            .record_world_snapshot_with_diff(&world, &diff)
            .expect("diff snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        let key1_payload = TieredKeyHandle::SmartContractState(key1)
            .encode_key()
            .expect("first state key encode");
        let key2_payload = TieredKeyHandle::SmartContractState(key2)
            .encode_key()
            .expect("second state key encode");
        let mut entries = manifest.hot_entries.iter().chain(&manifest.cold_entries);
        let entry1 = entries
            .clone()
            .find(|entry| entry.key_payload == key1_payload)
            .expect("first state entry present");
        let entry2 = entries
            .find(|entry| entry.key_payload == key2_payload)
            .expect("second state entry present");
        assert_eq!(entry1.last_mutated_snapshot, manifest.snapshot_index);
        assert_eq!(entry2.last_mutated_snapshot, snapshot1);
    }
    #[test]
    fn record_world_snapshot_with_payload_updates_touched_entries() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1.clone(), value1);
        world.smart_contract_state.insert(key2.clone(), value2);
        backend
            .record_world_snapshot(&world)
            .expect("initial snapshot");
        let snapshot1 = backend
            .last_manifest()
            .expect("manifest recorded")
            .snapshot_index;
        let updated = vec![0xA1; 8];
        world
            .smart_contract_state
            .insert(key1.clone(), updated.clone());
        let mut payload = TieredSnapshotPayload::default();
        payload.push_value(
            TieredKeyHandle::SmartContractState(key1.clone()),
            Some(updated),
        );
        backend
            .record_world_snapshot_with_payload(&payload)
            .expect("payload snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        let key1_payload = TieredKeyHandle::SmartContractState(key1)
            .encode_key()
            .expect("first state key encode");
        let key2_payload = TieredKeyHandle::SmartContractState(key2)
            .encode_key()
            .expect("second state key encode");
        let mut entries = manifest.hot_entries.iter().chain(&manifest.cold_entries);
        let entry1 = entries
            .clone()
            .find(|entry| entry.key_payload == key1_payload)
            .expect("first state entry present");
        let entry2 = entries
            .find(|entry| entry.key_payload == key2_payload)
            .expect("second state entry present");
        assert_eq!(entry1.last_mutated_snapshot, manifest.snapshot_index);
        assert_eq!(entry2.last_mutated_snapshot, snapshot1);
    }
    #[test]
    fn da_store_root_used_when_cold_root_missing() {
        let temp = tempdir().expect("tmpdir");
        let da_root = temp.path().join("da");
        let mut backend = TieredStateBackend::new(true, 1, 0, 0, None, Some(da_root.clone()), 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world
            .smart_contract_state
            .insert(key1.clone(), value1.clone());
        world
            .smart_contract_state
            .insert(key2.clone(), value2.clone());
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.cold_entries.len(), 1);
        let snapshot_dir = da_root.join(format!("{:020}", manifest.snapshot_index));
        assert!(snapshot_dir.exists(), "snapshot directory should exist");
        let cold_entry = &manifest.cold_entries[0];
        let spill_path = cold_entry
            .spill_path
            .as_ref()
            .expect("cold entry has spill path");
        let payload_path = snapshot_dir.join(spill_path);
        assert!(
            payload_path.exists(),
            "cold payload should be stored under da root"
        );
        let encoded = backend
            .read_cold_payload(manifest.snapshot_index, cold_entry)
            .expect("read cold payload")
            .expect("payload present");
        let decoded: Vec<u8> = json::from_slice(&encoded).expect("cold payload decodes");
        assert!(decoded == value1 || decoded == value2);
    }
    #[test]
    fn cold_snapshots_offload_to_da_root_and_rehydrate_on_read() {
        let temp = tempdir().expect("tmpdir");
        let cold_root = temp.path().join("cold");
        let da_root = temp.path().join("da");
        let mut backend = TieredStateBackend::new(
            true,
            1,
            0,
            0,
            Some(cold_root.clone()),
            Some(da_root.clone()),
            0,
            1,
        );
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world
            .smart_contract_state
            .insert(key1.clone(), value1.clone());
        world
            .smart_contract_state
            .insert(key2.clone(), value2.clone());
        backend
            .record_world_snapshot(&world)
            .expect("first snapshot");
        let manifest1 = backend.last_manifest().expect("manifest recorded").clone();
        assert!(
            !manifest1.cold_entries.is_empty(),
            "expected cold entries in first snapshot"
        );
        let first_index = manifest1.snapshot_index;
        world
            .smart_contract_state
            .insert(key2, vec![99; value2.len()]);
        backend
            .record_world_snapshot(&world)
            .expect("second snapshot");
        let second_index = backend
            .last_manifest()
            .expect("manifest recorded")
            .snapshot_index;
        assert_ne!(first_index, second_index);
        let cold_dir = cold_root.join(format!("{first_index:020}"));
        assert!(
            !cold_dir.exists(),
            "old snapshot should be offloaded from cold storage"
        );
        let da_dir = da_root.join(format!("{first_index:020}"));
        assert!(
            da_dir.exists(),
            "offloaded snapshot should exist in DA root"
        );
        let cold_entry = &manifest1.cold_entries[0];
        let spill_path = cold_entry
            .spill_path
            .as_ref()
            .expect("cold entry has spill path");
        let encoded = backend
            .read_cold_payload(first_index, cold_entry)
            .expect("read cold payload")
            .expect("payload present");
        let decoded: Vec<u8> = json::from_slice(&encoded).expect("cold payload decodes");
        assert!(decoded == value1 || decoded == value2);
        let rehydrated_path = cold_root
            .join(format!("{first_index:020}"))
            .join(spill_path);
        assert!(
            rehydrated_path.exists(),
            "expected rehydrated cold payload in cold root"
        );
    }
    #[test]
    fn da_cold_payload_rehydrates_into_primary_root() {
        let temp = tempdir().expect("tmpdir");
        let cold_root = temp.path().join("cold");
        let da_root = temp.path().join("da");
        let mut backend = TieredStateBackend::new(
            true,
            1,
            0,
            0,
            Some(cold_root.clone()),
            Some(da_root.clone()),
            0,
            0,
        );
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world
            .smart_contract_state
            .insert(key1.clone(), value1.clone());
        world
            .smart_contract_state
            .insert(key2.clone(), value2.clone());
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        let manifest = backend.last_manifest().expect("manifest recorded");
        let cold_entry = &manifest.cold_entries[0];
        let spill_path = cold_entry
            .spill_path
            .as_ref()
            .expect("cold entry has spill path");
        let snapshot_dir = cold_root.join(format!("{:020}", manifest.snapshot_index));
        let cold_payload_path = snapshot_dir.join(spill_path);
        assert!(cold_payload_path.exists(), "cold payload written");
        let da_snapshot_dir = da_root.join(format!("{:020}", manifest.snapshot_index));
        let da_payload_path = da_snapshot_dir.join(spill_path);
        if let Some(parent) = da_payload_path.parent() {
            fs::create_dir_all(parent).expect("da payload parent created");
        }
        fs::copy(&cold_payload_path, &da_payload_path).expect("cold payload copied to DA root");
        fs::remove_file(&cold_payload_path).expect("cold payload evicted");
        let encoded = backend
            .read_cold_payload(manifest.snapshot_index, cold_entry)
            .expect("read cold payload")
            .expect("payload present");
        let decoded: Vec<u8> = json::from_slice(&encoded).expect("cold payload decodes");
        assert!(decoded == value1 || decoded == value2);
        assert!(
            cold_payload_path.exists(),
            "cold payload rehydrated into primary root"
        );
    }
    #[test]
    fn hot_byte_budget_demotes_entries_to_cold() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 0, 1, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1, value1);
        world.smart_contract_state.insert(key2, value2);
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert!(!manifest.cold_entries.is_empty());
        assert!(
            manifest.hot_entries.len() < manifest.total_entries,
            "byte budget should force some entries into cold tier"
        );
    }
    #[test]
    fn hot_grace_snapshots_keep_recent_hot_entry() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 1, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1.clone(), value1);
        world.smart_contract_state.insert(key2.clone(), value2);
        backend
            .record_world_snapshot(&world)
            .expect("first snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.hot_entries.len(), 1);
        let key1_hash = hex::encode(sha256(&norito::codec::Encode::encode(&key1)));
        let key2_hash = hex::encode(sha256(&norito::codec::Encode::encode(&key2)));
        let hot_hash = manifest.hot_entries[0].key_hash_hex.clone();
        assert!(
            hot_hash == key1_hash || hot_hash == key2_hash,
            "hot entry should match one of the recent state keys"
        );
        let mutate_key = if hot_hash == key1_hash { key2 } else { key1 };
        world.smart_contract_state.insert(mutate_key, vec![99; 8]);
        backend
            .record_world_snapshot(&world)
            .expect("second snapshot");
        let manifest2 = backend.last_manifest().expect("manifest recorded");
        let hot_hash2 = manifest2.hot_entries[0].key_hash_hex.clone();
        assert_eq!(hot_hash2, hot_hash, "hot grace should preserve hot entry");
    }
    #[test]
    fn tiered_backend_reports_budget_limits_and_cold_bytes() {
        let temp = tempdir().expect("tmpdir");
        let mut backend = TieredStateBackend::new(
            true,
            1,
            256,
            0,
            Some(temp.path().to_path_buf()),
            None,
            0,
            512,
        );
        assert_eq!(backend.hot_retained_bytes(), 256);
        assert_eq!(backend.max_cold_bytes(), 512);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1, value1);
        world.smart_contract_state.insert(key2, value2);
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        let manifest = backend.last_manifest().expect("manifest recorded");
        let cold_bytes = backend
            .cold_store_bytes()
            .expect("cold store bytes")
            .expect("cold tier enabled");
        assert!(
            cold_bytes >= manifest.cold_bytes_total,
            "cold store usage should cover cold payload bytes"
        );
    }
    #[test]
    fn cold_payload_reuse_is_recorded_for_unchanged_entries() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1, value1);
        world.smart_contract_state.insert(key2, value2);
        backend
            .record_world_snapshot(&world)
            .expect("first snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.cold_reused_entries, 0);
        backend
            .record_world_snapshot(&world)
            .expect("second snapshot");
        let manifest2 = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest2.cold_reused_entries, 1);
        assert!(manifest2.cold_reused_bytes > 0);
    }
    #[cfg(unix)]
    #[test]
    fn cold_payload_reuse_prefers_hard_links_when_supported() {
        let temp = tempdir().expect("tmpdir");
        let probe_source = temp.path().join("probe_source");
        let probe_dest = temp.path().join("probe_dest");
        fs::write(&probe_source, b"probe").expect("write probe");
        if fs::hard_link(&probe_source, &probe_dest).is_err() {
            return;
        }
        fs::remove_file(&probe_dest).expect("cleanup probe link");
        let source = temp.path().join("source");
        let dest = temp.path().join("dest");
        let payload = b"cold payload";
        fs::write(&source, payload).expect("write source");
        let bytes = TieredStateBackend::try_reuse_cold_payload(&source, &dest)
            .expect("reuse payload")
            .expect("reuse should return bytes");
        assert_eq!(bytes, payload.len() as u64);
        let source_meta = fs::metadata(&source).expect("source metadata");
        let dest_meta = fs::metadata(&dest).expect("dest metadata");
        assert_eq!(source_meta.len(), dest_meta.len());
        assert_eq!(source_meta.nlink(), 2);
        assert_eq!(dest_meta.nlink(), 2);
    }
    #[test]
    fn prune_snapshots_to_cold_byte_budget() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 0, Some(temp.path().to_path_buf()), None, 0, 1);
        let mut world = World::default();
        let (key1, value1) = dummy_state_entry(1);
        let (key2, value2) = dummy_state_entry(2);
        world.smart_contract_state.insert(key1, value1);
        world
            .smart_contract_state
            .insert(key2.clone(), value2.clone());
        backend
            .record_world_snapshot(&world)
            .expect("first snapshot");
        let first_index = backend
            .last_manifest()
            .expect("manifest recorded")
            .snapshot_index;
        world
            .smart_contract_state
            .insert(key2, vec![99; value2.len()]);
        backend
            .record_world_snapshot(&world)
            .expect("second snapshot");
        let second_index = backend
            .last_manifest()
            .expect("manifest recorded")
            .snapshot_index;
        let mut snapshots = fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                TieredStateBackend::parse_snapshot_dir_name(&entry.file_name())
            })
            .collect::<Vec<_>>();
        snapshots.sort_unstable();
        assert_eq!(snapshots, vec![second_index]);
        assert_ne!(first_index, second_index);
    }
    #[test]
    fn prune_cold_snapshots_to_bytes_prunes_oldest_first() {
        let temp = tempdir().expect("tmpdir");
        let cold_root = temp.path().join("cold");
        fs::create_dir_all(&cold_root).expect("create cold root");
        for idx in 1..=3u64 {
            let dir = cold_root.join(format!("{idx:020}"));
            fs::create_dir_all(&dir).expect("create snapshot dir");
            fs::write(dir.join("payload.norito"), vec![0u8; 50]).expect("write snapshot payload");
        }
        let backend = TieredStateBackend::new(true, 0, 0, 0, Some(cold_root.clone()), None, 0, 0);
        backend
            .prune_cold_snapshots_to_bytes(80)
            .expect("prune snapshots to budget");
        let mut snapshots = fs::read_dir(&cold_root)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                TieredStateBackend::parse_snapshot_dir_name(&entry.file_name())
            })
            .collect::<Vec<_>>();
        snapshots.sort_unstable();
        assert_eq!(snapshots, vec![3]);
    }
    #[test]
    fn snapshot_counter_seeds_from_existing_dirs() {
        let temp = tempdir().expect("tmpdir");
        let root = temp.path().to_path_buf();
        let snapshot_dir = root.join(format!("{:020}", 7_u64));
        fs::create_dir_all(&snapshot_dir).expect("seed snapshot");
        fs::create_dir_all(root.join("lanes")).expect("lanes dir");
        fs::create_dir_all(root.join("retired")).expect("retired dir");
        let mut backend = TieredStateBackend::new(true, 0, 0, 0, Some(root.clone()), None, 0, 0);
        let world = World::default();
        backend.record_world_snapshot(&world).expect("snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.snapshot_index, 8);
        let new_dir = root.join(format!("{:020}", manifest.snapshot_index));
        assert!(new_dir.exists(), "expected seeded snapshot directory");
    }
    #[test]
    fn snapshot_counter_seeds_from_da_root_dirs() {
        let temp = tempdir().expect("tmpdir");
        let da_root = temp.path().join("da");
        let snapshot_dir = da_root.join(format!("{:020}", 5_u64));
        fs::create_dir_all(&snapshot_dir).expect("seed snapshot");
        let mut backend = TieredStateBackend::new(true, 0, 0, 0, None, Some(da_root.clone()), 0, 0);
        let world = World::default();
        backend.record_world_snapshot(&world).expect("snapshot");
        let manifest = backend.last_manifest().expect("manifest recorded");
        assert_eq!(manifest.snapshot_index, 6);
        let new_dir = da_root.join(format!("{:020}", manifest.snapshot_index));
        assert!(new_dir.exists(), "expected seeded snapshot directory");
    }
    #[test]
    fn recover_snapshot_artifacts_restores_backups_and_cleans_staging() {
        let temp = tempdir().expect("tmpdir");
        let root = temp.path().to_path_buf();
        let live_dir = root.join(format!("{:020}", 1_u64));
        fs::create_dir_all(&live_dir).expect("live dir");
        let live_marker = live_dir.join("marker.txt");
        fs::write(&live_marker, b"live").expect("live marker");
        let live_backup = live_dir.with_extension("bak");
        fs::create_dir_all(&live_backup).expect("live backup");
        fs::write(live_backup.join("marker.txt"), b"backup").expect("backup marker");
        let live_staging = live_dir.with_extension("staging");
        fs::create_dir_all(&live_staging).expect("live staging");
        fs::write(live_staging.join("marker.txt"), b"staging").expect("staging marker");
        let backup_only = root.join(format!("{:020}.bak", 2_u64));
        fs::create_dir_all(&backup_only).expect("backup only");
        fs::write(backup_only.join("marker.txt"), b"backup only").expect("backup only marker");
        let staging_only = root.join(format!("{:020}.staging", 3_u64));
        fs::create_dir_all(&staging_only).expect("staging only");
        fs::write(staging_only.join("marker.txt"), b"staging only").expect("staging only marker");
        let lanes_root = root.join("lanes");
        fs::create_dir_all(&lanes_root).expect("lanes dir");
        let backend = TieredStateBackend::new(false, 0, 0, 0, None, None, 0, 0);
        backend
            .recover_snapshot_artifacts(&root)
            .expect("recover artifacts");
        assert!(live_dir.exists(), "live dir should remain");
        assert!(live_marker.exists(), "live marker should remain");
        assert!(!live_backup.exists(), "live backup should be cleaned");
        assert!(!live_staging.exists(), "live staging should be cleaned");
        let restored = root.join(format!("{:020}", 2_u64));
        assert!(restored.exists(), "backup should be restored");
        assert!(
            restored.join("marker.txt").exists(),
            "backup contents should be preserved on restore"
        );
        assert!(!backup_only.exists(), "backup directory should be renamed");
        assert!(!staging_only.exists(), "staging-only dir should be removed");
        assert!(lanes_root.exists(), "lanes dir should be preserved");
    }
    #[test]
    fn reconfigure_clears_entries_on_cold_root_change() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 0, Some(temp.path().to_path_buf()), None, 0, 0);
        let mut world = World::default();
        let (key, value) = dummy_state_entry(1);
        world.smart_contract_state.insert(key, value);
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        assert!(!backend.entries.is_empty());
        let new_root = tempdir().expect("tmpdir");
        backend.reconfigure(
            true,
            1,
            0,
            0,
            Some(new_root.path().to_path_buf()),
            None,
            0,
            0,
        );
        assert!(backend.entries.is_empty());
        assert_eq!(backend.snapshot_counter, 0);
        assert!(backend.last_manifest().is_none());
    }
    #[test]
    fn reconfigure_clears_entries_on_da_root_change() {
        let temp = tempdir().expect("tmpdir");
        let da_root = temp.path().join("da");
        let mut backend = TieredStateBackend::new(true, 1, 0, 0, None, Some(da_root), 0, 0);
        let mut world = World::default();
        let (key, value) = dummy_state_entry(1);
        world.smart_contract_state.insert(key, value);
        backend
            .record_world_snapshot(&world)
            .expect("snapshot recorded");
        assert!(!backend.entries.is_empty());
        let new_root = tempdir().expect("tmpdir");
        backend.reconfigure(
            true,
            1,
            0,
            0,
            None,
            Some(new_root.path().to_path_buf()),
            0,
            0,
        );
        assert!(backend.entries.is_empty());
        assert_eq!(backend.snapshot_counter, 0);
        assert!(backend.last_manifest().is_none());
    }
    #[test]
    fn prune_old_snapshots_ignores_lane_and_retired_dirs() {
        let temp = tempdir().expect("tmpdir");
        let backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 1, 0);
        let snapshot1 = temp.path().join(format!("{:020}", 1_u64));
        let snapshot2 = temp.path().join(format!("{:020}", 2_u64));
        fs::create_dir_all(&snapshot1).expect("snapshot1");
        fs::create_dir_all(&snapshot2).expect("snapshot2");
        let lanes_root = temp.path().join("lanes");
        let retired_root = temp.path().join("retired");
        fs::create_dir_all(&lanes_root).expect("lanes dir");
        fs::create_dir_all(&retired_root).expect("retired dir");
        let lanes_marker = lanes_root.join("marker.txt");
        let retired_marker = retired_root.join("marker.txt");
        fs::write(&lanes_marker, b"lanes").expect("lanes marker");
        fs::write(&retired_marker, b"retired").expect("retired marker");
        backend
            .prune_old_snapshots(temp.path())
            .expect("prune snapshots");
        assert!(!snapshot1.exists(), "oldest snapshot should be pruned");
        assert!(snapshot2.exists(), "latest snapshot should remain");
        assert!(lanes_root.exists(), "lanes directory should remain");
        assert!(retired_root.exists(), "retired directory should remain");
        assert!(lanes_marker.exists(), "lanes contents should remain");
        assert!(retired_marker.exists(), "retired contents should remain");
    }
    #[test]
    fn reconcile_lane_geometry_manages_lane_directories() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 1, 0, 0, Some(temp.path().to_path_buf()), None, 4, 0);
        let lane_count = NonZeroU32::new(4).expect("lane count");
        let lane0 = LaneConfig::default();
        let lane1 = LaneConfig {
            id: LaneId::from(1),
            alias: "beta".to_string(),
            ..LaneConfig::default()
        };
        let initial_catalog =
            LaneCatalog::new(lane_count, vec![lane0.clone(), lane1.clone()]).expect("catalog");
        let initial_cfg = RuntimeLaneConfig::from_catalog(&initial_catalog);
        let lane2 = LaneConfig {
            id: LaneId::from(2),
            alias: "gamma".to_string(),
            ..LaneConfig::default()
        };
        let extended_catalog = LaneCatalog::new(
            lane_count,
            vec![lane0.clone(), lane1.clone(), lane2.clone()],
        )
        .expect("catalog");
        let extended_cfg = RuntimeLaneConfig::from_catalog(&extended_catalog);
        backend
            .reconcile_lane_geometry(&initial_cfg, &extended_cfg, &[])
            .expect("lane add reconcile");
        let lanes_root = temp.path().join("lanes");
        let lane2_entry = extended_cfg.entry(LaneId::from(2)).expect("lane 2 entry");
        let lane2_path = lanes_root.join(&lane2_entry.kura_segment);
        assert!(
            lane2_path.exists(),
            "expected lane 2 snapshot directory provisioned"
        );
        backend
            .reconcile_lane_geometry(&extended_cfg, &initial_cfg, &[])
            .expect("lane retire reconcile");
        assert!(
            !lane2_path.exists(),
            "expected lane 2 snapshot directory to be retired"
        );
        let retired_root = temp.path().join("retired").join("lanes");
        let retired_entries: Vec<_> = std::fs::read_dir(&retired_root)
            .expect("retired dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect retired entries");
        assert!(
            !retired_entries.is_empty(),
            "expected retired lane snapshot archive"
        );
    }
    #[test]
    fn lane_snapshot_dirs_relabel_on_alias_change() {
        let temp = tempdir().expect("tmpdir");
        let mut backend =
            TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().to_path_buf()), None, 1, 0);
        let initial_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                alias: "Alpha Lane".to_string(),
                ..LaneConfig::default()
            }],
        )
        .expect("initial catalog");
        let initial_cfg = RuntimeLaneConfig::from_catalog(&initial_catalog);
        backend
            .reconcile_lane_geometry(&RuntimeLaneConfig::default(), &initial_cfg, &[])
            .expect("provision initial snapshot");
        let old_entry = initial_cfg
            .entry(LaneId::SINGLE)
            .expect("initial lane entry");
        let cold_root = backend
            .cold_store_root
            .clone()
            .expect("cold root configured");
        let lanes_root = cold_root.join("lanes");
        let old_dir = lane_snapshot_dir(&lanes_root, old_entry);
        assert!(
            old_dir.exists(),
            "expected snapshot directory for initial alias"
        );
        let updated_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                alias: "Payments Lane".to_string(),
                ..LaneConfig::default()
            }],
        )
        .expect("updated catalog");
        let updated_cfg = RuntimeLaneConfig::from_catalog(&updated_catalog);
        let new_entry = updated_cfg
            .entry(LaneId::SINGLE)
            .expect("updated lane entry");
        backend
            .prepare_lane_geometry_attempt(
                &initial_cfg,
                &updated_cfg,
                &[],
                &[(old_entry, new_entry)],
            )
            .expect("capture snapshot relabel")
            .resume(&mut backend)
            .expect("relabel snapshot directories");
        let new_dir = lane_snapshot_dir(&lanes_root, new_entry);
        assert!(
            new_dir.exists(),
            "expected snapshot directory with updated alias"
        );
        assert!(
            !old_dir.exists(),
            "old snapshot directory should be moved away"
        );
    }
    include!("tiered_preflight_lane_tests.rs");
}
