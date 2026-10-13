//! Replay cache for data availability ingest.
//!
//! The DA ingest pipeline must reject duplicate manifests and stale sequence numbers so
//! storage operators cannot replay previously accepted blobs. The replay cache keeps a
//! bounded, per-lane/per-epoch window of recently seen manifest fingerprints and
//! exposes deterministic outcomes that higher layers can map to admission errors.
use iroha_model_base::topology::LaneId;
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use thiserror::Error;
/// Identifier for a `(lane, epoch)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneEpoch {
    /// Lane identifier.
    pub lane_id: LaneId,
    /// Sequencer epoch associated with the manifest.
    pub epoch: u64,
}
impl LaneEpoch {
    /// Construct a new `(lane, epoch)` handle.
    #[must_use]
    pub const fn new(lane_id: LaneId, epoch: u64) -> Self {
        Self { lane_id, epoch }
    }
}
/// Blake3 fingerprint used for DA replay detection. The ingest path computes this over a
/// canonical Norito manifest template with `storage_ticket` and `issued_at_unix` zeroed
/// before de-duplicating entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplayFingerprint([u8; blake3::OUT_LEN]);
impl ReplayFingerprint {
    #[cfg(test)]
    /// Try to construct a fingerprint from raw Blake3 hash output bytes.
    #[must_use]
    pub fn try_from_hash_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes = <[u8; blake3::OUT_LEN]>::try_from(bytes).ok()?;
        Some(Self(bytes))
    }
    /// Construct a fingerprint from a [`blake3::Hash`].
    #[must_use]
    pub fn from_hash(hash: blake3::Hash) -> Self {
        Self(hash.into())
    }
    /// Access the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; blake3::OUT_LEN] {
        &self.0
    }
}
impl From<[u8; blake3::OUT_LEN]> for ReplayFingerprint {
    fn from(bytes: [u8; blake3::OUT_LEN]) -> Self {
        Self(bytes)
    }
}
impl From<ReplayFingerprint> for [u8; blake3::OUT_LEN] {
    fn from(value: ReplayFingerprint) -> Self {
        value.0
    }
}
/// High-level identifier used when inserting items into the replay cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    /// Lane and epoch this manifest is scoped to.
    pub lane_epoch: LaneEpoch,
    /// Monotonic sequence number advertised alongside the manifest.
    pub sequence: u64,
    /// Canonical fingerprint derived from the manifest contents.
    pub fingerprint: ReplayFingerprint,
}
impl ReplayKey {
    /// Helper to create a new key.
    #[must_use]
    pub const fn new(lane_epoch: LaneEpoch, sequence: u64, fingerprint: ReplayFingerprint) -> Self {
        Self {
            lane_epoch,
            sequence,
            fingerprint,
        }
    }
}
/// Opaque handle for rolling back one specific fresh replay-cache insertion.
///
/// The generation distinguishes a reservation from a later insertion of the same key after
/// expiry or eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayReservation {
    key: ReplayKey,
    generation: u128,
}
/// Configuration for [`ReplayCache`]. This governs eviction, TTL, and sequence windows.
#[derive(Clone, Copy, Debug)]
pub struct ReplayCacheConfig {
    /// Maximum number of committed manifests tracked per `(lane, epoch)` window.
    /// In-flight reservations may temporarily exceed this bound until they commit or roll back.
    pub max_entries_per_lane: NonZeroUsize,
    /// Maximum number of distinct `(lane, epoch)` windows retained globally.
    pub max_lane_epochs: NonZeroUsize,
    /// How long a manifest fingerprint stays live after its last observation.
    ///
    /// Expiry retains the lane/epoch sequence floor until [`ReplayCache::clear_lane_epoch`], so a
    /// pruned lane cannot be re-created at an arbitrary nonzero sequence.
    pub ttl: Duration,
    /// Maximum allowed distance from the highest observed sequence number before a new
    /// manifest is considered stale.
    pub max_sequence_lag: u64,
}
impl ReplayCacheConfig {
    /// Default TTL used for DA manifest replay detection (15 minutes).
    pub const DEFAULT_TTL: Duration = Duration::from_mins(15);
    /// Default capacity per `(lane, epoch)` window (4096 entries).
    pub const DEFAULT_CAPACITY: usize = 4096;
    /// Default global `(lane, epoch)` capacity (1024 windows).
    pub const DEFAULT_LANE_EPOCH_CAPACITY: usize = 1024;
    /// Default sequence lag tolerance (4096 slots behind the high-water mark).
    pub const DEFAULT_SEQUENCE_LAG: u64 = 4096;
    /// Construct a configuration using workspace defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_entries_per_lane: Self::default_capacity(),
            max_lane_epochs: Self::default_lane_epoch_capacity(),
            ttl: Self::DEFAULT_TTL,
            max_sequence_lag: Self::DEFAULT_SEQUENCE_LAG,
        }
    }
    fn default_capacity() -> NonZeroUsize {
        match NonZeroUsize::new(Self::DEFAULT_CAPACITY) {
            Some(capacity) => capacity,
            None => NonZeroUsize::MIN,
        }
    }
    fn default_lane_epoch_capacity() -> NonZeroUsize {
        match NonZeroUsize::new(Self::DEFAULT_LANE_EPOCH_CAPACITY) {
            Some(capacity) => capacity,
            None => NonZeroUsize::MIN,
        }
    }
    /// Override the per-lane capacity.
    #[must_use]
    pub fn with_max_entries_per_lane(mut self, capacity: NonZeroUsize) -> Self {
        self.max_entries_per_lane = capacity;
        self
    }
    /// Override the global `(lane, epoch)` capacity.
    #[must_use]
    pub fn with_max_lane_epochs(mut self, capacity: NonZeroUsize) -> Self {
        self.max_lane_epochs = capacity;
        self
    }
    /// Override the TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
    /// Override the maximum sequence lag.
    #[must_use]
    pub fn with_max_sequence_lag(mut self, lag: u64) -> Self {
        self.max_sequence_lag = lag;
        self
    }
}
impl Default for ReplayCacheConfig {
    fn default() -> Self {
        Self::new()
    }
}
/// Result returned when inserting a manifest fingerprint into the replay cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayInsertOutcome {
    /// Manifest is fresh and accepted into the cache.
    Fresh {
        /// Snapshot captured after inserting the manifest.
        snapshot: ReplayEntrySnapshot,
    },
    /// Manifest was already committed; the cache updates its observation metadata.
    Duplicate {
        /// Snapshot captured after registering the duplicate manifest.
        snapshot: ReplayEntrySnapshot,
    },
    /// An identical manifest is reserved by an ingest that has not committed durably yet.
    InFlight {
        /// Snapshot captured after observing the in-flight manifest.
        snapshot: ReplayEntrySnapshot,
    },
    /// Sequence number fell outside the permitted lag window.
    StaleSequence {
        /// Highest sequence observed for this `(lane, epoch)` window.
        highest_observed: u64,
    },
    /// Sequence number skipped over the next required slot, including sequence zero for a new
    /// `(lane, epoch)` window.
    SequenceGap {
        /// The next accepted sequence after the lane/epoch high-water mark.
        expected_next: u64,
        /// Sequence number supplied by the caller.
        observed: u64,
    },
    /// The manifest reused a sequence number but had a conflicting fingerprint.
    ConflictingFingerprint {
        /// Fingerprint that was already registered under the same sequence number.
        expected: ReplayFingerprint,
        /// Fingerprint that the caller attempted to insert.
        observed: ReplayFingerprint,
    },
    /// The global `(lane, epoch)` capacity is full.
    LaneEpochCapacityExceeded {
        /// Configured maximum number of distinct `(lane, epoch)` windows.
        capacity: usize,
    },
    /// The per-lane in-flight reservation capacity is full.
    ReservationCapacityExceeded {
        /// Configured maximum number of pending reservations for the lane/epoch.
        capacity: usize,
    },
}
/// Failure returned when persisted replay state cannot be primed safely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReplayPrimeError {
    /// Priming another distinct `(lane, epoch)` would exceed the global capacity.
    #[error("DA replay lane/epoch capacity {capacity} is exhausted")]
    LaneEpochCapacityExceeded {
        /// Configured maximum number of distinct `(lane, epoch)` windows.
        capacity: usize,
    },
}
/// Snapshot describing the state of a cached manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayEntrySnapshot {
    /// Timestamp when the manifest was first observed.
    pub first_seen: Instant,
    /// Timestamp of the most recent observation.
    pub last_seen: Instant,
    /// Number of times the manifest has been observed.
    pub hit_count: u32,
    /// Sequence number assigned to the manifest.
    pub sequence: u64,
}
/// Concurrency-safe cache tracking recently observed DA manifest fingerprints.
#[derive(Debug)]
pub struct ReplayCache {
    config: ReplayCacheConfig,
    inner: Mutex<ReplayCacheInner>,
}
impl ReplayCache {
    /// Construct a new replay cache using the provided configuration.
    #[must_use]
    pub fn new(config: ReplayCacheConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(ReplayCacheInner::default()),
        }
    }
    /// Insert a manifest fingerprint into the cache and obtain the resulting outcome.
    ///
    /// A new `(lane, epoch)` window starts at sequence zero. Once present, each fresh sequence must
    /// be the exact successor of its high-water mark.
    #[must_use]
    pub fn insert(&self, key: ReplayKey, now: Instant) -> ReplayInsertOutcome {
        self.insert_inner(key, now, false).0
    }
    /// Reserve a fresh manifest until the caller durably commits or rolls back the ingest.
    ///
    /// The optional handle is present exactly when the outcome is [`ReplayInsertOutcome::Fresh`].
    /// Pending reservations are not evicted by cache pruning and do not displace committed replay
    /// history before their durable receipt commits. A new `(lane, epoch)` reservation must start
    /// at sequence zero; later fresh reservations must be contiguous.
    #[must_use]
    pub fn reserve(
        &self,
        key: ReplayKey,
        now: Instant,
    ) -> (ReplayInsertOutcome, Option<ReplayReservation>) {
        self.insert_inner(key, now, true)
    }
    fn insert_inner(
        &self,
        key: ReplayKey,
        now: Instant,
        reserve: bool,
    ) -> (ReplayInsertOutcome, Option<ReplayReservation>) {
        let mut guard = self.inner.lock();
        guard.prune(now, &self.config);
        if !guard.lanes.contains_key(&key.lane_epoch)
            && guard.lanes.len() >= self.config.max_lane_epochs.get()
        {
            return (
                ReplayInsertOutcome::LaneEpochCapacityExceeded {
                    capacity: self.config.max_lane_epochs.get(),
                },
                None,
            );
        }
        if !guard.lanes.contains_key(&key.lane_epoch) && key.sequence != 0 {
            return (
                ReplayInsertOutcome::SequenceGap {
                    expected_next: 0,
                    observed: key.sequence,
                },
                None,
            );
        }
        let generation = reserve.then(|| {
            let generation = guard.next_reservation_generation;
            guard.next_reservation_generation = guard.next_reservation_generation.wrapping_add(1);
            generation
        });
        let lane_state = guard.lanes.entry(key.lane_epoch).or_default();
        if let Some(floor) = lane_state.stale_floor {
            if key.sequence <= floor {
                return (
                    ReplayInsertOutcome::StaleSequence {
                        highest_observed: lane_state.highest_sequence.max(floor),
                    },
                    None,
                );
            }
        }
        if lane_state.highest_sequence >= key.sequence {
            let lag = lane_state.highest_sequence.saturating_sub(key.sequence);
            if lag > self.config.max_sequence_lag {
                return (
                    ReplayInsertOutcome::StaleSequence {
                        highest_observed: lane_state.highest_sequence,
                    },
                    None,
                );
            }
        }
        if let Some(entry) = lane_state.entries.get_mut(&key.sequence) {
            if entry.fingerprint != key.fingerprint {
                return (
                    ReplayInsertOutcome::ConflictingFingerprint {
                        expected: entry.fingerprint,
                        observed: key.fingerprint,
                    },
                    None,
                );
            }
            entry.hit_count = entry.hit_count.saturating_add(1);
            entry.last_seen = now;
            let snapshot = entry.snapshot(key.sequence);
            if entry.reservation_generation.is_some() {
                (ReplayInsertOutcome::InFlight { snapshot }, None)
            } else {
                (ReplayInsertOutcome::Duplicate { snapshot }, None)
            }
        } else {
            if key.sequence > lane_state.highest_sequence
                && lane_state.requires_contiguous_successor()
                && let Some(expected_next) = lane_state.highest_sequence.checked_add(1)
                && key.sequence != expected_next
            {
                return (
                    ReplayInsertOutcome::SequenceGap {
                        expected_next,
                        observed: key.sequence,
                    },
                    None,
                );
            }
            if reserve
                && lane_state
                    .entries
                    .values()
                    .filter(|entry| entry.reservation_generation.is_some())
                    .count()
                    >= self.config.max_entries_per_lane.get()
            {
                return (
                    ReplayInsertOutcome::ReservationCapacityExceeded {
                        capacity: self.config.max_entries_per_lane.get(),
                    },
                    None,
                );
            }
            if lane_state.cannot_commit_sequence(key.sequence, &self.config) {
                return (
                    ReplayInsertOutcome::StaleSequence {
                        highest_observed: lane_state.highest_sequence,
                    },
                    None,
                );
            }
            let entry = Entry {
                fingerprint: key.fingerprint,
                first_seen: now,
                last_seen: now,
                hit_count: 1,
                reservation_generation: generation,
            };
            let updated = lane_state.highest_sequence.max(key.sequence);
            lane_state.highest_sequence = updated;
            if generation.is_none() {
                lane_state.committed_highest_sequence =
                    lane_state.committed_highest_sequence.max(key.sequence);
            }
            lane_state.entries.insert(key.sequence, entry);
            lane_state.enforce_capacity(&self.config, Some(key.sequence));
            let snapshot = lane_state.entries.get(&key.sequence).map_or_else(
                || entry.snapshot(key.sequence),
                |entry| entry.snapshot(key.sequence),
            );
            let reservation = generation.map(|generation| ReplayReservation { key, generation });
            (ReplayInsertOutcome::Fresh { snapshot }, reservation)
        }
    }
    /// Prime the replay cache with a known highest sequence for a `(lane, epoch)` window.
    /// This is useful when restoring state from persisted cursors after a restart. Priming
    /// invalidates any in-memory entries and reservations already present for that window.
    ///
    /// # Errors
    /// Returns `LaneEpochCapacityExceeded` if this is a new lane/epoch window and
    /// the configured window capacity is already occupied. Existing windows can
    /// always be primed without lowering their committed sequence.
    pub fn prime_lane_epoch(
        &self,
        lane_epoch: LaneEpoch,
        highest_sequence: u64,
    ) -> Result<(), ReplayPrimeError> {
        let mut guard = self.inner.lock();
        if !guard.lanes.contains_key(&lane_epoch)
            && guard.lanes.len() >= self.config.max_lane_epochs.get()
        {
            return Err(ReplayPrimeError::LaneEpochCapacityExceeded {
                capacity: self.config.max_lane_epochs.get(),
            });
        }
        let lane_state = guard.lanes.entry(lane_epoch).or_default();
        let primed = lane_state.committed_highest_sequence.max(highest_sequence);
        lane_state.highest_sequence = primed;
        lane_state.committed_highest_sequence = primed;
        lane_state.stale_floor = Some(primed);
        lane_state.entries.clear();
        Ok(())
    }
    /// Commit a fresh replay reservation after its durable receipt is accepted.
    ///
    /// Callers must let the durable receipt/cursor layer authorize sequence order first; a replay
    /// reservation prevents duplicate concurrent work but is not itself a durable admission grant.
    ///
    /// Returns `true` only when the exact pending generation was still present.
    pub fn commit_reservation(&self, reservation: &ReplayReservation) -> bool {
        let mut guard = self.inner.lock();
        let key = reservation.key;
        let Some(lane_state) = guard.lanes.get_mut(&key.lane_epoch) else {
            return false;
        };
        let matches_reservation = lane_state.entries.get(&key.sequence).is_some_and(|entry| {
            entry.fingerprint == key.fingerprint
                && entry.reservation_generation == Some(reservation.generation)
        });
        if !matches_reservation {
            return false;
        }
        if lane_state
            .stale_floor
            .is_some_and(|floor| key.sequence <= floor)
            || lane_state.cannot_commit_sequence(key.sequence, &self.config)
        {
            lane_state.entries.remove(&key.sequence);
            return false;
        }
        lane_state
            .entries
            .get_mut(&key.sequence)
            .expect("matching replay reservation entry exists")
            .reservation_generation = None;
        lane_state.committed_highest_sequence =
            lane_state.committed_highest_sequence.max(key.sequence);
        lane_state.enforce_capacity(&self.config, Some(key.sequence));
        true
    }
    /// Roll back a fresh replay reservation that did not reach durable acceptance.
    ///
    /// The entry is removed only when its key and opaque reservation generation still match, so
    /// an expired or evicted reservation cannot discard a later insertion of the same manifest.
    /// Returns `true` when the matching reservation was present.
    pub fn rollback_reservation(&self, reservation: ReplayReservation) -> bool {
        let mut guard = self.inner.lock();
        let mut remove_lane = false;
        let ReplayReservation { key, generation } = reservation;
        let removed = if let Some(lane_state) = guard.lanes.get_mut(&key.lane_epoch) {
            let matches_reservation = lane_state.entries.get(&key.sequence).is_some_and(|entry| {
                entry.fingerprint == key.fingerprint
                    && entry.reservation_generation == Some(generation)
            });
            if matches_reservation {
                lane_state.entries.remove(&key.sequence);
                lane_state.highest_sequence = lane_state
                    .entries
                    .keys()
                    .next_back()
                    .copied()
                    .into_iter()
                    .chain(lane_state.stale_floor)
                    .chain(std::iter::once(lane_state.committed_highest_sequence))
                    .max()
                    .unwrap_or_default();
                remove_lane = lane_state.entries.is_empty() && lane_state.stale_floor.is_none();
                true
            } else {
                false
            }
        } else {
            false
        };
        if remove_lane {
            guard.lanes.remove(&key.lane_epoch);
        }
        removed
    }
    /// Drop cached manifests for a `(lane, epoch)` window. This is useful during epoch
    /// transitions or when replay state is reset via governance.
    pub fn clear_lane_epoch(&self, lane_epoch: LaneEpoch) {
        let mut guard = self.inner.lock();
        guard.lanes.remove(&lane_epoch);
    }
    /// Inspect the number of cached manifests for a `(lane, epoch)` window. Intended for
    /// diagnostics and testing only.
    #[must_use]
    pub fn len_for_lane_epoch(&self, lane_epoch: LaneEpoch) -> usize {
        let guard = self.inner.lock();
        guard
            .lanes
            .get(&lane_epoch)
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }
    #[cfg(test)]
    /// Inspect the number of distinct `(lane, epoch)` windows retained globally.
    #[must_use]
    pub fn lane_epoch_count(&self) -> usize {
        self.inner.lock().lanes.len()
    }
    #[cfg(test)]
    fn highest_sequence(&self, lane_epoch: LaneEpoch) -> Option<u64> {
        self.inner
            .lock()
            .lanes
            .get(&lane_epoch)
            .map(|state| state.highest_sequence)
    }
}
#[derive(Default, Debug)]
struct ReplayCacheInner {
    lanes: BTreeMap<LaneEpoch, LaneState>,
    next_reservation_generation: u128,
}
impl ReplayCacheInner {
    fn prune(&mut self, now: Instant, config: &ReplayCacheConfig) {
        let mut empty_lanes = Vec::new();
        for (lane_epoch, state) in &mut self.lanes {
            if state.prune(now, config) {
                empty_lanes.push(*lane_epoch);
            }
        }
        for lane in empty_lanes {
            self.lanes.remove(&lane);
        }
    }
}
#[derive(Debug, Default)]
struct LaneState {
    highest_sequence: u64,
    committed_highest_sequence: u64,
    stale_floor: Option<u64>,
    entries: BTreeMap<u64, Entry>,
}
impl LaneState {
    fn cannot_commit_sequence(&self, sequence: u64, config: &ReplayCacheConfig) -> bool {
        let mut committed = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.reservation_generation.is_none());
        let first_sequence = committed.next().map(|(sequence, _)| *sequence);
        let committed_count = if first_sequence.is_some() {
            1_usize.saturating_add(committed.count())
        } else {
            Default::default()
        };
        committed_count >= config.max_entries_per_lane.get()
            && first_sequence.is_some_and(|first| sequence < first)
    }
    /// Returns `true` if the state became empty after pruning.
    fn prune(&mut self, now: Instant, config: &ReplayCacheConfig) -> bool {
        if self.entries.is_empty() {
            return self.stale_floor.is_none();
        }
        let ttl = config.ttl;
        let highest = self.highest_sequence;
        let max_lag = config.max_sequence_lag;
        let mut retired_floor = self.stale_floor;
        self.entries.retain(|sequence, entry| {
            if entry.reservation_generation.is_some() {
                return true;
            }
            let expired = now
                .checked_duration_since(entry.last_seen)
                .is_some_and(|duration| duration >= ttl);
            let too_far = highest.saturating_sub(*sequence) > max_lag;
            let retain = !(expired || too_far);
            if !retain {
                retired_floor = Some(retired_floor.map_or(*sequence, |floor| floor.max(*sequence)));
            }
            retain
        });
        self.stale_floor = retired_floor;
        self.entries.is_empty() && self.stale_floor.is_none()
    }
    fn enforce_capacity(&mut self, config: &ReplayCacheConfig, protected_sequence: Option<u64>) {
        let max_entries = config.max_entries_per_lane.get();
        while self
            .entries
            .values()
            .filter(|entry| entry.reservation_generation.is_none())
            .count()
            > max_entries
        {
            if let Some((&sequence, _)) = self
                .entries
                .iter()
                .filter(|(sequence, _)| Some(**sequence) != protected_sequence)
                .find(|(_, entry)| entry.reservation_generation.is_none())
            {
                if self.entries.remove(&sequence).is_some() {
                    self.retire_evicted_sequence(sequence);
                }
            } else {
                break;
            }
        }
        if let Some(floor) = self.stale_floor {
            self.entries.retain(|sequence, entry| {
                entry.reservation_generation.is_none() || *sequence > floor
            });
        }
    }
    fn retire_evicted_sequence(&mut self, sequence: u64) {
        let min_retained = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.reservation_generation.is_none())
            .map(|(sequence, _)| *sequence)
            .next();
        if min_retained.is_none_or(|min| sequence < min) {
            self.stale_floor = Some(
                self.stale_floor
                    .map_or(sequence, |floor| floor.max(sequence)),
            );
        }
    }
    fn requires_contiguous_successor(&self) -> bool {
        self.stale_floor.is_some() || !self.entries.is_empty()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    fingerprint: ReplayFingerprint,
    first_seen: Instant,
    last_seen: Instant,
    hit_count: u32,
    reservation_generation: Option<u128>,
}
impl Entry {
    fn snapshot(&self, sequence: u64) -> ReplayEntrySnapshot {
        ReplayEntrySnapshot {
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            hit_count: self.hit_count,
            sequence,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::topology::LaneId;
    use std::{
        collections::BTreeSet,
        num::NonZeroUsize,
        thread,
        time::{Duration, Instant},
    };
    fn fingerprint(seed: u8) -> ReplayFingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[seed]);
        ReplayFingerprint::from_hash(hasher.finalize())
    }
    fn reserve_fresh(cache: &ReplayCache, key: ReplayKey, now: Instant) -> ReplayReservation {
        let (outcome, reservation) = cache.reserve(key, now);
        assert!(matches!(outcome, ReplayInsertOutcome::Fresh { .. }));
        reservation.expect("fresh outcome carries a replay reservation")
    }
    #[test]
    fn try_from_hash_bytes_rejects_malformed_lengths() {
        let bytes = [7u8; blake3::OUT_LEN];
        assert_eq!(
            ReplayFingerprint::try_from_hash_bytes(&bytes),
            Some(ReplayFingerprint::from(bytes)),
        );
        assert_eq!(
            ReplayFingerprint::try_from_hash_bytes(&bytes[..blake3::OUT_LEN - 1]),
            None,
        );
        let mut oversized = Vec::from(bytes);
        oversized.push(8);
        assert_eq!(ReplayFingerprint::try_from_hash_bytes(&oversized), None);
    }
    #[test]
    fn default_config_uses_declared_nonzero_capacity() {
        let config = ReplayCacheConfig::new();
        assert_eq!(
            config.max_entries_per_lane.get(),
            ReplayCacheConfig::DEFAULT_CAPACITY
        );
        assert_eq!(
            config.max_lane_epochs.get(),
            ReplayCacheConfig::DEFAULT_LANE_EPOCH_CAPACITY
        );
        const {
            assert!(ReplayCacheConfig::DEFAULT_CAPACITY > 0);
        }
        const {
            assert!(ReplayCacheConfig::DEFAULT_LANE_EPOCH_CAPACITY > 0);
        }
    }
    #[test]
    fn fresh_insert_is_recorded() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 42);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(1));
        let now = Instant::now();
        let outcome = cache.insert(key, now);
        match outcome {
            ReplayInsertOutcome::Fresh { snapshot, .. } => {
                assert_eq!(snapshot.sequence, 0);
                assert_eq!(snapshot.hit_count, 1);
                assert_eq!(snapshot.first_seen, now);
                assert_eq!(snapshot.last_seen, now);
            }
            other => panic!("expected Fresh, got {other:?}"),
        }
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 1);
    }
    #[test]
    fn first_reservation_requires_zero_sequence_without_allocating_lane_state() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 42);
        for (sequence, seed) in [(1, 1), (77, 77), (u64::MAX - 1, 0xFE)] {
            let (outcome, reservation) = cache.reserve(
                ReplayKey::new(lane_epoch, sequence, fingerprint(seed)),
                Instant::now(),
            );
            assert_eq!(
                outcome,
                ReplayInsertOutcome::SequenceGap {
                    expected_next: 0,
                    observed: sequence,
                }
            );
            assert!(reservation.is_none());
            assert_eq!(cache.lane_epoch_count(), 0);
        }
        let (outcome, reservation) = cache.reserve(
            ReplayKey::new(lane_epoch, 0, fingerprint(0)),
            Instant::now(),
        );
        assert!(matches!(outcome, ReplayInsertOutcome::Fresh { .. }));
        assert!(reservation.is_some());
    }
    #[test]
    fn forward_sequence_gap_rejected_after_history_exists() {
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_sequence_lag(u64::MAX));
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 42);
        let now = Instant::now();
        assert!(matches!(
            cache.insert(ReplayKey::new(lane_epoch, 0, fingerprint(7)), now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let outcome = cache.insert(
            ReplayKey::new(lane_epoch, 2, fingerprint(9)),
            now + Duration::from_millis(1),
        );
        assert_eq!(
            outcome,
            ReplayInsertOutcome::SequenceGap {
                expected_next: 1,
                observed: 2
            }
        );
        assert_eq!(
            cache.len_for_lane_epoch(lane_epoch),
            1,
            "gap rejection must not mutate the replay cache"
        );
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 1, fingerprint(8)),
                now + Duration::from_millis(2),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
    }
    #[test]
    fn primed_lane_rejects_forward_sequence_gap() {
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_sequence_lag(u64::MAX));
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 43);
        cache
            .prime_lane_epoch(lane_epoch, 50)
            .expect("priming within capacity succeeds");
        let outcome = cache.insert(
            ReplayKey::new(lane_epoch, 52, fingerprint(52)),
            Instant::now(),
        );
        assert_eq!(
            outcome,
            ReplayInsertOutcome::SequenceGap {
                expected_next: 51,
                observed: 52
            }
        );
        assert_eq!(
            cache.len_for_lane_epoch(lane_epoch),
            0,
            "gap rejection must not add an entry to a primed lane"
        );
    }
    #[test]
    fn duplicate_updates_hit_count() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 7);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(5));
        let first = Instant::now();
        let second = first + Duration::from_secs(1);
        let third = second + Duration::from_secs(1);
        assert!(matches!(
            cache.insert(key, first),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert!(matches!(
            cache.insert(key, second),
            ReplayInsertOutcome::Duplicate {
                snapshot: ReplayEntrySnapshot {
                    hit_count: 2,
                    last_seen,
                    ..
                }
            } if last_seen == second
        ));
        assert!(matches!(
            cache.insert(key, third),
            ReplayInsertOutcome::Duplicate {
                snapshot: ReplayEntrySnapshot {
                    hit_count: 3,
                    last_seen,
                    ..
                }
            } if last_seen == third
        ));
    }
    #[test]
    fn matching_pending_reservation_is_not_a_durable_duplicate() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 17);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(5));
        let first = Instant::now();
        let second = first + Duration::from_secs(1);
        let reservation = reserve_fresh(&cache, key, first);

        assert!(matches!(
            cache.reserve(key, second),
            (
                ReplayInsertOutcome::InFlight {
                    snapshot: ReplayEntrySnapshot {
                        hit_count: 2,
                        last_seen,
                        ..
                    }
                },
                None,
            ) if last_seen == second
        ));
        assert!(cache.commit_reservation(&reservation));
        assert!(matches!(
            cache.insert(key, second),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }
    #[test]
    fn rollback_reservation_reopens_only_the_matching_fresh_entry() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 8);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(5));
        let now = Instant::now();
        let first_reservation = reserve_fresh(&cache, key, now);
        let stale_first_reservation = first_reservation;
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 1);
        assert!(cache.rollback_reservation(first_reservation));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 0);
        assert_eq!(cache.lane_epoch_count(), 0);
        let current_reservation = reserve_fresh(&cache, key, now + Duration::from_millis(1));
        assert!(!cache.rollback_reservation(stale_first_reservation));
        assert!(cache.rollback_reservation(current_reservation));
    }
    #[test]
    fn rollback_reservation_does_not_remove_reinserted_generation() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(1).expect("non-zero capacity")),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 9);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(5));
        let now = Instant::now();
        let old_reservation = reserve_fresh(&cache, key, now);
        cache.clear_lane_epoch(lane_epoch);
        let current_reservation = reserve_fresh(&cache, key, now);
        assert!(!cache.rollback_reservation(old_reservation));
        assert!(cache.commit_reservation(&current_reservation));
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }
    #[test]
    fn priming_invalidates_older_pending_reservation() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 15);
        let pending = reserve_fresh(
            &cache,
            ReplayKey::new(lane_epoch, 0, fingerprint(5)),
            Instant::now(),
        );

        cache
            .prime_lane_epoch(lane_epoch, 10)
            .expect("priming existing lane within capacity succeeds");

        assert!(!cache.commit_reservation(&pending));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 0);
        assert_eq!(cache.highest_sequence(lane_epoch), Some(10));
        assert_eq!(
            cache.insert(
                ReplayKey::new(lane_epoch, 0, fingerprint(5)),
                Instant::now(),
            ),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 10
            }
        );
    }
    #[test]
    fn rollback_reservation_preserves_committed_entry_at_capacity() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(1).expect("non-zero capacity")),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 10);
        let accepted_key = ReplayKey::new(lane_epoch, 0, fingerprint(5));
        let failed_key = ReplayKey::new(lane_epoch, 1, fingerprint(6));
        let now = Instant::now();
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let failed_reservation = reserve_fresh(&cache, failed_key, now);
        assert!(cache.rollback_reservation(failed_reservation));
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 0, fingerprint(6)),
                now + Duration::from_millis(1),
            ),
            ReplayInsertOutcome::ConflictingFingerprint { .. }
        ));
    }
    #[test]
    fn later_commit_does_not_replace_newer_history_with_rolled_back_history() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(2).expect("non-zero capacity"))
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 12);
        let base = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 8)
            .expect("seed durable predecessor");
        for sequence in 9_u64..=10 {
            assert!(matches!(
                cache.insert(
                    ReplayKey::new(
                        lane_epoch,
                        sequence,
                        fingerprint(u8::try_from(sequence).expect("fixture value fits u8"))
                    ),
                    base + Duration::from_millis(sequence),
                ),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        let first = reserve_fresh(
            &cache,
            ReplayKey::new(lane_epoch, 11, fingerprint(11)),
            base + Duration::from_millis(11),
        );
        let second_key = ReplayKey::new(lane_epoch, 12, fingerprint(12));
        let second = reserve_fresh(&cache, second_key, base + Duration::from_millis(12));

        assert!(cache.commit_reservation(&second));
        assert!(cache.rollback_reservation(first));

        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 2);
        assert_eq!(cache.highest_sequence(lane_epoch), Some(12));
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 10, fingerprint(10)),
                base + Duration::from_millis(13),
            ),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(
            cache.insert(
                ReplayKey::new(lane_epoch, 9, fingerprint(9)),
                base + Duration::from_millis(14),
            ),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 12
            }
        );
        assert!(matches!(
            cache.insert(second_key, base + Duration::from_millis(15)),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }
    #[test]
    fn chained_pending_reservations_do_not_evict_or_restore_each_other() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(2).expect("non-zero capacity")),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 11);
        let accepted_key = ReplayKey::new(lane_epoch, 10, fingerprint(10));
        let first_pending_key = ReplayKey::new(lane_epoch, 11, fingerprint(11));
        let second_pending_key = ReplayKey::new(lane_epoch, 12, fingerprint(12));
        let now = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 9)
            .expect("seed durable predecessor");
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let first = reserve_fresh(&cache, first_pending_key, now);
        let second = reserve_fresh(&cache, second_pending_key, now);

        assert!(cache.rollback_reservation(first));
        assert!(cache.rollback_reservation(second));
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(cache.highest_sequence(lane_epoch), Some(10));

        let first = reserve_fresh(&cache, first_pending_key, now);
        let second = reserve_fresh(&cache, second_pending_key, now);
        assert!(cache.commit_reservation(&second));
        assert!(cache.rollback_reservation(first));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 2);
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert!(matches!(
            cache.insert(second_pending_key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(cache.highest_sequence(lane_epoch), Some(12));
    }
    #[test]
    fn pending_reservation_capacity_is_bounded_without_displacing_history() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(1).expect("non-zero capacity")),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 13);
        let accepted_key = ReplayKey::new(lane_epoch, 10, fingerprint(10));
        let first_pending_key = ReplayKey::new(lane_epoch, 11, fingerprint(11));
        let now = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 9)
            .expect("seed durable predecessor");
        assert!(matches!(
            cache.insert(accepted_key, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let first = reserve_fresh(&cache, first_pending_key, now);

        assert_eq!(
            cache.reserve(
                ReplayKey::new(lane_epoch, 12, fingerprint(12)),
                now + Duration::from_millis(1),
            ),
            (
                ReplayInsertOutcome::ReservationCapacityExceeded { capacity: 1 },
                None,
            )
        );
        assert!(matches!(
            cache.insert(accepted_key, now + Duration::from_millis(2)),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert!(cache.rollback_reservation(first));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 1);
    }
    #[test]
    fn capacity_floor_invalidates_older_pending_reservation() {
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(NonZeroUsize::new(3).expect("non-zero capacity"))
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 14);
        let base = Instant::now();
        let stale_pending =
            reserve_fresh(&cache, ReplayKey::new(lane_epoch, 0, fingerprint(0)), base);
        for sequence in 1_u64..=2 {
            assert!(matches!(
                cache.insert(
                    ReplayKey::new(
                        lane_epoch,
                        sequence,
                        fingerprint(u8::try_from(sequence).expect("fixture value fits u8"))
                    ),
                    base + Duration::from_millis(sequence),
                ),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        let first_successor = reserve_fresh(
            &cache,
            ReplayKey::new(lane_epoch, 3, fingerprint(3)),
            base + Duration::from_millis(3),
        );
        assert!(cache.commit_reservation(&first_successor));
        let second_successor = reserve_fresh(
            &cache,
            ReplayKey::new(lane_epoch, 4, fingerprint(4)),
            base + Duration::from_millis(4),
        );

        assert!(cache.commit_reservation(&second_successor));
        assert!(
            !cache.rollback_reservation(stale_pending),
            "advancing the committed capacity floor must invalidate an older pending entry"
        );
        assert_eq!(
            cache.insert(
                ReplayKey::new(lane_epoch, 1, fingerprint(1)),
                base + Duration::from_millis(5),
            ),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 4
            }
        );
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 3);
    }
    #[test]
    fn conflicting_fingerprint_detected() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        cache
            .prime_lane_epoch(lane_epoch, 9)
            .expect("seed durable predecessor");
        let key_a = ReplayKey::new(lane_epoch, 10, fingerprint(10));
        let key_b = ReplayKey::new(lane_epoch, 10, fingerprint(11));
        let now = Instant::now();
        assert!(matches!(
            cache.insert(key_a, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert!(matches!(
            cache.insert(key_b, now),
            ReplayInsertOutcome::ConflictingFingerprint { .. }
        ));
    }
    #[test]
    fn stale_sequence_rejected() {
        let config = ReplayCacheConfig::new().with_max_sequence_lag(2);
        let cache = ReplayCache::new(config);
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        cache
            .prime_lane_epoch(lane_epoch, 4)
            .expect("seed durable predecessor");
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 5, fingerprint(1)),
                Instant::now()
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 2, fingerprint(2)),
                Instant::now()
            ),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 5
            }
        ));
    }
    #[test]
    fn ttl_eviction_preserves_sequence_floor_and_accepts_exact_successor() {
        let config = ReplayCacheConfig::new()
            .with_ttl(Duration::from_millis(10))
            .with_max_entries_per_lane(NonZeroUsize::new(16).unwrap());
        let cache = ReplayCache::new(config);
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(1));
        let now = Instant::now();
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 1);
        thread::sleep(Duration::from_millis(20));
        let later = Instant::now();
        // Trigger pruning with the exact successor. The expired entry leaves a
        // floor so this lane/epoch cannot be reinitialized at an arbitrary head.
        assert!(matches!(
            cache.insert(ReplayKey::new(lane_epoch, 1, fingerprint(2)), later),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 1);
        assert_eq!(
            cache.insert(key, later + Duration::from_millis(1)),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 1
            }
        );
    }
    #[test]
    fn ttl_expires_at_exact_boundary() {
        let ttl = Duration::from_millis(10);
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_ttl(ttl));
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 16);
        let key = ReplayKey::new(lane_epoch, 0, fingerprint(1));
        let now = Instant::now();
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert_eq!(
            cache.insert(key, now + ttl),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 0
            }
        );
        assert!(matches!(
            cache.insert(ReplayKey::new(lane_epoch, 1, fingerprint(2)), now + ttl),
            ReplayInsertOutcome::Fresh { .. }
        ));
    }
    #[test]
    fn capacity_enforced() {
        let capacity = NonZeroUsize::new(4).unwrap();
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_entries_per_lane(capacity));
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        let base = Instant::now();
        for idx in 0_u64..6 {
            let idx_byte = u8::try_from(idx).expect("idx fits in u8");
            let key = ReplayKey::new(lane_epoch, idx, fingerprint(idx_byte));
            assert!(matches!(
                cache.insert(key, base + Duration::from_millis(idx)),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), capacity.get());
    }
    #[test]
    fn capacity_eviction_rejects_evicted_low_sequence_as_stale() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(capacity)
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        let base = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 9)
            .expect("seed durable predecessor");
        for sequence in 10_u64..=12 {
            assert!(matches!(
                cache.insert(
                    ReplayKey::new(
                        lane_epoch,
                        sequence,
                        fingerprint(u8::try_from(sequence).expect("fixture value fits u8"))
                    ),
                    base + Duration::from_millis(sequence),
                ),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), capacity.get());
        let replay = cache.insert(
            ReplayKey::new(lane_epoch, 10, fingerprint(10)),
            base + Duration::from_millis(13),
        );
        assert_eq!(
            replay,
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 12
            }
        );
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 11, fingerprint(11)),
                base + Duration::from_millis(14),
            ),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }
    #[test]
    fn capacity_eviction_preserves_new_insert_when_timestamp_is_oldest() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(capacity)
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 1);
        let base = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 9)
            .expect("seed durable predecessor");
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 10, fingerprint(10)),
                base + Duration::from_millis(10),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 11, fingerprint(11)),
                base + Duration::from_millis(11),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let key = ReplayKey::new(lane_epoch, 12, fingerprint(12));
        match cache.insert(key, base) {
            ReplayInsertOutcome::Fresh { snapshot, .. } => {
                assert_eq!(snapshot.sequence, 12);
                assert_eq!(snapshot.last_seen, base);
            }
            other => panic!("expected protected fresh insert, got {other:?}"),
        }
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), capacity.get());
        match cache.insert(key, base + Duration::from_millis(12)) {
            ReplayInsertOutcome::Duplicate { snapshot } => {
                assert_eq!(snapshot.sequence, 12);
                assert_eq!(snapshot.hit_count, 2);
            }
            other => panic!("protected insert should remain cached, got {other:?}"),
        }
    }
    #[test]
    fn capacity_evicts_sequence_prefix_instead_of_recently_touched_hole() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(capacity)
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 17);
        let base = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 0)
            .expect("seed durable predecessor");
        let first = ReplayKey::new(lane_epoch, 1, fingerprint(1));
        let second = ReplayKey::new(lane_epoch, 2, fingerprint(2));
        for key in [first, second] {
            assert!(matches!(
                cache.insert(key, base),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        assert!(matches!(
            cache.insert(first, base + Duration::from_millis(1)),
            ReplayInsertOutcome::Duplicate { .. }
        ));
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 3, fingerprint(3)),
                base + Duration::from_millis(2),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));

        assert_eq!(
            cache.insert(first, base + Duration::from_millis(3)),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 3
            }
        );
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 2, fingerprint(9)),
                base + Duration::from_millis(4),
            ),
            ReplayInsertOutcome::ConflictingFingerprint { .. }
        ));
    }
    #[test]
    fn full_capacity_rejects_new_sequence_below_retained_window() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_entries_per_lane(capacity)
                .with_max_sequence_lag(u64::MAX),
        );
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 18);
        let now = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 8)
            .expect("seed durable predecessor");
        for sequence in 9_u64..=10 {
            assert!(matches!(
                cache.insert(
                    ReplayKey::new(
                        lane_epoch,
                        sequence,
                        fingerprint(u8::try_from(sequence).expect("fixture value fits u8"))
                    ),
                    now,
                ),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }

        assert_eq!(
            cache.insert(
                ReplayKey::new(lane_epoch, 8, fingerprint(8)),
                now + Duration::from_millis(1),
            ),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 10
            }
        );
        assert_eq!(
            cache.reserve(
                ReplayKey::new(lane_epoch, 8, fingerprint(8)),
                now + Duration::from_millis(2),
            ),
            (
                ReplayInsertOutcome::StaleSequence {
                    highest_observed: 10
                },
                None,
            ),
            "a pending backfill must not force a hole in committed history"
        );
        assert_eq!(cache.len_for_lane_epoch(lane_epoch), 2);
    }
    #[test]
    fn fresh_then_duplicate_for_replayed_sequences() {
        let cases: &[&[u64]] = &[
            &[0],
            &[0, 0],
            &[0, 1, 0, 2, 1],
            &[0, 1, 2, 0, 2, 1, 3],
            &[0, 1, 2, 3, 0, 1, 3, 2],
            &[0, 0, 1, 2, 1, 3, 0],
        ];
        for sequences in cases {
            let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_sequence_lag(u64::MAX));
            let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 99);
            let mut seen = BTreeSet::new();
            let mut now = Instant::now();
            for &sequence in *sequences {
                now += Duration::from_micros(1);
                let key =
                    ReplayKey::new(lane_epoch, sequence, fingerprint((sequence & 0xFF) as u8));
                let outcome = cache.insert(key, now);
                if seen.insert(sequence) {
                    let is_fresh = matches!(&outcome, ReplayInsertOutcome::Fresh { .. });
                    assert!(is_fresh, "sequence={sequence}");
                } else {
                    let is_duplicate = matches!(&outcome, ReplayInsertOutcome::Duplicate { .. });
                    assert!(is_duplicate, "sequence={sequence}");
                }
            }
        }
    }
    #[test]
    fn prime_restores_highest_sequence() {
        let cache = ReplayCache::new(ReplayCacheConfig::new());
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 5);
        cache
            .prime_lane_epoch(lane_epoch, 10)
            .expect("priming within capacity succeeds");
        let outcome = cache.insert(
            ReplayKey::new(lane_epoch, 4, fingerprint(1)),
            Instant::now(),
        );
        match outcome {
            ReplayInsertOutcome::StaleSequence { highest_observed } => {
                assert_eq!(highest_observed, 10);
            }
            other => panic!("expected stale sequence, got {other:?}"),
        }
    }
    #[test]
    fn prime_enforces_floor_even_when_within_lag() {
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_sequence_lag(4096));
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 7);
        cache
            .prime_lane_epoch(lane_epoch, 50)
            .expect("priming within capacity succeeds");
        let outcome = cache.insert(
            ReplayKey::new(lane_epoch, 49, fingerprint(2)),
            Instant::now(),
        );
        match outcome {
            ReplayInsertOutcome::StaleSequence { highest_observed } => {
                assert_eq!(highest_observed, 50);
            }
            other => panic!("expected stale sequence due to primed floor, got {other:?}"),
        }
    }
    #[test]
    fn prime_floor_survives_ttl_pruning() {
        let config = ReplayCacheConfig::new()
            .with_ttl(Duration::from_millis(10))
            .with_max_sequence_lag(4096);
        let cache = ReplayCache::new(config);
        let lane_epoch = LaneEpoch::new(LaneId::SINGLE, 8);
        let base = Instant::now();
        cache
            .prime_lane_epoch(lane_epoch, 50)
            .expect("priming within capacity succeeds");
        assert!(matches!(
            cache.insert(
                ReplayKey::new(lane_epoch, 51, fingerprint(51)),
                base + Duration::from_millis(1),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
        let outcome = cache.insert(
            ReplayKey::new(lane_epoch, 50, fingerprint(50)),
            base + Duration::from_millis(20),
        );
        match outcome {
            ReplayInsertOutcome::StaleSequence { highest_observed } => {
                assert_eq!(highest_observed, 51);
            }
            other => panic!("expected primed floor to survive TTL pruning, got {other:?}"),
        }
    }
    #[test]
    fn global_lane_epoch_capacity_rejects_new_windows_without_mutation() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let cache = ReplayCache::new(
            ReplayCacheConfig::new()
                .with_max_lane_epochs(capacity)
                .with_max_sequence_lag(u64::MAX),
        );
        let base = Instant::now();
        let first = LaneEpoch::new(LaneId::new(1), 1);
        let second = LaneEpoch::new(LaneId::new(1), 2);
        let rejected = LaneEpoch::new(LaneId::new(1), 3);
        for (index, lane_epoch) in [first, second].into_iter().enumerate() {
            assert!(matches!(
                cache.insert(
                    ReplayKey::new(
                        lane_epoch,
                        0,
                        fingerprint(u8::try_from(index).expect("fixture value fits u8"))
                    ),
                    base + Duration::from_millis(index as u64),
                ),
                ReplayInsertOutcome::Fresh { .. }
            ));
        }
        assert_eq!(
            cache.insert(
                ReplayKey::new(rejected, 0, fingerprint(3)),
                base + Duration::from_millis(3),
            ),
            ReplayInsertOutcome::LaneEpochCapacityExceeded { capacity: 2 }
        );
        assert_eq!(cache.lane_epoch_count(), 2);
        assert_eq!(cache.len_for_lane_epoch(rejected), 0);
        assert!(matches!(
            cache.insert(
                ReplayKey::new(first, 1, fingerprint(4)),
                base + Duration::from_millis(4),
            ),
            ReplayInsertOutcome::Fresh { .. }
        ));
    }
    #[test]
    fn priming_fails_closed_at_global_lane_epoch_capacity() {
        let capacity = NonZeroUsize::new(1).unwrap();
        let cache = ReplayCache::new(ReplayCacheConfig::new().with_max_lane_epochs(capacity));
        let retained = LaneEpoch::new(LaneId::new(2), 10);
        let rejected = LaneEpoch::new(LaneId::new(2), 11);
        cache
            .prime_lane_epoch(retained, 7)
            .expect("first lane/epoch fits");
        assert_eq!(
            cache.prime_lane_epoch(rejected, 9),
            Err(ReplayPrimeError::LaneEpochCapacityExceeded { capacity: 1 })
        );
        assert_eq!(cache.lane_epoch_count(), 1);
        cache
            .prime_lane_epoch(retained, 8)
            .expect("updating an existing primed window remains allowed");
        assert!(matches!(
            cache.insert(ReplayKey::new(retained, 8, fingerprint(8)), Instant::now(),),
            ReplayInsertOutcome::StaleSequence {
                highest_observed: 8
            }
        ));
    }
}
