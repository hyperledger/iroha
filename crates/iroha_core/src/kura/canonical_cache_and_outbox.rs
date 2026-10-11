type BlockDataEntry = (
    HashOf<BlockHeader>,
    Option<iroha_data_model::block::SharedSignedBlock>,
);

/// Canonical block identities and the bounded body cache.
///
/// Strict startup materializes every hash so it can audit and index the complete
/// history. Emergency Fast startup deliberately keeps only the durable height
/// and populates sparse entries when a caller reads a particular block. This
/// makes Fast startup memory and CPU independent of chain height.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BlockData {
    Dense(Vec<BlockDataEntry>),
    Deferred {
        len: usize,
        entries: BTreeMap<usize, BlockDataEntry>,
    },
}

impl Default for BlockData {
    fn default() -> Self {
        Self::Dense(Vec::new())
    }
}

impl FromIterator<BlockDataEntry> for BlockData {
    fn from_iter<T: IntoIterator<Item = BlockDataEntry>>(iter: T) -> Self {
        Self::Dense(iter.into_iter().collect())
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for BlockData {
    type Output = BlockDataEntry;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .expect("test requested an uncached deferred Kura block entry")
    }
}

#[cfg(test)]
impl std::ops::IndexMut<usize> for BlockData {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index)
            .expect("test requested an uncached deferred Kura block entry")
    }
}

impl BlockData {
    fn deferred(len: usize) -> Self {
        Self::Deferred {
            len,
            entries: BTreeMap::new(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Dense(entries) => entries.len(),
            Self::Deferred { len, .. } => *len,
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, index: usize) -> Option<&BlockDataEntry> {
        match self {
            Self::Dense(entries) => entries.get(index),
            Self::Deferred { len, entries } => {
                (*len > index).then(|| entries.get(&index)).flatten()
            }
        }
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut BlockDataEntry> {
        match self {
            Self::Dense(entries) => entries.get_mut(index),
            Self::Deferred { len, entries } => {
                (*len > index).then(|| entries.get_mut(&index)).flatten()
            }
        }
    }

    fn known_hash(&self, index: usize) -> Option<HashOf<BlockHeader>> {
        self.get(index).map(|(hash, _)| *hash)
    }

    fn cached_body(&self, index: usize) -> Option<iroha_data_model::block::SharedSignedBlock> {
        self.get(index).and_then(|(_, body)| body.clone())
    }

    fn cache_hash(&mut self, index: usize, hash: HashOf<BlockHeader>) {
        match self {
            Self::Dense(entries) => {
                debug_assert_eq!(entries.get(index).map(|(known, _)| *known), Some(hash));
            }
            Self::Deferred { len, entries } if index < *len => {
                entries
                    .entry(index)
                    .and_modify(|(known, _)| debug_assert_eq!(*known, hash))
                    .or_insert((hash, None));
            }
            Self::Deferred { .. } => {}
        }
    }

    fn cache_body_if_hash(
        &mut self,
        index: usize,
        hash: HashOf<BlockHeader>,
        body: iroha_data_model::block::SharedSignedBlock,
    ) -> bool {
        match self {
            Self::Dense(entries) => {
                let Some((known, cached)) = entries.get_mut(index) else {
                    return false;
                };
                if *known != hash {
                    return false;
                }
                *cached = Some(body);
                true
            }
            Self::Deferred { len, entries } => {
                if index >= *len {
                    return false;
                }
                match entries.entry(index) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert((hash, Some(body)));
                        true
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        if slot.get().0 != hash {
                            return false;
                        }
                        slot.get_mut().1 = Some(body);
                        true
                    }
                }
            }
        }
    }

    /// Borrow the complete canonical history when Strict startup materialized it.
    fn dense_entries(&self) -> Option<&[BlockDataEntry]> {
        match self {
            Self::Dense(entries) => Some(entries.as_slice()),
            Self::Deferred { .. } => None,
        }
    }

    #[cfg(test)]
    fn as_slice(&self) -> &[BlockDataEntry] {
        self.dense_entries()
            .expect("test requested a dense slice from deferred Fast history")
    }

    #[cfg(test)]
    fn first(&self) -> Option<&BlockDataEntry> {
        self.get(0)
    }

    fn last(&self) -> Option<&BlockDataEntry> {
        self.len().checked_sub(1).and_then(|index| self.get(index))
    }

    fn last_mut(&mut self) -> Option<&mut BlockDataEntry> {
        self.len()
            .checked_sub(1)
            .and_then(|index| self.get_mut(index))
    }

    fn push(&mut self, entry: BlockDataEntry) {
        match self {
            Self::Dense(entries) => entries.push(entry),
            Self::Deferred { len, entries } => {
                entries.insert(*len, entry);
                *len = len.saturating_add(1);
            }
        }
    }

    fn truncate(&mut self, len: usize) {
        match self {
            Self::Dense(entries) => entries.truncate(len),
            Self::Deferred {
                len: logical_len,
                entries,
            } => {
                *logical_len = (*logical_len).min(len);
                entries.retain(|index, _| *index < *logical_len);
            }
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        match self {
            Self::Dense(entries) => entries.clear(),
            Self::Deferred { len, entries } => {
                *len = 0;
                entries.clear();
            }
        }
    }

    fn extend<T: IntoIterator<Item = BlockDataEntry>>(&mut self, entries: T) {
        for entry in entries {
            self.push(entry);
        }
    }
}
type BlockHeightIndex = HashMap<HashOf<BlockHeader>, NonZeroUsize>;
type TransactionEntrypointHeights = BTreeMap<HashOf<TransactionEntrypoint>, BTreeSet<NonZeroUsize>>;
type TransactionAuthorityHeights = BTreeMap<AccountId, BTreeSet<NonZeroUsize>>;
type TransactionTimestampHeights = BTreeMap<u64, BTreeSet<NonZeroUsize>>;
type TransactionResultStatusHeights = BTreeMap<bool, BTreeSet<NonZeroUsize>>;
#[derive(Debug, Clone)]
struct QueuedFastpqProofSnapshot {
    snapshot: FastpqProofSnapshot,
    retries: usize,
}
/// Result of enqueueing pipeline recovery metadata for sidecar persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PipelineSidecarEnqueueResult {
    /// The sidecar was accepted.
    Enqueued {
        /// Queue depth after the sidecar was accepted.
        queue_depth: usize,
    },
    /// The queue is already at the configured capacity.
    RejectedQueueFull {
        /// Configured queue capacity.
        cap: usize,
    },
    /// A canonical prune is active or prune recovery requires a process restart.
    RejectedPruneRecovery,
    /// Emergency Fast mode is read-only and never starts a persistence worker.
    RejectedEmergencyFast,
    /// Snapshot authentication is pending or canonical storage is poisoned.
    RejectedUnauthorized,
}
/// Result of enqueueing a FASTPQ proof snapshot for sidecar persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum FastpqProofEnqueueResult {
    /// The snapshot was accepted.
    Enqueued {
        /// Queue depth after the snapshot was accepted.
        queue_depth: usize,
    },
    /// The encoded snapshot exceeded the configured byte limit.
    RejectedTooLarge {
        /// Encoded snapshot size in bytes.
        actual: usize,
        /// Configured maximum size in bytes.
        max: usize,
    },
    /// The queue is already at the configured capacity.
    RejectedQueueFull {
        /// Configured queue capacity.
        cap: usize,
    },
    /// The snapshot could not be encoded for size accounting.
    RejectedEncode {
        /// Human-readable encode failure.
        reason: String,
    },
    /// A canonical prune is active or prune recovery requires a process restart.
    RejectedPruneRecovery,
    /// Emergency Fast mode is read-only and never starts a persistence worker.
    RejectedEmergencyFast,
    /// Snapshot authentication is pending or canonical storage is poisoned.
    RejectedUnauthorized,
    /// Shutdown began before the snapshot's queue insertion was committed.
    RejectedShutdown,
}
#[derive(Clone, Default, Debug)]
struct FastpqProofSidecarTelemetry;
impl FastpqProofSidecarTelemetry {
    fn set_queue_depth(&self, depth: usize) {
        let _ = self;
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics.set_fastpq_proof_sidecar_queue_depth(u64::try_from(depth).unwrap_or(u64::MAX));
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = depth;
    }
    fn record_event(&self, event: &'static str) {
        let _ = self;
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics.inc_fastpq_proof_sidecar_event(event);
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = event;
    }
}

/// Stable structural position of one indexed Kaigi signal carrier.
///
/// Positions follow the app endpoint's chronological order: lower block
/// heights are older and lower Network input indexes are earlier within one
/// carrier. Internal invocation outputs have no position here. The
/// hashes bind a cursor to the exact canonical carrier and entrypoint.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::KaigiSignalCandidatePosition")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct KaigiSignalCandidatePosition {
    block_height: u64,
    network_input_index: u32,
    block_hash: HashOf<BlockHeader>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
}

impl KaigiSignalCandidatePosition {
    /// Construct a canonical signal position.
    #[must_use]
    pub fn new(
        block_height: u64,
        network_input_index: u32,
        block_hash: HashOf<BlockHeader>,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Option<Self> {
        (block_height > 0).then_some(Self {
            block_height,
            network_input_index,
            block_hash,
            entrypoint_hash,
        })
    }

    /// Return the one-based canonical carrier height.
    #[must_use]
    pub const fn block_height(self) -> u64 {
        self.block_height
    }

    /// Return the position in the complete canonical Network input sequence.
    #[must_use]
    pub const fn network_input_index(self) -> u32 {
        self.network_input_index
    }

    /// Return the canonical carrier block hash.
    #[must_use]
    pub const fn block_hash(self) -> HashOf<BlockHeader> {
        self.block_hash
    }

    /// Return the indexed entrypoint hash.
    #[must_use]
    pub const fn entrypoint_hash(self) -> HashOf<TransactionEntrypoint> {
        self.entrypoint_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KaigiSignalCandidateLocator {
    pub(crate) position: KaigiSignalCandidatePosition,
    pub(crate) authority: AccountId,
}

type KaigiSignalCandidatesByOffset = BTreeMap<u32, KaigiSignalCandidateLocator>;
type KaigiSignalCandidatesByHeight = BTreeMap<NonZeroUsize, KaigiSignalCandidatesByOffset>;
type KaigiSignalCandidatesByCall = BTreeMap<KaigiId, KaigiSignalCandidatesByHeight>;

#[derive(Debug, Default)]
struct TransactionEntrypointHeightInventory {
    entrypoint_hashes: BTreeSet<HashOf<TransactionEntrypoint>>,
    authorities: BTreeSet<AccountId>,
    timestamps_ms: BTreeSet<u64>,
    result_statuses: BTreeSet<bool>,
    kaigi_calls: BTreeSet<KaigiId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KaigiSignalCandidateIndexError {
    Unavailable,
    CursorMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KaigiSignalCandidateLocatorPage {
    pub(crate) candidates: Vec<KaigiSignalCandidateLocator>,
    pub(crate) has_more: bool,
}

#[derive(Debug)]
struct TransactionEntrypointIndex {
    /// All nested memberships; outer height-marker maps are counted separately.
    nested_associations: AssociationCount,
    complete: bool,
    indexed_heights: BTreeSet<NonZeroUsize>,
    incomplete_heights: BTreeSet<NonZeroUsize>,
    heights_by_entrypoint: TransactionEntrypointHeights,
    heights_by_authority: TransactionAuthorityHeights,
    heights_by_timestamp_ms: TransactionTimestampHeights,
    heights_by_result_status: TransactionResultStatusHeights,
    kaigi_signal_candidates: KaigiSignalCandidatesByCall,
    inventories_by_height: BTreeMap<NonZeroUsize, TransactionEntrypointHeightInventory>,
}
impl TransactionEntrypointIndex {
    fn complete_empty() -> Self {
        Self {
            nested_associations: AssociationCount::default(),
            complete: true,
            indexed_heights: BTreeSet::new(),
            incomplete_heights: BTreeSet::new(),
            heights_by_entrypoint: BTreeMap::new(),
            heights_by_authority: BTreeMap::new(),
            heights_by_timestamp_ms: BTreeMap::new(),
            heights_by_result_status: BTreeMap::new(),
            kaigi_signal_candidates: BTreeMap::new(),
            inventories_by_height: BTreeMap::new(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum FsyncTarget {
    Data,
    Index,
    Hashes,
}
impl FsyncTarget {
    #[cfg(feature = "telemetry")]
    fn label(self) -> &'static str {
        match self {
            Self::Data => "blocks.data",
            Self::Index => "blocks.index",
            Self::Hashes => "blocks.hashes",
        }
    }
}
#[derive(Debug, Clone)]
struct FsyncState {
    mode: FsyncMode,
    interval: Duration,
    pending_since: Option<Instant>,
}
impl FsyncState {
    fn new(mode: FsyncMode, interval: Duration) -> Self {
        Self {
            mode,
            interval,
            pending_since: None,
        }
    }
    fn record_write(&mut self, now: Instant) {
        self.pending_since.get_or_insert(now);
    }
    fn clear(&mut self) {
        self.pending_since = None;
    }
    fn deadline(&self) -> Option<Instant> {
        match (self.mode, self.pending_since) {
            (_, None) => None,
            (FsyncMode::Always, Some(ts)) => Some(ts),
            (FsyncMode::Batched, Some(ts)) => Some(ts + self.interval),
        }
    }
    fn is_due(&self, now: Instant, force: bool) -> bool {
        match self.mode {
            FsyncMode::Always => self.pending_since.is_some(),
            FsyncMode::Batched => self.pending_since.is_some_and(|pending| {
                force
                    || self.interval == Duration::ZERO
                    || now.saturating_duration_since(pending) >= self.interval
            }),
        }
    }
}
#[derive(Clone, Default, Debug)]
struct FsyncTelemetry;
impl FsyncTelemetry {
    fn new(mode: FsyncMode) -> Self {
        let telemetry = Self;
        telemetry.update_mode(mode);
        telemetry
    }
    fn update_mode(&self, mode: FsyncMode) {
        let _ = self;
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics.set_kura_fsync_mode(mode);
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = mode;
    }
    fn record_success(&self, target: FsyncTarget, duration: Duration) {
        let _ = self;
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics.record_kura_fsync_latency(target.label(), duration);
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = (target, duration);
    }
    fn record_failure(&self, target: FsyncTarget, duration: Option<Duration>) {
        let _ = self;
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = iroha_telemetry::metrics::global() {
            metrics.inc_kura_fsync_failure(target.label());
            if let Some(duration) = duration {
                metrics.record_kura_fsync_latency(target.label(), duration);
            }
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = (target, duration);
    }
}
#[derive(Debug)]
struct ChainValidation {
    hashes: Vec<HashOf<BlockHeader>>,
}
