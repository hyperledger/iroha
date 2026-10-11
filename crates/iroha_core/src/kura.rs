//! Translates to warehouse. File-system and persistence-related
//! logic.  [`Kura`] is the main entity which should be used to store
//! new [`Block`](iroha_data_model::block::SignedBlock)s on the
//! blockchain.
mod block_hash_range;
#[cfg(any(test, feature = "iroha-core-tests"))]
mod certificate_corruption_test_support;
mod fastpq_artifact_store;
pub(crate) mod history_checkpoints;
mod lane_geometry;
mod lane_storage;
mod membership_storage;
use crate::telemetry::StateTelemetry;
use crate::{
    block::CommittedBlock,
    secure_file_metadata::{self, SecureMetadata},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use block_hash_range::checked_block_hash_read_range;
pub use fastpq_artifact_store::{FastpqDurableArtifactReceipt, FastpqStoredArtifactReference};
use iroha_config::{
    base::WithOrigin,
    kura::{FsyncMode, InitMode},
    parameters::{
        actual::{Fastpq as FastpqConfig, Kura as Config, LaneConfig},
        defaults::{
            kura::{BLOCKS_IN_MEMORY, FSYNC_INTERVAL, MAX_DISK_USAGE_BYTES},
            zk::fastpq as FASTPQ_DEFAULTS,
        },
    },
};
#[cfg(test)]
use iroha_crypto::Algorithm;
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
use iroha_crypto::KeyPair;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    AccountId, NetworkId,
    block::{
        BlockHeader, SignedBlock, consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
        decode_framed_signed_block,
    },
    kaigi::KaigiId,
    nexus::{LaneCatalog, LaneLifecycleParameterV1},
    transaction::signed::{TransactionEntrypoint, TransactionResult},
};
use iroha_file_mmap::ReadOnlyMmap;
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal, spawn_os_thread_as_future};
use iroha_logger::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
pub use lane_geometry::RawGeometryWait;
pub(crate) use lane_geometry::{GeometryBindingRequest, RawGeometryAttempt, RawGeometryPhase};
use lane_storage::LaneStorageEntry;
pub use lane_storage::LaneStorageIdentity;
pub(crate) use membership_storage::MEMBERSHIP_RECORD_BYTES;
pub use membership_storage::{
    MembershipAppendCleanup, MembershipAppendRange, MembershipStorageError,
};
#[cfg(test)]
use norito::core::{Header, MAGIC};
use norito::{
    codec::{Decode, DecodeAll, Encode},
    json::Value as JsonValue,
};
use parking_lot::{Condvar, Mutex};
#[cfg(test)]
use std::num::NonZeroU64;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fmt::Debug,
    io::{BufWriter, ErrorKind, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    ops::Bound,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
impl From<CommittedBlock> for iroha_data_model::block::SharedSignedBlock {
    fn from(value: CommittedBlock) -> Self {
        value.into_shared()
    }
}
const INDEX_FILE_NAME: &str = "blocks.index";
const DATA_FILE_NAME: &str = "blocks.data";
const HASHES_FILE_NAME: &str = "blocks.hashes";
const COUNT_FILE_NAME: &str = "blocks.count.norito";
const MAX_BOUND_PROGRESS_INDEX_ENTRIES: usize = 65_536;
const BOUND_PROGRESS_APPEND_INTENT_VERSION: u16 = 1;
const BOUND_PROGRESS_APPEND_INTENT_MAX_BYTES: usize = 128 * 1024;
// Ordinary append/replacement keeps its existing envelope. A bounded prepend
// owns both complete index images in the same durable intent.
const BOUND_PROGRESS_PREPEND_INDEX_MAX_BYTES: usize =
    INDEXED_SIDECAR_BASE_HEADER_SIZE + MAX_BOUND_PROGRESS_INDEX_ENTRIES * PIPELINE_INDEX_ENTRY_SIZE;
const BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES: usize =
    BOUND_PROGRESS_APPEND_INTENT_MAX_BYTES + 2 * BOUND_PROGRESS_PREPEND_INDEX_MAX_BYTES;

const BOUND_PROGRESS_APPEND_DIGEST_DOMAIN: &[u8] = b"iroha:kura:bound-progress-append:v1\0";
const BOUND_PROGRESS_APPEND_INTENT_DIGEST_DOMAIN: &[u8] =
    b"iroha:kura:bound-progress-append-intent:v1\0";
const MAX_BLOCK_COMMIT_MARKER_BYTES: usize = 1024;
const VERIFIED_SNAPSHOT_TAIL_FILE_NAME: &str = "verified_snapshot_tail.norito";
const STORE_ROOT_LOCK_FILE_NAME: &str = ".kura.lock";
/// Retired pre-release rollback marker. No first-release code writes or recovers it;
/// its presence is rejected so operators must remove stale state explicitly.
const ROLLBACK_INTENT_FILE_NAME: &str = "rollback-intent.norito";
/// Maximum canonical pipeline recovery sidecar accepted by storage and read APIs.
pub const MAX_PIPELINE_RECOVERY_SIDECAR_BYTES: usize = 1024 * 1024;
const PIPELINE_DIR_NAME: &str = "pipeline";
const DA_BLOCKS_DIR_NAME: &str = "da_blocks";
const DA_BLOCK_REWRITE_STAGE_FILE_NAME: &str = "da_block_rewrite_stage.norito";
const DA_BLOCK_REWRITE_STAGE_VERSION: u16 = 1;
const EVICTION_COMPACTION_STAGE_FILE_NAME: &str = "eviction_compaction_stage.norito";
const EVICTION_COMPACTION_STAGE_VERSION: u16 = 1;
const EVICTION_COMPACTION_DATA_FILE_NAME: &str = "blocks.data.eviction-v1";
const EVICTION_COMPACTION_INDEX_FILE_NAME: &str = "blocks.index.eviction-v1";
const MAX_EVICTION_COMPACTION_STAGE_BYTES: u64 = 1024 * 1024;
const MAX_EVICTION_COMPACTION_ENTRIES: usize = 4096;
const EVICTION_FILE_DIGEST_DOMAIN: &[u8] = b"iroha:kura:eviction-file:v1\0";

include!("kura/storage_identity.rs");
include!("kura/read_only_evidence.rs");
include!("kura/bound_progress_and_retained_support.rs");
#[cfg(test)]
std::thread_local! {
    static AUTONOMOUS_ATTEMPT_FRAME_DECODES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static SIDECAR_DIRECTORY_CANONICALIZATIONS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static AUTONOMOUS_ARTIFACT_VALIDATIONS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
const CONSENSUS_SIDECAR_MATCH_SCAN_BUDGET: usize = 64;
/// Lane evidence that authorizes a later durable publication must cross the
/// complete data/index/directory barrier independently of ordinary batched
/// sidecar persistence.
const REQUIRED_LANE_SIDECAR_FSYNC_MODE: FsyncMode = FsyncMode::Always;
const PIPELINE_SIDECARS_DATA_FILE: &str = "sidecars.norito";
const PIPELINE_SIDECARS_INDEX_FILE: &str = "sidecars.index";
const PIPELINE_INDEX_ENTRY_SIZE: usize = core::mem::size_of::<u64>() * 2;
const PIPELINE_INDEX_ENTRY_SIZE_U64: u64 = PIPELINE_INDEX_ENTRY_SIZE as u64;
// Every present V1 index starts with `(MAX, MAX)` (invalid as a payload entry),
// followed by `(base_height, base_height ^ mask)`.
const INDEXED_SIDECAR_BASE_HEADER_SIZE: usize = PIPELINE_INDEX_ENTRY_SIZE * 2;
const INDEXED_SIDECAR_BASE_HEADER_SIZE_U64: u64 = INDEXED_SIDECAR_BASE_HEADER_SIZE as u64;
const INDEXED_SIDECAR_BASE_CHECK_MASK: u64 = 0x6B75_7261_2D69_6478;
/// Keep a single sparse append bounded even when its height came from untrusted metadata.
const MAX_INDEXED_SIDECAR_GAP_ENTRIES: u64 = 4_096;
const DISK_USAGE_TOTAL_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const BLOCK_NOTIFY_CHANNEL_CAPACITY: usize = 1;
const SIZE_OF_BLOCK_HASH: u64 = Hash::LENGTH as u64;
pub(crate) const STRICT_INIT_MAX_BLOCK_BYTES: u64 = MAX_EXECUTED_BLOCK_WIRE_BYTES;
/// V1 rewrite stage: at most one maximum old body, one maximum new body, and 1 MiB framing.
const MAX_DA_BLOCK_REWRITE_STAGE_BYTES: u64 = STRICT_INIT_MAX_BLOCK_BYTES * 2 + 1024 * 1024;
const MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES: usize = 4_096;
/// Decode-depth ceiling for Kura's version-one canonical recovery records.
///
/// Block bodies in these records are opaque byte fields. The remaining typed
/// merge/rewrite envelopes are shallow, so this is deliberately below Norito's
/// generic owned-value limit while retaining generous schema headroom.
const RECOVERY_CONTROL_DECODE_DEPTH_V1: usize = 128;
const EVICTED_BLOCK_START: u64 = u64::MAX;
/// Build the conservative Norito budget at a recovery format's exact V1 wire cap.
///
/// `decode_canonical_with_limits` also installs its payload-derived budget, so
/// a shorter damaged file inherits the stricter bound instead of gaining the
/// full protocol maximum.
fn recovery_control_decode_limits_v1(wire_limit: u64) -> Result<norito::DecodeLimits> {
    let wire_limit = usize::try_from(wire_limit)?;
    let defaults = norito::canonical_decode_limits(wire_limit);
    Ok(norito::DecodeLimits::new(
        defaults.max_sequence_elements(),
        defaults.max_field_bytes(),
        defaults.max_total_elements(),
        defaults.max_total_allocated_bytes(),
        defaults
            .max_nesting_depth()
            .min(RECOVERY_CONTROL_DECODE_DEPTH_V1),
    ))
}
#[cfg(any(test, feature = "bench", feature = "iroha-core-tests"))]
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("kura fixture key generation should succeed")
}
#[cfg(test)]
fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("kura algorithm-specific fixture key generation should succeed")
}
#[cfg(any(test, feature = "bench", feature = "iroha-core-tests"))]
fn checked_peer_id() -> PeerId {
    PeerId::new(checked_keypair().public_key().clone())
}
fn default_fastpq_proof_sidecar_queue_cap() -> usize {
    FASTPQ_DEFAULTS::PROOF_SIDECAR_QUEUE_CAP.get()
}
fn default_pipeline_sidecar_queue_cap() -> usize {
    BLOCKS_IN_MEMORY.get()
}
const EMERGENCY_FAST_RECENT_BLOCK_CACHE_CAPACITY: NonZeroUsize =
    NonZeroUsize::new(256).expect("the emergency Fast cache ceiling is non-zero");
fn default_fastpq_proof_sidecar_max_bytes() -> usize {
    usize::try_from(FASTPQ_DEFAULTS::PROOF_SIDECAR_MAX_BYTES.get())
        .unwrap_or(usize::MAX)
        .max(1)
}
fn default_fastpq_proof_sidecar_max_retries() -> usize {
    FASTPQ_DEFAULTS::PROOF_SIDECAR_MAX_RETRIES.get()
}
#[path = "kura/resource_inventory.rs"]
pub(crate) mod resource_inventory;
#[cfg(feature = "telemetry")]
mod resource_telemetry;
include!("kura/index_resource_accounting.rs");
include!("kura/evidence_resource_accounting.rs");
include!("kura/storage_resource_accounting.rs");
include!("kura/physical_resource_accounting.rs");
include!("kura/physical_resource_guard.rs");
include!("kura/publication_capacity.rs");
include!("kura/canonical_physical_resource_accounting.rs");
include!("kura/physical_resource_initialization.rs");
#[cfg(test)]
#[path = "kura/physical_resource_accounting_tests.rs"]
mod physical_resource_accounting_tests;
#[cfg(test)]
#[path = "kura/physical_resource_initialization_tests.rs"]
mod physical_resource_initialization_tests;

use crate::publication_lock::{PublicationGuard, PublicationMutex};
mod publication_lease;
pub(crate) use publication_lease::{KuraPublicationLease, KuraPublicationPreparationError};

/// The interface of Kura subsystem.
///
/// Native persistence requirements are tracked in
/// `specs/sumeragi_liveness_redesign_goals.md`; follow that plan when wiring
/// global state checkpoints into storage.
#[derive(Debug)]
pub struct Kura {
    /// Configured finite maximum for an original native context archive record.
    native_context_archive_max_bytes: NonZeroUsize,
    /// One finite pool shared by every State hash generation using this store.
    block_hash_history_budget: iroha_allocation::AllocationBudget,
    /// One finite pool shared by every State transaction-membership generation using this store.
    transaction_history_budget: iroha_allocation::AllocationBudget,
    membership_storage: membership_storage::MembershipStorage,
    /// Exact owner-published resident and physical resources; never consensus authority.
    resource_inventory: Arc<resource_inventory::Inventory>,
    /// Process-local identity shared with sealed lifecycle storage authority.
    instance_identity: Arc<KuraInstanceIdentityMarker>,
    /// Opened canonical store-root owner used to mint descriptor-relative WAL storage.
    #[cfg(all(unix, not(target_os = "espidf")))]
    store_root_directory: BoundProgressDirectory,
    /// The block storage
    block_store: Mutex<BlockStore>,
    /// Serializes destructive canonical-chain changes with finality association and lane relabels.
    ///
    /// Operations that also hold `prune_lock` acquire that gate first. Inner locks retain their
    /// existing order: identity/path snapshots, then `block_store_write_lock`, then `block_store`.
    canonical_chain_lock: PublicationMutex,
    /// Serializes block-store writes while allowing reads during long eviction compaction.
    block_store_write_lock: Mutex<()>,
    /// Serializes canonical prune transactions from preflight through intent clearance.
    /// When combined with canonical-chain or lane locks, acquire this before
    /// `canonical_chain_lock`, `lane_geometry_lock`, and `sidecar_lock`.
    prune_lock: PublicationMutex,
    /// Rejects consensus-path sidecar enqueues while a canonical prune is active.
    ///
    /// Unlike `prune_lock`, this gate does not make enqueuers wait behind unrelated writer work
    /// that uses the same disk-mutation lock. Enqueuers check it both before and while holding
    /// their queue lock so prune start is linearizable with queue insertion.
    prune_in_progress: AtomicBool,
    /// Prevents a live Kura from serving or mutating a chain whose durable prune needs restart
    /// recovery.
    prune_recovery_required: AtomicBool,
    /// The array of block hashes and a slot for an arc of the block. This is normally recovered from the index file.
    block_data: ResidentMutex<BlockData>,
    /// Whether emergency Fast startup deliberately left historical auxiliary indexes unknown.
    auxiliary_history_deferred: bool,
    /// Reverse lookup for committed block hash to block height.
    block_height_index: ResidentMutex<BlockHeightIndex>,
    /// Reverse lookup for committed transaction entrypoint hash to containing block heights.
    transaction_entrypoint_index: ResidentMutex<TransactionEntrypointIndex>,
    /// Authenticated native identities of checkpoint heights for off-chain
    /// history reads; node-local and never consensus authority.
    history_checkpoints: history_checkpoints::HistoryCheckpoints,
    /// Channel for waking the writer thread when sidecars need flushing or shutdown is signalled.
    block_notify_tx: mpsc::SyncSender<BlockNotify>,
    block_notify_rx: Mutex<Option<mpsc::Receiver<BlockNotify>>>,
    /// Path to newline-delimited JSON (JSONL) block dump.
    block_plain_text_path: Mutex<Option<PathBuf>>,
    /// Serialize sidecar writes to avoid index/data races.
    sidecar_lock: PublicationMutex,
    /// Opaque permission for audited immutable reads of this exact sidecar fence.
    sidecar_read_permit: crate::publication_lock::PublicationReadPermit,
    /// Queue of pipeline sidecar writes flushed by the Kura writer thread.
    pipeline_sidecar_queue: ResidentMutex<VecDeque<PipelineRecoverySidecar>>,
    /// Maximum queued pipeline sidecar writes.
    pipeline_sidecar_queue_cap: AtomicUsize,
    /// Queue of FASTPQ proof attachments merged into existing pipeline sidecars.
    fastpq_proof_queue: ResidentMutex<VecDeque<QueuedFastpqProofSnapshot>>,
    /// Maximum queued FASTPQ proof sidecar attachments.
    fastpq_proof_sidecar_queue_cap: AtomicUsize,
    /// Maximum encoded FASTPQ proof snapshot bytes accepted for persistence.
    fastpq_proof_sidecar_max_bytes: AtomicUsize,
    /// Maximum merge attempts for a pending FASTPQ proof sidecar.
    fastpq_proof_sidecar_max_retries: AtomicUsize,
    /// Root directory where Kura stores lane segments.
    store_root: PathBuf,
    /// Fixed canonical-chain directory, independent of every lane alias and incarnation.
    active_blocks_dir: Mutex<PathBuf>,
    /// Current lane storage entries, keyed by lane id, used for lane-local artifact placement.
    lane_storage_entries: ResidentMutex<BTreeMap<LaneId, LaneStorageEntry>>,
    lane_storage_network: Mutex<Option<NetworkId>>,
    /// Serializes lifecycle geometry moves, snapshot checkpoints, and archive garbage collection.
    /// Acquire it after `prune_lock` and before `sidecar_lock` when locks are combined.
    lane_geometry_lock: PublicationMutex,
    /// Exact in-process operation custody while physical geometry locks are released.
    raw_geometry_claim: lane_geometry::RawGeometryClaimGate,
    /// Maximum on-disk footprint for Kura block storage (0 = unlimited).
    max_disk_usage_bytes: u64,
    /// Cached disk usage for budget enforcement.
    disk_usage: AtomicU64,
    /// Cached total disk usage.
    disk_usage_total: AtomicU64,
    /// Serializes total-usage scans with filesystem mutations that publish total-cache deltas.
    disk_usage_total_accounting: Mutex<TotalDiskUsageAccountingState>,
    /// Wakes total-usage scanners after the last in-flight filesystem mutation completes.
    disk_usage_total_accounting_changed: Condvar,
    /// Cached sum of budgeted bytes for in-memory blocks not yet durably indexed.
    pending_budget_bytes: AtomicU64,
    /// Marks whether `pending_budget_bytes` currently reflects in-memory block state.
    pending_budget_bytes_valid: AtomicBool,
    /// Counts raw pending-budget scans for focused cache tests.
    #[cfg(test)]
    pending_budget_raw_scans: AtomicUsize,
    /// Cached durable block count for budget accounting.
    durable_budget_persisted_count: AtomicUsize,
    /// Cached unindexed block-store bytes for budget accounting.
    durable_budget_unindexed_bytes: AtomicU64,
    /// Marks whether the durable budget metadata cache is usable.
    durable_budget_snapshot_valid: AtomicBool,
    /// Indicates whether the budget usage cache was initialized successfully.
    disk_usage_initialized: AtomicBool,
    /// Indicates whether the total usage cache was initialized successfully.
    disk_usage_total_initialized: AtomicBool,
    /// Last successful total-usage refresh time (seconds since UNIX epoch).
    disk_usage_total_last_refresh: AtomicU64,
    /// Number of most recent non-genesis blocks stored in memory.
    /// The genesis block is always retained for metrics and replay.
    blocks_in_memory: NonZeroUsize,
    fastpq_artifact_policy: iroha_config::parameters::actual::KuraFastpqArtifactPolicy,
    /// Optional telemetry sink for storage and durable finality reporting.
    telemetry: OnceLock<StateTelemetry>,
    /// Last fatal writer fault observed by the background persistence loop.
    writer_fault: Mutex<Option<String>>,
    /// Fail-stop latch for an ambiguous canonical-journal publication boundary.
    canonical_storage_poisoned: AtomicBool,
    /// Permanent storage-owner gate shared by global and lane consensus instances.
    native_consensus_gate: Arc<crate::sumeragi::driver::NodeGate>,
    /// Test hook that pauses canonical poison after publishing its latch.
    #[cfg(test)]
    pause_canonical_poison_after_latch: AtomicBool,
    /// Test hook indicating canonical poison is paused after closing the native gate.
    #[cfg(test)]
    canonical_poison_paused_after_latch: AtomicBool,
    /// Test hook for forcing the next synchronous block write to fail after pre-write work.
    #[cfg(test)]
    fail_next_block_write: AtomicBool,
    #[cfg(test)]
    fail_next_atomic_write_after_temporary_sync: AtomicBool,
    /// Test hook for forcing the next lane-geometry catalog publication to fail.
    #[cfg(test)]
    fail_next_lane_geometry_publication: AtomicBool,
    /// Test hook for failing catalog publication after its journal target was replaced.
    #[cfg(test)]
    fail_next_lane_geometry_publication_after_write: AtomicBool,
    /// Test hook selecting a crash boundary in lane-geometry archive garbage collection.
    #[cfg(test)]
    fail_lane_geometry_gc_stage: AtomicUsize,
    /// Test hook selecting a crash boundary in canonical prune recovery.
    #[cfg(test)]
    fail_prune_after_stage: AtomicUsize,
    /// Test hook forcing a fallible indexed-sidecar prune promotion to stop before rename.
    #[cfg(test)]
    fail_prune_sidecar_promotion_stage: AtomicUsize,
    /// Test hook that pauses a canonical prune after all mutable read locks are held but before
    /// its durable intent is published.
    #[cfg(test)]
    pause_prune_before_intent: AtomicBool,
    /// Indicates that the prune-before-intent test hook is currently paused.
    #[cfg(test)]
    prune_paused_before_intent: AtomicBool,
    /// Enables observation of canonical readers after their initial prune-poison check.
    #[cfg(test)]
    observe_canonical_reads_after_prune_check: AtomicBool,
    /// Bitmask of observed canonical reader kinds after their initial prune-poison check.
    #[cfg(test)]
    canonical_read_kinds_after_prune_check: AtomicUsize,
    /// Test hook pausing after exact instance preparation and before reference publication.
    #[cfg(test)]
    pause_geometry_reference_publication: AtomicBool,
    /// Test hook indicating that geometry and sidecar authority are held at reference publication.
    #[cfg(test)]
    geometry_reference_publication_paused: AtomicBool,
    /// Counts raw durable-budget metadata reads for focused cache tests.
    #[cfg(test)]
    durable_budget_metadata_reads: AtomicUsize,
    /// Test hook that pauses eviction after the block-store snapshot is captured.
    #[cfg(test)]
    pause_eviction_after_snapshot: AtomicBool,
    /// Test hook indicating eviction is paused after releasing the block-store lock.
    #[cfg(test)]
    eviction_paused_after_snapshot: AtomicBool,
    /// Test hook that pauses eviction immediately before the final keeper-freshness check.
    #[cfg(test)]
    pause_eviction_before_stage_publication: AtomicBool,
    /// Test hook indicating eviction reached its last pre-publication freshness boundary.
    #[cfg(test)]
    eviction_paused_before_stage_publication: AtomicBool,
    /// Test hook that pauses an inline read immediately before its cache publication recheck.
    #[cfg(test)]
    pause_block_read_before_cache_recheck: AtomicBool,
    /// Test hook indicating an inline read is paused before its cache publication recheck.
    #[cfg(test)]
    block_read_paused_before_cache_recheck: AtomicBool,
    /// Test hook forcing `durable_blocks_count` through its in-memory fallback.
    #[cfg(test)]
    force_durable_blocks_count_fallback: AtomicBool,
    /// Test hook indicating the durable-count fallback is about to acquire `block_data`.
    #[cfg(test)]
    durable_blocks_count_fallback_reached: AtomicBool,
    /// Test hook that pauses a total-usage refresh after its filesystem scan.
    #[cfg(test)]
    pause_total_disk_usage_scan_after_scan: AtomicBool,
    /// Test hook indicating a total-usage refresh is paused before publication.
    #[cfg(test)]
    total_disk_usage_scan_paused: AtomicBool,
    /// Exclusive OS lock dropped after every Kura resource but before temporary-directory cleanup.
    _store_root_lock_file: Option<std::fs::File>,
    /// Retains the temporary storage directory used by isolated Kura instances.
    _temp_store_dir: Option<tempfile::TempDir>,
}
#[derive(Debug)]
struct KuraInstanceIdentityMarker;
/// Comparison-only identity for one exact live Kura instance.
///
/// This seal carries no storage path and cannot reopen Kura. Lifecycle startup
/// retains it solely to prevent a canonical owner built under one Kura from
/// launching its workers against another.
#[derive(Clone, Debug)]
pub(crate) struct KuraInstanceIdentity(Arc<KuraInstanceIdentityMarker>);
impl KuraInstanceIdentity {
    /// Return whether this seal came from the exact supplied Kura instance.
    pub(crate) fn matches(&self, kura: &Kura) -> bool {
        Arc::ptr_eq(&self.0, &kura.instance_identity)
    }
    /// Return whether two seals name the same live Kura instance.
    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[path = "kura/resident_inventory.rs"]
mod resident_inventory;
use resident_inventory::{AssociationCount, ResidentMutex};
include!("kura/canonical_cache_and_outbox.rs");
include!("kura/resident_inventory_owners.rs");
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockNotify {
    NewBlock,
    StorageBudgetEviction,
    Shutdown,
}
/// Result of one bounded lane-history compaction pass.
///
/// Capacity-blocked maintenance is deliberately distinct from incomplete
/// progress: callers must exit the pass and retain the uncompacted evidence,
/// never retry while holding the startup or retirement lock corridor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaneHistoryCompactionOutcome {
    Complete,
    CapacityBlocked,
}
impl Kura {
    /// Retain the original configured pool for State history construction and edits.
    pub(crate) fn block_hash_history_budget(&self) -> iroha_allocation::AllocationBudget {
        self.block_hash_history_budget.clone()
    }
    /// Retain the original configured pool through membership restore, replay, and edits.
    pub(crate) fn transaction_history_budget(&self) -> iroha_allocation::AllocationBudget {
        self.transaction_history_budget.clone()
    }
    /// Node-local checkpoints that let off-chain history reads start below the tip.
    pub(crate) fn history_checkpoints(&self) -> &history_checkpoints::HistoryCheckpoints {
        &self.history_checkpoints
    }
    fn notify_block_writer_sender(
        sender: &mpsc::SyncSender<BlockNotify>,
        notification: BlockNotify,
        context: &'static str,
    ) {
        match sender.try_send(notification) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                debug!(
                    ?notification,
                    context, "coalesced redundant Kura writer notification"
                );
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                warn!(
                    ?notification,
                    context, "failed to notify Kura writer because channel is closed"
                );
            }
        }
    }
    fn notify_block_writer(&self, notification: BlockNotify, context: &'static str) {
        Self::notify_block_writer_sender(&self.block_notify_tx, notification, context);
    }
    fn ensure_prune_recovery_not_required(&self) -> Result<()> {
        if self.prune_recovery_required.load(Ordering::Acquire) {
            return Err(Error::PruneRecoveryRequired);
        }
        Ok(())
    }
    fn prune_recovery_is_required(&self) -> bool {
        self.prune_recovery_required.load(Ordering::Acquire)
    }
    /// Return whether a consensus-path sidecar enqueue must fail closed for pruning.
    ///
    /// Callers repeat this check while holding the queue mutex. A queue insertion whose locked
    /// check observes `false` linearizes before prune start and is covered by prune's queue
    /// truncation. Once prune start publishes `true`, no later insertion is accepted.
    fn prune_blocks_sidecar_enqueue(&self) -> bool {
        self.prune_in_progress.load(Ordering::Acquire) || self.prune_recovery_is_required()
    }
    #[cfg(test)]
    fn observe_canonical_read_after_prune_check_for_tests(&self, reader_kind: usize) {
        if self
            .observe_canonical_reads_after_prune_check
            .load(Ordering::Acquire)
        {
            self.canonical_read_kinds_after_prune_check
                .fetch_or(reader_kind, Ordering::AcqRel);
        }
    }
    #[cfg(test)]
    fn maybe_pause_prune_before_intent(&self) {
        if self.pause_prune_before_intent.load(Ordering::Acquire) {
            self.prune_paused_before_intent
                .store(true, Ordering::Release);
            while self.pause_prune_before_intent.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            self.prune_paused_before_intent
                .store(false, Ordering::Release);
        }
    }
    fn build_block_height_index(block_data: &BlockData) -> BlockHeightIndex {
        let Some(entries) = block_data.dense_entries() else {
            return HashMap::new();
        };
        let mut index = HashMap::with_capacity(block_data.len());
        for (offset, (hash, _)) in entries.iter().enumerate() {
            if let Some(height) = NonZeroUsize::new(offset.saturating_add(1)) {
                index.entry(*hash).or_insert(height);
            }
        }
        index
    }
    fn build_transaction_entrypoint_index(block_data: &BlockData) -> TransactionEntrypointIndex {
        let mut index = TransactionEntrypointIndex::complete_empty();
        index.complete = false;
        let Some(entries) = block_data.dense_entries() else {
            return index;
        };
        for (offset, (expected_hash, block)) in entries.iter().enumerate() {
            let Some(height) = NonZeroUsize::new(offset.saturating_add(1)) else {
                continue;
            };
            if let Some(block) = block
                .as_ref()
                .filter(|block| block.hash() == *expected_hash)
            {
                Self::insert_transaction_entrypoint_heights(&mut index, height, block);
            } else {
                index.incomplete_heights.insert(height);
            }
        }
        index.complete =
            index.incomplete_heights.is_empty() && index.indexed_heights.len() == block_data.len();
        index
    }

    /// Publish only a complete, structurally validated Network projection. Physical
    /// canonical body/finality admission remains the caller's existing responsibility.
    fn insert_transaction_entrypoint_heights(
        index: &mut TransactionEntrypointIndex,
        height: NonZeroUsize,
        block: &SignedBlock,
    ) {
        Self::remove_transaction_entrypoint_height(index, height);
        if u64::try_from(height.get()).ok() != Some(block.header().height().get())
            || block
                .execution_context()
                .is_some_and(|context| !context.has_current_version())
            || block.validate_output_merkle_cache().is_err()
            || u32::try_from(block.network_entrypoint_count()).is_err()
        {
            index.incomplete_heights.insert(height);
            index.complete = false;
            return;
        }
        // Validate the entire carrier before any membership is exposed, including
        // internal outputs, source joins and every retained Merkle cache node.
        index.inventories_by_height.entry(height).or_default();
        for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
            let input_index = u32::try_from(input_index).expect("validated Network index range");
            let (_, output) = block
                .network_output_at(input_index)
                .expect("validated complete Network output join");
            let hash = entrypoint.hash();
            let inserted = index
                .inventories_by_height
                .entry(height)
                .or_default()
                .entrypoint_hashes
                .insert(hash);
            index.nested_associations.inserted(inserted);
            let inserted = index
                .heights_by_entrypoint
                .entry(hash)
                .or_default()
                .insert(height);
            index.nested_associations.inserted(inserted);
            if let Some(authority) = entrypoint.authority_opt() {
                let inserted = index
                    .inventories_by_height
                    .entry(height)
                    .or_default()
                    .authorities
                    .insert(authority.clone());
                index.nested_associations.inserted(inserted);
                let inserted = index
                    .heights_by_authority
                    .entry(authority.clone())
                    .or_default()
                    .insert(height);
                index.nested_associations.inserted(inserted);
            }
            if let Some(timestamp_ms) = entrypoint.creation_time_ms() {
                let inserted = index
                    .inventories_by_height
                    .entry(height)
                    .or_default()
                    .timestamps_ms
                    .insert(timestamp_ms);
                index.nested_associations.inserted(inserted);
                let inserted = index
                    .heights_by_timestamp_ms
                    .entry(timestamp_ms)
                    .or_default()
                    .insert(height);
                index.nested_associations.inserted(inserted);
            }
            let status = output.result.is_ok();
            let inserted = index
                .inventories_by_height
                .entry(height)
                .or_default()
                .result_statuses
                .insert(status);
            index.nested_associations.inserted(inserted);
            let inserted = index
                .heights_by_result_status
                .entry(status)
                .or_default()
                .insert(height);
            index.nested_associations.inserted(inserted);
            if !Self::insert_kaigi_signal_candidate(
                index,
                height,
                block.hash(),
                input_index,
                entrypoint,
                &output.result,
            ) {
                Self::remove_transaction_entrypoint_height(index, height);
                index.incomplete_heights.insert(height);
                index.complete = false;
                return;
            }
        }
        index.indexed_heights.insert(height);
    }

    pub(crate) fn kaigi_signal_candidate_identity(
        entrypoint: &TransactionEntrypoint,
        result: &TransactionResult,
    ) -> Option<(KaigiId, AccountId)> {
        if result.as_ref().is_err() {
            return None;
        }
        let transaction = match entrypoint {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_) => {
                return None;
            }
        };
        let key = "kaigi_signal".parse::<Name>().ok()?;
        let signal = transaction
            .metadata()
            .get(&key)?
            .try_into_any_norito::<JsonValue>()
            .ok()?;
        let object = signal.as_object()?;
        if object.get("schema")?.as_str()? != "iroha-demo-kaigi-chain-signal/v1" {
            return None;
        }
        let mut call_literal = None;
        for key in ["callId", "call_id"] {
            let Some(value) = object.get(key) else {
                continue;
            };
            let candidate = value.as_str()?;
            if call_literal.is_some_and(|existing| existing != candidate) {
                return None;
            }
            call_literal = Some(candidate);
        }
        let call_literal = call_literal?;
        let (domain_literal, call_name_literal) = call_literal.split_once(':')?;
        if call_name_literal.contains(':') {
            return None;
        }
        let call_id = KaigiId::new(
            DomainId::parse_fully_qualified(domain_literal).ok()?,
            call_name_literal.parse::<Name>().ok()?,
        );
        if call_id.to_string() != call_literal {
            return None;
        }
        Some((call_id, transaction.authority().clone()))
    }

    fn insert_kaigi_signal_candidate(
        index: &mut TransactionEntrypointIndex,
        height: NonZeroUsize,
        block_hash: HashOf<BlockHeader>,
        network_input_index: u32,
        entrypoint: &TransactionEntrypoint,
        result: &TransactionResult,
    ) -> bool {
        let Some((call_id, authority)) = Self::kaigi_signal_candidate_identity(entrypoint, result)
        else {
            return true;
        };
        let Ok(block_height) = u64::try_from(height.get()) else {
            return false;
        };
        let position = KaigiSignalCandidatePosition {
            block_height,
            network_input_index,
            block_hash,
            entrypoint_hash: entrypoint.hash(),
        };
        let locator = KaigiSignalCandidateLocator {
            position,
            authority,
        };
        let inserted = index
            .inventories_by_height
            .entry(height)
            .or_default()
            .kaigi_calls
            .insert(call_id.clone());
        index.nested_associations.inserted(inserted);
        match index
            .kaigi_signal_candidates
            .entry(call_id)
            .or_default()
            .entry(height)
            .or_default()
            .insert(network_input_index, locator.clone())
        {
            None => {
                index.nested_associations.inserted(true);
                true
            }
            Some(existing) => existing == locator,
        }
    }
    fn remove_transaction_entrypoint_height(
        index: &mut TransactionEntrypointIndex,
        height: NonZeroUsize,
    ) {
        let inventory = index
            .inventories_by_height
            .remove(&height)
            .unwrap_or_default();
        index.nested_associations.removed(
            resident_inventory::lengths([
                inventory.entrypoint_hashes.len(),
                inventory.authorities.len(),
                inventory.timestamps_ms.len(),
                inventory.result_statuses.len(),
                inventory.kaigi_calls.len(),
            ])
            .ok(),
        );
        let removed = Self::remove_transaction_height_for_keys(
            &mut index.heights_by_entrypoint,
            inventory.entrypoint_hashes,
            height,
        );
        index.nested_associations.removed(removed);
        let removed = Self::remove_transaction_height_for_keys(
            &mut index.heights_by_authority,
            inventory.authorities,
            height,
        );
        index.nested_associations.removed(removed);
        let removed = Self::remove_transaction_height_for_keys(
            &mut index.heights_by_timestamp_ms,
            inventory.timestamps_ms,
            height,
        );
        index.nested_associations.removed(removed);
        let removed = Self::remove_transaction_height_for_keys(
            &mut index.heights_by_result_status,
            inventory.result_statuses,
            height,
        );
        index.nested_associations.removed(removed);
        for call_id in inventory.kaigi_calls {
            let remove_call =
                index
                    .kaigi_signal_candidates
                    .get_mut(&call_id)
                    .is_some_and(|heights| {
                        if let Some(candidates) = heights.remove(&height) {
                            index
                                .nested_associations
                                .removed(u64::try_from(candidates.len()).ok());
                        }
                        heights.is_empty()
                    });
            if remove_call {
                index.kaigi_signal_candidates.remove(&call_id);
            }
        }
        index.indexed_heights.remove(&height);
        index.incomplete_heights.remove(&height);
    }

    fn remove_transaction_height_for_keys<K: Ord>(
        indexed: &mut BTreeMap<K, BTreeSet<NonZeroUsize>>,
        keys: impl IntoIterator<Item = K>,
        height: NonZeroUsize,
    ) -> Option<u64> {
        let mut removed = Some(0_u64);
        for key in keys {
            let remove_key = indexed.get_mut(&key).is_some_and(|heights| {
                if heights.remove(&height) {
                    removed = removed.and_then(|count| count.checked_add(1));
                }
                heights.is_empty()
            });
            if remove_key {
                indexed.remove(&key);
            }
        }
        removed
    }
    fn set_transaction_entrypoint_index_entry(
        &self,
        height: usize,
        block: &SignedBlock,
        chain_len: usize,
    ) {
        let Some(height) = NonZeroUsize::new(height) else {
            return;
        };
        let mut index = self.transaction_entrypoint_index.lock();
        Self::insert_transaction_entrypoint_heights(&mut index, height, block);
        index.complete =
            index.incomplete_heights.is_empty() && index.indexed_heights.len() == chain_len;
    }

    fn mark_transaction_entrypoint_index_incomplete(&self, height: usize, chain_len: usize) {
        let Some(height) = NonZeroUsize::new(height) else {
            return;
        };
        let mut index = self.transaction_entrypoint_index.lock();
        Self::remove_transaction_entrypoint_height(&mut index, height);
        index.incomplete_heights.insert(height);
        index.complete =
            index.incomplete_heights.is_empty() && index.indexed_heights.len() == chain_len;
    }
    fn truncate_transaction_entrypoint_index(&self, keep: usize) {
        let mut index = self.transaction_entrypoint_index.lock();
        Self::truncate_transaction_entrypoint_index_to(&mut index, keep);
    }

    fn truncate_transaction_entrypoint_index_to(
        index: &mut TransactionEntrypointIndex,
        keep: usize,
    ) {
        let removed_heights = index
            .inventories_by_height
            .keys()
            .chain(index.incomplete_heights.iter())
            .copied()
            .filter(|height| height.get() > keep)
            .collect::<Vec<_>>();
        for height in removed_heights {
            Self::remove_transaction_entrypoint_height(index, height);
        }
        index.complete = index.incomplete_heights.is_empty() && index.indexed_heights.len() == keep;
    }
    fn set_block_height_index_entry(&self, height: usize, hash: HashOf<BlockHeader>) {
        let Some(height) = NonZeroUsize::new(height) else {
            return;
        };
        let mut index = self.block_height_index.lock();
        index.retain(|_, indexed_height| *indexed_height != height);
        index.insert(hash, height);
    }
    fn truncate_block_height_index(&self, keep: usize) {
        let mut index = self.block_height_index.lock();
        index.retain(|_, height| height.get() <= keep);
    }
}
impl Kura {
    /// Initialize a fresh Kura with the canonical single-lane storage geometry.
    ///
    /// This does _not_ start the thread which receives and stores new blocks, see [`Self::start`].
    /// This constructor accepts only an exact [`LaneConfig::default`] and a
    /// missing or empty, non-symlink store root. Persistent or custom-geometry
    /// stores must use
    /// [`Self::new_with_configured_lane_catalog`] so their storage paths are
    /// authenticated before Kura opens them.
    ///
    /// # Errors
    /// Fails if the lane geometry is not canonical single-lane geometry, the
    /// store root is nonempty, is a symlink, or is not a directory, a rollback
    /// intent is invalid or cannot be completed, or filesystem access to a
    /// Kura-owned durability artifact fails.
    pub fn new_fresh_single_lane(
        config: &Config,
        lane_config: &LaneConfig,
    ) -> Result<(Arc<Self>, BlockCount)> {
        Self::validate_fresh_single_lane_store(config, lane_config)?;
        Self::new_inner(config, lane_config, None)
    }
    fn validate_fresh_single_lane_store(config: &Config, lane_config: &LaneConfig) -> Result<()> {
        let store_root = config.store_dir.resolve_relative_path();
        if *lane_config != LaneConfig::default() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Kura::new_fresh_single_lane only accepts the canonical single-lane geometry; use Kura::new_with_configured_lane_catalog for custom lane storage",
                ),
                store_root,
            ));
        }
        let metadata = match std::fs::symlink_metadata(&store_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(Error::IO(error, store_root)),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura::new_fresh_single_lane requires a missing or empty, non-symlink store root; use Kura::new_with_configured_lane_catalog for persistent storage",
                ),
                store_root,
            ));
        }
        let mut entries =
            std::fs::read_dir(&store_root).map_err(|error| Error::IO(error, store_root.clone()))?;
        if let Some(entry) = entries.next() {
            let entry = entry.map_err(|error| Error::IO(error, store_root.clone()))?;
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura::new_fresh_single_lane cannot open a nonempty store; use Kura::new_with_configured_lane_catalog with the authenticated process catalog",
                ),
                entry.path(),
            ));
        }
        Ok(())
    }
    /// Open a crate test fixture through the production authenticated-catalog boundary.
    ///
    /// This helper exists only in unit-test builds. It reconstructs the
    /// canonical storage-bearing catalog projection supplied by the fixture and
    /// delegates to [`Self::new_with_configured_lane_catalog`]; it never calls
    /// [`Self::new_inner`] or weakens any shipping validation. Fixtures that
    /// exercise a full catalog commitment use the production constructor
    /// directly with that exact catalog.
    #[cfg(test)]
    pub(crate) fn open_test_kura_with_configured_lane_config(
        config: &Config,
        lane_config: &LaneConfig,
    ) -> Result<(Arc<Self>, BlockCount)> {
        let store_root = config.store_dir.resolve_relative_path();
        let maximum_lane_id = lane_config
            .entries()
            .iter()
            .map(|entry| entry.lane_id.as_u32())
            .max()
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "test lane configuration must contain a primary lane",
                    ),
                    store_root.clone(),
                )
            })?;
        let lane_count = maximum_lane_id
            .checked_add(1)
            .and_then(std::num::NonZeroU32::new)
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "test lane configuration exceeds the lane identifier namespace",
                    ),
                    store_root.clone(),
                )
            })?;
        let configured_lanes = lane_config
            .entries()
            .iter()
            .map(|entry| iroha_data_model::nexus::LaneConfig {
                id: entry.lane_id,
                shard_id: (entry.shard_id != entry.lane_id.as_u32())
                    .then_some(iroha_model_base::topology::ShardId::new(entry.shard_id)),
                dataspace_id: entry.dataspace_id,
                alias: entry.alias.clone(),
                description: None,
                visibility: entry.visibility,
                lane_type: None,
                governance: None,
                settlement: None,
                storage: entry.storage_profile,
                proof_scheme: entry.proof_scheme,
                manifest_policy: entry.manifest_policy,
                confidential_compute: entry.confidential_compute.clone(),
                scheduler: entry.scheduler,
                settlement_buffer: entry.settlement_buffer.clone(),
                metadata: BTreeMap::new(),
            })
            .collect();
        let configured_lane_catalog =
            LaneCatalog::new(lane_count, configured_lanes).map_err(|error| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("invalid configured lane catalog for Kura test fixture: {error}"),
                    ),
                    store_root,
                )
            })?;
        Self::new_with_configured_lane_catalog(config, lane_config, &configured_lane_catalog)
    }
    /// Initialize Kura after authenticating the process-configured lane catalog.
    ///
    /// Unlike [`Self::new_fresh_single_lane`], this production startup boundary checks an existing
    /// lane-geometry journal before opening or reconciling any lane-derived
    /// block, merge-ledger, or sidecar path. On the first startup it durably
    /// establishes the exact configured-catalog commitment before opening those
    /// paths; every reconstructed process must then authenticate the same value.
    ///
    /// # Errors
    ///
    /// Fails without mutating Kura storage when an existing journal is invalid,
    /// lacks its configured-catalog baseline, or commits a different catalog.
    pub fn new_with_configured_lane_catalog(
        config: &Config,
        lane_config: &LaneConfig,
        configured_lane_catalog: &LaneCatalog,
    ) -> Result<(Arc<Self>, BlockCount)> {
        Self::new_with_configured_lane_catalog_inner(config, lane_config, configured_lane_catalog)
    }
    fn new_with_configured_lane_catalog_inner(
        config: &Config,
        lane_config: &LaneConfig,
        configured_lane_catalog: &LaneCatalog,
    ) -> Result<(Arc<Self>, BlockCount)> {
        let authenticated_lane_config = LaneConfig::from_catalog(configured_lane_catalog);
        let Some(configured_primary) = authenticated_lane_config.entries().first() else {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "authenticated configured catalog must contain physical primary lane zero",
                ),
                config.store_dir.resolve_relative_path(),
            ));
        };
        if configured_primary.lane_id != LaneId::SINGLE {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "authenticated configured catalog must contain physical primary lane zero",
                ),
                config.store_dir.resolve_relative_path(),
            ));
        }
        if *lane_config != authenticated_lane_config {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "runtime lane storage configuration differs from the authenticated configured catalog",
                ),
                config.store_dir.resolve_relative_path(),
            ));
        }
        Self::new_inner(
            config,
            &authenticated_lane_config,
            Some(LaneLifecycleParameterV1::catalog_hash(
                configured_lane_catalog,
            )),
        )
    }
    /// Initialize an authenticated Kura in an isolated temporary directory.
    ///
    /// This applies the same configured-catalog authentication as
    /// [`Self::new_with_configured_lane_catalog`] while binding the directory lifetime to the
    /// returned Kura. It is intended for non-committing genesis validation and other transient
    /// staging that must exercise production lane-storage invariants without touching node data.
    ///
    /// # Errors
    ///
    /// Returns an error if the temporary directory cannot be created or the configured lane
    /// catalog cannot initialize an authenticated Kura inside it.
    pub fn new_temporary_with_configured_lane_catalog(
        config: &Config,
        lane_config: &LaneConfig,
        configured_lane_catalog: &LaneCatalog,
    ) -> Result<Arc<Self>> {
        let temp_store_dir = tempfile::Builder::new()
            .prefix("iroha-staging-kura-")
            .tempdir()
            .map_err(|error| Error::IO(error, std::env::temp_dir()))?;
        let mut temporary_config = config.clone();
        temporary_config.store_dir = WithOrigin::inline(temp_store_dir.path().to_path_buf());
        let (mut kura, _) = Self::new_with_configured_lane_catalog(
            &temporary_config,
            lane_config,
            configured_lane_catalog,
        )?;
        let store_root = temporary_config.store_dir.resolve_relative_path();
        let kura_inner = Arc::get_mut(&mut kura).ok_or_else(|| {
            Error::IO(
                std::io::Error::other(
                    "newly initialized temporary Kura unexpectedly acquired another owner",
                ),
                store_root,
            )
        })?;
        kura_inner._temp_store_dir = Some(temp_store_dir);
        Ok(kura)
    }
    fn acquire_store_root_lock(
        store_root: &Path,
        create_if_missing: bool,
    ) -> Result<std::fs::File> {
        let canonical_root = std::fs::canonicalize(store_root)
            .map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
        let root_before = secure_file_metadata::from_path(&canonical_root)
            .map_err(|error| Error::IO(error, canonical_root.clone()))?;
        if root_before.file_type().is_symlink() || !root_before.is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "canonical Kura store root is not a direct directory",
                ),
                canonical_root,
            ));
        }
        let lock_path = canonical_root.join(STORE_ROOT_LOCK_FILE_NAME);
        if let Some(metadata) = match secure_file_metadata::from_path(&lock_path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(Error::IO(error, lock_path)),
        } && (metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || !Self::sidecar_is_single_link(&metadata))
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura store-root lock path is not a single-link regular file",
                ),
                lock_path,
            ));
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(create_if_missing);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let file = options
            .open(&lock_path)
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let opened_metadata = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        let path_metadata = secure_file_metadata::from_path(&lock_path)
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        if !opened_metadata.file_type().is_file()
            || !path_metadata.file_type().is_file()
            || path_metadata.file_type().is_symlink()
            || !Self::sidecar_is_single_link(&opened_metadata)
            || !Self::sidecar_is_single_link(&path_metadata)
            || !Self::sidecar_metadata_same_object(&opened_metadata, &path_metadata)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura store-root lock path changed while opening",
                ),
                lock_path,
            ));
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Locked(lock_path)),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(Error::IO(error, lock_path));
            }
        }
        let root_after = secure_file_metadata::from_path(&canonical_root)
            .map_err(|error| Error::IO(error, canonical_root.clone()))?;
        let path_after = secure_file_metadata::from_path(&lock_path)
            .map_err(|error| Error::IO(error, lock_path.clone()))?;
        if root_after.file_type().is_symlink()
            || !root_after.is_dir()
            || !Self::sidecar_metadata_same_object(&root_before, &root_after)
            || path_after.file_type().is_symlink()
            || !path_after.is_file()
            || !Self::sidecar_file_metadata_unchanged(&path_metadata, &path_after)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura store root or lock path changed while acquiring the OS lock",
                ),
                lock_path,
            ));
        }
        Ok(file)
    }
    fn reject_retired_commit_roster_artifacts(store_root: &Path) -> Result<()> {
        let entries = std::fs::read_dir(store_root)
            .map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
        for entry in entries {
            let entry = entry.map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "commit-rosters"
                || name.starts_with("commit-rosters.norito")
                || name.starts_with("autonomous_")
                || name.starts_with(".autonomous-")
                || name.starts_with("native_amx_")
                || name.starts_with("pending_queue_plan")
            {
                return Err(Error::RetiredKuraArtifact { path: entry.path() });
            }
        }
        Ok(())
    }
}
include!("kura/retired_pipeline_roster_rejection.rs");
include!("kura/retired_snapshot_rejection.rs");
impl Kura {
    fn new_inner(
        config: &Config,
        _lane_config: &LaneConfig,
        configured_catalog_hash: Option<Hash>,
    ) -> Result<(Arc<Self>, BlockCount)> {
        let init_started_at = Instant::now();
        let configured_store_dir = config.store_dir.resolve_relative_path();
        let history_bytes = usize::try_from(config.block_hash_history_bytes.get())
            .ok()
            .filter(|bytes| *bytes != 0)
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "kura.block_hash_history_bytes must be nonzero and representable as usize",
                    ),
                    configured_store_dir.clone(),
                )
            })?;
        let transaction_history_bytes = usize::try_from(config.transaction_history_bytes.get())
            .ok()
            .filter(|bytes| *bytes != 0)
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "kura.transaction_history_bytes must be nonzero and representable as usize",
                    ),
                    configured_store_dir.clone(),
                )
            })?;
        let membership_storage = membership_storage::MembershipStorage::new(
            config.membership_storage,
        )
        .map_err(|error| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, error),
                configured_store_dir.clone(),
            )
        })?;
        config.fastpq_artifacts.validate().map_err(|error| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, error.to_string()),
                configured_store_dir.clone(),
            )
        })?;
        if configured_store_dir.as_os_str().is_empty() {
            return Err(Error::EmptyStoreRoot);
        }
        Self::reject_retired_snapshot_tail(&Self::canonical_storage_path(&configured_store_dir))?;
        if config.init_mode == InitMode::Strict {
            create_dir_all_with_context(&configured_store_dir)?;
        }
        // Resolve aliases once, before taking the lock, and use the same stable
        // absolute root for every subsequent Kura path. Fast deliberately does
        // not create a missing root; it is valid only for Strict-initialized
        // storage.
        let store_dir = std::fs::canonicalize(&configured_store_dir)
            .map_err(|error| Error::IO(error, configured_store_dir))?;
        let store_root = store_dir.clone();
        let store_root_lock_file =
            Self::acquire_store_root_lock(&store_dir, config.init_mode == InitMode::Strict)?;
        #[cfg(all(unix, not(target_os = "espidf")))]
        let store_root_directory =
            Self::open_safety_wal_store_root_directory(&store_root, &store_root_lock_file)?;
        if config.init_mode == InitMode::Strict {
            Self::reject_retired_commit_roster_artifacts(&store_root)?;
        }
        let blocks_in_memory = if config.init_mode == InitMode::Fast {
            NonZeroUsize::new(
                config
                    .blocks_in_memory
                    .get()
                    .min(EMERGENCY_FAST_RECENT_BLOCK_CACHE_CAPACITY.get()),
            )
            .expect("the emergency Fast cache ceiling is non-zero")
        } else {
            config.blocks_in_memory
        };
        Self::reject_retired_merge_storage(&store_dir)?;
        // A local marker cannot authorize imported history or replace native execution.
        Self::reject_retired_snapshot_tail(&Self::canonical_storage_path(&store_dir))?;
        if let Some(configured_catalog_hash) = configured_catalog_hash {
            if config.init_mode == InitMode::Strict {
                Self::establish_or_verify_configured_lane_catalog_baseline_with_lock(
                    &store_dir,
                    configured_catalog_hash,
                    &store_root_lock_file,
                )?;
                #[cfg(test)]
                Self::configured_catalog_preflight_crash_boundary(&store_dir)?;
            } else {
                warn!(
                    "emergency Fast startup skipped configured-catalog and lane-geometry journal decoding"
                );
            }
        }
        // Canonical bodies do not depend on a current LaneId or lane namespace.
        // State installs the authenticated instance catalog after genesis
        // authentication; this open guesses and provisions no lane path.
        let blocks_root = Self::canonical_storage_path(&store_dir);
        let mut canonical_preflight = (config.init_mode == InitMode::Strict)
            .then(|| Self::preflight_canonical_storage(&store_dir))
            .transpose()?;
        if let Some(preflight) = canonical_preflight.as_mut() {
            Self::reverify_canonical_storage_parents(preflight, true)?;
        }
        if blocks_root.as_os_str().is_empty() {
            return Err(Error::EmptyStoreRoot);
        }
        if config.init_mode == InitMode::Strict {
            Self::reject_retired_pipeline_artifacts(&blocks_root)?;
            Self::reject_retired_rollback_intents(&blocks_root)?;
            for retired in [
                "v2_finality",
                "retained_blocks",
                "retained_blocks_rewrite_staging",
                "wsv_checkpoints",
                "commit_manifests",
                "canonical_association_stage.norito",
                "lane_artifacts",
                "kagemusha_v1_finality_staging",
                "kagemusha_v1_finality",
            ] {
                let path = blocks_root.join(retired);
                match std::fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(Error::IO(error, path)),
                    Ok(_) => {
                        return Err(Self::invalid_lane_artifact_error(
                            path,
                            "retired pre-release storage owner",
                        ));
                    }
                }
            }
            for retired in [
                "prune_intent.norito",
                "prune_intent.norito.tmp",
                "pending_merge_entries",
                "merge_carriers",
            ] {
                let path = store_root.join(retired);
                match std::fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(Error::IO(error, path)),
                    Ok(_) => {
                        return Err(Self::invalid_lane_artifact_error(
                            path,
                            "retired pre-release storage owner",
                        ));
                    }
                }
            }
        }
        if let Some(preflight) = canonical_preflight.as_mut() {
            #[cfg(test)]
            {
                configured_primary_open_identity_swap_boundary(&store_dir)?;
                configured_primary_open_identity_swap_boundary(&blocks_root)?;
            }
            Self::reverify_canonical_blocks_open(preflight, &blocks_root, false)?;
        }
        let mut block_store =
            BlockStore::with_fsync(&blocks_root, config.fsync_mode, config.fsync_interval);
        let mut fast_preflight_height = None;
        match config.init_mode {
            InitMode::Fast => {
                if canonical_preflight
                    .as_ref()
                    .is_some_and(|preflight| preflight.requires_existing_files)
                {
                    block_store.require_existing_journal_bound_canonical_files()?;
                }
                fast_preflight_height = Some(block_store.preflight_fast_durable_prefix()?);
                block_store.open_fast_prevalidated_files_read_only()?;
            }
            InitMode::Strict => {
                block_store.recover_canonical_storage_stages()?;
                if canonical_preflight
                    .as_ref()
                    .is_some_and(|preflight| preflight.requires_existing_files)
                {
                    block_store.require_existing_journal_bound_canonical_files()?;
                }
                block_store.read_commit_marker()?;
                block_store.create_files_if_they_do_not_exist()?;
            }
        }
        if let Some(expected_height) = fast_preflight_height {
            if block_store.read_exact_durable_index_count()? != expected_height {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Kura fast init recovery changed the committed block boundary",
                    ),
                    blocks_root.clone(),
                ));
            }
        }
        if let Some(preflight) = canonical_preflight.as_mut() {
            Self::reverify_canonical_blocks_open(preflight, &blocks_root, true)?;
        }

        let (block_notify_tx, block_notify_rx) = mpsc::sync_channel(BLOCK_NOTIFY_CHANNEL_CAPACITY);
        let block_plain_text_path = config
            .debug_output_new_blocks
            .then(|| blocks_root.join("blocks.jsonl"));
        let mut chain_validation = Kura::init(&mut block_store, config.init_mode)?;
        if let Some(preflight) = canonical_preflight.as_mut() {
            Self::reverify_canonical_blocks_open(preflight, &blocks_root, true)?;
        }

        let block_count = usize::try_from(block_store.read_exact_durable_index_count()?)?;
        let block_data = if config.init_mode == InitMode::Fast {
            BlockData::deferred(block_count)
        } else {
            std::mem::take(&mut chain_validation.hashes)
                .into_iter()
                .map(|hash| (hash, None))
                .collect()
        };
        let block_height_index = Self::build_block_height_index(&block_data);
        let transaction_entrypoint_index = Self::build_transaction_entrypoint_index(&block_data);
        info!(
            mode = ?config.init_mode,
            block_count,
            "Kura block journal init complete"
        );
        let startup_lane_storage_entries = BTreeMap::new();

        let resource_inventory = Arc::new(resource_inventory::Inventory::default());
        let (sidecar_lock, sidecar_read_permit) = PublicationMutex::with_read_permit();
        let kura = Arc::new(Self {
            block_hash_history_budget: iroha_allocation::AllocationBudget::new(history_bytes),
            transaction_history_budget: iroha_allocation::AllocationBudget::new(
                transaction_history_bytes,
            ),
            membership_storage,
            resource_inventory: Arc::clone(&resource_inventory),
            instance_identity: Arc::new(KuraInstanceIdentityMarker),
            #[cfg(all(unix, not(target_os = "espidf")))]
            store_root_directory,
            _store_root_lock_file: Some(store_root_lock_file),
            block_store: Mutex::new(block_store),
            canonical_chain_lock: PublicationMutex::default(),
            block_store_write_lock: Mutex::new(()),
            prune_lock: PublicationMutex::default(),
            prune_in_progress: AtomicBool::new(false),
            prune_recovery_required: AtomicBool::new(false),
            block_data: ResidentMutex::new(block_data, &resource_inventory),
            auxiliary_history_deferred: config.init_mode == InitMode::Fast,
            block_height_index: ResidentMutex::new(block_height_index, &resource_inventory),
            transaction_entrypoint_index: ResidentMutex::new(
                transaction_entrypoint_index,
                &resource_inventory,
            ),
            history_checkpoints: history_checkpoints::HistoryCheckpoints::new(
                config.history_checkpoint_cache_capacity.get(),
            ),
            block_notify_tx,
            block_notify_rx: Mutex::new(Some(block_notify_rx)),
            block_plain_text_path: Mutex::new(block_plain_text_path),
            sidecar_lock,
            sidecar_read_permit,
            pipeline_sidecar_queue: ResidentMutex::new(VecDeque::new(), &resource_inventory),
            pipeline_sidecar_queue_cap: AtomicUsize::new(blocks_in_memory.get()),
            fastpq_proof_queue: ResidentMutex::new(VecDeque::new(), &resource_inventory),
            fastpq_proof_sidecar_queue_cap: AtomicUsize::new(
                default_fastpq_proof_sidecar_queue_cap(),
            ),
            fastpq_proof_sidecar_max_bytes: AtomicUsize::new(
                default_fastpq_proof_sidecar_max_bytes(),
            ),
            fastpq_proof_sidecar_max_retries: AtomicUsize::new(
                default_fastpq_proof_sidecar_max_retries(),
            ),
            store_root,
            active_blocks_dir: Mutex::new(blocks_root.clone()),
            lane_storage_entries: ResidentMutex::new(
                startup_lane_storage_entries,
                &resource_inventory,
            ),
            lane_storage_network: Mutex::new(None),
            lane_geometry_lock: PublicationMutex::default(),
            raw_geometry_claim: lane_geometry::RawGeometryClaimGate::default(),
            max_disk_usage_bytes: if config.init_mode == InitMode::Fast {
                0
            } else {
                config.max_disk_usage_bytes.get()
            },
            disk_usage: AtomicU64::new(0),
            disk_usage_total: AtomicU64::new(0),
            disk_usage_total_accounting: Mutex::new(TotalDiskUsageAccountingState::default()),
            disk_usage_total_accounting_changed: Condvar::new(),
            pending_budget_bytes: AtomicU64::new(0),
            pending_budget_bytes_valid: AtomicBool::new(false),
            #[cfg(test)]
            pending_budget_raw_scans: AtomicUsize::new(0),
            durable_budget_persisted_count: AtomicUsize::new(block_count),
            durable_budget_unindexed_bytes: AtomicU64::new(0),
            durable_budget_snapshot_valid: AtomicBool::new(true),
            disk_usage_initialized: AtomicBool::new(false),
            disk_usage_total_initialized: AtomicBool::new(false),
            disk_usage_total_last_refresh: AtomicU64::new(0),
            blocks_in_memory,
            fastpq_artifact_policy: config.fastpq_artifacts,
            native_context_archive_max_bytes: config.native_context_archive_max_bytes,
            telemetry: OnceLock::new(),
            writer_fault: Mutex::new(None),
            canonical_storage_poisoned: AtomicBool::new(false),
            native_consensus_gate: Arc::new(crate::sumeragi::driver::NodeGate::new()),
            #[cfg(test)]
            pause_canonical_poison_after_latch: AtomicBool::new(false),
            #[cfg(test)]
            canonical_poison_paused_after_latch: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_block_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_atomic_write_after_temporary_sync: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_lane_geometry_publication: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_lane_geometry_publication_after_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_lane_geometry_gc_stage: AtomicUsize::new(0),
            #[cfg(test)]
            fail_prune_after_stage: AtomicUsize::new(0),
            #[cfg(test)]
            fail_prune_sidecar_promotion_stage: AtomicUsize::new(0),
            #[cfg(test)]
            pause_prune_before_intent: AtomicBool::new(false),
            #[cfg(test)]
            prune_paused_before_intent: AtomicBool::new(false),
            #[cfg(test)]
            observe_canonical_reads_after_prune_check: AtomicBool::new(false),
            #[cfg(test)]
            canonical_read_kinds_after_prune_check: AtomicUsize::new(0),
            #[cfg(test)]
            pause_geometry_reference_publication: AtomicBool::new(false),
            #[cfg(test)]
            geometry_reference_publication_paused: AtomicBool::new(false),
            #[cfg(test)]
            durable_budget_metadata_reads: AtomicUsize::new(0),
            #[cfg(test)]
            pause_eviction_after_snapshot: AtomicBool::new(false),
            #[cfg(test)]
            eviction_paused_after_snapshot: AtomicBool::new(false),
            #[cfg(test)]
            pause_eviction_before_stage_publication: AtomicBool::new(false),
            #[cfg(test)]
            eviction_paused_before_stage_publication: AtomicBool::new(false),
            #[cfg(test)]
            pause_block_read_before_cache_recheck: AtomicBool::new(false),
            #[cfg(test)]
            block_read_paused_before_cache_recheck: AtomicBool::new(false),
            #[cfg(test)]
            force_durable_blocks_count_fallback: AtomicBool::new(false),
            #[cfg(test)]
            durable_blocks_count_fallback_reached: AtomicBool::new(false),
            #[cfg(test)]
            pause_total_disk_usage_scan_after_scan: AtomicBool::new(false),
            #[cfg(test)]
            total_disk_usage_scan_paused: AtomicBool::new(false),
            _temp_store_dir: None,
        });

        if config.init_mode == InitMode::Strict {
            kura.recover_journal_owned_lane_instances_on_startup()?;
        }
        if config.init_mode == InitMode::Strict {
            kura.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)?;
        } else {
            warn!(
                configured_limit = config.max_disk_usage_bytes.get(),
                "Kura emergency Fast mode skipped the full disk-usage inventory and suspended its local Kura capacity cap until a Strict restart"
            );
        }
        kura.validate_fastpq_artifact_inventory_on_startup()?;
        info!(
            mode = ?config.init_mode,
            block_count,
            init_ms = init_started_at.elapsed().as_millis(),
            "Kura init complete"
        );
        let _ = kura.reconcile_physical_resource_inventory();
        let _ = kura.reconcile_resident_resource_inventory();
        Ok((kura, BlockCount(block_count)))
    }
    /// Create an isolated Kura instance for tests.
    ///
    /// The instance keeps blocks in memory for normal test access, while any background writer
    /// activity is redirected into a per-instance temporary directory instead of the crate root.
    /// Its empty canonical data, index, hash, and count journals match production first-boot
    /// storage so startup-boundary tests cannot accidentally rely on a fileless test-only shape.
    pub fn blank_kura_for_testing() -> Arc<Kura> {
        Self::blank_kura_for_testing_with_lane_config_and_retention(
            &LaneConfig::default(),
            BLOCKS_IN_MEMORY,
        )
    }
    /// Create an isolated empty Kura that exercises emergency Fast startup validation.
    #[cfg(test)]
    pub(crate) fn blank_kura_for_testing_in_emergency_fast_mode() -> Arc<Kura> {
        let mut kura = Self::blank_kura_for_testing();
        Arc::get_mut(&mut kura)
            .expect("a fresh test Kura has one owner")
            .auxiliary_history_deferred = true;
        kura
    }
    /// Return the number of FASTPQ proof snapshots awaiting persistence in tests.
    #[cfg(test)]
    pub(crate) fn fastpq_proof_queue_len_for_testing(&self) -> usize {
        self.fastpq_proof_queue.lock().len()
    }
    /// Create an isolated Kura with a caller-selected body-retention bound.
    ///
    /// This is exposed only to crate tests and downstream users of the
    /// existing `iroha-core-tests` feature so eviction regressions can exercise
    /// the real compaction path without changing production configuration.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn blank_kura_for_testing_with_blocks_in_memory(
        blocks_in_memory: NonZeroUsize,
    ) -> Arc<Kura> {
        Self::blank_kura_for_testing_with_lane_config_and_retention(
            &LaneConfig::default(),
            blocks_in_memory,
        )
    }
    fn blank_kura_for_testing_with_lane_config_and_retention(
        _lane_config: &LaneConfig,
        blocks_in_memory: NonZeroUsize,
    ) -> Arc<Kura> {
        let (block_notify_tx, block_notify_rx) = mpsc::sync_channel(BLOCK_NOTIFY_CHANNEL_CAPACITY);
        let temp_store_dir = tempfile::Builder::new()
            .prefix("iroha-blank-kura-")
            .tempdir()
            .expect("create temporary Kura directory for tests");
        // Keep the test constructor on the same canonical-root boundary as
        // `new_inner`.  On macOS `/var` resolves through `/private/var`; retaining
        // the spelling returned by `tempfile` makes subsequently canonicalized
        // lane-geometry paths appear to escape the Kura root.
        let store_root = std::fs::canonicalize(temp_store_dir.path())
            .expect("canonicalize temporary Kura directory for tests");
        let store_root_lock_file = Self::acquire_store_root_lock(&store_root, true)
            .expect("lock temporary Kura directory for tests");
        Self::establish_or_verify_configured_lane_catalog_baseline_with_lock(
            &store_root,
            LaneLifecycleParameterV1::catalog_hash(&LaneCatalog::default()),
            &store_root_lock_file,
        )
        .expect("authenticate default configured catalog before opening test storage");
        let blocks_root = Self::canonical_storage_path(&store_root);
        std::fs::create_dir_all(&blocks_root)
            .expect("create temporary Kura block directory for tests");
        let mut block_store =
            BlockStore::with_fsync(&blocks_root, FsyncMode::Batched, FSYNC_INTERVAL);
        block_store
            .create_files_if_they_do_not_exist()
            .expect("initialize empty canonical Kura journal for tests");
        #[cfg(all(unix, not(target_os = "espidf")))]
        let store_root_directory = Self::open_bound_progress_directory(&store_root, &store_root)
            .expect("bind temporary Kura store-root directory");
        let resource_inventory = Arc::new(resource_inventory::Inventory::default());
        let (sidecar_lock, sidecar_read_permit) = PublicationMutex::with_read_permit();
        Arc::new(Self {
            membership_storage: membership_storage::MembershipStorage::new(
                iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            )
            .expect("default finite membership control fits its original pool"),
            block_hash_history_budget: iroha_allocation::AllocationBudget::new(
                usize::try_from(
                    iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES.get(),
                )
                .expect("default history budget fits supported platforms"),
            ),
            transaction_history_budget: iroha_allocation::AllocationBudget::new(
                usize::try_from(
                    iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES.get(),
                )
                .expect("default transaction history budget fits supported platforms"),
            ),
            resource_inventory: Arc::clone(&resource_inventory),
            instance_identity: Arc::new(KuraInstanceIdentityMarker),
            #[cfg(all(unix, not(target_os = "espidf")))]
            store_root_directory,
            _store_root_lock_file: Some(store_root_lock_file),
            block_store: Mutex::new(block_store),
            canonical_chain_lock: PublicationMutex::default(),
            block_store_write_lock: Mutex::new(()),
            prune_lock: PublicationMutex::default(),
            prune_in_progress: AtomicBool::new(false),
            prune_recovery_required: AtomicBool::new(false),
            block_data: ResidentMutex::new(BlockData::default(), &resource_inventory),
            auxiliary_history_deferred: false,
            block_height_index: ResidentMutex::new(HashMap::new(), &resource_inventory),
            transaction_entrypoint_index: ResidentMutex::new(
                TransactionEntrypointIndex::complete_empty(),
                &resource_inventory,
            ),
            history_checkpoints: history_checkpoints::HistoryCheckpoints::default(),
            block_notify_tx,
            block_notify_rx: Mutex::new(Some(block_notify_rx)),
            block_plain_text_path: Mutex::new(None),
            sidecar_lock,
            sidecar_read_permit,
            pipeline_sidecar_queue: ResidentMutex::new(VecDeque::new(), &resource_inventory),
            pipeline_sidecar_queue_cap: AtomicUsize::new(default_pipeline_sidecar_queue_cap()),
            fastpq_proof_queue: ResidentMutex::new(VecDeque::new(), &resource_inventory),
            fastpq_proof_sidecar_queue_cap: AtomicUsize::new(
                default_fastpq_proof_sidecar_queue_cap(),
            ),
            fastpq_proof_sidecar_max_bytes: AtomicUsize::new(
                default_fastpq_proof_sidecar_max_bytes(),
            ),
            fastpq_proof_sidecar_max_retries: AtomicUsize::new(
                default_fastpq_proof_sidecar_max_retries(),
            ),
            store_root,
            active_blocks_dir: Mutex::new(blocks_root),
            lane_storage_entries: ResidentMutex::new(BTreeMap::new(), &resource_inventory),
            lane_storage_network: Mutex::new(None),
            lane_geometry_lock: PublicationMutex::default(),
            raw_geometry_claim: lane_geometry::RawGeometryClaimGate::default(),
            max_disk_usage_bytes: MAX_DISK_USAGE_BYTES.get(),
            disk_usage: AtomicU64::new(0),
            disk_usage_total: AtomicU64::new(0),
            disk_usage_total_accounting: Mutex::new(TotalDiskUsageAccountingState::default()),
            disk_usage_total_accounting_changed: Condvar::new(),
            pending_budget_bytes: AtomicU64::new(0),
            pending_budget_bytes_valid: AtomicBool::new(false),
            #[cfg(test)]
            pending_budget_raw_scans: AtomicUsize::new(0),
            durable_budget_persisted_count: AtomicUsize::new(0),
            durable_budget_unindexed_bytes: AtomicU64::new(0),
            durable_budget_snapshot_valid: AtomicBool::new(true),
            disk_usage_initialized: AtomicBool::new(true),
            disk_usage_total_initialized: AtomicBool::new(true),
            disk_usage_total_last_refresh: AtomicU64::new(0),
            blocks_in_memory,
            fastpq_artifact_policy:
                iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            telemetry: OnceLock::new(),
            writer_fault: Mutex::new(None),
            canonical_storage_poisoned: AtomicBool::new(false),
            native_consensus_gate: Arc::new(crate::sumeragi::driver::NodeGate::new()),
            #[cfg(test)]
            pause_canonical_poison_after_latch: AtomicBool::new(false),
            #[cfg(test)]
            canonical_poison_paused_after_latch: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_block_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_atomic_write_after_temporary_sync: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_lane_geometry_publication: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_lane_geometry_publication_after_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_lane_geometry_gc_stage: AtomicUsize::new(0),
            #[cfg(test)]
            fail_prune_after_stage: AtomicUsize::new(0),
            #[cfg(test)]
            fail_prune_sidecar_promotion_stage: AtomicUsize::new(0),
            #[cfg(test)]
            pause_prune_before_intent: AtomicBool::new(false),
            #[cfg(test)]
            prune_paused_before_intent: AtomicBool::new(false),
            #[cfg(test)]
            observe_canonical_reads_after_prune_check: AtomicBool::new(false),
            #[cfg(test)]
            canonical_read_kinds_after_prune_check: AtomicUsize::new(0),
            #[cfg(test)]
            pause_geometry_reference_publication: AtomicBool::new(false),
            #[cfg(test)]
            geometry_reference_publication_paused: AtomicBool::new(false),
            #[cfg(test)]
            durable_budget_metadata_reads: AtomicUsize::new(0),
            #[cfg(test)]
            pause_eviction_after_snapshot: AtomicBool::new(false),
            #[cfg(test)]
            eviction_paused_after_snapshot: AtomicBool::new(false),
            #[cfg(test)]
            pause_eviction_before_stage_publication: AtomicBool::new(false),
            #[cfg(test)]
            eviction_paused_before_stage_publication: AtomicBool::new(false),
            #[cfg(test)]
            pause_block_read_before_cache_recheck: AtomicBool::new(false),
            #[cfg(test)]
            block_read_paused_before_cache_recheck: AtomicBool::new(false),
            #[cfg(test)]
            force_durable_blocks_count_fallback: AtomicBool::new(false),
            #[cfg(test)]
            durable_blocks_count_fallback_reached: AtomicBool::new(false),
            #[cfg(test)]
            pause_total_disk_usage_scan_after_scan: AtomicBool::new(false),
            #[cfg(test)]
            total_disk_usage_scan_paused: AtomicBool::new(false),
            _temp_store_dir: Some(temp_store_dir),
        })
    }
    /// Attach a telemetry sink for storage and durable finality reporting.
    pub fn attach_telemetry(&self, telemetry: StateTelemetry) {
        let _ = self.telemetry.set(telemetry);
    }
    /// Configure FASTPQ proof sidecar persistence limits from runtime configuration.
    pub fn configure_fastpq_proof_sidecar_limits(&self, config: &FastpqConfig) {
        let max_bytes = usize::try_from(config.proof_sidecar_max_bytes.get())
            .unwrap_or(usize::MAX)
            .max(1);
        self.set_fastpq_proof_sidecar_limits(
            config.proof_sidecar_queue_cap.get(),
            max_bytes,
            config.proof_sidecar_max_retries.get(),
        );
    }
    fn set_fastpq_proof_sidecar_limits(
        &self,
        queue_cap: usize,
        max_bytes: usize,
        max_retries: usize,
    ) {
        self.fastpq_proof_sidecar_queue_cap
            .store(queue_cap.max(1), Ordering::Relaxed);
        self.fastpq_proof_sidecar_max_bytes
            .store(max_bytes.max(1), Ordering::Relaxed);
        self.fastpq_proof_sidecar_max_retries
            .store(max_retries.max(1), Ordering::Relaxed);
    }
    /// Record that a FASTPQ proof could not be persisted because no entry hash was available.
    pub fn record_fastpq_missing_entry_hash(&self) {
        let _ = self;
        let telemetry = FastpqProofSidecarTelemetry;
        telemetry.record_event("missing_entry_hash");
    }
    #[cfg(test)]
    fn set_fastpq_proof_sidecar_limits_for_testing(
        &self,
        queue_cap: usize,
        max_bytes: usize,
        max_retries: usize,
    ) {
        self.set_fastpq_proof_sidecar_limits(queue_cap, max_bytes, max_retries);
    }
    #[cfg(test)]
    fn set_pipeline_sidecar_queue_cap_for_testing(&self, queue_cap: usize) {
        self.pipeline_sidecar_queue_cap
            .store(queue_cap.max(1), Ordering::Relaxed);
    }
    /// Return the number of pipeline recovery sidecars pending in the test-only writer queue.
    #[cfg(test)]
    pub(crate) fn pipeline_sidecar_queue_len_for_testing(&self) -> usize {
        self.pipeline_sidecar_queue.lock().len()
    }
    /// Retain this Kura's original opened directory for native context publication.
    pub(crate) fn native_context_archive_root(&self) -> std::io::Result<std::fs::File> {
        #[cfg(all(unix, not(target_os = "espidf")))]
        {
            if !self.instance_identity().matches(self)
                || !self.bound_storage_directory_unchanged(&self.store_root_directory)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "opened Kura root changed before native context archive binding",
                ));
            }
            self.store_root_directory.file.try_clone()
        }
        #[cfg(not(all(unix, not(target_os = "espidf"))))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "original Kura directory custody is required for native context publication",
            ))
        }
    }
    /// Original configured limit for each canonical native context projection.
    #[must_use]
    pub const fn native_context_archive_max_bytes(&self) -> NonZeroUsize {
        self.native_context_archive_max_bytes
    }
    /// Root directory used by this Kura instance.
    #[must_use]
    pub fn store_root(&self) -> PathBuf {
        self.store_root.clone()
    }
    /// Return cached total on-disk bytes used by Kura (active + retired segments).
    ///
    /// Includes canonical frames, local DA custody, monetary outboxes, pipeline
    /// records and every other declared Kura storage owner. Native consensus
    /// archive writers retain their independent finite resource owner.
    /// Use [`Self::refresh_disk_usage_bytes`] to rescan the physical inventory.
    pub(crate) fn disk_usage_bytes(&self) -> Result<u64> {
        if self.emergency_fast_startup_enabled()
            && !self.disk_usage_total_initialized.load(Ordering::Acquire)
        {
            return Err(self.emergency_fast_disk_usage_unavailable());
        }
        loop {
            let generation = {
                let mut accounting = self.disk_usage_total_accounting.lock();
                while accounting.mutations_in_flight != 0 {
                    self.disk_usage_total_accounting_changed
                        .wait(&mut accounting);
                }
                accounting.generation
            };
            self.maybe_refresh_total_disk_usage_bytes()?;
            let accounting = self.disk_usage_total_accounting.lock();
            if accounting.mutations_in_flight != 0 || accounting.generation != generation {
                drop(accounting);
                continue;
            }
            if !self.disk_usage_total_initialized.load(Ordering::Acquire) {
                drop(accounting);
                continue;
            }
            return Ok(self.disk_usage_total.load(Ordering::Relaxed));
        }
    }
    /// Recompute enforced and total on-disk bytes in one scan and refresh both caches.
    pub(crate) fn refresh_disk_usage_bytes(&self) -> Result<u64> {
        if self.emergency_fast_startup_enabled() {
            return Err(self.emergency_fast_disk_usage_unavailable());
        }
        loop {
            let generation = {
                let mut accounting = self.disk_usage_total_accounting.lock();
                while accounting.mutations_in_flight != 0 {
                    self.disk_usage_total_accounting_changed
                        .wait(&mut accounting);
                }
                accounting.generation
            };
            let scanned = self.kura_disk_usage_bytes_with_total();
            let durable_budget = self.persisted_count_and_unindexed_bytes_raw();
            #[cfg(test)]
            self.maybe_pause_total_disk_usage_scan_after_scan_for_tests();
            let accounting = self.disk_usage_total_accounting.lock();
            if accounting.mutations_in_flight != 0 || accounting.generation != generation {
                drop(accounting);
                continue;
            }
            let (usage, total) = match scanned {
                Ok(usage) => usage,
                Err(error) => {
                    self.disk_usage_initialized.store(false, Ordering::Relaxed);
                    self.disk_usage_total_initialized
                        .store(false, Ordering::Relaxed);
                    self.invalidate_durable_budget_snapshot();
                    return Err(error);
                }
            };
            self.disk_usage.store(usage, Ordering::Relaxed);
            self.disk_usage_initialized.store(true, Ordering::Relaxed);
            match durable_budget {
                Ok((persisted_count, unindexed_bytes)) => {
                    self.publish_durable_budget_snapshot(persisted_count, unindexed_bytes);
                }
                Err(err) => {
                    warn!(?err, "failed to refresh Kura durable budget metadata");
                    self.invalidate_durable_budget_snapshot();
                }
            }
            self.disk_usage_total.store(total, Ordering::Relaxed);
            self.disk_usage_total_initialized
                .store(true, Ordering::Relaxed);
            self.disk_usage_total_last_refresh
                .store(Self::now_unix_secs(), Ordering::Relaxed);
            return Ok(usage);
        }
    }
    /// Recompute total on-disk bytes and refresh the cached value.
    pub(crate) fn refresh_total_disk_usage_bytes(&self) -> Result<u64> {
        if self.emergency_fast_startup_enabled() {
            return Err(self.emergency_fast_disk_usage_unavailable());
        }
        loop {
            let generation = {
                let mut accounting = self.disk_usage_total_accounting.lock();
                while accounting.mutations_in_flight != 0 {
                    self.disk_usage_total_accounting_changed
                        .wait(&mut accounting);
                }
                accounting.generation
            };
            let scanned = self.kura_total_disk_usage_bytes();
            #[cfg(test)]
            self.maybe_pause_total_disk_usage_scan_after_scan_for_tests();
            let accounting = self.disk_usage_total_accounting.lock();
            if accounting.mutations_in_flight != 0 || accounting.generation != generation {
                drop(accounting);
                continue;
            }
            let usage = match scanned {
                Ok(usage) => usage,
                Err(error) => {
                    self.disk_usage_total_initialized
                        .store(false, Ordering::Release);
                    return Err(error);
                }
            };
            self.disk_usage_total.store(usage, Ordering::Relaxed);
            self.disk_usage_total_initialized
                .store(true, Ordering::Relaxed);
            self.disk_usage_total_last_refresh
                .store(Self::now_unix_secs(), Ordering::Relaxed);
            return Ok(usage);
        }
    }
    /// Register a filesystem mutation before its first write, rename, or removal.
    pub(crate) fn begin_total_disk_usage_mutation(&self) -> TotalDiskUsageMutation<'_> {
        let mut accounting = self.disk_usage_total_accounting.lock();
        accounting.mutations_in_flight = accounting
            .mutations_in_flight
            .checked_add(1)
            .expect("total disk-usage mutation count must not overflow");
        accounting.generation = accounting.generation.wrapping_add(1);
        drop(accounting);
        TotalDiskUsageMutation {
            kura: self,
            published: false,
            physical_resources: self.begin_physical_resource_mutation(),
            physical_scope_classified: false,
            physical_children_remaining: None,
        }
    }
    fn finish_total_disk_usage_mutation(&self, published: bool) {
        let mut accounting = self.disk_usage_total_accounting.lock();
        if !published {
            self.disk_usage_initialized.store(false, Ordering::Relaxed);
            self.disk_usage_total_initialized
                .store(false, Ordering::Relaxed);
            self.invalidate_durable_budget_snapshot();
        }
        accounting.mutations_in_flight = accounting
            .mutations_in_flight
            .checked_sub(1)
            .expect("total disk-usage mutation guard must be balanced");
        accounting.generation = accounting.generation.wrapping_add(1);
        if accounting.mutations_in_flight == 0 {
            self.disk_usage_total_accounting_changed.notify_all();
        }
    }
    #[cfg(test)]
    fn maybe_pause_total_disk_usage_scan_after_scan_for_tests(&self) {
        if self
            .pause_total_disk_usage_scan_after_scan
            .swap(false, Ordering::AcqRel)
        {
            self.total_disk_usage_scan_paused
                .store(true, Ordering::Release);
            while self.total_disk_usage_scan_paused.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
    }
    fn maybe_refresh_total_disk_usage_bytes(&self) -> Result<()> {
        if self.emergency_fast_startup_enabled() {
            return Err(self.emergency_fast_disk_usage_unavailable());
        }
        if !self.disk_usage_total_initialized.load(Ordering::Relaxed) {
            let _ = self.refresh_total_disk_usage_bytes()?;
            return Ok(());
        }
        let last_refresh = self.disk_usage_total_last_refresh.load(Ordering::Relaxed);
        let now = Self::now_unix_secs();
        if now.saturating_sub(last_refresh) >= DISK_USAGE_TOTAL_REFRESH_INTERVAL.as_secs() {
            let _ = self.refresh_total_disk_usage_bytes()?;
        }
        Ok(())
    }
    fn ensure_disk_usage_initialized(&self) -> Result<()> {
        if self.emergency_fast_startup_enabled() {
            return Err(self.emergency_fast_disk_usage_unavailable());
        }
        if self.disk_usage_initialized.load(Ordering::Relaxed) {
            return Ok(());
        }
        let _ = self.refresh_disk_usage_bytes()?;
        Ok(())
    }
    fn emergency_fast_disk_usage_unavailable(&self) -> Error {
        Error::EmergencyFastAuxiliaryUnavailable {
            subsystem: "disk-usage inventory",
        }
    }
    /// Update the cached disk usage by applying a before/after delta.
    pub(crate) fn update_disk_usage_delta(&self, before: u64, after: u64) {
        if before == after {
            return;
        }
        if after > before {
            self.add_disk_usage_bytes(after - before);
        } else {
            self.sub_disk_usage_bytes(before - after);
        }
    }
    fn update_total_disk_usage_delta(&self, before: u64, after: u64) {
        if before == after {
            return;
        }
        if after > before {
            self.add_total_disk_usage_bytes(after - before);
        } else {
            self.sub_total_disk_usage_bytes(before - after);
        }
    }
    fn add_disk_usage_bytes(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        let _accounting_guard = self.disk_usage_total_accounting.lock();
        self.add_disk_usage_bytes_locked(delta);
    }
    fn add_disk_usage_bytes_locked(&self, delta: u64) {
        let _ = self
            .disk_usage
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            });
        self.add_total_disk_usage_bytes_locked(delta);
    }
    fn sub_disk_usage_bytes(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        let _accounting_guard = self.disk_usage_total_accounting.lock();
        self.sub_disk_usage_bytes_locked(delta);
    }
    fn sub_disk_usage_bytes_locked(&self, delta: u64) {
        let _ = self
            .disk_usage
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(delta))
            });
        self.sub_total_disk_usage_bytes_locked(delta);
    }
    fn add_total_disk_usage_bytes(&self, delta: u64) {
        let _accounting_guard = self.disk_usage_total_accounting.lock();
        self.add_total_disk_usage_bytes_locked(delta);
    }
    fn add_total_disk_usage_bytes_locked(&self, delta: u64) {
        if delta == 0 || !self.disk_usage_total_initialized.load(Ordering::Relaxed) {
            return;
        }
        let _ =
            self.disk_usage_total
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(delta))
                });
    }
    fn sub_total_disk_usage_bytes(&self, delta: u64) {
        let _accounting_guard = self.disk_usage_total_accounting.lock();
        self.sub_total_disk_usage_bytes_locked(delta);
    }
    fn sub_total_disk_usage_bytes_locked(&self, delta: u64) {
        if delta == 0 || !self.disk_usage_total_initialized.load(Ordering::Relaxed) {
            return;
        }
        let _ =
            self.disk_usage_total
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(delta))
                });
    }
    fn invalidate_pending_budget_cache(&self) {
        self.pending_budget_bytes_valid
            .store(false, Ordering::Relaxed);
    }
    fn durable_budget_snapshot(&self) -> Option<(usize, u64)> {
        if !self.durable_budget_snapshot_valid.load(Ordering::Acquire) {
            return None;
        }
        Some((
            self.durable_budget_persisted_count.load(Ordering::Relaxed),
            self.durable_budget_unindexed_bytes.load(Ordering::Relaxed),
        ))
    }
    fn publish_durable_budget_snapshot(&self, persisted_count: usize, unindexed_bytes: u64) {
        self.durable_budget_persisted_count
            .store(persisted_count, Ordering::Relaxed);
        self.durable_budget_unindexed_bytes
            .store(unindexed_bytes, Ordering::Relaxed);
        self.durable_budget_snapshot_valid
            .store(true, Ordering::Release);
    }
    fn invalidate_durable_budget_snapshot(&self) {
        self.durable_budget_snapshot_valid
            .store(false, Ordering::Release);
    }
    fn lock_block_store_for_write(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.block_store_write_lock.lock()
    }
    #[cfg(test)]
    fn maybe_pause_eviction_after_snapshot_for_tests(&self) {
        if self
            .pause_eviction_after_snapshot
            .swap(false, Ordering::AcqRel)
        {
            self.eviction_paused_after_snapshot
                .store(true, Ordering::Release);
            while self.eviction_paused_after_snapshot.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
    }
    #[cfg(test)]
    fn maybe_pause_eviction_before_stage_publication_for_tests(&self) {
        if self
            .pause_eviction_before_stage_publication
            .swap(false, Ordering::AcqRel)
        {
            self.eviction_paused_before_stage_publication
                .store(true, Ordering::Release);
            while self
                .eviction_paused_before_stage_publication
                .load(Ordering::Acquire)
            {
                std::thread::yield_now();
            }
        }
    }
    #[cfg(test)]
    fn maybe_pause_block_read_before_cache_recheck_for_tests(&self) {
        if self
            .pause_block_read_before_cache_recheck
            .swap(false, Ordering::AcqRel)
        {
            self.block_read_paused_before_cache_recheck
                .store(true, Ordering::Release);
            while self
                .block_read_paused_before_cache_recheck
                .load(Ordering::Acquire)
            {
                std::thread::yield_now();
            }
        }
    }
    #[cfg(test)]
    fn maybe_pause_canonical_poison_after_latch_for_tests(&self) {
        if self
            .pause_canonical_poison_after_latch
            .swap(false, Ordering::AcqRel)
        {
            self.canonical_poison_paused_after_latch
                .store(true, Ordering::Release);
            while self
                .canonical_poison_paused_after_latch
                .load(Ordering::Acquire)
            {
                std::thread::yield_now();
            }
        }
    }
    fn record_writer_fault(&self, context: &'static str, error: &Error) {
        {
            let mut fault = self.writer_fault.lock();
            if fault.is_none() {
                *fault = Some(format!("{context}: {error}"));
            }
        }
        if let Some(telemetry) = self.telemetry.get() {
            telemetry.inc_storage_budget_exceeded("kura_writer_fault");
        }
    }
    fn poison_canonical_storage(&self, context: &'static str, error: &Error) {
        // The gate belongs to this storage owner from construction, before any
        // driver can start. Close it before publishing poison; no bind race exists.
        // Already admitted operations retain their original owners until they return.
        self.native_consensus_gate.close();
        self.canonical_storage_poisoned
            .store(true, Ordering::Release);
        #[cfg(test)]
        self.maybe_pause_canonical_poison_after_latch_for_tests();
        self.record_writer_fault(context, error);
        // Invalidate after the existing fail-stop sequence: resource accounting
        // must never delay publishing the latch or closing consensus admission.
        // The generation also rejects a reconciliation captured before poison.
        self.resource_inventory.invalidate(
            physical_resource_mask(),
            resource_inventory::Unavailable::InvalidInventory,
        );
    }
    /// Preserve a local storage read failure by closing the permanent native gate.
    /// Only storage-coordinate reads belong here; candidate identity checks run afterwards.
    pub(crate) fn consensus_storage_read<T>(&self, result: Result<T>) -> Result<T> {
        result.inspect_err(|error| {
            self.poison_canonical_storage("consensus storage read failed", error);
        })
    }
    /// The permanent native consensus gate shared by every instance using this Kura.
    /// A clone obtained after poison is already closed; there is no replaceable binding.
    pub(crate) fn native_consensus_gate(&self) -> Arc<crate::sumeragi::driver::NodeGate> {
        Arc::clone(&self.native_consensus_gate)
    }
    fn committed_recovery_failure(&self, context: &'static str, error: &Error) -> Error {
        let recovery_error = Error::CanonicalBlockCommittedRecoveryRequired {
            detail: format!("{context}: {error}"),
        };
        self.poison_canonical_storage(context, &recovery_error);
        recovery_error
    }
    fn record_or_poison_fsync_fault(&self, context: &'static str, error: &Error) {
        if self.store_root.as_os_str().is_empty() {
            self.record_writer_fault(context, error);
            return;
        }
        let unresolved_stage = {
            let store = self.block_store.lock();
            [
                store.da_block_rewrite_stage_path(),
                store.eviction_compaction_stage_path(),
            ]
            .into_iter()
            .any(|path| match std::fs::symlink_metadata(path) {
                Ok(_) => true,
                Err(error) => error.kind() != ErrorKind::NotFound,
            })
        };
        if unresolved_stage
            || matches!(
                error,
                Error::DaBlockRewriteCommitStateUnknown { .. } | Error::CanonicalStoragePoisoned
            )
        {
            self.poison_canonical_storage(context, error);
        } else {
            self.record_writer_fault(context, error);
        }
    }
    fn ensure_canonical_storage_not_poisoned(&self) -> Result<()> {
        if self.canonical_storage_poisoned.load(Ordering::Acquire) {
            return Err(Error::CanonicalStoragePoisoned);
        }
        Ok(())
    }
    fn resolve_canonical_storage_before_mutation(&self) -> Result<()> {
        // The canonical fence also orders raw geometry claim acquisition.
        // Its original request must not observe a different carrier frontier
        // while State retains the operation between physical leases.
        self.raw_geometry_claim.ensure_unclaimed()?;
        self.durable_mutation_authorized()?;
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        let write_guard = self.block_store_write_lock.lock();
        let mut store = self.block_store.lock();
        let resources = self
            .begin_canonical_physical_mutation(&mut store, CanonicalPhysicalOperation::Recovery);
        if let Err(error) = store.recover_canonical_storage_stages() {
            drop(store);
            self.poison_canonical_storage("unresolved canonical storage stage", &error);
            return Err(Error::CanonicalStoragePoisoned);
        }
        let deferred_da_recovery_fault = store.take_deferred_da_recovery_fault();
        let da_rewrite_stage_path = store.da_block_rewrite_stage_path();
        if deferred_da_recovery_fault.is_none() {
            resources.finish_resources_before_disk_rescan();
        }
        drop(store);
        drop(write_guard);
        if let Some(message) = deferred_da_recovery_fault {
            let recovered = Error::IO(std::io::Error::other(message), da_rewrite_stage_path);
            return Err(
                self.committed_recovery_failure("recovered committed DA block rewrite", &recovered)
            );
        }
        self.ensure_prune_recovery_not_required()
    }
    /// Number of newest canonical block bodies protected from Kura eviction.
    #[must_use]
    pub(crate) fn blocks_in_memory(&self) -> NonZeroUsize {
        self.blocks_in_memory
    }
    fn lane_storage_entries_from_geometry(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
    ) -> Result<BTreeMap<LaneId, LaneStorageEntry>> {
        let network_id = self.bound_lane_storage_network()?;
        lane_config
            .entries()
            .iter()
            .map(|entry| {
                let incarnation = incarnations.get(&entry.lane_id).copied().ok_or_else(|| {
                    Self::invalid_lane_artifact_error(
                        self.store_root.clone(),
                        "lane storage catalog lacks its exact incarnation",
                    )
                })?;
                let activation_height = activation_heights
                    .get(&entry.lane_id)
                    .copied()
                    .ok_or_else(|| {
                        Self::invalid_lane_artifact_error(
                            self.store_root.clone(),
                            "lane storage catalog lacks its exact activation",
                        )
                    })?;
                if incarnation.as_ref().iter().all(|byte| *byte == 0) {
                    return Err(Self::invalid_lane_artifact_error(
                        self.store_root.clone(),
                        "lane storage incarnation is zero",
                    ));
                }
                let identity = LaneStorageIdentity {
                    network_id,
                    lane_id: entry.lane_id,
                    dataspace_id: entry.dataspace_id,
                    incarnation,
                    activation_height,
                };
                Ok((entry.lane_id, LaneStorageEntry { identity }))
            })
            .collect()
    }
    fn bound_lane_storage_network(&self) -> Result<NetworkId> {
        self.lane_storage_network
            .lock()
            .as_ref()
            .copied()
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    self.store_root.clone(),
                    "lane storage is unavailable before authenticated network binding",
                )
            })
    }
    fn lane_storage_entry(&self, lane_id: LaneId) -> Result<LaneStorageEntry> {
        self.lane_storage_entries
            .lock()
            .get(&lane_id)
            .cloned()
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::NotFound,
                        format!("no Kura storage segment configured for lane {lane_id:?}"),
                    ),
                    self.store_root
                        .join("blocks")
                        .join(format!("lane_{:03}", lane_id.as_u32())),
                )
            })
    }
    /// Restore snapshot lane storage at an exact committed transition height
    /// and retained-lineage commitment.
    pub(crate) fn restore_lane_segments_with_geometry_at_height_and_lineage_root(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        authoritative_height: u64,
        lineage_root: Hash,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_at_height_with_lineage_root(
            lane_config,
            incarnations,
            activation_heights,
            authoritative_height,
            lineage_root,
        )?;
        self.finish_restored_lane_segments_with_geometry(lane_config)
    }
    /// Restore lane storage to the cursor before every transition at one committed height.
    ///
    /// Startup replay uses this for the genesis/configuration height, where more than one
    /// transition can legitimately share the same height and must be retried in journal order.
    pub(crate) fn restore_lane_segments_with_geometry_before_first_transition_at_height(
        &self,
        lane_config: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        transition_height: u64,
    ) -> Result<()> {
        self.recover_lane_geometry_journal_before_first_transition_at_height_with_lineage_root(
            lane_config,
            incarnations,
            activation_heights,
            lineage_root,
            transition_height,
        )?;
        self.finish_restored_lane_segments_with_geometry(lane_config)
    }
    fn finish_restored_lane_segments_with_geometry(&self, _lane_config: &LaneConfig) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        // Recovery already authenticated the exact lane bindings; canonical
        // storage is independent of the restored primary alias.
        if self.emergency_fast_startup_enabled() {
            warn!(
                "Kura emergency Fast mode skipped historical lane repair and capacity audits after geometry restore"
            );
            return Ok(());
        }
        self.validate_and_publish_configured_kura_capacity_after_startup_recovery(true)?;
        Ok(())
    }
    #[cfg(unix)]
    fn sidecar_metadata_same_object(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(windows)]
    fn sidecar_metadata_same_object(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
            && left.volume_serial_number().is_some()
            && left.file_index().is_some()
    }
    #[cfg(all(not(unix), not(windows)))]
    fn sidecar_metadata_same_object(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
        false
    }
    #[cfg(unix)]
    fn sidecar_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        Self::sidecar_metadata_same_object(left, right)
            && left.nlink() == 1
            && right.nlink() == 1
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(unix)]
    fn sidecar_file_metadata_unchanged_across_rename(
        left: &SecureMetadata,
        right: &SecureMetadata,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        // Renaming the bound object legitimately advances ctime. Preserve the
        // exact-object, link-count, length, and content-mtime checks that detect
        // replacement or concurrent writes across quarantine publication.
        Self::sidecar_metadata_same_object(left, right)
            && left.nlink() == 1
            && right.nlink() == 1
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
    }
    #[cfg(unix)]
    fn sidecar_directory_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        Self::sidecar_metadata_same_object(left, right)
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(windows)]
    fn sidecar_directory_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        Self::sidecar_metadata_same_object(left, right)
            && left.last_write_time() == right.last_write_time()
            && left.creation_time() == right.creation_time()
    }
    #[cfg(all(not(unix), not(windows)))]
    fn sidecar_directory_metadata_unchanged(
        _left: &SecureMetadata,
        _right: &SecureMetadata,
    ) -> bool {
        false
    }
    fn sidecar_directory_binding_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        // Directory mtime/ctime describe mutations to child entries, not replacement of the
        // directory itself. Progress sidecars are published concurrently, so descriptor binding
        // must compare object identity only. Stable inventory scans deliberately retain the
        // stronger timestamp comparison in `sidecar_directory_metadata_unchanged`.
        Self::sidecar_metadata_same_object(left, right)
    }
    #[cfg(windows)]
    fn sidecar_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        Self::sidecar_metadata_same_object(left, right)
            && left.number_of_links() == Some(1)
            && right.number_of_links() == Some(1)
            && left.file_size() == right.file_size()
            && left.last_write_time() == right.last_write_time()
            && left.creation_time() == right.creation_time()
    }
    #[cfg(all(not(unix), not(windows)))]
    fn sidecar_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        Self::sidecar_metadata_same_object(left, right)
            && left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
    }
    fn stable_sidecar_metadata_unchanged(
        left: &StableSidecarMetadata,
        right: &StableSidecarMetadata,
    ) -> bool {
        left.canonical_path == right.canonical_path
            && Self::sidecar_file_metadata_unchanged(&left.file, &right.file)
            && Self::sidecar_directory_metadata_unchanged(&left.directory, &right.directory)
    }
    fn stable_sidecar_file_binding_unchanged(
        left: &StableSidecarMetadata,
        right: &StableSidecarMetadata,
    ) -> bool {
        // A sibling publication legitimately advances the directory timestamps
        // without changing this file. Single-file reads bind the directory by
        // object identity; inventory scans use the stronger timestamp check in
        // `stable_sidecar_metadata_unchanged` to detect sibling mutations.
        left.canonical_path == right.canonical_path
            && Self::sidecar_file_metadata_unchanged(&left.file, &right.file)
            && Self::sidecar_directory_binding_unchanged(&left.directory, &right.directory)
    }
    fn stable_sidecar_directory_metadata_unchanged(
        left: &StableSidecarDirectoryMetadata,
        right: &StableSidecarDirectoryMetadata,
    ) -> bool {
        if left.expected_path != right.expected_path || left.canonical_path != right.canonical_path
        {
            return false;
        }
        match (&left.metadata, &right.metadata) {
            (None, None) => true,
            (Some(left), Some(right)) => Self::sidecar_directory_metadata_unchanged(left, right),
            (None, Some(_)) | (Some(_), None) => false,
        }
    }
    #[cfg(unix)]
    fn sidecar_is_single_link(metadata: &SecureMetadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    }
    #[cfg(windows)]
    fn sidecar_is_single_link(metadata: &SecureMetadata) -> bool {
        metadata.number_of_links() == Some(1)
    }
    #[cfg(all(not(unix), not(windows)))]
    fn sidecar_is_single_link(_metadata: &SecureMetadata) -> bool {
        false
    }
    #[cfg(unix)]
    fn sidecar_has_link_count(metadata: &SecureMetadata, expected: u64) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == expected
    }
    #[cfg(windows)]
    fn sidecar_has_link_count(metadata: &SecureMetadata, expected: u64) -> bool {
        u32::try_from(expected)
            .ok()
            .is_some_and(|expected| metadata.number_of_links() == Some(expected))
    }
    #[cfg(all(not(unix), not(windows)))]
    fn sidecar_has_link_count(_metadata: &SecureMetadata, _expected: u64) -> bool {
        false
    }
    fn canonical_sidecar_directory_for(
        store_root: &Path,
        expected_directory: &Path,
    ) -> Result<Option<(PathBuf, SecureMetadata)>> {
        #[cfg(test)]
        SIDECAR_DIRECTORY_CANONICALIZATIONS.with(|count| {
            if let Some(current) = count.get() {
                count.set(Some(current + 1));
            }
        });
        let before = match secure_file_metadata::from_path(expected_directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::IO(error, expected_directory.to_path_buf())),
        };
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar directory is not a direct directory",
                ),
                expected_directory.to_path_buf(),
            ));
        }
        let relative = expected_directory.strip_prefix(store_root).map_err(|_| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar directory is outside the configured Kura root",
                ),
                expected_directory.to_path_buf(),
            )
        })?;
        let canonical_root = std::fs::canonicalize(store_root)
            .map_err(|error| Error::IO(error, store_root.to_path_buf()))?;
        let canonical_directory = std::fs::canonicalize(expected_directory)
            .map_err(|error| Error::IO(error, expected_directory.to_path_buf()))?;
        if canonical_directory != canonical_root.join(relative) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar directory contains a symlink or escapes the Kura root",
                ),
                expected_directory.to_path_buf(),
            ));
        }
        let after = secure_file_metadata::from_path(expected_directory)
            .map_err(|error| Error::IO(error, expected_directory.to_path_buf()))?;
        if after.file_type().is_symlink()
            || !after.is_dir()
            || !Self::sidecar_directory_binding_unchanged(&before, &after)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar directory changed during canonical validation",
                ),
                expected_directory.to_path_buf(),
            ));
        }
        Ok(Some((canonical_directory, after)))
    }
    fn canonical_sidecar_directory(
        &self,
        expected_directory: &Path,
    ) -> Result<Option<(PathBuf, SecureMetadata)>> {
        Self::canonical_sidecar_directory_for(&self.store_root, expected_directory)
    }
    fn stable_sidecar_directory_metadata(
        &self,
        expected_directory: &Path,
    ) -> Result<StableSidecarDirectoryMetadata> {
        let current = self.canonical_sidecar_directory(expected_directory)?;
        Ok(StableSidecarDirectoryMetadata {
            expected_path: expected_directory.to_path_buf(),
            canonical_path: current.as_ref().map(|(path, _)| path.clone()),
            metadata: current.map(|(_, metadata)| metadata),
        })
    }
    fn stable_sidecar_directory_inventory(
        &self,
        expected_directory: &Path,
    ) -> Result<StableSidecarDirectoryInventory> {
        self.stable_sidecar_directory_inventory_with_recognized_child(expected_directory, None)
    }
    fn stable_sidecar_directory_inventory_with_recognized_child(
        &self,
        expected_directory: &Path,
        recognized_child: Option<&Path>,
    ) -> Result<StableSidecarDirectoryInventory> {
        if recognized_child.is_some_and(|child| child.parent() != Some(expected_directory)) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "recognized startup replay child is not direct",
                ),
                expected_directory.to_path_buf(),
            ));
        }
        let before = self.stable_sidecar_directory_metadata(expected_directory)?;
        let mut files = BTreeMap::new();
        if before.metadata.is_some() {
            let entries = std::fs::read_dir(expected_directory)
                .map_err(|error| Error::IO(error, expected_directory.to_path_buf()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| Error::IO(error, expected_directory.to_path_buf()))?;
                let path = entry.path();
                if recognized_child == Some(path.as_path()) {
                    self.canonical_sidecar_directory(&path)?.ok_or_else(|| {
                        Error::IO(
                            std::io::Error::new(
                                ErrorKind::InvalidData,
                                "recognized startup replay child directory disappeared during identity capture",
                            ),
                            path.clone(),
                        )
                    })?;
                    continue;
                }
                let metadata = self
                    .regular_sidecar_metadata(&path, expected_directory)?
                    .ok_or_else(|| {
                        Error::IO(
                            std::io::Error::new(
                                ErrorKind::InvalidData,
                                "startup replay sidecar disappeared during identity capture",
                            ),
                            path.clone(),
                        )
                    })?;
                files.insert(path, metadata);
            }
        }
        let after = self.stable_sidecar_directory_metadata(expected_directory)?;
        if !Self::stable_sidecar_directory_metadata_unchanged(&before, &after) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "startup replay sidecar directory changed during identity capture",
                ),
                expected_directory.to_path_buf(),
            ));
        }
        Ok(StableSidecarDirectoryInventory {
            directory: after,
            files,
        })
    }
    fn startup_auxiliary_identity_error(&self, path: &Path, change: &str) -> Error {
        Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("startup replay sidecar identity changed: {change}"),
            ),
            path.to_path_buf(),
        )
    }
    fn require_startup_auxiliary_identity(
        expected: &StableSidecarDirectoryInventory,
        current: &StableSidecarDirectoryInventory,
    ) -> Result<()> {
        let error = |path: &Path, change: &str| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("startup replay sidecar identity changed: {change}"),
                ),
                path.to_path_buf(),
            )
        };
        for (path, metadata) in &expected.files {
            let found = current
                .files
                .get(path)
                .ok_or_else(|| error(path, "file removed"))?;
            if !Self::stable_sidecar_metadata_unchanged(metadata, found) {
                return Err(error(path, "file object or metadata changed"));
            }
        }
        if let Some(path) = current
            .files
            .keys()
            .find(|path| !expected.files.contains_key(*path))
        {
            return Err(error(path, "file added"));
        }
        if !Self::stable_sidecar_directory_metadata_unchanged(
            &expected.directory,
            &current.directory,
        ) {
            let change = match (&expected.directory.metadata, &current.directory.metadata) {
                (None, Some(_)) => "directory appeared",
                (Some(_), None) => "directory disappeared",
                _ => "directory object, path, or metadata changed",
            };
            return Err(error(&expected.directory.expected_path, change));
        }
        Ok(())
    }
    fn stable_sidecar_directory_inventory_unchanged(
        left: &StableSidecarDirectoryInventory,
        right: &StableSidecarDirectoryInventory,
    ) -> bool {
        Self::stable_sidecar_directory_metadata_unchanged(&left.directory, &right.directory)
            && left.files.len() == right.files.len()
            && left.files.iter().all(|(path, metadata)| {
                right.files.get(path).is_some_and(|current| {
                    Self::stable_sidecar_metadata_unchanged(metadata, current)
                })
            })
    }
    fn regular_sidecar_metadata_for(
        store_root: &Path,
        path: &Path,
        expected_directory: &Path,
    ) -> Result<Option<StableSidecarMetadata>> {
        if path.parent() != Some(expected_directory) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar path is not an immediate child of its expected directory",
                ),
                path.to_path_buf(),
            ));
        }
        let directory = Self::canonical_sidecar_directory_for(store_root, expected_directory)?;
        let metadata = match secure_file_metadata::from_path(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Error::IO(err, path.to_path_buf())),
        };
        let Some((canonical_directory, directory_metadata)) = directory else {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar exists without its expected direct directory",
                ),
                path.to_path_buf(),
            ));
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || !Self::sidecar_is_single_link(&metadata)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar path is not a single-link regular file",
                ),
                path.to_path_buf(),
            ));
        }
        let canonical_path =
            std::fs::canonicalize(path).map_err(|err| Error::IO(err, path.to_path_buf()))?;
        if canonical_path.parent() != Some(canonical_directory.as_path()) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar path escapes its canonical Kura directory",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(Some(StableSidecarMetadata {
            canonical_path,
            file: metadata,
            directory: directory_metadata,
        }))
    }
    fn regular_sidecar_metadata(
        &self,
        path: &Path,
        expected_directory: &Path,
    ) -> Result<Option<StableSidecarMetadata>> {
        Self::regular_sidecar_metadata_for(&self.store_root, path, expected_directory)
    }
    fn open_bound_progress_file(
        namespace: &BoundProgressNamespace,
        path: &Path,
        expected: &StableSidecarMetadata,
    ) -> Result<std::fs::File> {
        let immediate = namespace.directories.first().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "bound progress namespace has no immediate directory",
                ),
                path.to_path_buf(),
            )
        })?;
        if path.parent() != Some(immediate.expected_path.as_path()) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar file is outside its bound immediate directory",
                ),
                path.to_path_buf(),
            ));
        }
        let _file_name = path.file_name().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar file has no entry name",
                ),
                path.to_path_buf(),
            )
        })?;
        #[cfg(unix)]
        let file = std::fs::File::from(
            rustix::fs::openat(
                &immediate.file,
                _file_name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?,
        );
        #[cfg(not(unix))]
        let file = {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            options
                .open(path)
                .map_err(|error| Error::IO(error, path.to_path_buf()))?
        };
        let opened = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if !opened.is_file() || !Self::sidecar_file_metadata_unchanged(&expected.file, &opened) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar file changed while opening",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(file)
    }
    fn open_optional_bound_progress_file(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
    ) -> Result<Option<std::fs::File>> {
        let immediate = namespace.directories.first().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "bound progress namespace has no immediate directory",
                ),
                path.to_path_buf(),
            )
        })?;
        if path.parent() != Some(immediate.expected_path.as_path()) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar file is outside its bound immediate directory",
                ),
                path.to_path_buf(),
            ));
        }
        let Some(expected) =
            Self::regular_sidecar_metadata_for(&self.store_root, path, &immediate.expected_path)?
        else {
            if !Self::progress_mutation_namespace_unchanged(namespace) {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar namespace changed while proving an optional file absent",
                    ),
                    path.to_path_buf(),
                ));
            }
            return Ok(None);
        };
        if !Self::sidecar_metadata_same_object(&immediate.metadata, &expected.directory) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar directory changed while binding an optional file",
                ),
                path.to_path_buf(),
            ));
        }
        let file = Self::open_bound_progress_file(namespace, path, &expected)?;
        if !Self::progress_mutation_namespace_unchanged(namespace) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar namespace changed while binding an optional file",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(Some(file))
    }
    fn open_direct_sidecar_file_in_namespace(
        path: &Path,
        create: bool,
        append: bool,
        _namespace: Option<&BoundProgressNamespace>,
    ) -> std::io::Result<std::fs::File> {
        let before = match secure_file_metadata::from_path(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == ErrorKind::NotFound && create => None,
            Err(error) => return Err(error),
        };
        if before.as_ref().is_some_and(|metadata| {
            metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !Self::sidecar_is_single_link(metadata)
        }) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "sidecar path is not a direct single-link regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
            let parent_path = path.parent().ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "sidecar path has no parent")
            })?;
            let file_name = path.file_name().ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "sidecar path has no file name")
            })?;
            let owned_parent;
            let parent = if let Some(namespace) = _namespace {
                let immediate = namespace.directories.first().ok_or_else(|| {
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "bound sidecar namespace has no immediate directory",
                    )
                })?;
                if parent_path != immediate.expected_path {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "sidecar path is outside its bound namespace",
                    ));
                }
                let opened = immediate.file.metadata()?;
                let current = std::fs::symlink_metadata(parent_path)?;
                if !opened.is_dir()
                    || current.file_type().is_symlink()
                    || !current.is_dir()
                    || !Self::sidecar_metadata_same_object(&immediate.metadata, &opened)
                    || !Self::sidecar_metadata_same_object(&immediate.metadata, &current)
                {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "bound sidecar namespace changed before mutation",
                    ));
                }
                &immediate.file
            } else {
                let parent_before = std::fs::symlink_metadata(parent_path)?;
                if parent_before.file_type().is_symlink() || !parent_before.is_dir() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "sidecar parent is not a direct directory",
                    ));
                }
                let mut options = std::fs::OpenOptions::new();
                options.read(true).custom_flags(
                    (rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC)
                        .bits() as i32,
                );
                owned_parent = options.open(parent_path)?;
                let parent_opened = owned_parent.metadata()?;
                let parent_after = std::fs::symlink_metadata(parent_path)?;
                if !parent_opened.is_dir()
                    || parent_after.file_type().is_symlink()
                    || !parent_after.is_dir()
                    || !Self::sidecar_metadata_same_object(&parent_before, &parent_opened)
                    || !Self::sidecar_metadata_same_object(&parent_before, &parent_after)
                {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "sidecar parent changed while binding it",
                    ));
                }
                &owned_parent
            };
            let mut flags = rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            if create {
                flags |= rustix::fs::OFlags::CREATE;
            }
            if append {
                flags |= rustix::fs::OFlags::APPEND;
            }
            let file = std::fs::File::from(
                rustix::fs::openat(
                    parent,
                    file_name,
                    flags,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map_err(std::io::Error::from)?,
            );
            let opened = file.metadata()?;
            let after =
                rustix::fs::statat(parent, file_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(std::io::Error::from)?;
            if !opened.is_file()
                || !Self::sidecar_is_single_link(&opened)
                || after.st_dev as u64 != opened.dev()
                || after.st_ino as u64 != opened.ino()
                || after.st_nlink as u64 != 1
                || before
                    .as_ref()
                    .is_some_and(|metadata| !Self::sidecar_metadata_same_object(metadata, &opened))
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar path identity changed while opening",
                ));
            }
            return Ok(file);
        }
        #[cfg(not(unix))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(create).append(append);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = options.open(path)?;
            let opened = secure_file_metadata::from_file(&file)?;
            let after = secure_file_metadata::from_path(path)?;
            if !opened.is_file()
                || after.file_type().is_symlink()
                || !after.is_file()
                || !Self::sidecar_is_single_link(&opened)
                || !Self::sidecar_is_single_link(&after)
                || !Self::sidecar_metadata_same_object(&opened, &after)
                || before
                    .as_ref()
                    .is_some_and(|metadata| !Self::sidecar_metadata_same_object(metadata, &opened))
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar path identity changed while opening",
                ));
            }
            Ok(file)
        }
    }
    fn remove_bound_progress_temp_if_present(
        namespace: &BoundProgressNamespace,
        path: &Path,
    ) -> std::io::Result<()> {
        let immediate = namespace.directories.first().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "bound progress namespace has no immediate directory",
            )
        })?;
        if path.parent() != Some(immediate.expected_path.as_path()) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "progress temp is outside its bound namespace",
            ));
        }
        let _name = path.file_name().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "progress temp has no entry name")
        })?;
        #[cfg(unix)]
        {
            let entry = match rustix::fs::statat(
                &immediate.file,
                _name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(entry) => entry,
                Err(rustix::io::Errno::NOENT) => return Ok(()),
                Err(error) => return Err(std::io::Error::from(error)),
            };
            if rustix::fs::FileType::from_raw_mode(entry.st_mode)
                != rustix::fs::FileType::RegularFile
                || entry.st_nlink as u64 != 1
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress temp is not a direct single-link regular file",
                ));
            }
            rustix::fs::unlinkat(&immediate.file, _name, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            match secure_file_metadata::from_path(path) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && Self::sidecar_is_single_link(&metadata) =>
                {
                    std::fs::remove_file(path)
                }
                Ok(_) => Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress temp is not a direct single-link regular file",
                )),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }
    fn remove_bound_progress_file_if_matches(
        namespace: &BoundProgressNamespace,
        path: &Path,
        expected: &std::fs::File,
        expected_snapshot: &StableSidecarMetadata,
    ) -> std::io::Result<()> {
        let immediate = namespace.directories.first().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "bound progress namespace has no immediate directory",
            )
        })?;
        if path.parent() != Some(immediate.expected_path.as_path()) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "progress file is outside its bound namespace",
            ));
        }
        let _name = path.file_name().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "progress file has no entry name")
        })?;
        let expected_metadata = secure_file_metadata::from_file(expected)?;
        if !Self::sidecar_file_metadata_unchanged(&expected_snapshot.file, &expected_metadata) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "progress file changed after exact-object verification",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let entry = rustix::fs::statat(
                &immediate.file,
                _name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)?;
            if rustix::fs::FileType::from_raw_mode(entry.st_mode)
                != rustix::fs::FileType::RegularFile
                || expected_metadata.nlink() != 1
                || entry.st_dev as u64 != expected_snapshot.file.dev()
                || entry.st_ino as u64 != expected_snapshot.file.ino()
                || entry.st_nlink as u64 != 1
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress file changed before exact-object removal",
                ));
            }
            rustix::fs::unlinkat(&immediate.file, _name, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let current = secure_file_metadata::from_path(path)?;
            if current.file_type().is_symlink()
                || !current.is_file()
                || !Self::sidecar_is_single_link(&current)
                || !Self::sidecar_file_metadata_unchanged(&expected_snapshot.file, &current)
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress file changed before exact-object removal",
                ));
            }
            std::fs::remove_file(path)
        }
    }
    fn create_new_bound_progress_temp(
        namespace: &BoundProgressNamespace,
        path: &Path,
    ) -> std::io::Result<std::fs::File> {
        let immediate = namespace.directories.first().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                "bound progress namespace has no immediate directory",
            )
        })?;
        if path.parent() != Some(immediate.expected_path.as_path()) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "progress temp is outside its bound namespace",
            ));
        }
        let _name = path.file_name().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "progress temp has no entry name")
        })?;
        #[cfg(unix)]
        {
            let file = std::fs::File::from(
                rustix::fs::openat(
                    &immediate.file,
                    _name,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map_err(std::io::Error::from)?,
            );
            let metadata = secure_file_metadata::from_file(&file)?;
            let entry = rustix::fs::statat(
                &immediate.file,
                _name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)?;
            use std::os::unix::fs::MetadataExt as _;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || entry.st_dev as u64 != metadata.dev()
                || entry.st_ino as u64 != metadata.ino()
                || entry.st_nlink as u64 != 1
            {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress temp identity changed during exclusive creation",
                ));
            }
            return Ok(file);
        }
        #[cfg(not(unix))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = options.open(path)?;
            let metadata = secure_file_metadata::from_file(&file)?;
            if !metadata.is_file() || !Self::sidecar_is_single_link(&metadata) {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress temp is not a direct single-link regular file",
                ));
            }
            Ok(file)
        }
    }
    fn promote_bound_progress_temp(
        namespace: &BoundProgressNamespace,
        temp_path: &Path,
        main_path: &Path,
        temp: &std::fs::File,
    ) -> std::result::Result<(), BoundProgressPromotionError> {
        let unpublished = |source| BoundProgressPromotionError {
            published: false,
            source,
        };
        let _published = |source| BoundProgressPromotionError {
            published: true,
            source,
        };
        let immediate = namespace
            .directories
            .first()
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "bound progress namespace has no immediate directory",
                )
            })
            .map_err(unpublished)?;
        if temp_path.parent() != Some(immediate.expected_path.as_path())
            || main_path.parent() != Some(immediate.expected_path.as_path())
        {
            return Err(unpublished(std::io::Error::new(
                ErrorKind::InvalidInput,
                "progress promotion escapes its bound namespace",
            )));
        }
        let _temp_name = temp_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "progress temp has no entry name")
            })
            .map_err(unpublished)?;
        let _main_name = main_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "progress index has no entry name")
            })
            .map_err(unpublished)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = temp.metadata().map_err(unpublished)?;
            let before = rustix::fs::statat(
                &immediate.file,
                _temp_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)
            .map_err(unpublished)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || before.st_dev as u64 != metadata.dev()
                || before.st_ino as u64 != metadata.ino()
                || before.st_nlink as u64 != 1
            {
                return Err(unpublished(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress temp changed before promotion",
                )));
            }
            rustix::fs::renameat(&immediate.file, _temp_name, &immediate.file, _main_name)
                .map_err(std::io::Error::from)
                .map_err(unpublished)?;
            let after = rustix::fs::statat(
                &immediate.file,
                _main_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)
            .map_err(_published)?;
            if after.st_dev as u64 != metadata.dev()
                || after.st_ino as u64 != metadata.ino()
                || after.st_nlink as u64 != 1
            {
                return Err(_published(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "promoted progress index has the wrong identity",
                )));
            }
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let _ = (namespace, temp_path, main_path, temp);
            Err(BoundProgressPromotionError {
                published: false,
                source: std::io::Error::new(
                    ErrorKind::Unsupported,
                    "descriptor-relative progress prepend promotion is unsupported on this platform",
                ),
            })
        }
    }
    fn bound_progress_append_build_path(index_path: &Path) -> PathBuf {
        index_path.with_extension("index.append.build.tmp")
    }
    fn bound_progress_append_intent_path(index_path: &Path) -> PathBuf {
        index_path.with_extension("index.append.intent.tmp")
    }
    fn sync_bound_progress_intent_directories(
        namespace: &BoundProgressNamespace,
    ) -> std::io::Result<()> {
        #[cfg(test)]
        let fail_at = FAIL_BOUND_PROGRESS_INTENT_DIRECTORY_SYNC.with(|slot| {
            let Some(mut fault) = slot.get() else {
                return None;
            };
            if fault.calls_before_failure > 0 {
                fault.calls_before_failure -= 1;
                slot.set(Some(fault));
                None
            } else {
                Some(fault.target_index)
            }
        });
        #[cfg(not(test))]
        let fail_at: Option<usize> = None;
        for (position, directory) in namespace.directories.iter().enumerate() {
            if fail_at == Some(position) {
                #[cfg(test)]
                FAIL_BOUND_PROGRESS_INTENT_DIRECTORY_SYNC.with(|slot| slot.set(None));
                return Err(std::io::Error::other(
                    "injected bound progress append-intent directory sync failure",
                ));
            }
            directory.file.sync_all()?;
        }
        Ok(())
    }
    fn promote_bound_progress_temp_noreplace(
        namespace: &BoundProgressNamespace,
        temp_path: &Path,
        intent_path: &Path,
        temp: &std::fs::File,
    ) -> std::result::Result<(), BoundProgressPromotionError> {
        let unpublished = |source| BoundProgressPromotionError {
            published: false,
            source,
        };
        let _published = |source| BoundProgressPromotionError {
            published: true,
            source,
        };
        let immediate = namespace
            .directories
            .first()
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "bound progress namespace has no immediate directory",
                )
            })
            .map_err(unpublished)?;
        if temp_path.parent() != Some(immediate.expected_path.as_path())
            || intent_path.parent() != Some(immediate.expected_path.as_path())
        {
            return Err(unpublished(std::io::Error::new(
                ErrorKind::InvalidInput,
                "progress append-intent promotion escapes its bound namespace",
            )));
        }
        let _temp_name = temp_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "progress build has no entry name")
            })
            .map_err(unpublished)?;
        let _intent_name = intent_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "progress intent has no entry name")
            })
            .map_err(unpublished)?;
        #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = temp.metadata().map_err(unpublished)?;
            let before = rustix::fs::statat(
                &immediate.file,
                _temp_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)
            .map_err(unpublished)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || before.st_dev as u64 != metadata.dev()
                || before.st_ino as u64 != metadata.ino()
                || before.st_nlink as u64 != 1
            {
                return Err(unpublished(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress append-intent build changed before promotion",
                )));
            }
            rustix::fs::renameat_with(
                &immediate.file,
                _temp_name,
                &immediate.file,
                _intent_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)
            .map_err(unpublished)?;
            let after = rustix::fs::statat(
                &immediate.file,
                _intent_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)
            .map_err(_published)?;
            if after.st_dev as u64 != metadata.dev()
                || after.st_ino as u64 != metadata.ino()
                || after.st_nlink as u64 != 1
            {
                return Err(_published(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "published progress append intent has the wrong identity",
                )));
            }
            return Ok(());
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
        {
            let _ = (namespace, temp_path, intent_path, temp);
            Err(BoundProgressPromotionError {
                published: false,
                source: std::io::Error::new(
                    ErrorKind::Unsupported,
                    "atomic descriptor-relative append-intent publication is unsupported on this platform",
                ),
            })
        }
    }
    fn publish_bound_progress_append_intent(
        namespace: &BoundProgressNamespace,
        index_path: &Path,
        intent: &BoundProgressAppendIntentV1,
        kind: &str,
    ) -> Option<std::fs::File> {
        let build_path = Self::bound_progress_append_build_path(index_path);
        let intent_path = Self::bound_progress_append_intent_path(index_path);
        let bytes = match norito::encode_canonical(intent) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= intent.encoded_byte_limit() => bytes,
            Ok(bytes) => {
                warn!(
                    len = bytes.len(),
                    ?intent_path,
                    kind,
                    "bound progress append intent exceeds its hard byte limit"
                );
                return None;
            }
            Err(error) => {
                warn!(
                    ?error,
                    ?intent_path,
                    kind,
                    "failed to encode progress append intent"
                );
                return None;
            }
        };
        let mut build = match Self::create_new_bound_progress_temp(namespace, &build_path) {
            Ok(build) => build,
            Err(error) => {
                warn!(
                    ?error,
                    ?build_path,
                    kind,
                    "failed to create progress append-intent build"
                );
                return None;
            }
        };
        if let Err(error) = build
            .write_all(&bytes)
            .and_then(|_| build.flush())
            .and_then(|_| sync_bound_progress_intent_file(&build))
        {
            warn!(
                ?error,
                ?build_path,
                kind,
                "failed to persist progress append-intent build"
            );
            drop(build);
            let _ = Self::remove_bound_progress_temp_if_present(namespace, &build_path);
            let _ = Self::sync_bound_progress_intent_directories(namespace);
            return None;
        }
        #[cfg(test)]
        if should_fail_after_bound_progress_append_build_for_tests() {
            return None;
        }
        if let Err(error) = Self::promote_bound_progress_temp_noreplace(
            namespace,
            &build_path,
            &intent_path,
            &build,
        ) {
            warn!(
                source = ?error.source,
                published = error.published,
                ?build_path,
                ?intent_path,
                kind,
                "failed to publish progress append intent"
            );
            drop(build);
            if !error.published {
                let _ = Self::remove_bound_progress_temp_if_present(namespace, &build_path);
                let _ = Self::sync_bound_progress_intent_directories(namespace);
            }
            return None;
        }
        if let Err(error) = Self::sync_bound_progress_intent_directories(namespace) {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to sync progress append-intent publication"
            );
            return None;
        }
        Some(build)
    }
    fn open_bound_progress_directory(
        store_root: &Path,
        expected_path: &Path,
    ) -> Result<BoundProgressDirectory> {
        let (canonical_path, metadata) =
            Self::canonical_sidecar_directory_for(store_root, expected_path)?.ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::NotFound,
                        "progress sidecar directory disappeared while binding it",
                    ),
                    expected_path.to_path_buf(),
                )
            })?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
        }
        let file = options
            .open(expected_path)
            .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
        let opened = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
        let after = Self::canonical_sidecar_directory_for(store_root, expected_path)?;
        if !opened.is_dir()
            || !Self::sidecar_directory_binding_unchanged(&metadata, &opened)
            || !after.as_ref().is_some_and(|(after_path, after_metadata)| {
                *after_path == canonical_path
                    && Self::sidecar_directory_binding_unchanged(&metadata, after_metadata)
            })
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar directory changed while opening",
                ),
                expected_path.to_path_buf(),
            ));
        }
        Ok(BoundProgressDirectory {
            expected_path: expected_path.to_path_buf(),
            canonical_path,
            entry_name: None,
            file,
            metadata,
        })
    }
    /// Return whether a progress pair's immediate directory is durably absent
    /// beneath an unchanged canonical parent.
    ///
    /// Non-owning validators legitimately have no committee-private lane
    /// artifact directory. Read-only consumers must interpret that cold-start
    /// state as an empty namespace without weakening the no-follow checks used
    /// once the namespace exists. A missing, replaced, symlinked, or mutated
    /// parent remains an error.
    fn bound_progress_sidecar_directory_is_absent(
        &self,
        data_path: &Path,
        index_path: &Path,
    ) -> Result<bool> {
        let sidecar_dir = data_path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar data path has no parent",
                ),
                data_path.to_path_buf(),
            )
        })?;
        if index_path.parent() != Some(sidecar_dir) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar files do not share one parent directory",
                ),
                index_path.to_path_buf(),
            ));
        }
        let parent = sidecar_dir.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar directory has no parent",
                ),
                sidecar_dir.to_path_buf(),
            )
        })?;
        let bound_parent = Self::open_bound_progress_directory(&self.store_root, parent)?;
        let observed = Self::canonical_sidecar_directory_for(&self.store_root, sidecar_dir)?;
        let opened_parent = secure_file_metadata::from_file(&bound_parent.file)
            .map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        let (current_parent_path, current_parent) =
            Self::canonical_sidecar_directory_for(&self.store_root, parent)?.ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar parent disappeared while attesting an empty namespace",
                    ),
                    parent.to_path_buf(),
                )
            })?;
        if current_parent_path != bound_parent.canonical_path
            || !Self::sidecar_directory_metadata_unchanged(&bound_parent.metadata, &opened_parent)
            || !Self::sidecar_directory_metadata_unchanged(&bound_parent.metadata, &current_parent)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar parent changed while attesting an empty namespace",
                ),
                parent.to_path_buf(),
            ));
        }
        Ok(observed.is_none())
    }
    fn open_bound_progress_child_directory(
        store_root: &Path,
        parent: &BoundProgressDirectory,
        expected_path: &Path,
    ) -> Result<BoundProgressDirectory> {
        #[cfg(unix)]
        let _ = store_root;
        if expected_path.parent() != Some(parent.expected_path.as_path()) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar directory is not a direct child of its bound parent",
                ),
                expected_path.to_path_buf(),
            ));
        }
        let name = expected_path.file_name().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar child directory has no entry name",
                ),
                expected_path.to_path_buf(),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let before =
                rustix::fs::statat(&parent.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(std::io::Error::from)
                    .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
            if rustix::fs::FileType::from_raw_mode(before.st_mode)
                != rustix::fs::FileType::Directory
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar path component is not a direct directory",
                    ),
                    expected_path.to_path_buf(),
                ));
            }
            let file = std::fs::File::from(
                rustix::fs::openat(
                    &parent.file,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(std::io::Error::from)
                .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?,
            );
            let metadata = secure_file_metadata::from_file(&file)
                .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
            let after =
                rustix::fs::statat(&parent.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(std::io::Error::from)
                    .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
            let canonical_path = parent.canonical_path.join(name);
            let canonical_after = std::fs::canonicalize(expected_path)
                .map_err(|error| Error::IO(error, expected_path.to_path_buf()))?;
            if !metadata.is_dir()
                || before.st_dev as u64 != metadata.dev()
                || before.st_ino as u64 != metadata.ino()
                || after.st_dev as u64 != metadata.dev()
                || after.st_ino as u64 != metadata.ino()
                || canonical_after != canonical_path
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar directory changed during descriptor-relative binding",
                    ),
                    expected_path.to_path_buf(),
                ));
            }
            return Ok(BoundProgressDirectory {
                expected_path: expected_path.to_path_buf(),
                canonical_path,
                entry_name: Some(name.to_os_string()),
                file,
                metadata,
            });
        }
        #[cfg(not(unix))]
        {
            let mut child = Self::open_bound_progress_directory(store_root, expected_path)?;
            child.entry_name = Some(name.to_os_string());
            Ok(child)
        }
    }
    fn open_bound_progress_namespace(
        &self,
        data_path: &Path,
        index_path: &Path,
    ) -> Result<BoundProgressNamespace> {
        let sidecar_dir = data_path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar data path has no parent",
                ),
                data_path.to_path_buf(),
            )
        })?;
        if index_path.parent() != Some(sidecar_dir) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "progress sidecar files do not share one parent directory",
                ),
                index_path.to_path_buf(),
            ));
        }
        let mut directory_paths = vec![sidecar_dir.to_path_buf()];
        let mut ancestor = sidecar_dir;
        loop {
            if ancestor == self.store_root {
                break;
            }
            ancestor = ancestor.parent().ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar durability chain did not reach the Kura root",
                    ),
                    ancestor.to_path_buf(),
                )
            })?;
            directory_paths.push(ancestor.to_path_buf());
        }
        directory_paths.reverse();
        let Some(root_path) = directory_paths.first() else {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar durability chain is empty",
                ),
                sidecar_dir.to_path_buf(),
            ));
        };
        let root = Self::open_bound_progress_directory(&self.store_root, root_path)?;
        let mut directories = Vec::with_capacity(directory_paths.len());
        directories.push(root);
        for path in directory_paths.iter().skip(1) {
            let parent = directories
                .last()
                .expect("bound progress directory chain starts at Kura root");
            let child = Self::open_bound_progress_child_directory(&self.store_root, parent, path)?;
            directories.push(child);
        }
        directories.reverse();
        let namespace = BoundProgressNamespace {
            data_path: data_path.to_path_buf(),
            index_path: index_path.to_path_buf(),
            directories,
        };
        if !self.bound_progress_namespace_unchanged(&namespace) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar namespace changed while binding durability handles",
                ),
                sidecar_dir.to_path_buf(),
            ));
        }
        Ok(namespace)
    }
    fn open_bound_progress_pair(
        &self,
        data_path: &Path,
        index_path: &Path,
    ) -> Result<BoundProgressPair> {
        let namespace = self.open_bound_progress_namespace(data_path, index_path)?;
        self.open_bound_progress_pair_in_namespace(namespace)
    }
    /// Bind an exact pair without reopening its already held directory chain.
    fn open_bound_progress_pair_in_namespace(
        &self,
        namespace: BoundProgressNamespace,
    ) -> Result<BoundProgressPair> {
        let data_path_owned = namespace.data_path.clone();
        let index_path_owned = namespace.index_path.clone();
        let data_path = data_path_owned.as_path();
        let index_path = index_path_owned.as_path();
        if !self.bound_progress_namespace_unchanged(&namespace) {
            return Err(Self::invalid_lane_artifact_error(
                data_path.to_path_buf(),
                "progress namespace changed before opening its exact pair",
            ));
        }
        let sidecar_dir = namespace
            .data_path
            .parent()
            .expect("bound progress namespace always has an immediate parent");
        let data_metadata =
            Self::regular_sidecar_metadata_for(&self.store_root, data_path, sidecar_dir)?;
        let index_metadata =
            Self::regular_sidecar_metadata_for(&self.store_root, index_path, sidecar_dir)?;
        let (data_metadata, index_metadata) = match (data_metadata, index_metadata) {
            (None, None) => {
                if !self.bound_progress_namespace_unchanged(&namespace) {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "progress sidecar namespace changed while attesting absence",
                        ),
                        sidecar_dir.to_path_buf(),
                    ));
                }
                return Ok(BoundProgressPair::Absent(namespace));
            }
            (Some(data), Some(index)) => (data, index),
            _ => {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "progress sidecar data and index are only partially present",
                    ),
                    sidecar_dir.to_path_buf(),
                ));
            }
        };
        let data = Self::open_bound_progress_file(&namespace, data_path, &data_metadata)?;
        let index = Self::open_bound_progress_file(&namespace, index_path, &index_metadata)?;
        let bound = BoundProgressSidecar {
            namespace,
            data,
            index,
            data_metadata,
            index_metadata,
        };
        if !self.bound_progress_sidecar_unchanged(&bound) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar identity changed while binding its durability handles",
                ),
                data_path.to_path_buf(),
            ));
        }
        Ok(BoundProgressPair::Present(bound))
    }
    fn bound_progress_pair_namespace(pair: &BoundProgressPair) -> &BoundProgressNamespace {
        match pair {
            BoundProgressPair::Absent(namespace) => namespace,
            BoundProgressPair::Present(bound) => &bound.namespace,
        }
    }
    #[cfg(all(test, unix))]
    fn open_bound_progress_sidecar(
        &self,
        data_path: &Path,
        index_path: &Path,
    ) -> Result<BoundProgressSidecar> {
        match self.open_bound_progress_pair(data_path, index_path)? {
            BoundProgressPair::Present(bound) => Ok(bound),
            BoundProgressPair::Absent(namespace) => Err(Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "progress sidecar pair is absent"),
                namespace.data_path,
            )),
        }
    }
    fn bound_progress_namespace_unchanged(&self, namespace: &BoundProgressNamespace) -> bool {
        namespace
            .directories
            .iter()
            .enumerate()
            .all(|(_index, directory)| {
                let Ok(opened) = secure_file_metadata::from_file(&directory.file) else {
                    return false;
                };
                if !opened.is_dir()
                    || !Self::sidecar_directory_binding_unchanged(&directory.metadata, &opened)
                {
                    return false;
                }
                #[cfg(unix)]
                if let Some(name) = directory.entry_name.as_deref() {
                    use std::os::unix::fs::MetadataExt as _;
                    let Some(parent) = namespace.directories.get(_index.saturating_add(1)) else {
                        return false;
                    };
                    if directory.expected_path.parent() != Some(parent.expected_path.as_path())
                        || directory.expected_path.file_name() != Some(name)
                        || directory.canonical_path != parent.canonical_path.join(name)
                    {
                        return false;
                    }
                    let Ok(entry) = rustix::fs::statat(
                        &parent.file,
                        name,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    ) else {
                        return false;
                    };
                    // Every ancestor is checked by this same traversal. The
                    // terminal root (or standalone directory) below retains
                    // its full canonical path binding. A fresh no-follow link
                    // to that bound parent proves this child's path identity
                    // without resolving the whole root-to-child path again.
                    return rustix::fs::FileType::from_raw_mode(entry.st_mode)
                        == rustix::fs::FileType::Directory
                        && entry.st_dev as u64 == opened.dev()
                        && entry.st_ino as u64 == opened.ino();
                }
                Self::canonical_sidecar_directory_for(&self.store_root, &directory.expected_path)
                    .ok()
                    .flatten()
                    .is_some_and(|(canonical_path, metadata)| {
                        let path_matches = Self::sidecar_directory_binding_unchanged(
                            &directory.metadata,
                            &metadata,
                        );
                        canonical_path == directory.canonical_path && path_matches
                    })
            })
    }
    /// Revalidate one exact child through its already authenticated parent handle.
    ///
    /// The no-op production observer is a test seam after the no-follow lookup,
    /// before fresh descriptor metadata detects concurrent file writes.
    #[cfg(unix)]
    fn bound_progress_file_unchanged<F>(
        directory: &BoundProgressDirectory,
        path: &Path,
        expected: &StableSidecarMetadata,
        file: &std::fs::File,
        after_lookup: F,
    ) -> bool
    where
        F: FnOnce(),
    {
        use std::os::unix::fs::MetadataExt as _;
        let Some(name) = path.file_name() else {
            return false;
        };
        if path.parent() != Some(directory.expected_path.as_path())
            || expected.canonical_path != directory.canonical_path.join(name)
        {
            return false;
        }
        let Ok(entry) =
            rustix::fs::statat(&directory.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        else {
            return false;
        };
        if rustix::fs::FileType::from_raw_mode(entry.st_mode) != rustix::fs::FileType::RegularFile
            || entry.st_nlink as u64 != 1
        {
            return false;
        }
        after_lookup();
        let Ok(opened) = secure_file_metadata::from_file(file) else {
            return false;
        };
        opened.is_file()
            && Self::sidecar_file_metadata_unchanged(&expected.file, &opened)
            && entry.st_dev as u64 == opened.dev()
            && entry.st_ino as u64 == opened.ino()
    }

    /// Retain the strong present-pair snapshot checks without repeated full-path resolution.
    #[cfg(unix)]
    fn bound_progress_sidecar_unchanged_with_observer<F>(
        &self,
        bound: &BoundProgressSidecar,
        mut after_lookup: F,
    ) -> bool
    where
        F: FnMut(usize),
    {
        if !self.bound_progress_namespace_unchanged(&bound.namespace) {
            return false;
        }
        let Some(directory) = bound.namespace.directories.first() else {
            return false;
        };
        let Ok(before) = secure_file_metadata::from_file(&directory.file) else {
            return false;
        };
        // Namespace binding permits sibling publications. This pair snapshot
        // intentionally retains the stronger directory timestamp contract.
        let directory_matches = |current: &SecureMetadata| {
            current.is_dir()
                && Self::sidecar_directory_metadata_unchanged(
                    &bound.data_metadata.directory,
                    current,
                )
                && Self::sidecar_directory_metadata_unchanged(
                    &bound.index_metadata.directory,
                    current,
                )
        };
        if !directory_matches(&before) {
            return false;
        }
        for (ordinal, (path, expected, file)) in [
            (
                &bound.namespace.data_path,
                &bound.data_metadata,
                &bound.data,
            ),
            (
                &bound.namespace.index_path,
                &bound.index_metadata,
                &bound.index,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            if !Self::bound_progress_file_unchanged(directory, path, expected, file, || {
                after_lookup(ordinal);
            }) {
                return false;
            }
        }
        let Ok(after) = secure_file_metadata::from_file(&directory.file) else {
            return false;
        };
        directory_matches(&after)
            && Self::sidecar_directory_metadata_unchanged(&before, &after)
            && self.bound_progress_namespace_unchanged(&bound.namespace)
    }
    fn bound_progress_sidecar_unchanged(&self, bound: &BoundProgressSidecar) -> bool {
        #[cfg(unix)]
        {
            self.bound_progress_sidecar_unchanged_with_observer(bound, |_| {})
        }
        #[cfg(not(unix))]
        {
            let Some(sidecar_dir) = bound.namespace.data_path.parent() else {
                return false;
            };
            if bound.namespace.index_path.parent() != Some(sidecar_dir) {
                return false;
            }
            let Ok(data_opened) = secure_file_metadata::from_file(&bound.data) else {
                return false;
            };
            let Ok(index_opened) = secure_file_metadata::from_file(&bound.index) else {
                return false;
            };
            if !Self::sidecar_file_metadata_unchanged(&bound.data_metadata.file, &data_opened)
                || !Self::sidecar_file_metadata_unchanged(&bound.index_metadata.file, &index_opened)
            {
                return false;
            }
            let Ok(data_after) = Self::regular_sidecar_metadata_for(
                &self.store_root,
                &bound.namespace.data_path,
                sidecar_dir,
            ) else {
                return false;
            };
            let Ok(index_after) = Self::regular_sidecar_metadata_for(
                &self.store_root,
                &bound.namespace.index_path,
                sidecar_dir,
            ) else {
                return false;
            };
            if !data_after.as_ref().is_some_and(|after| {
                Self::stable_sidecar_metadata_unchanged(&bound.data_metadata, after)
            }) || !index_after.as_ref().is_some_and(|after| {
                Self::stable_sidecar_metadata_unchanged(&bound.index_metadata, after)
            }) {
                return false;
            }
            self.bound_progress_namespace_unchanged(&bound.namespace)
        }
    }
    fn sync_bound_progress_namespace(
        &self,
        namespace: &BoundProgressNamespace,
        kind: &str,
    ) -> bool {
        if self.emergency_fast_startup_enabled() {
            return false;
        }
        for (index, directory) in namespace.directories.iter().enumerate() {
            let result = if index == 0 {
                sync_indexed_sidecar_dir_handle(&directory.file)
            } else {
                sync_progress_sidecar_ancestor_dir_handle(&directory.file)
            };
            if let Err(err) = result {
                iroha_logger::warn!(
                    ?err,
                    path = ?directory.expected_path,
                    kind,
                    "failed to sync bound progress sidecar namespace"
                );
                return false;
            }
        }
        self.bound_progress_namespace_unchanged(namespace)
    }
    fn sync_bound_progress_absence(&self, namespace: &BoundProgressNamespace, kind: &str) -> bool {
        if !self.sync_bound_progress_namespace(namespace, kind) {
            return false;
        }
        let Some(sidecar_dir) = namespace.data_path.parent() else {
            return false;
        };
        if namespace.index_path.parent() != Some(sidecar_dir) {
            return false;
        }
        matches!(
            Self::regular_sidecar_metadata_for(&self.store_root, &namespace.data_path, sidecar_dir,),
            Ok(None)
        ) && matches!(
            Self::regular_sidecar_metadata_for(
                &self.store_root,
                &namespace.index_path,
                sidecar_dir,
            ),
            Ok(None)
        ) && self.bound_progress_namespace_unchanged(namespace)
    }
    fn sync_bound_progress_sidecar(&self, bound: &BoundProgressSidecar, kind: &str) -> bool {
        if self.emergency_fast_startup_enabled() {
            return false;
        }
        if let Err(err) = sync_indexed_sidecar_data(&bound.data) {
            iroha_logger::warn!(?err, path = ?bound.namespace.data_path, kind, "failed to sync progress sidecar payload");
            return false;
        }
        if let Err(err) = sync_indexed_sidecar_index(&bound.index) {
            iroha_logger::warn!(?err, path = ?bound.namespace.index_path, kind, "failed to sync progress sidecar index");
            return false;
        }
        self.sync_bound_progress_namespace(&bound.namespace, kind)
            && self.bound_progress_sidecar_unchanged(bound)
    }
    fn bound_indexed_sidecar_payload_heights(
        &self,
        bound: &mut BoundProgressSidecar,
        kind: &str,
        limit: usize,
    ) -> Result<BTreeSet<u64>> {
        if !self.bound_progress_sidecar_unchanged(bound) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar identity changed before index enumeration",
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        let index_len = bound
            .index
            .metadata()
            .map_err(|error| Error::IO(error, bound.namespace.index_path.clone()))?
            .len();
        let layout =
            SidecarIndexLayout::read_from(&mut bound.index, index_len).map_err(|reason| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("{kind} index is malformed: {reason}"),
                    ),
                    bound.namespace.index_path.clone(),
                )
            })?;
        if layout.aligned_len != index_len
            || usize::try_from(layout.entry_count).unwrap_or(usize::MAX) > limit
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{kind} index is misaligned or exceeds its bounded entry count"),
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        let data_len = bound
            .data
            .metadata()
            .map_err(|error| Error::IO(error, bound.namespace.data_path.clone()))?
            .len();
        bound
            .index
            .seek(SeekFrom::Start(layout.entries_offset))
            .map_err(|error| Error::IO(error, bound.namespace.index_path.clone()))?;
        let mut heights = BTreeSet::new();
        let mut indexed_end = 0_u64;
        let mut encoded = [0_u8; PIPELINE_INDEX_ENTRY_SIZE];
        for offset in 0..layout.entry_count {
            bound
                .index
                .read_exact(&mut encoded)
                .map_err(|error| Error::IO(error, bound.namespace.index_path.clone()))?;
            let entry = SidecarIndexEntry::from_bytes(encoded);
            if entry.len == 0 {
                continue;
            }
            if entry.len > STRICT_INIT_MAX_BLOCK_BYTES
                || entry
                    .offset
                    .checked_add(entry.len)
                    .is_none_or(|end| end > data_len)
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("{kind} index contains an invalid payload range"),
                    ),
                    bound.namespace.index_path.clone(),
                ));
            }
            indexed_end = indexed_end.max(
                entry
                    .offset
                    .checked_add(entry.len)
                    .expect("validated sidecar range cannot overflow"),
            );
            let height = layout.base_height.checked_add(offset).ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("{kind} index height overflows"),
                    ),
                    bound.namespace.index_path.clone(),
                )
            })?;
            heights.insert(height);
        }
        if data_len != indexed_end {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{kind} data has an unindexed suffix and requires writer recovery"),
                ),
                bound.namespace.data_path.clone(),
            ));
        }
        if !self.bound_progress_sidecar_unchanged(bound) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar identity changed during index enumeration",
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        Ok(heights)
    }
    fn bound_indexed_sidecar_height_range(
        &self,
        bound: &mut BoundProgressSidecar,
        kind: &str,
    ) -> Result<Option<core::ops::RangeInclusive<u64>>> {
        if !self.bound_progress_sidecar_unchanged(bound) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar identity changed before range enumeration",
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        let index_len = bound
            .index
            .metadata()
            .map_err(|error| Error::IO(error, bound.namespace.index_path.clone()))?
            .len();
        let layout =
            SidecarIndexLayout::read_from(&mut bound.index, index_len).map_err(|reason| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("{kind} index is malformed: {reason}"),
                    ),
                    bound.namespace.index_path.clone(),
                )
            })?;
        if layout.aligned_len != index_len {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{kind} index has trailing or partial bytes"),
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        if !self.bound_progress_sidecar_unchanged(bound) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "progress sidecar identity changed during range enumeration",
                ),
                bound.namespace.index_path.clone(),
            ));
        }
        Ok(layout.height_range())
    }
    fn read_regular_sidecar_bytes_for(
        store_root: &Path,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(Self::read_regular_sidecar_snapshot_for(
            store_root,
            path,
            expected_directory,
            byte_limit,
        )?
        .map(|snapshot| snapshot.bytes))
    }
    fn read_regular_sidecar_snapshot_for(
        store_root: &Path,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
    ) -> Result<Option<StableSidecarRead<Vec<u8>>>> {
        Self::read_regular_sidecar_snapshot_for_with_admission_hook(
            store_root,
            path,
            expected_directory,
            byte_limit,
            || {},
        )
    }
    /// Perform one stable, no-follow bounded read after invoking a post-admission hook.
    ///
    /// Production passes a no-op hook. Tests use the seam to grow a file after
    /// its capped metadata has been admitted, proving that the reader allocates
    /// only the admitted length and rejects the max-plus-one race.
    fn read_regular_sidecar_snapshot_for_with_admission_hook<F>(
        store_root: &Path,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
        after_admission: F,
    ) -> Result<Option<StableSidecarRead<Vec<u8>>>>
    where
        F: FnOnce(),
    {
        Self::read_regular_sidecar_snapshot_into(
            store_root,
            path,
            expected_directory,
            byte_limit,
            after_admission,
            |expected_len| {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(expected_len).map_err(|_| {
                    Error::NoritoFrame(norito::Error::AllocationFailed {
                        bytes: expected_len as u64,
                    })
                })?;
                bytes.resize(expected_len, 0);
                Ok(bytes)
            },
        )
    }

    // Both physical owners use this sole stable no-follow read and metadata walk.
    // The allocator supplies exactly one initialized fixed extent before body I/O.
    fn read_regular_sidecar_snapshot_into<F, A, B>(
        store_root: &Path,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
        after_admission: F,
        allocate: A,
    ) -> Result<Option<StableSidecarRead<B>>>
    where
        F: FnOnce(),
        A: FnOnce(usize) -> Result<B>,
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        let directory_before =
            Self::canonical_sidecar_directory_for(store_root, expected_directory)?;
        let Some(metadata) =
            Self::regular_sidecar_metadata_for(store_root, path, expected_directory)?
        else {
            return Ok(None);
        };
        let Some((_, directory_before)) = directory_before else {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar exists without a stable direct directory",
                ),
                path.to_path_buf(),
            ));
        };
        if !Self::sidecar_directory_binding_unchanged(&directory_before, &metadata.directory) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar directory changed before bounded read",
                ),
                path.to_path_buf(),
            ));
        }
        if metadata.file.len() > u64::try_from(byte_limit)? {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar exceeds its hard byte limit",
                ),
                path.to_path_buf(),
            ));
        }
        after_admission();
        let mut file = open_read_only_regular_file(path, "bounded Kura sidecar")
            .map_err(|err| Error::IO(err, path.to_path_buf()))?;
        let opened_metadata = secure_file_metadata::from_file(&file)
            .map_err(|err| Error::IO(err, path.to_path_buf()))?;
        if !opened_metadata.is_file()
            || !Self::sidecar_file_metadata_unchanged(&metadata.file, &opened_metadata)
        {
            return Err(Error::IO(
                std::io::Error::new(ErrorKind::InvalidData, "sidecar file changed while opening"),
                path.to_path_buf(),
            ));
        }
        let expected_len = usize::try_from(metadata.file.len())?;
        // The cumulative decode allowance and physical pool are separate obligations.
        norito::core::reserve_decode_allocation(expected_len).map_err(Error::NoritoFrame)?;
        let mut bytes = allocate(expected_len)?;
        if bytes.as_ref().len() != expected_len || bytes.as_mut().len() != expected_len {
            return Err(Error::CanonicalBlockWireMismatch { height: 0 });
        }
        file.read_exact(bytes.as_mut())
            .map_err(|err| Error::IO(err, path.to_path_buf()))?;
        let mut growth_probe = [0_u8; 1];
        if file
            .read(&mut growth_probe)
            .map_err(|err| Error::IO(err, path.to_path_buf()))?
            != 0
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar grew beyond its admitted length while reading",
                ),
                path.to_path_buf(),
            ));
        }
        let opened_after = secure_file_metadata::from_file(&file)
            .map_err(|err| Error::IO(err, path.to_path_buf()))?;
        let path_after = Self::regular_sidecar_metadata_for(store_root, path, expected_directory)?;
        if bytes.as_ref().len() > byte_limit
            || u64::try_from(bytes.as_ref().len())? != metadata.file.len()
            || !Self::sidecar_file_metadata_unchanged(&metadata.file, &opened_after)
            || !path_after.as_ref().is_some_and(|after| {
                Self::stable_sidecar_file_binding_unchanged(&metadata, after)
                    && Self::sidecar_metadata_same_object(&directory_before, &after.directory)
            })
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "sidecar changed or exceeded its hard byte limit while reading",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(Some(StableSidecarRead {
            bytes_hash: Hash::new(bytes.as_ref()),
            bytes,
            metadata: path_after.expect("validated stable sidecar metadata exists"),
        }))
    }
    fn read_regular_sidecar_snapshot(
        &self,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
    ) -> Result<Option<StableSidecarRead<Vec<u8>>>> {
        Self::read_regular_sidecar_snapshot_for(
            &self.store_root,
            path,
            expected_directory,
            byte_limit,
        )
    }
    fn read_regular_sidecar_bytes(
        &self,
        path: &Path,
        expected_directory: &Path,
        byte_limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        Self::read_regular_sidecar_bytes_for(&self.store_root, path, expected_directory, byte_limit)
    }

    /// Start the background writer after native startup has authenticated its execution prefix.
    ///
    /// # Errors
    /// Returns an error in read-only emergency Fast mode or when canonical storage is poisoned.
    pub fn start(kura: Arc<Self>, shutdown_signal: ShutdownSignal) -> Result<Child> {
        kura.durable_mutation_authorized()?;

        let shutdown_notify_tx = kura.block_notify_tx.clone();
        let shutdown_signal_clone = shutdown_signal.clone();
        tokio::spawn(async move {
            shutdown_signal_clone.receive().await;
            Self::notify_block_writer_sender(
                &shutdown_notify_tx,
                BlockNotify::Shutdown,
                "shutdown",
            );
        });
        Ok(Child::new(
            tokio::task::spawn(spawn_os_thread_as_future(
                std::thread::Builder::new().name("kura".to_owned()),
                move || {
                    kura.receive_blocks_loop(&shutdown_signal);
                },
            )),
            OnShutdown::Wait(Duration::from_secs(5)),
        ))
    }
    /// Initialize [`Kura`] after its construction to be able to work with it.
    ///
    /// # Errors
    /// Fails if:
    /// - file storage is unavailable
    /// - data in file storage is invalid or corrupted
    #[iroha_logger::log(skip_all, name = "kura_init")]
    fn init(block_store: &mut BlockStore, mode: InitMode) -> Result<ChainValidation> {
        let block_index_count: usize = block_store
            .read_durable_index_count()?
            .try_into()
            .expect("INTERNAL BUG: block index count exceeds usize::MAX");
        let chain_validation = match mode {
            InitMode::Fast => {
                warn!(
                    "Kura fast init trusts the durable local journal and defers full block validation; restart in strict mode after emergency recovery"
                );
                Kura::init_fast_mode(block_store, block_index_count)
            }
            InitMode::Strict => Kura::init_canonical_chain(block_store, block_index_count),
        }?;

        Ok(chain_validation)
    }
    /// Open the exact durable journal without decoding historical block bodies.
    ///
    /// Read-only preflight has already bound the durable count and terminal hash.
    /// Fast mode leaves any unpublished suffix untouched and deliberately trusts the
    /// committed journal prefix. A requested block is still decoded and checked
    /// lazily before it is returned.
    fn init_fast_mode(
        block_store: &mut BlockStore,
        block_index_count: usize,
    ) -> Result<ChainValidation, Error> {
        if block_store.fast_prevalidated_count != Some(u64::try_from(block_index_count)?) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura fast init did not pass the read-only committed-prefix preflight",
                ),
                block_store.path_to_blockchain.clone(),
            ));
        }
        block_store.fast_prevalidated_count = None;
        if block_store.read_exact_durable_index_count()? != u64::try_from(block_index_count)? {
            return Err(Error::HashesFileHeightMismatch);
        }

        Ok(ChainValidation {
            // Fast keeps only the durable count and reads exact hashes on demand. This avoids
            // startup I/O and RAM proportional to total chain height.
            hashes: Vec::new(),
        })
    }
    /// Audit every committed slot without repairing occupied native history.
    fn init_canonical_chain(
        block_store: &mut BlockStore,
        block_index_count: usize,
    ) -> Result<ChainValidation, Error> {
        if block_store.read_hashes_count()? != u64::try_from(block_index_count)? {
            return Err(Error::HashesFileHeightMismatch);
        }
        let mut indices = vec![BlockIndex::default(); block_index_count];
        block_store.read_block_indices(0, &mut indices)?;
        let hashes = block_store.read_block_hashes(0, block_index_count)?;
        Self::validate_block_chain(block_store, &indices, Some(&hashes))
    }
    /// Validate committed canonical frame identities; corruption never authorizes pruning.
    fn validate_block_chain(
        block_store: &mut BlockStore,
        block_indices: &[BlockIndex],
        expected_hashes: Option<&[HashOf<BlockHeader>]>,
    ) -> Result<ChainValidation, Error> {
        if block_store.read_hashes_count()? != u64::try_from(block_indices.len())? {
            return Err(Error::HashesFileHeightMismatch);
        }
        Self::validate_committed_block_prefix(
            block_store,
            block_indices,
            expected_hashes.ok_or(Error::HashesFileHeightMismatch)?,
        )
    }
    /// Audit the durable prefix before reconciling any uncommitted journal suffix.
    fn validate_committed_block_prefix(
        block_store: &mut BlockStore,
        block_indices: &[BlockIndex],
        expected: &[HashOf<BlockHeader>],
    ) -> Result<ChainValidation, Error> {
        if expected.len() != block_indices.len()
            || block_store.read_hashes_count()? < u64::try_from(block_indices.len())?
        {
            return Err(Error::HashesFileHeightMismatch);
        }
        let data_len = block_store.data_file_len()?;
        let mut buffer = Vec::new();
        let mut previous = None;
        for (position, slot) in block_indices.iter().enumerate() {
            let height = u64::try_from(position)?
                .checked_add(1)
                .ok_or(Error::HashesFileHeightMismatch)?;
            if slot.length == 0 || slot.length > STRICT_INIT_MAX_BLOCK_BYTES {
                return Err(Error::CorruptedBlockLength {
                    length: slot.length,
                    limit: STRICT_INIT_MAX_BLOCK_BYTES,
                });
            }
            if slot.is_evicted() {
                let Some(bytes) = block_store.read_optional_da_cache(height)? else {
                    // Missing availability grants no execution authority. The native
                    // certified-chain reader must obtain and authenticate the actual frame.
                    previous = Some(expected[position]);
                    continue;
                };
                if u64::try_from(bytes.len())? != slot.length {
                    return Err(Error::CanonicalBlockWireMismatch { height });
                }
                buffer = bytes;
            } else {
                let end =
                    slot.start
                        .checked_add(slot.length)
                        .ok_or(Error::CorruptedBlockRange {
                            start: slot.start,
                            length: slot.length,
                            data_len,
                        })?;
                if end > data_len {
                    return Err(Error::CorruptedBlockRange {
                        start: slot.start,
                        length: slot.length,
                        data_len,
                    });
                }
                let length = usize::try_from(slot.length)?;
                buffer.try_reserve(length.saturating_sub(buffer.len()))?;
                buffer.resize(length, 0);
                block_store.read_block_data(slot.start, &mut buffer)?;
            }
            let block = decode_framed_signed_block(&buffer).map_err(Error::BlockDecode)?;
            if block.header().height().get() != height
                || block.hash() != expected[position]
                || block.header().prev_block_hash() != previous
                || block.encode_wire()? != buffer
            {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            previous = Some(expected[position]);
        }
        Ok(ChainValidation {
            hashes: expected.to_vec(),
        })
    }
    #[iroha_logger::log(skip_all)]
    fn receive_blocks_loop(&self, shutdown_signal: &ShutdownSignal) {
        let kura = self;
        let block_rx = kura
            .block_notify_rx
            .lock()
            .take()
            .expect("Kura writer thread already started");
        let mut should_exit = false;
        loop {
            if shutdown_signal.is_sent() {
                info!("Kura block thread is being shut down. Flushing sidecars and fsync state.");
                should_exit = true;
            }
            let prune_guard = kura.prune_lock.lock();
            if kura.prune_recovery_is_required() {
                error!("Kura writer stopped because canonical prune recovery requires restart");
                return;
            }
            kura.flush_pipeline_sidecars();
            kura.flush_fastpq_proof_snapshots();
            drop(prune_guard);
            if should_exit {
                let _prune_guard = kura.prune_lock.lock();
                if kura.prune_recovery_is_required() {
                    error!("Kura writer stopped because canonical prune recovery requires restart");
                    return;
                }
                let flush_result = {
                    let mut store = kura.block_store.lock();
                    kura.flush_pending_fsync_with_resources(&mut store, true)
                };
                if let Err(error) = flush_result {
                    error!(?error, "Failed to fsync pending blocks on shutdown");
                    kura.record_or_poison_fsync_fault("shutdown fsync", &error);
                    return;
                }
                info!("Kura has flushed sidecars and pending fsync state and is shutting down.");
                return;
            }
            let wait_for_fsync = {
                let guard = kura.block_store.lock();
                guard.next_fsync_wait()
            };
            match wait_for_fsync {
                Some(wait) => match block_rx.recv_timeout(wait) {
                    Ok(BlockNotify::NewBlock) => {
                        debug!("kura writer received sidecar flush signal");
                    }
                    Ok(BlockNotify::StorageBudgetEviction) => {
                        debug!("kura writer received storage-budget eviction signal");
                    }
                    Ok(BlockNotify::Shutdown) => {
                        should_exit = true;
                        debug!("kura writer received shutdown signal");
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let _prune_guard = kura.prune_lock.lock();
                        if kura.prune_recovery_is_required() {
                            error!(
                                "Kura writer stopped because canonical prune recovery requires restart"
                            );
                            return;
                        }
                        let mut store = kura.block_store.lock();
                        if let Err(error) =
                            kura.flush_pending_fsync_with_resources(&mut store, false)
                        {
                            error!(?error, "Failed to fsync pending batch");
                            drop(store);
                            kura.record_or_poison_fsync_fault("periodic fsync", &error);
                            return;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        info!("Block writer channel closed; exiting thread.");
                        return;
                    }
                },
                None => match block_rx.recv() {
                    Ok(BlockNotify::NewBlock) => {
                        debug!("kura writer received sidecar flush signal");
                    }
                    Ok(BlockNotify::StorageBudgetEviction) => {
                        debug!("kura writer received storage-budget eviction signal");
                    }
                    Ok(BlockNotify::Shutdown) => {
                        should_exit = true;
                        debug!("kura writer received shutdown signal");
                    }
                    Err(error) => {
                        info!(?error, "Block writer channel closed; exiting thread.");
                        return;
                    }
                },
            }
        }
    }
    /// Get the hash of the block at the provided height.
    pub fn get_block_hash(&self, block_height: NonZeroUsize) -> Option<HashOf<BlockHeader>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        #[cfg(test)]
        self.observe_canonical_read_after_prune_check_for_tests(CANONICAL_HASH_READER_OBSERVED);
        if self.emergency_fast_startup_enabled() {
            return self.get_durable_block_hash(block_height);
        }
        let hash_data_guard = self.block_data.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let block_height = block_height.get();
        if hash_data_guard.len() < block_height {
            return None;
        }
        let block_index = block_height - 1;
        hash_data_guard.get(block_index).map(|(hash, _)| *hash)
    }
    /// Get the committed hash at the provided height from Kura's durable hash journal.
    pub fn get_durable_block_hash(
        &self,
        block_height: NonZeroUsize,
    ) -> Option<HashOf<BlockHeader>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let height = u64::try_from(block_height.get()).ok()?;
        let mut block_store = self.block_store.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let hash = Self::read_durable_hash_at_height(&mut block_store, height)
            .ok()
            .flatten();
        if self.prune_recovery_is_required() {
            return None;
        }
        hash
    }
    /// Resolve the height of the block with the given hash.
    ///
    /// Emergency Fast mode resolves only hashes learned after startup or by a
    /// height-based block read. It deliberately does not scan the complete
    /// durable hash journal to answer a reverse lookup.
    pub fn get_block_height_by_hash(&self, hash: HashOf<BlockHeader>) -> Option<NonZeroUsize> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let cached = self.block_height_index.lock().get(&hash).copied();
        if self.prune_recovery_is_required() {
            return None;
        }
        cached
    }
    /// Resolve block heights containing the given transaction entrypoint hash.
    ///
    /// Returns `None` when the in-memory index is known to be partial, so callers can fall back to
    /// scanning blocks without risking incomplete query results.
    pub fn get_block_heights_by_entrypoint_hash(
        &self,
        hash: HashOf<TransactionEntrypoint>,
    ) -> Option<BTreeSet<NonZeroUsize>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let heights = index.complete.then(|| {
            index
                .heights_by_entrypoint
                .get(&hash)
                .cloned()
                .unwrap_or_default()
        });
        if self.prune_recovery_is_required() {
            return None;
        }
        heights
    }
    /// Resolve block heights containing committed transactions with the given authority.
    ///
    /// Returns `None` when the in-memory transaction index is known to be partial.
    pub fn get_block_heights_by_transaction_authority(
        &self,
        authority: &AccountId,
    ) -> Option<BTreeSet<NonZeroUsize>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let heights = index.complete.then(|| {
            index
                .heights_by_authority
                .get(authority)
                .cloned()
                .unwrap_or_default()
        });
        if self.prune_recovery_is_required() {
            return None;
        }
        heights
    }
    /// Resolve block heights containing committed transactions with the given timestamp.
    ///
    /// Returns `None` when the in-memory transaction index is known to be partial.
    pub fn get_block_heights_by_transaction_timestamp_ms(
        &self,
        timestamp_ms: u64,
    ) -> Option<BTreeSet<NonZeroUsize>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let heights = index.complete.then(|| {
            index
                .heights_by_timestamp_ms
                .get(&timestamp_ms)
                .cloned()
                .unwrap_or_default()
        });
        if self.prune_recovery_is_required() {
            return None;
        }
        heights
    }
    /// Resolve block heights containing committed transactions in the timestamp range.
    ///
    /// Returns `None` when the in-memory transaction index is known to be partial.
    pub fn get_block_heights_by_transaction_timestamp_range(
        &self,
        lower_bound: Option<u64>,
        upper_bound: Option<u64>,
    ) -> Option<BTreeSet<NonZeroUsize>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        if let (Some(lower), Some(upper)) = (lower_bound, upper_bound)
            && lower > upper
        {
            return Some(BTreeSet::new());
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let heights = index.complete.then(|| {
            let lower = lower_bound.map_or(Bound::Unbounded, Bound::Included);
            let upper = upper_bound.map_or(Bound::Unbounded, Bound::Included);
            index
                .heights_by_timestamp_ms
                .range((lower, upper))
                .flat_map(|(_, heights)| heights.iter().copied())
                .collect()
        });
        if self.prune_recovery_is_required() {
            return None;
        }
        heights
    }
    /// Resolve block heights containing committed transactions with the given result status.
    ///
    /// Returns `None` when the in-memory transaction index is known to be partial.
    pub fn get_block_heights_by_transaction_result_status(
        &self,
        is_ok: bool,
    ) -> Option<BTreeSet<NonZeroUsize>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        let heights = index.complete.then(|| {
            index
                .heights_by_result_status
                .get(&is_ok)
                .cloned()
                .unwrap_or_default()
        });
        if self.prune_recovery_is_required() {
            return None;
        }
        heights
    }

    /// Return a bounded chronological page of exact-schema Kaigi signal locators.
    ///
    /// The index stores only structural locations and transaction authorities.
    /// An exclusive `after` position must name an exact candidate for the same
    /// call. `anchor_height` excludes later appends. A partial index, pruning,
    /// or poisoned canonical storage returns `Unavailable`; callers must not
    /// fall back to a ledger scan.
    pub(crate) fn get_kaigi_signal_candidate_locators(
        &self,
        call_id: &KaigiId,
        anchor_height: usize,
        after: Option<KaigiSignalCandidatePosition>,
        limit: NonZeroUsize,
    ) -> core::result::Result<KaigiSignalCandidateLocatorPage, KaigiSignalCandidateIndexError> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return Err(KaigiSignalCandidateIndexError::Unavailable);
        }
        let index = self.transaction_entrypoint_index.lock();
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
            || !index.complete
            || (anchor_height > 0
                && index
                    .indexed_heights
                    .last()
                    .is_none_or(|height| height.get() < anchor_height))
        {
            return Err(KaigiSignalCandidateIndexError::Unavailable);
        }
        let page = Self::collect_kaigi_signal_candidate_locators(
            &index,
            call_id,
            anchor_height,
            after,
            limit,
        )?;
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return Err(KaigiSignalCandidateIndexError::Unavailable);
        }
        Ok(page)
    }

    fn collect_kaigi_signal_candidate_locators(
        index: &TransactionEntrypointIndex,
        call_id: &KaigiId,
        anchor_height: usize,
        after: Option<KaigiSignalCandidatePosition>,
        limit: NonZeroUsize,
    ) -> core::result::Result<KaigiSignalCandidateLocatorPage, KaigiSignalCandidateIndexError> {
        let Some(by_height) = index.kaigi_signal_candidates.get(call_id) else {
            return if after.is_some() {
                Err(KaigiSignalCandidateIndexError::CursorMismatch)
            } else {
                Ok(KaigiSignalCandidateLocatorPage {
                    candidates: Vec::new(),
                    has_more: false,
                })
            };
        };
        let after_key = after.map(|position| position.network_input_index);
        let after_height = after
            .and_then(|position| usize::try_from(position.block_height).ok())
            .and_then(NonZeroUsize::new);
        if let Some(position) = after {
            let Some(height) = after_height else {
                return Err(KaigiSignalCandidateIndexError::CursorMismatch);
            };
            if height.get() > anchor_height {
                return Err(KaigiSignalCandidateIndexError::CursorMismatch);
            }
            let Some(locator) = by_height
                .get(&height)
                .and_then(|by_offset| by_offset.get(&after_key.expect("cursor key exists")))
            else {
                return Err(KaigiSignalCandidateIndexError::CursorMismatch);
            };
            if locator.position != position {
                return Err(KaigiSignalCandidateIndexError::CursorMismatch);
            }
        }
        let Some(anchor_height) = NonZeroUsize::new(anchor_height) else {
            return Ok(KaigiSignalCandidateLocatorPage {
                candidates: Vec::new(),
                has_more: false,
            });
        };
        let lower_height = after_height.map_or(Bound::Unbounded, Bound::Included);
        let mut candidates = Vec::new();
        candidates
            .try_reserve(limit.get())
            .map_err(|_| KaigiSignalCandidateIndexError::Unavailable)?;
        for (height, by_offset) in by_height.range((lower_height, Bound::Included(anchor_height))) {
            let lower_offset = if Some(*height) == after_height {
                Bound::Excluded(after_key.expect("cursor key exists"))
            } else {
                Bound::Unbounded
            };
            for locator in by_offset
                .range((lower_offset, Bound::Unbounded))
                .map(|(_, locator)| locator)
            {
                if candidates.len() == limit.get() {
                    return Ok(KaigiSignalCandidateLocatorPage {
                        candidates,
                        has_more: true,
                    });
                }
                candidates.push(locator.clone());
            }
        }
        Ok(KaigiSignalCandidateLocatorPage {
            candidates,
            has_more: false,
        })
    }
    /// Get a reference to block by height, loading it from disk if needed.
    /// # Errors
    /// Preserves original local allocation refusal separately from malformed or unavailable storage.
    pub fn get_block(
        &self,
        block_height: NonZeroUsize,
        budget: &iroha_allocation::AllocationBudget,
    ) -> std::result::Result<
        Option<iroha_data_model::block::SharedSignedBlock>,
        crate::execution_attempt::ExecutionAttemptError<Error>,
    > {
        self.get_block_inner(block_height, true, budget)
    }
    fn poison_corrupt_canonical_read(&self, block_index: usize, reason: &'static str) {
        let path = self.active_blocks_dir.lock().clone();
        let error = Error::IO(std::io::Error::new(ErrorKind::InvalidData, reason), path);
        error!(
            block_index,
            reason, "Canonical Kura block read failed validation"
        );
        self.poison_canonical_storage("canonical block read validation", &error);
    }
    fn get_block_inner(
        &self,
        block_height: NonZeroUsize,
        update_transaction_index: bool,
        budget: &iroha_allocation::AllocationBudget,
    ) -> std::result::Result<
        Option<iroha_data_model::block::SharedSignedBlock>,
        crate::execution_attempt::ExecutionAttemptError<Error>,
    > {
        use crate::execution_attempt::{
            ExecutionAttemptError as Attempt, canonical_decode_attempt_error,
        };
        use iroha_data_model::block::SharedSignedBlock;
        let reserve =
            || SharedSignedBlock::reserve(budget).map_err(|error| Attempt::Deferred(error.into()));
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            if self.canonical_storage_poisoned.load(Ordering::Relaxed) {
                error!(
                    height = block_height.get(),
                    "refusing canonical block read while Kura storage is fail-stop poisoned"
                );
            }
            return Err(Error::CanonicalStoragePoisoned.into());
        }
        #[cfg(test)]
        self.observe_canonical_read_after_prune_check_for_tests(CANONICAL_BLOCK_READER_OBSERVED);
        let (block_index, known_hash, known_previous_hash, cached_block, should_cache, chain_len) = {
            let data = self.block_data.lock();
            if self.prune_recovery_is_required() {
                return Err(Error::CanonicalStoragePoisoned.into());
            }
            if data.len() < block_height.get() {
                return Ok(None);
            }
            let idx = block_height.get() - 1;
            let known_hash = data.known_hash(idx);
            let known_previous_hash = idx
                .checked_sub(1)
                .and_then(|previous| data.known_hash(previous));
            let cached_block = data.cached_body(idx);
            let should_cache = idx + self.blocks_in_memory.get() >= data.len();
            (
                idx,
                known_hash,
                known_previous_hash,
                cached_block,
                should_cache,
                data.len(),
            )
        };
        let expected_hash = known_hash
            .or_else(|| self.get_durable_block_hash(block_height))
            .ok_or(Error::CanonicalBlockWireMismatch {
                height: block_height.get() as u64,
            })?;
        let expected_previous_hash = if block_index == 0 {
            None
        } else {
            let previous_height = NonZeroUsize::new(block_index)
                .expect("a non-genesis block has a non-zero parent height");
            Some(
                known_previous_hash
                    .or_else(|| self.get_durable_block_hash(previous_height))
                    .ok_or(Error::CanonicalBlockWireMismatch {
                        height: previous_height.get() as u64,
                    })?,
            )
        };
        if should_cache {
            let mut data = self.block_data.lock();
            if data.len() != chain_len || self.prune_recovery_is_required() {
                return Ok(None);
            }
            if update_transaction_index {
                data.cache_hash(block_index, expected_hash);
                if let (Some(previous_index), Some(previous_hash)) =
                    (block_index.checked_sub(1), expected_previous_hash)
                {
                    data.cache_hash(previous_index, previous_hash);
                }
                self.set_block_height_index_entry(block_height.get(), expected_hash);
            }
        }
        let (block, is_evicted, authenticated_for_index) = {
            let mut block_store = self.block_store.lock();
            if self.prune_recovery_is_required() {
                return Err(Error::CanonicalStoragePoisoned.into());
            }
            let index = match block_store.read_block_index(block_index as u64) {
                Ok(index) => index,
                Err(error) => {
                    error!(?error, block_index, "Failed to read block index from disk");
                    return Err(error.into());
                }
            };
            let is_evicted = index.is_evicted();
            let BlockIndex { start, length } = index;
            if length > STRICT_INIT_MAX_BLOCK_BYTES {
                drop(block_store);
                self.poison_corrupt_canonical_read(
                    block_index,
                    "committed block length exceeds the canonical wire limit",
                );
                return Err(Error::CanonicalBlockWireMismatch {
                    height: block_height.get() as u64,
                }
                .into());
            }
            if length == 0 {
                debug!(
                    block_index,
                    height = block_index.saturating_add(1),
                    evicted = is_evicted,
                    "Kura block body is unavailable for an invalid zero-length canonical slot"
                );
                return Ok(None);
            }
            if let Some(telemetry) = self.telemetry.get() {
                let outcome = if is_evicted { "miss" } else { "hit" };
                telemetry.inc_storage_da_cache("kura", outcome);
            }
            let authenticated_for_index = false;
            let loaded = if is_evicted {
                let height = block_index.saturating_add(1) as u64;
                let bytes = match block_store.read_optional_da_cache(height) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => return Ok(None),
                    Err(error) => {
                        error!(
                            ?error,
                            block_index, height, "Failed to read evicted block cache"
                        );
                        return Err(error.into());
                    }
                };
                if u64::try_from(bytes.len()).ok() != Some(length) {
                    error!(
                        block_index,
                        height, "Evicted block cache differs from its signed complete-wire binding"
                    );
                    return Err(Error::CanonicalBlockWireMismatch { height }.into());
                }
                if let Some(telemetry) = self.telemetry.get() {
                    let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                    telemetry.add_storage_da_churn_bytes("kura", "rehydrated", actual_len);
                }
                let shell = reserve()?;
                let decoded = match decode_framed_signed_block(&bytes) {
                    Ok(decoded) => decoded,
                    Err(error) => {
                        error!(
                            ?error,
                            block_index, height, "Failed to decode evicted block payload"
                        );
                        return Err(canonical_decode_attempt_error(error, Error::BlockDecode));
                    }
                };
                shell.initialize(decoded)
            } else {
                if let Some(block) = cached_block {
                    return Ok(Some(block));
                }
                let bytes = match block_store.block_bytes(start, length) {
                    Ok(slice) => slice,
                    Err(error) => {
                        error!(?error, block_index, "Failed to borrow block data slice");
                        drop(block_store);
                        self.poison_corrupt_canonical_read(
                            block_index,
                            "committed inline block range is unreadable",
                        );
                        return Err(error.into());
                    }
                };
                let shell = reserve()?;
                match decode_framed_signed_block(bytes) {
                    Ok(decoded) => shell.initialize(decoded),
                    Err(error) => {
                        error!(?error, block_index, "Failed to decode block from disk");
                        drop(block_store);
                        // A caller's nested Norito budget may refuse a valid stored
                        // frame. That refusal cannot establish persistent corruption
                        // or revoke native admission for the entire node.
                        if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid {
                            self.poison_corrupt_canonical_read(
                                block_index,
                                "committed inline block body is not decodable",
                            );
                        }
                        return Err(canonical_decode_attempt_error(error, Error::BlockDecode));
                    }
                }
            };
            (loaded, is_evicted, authenticated_for_index)
        };
        if self.prune_recovery_is_required() {
            return Err(Error::CanonicalStoragePoisoned.into());
        }
        if block.hash() != expected_hash {
            error!(
                expected = ?expected_hash,
                actual = ?block.hash(),
                block_index,
                "Loaded block hash mismatched the index entry"
            );
            self.poison_corrupt_canonical_read(
                block_index,
                "loaded block hash mismatches the canonical hash journal",
            );
            return Err(Error::CanonicalBlockWireMismatch {
                height: block_height.get() as u64,
            }
            .into());
        }
        let header = block.header();
        let expected_height = u64::try_from(block_height.get())
            .map_err(|_| Error::CanonicalBlockWireMismatch { height: u64::MAX })?;
        if header.height().get() != expected_height
            || header.prev_block_hash() != expected_previous_hash
        {
            error!(
                expected_height = block_height.get(),
                actual_height = header.height().get(),
                expected_previous_hash = ?expected_previous_hash,
                actual_previous_hash = ?header.prev_block_hash(),
                block_index,
                "Loaded block lineage mismatched the canonical journal"
            );
            self.poison_corrupt_canonical_read(
                block_index,
                "loaded block height or parent mismatches the canonical journal",
            );
            return Err(Error::CanonicalBlockWireMismatch {
                height: block_height.get() as u64,
            }
            .into());
        }
        if self.prune_recovery_is_required() {
            return Err(Error::CanonicalStoragePoisoned.into());
        }
        let block_arc = block;
        if update_transaction_index {
            let height = NonZeroUsize::new(block_index.saturating_add(1))
                .expect("canonical block index produces a non-zero height");
            let already_indexed = self
                .transaction_entrypoint_index
                .lock()
                .indexed_heights
                .contains(&height);
            if !authenticated_for_index {
                self.mark_transaction_entrypoint_index_incomplete(height.get(), chain_len);
            } else if !already_indexed {
                // Index only the complete Network projection of this canonical body.
                // A retired merge carrier or invalid result remains incomplete.
                self.set_transaction_entrypoint_index_entry(
                    height.get(),
                    block_arc.as_ref(),
                    chain_len,
                );
            }
        }
        if should_cache && update_transaction_index && !is_evicted && authenticated_for_index {
            #[cfg(test)]
            self.maybe_pause_block_read_before_cache_recheck_for_tests();
            // Cache publication is opportunistic, but it must be ordered after the durable index
            // observation. Eviction publishes its new index and clears this slot while retaining
            // `block_store`; re-read both durable identity fields before acquiring the cache so a
            // reader that decoded the old inline body cannot reinsert it after that publication.
            // Some canonical writers already own `block_data` before taking `block_store`, so use
            // a non-blocking cache acquisition while the store guard is held to avoid introducing
            // a reverse-order deadlock. A missed cache fill is harmless.
            let mut block_store = self.block_store.lock();
            let current_index = block_store.read_block_index(block_index as u64);
            let current_hash = block_store
                .read_block_hashes(block_index as u64, 1)
                .map(|hashes| hashes.first().copied());
            match (current_index, current_hash) {
                (Ok(index), Ok(Some(hash)))
                    if !index.is_evicted() && index.length > 0 && hash == expected_hash =>
                {
                    if let Some(mut data) = self.block_data.try_lock() {
                        let _ =
                            data.cache_body_if_hash(block_index, expected_hash, block_arc.clone());
                    }
                }
                (Err(error), _) | (_, Err(error)) => {
                    debug!(
                        ?error,
                        block_index, "Skipping block cache fill after durable recheck failed"
                    );
                }
                _ => {}
            }
            drop(block_store);
        }
        if self.prune_recovery_is_required() {
            return Err(Error::CanonicalStoragePoisoned.into());
        }
        Ok(Some(block_arc))
    }
    /// Authorize a durable sidecar or journal mutation which does not require
    /// canonical block-stage recovery.
    fn durable_mutation_authorized(&self) -> Result<()> {
        if self.emergency_fast_startup_enabled() {
            return Err(Error::EmergencyFastAuxiliaryUnavailable {
                subsystem: "canonical mutation",
            });
        }
        self.ensure_canonical_storage_not_poisoned()
    }
    /// Diagnose an invalid zero-length canonical body slot. This grants no replay authority.
    pub(crate) fn is_canonical_body_missing(&self, block_height: NonZeroUsize) -> bool {
        if self.prune_recovery_is_required() {
            return false;
        }
        let idx = block_height.get().saturating_sub(1);
        let data = self.block_data.lock();
        if self.prune_recovery_is_required() {
            return false;
        }
        if data.len() <= idx || data.cached_body(idx).is_some() {
            return false;
        }
        drop(data);
        let mut store = self.block_store.lock();
        if self.prune_recovery_is_required() {
            return false;
        }
        let missing_body = matches!(
            store.read_block_index(idx as u64),
            Ok(index) if index.length == 0
        );
        !self.prune_recovery_is_required() && missing_body
    }
    /// Corrupt a stored block body into a zero-length slot for fail-closed read tests.
    #[doc(hidden)]
    #[cfg(any(test, feature = "iroha-core-tests"))]
    #[allow(dead_code)]
    pub fn corrupt_canonical_body_for_testing(&self, block_height: NonZeroUsize) -> Result<()> {
        let idx = block_height.get().saturating_sub(1);
        let (block_hash, block_count) = {
            let mut data = self.block_data.lock();
            let block_count = data.len();
            let Some((block_hash, block_body)) = data.get_mut(idx) else {
                return Err(Error::OutOfBoundsBlockRead {
                    start_block_height: u64::try_from(block_height.get())?,
                    block_count,
                });
            };
            *block_body = None;
            (*block_hash, block_count)
        };
        let _write_guard = self.block_store_write_lock.lock();
        let mut store = self.block_store.lock();
        store.create_files_if_they_do_not_exist()?;
        store.write_block_hash(u64::try_from(idx)?, block_hash)?;
        store.write_block_index(u64::try_from(idx)?, EVICTED_BLOCK_START, 0)?;
        store.publish_commit_marker(u64::try_from(block_count)?)?;
        // Deliberate corruption of one body cannot authorize other missing history.
        Ok(())
    }
}
include!("kura/canonical_wire_identity.rs");
impl Kura {
    fn canonical_block_store_metadata(
        &self,
        blocks_dir: &Path,
    ) -> Result<StableCanonicalBlockStoreMetadata> {
        let required = |name: &str| {
            let path = blocks_dir.join(name);
            self.regular_sidecar_metadata(&path, blocks_dir)?
                .ok_or_else(|| {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::NotFound,
                            "canonical block-store file is missing",
                        ),
                        path,
                    )
                })
        };
        Ok(StableCanonicalBlockStoreMetadata {
            data: required(DATA_FILE_NAME)?,
            index: required(INDEX_FILE_NAME)?,
            hashes: required(HASHES_FILE_NAME)?,
            commit_marker: required(COUNT_FILE_NAME)?,
        })
    }
    fn canonical_block_store_metadata_unchanged(
        left: &StableCanonicalBlockStoreMetadata,
        right: &StableCanonicalBlockStoreMetadata,
    ) -> bool {
        Self::stable_sidecar_metadata_unchanged(&left.data, &right.data)
            && Self::stable_sidecar_metadata_unchanged(&left.index, &right.index)
            && Self::stable_sidecar_metadata_unchanged(&left.hashes, &right.hashes)
            && Self::stable_sidecar_metadata_unchanged(&left.commit_marker, &right.commit_marker)
    }
    #[cfg(test)]
    pub(crate) fn canonical_body_bytes_read_for_test(&self) -> u64 {
        self.block_store
            .lock()
            .body_bytes_read
            .load(Ordering::Relaxed)
    }
    /// Reset this physical store's actual read accounting for a scoped query fixture.
    #[cfg(test)]
    pub(crate) fn reset_canonical_query_reads_for_test(&self) {
        let store = self.block_store.lock();
        store.body_read_calls.store(0, Ordering::Relaxed);
        store.body_bytes_read.store(0, Ordering::Relaxed);
    }
    /// Return actual physical body read calls and bytes; no decoded-cache proxy.
    #[cfg(test)]
    pub(crate) fn canonical_query_reads_for_test(&self) -> (usize, u64) {
        let store = self.block_store.lock();
        (
            store.body_read_calls.load(Ordering::Relaxed),
            store.body_bytes_read.load(Ordering::Relaxed),
        )
    }
    /// Project a comparison-only identity for this exact live Kura owner.
    pub(crate) fn instance_identity(&self) -> KuraInstanceIdentity {
        KuraInstanceIdentity(Arc::clone(&self.instance_identity))
    }
}
include!("kura/durable_block_and_atomic_sidecar_io.rs");
impl Kura {
    fn rollback_intent_path(blocks_root: &Path) -> PathBuf {
        blocks_root.join(ROLLBACK_INTENT_FILE_NAME)
    }
    fn reject_retired_rollback_intents(blocks_root: &Path) -> Result<()> {
        if blocks_root.as_os_str().is_empty() {
            return Err(Error::EmptyStoreRoot);
        }
        let path = Self::rollback_intent_path(blocks_root);
        let tmp_path = path.with_extension("norito.tmp");
        for artifact in [path, tmp_path] {
            match std::fs::symlink_metadata(&artifact) {
                Ok(_) => return Err(Error::RetiredKuraArtifact { path: artifact }),
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(Error::IO(err, artifact)),
            }
        }
        Ok(())
    }
    fn ensure_no_retired_rollback_intents(&self) -> Result<()> {
        let blocks_root = self.active_blocks_dir.lock().clone();
        Self::reject_retired_rollback_intents(&blocks_root)
    }
    fn block_store_tracked_bytes(block_store: &mut BlockStore) -> Result<u64> {
        if block_store.path_to_blockchain.as_os_str().is_empty() {
            return Ok(0);
        }
        let data_len = block_store.data_file_len()?;
        let index_len = block_store.index_file_len()?;
        let hashes_len = block_store.hashes_file_len()?;
        let marker_path = block_store.commit_marker_path();
        let marker_len = Self::file_len_or_zero(&marker_path)?;
        let marker_tmp_len = Self::file_len_or_zero(&marker_path.with_extension("norito.tmp"))?;
        let data_tmp_len = Self::file_len_or_zero(
            &block_store
                .path_to_blockchain
                .join(format!("{DATA_FILE_NAME}.tmp")),
        )?;
        let index_tmp_len = Self::file_len_or_zero(
            &block_store
                .path_to_blockchain
                .join(format!("{INDEX_FILE_NAME}.tmp")),
        )?;
        let hashes_tmp_len = Self::file_len_or_zero(
            &block_store
                .path_to_blockchain
                .join(format!("{HASHES_FILE_NAME}.tmp")),
        )?;
        Ok(data_len
            .saturating_add(index_len)
            .saturating_add(hashes_len)
            .saturating_add(marker_len)
            .saturating_add(marker_tmp_len)
            .saturating_add(data_tmp_len)
            .saturating_add(index_tmp_len)
            .saturating_add(hashes_tmp_len))
    }
    fn da_payload_bytes_for_range(
        block_store: &BlockStore,
        start_height: u64,
        count: usize,
    ) -> Result<u64> {
        if block_store.da_blocks_dir.as_os_str().is_empty() || count == 0 {
            return Ok(0);
        }
        let mut total = 0u64;
        for offset in 0..count {
            let height = start_height.saturating_add(offset as u64).saturating_add(1);
            let path = block_store.da_block_path(height);
            total = total.saturating_add(Self::file_len_or_zero(&path)?);
        }
        Ok(total)
    }
    fn sidecar_tracked_bytes(data_path: &Path, index_path: &Path) -> Result<u64> {
        let data_tmp = data_path.with_extension("norito.tmp");
        let index_tmp = index_path.with_extension("index.tmp");
        Ok(Self::file_len_or_zero(data_path)?
            .saturating_add(Self::file_len_or_zero(index_path)?)
            .saturating_add(Self::file_len_or_zero(&data_tmp)?)
            .saturating_add(Self::file_len_or_zero(&index_tmp)?))
    }
    fn block_required_bytes(block: &SignedBlock) -> Result<u64> {
        let wire = block.canonical_wire()?;
        let frame = wire.into_vec();
        let frame_len = u64::try_from(frame.len())?;
        Ok(frame_len
            .saturating_add(BlockIndex::SIZE)
            .saturating_add(SIZE_OF_BLOCK_HASH))
    }
    fn sidecar_bytes(store_dir: &Path) -> Result<u64> {
        if store_dir.as_os_str().is_empty() {
            return Ok(0);
        }
        let mut total = 0u64;
        for dir_name in [PIPELINE_DIR_NAME] {
            let dir = store_dir.join(dir_name);
            let before = match secure_file_metadata::from_path(&dir) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(Error::IO(err, dir.clone())),
            };
            if before.file_type().is_symlink() || !before.file_type().is_dir() {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Kura sidecar namespace is not a direct directory",
                    ),
                    dir,
                ));
            }
            let entries = std::fs::read_dir(&dir).map_err(|err| Error::IO(err, dir.clone()))?;
            for entry in entries {
                let entry = entry.map_err(|err| Error::IO(err, dir.clone()))?;
                let path = entry.path();
                let metadata = secure_file_metadata::from_path(&path)
                    .map_err(|err| Error::IO(err, path.clone()))?;
                if metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && Self::sidecar_is_single_link(&metadata)
                {
                    total = total.checked_add(metadata.len()).ok_or_else(|| {
                        Error::IO(
                            std::io::Error::new(
                                ErrorKind::InvalidData,
                                "Kura sidecar byte count overflowed",
                            ),
                            path.clone(),
                        )
                    })?;
                    continue;
                }
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Kura sidecar namespace contains an unrecognized linked or non-regular entry",
                    ),
                    path,
                ));
            }
            let after =
                secure_file_metadata::from_path(&dir).map_err(|err| Error::IO(err, dir.clone()))?;
            if after.file_type().is_symlink()
                || !after.file_type().is_dir()
                || !Self::sidecar_directory_metadata_unchanged(&before, &after)
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Kura sidecar namespace changed during disk accounting",
                    ),
                    dir,
                ));
            }
        }
        Ok(total)
    }
    fn block_store_bytes(blocks_dir: &Path) -> Result<u64> {
        if blocks_dir.as_os_str().is_empty() {
            return Ok(0);
        }
        let mut files = 0u64;
        Self::visit_disk_accounting_directory(blocks_dir, |_, metadata| {
            if metadata.is_file() {
                files = files.saturating_add(metadata.len());
            }
            Ok(())
        })?;
        let sidecars = Self::sidecar_bytes(blocks_dir)?;
        Ok(files.saturating_add(sidecars))
    }
    fn blocks_root_bytes(root: &Path) -> Result<u64> {
        Self::blocks_root_usage_bytes(root).map(|(enforced, _)| enforced)
    }
    /// Stream a fixed-depth accounting namespace without following links or
    /// retaining a descriptor for every instance. This observes physical bytes;
    /// it never installs an active route or grants historical write authority.
    fn visit_disk_accounting_directory(
        directory: &Path,
        mut visit: impl FnMut(&Path, &SecureMetadata) -> Result<()>,
    ) -> Result<()> {
        let before = match secure_file_metadata::from_path(directory) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(Error::IO(err, directory.to_path_buf())),
        };
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(Self::invalid_lane_artifact_error(
                directory.to_path_buf(),
                "Kura accounting namespace is not a direct directory",
            ));
        }
        for (index, entry) in std::fs::read_dir(directory)
            .map_err(|err| Error::IO(err, directory.to_path_buf()))?
            .enumerate()
        {
            // Same ceiling as the complete retained physical inventory. The
            // nesting below blocks is exactly one instance level.
            if index >= 4_000_000 {
                return Err(Self::invalid_lane_artifact_error(
                    directory.to_path_buf(),
                    "Kura accounting namespace exceeds its entry bound",
                ));
            }
            let entry = entry.map_err(|err| Error::IO(err, directory.to_path_buf()))?;
            let path = entry.path();
            let metadata = secure_file_metadata::from_path(&path)
                .map_err(|err| Error::IO(err, path.clone()))?;
            if metadata.file_type().is_symlink()
                || !(metadata.is_dir()
                    || (metadata.is_file() && Self::sidecar_is_single_link(&metadata)))
            {
                return Err(Self::invalid_lane_artifact_error(
                    path,
                    "Kura accounting namespace contains a linked or non-regular entry",
                ));
            }
            visit(&path, &metadata)?;
        }
        let after = secure_file_metadata::from_path(directory)
            .map_err(|err| Error::IO(err, directory.to_path_buf()))?;
        if after.file_type().is_symlink()
            || !after.is_dir()
            || !Self::sidecar_directory_metadata_unchanged(&before, &after)
        {
            return Err(Self::invalid_lane_artifact_error(
                directory.to_path_buf(),
                "Kura accounting namespace changed during observation",
            ));
        }
        Ok(())
    }
    fn is_immutable_instance_accounting_key(name: &str) -> bool {
        name.len() == 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    fn dir_file_bytes(dir: &Path) -> Result<u64> {
        if dir.as_os_str().is_empty() {
            return Ok(0);
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(Error::IO(err, dir.to_path_buf())),
        };
        let mut total = 0u64;
        for entry in entries {
            let entry = entry.map_err(|err| Error::IO(err, dir.to_path_buf()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| Error::IO(err, path.clone()))?;
            if file_type.is_file() {
                let len = entry
                    .metadata()
                    .map_err(|err| Error::IO(err, path.clone()))?
                    .len();
                total = total.saturating_add(len);
            }
        }
        Ok(total)
    }
    fn block_store_supplemental_bytes(blocks_dir: &Path) -> Result<u64> {
        let mut total = 0u64;
        let da_dir = blocks_dir.join(DA_BLOCKS_DIR_NAME);
        total = total.saturating_add(Self::dir_file_bytes(&da_dir)?);
        Ok(total)
    }
    fn blocks_root_usage_bytes(root: &Path) -> Result<(u64, u64)> {
        if root.as_os_str().is_empty() {
            return Ok((0, 0));
        }
        let debug_bytes = Self::blocks_root_debug_file_bytes(root)?;
        let mut enforced = debug_bytes;
        let mut total = debug_bytes;
        let mut count_store = |path: &Path| -> Result<()> {
            let budgeted = Self::block_store_bytes(path)?;
            enforced = enforced.saturating_add(budgeted);
            total = total
                .saturating_add(budgeted)
                .saturating_add(Self::block_store_supplemental_bytes(path)?);
            Ok(())
        };
        Self::visit_disk_accounting_directory(root, |path, metadata| {
            if path.file_name() == Some(std::ffi::OsStr::new("instances")) {
                Self::visit_disk_accounting_directory(path, |instance, metadata| {
                    if !metadata.is_dir()
                        || !instance
                            .file_name()
                            .and_then(std::ffi::OsStr::to_str)
                            .is_some_and(Self::is_immutable_instance_accounting_key)
                    {
                        return Err(Self::invalid_lane_artifact_error(
                            instance.to_path_buf(),
                            "Kura instance accounting contains an unknown physical entry",
                        ));
                    }
                    count_store(instance)
                })?;
            } else if metadata.is_dir() {
                // Count canonical custody and disposable retained stores. This
                // physical enumeration does not resolve an alias into a lane.
                count_store(path)?;
            }
            Ok(())
        })?;
        Ok((enforced, total))
    }
    /// Count regular files below `root` without following symbolic links.
    ///
    /// Retained geometry trees remain opaque recovery evidence. Their regular
    /// bytes count against the Kura budget without granting an execution or release owner.
    fn directory_tree_file_bytes(root: &Path) -> Result<u64> {
        if root.as_os_str().is_empty() {
            return Ok(0);
        }
        let root_metadata = match std::fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(Error::IO(err, root.to_path_buf())),
        };
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura retained geometry root must be a non-symlink directory",
                ),
                root.to_path_buf(),
            ));
        }
        let mut total = 0u64;
        let mut seen = 0_usize;
        let mut pending = vec![(root.to_path_buf(), 0_usize)];
        while let Some((directory, depth)) = pending.pop() {
            if depth > 128 {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "Kura retained geometry tree exceeds the maximum directory depth",
                    ),
                    directory,
                ));
            }
            let entries =
                std::fs::read_dir(&directory).map_err(|err| Error::IO(err, directory.clone()))?;
            for entry in entries {
                let entry = entry.map_err(|err| Error::IO(err, directory.clone()))?;
                seen = seen.saturating_add(1);
                if seen > 4_000_000 {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "Kura retained geometry tree exceeds the maximum entry count",
                        ),
                        directory,
                    ));
                }
                let path = entry.path();
                let file_type = entry
                    .file_type()
                    .map_err(|err| Error::IO(err, path.clone()))?;
                if file_type.is_symlink() {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "Kura retained geometry tree contains a symbolic link",
                        ),
                        path,
                    ));
                }
                if file_type.is_file() {
                    total = total.saturating_add(
                        entry
                            .metadata()
                            .map_err(|err| Error::IO(err, path.clone()))?
                            .len(),
                    );
                } else if file_type.is_dir() {
                    pending.push((path, depth.saturating_add(1)));
                } else {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "Kura retained geometry tree contains a non-regular entry",
                        ),
                        path,
                    ));
                }
            }
        }
        Ok(total)
    }
    fn kura_shared_disk_usage_bytes(&self) -> Result<u64> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(0);
        }
        Self::reject_retired_merge_storage(&self.store_root)?;
        let retired_root = self.store_root.join("retired");
        let retired_geometry_root = retired_root.join("lane_geometry");
        let mut used = 0u64;
        used = used.saturating_add(Self::file_len_or_zero(
            &self.store_root.join(membership_storage::SEGMENT_NAME),
        )?);
        used = used.saturating_add(Self::directory_tree_file_bytes(&retired_geometry_root)?);
        used = used.saturating_add(Self::directory_tree_file_bytes(
            &self.store_root.join(fastpq_artifact_store::DIRECTORY),
        )?);
        for journal_name in [
            crate::query::index_status::QueryIndexJournal::JOURNAL_FILE,
            crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE,
        ] {
            let path = self.store_root.join(journal_name);
            used = used.saturating_add(Self::file_len_or_zero(&path)?);
            used = used.saturating_add(Self::file_len_or_zero(
                &path.with_extension("norito.tmp"),
            )?);
        }
        used = used.saturating_add(Self::file_len_or_zero(&self.lane_geometry_journal_path())?);
        used = used.saturating_add(Self::file_len_or_zero(
            &self
                .lane_geometry_journal_path()
                .with_extension("norito.tmp"),
        )?);
        Ok(used)
    }
    fn kura_disk_usage_bytes(&self) -> Result<u64> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(0);
        }
        let blocks_root = self.store_root.join("blocks");
        let retired_blocks_root = self.store_root.join("retired").join("blocks");
        let active = Self::blocks_root_bytes(&blocks_root)?;
        let retired = Self::blocks_root_bytes(&retired_blocks_root)?;
        Ok(active
            .saturating_add(retired)
            .saturating_add(self.kura_shared_disk_usage_bytes()?))
    }
    fn kura_disk_usage_bytes_with_total(&self) -> Result<(u64, u64)> {
        if self.store_root.as_os_str().is_empty() {
            return Ok((0, 0));
        }
        let blocks_root = self.store_root.join("blocks");
        let retired_blocks_root = self.store_root.join("retired").join("blocks");
        let (active_enforced, active_total) = Self::blocks_root_usage_bytes(&blocks_root)?;
        let (retired_enforced, retired_total) =
            Self::blocks_root_usage_bytes(&retired_blocks_root)?;
        let shared = self.kura_shared_disk_usage_bytes()?;
        Ok((
            active_enforced
                .saturating_add(retired_enforced)
                .saturating_add(shared),
            active_total
                .saturating_add(retired_total)
                .saturating_add(shared),
        ))
    }
    fn kura_total_disk_usage_bytes(&self) -> Result<u64> {
        self.kura_disk_usage_bytes_with_total()
            .map(|(_, total)| total)
    }
    fn pending_block_bytes_raw(&self, persisted_count: usize) -> Result<u64> {
        if self.emergency_fast_startup_enabled() {
            return Err(Error::EmergencyFastAuxiliaryUnavailable {
                subsystem: "pending canonical block cache",
            }
            .into());
        }
        #[cfg(test)]
        self.pending_budget_raw_scans
            .fetch_add(1, Ordering::Relaxed);
        let pending_blocks = {
            let data = self.block_data.lock();
            let start = persisted_count.min(data.len());
            let mut blocks = Vec::with_capacity(data.len().saturating_sub(start));
            let entries = data
                .dense_entries()
                .ok_or(Error::EmergencyFastAuxiliaryUnavailable {
                    subsystem: "pending canonical block cache",
                })?;
            for (_, block) in entries.iter().skip(start) {
                let block = block
                    .as_ref()
                    .expect("pending block missing from Kura memory cache");
                blocks.push(block.clone());
            }
            blocks
        };
        let mut pending_bytes = 0u64;
        for block in pending_blocks {
            pending_bytes = pending_bytes
                .checked_add(Self::block_required_bytes(&block)?)
                .ok_or_else(|| {
                    Self::invalid_lane_artifact_error(
                        self.store_root.clone(),
                        "pending canonical wire bytes overflowed",
                    )
                })?;
        }
        Ok(pending_bytes)
    }
    /// Share exact pending accounting while the caller owns merge lookup acquisition.
    /// A resolver refusal leaves the pending-byte cache invalid for the next attempt.
    fn pending_block_bytes(&self, persisted_count: usize, unindexed_bytes: u64) -> Result<u64> {
        if self.pending_budget_bytes_valid.load(Ordering::Relaxed) {
            let pending = self.pending_budget_bytes.load(Ordering::Relaxed);
            return Ok(pending.saturating_sub(unindexed_bytes));
        }
        let pending_bytes = self.pending_block_bytes_raw(persisted_count)?;
        self.pending_budget_bytes
            .store(pending_bytes, Ordering::Relaxed);
        self.pending_budget_bytes_valid
            .store(true, Ordering::Relaxed);
        Ok(pending_bytes.saturating_sub(unindexed_bytes))
    }
    fn persisted_count_and_unindexed_bytes_raw(&self) -> Result<(usize, u64)> {
        #[cfg(test)]
        self.durable_budget_metadata_reads
            .fetch_add(1, Ordering::Relaxed);
        let mut block_store = self.block_store.lock();
        let persisted = usize::try_from(block_store.read_durable_index_count()?)?;
        let persisted_u64 = persisted as u64;
        let indexed_data_len = if persisted == 0 {
            0
        } else {
            let last = block_store.read_block_index(persisted as u64 - 1)?;
            last.start.saturating_add(last.length)
        };
        let data_file_len = block_store.data_file_len()?;
        let index_file_len = block_store.index_file_len()?;
        let hashes_file_len = block_store.hashes_file_len()?;
        let indexed_index_len = persisted_u64.saturating_mul(BlockIndex::SIZE);
        let indexed_hash_len = persisted_u64.saturating_mul(SIZE_OF_BLOCK_HASH);
        let unindexed_bytes = data_file_len
            .saturating_sub(indexed_data_len)
            .saturating_add(index_file_len.saturating_sub(indexed_index_len))
            .saturating_add(hashes_file_len.saturating_sub(indexed_hash_len));
        Ok((persisted, unindexed_bytes))
    }
    fn persisted_count_and_unindexed_bytes(&self) -> Result<(usize, u64)> {
        if let Some(snapshot) = self.durable_budget_snapshot() {
            return Ok(snapshot);
        }
        let (persisted_count, unindexed_bytes) = self.persisted_count_and_unindexed_bytes_raw()?;
        self.publish_durable_budget_snapshot(persisted_count, unindexed_bytes);
        Ok((persisted_count, unindexed_bytes))
    }
    fn check_storage_budget(&self, block: &SignedBlock) -> Result<()> {
        if self.max_disk_usage_bytes == 0 || self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        self.ensure_disk_usage_initialized()?;
        let (persisted_count, unindexed_bytes) = self.persisted_count_and_unindexed_bytes()?;
        let pending = self.pending_block_bytes(persisted_count, unindexed_bytes)?;
        let used = self.kura_total_disk_usage_bytes()?;
        let required = [
            pending,
            self.membership_storage.pending_bytes(),
            Self::block_required_bytes(block)?,
        ]
        .into_iter()
        .try_fold(used, u64::checked_add)
        .ok_or_else(|| {
            Self::invalid_lane_artifact_error(
                self.store_root.clone(),
                "canonical append capacity overflowed",
            )
        })?;
        let limit = self.max_disk_usage_bytes;
        if let Some(telemetry) = self.telemetry.get() {
            telemetry.record_storage_budget_usage("kura", required, limit);
        }
        if required > limit {
            if let Some(telemetry) = self.telemetry.get() {
                telemetry.inc_storage_budget_exceeded("kura");
            }
            return Err(Error::StorageBudgetExceeded {
                limit,
                used,
                required,
            });
        }
        Ok(())
    }
    /// Persist the canonical block after checking append capacity and durable ordering.
    pub fn store_block(&self, block: iroha_data_model::block::SharedSignedBlock) -> Result<()> {
        self.store_block_durable(&block)
    }
    /// Read the exact canonical framed block bytes persisted at `height`.
    #[cfg(test)]
    pub(crate) fn canonical_block_wire_bytes_for_testing(
        &self,
        height: NonZeroUsize,
    ) -> Result<Vec<u8>> {
        let mut block_store = self.block_store.lock();
        let index_position = u64::try_from(height.get().saturating_sub(1))?;
        let index = block_store.read_block_index(index_position)?;
        if index.is_evicted() {
            return block_store.read_da_block_bytes(u64::try_from(height.get())?, index.length);
        }
        let mut bytes = vec![0_u8; usize::try_from(index.length)?];
        block_store.read_block_data(index.start, &mut bytes)?;
        Ok(bytes)
    }
    fn read_bound_regular_file_bytes_locked(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
        max_bytes: usize,
        kind: &str,
    ) -> Result<Option<Vec<u8>>> {
        let directory = path.parent().ok_or_else(|| {
            Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} path has no directory"),
            )
        })?;
        let Some(metadata) = Self::regular_sidecar_metadata_for(&self.store_root, path, directory)?
        else {
            if !Self::progress_mutation_namespace_unchanged(namespace) {
                return Err(Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} namespace changed while proving absence"),
                ));
            }
            return Ok(None);
        };
        let len = usize::try_from(metadata.file.len())?;
        if len == 0 || len > max_bytes {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} has an empty or oversized payload"),
            ));
        }
        let mut file = Self::open_bound_progress_file(namespace, path, &metadata)?;
        let mut bytes = Vec::with_capacity(len);
        std::io::Read::by_ref(&mut file)
            .take(u64::try_from(max_bytes)?.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let current = Self::regular_sidecar_metadata_for(&self.store_root, path, directory)?
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} disappeared while reading"),
                )
            })?;
        if bytes.len() != len
            || !Self::stable_sidecar_metadata_unchanged(&metadata, &current)
            || !Self::progress_mutation_namespace_unchanged(namespace)
        {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} changed while reading"),
            ));
        }
        Ok(Some(bytes))
    }
    fn open_bound_regular_file_with_exact_bytes_locked(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
        expected_bytes: &[u8],
        max_bytes: usize,
        kind: &str,
    ) -> Result<(std::fs::File, StableSidecarMetadata)> {
        let directory = path.parent().ok_or_else(|| {
            Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} path has no directory"),
            )
        })?;
        let metadata = Self::regular_sidecar_metadata_for(&self.store_root, path, directory)?
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} disappeared before exact-object binding"),
                )
            })?;
        let len = usize::try_from(metadata.file.len())?;
        if len == 0 || len > max_bytes || len != expected_bytes.len() {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} changed size before exact-object binding"),
            ));
        }
        let mut file = Self::open_bound_progress_file(namespace, path, &metadata)?;
        self.verify_bound_open_regular_file_exact_bytes_locked(
            namespace,
            path,
            &mut file,
            &metadata,
            expected_bytes,
            max_bytes,
            kind,
        )?;
        Ok((file, metadata))
    }
    #[allow(clippy::too_many_arguments)]
    fn verify_bound_open_regular_file_exact_bytes_locked(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
        file: &mut std::fs::File,
        metadata: &StableSidecarMetadata,
        expected_bytes: &[u8],
        max_bytes: usize,
        kind: &str,
    ) -> Result<()> {
        let directory = path.parent().ok_or_else(|| {
            Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} path has no directory"),
            )
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let mut readback = Vec::with_capacity(expected_bytes.len());
        std::io::Read::by_ref(&mut *file)
            .take(u64::try_from(max_bytes)?.saturating_add(1))
            .read_to_end(&mut readback)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let opened = secure_file_metadata::from_file(file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let current = Self::regular_sidecar_metadata_for(&self.store_root, path, directory)?
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} disappeared during exact-object binding"),
                )
            })?;
        if readback != expected_bytes
            || !Self::sidecar_file_metadata_unchanged(&metadata.file, &opened)
            || !Self::stable_sidecar_metadata_unchanged(&metadata, &current)
            || !Self::progress_mutation_namespace_unchanged(namespace)
        {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} changed during exact-object binding"),
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn verify_bound_open_regular_file_exact_bytes_after_namespace_mutation_locked(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
        file: &mut std::fs::File,
        metadata: &StableSidecarMetadata,
        expected_bytes: &[u8],
        max_bytes: usize,
        kind: &str,
    ) -> Result<()> {
        let directory = path.parent().ok_or_else(|| {
            Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} path has no directory"),
            )
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let mut readback = Vec::with_capacity(expected_bytes.len());
        std::io::Read::by_ref(&mut *file)
            .take(u64::try_from(max_bytes)?.saturating_add(1))
            .read_to_end(&mut readback)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let opened = secure_file_metadata::from_file(file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let current = Self::regular_sidecar_metadata_for(&self.store_root, path, directory)?
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} disappeared after namespace mutation"),
                )
            })?;
        if readback != expected_bytes
            || metadata.canonical_path != current.canonical_path
            || !Self::sidecar_file_metadata_unchanged(&metadata.file, &opened)
            || !Self::sidecar_file_metadata_unchanged(&metadata.file, &current.file)
            || !Self::sidecar_directory_binding_unchanged(&metadata.directory, &current.directory)
            || !Self::progress_mutation_namespace_unchanged(namespace)
        {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} changed after namespace mutation"),
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        Ok(())
    }
    fn publish_bound_noclobber_file_locked(
        &self,
        namespace: &BoundProgressNamespace,
        path: &Path,
        temp_path: &Path,
        bytes: &[u8],
        kind: &str,
    ) -> Result<bool> {
        self.durable_mutation_authorized()?;
        if path.parent() != namespace.data_path.parent()
            || temp_path.parent() != namespace.data_path.parent()
        {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} publication escapes its descriptor-bound directory"),
            ));
        }
        if self
            .read_bound_regular_file_bytes_locked(namespace, path, bytes.len().max(1), kind)?
            .is_some()
        {
            return Ok(false);
        }
        match std::fs::symlink_metadata(temp_path) {
            Ok(_) => {
                return Err(Self::invalid_lane_artifact_error(
                    temp_path.to_path_buf(),
                    format!("{kind} publication found an unresolved temporary"),
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(Error::IO(error, temp_path.to_path_buf())),
        }
        let mut temporary = Self::create_new_bound_progress_temp(namespace, temp_path)
            .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
        #[cfg(test)]
        if let Some(prefix_len) =
            FAIL_AFTER_NEXT_BOUND_EVIDENCE_TEMP_PREFIX.with(|flag| flag.take())
        {
            assert!(
                prefix_len < bytes.len(),
                "crash cut must precede the complete artifact"
            );
            temporary
                .write_all(&bytes[..prefix_len])
                .map_err(|error| Error::IO(error, temp_path.to_path_buf()))?;
            // Keep this original exclusive-create descriptor's actual bytes, as
            // process loss before write_all completion would. No fabricated file.
            return Err(Error::IO(
                std::io::Error::other(
                    "injected Native evidence interruption during temporary write",
                ),
                temp_path.to_path_buf(),
            ));
        }
        if let Err(error) = temporary
            .write_all(bytes)
            .and_then(|_| temporary.flush())
            .and_then(|_| temporary.sync_all())
        {
            drop(temporary);
            let _ = Self::remove_bound_progress_temp_if_present(namespace, temp_path);
            let _ = Self::sync_bound_progress_intent_directories(namespace);
            return Err(Error::IO(error, temp_path.to_path_buf()));
        }
        #[cfg(test)]
        if FAIL_AFTER_NEXT_NATIVE_AMX_EVIDENCE_TEMP_SYNC.with(|flag| flag.replace(false)) {
            // Retain the actual synced temporary exactly as a crash between
            // write/fsync and promotion would; no synthetic artifact is installed.
            return Err(Error::IO(
                std::io::Error::other(
                    "injected Native evidence interruption after temporary fsync",
                ),
                temp_path.to_path_buf(),
            ));
        }
        if let Err(error) =
            Self::promote_bound_progress_temp_noreplace(namespace, temp_path, path, &temporary)
        {
            drop(temporary);
            if !error.published {
                let _ = Self::remove_bound_progress_temp_if_present(namespace, temp_path);
                let _ = Self::sync_bound_progress_intent_directories(namespace);
            }
            return Err(Error::IO(error.source, path.to_path_buf()));
        }
        self.sync_bound_evidence_namespace(namespace, kind)?;
        let persisted = self
            .read_bound_regular_file_bytes_locked(namespace, path, bytes.len().max(1), kind)?
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    format!("{kind} disappeared after publication"),
                )
            })?;
        if persisted != bytes {
            return Err(Self::invalid_lane_artifact_error(
                path.to_path_buf(),
                format!("{kind} changed during publication"),
            ));
        }
        Ok(true)
    }
    // Drop cached blocks that are already persisted and outside the retention window.
    // Keep the genesis block plus the most recent `blocks_in_memory` persisted blocks.
    fn drop_persisted_blocks(
        block_data: &mut BlockData,
        persisted_count: usize,
        blocks_in_memory: usize,
    ) {
        let drop_before = persisted_count.saturating_sub(blocks_in_memory);
        let limit = drop_before.min(block_data.len());
        if limit <= 1 {
            return;
        }
        // (Genesis block is used in metrics to get genesis timestamp.)
        match block_data {
            BlockData::Dense(entries) => {
                for entry in entries.iter_mut().take(limit).skip(1) {
                    entry.1 = None;
                }
            }
            BlockData::Deferred { entries, .. } => {
                for entry in entries.range_mut(1..limit).map(|(_, entry)| entry) {
                    entry.1 = None;
                }
            }
        }
    }
    /// Returns count of blocks Kura currently holds
    pub fn blocks_count(&self) -> usize {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return 0;
        }
        let data = self.block_data.lock();
        if self.prune_recovery_is_required() {
            return 0;
        }
        data.len()
    }
    /// Return the exact count of blocks durably committed to disk.
    ///
    /// Unlike logical-height and telemetry accessors, this propagates commit
    /// marker/index corruption and conversion failures. Startup and every
    /// authorization decision must use this method so an in-memory height can
    /// never mask an unauthenticated durable boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical storage is poisoned or the durable
    /// commit marker/index cannot be read exactly.
    pub fn exact_durable_blocks_count(&self) -> Result<usize> {
        self.ensure_canonical_storage_not_poisoned()?;
        let count = self.block_store.lock().read_exact_durable_index_count()?;
        usize::try_from(count).map_err(Error::from)
    }
    /// Bind startup replay to one exact durable hash-journal image.
    ///
    /// The returned hashes are read under the same block-store lock as the
    /// authenticated durable count. Callers re-read and compare this value
    /// after prevalidation so a same-height journal replacement cannot be
    /// consumed as though it were the prevalidated chain.
    pub(crate) fn exact_replay_boundary(&self) -> Result<ExactReplayBoundary> {
        self.ensure_canonical_storage_not_poisoned()?;
        let mut store = self.block_store.lock();
        let count = store.read_exact_durable_index_count()?;
        let hashes = store.read_block_hashes(0, usize::try_from(count)?)?;
        if store.read_exact_durable_index_count()? != count {
            return Err(Error::HashesFileHeightMismatch);
        }
        Ok(ExactReplayBoundary { count, hashes })
    }
    /// Return whether this process deliberately skipped historical startup audits.
    pub const fn emergency_fast_startup_enabled(&self) -> bool {
        self.auxiliary_history_deferred
    }
    /// Read the one canonical hash needed to bind a restored snapshot in emergency Fast mode.
    ///
    /// The durable count and requested boundary hash are captured under the canonical-chain and
    /// block-store locks. This deliberately avoids materializing or rereading the historical hash
    /// prefix; Strict startup is responsible for validating every retained height later.
    pub(crate) fn emergency_fast_snapshot_boundary(
        &self,
        snapshot_height: usize,
    ) -> Result<(usize, Option<HashOf<BlockHeader>>)> {
        if !self.emergency_fast_startup_enabled() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "emergency Fast snapshot boundary requested after Strict startup",
                ),
                self.active_blocks_dir.lock().clone(),
            ));
        }
        let _prune_guard = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical_chain_guard = self.canonical_chain_lock.lock();
        self.ensure_canonical_storage_not_poisoned()?;
        let mut store = self.block_store.lock();
        let count = store.read_exact_durable_index_count()?;
        let requested_height = u64::try_from(snapshot_height)?;
        let boundary_hash = if requested_height == 0 || requested_height > count {
            None
        } else {
            store
                .read_block_hashes(requested_height.saturating_sub(1), 1)?
                .first()
                .copied()
        };
        if (requested_height > 0 && requested_height <= count && boundary_hash.is_none())
            || store.read_exact_durable_index_count()? != count
        {
            return Err(Error::HashesFileHeightMismatch);
        }
        Ok((usize::try_from(count)?, boundary_hash))
    }
    /// Map the exact durable hash prefix used by emergency Fast state reads.
    ///
    /// The mapping is copy-on-write and read-only, so startup neither copies
    /// the complete journal nor permits State to mutate it. Kura's exclusive
    /// store lock keeps the mapped file from being truncated by another node
    /// process; this Fast process never starts a writer.
    pub(crate) fn emergency_fast_snapshot_hash_mapping(
        &self,
        snapshot_height: usize,
    ) -> Result<Option<ReadOnlyMmap>> {
        if !self.emergency_fast_startup_enabled() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "emergency Fast hash mapping requested after Strict startup",
                ),
                self.active_blocks_dir.lock().clone(),
            ));
        }
        let _prune_guard = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical_chain_guard = self.canonical_chain_lock.lock();
        self.ensure_canonical_storage_not_poisoned()?;
        let mut store = self.block_store.lock();
        let durable_count = store.read_exact_durable_index_count()?;
        if usize::try_from(durable_count)? != snapshot_height {
            return Err(Error::HashesFileHeightMismatch);
        }
        if snapshot_height == 0 {
            return Ok(None);
        }
        let byte_len = snapshot_height
            .checked_mul(Hash::LENGTH)
            .ok_or(Error::HashesFileHeightMismatch)?;
        let hashes_path = store.path_to_blockchain.join(HASHES_FILE_NAME);
        let hashes_file = store.hashes_file.as_mut().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::NotFound,
                    "emergency Fast hash journal is not open read-only",
                ),
                hashes_path,
            )
        })?;
        let file_len = hashes_file.try_io(|file| file.metadata().map(|metadata| metadata.len()))?;
        let mapping = hashes_file
            .try_io(|file| ReadOnlyMmap::copy_read_only_with_file_len(file, byte_len, file_len))?;
        Ok(Some(mapping))
    }
    /// Exclude canonical Kura writers while a validated State result is
    /// consumed. The caller must not invoke a Kura mutation while holding this
    /// lease because canonical mutations acquire the same lock.
    pub(crate) fn canonical_publication_lease(&self) -> PublicationGuard<'_> {
        self.canonical_chain_lock.lock()
    }
    /// Return a best-effort durable count for diagnostics and telemetry only.
    ///
    /// Security, startup, replay, and mutation decisions must use
    /// [`Self::exact_durable_blocks_count`] instead.
    pub fn durable_blocks_count_lossy(&self) -> usize {
        if self.canonical_storage_poisoned.load(Ordering::Acquire) {
            return 0;
        }
        #[cfg(test)]
        let force_fallback = self
            .force_durable_blocks_count_fallback
            .swap(false, Ordering::AcqRel);
        let durable_count = {
            #[cfg(test)]
            if force_fallback {
                None
            } else {
                self.exact_durable_blocks_count().ok()
            }
            #[cfg(not(test))]
            {
                self.exact_durable_blocks_count().ok()
            }
        };
        #[cfg(test)]
        if force_fallback {
            self.durable_blocks_count_fallback_reached
                .store(true, Ordering::Release);
        }
        durable_count.unwrap_or_else(|| self.blocks_count())
    }
    /// Return the canonical block hash recorded at `height` without decoding the block body.
    pub fn block_hash_at_height(&self, height: NonZeroUsize) -> Option<HashOf<BlockHeader>> {
        if self.prune_recovery_is_required()
            || self.canonical_storage_poisoned.load(Ordering::Acquire)
        {
            return None;
        }
        if self.emergency_fast_startup_enabled() {
            return self.get_durable_block_hash(height);
        }
        let data = self.block_data.lock();
        if self.prune_recovery_is_required() {
            return None;
        }
        data.get(height.get().saturating_sub(1))
            .map(|(hash, _)| *hash)
    }
}
include!("kura/block_store_definition_and_test_controls.rs");
/// Read-only mirror of the block data file backed either by a memory mapping or a heap copy.
#[derive(Clone)]
enum MemoryMirror {
    /// OS-backed memory map sharing pages with the data file (copy-on-write).
    Mapped(Arc<ReadOnlyMmap>),
    /// Heap-backed copy used as a portable fallback when memory mapping is unavailable.
    Heap(Arc<[u8]>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryMirrorKind {
    /// Mirror is backed by an OS memory map.
    MemoryMapped,
    /// Mirror contains a heap-allocated copy of the file contents.
    HeapCopy,
}
impl MemoryMirror {
    fn from_mmap(map: ReadOnlyMmap) -> Self {
        Self::Mapped(Arc::new(map))
    }
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::Heap(Arc::from(bytes.into_boxed_slice()))
    }
    fn len(&self) -> usize {
        match self {
            Self::Mapped(map) => map.len(),
            Self::Heap(bytes) => bytes.len(),
        }
    }
    fn slice(&self, start: usize, end: usize) -> &[u8] {
        match self {
            Self::Mapped(map) => &map[start..end],
            Self::Heap(bytes) => &bytes[start..end],
        }
    }
    fn kind(&self) -> MemoryMirrorKind {
        match self {
            Self::Mapped(_) => MemoryMirrorKind::MemoryMapped,
            Self::Heap(_) => MemoryMirrorKind::HeapCopy,
        }
    }
    fn from_file(file: &mut std::fs::File, len: usize, file_len: u64) -> std::io::Result<Self> {
        match ReadOnlyMmap::copy_read_only_with_file_len(file, len, file_len) {
            Ok(map) => Ok(Self::from_mmap(map)),
            Err(map_err) => {
                iroha_logger::debug!(
                    ?map_err,
                    "failed to memory-map block data; falling back to heap mirror"
                );
                file.seek(SeekFrom::Start(0))?;
                let mut buffer = Vec::with_capacity(len);
                {
                    let mut reader = file.take(len as u64);
                    reader.read_to_end(&mut buffer)?;
                    if buffer.len() != len {
                        return Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            format!(
                                "expected {len} bytes while mirroring block data, read {} bytes",
                                buffer.len()
                            ),
                        ));
                    }
                }
                Ok(Self::from_bytes(buffer))
            }
        }
    }
}
#[derive(Default, Debug, Clone, Copy)]
/// Lightweight wrapper for block indices in the block index file
pub struct BlockIndex {
    /// Start of block in bytes
    pub start: u64,
    /// Length of block section in bytes
    pub length: u64,
}
impl BlockIndex {
    fn is_evicted(&self) -> bool {
        self.start == EVICTED_BLOCK_START
    }
}
impl BlockIndex {
    const SIZE: u64 = core::mem::size_of::<Self>() as u64;
    const SIZE_USIZE: usize = core::mem::size_of::<Self>();
    fn encode(self) -> [u8; Self::SIZE_USIZE] {
        let mut out = [0u8; Self::SIZE_USIZE];
        out[..core::mem::size_of::<u64>()].copy_from_slice(&self.start.to_le_bytes());
        out[core::mem::size_of::<u64>()..].copy_from_slice(&self.length.to_le_bytes());
        out
    }
    fn read(
        file: &mut std::fs::File,
        buff: &mut [u8; core::mem::size_of::<u64>()],
    ) -> std::io::Result<Self> {
        fn read_u64(
            file: &mut std::fs::File,
            buff: &mut [u8; core::mem::size_of::<u64>()],
        ) -> std::io::Result<u64> {
            file.read_exact(buff).map(|()| u64::from_le_bytes(*buff))
        }
        Ok(Self {
            start: read_u64(file, buff)?,
            length: read_u64(file, buff)?,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::BlockStoreCommitMarker")]
struct BlockStoreCommitMarker {
    /// Marker format version (v1).
    version: u32,
    /// Count of blocks that are fully durable on disk.
    count: u64,
    /// Canonical header hash at `count`, or `None` for the empty chain.
    tip_hash: Option<HashOf<BlockHeader>>,
}
/// Exact old or replacement image for one height in a staged canonical rewrite.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::DaBlockRewriteImageV1")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
struct DaBlockRewriteImageV1 {
    /// One-based canonical block height.
    height: u64,
    /// Canonical block-header hash journal value.
    block_hash: HashOf<BlockHeader>,
    /// Raw block-index start value.
    index_start: u64,
    /// Raw framed-block length committed by the index.
    index_length: u64,
    /// Exact original canonical framed block bytes.
    body: Vec<u8>,
}
impl DaBlockRewriteImageV1 {
    fn index(&self) -> BlockIndex {
        BlockIndex {
            start: self.index_start,
            length: self.index_length,
        }
    }
}
/// Write-ahead record making DA-sidecar and canonical-journal rewrites recoverable.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::DaBlockRewriteStageV1")]
struct DaBlockRewriteStageV1 {
    /// Stage format version.
    format_version: u16,
    /// Durable marker before the rewrite began.
    old_marker: BlockStoreCommitMarker,
    /// Marker published only after all replacement journal files are durable.
    new_marker: BlockStoreCommitMarker,
    /// Exact old data-file length.
    old_data_len: u64,
    /// Exact old index-journal entry count.
    old_index_count: u64,
    /// Exact old hash-journal entry count.
    old_hash_count: u64,
    /// Complete old suffix beginning at the first rewritten height.
    old_suffix: Vec<DaBlockRewriteImageV1>,
    /// Complete replacement suffix supplied by the caller.
    replacement: Vec<DaBlockRewriteImageV1>,
}
/// Exact canonical identity of one body moved to DA storage by compaction.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::EvictionCompactionEntryV1")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
struct EvictionCompactionEntryV1 {
    /// One-based canonical block height.
    height: u64,
    /// Canonical header hash at `height`.
    block_hash: HashOf<BlockHeader>,
    /// Hash of the complete framed signed-block wire image.
    canonical_wire_hash: Hash,
    /// Exact framed signed-block byte length retained in the evicted index entry.
    wire_len: u64,
}
/// Roll-forward manifest for the two-file body-eviction compaction publication.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::EvictionCompactionStageV1")]
struct EvictionCompactionStageV1 {
    /// Stage format version.
    format_version: u16,
    /// Exact durable commit marker that must remain unchanged by compaction.
    marker: BlockStoreCommitMarker,
    /// Byte length of the exact canonical marker file.
    marker_len: u64,
    /// Digest of the exact canonical marker file.
    marker_digest: Hash,
    /// Byte length of the exact canonical hash journal.
    hashes_len: u64,
    /// Digest of the exact canonical hash journal.
    hashes_digest: Hash,
    /// Fixed basename of the synced replacement data file.
    data_temp_name: String,
    /// Exact replacement data-file length.
    data_len: u64,
    /// Digest of the exact replacement data file.
    data_digest: Hash,
    /// Fixed basename of the synced replacement index file.
    index_temp_name: String,
    /// Exact replacement index-file length.
    index_len: u64,
    /// Digest of the exact replacement index file.
    index_digest: Hash,
    /// Dense canonical identities of all bodies newly moved to DA storage.
    evicted: Vec<EvictionCompactionEntryV1>,
}
/// Exact authenticated canonical hash-journal image used by startup replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExactReplayBoundary {
    pub(crate) count: u64,
    pub(crate) hashes: Vec<HashOf<BlockHeader>>,
}
impl BlockStoreCommitMarker {
    const VERSION: u32 = 1;
    fn new(count: u64, tip_hash: Option<HashOf<BlockHeader>>) -> Self {
        debug_assert_eq!(count == 0, tip_hash.is_none());
        Self {
            version: Self::VERSION,
            count,
            tip_hash,
        }
    }
}
include!("kura/pipeline_and_lane_artifacts.rs");
impl Kura {
    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0)
    }
    /// Return the path to the block storage directory, if configured.
    /// For in-memory test Kura, returns `None`.
    fn store_dir(&self) -> Option<PathBuf> {
        let path = self.block_store.lock().path_to_blockchain.clone();
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }
    fn sidecar_fsync_mode(&self) -> FsyncMode {
        self.block_store.lock().fsync.mode
    }
}
impl Kura {
    fn hash_path_component(hash: &Hash) -> String {
        Self::fixed_bytes_path_component(hash.as_ref())
    }
    fn network_id_path_component(network_id: &iroha_data_model::NetworkId) -> String {
        Self::fixed_bytes_path_component(network_id.as_bytes())
    }
    fn fixed_bytes_path_component(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
        encoded
    }
    fn invalid_lane_artifact_error(path: PathBuf, message: impl Into<String>) -> Error {
        Error::IO(
            std::io::Error::new(ErrorKind::InvalidData, message.into()),
            path,
        )
    }
    const fn maximum_index_growth_for_unresolved_sidecar_write(_height: u64) -> u64 {
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64
            + (MAX_INDEXED_SIDECAR_GAP_ENTRIES + 1) * PIPELINE_INDEX_ENTRY_SIZE_U64
    }
}
impl Kura {
    fn ensure_bound_progress_pair_has_no_recovery_artifacts_locked(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.ensure_bound_progress_recovery_absent_with_observer(
                namespace,
                data_path,
                index_path,
                kind,
                |_| {},
            )
        }
        #[cfg(not(unix))]
        {
            let paths = [
                data_path.with_extension("norito.tmp"),
                index_path.with_extension("index.tmp"),
                index_path.with_extension("index.prepend.tmp"),
                Self::bound_progress_append_build_path(index_path),
                Self::bound_progress_append_intent_path(index_path),
            ];
            for path in paths {
                if self
                    .open_optional_bound_progress_file(namespace, &path)?
                    .is_some()
                {
                    return Err(Self::invalid_lane_artifact_error(
                        path,
                        format!(
                            "{kind} has unresolved recovery state; read-only startup planning cannot mutate it"
                        ),
                    ));
                }
            }
            Ok(())
        }
    }
    /// Prove absence of the fixed recovery inventory through held parent handles.
    /// The observer is a no-op in production and injects filesystem races in tests.
    #[cfg(unix)]
    fn ensure_bound_progress_recovery_absent_with_observer<F>(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
        mut after_lookup: F,
    ) -> Result<()>
    where
        F: FnMut(usize),
    {
        let invalid = |path: &Path, message: &str| {
            Self::invalid_lane_artifact_error(path.to_path_buf(), message)
        };
        let immediate = namespace.directories.first().ok_or_else(|| {
            invalid(
                data_path,
                "bound recovery namespace has no immediate directory",
            )
        })?;
        if namespace.data_path != data_path
            || namespace.index_path != index_path
            || data_path.parent() != Some(immediate.expected_path.as_path())
            || index_path.parent() != Some(immediate.expected_path.as_path())
            || !self.bound_progress_namespace_unchanged(namespace)
        {
            return Err(invalid(
                data_path,
                "bound recovery namespace differs from the exact pair",
            ));
        }
        let before = secure_file_metadata::from_file(&immediate.file)
            .map_err(|error| Error::IO(error, immediate.expected_path.clone()))?;
        if !before.is_dir()
            || !Self::sidecar_directory_binding_unchanged(&immediate.metadata, &before)
        {
            return Err(invalid(
                data_path,
                "bound recovery directory changed before absence scan",
            ));
        }
        for (ordinal, path) in [
            data_path.with_extension("norito.tmp"),
            index_path.with_extension("index.tmp"),
            index_path.with_extension("index.prepend.tmp"),
            Self::bound_progress_append_build_path(index_path),
            Self::bound_progress_append_intent_path(index_path),
        ]
        .into_iter()
        .enumerate()
        {
            let name = path
                .file_name()
                .ok_or_else(|| invalid(&path, "bound recovery file has no immediate entry name"))?;
            if path.parent() != Some(immediate.expected_path.as_path()) {
                return Err(invalid(
                    &path,
                    "bound recovery file is outside its exact parent",
                ));
            }
            let observed =
                rustix::fs::statat(&immediate.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
            after_lookup(ordinal);
            match observed {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(Error::IO(std::io::Error::from(error), path)),
                Ok(metadata) => {
                    if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                        != rustix::fs::FileType::RegularFile
                        || metadata.st_nlink != 1
                    {
                        return Err(invalid(
                            &path,
                            "recovery path is not a single-link regular file",
                        ));
                    }
                    return Err(Self::invalid_lane_artifact_error(
                        path,
                        format!(
                            "{kind} has unresolved recovery state; read-only startup planning cannot mutate it"
                        ),
                    ));
                }
            }
        }
        let after = secure_file_metadata::from_file(&immediate.file)
            .map_err(|error| Error::IO(error, immediate.expected_path.clone()))?;
        if !Self::sidecar_directory_metadata_unchanged(&before, &after)
            || !self.bound_progress_namespace_unchanged(namespace)
        {
            return Err(invalid(
                data_path,
                "bound recovery namespace changed during absence scan",
            ));
        }
        Ok(())
    }
}
impl Kura {}
impl Kura {}
include!("kura/sidecar_physical_resource_accounting.rs");
include!("kura/indexed_sidecar_io.rs");
include!("kura/native_execution_reads.rs");
#[cfg(test)]
#[path = "kura/native_compaction_recovery_tests.rs"]
mod native_compaction_recovery_tests;
#[cfg(test)]
#[path = "kura/native_journal_tests.rs"]
mod native_journal_tests;
include!("kura/indexed_sidecar_rewrite.rs");
impl BlockStore {
    /// Create a new block store in `path`.
    pub fn new(store_path: impl AsRef<Path>) -> Self {
        Self::with_fsync(store_path, FsyncMode::Always, FSYNC_INTERVAL)
    }
    /// Open an existing block store for inspection without creating or
    /// requesting write access to any canonical journal.
    ///
    /// All three journals are opened eagerly so a missing or non-regular file
    /// fails before an inspector consumes a partial store.
    ///
    /// # Errors
    /// Returns an I/O error when a canonical journal cannot be opened read-only.
    pub fn open_read_only(store_path: impl AsRef<Path>) -> Result<Self> {
        let mut store = Self::with_fsync(store_path, FsyncMode::Always, FSYNC_INTERVAL);
        store.read_only = true;
        store.data_file = Some(FileWrap::open_read_only(
            store.path_to_blockchain.join(DATA_FILE_NAME),
        )?);
        store.index_file = Some(FileWrap::open_read_only(
            store.path_to_blockchain.join(INDEX_FILE_NAME),
        )?);
        store.hashes_file = Some(FileWrap::open_read_only(
            store.path_to_blockchain.join(HASHES_FILE_NAME),
        )?);
        Ok(store)
    }
    /// Create a new block store in `path` with an explicit fsync policy.
    pub fn with_fsync(
        store_path: impl AsRef<Path>,
        fsync_mode: FsyncMode,
        fsync_interval: Duration,
    ) -> Self {
        let path_to_blockchain = store_path.as_ref().to_path_buf();
        Self {
            da_blocks_dir: path_to_blockchain.join(DA_BLOCKS_DIR_NAME),
            path_to_blockchain,
            read_only: false,
            data_file: None,
            index_file: None,
            hashes_file: None,
            fsync: FsyncState::new(fsync_mode, fsync_interval),
            fsync_telemetry: FsyncTelemetry::new(fsync_mode),
            read_scratch: Vec::new(),
            data_mmap: None,
            data_mmap_len: 0,
            #[cfg(test)]
            body_bytes_read: AtomicU64::new(0),
            #[cfg(test)]
            body_read_calls: AtomicUsize::new(0),
            fast_prevalidated_count: None,
            commit_marker_count: 0,
            commit_marker_pending: None,
            deferred_da_recovery_fault: None,
            #[cfg(test)]
            fail_next_da_rewrite_before_marker: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_da_rewrite_after_marker: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_da_rewrite_recovery: AtomicBool::new(false),
            #[cfg(test)]
            crash_next_da_rewrite_before_marker: AtomicBool::new(false),
            #[cfg(test)]
            crash_next_da_rewrite_after_marker: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_after_temp_sync: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_read: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_ack_after_persist: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_write_and_readback: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_commit_marker_ack_and_readback: AtomicBool::new(false),
            #[cfg(test)]
            crash_next_eviction_after_stage: AtomicBool::new(false),
            #[cfg(test)]
            crash_next_eviction_after_data_promotion: AtomicBool::new(false),
            #[cfg(test)]
            crash_next_eviction_after_index_promotion: AtomicBool::new(false),
            #[cfg(test)]
            fail_eviction_stage_syncs_remaining: AtomicUsize::new(0),
        }
    }
    fn da_block_path(&self, height: u64) -> PathBuf {
        self.da_blocks_dir.join(format!("{height:020}.norito"))
    }
    fn ensure_da_blocks_dir(&self) -> Result<()> {
        if self.da_blocks_dir.as_os_str().is_empty() {
            return Ok(());
        }
        let (_, root_before) = Kura::canonical_sidecar_directory_for(
            &self.path_to_blockchain,
            &self.path_to_blockchain,
        )?
        .ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "canonical block directory is missing"),
                self.path_to_blockchain.clone(),
            )
        })?;
        match std::fs::create_dir(&self.da_blocks_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(Error::MkDir(error, self.da_blocks_dir.clone())),
        }
        let (_, root_after) = Kura::canonical_sidecar_directory_for(
            &self.path_to_blockchain,
            &self.path_to_blockchain,
        )?
        .ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::NotFound,
                    "canonical block directory disappeared while creating the DA cache",
                ),
                self.path_to_blockchain.clone(),
            )
        })?;
        if !Kura::sidecar_metadata_same_object(&root_before, &root_after)
            || Kura::canonical_sidecar_directory_for(&self.path_to_blockchain, &self.da_blocks_dir)?
                .is_none()
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "DA cache directory changed identity during creation",
                ),
                self.da_blocks_dir.clone(),
            ));
        }
        sync_dir(&self.path_to_blockchain)
            .map_err(|error| Error::IO(error, self.path_to_blockchain.clone()))
    }
    fn eviction_compaction_stage_path(&self) -> PathBuf {
        self.path_to_blockchain
            .join(EVICTION_COMPACTION_STAGE_FILE_NAME)
    }
    fn eviction_compaction_data_path(&self) -> PathBuf {
        self.path_to_blockchain
            .join(EVICTION_COMPACTION_DATA_FILE_NAME)
    }
    fn eviction_compaction_index_path(&self) -> PathBuf {
        self.path_to_blockchain
            .join(EVICTION_COMPACTION_INDEX_FILE_NAME)
    }
    fn invalid_eviction_compaction_stage(&self, message: impl Into<String>) -> Error {
        Error::IO(
            std::io::Error::new(ErrorKind::InvalidData, message.into()),
            self.eviction_compaction_stage_path(),
        )
    }
    fn eviction_reader_digest(reader: &mut impl Read, total: u64) -> std::io::Result<Hash> {
        let mut digest = Hash::new(EVICTION_FILE_DIGEST_DOMAIN);
        let mut remaining = total;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let chunk_len = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("fixed eviction digest chunk length fits usize");
            reader.read_exact(&mut buffer[..chunk_len])?;
            let chunk_len_bytes = (chunk_len as u64).to_le_bytes();
            digest = Hash::new_from_chunks(&[
                EVICTION_FILE_DIGEST_DOMAIN,
                digest.as_ref(),
                chunk_len_bytes.as_slice(),
                &buffer[..chunk_len],
            ]);
            remaining -= chunk_len as u64;
        }
        let total_bytes = total.to_le_bytes();
        Ok(Hash::new_from_chunks(&[
            EVICTION_FILE_DIGEST_DOMAIN,
            digest.as_ref(),
            total_bytes.as_slice(),
        ]))
    }
    fn eviction_file_digest(path: &Path) -> Result<(u64, Hash)> {
        let before = secure_file_metadata::from_path(path)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || !Kura::sidecar_is_single_link(&before)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "eviction file digest target is not a single-link regular file",
                ),
                path.to_path_buf(),
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let opened = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if !opened.is_file() || !Kura::sidecar_file_metadata_unchanged(&before, &opened) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "eviction file changed while it was opened for hashing",
                ),
                path.to_path_buf(),
            ));
        }
        let total = before.len();
        let digest = Self::eviction_reader_digest(&mut file, total)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let after_handle = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let after_path = secure_file_metadata::from_path(path)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if !Kura::sidecar_file_metadata_unchanged(&before, &after_handle)
            || !Kura::sidecar_file_metadata_unchanged(&before, &after_path)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "eviction file changed while it was being hashed",
                ),
                path.to_path_buf(),
            ));
        }
        Ok((total, digest))
    }
    fn eviction_file_matches(
        path: &Path,
        expected_len: u64,
        expected_digest: Hash,
    ) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "eviction compaction file is not a regular file",
                        ),
                        path.to_path_buf(),
                    ));
                }
                if metadata.len() != expected_len {
                    return Ok(false);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(Error::IO(error, path.to_path_buf())),
        }
        let (actual_len, actual_digest) = Self::eviction_file_digest(path)?;
        Ok(actual_len == expected_len && actual_digest == expected_digest)
    }
    fn validate_eviction_compaction_stage(&self, stage: &EvictionCompactionStageV1) -> Result<()> {
        let expected_index_len = stage
            .marker
            .count
            .checked_mul(BlockIndex::SIZE)
            .ok_or_else(|| {
                self.invalid_eviction_compaction_stage("eviction index length overflowed")
            })?;
        let expected_hashes_len = stage
            .marker
            .count
            .checked_mul(u64::try_from(Hash::LENGTH)?)
            .ok_or_else(|| {
                self.invalid_eviction_compaction_stage("eviction hash length overflowed")
            })?;
        if stage.format_version != EVICTION_COMPACTION_STAGE_VERSION
            || stage.marker.version != BlockStoreCommitMarker::VERSION
            || stage.marker.count < 2
            || stage.marker.tip_hash.is_none()
            || stage.marker_len == 0
            || stage.hashes_len != expected_hashes_len
            || stage.data_temp_name != EVICTION_COMPACTION_DATA_FILE_NAME
            || stage.index_temp_name != EVICTION_COMPACTION_INDEX_FILE_NAME
            || stage.index_len != expected_index_len
            || stage.evicted.is_empty()
            || stage.evicted.len() > MAX_EVICTION_COMPACTION_ENTRIES
        {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage envelope is inconsistent",
            ));
        }
        let mut previous_height = 0_u64;
        for entry in &stage.evicted {
            if entry.height <= 1
                || entry.height > stage.marker.count
                || entry.height <= previous_height
                || entry.wire_len == 0
                || entry.wire_len > STRICT_INIT_MAX_BLOCK_BYTES
            {
                return Err(self.invalid_eviction_compaction_stage(
                    "eviction compaction entry is out of bounds or not strictly ordered",
                ));
            }
            previous_height = entry.height;
        }
        Ok(())
    }
    fn read_eviction_compaction_stage(&self) -> Result<Option<EvictionCompactionStageV1>> {
        let path = self.eviction_compaction_stage_path();
        let byte_limit = usize::try_from(MAX_EVICTION_COMPACTION_STAGE_BYTES)?;
        let Some(bytes) = Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &path,
            &self.path_to_blockchain,
            byte_limit,
        )?
        else {
            return Ok(None);
        };
        let stage =
            norito::decode_canonical::<EvictionCompactionStageV1>(&bytes).map_err(|error| {
                match error {
                    norito::Error::NonCanonicalEncoding => self.invalid_eviction_compaction_stage(
                        "eviction compaction stage is not canonically encoded",
                    ),
                    other => Error::NoritoFrame(other.into()),
                }
            })?;
        self.validate_eviction_compaction_stage(&stage)?;
        Ok(Some(stage))
    }
    fn sync_eviction_compaction_stage(&self, expected: &EvictionCompactionStageV1) -> Result<()> {
        let path = self.eviction_compaction_stage_path();
        if self.read_eviction_compaction_stage()?.as_ref() != Some(expected) {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage changed before durability acknowledgement",
            ));
        }
        #[cfg(test)]
        if self
            .fail_eviction_stage_syncs_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(Error::IO(
                std::io::Error::other("injected eviction-stage durability failure"),
                path,
            ));
        }
        let before = secure_file_metadata::from_path(&path)
            .map_err(|error| Error::IO(error, path.clone()))?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || !Kura::sidecar_is_single_link(&before)
        {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage is not a single-link regular file",
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| Error::IO(error, path.clone()))?;
        let opened = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.clone()))?;
        if !Kura::sidecar_file_metadata_unchanged(&before, &opened) {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage changed while opening for sync",
            ));
        }
        file.sync_all()
            .map_err(|error| Error::IO(error, path.clone()))?;
        let after = secure_file_metadata::from_path(&path)
            .map_err(|error| Error::IO(error, path.clone()))?;
        if !Kura::sidecar_file_metadata_unchanged(&before, &after) {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage changed while being synchronized",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "eviction compaction stage has no parent",
                ),
                path.clone(),
            )
        })?;
        sync_dir(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        if self.read_eviction_compaction_stage()?.as_ref() != Some(expected) {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage changed after durability acknowledgement",
            ));
        }
        Ok(())
    }
    fn write_eviction_compaction_stage(&self, stage: &EvictionCompactionStageV1) -> Result<()> {
        self.validate_eviction_compaction_stage(stage)?;
        let path = self.eviction_compaction_stage_path();
        if self.read_eviction_compaction_stage()?.is_some() {
            return Err(self.invalid_eviction_compaction_stage(
                "a prior eviction compaction stage is still present",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "eviction compaction stage has no parent",
                ),
                path.clone(),
            )
        })?;
        let bytes = norito::encode_canonical(stage).map_err(Error::NoritoFrame)?;
        if u64::try_from(bytes.len())? > MAX_EVICTION_COMPACTION_STAGE_BYTES {
            return Err(self.invalid_eviction_compaction_stage(
                "eviction compaction stage exceeds its hard size limit",
            ));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".kura-eviction-stage-")
            .tempfile_in(parent)
            .map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        temporary
            .as_file_mut()
            .write_all(&bytes)
            .and_then(|()| temporary.as_file_mut().flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| Error::IO(error, path.clone()))?;
        let persisted = temporary
            .persist_noclobber(&path)
            .map_err(|error| Error::IO(error.error, path.clone()))?;
        drop(persisted);
        self.sync_eviction_compaction_stage(stage)
    }
    fn remove_eviction_compaction_path(&self, path: &Path) -> Result<bool> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(Error::IO(error, path.to_path_buf())),
        }
    }
    fn cleanup_unpublished_eviction_compaction_files(&self) -> Result<()> {
        let data = self.eviction_compaction_data_path();
        let index = self.eviction_compaction_index_path();
        let removed = self.remove_eviction_compaction_path(&data)?
            | self.remove_eviction_compaction_path(&index)?;
        if removed {
            sync_dir(&self.path_to_blockchain)
                .map_err(|error| Error::IO(error, self.path_to_blockchain.clone()))?;
        }
        Ok(())
    }
    fn read_optional_da_cache(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let path = self.da_block_path(height);
        Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &path,
            &self.da_blocks_dir,
            usize::try_from(STRICT_INIT_MAX_BLOCK_BYTES)?,
        )
    }
    fn validate_eviction_compaction_result(
        &mut self,
        stage: &EvictionCompactionStageV1,
    ) -> Result<()> {
        let data_path = self.path_to_blockchain.join(DATA_FILE_NAME);
        let index_path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        if !Self::eviction_file_matches(&data_path, stage.data_len, stage.data_digest)?
            || !Self::eviction_file_matches(&index_path, stage.index_len, stage.index_digest)?
        {
            return Err(self.invalid_eviction_compaction_stage(
                "promoted eviction data/index files do not match their manifest",
            ));
        }
        self.drop_cached_handles();
        let mut staged = stage
            .evicted
            .iter()
            .map(|entry| (entry.height, entry))
            .collect::<BTreeMap<_, _>>();
        let mut inline_cursor = 0_u64;
        for index_position in 0..stage.marker.count {
            let height = index_position.saturating_add(1);
            let index = self.read_block_index(index_position)?;
            if index.length > STRICT_INIT_MAX_BLOCK_BYTES
                || (index.length == 0 && !index.is_evicted())
            {
                return Err(self.invalid_eviction_compaction_stage(
                    "promoted eviction index contains an invalid block length",
                ));
            }
            let durable_hash = self
                .read_block_hashes(index_position, 1)?
                .first()
                .copied()
                .ok_or_else(|| {
                    self.invalid_eviction_compaction_stage(
                        "promoted index has no durable hash-journal identity",
                    )
                })?;
            let staged_entry = staged.remove(&height);
            if index.length == 0 {
                if staged_entry.is_some() {
                    return Err(self.invalid_eviction_compaction_stage(
                        "new eviction entry cannot target a hash-only canonical index",
                    ));
                }
                continue;
            }
            if !index.is_evicted() {
                if staged_entry.is_some() {
                    return Err(self.invalid_eviction_compaction_stage(
                        "new eviction entry remained inline after promotion",
                    ));
                }
                if index.start != inline_cursor {
                    return Err(self.invalid_eviction_compaction_stage(
                        "promoted inline indices are not densely compacted",
                    ));
                }
                let mut bytes = vec![0_u8; usize::try_from(index.length)?];
                self.read_block_data(index.start, &mut bytes)?;
                inline_cursor = inline_cursor.checked_add(index.length).ok_or_else(|| {
                    self.invalid_eviction_compaction_stage("promoted inline data cursor overflowed")
                })?;
                let block = decode_framed_signed_block(&bytes)?;
                if block.header().height().get() != height || block.hash() != durable_hash {
                    return Err(self.invalid_eviction_compaction_stage(
                        "promoted inline block mismatches its durable height or header hash",
                    ));
                }
                continue;
            }
            let cached = self.read_optional_da_cache(height)?;
            if let Some(entry) = staged_entry {
                let bytes = cached.ok_or_else(|| {
                    self.invalid_eviction_compaction_stage(
                        "newly evicted canonical body is missing from its DA sidecar",
                    )
                })?;
                if u64::try_from(bytes.len())? != index.length
                    || index.length != entry.wire_len
                    || durable_hash != entry.block_hash
                    || Hash::new(&bytes) != entry.canonical_wire_hash
                {
                    return Err(self.invalid_eviction_compaction_stage(
                        "newly evicted body mismatches its staged or signed complete-wire binding",
                    ));
                }
                let block = decode_framed_signed_block(&bytes)?;
                if block.header().height().get() != height || block.hash() != durable_hash {
                    return Err(self.invalid_eviction_compaction_stage(
                        "newly evicted block mismatches its durable height or header hash",
                    ));
                }
            } else if let Some(bytes) = cached {
                if u64::try_from(bytes.len())? == index.length {
                    let block = decode_framed_signed_block(&bytes)?;
                    if block.header().height().get() != height || block.hash() != durable_hash {
                        return Err(self.invalid_eviction_compaction_stage(
                            "prior cached eviction mismatches its durable height or header hash",
                        ));
                    }
                } else {
                    return Err(self.invalid_eviction_compaction_stage(
                        "prior DA frame length differs from canonical index",
                    ));
                }
            }
        }
        if inline_cursor != stage.data_len || !staged.is_empty() {
            return Err(self.invalid_eviction_compaction_stage(
                "promoted eviction files do not consume the exact staged data or entry set",
            ));
        }
        Ok(())
    }
    fn promote_eviction_compaction_file(
        &self,
        live_path: &Path,
        temp_path: &Path,
        expected_len: u64,
        expected_digest: Hash,
    ) -> Result<()> {
        if Self::eviction_file_matches(live_path, expected_len, expected_digest)? {
            let _ = self.remove_eviction_compaction_path(temp_path)?;
            return Ok(());
        }
        if !Self::eviction_file_matches(temp_path, expected_len, expected_digest)? {
            return Err(self.invalid_eviction_compaction_stage(
                "neither live nor temporary eviction file matches the manifest",
            ));
        }
        #[cfg(windows)]
        {
            // Windows does not replace an open destination with `rename`. The durable
            // stage makes remove-then-rename safe: a crash between them leaves the exact
            // replacement under its authenticated temporary name for startup recovery.
            match std::fs::remove_file(live_path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(Error::IO(error, live_path.to_path_buf())),
            }
            std::fs::rename(temp_path, live_path)
                .map_err(|error| Error::IO(error, live_path.to_path_buf()))
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(temp_path, live_path)
                .map_err(|error| Error::IO(error, live_path.to_path_buf()))
        }
    }
    fn recover_eviction_compaction_stage(&mut self) -> Result<()> {
        let Some(stage) = self.read_eviction_compaction_stage()? else {
            return self.cleanup_unpublished_eviction_compaction_files();
        };
        let current_marker = self.read_commit_marker()?;
        if current_marker.as_ref() != Some(&stage.marker) {
            return Err(self.invalid_eviction_compaction_stage(
                "durable commit marker changed while eviction compaction was staged",
            ));
        }
        let marker_path = self.commit_marker_path();
        let (marker_len, marker_digest) = Self::eviction_file_digest(&marker_path)?;
        let hashes_path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let (hashes_len, hashes_digest) = Self::eviction_file_digest(&hashes_path)?;
        if marker_len != stage.marker_len
            || marker_digest != stage.marker_digest
            || hashes_len != stage.hashes_len
            || hashes_digest != stage.hashes_digest
        {
            return Err(self.invalid_eviction_compaction_stage(
                "durable marker or hash journal changed while eviction compaction was staged",
            ));
        }
        #[cfg(test)]
        if self
            .crash_next_eviction_after_stage
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other(
                    "injected abrupt stop after eviction compaction stage publication",
                ),
                self.eviction_compaction_stage_path(),
            ));
        }
        self.drop_cached_handles();
        let data_path = self.path_to_blockchain.join(DATA_FILE_NAME);
        let index_path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let data_temp = self.eviction_compaction_data_path();
        let index_temp = self.eviction_compaction_index_path();
        self.promote_eviction_compaction_file(
            &data_path,
            &data_temp,
            stage.data_len,
            stage.data_digest,
        )?;
        #[cfg(test)]
        if self
            .crash_next_eviction_after_data_promotion
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other("injected abrupt stop after eviction data-file promotion"),
                self.eviction_compaction_stage_path(),
            ));
        }
        self.promote_eviction_compaction_file(
            &index_path,
            &index_temp,
            stage.index_len,
            stage.index_digest,
        )?;
        #[cfg(test)]
        if self
            .crash_next_eviction_after_index_promotion
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other("injected abrupt stop after eviction index-file promotion"),
                self.eviction_compaction_stage_path(),
            ));
        }
        sync_dir(&self.path_to_blockchain)
            .map_err(|error| Error::IO(error, self.path_to_blockchain.clone()))?;
        self.validate_eviction_compaction_result(&stage)?;
        let stage_path = self.eviction_compaction_stage_path();
        let removed = self.remove_eviction_compaction_path(&data_temp)?
            | self.remove_eviction_compaction_path(&index_temp)?
            | self.remove_eviction_compaction_path(&stage_path)?;
        if removed {
            sync_dir(&self.path_to_blockchain)
                .map_err(|error| Error::IO(error, self.path_to_blockchain.clone()))?;
        }
        self.fsync.clear();
        self.drop_cached_handles();
        Ok(())
    }
    fn recover_canonical_storage_stages(&mut self) -> Result<()> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(());
        }
        self.recover_eviction_compaction_stage()?;
        self.recover_da_block_rewrite_stage()
    }
    fn read_da_block_bytes(&self, height: u64, expected_len: u64) -> Result<Vec<u8>> {
        self.ensure_da_blocks_dir()?;
        let path = self.da_block_path(height);
        let bytes = Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &path,
            &self.da_blocks_dir,
            usize::try_from(STRICT_INIT_MAX_BLOCK_BYTES)?,
        )?
        .ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "DA block cache is missing"),
                path.clone(),
            )
        })?;
        if expected_len > 0 && u64::try_from(bytes.len())? != expected_len {
            warn!(
                height,
                expected_len,
                actual_len = bytes.len(),
                path = %path.display(),
                "DA-backed block payload length mismatched index entry"
            );
        }
        Ok(bytes)
    }
    fn write_da_block_bytes(&self, height: u64, bytes: &[u8]) -> Result<()> {
        if u64::try_from(bytes.len())? > STRICT_INIT_MAX_BLOCK_BYTES {
            return Err(Error::CorruptedBlockLength {
                length: u64::try_from(bytes.len())?,
                limit: STRICT_INIT_MAX_BLOCK_BYTES,
            });
        }
        self.ensure_da_blocks_dir()?;
        let path = self.da_block_path(height);
        let parent = path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "DA sidecar path has no parent directory",
                ),
                path.clone(),
            )
        })?;
        let (canonical_parent, parent_before) =
            Kura::canonical_sidecar_directory_for(&self.path_to_blockchain, parent)?.ok_or_else(
                || {
                    Error::IO(
                        std::io::Error::new(ErrorKind::NotFound, "DA cache directory is missing"),
                        parent.to_path_buf(),
                    )
                },
            )?;
        let _ = Kura::regular_sidecar_metadata_for(&self.path_to_blockchain, &path, parent)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".kura-da-")
            .tempfile_in(&canonical_parent)
            .map_err(|error| Error::IO(error, canonical_parent.clone()))?;
        let (_, parent_after_create) =
            Kura::canonical_sidecar_directory_for(&self.path_to_blockchain, parent)?.ok_or_else(
                || {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::NotFound,
                            "DA cache directory disappeared while creating a temporary file",
                        ),
                        parent.to_path_buf(),
                    )
                },
            )?;
        if !Kura::sidecar_metadata_same_object(&parent_before, &parent_after_create) {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "DA cache directory changed while creating a temporary file",
                ),
                parent.to_path_buf(),
            ));
        }
        temporary
            .as_file_mut()
            .write_all(bytes)
            .map_err(|error| Error::IO(error, path.clone()))?;
        temporary
            .as_file_mut()
            .flush()
            .map_err(|error| Error::IO(error, path.clone()))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| Error::IO(error, path.clone()))?;
        let persisted = temporary
            .persist(&path)
            .map_err(|error| Error::IO(error.error, path.clone()))?;
        persisted
            .sync_all()
            .map_err(|error| Error::IO(error, path.clone()))?;
        let persisted_metadata = secure_file_metadata::from_file(&persisted)
            .map_err(|error| Error::IO(error, path.clone()))?;
        let path_metadata = secure_file_metadata::from_path(&path)
            .map_err(|error| Error::IO(error, path.clone()))?;
        let (_, parent_after_persist) =
            Kura::canonical_sidecar_directory_for(&self.path_to_blockchain, parent)?.ok_or_else(
                || {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::NotFound,
                            "DA cache directory disappeared after publication",
                        ),
                        parent.to_path_buf(),
                    )
                },
            )?;
        if !Kura::sidecar_metadata_same_object(&parent_before, &parent_after_persist)
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || !Kura::sidecar_file_metadata_unchanged(&persisted_metadata, &path_metadata)
            || persisted_metadata.len() != u64::try_from(bytes.len())?
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "DA cache changed during durable publication",
                ),
                path,
            ));
        }
        sync_dir(parent).map_err(|err| Error::IO(err, parent.to_path_buf()))?;
        let readback = Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &path,
            parent,
            bytes.len(),
        )?
        .ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "DA cache disappeared after sync"),
                path.clone(),
            )
        })?;
        if readback != bytes {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "DA cache readback differs from the published block wire",
                ),
                path,
            ));
        }
        Ok(())
    }
    fn remove_da_block_file(&self, height: u64) -> Result<()> {
        self.ensure_da_blocks_dir()?;
        let path = self.da_block_path(height);
        let Some(before) = Kura::regular_sidecar_metadata_for(
            &self.path_to_blockchain,
            &path,
            &self.da_blocks_dir,
        )?
        else {
            return Ok(());
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {
                let (_, parent_after) = Kura::canonical_sidecar_directory_for(
                    &self.path_to_blockchain,
                    &self.da_blocks_dir,
                )?
                .ok_or_else(|| {
                    Error::IO(
                        std::io::Error::new(
                            ErrorKind::NotFound,
                            "DA cache directory disappeared during removal",
                        ),
                        self.da_blocks_dir.clone(),
                    )
                })?;
                if !Kura::sidecar_metadata_same_object(&before.directory, &parent_after) {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "DA cache directory changed during removal",
                        ),
                        self.da_blocks_dir.clone(),
                    ));
                }
                sync_dir(&self.da_blocks_dir)
                    .map_err(|err| Error::IO(err, self.da_blocks_dir.clone()))?;
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Err(Error::IO(err, path)),
            Err(err) => Err(Error::IO(err, path)),
        }
    }
    fn da_block_rewrite_stage_path(&self) -> PathBuf {
        self.path_to_blockchain
            .join(DA_BLOCK_REWRITE_STAGE_FILE_NAME)
    }
    fn defer_da_block_rewrite_recovery(&mut self, error: &Error) {
        let message = error.to_string();
        error!(
            ?error,
            "canonical DA rewrite marker is durable; deferring body promotion recovery"
        );
        self.deferred_da_recovery_fault = Some(message);
    }
    fn take_deferred_da_recovery_fault(&mut self) -> Option<String> {
        self.deferred_da_recovery_fault.take()
    }
    fn unknown_da_rewrite_state(&self, context: &str, error: &Error) -> Error {
        Error::DaBlockRewriteCommitStateUnknown {
            detail: format!("{context}: {error}"),
        }
    }
    fn rollback_da_rewrite_before_returning(&mut self, original_error: Error) -> Error {
        // The replacement marker is not published on this path. Prevent periodic/shutdown fsync
        // from advancing it while rollback is being attempted.
        self.commit_marker_pending = None;
        self.fsync.clear();
        match self.recover_da_block_rewrite_stage() {
            Ok(()) => original_error,
            Err(recovery_error) => {
                self.unknown_da_rewrite_state("pre-marker rollback failed", &recovery_error)
            }
        }
    }
    fn invalid_da_block_rewrite_stage(&self, message: impl Into<String>) -> Error {
        Error::IO(
            std::io::Error::new(ErrorKind::InvalidData, message.into()),
            self.da_block_rewrite_stage_path(),
        )
    }
    fn read_da_block_rewrite_stage(&self) -> Result<Option<DaBlockRewriteStageV1>> {
        let path = self.da_block_rewrite_stage_path();
        let Some(bytes) = Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &path,
            &self.path_to_blockchain,
            usize::try_from(MAX_DA_BLOCK_REWRITE_STAGE_BYTES)?,
        )?
        else {
            return Ok(None);
        };
        self.decode_da_block_rewrite_stage_bytes(bytes).map(Some)
    }
    /// Decode and authenticate one bounded canonical rewrite image without filesystem I/O.
    fn decode_da_block_rewrite_stage_bytes(&self, bytes: Vec<u8>) -> Result<DaBlockRewriteStageV1> {
        let decode_limits = recovery_control_decode_limits_v1(MAX_DA_BLOCK_REWRITE_STAGE_BYTES)?;
        let stage =
            norito::decode_canonical_with_limits::<DaBlockRewriteStageV1>(&bytes, decode_limits)
                .map_err(|error| Error::NoritoFrame(error.into()))?;
        self.validate_da_block_rewrite_stage(&stage)?;
        Ok(stage)
    }
    fn validate_da_block_rewrite_image(&self, image: &DaBlockRewriteImageV1) -> Result<()> {
        if image.height == 0
            || image.index_length == 0
            || image.index_length > STRICT_INIT_MAX_BLOCK_BYTES
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite image has an invalid height or length",
            ));
        }
        if u64::try_from(image.body.len())? != image.index_length {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite image body length mismatches its index",
            ));
        }
        let decoded = decode_framed_signed_block(&image.body)?;
        if decoded.header().height().get() != image.height
            || decoded.hash() != image.block_hash
            || decoded.encode_wire()? != image.body
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite image body mismatches its height, hash or canonical frame",
            ));
        }
        Ok(())
    }
    fn validate_da_block_rewrite_stage(&self, stage: &DaBlockRewriteStageV1) -> Result<()> {
        if stage.format_version != DA_BLOCK_REWRITE_STAGE_VERSION
            || stage.replacement.is_empty()
            || stage.old_marker.version != BlockStoreCommitMarker::VERSION
            || stage.new_marker.version != BlockStoreCommitMarker::VERSION
            || (stage.old_marker.count == 0) != stage.old_marker.tip_hash.is_none()
            || (stage.new_marker.count == 0) != stage.new_marker.tip_hash.is_none()
            || stage.old_index_count != stage.old_marker.count
            || stage.old_hash_count != stage.old_marker.count
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite stage envelope is inconsistent",
            ));
        }
        if stage
            .old_suffix
            .len()
            .checked_add(stage.replacement.len())
            .is_none_or(|count| count > MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES)
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite stage exceeds its hard entry-count limit",
            ));
        }
        let replacement_start = stage.replacement[0].height;
        for (offset, image) in stage.replacement.iter().enumerate() {
            self.validate_da_block_rewrite_image(image)?;
            if image.height != replacement_start.saturating_add(u64::try_from(offset)?) {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite replacement heights are not dense",
                ));
            }
        }
        let replacement_tip = stage
            .replacement
            .last()
            .expect("replacement was checked nonempty");
        if stage.new_marker.count != replacement_tip.height
            || stage.new_marker.tip_hash != Some(replacement_tip.block_hash)
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite replacement mismatches its new marker",
            ));
        }
        if stage.old_suffix.is_empty() {
            if replacement_start <= stage.old_marker.count {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite stage omits an existing old suffix",
                ));
            }
        } else {
            if stage.old_suffix[0].height != replacement_start {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite old and replacement suffixes start at different heights",
                ));
            }
            for (offset, image) in stage.old_suffix.iter().enumerate() {
                self.validate_da_block_rewrite_image(image)?;
                if image.height != replacement_start.saturating_add(u64::try_from(offset)?) {
                    return Err(self.invalid_da_block_rewrite_stage(
                        "DA block rewrite old suffix heights are not dense",
                    ));
                }
            }
            let old_tip = stage.old_suffix.last().expect("old suffix is nonempty");
            if old_tip.height != stage.old_marker.count
                || stage.old_marker.tip_hash != Some(old_tip.block_hash)
            {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite old suffix mismatches its old marker",
                ));
            }
        }
        if stage.old_marker == stage.new_marker && stage.old_suffix != stage.replacement {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite has ambiguous identical publication markers",
            ));
        }
        Ok(())
    }
    fn write_da_block_rewrite_stage(&self, stage: &DaBlockRewriteStageV1) -> Result<()> {
        self.validate_da_block_rewrite_stage(stage)?;
        let path = self.da_block_rewrite_stage_path();
        let parent = path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, "rewrite stage has no parent"),
                path.clone(),
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        let bytes = norito::encode_canonical(stage).map_err(Error::NoritoFrame)?;
        if u64::try_from(bytes.len())? > MAX_DA_BLOCK_REWRITE_STAGE_BYTES {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite stage exceeds its hard size limit",
            ));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".kura-da-rewrite-")
            .tempfile_in(parent)
            .map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        temporary
            .as_file_mut()
            .write_all(&bytes)
            .and_then(|()| temporary.as_file_mut().flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| Error::IO(error, path.clone()))?;
        let persisted = temporary
            .persist(&path)
            .map_err(|error| Error::IO(error.error, path.clone()))?;
        persisted
            .sync_all()
            .map_err(|error| Error::IO(error, path.clone()))?;
        sync_dir(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
        Ok(())
    }
    fn remove_da_block_rewrite_stage(&self) -> Result<()> {
        let path = self.da_block_rewrite_stage_path();
        match std::fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    sync_dir(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
                }
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::IO(error, path)),
        }
    }
    fn read_block_rewrite_image(&mut self, height: u64) -> Result<DaBlockRewriteImageV1> {
        let index_position = height.saturating_sub(1);
        let index = self.read_block_index(index_position)?;
        let block_hash = self
            .read_block_hashes(index_position, 1)?
            .first()
            .copied()
            .ok_or(Error::OutOfBoundsBlockRead {
                start_block_height: index_position,
                block_count: 1,
            })?;
        if index.length == 0 || index.length > STRICT_INIT_MAX_BLOCK_BYTES {
            return Err(Error::CorruptedBlockLength {
                length: index.length,
                limit: STRICT_INIT_MAX_BLOCK_BYTES,
            });
        }
        let body = if index.is_evicted() {
            self.read_da_block_bytes(height, index.length)?
        } else {
            let length = usize::try_from(index.length)?;
            let mut body = vec![0_u8; length];
            self.read_block_data(index.start, &mut body)?;
            body
        };
        let image = DaBlockRewriteImageV1 {
            height,
            block_hash,
            index_start: index.start,
            index_length: index.length,
            body,
        };
        self.validate_da_block_rewrite_image(&image)?;
        Ok(image)
    }
    fn durable_marker_before_rewrite(&mut self) -> Result<BlockStoreCommitMarker> {
        self.flush_pending_fsync(true)?;
        self.read_commit_marker()?.ok_or_else(|| {
            self.invalid_da_block_rewrite_stage("durable commit marker is unavailable")
        })
    }
    fn prepare_da_block_rewrite_stage(
        &mut self,
        start_height: u64,
        frames: &[Vec<u8>],
        offsets: &[u64],
        lengths: &[u64],
        hashes: &[HashOf<BlockHeader>],
    ) -> Result<Option<DaBlockRewriteStageV1>> {
        let logical_count = self.read_index_count()?;
        let needs_stage = start_height < logical_count
            || offsets.iter().any(|start| *start == EVICTED_BLOCK_START);
        if !needs_stage {
            return Ok(None);
        }
        let old_marker = self.durable_marker_before_rewrite()?;
        if old_marker.count != logical_count || self.read_hashes_count()? != logical_count {
            return Err(self.invalid_da_block_rewrite_stage(
                "canonical journals are not at their durable marker before rewrite",
            ));
        }
        let old_data_len = self.data_file_len()?;
        let replacement_start = start_height.saturating_add(1);
        let old_suffix_count = if replacement_start <= old_marker.count {
            old_marker
                .count
                .saturating_sub(replacement_start)
                .saturating_add(1)
        } else {
            0
        };
        let staged_entry_count = usize::try_from(old_suffix_count)?
            .checked_add(frames.len())
            .ok_or_else(|| {
                self.invalid_da_block_rewrite_stage("DA block rewrite stage entry count overflowed")
            })?;
        if staged_entry_count > MAX_DA_BLOCK_REWRITE_STAGE_ENTRIES {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite stage exceeds its hard entry-count limit",
            ));
        }
        const IMAGE_ENVELOPE_BUDGET: u64 = 256;
        let mut staged_bytes = IMAGE_ENVELOPE_BUDGET;
        for height in replacement_start..=old_marker.count {
            let index = self.read_block_index(height.saturating_sub(1))?;
            staged_bytes = staged_bytes
                .checked_add(index.length)
                .and_then(|bytes| bytes.checked_add(IMAGE_ENVELOPE_BUDGET))
                .ok_or_else(|| {
                    self.invalid_da_block_rewrite_stage(
                        "DA block rewrite stage size preflight overflowed",
                    )
                })?;
            if staged_bytes > MAX_DA_BLOCK_REWRITE_STAGE_BYTES {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite old suffix exceeds its hard stage limit",
                ));
            }
        }
        for frame in frames {
            staged_bytes = staged_bytes
                .checked_add(u64::try_from(frame.len())?)
                .and_then(|bytes| bytes.checked_add(IMAGE_ENVELOPE_BUDGET))
                .ok_or_else(|| {
                    self.invalid_da_block_rewrite_stage(
                        "DA block rewrite stage size preflight overflowed",
                    )
                })?;
            if staged_bytes > MAX_DA_BLOCK_REWRITE_STAGE_BYTES {
                return Err(self.invalid_da_block_rewrite_stage(
                    "DA block rewrite replacement exceeds its hard stage limit",
                ));
            }
        }
        let mut old_suffix = Vec::new();
        for height in replacement_start..=old_marker.count {
            old_suffix.push(self.read_block_rewrite_image(height)?);
        }
        let mut replacement = Vec::with_capacity(frames.len());
        for (offset, (((body, index_start), index_length), block_hash)) in frames
            .iter()
            .zip(offsets)
            .zip(lengths)
            .zip(hashes)
            .enumerate()
        {
            let image = DaBlockRewriteImageV1 {
                height: replacement_start.saturating_add(u64::try_from(offset)?),
                block_hash: *block_hash,
                index_start: *index_start,
                index_length: *index_length,
                body: body.clone(),
            };
            self.validate_da_block_rewrite_image(&image)?;
            replacement.push(image);
        }
        let replacement_tip = replacement.last().ok_or_else(|| {
            self.invalid_da_block_rewrite_stage("empty DA block rewrite replacement")
        })?;
        let stage = DaBlockRewriteStageV1 {
            format_version: DA_BLOCK_REWRITE_STAGE_VERSION,
            old_marker,
            new_marker: BlockStoreCommitMarker::new(
                replacement_tip.height,
                Some(replacement_tip.block_hash),
            ),
            old_data_len,
            old_index_count: logical_count,
            old_hash_count: logical_count,
            old_suffix,
            replacement,
        };
        if stage.old_marker == stage.new_marker && stage.old_suffix == stage.replacement {
            return Ok(None);
        }
        self.write_da_block_rewrite_stage(&stage)?;
        Ok(Some(stage))
    }
    fn restore_old_da_block_rewrite_stage(&mut self, stage: &DaBlockRewriteStageV1) -> Result<()> {
        self.drop_cached_handles();
        {
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| {
                file.set_len(stage.old_data_len)?;
                for image in &stage.old_suffix {
                    if image.index_start == EVICTED_BLOCK_START {
                        continue;
                    }
                    file.seek(SeekFrom::Start(image.index_start))?;
                    file.write_all(&image.body)?;
                }
                file.flush()?;
                file.sync_all()
            })?;
        }
        for image in &stage.old_suffix {
            if image.index_start == EVICTED_BLOCK_START {
                self.write_da_block_bytes(image.height, &image.body)?;
            } else {
                self.remove_da_block_file(image.height)?;
            }
        }
        for image in &stage.replacement {
            if image.height > stage.old_marker.count {
                self.remove_da_block_file(image.height)?;
            }
        }
        {
            let hashes_file = self.ensure_hashes_file()?;
            hashes_file.try_io(|file| {
                file.set_len(stage.old_hash_count.saturating_mul(SIZE_OF_BLOCK_HASH))?;
                for image in &stage.old_suffix {
                    file.seek(SeekFrom::Start(
                        image.height.saturating_sub(1) * SIZE_OF_BLOCK_HASH,
                    ))?;
                    file.write_all(image.block_hash.as_ref())?;
                }
                file.flush()?;
                file.sync_all()
            })?;
        }
        {
            let index_file = self.ensure_index_file()?;
            index_file.try_io(|file| {
                file.set_len(stage.old_index_count.saturating_mul(BlockIndex::SIZE))?;
                for image in &stage.old_suffix {
                    file.seek(SeekFrom::Start(
                        image.height.saturating_sub(1) * BlockIndex::SIZE,
                    ))?;
                    file.write_all(&image.index().encode())?;
                }
                file.flush()?;
                file.sync_all()
            })?;
        }
        self.write_commit_marker_value(&stage.old_marker)?;
        self.commit_marker_count = stage.old_marker.count;
        self.commit_marker_pending = None;
        self.fsync.clear();
        self.drop_cached_handles();
        Ok(())
    }
    fn promote_new_da_block_rewrite_stage(&mut self, stage: &DaBlockRewriteStageV1) -> Result<()> {
        if self.read_index_count()? != stage.new_marker.count
            || self.read_hashes_count()? != stage.new_marker.count
        {
            return Err(self.invalid_da_block_rewrite_stage(
                "published DA block rewrite journal length mismatches its marker",
            ));
        }
        for image in &stage.replacement {
            let index_position = image.height.saturating_sub(1);
            let index = self.read_block_index(index_position)?;
            let block_hash = self.read_block_hashes(index_position, 1)?.first().copied();
            if index.start != image.index_start
                || index.length != image.index_length
                || block_hash != Some(image.block_hash)
            {
                return Err(self.invalid_da_block_rewrite_stage(
                    "published DA block rewrite metadata mismatches its stage",
                ));
            }
            let body = image.body.as_slice();
            if index.is_evicted() {
                self.write_da_block_bytes(image.height, body)?;
            } else {
                let mut persisted = vec![0_u8; usize::try_from(index.length)?];
                self.read_block_data(index.start, &mut persisted)?;
                if persisted != body {
                    return Err(self.invalid_da_block_rewrite_stage(
                        "published inline block bytes mismatch their rewrite stage",
                    ));
                }
                self.remove_da_block_file(image.height)?;
            }
        }
        Ok(())
    }
    fn recover_da_block_rewrite_stage(&mut self) -> Result<()> {
        let Some(stage) = self.read_da_block_rewrite_stage()? else {
            return Ok(());
        };
        #[cfg(test)]
        if self
            .fail_next_da_rewrite_recovery
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other("injected DA rewrite recovery failure"),
                self.da_block_rewrite_stage_path(),
            ));
        }
        let marker = self.read_commit_marker()?.ok_or_else(|| {
            self.invalid_da_block_rewrite_stage(
                "cannot recover a DA block rewrite without a commit marker",
            )
        })?;
        if marker == stage.old_marker {
            remove_commit_marker_temp_and_sync(
                &self.commit_marker_path().with_extension("norito.tmp"),
            )?;
            self.restore_old_da_block_rewrite_stage(&stage)?;
        } else if marker == stage.new_marker {
            self.promote_new_da_block_rewrite_stage(&stage)?;
            self.commit_marker_count = stage.new_marker.count;
            self.commit_marker_pending = None;
            self.fsync.clear();
        } else {
            return Err(self.invalid_da_block_rewrite_stage(
                "DA block rewrite marker matches neither staged publication state",
            ));
        }
        self.remove_da_block_rewrite_stage()
    }
    fn prune_da_block_files_above(&self, height: u64) -> Result<()> {
        if self.da_blocks_dir.as_os_str().is_empty() || !self.da_blocks_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.da_blocks_dir)
            .map_err(|err| Error::IO(err, self.da_blocks_dir.clone()))?
        {
            let entry = entry.map_err(|err| Error::IO(err, self.da_blocks_dir.clone()))?;
            let path = entry.path();
            let Some(sidecar_height) = numbered_norito_sidecar_height(&path) else {
                continue;
            };
            if sidecar_height > height {
                let file_type = entry
                    .file_type()
                    .map_err(|err| Error::IO(err, path.clone()))?;
                if !file_type.is_file() && !file_type.is_symlink() {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "DA sidecar suffix entry is not removable as a file",
                        ),
                        path.clone(),
                    ));
                }
                std::fs::remove_file(&path).map_err(|err| Error::IO(err, path))?;
            }
        }
        sync_dir(&self.da_blocks_dir).map_err(|err| Error::IO(err, self.da_blocks_dir.clone()))?;
        Ok(())
    }
    fn ensure_data_file(&mut self) -> Result<&mut FileWrap> {
        if self.data_file.is_none() {
            let path = self.path_to_blockchain.join(DATA_FILE_NAME);
            self.data_file = Some(if self.read_only {
                FileWrap::open_read_only(path)?
            } else {
                FileWrap::open_existing_read_write(path)?
            });
        }
        Ok(self.data_file.as_mut().expect("handle just initialised"))
    }
    fn ensure_index_file(&mut self) -> Result<&mut FileWrap> {
        if self.index_file.is_none() {
            let path = self.path_to_blockchain.join(INDEX_FILE_NAME);
            self.index_file = Some(if self.read_only {
                FileWrap::open_read_only(path)?
            } else {
                FileWrap::open_existing_read_write(path)?
            });
        }
        Ok(self.index_file.as_mut().expect("handle just initialised"))
    }
    fn ensure_hashes_file(&mut self) -> Result<&mut FileWrap> {
        if self.hashes_file.is_none() {
            let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
            self.hashes_file = Some(if self.read_only {
                FileWrap::open_read_only(path)?
            } else {
                FileWrap::open_existing_read_write(path)?
            });
        }
        Ok(self.hashes_file.as_mut().expect("handle just initialised"))
    }
    fn commit_marker_path(&self) -> PathBuf {
        self.path_to_blockchain.join(COUNT_FILE_NAME)
    }
    fn read_bounded_commit_marker_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
        let before = match secure_file_metadata::from_path(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::IO(error, path.to_path_buf())),
        };
        if before.file_type().is_symlink()
            || !before.file_type().is_file()
            || !Kura::sidecar_is_single_link(&before)
            || before.len() > u64::try_from(MAX_BLOCK_COMMIT_MARKER_BYTES).unwrap_or(u64::MAX)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block commit marker is not a bounded single-link regular file",
                ),
                path.to_path_buf(),
            ));
        }
        let mut file =
            std::fs::File::open(path).map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let opened_before = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if !opened_before.is_file()
            || !Kura::sidecar_is_single_link(&opened_before)
            || !Kura::sidecar_metadata_same_object(&before, &opened_before)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block commit marker changed while being opened",
                ),
                path.to_path_buf(),
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
        (&mut file)
            .take(
                u64::try_from(MAX_BLOCK_COMMIT_MARKER_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let opened_after = secure_file_metadata::from_file(&file)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        let after = secure_file_metadata::from_path(path)
            .map_err(|error| Error::IO(error, path.to_path_buf()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != before.len()
            || after.file_type().is_symlink()
            || !after.file_type().is_file()
            || !Kura::sidecar_is_single_link(&opened_after)
            || !Kura::sidecar_is_single_link(&after)
            || !Kura::sidecar_metadata_same_object(&before, &opened_after)
            || !Kura::sidecar_metadata_same_object(&opened_after, &after)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block commit marker changed during bounded read",
                ),
                path.to_path_buf(),
            ));
        }
        Ok(Some(bytes))
    }
    fn read_commit_marker(&mut self) -> Result<Option<BlockStoreCommitMarker>> {
        let path = self.commit_marker_path();
        if path.as_os_str().is_empty() {
            return Ok(None);
        }
        #[cfg(test)]
        if self
            .fail_next_commit_marker_read
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other("injected commit-marker readback failure"),
                path,
            ));
        }
        let marker = Self::read_bounded_commit_marker_bytes(&path)?
            .map(|bytes| {
                let marker = norito::decode_canonical::<BlockStoreCommitMarker>(&bytes)
                    .map_err(|error| Error::IO(std::io::Error::new(ErrorKind::InvalidData,
                        format!("invalid canonical block commit marker: {error}")), path.clone()))?;
                if marker.version != BlockStoreCommitMarker::VERSION
                    || (marker.count == 0) != marker.tip_hash.is_none()
                {
                    return Err(Error::IO(std::io::Error::new(ErrorKind::InvalidData,
                        "block commit marker has an unsupported version or invalid empty/tip invariant"), path.clone()));
                }
                Ok(marker)
            }).transpose()?;
        // The rename to the stable path is the publication boundary. A temporary
        // file never replaces that authority merely because it can be decoded.
        // Validate its filesystem shape without publishing, deleting or adopting it.
        Self::read_bounded_commit_marker_bytes(&path.with_extension("norito.tmp"))?;
        Ok(marker)
    }
    fn commit_marker_for_count(&mut self, count: u64) -> Result<BlockStoreCommitMarker> {
        let tip_hash = if count == 0 {
            None
        } else {
            self.read_block_hashes(count.saturating_sub(1), 1)?
                .first()
                .copied()
        };
        if count > 0 && tip_hash.is_none() {
            return Err(Error::OutOfBoundsBlockRead {
                start_block_height: count.saturating_sub(1),
                block_count: 1,
            });
        }
        Ok(BlockStoreCommitMarker::new(count, tip_hash))
    }
    fn write_commit_marker(&mut self, count: u64) -> Result<()> {
        let marker = self.commit_marker_for_count(count)?;
        self.write_commit_marker_value(&marker)
    }
    fn write_commit_marker_value(&mut self, marker: &BlockStoreCommitMarker) -> Result<()> {
        let path = self.commit_marker_path();
        if path.as_os_str().is_empty() {
            return Ok(());
        }
        #[cfg(test)]
        if self
            .fail_next_commit_marker_write_and_readback
            .swap(false, Ordering::AcqRel)
        {
            self.fail_next_commit_marker_read
                .store(true, Ordering::Release);
            return Err(Error::IO(
                std::io::Error::other(
                    "injected commit-marker write and subsequent readback failure",
                ),
                path,
            ));
        }
        #[cfg(test)]
        if self
            .fail_next_commit_marker_write
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other("injected commit-marker write failure"),
                path,
            ));
        }
        if marker.version != BlockStoreCommitMarker::VERSION
            || (marker.count == 0) != marker.tip_hash.is_none()
        {
            return Err(Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, "invalid block commit marker"),
                path,
            ));
        }
        let bytes = norito::encode_canonical(marker).map_err(Error::NoritoFrame)?;
        let parent = path.parent().ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, "commit marker has no parent"),
                path.clone(),
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|err| Error::IO(err, parent.to_path_buf()))?;
        if bytes.is_empty() || bytes.len() > MAX_BLOCK_COMMIT_MARKER_BYTES {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "encoded block commit marker exceeds its hard bound",
                ),
                path,
            ));
        }
        let temporary_path = path.with_extension("norito.tmp");
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
        {
            Ok(mut temporary) => {
                temporary
                    .write_all(&bytes)
                    .and_then(|()| temporary.flush())
                    .and_then(|()| temporary.sync_all())
                    .map_err(|error| Error::IO(error, temporary_path.clone()))?;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let existing = Self::read_bounded_commit_marker_bytes(&temporary_path)?
                    .ok_or_else(|| {
                        Error::IO(
                            std::io::Error::new(
                                ErrorKind::NotFound,
                                "block commit marker temp disappeared during retry",
                            ),
                            temporary_path.clone(),
                        )
                    })?;
                if existing != bytes {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::AlreadyExists,
                            "block commit marker temp conflicts with the intended marker",
                        ),
                        temporary_path,
                    ));
                }
            }
            Err(error) => return Err(Error::IO(error, temporary_path)),
        }
        self.maybe_fail_commit_marker_after_temp_sync(&temporary_path)?;
        std::fs::rename(&temporary_path, &path).map_err(|error| Error::IO(error, path.clone()))?;
        let persisted = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| Error::IO(error, path.clone()))?;
        persisted
            .sync_all()
            .map_err(|error| Error::IO(error, path.clone()))?;
        sync_dir(parent).map_err(|err| Error::IO(err, parent.to_path_buf()))?;
        let readback = Self::read_bounded_commit_marker_bytes(&path)?.ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::NotFound,
                    "published block commit marker disappeared before exact readback",
                ),
                path.clone(),
            )
        })?;
        if readback != bytes {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "published block commit marker differs from its synced temporary",
                ),
                path,
            ));
        }
        #[cfg(test)]
        if self
            .fail_next_commit_marker_ack_and_readback
            .swap(false, Ordering::AcqRel)
        {
            self.fail_next_commit_marker_read
                .store(true, Ordering::Release);
            return Err(Error::IO(
                std::io::Error::other(
                    "injected persisted marker acknowledgement and readback failure",
                ),
                path,
            ));
        }
        #[cfg(test)]
        if self
            .fail_next_commit_marker_ack_after_persist
            .swap(false, Ordering::AcqRel)
        {
            return Err(Error::IO(
                std::io::Error::other(
                    "injected post-persist commit-marker acknowledgement failure",
                ),
                path,
            ));
        }
        Ok(())
    }
    fn validate_commit_marker_tip(
        &mut self,
        marker: &BlockStoreCommitMarker,
        hashes_count: u64,
    ) -> Result<()> {
        if marker.count == 0 {
            if marker.tip_hash.is_none() {
                return Ok(());
            }
        } else if marker.count <= hashes_count {
            let journal_tip = self
                .read_block_hashes(marker.count.saturating_sub(1), 1)?
                .first()
                .copied();
            if journal_tip == marker.tip_hash {
                return Ok(());
            }
        }
        Err(Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidData,
                "block commit marker tip hash mismatches the canonical hash journal",
            ),
            self.commit_marker_path(),
        ))
    }
    fn align_hashes_len(&mut self) -> Result<u64> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(0);
        }
        let hashes_file = self.ensure_hashes_file()?;
        let len = hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        let aligned = len - (len % SIZE_OF_BLOCK_HASH);
        if aligned != len {
            warn!(
                len,
                aligned, "block hashes length misaligned; truncating trailing bytes"
            );
            hashes_file.try_io(|file| file.set_len(aligned))?;
        }
        Ok(aligned / SIZE_OF_BLOCK_HASH)
    }
    fn data_backed_count(&mut self, mut candidate: u64, hashes_count: u64) -> Result<u64> {
        if candidate > hashes_count {
            warn!(
                index_count = candidate,
                hashes_count,
                "block store index exceeds hash journal; capping durable count to hashes height"
            );
            candidate = hashes_count;
        }
        if candidate == 0 {
            return Ok(0);
        }
        let data_len = self.data_file_len()?;
        let initial = candidate;
        while candidate > 0 {
            match self.read_block_index(candidate - 1) {
                Ok(index) => {
                    if index.is_evicted() {
                        if index.length == 0
                            || index.length > STRICT_INIT_MAX_BLOCK_BYTES
                            || candidate > hashes_count
                        {
                            candidate = candidate.saturating_sub(1);
                            continue;
                        }
                        break;
                    }
                    let end = if let Some(end) = index.start.checked_add(index.length) {
                        end
                    } else {
                        candidate = candidate.saturating_sub(1);
                        continue;
                    };
                    if index.length == 0
                        || index.length > STRICT_INIT_MAX_BLOCK_BYTES
                        || end > data_len
                    {
                        candidate = candidate.saturating_sub(1);
                        continue;
                    }
                    break;
                }
                Err(err) => {
                    warn!(
                        ?err,
                        candidate,
                        "failed to read block index while reconciling data length; truncating"
                    );
                    candidate = 0;
                    break;
                }
            }
        }
        if candidate != initial {
            warn!(
                initial,
                candidate,
                data_len,
                "block store data shorter than index; truncating durable count"
            );
        }
        Ok(candidate)
    }
    /// Validate the committed journal prefix before ordinary startup is allowed to mutate it.
    ///
    /// Fast mode never initializes or repairs storage. The store must already carry an exact stable
    /// commit marker and every required canonical file. Entries and bytes beyond that marker are
    /// unpublished crash suffixes and remain untouched for the next Strict restart to reconcile.
    fn preflight_fast_durable_prefix(&mut self) -> Result<u64> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            self.fast_prevalidated_count = Some(0);
            return Ok(0);
        }
        let root_metadata = std::fs::symlink_metadata(&self.path_to_blockchain)
            .map_err(|error| Error::IO(error, self.path_to_blockchain.clone()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura canonical block root is not a direct directory",
                ),
                self.path_to_blockchain.clone(),
            ));
        }
        let invalid = |path: PathBuf, reason: &'static str| {
            Error::IO(std::io::Error::new(ErrorKind::InvalidData, reason), path)
        };
        Kura::reject_retired_snapshot_tail(&self.path_to_blockchain)?;
        let marker_path = self.commit_marker_path();
        let marker_bytes = Self::read_required_bounded_commit_marker_bytes(
            &marker_path,
            "Kura fast init requires a stable block commit marker",
        )?;
        let marker =
            norito::decode_canonical::<BlockStoreCommitMarker>(&marker_bytes).map_err(|_| {
                invalid(
                    marker_path.clone(),
                    "Kura fast init requires a canonical block commit marker",
                )
            })?;
        if marker.version != BlockStoreCommitMarker::VERSION
            || (marker.count == 0) != marker.tip_hash.is_none()
        {
            return Err(invalid(
                marker_path,
                "Kura fast init found an invalid block commit marker",
            ));
        }

        let required_index_len = marker.count.checked_mul(BlockIndex::SIZE).ok_or_else(|| {
            invalid(
                self.path_to_blockchain.join(INDEX_FILE_NAME),
                "Kura fast init index prefix length overflows",
            )
        })?;
        let required_hashes_len =
            marker
                .count
                .checked_mul(SIZE_OF_BLOCK_HASH)
                .ok_or_else(|| {
                    invalid(
                        self.path_to_blockchain.join(HASHES_FILE_NAME),
                        "Kura fast init hash prefix length overflows",
                    )
                })?;
        let required_file_len = |path: &Path, required: u64| -> Result<u64> {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|error| Error::IO(error, path.to_path_buf()))?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.len() < required
            {
                return Err(invalid(
                    path.to_path_buf(),
                    "Kura fast init found a missing, linked, or truncated canonical journal",
                ));
            }
            Ok(metadata.len())
        };
        let index_path = self.path_to_blockchain.join(INDEX_FILE_NAME);
        let hashes_path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let data_path = self.path_to_blockchain.join(DATA_FILE_NAME);
        let _index_len = required_file_len(&index_path, required_index_len)?;
        let _hashes_len = required_file_len(&hashes_path, required_hashes_len)?;
        let data_len = required_file_len(&data_path, 0)?;

        if marker.count > 0 {
            let mut hashes_file = std::fs::File::open(&hashes_path)
                .map_err(|error| Error::IO(error, hashes_path.clone()))?;
            hashes_file
                .seek(SeekFrom::Start(
                    marker.count.saturating_sub(1) * SIZE_OF_BLOCK_HASH,
                ))
                .map_err(|error| Error::IO(error, hashes_path.clone()))?;
            let mut tip_bytes = [0_u8; Hash::LENGTH];
            hashes_file
                .read_exact(&mut tip_bytes)
                .map_err(|error| Error::IO(error, hashes_path.clone()))?;
            let expected_tip_bytes: &[u8] = marker
                .tip_hash
                .as_ref()
                .expect("non-empty commit marker has a tip hash")
                .as_ref();
            if expected_tip_bytes != tip_bytes {
                return Err(invalid(
                    hashes_path,
                    "Kura fast init commit marker tip mismatches the hash journal",
                ));
            }
        }

        if marker.count > 0 {
            let mut index_file = std::fs::File::open(&index_path)
                .map_err(|error| Error::IO(error, index_path.clone()))?;
            index_file
                .seek(SeekFrom::Start(
                    marker.count.saturating_sub(1) * BlockIndex::SIZE,
                ))
                .map_err(|error| Error::IO(error, index_path.clone()))?;
            let mut buffer = [0_u8; core::mem::size_of::<u64>()];
            let index = BlockIndex::read(&mut index_file, &mut buffer).map_err(|_| {
                invalid(
                    index_path.clone(),
                    "Kura fast init could not read the committed tip index",
                )
            })?;
            if index.length == 0 || index.length > STRICT_INIT_MAX_BLOCK_BYTES {
                return Err(invalid(
                    index_path,
                    "Kura fast init found a zero or oversized committed tip length",
                ));
            }
            if !index.is_evicted() {
                let end = index.start.checked_add(index.length).ok_or_else(|| {
                    invalid(
                        data_path.clone(),
                        "Kura fast init committed tip range overflows",
                    )
                })?;
                if end > data_len {
                    return Err(invalid(
                        data_path,
                        "Kura fast init committed tip range exceeds the data journal",
                    ));
                }
            }
        }
        self.commit_marker_count = marker.count;
        self.commit_marker_pending = None;
        self.fast_prevalidated_count = Some(marker.count);
        Ok(marker.count)
    }
    fn init_commit_marker(&mut self) -> Result<()> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(());
        }
        Kura::reject_retired_snapshot_tail(&self.path_to_blockchain)?;
        let index_len = self
            .ensure_index_file()?
            .try_io(|file| file.metadata().map(|meta| meta.len()))?;
        let logical_count = index_len / BlockIndex::SIZE;
        let hashes_count = self.read_hashes_count()?;
        let existing_marker = self.read_commit_marker()?;
        if let Some(marker) = existing_marker.as_ref() {
            self.validate_commit_marker_tip(marker, hashes_count)?;
            if marker.count > logical_count {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "committed block prefix exceeds the index journal",
                    ),
                    self.path_to_blockchain.join(INDEX_FILE_NAME),
                ));
            }
            // Bounds alone cannot detect an in-range offset or shortened frame
            // that would trim another committed body. Check the original frame
            // and hash correspondence before changing any journal bytes.
            let count = usize::try_from(marker.count)?;
            let mut indices = vec![BlockIndex::default(); count];
            self.read_block_indices(0, &mut indices)?;
            let hashes = self.read_block_hashes(0, count)?;
            Kura::validate_committed_block_prefix(self, &indices, &hashes)?;
        }
        let data_backed_count = self.data_backed_count(logical_count, hashes_count)?;
        if existing_marker.is_none()
            && (index_len != 0 || hashes_count != 0 || self.data_file_len()? != 0)
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "nonempty canonical journals have no stable commit marker",
                ),
                self.commit_marker_path(),
            ));
        }
        // The prefix is intact and any staged owner has completed recovery.
        // Abort an unpublished temporary; the stable marker remains authoritative.
        remove_commit_marker_temp_and_sync(
            &self.commit_marker_path().with_extension("norito.tmp"),
        )?;
        let durable_count = if let Some(marker) = existing_marker {
            if marker.count > data_backed_count {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "committed block prefix contains unavailable or corrupt canonical storage",
                    ),
                    self.path_to_blockchain.clone(),
                ));
            }
            marker.count
        } else {
            self.write_commit_marker(data_backed_count)?;
            data_backed_count
        };
        // Reconciliation may discard only an uncommitted suffix. Validate the
        // durable boundary before changing even partial trailing journal bytes.
        let aligned = logical_count * BlockIndex::SIZE;
        if aligned != index_len {
            self.ensure_index_file()?
                .try_io(|file| file.set_len(aligned))?;
        }
        self.align_hashes_len()?;
        if logical_count > durable_count {
            warn!(
                logical_count,
                durable_count,
                discarded_count = logical_count - durable_count,
                "block store contains an uncommitted suffix; pruning to the durable commit marker"
            );
            self.commit_marker_count = durable_count;
            self.commit_marker_pending = None;
            self.prune(durable_count)?;
        }
        self.truncate_hashes_to_count(durable_count)?;
        self.truncate_data_to_index(durable_count)?;
        self.commit_marker_count = durable_count;
        self.commit_marker_pending = None;
        Ok(())
    }
    fn drop_cached_handles(&mut self) {
        self.data_file = None;
        self.index_file = None;
        self.hashes_file = None;
        self.invalidate_data_mmap();
    }
    fn next_fsync_wait(&self) -> Option<Duration> {
        let deadline = self.fsync.deadline()?;
        let now = Instant::now();
        if deadline <= now {
            Some(Duration::ZERO)
        } else {
            deadline.checked_duration_since(now)
        }
    }
    #[cfg(test)]
    fn fsync_pending_for_tests(&self) -> bool {
        self.fsync.pending_since.is_some()
    }
    fn flush_pending_fsync(&mut self, force: bool) -> Result<()> {
        if !self.path_to_blockchain.as_os_str().is_empty()
            && (self.da_block_rewrite_stage_path().exists()
                || self.eviction_compaction_stage_path().exists())
        {
            self.recover_canonical_storage_stages()?;
        }
        self.fsync_telemetry.update_mode(self.fsync.mode);
        let now = Instant::now();
        if !self.fsync.is_due(now, force) {
            return Ok(());
        }
        // Sync index last so the commit marker only advances after data/hashes/index are durable.
        self.sync_target(FsyncTarget::Data, Self::ensure_data_file)?;
        self.sync_target(FsyncTarget::Hashes, Self::ensure_hashes_file)?;
        self.sync_target(FsyncTarget::Index, Self::ensure_index_file)?;
        self.commit_pending_marker()?;
        self.fsync.clear();
        Ok(())
    }
    fn commit_pending_marker(&mut self) -> Result<()> {
        let Some(count) = self.commit_marker_pending else {
            return Ok(());
        };
        let old_marker = match self.read_commit_marker() {
            Ok(marker) => marker,
            Err(read_error) => {
                self.commit_marker_pending = None;
                self.fsync.clear();
                return Err(self.unknown_da_rewrite_state(
                    "failed to read the pre-publication commit marker",
                    &read_error,
                ));
            }
        };
        let expected_marker = match self.commit_marker_for_count(count) {
            Ok(marker) => marker,
            Err(marker_error) => {
                self.commit_marker_pending = None;
                self.fsync.clear();
                if old_marker
                    .as_ref()
                    .is_some_and(|marker| marker.count < count)
                    && let Err(rollback_error) = self.init_commit_marker()
                {
                    return Err(self.unknown_da_rewrite_state(
                        "failed to roll back after deriving the pending marker failed",
                        &rollback_error,
                    ));
                }
                return Err(marker_error);
            }
        };
        match self.write_commit_marker_value(&expected_marker) {
            Ok(()) => {
                self.commit_marker_count = count;
                self.commit_marker_pending = None;
                Ok(())
            }
            Err(publication_error) => {
                let readback = match self.read_commit_marker() {
                    Ok(readback) => readback,
                    Err(readback_error) => {
                        self.commit_marker_pending = None;
                        self.fsync.clear();
                        return Err(self.unknown_da_rewrite_state(
                            "commit-marker publication and readback both failed",
                            &readback_error,
                        ));
                    }
                };
                if readback.as_ref() == Some(&expected_marker) {
                    self.commit_marker_count = count;
                    self.commit_marker_pending = None;
                    return Ok(());
                }
                if let Some(old_marker) = old_marker
                    && readback.as_ref() == Some(&old_marker)
                    && old_marker.count < count
                {
                    self.commit_marker_pending = None;
                    self.fsync.clear();
                    if let Err(rollback_error) = self.init_commit_marker() {
                        return Err(self.unknown_da_rewrite_state(
                            "failed to roll back an unpublished append journal",
                            &rollback_error,
                        ));
                    }
                    return Err(publication_error);
                }
                self.commit_marker_pending = None;
                self.fsync.clear();
                Err(self.unknown_da_rewrite_state(
                    "commit marker matches neither the pre-write nor published append state",
                    &publication_error,
                ))
            }
        }
    }
    fn publish_commit_marker(&mut self, count: u64) -> Result<()> {
        self.commit_marker_pending = Some(count);
        self.mark_fsync_pending();
        self.flush_pending_fsync(true)
    }
    fn sync_target(
        &mut self,
        target: FsyncTarget,
        open: impl Fn(&mut Self) -> Result<&mut FileWrap>,
    ) -> Result<()> {
        let start = Instant::now();
        let result = open(self)?.try_io(|inner| inner.sync_data());
        match result {
            Ok(()) => {
                self.fsync_telemetry.record_success(target, start.elapsed());
                Ok(())
            }
            Err(err) => {
                self.fsync_telemetry
                    .record_failure(target, Some(start.elapsed()));
                Err(err)
            }
        }
    }
    fn schedule_fsync_after_write(&mut self) -> Result<()> {
        self.mark_fsync_pending();
        self.flush_pending_fsync(false)
    }
    fn mark_fsync_pending(&mut self) {
        let now = Instant::now();
        self.fsync.record_write(now);
    }
    fn invalidate_data_mmap(&mut self) {
        let _ = self.data_mmap.take();
        self.data_mmap_len = 0;
    }
    fn ensure_data_file_present(&mut self) -> Result<()> {
        let path = self.path_to_blockchain.join(DATA_FILE_NAME);
        match std::fs::metadata(&path) {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.drop_cached_handles();
                }
                Err(Error::IO(err, path))
            }
        }
    }
    fn ensure_data_mmap(&mut self) -> Result<()> {
        self.ensure_data_file_present()?;
        let len = {
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| file.metadata().map(|meta| meta.len()))?
        };
        if len == 0 {
            self.invalidate_data_mmap();
            return Ok(());
        }
        if self.data_mmap.as_ref().map(|m| m.len() as u64) == Some(len) {
            self.data_mmap_len = len;
            return Ok(());
        }
        self.invalidate_data_mmap();
        let len_usize: usize = len.try_into()?;
        let mirror = {
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| MemoryMirror::from_file(file, len_usize, len))?
        };
        self.data_mmap_len = len;
        self.data_mmap = Some(mirror);
        Ok(())
    }
    /// Read a contiguous range of bytes from the block data file.
    ///
    /// # Errors
    /// Returns an error if the requested range is out of bounds or if the
    /// underlying storage cannot be read.
    pub fn block_bytes(&mut self, start: u64, length: u64) -> Result<&[u8]> {
        if length == 0 {
            self.ensure_data_mmap()?;
            return Ok(&[]);
        }
        self.ensure_data_mmap()?;
        let end = start
            .checked_add(length)
            .ok_or(Error::CorruptedBlockRange {
                start,
                length,
                data_len: self.data_mmap_len,
            })?;
        if end > self.data_mmap_len {
            return Err(Error::CorruptedBlockRange {
                start,
                length,
                data_len: self.data_mmap_len,
            });
        }
        #[cfg(test)]
        {
            self.body_read_calls.fetch_add(1, Ordering::Relaxed);
            self.body_bytes_read.fetch_add(length, Ordering::Relaxed);
        }
        let len_usize: usize = length.try_into()?;
        let start_usize: usize = start.try_into()?;
        let end_usize = start_usize + len_usize;
        if let Some(ref mirror) = self.data_mmap {
            return Ok(mirror.slice(start_usize, end_usize));
        }
        let mut scratch = std::mem::take(&mut self.read_scratch);
        if scratch.len() < len_usize {
            scratch.resize(len_usize, 0);
        }
        self.ensure_data_file()?.try_io(|file| {
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut scratch[..len_usize])
        })?;
        self.read_scratch = scratch;
        Ok(&self.read_scratch[..len_usize])
    }
    /// Read a series of block indices from the block index file and
    /// attempt to fill all of `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_indices(
        &mut self,
        start_block_height: u64,
        dest_buffer: &mut [BlockIndex],
    ) -> Result<()> {
        let block_count = dest_buffer.len();
        if block_count == 0 {
            return Ok(());
        }
        let start_location = start_block_height * BlockIndex::SIZE;
        let required = BlockIndex::SIZE * block_count as u64;
        let index_file = self.ensure_index_file()?;
        let file_len = index_file.try_io(|f| f.metadata().map(|meta| meta.len()))?;
        if start_location + required > file_len {
            return Err(Error::OutOfBoundsBlockRead {
                start_block_height,
                block_count,
            });
        }
        index_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location))?;
            let mut buffer = [0; 8];
            for current in dest_buffer.iter_mut() {
                *current = BlockIndex::read(file, &mut buffer)?;
            }
            Ok(())
        })?;
        Ok(())
    }
    /// Call `read_block_indices` with a buffer of one.
    ///
    /// # Errors
    /// IO Error.
    pub(crate) fn read_block_index(&mut self, block_height: u64) -> Result<BlockIndex> {
        let mut index = BlockIndex {
            start: 0,
            length: 0,
        };
        self.read_block_indices(block_height, std::slice::from_mut(&mut index))?;
        Ok(index)
    }
    /// Get the number of indices in the index file, which is
    /// calculated as the size of the index file in bytes divided by
    /// `2*size_of(u64)`.
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    ///
    /// Note that if there is an error, you can be quite sure all
    /// other read and write operations will also fail.
    #[allow(clippy::integer_division)]
    fn read_index_count_from_len(&mut self) -> Result<u64> {
        let index_file = self.ensure_index_file()?;
        let len = index_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        Ok(len / BlockIndex::SIZE)
    }
    /// Return the logical index count based on the index file length.
    ///
    /// # Errors
    /// Returns any underlying IO errors when reading the index file metadata.
    #[allow(clippy::integer_division)]
    pub fn read_index_count(&mut self) -> Result<u64> {
        self.read_index_count_from_len()
    }
    /// Read pipeline recovery metadata for a canonical persisted block.
    ///
    /// This read-only tooling path uses Kura's current indexed-sidecar layout and
    /// returns metadata only when its embedded height and block hash match the
    /// canonical block journals. Missing, malformed, or stale sidecars return
    /// `Ok(None)`.
    ///
    /// # Errors
    /// Returns an error when the canonical block journals cannot be read.
    pub fn read_pipeline_metadata(
        &mut self,
        height: u64,
    ) -> Result<Option<PipelineRecoverySidecar>> {
        if height == 0 || height > self.read_index_count()? {
            return Ok(None);
        }
        let pipeline_dir = self.path_to_blockchain.join(PIPELINE_DIR_NAME);
        let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
        let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
        let entry_byte_limit =
            u64::try_from(MAX_PIPELINE_RECOVERY_SIDECAR_BYTES).unwrap_or(u64::MAX);
        let Some(sidecar) = Kura::read_indexed_sidecar_from_paths_with_recovery_and_limit(
            height,
            &data_path,
            &index_path,
            norito::decode_canonical::<PipelineRecoverySidecar>,
            "pipeline sidecar",
            false,
            entry_byte_limit,
        ) else {
            return Ok(None);
        };
        if sidecar.height != height {
            return Ok(None);
        }
        let expected_hash = self
            .read_block_hashes(height.saturating_sub(1), 1)?
            .into_iter()
            .next();
        Ok((expected_hash == Some(sidecar.block_hash)).then_some(sidecar))
    }
    /// Return the durable index count as recorded by the commit marker.
    ///
    /// # Errors
    /// Returns any durable marker/journal integrity or underlying I/O error.
    pub(crate) fn read_durable_index_count(&mut self) -> Result<u64> {
        self.read_exact_durable_index_count()
    }
    /// Read and validate the exact durable boundary without repair or fallback.
    ///
    /// This rejects partial journals, missing/malformed/non-canonical commit
    /// markers, marker/cache divergence, and a marker tip that does not match
    /// the hash journal. It deliberately does not inspect or promote a temp
    /// marker because authorization must bind the already-published boundary.
    fn read_exact_durable_index_count(&mut self) -> Result<u64> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(0);
        }
        let index_len = self.index_file_len()?;
        if index_len % BlockIndex::SIZE != 0 {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block index journal has a partial trailing entry",
                ),
                self.path_to_blockchain.join(INDEX_FILE_NAME),
            ));
        }
        let hashes_len = self.hashes_file_len()?;
        if hashes_len % SIZE_OF_BLOCK_HASH != 0 {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block hash journal has a partial trailing entry",
                ),
                self.path_to_blockchain.join(HASHES_FILE_NAME),
            ));
        }
        let index_count = index_len / BlockIndex::SIZE;
        let hashes_count = hashes_len / SIZE_OF_BLOCK_HASH;
        let marker_path = self.commit_marker_path();
        let Some(marker_bytes) = Kura::read_regular_sidecar_bytes_for(
            &self.path_to_blockchain,
            &marker_path,
            &self.path_to_blockchain,
            MAX_BLOCK_COMMIT_MARKER_BYTES,
        )?
        else {
            return Err(Error::IO(
                std::io::Error::new(ErrorKind::NotFound, "block commit marker is missing"),
                marker_path,
            ));
        };
        let marker =
            norito::decode_canonical::<BlockStoreCommitMarker>(&marker_bytes).map_err(|error| {
                match error {
                    norito::Error::NonCanonicalEncoding => Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "block commit marker is non-canonical or structurally invalid",
                        ),
                        marker_path.clone(),
                    ),
                    other => Error::NoritoFrame(other),
                }
            })?;
        if marker.version != BlockStoreCommitMarker::VERSION
            || (marker.count == 0) != marker.tip_hash.is_none()
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block commit marker is non-canonical or structurally invalid",
                ),
                marker_path,
            ));
        }
        if marker.count != self.commit_marker_count {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "published block commit marker differs from the opened durable boundary",
                ),
                marker_path,
            ));
        }
        if marker.count > index_count || marker.count > hashes_count {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "block commit marker exceeds a canonical journal",
                ),
                marker_path,
            ));
        }
        if marker.count > 0 {
            let actual_tip = self
                .read_block_hashes(marker.count.saturating_sub(1), 1)?
                .first()
                .copied();
            if actual_tip != marker.tip_hash {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "block commit marker tip differs from the canonical hash journal",
                    ),
                    marker_path,
                ));
            }
        }
        Ok(marker.count)
    }
    /// Read a series of block hashes from the block hashes file
    ///
    /// # Errors
    /// Returns an out-of-bounds error for an overflowing or unavailable range,
    /// or the original allocation or journal I/O error.
    pub(crate) fn read_block_hashes(
        &mut self,
        start_block_height: u64,
        block_count: usize,
    ) -> Result<Vec<HashOf<BlockHeader>>> {
        let hashes_file = self.ensure_hashes_file()?;
        let file_len = hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        let (start_location, _) =
            checked_block_hash_read_range(start_block_height, block_count, file_len)?;
        let mut hashes = Vec::new();
        hashes.try_reserve(block_count)?;
        hashes_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location))?;
            for _ in 0..block_count {
                let mut buffer = [0; Hash::LENGTH];
                file.read_exact(&mut buffer)?;
                if buffer[Hash::LENGTH - 1] & 1 == 0 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "block hash journal entry lacks the canonical marker bit",
                    ));
                }
                hashes.push(HashOf::from_untyped_unchecked(Hash::prehashed(buffer)));
            }
            Ok(())
        })?;
        Ok(hashes)
    }
    /// Get the number of hashes in the hashes file, which is
    /// calculated as the size of the hashes file in bytes divided by
    /// `size_of(HashOf<BlockHeader>)`.
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    #[allow(clippy::integer_division)]
    pub(crate) fn read_hashes_count(&mut self) -> Result<u64> {
        let hashes_file = self.ensure_hashes_file()?;
        let len = hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        Ok(len / SIZE_OF_BLOCK_HASH)
    }
    fn truncate_hashes_to_count(&mut self, count: u64) -> Result<()> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(());
        }
        let hashes_file = self.ensure_hashes_file()?;
        let new_len = count.saturating_mul(SIZE_OF_BLOCK_HASH);
        let current_len = hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        if new_len < current_len {
            hashes_file.try_io(|file| file.set_len(new_len))?;
        }
        Ok(())
    }
    fn data_end_for_index_prefix(&mut self, count: u64) -> Result<u64> {
        let mut data_end = 0u64;
        for index_pos in 0..count {
            let index = self.read_block_index(index_pos)?;
            if index.is_evicted() {
                continue;
            }
            let end = index
                .start
                .checked_add(index.length)
                .ok_or(Error::CorruptedBlockRange {
                    start: index.start,
                    length: index.length,
                    data_len: self.data_file_len()?,
                })?;
            data_end = data_end.max(end);
        }
        Ok(data_end)
    }
    fn truncate_data_to_index(&mut self, count: u64) -> Result<()> {
        if self.path_to_blockchain.as_os_str().is_empty() {
            return Ok(());
        }
        if count == 0 {
            self.invalidate_data_mmap();
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| file.set_len(0))?;
            return Ok(());
        }
        let target_len = match self.data_end_for_index_prefix(count) {
            Ok(index) => index,
            Err(err) => {
                warn!(
                    ?err,
                    count, "failed to read block indices while trimming data file"
                );
                return Ok(());
            }
        };
        let current_len = {
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| file.metadata().map(|meta| meta.len()))?
        };
        if current_len > target_len {
            self.invalidate_data_mmap();
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| file.set_len(target_len))?;
        }
        Ok(())
    }
    /// Return the current size of the block data file in bytes.
    ///
    /// # Errors
    /// Propagates I/O errors when the metadata cannot be read.
    pub(crate) fn data_file_len(&mut self) -> Result<u64> {
        let data_file = self.ensure_data_file()?;
        data_file.try_io(|file| file.metadata().map(|meta| meta.len()))
    }
    /// Return the current size of the block index file in bytes.
    ///
    /// # Errors
    /// Propagates I/O errors when the metadata cannot be read.
    pub(crate) fn index_file_len(&mut self) -> Result<u64> {
        let index_file = self.ensure_index_file()?;
        index_file.try_io(|file| file.metadata().map(|meta| meta.len()))
    }
    /// Return the current size of the block hashes file in bytes.
    ///
    /// # Errors
    /// Propagates I/O errors when the metadata cannot be read.
    pub(crate) fn hashes_file_len(&mut self) -> Result<u64> {
        let hashes_file = self.ensure_hashes_file()?;
        hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))
    }
    /// Read block data starting from the
    /// `start_location_in_data_file` in data file in order to fill
    /// `dest_buffer`.
    ///
    /// # Errors
    /// IO Error.
    pub fn read_block_data(
        &mut self,
        start_location_in_data_file: u64,
        dest_buffer: &mut [u8],
    ) -> Result<()> {
        #[cfg(test)]
        {
            self.body_read_calls.fetch_add(1, Ordering::Relaxed);
            self.body_bytes_read
                .fetch_add(u64::try_from(dest_buffer.len())?, Ordering::Relaxed);
        }
        let data_file = self.ensure_data_file()?;
        data_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location_in_data_file))?;
            file.read_exact(dest_buffer)
        })?;
        Ok(())
    }
    /// Write the index of a single block at the specified `block_height`.
    /// If `block_height` is beyond the end of the index file, attempt to
    /// extend the index file.
    ///
    /// # Errors
    /// IO Error.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn write_block_index(
        &mut self,
        block_height: u64,
        start: u64,
        length: u64,
    ) -> Result<()> {
        let index_file = self.ensure_index_file()?;
        let start_location = block_height * BlockIndex::SIZE;
        let new_len = start_location + BlockIndex::SIZE;
        let current_len = index_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        if new_len > current_len {
            index_file.try_io(|file| file.set_len(new_len))?;
        }
        index_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location))?;
            let bytes = BlockIndex { start, length }.encode();
            file.write_all(&bytes)
        })?;
        self.schedule_fsync_after_write()?;
        Ok(())
    }
    /// Change the size of the index file (the value returned by
    /// `read_index_count`).
    ///
    /// # Errors
    /// IO Error.
    ///
    /// The most common reason this function fails is
    /// that you did not call `create_files_if_they_do_not_exist`.
    ///
    /// Note that if there is an error, you can be quite sure all other
    /// read and write operations will also fail.
    #[cfg(test)]
    pub(crate) fn write_index_count(&mut self, new_count: u64) -> Result<()> {
        let index_file = self.ensure_index_file()?;
        let new_byte_size = new_count * BlockIndex::SIZE;
        index_file.try_io(|file| file.set_len(new_byte_size))?;
        Ok(())
    }
    /// Write `block_data` into the data file starting at
    /// `start_location_in_data_file`. Extend the file if
    /// necessary.
    ///
    /// # Errors
    /// IO Error.
    #[cfg(test)]
    pub(crate) fn write_block_data(
        &mut self,
        start_location_in_data_file: u64,
        block_data: &[u8],
    ) -> Result<()> {
        self.invalidate_data_mmap();
        let data_file = self.ensure_data_file()?;
        let end = start_location_in_data_file + block_data.len() as u64;
        let current_len = data_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        if end > current_len {
            data_file.try_io(|file| file.set_len(end))?;
        }
        data_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location_in_data_file))?;
            file.write_all(block_data)
        })?;
        self.schedule_fsync_after_write()?;
        Ok(())
    }
    /// Write the hash of a single block at the specified `block_height`.
    /// If `block_height` is beyond the end of the index file, attempt to
    /// extend the index file.
    ///
    /// # Errors
    /// IO Error.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn write_block_hash(
        &mut self,
        block_height: u64,
        hash: HashOf<BlockHeader>,
    ) -> Result<()> {
        let hashes_file = self.ensure_hashes_file()?;
        let start_location = block_height * SIZE_OF_BLOCK_HASH;
        let end = start_location + SIZE_OF_BLOCK_HASH;
        let current_len = hashes_file.try_io(|file| file.metadata().map(|meta| meta.len()))?;
        if end > current_len {
            hashes_file.try_io(|file| file.set_len(end))?;
        }
        hashes_file.try_io(|file| {
            file.seek(SeekFrom::Start(start_location))?;
            file.write_all(hash.as_ref())
        })?;
        self.schedule_fsync_after_write()?;
        Ok(())
    }
    /// Write the hashes to the hashes file overwriting any previous hashes.
    ///
    /// # Errors
    /// IO Error.
    pub(crate) fn overwrite_block_hashes(&mut self, hashes: &[HashOf<BlockHeader>]) -> Result<()> {
        let hashes_file = self.ensure_hashes_file()?;
        hashes_file.try_io(|file| {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))
        })?;
        hashes_file.try_io(|file| {
            let mut writer = BufWriter::new(&mut *file);
            for hash in hashes {
                writer.write_all(hash.as_ref())?;
            }
            writer.flush()
        })?;
        self.schedule_fsync_after_write()?;
        Ok(())
    }
    /// Rewrite a suffix of the hashes file while preserving every preceding byte.
    ///
    /// `start_block_height` is the zero-based hash index at which `hashes` begins.
    /// The existing journal must already contain the entire prefix. This is used by
    /// startup recovery when that prefix is protected by durable finality.
    fn overwrite_block_hash_suffix(
        &mut self,
        start_block_height: u64,
        hashes: &[HashOf<BlockHeader>],
    ) -> Result<()> {
        let path = self.path_to_blockchain.join(HASHES_FILE_NAME);
        let start_location = start_block_height
            .checked_mul(SIZE_OF_BLOCK_HASH)
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "hash suffix start offset overflowed",
                    ),
                    path.clone(),
                )
            })?;
        let suffix_count = u64::try_from(hashes.len())?;
        let new_count = start_block_height
            .checked_add(suffix_count)
            .ok_or_else(|| {
                Error::IO(
                    std::io::Error::new(ErrorKind::InvalidInput, "hash suffix count overflowed"),
                    path.clone(),
                )
            })?;
        let new_len = new_count.checked_mul(SIZE_OF_BLOCK_HASH).ok_or_else(|| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, "hash suffix length overflowed"),
                path.clone(),
            )
        })?;
        let hashes_file = self.ensure_hashes_file()?;
        hashes_file.try_io(|file| {
            let current_len = file.metadata()?.len();
            if current_len < start_location {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "hashes journal does not contain the finalized prefix",
                ));
            }
            file.seek(SeekFrom::Start(start_location))?;
            let mut writer = BufWriter::new(&mut *file);
            for hash in hashes {
                writer.write_all(hash.as_ref())?;
            }
            writer.flush()?;
            drop(writer);
            file.set_len(new_len)
        })?;
        self.schedule_fsync_after_write()?;
        Ok(())
    }
    fn require_existing_journal_bound_canonical_files(&self) -> Result<()> {
        for name in [
            INDEX_FILE_NAME,
            DATA_FILE_NAME,
            HASHES_FILE_NAME,
            COUNT_FILE_NAME,
        ] {
            let path = self.path_to_blockchain.join(name);
            if Kura::regular_sidecar_metadata_for(
                &self.path_to_blockchain,
                &path,
                &self.path_to_blockchain,
            )?
            .is_none()
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::NotFound,
                        "journal-selected canonical binding is missing a required store file",
                    ),
                    path,
                ));
            }
        }
        Ok(())
    }
    /// Open the prefix accepted by [`Self::preflight_fast_durable_prefix`] read-only.
    ///
    /// Fast mode leaves all published and unpublished bytes untouched. A later Strict restart owns
    /// journal-tail reconciliation and any required file creation.
    fn open_fast_prevalidated_files_read_only(&mut self) -> Result<()> {
        let count = self.fast_prevalidated_count.ok_or_else(|| {
            Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura Fast files were opened without committed-prefix preflight",
                ),
                self.path_to_blockchain.clone(),
            )
        })?;
        self.data_file = Some(FileWrap::open_read_only(
            self.path_to_blockchain.join(DATA_FILE_NAME),
        )?);
        self.index_file = Some(FileWrap::open_read_only(
            self.path_to_blockchain.join(INDEX_FILE_NAME),
        )?);
        self.hashes_file = Some(FileWrap::open_read_only(
            self.path_to_blockchain.join(HASHES_FILE_NAME),
        )?);

        let marker_path = self.commit_marker_path();
        let marker = match Self::read_bounded_commit_marker_bytes(&marker_path)? {
            Some(bytes) => norito::decode_canonical::<BlockStoreCommitMarker>(&bytes)
                .map_err(Error::NoritoFrame)?,
            None => {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::NotFound,
                        "Kura Fast committed-prefix marker disappeared after preflight",
                    ),
                    marker_path,
                ));
            }
        };
        if marker.version != BlockStoreCommitMarker::VERSION
            || marker.count != count
            || (marker.count == 0) != marker.tip_hash.is_none()
        {
            return Err(Error::IO(
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Kura Fast committed-prefix marker changed after preflight",
                ),
                marker_path,
            ));
        }

        self.commit_marker_count = count;
        self.commit_marker_pending = None;
        if self.read_exact_durable_index_count()? != count {
            return Err(Error::HashesFileHeightMismatch);
        }
        Ok(())
    }
    /// Create the index and data files if they do not
    /// already exist.
    ///
    /// This public entry point is for constructing an offline store. Live-node storage must be
    /// initialized through [`Kura`], which owns the process lock and recovery authority.
    ///
    /// # Errors
    /// Fails if any of the files don't exist and couldn't be
    /// created.
    pub fn create_files_if_they_do_not_exist(&mut self) -> Result<()> {
        Kura::reject_retired_snapshot_tail(&self.path_to_blockchain)?;
        // An exact retained compaction/rewrite stage may own replacement of a
        // missing live file. Recover that owner before generic absence checks.
        self.drop_cached_handles();
        self.recover_canonical_storage_stages()?;
        let stable_marker = self.read_commit_marker()?;
        if stable_marker.is_none() {
            for name in [INDEX_FILE_NAME, DATA_FILE_NAME, HASHES_FILE_NAME] {
                let path = self.path_to_blockchain.join(name);
                match secure_file_metadata::from_path(&path) {
                    Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => {}
                    Ok(_) => {
                        return Err(Error::IO(
                            std::io::Error::new(
                                ErrorKind::InvalidData,
                                "existing canonical journal has no stable commit marker",
                            ),
                            path,
                        ));
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(Error::IO(error, path)),
                }
            }
        }
        if stable_marker.is_some_and(|marker| marker.count > 0) {
            // Existing committed custody cannot be repaired by creating an empty
            // replacement journal. Preserve both absent paths and surviving bytes.
            for name in [INDEX_FILE_NAME, DATA_FILE_NAME, HASHES_FILE_NAME] {
                let path = self.path_to_blockchain.join(name);
                let metadata = secure_file_metadata::from_path(&path)
                    .map_err(|error| Error::IO(error, path.clone()))?;
                if !metadata.file_type().is_file() || !Kura::sidecar_is_single_link(&metadata) {
                    return Err(Error::IO(
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "committed canonical journal is not a direct single-link file",
                        ),
                        path,
                    ));
                }
            }
        }
        std::fs::create_dir_all(&*self.path_to_blockchain)
            .map_err(|e| Error::MkDir(e, self.path_to_blockchain.clone()))?;
        for name in [INDEX_FILE_NAME, DATA_FILE_NAME, HASHES_FILE_NAME] {
            let path = self.path_to_blockchain.join(name);
            FileWrap::open_with(path, |opts| {
                opts.write(true).truncate(false).create(true);
            })?;
        }
        self.drop_cached_handles();
        self.init_commit_marker()?;
        self.drop_cached_handles();
        Ok(())
    }
    /// Append `block_data` to this block store. First write
    /// the data to the data file and then create a new index
    /// for it in the index file.
    ///
    /// This public entry point is for offline store construction. Live nodes must append through
    /// [`Kura::store_block`] so canonical mutation authorization cannot be bypassed.
    ///
    /// # Errors
    /// Fails if any of the required platform-specific functions
    /// fail.
    pub fn append_block_to_chain(&mut self, block: &SignedBlock) -> Result<()> {
        // Borrow the original body through the same writer; offline persistence
        // needs neither a cloned execution graph nor a new shared control.
        let start_height = self.read_index_count()?;
        self.append_block_batch_at(start_height, &[block], 0)
    }
    /// Append multiple blocks to the chain in a single I/O batch.
    ///
    /// This method mirrors [`Self::append_block_to_chain`] but avoids repeated
    /// `sync_data` calls when persisting a contiguous run of blocks.
    ///
    /// # Errors
    /// Propagates I/O and encoding errors.
    pub(crate) fn append_block_batch(
        &mut self,
        blocks: &[iroha_data_model::block::SharedSignedBlock],
    ) -> Result<()> {
        let start_height = self.read_index_count()?;
        self.append_block_batch_at(start_height, blocks, 0)
    }
    #[allow(clippy::too_many_lines)]
    fn append_block_batch_at<B: core::ops::Deref<Target = SignedBlock>>(
        &mut self,
        start_height: u64,
        blocks: &[B],
        max_disk_usage_bytes: u64,
    ) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        self.recover_canonical_storage_stages()?;
        self.invalidate_data_mmap();
        debug!(
            start_height,
            batch_len = blocks.len(),
            "append_block_batch start"
        );
        let start_location_in_data_file = if start_height == 0 {
            0
        } else {
            let mut idx = start_height.saturating_sub(1);
            loop {
                let entry = self.read_block_index(idx)?;
                if !entry.is_evicted() {
                    break entry.start.checked_add(entry.length).ok_or(
                        Error::CorruptedBlockRange {
                            start: entry.start,
                            length: entry.length,
                            data_len: entry.start,
                        },
                    )?;
                }
                if idx == 0 {
                    break 0;
                }
                idx = idx.saturating_sub(1);
            }
        };
        debug!(
            start_height,
            start_location_in_data_file, "append_block_batch computed start location"
        );
        let mut frames = Vec::with_capacity(blocks.len());
        let mut lengths = Vec::with_capacity(blocks.len());
        let mut offsets = Vec::with_capacity(blocks.len());
        let mut hashes = Vec::with_capacity(blocks.len());
        for (idx, block) in blocks.iter().enumerate() {
            debug!(
                start_height,
                block_idx = idx,
                "append_block_batch encoding block"
            );
            let wire = block.canonical_wire()?;
            let frame = wire.into_vec();
            let frame_len = u64::try_from(frame.len())?;
            frames.push(frame);
            lengths.push(frame_len);
            hashes.push(block.hash());
            debug!(
                start_height,
                block_idx = idx,
                frame_len,
                "append_block_batch encoded block"
            );
        }
        debug!(
            start_height,
            frames = frames.len(),
            "append_block_batch prepared frames"
        );
        let mut cursor = start_location_in_data_file;
        let mut evicted = Vec::with_capacity(blocks.len());
        for (idx, len) in lengths.iter().enumerate() {
            let block_count_after = start_height
                .saturating_add(u64::try_from(idx)?)
                .saturating_add(1);
            let metadata_bytes =
                block_count_after.saturating_mul(BlockIndex::SIZE + SIZE_OF_BLOCK_HASH);
            let projected_inline_bytes = cursor.saturating_add(*len).saturating_add(metadata_bytes);
            let evict = max_disk_usage_bytes > 0 && projected_inline_bytes > max_disk_usage_bytes;
            evicted.push(evict);
            if evict {
                offsets.push(EVICTED_BLOCK_START);
                debug!(
                    start_height,
                    block_idx = idx,
                    frame_len = *len,
                    projected_inline_bytes,
                    max_disk_usage_bytes,
                    "append_block_batch sidecarring block body"
                );
                continue;
            }
            offsets.push(cursor);
            cursor = cursor.checked_add(*len).ok_or(Error::CorruptedBlockRange {
                start: cursor,
                length: *len,
                data_len: cursor,
            })?;
        }
        let end_pos = cursor;
        debug!(
            start_height,
            start_location = start_location_in_data_file,
            end_pos,
            frames = frames.len(),
            "append_block_batch preparing to write data"
        );
        let rewrite_stage = self.prepare_da_block_rewrite_stage(
            start_height,
            &frames,
            &offsets,
            &lengths,
            &hashes,
        )?;
        let journal_result = (|| -> Result<()> {
            let data_file = self.ensure_data_file()?;
            data_file.try_io(|file| {
                debug!(
                    start_height,
                    "append_block_batch writing frames to data file"
                );
                file.seek(SeekFrom::Start(start_location_in_data_file))?;
                for (frame, evict) in frames.iter().zip(evicted.iter()) {
                    if *evict {
                        continue;
                    }
                    file.write_all(frame)?;
                }
                debug!(start_height, "append_block_batch flushing data file");
                file.flush()?;
                Ok(())
            })?;
            debug!(
                start_height,
                start_location = start_location_in_data_file,
                end_pos,
                frames = frames.len(),
                "append_block_batch wrote data"
            );
            data_file.try_io(|file| {
                file.seek(SeekFrom::Start(end_pos))?;
                file.set_len(end_pos)
            })?;
            let hashes_file = self.ensure_hashes_file()?;
            let start_location = start_height * SIZE_OF_BLOCK_HASH;
            let new_hashes_len = start_location + SIZE_OF_BLOCK_HASH * u64::try_from(blocks.len())?;
            hashes_file.try_io(|file| file.set_len(new_hashes_len))?;
            hashes_file.try_io(|file| {
                file.seek(SeekFrom::Start(start_location))?;
                for hash in &hashes {
                    file.write_all(hash.as_ref())?;
                }
                file.flush()?;
                Ok(())
            })?;
            debug!(
                start_height,
                new_hashes_len, "append_block_batch wrote hashes"
            );
            // Write the index after data + hashes so the commit marker can safely advance.
            let index_file = self.ensure_index_file()?;
            let new_index_len = (start_height + blocks.len() as u64) * BlockIndex::SIZE;
            index_file.try_io(|file| {
                file.seek(SeekFrom::Start(start_height * BlockIndex::SIZE))?;
                for (start, len) in offsets.iter().zip(lengths.iter()) {
                    let bytes = BlockIndex {
                        start: *start,
                        length: *len,
                    }
                    .encode();
                    file.write_all(&bytes)?;
                }
                file.flush()?;
                file.set_len(new_index_len)?;
                Ok(())
            })?;
            debug!(
                start_height,
                new_index_len, "append_block_batch wrote index entries"
            );
            Ok(())
        })();
        if let Err(error) = journal_result {
            if rewrite_stage.is_some() {
                return Err(self.rollback_da_rewrite_before_returning(error));
            }
            return Err(error);
        }
        let end_height = start_height + blocks.len() as u64;
        self.commit_marker_pending = Some(
            self.commit_marker_pending
                .map_or(end_height, |pending| pending.max(end_height)),
        );
        self.mark_fsync_pending();
        if let Some(stage) = rewrite_stage.as_ref() {
            #[cfg(test)]
            if self
                .crash_next_da_rewrite_before_marker
                .swap(false, Ordering::AcqRel)
            {
                return Err(Error::IO(
                    std::io::Error::other(
                        "simulated crash after DA journal writes and before marker publication",
                    ),
                    self.da_block_rewrite_stage_path(),
                ));
            }
            let publication_result = (|| -> Result<()> {
                #[cfg(test)]
                if self
                    .fail_next_da_rewrite_before_marker
                    .swap(false, Ordering::AcqRel)
                {
                    return Err(Error::IO(
                        std::io::Error::other(
                            "injected DA rewrite failure after staging and before commit marker",
                        ),
                        self.da_block_rewrite_stage_path(),
                    ));
                }
                self.sync_target(FsyncTarget::Data, Self::ensure_data_file)?;
                self.sync_target(FsyncTarget::Hashes, Self::ensure_hashes_file)?;
                self.sync_target(FsyncTarget::Index, Self::ensure_index_file)?;
                self.write_commit_marker_value(&stage.new_marker)
            })();
            if let Err(publication_error) = publication_result {
                let marker = match self.read_commit_marker() {
                    Ok(marker) => marker,
                    Err(marker_error) => {
                        self.commit_marker_pending = None;
                        self.fsync.clear();
                        return Err(self.unknown_da_rewrite_state(
                            "commit-marker acknowledgement and readback both failed",
                            &marker_error,
                        ));
                    }
                };
                if marker.as_ref() == Some(&stage.new_marker) {
                    if let Err(recovery_error) = self.recover_da_block_rewrite_stage() {
                        self.defer_da_block_rewrite_recovery(&recovery_error);
                    }
                    debug!(
                        start_height,
                        end_height,
                        "append_block_batch committed despite publication acknowledgement error"
                    );
                    return Ok(());
                }
                if marker.as_ref() == Some(&stage.old_marker) {
                    return Err(self.rollback_da_rewrite_before_returning(publication_error));
                }
                self.commit_marker_pending = None;
                self.fsync.clear();
                return Err(self.unknown_da_rewrite_state(
                    "commit marker matches neither staged state after publication failure",
                    &publication_error,
                ));
            }
            self.commit_marker_count = stage.new_marker.count;
            self.commit_marker_pending = None;
            self.fsync.clear();
            #[cfg(test)]
            if self
                .crash_next_da_rewrite_after_marker
                .swap(false, Ordering::AcqRel)
            {
                return Err(Error::IO(
                    std::io::Error::other(
                        "simulated crash after DA marker publication and before body promotion",
                    ),
                    self.da_block_rewrite_stage_path(),
                ));
            }
            #[cfg(test)]
            if self
                .fail_next_da_rewrite_after_marker
                .swap(false, Ordering::AcqRel)
            {
                let injected_error = Error::IO(
                    std::io::Error::other(
                        "injected DA rewrite failure after commit marker publication",
                    ),
                    self.da_block_rewrite_stage_path(),
                );
                warn!(
                    ?injected_error,
                    "DA rewrite marker is durable; recovering staged body promotion in-call"
                );
                if let Err(recovery_error) = self.recover_da_block_rewrite_stage() {
                    self.defer_da_block_rewrite_recovery(&recovery_error);
                }
            } else if let Err(promotion_error) = self.promote_new_da_block_rewrite_stage(stage) {
                warn!(
                    ?promotion_error,
                    "DA rewrite marker is durable; retrying staged body promotion"
                );
                if let Err(recovery_error) = self.recover_da_block_rewrite_stage() {
                    self.defer_da_block_rewrite_recovery(&recovery_error);
                }
            } else if let Err(cleanup_error) = self.remove_da_block_rewrite_stage() {
                self.defer_da_block_rewrite_recovery(&cleanup_error);
            }
        } else if matches!(self.fsync.mode, FsyncMode::Always)
            || (matches!(self.fsync.mode, FsyncMode::Batched)
                && self.fsync.interval == Duration::ZERO)
        {
            self.flush_pending_fsync(false)?;
        }
        debug!(start_height, end_height, "append_block_batch complete");
        Ok(())
    }
}
include!("kura/prune_block_store_tail.rs");
#[cfg(test)]
include!("kura/test_fault_injection_state.rs");
#[cfg(test)]
include!("kura/test_fault_injection_controls.rs");
include!("kura/file_error_support.rs");
#[cfg(test)]
pub(crate) mod tests {
    use crate::state::StateReadOnly as _;

    #[test]
    fn root_storage_frame_owners_roundtrip_and_reject_substitution() {
        fn check<T>(value: &T, nominal: &str) -> T
        where
            T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
        {
            assert_eq!(T::nominal_name(), nominal);
            assert_eq!(T::frame_name(), nominal);
            let frame = norito::encode_canonical(value).expect("encode storage owner");
            assert_eq!(frame[6..22], norito::schema::identity::frame_hash::<T>());
            let decoded = norito::decode_canonical::<T>(&frame).expect("decode storage owner");
            assert_eq!(
                norito::encode_canonical(&decoded).expect("re-encode storage owner"),
                frame
            );
            let mut wrong_owner = frame.clone();
            wrong_owner[6] ^= 1;
            assert!(matches!(
                norito::decode_canonical::<T>(&wrong_owner),
                Err(norito::Error::SchemaMismatch)
            ));
            assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
            let mut trailing = frame;
            trailing.push(0);
            assert!(norito::decode_canonical::<T>(&trailing).is_err());
            decoded
        }
        fn file_digest(mut bytes: &[u8]) -> Hash {
            let len = bytes.len() as u64;
            BlockStore::eviction_reader_digest(&mut bytes, len).expect("digest fixture file image")
        }

        let mut blocks = NativeBlocks::new();
        let first = blocks.next();
        let second = blocks.next();
        let first_wire = first.encode_wire().expect("encode first canonical block");
        let second_wire = second.encode_wire().expect("encode second canonical block");
        let marker = BlockStoreCommitMarker::new(2, Some(second.hash()));
        assert_eq!(
            check(&marker, "iroha_core::kura::BlockStoreCommitMarker"),
            marker
        );
        let store = BlockStore::new(Path::new(""));
        let rewrite = DaBlockRewriteStageV1 {
            format_version: DA_BLOCK_REWRITE_STAGE_VERSION,
            old_marker: BlockStoreCommitMarker::new(1, Some(first.hash())),
            new_marker: marker.clone(),
            old_data_len: first_wire.len() as u64,
            old_index_count: 1,
            old_hash_count: 1,
            old_suffix: Vec::new(),
            replacement: vec![DaBlockRewriteImageV1 {
                height: 2,
                block_hash: second.hash(),
                index_start: first_wire.len() as u64,
                index_length: second_wire.len() as u64,
                body: second_wire.clone(),
            }],
        };
        store
            .validate_da_block_rewrite_stage(&rewrite)
            .expect("valid rewrite fixture");
        assert_eq!(
            check(&rewrite, "iroha_core::kura::DaBlockRewriteStageV1"),
            rewrite
        );
        let marker_bytes = norito::encode_canonical(&marker).expect("encode commit marker image");
        let hashes = [first.hash(), second.hash()];
        let hash_bytes: Vec<u8> = hashes
            .iter()
            .flat_map(|hash| hash.as_ref().iter().copied())
            .collect();
        let index_bytes = [
            BlockIndex {
                start: 0,
                length: first_wire.len() as u64,
            }
            .encode(),
            BlockIndex {
                start: EVICTED_BLOCK_START,
                length: second_wire.len() as u64,
            }
            .encode(),
        ]
        .concat();
        let eviction = EvictionCompactionStageV1 {
            format_version: EVICTION_COMPACTION_STAGE_VERSION,
            marker,
            marker_len: marker_bytes.len() as u64,
            marker_digest: file_digest(&marker_bytes),
            hashes_len: hash_bytes.len() as u64,
            hashes_digest: file_digest(&hash_bytes),
            data_temp_name: EVICTION_COMPACTION_DATA_FILE_NAME.to_owned(),
            data_len: first_wire.len() as u64,
            data_digest: file_digest(&first_wire),
            index_temp_name: EVICTION_COMPACTION_INDEX_FILE_NAME.to_owned(),
            index_len: index_bytes.len() as u64,
            index_digest: file_digest(&index_bytes),
            evicted: vec![EvictionCompactionEntryV1 {
                height: 2,
                block_hash: second.hash(),
                canonical_wire_hash: Hash::new(&second_wire),
                wire_len: second_wire.len() as u64,
            }],
        };
        store
            .validate_eviction_compaction_stage(&eviction)
            .expect("valid eviction fixture");
        assert_eq!(
            check(&eviction, "iroha_core::kura::EvictionCompactionStageV1"),
            eviction
        );
        let rewrite_frame = norito::encode_canonical(&rewrite).expect("encode rewrite owner");
        assert!(matches!(
            norito::decode_canonical::<EvictionCompactionStageV1>(&rewrite_frame),
            Err(norito::Error::SchemaMismatch)
        ));
    }

    fn kaigi_signal_test_call(name: &str) -> iroha_data_model::kaigi::KaigiId {
        iroha_data_model::kaigi::KaigiId::new(
            iroha_model_base::domain::DomainId::try_new("kaigi", "universal").expect("test domain"),
            name.parse().expect("test call name"),
        )
    }

    fn kaigi_signal_test_locator(
        height: usize,
        network_input_index: u32,
    ) -> super::KaigiSignalCandidateLocator {
        use iroha_crypto::{Hash, HashOf};
        use iroha_data_model::{block::BlockHeader, transaction::signed::TransactionEntrypoint};

        let marker = u64::try_from(height)
            .expect("test height fits u64")
            .wrapping_mul(4);
        super::KaigiSignalCandidateLocator {
            position: super::KaigiSignalCandidatePosition {
                block_height: u64::try_from(height).expect("test height fits u64"),
                network_input_index,
                block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                    marker.to_le_bytes(),
                )),
                entrypoint_hash: HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
                    Hash::new((marker ^ u64::from(network_input_index)).to_le_bytes()),
                ),
            },
            authority: iroha_data_model::AccountId::new(
                super::checked_keypair().public_key().clone(),
            ),
        }
    }

    fn insert_kaigi_signal_test_locator(
        index: &mut super::TransactionEntrypointIndex,
        call_id: &iroha_data_model::kaigi::KaigiId,
        locator: super::KaigiSignalCandidateLocator,
    ) {
        let height = usize::try_from(locator.position.block_height)
            .ok()
            .and_then(std::num::NonZeroUsize::new)
            .expect("test locator height is nonzero");
        let inserted = index
            .inventories_by_height
            .entry(height)
            .or_default()
            .kaigi_calls
            .insert(call_id.clone());
        index.nested_associations.inserted(inserted);
        let replaced = index
            .kaigi_signal_candidates
            .entry(call_id.clone())
            .or_default()
            .entry(height)
            .or_default()
            .insert(locator.position.network_input_index, locator);
        index.nested_associations.inserted(replaced.is_none());
    }

    #[test]
    fn kaigi_signal_locator_pages_are_chronological_exclusive_and_call_bound() {
        let call_id = kaigi_signal_test_call("page-order");
        let other_call = kaigi_signal_test_call("other-call");
        let mut index = super::TransactionEntrypointIndex::complete_empty();
        for locator in [
            kaigi_signal_test_locator(1, 1),
            kaigi_signal_test_locator(2, 0),
            kaigi_signal_test_locator(1, 0),
        ] {
            insert_kaigi_signal_test_locator(&mut index, &call_id, locator);
        }
        let first = super::Kura::collect_kaigi_signal_candidate_locators(
            &index,
            &call_id,
            2,
            None,
            std::num::NonZeroUsize::new(2).expect("nonzero page"),
        )
        .expect("first locator page");
        assert!(first.has_more);
        assert_eq!(first.candidates[0].position.network_input_index, 0);
        assert_eq!(first.candidates[1].position.network_input_index, 1);
        let after = first.candidates[1].position;
        let second = super::Kura::collect_kaigi_signal_candidate_locators(
            &index,
            &call_id,
            2,
            Some(after),
            std::num::NonZeroUsize::new(2).expect("nonzero page"),
        )
        .expect("second locator page");
        assert!(!second.has_more);
        assert_eq!(second.candidates.len(), 1);
        assert_eq!(second.candidates[0].position.block_height, 2);
        assert_eq!(
            super::Kura::collect_kaigi_signal_candidate_locators(
                &index,
                &other_call,
                2,
                Some(after),
                std::num::NonZeroUsize::new(1).expect("nonzero page"),
            ),
            Err(super::KaigiSignalCandidateIndexError::CursorMismatch),
        );
        let position = first.candidates[0].position;
        assert!(
            super::KaigiSignalCandidatePosition::new(
                0,
                position.network_input_index,
                position.block_hash,
                position.entrypoint_hash,
            )
            .is_none()
        );
        let foreign = super::KaigiSignalCandidatePosition::new(
            1,
            u32::MAX,
            position.block_hash,
            position.entrypoint_hash,
        )
        .expect("structural position uses the full u32 input range");
        assert_eq!(
            super::Kura::collect_kaigi_signal_candidate_locators(
                &index,
                &call_id,
                2,
                Some(foreign),
                std::num::NonZeroUsize::new(1).unwrap(),
            ),
            Err(super::KaigiSignalCandidateIndexError::CursorMismatch),
        );
    }

    #[test]
    fn kaigi_signal_locator_pages_advance_beyond_five_hundred_carriers() {
        let call_id = kaigi_signal_test_call("long-history");
        let mut index = super::TransactionEntrypointIndex::complete_empty();
        for height in 1..=501 {
            insert_kaigi_signal_test_locator(
                &mut index,
                &call_id,
                kaigi_signal_test_locator(height, 0),
            );
        }
        let first = super::Kura::collect_kaigi_signal_candidate_locators(
            &index,
            &call_id,
            501,
            None,
            std::num::NonZeroUsize::new(500).expect("nonzero page"),
        )
        .expect("bounded first page");
        assert_eq!(first.candidates.len(), 500);
        assert!(first.has_more);
        let second = super::Kura::collect_kaigi_signal_candidate_locators(
            &index,
            &call_id,
            501,
            first.candidates.last().map(|locator| locator.position),
            std::num::NonZeroUsize::new(500).expect("nonzero page"),
        )
        .expect("bounded continuation");
        assert_eq!(second.candidates.len(), 1);
        assert_eq!(second.candidates[0].position.block_height, 501);
        assert!(!second.has_more);
    }

    #[test]
    fn kaigi_signal_reverse_inventories_follow_replacement_and_truncation() {
        let call_id = kaigi_signal_test_call("lifecycle");
        let replacement_call = kaigi_signal_test_call("replacement");
        let mut index = super::TransactionEntrypointIndex::complete_empty();
        for height in 1..=3 {
            let height_key = std::num::NonZeroUsize::new(height).expect("nonzero height");
            index.indexed_heights.insert(height_key);
            insert_kaigi_signal_test_locator(
                &mut index,
                &call_id,
                kaigi_signal_test_locator(height, 0),
            );
        }
        let height_two = std::num::NonZeroUsize::new(2).expect("nonzero height");
        index.incomplete_heights.insert(height_two);
        super::Kura::remove_transaction_entrypoint_height(&mut index, height_two);
        assert!(!index.indexed_heights.contains(&height_two));
        assert!(!index.incomplete_heights.contains(&height_two));
        assert!(
            index.kaigi_signal_candidates[&call_id]
                .get(&height_two)
                .is_none()
        );
        index.indexed_heights.insert(height_two);
        insert_kaigi_signal_test_locator(
            &mut index,
            &replacement_call,
            kaigi_signal_test_locator(2, 7),
        );
        assert!(
            index
                .kaigi_signal_candidates
                .contains_key(&replacement_call)
        );
        super::Kura::truncate_transaction_entrypoint_index_to(&mut index, 1);
        assert_eq!(index.kaigi_signal_candidates[&call_id].len(), 1);
        assert_eq!(
            index.kaigi_signal_candidates[&call_id]
                .first_key_value()
                .map(|(height, _)| height.get()),
            Some(1),
        );
        assert!(
            !index
                .kaigi_signal_candidates
                .contains_key(&replacement_call)
        );
        assert_eq!(index.inventories_by_height.len(), 1);
        assert!(
            index
                .inventories_by_height
                .contains_key(&std::num::NonZeroUsize::new(1).expect("nonzero height"))
        );
    }

    include!("kura/tests/canonical_network_index.rs");
    include!("kura/tests/bounded_canonical_body_reads.rs");
    include!("kura/tests/committed_network_proof_support.rs");
    include!("kura/tests/canonical_network_query_support.rs");
    include!("kura/tests/resident_resource_inventory.rs");

    // Textual includes preserve every test in the existing `kura::tests` namespace.
    include!("kura/tests/00_bounded_sidecar_read_tests.rs");
    include!("kura/tests/01_support_snapshot_bootstrap_and_rewrite.rs");
    include!("kura/tests/02_replacement_and_preflight.rs");
    include!("kura/tests/02a_fresh_single_lane_preflight.rs");
    include!("kura/tests/03_preflight_and_merge_entry.rs");
    include!("kura/tests/04_merge_log_and_associations.rs");
    include!("kura/tests/05_merge_resolution_and_eviction.rs");
    include!("kura/tests/05b_canonical_physical_resource_tests.rs");
    include!("kura/tests/06_eviction_and_autonomous_lanes.rs");
    include!("kura/tests/07e_autonomous_publication_temp_recovery_tests.rs");
    include!("kura/tests/09_lane_artifacts_and_fastpq.rs");
    include!("kura/tests/11_roster_and_progress_sidecars.rs");
    include!("kura/tests/12_sidecar_index_and_pruning.rs");
    include!("kura/tests/13_manifests_and_fsync.rs");
    include!("kura/tests/14_pipeline_and_lane_frame_owners.rs");
    include!("kura/tests/14b_sidecar_physical_resource_tests.rs");
    include!("kura/tests/14a_physical_resource_guard_tests.rs");
    include!("kura/tests/14b_metadata_physical_resource_tests.rs");
    include!("kura/tests/15_remaining_physical_writer_tests.rs");
    include!("kura/tests/16_resource_file_admission_tests.rs");
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    include!("kura/tests/17_read_only_evidence_tests.rs");
    include!("kura/tests/18_block_hash_ranges.rs");
    include!("kura/tests/19_transaction_history_budget.rs");
}
