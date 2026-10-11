//! Sans-IO interface data types (spec §12): events the driver feeds into the core, actions the
//! core asks the driver to perform, startup input, local configuration, halt and fault reasons,
//! and read-only diagnostics.

use core::fmt;

use iroha_schema::IntoSchema;

use crate::{
    availability::{AvailabilitySource, AvailableBody, PayloadBytes},
    message::{BlockHeader, Evidence, Qc, WireMessage},
    safety::{RecordState, SafetyRecord},
    types::{Hash32, HeightConfig, Millis, PublicKey},
};

/// Complete view-independent application-control source for the next proposal height.
/// Every field must be revalidated against the same applied parent by the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, IntoSchema)]
pub struct ApplicationControlContext {
    /// Exact consensus instance.
    pub instance: Hash32,
    /// Authenticated scheduling epoch and complete authority context.
    pub epoch: crate::types::EpochId,
    /// Height whose control input is being prepared.
    pub height: u64,
    /// Exact core hash of the applied parent.
    pub parent_hash: Hash32,
    /// Parent result, independently rederived by the application from that same State.
    pub parent_result: Hash32,
}

/// A view-specific request for independently built application control witness bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlWitnessContext {
    /// Proposal height.
    pub height: u64,
    /// Fresh proposal view; a response from another view is stale.
    pub view: u64,
    /// Exact authenticated scheduling epoch and complete context.
    pub epoch: crate::types::EpochId,
    /// Exact core hash of the applied parent.
    pub parent_hash: Hash32,
    /// Independently checked execution result of that same parent.
    pub parent_result: Hash32,
}

/// Local configuration (§12.4). Only affects performance; validated by
/// [`crate::pacemaker::validate_local`] (§9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalParams {
    /// Base view timeout `T_base`.
    pub t_base: Millis,
    /// Timeout cap `T_max` (the effective cap is never below `T_req`).
    pub t_max: Millis,
    /// Largest start level.
    pub start_cap: u32,
    /// Fast commits needed to lower the start level by one.
    pub decay_after: u32,
    /// State rebroadcast interval while unsettled (`≤ T_base / 2`).
    pub rebroadcast_interval: Millis,
    /// Status interval while settled.
    pub status_keepalive: Millis,
    /// Payload build timeout.
    pub build_timeout: Millis,
    /// Body fetch retry interval (`≤ rebroadcast_interval`).
    pub fetch_retry: Millis,
    /// Entries per sync request.
    pub sync_batch: u16,
    /// Sync request retry interval.
    pub sync_retry: Millis,
    /// Bytes per sync response (`≥ max_block_bytes + FRAME_OVERHEAD`).
    pub sync_max_bytes: u32,
    /// Observers kept in the peer table besides the committee.
    pub max_observers: u32,
}

impl LocalParams {
    /// §9.3 defaults for a committee of `n` members: the `n = 4` column below 10 members, the
    /// `n ≈ 20` column from 10 members on.
    // SPEC: §9.3 gives columns for n = 4 and n ≈ 20 (≤ 31) without a boundary; 10 is used.
    // (Appendix E, E14)
    pub fn for_committee_size(n: usize) -> Self {
        if n < 10 {
            Self::default()
        } else {
            Self {
                t_base: 3_000,
                rebroadcast_interval: 1_000,
                fetch_retry: 500,
                ..Self::default()
            }
        }
    }
}

impl Default for LocalParams {
    /// §9.3 defaults, `n = 4` column.
    fn default() -> Self {
        Self {
            t_base: 2_000,
            t_max: 30_000,
            start_cap: 4,
            decay_after: 8,
            rebroadcast_interval: 500,
            status_keepalive: 5_000,
            build_timeout: 200,
            fetch_retry: 250,
            sync_batch: 64,
            sync_retry: 1_000,
            sync_max_bytes: 16 * 1024 * 1024,
            max_observers: 64,
        }
    }
}

/// Invalid local configuration or chain parameters (§9.4), or unusable startup input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Signed availability layout violates the protocol dimensions or capacity.
    AvailabilityLayout(crate::availability::LayoutError),
    /// The admitted chain payload maximum exceeds its authenticated RS16 limit.
    PayloadAboveAvailabilityLimit,
    /// `T_max < T_req(nominal)` for an initial configuration.
    TMaxBelowRequirement {
        /// Configured `T_max`.
        t_max: Millis,
        /// Required `T_req(nominal)`.
        t_req: Millis,
    },
    /// `rebroadcast_interval > T_base / 2`.
    RebroadcastTooLong,
    /// `sync_batch < 1`.
    SyncBatchZero,
    /// `sync_batch` above the decode limit of a sync response.
    SyncBatchTooLarge,
    /// `sync_max_bytes < max_block_bytes + FRAME_OVERHEAD`.
    SyncMaxBytesTooSmall,
    /// `fetch_retry > rebroadcast_interval`.
    FetchRetryTooLong,
    /// A timer interval is zero.
    ZeroInterval(&'static str),
    /// Chain parameters: `block_time > payload_retry_interval`.
    BlockTimeAbovePayloadRetry,
    /// Chain parameters: payload rebuild polling must not busy-loop.
    PayloadRetryIntervalZero,
    /// `Init.demotion_window < 1` (`W` is a genesis constant, §9.4).
    DemotionWindowZero,
    /// Chain parameters: `max_block_bytes` above the transport frame limit.
    MaxBlockBytesAboveTransport,
    /// `Init` lacks the configuration of a required height.
    MissingConfig(u64),
    /// `Init` is internally inconsistent (e.g. tip below genesis).
    InvalidInit(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

/// The committed tip the driver's block store holds at startup (§7.4 Restart).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommittedTip {
    /// Tip height `t` (`g` before the first commit).
    pub height: u64,
    /// Block hash of the tip (the genesis block hash at `g`).
    pub block_hash: Hash32,
    /// Certified result of the tip (the genesis result at `g`).
    pub result: Hash32,
    /// Header of the tip (`None` at `g`).
    pub header: Option<BlockHeader>,
    /// `CommitQC` of the tip (`None` at `g`).
    pub commit_qc: Option<Qc>,
}

/// Startup input (§12.1, §7.4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Init {
    /// Instance id `I` (§1.8), derived by the application.
    // SPEC: §12.1 `Init` has no instance id, but the core needs `I` before any record, header or
    // certificate is available (a fresh genesis start); it is passed explicitly (Appendix E, E15).
    pub instance: Hash32,
    /// One entry per configured or retired key (§7.4 Keys): the key, what the driver found on
    /// disk, and whether the key is retired (restored like the others, but never signs; no
    /// signer is passed for it).
    pub records: Vec<(PublicKey, RecordState, bool)>,
    /// Genesis height `g`.
    pub genesis_height: u64,
    /// The demotion window `W`, a genesis constant of the instance (§2.1); must be `≥ 1`.
    pub demotion_window: u64,
    /// A fresh random value drawn by the driver for this `Init`: the probe nonce of this
    /// process lifetime (§7.4 R2).
    pub nonce: u64,
    /// Block-store tip `t`.
    pub tip: CommittedTip,
    /// Exact installed/pending slots of `t` (unless `t = g`), `t + 1` and `t + 2`.
    pub configs: Vec<(u64, crate::types::ConfigSlot)>,
    /// The last `W + 2` committed headers (`≤ t`).
    pub recent_headers: Vec<BlockHeader>,
}

/// Answer to `Action::Execute` (§4.1, O4): exactly one per request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExecOutcome {
    /// Deterministic success with execution commitment `R`.
    Valid(Hash32),
    /// Deterministically invalid block.
    Invalid,
    /// Local executor failure (panic, I/O, resource exhaustion) — never invalidity.
    Failed(String),
    /// Work cancelled by a `DiscardExecution` that left the block out.
    Cancelled,
}

/// Events delivered to `Core::handle` (§12.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Timer: `next_wakeup()` was reached.
    Tick,
    /// A network message from an authenticated peer.
    Message {
        /// Sender's key (from the P2P layer; never trusted for safety).
        from: PublicKey,
        /// The message.
        msg: WireMessage,
    },
    /// Answer to `BuildPayload{req}`; an answer to another request is ignored.
    PayloadBuilt {
        /// Request id of the `BuildPayload`.
        req: u64,
        /// Original funded nonempty payload, or no includable work.
        payload: Option<PayloadBytes>,
    },
    /// Exact original-author worker completion; stale request/source completions are ignored.
    PayloadAuthored {
        /// Original request id whose work and application control produced this header.
        req: u64,
        /// Opaque authenticated original-pool body; no raw substitute is accepted.
        body: AvailableBody,
    },
    /// Exact answer to application control requested after selecting nonempty work.
    ControlWitnessBuilt {
        /// Fresh build request id.
        req: u64,
        /// Exact request source; a response from another source or view is ignored.
        context: ControlWitnessContext,
        /// Bounded canonical control bytes.
        witness: crate::types::ControlWitness,
    },
    /// The sole application owner has one own partial to retransmit for this source.
    ApplicationControlBuilt {
        /// Complete source-bound envelope; the core rechecks it before sending.
        message: crate::message::ApplicationControl,
    },
    /// After answering `BuildPayload{req}` with `EMPTY`: an includable transaction arrived (at
    /// most once per `req`). It ends an eligible leader's empty-build wait at any view (§6.10).
    PayloadReady {
        /// Request id of the `BuildPayload` answered with `EMPTY`.
        req: u64,
    },
    /// Answer to `Execute`.
    Executed {
        /// Executed block.
        block_hash: Hash32,
        /// Request id of the `Execute`.
        req: u64,
        /// Outcome.
        outcome: ExecOutcome,
    },
    /// Actual authenticated custody from reconstruction or exact stored-body restoration.
    BodyAvailable {
        /// The block.
        block: AvailableBody,
    },
    /// A worker rejected this exact manifest's semantics; never a local resource refusal.
    ManifestRejected {
        /// Original rejected carrier, compared exactly before clearing a buffered sync entry.
        manifest: crate::message::PayloadManifest,
    },
    /// A committed block is durably applied (in height order, one per height, O3).
    BlockApplied {
        /// Applied height `a`.
        height: u64,
        /// Its block hash.
        block_hash: Hash32,
        /// The applied header (source of the core's `recent_headers`, §2.1).
        header: Box<BlockHeader>,
        /// Configuration of height `a + 2` scheduled by the state after `a`.
        config: crate::types::AppliedConfig,
    },
    /// The original publication owner cannot retry safely; it was consumed, may be visible,
    /// or was lost with its worker. Local recovery is required, not a consensus invalid verdict.
    PublicationRecoveryRequired {
        /// Height whose publication cannot safely resume in this process.
        height: u64,
    },
    /// Apply produced a commitment different from the certified result (O3).
    ApplyDiverged {
        /// Height.
        height: u64,
        /// Block hash.
        block_hash: Hash32,
        /// The locally computed commitment.
        local_result: Hash32,
    },
}

/// Actions returned by `Core::handle`, executed by the driver in order (O1).
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::large_enum_variant, reason = "driver takes blocks by value")]
pub enum Action {
    /// Durably write the safety record (a barrier for later effects, O2).
    PersistSafety(Box<SafetyRecord>),
    /// Durably store a block body keyed by `(height, block_hash)`.
    StoreBody {
        /// The block.
        block: AvailableBody,
    },
    /// Send to one peer.
    Send {
        /// Recipient.
        to: PublicKey,
        /// Message.
        msg: WireMessage,
    },
    /// Send to several peers, in list order.
    Broadcast {
        /// Recipients.
        to: Vec<PublicKey>,
        /// Message.
        msg: WireMessage,
    },
    /// Build the mandatory application-control response for retained nonempty work.
    BuildControlWitness {
        /// Fresh request id shared with this fresh proposal's transaction request.
        req: u64,
        /// Exact view and authenticated parent source.
        context: ControlWitnessContext,
    },
    /// Drive the single process-lived application-control producer for an applied parent.
    DriveApplicationControl {
        /// View-independent source, independently revalidated by the application.
        context: ApplicationControlContext,
    },
    /// Deliver one bounded peer partial to the sole application-control owner.
    ReceiveApplicationControl {
        /// P2P-authenticated current committee sender, rechecked by the application.
        from: PublicKey,
        /// Complete source-bound envelope.
        message: crate::message::ApplicationControl,
    },
    /// Build a payload (the builder only peeks at its queue).
    BuildPayload {
        /// Request id (never reused); the answer `PayloadBuilt{req}` carries it.
        req: u64,
        /// Height.
        height: u64,
        /// View.
        view: u64,
        /// Size limit.
        max_bytes: u32,
        /// Execution budget hint `min(e_max, φ·T_base/2)` (§9.1).
        exec_budget_ms: u32,
    },
    /// Encode/sign the retained nonempty work outside the Core event loop.
    AuthorPayload {
        /// Original build request id.
        req: u64,
        /// Independently authenticated height configuration for original author/geometry.
        config: HeightConfig,
        /// Exact header template; the worker replaces only its availability digest.
        header: BlockHeader,
        /// Original funded application work, retained by the move-only worker job.
        payload: PayloadBytes,
    },
    /// Start or resume source-bound acquisition using mandatory original availability evidence.
    AcquirePayload {
        /// Independent expected source and authenticated historical configuration.
        source: AvailabilitySource,
        /// Original evidence; it grants no custody before real reconstruction.
        manifest: crate::message::PayloadManifest,
    },
    /// Supply actual received row bytes only to an already-wanted acquisition job.
    ReceivePayloadChunk {
        /// Authenticated transport sender; this is relay provenance, not the original author.
        from: PublicKey,
        /// Exact row; the counted Sumeragi worker authenticates it before retaining/counting it.
        chunk: crate::message::PayloadChunk,
    },
    /// Disseminate exact original rows after the existing durable-body barrier.
    DisseminatePayload {
        /// Recipients, in canonical order.
        peers: Vec<PublicKey>,
        /// Opaque body from which exact rows are derived without any re-signing.
        body: AvailableBody,
    },
    /// Execute a block against its parent's state.
    Execute {
        /// The block.
        block: AvailableBody,
        /// Request id (never reused).
        req: u64,
        /// The node holds a `PrepareQC` at the block's height for this block (a re-proposal's
        /// `Q`, or its own lock), evaluated at every emission (§4.2, §6.2 step 9). It never
        /// changes the verdict: it only exempts the block from the application's local-clock
        /// guards (§4.5 CT1, CT5), whose honest first Prepare voters already passed them.
        certified: bool,
    },
    /// Cancel and drop executions of blocks at `height` other than `keep`.
    DiscardExecution {
        /// Height.
        height: u64,
        /// Blocks whose executions are kept.
        keep: Vec<Hash32>,
    },
    /// Apply a committed block (strictly increasing heights). The driver reuses a cached
    /// post-state whose commitment equals `commit_qc.result`, or an execution of the block still
    /// in flight, and otherwise executes it (O3).
    CommitBlock {
        /// The block.
        block: AvailableBody,
        /// Its `CommitQC`.
        commit_qc: Qc,
    },
    /// Obtain exact source-bound custody from a retained storage job or actual signed rows.
    FetchPayload {
        /// Independent source and authenticated historical configuration.
        source: AvailabilitySource,
        /// Peers to ask.
        peers: Vec<PublicKey>,
    },
    /// Serve requested original rows only after resolving the authenticated historical source.
    ServePayload {
        /// Requester.
        to: PublicKey,
        /// Height.
        height: u64,
        /// Block hash.
        block_hash: Hash32,
    },
    /// Answer a `SyncRequest` from the block store.
    ServeBlocks {
        /// Requester.
        to: PublicKey,
        /// First height.
        from_height: u64,
        /// Entry limit.
        max_count: u16,
        /// Byte limit.
        max_bytes: u32,
    },
    /// The payload of this block is deterministically invalid; quarantine its transactions.
    PayloadRejected {
        /// Height.
        height: u64,
        /// View.
        view: u64,
        /// Block hash.
        block_hash: Hash32,
    },
    /// Report signed misbehaviour.
    ReportEvidence(Box<Evidence>),
    /// Report a local fault (telemetry).
    LocalFault(LocalFault),
    /// Halt this instance (only serving continues).
    Halt(HaltReason),
}

/// Why an instance halts (§12.5). Nothing else halts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltReason {
    /// R1: the local safety record is corrupt or belongs to another instance or key.
    SafetyRecordCorrupt,
    /// The safety record or a committed body contradicts the block store (local storage
    /// corruption): R5, the record's parent `CommitQC` does not verify; §7.4 step 4 (E2), the
    /// record of some key at `tip.height + 1` has a `parent_commit_qc` that is not a valid
    /// `CommitQC` of the block-store tip (or one is present at `g + 1` or absent above it);
    /// §6.9 rule 6, a committed body does not extend the committed parent.
    SafetyRecordInconsistent,
    /// §7.6: a valid `CommitQC` conflicts with a committed block.
    SafetyViolation {
        /// The committed height with two values.
        height: u64,
    },
    /// O3: local apply disagrees with a certified result.
    ApplyDiverged {
        /// Height.
        height: u64,
    },
    /// The executor lost or consumed the original publication owner; stop until recovery.
    PublicationRecoveryRequired {
        /// Height whose original publication requires recovery.
        height: u64,
    },
    /// A driver contract violation (§6.13): a `BlockApplied` out of order, whose header does
    /// not hash to its `block_hash`, or whose block is not the one this core committed there.
    DriverAnomaly,
}

/// Local faults (telemetry only; never evidence, never a halt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFault {
    /// Local execution disagrees with a certified result (§4.2).
    ExecutionMismatch {
        /// Height.
        height: u64,
        /// View.
        view: u64,
    },
    /// The executor reported `Failed` (§4.2).
    ExecutorFailed {
        /// Height.
        height: u64,
    },
    /// R2: the safety record was missing; the key is unanchored until the probe anchors it.
    RecordMissing,
    /// R6: the block store is behind the safety record; the key abstains.
    StoreBehindRecord {
        /// Height of the record.
        record_height: u64,
    },
    /// Two configured keys are in `C_h`; neither signs (§7.4).
    KeyConflict {
        /// Height.
        height: u64,
    },
    /// A committed configuration raised `T_req` above `T_max` (§9.4).
    ConfigTooTight {
        /// The new `T_req(nominal)`.
        t_req: Millis,
    },
}

/// Memory footprint counters of a core (§8.4), checked by the O-MEM oracle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Footprint {
    /// Votes in all pools.
    pub votes: usize,
    /// Stored timeout votes.
    pub timeouts: usize,
    /// Fresh transaction parts waiting for their independent control response (at most one).
    pub fresh_payloads: usize,
    /// Current-source per-member application-control ingress timestamps.
    pub control_peers: usize,
    /// Block bodies in memory.
    pub blocks: usize,
    /// `exec` entries.
    pub exec_entries: usize,
    /// Outstanding wants.
    pub wants: usize,
    /// `pending_apply` entries.
    pub pending_apply: usize,
    /// Buffered sync entries.
    pub sync_entries: usize,
    /// Bytes of buffered sync entries.
    pub sync_bytes: usize,
    /// Peer table entries.
    pub peers: usize,
    /// Recent committed headers.
    pub recent_headers: usize,
    /// Height configurations held.
    pub configs: usize,
    /// Verified-certificate cache entries.
    pub cert_cache: usize,
    /// Evidence dedup keys.
    pub evidence_keys: usize,
    /// Probe table entries (§7.4 R2).
    pub probe: usize,
}

impl Footprint {
    /// The §8.4 bounds for a committee of `n` members and the demotion window `window`.
    pub fn bound(n: usize, local: &LocalParams, window: u64) -> Self {
        let sync_batch = usize::from(local.sync_batch);
        let window = usize::try_from(window).unwrap_or(usize::MAX);
        Self {
            votes: 3 * 2 * n,
            timeouts: n,
            fresh_payloads: 1,
            control_peers: n,
            blocks: 6,
            exec_entries: 6,
            wants: 5,
            pending_apply: 2,
            sync_entries: 2 * sync_batch,
            sync_bytes: 2 * usize::try_from(local.sync_max_bytes).unwrap_or(usize::MAX),
            peers: n + usize::try_from(local.max_observers).unwrap_or(usize::MAX),
            recent_headers: window.saturating_add(2),
            configs: 4,
            cert_cache: 4 * n,
            evidence_keys: 3 * (3 * n + 1),
            probe: n,
        }
    }

    /// Whether every counter is within `bound`.
    pub fn within(&self, bound: &Self) -> bool {
        self.votes <= bound.votes
            && self.timeouts <= bound.timeouts
            && self.fresh_payloads <= bound.fresh_payloads
            && self.control_peers <= bound.control_peers
            && self.blocks <= bound.blocks
            && self.exec_entries <= bound.exec_entries
            && self.wants <= bound.wants
            && self.pending_apply <= bound.pending_apply
            && self.sync_entries <= bound.sync_entries
            && self.sync_bytes <= bound.sync_bytes
            && self.peers <= bound.peers
            && self.recent_headers <= bound.recent_headers
            && self.configs <= bound.configs
            && self.cert_cache <= bound.cert_cache
            && self.evidence_keys <= bound.evidence_keys
            && self.probe <= bound.probe
    }
}

/// Read-only diagnostics of a core (§12.1 `status()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreStatus {
    /// Instance id.
    pub instance: Hash32,
    /// Current round height.
    pub height: u64,
    /// Current round view.
    pub view: u64,
    /// Routing stage of the round (0, 1, 2).
    pub stage: u8,
    /// Leader `L(h, view)` of the current round (`None` while awaiting: the next round's
    /// committee is not known yet).
    // SPEC: §12.1 lists no roles in `status()`; the node's status endpoint reports them
    // (Appendix E, E45).
    pub leader: Option<PublicKey>,
    /// Proxy tail `P(h, view)` of the current round (`None` while awaiting).
    pub proxy_tail: Option<PublicKey>,
    /// View of the lock (`high_pqc`) at the current height, if any.
    pub high_qc_view: Option<u64>,
    /// Level of the current view.
    pub level: u32,
    /// Start level of the height.
    pub start_level: u32,
    /// Current `t_retx`.
    pub t_retx: Millis,
    /// Committed tip height.
    pub committed_height: u64,
    /// Highest applied height.
    pub applied_height: u64,
    /// Committed but waiting for the next configuration.
    pub awaiting: bool,
    /// Key signing at this height (`None` = observer).
    pub signer: Option<PublicKey>,
    /// Some key is unanchored (R2): the node probes and signs nothing with it.
    pub unanchored: bool,
    /// The node is not a signing member at its height (not a member, or its key abstains, is
    /// unanchored or conflicts): for liveness it counts as faulty there (§1, §8.1).
    pub abstaining: bool,
    /// Halt reason, if halted.
    pub halted: Option<HaltReason>,
    /// Memory footprint.
    pub footprint: Footprint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_defaults_by_size() {
        let small = LocalParams::for_committee_size(4);
        assert_eq!(small, LocalParams::default());
        assert_eq!(
            (small.t_base, small.rebroadcast_interval, small.fetch_retry),
            (2_000, 500, 250)
        );
        let large = LocalParams::for_committee_size(22);
        assert_eq!(
            (large.t_base, large.rebroadcast_interval, large.fetch_retry),
            (3_000, 1_000, 500)
        );
        assert_eq!(large.t_max, 30_000);
        assert_eq!(LocalParams::for_committee_size(9), small);
        assert_eq!(LocalParams::for_committee_size(10), large);
    }

    #[test]
    fn footprint_bounds() {
        let local = LocalParams::default();
        let bound = Footprint::bound(4, &local, 128);
        assert_eq!(bound.votes, 24);
        assert_eq!(bound.timeouts, 4);
        assert_eq!(bound.cert_cache, 16);
        assert_eq!(bound.peers, 68);
        assert_eq!(bound.recent_headers, 130);
        assert_eq!(bound.sync_entries, 128);
        assert_eq!(bound.evidence_keys, 39);
        assert_eq!(bound.probe, 4);
        assert!(Footprint::default().within(&bound));
        assert!(bound.within(&bound));
        let over = Footprint {
            votes: 25,
            ..Footprint::default()
        };
        assert!(!over.within(&bound));
        for field in 0..14 {
            let mut f = Footprint::default();
            let slot = match field {
                0 => &mut f.votes,
                1 => &mut f.timeouts,
                2 => &mut f.blocks,
                3 => &mut f.exec_entries,
                4 => &mut f.wants,
                5 => &mut f.pending_apply,
                6 => &mut f.sync_entries,
                7 => &mut f.sync_bytes,
                8 => &mut f.peers,
                9 => &mut f.recent_headers,
                10 => &mut f.configs,
                11 => &mut f.cert_cache,
                12 => &mut f.evidence_keys,
                _ => &mut f.probe,
            };
            *slot = usize::MAX;
            assert!(!f.within(&bound), "field {field}");
        }
    }

    #[test]
    fn errors_display() {
        assert_eq!(ConfigError::SyncBatchZero.to_string(), "SyncBatchZero");
    }
}
