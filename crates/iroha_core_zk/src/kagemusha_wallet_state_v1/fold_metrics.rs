//! Observation-only fold telemetry: phase durations per sub-proof, cancellations by cause and
//! the process peak resident set size a host reads at the end of each sub-proof.
//!
//! A fold turn times its fixed phases on its calling thread, which runs its locked prepare,
//! its proof without the wallet owner and its locked publication; native proving runs
//! synchronously there and its kernel threads report nothing. Every turn that selected a
//! sub-proof yields one [`FoldSubProofV1`] for the scheduler's [`FoldObserverV1`]. A turn that
//! ends before its proof finished reports before the background slot is released, so a
//! joining payment returns only after its own cancellation was reported; a proved turn
//! reports after its publication. Idle and caught-up wakes report nothing. Values are public
//! names, durations and counts only. Verification deltas include calls answered by the
//! parameter owner's successful-verification and folded-generator memos.
//! `engineMicros` reports nested key-original revalidation, key reconstruction, physical
//! witness synthesis, engine proving, new-proof acceptance and commit durations. It must
//! not be added to enclosing phase or call durations. `commit` includes validation and
//! durable Advance, not only storage writes. `nativeWork` is a separate bounded ring of
//! execute/reviewed-execute/speculative-Send calls; `returned` is only Rust `Result::is_ok`,
//! never a monetary completion or a custody verdict. Speculative publication is volatile.
//! Cumulative `counts.subProofs` and `nativeWorkCount` let hosts deduplicate each ring within
//! one open owner and detect overwritten observations without changing poll cadence.
//! `startedNativeMicros`, `endedNativeMicros` and snapshot `sampledNativeMicros` share one
//! process-local monotonic origin. They are never wall time, survive owner reopening but
//! reset on process restart. Hosts may bracket an observation with their monotonic clock
//! to bound a local clock offset; an end mark is not the later poll or UI observation.
//! They are kept in memory, never persisted, signed or matched against a profile, and no
//! admission, scheduling, error, retry or cancellation decision reads them.

use std::{
    cell::Cell,
    collections::VecDeque,
    fmt::Write as _,
    sync::OnceLock,
    time::{Duration, Instant},
};

use iroha_data_model::kagemusha::KagemushaWalletOperationKindV1;

pub(in crate::kagemusha_wallet_state_v1) mod admission;
mod bridge;
pub use admission::{
    NATIVE_ADMISSION_RECORDS_V1, NativeAdmissionPhaseV1, NativeAdmissionResultV1,
    NativeAdmissionV1, NativeAdmissionsV1,
};
pub use bridge::{NativeBridgeMetricsV1, NativeBridgePhaseV1, NativeBridgeTimerV1};

use super::{Error, FoldStatus};
use crate::kagemusha_wallet_proofs_v1::KagemushaWalletVerificationCountsV1;

/// Schema of [`FoldMetricsV1::to_json`].
pub const FOLD_METRICS_SCHEMA_V1: &str = "iroha.kagemusha.fold-metrics.v2";

/// Most recent sub-proof records one [`FoldMetricsV1`] keeps.
pub const FOLD_METRICS_RECORDS_V1: usize = 64;

/// Maximum UTF-8 bytes in the bounded diagnostic JSON returned to mobile hosts.
pub const FOLD_METRICS_MAX_BYTES_V1: usize = 131_072;

/// Most recent Native execution/speculation observations retained by one open owner.
pub const NATIVE_WORK_RECORDS_V1: usize = 16;

/// Fixed public phases of one fold turn. The locked prepare runs everything up to
/// `key_import`; `restore` and `prove` run without the wallet owner; `publish` takes it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldPhaseV1 {
    /// Source manifest synchronization.
    SyncManifest,
    /// Predecessor Ω read and its full verification.
    ReadFold,
    /// Released step, fold seed, schedule, checkpoint chain and interrupted-publication reads.
    FoldSeed,
    /// Owner credentials, folded predecessor state and preparation replay.
    OwnerReplay,
    /// Native session preparation and restoration of every prior source, without the owner.
    Restore,
    /// Revalidation of the selected stage's proving originals, in the locked prepare.
    KeyImport,
    /// The proof with its self-verification and encoding, without the wallet owner.
    Prove,
    /// Adoption of interrupted output, or the wait for the wallet owner, the fold-field
    /// re-check, the full Ω verification and durable publication.
    Publish,
}

impl FoldPhaseV1 {
    /// Number of phases.
    pub const COUNT: usize = 8;
    /// Every phase, in this fixed order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::SyncManifest,
        Self::ReadFold,
        Self::FoldSeed,
        Self::OwnerReplay,
        Self::Restore,
        Self::KeyImport,
        Self::Prove,
        Self::Publish,
    ];

    /// Fixed public identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SyncManifest => "sync_manifest",
            Self::ReadFold => "read_fold",
            Self::FoldSeed => "fold_seed",
            Self::OwnerReplay => "owner_replay",
            Self::Restore => "restore",
            Self::KeyImport => "key_import",
            Self::Prove => "prove",
            Self::Publish => "publish",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Kind of proof a sub-proof produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldStageV1 {
    /// A source Q proof.
    Q,
    /// An accumulation A proof.
    A,
    /// A wrapper W proof.
    W,
    /// The final Ω.
    Omega,
}

impl FoldStageV1 {
    /// Fixed public identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Q => "q",
            Self::A => "a",
            Self::W => "w",
            Self::Omega => "omega",
        }
    }
}

/// Host call class that took payment priority. It labels telemetry and changes no scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldCallClassV1 {
    /// Operations, reviews, deliveries, custody deletion and every other priority call.
    Payment,
    /// A setup input that ingests activation, Load, Unload, ledger or epoch evidence.
    SetupIngest,
    /// A pure status or original read.
    StatusRead,
}

impl FoldCallClassV1 {
    pub(super) const fn cause(self) -> FoldCancelCauseV1 {
        match self {
            Self::Payment => FoldCancelCauseV1::Payment,
            Self::SetupIngest => FoldCancelCauseV1::SetupIngest,
            Self::StatusRead => FoldCancelCauseV1::StatusRead,
        }
    }
}

/// The first scheduler signal that cancelled a running sub-proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldCancelCauseV1 {
    /// Payment priority of a [`FoldCallClassV1::Payment`] call.
    Payment,
    /// Payment priority of a [`FoldCallClassV1::SetupIngest`] call.
    SetupIngest,
    /// Payment priority of a [`FoldCallClassV1::StatusRead`] call.
    StatusRead,
    /// The app left both foreground and charging.
    Activity,
    /// The owner is closing.
    Close,
}

impl FoldCancelCauseV1 {
    /// Fixed public identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::SetupIngest => "setup_ingest",
            Self::StatusRead => "status_read",
            Self::Activity => "activity",
            Self::Close => "close",
        }
    }
}

/// How one selected sub-proof turn ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldOutcomeV1 {
    /// A new checkpoint became durable.
    Checkpoint,
    /// A new verified Ω became durable.
    Folded,
    /// Exact bytes of an interrupted publication were adopted, never proved again.
    Adopted,
    /// This scheduler's signal cancelled the turn; its work was discarded.
    Cancelled(FoldCancelCauseV1),
    /// The fold fields or custody changed while the sub-proof was outside the wallet owner,
    /// so its proof was discarded and never published.
    Discarded,
    /// Any other error, including a cancellation without this scheduler's signal.
    Failed,
}

impl FoldOutcomeV1 {
    /// Fixed public identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::Folded => "folded",
            Self::Adopted => "adopted",
            Self::Cancelled(_) => "cancelled",
            Self::Discarded => "discarded",
            Self::Failed => "failed",
        }
    }

    /// The cancelling signal, for a cancelled turn only.
    #[must_use]
    pub const fn cause(self) -> Option<FoldCancelCauseV1> {
        match self {
            Self::Cancelled(cause) => Some(cause),
            _ => None,
        }
    }
}

/// One selected sub-proof turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoldSubProofV1 {
    /// Start relative to the process-local monotonic origin, in whole microseconds.
    pub started_native_micros: u64,
    /// End relative to the same origin, before the observer receives this record.
    pub ended_native_micros: u64,
    /// Head sequence being folded.
    pub sequence: u128,
    /// Operation of that head, once its released step was read.
    pub operation: Option<KagemushaWalletOperationKindV1>,
    /// Kind of proof the turn produced or started; `None` when no native proof started.
    pub stage: Option<FoldStageV1>,
    /// Zero-based sub-proof ordinal.
    pub ordinal: u32,
    /// How the turn ended.
    pub outcome: FoldOutcomeV1,
    /// Monotonic time per phase, in [`FoldPhaseV1::ALL`] order.
    pub phases: [Duration; FoldPhaseV1::COUNT],
    /// Verification work on the calling thread during this turn, including memo hits.
    /// Kernel threads report no counts; these confer no verification authority.
    pub verification: KagemushaWalletVerificationCountsV1,
    /// Nested engine/host phase durations on the same thread. Do not add these to `phases`.
    pub work: iroha_plonk::work_metrics::WorkMetrics,
    /// Process lifetime peak resident set size, read by the host at the end of the turn.
    pub peak_rss_bytes: Option<u64>,
    /// Ingest and status calls that ran while this sub-proof held the background slot,
    /// none of which cancelled it.
    pub ingests: u32,
}

impl FoldSubProofV1 {
    /// Monotonic time spent in `phase`.
    #[must_use]
    pub const fn phase(&self, phase: FoldPhaseV1) -> Duration {
        self.phases[phase.index()]
    }
}

/// Receives every finished sub-proof of one scheduler (observation only).
pub trait FoldObserverV1: Send + Sync {
    /// Called on the folding thread: before the background slot is released for a turn that
    /// ended before its proof finished, after the publication otherwise. It must not block,
    /// and must not call the scheduler or the wallet.
    fn sub_proof(&self, record: FoldSubProofV1);
}

/// The fixed Native entry boundaries measured independently of fold turns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeWorkKindV1 {
    /// Native Request construction and its existing source/fee verification.
    Request,
    /// Native wallet Bootstrap.
    Bootstrap,
    /// Native Credited intake/query and any required ArchiveSent transition.
    Credited,
    /// An ordinary Native execution, including its existing validation and publication.
    Execute,
    /// Execution after consuming a hardware-confirmed Native review.
    ReviewedExecute,
    /// Preparation and proving of one speculative Send; its publication is volatile only.
    SpeculativeSend,
    /// A selected fold turn through its bridge return and final durability fence.
    Fold,
}
impl NativeWorkKindV1 {
    /// Fixed public identifier; it never contains a request or wallet identity.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Bootstrap => "bootstrap",
            Self::Credited => "credited",
            Self::Execute => "execute",
            Self::ReviewedExecute => "reviewed_execute",
            Self::SpeculativeSend => "speculative_send",
            Self::Fold => "fold",
        }
    }
}

/// One observation of an execution or speculative-proof call, never a completion verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWorkRecordV1 {
    /// Start relative to the process-local monotonic origin, in whole microseconds.
    pub started_native_micros: u64,
    /// End relative to the same origin, after the original call returned.
    pub ended_native_micros: u64,
    /// The observed entry boundary.
    pub kind: NativeWorkKindV1,
    /// Whether the Native call returned `Ok`; even `true` grants no monetary completion.
    pub returned: bool,
    /// Wall duration of the whole call, including scheduling/custody waits where present.
    pub elapsed: Duration,
    /// Exact owner-local core fold record captured on this thread; only for `Fold`.
    pub fold_record_id: Option<u64>,
    /// Nested existing bridge waits/admission, never added to elapsed time.
    pub bridge: NativeBridgeMetricsV1,
    /// Existing capacity checks made on the calling thread during this interval.
    pub admissions: NativeAdmissionsV1,
    /// Verification work done on the calling thread.
    pub verification: KagemushaWalletVerificationCountsV1,
    /// Nested measured phases; do not add them to `elapsed` or to one another.
    pub work: iroha_plonk::work_metrics::WorkMetrics,
}

/// Observation-only scope for a Native entry call; keep and finish it on the same thread.
pub struct NativeWorkTurnV1 {
    kind: NativeWorkKindV1,
    started: Instant,
    started_native_micros: u64,
    bridge: NativeBridgeMetricsV1,
    admission_count: u64,
    verification: KagemushaWalletVerificationCountsV1,
    work: iroha_plonk::work_metrics::WorkMetrics,
    // A non-Copy, non-Send marker keeps the scope single-use on its originating thread.
    _thread: Cell<std::marker::PhantomData<std::rc::Rc<()>>>,
}
impl NativeWorkTurnV1 {
    /// Observe a known entry boundary without changing its scheduling or result.
    pub fn start(kind: NativeWorkKindV1) -> Self {
        let (started, started_native_micros) = native_mark();
        Self {
            kind,
            started,
            started_native_micros,
            bridge: NativeBridgeMetricsV1::current(),
            admission_count: admission::count(),
            verification: KagemushaWalletVerificationCountsV1::current_thread(),
            work: iroha_plonk::work_metrics::WorkMetrics::current_thread(),
            _thread: Cell::new(std::marker::PhantomData),
        }
    }
    /// Close the scope after the original call returned, preserving its result separately.
    pub fn finish(self, returned: bool) -> NativeWorkRecordV1 {
        let (ended, ended_native_micros) = native_mark();
        NativeWorkRecordV1 {
            started_native_micros: self.started_native_micros,
            ended_native_micros,
            kind: self.kind,
            returned,
            elapsed: ended.saturating_duration_since(self.started),
            fold_record_id: None,
            bridge: NativeBridgeMetricsV1::current().since(self.bridge),
            admissions: admission::since(self.admission_count),
            verification: KagemushaWalletVerificationCountsV1::current_thread()
                .since(self.verification),
            work: iroha_plonk::work_metrics::WorkMetrics::current_thread().since(self.work),
        }
    }
}

/// Cumulative counts since the log was created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoldCountsV1 {
    /// Every recorded sub-proof turn.
    pub sub_proofs: u64,
    /// New checkpoints.
    pub checkpoints: u64,
    /// New verified Ω.
    pub folded: u64,
    /// Adopted interrupted publications.
    pub adopted: u64,
    /// Turns that ended with any other error.
    pub failed: u64,
    /// Proofs discarded because the fold fields or custody changed before their publication.
    pub discarded: u64,
    /// Cancellations by [`FoldCancelCauseV1::Payment`].
    pub cancelled_by_payment: u64,
    /// Cancellations by [`FoldCancelCauseV1::SetupIngest`].
    pub cancelled_by_setup_ingest: u64,
    /// Cancellations by [`FoldCancelCauseV1::StatusRead`].
    pub cancelled_by_status_read: u64,
    /// Cancellations by [`FoldCancelCauseV1::Activity`].
    pub cancelled_by_activity: u64,
    /// Cancellations by [`FoldCancelCauseV1::Close`].
    pub cancelled_by_close: u64,
    /// Prove-phase time of cancelled and discarded turns, whose work was thrown away.
    pub discarded_prove: Duration,
    /// Ingest and status calls that overlapped a sub-proof without cancelling it.
    pub overlapped_ingests: u64,
}

/// The last [`FOLD_METRICS_RECORDS_V1`] sub-proof records and cumulative counts of one owner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FoldMetricsV1 {
    records: VecDeque<FoldSubProofV1>,
    native_work: VecDeque<NativeWorkRecordV1>,
    native_work_count: u64,
    counts: FoldCountsV1,
    process_peak_rss_bytes: Option<u64>,
}

impl FoldMetricsV1 {
    /// Attach the host's process-lifetime peak RSS observation; this is not Native allocation.
    pub fn set_process_peak_rss_bytes(&mut self, bytes: Option<u64>) {
        self.process_peak_rss_bytes = bytes;
    }
    /// Keep one Native call observation without changing fold counts or scheduling.
    pub fn record_native_work(&mut self, record: NativeWorkRecordV1) {
        self.native_work_count = self.native_work_count.saturating_add(1);
        retain_observation(&mut self.native_work, record, NATIVE_WORK_RECORDS_V1);
    }

    /// Total observed Native calls, including those no longer retained. Observation only.
    pub const fn native_work_count(&self) -> u64 {
        self.native_work_count
    }

    /// Recent Native call observations, oldest first; never operation readiness.
    pub const fn native_work(&self) -> &VecDeque<NativeWorkRecordV1> {
        &self.native_work
    }

    /// Count `record` and keep it, dropping the oldest record beyond the bound.
    pub fn record(&mut self, record: FoldSubProofV1) {
        let counts = &mut self.counts;
        counts.sub_proofs = counts.sub_proofs.saturating_add(1);
        counts.overlapped_ingests = counts
            .overlapped_ingests
            .saturating_add(u64::from(record.ingests));
        let count = match record.outcome {
            FoldOutcomeV1::Checkpoint => &mut counts.checkpoints,
            FoldOutcomeV1::Folded => &mut counts.folded,
            FoldOutcomeV1::Adopted => &mut counts.adopted,
            FoldOutcomeV1::Failed => &mut counts.failed,
            FoldOutcomeV1::Discarded => {
                counts.discarded_prove = counts
                    .discarded_prove
                    .saturating_add(record.phase(FoldPhaseV1::Prove));
                &mut counts.discarded
            }
            FoldOutcomeV1::Cancelled(cause) => {
                counts.discarded_prove = counts
                    .discarded_prove
                    .saturating_add(record.phase(FoldPhaseV1::Prove));
                match cause {
                    FoldCancelCauseV1::Payment => &mut counts.cancelled_by_payment,
                    FoldCancelCauseV1::SetupIngest => &mut counts.cancelled_by_setup_ingest,
                    FoldCancelCauseV1::StatusRead => &mut counts.cancelled_by_status_read,
                    FoldCancelCauseV1::Activity => &mut counts.cancelled_by_activity,
                    FoldCancelCauseV1::Close => &mut counts.cancelled_by_close,
                }
            }
        };
        *count = count.saturating_add(1);
        retain_observation(&mut self.records, record, FOLD_METRICS_RECORDS_V1);
    }

    /// Kept records, oldest first.
    #[must_use]
    pub const fn records(&self) -> &VecDeque<FoldSubProofV1> {
        &self.records
    }

    /// Cumulative counts, including records no longer kept.
    #[must_use]
    pub const fn counts(&self) -> FoldCountsV1 {
        self.counts
    }

    /// One-line log record: fixed names, whole microseconds, counts and bytes only.
    #[must_use]
    pub fn to_json(&self) -> String {
        let counts = self.counts;
        let (_, sampled_native_micros) = native_mark();
        let mut output = format!(
            "{{\"schema\":\"{FOLD_METRICS_SCHEMA_V1}\",\"sampledNativeMicros\":{sampled_native_micros},\"counts\":{{"
        );
        for (index, (field, value)) in [
            ("subProofs", counts.sub_proofs),
            ("checkpoints", counts.checkpoints),
            ("folded", counts.folded),
            ("adopted", counts.adopted),
            ("failed", counts.failed),
            ("discarded", counts.discarded),
            ("cancelledByPayment", counts.cancelled_by_payment),
            ("cancelledBySetupIngest", counts.cancelled_by_setup_ingest),
            ("cancelledByStatusRead", counts.cancelled_by_status_read),
            ("cancelledByActivity", counts.cancelled_by_activity),
            ("cancelledByClose", counts.cancelled_by_close),
            ("discardedProveMicros", micros(counts.discarded_prove)),
            ("overlappedIngests", counts.overlapped_ingests),
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(output, "\"{field}\":{value}");
        }
        output.push_str("},\"processScratch\":{");
        let scratch = iroha_pasta::msm::SharedMemoryBudget::process_default();
        let in_use = scratch.in_use_bytes();
        // Acquire charges used before updating peak. Both are actual observed reservations;
        // this nontransactional maximum is a lower bound on the true lifetime peak.
        let peak = scratch.peak_bytes().max(in_use);
        let _ = write!(
            output,
            "\"limitBytes\":{},\"inUseBytes\":{},\"peakBytes\":{}}}",
            scratch.limit_bytes(),
            in_use,
            peak
        );
        output.push_str(",\"processPeakRssBytes\":");
        push_optional_u64(&mut output, self.process_peak_rss_bytes);
        output.push_str(",\"records\":[");
        for (index, record) in self.records.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(
                output,
                "{{\"startedNativeMicros\":{},\"endedNativeMicros\":{},\"sequence\":{},\"operation\":",
                record.started_native_micros, record.ended_native_micros, record.sequence
            );
            push_name(&mut output, record.operation.map(operation_name));
            output.push_str(",\"stage\":");
            push_name(&mut output, record.stage.map(FoldStageV1::name));
            let _ = write!(
                output,
                ",\"ordinal\":{},\"outcome\":\"{}\",\"cause\":",
                record.ordinal,
                record.outcome.name()
            );
            push_name(
                &mut output,
                record.outcome.cause().map(FoldCancelCauseV1::name),
            );
            let _ = write!(output, ",\"ingests\":{}", record.ingests);
            output.push_str(",\"peakRssBytes\":");
            match record.peak_rss_bytes {
                Some(bytes) => {
                    let _ = write!(output, "{bytes}");
                }
                None => output.push_str("null"),
            }
            push_verification(&mut output, record.verification);
            push_work(&mut output, record.work);
            output.push_str(",\"micros\":{");
            for (position, phase) in FoldPhaseV1::ALL.into_iter().enumerate() {
                if position != 0 {
                    output.push(',');
                }
                let _ = write!(
                    output,
                    "\"{}\":{}",
                    phase.name(),
                    micros(record.phase(phase))
                );
            }
            output.push_str("}}");
        }
        let _ = write!(
            output,
            "],\"nativeWorkCount\":{},\"nativeWork\":[",
            self.native_work_count
        );
        for (index, record) in self.native_work.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(
                output,
                "{{\"startedNativeMicros\":{},\"endedNativeMicros\":{},\"kind\":\"{}\",\"returned\":{},\"micros\":{}",
                record.started_native_micros,
                record.ended_native_micros,
                record.kind.name(),
                record.returned,
                micros(record.elapsed)
            );
            output.push_str(",\"foldRecordId\":");
            push_optional_u64(&mut output, record.fold_record_id);
            push_bridge(&mut output, record.bridge);
            push_admissions(&mut output, record.admissions);
            push_verification(&mut output, record.verification);
            push_work(&mut output, record.work);
            output.push('}');
        }
        output.push_str("]}");
        output
    }
}

// Allocate the bounded ring fallibly before appending. Failure loses only observation.
// Clearing on refusal keeps retained rows a contiguous suffix of the cumulative count.
fn retain_observation<T>(records: &mut VecDeque<T>, record: T, limit: usize) {
    retain_observation_with(records, record, limit, |records, additional| {
        records.try_reserve_exact(additional).map_err(|_| ())
    });
}
fn retain_observation_with<T>(
    records: &mut VecDeque<T>,
    record: T,
    limit: usize,
    reserve: impl FnOnce(&mut VecDeque<T>, usize) -> Result<(), ()>,
) {
    if records.capacity() < limit && reserve(records, limit - records.len()).is_err() {
        records.clear();
        return;
    }
    if records.len() == limit {
        records.pop_front();
    }
    records.push_back(record);
}

fn push_optional_u64(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => {
            let _ = write!(output, "{value}");
        }
        None => output.push_str("null"),
    }
}
fn push_bridge(output: &mut String, value: NativeBridgeMetricsV1) {
    let _ = write!(
        output,
        ",\"bridgeMicros\":{{\"scheduler_wait\":{},\"wallet_lock_wait\":{},\"custody_admission\":{}}}",
        micros(value.scheduler_wait),
        micros(value.wallet_lock_wait),
        micros(value.custody_admission)
    );
}
fn push_admissions(output: &mut String, value: NativeAdmissionsV1) {
    let _ = write!(
        output,
        ",\"admissionCount\":{},\"admissions\":[",
        value.count
    );
    for (index, record) in value.records.iter().flatten().enumerate() {
        if index != 0 {
            output.push(',');
        }
        let _ = write!(
            output,
            "{{\"phase\":\"{}\",\"requiredStorageBytes\":{},\"requiredMemoryBytes\":{},\"availableStorageBytes\":",
            record.phase.name(),
            record.required.storage_bytes,
            record.required.memory_bytes
        );
        push_optional_u64(
            output,
            record.available.map(|resources| resources.storage_bytes),
        );
        output.push_str(",\"availableMemoryBytes\":");
        push_optional_u64(
            output,
            record
                .available
                .and_then(|resources| resources.memory_bytes),
        );
        let _ = write!(output, ",\"result\":\"{}\"}}", record.result.name());
    }
    output.push(']');
}

fn push_verification(output: &mut String, work: KagemushaWalletVerificationCountsV1) {
    output.push_str(",\"verification\":{");
    for (index, (field, value)) in [
        ("lineage", work.verify_lineage),
        ("full", work.proofs.verify_full),
        ("decides", work.proofs.decides),
        ("batches", work.proofs.batches),
        ("generatorMsms", work.proofs.generator_msms),
        ("generatorMsmBases", work.proofs.generator_msm_bases),
        ("reusedVerifications", work.proofs.reused_verifications),
        ("reusedGenerators", work.proofs.reused_generators),
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            output.push(',');
        }
        let _ = write!(output, "\"{field}\":{value}");
    }
    output.push('}');
}
fn push_work(output: &mut String, work: iroha_plonk::work_metrics::WorkMetrics) {
    output.push_str(",\"engineMicros\":{");
    for (index, (field, value)) in [
        ("key_import", work.key_import),
        ("key_rebuild", work.key_rebuild),
        ("witness", work.witness),
        ("prove", work.prove),
        ("self_verify", work.self_verify),
        ("commit", work.commit),
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            output.push(',');
        }
        let _ = write!(output, "\"{field}\":{}", micros(value));
    }
    output.push('}');
}

// Initialized before sampling `now`, so the first mark cannot precede its origin.
// This clock is observation-only and is independent of wallet/ledger time.
fn native_mark() -> (Instant, u64) {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    let now = Instant::now();
    (now, micros(now.saturating_duration_since(origin)))
}

fn micros(value: Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}

fn push_name(output: &mut String, name: Option<&'static str>) {
    match name {
        Some(name) => {
            let _ = write!(output, "\"{name}\"");
        }
        None => output.push_str("null"),
    }
}

const fn operation_name(kind: KagemushaWalletOperationKindV1) -> &'static str {
    match kind {
        KagemushaWalletOperationKindV1::Bootstrap => "bootstrap",
        KagemushaWalletOperationKindV1::Load => "load",
        KagemushaWalletOperationKindV1::Send => "send",
        KagemushaWalletOperationKindV1::Receive => "receive",
        KagemushaWalletOperationKindV1::ArchiveSent => "archive_sent",
        KagemushaWalletOperationKindV1::Unload => "unload",
        KagemushaWalletOperationKindV1::RefreshPolicy => "refresh_policy",
        KagemushaWalletOperationKindV1::Retiring => "retiring",
    }
}

/// The open turn of this thread.
#[derive(Clone, Copy)]
struct Active {
    started_native_micros: u64,
    phase: FoldPhaseV1,
    since: Instant,
    elapsed: [Duration; FoldPhaseV1::COUNT],
    verification: KagemushaWalletVerificationCountsV1,
    work: iroha_plonk::work_metrics::WorkMetrics,
    stage: Option<FoldStageV1>,
}

thread_local! {
    static ACTIVE: Cell<Option<Active>> = const { Cell::new(None) };
}

fn update(change: impl FnOnce(&mut Active)) {
    // Thread-local teardown loses only observation, never a verdict.
    let _ = ACTIVE.try_with(|cell| {
        if let Some(mut active) = cell.get() {
            change(&mut active);
            cell.set(Some(active));
        }
    });
}

/// Close the current phase of this thread's fold turn and start `phase`. No effect outside
/// a turn.
pub(super) fn enter(phase: FoldPhaseV1) {
    update(|active| {
        let now = Instant::now();
        let spent = &mut active.elapsed[active.phase.index()];
        *spent = spent.saturating_add(now.saturating_duration_since(active.since));
        active.phase = phase;
        active.since = now;
    });
}

/// The kind of proof this thread's fold turn is producing. No effect outside a turn.
pub(super) fn stage(stage: FoldStageV1) {
    update(|active| active.stage = Some(stage));
}

/// One fold turn on the calling thread, open from [`Self::start`] until it is finished or
/// dropped. Only a turn that selected a sub-proof yields a record.
pub(super) struct FoldTurnV1 {
    sequence: Option<u128>,
    ordinal: u32,
    operation: Option<KagemushaWalletOperationKindV1>,
    adopted: bool,
    discarded: bool,
}

impl FoldTurnV1 {
    /// Open a turn on this thread in [`FoldPhaseV1::SyncManifest`].
    pub(super) fn start() -> Self {
        let (now, started_native_micros) = native_mark();
        let _ = ACTIVE.try_with(|cell| {
            cell.set(Some(Active {
                started_native_micros,
                phase: FoldPhaseV1::SyncManifest,
                since: now,
                elapsed: [Duration::ZERO; FoldPhaseV1::COUNT],
                verification: KagemushaWalletVerificationCountsV1::current_thread(),
                work: iroha_plonk::work_metrics::WorkMetrics::current_thread(),
                stage: None,
            }));
        });
        Self {
            sequence: None,
            ordinal: 0,
            operation: None,
            adopted: false,
            discarded: false,
        }
    }

    /// The turn works on sub-proof `ordinal` of head `sequence`.
    pub(super) fn select(&mut self, sequence: u128, ordinal: u32) {
        self.sequence = Some(sequence);
        self.ordinal = ordinal;
    }

    /// The operation of the selected head.
    pub(super) fn operation(&mut self, kind: KagemushaWalletOperationKindV1) {
        self.operation = Some(kind);
    }

    /// The turn adopts the exact bytes of an interrupted publication.
    pub(super) fn adopting(&mut self) {
        self.adopted = true;
    }

    /// The turn discards its proof: the fold fields or custody changed before its publication.
    pub(super) fn discarding(&mut self) {
        self.discarded = true;
    }

    /// Close the turn. `cause` is the scheduler signal that cancelled it, if any; only that
    /// signal makes a `Cancelled` error a cancellation.
    pub(super) fn finish(
        self,
        result: Result<FoldStatus, &Error>,
        cause: Option<FoldCancelCauseV1>,
    ) -> Option<FoldSubProofV1> {
        let (now, ended_native_micros) = native_mark();
        let active = ACTIVE.try_with(Cell::take).ok().flatten();
        let sequence = self.sequence?;
        let outcome = match result {
            Ok(FoldStatus::Idle | FoldStatus::CaughtUp) => return None,
            Ok(FoldStatus::Checkpoint { .. } | FoldStatus::Folded(_)) if self.adopted => {
                FoldOutcomeV1::Adopted
            }
            Ok(FoldStatus::Checkpoint { .. }) => FoldOutcomeV1::Checkpoint,
            Ok(FoldStatus::Folded(_)) => FoldOutcomeV1::Folded,
            Err(Error::Cancelled) if self.discarded => FoldOutcomeV1::Discarded,
            Err(Error::Cancelled) => cause.map_or(FoldOutcomeV1::Failed, FoldOutcomeV1::Cancelled),
            Err(_) => FoldOutcomeV1::Failed,
        };
        let mut started_native_micros = ended_native_micros;
        let mut phases = [Duration::ZERO; FoldPhaseV1::COUNT];
        let mut stage = None;
        let mut verification = KagemushaWalletVerificationCountsV1::default();
        let mut work = iroha_plonk::work_metrics::WorkMetrics::default();
        if let Some(active) = active {
            started_native_micros = active.started_native_micros;
            phases = active.elapsed;
            let spent = &mut phases[active.phase.index()];
            *spent = spent.saturating_add(now.saturating_duration_since(active.since));
            stage = active.stage;
            verification =
                KagemushaWalletVerificationCountsV1::current_thread().since(active.verification);
            work = iroha_plonk::work_metrics::WorkMetrics::current_thread().since(active.work);
        }
        Some(FoldSubProofV1 {
            started_native_micros,
            ended_native_micros,
            sequence,
            operation: self.operation,
            stage,
            ordinal: self.ordinal,
            outcome,
            phases,
            verification,
            work,
            peak_rss_bytes: None,
            ingests: 0,
        })
    }
}

impl Drop for FoldTurnV1 {
    fn drop(&mut self) {
        // A finished turn already took its state; an unwinding one must not leave it open.
        let _ = ACTIVE.try_with(|cell| cell.set(None));
    }
}

#[cfg(test)]
#[path = "fold_metrics/tests.rs"]
mod tests;
