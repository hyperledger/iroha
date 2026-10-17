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
//! names, durations and counts only.
//! They are kept in memory, never persisted, signed or matched against a profile, and no
//! admission, scheduling, error, retry or cancellation decision reads them.

use std::{
    cell::Cell,
    collections::VecDeque,
    fmt::Write as _,
    time::{Duration, Instant},
};

use iroha_data_model::kagemusha::KagemushaWalletOperationKindV1;

use super::{Error, FoldStatus};

/// Schema of [`FoldMetricsV1::to_json`].
pub const FOLD_METRICS_SCHEMA_V1: &str = "iroha.kagemusha.fold-metrics.v1";

/// Most recent sub-proof records one [`FoldMetricsV1`] keeps.
pub const FOLD_METRICS_RECORDS_V1: usize = 64;

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
    /// The fold fields changed while the sub-proof proved without the wallet owner, so its
    /// proof was discarded and never published.
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
    /// Proofs discarded because the fold fields changed before their publication.
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
    counts: FoldCountsV1,
}

impl FoldMetricsV1 {
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
        if self.records.len() == FOLD_METRICS_RECORDS_V1 {
            self.records.pop_front();
        }
        self.records.push_back(record);
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
        let mut output = format!("{{\"schema\":\"{FOLD_METRICS_SCHEMA_V1}\",\"counts\":{{");
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
        output.push_str("},\"records\":[");
        for (index, record) in self.records.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(output, "{{\"sequence\":{},\"operation\":", record.sequence);
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
        output.push_str("]}");
        output
    }
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
    phase: FoldPhaseV1,
    since: Instant,
    elapsed: [Duration; FoldPhaseV1::COUNT],
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
        let _ = ACTIVE.try_with(|cell| {
            cell.set(Some(Active {
                phase: FoldPhaseV1::SyncManifest,
                since: Instant::now(),
                elapsed: [Duration::ZERO; FoldPhaseV1::COUNT],
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

    /// The turn discards its proof: the fold fields changed before its publication.
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
        let now = Instant::now();
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
        let mut phases = [Duration::ZERO; FoldPhaseV1::COUNT];
        let mut stage = None;
        if let Some(active) = active {
            phases = active.elapsed;
            let spent = &mut phases[active.phase.index()];
            *spent = spent.saturating_add(now.saturating_duration_since(active.since));
            stage = active.stage;
        }
        Some(FoldSubProofV1 {
            sequence,
            operation: self.operation,
            stage,
            ordinal: self.ordinal,
            outcome,
            phases,
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
