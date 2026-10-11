//! Scheduling of execution, apply and payload building (`specs/sumeragi.md` §12.2, §12.3 O3,
//! O4) over one executor that runs one operation at a time:
//!
//! - every `Execute` is answered exactly once — `Valid`, `Invalid`, `Failed`, or `Cancelled`
//!   when a later `DiscardExecution` of its height left it out (a running job finishes first
//!   and is then answered `Cancelled`), or when its height was applied meanwhile;
//! - the most recent `Execute` runs first; one whose parent post-state the executor does not
//!   hold is *parked* (never `Failed`) until the parent is applied or executed;
//! - `CommitBlock`s apply strictly in height order in three steps — prepare (the cached
//!   post-state or a re-execution; an execution of the block in flight finishes first and is
//!   reused, an `Execute` of it still queued is answered from the apply), durable append to the
//!   block store, commit — and `BlockApplied` carries the applied header; a local commitment
//!   that differs from the certified one is reported as `ApplyDiverged` and apply stops; local
//!   retryable refusals retain the original owner and await its release when supplied;
//!   source-less failures back off, and consuming failures halt;
//! - once prepared, and while a failed step waits, a commit runs alone: no other executor
//!   call comes between its prepare and its commit (the executor may hold a single live
//!   overlay); a failed commit is retried after a fresh prepare, without a second append or
//!   resetting its failure backoff;
//! - `BuildPayload` for height `h` runs only after `h − 1` is applied (the builder filters the
//!   applied transactions), and `PayloadReady{req}` follows at most once an `EMPTY` answer;
//! - the queues other than the `Execute`s are bounded: discards of one height merge (keeping
//!   what both keep), and rejections are deduplicated and capped (the oldest go first: the
//!   quarantine is best effort).

use std::{
    collections::VecDeque,
    sync::Arc,
    task::{Context, Waker},
};

use iroha_allocation::{
    ChargedBuffer,
    release::{ReleaseRegistration, ReleaseWait},
};

use iroha_sumeragi::{
    api::{ApplicationControlContext, ControlWitnessContext, Event, ExecOutcome, HaltReason},
    availability::{AvailableBody, PayloadBytes},
    message::{ApplicationControl, Qc},
    types::{
        AppliedConfig, ControlWitness, Hash32, MAX_COMMITTEE_SIZE, MAX_PUBLIC_KEY_LEN, Millis,
        PublicKey,
    },
};

use super::{persist::Backoff, traits::PublicationError};

// Every execution queue retains its own preadmitted release custody. Shared wire
// ingress admission and nested execution-graph funding have separate owners.

/// Rejections kept while the executor is busy (the oldest are dropped beyond).
const MAX_REJECTS: usize = 64;

/// A committed block waiting to be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    /// The block.
    pub block: AvailableBody,
    /// Its `CommitQC` (carries the block hash and the certified result).
    pub qc: Qc,
}

/// Process-local identity of one owed inbound occurrence, never encoded on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlOccurrence(pub(super) u64);

/// An operation for the executor thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecOp {
    /// Execute a block on its parent's post-state.
    Execute {
        /// The block.
        block: Arc<AvailableBody>,
        /// Its hash.
        block_hash: Hash32,
        /// The core already holds a certificate for this block; application clock guards exempt it.
        certified: bool,
    },
    /// Drop the post-states at `height` other than `keep`.
    Discard {
        /// Height.
        height: u64,
        /// Kept blocks.
        keep: Vec<Hash32>,
    },
    /// Obtain the post-state of the next committed block.
    Prepare(Arc<Commit>),
    /// Durably append the next committed block to the block store.
    Append(Arc<Commit>),
    /// Make the prepared post-state the applied state.
    Commit(Arc<Commit>),
    /// Build the independent control witness for one exact fresh proposal.
    BuildControlWitness {
        /// Fresh core request id.
        req: u64,
        /// Exact view and parent source.
        context: ControlWitnessContext,
    },
    /// Drive one all-validator application producer for an applied parent.
    DriveApplicationControl(ApplicationControlContext),
    /// Reduce one bounded authenticated peer partial.
    ReceiveApplicationControl {
        /// Same internal occurrence retained through every retry.
        occurrence: ControlOccurrence,
        /// P2P authenticated sender.
        from: PublicKey,
        /// Exact context and bounded application bytes.
        message: ApplicationControl,
    },
    /// Build a payload.
    Build {
        /// Request id.
        req: u64,
        /// Height.
        height: u64,
        /// View.
        view: u64,
        /// Size limit.
        max_bytes: u32,
        /// Execution budget hint.
        exec_budget_ms: u32,
    },
    /// Quarantine the transactions of an `Invalid` block.
    Reject {
        /// Height.
        height: u64,
        /// View.
        view: u64,
        /// AvailableBody hash.
        block_hash: Hash32,
    },
}

/// The executor thread's answer to the operation in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecDone {
    /// `Execute`: the outcome, or `None` if the parent post-state is not held.
    Executed(Option<ExecOutcome>),
    /// `Discard` done.
    Discarded,
    /// `Prepare`: the local commitment (`None`: not `Valid`), or a local failure.
    Prepared(Result<Option<Hash32>, PublicationError>),
    /// `Append`: whether the block is durable in the block store.
    Appended {
        /// Whether the original block is durable.
        durable: bool,
        /// Exact local refusal when the historical authority read did not finish.
        deferred: Option<crate::execution_attempt::ExecutionDeferred>,
    },
    /// `Commit`: the original atomic epoch/configuration output, or a local failure.
    Committed(Result<Box<AppliedConfig>, PublicationError>),
    /// Independent exact control response; no empty fallback on local failure.
    ControlWitnessBuilt(Result<ControlWitness, PublicationError>),
    /// At most one source-bound own partial from the sole producer.
    ApplicationControlDriven(Result<Option<ApplicationControl>, PublicationError>),
    /// The application accepted/rejected one peer partial.
    ApplicationControlReceived {
        /// The original internal occurrence moved through the worker.
        occurrence: ControlOccurrence,
        /// The exact authenticated sender moved through the worker.
        from: PublicKey,
        /// The same original admitted partial, returned without reconstruction.
        message: ApplicationControl,
        /// The outcome of borrowing this exact original partial.
        result: Result<(), PublicationError>,
    },
    /// Exact admitted payload, genuine absence, or a retained local failure.
    Built(Result<Option<PayloadBytes>, PublicationError>),
    /// `Reject` done.
    Rejected,
}

#[derive(Clone, Debug)]
struct Job {
    req: u64,
    block_hash: Hash32,
    block: Arc<AvailableBody>,
    certified: bool,
    cancelled: bool,
}

impl Job {
    fn height(&self) -> u64 {
        self.block.header().height
    }
}

#[derive(Debug)]
enum Running {
    Execute(Job),
    Discard,
    Prepare,
    Append,
    Commit,
    Build(BuildRequest),
    BuildControl(ControlBuild),
    DriveControl(ApplicationControlContext),
    ReceiveControl { index: usize },
    Reject,
}

/// Where the head of the commit queue is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Fresh,
    Prepared,
    Appended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BuildRequest {
    req: u64,
    height: u64,
    view: u64,
    max_bytes: u32,
    exec_budget_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlBuild {
    req: u64,
    context: ControlWitnessContext,
    source: ApplicationControlContext,
}

/// Exact preadmitted waiter custody for every bounded execution queue.
#[derive(Debug)]
pub struct ExecutionRegistrations {
    committed: ReleaseRegistration,
    payload: ReleaseRegistration,
    witness: ReleaseRegistration,
    drive: ReleaseRegistration,
    inbound: InboundSlots,
}

impl ExecutionRegistrations {
    /// Total physical control bytes required before any Core work is started.
    pub fn admission_bytes() -> usize {
        Self::inbound_layout().size()
            + ReleaseRegistration::allocation_layout().size() * (4 + MAX_COMMITTEE_SIZE)
    }

    fn inbound_layout() -> std::alloc::Layout {
        std::alloc::Layout::array::<InboundSlot>(MAX_COMMITTEE_SIZE)
            .expect("the fixed protocol peer bound has a representable layout")
    }

    /// Admit every control and the fixed peer-slot backing from the same instance authority.
    ///
    /// # Errors
    /// Returns the exact pool or physical-allocation refusal. Every partial
    /// construction refunds its original controls before returning an error.
    pub fn admit(
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, super::KernelStartError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_bytes())?;
        let mut slots = ChargedBuffer::from_reservation(MAX_COMMITTEE_SIZE, &mut reservation)?;
        // Initialize one owned slot at a time in its final prepaid backing, with
        // no large temporary array, extra Vec, or allocation after Core starts.
        for _ in 0..MAX_COMMITTEE_SIZE {
            slots.push_reserved(InboundSlot {
                input: None,
                in_flight: None,
                retry: RetryGate::new(ReleaseRegistration::from_reservation(&mut reservation)?),
            });
        }
        Ok(Self {
            committed: ReleaseRegistration::from_reservation(&mut reservation)?,
            payload: ReleaseRegistration::from_reservation(&mut reservation)?,
            witness: ReleaseRegistration::from_reservation(&mut reservation)?,
            drive: ReleaseRegistration::from_reservation(&mut reservation)?,
            inbound: InboundSlots { slots },
        })
    }
}

/// Refusal belongs to one immutable request until success, replacement or cancellation.
#[derive(Debug)]
struct RetryGate {
    registration: ReleaseRegistration,
    error: Option<PublicationError>,
    retry_at: Millis,
    failures: u32,
}
impl RetryGate {
    fn new(registration: ReleaseRegistration) -> Self {
        Self {
            registration,
            error: None,
            retry_at: 0,
            failures: 0,
        }
    }
    fn reset(&mut self) {
        self.registration.cancel();
        self.error = None;
        self.retry_at = 0;
        self.failures = 0;
    }
    fn source(&self) -> Option<&ReleaseWait> {
        match &self.error {
            Some(PublicationError::Deferred(reason)) => reason.release_wait(),
            _ => None,
        }
    }
    fn refuse(&mut self, now: Millis, backoff: Backoff, error: PublicationError) {
        debug_assert!(!matches!(error, PublicationError::RecoveryRequired(_)));
        self.registration.cancel();
        self.error = Some(error);
        self.failures = self.failures.saturating_add(1);
        self.retry_at = now.saturating_add(backoff.delay(self.failures));
    }
    fn ready(&mut self, now: Millis, waker: &Waker) -> bool {
        let Some(PublicationError::Deferred(reason)) = &self.error else {
            return now >= self.retry_at;
        };
        let Some(source) = reason.release_wait() else {
            return now >= self.retry_at;
        };
        // HC76: timers and identical requests cannot defeat an original physical refusal.
        if cfg!(all(test, sumeragi_core_mutation = "HC76")) {
            return now >= self.retry_at;
        }
        if self
            .registration
            .poll_wait(source, &mut Context::from_waker(waker))
            .is_pending()
        {
            return false;
        }
        self.registration.cancel();
        // Retain the typed failure through this actual retry, until its result arrives.
        true
    }
    fn deadline(&self) -> Millis {
        if self.source().is_some() {
            Millis::MAX
        } else {
            self.retry_at
        }
    }
    fn expedite(&mut self) {
        if self.source().is_none() {
            self.retry_at = 0;
        }
    }
}

/// Fixed identity of a moved partial; matching never clones its key or proof graph.
#[derive(Clone, Copy, Debug)]
struct ReceiveIdentity {
    sender: [u8; MAX_PUBLIC_KEY_LEN],
    sender_len: usize,
    context: ApplicationControlContext,
    occurrence: ControlOccurrence,
    bytes: ControlWitness,
}
impl ReceiveIdentity {
    fn new(occurrence: ControlOccurrence, from: &PublicKey, message: &ApplicationControl) -> Self {
        assert!(
            from.is_well_formed(),
            "Core authenticates bounded sender keys"
        );
        let mut sender = [0; MAX_PUBLIC_KEY_LEN];
        sender[..from.as_bytes().len()].copy_from_slice(from.as_bytes());
        Self {
            sender,
            sender_len: from.as_bytes().len(),
            context: message.context,
            occurrence,
            bytes: message.bytes,
        }
    }
    fn sender_is(&self, from: &PublicKey) -> bool {
        &self.sender[..self.sender_len] == from.as_bytes()
    }
    fn matches(
        &self,
        occurrence: ControlOccurrence,
        from: &PublicKey,
        message: &ApplicationControl,
    ) -> bool {
        self.occurrence == occurrence
            && self.sender_is(from)
            && self.context == message.context
            && self.bytes == message.bytes
    }
}

#[derive(Debug)]
struct InboundControl {
    occurrence: ControlOccurrence,
    from: PublicKey,
    message: ApplicationControl,
}

#[derive(Debug)]
struct InboundSlot {
    input: Option<InboundControl>,
    /// Complete fixed-value identity stays in charged backing while the worker owns the input.
    in_flight: Option<ReceiveIdentity>,
    retry: RetryGate,
}

/// One fixed, fully initialized backing; only its existing slot contents can change.
struct InboundSlots {
    slots: ChargedBuffer<InboundSlot>,
}
impl std::fmt::Debug for InboundSlots {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}
impl InboundSlots {
    fn iter(&self) -> std::slice::Iter<'_, InboundSlot> {
        self.slots.as_slice().iter()
    }
    fn iter_mut(&mut self) -> std::slice::IterMut<'_, InboundSlot> {
        self.slots.as_mut_slice().iter_mut()
    }
}
impl std::ops::Index<usize> for InboundSlots {
    type Output = InboundSlot;
    fn index(&self, index: usize) -> &Self::Output {
        &self.slots.as_slice()[index]
    }
}
impl std::ops::IndexMut<usize> for InboundSlots {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.slots.as_mut_slice()[index]
    }
}

/// The original failed operation whose resource release permits another attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitWaitPhase {
    Prepare,
    Append,
    Commit,
}

/// Only the current committed head may use this original release observation.
#[derive(Debug)]
struct CommitWait {
    height: u64,
    block_hash: Hash32,
    phase: CommitWaitPhase,
    release: ReleaseWait,
}

/// The execution scheduler of one instance.
#[derive(Debug)]
pub struct ExecSched {
    /// Queued `Execute`s; the last is the most recent.
    jobs: Vec<Job>,
    parked: Vec<Job>,
    /// Queued jobs of the block being applied, answered from its apply.
    merged: Vec<Job>,
    running: Option<Running>,
    /// Cancellation is sticky until the actual original worker completion returns.
    running_cancelled: bool,
    commits: VecDeque<Arc<Commit>>,
    stage: Stage,
    /// The head commit is durable in the block store (a re-prepare skips the append).
    appended: bool,
    append_refusal: Option<crate::execution_attempt::ExecutionDeferred>,
    /// Original local preparation refusal stays with the queued committed decision.
    preparation_refusal: Option<super::traits::PublicationDeferral>,
    /// Prepaid before Core starts; rearming never allocates while the pool is exhausted.
    commit_registration: ReleaseRegistration,
    commit_wait: Option<CommitWait>,
    release_waker: Waker,
    build: Option<BuildRequest>,
    active_build: Option<BuildRequest>,
    control_build: Option<ControlBuild>,
    control_context: Option<(ApplicationControlContext, u64)>,
    payload_retry: RetryGate,
    witness_retry: RetryGate,
    drive_retry: RetryGate,
    inbound: InboundSlots,
    inbound_cursor: usize,
    next_occurrence: u64,
    control_drive: Option<ApplicationControlContext>,
    /// Alternate one control operation with ordinary work so partial ingress cannot starve it.
    prefer_control: bool,
    /// Rotate drive, ingress and due builds within the control class under saturation.
    control_cursor: u8,
    rejects: VecDeque<(u64, u64, Hash32)>,
    discards: VecDeque<(u64, Vec<Hash32>)>,
    applied: u64,
    halted: Option<HaltReason>,
    failures: u32,
    retry_at: Option<Millis>,
    backoff: Backoff,
    pending_ready: Option<u64>,
    /// An includable transaction arrived while a build ran: its queue snapshot may predate it.
    arrived_during_build: bool,
    events: Vec<Event>,
}

impl ExecSched {
    /// A scheduler whose executor has applied `applied`.
    pub fn new(applied: u64, backoff: Backoff, registrations: ExecutionRegistrations) -> Self {
        let ExecutionRegistrations {
            committed,
            payload,
            witness,
            drive,
            inbound,
        } = registrations;
        Self {
            jobs: Vec::new(),
            parked: Vec::new(),
            merged: Vec::new(),
            running: None,
            running_cancelled: false,
            commits: VecDeque::new(),
            stage: Stage::Fresh,
            appended: false,
            append_refusal: None,
            preparation_refusal: None,
            commit_registration: committed,
            commit_wait: None,
            release_waker: Waker::noop().clone(),
            build: None,
            active_build: None,
            control_build: None,
            control_context: None,
            payload_retry: RetryGate::new(payload),
            witness_retry: RetryGate::new(witness),
            drive_retry: RetryGate::new(drive),
            inbound,
            inbound_cursor: 0,
            next_occurrence: 0,
            control_drive: None,
            prefer_control: true,
            control_cursor: 0,
            rejects: VecDeque::new(),
            discards: VecDeque::new(),
            applied,
            halted: None,
            failures: 0,
            retry_at: None,
            backoff,
            pending_ready: None,
            arrived_during_build: false,
            events: Vec::new(),
        }
    }

    /// Highest applied height.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    fn answer(&mut self, job: &Job, outcome: ExecOutcome) {
        self.events.push(Event::Executed {
            block_hash: job.block_hash,
            req: job.req,
            outcome,
        });
    }

    /// `Execute{block, req, certified}`: queued (most recent first); answered `Cancelled` at once if its
    /// height is already applied.
    pub fn execute(&mut self, req: u64, block_hash: Hash32, block: AvailableBody, certified: bool) {
        if self.halted.is_some() {
            self.events.push(Event::Executed {
                req,
                block_hash,
                outcome: ExecOutcome::Cancelled,
            });
            return;
        }
        let job = Job {
            req,
            block_hash,
            block: Arc::new(block),
            certified,
            cancelled: false,
        };
        if job.height() <= self.applied {
            self.answer(&job, ExecOutcome::Cancelled);
        } else {
            self.jobs.push(job);
        }
    }

    /// `DiscardExecution{height, keep}`: waiting jobs left out are answered `Cancelled` now, a
    /// running one when it finishes; the executor drops the post-states.
    pub fn discard(&mut self, height: u64, keep: Vec<Hash32>) {
        if self.halted.is_some() {
            return;
        }
        let out = |job: &Job| job.height() == height && !keep.contains(&job.block_hash);
        let mut cancelled = Vec::new();
        for list in [&mut self.jobs, &mut self.parked] {
            list.retain(|job| {
                if out(job) {
                    cancelled.push(job.clone());
                    false
                } else {
                    true
                }
            });
        }
        for job in &cancelled {
            self.answer(job, ExecOutcome::Cancelled);
        }
        if let Some(Running::Execute(job)) = &mut self.running
            && out(job)
        {
            job.cancelled = true;
        }
        // Discards run before any execution, so two of one height in a row keep what both keep.
        match self.discards.iter_mut().find(|(h, _)| *h == height) {
            Some((_, kept)) => kept.retain(|bh| keep.contains(bh)),
            None => self.discards.push_back((height, keep)),
        }
    }

    /// `CommitBlock` (after the O2 barrier; the core emits them in height order).
    pub fn commit(&mut self, block: AvailableBody, qc: Qc) {
        if self.halted.is_some() {
            return;
        }
        self.commits.push_back(Arc::new(Commit { block, qc }));
    }

    /// `BuildPayload`: replace only a different exact request; duplicates preserve retry custody.
    pub fn build(&mut self, req: u64, height: u64, view: u64, max_bytes: u32, exec_budget_ms: u32) {
        if self.halted.is_some() {
            return;
        }
        let next = BuildRequest {
            req,
            height,
            view,
            max_bytes,
            exec_budget_ms,
        };
        if self.active_build == Some(next) {
            return;
        }
        if matches!(self.running, Some(Running::Build(_))) {
            self.running_cancelled = true;
        }
        self.payload_retry.reset();
        self.pending_ready = None;
        self.build = Some(next);
        self.active_build = Some(next);
        self.arrived_during_build = false;
    }

    fn payload_build_is_current(&self, build: &BuildRequest) -> bool {
        self.control_context
            .is_some_and(|(source, view)| source.height == build.height && view == build.view)
    }

    fn witness_is_current(&self, context: &ControlWitnessContext) -> bool {
        self.control_context.is_some_and(|(source, view)| {
            source.height == context.height
                && view == context.view
                && source.epoch == context.epoch
                && source.parent_hash == context.parent_hash
                && source.parent_result == context.parent_result
        })
    }
    fn witness_build_is_current(&self, build: &ControlBuild) -> bool {
        self.partial_is_current(build.source) && self.witness_is_current(&build.context)
    }
    fn partial_is_current(&self, context: ApplicationControlContext) -> bool {
        self.control_context
            .is_some_and(|(source, _)| source == context)
    }

    /// Keep only the live Core's complete applied-parent source and fresh signing view.
    pub fn retain_control_context(&mut self, context: Option<(ApplicationControlContext, u64)>) {
        // First cancel every affected observer without dropping any retained source or
        // input. Their subsequent refunds cannot wake another cancelled queue.
        if self.control_context != context {
            self.payload_retry.registration.cancel();
            self.witness_retry.registration.cancel();
        }
        let next_source = context.map(|(source, _)| source);
        if self.control_context.map(|(source, _)| source) != next_source {
            self.drive_retry.registration.cancel();
            for slot in self.inbound.iter_mut() {
                slot.retry.registration.cancel();
            }
        }
        let activates_waiting_parent = self.control_context.is_none()
            && self.build.is_some_and(|build| {
                context.is_some_and(|(source, view)| {
                    source.height == build.height && view == build.view
                })
            });
        if self.control_context != context && !activates_waiting_parent {
            if matches!(self.running, Some(Running::Build(_))) {
                self.running_cancelled = true;
            }
            self.build = None;
            self.active_build = None;
            self.pending_ready = None;
            self.payload_retry.reset();
            self.arrived_during_build = false;
        }
        // Core may request its successor while the parent is still applying. That
        // request is queued, never dispatched, until Core itself accepts BlockApplied.
        // Its first matching parent activation is not a withdrawal of a bound source.
        self.control_context = context;
        match &self.running {
            Some(Running::BuildControl(build)) if !self.witness_build_is_current(build) => {
                self.running_cancelled = true;
                self.witness_retry.reset()
            }
            Some(Running::DriveControl(source)) if !self.partial_is_current(*source) => {
                self.running_cancelled = true;
                self.drive_retry.reset()
            }
            Some(Running::ReceiveControl { index })
                if !self.partial_is_current(
                    self.inbound[*index]
                        .in_flight
                        .as_ref()
                        .expect("running original identity")
                        .context,
                ) =>
            {
                self.running_cancelled = true;
                self.inbound[*index].retry.reset()
            }
            _ => {}
        }
        if self
            .control_build
            .is_some_and(|build| !self.witness_build_is_current(&build))
        {
            self.control_build = None;
            self.witness_retry.reset();
        }
        if self
            .control_drive
            .is_some_and(|source| !self.partial_is_current(source))
        {
            self.control_drive = None;
            self.drive_retry.reset();
        }
        for index in 0..MAX_COMMITTEE_SIZE {
            if self.inbound[index]
                .input
                .as_ref()
                .is_some_and(|item| !self.partial_is_current(item.message.context))
            {
                self.inbound[index].retry.reset();
                self.inbound[index].input = None;
            }
        }
    }

    /// Supersede only with a different exact fresh-proposal request.
    pub fn build_control(&mut self, req: u64, context: ControlWitnessContext) {
        if self.halted.is_some()
            || context.height <= self.applied
            || !self.witness_is_current(&context)
        {
            return;
        }
        let next = ControlBuild {
            req,
            context,
            source: self.control_context.expect("current witness source").0,
        };
        if self.control_build == Some(next)
            || (!self.running_cancelled
                && matches!(&self.running, Some(Running::BuildControl(original)) if *original == next))
        {
            return;
        }
        if matches!(self.running, Some(Running::BuildControl(_))) {
            self.running_cancelled = true;
        }
        self.witness_retry.reset();
        self.control_build = Some(next);
    }

    /// Coalesce periodic drives without releasing a blocked original request.
    pub fn drive_control(&mut self, context: ApplicationControlContext) {
        if self.halted.is_some()
            || context.height <= self.applied
            || !self.partial_is_current(context)
        {
            return;
        }
        if self.control_drive == Some(context)
            || (!self.running_cancelled
                && matches!(&self.running, Some(Running::DriveControl(original)) if *original == context))
        {
            return;
        }
        self.drive_retry.reset();
        self.control_drive = Some(context);
    }

    /// Retain one original partial per authenticated sender, counting the in-flight owner.
    /// Repeated ingress cannot replace a partial whose local operation is still owed.
    pub fn receive_control(&mut self, from: PublicKey, message: ApplicationControl) {
        if self.halted.is_some()
            || message.context.height <= self.applied
            || !self.partial_is_current(message.context)
            || !from.is_well_formed()
        {
            return;
        }
        let running_index = match &self.running {
            Some(Running::ReceiveControl { index }) => {
                if self.inbound[*index]
                    .in_flight
                    .as_ref()
                    .expect("running original identity")
                    .sender_is(&from)
                {
                    return;
                }
                Some(*index)
            }
            _ => None,
        };
        if self
            .inbound
            .iter()
            .filter_map(|slot| slot.input.as_ref())
            .any(|item| item.from == from)
        {
            return;
        }
        if let Some(index) = (0..MAX_COMMITTEE_SIZE)
            .find(|index| Some(*index) != running_index && self.inbound[*index].input.is_none())
        {
            let Some(next) = self.next_occurrence.checked_add(1) else {
                self.require_recovery(
                    message.context.height,
                    "local control occurrence identifiers exhausted",
                );
                return;
            };
            let occurrence = ControlOccurrence(self.next_occurrence);
            self.next_occurrence = next;
            self.inbound[index].retry.reset();
            self.inbound[index].input = Some(InboundControl {
                occurrence,
                from,
                message,
            });
        }
    }

    fn next_control(&mut self, now: Millis) -> Option<ExecOp> {
        self.control_context?;
        let next = self.applied.checked_add(1)?;
        for offset in 0..3 {
            let kind = (self.control_cursor + offset) % 3;
            let op = match kind {
                0 => {
                    if let Some(context) = self.control_drive
                        && context.height == next
                        && self.drive_retry.ready(now, &self.release_waker)
                    {
                        self.control_drive = None;
                        self.running = Some(Running::DriveControl(context));
                        Some(ExecOp::DriveApplicationControl(context))
                    } else {
                        None
                    }
                }
                1 => {
                    let mut ready = None;
                    for offset in 0..MAX_COMMITTEE_SIZE {
                        let index = (self.inbound_cursor + offset) % MAX_COMMITTEE_SIZE;
                        if self.inbound[index]
                            .input
                            .as_ref()
                            .is_some_and(|item| item.message.context.height == next)
                            && self.inbound[index].retry.ready(now, &self.release_waker)
                        {
                            ready = Some(index);
                            break;
                        }
                    }
                    ready.map(|index| {
                        let InboundControl {
                            occurrence,
                            from,
                            message,
                        } = self.inbound[index]
                            .input
                            .take()
                            .expect("selected original partial");
                        self.inbound_cursor = (index + 1) % MAX_COMMITTEE_SIZE;
                        self.inbound[index].in_flight =
                            Some(ReceiveIdentity::new(occurrence, &from, &message));
                        self.running = Some(Running::ReceiveControl { index });
                        ExecOp::ReceiveApplicationControl {
                            occurrence,
                            from,
                            message,
                        }
                    })
                }
                _ => {
                    if let Some(build) = self.control_build
                        && build.context.height == next
                        && self.witness_retry.ready(now, &self.release_waker)
                    {
                        self.control_build = None;
                        self.running = Some(Running::BuildControl(build));
                        Some(ExecOp::BuildControlWitness {
                            req: build.req,
                            context: build.context,
                        })
                    } else {
                        None
                    }
                }
            };
            if op.is_some() {
                self.control_cursor = (kind + 1) % 3;
                return op;
            }
        }
        None
    }

    /// `PayloadRejected` (once per block; the oldest go beyond [`MAX_REJECTS`]).
    pub fn reject(&mut self, height: u64, view: u64, block_hash: Hash32) {
        if self.halted.is_some() {
            return;
        }
        if self.rejects.iter().any(|(_, _, bh)| *bh == block_hash) {
            return;
        }
        if self.rejects.len() >= MAX_REJECTS {
            self.rejects.pop_front();
        }
        self.rejects.push_back((height, view, block_hash));
    }

    /// An includable transaction arrived: `PayloadReady{req}` if the latest build was `EMPTY`
    /// (at most once per request). During a build the arrival is remembered: an `EMPTY` answer
    /// may have read the queue before it, and is followed by `PayloadReady` at once (E55).
    pub fn transactions_available(&mut self) {
        if self.halted.is_some() {
            return;
        }
        if let Some(req) = self.pending_ready.take() {
            self.events.push(Event::PayloadReady { req });
        } else if self.build.is_some() || matches!(self.running, Some(Running::Build(_))) {
            self.arrived_during_build = true;
        }
    }

    /// The next operation for the executor, if it is idle. A commit that is prepared or
    /// appended, or whose failed step backs off, runs alone (its next step once due, nothing
    /// else meanwhile). Otherwise: discards, then the apply of the next committed block, then a
    /// build whose parent is applied, then rejections, then the most recent `Execute`.
    pub fn next(&mut self, now: Millis) -> Option<ExecOp> {
        if self.halted.is_some() || self.running.is_some() {
            return None;
        }
        let committing = self.halted.is_none()
            && !self.commits.is_empty()
            && (self.stage != Stage::Fresh || self.retry_at.is_some());
        if committing {
            let due = self.commit_retry_ready(now);
            return if due { self.commit_step() } else { None };
        }
        if let Some((height, keep)) = self.discards.pop_front() {
            self.running = Some(Running::Discard);
            return Some(ExecOp::Discard { height, keep });
        }
        if self.halted.is_none() && !self.commits.is_empty() {
            return self.commit_step();
        }
        if self.prefer_control
            && let Some(op) = self.next_control(now)
        {
            self.prefer_control = false;
            return Some(op);
        }
        if let Some(build) = self.build
            && build.height <= self.applied.saturating_add(1)
            && self.payload_build_is_current(&build)
            && self.payload_retry.ready(now, &self.release_waker)
        {
            self.build = None;
            self.prefer_control = true;
            self.running = Some(Running::Build(build));
            return Some(ExecOp::Build {
                req: build.req,
                height: build.height,
                view: build.view,
                max_bytes: build.max_bytes,
                exec_budget_ms: build.exec_budget_ms,
            });
        }
        if let Some((height, view, block_hash)) = self.rejects.pop_front() {
            self.prefer_control = true;
            self.running = Some(Running::Reject);
            return Some(ExecOp::Reject {
                height,
                view,
                block_hash,
            });
        }
        let Some(job) = self.jobs.pop() else {
            self.prefer_control = false;
            return self.next_control(now);
        };
        self.prefer_control = true;
        let op = ExecOp::Execute {
            block: Arc::clone(&job.block),
            block_hash: job.block_hash,
            certified: job.certified,
        };
        self.running = Some(Running::Execute(job));
        Some(op)
    }

    /// Test observation of the original completed EMPTY request. It grants no protocol event.
    #[cfg(test)]
    pub(super) fn waiting_empty_request_for_test(&self) -> Option<u64> {
        if self.running.is_none() && self.build.is_none() && !self.arrived_during_build {
            self.pending_ready
        } else {
            None
        }
    }

    /// Bind the production loop's original charged wake control before dispatch.
    pub(super) fn bind_release_waker(&mut self, waker: Waker) {
        self.release_waker = waker;
    }

    fn clear_commit_wait(&mut self) {
        self.commit_registration.cancel();
        self.commit_wait = None;
    }

    fn retain_commit_wait(&mut self, phase: CommitWaitPhase, release: Option<ReleaseWait>) {
        self.clear_commit_wait();
        if let Some(release) = release {
            let head = self
                .commits
                .front()
                .expect("only a committed head can refuse publication");
            self.commit_wait = Some(CommitWait {
                height: head.block.header().height,
                block_hash: head.qc.block_hash,
                phase,
                release,
            });
        }
    }

    fn commit_retry_ready(&mut self, now: Millis) -> bool {
        let Some(wait) = self.commit_wait.as_ref() else {
            return self.retry_at.is_none_or(|at| at <= now);
        };
        let head = self
            .commits
            .front()
            .expect("the refused committed head is retained");
        assert_eq!(
            (wait.height, wait.block_hash),
            (head.block.header().height, head.qc.block_hash)
        );
        debug_assert!(matches!(
            (wait.phase, self.stage),
            (
                CommitWaitPhase::Prepare | CommitWaitPhase::Commit,
                Stage::Fresh
            ) | (CommitWaitPhase::Append, Stage::Prepared)
        ));
        // HC74: elapsed time grants no right to retry an unchanged busy source.
        if cfg!(all(test, sumeragi_core_mutation = "HC74")) {
            return self.retry_at.is_none_or(|at| at <= now);
        }
        let mut context = Context::from_waker(&self.release_waker);
        if self
            .commit_registration
            .poll_wait(&wait.release, &mut context)
            .is_pending()
        {
            return false;
        }
        self.clear_commit_wait();
        true
    }

    /// The next step of the head commit.
    fn commit_step(&mut self) -> Option<ExecOp> {
        let commit = self.commits.front().cloned()?;
        let (running, op) = match self.stage {
            Stage::Fresh => {
                let bh = commit.qc.block_hash;
                for list in [&mut self.jobs, &mut self.parked] {
                    let (same, rest): (Vec<Job>, Vec<Job>) =
                        list.drain(..).partition(|job| job.block_hash == bh);
                    *list = rest;
                    self.merged.extend(same);
                }
                (Running::Prepare, ExecOp::Prepare(commit))
            }
            Stage::Prepared => (Running::Append, ExecOp::Append(commit)),
            Stage::Appended => (Running::Commit, ExecOp::Commit(commit)),
        };
        self.running = Some(running);
        Some(op)
    }

    /// Jobs whose parent is `parent` may run now: back in the queue, behind newer ones.
    fn unpark(&mut self, parent: &Hash32) {
        let (ready, rest): (Vec<Job>, Vec<Job>) = self
            .parked
            .drain(..)
            .partition(|job| job.block.header().parent_hash == *parent);
        self.parked = rest;
        let newer = std::mem::replace(&mut self.jobs, ready);
        self.jobs.extend(newer);
    }

    fn retry(&mut self, now: Millis, what: &str, reason: &str) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now.saturating_add(self.backoff.delay(self.failures)));
        iroha_logger::warn!(%reason, step = what, "sumeragi apply failed; retrying");
    }

    /// Original local preparation source retained with the unchanged committed head.
    /// This observation grants neither successful preparation nor future allocation credit.
    pub fn preparation_refusal(&self) -> Option<&super::traits::PublicationDeferral> {
        self.preparation_refusal.as_ref()
    }

    /// Why execution scheduling stopped; a halt never schedules a publication retry.
    pub fn halted(&self) -> Option<HaltReason> {
        self.halted
    }

    fn cancel_registrations(&mut self) {
        self.commit_registration.cancel();
        self.payload_retry.registration.cancel();
        self.witness_retry.registration.cancel();
        self.drive_retry.registration.cancel();
        for slot in self.inbound.iter_mut() {
            slot.retry.registration.cancel();
        }
    }

    fn require_recovery(&mut self, height: u64, reason: &str) {
        self.cancel_registrations();
        self.clear_commit_wait();
        self.halted = Some(HaltReason::PublicationRecoveryRequired { height });
        self.retry_at = None;
        self.pending_ready = None;
        self.build = None;
        self.active_build = None;
        self.control_build = None;
        self.control_context = None;
        self.control_drive = None;
        self.inbound.iter_mut().for_each(|slot| {
            slot.input = None;
            slot.retry.reset();
        });
        self.payload_retry.reset();
        self.witness_retry.reset();
        self.drive_retry.reset();
        self.rejects.clear();
        self.discards.clear();
        // Preserve the committed head for diagnostics; no owner is re-entered after this point.
        self.events
            .push(Event::PublicationRecoveryRequired { height });
        for jobs in [
            std::mem::take(&mut self.jobs),
            std::mem::take(&mut self.parked),
            std::mem::take(&mut self.merged),
        ] {
            for job in jobs {
                self.answer(&job, ExecOutcome::Cancelled);
            }
        }
        iroha_logger::error!(height, %reason, "sumeragi publication requires recovery; stopped scheduling");
    }

    /// The executor answered the operation in flight. Returns the height newly applied, if
    /// any (its stored bodies can be pruned).
    #[allow(clippy::too_many_lines)] // one arm per operation
    pub fn done(&mut self, now: Millis, done: ExecDone) -> Option<u64> {
        let running = self.running.take()?;
        // HC78: once cancelled, the original in-flight work cannot become current again.
        let cancelled = std::mem::take(&mut self.running_cancelled)
            && !cfg!(all(test, sumeragi_core_mutation = "HC78"));
        match (running, done) {
            (Running::Execute(job), ExecDone::Executed(outcome)) => match outcome {
                _ if job.cancelled => self.answer(&job, ExecOutcome::Cancelled),
                None if job.height() <= self.applied => {
                    self.answer(&job, ExecOutcome::Cancelled);
                }
                None => self.parked.push(job),
                Some(outcome) => {
                    let valid = matches!(outcome, ExecOutcome::Valid(_));
                    self.answer(&job, outcome);
                    if valid {
                        self.unpark(&job.block_hash);
                    }
                }
            },
            (Running::Prepare, ExecDone::Prepared(result)) => {
                let commit = self.commits.front().cloned()?;
                match result {
                    Ok(Some(local)) if local == commit.qc.result => {
                        self.clear_commit_wait();
                        self.preparation_refusal = None;
                        // Re-prepare after append is part of the same failed commit attempt.
                        // In particular, archive capture may still be pending after State
                        // publication: obtaining that retained result is not recovery.
                        if !self.appended {
                            self.failures = 0;
                        }
                        self.retry_at = None;
                        self.stage = if self.appended {
                            Stage::Appended
                        } else {
                            Stage::Prepared
                        };
                        for job in std::mem::take(&mut self.merged) {
                            self.answer(&job, ExecOutcome::Valid(local));
                        }
                    }
                    Ok(local) => {
                        // O3: the local state or executor disagrees with a certified result.
                        self.clear_commit_wait();
                        self.halted = Some(HaltReason::ApplyDiverged {
                            height: commit.block.header().height,
                        });
                        let outcome = local.map_or(ExecOutcome::Invalid, ExecOutcome::Valid);
                        for job in std::mem::take(&mut self.merged) {
                            self.answer(&job, outcome.clone());
                        }
                        self.events.push(Event::ApplyDiverged {
                            height: commit.block.header().height,
                            block_hash: commit.qc.block_hash,
                            local_result: local.unwrap_or(Hash32::ZERO),
                        });
                    }
                    Err(PublicationError::Retryable(reason)) => {
                        self.clear_commit_wait();
                        self.preparation_refusal = None;
                        self.retry(now, "prepare", &reason);
                    }
                    Err(PublicationError::Deferred(original)) => {
                        let diagnostic = original.to_string();
                        // HC60: a diagnostic cannot replace the source-bound release observation.
                        if !cfg!(all(test, sumeragi_core_mutation = "HC60")) {
                            self.preparation_refusal = Some(original);
                        }
                        let release = self
                            .preparation_refusal
                            .as_ref()
                            .and_then(|reason| reason.release_wait())
                            .cloned();
                        self.retain_commit_wait(CommitWaitPhase::Prepare, release);
                        self.retry(now, "prepare", &diagnostic);
                    }
                    Err(PublicationError::RecoveryRequired(reason)) => {
                        self.require_recovery(commit.block.header().height, &reason)
                    }
                }
            }
            (Running::Append, ExecDone::Appended { durable, deferred }) => {
                self.append_refusal = if cfg!(all(test, sumeragi_core_mutation = "HC47")) {
                    None
                } else {
                    deferred
                };
                if durable {
                    self.clear_commit_wait();
                    self.append_refusal = None;
                    self.failures = 0;
                    self.retry_at = None;
                    self.appended = true;
                    self.stage = Stage::Appended;
                } else {
                    let release = self.append_refusal.as_ref().and_then(|reason| {
                        match reason.allocation_refusal() {
                            Some(iroha_allocation::AllocationRefusal::Capacity {
                                release, ..
                            }) => Some(release.clone()),
                            _ => None,
                        }
                    });
                    self.retain_commit_wait(CommitWaitPhase::Append, release);
                    self.retry(now, "append", "block store write failed");
                }
            }
            (Running::Commit, ExecDone::Committed(result)) => match result {
                Ok(config) => {
                    self.clear_commit_wait();
                    self.preparation_refusal = None;
                    let commit = self.commits.pop_front()?;
                    self.failures = 0;
                    self.retry_at = None;
                    self.stage = Stage::Fresh;
                    self.appended = false;
                    let height = commit.block.header().height;
                    self.applied = height;
                    self.events.push(Event::BlockApplied {
                        height,
                        block_hash: commit.qc.block_hash,
                        header: Box::new(commit.block.header().clone()),
                        config: *config,
                    });
                    // Requests of applied heights are moot: answered, never left waiting.
                    let applied = self.applied;
                    for list in [&mut self.jobs, &mut self.parked] {
                        let (stale, rest): (Vec<Job>, Vec<Job>) =
                            list.drain(..).partition(|job| job.height() <= applied);
                        *list = rest;
                        for job in stale {
                            let outcome = if job.block_hash == commit.qc.block_hash {
                                ExecOutcome::Valid(commit.qc.result)
                            } else {
                                ExecOutcome::Cancelled
                            };
                            self.events.push(Event::Executed {
                                block_hash: job.block_hash,
                                req: job.req,
                                outcome,
                            });
                        }
                    }
                    self.unpark(&commit.qc.block_hash);
                    return Some(height);
                }
                Err(PublicationError::Deferred(original)) => {
                    let diagnostic = original.to_string();
                    let release = original.release_wait().cloned();
                    self.preparation_refusal = Some(original);
                    self.retain_commit_wait(CommitWaitPhase::Commit, release);
                    self.stage = Stage::Fresh;
                    self.retry(now, "commit", &diagnostic);
                }
                Err(PublicationError::Retryable(reason)) => {
                    self.clear_commit_wait();
                    self.preparation_refusal = None;
                    // Re-prepare the retained original owner; the append is kept.
                    self.stage = Stage::Fresh;
                    self.retry(now, "commit", &reason);
                }
                Err(PublicationError::RecoveryRequired(reason)) => {
                    if let Some(commit) = self.commits.front() {
                        self.require_recovery(commit.block.header().height, &reason);
                    }
                }
            },
            (Running::BuildControl(build), ExecDone::ControlWitnessBuilt(result)) => {
                let current = !cancelled
                    && self.witness_build_is_current(&build)
                    && self.control_build.is_none_or(|pending| pending == build);
                match result {
                    Err(PublicationError::RecoveryRequired(reason)) => {
                        self.require_recovery(build.context.height, &reason)
                    }
                    _ if !current => {}
                    Ok(witness) => {
                        self.witness_retry.reset();
                        self.events.push(Event::ControlWitnessBuilt {
                            req: build.req,
                            context: build.context,
                            witness,
                        });
                    }
                    Err(error) => {
                        self.witness_retry.refuse(now, self.backoff, error);
                        self.control_build = Some(build);
                    }
                }
            }
            (Running::DriveControl(context), ExecDone::ApplicationControlDriven(result)) => {
                let current = !cancelled
                    && self.partial_is_current(context)
                    && self.control_drive.is_none_or(|pending| pending == context);
                match result {
                    Err(PublicationError::RecoveryRequired(reason)) => {
                        self.require_recovery(context.height, &reason)
                    }
                    _ if !current => {}
                    Ok(message) => {
                        self.drive_retry.reset();
                        if let Some(message) = message
                            && message.context == context
                        {
                            self.events.push(Event::ApplicationControlBuilt { message });
                        }
                    }
                    Err(error) => {
                        self.drive_retry.refuse(now, self.backoff, error);
                        self.control_drive = Some(context);
                    }
                }
            }
            (
                Running::ReceiveControl { index },
                ExecDone::ApplicationControlReceived {
                    occurrence,
                    from,
                    message,
                    result,
                },
            ) => {
                let identity = self.inbound[index]
                    .in_flight
                    .take()
                    .expect("running original identity");
                if !identity.matches(occurrence, &from, &message) {
                    self.require_recovery(
                        identity.context.height,
                        "application-control completion replaced the original input",
                    );
                    return None;
                }
                match result {
                    Err(PublicationError::RecoveryRequired(reason)) => {
                        self.require_recovery(identity.context.height, &reason)
                    }
                    _ if cancelled || !self.partial_is_current(identity.context) => {
                        self.inbound[index].retry.reset()
                    }
                    Ok(()) => {
                        self.inbound[index].retry.reset();
                        // New shares accelerate awaiting-share backoff, never a held physical source.
                        self.witness_retry.expedite();
                    }
                    Err(error) => {
                        debug_assert!(self.inbound[index].input.is_none());
                        self.inbound[index].retry.refuse(now, self.backoff, error);
                        self.inbound[index].input = Some(InboundControl {
                            occurrence,
                            from,
                            message,
                        });
                    }
                }
            }
            (Running::Build(build), ExecDone::Built(result)) => {
                if let Err(PublicationError::RecoveryRequired(reason)) = &result {
                    self.require_recovery(build.height, reason);
                    return None;
                }
                if !cancelled && self.active_build == Some(build) {
                    match result {
                        Ok(payload) => {
                            self.active_build = None;
                            self.payload_retry.reset();
                            let empty = payload.is_none();
                            let arrived = std::mem::take(&mut self.arrived_during_build);
                            self.pending_ready = (empty && !arrived).then_some(build.req);
                            self.events.push(Event::PayloadBuilt {
                                req: build.req,
                                payload,
                            });
                            if !empty || arrived {
                                self.events.push(Event::PayloadReady { req: build.req });
                            }
                        }
                        Err(PublicationError::RecoveryRequired(reason)) => {
                            self.require_recovery(build.height, &reason)
                        }
                        Err(error) => {
                            self.payload_retry.refuse(now, self.backoff, error);
                            self.build = Some(build);
                        }
                    }
                }
            }
            (Running::Discard, ExecDone::Discarded) | (Running::Reject, ExecDone::Rejected) => {}
            (running, done) => {
                iroha_logger::error!(?running, ?done, "sumeragi executor answer does not match");
                self.running = Some(running);
                self.running_cancelled = cancelled;
            }
        }
        None
    }

    /// When a failed apply step is due again (`Millis::MAX`: nothing to wait for). Only while
    /// the executor is idle, so the wakeup can always be acted on.
    pub fn wakeup(&self) -> Millis {
        if self.running.is_some() || self.halted.is_some() {
            return Millis::MAX;
        }
        if !self.commits.is_empty() {
            // The actual release wakes the loop; an expired timer must not spin it.
            return if self.commit_wait.is_some() {
                Millis::MAX
            } else {
                self.retry_at.unwrap_or(Millis::MAX)
            };
        }
        let next = self.applied.saturating_add(1);
        let witness = self
            .control_build
            .filter(|build| build.context.height == next)
            .map_or(Millis::MAX, |_| self.witness_retry.deadline());
        let drive = self
            .control_drive
            .filter(|context| context.height == next)
            .map_or(Millis::MAX, |_| self.drive_retry.deadline());
        let inbound = self
            .inbound
            .iter()
            .filter(|slot| {
                slot.input
                    .as_ref()
                    .is_some_and(|item| item.message.context.height == next)
            })
            .map(|slot| slot.retry.deadline())
            .min()
            .unwrap_or(Millis::MAX);
        let payload = self
            .build
            .filter(|build| build.height <= next && self.payload_build_is_current(build))
            .map_or(Millis::MAX, |_| self.payload_retry.deadline());
        witness.min(drive).min(inbound).min(payload)
    }

    /// The local events produced so far (answers for the core), in order.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// `Execute` requests not answered yet (queued, parked, merged or running).
    pub fn outstanding(&self) -> usize {
        self.jobs.len()
            + self.parked.len()
            + self.merged.len()
            + usize::from(matches!(self.running, Some(Running::Execute(_))))
    }

    /// Whether an operation is in flight.
    pub fn busy(&self) -> bool {
        self.running.is_some()
    }

    /// Executor operations queued other than `Execute`s: commits, discards, rejections and a
    /// build.
    pub fn queued_ops(&self) -> usize {
        self.commits.len()
            + self.discards.len()
            + self.rejects.len()
            + usize::from(self.build.is_some())
            + usize::from(self.control_build.is_some())
            + usize::from(self.control_drive.is_some())
            + self
                .inbound
                .iter()
                .filter(|slot| slot.input.is_some())
                .count()
    }
}

impl Drop for ExecSched {
    fn drop(&mut self) {
        if !cfg!(all(test, sumeragi_core_mutation = "HC83")) {
            self.cancel_registrations();
        }
    }
}

#[cfg(test)]
mod refusal_tests {
    //! The sole append slot retains its original commit and capacity owner through retry.
    use super::*;
    use crate::sumeragi::driver::tests::{block, commit_qc};

    #[test]
    fn append_refusal_keeps_original_commit_and_release_owner_until_durable() {
        let registration_bytes = ExecutionRegistrations::admission_bytes();
        let budget = iroha_allocation::AllocationBudget::new(registration_bytes + 1);
        let registration = ExecutionRegistrations::admit(&budget).unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let body = block(1, Hash32::ZERO, Hash32::ZERO, vec![1]);
        let result = Hash32([9; 32]);
        let qc = commit_qc(&body, result);
        let mut scheduler = ExecSched::new(0, Backoff::default(), registration);
        scheduler.commit(body, qc);
        let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
            panic!("prepare original")
        };
        scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
        let Some(ExecOp::Append(append)) = scheduler.next(0) else {
            panic!("append original")
        };
        assert!(Arc::ptr_eq(&original, &append));
        scheduler.done(
            0,
            ExecDone::Appended {
                durable: false,
                deferred: Some(refusal.clone().into()),
            },
        );
        assert_eq!(
            scheduler
                .append_refusal
                .as_ref()
                .unwrap()
                .allocation_refusal(),
            Some(&refusal)
        );
        assert_eq!(scheduler.applied(), 0);
        assert!(scheduler.take_events().is_empty());
        assert!(scheduler.next(0).is_none());
        drop(held);
        let Some(ExecOp::Append(retry)) = scheduler.next(scheduler.wakeup()) else {
            panic!("retry same append")
        };
        assert!(Arc::ptr_eq(&original, &retry));
        assert_eq!(
            scheduler
                .append_refusal
                .as_ref()
                .unwrap()
                .allocation_refusal(),
            Some(&refusal)
        );
        scheduler.done(
            scheduler.wakeup(),
            ExecDone::Appended {
                durable: true,
                deferred: None,
            },
        );
        assert!(scheduler.append_refusal.is_none());
        let Some(ExecOp::Commit(commit)) = scheduler.next(u64::MAX) else {
            panic!("commit only after durability")
        };
        assert!(Arc::ptr_eq(&original, &commit));
        assert_eq!(scheduler.applied(), 0);
    }
}

#[cfg(test)]
#[path = "source_retry_tests.rs"]
mod source_retry_tests;

#[cfg(test)]
#[path = "producer_retry_tests.rs"]
mod producer_retry_tests;
