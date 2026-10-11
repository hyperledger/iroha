//! The node driver of the Sumeragi consensus core (`specs/sumeragi.md` §12, §13.5).
//!
//! One driver runs per consensus instance. Its [`Kernel`] owns the sans-IO
//! [`iroha_sumeragi::Core`] (constructed on the event-loop thread, since it is `!Send`), the
//! bounded ingress ([`ingress`]), the persist-before-effect barrier ([`barrier`]), the ordered
//! persistence queue ([`persist`]), the execution, apply and build scheduler ([`exec`]) and the
//! serving scheduler ([`serve`]). It performs no I/O: it turns the core's actions into
//! operations ([`Op`]) for three worker threads — persistence, executor, serving — and the
//! transport, and their completions back into core events. [`Driver::spawn`] runs the kernel on
//! its own thread with the workers over the backends of [`traits`]; the §13.5 conformance runs
//! the *same* kernel inside the `iroha_sumeragi` simulator, whose world performs the operations
//! on fake devices.
//!
//! Guarantees of §12.3: O1 (the core's actions take effect in order, exempt ones at once and
//! gated ones through the barrier), O2 ([`barrier`], with the durable watermark of the ordered
//! [`persist`] queue), O3/O4 ([`exec`]), O5 (a due `Tick` first, then local events, then
//! messages by class; nothing on the loop thread blocks on I/O, and released effects leave in
//! batches of [`MAX_OPS_PER_POLL`] with a due `Tick` handled in between), O6/O8 ([`ingress`];
//! held effects and serving are bounded too, [`barrier`], [`serve`]), O7 (the node's own keys
//! are never delivered to or addressed by it), O9 (every instance has its own threads, queues,
//! barrier and backends), O10 (the transport limit is checked at start against the chain
//! parameters, every frame is decoded within it, and a committed configuration that outgrows it
//! is reported, [`FrameLimitExceeded`]).
//!
//! Audit lines: the persistence worker logs every durable safety record (DEBUG) and the
//! executor worker every applied block (INFO) in the stable format that the multi-process soak
//! of §13.5 parses (module `audit`, `scripts/sumeragi_soak.py`).
//!
//! Every backend call on a worker thread is guarded. Publication unwind requires recovery;
//! ordinary execution, idempotent writes and missing reads retain their retry semantics
//! (§12.5). A thread that stops anyway, or a
//! worker that cannot be reached, stops the instance: the observer is told
//! ([`Observer::stopped`]) and the handle reports it (`ready()` false, [`DriverHandle::stopped`]).
//!
//! Production backends: the P2P `Net` and ingress router (`sumeragi::net`), the file record and
//! body stores (`sumeragi::records`, `sumeragi::bodies`) and the BLS crypto and signer
//! (`sumeragi::crypto`). `sumeragi::node` wires Kura's certified block store, the State
//! executor and builder, replay-derived `Init`, and the native lane runner. Complete
//! resource funding and whole-node qualification remain tracked in `specs/sumeragi_goals.md`.

pub mod acquisition;
mod audit;
pub mod barrier;
pub mod exec;
pub mod ingress;
mod node_gate;
pub mod payload_build;
pub mod payload_jobs;
pub mod payload_worker;
#[cfg(test)]
mod payload_worker_tests;
pub mod persist;
pub mod serve;
pub mod traits;
mod wake;
pub use node_gate::NodeGate;

#[cfg(test)]
mod tests;
#[cfg(test)]
#[path = "tests/witness_admission.rs"]
mod witness_admission_tests;

use std::{
    collections::{BTreeMap, VecDeque},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::{Context, Waker},
    thread::JoinHandle,
    time::Duration,
};

use iroha_allocation::{
    AllocationRefusal, ChargedBufferError,
    release::{ReleaseRegistration, ReleaseWait},
};
use iroha_sumeragi::{
    Core,
    api::{
        Action, CommittedTip, ConfigError, CoreStatus, Event, HaltReason, Init, LocalFault,
        LocalParams,
    },
    crypto::{Crypto, Signer},
    message::{ByteAdmissionError, Evidence, TrafficClass, WireMessage},
    pacemaker::FRAME_OVERHEAD,
    safety::RecordState,
    types::{
        AggregateSignature, AppliedConfig, ConfigSlot, Hash32, HeightConfig, Millis, PublicKey,
        Signature,
    },
};
use iroha_telemetry::metrics::sumeragi::InstanceSeries;
use parking_lot::Mutex;

use self::{
    barrier::{Barrier, HeldLimits},
    exec::{ExecDone, ExecOp, ExecSched},
    ingress::{Ingress, IngressLimits},
    persist::{Backoff, PersistQueue, Write},
    serve::{ServeLimits, ServeRequest, ServeSched, Served},
    traits::{
        BlockStore, BodyStore, Clock, Executor, Frame, Net, Observer, PendingSend,
        PublicationError, RecordStore, SendOutcome,
    },
};
use super::metrics::InstanceMetrics;
use wake::ThreadWake;

/// Longest idle wait of the event loop before it re-reads the clock.
const MAX_IDLE_WAIT_MS: Millis = 1_000;

/// Released effects handed out per [`Kernel::poll`]: a burst (a long-pending record finally
/// durable) leaves in batches, and a due `Tick` is handled between them (O5).
pub const MAX_OPS_PER_POLL: usize = 64;

/// A thread of a driver instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Worker {
    /// The event loop (the core's thread).
    Loop,
    /// The persistence thread.
    Persist,
    /// The executor thread.
    Exec,
    /// The serve thread.
    Serve,
}

/// O10 at run time: a committed configuration needs larger frames than the transport accepts,
/// so its larger proposals and bodies will not arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLimitExceeded {
    /// Height the configuration applies from.
    pub height: u64,
    /// `max_block_bytes + FRAME_OVERHEAD`.
    pub needed: u64,
    /// The transport's frame limit.
    pub limit: u64,
}

/// A report for the [`Observer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    /// Signed misbehaviour (released by the O2 barrier).
    Evidence(Box<Evidence>),
    /// A local fault.
    Fault(LocalFault),
    /// The instance halted (only serving continues).
    Halt(HaltReason),
    /// A committed configuration outgrows the transport (O10).
    FrameLimit(FrameLimitExceeded),
}

/// An operation of the kernel for a worker or the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Send `msg` to every peer of `to` (encoded once).
    Send {
        /// Recipients, in order.
        to: Vec<PublicKey>,
        /// The message.
        msg: WireMessage,
    },
    /// The next serving request for the serve thread.
    Serve(ServeRequest),
    /// The next durable write for the persistence thread.
    Persist {
        /// Sequence number.
        seq: u64,
        /// The write.
        write: Write,
    },
    /// The next operation for the executor thread.
    Exec(ExecOp),
    /// A report for the observer.
    Report(Report),
}

/// A worker's completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Write `seq` became durable, or failed and comes back to be retried.
    Persisted {
        /// Sequence number.
        seq: u64,
        /// Its result.
        result: Result<(), Write>,
    },
    /// The executor answered its operation.
    Exec(ExecDone),
    /// The serve thread finished its request.
    Served(Served),
}

/// The queues of an instance: diagnostics, and what the §13.5 conformance bounds (O-MEM).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Backlog {
    /// Effects held behind a pending record.
    pub held: usize,
    /// Block payload bytes of the held effects.
    pub held_bytes: u64,
    /// Held effects dropped by the bounds so far.
    pub held_dropped: u64,
    /// Released effects not handed out yet.
    pub released: usize,
    /// Writes queued or in flight.
    pub writes: usize,
    /// Safety records queued (not in flight).
    pub records: usize,
    /// Payload bytes of the queued bodies, per height.
    pub bodies: BTreeMap<u64, u64>,
    /// Executor operations queued other than `Execute`s.
    pub exec_ops: usize,
    /// `Execute` requests not answered yet.
    pub executes: usize,
    /// Serving requests pending.
    pub serve: usize,
    /// Serving requests dropped by the bounds so far.
    pub serve_dropped: u64,
    /// Messages queued in the ingress.
    pub ingress: usize,
    /// Messages dropped by the ingress bounds so far.
    pub ingress_dropped: u64,
}

/// What the kernel of an instance starts from.
pub struct KernelStart {
    /// Exact original instance resource pool shared by Core and workers.
    pub allocation_budget: iroha_allocation::AllocationBudget,
    /// Local parameters.
    pub local: LocalParams,
    /// Startup input (§7.4).
    pub init: Init,
    /// Configured signing keys.
    pub signers: Vec<Arc<dyn Signer>>,
    /// The core's crypto.
    pub crypto: Box<dyn Crypto>,
    /// The kernel's hashing (block hashes of stored and executed bodies).
    pub hasher: Box<dyn Crypto>,
    /// Local time of the start.
    pub now: Millis,
    /// The ingress queues (shared with the handle that fills them).
    pub ingress: Arc<Mutex<Ingress>>,
    /// Backoff, bounds and the transport limit (the ingress bounds are the queues').
    pub config: DriverConfig,
}

/// Queue a network message into the ingress, unless it is the node's own (O7) or for another
/// instance. Returns whether it was queued.
pub fn admit_message(
    ingress: &Mutex<Ingress>,
    own: &[PublicKey],
    instance: &Hash32,
    from: PublicKey,
    msg: WireMessage,
    class: TrafficClass,
) -> bool {
    if own.contains(&from) || msg.instance() != instance {
        return false;
    }
    ingress.lock().push(from, msg, class);
    true
}

/// O10: whether the configuration of `height` needs larger frames than the transport accepts.
pub fn frame_limit_exceeded(
    frame_limit: u64,
    height: u64,
    config: &HeightConfig,
) -> Option<FrameLimitExceeded> {
    let needed = u64::from(config.params.max_block_bytes) + u64::from(FRAME_OVERHEAD);
    (needed > frame_limit).then_some(FrameLimitExceeded {
        height,
        needed,
        limit: frame_limit,
    })
}

/// O10 examines every concrete config in an atomic publication; a pending authority has
/// no guessed parameters or committee to inspect.
fn applied_frame_limits(
    frame_limit: u64,
    height: u64,
    output: &AppliedConfig,
) -> [Option<FrameLimitExceeded>; 2] {
    match output {
        AppliedConfig::Continuation { after_next } => [
            after_next.ready().and_then(|config| {
                frame_limit_exceeded(frame_limit, height.saturating_add(2), config)
            }),
            None,
        ],
        AppliedConfig::Boundary { next, after_next } => [
            frame_limit_exceeded(frame_limit, height.saturating_add(1), next),
            frame_limit_exceeded(frame_limit, height.saturating_add(2), after_next),
        ],
    }
}

/// A startup refusal preserves its original configuration or finite-pool cause.
#[derive(Debug, thiserror::Error)]
pub enum KernelStartError {
    /// The consensus configuration or authenticated startup input is invalid.
    #[error("sumeragi configuration: {0}")]
    Config(#[from] ConfigError),
    /// The original instance pool refused the exact waiter control layout.
    #[error("sumeragi waiter admission: {0}")]
    Admission(#[from] iroha_allocation::AllocationRefusal),
    /// Construction of an already admitted waiter allocation failed locally.
    #[error("sumeragi waiter allocation: {0}")]
    Allocation(#[from] iroha_allocation::PrepaidSharedError),
    /// The fixed peer-slot backing could not be constructed from its original prepaid credit.
    #[error("sumeragi peer-slot backing: {0}")]
    Buffer(#[from] iroha_allocation::PrepaidBufferError),
}

/// The single-threaded, I/O-free heart of a driver instance.
pub struct Kernel {
    core: Core,
    hasher: Box<dyn Crypto>,
    instance: Hash32,
    own: Vec<PublicKey>,
    ingress: Arc<Mutex<Ingress>>,
    local: VecDeque<Event>,
    barrier: Barrier,
    persist: PersistQueue,
    exec: ExecSched,
    serve: ServeSched,
    out: VecDeque<Op>,
    frame_limit: u64,
    /// Local time of the latest call that told it.
    now: Millis,
    /// Prometheus telemetry of the instance (never read back by the kernel).
    metrics: Option<InstanceMetrics>,
}

impl Kernel {
    /// Start the core (§12.1) and route its start-up actions; returns the kernel and a copy of
    /// those actions (for observers).
    ///
    /// # Errors
    /// The core refused its input, or the original pool could not prepay the waiter.
    pub fn start(start: KernelStart) -> Result<(Self, Vec<Action>), KernelStartError> {
        let registrations = exec::ExecutionRegistrations::admit(&start.allocation_budget)?;
        let instance = start.init.instance;
        let own = start
            .init
            .records
            .iter()
            .map(|(k, _, _)| k.clone())
            .collect();
        let applied = start.init.tip.height;
        let config = start.config;
        let (core, actions) = Core::new(
            start.local,
            start.init,
            start.signers,
            start.crypto,
            start.allocation_budget,
            start.now,
        )?;
        let mut kernel = Self {
            core,
            hasher: start.hasher,
            instance,
            own,
            ingress: start.ingress,
            local: VecDeque::new(),
            barrier: Barrier::new(config.held),
            persist: PersistQueue::new(config.backoff),
            exec: ExecSched::new(applied, config.backoff, registrations),
            serve: ServeSched::new(config.serve),
            out: VecDeque::new(),
            frame_limit: config.frame_limit,
            now: start.now,
            metrics: None,
        };
        kernel.route(actions.clone());
        Ok((kernel, actions))
    }

    /// Record the instance's telemetry from now on: its routed actions, applied blocks and
    /// [`Kernel::observe`]d snapshots.
    pub fn attach_metrics(&mut self, metrics: InstanceMetrics) {
        self.metrics = Some(metrics);
    }

    /// A status snapshot and the queues of the same step, as the driver publishes them.
    pub fn observe(&mut self, status: &CoreStatus, backlog: &Backlog) {
        if let Some(metrics) = self.metrics.as_mut() {
            metrics.observe(status, backlog);
        }
    }

    /// The core (read-only).
    pub fn core(&self) -> &Core {
        &self.core
    }

    /// The execution scheduler (read-only).
    pub fn exec(&self) -> &ExecSched {
        &self.exec
    }

    /// Queue a network message (O6–O8); the node's own messages are dropped (O7).
    pub fn receive(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass) {
        admit_message(&self.ingress, &self.own, &self.instance, from, msg, class);
    }

    /// Queue a local event (never dropped, O6).
    pub fn deliver(&mut self, event: Event) {
        self.local.push_back(event);
    }

    /// An includable transaction arrived (the builder's `PayloadReady` source).
    pub fn transactions_available(&mut self) {
        self.exec.transactions_available();
        self.collect();
    }

    /// Whether an input is queued.
    pub fn has_input(&self) -> bool {
        !self.local.is_empty() || !self.ingress.lock().is_empty()
    }

    /// The next input at local time `now` (O5): the due `Tick`, then local events, then
    /// messages by class.
    pub fn next_input(&mut self, now: Millis) -> Option<Event> {
        self.now = now;
        if self.core.next_wakeup() <= now {
            return Some(Event::Tick);
        }
        if let Some(event) = self.local.pop_front() {
            return Some(event);
        }
        let (from, msg) = self.ingress.lock().pop()?;
        Some(Event::Message { from, msg })
    }

    /// Hand one input to the core and route its actions (O1).
    pub fn handle(&mut self, now: Millis, event: Event) {
        self.now = now;
        let actions = self.core.handle(now, event);
        self.route(actions);
    }

    /// [`Kernel::handle`] for hosts that also observe the core's actions (the simulator's
    /// oracles): returns a copy of them.
    pub fn handle_observed(&mut self, now: Millis, event: Event) -> Vec<Action> {
        self.now = now;
        let actions = self.core.handle(now, event);
        self.route(actions.clone());
        actions
    }

    /// Route the core's actions in order: writes to the persistence queue (a record raises the
    /// barrier; a newer record of a key supersedes its queued one), executor work to the
    /// scheduler, the rest through the barrier (O1, O2).
    pub fn route(&mut self, actions: Vec<Action>) {
        self.exec
            .retain_control_context(self.core.control_work_context());
        for action in actions {
            if let Some(metrics) = self.metrics.as_mut() {
                metrics.action(self.now, &action);
            }
            match action {
                Action::PersistSafety(record) => {
                    let (seq, superseded) = self.persist.push_record(record);
                    if let Some(old) = superseded {
                        self.barrier.superseded(old, seq);
                    }
                    self.barrier.persisting(seq);
                }
                Action::StoreBody { block } => {
                    // An applied height lives in the block store.
                    if block.header().height > self.exec.applied() {
                        self.persist.push(Write::Body(Box::new(block)));
                    }
                }
                Action::Execute {
                    block,
                    req,
                    certified,
                } => {
                    let block_hash = block.hash(&*self.hasher);
                    self.exec.execute(req, block_hash, block, certified);
                }
                Action::DiscardExecution { height, keep } => {
                    self.exec.discard(height, keep.clone());
                    // The same authorized lifetime ends obsolete proactive payload streams.
                    // Release their funded codewords before a subsequent Author allocates.
                    self.serve.push(
                        ServeRequest::Payload(Box::new(payload_worker::PayloadWork::Retain {
                            height,
                            keep,
                        })),
                        self.now,
                    );
                }
                Action::BuildControlWitness { req, context } => {
                    self.exec.build_control(req, context)
                }
                Action::DriveApplicationControl { context } => self.exec.drive_control(context),
                Action::ReceiveApplicationControl { from, message } => {
                    self.exec.receive_control(from, message)
                }
                Action::BuildPayload {
                    req,
                    height,
                    view,
                    max_bytes,
                    exec_budget_ms,
                } => self
                    .exec
                    .build(req, height, view, max_bytes, exec_budget_ms),
                Action::PayloadRejected {
                    height,
                    view,
                    block_hash,
                } => self.exec.reject(height, view, block_hash),
                Action::LocalFault(fault) => self.out.push_back(Op::Report(Report::Fault(fault))),
                gated => {
                    if let Some(effect) = self.barrier.admit(gated) {
                        self.effect(effect);
                    }
                }
            }
        }

        self.collect();
    }

    /// Carry out an effect the barrier let through.
    fn effect(&mut self, action: Action) {
        // Effects produced before recovery may still be held behind an O2 write. Do not
        // release their votes, proposals or publications after the terminal local failure.
        if matches!(
            self.exec.halted(),
            Some(HaltReason::PublicationRecoveryRequired { .. })
        ) && !matches!(
            &action,
            Action::ServeBlocks { .. }
                | Action::ServePayload { .. }
                | Action::ReportEvidence(_)
                | Action::Halt(_)
        ) {
            return;
        }
        match action {
            Action::Send { to, msg } => self.send(vec![to], msg),
            Action::Broadcast { to, msg } => self.send(to, msg),
            Action::CommitBlock { block, commit_qc } => self.exec.commit(block, commit_qc),
            Action::ReportEvidence(evidence) => {
                self.out.push_back(Op::Report(Report::Evidence(evidence)));
            }
            Action::Halt(reason) => self.out.push_back(Op::Report(Report::Halt(reason))),
            other => match ServeRequest::from_action(other) {
                Ok(request) => {
                    self.serve.push(request, self.now);
                }
                Err(other) => iroha_logger::error!(?other, "sumeragi action not routable"),
            },
        }
    }

    fn send(&mut self, to: Vec<PublicKey>, msg: WireMessage) {
        let to: Vec<PublicKey> = to.into_iter().filter(|k| !self.own.contains(k)).collect();
        if !to.is_empty() {
            self.out.push_back(Op::Send { to, msg });
        }
    }

    /// Take the scheduler's answers for the core; a committed configuration that outgrows the
    /// transport limit is reported (O10).
    fn collect(&mut self) {
        for event in self.exec.take_events() {
            if matches!(event, Event::PublicationRecoveryRequired { .. }) {
                // This completion stops the core synchronously, before a due Tick or another
                // poll can sign or dispatch anything. Already durable safety writes remain;
                // the halt report still obeys the existing persist-before-effect barrier.
                self.out
                    .retain(|op| !matches!(op, Op::Send { .. } | Op::Exec(_)));
                let actions = self.core.handle(self.now, event);
                self.route(actions);
                continue;
            }
            if let Event::BlockApplied { height, config, .. } = &event {
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.applied(self.now, *height);
                }
                for exceeded in applied_frame_limits(self.frame_limit, *height, config)
                    .into_iter()
                    .flatten()
                {
                    iroha_logger::error!(
                        ?exceeded,
                        "sumeragi configuration outgrows the transport"
                    );
                    self.out.push_back(Op::Report(Report::FrameLimit(exceeded)));
                }
            }
            self.local.push_back(event);
        }
    }

    /// A worker's completion at local time `now`.
    pub fn complete(&mut self, now: Millis, completion: Completion) {
        self.now = now;
        match completion {
            Completion::Persisted { seq, result } => match result {
                Ok(()) => {
                    let durable = self.persist.done(seq);
                    for effect in self.barrier.release(durable) {
                        self.effect(effect);
                    }
                }
                Err(write) => {
                    if let Some((old, newer)) = self.persist.failed(seq, write, now) {
                        self.barrier.superseded(old, newer);
                    }
                }
            },
            Completion::Exec(done) => {
                if let Some(height) = self.exec.done(now, done) {
                    self.persist.push(Write::Prune(height));
                    self.serve.push(
                        ServeRequest::Payload(Box::new(payload_worker::PayloadWork::Applied(
                            height,
                        ))),
                        now,
                    );
                }
            }
            Completion::Served(served) => {
                self.serve.done(now, &served);
                self.local.extend(served.events);
            }
        }
        self.collect();
    }

    /// The operations to start now: at most [`MAX_OPS_PER_POLL`] pending sends and reports,
    /// then at most one write, one executor operation and one serving request (each worker
    /// runs one at a time).
    pub fn poll(&mut self, now: Millis) -> Vec<Op> {
        self.now = now;
        let batch = self.out.len().min(MAX_OPS_PER_POLL);
        let mut ops: Vec<Op> = self.out.drain(..batch).collect();
        if let Some((seq, write)) = self.persist.next(now) {
            ops.push(Op::Persist { seq, write });
        }
        if let Some(op) = self.exec.next(now) {
            ops.push(Op::Exec(op));
        }
        if let Some(request) = self.serve.next(now) {
            ops.push(Op::Serve(request));
        }
        ops
    }

    /// Whether sends or reports wait for the next [`Kernel::poll`].
    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
    }

    /// The next local time the kernel needs to run: the core's deadline or a retry.
    pub fn next_wakeup(&self) -> Millis {
        self.core
            .next_wakeup()
            .min(self.persist.wakeup())
            .min(self.exec.wakeup())
            .min(self.serve.wakeup())
    }

    /// The effects held behind the O2 barrier, in order.
    pub fn held(&self) -> Vec<Action> {
        self.barrier.held().cloned().collect()
    }

    /// Messages dropped by the ingress bounds so far (O6).
    pub fn ingress_drops(&self) -> u64 {
        self.ingress.lock().dropped()
    }

    /// The queues of the instance.
    pub fn backlog(&self) -> Backlog {
        let (held, held_bytes) = self.barrier.size();
        let (ingress, ingress_dropped) = {
            let ingress = self.ingress.lock();
            (ingress.len(), ingress.dropped())
        };
        Backlog {
            held,
            held_bytes,
            held_dropped: self.barrier.dropped(),
            released: self.out.len(),
            writes: self.persist.len(),
            records: self.persist.queued_records(),
            bodies: self.persist.queued_bodies(),
            exec_ops: self.exec.queued_ops(),
            executes: self.exec.outstanding(),
            serve: self.serve.len(),
            serve_dropped: self.serve.dropped(),
            ingress,
            ingress_dropped,
        }
    }
}

/// A completed failure while assembling the exact committed startup prefix.
#[derive(Debug, thiserror::Error)]
pub enum StartupHistoryError {
    /// The original committed reader completed with an I/O or authentication error.
    #[error("committed startup history at height {height}: {source}")]
    Read {
        /// Exact committed height whose original read failed.
        height: u64,
        /// Original storage error; local resource refusal is carried separately as Deferred.
        #[source]
        source: std::io::Error,
    },
    /// The authoritative store reported no entry within its committed prefix.
    #[error("committed startup history is missing height {height}")]
    Missing {
        /// Exact missing committed height.
        height: u64,
    },
}

fn startup_entry(
    blocks: &(impl BlockStore + ?Sized),
    height: u64,
) -> Result<
    iroha_sumeragi::message::SyncEntry,
    crate::execution_attempt::ExecutionAttemptError<StartupHistoryError>,
> {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    blocks
        .entry(height)
        .map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC84")) {
                return Attempt::Rejected(StartupHistoryError::Read {
                    height,
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
                });
            }
            error.map_rejection(|source| StartupHistoryError::Read { height, source })
        })?
        .ok_or_else(|| Attempt::Rejected(StartupHistoryError::Missing { height }))
}

/// Assemble the core's startup input (§7.4 Restart) from the block store: the tip (the genesis
/// block's hash and result at `genesis_height`), the last `W + 2` committed headers, the
/// records found for every key, the configurations of `t`, `t + 1`, `t + 2` and a fresh nonce.
///
/// # Errors
/// Original local read refusal remains Deferred. A missing, corrupt or unreadable
/// committed entry retains its concrete failure and height as a completed error.
#[allow(clippy::too_many_arguments)] // the startup inputs of §7.4, each from its own source
pub fn assemble_init(
    blocks: &(impl BlockStore + ?Sized),
    instance: Hash32,
    genesis_height: u64,
    genesis: (Hash32, Hash32),
    demotion_window: u64,
    records: Vec<(PublicKey, RecordState, bool)>,
    configs: Vec<(u64, ConfigSlot)>,
    nonce: u64,
) -> Result<Init, crate::execution_attempt::ExecutionAttemptError<StartupHistoryError>> {
    let t = blocks.height().max(genesis_height);
    let tip = if t == genesis_height {
        CommittedTip {
            height: t,
            block_hash: genesis.0,
            result: genesis.1,
            header: None,
            commit_qc: None,
        }
    } else {
        let entry = startup_entry(blocks, t)?;
        CommittedTip {
            height: t,
            block_hash: entry.commit_qc.block_hash,
            result: entry.commit_qc.result,
            header: Some(entry.manifest.header),
            commit_qc: Some(entry.commit_qc),
        }
    };
    let first = t
        .saturating_sub(demotion_window.saturating_add(1))
        .max(genesis_height + 1);
    let mut recent_headers = Vec::new();
    for height in first..=t {
        let entry = startup_entry(blocks, height)?;
        recent_headers.push(entry.manifest.header);
    }
    Ok(Init {
        instance,
        records,
        genesis_height,
        demotion_window,
        nonce,
        tip,
        configs,
        recent_headers,
    })
}

/// Why a driver did not start.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The core refused its configuration or startup input.
    #[error("sumeragi configuration: {0}")]
    Config(ConfigError),
    /// Original instance resources cannot admit a required startup control.
    #[error("sumeragi startup admission: {0}")]
    Admission(#[from] iroha_allocation::AllocationRefusal),
    /// An admitted startup control could not be physically allocated.
    #[error("sumeragi startup allocation: {0}")]
    Allocation(#[from] iroha_allocation::PrepaidSharedError),
    /// The fixed peer-slot backing could not be constructed from its original prepaid credit.
    #[error("sumeragi peer-slot backing: {0}")]
    Buffer(#[from] iroha_allocation::PrepaidBufferError),
    /// Canonical storage failed; this storage owner cannot start another instance.
    #[error("sumeragi canonical storage is closed; restart is required")]
    StorageClosed,
    /// O10: the transport's frame limit is below what the chain parameters need.
    #[error("sumeragi frame limit {limit} is below the {needed} bytes the parameters need")]
    FrameLimit {
        /// Needed.
        needed: u64,
        /// Configured.
        limit: u64,
    },
    /// A thread could not be spawned.
    #[error("sumeragi driver thread: {0}")]
    Thread(#[from] std::io::Error),
}

impl From<KernelStartError> for DriverError {
    fn from(error: KernelStartError) -> Self {
        match error {
            KernelStartError::Config(error) => Self::Config(error),
            KernelStartError::Admission(error) => Self::Admission(error),
            KernelStartError::Allocation(error) => Self::Allocation(error),
            KernelStartError::Buffer(error) => Self::Buffer(error),
        }
    }
}

/// Configuration of one driver instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverConfig {
    /// Ingress bounds (O6, O8).
    pub ingress: IngressLimits,
    /// Retry backoff of failed writes and apply steps.
    pub backoff: Backoff,
    /// Bounds of the effects held behind a pending record (O6).
    pub held: HeldLimits,
    /// Per-peer serving limits (§12.2).
    pub serve: ServeLimits,
    /// Largest frame the transport accepts (O10); every frame is decoded within it.
    pub frame_limit: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            ingress: IngressLimits::default(),
            backoff: Backoff::default(),
            held: HeldLimits::default(),
            serve: ServeLimits::default(),
            // The chain-wide bound committed chain parameters are validated against: a
            // parameter change the chain accepts always fits this node's frames.
            frame_limit: iroha_data_model::sumeragi_finality::CHAIN_TRANSPORT_FRAME_LIMIT,
        }
    }
}

/// The cryptography of a driver instance, shared by its threads.
pub type SharedCrypto = Arc<dyn Crypto + Send + Sync>;

/// [`Crypto`] through a shared handle (the core and the kernel each hold a box).
struct CryptoRef(SharedCrypto);

impl Crypto for CryptoRef {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        self.0.hash_chunks(chunks)
    }
    fn hash(&self, bytes: &[u8]) -> Hash32 {
        self.0.hash(bytes)
    }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        self.0.verify(pk, msg, sig)
    }
    fn aggregate(&self, sigs: &[Signature]) -> AggregateSignature {
        self.0.aggregate(sigs)
    }
    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool {
        self.0.verify_aggregate(pks, msg, agg)
    }
    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        self.0.verify_aggregate_multi(groups, agg)
    }
}

/// What a driver instance starts with (all of it moves to its threads).
pub struct DriverStart {
    /// Node-wide storage gate; every production instance shares its Kura owner’s gate.
    pub node_gate: Arc<NodeGate>,
    /// Exact original State resource pool used to admit retained availability tables and rows.
    pub allocation_budget: iroha_allocation::AllocationBudget,
    /// Local parameters.
    pub local: LocalParams,
    /// Startup input ([`assemble_init`]).
    pub init: Init,
    /// Configured signing keys.
    pub signers: Vec<Arc<dyn Signer>>,
    /// Cryptography.
    pub crypto: SharedCrypto,
}

enum Input {
    Done(Completion),
    Transactions,
    /// A worker thread ended.
    Exited(Worker),
    Stop,
}

/// Every real input wakes the same original loop control after enqueueing.
#[derive(Clone)]
struct DriverInputs {
    sender: mpsc::Sender<Input>,
    wake: iroha_allocation::ChargedShared<ThreadWake>,
}

impl DriverInputs {
    fn send(&self, input: Input) -> Result<(), mpsc::SendError<Input>> {
        self.sender.send(input)?;
        self.wake.notify();
        Ok(())
    }
}

/// One original decoded frame awaiting its remaining semantic-byte admission.
/// Only this slot can retain an incompletely admitted frame; Core never observes it.
struct PendingMessage {
    from: PublicKey,
    message: WireMessage,
    /// Exact failure of this original owner, including partial byte admission.
    refusal: ByteAdmissionError,
    failures: u32,
    retry_at: Option<Millis>,
}

/// One reusable, prepaid waiter belongs to this instance's pending frame slot.
struct PendingAdmission {
    message: Option<PendingMessage>,
    registration: ReleaseRegistration,
    backoff: Backoff,
}

/// Only a genuine occupied original pool supplies a release-driven retry.
fn byte_admission_release(error: &ByteAdmissionError) -> Option<&ReleaseWait> {
    match error {
        ByteAdmissionError::Buffer(ChargedBufferError::Admission(
            AllocationRefusal::Capacity { release, .. },
        ))
        | ByteAdmissionError::ControlAdmission(AllocationRefusal::Capacity { release, .. }) => {
            Some(release)
        }
        _ => None,
    }
}

impl PendingAdmission {
    fn admit(
        budget: &iroha_allocation::AllocationBudget,
        backoff: Backoff,
    ) -> Result<Self, DriverError> {
        let mut reservation = budget.try_reserve(ReleaseRegistration::allocation_layout())?;
        let registration = ReleaseRegistration::from_reservation(&mut reservation)?;
        Ok(Self {
            message: None,
            registration,
            backoff,
        })
    }

    fn arm_source(&mut self, waker: &Waker) {
        self.registration.cancel();
        if let Some(release) = self
            .message
            .as_ref()
            .and_then(|pending| byte_admission_release(&pending.refusal))
            && self
                .registration
                .poll_wait(release, &mut Context::from_waker(waker))
                .is_ready()
        {
            // A release between failure and registration still reaches the same loop.
            waker.wake_by_ref();
        }
    }

    fn ready(&mut self, now: Millis, waker: &Waker) -> bool {
        let Some(pending) = self.message.as_mut() else {
            return false;
        };
        if let Some(release) = byte_admission_release(&pending.refusal) {
            #[cfg(all(test, sumeragi_core_mutation = "HC77"))]
            {
                let _ = (release, waker);
                return true;
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC77")))]
            return self
                .registration
                .poll_wait(release, &mut Context::from_waker(waker))
                .is_ready();
        }
        // A source-less refusal starts its first bounded delay at the loop's
        // actual clock observation, never at a fabricated transport timestamp.
        let due = pending
            .retry_at
            .get_or_insert_with(|| now.saturating_add(self.backoff.delay(pending.failures)));
        now >= *due
    }

    fn next_wakeup(&self) -> Millis {
        self.message.as_ref().map_or(Millis::MAX, |pending| {
            if byte_admission_release(&pending.refusal).is_some() {
                Millis::MAX
            } else {
                pending.retry_at.unwrap_or(0)
            }
        })
    }

    fn take(&mut self) -> Option<PendingMessage> {
        self.registration.cancel();
        self.message.take()
    }
}

impl Drop for PendingAdmission {
    fn drop(&mut self) {
        // Last-owner retirement also cancels before partial bytes can refund.
        self.registration.cancel();
    }
}

/// State shared between the event loop and the handles.
struct Shared {
    node_gate: Arc<NodeGate>,
    allocation_budget: iroha_allocation::AllocationBudget,
    pending_admission: Mutex<PendingAdmission>,
    instance: Hash32,
    own: Vec<PublicKey>,
    ingress: Arc<Mutex<Ingress>>,
    /// Decode limit of every frame: the transport's (O10).
    frame_limit: usize,
    status: Mutex<Option<CoreStatus>>,
    backlog: Mutex<Backlog>,
    wake: iroha_allocation::ChargedShared<ThreadWake>,
    /// One transaction notification remains pending through the completion drain.
    transactions_pending: AtomicBool,
    #[cfg(test)]
    empty_waiting: AtomicBool,
    #[cfg(test)]
    empty_epoch: std::sync::atomic::AtomicU64,
    /// The event loop runs.
    alive: AtomicBool,
    /// The thread whose end stopped the instance, if one did.
    stopped: Mutex<Option<Worker>>,
    /// The instance's telemetry series, flagged when a stopped thread stops the instance.
    metrics: Option<InstanceSeries>,
}

impl Shared {
    /// Retry only after this original failure's source releases or its source-less delay expires.
    fn retry_pending_message(&self, now: Millis) -> bool {
        self.allocation_budget
            .with_deferred_refund_notifications(|_| {
                let Some(mut slot) = self.pending_admission.try_lock() else {
                    return false;
                };
                let waker = self.wake.clone().into_waker();
                if !slot.ready(now, &waker) {
                    return false;
                }
                let pending = slot.message.as_mut().expect("ready original frame");
                if let Err(error) = pending.message.admit_owned_bytes(&self.allocation_budget) {
                    if error.is_local_refusal() {
                        pending.failures = pending.failures.saturating_add(1);
                        pending.refusal = error;
                        pending.retry_at = None;
                        // Cancel the previous source before arming this exact new one.
                        slot.arm_source(&waker);
                        // Set only the source-less deadline from the same observed clock.
                        let _ = slot.ready(now, &waker);
                    } else {
                        let rejected = slot.take();
                        drop(slot);
                        drop(rejected);
                    }
                    return false;
                }
                let pending = slot
                    .take()
                    .expect("the original pending frame remains installed");
                drop(slot);
                let class = pending.message.traffic_class();
                admit_message(
                    &self.ingress,
                    &self.own,
                    &self.instance,
                    pending.from,
                    pending.message,
                    class,
                )
            })
    }

    fn pending_message_wakeup(&self) -> Millis {
        self.pending_admission
            .try_lock()
            .map_or(Millis::MAX, |slot| slot.next_wakeup())
    }

    fn publish(&self, kernel: &mut Kernel) {
        #[cfg(test)]
        {
            let waiting = kernel
                .exec
                .waiting_empty_request_for_test()
                .is_some_and(|req| {
                    // Pending-ready is created while absorbing the worker completion. Do not
                    // observe it until its matching EMPTY answer has actually reached Core.
                    !kernel.local.iter().any(|event| {
                        matches!(event,
                    Event::PayloadBuilt { req: queued, payload: None } if *queued == req)
                    })
                });
            self.empty_waiting.store(waiting, Ordering::Release);
        }
        let status = kernel.core().status();
        let backlog = kernel.backlog();
        kernel.observe(&status, &backlog);
        *self.status.lock() = Some(status);
        *self.backlog.lock() = backlog;
    }
}

/// Run `f`, containing a panic (logged): an observer or transport call on the loop thread.
fn contained(what: &str, f: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        iroha_logger::error!(what, "sumeragi driver backend panicked");
    }
}

/// Record that the end of `worker` stopped the instance and tell the observer.
fn stop(shared: &Shared, observer: &dyn Observer, worker: Worker) {
    iroha_logger::error!(
        ?worker,
        "sumeragi driver thread stopped; the instance stops"
    );
    shared.stopped.lock().get_or_insert(worker);
    if let Some(series) = &shared.metrics {
        InstanceMetrics::stopped(series);
    }
    contained("observer", || observer.stopped(worker));
}

/// Tells the event loop that a worker thread ended, however it ended.
struct ExitGuard {
    worker: Worker,
    tx: DriverInputs,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(Input::Exited(self.worker));
    }
}

/// Marks the event loop stopped when its thread ends; a panic stops the instance.
struct LoopGuard {
    shared: Arc<Shared>,
    observer: Arc<dyn Observer>,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            stop(&self.shared, &*self.observer, Worker::Loop);
        } else {
            let orderly = self.shared.stopped.lock().is_none();
            if orderly {
                contained("observer", || self.observer.finished());
            }
        }
        self.shared.alive.store(false, Ordering::Release);
        // No partially admitted owner can outlive a stopped instance via a retained handle.
        self.shared
            .allocation_budget
            .with_deferred_refund_notifications(|_| {
                let abandoned = self.shared.pending_admission.lock().take();
                drop(abandoned);
                self.shared.ingress.lock().clear();
            });
    }
}

/// A cheap, cloneable handle of a running driver instance.
#[derive(Clone)]
pub struct DriverHandle {
    shared: Arc<Shared>,
    inputs: DriverInputs,
}

/// Queue admission retains the original input/wake allocation without retaining Worker,
/// State, Queue or the driver's physical joins. No callback allocation or bridge thread exists.
#[derive(Clone)]
pub(crate) struct QueueWake {
    shared: std::sync::Weak<Shared>,
    inputs: Option<DriverInputs>,
    budget: iroha_allocation::AllocationBudget,
}

impl QueueWake {
    pub(crate) fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }

    #[cfg(test)]
    pub(crate) fn is_live(&self) -> bool {
        self.budget.with_deferred_refund_notifications(|_| {
            let Some(shared) = self.shared.upgrade() else {
                return false;
            };
            let live = !shared.node_gate.is_closed() && shared.alive.load(Ordering::Acquire);
            drop(shared);
            live
        })
    }

    #[cfg(test)]
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        std::sync::Weak::ptr_eq(&self.shared, &other.shared)
    }

    pub(crate) fn notify(&self) {
        self.budget.with_deferred_refund_notifications(|_| {
            if let Some(shared) = self.shared.upgrade() {
                notify_transactions(&shared, self.inputs.as_ref().expect("original live inputs"));
                // A concurrent stop may make this the last original Shared reference.
                drop(shared);
            }
        });
    }
}

impl Drop for QueueWake {
    fn drop(&mut self) {
        let inputs = self.inputs.take();
        self.budget
            .with_deferred_refund_notifications(|_| drop(inputs));
    }
}

fn notify_transactions(shared: &Shared, inputs: &DriverInputs) {
    if shared.node_gate.is_closed() || !shared.alive.load(Ordering::Acquire) {
        return;
    }
    if !shared.transactions_pending.swap(true, Ordering::AcqRel) {
        let _ = inputs.send(Input::Transactions);
    }
}

impl DriverHandle {
    fn wake(&self) {
        self.shared.wake.notify();
    }

    /// Deliver an encoded frame from the authenticated peer `from` (never blocks; bounded,
    /// O6). The driver alone decodes, within the transport's frame limit (O10), which every
    /// committed configuration is validated against. Returns whether the message was queued.
    pub fn deliver(&self, from: &PublicKey, frame: &[u8]) -> bool {
        if self.shared.node_gate.is_closed() {
            return false;
        }
        match WireMessage::decode(frame, self.shared.frame_limit) {
            Ok(msg) => self.deliver_message(from.clone(), msg),
            Err(_) => false,
        }
    }

    /// Deliver a decoded message (in-process transports and tests).
    ///
    /// A local semantic-byte refusal may retain this original frame in the sole pending slot.
    /// True means retained for retry or queued; incomplete admission never reaches Core.
    /// A full slot refuses new unadmitted frames while already admitted/control traffic
    /// continues. Refusal is local backpressure, not evidence of invalid consensus data.
    pub fn deliver_message(&self, from: PublicKey, mut msg: WireMessage) -> bool {
        let shared = &self.shared;
        if shared.node_gate.is_closed()
            || !shared.alive.load(Ordering::Acquire)
            || msg.instance() != &shared.instance
            || shared.own.contains(&from)
        {
            return false;
        }
        // Admitted evictions may refund the pending frame's own finite pool.
        // Dispatch those callbacks only after both ingress mutexes are released.
        let deliver = || {
            let Some(mut pending) = shared.pending_admission.try_lock() else {
                return false;
            };
            // Serialize with final cleanup: a caller that passed the optimistic check
            // cannot leave a frame behind after the event loop's owners have retired.
            if shared.node_gate.is_closed() || !shared.alive.load(Ordering::Acquire) {
                return false;
            }
            if pending.message.is_some() && !msg.owned_bytes_admitted_to(&shared.allocation_budget)
            {
                return false;
            }
            if let Err(error) = msg.admit_owned_bytes(&shared.allocation_budget) {
                if !error.is_local_refusal() {
                    return false;
                }
                debug_assert!(
                    pending.message.is_none(),
                    "completed semantic bytes cannot require allocation"
                );
                pending.message = Some(PendingMessage {
                    from,
                    message: msg,
                    refusal: error,
                    failures: 1,
                    retry_at: None,
                });
                pending.arm_source(&shared.wake.clone().into_waker());
                drop(pending);
                self.wake();
                return true;
            }
            let class = msg.traffic_class();
            let queued = admit_message(
                &shared.ingress,
                &shared.own,
                &shared.instance,
                from,
                msg,
                class,
            );
            drop(pending);
            if queued {
                self.wake();
            }
            queued
        };
        #[cfg(all(test, sumeragi_core_mutation = "HC80"))]
        {
            deliver()
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC80")))]
        {
            shared
                .allocation_budget
                .with_deferred_refund_notifications(|_| deliver())
        }
    }

    /// Observe the real EMPTY wait after Core consumed the completion and startup admission.
    #[cfg(test)]
    pub(crate) fn waiting_after_empty_for_test(&self) -> bool {
        let before = self.shared.empty_epoch.load(Ordering::Acquire);
        before % 2 == 0
            && !self.shared.transactions_pending.load(Ordering::Acquire)
            && self.shared.empty_waiting.load(Ordering::Acquire)
            && !self.shared.transactions_pending.load(Ordering::Acquire)
            && self.shared.alive.load(Ordering::Acquire)
            && before == self.shared.empty_epoch.load(Ordering::Acquire)
    }

    /// An includable transaction arrived (`PayloadReady` after an `EMPTY` build).
    pub fn transactions_available(&self) {
        notify_transactions(&self.shared, &self.inputs);
    }

    /// Allocation-free weak admission binding to this exact driver's existing inputs.
    pub(crate) fn queue_wake(&self) -> QueueWake {
        QueueWake {
            shared: Arc::downgrade(&self.shared),
            inputs: Some(self.inputs.clone()),
            budget: self.shared.allocation_budget.clone(),
        }
    }

    /// The core's latest diagnostics (`None` before the core started).
    pub fn status(&self) -> Option<CoreStatus> {
        self.shared.status.lock().clone()
    }

    /// Why the instance halted, if it did: the core's reason, or `DriverAnomaly` when a
    /// stopped thread stopped the instance ([`DriverHandle::stopped`]).
    pub fn halted(&self) -> Option<HaltReason> {
        if self.shared.node_gate.is_closed() {
            return Some(HaltReason::DriverAnomaly);
        }
        self.status()
            .and_then(|s| s.halted)
            .or_else(|| self.stopped().map(|_| HaltReason::DriverAnomaly))
    }

    /// The thread whose end stopped the instance, if one did.
    pub fn stopped(&self) -> Option<Worker> {
        *self.shared.stopped.lock()
    }

    /// Whether the core started and has not halted, and the instance runs.
    pub fn ready(&self) -> bool {
        !self.shared.node_gate.is_closed()
            && self.shared.alive.load(Ordering::Acquire)
            && self.stopped().is_none()
            && self.status().is_some_and(|s| s.halted.is_none())
    }

    /// Messages dropped by the ingress bounds so far.
    pub fn ingress_drops(&self) -> u64 {
        self.shared.ingress.lock().dropped()
    }

    /// The instance's queues, as of the loop's latest step.
    pub fn backlog(&self) -> Backlog {
        self.shared.backlog.lock().clone()
    }
}

/// Owns the physical joins before any protocol worker can start. Retirement from
/// a worker callback hands off its handles without waiting on that same worker.
struct DriverJoiner {
    workers: mpsc::SyncSender<Vec<JoinHandle<()>>>,
    thread: JoinHandle<()>,
}

impl DriverJoiner {
    fn start() -> std::io::Result<Self> {
        let (workers, receive) = mpsc::sync_channel::<Vec<JoinHandle<()>>>(1);
        let thread = super::threads::sumeragi_thread_builder("sumeragi-join").spawn(move || {
            if let Ok(threads) = receive.recv() {
                for thread in threads {
                    let _ = thread.join();
                }
            }
        })?;
        Ok(Self { workers, thread })
    }

    fn finish(self, threads: Vec<JoinHandle<()>>, on_worker: bool) {
        let Self { workers, thread } = self;
        if let Err(mpsc::SendError(threads)) = workers.send(threads) {
            // The private receiver has no backend calls before this one handoff.
            // If it nevertheless stopped, never panic or self-join during unwind.
            iroha_logger::error!("sumeragi joining control stopped before receiving workers");
            if !on_worker {
                for thread in threads {
                    let _ = thread.join();
                }
            }
        }
        drop(workers);
        if !on_worker {
            let _ = thread.join();
        }
    }
}

/// A running driver instance: its handle and owned worker joins.
///
/// Dropping the owner requests shutdown even when delivery handles remain. A
/// caller outside the instance waits for every worker. A callback on an instance
/// worker transfers all physical joins to the prestarted joiner, allowing that
/// callback and the event loop to return before their threads can be joined.
pub struct RunningDriver {
    handle: DriverHandle,
    threads: Vec<JoinHandle<()>>,
    joiner: Option<DriverJoiner>,
}

impl RunningDriver {
    /// A handle for delivering messages and reading the status.
    pub fn handle(&self) -> DriverHandle {
        self.handle.clone()
    }

    /// Stop the event loop and wait for every thread of the instance.
    ///
    /// Called by an instance worker, shutdown transfers its joins to the original
    /// joining control instead of blocking the callback needed to finish them.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        let Some(joiner) = self.joiner.take() else {
            return;
        };
        let _ = self.handle.inputs.send(Input::Stop);
        let current = std::thread::current().id();
        let on_worker = self
            .threads
            .iter()
            .any(|thread| thread.thread().id() == current);
        joiner.finish(std::mem::take(&mut self.threads), on_worker);
    }
}

impl Drop for RunningDriver {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// The driver of one instance over its backends (§13.5): the transport `N`, the record store
/// `R`, the body store `B`, the block store `K`, the clock `C` and the executor `E`.
pub struct Driver<N, R, B, K, C, E> {
    /// Transport.
    pub net: Arc<N>,
    /// Safety records.
    pub records: Arc<R>,
    /// Block bodies.
    pub bodies: Arc<B>,
    /// Committed blocks.
    pub blocks: Arc<K>,
    /// Local clock.
    pub clock: Arc<C>,
    /// The application.
    pub executor: E,
    /// Reports.
    pub observer: Arc<dyn Observer>,
    /// Prometheus telemetry of the instance, if the node records it.
    pub metrics: Option<InstanceMetrics>,
}

impl<N, R, B, K, C, E> Driver<N, R, B, K, C, E>
where
    N: Net + 'static,
    R: RecordStore + 'static,
    B: BodyStore + 'static,
    K: BlockStore + 'static,
    C: Clock + 'static,
    E: Executor + 'static,
{
    /// A driver over these backends.
    pub fn new(
        net: Arc<N>,
        records: Arc<R>,
        bodies: Arc<B>,
        blocks: Arc<K>,
        clock: Arc<C>,
        executor: E,
        observer: Arc<dyn Observer>,
    ) -> Self {
        Self {
            net,
            records,
            bodies,
            blocks,
            clock,
            executor,
            observer,
            metrics: None,
        }
    }

    /// Record the instance's telemetry with `metrics` (`None`: telemetry is disabled).
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<InstanceMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Start the instance: checks the frame limit (O10), spawns the persistence, executor and
    /// serve threads and the event loop, which constructs the core (§12.1).
    ///
    /// # Errors
    /// An invalid configuration, a frame limit below the parameters' needs, or a thread that
    /// could not be spawned.
    #[allow(clippy::too_many_lines)] // one block per thread
    pub fn spawn(
        self,
        config: DriverConfig,
        start: DriverStart,
    ) -> Result<RunningDriver, DriverError> {
        check_frame_limit(&config, &start)?;
        if start.node_gate.is_closed() {
            return Err(DriverError::StorageClosed);
        }
        // Admit the original wake control before any worker can publish a completion.
        let wake = ThreadWake::admit(&start.allocation_budget)?;
        let pending_admission = PendingAdmission::admit(&start.allocation_budget, config.backoff)?;
        let instance = start.init.instance;
        let own: Vec<PublicKey> = start
            .init
            .records
            .iter()
            .map(|(k, _, _)| k.clone())
            .collect();
        let ingress = Arc::new(Mutex::new(Ingress::new(config.ingress)));
        let metrics = self.metrics;
        let shared = Arc::new(Shared {
            node_gate: Arc::clone(&start.node_gate),
            allocation_budget: start.allocation_budget.clone(),
            pending_admission: Mutex::new(pending_admission),
            instance,
            own,
            ingress: Arc::clone(&ingress),
            frame_limit: usize::try_from(config.frame_limit).unwrap_or(usize::MAX),
            status: Mutex::new(None),
            backlog: Mutex::new(Backlog::default()),
            wake: wake.clone(),
            transactions_pending: AtomicBool::new(false),
            #[cfg(test)]
            empty_waiting: AtomicBool::new(false),
            #[cfg(test)]
            empty_epoch: std::sync::atomic::AtomicU64::new(0),
            alive: AtomicBool::new(true),
            stopped: Mutex::new(None),
            metrics: metrics.as_ref().map(|metrics| metrics.series().clone()),
        });
        let net: Arc<dyn Net> = Arc::new(NodeNet {
            net: Arc::clone(&self.net),
            gate: Arc::clone(&shared.node_gate),
        });
        let (sender, rx) = mpsc::channel();
        let inputs = DriverInputs { sender, wake };
        // Create the joiner before any worker. Declaring this owner before the
        // worker channels also closes those channels before its Drop on a spawn
        // error, so partially started workers can be joined instead of detached.
        let mut running = RunningDriver {
            handle: DriverHandle {
                shared: Arc::clone(&shared),
                inputs: inputs.clone(),
            },
            threads: Vec::new(),
            joiner: Some(DriverJoiner::start()?),
        };
        let (persist_tx, persist_rx) = mpsc::channel::<(u64, Write)>();
        {
            let (records, bodies, crypto) = (
                self.records,
                Arc::clone(&self.bodies),
                Arc::clone(&start.crypto),
            );
            let tx = inputs.clone();
            let gate = Arc::clone(&shared.node_gate);
            running.threads.push(
                super::threads::sumeragi_thread_builder("sumeragi-persist").spawn(move || {
                    let _exit = ExitGuard {
                        worker: Worker::Persist,
                        tx: tx.clone(),
                    };
                    for (seq, write) in persist_rx {
                        let Some(_operation) = gate.enter() else {
                            break;
                        };
                        let result = persist::perform(&*records, &*bodies, &*crypto, write);
                        if tx
                            .send(Input::Done(Completion::Persisted { seq, result }))
                            .is_err()
                        {
                            break;
                        }
                    }
                })?,
            );
        }
        let (exec_tx, exec_rx) = mpsc::channel::<ExecOp>();
        {
            let (mut executor, blocks) = (self.executor, Arc::clone(&self.blocks));
            let tx = inputs.clone();
            let gate = Arc::clone(&shared.node_gate);
            running.threads.push(
                super::threads::sumeragi_thread_builder("sumeragi-exec").spawn(move || {
                    let _exit = ExitGuard {
                        worker: Worker::Exec,
                        tx: tx.clone(),
                    };
                    for op in exec_rx {
                        let Some(_operation) = gate.enter() else {
                            break;
                        };
                        let done = run_exec(&mut executor, &*blocks, op);
                        if tx.send(Input::Done(Completion::Exec(done))).is_err() {
                            break;
                        }
                    }
                })?,
            );
        }
        let (serve_tx, serve_rx) = mpsc::channel::<ServeRequest>();
        {
            let (bodies, blocks, net) = (self.bodies, self.blocks, Arc::clone(&net));
            let mut payloads = payload_worker::PayloadWorker::new(
                instance,
                start.allocation_budget.clone(),
                Arc::clone(&start.crypto),
                start.signers.clone(),
                config.serve.max_peers,
                start.init.tip.height,
            );
            let tx = inputs.clone();
            let gate = Arc::clone(&shared.node_gate);
            running.threads.push(
                super::threads::sumeragi_thread_builder("sumeragi-serve").spawn(move || {
                    let _exit = ExitGuard {
                        worker: Worker::Serve,
                        tx: tx.clone(),
                    };
                    for request in serve_rx {
                        let Some(_operation) = gate.enter() else {
                            break;
                        };
                        let served = catch_unwind(AssertUnwindSafe(|| {
                            serve::serve(request, instance, &*bodies, &*blocks, &*net, &mut payloads)
                        }))
                        .unwrap_or_else(|_| Err(std::io::Error::other("sumeragi serving panicked")));
                        let served = match served {
                            Ok(served) => served,
                            Err(error) => { iroha_logger::error!(%error, "sumeragi availability/storage worker failed"); break; }
                        };
                        if tx.send(Input::Done(Completion::Served(served))).is_err() {
                            break;
                        }
                    }
                })?,
            );
        }
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), DriverError>>(1);
        {
            let (clock, net, observer) = (self.clock, net, self.observer);
            let shared = Arc::clone(&shared);
            running.threads.push(
                super::threads::sumeragi_thread_builder("sumeragi-loop").spawn(move || {
                    shared.wake.bind_current();
                    let _guard = LoopGuard {
                        shared: Arc::clone(&shared),
                        observer: Arc::clone(&observer),
                    };
                    let workers = Workers {
                        node_gate: Arc::clone(&shared.node_gate),
                        net,
                        observer,
                        persist: persist_tx,
                        exec: exec_tx,
                        serve: serve_tx,
                    };
                    let Some(startup) = shared.node_gate.enter() else {
                        let _ = ready_tx.send(Err(DriverError::StorageClosed));
                        return;
                    };
                    let kernel = Kernel::start(KernelStart {
                        local: start.local,
                        init: start.init,
                        allocation_budget: start.allocation_budget,
                        signers: start.signers,
                        crypto: Box::new(CryptoRef(Arc::clone(&start.crypto))),
                        hasher: Box::new(CryptoRef(start.crypto)),
                        now: clock.now(),
                        ingress,
                        config,
                    });
                    drop(startup);
                    match kernel {
                        Ok((mut kernel, _)) => {
                            kernel
                                .exec
                                .bind_release_waker(shared.wake.clone().into_waker());
                            if let Some(metrics) = metrics {
                                kernel.attach_metrics(metrics);
                            }
                            shared.publish(&mut kernel);
                            let _ = ready_tx.send(Ok(()));
                            if let Err(worker) = run_loop(kernel, &rx, &shared, &*clock, &workers) {
                                stop(&shared, &*workers.observer, worker);
                            }
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.into()));
                        }
                    }
                })?,
            );
        }
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(running),
            Ok(Err(error)) => {
                running.shutdown();
                Err(error)
            }
            Err(_) => {
                running.shutdown();
                Err(DriverError::Config(ConfigError::InvalidInit(
                    "event loop died",
                )))
            }
        }
    }
}

/// O10 at start: the transport limit covers the blocks of every startup configuration and the
/// sync byte cap.
fn check_frame_limit(config: &DriverConfig, start: &DriverStart) -> Result<(), DriverError> {
    for (height, slot) in &start.init.configs {
        if let Some(height_config) = slot.ready()
            && let Some(exceeded) = frame_limit_exceeded(config.frame_limit, *height, height_config)
        {
            return Err(DriverError::FrameLimit {
                needed: exceeded.needed,
                limit: exceeded.limit,
            });
        }
    }
    let bulk = u64::from(start.local.sync_max_bytes) + u64::from(FRAME_OVERHEAD);
    if bulk > config.frame_limit {
        return Err(DriverError::FrameLimit {
            needed: bulk,
            limit: config.frame_limit,
        });
    }
    Ok(())
}

/// Run one executor operation (the executor thread); a panic of the executor or of the block
/// store becomes a local failure. Publication unwind requires recovery because the original
/// owner may be consumed or visible; ordinary execution and idempotent append remain retryable.
fn run_exec<E: Executor, K: BlockStore + ?Sized>(
    executor: &mut E,
    blocks: &K,
    op: ExecOp,
) -> ExecDone {
    let failed = |what: &str| format!("executor panicked in {what}");
    match op {
        // TODO: SC17 / spec §4.5: pass this flag into the production executor when CT1/CT5
        // wall-clock guards land. The current executor has no such guards; the scheduler
        // and conformance host retain the core's flag without inferring it from local state.
        ExecOp::Execute {
            block,
            block_hash,
            certified: _,
        } => ExecDone::Executed(
            catch_unwind(AssertUnwindSafe(|| executor.execute(&block, &block_hash)))
                .unwrap_or_else(|_| {
                    Some(iroha_sumeragi::api::ExecOutcome::Failed(failed("execute")))
                }),
        ),
        ExecOp::Discard { height, keep } => {
            let _ = catch_unwind(AssertUnwindSafe(|| executor.discard(height, &keep)));
            ExecDone::Discarded
        }
        ExecOp::Prepare(commit) => ExecDone::Prepared(
            catch_unwind(AssertUnwindSafe(|| {
                executor.prepare(&commit.block, &commit.qc)
            }))
            .unwrap_or_else(|_| Err(PublicationError::RecoveryRequired(failed("prepare")))),
        ),
        ExecOp::Append(commit) => {
            let appended = catch_unwind(AssertUnwindSafe(|| {
                blocks.append(&commit.block, &commit.qc)
            }))
            .unwrap_or_else(|_| Err(std::io::Error::other("block store panicked").into()));
            match appended {
                Ok(()) => ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
                Err(crate::execution_attempt::ExecutionAttemptError::Deferred(reason)) => {
                    ExecDone::Appended {
                        durable: false,
                        deferred: Some(reason),
                    }
                }
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(error)) => {
                    iroha_logger::warn!(%error, "sumeragi block store append failed; retrying");
                    ExecDone::Appended {
                        durable: false,
                        deferred: None,
                    }
                }
            }
        }
        ExecOp::Commit(commit) => {
            let committed = catch_unwind(AssertUnwindSafe(|| {
                executor.commit(&commit.block, &commit.qc).map(Box::new)
            }))
            .unwrap_or_else(|_| Err(PublicationError::RecoveryRequired(failed("commit"))));
            if committed.is_ok() {
                audit::block_applied(&commit.block, &commit.qc);
            }
            ExecDone::Committed(committed)
        }
        ExecOp::BuildControlWitness { context, .. } => ExecDone::ControlWitnessBuilt(
            catch_unwind(AssertUnwindSafe(|| {
                executor.build_control_witness(&context)
            }))
            .unwrap_or_else(|_| {
                Err(PublicationError::RecoveryRequired(failed(
                    "build control witness",
                )))
            }),
        ),
        ExecOp::DriveApplicationControl(context) => ExecDone::ApplicationControlDriven(
            catch_unwind(AssertUnwindSafe(|| executor.drive_control(&context))).unwrap_or_else(
                |_| {
                    Err(PublicationError::RecoveryRequired(failed(
                        "drive application control",
                    )))
                },
            ),
        ),
        ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        } => {
            let result = catch_unwind(AssertUnwindSafe(|| {
                executor.receive_application_control(&from, &message)
            }))
            .unwrap_or_else(|_| {
                Err(PublicationError::RecoveryRequired(failed(
                    "receive application control",
                )))
            });
            ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result,
            }
        }
        ExecOp::Build {
            height,
            view,
            max_bytes,
            exec_budget_ms,
            ..
        } => ExecDone::Built(
            catch_unwind(AssertUnwindSafe(|| {
                executor.build(height, view, max_bytes, exec_budget_ms)
            }))
            .unwrap_or_else(|_| Err(PublicationError::RecoveryRequired(failed("build payload")))),
        ),
        ExecOp::Reject {
            height,
            view,
            block_hash,
        } => {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                executor.reject(height, view, &block_hash)
            }));
            ExecDone::Rejected
        }
    }
}

/// Gate each physical send, including responses emitted inside a serving operation.
struct NodeNet<N> {
    net: Arc<N>,
    gate: Arc<NodeGate>,
}
impl<N: Net> Net for NodeNet<N> {
    fn send(&self, to: &PublicKey, frame: &Frame) -> SendOutcome {
        let Some(_send) = self.gate.enter() else {
            return SendOutcome::Closed;
        };
        gate_send(self.net.send(to, frame), &self.gate)
    }
}

/// A retained send obeys the same node gate as its first admission attempt.
struct GatedSend {
    pending: Box<dyn PendingSend>,
    gate: Arc<NodeGate>,
}

fn gate_send(outcome: SendOutcome, gate: &Arc<NodeGate>) -> SendOutcome {
    match outcome {
        SendOutcome::Backpressured(pending) => SendOutcome::Backpressured(Box::new(GatedSend {
            pending,
            gate: Arc::clone(gate),
        })),
        terminal => terminal,
    }
}

impl PendingSend for GatedSend {
    fn retry(self: Box<Self>) -> SendOutcome {
        let Self { pending, gate } = *self;
        let Some(_send) = gate.enter() else {
            return SendOutcome::Closed;
        };
        gate_send(pending.retry(), &gate)
    }
}

#[cfg(test)]
#[path = "delivery_gate_tests.rs"]
mod delivery_gate_tests;

/// Where the event loop sends operations.
struct Workers {
    node_gate: Arc<NodeGate>,
    net: Arc<dyn Net>,
    observer: Arc<dyn Observer>,
    persist: mpsc::Sender<(u64, Write)>,
    exec: mpsc::Sender<ExecOp>,
    serve: mpsc::Sender<ServeRequest>,
}

impl Workers {
    /// Start `ops`; a worker that cannot be reached stops the instance (returned).
    fn dispatch(&self, ops: Vec<Op>) -> Result<(), Worker> {
        for op in ops {
            let Some(_operation) = self.node_gate.enter() else {
                return Err(Worker::Loop);
            };
            match op {
                Op::Send { to, msg } => contained("transport", || {
                    if let Some(frame) = serve::frame(&msg) {
                        for peer in &to {
                            // Core owns bounded retransmission timers for these messages.
                            // Payload streams instead retain the original admission owner.
                            drop(self.net.send(peer, &frame));
                        }
                    }
                }),
                Op::Serve(request) => self.serve.send(request).map_err(|_| Worker::Serve)?,
                Op::Persist { seq, write } => self
                    .persist
                    .send((seq, write))
                    .map_err(|_| Worker::Persist)?,
                Op::Exec(op) => self.exec.send(op).map_err(|_| Worker::Exec)?,
                Op::Report(report) => contained("observer", || match &report {
                    Report::Evidence(evidence) => self.observer.evidence(evidence),
                    Report::Fault(fault) => self.observer.fault(fault),
                    Report::Halt(reason) => self.observer.halt(reason),
                    Report::FrameLimit(exceeded) => self.observer.frame_limit(exceeded),
                }),
            }
        }
        Ok(())
    }
}

/// The event loop (O5): absorb completions, start operations, handle the next input by
/// priority (a due `Tick` also between batches of released effects), publish the status, and
/// otherwise wait for an input or the next deadline. Returns on shutdown, or with the worker
/// whose end stops the instance (it ended, or cannot be reached).
fn run_loop(
    mut kernel: Kernel,
    rx: &mpsc::Receiver<Input>,
    shared: &Shared,
    clock: &dyn Clock,
    workers: &Workers,
) -> Result<(), Worker> {
    let absorb = |kernel: &mut Kernel,
                  input: Input,
                  received_transactions: &mut bool|
     -> Result<bool, Worker> {
        let Some(_operation) = shared.node_gate.enter() else {
            return Err(Worker::Loop);
        };
        match input {
            Input::Done(completion) => kernel.complete(clock.now(), completion),
            Input::Transactions => {
                #[cfg(test)]
                {
                    shared
                        .empty_epoch
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                            epoch.checked_add(1)
                        })
                        .expect("finite test EMPTY observation epoch");
                    shared.empty_waiting.store(false, Ordering::Release);
                }
                kernel.transactions_available();
                *received_transactions = true;
                #[cfg(test)]
                shared
                    .empty_epoch
                    .fetch_update(Ordering::Release, Ordering::Acquire, |epoch| {
                        epoch.checked_add(1)
                    })
                    .expect("finite test EMPTY observation epoch");
            }
            Input::Exited(worker) => return Err(worker),
            Input::Stop => return Ok(false),
        }
        Ok(true)
    };
    loop {
        // Consume the previous edge before draining inputs and polling release sources.
        shared.wake.take_pending();
        let mut received_transactions = false;
        loop {
            match rx.try_recv() {
                Ok(input) => {
                    if !absorb(&mut kernel, input, &mut received_transactions)? {
                        return Ok(());
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            }
        }
        if received_transactions {
            // Reopen before dispatch: an arrival during Build must survive its EMPTY result.
            shared.transactions_pending.store(false, Ordering::Release);
        }
        let operations = {
            let Some(_operation) = shared.node_gate.enter() else {
                return Err(Worker::Loop);
            };
            shared.retry_pending_message(clock.now());
            kernel.poll(clock.now())
        };
        workers.dispatch(operations)?;
        let Some(operation) = shared.node_gate.enter() else {
            return Err(Worker::Loop);
        };
        let now = clock.now();
        if let Some(event) = kernel.next_input(now) {
            kernel.handle(now, event);
            let operations = kernel.poll(clock.now());
            drop(operation);
            workers.dispatch(operations)?;
            shared.publish(&mut kernel);
            continue;
        }
        drop(operation);
        if kernel.has_output() {
            continue;
        }
        shared.publish(&mut kernel);
        let wait = kernel
            .next_wakeup()
            .min(shared.pending_message_wakeup())
            .saturating_sub(clock.now())
            .min(MAX_IDLE_WAIT_MS);
        // A producer between the last empty drain and this check leaves a latch.
        // A producer after it leaves an unpark token, including before park begins.
        if !shared.wake.take_pending() {
            std::thread::park_timeout(Duration::from_millis(wait));
        }
    }
}
