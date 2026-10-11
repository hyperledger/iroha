//! The host seam of the simulator (spec §13.5): the node program the world runs for each
//! replica, behind the [`Host`] trait.
//!
//! A host owns what a production driver owns between the hardware and the core: the ingress
//! queues with the O5 priorities and the O6/O8 bounds and classes, the consensus core itself,
//! and the O1/O2 persist-before-effect barrier. The world keeps everything else as fake
//! backends — network, clocks, the write device and record store with the installation log,
//! the body store, the block store with O3 apply, the O4 executor, the payload builder — and
//! assembles the `Init` of every (re)start from the durable stores.
//!
//! The default host, [`FakeHost`], is the simulator's fake driver. An external node
//! implementation (the production driver of `iroha_core`, run against the world as its
//! hardware) is another [`Host`], chosen per replica by [`Scenario::host`](super::Scenario).
//! Byzantine machines always run the fake driver: their strategies rewrite its actions.
//!
//! **Hosts that own their driver scheduling.** A host whose [`Host::owns_io`] is `true` also
//! schedules its own persistence (one ordered write queue with retries), execution (parking,
//! most-recent-first, exactly one answer per `Execute`), apply (`CommitBlock` in order, reusing
//! an execution in flight) and payload building. The world then no longer interprets the core's
//! actions (the oracles still observe them): it performs only the host's device operations
//! ([`Op`]) on the replica's fake backends — the write device (whose writes may fail, F27, and
//! are lost in a crash), the executor with its post-state cache, the block store, the builder,
//! the network and serving — and reports their completions ([`Done`]) back. `Init` assembly and
//! serving stay with the world.

use std::collections::BTreeMap;

use super::driver::{Barrier, Lanes};
use crate::{
    Core,
    api::{Action, Event, ExecOutcome, Init, LocalParams},
    availability::AvailableBody,
    crypto::{Crypto, Signer},
    message::{Qc, TrafficClass, WireMessage},
    safety::SafetyRecord,
    types::{AppliedConfig, Hash32, Millis, PublicKey},
};

/// A device operation of a host that owns its driver scheduling ([`Host::owns_io`]). `op` is
/// the host's id of the operation; its [`Done`] carries it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Durably write a safety record (the write may fail: nothing is written, F27).
    WriteRecord {
        /// Operation id.
        op: u64,
        /// The record.
        record: Box<SafetyRecord>,
    },
    /// Durably store a block body (may fail like a record write).
    WriteBody {
        /// Operation id.
        op: u64,
        /// The block.
        block: Box<AvailableBody>,
    },
    /// Execute a block on its parent's post-state (the applied state or a cached post-state).
    Execute {
        /// Operation id.
        op: u64,
        /// The block.
        block: Box<AvailableBody>,
        /// The core's `Execute.certified` flag: the application clock guard skips the block
        /// (§4.5).
        certified: bool,
    },
    /// Drop the cached post-states of the blocks at `height` other than `keep`.
    Discard {
        /// Operation id.
        op: u64,
        /// Height.
        height: u64,
        /// Blocks whose post-states are kept.
        keep: Vec<Hash32>,
    },
    /// The post-state of the next committed block: the cached one if its commitment is
    /// `qc.result`, otherwise by executing the block on the applied state (O3).
    Prepare {
        /// Operation id.
        op: u64,
        /// The committed block.
        block: Box<AvailableBody>,
        /// Its `CommitQC`.
        qc: Box<Qc>,
    },
    /// Durably append a committed block and its `CommitQC` to the block store (may fail).
    Append {
        /// Operation id.
        op: u64,
        /// The committed block.
        block: Box<AvailableBody>,
        /// Its `CommitQC`.
        qc: Box<Qc>,
    },
    /// Make the prepared post-state of the appended block the applied state.
    Commit {
        /// Operation id.
        op: u64,
        /// The committed block.
        block: Box<AvailableBody>,
        /// Its `CommitQC`.
        qc: Box<Qc>,
    },
    /// Build a payload; answered with `Event::PayloadBuilt{req}` through [`Host::deliver`] (and
    /// later `Event::PayloadReady{req}` if it was `EMPTY`).
    Build {
        /// Request id of the `BuildPayload`.
        req: u64,
        /// Size limit.
        max_bytes: u32,
        /// Execution budget hint.
        exec_budget_ms: u32,
    },
    /// Quarantine the transactions of a rejected block (no completion).
    Reject {
        /// `AvailableBody` hash.
        block_hash: Hash32,
    },
    /// An externally visible effect the host's barrier released — `Send`, `Broadcast`,
    /// `FetchBody`, `ServeBody`, `ServeBlocks` or `ReportEvidence` — performed (and served) as
    /// for the fake driver; a local body found by `FetchBody` arrives through
    /// [`Host::deliver`].
    Effect(Box<Action>),
}

/// The completion of an [`Op`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Done {
    /// A `WriteRecord`, `WriteBody` or `Append` completed: durable (`ok`) or failed (nothing
    /// was written).
    Written {
        /// Operation id.
        op: u64,
        /// Whether the write is durable.
        ok: bool,
    },
    /// An `Execute` completed; `None`: the parent's post-state is not held (nothing ran).
    Executed {
        /// Operation id.
        op: u64,
        /// The outcome.
        outcome: Option<ExecOutcome>,
    },
    /// A `Discard` completed.
    Discarded {
        /// Operation id.
        op: u64,
    },
    /// A `Prepare` completed with the local commitment of the block (`None`: not `Valid`).
    Prepared {
        /// Operation id.
        op: u64,
        /// The local commitment.
        result: Option<Hash32>,
    },
    /// A `Commit` completed: the block is applied.
    Committed {
        /// Operation id.
        op: u64,
        /// Configuration of `height + 2` scheduled by the state after the block.
        config: AppliedConfig,
    },
}

/// The queues of a host that owns its scheduling, for the O-MEM oracle (§13.2, §13.5): they
/// must stay within bounds that do not grow with time, however long a write keeps failing or
/// the executor stays busy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Backlog {
    /// Effects held behind a pending record (O2).
    pub held: usize,
    /// `AvailableBody` payload bytes of the held effects.
    pub held_bytes: u64,
    /// Safety records queued and not yet handed to the write device.
    pub records: usize,
    /// Payload bytes of the block bodies queued and not yet handed to the write device, per
    /// height.
    pub bodies: BTreeMap<u64, u64>,
    /// Executor operations queued other than `Execute`s (commits, discards, rejections, a
    /// build).
    pub exec_ops: usize,
    /// Serving requests queued.
    pub serve: usize,
}

/// The O-MEM bounds of a [`Backlog`]. None of them grows with time: held effects and
/// executor operations are capped, records are at most one queued per key (a newer record
/// supersedes a queued one), bodies are those of unapplied heights within the per-height
/// payload bound of §8.4, and serving keeps at most two requests per peer and the node's
/// own body fetches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BacklogBound {
    /// Held effects.
    pub held: usize,
    /// `AvailableBody` payload bytes of the held effects.
    pub held_bytes: u64,
    /// Queued safety records.
    pub records: usize,
    /// Lowest height a queued body may have (lower heights are applied and pruned).
    pub min_body_height: u64,
    /// Payload bytes of the queued bodies of one height.
    pub body_bytes_per_height: u64,
    /// Queued executor operations other than `Execute`s.
    pub exec_ops: usize,
    /// Queued serving requests.
    pub serve: usize,
}

impl BacklogBound {
    /// Held effects of a host.
    pub const HELD: usize = 4_096;
    /// `AvailableBody` payload bytes of a host's held effects.
    pub const HELD_BYTES: u64 = 64 << 20;
    /// Queued executor operations of a host other than `Execute`s.
    pub const EXEC_OPS: usize = 128;

    /// The bounds of a replica with `keys` keys among `peers` peers, applied up to `applied`,
    /// whose instance allows `per_height` payload bytes of bodies per height.
    pub fn new(keys: usize, peers: usize, applied: u64, per_height: u64) -> Self {
        Self {
            held: Self::HELD,
            held_bytes: Self::HELD_BYTES,
            records: keys.max(1),
            min_body_height: applied,
            body_bytes_per_height: per_height,
            exec_ops: Self::EXEC_OPS,
            serve: peers.saturating_mul(2).saturating_add(8),
        }
    }
}

impl Backlog {
    /// The first bound of `bound` this backlog exceeds, described (`None`: within them).
    pub fn exceeds(&self, bound: &BacklogBound) -> Option<String> {
        if self.held > bound.held || self.held_bytes > bound.held_bytes {
            return Some(format!(
                "{} held effects of {} payload bytes (bounds {}, {})",
                self.held, self.held_bytes, bound.held, bound.held_bytes
            ));
        }
        if self.records > bound.records {
            return Some(format!(
                "{} queued records for {} keys",
                self.records, bound.records
            ));
        }
        if let Some((height, bytes)) = self.bodies.iter().find(|(height, bytes)| {
            **height < bound.min_body_height || **bytes > bound.body_bytes_per_height
        }) {
            return Some(format!(
                "{bytes} queued body bytes at height {height} (applied {}, limit {})",
                bound.min_body_height, bound.body_bytes_per_height
            ));
        }
        if self.exec_ops > bound.exec_ops {
            return Some(format!("{} queued executor operations", self.exec_ops));
        }
        if self.serve > bound.serve {
            return Some(format!("{} queued serving requests", self.serve));
        }
        None
    }
}

/// What the world hands a host that (re)starts: the core's configuration and startup input
/// (§12.1), assembled by the world from the machine's durable stores, and the machine profile's
/// ingress mode.
pub struct Start {
    /// Local parameters (§12.4).
    pub local: LocalParams,
    /// Startup input built from the durable stores (§7.4).
    pub init: Init,
    /// The configured signing keys.
    pub signers: Vec<std::sync::Arc<dyn Signer>>,
    /// Crypto (counting, with provenance).
    pub crypto: Box<dyn Crypto>,
    /// Original pool shared by Core and its worker jobs.
    pub budget: iroha_allocation::AllocationBudget,
    /// Local time of the start.
    pub now: Millis,
    /// One FIFO for all ingress, ticks behind queued messages (the ML12 fault, F29 control).
    pub fifo_ingress: bool,
}

/// A node implementation hosted by the simulated world for one replica (§13.5). The world
/// calls it from its single-threaded scheduler; every method returns at once.
pub trait Host {
    /// Start (or restart after a crash) from `start`; returns the start-up actions, which the
    /// world executes like those of [`Host::handle`].
    ///
    /// # Errors
    /// The original configuration or resource error is retained for diagnosis.
    fn start(&mut self, start: Start) -> Result<Vec<Action>, Box<dyn std::error::Error>>;
    /// Crash: lose the core, every queued input and every held effect.
    fn crash(&mut self);
    /// Whether the node is running (started and not crashed).
    fn running(&self) -> bool;
    /// A network message arrived from the authenticated peer `from` (its O8 class attached).
    fn receive(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass);
    /// A local event arrived (executor, builder, block store, body store); never dropped (O6).
    fn deliver(&mut self, event: Event);
    /// Whether an input is queued.
    fn has_input(&self) -> bool;
    /// The next input to handle at local time `now`: the due `Tick` first (O5), then the queued
    /// inputs by priority. `None` if there is nothing to do.
    fn next_input(&mut self, now: Millis) -> Option<Event>;
    /// Handle one input; the world executes the returned actions in order (O1) through
    /// [`Host::persisting`] and [`Host::gate`].
    fn handle(&mut self, now: Millis, event: Event) -> Vec<Action>;
    /// Local time of the next wanted `Tick` (`Millis::MAX` for none).
    fn next_wakeup(&self) -> Millis;
    /// The `PersistSafety` of write `write` went to the write device (O2).
    fn persisting(&mut self, write: u64);
    /// An externally visible effect the node wants to take place: `Some` to perform it now,
    /// `None` if it is held behind a pending record (O2).
    fn gate(&mut self, effect: Action) -> Option<Action>;
    /// The writes up to `write` are durable: the held effects to perform now, in order.
    fn durable(&mut self, write: u64) -> Vec<Action>;
    /// The node's core, for the oracles' read-only observations.
    fn core(&self) -> Option<&Core>;
    /// The effects held behind the O2 barrier, in order (an observation for tests).
    fn held(&self) -> Vec<Action>;
    /// Messages dropped by the ingress bounds (O6).
    fn ingress_drops(&self) -> u64;
    /// Whether the host schedules its own persistence, execution, apply and building over the
    /// world's devices: the world then performs only its [`Op`]s and never calls
    /// [`Host::persisting`], [`Host::gate`] or [`Host::durable`]. Default: `false`.
    fn owns_io(&self) -> bool {
        false
    }
    /// For a host that owns its scheduling: the device operations to perform now, in order.
    /// The world asks after every input, completion and handled event, and when
    /// [`Host::next_wakeup`] (which then includes the host's own timers, e.g. a write retry)
    /// is due.
    fn poll(&mut self, _now: Millis) -> Vec<Op> {
        Vec::new()
    }
    /// For a host that owns its scheduling: a device operation completed at local time `now`.
    fn complete(&mut self, _now: Millis, _done: Done) {}
    /// For a host that owns its scheduling: its queues, bounded by the O-MEM oracle. Default:
    /// `None` (not observed).
    fn backlog(&self) -> Option<Backlog> {
        None
    }
}

/// Creates the host of a replica: `(machine, instance index)` → host.
pub type HostFactory = fn(usize, usize) -> Box<dyn Host>;

/// The default [`HostFactory`]: every replica runs a [`FakeHost`].
pub fn fake_host(_machine: usize, _instance: usize) -> Box<dyn Host> {
    Box::new(FakeHost::default())
}

/// The simulator's fake driver as a host: ingress [`Lanes`], the core and the O2 [`Barrier`].
#[derive(Default)]
pub struct FakeHost {
    core: Option<Core>,
    lanes: Lanes,
    barrier: Barrier,
}

impl Host for FakeHost {
    fn start(&mut self, start: Start) -> Result<Vec<Action>, Box<dyn std::error::Error>> {
        let (core, actions) = Core::new(
            start.local,
            start.init,
            start.signers,
            start.crypto,
            start.budget,
            start.now,
        )?;
        self.core = Some(core);
        self.lanes.fifo = start.fifo_ingress;
        Ok(actions)
    }

    fn crash(&mut self) {
        self.core = None;
        self.lanes.clear();
        self.barrier.clear();
    }

    fn running(&self) -> bool {
        self.core.is_some()
    }

    fn receive(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass) {
        self.lanes.push_message(from, msg, class);
    }

    fn deliver(&mut self, event: Event) {
        self.lanes.push_local(event);
    }

    fn has_input(&self) -> bool {
        !self.lanes.is_empty()
    }

    fn next_input(&mut self, now: Millis) -> Option<Event> {
        let core = self.core.as_ref()?;
        let tick_first = !self.lanes.fifo || self.lanes.is_empty();
        if core.next_wakeup() <= now && tick_first {
            return Some(Event::Tick);
        }
        self.lanes.pop()
    }

    fn handle(&mut self, now: Millis, event: Event) -> Vec<Action> {
        self.core
            .as_mut()
            .map_or_else(Vec::new, |core| core.handle(now, event))
    }

    fn next_wakeup(&self) -> Millis {
        self.core.as_ref().map_or(Millis::MAX, Core::next_wakeup)
    }

    fn persisting(&mut self, write: u64) {
        self.barrier.persisting(write);
    }

    fn gate(&mut self, effect: Action) -> Option<Action> {
        self.barrier.hold(effect)
    }

    fn durable(&mut self, write: u64) -> Vec<Action> {
        self.barrier.release(write)
    }

    fn core(&self) -> Option<&Core> {
        self.core.as_ref()
    }

    fn held(&self) -> Vec<Action> {
        self.barrier.held.iter().map(|(_, a)| a.clone()).collect()
    }

    fn ingress_drops(&self) -> u64 {
        self.lanes.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::HaltReason,
        message::{PayloadRequest, WireMessage},
        sim::{Scenario, World},
        types::Hash32,
    };

    /// The O-MEM bounds of a host's queues: each bound is checked, bodies of applied heights
    /// count as a violation, and the fake driver reports no backlog.
    #[test]
    fn backlog_bounds() {
        let bound = BacklogBound::new(1, 4, 10, 1_000);
        assert_eq!(bound.serve, 16);
        let ok = Backlog {
            held: 5,
            held_bytes: 100,
            records: 1,
            bodies: BTreeMap::from([(10, 1_000), (11, 0)]),
            exec_ops: 3,
            serve: 16,
        };
        assert_eq!(ok.exceeds(&bound), None);
        let over = [
            Backlog {
                held: BacklogBound::HELD + 1,
                ..ok.clone()
            },
            Backlog {
                held_bytes: BacklogBound::HELD_BYTES + 1,
                ..ok.clone()
            },
            Backlog {
                records: 2,
                ..ok.clone()
            },
            Backlog {
                bodies: BTreeMap::from([(9, 1)]),
                ..ok.clone()
            },
            Backlog {
                bodies: BTreeMap::from([(12, 1_001)]),
                ..ok.clone()
            },
            Backlog {
                exec_ops: BacklogBound::EXEC_OPS + 1,
                ..ok.clone()
            },
            Backlog {
                serve: 17,
                ..ok.clone()
            },
        ];
        for backlog in over {
            assert!(backlog.exceeds(&bound).is_some(), "{backlog:?}");
        }
        assert_eq!(FakeHost::default().backlog(), None);
    }

    /// The fake driver behind the seam: ingress priorities (a due `Tick` first, local events
    /// before messages), the O2 barrier and a crash that loses the core, the queues and the held
    /// effects.
    #[test]
    fn fake_host_ingress_barrier_and_crash() {
        let mut world = World::new(Scenario::base("host", 1, 4));
        let host = &mut world.replicas[0].host;
        assert!(host.running() && host.core().is_some());
        let wake = host.next_wakeup();
        assert!(wake < Millis::MAX);
        let key = PublicKey::new(vec![7; 32]).unwrap();
        let request = WireMessage::PayloadRequest(PayloadRequest {
            instance: Hash32::ZERO,
            height: 1,
            block_hash: Hash32::ZERO,
        });
        host.receive(key.clone(), request.clone(), TrafficClass::Control);
        host.deliver(Event::PayloadReady { req: 99 });
        assert!(host.has_input());
        assert_eq!(host.next_input(wake), Some(Event::Tick), "a due Tick first");
        host.handle(wake, Event::Tick);
        let now = wake;
        assert!(host.next_wakeup() > now, "the Tick consumed its deadline");
        assert_eq!(host.next_input(now), Some(Event::PayloadReady { req: 99 }));
        assert_eq!(
            host.next_input(now),
            Some(Event::Message {
                from: key,
                msg: request
            })
        );
        assert!(!host.has_input());
        assert_eq!(host.next_input(now), None);
        assert!(host.handle(now, Event::PayloadReady { req: 99 }).is_empty());
        // O2: effects wait for the pending record and leave in order once it is durable.
        let effect = Action::Halt(HaltReason::DriverAnomaly);
        assert!(host.gate(effect.clone()).is_some(), "no pending record");
        host.persisting(5);
        assert!(host.gate(effect.clone()).is_none());
        assert_eq!(host.held(), vec![effect.clone()]);
        assert!(host.durable(4).is_empty());
        assert_eq!(host.durable(5), vec![effect.clone()]);
        host.persisting(6);
        assert!(host.gate(effect).is_none());
        assert_eq!(host.ingress_drops(), 0);
        host.crash();
        assert!(!host.running() && host.core().is_none() && host.held().is_empty());
        assert_eq!(host.next_wakeup(), Millis::MAX);
        assert_eq!(host.next_input(Millis::MAX), None);
        assert!(host.handle(0, Event::Tick).is_empty());
    }

    /// What a [`Probe`] host shares with its test.
    #[derive(Default)]
    struct ProbeState {
        /// Operations to perform at the next poll.
        ops: Vec<Op>,
        /// Completions received.
        done: Vec<Done>,
        /// Local events received (builder answers).
        events: Vec<Event>,
    }

    /// A host that owns its scheduling and performs exactly the operations its test queues; its
    /// core runs, but none of its actions is performed.
    struct Probe {
        inner: FakeHost,
        state: std::rc::Rc<std::cell::RefCell<ProbeState>>,
    }

    impl Host for Probe {
        fn start(&mut self, start: Start) -> Result<Vec<Action>, Box<dyn std::error::Error>> {
            self.inner.start(start)
        }
        fn crash(&mut self) {
            self.inner.crash();
        }
        fn running(&self) -> bool {
            self.inner.running()
        }
        fn receive(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass) {
            self.inner.receive(from, msg, class);
        }
        fn deliver(&mut self, event: Event) {
            self.state.borrow_mut().events.push(event);
        }
        fn has_input(&self) -> bool {
            self.inner.has_input()
        }
        fn next_input(&mut self, now: Millis) -> Option<Event> {
            self.inner.next_input(now)
        }
        fn handle(&mut self, now: Millis, event: Event) -> Vec<Action> {
            self.inner.handle(now, event)
        }
        fn next_wakeup(&self) -> Millis {
            self.inner.next_wakeup()
        }
        fn persisting(&mut self, _write: u64) {
            unreachable!("the world never calls `persisting` on a host that owns its I/O")
        }
        fn gate(&mut self, _effect: Action) -> Option<Action> {
            unreachable!("the world never calls `gate` on a host that owns its I/O")
        }
        fn durable(&mut self, _write: u64) -> Vec<Action> {
            unreachable!("the world never calls `durable` on a host that owns its I/O")
        }
        fn core(&self) -> Option<&Core> {
            self.inner.core()
        }
        fn held(&self) -> Vec<Action> {
            Vec::new()
        }
        fn ingress_drops(&self) -> u64 {
            0
        }
        fn owns_io(&self) -> bool {
            true
        }
        fn poll(&mut self, _now: Millis) -> Vec<Op> {
            std::mem::take(&mut self.state.borrow_mut().ops)
        }
        fn complete(&mut self, _now: Millis, done: Done) {
            self.state.borrow_mut().done.push(done);
        }
    }

    /// §13.5 seam for a host that owns its scheduling: every device operation is performed on
    /// the replica's fake backends and completed exactly once — durable writes (and failed ones,
    /// which store nothing), executions with and without the parent post-state, discards, the
    /// three apply steps, the builder and network effects — and a crash loses the operations in
    /// flight. The world never interprets such a host's core actions.
    #[test]
    #[allow(clippy::too_many_lines)] // one scripted walk through every device operation
    fn owned_host_ops_and_completions() {
        use crate::{
            message::{BlockHeader, Qc, VoteKind},
            preimage::payload_hash,
            safety::SafetyRecord,
            sim::{crypto::SimCrypto, driver::reference_exec},
            types::{AggregateSignature, Bitmap, SIGNATURE_LEN},
        };
        let mut sc = Scenario::base("owned", 1, 4);
        sc.checks.liveness = false;
        sc.checks.progress = 0;
        let mut world = World::new(sc);
        let state = std::rc::Rc::new(std::cell::RefCell::new(ProbeState::default()));
        world.crash(0);
        world.replicas[0].host = Box::new(Probe {
            inner: FakeHost::default(),
            state: std::rc::Rc::clone(&state),
        });
        world.restart(0);
        assert!(world.replicas[0].host.owns_io());
        let inst = world.instances[0].clone();
        let key = world.replicas[0].keys[0].clone();
        let crypto = SimCrypto::new();
        let payload = super::super::driver::encode_tx(1, false, 0);
        let budget = world.replicas[0].budget.clone();
        let signer = super::super::crypto::SimSigner::new(
            inst.committee(1).get(0).unwrap().clone(),
            None,
            std::sync::Arc::clone(&world.log),
        );
        let block_at = |height: u64, parent: Hash32, parent_result: Hash32| {
            crate::testing::author_body(
                BlockHeader {
                    control_witness: crate::types::ControlWitness::empty(),
                    epoch: crate::testing::TEST_EPOCH.id,
                    instance: inst.id,
                    height,
                    origin_view: 0,
                    parent_hash: parent,
                    parent_result,
                    payload_hash: payload_hash(&crypto, &payload),
                    availability_digest: crate::types::Hash32::ZERO,
                    payload_len: u32::try_from(payload.len()).unwrap(),
                    proposer: 0,
                    skipped_leaders: Vec::new(),
                },
                &payload,
                &inst.config(height),
                &budget,
                &crypto,
                &signer,
            )
        };
        let b1 = block_at(1, inst.genesis_hash, inst.genesis_result);
        let bh1 = b1.hash(&crypto);
        let ExecOutcome::Valid(r1) = reference_exec(&inst.genesis_result, &payload) else {
            unreachable!("ordinary setup transaction is valid")
        };
        let orphan = block_at(2, Hash32([9; 32]), Hash32([9; 32]));
        let qc = Qc {
            epoch: crate::testing::TEST_EPOCH.id,
            kind: VoteKind::Commit,
            instance: inst.id,
            height: 1,
            view: 0,
            block_hash: bh1,
            result: r1,
            signers: Bitmap::new(4),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        };
        let step = |world: &mut World, ops: Vec<Op>, until: Millis| {
            state.borrow_mut().ops = ops;
            world.run_until(until);
            assert!(world.failure.is_none(), "{:?}", world.failure);
            let mut s = state.borrow_mut();
            (std::mem::take(&mut s.done), std::mem::take(&mut s.events))
        };
        // Writes and executions.
        let record =
            SafetyRecord::fresh(inst.id, crate::testing::TEST_EPOCH.id, key.clone(), 5, None);
        let (done, _) = step(
            &mut world,
            vec![
                Op::WriteRecord {
                    op: 1,
                    record: Box::new(record.clone()),
                },
                Op::WriteBody {
                    op: 2,
                    block: Box::new(b1.clone()),
                },
                Op::Execute {
                    op: 3,
                    block: Box::new(b1.clone()),
                    certified: false,
                },
                Op::Execute {
                    op: 4,
                    block: Box::new(orphan),
                    certified: false,
                },
            ],
            500,
        );
        assert!(
            done.contains(&Done::Written { op: 1, ok: true }),
            "{done:?}"
        );
        assert!(done.contains(&Done::Written { op: 2, ok: true }));
        assert!(done.contains(&Done::Executed {
            op: 3,
            outcome: Some(ExecOutcome::Valid(r1))
        }));
        assert!(done.contains(&Done::Executed {
            op: 4,
            outcome: None
        }));
        assert_eq!(done.len(), 4, "each operation completes once");
        let rep = &world.replicas[0];
        assert_eq!(rep.records.get(&key).map(|d| &d.record), Some(&record));
        assert!(rep.bodies.contains_key(&bh1));
        assert_eq!(rep.exec.cache.get(&bh1), Some(&(1, r1)));
        // A discard drops the post-state; Prepare then executes the block again.
        let (done, _) = step(
            &mut world,
            vec![
                Op::Discard {
                    op: 5,
                    height: 1,
                    keep: Vec::new(),
                },
                Op::Prepare {
                    op: 6,
                    block: Box::new(b1.clone()),
                    qc: Box::new(qc.clone()),
                },
            ],
            1_000,
        );
        assert_eq!(
            done,
            vec![
                Done::Discarded { op: 5 },
                Done::Prepared {
                    op: 6,
                    result: Some(r1)
                }
            ]
        );
        assert!(!world.replicas[0].exec.cache.contains_key(&bh1));
        // Apply: append, then commit; the builder answers through `deliver`.
        let (done, events) = step(
            &mut world,
            vec![
                Op::Append {
                    op: 7,
                    block: Box::new(b1.clone()),
                    qc: Box::new(qc.clone()),
                },
                Op::Commit {
                    op: 8,
                    block: Box::new(b1.clone()),
                    qc: Box::new(qc.clone()),
                },
                Op::Build {
                    req: 9,
                    max_bytes: 1024,
                    exec_budget_ms: 100,
                },
                Op::Reject { block_hash: bh1 },
            ],
            1_500,
        );
        assert_eq!(done.len(), 2, "{done:?}");
        assert!(done.contains(&Done::Written { op: 7, ok: true }));
        assert!(done.iter().any(|d| matches!(
            d,
            Done::Committed { op: 8, config } if *config == inst.applied_config(1)
        )));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::PayloadBuilt { req: 9, .. }))
        );
        let rep = &world.replicas[0];
        assert_eq!(rep.store.len(), 1);
        assert_eq!(rep.applied, (1, bh1, r1));
        assert!(rep.bodies.is_empty(), "applied bodies are pruned");
        // A failing device reports the failure and stores nothing.
        world.machines[0].profile.write_fail_ppm = 1_000_000;
        let later =
            SafetyRecord::fresh(inst.id, crate::testing::TEST_EPOCH.id, key.clone(), 9, None);
        let (done, _) = step(
            &mut world,
            vec![Op::WriteRecord {
                op: 10,
                record: Box::new(later),
            }],
            2_000,
        );
        assert_eq!(done, vec![Done::Written { op: 10, ok: false }]);
        assert_eq!(
            world.replicas[0].records.get(&key).map(|d| d.record.height),
            Some(5)
        );
        // A crash loses the operations in flight.
        world.machines[0].profile.write_fail_ppm = 0;
        world.machines[0].profile.write_min = 400;
        world.machines[0].profile.write_max = 400;
        state.borrow_mut().ops = vec![Op::WriteBody {
            op: 11,
            block: Box::new(b1.clone()),
        }];
        world.run_until(2_100);
        world.crash(0);
        world.run_until(3_000);
        assert!(state.borrow().done.is_empty(), "{:?}", state.borrow().done);
        assert!(world.replicas[0].bodies.is_empty());
        // An effect is performed as for the fake driver (a request to machine 1). The synthetic
        // block (its CommitQC has no signers) must not become the restarted core's tip.
        world.replicas[0].store.clear();
        world.restart(0);
        let packets = world.stats.packets[0];
        let to = world.replicas[1].keys[0].clone();
        let msg = WireMessage::PayloadRequest(PayloadRequest {
            instance: inst.id,
            height: 1,
            block_hash: bh1,
        });
        step(
            &mut world,
            vec![Op::Effect(Box::new(Action::Send { to, msg }))],
            3_100,
        );
        assert!(world.stats.packets[0] > packets);
        // The application may hold a single live overlay: an executor operation between a
        // prepare and its commit drops the prepared post-state, and that commit fails the run.
        step(
            &mut world,
            vec![
                Op::Prepare {
                    op: 12,
                    block: Box::new(b1.clone()),
                    qc: Box::new(qc.clone()),
                },
                Op::Execute {
                    op: 13,
                    block: Box::new(b1.clone()),
                    certified: false,
                },
            ],
            3_500,
        );
        state.borrow_mut().ops = vec![Op::Commit {
            op: 14,
            block: Box::new(b1),
            qc: Box::new(qc),
        }];
        world.run_until(4_000);
        let failure = world.failure.clone().unwrap_or_default();
        assert!(failure.contains("prepared post-state"), "{failure}");
    }

    /// A host that refuses its configuration reports the error.
    #[test]
    fn fake_host_start_errors() {
        let world = World::new(Scenario::base("host", 1, 4));
        let mut init = world.init_for(0);
        init.demotion_window = 0;
        let start = Start {
            local: world.instances[0].local,
            init,
            signers: Vec::new(),
            crypto: Box::new(world.replicas[0].crypto.clone()),
            now: 0,
            budget: world.replicas[0].budget.clone(),
            fifo_ingress: false,
        };
        let mut host = FakeHost::default();
        let error = host.start(start).unwrap_err();
        assert!(
            error.downcast_ref::<crate::api::ConfigError>().is_some(),
            "the original configuration error remains typed"
        );
        assert!(!host.running());
        assert!(
            fake_host(0, 0).core().is_none(),
            "a new host is not running"
        );
    }
}
