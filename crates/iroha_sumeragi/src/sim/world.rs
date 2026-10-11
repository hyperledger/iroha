//! The simulated world (§13.1): instances, machines and their replicas (one core per machine
//! and instance), a single-threaded discrete-event scheduler in virtual milliseconds, and the
//! fake driver that executes each core's actions under the §12.3 guarantees.
//!
//! Scheduling: arrivals (network deliveries, write completions, executor and builder answers,
//! scripted faults) enter a global time-ordered queue. When a replica is idle it handles, in
//! O5 priority, a due `Tick`, then local events, then control, proposal and bulk messages. A
//! handled event costs virtual CPU time (per pairing counted by the crypto wrapper), during
//! which the replica is busy; its actions take effect at the end of that time.

mod clock_guard;
mod progress;
mod seed_config;
mod storage;
mod transport;

pub use clock_guard::{CertifiedTime, GuardEvent, GuardRule, GuardState};
pub use transport::SharedWire;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    rc::Rc,
};

use super::{
    byz::Adversary,
    crypto::{SharedLog, SimCrypto, SimSigner},
    driver::{Clock, Executor, Io, OwnedWrite, Write, decode_txs, divergent_exec},
    host::{Done, Host, Op, Start, fake_host},
    net::{Fate, NetConfig, Nic, Packet, approx_size, class_of, lane},
    oracle::Oracle,
    records::{KeyStore, StoreId},
    rng::{Rng, seed_of},
    scenario::{Checks, Churn, CrashPoint, Fault, IoKill, Profile, Scenario, Workload},
};
use crate::{
    api::{Action, CommittedTip, Event, ExecOutcome, HaltReason, Init, LocalParams},
    availability::AvailableBody,
    crypto::Signer,
    message::{
        PayloadChunk, PayloadManifest, PayloadRequest, Qc, SyncEntry, SyncResponse, WireMessage,
    },
    safety::{RecordState, SafetyRecord},
    testing::sha256,
    types::{ChainParams, Committee, Hash32, HeightConfig, Millis, PublicKey},
};

/// A consensus instance of the world (§1.8) with its committee schedule (§10).
#[derive(Clone, Debug)]
pub struct Inst {
    /// Instance id `I`.
    pub id: Hash32,
    /// Genesis block hash.
    pub genesis_hash: Hash32,
    /// Genesis result.
    pub genesis_result: Hash32,
    /// `(from height, committee)`, ascending, first entry from height 0.
    pub schedule: Vec<(u64, Committee)>,
    /// Chain parameters.
    pub params: ChainParams,
    /// Demotion window `W` (genesis constant).
    pub window: u64,
    /// Local parameters of every node.
    pub local: LocalParams,
}

impl Inst {
    /// `C_h`.
    pub fn committee(&self, height: u64) -> &Committee {
        let mut out = None;
        for (from, committee) in &self.schedule {
            if *from <= height || out.is_none() {
                out = Some(committee);
            }
        }
        out.unwrap_or_else(|| unreachable!("a schedule has at least one committee"))
    }

    /// The scheduled epoch of `height`, without constructing an owned committee.
    ///
    /// # Panics
    /// Panics if the instance's committee schedule is empty.
    pub fn epoch(&self, height: u64) -> crate::types::EpochConfig {
        let index = self
            .schedule
            .iter()
            .rposition(|(from, _)| *from <= height)
            .unwrap_or(0);
        let first = self.schedule[index].0;
        let last = self
            .schedule
            .get(index + 1)
            .map_or(u64::MAX, |(from, _)| from - 1);
        crate::testing::scheduled_epoch(index as u64, first, last)
    }

    /// The height configuration of `height`.
    pub fn config(&self, height: u64) -> HeightConfig {
        HeightConfig {
            epoch: Box::new(self.epoch(height)),
            committee: self.committee(height).clone(),
            params: self.params,
        }
    }
    /// Exact atomic original-application schedule outcome.
    pub fn applied_config(&self, height: u64) -> crate::types::AppliedConfig {
        crate::testing::applied_config(
            height,
            &self.config(height),
            self.config(height + 1),
            self.config(height + 2),
        )
    }
}

/// A simulated machine: a clock, resources, and one replica per instance it takes part in.
#[derive(Clone, Debug)]
pub struct Machine {
    /// Running (not crashed).
    pub up: bool,
    /// Incarnation counter; events of an older incarnation are lost.
    pub epoch: u64,
    /// Local clock.
    pub clock: Clock,
    /// Runs a Byzantine strategy.
    pub byz: bool,
    /// Replica index per instance (`None` if not a participant).
    pub replicas: Vec<Option<usize>>,
    /// Resources.
    pub profile: Profile,
    /// Time of the latest (re)start.
    pub started_at: Millis,
    /// Crashes so far.
    pub crashes: u32,
    /// Keys by slot.
    pub keys: Vec<PublicKey>,
    /// Key store with the installation log (§7.4 record provenance).
    pub keystore: KeyStore,
    /// The store-id file next to the record files (`None`: missing).
    pub store_id: Option<StoreId>,
    /// A backup of the key store (restored by `Fault::RestoreKeyStore`).
    pub snapshot: Option<KeyStore>,
    /// Keys no longer configured for signing (retired, §7.4 Keys).
    pub retired: BTreeSet<PublicKey>,
}

/// A durable safety record.
#[derive(Clone, Debug)]
pub struct Durable {
    /// The record.
    pub record: SafetyRecord,
    /// Its encoding.
    pub bytes: Vec<u8>,
}

/// One core instance on one machine with its fake driver state.
pub struct Replica {
    /// Machine.
    pub machine: usize,
    /// Instance index.
    pub inst: usize,
    /// Configured signing keys.
    pub keys: Vec<PublicKey>,
    /// The hosted node: ingress, core and O2 barrier (§13.5); the fake driver by default.
    pub host: Box<dyn Host>,
    /// Counting crypto shared with the core.
    pub crypto: SimCrypto,
    /// Original pool and live actual reconstruction jobs of this incarnation.
    pub budget: iroha_allocation::AllocationBudget,
    acquisitions: BTreeMap<Hash32, crate::availability::PayloadAcquisition>,
    /// Durable safety-record files of this instance per key (part of the machine's record
    /// store; never backed up or restored).
    pub records: BTreeMap<PublicKey, Durable>,
    /// Durable body store.
    pub bodies: BTreeMap<Hash32, AvailableBody>,
    /// Durable block store (Kura), consecutive heights from `g + 1`.
    pub store: Vec<(AvailableBody, Qc)>,
    /// Busy until (virtual CPU).
    pub busy_until: Millis,
    cpu_carry_us: u64,
    /// Write device and O2 barrier.
    pub io: Io,
    /// Executor.
    pub exec: Executor,
    /// Egress NIC: packets carry `(target replica, message)`.
    pub nic: Nic<(usize, Rc<SharedWire>)>,
    /// Transaction queue of the payload builder.
    pub txs: BTreeMap<u64, Vec<u8>>,
    /// Quarantined transactions.
    pub quarantine: BTreeSet<u64>,
    /// Applied state: `(height, block hash, result)`.
    pub applied: (u64, Hash32, Hash32),
    /// Current round height of the core (cached after every event).
    pub height: u64,
    /// Halt reason reported by the core.
    pub halted: Option<HaltReason>,
    /// Last record persisted per key (to classify crash points).
    last_persisted: BTreeMap<PublicKey, SafetyRecord>,
    /// Largest `Tick` lateness observed (local ms).
    pub max_tick_late: Millis,
    /// `(next_wakeup, local time it was first reported)`.
    wake_mark: (Millis, Millis),
    /// The builder's latest `BuildPayload` answered `EMPTY` whose `PayloadReady{req}` is still
    /// owed (at most once per request, §12.2).
    pub pending_ready: Option<u64>,
}

/// Time-ordered events of the scheduler.
enum Ev {
    Arrive {
        r: usize,
        from: PublicKey,
        msg: Rc<SharedWire>,
    },
    Local {
        r: usize,
        epoch: u64,
        event: Box<Event>,
    },
    IoDone {
        r: usize,
        epoch: u64,
        id: u64,
    },
    ExecDone {
        r: usize,
        epoch: u64,
        job: u64,
    },
    /// A device operation of a host that owns its scheduling completed.
    Done {
        r: usize,
        epoch: u64,
        done: Box<Done>,
    },
    /// An owned `Execute` finished: the post-state is cached, then the host learns it.
    OwnedExec {
        r: usize,
        epoch: u64,
        op: u64,
        bh: Hash32,
        height: u64,
        outcome: ExecOutcome,
    },
    NicFree {
        r: usize,
        epoch: u64,
    },
    Script(usize),
    Restart(usize),
    TxGen(usize),
    AmxTick,
    ByzTick(usize),
    Evict(usize),
}

/// A compact trace entry (formatted only on failure).
#[derive(Clone, Debug)]
pub struct TraceEntry {
    /// Global time.
    pub t: Millis,
    /// Replica (or machine for crash/restart).
    pub who: usize,
    /// What happened.
    pub what: String,
}

/// Counters of a run.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Events handled by cores.
    pub events: u64,
    /// Packets put on the wire, by class lane.
    pub packets: [u64; 3],
    /// Bytes put on the wire.
    pub bytes: u64,
    /// Packets lost by the network.
    pub lost: u64,
    /// Packets above the frame limit.
    pub oversize: u64,
    /// Crashes.
    pub crashes: u64,
    /// Evidence reports by honest nodes.
    pub evidence: u64,
    /// Proposals broadcast by honest leaders.
    pub proposals: u64,
}

/// Submitted transactions of an instance: id → (submitted at, poison, committed at).
pub type TxLog = BTreeMap<u64, (Millis, bool, Option<Millis>)>;

/// Maximum trace entries kept.
const TRACE_LEN: usize = 60;

/// The simulated world.
pub struct World {
    /// Scenario name.
    pub name: String,
    /// Seed.
    pub seed: u64,
    /// Global virtual time.
    pub now: Millis,
    /// The single PRNG of the run.
    pub rng: Rng,
    queue: BTreeMap<(Millis, u64), Ev>,
    seq: u64,
    /// Heal time `t_g`.
    pub heal_at: Millis,
    /// End of the run.
    pub duration: Millis,
    /// Network.
    pub net: NetConfig,
    /// Instances.
    pub instances: Vec<Inst>,
    /// Machines.
    pub machines: Vec<Machine>,
    /// Replicas.
    pub replicas: Vec<Replica>,
    /// Provenance log.
    pub log: SharedLog,
    /// Hashing for the world (not counted as CPU).
    pub hasher: SimCrypto,
    /// Oracles and bounds.
    pub checks: Checks,
    /// Oracle state.
    pub oracle: Oracle,
    /// Byzantine strategies and the network adversary.
    pub adv: Adversary,
    trace: Vec<TraceEntry>,
    trace_next: usize,
    ready: Vec<Millis>,
    script: Vec<Option<Fault>>,
    churn: Option<Churn>,
    io_kill: Option<IoKill>,
    /// Write completions per machine so far.
    pub io_completions: Vec<u64>,
    workload: Option<Workload>,
    /// Toy two-phase application and independent O-AMX observations, when configured.
    pub amx: Option<super::amx::AmxWorld>,
    /// The application clock guard (§4.5) and O-TIME observations, when configured.
    pub clock_guard: Option<GuardState>,
    /// Submitted transactions per instance.
    pub txs: Vec<TxLog>,
    next_tx: u64,
    /// Counters.
    pub stats: Stats,
    /// The first oracle violation.
    pub failure: Option<String>,
    /// Key → machine.
    pub key_owner: BTreeMap<PublicKey, usize>,
    /// Instance id → instance index.
    pub inst_by_id: BTreeMap<Hash32, usize>,
    /// Print every handled event (`SUMERAGI_SIM_TRACE`).
    pub verbose: bool,
    /// Source of `Init.nonce` values (seeded from the PRNG).
    nonce_source: std::cell::Cell<u64>,
}

/// A fresh random 128-bit store id.
fn fresh_id(rng: &mut Rng) -> StoreId {
    (StoreId::from(rng.next_u64()) << 64) | StoreId::from(rng.next_u64())
}

/// Derive a 32-byte fake key.
fn derive_key(seed: u64, machine: usize, slot: usize) -> PublicKey {
    let mut input = b"sumeragi-sim-key".to_vec();
    input.extend_from_slice(&seed.to_be_bytes());
    input.extend_from_slice(&u64::try_from(machine).unwrap_or(0).to_be_bytes());
    input.extend_from_slice(&u64::try_from(slot).unwrap_or(0).to_be_bytes());
    PublicKey::new(sha256(&input).to_vec()).unwrap_or_else(|_| unreachable!("32-byte key"))
}

fn derive_hash(tag: &[u8], seed: u64, index: usize) -> Hash32 {
    let mut input = tag.to_vec();
    input.extend_from_slice(&seed.to_be_bytes());
    input.extend_from_slice(&u64::try_from(index).unwrap_or(0).to_be_bytes());
    Hash32(sha256(&input))
}

/// The topology of `height` of instance 0 that a scenario's world will use, assuming no
/// demotions (static corruption with hindsight, §13.1), and the machine of each canonical index.
pub fn preview(sc: &Scenario, height: u64) -> (crate::topology::Topology, Vec<usize>) {
    let mut rng = Rng::new(seed_of(&sc.name, sc.seed));
    let key_seed = rng.next_u64();
    let members = sc
        .committees
        .iter()
        .rev()
        .find(|(from, _)| *from <= height)
        .or_else(|| sc.committees.first())
        .map(|(_, m)| m.clone())
        .unwrap_or_default();
    let keyed: Vec<(PublicKey, usize)> = members
        .iter()
        .map(|(m, slot)| (derive_key(key_seed, m * 16, *slot), *m))
        .collect();
    let committee = Committee::new(keyed.iter().map(|(k, _)| k.clone()).collect())
        .expect("scenario committees are well formed");
    let machine_of = committee
        .members()
        .iter()
        .map(|k| keyed.iter().find(|(x, _)| x == k).map_or(0, |(_, m)| *m))
        .collect();
    let id = derive_hash(b"sim-instance", key_seed, 0);
    let epoch_index = sc
        .committees
        .iter()
        .rposition(|(from, _)| *from <= height)
        .unwrap_or(0);
    let first = sc.committees[epoch_index].0;
    let last = sc
        .committees
        .get(epoch_index + 1)
        .map_or(u64::MAX, |(from, _)| from - 1);
    let epoch = crate::testing::scheduled_epoch(epoch_index as u64, first, last);
    let topo = crate::topology::Topology::compute(
        &SimCrypto::new(),
        &id,
        &epoch,
        &committee,
        height,
        0,
        sc.demotion_window,
        &[],
    );
    (topo, machine_of)
}

impl World {
    /// Build the world of a scenario and start every machine.
    ///
    /// # Panics
    /// If the scenario is malformed (empty committee schedule, invalid configuration).
    #[allow(clippy::too_many_lines)] // one straight-line setup of every component
    pub fn new(sc: Scenario) -> Self {
        let mut rng = Rng::new(seed_of(&sc.name, sc.seed));
        let machines_n = sc.machines();
        let key_seed = rng.next_u64();
        let slots = sc
            .committees
            .iter()
            .chain(
                sc.instance_committees
                    .iter()
                    .flat_map(|(_, schedule)| schedule.iter()),
            )
            .flat_map(|(_, members)| members.iter().map(|(_, slot)| *slot + 1))
            .max()
            .unwrap_or(1);
        let mut instances = Vec::new();
        for i in 0..sc.instances.max(1) {
            let key_of = |m: usize, slot: usize| {
                let base = if sc.shared_keys { 0 } else { i };
                derive_key(key_seed, m * 16 + base, slot)
            };
            let schedule = sc
                .instance_committees
                .iter()
                .find(|(inst, _)| *inst == i && i != 0)
                .map_or(&sc.committees, |(_, schedule)| schedule)
                .iter()
                .map(|(from, members)| {
                    let keys = members.iter().map(|(m, s)| key_of(*m, *s)).collect();
                    (
                        *from,
                        Committee::new(keys).expect("scenario committees are well formed"),
                    )
                })
                .collect();
            instances.push(Inst {
                id: derive_hash(b"sim-instance", key_seed, i),
                genesis_hash: derive_hash(b"sim-genesis", key_seed, i),
                genesis_result: derive_hash(b"sim-genesis-result", key_seed, i),
                schedule,
                params: sc.params,
                window: sc.demotion_window,
                local: sc.local,
            });
        }
        let mut machines = Vec::new();
        let mut replicas = Vec::new();
        let mut key_owner = BTreeMap::new();
        let log: SharedLog = std::sync::Arc::default();
        for m in 0..machines_n {
            let mut machine = Machine {
                up: false,
                epoch: 0,
                clock: sc.clocks.get(m).copied().unwrap_or_default(),
                byz: sc.is_byz(m),
                replicas: vec![None; instances.len()],
                profile: sc.profile(m),
                started_at: 0,
                crashes: 0,
                keys: Vec::new(),
                keystore: KeyStore::default(),
                store_id: None,
                snapshot: None,
                retired: BTreeSet::new(),
            };
            for (i, inst) in instances.iter().enumerate() {
                let base = if sc.shared_keys { 0 } else { i };
                let keys: Vec<PublicKey> = (0..slots)
                    .map(|slot| derive_key(key_seed, m * 16 + base, slot))
                    .filter(|key| inst.schedule.iter().any(|(_, c)| c.contains(key)))
                    .collect();
                let observer = keys.is_empty() && (m >= sc.n || sc.follow_all_instances);
                let keys = if observer {
                    vec![derive_key(key_seed, m * 16 + base, 0)]
                } else {
                    keys
                };
                if keys.is_empty() {
                    continue;
                }
                for key in &keys {
                    key_owner.insert(key.clone(), m);
                    if !machine.keys.contains(key) {
                        machine.keys.push(key.clone());
                    }
                }
                let crypto = SimCrypto::new();
                let rep = Replica {
                    machine: m,
                    inst: i,
                    keys: keys.clone(),
                    // Byzantine strategies rewrite the fake driver's actions (§13.5).
                    host: if sc.is_byz(m) {
                        fake_host(m, i)
                    } else {
                        (sc.host)(m, i)
                    },
                    crypto,
                    budget: iroha_allocation::AllocationBudget::new(1 << 30),
                    acquisitions: BTreeMap::new(),
                    records: BTreeMap::new(),
                    bodies: BTreeMap::new(),
                    store: Vec::new(),
                    busy_until: 0,
                    cpu_carry_us: 0,
                    io: Io::default(),
                    exec: Executor::default(),
                    nic: Nic::default(),
                    txs: BTreeMap::new(),
                    quarantine: BTreeSet::new(),
                    applied: (0, inst.genesis_hash, inst.genesis_result),
                    height: 1,
                    halted: None,
                    last_persisted: BTreeMap::new(),
                    max_tick_late: 0,
                    wake_mark: (0, 0),
                    pending_ready: None,
                };
                machine.replicas[i] = Some(replicas.len());
                replicas.push(rep);
            }
            // The keys are generated on the node (§7.4 record provenance); the instances start
            // at the first restart (installation events with initial records).
            for key in machine.keys.clone() {
                let id = fresh_id(&mut rng);
                machine
                    .keystore
                    .install_key(&mut machine.store_id, &key, true, id);
            }
            if sc.keystore_snapshot {
                machine.snapshot = Some(machine.keystore.clone());
            }
            machines.push(machine);
        }
        let inst_by_id = instances
            .iter()
            .enumerate()
            .map(|(i, inst)| (inst.id, i))
            .collect();
        let replica_count = replicas.len();
        let adv = Adversary::new(&sc, &machines);
        let clock_guard = sc
            .clock_guard
            .as_ref()
            .map(|config| GuardState::new(config, machines_n));
        let mut world = Self {
            name: sc.name.clone(),
            seed: sc.seed,
            now: 0,
            rng,
            queue: BTreeMap::new(),
            seq: 0,
            heal_at: sc.heal_at,
            duration: sc.duration,
            net: sc.net,
            instances,
            machines,
            replicas,
            log,
            hasher: SimCrypto::new(),
            checks: sc.checks,
            oracle: Oracle::new(replica_count),
            adv,
            trace: Vec::new(),
            trace_next: 0,
            ready: vec![Millis::MAX; replica_count],
            script: Vec::new(),
            churn: sc.churn,
            io_kill: sc.io_kill,
            io_completions: vec![0; machines_n],
            workload: sc.workload,
            amx: None,
            clock_guard,
            txs: Vec::new(),
            next_tx: 0,
            stats: Stats::default(),
            failure: None,
            key_owner,
            inst_by_id,
            verbose: std::env::var("SUMERAGI_SIM_TRACE").is_ok(),
            nonce_source: std::cell::Cell::new(0),
        };
        world.nonce_source.set(world.rng.next_u64());
        world.txs = vec![BTreeMap::new(); world.instances.len()];
        world.oracle.init(&world.instances);
        world.amx = sc
            .amx
            .map(|config| super::amx::AmxWorld::new(config, &world.instances));
        if world.amx.is_some() {
            world.schedule(super::amx::TICK, Ev::AmxTick);
        }
        if sc.prebuilt > 0 {
            world.prebuild(sc.prebuilt, &sc.prebuilt_holders);
        }
        for (at, fault) in sc.script {
            let index = world.script.len();
            world.script.push(Some(fault));
            world.schedule(at, Ev::Script(index));
        }
        if world.workload.is_some() {
            for i in 0..world.instances.len() {
                world.schedule(1, Ev::TxGen(i));
            }
        }
        for r in 0..world.replicas.len() {
            if world.adv.has_strategy(r) {
                world.schedule(50, Ev::ByzTick(r));
            }
            if world.machines[world.replicas[r].machine].profile.evict_ppm > 0 {
                world.schedule(100, Ev::Evict(r));
            }
        }
        for m in 0..world.machines.len() {
            world.restart(m);
        }
        world
    }

    // ---- scheduling ----------------------------------------------------------------------

    fn schedule(&mut self, at: Millis, ev: Ev) {
        self.seq += 1;
        self.queue.insert((at.max(self.now), self.seq), ev);
    }

    /// Record a trace line.
    pub fn trace(&mut self, who: usize, what: String) {
        if self.verbose && !what.starts_with("<-") && !what.starts_with("Tick") {
            eprintln!("t={:>7} #{who:<3} ** {what}", self.now);
        }
        let entry = TraceEntry {
            t: self.now,
            who,
            what,
        };
        if self.trace.len() < TRACE_LEN {
            self.trace.push(entry);
        } else {
            self.trace[self.trace_next] = entry;
        }
        self.trace_next = (self.trace_next + 1) % TRACE_LEN;
    }

    /// Record the first violation (the run stops).
    pub fn fail(&mut self, what: String) {
        if self.failure.is_none() {
            let mut what = what;
            what.insert_str(0, &format!("t={} ", self.now));
            self.failure = Some(what);
        }
    }

    /// The failure report: scenario, seed, violation, reproduction hint and the last events.
    pub fn report(&self, violation: &str) -> String {
        let mut out = format!(
            "sumeragi simulation failure\n  scenario {} seed {} (reproduce: SUMERAGI_SIM_SEED={} \
             cargo test -p iroha_sumeragi --release sim::)\n  violation: {violation}\n  last events:\n",
            self.name, self.seed, self.seed
        );
        let len = self.trace.len();
        for i in 0..len {
            let entry = &self.trace[(self.trace_next + i) % len];
            let _ = writeln!(out, "    t={:>7} #{:<3} {}", entry.t, entry.who, entry.what);
        }
        out
    }

    /// Run for the minimum duration or until the first violation. Scenarios requesting bounded
    /// progress completion then observe their remaining heights under captured O-LIVE deadlines.
    ///
    /// # Errors
    /// The failure report of the first violation.
    pub fn run(&mut self) -> Result<(), String> {
        while self.failure.is_none() && self.step() {}
        if self.failure.is_none() {
            self.now = self.now.max(self.duration);
            if self.checks.complete_progress {
                self.complete_progress_observation();
            }
            if self.failure.is_none() {
                self.finish();
            }
        }
        self.failure
            .as_ref()
            .map_or(Ok(()), |violation| Err(self.report(violation)))
    }

    /// Run until `until` (for scripted tests); stops early on a violation.
    pub fn run_until(&mut self, until: Millis) {
        let end = self.duration;
        self.duration = until.min(end);
        while self.failure.is_none() && self.step() {}
        self.now = self.now.max(self.duration);
        self.duration = end;
    }

    fn step(&mut self) -> bool {
        let next_q = self.queue.first_key_value().map(|((t, _), _)| *t);
        let next_r = self
            .ready
            .iter()
            .enumerate()
            .min_by_key(|(_, t)| **t)
            .map(|(r, t)| (*t, r));
        let t_q = next_q.unwrap_or(Millis::MAX);
        let (t_r, r) = next_r.unwrap_or((Millis::MAX, 0));
        let t = t_q.min(t_r);
        if t == Millis::MAX || t > self.duration {
            return false;
        }
        self.now = self.now.max(t);
        self.check_live();
        if self.failure.is_some() {
            return false;
        }
        if t_q <= t_r {
            if let Some((_, ev)) = self.queue.pop_first() {
                self.dispatch(ev);
            }
        } else {
            self.process(r);
        }
        true
    }

    fn dispatch(&mut self, ev: Ev) {
        match ev {
            Ev::Arrive { r, from, msg } => self.arrive(r, from, &msg),
            Ev::Local { r, epoch, event } => {
                if self.alive(r, epoch) {
                    self.replicas[r].host.deliver(*event);
                    self.poll_host(r, self.now);
                    self.refresh(r);
                }
            }
            Ev::Done { r, epoch, done } => {
                if self.alive(r, epoch) {
                    self.complete_host(r, *done);
                }
            }
            Ev::OwnedExec {
                r,
                epoch,
                op,
                bh,
                height,
                outcome,
            } => {
                if self.alive(r, epoch) {
                    if let ExecOutcome::Valid(res) = &outcome {
                        let exec = &mut self.replicas[r].exec;
                        exec.cache.insert(bh, (height, *res));
                    }
                    let outcome = Some(outcome);
                    self.complete_host(r, Done::Executed { op, outcome });
                }
            }
            Ev::IoDone { r, epoch, id } => {
                if self.alive(r, epoch) {
                    self.io_attempt(r, id);
                }
            }
            Ev::ExecDone { r, epoch, job } => {
                if self.alive(r, epoch) {
                    self.exec_done(r, job);
                }
            }
            Ev::NicFree { r, epoch } => {
                if self.alive(r, epoch) {
                    self.replicas[r].nic.wakeup_pending = false;
                    self.nic_flush(r, self.now);
                }
            }
            Ev::Script(index) => {
                if let Some(fault) = self.script.get_mut(index).and_then(Option::take) {
                    self.trace(0, format!("script {fault:?}"));
                    self.apply_fault(fault);
                }
            }
            Ev::Restart(m) => {
                if !self.machines[m].up {
                    self.restart(m);
                }
            }
            Ev::TxGen(inst) => self.gen_tx(inst),
            Ev::AmxTick => {
                self.amx_tick();
                self.schedule(self.now + super::amx::TICK, Ev::AmxTick);
            }
            Ev::ByzTick(r) => {
                self.byz_tick(r);
                self.schedule(self.now + 100, Ev::ByzTick(r));
            }
            Ev::Evict(r) => {
                self.evict(r);
                self.schedule(self.now + 100, Ev::Evict(r));
            }
        }
    }

    fn alive(&self, r: usize, epoch: u64) -> bool {
        let m = &self.machines[self.replicas[r].machine];
        m.up && m.epoch == epoch
    }

    /// Current incarnation of replica `r`'s machine.
    pub fn epoch_of(&self, r: usize) -> u64 {
        self.machines[self.replicas[r].machine].epoch
    }

    /// Recompute the time at which replica `r` next has work.
    pub fn refresh(&mut self, r: usize) {
        let rep = &self.replicas[r];
        let machine = &self.machines[rep.machine];
        let t = match &rep.host {
            host if machine.up && host.running() => {
                let wake = machine.clock.global_at(host.next_wakeup());
                let t = if host.has_input() {
                    wake.min(self.now)
                } else {
                    wake
                };
                if t == Millis::MAX {
                    t
                } else {
                    t.max(rep.busy_until)
                }
            }
            _ => Millis::MAX,
        };
        self.ready[r] = t;
    }

    // ---- handling --------------------------------------------------------------------------

    fn process(&mut self, r: usize) {
        let m = self.replicas[r].machine;
        let local_now = self.machines[m].clock.local(self.now);
        let byz = self.machines[m].byz;
        let rep = &mut self.replicas[r];
        if !rep.host.running() {
            self.ready[r] = Millis::MAX;
            return;
        }
        // The core's own deadline (a host that owns its scheduling may also wake for its timers).
        let wake = core_wakeup(&*rep.host);
        let Some(event) = rep.host.next_input(local_now) else {
            self.poll_host(r, self.now);
            self.refresh(r);
            return;
        };
        if matches!(event, Event::Tick) {
            // The deadline became due at `wake`, or when the core first reported it.
            let due = wake.max(rep.wake_mark.1);
            rep.max_tick_late = rep.max_tick_late.max(local_now.saturating_sub(due));
        }
        let mut what = describe_event(&event);
        if let Event::Message { from, .. } = &event
            && let Some(sender) = self.key_owner.get(from)
        {
            let _ = write!(what, " [m{sender}]");
        }
        let is_tick = matches!(event, Event::Tick);
        let before = rep.crypto.pairings();
        let actions = rep.host.handle(local_now, event);
        let after_wake = core_wakeup(&*rep.host);
        let pairings = rep.crypto.pairings() - before;
        if let Some(core) = rep.host.core() {
            rep.height = core.status().height;
        }
        let profile = self.machines[m].profile;
        rep.cpu_carry_us += pairings * profile.cpu_us_per_pairing + profile.cpu_us_per_event;
        let cost = rep.cpu_carry_us / 1_000;
        rep.cpu_carry_us %= 1_000;
        let at = self.now + cost;
        rep.busy_until = at;
        if after_wake != rep.wake_mark.0 {
            rep.wake_mark = (after_wake, self.machines[m].clock.local(at));
        }
        self.stats.events += 1;
        if self.verbose {
            let summary = summarize(&actions);
            eprintln!("t={:>7} #{r:<3} m{m:<3} {what} => {summary}", self.now);
        }
        self.trace(r, what);
        if is_tick && after_wake <= local_now && !byz {
            self.fail(format!(
                "replica {r}: Tick did not consume its due deadline ({after_wake} ≤ {local_now})"
            ));
        }
        let actions = if byz {
            self.byz_filter(r, actions, at)
        } else {
            self.after_handle(r, &actions);
            actions
        };
        if self.replicas[r].host.owns_io() {
            self.observe_owned(r, &actions);
            self.poll_host(r, at);
        } else {
            self.apply_actions(r, actions, at);
        }
        self.refresh(r);
    }

    /// Execute a core's actions in order (O1); a churn crash may cut the list short.
    pub fn apply_actions(&mut self, r: usize, actions: Vec<Action>, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        for action in actions {
            if !self.alive(r, epoch) {
                return;
            }
            let point = self.crash_point_of(r, &action);
            self.apply_action(r, action, at);
            if self.churn_hit(m, point) {
                self.crash_by_churn(m);
                return;
            }
        }
    }

    fn crash_point_of(&mut self, r: usize, action: &Action) -> CrashPoint {
        let Action::PersistSafety(record) = action else {
            return CrashPoint::Random;
        };
        self.crash_point_of_record(r, record)
    }

    /// The crash point right after the write of `record` was submitted.
    fn crash_point_of_record(&mut self, r: usize, record: &SafetyRecord) -> CrashPoint {
        let rep = &mut self.replicas[r];
        let point = match rep.last_persisted.get(&record.key) {
            Some(old) if old.height == record.height => {
                if old.proposal != record.proposal {
                    CrashPoint::ProposalRecord
                } else if old.timeout != record.timeout {
                    CrashPoint::TimeoutRecord
                } else if old.prepare != record.prepare || old.lock != record.lock {
                    // A Commit is recorded through the lock (§6.5).
                    CrashPoint::VoteRecord
                } else {
                    CrashPoint::Random
                }
            }
            _ => {
                if record.proposal.is_some() {
                    CrashPoint::ProposalRecord
                } else if record.prepare.is_some() || record.lock.is_some() {
                    CrashPoint::VoteRecord
                } else if record.timeout.is_some() {
                    CrashPoint::TimeoutRecord
                } else {
                    CrashPoint::Random
                }
            }
        };
        rep.last_persisted
            .insert(record.key.clone(), record.clone());
        point
    }

    fn write_latency(&mut self, m: usize) -> Millis {
        let p = self.machines[m].profile;
        self.rng.range(p.write_min, p.write_max)
    }

    fn apply_action(&mut self, r: usize, action: Action, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        match action {
            Action::PersistSafety(record) => {
                let bytes = match record.encode(&self.hasher) {
                    Ok(bytes) => bytes,
                    Err(e) => return self.fail(format!("replica {r}: record encode: {e}")),
                };
                let latency = self.write_latency(m);
                let (id, done) =
                    self.replicas[r]
                        .io
                        .write(at, latency, Write::Record(record, bytes));
                self.replicas[r].host.persisting(id);
                self.schedule(done, Ev::IoDone { r, epoch, id });
            }
            Action::StoreBody { block } => {
                let latency = self.write_latency(m);
                let (id, done) =
                    self.replicas[r]
                        .io
                        .write(at, latency, Write::Body(Box::new(block)));
                self.schedule(done, Ev::IoDone { r, epoch, id });
            }
            Action::Execute {
                block,
                req,
                certified,
            } => {
                let bh = block.hash(&self.hasher);
                self.replicas[r].exec.submit(bh, req, block, certified);
                self.exec_kick(r, at);
            }
            Action::DiscardExecution { height, keep } => {
                let abort = self.machines[m].profile.abort_discarded;
                let cancelled = self.replicas[r].exec.discard(height, &keep, abort);
                if abort {
                    self.exec_kick(r, at);
                }
                for (bh, req) in cancelled {
                    self.schedule(
                        at,
                        Ev::Local {
                            r,
                            epoch,
                            event: Box::new(Event::Executed {
                                block_hash: bh,
                                req,
                                outcome: ExecOutcome::Cancelled,
                            }),
                        },
                    );
                }
            }
            Action::BuildControlWitness { req, context } => self.schedule(
                at,
                Ev::Local {
                    r,
                    epoch,
                    event: Box::new(Event::ControlWitnessBuilt {
                        req,
                        context,
                        witness: crate::types::ControlWitness::empty(),
                    }),
                },
            ),
            Action::DriveApplicationControl { .. } | Action::ReceiveApplicationControl { .. } => {}
            Action::BuildPayload {
                req,
                max_bytes,
                exec_budget_ms,
                ..
            } => self.build_payload(r, req, max_bytes, exec_budget_ms, at),
            #[cfg(not(sumeragi_mutation = "ML14"))]
            Action::PayloadRejected { block_hash, .. } => self.quarantine(r, &block_hash),
            #[cfg(sumeragi_mutation = "ML14")]
            Action::PayloadRejected { .. } => {}
            Action::LocalFault(_) => {}
            Action::Halt(reason) => {
                self.replicas[r].halted = Some(reason);
                self.trace(r, format!("HALT {reason:?}"));
            }
            effect => {
                if let Some(effect) = self.replicas[r].host.gate(effect) {
                    self.perform(r, effect, at);
                }
            }
        }
    }

    /// Carry out an externally visible effect (after the O2 barrier).
    fn perform(&mut self, r: usize, action: Action, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        match action {
            Action::Send { to, msg } => {
                self.expose(r, &msg);
                if matches!(msg, WireMessage::Proposal(_)) && !self.machines[m].byz {
                    self.stats.proposals += 1;
                }
                self.net_send(r, &to, SharedWire::share(msg), at);
            }
            Action::Broadcast { to, msg } => {
                self.expose(r, &msg);
                if let WireMessage::Proposal(p) = &msg
                    && !self.machines[m].byz
                {
                    self.stats.proposals += 1;
                    let bh = p.proposal.block_hash(&self.hasher);
                    self.oracle.proposed.entry(bh).or_insert(at);
                }
                let msg = SharedWire::share(msg);
                for key in &to {
                    self.net_send(r, key, Rc::clone(&msg), at);
                }
            }
            Action::CommitBlock { block, commit_qc } => {
                self.expose_qc(r, &commit_qc);
                let latency = self
                    .write_latency(m)
                    .saturating_add(self.machines[m].profile.block_write_extra);
                let (id, done) = self.replicas[r].io.write(
                    at,
                    latency,
                    Write::Commit(Box::new((block, commit_qc))),
                );
                self.schedule(done, Ev::IoDone { r, epoch, id });
            }
            Action::FetchPayload { source, peers } => {
                if let Some(block) = self.local_body(r, source.height(), &source.block_hash()) {
                    let frame = crate::availability::AvailabilityFrame::from_untrusted(
                        block.availability().as_slice().to_vec(),
                    )
                    .unwrap();
                    let payload = crate::availability::PayloadBytes::from_untrusted(
                        block.payload().as_slice().to_vec(),
                    )
                    .unwrap();
                    let job = crate::availability::BodyRestoration::new(
                        source,
                        block.header().clone(),
                        frame,
                        payload,
                    );
                    match job.complete(&self.replicas[r].budget, &self.hasher) {
                        Ok(block) => self.schedule(
                            at + 1,
                            Ev::Local {
                                r,
                                epoch,
                                event: Box::new(Event::BodyAvailable { block }),
                            },
                        ),
                        Err((_, error)) => self.fail(format!("sim restoration failed: {error:?}")),
                    }
                } else {
                    let msg = SharedWire::share(WireMessage::PayloadRequest(PayloadRequest {
                        instance,
                        height: source.height(),
                        block_hash: source.block_hash(),
                    }));
                    for peer in &peers {
                        self.net_send(r, peer, Rc::clone(&msg), at);
                    }
                }
            }
            Action::ServePayload {
                to,
                height,
                block_hash,
            } => {
                if let Some(block) = self.local_body(r, height, &block_hash) {
                    self.disseminate_body(r, &[to], &block, at);
                }
            }
            Action::DisseminatePayload { peers, body } => {
                self.disseminate_body(r, &peers, &body, at);
            }
            Action::AuthorPayload {
                req,
                config,
                header,
                payload,
            } => {
                let key = config
                    .committee
                    .get(header.proposer)
                    .expect("author member");
                let signer = SimSigner::new(
                    key.clone(),
                    (!self.machines[m].byz).then_some(m),
                    std::sync::Arc::clone(&self.log),
                );
                let job = crate::availability::PayloadAuthoring::new(header, payload);
                match job.complete(
                    instance,
                    &config,
                    &self.replicas[r].budget,
                    &self.hasher,
                    &signer,
                ) {
                    Ok(authored) => self.schedule(
                        at + 1,
                        Ev::Local {
                            r,
                            epoch,
                            event: Box::new(Event::PayloadAuthored {
                                req,
                                body: authored.body,
                            }),
                        },
                    ),
                    Err((_, error)) => self.fail(format!("sim authoring failed: {error:?}")),
                }
            }
            Action::AcquirePayload { source, manifest } => {
                let bh = source.block_hash();
                let mut job = crate::availability::PayloadAcquisition::new(source, manifest);
                match job.prepare(&self.replicas[r].budget, &self.hasher) {
                    Ok(()) => {
                        self.replicas[r].acquisitions.entry(bh).or_insert(job);
                    }
                    Err(error) if error.rejects_manifest() => self.schedule(
                        at + 1,
                        Ev::Local {
                            r,
                            epoch,
                            event: Box::new(Event::ManifestRejected {
                                manifest: job.manifest().clone(),
                            }),
                        },
                    ),
                    Err(error) => {
                        self.fail(format!("sim acquisition preparation failed: {error:?}"))
                    }
                }
            }
            Action::ReceivePayloadChunk { chunk, .. } => {
                let bh = chunk.block_hash;
                if let Some(mut job) = self.replicas[r].acquisitions.remove(&bh) {
                    let _ = job.push(chunk, &self.replicas[r].budget, &self.hasher);
                    match job.complete(&self.replicas[r].budget, &self.hasher) {
                        Ok(block) => self.schedule(
                            at + 1,
                            Ev::Local {
                                r,
                                epoch,
                                event: Box::new(Event::BodyAvailable { block }),
                            },
                        ),
                        Err((job, crate::availability::AcquisitionError::Incomplete)) => {
                            self.replicas[r].acquisitions.insert(bh, job);
                        }
                        Err((job, error)) if error.rejects_manifest() => self.schedule(
                            at + 1,
                            Ev::Local {
                                r,
                                epoch,
                                event: Box::new(Event::ManifestRejected {
                                    manifest: job.manifest().clone(),
                                }),
                            },
                        ),
                        Err((_, error)) => {
                            self.fail(format!("sim reconstruction failed: {error:?}"))
                        }
                    }
                }
            }
            Action::ServeBlocks {
                to,
                from_height,
                max_count,
                max_bytes,
            } => {
                // An empty response means "I hold nothing at from_height" (§3.5).
                let blocks = self.serve_blocks(r, from_height, max_count, max_bytes);
                let msg = WireMessage::SyncResponse(SyncResponse { instance, blocks });
                self.expose(r, &msg);
                self.net_send(r, &to, SharedWire::share(msg), at);
            }
            Action::ReportEvidence(evidence) => {
                self.expose_evidence(r, &evidence);
            }
            _ => {}
        }
    }

    /// Actual worker-side row encoding; all original authorizations stay in the manifest.
    pub(super) fn disseminate_body(
        &mut self,
        r: usize,
        peers: &[PublicKey],
        body: &AvailableBody,
        at: Millis,
    ) {
        let epoch = self.instances[self.replicas[r].inst].epoch(body.header().height);
        let shape = epoch
            .da_layout
            .shape(body.payload().as_slice().len() as u64)
            .unwrap();
        let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
            shape,
            body.payload().as_slice(),
            &self.replicas[r].budget,
        )
        .unwrap();
        let manifest = SharedWire::share(WireMessage::PayloadManifest(PayloadManifest {
            header: body.header().clone(),
            availability: body.availability().clone(),
        }));
        for peer in peers {
            self.net_send(r, peer, Rc::clone(&manifest), at);
        }
        for index in 0..shape.chunk_count() {
            let range = shape.chunk_range(index).unwrap();
            let mut bytes =
                crate::availability::RowBytes::from_untrusted(encoded.codeword()[range].to_vec())
                    .unwrap();
            bytes.admit(&self.replicas[r].budget).unwrap();
            let chunk = SharedWire::share(WireMessage::PayloadChunk(PayloadChunk {
                instance: body.header().instance,
                height: body.header().height,
                block_hash: body.hash(&self.hasher),
                index: u32::try_from(index).expect("protocol-bounded row index"),
                bytes,
            }));
            for peer in peers {
                self.net_send(r, peer, Rc::clone(&chunk), at);
            }
        }
    }

    pub(super) fn local_body(&self, r: usize, height: u64, bh: &Hash32) -> Option<AvailableBody> {
        let rep = &self.replicas[r];
        rep.bodies
            .get(bh)
            .cloned()
            .or_else(|| rep.io.pending_body(bh, &self.hasher))
            .or_else(|| {
                let g = 0u64;
                let index = usize::try_from(height.checked_sub(g + 1)?).ok()?;
                rep.store
                    .get(index)
                    .filter(|(_, qc)| qc.block_hash == *bh)
                    .map(|(b, _)| b.clone())
            })
            .filter(|b| b.header().height == height)
    }

    fn serve_blocks(
        &self,
        r: usize,
        from_height: u64,
        max_count: u16,
        max_bytes: u32,
    ) -> Vec<SyncEntry> {
        let rep = &self.replicas[r];
        let Some(start) = from_height
            .checked_sub(1)
            .and_then(|i| usize::try_from(i).ok())
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut bytes = 0u64;
        for (block, qc) in rep.store.iter().skip(start).take(usize::from(max_count)) {
            let size = u64::try_from(block.payload().as_slice().len()).unwrap_or(u64::MAX)
                + 512
                + crate::types::MAX_CONTROL_WITNESS_BYTES as u64;
            if !out.is_empty() && bytes + size > u64::from(max_bytes) {
                break;
            }
            bytes += size;
            out.push(SyncEntry {
                manifest: PayloadManifest {
                    header: block.header().clone(),
                    availability: block.availability().clone(),
                },
                commit_qc: qc.clone(),
            });
        }
        out
    }

    // ---- network ---------------------------------------------------------------------------

    /// The key a replica uses as its P2P identity (its key in the current committee).
    pub fn net_key(&self, r: usize) -> PublicKey {
        let rep = &self.replicas[r];
        let committee = self.instances[rep.inst].committee(rep.height);
        rep.keys
            .iter()
            .rev()
            .find(|k| committee.contains(k))
            .or_else(|| rep.keys.first())
            .cloned()
            .unwrap_or_else(|| unreachable!("a replica has a key"))
    }

    /// Queue a message from replica `r` to the owner of `to` on `r`'s NIC.
    pub fn net_send(&mut self, r: usize, to: &PublicKey, msg: Rc<SharedWire>, at: Millis) {
        let Some(&tm) = self.key_owner.get(to) else {
            return;
        };
        let inst = self
            .inst_by_id
            .get(msg.instance())
            .copied()
            .unwrap_or(self.replicas[r].inst);
        let Some(target) = self.machines[tm].replicas.get(inst).copied().flatten() else {
            return;
        };
        self.send_to_replica(r, target, msg, at);
    }

    /// Queue a message from replica `r` to replica `target` (bypassing key routing).
    pub fn send_to_replica(&mut self, r: usize, target: usize, msg: Rc<SharedWire>, at: Millis) {
        if target == r {
            return; // O7
        }
        let size = approx_size(&msg);
        if size > self.net.frame_limit {
            self.stats.oversize += 1;
            return;
        }
        let class = class_of(&msg);
        self.replicas[r].nic.push(
            class,
            Packet {
                item: (target, msg),
                size,
            },
        );
        self.nic_flush(r, at);
    }

    fn nic_flush(&mut self, r: usize, at: Millis) {
        let bandwidth = self.net.bandwidth;
        let (out, next) = self.replicas[r].nic.drain(at, bandwidth);
        for (depart, (target, msg)) in out {
            self.transmit(r, target, msg, depart);
        }
        if let Some(next) = next
            && !self.replicas[r].nic.wakeup_pending
        {
            self.replicas[r].nic.wakeup_pending = true;
            let epoch = self.epoch_of(r);
            self.schedule(next, Ev::NicFree { r, epoch });
        }
    }

    fn transmit(&mut self, r: usize, target: usize, msg: Rc<SharedWire>, depart: Millis) {
        let size = approx_size(&msg);
        let lane = lane(class_of(&msg));
        self.stats.packets[lane] += 1;
        self.stats.bytes += size;
        let Some((msg, extra)) = self.adv_net(r, target, msg, depart) else {
            self.stats.lost += 1;
            return;
        };
        let a = self.replicas[r].machine;
        let b = self.replicas[target].machine;
        let from = self.net_key(r);
        match self.net.fate(&mut self.rng, depart, self.heal_at, a, b) {
            Fate::Drop => self.stats.lost += 1,
            Fate::Deliver(first, second) => {
                self.schedule(
                    depart + first + extra,
                    Ev::Arrive {
                        r: target,
                        from: from.clone(),
                        msg: Rc::clone(&msg),
                    },
                );
                if let Some(second) = second {
                    self.schedule(
                        depart + second + extra,
                        Ev::Arrive {
                            r: target,
                            from,
                            msg,
                        },
                    );
                }
            }
        }
    }

    /// Deliver a message into the ingress lanes of replica `r` directly (adversary injection).
    pub fn inject(&mut self, r: usize, from: PublicKey, msg: WireMessage, delay: Millis) {
        self.schedule(
            self.now + delay,
            Ev::Arrive {
                r,
                from,
                msg: SharedWire::share(msg),
            },
        );
    }

    fn arrive(&mut self, r: usize, from: PublicKey, msg: &Rc<SharedWire>) {
        let m = self.replicas[r].machine;
        if !self.machines[m].up || !self.replicas[r].host.running() {
            return;
        }
        if self.machines[m].byz {
            self.byz_observe(r, &from, msg);
        }
        let class = class_of(msg);
        let Ok(bytes) = msg.canonical_bytes() else {
            return;
        };
        let Ok(mut decoded) = WireMessage::decode(
            bytes,
            usize::try_from(self.net.frame_limit).unwrap_or(usize::MAX),
        ) else {
            return;
        };
        if decoded.admit_owned_bytes(&self.replicas[r].budget).is_err() {
            return;
        }
        self.replicas[r].host.receive(from, decoded, class);
        self.refresh(r);
    }

    // ---- storage, execution, building -------------------------------------------------------

    /// Count a write completion of replica `r`'s machine: `Some(before_durable)` if the scenario
    /// kills the machine at it (§13.5 O2 conformance, [`Scenario::io_kill`]).
    fn io_kill_at(&mut self, r: usize) -> Option<bool> {
        let m = self.replicas[r].machine;
        self.io_completions[m] += 1;
        let kill = self.io_kill?;
        (kill.machine == m && self.io_completions[m] == kill.nth).then_some(kill.before_durable)
    }

    /// Kill replica `r`'s machine at a write completion and restart it after the scenario's
    /// down time.
    fn io_kill(&mut self, r: usize) {
        let m = self.replicas[r].machine;
        let down = self.io_kill.map_or(0, |kill| kill.down);
        self.trace(m, "IO KILL".to_owned());
        self.crash(m);
        self.schedule(self.now + down, Ev::Restart(m));
    }

    /// Complete the writes up to `id` (durable), then perform what waited for them — unless
    /// `kill` kills the machine right after they became durable.
    fn io_done(&mut self, r: usize, id: u64, kill: bool) {
        let writes = self.replicas[r].io.complete(id);
        let mut owned = Vec::new();
        for write in writes {
            match write {
                Write::Owned { op, ok, write } => {
                    if ok && !self.owned_durable(r, write) {
                        return;
                    }
                    owned.push(Done::Written { op, ok });
                }
                Write::Record(record, bytes) => {
                    let rep = &mut self.replicas[r];
                    // MS33a: one record file per instance for all keys.
                    #[cfg(sumeragi_mutation = "MS33a")]
                    for durable in rep.records.values_mut() {
                        durable.record = (*record).clone();
                        durable.bytes.clone_from(&bytes);
                    }
                    rep.records.insert(
                        record.key.clone(),
                        Durable {
                            record: *record,
                            bytes,
                        },
                    );
                }
                Write::Body(block) => {
                    let rep = &mut self.replicas[r];
                    if block.header().height > rep.applied.0 {
                        let bh = block.hash(&self.hasher);
                        rep.bodies.insert(bh, *block);
                    }
                }
                Write::Commit(entry) => {
                    let (block, qc) = *entry;
                    self.apply_block(r, &block, &qc);
                    if !self.machines[self.replicas[r].machine].up {
                        return;
                    }
                }
            }
        }
        let m = self.replicas[r].machine;
        if kill {
            return self.io_kill(r);
        }
        if self.replicas[r].host.owns_io() {
            if !owned.is_empty() && self.churn_hit(m, CrashPoint::AfterDurable) {
                self.crash_by_churn(m);
                return;
            }
            for done in owned {
                self.complete_host(r, done);
            }
            if self.churn_hit(m, CrashPoint::Random) {
                self.crash_by_churn(m);
            }
            return;
        }
        // O2: the host releases the effects that waited for these writes.
        let released = self.replicas[r].host.durable(id);
        if !released.is_empty() && self.churn_hit(m, CrashPoint::AfterDurable) {
            self.crash_by_churn(m);
            return;
        }
        let now = self.now;
        let epoch = self.machines[m].epoch;
        for effect in released {
            if !self.alive(r, epoch) {
                return;
            }
            self.perform(r, effect, now);
        }
        if self.churn_hit(m, CrashPoint::Random) {
            self.crash_by_churn(m);
        }
    }

    /// O3: apply a committed block. The cached post-state of exactly this block is reused if
    /// its commitment equals the certified result; otherwise the block is executed (a
    /// divergent executor then reports `ApplyDiverged`). `BlockApplied` carries the header.
    fn apply_block(&mut self, r: usize, block: &AvailableBody, qc: &Qc) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        let inst = self.replicas[r].inst;
        let height = block.header().height;
        let bh = qc.block_hash;
        let (tip_height, tip_hash, tip_result) = self.replicas[r].applied;
        if height != tip_height + 1 || block.header().parent_hash != tip_hash {
            let byz = self.machines[m].byz;
            if !byz {
                self.fail(format!(
                    "O3: replica {r} CommitBlock {height} does not extend the applied state {tip_height}"
                ));
            }
            return;
        }
        self.replicas[r].store.push((block.clone(), qc.clone()));
        if self.churn_hit(m, CrashPoint::InsideApply) {
            self.crash_by_churn(m);
            return;
        }
        let profile = self.machines[m].profile;
        let cached = self.replicas[r]
            .exec
            .cache
            .get(&bh)
            .map(|(_, res)| *res)
            .filter(|res| *res == qc.result);
        let local = cached.or_else(|| {
            let outcome = if profile.divergent && !block.payload().as_slice().is_empty() {
                divergent_exec(&tip_result, block.payload().as_slice(), &bh)
            } else {
                self.app_exec(inst, &tip_result, block)
            };
            match outcome {
                ExecOutcome::Valid(res) => Some(res),
                _ => None,
            }
        });
        let at = self.now + profile.apply_ms;
        if local != Some(qc.result) && !cfg!(sumeragi_mutation = "MS34") {
            self.schedule(
                at,
                Ev::Local {
                    r,
                    epoch,
                    event: Box::new(Event::ApplyDiverged {
                        height,
                        block_hash: bh,
                        local_result: local.unwrap_or(Hash32::ZERO),
                    }),
                },
            );
            return;
        }
        let rep = &mut self.replicas[r];
        rep.applied = (height, bh, qc.result);
        rep.bodies.retain(|_, b| b.header().height > height);
        rep.exec.cache.retain(|_, (h, _)| *h >= height);
        for (id, _) in decode_txs(block.payload().as_slice()) {
            rep.txs.remove(&id);
        }
        let config = self.instances[inst].applied_config(height);
        self.schedule(
            at,
            Ev::Local {
                r,
                epoch,
                event: Box::new(Event::BlockApplied {
                    height,
                    block_hash: bh,
                    header: Box::new(block.header().clone()),
                    config,
                }),
            },
        );
        self.exec_unpark(r);
    }

    fn parent_result(&self, r: usize, block: &AvailableBody) -> Option<Hash32> {
        let rep = &self.replicas[r];
        if block.header().parent_hash == rep.applied.1 {
            return Some(rep.applied.2);
        }
        rep.exec
            .cache
            .get(&block.header().parent_hash)
            .map(|(_, res)| *res)
    }

    fn exec_kick(&mut self, r: usize, at: Millis) {
        loop {
            if self.replicas[r].exec.running.is_some() {
                return;
            }
            let Some(mut job) = self.replicas[r].exec.queue.pop() else {
                return;
            };
            let Some(parent) = self.parent_result(r, &job.block) else {
                self.replicas[r].exec.parked.push(job);
                continue;
            };
            let (outcome, latency) =
                self.exec_outcome(r, &job.block, &job.bh, &parent, job.certified);
            job.outcome = Some(outcome);
            let id = job.id;
            let finish = at + latency;
            self.replicas[r].exec.running = Some((job, finish));
            let epoch = self.epoch_of(r);
            self.schedule(finish, Ev::ExecDone { r, epoch, job: id });
            return;
        }
    }

    /// The executor's outcome for `block` (hash `bh`) on the post-state `parent` under the
    /// machine profile (injected failures, defects, divergence) and the application clock
    /// guard of an `Execute` with the given `certified` flag (§4.5), and its latency. A guard
    /// refusal is answered before execution (1 ms).
    fn exec_outcome(
        &mut self,
        r: usize,
        block: &AvailableBody,
        bh: &Hash32,
        parent: &Hash32,
        certified: bool,
    ) -> (ExecOutcome, Millis) {
        let m = self.replicas[r].machine;
        let profile = self.machines[m].profile;
        let injected = self.rng.chance(profile.exec_fail_ppm);
        if !injected && let Some(refused) = self.clock_guard_refusal(r, block, bh, certified) {
            return (refused, 1);
        }
        let outcome = if injected {
            ExecOutcome::Failed("injected".to_owned())
        } else if profile.reject_nonempty && !block.payload().as_slice().is_empty() {
            ExecOutcome::Invalid
        } else if profile.divergent && !block.payload().as_slice().is_empty() {
            divergent_exec(parent, block.payload().as_slice(), bh)
        } else {
            self.app_exec(self.replicas[r].inst, parent, block)
        };
        (outcome, self.exec_latency(m, block))
    }

    /// Execution latency of `block` on machine `m`.
    fn exec_latency(&self, m: usize, block: &AvailableBody) -> Millis {
        let profile = self.machines[m].profile;
        let kib = u64::try_from(block.payload().as_slice().len()).unwrap_or(u64::MAX) / 1024;
        let nonempty = if block.payload().as_slice().is_empty() {
            0
        } else {
            profile.exec_nonempty
        };
        profile.exec_base + profile.exec_per_kib.saturating_mul(kib) + nonempty
    }

    fn exec_unpark(&mut self, r: usize) {
        let exec = &mut self.replicas[r].exec;
        if exec.parked.is_empty() {
            return;
        }
        let parked = std::mem::take(&mut exec.parked);
        // Keep LIFO service: parked jobs are older than queued ones.
        let queued = std::mem::take(&mut exec.queue);
        exec.queue = parked;
        exec.queue.extend(queued);
        self.exec_kick(r, self.now);
    }

    fn exec_done(&mut self, r: usize, job_id: u64) {
        let epoch = self.epoch_of(r);
        let rep = &mut self.replicas[r];
        let Some((job, _)) = rep.exec.running.take_if(|(job, _)| job.id == job_id) else {
            return;
        };
        let outcome = if job.cancelled {
            ExecOutcome::Cancelled
        } else {
            job.outcome.clone().unwrap_or(ExecOutcome::Cancelled)
        };
        if let ExecOutcome::Valid(res) = &outcome {
            let height = job.block.header().height;
            rep.exec.cache.insert(job.bh, (height, *res));
        }
        rep.host.deliver(Event::Executed {
            block_hash: job.bh,
            req: job.req,
            outcome,
        });
        let _ = epoch;
        self.refresh(r);
        self.exec_unpark(r);
        self.exec_kick(r, self.now);
    }

    fn evict(&mut self, r: usize) {
        let m = self.replicas[r].machine;
        let ppm = self.machines[m].profile.evict_ppm;
        if !self.machines[m].up || !self.rng.chance(ppm) {
            return;
        }
        let keys: Vec<Hash32> = self.replicas[r].exec.cache.keys().copied().collect();
        if let Some(bh) = self.rng.pick(&keys).copied() {
            self.replicas[r].exec.cache.remove(&bh);
        }
    }

    /// The payload builder (§12.2): it only peeks at the queue; an `EMPTY` answer to `req`
    /// makes it owe one `PayloadReady{req}` when a transaction arrives.
    fn build_payload(&mut self, r: usize, req: u64, max_bytes: u32, budget_ms: u32, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        let profile = self.machines[m].profile;
        let budget_bytes = if profile.exec_per_kib == 0 {
            u64::MAX
        } else {
            u64::from(budget_ms).saturating_sub(profile.exec_base) * 1024 / profile.exec_per_kib
        };
        let limit = u64::from(max_bytes)
            .min(budget_bytes)
            .saturating_sub(self.block_time_bytes());
        let rep = &self.replicas[r];
        let mut payload = Vec::new();
        for (id, tx) in &rep.txs {
            if rep.quarantine.contains(id) {
                continue;
            }
            let len = u64::try_from(payload.len() + tx.len()).unwrap_or(u64::MAX);
            if len > limit {
                break;
            }
            payload.extend_from_slice(tx);
        }
        let inst = rep.inst;
        self.stamp_block_time(m, &mut payload);
        let hash = crate::preimage::payload_hash(&self.hasher, &payload);
        self.oracle.built.insert((inst, m, hash));
        self.replicas[r].pending_ready = payload.is_empty().then_some(req);
        // Deliver the build result after the selected application latency.
        let latency = self.rng.range(profile.build_min, profile.build_max);
        self.schedule(
            at + latency,
            Ev::Local {
                r,
                epoch,
                event: Box::new(Event::PayloadBuilt {
                    req,
                    payload: if payload.is_empty() {
                        None
                    } else {
                        let mut owned =
                            crate::availability::PayloadBytes::from_untrusted(payload).unwrap();
                        owned.admit(&self.replicas[r].budget).unwrap();
                        Some(owned)
                    },
                }),
            },
        );
    }

    fn quarantine(&mut self, r: usize, bh: &Hash32) {
        let rep = &self.replicas[r];
        let body = rep
            .bodies
            .get(bh)
            .cloned()
            .or_else(|| rep.io.pending_body(bh, &self.hasher));
        let Some(block) = body else {
            return;
        };
        let rep = &mut self.replicas[r];
        for (id, poison) in decode_txs(block.payload().as_slice()) {
            if poison {
                rep.quarantine.insert(id);
                rep.txs.remove(&id);
            }
        }
    }

    fn gen_tx(&mut self, inst: usize) {
        let Some(workload) = self.workload else {
            return;
        };
        if self.now > workload.until {
            return;
        }
        self.next_tx += 1;
        let id = self.next_tx;
        let poison = self.rng.chance(workload.poison_ppm);
        let tx = workload.tx(id, poison);
        self.txs[inst].insert(id, (self.now, poison, None));
        for r in 0..self.replicas.len() {
            let m = self.replicas[r].machine;
            let targeted = workload.targets == 0
                || u32::try_from(m)
                    .ok()
                    .and_then(|bit| 1u64.checked_shl(bit))
                    .is_some_and(|bit| workload.targets & bit != 0);
            if self.replicas[r].inst == inst && self.machines[m].up && targeted {
                self.offer_tx(r, id, tx.clone());
            }
        }
        let next = self.now + self.rng.range(workload.every_min, workload.every_max);
        self.schedule(next, Ev::TxGen(inst));
    }

    pub(super) fn offer_tx(&mut self, r: usize, id: u64, tx: Vec<u8>) {
        let rep = &mut self.replicas[r];
        if rep.quarantine.contains(&id) {
            return;
        }
        rep.txs.insert(id, tx);
        if let Some(req) = rep.pending_ready.take() {
            rep.host.deliver(Event::PayloadReady { req });
            self.refresh(r);
        }
    }

    // ---- hosts that own their driver scheduling (§13.5) ------------------------------------

    /// The world's side of the core's actions of a host that owns its scheduling: the halt
    /// reason is recorded (O-HALT); every other action is the host's to schedule.
    fn observe_owned(&mut self, r: usize, actions: &[Action]) {
        for action in actions {
            if let Action::Halt(reason) = action {
                self.replicas[r].halted = Some(*reason);
                self.trace(r, format!("HALT {reason:?}"));
            }
        }
    }

    /// Perform the device operations replica `r`'s host wants now (in order; a churn crash may
    /// cut the list short).
    fn poll_host(&mut self, r: usize, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        if !self.alive(r, epoch) || !self.replicas[r].host.owns_io() {
            return;
        }
        let local = self.machines[m].clock.local(self.now);
        let ops = self.replicas[r].host.poll(local);
        for op in ops {
            if !self.alive(r, epoch) {
                return;
            }
            let point = match &op {
                Op::WriteRecord { record, .. } => self.crash_point_of_record(r, record),
                _ => CrashPoint::Random,
            };
            if self.verbose {
                eprintln!("t={:>7} #{r:<3} op {}", self.now, describe_op(&op));
            }
            self.perform_op(r, op, at);
            if self.churn_hit(m, point) {
                self.crash_by_churn(m);
                return;
            }
        }
    }

    /// Hand a completion to replica `r`'s host, then perform what it wants next.
    fn complete_host(&mut self, r: usize, done: Done) {
        let m = self.replicas[r].machine;
        let local = self.machines[m].clock.local(self.now);
        self.replicas[r].host.complete(local, done);
        self.poll_host(r, self.now);
        self.refresh(r);
    }

    /// Make an owned write durable; `false` if the run failed or a churn crash hit inside apply.
    fn owned_durable(&mut self, r: usize, write: OwnedWrite) -> bool {
        match write {
            OwnedWrite::Record(record, bytes) => {
                let durable = Durable {
                    record: *record,
                    bytes,
                };
                let key = durable.record.key.clone();
                self.replicas[r].records.insert(key, durable);
            }
            OwnedWrite::Body(block) => {
                if block.header().height > self.replicas[r].applied.0 {
                    let bh = block.hash(&self.hasher);
                    self.replicas[r].bodies.insert(bh, *block);
                }
            }
            OwnedWrite::Append(entry) => {
                let height = entry.0.header().height;
                let stored = u64::try_from(self.replicas[r].store.len()).unwrap_or(u64::MAX);
                if height != stored + 1 {
                    self.fail(format!(
                        "O3: replica {r} appended height {height} to a block store of {stored} heights"
                    ));
                    return false;
                }
                self.replicas[r].store.push(*entry);
                let m = self.replicas[r].machine;
                if self.churn_hit(m, CrashPoint::InsideApply) {
                    self.crash_by_churn(m);
                    return false;
                }
            }
        }
        true
    }

    /// A write of the device: its latency, and whether it succeeds (F27 failures are reported
    /// to the host, which retries).
    fn owned_write(&mut self, m: usize, extra: Millis) -> (Millis, bool) {
        let p = self.machines[m].profile;
        let latency = self.rng.range(p.write_min, p.write_max) + extra;
        (latency, !self.rng.chance(p.write_fail_ppm))
    }

    /// Perform one device operation of replica `r`'s host (§13.5).
    #[allow(clippy::too_many_lines)] // one arm per device operation
    fn perform_op(&mut self, r: usize, op: Op, at: Millis) {
        let m = self.replicas[r].machine;
        let epoch = self.machines[m].epoch;
        let done = |world: &mut Self, when: Millis, done: Done| {
            world.schedule(
                when,
                Ev::Done {
                    r,
                    epoch,
                    done: Box::new(done),
                },
            );
        };
        match op {
            Op::WriteRecord { op, record } => {
                let bytes = match record.encode(&self.hasher) {
                    Ok(bytes) => bytes,
                    Err(e) => return self.fail(format!("replica {r}: record encode: {e}")),
                };
                let (latency, ok) = self.owned_write(m, 0);
                let write = OwnedWrite::Record(record, bytes);
                let (id, when) =
                    self.replicas[r]
                        .io
                        .write(at, latency, Write::Owned { op, ok, write });
                self.schedule(when, Ev::IoDone { r, epoch, id });
            }
            Op::WriteBody { op, block } => {
                let (latency, ok) = self.owned_write(m, 0);
                let write = OwnedWrite::Body(block);
                let (id, when) =
                    self.replicas[r]
                        .io
                        .write(at, latency, Write::Owned { op, ok, write });
                self.schedule(when, Ev::IoDone { r, epoch, id });
            }
            Op::Append { op, block, qc } => {
                self.expose_qc(r, &qc);
                let extra = self.machines[m].profile.block_write_extra;
                let (latency, ok) = self.owned_write(m, extra);
                let write = OwnedWrite::Append(Box::new((*block, *qc)));
                let (id, when) =
                    self.replicas[r]
                        .io
                        .write(at, latency, Write::Owned { op, ok, write });
                self.schedule(when, Ev::IoDone { r, epoch, id });
            }
            Op::Execute {
                op,
                block,
                certified,
            } => {
                self.replicas[r].exec.prepared = None;
                let bh = block.hash(&self.hasher);
                let Some(parent) = self.parent_result(r, &block) else {
                    let outcome = None;
                    return done(self, at, Done::Executed { op, outcome });
                };
                let (outcome, latency) = self.exec_outcome(r, &block, &bh, &parent, certified);
                let height = block.header().height;
                self.schedule(
                    at + latency,
                    Ev::OwnedExec {
                        r,
                        epoch,
                        op,
                        bh,
                        height,
                        outcome,
                    },
                );
            }
            Op::Discard { op, height, keep } => {
                let exec = &mut self.replicas[r].exec;
                exec.prepared = None;
                exec.cache
                    .retain(|bh, (h, _)| *h != height || keep.contains(bh));
                done(self, at, Done::Discarded { op });
            }
            Op::Prepare { op, block, qc } => {
                let (tip_height, tip_hash, tip_result) = self.replicas[r].applied;
                let height = block.header().height;
                if height != tip_height + 1 || block.header().parent_hash != tip_hash {
                    return self.fail(format!(
                        "O3: replica {r} prepares {height}, which does not extend the applied state {tip_height}"
                    ));
                }
                let cached = self.replicas[r]
                    .exec
                    .cache
                    .get(&qc.block_hash)
                    .map(|(_, res)| *res)
                    .filter(|res| *res == qc.result);
                let (result, latency) = if let Some(res) = cached {
                    (Some(res), 0)
                } else {
                    let profile = self.machines[m].profile;
                    let outcome = if profile.divergent && !block.payload().as_slice().is_empty() {
                        divergent_exec(&tip_result, block.payload().as_slice(), &qc.block_hash)
                    } else {
                        self.app_exec(self.replicas[r].inst, &tip_result, &block)
                    };
                    let result = match outcome {
                        ExecOutcome::Valid(res) => Some(res),
                        _ => None,
                    };
                    (result, self.exec_latency(m, &block))
                };
                self.replicas[r].exec.prepared = result.map(|_| qc.block_hash);
                done(self, at + latency, Done::Prepared { op, result });
            }
            Op::Commit { op, block, qc } => {
                let inst = self.replicas[r].inst;
                let height = block.header().height;
                if self.replicas[r].exec.prepared.take() != Some(qc.block_hash) {
                    return self.fail(format!(
                        "O3: replica {r} commits {height} without its prepared post-state (another executor operation ran after its prepare)"
                    ));
                }
                let rep = &mut self.replicas[r];
                rep.applied = (height, qc.block_hash, qc.result);
                rep.bodies.retain(|_, b| b.header().height > height);
                rep.exec.cache.retain(|_, (h, _)| *h >= height);
                for (id, _) in decode_txs(block.payload().as_slice()) {
                    rep.txs.remove(&id);
                }
                let config = self.instances[inst].applied_config(height);
                let when = at + self.machines[m].profile.apply_ms;
                done(self, when, Done::Committed { op, config });
            }
            Op::Build {
                req,
                max_bytes,
                exec_budget_ms,
            } => {
                self.replicas[r].exec.prepared = None;
                self.build_payload(r, req, max_bytes, exec_budget_ms, at);
            }
            Op::Reject { block_hash } => {
                self.replicas[r].exec.prepared = None;
                self.quarantine(r, &block_hash);
            }
            Op::Effect(effect) => self.perform(r, *effect, at),
        }
    }

    // ---- crashes and restarts ---------------------------------------------------------------

    fn churn_hit(&mut self, m: usize, point: CrashPoint) -> bool {
        let Some(churn) = &self.churn else {
            return false;
        };
        if self.now < churn.from || self.now >= churn.until || self.machines[m].byz {
            return false;
        }
        if !churn.targets.is_empty() && !churn.targets.contains(&m) {
            return false;
        }
        let eligible = churn.points.contains(&point)
            || (churn.points.contains(&CrashPoint::Random) && point != CrashPoint::InsideApply);
        if !eligible {
            return false;
        }
        let down = self.machines.iter().filter(|x| !x.up).count();
        if down >= churn.max_down {
            return false;
        }
        let ppm = churn.ppm;
        self.rng.chance(ppm)
    }

    fn crash_by_churn(&mut self, m: usize) {
        let Some(churn) = self.churn.clone() else {
            return;
        };
        self.crash(m);
        let down = self.rng.range(churn.down_min, churn.down_max);
        self.schedule(self.now + down, Ev::Restart(m));
    }

    /// Crash machine `m`: every volatile state and non-durable write is lost.
    pub fn crash(&mut self, m: usize) {
        if !self.machines[m].up {
            return;
        }
        self.stats.crashes += 1;
        let machine = &mut self.machines[m];
        machine.up = false;
        machine.epoch += 1;
        machine.crashes += 1;
        let replicas: Vec<usize> = machine.replicas.iter().flatten().copied().collect();
        for r in replicas {
            let rep = &mut self.replicas[r];
            rep.host.crash();
            rep.acquisitions.clear();
            rep.io.clear();
            rep.exec.clear();
            rep.nic.clear();
            rep.txs.clear();
            rep.busy_until = self.now;
            rep.halted = None;
            rep.last_persisted.clear();
            rep.pending_ready = None;
            self.ready[r] = Millis::MAX;
        }
        let durable: Vec<(PublicKey, SafetyRecord)> = self.machines[m]
            .replicas
            .iter()
            .flatten()
            .flat_map(|r| {
                self.replicas[*r]
                    .records
                    .iter()
                    .map(|(k, d)| (k.clone(), d.record.clone()))
            })
            .collect();
        self.log
            .lock()
            .expect("signing log")
            .retract(m, |key, slot| {
                durable
                    .iter()
                    .any(|(k, record)| k == key && super::oracle::covers(record, slot))
            });
        self.trace(m, "CRASH".to_owned());
    }

    /// (Re)start machine `m` from its durable stores (§7.4 Restart): the start-up store-id check
    /// and the installation events (§7.4 record provenance), then one core per instance.
    pub fn restart(&mut self, m: usize) {
        self.machines[m].up = true;
        self.machines[m].started_at = self.now;
        let byz = self.machines[m].byz;
        let replicas: Vec<usize> = self.machines[m]
            .replicas
            .iter()
            .flatten()
            .copied()
            .collect();
        self.install_instances(m, &replicas);
        let local_now = self.machines[m].clock.local(self.now);
        for r in replicas {
            let init = self.init_for(r);
            let rep = &self.replicas[r];
            // Ground truth for the abstention oracle: a lost record (R2) must keep the key
            // from signing wherever it may have signed (Lemma 0), a store behind the record
            // (R6) below the record's height.
            let t = init.tip.height;
            self.oracle.reps[r].at_start = Some(t);
            let instance = self.instances[rep.inst].id;
            for key in &rep.keys {
                let below = match rep.records.get(key) {
                    None => self
                        .log
                        .lock()
                        .expect("signing log")
                        .max_signed_height(key, &instance)
                        .map(|h| h + 1),
                    Some(d) => Some(d.record.height).filter(|h| *h > t + 2),
                };
                if let Some(below) = below
                    && !byz
                {
                    self.log
                        .lock()
                        .expect("signing log")
                        .set_abstain(key, instance, below);
                }
            }
            let machine = (!byz).then_some(m);
            let retired = &self.machines[m].retired;
            let signers: Vec<std::sync::Arc<dyn Signer>> = rep
                .keys
                .iter()
                .filter(|key| !retired.contains(*key))
                .map(|key| -> std::sync::Arc<dyn Signer> {
                    std::sync::Arc::new(SimSigner::new(
                        key.clone(),
                        machine,
                        std::sync::Arc::clone(&self.log),
                    ))
                })
                .collect();
            let local = self.instances[rep.inst].local;
            let crypto = rep.crypto.clone();
            let start = Start {
                local,
                init,
                signers,
                crypto: Box::new(crypto),
                budget: rep.budget.clone(),
                now: local_now,
                fifo_ingress: self.machines[m].profile.fifo_ingress
                    || cfg!(sumeragi_mutation = "ML12"),
            };
            let started = self.replicas[r].host.start(start);
            match started {
                Ok(actions) => {
                    let rep = &mut self.replicas[r];
                    let core_wake = core_wakeup(&*rep.host);
                    rep.wake_mark = (core_wake, local_now);
                    if let Some(core) = rep.host.core() {
                        rep.height = core.status().height;
                    }
                    rep.busy_until = self.now;
                    rep.applied = rep.store.last().map_or_else(
                        || {
                            let instance = &self.instances[rep.inst];
                            (0, instance.genesis_hash, instance.genesis_result)
                        },
                        |(block, qc)| (block.header().height, qc.block_hash, qc.result),
                    );
                    let applied = rep.applied.0;
                    rep.bodies.retain(|_, b| b.header().height > applied);
                    self.oracle_on_start(r);
                    if !byz {
                        self.after_handle(r, &actions);
                    }
                    let actions = if byz {
                        self.byz_filter(r, actions, self.now)
                    } else {
                        actions
                    };
                    if self.replicas[r].host.owns_io() {
                        self.observe_owned(r, &actions);
                        self.poll_host(r, self.now);
                    } else {
                        self.apply_actions(r, actions, self.now);
                    }
                    self.refill_txs(r);
                    self.refresh(r);
                }
                Err(e) => {
                    self.fail(format!("replica {r}: the host did not start: {e}"));
                    return;
                }
            }
        }
        self.trace(m, "RESTART".to_owned());
    }

    /// The start-up check of the store id (§7.4 rule 3), then the installation event of every
    /// `(instance, key)` the log lacks (rule 2): the initial record `{I, K, height: g}` only for
    /// a key generated on this node, never over an existing record file.
    fn install_instances(&mut self, m: usize, replicas: &[usize]) {
        let mut store_id = self.machines[m].store_id;
        let mut keystore = std::mem::take(&mut self.machines[m].keystore);
        let rng = &mut self.rng;
        keystore.check_store_id(&mut store_id, || fresh_id(rng));
        for &r in replicas {
            let inst = self.replicas[r].inst;
            let instance = self.instances[inst].id;
            for key in self.replicas[r].keys.clone() {
                let exists = self.replicas[r].records.contains_key(&key);
                let id = fresh_id(&mut self.rng);
                if keystore.install_instance(&mut store_id, &instance, &key, exists, false, id) {
                    let record = SafetyRecord::fresh(
                        instance,
                        self.instances[inst].epoch(0).id,
                        key.clone(),
                        0,
                        None,
                    );
                    let bytes = record
                        .encode(&self.hasher)
                        .expect("encode an initial record");
                    self.replicas[r]
                        .records
                        .insert(key, Durable { record, bytes });
                }
            }
        }
        self.machines[m].keystore = keystore;
        self.machines[m].store_id = store_id;
    }

    fn refill_txs(&mut self, r: usize) {
        let inst = self.replicas[r].inst;
        let pending: Vec<(u64, bool)> = self.txs[inst]
            .iter()
            .filter(|(_, (_, _, committed))| committed.is_none())
            .map(|(id, (_, poison, _))| (*id, *poison))
            .collect();
        let Some(workload) = self.workload else {
            return;
        };
        for (id, poison) in pending {
            let tx = workload.tx(id, poison);
            self.offer_tx(r, id, tx);
        }
    }

    /// The `Init` the fake driver builds for replica `r` from its durable stores (§7.4).
    pub fn init_for(&self, r: usize) -> Init {
        let rep = &self.replicas[r];
        let inst = &self.instances[rep.inst];
        let tip = match rep.store.last() {
            None => CommittedTip {
                height: 0,
                block_hash: inst.genesis_hash,
                result: inst.genesis_result,
                header: None,
                commit_qc: None,
            },
            Some((block, qc)) => CommittedTip {
                height: block.header().height,
                block_hash: qc.block_hash,
                result: qc.result,
                header: Some(block.header().clone()),
                commit_qc: Some(qc.clone()),
            },
        };
        let t = tip.height;
        let active = inst.config(t + 1);
        let mut configs = vec![
            (t + 1, crate::types::ConfigSlot::Ready(active.clone())),
            (
                t + 2,
                crate::testing::window_slot(&active, t + 2, inst.config(t + 2)),
            ),
        ];
        if t > 0 {
            configs.push((t, crate::types::ConfigSlot::Ready(inst.config(t))));
        }
        let window = usize::try_from(inst.window + 2).unwrap_or(usize::MAX);
        let skip = rep.store.len().saturating_sub(window);
        let recent_headers = rep
            .store
            .iter()
            .skip(skip)
            .map(|(b, _)| b.header().clone())
            .collect();
        let retired = &self.machines[rep.machine].retired;
        let records = rep
            .keys
            .iter()
            .map(|key| {
                let state = rep.records.get(key).map_or(RecordState::Absent, |d| {
                    RecordState::Present(d.bytes.clone())
                });
                (key.clone(), state, retired.contains(key))
            })
            .collect();
        Init {
            instance: inst.id,
            records,
            genesis_height: 0,
            demotion_window: inst.window,
            nonce: self.nonce_for_init(),
            tip,
            configs,
            recent_headers,
        }
    }

    /// A fresh `Init.nonce` from the world's PRNG (§13.1).
    fn nonce_for_init(&self) -> u64 {
        if cfg!(sumeragi_mutation = "MR-fresh-nonce") {
            return 1;
        }
        self.nonce_source.set(
            self.nonce_source
                .get()
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0x632b_e59b_d9b4_e019),
        );
        self.nonce_source.get()
    }

    fn apply_fault(&mut self, fault: Fault) {
        match fault {
            Fault::Crash(m) => self.crash(m),
            Fault::Restart(m) => {
                if !self.machines[m].up {
                    self.restart(m);
                }
            }
            Fault::CrashAll => {
                for m in 0..self.machines.len() {
                    self.crash(m);
                }
            }
            Fault::RestartAll => {
                for m in 0..self.machines.len() {
                    if !self.machines[m].up {
                        self.restart(m);
                    }
                }
            }
            Fault::CorruptRecord(m, i) => {
                if let Some(r) = self.machines[m].replicas.get(i).copied().flatten() {
                    for durable in self.replicas[r].records.values_mut() {
                        if let Some(byte) = durable.bytes.get_mut(7) {
                            *byte ^= 0x5a;
                        }
                    }
                }
            }
            Fault::DeleteRecord(m, i) => {
                if let Some(r) = self.machines[m].replicas.get(i).copied().flatten() {
                    self.replicas[r].records.clear();
                }
            }
            Fault::RestoreKeyStore(m) => {
                if let Some(snapshot) = self.machines[m].snapshot.clone() {
                    self.machines[m].keystore = snapshot;
                }
            }
            Fault::ReplaceRecordStore(m) => self.replace_record_store(m),
            Fault::ReinstallKey(m) => {
                self.replace_record_store(m);
                let mut keystore = KeyStore::default();
                let mut store_id = None;
                for key in self.machines[m].keys.clone() {
                    let id = fresh_id(&mut self.rng);
                    keystore.install_key(&mut store_id, &key, false, id);
                }
                self.machines[m].keystore = keystore;
                self.machines[m].store_id = store_id;
            }
            Fault::RetireKey(m, slot) => {
                let key = self.machines[m].keys.get(slot).cloned();
                if let Some(key) = key {
                    self.machines[m].retired.insert(key);
                }
            }
            Fault::ForgeRecordParent(m, i) => {
                if let Some(r) = self.machines[m].replicas.get(i).copied().flatten() {
                    let hasher = self.hasher.clone();
                    for durable in self.replicas[r].records.values_mut() {
                        if let Some(qc) = durable.record.parent_commit_qc.as_mut() {
                            qc.block_hash = Hash32([0x66; 32]);
                            if let Ok(bytes) = durable.record.encode(&hasher) {
                                durable.bytes = bytes;
                            }
                        }
                    }
                }
            }
            Fault::TruncateStore(m, i, k) => {
                if let Some(r) = self.machines[m].replicas.get(i).copied().flatten() {
                    let rep = &mut self.replicas[r];
                    let keep = rep.store.len().saturating_sub(k);
                    rep.store.truncate(keep);
                }
            }
            Fault::Custom(f) => f(self),
        }
    }

    /// A new, empty record store for machine `m`: every record file and the store id are gone.
    fn replace_record_store(&mut self, m: usize) {
        for r in self.machines[m].replicas.clone().into_iter().flatten() {
            self.replicas[r].records.clear();
        }
        self.machines[m].store_id = None;
    }

    /// Pre-build a committed chain of `len` heights signed by the genesis committee's keys
    /// (logged as genuine signatures) into the stores of `holders` (F17).
    fn prebuild(&mut self, len: u64, holders: &[usize]) {
        let inst = self.instances[0].clone();
        let signers: Vec<SimSigner> = inst
            .committee(1)
            .members()
            .iter()
            .map(|k| SimSigner::new(k.clone(), None, std::sync::Arc::clone(&self.log)))
            .collect();
        let chain = super::oracle::build_chain(&inst, &signers, len, &self.hasher);
        // The pre-built history was exposed long ago.
        for (_, qc) in &chain {
            let msg = qc.preimage();
            if let Some(keys) = inst.committee(qc.height).keys_of(&qc.signers) {
                for key in keys {
                    self.log.lock().expect("signing log").expose(key, &msg);
                }
            }
        }
        for &m in holders {
            if let Some(r) = self.machines[m].replicas.first().copied().flatten() {
                self.replicas[r].store.clone_from(&chain);
            }
        }
        self.oracle.adopt_chain(0, &chain);
    }

    /// Replica of machine `m` in instance `inst`.
    pub fn replica_of(&self, m: usize, inst: usize) -> Option<usize> {
        self.machines.get(m)?.replicas.get(inst).copied().flatten()
    }

    /// Committed height of replica `r` (core tip; store tip while crashed).
    pub fn committed(&self, r: usize) -> u64 {
        let rep = &self.replicas[r];
        rep.host.core().map_or_else(
            || u64::try_from(rep.store.len()).unwrap_or(0),
            |core| core.status().committed_height,
        )
    }

    /// Transaction interval of the workload (upper end), if any.
    pub fn workload_every(&self) -> Option<Millis> {
        self.workload.map(|w| w.every_max)
    }

    /// Ground-truth topology of height `h` of instance `inst` (reference chain headers).
    pub fn ground_topology(&self, inst: usize, h: u64) -> crate::topology::Topology {
        let instance = &self.instances[inst];
        let window = instance.window;
        let lo = h.saturating_sub(1 + window).max(1);
        let headers: Vec<crate::message::BlockHeader> = (lo..h.saturating_sub(1))
            .filter_map(|x| self.oracle.refs[inst].get(&x).map(|b| b.header.clone()))
            .collect();
        crate::topology::Topology::compute(
            &self.hasher,
            &instance.id,
            &instance.epoch(h),
            instance.committee(h),
            h,
            0,
            window,
            &headers,
        )
    }

    /// Honest replicas.
    pub fn honest(&self) -> Vec<usize> {
        (0..self.replicas.len())
            .filter(|r| !self.machines[self.replicas[*r].machine].byz)
            .collect()
    }
}

/// The core's own next deadline behind a host (`Millis::MAX` while it is not running).
fn core_wakeup(host: &dyn Host) -> Millis {
    host.core().map_or(Millis::MAX, crate::Core::next_wakeup)
}

/// A short description of a host's device operation for verbose traces.
fn describe_op(op: &Op) -> String {
    match op {
        Op::WriteRecord { op, record } => format!("write-record#{op} h{}", record.height),
        Op::WriteBody { op, block } => format!("write-body#{op} h{}", block.header().height),
        Op::Execute { op, block, .. } => format!("execute#{op} h{}", block.header().height),
        Op::Discard { op, height, .. } => format!("discard#{op} h{height}"),
        Op::Prepare { op, block, .. } => format!("prepare#{op} h{}", block.header().height),
        Op::Append { op, block, .. } => format!("append#{op} h{}", block.header().height),
        Op::Commit { op, block, .. } => format!("commit#{op} h{}", block.header().height),
        Op::Build { req, .. } => format!("build req{req}"),
        Op::Reject { .. } => "reject".to_owned(),
        Op::Effect(effect) => summarize(std::slice::from_ref(&**effect)),
    }
}

fn describe_event(event: &Event) -> String {
    match event {
        Event::Tick => "Tick".to_owned(),
        Event::Message { msg, .. } => describe_msg(msg),
        Event::PayloadBuilt { req, payload } => {
            format!(
                "PayloadBuilt req{req} {}B",
                payload.as_ref().map_or(0, |value| value.as_slice().len())
            )
        }
        Event::ControlWitnessBuilt { req, context, .. } => {
            format!("ControlWitnessBuilt req{req} h{}", context.height)
        }
        Event::ApplicationControlBuilt { message } => {
            format!("ApplicationControlBuilt h{}", message.context.height)
        }
        Event::PayloadAuthored { req, body } => {
            format!("PayloadAuthored req{req} h{}", body.header().height)
        }
        Event::ManifestRejected { manifest } => {
            format!("ManifestRejected h{}", manifest.header.height)
        }
        Event::PayloadReady { req } => format!("PayloadReady req{req}"),
        Event::Executed { req, outcome, .. } => format!("Executed req{req} {outcome:?}"),
        Event::BodyAvailable { block } => format!("BodyAvailable h{}", block.header().height),
        Event::BlockApplied { height, .. } => format!("BlockApplied h{height}"),
        Event::ApplyDiverged { height, .. } => format!("ApplyDiverged h{height}"),
        Event::PublicationRecoveryRequired { height } => {
            format!("PublicationRecoveryRequired h{height}")
        }
    }
}

/// A one-line summary of an action list for verbose traces.
fn summarize(actions: &[Action]) -> String {
    let mut out = String::new();
    for action in actions {
        let item = match action {
            Action::PersistSafety(r) => format!(
                "persist(h{} p{:?} l{:?} t{:?})",
                r.height,
                r.prepare.map(|v| v.view),
                r.lock.as_ref().map(|q| q.view),
                r.timeout.as_ref().map(|t| t.view)
            ),
            Action::StoreBody { block } => format!("store(h{})", block.header().height),
            Action::Send { to, msg } => format!(
                "send[{}]{}",
                &format!("{to:?}")[3..11],
                describe_msg(msg).trim_start_matches("<- ")
            ),
            Action::Broadcast { to, msg } => {
                format!(
                    "bcast[{}]{}",
                    to.len(),
                    describe_msg(msg).trim_start_matches("<- ")
                )
            }
            Action::BuildControlWitness { req, context } => format!(
                "build_control(req{req} h{} v{})",
                context.height, context.view
            ),
            Action::DriveApplicationControl { context } => {
                format!("drive_control(h{})", context.height)
            }
            Action::ReceiveApplicationControl { message, .. } => {
                format!("receive_control(h{})", message.context.height)
            }
            Action::BuildPayload {
                req, height, view, ..
            } => format!("build(req{req} h{height} v{view})"),
            Action::AuthorPayload { req, header, .. } => {
                format!("author(req{req} h{})", header.height)
            }
            Action::AcquirePayload { source, .. } => format!("acquire(h{})", source.height()),
            Action::ReceivePayloadChunk { chunk, .. } => {
                format!("row(h{} i{})", chunk.height, chunk.index)
            }
            Action::DisseminatePayload { body, peers } => format!(
                "disseminate(h{} {} peers)",
                body.header().height,
                peers.len()
            ),
            Action::Execute {
                block,
                req,
                certified,
            } => format!(
                "exec(h{} req{req}{})",
                block.header().height,
                if *certified { " certified" } else { "" }
            ),
            Action::DiscardExecution { height, keep } => {
                format!("discard(h{height} keep {})", keep.len())
            }
            Action::CommitBlock { block, .. } => format!("COMMIT(h{})", block.header().height),
            Action::FetchPayload { source, peers } => {
                format!("fetch(h{} {} peers)", source.height(), peers.len())
            }
            Action::ServePayload { height, .. } => format!("serve_body(h{height})"),
            Action::ServeBlocks { from_height, .. } => format!("serve_blocks({from_height})"),
            Action::PayloadRejected { height, .. } => format!("rejected(h{height})"),
            Action::ReportEvidence(_) => "EVIDENCE".to_owned(),
            Action::LocalFault(f) => format!("fault({f:?})"),
            Action::Halt(h) => format!("HALT({h:?})"),
        };
        out.push_str(&item);
        out.push(' ');
    }
    out
}

/// A short description of a message for traces.
pub fn describe_msg(msg: &WireMessage) -> String {
    match msg {
        WireMessage::Proposal(p) => format!(
            "<- Proposal h{} v{} manifest {}",
            p.proposal.height,
            p.proposal.view,
            p.availability.as_slice().len()
        ),
        WireMessage::Vote(v) => format!(
            "<- Vote {:?} h{} v{} from #{}",
            v.kind, v.height, v.view, v.signer
        ),
        WireMessage::Qc(q) => format!("<- Qc {:?} h{} v{}", q.kind, q.height, q.view),
        WireMessage::Timeout(t) => format!(
            "<- Timeout h{} v{} hq {:?} from #{}",
            t.height,
            t.view,
            t.hq(),
            t.signer
        ),
        WireMessage::Tc(t) => format!("<- Tc h{} v{} max_hq {:?}", t.height, t.view, t.max_hq()),
        WireMessage::Status(s) => format!(
            "<- Status h{} v{} cqc {:?}{}{}{}",
            s.height,
            s.view,
            s.committed_qc.as_ref().map(|q| q.height),
            if s.want_proposal { " want" } else { "" },
            if s.probe.is_some() { " probe" } else { "" },
            if s.echo.is_some() { " echo" } else { "" },
        ),
        WireMessage::SyncRequest(q) => format!("<- SyncRequest from {}", q.from_height),
        WireMessage::SyncResponse(q) => format!("<- SyncResponse {} blocks", q.blocks.len()),
        WireMessage::PayloadRequest(q) => format!("<- PayloadRequest h{}", q.height),
        WireMessage::PayloadManifest(q) => format!("<- PayloadManifest h{}", q.header.height),
        WireMessage::PayloadChunk(q) => format!("<- PayloadChunk h{} i{}", q.height, q.index),
        WireMessage::ApplicationControl(message) => {
            format!("<- ApplicationControl h{}", message.context.height)
        }
    }
}

/// Seeds to run: `SUMERAGI_SIM_SEED` (one seed) or `SUMERAGI_SIM_SEEDS` (count, from
/// `SUMERAGI_SIM_SEED_BASE`), else `default` seeds from 0.
///
/// # Panics
/// Rejects malformed selected settings, a zero count or a range exceeding `u64`.
pub fn seeds(default: u64) -> Vec<u64> {
    seed_iter(default).collect()
}

/// Iterate the same configured seed range without retaining a campaign-sized seed list.
///
/// # Panics
/// Rejects malformed selected settings, a zero count or a range exceeding `u64`.
pub(super) fn seed_iter(default: u64) -> impl Iterator<Item = u64> {
    seed_config::from_env(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured original owned constructor: the epoch-only projection must preserve every field.
    fn original_config(instance: &Inst, height: u64) -> HeightConfig {
        let index = instance
            .schedule
            .iter()
            .rposition(|(from, _)| *from <= height)
            .unwrap_or(0);
        let first = instance.schedule[index].0;
        let last = instance
            .schedule
            .get(index + 1)
            .map_or(u64::MAX, |(from, _)| from - 1);
        HeightConfig {
            epoch: Box::new(crate::testing::scheduled_epoch(index as u64, first, last)),
            committee: instance.committee(height).clone(),
            params: instance.params,
        }
    }

    #[test]
    fn epoch_only_lookup_preserves_complete_configuration_at_rotation_boundaries() {
        let first = crate::testing::FakeValidators::new(4, 1, None).committee;
        let second = crate::testing::FakeValidators::new(7, 2, None).committee;
        let third = crate::testing::FakeValidators::new(4, 3, None).committee;
        for schedule in [
            vec![(0, first.clone())],
            vec![(0, first), (8, second), (19, third)],
        ] {
            let instance = Inst {
                id: Hash32([1; 32]),
                genesis_hash: Hash32([2; 32]),
                genesis_result: Hash32([3; 32]),
                schedule,
                params: ChainParams::default(),
                window: 5,
                local: LocalParams::default(),
            };
            for height in [0, 1, 6, 7, 8, 9, 17, 18, 19, 20, u64::MAX - 1, u64::MAX] {
                let original = original_config(&instance, height);
                // EpochConfig equality covers layout, full id, generation, both bounds and seed.
                assert_eq!(instance.epoch(height), *original.epoch, "height {height}");
                assert_eq!(instance.config(height), original, "height {height}");
            }
            for &(boundary, _) in instance.schedule.iter().skip(1) {
                let previous = instance.epoch(boundary - 1);
                let successor = instance.epoch(boundary);
                assert!(previous.contains(boundary - 1));
                assert!(!previous.contains(boundary));
                assert!(successor.contains(boundary));
                assert!(successor.follows(&previous));
            }
        }
    }
}
