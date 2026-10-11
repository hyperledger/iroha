//! Scenario descriptions: everything a run needs besides the seed-derived randomness — the
//! committee and its schedule, network, clocks, per-machine profiles, Byzantine strategies,
//! scripted faults, crash churn, the workload and which oracles and bounds apply.

use super::{
    byz::{NetRule, Strategy},
    driver::Clock,
    host::{HostFactory, fake_host},
    net::NetConfig,
    world::World,
};
use crate::{
    api::LocalParams,
    types::{ChainParams, Millis},
};

/// Per-machine resources of the fake driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent fault switches
pub struct Profile {
    /// Execution latency of an empty block.
    pub exec_base: Millis,
    /// Extra execution latency per KiB of payload.
    pub exec_per_kib: Millis,
    /// Extra execution latency of every non-empty payload, unknown to the payload builder
    /// (its `exec_budget` estimate is wrong: a machine slower than calibrated; F15).
    pub exec_nonempty: Millis,
    /// O4 with preemption: a `DiscardExecution` that leaves the running job out of `keep`
    /// aborts it and answers `Cancelled` at once, so the next `Execute` starts without waiting
    /// for the discarded work (otherwise the running job finishes first; F15).
    pub abort_discarded: bool,
    /// Probability (ppm) that an execution reports `Failed`.
    pub exec_fail_ppm: u32,
    /// Divergent (nondeterministic) executor (F21).
    pub divergent: bool,
    /// A deterministic executor defect: every transaction payload is `Invalid` (F19).
    pub reject_nonempty: bool,
    /// Probability (ppm), per finished execution, of evicting a random cached post-state.
    pub evict_ppm: u32,
    /// Write latency range.
    pub write_min: Millis,
    /// Write latency range.
    pub write_max: Millis,
    /// Probability (ppm) that a write fails and is retried (ENOSPC/EIO, F27).
    pub write_fail_ppm: u32,
    /// Retry backoff of a failed write.
    pub write_retry: Millis,
    /// Virtual CPU cost per pairing (µs).
    pub cpu_us_per_pairing: u64,
    /// Virtual CPU cost per handled event (µs).
    pub cpu_us_per_event: u64,
    /// Payload build latency range.
    pub build_min: Millis,
    /// Payload build latency range.
    pub build_max: Millis,
    /// Apply latency after the block store write.
    pub apply_ms: Millis,
    /// Extra latency of block-store writes (F32).
    pub block_write_extra: Millis,
    /// Ingress without priority lanes (FIFO; only to show that `det_l12` detects ML12).
    pub fifo_ingress: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            exec_base: 10,
            exec_per_kib: 1,
            exec_nonempty: 0,
            abort_discarded: false,
            exec_fail_ppm: 0,
            divergent: false,
            reject_nonempty: false,
            evict_ppm: 0,
            write_min: 1,
            write_max: 4,
            write_fail_ppm: 0,
            write_retry: 20,
            cpu_us_per_pairing: 150,
            cpu_us_per_event: 50,
            build_min: 1,
            build_max: 5,
            apply_ms: 5,
            block_write_extra: 0,
            fifo_ingress: false,
        }
    }
}

/// A scripted fault or intervention at a fixed time.
pub enum Fault {
    /// Crash a machine (non-durable writes are lost).
    Crash(usize),
    /// Restart a crashed machine from its durable stores.
    Restart(usize),
    /// Crash every machine at once.
    CrashAll,
    /// Restart every crashed machine.
    RestartAll,
    /// Corrupt the durable safety record of a machine's replica of an instance (R1).
    CorruptRecord(usize, usize),
    /// Delete the durable safety records of a machine's replica of an instance (R2).
    DeleteRecord(usize, usize),
    /// Restore a machine's key store (with its installation log) from its snapshot; the record
    /// files and the store id are untouched (§7.4 record provenance rule 3).
    RestoreKeyStore(usize),
    /// Replace a machine's record store by a new, empty one (all record files and the store id
    /// are gone).
    ReplaceRecordStore(usize),
    /// Reinstall a machine's keys from a KMS onto a new disk: a new key store in which every
    /// key is imported, and an empty record store (every record `Absent`).
    ReinstallKey(usize),
    /// Stop configuring machine `m`'s key of slot `slot` for signing: it becomes retired (its
    /// record and log entries are kept, §7.4 Keys). Effective at the next restart.
    RetireKey(usize, usize),
    /// Drop the last `k` blocks of a replica's block store (Kura tail loss, R5/R6).
    TruncateStore(usize, usize, usize),
    /// Replace the parent `CommitQC` in a replica's durable record by a forged one, with a
    /// valid checksum (a consistent but wrong record; R5 must refuse it).
    ForgeRecordParent(usize, usize),
    /// Anything else, with full access to the world.
    Custom(Box<dyn Fn(&mut World)>),
}

impl core::fmt::Debug for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crash(m) => write!(f, "Crash({m})"),
            Self::Restart(m) => write!(f, "Restart({m})"),
            Self::CrashAll => write!(f, "CrashAll"),
            Self::RestartAll => write!(f, "RestartAll"),
            Self::CorruptRecord(m, i) => write!(f, "CorruptRecord({m}, {i})"),
            Self::DeleteRecord(m, i) => write!(f, "DeleteRecord({m}, {i})"),
            Self::RestoreKeyStore(m) => write!(f, "RestoreKeyStore({m})"),
            Self::ReplaceRecordStore(m) => write!(f, "ReplaceRecordStore({m})"),
            Self::ReinstallKey(m) => write!(f, "ReinstallKey({m})"),
            Self::RetireKey(m, slot) => write!(f, "RetireKey({m}, {slot})"),
            Self::TruncateStore(m, i, k) => write!(f, "TruncateStore({m}, {i}, {k})"),
            Self::ForgeRecordParent(m, i) => write!(f, "ForgeRecordParent({m}, {i})"),
            Self::Custom(_) => write!(f, "Custom"),
        }
    }
}

/// Where churn crashes land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Random: in the middle of any action list or at any write completion.
    Random,
    /// Right after a `PersistSafety` recording a proposal (before durability).
    ProposalRecord,
    /// Right after a `PersistSafety` recording a new vote (before durability).
    VoteRecord,
    /// Right after a `PersistSafety` recording a timeout (before durability).
    TimeoutRecord,
    /// Right after a write becomes durable, before held effects leave.
    AfterDurable,
    /// Between the block store write and `BlockApplied` (inside apply).
    InsideApply,
}

/// Random crash-restart churn (F13).
#[derive(Clone, Debug)]
pub struct Churn {
    /// Window start.
    pub from: Millis,
    /// Window end (no crash after it; every machine is restarted by then).
    pub until: Millis,
    /// Crash probability (ppm) per eligible point.
    pub ppm: u32,
    /// Down time range.
    pub down_min: Millis,
    /// Down time range.
    pub down_max: Millis,
    /// At most this many machines down at once.
    pub max_down: usize,
    /// Crash points.
    pub points: Vec<CrashPoint>,
    /// Machines eligible (empty = all honest).
    pub targets: Vec<usize>,
}

/// Kill one machine at its `nth` write completion (§13.5 O2 conformance: nothing externally
/// visible may precede durability, whichever completion the process dies at).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoKill {
    /// The machine.
    pub machine: usize,
    /// Which of its write completions (counted from 1 over the whole run).
    pub nth: u64,
    /// Kill just before the write becomes durable (it is lost), else right after it became
    /// durable and before anything waiting for it takes effect.
    pub before_durable: bool,
    /// Down time before the restart.
    pub down: Millis,
}

/// Transaction workload of an instance.
#[derive(Clone, Copy, Debug)]
pub struct Workload {
    /// Interval between transactions (uniform range).
    pub every_min: Millis,
    /// Interval between transactions (uniform range).
    pub every_max: Millis,
    /// Padding bytes per transaction.
    pub pad: u16,
    /// Probability (ppm) that a transaction is poison (F19).
    pub poison_ppm: u32,
    /// No transactions after this time.
    pub until: Millis,
    /// Bit mask of the machines that receive transactions (0 = all; F35 local-queue
    /// asymmetry).
    pub targets: u64,
    /// Every `due_every`-th transaction applies due application work, so the block holding it
    /// is subject to the stale-due-work guard of a [`ClockGuard`] world (§4.5 CT5); 0 = none.
    pub due_every: u64,
}

impl Workload {
    /// Whether transaction `id` applies due work (§4.5 CT5).
    pub fn due(&self, id: u64) -> bool {
        self.due_every > 0 && id.is_multiple_of(self.due_every)
    }

    /// The encoding of transaction `id` with this workload's flags and padding.
    pub fn tx(&self, id: u64, poison: bool) -> Vec<u8> {
        super::driver::encode_tx_with_due(id, poison, self.due(id), self.pad)
    }
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            every_min: 100,
            every_max: 300,
            pad: 32,
            poison_ppm: 0,
            until: Millis::MAX,
            targets: 0,
            due_every: 0,
        }
    }
}

/// The application clock guard of the simulator's toy application (§4.5), the model of the node
/// driver's executor rules CT1, CT3 and CT5. Without it (the default) payloads carry no block
/// time and no execution consults a clock, as F12 requires of the core.
///
/// With it, every payload builder stamps its payload with a block time `t = wall + lead`
/// (honest builders: `lead = 0`, CT3), and every honest executor answers
/// `Failed(ClockAhead)` for an execution with `certified = false` while
/// `t > wall + max_clock_drift_ms` (CT1), and `Failed(StaleDueWork)` for an uncertified
/// execution of a block that applies due work while `wall − t > due_work_max_lag_ms` (CT5).
/// Byzantine executors run no guard. Apply and replay never consult the clock (CT2). A
/// machine's wall clock is its monotonic clock plus a wall offset that scripts may step
/// ([`World::set_wall_offset`]), so a wall clock can converge without moving the core's time.
#[derive(Clone, Debug, Default)]
pub struct ClockGuard {
    /// `max_clock_drift_ms`, the committed chain parameter of CT1 (CT4).
    pub max_clock_drift_ms: Millis,
    /// `gov.due_work_max_lag_ms`, the committed governance parameter of CT5.
    pub due_work_max_lag_ms: Millis,
    /// Initial wall offsets (ms) per machine, relative to its monotonic clock (missing: 0).
    pub wall_offsets: Vec<i64>,
    /// Builder leads (ms) per machine: the `k`-th payload the machine builds is stamped
    /// `wall + leads[k % len]`. Missing or empty: `[0]` (an honest builder, CT3); a Byzantine
    /// builder may post-date (positive) or back-date (negative) its blocks.
    pub leads: Vec<(usize, Vec<i64>)>,
}

/// Performance bound checked by O-PERF (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perf {
    /// No performance bound.
    None,
    /// P1: all honest, loss ≤ 1 %.
    P1,
    /// P2: one vote-withholding member.
    P2,
    /// P3: silent or withholding proxy tail.
    P3,
    /// P4: one crashed member.
    P4,
    /// P5: first commit after heal.
    P5,
    /// P6: tick lateness under a flood.
    P6,
    /// Every gap within the P4 leader-turn bound (at most one failed view per height; ML18),
    /// without P4's count limit.
    OneViewFailure,
    /// Sparse local work (F35, §8.1): the workload reaches only the honest machines of this
    /// bit mask (the holders), each of which builds every block from its whole queue. Let
    /// `v*(h)` be the first view `v ≥ 1` whose leader `L(h, v)` (ground-truth topology, §2.1)
    /// is a running holder. Every height commits in a view `≤ v*(h)` (§6.10: new work wakes
    /// the eligible leader; §8.2 L4), within `Σ_{v ≤ v*(h)} (P(v) + T(level(h, v)) + σ + Δ)`
    /// of the replica's entry (§9.1; §8.2 L1, L2), and every transaction by the second height
    /// first committed after its submission (Appendix E, E62). Requires a workload interval
    /// `every_max` below `P(0) + T(0) + P(1) + T(1)` minus the commit latency, so a holder
    /// leading any view `≥ 1` holds work before that view ends.
    LeaderTurns(u64),
}

/// Which oracles and bounds apply to a scenario.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // independent oracle switches
pub struct Checks {
    /// O-LIVE after `heal_at`.
    pub liveness: bool,
    /// O-PERF bound.
    pub perf: Perf,
    /// Sanity: every honest running node commits at least this many heights after heal.
    pub progress: u64,
    /// After the minimum duration, finish missing progress under already established O-LIVE
    /// deadlines. Only a genuine commit starts another deadline; the progress target is fixed.
    pub complete_progress: bool,
    /// O-TXP (poison present).
    pub txp: bool,
    /// O-CQ (no crashes).
    pub cq: bool,
    /// Machines allowed to halt (injected corruption or divergence), for O-HALT.
    pub may_halt: Vec<usize>,
    /// Machines allowed to report executor faults (O-FAULT).
    pub may_fault: Vec<usize>,
    /// No view change after heal: every committed block is proposed and committed in view 0
    /// (F9r: the round in progress at GST still commits in view 0).
    pub no_view_change: bool,
    /// Instances exempt from O-LIVE/progress until the given time (F31 stalls).
    pub stalled: Vec<(usize, Millis)>,
    /// `(instance, from, until, heights)`: at least `heights` commits in the window.
    pub windows: Vec<(usize, Millis, Millis, usize)>,
}

impl Default for Checks {
    fn default() -> Self {
        Self {
            liveness: true,
            perf: Perf::None,
            progress: 3,
            complete_progress: false,
            txp: false,
            cq: false,
            may_halt: Vec::new(),
            may_fault: Vec::new(),
            no_view_change: false,
            stalled: Vec::new(),
            windows: Vec::new(),
        }
    }
}

/// Committee schedule: from height → members as `(machine, key slot)`.
pub type CommitteeSchedule = Vec<(u64, Vec<(usize, usize)>)>;

/// A complete scenario.
pub struct Scenario {
    /// Name (e.g. `F5`).
    pub name: String,
    /// Seed of this run.
    pub seed: u64,
    /// Size of the initial committee (machines `0..n`).
    pub n: usize,
    /// Machines outside the initial committee (joiners, observers).
    pub extra: usize,
    /// Number of consensus instances in the world.
    pub instances: usize,
    /// Every instance uses the same keys (F20).
    pub shared_keys: bool,
    /// Simulated duration.
    pub duration: Millis,
    /// Heal time / GST `t_g`.
    pub heal_at: Millis,
    /// Local parameters of every node.
    pub local: LocalParams,
    /// Chain parameters.
    pub params: ChainParams,
    /// The demotion window `W` (a genesis constant of every instance, §2.1).
    pub demotion_window: u64,
    /// Take a snapshot of every key store after the keys are installed and before any instance
    /// starts (restored by [`Fault::RestoreKeyStore`]).
    pub keystore_snapshot: bool,
    /// Network.
    pub net: NetConfig,
    /// Per-machine clocks (missing entries: default clock).
    pub clocks: Vec<Clock>,
    /// Per-machine profiles (missing entries: default profile).
    pub profiles: Vec<Profile>,
    /// Byzantine machines and their strategies.
    pub byz: Vec<(usize, Vec<Strategy>)>,
    /// Rules of the network adversary (before heal).
    pub net_rules: Vec<NetRule>,
    /// `Strategy::SilentLeader` stays honest before this time.
    pub silent_leader_from: Millis,
    /// Scripted faults.
    pub script: Vec<(Millis, Fault)>,
    /// Random crash churn.
    pub churn: Option<Churn>,
    /// Kill a machine at one write completion (§13.5 O2).
    pub io_kill: Option<IoKill>,
    /// Workload (per instance), `None` = idle.
    pub workload: Option<Workload>,
    /// Optional toy AMX application over the same unmodified consensus instances.
    pub amx: Option<super::amx::AmxConfig>,
    /// Optional application clock guard (§4.5) with per-machine wall clocks and block times.
    pub clock_guard: Option<ClockGuard>,
    /// Committee schedule: from height → members as `(machine, key slot)`; the first entry
    /// must start at height 0 (it is the genesis committee).
    pub committees: CommitteeSchedule,
    /// Committee schedules of individual instances that differ from [`Self::committees`]
    /// (`(instance, schedule)`), e.g. a lane instance whose committee is a subset of the global
    /// one. Instance 0 always uses [`Self::committees`].
    pub instance_committees: Vec<(usize, CommitteeSchedule)>,
    /// Every machine follows every instance: a machine without a key in an instance's schedule
    /// runs it as an observer (the node's lane rule, `specs/sumeragi_lanes.md` §4.1). Otherwise
    /// only machines outside the initial committee observe.
    pub follow_all_instances: bool,
    /// Oracles and bounds.
    pub checks: Checks,
    /// Pre-built committed chain length (F17): machines in `prebuilt_holders` start with it.
    pub prebuilt: u64,
    /// Machines whose stores hold the pre-built chain.
    pub prebuilt_holders: Vec<usize>,
    /// The node implementation of every replica (§13.5; default: the fake driver).
    pub host: HostFactory,
}

impl Scenario {
    /// A lossless all-honest scenario of `n` validators with default parameters.
    pub fn base(name: &str, seed: u64, n: usize) -> Self {
        let n = n.max(1);
        Self {
            name: name.to_owned(),
            seed,
            n,
            extra: 0,
            instances: 1,
            shared_keys: false,
            duration: 60_000,
            heal_at: 0,
            local: LocalParams::for_committee_size(n),
            params: ChainParams::default(),
            demotion_window: 128,
            keystore_snapshot: false,
            net: NetConfig::default(),
            clocks: Vec::new(),
            profiles: Vec::new(),
            byz: Vec::new(),
            net_rules: Vec::new(),
            silent_leader_from: 0,
            script: Vec::new(),
            churn: None,
            io_kill: None,
            workload: Some(Workload::default()),
            amx: None,
            clock_guard: None,
            committees: vec![(0, (0..n).map(|m| (m, 0)).collect())],
            instance_committees: Vec::new(),
            follow_all_instances: false,
            checks: Checks::default(),
            prebuilt: 0,
            prebuilt_holders: Vec::new(),
            host: fake_host,
        }
    }

    /// Machines in the world.
    pub fn machines(&self) -> usize {
        self.n + self.extra
    }

    /// Profile of machine `m`.
    pub fn profile(&self, m: usize) -> Profile {
        self.profiles.get(m).copied().unwrap_or_default()
    }

    /// Whether machine `m` is Byzantine.
    pub fn is_byz(&self, m: usize) -> bool {
        self.byz.iter().any(|(b, _)| *b == m)
    }

    /// Set the profile of machine `m`.
    pub fn set_profile(&mut self, m: usize, profile: Profile) {
        if self.profiles.len() <= m {
            self.profiles.resize(m + 1, Profile::default());
        }
        self.profiles[m] = profile;
    }
}
