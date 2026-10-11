//! Oracles of §13.2, checked after every event of every honest replica: O-AGR, O-VAL, O-SIGN
//! (in the provenance log at signing time), O-PBS (at the first exposure of every own
//! signature), O-CERT (every certificate a core holds or commits on), O-LIVE, O-PERF (P1–P6),
//! O-MEM, O-HALT, O-EVID, O-FAULT, O-TXP, O-CQ and O-TIME
//! (the certified-time bound of the application clock guard, §4.5, in `world::clock_guard`).

use std::collections::{BTreeMap, BTreeSet};

use super::{
    crypto::{SigSlot, SimSigner, aggregate, parse_preimage},
    driver::{decode_txs, encode_tx, reference_exec},
    host::BacklogBound,
    scenario::Perf,
    world::{Inst, World},
};
use crate::{
    api::{Action, CoreStatus, ExecOutcome, LocalFault, LocalParams},
    availability::AvailableBody,
    crypto::{Crypto, Signer},
    message::{BlockHeader, Evidence, Proposal, Qc, TimeoutCert, VoteKind, WireMessage},
    pacemaker::{
        PHI_DEN, PHI_NUM, ceil_log2, effective_t_max, level_cap, propose_allowance, view_timeout,
    },
    preimage::{self, KIND_COMMIT, KIND_ECHO, KIND_PREPARE, KIND_PROPOSAL, KIND_TIMEOUT},
    safety::SafetyRecord,
    testing::fake_sig,
    topology::Topology,
    types::{Bitmap, ChainParams, Hash32, Millis, PublicKey},
};

#[cfg(test)]
std::thread_local! {
    static HELD_CERTIFICATE_COPIES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

// Count the actual held-certificate copies in tests without changing the oracle's verdicts.
fn clone_held_certificate<T: Clone>(certificate: &T) -> T {
    #[cfg(test)]
    HELD_CERTIFICATE_COPIES.with(|copies| {
        if let Some(count) = copies.get() {
            copies.set(Some(count + 1));
        }
    });
    certificate.clone()
}

/// A committed block of the reference chain.
#[derive(Clone, Debug)]
pub struct RefBlock {
    /// `AvailableBody` hash.
    pub bh: Hash32,
    /// Certified result.
    pub result: Hash32,
    /// Header.
    pub header: BlockHeader,
    /// First commit time.
    pub at: Millis,
    /// Proposed by an honest machine.
    pub honest_proposer: bool,
    /// View of the `CommitQC`.
    pub view: u64,
}

/// Per-replica observations.
#[derive(Clone, Debug, Default)]
pub struct RepObs {
    /// Committed height seen.
    pub committed: u64,
    /// Time of the last commit.
    pub last_commit: Millis,
    /// Last `CommitBlock` height emitted (contiguity).
    pub emitted: u64,
    /// O-LIVE window start.
    pub window: Millis,
    /// O-LIVE deadline.
    pub deadline: Millis,
    /// Committed height at heal time.
    pub at_heal: Option<u64>,
    /// Committed height when the replica last (re)started (its store tip).
    pub at_start: Option<u64>,
    /// First commit after heal.
    pub first_after_heal: Option<Millis>,
    /// Commit gaps after heal: `(height, gap, t̂)` with `t̂ = φ·T(level)/2` (§8.2).
    pub gaps: Vec<(u64, Millis, Millis)>,
    checked_lock: Option<Qc>,
    checked_tc: Option<TimeoutCert>,
    checked_cqc: Option<Qc>,
    /// Largest `t_retx` reported.
    pub max_t_retx: Millis,
    /// Highest start level reported (§9.2 adaptation, F15).
    pub max_start_level: u32,
    /// Highest start level before the scenario's heal boundary (F36's deliberate crash).
    pub max_start_level_before_heal: u32,
    /// [`Perf::LeaderTurns`]: the replica's uncommitted height and its bound.
    pub turn: Option<Turn>,
}

/// [`Perf::LeaderTurns`] state of a replica at its uncommitted height (Appendix E, E62).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Turn {
    /// The height.
    pub height: u64,
    /// When the replica was first observed at the height.
    pub entry: Millis,
    /// `v*(height)` and the machine leading it (`None`: no running holder leads a view).
    pub first: Option<(u64, usize)>,
    /// The start level the bound was computed with (the highest reported at the height).
    pub level: u32,
    /// `entry` plus the leader-turn bound ([`leader_turns_bound`]).
    pub deadline: Millis,
}

/// Oracle state of a world.
#[derive(Clone, Debug, Default)]
pub struct Oracle {
    /// Reference chain per instance.
    pub refs: Vec<BTreeMap<u64, RefBlock>>,
    /// Payloads built by honest builders: `(instance, machine, payload hash)`.
    pub built: BTreeSet<(usize, usize, Hash32)>,
    /// Per-replica observations.
    pub reps: Vec<RepObs>,
    heal_seen: bool,
    live_min: Millis,
    events_since_prune: u64,
    /// P5 deadline per replica.
    p5: Vec<Option<Millis>>,
    /// First broadcast of each block proposed by an honest leader.
    pub proposed: BTreeMap<Hash32, Millis>,
    /// Sum and count of proposal-to-commit latencies over honest commits.
    latency: (u64, u64),
    /// Per instance: whether the O-LIVE precondition held at the last evaluation (`≥ q`
    /// honest, running members that may sign; §1 Liveness, §13.2 O-LIVE).
    live_ok: Vec<bool>,
    /// When the precondition was last evaluated (every 50 virtual ms at most).
    live_eval_at: Option<Millis>,
    /// [`Perf::LeaderTurns`]: the machine owning `L(h, v)` for `v = 0 ..= a_h` per
    /// `(instance, height)` (ground-truth topology, one full rotation).
    turn_leaders: BTreeMap<(usize, u64), Vec<Option<usize>>>,
    /// [`Perf::LeaderTurns`]: the highest start level an honest replica reported at
    /// `(instance, height)` (timers are local, §9.1).
    turn_levels: BTreeMap<(usize, u64), u32>,
}

impl Oracle {
    /// Oracle state for `replicas` replicas.
    pub fn new(replicas: usize) -> Self {
        Self {
            reps: vec![RepObs::default(); replicas],
            p5: vec![None; replicas],
            live_min: Millis::MAX,
            ..Self::default()
        }
    }

    /// Initialise the reference chains.
    pub fn init(&mut self, instances: &[Inst]) {
        self.refs = vec![BTreeMap::new(); instances.len()];
        self.live_ok = vec![true; instances.len()];
    }

    /// Average simulated latency from an honest proposal to each honest node's commit.
    pub fn commit_latency(&self) -> Millis {
        self.latency.0 / self.latency.1.max(1)
    }

    /// Adopt a pre-built chain as committed (F17).
    pub fn adopt_chain(&mut self, inst: usize, chain: &[(AvailableBody, Qc)]) {
        for (block, qc) in chain {
            self.refs[inst].insert(
                block.header().height,
                RefBlock {
                    bh: qc.block_hash,
                    result: qc.result,
                    header: block.header().clone(),
                    at: 0,
                    honest_proposer: true,
                    view: qc.view,
                },
            );
        }
    }
}

/// Whether a durable record covers a signature (§7.4 O-PBS): for a proposal, Prepare or
/// timeout the same height and entry at a view `≥`, or a higher height; for a Commit at
/// `(h, v)` a record at `h` whose lock has view `≥ v`, or a higher height. Probe echoes carry no
/// sign-once obligation and are exempt.
pub fn covers(record: &SafetyRecord, slot: &SigSlot) -> bool {
    if slot.kind == KIND_ECHO {
        return true;
    }
    if record.instance != slot.instance || record.height < slot.height {
        return false;
    }
    if record.height > slot.height {
        return true;
    }
    if record.epoch != slot.epoch {
        return false;
    }
    match slot.kind {
        KIND_PROPOSAL => record
            .proposal
            .as_ref()
            .is_some_and(|p| p.view >= slot.view),
        KIND_PREPARE => record.prepare.is_some_and(|v| v.view >= slot.view),
        KIND_COMMIT => record.lock.as_ref().is_some_and(|q| q.view >= slot.view),
        KIND_TIMEOUT => record.timeout.as_ref().is_some_and(|t| t.view >= slot.view),
        _ => true,
    }
}

/// [`Perf::LeaderTurns`]: the longest a replica stays at a height whose views `0 .. turns`
/// fail and whose view `turns` commits (Appendix E, E62). Each view `v ≤ turns` lasts at most
/// its anchor allowance and timer, `P(v) + T(min(level_cap, start + v))` (§9.1), plus `slack`
/// for the entry skew and the certificate that ends it (`σ + Δ`, §8.2 L1, L2).
pub fn leader_turns_bound(
    local: &LocalParams,
    params: &ChainParams,
    t_max_eff: Millis,
    start: u32,
    turns: u64,
    slack: Millis,
) -> Millis {
    let cap = level_cap(local.t_base, t_max_eff);
    (0..=turns)
        .map(|v| {
            let level = u32::try_from(v)
                .unwrap_or(u32::MAX)
                .saturating_add(start)
                .min(cap);
            propose_allowance(v, params, local.build_timeout)
                .saturating_add(view_timeout(local.t_base, t_max_eff, level))
                .saturating_add(slack)
        })
        .fold(0, Millis::saturating_add)
}

/// Build a committed chain of `len` transaction blocks at view 0 using one exact quorum
/// from `signers` at each height (F17), selected in canonical committee order.
pub fn build_chain(
    inst: &Inst,
    signers: &[SimSigner],
    len: u64,
    crypto: &dyn Crypto,
) -> Vec<(AvailableBody, Qc)> {
    let mut chain = Vec::new();
    let (mut parent_hash, mut parent_result) = (inst.genesis_hash, inst.genesis_result);
    for h in 1..=len {
        let committee = inst.committee(h);
        let topo = Topology::compute(
            crypto,
            &inst.id,
            &inst.config(h).epoch,
            committee,
            h,
            0,
            inst.window,
            &[],
        );
        let payload = encode_tx(u64::MAX - h, false, 0);
        let header = BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: inst.config(h).epoch.id,
            instance: inst.id,
            height: h,
            origin_view: 0,
            parent_hash,
            parent_result,
            payload_hash: preimage::payload_hash(crypto, &payload),
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).unwrap(),
            proposer: topo.leader(0),
            skipped_leaders: Vec::new(),
            // The application flags no plain payload, at an epoch boundary or elsewhere.
        };
        let author = signers
            .iter()
            .find(|signer| committee.get(header.proposer) == Some(signer.public_key()))
            .expect("prebuilt author key");
        let block = crate::testing::author_body(
            header,
            &payload,
            &inst.config(h),
            &iroha_allocation::AllocationBudget::new(1 << 30),
            crypto,
            author,
        );
        let bh = block.hash(crypto);
        let ExecOutcome::Valid(result) = reference_exec(&parent_result, &payload) else {
            break;
        };
        let msg = preimage::vote_preimage(
            VoteKind::Commit,
            &inst.id,
            &inst.config(h).epoch.id,
            h,
            0,
            &bh,
            &result,
        );
        let mut indices = Vec::new();
        let mut sigs = Vec::new();
        let members: BTreeMap<_, _> = signers
            .iter()
            .filter_map(|signer| {
                committee
                    .index_of(signer.public_key())
                    .map(|index| (index, signer))
            })
            .collect();
        for (index, signer) in members.into_iter().take(committee.q()) {
            indices.push(index);
            sigs.push(signer.sign(&msg));
        }
        assert_eq!(
            indices.len(),
            committee.q(),
            "prebuilt history needs a complete quorum"
        );
        let qc = Qc {
            epoch: inst.config(h).epoch.id,
            kind: VoteKind::Commit,
            instance: inst.id,
            height: h,
            view: 0,
            block_hash: bh,
            result,
            signers: Bitmap::from_indices(committee.n(), indices.iter().copied())
                .unwrap_or_else(|| Bitmap::new(committee.n())),
            agg_sig: aggregate(&sigs),
        };
        chain.push((block, qc));
        parent_hash = bh;
        parent_result = result;
    }
    chain
}

/// Scenario-level timing constants used by the performance bounds (§8.2).
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// `G_norm = X + E + 5Δ + 4δ`.
    pub g_norm: Millis,
    /// `Δ`.
    pub delta: Millis,
    /// `B_live` without the lag term.
    pub b_live: Millis,
    /// Lag term per `sync_batch` heights.
    pub per_batch: Millis,
    /// `sync_batch`.
    pub batch: u64,
    /// `σ = rebroadcast_interval + Δ`.
    pub sigma: Millis,
    /// `F`.
    pub fetch: Millis,
    /// `E`.
    pub exec: Millis,
    /// `P(0) + T(start = 0) + G_norm`.
    pub p4: Millis,
    /// `T_req` with the scenario's `Δ` (§8.2 L3).
    pub t_req: Millis,
    /// `rebroadcast_interval`.
    pub rebroadcast: Millis,
    /// `ε_tick` (P6).
    pub eps_tick: Millis,
}

impl World {
    /// Timing constants of instance `inst` for a replica of machine `m`.
    pub fn bounds(&self, inst: usize, m: usize) -> Bounds {
        let instance = &self.instances[inst];
        let local = instance.local;
        let params = instance.params;
        let committee = instance.committee(1);
        let n = committee.n();
        let f = u64::try_from(committee.f()).unwrap_or(0);
        let profile = self.machines[m].profile;
        let cpu = |pairings: u64| pairings * profile.cpu_us_per_pairing / 1_000;
        let n64 = u64::try_from(n).unwrap_or(1);
        let small = u64::from(self.net.bandwidth == 0 || self.net.bandwidth >= 100_000);
        let serialization = if small == 1 {
            n64 * 2
        } else {
            n64 * u64::from(params.max_block_bytes) / self.net.bandwidth.max(1)
        };
        let delta = self.net.delta() + serialization + cpu(4 * n64 + 8) + 5;
        let small_delta = profile.write_max + cpu(2 * n64 + 2) + 2;
        let loaded = self
            .workload_every()
            .is_some_and(|every| every < params.block_time);
        let x = if loaded {
            params.block_time
        } else {
            params.payload_retry_interval
        };
        let exec = profile.exec_base + profile.exec_per_kib * 8;
        let g_norm = x + exec + 5 * delta + 4 * small_delta;
        let t_max = effective_t_max(&local, &instance.config(1));
        let cap = level_cap(local.t_base, t_max);
        let fetch = u64::from(ceil_log2(f + 1)) * local.fetch_retry;
        let b_view = t_max
            + params.payload_retry_interval
            + 2 * local.build_timeout
            + 2 * local.rebroadcast_interval
            + 4 * delta
            + fetch;
        let b_live = (f + 2 + u64::from(cap)) * b_view;
        let batch = u64::from(local.sync_batch);
        let per_batch = local.sync_retry + 2 * delta + batch * (params.a_max + params.e_max);
        // The view-0 anchor allowance `P(0) = payload_retry_interval + build_timeout` (§9.1): no
        // timer depends on a node's own queue.
        let p0 = params.payload_retry_interval + local.build_timeout;
        let sigma = local.rebroadcast_interval + delta;
        let t_req = 2
            * (sigma + local.build_timeout + 3 * delta + fetch + params.a_max + params.e_max)
            + 4 * small_delta;
        Bounds {
            g_norm,
            delta,
            b_live,
            per_batch,
            batch,
            sigma,
            fetch,
            exec,
            p4: p0 + view_timeout(local.t_base, t_max, 0) + g_norm,
            t_req,
            rebroadcast: local.rebroadcast_interval,
            // One non-preemptible event at most: a certificate-laden `Status` or proposal
            // (≤ q + 8 pairings), plus rounding.
            eps_tick: 2
                + cpu(u64::try_from(committee.q()).unwrap_or(1) + 8)
                + profile.cpu_us_per_event / 1_000,
        }
    }

    /// `t̂ = φ·T(level)/2`, the upper end of the `t_retx` clamp at `level` (§8.2).
    pub fn t_hat(&self, inst: usize, level: u32) -> Millis {
        let local = self.instances[inst].local;
        let t_max = effective_t_max(&local, &self.instances[inst].config(1));
        // (Only on commits: `config` clones the committee.)
        view_timeout(local.t_base, t_max, level) * PHI_NUM / PHI_DEN / 2
    }

    /// Heal time of instance `inst` (stalls of F31 extend it).
    pub fn heal_of(&self, inst: usize) -> Millis {
        self.checks
            .stalled
            .iter()
            .filter(|(i, _)| *i == inst)
            .map(|(_, until)| *until)
            .max()
            .unwrap_or(0)
            .max(self.heal_at)
    }

    fn honest_running(&self, r: usize) -> bool {
        let rep = &self.replicas[r];
        let m = &self.machines[rep.machine];
        !m.byz && m.up && rep.host.core().is_some() && rep.halted.is_none()
    }

    /// Checks after every `handle` of an honest replica.
    pub fn after_handle(&mut self, r: usize, actions: &[Action]) {
        let violations = self.log.lock().expect("signing log").take_violations();
        if let Some(v) = violations.into_iter().next() {
            return self.fail(v);
        }
        self.check_view_change(actions);
        let commits = std::mem::take(&mut self.log.lock().expect("signing log").commits);
        for (m, msg) in commits {
            if let Err(e) = self.commit_backed(&msg) {
                return self.fail(format!("O-SIGN: honest machine {m} {e}"));
            }
        }
        self.observe_core(r);
        for action in actions {
            match action {
                Action::CommitBlock { block, commit_qc } => self.check_commit(r, block, commit_qc),
                Action::ReportEvidence(evidence) => self.check_evidence(r, evidence),
                Action::LocalFault(
                    LocalFault::ExecutorFailed { .. } | LocalFault::ExecutionMismatch { .. },
                ) => {
                    let m = self.replicas[r].machine;
                    if !self.checks.may_fault.contains(&m) {
                        self.fail(format!(
                            "O-FAULT: honest machine {m} reported {action:?} without an injected fault"
                        ));
                    }
                }
                Action::Halt(reason) => {
                    let m = self.replicas[r].machine;
                    if !self.checks.may_halt.contains(&m) {
                        self.fail(format!("O-HALT: honest machine {m} halted: {reason:?}"));
                    }
                }
                _ => {}
            }
        }
        self.oracle.events_since_prune += 1;
        if self.oracle.events_since_prune >= 5_000 {
            self.oracle.events_since_prune = 0;
            let low = self
                .honest()
                .into_iter()
                .map(|r| self.committed(r))
                .min()
                .unwrap_or(0);
            // A margin: a store restored from backup re-syncs (and re-verifies) old heights.
            self.log
                .lock()
                .expect("signing log")
                .prune_below(low.saturating_sub(256));
        }
    }

    /// O-MEM, O-CERT on held certificates, and commit progress of replica `r`.
    fn observe_core(&mut self, r: usize) {
        let Some(core) = self.replicas[r].host.core() else {
            return;
        };
        let status = core.status();
        let bound = core.footprint_bound();
        if !status.footprint.within(&bound) {
            return self.fail(format!(
                "O-MEM: replica {r} footprint {:?} exceeds {bound:?}",
                status.footprint
            ));
        }
        // Durable bodies remain available for delayed certificates until their height
        // applies. Model the production store's finite 1 GiB capacity; local memory
        // remains independently bounded above. A view count is not a custody proof.
        let limit = 1_u64 << 30;
        let applied = self.replicas[r].applied.0;
        let mut per_height: BTreeMap<u64, u64> = BTreeMap::new();
        for block in self.replicas[r].bodies.values() {
            *per_height.entry(block.header().height).or_default() +=
                u64::try_from(block.payload().as_slice().len()).unwrap_or(u64::MAX);
        }
        if let Some((h, bytes)) = per_height
            .iter()
            .find(|(h, bytes)| **h <= applied || **bytes > limit)
        {
            return self.fail(format!(
                "O-MEM: replica {r} body store holds {bytes} payload bytes at height {h} (applied {applied}, limit {limit})"
            ));
        }
        // O-MEM of the queues of a host that owns its scheduling (§13.5).
        if let Some(backlog) = self.replicas[r].host.backlog() {
            let rep = &self.replicas[r];
            let keys = rep.keys.len().max(rep.records.len());
            let bound = BacklogBound::new(keys, self.replicas.len(), applied, limit);
            if let Some(excess) = backlog.exceeds(&bound) {
                return self.fail(format!("O-MEM: replica {r} host queues: {excess}"));
            }
        }
        let inst = self.replicas[r].inst;
        let obs = &self.oracle.reps[r];
        let new_lock = core
            .lock()
            .filter(|q| obs.checked_lock.as_ref() != Some(*q))
            .map(clone_held_certificate);
        let new_tc = core
            .highest_tc()
            .filter(|t| obs.checked_tc.as_ref() != Some(*t))
            .map(clone_held_certificate);
        let new_cqc = core
            .committed_qc()
            .filter(|q| obs.checked_cqc.as_ref() != Some(*q))
            .map(clone_held_certificate);
        if let Some(q) = &new_lock {
            if let Err(e) = self.cert_qc(inst, q) {
                return self.fail(format!("O-CERT: replica {r} holds lock {e}"));
            }
            self.oracle.reps[r].checked_lock = Some(q.clone());
        }
        if let Some(t) = &new_tc {
            if let Err(e) = self.cert_tc(inst, t) {
                return self.fail(format!("O-CERT: replica {r} holds TC {e}"));
            }
            self.oracle.reps[r].checked_tc = Some(t.clone());
        }
        if let Some(q) = &new_cqc {
            if let Err(e) = self.cert_qc(inst, q) {
                return self.fail(format!("O-CERT: replica {r} committed on {e}"));
            }
            if q.kind != VoteKind::Commit {
                return self.fail(format!("O-CERT: replica {r} committed on a PrepareQC"));
            }
            self.oracle.reps[r].checked_cqc = Some(q.clone());
        }
        if status.start_level > self.oracle.reps[r].max_start_level {
            self.trace(r, format!("start level increased: {status:?}"));
        }
        let obs = &mut self.oracle.reps[r];
        obs.max_t_retx = obs.max_t_retx.max(status.t_retx);
        obs.max_start_level = obs.max_start_level.max(status.start_level);
        if self.now < self.heal_at {
            obs.max_start_level_before_heal =
                obs.max_start_level_before_heal.max(status.start_level);
        }
        if status.committed_height > obs.committed {
            // `t̂` of the committed height's view 0: its start level is within one of the level
            // the node entered the next height with (§9.2), so the next level up bounds it.
            let t_hat = self.t_hat(inst, status.start_level.saturating_add(1));
            let obs = &mut self.oracle.reps[r];
            let jumped = status.committed_height > obs.committed + 1;
            let old = obs.committed;
            obs.committed = status.committed_height;
            let gap = self.now.saturating_sub(obs.last_commit);
            let had_commit = obs.last_commit > 0 || old > 0;
            obs.last_commit = self.now;
            self.on_commit(
                r,
                status.committed_height,
                gap,
                t_hat,
                jumped || !had_commit,
            );
        }
        if self.failure.is_none() {
            self.check_turns(r, &status);
        }
    }

    /// `no_view_change` (F9r): after heal every height commits in view 0 with a block first
    /// proposed there (no timer may move).
    fn check_view_change(&mut self, actions: &[Action]) {
        if !self.checks.no_view_change || self.now < self.heal_at {
            return;
        }
        for action in actions {
            if let Action::CommitBlock { block, commit_qc } = action
                && (commit_qc.view > 0 || block.header().origin_view > 0)
            {
                return self.fail(format!(
                    "O-PERF no view change: height {} committed in view {} (origin view {}); a \
                     timer moved",
                    block.header().height,
                    commit_qc.view,
                    block.header().origin_view
                ));
            }
        }
    }

    /// [`Perf::LeaderTurns`] at honest replica `r` (Appendix E, E62): a replica never passes
    /// `v*(h)` at its uncommitted height `h`, and it commits `h` by its leader-turn deadline.
    fn check_turns(&mut self, r: usize, status: &CoreStatus) {
        let Perf::LeaderTurns(holders) = self.checks.perf else {
            return;
        };
        let inst = self.replicas[r].inst;
        if self.now < self.heal_of(inst) {
            return;
        }
        let height = status.height;
        let previous = self.oracle.reps[r].turn;
        if let Some(turn) = previous
            && turn.height != height
        {
            // The replica left `turn.height` in this handle; it committed it at the latest now.
            self.oracle.reps[r].turn = None;
            if status.committed_height >= turn.height && self.now > turn.deadline {
                return self.turn_late(r, &turn);
            }
        }
        if status.awaiting || height <= status.committed_height {
            return;
        }
        let level = self.oracle.turn_levels.entry((inst, height)).or_default();
        *level = (*level).max(status.start_level);
        let level = *level;
        let first = self.first_holder_turn(inst, height, holders);
        let turn = match self.oracle.reps[r].turn {
            Some(turn) if turn.first == first && turn.level == level => turn,
            other => {
                let entry = other.map_or(self.now, |turn| turn.entry);
                let deadline = first.map_or(Millis::MAX, |(view, _)| {
                    entry.saturating_add(self.turns_budget(inst, r, height, level, view))
                });
                Turn {
                    height,
                    entry,
                    first,
                    level,
                    deadline,
                }
            }
        };
        self.oracle.reps[r].turn = Some(turn);
        if let Some((view, m)) = first
            && status.view > view
        {
            return self.fail(format!(
                "O-PERF LeaderTurns: replica {r} is in view {} of height {height}, past view \
                 {view} led by running holder machine {m} (§6.10, §8.2 L4)",
                status.view
            ));
        }
        if self.now > turn.deadline {
            self.turn_late(r, &turn);
        }
    }

    fn turn_late(&mut self, r: usize, turn: &Turn) {
        self.fail(format!(
            "O-PERF LeaderTurns: replica {r} entered height {} at t={} and did not commit it by \
             t={} (v* {:?}, start level {})",
            turn.height, turn.entry, turn.deadline, turn.first, turn.level
        ));
    }

    /// `v*(height)`: the first view `v ≥ 1` whose leader is a running honest holder that may
    /// sign, and that machine (`None` if no view of a whole rotation has one).
    fn first_holder_turn(
        &mut self,
        inst: usize,
        height: u64,
        holders: u64,
    ) -> Option<(u64, usize)> {
        if !self.oracle.turn_leaders.contains_key(&(inst, height)) {
            let topo = self.ground_topology(inst, height);
            let committee = self.instances[inst].committee(height);
            let rotation = topo.n().saturating_sub(topo.demoted().len());
            let leaders = (0..=u64::try_from(rotation).unwrap_or(u64::MAX))
                .map(|view| {
                    committee
                        .get(topo.leader(view))
                        .and_then(|key| self.key_owner.get(key).copied())
                })
                .collect();
            self.oracle
                .turn_leaders
                .retain(|(i, h), _| *i != inst || h.saturating_add(16) >= height);
            self.oracle
                .turn_levels
                .retain(|(i, h), _| *i != inst || h.saturating_add(16) >= height);
            self.oracle.turn_leaders.insert((inst, height), leaders);
        }
        let leaders = self.oracle.turn_leaders.get(&(inst, height))?;
        leaders.iter().enumerate().skip(1).find_map(|(view, m)| {
            let m = (*m)?;
            let holder = u32::try_from(m)
                .ok()
                .and_then(|bit| 1u64.checked_shl(bit))
                .is_some_and(|bit| holders & bit != 0);
            let running = self.replica_of(m, inst).is_some_and(|x| {
                self.honest_running(x)
                    && self.replicas[x]
                        .host
                        .core()
                        .is_some_and(|core| !core.abstaining())
            });
            (holder && running).then(|| (u64::try_from(view).unwrap_or(u64::MAX), m))
        })
    }

    /// The leader-turn bound of replica `r` at `height` with start level `level` and
    /// `v*(height) = turns`, with O-LIVE's 3 % margin for clock drift.
    fn turns_budget(&self, inst: usize, r: usize, height: u64, level: u32, turns: u64) -> Millis {
        let instance = &self.instances[inst];
        let b = self.bounds(inst, self.replicas[r].machine);
        let t_max = effective_t_max(&instance.local, &instance.config(height));
        leader_turns_bound(
            &instance.local,
            &instance.params,
            t_max,
            level,
            turns,
            b.sigma + b.delta,
        ) * 103
            / 100
    }

    fn on_commit(&mut self, r: usize, height: u64, gap: Millis, t_hat: Millis, skip_gap: bool) {
        let inst = self.replicas[r].inst;
        let heal = self.heal_of(inst);
        if self.now < heal {
            return;
        }
        let obs = &mut self.oracle.reps[r];
        if obs.first_after_heal.is_none() {
            obs.first_after_heal = Some(self.now);
        }
        let started = self.machines[self.replicas[r].machine].started_at;
        if !skip_gap && self.now.saturating_sub(gap) >= heal.max(started) {
            obs.gaps.push((height, gap, t_hat));
            self.check_gap(r, gap, t_hat);
        }
        self.reset_live(r);
    }

    /// O-PERF on one commit gap (P1–P4 per-gap bounds, with `t̂` for `t_retx`, §8.2).
    fn check_gap(&mut self, r: usize, gap: Millis, t_hat: Millis) {
        let m = self.replicas[r].machine;
        let b = self.bounds(self.replicas[r].inst, m);
        let limit = match self.checks.perf {
            // SPEC: §8.2 P1 bounds every gap by `G_norm + rebroadcast_interval` at ≤ 1 % loss.
            // A proposal lost to two members the quorum needs (e.g. n = 5, q = n − 1) is only
            // recovered once they see evidence of it (a stage-2 vote at the latest, about
            // `2·t_retx` after the others voted) or by the leader's re-push: up to
            // `2·rebroadcast_interval + Δ` (F9 seeds 34, 274, 284). That is the bound checked
            // (Appendix E, E8).
            Perf::P1 => b.g_norm + 2 * b.rebroadcast + b.delta,
            Perf::P2 => b.g_norm + t_hat.max(b.rebroadcast),
            Perf::P3 => b.g_norm + 2 * t_hat + b.delta,
            Perf::P4 | Perf::OneViewFailure => b.p4 + 2 * t_hat + b.delta,
            // Bounded per height and view by `check_turns` instead.
            Perf::None | Perf::P5 | Perf::P6 | Perf::LeaderTurns(_) => return,
        };
        if gap > limit {
            self.fail(format!(
                "O-PERF {:?}: replica {r} commit gap {gap} ms > {limit} ms (G_norm {}, t̂ {t_hat})",
                self.checks.perf, b.g_norm
            ));
        }
    }

    /// Start a new O-LIVE window for replica `r`.
    fn reset_live(&mut self, r: usize) {
        let inst = self.replicas[r].inst;
        let heal = self.heal_of(inst);
        let b = self.bounds(inst, self.replicas[r].machine);
        let max = self
            .honest()
            .into_iter()
            .filter(|x| self.replicas[*x].inst == inst)
            .map(|x| self.committed(x))
            .max()
            .unwrap_or(0);
        let lag = max.saturating_sub(self.committed(r));
        let lag_term = lag.div_ceil(b.batch.max(1)) * b.per_batch;
        let start = self.now.max(heal);
        // Clock drift (±1 %) stretches local timers: 3 % margin.
        let budget = (b.b_live + lag_term) * 103 / 100;
        let obs = &mut self.oracle.reps[r];
        obs.window = start;
        obs.deadline = start + budget;
        self.oracle.live_min = self.oracle.live_min.min(obs.deadline);
    }

    /// The O-LIVE precondition of instance `inst` (§1 Liveness, §13.2): at least `q` members
    /// of the current committee are honest, running, and able to sign — a member with an
    /// unanchored key counts as faulty until it anchors, and one whose key abstains at its
    /// height counts as faulty there (R2, R6).
    pub(super) fn live_precondition(&self, inst: usize) -> bool {
        let height = self
            .replicas
            .iter()
            .filter(|rep| rep.inst == inst && !self.machines[rep.machine].byz)
            .map(|rep| rep.height)
            .max()
            .unwrap_or(1);
        let committee = self.instances[inst].committee(height);
        let able = committee
            .members()
            .iter()
            .filter_map(|key| self.key_owner.get(key))
            .filter_map(|m| self.replica_of(*m, inst))
            .filter(|r| {
                self.honest_running(*r)
                    && self.replicas[*r]
                        .host
                        .core()
                        .is_some_and(|core| !core.abstaining())
            })
            .count();
        let work = self
            .replicas
            .iter()
            .filter(|rep| rep.inst == inst)
            .any(|rep| {
                !self.machines[rep.machine].byz
                    && rep.txs.iter().any(|(id, bytes)| {
                        !rep.quarantine.contains(id)
                            && decode_txs(bytes).iter().any(|(_, poison)| !poison)
                    })
            });
        let lagging = self
            .replicas
            .iter()
            .filter(|rep| rep.inst == inst)
            .map(|rep| rep.applied.0)
            .min()
            .is_some_and(|minimum| minimum + 1 < height);
        able >= committee.q() && (work || lagging)
    }

    /// O-LIVE and P5 deadlines (called at every step).
    pub fn check_live(&mut self) {
        if !self.oracle.heal_seen && self.now >= self.heal_at {
            self.oracle.heal_seen = true;
            for r in self.honest() {
                self.oracle.reps[r].at_heal = Some(self.committed(r));
                self.reset_live(r);
                if self.checks.perf == Perf::P5 {
                    self.set_p5(r);
                }
            }
        }
        if !self.checks.liveness {
            return;
        }
        // While the precondition fails for an instance its liveness is not required; when it
        // holds again, its O-LIVE windows restart (evaluated every 50 virtual ms at most).
        let due = self
            .oracle
            .live_eval_at
            .is_none_or(|at| self.now >= at.saturating_add(50));
        if self.oracle.heal_seen && due {
            self.oracle.live_eval_at = Some(self.now);
            for inst in 0..self.instances.len() {
                let ok = self.live_precondition(inst);
                let was = self.oracle.live_ok.get(inst).copied().unwrap_or(true);
                if ok != was {
                    if let Some(slot) = self.oracle.live_ok.get_mut(inst) {
                        *slot = ok;
                    }
                    if ok {
                        for r in self.honest() {
                            if self.replicas[r].inst == inst {
                                self.reset_live(r);
                            }
                        }
                    }
                }
            }
        }
        if self.now < self.oracle.live_min {
            return;
        }
        let mut next = Millis::MAX;
        for r in self.honest() {
            let inst = self.replicas[r].inst;
            if self.now < self.heal_of(inst) {
                continue;
            }
            if !self.honest_running(r) || !self.oracle.live_ok.get(inst).copied().unwrap_or(true) {
                continue;
            }
            let deadline = self.oracle.reps[r].deadline;
            if self.now > deadline {
                return self.fail(format!(
                    "O-LIVE: honest replica {r} committed nothing since t={} (bound {} ms)",
                    self.oracle.reps[r].window,
                    deadline - self.oracle.reps[r].window
                ));
            }
            next = next.min(deadline);
        }
        self.oracle.live_min = next;
    }

    /// P5 (§8.2): the first commit after heal at every honest node by
    /// `t_g + P(0) + Σ_{L=ℓ..max(ℓ, k*)} (T(L) + Δ) + 2σ + F + E + 5Δ`, with `ℓ` the level of
    /// the node's current view at `t_g` and `k* = min{L : T(L) ≥ T_req}`.
    fn set_p5(&mut self, r: usize) {
        let Some(core) = self.replicas[r].host.core() else {
            return;
        };
        let level = core.status().level;
        let inst = self.replicas[r].inst;
        let local = self.instances[inst].local;
        let params = self.instances[inst].params;
        let t_max = effective_t_max(&local, &self.instances[inst].config(1));
        let b = self.bounds(inst, self.replicas[r].machine);
        let cap = level_cap(local.t_base, t_max);
        let k_star = (0..=cap)
            .find(|l| view_timeout(local.t_base, t_max, *l) >= b.t_req)
            .unwrap_or(cap);
        let views: Millis = (level..=level.max(k_star))
            .map(|l| view_timeout(local.t_base, t_max, l) + b.delta)
            .sum();
        let p0 = params.payload_retry_interval + local.build_timeout;
        let bound = p0 + views + 2 * b.sigma + b.fetch + b.exec + 5 * b.delta;
        self.oracle.p5[r] = Some(self.heal_at + bound * 103 / 100);
    }

    /// A (re)start: contiguity restarts at the store tip, O-LIVE window restarts.
    pub fn oracle_on_start(&mut self, r: usize) {
        let tip = u64::try_from(self.replicas[r].store.len()).unwrap_or(0);
        let obs = &mut self.oracle.reps[r];
        obs.emitted = tip;
        obs.committed = obs.committed.min(tip).max(tip);
        obs.checked_lock = None;
        obs.checked_tc = None;
        obs.checked_cqc = None;
        // A restarted replica enters its height anew (§7.4: start level 0).
        obs.turn = None;
        if self.oracle.heal_seen {
            self.reset_live(r);
        }
    }

    /// O-AGR and O-VAL on a `CommitBlock` of an honest replica.
    fn check_commit(&mut self, r: usize, block: &AvailableBody, qc: &Qc) {
        let inst = self.replicas[r].inst;
        let h = block.header().height;
        let emitted = self.oracle.reps[r].emitted;
        if h != emitted + 1 {
            return self.fail(format!(
                "O-AGR: replica {r} committed height {h} after {emitted} (not contiguous)"
            ));
        }
        self.oracle.reps[r].emitted = h;
        if let Some(t) = self.oracle.proposed.get(&qc.block_hash) {
            self.oracle.latency.0 += self.now.saturating_sub(*t);
            self.oracle.latency.1 += 1;
        }
        if let Err(e) = self.cert_qc(inst, qc) {
            return self.fail(format!("O-CERT: replica {r} CommitBlock {h} with {e}"));
        }
        if let Some(known) = self.oracle.refs[inst].get(&h) {
            if (known.bh, known.result) != qc.value() {
                return self.fail(format!(
                    "O-AGR: replica {r} committed {:?} at height {h}, another honest node committed {:?}",
                    qc.value(),
                    (known.bh, known.result)
                ));
            }
            return;
        }
        if let Err(e) = self.validity(inst, block, qc) {
            return self.fail(format!("O-VAL: replica {r} height {h}: {e}"));
        }
        let proposer_key = self.instances[inst]
            .committee(h)
            .get(block.header().proposer)
            .cloned();
        let proposer = proposer_key.and_then(|k| self.key_owner.get(&k).copied());
        let honest_proposer = proposer.is_some_and(|m| !self.machines[m].byz);
        for (id, _) in decode_txs(block.payload().as_slice()) {
            if let Some(entry) = self.txs[inst].get_mut(&id)
                && entry.2.is_none()
            {
                entry.2 = Some(self.now);
            }
        }
        self.oracle.refs[inst].insert(
            h,
            RefBlock {
                bh: qc.block_hash,
                result: qc.result,
                header: block.header().clone(),
                at: self.now,
                honest_proposer,
                view: qc.view,
            },
        );
        // O-TIME: the application clock guard's certified-time bound (§4.5).
        self.check_certified_time(inst, block, qc.block_hash, proposer);
    }

    fn validity(&self, inst: usize, block: &AvailableBody, qc: &Qc) -> Result<(), String> {
        let instance = &self.instances[inst];
        let h = block.header().height;
        if block.header().epoch != instance.config(h).epoch.id || qc.epoch != block.header().epoch {
            return Err(
                "block or certificate epoch context differs from authenticated schedule".into(),
            );
        }
        if qc.kind != VoteKind::Commit || qc.height != h {
            return Err("not a CommitQC of the block's height".to_owned());
        }
        if block.hash(&self.hasher) != qc.block_hash {
            return Err("block hash differs from the CommitQC's".to_owned());
        }
        let proof = crate::availability::verify_availability(
            instance.id,
            &instance.config(h),
            block.header(),
            block.availability().as_slice(),
            &self.hasher,
        )
        .map_err(|error| format!("original availability rejected: {error:?}"))?;
        let mut codeword = vec![0; proof.shape().encoded_bytes()];
        let mut scratch = vec![0; proof.shape().workspace_words()];
        proof
            .verify_payload(
                block.payload().as_slice(),
                &mut codeword,
                &mut scratch,
                &self.hasher,
            )
            .map_err(|error| format!("actual canonical codeword rejected: {error:?}"))?;
        let (parent_hash, parent_result) = if h == 1 {
            (instance.genesis_hash, instance.genesis_result)
        } else {
            let parent = self.oracle.refs[inst]
                .get(&(h - 1))
                .ok_or("parent not committed")?;
            (parent.bh, parent.result)
        };
        if block.header().parent_hash != parent_hash
            || block.header().parent_result != parent_result
        {
            return Err("does not extend the committed parent".to_owned());
        }
        if block.header().instance != instance.id {
            return Err("foreign instance".to_owned());
        }
        match self.app_exec(inst, &parent_result, block) {
            ExecOutcome::Valid(expected) if expected == qc.result => {}
            other => return Err(format!("result {:?} but reference {other:?}", qc.result)),
        }
        let window = instance.window;
        let lo = h.saturating_sub(1 + window).max(1);
        let headers: Vec<BlockHeader> = (lo..h.saturating_sub(1))
            .filter_map(|x| self.oracle.refs[inst].get(&x).map(|b| b.header.clone()))
            .collect();
        let topo = Topology::compute(
            &self.hasher,
            &instance.id,
            &instance.config(h).epoch,
            instance.committee(h),
            h,
            0,
            window,
            &headers,
        );
        if block.header().proposer != topo.leader(block.header().origin_view) {
            return Err(format!(
                "proposer {} is not L(h, {}) = {}",
                block.header().proposer,
                block.header().origin_view,
                topo.leader(block.header().origin_view)
            ));
        }
        let proposer = instance
            .committee(h)
            .get(block.header().proposer)
            .and_then(|k| self.key_owner.get(k).copied());
        if let Some(m) = proposer
            && !self.machines[m].byz
            && !block.payload().as_slice().is_empty()
            && !self
                .oracle
                .built
                .contains(&(inst, m, block.header().payload_hash))
        {
            return Err(format!("payload was not built by the honest proposer {m}"));
        }
        Ok(())
    }

    /// S3 (SR5): an honest Commit `(h, v, bh, R)` is backed by a `PrepareQC` of the same view
    /// and value — at least `q` members of `C_h` genuinely signed the Prepare preimage.
    fn commit_backed(&self, commit: &[u8]) -> Result<(), String> {
        let Some(slot) = parse_preimage(commit) else {
            return Ok(());
        };
        let Some(&inst) = self.inst_by_id.get(&slot.instance) else {
            return Ok(());
        };
        let mut prepare = commit.to_vec();
        if let Some(kind) = prepare.get_mut(preimage::TAG_SIG.len()) {
            *kind = KIND_PREPARE;
        }
        let committee = self.instances[inst].committee(slot.height);
        let log = self.log.lock().expect("signing log");
        let backing = committee
            .members()
            .iter()
            .filter(|k| log.was_signed(k, &prepare))
            .count();
        if backing < committee.q() {
            return Err(format!(
                "signed a Commit at h {} v {} backed by only {backing} < q Prepare signatures of that view",
                slot.height, slot.view
            ));
        }
        Ok(())
    }

    /// O-CERT for a QC: ground-truth committee, quorum, provenance of every signature.
    ///
    /// # Errors
    /// A description of the first ground-truth defect.
    pub fn cert_qc(&self, inst: usize, qc: &Qc) -> Result<(), String> {
        let instance = &self.instances[inst];
        if qc.instance != instance.id {
            return Err(format!(
                "a certificate of another instance at h {}",
                qc.height
            ));
        }
        let committee = instance.committee(qc.height);
        let keys = committee
            .keys_of(&qc.signers)
            .ok_or_else(|| format!("a malformed bitmap at h {}", qc.height))?;
        if keys.len() != committee.q() {
            return Err(format!(
                "a {:?}QC with {} != q signers at h {} v {}",
                qc.kind,
                keys.len(),
                qc.height,
                qc.view
            ));
        }
        let msg = qc.preimage();
        let log = self.log.lock().expect("signing log");
        if let Some(key) = keys.iter().find(|k| !log.was_signed(k, &msg)) {
            return Err(format!(
                "a {:?}QC h {} v {} whose signer {key:?} never signed it",
                qc.kind, qc.height, qc.view
            ));
        }
        Ok(())
    }

    /// O-CERT for a TC: quorum of genuine timeouts and `high_pqc` of the true maximum `hq`.
    ///
    /// # Errors
    /// A description of the first ground-truth defect.
    pub fn cert_tc(&self, inst: usize, tc: &TimeoutCert) -> Result<(), String> {
        let instance = &self.instances[inst];
        if tc.epoch != instance.config(tc.height).epoch.id {
            return Err(
                "timeout certificate epoch context differs from authenticated schedule".into(),
            );
        }
        if tc.instance != instance.id {
            return Err("a TC of another instance".to_owned());
        }
        let committee = instance.committee(tc.height);
        let distinct: BTreeSet<u32> = tc.entries.iter().map(|e| e.signer).collect();
        if distinct.len() != committee.q() || distinct.len() != tc.entries.len() {
            return Err(format!(
                "a TC h {} v {} without q distinct entries",
                tc.height, tc.view
            ));
        }
        {
            let log = self.log.lock().expect("signing log");
            for entry in &tc.entries {
                let key = committee
                    .get(entry.signer)
                    .ok_or("a TC entry outside the committee")?;
                let msg =
                    preimage::tmo_preimage(&tc.instance, &tc.epoch, tc.height, tc.view, entry.hq);
                if !log.was_signed(key, &msg) {
                    return Err(format!(
                        "a TC h {} v {} with a timeout never signed by #{}",
                        tc.height, tc.view, entry.signer
                    ));
                }
            }
        }
        match (tc.max_hq(), &tc.high_pqc) {
            (None, None) => Ok(()),
            (Some(max), Some(q))
                if q.view == max && q.kind == VoteKind::Prepare && q.height == tc.height =>
            {
                self.cert_qc(inst, q)
            }
            _ => Err(format!(
                "a TC h {} v {} whose high_pqc is not the PrepareQC of the maximal hq",
                tc.height, tc.view
            )),
        }
    }

    /// O-EVID: honest nodes never accuse honest nodes.
    fn check_evidence(&mut self, r: usize, evidence: &Evidence) {
        self.stats.evidence += 1;
        let inst = self.replicas[r].inst;
        let committee = |h: u64| self.instances[inst].committee(h).clone();
        let accused: Option<PublicKey> = match evidence {
            Evidence::ProposalEquivocation(p, _) => self.proposal_signer(inst, p),
            // Only signed-content defects produce evidence (§3.6): never exempt.
            Evidence::InvalidProposal { proposal, .. } => self.proposal_signer(inst, proposal),
            Evidence::VoteEquivocation(v, _) => committee(v.height).get(v.signer).cloned(),
            Evidence::TimeoutEquivocation(t, _) => committee(t.height).get(t.signer).cloned(),
            Evidence::ConflictingCertificates(..) => None,
        };
        if let Some(key) = accused
            && let Some(&m) = self.key_owner.get(&key)
            && !self.machines[m].byz
        {
            self.fail(format!(
                "O-EVID: replica {r} reported evidence against honest machine {m}: {}",
                evidence_name(evidence)
            ));
        }
    }

    fn proposal_signer(&self, inst: usize, p: &Proposal) -> Option<PublicKey> {
        let msg = p.signing_preimage(&self.hasher);
        self.instances[inst]
            .committee(p.height)
            .members()
            .iter()
            .find(|k| fake_sig(k, &msg) == p.sig)
            .cloned()
    }

    // ---- O-PBS -----------------------------------------------------------------------------

    /// Every own signature in a message leaving honest replica `r`: at its first exposure the
    /// durable record must cover it (O-PBS).
    pub fn expose(&mut self, r: usize, msg: &WireMessage) {
        if self.machines[self.replicas[r].machine].byz {
            return;
        }
        let mut own = Vec::new();
        self.own_in_msg(r, msg, &mut own);
        self.check_exposed(r, own);
    }

    /// [`World::expose`] for a certificate written to the block store.
    pub fn expose_qc(&mut self, r: usize, qc: &Qc) {
        if self.machines[self.replicas[r].machine].byz {
            return;
        }
        let mut own = Vec::new();
        self.own_in_qc(r, qc, &mut own);
        self.check_exposed(r, own);
    }

    /// [`World::expose`] for evidence.
    pub fn expose_evidence(&mut self, r: usize, evidence: &Evidence) {
        if self.machines[self.replicas[r].machine].byz {
            return;
        }
        let mut own = Vec::new();
        match evidence {
            Evidence::ProposalEquivocation(a, b) => {
                self.own_in_proposal(r, a, &mut own);
                self.own_in_proposal(r, b, &mut own);
            }
            Evidence::InvalidProposal { proposal, .. } => {
                self.own_in_proposal(r, proposal, &mut own);
            }
            Evidence::VoteEquivocation(a, b) => {
                self.own_in_msg(r, &WireMessage::Vote(*a), &mut own);
                self.own_in_msg(r, &WireMessage::Vote(*b), &mut own);
            }
            Evidence::TimeoutEquivocation(a, b) => {
                self.own_in_msg(r, &WireMessage::Timeout(a.clone()), &mut own);
                self.own_in_msg(r, &WireMessage::Timeout(b.clone()), &mut own);
            }
            Evidence::ConflictingCertificates(a, b) => {
                self.own_in_qc(r, a, &mut own);
                self.own_in_qc(r, b, &mut own);
            }
        }
        self.check_exposed(r, own);
    }

    fn check_exposed(&mut self, r: usize, own: Vec<(PublicKey, Vec<u8>)>) {
        for (key, msg) in own {
            if !self.log.lock().expect("signing log").expose(&key, &msg) {
                continue;
            }
            let Some(slot) = parse_preimage(&msg).filter(|slot| slot.kind != KIND_ECHO) else {
                continue;
            };
            let covered = self.replicas[r]
                .records
                .get(&key)
                .is_some_and(|d| covers(&d.record, &slot));
            if !covered {
                return self.fail(format!(
                    "O-PBS: replica {r} exposed its {} signature at h {} v {} before its record was durable",
                    super::crypto::kind_name(slot.kind),
                    slot.height,
                    slot.view
                ));
            }
        }
    }

    fn own_index(&self, r: usize, height: u64) -> Vec<(PublicKey, u32)> {
        let rep = &self.replicas[r];
        let committee = self.instances[rep.inst].committee(height);
        rep.keys
            .iter()
            .filter_map(|k| committee.index_of(k).map(|i| (k.clone(), i)))
            .collect()
    }

    fn own_in_qc(&self, r: usize, qc: &Qc, out: &mut Vec<(PublicKey, Vec<u8>)>) {
        for (key, index) in self.own_index(r, qc.height) {
            if qc.signers.get(index) {
                out.push((key, qc.preimage()));
            }
        }
    }

    fn own_in_tc(&self, r: usize, tc: &TimeoutCert, out: &mut Vec<(PublicKey, Vec<u8>)>) {
        for (key, index) in self.own_index(r, tc.height) {
            if let Some(entry) = tc.entries.iter().find(|e| e.signer == index) {
                out.push((
                    key,
                    preimage::tmo_preimage(&tc.instance, &tc.epoch, tc.height, tc.view, entry.hq),
                ));
            }
        }
        if let Some(q) = &tc.high_pqc {
            self.own_in_qc(r, q, out);
        }
    }

    fn own_in_proposal(&self, r: usize, p: &Proposal, out: &mut Vec<(PublicKey, Vec<u8>)>) {
        let own = self.own_index(r, p.height);
        if !own.is_empty() {
            let msg = p.signing_preimage(&self.hasher);
            for (key, _) in own {
                if fake_sig(&key, &msg) == p.sig {
                    out.push((key, msg.clone()));
                }
            }
        }
        if let Some(tc) = &p.justify {
            self.own_in_tc(r, tc, out);
        }
        if let Some(q) = &p.parent_qc {
            self.own_in_qc(r, q, out);
        }
    }

    fn own_in_msg(&self, r: usize, msg: &WireMessage, out: &mut Vec<(PublicKey, Vec<u8>)>) {
        match msg {
            WireMessage::Proposal(p) => self.own_in_proposal(r, &p.proposal, out),
            WireMessage::Vote(v) => {
                for (key, index) in self.own_index(r, v.height) {
                    if v.signer == index {
                        out.push((key, v.preimage()));
                    }
                }
            }
            WireMessage::Qc(q) => self.own_in_qc(r, q, out),
            WireMessage::Timeout(t) => {
                for (key, index) in self.own_index(r, t.height) {
                    if t.signer == index {
                        out.push((key, t.preimage()));
                    }
                }
                if let Some(q) = &t.high_pqc {
                    self.own_in_qc(r, q, out);
                }
            }
            WireMessage::Tc(tc) => self.own_in_tc(r, tc, out),
            WireMessage::Status(s) => {
                for q in [&s.committed_qc, &s.high_pqc].into_iter().flatten() {
                    self.own_in_qc(r, q, out);
                }
                if let Some(tc) = &s.high_tc {
                    self.own_in_tc(r, tc, out);
                }
            }
            WireMessage::SyncResponse(resp) => {
                for entry in &resp.blocks {
                    self.own_in_qc(r, &entry.commit_qc, out);
                }
            }
            WireMessage::SyncRequest(_)
            | WireMessage::PayloadRequest(_)
            | WireMessage::PayloadManifest(_)
            | WireMessage::PayloadChunk(_)
            | WireMessage::ApplicationControl(_) => {}
        }
    }

    // ---- end of run --------------------------------------------------------------------------

    /// The same original progress baseline and height count used at completion and during
    /// bounded observation. Restarted replicas retain their existing one-height requirement.
    pub(super) fn progress_obligation(&self, r: usize) -> Option<(u64, u64)> {
        let heal = self.heal_of(self.replicas[r].inst);
        if !self.honest_running(r) || self.now < heal {
            return None;
        }
        let started = self.machines[self.replicas[r].machine].started_at;
        Some(if started > heal {
            (
                self.oracle.reps[r].at_start.unwrap_or(0),
                1.min(self.checks.progress),
            )
        } else {
            (
                self.oracle.reps[r].at_heal.unwrap_or(0),
                self.checks.progress,
            )
        })
    }

    /// End-of-run checks: progress, P1 p99, P2/P4 frequencies, P5, O-TXP, O-CQ, O-MEM of the
    /// body stores.
    pub fn finish(&mut self) {
        self.amx_finish();
        let honest = self.honest();
        for &r in &honest {
            if self.failure.is_some() {
                return;
            }
            self.observe_core(r);
            let Some((base, expect)) = self.progress_obligation(r) else {
                continue;
            };
            let progress = self.committed(r).saturating_sub(base);
            if progress < expect && self.checks.liveness {
                return self.fail(format!(
                    "progress: honest replica {r} committed {progress} heights after heal (expected ≥ {expect})"
                ));
            }
            self.finish_perf(r);
        }
        if self.failure.is_none() && self.checks.txp {
            self.finish_txp();
        }
        if self.failure.is_none() && self.checks.cq {
            self.finish_cq();
        }
        for (inst, from, until, heights) in self.checks.windows.clone() {
            let during = self.oracle.refs[inst]
                .values()
                .filter(|b| (from..until).contains(&b.at))
                .count();
            if during < heights && self.failure.is_none() {
                self.fail(format!(
                    "progress: instance {inst} committed {during} < {heights} heights in [{from}, {until})"
                ));
            }
        }
    }

    fn finish_perf(&mut self, r: usize) {
        let b = self.bounds(self.replicas[r].inst, self.replicas[r].machine);
        let gaps = self.oracle.reps[r].gaps.clone();
        match self.checks.perf {
            Perf::P1 if r == self.honest().first().copied().unwrap_or(0) => {
                // p99 over the commit gaps of every honest replica (a nearest-rank p99 of
                // fewer than 100 samples would be the maximum), after a warm-up of 20 heights:
                // `qc_lat_ewma` starts at 250 ms, so `t_retx` is ~500 ms until it converges.
                let mut sorted: Vec<Millis> = self
                    .honest()
                    .iter()
                    .flat_map(|x| self.oracle.reps[*x].gaps.iter().skip(20).map(|g| g.1))
                    .collect();
                sorted.sort_unstable();
                if std::env::var("SUMERAGI_SIM_GAPS").is_ok() && !sorted.is_empty() {
                    let mut all: Vec<(Millis, usize, u64)> = self
                        .honest()
                        .iter()
                        .flat_map(|x| self.oracle.reps[*x].gaps.iter().map(|g| (g.1, *x, g.0)))
                        .collect();
                    all.sort_unstable();
                    eprintln!(
                        "gaps: {} top {:?}",
                        all.len(),
                        &all[all.len().saturating_sub(12)..]
                    );
                }
                if sorted.len() >= 300 {
                    let index = (sorted.len() * 99).div_ceil(100).saturating_sub(1);
                    let p99 = sorted.get(index).copied().unwrap_or(0);
                    if p99 > b.g_norm {
                        self.fail(format!(
                            "O-PERF P1: p99 commit gap {p99} ms > G_norm {} ms over {} gaps",
                            b.g_norm,
                            sorted.len()
                        ));
                    }
                }
            }
            Perf::P2 => {
                let n = self.instances[self.replicas[r].inst].committee(1).n();
                let n64 = u64::try_from(n).unwrap_or(1);
                for (i, (h, gap, _)) in gaps.iter().enumerate() {
                    if *gap <= b.g_norm {
                        continue;
                    }
                    let slow = gaps
                        .iter()
                        .skip(i)
                        .take_while(|(h2, _, _)| *h2 < h + n64)
                        .filter(|(_, g, _)| *g > b.g_norm)
                        .count();
                    if slow > 1 {
                        return self.fail(format!(
                            "O-PERF P2: replica {r}: {slow} gaps above G_norm {} within {n} heights from {h}",
                            b.g_norm
                        ));
                    }
                }
            }
            Perf::P4 => {
                let long = gaps
                    .iter()
                    .filter(|(_, g, t)| *g > b.g_norm + 2 * *t + b.delta)
                    .count();
                // §8.2 P4: per `W` heights one leader-turn gap for the crashed member, plus one
                // more for every honest leader recorded in `skipped_leaders` inside the window
                // (an honest skip can displace it from `D_h`, or put a demoted slot right
                // before it). The runs are shorter than `W` heights.
                let inst = self.replicas[r].inst;
                let allowed = 1 + self.honest_skips(inst).len();
                if long > allowed {
                    self.fail(format!(
                        "O-PERF P4: replica {r}: {long} leader-turn gaps above P3 in the run \
                         (allowed {allowed})"
                    ));
                }
            }
            Perf::P5 => {
                if let Some(deadline) = self.oracle.p5[r] {
                    match self.oracle.reps[r].first_after_heal {
                        Some(t) if t <= deadline => {}
                        other => self.fail(format!(
                            "O-PERF P5: replica {r} first commit after heal at {other:?} > {deadline}"
                        )),
                    }
                }
            }
            Perf::P6 => {
                let late = self.replicas[r].max_tick_late;
                if late > b.eps_tick {
                    self.fail(format!(
                        "O-PERF P6: replica {r} handled a Tick {late} ms late (ε_tick {} ms)",
                        b.eps_tick
                    ));
                }
            }
            _ => {}
        }
    }

    fn finish_txp(&mut self) {
        for inst in 0..self.instances.len() {
            let heal = self.heal_of(inst);
            let b = self.bounds(inst, 0);
            // Transactions old enough to be judged: the spec's B_live bound, and a sanity
            // check that most transactions older than 20 s committed at all. Under sparse
            // local work a height may take several leader turns (§8.1), so there each
            // transaction must instead be in a block of the second height first committed
            // after its submission: that height is entered after the submission, and a holder
            // builds its block from its whole queue (Appendix E, E62).
            let turns = matches!(self.checks.perf, Perf::LeaderTurns(_));
            let mut judged = 0usize;
            let mut committed = 0usize;
            for (id, (submitted, poison, at)) in &self.txs[inst] {
                if *poison || *submitted < heal {
                    continue;
                }
                if *submitted + b.b_live <= self.now && at.is_none_or(|t| t > submitted + b.b_live)
                {
                    return self.fail(format!(
                        "O-TXP: transaction {id} not committed within B_live"
                    ));
                }
                if turns {
                    let due = self.oracle.refs[inst]
                        .values()
                        .map(|block| block.at)
                        .filter(|t| t > submitted)
                        .nth(1);
                    if let Some(due) = due
                        && at.is_none_or(|t| t > due)
                    {
                        return self.fail(format!(
                            "O-TXP: transaction {id} submitted at t={submitted} not committed \
                             by t={due}, the second height first committed after it"
                        ));
                    }
                    continue;
                }
                if *submitted + 20_000 <= self.now {
                    judged += 1;
                    committed += usize::from(at.is_some());
                }
            }
            if judged >= 10 && committed * 2 < judged {
                return self.fail(format!(
                    "O-TXP: only {committed} of {judged} non-poison transactions older than 20 s committed"
                ));
            }
        }
    }

    /// Heights of the reference chain whose `skipped_leaders` names an honest member.
    fn honest_skips(&self, inst: usize) -> Vec<u64> {
        self.oracle.refs[inst]
            .values()
            .filter(|b| {
                b.header.skipped_leaders.iter().any(|key| {
                    self.key_owner
                        .get(key)
                        .is_some_and(|m| !self.machines[*m].byz)
                })
            })
            .map(|b| b.header.height)
            .collect()
    }

    /// O-CQ (§13.2): over every window of `4n` committed heights that starts at least `W`
    /// heights after both `t_g` and the last height whose `skipped_leaders` names an honest
    /// member, the share of honest proposers is `≥ (n − f)/n − 0.05`.
    fn finish_cq(&mut self) {
        for inst in 0..self.instances.len() {
            let committee = self.instances[inst].committee(1);
            let n = u64::try_from(committee.n()).unwrap_or(1);
            let f = u64::try_from(committee.f()).unwrap_or(0);
            let w = self.instances[inst].window;
            let heal = self.heal_of(inst);
            let first_after_heal = self.oracle.refs[inst]
                .values()
                .find(|b| b.at >= heal)
                .map_or(u64::MAX, |b| b.header.height);
            let last_skip = self.honest_skips(inst).last().copied().unwrap_or(0);
            let start = first_after_heal.max(last_skip).saturating_add(w);
            let heights: Vec<bool> = self.oracle.refs[inst]
                .values()
                .filter(|b| b.header.height >= start)
                .map(|b| b.honest_proposer)
                .collect();
            let window = usize::try_from(4 * n).unwrap_or(16);
            for chunk in heights.windows(window) {
                let honest = u64::try_from(chunk.iter().filter(|x| **x).count()).unwrap_or(0);
                // honest / 4n ≥ (n − f)/n − 1/20  ⟺  20·honest ≥ 80·(n − f) − 4·n
                if 20 * honest + 4 * n < 80 * (n - f) {
                    return self.fail(format!(
                        "O-CQ: only {honest} of {window} blocks proposed by honest members"
                    ));
                }
            }
        }
    }
}

fn evidence_name(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::ProposalEquivocation(..) => "ProposalEquivocation",
        Evidence::VoteEquivocation(..) => "VoteEquivocation",
        Evidence::TimeoutEquivocation(..) => "TimeoutEquivocation",
        Evidence::InvalidProposal { .. } => "InvalidProposal",
        Evidence::ConflictingCertificates(..) => "ConflictingCertificates",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::{run, scenarios};

    fn count_held_certificate_copies(work: impl FnOnce()) -> usize {
        struct Disable;
        impl Drop for Disable {
            fn drop(&mut self) {
                HELD_CERTIFICATE_COPIES.with(|copies| copies.set(None));
            }
        }
        HELD_CERTIFICATE_COPIES.with(|copies| {
            assert_eq!(copies.get(), None, "one observation probe on this thread");
            copies.set(Some(0));
        });
        let _disable = Disable;
        work();
        HELD_CERTIFICATE_COPIES.with(|copies| copies.get().expect("active observation probe"))
    }

    #[test]
    fn unchanged_genuine_held_certificates_do_not_clone_on_each_observation() {
        // This is the same signed short World used by the complete-history sweep controls.
        let mut scenario = scenarios::smoke(0, 4);
        scenario.duration = 6_000;
        scenario.checks.progress = 2;
        assert_eq!(HELD_CERTIFICATE_COPIES.with(std::cell::Cell::get), None);
        let mut world = run(scenario).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(HELD_CERTIFICATE_COPIES.with(std::cell::Cell::get), None);
        let r = world
            .honest()
            .into_iter()
            .find(|&r| {
                world.replicas[r]
                    .host
                    .core()
                    .is_some_and(|core| core.committed_qc().is_some())
            })
            .expect("a genuine signed CommitQC from the completed World");
        let core = world.replicas[r].host.core().expect("running honest core");
        let obs = &world.oracle.reps[r];
        // The oracle retains the last verified owner after the Core clears a held certificate.
        if let Some(lock) = core.lock() {
            assert_eq!(Some(lock), obs.checked_lock.as_ref());
        }
        if let Some(tc) = core.highest_tc() {
            assert_eq!(Some(tc), obs.checked_tc.as_ref());
        }
        assert_eq!(core.committed_qc(), obs.checked_cqc.as_ref());
        let commit = core.committed_qc().expect("genuine signed CommitQC");
        assert_eq!(commit.kind, VoteKind::Commit);
        world
            .cert_qc(world.replicas[r].inst, commit)
            .expect("the original signing log authenticates the held certificate");
        assert!(world.committed(r) >= 2);
        assert!(!world.replicas[r].store.is_empty());
        let checked = (
            obs.checked_lock.clone(),
            obs.checked_tc.clone(),
            obs.checked_cqc.clone(),
        );
        let counters = |world: &World| {
            let stats = world.stats;
            (
                stats.events,
                stats.packets,
                stats.bytes,
                stats.lost,
                stats.oversize,
                stats.crashes,
                stats.evidence,
                stats.proposals,
            )
        };
        let original_counters = counters(&world);
        let original_height = world.committed(r);
        let original_time = world.now;
        let original_reference_count = world.oracle.refs[world.replicas[r].inst].len();
        let copies = count_held_certificate_copies(|| {
            for _ in 0..4 {
                world.observe_core(r);
            }
        });
        assert_eq!(HELD_CERTIFICATE_COPIES.with(std::cell::Cell::get), None);
        assert_eq!(world.failure, None);
        assert_eq!(counters(&world), original_counters);
        assert_eq!(world.committed(r), original_height);
        assert_eq!(world.now, original_time);
        assert_eq!(
            world.oracle.refs[world.replicas[r].inst].len(),
            original_reference_count
        );
        let obs = &world.oracle.reps[r];
        assert_eq!(obs.checked_lock.as_ref(), checked.0.as_ref());
        assert_eq!(obs.checked_tc.as_ref(), checked.1.as_ref());
        assert_eq!(obs.checked_cqc.as_ref(), checked.2.as_ref());
        assert_eq!(
            copies, 0,
            "unchanged genuine held certificates must be compared before any certificate clone"
        );

        // A different complete certificate value still invokes the original O-CERT kernel.
        world.oracle.reps[r]
            .checked_cqc
            .as_mut()
            .expect("original checked CommitQC")
            .view ^= 1;
        let copies = count_held_certificate_copies(|| world.observe_core(r));
        assert_eq!(HELD_CERTIFICATE_COPIES.with(std::cell::Cell::get), None);
        assert_eq!(
            copies, 1,
            "a changed held certificate must be copied and checked"
        );
        assert_eq!(world.failure, None);
        assert_eq!(
            world.oracle.reps[r].checked_cqc.as_ref(),
            checked.2.as_ref()
        );
        assert_eq!(counters(&world), original_counters);
        assert_eq!(world.committed(r), original_height);
    }
}
