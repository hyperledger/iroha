//! The Sumeragi state machine (spec §6–§10, §12): [`Core`], one per consensus instance.
//!
//! [`Core::handle`] runs one handler to completion and returns the driver's actions in order;
//! [`Core::next_wakeup`] is the earliest pending deadline. The handlers are split by concern:
//!
//! - `intake`: the intake filter of §6.1, `Status` handling (§6.11), the probe echo (§7.4 R2)
//!   and the proposal request (`request_proposal`);
//! - `proposal`: accepting proposals (§6.2), execution results (§6.3) and the Prepare vote;
//! - `votes`: vote pools, aggregation, `PrepareQC`s (`on_qc`), the Commit vote and the stage
//!   ladder (§5.2, §6.4, §6.5);
//! - `timeout`: timing out, joining, timeout certificates and view changes (§6.6, §6.7, §6.12);
//! - `round`: commit, height entry, `BlockApplied`, the safety monitor (§6.8, §6.13, §7.6);
//! - `sync`: catch-up, body wants and serving (§6.9);
//! - `propose`: work-driven proposing (§6.10);
//! - `timers`: `Tick`, retransmission, rebroadcast, `Status` cadence and the probe (§6.11);
//! - `restart`: `Core::new` and `restore`, the restart rules R1–R6 (§7.4).
//!
//! Safety-relevant ordering: every signed message is created after the `PersistSafety` that
//! records it, in the same action list (§7.4, O2), and the node's own votes and timeouts enter
//! its own pools last through `pool_insert` / `timeout_insert`, because forming a certificate
//! may commit and move to the next height.

mod control;
mod intake;
mod proposal;
mod propose;
mod restart;
mod round;
mod sync;
mod timeout;
mod timers;
mod votes;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use self::{sync::SyncState, votes::Pools};
use crate::{
    api::{Action, CoreStatus, Event, Footprint, HaltReason, LocalFault, LocalParams},
    crypto::{Crypto, Signer, Verifier},
    message::{
        BlockHeader, Evidence, Proposal, Qc, TimeoutCert, TimeoutVote, Vote, VoteKind, WireMessage,
    },
    pacemaker::{self, Pacemaker},
    safety::SafetyRecord,
    topology::{Round, Topology},
    types::{Hash32, HeightConfig, Millis, PublicKey, Signature, ValidatorIndex, usize_of},
};

/// The Sumeragi consensus core of one instance (spec §6.0). Sans-IO: it never blocks, never
/// reads a clock and performs no I/O; the driver executes the returned [`Action`]s in order and
/// honours the guarantees of §12.3.
#[allow(clippy::struct_excessive_bools)] // independent per-view and per-height flags of §6.0
pub struct Core {
    body_budget: iroha_allocation::AllocationBudget,
    crypto: Box<dyn Crypto>,
    local: LocalParams,
    instance: Hash32,
    genesis: u64,
    /// The demotion window `W` (`Init.demotion_window`, a genesis constant, §2.1).
    w: u64,
    /// Configured and retired keys (§7.4 Keys).
    keys: Vec<LocalKey>,
    /// `Init.nonce`: the probe nonce of this process lifetime (§7.4 R2).
    nonce: u64,
    /// While a key is unanchored: the lowest height reported per member key of
    /// `C_{tip.height+2}` in a fresh, verified echo (§6.11).
    probe: BTreeMap<PublicKey, u64>,
    /// The exact epoch whose authenticated echoes populate `probe`.
    probe_epoch: Option<crate::types::EpochId>,
    /// When the last probe round was sent (§6.11).
    last_probe: Millis,
    halted: Option<HaltReason>,
    now: Millis,
    out: Vec<Action>,
    // Committed chain (consensus view of it).
    tip: Tip,
    applied: u64,
    configs: BTreeMap<u64, crate::types::ConfigSlot>,
    recent_headers: VecDeque<BlockHeader>,
    pending_apply: VecDeque<PendingApply>,
    awaiting: bool,
    // Current round.
    height: u64,
    view: u64,
    cfg: HeightConfig,
    topo: Topology,
    rnd: Round,
    t_enter: Millis,
    t_prop: Option<Millis>,
    /// When this node first held the round's proposal together with its body; the committing
    /// view's duration `d_c` is measured from it (§9.2).
    t_body: Option<Millis>,
    /// The height was entered late (from awaiting, sync, a `Status` `CommitQC` or a restart,
    /// §6.8 step 5); reset on a view change.
    late_entry: bool,
    /// A `Status{want_proposal}` was sent to `L(h, view)` in this round (§6.11).
    asked: bool,
    me: Option<Me>,
    safety: Option<SafetyRecord>,
    timeout_view: Option<u64>,
    proposal: Option<Held>,
    stage: u8,
    hint: u8,
    t_ready: Option<Millis>,
    /// When this node first held the `PrepareQC` of `(h, view)` (§5.2 stage 1).
    t_pqc: Option<Millis>,
    t_lastvote: Option<Millis>,
    mine: Mine,
    retx: [Option<Retx>; 2],
    build: Build,
    /// One payload request followed by its exact source-bound control response.
    fresh_build: Option<FreshBuild>,
    /// Bounded cadence for every member's single application producer.
    control_drive: Option<(crate::api::ApplicationControlContext, Millis)>,
    control_received: BTreeMap<PublicKey, Millis>,
    repropose: bool,
    resend_recorded: Option<Hash32>,
    proposal_sent_at: Option<Millis>,
    /// Members re-pushed by the rebroadcast rule (§6.11 rebroadcast 2), once per view.
    repushed: BTreeSet<ValidatorIndex>,
    /// Recipients re-pushed on their `Status{want_proposal}` (§6.11), once per view.
    request_pushed: BTreeSet<PublicKey>,
    answered: BTreeSet<(u64, ValidatorIndex)>,
    votes: Pools,
    timeouts: Vec<Option<TimeoutVote>>,
    high_pqc: Option<Qc>,
    high_tc: Option<TimeoutCert>,
    cert_cache: CertCache,
    /// Evidence already emitted (§6.0 `reported`).
    reported: BTreeSet<EvKey>,
    // Bodies and execution.
    blocks: BTreeMap<Hash32, crate::availability::AvailableBody>,
    exec: BTreeMap<Hash32, ExecState>,
    next_req: u64,
    wants: BTreeMap<Hash32, Want>,
    // Pacemaker, sync, peers.
    pm: Pacemaker,
    reported_t_req: Millis,
    sync: SyncState,
    peers: BTreeMap<PublicKey, Peer>,
    last_status: Option<Millis>,
    last_rebroadcast: Millis,
}

/// A configured or retired key and its restart state (§7.4).
struct LocalKey {
    pk: PublicKey,
    /// `None` for a retired key: restored like the others, but it never signs.
    signer: Option<std::sync::Arc<dyn Signer>>,
    /// First height at which the key may sign (R2 after anchoring, R6).
    abstain_below: u64,
    /// R2: the record was `Absent`; the key signs nothing until the probe anchors it.
    unanchored: bool,
    /// A restored record, resumed when the key signs at `restore.height` (R4, R6).
    restore: Option<SafetyRecord>,
}

/// The committed tip (§6.0).
#[derive(Clone, Debug)]
struct Tip {
    height: u64,
    block_hash: Hash32,
    result: Hash32,
    commit_qc: Option<Qc>,
    /// This node executed the tip block with exactly the certified result, and the driver
    /// still holds that post-state (§4.1).
    exec_ok: bool,
    /// The execution of the tip block that was still pending when it committed (§6.3 step 0).
    exec_req: Option<u64>,
    /// `(block_hash, result)` of `height − 1` (§6.13, §7.6).
    prev: Option<(Hash32, Hash32)>,
    /// The `CommitQC` of `height − 1`, if held (evidence of the safety monitor).
    prev_qc: Option<Qc>,
}

/// A committed block whose `CommitBlock` is not emitted yet (§6.8 step 3).
#[derive(Clone, Debug)]
struct PendingApply {
    height: u64,
    block_hash: Hash32,
    qc: Qc,
    /// The committed parent's hash and result: the body must extend them (§6.9 rule 6).
    parent_hash: Hash32,
    parent_result: Hash32,
}

/// The configured key that is a member of `C_h` (routing roles), with its slot in `keys` and
/// whether it signs at `h` (it does not while abstaining or unanchored, R2/R6).
// SPEC: an abstaining member keeps its routing roles (it still aggregates votes sent to it as
// proxy tail and broadcasts the QCs it forms); only signing is suppressed (Appendix E, E19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Me {
    slot: usize,
    index: ValidatorIndex,
    signs: bool,
}

/// Execution state of a block (§6.0 `exec`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecState {
    Pending {
        since: Millis,
        req: u64,
        attempt: u32,
    },
    Valid(Hash32),
    Invalid,
    RetryAt {
        at: Millis,
        attempt: u32,
    },
}

/// The accepted proposal of the current round (payload stripped; the body is in `blocks`).
#[derive(Clone, Debug)]
struct Held {
    p: Proposal,
    bh: Hash32,
    ad: Hash32,
    /// `Q.result` of a re-proposal justified by a TC naming `Q` (TC rule).
    expected: Option<Hash32>,
}

/// The exact signed messages of the current round (§6.0 `mine`).
#[derive(Clone, Debug, Default)]
struct Mine {
    /// Own proposal without payload.
    proposal: Option<Proposal>,
    prepare: Option<Vote>,
    commit: Option<Vote>,
    timeout: Option<TimeoutVote>,
}

/// Retransmission schedule of an own vote (§6.11).
#[derive(Clone, Copy, Debug)]
struct Retx {
    next: Millis,
    k: u32,
    /// First send (vote-to-QC latency sample, §9.1).
    sent: Millis,
}

/// Original exact source and its payload awaiting the source-bound control response.
struct FreshBuild {
    context: crate::api::ControlWitnessContext,
    payload: Option<crate::availability::PayloadBytes>,
    authoring: Option<(BlockHeader, Option<TimeoutCert>)>,
}

/// The leader's payload build state (§6.10). `req` is the outstanding request id (§6.0 `build`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Build {
    Idle,
    /// The view-0 build is due at `t_propose`.
    Scheduled(Millis),
    /// `BuildPayload{req}` is outstanding; `ready` arrived before its answer.
    Requested {
        req: u64,
        deadline: Millis,
        ready: bool,
    },
    /// Request `req` had no usable payload: wait for a bounded retry or new work.
    IdleWait {
        req: u64,
        until: Millis,
    },
}

/// Where a `CommitQC` for the current height came from (§6.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// Formed locally from this node's pools.
    Formed,
    /// A `Qc` message.
    Qc,
    /// A proposal's `parent_qc`.
    ParentQc,
    /// A `Status`'s `committed_qc` (entry is late).
    Status,
    /// A verified sync entry (entry is late).
    Sync,
}

impl Via {
    /// Verified (or formed) before it reaches `commit_height`.
    fn trusted(self) -> bool {
        matches!(self, Self::Formed | Self::Sync)
            || (cfg!(sumeragi_mutation = "MS21") && matches!(self, Self::Status | Self::ParentQc))
    }

    /// Entering the next height from this `CommitQC` is a late entry (§6.8 step 5).
    fn late(self) -> bool {
        matches!(self, Self::Status | Self::Sync)
    }
}

/// Where a `PrepareQC` came from (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqcVia {
    /// A top-level certificate (a `Qc` message or a `Status`'s `high_pqc`): cheap-rejected
    /// unless it raises the lock, then verified.
    Wire,
    /// Carried by a verified timeout: all of §6.5 step 2 runs.
    Timeout,
    /// A TC's `high_pqc` (verified with the TC): only steps 2a and 2c run.
    Tc,
    /// Formed locally.
    Formed,
}

/// A wanted block body (§6.9 rule 5).
#[derive(Clone, Debug)]
struct Want {
    height: u64,
    sources: Vec<PublicKey>,
    cursor: usize,
    attempt: u32,
    next_retry: Millis,
}

/// Evidence de-duplication key (§6.0 `reported`, §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EvKey {
    Proposal(u64),
    Vote(VoteKind, u64, ValidatorIndex),
    Timeout(u64, ValidatorIndex),
    Invalid(u64),
}

impl EvKey {
    fn view(self) -> u64 {
        match self {
            Self::Proposal(v) | Self::Vote(_, v, _) | Self::Timeout(v, _) | Self::Invalid(v) => v,
        }
    }
}

/// What the core knows about a peer (§6.11).
#[derive(Clone, Debug, Default)]
struct Peer {
    height: u64,
    view: u64,
    proposal_hash: Option<Hash32>,
    /// When its latest processed `Status` arrived.
    status_at: Option<Millis>,
    /// When the core last replied with its own `Status`.
    replied_at: Option<Millis>,
    /// When the core last answered one of its probes with a signed echo.
    echoed_at: Option<Millis>,
    /// Highest `committed_qc` height of its processed `Status` messages.
    committed: u64,
    seen: Millis,
}

/// Digests of certificates verified at the current height (§6.1 rule 5): an LRU of capacity
/// `4n`, cleared on height entry.
#[derive(Clone, Debug, Default)]
struct CertCache {
    set: BTreeSet<Hash32>,
    order: VecDeque<Hash32>,
    cap: usize,
}

impl CertCache {
    /// Whether `digest` is cached; a hit becomes the most recently used entry.
    fn hit(&mut self, digest: &Hash32) -> bool {
        if !self.set.contains(digest) {
            return false;
        }
        #[cfg(not(sumeragi_mutation = "MR-cert-lru"))]
        if let Some(position) = self.order.iter().position(|d| d == digest)
            && let Some(entry) = self.order.remove(position)
        {
            self.order.push_back(entry);
        }
        true
    }

    fn contains(&self, digest: &Hash32) -> bool {
        self.set.contains(digest)
    }

    fn insert(&mut self, digest: Hash32) {
        if self.cap == 0 || self.hit(&digest) {
            return;
        }
        self.set.insert(digest);
        self.order.push_back(digest);
        // One insertion can exceed the established capacity by at most one entry.
        if self.order.len() > self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
    }

    fn reset(&mut self, cap: usize) {
        self.set.clear();
        self.order.clear();
        self.cap = cap;
    }
}

/// Upper bound on outstanding wants (§8.4 lists at most 5 reasons).
const MAX_WANTS: usize = 5;

/// Evidence keys per signer (E28): the three views of the vote-pool window times the five keys
/// a signer can earn in a view (proposal equivocation, signed defect, Prepare, Commit and
/// timeout equivocation).
const EVIDENCE_PER_SIGNER: usize = 15;

impl std::fmt::Debug for Core {
    /// The read-only diagnostics of [`Core::status`] (the state itself is not printed).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Handle one event (§12.1): runs one handler to completion and returns the actions for the
    /// driver, to be executed in order (O1) with persist-before-effect (O2).
    pub fn handle(&mut self, now: Millis, event: Event) -> Vec<Action> {
        // The driver's clock is monotonic; a regression is ignored rather than trusted.
        self.now = self.now.max(now);
        if self.halted.is_some() {
            self.serve_only(event);
            return std::mem::take(&mut self.out);
        }
        match event {
            Event::Tick => self.on_tick(),
            Event::Message { from, msg } => self.on_message(&from, msg),
            Event::PayloadBuilt { req, payload } => self.on_payload_built(req, payload),
            Event::PayloadReady { req } => self.on_payload_ready(req),
            Event::ControlWitnessBuilt {
                req,
                context,
                witness,
            } => {
                self.on_control_witness_built(req, context, &witness);
            }
            Event::ApplicationControlBuilt { message } => {
                self.on_application_control_built(message)
            }
            Event::Executed {
                block_hash,
                req,
                outcome,
            } => self.on_executed(block_hash, req, &outcome),
            Event::BodyAvailable { block } => self.on_body(block),
            Event::PayloadAuthored { req, body } => self.on_payload_authored(req, body),
            Event::ManifestRejected { manifest } => self.on_manifest_rejected(&manifest),
            Event::BlockApplied {
                height,
                block_hash,
                header,
                config,
            } => self.on_block_applied(height, block_hash, *header, config),
            Event::ApplyDiverged { height, .. } => self.halt(HaltReason::ApplyDiverged { height }),
            Event::PublicationRecoveryRequired { height } => {
                // MS42: an irreversibly failed original publication is treated as retryable.
                if !cfg!(sumeragi_mutation = "MS42") {
                    self.halt(HaltReason::PublicationRecoveryRequired { height });
                }
            }
        }
        self.finish_call();
        std::mem::take(&mut self.out)
    }

    /// The end of every `handle` call (and of `Core::new`): buffered sync entries, the next
    /// sync request, and the proposal request of §6.11.
    fn finish_call(&mut self) {
        if self.halted.is_none() {
            self.process_sync_buffer();
            self.maybe_request_sync();
        }
        if self.halted.is_none() {
            self.request_proposal();
            self.drive_application_control();
        }
    }

    /// The driver may retain work only for this exact applied parent and signing view.
    /// This allocation-free context cancels obsolete custody after source changes,
    /// view advance, abstention or halt; it does not authenticate application bytes.
    pub fn control_work_context(&self) -> Option<(crate::api::ApplicationControlContext, u64)> {
        if self.halted.is_some() || self.signer().is_none() {
            return None;
        }
        self.application_control_context()
            .map(|source| (source, self.view))
    }

    /// Read-only diagnostics (§12.1 `status()`).
    pub fn status(&self) -> CoreStatus {
        let role = |index: ValidatorIndex| {
            self.member_key(index)
                .filter(|_| !self.awaiting && self.topo.height() == self.height)
        };
        CoreStatus {
            instance: self.instance,
            height: self.height,
            view: self.view,
            stage: self.stage,
            leader: role(self.rnd.leader()),
            proxy_tail: role(self.rnd.proxy_tail()),
            high_qc_view: self.high_pqc.as_ref().map(|qc| qc.view),
            level: self.pm.level(self.view),
            start_level: self.pm.start_level(),
            t_retx: self.pm.t_retx(self.view),
            committed_height: self.tip.height,
            applied_height: self.applied,
            awaiting: self.awaiting,
            signer: self
                .signer()
                .and_then(|me| self.key_of_slot(me.slot))
                .cloned(),
            unanchored: self.any_unanchored(),
            abstaining: self.me.is_none_or(|me| !me.signs),
            halted: self.halted,
            footprint: self.footprint(),
        }
    }

    /// The §8.4 bounds for this core's current committee and configuration.
    pub fn footprint_bound(&self) -> Footprint {
        Footprint::bound(self.cfg.committee.n(), &self.local, self.w)
    }

    /// Read-only observation for the simulator's O-LIVE accounting (§13.2): the node is not a
    /// signing member at its height (`CoreStatus::abstaining`, without the footprint).
    #[cfg(any(test, feature = "sim"))]
    pub fn abstaining(&self) -> bool {
        self.me.is_none_or(|me| !me.signs)
    }

    /// Read-only observation for the simulator's O-CERT oracle (§13.2): the lock (`high_pqc`)
    /// held at the current height.
    #[cfg(any(test, feature = "sim"))]
    pub fn lock(&self) -> Option<&Qc> {
        self.high_pqc.as_ref()
    }

    /// Read-only observation for the simulator's O-CERT oracle (§13.2): the highest TC held at
    /// the current height.
    #[cfg(any(test, feature = "sim"))]
    pub fn highest_tc(&self) -> Option<&TimeoutCert> {
        self.high_tc.as_ref()
    }

    /// Read-only observation for the simulator's O-CERT oracle (§13.2): the `CommitQC` of the
    /// committed tip.
    #[cfg(any(test, feature = "sim"))]
    pub fn committed_qc(&self) -> Option<&Qc> {
        self.tip.commit_qc.as_ref()
    }

    /// Read-only observation for the simulator's late-leader strategy (§9.2): when this node
    /// entered its current round (`t_enter`, §9.1).
    #[cfg(any(test, feature = "sim"))]
    pub fn round_entered_at(&self) -> Millis {
        self.t_enter
    }

    fn footprint(&self) -> Footprint {
        Footprint {
            votes: self.votes.len(),
            timeouts: self.timeouts.iter().flatten().count(),
            fresh_payloads: usize::from(
                self.fresh_build
                    .as_ref()
                    .is_some_and(|build| build.payload.is_some()),
            ),
            control_peers: self.control_received.len(),
            blocks: self.blocks.len(),
            exec_entries: self.exec.len(),
            wants: self.wants.len(),
            pending_apply: self.pending_apply.len(),
            sync_entries: self.sync.buffer.len(),
            sync_bytes: self.sync.buffer_bytes,
            peers: self.peers.len(),
            recent_headers: self.recent_headers.len(),
            configs: self.configs.len(),
            cert_cache: self.cert_cache.set.len(),
            evidence_keys: self.reported.len(),
            probe: self.probe.len(),
        }
    }

    // ---- identity and roles -------------------------------------------------------------

    /// The member that signs at `h` (`None` = observer at this height, §6.0).
    fn signer(&self) -> Option<Me> {
        self.me.filter(|me| me.signs && !self.awaiting)
    }

    fn my_index(&self) -> Option<ValidatorIndex> {
        self.me.map(|me| me.index)
    }

    fn key_of_slot(&self, slot: usize) -> Option<&PublicKey> {
        self.keys.get(slot).map(|key| &key.pk)
    }

    /// Whether `key` is one of this node's keys (configured or retired).
    fn is_local_key(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|k| &k.pk == key)
    }

    /// Whether some key is unanchored (R2).
    fn any_unanchored(&self) -> bool {
        self.keys.iter().any(|k| k.unanchored)
    }

    fn member_key(&self, index: ValidatorIndex) -> Option<PublicKey> {
        self.cfg.committee.get(index).cloned()
    }

    fn n(&self) -> usize {
        self.cfg.committee.n()
    }

    /// Proxy tail of `(h, view)` for any view.
    fn proxy_tail_of(&self, view: u64) -> ValidatorIndex {
        if view == self.view {
            self.rnd.proxy_tail()
        } else {
            self.topo.round(view).proxy_tail()
        }
    }

    /// Whether this node is currently in round `h` (not awaiting, not halted) at height `h0`.
    fn same_height(&self, h0: u64) -> bool {
        self.height == h0 && !self.awaiting && self.halted.is_none()
    }

    // ---- output helpers -----------------------------------------------------------------

    fn send(&mut self, to: PublicKey, msg: WireMessage) {
        if !self.is_local_key(&to) {
            self.out.push(Action::Send { to, msg });
        }
    }

    fn broadcast(&mut self, to: Vec<PublicKey>, msg: WireMessage) {
        if !to.is_empty() {
            self.out.push(Action::Broadcast { to, msg });
        }
    }

    /// Members of `C_h` except this node, in canonical order.
    fn members_except_me(&self) -> Vec<PublicKey> {
        self.cfg
            .committee
            .members()
            .iter()
            .filter(|key| !self.is_local_key(key))
            .cloned()
            .collect()
    }

    /// `recipients` (§6.0) of `(h, view)`: members of `C_h` except self, set A first; with
    /// `joiners`, also `C_{h+1} \ C_h` when `C_{h+1}` is known.
    fn recipients(&self, joiners: bool) -> Vec<PublicKey> {
        self.recipients_of(self.view, joiners)
    }

    /// [`Core::recipients`] in the order of `(h, view)` for any view.
    fn recipients_of(&self, view: u64, joiners: bool) -> Vec<PublicKey> {
        let other;
        let round = if view == self.view {
            &self.rnd
        } else {
            other = self.topo.round(view);
            &other
        };
        let mut out: Vec<PublicKey> = round
            .order()
            .iter()
            .filter_map(|index| self.member_key(*index))
            .filter(|key| !self.is_local_key(key))
            .collect();
        if joiners && let Some(next) = self.config(self.height.saturating_add(1)) {
            out.extend(
                next.committee
                    .members()
                    .iter()
                    .filter(|key| !self.cfg.committee.contains(key) && !self.is_local_key(key))
                    .cloned(),
            );
        }
        out
    }

    fn local_fault(&mut self, fault: LocalFault) {
        self.out.push(Action::LocalFault(fault));
    }

    /// Halt the instance (§12.5): from now on only serving continues.
    fn halt(&mut self, reason: HaltReason) {
        if self.halted.is_none() {
            self.halted = Some(reason);
            self.out.push(Action::Halt(reason));
        }
    }

    /// Report evidence once per key (§6.0 `reported`); keys of views below the vote-pool
    /// window are pruned with the pools, all on height entry.
    // SPEC: proposal evidence is keyed by kind and view (equivocation and signed defect), so a
    // view has up to `3n + 2` keys; the set is capped at `3·(3n + 1)` (§8.4) and evidence beyond
    // the cap is dropped (best effort). It is also capped per signer (the leader of the view for
    // proposal evidence) at `EVIDENCE_PER_SIGNER`: a proposal for any future view without
    // `justify` is a signed defect and timeouts are accepted for any future view, so one
    // Byzantine member could otherwise fill the whole cap with far-future keys that are never
    // pruned within the height, suppressing all other evidence (found by review). `f` signers
    // hold at most `15f < 3·(3n + 1)` keys (Appendix E, E28).
    fn report(&mut self, key: EvKey, evidence: Evidence) {
        let cap = 3 * (3 * self.n() + 1);
        let signer = self.evidence_signer(key);
        let by_signer = (self.reported.iter())
            .filter(|k| self.evidence_signer(**k) == signer)
            .count();
        if self.reported.len() >= cap
            || by_signer >= EVIDENCE_PER_SIGNER
            || !self.reported.insert(key)
        {
            return;
        }
        self.out.push(Action::ReportEvidence(Box::new(evidence)));
    }

    /// The member an evidence key accuses (the leader of the view for proposal evidence).
    fn evidence_signer(&self, key: EvKey) -> ValidatorIndex {
        match key {
            EvKey::Proposal(view) | EvKey::Invalid(view) => self.topo.leader(view),
            EvKey::Vote(_, _, signer) | EvKey::Timeout(_, signer) => signer,
        }
    }

    // ---- safety record and signing --------------------------------------------------------

    /// `persist()` (§6.0): write the lock and `high_tc` into the record and push
    /// `PersistSafety`. Every signed message is created after it.
    fn persist(&mut self) {
        if let Some(record) = self.safety.as_mut() {
            #[cfg(not(sumeragi_mutation = "MS25"))]
            record.lock.clone_from(&self.high_pqc);
            #[cfg(not(sumeragi_mutation = "ML9"))]
            record.high_tc.clone_from(&self.high_tc);
            self.out
                .push(Action::PersistSafety(Box::new(record.clone())));
        }
    }

    /// Sign with the key of `me` (deterministic, §12.1); `None` for a retired key.
    fn sign(&self, me: Me, preimage: &[u8]) -> Option<Signature> {
        self.keys
            .get(me.slot)
            .and_then(|key| key.signer.as_ref())
            .map(|signer| signer.sign(preimage))
    }

    // ---- certificate verification with the cache (§6.1 rule 5) ---------------------------

    /// Installed authority only. A pending epoch never supplies voters or leader randomness.
    fn config(&self, height: u64) -> Option<&HeightConfig> {
        self.configs
            .get(&height)
            .and_then(crate::types::ConfigSlot::ready)
    }

    /// Bind the authenticated configuration selected by the caller, including past heights.
    fn verifier<'a>(&'a self, config: &'a HeightConfig) -> Verifier<'a> {
        Verifier::new(
            &*self.crypto,
            &self.instance,
            &config.epoch.id,
            &config.committee,
        )
    }

    /// Verify a QC under `C_{qc.height}` (SR15), using and filling the cache.
    fn verify_qc_cached(&mut self, qc: &Qc) -> bool {
        let Some(active) = self.config(qc.height) else {
            return false;
        };
        if qc.epoch != active.epoch.id || !active.epoch.contains(qc.height) {
            return false;
        }
        let digest = qc.digest(&*self.crypto);
        if self.cert_cache.hit(&digest) {
            return true;
        }
        #[cfg(not(sumeragi_mutation = "MS15"))]
        let config_height = qc.height;
        #[cfg(sumeragi_mutation = "MS15")]
        let config_height = self.tip.height;
        let Some(config) = self.config(config_height) else {
            return false;
        };
        let ok = self.verifier(config).verify_qc(qc).is_ok();
        if ok {
            self.cert_cache.insert(digest);
        }
        ok
    }

    /// Verify a TC of the current height under `C_h`, using and filling the cache.
    fn verify_tc_cached(&mut self, tc: &TimeoutCert) -> bool {
        if self.awaiting || tc.height != self.height || tc.epoch != self.cfg.epoch.id {
            return false;
        }
        let digest = tc.digest(&*self.crypto);
        if self.cert_cache.hit(&digest) {
            return true;
        }
        let high_cached = tc
            .high_pqc
            .as_ref()
            .is_some_and(|qc| self.cert_cache.contains(&qc.digest(&*self.crypto)));
        let verifier = self.verifier(&self.cfg);
        let checked = if high_cached {
            verifier.verify_tc_with_verified_high_qc(tc)
        } else {
            verifier.verify_tc(tc)
        };
        let ok = checked.is_ok();
        if ok {
            if let Some(qc) = &tc.high_pqc {
                let qc_digest = qc.digest(&*self.crypto);
                self.cert_cache.insert(qc_digest);
            }
            self.cert_cache.insert(digest);
        }
        ok
    }

    fn cache_cert_qc(&mut self, qc: &Qc) {
        let digest = qc.digest(&*self.crypto);
        self.cert_cache.insert(digest);
    }

    /// Keys of a certificate's signers in `C_h` (want sources).
    fn signer_keys(&self, qc: &Qc) -> Vec<PublicKey> {
        self.config(qc.height)
            .and_then(|config| config.committee.keys_of(&qc.signers))
            .map(|keys| keys.into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Timeout table slot of `signer` (`None` when out of range).
    fn timeout_slot(&self, signer: ValidatorIndex) -> Option<&Option<TimeoutVote>> {
        self.timeouts.get(usize_of(signer))
    }

    /// `anchor(h, view) = min(t_enter + P(view), t_prop)` (§9.1).
    fn anchor(&self) -> Millis {
        pacemaker::anchor(
            self.t_enter,
            self.view,
            self.t_prop,
            &self.cfg.params,
            self.local.build_timeout,
        )
    }

    /// Whether a `PrepareQC` of the current view is held.
    fn has_pqc_of_view(&self) -> bool {
        self.high_pqc
            .as_ref()
            .is_some_and(|qc| qc.view == self.view)
    }

    /// Blocks whose bodies the round needs (§8.4, §6.9 rule 5): `pending_apply`, the current
    /// proposal (or the recorded one to re-send), the lock, and `high_tc.high_pqc`'s block
    /// (always kept in memory; fetched only while re-proposing).
    fn needed_bodies(&self, keep_tc_block: bool) -> Vec<Hash32> {
        let mut keep: Vec<Hash32> = self.pending_apply.iter().map(|p| p.block_hash).collect();
        if !self.awaiting {
            keep.extend(self.proposal.as_ref().map(|held| held.bh));
            keep.extend(self.resend_recorded);
            keep.extend(self.high_pqc.as_ref().map(|qc| qc.block_hash));
            if keep_tc_block || self.repropose {
                keep.extend(
                    self.high_tc
                        .as_ref()
                        .and_then(|tc| tc.high_pqc.as_ref())
                        .map(|qc| qc.block_hash),
                );
            }
        }
        keep
    }

    /// Drop bodies and wants that are no longer needed.
    fn prune_bodies(&mut self) {
        let keep = self.needed_bodies(true);
        self.blocks.retain(|bh, _| keep.contains(bh));
        let wanted = self.needed_bodies(false);
        self.wants.retain(|bh, _| wanted.contains(bh));
    }
}
