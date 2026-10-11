//! Mutation group 2 (spec §13.4, ML5a): the strengthened named test
//! `det_l5_lost_vote_retransmitted_strong`.
//!
//! The original `det_l5_lost_vote_retransmitted` (`machine::tests::liveness`) looks for the
//! lost Prepare re-sent at `t_retx` and again within `rebroadcast_interval`. The stage ladder
//! (§5.2) re-sends the same vote at exactly those times (stage 1 at `t_ready + t_retx`, stage 2
//! at `t_lastvote + 2·t_retx`), so deleting the §6.11 vote retransmit (mutation `ML5a`) went
//! unnoticed.
//!
//! This test drives one unmodified [`Core`] through its public API only (the harness plays
//! the other three validators with [`FakeValidators`] keys) and checks the exact send times
//! and recipients of the node's own votes against the §6.11 schedule — first send, one re-send
//! per stage entry, and re-sends at `t_vote + t_retx·(2^k − 1)` with the spacing capped at
//! `rebroadcast_interval` — in rounds where the retransmit is the only re-send path:
//!
//! 1. a set-A voter, default parameters: after the stage-2 re-send the Prepare is re-broadcast
//!    at `t_s2 + t_retx` until its `PrepareQC` is held;
//! 2. a set-B voter whose first Prepare (sent on entering stage 1) is lost: re-sent to `P` at
//!    `t_vote + t_retx` while still at stage 1 — the literal §13.4 row (a);
//! 3. that voter's Commit, sent at stage 1 on the `PrepareQC` and lost: re-sent to `P` at
//!    `t_pqc + t_retx`, then broadcast with doubling and capped spacing until the `CommitQC`;
//! 4. (b) the proxy tail answers a retransmitted Prepare with the `PrepareQC`, once per voter.
//!
//! The randomized scenario F9r ([`f09r`]) complements F9 for `ML5a`: under F9's random loss the
//! stage re-sends and the stage-2 broadcast recover every lost vote, so F9 cannot see the
//! retransmit. F9r lets the network adversary drop every vote and bare certificate for a window
//! ending at GST, long enough that the round in progress loses its first sends and both
//! stage-entry re-sends, and short enough that its view deadline lies well after GST. After GST
//! only the §6.11 retransmit re-sends those votes: the round must still commit in view 0 (the
//! `no_view_change` oracle). Without the retransmit its view times out.

use super::{
    byz::NetRule,
    rng::{Rng, seed_of},
    run,
    scenario::Scenario,
    sweep::{Failures, fold_seeds},
    world::seed_iter,
};
use crate::{
    Core,
    api::{Action, CommittedTip, Event, ExecOutcome, Init, LocalParams},
    availability::AvailableBody,
    crypto::Signer,
    message::{BlockHeader, Qc, VoteKind, WireMessage},
    preimage,
    safety::{RecordState, SafetyRecord},
    testing::{FakeValidators, SignLog, sha256},
    topology::Topology,
    types::{ChainParams, Hash32, HeightConfig, Millis, PublicKey, ValidatorIndex},
};

/// Instance id of the test.
const I: Hash32 = Hash32([0x5a; 32]);
/// Demotion window `W` (the §9.3 default).
const W: u64 = 128;
/// Genesis block hash and result.
const G_HASH: Hash32 = Hash32([0xaa; 32]);
const G_RESULT: Hash32 = Hash32([0xbb; 32]);
/// Committee size: `q = 3`, set A = {leader, one member, proxy tail}, set B = one member.
const N: usize = 4;

/// The deterministic execution result of the test: `R = H(parent_R ‖ payload)`.
fn result_of(block: &AvailableBody) -> Hash32 {
    let mut input = block.header().parent_result.0.to_vec();
    input.extend_from_slice(block.payload().as_slice());
    Hash32(sha256(&input))
}

/// One core at height 1 of a genesis chain, driven like a driver would (every `Send` and
/// `Broadcast` is recorded with its time; `Execute` is answered by the test).
struct Rig {
    v: FakeValidators,
    /// The topology of height 1 (no demotion before height 3).
    topo: Topology,
    me: ValidatorIndex,
    core: Core,
    budget: iroha_allocation::AllocationBudget,
    now: Millis,
    local: LocalParams,
    pending: Vec<(u64, AvailableBody)>,
    /// Every message the core sent: `(time, recipients, message)`.
    sent: Vec<(Millis, Vec<PublicKey>, WireMessage)>,
    /// The core's routing stage after every handled event, recorded when it changes.
    stages: Vec<(Millis, u8)>,
}

impl Rig {
    fn new(local: LocalParams, pick: impl Fn(&Topology) -> ValidatorIndex) -> Self {
        let v = FakeValidators::new(N, 7, Some(SignLog::new()));
        let topo = Topology::compute(
            &v.crypto,
            &I,
            &crate::testing::TEST_EPOCH,
            &v.committee,
            1,
            0,
            W,
            &[],
        );
        let me = pick(&topo);
        let signer = v.signer(me).clone();
        let key = signer.public_key().clone();
        let record = SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, key.clone(), 0, None)
            .encode(&v.crypto)
            .expect("encode the initial record");
        let config = HeightConfig {
            epoch: Box::new(crate::testing::TEST_EPOCH),
            committee: v.committee.clone(),
            params: ChainParams::default(),
        };
        let init = Init {
            instance: I,
            records: vec![(key, RecordState::Present(record), false)],
            genesis_height: 0,
            demotion_window: W,
            nonce: 1,
            tip: CommittedTip {
                height: 0,
                block_hash: G_HASH,
                result: G_RESULT,
                header: None,
                commit_qc: None,
            },
            configs: vec![
                (1, crate::types::ConfigSlot::Ready(config.clone())),
                (2, crate::types::ConfigSlot::Ready(config)),
            ],
            recent_headers: Vec::new(),
        };
        let budget = iroha_allocation::AllocationBudget::new(1 << 28);
        let (core, actions) = Core::new(
            local,
            init,
            vec![std::sync::Arc::new(signer)],
            Box::new(v.crypto.clone()),
            budget.clone(),
            0,
        )
        .expect("valid test configuration");
        let stage = core.status().stage;
        let mut rig = Self {
            v,
            topo,
            me,
            core,
            budget,
            now: 0,
            local,
            pending: Vec::new(),
            sent: Vec::new(),
            stages: vec![(0, stage)],
        };
        rig.absorb(actions);
        rig
    }

    fn absorb(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send { to, msg } => self.sent.push((self.now, vec![to], msg)),
                Action::Broadcast { to, msg } => self.sent.push((self.now, to, msg)),
                Action::Execute { block, req, .. } => self.pending.push((req, block)),
                _ => {}
            }
        }
        let stage = self.core.status().stage;
        if self.stages.last().is_none_or(|(_, s)| *s != stage) {
            self.stages.push((self.now, stage));
        }
    }

    fn fire(&mut self, event: Event) {
        let actions = self.core.handle(self.now, event);
        self.absorb(actions);
    }

    fn key(&self, index: ValidatorIndex) -> PublicKey {
        self.v.key(index)
    }

    fn deliver(&mut self, from: ValidatorIndex, msg: &WireMessage) {
        let mut msg = WireMessage::decode(&msg.encode().unwrap(), 32 << 20).unwrap();
        msg.admit_owned_bytes(&self.budget).unwrap();
        let from = self.key(from);
        self.fire(Event::Message { from, msg });
    }

    /// Deliver `Tick`s at every wakeup up to `until` (inclusive).
    fn run_until(&mut self, until: Millis) {
        for _ in 0..10_000 {
            let wake = self.core.next_wakeup();
            if wake > until {
                break;
            }
            self.now = self.now.max(wake);
            self.fire(Event::Tick);
        }
        self.now = self.now.max(until);
    }

    /// Answer every outstanding `Execute` with `Valid(result_of(block))`.
    fn exec_all(&mut self) {
        for (req, block) in std::mem::take(&mut self.pending) {
            let block_hash = block.hash(&self.v.crypto);
            self.fire(Event::Executed {
                block_hash,
                req,
                outcome: ExecOutcome::Valid(result_of(&block)),
            });
        }
    }

    /// A fresh block of height 1 first proposed in `view` by its leader.
    fn block(&self, view: u64, payload: &[u8]) -> AvailableBody {
        let header = BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: crate::testing::TEST_EPOCH.id,
            instance: I,
            height: 1,
            origin_view: view,
            parent_hash: G_HASH,
            parent_result: G_RESULT,
            payload_hash: preimage::payload_hash(&self.v.crypto, payload),
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).expect("a small payload"),
            proposer: self.topo.leader(view),
            skipped_leaders: self.topo.skipped_leader_keys(&self.v.committee, view),
        };
        crate::testing::author_body(
            header,
            payload,
            &HeightConfig {
                epoch: Box::new(crate::testing::TEST_EPOCH),
                committee: self.v.committee.clone(),
                params: ChainParams::default(),
            },
            &self.budget,
            &self.v.crypto,
            self.v.signer(self.topo.leader(view)),
        )
    }

    /// The leader of `(1, view)` sends its proposal of `block` (with payload).
    fn propose(&mut self, view: u64, block: &AvailableBody) {
        let leader = self.topo.leader(view);
        let proposal = self
            .v
            .proposal(leader, &I, 1, view, block.header().clone(), None, None);
        self.deliver(
            leader,
            &WireMessage::Proposal(Box::new(crate::message::ProposalMessage {
                proposal,
                availability: block.availability().clone(),
            })),
        );
        self.fire(Event::BodyAvailable {
            block: block.clone(),
        });
    }

    /// A certificate of `(1, view)` for `block` by exactly `signers`.
    fn qc(
        &self,
        kind: VoteKind,
        view: u64,
        block: &AvailableBody,
        signers: &[ValidatorIndex],
    ) -> Qc {
        let bh = block.hash(&self.v.crypto);
        self.v
            .qc(kind, &I, 1, view, &bh, &result_of(block), signers)
    }

    /// A certificate by the `q = 3` members other than the core.
    fn qc_q(&self, kind: VoteKind, view: u64, block: &AvailableBody) -> Qc {
        let others = self.others();
        self.qc(kind, view, block, &others)
    }

    /// The members other than the core, canonical order.
    fn others(&self) -> Vec<ValidatorIndex> {
        (0..u32::try_from(N).expect("small n"))
            .filter(|i| *i != self.me)
            .collect()
    }

    /// The proxy tail of `(1, view)`.
    fn proxy_tail(&self, view: u64) -> ValidatorIndex {
        self.topo.round(view).proxy_tail()
    }

    /// When the core first reached `stage` in the round (after `Core::new`).
    fn stage_entry(&self, stage: u8) -> Option<Millis> {
        self.stages
            .iter()
            .find(|(_, s)| *s >= stage)
            .map(|(t, _)| *t)
    }

    /// Every send of the core's own vote of `kind` at height 1 in `[from, until]`, with its
    /// recipients (sorted).
    fn own_votes(
        &self,
        kind: VoteKind,
        from: Millis,
        until: Millis,
    ) -> Vec<(Millis, Vec<PublicKey>)> {
        self.sent
            .iter()
            .filter(|(t, _, _)| (from..=until).contains(t))
            .filter_map(|(t, to, msg)| match msg {
                WireMessage::Vote(vote)
                    if vote.kind == kind && vote.signer == self.me && vote.height == 1 =>
                {
                    let mut to = to.clone();
                    to.sort();
                    Some((*t, to))
                }
                _ => None,
            })
            .collect()
    }

    /// The expected recipients of an own vote sent at `t`: `P` before stage 2, every other
    /// member from the stage-2 entry `t_s2` on (§5.2 routing).
    fn route_at(&self, t: Millis, t_s2: Option<Millis>) -> Vec<PublicKey> {
        let mut to: Vec<PublicKey> = if t_s2.is_some_and(|s2| t >= s2) {
            self.others().into_iter().map(|i| self.key(i)).collect()
        } else {
            vec![self.key(self.proxy_tail(0))]
        };
        to.sort();
        to
    }

    /// Whether the core sent a `Timeout` in `[from, until]`.
    fn timed_out_in(&self, from: Millis, until: Millis) -> bool {
        self.sent
            .iter()
            .any(|(t, _, msg)| (from..=until).contains(t) && matches!(msg, WireMessage::Timeout(_)))
    }
}

/// The §6.11 send times of one own vote in `[first, until]`: its first send, the one re-send
/// at each stage entry in `entries` (§5.2), and the retransmits at `t_vote + t_retx·(2^k − 1)`,
/// `k = 1, 2, …`, spacing capped at `cap`, `t_vote` being the latest of the first send and the
/// stage-entry re-sends. A retransmit due at a stage entry is that entry's re-send.
fn schedule(
    first: Millis,
    entries: &[Millis],
    t_retx: Millis,
    cap: Millis,
    until: Millis,
) -> Vec<Millis> {
    let mut out = vec![first];
    let mut entries = entries.iter().copied().filter(|t| *t > first).peekable();
    let mut k: u32 = 1;
    let mut last = first;
    loop {
        let spacing = t_retx.saturating_mul(2u64.saturating_pow(k - 1)).min(cap);
        let retx = last.saturating_add(spacing);
        let next = match entries.peek() {
            Some(&entry) if entry <= retx => {
                entries.next();
                k = 1;
                entry
            }
            _ => {
                k += 1;
                retx
            }
        };
        if next > until {
            break;
        }
        out.push(next);
        last = next;
    }
    out
}

/// Check the sends of an own vote in `[first, until]` against [`schedule`] with the stage
/// entries the core went through, and return the retransmit-only send times (neither the first
/// send nor a stage-entry re-send).
fn check_schedule(
    rig: &Rig,
    kind: VoteKind,
    first: Millis,
    until: Millis,
    what: &str,
) -> Vec<Millis> {
    let t_retx = rig.core.status().t_retx;
    let cap = rig.local.rebroadcast_interval;
    let entries: Vec<Millis> = [rig.stage_entry(1), rig.stage_entry(2)]
        .into_iter()
        .flatten()
        .filter(|t| *t > first && *t <= until)
        .collect();
    let t_s2 = rig.stage_entry(2);
    let expected: Vec<(Millis, Vec<PublicKey>)> = schedule(first, &entries, t_retx, cap, until)
        .into_iter()
        .map(|t| (t, rig.route_at(t, t_s2)))
        .collect();
    let got = rig.own_votes(kind, first, until);
    assert_eq!(
        got.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        expected.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        "{what}: {kind:?} send times vs the §6.11 schedule (t_retx {t_retx}, cap {cap}, \
         stage entries {entries:?})"
    );
    assert_eq!(got, expected, "{what}: {kind:?} recipients (§5.2 routing)");
    expected
        .into_iter()
        .map(|(t, _)| t)
        .filter(|t| *t != first && !entries.contains(t))
        .collect()
}

/// (1) Set-A voter, §9.3 default parameters: the Prepare sent to `P` at `t0` is lost; stage 1
/// re-sends it at `t0 + t_retx`, stage 2 broadcasts it at `t0 + 2·t_retx`, and from then on
/// only the retransmit schedule re-sends it (by broadcast), until the `PrepareQC` is held.
fn set_a_prepare_retransmitted_after_stage_2() {
    let mut r = Rig::new(LocalParams::default(), |t| {
        let round = t.round(0);
        round.set_a()[1..round.set_a().len() - 1][0]
    });
    let b = r.block(0, b"B");
    r.propose(0, &b);
    r.exec_all();
    let t0 = r.now;
    let t_retx = r.core.status().t_retx;
    let first = r.own_votes(VoteKind::Prepare, t0, t0);
    assert_eq!(
        first,
        vec![(t0, r.route_at(t0, None))],
        "Prepare to P when ready"
    );
    // The anchor is the proposal's arrival (t0): the view deadline is t0 + T(0).
    let until = t0 + r.local.t_base - 1;
    r.run_until(until);
    assert!(!r.timed_out_in(t0, until), "still in the view");
    assert_eq!(
        r.stage_entry(1),
        Some(t0 + t_retx),
        "stage 1 at t_ready + t_retx"
    );
    assert_eq!(
        r.stage_entry(2),
        Some(t0 + 2 * t_retx),
        "stage 2 at t_lastvote + 2·t_retx"
    );
    let retransmits = check_schedule(&r, VoteKind::Prepare, t0, until, "set-A Prepare");
    assert!(
        !retransmits.is_empty(),
        "the window holds a retransmit after the stage-2 re-send"
    );
    // The phase's QC stops the retransmissions of the Prepare.
    let qc = r.qc_q(VoteKind::Prepare, 0, &b);
    r.deliver(r.proxy_tail(0), &WireMessage::Qc(qc));
    let from = r.now + 1;
    r.run_until(from + 3 * r.local.rebroadcast_interval);
    assert!(
        r.own_votes(VoteKind::Prepare, from, r.now).is_empty(),
        "no Prepare re-sent once its PrepareQC is held"
    );
}

/// Parameters where `t_retx` (`3 · qc_lat_ewma = 750 ms`) is below both `φ·T/2` and the
/// spacing cap, so the doubling and the cap of §6.11 are visible before the view deadline.
fn wide_params() -> LocalParams {
    LocalParams {
        t_base: 8_000,
        rebroadcast_interval: 2_000,
        ..LocalParams::default()
    }
}

/// A set-B member of `(1, 0)` that accepted and executed the proposal at time 0: it votes only
/// on entering stage 1 at `t_ready + t_retx` (§5.2). Returns the rig and that time.
fn set_b_voter() -> (Rig, AvailableBody, Millis) {
    let mut r = Rig::new(wide_params(), |t| t.round(0).set_b()[0]);
    let b = r.block(0, b"B");
    r.propose(0, &b);
    r.exec_all();
    let t0 = r.now;
    let t_retx = r.core.status().t_retx;
    assert!(
        2 * t_retx < r.local.rebroadcast_interval && 2 * t_retx < r.local.t_base / 2,
        "t_retx {t_retx} is below the cap and φ·T/2"
    );
    assert!(
        r.own_votes(VoteKind::Prepare, t0, t0).is_empty(),
        "set B does not vote at stage 0"
    );
    let t_vote = t0 + t_retx;
    r.run_until(t_vote);
    assert_eq!(
        r.stage_entry(1),
        Some(t_vote),
        "stage 1 at t_ready + t_retx"
    );
    assert_eq!(
        r.own_votes(VoteKind::Prepare, t0, t_vote),
        vec![(t_vote, r.route_at(t_vote, None))],
        "the first Prepare, to P, on entering stage 1"
    );
    (r, b, t_vote)
}

/// (2) The set-B voter's first Prepare is lost: re-sent to `P` at `t_vote + t_retx`, still at
/// stage 1 (no stage entry is due then), then on the full schedule.
fn set_b_prepare_retransmitted_at_stage_1() {
    let (mut r, _, t_vote) = set_b_voter();
    let t_retx = r.core.status().t_retx;
    let until = r.local.t_base - 1;
    r.run_until(until);
    assert!(!r.timed_out_in(0, until), "still in the view");
    let t_s2 = r.stage_entry(2).expect("stage 2 within the view");
    assert_eq!(
        t_s2,
        t_vote + 2 * t_retx,
        "stage 2 at t_lastvote + 2·t_retx"
    );
    let resend = t_vote + t_retx;
    assert!(
        r.own_votes(VoteKind::Prepare, resend, resend)
            .contains(&(resend, r.route_at(resend, None))),
        "the lost Prepare is re-sent to P at t_vote + t_retx (§13.4 ML5a row (a))"
    );
    let retransmits = check_schedule(&r, VoteKind::Prepare, t_vote, until, "set-B Prepare");
    assert!(retransmits.contains(&resend));
    assert!(
        retransmits.iter().filter(|t| **t > t_s2).count() >= 3,
        "doubling spacing, then capped, after stage 2: {retransmits:?}"
    );
}

/// (3) The set-B voter holds the `PrepareQC` right after its Prepare: its Commit goes to `P` at
/// `t_pqc` and is lost; it is re-sent to `P` at `t_pqc + t_retx` (stage 1 already holds, so no
/// stage entry is due), broadcast from stage 2 on, until the `CommitQC` is held.
fn set_b_commit_retransmitted_at_stage_1() {
    let (mut r, b, t_vote) = set_b_voter();
    let pqc = r.qc_q(VoteKind::Prepare, 0, &b);
    r.deliver(r.proxy_tail(0), &WireMessage::Qc(pqc));
    let t_pqc = r.now;
    // The PrepareQC is a vote-to-QC latency sample (§9.1): `t_retx` from here on.
    let t_retx = r.core.status().t_retx;
    assert_eq!(t_pqc, t_vote);
    assert_eq!(
        r.own_votes(VoteKind::Commit, t_pqc, t_pqc),
        vec![(t_pqc, r.route_at(t_pqc, None))],
        "the Commit, to P, on the PrepareQC"
    );
    let until = r.local.t_base - 1;
    r.run_until(until);
    assert!(!r.timed_out_in(0, until), "still in the view");
    assert_eq!(
        r.stage_entry(2),
        Some(t_pqc + 2 * t_retx),
        "stage 2 at t_lastvote + 2·t_retx"
    );
    let resend = t_pqc + t_retx;
    assert!(
        r.own_votes(VoteKind::Commit, resend, resend)
            .contains(&(resend, r.route_at(resend, None))),
        "the lost Commit is re-sent to P at t_pqc + t_retx"
    );
    let retransmits = check_schedule(&r, VoteKind::Commit, t_pqc, until, "set-B Commit");
    assert!(retransmits.contains(&resend));
    assert_eq!(
        r.own_votes(VoteKind::Prepare, t_vote + 1, until),
        Vec::new(),
        "the PrepareQC ended the Prepare's retransmissions"
    );
    // The CommitQC ends the Commit's retransmissions.
    let cqc = r.qc_q(VoteKind::Commit, 0, &b);
    r.deliver(r.proxy_tail(0), &WireMessage::Qc(cqc));
    assert_eq!(r.core.status().committed_height, 1);
    let from = r.now + 1;
    r.run_until(from + 3 * r.local.rebroadcast_interval);
    assert!(
        r.own_votes(VoteKind::Commit, from, r.now).is_empty(),
        "no Commit re-sent once its CommitQC is held"
    );
}

/// (4) Row (b): the proxy tail answers a voter that evidently lacks the `PrepareQC` (its
/// Prepare of the view arrives after the QC formed), once per voter and view.
fn proxy_tail_answers_retransmitted_prepare() {
    let mut r = Rig::new(LocalParams::default(), |t| t.round(0).proxy_tail());
    let b = r.block(0, b"B");
    let pqc = r.qc_q(VoteKind::Prepare, 0, &b);
    let voter = r.others()[0];
    r.deliver(voter, &WireMessage::Qc(pqc.clone()));
    let bh = b.hash(&r.v.crypto);
    let vote =
        r.v.vote(VoteKind::Prepare, voter, &I, 1, 0, &bh, &result_of(&b));
    let answers = |r: &Rig, from: usize| {
        r.sent[from..]
            .iter()
            .filter(|(_, to, msg)| {
                matches!(msg, WireMessage::Qc(q) if *q == pqc) && *to == vec![r.key(voter)]
            })
            .count()
    };
    let mark = r.sent.len();
    r.deliver(voter, &WireMessage::Vote(vote));
    assert_eq!(answers(&r, mark), 1, "the PrepareQC answers the voter");
    let mark = r.sent.len();
    r.deliver(voter, &WireMessage::Vote(vote));
    assert_eq!(answers(&r, mark), 0, "once per voter");
}

#[test]
fn schedule_model() {
    // Stage entries at 500 and 1000 hide the first two retransmits; spacing capped at 500.
    assert_eq!(
        schedule(0, &[500, 1_000], 500, 500, 1_999),
        vec![0, 500, 1_000, 1_500]
    );
    // Doubling, a stage entry restarting the schedule, then the cap.
    assert_eq!(
        schedule(750, &[2_250], 750, 2_000, 7_999),
        vec![750, 1_500, 2_250, 3_000, 4_500, 6_500]
    );
}

/// `det_l5_lost_vote_retransmitted` strengthened (§13.4 `ML5a` (a), `ML5b` (b)): see the module
/// documentation.
#[test]
fn det_l5_lost_vote_retransmitted_strong() {
    set_a_prepare_retransmitted_after_stage_2();
    set_b_prepare_retransmitted_at_stage_1();
    set_b_commit_retransmitted_at_stage_1();
    proxy_tail_answers_retransmitted_prepare();
}

/// F9r: a vote blackout that ends at GST (see the module documentation). `n ∈ {4, 7, 5}`,
/// lossless links with random delays, the default workload (one height per `block_time`),
/// `T_base = 4 s` so that `2·t_retx` (at most `φ·T/2 = 1 s` each) plus the retransmit cap stay
/// far inside `T(0)`.
///
/// The blackout `[t_b, t_g)` lasts `D ∈ [1.5 s, 2.5 s)`. The round in progress at `t_b` was
/// proposed at `t_prop ≥ t_b − 100 ms` (earlier rounds commit within about 100 ms) and at the
/// latest about one `block_time` after `t_b`; its first votes, stage-1 and stage-2 re-sends
/// (within `2·t_retx ≈ 0.5 s` of its votes after warm-up) all fall into the blackout. Its view
/// deadline `t_prop + T(0) ≥ t_g + 1.4 s` leaves the retransmit (spacing capped at
/// `rebroadcast_interval = 0.5 s`) ample time after GST.
fn f09r(seed: u64) -> Scenario {
    let n = [4, 7, 5][usize::try_from(seed % 3).unwrap_or(0)];
    let mut sc = Scenario::base("F9r", seed, n);
    let mut rng = Rng::new(seed_of("F9r", seed) ^ 0x5bd1_e995_9e37_79b9);
    sc.local.t_base = 4_000;
    let blackout = rng.range(15_000, 25_000);
    let heal = blackout + rng.range(1_500, 2_500);
    sc.net_rules = vec![NetRule::DropVotes {
        from: blackout,
        until: heal,
    }];
    sc.heal_at = heal;
    sc.duration = heal + 20_000;
    sc.checks.no_view_change = true;
    sc.checks.progress = 8;
    sc
}

/// The F9r sweep (`SUMERAGI_SIM_SEEDS` seeds; default 5 in debug, 20 in release).
#[test]
fn f09r_vote_blackout_until_gst() {
    let default = if cfg!(debug_assertions) { 5 } else { 20 };
    let mut failures = Failures::default();
    let mut lost = 0;
    fold_seeds(
        seed_iter(default),
        |seed| run(f09r(seed)).map(|world| world.stats.lost),
        |seed, result| {
            if let Some(seed_lost) = failures.observe(seed, result) {
                lost += seed_lost;
            }
        },
    );
    failures.finish("F9r");
    assert!(lost > 0, "the blackout dropped votes");
}
