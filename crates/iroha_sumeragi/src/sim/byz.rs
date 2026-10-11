//! Byzantine strategies (§13.1, §13.3, the targeted adversaries of §13.4) and the adaptive
//! network adversary.
//!
//! A Byzantine machine runs an unmodified core for its protocol state, but everything it emits
//! passes through its strategies, which may drop, redirect or rewrite messages and inject
//! messages signed with its **own** keys only (honest signatures are never forged: the fake
//! scheme would allow it, the provenance log would expose it). Strategies compose: a machine may
//! have several. The network adversary sees every packet and applies [`NetRule`]s before heal.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

use super::{
    crypto::{SimSigner, aggregate},
    driver::{encode_tx, reference_exec},
    scenario::Scenario,
    world::{Machine, SharedWire, World},
};
use crate::{
    api::{Action, ExecOutcome},
    crypto::Signer,
    message::{
        BlockHeader, PayloadChunk, PayloadManifest, Proposal, ProposalMessage, Qc, Status,
        SyncEntry, SyncResponse, TcEntry, TimeoutCert, TimeoutVote, Vote, VoteKind, WireMessage,
    },
    preimage,
    types::{Bitmap, Hash32, Millis, PublicKey, SIGNATURE_LEN, Signature},
};

/// Who receives the certificates a withholding proxy tail forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deliver {
    /// Nobody (silent proxy tail).
    Nobody,
    /// One random honest member.
    One,
    /// A random half of the members.
    Half,
}

/// What a late leader delivers late (§9.2, F36).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Late {
    /// The whole proposal.
    Proposal,
    /// The actual rows: the mandatory signed proposal and manifest arrive at once.
    Body,
}

/// A Byzantine behaviour. Strategies compose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Emit nothing at all.
    Silent,
    /// Drop own votes; lead and aggregate correctly (F6, P2).
    WithholdVotes,
    /// As proxy tail, deliver formed certificates only as chosen (F2, F3, P3).
    WithholdQcs(Deliver),
    /// As leader, send a signed twin block to half of the recipients, then both to everyone
    /// in opposite orders (F5).
    Equivocate,
    /// Build TCs from the lowest-`hq` timeouts; propose with them when leading (F7).
    TcMinHq,
    /// Answer body requests with forged payloads under genuine headers, solicited and
    /// unsolicited (F26).
    ForgeBodies,
    /// Forged `CommitQC`s in `Status`, bare, and as `parent_qc` of own proposals (MS21).
    ForgeCommitQc,
    /// Replay every observed message into the other instances, unchanged and re-labelled
    /// (F20).
    Replay,
    /// Votes and timeouts for huge views and heights, far-future proposals and `Status`,
    /// junk requests, oversize messages (F18).
    Flood,
    /// `Status` with maximal-group TCs and timeouts with forged signatures at the rate limit
    /// (F29).
    CpuFlood,
    /// Own proposals carry a signed defect (F19-adjacent, MS19, `MS10b`).
    InvalidProposals,
    /// Relay honest proposals with stripped and corrupted payloads, before and after the
    /// genuine copy (F25).
    TamperRelay,
    /// Own proposals build on a stale parent (MS19).
    StaleParent,
    /// Propose in every view without being the leader (MS18).
    RaceProposals,
    /// Answer sync requests with forged blocks, invalid certificates, or not at all (F17).
    ForgeSync,
    /// Commit votes with forged signatures under honest signer indices for the current lock,
    /// plus the own genuine one (MS38).
    ForgeVotes,
    /// As proxy tail, rewrite the result of every certificate it forms (MS17).
    RewriteResult,
    /// Once removed from the committee, sign `CommitQC`s for later heights with the old keys
    /// (F16, MS15).
    RemovedCollusion,
    /// As proxy tail: broadcast the `PrepareQC`, deliver the `CommitQC` to one honest node,
    /// isolate it until a TC of the height is seen, and time out and vote for whatever is
    /// proposed meanwhile (F8, `MS10a`).
    SplitBrain,
    /// As proxy tail: deliver the `PrepareQC` to one honest node only and time out without a
    /// lock (F33).
    HiddenPqc,
    /// Replay the oldest `PrepareQC` seen at the current height to everyone (MS7).
    ReplayOldPqc,
    /// Form and broadcast certificates from `q − 1` votes (itself included, MS14).
    ShortQcs,
    /// Never propose (a leader that is silent only as leader; ML18).
    SilentLeader,
    /// As leader of view 0, deliver the proposal (or only its body) as late as the view still
    /// commits: `T(start)/2 + 100 ms` after the honest anchor `t_enter + P(0)` (or after the
    /// payload-less copy, whose body it never serves on request), with `start` the lowest
    /// honest start level (F36, ML29, ML30).
    LateLeader(Late),
    /// Answer every probe (§7.4 R2) with echoes that name other members' keys but carry its
    /// own signature (forged), with its own echo under another nonce (replayed), and with its
    /// own valid echo reporting a low height (a Byzantine member counts as one reply) (F24).
    ForgeEchoes,
    /// Broadcast a certificate with q + 1 genuine votes to test exact-quorum rejection.
    OverAggregate,
}

/// `(instance, kind, h, v, block hash, result)` of votes collected for a short certificate.
type ShortKey = (usize, u8, u64, u64, Hash32, Hash32);

/// A rule of the adaptive network adversary (active before heal unless stated otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetRule {
    /// Delay every timeout that carries a `PrepareQC` (lock holders' timeouts, F7).
    DelayLockedTimeouts(Millis),
    /// Strip (ppm) or corrupt (ppm) proposal payloads in flight (F25).
    TamperPayloads {
        /// Strip probability.
        strip_ppm: u32,
        /// Corrupt probability.
        corrupt_ppm: u32,
    },
    /// Drop every Commit vote in `[from, until)` (F32).
    DropCommitVotes {
        /// Start.
        from: Millis,
        /// End.
        until: Millis,
    },
    /// Drop every vote and bare certificate in `[from, until)` (F32: after a restart only the
    /// durable locks, carried in timeouts, can bring the certified block back).
    DropVotes {
        /// Start.
        from: Millis,
        /// End.
        until: Millis,
    },
    /// Strip the payload of proposals to the given machine before heal (forces body fetches).
    DropRowsTo(usize),
    /// Relay every echo `Status` through the given Byzantine machine: the direct copy is lost
    /// and the prober gets it from the relay (a relayed signed echo counts, F24).
    RelayEchoes(usize),
    /// Drop every packet of an instance in `[from, until)` (F31: one instance stalls).
    StallInstance {
        /// Instance index.
        inst: u32,
        /// Start.
        from: Millis,
        /// End.
        until: Millis,
    },
}

/// The adversary of a world.
#[derive(Debug, Default)]
pub struct Adversary {
    by_machine: BTreeMap<usize, Vec<Strategy>>,
    replica_machine: BTreeMap<usize, usize>,
    /// Network rules.
    pub rules: Vec<NetRule>,
    /// `SilentLeader` is active from this time on.
    pub silent_from: Millis,
    /// Timeouts observed: `(instance, h, v)` → signer → vote.
    timeouts: BTreeMap<(usize, u64, u64), BTreeMap<u32, TimeoutVote>>,
    /// TCs formed from the lowest `hq`: `(instance, h, v)`.
    min_tcs: BTreeMap<(usize, u64, u64), TimeoutCert>,
    /// Split brain: isolated machine, instance, height, view of the hidden commit.
    pub isolated: Option<(usize, usize, u64, u64)>,
    split_heights: BTreeSet<(usize, u64)>,
    /// Hidden PQC: `(instance, h, v, machine X that holds it)`.
    pub hidden: Option<(usize, u64, u64, usize)>,
    hidden_count: u32,
    /// Views of `(instance, h)` the split-brain adversary already timed out.
    split_timeouts: BTreeSet<(usize, u64, u64)>,
    split_votes: BTreeSet<(usize, u64, u64, u8)>,
    replay: VecDeque<(usize, WireMessage)>,
    /// Oldest `PrepareQC` seen per `(instance, h)`.
    old_pqcs: BTreeMap<(usize, u64), Qc>,
    /// Votes seen by short-certificate forgers.
    short: BTreeMap<ShortKey, BTreeMap<u32, Signature>>,
    /// Attested Commit votes seen by over-aggregators, and the values already over-aggregated.
    over: BTreeMap<ShortKey, BTreeMap<u32, Signature>>,
    over_sent: BTreeSet<ShortKey>,
    requests: VecDeque<(usize, PublicKey, WireMessage)>,
    relayed: BTreeSet<(usize, u64, u64)>,
    /// Each malicious replica injects one unsolicited corrupt copy per exact row identity.
    /// Receiving another adversary's copy must not recursively amplify the test traffic.
    forged_rows: BTreeSet<(usize, Hash32, u64, Hash32, u32)>,
    twins: VecDeque<(usize, Millis, Vec<usize>, Rc<SharedWire>)>,
    /// Late leader (body): when the full copy of `(instance, h)` goes out.
    late_bodies: BTreeMap<(usize, u64), Millis>,
    counter: u64,
}

impl Adversary {
    /// The adversary of a scenario.
    pub fn new(sc: &Scenario, machines: &[Machine]) -> Self {
        let by_machine: BTreeMap<usize, Vec<Strategy>> = sc.byz.iter().cloned().collect();
        let replica_machine = machines
            .iter()
            .enumerate()
            .flat_map(|(m, machine)| machine.replicas.iter().flatten().map(move |r| (*r, m)))
            .collect();
        Self {
            by_machine,
            replica_machine,
            rules: sc.net_rules.clone(),
            silent_from: sc.silent_leader_from,
            ..Self::default()
        }
    }

    /// Whether replica `r` runs any strategy.
    pub fn has_strategy(&self, r: usize) -> bool {
        self.replica_machine
            .get(&r)
            .is_some_and(|m| self.by_machine.contains_key(m))
    }

    fn strategies(&self, r: usize) -> Vec<Strategy> {
        self.replica_machine
            .get(&r)
            .and_then(|m| self.by_machine.get(m))
            .cloned()
            .unwrap_or_default()
    }
}

/// Junk signature bytes.
fn junk_sig(tag: u64) -> Signature {
    let mut bytes = [0u8; SIGNATURE_LEN];
    for (i, chunk) in bytes.chunks_mut(8).enumerate() {
        let word = tag
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(u64::try_from(i).unwrap_or(0));
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    Signature(bytes)
}

/// Re-label every instance field of a message (signatures are left alone).
pub fn relabel(msg: &WireMessage, id: Hash32) -> WireMessage {
    fn qc(q: &Qc, id: Hash32) -> Qc {
        Qc {
            instance: id,
            ..q.clone()
        }
    }
    fn tc(t: &TimeoutCert, id: Hash32) -> TimeoutCert {
        TimeoutCert {
            instance: id,
            high_pqc: t.high_pqc.as_ref().map(|q| qc(q, id)),
            ..t.clone()
        }
    }
    match msg {
        WireMessage::Proposal(p) => {
            let mut p = (**p).clone();
            p.proposal.instance = id;
            p.proposal.header.instance = id;
            p.proposal.justify = p.proposal.justify.as_ref().map(|t| tc(t, id));
            p.proposal.parent_qc = p.proposal.parent_qc.as_ref().map(|q| qc(q, id));
            WireMessage::Proposal(Box::new(p))
        }
        WireMessage::Vote(v) => WireMessage::Vote(Vote { instance: id, ..*v }),
        WireMessage::Qc(q) => WireMessage::Qc(qc(q, id)),
        WireMessage::Timeout(t) => WireMessage::Timeout(Box::new(TimeoutVote {
            instance: id,
            high_pqc: t.high_pqc.as_ref().map(|q| qc(q, id)),
            ..(**t).clone()
        })),
        WireMessage::Tc(t) => WireMessage::Tc(Box::new(tc(t, id))),
        WireMessage::Status(s) => WireMessage::Status(Box::new(Status {
            instance: id,
            committed_qc: s.committed_qc.as_ref().map(|q| qc(q, id)),
            high_pqc: s.high_pqc.as_ref().map(|q| qc(q, id)),
            high_tc: s.high_tc.as_ref().map(|t| tc(t, id)),
            ..(**s).clone()
        })),
        WireMessage::SyncRequest(q) => {
            WireMessage::SyncRequest(crate::message::SyncRequest { instance: id, ..*q })
        }
        WireMessage::SyncResponse(q) => WireMessage::SyncResponse(SyncResponse {
            instance: id,
            blocks: q
                .blocks
                .iter()
                .map(|e| SyncEntry {
                    manifest: PayloadManifest {
                        header: BlockHeader {
                            instance: id,
                            ..e.manifest.header.clone()
                        },
                        availability: e.manifest.availability.clone(),
                    },
                    commit_qc: qc(&e.commit_qc, id),
                })
                .collect(),
        }),
        WireMessage::PayloadRequest(q) => {
            WireMessage::PayloadRequest(crate::message::PayloadRequest { instance: id, ..*q })
        }
        WireMessage::ApplicationControl(message) => {
            WireMessage::ApplicationControl(crate::message::ApplicationControl {
                context: crate::api::ApplicationControlContext {
                    instance: id,
                    ..message.context
                },
                bytes: message.bytes,
            })
        }
        WireMessage::PayloadManifest(value) => WireMessage::PayloadManifest(PayloadManifest {
            header: BlockHeader {
                instance: id,
                ..value.header.clone()
            },
            availability: value.availability.clone(),
        }),
        WireMessage::PayloadChunk(value) => WireMessage::PayloadChunk(PayloadChunk {
            instance: id,
            ..value.clone()
        }),
    }
}

impl World {
    fn byz_signer(&self, r: usize) -> SimSigner {
        SimSigner::new(self.net_key(r), None, std::sync::Arc::clone(&self.log))
    }

    fn members_except(&self, r: usize, height: u64) -> Vec<usize> {
        let inst = self.replicas[r].inst;
        self.instances[inst]
            .committee(height)
            .members()
            .iter()
            .filter_map(|k| self.key_owner.get(k))
            .filter_map(|m| self.replica_of(*m, inst))
            .filter(|x| *x != r)
            .collect()
    }

    fn honest_members(&self, r: usize, height: u64) -> Vec<usize> {
        self.members_except(r, height)
            .into_iter()
            .filter(|x| !self.machines[self.replicas[*x].machine].byz)
            .collect()
    }

    fn byz_send_all(&mut self, r: usize, height: u64, msg: WireMessage, at: Millis) {
        let msg = SharedWire::share(msg);
        for target in self.members_except(r, height) {
            self.send_to_replica(r, target, Rc::clone(&msg), at);
        }
    }

    /// Sign only the current proposal envelope; relay/table corruption never gains an
    /// original author's signature by passing through this helper.
    fn resign_carrier(&self, r: usize, mut carrier: ProposalMessage) -> ProposalMessage {
        carrier.proposal.sig = self
            .byz_signer(r)
            .sign(&carrier.proposal.signing_preimage(&self.hasher));
        carrier
    }

    /// Encode and sign a fresh malicious-author body with that machine's actual own key.
    fn byz_proposal(
        &mut self,
        r: usize,
        header: BlockHeader,
        payload: &[u8],
        view: u64,
        justify: Option<TimeoutCert>,
        parent_qc: Option<Qc>,
    ) -> ProposalMessage {
        let config = self.instances[self.replicas[r].inst].config(header.height);
        let body = crate::testing::author_body(
            header,
            payload,
            &config,
            &self.replicas[r].budget,
            &self.hasher,
            &self.byz_signer(r),
        );
        let header = body.header().clone();
        let frame = body.availability().clone();
        self.replicas[r]
            .bodies
            .insert(body.hash(&self.hasher), body);
        self.resign_carrier(
            r,
            ProposalMessage {
                availability: frame,
                proposal: Proposal {
                    instance: header.instance,
                    height: header.height,
                    view,
                    header,
                    justify,
                    parent_qc,
                    sig: Signature([0; SIGNATURE_LEN]),
                },
            },
        )
    }

    fn proposal_payload(&self, r: usize, p: &ProposalMessage) -> Option<Vec<u8>> {
        self.local_body(r, p.proposal.height, &p.proposal.block_hash(&self.hasher))
            .map(|body| body.payload().as_slice().to_vec())
    }

    fn forged_qc(&mut self, r: usize, kind: VoteKind, height: u64, view: u64) -> Qc {
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        let committee = self.instances[inst].committee(height);
        let n = committee.n();
        let q = committee.q();
        self.adv.counter += 1;
        let bh = Hash32([u8::try_from(self.adv.counter % 251).unwrap_or(0); 32]);
        let result = Hash32([0x77; 32]);
        let epoch = self.instances[inst].epoch(height).id;
        let msg = preimage::vote_preimage(kind, &instance, &epoch, height, view, &bh, &result);
        let own = self.byz_signer(r).sign(&msg);
        let indices: Vec<u32> = (0..u32::try_from(q).unwrap_or(1)).collect();
        Qc {
            epoch,
            kind,
            instance,
            height,
            view,
            block_hash: bh,
            result,
            signers: Bitmap::from_indices(n, indices.iter().copied())
                .unwrap_or_else(|| Bitmap::new(n)),
            agg_sig: aggregate(&[own]),
        }
    }

    /// Filter and rewrite a Byzantine core's actions.
    #[allow(clippy::too_many_lines)] // one arm per strategy
    pub fn byz_filter(&mut self, r: usize, actions: Vec<Action>, at: Millis) -> Vec<Action> {
        let strategies = self.adv.strategies(r);
        if strategies.is_empty() {
            return actions;
        }
        let me = self.net_key(r);
        let inst = self.replicas[r].inst;
        let mut out = Vec::new();
        for action in &actions {
            if let Action::StoreBody { block } = action {
                self.replicas[r]
                    .bodies
                    .insert(block.hash(&self.hasher), block.clone());
            }
        }
        for action in actions {
            let (to, msg) = match &action {
                Action::DisseminatePayload { .. } if strategies.contains(&Strategy::Silent) => {
                    continue;
                }
                Action::DisseminatePayload { peers, body }
                    if strategies.contains(&Strategy::LateLeader(Late::Body)) =>
                {
                    let half = self.late_half_timeout(inst);
                    let due = *self
                        .adv
                        .late_bodies
                        .entry((inst, body.header().height))
                        .or_insert(at + half + 100);
                    self.disseminate_body(r, peers, body, due);
                    continue;
                }
                Action::Send { to, msg } => (vec![to.clone()], msg.clone()),
                Action::Broadcast { to, msg } => (to.clone(), msg.clone()),
                Action::ServeBlocks { .. } if strategies.contains(&Strategy::ForgeSync) => {
                    continue;
                }
                Action::ServePayload { height, .. }
                    if strategies.contains(&Strategy::ForgeBodies)
                        || (strategies.contains(&Strategy::LateLeader(Late::Body))
                            && self
                                .adv
                                .late_bodies
                                .get(&(inst, *height))
                                .is_some_and(|due| at < *due)) =>
                {
                    // F36 delays the initial rows. Once released, serve retries:
                    // rows that raced ahead of metadata may need to be fetched.
                    // Withholding them indefinitely introduces a different fault
                    // whose recovery legitimately increases measured view latency.
                    continue;
                }
                _ => {
                    if !strategies.contains(&Strategy::Silent)
                        || !matches!(
                            action,
                            Action::ServeBlocks { .. }
                                | Action::ServePayload { .. }
                                | Action::FetchPayload { .. }
                        )
                    {
                        out.push(action);
                    }
                    continue;
                }
            };
            if strategies.contains(&Strategy::Silent) {
                continue;
            }
            let own_index = self.instances[inst]
                .committee(self.replicas[r].height)
                .index_of(&me);
            let mut to = to;
            let mut msg = msg;
            let mut keep = true;
            for strategy in &strategies {
                match (strategy, &msg) {
                    (Strategy::WithholdVotes, WireMessage::Vote(v))
                        if Some(v.signer) == own_index =>
                    {
                        keep = false;
                    }
                    (Strategy::WithholdQcs(deliver), WireMessage::Qc(_)) => match deliver {
                        Deliver::Nobody => keep = false,
                        Deliver::One => {
                            let pick = self.rng.index(to.len().max(1));
                            to = to.get(pick).cloned().into_iter().collect();
                        }
                        Deliver::Half => {
                            self.rng.shuffle(&mut to);
                            to.truncate(to.len() / 2);
                        }
                    },
                    (Strategy::WithholdQcs(Deliver::Nobody), WireMessage::Status(s)) => {
                        let mut s = (**s).clone();
                        s.high_pqc = None;
                        msg = WireMessage::Status(Box::new(s));
                    }
                    (Strategy::RewriteResult, WireMessage::Qc(q)) => {
                        let mut q = q.clone();
                        q.result = Hash32([0x5e; 32]);
                        msg = WireMessage::Qc(q);
                    }
                    (Strategy::SplitBrain, _)
                        if self.adv.isolated.is_some_and(|(_, i, _, _)| i == inst) =>
                    {
                        // Act as if still at the split height: nothing above it leaves, and
                        // no `Status` reveals the hidden commit.
                        let Some((_, _, h, _)) = self.adv.isolated else {
                            continue;
                        };
                        match &msg {
                            WireMessage::Status(s) => {
                                let mut s = (**s).clone();
                                s.committed_qc = s.committed_qc.filter(|q| q.height < h);
                                s.high_pqc = None;
                                s.high_tc = None;
                                s.height = s.height.min(h);
                                msg = WireMessage::Status(Box::new(s));
                            }
                            other if other.round_height().is_some_and(|x| x >= h) => keep = false,
                            _ => {}
                        }
                    }
                    (Strategy::SplitBrain, WireMessage::Qc(q))
                        if q.kind == VoteKind::Commit && self.now < self.heal_at =>
                    {
                        let honest = self.honest_members(r, q.height);
                        if self.adv.split_heights.insert((inst, q.height))
                            && let Some(&x) = self.rng.pick(&honest)
                        {
                            let xm = self.replicas[x].machine;
                            self.adv.isolated = Some((xm, inst, q.height, q.view));
                            self.trace(
                                r,
                                format!(
                                    "split brain: CommitQC h{} v{} only to machine {xm}",
                                    q.height, q.view
                                ),
                            );
                            let target = self.net_key(x);
                            to = vec![target];
                        }
                    }
                    (Strategy::HiddenPqc, WireMessage::Qc(q)) => {
                        let active = self
                            .adv
                            .hidden
                            .filter(|(i, h, _, _)| *i == inst && *h == q.height);
                        match active {
                            Some((_, _, v, x)) if q.kind == VoteKind::Prepare && q.view == v => {
                                to = self
                                    .replica_of(x, inst)
                                    .map(|xr| self.net_key(xr))
                                    .into_iter()
                                    .collect();
                            }
                            Some(_) => keep = false,
                            None if q.kind == VoteKind::Prepare
                                && self.adv.hidden_count < 3
                                && self.now < self.heal_at =>
                            {
                                let honest = self.honest_members(r, q.height);
                                if let Some(&x) = self.rng.pick(&honest) {
                                    let xm = self.replicas[x].machine;
                                    self.adv.hidden = Some((inst, q.height, q.view, xm));
                                    self.adv.hidden_count += 1;
                                    self.trace(
                                        r,
                                        format!(
                                            "hidden PQC h{} v{} to machine {xm}",
                                            q.height, q.view
                                        ),
                                    );
                                    to = vec![self.net_key(x)];
                                }
                            }
                            None => {}
                        }
                    }
                    (Strategy::HiddenPqc, WireMessage::Status(s)) if self.adv.hidden.is_some() => {
                        let mut s = (**s).clone();
                        s.high_pqc = None;
                        msg = WireMessage::Status(Box::new(s));
                    }
                    (Strategy::HiddenPqc, WireMessage::Timeout(t)) => {
                        if let Some((i, h, v, _)) = self.adv.hidden
                            && i == inst
                            && t.height == h
                        {
                            if t.view > v {
                                // Withhold: the next TC needs the holder's timeout.
                                keep = false;
                            } else if t.high_pqc.is_some() {
                                let pre = preimage::tmo_preimage(
                                    &t.instance,
                                    &t.epoch,
                                    t.height,
                                    t.view,
                                    None,
                                );
                                let mut t2 = (**t).clone();
                                t2.high_pqc = None;
                                t2.sig = self.byz_signer(r).sign(&pre);
                                msg = WireMessage::Timeout(Box::new(t2));
                            }
                        }
                    }
                    (Strategy::HiddenPqc, WireMessage::Vote(v)) => {
                        if self
                            .adv
                            .hidden
                            .is_some_and(|(i, h, _, _)| i == inst && v.height == h)
                        {
                            keep = false;
                        }
                    }
                    (Strategy::Equivocate, WireMessage::Proposal(p)) => {
                        if let Some((a, b)) = self.twin(r, p) {
                            let recipients: Vec<usize> = to
                                .iter()
                                .filter_map(|k| self.key_owner.get(k))
                                .filter_map(|m| self.replica_of(*m, inst))
                                .collect();
                            let (half_a, half_b) = recipients.split_at(recipients.len() / 2);
                            let a = SharedWire::share(a);
                            let b = SharedWire::share(b);
                            for &x in half_a {
                                self.send_to_replica(r, x, Rc::clone(&a), at);
                            }
                            for &x in half_b {
                                self.send_to_replica(r, x, Rc::clone(&b), at);
                            }
                            // Later, everybody gets the other version too (both orders).
                            self.adv.twins.push_back((r, at + 150, half_a.to_vec(), b));
                            self.adv.twins.push_back((r, at + 150, half_b.to_vec(), a));
                            keep = false;
                        }
                    }
                    (Strategy::InvalidProposals, WireMessage::Proposal(p)) => {
                        msg = WireMessage::Proposal(Box::new(self.defective(r, p)));
                    }
                    (Strategy::StaleParent, WireMessage::Proposal(p)) if p.proposal.height > 1 => {
                        let mut header = p.proposal.header.clone();
                        let parent = self.oracle.refs[inst].get(&(p.proposal.height - 2)).map_or(
                            (
                                self.instances[inst].genesis_hash,
                                self.instances[inst].genesis_result,
                            ),
                            |b| (b.bh, b.result),
                        );
                        header.parent_hash = parent.0;
                        header.parent_result = parent.1;
                        let mut changed = (**p).clone();
                        changed.proposal.header = header;
                        msg = WireMessage::Proposal(Box::new(self.resign_carrier(r, changed)));
                    }
                    (Strategy::ForgeCommitQc, WireMessage::Proposal(p))
                        if p.proposal.parent_qc.is_some() =>
                    {
                        let forged = self.forged_qc(r, VoteKind::Commit, p.proposal.height - 1, 0);
                        let mut changed = (**p).clone();
                        changed.proposal.parent_qc = Some(forged);
                        msg = WireMessage::Proposal(Box::new(self.resign_carrier(r, changed)));
                    }
                    (Strategy::TcMinHq, WireMessage::Proposal(p)) if p.proposal.view > 0 => {
                        if let Some(min) = self
                            .adv
                            .min_tcs
                            .get(&(inst, p.proposal.height, p.proposal.view - 1))
                            .cloned()
                            .filter(|tc| tc.high_pqc.is_none())
                            && p.proposal
                                .justify
                                .as_ref()
                                .is_some_and(|j| j.high_pqc.is_some())
                        {
                            // Legal: a fresh block justified by a TC whose q entries carry
                            // no lock. Honest safety must not depend on the aggregator.
                            let topo = self.ground_topology(inst, p.proposal.height);
                            let committee =
                                self.instances[inst].committee(p.proposal.height).clone();
                            let payload = encode_tx(u64::MAX - self.adv.counter, false, 0);
                            let header = BlockHeader {
                                origin_view: p.proposal.view,
                                payload_hash: preimage::payload_hash(&self.hasher, &payload),
                                availability_digest: crate::types::Hash32::ZERO,
                                payload_len: u32::try_from(payload.len())
                                    .expect("bounded simulated payload"),
                                skipped_leaders: topo
                                    .skipped_leader_keys(&committee, p.proposal.view),
                                ..p.proposal.header.clone()
                            };
                            let header = BlockHeader {
                                parent_hash: p
                                    .proposal
                                    .parent_qc
                                    .as_ref()
                                    .map_or(self.instances[inst].genesis_hash, |q| q.block_hash),
                                parent_result: p
                                    .proposal
                                    .parent_qc
                                    .as_ref()
                                    .map_or(self.instances[inst].genesis_result, |q| q.result),
                                proposer: topo.leader(p.proposal.view),
                                ..header
                            };
                            msg = WireMessage::Proposal(Box::new(self.byz_proposal(
                                r,
                                header,
                                &payload,
                                p.proposal.view,
                                Some(min),
                                p.proposal.parent_qc.clone(),
                            )));
                        }
                    }
                    (Strategy::TcMinHq, WireMessage::Timeout(t)) => {
                        self.observe_timeout(r, t);
                    }
                    (Strategy::SilentLeader, WireMessage::Proposal(_))
                        if self.now >= self.adv.silent_from =>
                    {
                        keep = false;
                    }
                    (Strategy::LateLeader(late), WireMessage::Proposal(p))
                        if p.proposal.view == 0 =>
                    {
                        let recipients: Vec<usize> = to
                            .iter()
                            .filter_map(|k| self.key_owner.get(k))
                            .filter_map(|m| self.replica_of(*m, inst))
                            .collect();
                        let half = self.late_half_timeout(inst);
                        match late {
                            Late::Proposal => {
                                let p0 = self.instances[inst].params.payload_retry_interval
                                    + self.instances[inst].local.build_timeout;
                                // `t_enter` is on this machine's clock.
                                let clock = self.machines[self.replicas[r].machine].clock;
                                let due = self.replicas[r].host.core().map_or(at, |core| {
                                    clock.global_at(core.round_entered_at() + p0 + half + 100)
                                });
                                if at < due {
                                    self.adv.twins.push_back((
                                        r,
                                        due,
                                        recipients,
                                        SharedWire::share(msg.clone()),
                                    ));
                                    keep = false;
                                }
                            }
                            Late::Body => {
                                self.adv
                                    .late_bodies
                                    .entry((inst, p.proposal.height))
                                    .or_insert(at + half + 100);
                                // The mandatory metadata arrives now; actual rows are delayed
                                // by the DisseminatePayload action branch above.
                            }
                        }
                    }
                    (Strategy::ShortQcs, WireMessage::Vote(v)) => self.observe_short(r, v),
                    _ => {}
                }
                if !keep {
                    break;
                }
            }
            if keep && !to.is_empty() {
                out.push(Action::Broadcast { to, msg });
            }
        }
        out
    }

    /// `T(start)/2` for the lowest start level among the honest replicas of `inst` (a late
    /// leader targets the nodes whose timer is shortest, so the view still commits everywhere).
    fn late_half_timeout(&self, inst: usize) -> Millis {
        let local = self.instances[inst].local;
        let t_max = crate::pacemaker::effective_t_max(&local, &self.instances[inst].config(1));
        let level = self
            .honest()
            .into_iter()
            .filter(|x| self.replicas[*x].inst == inst)
            .filter_map(|x| self.replicas[x].host.core())
            .map(|core| core.status().start_level)
            .min()
            .unwrap_or(0);
        crate::pacemaker::view_timeout(local.t_base, t_max, level) / 2
    }

    /// A signed twin of an own fresh proposal: same round, a different payload.
    fn twin(&mut self, r: usize, p: &ProposalMessage) -> Option<(WireMessage, WireMessage)> {
        let fresh = p
            .proposal
            .justify
            .as_ref()
            .is_none_or(|tc| tc.high_pqc.is_none());
        if !fresh {
            return None;
        }
        self.adv.counter += 1;
        let mut payload = self.proposal_payload(r, p)?;
        payload.extend(encode_tx(u64::MAX - self.adv.counter, false, 8));
        let mut header = p.proposal.header.clone();
        header.payload_hash = preimage::payload_hash(&self.hasher, &payload);
        header.payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let twin = self.byz_proposal(
            r,
            header,
            &payload,
            p.proposal.view,
            p.proposal.justify.clone(),
            p.proposal.parent_qc.clone(),
        );
        Some((
            WireMessage::Proposal(Box::new(p.clone())),
            WireMessage::Proposal(Box::new(twin)),
        ))
    }

    /// A valid envelope signature over a defective signed header. The unchanged original
    /// manifest cannot authorize the mutated header; no relay can create this envelope signature.
    fn defective(&mut self, r: usize, p: &ProposalMessage) -> ProposalMessage {
        let mut changed = p.clone();
        let header = &mut changed.proposal.header;
        match self.rng.below(3) {
            0 => header.skipped_leaders.push(self.net_key(r)),
            1 => header.parent_result = Hash32([0x42; 32]),
            _ => {
                header.payload_hash = preimage::payload_hash(&self.hasher, &[]);
                header.payload_len = 0;
            }
        }
        self.resign_carrier(r, changed)
    }

    fn observe_timeout(&mut self, r: usize, t: &TimeoutVote) {
        let inst = self.replicas[r].inst;
        let key = (inst, t.height, t.view);
        self.adv
            .timeouts
            .entry(key)
            .or_default()
            .insert(t.signer, t.clone());
        // Bounded: keep the latest few rounds only.
        while self.adv.timeouts.len() > 64 {
            self.adv.timeouts.pop_first();
        }
        let q = self.instances[inst].committee(t.height).q();
        let Some(pool) = self.adv.timeouts.get(&key) else {
            return;
        };
        if pool.len() < q || self.adv.min_tcs.contains_key(&key) {
            return;
        }
        let mut chosen: Vec<&TimeoutVote> = pool.values().collect();
        chosen.sort_by(|a, b| a.hq().cmp(&b.hq()).then(a.signer.cmp(&b.signer)));
        chosen.truncate(q);
        chosen.sort_by_key(|t| t.signer);
        let high_pqc = chosen
            .iter()
            .filter(|t| t.high_pqc.is_some())
            .max_by(|a, b| a.hq().cmp(&b.hq()).then(b.signer.cmp(&a.signer)))
            .and_then(|t| t.high_pqc.clone());
        let tc = TimeoutCert {
            epoch: t.epoch,
            instance: t.instance,
            height: t.height,
            view: t.view,
            entries: chosen
                .iter()
                .map(|t| TcEntry {
                    signer: t.signer,
                    hq: t.hq(),
                })
                .collect(),
            agg_sig: aggregate(&chosen.iter().map(|t| t.sig).collect::<Vec<_>>()),
            high_pqc,
        };
        self.adv.min_tcs.insert(key, tc.clone());
        while self.adv.min_tcs.len() > 64 {
            self.adv.min_tcs.pop_first();
        }
        let height = t.height;
        let at = self.now;
        // A downgraded TC (MS12): the entries declare the true maximum `hq`, the attached
        // PrepareQC is an older one. Verification must recompute the maximum and reject it.
        let all: Vec<&TimeoutVote> = self
            .adv
            .timeouts
            .get(&key)
            .map(|pool| pool.values().collect())
            .unwrap_or_default();
        let max = all.iter().filter_map(|t| t.hq()).max();
        let older = all
            .iter()
            .filter_map(|t| t.high_pqc.as_ref())
            .chain(self.adv.old_pqcs.get(&(inst, t.height)))
            .filter(|q| max.is_some_and(|m| q.view < m))
            .min_by_key(|q| q.view)
            .cloned();
        if let Some(older) = older
            && all.len() >= q
        {
            let mut chosen: Vec<&TimeoutVote> = all.clone();
            chosen.sort_by(|a, b| b.hq().cmp(&a.hq()).then(a.signer.cmp(&b.signer)));
            chosen.truncate(q);
            chosen.sort_by_key(|t| t.signer);
            let downgraded = TimeoutCert {
                epoch: t.epoch,
                instance: t.instance,
                height: t.height,
                view: t.view,
                entries: chosen
                    .iter()
                    .map(|t| TcEntry {
                        signer: t.signer,
                        hq: t.hq(),
                    })
                    .collect(),
                agg_sig: aggregate(&chosen.iter().map(|t| t.sig).collect::<Vec<_>>()),
                high_pqc: Some(older),
            };
            self.trace(r, format!("downgraded TC h{} v{}", t.height, t.view));
            self.byz_send_all(r, height, WireMessage::Tc(Box::new(downgraded)), at);
        }
        self.byz_send_all(r, height, WireMessage::Tc(Box::new(tc)), at);
    }

    /// Short certificates (MS14): as soon as `q − 1` matching votes are known, broadcast a
    /// certificate with exactly those signers (it must be rejected: below quorum).
    fn observe_short(&mut self, r: usize, v: &Vote) {
        let inst = self.replicas[r].inst;
        let committee = self.instances[inst].committee(v.height).clone();
        let need = committee.q().saturating_sub(1).max(1);
        let key = (
            inst,
            v.kind.byte(),
            v.height,
            v.view,
            v.block_hash,
            v.result,
        );
        let pool = self.adv.short.entry(key).or_default();
        if pool.len() >= need || pool.contains_key(&v.signer) {
            return;
        }
        pool.insert(v.signer, v.sig);
        if pool.len() < need {
            while self.adv.short.len() > 256 {
                self.adv.short.pop_first();
            }
            return;
        }
        let signers: Vec<u32> = pool.keys().copied().collect();
        let sigs: Vec<Signature> = pool.values().copied().collect();
        let qc = Qc {
            epoch: v.epoch,
            kind: v.kind,
            instance: v.instance,
            height: v.height,
            view: v.view,
            block_hash: v.block_hash,
            result: v.result,
            signers: Bitmap::from_indices(committee.n(), signers.iter().copied())
                .unwrap_or_else(|| Bitmap::new(committee.n())),
            agg_sig: aggregate(&sigs),
        };
        let at = self.now;
        self.byz_send_all(r, v.height, WireMessage::Qc(qc), at);
    }

    /// Pool q genuine Commit votes, add one distinct own vote, and broadcast a
    /// q + 1 signer certificate to exercise exact-quorum rejection.
    fn observe_over(&mut self, r: usize, v: &Vote) {
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        let committee = self.instances[inst].committee(v.height).clone();
        let me = self.net_key(r);
        let Some(own) = committee.index_of(&me) else {
            return;
        };
        let key = (
            inst,
            v.kind.byte(),
            v.height,
            v.view,
            v.block_hash,
            v.result,
        );
        let genuine = v.kind == VoteKind::Commit
            && v.signer != own
            && crate::crypto::Verifier::new(&self.hasher, &instance, &v.epoch, &committee)
                .verify_vote(v)
                .is_ok();
        if !genuine || self.adv.over_sent.contains(&key) {
            return;
        }
        let pool = self.adv.over.entry(key).or_default();
        pool.insert(v.signer, v.sig);
        if pool.len() < committee.q() {
            while self.adv.over.len() > 256 {
                self.adv.over.pop_first();
            }
            return;
        }
        let mut votes = self.adv.over.remove(&key).unwrap_or_default();
        self.adv.over_sent.insert(key);
        let msg = preimage::vote_preimage(
            VoteKind::Commit,
            &instance,
            &v.epoch,
            v.height,
            v.view,
            &v.block_hash,
            &v.result,
        );
        votes.insert(own, self.byz_signer(r).sign(&msg));
        let qc = Qc {
            epoch: v.epoch,
            kind: VoteKind::Commit,
            instance,
            height: v.height,
            view: v.view,
            block_hash: v.block_hash,
            result: v.result,
            signers: Bitmap::from_indices(committee.n(), votes.keys().copied())
                .unwrap_or_else(|| Bitmap::new(committee.n())),
            agg_sig: aggregate(&votes.values().copied().collect::<Vec<_>>()),
        };
        self.trace(
            r,
            format!("over-aggregated CommitQC h{} v{}", v.height, v.view),
        );
        let at = self.now;
        self.byz_send_all(r, v.height, WireMessage::Qc(qc), at);
    }

    /// Observe a message arriving at a Byzantine replica.
    #[allow(clippy::too_many_lines)] // one dispatch over the strategies
    pub fn byz_observe(&mut self, r: usize, from: &PublicKey, msg: &Rc<SharedWire>) {
        let strategies = self.adv.strategies(r);
        let inst = self.replicas[r].inst;
        for strategy in &strategies {
            match (strategy, msg.message()) {
                (Strategy::TcMinHq, WireMessage::Timeout(t)) => self.observe_timeout(r, t),
                (Strategy::ForgeEchoes, WireMessage::Status(s)) => {
                    if let Some(nonce) = s.probe {
                        self.forge_echoes(r, from, nonce);
                    }
                }
                (Strategy::ShortQcs, WireMessage::Vote(v)) => self.observe_short(r, v),
                (Strategy::OverAggregate, WireMessage::Vote(v)) => self.observe_over(r, v),
                (Strategy::ForgeBodies, WireMessage::PayloadRequest(_))
                | (Strategy::ForgeSync, WireMessage::SyncRequest(_)) => {
                    if self.adv.requests.len() < 256 {
                        self.adv
                            .requests
                            .push_back((r, from.clone(), msg.message().clone()));
                    }
                }
                (Strategy::ForgeBodies, WireMessage::PayloadChunk(chunk)) => {
                    if !self.adv.forged_rows.insert((
                        r,
                        chunk.instance,
                        chunk.height,
                        chunk.block_hash,
                        chunk.index,
                    )) {
                        continue;
                    }
                    let mut forged = chunk.clone();
                    let mut bytes = forged.bytes.as_slice().to_vec();
                    bytes[0] ^= 0xee;
                    forged.bytes = crate::availability::RowBytes::from_untrusted(bytes).unwrap();
                    self.byz_send_all(r, chunk.height, WireMessage::PayloadChunk(forged), self.now);
                }
                (Strategy::TamperRelay, WireMessage::Proposal(p)) => {
                    if self
                        .adv
                        .relayed
                        .insert((inst, p.proposal.height, p.proposal.view))
                    {
                        let mut corrupt = (**p).clone();
                        let mut bytes = corrupt.availability.as_slice().to_vec();
                        *bytes.last_mut().unwrap() ^= 1;
                        corrupt.availability =
                            crate::availability::AvailabilityFrame::from_untrusted(bytes).unwrap();
                        let mut stripped = (**p).clone();
                        stripped.availability =
                            crate::availability::AvailabilityFrame::from_untrusted(Vec::new())
                                .unwrap();
                        self.byz_send_all(
                            r,
                            p.proposal.height,
                            WireMessage::Proposal(Box::new(corrupt)),
                            self.now,
                        );
                        self.byz_send_all(
                            r,
                            p.proposal.height,
                            WireMessage::Proposal(Box::new(stripped)),
                            self.now,
                        );
                        self.adv.twins.push_back((
                            r,
                            self.now + 150,
                            self.members_except(r, p.proposal.height),
                            Rc::clone(msg),
                        ));
                    }
                }
                (Strategy::Replay, _) => {
                    if self.adv.replay.len() < 512 {
                        self.adv.replay.push_back((inst, msg.message().clone()));
                    }
                }
                (Strategy::SplitBrain, _) => self.split_brain_observe(r, msg),
                (Strategy::ReplayOldPqc, _) => {
                    let found: Vec<&Qc> = match msg.message() {
                        WireMessage::Qc(q) => vec![q],
                        WireMessage::Timeout(t) => t.high_pqc.iter().collect(),
                        WireMessage::Tc(t) => t.high_pqc.iter().collect(),
                        WireMessage::Status(s) => s.high_pqc.iter().collect(),
                        WireMessage::Proposal(p) => p
                            .proposal
                            .justify
                            .as_ref()
                            .and_then(|t| t.high_pqc.as_ref())
                            .into_iter()
                            .collect(),
                        _ => Vec::new(),
                    };
                    for q in found {
                        if q.kind == VoteKind::Prepare {
                            let slot = self
                                .adv
                                .old_pqcs
                                .entry((inst, q.height))
                                .or_insert_with(|| q.clone());
                            if q.view < slot.view {
                                *slot = q.clone();
                            }
                        }
                    }
                    while self.adv.old_pqcs.len() > 32 {
                        self.adv.old_pqcs.pop_first();
                    }
                }
                _ => {}
            }
        }
    }

    /// Split-brain helper: time out and vote for anything at the split height while the
    /// committer is isolated, so that the remaining members can form certificates.
    fn split_brain_observe(&mut self, r: usize, msg: &WireMessage) {
        let inst = self.replicas[r].inst;
        let Some((_, i, h, _)) = self.adv.isolated else {
            return;
        };
        if i != inst {
            return;
        }
        let signer = self.byz_signer(r);
        let me = self.net_key(r);
        let committee = self.instances[inst].committee(h).clone();
        let Some(index) = committee.index_of(&me) else {
            return;
        };
        let instance = self.instances[inst].id;
        let epoch = self.instances[inst].epoch(h).id;
        let at = self.now;
        let vote = |world: &mut Self, kind: VoteKind, view: u64, bh: Hash32, result: Hash32| {
            if !world.adv.split_votes.insert((inst, h, view, kind.byte())) {
                return;
            }
            let pre = preimage::vote_preimage(kind, &instance, &epoch, h, view, &bh, &result);
            let vote = Vote {
                epoch,
                kind,
                instance,
                height: h,
                view,
                block_hash: bh,
                result,
                signer: index,
                sig: signer.sign(&pre),
            };
            world.byz_send_all(r, h, WireMessage::Vote(vote), at);
        };
        match msg {
            WireMessage::Timeout(t) if t.height == h => {
                if self.adv.split_timeouts.insert((inst, h, t.view)) {
                    let msgs = preimage::tmo_preimage(&instance, &epoch, h, t.view, None);
                    let timeout = TimeoutVote {
                        epoch,
                        instance,
                        height: h,
                        view: t.view,
                        high_pqc: None,
                        signer: index,
                        sig: self.byz_signer(r).sign(&msgs),
                    };
                    self.byz_send_all(r, h, WireMessage::Timeout(Box::new(timeout)), at);
                }
            }
            WireMessage::Proposal(p) if p.proposal.height == h && p.proposal.view > 0 => {
                let Some(payload) = self.proposal_payload(r, p) else {
                    return;
                };
                let bh = preimage::block_hash(&self.hasher, &p.proposal.header);
                let result = p
                    .proposal
                    .justify
                    .as_ref()
                    .and_then(|tc| tc.high_pqc.as_ref())
                    .map(|q| q.result)
                    .or_else(
                        || match reference_exec(&p.proposal.header.parent_result, &payload) {
                            ExecOutcome::Valid(res) => Some(res),
                            _ => None,
                        },
                    );
                if let Some(result) = result {
                    vote(self, VoteKind::Prepare, p.proposal.view, bh, result);
                }
            }
            WireMessage::Vote(v) if v.height == h && v.view > 0 => {
                vote(self, v.kind, v.view, v.block_hash, v.result);
            }
            WireMessage::Qc(q) if q.height == h && q.kind == VoteKind::Prepare && q.view > 0 => {
                vote(self, VoteKind::Commit, q.view, q.block_hash, q.result);
            }
            _ => {}
        }
    }

    /// Periodic active behaviour of a Byzantine replica (every 100 ms).
    #[allow(clippy::too_many_lines)] // one arm per strategy
    pub fn byz_tick(&mut self, r: usize) {
        let m = self.replicas[r].machine;
        if !self.machines[m].up || self.replicas[r].host.core().is_none() {
            return;
        }
        let now = self.now;
        // Delayed twins / relays.
        let due: Vec<_> = {
            let (ready, later): (Vec<_>, Vec<_>) = self
                .adv
                .twins
                .drain(..)
                .partition(|(from, t, _, _)| *from == r && *t <= now);
            self.adv.twins = later.into();
            ready
        };
        for (_, _, targets, msg) in due {
            for x in targets {
                self.send_to_replica(r, x, Rc::clone(&msg), now);
            }
        }
        let strategies = self.adv.strategies(r);
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        let (height, view, lock, tip_qc) = {
            let Some(core) = self.replicas[r].host.core() else {
                return;
            };
            let status = core.status();
            (
                status.height,
                status.view,
                core.lock().cloned(),
                core.committed_qc().cloned(),
            )
        };
        let epoch = self.instances[inst].epoch(height).id;
        let me = self.net_key(r);
        let signer = self.byz_signer(r);
        let committee = self.instances[inst].committee(height).clone();
        let own_index = committee.index_of(&me);
        for strategy in &strategies {
            match strategy {
                Strategy::ForgeCommitQc => {
                    let forged = self.forged_qc(r, VoteKind::Commit, height, view);
                    let far = self.forged_qc(r, VoteKind::Commit, height + 3, 0);
                    let status = Status {
                        instance,
                        height,
                        view,
                        committed_qc: Some(forged.clone()),
                        ..Status::default()
                    };
                    self.byz_send_all(r, height, WireMessage::Status(Box::new(status)), now);
                    self.byz_send_all(r, height, WireMessage::Qc(forged), now);
                    self.byz_send_all(r, height, WireMessage::Qc(far), now);
                }
                Strategy::ForgeVotes => {
                    // `q − 1` forged Commit votes under honest signer indices for the current
                    // lock (the MS38 attack), to the proxy tail and two other members.
                    if let Some(q) = lock
                        .as_ref()
                        .filter(|q| q.view == view && q.height == height)
                    {
                        let tail = self.ground_topology(inst, height).round(view).proxy_tail();
                        let mut targets: Vec<usize> = committee
                            .get(tail)
                            .and_then(|k| self.key_owner.get(k))
                            .and_then(|m| self.replica_of(*m, inst))
                            .into_iter()
                            .collect();
                        let others = self.members_except(r, height);
                        for _ in 0..2 {
                            if let Some(x) = self.rng.pick(&others) {
                                targets.push(*x);
                            }
                        }
                        let forged: Vec<u32> = (0..u32::try_from(committee.n()).unwrap_or(0))
                            .filter(|s| Some(*s) != own_index)
                            .take(committee.q().saturating_sub(1))
                            .collect();
                        for s in forged {
                            self.adv.counter += 1;
                            let vote = SharedWire::share(WireMessage::Vote(Vote {
                                epoch,
                                kind: VoteKind::Commit,
                                instance,
                                height,
                                view,
                                block_hash: q.block_hash,
                                result: q.result,
                                signer: s,
                                sig: junk_sig(self.adv.counter),
                            }));
                            for &x in &targets {
                                if x != r {
                                    self.send_to_replica(r, x, Rc::clone(&vote), now);
                                }
                            }
                        }
                    }
                }
                Strategy::RaceProposals => {
                    let leader = self.ground_topology(inst, height).leader(view);
                    if Some(leader) != own_index
                        && let Some(index) = own_index
                    {
                        let (parent_hash, parent_result) = tip_qc.as_ref().map_or(
                            (
                                self.instances[inst].genesis_hash,
                                self.instances[inst].genesis_result,
                            ),
                            Qc::value,
                        );
                        let payload = encode_tx(u64::MAX - u64::from(index), false, 2);
                        let header = BlockHeader {
                            control_witness: crate::types::ControlWitness::empty(),
                            epoch,
                            instance,
                            height,
                            origin_view: view,
                            parent_hash,
                            parent_result,
                            payload_hash: preimage::payload_hash(&self.hasher, &payload),
                            availability_digest: crate::types::Hash32::ZERO,
                            payload_len: u32::try_from(payload.len()).unwrap_or(0),
                            proposer: index,
                            skipped_leaders: Vec::new(),
                        };
                        let justify = self.replicas[r]
                            .host
                            .core()
                            .and_then(|c| c.highest_tc().cloned())
                            .filter(|tc| tc.view + 1 == view);
                        if view == 0 || justify.is_some() {
                            let p = self.byz_proposal(
                                r,
                                header,
                                &payload,
                                view,
                                justify,
                                tip_qc.clone(),
                            );
                            self.byz_send_all(r, height, WireMessage::Proposal(Box::new(p)), now);
                        }
                    }
                }
                Strategy::Flood => {
                    if let Some(index) = own_index {
                        let v2 = view + 1_000_000;
                        let pre = preimage::vote_preimage(
                            VoteKind::Prepare,
                            &instance,
                            &epoch,
                            height,
                            v2,
                            &Hash32::ZERO,
                            &Hash32::ZERO,
                        );
                        let vote = Vote {
                            epoch,
                            kind: VoteKind::Prepare,
                            instance,
                            height,
                            view: v2,
                            block_hash: Hash32::ZERO,
                            result: Hash32::ZERO,
                            signer: index,
                            sig: signer.sign(&pre),
                        };
                        self.byz_send_all(r, height, WireMessage::Vote(vote), now);
                        let tv = view + 1_000_000_000;
                        let tmo = TimeoutVote {
                            epoch,
                            instance,
                            height,
                            view: tv,
                            high_pqc: None,
                            signer: index,
                            sig: signer
                                .sign(&preimage::tmo_preimage(&instance, &epoch, height, tv, None)),
                        };
                        self.byz_send_all(r, height, WireMessage::Timeout(Box::new(tmo)), now);
                        let far = self.forged_qc(r, VoteKind::Commit, height + 1_000, 0);
                        let status = Status {
                            instance,
                            height: height + 1_001,
                            view: 5,
                            committed_qc: Some(far),
                            proposal_hash: Some(Hash32([9; 32])),
                            want_proposal: true,
                            probe: Some(self.adv.counter),
                            ..Status::default()
                        };
                        self.byz_send_all(r, height, WireMessage::Status(Box::new(status)), now);
                        let request = WireMessage::PayloadRequest(crate::message::PayloadRequest {
                            instance,
                            height,
                            block_hash: Hash32([self.adv.counter.to_be_bytes()[7]; 32]),
                        });
                        self.byz_send_all(r, height, request, now);
                        let sync = WireMessage::SyncRequest(crate::message::SyncRequest {
                            instance,
                            from_height: 1,
                            max_count: 64,
                            max_bytes: u32::MAX,
                        });
                        self.byz_send_all(r, height, sync, now);
                        if self.adv.counter.is_multiple_of(10) {
                            let mut table =
                                vec![0; crate::availability::MAX_AVAILABILITY_FRAME_BYTES];
                            table[..4].copy_from_slice(
                                &crate::availability::MAX_DA_CHUNK_COUNT.to_be_bytes(),
                            );
                            let header = BlockHeader {
                                control_witness: crate::types::ControlWitness::empty(),
                                epoch,
                                instance,
                                height,
                                origin_view: view,
                                parent_hash: Hash32::ZERO,
                                parent_result: Hash32::ZERO,
                                payload_hash: Hash32::ZERO,
                                availability_digest: Hash32::ZERO,
                                payload_len: 1,
                                proposer: index,
                                skipped_leaders: Vec::new(),
                            };
                            let manifest = PayloadManifest {
                                header,
                                availability:
                                    crate::availability::AvailabilityFrame::from_untrusted(table)
                                        .unwrap(),
                            };
                            let qc = self.forged_qc(r, VoteKind::Commit, height, view);
                            let msg = WireMessage::SyncResponse(SyncResponse {
                                instance,
                                blocks: vec![
                                    SyncEntry {
                                        manifest,
                                        commit_qc: qc
                                    };
                                    65
                                ],
                            });
                            self.byz_send_all(r, height, msg, now);
                        }
                        self.adv.counter += 1;
                    }
                }
                Strategy::CpuFlood => {
                    let q = committee.q();
                    // A TC whose q entries all carry distinct `hq`: q + 1 pairings to reject.
                    let tview = view + u64::try_from(q).unwrap_or(1);
                    let entries: Vec<TcEntry> = (0..u32::try_from(q).unwrap_or(1))
                        .map(|s| TcEntry {
                            signer: s,
                            hq: (s > 0).then(|| u64::from(s) - 1),
                        })
                        .collect();
                    let high = self.forged_qc(
                        r,
                        VoteKind::Prepare,
                        height,
                        u64::try_from(q).unwrap_or(2) - 2,
                    );
                    self.adv.counter += 1;
                    let tc = TimeoutCert {
                        epoch,
                        instance,
                        height,
                        view: tview,
                        entries,
                        agg_sig: crate::types::AggregateSignature(junk_sig(self.adv.counter).0),
                        high_pqc: Some(high),
                    };
                    let status = Status {
                        instance,
                        height,
                        view: tview,
                        high_tc: Some(tc),
                        ..Status::default()
                    };
                    self.byz_send_all(r, height, WireMessage::Status(Box::new(status)), now);
                    // Forged timeouts under four (rotating) honest indices per tick: each costs a
                    // verification; more would only be dropped at the per-peer ingress bound.
                    let n32 = u32::try_from(committee.n()).unwrap_or(1).max(1);
                    let first = u32::try_from(self.adv.counter % u64::from(n32)).unwrap_or(0);
                    for s in (0..4).map(|k| (first + k) % n32) {
                        if Some(s) == own_index {
                            continue;
                        }
                        self.adv.counter += 1;
                        let tmo = TimeoutVote {
                            epoch,
                            instance,
                            height,
                            view,
                            high_pqc: None,
                            signer: s,
                            sig: junk_sig(self.adv.counter),
                        };
                        self.byz_send_all(r, height, WireMessage::Timeout(Box::new(tmo)), now);
                    }
                }
                Strategy::RemovedCollusion if own_index.is_none() && height > 1 => {
                    // Old keys certify a fabricated block of a height they no longer own.
                    let Some(from_height) = (1..height)
                        .rev()
                        .find(|h| self.instances[inst].committee(*h).contains(&me))
                    else {
                        continue;
                    };
                    let old = self.instances[inst].committee(from_height).clone();
                    let colluders: Vec<SimSigner> = old
                        .members()
                        .iter()
                        .filter(|k| {
                            self.key_owner
                                .get(*k)
                                .is_some_and(|mm| self.machines[*mm].byz)
                        })
                        .map(|k| SimSigner::new(k.clone(), None, std::sync::Arc::clone(&self.log)))
                        .collect();
                    let bh = Hash32([0x99; 32]);
                    let result = Hash32([0x98; 32]);
                    let pre = preimage::vote_preimage(
                        VoteKind::Commit,
                        &instance,
                        &epoch,
                        height,
                        0,
                        &bh,
                        &result,
                    );
                    let indices: Vec<u32> = colluders
                        .iter()
                        .filter_map(|s| old.index_of(s.public_key()))
                        .collect();
                    let sigs: Vec<Signature> = colluders.iter().map(|s| s.sign(&pre)).collect();
                    let qc = Qc {
                        epoch,
                        kind: VoteKind::Commit,
                        instance,
                        height,
                        view: 0,
                        block_hash: bh,
                        result,
                        signers: Bitmap::from_indices(committee.n(), indices.iter().copied())
                            .unwrap_or_else(|| Bitmap::new(committee.n())),
                        agg_sig: aggregate(&sigs),
                    };
                    let status = Status {
                        instance,
                        height,
                        committed_qc: Some(qc.clone()),
                        ..Status::default()
                    };
                    let all: Vec<usize> = (0..self.replicas.len())
                        .filter(|x| self.replicas[*x].inst == inst && *x != r)
                        .collect();
                    let status = SharedWire::share(WireMessage::Status(Box::new(status)));
                    let bare = SharedWire::share(WireMessage::Qc(qc));
                    for x in all {
                        self.send_to_replica(r, x, Rc::clone(&status), now);
                        self.send_to_replica(r, x, Rc::clone(&bare), now);
                    }
                }
                Strategy::ReplayOldPqc => {
                    if let Some(q) = self.adv.old_pqcs.get(&(inst, height)).cloned() {
                        self.byz_send_all(r, height, WireMessage::Qc(q), now);
                    }
                }
                Strategy::Replay => {
                    for _ in 0..8 {
                        let Some((from_inst, msg)) = self.adv.replay.pop_front() else {
                            break;
                        };
                        for other in 0..self.instances.len() {
                            if other == from_inst {
                                continue;
                            }
                            let Some(target) = self.instances.get(other).and_then(|_| {
                                self.machines[m].replicas.get(other).copied().flatten()
                            }) else {
                                continue;
                            };
                            let id = self.instances[other].id;
                            let relabelled = SharedWire::share(relabel(&msg, id));
                            let raw = SharedWire::share(msg.clone());
                            // Deliver to every replica of the other instance (bypassing
                            // routing for the unchanged copy).
                            let targets: Vec<usize> = (0..self.replicas.len())
                                .filter(|x| self.replicas[*x].inst == other && *x != target)
                                .collect();
                            for x in targets {
                                self.send_to_replica(target, x, Rc::clone(&relabelled), now);
                                self.send_to_replica(target, x, Rc::clone(&raw), now);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        self.serve_forged(r);
    }

    /// `ForgeEchoes`: forged, replayed and own echoes to the prober `to`.
    fn forge_echoes(&mut self, r: usize, to: &PublicKey, nonce: u64) {
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        let me = self.net_key(r);
        let signer = self.byz_signer(r);
        let height = self.replicas[r].height;
        let now = self.now;
        let committee = self.instances[inst].committee(height).clone();
        let status = |height: u64, echo: crate::message::Echo| Status {
            instance,
            height,
            echo: Some(echo),
            ..Status::default()
        };
        let low = 1;
        let epoch = self.instances[inst].epoch(low).id;
        let mut out = Vec::new();
        // Forged: other members' keys under this node's signature.
        for key in committee.members().iter().filter(|k| **k != me && *k != to) {
            let sig = signer.sign(&preimage::echo_preimage(&instance, &epoch, nonce, low));
            out.push(status(
                low,
                crate::message::Echo {
                    epoch,
                    nonce,
                    key: key.clone(),
                    sig,
                },
            ));
        }
        // Replayed: a genuine echo of another nonce.
        let stale = nonce ^ 0x5a5a;
        let sig = signer.sign(&preimage::echo_preimage(&instance, &epoch, stale, low));
        out.push(status(
            low,
            crate::message::Echo {
                epoch,
                nonce: stale,
                key: me.clone(),
                sig,
            },
        ));
        // Its own valid echo, reporting a low height.
        let sig = signer.sign(&preimage::echo_preimage(&instance, &epoch, nonce, low));
        out.push(status(
            low,
            crate::message::Echo {
                epoch,
                nonce,
                key: me,
                sig,
            },
        ));
        for msg in out {
            self.net_send(
                r,
                to,
                SharedWire::share(WireMessage::Status(Box::new(msg))),
                now,
            );
        }
    }

    /// Answer queued body and sync requests with forged content.
    fn serve_forged(&mut self, r: usize) {
        let inst = self.replicas[r].inst;
        let instance = self.instances[inst].id;
        let now = self.now;
        let mine: Vec<(PublicKey, WireMessage)> = {
            let (mine, rest): (Vec<_>, Vec<_>) =
                self.adv.requests.drain(..).partition(|(x, _, _)| *x == r);
            self.adv.requests = rest.into();
            mine.into_iter().map(|(_, k, m)| (k, m)).collect()
        };
        for (from, request) in mine {
            match request {
                WireMessage::PayloadRequest(q) => {
                    let genuine =
                        self.replicas[r]
                            .bodies
                            .get(&q.block_hash)
                            .cloned()
                            .or_else(|| {
                                self.replicas[r]
                                    .store
                                    .iter()
                                    .find(|(_, c)| c.block_hash == q.block_hash)
                                    .map(|(b, _)| b.clone())
                            });
                    if let Some(block) = genuine {
                        let shape = self.instances[inst]
                            .epoch(block.header().height)
                            .da_layout
                            .shape(block.payload().as_slice().len() as u64)
                            .unwrap();
                        let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
                            shape,
                            block.payload().as_slice(),
                            &self.replicas[r].budget,
                        )
                        .unwrap();
                        let mut row = encoded.codeword()[shape.chunk_range(0).unwrap()].to_vec();
                        row[0] ^= 0xfe;
                        let manifest = WireMessage::PayloadManifest(PayloadManifest {
                            header: block.header().clone(),
                            availability: block.availability().clone(),
                        });
                        self.net_send(r, &from, SharedWire::share(manifest), now);
                        let chunk = WireMessage::PayloadChunk(PayloadChunk {
                            instance,
                            height: q.height,
                            block_hash: q.block_hash,
                            index: 0,
                            bytes: crate::availability::RowBytes::from_untrusted(row).unwrap(),
                        });
                        self.net_send(r, &from, SharedWire::share(chunk), now);
                    }
                }
                WireMessage::SyncRequest(q) => {
                    self.adv.counter += 1;
                    let mode = self.adv.counter % 4;
                    if mode == 3 {
                        continue; // withhold
                    }
                    let start = usize::try_from(q.from_height.saturating_sub(1)).unwrap_or(0);
                    let blocks: Vec<SyncEntry> = self.replicas[r]
                        .store
                        .iter()
                        .skip(start)
                        .take(usize::from(q.max_count).min(16))
                        .map(|(b, c)| {
                            let mut entry = SyncEntry {
                                manifest: PayloadManifest {
                                    header: b.header().clone(),
                                    availability: b.availability().clone(),
                                },
                                commit_qc: c.clone(),
                            };
                            match mode {
                                0 => {
                                    let mut bytes = entry.manifest.availability.as_slice().to_vec();
                                    *bytes.last_mut().unwrap() ^= 0xfd;
                                    entry.manifest.availability =
                                        crate::availability::AvailabilityFrame::from_untrusted(
                                            bytes,
                                        )
                                        .unwrap();
                                }
                                1 => entry.commit_qc.result = Hash32([0x31; 32]),
                                _ => entry.manifest.header.parent_result = Hash32([0x32; 32]),
                            }
                            entry
                        })
                        .collect();
                    if !blocks.is_empty() {
                        let msg = WireMessage::SyncResponse(SyncResponse { instance, blocks });
                        self.net_send(r, &from, SharedWire::share(msg), now);
                    }
                }
                _ => {}
            }
        }
    }

    /// The network adversary: may drop, delay or rewrite a packet (it sees all traffic).
    #[allow(clippy::too_many_lines)] // one arm per rule
    /// Returns the (possibly rewritten) message and an extra delay, or `None` to drop it.
    pub fn adv_net(
        &mut self,
        from: usize,
        to: usize,
        msg: Rc<SharedWire>,
        depart: Millis,
    ) -> Option<(Rc<SharedWire>, Millis)> {
        let from_m = self.replicas[from].machine;
        let to_m = self.replicas[to].machine;
        let inst = self.replicas[from].inst;
        // Split brain: the committer stays isolated until the others commit the height (or
        // the attack is given up after a few views), and at heal at the latest.
        if let Some((xm, i, h, v)) = self.adv.isolated {
            let from_byz = self.machines[from_m].byz;
            let done = i == inst
                && !from_byz
                && from_m != xm
                && match msg.message() {
                    WireMessage::Qc(q) => q.height == h && q.kind == VoteKind::Commit,
                    WireMessage::Status(s) => {
                        s.committed_qc.as_ref().is_some_and(|q| q.height >= h)
                    }
                    WireMessage::Proposal(p) => p.proposal.height > h,
                    WireMessage::Tc(tc) => tc.height == h && tc.view >= v + 4,
                    _ => false,
                };
            if done || (self.heal_at > 0 && self.now >= self.heal_at) {
                self.adv.isolated = None;
                self.trace(
                    from,
                    format!("split brain: h{h} settled, machine {xm} released"),
                );
            } else if from_m == xm || to_m == xm {
                return None;
            }
        }
        for rule in &self.adv.rules {
            if let NetRule::StallInstance {
                inst: i,
                from,
                until,
            } = *rule
                && usize::try_from(i).ok() == Some(inst)
                && (from..until).contains(&depart)
            {
                return None;
            }
        }
        // Echo relay (F24): the prober receives honest echoes only from the Byzantine relay.
        if let Some(relay) = self.adv.rules.iter().find_map(|rule| match rule {
            NetRule::RelayEchoes(m) => Some(*m),
            _ => None,
        }) && let WireMessage::Status(s) = msg.message()
            && s.echo.is_some()
            && !self.machines[from_m].byz
            && let Some(relay_r) = self.replica_of(relay, inst)
            && relay_r != to
        {
            let relay_key = self.net_key(relay_r);
            self.inject(to, relay_key, msg.message().clone(), 50);
            return None;
        }
        // Hidden PQC (F33): keep the holder's lock out of the next TC, make the next view fail,
        // then let the holder's timeout into the TC after it.
        if let Some((i, h, v, xm)) = self.adv.hidden
            && i == inst
        {
            let released = match msg.message() {
                WireMessage::Tc(tc) => tc.height == h && tc.view > v,
                WireMessage::Qc(q) => q.height == h && q.kind == VoteKind::Commit,
                WireMessage::Proposal(p) => {
                    p.proposal.height > h || (p.proposal.height == h && p.proposal.view > v + 1)
                }
                _ => false,
            };
            if released || depart >= self.heal_at {
                self.adv.hidden = None;
                self.trace(from, format!("hidden PQC of h{h} released"));
            } else {
                let to_byz = self.machines[to_m].byz;
                match msg.message() {
                    // The holder's round messages (votes, its lock-carrying timeouts) are slow.
                    _ if from_m == xm && !to_byz && msg.round_height() == Some(h) => {
                        return Some((msg, 2_500));
                    }
                    WireMessage::Timeout(t) if t.height == h && t.view == v + 1 => {
                        return Some((msg, 400));
                    }
                    WireMessage::Proposal(p)
                        if p.proposal.height == h && p.proposal.view == v + 1 =>
                    {
                        return Some((msg, 6_000));
                    }
                    WireMessage::Status(s) if from_m == xm && s.high_pqc.is_some() => {
                        let mut s2 = (**s).clone();
                        s2.high_pqc = None;
                        return Some((SharedWire::share(WireMessage::Status(Box::new(s2))), 0));
                    }
                    _ => {}
                }
            }
        }
        if depart >= self.heal_at {
            return Some((msg, 0));
        }
        let mut extra = 0;
        let mut msg = msg;
        for rule in self.adv.rules.clone() {
            match (rule, msg.message()) {
                (NetRule::DelayLockedTimeouts(ms), WireMessage::Timeout(t))
                    if t.high_pqc.is_some() =>
                {
                    extra += ms;
                }
                (
                    NetRule::TamperPayloads {
                        strip_ppm,
                        corrupt_ppm,
                    },
                    WireMessage::PayloadChunk(chunk),
                ) => {
                    if self.rng.chance(strip_ppm) {
                        return None;
                    }
                    if self.rng.chance(corrupt_ppm) {
                        let mut changed = chunk.clone();
                        let mut bytes = changed.bytes.as_slice().to_vec();
                        bytes[0] ^= 0xcc;
                        changed.bytes =
                            crate::availability::RowBytes::from_untrusted(bytes).unwrap();
                        msg = SharedWire::share(WireMessage::PayloadChunk(changed));
                    }
                }
                (NetRule::DropCommitVotes { from, until }, WireMessage::Vote(v))
                    if v.kind == VoteKind::Commit && (from..until).contains(&self.now) =>
                {
                    return None;
                }
                (NetRule::DropVotes { from, until }, WireMessage::Vote(_) | WireMessage::Qc(_))
                    if (from..until).contains(&self.now) =>
                {
                    return None;
                }
                (NetRule::DropVotes { from, until }, WireMessage::Status(s))
                    if (from..until).contains(&self.now) && s.high_pqc.is_some() =>
                {
                    let mut s2 = (**s).clone();
                    s2.high_pqc = None;
                    msg = SharedWire::share(WireMessage::Status(Box::new(s2)));
                }
                (NetRule::DropRowsTo(target), WireMessage::PayloadChunk(_)) if to_m == target => {
                    return None;
                }
                _ => {}
            }
        }
        Some((msg, extra))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{availability::RowBytes, message::PayloadChunk};

    /// Two malicious relays inject actual corrupt rows once each, even when their packets
    /// feed back through one another; a distinct original row still receives its own fault.
    #[test]
    fn forged_rows_do_not_recursively_amplify_between_adversaries() {
        let mut scenario = Scenario::base("bounded-forged-rows", 0, 7);
        scenario.byz = vec![
            (0, vec![Strategy::ForgeBodies]),
            (1, vec![Strategy::ForgeBodies]),
        ];
        let mut world = World::new(scenario);
        let source = world.net_key(2);
        let mut chunk = PayloadChunk {
            instance: world.instances[0].id,
            height: 1,
            block_hash: Hash32([7; 32]),
            index: 0,
            bytes: RowBytes::from_untrusted(vec![1, 2]).unwrap(),
        };
        let enqueued = |world: &World| {
            world.stats.packets.iter().sum::<u64>()
                + world
                    .replicas
                    .iter()
                    .map(|replica| replica.nic.len() as u64)
                    .sum::<u64>()
        };
        let initial = enqueued(&world);
        for relay in [0, 1] {
            world.byz_observe(
                relay,
                &source,
                &SharedWire::share(WireMessage::PayloadChunk(chunk.clone())),
            );
        }
        let injected = enqueued(&world);
        assert_eq!(
            injected - initial,
            12,
            "one six-peer injection by each relay"
        );
        chunk.bytes = RowBytes::from_untrusted(vec![1 ^ 0xee, 2]).unwrap();
        for _ in 0..4 {
            for relay in [0, 1] {
                world.byz_observe(
                    relay,
                    &source,
                    &SharedWire::share(WireMessage::PayloadChunk(chunk.clone())),
                );
            }
        }
        assert_eq!(
            enqueued(&world),
            injected,
            "feedback injects no additional packets"
        );
        chunk.index = 1;
        for relay in [0, 1] {
            world.byz_observe(
                relay,
                &source,
                &SharedWire::share(WireMessage::PayloadChunk(chunk.clone())),
            );
        }
        assert_eq!(
            enqueued(&world) - injected,
            12,
            "a distinct row is still corrupted"
        );
    }
}
