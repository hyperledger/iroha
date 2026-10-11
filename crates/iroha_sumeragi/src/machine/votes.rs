//! Vote pools and aggregation (§6.4), `PrepareQC`s and the Commit vote (§6.5), routing and the
//! stage ladder (§5.2).

use std::collections::BTreeMap;

use super::{Core, EvKey, PqcVia, Retx, Via};
use crate::{
    crypto::form_qc,
    message::{Evidence, Qc, Vote, VoteKind, WireMessage},
    pacemaker::retransmit_spacing,
    types::{Hash32, ValidatorIndex, usize_of},
};

/// Vote pools: per `(view, kind)` at most one verified vote per signer (§6.4). Only votes
/// whose signature was verified, or the node's own, are ever inserted (SR38).
#[derive(Clone, Debug, Default)]
pub(super) struct Pools {
    n: usize,
    slots: BTreeMap<(u64, VoteKind), Vec<Option<Vote>>>,
}

impl Pools {
    pub(super) fn new(n: usize) -> Self {
        Self {
            n,
            slots: BTreeMap::new(),
        }
    }

    pub(super) fn get(&self, kind: VoteKind, view: u64, signer: ValidatorIndex) -> Option<&Vote> {
        self.slots
            .get(&(view, kind))
            .and_then(|slots| slots.get(usize_of(signer)))
            .and_then(Option::as_ref)
    }

    /// Insert into an empty slot (callers checked it); out-of-range signers are ignored.
    pub(super) fn insert(&mut self, vote: Vote) {
        let n = self.n;
        let slots = self
            .slots
            .entry((vote.view, vote.kind))
            .or_insert_with(|| vec![None; n]);
        if let Some(slot) = slots.get_mut(usize_of(vote.signer)) {
            *slot = Some(vote);
        }
    }

    /// Votes of `(kind, view)` for the signed value `(bh, R)` of `x`, in signer order.
    fn matching(&self, x: &Vote) -> Vec<&Vote> {
        self.slots
            .get(&(x.view, x.kind))
            .map(|slots| {
                slots
                    .iter()
                    .flatten()
                    .filter(|vote| same_value(vote, x))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Distinct signers with a vote of either kind at `view`, other than `except`.
    fn signers_in_view(&self, view: u64, except: Option<ValidatorIndex>) -> usize {
        let mut seen = vec![false; self.n];
        for kind in [VoteKind::Prepare, VoteKind::Commit] {
            for vote in self
                .slots
                .get(&(view, kind))
                .into_iter()
                .flatten()
                .flatten()
            {
                if Some(vote.signer) != except
                    && let Some(flag) = seen.get_mut(usize_of(vote.signer))
                {
                    *flag = true;
                }
            }
        }
        seen.into_iter().filter(|flag| *flag).count()
    }

    /// Whether any verified vote of `view` is pooled (evidence that a proposal exists, §6.11).
    pub(super) fn any_in_view(&self, view: u64) -> bool {
        [VoteKind::Prepare, VoteKind::Commit].iter().any(|kind| {
            self.slots
                .get(&(view, *kind))
                .is_some_and(|slots| slots.iter().any(Option::is_some))
        })
    }

    /// Keep only views in `lo..=hi`.
    pub(super) fn retain_views(&mut self, lo: u64, hi: u64) {
        self.slots.retain(|(view, _), _| (lo..=hi).contains(view));
    }

    /// Number of pooled votes.
    pub(super) fn len(&self) -> usize {
        self.slots.values().flatten().flatten().count()
    }
}

/// Whether two votes sign the same value `(bh, R)` (§3.4 formation).
fn same_value(a: &Vote, b: &Vote) -> bool {
    a.value() == b.value()
}

impl Core {
    /// §6.4 steps 1–3 for a vote from the wire at the current height.
    pub(super) fn on_vote(&mut self, x: Vote) {
        let view = self.view;
        let in_window = x.view <= view.saturating_add(1) && x.view.saturating_add(1) >= view;
        if x.height != self.height || !in_window || usize_of(x.signer) >= self.n() {
            return;
        }
        // Step 2: the proxy tail answers a voter that evidently lacks the phase's QC.
        #[cfg(not(sumeragi_mutation = "ML5b"))]
        if x.kind == VoteKind::Prepare
            && self.my_index() == Some(self.proxy_tail_of(x.view))
            && Some(x.signer) != self.my_index()
            && let Some(qc) = self.high_pqc.clone().filter(|qc| qc.view == x.view)
            && self.answered.insert((x.view, x.signer))
            && let Some(to) = self.member_key(x.signer)
        {
            self.send(to, WireMessage::Qc(qc));
        }
        // Step 3: cheap reject, signature verification, equivocation.
        let held = self.votes.get(x.kind, x.view, x.signer).copied();
        if held.as_ref().is_some_and(|old| same_value(old, &x)) {
            return;
        }
        #[cfg(not(sumeragi_mutation = "MS38"))]
        if self.verifier(&self.cfg).verify_vote(&x).is_err() {
            return;
        }
        // Two signed values in one slot are equivocation.
        if let Some(old) = held {
            self.report(
                EvKey::Vote(x.kind, x.view, x.signer),
                Evidence::VoteEquivocation(old, x),
            );
            return;
        }
        self.pool_insert(&x);
    }

    /// `pool_insert` (§6.4 step 4): insert a verified (or own) vote, contagion, formation. The
    /// node's own votes enter here exactly once, right after they are signed (§6.0).
    pub(super) fn pool_insert(&mut self, x: &Vote) {
        if self.votes.get(x.kind, x.view, x.signer).is_some() {
            return;
        }
        self.votes.insert(*x);
        let h0 = self.height;
        let f = self.cfg.committee.f();
        if x.view == self.view
            && self.stage < 2
            && self.my_index() != Some(self.rnd.proxy_tail())
            && self.votes.signers_in_view(self.view, self.my_index()) > f
            && !cfg!(sumeragi_mutation = "ML4")
        {
            // Contagion (§5.2 stage 2c): f + 1 signers include an honest one that voted.
            self.raise_stage(2);
            if !self.same_height(h0) {
                return;
            }
        }
        let votes = self.votes.matching(x);
        if votes.len() != self.cfg.committee.q() {
            return;
        }
        let Ok(qc) = form_qc(&*self.crypto, self.n(), &votes) else {
            return;
        };
        self.cache_cert_qc(&qc);
        match qc.kind {
            VoteKind::Prepare => self.on_qc(qc, PqcVia::Formed),
            VoteKind::Commit => self.commit_height(qc, Via::Formed),
        }
    }

    /// `on_qc` (§6.5) for a certificate of the current height. A `CommitQC` goes to
    /// `commit_height` (§6.8). A `PrepareQC` from the wire is cheap-rejected unless it raises the
    /// lock (§6.1 rule 5, top-level objects only) and then verified; one carried by a timeout
    /// or a TC was verified with its container, and one formed locally is trusted.
    pub(super) fn on_qc(&mut self, c: Qc, via: PqcVia) {
        if c.kind == VoteKind::Commit {
            let via = if via == PqcVia::Formed {
                Via::Formed
            } else {
                Via::Qc
            };
            return self.commit_height(c, via);
        }
        if self.awaiting || c.height != self.height {
            return;
        }
        if via == PqcVia::Wire {
            // A lower or equal view (equal = same value by the uniqueness lemma).
            if self.high_pqc.as_ref().is_some_and(|q| q.view >= c.view) {
                return;
            }
            if !self.verify_qc_cached(&c) {
                return;
            }
        }
        let (view, bh) = (c.view, c.block_hash);
        let sources = self.signer_keys(&c);
        let set_b_signed = view >= self.view && {
            let round = self.topo.round(view);
            c.signers.ones().any(|m| round.in_set_b(m))
        };
        let announce = (via == PqcVia::Formed && self.my_index() == Some(self.proxy_tail_of(view)))
            .then(|| c.clone());
        // (a) Lock first, so that a view change keeps this block's execution (B3). The lock
        // never decreases within a height (S5).
        if self.high_pqc.as_ref().is_none_or(|q| view > q.view) || cfg!(sumeragi_mutation = "MS7") {
            self.high_pqc = Some(c.clone());
            self.prune_bodies();
        }
        let is_lock = self.high_pqc.as_ref() == Some(&c);
        // (b) Round synchronisation (not for a TC's high_pqc: the TC moves past `view` at once).
        if via != PqcVia::Tc && view > self.view {
            self.advance_to(view, false);
        }
        // (c) Fetch the locked block's body.
        if is_lock && !self.blocks.contains_key(&bh) {
            self.want(bh, self.height, sources);
        }
        #[cfg(not(sumeragi_mutation = "MR-tc-locks-only"))]
        if via == PqcVia::Tc {
            return;
        }
        // (d) The proxy tail broadcasts the QCs it forms.
        if let Some(qc) = announce {
            let to = self.recipients_of(view, false);
            self.broadcast(to, WireMessage::Qc(qc));
        }
        // (e) Stage raise and Commit vote in the current view.
        if view == self.view {
            if self.t_pqc.is_none() {
                self.t_pqc = Some(self.now);
            }
            if let Some(retx) = self.retx[0].take() {
                self.pm
                    .record_qc_latency(self.now.saturating_sub(retx.sent));
            }
            let h0 = self.height;
            if set_b_signed {
                self.raise_stage(1);
                if !self.same_height(h0) {
                    return;
                }
            }
            self.try_commit();
        }
    }

    /// `try_commit()` (§6.5, S3): Commit on the `PrepareQC` of the current view only, once per
    /// view (`mine.commit`). The lock written by `persist()` is the record of the Commit (SR25).
    pub(super) fn try_commit(&mut self) {
        let Some(me) = self.signer() else {
            return;
        };
        let view = self.view;
        #[cfg(not(sumeragi_mutation = "MS4"))]
        if self.timeout_view.is_some_and(|t| t >= view) {
            return;
        }
        if self.mine.commit.is_some() || self.safety.is_none() {
            return;
        }
        let Some((bh, result)) = self
            .high_pqc
            .as_ref()
            .filter(|q| q.view == view || cfg!(sumeragi_mutation = "MS5"))
            .map(|q| (q.block_hash, q.result))
        else {
            return;
        };
        if !self.rnd.in_set_a(me.index) && (self.stage < 1 || cfg!(sumeragi_mutation = "ML3")) {
            return;
        }
        self.persist();
        self.cast_vote(me, VoteKind::Commit, (bh, result));
    }

    /// Sign, route and pool an own vote for the signed value `(bh, R)` (after its
    /// `persist()`); pooling is last because it may form a certificate and commit.
    pub(super) fn cast_vote(
        &mut self,
        me: super::Me,
        kind: VoteKind,
        (bh, result): (Hash32, Hash32),
    ) {
        if let Some(vote) = self.record_vote(me, kind, (bh, result)) {
            self.route(&vote);
            self.pool_insert(&vote);
        }
    }

    /// Sign and record an own vote, including its retransmit deadline. Restart uses the same
    /// path with the durable Prepare value, without routing or pooling it before restoration.
    pub(super) fn record_vote(
        &mut self,
        me: super::Me,
        kind: VoteKind,
        (bh, result): (Hash32, Hash32),
    ) -> Option<Vote> {
        let mut vote = Vote {
            kind,
            instance: self.instance,
            epoch: self.cfg.epoch.id,
            height: self.height,
            view: self.view,
            block_hash: bh,
            result,
            signer: me.index,
            sig: crate::types::Signature([0; crate::types::SIGNATURE_LEN]),
        };
        // Only the fully signed object enters custody below; failure retains no vote.
        vote.sig = self.sign(me, &vote.preimage())?;
        match kind {
            VoteKind::Prepare => self.mine.prepare = Some(vote),
            VoteKind::Commit => self.mine.commit = Some(vote),
        }
        self.t_lastvote = Some(self.now);
        let t_retx = self.pm.t_retx(self.view);
        self.retx[usize::from(kind == VoteKind::Commit)] = Some(Retx {
            next: self.now.saturating_add(retransmit_spacing(
                1,
                t_retx,
                self.local.rebroadcast_interval,
            )),
            k: 1,
            sent: self.now,
        });
        Some(vote)
    }

    /// `route(vote)` (§5.2): to `P` at stages 0–1 (local if `P` is this node), broadcast to
    /// `C_h` at stage 2.
    pub(super) fn route(&mut self, vote: &Vote) {
        if self.stage >= 2 {
            let to = self.members_except_me();
            self.broadcast(to, WireMessage::Vote(*vote));
            return;
        }
        let tail = self.rnd.proxy_tail();
        if Some(tail) != self.my_index()
            && let Some(to) = self.member_key(tail)
        {
            self.send(to, WireMessage::Vote(*vote));
        }
    }

    /// Raise the routing stage (§5.2): re-send once, with the new routing, each own vote of
    /// the round whose phase QC is not held and restart its retransmit schedule from this send
    /// (§6.11 `t_vote`); then `try_prepare()` and `try_commit()`.
    pub(super) fn raise_stage(&mut self, stage: u8) {
        if stage <= self.stage || self.awaiting {
            return;
        }
        self.stage = stage;
        let unanswered = [
            self.mine.prepare.filter(|_| !self.has_pqc_of_view()),
            self.mine.commit,
        ];
        let t_retx = self.pm.t_retx(self.view);
        let spacing = retransmit_spacing(1, t_retx, self.local.rebroadcast_interval);
        for (slot, vote) in unanswered.into_iter().enumerate() {
            let Some(vote) = vote else {
                continue;
            };
            self.route(&vote);
            #[cfg(not(sumeragi_mutation = "MR-stage-resend"))]
            if let Some(retx) = self.retx.get_mut(slot).and_then(Option::as_mut) {
                retx.next = self.now.saturating_add(spacing);
                retx.k = 1;
            }
        }
        let h0 = self.height;
        self.try_prepare();
        if self.same_height(h0) {
            self.try_commit();
        }
    }
}
