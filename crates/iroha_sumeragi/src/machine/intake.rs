//! The intake filter (§6.1), `Status` handling (§6.11), the probe echo (§7.4 R2) and the
//! proposal request (`request_proposal`, §6.11).

use super::{Core, Peer, PqcVia, Via};
use crate::{
    api::{Action, Event},
    message::{Echo, ProposalMessage, Status, VoteKind, WireMessage},
    preimage, safety,
    types::PublicKey,
};

impl Core {
    /// §6.1 for every network message.
    pub(super) fn on_message(&mut self, from: &PublicKey, msg: WireMessage) {
        // Rule 1, plus the structural limits in case the driver did not decode with them.
        if msg.instance() != &self.instance
            || msg.check_limits().is_err()
            || !msg.owned_bytes_admitted_to(&self.body_budget)
        {
            return;
        }
        match msg {
            WireMessage::ApplicationControl(message) => self.on_application_control(from, message),
            // Rule 2: service messages are never height-filtered.
            WireMessage::Status(status) => self.on_status(from, *status),
            WireMessage::SyncRequest(request) => self.serve_sync(from.clone(), &request),
            WireMessage::SyncResponse(response) => self.on_sync_response(from, response),
            WireMessage::PayloadRequest(request) => {
                self.on_block_request(from.clone(), request.height, request.block_hash);
            }
            WireMessage::PayloadManifest(manifest) => self.on_manifest(manifest),
            WireMessage::PayloadChunk(chunk) => {
                if self
                    .wants
                    .get(&chunk.block_hash)
                    .is_some_and(|want| want.height == chunk.height)
                {
                    self.out.push(Action::ReceivePayloadChunk {
                        from: from.clone(),
                        chunk,
                    });
                }
            }
            round => self.on_round_message(from, round),
        }
    }

    /// Rules 3–4 and dispatch of round messages at the current height.
    fn on_round_message(&mut self, from: &PublicKey, msg: WireMessage) {
        let Some(height) = msg.round_height() else {
            return;
        };
        if height <= self.tip.height {
            return self.on_committed_height(from, &msg);
        }
        if height == self.height && !self.awaiting {
            return self.on_current(from, msg);
        }
        if height == self.height.saturating_add(1) {
            return self.on_next_height(from, msg);
        }
        // Heights beyond h + 1: only certificates of committed heights are useful (sync hints).
        match msg {
            WireMessage::Qc(qc) => self.sync_hint(&qc, from),
            WireMessage::Proposal(p) => {
                if let Some(qc) = &p.proposal.parent_qc {
                    self.sync_hint(qc, from);
                }
            }
            _ => {}
        }
    }

    /// Rule 3: a committed height (the round state of `h` is frozen while awaiting).
    fn on_committed_height(&mut self, from: &PublicKey, msg: &WireMessage) {
        match msg {
            WireMessage::Vote(_) | WireMessage::Timeout(_) => {
                if self.cfg.committee.contains(from) {
                    self.reply_status(from);
                }
            }
            #[cfg(not(sumeragi_mutation = "MS37"))]
            WireMessage::Qc(qc) if qc.kind == VoteKind::Commit => self.monitor(qc),
            _ => {}
        }
    }

    /// Rule 4: the height after the current round's.
    fn on_next_height(&mut self, from: &PublicKey, msg: WireMessage) {
        match msg {
            WireMessage::Proposal(p) => self.on_next_proposal(from, *p),
            WireMessage::Qc(qc) if qc.kind == VoteKind::Commit => self.sync_hint(&qc, from),
            WireMessage::Vote(_)
            | WireMessage::Timeout(_)
            | WireMessage::Qc(_)
            | WireMessage::Tc(_) => {
                if self.cfg.committee.contains(from) {
                    self.reply_status(from);
                }
            }
            _ => {}
        }
    }

    /// §6.2 step 0: a proposal for `h + 1` whose `parent_qc` commits `h`.
    fn on_next_proposal(&mut self, from: &PublicKey, carrier: ProposalMessage) {
        let ProposalMessage {
            proposal: p,
            availability,
        } = carrier;
        if self.awaiting {
            // Its parent is committed but its configuration is unknown: it cannot be verified.
            // The node gets the proposal again through its proposal request after it enters.
            return;
        }
        let Some(qc) = p.parent_qc.clone().filter(|qc| qc.kind == VoteKind::Commit) else {
            return;
        };
        if qc.height != self.height {
            return;
        }
        self.commit_height(qc, Via::ParentQc);
        if !self.awaiting && self.height == p.height && self.halted.is_none() {
            self.on_proposal(from, p, availability);
        }
    }

    /// Dispatch of round messages at the current height.
    fn on_current(&mut self, from: &PublicKey, msg: WireMessage) {
        match msg {
            WireMessage::Proposal(p) => self.on_proposal(from, p.proposal, p.availability),
            WireMessage::Vote(vote) => self.on_vote(vote),
            WireMessage::Qc(qc) => self.on_qc(qc, PqcVia::Wire),
            WireMessage::Timeout(t) => self.on_timeout(*t),
            WireMessage::Tc(tc) => self.on_tc(*tc),
            _ => {}
        }
    }

    /// §6.11 on `Status` from the authenticated peer `from`, in four steps: probe echoes,
    /// probe requests and proposal requests have independent admission; everything else is
    /// processed for at most one `Status` per peer per `rebroadcast_interval / 2`.
    pub(super) fn on_status(&mut self, from: &PublicKey, s: Status) {
        // Step 1: echo (a signed answer to this node's probe; relayed copies count).
        if let Some(echo) = &s.echo {
            self.on_echo(echo, s.height);
        }
        // MS31d: any `Status` of a member of `C_{t'+2}` counts as a probe reply.
        #[cfg(sumeragi_mutation = "MS31d")]
        if s.echo.is_none()
            && self.any_unanchored()
            && !self.is_local_key(from)
            && (self.config(self.tip.height.saturating_add(2)))
                .is_some_and(|next| next.committee.contains(from))
        {
            let low = self.probe.get(from).copied().unwrap_or(u64::MAX);
            self.probe.insert(from.clone(), low.min(s.height));
            self.check_anchoring();
        }
        // Step 2: a late entrant's (or a member's whose copy was lost) proposal request.
        #[cfg(not(any(sumeragi_mutation = "ML19b", sumeragi_mutation = "ML19c")))]
        if s.want_proposal && s.height == self.height && s.view == self.view && !self.awaiting {
            self.repush_on_request(from, &s);
        }
        // A signing refusal consumes no successful-Echo rate limit. The unrelated Status
        // intake gate must not suppress a subsequent retry of that same probe.
        #[cfg(not(sumeragi_mutation = "MS61"))]
        if let Some(nonce) = s.probe {
            self.answer_probe(from, nonce);
        }
        // Step 3: the per-peer rate limit.
        let interval = self.local.rebroadcast_interval / 2;
        let now = self.now;
        let known = self.peers.get(from);
        let limited = known
            .and_then(|peer| peer.status_at)
            .is_some_and(|at| now < at.saturating_add(interval));
        // SPEC: §6.11 drops the rest of every `Status` within `rebroadcast_interval / 2` of the
        // previous one from the same peer. That drops exactly the §6.1 rule 3 reply that carries
        // the `CommitQC` a lagging voter lacks whenever the peer's periodic `Status` arrived just
        // before it (found by the simulator: F3 seed 12, a withholding proxy tail; gaps above
        // the P3 bound). A rate-limited `Status` is still used for its `committed_qc` alone if
        // that could commit the current height and is newer than anything seen from the peer:
        // at most two extra verifications per peer and height (heights above `h + 1` are
        // unverified hints), so the flood protection is kept (Appendix E, E1).
        let fresh_commit = s.committed_qc.as_ref().is_some_and(|qc| {
            qc.kind == VoteKind::Commit
                && qc.height >= self.height
                && known.is_none_or(|peer| qc.height > peer.committed)
        });
        if limited && (!fresh_commit || cfg!(sumeragi_mutation = "ME1")) {
            return;
        }
        let peer = self.peer_entry(from);
        if let Some(qc) = s.committed_qc.as_ref() {
            peer.committed = peer.committed.max(qc.height);
        }
        if limited {
            if let Some(qc) = s.committed_qc.filter(|qc| qc.kind == VoteKind::Commit) {
                if qc.height == self.height && !self.awaiting {
                    self.commit_height(qc, Via::Status);
                } else if qc.height > self.tip.height {
                    self.sync_hint(&qc, from);
                }
            }
            return;
        }
        // Step 4.
        peer.height = s.height;
        peer.view = s.view;
        peer.proposal_hash = s.proposal_hash;
        peer.status_at = Some(now);
        // MS61: a failed Echo attempt leaves its retry behind the unrelated Status gate.
        #[cfg(sumeragi_mutation = "MS61")]
        if let Some(nonce) = s.probe {
            self.answer_probe(from, nonce);
        }
        // ML19c: the proposal request is served only after the rate limit.
        #[cfg(sumeragi_mutation = "ML19c")]
        if s.want_proposal && s.height == self.height && s.view == self.view && !self.awaiting {
            self.repush_on_request(from, &s);
        }
        if let Some(qc) = s
            .committed_qc
            .as_ref()
            .filter(|qc| qc.kind == VoteKind::Commit)
        {
            if qc.height == self.height && !self.awaiting {
                self.commit_height(qc.clone(), Via::Status);
            } else if qc.height > self.tip.height {
                self.sync_hint(qc, from);
            } else {
                self.monitor(qc);
            }
            if self.halted.is_some() {
                return;
            }
        }
        if !self.awaiting && s.height == self.height {
            if let Some(tc) = s.high_tc {
                self.on_tc(tc);
            }
            if let Some(qc) = s.high_pqc.filter(|qc| qc.height == self.height) {
                self.on_qc(qc, PqcVia::Wire);
            }
        }
        if s.height < self.tip.height.saturating_add(1) {
            self.reply_status(from);
        }
        if let Some(bh) = s.proposal_hash
            && let Some(want) = self.wants.get_mut(&bh)
            && !want.sources.contains(from)
            && want.sources.len() < self.cfg.committee.n().saturating_add(8)
        {
            want.sources.push(from.clone());
        }
    }

    /// §6.11 step 1: a probe echo. Cheap filters first (the nonce of this `Init`, some key
    /// unanchored, `C_{tip.height+2}` known, a member key that is not this node's own, and a
    /// reply that would lower that key's probe entry), then the signature over
    /// `echo_preimage(nonce, height)` under the named key; then the anchoring check (R2).
    fn on_echo(&mut self, echo: &Echo, height: u64) {
        if echo.nonce != self.nonce || !self.any_unanchored() {
            return;
        }
        let Some(next) = self.config(self.tip.height.saturating_add(2)) else {
            return;
        };
        if !next.committee.contains(&echo.key)
            || self.is_local_key(&echo.key)
            || echo.epoch != next.epoch.id
            || !next.epoch.contains(height)
        {
            return;
        }
        if self.probe_epoch != Some(echo.epoch) {
            self.probe.clear();
            self.probe_epoch = Some(echo.epoch);
        }
        if self.probe.get(&echo.key).is_some_and(|low| *low <= height) {
            return;
        }
        let msg = preimage::echo_preimage(&self.instance, &echo.epoch, self.nonce, height);
        if !self.crypto.verify(&echo.key, &msg, &echo.sig) && !cfg!(sumeragi_mutation = "MS31e") {
            return;
        }
        self.probe.insert(echo.key.clone(), height);
        self.check_anchoring();
    }

    /// R2 (§7.4): once `2f + 1` member keys of `C_{t'+2}` (other than this node's) reported
    /// heights `≤ t' + 1` in fresh echoes, every unanchored key abstains at heights `≤ t' + 2`
    /// and signs normally from `t' + 3` (`t' = tip.height`).
    pub(super) fn check_anchoring(&mut self) {
        if !self.any_unanchored() {
            return;
        }
        let t = self.tip.height;
        let Some(next) = self.config(t.saturating_add(2)) else {
            return;
        };
        if self.probe_epoch != Some(next.epoch.id) {
            return;
        }
        let keys: Vec<PublicKey> = self.keys.iter().map(|k| k.pk.clone()).collect();
        if !safety::anchored(&next.committee, |k| keys.contains(k), &self.probe, t) {
            return;
        }
        let abstain_below = t.saturating_add(3);
        for key in &mut self.keys {
            if key.unanchored {
                key.unanchored = false;
                key.abstain_below = key.abstain_below.max(abstain_below);
            }
        }
        self.probe.clear();
    }

    /// §6.11: answer a probe with a signed echo, at most once per peer per
    /// `rebroadcast_interval`, only with a configured key and while none of this node's keys
    /// (retired ones included) is unanchored or abstaining at the current height.
    fn answer_probe(&mut self, to: &PublicKey, nonce: u64) {
        // The current round height (also while awaiting: the next round's).
        let h = self.tip.height.saturating_add(1);
        let Some(epoch) = self.config(h).map(|config| *config.epoch) else {
            return;
        };
        if !epoch.contains(h) {
            return;
        }
        let blocked = self
            .keys
            .iter()
            .any(|k| k.unanchored || h < k.abstain_below)
            && !cfg!(sumeragi_mutation = "MS31c");
        if blocked {
            return;
        }
        let slot = self
            .me
            .map(|me| me.slot)
            .filter(|slot| self.keys.get(*slot).is_some_and(|k| k.signer.is_some()))
            .or_else(|| self.keys.iter().position(|k| k.signer.is_some()));
        let Some(slot) = slot else {
            return;
        };
        let now = self.now;
        let interval = self.local.rebroadcast_interval;
        let peer = self.peer_entry(to);
        if peer
            .echoed_at
            .is_some_and(|at| now < at.saturating_add(interval))
        {
            return;
        }
        let mut status = self.status_message();
        let msg = preimage::echo_preimage(&self.instance, &epoch.id, nonce, status.height);
        let key = self.keys[slot].pk.clone();
        let Some(sig) = self.sign(
            slot,
            crate::api::SigningKind::Echo,
            status.height,
            self.view,
            &msg,
        ) else {
            return;
        };
        self.peer_entry(to).echoed_at = Some(now);
        status.echo = Some(Echo {
            epoch: epoch.id,
            nonce,
            key,
            sig,
        });
        self.send(to.clone(), WireMessage::Status(Box::new(status)));
    }

    /// §6.11 step 2, the late-entrant re-push: the leader of `(h, view)` holding its proposal
    /// re-sends its manifest and rows to a recipient asking for it, at most once per
    /// recipient per view (independently of the interval-gated rebroadcast re-push).
    fn repush_on_request(&mut self, from: &PublicKey, s: &Status) {
        let (Some(me), Some(p)) = (self.my_index(), self.mine.proposal.clone()) else {
            return;
        };
        if self.rnd.leader() != me || p.view != self.view || self.request_pushed.contains(from) {
            return;
        }
        let Some(held) = self.proposal.as_ref() else {
            return;
        };
        let bh = held.bh;
        if s.proposal_hash == Some(bh)
            || (!self.recipients(true).contains(from)
                && !cfg!(sumeragi_mutation = "MR-repush-recipients"))
        {
            return;
        }
        let Some(body) = self.blocks.get(&bh).cloned() else {
            return;
        };
        let full = ProposalMessage {
            proposal: p,
            availability: body.availability().clone(),
        };
        self.request_pushed.insert(from.clone());
        self.send(from.clone(), WireMessage::Proposal(Box::new(full)));
        self.out.push(Action::DisseminatePayload {
            peers: vec![from.clone()],
            body,
        });
    }

    /// `request_proposal` (§6.11, at the end of every `handle` call and of `Core::new`): a node
    /// in round `(h, view)` that is not its leader, holds no proposal of it and has not asked in
    /// this round asks `L(h, view)` once if it entered late or holds evidence that the proposal
    /// exists.
    pub(super) fn request_proposal(&mut self) {
        if self.asked || !self.wants_proposal() {
            return;
        }
        let Some(to) = self.member_key(self.rnd.leader()) else {
            return;
        };
        #[cfg(not(sumeragi_mutation = "MR-request-asked"))]
        {
            self.asked = true;
        }
        let status = self.status_message();
        self.send(to, WireMessage::Status(Box::new(status)));
    }

    /// The condition of `request_proposal` and of `Status.want_proposal` (§6.11): not awaiting,
    /// `L(h, view) ≠ me`, no proposal of `(h, view)` held, and a late entry or evidence that the
    /// proposal exists (a verified vote of view `view` in the pools, a `PrepareQC` of
    /// `(h, view)`, or a peer's latest `Status` reporting a proposal hash for `(h, view)`).
    fn wants_proposal(&self) -> bool {
        if self.awaiting || self.halted.is_some() || self.proposal.is_some() {
            return false;
        }
        if self.my_index() == Some(self.rnd.leader()) {
            return false;
        }
        (self.late_entry && !cfg!(sumeragi_mutation = "ML19a"))
            || (self.proposal_evidence() && !cfg!(sumeragi_mutation = "ML24"))
    }

    fn proposal_evidence(&self) -> bool {
        self.votes.any_in_view(self.view)
            || self.has_pqc_of_view()
            || self.peers.values().any(|peer| {
                peer.height == self.height && peer.view == self.view && peer.proposal_hash.is_some()
            })
    }

    /// Send our `Status` to `to`, at most once per peer per `rebroadcast_interval` (§6.1).
    pub(super) fn reply_status(&mut self, to: &PublicKey) {
        let now = self.now;
        let interval = self.local.rebroadcast_interval;
        let peer = self.peer_entry(to);
        if peer
            .replied_at
            .is_some_and(|at| now < at.saturating_add(interval))
        {
            return;
        }
        peer.replied_at = Some(now);
        let status = self.status_message();
        self.send(to.clone(), WireMessage::Status(Box::new(status)));
    }

    /// The peer-table entry of `key`, inserting it (bounded LRU of `n + max_observers`,
    /// evicting non-members first).
    fn peer_entry(&mut self, key: &PublicKey) -> &mut Peer {
        let limit = self
            .cfg
            .committee
            .n()
            .saturating_add(usize::try_from(self.local.max_observers).unwrap_or(usize::MAX));
        if !self.peers.contains_key(key) && self.peers.len() >= limit {
            let committee = &self.cfg.committee;
            let victim = self
                .peers
                .iter()
                .min_by_key(|(k, peer)| (committee.contains(k), peer.seen))
                .map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                self.peers.remove(&victim);
            }
        }
        let now = self.now;
        let peer = self.peers.entry(key.clone()).or_default();
        peer.seen = now;
        peer
    }

    /// This node's `Status` (§3.5). While awaiting it reports `tip.height + 1`, view 0, the
    /// newest `CommitQC` and nothing else. While a key is unanchored every `Status` carries the
    /// probe nonce (§6.11).
    pub(super) fn status_message(&self) -> Status {
        let current = !self.awaiting;
        Status {
            instance: self.instance,
            height: self.tip.height.saturating_add(1),
            view: if current { self.view } else { 0 },
            committed_qc: self.tip.commit_qc.clone(),
            high_pqc: self.high_pqc.clone().filter(|_| current),
            high_tc: self.high_tc.clone().filter(|_| current),
            proposal_hash: self
                .proposal
                .as_ref()
                .map(|held| held.bh)
                .filter(|_| current),
            want_proposal: self.wants_proposal(),
            probe: (self.any_unanchored() && !cfg!(sumeragi_mutation = "MR-probe-status"))
                .then_some(self.nonce),
            echo: None,
        }
    }

    /// Events accepted while halted: only serving continues (§12.5).
    pub(super) fn serve_only(&mut self, event: Event) {
        if let Event::Message { from, msg } = event
            && msg.instance() == &self.instance
        {
            match msg {
                WireMessage::SyncRequest(request) => self.serve_sync(from, &request),
                WireMessage::PayloadRequest(request) => {
                    self.on_block_request(from, request.height, request.block_hash);
                }
                _ => {}
            }
        }
    }
}
