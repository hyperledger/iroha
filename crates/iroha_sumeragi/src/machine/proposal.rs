//! Proposals (§6.2), execution requests and results (§6.3, §4.2) and the Prepare vote (§4.3).

use super::{Core, EvKey, ExecState, Held};
use crate::{
    api::{Action, ExecOutcome, LocalFault},
    availability::{AvailabilityFrame, AvailabilitySource, AvailableBody},
    message::{Defect, Evidence, PayloadManifest, Proposal, VoteKind},
    pacemaker::exec_retry_delay,
    safety::RecordedVote,
    types::{Hash32, PublicKey},
};

/// §13.4 MS10a/MS10b: a TC-justified proposal is checked and executed like a fresh block (the
/// TC-rule branch of §6.2 step 6 and the binding of `Q.result` are gone). `false` unless mutated.
const NO_TC_RULE: bool = cfg!(any(
    sumeragi_mutation = "MS10a",
    sumeragi_mutation = "MS10b"
));

impl Core {
    /// §6.2 for a proposal of the current height (not awaiting).
    pub(super) fn on_proposal(
        &mut self,
        from: &PublicKey,
        p: Proposal,
        availability: AvailabilityFrame,
    ) {
        let w = p.view;
        let bh = p.block_hash(&*self.crypto);
        let ad = p.att_digest(&*self.crypto);
        // Step 1 (after the byte-identical cheap reject): the signature of L(h, w).
        let exact = self.proposal.as_ref().is_some_and(|held| {
            held.p.view == w && held.bh == bh && held.ad == ad && held.p.sig == p.sig
        });
        if !exact {
            let leader = self.topo.leader(w);
            #[cfg(not(sumeragi_mutation = "MS18"))]
            let signed = self
                .verifier(&self.cfg)
                .verify_proposal_signature(leader, &p)
                .is_ok();
            #[cfg(sumeragi_mutation = "MS18")]
            let signed = {
                let msg = crate::preimage::prop_preimage(
                    &self.instance,
                    &self.cfg.epoch.id,
                    self.height,
                    w,
                    &bh,
                    &ad,
                );
                p.instance == self.instance
                    && self.cfg.committee.get(leader).is_some()
                    && (self.cfg.committee.members().iter())
                        .any(|key| self.crypto.verify(key, &msg, &p.sig))
            };
            if !signed {
                return;
            }
        }
        // Step 2: duplicates and equivocation.
        if self.check_held(&p, bh, ad) {
            if exact {
                self.on_manifest(PayloadManifest {
                    header: p.header,
                    availability,
                });
            }
            return;
        }
        // Step 3: justify (runs the TC handler, which may advance the view to w).
        let h0 = self.height;
        if let Some(defect) = self.check_justify(&p) {
            return self.signed_defect(p, defect);
        }
        if !self.same_height(h0) {
            return;
        }
        if self.check_held(&p, bh, ad) {
            if self
                .proposal
                .as_ref()
                .is_some_and(|held| held.bh == bh && held.ad == ad)
            {
                self.on_manifest(PayloadManifest {
                    header: p.header,
                    availability,
                });
            }
            return;
        }
        // Step 4: view.
        if w < self.view {
            if self.wants.contains_key(&bh) {
                self.on_manifest(PayloadManifest {
                    header: p.header.clone(),
                    availability,
                });
            }
            return;
        }
        if w > self.view {
            return;
        }
        // Steps 5–6: parent and header (signed content).
        if let Some(defect) = self.check_parent(&p).or_else(|| self.check_header(&p, bh)) {
            return self.signed_defect(p, defect);
        }
        let manifest = PayloadManifest {
            header: p.header.clone(),
            availability,
        };
        self.accept_proposal(Some(from), p, bh, ad);
        self.on_manifest(manifest);
    }

    /// Step 2: `true` if a proposal for `(h, p.view)` is already held (the duplicate may supply
    /// the missing body; a different one is equivocation evidence, and in the current view an
    /// early timeout: both proposals carry a valid signature of `L(h, p.view)`, so the leader is
    /// proven faulty and cannot be framed).
    fn check_held(&mut self, p: &Proposal, bh: Hash32, ad: Hash32) -> bool {
        let Some(held) = self.proposal.as_ref().filter(|held| held.p.view == p.view) else {
            return false;
        };
        if held.bh == bh && held.ad == ad {
            return true;
        }
        let first = Box::new(held.p.clone());
        let second = Box::new(p.clone());
        self.report(
            EvKey::Proposal(p.view),
            Evidence::ProposalEquivocation(first, second),
        );
        if p.view == self.view && !cfg!(sumeragi_mutation = "ML26") {
            self.sign_timeout(self.view);
        }
        true
    }

    /// Step 3. Returns the defect, or runs the TC handler on a valid justification.
    fn check_justify(&mut self, p: &Proposal) -> Option<Defect> {
        let defect = p.justify_defect(self.height, |tc| {
            tc.instance == self.instance && self.verify_tc_cached(tc)
        });
        if defect.is_none()
            && let Some(tc) = &p.justify
        {
            self.on_verified_tc(tc.clone(), true);
        }
        defect
    }

    /// Step 5: `parent_qc` is absent exactly at the genesis parent.
    fn check_parent(&mut self, p: &Proposal) -> Option<Defect> {
        if cfg!(sumeragi_mutation = "MS19") {
            return None;
        }
        p.parent_defect(
            self.height == self.genesis.saturating_add(1),
            self.height.saturating_sub(1),
            (self.tip.block_hash, self.tip.result),
            |qc| self.tip.commit_qc.as_ref() == Some(qc) || self.verify_qc_cached(qc),
        )
    }

    /// Step 6: the same signed-content rules used by independent evidence attribution.
    fn check_header(&self, p: &Proposal, bh: Hash32) -> Option<Defect> {
        p.header_defect(
            self.instance,
            self.height,
            (self.tip.block_hash, self.tip.result),
            &self.cfg,
            &self.topo,
            bh,
            |defect| match defect {
                Defect::ParentHash | Defect::ParentResult => !cfg!(sumeragi_mutation = "MS19"),
                Defect::EmptyPayload => !cfg!(sumeragi_mutation = "MS53"),
                Defect::TcRule => !NO_TC_RULE,
                _ => true,
            },
        )
    }

    /// Step 7: evidence for a signed defect (payload stripped) and an early timeout if it is the
    /// current view's proposal (SR35).
    fn signed_defect(&mut self, p: Proposal, defect: Defect) {
        let w = p.view;
        self.report(
            EvKey::Invalid(w),
            Evidence::InvalidProposal {
                proposal: Box::new(p),
                defect,
            },
        );
        if w == self.view {
            self.sign_timeout(w);
        }
    }

    /// Accepted remote or locally recorded proposal: install the same held state, acquire
    /// its body if needed, then execute. `from` adds only the optional transport relay to
    /// body sources; it grants no signature, header, eligibility or storage exemption.
    pub(super) fn accept_proposal(
        &mut self,
        from: Option<&PublicKey>,
        p: Proposal,
        bh: Hash32,
        ad: Hash32,
    ) {
        let q = p
            .justify
            .as_ref()
            .and_then(|tc| tc.high_pqc.as_ref())
            .filter(|_| p.view > 0 && !NO_TC_RULE);
        let expected = q.map(|q| q.result);
        let sources = (!self.blocks.contains_key(&bh)).then(|| {
            // SPEC: besides §6.2 step 8's sources, ask the transport relay (Appendix E, E27).
            // A local proposal already holds its body; no relay authority is invented.
            let mut sources: Vec<PublicKey> = self
                .member_key(self.topo.leader(p.view))
                .into_iter()
                .collect();
            sources.extend(from.cloned());
            if let Some(q) = q {
                sources.extend(self.signer_keys(q));
            }
            sources
        });
        self.proposal = Some(Held {
            p,
            bh,
            ad,
            expected,
        });
        self.t_prop = Some(self.now);
        if let Some(sources) = sources {
            self.want(bh, self.height, sources);
        }
        self.maybe_execute();
    }

    /// Store a body in memory (`StoreBody` unless it came from the local stores). A held body
    /// is never replaced. Callers checked `body_ok` (SR20).
    pub(super) fn put_body(&mut self, bh: Hash32, block: AvailableBody) {
        if self.blocks.contains_key(&bh) {
            return;
        }
        #[cfg(not(sumeragi_mutation = "ML10"))]
        self.out.push(Action::StoreBody {
            block: block.clone(),
        });
        self.wants.remove(&bh);
        self.blocks.insert(bh, block);
    }

    /// Step 9: execute the current proposal's block once its body and parent state are there.
    pub(super) fn maybe_execute(&mut self) {
        let Some(bh) = self.proposal.as_ref().map(|held| held.bh) else {
            return;
        };
        if !self.blocks.contains_key(&bh) {
            return;
        }
        // §9.2: the committing view's duration is measured from here, when this node first
        // holds the round's proposal together with its body (a leader cannot stretch it by
        // sending either late).
        if self.t_body.is_none() {
            self.t_body = Some(self.now);
        }
        let parent_ready = self.applied.saturating_add(1) >= self.height || self.tip.exec_ok;
        if !parent_ready {
            return;
        }
        match self.exec.get(&bh) {
            None => self.request_exec(bh, 0),
            Some(ExecState::Valid(_) | ExecState::Invalid) => self.on_outcome(bh),
            Some(ExecState::Pending { .. } | ExecState::RetryAt { .. }) => {}
        }
    }

    /// `request_exec(bh)` (§6.2): a fresh request id per request, never reused. The
    /// `certified` flag is evaluated at every emission, so a due `RetryAt` re-evaluates it
    /// (§4.5 "Certified re-proposals").
    pub(super) fn request_exec(&mut self, bh: Hash32, attempt: u32) {
        let Some(block) = self.blocks.get(&bh).cloned() else {
            self.exec.remove(&bh);
            return;
        };
        let req = self.next_req;
        self.next_req = self.next_req.saturating_add(1);
        self.exec.insert(
            bh,
            ExecState::Pending {
                since: self.now,
                req,
                attempt,
            },
        );
        // MS51: the machine always emits `certified = false`.
        let certified = !self.certified_results(bh).is_empty() && !cfg!(sumeragi_mutation = "MS51");
        self.out.push(Action::Execute {
            block,
            req,
            certified,
        });
    }

    /// `discard_exec(keep)` (§6.2): the only source of `DiscardExecution`. Every `Pending`
    /// execution it removes first counts for the start level with its elapsed time, a lower
    /// bound of an execution that outlasted its view (§9.2): its answer, if any, is ignored.
    pub(super) fn discard_exec(&mut self, mut keep: Vec<Hash32>) {
        keep.sort();
        keep.dedup();
        let pending: Vec<Hash32> = self
            .exec
            .keys()
            .filter(|bh| !keep.contains(bh))
            .copied()
            .collect();
        for bh in pending {
            self.record_pending_exec(bh);
        }
        #[cfg(not(sumeragi_mutation = "ML17"))]
        self.exec.retain(|bh, _| keep.contains(bh));
        self.out.push(Action::DiscardExecution {
            height: self.height,
            keep,
        });
    }

    /// §9.2: if the execution of `bh` is still `Pending`, record its elapsed time `now − since`
    /// (a lower bound of its duration) in `pm.last_exec_ms`. Called when the entry is discarded
    /// and, for the committed block, at the commit (§6.8 step 4).
    pub(super) fn record_pending_exec(&mut self, bh: Hash32) {
        if cfg!(sumeragi_mutation = "ML27") {
            return;
        }
        if let Some(ExecState::Pending { since, .. }) = self.exec.get(&bh) {
            let elapsed = self.now.saturating_sub(*since);
            self.pm.record_exec(elapsed);
        }
    }

    /// §6.3 on `Executed`.
    pub(super) fn on_executed(&mut self, bh: Hash32, req: u64, outcome: &ExecOutcome) {
        // Step 0: the execution of the committed block that was still pending at its commit.
        if bh == self.tip.block_hash && self.tip.exec_req == Some(req) {
            self.tip.exec_req = None;
            match outcome {
                ExecOutcome::Valid(result) if *result == self.tip.result => {
                    self.tip.exec_ok = true;
                    if !self.awaiting && self.halted.is_none() {
                        self.maybe_execute();
                    }
                }
                ExecOutcome::Valid(_) | ExecOutcome::Invalid => {
                    let view = self.tip.commit_qc.as_ref().map_or(0, |qc| qc.view);
                    self.local_fault(LocalFault::ExecutionMismatch {
                        height: self.tip.height,
                        view,
                    });
                }
                // The driver executes the block when it applies it (O3).
                ExecOutcome::Failed(_) | ExecOutcome::Cancelled => {}
            }
            return;
        }
        let Some(ExecState::Pending {
            since,
            req: expected,
            attempt,
        }) = self.exec.get(&bh).copied()
        else {
            return;
        };
        if expected != req {
            return;
        }
        self.pm.record_exec(self.now.saturating_sub(since));
        let state = match outcome {
            ExecOutcome::Valid(result) => ExecState::Valid(*result),
            ExecOutcome::Invalid => ExecState::Invalid,
            #[cfg(sumeragi_mutation = "MS36b")]
            ExecOutcome::Failed(_) => ExecState::Invalid,
            ExecOutcome::Failed(_) | ExecOutcome::Cancelled => {
                let delay = exec_retry_delay(attempt, self.local.rebroadcast_interval);
                self.exec.insert(
                    bh,
                    ExecState::RetryAt {
                        at: self.now.saturating_add(delay),
                        attempt: attempt.saturating_add(1),
                    },
                );
                if matches!(outcome, ExecOutcome::Failed(_)) {
                    self.local_fault(LocalFault::ExecutorFailed {
                        height: self.height,
                    });
                }
                return;
            }
        };
        self.exec.insert(bh, state);
        self.on_outcome(bh);
    }

    /// Results a held `PrepareQC` certifies for `bh` (a re-proposal's `Q`, or the lock).
    fn certified_results(&self, bh: Hash32) -> Vec<Hash32> {
        let mut out = Vec::new();
        if let Some(held) = self.proposal.as_ref().filter(|held| held.bh == bh) {
            out.extend(held.expected);
        }
        if let Some(q) = self.high_pqc.as_ref().filter(|q| q.block_hash == bh) {
            out.push(q.result);
        }
        out
    }

    /// §6.3 steps 3–4 for the current proposal's block with a recorded outcome.
    fn on_outcome(&mut self, bh: Hash32) {
        // The held proposal of the current view only (a view change clears it; checked here
        // too, like `try_prepare`'s condition 3, so a stale proposal never times a view out).
        // MS3 removes this guard with the other two.
        let stale = |held: &Held| held.p.view != self.view && !cfg!(sumeragi_mutation = "MS3");
        if (self.proposal.as_ref()).is_none_or(|held| held.bh != bh || stale(held)) {
            return;
        }
        let certified = self.certified_results(bh);
        let fault = LocalFault::ExecutionMismatch {
            height: self.height,
            view: self.view,
        };
        match self.exec.get(&bh) {
            Some(ExecState::Invalid) if certified.is_empty() => self.reject_payload(bh),
            #[cfg(sumeragi_mutation = "MS36a")]
            Some(ExecState::Invalid) => self.reject_payload(bh),
            #[cfg(sumeragi_mutation = "MS36a")]
            Some(ExecState::Valid(r)) if certified.iter().any(|e| e != r) => {
                self.reject_payload(bh)
            }
            // A certified block the local executor disagrees with: local only (SR36).
            Some(ExecState::Invalid) => self.local_fault(fault),
            Some(ExecState::Valid(r)) if certified.iter().any(|e| e != r) => {
                self.local_fault(fault);
            }
            Some(ExecState::Valid(_)) => {
                self.try_prepare();
            }
            _ => {}
        }
    }

    /// Deterministic invalidity of an uncertified, `body_ok`, fresh block (SR35): no evidence
    /// (the leader does not execute before proposing, §3.6), the builder quarantines the culprit
    /// transactions, the view is abandoned at once.
    fn reject_payload(&mut self, bh: Hash32) {
        self.out.push(Action::PayloadRejected {
            height: self.height,
            view: self.view,
            block_hash: bh,
        });
        self.sign_timeout(self.view);
    }

    /// `try_prepare()`: the complete §4.3 predicate (S2), then persist, sign, route, pool.
    pub(super) fn try_prepare(&mut self) {
        let Some(me) = self.signer() else {
            return;
        };
        let view = self.view;
        // Condition 1: the timeout fence.
        #[cfg(not(sumeragi_mutation = "MS4"))]
        if self.timeout_view.is_some_and(|t| t >= view) {
            return;
        }
        // Condition 2: sign-once.
        if self.safety.as_ref().is_none_or(|r| {
            r.prepare.is_some_and(|v| v.view >= view) && !cfg!(sumeragi_mutation = "MS2")
        }) {
            return;
        }
        // Conditions 3–4: the held proposal of this view, its body, its valid result.
        let Some(bh) = self
            .proposal
            .as_ref()
            .filter(|held| held.p.view == view || cfg!(sumeragi_mutation = "MS3"))
            .map(|held| held.bh)
        else {
            return;
        };
        if !self.blocks.contains_key(&bh) {
            return;
        }
        let Some(ExecState::Valid(result)) = self.exec.get(&bh).copied() else {
            return;
        };
        if self.certified_results(bh).iter().any(|e| *e != result) {
            return;
        }
        if self.t_ready.is_none() {
            self.t_ready = Some(self.now);
        }
        // Condition 5: set A, or stage ≥ 1.
        if !self.rnd.in_set_a(me.index) && (self.stage < 1 || cfg!(sumeragi_mutation = "ML3")) {
            return;
        }
        #[cfg(not(sumeragi_mutation = "MS27"))]
        if let Some(record) = self.safety.as_mut() {
            record.prepare = Some(RecordedVote {
                view,
                block_hash: bh,
                result,
            });
        }
        #[cfg(not(sumeragi_mutation = "MS23"))]
        self.persist();
        self.cast_vote(me, VoteKind::Prepare, (bh, result));
        #[cfg(sumeragi_mutation = "MS23")]
        self.persist();
    }

    /// `on_block_request` (§6.9 rule 4): every requested response uses the driver's
    /// bounded, per-requester serving path and original authenticated body stores.
    pub(super) fn on_block_request(&mut self, to: PublicKey, height: u64, bh: Hash32) {
        #[cfg(sumeragi_mutation = "ML11")]
        if height <= self.tip.height {
            return;
        }
        self.out.push(Action::ServePayload {
            to,
            height,
            block_hash: bh,
        });
    }
    pub(super) fn on_manifest(&mut self, manifest: PayloadManifest) {
        let bh = manifest.hash(&*self.crypto);
        let Some(want) = self.wants.get(&bh) else {
            return;
        };
        if manifest.header.height != want.height
            || !manifest.availability.admitted_to(&self.body_budget)
        {
            return;
        }
        let Some(config) = self.config(want.height).cloned() else {
            return;
        };
        let Ok(source) = AvailabilitySource::new(self.instance, want.height, bh, config) else {
            return;
        };
        self.out.push(Action::AcquirePayload { source, manifest });
    }
}
