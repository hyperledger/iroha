//! Work-driven proposing (§6.10): empty builds wait and never become blocks.

use super::{Build, Core, FreshBuild, Me};
use crate::{
    api::{Action, ControlWitnessContext},
    availability::{AvailableBody, PayloadBytes},
    message::{BlockHeader, Proposal, ProposalMessage, TimeoutCert, WireMessage},
    preimage,
    safety::RecordedProposal,
    types::ControlWitness,
};

impl Core {
    /// The signing member if it may propose in `(h, view)`: it is `L(h, view)`, has not timed
    /// out of the view and has no proposal recorded at the view (S1).
    fn leader_eligible(&self) -> Option<Me> {
        let me = self.signer()?;
        let view = self.view;
        let recorded = self
            .safety
            .as_ref()
            .and_then(|r| r.proposal.as_ref())
            .is_some_and(|p| p.view >= view);
        (self.rnd.leader() == me.index
            && self.timeout_view.is_none_or(|t| t < view)
            && (!recorded || cfg!(sumeragi_mutation = "MS1")))
        .then_some(me)
    }

    /// `propose` (§6.10) on round entry: nothing if a proposal is recorded at `(h, view)` (rule
    /// 0: after a restart only the recorded one is re-sent); at view 0 schedule the build at
    /// `t_propose` (rule 1); after `TC(view − 1)` propose at once (rule 2): `Q`'s block unchanged
    /// if the TC carries `Q`, else build fresh nonempty work at every view.
    pub(super) fn propose(&mut self) {
        if self.leader_eligible().is_none() {
            return;
        }
        if self.view == 0 {
            let at = self
                .pm
                .propose_time(self.t_enter, self.cfg.params.block_time);
            self.build = Build::Scheduled(at);
            return;
        }
        let Some(tc) = self
            .high_tc
            .clone()
            .filter(|tc| tc.view.checked_add(1) == Some(self.view))
        else {
            return;
        };
        match tc
            .high_pqc
            .as_ref()
            .filter(|_| !cfg!(sumeragi_mutation = "MS10a"))
        {
            // TC rule: re-propose Q's block unchanged, fetching the body if needed.
            Some(q) => {
                if let Some(block) = self.blocks.get(&q.block_hash).cloned() {
                    self.propose_block(block, Some(tc));
                } else {
                    self.repropose = true;
                    let sources = self.signer_keys(q);
                    self.want(q.block_hash, self.height, sources);
                }
            }
            None => self.request_build(),
        }
    }

    /// Request real work first; only its exact bounded result may request application control.
    fn request_build(&mut self) {
        if self.leader_eligible().is_none() || (self.view > 0 && cfg!(sumeragi_mutation = "ML13")) {
            self.build = Build::Idle;
            return;
        }
        let budget = self.pm.exec_budget(self.cfg.params.e_max);
        let req = self.next_req;
        self.next_req = self.next_req.saturating_add(1);
        self.fresh_build = Some(FreshBuild {
            context: ControlWitnessContext {
                height: self.height,
                view: self.view,
                epoch: self.cfg.epoch.id,
                parent_hash: self.tip.block_hash,
                parent_result: self.tip.result,
            },
            payload: None,
            authoring: None,
        });
        self.out.push(Action::BuildPayload {
            req,
            height: self.height,
            view: self.view,
            max_bytes: self.cfg.params.max_block_bytes,
            exec_budget_ms: u32::try_from(budget).unwrap_or(u32::MAX),
        });
        self.build = Build::Requested {
            req,
            deadline: self.now.saturating_add(self.local.build_timeout),
            ready: false,
        };
    }

    /// Fire a due build deadline (`Tick`, §6.11 first).
    pub(super) fn build_tick(&mut self) {
        match self.build {
            Build::Scheduled(at) if self.now >= at => self.request_build(),
            Build::Requested {
                req,
                deadline,
                ready,
            } if deadline != u64::MAX && self.now >= deadline => {
                // A missed build deadline is not a block. Keep the request wakeup
                // and retry on the bounded interval or newly available work.
                self.wait_for_work(req, ready, false);
            }
            Build::IdleWait { until, .. } if self.now >= until => self.request_build(),
            _ => {}
        }
    }

    /// The build deadline, if any.
    pub(super) fn build_deadline(&self) -> Option<u64> {
        match self.build {
            Build::Idle => None,
            Build::Scheduled(at) | Build::IdleWait { until: at, .. } => Some(at),
            Build::Requested { deadline, .. } => (deadline != u64::MAX).then_some(deadline),
        }
    }

    /// Keep the first nonempty bounded payload until its exact control response arrives.
    pub(super) fn on_payload_built(&mut self, req: u64, payload: Option<PayloadBytes>) {
        if self.awaiting {
            return;
        }
        let Build::Requested {
            req: outstanding,
            ready,
            ..
        } = self.build
        else {
            return;
        };
        let Some(fresh) = self.fresh_build.as_ref() else {
            return;
        };
        if req != outstanding || fresh.payload.is_some() || fresh.authoring.is_some() {
            return;
        }
        let Some(payload) = payload else {
            self.wait_for_work(req, ready, false);
            return;
        };
        let too_large = u32::try_from(payload.as_slice().len())
            .map_or(true, |len| len > self.cfg.params.max_block_bytes);
        if !payload.admitted_to(&self.body_budget) {
            return;
        }
        if too_large {
            self.wait_for_work(req, ready, too_large);
            return;
        }
        let fresh = self
            .fresh_build
            .as_mut()
            .expect("original fresh build retained");
        fresh.payload = Some(payload);
        let context = fresh.context;
        self.build = Build::Requested {
            req,
            deadline: u64::MAX,
            ready,
        };
        self.out.push(Action::BuildControlWitness { req, context });
        // MS47: a missing authenticated application response is silently invented.
        if cfg!(sumeragi_mutation = "MS47") {
            self.on_control_witness_built(req, context, &ControlWitness::empty());
        }
    }

    fn wait_for_work(&mut self, req: u64, ready: bool, too_large: bool) {
        self.fresh_build = None;
        if ready && !too_large {
            // A work notification already arrived before the empty builder response.
            self.request_build();
        } else {
            self.build = Build::IdleWait {
                req,
                until: self
                    .now
                    .saturating_add(self.cfg.params.payload_retry_interval),
            };
        }
    }

    /// Exact request, view, epoch and both parent commitments prevent attaching a stale pulse.
    pub(super) fn on_control_witness_built(
        &mut self,
        req: u64,
        context: ControlWitnessContext,
        witness: &ControlWitness,
    ) {
        if self.awaiting {
            return;
        }
        let Build::Requested {
            req: outstanding, ..
        } = self.build
        else {
            return;
        };
        let Some(fresh) = self.fresh_build.as_mut() else {
            return;
        };
        if req != outstanding || fresh.payload.is_none() {
            return;
        }
        if !cfg!(sumeragi_mutation = "MS48") && context != fresh.context {
            return;
        }
        // Control is requested only after the first bounded payload. Taking the request
        // consumes its sole response and makes every duplicate stale.
        let fresh = self
            .fresh_build
            .as_mut()
            .expect("original request retained");
        let payload = fresh.payload.take().expect("original nonempty payload");
        self.request_authoring(req, payload, witness);
    }

    /// On `PayloadReady{req}` (§6.10): wake the eligible leader's empty-build wait at any
    /// view. Consensus view timers do not depend on its local queue (§9.1).
    pub(super) fn on_payload_ready(&mut self, req: u64) {
        if self.awaiting {
            return;
        }
        // ML21: the revision-3 `t_tx` term (any `PayloadReady` pulls the view-0 anchor in).
        #[cfg(sumeragi_mutation = "ML21")]
        if self.view == 0 {
            let t = (self.now.saturating_add(self.cfg.params.block_time))
                .saturating_add(self.local.build_timeout);
            self.t_prop = Some(self.t_prop.map_or(t, |x| x.min(t)));
        }
        match &mut self.build {
            Build::IdleWait { req: waiting, .. } if *waiting == req => self.request_build(),
            // SPEC: the driver sends `PayloadReady{req}` after answering `BuildPayload{req}`
            // with `EMPTY`; that answer may still be queued behind it. The readiness is kept,
            // and the `EMPTY` answer then requests again at once instead of idling until
            // `payload_retry_interval` (found by the simulator: F2 seed 115, an honest leader
            // demoted for idling; Appendix E, E4).
            #[cfg(not(sumeragi_mutation = "ME4"))]
            Build::Requested {
                req: outstanding,
                ready,
                ..
            } if *outstanding == req => *ready = true,
            _ => {}
        }
    }

    /// Build and send a fresh block from the authenticated application response (§6.10 rule 3).
    fn request_authoring(
        &mut self,
        req: u64,
        payload: PayloadBytes,
        control_witness: &ControlWitness,
    ) {
        let Some(me) = self.leader_eligible() else {
            self.build = Build::Idle;
            return;
        };
        let justify = if self.view == 0 {
            None
        } else {
            match self.high_tc.clone() {
                Some(tc) if tc.view.checked_add(1) == Some(self.view) => Some(tc),
                _ => return,
            }
        };
        let header = BlockHeader {
            instance: self.instance,
            epoch: self.cfg.epoch.id,
            height: self.height,
            origin_view: self.view,
            parent_hash: self.tip.block_hash,
            parent_result: self.tip.result,
            payload_hash: preimage::payload_hash(&*self.crypto, payload.as_slice()),
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: u32::try_from(payload.as_slice().len()).unwrap_or(u32::MAX),
            proposer: me.index,
            skipped_leaders: self
                .topo
                .skipped_leader_keys(&self.cfg.committee, self.view),
            control_witness: *control_witness,
        };
        self.fresh_build
            .as_mut()
            .expect("original source retained")
            .authoring = Some((header.clone(), justify));
        self.out.push(Action::AuthorPayload {
            req,
            config: self.cfg.clone(),
            header,
            payload,
        });
    }

    /// Only an exact current original request can become a fresh proposal after worker custody.
    pub(super) fn on_payload_authored(&mut self, req: u64, body: AvailableBody) {
        if self.awaiting
            || self.leader_eligible().is_none()
            || !body.admitted_to(&self.body_budget)
            || body.source().instance() != self.instance
            || body.source().config() != &self.cfg
        {
            return;
        }
        let Build::Requested { req: expected, .. } = self.build else {
            return;
        };
        if req != expected {
            return;
        }
        let Some(fresh) = self.fresh_build.as_ref() else {
            return;
        };
        let Some((template, _)) = &fresh.authoring else {
            return;
        };
        let mut template = template.clone();
        template.availability_digest = body.header().availability_digest;
        if &template != body.header()
            || template.height != self.height
            || template.origin_view != self.view
            || template.epoch != self.cfg.epoch.id
            || template.parent_hash != self.tip.block_hash
            || template.parent_result != self.tip.result
        {
            return;
        }
        let (_, justify) = self
            .fresh_build
            .as_mut()
            .expect("exact source retained")
            .authoring
            .take()
            .expect("exact template retained");
        self.propose_block(body, justify);
    }

    /// Record, sign and broadcast a proposal of `block`, then accept it (§6.10 rule 3, SR1).
    fn propose_block(&mut self, block: AvailableBody, justify: Option<TimeoutCert>) {
        let Some(me) = self.leader_eligible() else {
            return;
        };
        self.build = Build::Idle;
        self.fresh_build = None;
        self.repropose = false;
        let bh = block.hash(&*self.crypto);
        self.put_body(bh, block.clone());
        #[cfg(not(sumeragi_mutation = "MS29"))]
        if let Some(record) = self.safety.as_mut() {
            record.proposal = Some(RecordedProposal {
                view: self.view,
                block_hash: bh,
                justify: justify.clone(),
            });
        }
        self.persist();
        self.send_proposal(me, block, justify);
    }

    /// Sign and broadcast the proposal of `block` in `(h, view)` (after its record), then
    /// handle it as an accepted proposal.
    fn send_proposal(&mut self, me: Me, block: AvailableBody, justify: Option<TimeoutCert>) {
        let parent_qc = self
            .safety
            .as_ref()
            .and_then(|record| record.parent_commit_qc.clone());
        let bh = block.hash(&*self.crypto);
        let ad = preimage::att_digest(&*self.crypto, justify.as_ref(), parent_qc.as_ref());
        let msg = preimage::prop_preimage(
            &self.instance,
            &self.cfg.epoch.id,
            self.height,
            self.view,
            &bh,
            &ad,
        );
        let Some(sig) = self.sign(me, &msg) else {
            return;
        };
        let proposal = Proposal {
            instance: self.instance,
            height: self.height,
            view: self.view,
            header: block.header().clone(),
            justify,
            parent_qc,
            sig,
        };
        let to = self.recipients(true);
        self.broadcast(
            to.clone(),
            WireMessage::Proposal(Box::new(ProposalMessage {
                proposal: proposal.clone(),
                availability: block.availability().clone(),
            })),
        );
        self.out.push(Action::DisseminatePayload {
            peers: to,
            body: block,
        });
        self.mine.proposal = Some(proposal.clone());
        self.proposal_sent_at = Some(self.now);
        if self.proposal.is_none() {
            self.accept_proposal(None, proposal, bh, ad);
        }
    }

    /// §6.10 rule 0: after a restart the leader re-sends exactly the recorded proposal of the
    /// view once its body is loaded from the local store, and never builds another (SR1).
    pub(super) fn resend_recorded_proposal(&mut self) {
        let Some(bh) = self.resend_recorded.take() else {
            return;
        };
        let Some(me) = self.signer() else {
            return;
        };
        let Some(recorded) = self
            .safety
            .as_ref()
            .and_then(|r| r.proposal.clone())
            .filter(|p| p.view == self.view && p.block_hash == bh)
        else {
            return;
        };
        let Some(block) = self.blocks.get(&bh).cloned() else {
            return;
        };
        self.send_proposal(me, block, recorded.justify);
    }

    /// The re-proposal's body arrived (§6.10 rule 2).
    pub(super) fn try_repropose(&mut self) {
        let Some(tc) = self.high_tc.clone() else {
            return;
        };
        let Some(block) = tc
            .high_pqc
            .as_ref()
            .and_then(|q| self.blocks.get(&q.block_hash))
            .cloned()
        else {
            return;
        };
        if tc.view.checked_add(1) == Some(self.view) {
            self.propose_block(block, Some(tc));
        }
    }
}
