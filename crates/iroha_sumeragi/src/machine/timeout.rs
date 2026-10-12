//! Timing out, joining and timeout certificates (§6.6, §6.7) and round synchronisation
//! (`advance_to`, §6.12).

use super::{Core, EvKey, Mine, PqcVia};
use crate::{
    crypto::form_tc,
    message::{Evidence, TimeoutCert, TimeoutVote, WireMessage},
    preimage,
    safety::RecordedTimeout,
    types::usize_of,
};

impl Core {
    /// `sign_timeout(w)` (§6.6, S4): at most one timeout per view, carrying the lock held at
    /// signing time; `mine.timeout` is the only timeout for `w` ever sent (SR8, SR9). No
    /// timeout, whatever its cause, changes the start level (§9.2).
    pub(super) fn sign_timeout(&mut self, w: u64) {
        let Some(me) = self.signer() else {
            return;
        };
        let reserved = self
            .safety
            .as_ref()
            .and_then(|r| r.timeout.as_ref())
            .filter(|timeout| timeout.view == w)
            .cloned();
        let retry = reserved.is_some() && self.mine.timeout.as_ref().is_none_or(|t| t.view != w);
        if w < self.view
            || self
                .timeout_view
                .is_some_and(|t| t > w || (t == w && !retry))
        {
            return;
        }
        if w > self.view {
            self.advance_to(w, false);
        }
        // ML25: the revision-4.1 raise (a view timed out while its proposal was held).
        #[cfg(sumeragi_mutation = "ML25")]
        if self.proposal.is_some() {
            self.pm.failed_with_proposal = true;
        }
        self.timeout_view = Some(w);
        let carried = reserved
            .map_or_else(|| self.high_pqc.clone(), |t| t.high_pqc)
            .filter(|_| !cfg!(sumeragi_mutation = "MS8"));
        #[cfg(not(sumeragi_mutation = "MS26"))]
        if let Some(record) = self.safety.as_mut() {
            record.timeout = Some(RecordedTimeout {
                view: w,
                high_pqc: carried.clone(),
            });
        }
        self.persist();
        let Some(timeout) = self.build_timeout(me, w, carried) else {
            return;
        };
        self.mine.timeout = Some(timeout.clone());
        let to = self.members_except_me();
        self.broadcast(to, WireMessage::Timeout(Box::new(timeout.clone())));
        self.timeout_insert(timeout);
    }

    /// Sign `TimeoutVote(h, w, high_pqc)` (also used to rebuild a recorded timeout, R4).
    pub(super) fn build_timeout(
        &mut self,
        me: super::Me,
        w: u64,
        high_pqc: Option<crate::message::Qc>,
    ) -> Option<TimeoutVote> {
        let hq = high_pqc.as_ref().map(|qc| qc.view);
        let msg = preimage::tmo_preimage(&self.instance, &self.cfg.epoch.id, self.height, w, hq);
        let sig = self.sign(
            me.slot,
            crate::api::SigningKind::Timeout,
            self.height,
            w,
            &msg,
        )?;
        Some(TimeoutVote {
            instance: self.instance,
            epoch: self.cfg.epoch.id,
            height: self.height,
            view: w,
            high_pqc,
            signer: me.index,
            sig,
        })
    }

    /// §6.7 on a timeout vote from the wire at the current height.
    pub(super) fn on_timeout(&mut self, t: TimeoutVote) {
        if t.height != self.height {
            return;
        }
        let Some(old) = self.timeout_slot(t.signer).cloned() else {
            return;
        };
        // Step 1: cheap rejects (an older view, or the stored `(view, hq)`), then the signature
        // and the carried PrepareQC (verified, or found in the cache, as part of the timeout).
        if old
            .as_ref()
            .is_some_and(|o| o.view > t.view || (o.view == t.view && o.hq() == t.hq()))
        {
            return;
        }
        if self
            .verifier(&self.cfg)
            .verify_timeout_signature(&t)
            .is_err()
        {
            return;
        }
        // MR-nested-pqc: a nested PrepareQC is cheap-rejected like a top-level one.
        #[cfg(sumeragi_mutation = "MR-nested-pqc")]
        if (t.high_pqc.as_ref())
            .is_some_and(|qc| self.high_pqc.as_ref().is_some_and(|q| q.view >= qc.view))
        {
            return;
        }
        if let Some(qc) = &t.high_pqc
            && self.high_pqc.as_ref() != Some(qc)
            && !self.verify_qc_cached(qc)
        {
            return;
        }
        // Step 2: equivocation.
        if let Some(old) = old.filter(|o| o.view == t.view) {
            self.report(
                EvKey::Timeout(t.view, t.signer),
                Evidence::TimeoutEquivocation(Box::new(old), Box::new(t)),
            );
            return;
        }
        // Step 3: the carried PrepareQC (lock update, round sync), handled by §6.5's own rules.
        let h0 = self.height;
        if let Some(qc) = t.high_pqc.clone() {
            self.on_qc(qc, PqcVia::Timeout);
            if !self.same_height(h0) {
                return;
            }
        }
        // Step 4.
        self.timeout_insert(t);
    }

    /// `timeout_insert(t)` (§6.7), for received and own timeouts alike: store it, form a TC
    /// from `q` timeouts of its view (`form_tc`), and join the `(f + 1)`-th highest view.
    pub(super) fn timeout_insert(&mut self, t: TimeoutVote) {
        let view = t.view;
        match self.timeouts.get_mut(usize_of(t.signer)) {
            Some(slot) if slot.as_ref().is_none_or(|old| old.view <= view) => *slot = Some(t),
            _ => return,
        }
        let h0 = self.height;
        self.try_form_tc(view);
        if !self.same_height(h0) {
            return;
        }
        let mut views: Vec<u64> = self.timeouts.iter().flatten().map(|t| t.view).collect();
        views.sort_unstable_by(|a, b| b.cmp(a));
        #[cfg(not(sumeragi_mutation = "ML8"))]
        if let Some(&w_star) = views.get(self.cfg.committee.f())
            && w_star >= self.view
            && self.timeout_view.is_none_or(|t| t < w_star)
        {
            self.sign_timeout(w_star);
        }
    }

    /// Form or retry a timeout certificate from retained verified votes, without repooling.
    pub(super) fn try_form_tc(&mut self, view: u64) {
        if self.high_tc.as_ref().is_none_or(|tc| tc.view < view) {
            let same: Vec<&TimeoutVote> = self
                .timeouts
                .iter()
                .flatten()
                .filter(|t| t.view == view)
                .collect();
            if same.len() >= self.cfg.committee.q() {
                match form_tc(&*self.crypto, self.n(), &same) {
                    Ok(tc) => {
                        let digest = tc.digest(&*self.crypto);
                        self.cert_cache.insert(digest);
                        self.on_verified_tc(tc, false);
                    }
                    Err(crate::crypto::FormError::AggregationFailed(error)) => {
                        self.local_fault(crate::api::LocalFault::AggregationFailed {
                            kind: crate::api::CertificateKind::Timeout,
                            height: self.height,
                            view,
                            error,
                        });
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// §6.7 on a TC of the current height from the wire or a `Status`.
    pub(super) fn on_tc(&mut self, tc: TimeoutCert) {
        if self.awaiting || tc.height != self.height {
            return;
        }
        if self.high_tc.as_ref().is_some_and(|x| x.view >= tc.view) {
            return;
        }
        if tc.instance != self.instance || !self.verify_tc_cached(&tc) {
            return;
        }
        self.on_verified_tc(tc, false);
    }

    /// §6.7 TC handler rules 2–4 for a verified (or locally formed) TC. `justify`: it arrived
    /// as the next leader's own proposal justification.
    pub(super) fn on_verified_tc(&mut self, tc: TimeoutCert, justify: bool) {
        if self.high_tc.as_ref().is_none_or(|x| tc.view > x.view) {
            self.high_tc = Some(tc.clone());
        }
        // Rule 3: §6.5 steps 2a and 2c only (lock and want); `q` members timed out of
        // `tc.view ≥ Q.view`, so no Commit can form at `Q.view`.
        if let Some(qc) = tc.high_pqc.clone() {
            self.on_qc(qc, PqcVia::Tc);
        }
        let Some(next) = tc.view.checked_add(1) else {
            return;
        };
        if tc.view >= self.view && !self.awaiting {
            let leader = self.topo.leader(next);
            if Some(leader) != self.my_index()
                && !justify
                && let Some(to) = self.member_key(leader)
            {
                self.send(to, WireMessage::Tc(Box::new(tc)));
            }
            self.advance_to(next, true);
        }
    }

    /// `advance_to(w)` (§6.12): enter view `w > view` of the current height; `via_tc`: entered
    /// by `TC(w − 1)`, so the leader of `w` proposes.
    pub(super) fn advance_to(&mut self, w: u64, via_tc: bool) {
        if w <= self.view || self.awaiting {
            return;
        }
        self.view = w;
        self.reset_view();
        #[cfg(not(sumeragi_mutation = "MS3"))]
        {
            self.proposal = None;
        }
        self.late_entry = false;
        // Recorded votes are never re-sent once the view changed.
        self.mine = Mine {
            timeout: self.mine.timeout.take(),
            ..Mine::default()
        };
        let lo = w.saturating_sub(1);
        self.answered.retain(|(view, _)| *view >= lo);
        self.votes.retain_views(lo, w.saturating_add(1));
        #[cfg(not(sumeragi_mutation = "MR-advance-prune"))]
        self.reported.retain(|key| key.view() >= lo);
        self.rnd = self.topo.round(w);
        let keep: Vec<_> = [
            self.high_pqc.as_ref().map(|qc| qc.block_hash),
            self.high_tc
                .as_ref()
                .and_then(|tc| tc.high_pqc.as_ref())
                .map(|qc| qc.block_hash),
        ]
        .into_iter()
        .flatten()
        .collect();
        self.discard_exec(keep);
        self.prune_bodies();
        if via_tc {
            self.propose();
        }
    }
}
