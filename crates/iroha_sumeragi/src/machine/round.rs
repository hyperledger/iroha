//! Commit and height entry (§6.8), `BlockApplied` (§6.13), the safety monitor (§7.6),
//! committee and chain-parameter changes (§10) and key selection at height entry (§7.4).

use super::{Build, Core, ExecState, Me, Mine, PendingApply, Tip, Via, votes::Pools};
use crate::{
    api::{Action, HaltReason, LocalFault},
    message::{BlockHeader, Evidence, Qc, VoteKind, WireMessage},
    pacemaker::{effective_t_max, t_req_nominal},
    safety::{SafetyRecord, SignerChoice, select_signer},
    topology::{Topology, initial_stage},
    types::{AppliedConfig, ConfigSlot, Hash32},
};

impl Core {
    /// `commit_height` (§6.8) on a `CommitQC` for the current height: verify (SR21), broadcast
    /// it if this node is the proxy tail that formed it, commit, then enter `h + 1` or await its
    /// configuration.
    pub(super) fn commit_height(&mut self, c: Qc, via: Via) {
        if self.awaiting || c.kind != VoteKind::Commit || c.height != self.height {
            return;
        }
        // Step 1.
        if !via.trusted() && !self.verify_qc_cached(&c) {
            return;
        }
        // Step 1a: the proxy tail broadcasts the CommitQC it formed before committing (O2 holds
        // it until its own Commit record is durable).
        #[cfg(not(sumeragi_mutation = "ML20"))]
        if via == Via::Formed && self.my_index() == Some(self.proxy_tail_of(c.view)) {
            let to = self.recipients_of(c.view, true);
            self.broadcast(to, WireMessage::Qc(c.clone()));
        }
        let view = c.view;
        // §9.2: how long the committing view took here, `d_c = now − t_body`, measured from
        // when this node first held that view's proposal of the committed block together with
        // its body; undefined if it is not in that view (it left it or never reached it) or
        // does not hold them (a twin, or no body). Neither the view-0 wait for the proposal nor
        // a leader's late proposal or body counts.
        #[cfg(not(any(sumeragi_mutation = "ML29", sumeragi_mutation = "ML30")))]
        let view_ms = self
            .t_body
            .filter(|_| {
                view == self.view
                    && self
                        .proposal
                        .as_ref()
                        .is_some_and(|held| held.bh == c.block_hash)
            })
            .map(|t| self.now.saturating_sub(t));
        // ML29: the E40 rule, measured from the anchor (a late proposal stretches it).
        #[cfg(sumeragi_mutation = "ML29")]
        let view_ms = (view == self.view).then(|| self.now.saturating_sub(self.anchor()));
        // ML30: measured from the acceptance of any held proposal (a late body or a twin
        // stretches it).
        #[cfg(sumeragi_mutation = "ML30")]
        let view_ms = self
            .t_prop
            .filter(|_| view == self.view)
            .map(|t| self.now.saturating_sub(t));
        if view == self.view {
            if let Some(retx) = self.retx[1] {
                self.pm
                    .record_qc_latency(self.now.saturating_sub(retx.sent));
            }
            if let Some(t_prop) = self.t_prop {
                self.pm
                    .record_commit_latency(self.now.saturating_sub(t_prop));
            }
        }
        let late = via.late();
        self.install_commit(c);
        // §9.2: the committed block's own execution, if still pending (kept as
        // `tip.exec_req`), counts with its elapsed time, like the discarded ones.
        self.record_pending_exec(self.tip.block_hash);
        self.discard_exec(vec![self.tip.block_hash]);
        self.pm.on_commit(view, view_ms);
        // The round of the committed height is over: none of its timers may fire again.
        self.retx = [None, None];
        self.build = Build::Idle;
        self.fresh_build = None;
        self.control_received.clear();
        if self.halted.is_some() {
            return;
        }
        // Step 5.
        let next = self.height.saturating_add(1);
        if self.config(next).is_some() {
            self.enter_height(next, late);
        } else {
            self.awaiting = true;
            self.prune_bodies();
        }
    }

    /// §6.8 steps 2–3: the new tip (keeping a pending execution of the committed block,
    /// `tip.exec_req`) and the `CommitBlock` in height order through `pending_apply`. Also used
    /// by R5 at restart (§7.4).
    pub(super) fn install_commit(&mut self, c: Qc) {
        let bh = c.block_hash;
        let (exec_ok, exec_req) = match self.exec.get(&bh) {
            Some(ExecState::Valid(result)) => (*result == c.result, None),
            #[cfg(not(sumeragi_mutation = "ML23"))]
            Some(ExecState::Pending { req, .. }) => (false, Some(*req)),
            _ => (false, None),
        };
        let sources = self.signer_keys(&c);
        let old = std::mem::replace(
            &mut self.tip,
            Tip {
                height: c.height,
                block_hash: bh,
                result: c.result,
                commit_qc: Some(c.clone()),
                exec_ok,
                exec_req,
                prev: None,
                prev_qc: None,
            },
        );
        self.tip.prev = Some((old.block_hash, old.result));
        self.tip.prev_qc = old.commit_qc;
        self.pending_apply.push_back(PendingApply {
            height: c.height,
            block_hash: bh,
            qc: c,
            parent_hash: old.block_hash,
            parent_result: old.result,
        });
        if !self.blocks.contains_key(&bh) {
            self.want(bh, self.tip.height, sources);
        }
        self.flush_pending_apply();
    }

    /// Emit `CommitBlock` for committed blocks whose bodies are held, strictly in height order
    /// (O3). Each body must extend the committed parent recorded with its entry (§6.9 rule 6):
    /// with at most `f` faults a certified block always does, so a mismatch means local storage
    /// corruption (e.g. of the block-store tip used by R5).
    pub(super) fn flush_pending_apply(&mut self) {
        while let Some(front) = self.pending_apply.front() {
            let Some(block) = self.blocks.get(&front.block_hash) else {
                return;
            };
            #[cfg(not(sumeragi_mutation = "MS32c"))]
            let header = &block.header();
            #[cfg(not(sumeragi_mutation = "MS32c"))]
            if header.height != front.height
                || header.parent_hash != front.parent_hash
                || header.parent_result != front.parent_result
            {
                return self.halt(HaltReason::SafetyRecordInconsistent);
            }
            let Some(entry) = self.pending_apply.pop_front() else {
                return;
            };
            let Some(block) = self.blocks.remove(&entry.block_hash) else {
                return;
            };
            self.out.push(Action::CommitBlock {
                block,
                commit_qc: entry.qc,
            });
        }
    }

    fn trim_headers(&mut self) {
        let window = usize::try_from(self.w)
            .unwrap_or(usize::MAX)
            .saturating_add(2);
        while self.recent_headers.len() > window {
            self.recent_headers.pop_front();
        }
    }

    /// `enter_height` (§6.8 step 5): enter round `(new_h, 0)`. `late`: the entry came from
    /// awaiting, sync, a `Status` or a restart (§6.8 step 5, §6.11 proposal request).
    /// Clear transient work of the previous view. Height entry and TC advancement keep
    /// their distinct durable locks, timeout records and proposal mutation checks.
    pub(super) fn reset_view(&mut self) {
        self.t_enter = self.now;
        self.t_prop = None;
        self.t_body = None;
        self.asked = false;
        self.stage = self.hint;
        self.t_ready = None;
        self.t_pqc = None;
        self.t_lastvote = None;
        self.retx = [None, None];
        self.build = Build::Idle;
        self.fresh_build = None;
        self.repropose = false;
        self.resend_recorded = None;
        self.proposal_sent_at = None;
        self.repushed.clear();
        self.request_pushed.clear();
    }

    pub(super) fn enter_height(&mut self, new_h: u64, late: bool) {
        let Some(cfg) = self.config(new_h).cloned() else {
            self.awaiting = true;
            return;
        };
        if !cfg.epoch.contains(new_h)
            || (cfg.epoch.first_height > self.genesis
                && self.applied < cfg.epoch.first_height.saturating_sub(1))
        {
            self.awaiting = true;
            return;
        }
        // §10.2: `C_{new_h}` is known iff `applied ≥ new_h − 2` (checked `Init.configs`, E37).
        debug_assert!(
            new_h <= self.applied.saturating_add(2),
            "entering height {new_h} with applied {}",
            self.applied
        );
        // The stage-1 hint needs the topology of h − 1 (reuse the current one when it is).
        let parent = if self.topo.height() == self.tip.height {
            Some(self.topo.clone())
        } else {
            self.topology_of(self.tip.height)
        };
        self.hint = parent.map_or(0, |p| initial_stage(&p, self.tip.commit_qc.as_ref()));
        self.awaiting = false;
        self.height = new_h;
        self.view = 0;
        self.reset_view();
        self.late_entry = late;
        self.timeout_view = None;
        self.proposal = None;
        self.mine = Mine::default();
        self.control_received.clear();
        self.answered.clear();
        self.votes = Pools::new(cfg.committee.n());
        self.timeouts = vec![None; cfg.committee.n()];
        self.high_pqc = None;
        self.high_tc = None;
        self.exec.clear();
        self.cert_cache.reset(4 * cfg.committee.n());
        self.reported.clear();
        self.cfg = cfg;
        if let Some(topo) = self.topology_of(new_h) {
            self.topo = topo;
        }
        self.rnd = self.topo.round(0);
        self.update_t_max();
        self.trim_headers();
        let floor = self.tip.height.saturating_sub(1);
        self.configs.retain(|height, _| *height >= floor);
        self.prune_probe();
        self.select_keys();
        self.prune_bodies();
        let restore = self.take_restore();
        if self.halted.is_some() {
            return;
        }
        match restore {
            Some(record) => self.restore_round(record),
            None => self.propose(),
        }
    }

    /// While a key is unanchored: drop the probe entries whose key is not in
    /// `C_{tip.height+2}` and re-check anchoring (§6.8 step 5, §7.4 R2).
    // SPEC: while that configuration is not known yet (the entry came before the apply of
    // `tip.height`), the entries are kept: a lowest reported height stays valid as the tip
    // rises (Appendix E, E7).
    fn prune_probe(&mut self) {
        if !self.any_unanchored() {
            self.probe.clear();
            return;
        }
        if let Some(next) = self.config(self.tip.height.saturating_add(2)) {
            let committee = next.committee.clone();
            let epoch = next.epoch.id;
            if self.probe_epoch != Some(epoch) {
                self.probe.clear();
            }
            self.probe.retain(|key, _| committee.contains(key));
            self.check_anchoring();
        }
        #[cfg(sumeragi_mutation = "ME7")]
        if !(self.configs).contains_key(&self.tip.height.saturating_add(2)) {
            self.probe.clear();
        }
    }

    /// Topology of `height` from its configuration and the recent committed headers.
    pub(super) fn topology_of(&self, height: u64) -> Option<Topology> {
        let config = self.config(height)?;
        let headers: Vec<BlockHeader> = self.recent_headers.iter().cloned().collect();
        Some(Topology::compute(
            &*self.crypto,
            &self.instance,
            &config.epoch,
            &config.committee,
            height,
            self.genesis,
            self.w,
            &headers,
        ))
    }

    /// `T_max_eff` for the configuration of `h`; `LocalFault(ConfigTooTight)` when a committed
    /// configuration raised `T_req` above `T_max` (§9.4).
    fn update_t_max(&mut self) {
        let t_max_eff = effective_t_max(&self.local, &self.cfg);
        if t_max_eff != self.pm.t_max_eff() {
            self.pm.set_t_max_eff(t_max_eff);
        }
        let t_req = t_req_nominal(&self.local, &self.cfg.params, self.cfg.committee.n());
        if t_req > self.local.t_max && t_req != self.reported_t_req {
            self.reported_t_req = t_req;
            self.local_fault(LocalFault::ConfigTooTight { t_req });
        }
    }

    /// Key selection at height entry (§7.4 Keys, SR33): the unique configured (not retired)
    /// key in `C_h` signs if it is anchored and does not abstain; two configured keys in `C_h`
    /// sign neither.
    fn select_keys(&mut self) {
        let configured: Vec<(usize, (&crate::types::PublicKey, u64, bool))> = self
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.signer.is_some())
            .map(|(slot, key)| (slot, (&key.pk, key.abstain_below, !key.unanchored)))
            .collect();
        let triples: Vec<_> = configured.iter().map(|(_, t)| *t).collect();
        let choice = select_signer(&triples, &self.cfg.committee, self.height);
        let member = configured.iter().find_map(|(slot, (pk, _, _))| {
            self.cfg.committee.index_of(pk).map(|index| (*slot, index))
        });
        let me = match choice {
            SignerChoice::Conflict => {
                self.me = None;
                self.safety = None;
                self.local_fault(LocalFault::KeyConflict {
                    height: self.height,
                });
                return;
            }
            SignerChoice::Key { slot, member } => Some(Me {
                slot: configured.get(slot).map_or(slot, |(s, _)| *s),
                index: member,
                signs: true,
            }),
            SignerChoice::Observer => member.map(|(slot, index)| Me {
                slot,
                index,
                signs: false,
            }),
        };
        // MS33b: the first configured key signs, whatever its membership in `C_h`.
        #[cfg(sumeragi_mutation = "MS33b")]
        let me = me.map(|me| Me {
            slot: configured.first().map_or(me.slot, |(slot, _)| *slot),
            ..me
        });
        self.me = me;
        let key = me
            .filter(|me| me.signs)
            .and_then(|me| self.keys.get(me.slot))
            .map(|key| key.pk.clone());
        self.safety = key.map(|key| {
            SafetyRecord::fresh(
                self.instance,
                self.cfg.epoch.id,
                key,
                self.height,
                self.tip.commit_qc.clone(),
            )
        });
    }

    /// The restored record of the signing key for the current height, if any (R4, R6). The
    /// record of every key for this height must agree with the block store first (E2); one
    /// that does not halts the instance.
    fn take_restore(&mut self) -> Option<SafetyRecord> {
        let h = self.height;
        for key in &mut self.keys {
            if key.restore.as_ref().is_some_and(|r| r.height < h) {
                key.restore = None;
            }
        }
        let due: Vec<SafetyRecord> = (self.keys.iter())
            .filter_map(|key| key.restore.clone().filter(|record| record.height == h))
            .collect();
        for record in &due {
            if !self.record_matches_tip(record) {
                self.halt(HaltReason::SafetyRecordInconsistent);
                return None;
            }
        }
        let me = self.signer()?;
        let key = self.keys.get_mut(me.slot)?;
        key.restore.take_if(|record| record.height == h)
    }

    /// `on_block_applied` (§6.13): the driver applied height `a`. It must be the next height,
    /// its header must hash to `block_hash`, and `block_hash` must be the block this core
    /// committed there (the tip or its parent); anything else is `Halt(DriverAnomaly)`.
    pub(super) fn on_block_applied(
        &mut self,
        a: u64,
        bh: Hash32,
        header: BlockHeader,
        config: AppliedConfig,
    ) {
        let committed = if a == self.tip.height {
            bh == self.tip.block_hash
        } else if Some(a) == self.tip.height.checked_sub(1) {
            self.tip.prev.is_some_and(|(prev, _)| prev == bh)
        } else {
            false
        };
        let valid = Some(a) == self.applied.checked_add(1)
            && header.height == a
            && header.hash(&*self.crypto) == bh
            && committed;
        #[cfg(sumeragi_mutation = "MR-block-applied")]
        let valid = true;
        if !valid {
            return self.halt(HaltReason::DriverAnomaly);
        }
        let Some(updates) = self.applied_config_updates(a, &header, config) else {
            return self.halt(HaltReason::DriverAnomaly);
        };
        // Validate every slot before publication; no partial next-epoch install is observable.
        self.applied = a;
        for (height, slot) in updates {
            self.configs.insert(height, slot);
        }
        self.recent_headers.push_back(header);
        self.trim_headers();
        let floor = self.tip.height.saturating_sub(1);
        self.configs.retain(|h, _| *h >= floor);
        // SPEC: §7.4 R2 checks anchoring "on every fresh reply and every height entry", but at a
        // height entry `C_{t'+2}` is normally not known yet (it comes with `BlockApplied(t')`),
        // and later replies report higher heights, which never lower an entry and so never
        // trigger the check: a node whose lowest replies were recorded while it was behind would
        // stay unanchored (found by the simulator: F24 seed 10, record and Kura tail lost). The
        // check also runs when `C_{tip.height+2}` becomes known (Appendix E, E6).
        #[cfg(not(sumeragi_mutation = "ME6"))]
        if a.saturating_add(2) == self.tip.height.saturating_add(2) {
            self.check_anchoring();
        }
        if self.awaiting {
            let next = self.tip.height.saturating_add(1);
            if self.config(next).is_some() {
                self.enter_height(next, true);
            }
        } else if a.saturating_add(1) == self.height {
            self.maybe_execute();
        }
    }

    /// Validate the complete atomic application/configuration result before changing the window.
    fn applied_config_updates(
        &self,
        height: u64,
        header: &BlockHeader,
        outcome: AppliedConfig,
    ) -> Option<Vec<(u64, ConfigSlot)>> {
        let current = self.config(height)?;
        if header.epoch != current.epoch.id || !current.epoch.contains(height) {
            return None;
        }
        let next_height = height.checked_add(1)?;
        let later_height = height.checked_add(2)?;
        let updates = match outcome {
            AppliedConfig::Continuation { after_next } => {
                if height == current.epoch.last_height {
                    return None;
                }
                let valid = match &after_next {
                    ConfigSlot::Ready(next) => {
                        current.epoch.contains(later_height) && next.same_authority(current)
                    }
                    ConfigSlot::PendingBoundary {
                        boundary_height,
                        predecessor,
                    } => {
                        current.epoch.last_height.checked_add(1) == Some(later_height)
                            && *boundary_height == current.epoch.last_height
                            && *predecessor == current.epoch.id
                    }
                };
                // MS44: a later epoch is accepted through ordinary lag-2 scheduling.
                if !valid && !cfg!(sumeragi_mutation = "MS44") {
                    return None;
                }
                vec![(later_height, after_next)]
            }
            AppliedConfig::Boundary { next, after_next } => {
                if height != current.epoch.last_height
                    || !next.follows(current)
                    || !next.epoch.contains(next_height)
                    || !after_next.same_authority(&next)
                    || !after_next.epoch.contains(later_height)
                    || !matches!(self.configs.get(&next_height),
                        Some(ConfigSlot::PendingBoundary { boundary_height, predecessor })
                        if *boundary_height == height && *predecessor == current.epoch.id)
                {
                    return None;
                }
                vec![
                    (next_height, ConfigSlot::Ready(next)),
                    (later_height, ConfigSlot::Ready(after_next)),
                ]
            }
        };
        for (height, slot) in &updates {
            if let ConfigSlot::Ready(config) = slot
                && crate::pacemaker::validate_height(config, u64::MAX).is_err()
            {
                return None;
            }
            if let Some(existing) = self.configs.get(height) {
                match (existing, slot) {
                    (
                        ConfigSlot::PendingBoundary {
                            boundary_height, ..
                        },
                        ConfigSlot::Ready(_),
                    ) if *boundary_height == header.height => {}
                    _ if existing == slot => {}
                    _ => return None,
                }
            }
        }
        Some(updates)
    }

    /// Safety monitor (§7.6, SR37): a valid `CommitQC` for `tip.height − 1` (whose
    /// configuration is retained) or `tip.height` with a different value halts the instance.
    /// Values are compared first.
    pub(super) fn monitor(&mut self, c: &Qc) {
        if c.kind != VoteKind::Commit || c.height <= self.genesis {
            return;
        }
        let (ours, our_qc) = if c.height == self.tip.height {
            (
                (self.tip.block_hash, self.tip.result),
                self.tip.commit_qc.clone(),
            )
        } else if Some(c.height) == self.tip.height.checked_sub(1)
            && !cfg!(sumeragi_mutation = "MR-monitor-prev")
            && let Some(prev) = self.tip.prev
        {
            (prev, self.tip.prev_qc.clone())
        } else {
            return;
        };
        if c.value() == ours {
            return;
        }
        #[cfg(not(sumeragi_mutation = "MS15"))]
        let config_height = c.height;
        #[cfg(sumeragi_mutation = "MS15")]
        let config_height = self.tip.height;
        let Some(config) = self.config(config_height) else {
            return;
        };
        // The exact quorum of authenticated Commit signatures proves the violation (§7.6).
        if self.verifier(config).verify_qc(c).is_err() {
            return;
        }
        if let Some(qc) = our_qc {
            self.out.push(Action::ReportEvidence(Box::new(
                Evidence::ConflictingCertificates(qc, c.clone()),
            )));
        }
        self.halt(HaltReason::SafetyViolation { height: c.height });
    }
}
