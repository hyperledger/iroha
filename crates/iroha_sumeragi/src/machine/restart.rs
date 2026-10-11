//! `Core::new` (§12.1) and `restore`, the restart rules R1–R6 composed into one starting round
//! (§7.4), with the round restore of R4/R6.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{Build, CertCache, Core, LocalKey, Mine, Tip, sync::SyncState, votes::Pools};
use crate::{
    api::{Action, ConfigError, ConfigError::InvalidInit, HaltReason, Init, LocalParams},
    crypto::{Crypto, Signer},
    message::VoteKind,
    pacemaker::{Pacemaker, effective_t_max, validate_height, validate_local},
    safety::{
        RecordState, RestartPlan, SafetyRecord, check_recommit, read_record, recommit_candidate,
    },
    topology::Topology,
    types::{ConfigSlot, HeightConfig, Millis},
};

impl Core {
    /// Start a core (§12.1): validates the configuration (§9.4), then `restore` applies the
    /// restart rules R1–R6 (§7.4) to every configured and retired key and enters one starting
    /// round. `signers` are the configured keys; every key (configured or retired) has one
    /// entry in `init.records`. A corrupt or inconsistent record halts the instance
    /// (the core is still returned; it only serves).
    ///
    /// # Errors
    /// [`ConfigError`] for an invalid local configuration or unusable startup input.
    pub fn new(
        local: LocalParams,
        init: Init,
        signers: Vec<std::sync::Arc<dyn Signer>>,
        crypto: Box<dyn Crypto>,
        body_budget: iroha_allocation::AllocationBudget,
        now: Millis,
    ) -> Result<(Self, Vec<Action>), ConfigError> {
        let t = init.tip.height;
        let g = init.genesis_height;
        let configs: BTreeMap<u64, ConfigSlot> = init.configs.iter().cloned().collect();
        check_init(&init, &*crypto, &configs)?;
        if init.demotion_window < 1 {
            return Err(ConfigError::DemotionWindowZero);
        }
        let initial: Vec<_> = configs
            .iter()
            .filter(|(height, _)| **height > g)
            .filter_map(|(_, slot)| slot.ready())
            .collect();
        validate_local(&local, &initial)?;
        // SPEC: §9.4 leaves the chain-parameter rules to the application; the core also checks
        // the transport-independent ones for the initial configurations, so a genesis with
        // a zero retry interval or `block_time > payload_retry_interval`
        // is refused at startup (Appendix E, E38).
        for config in &initial {
            validate_height(config, u64::MAX)?;
        }
        let (keys, states) = local_keys(&init, signers)?;
        let first = configs
            .get(&t.saturating_add(1))
            .and_then(ConfigSlot::ready)
            .cloned()
            .ok_or_else(|| ConfigError::MissingConfig(t.saturating_add(1)))?;
        let mut core = Self::blank(
            local,
            init,
            keys,
            (crypto, body_budget),
            now,
            configs,
            first,
        );
        core.restore(&states);
        core.finish_call();
        let out = std::mem::take(&mut core.out);
        Ok((core, out))
    }

    /// `restore` (§7.4 Restart): R1 for every key; R5 at most once (it commits `t + 1` and
    /// advances the tip); every key classified against the new tip (R2, R3, R4, R6); the node
    /// starts in round `t + 1` (a late entry), restoring it from the signing key's R4 record.
    fn restore(&mut self, states: &[RecordState]) {
        // R1.
        let mut records = Vec::with_capacity(states.len());
        for (key, state) in self.keys.iter().zip(states) {
            match read_record(&*self.crypto, &self.instance, &key.pk, state) {
                Ok(record) => records.push(record),
                Err(_) => return self.halt(HaltReason::SafetyRecordCorrupt),
            }
        }
        // R5: the block store lost the last commit; the record's parent CommitQC restores it
        // (that its block extends the tip is checked when the body arrives, §6.9 rule 6).
        let t = self.tip.height;
        if let Some(record) = recommit_candidate(&records, t) {
            #[cfg(not(sumeragi_mutation = "MS15"))]
            let config_height = t.saturating_add(1);
            #[cfg(sumeragi_mutation = "MS15")]
            let config_height = t;
            let Some(config) = self.config(config_height) else {
                return self.halt(HaltReason::SafetyRecordInconsistent);
            };
            match check_recommit(&*self.crypto, &config.committee, &config.epoch, t, record) {
                Ok(qc) => {
                    let qc = qc.clone();
                    self.install_commit(qc);
                    if self.halted.is_some() {
                        return;
                    }
                }
                Err(reason) => return self.halt(reason),
            }
        }
        // Classification against the (possibly advanced) tip.
        #[cfg(not(sumeragi_mutation = "MS33c"))]
        let t = self.tip.height;
        let mut faults = Vec::new();
        for (key, record) in self.keys.iter_mut().zip(records) {
            let plan = RestartPlan::classify(record, t);
            key.abstain_below = plan.abstain_below();
            key.unanchored = plan.unanchored();
            // MS31b: R2 anchors at once from the local block-store tip (no probe).
            #[cfg(sumeragi_mutation = "MS31b")]
            if key.unanchored {
                key.unanchored = false;
                key.abstain_below = t.saturating_add(3);
            }
            key.restore = plan.record().cloned();
            faults.extend(plan.local_fault());
        }
        for fault in faults {
            self.local_fault(fault);
        }
        self.enter_height(t.saturating_add(1), true);
    }

    /// A core positioned at the startup tip, before the first height entry.
    #[allow(clippy::too_many_lines)] // one line per field of the §6.0 state
    fn blank(
        local: LocalParams,
        init: Init,
        keys: Vec<LocalKey>,
        (crypto, body_budget): (Box<dyn Crypto>, iroha_allocation::AllocationBudget),
        now: Millis,
        configs: BTreeMap<u64, ConfigSlot>,
        first: HeightConfig,
    ) -> Self {
        let tip = &init.tip;
        let prev = tip
            .header
            .as_ref()
            .map(|header| (header.parent_hash, header.parent_result));
        let mut headers: Vec<_> = init
            .recent_headers
            .iter()
            .filter(|header| header.height <= tip.height && header.instance == init.instance)
            .cloned()
            .collect();
        headers.sort_by_key(|header| header.height);
        headers.dedup_by_key(|header| header.height);
        let window = usize::try_from(init.demotion_window)
            .unwrap_or(usize::MAX)
            .saturating_add(2);
        let skip = headers.len().saturating_sub(window);
        let recent_headers: VecDeque<_> = headers.into_iter().skip(skip).collect();
        let tip = init.tip;
        let pm = Pacemaker::new(&local, effective_t_max(&local, &first));
        let n = first.committee.n();
        let topo = Topology::from_parts(vec![0], &[], u64::MAX)
            .expect("one placeholder slot is a nonempty permutation");
        let rnd = topo.round(0);
        Self {
            body_budget,
            crypto,
            local,
            instance: init.instance,
            genesis: init.genesis_height,
            #[cfg(not(sumeragi_mutation = "MR-window-init"))]
            w: init.demotion_window,
            #[cfg(sumeragi_mutation = "MR-window-init")]
            w: 128,
            keys,
            nonce: init.nonce,
            probe: BTreeMap::new(),
            probe_epoch: None,
            last_probe: now,
            halted: None,
            now,
            out: Vec::new(),
            tip: Tip {
                height: tip.height,
                block_hash: tip.block_hash,
                result: tip.result,
                commit_qc: tip.commit_qc,
                exec_ok: false,
                exec_req: None,
                prev,
                prev_qc: None,
            },
            applied: tip.height,
            configs,
            recent_headers,
            pending_apply: VecDeque::new(),
            awaiting: true,
            height: tip.height,
            view: 0,
            cfg: first,
            topo,
            rnd,
            t_enter: now,
            t_prop: None,
            t_body: None,
            late_entry: false,
            asked: false,
            me: None,
            safety: None,
            timeout_view: None,
            proposal: None,
            stage: 0,
            hint: 0,
            t_ready: None,
            t_pqc: None,
            t_lastvote: None,
            mine: Mine::default(),
            retx: [None, None],
            build: Build::Idle,
            fresh_build: None,
            control_drive: None,
            control_received: BTreeMap::new(),
            repropose: false,
            resend_recorded: None,
            proposal_sent_at: None,
            repushed: BTreeSet::new(),
            request_pushed: BTreeSet::new(),
            answered: BTreeSet::new(),
            votes: Pools::new(n),
            timeouts: vec![None; n],
            high_pqc: None,
            high_tc: None,
            cert_cache: CertCache::default(),
            reported: BTreeSet::new(),
            blocks: BTreeMap::new(),
            exec: BTreeMap::new(),
            next_req: 0,
            wants: BTreeMap::new(),
            pm,
            reported_t_req: 0,
            sync: SyncState::default(),
            peers: BTreeMap::new(),
            last_status: None,
            last_rebroadcast: now,
        }
    }

    /// §7.4 step 4: restore the current round from the signing key's record (R4, or R6 once
    /// the node reached the record's height): sign-once state, lock, `high_tc`,
    /// `timeout_view`, the exact recorded messages of the resumed view (SR26–SR30), the leader
    /// rules, and finally `try_commit()`. `take_restore` checked the record against the block
    /// store (E2).
    pub(super) fn restore_round(&mut self, record: SafetyRecord) {
        let Some(me) = self.signer() else {
            return;
        };
        for qc in record.lock.iter().chain(record.parent_commit_qc.iter()) {
            self.cache_cert_qc(qc);
        }
        if let Some(tc) = &record.high_tc {
            let digest = tc.digest(&*self.crypto);
            self.cert_cache.insert(digest);
        }
        let view = record.resume_view();
        #[cfg(not(sumeragi_mutation = "MS30"))]
        self.high_pqc.clone_from(&record.lock);
        self.high_tc.clone_from(&record.high_tc);
        self.timeout_view = record.timeout_view();
        if view > self.view {
            self.view = view;
            self.rnd = self.topo.round(view);
        }
        self.stage = self.hint;
        // A restored lock of the resumed view is a PrepareQC of `(h, view)` first held now: the
        // §5.2 stage-1 rules apply to it as in §6.5 (e) — `t_pqc` starts now (trigger a) and a
        // set-B signer raises the stage at once (trigger b) — so a restarted set-B member
        // re-signs its Commit in the final `try_commit()` as R4 requires.
        if let Some(lock) = record.lock.as_ref().filter(|lock| lock.view == view) {
            self.t_pqc = Some(self.now);
            let round = self.topo.round(view);
            if lock.signers.ones().any(|m| round.in_set_b(m)) {
                self.stage = self.stage.max(1);
            }
        }
        let timeout = record
            .timeout
            .clone()
            .and_then(|t| self.build_timeout(me, t.view, t.high_pqc));
        let prepare = record.prepare.filter(|v| v.view == view);
        let proposal = (record.proposal.clone())
            .filter(|p| p.view == view && !cfg!(sumeragi_mutation = "MS1"));
        self.safety = Some(record);
        self.mine.timeout.clone_from(&timeout);
        // The recorded Prepare of the resumed view: identical preimage, identical bytes
        // (deterministic signatures), on the retransmit schedule from now.
        let prepare =
            prepare.and_then(|v| self.record_vote(me, VoteKind::Prepare, (v.block_hash, v.result)));
        if let Some(qc) = self.high_pqc.clone() {
            let sources = self.signer_keys(&qc);
            self.want(qc.block_hash, self.height, sources);
        }
        let h0 = self.height;
        match proposal {
            // §6.10 rule 0: re-send exactly the recorded proposal once its body is loaded.
            Some(recorded) => {
                self.resend_recorded = Some(recorded.block_hash);
                self.want(recorded.block_hash, self.height, Vec::new());
            }
            // The leader rules: view 0 schedules the proposal, a view entered via
            // `high_tc = TC(view − 1)` proposes with it.
            #[cfg(not(sumeragi_mutation = "MR-restart-leader"))]
            None => self.propose(),
            #[cfg(sumeragi_mutation = "MR-restart-leader")]
            None => {}
        }
        // The own messages re-enter the own pools (§6.0); forming a certificate may commit.
        if let Some(vote) = prepare.filter(|_| self.same_height(h0)) {
            self.pool_insert(&vote);
        }
        if let Some(timeout) = timeout.filter(|_| self.same_height(h0)) {
            self.timeout_insert(timeout);
        }
        #[cfg(not(sumeragi_mutation = "MR-restore-commit"))]
        if self.same_height(h0) {
            self.try_commit();
        }
    }

    /// §7.4 step 4 (E2): a restored record at `h = tip.height + 1` must agree with the block
    /// store: its `parent_commit_qc` is absent only at `g + 1`, and otherwise a valid `CommitQC`
    /// of the tip for `(tip.block_hash, tip.result)`.
    // SPEC: R4 does not say that the record must agree with the block store. Its
    // `parent_commit_qc` is the `parent_qc` of every proposal re-sent from the record
    // (§6.10 rule 0), so a checksum-valid record whose parent CommitQC is not a valid
    // CommitQC of the committed tip would make this node re-send a different proposal for
    // a recorded round (found by the simulator: F24 with a forged record parent, seed 11).
    // Such a record contradicts the store: halt as for R5 (Appendix E, E2). The check runs
    // for the record of every key (configured or retired, signing or not) when the node
    // reaches its height, not only for the signing key's (found by review).
    pub(super) fn record_matches_tip(&mut self, record: &SafetyRecord) -> bool {
        if record.epoch != self.cfg.epoch.id || !self.cfg.epoch.contains(record.height) {
            return false;
        }
        if cfg!(sumeragi_mutation = "ME2") {
            return true;
        }
        match &record.parent_commit_qc {
            None => self.tip.height == self.genesis,
            Some(qc) => {
                qc.kind == VoteKind::Commit
                    && qc.height == self.tip.height
                    && qc.value() == (self.tip.block_hash, self.tip.result)
                    && (self.tip.commit_qc.as_ref() == Some(qc) || self.verify_qc_cached(qc))
            }
        }
    }
}

/// The configured and retired keys of `Init`, in `Init.records` order, with their record
/// states. Every configured key needs a signer and a record entry; a retired key has none.
// SPEC: §7.4 expects one `RecordState` per configured or retired key; a missing one, a signer
// for a retired key or a duplicate key is a driver error and is rejected rather than guessed
// (Appendix E, E16).
fn local_keys(
    init: &Init,
    signers: Vec<std::sync::Arc<dyn Signer>>,
) -> Result<(Vec<LocalKey>, Vec<RecordState>), ConfigError> {
    let mut signers: Vec<Option<std::sync::Arc<dyn Signer>>> =
        signers.into_iter().map(Some).collect();
    let mut keys: Vec<LocalKey> = Vec::with_capacity(init.records.len());
    let mut states = Vec::with_capacity(init.records.len());
    for (pk, state, retired) in &init.records {
        if keys.iter().any(|key| &key.pk == pk) {
            return Err(InvalidInit("a key listed twice"));
        }
        let signer = signers
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.public_key() == pk))
            .and_then(|i| signers.get_mut(i).and_then(Option::take));
        match (retired, signer.is_some()) {
            (false, false) => {
                return Err(InvalidInit("no signer for a configured key"));
            }
            (true, true) => return Err(InvalidInit("a signer for a retired key")),
            _ => {}
        }
        keys.push(LocalKey {
            pk: pk.clone(),
            signer,
            abstain_below: 0,
            unanchored: false,
            restore: None,
        });
        states.push(state.clone());
    }
    if signers.iter().any(Option::is_some) {
        return Err(InvalidInit("no record state for a configured key"));
    }
    Ok((keys, states))
}

/// Startup input consistency (the driver's own stores; checked, not trusted blindly).
fn check_init(
    init: &Init,
    crypto: &dyn Crypto,
    configs: &BTreeMap<u64, ConfigSlot>,
) -> Result<(), ConfigError> {
    let tip = &init.tip;
    if tip.height < init.genesis_height {
        return Err(InvalidInit("tip below genesis"));
    }
    let at_genesis = tip.height == init.genesis_height;
    if at_genesis != tip.commit_qc.is_none() || at_genesis != tip.header.is_none() {
        return Err(InvalidInit("tip certificate or header presence"));
    }
    if let Some(header) = &tip.header
        && (header.height != tip.height || header.hash(crypto) != tip.block_hash)
    {
        return Err(InvalidInit("tip header does not match the tip"));
    }
    // SPEC: §12.1 lists the configurations of `t` (unless `t = g`), `t + 1` and `t + 2`. One
    // above `t + 2` let commits run more than two heights ahead of apply (§10.2), and the next
    // in-order `BlockApplied` then halted the core as a driver anomaly (found by review): any
    // other height, or a height listed twice, is refused (Appendix E, E37).
    if configs.len() != init.configs.len() {
        return Err(InvalidInit("a configuration listed twice"));
    }
    if configs
        .keys()
        .any(|height| *height < tip.height || *height > tip.height.saturating_add(2))
    {
        return Err(InvalidInit(
            "a configuration for a height other than t, t + 1 and t + 2",
        ));
    }
    let (Some(next_height), Some(later_height)) =
        (tip.height.checked_add(1), tip.height.checked_add(2))
    else {
        return Err(InvalidInit("height overflow"));
    };
    let first = configs
        .get(&next_height)
        .and_then(ConfigSlot::ready)
        .ok_or(ConfigError::MissingConfig(next_height))?;
    if !first.epoch.contains(next_height) {
        return Err(InvalidInit("next height outside authenticated epoch"));
    }
    if !at_genesis {
        let current = configs
            .get(&tip.height)
            .and_then(ConfigSlot::ready)
            .ok_or(ConfigError::MissingConfig(tip.height))?;
        if !current.epoch.contains(tip.height)
            || tip.header.as_ref().map(|header| header.epoch) != Some(current.epoch.id)
            || (current.epoch.contains(next_height) && !first.same_authority(current))
            || (!current.epoch.contains(next_height) && !first.follows(current))
        {
            return Err(InvalidInit("noncontiguous authenticated epoch window"));
        }
    }
    let later_valid = match configs.get(&later_height) {
        Some(ConfigSlot::Ready(later)) => {
            first.epoch.contains(later_height) && later.same_authority(first)
        }
        Some(ConfigSlot::PendingBoundary {
            boundary_height,
            predecessor,
        }) => {
            first.epoch.last_height.checked_add(1) == Some(later_height)
                && *boundary_height == first.epoch.last_height
                && *predecessor == first.epoch.id
        }
        None => false,
    };
    if !later_valid {
        return Err(InvalidInit("next epoch must await its applied boundary"));
    }
    if let Some(qc) = &tip.commit_qc
        && (qc.kind != VoteKind::Commit
            || qc.height != tip.height
            || configs
                .get(&tip.height)
                .and_then(ConfigSlot::ready)
                .is_none_or(|config| qc.epoch != config.epoch.id)
            || qc.value() != (tip.block_hash, tip.result))
    {
        return Err(InvalidInit("tip CommitQC does not match the tip"));
    }
    Ok(())
}
