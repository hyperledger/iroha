//! The application clock guard of the simulator's toy application (§4.5): per-machine wall
//! clocks, block times stamped by the payload builders (CT3), the executor rules CT1 and CT5 for
//! executions with `certified = false`, and the oracle O-TIME (§13.2): the time of every
//! committed block exceeds every honest wall clock by at most `2·max_clock_drift_ms`, and
//! every due-work block is fresh at its first genuine honest Prepare.
//!
//! The guard is application-level (the node driver's executor, `iroha_core`); the sans-IO core
//! only emits the `certified` flag of `Action::Execute`. It is modelled here so that the
//! deterministic simulator can show liveness under skewed honest clocks and the certified-time
//! bounds, and so that its mutations (MS51, MS52, MS65, MS66, MS68–MS70) are killed by named simulator
//! tests (§13.4).
//!
//! Clock-enabled worlds retain the original parent cadence and queued creation-time floors.
//! Honest builders answer `EMPTY` while that floor is ahead, retain their queued work and wake
//! the same request when their wall clock catches up. A completed payload is retained unchanged
//! if the wall regresses during build latency. Creation times travel in immutable toy transaction
//! bytes. The final fresh `PayloadAuthored` admission resamples the wall immediately before Core
//! signs, preserving certified re-proposal exemptions. Custom/AMX inputs without creation metadata
//! explicitly have no creation floor. The stamp models the builder's additional
//! transaction-time floor; Byzantine leads may violate either deterministic floors or CT1/CT5.
//! These toy application records do not change the sans-IO protocol or clock-disabled worlds.

use super::*;
use crate::sim::{
    driver::{TIME_RECORD, block_time, encode_time, payload_due},
    scenario::ClockGuard,
};

/// The guard rule that refused, or would have refused, an execution (§4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardRule {
    /// CT1: `t(block) > wall + max_clock_drift_ms`.
    ClockAhead,
    /// CT5: a block that applies due work with `wall − t(block) > due_work_max_lag_ms`.
    StaleDueWork,
}

impl GuardRule {
    /// The reason of the executor's `Failed` answer.
    pub fn reason(self) -> &'static str {
        match self {
            Self::ClockAhead => "ClockAhead",
            Self::StaleDueWork => "StaleDueWork",
        }
    }
}

/// One decision of an honest executor's guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardEvent {
    /// Global time of the execution.
    pub at: Millis,
    /// The executing replica.
    pub replica: usize,
    /// Height of the block.
    pub height: u64,
    /// `AvailableBody` hash of the block.
    pub block_hash: Hash32,
    /// The rule that applies to the block at this wall time.
    pub rule: GuardRule,
    /// The execution was certified, so the rule was skipped and the block executed; otherwise
    /// the executor answered `Failed`.
    pub certified: bool,
}

/// The time of a committed block at its first honest commit (O-TIME).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertifiedTime {
    /// Instance.
    pub inst: usize,
    /// Height.
    pub height: u64,
    /// `AvailableBody` hash.
    pub block_hash: Hash32,
    /// Machine of the block's proposer (ground truth), if known.
    pub proposer: Option<usize>,
    /// Block time `t(block)` of the payload.
    pub t: u64,
    /// Global time of the first honest commit.
    pub at: Millis,
    /// `t − min honest wall` at `at` (negative when the block is in every honest clock's past).
    pub excess: i64,
}

/// The state of the clock guard model of a world.
#[derive(Clone, Debug)]
pub struct GuardState {
    /// `max_clock_drift_ms` (CT1, CT4).
    pub max_clock_drift_ms: Millis,
    /// `gov.due_work_max_lag_ms` (CT5).
    pub due_work_max_lag_ms: Millis,
    /// Current wall offset of every machine, relative to its monotonic clock.
    pub wall_offsets: Vec<i64>,
    /// Builder leads of every machine (cycled per build).
    leads: Vec<Vec<i64>>,
    /// Payloads built so far per machine.
    builds: Vec<usize>,
    /// Every guard decision of an honest executor, in order.
    pub events: Vec<GuardEvent>,
    /// Every committed block with a block time, in first-commit order.
    pub certified: Vec<CertifiedTime>,
    /// Due-work blocks already checked at their first genuine honest Prepare; later
    /// certified re-proposals and commits need not still be fresh (§4.5).
    first_due_prepares: BTreeSet<(usize, Hash32)>,
}

impl GuardState {
    /// The model of `config` for a world of `machines` machines.
    pub fn new(config: &ClockGuard, machines: usize) -> Self {
        let mut leads = vec![Vec::new(); machines];
        for (m, list) in &config.leads {
            if let Some(slot) = leads.get_mut(*m) {
                slot.clone_from(list);
            }
        }
        Self {
            max_clock_drift_ms: config.max_clock_drift_ms,
            due_work_max_lag_ms: config.due_work_max_lag_ms,
            wall_offsets: (0..machines)
                .map(|m| config.wall_offsets.get(m).copied().unwrap_or(0))
                .collect(),
            leads,
            builds: vec![0; machines],
            events: Vec::new(),
            certified: Vec::new(),
            first_due_prepares: BTreeSet::new(),
        }
    }

    /// The next builder lead of machine `m` (`0` for an honest builder, CT3).
    fn next_lead(&mut self, m: usize) -> i64 {
        let Some(list) = self.leads.get(m).filter(|list| !list.is_empty()) else {
            return 0;
        };
        let k = self.builds.get(m).copied().unwrap_or(0);
        if let Some(count) = self.builds.get_mut(m) {
            *count += 1;
        }
        list[k % list.len()]
    }

    /// The guard rule `block_time` violates at wall time `wall` (CT1 before CT5), if any.
    /// MS52 deletes CT1, MS65 deletes CT5, and MS66 removes CT1's drift allowance.
    pub fn violated(&self, t: u64, due: bool, wall: i64) -> Option<GuardRule> {
        let t = i64::try_from(t).unwrap_or(i64::MAX);
        let drift = if cfg!(sumeragi_mutation = "MS66") {
            0
        } else {
            i64::try_from(self.max_clock_drift_ms).unwrap_or(i64::MAX)
        };
        let lag = i64::try_from(self.due_work_max_lag_ms).unwrap_or(i64::MAX);
        if t > wall.saturating_add(drift) && !cfg!(sumeragi_mutation = "MS52") {
            return Some(GuardRule::ClockAhead);
        }
        (due && wall.saturating_sub(t) > lag && !cfg!(sumeragi_mutation = "MS65"))
            .then_some(GuardRule::StaleDueWork)
    }
}

impl World {
    /// Original local certified parent and transaction floors, without consulting a wall clock.
    pub(super) fn builder_clock_floor(&self, r: usize, height: u64, payload: &[u8]) -> Option<u64> {
        if self.clock_guard.is_none() || payload.is_empty() {
            return Some(0);
        }
        let replica = &self.replicas[r];
        let parent_time = if height <= 1 {
            0
        } else {
            let index = usize::try_from(height.checked_sub(2)?).ok()?;
            let (parent, _) = replica.store.get(index)?;
            if parent.header().height.checked_add(1) != Some(height) {
                return None;
            }
            block_time(parent.payload().as_slice())?
        };
        Some(
            parent_time
                .saturating_add(self.instances[replica.inst].params.block_time)
                .max(crate::sim::driver::payload_creation_floor(payload)?),
        )
    }

    pub(super) fn raise_block_time_floor(&self, payload: &mut [u8], floor: u64) {
        if self.clock_guard.is_some()
            && let Some(time) = block_time(payload)
        {
            payload[..TIME_RECORD].copy_from_slice(&encode_time(time.max(floor)));
        }
    }

    /// Deterministic parent/creation validation also applies to certified apply and replay.
    pub(in crate::sim) fn clock_payload_validity(
        &self,
        inst: usize,
        block: &AvailableBody,
    ) -> Option<ExecOutcome> {
        self.clock_guard.as_ref()?;
        let Some(time) = block_time(block.payload().as_slice()) else {
            return Some(ExecOutcome::Invalid);
        };
        let parent_time = if block.header().height <= 1 {
            0
        } else {
            let parent_height = block.header().height - 1;
            let parent = self
                .replicas
                .iter()
                .enumerate()
                .filter(|(_, replica)| replica.inst == inst)
                .find_map(|(r, _)| self.local_body(r, parent_height, &block.header().parent_hash));
            let Some(parent_time) =
                parent.and_then(|parent| block_time(parent.payload().as_slice()))
            else {
                return Some(ExecOutcome::Failed(
                    "original clock parent unavailable".to_owned(),
                ));
            };
            parent_time
        };
        let Some(creation_floor) =
            crate::sim::driver::payload_creation_floor(block.payload().as_slice())
        else {
            return Some(ExecOutcome::Invalid);
        };
        let floor = parent_time
            .saturating_add(self.instances[inst].params.block_time)
            .max(creation_floor);
        (time < floor).then_some(ExecOutcome::Invalid)
    }

    /// Complete only the original build, retaining its exact bytes through a wall backstep.
    pub(super) fn complete_payload_build(
        &mut self,
        r: usize,
        req: u64,
        payload: Option<crate::availability::PayloadBytes>,
    ) {
        if self.replicas[r].build_request != Some(req) {
            return;
        }
        let m = self.replicas[r].machine;
        if let Some(payload) = payload {
            if self.clock_guard.is_some()
                && !self.machines[m].byz
                && !cfg!(sumeragi_mutation = "MS69")
                && block_time(payload.as_slice())
                    .is_some_and(|time| self.wall_ms(m) < i64::try_from(time).unwrap_or(i64::MAX))
            {
                self.replicas[r].completed_build = Some((req, payload));
                self.schedule_completed_clock_ready(r, req);
                return;
            }
            self.publish_built_payload(r, req, Some(payload));
        } else {
            self.publish_built_payload(r, req, None);
        }
    }

    fn publish_built_payload(
        &mut self,
        r: usize,
        req: u64,
        payload: Option<crate::availability::PayloadBytes>,
    ) {
        let rep = &mut self.replicas[r];
        rep.build_request = None;
        rep.completed_build = None;
        let hash = crate::preimage::payload_hash(
            &self.hasher,
            payload.as_ref().map_or(&[], |payload| payload.as_slice()),
        );
        self.oracle.built.insert((rep.inst, rep.machine, hash));
        rep.host.deliver(Event::PayloadBuilt { req, payload });
        self.poll_host(r, self.now);
        self.refresh(r);
    }

    fn schedule_completed_clock_ready(&mut self, r: usize, req: u64) {
        let Some((owner, payload)) = self.replicas[r].completed_build.as_ref() else {
            return;
        };
        if *owner != req {
            return;
        }
        let floor =
            block_time(payload.as_slice()).expect("a completed guarded payload has a stamp");
        let when = self
            .clock_floor_global_time(r, floor)
            .max(self.now.saturating_add(1));
        self.schedule(
            when,
            Ev::CompletedClockReady {
                r,
                epoch: self.epoch_of(r),
                req,
            },
        );
    }

    pub(super) fn completed_clock_ready(&mut self, r: usize, req: u64) {
        let Some((_, payload)) = self.replicas[r]
            .completed_build
            .take_if(|(owner, _)| *owner == req)
        else {
            return;
        };
        self.complete_payload_build(r, req, Some(payload));
    }

    fn clock_floor_global_time(&self, r: usize, floor: u64) -> Millis {
        let m = self.replicas[r].machine;
        let offset = self
            .clock_guard
            .as_ref()
            .map_or(0, |guard| guard.wall_offsets[m]);
        let local =
            u64::try_from((i128::from(floor) - i128::from(offset)).clamp(0, i128::from(u64::MAX)))
                .expect("clamped clock floor fits u64");
        self.machines[m].clock.global_at(local)
    }

    /// Recheck fresh authored custody at the final synchronous proposal-signing boundary.
    /// Certified re-proposals do not pass through `PayloadAuthored` and stay exempt.
    pub(super) fn gate_authored_clock(&mut self, r: usize, event: Event) -> Option<Event> {
        if let Event::PayloadAuthored { req, body } = event {
            let m = self.replicas[r].machine;
            let current = self.replicas[r].host.core().is_some_and(|core| {
                let status = core.status();
                status.height == body.header().height && status.view == body.header().origin_view
            });
            if current
                && self.clock_guard.is_some()
                && !self.machines[m].byz
                && !cfg!(sumeragi_mutation = "MS70")
                && block_time(body.payload().as_slice())
                    .is_some_and(|time| self.wall_ms(m) < i64::try_from(time).unwrap_or(i64::MAX))
            {
                self.replicas[r].authored_clock = Some((req, body));
                self.schedule_authored_clock_ready(r, req);
                None
            } else {
                Some(Event::PayloadAuthored { req, body })
            }
        } else {
            Some(event)
        }
    }

    fn schedule_authored_clock_ready(&mut self, r: usize, req: u64) {
        let Some((owner, body)) = self.replicas[r].authored_clock.as_ref() else {
            return;
        };
        if *owner != req {
            return;
        }
        let floor = block_time(body.payload().as_slice())
            .expect("guarded original authored body has a stamp");
        let when = self
            .clock_floor_global_time(r, floor)
            .max(self.now.saturating_add(1));
        self.schedule(
            when,
            Ev::AuthoredClockReady {
                r,
                epoch: self.epoch_of(r),
                req,
            },
        );
    }

    pub(super) fn authored_clock_ready(&mut self, r: usize, req: u64) {
        let Some((_, body)) = self.replicas[r]
            .authored_clock
            .take_if(|(owner, _)| *owner == req)
        else {
            return;
        };
        self.replicas[r]
            .host
            .deliver(Event::PayloadAuthored { req, body });
        self.poll_host(r, self.now);
        self.refresh(r);
    }

    pub(super) fn schedule_clock_payload_ready(
        &mut self,
        r: usize,
        req: u64,
        floor: u64,
        earliest: Millis,
    ) {
        let when = self
            .clock_floor_global_time(r, floor)
            .max(earliest)
            .max(self.now.saturating_add(1));
        self.schedule(
            when,
            Ev::ClockReady {
                r,
                epoch: self.epoch_of(r),
                req,
                floor,
            },
        );
    }

    pub(super) fn clock_payload_ready(&mut self, r: usize, req: u64, floor: u64) {
        if self.replicas[r].pending_ready != Some(req)
            || self.replicas[r].clock_ready != Some((req, floor))
        {
            return;
        }
        let m = self.replicas[r].machine;
        if self.wall_ms(m) < i64::try_from(floor).unwrap_or(i64::MAX) {
            self.schedule_clock_payload_ready(r, req, floor, self.now.saturating_add(1));
            return;
        }
        self.replicas[r].pending_ready = None;
        self.replicas[r].clock_ready = None;
        self.replicas[r].host.deliver(Event::PayloadReady { req });
        self.poll_host(r, self.now);
        self.refresh(r);
    }

    /// O-TIME's lower bound is checked once per due-work block at its first genuine honest
    /// Prepare, not at a later certified re-proposal or commit, which may be arbitrarily late.
    pub(in crate::sim) fn check_first_due_prepare(
        &mut self,
        machine: usize,
        slot: crate::sim::crypto::SigSlot,
        block_hash: Hash32,
    ) {
        if self.clock_guard.is_none() {
            return;
        }
        let Some(&inst) = self.inst_by_id.get(&slot.instance) else {
            return;
        };
        let Some(replica) = self.machines[machine].replicas[inst] else {
            return;
        };
        let Some(block) = self.local_body(replica, slot.height, &block_hash) else {
            return self.fail("O-TIME: first honest Prepare has no original body".to_owned());
        };
        let payload = block.payload().as_slice();
        let Some(t) = block_time(payload).filter(|_| payload_due(payload)) else {
            return;
        };
        let wall = self.wall_ms(machine);
        let guard = self.clock_guard.as_mut().expect("guarded world");
        if !guard.first_due_prepares.insert((inst, block_hash)) {
            return;
        }
        let lag = i64::try_from(guard.due_work_max_lag_ms).unwrap_or(i64::MAX);
        let age = wall.saturating_sub(i64::try_from(t).unwrap_or(i64::MAX));
        if age > lag {
            self.fail(format!(
                "O-TIME: first honest Prepare of due-work block at instance {inst} height {} \
                 has age {age} ms > due_work_max_lag_ms = {lag} ms",
                slot.height,
            ));
        }
    }

    /// Machine `m`'s wall clock (ms): its monotonic clock plus its wall offset (§4.5).
    pub fn wall_ms(&self, m: usize) -> i64 {
        let local = i64::try_from(self.machines[m].clock.local(self.now)).unwrap_or(i64::MAX);
        let offset = self
            .clock_guard
            .as_ref()
            .and_then(|guard| guard.wall_offsets.get(m).copied())
            .unwrap_or(0);
        local.saturating_add(offset)
    }

    /// Step machine `m`'s wall clock to `offset` ms from its monotonic clock (an NTP step; the
    /// core's monotonic clock is unaffected). No effect without a clock guard.
    pub fn set_wall_offset(&mut self, m: usize, offset: i64) {
        if let Some(slot) = self
            .clock_guard
            .as_mut()
            .and_then(|guard| guard.wall_offsets.get_mut(m))
        {
            *slot = offset;
            self.trace(m, format!("wall clock offset {offset} ms"));
            for r in 0..self.replicas.len() {
                if self.replicas[r].machine == m
                    && let Some((req, _)) = self.replicas[r].authored_clock.as_ref()
                {
                    self.schedule_authored_clock_ready(r, *req);
                }
                if self.replicas[r].machine == m
                    && let Some((req, _)) = self.replicas[r].completed_build.as_ref()
                {
                    self.schedule_completed_clock_ready(r, *req);
                }
                if self.replicas[r].machine == m
                    && let Some((req, floor)) = self.replicas[r].clock_ready
                {
                    self.schedule_clock_payload_ready(r, req, floor, self.now.saturating_add(1));
                }
            }
        }
    }

    /// The smallest wall clock of the honest machines.
    pub fn min_honest_wall(&self) -> Option<i64> {
        (0..self.machines.len())
            .filter(|m| !self.machines[*m].byz)
            .map(|m| self.wall_ms(m))
            .min()
    }

    /// CT3: the payload builder of machine `m` stamps a non-empty payload with its block time,
    /// `wall + lead` (an honest builder's lead is 0, so its block time never exceeds its wall
    /// clock). No effect without a clock guard.
    pub(super) fn stamp_block_time(&mut self, m: usize, payload: &mut Vec<u8>) {
        if payload.is_empty() {
            return;
        }
        let wall = self.wall_ms(m);
        let Some(guard) = self.clock_guard.as_mut() else {
            return;
        };
        let t = wall.saturating_add(guard.next_lead(m)).max(0);
        let stamp = encode_time(u64::try_from(t).unwrap_or(0));
        payload.splice(0..0, stamp);
    }

    /// The block-time record's share of a builder's byte limit (0 without a clock guard).
    pub(super) fn block_time_bytes(&self) -> u64 {
        if self.clock_guard.is_some() {
            u64::try_from(TIME_RECORD).unwrap_or(u64::MAX)
        } else {
            0
        }
    }

    /// CT1 and CT5 (§4.5) for an `Execute` of `block` by replica `r`: the `Failed` answer of an
    /// honest executor that refuses an uncertified execution. A certified execution skips both
    /// rules (recorded as exempt). Byzantine executors, blocks without a block time and worlds
    /// without a clock guard are never refused.
    pub(super) fn clock_guard_refusal(
        &mut self,
        r: usize,
        block: &AvailableBody,
        bh: &Hash32,
        certified: bool,
    ) -> Option<ExecOutcome> {
        let m = self.replicas[r].machine;
        if self.machines[m].byz {
            return None;
        }
        let payload = block.payload().as_slice();
        let t = block_time(payload)?;
        let wall = self.wall_ms(m);
        let now = self.now;
        let guard = self.clock_guard.as_mut()?;
        let rule = guard.violated(t, payload_due(payload), wall)?;
        guard.events.push(GuardEvent {
            at: now,
            replica: r,
            height: block.header().height,
            block_hash: *bh,
            rule,
            certified,
        });
        (!certified).then(|| ExecOutcome::Failed(rule.reason().to_owned()))
    }

    /// O-TIME (§13.2, §4.5 "Upper bound") at the first honest commit of `block`: its time
    /// exceeds no honest wall clock by more than `2·max_clock_drift_ms`.
    pub(in crate::sim) fn check_certified_time(
        &mut self,
        inst: usize,
        block: &AvailableBody,
        block_hash: Hash32,
        proposer: Option<usize>,
    ) {
        let Some(t) = block_time(block.payload().as_slice()) else {
            return;
        };
        let Some(min_wall) = self.min_honest_wall() else {
            return;
        };
        let now = self.now;
        let height = block.header().height;
        let Some(guard) = self.clock_guard.as_mut() else {
            return;
        };
        let excess = i64::try_from(t)
            .unwrap_or(i64::MAX)
            .saturating_sub(min_wall);
        guard.certified.push(CertifiedTime {
            inst,
            height,
            block_hash,
            proposer,
            t,
            at: now,
            excess,
        });
        let bound = i64::try_from(guard.max_clock_drift_ms.saturating_mul(2)).unwrap_or(i64::MAX);
        if excess > bound {
            self.fail(format!(
                "O-TIME: instance {inst} height {height} certified block time {t} exceeds the \
                 smallest honest wall clock {min_wall} by {excess} ms > 2·max_clock_drift_ms = \
                 {bound} ms"
            ));
        }
    }
}

#[cfg(test)]
mod tests;
