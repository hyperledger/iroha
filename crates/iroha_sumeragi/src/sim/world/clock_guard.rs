//! The application clock guard of the simulator's toy application (§4.5): per-machine wall
//! clocks, block times stamped by the payload builders (CT3), the executor rules CT1 and CT5 for
//! executions with `certified = false`, and the oracle O-TIME (§13.2): the time of every
//! committed block exceeds every honest wall clock by at most `2·max_clock_drift_ms`.
//!
//! The guard is application-level (the node driver's executor, `iroha_core`); the sans-IO core
//! only emits the `certified` flag of `Action::Execute`. It is modelled here so that the
//! deterministic simulator can show liveness under skewed honest clocks and the certified-time
//! bound, and so that its mutations (MS51, MS52) are killed by named simulator tests (§13.4).
//!
//! TODO: the block time is the builder's stamp `wall + lead`, not the canonical
//! `max(parent + cadence, …)` of the real application, so a committed post-dated block does not
//! raise the next block's time and the CT3 builder wait is never exercised here (the Core entry
//! SC6 covers CT3). Model the canonical floor, its deterministic validity check and the
//! honest builder's wait (`EMPTY`, then `PayloadReady` once its wall clock reaches the floor).

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
    /// MS52 deletes CT1.
    pub fn violated(&self, t: u64, due: bool, wall: i64) -> Option<GuardRule> {
        let t = i64::try_from(t).unwrap_or(i64::MAX);
        let drift = i64::try_from(self.max_clock_drift_ms).unwrap_or(i64::MAX);
        let lag = i64::try_from(self.due_work_max_lag_ms).unwrap_or(i64::MAX);
        if t > wall.saturating_add(drift) && !cfg!(sumeragi_mutation = "MS52") {
            return Some(GuardRule::ClockAhead);
        }
        (due && wall.saturating_sub(t) > lag).then_some(GuardRule::StaleDueWork)
    }
}

impl World {
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
