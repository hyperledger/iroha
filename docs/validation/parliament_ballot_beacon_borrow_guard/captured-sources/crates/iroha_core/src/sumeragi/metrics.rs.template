//! Prometheus telemetry of the node's Sumeragi instances (`specs/telemetry.md`, "Sumeragi
//! consensus metrics").
//!
//! One [`InstanceMetrics`] records one instance — the global instance or a lane instance —
//! through its [`InstanceSeries`] (`sumeragi_*{lane}`). The driver's event loop feeds it:
//!
//! - every status snapshot it publishes ([`InstanceMetrics::observe`]): the gauges and the halt
//!   flag, and the counters derived from the transitions between snapshots — committed blocks
//!   (`committed_height` advances), view changes (the view advances at a height, or a height is
//!   entered at a later view) and the drops of the driver's bounded queues;
//! - every action of the core it routes ([`InstanceMetrics::action`]): the node's own timeout
//!   votes (once per height and view), catch-up `SyncRequest`s and `FetchPayload`s, the first
//!   `Execute` of a height (the node holds the round's proposal with its body, where §9.2 also
//!   starts timing a committing view) and the `CommitBlock` of the height (its CommitQC);
//! - every `BlockApplied` it hands to the core ([`InstanceMetrics::applied`]).
//!
//! Recording only reads what the core and the driver produce anyway: it never feeds back into
//! either, never blocks, and retains at most [`MAX_TIMED_HEIGHTS`] timestamps of each kind. Times
//! are the driver's local clock, so the latencies are node-local observations.

use std::collections::BTreeMap;

use iroha_data_model::sumeragi::SumeragiHaltReason;
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::{
    api::{Action, CoreStatus},
    message::WireMessage,
    types::Millis,
};
use iroha_telemetry::metrics::sumeragi::{
    DropQueue, FetchKind, GLOBAL_LANE, InstanceGauges, InstanceSeries,
};

use super::driver::Backlog;
use crate::telemetry::StateTelemetry;

/// Most heights whose first-execution or CommitQC time is retained at once (per kind).
///
/// Applying runs at most two heights behind the CommitQC (§10.2), and a node executes the
/// proposals of its current height only, so the bound is never reached in operation; it keeps
/// the recorder bounded whatever the input.
pub const MAX_TIMED_HEIGHTS: usize = 64;

/// The instance a recorder reports for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricsInstance {
    /// The global instance.
    Global,
    /// The instance of a lane (`specs/sumeragi_lanes.md` §4.1).
    Lane(LaneId),
}

impl MetricsInstance {
    /// The `lane` label value: `global`, or the decimal lane id.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Global => GLOBAL_LANE.to_owned(),
            Self::Lane(lane) => lane.as_u32().to_string(),
        }
    }
}

/// What the recorder remembers of the previous status snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    height: u64,
    view: u64,
    committed_height: u64,
    dropped: [u64; DropQueue::ALL.len()],
}

/// Records the telemetry of one Sumeragi instance (see the module documentation).
#[derive(Debug)]
pub struct InstanceMetrics {
    series: InstanceSeries,
    seen: Option<Seen>,
    /// Height → local time of its first `Execute`.
    executed: BTreeMap<u64, Millis>,
    /// Height → local time of its `CommitBlock`.
    committed: BTreeMap<u64, Millis>,
    /// `(height, view)` of the latest own timeout vote counted.
    last_timeout: Option<(u64, u64)>,
}

impl InstanceMetrics {
    /// A recorder writing to `series`.
    #[must_use]
    pub fn new(series: InstanceSeries) -> Self {
        Self {
            series,
            seen: None,
            executed: BTreeMap::new(),
            committed: BTreeMap::new(),
            last_timeout: None,
        }
    }

    /// The recorder of `instance` in the node's registry, or `None` while telemetry is
    /// disabled.
    #[must_use]
    pub fn for_node(telemetry: &StateTelemetry, instance: MetricsInstance) -> Option<Self> {
        telemetry
            .is_enabled()
            .then(|| Self::new(telemetry.sumeragi_instance(&instance.label())))
    }

    /// Remove the series of `instance` from the node's registry (a retired lane).
    pub fn retire(telemetry: &StateTelemetry, instance: MetricsInstance) {
        telemetry.remove_sumeragi_instance(&instance.label());
    }

    /// The series the recorder writes (shared, for the driver's stop report).
    #[must_use]
    pub fn series(&self) -> &InstanceSeries {
        &self.series
    }

    /// A status snapshot the driver publishes, with the driver's queues at the same step.
    ///
    /// The first snapshot is the baseline: the heights and drops the instance started from
    /// are not counted.
    pub fn observe(&mut self, status: &CoreStatus, backlog: &Backlog) {
        self.series.set(&InstanceGauges {
            round_height: status.height,
            round_view: status.view,
            round_stage: status.stage,
            pacemaker_level: status.level,
            pacemaker_start_level: status.start_level,
            retransmit_interval_ms: status.t_retx,
            committed_height: status.committed_height,
            applied_height: status.applied_height,
            awaiting_configuration: status.awaiting,
            signer_present: status.signer.is_some(),
            abstaining: status.abstaining,
            unanchored: status.unanchored,
        });
        self.series
            .set_halted(status.halted.map(super::node::halt_reason_dto));
        let dropped = [
            backlog.ingress_dropped,
            backlog.held_dropped,
            backlog.serve_dropped,
        ];
        if let Some(seen) = self.seen {
            self.series.add_commits(
                status
                    .committed_height
                    .saturating_sub(seen.committed_height),
            );
            let views = match status.height.cmp(&seen.height) {
                core::cmp::Ordering::Equal => status.view.saturating_sub(seen.view),
                // A height entered at a later view advanced through those views there.
                core::cmp::Ordering::Greater => status.view,
                core::cmp::Ordering::Less => 0,
            };
            self.series.add_view_changes(views);
            for ((queue, now), before) in DropQueue::ALL.into_iter().zip(dropped).zip(seen.dropped)
            {
                self.series.add_dropped(queue, now.saturating_sub(before));
            }
        }
        self.seen = Some(Seen {
            height: status.height,
            view: status.view,
            committed_height: status.committed_height,
            dropped,
        });
    }

    /// An action of the core at local time `now`, as the driver routes it.
    pub fn action(&mut self, now: Millis, action: &Action) {
        match action {
            Action::Execute { block, .. } => {
                self.executed.entry(block.header().height).or_insert(now);
                bound(&mut self.executed);
            }
            Action::CommitBlock { commit_qc, .. } => {
                let height = commit_qc.height;
                if let Some(start) = self.executed.remove(&height) {
                    self.series
                        .observe_commit_latency_ms(now.saturating_sub(start));
                }
                self.executed.retain(|executed, _| *executed > height);
                self.committed.insert(height, now);
                bound(&mut self.committed);
            }
            Action::Send { msg, .. } | Action::Broadcast { msg, .. } => match msg {
                WireMessage::Timeout(vote) => {
                    let key = (vote.height, vote.view);
                    // A timeout vote is re-sent unchanged at every rebroadcast (§6.6).
                    if self.last_timeout.is_none_or(|last| key > last) {
                        self.last_timeout = Some(key);
                        self.series.inc_timeout_votes();
                    }
                }
                WireMessage::SyncRequest(_) => self.series.inc_fetch(FetchKind::Sync),
                _ => {}
            },
            Action::FetchPayload { .. } => self.series.inc_fetch(FetchKind::Body),
            _ => {}
        }
    }

    /// The block of `height` was applied at local time `now` (`BlockApplied` for the core).
    pub fn applied(&mut self, now: Millis, height: u64) {
        if let Some(committed) = self.committed.remove(&height) {
            self.series
                .observe_apply_latency_ms(now.saturating_sub(committed));
        }
        self.committed.retain(|committed, _| *committed > height);
    }

    /// The instance stopped with a stopped worker (reported as `DriverAnomaly`).
    pub fn stopped(series: &InstanceSeries) {
        series.set_halted(Some(SumeragiHaltReason::DriverAnomaly));
    }
}

/// Keep at most [`MAX_TIMED_HEIGHTS`] entries, dropping the lowest heights.
fn bound(times: &mut BTreeMap<u64, Millis>) {
    while times.len() > MAX_TIMED_HEIGHTS {
        times.pop_first();
    }
}

#[cfg(test)]
mod tests;
