//! Fair bounded observation of the destination-progress liability gate.

use std::ops::Bound::{Excluded, Unbounded};

use iroha_core::{smartcontracts::isi::sccp::store, state::WorldReadOnly};
use iroha_data_model::{bridge::SccpNetworkV1, sccp::registry::SccpRouteActivationV1};
use mv::storage::StorageReadOnly as _;

/// Maximum route revisions and pending generations observed per poll.
const PAGE: usize = 64;

/// Local fairness cursors; these observations never authorize consensus effects.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Cursor {
    active_revision: Option<u32>,
    revision_after: u32,
    generation_after: u64,
}

impl Cursor {
    /// Read one original parent without cloning its route or generation history.
    pub(super) fn lagging(
        &mut self,
        world: &impl WorldReadOnly,
        network: SccpNetworkV1,
        source_time_ms: u64,
    ) -> bool {
        let Some(route) = store::routes::get(world, &network) else {
            *self = Self::default();
            return false;
        };
        let cached_active = self.active_revision.is_some_and(|revision| {
            route
                .revisions
                .get(&revision)
                .is_some_and(|record| record.activation != SccpRouteActivationV1::Retired)
        });
        if !cached_active {
            self.active_revision = None;
            let after = self.revision_after;
            self.observe_revisions(route.revisions.range((Excluded(after), Unbounded)).map(
                |(revision, record)| {
                    (
                        *revision,
                        record.activation != SccpRouteActivationV1::Retired,
                    )
                },
            ));
        }
        if self.active_revision.is_none() {
            return false;
        }
        let after = self.generation_after;
        self.observe_generations(
            world
                .sccp_destination_pending_generations()
                .range::<u64>((Excluded(after), Unbounded))
                .map(|(id, ())| {
                    (
                        *id,
                        store::committee_generations::get(world, id)
                            .filter(|record| {
                                record.end.is_some() && record.dest_cleared_lc.is_none()
                            })
                            .map(|record| record.deadline_ms),
                    )
                }),
            source_time_ms,
        )
    }

    fn observe_revisions(&mut self, rows: impl Iterator<Item = (u32, bool)>) {
        let mut count = 0;
        for (revision, active) in rows.take(PAGE) {
            count += 1;
            self.revision_after = revision;
            if active {
                self.active_revision = Some(revision);
                return;
            }
        }
        if count < PAGE {
            self.revision_after = 0;
        }
    }

    fn observe_generations(
        &mut self,
        rows: impl Iterator<Item = (u64, Option<u64>)>,
        source_time_ms: u64,
    ) -> bool {
        let mut count = 0;
        let mut lagging = false;
        for (generation, deadline) in rows.take(PAGE) {
            count += 1;
            self.generation_after = generation;
            // L5 requires a checkpoint strictly after the deadline, including equality here.
            lagging |= deadline.is_some_and(|deadline| source_time_ms <= deadline);
        }
        if count < PAGE {
            self.generation_after = 0;
        }
        lagging
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn bounded_pages_reach_later_revisions_and_pending_deadlines_without_history_clones() {
        let mut cursor = Cursor::default();
        let visited = Cell::new(0);
        cursor.observe_revisions((1..=130).map(|id| {
            visited.set(visited.get() + 1);
            (id, id == 100)
        }));
        assert_eq!(visited.get(), 64);
        assert_eq!(cursor.active_revision, None);
        assert_eq!(cursor.revision_after, 64);
        cursor.observe_revisions((cursor.revision_after + 1..=130).map(|id| (id, id == 100)));
        assert_eq!(cursor.active_revision, Some(100));
        let later = |start| (start..=130).map(|id| (id, Some(if id == 100 { 500 } else { 1 })));
        assert!(!cursor.observe_generations(later(1), 500));
        assert_eq!(cursor.generation_after, 64);
        assert!(cursor.observe_generations(later(cursor.generation_after + 1), 500));
        assert_eq!(cursor.generation_after, 128);
        assert!(!cursor.observe_generations(later(cursor.generation_after + 1), 500));
        assert_eq!(cursor.generation_after, 0);
        assert!(!cursor.observe_generations([(1, Some(500))].into_iter(), 501));
        assert!(cursor.observe_generations([(1, Some(500))].into_iter(), 500));
        assert!(!cursor.observe_generations([(1, None)].into_iter(), 0));
        cursor.observe_revisions(std::iter::empty());
        assert_eq!(cursor.revision_after, 0);
    }
}
