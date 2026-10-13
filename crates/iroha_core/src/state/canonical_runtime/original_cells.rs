//! Actual committed current/undo values joined to the original runtime writers.
//!
//! Ordinary Cell acquisition clears undo and replacement acquisition consumes it.
//! Capture therefore precedes overlay initialization. Each pair is authenticated
//! by the original MV publication identity; the later joint writer acquisition
//! proves that none of the four sources changed, even if a direct MV write did
//! not increment State's generation. This remains an input owner, not a complete
//! State commitment, finalized anchor or permission to enable execution proofs.
//! TODO: consume these exact pairs with complete World/membership/policy/history
//! capture, funded canonical codecs, atomic publication and verified recovery.

use super::*;
use mv::cell::{CommittedCellReadError, CommittedCellView};

/// Four original committed pairs; only binding to actual writers joins their cuts.
pub(in crate::state) struct OriginalRuntimeCells<'state> {
    source: &'state State,
    generation: u64,
    commit_topology: CommittedCellView<'state, Vec<PeerId>>,
    prev_commit_topology: CommittedCellView<'state, Vec<PeerId>>,
    canonical_runtime: CommittedCellView<'state, SnapshotNexusRuntime>,
    native_execution_tip: CommittedCellView<'state, Option<NativeExecutionTip>>,
}

/// No value, copied digest or caller-supplied row list can construct this join.
pub(in crate::state) struct BoundOriginalRuntimeCells<'state> {
    // Release every actual World/membership/Cell writer before any epoch reader
    // can drop, reclaim a payload or dispatch a pool callback on error/unwind.
    acquired: AcquiredRuntimeBlock<'state>,
    committed: OriginalRuntimeCells<'state>,
}

/// A failed original-source join grants no execution or publication authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(in crate::state) enum OriginalRuntimeJoinError {
    /// Equal values from another State are not the original source.
    #[error("committed runtime cells belong to a different State")]
    ForeignState,
    /// A coordinated publication or one original current/undo identity changed.
    #[error("committed runtime cell source changed before joint acquisition")]
    SourceChanged,
}

impl State {
    /// Retain actual committed values before any block clears their undo images.
    ///
    /// `None` is a concurrent State publication. A successful result still must
    /// bind to an actual joint acquisition: generation checks alone do not cover
    /// direct MV writes. No payload clone, new MV successor or root is produced.
    pub(in crate::state) fn capture_committed_runtime_cells_once(
        &self,
    ) -> Result<Option<OriginalRuntimeCells<'_>>, CommittedCellReadError> {
        let generation = self.state_view_generation();
        if generation & 1 != 0 {
            return Ok(None);
        }
        let captured = OriginalRuntimeCells {
            source: self,
            generation,
            commit_topology: self.commit_topology.try_committed_view()?,
            prev_commit_topology: self.prev_commit_topology.try_committed_view()?,
            canonical_runtime: self.canonical_runtime.try_committed_view()?,
            native_execution_tip: self.native_execution_tip.try_committed_view()?,
        };
        if !is_stable_state_view_generation(generation, self.state_view_generation()) {
            return Ok(None);
        }
        Ok(Some(captured))
    }
}

impl<'state> OriginalRuntimeCells<'state> {
    /// Consume the original four pairs and actual joint acquisition together.
    /// The result retains the original writer mode; a committed pair does not
    /// claim to be the already-reverted execution prestate of a replacement.
    pub(in crate::state) fn bind(
        self,
        acquired: AcquiredRuntimeBlock<'state>,
    ) -> Result<BoundOriginalRuntimeCells<'state>, OriginalRuntimeJoinError> {
        let bound = BoundOriginalRuntimeCells {
            acquired,
            committed: self,
        };
        if !bound.acquired.belongs_to(bound.committed.source) {
            return Err(OriginalRuntimeJoinError::ForeignState);
        }
        let fields = bound.acquired.fields();
        let committed = &bound.committed;
        if !is_stable_state_view_generation(
            committed.generation,
            committed.source.state_view_generation(),
        ) || !committed
            .commit_topology
            .matches_block_source(&fields.commit_topology)
            || !committed
                .prev_commit_topology
                .matches_block_source(&fields.prev_commit_topology)
            || !committed
                .canonical_runtime
                .matches_block_source(&fields.canonical_runtime)
            || !committed
                .native_execution_tip
                .matches_block_source(&fields.native_execution_tip)
        {
            return Err(OriginalRuntimeJoinError::SourceChanged);
        }
        Ok(bound)
    }
}

impl<'state> BoundOriginalRuntimeCells<'state> {
    /// Borrow both original published committee values; undo absence stays explicit.
    pub(in crate::state) fn commit_topology(&self) -> (&Vec<PeerId>, &Option<Vec<PeerId>>) {
        (
            self.committed.commit_topology.current(),
            self.committed.commit_topology.undo(),
        )
    }

    /// Borrow both original previous-committee values under the same joint owner.
    pub(in crate::state) fn prev_commit_topology(&self) -> (&Vec<PeerId>, &Option<Vec<PeerId>>) {
        (
            self.committed.prev_commit_topology.current(),
            self.committed.prev_commit_topology.undo(),
        )
    }

    /// Borrow the complete typed runtime records, including every retained descendant.
    pub(in crate::state) fn canonical_runtime(
        &self,
    ) -> (&SnapshotNexusRuntime, &Option<SnapshotNexusRuntime>) {
        (
            self.committed.canonical_runtime.current(),
            self.committed.canonical_runtime.undo(),
        )
    }

    /// Borrow exact current/undo native tips without decoding claims as authority.
    #[expect(
        clippy::option_option,
        reason = "MV stores an optional native tip with an independent optional undo; unchanged, genesis absence, and a prior tip must remain distinct."
    )]
    pub(in crate::state) fn native_execution_tip(
        &self,
    ) -> (
        &Option<NativeExecutionTip>,
        &Option<Option<NativeExecutionTip>>,
    ) {
        (
            self.committed.native_execution_tip.current(),
            self.committed.native_execution_tip.undo(),
        )
    }

    /// Borrow the same acquired World, membership, history and runtime originals.
    pub(in crate::state) fn acquired(&self) -> &AcquiredRuntimeBlockFields<'state> {
        self.acquired.fields()
    }
}

#[cfg(test)]
#[path = "original_cells_tests.rs"]
mod tests;
