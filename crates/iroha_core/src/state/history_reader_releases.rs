//! Original reader notices retained through State views and enclosing physical owners.

use super::*;
use iroha_allocation::release::DeferredReleaseBatch;

impl State {
    /// Original physical history pools whose refunds must outlive an outer fence.
    pub(crate) fn history_allocation_budgets(
        &self,
    ) -> (
        iroha_allocation::AllocationBudget,
        iroha_allocation::AllocationBudget,
    ) {
        (
            self.block_hashes.budget.clone(),
            self.transactions.budget.clone(),
        )
    }
}

/// Same-source view readers whose actual unlocks notify only after this owner drops.
/// Physical guards never remain held between calls; no caller-selected source is accepted.
pub(crate) struct StateViewReleases<'state> {
    state: &'state State,
    pub(super) lifecycle: LaneLifecycleReleases<'state>,
}

/// Original notices detached from a State borrow before an authenticated State swap.
/// This is only cleanup custody; it grants no read or publication authority.
#[must_use = "retain original read notices through every enclosing physical owner"]
pub(crate) struct StateViewRetirement {
    _indexes: [DeferredReleaseBatch; 12],
    _hashes: Option<DeferredReleaseBatch>,
    _membership: DeferredReleaseBatch,
    _world: view_acquisition::WorldReadReleases,
}

impl<'state> StateViewReleases<'state> {
    /// Bind all view-release sources to this exact State before taking outer fences.
    pub(crate) fn new(state: &'state State) -> Self {
        Self {
            state,
            lifecycle: LaneLifecycleReleases::new(state),
        }
    }

    /// The original State; this reference does not borrow mutable release custody.
    pub(crate) fn state(&self) -> &'state State {
        self.state
    }

    /// Attempt one original-State observation, retaining every actual reader unlock.
    pub(crate) fn try_view_once(&mut self) -> Result<StateView<'state>, StateViewError> {
        self.state
            .try_view_once_with_index_releases(&mut self.lifecycle)
    }

    /// Hash the complete current State without delivering notices beneath its writers.
    #[cfg(test)]
    pub(super) fn lane_execution_state_hash(
        &mut self,
    ) -> Result<HashOf<BlockHeader>, crate::snapshot::SnapshotCaptureError> {
        crate::snapshot::canonical_state_snapshot_hash_with_releases(self)
            .map(HashOf::<BlockHeader>::from_untyped_unchecked)
    }

    /// End read authority while retaining all original notices through later mutation.
    pub(crate) fn into_retirement(self) -> StateViewRetirement {
        let LaneLifecycleReleases {
            hashes,
            membership,
            world,
            prepared_cache,
            crypto,
            nexus,
            header,
            manifests,
            privacy,
            commitments,
            confidential_compute,
            receipt_cursors,
            shard_cursors,
            pin_intents,
            hydrated,
        } = self.lifecycle;
        StateViewRetirement {
            _indexes: [
                prepared_cache.into_releases(),
                crypto.into_releases(),
                nexus.into_releases(),
                header.into_releases(),
                manifests.into_releases(),
                privacy.into_releases(),
                commitments.into_releases(),
                confidential_compute.into_releases(),
                receipt_cursors.into_releases(),
                shard_cursors.into_releases(),
                pin_intents.into_releases(),
                hydrated.into_releases(),
            ],
            _hashes: hashes,
            _membership: membership,
            _world: world,
        }
    }
}

impl BlockHashes {
    /// Only an ordinary original map has an active-reader release source.
    pub(super) fn reader_release_batch(&self) -> Option<DeferredReleaseBatch> {
        self.map().map(BlockHashMap::reader_release_batch)
    }

    /// Synchronously retry the sole reader kernel with caller-owned notifications.
    pub(super) fn view_retaining(
        &self,
        releases: &mut Option<DeferredReleaseBatch>,
    ) -> BlockHashesView<'_> {
        loop {
            match self.try_view_retaining(releases) {
                Ok(view) => return view,
                Err(StateViewError::Busy(_)) => std::thread::yield_now(),
                Err(error) => panic!("original hash reader refused: {error}"),
            }
        }
    }

    /// Probe the exact original map while retaining its actual active-lock release.
    pub(super) fn try_view_retaining(
        &self,
        releases: &mut Option<DeferredReleaseBatch>,
    ) -> Result<BlockHashesView<'_>, StateViewError> {
        let inner = match (&self.inner, releases.as_mut()) {
            (BlockHashStorage::Owned(map), Some(releases)) => {
                let wait = map.observe_reader_release();
                BlockHashesViewInner::Owned(map.try_read_retaining(releases).map_err(|error| {
                    match error {
                        concread::bptree::OwnedWriteError::Busy => StateViewError::Busy(wait),
                        concread::bptree::OwnedWriteError::Poisoned => StateViewError::Poisoned,
                        concread::bptree::OwnedWriteError::Changed => StateViewError::Changed,
                    }
                })?)
            }
            (BlockHashStorage::EmergencyFastMapped(mapping), None) => {
                BlockHashesViewInner::Mapped(mapped_block_hashes(mapping))
            }
            (BlockHashStorage::EmergencyFastEmpty, None) => BlockHashesViewInner::Mapped(&[]),
            _ => return Err(StateViewError::Changed),
        };
        Ok(BlockHashesView { inner })
    }
}

#[cfg(test)]
#[path = "history_reader_release_tests.rs"]
mod tests;
