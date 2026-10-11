//! Exact predecessor publication of the original shared hash generation.

use super::*;
use concread::bptree::{BptreeMapPreparedCommit, OwnedWriteError};

/// Exact original successor and both physical publication locks.
/// Field order releases locks before notification or caller installation custody.
pub(crate) struct PreparedBlockHashes<'target, Installation> {
    owner: NativeLaneStateOwner,
    prepared: iroha_allocation::release::ReleaseGuard<
        'target,
        BptreeMapPreparedCommit<'target, usize, HashOf<BlockHeader>, BlockHashMode>,
    >,
    mode: mv::BlockMode,
    visible_len: usize,
    height: usize,
    committed_height: &'target AtomicUsize,
    installation: Installation,
    preflight_release: Option<iroha_allocation::release::DeferredRelease>,
}
/// Original abort notifications and resources after the hash writer unlocks.
pub(crate) struct AbortedBlockHashes<Installation> {
    _owner: NativeLaneStateOwner,
    _release: [iroha_allocation::release::DeferredRelease; 2],
    _installation: Installation,
    _preflight_release: Option<iroha_allocation::release::DeferredRelease>,
}

#[path = "retained_hash_slot.rs"]
pub(super) mod retained_hash_slot;
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
use retained_hash_slot::RetainedHashSlot;

fn refusal<E>(
    error: OwnedWriteError,
    wait: iroha_allocation::release::ReleaseWait,
) -> mv::PublicationPreparationError<E> {
    match error {
        OwnedWriteError::Changed => mv::PublicationPreparationError::Changed,
        OwnedWriteError::Poisoned => mv::PublicationPreparationError::Poisoned,
        OwnedWriteError::Busy => mv::PublicationPreparationError::after_failed_acquisition(wait),
    }
}
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
impl DetachedBlockHashes {
    /// Standalone fixture adapter to the same caller-owned preparation kernel.
    /// Aggregate production callers retain the slot before invoking admission.
    pub(crate) fn try_prepare_publication<'target, Installation, E>(
        self,
        target: &'target BlockHashes,
        admit: impl FnOnce(&Self, &BlockHashes) -> Result<Installation, E>,
    ) -> Result<
        PreparedBlockHashes<'target, Installation>,
        (
            Self,
            mv::PublicationPreparationError<E>,
            RetainedHashSlot<'target, Installation>,
        ),
    > {
        let mut slot = RetainedHashSlot::new(self, target);
        match slot.try_prepare(admit) {
            Ok(()) => Ok(slot.take_prepared()),
            Err(error) => Err((slot.recover_original(), error, slot)),
        }
    }
}
impl<'target, Installation> PreparedBlockHashes<'target, Installation> {
    /// Release physical locks and return the same private tree for retry.
    pub(crate) fn abort(self) -> (DetachedBlockHashes, AbortedBlockHashes<Installation>) {
        let Self {
            owner,
            prepared,
            mode,
            visible_len,
            installation,
            preflight_release,
            ..
        } = self;
        let ((work, reader), writer) = prepared.release_deferred(|prepared| {
            let (writer, reader) = prepared.abort_retaining();
            (writer.detach(), reader)
        });
        let retirement = AbortedBlockHashes {
            _owner: owner,
            _release: [reader, writer],
            _installation: installation,
            _preflight_release: preflight_release,
        };
        (
            DetachedBlockHashes {
                work,
                mode,
                visible_len,
                reserved_tip: None,
            },
            retirement,
        )
    }
    /// Publish without allocation; retain cleanup until aggregate fences release.
    pub(crate) fn publish(self) -> PublishedBlockHashes<'target, Installation> {
        let Self {
            prepared,
            height,
            committed_height,
            installation,
            preflight_release,
            ..
        } = self;
        let published = prepared.map_preserving_release(|prepared| prepared.publish());
        committed_height.store(height, Ordering::Release);
        let retirement = published.release_retaining(|published| published.release());
        PublishedBlockHashes {
            _retirement: retirement,
            _installation: installation,
            _preflight_release: preflight_release,
        }
    }
}
/// Released tree cleanup and wake custody. Drop after other publication fences.
pub(crate) struct PublishedBlockHashes<'a, Installation> {
    _retirement: iroha_allocation::release::ReleaseGuard<
        'a,
        concread::bptree::BptreeMapCommitRetirement<usize, HashOf<BlockHeader>, BlockHashMode>,
    >,
    _installation: Installation,
    _preflight_release: Option<iroha_allocation::release::DeferredRelease>,
}

#[cfg(test)]
#[path = "block_hashes_publication_tests.rs"]
mod tests;
