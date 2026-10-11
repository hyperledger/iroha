//! Exact committed current/undo pair before an execution overlay clears undo.
//!
//! Retained EBR reads are acquired before the short publication lock. Pointer
//! checks under that lock bind both allocations and the original version. This
//! owner never stages a successor or turns equal values into source identity.

use super::*;
use concread::ebrcell::EbrCellReadTxn;
use std::convert::Infallible;

/// Local refusal to retain a uniquely identified committed Cell pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommittedCellReadError {
    /// Preserve the actual publication contention, poison or changed-source reason.
    Publication(PublicationPreparationError<Infallible>),
}

impl From<PublicationPreparationError<Infallible>> for CommittedCellReadError {
    fn from(error: PublicationPreparationError<Infallible>) -> Self {
        Self::Publication(error)
    }
}

/// Immutable original committed pair, including explicit absence of retained undo.
///
/// This is local source custody, not a State commitment or permission to publish.
/// Collector pin/control allocation is outside this owner's funding guarantees.
pub struct CommittedCellView<'storage, V: Value> {
    current: EbrCellReadTxn<V>,
    undo: EbrCellReadTxn<Option<V>>,
    original: CapturedPublication,
    _source: PhantomData<&'storage V>,
}

impl<V: Value> CommittedCellView<'_, V> {
    /// Borrow the exact published value without cloning its payload.
    pub fn current(&self) -> &V {
        &self.current
    }

    /// Borrow the published undo; `None` means no predecessor value is retained.
    /// For optional values `Some(None)` remains distinct from absent undo.
    pub fn undo(&self) -> &Option<V> {
        &self.undo
    }

    /// Compare the original committed pair, not any newly staged value or undo.
    /// Ordinary and replacement overlays both name their actual source version;
    /// the caller must separately retain and interpret the block's acquisition mode.
    pub fn matches_block_source<C: Send + Sync + 'static>(&self, block: &Block<'_, V, C>) -> bool {
        self.original.same_as(&block.predecessor)
    }

    /// Check exact owner and published pair without taking a lock or reading data.
    pub fn same_publication(&self, other: &Self) -> bool {
        self.original.same_as(&other.original)
    }
}

impl<V: Value, C: Send + Sync + 'static> Cell<V, C> {
    /// Retain a coherent current/undo pair without initializing an execution block.
    ///
    /// Both collector pins are acquired before entering the publication lock.
    /// Once locked, comparing both protected pointers cannot run payload code,
    /// allocate a new generation or pin/reclaim the epoch collector. Stale reads
    /// return `Changed`; the caller may retry after releasing enclosing owners.
    /// This creates no successor identity and does not clear the retained undo.
    ///
    /// # Errors
    /// Returns the original publication release source on contention, poison on
    /// a failed owner, or `Changed` when either allocation changed during capture.
    pub fn try_committed_view(&self) -> Result<CommittedCellView<'_, V>, CommittedCellReadError> {
        let current = self.blocks.read();
        let undo = self.revert.read();
        self.capture_committed_reads(current, undo)
    }

    fn capture_committed_reads(
        &self,
        current: EbrCellReadTxn<V>,
        undo: EbrCellReadTxn<Option<V>>,
    ) -> Result<CommittedCellView<'_, V>, CommittedCellReadError> {
        let original = self.publication.try_capture_reads(|| {
            self.blocks.matches_read(&current) && self.revert.matches_read(&undo)
        })?;
        Ok(CommittedCellView {
            current,
            undo,
            original,
            _source: PhantomData,
        })
    }
}

#[cfg(test)]
#[path = "original_read_tests.rs"]
mod tests;
