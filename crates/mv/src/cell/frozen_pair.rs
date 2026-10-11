//! Exact original unpublished Cell pair, retained independently of execution writers.
//!
//! Freezing moves the same current/undo EBR allocations and complete metadata.
//! Neither a value copy nor predecessor identity alone establishes this staged
//! pair. Immutable handles exclude thaw; every refusal returns the original pair.
//! Core's CellField and StatePublication retain this same pair for revision reads.
//! TODO: complete predecessor semantics and materialization before full-State use.

use super::*;
use concread::ebrcell::{EbrCellFrozen, EbrCellFrozenRead};

/// Original immutable current/undo allocations and unchanged publication metadata.
///
/// The actual values/backings drop before metadata admission. Read handles retain
/// those original backings/charges independently, but do not clone Admission.
/// An aggregate must keep this owner and the original refund scope until all its
/// readers retire; abandoning it is not acknowledgement that readers retired.
/// No wrapper, payload or identity allocation is added by this owner.
pub struct FrozenDetached<V: Value, Admission, Charge: Send + Sync + 'static = Untracked> {
    revert: EbrCellFrozen<Option<V>, Charge>,
    blocks: EbrCellFrozen<V, Charge>,
    metadata: DetachedMetadata<Admission>,
}

/// Strong immutable projection of both exact original staged allocations and cut.
///
/// This retains actual original backing, not copied scalar authority. It grants
/// no writer, publication or refund authority; the aggregate retains Admission
/// and its original scope in `FrozenDetached` until read retirement completes.
pub struct FrozenDetachedRead<V: Value, Charge: Send + Sync + 'static = Untracked> {
    revert: EbrCellFrozenRead<Option<V>, Charge>,
    blocks: EbrCellFrozenRead<V, Charge>,
    identity: crate::BlockPublicationIdentity,
}

impl<V: Value, A, C: Send + Sync + 'static> Detached<V, A, C> {
    /// Move the exact original current/undo backing and metadata into frozen custody.
    /// No writer, collector pin, clone, allocation or new identity is acquired.
    pub fn freeze_pair(self) -> FrozenDetached<V, A, C> {
        let Self {
            revert,
            blocks,
            metadata,
        } = self;
        FrozenDetached {
            revert: revert.freeze(),
            blocks: blocks.freeze(),
            metadata,
        }
    }
}

impl<V: Value, A, C: Send + Sync + 'static> FrozenDetached<V, A, C> {
    /// Retain both same original backing allocations and their existing local cut.
    pub fn readers(&self) -> FrozenDetachedRead<V, C> {
        FrozenDetachedRead {
            revert: self.revert.read(),
            blocks: self.blocks.read(),
            identity: self.publication_identity(),
        }
    }

    /// Borrow the actual immutable original staged current value.
    pub fn get(&self) -> &V {
        self.blocks.get()
    }

    /// Borrow actual raw original undo; None and Some(None) stay distinct.
    pub fn original_undo(&self) -> &Option<V> {
        self.revert.get()
    }

    /// Borrow the before-block value from this original pair, including replacement.
    pub fn get_before_block(&self) -> &V {
        self.original_undo().as_ref().unwrap_or_else(|| self.get())
    }

    /// Borrow actual touched values; equal values do not erase a mutation record.
    pub fn touched_value(&self) -> Option<TouchedValue<'_, V>> {
        self.original_undo().as_ref().map(|before| TouchedValue {
            before,
            after: self.get(),
        })
    }

    /// Preserve the original ordinary or replacement acquisition mode.
    pub fn mode(&self) -> BlockMode {
        self.metadata.mode
    }

    /// Preserve the original current publication requirement without value comparison.
    pub fn is_dirty(&self) -> bool {
        self.metadata.dirty
    }

    /// Borrow unchanged original admission, separate from actual EBR allocation charges.
    pub fn admission(&self) -> &A {
        &self.metadata.admission
    }

    /// Retain the existing original target/predecessor/mode without allocating.
    pub fn publication_identity(&self) -> crate::BlockPublicationIdentity {
        crate::BlockPublicationIdentity::capture(&self.metadata.predecessor, self.metadata.mode)
    }

    /// Observe original target identity only; this grants no publication permission.
    pub fn belongs_to(&self, target: &Cell<V, C>) -> bool {
        self.metadata.predecessor.belongs_to(&target.publication)
    }

    /// Observe current predecessor equality; installation still rechecks under writers.
    pub fn matches_current(&self, target: &Cell<V, C>) -> bool {
        self.metadata.predecessor.matches(&target.publication)
    }

    /// Compare exact original current/undo allocations and cut, without cloning reads.
    pub fn matches_read(&self, read: &FrozenDetachedRead<V, C>) -> bool {
        self.publication_identity() == read.identity
            && self.blocks.matches_read(&read.blocks)
            && self.revert.matches_read(&read.revert)
    }

    /// Restore this exact Detached pair only when both original allocations are unique.
    ///
    /// Either reader-held refusal returns unchanged metadata/admission and original
    /// values/backings. If undo thaws before current refuses, refreezing that same
    /// undo neither copies a value nor acquires a new charge or identity. There is
    /// no physical mutex contention here and no mutex ReleaseWait is fabricated.
    /// Subsequent publication uses the existing original-source checks and owner.
    pub fn try_into_detached(self) -> Result<Detached<V, A, C>, Self> {
        let Self {
            revert,
            blocks,
            metadata,
        } = self;
        let revert = match revert.try_thaw() {
            Ok(revert) => revert,
            Err(revert) => {
                return Err(Self {
                    revert,
                    blocks,
                    metadata,
                });
            }
        };
        let blocks = match blocks.try_thaw() {
            Ok(blocks) => blocks,
            Err(blocks) => {
                return Err(Self {
                    revert: revert.freeze(),
                    blocks,
                    metadata,
                });
            }
        };
        Ok(Detached {
            revert,
            blocks,
            metadata,
        })
    }
}

impl<V: Value, C: Send + Sync + 'static> FrozenDetachedRead<V, C> {
    /// Borrow the same original staged current backing, never a new target view.
    pub fn current(&self) -> &EbrCellFrozenRead<V, C> {
        &self.blocks
    }

    /// Borrow the same original raw undo backing, including explicit absence.
    pub fn undo(&self) -> &EbrCellFrozenRead<Option<V>, C> {
        &self.revert
    }

    /// Borrow the same original before-block value, including replacement semantics.
    pub fn get_before_block(&self) -> &V {
        self.revert.as_ref().unwrap_or(&self.blocks)
    }

    /// Borrow the retained original target/predecessor/mode identity.
    pub fn publication_identity(&self) -> &crate::BlockPublicationIdentity {
        &self.identity
    }

    /// Compare both actual original allocations and their retained local cut.
    pub fn same_original(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.blocks.same_source(&other.blocks)
            && self.revert.same_source(&other.revert)
    }
}

#[cfg(test)]
#[path = "frozen_pair_tests.rs"]
mod tests;
