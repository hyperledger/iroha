//! Reference-free reads from the exact detached current/undo pair.
//!
//! This owner moves the original maps and metadata without copying rows,
//! allocating a new identity or acquiring a physical writer. Retained readers
//! prevent thaw of either original map. Once every reader/position retires,
//! thaw returns the same `Detached`; its existing publication path still checks
//! the original predecessor and the caller's original allocation/refund scope.
//! Core StatePublication retains funded row indexes and cumulative structural work.
//! TODO: complete retained predecessor and semantic stages there. This pair alone
//! does not capture complete State.

use super::*;
use concread::bptree::{BptreeMapFrozenOwned, BptreeMapFrozenReader};

/// Exact immutable current/undo work plus its unchanged original metadata.
///
/// Undo and current map facades drop before the original metadata admission,
/// just as in `Detached`; retained readers can keep their original payloads alive.
/// No row, cursor, root or metadata owner is reconstructed.
/// The original admission stays here; a read handle supplies no publication or
/// allocation authority and must not substitute for the caller's refund scope.
pub struct FrozenDetached<K: Key, V: Value, Admission, M: StorageMode<K, V> = Untracked> {
    revert: BptreeMapFrozenOwned<K, Option<V>, M>,
    blocks: BptreeMapFrozenOwned<K, V, M>,
    metadata: DetachedMetadata<Admission>,
}

/// Strong immutable custody of both exact original working cursors and their cut.
///
/// These are existing charged shared owners; construction allocates nothing.
/// Row positions may retain these same map allocations independently. This read
/// projection retains the original publication identity but not a separate copy
/// of `Admission`; the aggregate must keep its `FrozenDetached` and original
/// refund scope until it retires indexes/readers and attempts publication.
pub struct FrozenDetachedRead<K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
    revert: BptreeMapFrozenReader<K, Option<V>, M>,
    blocks: BptreeMapFrozenReader<K, V, M>,
    identity: crate::BlockPublicationIdentity,
}

impl<K: Key, V: Value, Admission, M: StorageMode<K, V>> Detached<K, V, Admission, M> {
    /// Move this exact original map pair and metadata into immutable custody.
    /// No writer acquisition, row comparison, allocation or admission runs here.
    pub fn freeze_pair(self) -> FrozenDetached<K, V, Admission, M> {
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

impl<K: Key, V: Value, Admission, M: StorageMode<K, V>> FrozenDetached<K, V, Admission, M> {
    /// Retain both exact map cursors and the existing original publication cut.
    /// No replacement view, successor allocation or new identity is created.
    pub fn readers(&self) -> FrozenDetachedRead<K, V, M> {
        FrozenDetachedRead {
            revert: self.revert.reader(),
            blocks: self.blocks.reader(),
            identity: self.publication_identity(),
        }
    }

    /// Original block acquisition mode, preserved through either thaw refusal.
    pub fn mode(&self) -> BlockMode {
        self.metadata.mode
    }

    /// Original current-map publication requirement; this never inspects rows.
    pub fn is_dirty(&self) -> bool {
        self.metadata.dirty
    }

    /// Borrow the same move-only capture admission; no new credit is acquired.
    pub fn admission(&self) -> &Admission {
        &self.metadata.admission
    }

    /// Retain the exact original owner, predecessor and mode without allocating.
    /// Equality is a local observation and grants no publication authority.
    pub fn publication_identity(&self) -> crate::BlockPublicationIdentity {
        crate::BlockPublicationIdentity::capture(&self.metadata.predecessor, self.metadata.mode)
    }

    /// Compare the original owner only, without acquiring a new target view.
    /// A match cannot authorize publication or establish currentness later.
    pub fn belongs_to(&self, target: &Storage<K, V, M>) -> bool {
        self.metadata.predecessor.belongs_to(&target.publication)
    }

    /// Observe the original pair's present predecessor equality.
    /// Existing publication must recheck it under its physical identity owner.
    pub fn matches_current(&self, target: &Storage<K, V, M>) -> bool {
        self.metadata.predecessor.matches(&target.publication)
    }

    /// Return the identical original journal only after both maps become unique.
    ///
    /// Either refusal returns this intact pair and unchanged metadata. If undo
    /// thaw succeeds before current thaw refuses, refreezing that same undo work
    /// only moves its facade: no node, cursor, charge or identity is replaced.
    /// Retiring a reader permits another attempt; no work quota is reset here.
    /// The returned journal still requires its original target and refund scope.
    pub fn try_into_detached(self) -> Result<Detached<K, V, Admission, M>, Self> {
        let Self {
            revert,
            blocks,
            metadata,
        } = self;
        let revert = match revert.try_into_owned() {
            Ok(revert) => revert,
            Err(revert) => {
                return Err(Self {
                    revert,
                    blocks,
                    metadata,
                });
            }
        };
        let blocks = match blocks.try_into_owned() {
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

impl<K: Key, V: Value, M: StorageMode<K, V>> FrozenDetachedRead<K, V, M> {
    /// Borrow the exact original complete current-map cursor.
    /// Its structural row traversal/resolve API admits finite work before use.
    pub fn current(&self) -> &BptreeMapFrozenReader<K, V, M> {
        &self.blocks
    }

    /// Borrow the exact original raw undo-map cursor, including absent preimages.
    /// This subset alone is not the complete predecessor image.
    pub fn undo(&self) -> &BptreeMapFrozenReader<K, Option<V>, M> {
        &self.revert
    }

    /// Borrow the original pair's retained local cut identity.
    pub fn publication_identity(&self) -> &crate::BlockPublicationIdentity {
        &self.identity
    }

    /// Compare both physical working cursors and their exact original pair cut.
    /// Equal keys/values or a shared target do not substitute another work owner.
    pub fn same_original(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.blocks.same_original(&other.blocks)
            && self.revert.same_original(&other.revert)
    }
}

#[cfg(test)]
#[path = "frozen_pair/tests.rs"]
mod tests;
