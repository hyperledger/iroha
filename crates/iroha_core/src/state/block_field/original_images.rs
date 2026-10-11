//! Borrow raw original images only while the original State field is frozen.
//!
//! This is the source boundary for bounded canonical encoding, not an encoder,
//! complete-State root or another publisher. Exhaustive table/cell traversal,
//! original-pool encoding/node admission and durable publication remain separate.
//! TODO: join exhaustive funded table/cell encoding to the existing StatePublication
//! owner before constructing or publishing any complete-State root.

use super::*;

impl<K: Key, V: Value, M: mv::storage::StorageMode<K, V>> StorageField<'_, K, V, M> {
    /// Borrow this field's original frozen current and raw undo rows.
    ///
    /// Executing, partially captured, publishing and terminally released fields
    /// return `None`; no phase transition, reader allocation or target lookup occurs.
    /// The borrow prevents mutation or movement of this field for its lifetime.
    /// Callers still owe complete-owner checks and work admission before traversing
    /// or comparing physical rows. This value grants no publication authority.
    pub fn frozen_images(&self) -> Option<mv::storage::FrozenStorageImages<'_, K, V, M>> {
        if self.released {
            return None;
        }
        match self.phase.as_ref() {
            Some(Phase::Frozen(original)) => Some(original.original_images()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "original_images/tests.rs"]
mod tests;

impl<V: Value, C: Send + Sync + 'static> CellField<'_, V, C> {
    /// Borrow both exact original cell values in the complete frozen/read phases.
    /// No executing, capturing, publishing or released owner can become a source.
    pub fn frozen_values(&self) -> Option<(&V, &V)> {
        if self.released {
            return None;
        }
        match self.phase.as_ref() {
            Some(Phase::Frozen(original)) => Some((original.get(), original.get_before_block())),
            Some(Phase::Reading(original)) => Some((original.get(), original.get_before_block())),
            _ => None,
        }
    }
}
