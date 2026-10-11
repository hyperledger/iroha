//! Retain the exact original pair in its existing field while indexes read it.
//!
//! This phase adds no writer, publication permission, copied tree or allocation.
//! The State publisher owns all read/position handles and their original scope.
//! A reader-held thaw refusal is not a physical writer lock or release event.

use super::*;

/// Why this original field cannot return to its detached publication phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetainedReadPhaseError {
    /// Execution, incomplete capture, publication or terminal release is not a read cut.
    NotFrozen,
    /// Actual original read/position owners still retain one of the paired cursors.
    ReadersRetained,
}

impl<K: Key, V: Value, M: mv::storage::StorageMode<K, V>> StorageField<'_, K, V, M> {
    /// Retain immutable handles after moving the same journal inside this field.
    /// Repeated calls retain the same current/undo work; no target is reacquired.
    pub(crate) fn retain_original_readers(
        &mut self,
    ) -> Option<mv::storage::FrozenDetachedRead<K, V, M>> {
        if self.released {
            return None;
        }
        if matches!(self.phase, Some(Phase::Frozen(_))) {
            let Some(Phase::Frozen(original)) = self.phase.take() else {
                unreachable!("checked original frozen phase")
            };
            self.phase = Some(Phase::Reading(original.freeze_pair()));
        }
        match self.phase.as_ref() {
            Some(Phase::Reading(original)) => Some(original.readers()),
            _ => None,
        }
    }

    /// Check original target/currentness without taking a fresh map or read owner.
    /// This is advisory; existing physical installation must authenticate again.
    pub(crate) fn retained_read_matches_current(
        &self,
        target: &mv::storage::Storage<K, V, M>,
    ) -> Option<bool> {
        if self.released {
            return None;
        }
        match self.phase.as_ref() {
            Some(Phase::Frozen(original)) => Some(original.matches_current(target)),
            Some(Phase::Reading(original)) => Some(original.matches_current(target)),
            _ => None,
        }
    }

    /// Bind a retained plan to both exact original physical work cursors.
    /// Matching target/predecessor or equal rows cannot replace this paired source.
    pub(crate) fn retained_read_matches_source(
        &self,
        source: &mv::storage::FrozenDetachedRead<K, V, M>,
    ) -> bool {
        if self.released {
            return false;
        }
        match self.phase.as_ref() {
            Some(Phase::Reading(original)) => original.readers().same_original(source),
            _ => false,
        }
    }

    /// Restore this same paired journal once every index/read owner has retired.
    /// Either map refusal retains the intact phase; no release wait is fabricated.
    pub(crate) fn try_retire_original_readers(&mut self) -> Result<(), RetainedReadPhaseError> {
        if self.released {
            return Err(RetainedReadPhaseError::NotFrozen);
        }
        if matches!(self.phase, Some(Phase::Frozen(_))) {
            return Ok(());
        }
        if !matches!(self.phase, Some(Phase::Reading(_))) {
            return Err(RetainedReadPhaseError::NotFrozen);
        }
        let Some(Phase::Reading(original)) = self.phase.take() else {
            unreachable!("checked original retained-read phase")
        };
        match original.try_into_detached() {
            Ok(original) => {
                self.phase = Some(Phase::Frozen(original));
                Ok(())
            }
            Err(original) => {
                self.phase = Some(Phase::Reading(original));
                #[cfg(all(test, sumeragi_core_mutation = "HC170"))]
                {
                    // Mutation: falsely acknowledge retirement with live original readers.
                    Ok(())
                }
                #[cfg(not(all(test, sumeragi_core_mutation = "HC170")))]
                {
                    Err(RetainedReadPhaseError::ReadersRetained)
                }
            }
        }
    }
}

impl<V: Value, C: Send + Sync + 'static> CellField<'_, V, C> {
    /// Move the same original current/undo allocations into this field's read phase.
    /// No value, charge, admission or predecessor is cloned or reacquired.
    pub(crate) fn retain_original_readers(&mut self) -> Option<mv::cell::FrozenDetachedRead<V, C>> {
        if self.released {
            return None;
        }
        if matches!(self.phase, Some(Phase::Frozen(_))) {
            let Some(Phase::Frozen(original)) = self.phase.take() else {
                unreachable!("checked original frozen phase")
            };
            self.phase = Some(Phase::Reading(original.freeze_pair()));
        }
        match self.phase.as_ref() {
            Some(Phase::Reading(original)) => Some(original.readers()),
            _ => None,
        }
    }

    /// Check the original target/predecessor without allocating a fresh read owner.
    /// Existing physical installation must still authenticate under its writers.
    pub(crate) fn retained_read_matches_current(
        &self,
        target: &mv::cell::Cell<V, C>,
    ) -> Option<bool> {
        if self.released {
            return None;
        }
        match self.phase.as_ref() {
            Some(Phase::Frozen(original)) => Some(original.matches_current(target)),
            Some(Phase::Reading(original)) => Some(original.matches_current(target)),
            _ => None,
        }
    }

    /// Bind to both actual staged allocations, not merely an equal predecessor/value.
    pub(crate) fn retained_read_matches_source(
        &self,
        source: &mv::cell::FrozenDetachedRead<V, C>,
    ) -> bool {
        if self.released {
            return false;
        }
        match self.phase.as_ref() {
            Some(Phase::Reading(original)) => original.matches_read(source),
            _ => false,
        }
    }

    /// Restore this same original pair only after both actual readers retire.
    /// Partial thaw refusal retains both allocations, metadata and original charge.
    /// A retained EBR reader is not a physical writer lock or ReleaseWait event.
    pub(crate) fn try_retire_original_readers(&mut self) -> Result<(), RetainedReadPhaseError> {
        if self.released {
            return Err(RetainedReadPhaseError::NotFrozen);
        }
        if matches!(self.phase, Some(Phase::Frozen(_))) {
            return Ok(());
        }
        if !matches!(self.phase, Some(Phase::Reading(_))) {
            return Err(RetainedReadPhaseError::NotFrozen);
        }
        let Some(Phase::Reading(original)) = self.phase.take() else {
            unreachable!("checked original retained-read phase")
        };
        match original.try_into_detached() {
            Ok(original) => {
                self.phase = Some(Phase::Frozen(original));
                Ok(())
            }
            Err(original) => {
                self.phase = Some(Phase::Reading(original));
                #[cfg(all(test, sumeragi_core_mutation = "HC173"))]
                {
                    // Mutation: claim retirement with a real original Cell reader alive.
                    Ok(())
                }
                #[cfg(not(all(test, sumeragi_core_mutation = "HC173")))]
                {
                    Err(RetainedReadPhaseError::ReadersRetained)
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "retained_read/tests.rs"]
mod tests;
