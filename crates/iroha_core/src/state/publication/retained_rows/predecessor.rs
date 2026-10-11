//! Retained reference-free ordered predecessor descriptors over the original pair.
//!
//! Current is the complete original staged image; undo supplies first preimages.
//! Equal keys select undo `Some`, undo `None` masks inserted-only rows, and
//! untouched current rows remain. Descriptors contain ordinals into the retained
//! structural positions, never references, copied values or an alternate source.
//! Every real resolve/comparison is prepaid; completed heads/frontiers/descriptors
//! and successful work survive local refusal in the original State-owned plan.
//! TODO: admit semantic queries/accumulators and retain materialized nodes before
//! exposing any infallible semantic adapter or authorizing complete State.

use super::{
    OriginalTableRead, RetainedPackageReadError, admit, key_work::ComparisonKey, row_error,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use std::cmp::Ordering;

/// Observation of the ordered descriptor stage, not semantic verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PredecessorReadProgress {
    pub(crate) current_consumed: usize,
    pub(crate) undo_consumed: usize,
    pub(crate) rows: usize,
    pub(crate) complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PredecessorPosition {
    Current(usize),
    Undo(usize),
}

#[derive(Clone, Copy)]
struct HeadDemand {
    resolve: usize,
    compare: usize,
}

#[derive(Default)]
pub(super) struct PredecessorIndex {
    rows: Option<ChargedBuffer<PredecessorPosition>>,
    current_next: usize,
    undo_next: usize,
    current_head: Option<HeadDemand>,
    undo_head: Option<HeadDemand>,
    complete: bool,
}
impl PredecessorIndex {
    pub(super) fn observe(&self) -> PredecessorReadProgress {
        PredecessorReadProgress {
            current_consumed: self.current_next,
            undo_consumed: self.undo_next,
            rows: self.rows.as_ref().map_or(0, |rows| rows.as_slice().len()),
            complete: self.complete,
        }
    }
}

// Bounded branch/ordinal/masking/push/frontier work of one merge step. Actual
// tree walks and both complete variable key operands are admitted separately.
const MERGE_CONTROL_WORK: usize = 8;

fn exact_resolve(actual: usize, original: usize) -> Result<(), RetainedPackageReadError> {
    if actual == original {
        Ok(())
    } else {
        Err(RetainedPackageReadError::Geometry)
    }
}

impl<K: ComparisonKey, V: mv::Value> OriginalTableRead<K, V> {
    pub(in crate::state::publication) fn advance_predecessor(
        &mut self,
        budget: &AllocationBudget,
        work: &mut usize,
        limit: usize,
    ) -> Result<(), RetainedPackageReadError> {
        if !self.current_complete || !self.undo_complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        if self.predecessor.complete {
            return Ok(());
        }
        if self.predecessor.rows.is_none() {
            let capacity = self
                .current_count
                .checked_add(self.undo_count)
                .ok_or(RetainedPackageReadError::Geometry)?;
            self.predecessor.rows = Some(
                ChargedBuffer::new(capacity, budget)
                    .map_err(RetainedPackageReadError::Allocation)?,
            );
        }
        loop {
            // Each successful head's planning is retained inline in the already
            // charged original control shell. An unfinished planning attempt may
            // repeat work on retry, but every repeated traversal is charged and
            // no admitted prefix is reset or refunded.
            if self.predecessor.current_head.is_none()
                && self.predecessor.current_next < self.current_count
            {
                let index = self.predecessor.current_next;
                let position = self
                    .current
                    .as_ref()
                    .ok_or(RetainedPackageReadError::Incomplete)?
                    .as_slice()
                    .get(index)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                let mut resolve = 0;
                let (key, _) = self
                    .source
                    .current()
                    .resolve(position, |amount| {
                        admit(work, amount, limit)?;
                        resolve = amount;
                        Ok(())
                    })
                    .map_err(row_error)?;
                let compare = key.comparison_units(work, limit)?;
                self.predecessor.current_head = Some(HeadDemand { resolve, compare });
            }
            if self.predecessor.undo_head.is_none() && self.predecessor.undo_next < self.undo_count
            {
                let index = self.predecessor.undo_next;
                let position = self
                    .undo
                    .as_ref()
                    .ok_or(RetainedPackageReadError::Incomplete)?
                    .as_slice()
                    .get(index)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                let mut resolve = 0;
                let (key, _) = self
                    .source
                    .undo()
                    .resolve(position, |amount| {
                        admit(work, amount, limit)?;
                        resolve = amount;
                        Ok(())
                    })
                    .map_err(row_error)?;
                let compare = key.comparison_units(work, limit)?;
                self.predecessor.undo_head = Some(HeadDemand { resolve, compare });
            }
            let (current, undo) = (self.predecessor.current_head, self.predecessor.undo_head);
            if current.is_none() && undo.is_none() {
                self.predecessor.complete = true;
                return Ok(());
            }
            let mut required = MERGE_CONTROL_WORK;
            for head in [current, undo].into_iter().flatten() {
                required = required
                    .checked_add(head.resolve)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                if current.is_some() && undo.is_some() {
                    required = required
                        .checked_add(head.compare)
                        .ok_or(RetainedPackageReadError::Geometry)?;
                }
            }
            // This private source-bound step prepays the actual repeated tree
            // resolves as well as comparison. The callbacks below verify their
            // unchanged recorded demand; they do not waive or reset a quota.
            if let Err(error) = admit(work, required, limit) {
                #[cfg(all(test, sumeragi_core_mutation = "HC175"))]
                {
                    self.predecessor = PredecessorIndex::default();
                }
                return Err(error);
            }
            let current_row = if let Some(head) = current {
                let position = self
                    .current
                    .as_ref()
                    .ok_or(RetainedPackageReadError::Incomplete)?
                    .as_slice()
                    .get(self.predecessor.current_next)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                Some(
                    self.source
                        .current()
                        .resolve(position, |amount| exact_resolve(amount, head.resolve))
                        .map_err(row_error)?,
                )
            } else {
                None
            };
            let undo_row = if let Some(head) = undo {
                let position = self
                    .undo
                    .as_ref()
                    .ok_or(RetainedPackageReadError::Incomplete)?
                    .as_slice()
                    .get(self.predecessor.undo_next)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                Some(
                    self.source
                        .undo()
                        .resolve(position, |amount| exact_resolve(amount, head.resolve))
                        .map_err(row_error)?,
                )
            } else {
                None
            };
            let (take_current, take_undo, selected) = match (current_row, undo_row) {
                (Some((key, _)), Some((old_key, old))) => match key.cmp(old_key) {
                    Ordering::Less => (
                        true,
                        false,
                        Some(PredecessorPosition::Current(self.predecessor.current_next)),
                    ),
                    Ordering::Equal => {
                        #[cfg(not(all(test, sumeragi_core_mutation = "HC174")))]
                        let selected = old
                            .as_ref()
                            .map(|_| PredecessorPosition::Undo(self.predecessor.undo_next));
                        #[cfg(all(test, sumeragi_core_mutation = "HC174"))]
                        let selected = {
                            let _ = old;
                            Some(PredecessorPosition::Current(self.predecessor.current_next))
                        };
                        (true, true, selected)
                    }
                    Ordering::Greater => (
                        false,
                        true,
                        old.as_ref()
                            .map(|_| PredecessorPosition::Undo(self.predecessor.undo_next)),
                    ),
                },
                (Some(_), None) => (
                    true,
                    false,
                    Some(PredecessorPosition::Current(self.predecessor.current_next)),
                ),
                (None, Some((_, old))) => (
                    false,
                    true,
                    old.as_ref()
                        .map(|_| PredecessorPosition::Undo(self.predecessor.undo_next)),
                ),
                (None, None) => return Err(RetainedPackageReadError::Geometry),
            };
            if let Some(selected) = selected {
                self.predecessor
                    .rows
                    .as_mut()
                    .ok_or(RetainedPackageReadError::Incomplete)?
                    .try_push(selected)
                    .map_err(|_| RetainedPackageReadError::Geometry)?;
            }
            if take_current {
                self.predecessor.current_next += 1;
                self.predecessor.current_head = None;
            }
            if take_undo {
                self.predecessor.undo_next += 1;
                self.predecessor.undo_head = None;
            }
        }
    }
}

impl<K: mv::Key, V: mv::Value> OriginalTableRead<K, V> {
    pub(in crate::state::publication) fn predecessor_progress(&self) -> PredecessorReadProgress {
        self.predecessor.observe()
    }

    /// Borrow a completed ordered predecessor row from its actual original owner.
    /// No nth scan/comparison/clone runs; the exact structural resolve is admitted.
    pub(in crate::state::publication) fn predecessor_row(
        &self,
        index: usize,
        work: &mut usize,
        limit: usize,
    ) -> Result<(&K, &V), RetainedPackageReadError> {
        if !self.predecessor.complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        let descriptor = self
            .predecessor
            .rows
            .as_ref()
            .and_then(|rows| rows.as_slice().get(index))
            .ok_or(RetainedPackageReadError::Incomplete)?;
        match *descriptor {
            PredecessorPosition::Current(index) => self.current_row(index, work, limit),
            PredecessorPosition::Undo(index) => {
                let (key, before) = self.undo_row(index, work, limit)?;
                Ok((
                    key,
                    before.as_ref().ok_or(RetainedPackageReadError::Geometry)?,
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "predecessor_tests.rs"]
mod tests;
