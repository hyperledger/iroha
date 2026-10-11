//! Original structural position ownership shared by the actual State read plans.
//!
//! This is a thin owner over the original MV pair. Every position/cursor retains
//! actual original map work; buffers are charged before allocation. No row/map is
//! copied. The optional ordered predecessor descriptor stage retains successful
//! merge work through retry; it grants no semantic or State authority.

use super::retained_musubi::{PackageReadProgress, RetainedPackageReadError};
use concread::bptree::{BptreeMapRowPosition, BptreeMapRowPositions, RowPositionError};
use iroha_allocation::{AllocationBudget, ChargedBuffer};

#[path = "retained_rows/key_work.rs"]
mod key_work;
#[path = "retained_rows/predecessor.rs"]
mod predecessor;
pub(super) use predecessor::PredecessorReadProgress;

pub(super) struct OriginalTableRead<K: mv::Key, V: mv::Value> {
    // Descriptors retire before the positions/cursors/source they resolve.
    predecessor: predecessor::PredecessorIndex,
    pub(super) current: Option<ChargedBuffer<BptreeMapRowPosition<K, V>>>,
    pub(super) undo: Option<ChargedBuffer<BptreeMapRowPosition<K, Option<V>>>>,
    pub(super) current_cursor: BptreeMapRowPositions<K, V>,
    pub(super) undo_cursor: BptreeMapRowPositions<K, Option<V>>,
    pub(super) source: mv::storage::FrozenDetachedRead<K, V>,
    pub(super) current_count: usize,
    pub(super) undo_count: usize,
    pub(super) current_complete: bool,
    pub(super) undo_complete: bool,
}

pub(super) fn admit(
    work: &mut usize,
    amount: usize,
    limit: usize,
) -> Result<(), RetainedPackageReadError> {
    let required = work
        .checked_add(amount)
        .ok_or(RetainedPackageReadError::Geometry)?;
    if required > limit {
        return Err(RetainedPackageReadError::Work {
            used: *work,
            required,
            limit,
        });
    }
    *work = required;
    Ok(())
}
fn row_error(error: RowPositionError<RetainedPackageReadError>) -> RetainedPackageReadError {
    match error {
        RowPositionError::Work(error) => error,
        RowPositionError::ForeignOwner => RetainedPackageReadError::SourceChanged,
        RowPositionError::InvalidPosition => RetainedPackageReadError::Geometry,
    }
}
impl<K: mv::Key, V: mv::Value> OriginalTableRead<K, V> {
    pub(super) fn new(
        source: mv::storage::FrozenDetachedRead<K, V>,
        current_count: usize,
        undo_count: usize,
    ) -> Self {
        let current_cursor = source.current().positions();
        let undo_cursor = source.undo().positions();
        Self {
            predecessor: predecessor::PredecessorIndex::default(),
            current: None,
            undo: None,
            current_cursor,
            undo_cursor,
            source,
            current_count,
            undo_count,
            current_complete: false,
            undo_complete: false,
        }
    }
    pub(super) fn observe(&self, work: usize, retired: bool) -> PackageReadProgress {
        PackageReadProgress {
            current: self
                .current
                .as_ref()
                .map_or(0, |rows| rows.as_slice().len()),
            undo: self.undo.as_ref().map_or(0, |rows| rows.as_slice().len()),
            work,
            complete: self.current_complete && self.undo_complete,
            retired,
        }
    }
    pub(super) fn advance(
        &mut self,
        budget: &AllocationBudget,
        work: &mut usize,
        limit: usize,
    ) -> Result<(), RetainedPackageReadError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC168"))]
        {
            *work = 0;
        }
        if self.current.is_none() {
            self.current = Some(
                ChargedBuffer::new(self.current_count, budget)
                    .map_err(RetainedPackageReadError::Allocation)?,
            );
        }
        if !self.current_complete {
            loop {
                let position = self
                    .current_cursor
                    .try_next(|amount| admit(work, amount, limit))
                    .map_err(row_error)?;
                let Some(position) = position else { break };
                self.current
                    .as_mut()
                    .expect("admitted original current positions")
                    .try_push(position)
                    .map_err(|_| RetainedPackageReadError::Geometry)?;
            }
            if self
                .current
                .as_ref()
                .expect("original current positions")
                .as_slice()
                .len()
                != self.current_count
            {
                return Err(RetainedPackageReadError::Geometry);
            }
            self.current_complete = true;
        }
        // Later physical refusal leaves every completed current position and its
        // actual charge/cursor/work in place. No reread or new source is installed.
        if self.undo.is_none() {
            let undo = ChargedBuffer::new(self.undo_count, budget).map_err(|error| {
                #[cfg(all(test, sumeragi_core_mutation = "HC169"))]
                {
                    // Mutation: later refusal discards the completed current prefix.
                    self.current = None;
                    self.current_complete = false;
                    self.current_cursor = self.source.current().positions();
                }
                RetainedPackageReadError::Allocation(error)
            })?;
            self.undo = Some(undo);
        }
        if !self.undo_complete {
            loop {
                let position = self
                    .undo_cursor
                    .try_next(|amount| admit(work, amount, limit))
                    .map_err(row_error)?;
                let Some(position) = position else { break };
                self.undo
                    .as_mut()
                    .expect("admitted original undo positions")
                    .try_push(position)
                    .map_err(|_| RetainedPackageReadError::Geometry)?;
            }
            if self
                .undo
                .as_ref()
                .expect("original undo positions")
                .as_slice()
                .len()
                != self.undo_count
            {
                return Err(RetainedPackageReadError::Geometry);
            }
            self.undo_complete = true;
        }
        Ok(())
    }
    pub(super) fn current_row(
        &self,
        index: usize,
        work: &mut usize,
        limit: usize,
    ) -> Result<(&K, &V), RetainedPackageReadError> {
        let position = self
            .current
            .as_ref()
            .and_then(|rows| rows.as_slice().get(index))
            .ok_or(RetainedPackageReadError::Incomplete)?;
        self.source
            .current()
            .resolve(position, |amount| admit(work, amount, limit))
            .map_err(row_error)
    }
    pub(super) fn undo_row(
        &self,
        index: usize,
        work: &mut usize,
        limit: usize,
    ) -> Result<(&K, &Option<V>), RetainedPackageReadError> {
        let position = self
            .undo
            .as_ref()
            .and_then(|rows| rows.as_slice().get(index))
            .ok_or(RetainedPackageReadError::Incomplete)?;
        self.source
            .undo()
            .resolve(position, |amount| admit(work, amount, limit))
            .map_err(row_error)
    }
}
