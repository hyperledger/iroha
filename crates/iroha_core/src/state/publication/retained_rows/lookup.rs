//! Fallible exact-key queries over the existing retained original positions.
//!
//! Current queries use the original current positions; predecessor queries use
//! the already completed original merge descriptors. Every actual native resolve
//! and both operands of each canonical comparison are admitted before use. There
//! is no new map, row copy, allocation, budget, source capture or semantic token.
//! Work already spent remains charged on refusal. The retained semantic owner
//! stores fixed query cursors bound to its original phase, row and call site;
//! paid key geometry, binary-search bounds and comparison admission survive.
//! Convenience one-shot queries use the same kernel with a local cursor. All
//! returned references borrow the original map, and actual reborrows stay charged.

use super::{OriginalTableRead, RetainedPackageReadError, admit, key_work::ComparisonKey};
use crate::state::deserialize::musubi_source_read::{
    KeyWorkCursor, LookupCursor, LookupResolution,
};
use std::cmp::Ordering;

// Bounds test, midpoint, branch and next bound of a single binary-search step.
const LOOKUP_CONTROL_WORK: usize = 4;

fn lookup<'read, K: ComparisonKey, V: mv::Value>(
    key: &K,
    count: usize,
    query: &mut LookupCursor,
    work: &mut usize,
    limit: usize,
    mut row: impl FnMut(
        usize,
        &mut usize,
        usize,
    ) -> Result<(&'read K, &'read V), RetainedPackageReadError>,
) -> Result<Option<(&'read K, &'read V)>, RetainedPackageReadError> {
    match query.resolved {
        LookupResolution::Present(index) => return row(index, work, limit).map(Some),
        LookupResolution::Absent => return Ok(None),
        LookupResolution::Pending => {}
    }
    if query.phase == 0 {
        admit(work, 1, limit)?;
        query.end = count;
        if count == 0 {
            query.resolved = LookupResolution::Absent;
            return Ok(None);
        }
        query.phase = 1;
    }
    if query.phase == 1 {
        key.comparison_units_retained(&mut query.key, work, limit)?;
        query.phase = 2;
    }
    while query.first < query.end {
        if query.phase == 2 {
            admit(work, LOOKUP_CONTROL_WORK, limit)?;
            query.middle = query.first + (query.end - query.first) / 2;
            query.phase = 3;
        }
        if query.phase == 3 {
            let (candidate, _) = row(query.middle, work, limit)?;
            candidate.comparison_units_retained(&mut query.candidate, work, limit)?;
            query.phase = 4;
        }
        if query.phase == 4 {
            let comparison = query
                .key
                .units
                .checked_add(query.candidate.units)
                .ok_or(RetainedPackageReadError::Geometry)?;
            admit(work, comparison, limit)?;
            // This comparison's original charge is retained if its subsequent
            // native reborrow refuses. It is never refunded or charged twice.
            #[cfg(not(all(test, sumeragi_core_mutation = "HC370")))]
            {
                query.phase = 5;
            }
            #[cfg(all(test, sumeragi_core_mutation = "HC370"))]
            {
                query.phase = 4;
            }
        }
        let (candidate, value) = row(query.middle, work, limit)?;
        match candidate.cmp(key) {
            Ordering::Less => query.first = query.middle + 1,
            Ordering::Equal => {
                query.resolved = LookupResolution::Present(query.middle);
                return Ok(Some((candidate, value)));
            }
            Ordering::Greater => query.end = query.middle,
        }
        query.candidate = KeyWorkCursor::default();
        query.phase = 2;
    }
    query.resolved = LookupResolution::Absent;
    Ok(None)
}

pub(in crate::state::publication) fn compare<K: ComparisonKey>(
    original: &K,
    key: &K,
    work: &mut usize,
    limit: usize,
) -> Result<Ordering, RetainedPackageReadError> {
    let original_units = original.comparison_units(work, limit)?;
    let key_units = key.comparison_units(work, limit)?;
    admit(
        work,
        original_units
            .checked_add(key_units)
            .ok_or(RetainedPackageReadError::Geometry)?,
        limit,
    )?;
    Ok(original.cmp(key))
}

impl<K: ComparisonKey, V: mv::Value> OriginalTableRead<K, V> {
    /// Compare an original current key for the shared semantic accumulator.
    pub(in crate::state::publication) fn compare_current_key(
        &self,
        index: usize,
        key: &K,
        work: &mut usize,
        limit: usize,
    ) -> Result<Ordering, RetainedPackageReadError> {
        let (original, _) = self.current_row(index, work, limit)?;
        compare(original, key, work, limit)
    }
    /// Compare an original predecessor key for the same semantic accumulator.
    pub(in crate::state::publication) fn compare_predecessor_key(
        &self,
        index: usize,
        key: &K,
        work: &mut usize,
        limit: usize,
    ) -> Result<Ordering, RetainedPackageReadError> {
        let (original, _) = self.predecessor_row(index, work, limit)?;
        compare(original, key, work, limit)
    }
    /// Continue one fixed semantic query over the same complete original current index.
    pub(in crate::state::publication) fn current_lookup_retained(
        &self,
        key: &K,
        query: &mut LookupCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<Option<(&K, &V)>, RetainedPackageReadError> {
        if !self.current_complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        lookup(
            key,
            self.current_count,
            query,
            work,
            limit,
            |index, work, limit| self.current_row(index, work, limit),
        )
    }
    /// Continue one fixed semantic query over the same complete predecessor descriptors.
    pub(in crate::state::publication) fn predecessor_lookup_retained(
        &self,
        key: &K,
        query: &mut LookupCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<Option<(&K, &V)>, RetainedPackageReadError> {
        let progress = self.predecessor_progress();
        if !progress.complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        lookup(
            key,
            progress.rows,
            query,
            work,
            limit,
            |index, work, limit| self.predecessor_row(index, work, limit),
        )
    }
    /// Query only a complete original current index, without recapturing source.
    pub(in crate::state::publication) fn current_lookup(
        &self,
        key: &K,
        work: &mut usize,
        limit: usize,
    ) -> Result<Option<(&K, &V)>, RetainedPackageReadError> {
        if !self.current_complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        lookup(
            key,
            self.current_count,
            &mut LookupCursor::new(),
            work,
            limit,
            |index, work, limit| self.current_row(index, work, limit),
        )
    }

    /// Query only the complete original predecessor descriptors, including masks.
    pub(in crate::state::publication) fn predecessor_lookup(
        &self,
        key: &K,
        work: &mut usize,
        limit: usize,
    ) -> Result<Option<(&K, &V)>, RetainedPackageReadError> {
        let progress = self.predecessor_progress();
        if !progress.complete {
            return Err(RetainedPackageReadError::Incomplete);
        }
        lookup(
            key,
            progress.rows,
            &mut LookupCursor::new(),
            work,
            limit,
            |index, work, limit| self.predecessor_row(index, work, limit),
        )
    }
}

#[cfg(test)]
#[path = "lookup/tests.rs"]
mod tests;
