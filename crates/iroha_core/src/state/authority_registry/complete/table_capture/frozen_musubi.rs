//! Three canonical semantic encoders retained in the original Musubi publisher.
//!
//! Checked ordinal reads use the same fourteen immutable original map pairs and
//! revision as semantic validation. Encoding uses the existing canonical kernel
//! and original allocation scope. Completed rows and trees survive local refusal;
//! callers borrow all three completed outputs under that same retained owner.
//! These scoped tables do not establish complete State or certified history.

#[cfg(test)]
use super::StateBlock;
use super::{CanonicalTablePairedSnapshot, LeafError, LeafLimits, MusubiSemanticTable};
use crate::state::{
    authority_registry::{
        leaf::{RetainedSemanticError, RetainedSemanticOrdinalRows, RetainedSemanticProgress},
        world::{
            musubi_availability_policy::MusubiAvailabilityAuthorityV1,
            musubi_universal_policy::{MusubiDirectoryAuthorityV1, MusubiResolverAuthorityV1},
        },
    },
    publication::{OriginalMusubiImage, OriginalMusubiRows, RetainedMusubiGroupReadError},
};
use iroha_allocation::OwnedAllocationScope;

const TABLES: [MusubiSemanticTable; 3] = [
    MusubiSemanticTable::Availability,
    MusubiSemanticTable::Resolver,
    MusubiSemanticTable::Directory,
];
const IDENTITIES: [&str; 3] = [
    "iroha:state:musubi-availability-authority:v1",
    "iroha:state:musubi-resolver-authority:v1",
    "iroha:state:musubi-directory-authority:v1",
];
// Positions in the single closed physical group inventory.
const POSITIONS: [usize; 3] = [1, 10, 8];

/// Preserve exact original-source and canonical-encoder refusals.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum FrozenMusubiError {
    /// Original source failed its structural, semantic or identity requirement.
    #[error("original Musubi source refused: {0:?}")]
    Source(RetainedMusubiGroupReadError),
    /// Exact canonical key, value, backing or work failure.
    #[error(transparent)]
    Encoding(#[from] RetainedSemanticError),
    /// A retained operation cannot replace its original cardinality or limits.
    #[error("original Musubi materializer policy or source cardinality changed")]
    Changed,
}

/// Reference-free canonical backing owned by the existing charged publication group.
pub(in crate::state) struct OriginalMusubiMaterializers {
    tables: [RetainedSemanticOrdinalRows; 3],
    counts: [usize; 14],
    limits: [LeafLimits; 3],
    max_total_rows: u64,
}

impl OriginalMusubiMaterializers {
    /// Check all output cardinalities before creating any canonical backing.
    pub(in crate::state) fn new(
        limits: [LeafLimits; 3],
        max_total_rows: u64,
        scope: &OwnedAllocationScope,
        counts: [usize; 14],
    ) -> Result<Self, FrozenMusubiError> {
        let mut remaining = max_total_rows;
        for (index, position) in POSITIONS.into_iter().enumerate() {
            let count =
                u64::try_from(counts[position]).map_err(|_| RetainedSemanticError::Overflow)?;
            if limits[index].max_tables == 0 {
                return Err(RetainedSemanticError::Table(LeafError::TableLimit).into());
            }
            if count > limits[index].max_rows {
                return Err(RetainedSemanticError::Table(LeafError::RowLimit).into());
            }
            remaining = remaining
                .checked_sub(count)
                .ok_or(RetainedSemanticError::Table(LeafError::RowLimit))?;
        }
        let table = |index: usize| {
            RetainedSemanticOrdinalRows::new(
                TABLES[index].id(),
                IDENTITIES[index],
                limits[index],
                counts[POSITIONS[index]],
                scope,
            )
        };
        Ok(Self {
            tables: [table(0)?, table(1)?, table(2)?],
            counts,
            limits,
            max_total_rows,
        })
    }

    /// Initialize or resume only this exact retained source/policy under its admitted scope.
    pub(in crate::state) fn advance_retained(
        retained: &mut Option<Self>,
        rows: &mut OriginalMusubiRows<'_>,
        limits: [LeafLimits; 3],
        max_total_rows: u64,
        encoding_work_limit: usize,
    ) -> Result<[RetainedSemanticProgress; 3], FrozenMusubiError> {
        if let Some(materializers) = retained.as_ref() {
            if !materializers.matches_policy(limits, max_total_rows) {
                return Err(FrozenMusubiError::Changed);
            }
        } else {
            let counts = rows
                .counts(OriginalMusubiImage::Current)
                .map_err(FrozenMusubiError::Source)?;
            *retained = Some(Self::new(limits, max_total_rows, rows.scope(), counts)?);
        }
        let materializers = retained.as_mut().ok_or(FrozenMusubiError::Changed)?;
        let progress = materializers.advance(rows, encoding_work_limit)?;
        if TABLES
            .into_iter()
            .any(|table| materializers.snapshot(table).is_none())
        {
            return Err(FrozenMusubiError::Changed);
        }
        Ok(progress)
    }

    fn matches_policy(&self, limits: [LeafLimits; 3], max_total_rows: u64) -> bool {
        fn fields(limit: LeafLimits) -> (usize, u64, usize, usize, u64) {
            (
                limit.max_tables,
                limit.max_rows,
                limit.max_payload_bytes,
                limit.max_ordered_table_bytes,
                limit.max_streamed_value_bytes,
            )
        }
        self.max_total_rows == max_total_rows
            && self
                .limits
                .into_iter()
                .zip(limits)
                .all(|(a, b)| fields(a) == fields(b))
    }

    /// Observe every retained table, including after a later table's refusal.
    pub(in crate::state) fn progress(&self) -> [RetainedSemanticProgress; 3] {
        std::array::from_fn(|index| self.tables[index].progress())
    }

    /// Advance using one aggregate cumulative encoding allowance for all three tables.
    /// Structural row reads have their own original source-work allowance.
    pub(in crate::state) fn advance(
        &mut self,
        rows: &mut OriginalMusubiRows<'_>,
        encoding_work_limit: usize,
    ) -> Result<[RetainedSemanticProgress; 3], FrozenMusubiError> {
        if rows
            .counts(OriginalMusubiImage::Current)
            .map_err(FrozenMusubiError::Source)?
            != self.counts
        {
            return Err(FrozenMusubiError::Changed);
        }
        for index in 0..3 {
            let other = self
                .tables
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .try_fold(0usize, |used, (_, table)| {
                    used.checked_add(table.progress().work)
                })
                .ok_or(RetainedSemanticError::Overflow)?;
            let limit =
                encoding_work_limit
                    .checked_sub(other)
                    .ok_or(RetainedSemanticError::Work {
                        used: other,
                        required: other,
                        limit: encoding_work_limit,
                    })?;
            let table = &mut self.tables[index];
            table.prepare(limit)?;
            while table.next_row() < self.counts[POSITIONS[index]] {
                if table.pending_digest() {
                    table.resume_pending(limit)?;
                    continue;
                }
                let ordinal = table.next_row();
                match TABLES[index] {
                    MusubiSemanticTable::Availability => {
                        let (key, value) = rows
                            .musubi_archive_availability_current_row(ordinal)
                            .map_err(FrozenMusubiError::Source)?;
                        table.push(
                            key,
                            || MusubiAvailabilityAuthorityV1::from_record(value),
                            limit,
                        )?;
                    }
                    MusubiSemanticTable::Resolver => {
                        let (key, value) = rows
                            .musubi_resolver_index_current_row(ordinal)
                            .map_err(FrozenMusubiError::Source)?;
                        table.push(key, || MusubiResolverAuthorityV1::from_record(value), limit)?;
                    }
                    MusubiSemanticTable::Directory => {
                        let (key, value) = rows
                            .musubi_public_directory_current_row(ordinal)
                            .map_err(FrozenMusubiError::Source)?;
                        table.push(
                            key,
                            || MusubiDirectoryAuthorityV1::from_record(value),
                            limit,
                        )?;
                    }
                }
            }
            table.finish(limit)?;
        }
        Ok(self.progress())
    }

    /// Borrow one table only when the whole original three-table group is complete.
    pub(in crate::state) fn snapshot(
        &self,
        table: MusubiSemanticTable,
    ) -> Option<&CanonicalTablePairedSnapshot> {
        if !self.tables.iter().all(|table| table.progress().complete) {
            return None;
        }
        let index = TABLES.iter().position(|candidate| *candidate == table)?;
        self.tables[index].snapshot()
    }
}

/// Advance and borrow the complete group inside the existing publisher's checked cut.
/// The callback cannot return a reference that outlives the exact original owner.
#[cfg(test)]
pub(in crate::state) fn with_original_musubi_tables<R>(
    block: &mut StateBlock<'_>,
    limits: [LeafLimits; 3],
    max_total_rows: u64,
    source_work_limit: usize,
    encoding_work_limit: usize,
    callback: impl for<'tables> FnOnce([&'tables CanonicalTablePairedSnapshot; 3]) -> R,
) -> Result<R, FrozenMusubiError> {
    block
        .with_validated_original_musubi_materializers(source_work_limit, |mut rows, _, retained| {
            OriginalMusubiMaterializers::advance_retained(
                retained,
                &mut rows,
                limits,
                max_total_rows,
                encoding_work_limit,
            )?;
            let materializers = retained.as_ref().ok_or(FrozenMusubiError::Changed)?;
            let snapshots = [
                materializers
                    .snapshot(TABLES[0])
                    .ok_or(FrozenMusubiError::Changed)?,
                materializers
                    .snapshot(TABLES[1])
                    .ok_or(FrozenMusubiError::Changed)?,
                materializers
                    .snapshot(TABLES[2])
                    .ok_or(FrozenMusubiError::Changed)?,
            ];
            Ok(callback(snapshots))
        })
        .map_err(FrozenMusubiError::Source)?
}

#[cfg(test)]
#[path = "frozen_musubi/tests.rs"]
mod tests;
