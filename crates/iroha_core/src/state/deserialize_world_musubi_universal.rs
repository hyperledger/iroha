//! Exact Musubi universal resolver and directory checks for one World cut.
//!
//! The row's index revision is independent authority. Every other row field
//! is reconstructed from its canonical package, release, archive, and archive
//! availability sources before a semantic authority projection is admitted.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use crate::state::deserialize::musubi_source_read::{
    MusubiRead, MusubiSourceReadOnly, ReadFailure,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

#[path = "deserialize_world_musubi_universal/accumulator.rs"]
mod accumulator;
use accumulator::PackageRevision;

#[path = "deserialize_world_musubi_universal/cursor.rs"]
pub(in crate::state) mod cursor;

fn invalid(
    cut: ProjectionCut,
    table: ProjectionTable,
    reason: &'static str,
) -> ProjectionRejection {
    ProjectionRejection::new(table, reason).with_cut(cut)
}

/// Verify exact row content and membership against authoritative source tables.
///
/// This is read-only so both finalized restore and World publication can use the
/// same predicate. A failed check cannot mutate the candidate or its predecessor.
pub(in crate::state) fn validate_musubi_universal_projection_cut(
    world: &impl MusubiSourceReadOnly,
    cut: ProjectionCut,
    execution_budget: &AllocationBudget,
) -> Result<(), ExecutionAttemptError<ProjectionRejection>> {
    try_validate_musubi_universal_projection_cut(world, cut, execution_budget)
        .map_err(ReadFailure::into_predicate)
}

/// The same universal predicate preserves each original physical source refusal.
pub(in crate::state) fn try_validate_musubi_universal_projection_cut<W: MusubiRead>(
    world: &W,
    cut: ProjectionCut,
    execution_budget: &AllocationBudget,
) -> Result<(), ReadFailure<W::Error, ExecutionAttemptError<ProjectionRejection>>> {
    let source = cursor::BorrowedUniversalSource(world);
    let mut validation = cursor::UniversalValidation::new(cut);
    validation.advance(&source, execution_budget)
}

/// Check both the current and rollback-visible versions retained by one World.
pub(super) fn validate_musubi_universal_projection_cuts(
    world: &World,
    execution_budget: &AllocationBudget,
) -> Result<(), StateRestoreError> {
    validate_musubi_universal_projection_cut(
        &world.view(),
        ProjectionCut::Current,
        execution_budget,
    )
    .map_err(|error| error.map_rejection(ProjectionRejection::into_json))?;
    validate_musubi_universal_projection_cut(
        &world.try_block_and_revert(execution_budget)?,
        ProjectionCut::Predecessor,
        execution_budget,
    )
    .map_err(|error| error.map_rejection(ProjectionRejection::into_json))
    .map_err(Into::into)
}

#[cfg(test)]
#[path = "deserialize_world_musubi_universal/funding_tests.rs"]
mod funding_tests;
