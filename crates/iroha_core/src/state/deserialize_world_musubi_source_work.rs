//! Bounded public source geometry and invocation admission on one World borrow.
//!
//! This reusable capture prerequisite supplies no table reader or finality token.
//! Its required limits are local policy; refusals never become transaction gas
//! or validity. Semantic NFC scratch is prepaid for the complete sequential validation call.
//! Concrete signature/model helpers use borrowed fixed-error paths; their native
//! allocation census and the exact semantic codecs cover the registered readers.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
#[cfg(test)]
use crate::state::deserialize::musubi_source_read::MusubiSourceReadOnly;
use crate::state::deserialize::musubi_source_read::{MusubiRead, ReadFailure};
use iroha_allocation::AllocationBudget;
use iroha_data_model::musubi::source_work::{
    SourceGeometry, SourceGeometryError, SourceGeometryLimits, SourceShape,
};

/// Required independent local bounds for validation dependencies, not output rows.
#[derive(Clone, Copy, Debug)]
pub(in crate::state) struct SourceWorkLimits {
    /// Complete borrowed input geometry, including variable storage keys.
    pub geometry: SourceGeometryLimits,
    /// Rows admitted across explicit sequential table passes; excludes point lookups.
    pub table_pass_rows: u64,
    /// Total population of additional fixed-key evidence indexes searched by location checks.
    pub lookup_index_entries: u64,
    /// Sum of the named model/hash operations in the audited call graph.
    pub model_operations: u64,
    /// Maximum signature verifications across all repeated provider edges.
    pub signature_checks: u64,
}

impl SourceWorkLimits {
    /// Project only explicitly configured input-work authority, never memory or output.
    pub(in crate::state) const fn from_capture_policy(
        policy: iroha_config::parameters::actual::StateCapture,
    ) -> Self {
        Self {
            geometry: SourceGeometryLimits {
                elements: policy.source_elements,
                variable_bytes: policy.source_variable_bytes,
            },
            table_pass_rows: policy.source_table_pass_rows,
            lookup_index_entries: policy.source_lookup_index_entries,
            model_operations: policy.source_model_operations,
            signature_checks: policy.source_signature_checks,
        }
    }
}

/// Public-work dimension with no resource-release event or consensus meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum WorkDimension {
    TablePassRows,
    LookupIndexEntries,
    ModelOperations,
    SignatureChecks,
}

/// Original local work failure; no formatted string erases its resource kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum WorkRefusal {
    Geometry(SourceGeometryError),
    Limit {
        dimension: WorkDimension,
        requested: u64,
        limit: u64,
    },
    Overflow(WorkDimension),
}

/// Validation remains incomplete locally or completes with its original error.
#[derive(Debug)]
pub(in crate::state) enum SourceValidationError {
    Work(WorkRefusal),
    Attempt(ExecutionAttemptError<ProjectionRejection>),
}

impl std::fmt::Display for SourceValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Work(reason) => {
                write!(formatter, "Musubi source validation deferred: {reason:?}")
            }
            Self::Attempt(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for SourceValidationError {}

impl From<SourceGeometryError> for WorkRefusal {
    fn from(error: SourceGeometryError) -> Self {
        Self::Geometry(error)
    }
}

/// Named expensive operations in the audited existing validation graph.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
enum Operation {
    ArchiveValidation,
    LocationValidation,
    OrderBindingValidation,
    AttestationRecordValidation,
    AttestationValidation,
    AttestationDigest,
    SigningHash,
    ProviderSetDigest,
    AvailabilityValidation,
    PackageValidation,
    ResolverValidation,
    ReleaseValidation,
    DirectoryValidation,
    NamespaceScratchPlan,
}
const OPERATION_COUNT: usize = Operation::NamespaceScratchPlan as usize + 1;

struct Plan {
    limits: SourceWorkLimits,
    geometry: SourceGeometry,
    table_rows: u64,
    index_entries: u64,
    operations: u64,
    signatures: u64,
    nfc_scratch_bytes: usize,
    occurrences: [u64; OPERATION_COUNT],
}

impl Plan {
    fn new(limits: SourceWorkLimits) -> Self {
        Self {
            geometry: SourceGeometry::new(limits.geometry),
            limits,
            table_rows: 0,
            index_entries: 0,
            operations: 0,
            signatures: 0,
            nfc_scratch_bytes: 0,
            occurrences: [0; OPERATION_COUNT],
        }
    }
    #[cfg(test)]
    fn with_nfc_scratch<T>(
        &self,
        budget: &AllocationBudget,
        operation: impl FnOnce() -> Result<T, SourceValidationError>,
    ) -> Result<T, SourceValidationError> {
        let _scratch = self.nfc_scratch(budget)?;
        operation()
    }

    fn nfc_scratch(
        &self,
        budget: &AllocationBudget,
    ) -> Result<Option<iroha_allocation::AllocationReservation>, SourceValidationError> {
        // One peak spans all sequential Name checks, beside the original
        // directory/package scratch. It does not grant source/read authority.
        if self.nfc_scratch_bytes == 0 {
            return Ok(None);
        }
        budget
            .try_reserve_bytes(self.nfc_scratch_bytes)
            .map(Some)
            .map_err(|refusal| {
                SourceValidationError::Attempt(ExecutionAttemptError::Deferred(refusal.into()))
            })
    }

    fn add(&mut self, dimension: WorkDimension, count: usize) -> Result<(), WorkRefusal> {
        let count = u64::try_from(count).map_err(|_| WorkRefusal::Overflow(dimension))?;
        let (used, limit) = match dimension {
            WorkDimension::TablePassRows => (&mut self.table_rows, self.limits.table_pass_rows),
            WorkDimension::LookupIndexEntries => {
                (&mut self.index_entries, self.limits.lookup_index_entries)
            }
            WorkDimension::ModelOperations => (&mut self.operations, self.limits.model_operations),
            WorkDimension::SignatureChecks => (&mut self.signatures, self.limits.signature_checks),
        };
        let requested = used
            .checked_add(count)
            .ok_or(WorkRefusal::Overflow(dimension))?;
        if requested > limit {
            return Err(WorkRefusal::Limit {
                dimension,
                requested,
                limit,
            });
        }
        *used = requested;
        Ok(())
    }
    fn operation(&mut self, operation: Operation, count: usize) -> Result<(), WorkRefusal> {
        self.add(WorkDimension::ModelOperations, count)?;
        let count = u64::try_from(count)
            .map_err(|_| WorkRefusal::Overflow(WorkDimension::ModelOperations))?;
        let slot = &mut self.occurrences[operation as usize];
        *slot = slot
            .checked_add(count)
            .ok_or(WorkRefusal::Overflow(WorkDimension::ModelOperations))?;
        Ok(())
    }
    fn shape(&mut self, shape: SourceShape<'_>) -> Result<(), WorkRefusal> {
        self.geometry.admit(shape).map_err(WorkRefusal::from)
    }
}

/// Admit complete source geometry and every audited repeated operation first.
fn admit_passes<W: MusubiRead>(
    world: &W,
    plan: &mut Plan,
) -> Result<(), ReadFailure<W::Error, WorkRefusal>> {
    // Source predicates only reach these additional fixed-key indexes through
    // locations. Their retained population bounds point-lookup depth without
    // pretending unrelated payloads were visited or creating a new authority.
    if world
        .musubi_archive_locations_len()
        .map_err(ReadFailure::Source)?
        != 0
    {
        for count in [
            world
                .musubi_locations_by_pin_len()
                .map_err(ReadFailure::Source)?,
            world
                .musubi_locations_by_provider_len()
                .map_err(ReadFailure::Source)?,
            world
                .musubi_locations_by_replication_order_len()
                .map_err(ReadFailure::Source)?,
            world.pin_manifests_len().map_err(ReadFailure::Source)?,
            world
                .replication_orders_len()
                .map_err(ReadFailure::Source)?,
            world.provider_owners_len().map_err(ReadFailure::Source)?,
        ] {
            plan.add(WorkDimension::LookupIndexEntries, count)?;
        }
    }
    // Admit each pass explicitly, not an unexplained aggregate multiplier.
    // Shape admission plus the second location/evidence pass. Availability is
    // fixed-size, so its row allowance conservatively covers no shape traversal.
    for count in [
        world.musubi_archives_len().map_err(ReadFailure::Source)?,
        world
            .musubi_archive_availability_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_provider_bundle_attestations_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_archive_locations_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_resolver_index_len()
            .map_err(ReadFailure::Source)?,
        world.musubi_packages_len().map_err(ReadFailure::Source)?,
        world.musubi_releases_len().map_err(ReadFailure::Source)?,
        world
            .musubi_public_directory_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_archive_locations_len()
            .map_err(ReadFailure::Source)?,
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    // Live: attestations, locations, archives + merged locations, availability,
    // resolver revisions, directory-reference construction + merge, resolver merge.
    for count in [
        world
            .musubi_provider_bundle_attestations_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_archive_locations_len()
            .map_err(ReadFailure::Source)?,
        world.musubi_archives_len().map_err(ReadFailure::Source)?,
        world
            .musubi_archive_locations_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_archive_availability_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_resolver_index_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_public_directory_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_public_directory_len()
            .map_err(ReadFailure::Source)?,
        world
            .musubi_resolver_index_len()
            .map_err(ReadFailure::Source)?,
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    // Universal: package validation + initialization, resolver, release completeness,
    // directory, then complete package accumulator check.
    for count in [
        world.musubi_packages_len().map_err(ReadFailure::Source)?,
        world.musubi_packages_len().map_err(ReadFailure::Source)?,
        world
            .musubi_resolver_index_len()
            .map_err(ReadFailure::Source)?,
        world.musubi_releases_len().map_err(ReadFailure::Source)?,
        world
            .musubi_public_directory_len()
            .map_err(ReadFailure::Source)?,
        world.musubi_packages_len().map_err(ReadFailure::Source)?,
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    for (operation, count) in [
        (
            Operation::ArchiveValidation,
            world.musubi_archives_len().map_err(ReadFailure::Source)?,
        ),
        (
            Operation::LocationValidation,
            world
                .musubi_archive_locations_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::ProviderSetDigest,
            world
                .musubi_archive_locations_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::AttestationRecordValidation,
            world
                .musubi_provider_bundle_attestations_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::AttestationValidation,
            world
                .musubi_provider_bundle_attestations_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::AttestationDigest,
            world
                .musubi_provider_bundle_attestations_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::AvailabilityValidation,
            world
                .musubi_archive_availability_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::PackageValidation,
            world.musubi_packages_len().map_err(ReadFailure::Source)?,
        ),
        (
            Operation::ResolverValidation,
            world
                .musubi_resolver_index_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::ReleaseValidation,
            world
                .musubi_resolver_index_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::DirectoryValidation,
            world
                .musubi_public_directory_len()
                .map_err(ReadFailure::Source)?,
        ),
        (
            Operation::NamespaceScratchPlan,
            world.musubi_packages_len().map_err(ReadFailure::Source)?,
        ),
        (
            Operation::NamespaceScratchPlan,
            world
                .musubi_public_directory_len()
                .map_err(ReadFailure::Source)?,
        ),
    ] {
        plan.operation(operation, count)?;
    }
    Ok(())
}

#[path = "deserialize_world_musubi_source_work/admission.rs"]
mod admission;
pub(in crate::state) use admission::{Admission, AdmissionProgress};

#[cfg(test)]
fn admit(world: &impl MusubiSourceReadOnly, limits: SourceWorkLimits) -> Result<Plan, WorkRefusal> {
    try_admit(world, limits).map_err(ReadFailure::into_predicate)
}

fn try_admit<W: MusubiRead>(
    world: &W,
    limits: SourceWorkLimits,
) -> Result<Plan, ReadFailure<W::Error, WorkRefusal>> {
    let mut admission = Admission::new(limits);
    admission.advance(world)?;
    Ok(admission.into_plan())
}

#[path = "deserialize_world_musubi_source_observation.rs"]
pub(in crate::state) mod observation;

/// Validate and retain access to this exact World borrow after source-work admission.
///
/// The returned token binds semantic projection reads only. Original memory
/// refusals retain their pool identity. Physical State finality and publication
/// remain independent prerequisites; this validator cannot authorize a root.
pub(in crate::state) fn validate<'cut, W: observation::MusubiObservationCut>(
    world: &'cut W,
    execution_budget: &'cut AllocationBudget,
    limits: SourceWorkLimits,
) -> Result<observation::ValidatedMusubiSource<'cut, W>, SourceValidationError> {
    validate_read(world, execution_budget, limits, ProjectionCut::Capture)
        .map_err(ReadFailure::into_predicate)?;
    Ok(observation::ValidatedMusubiSource::new_validated(
        world,
        execution_budget,
    ))
}

/// Validate one same-owner original cut without erasing a physical read refusal.
/// This scoped call retains no success token across a changed source. Its caller
/// owns cumulative native work and any successful preceding cut; unfinished
/// semantic scratch still requires retained publication integration.
pub(in crate::state) fn validate_read<W: MusubiRead>(
    world: &W,
    execution_budget: &AllocationBudget,
    limits: SourceWorkLimits,
    cut: ProjectionCut,
) -> Result<(), ReadFailure<W::Error, SourceValidationError>> {
    let plan = try_admit(world, limits)
        .map_err(|error| error.map_predicate(SourceValidationError::Work))?;
    let _scratch = plan
        .nfc_scratch(execution_budget)
        .map_err(ReadFailure::Predicate)?;
    super::musubi_live::try_validate_musubi_live_projection_cut(world, execution_budget)
        .map_err(|error| error.map_predicate(SourceValidationError::Attempt))?;
    musubi_universal::try_validate_musubi_universal_projection_cut(world, cut, execution_budget)
        .map_err(|error| error.map_predicate(SourceValidationError::Attempt))?;
    Ok(())
}

#[cfg(test)]
#[path = "deserialize_world_musubi_source_work_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deserialize_world_musubi_source_work/nfc_tests.rs"]
mod nfc_tests;
