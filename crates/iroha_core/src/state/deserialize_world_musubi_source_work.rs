//! Bounded public source geometry and invocation admission on one World borrow.
//!
//! This reusable capture prerequisite supplies no table reader or finality token.
//! Its required limits are local policy; refusals never become transaction gas
//! or validity. Semantic NFC scratch is prepaid for the complete sequential validation call.
//! Concrete signature/model helpers use borrowed fixed-error paths; their native
//! allocation census and the exact semantic codecs cover the registered readers.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use crate::state::deserialize::musubi_source_read::MusubiSourceReadOnly;
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
    fn with_nfc_scratch<T>(
        &self,
        budget: &AllocationBudget,
        operation: impl FnOnce() -> Result<T, SourceValidationError>,
    ) -> Result<T, SourceValidationError> {
        // One peak spans all sequential Name checks and remains live alongside
        // directory/package scratch. ICU owns and frees each internal buffer
        // before returning; no normalization storage is retained in the token.
        let _scratch = if self.nfc_scratch_bytes == 0 {
            None
        } else {
            Some(
                budget
                    .try_reserve_bytes(self.nfc_scratch_bytes)
                    .map_err(|refusal| {
                        SourceValidationError::Attempt(ExecutionAttemptError::Deferred(
                            refusal.into(),
                        ))
                    })?,
            )
        };
        operation()
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
fn admit_passes(world: &impl MusubiSourceReadOnly, plan: &mut Plan) -> Result<(), WorkRefusal> {
    let archives = world.source_musubi_archives();
    let availability = world.source_musubi_archive_availability();
    let attestations = world.source_musubi_provider_bundle_attestations();
    let locations = world.source_musubi_archive_locations();
    let resolver = world.source_musubi_resolver_index();
    let packages = world.source_musubi_packages();
    let releases = world.source_musubi_releases();
    let directory = world.source_musubi_public_directory();
    // Source predicates only reach these additional fixed-key indexes through
    // locations. Their retained population bounds point-lookup depth without
    // pretending unrelated payloads were visited or creating a new authority.
    if !locations.is_empty() {
        for count in [
            world.source_musubi_locations_by_pin().len(),
            world.source_musubi_locations_by_provider().len(),
            world.source_musubi_locations_by_replication_order().len(),
            world.source_pin_manifests().len(),
            world.source_replication_orders().len(),
            world.source_provider_owners().len(),
        ] {
            plan.add(WorkDimension::LookupIndexEntries, count)?;
        }
    }
    // Admit each pass explicitly, not an unexplained aggregate multiplier.
    // Shape admission plus the second location/evidence pass. Availability is
    // fixed-size, so its row allowance conservatively covers no shape traversal.
    for count in [
        archives.len(),
        availability.len(),
        attestations.len(),
        locations.len(),
        resolver.len(),
        packages.len(),
        releases.len(),
        directory.len(),
        locations.len(),
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    // Live: attestations, locations, archives + merged locations, availability,
    // resolver revisions, directory-reference construction + merge, resolver merge.
    for count in [
        attestations.len(),
        locations.len(),
        archives.len(),
        locations.len(),
        availability.len(),
        resolver.len(),
        directory.len(),
        directory.len(),
        resolver.len(),
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    // Universal: package validation + initialization, resolver, release completeness,
    // directory, then complete package accumulator check.
    for count in [
        packages.len(),
        packages.len(),
        resolver.len(),
        releases.len(),
        directory.len(),
        packages.len(),
    ] {
        plan.add(WorkDimension::TablePassRows, count)?;
    }
    for (operation, count) in [
        (Operation::ArchiveValidation, archives.len()),
        (Operation::LocationValidation, locations.len()),
        (Operation::ProviderSetDigest, locations.len()),
        (Operation::AttestationRecordValidation, attestations.len()),
        (Operation::AttestationValidation, attestations.len()),
        (Operation::AttestationDigest, attestations.len()),
        (Operation::AvailabilityValidation, availability.len()),
        (Operation::PackageValidation, packages.len()),
        (Operation::ResolverValidation, resolver.len()),
        (Operation::ReleaseValidation, resolver.len()),
        (Operation::DirectoryValidation, directory.len()),
        (Operation::NamespaceScratchPlan, packages.len()),
        (Operation::NamespaceScratchPlan, directory.len()),
    ] {
        plan.operation(operation, count)?;
    }
    Ok(())
}

fn admit_source_shapes(
    world: &impl MusubiSourceReadOnly,
    plan: &mut Plan,
) -> Result<(), WorkRefusal> {
    let archives = world.source_musubi_archives();
    let attestations = world.source_musubi_provider_bundle_attestations();
    let locations = world.source_musubi_archive_locations();
    let resolver = world.source_musubi_resolver_index();
    let packages = world.source_musubi_packages();
    let releases = world.source_musubi_releases();
    let directory = world.source_musubi_public_directory();
    // Full payloads and variable keys are independent inputs, even when semantic
    // validation will reject a duplicated identity or an orphan row later.
    for (_, row) in archives.iter() {
        plan.shape(SourceShape::Archive(row))?;
    }
    for (_, row) in attestations.iter() {
        plan.shape(SourceShape::Attestation(row))?;
    }
    for (_, row) in locations.iter() {
        plan.shape(SourceShape::Location(row))?;
    }
    for (key, row) in packages.iter() {
        plan.shape(SourceShape::PackageId(key))?;
        plan.shape(SourceShape::Package(row))?;
        plan.nfc_scratch_bytes = plan
            .nfc_scratch_bytes
            .max(row.claimed_namespace.validation_scratch_bytes());
    }
    for (key, row) in releases.iter() {
        plan.shape(SourceShape::ReleaseId(key))?;
        plan.shape(SourceShape::Release(row))?;
    }
    for (key, row) in resolver.iter() {
        plan.shape(SourceShape::ReleaseId(key))?;
        plan.shape(SourceShape::Resolver(row))?;
    }
    for (key, row) in directory.iter() {
        plan.shape(SourceShape::Selector(key))?;
        plan.shape(SourceShape::Directory(row))?;
        plan.nfc_scratch_bytes = plan
            .nfc_scratch_bytes
            .max(row.selector.namespace.validation_scratch_bytes());
    }
    Ok(())
}

fn admit_current_evidence(
    world: &impl MusubiSourceReadOnly,
    plan: &mut Plan,
) -> Result<(), WorkRefusal> {
    let locations = world.source_musubi_archive_locations();
    let attestations = world.source_musubi_provider_bundle_attestations();
    for (_, location) in locations.iter() {
        if location.state == MusubiArchiveLocationStateV1::Retired {
            continue;
        }
        // current providers directly validates archive/location; binding and
        // attestation helpers each validate that archive once again.
        for operation in [
            Operation::ArchiveValidation,
            Operation::LocationValidation,
            Operation::ArchiveValidation,
            Operation::OrderBindingValidation,
            Operation::ArchiveValidation,
            Operation::LocationValidation,
            Operation::ProviderSetDigest,
        ] {
            plan.operation(operation, 1)?;
        }
        if let Some(row) = world
            .source_musubi_locations_by_replication_order()
            .get(&location.replication_order)
        {
            plan.shape(SourceShape::OrderBinding(row))?;
        }
        if let Some(row) = world.source_pin_manifests().get(&location.pin_manifest) {
            plan.shape(SourceShape::Pin(row))?;
        }
        if let Some(row) = world
            .source_replication_orders()
            .get(&location.replication_order)
        {
            plan.shape(SourceShape::Order(row))?;
        }
        // The complete provider shape was admitted above. Its repeated traversals
        // belong to the named operation graph; signature calls are never deduplicated.
        for provider in &location.providers {
            if let Some(owner) = world.source_provider_owners().get(provider) {
                plan.shape(SourceShape::Account(owner))?;
            }
            let key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: location.archive_id,
                replication_order: location.replication_order,
                provider_id: *provider,
            };
            if let Some(record) = attestations.get(&key) {
                for operation in [
                    Operation::AttestationRecordValidation,
                    Operation::AttestationValidation,
                    Operation::AttestationDigest,
                    Operation::AttestationValidation,
                    Operation::SigningHash,
                    Operation::AttestationDigest,
                ] {
                    plan.operation(operation, 1)?;
                }
                plan.add(
                    WorkDimension::SignatureChecks,
                    record.attestation.approvals.len(),
                )?;
            }
        }
    }
    Ok(())
}

fn admit(world: &impl MusubiSourceReadOnly, limits: SourceWorkLimits) -> Result<Plan, WorkRefusal> {
    let mut plan = Plan::new(limits);
    admit_passes(world, &mut plan)?;
    admit_source_shapes(world, &mut plan)?;
    admit_current_evidence(world, &mut plan)?;
    Ok(plan)
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
    let plan = admit(world, limits).map_err(SourceValidationError::Work)?;
    plan.with_nfc_scratch(execution_budget, || {
        validate_musubi_live_projection_cut(world, execution_budget)
            .map_err(SourceValidationError::Attempt)?;
        musubi_universal::validate_musubi_universal_projection_cut(
            world,
            ProjectionCut::Capture,
            execution_budget,
        )
        .map_err(SourceValidationError::Attempt)?;
        Ok(observation::ValidatedMusubiSource::new_validated(
            world,
            execution_budget,
        ))
    })
}

#[cfg(test)]
#[path = "deserialize_world_musubi_source_work_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deserialize_world_musubi_source_work/nfc_tests.rs"]
mod nfc_tests;
