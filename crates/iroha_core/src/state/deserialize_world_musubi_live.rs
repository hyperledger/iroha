//! Existing live Musubi projection validation over one immutable World borrow.
//!
//! Archive-local provider and location-directory scratch uses fixed V1 capacities.
//! The availability pass consumes one ordered location cursor, including all
//! retained retired rows, rather than scanning the complete location table once
//! per archive.
//! The separate attestation pass still visits every stored attestation/location.
//! Source capture separately admits complete borrowed geometry and invocation
//! work before these validators. Directory/revision and universal package scratch
//! use the original execution pool. Static rejection descriptors do not allocate.
//! TODO: retain typed original-pool custody through semantic Unicode scratch,
//! codec failures, provider instruction errors, and signature backend workspaces.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use crate::state::deserialize::musubi_source_read::{
    MusubiRead, MusubiSourceReadOnly, ReadFailure, next_if_row,
};
use iroha_allocation::AllocationBudget;

#[path = "deserialize_world_musubi_revisions.rs"]
pub(in crate::state) mod revisions;
use iroha_data_model::{
    musubi::{
        MUSUBI_MAX_ARCHIVE_LOCATIONS_V1, MUSUBI_MAX_LOCATION_PROVIDERS_V1,
        MusubiProviderBundleAttestationDigestV1,
    },
    sorafs::capacity::ProviderId,
};

impl<E> From<ProjectionRejection> for ReadFailure<E, ExecutionAttemptError<ProjectionRejection>> {
    fn from(original: ProjectionRejection) -> Self {
        Self::Predicate(original.into())
    }
}

const MAX_PROVIDER_OCCURRENCES: usize =
    MUSUBI_MAX_ARCHIVE_LOCATIONS_V1 * MUSUBI_MAX_LOCATION_PROVIDERS_V1;

/// Deduplicate only the protocol-bounded provider occurrences of one archive.
#[derive(Clone, Copy)]
struct CurrentProviderSet {
    values: [ProviderId; MAX_PROVIDER_OCCURRENCES],
    len: usize,
}

impl CurrentProviderSet {
    fn new() -> Self {
        Self {
            values: [ProviderId::new([0; 32]); MAX_PROVIDER_OCCURRENCES],
            len: 0,
        }
    }

    fn insert(&mut self, provider: ProviderId) -> Result<(), ProjectionRejection> {
        if self.values[..self.len].contains(&provider) {
            return Ok(());
        }
        let Some(slot) = self.values.get_mut(self.len) else {
            return Err(ProjectionRejection::new(
                ProjectionTable::ArchiveAvailability,
                "healthy provider count exceeds the V1 location capacity",
            ));
        };
        *slot = provider;
        self.len += 1;
        Ok(())
    }
}

pub(super) fn validate_musubi_live_projections(
    world: &World,
    execution_budget: &AllocationBudget,
) -> Result<(), StateRestoreError> {
    validate_musubi_live_projection_cut(&world.view(), execution_budget).map_err(|error| {
        error.map_rejection(|error| error.with_cut(ProjectionCut::Current).into_json())
    })?;
    validate_musubi_live_projection_cut(
        &world.try_block_and_revert(execution_budget)?,
        execution_budget,
    )
    .map_err(|error| {
        error.map_rejection(|error| error.with_cut(ProjectionCut::Predecessor).into_json())
    })
    .map_err(Into::into)
}

/// Verify one World cut's live Musubi availability against its SoraFS evidence.
///
/// The publication owner calls this after its last deterministic World write;
/// restore calls it separately for the current and rollback-visible cuts.
pub(in crate::state) fn validate_musubi_live_projection_cut(
    world: &impl MusubiSourceReadOnly,
    execution_budget: &AllocationBudget,
) -> Result<(), ExecutionAttemptError<ProjectionRejection>> {
    try_validate_musubi_live_projection_cut(world, execution_budget)
        .map_err(ReadFailure::into_predicate)
}

/// The same live predicate preserves each actual source-owner refusal.
pub(in crate::state) fn try_validate_musubi_live_projection_cut<W: MusubiRead>(
    world: &W,
    execution_budget: &AllocationBudget,
) -> Result<(), ReadFailure<W::Error, ExecutionAttemptError<ProjectionRejection>>> {
    LiveValidation::new().advance(world)?;
    revisions::validate_directory_revisions(world, execution_budget)
}

/// Original live predicate progress; this alone grants no table/root authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct LiveProgress {
    /// Attestations, locations, availability construction, availability rows, resolver rows, complete.
    pub phase: u8,
    /// Next source row in the current pass.
    pub row: usize,
    /// Completed local model substep for the current row.
    pub step: u8,
    /// Next provider edge in the retained location evidence pass.
    pub provider: usize,
    /// Number of original location rows consumed by the ordered archive merge.
    pub location: usize,
    /// Whether all live predicates except the separate directory merge completed.
    pub complete: bool,
}

/// One immutable image's live predicate and bounded in-progress location evidence.
pub(in crate::state) struct LiveValidation {
    queries: [crate::state::deserialize::musubi_source_read::LookupCursor; 2],
    phase: u8,
    row: usize,
    step: u8,
    provider: usize,
    references: [MusubiProviderBundleAttestationRefV1; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
    verification_lock_digest: Option<iroha_data_model::musubi::MusubiVerificationLockDigestV1>,
    location: usize,
    location_started: bool,
    current: crate::smartcontracts::isi::musubi::CurrentProviderValidation,
    active_locations: usize,
    healthy_providers: CurrentProviderSet,
    maximum_location_revision: u64,
    current_location_count: usize,
    rejected: Option<ProjectionRejection>,
}
impl LiveValidation {
    /// Begin without reading any source or granting memory/work credit.
    pub(in crate::state) fn new() -> Self {
        Self {
            phase: 0,
            queries: [crate::state::deserialize::musubi_source_read::LookupCursor::new(); 2],
            row: 0,
            step: 0,
            provider: 0,
            references: [MusubiProviderBundleAttestationRefV1 {
                provider_id: ProviderId::new([0; 32]),
                digest: MusubiProviderBundleAttestationDigestV1::new([0; 32]),
            }; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
            verification_lock_digest: None,
            location: 0,
            location_started: false,
            current: crate::smartcontracts::isi::musubi::CurrentProviderValidation::new(),
            active_locations: 0,
            healthy_providers: CurrentProviderSet::new(),
            maximum_location_revision: 1,
            current_location_count: 0,
            rejected: None,
        }
    }
    /// Observe the retained original cursor without any native read.
    pub(in crate::state) fn progress(&self) -> LiveProgress {
        LiveProgress {
            phase: self.phase,
            row: self.row,
            step: self.step,
            provider: self.provider,
            location: self.location,
            complete: self.phase == 5,
        }
    }
    fn next_phase(&mut self) {
        self.phase += 1;
        self.row = 0;
        self.step = 0;
    }
    /// Continue the same live predicate on the same immutable original source.
    pub(in crate::state) fn advance<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<(), ReadFailure<W::Error, ExecutionAttemptError<ProjectionRejection>>> {
        if let Some(original) = self.rejected {
            return Err(original.into());
        }
        if self.phase == 5 {
            return Ok(());
        }
        let result = self.advance_inner(world);
        if let Err(ReadFailure::Predicate(ExecutionAttemptError::Rejected(original))) = &result {
            self.rejected = Some(*original);
        }
        result
    }
    fn advance_inner<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<(), ReadFailure<W::Error, ExecutionAttemptError<ProjectionRejection>>> {
        if self.phase == 0 {
            for original_row in world
                .musubi_provider_bundle_attestations_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (key, record) = original_row.map_err(ReadFailure::Source)?;
                if self.step == 0 {
                    record.validate().map_err(|error| {
                        ProjectionRejection::new(
                            ProjectionTable::ProviderBundleAttestations,
                            error.reason(),
                        )
                    })?;
                    self.step = 1;
                }
                let archive = world
                    .musubi_archives_get_retained(&key.archive_id, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        ProjectionRejection::new(
                            ProjectionTable::ProviderBundleAttestations,
                            "provider attestation references a missing archive",
                        )
                    })?;
                let binding = &record.attestation.payload.binding;
                let ingress = &archive.staging_receipt.payload.binding;
                if key != &record.key
                    || record.registered_at_height < archive.registered_at_height
                    || binding.network_id != ingress.network_id
                    || binding.archive_id != archive.archive_id
                    || binding.bundle_digest != archive.commitment.bundle_digest
                    || binding.descriptor_digest != archive.commitment.descriptor_digest
                    || binding.semantic_release_manifest_digest
                        != ingress.semantic_release_manifest_digest
                    || binding.source_tree_digest != archive.commitment.source_tree_digest
                {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::ProviderBundleAttestations,
                        "provider attestation disagrees with its key, archive, or ingress receipt",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.step = 0;
            }
            self.next_phase();
        }
        if self.phase == 1 {
            for original_row in world
                .musubi_archive_locations_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (key, location) = original_row.map_err(ReadFailure::Source)?;
                if self.step == 0 {
                    location.validate().map_err(|error| {
                        ProjectionRejection::new(ProjectionTable::ArchiveLocations, error.reason())
                    })?;
                    self.step = 1;
                }
                let archive = world
                    .musubi_archives_get_retained(&location.archive_id, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        ProjectionRejection::new(
                            ProjectionTable::ArchiveLocations,
                            "archive location references a missing archive",
                        )
                    })?;
                if key != &location.key() || location.revision > archive.location_revision {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::ArchiveLocations,
                        "archive-location key or revision is inconsistent with its archive",
                    )
                    .into());
                }
                for (index, provider_id) in
                    location.providers.iter().enumerate().skip(self.provider)
                {
                    let attestation_key = MusubiProviderBundleAttestationKeyV1 {
                        archive_id: location.archive_id,
                        replication_order: location.replication_order,
                        provider_id: *provider_id,
                    };
                    let record = world
                        .musubi_provider_bundle_attestations_get_retained(
                            &attestation_key,
                            &mut self.queries[1],
                        )
                        .map_err(ReadFailure::Source)?
                        .ok_or_else(|| {
                            ProjectionRejection::new(
                                ProjectionTable::ArchiveLocations,
                                "archive location references a missing exact provider attestation",
                            )
                        })?;
                    let digest = record.attestation.payload.binding.verification_lock_digest;
                    if self
                        .verification_lock_digest
                        .is_some_and(|expected| expected != digest)
                    {
                        return Err(ProjectionRejection::new(
                    ProjectionTable::ArchiveLocations,
                    "archive-location provider attestations disagree on the verification lock",
                )
                .into());
                    }
                    self.verification_lock_digest = Some(digest);
                    self.references[index] = MusubiProviderBundleAttestationRefV1 {
                        provider_id: *provider_id,
                        digest: record.attestation_digest,
                    };
                    self.provider += 1;
                    self.queries[1].reset();
                }
                let expected_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
                    location.archive_id,
                    location.replication_order,
                    &self.references[..location.providers.len()],
                )
                .map_err(|error| {
                    ProjectionRejection::new(ProjectionTable::ArchiveLocations, error.reason())
                })?;
                if location.provider_attestation_set_digest != expected_set_digest {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::ArchiveLocations,
                        "archive-location provider-attestation set digest is not exact",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.step = 0;
                self.provider = 0;
                self.verification_lock_digest = None;
            }
            self.next_phase();
        }
        if self.phase == 2 {
            let mut locations = world
                .musubi_archive_locations_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.location)
                .peekable();
            for original_row in world
                .musubi_archives_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (archive_id, archive) = original_row.map_err(ReadFailure::Source)?;
                if self.step == 0 {
                    archive.validate().map_err(|error| {
                        ProjectionRejection::new(ProjectionTable::Archives, error.reason())
                    })?;
                    if archive_id != &archive.archive_id {
                        return Err(ProjectionRejection::new(
                            ProjectionTable::Archives,
                            "archive lookup key differs from its canonical identity",
                        )
                        .into());
                    }
                    self.step = 1;
                }
                while let Some((key, location)) =
                    next_if_row(&mut locations, |(key, _)| key.archive_id == *archive_id)
                        .map_err(ReadFailure::Source)?
                {
                    if !self.location_started {
                        self.maximum_location_revision =
                            self.maximum_location_revision.max(location.revision);
                        if location.state == MusubiArchiveLocationStateV1::Retired {
                            self.location += 1;
                            continue;
                        }
                        if archive
                            .location_ids
                            .binary_search(&key.location_id)
                            .is_err()
                        {
                            return Err(ProjectionRejection::new(
                                ProjectionTable::ArchiveLocations,
                                "non-retired location is absent from its archive directory",
                            )
                            .into());
                        }
                        self.current_location_count += 1;
                        self.location_started = true;
                    }
                    let current = self
                        .current
                        .advance(location, world)
                        .map_err(ReadFailure::Source)?;
                    let current_count = current.as_ref().map_or(0, |providers| providers.len());
                    let expected_state = if current_count
                        >= usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
                    {
                        MusubiArchiveLocationStateV1::Healthy
                    } else {
                        MusubiArchiveLocationStateV1::Degraded
                    };
                    if location.state != expected_state {
                        return Err(ProjectionRejection::new(
                    ProjectionTable::ArchiveLocations,
                    "archive-location lifecycle state disagrees with current SoraFS evidence",
                )
                .into());
                    }
                    if let Some(providers) = current {
                        self.active_locations =
                            self.active_locations.checked_add(1).ok_or_else(|| {
                                ProjectionRejection::new(
                                    ProjectionTable::ArchiveAvailability,
                                    "active archive-location count overflows usize",
                                )
                            })?;
                        for provider in providers {
                            // At most four exact current locations each admit at most
                            // 64 providers. Deduplication retains only these identities.
                            self.healthy_providers.insert(provider)?;
                        }
                    }
                    self.location += 1;
                    self.location_started = false;
                    self.current =
                        crate::smartcontracts::isi::musubi::CurrentProviderValidation::new();
                }
                // Canonical unique table keys and the membership checks above make
                // equal cardinality sufficient for exact directory equality. Retired
                // rows contribute to revision checks but not this current set.
                if self.current_location_count != archive.location_ids.len() {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::Archives,
                        "archive directory is not the exact non-retired location set",
                    )
                    .into());
                }
                if archive.location_revision != self.maximum_location_revision {
                    return Err(ProjectionRejection::new(
                ProjectionTable::Archives,
                "archive location revision is not the exact maximum retained location revision",
            )
            .into());
                }
                let active_locations = u8::try_from(self.active_locations).map_err(|_| {
                    ProjectionRejection::new(
                        ProjectionTable::ArchiveAvailability,
                        "active archive-location count overflows u8",
                    )
                })?;
                let healthy_replicas = u16::try_from(self.healthy_providers.len).map_err(|_| {
                    ProjectionRejection::new(
                        ProjectionTable::ArchiveAvailability,
                        "healthy provider count overflows u16",
                    )
                })?;
                let expected_availability = if healthy_replicas
                    >= iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1
                {
                    iroha_data_model::musubi::MusubiStorageAvailabilityV1::Selectable
                } else if active_locations > 0 && healthy_replicas > 0 {
                    iroha_data_model::musubi::MusubiStorageAvailabilityV1::BelowQuorum
                } else {
                    iroha_data_model::musubi::MusubiStorageAvailabilityV1::Unavailable
                };
                let projection = world
                    .musubi_archive_availability_get_retained(archive_id, &mut self.queries[0])
                    .map_err(ReadFailure::Source)?
                    .ok_or_else(|| {
                        ProjectionRejection::new(
                            ProjectionTable::ArchiveAvailability,
                            "archive is missing its availability projection",
                        )
                    })?;
                if projection.active_locations != active_locations
                    || projection.healthy_replicas != healthy_replicas
                    || projection.availability != expected_availability
                {
                    return Err(ProjectionRejection::new(
                ProjectionTable::ArchiveAvailability,
                "availability projection is not the exact result of current SoraFS evidence",
            )
            .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.step = 0;
                self.active_locations = 0;
                self.healthy_providers = CurrentProviderSet::new();
                self.maximum_location_revision = 1;
                self.current_location_count = 0;
            }
            self.next_phase();
        }
        if self.phase == 3 {
            for original_row in world
                .musubi_archive_availability_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (archive_id, projection) = original_row.map_err(ReadFailure::Source)?;
                if archive_id != &projection.archive_id
                    || world
                        .musubi_archives_get_retained(archive_id, &mut self.queries[0])
                        .map_err(ReadFailure::Source)?
                        .is_none()
                    || projection.validate().is_err()
                {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::ArchiveAvailability,
                        "availability row is invalid or has no exact archive source",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
            }
            self.next_phase();
        }
        if self.phase == 4 {
            for original_row in world
                .musubi_resolver_index_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.row)
            {
                let (_, row) = original_row.map_err(ReadFailure::Source)?;
                if row.index_revision < row.selection.storage.index_revision {
                    return Err(ProjectionRejection::new(
                        ProjectionTable::ResolverIndex,
                        "resolver row predates its embedded availability projection",
                    )
                    .into());
                }
                self.row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
            }
            self.next_phase();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_provider_set_deduplicates_and_refuses_growth_after_the_exact_v1_capacity() {
        let mut providers = CurrentProviderSet::new();
        for index in 0..MAX_PROVIDER_OCCURRENCES {
            let mut bytes = [0x61; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let provider = ProviderId::new(bytes);
            providers.insert(provider).unwrap();
            providers.insert(provider).unwrap();
            assert_eq!(providers.len, index + 1);
        }
        let original = providers;
        assert!(providers.insert(ProviderId::new([0xff; 32])).is_err());
        assert_eq!(providers.values, original.values);
        assert_eq!(providers.len, original.len);
        assert!(
            std::mem::size_of_val(&providers)
                <= MAX_PROVIDER_OCCURRENCES * std::mem::size_of::<ProviderId>()
                    + std::mem::size_of::<usize>()
        );
    }
}
