//! Narrow native sources for the existing Musubi semantic predicates.
//!
//! Retains exactly fourteen original table generations and one original Copy
//! revision. Acquisition creates no full WorldView, catalog, row copy or epoch
//! collector participant. This local source cut does not establish State finality.

use super::super::*;
use mv::{PublicationPreparationError, cell::CommittedCellCopy, storage::CommittedStorageView};
use std::convert::Infallible;

#[path = "deserialize_world_musubi_source_traits.rs"]
mod source_traits;
pub(crate) use source_traits::{
    MusubiSourceReadOnly,
    access::{KeyWorkCursor, LookupCursor, MusubiRead, ReadFailure, next_if_row, try_next_if_row},
};

/// An original source acquisition refusal, separate from semantic validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::state) struct MusubiSourceAcquisitionError {
    /// Exact declared physical source whose acquisition did not complete.
    pub(in crate::state) field: &'static str,
    /// The original Busy release, poison, or changed-publication reason.
    pub(in crate::state) original: PublicationPreparationError<Infallible>,
}
impl std::fmt::Display for MusubiSourceAcquisitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Musubi original source {} unavailable: {:?}",
            self.field, self.original
        )
    }
}
impl std::error::Error for MusubiSourceAcquisitionError {}
fn refusal(
    field: &'static str,
    original: PublicationPreparationError<Infallible>,
) -> MusubiSourceAcquisitionError {
    MusubiSourceAcquisitionError { field, original }
}

/// Original State-owned native sources retained at one checked publication cut.
pub(in crate::state) struct StateMusubiSourceCut<'state> {
    state: &'state State,
    generation: u64,
    musubi_archives: CommittedStorageView<'state, ArchiveId, MusubiArchiveRecordV1>,
    musubi_archive_availability:
        CommittedStorageView<'state, ArchiveId, MusubiArchiveAvailabilityV1>,
    musubi_archive_locations:
        CommittedStorageView<'state, MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1>,
    musubi_locations_by_pin:
        CommittedStorageView<'state, ManifestDigest, MusubiPinLocationReferenceV1>,
    musubi_locations_by_provider: CommittedStorageView<'state, MusubiProviderLocationKeyV1, ()>,
    musubi_locations_by_replication_order:
        CommittedStorageView<'state, ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1>,
    musubi_packages: CommittedStorageView<'state, MusubiPackageIdV1, MusubiPackageRecordV1>,
    musubi_provider_bundle_attestations: CommittedStorageView<
        'state,
        MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationRecordV1,
    >,
    musubi_public_directory:
        CommittedStorageView<'state, MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1>,
    musubi_releases: CommittedStorageView<'state, MusubiReleaseIdV1, MusubiReleaseRecordV1>,
    musubi_resolver_index:
        CommittedStorageView<'state, MusubiReleaseIdV1, MusubiResolverReleaseRowV1>,
    pin_manifests: CommittedStorageView<'state, ManifestDigest, PinManifestRecord>,
    provider_owners: CommittedStorageView<'state, ProviderId, AccountId>,
    replication_orders: CommittedStorageView<'state, ReplicationOrderId, ReplicationOrderRecord>,
    revision: CommittedCellCopy<MusubiResolverIndexRevisionV1>,
}
impl<'state> StateMusubiSourceCut<'state> {
    /// Capture original generations once, returning retry on State publication.
    /// No wait loop, source reconstruction, or unrelated state mutation occurs.
    pub(in crate::state) fn try_capture(
        state: &'state State,
    ) -> Result<Option<Self>, MusubiSourceAcquisitionError> {
        let generation = state.state_view_generation();
        if generation & 1 != 0 {
            return Ok(None);
        }
        let cut = Self {
            state,
            generation,
            musubi_archives: state
                .world
                .musubi_archives
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_archives", e))?,
            musubi_archive_availability: state
                .world
                .musubi_archive_availability
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_archive_availability", e))?,
            musubi_archive_locations: state
                .world
                .musubi_archive_locations
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_archive_locations", e))?,
            musubi_locations_by_pin: state
                .world
                .musubi_locations_by_pin
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_locations_by_pin", e))?,
            musubi_locations_by_provider: state
                .world
                .musubi_locations_by_provider
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_locations_by_provider", e))?,
            musubi_locations_by_replication_order: state
                .world
                .musubi_locations_by_replication_order
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_locations_by_replication_order", e))?,
            musubi_packages: state
                .world
                .musubi_packages
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_packages", e))?,
            musubi_provider_bundle_attestations: state
                .world
                .musubi_provider_bundle_attestations
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_provider_bundle_attestations", e))?,
            musubi_public_directory: state
                .world
                .musubi_public_directory
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_public_directory", e))?,
            musubi_releases: state
                .world
                .musubi_releases
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_releases", e))?,
            musubi_resolver_index: state
                .world
                .musubi_resolver_index
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.musubi_resolver_index", e))?,
            pin_manifests: state
                .world
                .pin_manifests
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.pin_manifests", e))?,
            provider_owners: state
                .world
                .provider_owners
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.provider_owners", e))?,
            replication_orders: state
                .world
                .replication_orders
                .try_committed_view_nonblocking()
                .map_err(|e| refusal("world.replication_orders", e))?,
            revision: state
                .world
                .musubi_resolver_index_revision
                .try_committed_copy()
                .map_err(|e| refusal("world.musubi_resolver_index_revision", e))?,
        };
        if !cut.try_matches_current()? {
            return Ok(None);
        }
        Ok(Some(cut))
    }
    /// Recheck opaque original identities, never equal values or caller roots.
    /// Both passes bracket the complete capture, so all retained generations
    /// coexist at the end of the first pass. Retaining identities prevents ABA.
    pub(in crate::state) fn try_matches_current(
        &self,
    ) -> Result<bool, MusubiSourceAcquisitionError> {
        if !is_stable_state_view_generation(self.generation, self.state.state_view_generation()) {
            return Ok(false);
        }
        if !self
            .musubi_archives
            .try_matches_current(&self.state.world.musubi_archives)
            .map_err(|e| refusal("world.musubi_archives", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_archive_availability
            .try_matches_current(&self.state.world.musubi_archive_availability)
            .map_err(|e| refusal("world.musubi_archive_availability", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_archive_locations
            .try_matches_current(&self.state.world.musubi_archive_locations)
            .map_err(|e| refusal("world.musubi_archive_locations", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_locations_by_pin
            .try_matches_current(&self.state.world.musubi_locations_by_pin)
            .map_err(|e| refusal("world.musubi_locations_by_pin", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_locations_by_provider
            .try_matches_current(&self.state.world.musubi_locations_by_provider)
            .map_err(|e| refusal("world.musubi_locations_by_provider", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_locations_by_replication_order
            .try_matches_current(&self.state.world.musubi_locations_by_replication_order)
            .map_err(|e| refusal("world.musubi_locations_by_replication_order", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_packages
            .try_matches_current(&self.state.world.musubi_packages)
            .map_err(|e| refusal("world.musubi_packages", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_provider_bundle_attestations
            .try_matches_current(&self.state.world.musubi_provider_bundle_attestations)
            .map_err(|e| refusal("world.musubi_provider_bundle_attestations", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_public_directory
            .try_matches_current(&self.state.world.musubi_public_directory)
            .map_err(|e| refusal("world.musubi_public_directory", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_releases
            .try_matches_current(&self.state.world.musubi_releases)
            .map_err(|e| refusal("world.musubi_releases", e))?
        {
            return Ok(false);
        }
        if !self
            .musubi_resolver_index
            .try_matches_current(&self.state.world.musubi_resolver_index)
            .map_err(|e| refusal("world.musubi_resolver_index", e))?
        {
            return Ok(false);
        }
        if !self
            .pin_manifests
            .try_matches_current(&self.state.world.pin_manifests)
            .map_err(|e| refusal("world.pin_manifests", e))?
        {
            return Ok(false);
        }
        if !self
            .provider_owners
            .try_matches_current(&self.state.world.provider_owners)
            .map_err(|e| refusal("world.provider_owners", e))?
        {
            return Ok(false);
        }
        if !self
            .replication_orders
            .try_matches_current(&self.state.world.replication_orders)
            .map_err(|e| refusal("world.replication_orders", e))?
        {
            return Ok(false);
        }
        if !self
            .revision
            .try_matches_current(&self.state.world.musubi_resolver_index_revision)
            .map_err(|e| refusal("world.musubi_resolver_index_revision", e))?
        {
            return Ok(false);
        }
        Ok(is_stable_state_view_generation(
            self.generation,
            self.state.state_view_generation(),
        ))
    }
}
impl MusubiSourceReadOnly for StateMusubiSourceCut<'_> {
    fn source_musubi_archives(&self) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveRecordV1> {
        &self.musubi_archives
    }
    fn source_musubi_archive_availability(
        &self,
    ) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveAvailabilityV1> {
        &self.musubi_archive_availability
    }
    fn source_musubi_archive_locations(
        &self,
    ) -> &impl StorageReadOnly<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1> {
        &self.musubi_archive_locations
    }
    fn source_musubi_locations_by_pin(
        &self,
    ) -> &impl StorageReadOnly<ManifestDigest, MusubiPinLocationReferenceV1> {
        &self.musubi_locations_by_pin
    }
    fn source_musubi_locations_by_provider(
        &self,
    ) -> &impl StorageReadOnly<MusubiProviderLocationKeyV1, ()> {
        &self.musubi_locations_by_provider
    }
    fn source_musubi_locations_by_replication_order(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1> {
        &self.musubi_locations_by_replication_order
    }
    fn source_musubi_packages(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageIdV1, MusubiPackageRecordV1> {
        &self.musubi_packages
    }
    fn source_musubi_provider_bundle_attestations(
        &self,
    ) -> &impl StorageReadOnly<
        MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationRecordV1,
    > {
        &self.musubi_provider_bundle_attestations
    }
    fn source_musubi_public_directory(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1> {
        &self.musubi_public_directory
    }
    fn source_musubi_releases(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiReleaseRecordV1> {
        &self.musubi_releases
    }
    fn source_musubi_resolver_index(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiResolverReleaseRowV1> {
        &self.musubi_resolver_index
    }
    fn source_pin_manifests(&self) -> &impl StorageReadOnly<ManifestDigest, PinManifestRecord> {
        &self.pin_manifests
    }
    fn source_provider_owners(&self) -> &impl StorageReadOnly<ProviderId, AccountId> {
        &self.provider_owners
    }
    fn source_replication_orders(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, ReplicationOrderRecord> {
        &self.replication_orders
    }
    fn source_musubi_resolver_index_revision(&self) -> u64 {
        self.revision.current().get()
    }
}

#[cfg(test)]
#[path = "deserialize_world_musubi_source_read_tests.rs"]
mod tests;
