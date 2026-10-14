//! Shared original table borrowing contract for Musubi semantic predicates.
//!
//! The native State cut and ordinary World readers implement this same contract;
//! standalone allocation tests include this exact owner rather than a copied shim.

use super::WorldReadOnly;
use iroha_data_model::account::AccountId;
use iroha_data_model::{
    musubi::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ManifestDigest, PinManifestRecord, ReplicationOrderId, ReplicationOrderRecord,
        },
    },
};
use mv::storage::StorageReadOnly;

/// Read-only dependencies of the existing live and universal Musubi predicates.
/// General native World readers forward the same sources; the closed State cut
/// below retains only this enumerated dependency set.
pub trait MusubiSourceReadOnly {
    /// Borrow original `musubi_archives` rows, never caller-supplied projections.
    fn source_musubi_archives(&self) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveRecordV1>;
    /// Borrow original `musubi_archive_availability` rows, never caller-supplied projections.
    fn source_musubi_archive_availability(
        &self,
    ) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveAvailabilityV1>;
    /// Borrow original `musubi_archive_locations` rows, never caller-supplied projections.
    fn source_musubi_archive_locations(
        &self,
    ) -> &impl StorageReadOnly<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1>;
    /// Borrow original `musubi_locations_by_pin` rows, never caller-supplied projections.
    fn source_musubi_locations_by_pin(
        &self,
    ) -> &impl StorageReadOnly<ManifestDigest, MusubiPinLocationReferenceV1>;
    /// Borrow original `musubi_locations_by_provider` rows, never caller-supplied projections.
    fn source_musubi_locations_by_provider(
        &self,
    ) -> &impl StorageReadOnly<MusubiProviderLocationKeyV1, ()>;
    /// Borrow original `musubi_locations_by_replication_order` rows, never caller-supplied projections.
    fn source_musubi_locations_by_replication_order(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1>;
    /// Borrow original `musubi_packages` rows, never caller-supplied projections.
    fn source_musubi_packages(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageIdV1, MusubiPackageRecordV1>;
    /// Borrow original `musubi_provider_bundle_attestations` rows, never caller-supplied projections.
    fn source_musubi_provider_bundle_attestations(
        &self,
    ) -> &impl StorageReadOnly<
        MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationRecordV1,
    >;
    /// Borrow original `musubi_public_directory` rows, never caller-supplied projections.
    fn source_musubi_public_directory(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1>;
    /// Borrow original `musubi_releases` rows, never caller-supplied projections.
    fn source_musubi_releases(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiReleaseRecordV1>;
    /// Borrow original `musubi_resolver_index` rows, never caller-supplied projections.
    fn source_musubi_resolver_index(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiResolverReleaseRowV1>;
    /// Borrow original `pin_manifests` rows, never caller-supplied projections.
    fn source_pin_manifests(&self) -> &impl StorageReadOnly<ManifestDigest, PinManifestRecord>;
    /// Borrow original `provider_owners` rows, never caller-supplied projections.
    fn source_provider_owners(&self) -> &impl StorageReadOnly<ProviderId, AccountId>;
    /// Borrow original `replication_orders` rows, never caller-supplied projections.
    fn source_replication_orders(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, ReplicationOrderRecord>;
    /// Read the independently retained resolver revision.
    fn source_musubi_resolver_index_revision(&self) -> u64;
}

impl<W: WorldReadOnly> MusubiSourceReadOnly for W {
    fn source_musubi_archives(&self) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveRecordV1> {
        WorldReadOnly::musubi_archives(self)
    }
    fn source_musubi_archive_availability(
        &self,
    ) -> &impl StorageReadOnly<ArchiveId, MusubiArchiveAvailabilityV1> {
        WorldReadOnly::musubi_archive_availability(self)
    }
    fn source_musubi_archive_locations(
        &self,
    ) -> &impl StorageReadOnly<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1> {
        WorldReadOnly::musubi_archive_locations(self)
    }
    fn source_musubi_locations_by_pin(
        &self,
    ) -> &impl StorageReadOnly<ManifestDigest, MusubiPinLocationReferenceV1> {
        WorldReadOnly::musubi_locations_by_pin(self)
    }
    fn source_musubi_locations_by_provider(
        &self,
    ) -> &impl StorageReadOnly<MusubiProviderLocationKeyV1, ()> {
        WorldReadOnly::musubi_locations_by_provider(self)
    }
    fn source_musubi_locations_by_replication_order(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1> {
        WorldReadOnly::musubi_locations_by_replication_order(self)
    }
    fn source_musubi_packages(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageIdV1, MusubiPackageRecordV1> {
        WorldReadOnly::musubi_packages(self)
    }
    fn source_musubi_provider_bundle_attestations(
        &self,
    ) -> &impl StorageReadOnly<
        MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationRecordV1,
    > {
        WorldReadOnly::musubi_provider_bundle_attestations(self)
    }
    fn source_musubi_public_directory(
        &self,
    ) -> &impl StorageReadOnly<MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1> {
        WorldReadOnly::musubi_public_directory(self)
    }
    fn source_musubi_releases(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiReleaseRecordV1> {
        WorldReadOnly::musubi_releases(self)
    }
    fn source_musubi_resolver_index(
        &self,
    ) -> &impl StorageReadOnly<MusubiReleaseIdV1, MusubiResolverReleaseRowV1> {
        WorldReadOnly::musubi_resolver_index(self)
    }
    fn source_pin_manifests(&self) -> &impl StorageReadOnly<ManifestDigest, PinManifestRecord> {
        WorldReadOnly::pin_manifests(self)
    }
    fn source_provider_owners(&self) -> &impl StorageReadOnly<ProviderId, AccountId> {
        WorldReadOnly::provider_owners(self)
    }
    fn source_replication_orders(
        &self,
    ) -> &impl StorageReadOnly<ReplicationOrderId, ReplicationOrderRecord> {
        WorldReadOnly::replication_orders(self)
    }
    fn source_musubi_resolver_index_revision(&self) -> u64 {
        WorldReadOnly::musubi_resolver_index_revision(self)
    }
}

#[path = "deserialize_world_musubi_source_access.rs"]
pub mod access;
