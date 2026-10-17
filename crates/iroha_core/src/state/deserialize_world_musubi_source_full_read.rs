//! Full source traversal for Musubi semantic admission and projection validation.
//!
//! Evidence predicates share the narrow point-query contract. Complete source
//! consumers retain the original counts, ordered rows and remaining queries here.

use super::{MusubiEvidenceRead, MusubiSourceReadOnly};
use iroha_data_model::{
    account::AccountId,
    musubi::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ManifestDigest, PinManifestRecord, ReplicationOrderId, ReplicationOrderRecord,
        },
    },
};
use mv::storage::StorageReadOnly;

/// Scalar progress of the original key's charged comparison geometry.
/// This contains no key, source, credit or publication authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyWorkCursor {
    /// Next charged geometry stage.
    pub(crate) part: usize,
    /// Next retained prerelease entry.
    pub(crate) entry: usize,
    /// Completed substage of the current entry.
    pub(crate) detail: u8,
    /// Successfully admitted comparison geometry.
    pub(crate) units: usize,
    /// Original measured variable length awaiting admission.
    pub(crate) pending: usize,
}

/// Original query progress, scoped by its enclosing immutable semantic row/substep.
/// The owner resets this cursor only when changing the query or finishing that row.
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupCursor {
    /// Next charged binary-search stage.
    pub(crate) phase: u8,
    /// Inclusive remaining search bound.
    pub(crate) first: usize,
    /// Exclusive remaining search bound.
    pub(crate) end: usize,
    /// Original midpoint whose geometry or comparison is pending.
    pub(crate) middle: usize,
    /// Retained geometry of the unchanged requested key.
    pub(crate) key: KeyWorkCursor,
    /// Retained geometry of the current original midpoint key.
    pub(crate) candidate: KeyWorkCursor,
    /// Exact resolved ordinal or proved absence, if complete.
    pub(crate) resolved: Option<Option<usize>>,
}
impl LookupCursor {
    /// A fresh query on the enclosing original source; no work has been granted.
    pub const fn new() -> Self {
        Self {
            phase: 0,
            first: 0,
            end: 0,
            middle: 0,
            key: KeyWorkCursor {
                part: 0,
                entry: 0,
                detail: 0,
                units: 0,
                pending: 0,
            },
            candidate: KeyWorkCursor {
                part: 0,
                entry: 0,
                detail: 0,
                units: 0,
                pending: 0,
            },
            resolved: None,
        }
    }
    /// Start the next fixed query site after its previous semantic row completed.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// One source cut with fallible ordered rows and exact-key queries.
/// Implementations preserve original row references and actual read refusals.
pub trait MusubiRead: MusubiEvidenceRead<LookupCursor> {
    /// Original stored count of `musubi_archives`, without a traversal.
    fn musubi_archives_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_archives`; local refusal is an explicit item.
    fn musubi_archives_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveRecordV1), Self::Error>>,
        Self::Error,
    >;
    /// Exact original lookup in `musubi_archives`; absence never replaces a refusal.
    fn musubi_archives_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveRecordV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_archives_get_retained(
        &self,
        key: &ArchiveId,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiArchiveRecordV1>, Self::Error> {
        self.musubi_archives_get(key)
    }
    /// Original stored count of `musubi_archive_availability`, without a traversal.
    fn musubi_archive_availability_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_archive_availability`; local refusal is an explicit item.
    fn musubi_archive_availability_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveAvailabilityV1), Self::Error>>,
        Self::Error,
    >;
    /// Exact original lookup in `musubi_archive_availability`; absence never replaces a refusal.
    fn musubi_archive_availability_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveAvailabilityV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_archive_availability_get_retained(
        &self,
        key: &ArchiveId,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiArchiveAvailabilityV1>, Self::Error> {
        self.musubi_archive_availability_get(key)
    }
    /// Original stored count of `musubi_archive_locations`, without a traversal.
    fn musubi_archive_locations_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_archive_locations`; local refusal is an explicit item.
    fn musubi_archive_locations_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiArchiveLocationKeyV1, &MusubiArchiveLocationV1), Self::Error>,
        >,
        Self::Error,
    >;
    /// Original stored count of `musubi_locations_by_pin`, without a traversal.
    fn musubi_locations_by_pin_len(&self) -> Result<usize, Self::Error>;
    /// Exact original lookup in `musubi_locations_by_pin`; absence never replaces a refusal.
    fn musubi_locations_by_pin_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&MusubiPinLocationReferenceV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_locations_by_pin_get_retained(
        &self,
        key: &ManifestDigest,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiPinLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_pin_get(key)
    }
    /// Original stored count of `musubi_locations_by_provider`, without a traversal.
    fn musubi_locations_by_provider_len(&self) -> Result<usize, Self::Error>;
    /// Exact original lookup in `musubi_locations_by_provider`; absence never replaces a refusal.
    fn musubi_locations_by_provider_get(
        &self,
        key: &MusubiProviderLocationKeyV1,
    ) -> Result<Option<&()>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_locations_by_provider_get_retained(
        &self,
        key: &MusubiProviderLocationKeyV1,
        _query: &mut LookupCursor,
    ) -> Result<Option<&()>, Self::Error> {
        self.musubi_locations_by_provider_get(key)
    }
    /// Original stored count of `musubi_locations_by_replication_order`, without a traversal.
    fn musubi_locations_by_replication_order_len(&self) -> Result<usize, Self::Error>;
    /// Original stored count of `musubi_packages`, without a traversal.
    fn musubi_packages_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_packages`; local refusal is an explicit item.
    fn musubi_packages_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>>,
        Self::Error,
    >;
    /// Exact original lookup in `musubi_packages`; absence never replaces a refusal.
    fn musubi_packages_get(
        &self,
        key: &MusubiPackageIdV1,
    ) -> Result<Option<&MusubiPackageRecordV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_packages_get_retained(
        &self,
        key: &MusubiPackageIdV1,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiPackageRecordV1>, Self::Error> {
        self.musubi_packages_get(key)
    }
    /// Original stored count of `musubi_provider_bundle_attestations`, without a traversal.
    fn musubi_provider_bundle_attestations_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_provider_bundle_attestations`; local refusal is an explicit item.
    fn musubi_provider_bundle_attestations_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<
                (
                    &MusubiProviderBundleAttestationKeyV1,
                    &MusubiProviderBundleAttestationRecordV1,
                ),
                Self::Error,
            >,
        >,
        Self::Error,
    >;
    /// Original stored count of `musubi_public_directory`, without a traversal.
    fn musubi_public_directory_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_public_directory`; local refusal is an explicit item.
    fn musubi_public_directory_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiPackageSelectorV1, &MusubiOrderedPackageEntryV1), Self::Error>,
        >,
        Self::Error,
    >;
    /// Original stored count of `musubi_releases`, without a traversal.
    fn musubi_releases_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_releases`; local refusal is an explicit item.
    fn musubi_releases_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiReleaseIdV1, &MusubiReleaseRecordV1), Self::Error>>,
        Self::Error,
    >;
    /// Exact original lookup in `musubi_releases`; absence never replaces a refusal.
    fn musubi_releases_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiReleaseRecordV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_releases_get_retained(
        &self,
        key: &MusubiReleaseIdV1,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiReleaseRecordV1>, Self::Error> {
        self.musubi_releases_get(key)
    }
    /// Original stored count of `musubi_resolver_index`, without a traversal.
    fn musubi_resolver_index_len(&self) -> Result<usize, Self::Error>;
    /// Ordered original rows of `musubi_resolver_index`; local refusal is an explicit item.
    fn musubi_resolver_index_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiReleaseIdV1, &MusubiResolverReleaseRowV1), Self::Error>,
        >,
        Self::Error,
    >;
    /// Exact original lookup in `musubi_resolver_index`; absence never replaces a refusal.
    fn musubi_resolver_index_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiResolverReleaseRowV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_resolver_index_get_retained(
        &self,
        key: &MusubiReleaseIdV1,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiResolverReleaseRowV1>, Self::Error> {
        self.musubi_resolver_index_get(key)
    }
    /// Original stored count of `pin_manifests`, without a traversal.
    fn pin_manifests_len(&self) -> Result<usize, Self::Error>;
    /// Exact original lookup in `pin_manifests`; absence never replaces a refusal.
    fn pin_manifests_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&PinManifestRecord>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn pin_manifests_get_retained(
        &self,
        key: &ManifestDigest,
        _query: &mut LookupCursor,
    ) -> Result<Option<&PinManifestRecord>, Self::Error> {
        self.pin_manifests_get(key)
    }
    /// Original stored count of `provider_owners`, without a traversal.
    fn provider_owners_len(&self) -> Result<usize, Self::Error>;
    /// Exact original lookup in `provider_owners`; absence never replaces a refusal.
    fn provider_owners_get(&self, key: &ProviderId) -> Result<Option<&AccountId>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn provider_owners_get_retained(
        &self,
        key: &ProviderId,
        _query: &mut LookupCursor,
    ) -> Result<Option<&AccountId>, Self::Error> {
        self.provider_owners_get(key)
    }
    /// Original stored count of `replication_orders`, without a traversal.
    fn replication_orders_len(&self) -> Result<usize, Self::Error>;
    /// Exact original lookup in `replication_orders`; absence never replaces a refusal.
    fn replication_orders_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&ReplicationOrderRecord>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn replication_orders_get_retained(
        &self,
        key: &ReplicationOrderId,
        _query: &mut LookupCursor,
    ) -> Result<Option<&ReplicationOrderRecord>, Self::Error> {
        self.replication_orders_get(key)
    }
    /// The exact revision of this same cut.
    fn musubi_revision(&self) -> u64;
}

// Ordinary readers forward original storage without extra rows or indexes.
impl<W: MusubiSourceReadOnly> MusubiRead for W {
    fn musubi_archives_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_archives().len())
    }
    fn musubi_archives_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveRecordV1), Self::Error>>,
        Self::Error,
    > {
        Ok(self.source_musubi_archives().iter().map(Ok))
    }
    fn musubi_archives_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveRecordV1>, Self::Error> {
        Ok(self.source_musubi_archives().get(key))
    }
    fn musubi_archive_availability_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_archive_availability().len())
    }
    fn musubi_archive_availability_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveAvailabilityV1), Self::Error>>,
        Self::Error,
    > {
        Ok(self.source_musubi_archive_availability().iter().map(Ok))
    }
    fn musubi_archive_availability_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveAvailabilityV1>, Self::Error> {
        Ok(self.source_musubi_archive_availability().get(key))
    }
    fn musubi_archive_locations_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_archive_locations().len())
    }
    fn musubi_archive_locations_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiArchiveLocationKeyV1, &MusubiArchiveLocationV1), Self::Error>,
        >,
        Self::Error,
    > {
        Ok(self.source_musubi_archive_locations().iter().map(Ok))
    }
    fn musubi_locations_by_pin_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_locations_by_pin().len())
    }
    fn musubi_locations_by_pin_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&MusubiPinLocationReferenceV1>, Self::Error> {
        Ok(self.source_musubi_locations_by_pin().get(key))
    }
    fn musubi_locations_by_provider_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_locations_by_provider().len())
    }
    fn musubi_locations_by_provider_get(
        &self,
        key: &MusubiProviderLocationKeyV1,
    ) -> Result<Option<&()>, Self::Error> {
        Ok(self.source_musubi_locations_by_provider().get(key))
    }
    fn musubi_locations_by_replication_order_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_locations_by_replication_order().len())
    }
    fn musubi_packages_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_packages().len())
    }
    fn musubi_packages_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>>,
        Self::Error,
    > {
        Ok(self.source_musubi_packages().iter().map(Ok))
    }
    fn musubi_packages_get(
        &self,
        key: &MusubiPackageIdV1,
    ) -> Result<Option<&MusubiPackageRecordV1>, Self::Error> {
        Ok(self.source_musubi_packages().get(key))
    }
    fn musubi_provider_bundle_attestations_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_provider_bundle_attestations().len())
    }
    fn musubi_provider_bundle_attestations_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<
                (
                    &MusubiProviderBundleAttestationKeyV1,
                    &MusubiProviderBundleAttestationRecordV1,
                ),
                Self::Error,
            >,
        >,
        Self::Error,
    > {
        Ok(self
            .source_musubi_provider_bundle_attestations()
            .iter()
            .map(Ok))
    }
    fn musubi_public_directory_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_public_directory().len())
    }
    fn musubi_public_directory_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiPackageSelectorV1, &MusubiOrderedPackageEntryV1), Self::Error>,
        >,
        Self::Error,
    > {
        Ok(self.source_musubi_public_directory().iter().map(Ok))
    }
    fn musubi_releases_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_releases().len())
    }
    fn musubi_releases_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiReleaseIdV1, &MusubiReleaseRecordV1), Self::Error>>,
        Self::Error,
    > {
        Ok(self.source_musubi_releases().iter().map(Ok))
    }
    fn musubi_releases_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiReleaseRecordV1>, Self::Error> {
        Ok(self.source_musubi_releases().get(key))
    }
    fn musubi_resolver_index_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_musubi_resolver_index().len())
    }
    fn musubi_resolver_index_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiReleaseIdV1, &MusubiResolverReleaseRowV1), Self::Error>,
        >,
        Self::Error,
    > {
        Ok(self.source_musubi_resolver_index().iter().map(Ok))
    }
    fn musubi_resolver_index_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiResolverReleaseRowV1>, Self::Error> {
        Ok(self.source_musubi_resolver_index().get(key))
    }
    fn pin_manifests_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_pin_manifests().len())
    }
    fn pin_manifests_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&PinManifestRecord>, Self::Error> {
        Ok(self.source_pin_manifests().get(key))
    }
    fn provider_owners_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_provider_owners().len())
    }
    fn provider_owners_get(&self, key: &ProviderId) -> Result<Option<&AccountId>, Self::Error> {
        Ok(self.source_provider_owners().get(key))
    }
    fn replication_orders_len(&self) -> Result<usize, Self::Error> {
        Ok(self.source_replication_orders().len())
    }
    fn replication_orders_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&ReplicationOrderRecord>, Self::Error> {
        Ok(self.source_replication_orders().get(key))
    }
    fn musubi_revision(&self) -> u64 {
        self.source_musubi_resolver_index_revision()
    }
}
