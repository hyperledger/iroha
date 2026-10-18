//! Fallible access to the same Musubi source predicates and physical rows.
//!
//! Ordinary immutable World readers have an uninhabited read error. Frozen
//! publication readers retain their exact native resolve/comparison refusal;
//! no missing row, semantic verdict or new source is manufactured from it.

use super::*;
use std::convert::Infallible;

/// Original physical read refusal or the unchanged result of a semantic predicate.
#[derive(Debug)]
pub enum ReadFailure<E, R> {
    /// Actual source owner refused before the semantic operation completed.
    Source(E),
    /// Original semantic or allocation error returned by the existing predicate.
    Predicate(R),
}
impl<E, R> From<R> for ReadFailure<E, R> {
    fn from(original: R) -> Self {
        Self::Predicate(original)
    }
}
impl<E, R> ReadFailure<E, R> {
    /// Preserve original physical custody while changing only the predicate boundary.
    pub fn map_predicate<T>(self, map: impl FnOnce(R) -> T) -> ReadFailure<E, T> {
        match self {
            Self::Source(original) => ReadFailure::Source(original),
            Self::Predicate(original) => ReadFailure::Predicate(map(original)),
        }
    }
}
impl<R> ReadFailure<Infallible, R> {
    /// An ordinary immutable source cannot produce a physical read refusal.
    pub fn into_predicate(self) -> R {
        match self {
            Self::Source(never) => match never {},
            Self::Predicate(original) => original,
        }
    }
}
impl<E: std::fmt::Display, R: std::fmt::Display> std::fmt::Display for ReadFailure<E, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(original) => original.fmt(formatter),
            Self::Predicate(original) => original.fmt(formatter),
        }
    }
}
impl<E: std::error::Error + 'static, R: std::error::Error + 'static> std::error::Error
    for ReadFailure<E, R>
{
}

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

/// Completion of an exact query over its retained original source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum LookupResolution {
    /// Source work remains before a presence or absence result is known.
    #[default]
    Pending,
    /// The complete query proved that the original source has no matching row.
    Absent,
    /// The complete query identified this original row ordinal.
    Present(usize),
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
    pub(crate) resolved: LookupResolution,
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
            resolved: LookupResolution::Pending,
        }
    }
    /// Start the next fixed query site after its previous semantic row completed.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// One source cut with fallible ordered rows and exact-key queries.
///
/// Implementations must return original immutable row references. Each native
/// resolve, iterator step and comparison is owned by its implementation. A failed
/// step cannot be reported as an absent row or a normally exhausted iterator.
pub trait MusubiRead {
    /// Original read-owner error, independent of model validity.
    type Error;
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
    /// Exact original lookup in `musubi_locations_by_replication_order`; absence never replaces a refusal.
    fn musubi_locations_by_replication_order_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_locations_by_replication_order_get_retained(
        &self,
        key: &ReplicationOrderId,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_replication_order_get(key)
    }
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
    /// Exact original lookup in `musubi_provider_bundle_attestations`; absence never replaces a refusal.
    fn musubi_provider_bundle_attestations_get(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_provider_bundle_attestations_get_retained(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
        _query: &mut LookupCursor,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        self.musubi_provider_bundle_attestations_get(key)
    }
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

// The ordinary adapter forwards the actual original iterator; no ordinal nth
// scan, table copy, additional index or allocated row container is introduced.
impl<W: MusubiSourceReadOnly> MusubiRead for W {
    type Error = Infallible;
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
    fn musubi_locations_by_replication_order_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        Ok(self.source_musubi_locations_by_replication_order().get(key))
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
    fn musubi_provider_bundle_attestations_get(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        Ok(self.source_musubi_provider_bundle_attestations().get(key))
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

/// Pull an ordered row only when the predicate accepts it; propagate an original
/// iterator refusal exactly once instead of treating it as exhaustion.
pub fn next_if_row<'row, K: 'row, V: 'row, E>(
    rows: &mut std::iter::Peekable<impl Iterator<Item = Result<(&'row K, &'row V), E>>>,
    predicate: impl FnOnce(&(&K, &V)) -> bool,
) -> Result<Option<(&'row K, &'row V)>, E> {
    match rows.peek() {
        Some(Ok(row)) if predicate(row) => rows.next().transpose(),
        Some(Err(_)) => rows.next().transpose(),
        _ => Ok(None),
    }
}

/// Consume one original row only after a fallible comparison permits it.
/// A comparison refusal retains the peeked row; an actual row refusal is moved
/// out unchanged and can never masquerade as the end of this ordered source.
pub fn try_next_if_row<T, E, I: Iterator<Item = Result<T, E>>>(
    rows: &mut std::iter::Peekable<I>,
    predicate: impl FnOnce(&T) -> Result<bool, E>,
) -> Result<Option<T>, E> {
    match rows.peek() {
        Some(Ok(row)) => {
            if predicate(row)? {
                rows.next().transpose()
            } else {
                Ok(None)
            }
        }
        Some(Err(_)) => rows.next().transpose(),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct OriginalRefusal(u8);

    #[test]
    fn refused_ordered_row_is_returned_once_without_becoming_an_empty_or_skipped_row() {
        let first = (1_u8, 10_u8);
        let last = (3_u8, 30_u8);
        let mut rows = [
            Ok((&first.0, &first.1)),
            Err(OriginalRefusal(7)),
            Ok((&last.0, &last.1)),
        ]
        .into_iter()
        .peekable();
        assert_eq!(next_if_row(&mut rows, |_| false).unwrap(), None);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            next_if_row(&mut rows, |_| true).unwrap(),
            Some((&first.0, &first.1))
        );
        assert_eq!(
            next_if_row(&mut rows, |_| false).unwrap_err(),
            OriginalRefusal(7)
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(
            next_if_row(&mut rows, |_| true).unwrap(),
            Some((&last.0, &last.1))
        );
        assert_eq!(next_if_row(&mut rows, |_| true).unwrap(), None);
    }

    #[test]
    fn predicate_mapping_preserves_an_original_non_clone_source_refusal() {
        let source: ReadFailure<OriginalRefusal, &'static str> =
            ReadFailure::Source(OriginalRefusal(9));
        let mapped: ReadFailure<OriginalRefusal, ()> =
            source.map_predicate(|_| panic!("a source refusal is not a semantic rejection"));
        assert!(matches!(mapped, ReadFailure::Source(OriginalRefusal(9))));
        let native: ReadFailure<Infallible, &'static str> =
            ReadFailure::Predicate("unchanged predicate");
        assert_eq!(native.into_predicate(), "unchanged predicate");
    }
    #[test]
    fn refused_comparison_retains_the_exact_peeked_row_and_actual_row_error() {
        let mut rows = [Ok(1_u8), Err(OriginalRefusal(7)), Ok(3_u8)]
            .into_iter()
            .peekable();
        assert_eq!(
            try_next_if_row(&mut rows, |_| Err(OriginalRefusal(8))).unwrap_err(),
            OriginalRefusal(8)
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(try_next_if_row(&mut rows, |_| Ok(false)).unwrap(), None);
        assert_eq!(try_next_if_row(&mut rows, |_| Ok(true)).unwrap(), Some(1));
        assert_eq!(
            try_next_if_row(&mut rows, |_| panic!("row refusal precedes comparisons")).unwrap_err(),
            OriginalRefusal(7)
        );
        assert_eq!(try_next_if_row(&mut rows, |_| Ok(true)).unwrap(), Some(3));
        assert_eq!(
            try_next_if_row(&mut rows, |_| panic!("no absent row is compared")).unwrap(),
            None
        );
    }
}
