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

/// Original point queries needed by binding and provider-attestation predicates.
///
/// Implementations must return original immutable row references. Each native
/// resolve and comparison is owned by its implementation. `Q` is the source-owned
/// query progress; ordinary World readers ignore it. A failed
/// step cannot be reported as an absent row or a normally exhausted iterator.
pub trait MusubiEvidenceRead<Q> {
    /// Original read-owner error, independent of model validity.
    type Error;
    /// Exact original lookup in `musubi_locations_by_replication_order`; absence never replaces a refusal.
    fn musubi_locations_by_replication_order_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_locations_by_replication_order_get_retained(
        &self,
        key: &ReplicationOrderId,
        _query: &mut Q,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_replication_order_get(key)
    }
    /// Exact original lookup in `musubi_provider_bundle_attestations`; absence never replaces a refusal.
    fn musubi_provider_bundle_attestations_get(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error>;
    /// Resume the same exact-key query; ordinary World readers require no native cursor.
    fn musubi_provider_bundle_attestations_get_retained(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
        _query: &mut Q,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        self.musubi_provider_bundle_attestations_get(key)
    }
}

// Ordinary readers borrow the original exact-key result and ignore query progress.
// No table copy, additional index or allocated row container is introduced.
impl<W: MusubiSourceReadOnly, Q> MusubiEvidenceRead<Q> for W {
    type Error = Infallible;
    fn musubi_locations_by_replication_order_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        Ok(self.source_musubi_locations_by_replication_order().get(key))
    }
    fn musubi_provider_bundle_attestations_get(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        Ok(self.source_musubi_provider_bundle_attestations().get(key))
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
