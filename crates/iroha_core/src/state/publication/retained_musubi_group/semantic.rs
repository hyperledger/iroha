//! The existing semantic predicates over the original retained frozen pair.
//!
//! No table, value, index, revision, pool or owner is recaptured. Ordered current
//! positions and predecessor descriptors remain in the StatePublication group.
//! Every native resolve/comparison updates its original cumulative work before
//! a fallible semantic operation can use the row. No read refusal becomes None.

use super::*;
use crate::state::deserialize::{
    musubi_rejection::ProjectionCut,
    musubi_source_read::{LookupCursor, MusubiEvidenceRead, MusubiRead, ReadFailure},
    musubi_source_work::{self, SourceValidationError, SourceWorkLimits},
};
use std::cell::Cell;

/// The original staged image or its exact undo-derived predecessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum OriginalMusubiImage {
    /// Full staged current map, including every actual mutation.
    Current,
    /// Full original predecessor, including deletion and insertion masks.
    Predecessor,
}

/// Scoped semantic validation on one original image, with original source errors.
pub(in crate::state) type OriginalMusubiValidationError =
    ReadFailure<RetainedMusubiGroupReadError, SourceValidationError>;

use crate::state::deserialize::musubi_live::{
    LiveProgress, LiveValidation,
    revisions::{DirectoryProgress, DirectoryValidation},
};
use crate::state::deserialize::musubi_universal::cursor::{
    UniversalProgress, UniversalSource, UniversalValidation,
};

struct FrozenMusubiCut<'read> {
    data: &'read MusubiGroupReadData,
    work: &'read Cell<usize>,
    limit: usize,
    image: OriginalMusubiImage,
    revision: u64,
}

// Retain even the attempted native work if a future native callback unwinds.
// This guard has no source or refund authority and performs no allocation.
struct OriginalWork<'work> {
    used: usize,
    target: &'work Cell<usize>,
}
impl Drop for OriginalWork<'_> {
    fn drop(&mut self) {
        self.target.set(self.used);
    }
}
impl FrozenMusubiCut<'_> {
    fn with_work<T>(
        &self,
        operation: impl FnOnce(&mut usize, usize) -> Result<T, RetainedPackageReadError>,
    ) -> Result<T, RetainedPackageReadError> {
        let mut work = OriginalWork {
            used: self.work.get(),
            target: self.work,
        };
        operation(&mut work.used, self.limit)
    }
}
impl MusubiEvidenceRead<LookupCursor> for FrozenMusubiCut<'_> {
    type Error = RetainedMusubiGroupReadError;
    fn musubi_locations_by_replication_order_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_replication_order_len()?;
        let table = self
            .data
            .musubi_locations_by_replication_order
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_replication_order",
            original,
        })
    }
    fn musubi_locations_by_replication_order_get_retained(
        &self,
        key: &ReplicationOrderId,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiReplicationOrderLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_replication_order_len()?;
        let table = self
            .data
            .musubi_locations_by_replication_order
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_replication_order",
            original,
        })
    }
    fn musubi_provider_bundle_attestations_get(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        self.musubi_provider_bundle_attestations_len()?;
        let table = self
            .data
            .musubi_provider_bundle_attestations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_provider_bundle_attestations",
            original,
        })
    }
    fn musubi_provider_bundle_attestations_get_retained(
        &self,
        key: &MusubiProviderBundleAttestationKeyV1,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiProviderBundleAttestationRecordV1>, Self::Error> {
        self.musubi_provider_bundle_attestations_len()?;
        let table = self
            .data
            .musubi_provider_bundle_attestations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_provider_bundle_attestations",
            original,
        })
    }
}

impl MusubiRead for FrozenMusubiCut<'_> {
    fn musubi_archives_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_archives
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_archives_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveRecordV1), Self::Error>>,
        Self::Error,
    > {
        let count = self.musubi_archives_len()?;
        let table = self
            .data
            .musubi_archives
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_archives",
                original,
            })
        }))
    }
    fn musubi_archives_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveRecordV1>, Self::Error> {
        self.musubi_archives_len()?;
        let table = self
            .data
            .musubi_archives
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_archives",
            original,
        })
    }
    fn musubi_archives_get_retained(
        &self,
        key: &ArchiveId,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiArchiveRecordV1>, Self::Error> {
        self.musubi_archives_len()?;
        let table = self
            .data
            .musubi_archives
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_archives",
            original,
        })
    }
    fn musubi_archive_availability_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_archive_availability
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_archive_availability_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&ArchiveId, &MusubiArchiveAvailabilityV1), Self::Error>>,
        Self::Error,
    > {
        let count = self.musubi_archive_availability_len()?;
        let table = self
            .data
            .musubi_archive_availability
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_archive_availability",
                original,
            })
        }))
    }
    fn musubi_archive_availability_get(
        &self,
        key: &ArchiveId,
    ) -> Result<Option<&MusubiArchiveAvailabilityV1>, Self::Error> {
        self.musubi_archive_availability_len()?;
        let table = self
            .data
            .musubi_archive_availability
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_archive_availability",
            original,
        })
    }
    fn musubi_archive_availability_get_retained(
        &self,
        key: &ArchiveId,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiArchiveAvailabilityV1>, Self::Error> {
        self.musubi_archive_availability_len()?;
        let table = self
            .data
            .musubi_archive_availability
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_archive_availability",
            original,
        })
    }
    fn musubi_archive_locations_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_archive_locations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_archive_locations_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiArchiveLocationKeyV1, &MusubiArchiveLocationV1), Self::Error>,
        >,
        Self::Error,
    > {
        let count = self.musubi_archive_locations_len()?;
        let table = self
            .data
            .musubi_archive_locations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_archive_locations",
                original,
            })
        }))
    }
    fn musubi_locations_by_pin_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_locations_by_pin
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_locations_by_pin_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&MusubiPinLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_pin_len()?;
        let table = self
            .data
            .musubi_locations_by_pin
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_pin",
            original,
        })
    }
    fn musubi_locations_by_pin_get_retained(
        &self,
        key: &ManifestDigest,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiPinLocationReferenceV1>, Self::Error> {
        self.musubi_locations_by_pin_len()?;
        let table = self
            .data
            .musubi_locations_by_pin
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_pin",
            original,
        })
    }
    fn musubi_locations_by_provider_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_locations_by_provider
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_locations_by_provider_get(
        &self,
        key: &MusubiProviderLocationKeyV1,
    ) -> Result<Option<&()>, Self::Error> {
        self.musubi_locations_by_provider_len()?;
        let table = self
            .data
            .musubi_locations_by_provider
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_provider",
            original,
        })
    }
    fn musubi_locations_by_provider_get_retained(
        &self,
        key: &MusubiProviderLocationKeyV1,
        query: &mut LookupCursor,
    ) -> Result<Option<&()>, Self::Error> {
        self.musubi_locations_by_provider_len()?;
        let table = self
            .data
            .musubi_locations_by_provider
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_locations_by_provider",
            original,
        })
    }
    fn musubi_locations_by_replication_order_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_locations_by_replication_order
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_packages_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_packages
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_packages_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>>,
        Self::Error,
    > {
        let count = self.musubi_packages_len()?;
        let table = self
            .data
            .musubi_packages
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_packages",
                original,
            })
        }))
    }
    fn musubi_packages_get(
        &self,
        key: &MusubiPackageIdV1,
    ) -> Result<Option<&MusubiPackageRecordV1>, Self::Error> {
        self.musubi_packages_len()?;
        let table = self
            .data
            .musubi_packages
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_packages",
            original,
        })
    }
    fn musubi_packages_get_retained(
        &self,
        key: &MusubiPackageIdV1,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiPackageRecordV1>, Self::Error> {
        self.musubi_packages_len()?;
        let table = self
            .data
            .musubi_packages
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_packages",
            original,
        })
    }
    fn musubi_provider_bundle_attestations_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_provider_bundle_attestations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
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
        let count = self.musubi_provider_bundle_attestations_len()?;
        let table = self
            .data
            .musubi_provider_bundle_attestations
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_provider_bundle_attestations",
                original,
            })
        }))
    }
    fn musubi_public_directory_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_public_directory
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_public_directory_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiPackageSelectorV1, &MusubiOrderedPackageEntryV1), Self::Error>,
        >,
        Self::Error,
    > {
        let count = self.musubi_public_directory_len()?;
        let table = self
            .data
            .musubi_public_directory
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_public_directory",
                original,
            })
        }))
    }
    fn musubi_releases_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_releases
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_releases_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&MusubiReleaseIdV1, &MusubiReleaseRecordV1), Self::Error>>,
        Self::Error,
    > {
        let count = self.musubi_releases_len()?;
        let table = self
            .data
            .musubi_releases
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_releases",
                original,
            })
        }))
    }
    fn musubi_releases_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiReleaseRecordV1>, Self::Error> {
        self.musubi_releases_len()?;
        let table = self
            .data
            .musubi_releases
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_releases",
            original,
        })
    }
    fn musubi_releases_get_retained(
        &self,
        key: &MusubiReleaseIdV1,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiReleaseRecordV1>, Self::Error> {
        self.musubi_releases_len()?;
        let table = self
            .data
            .musubi_releases
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_releases",
            original,
        })
    }
    fn musubi_resolver_index_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .musubi_resolver_index
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn musubi_resolver_index_rows(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(&MusubiReleaseIdV1, &MusubiResolverReleaseRowV1), Self::Error>,
        >,
        Self::Error,
    > {
        let count = self.musubi_resolver_index_len()?;
        let table = self
            .data
            .musubi_resolver_index
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        Ok((0..count).map(move |index| {
            self.with_work(|work, limit| match self.image {
                OriginalMusubiImage::Current => table.current_row(index, work, limit),
                OriginalMusubiImage::Predecessor => table.predecessor_row(index, work, limit),
            })
            .map_err(|original| Self::Error::Field {
                field: "musubi_resolver_index",
                original,
            })
        }))
    }
    fn musubi_resolver_index_get(
        &self,
        key: &MusubiReleaseIdV1,
    ) -> Result<Option<&MusubiResolverReleaseRowV1>, Self::Error> {
        self.musubi_resolver_index_len()?;
        let table = self
            .data
            .musubi_resolver_index
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_resolver_index",
            original,
        })
    }
    fn musubi_resolver_index_get_retained(
        &self,
        key: &MusubiReleaseIdV1,
        query: &mut LookupCursor,
    ) -> Result<Option<&MusubiResolverReleaseRowV1>, Self::Error> {
        self.musubi_resolver_index_len()?;
        let table = self
            .data
            .musubi_resolver_index
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "musubi_resolver_index",
            original,
        })
    }
    fn pin_manifests_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .pin_manifests
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn pin_manifests_get(
        &self,
        key: &ManifestDigest,
    ) -> Result<Option<&PinManifestRecord>, Self::Error> {
        self.pin_manifests_len()?;
        let table = self
            .data
            .pin_manifests
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "pin_manifests",
            original,
        })
    }
    fn pin_manifests_get_retained(
        &self,
        key: &ManifestDigest,
        query: &mut LookupCursor,
    ) -> Result<Option<&PinManifestRecord>, Self::Error> {
        self.pin_manifests_len()?;
        let table = self
            .data
            .pin_manifests
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "pin_manifests",
            original,
        })
    }
    fn provider_owners_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .provider_owners
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn provider_owners_get(&self, key: &ProviderId) -> Result<Option<&AccountId>, Self::Error> {
        self.provider_owners_len()?;
        let table = self
            .data
            .provider_owners
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "provider_owners",
            original,
        })
    }
    fn provider_owners_get_retained(
        &self,
        key: &ProviderId,
        query: &mut LookupCursor,
    ) -> Result<Option<&AccountId>, Self::Error> {
        self.provider_owners_len()?;
        let table = self
            .data
            .provider_owners
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "provider_owners",
            original,
        })
    }
    fn replication_orders_len(&self) -> Result<usize, Self::Error> {
        let table = self
            .data
            .replication_orders
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        let (complete, count) = match self.image {
            OriginalMusubiImage::Current => (table.current_complete, table.current_count),
            OriginalMusubiImage::Predecessor => {
                let progress = table.predecessor_progress();
                (progress.complete, progress.rows)
            }
        };
        if !complete {
            return Err(Self::Error::Incomplete);
        }
        Ok(count)
    }
    fn replication_orders_get(
        &self,
        key: &ReplicationOrderId,
    ) -> Result<Option<&ReplicationOrderRecord>, Self::Error> {
        self.replication_orders_len()?;
        let table = self
            .data
            .replication_orders
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup(key, work, limit),
            OriginalMusubiImage::Predecessor => table.predecessor_lookup(key, work, limit),
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "replication_orders",
            original,
        })
    }
    fn replication_orders_get_retained(
        &self,
        key: &ReplicationOrderId,
        query: &mut LookupCursor,
    ) -> Result<Option<&ReplicationOrderRecord>, Self::Error> {
        self.replication_orders_len()?;
        let table = self
            .data
            .replication_orders
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.current_lookup_retained(key, query, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.predecessor_lookup_retained(key, query, work, limit)
            }
        })
        .map(|row| row.map(|(_, value)| value))
        .map_err(|original| Self::Error::Field {
            field: "replication_orders",
            original,
        })
    }
    fn musubi_revision(&self) -> u64 {
        self.revision
    }
}

impl UniversalSource for FrozenMusubiCut<'_> {
    type Error = RetainedMusubiGroupReadError;
    type Package = usize;
    type Version = usize;
    type Directory = usize;
    fn world(&self) -> &impl MusubiRead<Error = Self::Error> {
        self
    }
    fn packages(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(usize, &MusubiPackageIdV1, &MusubiPackageRecordV1), Self::Error>,
        >,
        Self::Error,
    > {
        Ok(self
            .musubi_packages_rows()?
            .enumerate()
            .map(|(ordinal, row)| row.map(|(key, value)| (ordinal, key, value))))
    }
    fn resolvers(
        &self,
    ) -> Result<
        impl ExactSizeIterator<
            Item = Result<(usize, &MusubiReleaseIdV1, &MusubiResolverReleaseRowV1), Self::Error>,
        >,
        Self::Error,
    > {
        Ok(self
            .musubi_resolver_index_rows()?
            .enumerate()
            .map(|(ordinal, row)| row.map(|(key, value)| (ordinal, key, value))))
    }
    fn compare_package(
        &self,
        token: usize,
        key: &MusubiPackageIdV1,
    ) -> Result<std::cmp::Ordering, Self::Error> {
        let table = self
            .data
            .musubi_packages
            .as_ref()
            .ok_or(Self::Error::Incomplete)?;
        self.with_work(|work, limit| match self.image {
            OriginalMusubiImage::Current => table.compare_current_key(token, key, work, limit),
            OriginalMusubiImage::Predecessor => {
                table.compare_predecessor_key(token, key, work, limit)
            }
        })
        .map_err(|original| Self::Error::Field {
            field: "musubi_packages",
            original,
        })
    }
    fn version(
        &self,
        token: usize,
    ) -> Result<&iroha_data_model::musubi::MusubiVersionV1, Self::Error> {
        self.musubi_resolver_index_rows()?
            .nth(token)
            .ok_or(Self::Error::Incomplete)?
            .map(|(key, _)| &key.version)
    }

    fn compare_package_keys(
        &self,
        left: &MusubiPackageIdV1,
        right: &MusubiPackageIdV1,
    ) -> Result<std::cmp::Ordering, Self::Error> {
        self.with_work(|work, limit| {
            super::super::retained_rows::compare_source_keys(left, right, work, limit)
        })
        .map_err(|original| Self::Error::Field {
            field: "musubi_public_directory",
            original,
        })
    }
    fn directories(
        &self,
    ) -> Result<impl ExactSizeIterator<Item = Result<usize, Self::Error>>, Self::Error> {
        Ok(self
            .musubi_public_directory_rows()?
            .enumerate()
            .map(|(ordinal, row)| row.map(|_| ordinal)))
    }
    fn directory(&self, token: usize) -> Result<&MusubiOrderedPackageEntryV1, Self::Error> {
        self.musubi_public_directory_rows()?
            .nth(token)
            .ok_or(Self::Error::Incomplete)?
            .map(|(_, entry)| entry)
    }
    fn compare_directories(
        &self,
        left: usize,
        right: usize,
    ) -> Result<std::cmp::Ordering, Self::Error> {
        let left = self.directory(left)?;
        let right = self.directory(right)?;
        self.with_work(|work, limit| {
            super::super::retained_rows::compare_source_keys(
                &left.package,
                &right.package,
                work,
                limit,
            )
        })
        .map_err(|original| Self::Error::Field {
            field: "musubi_public_directory",
            original,
        })
    }
}

#[cfg(test)]
impl OriginalMusubiRows<'_> {
    /// Independently check one original frozen image with the same semantic graph.
    /// The enclosing owner checks the actual State, paired maps and revision
    /// before/after this call. Local refusal retains all original descriptors
    /// and cumulative native work; it cannot authorize a semantic output.
    #[cfg(test)]
    pub(in crate::state) fn validate_image(
        &mut self,
        image: OriginalMusubiImage,
        limits: SourceWorkLimits,
    ) -> Result<(), OriginalMusubiValidationError> {
        let revision = self.data.revision.as_ref().ok_or(ReadFailure::Source(
            RetainedMusubiGroupReadError::Incomplete,
        ))?;
        let (revision, context) = match image {
            OriginalMusubiImage::Current => (&**revision.current(), ProjectionCut::Current),
            OriginalMusubiImage::Predecessor => {
                (revision.get_before_block(), ProjectionCut::Predecessor)
            }
        };
        let cut = FrozenMusubiCut {
            data: self.data,
            work: Cell::from_mut(self.work),
            limit: self.limit,
            image,
            revision: revision.get(),
        };
        musubi_source_work::validate_read(&cut, self.scope.allocation_budget(), limits, context)
    }
}

/// Both original image cursors share the same retained group scope and pool.
/// This is source-work admission only, not completed semantic predicates.
pub(super) struct OriginalMusubiAdmissionPair {
    images: [musubi_source_work::Admission; 2],
    universal: [UniversalValidation<usize, usize>; 2],
    // Separate prepaid backing avoids constructing both large live cursors on
    // the stack while retaining their charge with the original admission owner.
    live: ChargedBuffer<LiveValidation>,
    materializers: Option<crate::state::authority_registry::OriginalMusubiMaterializers>,
    directory: [DirectoryValidation<usize>; 2],
    nfc: [Option<iroha_allocation::AllocationReservation>; 2],
    nfc_admitted: [bool; 2],
}
impl OriginalMusubiImage {
    const fn index(self) -> usize {
        match self {
            Self::Current => 0,
            Self::Predecessor => 1,
        }
    }
}

impl OriginalMusubiCapture<'_, '_> {
    /// Admit the immutable local policy captured by this original State publisher.
    /// This never reads current configuration or derives work from memory/output.
    pub(in crate::state) fn start_configured_original_musubi_source_admission(
        &mut self,
    ) -> Result<(), RetainedMusubiGroupReadError> {
        let policy = self.policy;
        self.start_original_musubi_source_admission(SourceWorkLimits::from_capture_policy(policy))
    }

    /// Pin explicit local source policy under the existing original group owner.
    /// The control allocation comes from its existing pool; no new allowance is
    /// derived from a protocol limit, output row count or a configuration fallback.
    pub(in crate::state) fn start_original_musubi_source_admission(
        &mut self,
        limits: SourceWorkLimits,
    ) -> Result<(), RetainedMusubiGroupReadError> {
        self.check_original_musubi_group_read()?;
        let plan = self
            .group
            .as_mut()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        if plan.admission.is_some() {
            return Err(RetainedMusubiGroupReadError::SemanticAlreadyStarted);
        }
        if plan.retired
            || !plan.complete
            || !plan
                .predecessor_progress()
                .is_some_and(|progress| progress.complete)
        {
            return Err(RetainedMusubiGroupReadError::Incomplete);
        }
        let control_layout = std::alloc::Layout::new::<OriginalMusubiAdmissionPair>();
        let live_layout = std::alloc::Layout::array::<LiveValidation>(2).map_err(|_| {
            RetainedMusubiGroupReadError::Control(
                iroha_allocation::AllocationRefusal::DemandOverflow.into(),
            )
        })?;
        // Admit both physical layouts atomically before either allocation. A
        // capacity refusal must not refund an earlier partial charge and wake
        // its own unchanged retry through the original pool's release sequence.
        let mut reservation = plan
            .scope
            .allocation_budget()
            .try_reserve_layouts([control_layout, live_layout])
            .map_err(|original| RetainedMusubiGroupReadError::Control(original.into()))?;
        let prepaid_control = |error| match error {
            iroha_allocation::PrepaidBufferError::Allocation(original) => {
                RetainedMusubiGroupReadError::Control(original)
            }
            iroha_allocation::PrepaidBufferError::Reservation(_) => {
                // Exact layouts were prepaid above; a broken partition is an
                // incomplete owner, never a new pool-capacity observation.
                RetainedMusubiGroupReadError::Incomplete
            }
        };
        let mut original =
            ChargedBuffer::from_reservation(1, &mut reservation).map_err(prepaid_control)?;
        let mut live =
            ChargedBuffer::from_reservation(2, &mut reservation).map_err(prepaid_control)?;
        for _ in 0..2 {
            live.push_reserved(LiveValidation::new());
        }
        original.push_reserved(OriginalMusubiAdmissionPair {
            images: [
                musubi_source_work::Admission::new(limits),
                musubi_source_work::Admission::new(limits),
            ],
            live,
            materializers: None,
            universal: [
                UniversalValidation::new(ProjectionCut::Current),
                UniversalValidation::new(ProjectionCut::Predecessor),
            ],
            directory: [DirectoryValidation::new(), DirectoryValidation::new()],
            nfc: [None, None],
            nfc_admitted: [false, false],
        });
        plan.admission = Some(original);
        self.check_original_musubi_group_read()
    }

    /// Continue exact admitted row/query substeps on the original image.
    /// Complete prefixes and native attempted work survive local refusal. A
    /// configured geometry/work rejection stays terminal for its pinned policy.
    /// Success means only admitted input work, never semantic validity or a root.
    pub(in crate::state) fn advance_original_musubi_source_admission(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<musubi_source_work::AdmissionProgress, OriginalMusubiValidationError> {
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        let plan = self
            .group
            .as_mut()
            .ok_or(ReadFailure::Source(RetainedMusubiGroupReadError::NotFrozen))?;
        let data = &plan
            .data
            .as_ref()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_slice()[0];
        let stage = 2 + image.index();
        data.check_retry(stage, plan.work, work_limit)
            .map_err(ReadFailure::Source)?;
        let attempt_start = plan.work;
        let revision = data.revision.as_ref().ok_or(ReadFailure::Source(
            RetainedMusubiGroupReadError::Incomplete,
        ))?;
        let revision = match image {
            OriginalMusubiImage::Current => &**revision.current(),
            OriginalMusubiImage::Predecessor => revision.get_before_block(),
        };
        let original = &mut plan
            .admission
            .as_mut()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_mut_slice()[0]
            .images[image.index()];
        let cut = FrozenMusubiCut {
            data,
            work: Cell::from_mut(&mut plan.work),
            limit: work_limit,
            image,
            revision: revision.get(),
        };
        let result = original
            .advance(&cut)
            .map_err(|error| error.map_predicate(SourceValidationError::Work));
        data.retain_retry(
            stage,
            attempt_start,
            match &result {
                Err(ReadFailure::Source(error)) => Some(error),
                _ => None,
            },
        );
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        result
    }
}

impl OriginalMusubiCapture<'_, '_> {
    /// Continue the single live predicate on the same original image.
    /// Original charged ordinal scratch survives physical/allocation refusal.
    /// This prerequisite alone does not complete the live predicate, table
    /// materializers, complete State root, publication or history authentication.
    pub(in crate::state) fn advance_original_musubi_live(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<LiveProgress, OriginalMusubiValidationError> {
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        let plan = self
            .group
            .as_mut()
            .ok_or(ReadFailure::Source(RetainedMusubiGroupReadError::NotFrozen))?;
        let data = &plan
            .data
            .as_ref()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_slice()[0];
        let stage = 4 + image.index();
        data.check_retry(stage, plan.work, work_limit)
            .map_err(ReadFailure::Source)?;
        let attempt_start = plan.work;
        let revision = data.revision.as_ref().ok_or(ReadFailure::Source(
            RetainedMusubiGroupReadError::Incomplete,
        ))?;
        let revision = match image {
            OriginalMusubiImage::Current => &**revision.current(),
            OriginalMusubiImage::Predecessor => revision.get_before_block(),
        };
        let original = &mut plan
            .admission
            .as_mut()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_mut_slice()[0];
        let index = image.index();
        let scratch_bytes =
            original.images[index]
                .nfc_scratch_bytes()
                .ok_or(ReadFailure::Source(
                    RetainedMusubiGroupReadError::Incomplete,
                ))?;
        if !original.nfc_admitted[index] {
            if scratch_bytes != 0 {
                original.nfc[index] = Some(
                    plan.scope
                        .allocation_budget()
                        .try_reserve_bytes(scratch_bytes)
                        .map_err(|refusal| {
                            ReadFailure::Predicate(SourceValidationError::Attempt(
                                crate::execution_attempt::ExecutionAttemptError::Deferred(
                                    refusal.into(),
                                ),
                            ))
                        })?,
                );
            }
            original.nfc_admitted[index] = true;
        }
        let cut = FrozenMusubiCut {
            data,
            work: Cell::from_mut(&mut plan.work),
            limit: work_limit,
            image,
            revision: revision.get(),
        };
        let result = original.live.as_mut_slice()[index]
            .advance(&cut)
            .map_err(|error| {
                error.map_predicate(|original| {
                    SourceValidationError::Attempt(original.map_rejection(|rejection| {
                        rejection.with_cut(match image {
                            OriginalMusubiImage::Current => ProjectionCut::Current,
                            OriginalMusubiImage::Predecessor => ProjectionCut::Predecessor,
                        })
                    }))
                })
            });
        let progress = original.live.as_slice()[index].progress();
        data.retain_retry(
            stage,
            attempt_start,
            match &result {
                Err(ReadFailure::Source(error)) => Some(error),
                _ => None,
            },
        );
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        result.map(|()| progress)
    }
    /// Continue the single universal predicate on the same original image.
    /// Original charged ordinal scratch survives physical/allocation refusal.
    /// This prerequisite alone does not complete the live predicate, table
    /// materializers, complete State root, publication or history authentication.
    pub(in crate::state) fn advance_original_musubi_universal(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<UniversalProgress, OriginalMusubiValidationError> {
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        let plan = self
            .group
            .as_mut()
            .ok_or(ReadFailure::Source(RetainedMusubiGroupReadError::NotFrozen))?;
        let data = &plan
            .data
            .as_ref()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_slice()[0];
        let stage = 8 + image.index();
        data.check_retry(stage, plan.work, work_limit)
            .map_err(ReadFailure::Source)?;
        let attempt_start = plan.work;
        let revision = data.revision.as_ref().ok_or(ReadFailure::Source(
            RetainedMusubiGroupReadError::Incomplete,
        ))?;
        let revision = match image {
            OriginalMusubiImage::Current => &**revision.current(),
            OriginalMusubiImage::Predecessor => revision.get_before_block(),
        };
        let original = &mut plan
            .admission
            .as_mut()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_mut_slice()[0];
        let index = image.index();
        let scratch_bytes =
            original.images[index]
                .nfc_scratch_bytes()
                .ok_or(ReadFailure::Source(
                    RetainedMusubiGroupReadError::Incomplete,
                ))?;
        if !original.nfc_admitted[index] {
            if scratch_bytes != 0 {
                original.nfc[index] = Some(
                    plan.scope
                        .allocation_budget()
                        .try_reserve_bytes(scratch_bytes)
                        .map_err(|refusal| {
                            ReadFailure::Predicate(SourceValidationError::Attempt(
                                crate::execution_attempt::ExecutionAttemptError::Deferred(
                                    refusal.into(),
                                ),
                            ))
                        })?,
                );
            }
            original.nfc_admitted[index] = true;
        }
        let cut = FrozenMusubiCut {
            data,
            work: Cell::from_mut(&mut plan.work),
            limit: work_limit,
            image,
            revision: revision.get(),
        };
        let result = original.universal[index]
            .advance(&cut, plan.scope.allocation_budget())
            .map_err(|error| error.map_predicate(SourceValidationError::Attempt));
        let progress = original.universal[index].progress();
        data.retain_retry(
            stage,
            attempt_start,
            match &result {
                Err(ReadFailure::Source(error)) => Some(error),
                _ => None,
            },
        );
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        result.map(|()| progress)
    }
    /// Continue the single directory revision predicate on the same original image.
    /// Original charged ordinal scratch survives physical/allocation refusal.
    /// This prerequisite alone does not complete the other live predicates, table
    /// materializers, complete State root, publication or history authentication.
    pub(in crate::state) fn advance_original_musubi_directory_revisions(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<DirectoryProgress, OriginalMusubiValidationError> {
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        let plan = self
            .group
            .as_mut()
            .ok_or(ReadFailure::Source(RetainedMusubiGroupReadError::NotFrozen))?;
        let data = &plan
            .data
            .as_ref()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_slice()[0];
        let stage = 6 + image.index();
        data.check_retry(stage, plan.work, work_limit)
            .map_err(ReadFailure::Source)?;
        let attempt_start = plan.work;
        let revision = data.revision.as_ref().ok_or(ReadFailure::Source(
            RetainedMusubiGroupReadError::Incomplete,
        ))?;
        let revision = match image {
            OriginalMusubiImage::Current => &**revision.current(),
            OriginalMusubiImage::Predecessor => revision.get_before_block(),
        };
        let original = &mut plan
            .admission
            .as_mut()
            .ok_or(ReadFailure::Source(
                RetainedMusubiGroupReadError::Incomplete,
            ))?
            .as_mut_slice()[0];
        let index = image.index();
        let scratch_bytes =
            original.images[index]
                .nfc_scratch_bytes()
                .ok_or(ReadFailure::Source(
                    RetainedMusubiGroupReadError::Incomplete,
                ))?;
        if !original.nfc_admitted[index] {
            if scratch_bytes != 0 {
                original.nfc[index] = Some(
                    plan.scope
                        .allocation_budget()
                        .try_reserve_bytes(scratch_bytes)
                        .map_err(|refusal| {
                            ReadFailure::Predicate(SourceValidationError::Attempt(
                                crate::execution_attempt::ExecutionAttemptError::Deferred(
                                    refusal.into(),
                                ),
                            ))
                        })?,
                );
            }
            original.nfc_admitted[index] = true;
        }
        let cut = FrozenMusubiCut {
            data,
            work: Cell::from_mut(&mut plan.work),
            limit: work_limit,
            image,
            revision: revision.get(),
        };
        let result = original.directory[index]
            .advance(&cut, plan.scope.allocation_budget())
            .map_err(|error| error.map_predicate(SourceValidationError::Attempt));
        let progress = original.directory[index].progress();
        data.retain_retry(
            stage,
            attempt_start,
            match &result {
                Err(ReadFailure::Source(error)) => Some(error),
                _ => None,
            },
        );
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        result.map(|()| progress)
    }
}

impl OriginalMusubiAdmissionPair {
    fn validated(&self) -> bool {
        (0..2).all(|image| {
            self.images[image].progress().complete
                && self.live.as_slice()[image].progress().complete
                && self.directory[image].progress().complete
                && self.universal[image].progress().complete
        })
    }
}

impl OriginalMusubiCapture<'_, '_> {
    /// Schedule one locally configured quantum against the existing original owner.
    /// The grant ledger adds policy authority to its former granted ceiling; it
    /// never infers credits from consumed work, output rows or allocation bytes.
    pub(in crate::state) fn grant_original_musubi_capture_attempt(
        &mut self,
    ) -> Result<usize, RetainedMusubiGroupReadError> {
        self.check_original_musubi_group_read()?;
        let plan = self
            .group
            .as_mut()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC372")))]
        let previous_grant = plan.native_work_granted;
        #[cfg(all(test, sumeragi_core_mutation = "HC372"))]
        let previous_grant = plan.work;
        let grant = previous_grant
            .checked_add(self.policy.native_work_per_attempt)
            .ok_or(RetainedMusubiGroupReadError::WorkGrantOverflow)?;
        plan.native_work_granted = grant;
        Ok(grant)
    }

    /// Resume structural and semantic prerequisites under this publisher's policy.
    /// Refusal retains the exact source, grant ledger, cursors and scratch. Success
    /// completes only both Musubi images, not complete State or certified history.
    #[cfg(test)]
    pub(in crate::state) fn advance_configured_original_musubi_validation(
        &mut self,
    ) -> Result<(), OriginalMusubiValidationError> {
        let limit = self
            .grant_original_musubi_capture_attempt()
            .map_err(ReadFailure::Source)?;
        self.advance_original_musubi_validation(limit)
    }

    fn advance_original_musubi_validation(
        &mut self,
        limit: usize,
    ) -> Result<(), OriginalMusubiValidationError> {
        self.check_original_musubi_group_read()
            .map_err(ReadFailure::Source)?;
        let complete = self
            .group
            .as_ref()
            .and_then(|plan| plan.admission.as_ref())
            .is_some_and(|original| original.as_slice()[0].validated());
        if complete {
            return Ok(());
        }
        self.advance_original_musubi_group_read(limit)
            .map_err(ReadFailure::Source)?;
        self.advance_original_musubi_group_predecessor_read(limit)
            .map_err(ReadFailure::Source)?;
        if self
            .group
            .as_ref()
            .is_some_and(|plan| plan.admission.is_none())
        {
            self.start_configured_original_musubi_source_admission()
                .map_err(ReadFailure::Source)?;
        }
        for image in [
            OriginalMusubiImage::Current,
            OriginalMusubiImage::Predecessor,
        ] {
            self.advance_original_musubi_source_admission(image, limit)?;
            self.advance_original_musubi_live(image, limit)?;
            self.advance_original_musubi_directory_revisions(image, limit)?;
            self.advance_original_musubi_universal(image, limit)?;
        }
        Ok(())
    }

    /// Use the three retained table builders beside their exact original validated rows.
    /// Original control allocation includes this slot; builders own their separately
    /// charged buffers. No source, allocation scope or table root is detached.
    pub(in crate::state) fn with_validated_original_musubi_materializers<R>(
        &mut self,
        limit: usize,
        callback: impl for<'read> FnOnce(
            OriginalMusubiRows<'read>,
            OriginalMusubiRevision<'read>,
            &'read mut Option<crate::state::authority_registry::OriginalMusubiMaterializers>,
        ) -> R,
    ) -> Result<R, RetainedMusubiGroupReadError> {
        self.check_original_musubi_group_read()?;
        let plan = self
            .group
            .as_mut()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        let original = &mut plan
            .admission
            .as_mut()
            .ok_or(RetainedMusubiGroupReadError::Incomplete)?
            .as_mut_slice()[0];
        if !original.validated() {
            return Err(RetainedMusubiGroupReadError::Incomplete);
        }
        let data = &plan
            .data
            .as_ref()
            .ok_or(RetainedMusubiGroupReadError::Incomplete)?
            .as_slice()[0];
        let revision = data
            .revision
            .as_ref()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        let result = callback(
            OriginalMusubiRows {
                data,
                work: &mut plan.work,
                scope: &plan.scope,
                limit,
            },
            OriginalMusubiRevision {
                current: revision.current(),
                predecessor: revision.get_before_block(),
            },
            &mut original.materializers,
        );
        self.check_original_musubi_group_read()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "semantic_test_entry.rs"]
mod test_entry;

impl OriginalMusubiCapture<'_, '_> {
    /// Prepare these three scoped tables under the sole frozen State publisher.
    /// This captures no complete-State, certified-history or lane-deletion authority.
    pub(in crate::state) fn advance_for_publication(
        &mut self,
    ) -> Result<(), TransactionsBlockError> {
        use super::super::capture_deferral::{
            materialization_refusal, source_refusal, validation_refusal,
        };
        use crate::state::authority_registry::{
            FrozenMusubiError, OriginalMusubiMaterializers,
            leaf::{LeafLimits, RetainedSemanticError},
        };

        // Diagnostic readers must retire through their original phase before the
        // engine can start its configured group. The engine never replaces an
        // unfinished source or its accumulated work.
        if self
            .group
            .as_ref()
            .is_some_and(|plan| !plan.scheduled && plan.retired)
        {
            *self.group = None;
        }
        if self.group.is_none() {
            let scope = self.world._refund_scope.clone();
            self.start_original_musubi_group_read(scope)
                .map_err(|(_, original)| source_refusal(original))?;
            self.group
                .as_mut()
                .expect("installed original capture")
                .scheduled = true;
        }
        self.check_original_musubi_group_read()
            .map_err(source_refusal)?;
        if self.group.as_ref().expect("original capture").retired {
            return Ok(());
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC376")))]
        if self
            .group
            .as_ref()
            .and_then(|plan| plan.admission.as_ref())
            .and_then(|original| original.as_slice()[0].materializers.as_ref())
            .is_some_and(|tables| tables.progress().iter().all(|table| table.complete))
        {
            // Retirement can itself refuse an outside reader after dropping the
            // structural descriptors. Resume that exact phase directly; never
            // try to reconstruct rows or encoding from already retired readers.
            return self
                .retire_original_musubi_group_read()
                .map_err(source_refusal);
        }
        // The two ledgers add independently configured authority to their former
        // grants. They never infer funding from rows, bytes or consumed work.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC373")))]
        let native_limit = self
            .grant_original_musubi_capture_attempt()
            .map_err(source_refusal)?;
        #[cfg(all(test, sumeragi_core_mutation = "HC373"))]
        let native_limit = if self
            .group
            .as_ref()
            .and_then(|plan| plan.admission.as_ref())
            .is_some_and(|original| original.as_slice()[0].validated())
        {
            // Mutation: semantic success incorrectly stops later source grants.
            self.group
                .as_ref()
                .expect("original capture")
                .native_work_granted
        } else {
            self.grant_original_musubi_capture_attempt()
                .map_err(source_refusal)?
        };
        let plan = self.group.as_mut().expect("original capture");
        let encoding_limit = plan
            .encoding_work_granted
            .checked_add(self.policy.encoding_work_per_attempt)
            .ok_or_else(|| source_refusal(RetainedMusubiGroupReadError::WorkGrantOverflow))?;
        plan.encoding_work_granted = encoding_limit;
        self.advance_original_musubi_validation(native_limit)
            .map_err(validation_refusal)?;

        let plan = self.group.as_mut().expect("original capture");
        let encoded_work = plan
            .admission
            .as_ref()
            .and_then(|original| original.as_slice()[0].materializers.as_ref())
            .map_or(Ok(0usize), |tables| {
                tables.progress().iter().try_fold(0usize, |used, table| {
                    used.checked_add(table.work)
                        .ok_or(RetainedSemanticError::Overflow)
                })
            })
            .map_err(|error| materialization_refusal(FrozenMusubiError::Encoding(error)))?;
        let required = encoded_work
            .checked_add(plan.encoding_retry_minimum)
            .ok_or_else(|| {
                materialization_refusal(FrozenMusubiError::Encoding(
                    RetainedSemanticError::Overflow,
                ))
            })?;
        // An unmet encoding demand must not repeatedly consume source reborrows.
        // Recording it is scheduling only: the separate grant authorizes work.
        if !cfg!(all(test, sumeragi_core_mutation = "HC375")) && required > encoding_limit {
            return Err(materialization_refusal(FrozenMusubiError::Encoding(
                RetainedSemanticError::Work {
                    used: encoded_work,
                    required,
                    limit: encoding_limit,
                },
            )));
        }
        let data = &plan
            .data
            .as_ref()
            .ok_or_else(|| source_refusal(RetainedMusubiGroupReadError::Incomplete))?
            .as_slice()[0];
        data.check_retry(10, plan.work, native_limit)
            .map_err(source_refusal)?;
        let native_start = plan.work;
        let policy = self.policy;
        let limits = LeafLimits {
            max_tables: policy.table_count,
            max_rows: policy.table_rows,
            max_payload_bytes: policy.table_payload_bytes,
            max_ordered_table_bytes: policy.table_ordered_bytes,
            max_streamed_value_bytes: policy.table_streamed_value_bytes,
        };
        let result = self
            .with_validated_original_musubi_materializers(native_limit, |mut rows, _, retained| {
                OriginalMusubiMaterializers::advance_retained(
                    retained,
                    &mut rows,
                    [limits; 3],
                    policy.total_table_rows,
                    encoding_limit,
                )
            })
            .map_err(FrozenMusubiError::Source)
            .and_then(|result| result);
        let plan = self.group.as_mut().expect("original capture");
        let data = &plan
            .data
            .as_ref()
            .expect("materializer keeps source until completion")
            .as_slice()[0];
        data.retain_retry(
            10,
            native_start,
            match &result {
                Err(FrozenMusubiError::Source(original)) => Some(original),
                _ => None,
            },
        );
        plan.encoding_retry_minimum = match &result {
            Err(FrozenMusubiError::Encoding(RetainedSemanticError::Work {
                used,
                required,
                ..
            })) => required
                .checked_sub(*used)
                .expect("monotonic encoder demand"),
            _ => 0,
        };
        result.map_err(materialization_refusal)?;
        // Source readers retire before installation. The charged admission and
        // all three canonical table trees remain beside this original scope.
        self.retire_original_musubi_group_read()
            .map_err(source_refusal)
    }
}

#[cfg(test)]
#[path = "production_tests.rs"]
mod production_tests;
