//! Closed comparison geometry of the actual fourteen Musubi map keys.
//!
//! Planning borrows retained keys and admits every length/variant traversal.
//! The recorded bound covers both operands of the unchanged canonical `Ord`;
//! there is no parsing, key clone, normalization or permissive external trait.

use super::{RetainedPackageReadError, admit};
use iroha_data_model::{
    musubi::{
        ArchiveId, MusubiArchiveLocationKeyV1, MusubiPackageIdV1, MusubiPackageScopeV1,
        MusubiPackageSelectorV1, MusubiPrereleaseIdentifierV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderLocationKeyV1, MusubiReleaseIdV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ManifestDigest, ReplicationOrderId},
    },
};

use crate::state::deserialize::musubi_source_read::KeyWorkCursor;
use std::mem::size_of;

mod sealed {
    pub trait NativeKey {}
}

pub(in crate::state::publication) trait ComparisonKey:
    mv::Key + sealed::NativeKey
{
    fn comparison_units(
        &self,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        self.comparison_units_retained(&mut KeyWorkCursor::default(), work, limit)
    }
    fn comparison_units_retained(
        &self,
        cursor: &mut KeyWorkCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError>;
}

fn add(
    units: &mut usize,
    amount: usize,
    work: &mut usize,
    limit: usize,
) -> Result<(), RetainedPackageReadError> {
    let next = units
        .checked_add(amount)
        .ok_or(RetainedPackageReadError::Geometry)?;
    admit(work, amount, limit)?;
    *units = next;
    Ok(())
}

macro_rules! fixed_keys {
    ($($key:ty),+ $(,)?) => { $(
        impl sealed::NativeKey for $key {}
        impl ComparisonKey for $key {
            fn comparison_units_retained(&self, cursor: &mut KeyWorkCursor, work: &mut usize, limit: usize)
                -> Result<usize, RetainedPackageReadError> {
                if cursor.part == 0 {
                    let amount = size_of::<Self>().checked_add(1).ok_or(RetainedPackageReadError::Geometry)?;
                    add(&mut cursor.units, amount, work, limit)?;
                    cursor.part = 1;
                }
                Ok(cursor.units)
            }
        }
    )+ };
}
fixed_keys!(
    ArchiveId,
    MusubiArchiveLocationKeyV1,
    MusubiProviderLocationKeyV1,
    MusubiProviderBundleAttestationKeyV1,
    ManifestDigest,
    ReplicationOrderId,
    ProviderId
);

fn package_units(
    key: &MusubiPackageIdV1,
    cursor: &mut KeyWorkCursor,
    work: &mut usize,
    limit: usize,
) -> Result<(), RetainedPackageReadError> {
    if cursor.part == 0 {
        add(&mut cursor.units, 8 + 1, work, limit)?;
        cursor.part = 1;
    }
    if cursor.part == 1 {
        if let MusubiPackageScopeV1::Domain(domain) = &key.scope {
            add(&mut cursor.units, 1, work, limit)?;
            cursor.pending = domain.as_ref().len();
        } else {
            cursor.pending = 0;
        }
        cursor.part = 2;
    }
    if cursor.part == 2 {
        add(&mut cursor.units, cursor.pending, work, limit)?;
        cursor.part = 3;
    }
    if cursor.part == 3 {
        add(&mut cursor.units, 1, work, limit)?;
        cursor.pending = key.name.as_str().len();
        cursor.part = 4;
    }
    if cursor.part == 4 {
        add(&mut cursor.units, cursor.pending, work, limit)?;
        cursor.part = 5;
    }
    Ok(())
}
impl sealed::NativeKey for MusubiPackageIdV1 {}
impl ComparisonKey for MusubiPackageIdV1 {
    fn comparison_units_retained(
        &self,
        cursor: &mut KeyWorkCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        package_units(self, cursor, work, limit)?;
        Ok(cursor.units)
    }
}
impl sealed::NativeKey for MusubiReleaseIdV1 {}
impl ComparisonKey for MusubiReleaseIdV1 {
    fn comparison_units_retained(
        &self,
        cursor: &mut KeyWorkCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        package_units(&self.package, cursor, work, limit)?;
        if cursor.part == 5 {
            add(&mut cursor.units, 3 * 8 + 1, work, limit)?;
            cursor.part = 6;
        }
        if cursor.part == 6 {
            add(
                &mut cursor.units,
                self.version.prerelease.len(),
                work,
                limit,
            )?;
            cursor.part = 7;
        }
        if cursor.part == 7 {
            while cursor.entry < self.version.prerelease.len() {
                if cursor.detail == 0 {
                    add(&mut cursor.units, 1, work, limit)?;
                    match &self.version.prerelease[cursor.entry] {
                        MusubiPrereleaseIdentifierV1::Numeric(_) => {
                            cursor.pending = 8;
                            cursor.detail = 2;
                        }
                        MusubiPrereleaseIdentifierV1::AlphaNumeric(_) => {
                            cursor.detail = 1;
                        }
                    }
                }
                if cursor.detail == 1 {
                    add(&mut cursor.units, 1, work, limit)?;
                    let MusubiPrereleaseIdentifierV1::AlphaNumeric(text) =
                        &self.version.prerelease[cursor.entry]
                    else {
                        return Err(RetainedPackageReadError::Geometry);
                    };
                    cursor.pending = text.len();
                    cursor.detail = 2;
                }
                add(&mut cursor.units, cursor.pending, work, limit)?;
                cursor.entry += 1;
                cursor.detail = 0;
            }
            cursor.part = 8;
        }
        Ok(cursor.units)
    }
}
impl sealed::NativeKey for MusubiPackageSelectorV1 {}
impl ComparisonKey for MusubiPackageSelectorV1 {
    fn comparison_units_retained(
        &self,
        cursor: &mut KeyWorkCursor,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        if cursor.part == 0 {
            add(&mut cursor.units, 1, work, limit)?;
            cursor.pending = self.namespace.as_str().len();
            cursor.part = 1;
        }
        if cursor.part == 1 {
            add(&mut cursor.units, cursor.pending, work, limit)?;
            cursor.part = 2;
        }
        if cursor.part == 2 {
            add(&mut cursor.units, 1, work, limit)?;
            cursor.pending = self.name.as_str().len();
            cursor.part = 3;
        }
        if cursor.part == 3 {
            add(&mut cursor.units, cursor.pending, work, limit)?;
            cursor.part = 4;
        }
        Ok(cursor.units)
    }
}
