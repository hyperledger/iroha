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
            fn comparison_units(&self, work: &mut usize, limit: usize)
                -> Result<usize, RetainedPackageReadError> {
                // These keys contain only fixed arrays/numbers. One unit per
                // byte plus a branch covers their derived scalar/array order.
                let amount = size_of::<Self>().checked_add(1)
                    .ok_or(RetainedPackageReadError::Geometry)?;
                admit(work, amount, limit)?;
                Ok(amount)
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

impl sealed::NativeKey for MusubiPackageIdV1 {}
impl ComparisonKey for MusubiPackageIdV1 {
    fn comparison_units(
        &self,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        let mut units = 0;
        add(&mut units, 8 + 1, work, limit)?; // dataspace and scope discriminant
        if let MusubiPackageScopeV1::Domain(domain) = &self.scope {
            add(&mut units, 1, work, limit)?; // before reading borrowed length
            add(&mut units, domain.as_ref().len(), work, limit)?;
        }
        add(&mut units, 1, work, limit)?;
        add(&mut units, self.name.as_str().len(), work, limit)?;
        Ok(units)
    }
}

impl sealed::NativeKey for MusubiReleaseIdV1 {}
impl ComparisonKey for MusubiReleaseIdV1 {
    fn comparison_units(
        &self,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        let mut units = self.package.comparison_units(work, limit)?;
        add(&mut units, 3 * 8 + 1, work, limit)?;
        // Admit sequence inspection before walking any prerelease element.
        add(&mut units, self.version.prerelease.len(), work, limit)?;
        for identifier in &self.version.prerelease {
            add(&mut units, 1, work, limit)?;
            match identifier {
                MusubiPrereleaseIdentifierV1::Numeric(_) => add(&mut units, 8, work, limit)?,
                MusubiPrereleaseIdentifierV1::AlphaNumeric(text) => {
                    add(&mut units, 1, work, limit)?;
                    add(&mut units, text.len(), work, limit)?;
                }
            }
        }
        Ok(units)
    }
}

impl sealed::NativeKey for MusubiPackageSelectorV1 {}
impl ComparisonKey for MusubiPackageSelectorV1 {
    fn comparison_units(
        &self,
        work: &mut usize,
        limit: usize,
    ) -> Result<usize, RetainedPackageReadError> {
        let mut units = 0;
        add(&mut units, 1, work, limit)?;
        add(&mut units, self.namespace.as_str().len(), work, limit)?;
        add(&mut units, 1, work, limit)?;
        add(&mut units, self.name.as_str().len(), work, limit)?;
        Ok(units)
    }
}
