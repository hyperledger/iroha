//! Exact sixteen-source sigma qualification without constructing proving buffers,
//! and the sealed per-operation rebuild of one selected sigma proving key.

use super::recipe::InstalledSourceSealV1;
use super::*;
use iroha_kagemusha_proof::{
    SigmaProver, SigmaShape,
    a_relation::native::artifact::{ArtifactError, KeyArtifact},
    admin_sigma::native::{
        AdminSigmaError, ArchiveProver, BootstrapProver, LoadProver, RefreshProver, RetiringProver,
        UnloadProver,
    },
    witness::SigmaRelation,
};
use iroha_plonk::{
    keys::{
        CosetCachePolicy, SourceBoundVerifyingKeyV2, SourceBoundViewV2, pk::artifact::ReadConfig,
    },
    pcs::ipa::PinnedParams,
};

/// A bounded original or exact compiled sigma source did not qualify.
#[derive(Debug, thiserror::Error)]
pub enum SigmaQualificationErrorV1 {
    /// Signed original identity or bounded content-addressed read failed.
    #[error(transparent)]
    Original(#[from] Error),
    /// The fixed native generator parameters could not be constructed.
    #[error("invalid compiled sigma parameters")]
    Parameters,
    /// A Send/Receive original or sealed source differs from its compiled monetary source.
    #[error(transparent)]
    Monetary(#[from] iroha_kagemusha_proof::SigmaError),
    /// An administrative original or sealed source differs from its operation source.
    #[error(transparent)]
    Administrative(#[from] AdminSigmaError),
    /// Imported source metadata differs from its exact descriptor/key identity.
    #[error(transparent)]
    Metadata(#[from] ArtifactError),
}

/// All sixteen exact source-qualified sigma verifiers for one authenticated installation,
/// each with the private seal its strict or exact closed-registry admission minted.
/// Every use binds that seal, revalidates the signed originals and rebuilds the key
/// from compiled source, as Q/A/W/Omega do. This retains no original PK bytes or
/// proving polynomials. Q/A/W/Omega source qualification and wallet custody are
/// still required before monetary admission.
pub struct QualifiedSigmasV1 {
    keys: [KeyArtifact<Eq>; 16],
    // Source authority from this qualification only, keyed by the signed member
    // `inventory.sigma[selector]`. Never serialized, decoded or returned.
    seals: [InstalledSourceSealV1<Eq>; 16],
    scheme_id: [u8; 32],
    manifest_digest: [u8; 32],
}
impl QualifiedSigmasV1 {
    /// Exact installation whose signed originals supplied these compiled sources.
    pub const fn installation(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme_id, self.manifest_digest)
    }
    /// Qualified metadata in global selector order, without a PK backreference.
    pub fn key(&self, selector: u8) -> Option<&KeyArtifact<Eq>> {
        self.keys.get(usize::from(selector))
    }
    pub(super) const fn metadata(&self) -> &[KeyArtifact<Eq>; 16] {
        &self.keys
    }
    /// Bind one selector's retained seal to its qualified metadata before any source
    /// I/O. A seal is authority only for its own signed member in this installation.
    pub(super) fn bind(
        &self,
        selector: u8,
        expected_member: u32,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'_, Eq>, Error> {
        let selected = usize::from(selector);
        let key = self.keys.get(selected).ok_or(Error::Inventory)?;
        self.seals
            .get(selected)
            .ok_or(Error::Inventory)?
            .bind(expected_member, key, cancellation)
    }
}

pub(super) fn monetary_shape(selector: usize) -> Result<SigmaShape, Error> {
    let relation = match selector {
        2..=9 => SigmaRelation::send(u32::try_from(selector - 2).map_err(|_| Error::Profile)?),
        10..=11 => {
            SigmaRelation::receive(u32::try_from(selector - 10).map_err(|_| Error::Profile)?)
        }
        _ => return Err(Error::Profile),
    };
    iroha_kagemusha_proof::wallet_monetary_shape(relation).map_err(|_| Error::Profile)
}

/// One active exact native sigma owner. Every variant holds only its own PK, rebuilt
/// from its compiled source under the qualified admission seal.
pub enum ImportedSigmaV1 {
    /// Initial wallet state source.
    Bootstrap(Box<BootstrapProver>),
    /// Finalized-load state source.
    Load(Box<LoadProver>),
    /// One exact Send mask or Receive renewal variant.
    Monetary(Box<SigmaProver<Eq>>),
    /// Credit archive source.
    Archive(Box<ArchiveProver>),
    /// Unload source.
    Unload(Box<UnloadProver>),
    /// Policy refresh source.
    Refresh(Box<RefreshProver>),
    /// Wallet retirement source.
    Retiring(Box<RetiringProver>),
}
#[cfg(test)]
impl ImportedSigmaV1 {
    /// The rebuilt key, for exact-reconstruction checks only.
    pub(super) fn proving_key(&self) -> &iroha_plonk::ProvingKey<Eq> {
        match self {
            Self::Bootstrap(p) => p.proving_key(),
            Self::Load(p) => p.proving_key(),
            Self::Monetary(p) => p.proving_key(),
            Self::Archive(p) => p.proving_key(),
            Self::Unload(p) => p.proving_key(),
            Self::Refresh(p) => p.proving_key(),
            Self::Retiring(p) => p.proving_key(),
        }
    }
}

/// Rebuild one selector's native owner from its bound admitted source view. The
/// circuit comes only from compiled code chosen by `selector`, with k12 or k14 taken
/// from the compiled monetary shape; no descriptor field selects a shape or relation.
/// A rebuild failure is final: there is no strict re-import of the original.
pub(super) fn rebuild_prover(
    selector: usize,
    view: SourceBoundViewV2<'_, Eq>,
    k12: &PinnedParams<Eq>,
    k14: &PinnedParams<Eq>,
    coset_cache: CosetCachePolicy,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<ImportedSigmaV1, SigmaQualificationErrorV1> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    macro_rules! administrative {
        ($owner:ty, $variant:ident) => {{
            ImportedSigmaV1::$variant(Box::new(<$owner>::from_source_view_cancellable(
                k12.clone(),
                view,
                coset_cache,
                cancellation,
            )?))
        }};
    }
    Ok(match selector {
        0 => administrative!(BootstrapProver, Bootstrap),
        1 => administrative!(LoadProver, Load),
        2..=11 => {
            let shape = monetary_shape(selector)?;
            let params = if shape.k == 12 { k12 } else { k14 };
            ImportedSigmaV1::Monetary(Box::new(SigmaProver::<Eq>::from_source_view_cancellable(
                shape,
                params.clone(),
                view,
                coset_cache,
                cancellation,
            )?))
        }
        12 => administrative!(ArchiveProver, Archive),
        13 => administrative!(UnloadProver, Unload),
        14 => administrative!(RefreshProver, Refresh),
        15 => administrative!(RetiringProver, Retiring),
        _ => return Err(Error::Profile.into()),
    })
}

#[cfg(test)]
pub(super) fn import(
    selector: usize,
    original: &OriginalBytesV1,
    k12: &PinnedParams<Eq>,
    k14: &PinnedParams<Eq>,
    config: ReadConfig,
) -> Result<KeyArtifact<Eq>, SigmaQualificationErrorV1> {
    let (binding, key, _) =
        import_with_admission(selector, original, k12, k14, config, None)?.into_parts();
    Ok(KeyArtifact::new(binding, key)?)
}

fn import_with_admission(
    selector: usize,
    original: &OriginalBytesV1,
    k12: &PinnedParams<Eq>,
    k14: &PinnedParams<Eq>,
    config: ReadConfig,
    member: Option<iroha_plonk::keys::BuiltinSourceMemberV1>,
) -> Result<SourceBoundVerifyingKeyV2<Eq>, SigmaQualificationErrorV1> {
    macro_rules! administrative {
        ($owner:ty) => {
            match member {
                Some(member) => <$owner>::admit_builtin_original_artifact_cancellable(
                    k12,
                    &original.descriptor,
                    &original.verifying_key,
                    &original.proving_key,
                    config,
                    member,
                    None,
                )?,
                None => <$owner>::admit_original_artifact_cancellable(
                    k12,
                    &original.descriptor,
                    &original.verifying_key,
                    &original.proving_key,
                    config,
                    None,
                )?,
            }
        };
    }
    Ok(match selector {
        0 => administrative!(BootstrapProver),
        1 => administrative!(LoadProver),
        2..=11 => {
            let shape = monetary_shape(selector)?;
            let params = if shape.k == 12 { k12 } else { k14 };
            match member {
                Some(member) => SigmaProver::<Eq>::admit_builtin_original_artifact_cancellable(
                    shape,
                    params.clone(),
                    &original.descriptor,
                    &original.verifying_key,
                    &original.proving_key,
                    config,
                    member,
                    None,
                )?,
                None => SigmaProver::<Eq>::admit_original_artifact_cancellable(
                    shape,
                    params.clone(),
                    &original.descriptor,
                    &original.verifying_key,
                    &original.proving_key,
                    config,
                    None,
                )?,
            }
        }
        12 => administrative!(ArchiveProver),
        13 => administrative!(UnloadProver),
        14 => administrative!(RefreshProver),
        15 => administrative!(RetiringProver),
        _ => return Err(Error::Profile.into()),
    })
}

impl AuthenticatedProducerInventoryV1 {
    /// Strictly import every signed sigma original against the fixed compiled
    /// source and retain only its exact descriptor/VK metadata and private
    /// member-bound admission seal. Temporary source
    /// tables are released before the next selector is read; proving-only FFTs,
    /// masks and caches are not constructed during qualification.
    /// This performs no key generation and grants no complete wallet capability.
    /// # Errors
    /// Missing/capped/changed originals, wrong operation/control source, different
    /// descriptor/VK, noncanonical proving tables or native import failure.
    pub fn qualify_sigmas(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedSigmasV1, SigmaQualificationErrorV1> {
        let k12 = PinnedParams::derive(12).map_err(|_| SigmaQualificationErrorV1::Parameters)?;
        let k14 = PinnedParams::derive(14).map_err(|_| SigmaQualificationErrorV1::Parameters)?;
        self.qualify_sigmas_with_params(originals, config, &k12, &k14)
    }

    /// Qualify the same sixteen exact sources using this authenticated
    /// installation's immutable parameter owners. Reuses public computations
    /// across the source graph without changing any source or commitment check.
    /// # Errors
    /// Another installation, invalid domain, or any ordinary sigma intake failure.
    pub fn qualify_sigmas_for_installation(
        &self,
        installed: &InstalledVerifierPackV1,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedSigmasV1, SigmaQualificationErrorV1> {
        if self.installation()
            != (
                installed.verifier().scheme().scheme_id(),
                installed.verifier().manifest_digest(),
            )
        {
            return Err(Error::Authority.into());
        }
        self.qualify_sigmas_with_params(
            originals,
            config,
            installed.verifier().vesta_parameters(12)?,
            installed.verifier().vesta_parameters(14)?,
        )
    }

    pub(super) fn qualify_sigmas_with_params(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        k12: &PinnedParams<Eq>,
        k14: &PinnedParams<Eq>,
    ) -> Result<QualifiedSigmasV1, SigmaQualificationErrorV1> {
        self.qualify_sigmas_with_admission(
            originals,
            config,
            k12,
            k14,
            super::builtin::Admission::Strict,
        )
    }

    pub(super) fn qualify_sigmas_with_admission(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        k12: &PinnedParams<Eq>,
        k14: &PinnedParams<Eq>,
        admission: super::builtin::Admission<'_>,
    ) -> Result<QualifiedSigmasV1, SigmaQualificationErrorV1> {
        if k12.k() != 12 || k14.k() != 14 {
            return Err(SigmaQualificationErrorV1::Parameters);
        }
        let mut keys = Vec::with_capacity(16);
        let mut seals = Vec::with_capacity(16);
        for (selector, index) in self.inventory.sigma.iter().copied().enumerate() {
            let original = self.read_original(index, originals, config.maximum_bytes)?;
            let (binding, key, seal) = import_with_admission(
                selector,
                &original,
                k12,
                k14,
                config,
                admission.member(&[1, u32::try_from(selector).map_err(|_| Error::Inventory)?])?,
            )?
            .into_parts();
            drop(original);
            keys.push(KeyArtifact::new(binding, key)?);
            seals.push(InstalledSourceSealV1::new(index, seal));
        }
        Ok(QualifiedSigmasV1 {
            keys: keys.try_into().map_err(|_| Error::Inventory)?,
            seals: seals.try_into().map_err(|_| Error::Inventory)?,
            scheme_id: self.scheme_id,
            manifest_digest: self.manifest_digest,
        })
    }
}

// Framed into the single native profile. None of these source choices is
// selected by a witness or by fields inside an untrusted original descriptor.
pub(in crate::kagemusha_wallet_artifacts_v1) fn compiled_sigma_policy() -> Result<Vec<u8>, Error> {
    let mut bytes = 1_u16.to_le_bytes().to_vec();
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    for (selector, (kind, mask)) in SIGMA_CATALOG_V1.into_iter().enumerate() {
        bytes.push(kind);
        bytes.extend_from_slice(&mask.to_le_bytes());
        if (2..=11).contains(&selector) {
            let shape = monetary_shape(selector)?;
            bytes.extend([
                1,
                u8::try_from(shape.k).map_err(|_| Error::Profile)?,
                u8::try_from(shape.params.lanes()).map_err(|_| Error::Profile)?,
                u8::try_from(shape.params.limb_bits()).map_err(|_| Error::Profile)?,
                1, // Exactly the compiled folded-prefix source.
            ]);
        } else {
            bytes.extend([0, 12, 0, 0, 0]); // Typed administrative source, no lane recipe.
        }
    }
    Ok(bytes)
}
