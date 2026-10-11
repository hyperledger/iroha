//! Exact sixteen-source sigma qualification with one active original PK at a time.

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
use iroha_plonk::{keys::pk::artifact::ReadConfig, pcs::ipa::PinnedParams};

/// A bounded original or exact compiled sigma source did not qualify.
#[derive(Debug, thiserror::Error)]
pub enum SigmaQualificationErrorV1 {
    /// Signed original identity or bounded content-addressed read failed.
    #[error(transparent)]
    Original(#[from] Error),
    /// The fixed native generator parameters could not be constructed.
    #[error("invalid compiled sigma parameters")]
    Parameters,
    /// A Send/Receive original differs from its compiled monetary source.
    #[error(transparent)]
    Monetary(#[from] iroha_kagemusha_proof::SigmaError),
    /// An administrative original differs from its operation-specific source.
    #[error(transparent)]
    Administrative(#[from] AdminSigmaError),
    /// Imported source metadata differs from its exact descriptor/key identity.
    #[error(transparent)]
    Metadata(#[from] ArtifactError),
}

/// All sixteen exact source-qualified sigma verifiers for one authenticated installation.
/// This retains no original PK bytes or proving polynomials. Q/A/W/Omega source
/// qualification and wallet custody are still required before monetary admission.
pub struct QualifiedSigmasV1 {
    keys: [KeyArtifact<Eq>; 16],
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

/// One active exact native sigma owner. Every variant holds only its own original PK.
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
impl ImportedSigmaV1 {
    pub(super) fn metadata(&self) -> Result<KeyArtifact<Eq>, SigmaQualificationErrorV1> {
        let (binding, key) = match self {
            Self::Bootstrap(p) => (p.binding(), p.verifying_key()),
            Self::Load(p) => (p.binding(), p.verifying_key()),
            Self::Monetary(p) => (p.proving_key().binding(), p.proving_key().vk()),
            Self::Archive(p) => (p.binding(), p.verifying_key()),
            Self::Unload(p) => (p.binding(), p.verifying_key()),
            Self::Refresh(p) => (p.binding(), p.verifying_key()),
            Self::Retiring(p) => (p.binding(), p.verifying_key()),
        };
        Ok(KeyArtifact::new(binding.clone(), key.clone())?)
    }
}

pub(super) fn import_prover(
    selector: usize,
    original: &OriginalBytesV1,
    k12: &PinnedParams<Eq>,
    k14: &PinnedParams<Eq>,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<ImportedSigmaV1, SigmaQualificationErrorV1> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    macro_rules! administrative {
        ($owner:ty, $variant:ident) => {{
            ImportedSigmaV1::$variant(Box::new(<$owner>::from_original_artifact_cancellable(
                k12.clone(),
                &original.descriptor,
                &original.verifying_key,
                &original.proving_key,
                config,
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
            ImportedSigmaV1::Monetary(Box::new(
                SigmaProver::<Eq>::from_original_artifact_cancellable(
                    shape,
                    params.clone(),
                    &original.descriptor,
                    &original.verifying_key,
                    &original.proving_key,
                    config,
                    cancellation,
                )?,
            ))
        }
        12 => administrative!(ArchiveProver, Archive),
        13 => administrative!(UnloadProver, Unload),
        14 => administrative!(RefreshProver, Refresh),
        15 => administrative!(RetiringProver, Retiring),
        _ => return Err(Error::Profile.into()),
    })
}

pub(super) fn import(
    selector: usize,
    original: &OriginalBytesV1,
    k12: &PinnedParams<Eq>,
    k14: &PinnedParams<Eq>,
    config: ReadConfig,
) -> Result<KeyArtifact<Eq>, SigmaQualificationErrorV1> {
    import_prover(selector, original, k12, k14, config, None)?.metadata()
}

impl AuthenticatedProducerInventoryV1 {
    /// Strictly import every signed sigma original against the fixed compiled
    /// source and retain only its exact descriptor/VK metadata. Each original PK
    /// and imported prover is released before the next selector is read.
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
        let mut keys = Vec::with_capacity(16);
        for (selector, index) in self.inventory.sigma.iter().copied().enumerate() {
            let original = self.read_original(index, originals, config.maximum_bytes)?;
            let key = import(selector, &original, &k12, &k14, config)?;
            drop(original);
            keys.push(key);
        }
        Ok(QualifiedSigmasV1 {
            keys: keys.try_into().map_err(|_| Error::Inventory)?,
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
