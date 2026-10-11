//! Exact source descriptors derived from the installed producer's configuration.
//!
//! Descriptor checks bind the arithmetic layout, transcript and public schema.
//! They do not replace authentication of the stage's verifying-key commitments.

use iroha_pasta::{Fp, PastaCurve};
use iroha_plonk::{
    DescriptorBinding, ProvingKey, VerifyingKey,
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, ConstraintSystem, CurveV1, DescriptorConfig,
        InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1, TranscriptV2,
    },
    frontend::Circuit,
};

/// Exact installed verifier identity mismatch; no failure grants source admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    /// The complete descriptor or canonical verifying-key bytes differ.
    Identity,
}
impl core::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native artifact identity mismatch")
    }
}
impl std::error::Error for ArtifactError {}
impl ArtifactError {
    /// Identity-only metadata checks do not run cancellable computation.
    pub const fn is_cancelled(self) -> bool {
        match self {
            Self::Identity => false,
        }
    }
}

/// Authenticated verifier metadata without proving polynomials or original PK bytes.
///
/// The installation owner authenticates the exact descriptor, VK and compiled-source
/// catalog. Constructing this pair checks identity only; it does not establish scheme
/// authority or validate an original PK against the compiled operation source.
#[derive(Clone, Debug)]
pub struct KeyArtifact<C: PastaCurve> {
    binding: DescriptorBinding,
    key: VerifyingKey<C>,
}
impl<C: PastaCurve> KeyArtifact<C> {
    /// Retain an exact installed descriptor/verifier pair without any PK backreference.
    /// # Errors
    /// The verifier is bound to another descriptor.
    pub fn new(binding: DescriptorBinding, key: VerifyingKey<C>) -> Result<Self, ArtifactError> {
        if key.descriptor_digest() != binding.digest() {
            return Err(ArtifactError::Identity);
        }
        Ok(Self { binding, key })
    }
    /// Exact installed proof descriptor.
    #[must_use]
    pub const fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }
    /// Exact installed verifier; this owns no proving polynomials.
    #[must_use]
    pub const fn key(&self) -> &VerifyingKey<C> {
        &self.key
    }
    /// Require exact installed identity of a strictly source-bound stage capability.
    /// This check precedes folds; the reconstruction additionally checks the full
    /// source fingerprint. Descriptor equality alone does not authorize a stage.
    /// # Errors
    /// Another descriptor, stage or canonical verifier.
    pub fn require_source_bound(
        &self,
        key: &iroha_plonk::keys::SourceBoundViewV2<'_, C>,
    ) -> Result<(), ArtifactError> {
        if key.binding() != &self.binding || key.verifying_key().to_bytes() != self.key.to_bytes() {
            return Err(ArtifactError::Identity);
        }
        Ok(())
    }
    /// Check a fully constructed PK during strict original admission.
    ///
    /// Both the entire descriptor and canonical VK bytes must match. Matching only
    /// a descriptor cannot establish the operation, stage or compiled source.
    /// Original-source validation remains the owning importer's responsibility.
    /// # Errors
    /// Another descriptor or same-descriptor foreign stage/verifier.
    pub fn require_prover(&self, key: &ProvingKey<C>) -> Result<(), ArtifactError> {
        if key.binding() != &self.binding || key.vk().to_bytes() != self.key.to_bytes() {
            return Err(ArtifactError::Identity);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "artifact/metadata_tests.rs"]
mod metadata_tests;

/// Reconstruct the fixed k16 source descriptor without synthesizing a witness.
/// The caller supplies its concrete circuit and circuit-fixed profile parameters.
/// No imported artifact can select a different configuration through this helper.
pub(super) fn source_descriptor<C: Circuit<Fp>>(params: C::Params) -> Option<DescriptorBinding> {
    let mut meta = ConstraintSystem::default();
    C::configure_with_params(&mut meta, params);
    finalize(meta)
}

fn finalize(meta: ConstraintSystem<Fp>) -> Option<DescriptorBinding> {
    if meta.instance_lengths() != [69] {
        return None;
    }
    // Compression is disabled for these source classes. Each selector becomes
    // its own fixed column, so its activation rows affect the VK commitments
    // but cannot affect the descriptor. Empty rows avoid allocating a witness.
    let activations = vec![Vec::new(); meta.num_selectors()];
    let finalized = meta.finalize(&activations, false).ok()?;
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Vesta,
            k: 16,
            // This is only the engine's common layout builder. The resulting
            // binding below is exclusively the PIPA-R V2 descriptor.
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .ok()?;
    DescriptorBinding::new_v2(
        CircuitDescriptorV2::from_layout(
            layout,
            TranscriptV2::KagemushaPoseidonRp57Base,
            vec![InstanceType::Bounded],
        )
        .ok()?,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_plonk_gadgets::bytes::tape::BytesConfig;
    use iroha_plonk_recursion::verifier::VerifierConfig;

    fn configured(tagged: bool, buses: usize, public_length: usize) -> ConstraintSystem<Fp> {
        let mut meta = ConstraintSystem::default();
        if tagged {
            VerifierConfig::<iroha_pasta::Ep>::configure_serialized_foreign_tagged(
                &mut meta, buses,
            )
            .unwrap();
        } else {
            VerifierConfig::<iroha_pasta::Ep>::configure_serialized_foreign(&mut meta, buses)
                .unwrap();
        }
        let a = meta.advice_column();
        let b = meta.advice_column();
        BytesConfig::configure(&mut meta, a, b);
        let public = meta.instance_column(public_length);
        meta.enable_equality(public);
        meta
    }

    #[test]
    fn native_terminal_sources_share_tagged3_and_internal_sources_have_exact_profiles() {
        let expected = finalize(configured(true, 3, 69)).unwrap();
        assert_eq!(
            source_descriptor::<super::super::bootstrap::StageCircuit>(()).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::load::StageCircuit>(()).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::send::StageCircuit>(()).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::consuming::StageCircuit>(()).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::receive::StageCircuit>(3).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::receive::StageCircuit>(4).unwrap(),
            finalize(configured(true, 4, 69)).unwrap()
        );
        assert_eq!(
            source_descriptor::<super::super::refresh::StageCircuit>(()).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::archive::StageCircuit>(3).unwrap(),
            expected
        );
        assert_eq!(
            source_descriptor::<super::super::archive::StageCircuit>(4).unwrap(),
            finalize(configured(true, 4, 69)).unwrap()
        );
        assert_ne!(finalize(configured(false, 4, 69)).unwrap(), expected);
        assert_ne!(finalize(configured(true, 4, 69)).unwrap(), expected);
        assert!(finalize(configured(true, 3, 68)).is_none());
    }
}
