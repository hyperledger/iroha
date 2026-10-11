//! Native original-key intake and proving of the fixed P-256 signature Q leaf.
//!
//! The installed owner authenticates the complete original descriptor/VK/PK and
//! selects the signature slots, hard/soft modes and fixed roots independently of
//! operation input. This component checks that exact compiled source and key
//! continuity, derives verdicts from the raw signatures, proves those verdicts,
//! and fully self-verifies the Q proof. Only source-bound verifier metadata survives
//! installation. Proving reconstructs temporary buffers without commitment MSMs;
//! no new artifact key is generated and no proving key is cached.
//!
//! A still binds every exported digest, key and signature to its original object
//! tapes and owns the global incoming/burn branch. A Q leaf alone is neither a
//! monetary verifier nor a completed lineage. TODO(G3/G4): authenticate this
//! component in the whole producer catalog and connect original G1 preparation,
//! complete operation schedules and the final uniform Omega owner before open.

use core::fmt;

use ff::Field;
use iroha_pasta::{Ep, Fp, Fq};
use iroha_plonk::{
    DescriptorBinding, KeyError, ProverConfig, ProverError, ProverRandomness, ProvingKey,
    VerifyError, VerifyingKey, Witness, create_proof_owned,
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    frontend::{Circuit, Error as LayoutError},
    keys::{
        CosetCachePolicy, RebuildError, SourceBoundVerifyingKeyV2, SourceBoundViewV2,
        keygen_pk_from_vk_v2_cancellable,
        pk::artifact::{Error as ArtifactError, ReadConfig},
    },
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{
    p256::{
        VerifyMode,
        native::{Affine, verify_prehashed},
    },
    sha256::native::sha256_of_digest,
};

use super::{QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureWitness};

const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

/// Fixed-source signature-Q intake or proof failure; no failure advances custody.
#[derive(Debug)]
pub enum QSignatureError {
    /// Invalid witness dimensions or signature leaf layout.
    Layout(LayoutError),
    /// The pinned outer parameters must cover exactly k16.
    Parameters,
    /// The installed descriptor is not the fixed V2 signature-Q profile.
    Profile,
    /// Original descriptor decoding failed.
    Descriptor(iroha_plonk::cs::DescriptorError),
    /// Bounded original-key source/commitment import failed.
    Artifact(ArtifactError),
    /// The original PK does not retain the independently installed VK.
    UnauthorizedKey,
    /// A supplied raw key differs from its fixed signature slot.
    KeyBinding,
    /// A hard slot's native low-S P-256 signature was rejected.
    Signature,
    /// Circuit assignment or actual proof generation failed.
    Prover(ProverError),
    /// Source-bound temporary proving-buffer reconstruction failed.
    Rebuild(RebuildError),
    /// Complete self-verification failed.
    Verify(VerifyError),
}
impl fmt::Display for QSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature Q: {self:?}")
    }
}
impl std::error::Error for QSignatureError {}
impl QSignatureError {
    /// Whether this is cancellation, never an invalid incoming proof or burn witness.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Layout(error) => matches!(error, iroha_plonk::frontend::Error::Cancelled),
            Self::Artifact(error) => error.is_cancelled(),
            Self::Prover(error) => error.is_cancelled(),
            Self::Rebuild(error) => error.is_cancelled(),
            Self::Verify(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

/// One immutable installed signature-Q source and its admitted verifier metadata.
/// Private fields prevent a witness from changing slot policy or fixed roots.
pub struct QSignatureProver {
    plan: QSignaturePlan,
    params: PinnedParams<Ep>,
    key: SourceBoundVerifyingKeyV2<Ep>,
}
impl QSignaturePlan {
    /// Reconstruct the exact unknown signature-Q source for offline key tooling.
    /// Slot order, hard/soft modes and fixed keys remain circuit constants;
    /// digest/key/signature witnesses are unknown. This creates no accepted
    /// signature verdict, prepared operation or catalog authority.
    /// # Errors
    /// Invalid fixed slot dimensions or source layout.
    pub fn source_circuit(&self) -> Result<QSignatureCircuit, QSignatureError> {
        let blank = SignatureWitness {
            digest: Fp::ZERO,
            key: [[0; 4]; 2],
            signature: [[0; 4]; 2],
        };
        QSignatureCircuit::new(self.clone(), vec![blank; self.slots().len()])
            .map(|source| source.without_witnesses())
            .map_err(QSignatureError::Layout)
    }
}

impl QSignatureProver {
    /// Import one original under the exact independently installed slot plan.
    /// No key generation, alternate profile or import fallback is performed.
    ///
    /// The complete originals, scheme/catalog scope and resource policy must
    /// already be authenticated by the native installation owner. This method
    /// checks fixed source/key continuity; it grants no catalog admission,
    /// `NativeProofs` implementation, wallet-open capability or enrollment identity.
    /// Original/domain bounds do not qualify total synthesis/prover memory.
    ///
    /// # Errors
    /// Wrong k16/Pallas/V2 signature profile or original bounds, noncanonical
    /// descriptor/VK/PK, substituted installed VK, or fixed-slot source mismatch.
    pub fn from_original_artifact(
        plan: QSignaturePlan,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: ReadConfig,
    ) -> Result<Self, QSignatureError> {
        Self::from_original_artifact_cancellable(
            plan,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            None,
        )
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn from_original_artifact_cancellable(
        plan: QSignaturePlan,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSignatureError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| QSignatureError::Prover(iroha_plonk::ProverError::Cancelled))?;
        if params.k() != 16 {
            return Err(QSignatureError::Parameters);
        }
        if descriptor.is_empty()
            || descriptor.len() > DESCRIPTOR_MAX_BYTES
            || installed_vk.is_empty()
            || installed_vk.len() > VERIFYING_KEY_MAX_BYTES
            || original.len() > config.maximum_bytes
        {
            return Err(QSignatureError::Artifact(ArtifactError::Length));
        }
        let binding =
            DescriptorBinding::decode_v2(descriptor).map_err(QSignatureError::Descriptor)?;
        let d = binding.descriptor();
        let instance_length =
            u32::try_from(plan.instance_length()).map_err(|_| QSignatureError::Profile)?;
        if d.k != 16
            || d.curve != CurveV1::Pallas
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_lengths.as_slice() != [instance_length]
            || d.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        {
            return Err(QSignatureError::Profile);
        }
        // Bound the original/domain before source construction, allocation or import.
        if binding.n() > config.maximum_rows {
            return Err(QSignatureError::Artifact(ArtifactError::Length));
        }
        VerifyingKey::<Ep>::read(installed_vk, &binding).map_err(|error| {
            QSignatureError::Artifact(ArtifactError::Key(KeyError::VerifyingKey(error)))
        })?;
        let circuit = plan.source_circuit()?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            &binding,
            &params,
            &circuit,
            config,
            cancellation,
        )
        .map_err(QSignatureError::Artifact)?;
        if key.vk().to_bytes() != installed_vk {
            return Err(QSignatureError::UnauthorizedKey);
        }
        let metadata = SourceBoundVerifyingKeyV2::from_proving_key(&key, cancellation)
            .map_err(QSignatureError::Rebuild)?;
        drop(key);
        Ok(Self {
            plan,
            params,
            key: metadata,
        })
    }

    /// Exact installed slot order, hard/soft policy and fixed keys.
    #[must_use]
    pub const fn plan(&self) -> &QSignaturePlan {
        &self.plan
    }

    /// Fixed original V2 descriptor used by A's signature-Q verifier.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        self.key.binding()
    }

    /// Fixed Q verifying key retained after strict original import.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        self.key.verifying_key()
    }

    /// Pinned k16 Pallas parameters of this immutable component.
    #[must_use]
    pub const fn params(&self) -> &PinnedParams<Ep> {
        &self.params
    }

    /// Move admitted metadata into an installed owner's existing public graph.
    #[must_use]
    pub fn into_metadata(self) -> SourceBoundVerifyingKeyV2<Ep> {
        self.key
    }
    /// Borrow the exact standalone policy, parameters and admitted source.
    #[must_use]
    pub fn view(&self) -> QSignatureProverView<'_> {
        QSignatureProverView {
            plan: &self.plan,
            params: &self.params,
            key: self.key.view(),
        }
    }
    /// Prove through the same borrowed implementation used by installed owners.
    /// # Errors
    /// Wrong fixed policy, source, witness, cancellation or complete proof failure.
    pub fn prove(
        &self,
        witnesses: &[SignatureWitness],
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<QSignatureProof, QSignatureError> {
        self.view().prove(witnesses, randomness, config)
    }
}

/// Borrowed installed signature policy and exact-source authority.
pub struct QSignatureProverView<'a> {
    plan: &'a QSignaturePlan,
    params: &'a PinnedParams<Ep>,
    key: SourceBoundViewV2<'a, Ep>,
}
impl<'a> QSignatureProverView<'a> {
    /// Select only a previously admitted source under its exact fixed signature schema.
    /// # Errors
    /// Non-k16/profile or a different declared public schema.
    pub fn from_source_bound(
        plan: &'a QSignaturePlan,
        params: &'a PinnedParams<Ep>,
        key: SourceBoundViewV2<'a, Ep>,
    ) -> Result<Self, QSignatureError> {
        if params.k() != 16 {
            return Err(QSignatureError::Parameters);
        }
        let d = key.binding().descriptor();
        let length = u32::try_from(plan.instance_length()).map_err(|_| QSignatureError::Profile)?;
        if d.k != 16
            || d.curve != CurveV1::Pallas
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
            || d.instance_lengths.as_slice() != [length]
        {
            return Err(QSignatureError::Profile);
        }
        Ok(Self { plan, params, key })
    }
    /// Exact borrowed policy.
    #[must_use]
    pub const fn plan(&self) -> &QSignaturePlan {
        self.plan
    }
    /// Exact borrowed descriptor.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        self.key.binding()
    }
    /// Exact borrowed verifier.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        self.key.verifying_key()
    }
    /// Shared pinned parameter storage.
    #[must_use]
    pub const fn params(&self) -> &PinnedParams<Ep> {
        self.params
    }
    /// Prove exact raw signature inputs under the installed policy and self-verify.
    /// Verdicts are derived from the actual low-S native P-256 check; the caller
    /// supplies no verdict or operation-wide incoming/burn decision. Soft failure
    /// remains a proved false bit for A's mandatory total incoming rule.
    ///
    /// # Errors
    /// Wrong slot count or fixed key, invalid hard signature, circuit/proof failure
    /// or failed complete self-verification. No failure changes a wallet head.
    pub fn prove(
        &self,
        witnesses: &[SignatureWitness],
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<QSignatureProof, QSignatureError> {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation)
            .map_err(|_| QSignatureError::Prover(ProverError::Cancelled))?;
        let instances = self.plan.native_instances(witnesses)?;
        let bytes = {
            let source = self.plan.source_circuit()?;
            let key = keygen_pk_from_vk_v2_cancellable(
                self.params,
                &source,
                &self.key,
                CosetCachePolicy::OnDemand,
                config.cancellation,
            )
            .map_err(QSignatureError::Rebuild)?;
            drop(source);
            let circuit = QSignatureCircuit::new((*self.plan).clone(), witnesses.to_vec())
                .map_err(QSignatureError::Layout)?;
            let witness =
                Witness::from_circuit_cancellable(&key, &circuit, &instances, config.cancellation)
                    .map_err(QSignatureError::Prover)?;
            create_proof_owned(self.params, &key, witness, randomness, config)
                .map_err(QSignatureError::Prover)?
        };
        // All proving buffers are released before complete self-verification.
        iroha_plonk::verifier::verify_full_cancellable(
            self.params,
            self.binding(),
            self.verifying_key(),
            &instances,
            &bytes,
            config.msm_budget,
            config.cancellation,
        )
        .map_err(QSignatureError::Verify)?;
        Ok(QSignatureProof { bytes, instances })
    }
}

impl QSignaturePlan {
    /// Derive exact Q public values from raw signed objects under this fixed policy.
    /// Native low-S verification derives every soft verdict and rejects failed hard
    /// slots. This supplies restoration inputs, never a proof or acceptance grant.
    /// # Errors
    /// Wrong slot count, substituted fixed key, invalid hard signature or field encoding.
    pub fn native_instances(
        &self,
        witnesses: &[SignatureWitness],
    ) -> Result<[Vec<Fq>; 1], QSignatureError> {
        let verdicts = signature_verdicts(self, witnesses)?;
        let circuit = QSignatureCircuit::new(self.clone(), witnesses.to_vec())
            .map_err(QSignatureError::Layout)?;
        circuit
            .instances(&verdicts)
            .map_err(QSignatureError::Layout)
    }
}

fn signature_verdicts(
    plan: &QSignaturePlan,
    witnesses: &[SignatureWitness],
) -> Result<Vec<bool>, QSignatureError> {
    if witnesses.len() != plan.slots().len() {
        return Err(QSignatureError::Layout(LayoutError::Synthesis));
    }
    let mut verdicts = Vec::with_capacity(witnesses.len());
    for (slot, witness) in plan.slots().iter().zip(witnesses) {
        if let SignatureKey::Fixed(key) = slot.key
            && witness.key != [key.x, key.y]
        {
            return Err(QSignatureError::KeyBinding);
        }
        let digest = sha256_of_digest(&witness.digest);
        let message = core::array::from_fn(|index| {
            let offset = (3 - index) * 8;
            u64::from_be_bytes(core::array::from_fn(|byte| digest[offset + byte]))
        });
        let verdict = verify_prehashed(
            &message,
            &witness.signature[0],
            &witness.signature[1],
            &Affine {
                x: witness.key[0],
                y: witness.key[1],
            },
        );
        if slot.mode == VerifyMode::Hard && !verdict {
            return Err(QSignatureError::Signature);
        }
        verdicts.push(verdict);
    }
    Ok(verdicts)
}

/// Actual self-verified Q bytes and their exact bound public signature columns.
/// A must still bind these values to original objects and retain the opening.
#[derive(Clone, Debug)]
pub struct QSignatureProof {
    /// Exact descriptor-sized unframed PIPA-R Q proof.
    pub bytes: Vec<u8>,
    /// The actual digests, raw keys/signatures and proved native verdicts.
    pub instances: [Vec<Fq>; 1],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::q_signature::SignatureSlot;

    #[test]
    fn rebuild_failure_preserves_cancellation_and_refuses_source_authority() {
        assert!(QSignatureError::Rebuild(RebuildError::Key(KeyError::Cancelled)).is_cancelled());
        for error in [RebuildError::Profile, RebuildError::Source] {
            assert!(!QSignatureError::Rebuild(error).is_cancelled());
        }
    }

    #[test]
    fn derived_verdicts_preserve_hard_soft_and_fixed_key_boundaries() {
        let hard = QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        }])
        .unwrap();
        let soft = QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Soft,
            key: SignatureKey::Variable,
        }])
        .unwrap();
        let invalid = SignatureWitness {
            digest: Fp::ZERO,
            key: [[0; 4]; 2],
            signature: [[0; 4]; 2],
        };
        assert!(matches!(
            signature_verdicts(&hard, &[invalid]),
            Err(QSignatureError::Signature)
        ));
        assert_eq!(signature_verdicts(&soft, &[invalid]).unwrap(), [false]);
        assert!(matches!(
            hard.native_instances(&[invalid]),
            Err(QSignatureError::Signature)
        ));
        let public = soft.native_instances(&[invalid]).unwrap();
        assert_eq!(public[0].last(), Some(&Fq::ZERO));
        assert!(soft.native_instances(&[]).is_err());

        assert!(matches!(
            signature_verdicts(&soft, &[]),
            Err(QSignatureError::Layout(_))
        ));
        let fixed = QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Soft,
            key: SignatureKey::Fixed(Affine::GENERATOR),
        }])
        .unwrap();
        assert!(matches!(
            signature_verdicts(&fixed, &[invalid]),
            Err(QSignatureError::KeyBinding)
        ));
    }
}

#[cfg(test)]
mod public_witness_tests;
