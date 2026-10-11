//! Original-key intake and proving for the fixed administrative sigma leaves.
//!
//! The installation owner independently authenticates the descriptor/VK and fixed
//! operation selection. Strict compiled-source/commitment import and exact VK
//! equality transitively admit original proving material; no separate PK signature
//! is required. Each typed owner
//! checks its existing compiled circuit, imports its original key and completely
//! self-verifies proofs. No runtime key generation or profile fallback is used.
//! A still authenticates objects, map effects, signatures and predecessor proofs.
//! TODO(G3/G4): mount these components in the authenticated producer inventory
//! and original G1 preparation before granting any Native wallet-open capability.

use core::fmt;

use ff::Field;
use iroha_pasta::{Eq, Fp};
use iroha_plonk::{
    DescriptorBinding, KeyError, ProverConfig, ProverError, ProverRandomness, ProvingKey,
    VerifyError, VerifyingKey, Witness, create_proof_owned,
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    frontend::Circuit,
    keys::pk::artifact::{Error as ArtifactError, ReadConfig},
    pcs::ipa::PinnedParams,
};

use super::{
    ArchiveCircuit, ArchiveWitness, BOOTSTRAP_K, BootstrapCircuit, BootstrapWitness,
    ConsumingWitness, LoadCircuit, LoadWitness, REFRESH_K, RefreshCircuit, RefreshKind,
    RefreshUpdateWitness, RefreshWitness, RetiringCircuit, StateWitness, UnloadCircuit,
};

// The one Refresh source is deliberately in the same measured k12 class.
const _: () = assert!(REFRESH_K == BOOTSTRAP_K);

const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

/// Original administrative-key intake or proof failure; no failure advances custody.
#[derive(Debug)]
pub enum AdminSigmaError {
    /// The pinned Vesta parameters must cover exactly k12.
    Parameters,
    /// The descriptor is not the fixed V2 administrative sigma profile.
    Profile,
    /// Strict original descriptor decoding failed.
    Descriptor(iroha_plonk::cs::DescriptorError),
    /// Bounded original-key source or commitment import failed.
    Artifact(ArtifactError),
    /// The original PK does not retain the independently installed VK.
    UnauthorizedKey,
    /// Witness assignment or actual proof generation failed.
    Prover(ProverError),
    /// Complete self-verification failed.
    Verify(VerifyError),
}
impl fmt::Display for AdminSigmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "administrative sigma: {self:?}")
    }
}
impl std::error::Error for AdminSigmaError {}
impl AdminSigmaError {
    /// Whether this is cancellation, never an invalid incoming proof or burn witness.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Artifact(error) => error.is_cancelled(),
            Self::Prover(error) => error.is_cancelled(),
            Self::Verify(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

// Only the typed public owners can select this helper's fixed native circuit.
struct AdminProver {
    params: PinnedParams<Eq>,
    key: ProvingKey<Eq>,
}
impl AdminProver {
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    fn from_original_artifact_cancellable<C: Circuit<Fp>>(
        circuit: &C,
        params: PinnedParams<Eq>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, AdminSigmaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| AdminSigmaError::Prover(iroha_plonk::ProverError::Cancelled))?;
        if params.k() != BOOTSTRAP_K {
            return Err(AdminSigmaError::Parameters);
        }
        if descriptor.is_empty()
            || descriptor.len() > DESCRIPTOR_MAX_BYTES
            || installed_vk.is_empty()
            || installed_vk.len() > VERIFYING_KEY_MAX_BYTES
            || original.len() > config.maximum_bytes
        {
            return Err(AdminSigmaError::Artifact(ArtifactError::Length));
        }
        let binding =
            DescriptorBinding::decode_v2(descriptor).map_err(AdminSigmaError::Descriptor)?;
        let d = binding.descriptor();
        if u32::from(d.k) != BOOTSTRAP_K
            || d.curve != CurveV1::Vesta
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_lengths.as_slice() != [1]
            || d.instance_types.as_deref() != Some(&BootstrapCircuit::instance_types())
        {
            return Err(AdminSigmaError::Profile);
        }
        if binding.n() > config.maximum_rows {
            return Err(AdminSigmaError::Artifact(ArtifactError::Length));
        }
        VerifyingKey::<Eq>::read(installed_vk, &binding).map_err(|error| {
            AdminSigmaError::Artifact(ArtifactError::Key(KeyError::VerifyingKey(error)))
        })?;
        // Witnessless import checks the operation's fixed tables, copy mapping,
        // selectors and commitments, not merely the shared descriptor class.
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            &binding,
            &params,
            circuit,
            config,
            cancellation,
        )
        .map_err(AdminSigmaError::Artifact)?;
        if key.vk().to_bytes() != installed_vk {
            return Err(AdminSigmaError::UnauthorizedKey);
        }
        Ok(Self { params, key })
    }

    fn prove<C: Circuit<Fp>>(
        &self,
        circuit: &C,
        instances: [Vec<Fp>; 1],
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<AdminSigmaProof, AdminSigmaError> {
        let witness =
            Witness::from_circuit_cancellable(&self.key, circuit, &instances, config.cancellation)
                .map_err(AdminSigmaError::Prover)?;
        let bytes = create_proof_owned(&self.params, &self.key, witness, randomness, config)
            .map_err(AdminSigmaError::Prover)?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.params,
            self.key.binding(),
            self.key.vk(),
            &instances,
            &bytes,
            config.msm_budget,
            config.cancellation,
        )
        .map_err(AdminSigmaError::Verify)?;
        Ok(AdminSigmaProof { bytes, instances })
    }
}

fn blank_bootstrap() -> BootstrapWitness {
    BootstrapWitness {
        core: [Fp::ZERO; super::CORE_FIELDS],
        rest: [Fp::ZERO; super::REST_FIELDS],
        lineage: [Fp::ZERO; 18],
        statement: [Fp::ZERO; 26],
    }
}
fn blank_state() -> StateWitness {
    StateWitness::from(&blank_bootstrap())
}
fn blank_load() -> LoadWitness {
    LoadWitness {
        predecessor: blank_state(),
        successor: blank_state(),
        statement: [Fp::ZERO; 26],
    }
}
fn blank_archive() -> ArchiveWitness {
    ArchiveWitness {
        predecessor: blank_state(),
        successor: blank_state(),
        statement: [Fp::ZERO; 26],
    }
}
fn blank_refresh() -> RefreshWitness {
    RefreshWitness {
        predecessor: blank_state(),
        successor: blank_state(),
        statement: [Fp::ZERO; 26],
        update: RefreshUpdateWitness {
            kind: RefreshKind::Credential,
            digest: Fp::ZERO,
            scheme: [Fp::ZERO; 2],
            asset: [Fp::ZERO; 2],
            wallet: [Fp::ZERO; 2],
            counter: Fp::ZERO,
            issued_at_ms: Fp::ZERO,
            expires_at_ms: Fp::ZERO,
            root: Fp::ZERO,
            controls: Fp::ZERO,
            fee_schedule: Fp::ZERO,
        },
    }
}
fn blank_consuming() -> ConsumingWitness {
    ConsumingWitness {
        predecessor: blank_state(),
        successor: blank_state(),
        statement: [Fp::ZERO; 26],
    }
}

macro_rules! admin_prover {
    ($owner:ident, $circuit:ident, $witness:ty, $blank:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $owner {
            inner: AdminProver,
        }
        impl $owner {
            /// Exact witnessless compiled source used for offline artifact
            /// construction and strict original import. No key or authority is
            /// created by obtaining this circuit.
            #[must_use]
            pub fn source_circuit() -> $circuit {
                $circuit::new(&$blank()).without_witnesses()
            }

            /// Import the original key against this fixed compiled operation.
            ///
            /// The installation owner must independently authenticate the descriptor,
            /// VK, operation, scheme/catalog scope and resource policy. Exact source
            /// and commitment checks then admit the PK material under that VK; no
            /// additional PK signature ceremony is required. This constructor
            /// supplies a proving component, not catalog admission or a wallet-open
            /// grant. Original/domain bounds do not qualify total prover memory.
            ///
            /// # Errors
            /// Wrong k12/Vesta/V2 profile, bounded or malformed originals, a different
            /// compiled operation, or an original PK differing from the installed VK.
            pub fn from_original_artifact(
                params: PinnedParams<Eq>,
                descriptor: &[u8],
                installed_vk: &[u8],
                original: &[u8],
                config: ReadConfig,
            ) -> Result<Self, AdminSigmaError> {
                Self::from_original_artifact_cancellable(
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
                params: PinnedParams<Eq>,
                descriptor: &[u8],
                installed_vk: &[u8],
                original: &[u8],
                config: ReadConfig,
                cancellation: Option<&iroha_pasta::CancellationToken>,
            ) -> Result<Self, AdminSigmaError> {
                iroha_pasta::CancellationToken::checkpoint(cancellation)
                    .map_err(|_| AdminSigmaError::Prover(iroha_plonk::ProverError::Cancelled))?;
                let circuit = Self::source_circuit();
                Ok(Self {
                    inner: AdminProver::from_original_artifact_cancellable(
                        &circuit,
                        params,
                        descriptor,
                        installed_vk,
                        original,
                        config,
                        cancellation,
                    )?,
                })
            }

            /// Imported original key; access grants no scheme or wallet authority.
            #[must_use]
            pub const fn proving_key(&self) -> &ProvingKey<Eq> {
                &self.inner.key
            }

            /// Fixed original descriptor for the installed operation.
            #[must_use]
            pub fn binding(&self) -> &DescriptorBinding {
                self.inner.key.binding()
            }

            /// Exact installed VK retained by the imported original.
            #[must_use]
            pub fn verifying_key(&self) -> &VerifyingKey<Eq> {
                self.inner.key.vk()
            }

            /// Pinned k12 Vesta parameters of this immutable component.
            #[must_use]
            pub const fn params(&self) -> &PinnedParams<Eq> {
                &self.inner.params
            }

            /// Prove the original typed witness and fully verify its derived instance.
            /// No witness-selected source, public digest or validity bit is accepted.
            ///
            /// # Errors
            /// Witness assignment, proof generation or complete self-verification
            /// fails. No failure changes a wallet head or authorizes an operation.
            pub fn prove(
                &self,
                witness: &$witness,
                randomness: ProverRandomness<'_>,
                config: ProverConfig,
            ) -> Result<AdminSigmaProof, AdminSigmaError> {
                let circuit = $circuit::new(witness);
                self.inner
                    .prove(&circuit, circuit.instances(), randomness, config)
            }
        }
    };
}

admin_prover!(
    BootstrapProver,
    BootstrapCircuit,
    BootstrapWitness,
    blank_bootstrap,
    "Original imported key and fixed Bootstrap sigma proving owner."
);
admin_prover!(
    LoadProver,
    LoadCircuit,
    LoadWitness,
    blank_load,
    "Original imported key and fixed Load sigma proving owner."
);
admin_prover!(
    ArchiveProver,
    ArchiveCircuit,
    ArchiveWitness,
    blank_archive,
    "Original imported key and fixed `ArchiveSent` sigma proving owner."
);
admin_prover!(
    UnloadProver,
    UnloadCircuit,
    ConsumingWitness,
    blank_consuming,
    "Original imported key and fixed Unload sigma proving owner."
);
admin_prover!(
    RetiringProver,
    RetiringCircuit,
    ConsumingWitness,
    blank_consuming,
    "Original imported key and fixed Retiring sigma proving owner."
);

admin_prover!(
    RefreshProver,
    RefreshCircuit,
    RefreshWitness,
    blank_refresh,
    "Original imported key for one fixed `RefreshPolicy` sigma source covering all five kinds."
);

/// Actual self-verified sigma bytes and the digest derived from the typed witness.
/// A still authenticates the original objects and binds this leaf to the operation.
#[derive(Clone, Debug)]
pub struct AdminSigmaProof {
    /// Exact unframed PIPA-R proof under the imported original key.
    pub bytes: Vec<u8>,
    /// One bounded statement digest computed from the original 26 fields.
    pub instances: [Vec<Fp>; 1],
}
