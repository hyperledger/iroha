//! Genuine final Omega original-key intake and proof production.
//!
//! The authenticated installation owner supplies the complete terminal A catalog,
//! exact source descriptor and fixed outer layout. This component imports the original
//! Pallas proving key against that compiled program and the installed VK. It verifies
//! the actual terminal A proof, derives all four Vesta fold slots from its canonical
//! frame, preserves the full original Pallas claim, and self-verifies the generated
//! Omega proof and both transported claims with complete native decisions.
//! It derives no new artifact key and grants no wallet-open or custody authority.
//! Strict import retains only source-bound verifier metadata; each proving attempt
//! rebuilds one OnDemand PK without commitment MSMs and drops it before verification.
//! Full catalog/profile authentication, original G1 preparation, source-marker admission
//! and exact G1 Payment/Credited byte qualification remain mandatory in the owning loader.

use core::fmt;

use ff::{Field, PrimeField};
use iroha_pasta::{
    Ep, Eq, EqAffine, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{
    DescriptorBinding, Protocol, ProverConfig, ProverRandomness, ProvingKey, VerifyingKey, Witness,
    create_proof_owned_with_claim,
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    frontend::Circuit,
    keys::{
        CosetCachePolicy, RebuildError, SourceBoundVerifyingKeyV2, SourceBoundViewV2,
        keygen_pk_from_vk_v2_cancellable, pk::artifact::ReadConfig,
    },
    pcs::ipa::PinnedParams,
    transcript::decode_point,
};
use iroha_plonk_gadgets::{range::secondary::SecondaryPlan, statement::foreign_limbs};
use iroha_plonk_recursion::{
    ACCUMULATOR_BYTES, AccumulatorT, FOLD_WITNESS_BYTES, FoldConfig, FoldInput, FoldWitness, K,
    VESTA_TRIVIAL_GENERATOR, create_fold, verifier::CompactSpans,
};

use super::{OmegaCircuit, OmegaPlan, OmegaWitness};

#[path = "native/layout.rs"]
mod layout;
pub use layout::compiled_policy_transcript;

#[cfg(test)]
#[path = "native/tests.rs"]
mod tests;

const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;
const LINEAGE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwomg_1");

/// Genuine original artifact/preparation/proof failure; no failure changes custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Explicit cancellation; no proof failure or burn verdict is produced.
    Cancelled,
    /// Installed descriptor/key/catalog/parameters/layout or imported source differs.
    Artifact,
    /// Original source frame, Pallas claim, incoming mode or field encoding differs.
    Input,
    /// Actual proof or complete native accumulator decision failed.
    Proof,
    /// Actual compiled circuit assignment or proof generation failed.
    Prover,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native final Omega: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Whether the operation was cancelled instead of proving an invalid input.
    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

fn fold_terminal_slots(
    params: &PinnedParams<Eq>,
    slots: &[FoldInput<Eq>],
    salt: [u8; 32],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<(FoldWitness<Eq>, AccumulatorT<Eq>), Error> {
    let config = FoldConfig {
        kernel_budget: budget,
        cancellation: cancellation.cloned(),
        ..FoldConfig::default()
    };
    create_fold(params, slots, salt, &config).map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof
        }
    })
}

/// Fixed outer source layout, supplied by the authenticated producer catalog owner.
/// The strict original-PK source import checks the exact resulting circuit. An operation
/// witness cannot choose this layout or switch it after installation.
#[derive(Clone, Debug)]
pub enum Layout {
    /// Existing complete verifier with its ordinary independent lanes.
    Ordinary,
    /// Complete verifier with fixed compact lane spans.
    Compact(CompactSpans),
    /// Complete verifier with fixed compact spans and the checked secondary range program.
    Secondary {
        /// Immutable compact lane spans of the installed source program.
        spans: CompactSpans,
        /// Exact checked secondary range schedule for that source program.
        schedule: SecondaryPlan,
    },
}

/// Immutable complete terminal catalog and native source program.
/// Construction checks genuine key syntax/profile; it does not authenticate release authority.
/// Cloning retains only source/key/parameter metadata, never an original PK or proof witness.
#[derive(Clone)]
pub struct Program {
    plan: OmegaPlan,
    source_binding: DescriptorBinding,
    source_keys: Vec<VerifyingKey<Eq>>,
    vesta: PinnedParams<Eq>,
    pallas: PinnedParams<Ep>,
    layout: Layout,
}
impl Program {
    /// Reconstruct the compiled compact source from the complete ordered terminal
    /// catalog. The secondary range schedule is derived only from unknown-source
    /// fixed tables and occupied cells, then replayed at k16 with all cell guards.
    /// No monetary witness, key generation or acceptance verdict is required.
    /// Catalog authentication and actual proof/transport qualification remain the
    /// installation owner's responsibility.
    ///
    /// # Errors
    /// Invalid terminal descriptor/catalog/parameters, unsupported fixed tape, or
    /// a source whose complete compact program does not fit the unchanged k16 cap.
    pub fn for_compiled_catalog(
        source_descriptor: &[u8],
        terminal_keys: &[Vec<u8>],
        vesta: PinnedParams<Eq>,
        pallas: PinnedParams<Ep>,
    ) -> Result<Self, Error> {
        let mut program = Self::new(
            source_descriptor,
            terminal_keys,
            vesta,
            pallas,
            Layout::Ordinary,
        )?;
        program.layout = layout::derive(&program.source_circuit()?)?;
        Ok(program)
    }

    /// Pin the complete installed terminal A key list in its authenticated catalog order.
    /// Pins the complete key catalog in the compiled source in this exact authenticated order.
    /// # Errors
    /// Not k16, bad V2 A profile, empty/duplicate/oversized catalog or malformed key.
    pub fn new(
        source_descriptor: &[u8],
        terminal_keys: &[Vec<u8>],
        vesta: PinnedParams<Eq>,
        pallas: PinnedParams<Ep>,
        layout: Layout,
    ) -> Result<Self, Error> {
        if source_descriptor.is_empty()
            || source_descriptor.len() > DESCRIPTOR_MAX_BYTES
            || terminal_keys.is_empty()
            || terminal_keys.len() > 32
            || vesta.k() != 16
            || pallas.k() != 16
        {
            return Err(Error::Artifact);
        }
        let source_binding =
            DescriptorBinding::decode_v2(source_descriptor).map_err(|_| Error::Artifact)?;
        let descriptor = source_binding.descriptor();
        if descriptor.curve != CurveV1::Vesta
            || descriptor.k != 16
            || descriptor.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || descriptor.instance_mode != InstanceModeV1::Direct
            || descriptor.proof_suffix != ProofSuffixV1::FoldedGenerator
            || descriptor.instance_lengths != [69]
            || descriptor.instance_types.as_deref()
                != Some(&[iroha_plonk::cs::InstanceType::Bounded])
        {
            return Err(Error::Artifact);
        }
        let mut source_keys = Vec::with_capacity(terminal_keys.len());
        let mut digests = Vec::with_capacity(terminal_keys.len());
        for original in terminal_keys {
            if original.is_empty() || original.len() > VERIFYING_KEY_MAX_BYTES {
                return Err(Error::Artifact);
            }
            let key =
                VerifyingKey::<Eq>::read(original, &source_binding).map_err(|_| Error::Artifact)?;
            digests.push(
                key.kagemusha_digest(&source_binding)
                    .map_err(|_| Error::Artifact)?,
            );
            source_keys.push(key);
        }
        let plan = OmegaPlan::new(source_binding.clone(), vesta.clone(), digests)
            .and_then(|plan| plan.with_key_catalog(source_keys.clone()))
            .map_err(|_| Error::Artifact)?;
        Ok(Self {
            plan,
            source_binding,
            source_keys,
            vesta,
            pallas,
            layout,
        })
    }

    fn circuit(&self, witness: OmegaWitness) -> Result<OmegaCircuit, Error> {
        let circuit = OmegaCircuit::new(self.plan.clone(), witness).map_err(|_| Error::Input)?;
        Ok(match &self.layout {
            Layout::Ordinary => circuit,
            Layout::Compact(spans) => circuit.with_compact_layout(*spans),
            Layout::Secondary { spans, schedule } => {
                circuit.with_secondary_layout(*spans, schedule.clone())
            }
        })
    }

    /// Exact unknown-witness source for offline construction and strict original
    /// intake. The complete terminal catalog and layout remain circuit metadata.
    /// This creates neither proving keys nor a proof-admission capability.
    ///
    /// # Errors
    /// The pinned source dimensions cannot construct the fixed outer circuit.
    pub fn source_circuit(&self) -> Result<OmegaCircuit, Error> {
        let length = self.plan.verifier().proof_length();
        self.circuit(OmegaWitness {
            key: self.source_keys[0].clone(),
            instances: vec![Fp::ZERO; 69],
            proof: vec![0; length],
            length: u32::try_from(length).map_err(|_| Error::Artifact)?,
            fold: [0; FOLD_WITNESS_BYTES],
        })
        .map(|circuit| circuit.without_witnesses())
    }
}

/// Original installed verifier identity and fixed program, without a retained PK.
/// No method generates a new artifact key. Proving buffers exist for one attempt only;
/// preparation and transport restore paths retain verifier metadata only.
pub struct Prover {
    program: Program,
    key: SourceBoundVerifyingKeyV2<Ep>,
}

fn rebuild_error(error: &RebuildError) -> Error {
    if error.is_cancelled() {
        Error::Cancelled
    } else {
        Error::Artifact
    }
}

impl Prover {
    /// Import one exact original PK under the installed VK and complete compiled source.
    /// # Errors
    /// Bad cap/profile/layout/rows, changed commitments or another original source/VK.
    pub fn from_original_artifact(
        program: Program,
        descriptor: &[u8],
        installed_vk: &[u8],
        original_pk: &[u8],
        config: ReadConfig,
    ) -> Result<Self, Error> {
        Self::from_original_artifact_cancellable(
            program,
            descriptor,
            installed_vk,
            original_pk,
            config,
            None,
        )
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn from_original_artifact_cancellable(
        program: Program,
        descriptor: &[u8],
        installed_vk: &[u8],
        original_pk: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        if descriptor.is_empty()
            || descriptor.len() > DESCRIPTOR_MAX_BYTES
            || installed_vk.is_empty()
            || installed_vk.len() > VERIFYING_KEY_MAX_BYTES
            || original_pk.is_empty()
            || original_pk.len() > config.maximum_bytes
        {
            return Err(Error::Artifact);
        }
        let binding = DescriptorBinding::decode_v2(descriptor).map_err(|_| Error::Artifact)?;
        let d = binding.descriptor();
        if d.curve != CurveV1::Pallas
            || d.k != 16
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_lengths != [1, 2, u32::try_from(K).map_err(|_| Error::Artifact)?]
            || d.instance_types.as_deref() != Some(&OmegaPlan::instance_types())
            || binding.n() > config.maximum_rows
        {
            return Err(Error::Artifact);
        }
        VerifyingKey::<Ep>::read(installed_vk, &binding).map_err(|_| Error::Artifact)?;
        let blank = program.source_circuit()?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original_pk,
            &binding,
            &program.pallas,
            &blank,
            config,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Artifact
            }
        })?;
        if key.vk().to_bytes() != installed_vk {
            return Err(Error::Artifact);
        }
        let identity = SourceBoundVerifyingKeyV2::from_proving_key(&key, cancellation)
            .map_err(|error| rebuild_error(&error))?;
        // Strict admission above remains the authority root. Do not retain its
        // polynomial/coset buffers between subproofs or during restore.
        drop(key);
        Ok(Self {
            program,
            key: identity,
        })
    }

    /// Exact immutable outer descriptor bound by the installed key.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        self.key.binding()
    }
    /// Exact installed native outer verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        self.key.verifying_key()
    }

    /// Move exact admitted public metadata into the installation's existing graph.
    #[must_use]
    pub fn into_metadata(self) -> SourceBoundVerifyingKeyV2<Ep> {
        self.key
    }
    /// Borrow the immutable standalone program and admitted public identity.
    #[must_use]
    pub fn view(&self) -> ProverView<'_> {
        ProverView {
            program: &self.program,
            key: self.key.view(),
        }
    }
    /// Prepare through the same borrowed implementation used by installed owners.
    /// # Errors
    /// Invalid source proof/frame/claim, fold or installed identity.
    pub fn prepare(
        &self,
        input: Input,
        salt: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<Session<'_>, Error> {
        self.view().prepare(input, salt, budget)
    }
    /// Prepare with cooperative cancellation and no partial session on refusal.
    /// # Errors
    /// As preparation, or cancellation.
    pub fn prepare_cancellable(
        &self,
        input: Input,
        salt: [u8; 32],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Session<'_>, Error> {
        self.view()
            .prepare_cancellable(input, salt, budget, cancellation)
    }
}

/// Borrowed complete program and exact admitted outer identity, without graph clones.
/// The installation owner binds this program to its strict-source admission; live
/// proof reconstruction additionally checks its complete source fingerprint.
#[derive(Clone, Copy)]
pub struct ProverView<'a> {
    program: &'a Program,
    key: SourceBoundViewV2<'a, Ep>,
}
impl<'a> ProverView<'a> {
    /// Bind exact admitted outer metadata to the retained complete source program.
    /// This component grants no catalog or installation authority.
    /// # Errors
    /// Another fixed outer protocol, k, curve or public schema.
    pub fn from_source_bound(
        program: &'a Program,
        key: SourceBoundViewV2<'a, Ep>,
    ) -> Result<Self, Error> {
        let d = key.binding().descriptor();
        if program.pallas.k() != 16
            || d.curve != CurveV1::Pallas
            || d.k != 16
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_lengths != [1, 2, u32::try_from(K).map_err(|_| Error::Artifact)?]
            || d.instance_types.as_deref() != Some(&OmegaPlan::instance_types())
        {
            return Err(Error::Artifact);
        }
        Ok(Self { program, key })
    }
    /// Exact borrowed outer descriptor.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        self.key.binding()
    }
    /// Exact borrowed outer verifier.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        self.key.verifying_key()
    }
    /// Prepare the actual final wrapper from the verified terminal A frame. Every Vesta
    /// slot, source-k and incoming selection is decoded from that same 69-word frame.
    /// # Errors
    /// Key not in installed catalog, wrong original/frame/source, failed A/P/selected-slot
    /// full verification, `D_A` or installed outer-key binding, or actual local fold failure.
    pub fn prepare(
        &self,
        input: Input,
        salt: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<Session<'a>, Error> {
        self.prepare_cancellable(input, salt, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn prepare_cancellable(
        &self,
        input: Input,
        salt: [u8; 32],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Session<'a>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let program = self.program;
        let original = input.key.to_bytes();
        let key = program
            .source_keys
            .iter()
            .find(|key| key.to_bytes() == original)
            .ok_or(Error::Artifact)?;
        if input.proof.len() != program.plan.verifier().proof_length() {
            return Err(Error::Input);
        }
        let source_public = [input.frame.to_vec()];
        iroha_plonk::verifier::verify_full_cancellable(
            &program.vesta,
            &program.source_binding,
            key,
            &source_public,
            &input.proof,
            budget,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            &program.vesta,
            &program.source_binding,
            key,
            &source_public,
            &input.proof,
            budget,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let opening = FoldInput::from_opening(*opening.g(), opening.challenges())
            .map_err(|_| Error::Proof)?;
        input
            .pallas
            .decide_cancellable(&program.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let omega_key_digest = self
            .key
            .verifying_key()
            .kagemusha_digest(self.key.binding())
            .map_err(|_| Error::Artifact)?;
        if input.public[17] != omega_key_digest
            || lineage_digest(&input.public, &input.pallas)? != input.frame[0]
        {
            return Err(Error::Input);
        }
        let slots = terminal_fold_inputs(&input.frame, opening.clone())?;
        for slot in &slots {
            slot.decide_cancellable(&program.vesta, budget, cancellation)
                .map_err(|error| {
                    if error.is_cancelled() {
                        Error::Cancelled
                    } else {
                        Error::Proof
                    }
                })?;
        }
        let (fold, vesta) =
            fold_terminal_slots(&program.vesta, &slots, salt, budget, cancellation)?;
        vesta
            .decide_cancellable(&program.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let public = outer_instances(input.frame[0], &vesta)?;
        let witness = OmegaWitness {
            key: key.clone(),
            instances: input.frame.to_vec(),
            length: u32::try_from(input.proof.len()).map_err(|_| Error::Input)?,
            proof: input.proof,
            fold: fold.to_bytes(),
        };
        let circuit = program.circuit(witness)?;
        Ok(Session {
            owner: *self,
            circuit,
            public,
            pallas: input.pallas,
            vesta,
        })
    }
}

/// Actual output of a genuine terminal A producer plus its matching native public18/P claim.
/// No host acceptance verdict, caller-computed Omega instances or optional slot objects.
pub struct Input {
    /// Actual terminal A key; must exactly equal a key in the installed complete catalog.
    pub key: VerifyingKey<Eq>,
    /// Exact original terminal A proof.
    pub proof: Vec<u8>,
    /// Exact original terminal A frame.
    pub frame: [Fp; 69],
    /// Exact source-bound eighteen-field native lineage prefix from canonical preparation.
    pub public: [Fp; 18],
    /// Full original Pallas output, bound through frame `D_A` and completely decided.
    pub pallas: AccumulatorT<Ep>,
}

/// Prepared session tied to its immutable imported owner; private fields prevent forged state.
pub struct Session<'a> {
    owner: ProverView<'a>,
    circuit: OmegaCircuit,
    public: Vec<Vec<Fq>>,
    pallas: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
}
impl Session<'_> {
    /// Restore the exact canonical final transport after interruption under this same
    /// rederived source session. Claim bytes cannot replace the prepared original P/V.
    /// # Errors
    /// Wrong total length, noncanonical/different claims, changed source public or a failed
    /// original Omega opening/full Pallas/Vesta native decision.
    pub fn restore_transport(
        &self,
        original: &[u8],
        budget: MemoryBudget,
    ) -> Result<Output, Error> {
        self.restore_transport_cancellable(original, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_transport_cancellable(
        &self,
        original: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Output, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let owner = self.owner;
        let length = Protocol::new(owner.key.binding().descriptor())
            .map_err(|_| Error::Artifact)?
            .proof_length();
        if length.checked_add(2 * ACCUMULATOR_BYTES) != Some(original.len()) {
            return Err(Error::Input);
        }
        let (proof, claims) = original.split_at(length);
        let (pallas, vesta) = claims.split_at(ACCUMULATOR_BYTES);
        let pallas = AccumulatorT::<Ep>::from_bytes(pallas).map_err(|_| Error::Input)?;
        let vesta = AccumulatorT::<Eq>::from_bytes(vesta).map_err(|_| Error::Input)?;
        if pallas != self.pallas || vesta != self.vesta {
            return Err(Error::Input);
        }
        iroha_plonk::verifier::verify_full_cancellable(
            &owner.program.pallas,
            owner.key.binding(),
            owner.key.verifying_key(),
            &self.public,
            proof,
            budget,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            &owner.program.pallas,
            owner.key.binding(),
            owner.key.verifying_key(),
            &self.public,
            proof,
            budget,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let opening = FoldInput::from_opening(*opening.g(), opening.challenges())
            .map_err(|_| Error::Proof)?;
        opening
            .decide_cancellable(&owner.program.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        pallas
            .decide_cancellable(&owner.program.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        vesta
            .decide_cancellable(&owner.program.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        Ok(Output {
            proof: proof.to_vec(),
            instances: self.public.clone(),
            pallas,
            vesta,
            opening,
        })
    }

    /// Prove the actual compiled Omega and fully verify own opening plus both transported claims.
    /// # Errors
    /// Actual witness assignment, installed proof generation or full native decisions fail.
    pub fn prove(
        &self,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<Output, Error> {
        let owner = self.owner;
        iroha_pasta::CancellationToken::checkpoint(config.cancellation)
            .map_err(|_| Error::Cancelled)?;
        let output = {
            let key = {
                let blank = owner.program.source_circuit()?;
                keygen_pk_from_vk_v2_cancellable(
                    &owner.program.pallas,
                    &blank,
                    &owner.key,
                    CosetCachePolicy::OnDemand,
                    config.cancellation,
                )
                .map_err(|error| rebuild_error(&error))?
            };
            let witness = Witness::from_circuit_cancellable(
                &key,
                &self.circuit,
                &self.public,
                config.cancellation,
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Prover
                }
            })?;
            let output = create_proof_owned_with_claim(
                &owner.program.pallas,
                &key,
                witness,
                randomness,
                config,
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Prover
                }
            })?;
            // No PK survives into native verification/decides. Lexical ownership
            // also drops it on every earlier error, cancellation or unwind.
            drop(key);
            output
        };
        let expected = Protocol::new(owner.key.binding().descriptor())
            .map_err(|_| Error::Artifact)?
            .proof_length();
        if output.proof.len() != expected {
            return Err(Error::Proof);
        }
        iroha_plonk::verifier::verify_full_cancellable(
            &owner.program.pallas,
            owner.key.binding(),
            owner.key.verifying_key(),
            &self.public,
            &output.proof,
            config.msm_budget,
            config.cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        output
            .opening
            .decide_cancellable(
                &owner.program.pallas,
                config.msm_budget,
                config.cancellation,
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        self.pallas
            .decide_cancellable(
                &owner.program.pallas,
                config.msm_budget,
                config.cancellation,
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        self.vesta
            .decide_cancellable(&owner.program.vesta, config.msm_budget, config.cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let opening = FoldInput::from_opening(*output.opening.g(), output.opening.challenges())
            .map_err(|_| Error::Proof)?;
        Ok(Output {
            proof: output.proof,
            instances: self.public.clone(),
            pallas: self.pallas.clone(),
            vesta: self.vesta.clone(),
            opening,
        })
    }
}

/// Genuine fully self-verified final native proof and distinct preserved obligations.
pub struct Output {
    /// Exact outer Omega proof.
    pub proof: Vec<u8>,
    /// Native public columns derived from source `D_A` and actual four-slot fold.
    pub instances: Vec<Vec<Fq>>,
    /// Original source full Pallas claim, distinct from the outer proof's own opening.
    pub pallas: AccumulatorT<Ep>,
    /// Actual full Vesta result of the four-slot local fold.
    pub vesta: AccumulatorT<Eq>,
    /// Outer proof's own opening, fully decided and retained separately.
    pub opening: FoldInput<Ep>,
}
impl Output {
    /// Canonical native unframed transport: original Omega proof || P544 || V544.
    /// The owning complete G1 allowlist enforces its exact admitted length and wire caps.
    #[must_use]
    pub fn transport(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.proof.len() + 2 * ACCUMULATOR_BYTES);
        bytes.extend_from_slice(&self.proof);
        bytes.extend_from_slice(&self.pallas.to_bytes());
        bytes.extend_from_slice(&self.vesta.to_bytes());
        bytes
    }
}

fn native_u128(value: Fp) -> Result<u128, Error> {
    let bytes = value.to_repr();
    if bytes[16..].iter().any(|byte| *byte != 0) {
        return Err(Error::Input);
    }
    Ok(u128::from_le_bytes(
        bytes[..16].try_into().map_err(|_| Error::Input)?,
    ))
}
fn foreign_coordinate(words: &[Fp]) -> Result<Fq, Error> {
    let [low, high] = words else {
        return Err(Error::Input);
    };
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&native_u128(*low)?.to_le_bytes());
    bytes[16..].copy_from_slice(&native_u128(*high)?.to_le_bytes());
    Option::<Fq>::from(Fq::from_repr(bytes)).ok_or(Error::Input)
}
fn point(words: &[Fp]) -> Result<EqAffine, Error> {
    if words.len() != 4 {
        return Err(Error::Input);
    }
    let point = Option::<EqAffine>::from(EqAffine::from_xy(
        foreign_coordinate(&words[..2])?,
        foreign_coordinate(&words[2..])?,
    ))
    .ok_or(Error::Input)?;
    // Pasta encodes the identity as (0, 0); a transported fold claim requires
    // a nonidentity affine point, including in an unselected incoming slot.
    if bool::from(point.coordinates().is_none()) {
        return Err(Error::Input);
    }
    Ok(point)
}
fn claim(point_words: &[Fp], challenges: &[Fp], source_k: u32) -> Result<FoldInput<Eq>, Error> {
    FoldInput::from_normalized(
        point(point_words)?,
        source_k,
        challenges.try_into().map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)
}
/// Derive the four ordered Vesta fold inputs from a canonical terminal A frame.
/// This checks only frame encoding and incoming-mode selection. It does not
/// verify the A proof, decide any original claim, or grant artifact/catalog
/// authority. Production preparation authenticates those boundaries separately.
///
/// # Errors
/// A malformed field, source domain, curve point or incoming selection, including
/// a corrected commitment equal to the original incoming commitment.
pub fn terminal_fold_inputs(
    frame: &[Fp; 69],
    opening: FoldInput<Eq>,
) -> Result<[FoldInput<Eq>; 4], Error> {
    let source_k = u32::try_from(native_u128(frame[1])?).map_err(|_| Error::Input)?;
    if !matches!(source_k, 12 | 14 | 16) || opening.source_k() != 16 {
        return Err(Error::Input);
    }
    let part = claim(&frame[2..6], &frame[6..22], source_k)?;
    let predecessor = claim(&frame[22..26], &frame[26..42], 16)?;
    let incoming = claim(&frame[42..46], &frame[46..62], 16)?;
    let corrected = point(&frame[65..69])?;
    let selected = match [frame[62], frame[63], frame[64]] {
        modes if modes == [Fp::ONE, Fp::ZERO, Fp::ZERO] => incoming,
        modes if modes == [Fp::ZERO, Fp::ONE, Fp::ZERO] => FoldInput::from_normalized(
            decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Artifact)?,
            16,
            [Fp::ONE; K],
        )
        .map_err(|_| Error::Artifact)?,
        modes if modes == [Fp::ZERO, Fp::ZERO, Fp::ONE] => {
            if &corrected == incoming.g() {
                return Err(Error::Input);
            }
            FoldInput::from_normalized(corrected, 16, *incoming.challenges())
                .map_err(|_| Error::Input)?
        }
        _ => return Err(Error::Input),
    };
    Ok([part, opening, predecessor, selected])
}
fn lineage_digest(public: &[Fp; 18], pallas: &AccumulatorT<Ep>) -> Result<Fp, Error> {
    let (x, y) = Option::<(Fp, Fp)>::from(pallas.g().coordinates()).ok_or(Error::Input)?;
    let mut fields = public.to_vec();
    fields.extend([x, y]);
    for challenge in pallas.challenges() {
        fields.extend(foreign_limbs(challenge).map(Fp::from_u128));
    }
    if fields.len() != 52 {
        return Err(Error::Input);
    }
    Ok(hash_with_domain(LINEAGE_DOMAIN, &fields))
}
fn outer_instances(context: Fp, vesta: &AccumulatorT<Eq>) -> Result<Vec<Vec<Fq>>, Error> {
    let (x, y) = Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Input)?;
    let context = Option::<Fq>::from(Fq::from_repr(context.to_repr())).ok_or(Error::Input)?;
    let challenges = vesta
        .challenges()
        .iter()
        .map(|value| Option::<Fq>::from(Fq::from_repr(value.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![vec![context], vec![x, y], challenges])
}
