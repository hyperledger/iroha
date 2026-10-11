//! Production Bootstrap A1/W/A2 assembly from original signed object tapes.
//!
//! The installed owner authenticates the fixed Q/A/W plan and verifier identities
//! independently of operation witnesses. Original A/W proving material is imported
//! against those keys and the exact witnessless compiled source; no separate PK
//! byte-signing format is required by this component. The owner converts canonical
//! G1 objects to these typed proof inputs. Every Q proof is verified in full here;
//! A1 binds its sigma tape, A2 authenticates the original Enrollment certificate,
//! Credential and Advance Receipt and retains Q0, W and Q1 opening obligations.
//! The terminal A proof is an input to the separately installed final Omega
//! catalog. Neither an intermediate W nor this terminal output is monetary
//! completion or a transported Omega. No method generates runtime artifact keys.

use iroha_plonk::keys::{SourceAdmissionSealV2, SourceBoundViewV2};
#[path = "bootstrap/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{CheckpointKind, CheckpointLayout};

use super::artifact::KeyArtifact;
use core::fmt;
use std::sync::Arc;

use ff::{Field, PrimeField};
use iroha_pasta::{
    Ep, Eq, EqAffine, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{
    DescriptorBinding, ProverConfig, ProverRandomness, ProvingKey, VerifyingKey,
    cs::{
        Column, ConstraintSystem, CurveV1, Instance, InstanceModeV1, InstanceType, ProofSuffixV1,
        TranscriptV2,
    },
    frontend::{Circuit, Error as LayoutError, Layouter, Region, SimpleFloorPlanner, Value},
    keys::pk::artifact::ReadConfig,
    pcs::ipa::PinnedParams,
    transcript::decode_point,
};
use iroha_plonk_gadgets::{
    GlueChip, Word,
    bytes::{
        element::le_message_segments,
        le_value, p_bytes_native,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    p256::VerifyMode,
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, K, VESTA_TRIVIAL_GENERATOR,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

use super::super::{
    AProofPlan, LineagePublicCells, ProofMessageCells, SigmaBindingCells, VestaClaimCells,
    bind_signature_q,
    bootstrap::{BootstrapInputs, BootstrapObjects, BootstrapPolicy},
    context::{ContextInputs, ContextPlan, ContextState},
    split::{SplitPlan, WCircuit, WKey, close_first, close_stage, resume_context},
    verify_q, verify_sigma,
};
use crate::{
    admin_sigma::BootstrapWitness,
    omega::OmegaWitness,
    operation_relation::{objects::ObjectKind, state::StateCells, statement::StatementCells},
    q_signature::{QSignaturePlan, SignatureKey},
};

/// The fixed source profile measured with the complete Bootstrap/Load catalog.
/// A witness cannot select another bus count or a generic fallback profile.
pub const SOURCE_RANGE_BUSES: usize = 3;

const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

fn terminal_restore_fold_config(
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> FoldConfig {
    FoldConfig {
        kernel_budget: budget,
        cancellation: cancellation.cloned(),
        ..FoldConfig::default()
    }
}

/// Production preparation or proof failure. No failure changes a monetary head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Explicit cancellation; no proof failure or burn verdict is produced.
    Cancelled,
    /// The installed stage/Q key, schema or pinned parameters differ.
    Artifact,
    /// A supplied original, frame, obligation or typed input is malformed.
    Input,
    /// A source or generated proof or complete decide failed.
    Proof,
    /// The exact installed circuit failed assignment or proving.
    Prover,
}
impl From<super::proving::Error> for Error {
    fn from(error: super::proving::Error) -> Self {
        match error {
            super::proving::Error::Cancelled => Self::Cancelled,
            super::proving::Error::Artifact => Self::Artifact,
            super::proving::Error::Prover => Self::Prover,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native Bootstrap: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Whether the operation was cancelled instead of proving an invalid input.
    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// One original Q proof and the exact public columns that proof authenticates.
/// Public instance values are witnesses, never a native acceptance verdict.
#[derive(Clone, Debug)]
pub struct QInput {
    /// Descriptor-sized proof bytes retained by the owning native producer.
    pub proof: Vec<u8>,
    /// Exact descriptor-shaped public columns.
    pub instances: Vec<Vec<Fq>>,
}

/// Original post-Advance inputs for Bootstrap's complete lineage composition.
/// The native G1 owner validates enrollment, canonical objects and custody before
/// conversion. These inputs are additionally checked by the actual A circuits.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Exact core33, rest8, public18 and statement26 field transcripts.
    pub state: BootstrapWitness,
    /// Original unframed sigma bytes, identical to Q0's exported carrier.
    pub sigma: Vec<u8>,
    /// Original canonical Certificate, Credential and Advance Receipt bytes.
    pub objects: [Vec<u8>; 3],
    /// The hard sigma-verification Q, followed by the hard three-signature Q.
    pub q: [QInput; 2],
}

/// Installed A1 and W0 keys for the first recursive transition.
#[derive(Clone, Copy)]
struct WrapperKeys<'a> {
    /// Exact first-stage verifier metadata whose proof W0 consumes.
    first: &'a KeyArtifact<Eq>,
    /// Exact source-bound W0 verifier metadata.
    wrapper: &'a SourceBoundViewV2<'a, Ep>,
}

/// Installed W0 and terminal A2 keys for the final Bootstrap transition.
#[derive(Clone, Copy)]
struct TerminalKeys<'a> {
    /// Verified wrapper metadata pinned by the terminal relation.
    wrapper: &'a WKey,
    /// Exact source-bound terminal A2 verifier metadata.
    terminal: &'a SourceBoundViewV2<'a, Eq>,
}

/// The fixed W0 circuit, its exact public columns and its Vesta obligation.
pub type WrapperPreparation = (WCircuit, Vec<Vec<Fq>>, AccumulatorT<Eq>);

/// Fixed Bootstrap circuit metadata from the authenticated native artifact owner.
/// No field is populated from an operation's witness or wire proof profile.
#[derive(Clone, Debug)]
pub struct Plan {
    context: ContextPlan,
    policy: BootstrapPolicy,
    signatures: QSignaturePlan,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin exactly Q0 in A1 and Q1 plus all Bootstrap tasks in A2.
    ///
    /// Signature slots are hard `[receipt, credential, certificate]`, with a
    /// fixed root for the certificate. The certificate/root equality is also
    /// constrained by `BootstrapObjects::authenticate` under `policy`.
    ///
    /// # Errors
    /// Wrong variant, slot/schema count, parameter k or signature key policy.
    pub fn new(
        operation: AProofPlan,
        policy: BootstrapPolicy,
        signatures: QSignaturePlan,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        if operation.frame().variant() != Variant::Bootstrap
            || operation.frame().part_source_k() != crate::admin_sigma::BOOTSTRAP_K
            || operation.q_count() != 2
        {
            return Err(Error::Artifact);
        }
        pallas.require_k(16).map_err(|_| Error::Artifact)?;
        vesta.require_k(16).map_err(|_| Error::Artifact)?;
        let slots = signatures.slots();
        if slots.len() != 3
            || slots.iter().any(|slot| slot.mode != VerifyMode::Hard)
            || slots[0].key != SignatureKey::Variable
            || slots[1].key != SignatureKey::Variable
            || !matches!(slots[2].key, SignatureKey::Fixed(_))
        {
            return Err(Error::Artifact);
        }
        let q1 = operation
            .q(1)
            .ok_or(Error::Artifact)?
            .verifier()
            .binding()
            .descriptor();
        if q1.instance_lengths
            != [u32::try_from(signatures.instance_length()).map_err(|_| Error::Artifact)?]
            || q1.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        {
            return Err(Error::Artifact);
        }
        let context = crate::a_relation::schedule::compiled::OperationSchedule::for_variant(
            Variant::Bootstrap,
        )
        .bind(
            operation,
            BootstrapObjects::context_specs()
                .map_err(|_| Error::Artifact)?
                .to_vec(),
        )
        .map_err(|_| Error::Artifact)?;
        Ok(Self {
            context,
            policy,
            signatures,
            pallas,
            vesta,
        })
    }

    /// Fixed complete context schema, including the exact Q keys and task owners.
    #[must_use]
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }

    /// Validate original dimensions and verify both source Q proofs in full.
    /// The resulting openings are independently decided, never caller supplied.
    ///
    /// # Errors
    /// Invalid originals, substituted public columns or failed proof/decide.
    pub fn prepare(&self, input: Inputs, budget: MemoryBudget) -> Result<Prepared, Error> {
        self.prepare_cancellable(input, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn prepare_cancellable(
        &self,
        input: Inputs,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Prepared, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        for (kind, original) in object_kinds().into_iter().zip(&input.objects) {
            if original.len() != kind.body_len() + 64 {
                return Err(Error::Input);
            }
        }
        let sigma_class = self
            .context
            .operation()
            .sigma
            .class(0)
            .ok_or(Error::Artifact)?;
        if input.sigma.len() != sigma_class.verifier().proof_length() {
            return Err(Error::Input);
        }
        let mut openings = Vec::with_capacity(2);
        for (index, original) in input.q.iter().enumerate() {
            let fixed = self.context.operation().q(index).ok_or(Error::Artifact)?;
            iroha_plonk::verifier::verify_full_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &original.instances,
                &original.proof,
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
            let claim = iroha_plonk::verifier::accumulate_generator_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &original.instances,
                &original.proof,
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
            let opening = FoldInput::from_opening(*claim.g(), claim.challenges())
                .map_err(|_| Error::Proof)?;
            opening
                .decide_cancellable(&self.pallas, budget, cancellation)
                .map_err(|error| {
                    if error.is_cancelled() {
                        Error::Cancelled
                    } else {
                        Error::Proof
                    }
                })?;
            openings.push(opening);
        }
        check_sigma_tape(&input)?;
        let part = q_sigma_part(
            &input.q[0],
            self.context.operation().frame().part_source_k(),
        )?;
        part.decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let original = Arc::new(input);
        Ok(Prepared {
            plan: Arc::new(self.clone()),
            original,
            openings: openings.try_into().map_err(|_| Error::Input)?,
            part,
        })
    }
}

fn object_kinds() -> [ObjectKind; 3] {
    [
        ObjectKind::Certificate,
        ObjectKind::Credential,
        ObjectKind::Receipt,
    ]
}

fn check_sigma_tape(input: &Inputs) -> Result<(), Error> {
    let bounded = input.q[0].instances.first().ok_or(Error::Input)?;
    let length = u32::try_from(input.sigma.len()).map_err(|_| Error::Input)?;
    let mut raw = length.to_le_bytes().to_vec();
    raw.extend(&input.sigma);
    let chunks = raw
        .chunks(31)
        .map(|bytes| le_value::<Fq>(bytes).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    let statement = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &input.state.statement,
    );
    let statement = Option::<Fq>::from(Fq::from_repr(statement.to_repr())).ok_or(Error::Input)?;
    if bounded.len() != 1 + chunks.len() + K
        || bounded[0] != statement
        || bounded[1..=chunks.len()] != chunks
        || input.q[0].instances.get(2).map(Vec::as_slice) != Some(&[Fq::ZERO])
    {
        return Err(Error::Input);
    }
    Ok(())
}

fn artifact_metadata<C: iroha_pasta::PastaCurve>(
    artifact: &KeyArtifact<C>,
    curve: CurveV1,
    lengths: &[u32],
    types: &[InstanceType],
) -> Result<(), Error> {
    let binding = artifact.binding();
    let d = binding.descriptor();
    if binding.encoded().len() > DESCRIPTOR_MAX_BYTES
        || artifact.key().to_bytes().len() > VERIFYING_KEY_MAX_BYTES
        || d.k != 16
        || d.curve != curve
        || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != InstanceModeV1::Direct
        || d.proof_suffix != ProofSuffixV1::FoldedGenerator
        || d.instance_lengths.as_slice() != lengths
        || d.instance_types.as_deref() != Some(types)
    {
        return Err(Error::Artifact);
    }
    Ok(())
}
fn original_bounds(original: &[u8], rows: usize, config: ReadConfig) -> Result<(), Error> {
    if original.is_empty() || original.len() > config.maximum_bytes || rows > config.maximum_rows {
        return Err(Error::Artifact);
    }
    Ok(())
}

/// Verifier metadata mounted against the single fixed Bootstrap plan.
/// The owner authenticates the plan and verifier identities independently. This
/// producer retains neither original PK bytes nor proving polynomials. Each proof
/// borrows one strictly imported key and rechecks its complete installed identity.
/// TODO(G3/G4): connect the complete authenticated producer catalog and original
/// G1 preparation to the wallet owner before enabling Native wallet open.
pub struct Prover {
    plan: Plan,
    first: KeyArtifact<Eq>,
    wrapper: KeyArtifact<Ep>,
    terminal: KeyArtifact<Eq>,
    w: WKey,
}
impl Prover {
    /// Mount A1/W0/A2 verifier metadata without retaining any proving key.
    ///
    /// The installation owner authenticates the scheme, Q keys, roots, schedule,
    /// descriptors and complete compiled-source catalog before this call. This
    /// constructor checks metadata consistency, not scheme/catalog authority or
    /// original-key admissibility. The per-stage importers perform exact source,
    /// table and commitment checks with no transaction witness or runtime keygen.
    /// # Errors
    /// Wrong stage/curve/k/public profile or noncanonical source descriptor.
    pub fn from_artifacts(
        plan: Plan,
        first: KeyArtifact<Eq>,
        wrapper: KeyArtifact<Ep>,
        terminal: KeyArtifact<Eq>,
    ) -> Result<Self, Error> {
        artifact_metadata(&first, CurveV1::Vesta, &[69], &[InstanceType::Bounded])?;
        artifact_metadata(
            &wrapper,
            CurveV1::Pallas,
            &[1, 2, 16],
            &crate::omega::OmegaPlan::instance_types(),
        )?;
        artifact_metadata(&terminal, CurveV1::Vesta, &[69], &[InstanceType::Bounded])?;
        let expected =
            super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?;
        if first.binding() != &expected || terminal.binding() != &expected {
            return Err(Error::Artifact);
        }
        let w = WKey::from_artifact(
            &plan.context,
            0,
            wrapper.binding().clone(),
            plan.pallas.clone(),
            wrapper.key().clone(),
        )
        .map_err(|_| Error::Artifact)?;
        Ok(Self {
            plan,
            first,
            wrapper,
            terminal,
            w,
        })
    }

    /// Import exactly one A1 original against the fixed unknown first-stage source.
    /// The imported PK is dropped before returning its compact source-admission seal.
    /// # Errors
    /// Original/domain cap, source/table/commitment or complete installed-key mismatch.
    pub fn import_first(
        &self,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_first_cancellable(original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_first_cancellable(
        &self,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        original_bounds(original, self.first.binding().n(), config)?;
        let source = self.plan.source_circuit(0, None)?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            self.first.binding(),
            &self.plan.vesta,
            &source,
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
        self.first
            .require_prover(&key)
            .map_err(|_| Error::Artifact)?;
        let metadata =
            SourceAdmissionSealV2::from_proving_key(&key, cancellation).map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })?;
        drop(key);
        Ok(metadata)
    }

    /// Import exactly one W0 original bound to the complete installed A1 identity.
    /// The imported PK is dropped before returning its compact source-admission seal.
    /// # Errors
    /// Original/domain cap, source/table/commitment or complete installed-key mismatch.
    pub fn import_wrapper(
        &self,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        self.import_wrapper_cancellable(original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_wrapper_cancellable(
        &self,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        original_bounds(original, self.wrapper.binding().n(), config)?;
        let source = self
            .plan
            .wrapper_source(0, self.first.binding(), self.first.key())?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            self.wrapper.binding(),
            &self.plan.pallas,
            &source,
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
        self.wrapper
            .require_prover(&key)
            .map_err(|_| Error::Artifact)?;
        let metadata =
            SourceAdmissionSealV2::from_proving_key(&key, cancellation).map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })?;
        drop(key);
        Ok(metadata)
    }

    /// Import exactly one A2 original bound to the complete installed W0 identity.
    /// The imported PK is dropped before returning its compact source-admission seal.
    /// # Errors
    /// Original/domain cap, source/table/commitment or complete installed-key mismatch.
    pub fn import_terminal(
        &self,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_terminal_cancellable(original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_terminal_cancellable(
        &self,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        original_bounds(original, self.terminal.binding().n(), config)?;
        let source = self.plan.source_circuit(1, Some(self.w.clone()))?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            self.terminal.binding(),
            &self.plan.vesta,
            &source,
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
        self.terminal
            .require_prover(&key)
            .map_err(|_| Error::Artifact)?;
        let metadata =
            SourceAdmissionSealV2::from_proving_key(&key, cancellation).map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })?;
        drop(key);
        Ok(metadata)
    }

    /// Verify source inputs and create a session using only these installed keys.
    ///
    /// # Errors
    /// Any source proof, complete decide or original-tape mismatch.
    pub fn prepare(&self, inputs: Inputs, budget: MemoryBudget) -> Result<Session<'_>, Error> {
        self.prepare_cancellable(inputs, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn prepare_cancellable(
        &self,
        inputs: Inputs,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Session<'_>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        Ok(Session {
            prover: self,
            prepared: self
                .plan
                .prepare_cancellable(inputs, budget, cancellation)?,
        })
    }

    /// Fixed descriptors of the three checkpoint/proof stages, in actual order.
    #[must_use]
    pub fn descriptors(&self) -> [&iroha_plonk::DescriptorBinding; 3] {
        [
            self.first.binding(),
            self.wrapper.binding(),
            self.terminal.binding(),
        ]
    }
}

/// One exact Bootstrap source coupled to immutable installed verifier metadata.
/// The custody owner retains source originals and checkpoints before advancing.
pub struct Session<'a> {
    prover: &'a Prover,
    prepared: Prepared,
}
impl Session<'_> {
    /// Compute the actual first checkpoint using the installed A1 key.
    /// # Errors
    /// Wrong installed circuit, failed proof or complete decide.
    pub fn first(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<FirstCheckpoint, Error> {
        self.prover
            .first
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.prepared.prove_first(key, randomness, config)
    }
    /// Reverify A1 proof bytes reloaded from the source-bound custody archive.
    /// # Errors
    /// A substituted checkpoint, context, source key or failed proof.
    pub fn restore_first(
        &self,
        proof: Vec<u8>,
        budget: MemoryBudget,
    ) -> Result<FirstCheckpoint, Error> {
        self.restore_first_cancellable(proof, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_first_cancellable(
        &self,
        proof: Vec<u8>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FirstCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let mut public = frame(
            &self.prepared.original.state.lineage,
            &self.prepared.openings[0],
            &self.prepared.part,
        )?;
        public[0] = self.prepared.first_stage_digest()?;
        let checkpoint = FirstCheckpoint {
            public,
            proof,
            carried: self.prepared.openings[0].clone(),
        };
        self.prepared.resume_first_cancellable(
            self.prover.first.key(),
            self.prover.first.binding(),
            checkpoint,
            budget,
            cancellation,
        )
    }
    /// Compute W0 from the exact first checkpoint using the installed wrapper key.
    /// # Errors
    /// A wrong source checkpoint or failed proof, fold or decide.
    pub fn wrapper(
        &self,
        first: &FirstCheckpoint,
        key: &SourceBoundViewV2<'_, Ep>,
        salt: Fq,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<WrapperCheckpoint, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        self.prover
            .wrapper
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.prepared.prove_wrapper(
            first,
            WrapperKeys {
                first: &self.prover.first,
                wrapper: key,
            },
            salt,
            fold,
            randomness,
            config,
        )
    }
    /// Reverify retained W proof and exact canonical Vesta claim from custody.
    /// # Errors
    /// A changed original context, noncanonical accumulator or failed proof/decide.
    pub fn restore_wrapper(
        &self,
        proof: Vec<u8>,
        vesta: &[u8],
        budget: MemoryBudget,
    ) -> Result<WrapperCheckpoint, Error> {
        self.restore_wrapper_cancellable(proof, vesta, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_wrapper_cancellable(
        &self,
        proof: Vec<u8>,
        vesta: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<WrapperCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let vesta = AccumulatorT::from_bytes(vesta).map_err(|_| Error::Input)?;
        let checkpoint = WrapperCheckpoint {
            proof,
            vesta,
            context: self.prepared.first_stage_digest()?,
        };
        self.prepared
            .resume_wrapper_cancellable(&self.prover.w, checkpoint, budget, cancellation)
    }
    /// Restore terminal A2 from its original proof, retained fold salt and exact
    /// verified W0 predecessor. The Pallas fold, public fields and every forwarded
    /// obligation are rederived from this session's original inputs.
    /// # Errors
    /// Changed source/salt, wrong installed proof or failed fold/decide.
    pub fn restore_terminal(
        &self,
        wrapper: &WrapperCheckpoint,
        proof: Vec<u8>,
        salt: Fp,
        budget: MemoryBudget,
    ) -> Result<Terminal, Error> {
        self.restore_terminal_cancellable(wrapper, proof, salt, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_terminal_cancellable(
        &self,
        wrapper: &WrapperCheckpoint,
        proof: Vec<u8>,
        salt: Fp,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let fold = terminal_restore_fold_config(budget, cancellation);
        let (_, public, pallas) =
            self.prepared
                .terminal_circuit(wrapper, &self.prover.w, salt, &fold)?;
        let source = &self.prover.terminal;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            source.binding(),
            source.key(),
            std::slice::from_ref(&public),
            &proof,
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
        let claim = iroha_plonk::verifier::accumulate_generator_cancellable(
            &self.prepared.plan.vesta,
            source.binding(),
            source.key(),
            std::slice::from_ref(&public),
            &proof,
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
        let opening =
            FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
        opening
            .decide_cancellable(&self.prepared.plan.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas,
            vesta: wrapper.vesta.clone(),
            opening,
        })
    }

    /// Compute the actual terminal A2 result using its installed key.
    /// # Errors
    /// A wrong W, source/profile mismatch or failed proof/fold/decide.
    pub fn terminal(
        &self,
        wrapper: &WrapperCheckpoint,
        key: &SourceBoundViewV2<'_, Eq>,
        salt: Fp,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<Terminal, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        self.prover
            .terminal
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.prepared.prove_terminal(
            wrapper,
            TerminalKeys {
                wrapper: &self.prover.w,
                terminal: key,
            },
            salt,
            fold,
            randomness,
            config,
        )
    }
}

fn q_sigma_part(input: &QInput, source_k: u32) -> Result<FoldInput<Eq>, Error> {
    let [bounded, point, indices, verdicts, source] = input.instances.as_slice() else {
        return Err(Error::Input);
    };
    if point.len() != 2
        || indices.len() != 1
        || verdicts.as_slice() != [Fq::ONE]
        || source.as_slice() != [Fq::from(u64::from(source_k))]
        || bounded.len() < K
    {
        return Err(Error::Input);
    }
    let g = Option::<EqAffine>::from(EqAffine::from_xy(point[0], point[1])).ok_or(Error::Input)?;
    let challenges = bounded[bounded.len() - K..]
        .iter()
        .map(|value| Option::<Fp>::from(Fp::from_repr(value.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    FoldInput::from_normalized(
        g,
        source_k,
        challenges.try_into().map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)
}

/// Prepared exact source Q proofs and all of their checked opening obligations.
/// Private fields prevent substituting an unverified opening or another tape.
#[derive(Clone)]
pub struct Prepared {
    plan: Arc<Plan>,
    original: Arc<Inputs>,
    openings: [FoldInput<Ep>; 2],
    part: FoldInput<Eq>,
}
impl Prepared {
    /// First A stage. It binds the actual sigma bytes and every deferred object
    /// and Q instance into the same committed context used by A2.
    #[must_use]
    pub fn first_circuit(&self) -> StageCircuit {
        StageCircuit {
            plan: self.plan.clone(),
            original: self.original.clone(),
            carried: Some(self.openings[0].clone()),
            stage: Stage::First,
            known: true,
        }
    }

    /// Generate A1 only by reconstructing its admitted fixed source.
    /// Its complete opening is verified and decided before returning.
    ///
    /// # Errors
    /// A mismatching key/circuit, failed proof or malformed public frame.
    fn prove_first(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<FirstCheckpoint, Error> {
        let circuit = self.first_circuit();
        let carried = &self.openings[0];
        let mut public = frame(&self.original.state.lineage, carried, &self.part)?;
        public[0] = self.first_stage_digest()?;
        let proof = prove_vesta(&self.plan, key, &circuit, &public, randomness, config)?;
        Ok(FirstCheckpoint {
            public,
            proof,
            carried: carried.clone(),
        })
    }

    /// Reverify a durably retained A1 checkpoint against these exact originals
    /// and the already installed stage key. No checkpoint verdict is trusted.
    ///
    /// # Errors
    /// Another context/public frame, wrong source key or failed proof/decide.
    pub fn resume_first(
        &self,
        key: &VerifyingKey<Eq>,
        binding: &iroha_plonk::DescriptorBinding,
        checkpoint: FirstCheckpoint,
        budget: MemoryBudget,
    ) -> Result<FirstCheckpoint, Error> {
        self.resume_first_cancellable(key, binding, checkpoint, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn resume_first_cancellable(
        &self,
        key: &VerifyingKey<Eq>,
        binding: &iroha_plonk::DescriptorBinding,
        checkpoint: FirstCheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FirstCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let mut expected = frame(&self.original.state.lineage, &self.openings[0], &self.part)?;
        expected[0] = self.first_stage_digest()?;
        if checkpoint.public != expected || checkpoint.carried != self.openings[0] {
            return Err(Error::Input);
        }
        iroha_plonk::verifier::verify_full_cancellable(
            &self.plan.vesta,
            binding,
            key,
            &[expected],
            &checkpoint.proof,
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
        Ok(checkpoint)
    }

    /// Build the fixed W0 relation consuming this exact A1 key and original proof.
    /// A full-k16 pinned trivial slot is explicit even when sigma is shorter.
    ///
    /// # Errors
    /// A1 public/descriptor mismatch or failure of the exact four-input fold.
    pub fn wrapper_circuit(
        &self,
        first: &FirstCheckpoint,
        a1: &KeyArtifact<Eq>,
        salt: Fq,
        config: &FoldConfig,
    ) -> Result<WrapperPreparation, Error> {
        self.resume_first_cancellable(
            a1.key(),
            a1.binding(),
            first.clone(),
            config.kernel_budget,
            config.cancellation.as_ref(),
        )?;
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            &self.plan.vesta,
            a1.binding(),
            a1.key(),
            std::slice::from_ref(&first.public),
            &first.proof,
            config.kernel_budget,
            config.cancellation.as_ref(),
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
        let trivial = AccumulatorT::trivial_cancellable(
            &self.plan.vesta,
            config.kernel_budget,
            config.cancellation.as_ref(),
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let (fold, vesta) = create_fold(
            &self.plan.vesta,
            &[
                self.part.clone(),
                opening,
                trivial.as_input(),
                trivial.as_input(),
            ],
            salt.to_repr(),
            config,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        vesta
            .decide_cancellable(
                &self.plan.vesta,
                config.kernel_budget,
                config.cancellation.as_ref(),
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let allowed = a1
            .key()
            .kagemusha_digest(a1.binding())
            .map_err(|_| Error::Artifact)?;
        let circuit = WCircuit::new(
            &self.plan.context,
            0,
            a1.binding().clone(),
            self.plan.vesta.clone(),
            vec![allowed],
            OmegaWitness {
                key: a1.key().clone(),
                instances: first.public.clone(),
                proof: first.proof.clone(),
                length: u32::try_from(first.proof.len()).map_err(|_| Error::Input)?,
                fold: fold.to_bytes(),
            },
        )
        .map_err(|_| Error::Input)?;
        let instances = omega_instances(self.first_stage_digest()?, &vesta)?;
        Ok((circuit, instances, vesta))
    }

    /// Prove W0 using the installed key. This checkpoint remains internal and
    /// cannot be used as the final Omega key or monetary completion.
    ///
    /// # Errors
    /// Wrong first/wrapper key, malformed instances, failed proof or decide.
    fn prove_wrapper(
        &self,
        first: &FirstCheckpoint,
        keys: WrapperKeys<'_>,
        salt: Fq,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<WrapperCheckpoint, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        let WrapperKeys {
            first: a1,
            wrapper: w,
        } = keys;
        let (circuit, instances, vesta) = self.wrapper_circuit(first, a1, salt, fold)?;
        let output = super::proving::prove(
            &self.plan.pallas,
            w,
            &circuit,
            &instances,
            randomness,
            config,
        )?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.plan.pallas,
            w.binding(),
            w.verifying_key(),
            &instances,
            &output.proof,
            fold.kernel_budget,
            config.cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        Ok(WrapperCheckpoint {
            proof: output.proof,
            vesta,
            context: self.first_stage_digest()?,
        })
    }

    /// Reverify the exact retained W proof, its complete Vesta obligation and
    /// its context binding before continuation. Transported metadata is never
    /// accepted as an operation-authorization boolean.
    ///
    /// # Errors
    /// Context substitution, wrong W key or failed proof/decide.
    pub fn resume_wrapper(
        &self,
        w: &WKey,
        checkpoint: WrapperCheckpoint,
        budget: MemoryBudget,
    ) -> Result<WrapperCheckpoint, Error> {
        self.resume_wrapper_cancellable(w, checkpoint, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn resume_wrapper_cancellable(
        &self,
        w: &WKey,
        checkpoint: WrapperCheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<WrapperCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        if checkpoint.context != self.first_stage_digest()? {
            return Err(Error::Input);
        }
        let public = omega_instances(checkpoint.context, &checkpoint.vesta)?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.plan.pallas,
            w.verifier().binding(),
            w.verifying_key(),
            &public,
            &checkpoint.proof,
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
        checkpoint
            .vesta
            .decide_cancellable(&self.plan.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        Ok(checkpoint)
    }

    /// Prepare A2's exact three-input Pallas fold: Q0, W0's opening, Q1.
    /// Its signature Q is hard-verified and authenticates the same three tapes.
    ///
    /// # Errors
    /// Wrong W/schema, changed originals or a failed proof/fold/decide.
    pub fn terminal_circuit(
        &self,
        wrapper: &WrapperCheckpoint,
        w: &WKey,
        salt: Fp,
        config: &FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>, AccumulatorT<Ep>), Error> {
        self.resume_wrapper_cancellable(
            w,
            wrapper.clone(),
            config.kernel_budget,
            config.cancellation.as_ref(),
        )?;
        let public = omega_instances(wrapper.context, &wrapper.vesta)?;
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            &self.plan.pallas,
            w.verifier().binding(),
            w.verifying_key(),
            &public,
            &wrapper.proof,
            config.kernel_budget,
            config.cancellation.as_ref(),
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
        let (fold, pallas) = create_fold(
            &self.plan.pallas,
            &[self.openings[0].clone(), opening, self.openings[1].clone()],
            salt.to_repr(),
            config,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        pallas
            .decide_cancellable(
                &self.plan.pallas,
                config.kernel_budget,
                config.cancellation.as_ref(),
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let split = SplitPlan::new(self.plan.context.clone(), 1, w.clone(), &self.plan.pallas)
            .map_err(|_| Error::Artifact)?;
        let circuit = StageCircuit {
            plan: self.plan.clone(),
            original: self.original.clone(),
            carried: Some(self.openings[0].clone()),
            known: true,
            stage: Stage::Last(Box::new(LastStage {
                split,
                proof: wrapper.proof.clone(),
                vesta: Some(wrapper.vesta.clone()),
                fold: fold.to_bytes(),
            })),
        };
        let public = frame(
            &self.original.state.lineage,
            &pallas.as_input(),
            &wrapper.vesta.as_input(),
        )?;
        Ok((circuit, public, pallas))
    }

    /// Complete the actual terminal A2 proof under its installed key and retain
    /// its own opening, final Pallas claim and forwarded Vesta claim for Omega.
    ///
    /// # Errors
    /// Another source profile, failed circuit/proof or any failed complete decide.
    fn prove_terminal(
        &self,
        wrapper: &WrapperCheckpoint,
        keys: TerminalKeys<'_>,
        salt: Fp,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
        config: ProverConfig,
    ) -> Result<Terminal, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        let TerminalKeys {
            wrapper: w,
            terminal: a2,
        } = keys;
        let (circuit, public, pallas) = self.terminal_circuit(wrapper, w, salt, fold)?;
        let proof = prove_vesta(&self.plan, a2, &circuit, &public, randomness, config)?;
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            &self.plan.vesta,
            a2.binding(),
            a2.verifying_key(),
            std::slice::from_ref(&public),
            &proof,
            fold.kernel_budget,
            config.cancellation,
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
            .decide_cancellable(&self.plan.vesta, fold.kernel_budget, config.cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas,
            vesta: wrapper.vesta.clone(),
            opening,
        })
    }

    fn immutable_context_digest(&self) -> Result<Fp, Error> {
        let mut words = self.plan.context.schema().to_vec();
        words.extend(self.original.state.statement);
        words.extend(self.original.state.core);
        words.extend(self.original.state.rest);
        words.extend(self.original.state.lineage);
        for value in self
            .original
            .q
            .iter()
            .flat_map(|q| q.instances.iter().flatten())
        {
            words.extend(foreign_limbs(value).map(Fp::from_u128));
        }
        for ((index, kind), original) in object_kinds()
            .into_iter()
            .enumerate()
            .zip(&self.original.objects)
        {
            let length = u32::try_from(original.len()).map_err(|_| Error::Input)?;
            let mut raw = length.to_le_bytes().to_vec();
            raw.extend(original);
            let mut tape = vec![Fp::from((index + 1) as u64), Fp::from(u64::from(length))];
            for chunk in raw.chunks(31) {
                tape.push(le_value::<Fp>(chunk).ok_or(Error::Input)?);
            }
            words.extend([
                object_digest(kind, original)?,
                Fp::from(u64::from(length)),
                hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
            ]);
        }
        Ok(hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words))
    }

    // Bootstrap has one internal A stage. Its proof-bound D0 includes the
    // current Q opening; durable source identity is the separate immutable C.
    fn first_stage_digest(&self) -> Result<Fp, Error> {
        let base = self.immutable_context_digest()?;
        let mut link = vec![Fp::ONE, self.plan.context.schema()[1], Fp::ONE, base];
        push_pallas(&mut link, &self.openings[0])?;
        Ok(hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &link))
    }
}

/// Exact proof/public context of a completed first stage. The custody owner
/// encodes this checkpoint with its source-bound Norito archive metadata.
#[derive(Clone, Debug)]
pub struct FirstCheckpoint {
    public: Vec<Fp>,
    proof: Vec<u8>,
    carried: FoldInput<Ep>,
}
impl FirstCheckpoint {
    /// Original A1 proof bytes; never monetary completion.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    /// Exact public frame authenticated by A1.
    #[must_use]
    pub fn instances(&self) -> &[Fp] {
        &self.public
    }
}
/// Internal W result. All fields are proved or recomputed from the same
/// originals; the custody owner retains this separately from final Omega.
#[derive(Clone, Debug)]
pub struct WrapperCheckpoint {
    proof: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    context: Fp,
}
impl WrapperCheckpoint {
    /// Original internal W proof.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    /// Canonical deciding Vesta accumulator authenticated by W.
    pub const fn vesta(&self) -> &AccumulatorT<Eq> {
        &self.vesta
    }
    /// Context digest binding both states, all originals and all Q public values.
    #[must_use]
    pub const fn context(&self) -> Fp {
        self.context
    }
}
/// Actual terminal Bootstrap A proof and every obligation final Omega must retain.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// Original terminal A2 proof under the installed source key.
    pub proof: Vec<u8>,
    /// Canonical homogeneous 69-word A frame.
    pub instances: Vec<Fp>,
    /// Full Pallas output bound through `D_A`.
    pub pallas: AccumulatorT<Ep>,
    /// Full Vesta part forwarded from W.
    pub vesta: AccumulatorT<Eq>,
    /// The terminal A proof's own Vesta opening, a separate Omega input slot.
    pub opening: FoldInput<Eq>,
}

fn prove_vesta(
    plan: &Plan,
    key: &SourceBoundViewV2<'_, Eq>,
    circuit: &StageCircuit,
    public: &[Fp],
    randomness: ProverRandomness<'_>,
    config: ProverConfig,
) -> Result<Vec<u8>, Error> {
    let d = key.binding().descriptor();
    if d.k != 16
        || d.instance_lengths != [69]
        || d.instance_types.as_deref() != Some(&[InstanceType::Bounded])
    {
        return Err(Error::Artifact);
    }
    let public = [public.to_vec()];
    let output = super::proving::prove(&plan.vesta, key, circuit, &public, randomness, config)?;
    iroha_plonk::verifier::verify_full_cancellable(
        &plan.vesta,
        key.binding(),
        key.verifying_key(),
        &public,
        &output.proof,
        MemoryBudget::DEFAULT,
        config.cancellation,
    )
    .map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof
        }
    })?;
    Ok(output.proof)
}

fn object_digest(kind: ObjectKind, bytes: &[u8]) -> Result<Fp, Error> {
    let end = kind.body_len();
    if bytes.len() != end + 64 {
        return Err(Error::Input);
    }
    let mut words = vec![p_bytes_native(kind.signing_domain(), &bytes[..end])];
    for offset in [16, 0, 48, 32] {
        words.push(Fp::from_u128(u128::from_be_bytes(
            bytes[end + offset..end + offset + 16]
                .try_into()
                .map_err(|_| Error::Input)?,
        )));
    }
    Ok(hash_with_domain(kind.object_domain(), &words))
}
fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) -> Result<(), Error> {
    if claim.source_k() != 16 {
        return Err(Error::Input);
    }
    let (x, y) = Option::<(Fp, Fp)>::from(claim.g().coordinates()).ok_or(Error::Input)?;
    words.extend([Fp::from(16), x, y]);
    for value in claim.challenges() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    Ok(())
}
fn frame(
    fields: &[Fp; 18],
    pallas: &FoldInput<Ep>,
    part: &FoldInput<Eq>,
) -> Result<Vec<Fp>, Error> {
    let mut digest = fields.to_vec();
    let mut claim = Vec::new();
    push_pallas(&mut claim, pallas)?;
    digest.extend(&claim[1..]);
    let mut out = vec![
        hash_with_domain(super::super::LINEAGE_DOMAIN, &digest),
        Fp::from(u64::from(part.source_k())),
    ];
    let (x, y) = Option::<(Fq, Fq)>::from(part.g().coordinates()).ok_or(Error::Input)?;
    for value in [x, y] {
        out.extend(foreign_limbs(&value).map(Fp::from_u128));
    }
    out.extend(part.challenges());
    let trivial = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Artifact)?;
    let (x, y) = Option::<(Fq, Fq)>::from(trivial.coordinates()).ok_or(Error::Artifact)?;
    let coordinates = [x, y]
        .into_iter()
        .flat_map(|v| foreign_limbs(&v).map(Fp::from_u128))
        .collect::<Vec<_>>();
    for _ in 0..2 {
        out.extend(&coordinates);
        out.extend([Fp::ONE; K]);
    }
    out.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    out.extend(coordinates);
    if out.len() != 69 {
        return Err(Error::Input);
    }
    Ok(out)
}
fn omega_instances(context: Fp, vesta: &AccumulatorT<Eq>) -> Result<Vec<Vec<Fq>>, Error> {
    let (x, y) = Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Input)?;
    let digest = Option::<Fq>::from(Fq::from_repr(context.to_repr())).ok_or(Error::Input)?;
    let challenges = vesta
        .challenges()
        .iter()
        .map(|u| Option::<Fq>::from(Fq::from_repr(u.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![vec![digest], vec![x, y], challenges])
}

/// Fixed source-stage configuration. Its columns and range buses are metadata.
#[derive(Clone, Debug)]
pub struct StageConfig {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
enum Stage {
    First,
    Last(Box<LastStage>),
}
#[derive(Clone)]
struct LastStage {
    split: SplitPlan,
    proof: Vec<u8>,
    vesta: Option<AccumulatorT<Eq>>,
    fold: [u8; 1120],
}
/// Complete first or terminal Bootstrap circuit. Stage and keys are fixed by
/// native assembly; source evidence and original tapes remain private witnesses.
#[derive(Clone)]
pub struct StageCircuit {
    plan: Arc<Plan>,
    original: Arc<Inputs>,
    carried: Option<FoldInput<Ep>>,
    stage: Stage,
    known: bool,
}

impl Plan {
    /// Reconstruct unknown A1 or A2 from the compiled Bootstrap source.
    /// Only A2 takes a wrapper, which must be this context's exact W0.
    /// This creates no prepared input, accepted proof or monetary authority.
    /// # Errors
    /// Out-of-range stage, missing/extra wrapper or wrong fixed context/stage.
    pub fn source_circuit(
        &self,
        stage: usize,
        previous: Option<WKey>,
    ) -> Result<StageCircuit, Error> {
        match (stage, previous) {
            (0, None) => StageCircuit::blank(Arc::new(self.clone()), Stage::First),
            (1, Some(w)) => StageCircuit::blank_terminal(Arc::new(self.clone()), &w),
            _ => Err(Error::Artifact),
        }
    }

    /// Reconstruct unknown W0 bound to the exact A1 verifier.
    /// The strict original importer uses this same source factory.
    /// # Errors
    /// Nonzero stage, foreign A source profile or invalid A verifier.
    pub fn wrapper_source(
        &self,
        stage: usize,
        binding: &DescriptorBinding,
        key: &VerifyingKey<Eq>,
    ) -> Result<WCircuit, Error> {
        if stage != 0
            || binding
                != &super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?
        {
            return Err(Error::Artifact);
        }
        wrapper_source(self, binding, key)
    }
}

// Installation specimens supply dimensions and unknown values only. They never
// pass through Plan::prepare or construct a verified opening/checkpoint owner.
fn wrapper_source(
    plan: &Plan,
    first: &DescriptorBinding,
    first_vk: &VerifyingKey<Eq>,
) -> Result<WCircuit, Error> {
    let allowed = first_vk
        .kagemusha_digest(first)
        .map_err(|_| Error::Artifact)?;
    let length = iroha_plonk::Protocol::new(first.descriptor())
        .map_err(|_| Error::Artifact)?
        .proof_length();
    let witness = OmegaWitness {
        key: first_vk.clone(),
        instances: vec![Fp::ZERO; 69],
        proof: vec![0; length],
        length: u32::try_from(length).map_err(|_| Error::Artifact)?,
        fold: [0; 1120],
    };
    WCircuit::new(
        &plan.context,
        0,
        first.clone(),
        plan.vesta.clone(),
        vec![allowed],
        witness,
    )
    .map(|source| source.without_witnesses())
    .map_err(|_| Error::Artifact)
}

impl StageCircuit {
    fn blank(plan: Arc<Plan>, stage: Stage) -> Result<Self, Error> {
        let operation = plan.context.operation();
        let sigma = operation.sigma.class(0).ok_or(Error::Artifact)?;
        let q = [0, 1].map(|index| -> Result<QInput, Error> {
            let fixed = operation.q(index).ok_or(Error::Artifact)?;
            Ok(QInput {
                proof: vec![0; fixed.verifier().proof_length()],
                instances: fixed
                    .verifier()
                    .binding()
                    .descriptor()
                    .instance_lengths
                    .iter()
                    .map(|length| vec![Fq::ZERO; *length as usize])
                    .collect(),
            })
        });
        let [q0, q1] = q;
        let original = Inputs {
            state: BootstrapWitness {
                core: [Fp::ZERO; 33],
                rest: [Fp::ZERO; 8],
                lineage: [Fp::ZERO; 18],
                statement: [Fp::ZERO; 26],
            },
            sigma: vec![0; sigma.verifier().proof_length()],
            objects: object_kinds().map(|kind| vec![0; kind.body_len() + 64]),
            q: [q0?, q1?],
        };
        Ok(Self {
            plan,
            original: Arc::new(original),
            carried: None,
            stage,
            known: false,
        })
    }

    fn blank_terminal(plan: Arc<Plan>, w: &WKey) -> Result<Self, Error> {
        let split = SplitPlan::new(plan.context.clone(), 1, w.clone(), &plan.pallas)
            .map_err(|_| Error::Artifact)?;
        Self::blank(
            plan,
            Stage::Last(Box::new(LastStage {
                split,
                proof: vec![0; w.verifier().proof_length()],
                vesta: None,
                fold: [0; 1120],
            })),
        )
    }

    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn assign(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Vec<Word<Fp>>, LayoutError> {
        let source = &self.original;
        let plan = &self.plan;
        let core = chip
            .uint()
            .glue()
            .witnesses(region, &source.state.core.map(|v| self.value(v)))?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &source.state.rest.map(|v| self.value(v)))?;
        let state = StateCells::constrain_with_verifier(
            chip,
            region,
            &core.try_into().map_err(|_| LayoutError::Synthesis)?,
            &rest.try_into().map_err(|_| LayoutError::Synthesis)?,
        )?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &source.state.lineage.map(|v| self.value(v)))?;
        let public = LineagePublicCells::constrain(
            &mut chip.uint(),
            region,
            &public.try_into().map_err(|_| LayoutError::Synthesis)?,
        )?;
        let statement = chip
            .uint()
            .glue()
            .witnesses(region, &source.state.statement.map(|v| self.value(v)))?;
        let statement = StatementCells::constrain_with_verifier(
            chip,
            region,
            Variant::Bootstrap,
            &statement.try_into().map_err(|_| LayoutError::Synthesis)?,
        )?;
        let mut q = Vec::new();
        for original in &source.q {
            let mut columns = Vec::new();
            for column in &original.instances {
                columns.push(
                    column
                        .iter()
                        .map(|v| scalar(chip, region, self.value(*v)))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            q.push(columns);
        }
        let values = source
            .objects
            .each_ref()
            .map(|object| object.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        let objects =
            BootstrapObjects::decode(chip, bytes, region, values.each_ref().map(Vec::as_slice))?;
        let context_objects = objects.context().to_vec();
        let point = chip.witness_point(
            region,
            self.carried.as_ref().map_or(Value::unknown(), |carried| {
                self.value(Ep::from(*carried.g()))
            }),
        )?;
        let challenges = (0..K)
            .map(|index| {
                scalar(
                    chip,
                    region,
                    self.carried.as_ref().map_or(Value::unknown(), |carried| {
                        self.value(carried.challenges()[index])
                    }),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pallas = FoldInputCells::from_normalized(
            chip,
            region,
            16,
            point,
            challenges.try_into().map_err(|_| LayoutError::Synthesis)?,
        )?;
        let input = ContextInputs {
            own_statement: &statement,
            incoming_statement: None,
            predecessor: None,
            successor: ContextState {
                state: &state,
                public: &public,
            },
            incoming: None,
            q_instances: &q,
            objects: &context_objects,
            modes: &[],
            pallas_corrections: &[],
            vesta_corrections: &[],
            receive_results: None,
        };
        match &self.stage {
            Stage::First => {
                let proof = carrier(chip, bytes, region, &source.q[0].proof, self.known)?;
                let sigma =
                    sigma_binding(chip, bytes, region, &statement, &source.sigma, self.known)?;
                let (verified, _) = verify_sigma(
                    chip,
                    region,
                    plan.context.operation(),
                    &q[0],
                    &proof,
                    &sigma,
                )?;
                let output = close_first(
                    chip,
                    region,
                    &plan.context,
                    &input,
                    None,
                    &[verified],
                    &sigma,
                    None,
                    &plan.pallas,
                )?;
                output.words(chip, region)
            }
            Stage::Last(last) => {
                let LastStage {
                    split,
                    proof,
                    vesta,
                    fold,
                } = last.as_ref();
                let proof = carrier(chip, bytes, region, proof, self.known)?;
                let sigma =
                    sigma_binding(chip, bytes, region, &statement, &source.sigma, self.known)?;
                let coordinates = vesta
                    .as_ref()
                    .map(|claim| {
                        Option::<(Fq, Fq)>::from(claim.g().coordinates())
                            .ok_or(LayoutError::Synthesis)
                    })
                    .transpose()?;
                let coordinates = [
                    scalar(
                        chip,
                        region,
                        coordinates.map_or(Value::unknown(), |(x, _)| self.value(x)),
                    )?,
                    scalar(
                        chip,
                        region,
                        coordinates.map_or(Value::unknown(), |(_, y)| self.value(y)),
                    )?,
                ];
                let challenges = (0..K)
                    .map(|index| {
                        chip.uint().glue().witness(
                            region,
                            vesta.as_ref().map_or(Value::unknown(), |claim| {
                                self.value(claim.challenges()[index])
                            }),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let vesta = VestaClaimCells::constrain(
                    chip,
                    region,
                    16,
                    coordinates,
                    challenges.try_into().map_err(|_| LayoutError::Synthesis)?,
                )?;
                let resumed =
                    resume_context(chip, region, split, &input, &pallas, &vesta, &proof, &sigma)?;
                let proof = carrier(chip, bytes, region, &source.q[1].proof, self.known)?;
                let verified = verify_q(chip, region, plan.context.operation(), 1, &q[1], &proof)?;
                let slots = bind_signature_q(
                    chip,
                    region,
                    plan.context.operation(),
                    1,
                    &plan.signatures,
                    &verified,
                )?;
                objects.authenticate(
                    chip,
                    region,
                    plan.policy,
                    BootstrapInputs {
                        state: &state,
                        lineage: &public,
                        sigma: &sigma[0],
                        signatures: slots.slots(),
                    },
                )?;
                for (slot, expected) in slots.slots().iter().zip(q[1][0].chunks_exact(10)) {
                    let actual = std::iter::once(slot.message())
                        .chain(slot.key())
                        .chain(slot.signature())
                        .chain(std::iter::once(slot.valid().word()));
                    for (actual, expected) in actual.zip(expected) {
                        let expected = super::super::bounded_word(chip, region, expected)?;
                        GlueChip::assert_equal(region, actual, &expected)?;
                    }
                }
                let fold = carrier(chip, bytes, region, fold, self.known)?;
                let output = close_stage(
                    chip,
                    region,
                    split,
                    &resumed,
                    None,
                    None,
                    None,
                    &[verified],
                    &fold,
                )?;
                output.words(chip, region, &public)
            }
        }
    }
}
impl Circuit<Fp> for StageCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StageConfig {
        let verifier =
            VerifierConfig::configure_serialized_foreign_tagged(meta, SOURCE_RANGE_BUSES)
                .expect("fixed native Bootstrap Tagged3 profile");
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(69);
        meta.enable_equality(public);
        StageConfig {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: StageConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), LayoutError> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "complete production Bootstrap stage",
            |mut region| self.assign(&mut chip, &mut bytes, &mut region),
        )?;
        if output.len() != 69 {
            return Err(LayoutError::Synthesis);
        }
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
fn scalar(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    value: Value<Fq>,
) -> Result<ScalarCells<Ep>, LayoutError> {
    let lo = chip
        .uint()
        .assign::<128>(region, value.map(|v| foreign_limbs(&v)[0]))?;
    let hi = chip
        .uint()
        .assign::<127>(region, value.map(|v| foreign_limbs(&v)[1]))?;
    ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
}
fn carrier(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut Region<'_, Fp>,
    body: &[u8],
    known: bool,
) -> Result<ProofMessageCells, LayoutError> {
    let length = u32::try_from(body.len()).map_err(|_| LayoutError::BoundsFailure)?;
    let raw = length
        .to_le_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .map(|v| {
            if known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        })
        .collect::<Vec<_>>();
    let mut segments = vec![SegmentSpec::little(0, 4)];
    segments.extend(le_message_segments(4, body.len() / 32));
    let run = bytes.run(
        region,
        &raw,
        &raw.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
        &segments,
    )?;
    ProofMessageCells::from_run(chip, region, &run, 0, body.len())
}
fn sigma_binding(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut Region<'_, Fp>,
    statement: &StatementCells,
    sigma: &[u8],
    known: bool,
) -> Result<Vec<SigmaBindingCells>, LayoutError> {
    let length = u32::try_from(sigma.len()).map_err(|_| LayoutError::BoundsFailure)?;
    let raw = length
        .to_le_bytes()
        .into_iter()
        .chain(sigma.iter().copied())
        .map(|v| {
            if known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        })
        .collect::<Vec<_>>();
    let run = bytes.run(
        region,
        &raw,
        &raw.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
        &[SegmentSpec::little(0, 4)],
    )?;
    let selector = chip.uint().glue().constant(region, Fp::ZERO)?;
    Ok(vec![SigmaBindingCells::from_run(
        chip, region, statement, selector, &run,
    )?])
}

impl Prover {
    /// Bind a previously source-admitted seal to this exact installed FIRST stage.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong stage, descriptor/verifier identity or cooperative cancellation.
    pub fn bind_first<'a>(
        &'a self,
        seal: &'a SourceAdmissionSealV2<Eq>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = &self.first;
        seal.bind(artifact.binding(), artifact.key(), cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })
    }
    /// Bind a previously source-admitted seal to this exact installed WRAPPER stage.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong stage, descriptor/verifier identity or cooperative cancellation.
    pub fn bind_wrapper<'a>(
        &'a self,
        seal: &'a SourceAdmissionSealV2<Ep>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, Ep>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = &self.wrapper;
        seal.bind(artifact.binding(), artifact.key(), cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })
    }
    /// Bind a previously source-admitted seal to this exact installed TERMINAL stage.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong stage, descriptor/verifier identity or cooperative cancellation.
    pub fn bind_terminal<'a>(
        &'a self,
        seal: &'a SourceAdmissionSealV2<Eq>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = &self.terminal;
        seal.bind(artifact.binding(), artifact.key(), cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })
    }
}

#[cfg(test)]
#[path = "bootstrap/tests.rs"]
mod tests;
