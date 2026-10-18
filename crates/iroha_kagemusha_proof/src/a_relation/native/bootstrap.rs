//! Production unsplit Bootstrap A assembly from original signed object tapes.
//!
//! The installed owner authenticates the fixed Q/A plan and verifier identities
//! independently of operation witnesses. The original A proving material is
//! imported against that key and the exact witnessless compiled source; no
//! separate PK byte-signing format is required by this component. The owner
//! converts canonical G1 objects to these typed proof inputs. The signature Q
//! proof is verified in full here. The one terminal A proves the Bootstrap
//! transition directly (lean lineage), authenticates the original Enrollment
//! certificate, Credential and Advance Receipt on that Q's hard slots and
//! forwards its opening as the Pallas claim; no W follows it. The terminal A
//! proof is an input to the separately installed final Omega catalog, never
//! monetary completion or a transported Omega. No method generates runtime
//! artifact keys.

use iroha_plonk::keys::{SourceAdmissionSealV2, SourceBoundViewV2};
#[path = "bootstrap/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::CheckpointLayout;

use super::artifact::KeyArtifact;
use super::identity::{BoundV1, ProverInstanceV1};
use core::fmt;
use std::sync::Arc;

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, ProverConfig, ProverRandomness, VerifyingKey,
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
    AccumulatorT, FoldInput, K, VESTA_TRIVIAL_GENERATOR,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

use super::super::{
    AProofPlan, LineagePublicCells, ProofMessageCells, bind_signature_q,
    bootstrap::{BootstrapInputs, BootstrapObjects, BootstrapPolicy},
    close_unsplit,
    context::ContextPlan,
    verify_q,
};
use crate::{
    admin_sigma::BootstrapWitness,
    operation_relation::{objects::ObjectKind, state::StateCells, statement::StatementCells},
    q_signature::{QSignaturePlan, SignatureKey},
};

/// The fixed source profile measured with the complete Bootstrap/Load catalog.
/// A witness cannot select another bus count or a generic fallback profile.
pub const SOURCE_RANGE_BUSES: usize = 3;

const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

/// Production preparation or proof failure. No failure changes a monetary head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Original local checkpoint read refusal; no invalid-input or proof verdict completed.
    DecodeResource(norito::core::DecodeLocalRefusal),
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
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeResource(original) => Some(original),
            _ => None,
        }
    }
}
impl From<norito::core::DecodeAttemptError> for Error {
    fn from(error: norito::core::DecodeAttemptError) -> Self {
        error
            .into_local_refusal()
            .map_or(Self::Input, Self::DecodeResource)
    }
}
impl Error {
    /// Whether the operation was cancelled instead of proving an invalid input.
    pub fn is_cancelled(&self) -> bool {
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
/// conversion. These inputs are additionally checked by the actual A circuit.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Exact core29, rest6, public18 and statement26 field transcripts.
    pub state: BootstrapWitness,
    /// Original canonical Certificate, Credential and Advance Receipt bytes.
    pub objects: [Vec<u8>; 3],
    /// The hard three-signature Q.
    pub q: [QInput; 1],
}

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
    /// Pin the single hard signature Q and both Bootstrap tasks in the one
    /// unsplit terminal A. No sigma verifier exists: A proves the Bootstrap
    /// transition directly and forwards the Q opening as its Pallas claim.
    ///
    /// Signature slots are hard `[receipt, credential, certificate]`, with a
    /// fixed root for the certificate. The certificate/root equality is also
    /// constrained by `BootstrapObjects::authenticate` under `policy`.
    ///
    /// # Errors
    /// Wrong variant, a sigma verifier, Q/slot/schema count, parameter k or
    /// signature key policy.
    pub fn new(
        operation: AProofPlan,
        policy: BootstrapPolicy,
        signatures: QSignaturePlan,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        if operation.frame().variant() != Variant::Bootstrap
            || operation.sigma().is_some()
            || operation.q_count() != 1
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
        let q = operation
            .q(0)
            .ok_or(Error::Artifact)?
            .verifier()
            .binding()
            .descriptor();
        if q.instance_lengths
            != [u32::try_from(signatures.instance_length()).map_err(|_| Error::Artifact)?]
            || q.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
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

    /// Fixed complete schedule, including the exact Q key and task owners.
    #[must_use]
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }

    /// Validate original dimensions and verify the source Q proof in full.
    /// The resulting opening is independently decided, never caller supplied.
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
        let original = &input.q[0];
        let fixed = self.context.operation().q(0).ok_or(Error::Artifact)?;
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
        let opening =
            FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
        opening
            .decide_cancellable(&self.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        // The k16 Q opening is A's whole Pallas claim, forwarded unfolded.
        let pallas =
            AccumulatorT::new(*opening.g(), *opening.challenges()).map_err(|_| Error::Proof)?;
        Ok(Prepared {
            plan: Arc::new(self.clone()),
            original: Arc::new(input),
            pallas,
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
/// The owner authenticates the plan and verifier identity independently. This
/// producer retains neither original PK bytes nor proving polynomials. Each proof
/// borrows the strictly imported key and rechecks its complete installed identity.
/// TODO(G3/G4): connect the complete authenticated producer catalog and original
/// G1 preparation to the wallet owner before enabling Native wallet open.
pub struct Prover {
    plan: Plan,
    terminal: KeyArtifact<Eq>,
    // Process-local instance identity; only this instance resumes its sessions.
    identity: ProverInstanceV1,
}
impl Prover {
    /// Mount the terminal A verifier metadata without retaining any proving key.
    ///
    /// The installation owner authenticates the scheme, Q key, roots, schedule,
    /// descriptor and complete compiled-source catalog before this call. This
    /// constructor checks metadata consistency, not scheme/catalog authority or
    /// original-key admissibility. The importer performs exact source, table and
    /// commitment checks with no transaction witness or runtime keygen.
    /// # Errors
    /// Wrong curve/k/public profile or noncanonical source descriptor.
    pub fn from_artifacts(plan: Plan, terminal: KeyArtifact<Eq>) -> Result<Self, Error> {
        artifact_metadata(&terminal, CurveV1::Vesta, &[69], &[InstanceType::Bounded])?;
        let expected =
            super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?;
        if terminal.binding() != &expected {
            return Err(Error::Artifact);
        }
        Ok(Self {
            plan,
            terminal,
            identity: ProverInstanceV1::fresh(),
        })
    }

    /// Import exactly one terminal A original against the fixed unknown source.
    /// Strict admission returns its compact seal without constructing proving FFTs or masks.
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
        self.import_terminal_with_admission_cancellable(
            original,
            config,
            crate::original_admission::OriginalAdmission::Strict,
            cancellation,
        )
    }

    /// Admit an exact original through an explicitly selected closed built-in source.
    /// All typed plan, source-profile and installed-key checks remain mandatory.
    /// The member attests only its pinned relation. The installation owner must
    /// bind this supplied plan to the complete selected built-in profile; a
    /// same-schema foreign plan is not certified by membership. Proof-time source
    /// reconstruction remains mandatory and rejects a different actual source.
    /// # Errors
    /// The ordinary importer errors, closed-member mismatch, or cancellation.
    #[allow(clippy::too_many_arguments)]
    pub fn import_terminal_builtin_cancellable(
        &self,
        original: &[u8],
        config: ReadConfig,
        member: iroha_plonk::keys::BuiltinSourceMemberV1,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_terminal_with_admission_cancellable(
            original,
            config,
            crate::original_admission::OriginalAdmission::Builtin(member),
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn import_terminal_with_admission_cancellable(
        &self,
        original: &[u8],
        config: ReadConfig,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        original_bounds(original, self.terminal.binding().n(), config)?;
        let source = self.plan.source_circuit()?;
        let key = admission
            .admit(
                original,
                self.terminal.binding(),
                self.terminal.key(),
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
            .require_source_bound(&key.view())
            .map_err(|_| Error::Artifact)?;
        let (_, _, seal) = key.into_parts();
        Ok(seal)
    }

    /// Verify source inputs and create a session using only this installed key.
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

    /// Resume a session retained from this exact prover instance.
    ///
    /// Nothing is re-read or re-verified: `prepare` on this instance verified the
    /// retained source Q proof and opening. A durable terminal checkpoint must
    /// still be restored strictly from its bytes.
    /// # Errors
    /// `Error::Input` when the state was retained from another prover instance,
    /// including an identically installed one; the state is dropped.
    pub fn resume(&self, retained: RetainedSession) -> Result<Session<'_>, Error> {
        let prepared = self.identity.admit(retained.0).map_err(|_| Error::Input)?;
        Ok(Session {
            prover: self,
            prepared,
        })
    }

    /// Fixed descriptor of the single terminal checkpoint/proof stage.
    #[must_use]
    pub fn descriptors(&self) -> [&DescriptorBinding; 1] {
        [self.terminal.binding()]
    }

    /// Bind a previously source-admitted seal to this exact installed terminal A.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong descriptor/verifier identity or cooperative cancellation.
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

/// One exact Bootstrap source coupled to immutable installed verifier metadata.
/// The custody owner retains source originals and the checkpoint before advancing.
pub struct Session<'a> {
    prover: &'a Prover,
    prepared: Prepared,
}

/// A Bootstrap session's verified preparation, detached between fold calls.
///
/// Only `Session::into_retained` creates one, and only `Prover::resume` on the
/// prover instance that prepared it consumes it. It is move-only, process-local
/// and never serialized or built from bytes. It holds the checked source
/// originals and opening, but no proving key, original-store handle or durable
/// checkpoint.
pub struct RetainedSession(BoundV1<Prepared>);

impl Session<'_> {
    /// Detach this session's verified preparation so a later fold call can resume
    /// it on the same prover instance instead of preparing again.
    #[must_use]
    pub fn into_retained(self) -> RetainedSession {
        RetainedSession(self.prover.identity.bind(self.prepared))
    }

    /// Compute the actual terminal A proof using its installed key.
    /// # Errors
    /// Wrong installed circuit, failed proof or complete decide.
    pub fn terminal(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<Terminal, Error> {
        self.prover
            .terminal
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.prepared.prove_terminal(key, randomness, config)
    }

    /// Reverify terminal A proof bytes reloaded from the source-bound custody
    /// archive. The public frame and Pallas claim are rederived from this
    /// session's originals; no transported claim is trusted.
    /// # Errors
    /// A substituted proof, changed source frame or failed proof/decide.
    pub fn restore_terminal(
        &self,
        proof: Vec<u8>,
        budget: MemoryBudget,
    ) -> Result<Terminal, Error> {
        self.restore_terminal_cancellable(proof, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_terminal_cancellable(
        &self,
        proof: Vec<u8>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let public = self.prepared.public()?;
        let source = &self.prover.terminal;
        let instances = std::slice::from_ref(&public);
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            source.binding(),
            source.key(),
            instances,
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
        let opening = decided_opening(
            &self.prepared.plan.vesta,
            source.binding(),
            source.key(),
            instances,
            &proof,
            budget,
            cancellation,
        )?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas: self.prepared.pallas.clone(),
            opening,
        })
    }
}

/// Prepared exact source Q proof and its checked opening obligation.
/// Private fields prevent substituting an unverified opening or another tape.
#[derive(Clone)]
pub struct Prepared {
    plan: Arc<Plan>,
    original: Arc<Inputs>,
    pallas: AccumulatorT<Ep>,
}
impl Prepared {
    /// The terminal A circuit over these exact originals and its public frame.
    /// The frame binds the lineage and the forwarded Q opening; the part and
    /// both absent Vesta slots are the pinned trivial filler.
    ///
    /// # Errors
    /// A malformed public frame.
    pub fn terminal_circuit(&self) -> Result<(StageCircuit, Vec<Fp>), Error> {
        Ok((
            StageCircuit {
                plan: self.plan.clone(),
                original: self.original.clone(),
                known: true,
            },
            self.public()?,
        ))
    }

    fn public(&self) -> Result<Vec<Fp>, Error> {
        frame(&self.original.state.lineage, &self.pallas.as_input())
    }

    /// Complete the actual terminal A proof under its installed key and retain
    /// its own decided opening and the forwarded Pallas claim for Omega.
    ///
    /// # Errors
    /// Another source profile, failed circuit/proof or failed complete decide.
    fn prove_terminal(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<Terminal, Error> {
        let (circuit, public) = self.terminal_circuit()?;
        let proof = prove_vesta(&self.plan, key, &circuit, &public, randomness, config)?;
        let opening = decided_opening(
            &self.plan.vesta,
            key.binding(),
            key.verifying_key(),
            std::slice::from_ref(&public),
            &proof,
            config.msm_budget,
            config.cancellation,
        )?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas: self.pallas.clone(),
            opening,
        })
    }

    // Durable source identity of a terminal checkpoint: the fixed schedule, the
    // statement, both state halves, the lineage, every Q public value and every
    // original object tape.
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
}

/// Actual terminal Bootstrap A proof and every obligation final Omega must retain.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// Original terminal A proof under the installed source key.
    pub proof: Vec<u8>,
    /// Canonical homogeneous 69-word A frame.
    pub instances: Vec<Fp>,
    /// Full Pallas claim bound through `D_A`: the hard Q's decided opening,
    /// forwarded unfolded.
    pub pallas: AccumulatorT<Ep>,
    /// The terminal A proof's own Vesta opening, a separate Omega input slot.
    pub opening: FoldInput<Eq>,
}

fn prove_vesta(
    plan: &Plan,
    key: &SourceBoundViewV2<'_, Eq>,
    circuit: &StageCircuit,
    public: &[Fp],
    randomness: ProverRandomness,
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

// The verified terminal A proof's own opening, accumulated and completely decided.
fn decided_opening(
    params: &PinnedParams<Eq>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
    instances: &[Vec<Fp>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Eq>, Error> {
    let claim = iroha_plonk::verifier::accumulate_generator_cancellable(
        params,
        binding,
        key,
        instances,
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
    let opening =
        FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
    opening
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(opening)
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
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Ep>(claim.g());
    words.extend([Fp::from(16), x, y]);
    for value in claim.challenges() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    Ok(())
}
// `D_A` over the lineage and the forwarded Q opening, then the pinned trivial
// part and the absent predecessor and incoming slots, as `close_unsplit` emits.
fn frame(fields: &[Fp; 18], pallas: &FoldInput<Ep>) -> Result<Vec<Fp>, Error> {
    let mut digest = fields.to_vec();
    let mut claim = Vec::new();
    push_pallas(&mut claim, pallas)?;
    digest.extend(&claim[1..]);
    let trivial = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Artifact)?;
    let (x, y) = Option::<(Fq, Fq)>::from(trivial.coordinates()).ok_or(Error::Artifact)?;
    let coordinates = [x, y]
        .into_iter()
        .flat_map(|v| foreign_limbs(&v).map(Fp::from_u128))
        .collect::<Vec<_>>();
    let mut out = vec![
        hash_with_domain(super::super::LINEAGE_DOMAIN, &digest),
        Fp::from(16),
    ];
    for _ in 0..3 {
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

/// Fixed source configuration. Its columns and range buses are metadata.
#[derive(Clone, Debug)]
pub struct StageConfig {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
/// Complete unsplit terminal Bootstrap A circuit. Keys are fixed by native
/// assembly; source evidence and original tapes remain private witnesses.
#[derive(Clone)]
pub struct StageCircuit {
    plan: Arc<Plan>,
    original: Arc<Inputs>,
    known: bool,
}

impl Plan {
    /// Reconstruct the unknown terminal A from the compiled Bootstrap source.
    /// This creates no prepared input, accepted proof or monetary authority.
    /// # Errors
    /// A missing fixed Q verifier.
    pub fn source_circuit(&self) -> Result<StageCircuit, Error> {
        StageCircuit::blank(Arc::new(self.clone()))
    }
}

impl StageCircuit {
    // Installation specimens supply dimensions and unknown values only. They never
    // pass through Plan::prepare or construct a verified opening or checkpoint owner.
    fn blank(plan: Arc<Plan>) -> Result<Self, Error> {
        let fixed = plan.context.operation().q(0).ok_or(Error::Artifact)?;
        let q = QInput {
            proof: vec![0; fixed.verifier().proof_length()],
            instances: fixed
                .verifier()
                .binding()
                .descriptor()
                .instance_lengths
                .iter()
                .map(|length| vec![Fq::ZERO; *length as usize])
                .collect(),
        };
        let original = Inputs {
            state: BootstrapWitness {
                core: [Fp::ZERO; 29],
                rest: [Fp::ZERO; 6],
                lineage: [Fp::ZERO; 18],
                statement: [Fp::ZERO; 26],
            },
            objects: object_kinds().map(|kind| vec![0; kind.body_len() + 64]),
            q: [q],
        };
        Ok(Self {
            plan,
            original: Arc::new(original),
            known: false,
        })
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
        let operation = plan.context.operation();
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
        let original = &source.q[0];
        let mut q = Vec::new();
        for column in &original.instances {
            q.push(
                column
                    .iter()
                    .map(|v| scalar(chip, region, self.value(*v)))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        let values = source
            .objects
            .each_ref()
            .map(|object| object.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        let objects =
            BootstrapObjects::decode(chip, bytes, region, values.each_ref().map(Vec::as_slice))?;
        let proof = carrier(chip, bytes, region, &original.proof, self.known)?;
        let verified = verify_q(chip, region, operation, 0, &q, &proof)?;
        let slots = bind_signature_q(chip, region, operation, 0, &plan.signatures, &verified)?;
        objects.authenticate(
            chip,
            region,
            plan.policy,
            BootstrapInputs {
                state: &state,
                lineage: &public,
                statement: &statement,
                signatures: slots.slots(),
            },
        )?;
        for (slot, expected) in slots.slots().iter().zip(q[0].chunks_exact(10)) {
            let actual = std::iter::once(slot.message())
                .chain(slot.key())
                .chain(slot.signature())
                .chain(std::iter::once(slot.valid().word()));
            for (actual, expected) in actual.zip(expected) {
                let expected = super::super::bounded_word(chip, region, expected)?;
                GlueChip::assert_equal(region, actual, &expected)?;
            }
        }
        close_unsplit(chip, region, operation, &public, &verified)
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
            || "complete production Bootstrap A",
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

#[cfg(test)]
#[path = "bootstrap/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bootstrap/capacity.rs"]
mod capacity;
