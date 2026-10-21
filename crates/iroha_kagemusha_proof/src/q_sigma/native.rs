//! Native preparation, key generation and proving for the fixed `Q_sigma` relation.
//!
//! A caller supplies the incoming mode after evaluating the complete operation's
//! soft checks. This module never chooses or authorizes a burn. It derives the
//! selected local claim, creates or verifies the retained local fold, binds every exported
//! instance and self-verifies each generated Q proof. Only source-bound verifier
//! metadata survives native key generation or strict original import. Each proof
//! reconstructs temporary on-demand buffers, then drops them before verification.

use core::fmt;

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaField, msm::MemoryBudget};
#[cfg(test)]
use iroha_plonk::Witness;
use iroha_plonk::{
    DescriptorBinding, KeyError, ProverConfig, ProverError, ProverRandomness, VerifyError,
    VerifyingKey, create_proof_owned,
    frontend::{Circuit, Error as LayoutError},
    keys::{
        CosetCachePolicy, KeygenConfigV2, RebuildError, SourceBoundVerifyingKeyV2,
        SourceBoundViewV2, keygen_pk_v2,
    },
    pcs::{
        ipa::{IpaError, PinnedParams},
        multiopen::MultiopenError,
    },
    prover::{RebuildWitnessError, rebuild_key_and_witness_v2_cancellable},
    transcript::TranscriptError,
};
use iroha_plonk_gadgets::bytes::tape::{ByteOrder, segment_value};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, FoldPurpose, FoldTape, FoldWitness, create_fold,
    verifier::VerifierPlan, verify_fold,
};

use super::{
    IncomingSigmaWitness, QSigmaCircuit, QSigmaPlan, QSigmaWitness, SigmaClass, SigmaSlotWitness,
};
use crate::SigmaVerifier;

/// Failure to prepare, prove or verify a fixed Q relation.
#[derive(Debug)]
pub enum QSigmaError {
    /// Slot/frame metadata or assignment failure.
    Layout(LayoutError),
    /// The key or class is absent from the fixed allowlist.
    UnauthorizedKey,
    /// The selected incoming mode cannot be realized by the actual claim.
    IncomingMode,
    /// The selected coin/witness source does not match the actual incoming slot.
    FoldSource,
    /// Own sigma has the wrong original carrier length.
    OwnLength,
    /// Outer parameters must cover exactly k16.
    Parameters,
    /// The installed descriptor is not the exact V2 Q profile for this source.
    Profile,
    /// The installed descriptor failed strict V2 decoding.
    Descriptor(iroha_plonk::cs::DescriptorError),
    /// Original proving-key source, allocation or commitment admission failed.
    Artifact(iroha_plonk::keys::pk::artifact::Error),
    /// Key-generation failure.
    Key(KeyError),
    /// Proof synthesis or creation failure.
    Prover(ProverError),
    /// Exact-source temporary proving-buffer reconstruction failed.
    Rebuild(RebuildError),
    /// Complete or succinct verification failure.
    Verify(VerifyError),
    /// Local accumulator or fold failure.
    Fold(iroha_plonk_recursion::Error),
}
impl fmt::Display for QSigmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Q_sigma: {self:?}")
    }
}
impl std::error::Error for QSigmaError {}
impl QSigmaError {
    /// Whether this is cancellation, never an invalid incoming proof or burn witness.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Layout(error) => matches!(error, iroha_plonk::frontend::Error::Cancelled),
            Self::Artifact(error) => error.is_cancelled(),
            Self::Key(error) => error.is_cancelled(),
            Self::Prover(error) => error.is_cancelled(),
            Self::Rebuild(error) => error.is_cancelled(),
            Self::Verify(error) => error.is_cancelled(),
            Self::Fold(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

/// The caller-selected global mode of the incoming sigma obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingMode {
    /// Keep a deciding original opening.
    Accept,
    /// Select the fixed full-length trivial claim.
    Trivial,
    /// Compute a distinct deciding commitment for the original challenges.
    Corrected,
}
impl IncomingMode {
    fn bits(self) -> [bool; 3] {
        match self {
            Self::Accept => [true, false, false],
            Self::Trivial => [false, true, false],
            Self::Corrected => [false, false, true],
        }
    }
}
/// Incoming proof bytes and the globally selected mode, before local folding.
#[derive(Clone, Debug)]
pub struct IncomingSigma {
    /// Descriptor-sized sigma carrier and statement.
    pub sigma: SigmaSlotWitness,
    /// Mode selected by the complete operation coordinator.
    pub mode: IncomingMode,
}
/// Exact local fold source selected by the private attempt/checkpoint owner.
///
/// An incoming route consumes a fresh tape once or verifies its original retained
/// witness. A route without an incoming slot takes no tape or fold witness.
/// Syntax or possession of retained bytes never grants source/proof authority.
#[derive(Debug)]
pub enum QSigmaFoldSource<'a> {
    /// No incoming sigma slot, so the own opening is forwarded without a fold.
    NoIncoming,
    /// One fresh private tape for a new incoming-sigma fold attempt.
    Fresh(FoldTape<Eq>),
    /// Exact private witness retained by this source-bound attempt's checkpoint.
    Retained(&'a crate::private_fold::PrivateFoldBytes),
}
impl QSigmaFoldSource<'_> {
    fn check_presence(&self, incoming: bool) -> Result<(), QSigmaError> {
        if incoming == !matches!(self, Self::NoIncoming) {
            Ok(())
        } else {
            Err(QSigmaError::FoldSource)
        }
    }
    fn resolve(
        self,
        params: &PinnedParams<Eq>,
        inputs: &[FoldInput<Eq>],
        config: &FoldConfig,
    ) -> Result<(crate::private_fold::PrivateFoldBytes, AccumulatorT<Eq>), QSigmaError> {
        let (bytes, part) = match self {
            Self::NoIncoming => return Err(QSigmaError::FoldSource),
            Self::Fresh(tape) => {
                let (witness, part) =
                    create_fold(params, inputs, tape, FoldPurpose::SigmaBatch, config)
                        .map_err(QSigmaError::Fold)?;
                (
                    crate::private_fold::PrivateFoldBytes::from_fold(witness),
                    part,
                )
            }
            Self::Retained(bytes) => {
                let witness = FoldWitness::<Eq>::from_private_bytes(bytes.as_slice())
                    .map_err(QSigmaError::Fold)?;
                let part = verify_fold(params, inputs, &witness, FoldPurpose::SigmaBatch, config)
                    .map_err(QSigmaError::Fold)?;
                (bytes.clone(), part)
            }
        };
        part.decide_cancellable(params, config.kernel_budget, config.cancellation.as_ref())
            .map_err(QSigmaError::Fold)?;
        Ok((bytes, part))
    }
}

/// A fully prepared local circuit and its exact public frame.
#[must_use = "prove this Q relation and register its returned obligation in A"]
#[derive(Clone, Debug)]
pub struct PreparedQSigma {
    circuit: QSigmaCircuit,
    instances: Vec<Vec<Fq>>,
    part: FoldInput<Eq>,
}
impl PreparedQSigma {
    /// The fixed circuit and prepared witnesses.
    pub const fn circuit(&self) -> &QSigmaCircuit {
        &self.circuit
    }
    /// Public columns in the exact homogeneous Q schema.
    pub fn instances(&self) -> &[Vec<Fq>] {
        &self.instances
    }
    /// Borrow the exact verified private fold for an incoming route's checkpoint.
    /// The private persistence owner must bind it to this source, stage and attempt.
    /// No-incoming routes return None and require no fold entropy or retained tape.
    pub fn retained_fold(&self) -> Option<&crate::private_fold::PrivateFoldBytes> {
        self.circuit
            .witness
            .incoming
            .as_ref()
            .map(|incoming| &incoming.fold)
    }
    /// Selected forwarded or folded Vesta part.
    pub const fn part(&self) -> &FoldInput<Eq> {
        &self.part
    }
}

impl SigmaClass {
    /// Builds one descriptor class from already checked Sigma verifiers and
    /// their indices in the global allowlist; no profile fallback is attempted.
    ///
    /// # Errors
    /// Empty/mixed classes or invalid/duplicate global entries.
    pub fn from_verifiers(entries: &[(u8, &SigmaVerifier<Eq>)]) -> Result<Self, QSigmaError> {
        let (_, first) = entries.first().ok_or(QSigmaError::UnauthorizedKey)?;
        let mut digests = Vec::with_capacity(entries.len());
        for (index, verifier) in entries {
            if verifier.binding() != first.binding() {
                return Err(QSigmaError::UnauthorizedKey);
            }
            let digest = verifier
                .vk()
                .kagemusha_digest(verifier.binding())
                .map_err(|_| QSigmaError::UnauthorizedKey)?;
            digests.push((*index, digest));
        }
        let plan = VerifierPlan::new(first.binding().clone(), first.params().clone())
            .map_err(QSigmaError::Verify)?;
        Self::new(plan, digests).map_err(QSigmaError::Layout)
    }
    fn index(&self, witness: &SigmaSlotWitness) -> Result<u8, QSigmaError> {
        self.key_index(&witness.key)
    }
    fn key_index(&self, key: &VerifyingKey<Eq>) -> Result<u8, QSigmaError> {
        let digest = key
            .kagemusha_digest(self.verifier.binding())
            .map_err(|_| QSigmaError::UnauthorizedKey)?;
        self.entries
            .iter()
            .find_map(|(index, allowed)| (*allowed == digest).then_some(*index))
            .ok_or(QSigmaError::UnauthorizedKey)
    }
    fn opening(
        &self,
        witness: &SigmaSlotWitness,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FoldInput<Eq>, QSigmaError> {
        let opening = iroha_plonk::verifier::accumulate_generator_cancellable(
            self.verifier.params(),
            self.verifier.binding(),
            &witness.key,
            &[vec![witness.statement]],
            &witness.proof,
            budget,
            cancellation,
        )
        .map_err(QSigmaError::Verify)?;
        FoldInput::from_opening(*opening.g(), opening.challenges()).map_err(QSigmaError::Fold)
    }
}
/// Whether total incoming verification maps this witness failure to false.
///
/// This classification never accepts a proof or authorizes a burn. Descriptor,
/// key, parameter, profile and resource failures remain hard errors. Native
/// operation coordinators and Q preparation use the same classification as the
/// total circuit's proof reader, including failures nested inside IPA/multiopen.
#[must_use]
pub fn incoming_proof_failure(error: &VerifyError) -> bool {
    match error {
        VerifyError::Transcript(error) => !matches!(error, TranscriptError::ProfileMismatch),
        VerifyError::DegenerateChallenge
        | VerifyError::IdentityInstanceCommitment { .. }
        | VerifyError::ProofLength { .. }
        | VerifyError::Multiopen(
            MultiopenError::PointCollision
            | MultiopenError::ConflictingEvaluations { .. }
            | MultiopenError::DegenerateChallenge,
        ) => true,
        VerifyError::Ipa(error) | VerifyError::Multiopen(MultiopenError::Ipa(error)) => match error
        {
            IpaError::Transcript(error) => !matches!(error, TranscriptError::ProfileMismatch),
            IpaError::ZeroChallenge { .. }
            | IpaError::OpeningFailed
            | IpaError::FoldedGeneratorMismatch => true,
            _ => false,
        },
        _ => false,
    }
}
fn scalar(value: Fp) -> Fq {
    // Fp is strictly smaller than Fq, so this integer embedding is injective.
    Fq::from_canonical_limbs(value.to_canonical_limbs()).expect("Fp fits Fq")
}
fn chunks(witness: &SigmaSlotWitness) -> Vec<Fq> {
    let bytes: Vec<_> = witness
        .length
        .to_le_bytes()
        .into_iter()
        .chain(witness.proof.iter().copied())
        .collect();
    bytes
        .chunks(31)
        .map(|chunk| segment_value(chunk, ByteOrder::Little).expect("31-byte integer fits"))
        .collect()
}
impl QSigmaPlan {
    /// Whether this fixed route has an incoming slot and retains a private fold.
    /// This query depends only on the installed plan, never on an operation witness.
    pub const fn requires_private_fold(&self) -> bool {
        self.incoming.is_some()
    }

    /// Derive the exact incoming original opening before operation-wide mode selection.
    /// The selected VK must occupy the source-derived global index in this plan's
    /// installed incoming class. A malformed original proof is soft only under the
    /// same failure partition used by Q preparation; profile/key/resource failures abort.
    /// The original length is separate from its descriptor-sized safe verifier view.
    /// No mode, proposed verdict, Q proof or deciding claim is accepted or produced.
    ///
    /// # Errors
    /// Missing incoming class, wrong original class/key/index/view, or a hard verifier
    /// resource/profile failure. An opening still retains its deferred generator equation.
    pub fn incoming_original(
        &self,
        witness: &SigmaSlotWitness,
        global_index: u8,
        budget: MemoryBudget,
    ) -> Result<Option<FoldInput<Eq>>, QSigmaError> {
        self.incoming_original_cancellable(witness, global_index, budget, None)
    }
    /// Derive an original opening with cancellation kept outside the soft-invalid branch.
    /// # Errors
    /// As [`Self::incoming_original`], or explicit cancellation without any verdict.
    pub fn incoming_original_cancellable(
        &self,
        witness: &SigmaSlotWitness,
        global_index: u8,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Option<FoldInput<Eq>>, QSigmaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| QSigmaError::Fold(iroha_plonk_recursion::Error::Cancelled))?;
        let class = self.incoming.as_ref().ok_or(QSigmaError::UnauthorizedKey)?;
        if class.index(witness)? != global_index {
            return Err(QSigmaError::UnauthorizedKey);
        }
        if witness.proof.len() != class.verifier.proof_length() {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        if usize::try_from(witness.length).ok() != Some(witness.proof.len()) {
            return Ok(None);
        }
        match class.opening(witness, budget, cancellation) {
            Ok(original) => Ok(Some(original)),
            Err(QSigmaError::Verify(error)) if incoming_proof_failure(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Prepares the exact local relation, including a fold whenever an incoming
    /// sigma is present. Own (when present) and Accept claims must decide.
    /// Corrected must change an undecidable original; Trivial uses the pinned k16
    /// claim. The caller must authorize the selected mode in A's global branch rule.
    ///
    /// # Errors
    /// Wrong slots/lengths/classes or fold source, invalid own proof, an impossible
    /// incoming mode, or failed fresh/retained fold verification and decision.
    /// Retained preparation never samples coins and rederives the complete public
    /// frame from the exact source proofs; callers must compare the whole frame
    /// against the retained original Q proof before accepting a checkpoint.
    pub fn prepare(
        &self,
        own: Option<SigmaSlotWitness>,
        incoming: Option<IncomingSigma>,
        params: &PinnedParams<Eq>,
        fold_source: QSigmaFoldSource<'_>,
        config: &FoldConfig,
    ) -> Result<PreparedQSigma, QSigmaError> {
        iroha_pasta::CancellationToken::checkpoint(config.cancellation.as_ref())
            .map_err(|_| QSigmaError::Fold(iroha_plonk_recursion::Error::Cancelled))?;
        fold_source.check_presence(incoming.is_some())?;
        if self.own.is_some() != own.is_some()
            || self
                .own
                .as_ref()
                .zip(own.as_ref())
                .is_some_and(|(class, own)| own.proof.len() != class.verifier.proof_length())
            || self.incoming.is_some() != incoming.is_some()
            || self
                .incoming
                .as_ref()
                .zip(incoming.as_ref())
                .is_some_and(|(class, input)| {
                    input.sigma.proof.len() != class.verifier.proof_length()
                })
        {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        let mut statements = Vec::new();
        let mut exported = Vec::new();
        let mut indices = Vec::new();
        let mut verdicts = Vec::new();
        let own_claim = match (self.own.as_ref(), own.as_ref()) {
            (Some(class), Some(own)) => {
                if usize::try_from(own.length).ok() != Some(own.proof.len()) {
                    return Err(QSigmaError::OwnLength);
                }
                let own_index = class.index(own)?;
                let own_claim =
                    class.opening(own, config.kernel_budget, config.cancellation.as_ref())?;
                own_claim
                    .decide_cancellable(params, config.kernel_budget, config.cancellation.as_ref())
                    .map_err(QSigmaError::Fold)?;
                statements.push(scalar(own.statement));
                exported.extend(chunks(own));
                indices.push(Fq::from(u64::from(own_index)));
                verdicts.push(Fq::ONE);
                Some(own_claim)
            }
            _ => None,
        };
        let (incoming, part) = if let Some(input) = incoming {
            let class = self.incoming.as_ref().ok_or(QSigmaError::IncomingMode)?;
            let index = class.index(&input.sigma)?;
            let original = self.incoming_original_cancellable(
                &input.sigma,
                index,
                config.kernel_budget,
                config.cancellation.as_ref(),
            )?;
            let valid = original.is_some();
            let trivial = AccumulatorT::trivial_cancellable(
                params,
                config.kernel_budget,
                config.cancellation.as_ref(),
            )
            .map_err(QSigmaError::Fold)?;
            let (selected, corrected) = match input.mode {
                IncomingMode::Accept => {
                    let original = original.ok_or(QSigmaError::IncomingMode)?;
                    original
                        .decide_cancellable(
                            params,
                            config.kernel_budget,
                            config.cancellation.as_ref(),
                        )
                        .map_err(QSigmaError::Fold)?;
                    (original, Eq::from(*trivial.g()))
                }
                IncomingMode::Trivial => (trivial.as_input(), Eq::from(*trivial.g())),
                IncomingMode::Corrected => {
                    let original = original.ok_or(QSigmaError::IncomingMode)?;
                    let correction = original
                        .corrected_cancellable(
                            params,
                            config.kernel_budget,
                            config.cancellation.as_ref(),
                        )
                        .map_err(QSigmaError::Fold)?;
                    (
                        correction.replacement().clone(),
                        Eq::from(*correction.replacement().g()),
                    )
                }
            };
            let inputs = own_claim
                .into_iter()
                .chain([selected, trivial.as_input()])
                .collect::<Vec<_>>();
            let (fold, part) = fold_source.resolve(params, &inputs, config)?;
            statements.push(scalar(input.sigma.statement));
            exported.extend(chunks(&input.sigma));
            indices.push(Fq::from(u64::from(index)));
            verdicts.push(Fq::from(u64::from(valid)));
            verdicts.extend(input.mode.bits().map(|bit| Fq::from(u64::from(bit))));
            (
                Some(IncomingSigmaWitness {
                    sigma: input.sigma,
                    mode: input.mode.bits(),
                    corrected,
                    fold,
                }),
                part.as_input(),
            )
        } else {
            (
                None,
                own_claim.ok_or(QSigmaError::Layout(LayoutError::Synthesis))?,
            )
        };
        statements.extend(exported);
        statements.extend(part.challenges().iter().copied().map(scalar));
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(part.g());
        let instances = vec![
            statements,
            vec![x, y],
            indices,
            verdicts,
            vec![Fq::from(u64::from(part.source_k()))],
        ];
        let circuit = QSigmaCircuit::new(self.clone(), QSigmaWitness { own, incoming })
            .map_err(QSigmaError::Layout)?;
        Ok(PreparedQSigma {
            circuit,
            instances,
            part,
        })
    }
}

/// Source-only installation metadata for one fixed Q plan and slot schedule.
///
/// The installation owner independently authenticates the complete plan/catalog,
/// profile and keys. These representative member keys supply only the witness
/// shape of each fixed descriptor class: their values remain unknown in source
/// synthesis, while every catalog digest remains circuit-fixed. This object
/// contains no operation proof, accepted mode, public frame or deciding claim.
#[derive(Clone, Debug)]
pub struct QSigmaSource {
    plan: QSigmaPlan,
    own_key: Option<VerifyingKey<Eq>>,
    incoming_key: Option<VerifyingKey<Eq>>,
}
impl QSigmaSource {
    /// Check one actual installed member VK per present descriptor class.
    ///
    /// The complete ordered catalog is preserved. A representative key never
    /// fixes the runtime-selected member, and construction grants no authority.
    /// Proof-sized buffers are allocated only after the import's resource bounds.
    ///
    /// # Errors
    /// Missing/extra incoming slot, foreign descriptor, noncanonical key/profile,
    /// or a key absent from its slot's independently installed catalog.
    pub fn new(
        plan: QSigmaPlan,
        own_key: VerifyingKey<Eq>,
        incoming_key: Option<VerifyingKey<Eq>>,
    ) -> Result<Self, QSigmaError> {
        Self::build(plan, Some(own_key), incoming_key)
    }

    /// The same check for an incoming-only plan, whose route proves its own step in A.
    ///
    /// # Errors
    /// As [`Self::new`], or a plan that has an own slot.
    pub fn incoming_only(
        plan: QSigmaPlan,
        incoming_key: VerifyingKey<Eq>,
    ) -> Result<Self, QSigmaError> {
        Self::build(plan, None, Some(incoming_key))
    }

    fn build(
        plan: QSigmaPlan,
        own_key: Option<VerifyingKey<Eq>>,
        incoming_key: Option<VerifyingKey<Eq>>,
    ) -> Result<Self, QSigmaError> {
        if plan.own.is_some() != own_key.is_some()
            || plan.incoming.is_some() != incoming_key.is_some()
        {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        let check = |class: &SigmaClass, key: VerifyingKey<Eq>| {
            if key.descriptor_digest() != class.verifier.binding().digest() {
                return Err(QSigmaError::UnauthorizedKey);
            }
            let key = VerifyingKey::<Eq>::read(key.to_bytes(), class.verifier.binding()).map_err(
                |error| {
                    QSigmaError::Artifact(iroha_plonk::keys::pk::artifact::Error::Key(
                        KeyError::VerifyingKey(error),
                    ))
                },
            )?;
            class.key_index(&key)?;
            Ok(key)
        };
        let own_key = plan
            .own
            .as_ref()
            .zip(own_key)
            .map(|(class, key)| check(class, key))
            .transpose()?;
        let incoming_key = plan
            .incoming
            .as_ref()
            .zip(incoming_key)
            .map(|(class, key)| check(class, key))
            .transpose()?;
        Ok(Self {
            plan,
            own_key,
            incoming_key,
        })
    }

    /// The complete immutable installed source plan, without operation witnesses.
    #[must_use]
    pub const fn plan(&self) -> &QSigmaPlan {
        &self.plan
    }

    /// Reconstruct the canonical two-range-bus serialized sigma-Q source.
    /// Every witness is unknown while the complete class catalogs remain fixed.
    /// Offline tooling can derive exact source keys without a prepared operation,
    /// accepted incoming mode, proof or deciding claim. The original importer
    /// uses this same source construction for its two-bus profile.
    /// # Errors
    /// Invalid source dimensions or unsupported fixed serialized layout.
    pub fn source_circuit(&self) -> Result<super::SerializedQSigmaCircuit, QSigmaError> {
        self.serialized_circuit(2)
    }

    fn serialized_circuit(
        &self,
        buses: usize,
    ) -> Result<super::SerializedQSigmaCircuit, QSigmaError> {
        self.circuit()?
            .with_serialized_foreign(buses)
            .map_err(QSigmaError::Layout)
    }

    // Original intake and source-parity tests share the raw unknown shape.
    // Every tape, mode, key coordinate and correction is assigned as unknown;
    // this function never constructs or accepts a PreparedQSigma.
    fn circuit(&self) -> Result<QSigmaCircuit, QSigmaError> {
        let slot = |class: &SigmaClass, key: &VerifyingKey<Eq>| {
            let length = class.verifier.proof_length();
            let encoded_length = u32::try_from(length)
                .map_err(|_| QSigmaError::Layout(LayoutError::BoundsFailure))?;
            Ok::<_, QSigmaError>(SigmaSlotWitness {
                key: key.clone(),
                statement: Fp::ZERO,
                proof: vec![0; length],
                length: encoded_length,
            })
        };
        let own = self
            .plan
            .own
            .as_ref()
            .zip(self.own_key.as_ref())
            .map(|(class, key)| slot(class, key))
            .transpose()?;
        let incoming = self
            .plan
            .incoming
            .as_ref()
            .zip(self.incoming_key.as_ref())
            .map(|(class, key)| {
                Ok::<_, QSigmaError>(IncomingSigmaWitness {
                    sigma: slot(class, key)?,
                    mode: [false; 3],
                    corrected: self.plan.trivial,
                    fold: crate::private_fold::PrivateFoldBytes::unknown(),
                })
            })
            .transpose()?;
        QSigmaCircuit::new(self.plan.clone(), QSigmaWitness { own, incoming })
            .map(|circuit| circuit.without_witnesses())
            .map_err(QSigmaError::Layout)
    }
}

/// Native outer Q verifier metadata and pinned Pallas parameters.
/// The exact profile/source authority is fixed; no proving polynomials are retained.
#[derive(Debug)]
pub struct QSigmaProver {
    params: PinnedParams<Ep>,
    key: SourceBoundVerifyingKeyV2<Ep>,
    serialized_buses: Option<usize>,
}
/// A Q proof and its exact public frame, retaining the Vesta part obligation.
#[must_use = "verify the Q proof in A and propagate the Vesta part to Omega"]
#[derive(Clone, Debug)]
pub struct QSigmaProof {
    /// Canonical PIPA-R proof, with its generator suffix.
    pub bytes: Vec<u8>,
    /// Five homogeneous public columns.
    pub instances: Vec<Vec<Fq>>,
    /// Forwarded or folded inner obligation, never implicitly omitted.
    pub part: FoldInput<Eq>,
}
impl QSigmaProver {
    /// Generates this concrete Q class key at k16, mints exact-source verifier
    /// metadata and drops proving buffers. Prepared values are discarded during
    /// source synthesis. Artifact producers use the explicit engine keygen path.
    ///
    /// # Errors
    /// Parameters are not k16, or synthesis/key generation fails.
    pub fn keygen(
        prepared: &PreparedQSigma,
        params: PinnedParams<Ep>,
    ) -> Result<Self, QSigmaError> {
        Self::keygen_profile(prepared, params, None)
    }
    /// Generates the explicitly selected shared-range serialized Q profile.
    /// The selected layout is retained by the prover and never inferred from
    /// supplied proof bytes or used as a verification fallback.
    ///
    /// # Errors
    /// Invalid fixed bus count, non-k16 parameters, or failed key generation.
    pub fn keygen_serialized_foreign(
        prepared: &PreparedQSigma,
        params: PinnedParams<Ep>,
        range_buses: usize,
    ) -> Result<Self, QSigmaError> {
        if !(1..=8).contains(&range_buses) {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        Self::keygen_profile(prepared, params, Some(range_buses))
    }
    fn keygen_profile(
        prepared: &PreparedQSigma,
        params: PinnedParams<Ep>,
        serialized_buses: Option<usize>,
    ) -> Result<Self, QSigmaError> {
        if params.k() != 16 {
            return Err(QSigmaError::Parameters);
        }
        let mut config = KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
        config.coset_cache = CosetCachePolicy::OnDemand;
        let key = if let Some(buses) = serialized_buses {
            let circuit = prepared
                .circuit
                .clone()
                .with_serialized_foreign(buses)
                .map_err(QSigmaError::Layout)?;
            keygen_pk_v2(&params, &circuit, &config)
        } else {
            keygen_pk_v2(&params, &prepared.circuit, &config)
        }
        .map_err(QSigmaError::Key)?;
        let metadata = SourceBoundVerifyingKeyV2::from_proving_key(&key, None)
            .map_err(QSigmaError::Rebuild)?;
        drop(key);
        Ok(Self {
            params,
            key: metadata,
            serialized_buses,
        })
    }
    /// Import original Q material for the default fixed source profile. The
    /// installed native owner authenticates the descriptor/VK, complete source
    /// plan/catalog, scheme scope and resource policy before this call. Strict
    /// source/commitment checks transitively admit PK material under that VK;
    /// no additional PK signature or prepared operation is required. Import generates no key and grants no
    /// `NativeProofs` owner, wallet-open capability or completed A/Omega relation.
    /// Original/domain bounds do not qualify total synthesis/prover memory.
    ///
    /// # Errors
    /// Non-k16 parameters, wrong V2 profile/schema, substituted installed VK, or
    /// a bounded source/commitment import failure. There is no profile fallback.
    pub fn from_original_artifact(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_artifact_cancellable(
            source,
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
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_with_admission_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
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
    pub fn from_builtin_original_artifact_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        member: iroha_plonk::keys::BuiltinSourceMemberV1,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_with_admission_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            crate::original_admission::OriginalAdmission::Builtin(member),
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_original_with_admission_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| QSigmaError::Prover(iroha_plonk::ProverError::Cancelled))?;
        Self::from_original_profile_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            None,
            admission,
            cancellation,
        )
    }

    /// Import the independently installed shared-range serialized Q profile.
    /// The fixed bus count is selected by native installation metadata, never
    /// inferred from original/proof bytes or tried as a fallback. Descriptor,
    /// VK and complete source/catalog selection remain the installation owner's
    /// duty, as in [`Self::from_original_artifact`]; no monetary authority is granted.
    ///
    /// # Errors
    /// Invalid fixed bus count or any default-profile import refusal above.
    pub fn from_original_artifact_serialized_foreign(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        range_buses: usize,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_artifact_serialized_foreign_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            range_buses,
            None,
        )
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    // Retain distinct authenticated originals and explicit per-operation policy.
    #[allow(clippy::too_many_arguments)]
    pub fn from_original_artifact_serialized_foreign_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        range_buses: usize,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_serialized_foreign_with_admission_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            range_buses,
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
    pub fn from_builtin_original_artifact_serialized_foreign_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        range_buses: usize,
        member: iroha_plonk::keys::BuiltinSourceMemberV1,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        Self::from_original_serialized_foreign_with_admission_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            range_buses,
            crate::original_admission::OriginalAdmission::Builtin(member),
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_original_serialized_foreign_with_admission_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        range_buses: usize,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| QSigmaError::Prover(iroha_plonk::ProverError::Cancelled))?;
        if !(1..=8).contains(&range_buses) {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        Self::from_original_profile_cancellable(
            source,
            params,
            descriptor,
            installed_vk,
            original,
            config,
            Some(range_buses),
            admission,
            cancellation,
        )
    }

    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    // Retain distinct authenticated originals and explicit per-operation policy.
    #[allow(clippy::too_many_arguments)]
    fn from_original_profile_cancellable(
        source: &QSigmaSource,
        params: PinnedParams<Ep>,
        descriptor: &[u8],
        installed_vk: &[u8],
        original: &[u8],
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
        serialized_buses: Option<usize>,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, QSigmaError> {
        use iroha_plonk::cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2};
        use iroha_plonk::keys::pk::artifact::Error as ArtifactError;
        iroha_pasta::CancellationToken::checkpoint(cancellation)
            .map_err(|_| QSigmaError::Prover(iroha_plonk::ProverError::Cancelled))?;
        if params.k() != 16 {
            return Err(QSigmaError::Parameters);
        }
        let binding = DescriptorBinding::decode_v2(descriptor).map_err(QSigmaError::Descriptor)?;
        let d = binding.descriptor();
        let lengths = source.plan.instance_lengths();
        if d.k != 16
            || d.curve != CurveV1::Pallas
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_types.as_deref() != Some(&QSigmaPlan::instance_types())
            || d.instance_lengths.len() != lengths.len()
            || !d
                .instance_lengths
                .iter()
                .zip(lengths)
                .all(|(found, expected)| usize::try_from(*found).ok() == Some(expected))
        {
            return Err(QSigmaError::Profile);
        }
        // Reject the installed allocation bounds before cloning a serialized source.
        if original.len() > config.maximum_bytes || binding.n() > config.maximum_rows {
            return Err(QSigmaError::Artifact(ArtifactError::Length));
        }
        let validated_vk = VerifyingKey::<Ep>::read(installed_vk, &binding).map_err(|error| {
            QSigmaError::Artifact(ArtifactError::Key(KeyError::VerifyingKey(error)))
        })?;
        let key = if let Some(buses) = serialized_buses {
            let circuit = source.serialized_circuit(buses)?;
            admission.admit(
                original,
                &binding,
                &validated_vk,
                &params,
                &circuit,
                config,
                cancellation,
            )
        } else {
            let circuit = source.circuit()?;
            admission.admit(
                original,
                &binding,
                &validated_vk,
                &params,
                &circuit,
                config,
                cancellation,
            )
        }
        .map_err(QSigmaError::Artifact)?;
        if key.verifying_key().to_bytes() != installed_vk {
            return Err(QSigmaError::UnauthorizedKey);
        }

        Ok(Self {
            params,
            key,
            serialized_buses,
        })
    }

    /// Validated V2 descriptor, suitable for A's fixed verifier program.
    pub fn binding(&self) -> &DescriptorBinding {
        self.key.binding()
    }
    /// Fixed Q verifying key for A's class registry.
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        self.key.verifying_key()
    }
    /// The outer pinned Pallas prefix.
    pub const fn params(&self) -> &PinnedParams<Ep> {
        &self.params
    }
    /// Move admitted public metadata into an installed owner's existing graph.
    #[must_use]
    pub fn into_metadata(self) -> SourceBoundVerifyingKeyV2<Ep> {
        self.key
    }

    /// Borrow this standalone owner's source authority without graph cloning.
    #[must_use]
    pub fn view(&self) -> QSigmaProverView<'_> {
        QSigmaProverView {
            params: &self.params,
            key: self.key.view(),
            serialized_buses: self.serialized_buses,
        }
    }
    /// Prove through the same borrowed implementation used by installed owners.
    /// # Errors
    /// Source mismatch, cancellation, proving or full verification failure.
    pub fn prove(
        &self,
        prepared: &PreparedQSigma,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<QSigmaProof, QSigmaError> {
        self.view().prove(prepared, randomness, config)
    }
}

/// Borrowed exact Q profile and source authority; no public graph or PK is cloned.
#[derive(Debug)]
pub struct QSigmaProverView<'a> {
    params: &'a PinnedParams<Ep>,
    key: SourceBoundViewV2<'a, Ep>,
    serialized_buses: Option<usize>,
}
impl<'a> QSigmaProverView<'a> {
    /// Bind the installed plan/profile to previously admitted exact metadata.
    /// A supplied source remains DATA and is checked again during reconstruction.
    /// # Errors
    /// Non-k16/profile, invalid bus count, or different declared public schema.
    pub fn from_source_bound(
        params: &'a PinnedParams<Ep>,
        key: SourceBoundViewV2<'a, Ep>,
        plan: &QSigmaPlan,
        serialized_buses: Option<usize>,
    ) -> Result<Self, QSigmaError> {
        use iroha_plonk::cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2};
        if params.k() != 16 {
            return Err(QSigmaError::Parameters);
        }
        if serialized_buses.is_some_and(|b| !(1..=8).contains(&b)) {
            return Err(QSigmaError::Layout(LayoutError::Synthesis));
        }
        let d = key.binding().descriptor();
        let lengths = plan.instance_lengths();
        if d.k != 16
            || d.curve != CurveV1::Pallas
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_types.as_deref() != Some(&QSigmaPlan::instance_types())
            || d.instance_lengths.len() != lengths.len()
            || !d
                .instance_lengths
                .iter()
                .zip(lengths)
                .all(|(a, b)| usize::try_from(*a).ok() == Some(b))
        {
            return Err(QSigmaError::Profile);
        }
        Ok(Self {
            params,
            key,
            serialized_buses,
        })
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
    /// Proves and completely self-verifies Q before returning its bytes.
    /// Witness construction rejects a different fixed plan/allowlist/copy graph.
    ///
    /// # Errors
    /// Circuit mismatch, synthesis/proving failure or failed self-verification.
    pub fn prove(
        &self,
        prepared: &PreparedQSigma,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<QSigmaProof, QSigmaError> {
        // Cancellation is checked before either profile clones/reconstructs a source.
        iroha_pasta::CancellationToken::checkpoint(config.cancellation)
            .map_err(|_| QSigmaError::Prover(ProverError::Cancelled))?;
        let bytes = if let Some(buses) = self.serialized_buses {
            let circuit = prepared
                .circuit
                .clone()
                .with_serialized_foreign(buses)
                .map_err(QSigmaError::Layout)?;
            self.prove_circuit(&circuit, prepared, randomness, config)?
        } else {
            self.prove_circuit(&prepared.circuit, prepared, randomness, config)?
        };
        let _self_verification = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SelfVerify,
        );
        // The helper's sole temporary PK has dropped before full verification,
        // including on errors, cancellation and unwinding. No cross-proof cache.
        iroha_plonk::verifier::verify_full_cancellable(
            self.params,
            self.binding(),
            self.verifying_key(),
            &prepared.instances,
            &bytes,
            config.msm_budget,
            config.cancellation,
        )
        .map_err(QSigmaError::Verify)?;
        Ok(QSigmaProof {
            bytes,
            instances: prepared.instances.clone(),
            part: prepared.part.clone(),
        })
    }

    fn prove_circuit<C: Circuit<Fq>>(
        &self,
        circuit: &C,
        prepared: &PreparedQSigma,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<Vec<u8>, QSigmaError> {
        // Prepared public values and the actual circuit remain independently
        // checked against the exact admitted source before any proof is produced.
        let (key, witness) = rebuild_key_and_witness_v2_cancellable(
            self.params,
            circuit,
            &self.key,
            &prepared.instances,
            CosetCachePolicy::OnDemand,
            config.cancellation,
        )
        .map_err(|error| match error {
            RebuildWitnessError::Rebuild(error) => QSigmaError::Rebuild(error),
            RebuildWitnessError::Witness(error) => QSigmaError::Prover(error),
        })?;
        #[cfg(test)]
        crate::proof_entry_probe::reached();
        create_proof_owned(self.params, &key, witness, randomness, config)
            .map_err(QSigmaError::Prover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_failures_remain_hard_and_preserve_cancellation() {
        assert!(QSigmaError::Rebuild(RebuildError::Key(KeyError::Cancelled)).is_cancelled());
        for error in [RebuildError::Profile, RebuildError::Source] {
            assert!(!QSigmaError::Rebuild(error).is_cancelled());
        }
    }

    fn source_fixture() -> (QSigmaPlan, Vec<VerifyingKey<Eq>>, PinnedParams<Eq>) {
        use crate::admin_sigma::{
            BOOTSTRAP_K, BootstrapCircuit, BootstrapWitness, ConsumingWitness, LoadCircuit,
            LoadWitness, RetiringCircuit, StateWitness,
        };
        use std::sync::OnceLock;
        type SourceFixture = (
            Vec<VerifyingKey<Eq>>,
            DescriptorBinding,
            PinnedParams<Eq>,
            PinnedParams<Eq>,
        );
        static FIXTURE: OnceLock<SourceFixture> = OnceLock::new();
        let (keys, binding, params, inner) = FIXTURE.get_or_init(|| {
            let params = PinnedParams::<Eq>::derive(BOOTSTRAP_K).unwrap();
            let blank = BootstrapWitness {
                core: [Fp::ZERO; 29],
                rest: [Fp::ZERO; 6],
                lineage: [Fp::ZERO; 18],
                statement: [Fp::ZERO; 26],
            };
            let state = StateWitness::from(&blank);
            let load = LoadWitness {
                predecessor: state,
                successor: state,
                statement: blank.statement,
            };
            let consuming = ConsumingWitness {
                predecessor: state,
                successor: state,
                statement: blank.statement,
            };
            let mut config = KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec());
            config.compress_selectors = false;
            let first = keygen_pk_v2(
                &params,
                &BootstrapCircuit::new(&blank).without_witnesses(),
                &config,
            )
            .unwrap();
            let binding = first.binding().clone();
            let keys = vec![
                first.vk().clone(),
                keygen_pk_v2(
                    &params,
                    &LoadCircuit::new(&load).without_witnesses(),
                    &config,
                )
                .unwrap()
                .vk()
                .clone(),
                keygen_pk_v2(
                    &params,
                    &RetiringCircuit::new(&consuming).without_witnesses(),
                    &config,
                )
                .unwrap()
                .vk()
                .clone(),
                keygen_pk_v2(
                    &params,
                    &BootstrapCircuit::new(&blank).without_witnesses(),
                    &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
                )
                .unwrap()
                .vk()
                .clone(),
            ];
            (
                keys,
                binding,
                params,
                PinnedParams::<Eq>::derive(16).unwrap(),
            )
        });
        // Exact same descriptor class, different operation keys. Retiring is not
        // in this source catalog and is retained only for the admission refusal.
        assert_eq!(keys[0].descriptor_digest(), keys[1].descriptor_digest());
        let verifier = VerifierPlan::new(binding.clone(), params.clone()).unwrap();
        let class = SigmaClass::new(
            verifier,
            vec![
                (0, keys[0].kagemusha_digest(binding).unwrap()),
                (1, keys[1].kagemusha_digest(binding).unwrap()),
            ],
        )
        .unwrap();
        (
            QSigmaPlan::new(class, None, inner).unwrap(),
            keys.clone(),
            inner.clone(),
        )
    }

    #[test]
    fn pre_q_original_checks_exact_class_and_global_selector_before_soft_length() {
        let (one, keys, params) = source_fixture();
        let own = one.class(QSigmaPlan::OWN).unwrap().clone();
        let plan = QSigmaPlan::new(own.clone(), Some(own), &params).unwrap();
        assert!(!one.requires_private_fold());
        assert!(plan.requires_private_fold());
        let length = plan.class(1).unwrap().verifier().proof_length();
        let mut original = SigmaSlotWitness {
            key: keys[0].clone(),
            statement: Fp::from(7),
            proof: vec![0; length],
            length: 0,
        };
        assert!(
            plan.incoming_original(&original, 0, MemoryBudget::DEFAULT)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            plan.incoming_original(&original, 1, MemoryBudget::DEFAULT),
            Err(QSigmaError::UnauthorizedKey)
        ));
        original.key = keys[2].clone();
        assert!(matches!(
            plan.incoming_original(&original, 0, MemoryBudget::DEFAULT),
            Err(QSigmaError::UnauthorizedKey)
        ));
        original.key = keys[3].clone();
        assert!(matches!(
            plan.incoming_original(&original, 0, MemoryBudget::DEFAULT),
            Err(QSigmaError::UnauthorizedKey)
        ));
        original.key = keys[0].clone();
        original.proof.pop();
        assert!(matches!(
            plan.incoming_original(&original, 0, MemoryBudget::DEFAULT),
            Err(QSigmaError::Layout(_))
        ));
        assert!(matches!(
            one.incoming_original(&original, 0, MemoryBudget::DEFAULT),
            Err(QSigmaError::UnauthorizedKey)
        ));
    }

    #[test]
    fn pre_q_sigma_uses_q_preparation_failure_partition_without_resource_fallback() {
        for error in [
            VerifyError::Transcript(TranscriptError::ProofTruncated),
            VerifyError::ProofLength {
                expected: 32,
                actual: 31,
            },
            VerifyError::Ipa(IpaError::OpeningFailed),
        ] {
            assert!(incoming_proof_failure(&error));
        }
        for error in [
            VerifyError::KeyMismatch,
            VerifyError::ParamsMismatch,
            VerifyError::SuffixRequired,
            VerifyError::Transcript(TranscriptError::ProfileMismatch),
            VerifyError::Ipa(IpaError::Transcript(TranscriptError::ProfileMismatch)),
            VerifyError::Ipa(IpaError::ParamsTooSmall {
                needed: 16,
                available: 12,
            }),
        ] {
            assert!(!incoming_proof_failure(&error));
        }
    }

    #[test]
    fn cancellation_never_authorizes_incoming_burn_or_correction() {
        for error in [
            VerifyError::Cancelled,
            VerifyError::Ipa(IpaError::Cancelled),
            VerifyError::Multiopen(iroha_plonk::pcs::multiopen::MultiopenError::Cancelled),
            VerifyError::Multiopen(iroha_plonk::pcs::multiopen::MultiopenError::Ipa(
                IpaError::Cancelled,
            )),
        ] {
            assert!(error.is_cancelled());
            assert!(!incoming_proof_failure(&error));
            assert!(QSigmaError::Verify(error).is_cancelled());
        }
        assert!(QSigmaError::Fold(iroha_plonk_recursion::Error::Cancelled).is_cancelled());
        assert!(!QSigmaError::IncomingMode.is_cancelled());
    }

    #[test]
    fn installed_q_source_rejects_missing_extra_or_unauthorized_members() {
        let (plan, keys, inner) = source_fixture();
        assert!(QSigmaSource::new(plan.clone(), keys[0].clone(), None).is_ok());
        assert!(QSigmaSource::new(plan.clone(), keys[0].clone(), Some(keys[1].clone())).is_err());
        assert!(matches!(
            QSigmaSource::new(plan.clone(), keys[2].clone(), None),
            Err(QSigmaError::UnauthorizedKey)
        ));
        assert_ne!(keys[3].descriptor_digest(), keys[0].descriptor_digest());
        assert!(matches!(
            QSigmaSource::new(plan.clone(), keys[3].clone(), None),
            Err(QSigmaError::UnauthorizedKey)
        ));
        let own = plan.class(QSigmaPlan::OWN).unwrap().clone();
        let two = QSigmaPlan::new(own.clone(), Some(own.clone()), &inner).unwrap();
        assert!(QSigmaSource::new(two.clone(), keys[0].clone(), None).is_err());
        assert!(matches!(
            QSigmaSource::new(two.clone(), keys[0].clone(), Some(keys[2].clone())),
            Err(QSigmaError::UnauthorizedKey)
        ));
        assert!(matches!(
            QSigmaSource::new(two.clone(), keys[0].clone(), Some(keys[3].clone())),
            Err(QSigmaError::UnauthorizedKey)
        ));
        assert!(QSigmaSource::new(two, keys[0].clone(), Some(keys[1].clone())).is_ok());
        // A lean route's incoming-only program has one soft slot and a k16 fold part.
        let lean = QSigmaPlan::incoming_only(own, &inner).unwrap();
        assert!(!lean.has_own());
        assert_eq!(lean.slot_count(), 1);
        assert_eq!(lean.position(QSigmaPlan::INCOMING), Some(0));
        assert!(lean.position(QSigmaPlan::OWN).is_none());
        assert_eq!(lean.part_source_k(), 16);
        let chunks = lean.class(QSigmaPlan::INCOMING).unwrap().chunks();
        assert_eq!(lean.chunk_range(QSigmaPlan::INCOMING), Some(1..1 + chunks));
        assert_eq!(
            lean.instance_lengths(),
            [1 + chunks + iroha_plonk_recursion::K, 2, 1, 4, 1]
        );
        assert!(QSigmaSource::new(lean.clone(), keys[0].clone(), Some(keys[1].clone())).is_err());
        assert!(QSigmaSource::incoming_only(lean.clone(), keys[1].clone()).is_ok());
        assert!(matches!(
            QSigmaSource::incoming_only(lean, keys[3].clone()),
            Err(QSigmaError::UnauthorizedKey)
        ));
    }

    #[test]
    fn installed_q_source_layout_does_not_pin_an_allowlisted_member() {
        use iroha_plonk::frontend::synthesize;
        let (plan, keys, inner) = source_fixture();
        let own = plan.class(QSigmaPlan::OWN).unwrap().clone();
        for incoming in [false, true] {
            let plan = QSigmaPlan::new(own.clone(), incoming.then(|| own.clone()), &inner).unwrap();
            let a = QSigmaSource::new(
                plan.clone(),
                keys[0].clone(),
                incoming.then(|| keys[1].clone()),
            )
            .unwrap();
            let b = QSigmaSource::new(
                plan.clone(),
                keys[1].clone(),
                incoming.then(|| keys[0].clone()),
            )
            .unwrap();
            assert_eq!(a.plan().instance_lengths(), plan.instance_lengths());
            let factory = a.source_circuit().unwrap();
            let a = a.circuit().unwrap();
            let b = b.circuit().unwrap();
            assert!(!a.known && !b.known);
            assert_eq!(a.params(), b.params());
            for buses in [None, Some(2)] {
                let synthesize_source = |c: &QSigmaCircuit| {
                    buses.map_or_else(
                        || synthesize(c, 16, None).unwrap(),
                        |buses| {
                            synthesize(&c.clone().with_serialized_foreign(buses).unwrap(), 16, None)
                                .unwrap()
                        },
                    )
                };
                let first = synthesize_source(&a);
                let second = synthesize_source(&b);
                if buses == Some(2) {
                    let actual = synthesize(&factory, 16, None).unwrap();
                    assert_eq!(actual.tables.fixed(), first.tables.fixed());
                    assert_eq!(actual.tables.selectors(), first.tables.selectors());
                    assert_eq!(actual.tables.permutation(), first.tables.permutation());
                    assert_eq!(
                        actual.tables.advice_assigned(),
                        first.tables.advice_assigned()
                    );
                }
                assert_eq!(first.tables.fixed(), second.tables.fixed());
                assert_eq!(first.tables.selectors(), second.tables.selectors());
                assert_eq!(first.tables.permutation(), second.tables.permutation());
                assert_eq!(
                    first.tables.advice_assigned(),
                    second.tables.advice_assigned()
                );
                assert_eq!(first.cs.instance_lengths(), second.cs.instance_lengths());
                if !incoming && buses.is_none() {
                    let mut changed = plan.clone();
                    changed.own.as_mut().unwrap().entries.reverse();
                    let changed = QSigmaSource::new(changed, keys[0].clone(), None)
                        .unwrap()
                        .circuit()
                        .unwrap();
                    let changed = synthesize_source(&changed);
                    assert_ne!(
                        first.tables.fixed(),
                        changed.tables.fixed(),
                        "catalog order remains fixed source metadata"
                    );
                }
            }
        }
    }

    #[test]
    fn soft_failure_classification_retains_configuration_and_resource_errors() {
        assert!(incoming_proof_failure(&VerifyError::Transcript(
            TranscriptError::InvalidPoint
        )));
        assert!(incoming_proof_failure(&VerifyError::Ipa(
            IpaError::OpeningFailed
        )));
        assert!(incoming_proof_failure(&VerifyError::Multiopen(
            MultiopenError::Ipa(IpaError::ZeroChallenge { round: 0 })
        )));
        assert!(!incoming_proof_failure(&VerifyError::Transcript(
            TranscriptError::ProfileMismatch
        )));
        for error in [
            TranscriptError::ProofTruncated,
            TranscriptError::TrailingBytes { remaining: 1 },
            TranscriptError::NonCanonicalScalar,
            TranscriptError::InvalidPoint,
            TranscriptError::IdentityPoint,
        ] {
            assert!(incoming_proof_failure(&VerifyError::Transcript(error)));
            assert!(incoming_proof_failure(&VerifyError::Ipa(
                IpaError::Transcript(error)
            )));
            assert!(incoming_proof_failure(&VerifyError::Multiopen(
                MultiopenError::Ipa(IpaError::Transcript(error))
            )));
        }
        assert!(incoming_proof_failure(
            &VerifyError::IdentityInstanceCommitment { column: 0 }
        ));
        assert!(!incoming_proof_failure(&VerifyError::Ipa(
            IpaError::Transcript(TranscriptError::ProfileMismatch)
        )));
        assert!(!incoming_proof_failure(&VerifyError::Multiopen(
            MultiopenError::Ipa(IpaError::Transcript(TranscriptError::ProfileMismatch))
        )));
        assert!(!incoming_proof_failure(&VerifyError::KeyMismatch));
        assert!(!incoming_proof_failure(&VerifyError::Ipa(
            IpaError::ParamsTooSmall {
                needed: 16,
                available: 12
            }
        )));
    }
}

#[cfg(test)]
mod public_witness_tests;

#[cfg(test)]
mod retained_fold_tests;
