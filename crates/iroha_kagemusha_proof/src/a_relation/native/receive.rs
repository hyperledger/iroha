//! Fixed native Receive and renewed-Receive A/W composition.
//!
//! Installed artifacts pin the complete owner schedule. A proves the own Receive
//! step inline from the prepared step witness (lean lineage); Q0 verifies only the
//! incoming Send sigma, and Q1 is the merged signature leaf with the hard own
//! receipt first. Incoming decoded values, four result bits and correction points
//! are witness proposals: the mandatory producers derive them from the exact
//! original tapes and bind one common context. Native preparation verifies every
//! hard predecessor/Q proof and all selected deciding claims; it never replaces a
//! soft failure with acceptance.

mod circuit;
pub use circuit::PredicateInputs;
mod session;

#[cfg(test)]
mod tests;

pub use circuit::StageCircuit;
pub use session::{
    ACheckpoint, CheckpointKind, CheckpointLayout, Prover, RetainedSession, Session, Terminal,
    WCheckpoint,
};

use core::fmt;
use std::sync::Arc;

use ff::{Field, PrimeField};
use iroha_pasta::{
    Ep, EpAffine, Eq, EqAffine, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{DescriptorBinding, VerifyingKey, cs::InstanceType, pcs::ipa::PinnedParams};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::foreign_limbs};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, create_fold, obligation::ledger::Variant,
    verifier::VerifierPlan,
};

use super::support::{
    self, active_context, exact_context, frame, internal_public, mode_words, object_digest,
    omega_instances, opening_pallas_cancellable, opening_vesta_cancellable, push_pallas,
    q_sigma_part, select_pallas_cancellable, select_vesta_cancellable, stage_digest,
    terminal_digest, vesta_words,
};
use crate::{
    a_relation::{
        AProofPlan, QProofPlan,
        context::{ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        receive::{
            MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES, PAYMENT_PROOF_BUDGET,
            PAYMENT_RAW_PROOF_BUDGET, ReceiveStagePlan,
        },
    },
    admin_sigma::StateWitness,
    circuit::{PrefixMode, RelationShape},
    operation_relation::objects::ObjectKind,
    q_sigma::{QSigmaPlan, native::IncomingMode},
    tree::IndexedInsert,
    witness::{NativeStep, SigmaRelation, StepWitness},
};
use circuit::Stage;

/// Internal A circuits use the fixed tagged-four range layout.
pub const INTERNAL_RANGE_BUSES: usize = 4;
/// The operation terminal uses the common tagged-three catalog layout.
pub const TERMINAL_RANGE_BUSES: usize = 3;
/// Nine A stages separated by eight authenticated W continuations.
pub const A_STAGE_COUNT: usize = 9;
/// Exact internal wrapper count for the fixed Receive owner sequence.
pub const W_STAGE_COUNT: usize = A_STAGE_COUNT - 1;
/// Maximum combined original Omega/public and sigma bytes within Payment.
pub const MAX_PAYMENT_ORIGINAL_BYTES: usize = PAYMENT_RAW_PROOF_BUDGET;

/// Native source/artifact/proof error. No failure changes monetary state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Original local checkpoint read refusal; no invalid-input or proof verdict completed.
    DecodeResource(norito::core::DecodeLocalRefusal),
    /// Explicit cancellation; no proof failure or burn verdict is produced.
    Cancelled,
    /// An installed key, descriptor, parameter set or fixed schedule differs.
    Artifact,
    /// Exact source shape, canonical claim or admitted envelope is invalid.
    Input,
    /// A hard proof or selected accumulator fails full verification.
    Proof,
    /// Circuit assignment or proving fails.
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
        write!(f, "native Receive: {self:?}")
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

impl From<support::Error> for Error {
    fn from(error: support::Error) -> Self {
        match error {
            support::Error::Cancelled => Self::Cancelled,
            support::Error::Input => Self::Input,
            support::Error::Proof => Self::Proof,
        }
    }
}

/// Original verified Q proof and its exact descriptor-shaped public columns.
#[derive(Clone, Debug)]
pub struct QInput {
    /// Original unframed proof bytes.
    pub proof: Vec<u8>,
    /// Exact public columns; result and mode exports remain circuit-bound.
    pub instances: Vec<Vec<Fq>>,
}

/// Hard predecessor proof and both original full-k16 transported claims.
#[derive(Clone, Debug)]
pub struct PredecessorInput {
    /// Descriptor-sized unframed proof.
    pub proof: Vec<u8>,
    /// Canonical Pallas accumulator bytes.
    pub pallas: [u8; 544],
    /// Canonical Vesta accumulator bytes.
    pub vesta: [u8; 544],
}

/// Complete Receive state transition and exact depth32 map routes.
#[derive(Clone, Debug)]
pub struct Transition {
    /// Pre-Advance state and lineage public fields.
    pub before: StateWitness,
    /// Proposed successor and adjusted credit/burn lineage fields.
    pub after: StateWitness,
    /// Exact own statement26.
    pub statement: [Fp; 26],
    /// Consumed-credit authenticated lookup and insertion route.
    pub consumed: IndexedInsert<Fp>,
    /// Credit-record insertion route.
    pub credit: IndexedInsert<Fp>,
    /// The OQ-3 insertion flag, derived again by terminal Effects.
    pub insert: bool,
}

/// Total incoming decoder and result proposals authenticated by the fixed owners.
/// Malformed original bytes use the decoder's fixed safe representation. These
/// fields are not native acceptance certificates: the circuits derive every
/// value and validity bit from the original objects and Q proofs.
#[derive(Clone, Debug)]
pub struct IncomingWitness {
    /// Exact decoded public fields, or the pinned safe fields on malformed input.
    pub public: [Fp; 18],
    /// Proposed total public-decoder validity bit.
    pub public_valid: bool,
    /// Original decoded Pallas claim, including a non-deciding commitment if present.
    pub pallas: AccumulatorT<Ep>,
    /// Original decoded Vesta claim, including a non-deciding commitment if present.
    pub vesta: AccumulatorT<Eq>,
    /// Actual soft-Omega verifier opening, or its fixed safe dummy on failure.
    pub opening: FoldInput<Ep>,
    /// Four proposed fixed-order owner results.
    pub results: [bool; 4],
    /// Original-P, Omega-opening, original-V, incoming-sigma modes.
    pub modes: [IncomingMode; 4],
    /// Proposed corrected commitments for original-P and Omega-opening slots.
    pub pallas_corrections: [EpAffine; 2],
    /// Proposed corrected commitment for the original-V slot.
    pub vesta_correction: EqAffine,
}

/// Exact originals retained after Advance for complete ordinary/renewed Receive.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Own state transition and local map witnesses.
    pub transition: Transition,
    /// Original incoming Send statement26.
    pub incoming_statement: [Fp; 26],
    /// The prepared Receive step witness that A1 proves the relation of.
    pub step: StepWitness<Fp>,
    /// Request, payer Credential, Send Receipt, Payment, raw Omega, raw sigma,
    /// own Receipt, quoted Credential, quoted certificate.
    pub objects: [Vec<u8>; 9],
    /// Q0 incoming-only sigma, Q1 merged signatures (own receipt hard, then the
    /// original incoming slots soft).
    pub q: [QInput; 2],
    /// Actual receiver predecessor.
    pub predecessor: PredecessorInput,
    /// Source-bound soft decoder/results and obligation proposals.
    pub incoming: IncomingWitness,
}

/// Immutable complete nine-stage Receive metadata, pinned by artifact installation.
#[derive(Clone, Debug)]
pub struct Plan {
    stage: ReceiveStagePlan,
    policy: OwnPolicy,
    predecessor_key: VerifyingKey<Ep>,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin the exact full-envelope schedule for Receive or renewed Receive.
    /// # Errors
    /// Wrong variant, sigma/Q/source descriptor, key continuity or parameter profile.
    pub fn new(
        operation: AProofPlan,
        policy: OwnPolicy,
        predecessor_key: VerifyingKey<Ep>,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        let variant = operation.frame().variant();
        if !matches!(variant, Variant::Receive | Variant::ReceiveRenewed)
            || operation.frame().part_source_k() != 16
            || operation.q_count() != 2
            || !operation.is_inline()
            || operation.sigma_slots() != 1
            || !operation.frame().has_predecessor()
            || !operation.frame().has_incoming()
        {
            return Err(Error::Artifact);
        }
        let class = operation
            .sigma_class(QSigmaPlan::INCOMING)
            .ok_or(Error::Artifact)?;
        if !matches!(class.verifier().binding().descriptor().k, 12 | 14)
            || class.verifier().proof_length() > MAX_SIGMA_RAW_BYTES
        {
            return Err(Error::Artifact);
        }
        let incoming =
            crate::a_relation::incoming_transport::IncomingTransportPlan::new(&operation)
                .map_err(|_| Error::Artifact)?;
        if incoming.payload_length().map_err(|_| Error::Artifact)? > MAX_OMEGA_RAW_BYTES {
            return Err(Error::Artifact);
        }
        validate_transport_profile(
            incoming.payload_length().map_err(|_| Error::Artifact)?,
            operation
                .sigma_class(QSigmaPlan::INCOMING)
                .ok_or(Error::Artifact)?
                .verifier()
                .proof_length(),
        )?;
        pallas.require_k(16).map_err(|_| Error::Artifact)?;
        vesta.require_k(16).map_err(|_| Error::Artifact)?;
        let predecessor = operation.omega().ok_or(Error::Artifact)?;
        let d = predecessor.binding().descriptor();
        if predecessor_key.descriptor_digest() != predecessor.binding().digest()
            || d.k != 16
            || d.instance_lengths != [1, 2, 16]
            || d.instance_types.as_deref()
                != Some(&[
                    InstanceType::Bounded,
                    InstanceType::Field,
                    InstanceType::Bounded,
                ])
        {
            return Err(Error::Artifact);
        }
        predecessor_key
            .kagemusha_digest(predecessor.binding())
            .map_err(|_| Error::Artifact)?;
        let context =
            crate::a_relation::schedule::compiled::OperationSchedule::for_variant(variant)
                .bind(
                    operation,
                    ReceiveStagePlan::context_specs(
                        variant,
                        MAX_OMEGA_RAW_BYTES,
                        MAX_SIGMA_RAW_BYTES,
                    )
                    .map_err(|_| Error::Artifact)?,
                )
                .map_err(|_| Error::Artifact)?;
        let stage = ReceiveStagePlan::new(context, policy).map_err(|_| Error::Artifact)?;
        Ok(Self {
            stage,
            policy,
            predecessor_key,
            pallas,
            vesta,
        })
    }
    /// Exact authenticated context, task owners and Q partitions.
    pub const fn context(&self) -> &ContextPlan {
        self.stage.context()
    }
    /// Verify hard originals and retain all soft proposals for their circuit owners.
    /// # Errors
    /// Over-envelope input, wrong exact tape shape, hard proof or deciding obligation.
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
        let program = self.context().operation();
        let omega = program.omega().ok_or(Error::Artifact)?;
        let sigma = program.sigma_plan().map_err(|_| Error::Artifact)?;
        check_payment_original_sizes(input.objects[4].len(), input.objects[5].len())?;
        let specs = self.context().object_specs();
        for (index, raw) in input.objects.iter().enumerate() {
            if !matches!(index, 4 | 5)
                && raw.len()
                    != usize::try_from(specs[index].capacity).map_err(|_| Error::Artifact)?
            {
                return Err(Error::Input);
            }
        }
        support::check_hard_own_receipt_slot(
            &input.objects[6],
            &input.q[ReceiveStagePlan::SIGNATURE_Q].instances,
            self.stage
                .signature_schema(ReceiveStagePlan::SIGNATURE_Q)
                .ok_or(Error::Artifact)?
                .slots()
                .len(),
            core::array::from_fn(|i| input.transition.before.lineage[9 + i]),
        )?;
        // The step witness must evaluate, rule for rule, to the exact statement Advance
        // committed; A1 then proves that relation inline.
        if input.step.relation() != SigmaRelation::RECEIVE.step() || !input.step.canonical_digests()
        {
            return Err(Error::Input);
        }
        let native = input.step.evaluate(SigmaRelation::RECEIVE);
        if !native.violations.is_empty() || native.statement != input.transition.statement {
            return Err(Error::Input);
        }
        let pallas =
            AccumulatorT::from_bytes(&input.predecessor.pallas).map_err(|_| Error::Input)?;
        let vesta = AccumulatorT::from_bytes(&input.predecessor.vesta).map_err(|_| Error::Input)?;
        pallas
            .decide_cancellable(&self.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        vesta
            .decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let key_digest = self
            .predecessor_key
            .kagemusha_digest(omega.binding())
            .map_err(|_| Error::Artifact)?;
        if input.transition.before.lineage[17] != key_digest
            || input.transition.after.lineage[17] != key_digest
        {
            return Err(Error::Input);
        }
        let public = omega_instances(
            terminal_digest(&input.transition.before.lineage, &pallas.as_input())?,
            &vesta,
        )?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.pallas,
            omega.binding(),
            &self.predecessor_key,
            &public,
            &input.predecessor.proof,
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
        let opening = opening_pallas_cancellable(
            &self.pallas,
            omega.binding(),
            &self.predecessor_key,
            &public,
            &input.predecessor.proof,
            budget,
            cancellation,
        )?;
        let predecessor = Head {
            state: input.transition.before,
            key: self.predecessor_key.clone(),
            proof: input.predecessor.proof,
            pallas,
            vesta,
            opening,
        };
        let mut q = Vec::with_capacity(2);
        for (index, source) in input.q.into_iter().enumerate() {
            let fixed = program.q(index).ok_or(Error::Artifact)?;
            iroha_plonk::verifier::verify_full_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &source.instances,
                &source.proof,
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
            let opening = opening_pallas_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &source.instances,
                &source.proof,
                budget,
                cancellation,
            )?;
            q.push(QSource {
                plan: fixed.clone(),
                proof: source.proof,
                instances: source.instances,
                opening,
            });
        }
        let part = q_sigma_part(&q[0].instances, sigma)?;
        part.decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        validate_modes(&input.incoming)?;
        let selected_pallas = [
            select_pallas_cancellable(
                &self.pallas,
                &input.incoming.pallas.as_input(),
                input.incoming.modes[0],
                input.incoming.pallas_corrections[0],
                budget,
                cancellation,
            )?,
            select_pallas_cancellable(
                &self.pallas,
                &input.incoming.opening,
                input.incoming.modes[1],
                input.incoming.pallas_corrections[1],
                budget,
                cancellation,
            )?,
        ];
        // The terminal exports original V and its mode, while native preparation
        // separately decides the exact selected replacement before any proof work.
        let _selected_vesta = select_vesta_cancellable(
            &self.vesta,
            &input.incoming.vesta.as_input(),
            input.incoming.modes[2],
            input.incoming.vesta_correction,
            budget,
            cancellation,
        )?;
        let commitments = object_commitments(specs, &input.objects)?;
        let incoming_head = Head {
            state: StateWitness {
                core: [Fp::ZERO; 29],
                rest: [Fp::ZERO; 6],
                lineage: input.incoming.public,
            },
            key: self.predecessor_key.clone(),
            proof: vec![],
            pallas: input.incoming.pallas,
            vesta: input.incoming.vesta,
            opening: input.incoming.opening,
        };
        let source = Arc::new(Source {
            own: Own {
                witness: input.transition,
                send: SendStatement {
                    statement: input.incoming_statement,
                },
                step: Some((input.step, native)),
                incoming_sigma: input.objects[5].clone(),
                sigma_plan: sigma.clone(),
                part,
            },
            incoming: input.objects[4].clone(),
            objects: input.objects,
            commitments,
            predecessor,
            incoming_head,
            q,
            plan: self.stage.clone(),
            policy: self.policy,
            variant: program.frame().variant(),
            params: self.pallas.clone(),
            vparams: self.vesta.clone(),
            results: input.incoming.results,
            modes: input.incoming.modes,
            public_valid: input.incoming.public_valid,
            pallas_corrections: input.incoming.pallas_corrections,
            vesta_correction: input.incoming.vesta_correction,
            selected_pallas,
        });
        Ok(Prepared {
            plan: self.clone(),
            source,
        })
    }
}

#[derive(Clone)]
struct QSource {
    plan: QProofPlan,
    proof: Vec<u8>,
    instances: Vec<Vec<Fq>>,
    opening: FoldInput<Ep>,
}
#[derive(Clone)]
struct Head {
    state: StateWitness,
    key: VerifyingKey<Ep>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
    opening: FoldInput<Ep>,
}
#[derive(Clone)]
struct SendStatement {
    statement: [Fp; 26],
}
#[derive(Clone)]
struct Own {
    witness: Transition,
    send: SendStatement,
    /// The step witness and its native evaluation, absent for a blank source.
    step: Option<(StepWitness<Fp>, NativeStep<Fp>)>,
    incoming_sigma: Vec<u8>,
    sigma_plan: QSigmaPlan,
    part: FoldInput<Eq>,
}
impl Own {
    /// The `σ_recv` relation A1 proves inline, with absorbed prefixes.
    fn shape() -> RelationShape {
        RelationShape::new(SigmaRelation::RECEIVE, PrefixMode::Absorbed)
    }
}
struct Source {
    own: Own,
    predecessor: Head,
    incoming_head: Head,
    q: Vec<QSource>,
    plan: ReceiveStagePlan,
    policy: OwnPolicy,
    variant: Variant,
    objects: [Vec<u8>; 9],
    commitments: Vec<[Fp; 3]>,
    incoming: Vec<u8>,
    params: PinnedParams<Ep>,
    vparams: PinnedParams<Eq>,
    results: [bool; 4],
    modes: [IncomingMode; 4],
    public_valid: bool,
    pallas_corrections: [EpAffine; 2],
    vesta_correction: EqAffine,
    selected_pallas: [FoldInput<Ep>; 2],
}
impl Source {
    fn mode_words(&self, index: usize) -> [Fp; 3] {
        mode_words(self.modes[index])
    }
}

/// Checked hard originals coupled to this exact full-envelope owner plan.
#[derive(Clone)]
pub struct Prepared {
    plan: Plan,
    source: Arc<Source>,
}
impl Prepared {
    fn first(
        &self,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<Stage, Error> {
        let (fold, pallas) = create_fold(
            &self.plan.pallas,
            &[
                self.source.predecessor.pallas.as_input(),
                self.source.predecessor.opening.clone(),
            ],
            tape,
            iroha_plonk_recursion::FoldPurpose::AInitial,
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
        Ok(Stage {
            source: self.source.clone(),
            continuation: None,
            pallas: pallas.clone(),
            fold: crate::private_fold::PrivateFoldBytes::from_fold(fold),
            known: true,
        })
    }
    /// Construct the real A1 relation and its exact public frame for artifact tooling.
    /// # Errors
    /// A failed two-input predecessor fold or public-frame conversion.
    pub fn first_circuit(
        &self,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>), Error> {
        let inner = self.first(tape, config)?;
        let public = stage_public(&inner)?;
        Ok((StageCircuit { inner }, public))
    }
}

fn validate_transport_profile(omega: usize, sigma: usize) -> Result<(), Error> {
    let public = crate::a_relation::own::ConsumingProofCells::PUBLIC_BYTES;
    if omega
        .checked_sub(public)
        .and_then(|payload| payload.checked_add(sigma))
        .is_none_or(|payload| payload > PAYMENT_PROOF_BUDGET)
    {
        return Err(Error::Artifact);
    }
    Ok(())
}

/// Check both carrier bounds and their exact joint Payment envelope before allocation.
/// # Errors
/// Oversized originals or an overflowing combined length.
pub fn check_payment_original_sizes(omega: usize, sigma: usize) -> Result<(), Error> {
    if omega > MAX_OMEGA_RAW_BYTES
        || sigma > MAX_SIGMA_RAW_BYTES
        || omega
            .checked_add(sigma)
            .is_none_or(|total| total > PAYMENT_RAW_PROOF_BUDGET)
    {
        return Err(Error::Input);
    }
    Ok(())
}

fn validate_modes(input: &IncomingWitness) -> Result<(), Error> {
    let corrections = input
        .modes
        .iter()
        .filter(|m| **m == IncomingMode::Corrected)
        .count();
    if corrections > 1 {
        return Err(Error::Input);
    }
    let valid = input.results.iter().all(|v| *v) && corrections == 0;
    if input
        .modes
        .iter()
        .any(|m| (*m == IncomingMode::Accept) != valid)
    {
        return Err(Error::Input);
    }
    Ok(())
}

fn object_commitments(
    specs: &[ContextObjectSpec],
    objects: &[Vec<u8>; 9],
) -> Result<Vec<[Fp; 3]>, Error> {
    if specs.len() != 9 {
        return Err(Error::Artifact);
    }
    let kinds = [
        Some(ObjectKind::Request),
        Some(ObjectKind::Credential),
        Some(ObjectKind::Receipt),
        None,
        None,
        None,
        Some(ObjectKind::Receipt),
        Some(ObjectKind::Credential),
        Some(ObjectKind::Certificate),
    ];
    let mut proof_bytes = frame(&objects[4])?;
    proof_bytes.extend(frame(&objects[5])?);
    let proof_digest = p_bytes_native(u64::from_le_bytes(*b"kgwprf_1"), &proof_bytes);
    specs
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let digest = match kinds[i] {
                Some(kind) => object_digest(kind, &objects[i])?,
                None => match i {
                    3 => p_bytes_native(u64::from_le_bytes(*b"kgwpay_1"), &objects[i]),
                    4 => proof_digest,
                    5 => p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &frame(&objects[i])?),
                    _ => return Err(Error::Input),
                },
            };
            Ok(if matches!(i, 4 | 5) {
                active_context(*spec, digest, &objects[i])?
            } else {
                exact_context(*spec, digest, &objects[i])?
            })
        })
        .collect()
}

fn context_digest(source: &Source) -> Result<Fp, Error> {
    let mut words = source.plan.context().schema().to_vec();
    words.extend(source.own.witness.statement);
    words.extend(source.own.send.statement);
    let before = &source.own.witness.before;
    let after = &source.own.witness.after;
    words.extend(before.core);
    words.extend(before.rest);
    words.extend(before.lineage);
    push_pallas(&mut words, &source.predecessor.pallas.as_input())?;
    words.extend(vesta_words(&source.predecessor.vesta.as_input()));
    words.extend(after.core);
    words.extend(after.rest);
    words.extend(after.lineage);
    words.extend(source.incoming_head.state.lineage);
    words.push(Fp::from(u64::from(source.public_valid)));
    push_pallas(&mut words, &source.incoming_head.pallas.as_input())?;
    words.extend(vesta_words(&source.incoming_head.vesta.as_input()));
    for q in &source.q {
        let types = q
            .plan
            .verifier()
            .binding()
            .descriptor()
            .instance_types
            .as_ref()
            .ok_or(Error::Artifact)?;
        if types.len() != q.instances.len() {
            return Err(Error::Input);
        }
        for (column, ty) in q.instances.iter().zip(types) {
            for value in column {
                if matches!(*ty, InstanceType::Bounded | InstanceType::Bits(0..=253)) {
                    words.push(
                        Option::<Fp>::from(Fp::from_repr(value.to_repr())).ok_or(Error::Input)?,
                    );
                } else {
                    words.extend(foreign_limbs(value).map(Fp::from_u128));
                }
            }
        }
    }
    words.extend(source.commitments.iter().flatten().copied());
    words.extend(source.results.map(|v| Fp::from(u64::from(v))));
    push_pallas(&mut words, &source.incoming_head.opening)?;
    for mode in source.modes {
        words.extend(mode_words(mode));
    }
    for point in source.pallas_corrections {
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<Ep>(&point);
        words.extend([x, y]);
    }
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(&source.vesta_correction);
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    Ok(hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words))
}

fn stage_public(c: &Stage) -> Result<Vec<Fp>, Error> {
    let root = context_digest(&c.source)?;
    let Some(continuation) = &c.continuation else {
        return Ok(internal_public(
            &c.source.vparams,
            stage_digest(c.source.plan.context(), 0, root, &c.pallas)?,
            &c.source.own.part,
        )?);
    };
    if !continuation.plan.is_terminal() {
        let digest = stage_digest(
            c.source.plan.context(),
            continuation.plan.stage(),
            root,
            &c.pallas,
        )?;
        return Ok(internal_public(
            &c.source.vparams,
            digest,
            &continuation.vesta.as_input(),
        )?);
    }
    let mut words = vec![
        terminal_digest(&c.source.own.witness.after.lineage, &c.pallas.as_input())?,
        Fp::from(16),
    ];
    words.extend(vesta_words(&continuation.vesta.as_input()));
    words.extend(vesta_words(&c.source.predecessor.vesta.as_input()));
    words.extend(vesta_words(&c.source.incoming_head.vesta.as_input()));
    words.extend(c.source.mode_words(2));
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(&c.source.vesta_correction);
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    if words.len() != 69 {
        return Err(Error::Input);
    }
    Ok(words)
}
