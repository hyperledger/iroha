//! Native fixed-mask Send A1/W0/A2/W1/A3 composition (lean lineage).
//!
//! A1 binds the actual predecessor Omega and the exact signed tapes, and proves the
//! Send step relation itself from the prepared step witness: balance, ordinals,
//! Request binding, epoch and accepted-time window, chain append and every enabled
//! control. There is no own sigma verifier. A2 inserts Pending and the fee claim and
//! preserves the remaining state. A3 authenticates the own Advance Receipt under the
//! predecessor payment key; the credential and its certificate are carried by
//! continuity. The fixed Tagged3 source profile consumes installed keys, verifies
//! every produced/restored proof and decides every carried opening. The terminal A3
//! is only an input to the final Omega producer. Every mask has an independently
//! installed pipeline whose stage keys fix that mask's relation.
//! TODO: qualify the remaining three masks and complete final Omega catalog.
//! Original PK imports reconstruct the same source with unknown circuit-only
//! witnesses and require exact installed descriptor and verifying-key agreement.

use iroha_plonk::keys::{SourceAdmissionSealV2, SourceBoundViewV2};
#[path = "send/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{CheckpointKind, CheckpointLayout};

use super::artifact::KeyArtifact;
use super::identity::{BoundV1, ProverInstanceV1};
use core::fmt;
use std::sync::Arc;

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, ProverConfig, ProverRandomness, VerifyingKey,
    cs::{
        Column, ConstraintSystem, CurveV1, Instance, InstanceModeV1, InstanceType, ProofSuffixV1,
        TranscriptV2,
    },
    frontend::{Circuit, Error as LayoutError, Layouter, Region, SimpleFloorPlanner, Value},
    keys::pk::artifact::ReadConfig,
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::{
        element::le_message_segments,
        le_value,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    imt::{LeafCells, OpeningCells, PathCells},
    p256::VerifyMode,
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, K,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

use super::super::{
    AProofPlan, LineagePublicCells, ProofMessageCells, VestaClaimCells,
    context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
    own::OwnPolicy,
    schedule::OperationTask,
    send::{
        SendAuthorization, SendAuthorizationObjects, SendInputs, SendObjects, SendStagePlan,
        SendStageWitness,
    },
    split::{SplitPlan, WCircuit, WKey, close_first},
    verify_predecessor,
};
use crate::{
    admin_sigma::StateWitness,
    circuit::{PrefixMode, RelationShape},
    omega::OmegaWitness,
    operation_relation::{
        map_effects::{InsertCells, MapState},
        objects::{ObjectKind, signed_message_native},
        state::StateCells,
        statement::StatementCells,
    },
    q_signature::{QSignaturePlan, SignatureKey},
    tree::IndexedInsert,
    witness::{NativeStep, SigmaRelation, StepWitness},
};

impl Prover {
    /// Bind a previously source-admitted seal to this exact installed A stage.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong stage, descriptor/verifier identity or cooperative cancellation.
    pub fn bind_a<'a>(
        &'a self,
        stage: usize,
        seal: &'a SourceAdmissionSealV2<Eq>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.a.get(stage).ok_or(Error::Artifact)?;
        seal.bind(artifact.binding(), artifact.key(), cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })
    }
    /// Bind a previously source-admitted seal to this exact installed W stage.
    /// This borrows existing metadata and retains no proving polynomials.
    /// # Errors
    /// Wrong stage, descriptor/verifier identity or cooperative cancellation.
    pub fn bind_w<'a>(
        &'a self,
        stage: usize,
        seal: &'a SourceAdmissionSealV2<Ep>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'a, Ep>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.w.get(stage).ok_or(Error::Artifact)?;
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
#[path = "send/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "send/capacity.rs"]
mod capacity;

/// Fixed native source profile; private inputs cannot choose another range-bus count.
pub const SOURCE_RANGE_BUSES: usize = 3;
/// Exact source schedule has three A stages and two W continuations.
pub const A_STAGE_COUNT: usize = 3;
/// Exact fixed wrapper count, ending in terminal A3.
pub const W_STAGE_COUNT: usize = A_STAGE_COUNT - 1;
const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

/// Native preparation/proof failure. No failure changes a monetary head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Original local checkpoint read refusal; no invalid-input or proof verdict completed.
    DecodeResource(norito::core::DecodeLocalRefusal),
    /// Explicit cancellation; no proof failure or burn verdict is produced.
    Cancelled,
    /// Installed descriptor/key/schema or fixed policy differs.
    Artifact,
    /// Original shape, exact tape or source checkpoint differs.
    Input,
    /// Native proof, accumulator or complete decide failed.
    Proof,
    /// Installed circuit assignment or proof production failed.
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
        write!(f, "native Send: {self:?}")
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

/// Exact original Q proof and columns, retained by the source native producer.
#[derive(Clone, Debug)]
pub struct QInput {
    /// Descriptor-sized proof bytes.
    pub proof: Vec<u8>,
    /// Exact descriptor-shaped public columns; never a native acceptance verdict.
    pub instances: Vec<Vec<Fq>>,
}

/// Actual predecessor Omega proof and both canonical transported accumulator originals.
#[derive(Clone, Debug)]
pub struct PredecessorInput {
    /// Unframed, descriptor-sized predecessor Omega proof.
    pub proof: Vec<u8>,
    /// Exact544 canonical Pallas claim bytes.
    pub pallas: [u8; 544],
    /// Exact544 canonical Vesta claim bytes.
    pub vesta: [u8; 544],
}

/// Exact before/after states and own Send statement from the irreversible Advance.
#[derive(Clone, Debug)]
pub struct SendState {
    /// Original committed predecessor state.
    pub before: StateWitness,
    /// Exact successor state retained by Advance.
    pub after: StateWitness,
    /// Exact26-field own Send statement.
    pub statement: [Fp; 26],
}

/// Post-Advance originals for complete native Send lineage composition.
/// The G1 owner authenticates canonical custody objects before producing these typed
/// field transcripts and exact signed-body transcript||signature tapes.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Exact predecessor/successor core29/rest6/public18 and own statement26.
    pub state: SendState,
    /// The prepared Send step witness that A1 proves the relation of.
    pub step: StepWitness<Fp>,
    /// Current Credential, Request, `FeeSchedule` and own Advance Receipt.
    pub objects: [Vec<u8>; 4],
    /// Exact depth32 pending-map insertion checked by A2.
    pub pending: IndexedInsert<Fp>,
    /// Exact depth32 fee-map insertion checked by A2.
    pub fee: IndexedInsert<Fp>,
    /// The own Receipt signature Q.
    pub q: [QInput; 1],
    /// Actual predecessor proof; its key/profile comes from the installed Plan.
    pub predecessor: PredecessorInput,
}

/// Immutable complete Send circuit metadata from the authenticated native artifact owner.
#[derive(Clone, Debug)]
pub struct Plan {
    context: ContextPlan,
    mask: u8,
    policy: OwnPolicy,
    signatures: QSignaturePlan,
    predecessor_key: VerifyingKey<Ep>,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin predecessor and the fixed [[],[],[Q0]] schedule with every Send task on an
    /// inline plan. The one hard signature slot is the own Receipt under the predecessor
    /// payment key. The mask, and with it the proved relation, is fixed by installed keys.
    /// # Errors
    /// Wrong variant/k/schema, absent predecessor or substituted fixed signature/key policy.
    pub fn new(
        operation: AProofPlan,
        mask: u8,
        policy: OwnPolicy,
        signatures: QSignaturePlan,
        predecessor_key: VerifyingKey<Ep>,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        if mask > 3
            || operation.frame().variant() != Variant::Send
            || !operation.is_inline()
            || operation.frame().part_source_k() != 16
            || operation.q_count() != 1
            || !operation.frame().has_predecessor()
        {
            return Err(Error::Artifact);
        }
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
        let slots = signatures.slots();
        if slots.len() != 1
            || slots[0].mode != VerifyMode::Hard
            || slots[0].key != SignatureKey::Variable
        {
            return Err(Error::Artifact);
        }
        let d = operation
            .q(0)
            .ok_or(Error::Artifact)?
            .verifier()
            .binding()
            .descriptor();
        if d.instance_lengths
            != [u32::try_from(signatures.instance_length()).map_err(|_| Error::Artifact)?]
            || d.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        {
            return Err(Error::Artifact);
        }
        // Λ consumes no σ_send, so the predecessor's transport is pinned to the receiver's
        // uniform Ω cap: with any σ_send up to its maximum, the Payment fits the joint
        // budget the receiver's Λ enforces in-circuit.
        if predecessor
            .proof_length()
            .checked_add(1088)
            .is_none_or(|n| n > super::super::receive::OMEGA_TRANSPORT_CAP)
        {
            return Err(Error::Artifact);
        }
        let context = crate::a_relation::schedule::compiled::OperationSchedule::for_variant(
            operation.frame().variant(),
        )
        .bind(
            operation,
            SendStagePlan::context_specs().map_err(|_| Error::Artifact)?,
        )
        .map_err(|_| Error::Artifact)?;
        SendStagePlan::new(context.clone()).map_err(|_| Error::Artifact)?;
        Ok(Self {
            context,
            mask,
            policy,
            signatures,
            predecessor_key,
            pallas,
            vesta,
        })
    }
    /// Complete fixed source-bound context schema.
    #[must_use]
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }
    /// The `σ_send` relation of this installed mask, which A1 proves inline.
    #[must_use]
    pub fn relation(&self) -> SigmaRelation {
        SigmaRelation::send(u32::from(self.mask))
    }
    fn shape(&self) -> RelationShape {
        RelationShape::new(self.relation(), PrefixMode::Absorbed)
    }

    /// Verify the actual predecessor and own-receipt Q proofs and both transported
    /// predecessor claims. Bind the retained signed tapes to their statement/state/Q
    /// exports and evaluate the step witness to the exact own statement, then derive
    /// every Q opening from those checked originals.
    /// # Errors
    /// Wrong tape/length/schema or any native proof/full-accumulator failure.
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
        check_object_tapes(&input, self.policy)?;
        check_mask(&input, self.mask)?;
        // The step witness must evaluate, rule for rule, to the exact statement Advance
        // committed; A1 then proves that relation for this installed mask.
        let relation = self.relation();
        if input.step.relation() != relation.step() || !input.step.canonical_digests() {
            return Err(Error::Input);
        }
        let native = input.step.evaluate(relation);
        if !native.violations.is_empty() || native.statement != input.state.statement {
            return Err(Error::Input);
        }
        let pallas =
            AccumulatorT::<Ep>::from_bytes(&input.predecessor.pallas).map_err(|_| Error::Input)?;
        let vesta =
            AccumulatorT::<Eq>::from_bytes(&input.predecessor.vesta).map_err(|_| Error::Input)?;
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
        let program = self
            .context
            .operation()
            .omega()
            .ok_or(Error::Artifact)?
            .clone();
        let digest = self
            .predecessor_key
            .kagemusha_digest(program.binding())
            .map_err(|_| Error::Artifact)?;
        if input.state.before.lineage[17] != digest {
            return Err(Error::Input);
        }
        let own = terminal_digest(&input.state.before.lineage, &pallas.as_input())?;
        let public = omega_instances(own, &vesta)?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.pallas,
            program.binding(),
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
            program.binding(),
            &self.predecessor_key,
            &public,
            &input.predecessor.proof,
            budget,
            cancellation,
        )?;
        let mut openings = Vec::new();
        for (index, q) in input.q.iter().enumerate() {
            let fixed = self.context.operation().q(index).ok_or(Error::Artifact)?;
            iroha_plonk::verifier::verify_full_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &q.instances,
                &q.proof,
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
            openings.push(opening_pallas_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &q.instances,
                &q.proof,
                budget,
                cancellation,
            )?);
        }
        // No own sigma verifier: the part forwarded to W0 is the pinned trivial claim.
        let part = trivial_vesta_claim()?;
        let maps = Maps {
            witness: input.state,
            pending: input.pending,
            fee: input.fee,
            objects: core::array::from_fn(|i| SignedTape {
                kind: object_kinds()[i],
                bytes: input.objects[i].clone(),
            }),
            known: true,
        };
        let predecessor = Predecessor {
            key: self.predecessor_key.clone(),
            proof: input.predecessor.proof,
            pallas,
            opening,
            vesta,
        };
        let source = Arc::new(Sources {
            maps,
            step: Some((input.step, native)),
            q_instances: input.q.each_ref().map(|q| q.instances.clone()).to_vec(),
            q_proofs: input.q.each_ref().map(|q| q.proof.clone()).to_vec(),
            q_openings: openings,
            signature_schema: self.signatures.clone(),
            part,
            predecessor,
            params: self.pallas.clone(),
            policy: self.policy,
        });
        Ok(Prepared {
            plan: self.clone(),
            source,
        })
    }
}

#[derive(Clone)]
struct Predecessor {
    key: VerifyingKey<Ep>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    opening: FoldInput<Ep>,
    vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
struct Sources {
    maps: Maps,
    /// The prepared step witness and its native evaluation.
    step: Option<(StepWitness<Fp>, NativeStep<Fp>)>,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    q_openings: Vec<FoldInput<Ep>>,
    signature_schema: QSignaturePlan,
    part: FoldInput<Eq>,
    predecessor: Predecessor,
    params: PinnedParams<Ep>,
    policy: OwnPolicy,
}
#[derive(Clone)]
struct SignedTape {
    kind: ObjectKind,
    bytes: Vec<u8>,
}
impl SignedTape {
    fn digest(&self) -> Result<Fp, Error> {
        object_digest(self.kind, &self.bytes)
    }
}
#[derive(Clone)]
struct Maps {
    witness: SendState,
    pending: IndexedInsert<Fp>,
    fee: IndexedInsert<Fp>,
    objects: [SignedTape; 4],
    known: bool,
}
impl Maps {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn state(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        witness: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), LayoutError> {
        let core = chip
            .uint()
            .glue()
            .witnesses(region, &witness.core.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &witness.rest.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        let state = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &witness.lineage.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        let public = LineagePublicCells::constrain(&mut chip.uint(), region, &public)?;
        Ok((state, public))
    }
    fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        insertion: &IndexedInsert<Fp>,
    ) -> Result<InsertCells, LayoutError> {
        let leaf = insertion.leaf;
        let words = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        let leaf = LeafCells::from_words(words);
        let mut paths = Vec::new();
        for (index, siblings) in [
            (insertion.leaf_slot, insertion.leaf_siblings),
            (insertion.slot, insertion.slot_siblings),
        ] {
            let index = uint
                .glue()
                .witness(region, self.value(Fp::from(u64::from(index))))?;
            let siblings = uint
                .glue()
                .witnesses(region, &siblings.map(|v| self.value(v)))?
                .try_into()
                .map_err(|_| LayoutError::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| LayoutError::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells { leaf, path: low },
            slot,
        })
    }
}
#[derive(Clone)]
struct First {
    source: Arc<Sources>,
    shape: RelationShape,
    plan: ContextPlan,
    pallas: AccumulatorT<Ep>,
    fold: crate::private_fold::PrivateFoldBytes,
    known: bool,
}
// Circuit-only witness views. Optional claims become unknown circuit cells;
// none of these types can create Prepared or a verified checkpoint.
#[derive(Clone)]
struct CircuitPredecessor {
    key: VerifyingKey<Ep>,
    proof: Vec<u8>,
    pallas: Option<FoldInput<Ep>>,
    vesta: Option<AccumulatorT<Eq>>,
}
#[derive(Clone)]
struct CircuitSources {
    maps: Maps,
    /// The step witness, absent for a blank source.
    step: Option<(StepWitness<Fp>, NativeStep<Fp>)>,
    /// This mask's relation with absorbed prefixes, fixed by the stage key.
    shape: RelationShape,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    signature_schema: QSignaturePlan,
    predecessor: CircuitPredecessor,
    params: PinnedParams<Ep>,
    policy: OwnPolicy,
}
#[derive(Clone)]
struct FirstCircuit {
    source: Arc<CircuitSources>,
    plan: ContextPlan,
    fold: crate::private_fold::PrivateFoldBytes,
    known: bool,
}
impl First {
    fn circuit(&self) -> FirstCircuit {
        let source = &self.source;
        FirstCircuit {
            source: Arc::new(CircuitSources {
                maps: source.maps.clone(),
                step: source.step.clone(),
                shape: self.shape,
                q_instances: source.q_instances.clone(),
                q_proofs: source.q_proofs.clone(),
                signature_schema: source.signature_schema.clone(),
                predecessor: CircuitPredecessor {
                    key: source.predecessor.key.clone(),
                    proof: source.predecessor.proof.clone(),
                    pallas: Some(source.predecessor.pallas.as_input()),
                    vesta: Some(source.predecessor.vesta.clone()),
                },
                params: source.params.clone(),
                policy: source.policy,
            }),
            plan: self.plan.clone(),
            fold: self.fold.clone(),
            known: self.known,
        }
    }
}
impl FirstCircuit {
    fn blank(plan: &Plan) -> Result<Self, Error> {
        let operation = plan.context.operation();
        let predecessor = operation.omega().ok_or(Error::Artifact)?;
        let state = StateWitness {
            core: [Fp::ZERO; 29],
            rest: [Fp::ZERO; 6],
            lineage: [Fp::ZERO; 18],
        };
        let mut q_instances = Vec::new();
        let mut q_proofs = Vec::new();
        for index in 0..operation.q_count() {
            let q = operation.q(index).ok_or(Error::Artifact)?;
            q_instances.push(
                q.verifier()
                    .binding()
                    .descriptor()
                    .instance_lengths
                    .iter()
                    .map(|length| vec![Fq::ZERO; *length as usize])
                    .collect(),
            );
            q_proofs.push(vec![0; q.verifier().proof_length()]);
        }
        let objects = object_kinds().map(|kind| vec![0; kind.body_len() + 64]);
        let path = IndexedInsert {
            leaf: crate::tree::IndexedLeaf::default(),
            leaf_slot: 0,
            leaf_siblings: [Fp::ZERO; 32],
            slot: 1,
            slot_siblings: [Fp::ZERO; 32],
        };
        let source = CircuitSources {
            maps: Maps {
                witness: SendState {
                    before: state,
                    after: state,
                    statement: [Fp::ZERO; 26],
                },
                pending: path,
                fee: path,
                objects: core::array::from_fn(|i| SignedTape {
                    kind: object_kinds()[i],
                    bytes: objects[i].clone(),
                }),
                known: false,
            },
            step: None,
            shape: plan.shape(),
            q_instances,
            q_proofs,
            signature_schema: plan.signatures.clone(),
            predecessor: CircuitPredecessor {
                key: plan.predecessor_key.clone(),
                proof: vec![0; predecessor.proof_length()],
                pallas: None,
                vesta: None,
            },
            params: plan.pallas.clone(),
            policy: plan.policy,
        };
        Ok(Self {
            source: Arc::new(source),
            plan: plan.context.clone(),
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
            known: false,
        })
    }
}

#[derive(Clone, Debug)]
/// Fixed Tagged3 source columns and exact homogeneous public schema.
pub struct StageConfig {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl FirstCircuit {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn scalar(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        v: Fq,
    ) -> Result<ScalarCells<Ep>, LayoutError> {
        Self::scalar_value(chip, region, self.value(v))
    }
    fn scalar_value(
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
    fn pallas(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: Option<&FoldInput<Ep>>,
    ) -> Result<FoldInputCells<Ep>, LayoutError> {
        let g = chip.witness_generator(
            region,
            input.map_or(Value::unknown(), |v| self.value(Ep::from(*v.g()))),
        )?;
        let challenges = (0..K)
            .map(|i| {
                Self::scalar_value(
                    chip,
                    region,
                    input.map_or(Value::unknown(), |v| self.value(v.challenges()[i])),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        FoldInputCells::from_normalized(chip, region, 16, g, challenges)
    }
    fn vesta(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: Option<&AccumulatorT<Eq>>,
    ) -> Result<VestaClaimCells, LayoutError> {
        let coordinates =
            input.map(|v| iroha_plonk::transcript::generator_coordinates::<Eq>(v.g()));
        let coordinates = [
            Self::scalar_value(
                chip,
                region,
                coordinates.map_or(Value::unknown(), |(x, _)| self.value(x)),
            )?,
            Self::scalar_value(
                chip,
                region,
                coordinates.map_or(Value::unknown(), |(_, y)| self.value(y)),
            )?,
        ];
        let values = core::array::from_fn::<_, K, _>(|i| {
            input.map_or(Value::unknown(), |v| self.value(v.challenges()[i]))
        });
        let challenges = chip
            .uint()
            .glue()
            .witnesses(region, &values)?
            .try_into()
            .map_err(|_| LayoutError::Synthesis)?;
        VestaClaimCells::constrain(chip, region, 16, coordinates, challenges)
    }
    fn carrier(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        body: &[u8],
    ) -> Result<ProofMessageCells, LayoutError> {
        let length = u32::try_from(body.len()).map_err(|_| LayoutError::BoundsFailure)?;
        let source = length
            .to_le_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .map(|v| self.value(v))
            .collect::<Vec<_>>();
        let mut segments = vec![SegmentSpec::little(0, 4)];
        segments.extend(le_message_segments(4, body.len() / 32));
        let run = bytes.run(
            region,
            &source,
            &source
                .chunks(31)
                .map(<[Value<u8>]>::len)
                .collect::<Vec<_>>(),
            &segments,
        )?;
        ProofMessageCells::from_run(chip, region, &run, 0, body.len())
    }
}
impl FirstCircuit {
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<
        (
            SendObjects,
            SendAuthorizationObjects,
            Vec<crate::a_relation::context::ContextObjectCells>,
        ),
        LayoutError,
    > {
        let sources: [Vec<_>; 3] = core::array::from_fn(|i| {
            self.source.maps.objects[i]
                .bytes
                .iter()
                .map(|v| self.value(*v))
                .collect()
        });
        let objects =
            SendObjects::decode(chip, bytes, region, sources.each_ref().map(Vec::as_slice))?;
        let sources: [Vec<_>; 1] = core::array::from_fn(|i| {
            self.source.maps.objects[i + 3]
                .bytes
                .iter()
                .map(|v| self.value(*v))
                .collect()
        });
        let own = SendAuthorizationObjects::decode(
            chip,
            bytes,
            region,
            sources.each_ref().map(Vec::as_slice),
        )?;
        let mut context = objects.context().to_vec();
        context.extend_from_slice(own.context());
        Ok((objects, own, context))
    }
}

impl Circuit<Fp> for FirstCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StageConfig {
        let verifier =
            VerifierConfig::configure_serialized_foreign_tagged(meta, SOURCE_RANGE_BUSES)
                .expect("fixed native Send Tagged3 profile");
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
        let out = layouter.assign_region(
            || "genuine Send predecessor-first relation",
            |mut region| {
                let mut maps = self.source.maps.clone();
                maps.known = self.known;
                let (old, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.before)?;
                let (new, next_public) = maps.state(&mut chip, &mut region, &maps.witness.after)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let (objects, _, context_objects) =
                    self.objects(&mut chip, &mut bytes, &mut region)?;
                let q_instances = self
                    .source
                    .q_instances
                    .iter()
                    .map(|cols| {
                        cols.iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| self.scalar(&mut chip, &mut region, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let pp = self.pallas(
                    &mut chip,
                    &mut region,
                    self.source.predecessor.pallas.as_ref(),
                )?;
                let pv = self.vesta(
                    &mut chip,
                    &mut region,
                    self.source.predecessor.vesta.as_ref(),
                )?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &old,
                        public: &pred_public,
                        pallas: &pp,
                        vesta: &pv,
                    }),
                    successor: ContextState {
                        state: &new,
                        public: &next_public,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: &context_objects,
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let vk = &self.source.predecessor.key;
                let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *vk.transcript_repr()
                else {
                    return Err(LayoutError::Synthesis);
                };
                let fixed = vk
                    .fixed_commitments()
                    .iter()
                    .map(|p| self.value(Ep::from(*p)))
                    .collect::<Vec<_>>();
                let permutation = vk
                    .permutation_commitments()
                    .iter()
                    .map(|p| self.value(Ep::from(*p)))
                    .collect::<Vec<_>>();
                let key = chip.witness_key(&mut region, self.value(repr), &fixed, &permutation)?;
                let proof = self.carrier(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    &self.source.predecessor.proof,
                )?;
                let pred = verify_predecessor(
                    &mut chip,
                    &mut region,
                    self.plan.operation(),
                    &key,
                    &pred_public,
                    &next_public,
                    &pp,
                    &pv,
                    &proof,
                )?;
                // A1: the objects and the step relation itself beside the hard
                // predecessor. Key generation lays out the same relation unknown.
                let witness = self
                    .source
                    .step
                    .as_ref()
                    .filter(|_| self.known)
                    .map(|(step, native)| (step, native));
                SendStagePlan::new(self.plan.clone())?.constrain_stage(
                    &mut chip,
                    &mut region,
                    0,
                    &objects,
                    SendInputs {
                        predecessor: MapState {
                            state: &old,
                            lineage: &pred_public,
                        },
                        successor: MapState {
                            state: &new,
                            lineage: &next_public,
                        },
                        statement: &statement,
                    },
                    SendStageWitness {
                        transition: Some(crate::a_relation::transition::TransitionInputs {
                            shape: self.source.shape,
                            witness,
                        }),
                        ..SendStageWitness::default()
                    },
                )?;
                if self.plan.first_q_count() != 0 {
                    return Err(LayoutError::Synthesis);
                }
                let fold = self.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                let first = close_first(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    Some(&pred),
                    &[],
                    &[],
                    Some(&fold),
                    &self.source.params,
                )?;
                first.words(&mut chip, &mut region)
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Continuation {
    first: First,
    plan: crate::a_relation::split::SplitPlan,
    wrapper: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    fold: crate::private_fold::PrivateFoldBytes,
    pallas: AccumulatorT<Ep>,
    carried: AccumulatorT<Ep>,
}

#[derive(Clone)]
struct ContinuationCircuit {
    first: FirstCircuit,
    plan: SplitPlan,
    wrapper: Vec<u8>,
    vesta: Option<AccumulatorT<Eq>>,
    fold: crate::private_fold::PrivateFoldBytes,
    carried: Option<FoldInput<Ep>>,
}
impl Continuation {
    fn circuit(&self) -> ContinuationCircuit {
        ContinuationCircuit {
            first: self.first.circuit(),
            plan: self.plan.clone(),
            wrapper: self.wrapper.clone(),
            vesta: Some(self.vesta.clone()),
            fold: self.fold.clone(),
            carried: Some(self.carried.as_input()),
        }
    }
}
impl ContinuationCircuit {
    fn blank(first: FirstCircuit, plan: SplitPlan) -> Result<Self, Error> {
        if !(1..A_STAGE_COUNT).contains(&plan.stage()) {
            return Err(Error::Artifact);
        }
        Ok(Self {
            first,
            wrapper: vec![0; plan.wrap().verifier().proof_length()],
            vesta: None,
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
            carried: None,

            plan,
        })
    }
}
impl Circuit<Fp> for ContinuationCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            first: self.first.without_witnesses(),
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StageConfig {
        FirstCircuit::configure(meta)
    }
    fn synthesize(
        &self,
        config: StageConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), LayoutError> {
        let first = &self.first;
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "Send deferred Q continuation",
            |mut region| {
                let mut maps = first.source.maps.clone();
                maps.known = first.known;
                let (old, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.before)?;
                let (new, next_public) = maps.state(&mut chip, &mut region, &maps.witness.after)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| first.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let (objects, auth_objects, context_objects) =
                    first.objects(&mut chip, &mut bytes, &mut region)?;
                let q_instances = first
                    .source
                    .q_instances
                    .iter()
                    .map(|cols| {
                        cols.iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| first.scalar(&mut chip, &mut region, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let pp = first.pallas(
                    &mut chip,
                    &mut region,
                    first.source.predecessor.pallas.as_ref(),
                )?;
                let pv = first.vesta(
                    &mut chip,
                    &mut region,
                    first.source.predecessor.vesta.as_ref(),
                )?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &old,
                        public: &pred_public,
                        pallas: &pp,
                        vesta: &pv,
                    }),
                    successor: ContextState {
                        state: &new,
                        public: &next_public,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: &context_objects,
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let cp = first.pallas(&mut chip, &mut region, self.carried.as_ref())?;
                let cv = first.vesta(&mut chip, &mut region, self.vesta.as_ref())?;
                let proof = first.carrier(&mut chip, &mut bytes, &mut region, &self.wrapper)?;
                let resumed = crate::a_relation::split::resume_context(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    &cp,
                    &cv,
                    &proof,
                    &[],
                )?;
                let mut verified = Vec::new();
                for index in first
                    .plan
                    .q_partition(self.plan.stage())
                    .ok_or(LayoutError::Synthesis)?
                    .iter()
                    .copied()
                {
                    let columns = &q_instances[index];
                    let proof = first.carrier(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &first.source.q_proofs[index],
                    )?;
                    let q = {
                        let q = crate::a_relation::verify_q(
                            &mut chip,
                            &mut region,
                            first.plan.operation(),
                            index,
                            columns,
                            &proof,
                        )?;
                        let slots = crate::a_relation::bind_signature_q(
                            &mut chip,
                            &mut region,
                            first.plan.operation(),
                            index,
                            &first.source.signature_schema,
                            &q,
                        )?;
                        SendStagePlan::new(first.plan.clone())?.constrain_stage(
                            &mut chip,
                            &mut region,
                            self.plan.stage(),
                            &objects,
                            SendInputs {
                                predecessor: MapState {
                                    state: &old,
                                    lineage: &pred_public,
                                },
                                successor: MapState {
                                    state: &new,
                                    lineage: &next_public,
                                },
                                statement: &statement,
                            },
                            SendStageWitness {
                                authorization: Some(SendAuthorization {
                                    objects: &auth_objects,
                                    policy: first.source.policy,
                                    signature: crate::a_relation::SignatureQContext {
                                        bundle: &slots,
                                        instances: columns,
                                    },
                                }),
                                ..SendStageWitness::default()
                            },
                        )?;
                        slots.verified().clone()
                    };
                    verified.push(q);
                }
                // A stage without the own receipt Q is the map stage.
                if !first
                    .plan
                    .q_partition(self.plan.stage())
                    .ok_or(LayoutError::Synthesis)?
                    .contains(&0)
                {
                    let tasks = first
                        .plan
                        .operation_tasks(self.plan.stage())
                        .ok_or(LayoutError::Synthesis)?;
                    let pending = if tasks.contains(&OperationTask::SendPending) {
                        Some(maps.insertion(&mut chip.uint(), &mut region, &maps.pending)?)
                    } else {
                        None
                    };
                    let fee = if tasks.contains(&OperationTask::SendFeeAndCarry) {
                        Some(maps.insertion(&mut chip.uint(), &mut region, &maps.fee)?)
                    } else {
                        None
                    };
                    SendStagePlan::new(first.plan.clone())?.constrain_stage(
                        &mut chip,
                        &mut region,
                        self.plan.stage(),
                        &objects,
                        SendInputs {
                            predecessor: MapState {
                                state: &old,
                                lineage: &pred_public,
                            },
                            successor: MapState {
                                state: &new,
                                lineage: &next_public,
                            },
                            statement: &statement,
                        },
                        SendStageWitness {
                            pending: pending.as_ref(),
                            fee: fee.as_ref(),
                            ..SendStageWitness::default()
                        },
                    )?;
                }
                let fold = first.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                let closed = crate::a_relation::split::close_stage(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &resumed,
                    None,
                    None,
                    None,
                    &verified,
                    &fold,
                )?;
                if self.plan.is_terminal() {
                    closed.words(&mut chip, &mut region, &next_public)
                } else {
                    closed.continuation()?.words(&mut chip, &mut region)
                }
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
enum StageData {
    First(Box<FirstCircuit>),
    Continued(Box<ContinuationCircuit>),
}
/// Actual fixed source A circuit. Its private stage is selected by native checkpoint order.
#[derive(Clone)]
pub struct StageCircuit {
    inner: StageData,
}
impl Circuit<Fp> for StageCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            inner: match &self.inner {
                StageData::First(c) => StageData::First(Box::new(c.without_witnesses())),
                StageData::Continued(c) => StageData::Continued(Box::new(c.without_witnesses())),
            },
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StageConfig {
        FirstCircuit::configure(meta)
    }
    fn synthesize(
        &self,
        config: StageConfig,
        layouter: impl Layouter<Fp>,
    ) -> Result<(), LayoutError> {
        match &self.inner {
            StageData::First(c) => c.synthesize(config, layouter),
            StageData::Continued(c) => c.synthesize(config, layouter),
        }
    }
}

/// Checked original source coupled to the fixed complete Send plan.
#[derive(Clone)]
pub struct Prepared {
    plan: Plan,
    source: Arc<Sources>,
}
impl Prepared {
    fn first(
        &self,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<First, Error> {
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
        Ok(First {
            source: self.source.clone(),
            shape: self.plan.shape(),
            plan: self.plan.context.clone(),
            pallas,
            fold: crate::private_fold::PrivateFoldBytes::from_fold(fold),
            known: true,
        })
    }
    /// Build the actual A1 relation and exact public frame from checked originals.
    /// The tape randomizes an actual fold; it does not choose a profile or obligation list.
    /// # Errors
    /// A failed exact predecessor two-input fold or complete decide.
    pub fn first_circuit(
        &self,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>), Error> {
        let first = self.first(tape, config)?;
        let public = first_public(&first)?;
        Ok((
            StageCircuit {
                inner: StageData::First(Box::new(first.circuit())),
            },
            public,
        ))
    }
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

/// Fixed Send verifier metadata with no retained proving polynomials or PK bytes.
/// Installation authenticates the plan and verifier identities independently;
/// metadata consistency alone grants no source/catalog or wallet-open authority.
/// TODO(G3/G4): connect the complete authenticated producer catalog and original
/// G1 preparation before enabling the Native wallet owner.
/// A clone is another prover instance: it cannot resume the original's sessions.
#[derive(Clone)]
pub struct Prover {
    plan: Plan,
    a: [KeyArtifact<Eq>; A_STAGE_COUNT],
    w: [KeyArtifact<Ep>; A_STAGE_COUNT - 1],
    wrappers: [WKey; A_STAGE_COUNT - 1],
    // Process-local instance identity; only this instance resumes its sessions.
    identity: ProverInstanceV1,
}
impl Prover {
    /// Install all fixed A/W verifier identities without retaining any PK.
    ///
    /// The native owner authenticates the complete scheme/provider/root, predecessor,
    /// Q keys, signature slots and compiled-source catalog independently of inputs.
    /// Per-stage imports reconstruct exact unknown sources and validate original
    /// tables and commitments; proving borrows only one key and checks its identity
    /// before any proof or fold. Metadata matching alone is not source authority.
    /// # Errors
    /// Wrong profile, curve, public schema or installed source descriptor.
    pub fn from_artifacts(
        plan: Plan,
        a: [KeyArtifact<Eq>; A_STAGE_COUNT],
        w: [KeyArtifact<Ep>; A_STAGE_COUNT - 1],
    ) -> Result<Self, Error> {
        let expected =
            super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?;
        for artifact in &a {
            artifact_metadata(artifact, CurveV1::Vesta, &[69], &[InstanceType::Bounded])?;
            if artifact.binding() != &expected {
                return Err(Error::Artifact);
            }
        }
        let mut wrappers = Vec::with_capacity(w.len());
        for (stage, artifact) in w.iter().enumerate() {
            artifact_metadata(
                artifact,
                CurveV1::Pallas,
                &[1, 2, 16],
                &crate::omega::OmegaPlan::instance_types(),
            )?;
            wrappers.push(
                WKey::from_artifact(
                    &plan.context,
                    stage,
                    artifact.binding().clone(),
                    plan.pallas.clone(),
                    artifact.key().clone(),
                )
                .map_err(|_| Error::Artifact)?,
            );
        }
        Ok(Self {
            plan,
            a,
            w,
            wrappers: wrappers.try_into().map_err(|_| Error::Artifact)?,
            identity: ProverInstanceV1::fresh(),
        })
    }
    /// Import one A original against the exact installed stage and preceding W identity.
    /// This uses unknown source inputs, never creates accepted claims, and returns
    /// a compact source-admission seal without constructing proving FFTs or masks.
    /// # Errors
    /// Wrong stage/cap, changed source/table/commitments or full installed-key mismatch.
    pub fn import_a(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_a_cancellable(stage, original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_a_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_a_with_admission_cancellable(
            stage,
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
    pub fn import_a_builtin_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        member: iroha_plonk::keys::BuiltinSourceMemberV1,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_a_with_admission_cancellable(
            stage,
            original,
            config,
            crate::original_admission::OriginalAdmission::Builtin(member),
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn import_a_with_admission_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.a.get(stage).ok_or(Error::Artifact)?;
        original_bounds(original, artifact.binding().n(), config)?;
        let circuit = self.plan.source_circuit(
            stage,
            stage
                .checked_sub(1)
                .map(|previous| self.wrappers[previous].clone()),
        )?;
        let key = admission
            .admit(
                original,
                artifact.binding(),
                artifact.key(),
                &self.plan.vesta,
                &circuit,
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
        artifact
            .require_source_bound(&key.view())
            .map_err(|_| Error::Artifact)?;
        let (_, _, seal) = key.into_parts();
        Ok(seal)
    }
    /// Import one W original bound to the preceding installed A descriptor and full VK.
    /// The returned seal retains no original bytes, descriptor, verifier copy or proving buffers.
    /// # Errors
    /// Wrong stage/cap, changed source/table/commitments or full installed-key mismatch.
    pub fn import_w(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        self.import_w_cancellable(stage, original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_w_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        self.import_w_with_admission_cancellable(
            stage,
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
    pub fn import_w_builtin_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        member: iroha_plonk::keys::BuiltinSourceMemberV1,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        self.import_w_with_admission_cancellable(
            stage,
            original,
            config,
            crate::original_admission::OriginalAdmission::Builtin(member),
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn import_w_with_admission_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        admission: crate::original_admission::OriginalAdmission,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.w.get(stage).ok_or(Error::Artifact)?;
        original_bounds(original, artifact.binding().n(), config)?;
        let a = &self.a[stage];
        let source = self.plan.wrapper_source(stage, a.binding(), a.key())?;
        let key = admission
            .admit(
                original,
                artifact.binding(),
                artifact.key(),
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
        artifact
            .require_source_bound(&key.view())
            .map_err(|_| Error::Artifact)?;
        let (_, _, seal) = key.into_parts();
        Ok(seal)
    }
    /// Check all original proofs/tapes and create a session using only installed artifacts.
    /// # Errors
    /// Any predecessor/Q proof, transported decide or same-tape mismatch.
    pub fn prepare(&self, input: Inputs, budget: MemoryBudget) -> Result<Session<'_>, Error> {
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
    ) -> Result<Session<'_>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        Ok(Session {
            prover: self,
            prepared: self.plan.prepare_cancellable(input, budget, cancellation)?,
        })
    }
    /// Resume a session retained from this exact prover instance.
    ///
    /// Nothing is re-read or re-verified: `prepare` on this instance verified the
    /// retained preparation. Checkpoints that session produced or restored stay
    /// bound to the same source; every later durable entry must still be restored
    /// strictly from its bytes.
    /// # Errors
    /// `Error::Input` when the state was retained from another prover instance,
    /// including a clone or an identically installed one; the state is dropped.
    pub fn resume(&self, retained: RetainedSession) -> Result<Session<'_>, Error> {
        let prepared = self.identity.admit(retained.0).map_err(|_| Error::Input)?;
        Ok(Session {
            prover: self,
            prepared,
        })
    }
    /// Exact installed descriptors in actual A1/W0/A2/W1/A3 checkpoint order.
    #[must_use]
    pub fn descriptors(&self) -> [&DescriptorBinding; A_STAGE_COUNT * 2 - 1] {
        core::array::from_fn(|index| {
            if index % 2 == 0 {
                self.a[index / 2].binding()
            } else {
                self.w[index / 2].binding()
            }
        })
    }
}

impl Plan {
    /// Reconstruct one compiled unknown A source for sequential offline tooling.
    /// A1 takes no wrapper; every continuation pins its immediately preceding W.
    /// This creates no prepared operation, accepted claim or monetary authority.
    /// # Errors
    /// Out-of-range stage, missing/extra wrapper or wrong fixed stage/context.
    pub fn source_circuit(
        &self,
        stage: usize,
        previous: Option<WKey>,
    ) -> Result<StageCircuit, Error> {
        if stage >= self.context.stage_count() || (stage == 0) != previous.is_none() {
            return Err(Error::Artifact);
        }
        let first = FirstCircuit::blank(self)?;
        Ok(if stage == 0 {
            StageCircuit {
                inner: StageData::First(Box::new(first)),
            }
        } else {
            let split = SplitPlan::new(
                self.context.clone(),
                stage,
                previous.ok_or(Error::Artifact)?,
                &self.pallas,
            )
            .map_err(|_| Error::Artifact)?;
            StageCircuit {
                inner: StageData::Continued(Box::new(ContinuationCircuit::blank(first, split)?)),
            }
        })
    }

    /// Reconstruct the unknown W source bound to this stage's exact A verifier.
    /// The strict original importer uses this same source factory.
    /// # Errors
    /// Terminal/out-of-range stage, foreign source profile or invalid A verifier.
    pub fn wrapper_source(
        &self,
        stage: usize,
        binding: &DescriptorBinding,
        key: &VerifyingKey<Eq>,
    ) -> Result<WCircuit, Error> {
        if stage >= self.context.stage_count().saturating_sub(1)
            || binding
                != &super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?
        {
            return Err(Error::Artifact);
        }
        wrapper_source(self, stage, binding, key)
    }
}

fn wrapper_source(
    plan: &Plan,
    stage: usize,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
) -> Result<WCircuit, Error> {
    let allowed = key.kagemusha_digest(binding).map_err(|_| Error::Artifact)?;
    let length = iroha_plonk::Protocol::new(binding.descriptor())
        .map_err(|_| Error::Artifact)?
        .proof_length();
    WCircuit::new(
        &plan.context,
        stage,
        binding.clone(),
        plan.vesta.clone(),
        vec![allowed],
        OmegaWitness {
            key: key.clone(),
            instances: vec![Fp::ZERO; 69],
            proof: vec![0; length],
            length: u32::try_from(length).map_err(|_| Error::Artifact)?,
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
        },
    )
    .map(|source| source.without_witnesses())
    .map_err(|_| Error::Artifact)
}

/// Source-bound session over the fixed installed Send artifacts.
pub struct Session<'a> {
    prover: &'a Prover,
    prepared: Prepared,
}

/// A Send session's verified preparation, detached between fold calls.
///
/// Only `Session::into_retained` creates one, and only `Prover::resume` on the
/// prover instance that prepared it consumes it. It is move-only, process-local
/// and never serialized or built from bytes. It holds the checked originals and
/// the source identity that the session's checkpoints carry, but no proving key,
/// original-store handle or durable checkpoint.
pub struct RetainedSession(BoundV1<Prepared>);

impl Session<'_> {
    fn require_source(&self, source: &ACheckpoint) -> Result<(), Error> {
        if source.stage >= A_STAGE_COUNT
            || !Arc::ptr_eq(&source.first.source, &self.prepared.source)
        {
            return Err(Error::Input);
        }
        Ok(())
    }

    /// Detach this session's verified preparation so a later fold call can resume
    /// it on the same prover instance instead of preparing again. Checkpoints this
    /// session produced or restored remain usable by the resumed session.
    #[must_use]
    pub fn into_retained(self) -> RetainedSession {
        RetainedSession(self.prover.identity.bind(self.prepared))
    }

    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    fn verify_a_cancellable(
        &self,
        source: &ACheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.require_source(source)?;
        let key = &self.prover.a[source.stage];
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
            std::slice::from_ref(&source.public),
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
        source
            .pallas
            .decide_cancellable(&self.prepared.plan.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        source
            .part
            .decide_cancellable(&self.prepared.plan.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        source
            .opening
            .decide_cancellable(&self.prepared.plan.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })
    }
    /// Prove A1 under its installed key, retaining the exact predecessor fold and opening.
    /// # Errors
    /// Fixed artifact/circuit mismatch, failed fold, proof or complete decide.
    pub fn first(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        fold: &FoldConfig,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<ACheckpoint, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        self.prover.a[0]
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        let first = self.prepared.first(tape, fold)?;
        let public = first_public(&first)?;
        let circuit = StageCircuit {
            inner: StageData::First(Box::new(first.circuit())),
        };
        let (proof, opening) = prove_a(
            &self.prepared.plan,
            key,
            &circuit,
            &public,
            randomness,
            config,
            fold.kernel_budget,
        )?;
        Ok(ACheckpoint {
            stage: 0,
            first: first.clone(),
            public,
            proof,
            pallas: first.pallas.clone(),
            part: first.source.part.clone(),

            opening,
        })
    }
    /// Restore A1 from original proof and exact544 carried Pallas bytes.
    /// Derive the expected frame from this session's original objects/Q/predecessor.
    /// # Errors
    /// Noncanonical/mismatching claim, changed source context, wrong proof or failed decide.
    pub fn restore_first(
        &self,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
    ) -> Result<ACheckpoint, Error> {
        self.restore_first_cancellable(proof, pallas, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_first_cancellable(
        &self,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ACheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let pallas = AccumulatorT::<Ep>::from_bytes(pallas).map_err(|_| Error::Input)?;
        pallas
            .decide_cancellable(&self.prepared.plan.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let first = First {
            source: self.prepared.source.clone(),
            shape: self.prepared.plan.shape(),
            plan: self.prepared.plan.context.clone(),
            pallas: pallas.clone(),
            fold: crate::private_fold::PrivateFoldBytes::unknown(),
            known: true,
        };
        let public = first_public(&first)?;
        let key = &self.prover.a[0];
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
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
        let opening = opening_vesta_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
            std::slice::from_ref(&public),
            &proof,
            budget,
            cancellation,
        )?;
        Ok(ACheckpoint {
            stage: 0,
            first,
            public,
            proof,
            pallas,
            part: self.prepared.source.part.clone(),

            opening,
        })
    }
    /// Prove the one fixed W continuation for a nonterminal A checkpoint.
    /// Its four Vesta slots are source part, actual A opening, and two explicit trivial16.
    /// # Errors
    /// Terminal/wrong-source checkpoint, artifact/circuit mismatch or any failed full proof.
    pub fn wrapper(
        &self,
        source: &ACheckpoint,
        key: &SourceBoundViewV2<'_, Ep>,
        tape: iroha_plonk_recursion::FoldTape<Eq>,
        fold: &FoldConfig,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<WCheckpoint, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        self.prover
            .w
            .get(source.stage)
            .ok_or(Error::Input)?
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.verify_a_cancellable(source, fold.kernel_budget, config.cancellation)?;
        if source.stage >= A_STAGE_COUNT - 1 {
            return Err(Error::Input);
        }
        let a = &self.prover.a[source.stage];
        let (vfold, vesta) = crate::private_fold::wrapper(
            &self.prepared.plan.vesta,
            a.binding(),
            a.key(),
            std::slice::from_ref(&source.public),
            &source.proof,
            tape,
            fold,
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
                &self.prepared.plan.vesta,
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
        let a = &self.prover.a[source.stage];
        let allowed = a
            .key()
            .kagemusha_digest(a.binding())
            .map_err(|_| Error::Artifact)?;
        let circuit = WCircuit::new(
            &self.prepared.plan.context,
            source.stage,
            a.binding().clone(),
            self.prepared.plan.vesta.clone(),
            vec![allowed],
            OmegaWitness {
                key: a.key().clone(),
                instances: source.public.clone(),
                proof: source.proof.clone(),
                length: u32::try_from(source.proof.len()).map_err(|_| Error::Input)?,
                fold: crate::private_fold::PrivateFoldBytes::from_fold(vfold),
            },
        )
        .map_err(|_| Error::Input)?;
        let public = omega_instances(source.public[0], &vesta)?;
        let w = key;
        let output = super::proving::prove(
            &self.prepared.plan.pallas,
            w,
            &circuit,
            &public,
            randomness,
            config,
        )?;
        self.restore_wrapper_cancellable(
            source,
            output.proof,
            &vesta.to_bytes(),
            fold.kernel_budget,
            config.cancellation,
        )
    }
    /// Restore the exact W proof and canonical Vesta obligation for the source A checkpoint.
    /// # Errors
    /// Terminal/wrong source, wrong W public frame or any failed proof/full claim decide.
    pub fn restore_wrapper(
        &self,
        source: &ACheckpoint,
        proof: Vec<u8>,
        vesta: &[u8],
        budget: MemoryBudget,
    ) -> Result<WCheckpoint, Error> {
        self.restore_wrapper_cancellable(source, proof, vesta, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_wrapper_cancellable(
        &self,
        source: &ACheckpoint,
        proof: Vec<u8>,
        vesta: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<WCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.verify_a_cancellable(source, budget, cancellation)?;
        if source.stage >= A_STAGE_COUNT - 1 {
            return Err(Error::Input);
        }
        let vesta = AccumulatorT::<Eq>::from_bytes(vesta).map_err(|_| Error::Input)?;
        vesta
            .decide_cancellable(&self.prepared.plan.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let public = omega_instances(source.public[0], &vesta)?;
        let w = &self.prover.w[source.stage];
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.pallas,
            w.binding(),
            w.key(),
            &public,
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
        let opening = opening_pallas_cancellable(
            &self.prepared.plan.pallas,
            w.binding(),
            w.key(),
            &public,
            &proof,
            budget,
            cancellation,
        )?;
        Ok(WCheckpoint {
            source: source.clone(),
            proof,
            vesta,
            opening,
        })
    }
    fn continuation(
        &self,
        wrapper: &WCheckpoint,
        pallas: AccumulatorT<Ep>,
        fold: crate::private_fold::PrivateFoldBytes,
    ) -> Result<Continuation, Error> {
        self.require_source(&wrapper.source)?;
        let previous = wrapper.source.stage;
        if previous >= A_STAGE_COUNT - 1 {
            return Err(Error::Input);
        }
        let split = SplitPlan::new(
            self.prepared.plan.context.clone(),
            previous + 1,
            self.prover.wrappers[previous].clone(),
            &self.prepared.plan.pallas,
        )
        .map_err(|_| Error::Artifact)?;
        Ok(Continuation {
            first: wrapper.source.first.clone(),
            plan: split,
            wrapper: wrapper.proof.clone(),
            vesta: wrapper.vesta.clone(),
            fold,
            pallas,
            carried: wrapper.source.pallas.clone(),
        })
    }
    /// Prove the next A stage using its installed key and all required Pallas slots.
    /// Ordered slots are previous carried P, actual W opening, and that stage's actual Q.
    /// # Errors
    /// Wrong source/stage, omitted obligation, circuit mismatch or any failed full proof.
    pub fn advance(
        &self,
        wrapper: &WCheckpoint,
        key: &SourceBoundViewV2<'_, Eq>,
        tape: iroha_plonk_recursion::FoldTape<Ep>,
        fold: &FoldConfig,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<ACheckpoint, Error> {
        let cancellation = config.cancellation.or(fold.cancellation.as_ref());
        let config = ProverConfig {
            cancellation,
            ..config
        };
        let mut normalized_fold = fold.clone();
        normalized_fold.cancellation = cancellation.cloned();
        let fold = &normalized_fold;

        let next = wrapper.source.stage.checked_add(1).ok_or(Error::Input)?;
        self.prover
            .a
            .get(next)
            .ok_or(Error::Input)?
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        let restored = self.restore_wrapper_cancellable(
            &wrapper.source,
            wrapper.proof.clone(),
            &wrapper.vesta.to_bytes(),
            fold.kernel_budget,
            config.cancellation,
        )?;
        let next = restored.source.stage + 1;
        let indices = self
            .prepared
            .plan
            .context
            .q_partition(next)
            .ok_or(Error::Artifact)?;
        let mut claims = vec![restored.source.pallas.as_input(), restored.opening.clone()];
        claims.extend(
            indices
                .iter()
                .map(|i| self.prepared.source.q_openings[*i].clone()),
        );
        let purpose = if next + 1 == A_STAGE_COUNT {
            crate::private_fold::terminal_inputs(&self.prepared.plan.pallas, &mut claims, fold)
                .map_err(|error| {
                    if error.is_cancelled() {
                        Error::Cancelled
                    } else {
                        Error::Proof
                    }
                })?
        } else {
            iroha_plonk_recursion::FoldPurpose::AContinuation
        };
        let (pfold, pallas) = create_fold(&self.prepared.plan.pallas, &claims, tape, purpose, fold)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        pallas
            .decide_cancellable(
                &self.prepared.plan.pallas,
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
        let continuation = self.continuation(
            &restored,
            pallas.clone(),
            crate::private_fold::PrivateFoldBytes::from_fold(pfold),
        )?;
        let public = continuation_public(&continuation)?;
        let circuit = StageCircuit {
            inner: StageData::Continued(Box::new(continuation.circuit())),
        };
        let (proof, opening) = prove_a(
            &self.prepared.plan,
            key,
            &circuit,
            &public,
            randomness,
            config,
            fold.kernel_budget,
        )?;
        Ok(ACheckpoint {
            stage: next,
            first: restored.source.first,
            public,
            proof,
            pallas,
            part: restored.vesta.as_input(),
            opening,
        })
    }
    /// Restore A2/A3 from its verified source W and canonical new Pallas claim.
    /// Every context/public field is derived from the retained source chain.
    /// # Errors
    /// Canonical claim, source/context, installed key, proof or complete decide mismatch.
    pub fn restore_a(
        &self,
        wrapper: &WCheckpoint,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
    ) -> Result<ACheckpoint, Error> {
        self.restore_a_cancellable(wrapper, proof, pallas, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_a_cancellable(
        &self,
        wrapper: &WCheckpoint,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ACheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let restored = self.restore_wrapper_cancellable(
            &wrapper.source,
            wrapper.proof.clone(),
            &wrapper.vesta.to_bytes(),
            budget,
            cancellation,
        )?;
        let pallas = AccumulatorT::<Ep>::from_bytes(pallas).map_err(|_| Error::Input)?;
        pallas
            .decide_cancellable(&self.prepared.plan.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let continuation = self.continuation(
            &restored,
            pallas.clone(),
            crate::private_fold::PrivateFoldBytes::unknown(),
        )?;
        let public = continuation_public(&continuation)?;
        let next = restored.source.stage + 1;
        let key = &self.prover.a[next];
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
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
        let opening = opening_vesta_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
            std::slice::from_ref(&public),
            &proof,
            budget,
            cancellation,
        )?;
        Ok(ACheckpoint {
            stage: next,
            first: restored.source.first,
            public,
            proof,
            pallas,
            part: restored.vesta.as_input(),
            opening,
        })
    }
    /// Export A3 and all distinct final Omega obligations after another full native check.
    /// This grants neither monetary completion nor a final transported Omega.
    /// # Errors
    /// A nonterminal/wrong source checkpoint or any failed native proof/decide.
    pub fn terminal(&self, source: &ACheckpoint, budget: MemoryBudget) -> Result<Terminal, Error> {
        self.terminal_cancellable(source, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn terminal_cancellable(
        &self,
        source: &ACheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.verify_a_cancellable(source, budget, cancellation)?;
        if source.stage != A_STAGE_COUNT - 1 {
            return Err(Error::Input);
        }
        if source.part.source_k() != 16 {
            return Err(Error::Input);
        }
        let vesta = AccumulatorT::<Eq>::new(*source.part.g(), *source.part.challenges())
            .map_err(|_| Error::Input)?;
        Ok(Terminal {
            proof: source.proof.clone(),
            instances: source.public.clone(),
            pallas: source.pallas.clone(),
            vesta_part: vesta,
            predecessor_vesta: self.prepared.source.predecessor.vesta.clone(),
            opening: source.opening.clone(),
        })
    }
}

/// A fully verified source-bound A checkpoint; ordinal/context/claims are private.
#[derive(Clone)]
pub struct ACheckpoint {
    stage: usize,
    first: First,
    public: Vec<Fp>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    part: FoldInput<Eq>,
    opening: FoldInput<Eq>,
}
impl ACheckpoint {
    /// Zero-based A ordinal, fixed by the native continuation chain.
    #[must_use]
    pub const fn stage(&self) -> usize {
        self.stage
    }
    /// Exact original proof for immutable custody.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    /// Exact69-word native public frame.
    #[must_use]
    pub fn instances(&self) -> &[Fp] {
        &self.public
    }
    /// Exact canonical carried Pallas claim for restoration.
    #[must_use]
    pub fn pallas_bytes(&self) -> [u8; 544] {
        self.pallas.to_bytes()
    }
}
/// Fully verified internal W checkpoint bound to its exact source A/context.
#[derive(Clone)]
pub struct WCheckpoint {
    source: ACheckpoint,
    proof: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    opening: FoldInput<Ep>,
}
impl WCheckpoint {
    /// Zero-based W ordinal in the fixed source schedule.
    #[must_use]
    pub const fn stage(&self) -> usize {
        self.source.stage
    }
    /// Exact original W proof for custody.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    /// Exact canonical deciding Vesta claim for restoration.
    #[must_use]
    pub fn vesta_bytes(&self) -> [u8; 544] {
        self.vesta.to_bytes()
    }
}
/// Actual A3 proof and every distinct obligation consumed by the final Omega producer.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// Original terminal A3 proof under its installed key.
    pub proof: Vec<u8>,
    /// Exact homogeneous69-word public frame.
    pub instances: Vec<Fp>,
    /// Full accumulated Pallas claim.
    pub pallas: AccumulatorT<Ep>,
    /// Full Vesta part forwarded by W1.
    pub vesta_part: AccumulatorT<Eq>,
    /// Full predecessor Vesta obligation, distinct from the current part and A opening.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Actual terminal A3 own opening, a separate final Omega slot.
    pub opening: FoldInput<Eq>,
}

fn object_kinds() -> [ObjectKind; 4] {
    [
        ObjectKind::Credential,
        ObjectKind::Request,
        ObjectKind::FeeSchedule,
        ObjectKind::Receipt,
    ]
}

// Mirror the SendObjects/SendAuthorizationObjects same-tape bindings before admitting
// retained originals. These comparisons do not authenticate Q: prepare still verifies
// the fixed Q proof and every predecessor obligation. Semantic predicates, the step
// relation and map effects remain enforced by the circuits.
fn check_object_tapes(input: &Inputs, policy: OwnPolicy) -> Result<(), Error> {
    use crate::{operation_relation::state::rest_index, witness::core_index};

    for (kind, raw) in object_kinds().into_iter().zip(&input.objects) {
        if raw.len() != kind.body_len() + 64 {
            return Err(Error::Input);
        }
    }
    let [credential, request, fee, receipt] = &input.objects;
    let statement = &input.state.statement;
    let before = &input.state.before;
    let after = &input.state.after;
    // All offsets below are the fixed body schemas in objects/schema.rs.
    let le = |raw: &[u8], start: usize, len: usize| -> Result<Fp, Error> {
        let bytes = raw.get(start..start + len).ok_or(Error::Input)?;
        let mut repr = [0; 32];
        repr.get_mut(..len)
            .ok_or(Error::Input)?
            .copy_from_slice(bytes);
        Option::<Fp>::from(Fp::from_repr(repr)).ok_or(Error::Input)
    };
    let key = |raw: &[u8], start: usize| -> Result<[Fp; 4], Error> {
        if raw.get(start) != Some(&4) {
            return Err(Error::Input);
        }
        [17, 1, 49, 33]
            .map(|offset| {
                let bytes = raw
                    .get(start + offset..start + offset + 16)
                    .ok_or(Error::Input)?;
                Ok(Fp::from_u128(u128::from_be_bytes(
                    bytes.try_into().map_err(|_| Error::Input)?,
                )))
            })
            .into_iter()
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Input)
    };
    for raw in [credential, request, receipt] {
        if raw[..2] != 1_u16.to_le_bytes() {
            return Err(Error::Input);
        }
    }
    let current = object_digest(ObjectKind::Credential, credential)?;
    if [
        before.core[core_index::CREDENTIAL],
        after.core[core_index::CREDENTIAL],
        before.lineage[8],
        after.lineage[8],
        statement[7],
    ]
    .iter()
    .any(|digest| *digest != current)
        || object_digest(ObjectKind::Request, request)? != statement[23]
    {
        return Err(Error::Input);
    }
    // The receiver signs only the Request terms, so its digest leaves the payer
    // fields to `bind_send`: payer wallet and account are the credential's (the
    // same offsets in both bodies) and the send ordinal is the statement's. Terms
    // enter the digest as canonical words; the fee schedule is checked below.
    if request[66..130] != credential[66..130] || le(request, 194, 16)? != statement[20] {
        return Err(Error::Input);
    }
    for offset in [210, 314, 354] {
        le(request, offset, 32)?;
    }
    let held = before.rest[rest_index::FEE_SCHEDULE];
    if le(request, 258, 32)? != held
        || (held != Fp::ZERO
            && (fee[..2] != 1_u16.to_le_bytes()
                || object_digest(ObjectKind::FeeSchedule, fee)? != held))
        || (held == Fp::ZERO && (le(request, 290, 16)? != Fp::ZERO || statement[22] != Fp::ZERO))
    {
        return Err(Error::Input);
    }
    // A zero held schedule deliberately permits any fixed-length dummy tape;
    // Send's circuit still commits its original bytes to the stage context.
    // The payment key is carried by continuity: the credential tape must still open it.
    let payment_key = key(credential, 130)?;
    if payment_key.as_slice() != &before.lineage[9..13] {
        return Err(Error::Input);
    }
    for (raw, offset, expected) in [
        (credential, 2, before.core[core_index::SCHEME]),
        (credential, 18, before.core[core_index::SCHEME + 1]),
        (credential, 195, Fp::from_u128(policy.provider[0])),
        (credential, 211, Fp::from_u128(policy.provider[1])),
    ] {
        if le(raw, offset, 16)? != expected {
            return Err(Error::Input);
        }
    }
    super::support::check_hard_own_receipt(receipt, &input.q[0].instances, payment_key)
        .map_err(|_| Error::Input)?;
    let digest = hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, statement);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            before.lineage[6],
            before.lineage[7],
            statement[16],
            statement[17],
        ],
    );
    for (offset, len, expected) in [
        (2, 16, statement[3]),
        (18, 16, statement[4]),
        (34, 16, before.lineage[6]),
        (50, 16, before.lineage[7]),
        (66, 16, Fp::from_u128(policy.provider[0])),
        (82, 16, Fp::from_u128(policy.provider[1])),
        (98, 16, statement[9]),
        (114, 32, operation),
        (146, 32, statement[14]),
        (178, 32, statement[15]),
        (210, 32, digest),
        (306, 32, Fp::ZERO),
    ] {
        if le(receipt, offset, len)? != expected {
            return Err(Error::Input);
        }
    }
    // The sigma-only proof digest names the Payment carriers Λ does not consume; the
    // circuit requires it nonzero, as here.
    if le(receipt, 242, 32)? == Fp::ZERO || receipt[274..306].iter().all(|byte| *byte == 0) {
        return Err(Error::Input);
    }
    Ok(())
}

fn check_mask(input: &Inputs, mask: u8) -> Result<(), Error> {
    let expected = Fp::from(u64::from(mask));
    if mask > 3
        || input.state.before.core[21] != expected
        || input.state.after.core[21] != expected
        || input.state.statement[11] != expected
    {
        return Err(Error::Input);
    }
    Ok(())
}

fn object_digest(kind: ObjectKind, bytes: &[u8]) -> Result<Fp, Error> {
    let end = kind.body_len();
    if bytes.len() != end + 64 {
        return Err(Error::Input);
    }
    let mut words = vec![signed_message_native(kind, &bytes[..end])];
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
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(claim.g());
    let mut words = Vec::with_capacity(20);
    for value in [x, y] {
        words.extend(foreign_limbs(&value).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}

fn context_digest(first: &First) -> Result<Fp, Error> {
    let source = &first.source;
    let mut words = first.plan.schema().to_vec();
    words.extend(source.maps.witness.statement);
    let old = &source.maps.witness.before;
    let new = &source.maps.witness.after;
    words.extend(old.core);
    words.extend(old.rest);
    words.extend(old.lineage);
    push_pallas(&mut words, &source.predecessor.pallas.as_input())?;
    words.extend(vesta_words(&source.predecessor.vesta.as_input()));
    words.extend(new.core);
    words.extend(new.rest);
    words.extend(new.lineage);
    for value in source.q_instances.iter().flatten().flatten() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    for (object, spec) in source
        .maps
        .objects
        .iter()
        .zip(SendStagePlan::context_specs().map_err(|_| Error::Artifact)?)
    {
        if object.bytes.len() != usize::try_from(spec.capacity).map_err(|_| Error::Input)? {
            return Err(Error::Input);
        }
        let mut bytes = spec.capacity.to_le_bytes().to_vec();
        bytes.extend(&object.bytes);
        let mut tape = vec![
            Fp::from(u64::from(spec.tag)),
            Fp::from(u64::from(spec.capacity)),
        ];
        for chunk in bytes.chunks(31) {
            tape.push(le_value::<Fp>(chunk).ok_or(Error::Input)?);
        }
        words.extend([
            object.digest()?,
            Fp::from(u64::from(spec.capacity)),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
    }
    Ok(hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words))
}

fn trivial_vesta_claim() -> Result<FoldInput<Eq>, Error> {
    let g = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .map_err(|_| Error::Artifact)?;
    FoldInput::<Eq>::from_normalized(g, 16, [Fp::ONE; K]).map_err(|_| Error::Artifact)
}
fn trivial_vesta_words() -> Result<Vec<Fp>, Error> {
    Ok(vesta_words(&trivial_vesta_claim()?))
}
fn internal_public(digest: Fp, part: &FoldInput<Eq>) -> Result<Vec<Fp>, Error> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part));
    let trivial = trivial_vesta_words()?;
    words.extend(&trivial);
    words.extend(&trivial);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&trivial[..4]);
    if words.len() != 69 {
        return Err(Error::Input);
    }
    Ok(words)
}
fn first_public(first: &First) -> Result<Vec<Fp>, Error> {
    internal_public(
        super::support::stage_digest(&first.plan, 0, context_digest(first)?, &first.pallas)
            .map_err(|_| Error::Input)?,
        &first.source.part,
    )
}
fn continuation_public(c: &Continuation) -> Result<Vec<Fp>, Error> {
    if !c.plan.is_terminal() {
        let digest = super::support::stage_digest(
            &c.first.plan,
            c.plan.stage(),
            context_digest(&c.first)?,
            &c.pallas,
        )
        .map_err(|_| Error::Input)?;
        return internal_public(digest, &c.vesta.as_input());
    }
    let mut words = vec![
        terminal_digest(
            &c.first.source.maps.witness.after.lineage,
            &c.pallas.as_input(),
        )?,
        Fp::from(16),
    ];
    words.extend(vesta_words(&c.vesta.as_input()));
    words.extend(vesta_words(&c.first.source.predecessor.vesta.as_input()));
    let trivial = trivial_vesta_words()?;
    words.extend(&trivial);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&trivial[..4]);
    if words.len() != 69 {
        return Err(Error::Input);
    }
    Ok(words)
}

fn terminal_digest(public: &[Fp; 18], pallas: &FoldInput<Ep>) -> Result<Fp, Error> {
    let mut words = public.to_vec();
    let mut claim = Vec::new();
    push_pallas(&mut claim, pallas)?;
    words.extend(&claim[1..]);
    if words.len() != 52 {
        return Err(Error::Input);
    }
    Ok(hash_with_domain(super::super::LINEAGE_DOMAIN, &words))
}
fn omega_instances(context: Fp, vesta: &AccumulatorT<Eq>) -> Result<Vec<Vec<Fq>>, Error> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(vesta.g());
    let digest = Option::<Fq>::from(Fq::from_repr(context.to_repr())).ok_or(Error::Input)?;
    let challenges = vesta
        .challenges()
        .iter()
        .map(|v| Option::<Fq>::from(Fq::from_repr(v.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![vec![digest], vec![x, y], challenges])
}

/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
fn opening_pallas_cancellable(
    params: &PinnedParams<Ep>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Ep>,
    instances: &[Vec<Fq>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Ep>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
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
    let input =
        FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
    input
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(input)
}

/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
fn opening_vesta_cancellable(
    params: &PinnedParams<Eq>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
    instances: &[Vec<Fp>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Eq>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
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
    let input =
        FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
    input
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(input)
}
fn prove_a(
    plan: &Plan,
    key: &SourceBoundViewV2<'_, Eq>,
    circuit: &StageCircuit,
    public: &[Fp],
    randomness: ProverRandomness,
    config: ProverConfig,
    budget: MemoryBudget,
) -> Result<(Vec<u8>, FoldInput<Eq>), Error> {
    let public = [public.to_vec()];
    let output = super::proving::prove(&plan.vesta, key, circuit, &public, randomness, config)?;
    iroha_plonk::verifier::verify_full_cancellable(
        &plan.vesta,
        key.binding(),
        key.verifying_key(),
        &public,
        &output.proof,
        budget,
        config.cancellation,
    )
    .map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof
        }
    })?;
    let opening = opening_vesta_cancellable(
        &plan.vesta,
        key.binding(),
        key.verifying_key(),
        &public,
        &output.proof,
        budget,
        config.cancellation,
    )?;
    Ok((output.proof, opening))
}

/// Complete immutable four-mask Send source catalog. Construction is not release qualification.
pub struct Catalog {
    masks: [Prover; 4],
}
impl Catalog {
    /// Require exactly one installed source pipeline for each global Send selector2..5.
    /// # Errors
    /// A missing/reordered mask or another fixed provider/root policy.
    pub fn new(masks: [Prover; 4]) -> Result<Self, Error> {
        let first = masks[0].plan.policy;
        for (mask, prover) in masks.iter().enumerate() {
            if usize::from(prover.plan.mask) != mask
                || prover.plan.policy.provider != first.provider
                || prover.plan.policy.root != first.root
            {
                return Err(Error::Artifact);
            }
        }
        Ok(Self { masks })
    }
    /// Select from the exact original statement mask, then verify its predecessor/core and proofs.
    /// # Errors
    /// Noncanonical mask, differing opened core, source/tape or native proof/decide failure.
    pub fn prepare(&self, input: Inputs, budget: MemoryBudget) -> Result<Session<'_>, Error> {
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
    ) -> Result<Session<'_>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let repr = input.state.statement[11].to_repr();
        if repr[0] > 3 || repr[1..] != [0; 31] {
            return Err(Error::Input);
        }
        self.masks[usize::from(repr[0])].prepare_cancellable(input, budget, cancellation)
    }
}
