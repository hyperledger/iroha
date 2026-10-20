//! Installed native Unload and Retiring composition over exact original tapes (lean lineage).
//!
//! One terminal A proves the whole step beside the hard predecessor: the recovery
//! insertion and value conservation, or the retirement effects, and the one own-receipt
//! signature Q under the predecessor payment key, verified in place. There is no own
//! sigma verifier and no W; the credential and its certificate are carried by
//! continuity. The A folds the predecessor's carried claim and opening with the Q
//! opening into its Pallas claim. Sessions use the installed key, verify every source
//! and checkpoint proof, and decide all retained openings. They do not authorize a
//! monetary head without the final rooted Omega and durable wallet commit.
//! TODO: qualify installed producer parity and the full common terminal catalog.
//! Original PK imports reconstruct the same source with unknown circuit-only
//! witnesses and require exact installed descriptor and verifying-key agreement.

use iroha_plonk::keys::{SourceAdmissionSealV2, SourceBoundViewV2};
#[path = "consuming/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::CheckpointLayout;

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
    AccumulatorT, FoldConfig, FoldInput, FoldTape, K,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

use super::super::{
    AProofPlan, LineagePublicCells, ProofMessageCells, VestaClaimCells, bind_signature_q,
    context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
    own::OwnPolicy,
    schedule::OperationTask,
    split::close_single,
    unload::{UnloadObjects, UnloadStagePlan, UnloadStageWitness},
    verify_predecessor, verify_q,
};
use crate::{
    admin_sigma::{ConsumingWitness, StateWitness},
    operation_relation::{
        map_effects::InsertCells,
        objects::{ObjectKind, signed_message_native},
        state::StateCells,
        statement::StatementCells,
    },
    private_fold::PrivateFoldBytes,
    q_signature::{QSignaturePlan, SignatureKey},
    tree::IndexedInsert,
};

/// Fixed native source profile; private inputs cannot choose another range-bus count.
pub const SOURCE_RANGE_BUSES: usize = 3;
const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;
/// Exact source schedule: one terminal A stage, with no W before or after it.
pub const A_STAGE_COUNT: usize = 1;
use super::super::receive::OMEGA_TRANSPORT_CAP;

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
        write!(f, "native consuming: {self:?}")
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

/// Post-Advance originals for complete native Unload/Retiring lineage composition.
/// The G1 owner authenticates canonical custody objects before producing these typed
/// field transcripts and exact signed-body transcript||signature tapes.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Exact predecessor/successor core (`CORE_FIELDS`)/rest6/public18 and own statement26.
    pub state: ConsumingWitness,
    /// Own Advance Receipt, the only signed object Λ consumes.
    pub objects: [Vec<u8>; 1],
    /// Exact depth32 recovery insertion for Unload; must be absent for Retiring.
    pub recovery: Option<IndexedInsert<Fp>>,
    /// The mandatory own-receipt signature Q.
    pub q: [QInput; 1],
    /// Actual predecessor proof; its key/profile comes from the installed Plan.
    pub predecessor: PredecessorInput,
}

/// Immutable complete consuming circuit metadata from the authenticated native artifact owner.
#[derive(Clone, Debug)]
pub struct Plan {
    context: ContextPlan,
    policy: OwnPolicy,
    signatures: QSignaturePlan,
    predecessor_key: VerifyingKey<Ep>,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin the fixed one-stage `[[Q0]]` schedule on an inline plan and both consuming
    /// tasks in that stage. The variant is an installed key property, never selected by
    /// private witness data. The one hard signature slot is the own receipt under the
    /// predecessor payment key.
    /// # Errors
    /// Wrong variant/k/schema/stage count, absent predecessor or substituted fixed
    /// signature/key policy.
    pub fn new(
        operation: AProofPlan,
        policy: OwnPolicy,
        signatures: QSignaturePlan,
        predecessor_key: VerifyingKey<Ep>,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        if !matches!(
            operation.frame().variant(),
            Variant::Unload | Variant::Retiring
        ) || !operation.is_inline()
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
        check_omega_transport_length(predecessor.proof_length()).map_err(|_| Error::Artifact)?;
        let slots = signatures.slots();
        if slots.len() != 1
            || slots[0].mode != VerifyMode::Hard
            || slots[0].key != SignatureKey::Variable
        {
            return Err(Error::Artifact);
        }
        let signature = operation
            .q(0)
            .ok_or(Error::Artifact)?
            .verifier()
            .binding()
            .descriptor();
        if signature.instance_lengths
            != [u32::try_from(signatures.instance_length()).map_err(|_| Error::Artifact)?]
            || signature.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        {
            return Err(Error::Artifact);
        }
        let context = crate::a_relation::schedule::compiled::OperationSchedule::for_variant(
            operation.frame().variant(),
        )
        .bind(
            operation,
            UnloadObjects::context_specs()
                .map_err(|_| Error::Artifact)?
                .to_vec(),
        )
        .map_err(|_| Error::Artifact)?;
        if context.stage_count() != A_STAGE_COUNT {
            return Err(Error::Artifact);
        }
        UnloadStagePlan::new(context.clone(), policy).map_err(|_| Error::Artifact)?;
        Ok(Self {
            context,
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

    /// Verify all actual predecessor/Q proofs and both transported predecessor claims.
    /// Derive every Q opening from those checked originals.
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
        for (kind, raw) in object_kinds().into_iter().zip(&input.objects) {
            if raw.len() != kind.body_len() + 64 {
                return Err(Error::Input);
            }
        }
        super::support::check_hard_own_receipt(
            &input.objects[0],
            &input.q[0].instances,
            core::array::from_fn(|i| input.state.predecessor.lineage[9 + i]),
        )
        .map_err(|_| Error::Input)?;
        let variant = self.context.operation().frame().variant();
        if input.recovery.is_some() != (variant == Variant::Unload) {
            return Err(Error::Input);
        }
        let predecessor_length = self
            .context
            .operation()
            .omega()
            .ok_or(Error::Artifact)?
            .proof_length();
        if input.predecessor.proof.len() != predecessor_length {
            return Err(Error::Input);
        }
        check_omega_transport_length(predecessor_length)?;
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
        if input.state.predecessor.lineage[17] != digest {
            return Err(Error::Input);
        }
        let own = terminal_digest(&input.state.predecessor.lineage, &pallas.as_input())?;
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
        let objects = core::array::from_fn(|i| SignedTape {
            kind: object_kinds()[i],
            bytes: input.objects[i].clone(),
        });
        let maps = Maps {
            witness: input.state,
            recovery: input.recovery,
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
            objects,
            variant,
            q_instances: input.q.each_ref().map(|q| q.instances.clone()).to_vec(),
            q_proofs: input.q.each_ref().map(|q| q.proof.clone()).to_vec(),
            q_openings: openings,
            signature_schema: self.signatures.clone(),
            predecessor,
            params: self.pallas.clone(),
            policy: self.policy,
        });
        Ok(Prepared {
            plan: self.clone(),
            source,
        })
    }

    /// Reconstruct the unknown terminal A from the compiled consuming source.
    /// The strict original importer uses this same source factory. This creates no
    /// prepared operation, accepted claim or monetary authority.
    /// # Errors
    /// A missing fixed predecessor or Q verifier.
    pub fn source_circuit(&self) -> Result<StageCircuit, Error> {
        StageCircuit::blank(self)
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
    objects: [SignedTape; 1],
    variant: Variant,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    q_openings: Vec<FoldInput<Ep>>,
    signature_schema: QSignaturePlan,
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
    witness: ConsumingWitness,
    recovery: Option<IndexedInsert<Fp>>,
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
    pub(crate) fn state(
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
    pub(crate) fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<InsertCells, LayoutError> {
        let insertion = self.recovery.as_ref().ok_or(LayoutError::Synthesis)?;
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
// Circuit-only views contain no verified native claim or Prepared authority.
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
    objects: [SignedTape; 1],
    variant: Variant,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    signature_schema: QSignaturePlan,
    predecessor: CircuitPredecessor,
    params: PinnedParams<Ep>,
    policy: OwnPolicy,
}

/// Complete one-stage Unload/Retiring A circuit. Keys are fixed by native assembly;
/// source evidence, original tapes and the terminal fold remain private witnesses.
#[derive(Clone)]
pub struct StageCircuit {
    source: Arc<CircuitSources>,
    plan: ContextPlan,
    fold: PrivateFoldBytes,
    known: bool,
}
impl StageCircuit {
    // Installation specimens supply dimensions and unknown values only. They never
    // pass through Plan::prepare or construct a verified opening or checkpoint owner.
    fn blank(plan: &Plan) -> Result<Self, Error> {
        let operation = plan.context.operation();
        let predecessor = operation.omega().ok_or(Error::Artifact)?;
        let state = StateWitness {
            core: [Fp::ZERO; crate::witness::CORE_FIELDS],
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
        let objects = object_kinds().map(|kind| SignedTape {
            kind,
            bytes: vec![0; kind.body_len() + 64],
        });
        let insertion = IndexedInsert {
            leaf: crate::tree::IndexedLeaf::default(),
            leaf_slot: 0,
            leaf_siblings: [Fp::ZERO; 32],
            slot: 1,
            slot_siblings: [Fp::ZERO; 32],
        };
        let source = CircuitSources {
            objects,
            variant: operation.frame().variant(),
            maps: Maps {
                witness: ConsumingWitness {
                    predecessor: state,
                    successor: state,
                    statement: [Fp::ZERO; 26],
                },
                recovery: (operation.frame().variant() == Variant::Unload).then_some(insertion),
                known: false,
            },
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
            fold: PrivateFoldBytes::unknown(),
            known: false,
        })
    }
}
#[derive(Clone, Debug)]
/// Fixed Tagged3 verifier, exact byte tape and homogeneous public columns.
pub struct StageConfig {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl StageCircuit {
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
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<UnloadObjects, LayoutError> {
        let sources = self
            .source
            .objects
            .each_ref()
            .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        UnloadObjects::decode(chip, bytes, region, sources.each_ref().map(Vec::as_slice))
    }
}

impl Circuit<Fp> for StageCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            fold: PrivateFoldBytes::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StageConfig {
        let verifier =
            VerifierConfig::configure_serialized_foreign_tagged(meta, SOURCE_RANGE_BUSES)
                .expect("fixed native consuming Tagged3 profile");
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
            || "complete consuming terminal relation",
            |mut region| {
                let mut maps = self.source.maps.clone();
                maps.known = self.known;
                let (old, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.predecessor)?;
                let (new, next_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    self.source.variant,
                    &fields,
                )?;
                let objects = self.objects(&mut chip, &mut bytes, &mut region)?;
                let context_objects = objects.context();
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
                    objects: context_objects,
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
                // The one stage proves the transition beside the hard predecessor and
                // verifies the own receipt Q in place; its hard slot authorizes the
                // receipt under the carried payment key.
                let tasks = self.plan.operation_tasks(0).ok_or(LayoutError::Synthesis)?;
                let recovery = if tasks.contains(&OperationTask::UnloadRecovery) {
                    Some(maps.insertion(&mut chip.uint(), &mut region)?)
                } else {
                    None
                };
                let &[index] = self.plan.q_partition(0).ok_or(LayoutError::Synthesis)? else {
                    return Err(LayoutError::Synthesis);
                };
                let q_proof = self.carrier(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    self.source
                        .q_proofs
                        .get(index)
                        .ok_or(LayoutError::Synthesis)?,
                )?;
                let verified = verify_q(
                    &mut chip,
                    &mut region,
                    self.plan.operation(),
                    index,
                    q_instances.get(index).ok_or(LayoutError::Synthesis)?,
                    &q_proof,
                )?;
                let slots = bind_signature_q(
                    &mut chip,
                    &mut region,
                    self.plan.operation(),
                    index,
                    &self.source.signature_schema,
                    &verified,
                )?;
                UnloadStagePlan::new(self.plan.clone(), self.source.policy)?.constrain_stage(
                    &mut chip,
                    &mut region,
                    0,
                    &objects,
                    &input,
                    UnloadStageWitness {
                        recovery: recovery.as_ref(),
                        signatures: Some(&slots),
                    },
                )?;
                let fold = self.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                close_single(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    &pred,
                    core::slice::from_ref(slots.verified()),
                    &fold,
                    &self.source.params,
                    &next_public,
                )
            },
        )?;
        if out.len() != 69 {
            return Err(LayoutError::Synthesis);
        }
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

/// Checked original source coupled to the fixed complete Unload/Retiring plan.
/// Private fields prevent substituting an unverified opening or another tape.
#[derive(Clone)]
pub struct Prepared {
    plan: Plan,
    source: Arc<Sources>,
}
impl Prepared {
    /// The terminal A circuit over these exact originals and its public frame.
    /// The tape randomizes the actual terminal fold; it selects no profile or claim.
    ///
    /// # Errors
    /// A failed fixed four-claim fold, complete decide or malformed frame.
    pub fn terminal_circuit(
        &self,
        tape: FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>), Error> {
        let (pallas, fold) = self.fold(tape, config)?;
        let public = self.public(&pallas)?;
        Ok((self.circuit(fold), public))
    }

    // The fixed terminal fold `close_single` verifies: the predecessor's carried claim
    // and actual opening, then the own receipt Q opening, padded with the pinned
    // trivial claim to four full-k16 slots. Its output is completely decided.
    fn fold(
        &self,
        tape: FoldTape<Ep>,
        config: &FoldConfig,
    ) -> Result<(AccumulatorT<Ep>, PrivateFoldBytes), Error> {
        let mut claims = vec![
            self.source.predecessor.pallas.as_input(),
            self.source.predecessor.opening.clone(),
        ];
        for index in self.plan.context.q_partition(0).ok_or(Error::Artifact)? {
            claims.push(
                self.source
                    .q_openings
                    .get(*index)
                    .ok_or(Error::Artifact)?
                    .clone(),
            );
        }
        let purpose = crate::private_fold::terminal_inputs(&self.plan.pallas, &mut claims, config)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let (fold, pallas) = create_fold(&self.plan.pallas, &claims, tape, purpose, config)
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
        Ok((pallas, PrivateFoldBytes::from_fold(fold)))
    }

    fn circuit(&self, fold: PrivateFoldBytes) -> StageCircuit {
        let source = &self.source;
        StageCircuit {
            source: Arc::new(CircuitSources {
                maps: source.maps.clone(),
                objects: source.objects.clone(),
                variant: source.variant,
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
            plan: self.plan.context.clone(),
            fold,
            known: true,
        }
    }

    fn public(&self, pallas: &AccumulatorT<Ep>) -> Result<Vec<Fp>, Error> {
        terminal_public(
            &self.source.maps.witness.successor.lineage,
            &pallas.as_input(),
            &self.source.predecessor.vesta.as_input(),
        )
    }

    // Fold, prove under the installed key and retain the decided own opening.
    fn prove_terminal(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        tape: FoldTape<Ep>,
        fold: &FoldConfig,
        randomness: ProverRandomness,
        config: ProverConfig,
    ) -> Result<Terminal, Error> {
        let (pallas, witness) = self.fold(tape, fold)?;
        let public = self.public(&pallas)?;
        let circuit = self.circuit(witness);
        let (proof, opening) = prove_a(
            &self.plan,
            key,
            &circuit,
            &public,
            randomness,
            config,
            fold.kernel_budget,
        )?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas,
            predecessor_vesta: self.source.predecessor.vesta.clone(),
            opening,
        })
    }

    // Durable source identity of a terminal checkpoint.
    fn context_digest(&self) -> Result<Fp, Error> {
        context_digest(&self.plan.context, &self.source)
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

/// Fixed Unload/Retiring verifier metadata with no retained proving polynomials or PK bytes.
/// Installation authenticates the plan and verifier identities independently;
/// metadata consistency alone grants no source/catalog or wallet-open authority.
/// TODO(G3/G4): connect the complete authenticated producer catalog and original
/// G1 preparation before enabling the Native wallet owner.
pub struct Prover {
    plan: Plan,
    terminal: KeyArtifact<Eq>,
    // Process-local instance identity; only this instance resumes its sessions.
    identity: ProverInstanceV1,
}
impl Prover {
    /// Mount the terminal A verifier metadata without retaining any proving key.
    ///
    /// The native owner authenticates the complete scheme/provider/root, predecessor,
    /// Q key, signature slot and compiled-source catalog independently of inputs.
    /// The importer reconstructs the exact unknown source and validates original
    /// tables and commitments; proving borrows only that key and checks its identity
    /// before any fold or proof. Metadata matching alone is not source authority.
    /// # Errors
    /// Wrong profile, curve, public schema or installed source descriptor.
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
    /// This uses unknown source inputs, never creates accepted claims, and returns
    /// a compact source-admission seal without constructing proving FFTs or masks.
    /// # Errors
    /// Original/domain cap, changed source/table/commitments or full installed-key mismatch.
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
    /// retained preparation. A durable terminal checkpoint must still be restored
    /// strictly from its bytes.
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

/// Source-bound session over the fixed installed consuming artifact.
/// The custody owner retains source originals and the checkpoint before advancing.
pub struct Session<'a> {
    prover: &'a Prover,
    prepared: Prepared,
}

/// An Unload/Retiring session's verified preparation, detached between fold calls.
///
/// Only `Session::into_retained` creates one, and only `Prover::resume` on the
/// prover instance that prepared it consumes it. It is move-only, process-local
/// and never serialized or built from bytes. It holds the checked originals and
/// openings, but no fold witness, proving key, original-store handle or durable
/// checkpoint.
pub struct RetainedSession(BoundV1<Prepared>);

impl Session<'_> {
    /// Detach this session's verified preparation so a later fold call can resume
    /// it on the same prover instance instead of preparing again.
    #[must_use]
    pub fn into_retained(self) -> RetainedSession {
        RetainedSession(self.prover.identity.bind(self.prepared))
    }

    /// Fold the hard predecessor pair and the own receipt Q opening, then prove the
    /// terminal A under its installed key. The tape randomizes the actual fold, whose
    /// decided output is the Pallas claim bound through `D_A`.
    /// # Errors
    /// Fixed artifact/circuit mismatch, failed fold, proof or complete decide.
    pub fn terminal(
        &self,
        key: &SourceBoundViewV2<'_, Eq>,
        tape: FoldTape<Ep>,
        fold: &FoldConfig,
        randomness: ProverRandomness,
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
        self.prepared
            .prove_terminal(key, tape, fold, randomness, config)
    }

    /// Reverify terminal A proof bytes and the exact544 carried Pallas claim reloaded
    /// from the source-bound custody archive. The claim is decided in full and the
    /// public frame is rederived from this session's originals and that claim; no
    /// transported frame is trusted.
    /// # Errors
    /// Noncanonical/undecided claim, a substituted proof, changed source frame or
    /// failed proof/decide.
    pub fn restore_terminal(
        &self,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
    ) -> Result<Terminal, Error> {
        self.restore_terminal_cancellable(proof, pallas, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_terminal_cancellable(
        &self,
        proof: Vec<u8>,
        pallas: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
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
        let public = self.prepared.public(&pallas)?;
        let key = &self.prover.terminal;
        let instances = std::slice::from_ref(&public);
        iroha_plonk::verifier::verify_full_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
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
        let opening = opening_vesta_cancellable(
            &self.prepared.plan.vesta,
            key.binding(),
            key.key(),
            instances,
            &proof,
            budget,
            cancellation,
        )?;
        Ok(Terminal {
            proof,
            instances: public,
            pallas,
            predecessor_vesta: self.prepared.source.predecessor.vesta.clone(),
            opening,
        })
    }
}

/// Actual terminal A proof and every distinct obligation the final Omega producer consumes.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// Original terminal A proof under its installed key.
    pub proof: Vec<u8>,
    /// Exact homogeneous69-word public frame.
    pub instances: Vec<Fp>,
    /// Full Pallas claim bound through `D_A`: the decided terminal fold of the hard
    /// predecessor pair, the own receipt Q opening and the pinned trivial filler.
    pub pallas: AccumulatorT<Ep>,
    /// Full predecessor Vesta obligation, distinct from the pinned trivial part and
    /// the A opening.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Actual terminal A own opening, a separate final Omega slot.
    pub opening: FoldInput<Eq>,
}

fn object_kinds() -> [ObjectKind; 1] {
    [ObjectKind::Receipt]
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

// Source identity of a terminal checkpoint: the fixed schedule, the statement, both
// states and lineages, both transported predecessor claims, every Q public value and
// the original receipt tape.
fn context_digest(plan: &ContextPlan, source: &Sources) -> Result<Fp, Error> {
    let mut words = plan.schema().to_vec();
    words.extend(source.maps.witness.statement);
    let old = &source.maps.witness.predecessor;
    let new = &source.maps.witness.successor;
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
        .objects
        .iter()
        .zip(UnloadObjects::context_specs().map_err(|_| Error::Artifact)?)
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
// The exact frame `close_single` emits: `D_A` over the successor lineage and the folded
// Pallas claim, then the pinned trivial part (no own sigma verifier and no W), the
// predecessor Vesta obligation and the absent incoming slot with its Trivial mode.
fn terminal_public(
    successor: &[Fp; 18],
    pallas: &FoldInput<Ep>,
    predecessor: &FoldInput<Eq>,
) -> Result<Vec<Fp>, Error> {
    let trivial = trivial_vesta_words()?;
    let mut words = vec![terminal_digest(successor, pallas)?, Fp::from(16)];
    words.extend(&trivial);
    words.extend(vesta_words(predecessor));
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
    let _self_verification = iroha_plonk::work_metrics::WorkTimer::start(
        iroha_plonk::work_metrics::WorkPhase::SelfVerify,
    );
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

fn check_omega_transport_length(proof: usize) -> Result<(), Error> {
    if proof == 0
        || !proof.is_multiple_of(32)
        || proof
            .checked_add(2 * iroha_plonk_recursion::ACCUMULATOR_BYTES)
            .is_none_or(|transport| transport > OMEGA_TRANSPORT_CAP)
    {
        return Err(Error::Input);
    }
    Ok(())
}

#[cfg(test)]
#[path = "consuming/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "consuming/capacity.rs"]
mod capacity;
