//! Installed native Refresh composition with exact signed originals and fixed owners.
//!
//! Each variant pins its source schedule, installed keys and every Q/map obligation.
//! Checkpoints retain original proof bytes and full accumulator claims. No operation
//! is monetarily complete before its admitted final Omega and durable wallet commit.
//! TODO: qualify the metadata-rebuild producer and final wrappers under the full terminal
//! catalog. Earlier eager-key component parity does not qualify current memory usage.

use iroha_plonk::keys::{SourceAdmissionSealV2, SourceBoundViewV2};
#[path = "refresh/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{CheckpointKind, CheckpointLayout};

#[path = "refresh/original.rs"]
mod original;
use super::artifact::KeyArtifact;

use core::fmt;
use std::sync::Arc;

use ff::{Field, PrimeField};
use iroha_pasta::{
    Ep, Eq, EqAffine, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{
    DescriptorBinding, ProverConfig, ProverRandomness, ProvingKey, VerifyingKey,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error as LayoutError, Layouter, Region, SimpleFloorPlanner, Value},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{
    bytes::{
        element::le_message_segments,
        le_value, p_bytes_native,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    imt::{LeafCells, OpeningCells, PathCells},
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
    AProofPlan, LineagePublicCells, ProofMessageCells, SigmaBindingCells, VestaClaimCells,
    context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
    own::OwnPolicy,
    refresh::{QuotaCommitmentCells, RefreshObjects, RefreshStagePlan, RefreshStageWitness},
    schedule::OperationTask,
    split::{SplitPlan, WCircuit, WKey, close_first},
    verify_predecessor, verify_sigma,
};
use crate::{
    admin_sigma::{RefreshWitness, StateWitness},
    omega::OmegaWitness,
    operation_relation::{
        map_effects::InsertCells, objects::ObjectKind, quota_refresh::QuotaRebuildCells,
        state::StateCells, statement::StatementCells,
    },
    q_signature::QSignaturePlan,
    tree::IndexedInsert,
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
#[path = "refresh/tests.rs"]
mod tests;

/// Fixed native source profile; private inputs cannot choose another range-bus count.
pub const SOURCE_RANGE_BUSES: usize = 3;
/// Ordinary Refresh kinds have four source A stages and three W continuations.
pub const BASIC_A_STAGE_COUNT: usize = 4;
/// Quota adds three authenticated root owners and one exact matching owner.
pub const QUOTA_A_STAGE_COUNT: usize = 7;

/// Native preparation/proof failure. No failure changes a monetary head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
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
        write!(f, "native refresh: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Whether the operation was cancelled instead of proving an invalid input.
    pub fn is_cancelled(self) -> bool {
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

/// Exact fixed64 arrays carried across the mandatory quota root/merge owners.
#[derive(Clone, Debug)]
pub struct QuotaInput {
    /// Previous `(kind,start,end,used)` leaves in canonical slot order.
    pub old: [[Fp; 4]; 64],
    /// Signed replacement `(kind,start,end,limit)` windows in slot order.
    pub windows: [[Fp; 4]; 64],
    /// Successor usage aligned with the replacement windows.
    pub used: [Fp; 64],
    /// Original signed share issue time.
    pub issued: Fp,
    /// Original signed count of non-padding windows.
    pub window_count: Fp,
}
impl QuotaInput {
    fn commitments(&self) -> [Fp; 5] {
        let hash = |tag: u64, count: u64, fields: Vec<Fp>| {
            let mut words = vec![Fp::from(tag), Fp::from(count)];
            words.extend(fields);
            hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &words)
        };
        [
            hash(7, 256, self.old.iter().flatten().copied().collect()),
            hash(8, 256, self.windows.iter().flatten().copied().collect()),
            hash(9, 64, self.used.to_vec()),
            self.issued,
            self.window_count,
        ]
    }
}

/// Post-Advance originals for the complete fixed Refresh relation.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Exact predecessor/successor core33/rest8/public18 and own statement26.
    pub state: RefreshWitness,
    /// Original unframed sigma also exported by Q0.
    pub sigma: Vec<u8>,
    /// Update certificate/update/receipt/current certificate/current credential.
    pub objects: [Vec<u8>; 5],
    /// Exact history insertion, present only for Blacklist.
    pub blacklist: Option<IndexedInsert<Fp>>,
    /// Exact arrays and signed issue/count, present only for Quota.
    pub quota: Option<QuotaInput>,
    /// Own sigma Q, update/receipt/certificate Q, current credential/certificate Q.
    pub q: [QInput; 3],
    /// Actual predecessor proof and both original transported claims.
    pub predecessor: PredecessorInput,
}

/// Immutable complete Refresh circuit metadata from the authenticated native artifact owner.
#[derive(Clone, Debug)]
pub struct Plan {
    context: ContextPlan,
    policy: OwnPolicy,
    signatures: [QSignaturePlan; 2],
    predecessor_key: VerifyingKey<Ep>,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin the exact four- or seven-stage schedule and both hard signature schemas.
    /// The variant is an installed key property, never chosen by private data.
    /// # Errors
    /// Wrong variant/k/schema, absent predecessor or foreign fixed artifact shape.
    pub fn new(
        operation: AProofPlan,
        policy: OwnPolicy,
        predecessor_key: VerifyingKey<Ep>,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        let variant = operation.frame().variant();
        let specs = RefreshObjects::context_specs(variant).map_err(|_| Error::Artifact)?;
        if operation.frame().part_source_k() != 12
            || operation.q_count() != 3
            || !operation.frame().has_predecessor()
            || operation.sigma.slot_count() != 1
            || operation
                .sigma
                .class(0)
                .ok_or(Error::Artifact)?
                .verifier()
                .binding()
                .descriptor()
                .k
                != 12
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
        let signatures =
            RefreshStagePlan::signature_schemas(policy).map_err(|_| Error::Artifact)?;
        let context =
            crate::a_relation::schedule::compiled::OperationSchedule::for_variant(variant)
                .bind(operation, specs)
                .map_err(|_| Error::Artifact)?;
        RefreshStagePlan::new(context.clone(), policy).map_err(|_| Error::Artifact)?;
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
    /// Derive every Q opening and sigma Vesta claim from those checked originals.
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
        for (kind, raw) in object_kinds(self.context.operation().frame().variant())?
            .into_iter()
            .zip(&input.objects)
        {
            if raw.len() != kind.body_len() + 64 {
                return Err(Error::Input);
            }
        }
        let class = self
            .context
            .operation()
            .sigma
            .class(0)
            .ok_or(Error::Artifact)?;
        if input.sigma.len() != class.verifier().proof_length() {
            return Err(Error::Input);
        }
        let variant = self.context.operation().frame().variant();
        if input.blacklist.is_some() != (variant == Variant::RefreshBlacklist)
            || input.quota.is_some() != (variant == Variant::RefreshQuotaShare)
        {
            return Err(Error::Input);
        }
        check_update_projection(variant, &input.state.update, &input.objects[1])?;
        check_sigma_tape(&input, variant)?;
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
        let part = q_sigma_part(&input.q[0], 12, variant)?;
        part.decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let kinds = object_kinds(variant)?;
        let objects = core::array::from_fn(|i| SignedTape {
            kind: kinds[i],
            bytes: input.objects[i].clone(),
        });
        let maps = Maps {
            witness: input.state,
            blacklist: input.blacklist,
            quota: input.quota,
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
            sigma: input.sigma,
            q_instances: input.q.each_ref().map(|q| q.instances.clone()).to_vec(),
            q_proofs: input.q.each_ref().map(|q| q.proof.clone()).to_vec(),
            q_openings: openings,
            signature_schemas: self.signatures.clone(),
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
    objects: [SignedTape; 5],
    variant: Variant,
    sigma: Vec<u8>,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    q_openings: Vec<FoldInput<Ep>>,
    signature_schemas: [QSignaturePlan; 2],
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
struct AssignedMaps {
    blacklist: Option<InsertCells>,
    quota: Option<QuotaRebuildCells>,
}
#[derive(Clone)]
struct Maps {
    witness: RefreshWitness,
    blacklist: Option<IndexedInsert<Fp>>,
    quota: Option<QuotaInput>,
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
    fn assign(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        task: &[OperationTask],
    ) -> Result<AssignedMaps, LayoutError> {
        let blacklist = if task.contains(&OperationTask::RefreshBlacklist) {
            let proof = self.blacklist.ok_or(LayoutError::Synthesis)?;
            let fields = [proof.leaf.key, proof.leaf.value, proof.leaf.next_key];
            let leaf = LeafCells::from_words(
                chip.uint()
                    .glue()
                    .witnesses(r, &fields.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?,
            );
            let mut paths = Vec::new();
            for (index, siblings) in [
                (proof.leaf_slot, proof.leaf_siblings),
                (proof.slot, proof.slot_siblings),
            ] {
                let index = chip
                    .uint()
                    .glue()
                    .witness(r, self.value(Fp::from(u64::from(index))))?;
                let siblings = chip
                    .uint()
                    .glue()
                    .witnesses(r, &siblings.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?;
                paths.push(PathCells::from_words(
                    &mut chip.uint(),
                    r,
                    &index,
                    siblings,
                )?);
            }
            let [low, slot] = paths.try_into().map_err(|_| LayoutError::Synthesis)?;
            Some(InsertCells {
                low: OpeningCells { leaf, path: low },
                slot,
            })
        } else {
            None
        };
        let quota = if task.iter().any(|task| {
            matches!(
                task,
                OperationTask::RefreshQuotaMerge
                    | OperationTask::RefreshQuotaPreviousRoot
                    | OperationTask::RefreshQuotaWindowRoot
                    | OperationTask::RefreshQuotaUsageRoot
            )
        }) {
            let q = self.quota.as_ref().ok_or(LayoutError::Synthesis)?;
            let values = q
                .old
                .iter()
                .flatten()
                .chain(q.windows.iter().flatten())
                .chain(&q.used)
                .chain([&q.issued, &q.window_count])
                .map(|v| self.value(*v))
                .collect::<Vec<_>>();
            let words = chip.uint().glue().witnesses(r, &values)?;
            Some(QuotaRebuildCells {
                old: ::core::array::from_fn(|i| {
                    ::core::array::from_fn(|j| words[4 * i + j].clone())
                }),
                windows: ::core::array::from_fn(|i| {
                    ::core::array::from_fn(|j| words[256 + 4 * i + j].clone())
                }),
                used: ::core::array::from_fn(|i| words[512 + i].clone()),
                issued: words[576].clone(),
                window_count: words[577].clone(),
            })
        } else {
            None
        };
        Ok(AssignedMaps { blacklist, quota })
    }
}
#[derive(Clone)]
struct First {
    source: Arc<Sources>,
    plan: ContextPlan,
    pallas: AccumulatorT<Ep>,
    fold: Vec<u8>,
    known: bool,
}
// Source-only circuit inputs. None is an unknown witness, never an accepted claim.
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
    objects: [SignedTape; 5],
    variant: Variant,
    sigma: Vec<u8>,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    signature_schemas: [QSignaturePlan; 2],
    predecessor: CircuitPredecessor,
    params: PinnedParams<Ep>,
    policy: OwnPolicy,
}
#[derive(Clone)]
struct FirstCircuit {
    source: Arc<CircuitSources>,
    plan: ContextPlan,
    fold: Vec<u8>,
    known: bool,
}
impl First {
    fn circuit(&self) -> FirstCircuit {
        let source = &self.source;
        FirstCircuit {
            source: Arc::new(CircuitSources {
                maps: source.maps.clone(),
                objects: source.objects.clone(),
                variant: source.variant,
                sigma: source.sigma.clone(),
                q_instances: source.q_instances.clone(),
                q_proofs: source.q_proofs.clone(),
                signature_schemas: source.signature_schemas.clone(),
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
#[derive(Clone, Debug)]
/// Fixed Tagged3 verifier, exact byte tape and homogeneous public columns.
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
        let g = chip.witness_point(
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
        let coordinates = input
            .map(|v| Option::<(Fq, Fq)>::from(v.g().coordinates()).ok_or(LayoutError::Synthesis))
            .transpose()?;
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
    fn sigma(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        statement: &StatementCells,
    ) -> Result<SigmaBindingCells, LayoutError> {
        let length =
            u32::try_from(self.source.sigma.len()).map_err(|_| LayoutError::BoundsFailure)?;
        let source = length
            .to_le_bytes()
            .into_iter()
            .chain(self.source.sigma.iter().copied())
            .map(|v| self.value(v))
            .collect::<Vec<_>>();
        let run = bytes.run(
            region,
            &source,
            &source
                .chunks(31)
                .map(<[Value<u8>]>::len)
                .collect::<Vec<_>>(),
            &[SegmentSpec::little(0, 4)],
        )?;
        let index = chip.uint().glue().constant(
            region,
            Fp::from(u64::from(
                super::super::schedule::sigma_selector(7, 0).ok_or(LayoutError::Synthesis)?,
            )),
        )?;
        SigmaBindingCells::from_run(chip, region, statement, index, &run)
    }
}
impl FirstCircuit {
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        stage: usize,
    ) -> Result<RefreshObjects, LayoutError> {
        if RefreshObjects::quota_root_only(&self.plan, stage) {
            let quota = self
                .source
                .maps
                .quota
                .as_ref()
                .ok_or(LayoutError::Synthesis)?;
            let fields = chip
                .uint()
                .glue()
                .witnesses(region, &quota.commitments().map(|v| self.value(v)))?;
            let proposal = QuotaCommitmentCells {
                previous_usage: fields[0].clone(),
                windows: fields[1].clone(),
                successor_usage: fields[2].clone(),
                issued: fields[3].clone(),
                window_count: fields[4].clone(),
            };
            let claims = object_claims_parts(
                &self.source.objects,
                self.source.variant,
                self.source.maps.quota.as_ref(),
            )
            .map_err(|_| LayoutError::Synthesis)?
            .into_iter()
            .map(|triple| triple.map(|v| self.value(v)))
            .collect::<Vec<_>>();
            return RefreshObjects::quota_root_claims(
                chip, region, &self.plan, stage, &claims, &proposal,
            );
        }
        let sources = self
            .source
            .objects
            .each_ref()
            .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        let mut objects = RefreshObjects::decode(
            chip,
            bytes,
            region,
            self.source.variant,
            sources.each_ref().map(Vec::as_slice),
        )?;
        if let Some(quota) = &self.source.maps.quota {
            let fields = chip
                .uint()
                .glue()
                .witnesses(region, &quota.commitments().map(|v| self.value(v)))?;
            let proposal = QuotaCommitmentCells {
                previous_usage: fields[0].clone(),
                windows: fields[1].clone(),
                successor_usage: fields[2].clone(),
                issued: fields[3].clone(),
                window_count: fields[4].clone(),
            };
            objects = objects.with_quota_commitment(chip, region, &proposal)?;
        }
        Ok(objects)
    }
}

impl Circuit<Fp> for FirstCircuit {
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
                .expect("fixed native Refresh Tagged3 profile");
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
        layouter: impl Layouter<Fp>,
    ) -> Result<(), LayoutError> {
        self.synthesize_stage(None, config, layouter)
    }
}
#[derive(Clone)]
struct Continuation {
    first: First,
    plan: SplitPlan,
    wrapper: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    fold: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    carried: AccumulatorT<Ep>,
}

#[derive(Clone)]
struct ContinuationCircuit {
    first: FirstCircuit,
    plan: SplitPlan,
    wrapper: Vec<u8>,
    vesta: Option<AccumulatorT<Eq>>,
    fold: Vec<u8>,
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
impl Circuit<Fp> for ContinuationCircuit {
    type Config = StageConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            first: self.first.without_witnesses(),
            ..self.clone()
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
        self.first.synthesize_stage(Some(self), config, layouter)
    }
}
impl FirstCircuit {
    fn synthesize_stage(
        &self,
        resume: Option<&ContinuationCircuit>,
        config: StageConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), LayoutError> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "complete genuine Refresh stage",
            |mut r| {
                let o = self;
                let stage = resume.map_or(0, |c| c.plan.stage());
                let mut assigned = self.source.maps.clone();
                assigned.known = self.known;
                let source = &o.source;
                let w = &source.maps.witness;
                let (before, previous) = assigned.state(&mut chip, &mut r, &w.predecessor)?;
                let (after, next) = assigned.state(&mut chip, &mut r, &w.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut r, &w.statement.map(|v| o.value(v)))?
                    .try_into()
                    .map_err(|_| LayoutError::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut r,
                    source.variant,
                    &fields,
                )?;
                let sigma = o.sigma(&mut chip, &mut bytes, &mut r, &statement)?;
                let objects = self.objects(&mut chip, &mut bytes, &mut r, stage)?;
                let q_instances = source
                    .q_instances
                    .iter()
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| o.scalar(&mut chip, &mut r, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, LayoutError>>()?;
                let pp = self.pallas(&mut chip, &mut r, self.source.predecessor.pallas.as_ref())?;
                let pv = self.vesta(&mut chip, &mut r, self.source.predecessor.vesta.as_ref())?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &before,
                        public: &previous,
                        pallas: &pp,
                        vesta: &pv,
                    }),
                    successor: ContextState {
                        state: &after,
                        public: &next,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: objects.context(),
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let mut verified = Vec::new();
                let mut signatures = None;
                for &index in self.plan.q_partition(stage).ok_or(LayoutError::Synthesis)? {
                    let proof =
                        o.carrier(&mut chip, &mut bytes, &mut r, &source.q_proofs[index])?;
                    let q = if index == 0 {
                        verify_sigma(
                            &mut chip,
                            &mut r,
                            self.plan.operation(),
                            &q_instances[index],
                            &proof,
                            core::slice::from_ref(&sigma),
                        )?
                        .0
                    } else {
                        let q = super::super::verify_q(
                            &mut chip,
                            &mut r,
                            self.plan.operation(),
                            index,
                            &q_instances[index],
                            &proof,
                        )?;
                        signatures = Some(super::super::bind_signature_q(
                            &mut chip,
                            &mut r,
                            self.plan.operation(),
                            index,
                            &source.signature_schemas[index - 1],
                            &q,
                        )?);
                        q
                    };
                    verified.push(q);
                }
                let maps = assigned.assign(
                    &mut chip,
                    &mut r,
                    self.plan
                        .operation_tasks(stage)
                        .ok_or(LayoutError::Synthesis)?,
                )?;
                RefreshStagePlan::new(self.plan.clone(), self.source.policy)?.constrain_stage(
                    &mut chip,
                    &mut r,
                    stage,
                    &objects,
                    &input,
                    RefreshStageWitness {
                        sigma: self
                            .plan
                            .operation_tasks(stage)
                            .ok_or(LayoutError::Synthesis)?
                            .contains(&OperationTask::RefreshUpdateAuthorization)
                            .then_some(&sigma),
                        signatures: signatures.as_ref(),
                        blacklist: maps.blacklist.as_ref(),
                        quota: maps.quota.as_ref(),
                    },
                )?;
                let fold = o.carrier(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    resume.map_or(self.fold.as_slice(), |c| c.fold.as_slice()),
                )?;
                if let Some(resume) = resume {
                    let cp = self.pallas(&mut chip, &mut r, resume.carried.as_ref())?;
                    let cv = self.vesta(&mut chip, &mut r, resume.vesta.as_ref())?;
                    let wrapper = o.carrier(&mut chip, &mut bytes, &mut r, &resume.wrapper)?;
                    let resumed = super::super::split::resume_context(
                        &mut chip,
                        &mut r,
                        &resume.plan,
                        &input,
                        &cp,
                        &cv,
                        &wrapper,
                        core::slice::from_ref(&sigma),
                    )?;
                    let closed = super::super::split::close_stage(
                        &mut chip,
                        &mut r,
                        &resume.plan,
                        &resumed,
                        None,
                        None,
                        None,
                        &verified,
                        &fold,
                    )?;
                    if resume.plan.is_terminal() {
                        closed.words(&mut chip, &mut r, &next)
                    } else {
                        closed.continuation()?.words(&mut chip, &mut r)
                    }
                } else {
                    let vk = &self.source.predecessor.key;
                    let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *vk.transcript_repr()
                    else {
                        return Err(LayoutError::Synthesis);
                    };
                    let fixed = vk
                        .fixed_commitments()
                        .iter()
                        .map(|p| o.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let permutation = vk
                        .permutation_commitments()
                        .iter()
                        .map(|p| o.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let key = chip.witness_key(&mut r, o.value(repr), &fixed, &permutation)?;
                    let proof = o.carrier(
                        &mut chip,
                        &mut bytes,
                        &mut r,
                        &self.source.predecessor.proof,
                    )?;
                    let pred = verify_predecessor(
                        &mut chip,
                        &mut r,
                        self.plan.operation(),
                        &key,
                        &previous,
                        &next,
                        &pp,
                        &pv,
                        &proof,
                    )?;
                    let first = close_first(
                        &mut chip,
                        &mut r,
                        &self.plan,
                        &input,
                        Some(&pred),
                        &verified,
                        core::slice::from_ref(&sigma),
                        Some(&fold),
                        &self.source.params,
                    )?;
                    first.words(&mut chip, &mut r)
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

/// Checked original source coupled to the fixed complete Refresh plan.
#[derive(Clone)]
pub struct Prepared {
    plan: Plan,
    source: Arc<Sources>,
}
impl Prepared {
    fn first(&self, salt: Fp, config: &FoldConfig) -> Result<First, Error> {
        let (fold, pallas) = create_fold(
            &self.plan.pallas,
            &[
                self.source.predecessor.pallas.as_input(),
                self.source.predecessor.opening.clone(),
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
            plan: self.plan.context.clone(),
            pallas,
            fold: fold.to_bytes().to_vec(),
            known: true,
        })
    }
    /// Build the actual A1 relation and exact public frame from checked originals.
    /// The salt randomizes an actual fold; it does not choose a profile or obligation list.
    /// # Errors
    /// A failed exact predecessor two-input fold or complete decide.
    pub fn first_circuit(
        &self,
        salt: Fp,
        config: &FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>), Error> {
        let first = self.first(salt, config)?;
        let public = first_public(&first)?;
        Ok((
            StageCircuit {
                inner: StageData::First(Box::new(first.circuit())),
            },
            public,
        ))
    }
}

/// Exact installed Refresh verifier metadata without proving buffers.
/// The installation owner authenticates the plan and source catalog. Per-stage
/// import checks compiled source, copy constraints and commitments; each proving
/// call borrows one matching PK and the caller can release it immediately afterward.
pub struct Prover {
    plan: Plan,
    a: Vec<KeyArtifact<Eq>>,
    w: Vec<KeyArtifact<Ep>>,
    wrappers: Vec<WKey>,
}
impl Prover {
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
    /// Installed descriptors in exact alternating A/W checkpoint order.
    #[must_use]
    pub fn descriptors(&self) -> Vec<&DescriptorBinding> {
        let mut out = Vec::with_capacity(self.a.len() + self.w.len());
        for (i, a) in self.a.iter().enumerate() {
            out.push(a.binding());
            if let Some(w) = self.w.get(i) {
                out.push(w.binding());
            }
        }
        out
    }
}

/// Source-bound session over the fixed installed Refresh artifacts.
pub struct Session<'a> {
    prover: &'a Prover,
    prepared: Prepared,
}
impl Session<'_> {
    fn require_source(&self, source: &ACheckpoint) -> Result<(), Error> {
        if source.stage >= self.prover.a.len()
            || !Arc::ptr_eq(&source.first.source, &self.prepared.source)
        {
            return Err(Error::Input);
        }
        Ok(())
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
        salt: Fp,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
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
        let first = self.prepared.first(salt, fold)?;
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
            plan: self.prepared.plan.context.clone(),
            pallas: pallas.clone(),
            fold: vec![],
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
        salt: Fq,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
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
            .ok_or(Error::Artifact)?
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        self.verify_a_cancellable(source, fold.kernel_budget, config.cancellation)?;
        if source.stage + 1 >= self.prover.a.len() {
            return Err(Error::Input);
        }
        let trivial = AccumulatorT::trivial_cancellable(
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
        let (vfold, vesta) = create_fold(
            &self.prepared.plan.vesta,
            &[
                source.part.clone(),
                source.opening.clone(),
                trivial.as_input(),
                trivial.as_input(),
            ],
            salt.to_repr(),
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
                fold: vfold.to_bytes(),
            },
        )
        .map_err(|_| Error::Input)?;
        let public = omega_instances(source.public[0], &vesta)?;
        let output = super::proving::prove(
            &self.prepared.plan.pallas,
            key,
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
        if source.stage + 1 >= self.prover.a.len() {
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
        fold: Vec<u8>,
    ) -> Result<Continuation, Error> {
        self.require_source(&wrapper.source)?;
        let previous = wrapper.source.stage;
        if previous + 1 >= self.prover.a.len() {
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
        salt: Fp,
        fold: &FoldConfig,
        randomness: ProverRandomness<'_>,
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

        let next = wrapper.source.stage.checked_add(1).ok_or(Error::Artifact)?;
        self.prover
            .a
            .get(next)
            .ok_or(Error::Artifact)?
            .require_source_bound(key)
            .map_err(|_| Error::Artifact)?;
        let restored = self.restore_wrapper_cancellable(
            &wrapper.source,
            wrapper.proof.clone(),
            &wrapper.vesta.to_bytes(),
            fold.kernel_budget,
            config.cancellation,
        )?;
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
        let (pfold, pallas) =
            create_fold(&self.prepared.plan.pallas, &claims, salt.to_repr(), fold).map_err(
                |error| {
                    if error.is_cancelled() {
                        Error::Cancelled
                    } else {
                        Error::Proof
                    }
                },
            )?;
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
        let continuation =
            self.continuation(&restored, pallas.clone(), pfold.to_bytes().to_vec())?;
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
    /// Restore any continued A stage from its verified source W and canonical new Pallas claim.
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
        let continuation = self.continuation(&restored, pallas.clone(), vec![])?;
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
    /// Export terminal A and all distinct final Omega obligations after another full native check.
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
        if source.stage + 1 != self.prover.a.len() {
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
/// Actual terminal A proof and every distinct obligation consumed by the final Omega producer.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// Original terminal A proof under its installed key.
    pub proof: Vec<u8>,
    /// Exact homogeneous69-word public frame.
    pub instances: Vec<Fp>,
    /// Full accumulated Pallas claim.
    pub pallas: AccumulatorT<Ep>,
    /// Full Vesta part forwarded by the last W.
    pub vesta_part: AccumulatorT<Eq>,
    /// Full predecessor Vesta obligation, distinct from the current part and A opening.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Actual terminal A own opening, a separate final Omega slot.
    pub opening: FoldInput<Eq>,
}

fn object_kinds(variant: Variant) -> Result<[ObjectKind; 5], Error> {
    let update = match variant {
        Variant::RefreshCredential => ObjectKind::Credential,
        Variant::RefreshSchemePolicy => ObjectKind::SchemePolicy,
        Variant::RefreshBlacklist => ObjectKind::Blacklist,
        Variant::RefreshQuotaShare => ObjectKind::QuotaShare,
        Variant::RefreshTimeAnchor => ObjectKind::TimeAnchor,
        _ => return Err(Error::Artifact),
    };
    Ok([
        ObjectKind::Certificate,
        update,
        ObjectKind::Receipt,
        ObjectKind::Certificate,
        ObjectKind::Credential,
    ])
}

fn check_sigma_tape(input: &Inputs, variant: Variant) -> Result<(), Error> {
    let bounded = input.q[0].instances.first().ok_or(Error::Input)?;
    let mut raw = u32::try_from(input.sigma.len())
        .map_err(|_| Error::Input)?
        .to_le_bytes()
        .to_vec();
    raw.extend(&input.sigma);
    let chunks = raw
        .chunks(31)
        .map(|chunk| le_value::<Fq>(chunk).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    let statement = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &input.state.statement,
    );
    let statement = Option::<Fq>::from(Fq::from_repr(statement.to_repr())).ok_or(Error::Input)?;
    if bounded.len() != 1 + chunks.len() + K
        || bounded[0] != statement
        || bounded[1..=chunks.len()] != chunks
        || input.q[0].instances.get(2).map(Vec::as_slice) != Some(&[sigma_selector(variant)?])
    {
        return Err(Error::Input);
    }
    Ok(())
}

fn q_sigma_part(input: &QInput, source_k: u32, variant: Variant) -> Result<FoldInput<Eq>, Error> {
    let [bounded, point, indices, verdicts, source] = input.instances.as_slice() else {
        return Err(Error::Input);
    };
    if point.len() != 2
        || indices.len() != 1
        || indices.as_slice() != [sigma_selector(variant)?]
        || verdicts.as_slice() != [Fq::ONE]
        || source.as_slice() != [Fq::from(u64::from(source_k))]
        || bounded.len() < K
    {
        return Err(Error::Input);
    }
    let g = Option::<EqAffine>::from(EqAffine::from_xy(point[0], point[1])).ok_or(Error::Input)?;
    let challenges = bounded[bounded.len() - K..]
        .iter()
        .map(|v| Option::<Fp>::from(Fp::from_repr(v.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    FoldInput::from_normalized(
        g,
        source_k,
        challenges.try_into().map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)
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
fn vesta_words(claim: &FoldInput<Eq>) -> Result<Vec<Fp>, Error> {
    let (x, y) = Option::<(Fq, Fq)>::from(claim.g().coordinates()).ok_or(Error::Input)?;
    let mut words = Vec::with_capacity(20);
    for value in [x, y] {
        words.extend(foreign_limbs(&value).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    Ok(words)
}

fn object_claims_parts(
    objects: &[SignedTape; 5],
    variant: Variant,
    quota: Option<&QuotaInput>,
) -> Result<Vec<[Fp; 3]>, Error> {
    let mut words = Vec::new();
    for (object, spec) in objects
        .iter()
        .zip(RefreshObjects::context_specs(variant).map_err(|_| Error::Artifact)?)
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
        words.push([
            object.digest()?,
            Fp::from(u64::from(spec.capacity)),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
    }
    if let Some(quota) = quota {
        let mut framed = vec![Fp::from(6), Fp::from(5)];
        framed.extend(quota.commitments());
        let digest = hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &framed);
        words.push([digest, Fp::from(160), digest]);
    }
    Ok(words)
}

fn object_claims(source: &Sources) -> Result<Vec<[Fp; 3]>, Error> {
    object_claims_parts(&source.objects, source.variant, source.maps.quota.as_ref())
}

fn context_digest(first: &First) -> Result<Fp, Error> {
    let source = &first.source;
    let mut words = first.plan.schema().to_vec();
    words.extend(source.maps.witness.statement);
    let old = &source.maps.witness.predecessor;
    let new = &source.maps.witness.successor;
    words.extend(old.core);
    words.extend(old.rest);
    words.extend(old.lineage);
    push_pallas(&mut words, &source.predecessor.pallas.as_input())?;
    words.extend(vesta_words(&source.predecessor.vesta.as_input())?);
    words.extend(new.core);
    words.extend(new.rest);
    words.extend(new.lineage);
    for value in source.q_instances.iter().flatten().flatten() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    words.extend(object_claims(source)?.into_iter().flatten());
    Ok(hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words))
}

fn trivial_vesta_words() -> Result<Vec<Fp>, Error> {
    let g = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .map_err(|_| Error::Artifact)?;
    let claim =
        FoldInput::<Eq>::from_normalized(g, 16, [Fp::ONE; K]).map_err(|_| Error::Artifact)?;
    vesta_words(&claim)
}
fn internal_public(digest: Fp, part: &FoldInput<Eq>) -> Result<Vec<Fp>, Error> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part)?);
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
            &c.first.source.maps.witness.successor.lineage,
            &c.pallas.as_input(),
        )?,
        Fp::from(16),
    ];
    words.extend(vesta_words(&c.vesta.as_input())?);
    words.extend(vesta_words(&c.first.source.predecessor.vesta.as_input())?);
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
    let (x, y) = Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Input)?;
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
    randomness: ProverRandomness<'_>,
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

fn sigma_selector(variant: Variant) -> Result<Fq, Error> {
    object_kinds(variant)?;
    super::super::schedule::sigma_selector(7, 0)
        .map(|index| Fq::from(u64::from(index)))
        .ok_or(Error::Artifact)
}

/// Exact signed-body projection for the fixed union sigma. This only parses
/// already required original fields; all issuer/signature authority remains in A.
fn check_update_projection(
    variant: Variant,
    actual: &crate::admin_sigma::RefreshUpdateWitness,
    raw: &[u8],
) -> Result<(), Error> {
    use crate::admin_sigma::RefreshKind;
    let (kind, schema): (_, &[usize]) = match variant {
        Variant::RefreshCredential => (
            ObjectKind::Credential,
            &[
                2, 32, 32, 32, 32, 65, 32, 1, 32, 8, 4, 4, 4, 4, 32, 8, 4, 4, 4, 4, 32, 4, 8, 8,
                32, 8, 4, 8, 32,
            ],
        ),
        Variant::RefreshSchemePolicy => (ObjectKind::SchemePolicy, &[2, 32, 32, 8, 4, 32, 32]),
        Variant::RefreshBlacklist => (ObjectKind::Blacklist, &[2, 32, 8, 8, 4, 32, 32]),
        Variant::RefreshQuotaShare => {
            (ObjectKind::QuotaShare, &[2, 32, 32, 32, 8, 8, 8, 32, 4, 32])
        }
        Variant::RefreshTimeAnchor => (ObjectKind::TimeAnchor, &[2, 32, 32, 32, 8, 32]),
        _ => return Err(Error::Input),
    };
    if raw.len() != kind.body_len() + 64 || raw[..2] != [1, 0] {
        return Err(Error::Input);
    }
    let mut offsets = vec![0];
    for n in schema {
        offsets.push(offsets.last().copied().ok_or(Error::Input)? + n);
    }
    if offsets.last().copied() != Some(kind.body_len()) {
        return Err(Error::Input);
    }
    let word = |i: usize| -> Result<Fp, Error> {
        let bytes = &raw[offsets[i]..offsets[i + 1]];
        if bytes.len() > 32 {
            return Err(Error::Input);
        }
        let mut repr = [0; 32];
        repr[..bytes.len()].copy_from_slice(bytes);
        Fp::from_repr(repr).into_option().ok_or(Error::Input)
    };
    let id = |i: usize| -> Result<[Fp; 2], Error> {
        let bytes = &raw[offsets[i]..offsets[i + 1]];
        if bytes.len() != 32 {
            return Err(Error::Input);
        }
        Ok([
            Fp::from_u128(u128::from_le_bytes(
                bytes[..16].try_into().map_err(|_| Error::Input)?,
            )),
            Fp::from_u128(u128::from_le_bytes(
                bytes[16..].try_into().map_err(|_| Error::Input)?,
            )),
        ])
    };
    let mut expected = crate::admin_sigma::RefreshUpdateWitness {
        kind: RefreshKind::Credential,
        digest: object_digest(kind, raw)?,
        scheme: [Fp::ZERO; 2],
        asset: [Fp::ZERO; 2],
        wallet: [Fp::ZERO; 2],
        counter: Fp::ZERO,
        issued_at_ms: Fp::ZERO,
        expires_at_ms: Fp::ZERO,
        root: Fp::ZERO,
        controls: Fp::ZERO,
        fee_schedule: Fp::ZERO,
    };
    match variant {
        Variant::RefreshCredential => {
            expected.issued_at_ms = word(25)?;
            expected.expires_at_ms = word(27)?;
        }
        Variant::RefreshSchemePolicy => {
            expected.kind = RefreshKind::SchemePolicy;
            expected.scheme = id(1)?;
            expected.asset = id(2)?;
            expected.counter = word(3)?;
            expected.controls = word(4)?;
            expected.fee_schedule = word(5)?;
        }
        Variant::RefreshBlacklist => {
            expected.kind = RefreshKind::Blacklist;
            expected.scheme = id(1)?;
            expected.counter = word(2)?;
            expected.issued_at_ms = word(3)?;
            expected.root = word(5)?;
        }
        Variant::RefreshQuotaShare => {
            expected.kind = RefreshKind::QuotaShare;
            expected.scheme = id(1)?;
            expected.asset = id(2)?;
            expected.wallet = id(3)?;
            expected.counter = word(4)?;
            expected.issued_at_ms = word(5)?;
            expected.expires_at_ms = word(6)?;
            expected.root = word(7)?;
        }
        Variant::RefreshTimeAnchor => {
            expected.kind = RefreshKind::TimeAnchor;
            expected.scheme = id(1)?;
            expected.wallet = id(2)?;
            expected.issued_at_ms = word(4)?;
        }
        _ => return Err(Error::Input),
    }
    if actual.kind != expected.kind
        || actual.digest != expected.digest
        || actual.scheme != expected.scheme
        || actual.asset != expected.asset
        || actual.wallet != expected.wallet
        || actual.counter != expected.counter
        || actual.issued_at_ms != expected.issued_at_ms
        || actual.expires_at_ms != expected.expires_at_ms
        || actual.root != expected.root
        || actual.controls != expected.controls
        || actual.fee_schedule != expected.fee_schedule
    {
        return Err(Error::Input);
    }
    Ok(())
}
