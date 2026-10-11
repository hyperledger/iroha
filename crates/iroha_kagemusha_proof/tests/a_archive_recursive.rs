//! Complete genuine `ArchiveReceive` owner chain and same-original no-op evidence.
//!
//! The predecessor requires genuine installed native-BLS-authorized Load originals.
//! The explicit ignored entry points use fresh originals for each reconstructed
//! predecessor; compilation is not proof qualification.
#![allow(clippy::duplicate_mod)]
#[path = "common/archive_objects.rs"]
mod archive_objects;
#[path = "common/archive_q.rs"]
mod archive_q;
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "compact_catalog.rs"]
/// Shared genuine compact predecessor fixtures; never release-catalog admission.
pub mod compact_catalog;
#[path = "a_archive_recursive/native_load_tests.rs"]
mod native_load_tests;
#[path = "common/receive_objects.rs"]
#[allow(dead_code)]
mod receive_objects;
#[path = "common/send_objects.rs"]
#[allow(dead_code)]
mod send_objects;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::a_relation::native::{archive as native, artifact::KeyArtifact};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, LineagePublicCells, ProofMessageCells, SigmaBindingCells, VestaClaimCells,
        archive::{
            authorization::ArchiveAuthorizationObjects,
            evidence::ArchiveEvidenceSource,
            incoming::ArchiveIncomingObjects,
            maps::ArchivePendingWitness,
            proofs::{ArchiveProofInputs, ArchiveProofSources},
            results::{ArchiveResultClaims, ArchiveResultTag},
            retained::{ArchiveRetainedPayment, ArchiveRetainedProofs, ArchiveRetainedSources},
            stage::{ArchiveStageInputs, ArchiveStagePlan, ArchiveStageWitness},
        },
        bind_signature_q, bounded_word,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        schedule::OperationTask,
        split::{self, SplitPlan, WCircuit, WKey},
        verify_predecessor, verify_q, verify_sigma,
    },
    admin_sigma::StateWitness,
    operation_relation::{
        incoming_statement::IncomingStatementCells, map_effects::RemoveCells, state::StateCells,
        statement::StatementCells,
    },
    tree::IndexedRemove,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, VerifyingKey, Witness,
    check::{CheckMode, check, check_circuit},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::verify_full,
};
use iroha_plonk_gadgets::{
    UintChip, Word,
    bytes::{
        chunk_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
        variable::ActiveBytes,
    },
    imt::{LeafCells, OpeningCells, PathCells},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::{ModeCells, ledger::Variant},
    verifier::{VerifierChip, VerifierConfig, VerifierKeyCells, VerifierPlan},
};
use std::sync::Arc;

#[derive(Clone, Copy)]
struct Cells {
    known: bool,
}
impl Cells {
    fn value<T: Copy>(self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn bytes(self, source: &[u8]) -> Vec<Value<u8>> {
        source.iter().map(|v| self.value(*v)).collect()
    }
    fn words<const N: usize>(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        values: &[Fp; N],
    ) -> Result<[Word<Fp>; N], Error> {
        chip.uint()
            .glue()
            .witnesses(region, &values.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
    fn scalar(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: Fq,
    ) -> Result<ScalarCells<Ep>, Error> {
        let [low, high] = foreign_limbs(&value);
        let low = chip.uint().assign::<128>(region, self.value(low))?;
        let high = chip.uint().assign::<127>(region, self.value(high))?;
        ScalarCells::from_limbs(&mut chip.uint(), region, &low, &high)
    }
    fn pallas(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: &FoldInput<Ep>,
    ) -> Result<FoldInputCells<Ep>, Error> {
        let point = chip.witness_point(region, self.value(Ep::from(*value.g())))?;
        let scalars = value
            .challenges()
            .iter()
            .map(|v| self.scalar(chip, region, *v))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        FoldInputCells::from_normalized(chip, region, value.source_k(), point, scalars)
    }
    fn vesta(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: &AccumulatorT<Eq>,
    ) -> Result<VestaClaimCells, Error> {
        let (x, y) = Option::from(value.g().coordinates()).ok_or(Error::Synthesis)?;
        let coordinates = [self.scalar(chip, region, x)?, self.scalar(chip, region, y)?];
        let challenges = self.words(chip, region, value.challenges())?;
        VestaClaimCells::constrain(chip, region, 16, coordinates, challenges)
    }
    fn state(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        state: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = self.words(chip, region, &state.core)?;
        let rest = self.words(chip, region, &state.rest)?;
        let state_cells = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = self.words(chip, region, &state.lineage)?;
        Ok((
            state_cells,
            LineagePublicCells::constrain(&mut chip.uint(), region, &public)?,
        ))
    }
    fn proof(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        raw: &[u8],
    ) -> Result<ProofMessageCells, Error> {
        if !raw.len().is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let length = chip.uint().assign::<32>(
            region,
            self.value(u128::try_from(raw.len()).map_err(|_| Error::BoundsFailure)?),
        )?;
        let messages = raw
            .chunks_exact(32)
            .map(|chunk| {
                iroha_plonk_gadgets::bytes::element::LeElement::assign(
                    &mut chip.uint(),
                    region,
                    self.value(chunk.try_into().map_err(|_| Error::Synthesis)?),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(ProofMessageCells::from_messages(Vec::new(), length.clone()).is_err());
        ProofMessageCells::from_messages(messages, length)
    }
    fn key(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        key: &VerifyingKey<Ep>,
    ) -> Result<VerifierKeyCells<Ep>, Error> {
        let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *key.transcript_repr() else {
            return Err(Error::Synthesis);
        };
        let fixed = key
            .fixed_commitments()
            .iter()
            .map(|p| self.value(Ep::from(*p)))
            .collect::<Vec<_>>();
        let permutation = key
            .permutation_commitments()
            .iter()
            .map(|p| self.value(Ep::from(*p)))
            .collect::<Vec<_>>();
        chip.witness_key(region, self.value(repr), &fixed, &permutation)
    }
    fn active(
        self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        raw: &[u8],
        capacity: usize,
        segments: &[SegmentSpec],
    ) -> Result<ActiveBytes<Fp>, Error> {
        let values = if self.known {
            Value::known(raw.to_vec())
        } else {
            Value::unknown()
        };
        ActiveBytes::assign(&mut chip.uint(), bytes, region, capacity, &values, segments)
    }
    fn removal(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: &IndexedRemove<Fp>,
    ) -> Result<RemoveCells, Error> {
        let mut openings = Vec::new();
        for (leaf, slot, siblings) in [
            (
                value.predecessor,
                value.predecessor_slot,
                value.predecessor_siblings,
            ),
            (value.leaf, value.slot, value.leaf_siblings),
        ] {
            let words = self.words(chip, region, &[leaf.key, leaf.value, leaf.next_key])?;
            let index = chip
                .uint()
                .glue()
                .witness(region, self.value(Fp::from(u64::from(slot))))?;
            let siblings = self.words(chip, region, &siblings)?;
            let path = PathCells::from_words(&mut chip.uint(), region, &index, siblings)?;
            openings.push(OpeningCells {
                leaf: LeafCells::from_words(words),
                path,
            });
        }
        let [predecessor, removed] = openings.try_into().map_err(|_| Error::Synthesis)?;
        Ok(RemoveCells {
            predecessor,
            removed,
        })
    }
}

#[derive(Clone)]
struct Continuation {
    plan: SplitPlan,
    proof: Vec<u8>,
    carried: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
struct Stage {
    source: Arc<archive_q::ArchiveSource>,
    plan: ArchiveStagePlan,
    continuation: Option<Continuation>,
    pallas: AccumulatorT<Ep>,
    fold: Vec<u8>,
    known: bool,
    omit_q: Option<usize>,
    mutate_context: Option<(usize, usize)>,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Stage {
    fn result_words(&self) -> [Fp; 11] {
        let p = self.plan.results();
        [
            Fp::ONE,
            Fp::ONE,
            Fp::ONE,
            Fp::from(u64::from(p.owner(ArchiveResultTag::Proofs))),
            Fp::from(2),
            Fp::from(u64::from(p.owner(ArchiveResultTag::Evidence))),
            Fp::from(3),
            Fp::from(u64::from(p.owner(ArchiveResultTag::Signatures))),
            Fp::from(u64::from(self.source.valid)),
            Fp::ONE,
            Fp::ONE,
        ]
    }
    fn mode_words(&self) -> [Fp; 3] {
        [
            Fp::from(u64::from(self.source.valid)),
            Fp::from(u64::from(!self.source.valid)),
            Fp::ZERO,
        ]
    }
}
impl Circuit<Fp> for Stage {
    type Config = Config;
    type Params = usize;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> usize {
        if self
            .continuation
            .as_ref()
            .is_some_and(|c| c.plan.is_terminal())
        {
            native::TERMINAL_RANGE_BUSES
        } else {
            native::INTERNAL_RANGE_BUSES
        }
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, native::INTERNAL_RANGE_BUSES)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, buses: usize) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, buses).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(69);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let cells = Cells { known: self.known };
        let s = &self.source;
        let plan = self.plan.context();
        let stage = self.continuation.as_ref().map_or(0, |c| c.plan.stage());
        let tasks = plan.operation_tasks(stage).ok_or(Error::Synthesis)?;
        let out = layouter.assign_region(
            || "Archive exact source owners",
            |mut region| {
                let (old, pred_public) =
                    cells.state(&mut chip, &mut region, &s.archive.witness.predecessor)?;
                let (new, next_public) =
                    cells.state(&mut chip, &mut region, &s.archive.witness.successor)?;
                let fields = cells.words(&mut chip, &mut region, &s.archive.witness.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::ArchiveReceive,
                    &fields,
                )?;
                let fields = cells.words(&mut chip, &mut region, &s.incoming_statement)?;
                let lanes = chip.operation_lanes()?;
                let incoming_statement = IncomingStatementCells::constrain(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    Variant::Receive,
                    &fields,
                )?;
                let q_instances =
                    s.q.iter()
                        .map(|q| {
                            q.instances
                                .iter()
                                .map(|col| {
                                    col.iter()
                                        .map(|v| cells.scalar(&mut chip, &mut region, *v))
                                        .collect()
                                })
                                .collect()
                        })
                        .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let mut triples = s.context_triples(&self.result_words());
                if let Some((slot, word)) = self.mutate_context {
                    triples[slot][word] += Fp::ONE;
                }
                let values = triples.map(|words| words.map(|v| cells.value(v)));
                let context = plan.assign_archive_object_claims(&mut chip, &mut region, &values)?;
                let results = ArchiveResultClaims::assign(
                    &mut chip,
                    &mut region,
                    self.plan.results(),
                    [cells.value(s.valid), cells.value(true), cells.value(true)],
                    None,
                )?;
                let pp = cells.pallas(
                    &mut chip,
                    &mut region,
                    &s.predecessor.source.pallas.as_input(),
                )?;
                let pv = cells.vesta(&mut chip, &mut region, &s.predecessor.vesta)?;
                let modes = cells.words(&mut chip, &mut region, &self.mode_words())?;
                let modes = [ModeCells::constrain(
                    chip.uint().glue(),
                    &mut region,
                    &modes,
                )?];
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: Some(&incoming_statement),
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
                    objects: &context,
                    modes: &modes,
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let indices = [0, 1]
                    .map(|slot| bounded_word(&mut chip, &mut region, &q_instances[0][2][slot]));
                let [own_index, incoming_index] = indices;
                let own_index = own_index?;
                let incoming_index = incoming_index?;
                let chunks = [0, 1].map(|slot| {
                    s.sigma_plan
                        .chunk_range(slot)
                        .ok_or(Error::Synthesis)?
                        .map(|i| bounded_word(&mut chip, &mut region, &q_instances[0][0][i]))
                        .collect::<Result<Vec<_>, _>>()
                });
                let [own_chunks, incoming_chunks] = chunks;
                let mut own_sigma =
                    SigmaBindingCells::from_statement(&statement, own_index.clone(), own_chunks?);
                let mut incoming_sigma = SigmaBindingCells::from_incoming(
                    &incoming_statement,
                    incoming_index.clone(),
                    incoming_chunks?,
                );
                if tasks.contains(&OperationTask::ArchiveOwnProof) {
                    let raw = frame(&s.own_sigma);
                    let run = bytes.run(
                        &mut region,
                        &cells.bytes(&raw),
                        &chunk_segments(0, raw.len()),
                        &[SegmentSpec::little(0, 4)],
                    )?;
                    own_sigma = SigmaBindingCells::from_run(
                        &mut chip,
                        &mut region,
                        &statement,
                        own_index,
                        &run,
                    )?;
                }
                let proof_source = if tasks.contains(&OperationTask::ArchiveProofs) {
                    let proof_bytes = s
                        .sigma_plan
                        .class(1)
                        .ok_or(Error::Synthesis)?
                        .verifier()
                        .proof_length();
                    let raw = cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &s.incoming_sigma,
                        plan.object_specs()[13].capacity as usize,
                        &SigmaBindingCells::incoming_segments(proof_bytes)?,
                    )?;
                    incoming_sigma = SigmaBindingCells::from_incoming_active(
                        &mut chip,
                        &mut region,
                        &incoming_statement,
                        incoming_index,
                        &raw,
                        proof_bytes,
                    )?;
                    Some(ArchiveProofSources::receive(&incoming_sigma, 13)?)
                } else {
                    None
                };
                let sigmas = [own_sigma.clone(), incoming_sigma];
                let own = if tasks.contains(&OperationTask::ArchiveOwnProof)
                    || tasks.contains(&OperationTask::ArchiveAuthorization)
                {
                    let raw = s.own.each_ref().map(|v| cells.bytes(&v.bytes));
                    Some(ArchiveAuthorizationObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        Variant::ArchiveReceive,
                        raw.each_ref().map(Vec::as_slice),
                    )?)
                } else {
                    None
                };
                let retained_proofs = if tasks.contains(&OperationTask::ArchiveRetainedProofs) {
                    let omega = cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &s.predecessor.source.predecessor_omega,
                        plan.object_specs()[9].capacity as usize,
                        &[],
                    )?;
                    let sigma = cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &s.predecessor.source.sigma,
                        plan.object_specs()[10].capacity as usize,
                        &[],
                    )?;
                    Some(ArchiveRetainedProofs::from_sources(
                        &mut chip,
                        &mut region,
                        &omega,
                        &sigma,
                    )?)
                } else {
                    None
                };
                let retained = if tasks.contains(&OperationTask::ArchiveRetainedPayment) {
                    let signed = s.retained.each_ref().map(|v| cells.bytes(v));
                    let payment = cells.bytes(&s.payment);
                    let words = cells.words(
                        &mut chip,
                        &mut region,
                        &s.predecessor.source.maps.witness.statement,
                    )?;
                    Some(ArchiveRetainedPayment::from_committed_proofs(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        s.policy,
                        ArchiveRetainedSources {
                            signed: signed.each_ref().map(Vec::as_slice),
                            payment: &payment,
                        },
                        &words,
                        (plan, &input),
                    )?)
                } else {
                    None
                };
                let incoming = if tasks.contains(&OperationTask::ArchiveEvidence)
                    || tasks.contains(&OperationTask::ArchiveSignatures)
                {
                    let raw = s.incoming.each_ref().map(|v| cells.bytes(v));
                    Some(ArchiveIncomingObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        raw.each_ref().map(Vec::as_slice),
                    )?)
                } else {
                    None
                };
                let resumed = if let Some(c) = &self.continuation {
                    let cp = cells.pallas(&mut chip, &mut region, &c.carried.as_input())?;
                    let cv = cells.vesta(&mut chip, &mut region, &c.vesta)?;
                    let proof = cells.proof(&mut chip, &mut region, &c.proof)?;
                    Some(split::resume_context(
                        &mut chip,
                        &mut region,
                        &c.plan,
                        &input,
                        &cp,
                        &cv,
                        &proof,
                        &sigmas,
                    )?)
                } else {
                    None
                };
                let pred = if self.continuation.is_none() {
                    let key = cells.key(&mut chip, &mut region, &s.predecessor.key)?;
                    let proof = cells.proof(&mut chip, &mut region, &s.predecessor.proof)?;
                    Some(verify_predecessor(
                        &mut chip,
                        &mut region,
                        plan.operation(),
                        &key,
                        &pred_public,
                        &next_public,
                        &pp,
                        &pv,
                        &proof,
                    )?)
                } else {
                    None
                };
                let mut verified = Vec::new();
                let mut own_signatures = None;
                let mut incoming_signatures = None;
                for &index in plan.q_partition(stage).ok_or(Error::Synthesis)? {
                    if self.omit_q == Some(index) {
                        continue;
                    }
                    let proof = cells.proof(&mut chip, &mut region, &s.q[index].proof)?;
                    if index == 0 {
                        verified.push(
                            verify_sigma(
                                &mut chip,
                                &mut region,
                                plan.operation(),
                                &q_instances[index],
                                &proof,
                                &sigmas,
                            )?
                            .0,
                        );
                    } else {
                        let q = verify_q(
                            &mut chip,
                            &mut region,
                            plan.operation(),
                            index,
                            &q_instances[index],
                            &proof,
                        )?;
                        let signatures = bind_signature_q(
                            &mut chip,
                            &mut region,
                            plan.operation(),
                            index,
                            self.plan.signature_schema(index).ok_or(Error::Synthesis)?,
                            &q,
                        )?;
                        verified.push(signatures.verified().clone());
                        if index == 1 {
                            own_signatures = Some(signatures);
                        } else {
                            incoming_signatures = Some(signatures);
                        }
                    }
                }
                let credited = cells.bytes(&s.credited);
                let mut pending = vec![None, None].into_boxed_slice();
                for (index, task) in [
                    OperationTask::ArchiveCorePending,
                    OperationTask::ArchiveLineagePending,
                ]
                .into_iter()
                .enumerate()
                {
                    if !tasks.contains(&task) {
                        continue;
                    }
                    pending[index] = Some(ArchivePendingWitness {
                        descriptor: cells.words(&mut chip, &mut region, &s.archive.descriptor)?,
                        removal: cells.removal(
                            &mut chip,
                            &mut region,
                            &s.archive.removals[index],
                        )?,
                    });
                }
                self.plan.constrain_stage(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                    ArchiveStageInputs {
                        context: &input,
                        results: &results,
                        own: own.as_ref(),
                        retained: retained.as_ref(),
                        retained_proofs: retained_proofs.as_ref(),
                        incoming: incoming.as_ref(),
                        sigma: tasks
                            .contains(&OperationTask::ArchiveOwnProof)
                            .then_some(&own_sigma),
                        proof_source: proof_source.as_ref(),
                    },
                    ArchiveStageWitness {
                        own_signatures: own_signatures.as_ref(),
                        incoming_signatures: incoming_signatures.as_ref(),
                        proof: tasks
                            .contains(&OperationTask::ArchiveProofs)
                            .then_some(ArchiveProofInputs::Receive(&own_sigma)),
                        evidence: tasks.contains(&OperationTask::ArchiveEvidence).then_some(
                            ArchiveEvidenceSource::Receive {
                                credited: &credited,
                            },
                        ),
                        core_pending: pending[0].as_ref(),
                        lineage_pending: pending[1].as_ref(),
                    },
                )?;
                let fold = cells.proof(&mut chip, &mut region, &self.fold)?;
                if let (Some(c), Some(resumed)) = (&self.continuation, resumed) {
                    let closed = split::close_stage(
                        &mut chip,
                        &mut region,
                        &c.plan,
                        &resumed,
                        None,
                        None,
                        None,
                        &verified,
                        &fold,
                    )?;
                    if c.plan.is_terminal() {
                        closed.words(&mut chip, &mut region, &next_public)
                    } else {
                        closed.continuation()?.words(&mut chip, &mut region)
                    }
                } else {
                    split::close_first(
                        &mut chip,
                        &mut region,
                        plan,
                        &input,
                        pred.as_ref(),
                        &verified,
                        &sigmas,
                        Some(&fold),
                        &PinnedParams::<Ep>::derive(16).map_err(|_| Error::Synthesis)?,
                    )?
                    .words(&mut chip, &mut region)
                }
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
fn frame(raw: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(raw);
    out
}
fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) {
    words.push(Fp::from(u64::from(claim.source_k())));
    let (x, y) = claim.g().coordinates().unwrap();
    words.extend([x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = claim.g().coordinates().unwrap();
    let mut words = Vec::new();
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}
fn internal_public(digest: Fp, part: &FoldInput<Eq>) -> Vec<Vec<Fp>> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part));
    let trivial =
        AccumulatorT::<Eq>::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
    let trivial = vesta_words(&trivial.as_input());
    words.extend(&trivial);
    words.extend(&trivial);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&trivial[..4]);
    assert_eq!(words.len(), 69);
    vec![words]
}
fn stage_digest(plan: &ContextPlan, stage: usize, context: Fp, current: &AccumulatorT<Ep>) -> Fp {
    assert!(stage + 1 < plan.stage_count());
    let mut words = vec![
        Fp::ONE,
        plan.schema()[1],
        Fp::from((stage + 1) as u64),
        context,
    ];
    push_pallas(&mut words, &current.as_input());
    hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
}
impl Stage {
    fn context_digest(&self) -> Fp {
        let s = &self.source;
        let mut words = self.plan.context().schema().to_vec();
        words.extend(s.archive.witness.statement);
        words.extend(s.incoming_statement);
        let before = &s.archive.witness.predecessor;
        words.extend(before.core);
        words.extend(before.rest);
        words.extend(before.lineage);
        push_pallas(&mut words, &s.predecessor.source.pallas.as_input());
        words.extend(vesta_words(&s.predecessor.vesta.as_input()));
        let after = &s.archive.witness.successor;
        words.extend(after.core);
        words.extend(after.rest);
        words.extend(after.lineage);
        for q in &s.q {
            for v in q.instances.iter().flatten() {
                words.extend(foreign_limbs(v).map(Fp::from_u128));
            }
        }
        let mut triples = s.context_triples(&self.result_words());
        if let Some((slot, word)) = self.mutate_context {
            triples[slot][word] += Fp::ONE;
        }
        words.extend(triples.into_iter().flatten());
        words.extend(self.mode_words());
        hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words)
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let Some(c) = &self.continuation else {
            return internal_public(
                stage_digest(self.plan.context(), 0, self.context_digest(), &self.pallas),
                &self.source.part,
            );
        };
        if c.plan.is_terminal() {
            let mut lineage = self.source.archive.witness.successor.lineage.to_vec();
            let (x, y) = self.pallas.g().coordinates().unwrap();
            lineage.extend([x, y]);
            for v in self.pallas.challenges() {
                lineage.extend(foreign_limbs(v).map(Fp::from_u128));
            }
            let digest = hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &lineage);
            let mut words = vec![digest, Fp::from(16)];
            words.extend(vesta_words(&c.vesta.as_input()));
            words.extend(vesta_words(&self.source.predecessor.vesta.as_input()));
            let trivial =
                AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
            let trivial = vesta_words(&trivial.as_input());
            words.extend(&trivial);
            words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
            words.extend(&trivial[..4]);
            assert_eq!(words.len(), 69);
            return vec![words];
        }
        let digest = stage_digest(
            self.plan.context(),
            c.plan.stage(),
            self.context_digest(),
            &self.pallas,
        );
        internal_public(digest, &c.vesta.as_input())
    }
}

fn first(source: archive_q::ArchiveSource) -> Stage {
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let operation = AProofPlan::new(
        Variant::ArchiveReceive,
        source.sigma_plan.clone(),
        source.q.iter().map(|q| q.plan.clone()).collect(),
        Some(VerifierPlan::new(source.predecessor.binding.clone(), params.clone()).unwrap()),
        &params,
    )
    .unwrap();
    let plan = ArchiveStagePlan::full(operation, source.policy).unwrap();
    assert_eq!(plan.context().object_specs(), source.specs);
    let (fold, pallas) = create_fold(
        &params,
        &[
            source.predecessor.source.pallas.as_input(),
            source.predecessor.opening.clone(),
        ],
        Fp::from(191).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    pallas.decide(&params, MemoryBudget::DEFAULT).unwrap();
    Stage {
        source: Arc::new(source),
        plan,
        continuation: None,
        pallas,
        fold: fold.to_bytes().to_vec(),
        known: true,
        omit_q: None,
        mutate_context: None,
    }
}

fn native_inputs(source: &archive_q::ArchiveSource) -> native::Inputs {
    native::Inputs {
        state: source.archive.witness,
        removals: source.archive.removals,
        own: source.own.each_ref().map(|s| s.bytes.clone()),
        sigma: source.own_sigma.clone(),
        retained: native::RetainedPayment {
            signed: source.retained.clone(),
            payment: source.payment.clone(),
            statement: source.predecessor.source.maps.witness.statement,
            omega: source.predecessor.source.predecessor_omega.clone(),
            sigma: source.predecessor.source.sigma.clone(),
        },
        evidence: native::Evidence::Receive {
            statement: source.incoming_statement,
            receipt: source.incoming[2].clone(),
            sigma: source.incoming_sigma.clone(),
            credited: source.credited.clone(),
            mode: if source.valid {
                iroha_kagemusha_proof::q_sigma::native::IncomingMode::Accept
            } else {
                iroha_kagemusha_proof::q_sigma::native::IncomingMode::Trivial
            },
        },
        results: [source.valid, true, true],
        q: source.q.each_ref().map(|q| native::QInput {
            proof: q.proof.clone(),
            instances: q.instances.clone(),
        }),
        predecessor: native::PredecessorInput {
            proof: source.predecessor.proof.clone(),
            pallas: source.predecessor.source.pallas.to_bytes(),
            vesta: source.predecessor.vesta.to_bytes(),
        },
    }
}

fn native_plan(stage: &Stage) -> native::Plan {
    native::Plan::new(
        stage.plan.context().operation().clone(),
        stage.source.policy,
        stage.source.predecessor.key.clone(),
        PinnedParams::derive(16).unwrap(),
        common::vesta_params(16),
    )
    .unwrap()
}

fn compare_native_source(stage: &Stage, circuit: &native::StageCircuit, public: &[Fp]) {
    assert_eq!(stage.public(), vec![public.to_vec()]);
    let actual = synthesize(circuit, 16, Some(&[public.to_vec()])).unwrap();
    assert!(
        check(&actual.cs, &actual.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let reference = synthesize(stage, 16, Some(&stage.public())).unwrap();
    assert_eq!(actual.tables.fixed(), reference.tables.fixed());
    assert_eq!(actual.tables.permutation(), reference.tables.permutation());
    assert_eq!(
        actual.tables.advice_assigned(),
        reference.tables.advice_assigned()
    );
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(actual.tables.fixed(), unknown.tables.fixed());
    assert_eq!(actual.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        actual.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
}

fn replay_native_checkpoints(
    prover: &native::Prover,
    input: native::Inputs,
    retained: &[Vec<u8>],
    foreign: &native::ACheckpoint,
) {
    let budget = MemoryBudget::DEFAULT;
    assert_eq!(
        retained.len(),
        native::A_STAGE_COUNT + native::W_STAGE_COUNT
    );
    for object in 0..3 {
        for offset in [0, input.own[object].len() - 1] {
            let mut bad = input.clone();
            bad.own[object][offset] ^= 1;
            assert!(
                prover.prepare(bad, budget).is_err(),
                "own tape {object}/{offset}"
            );
        }
    }
    let mut bad = input.clone();
    bad.sigma[0] ^= 1;
    assert!(
        prover.prepare(bad, budget).is_err(),
        "own sigma differs from Q0"
    );
    let session = prover.prepare(input.clone(), budget).unwrap();
    assert!(
        session.terminal(foreign, budget).is_err(),
        "foreign session handle"
    );
    let original = &retained[0];
    assert!(
        session
            .restore_first_checkpoint(&original[..original.len() - 1], budget)
            .is_err()
    );
    assert!(
        session
            .restore_first_checkpoint(&retained[1], budget)
            .is_err(),
        "wrong role"
    );
    let mut changed = original.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    assert!(session.restore_first_checkpoint(&changed, budget).is_err());
    let mut changed_input = input;
    changed_input.retained.payment[10] ^= 1;
    let changed_session = prover.prepare(changed_input, budget).unwrap();
    assert!(
        changed_session
            .restore_first_checkpoint(original, budget)
            .is_err(),
        "changed exact original"
    );
    let mut current = session.restore_first_checkpoint(original, budget).unwrap();
    assert_eq!(
        session.encode_a_checkpoint(&current, budget).unwrap(),
        *original
    );
    for (index, pair) in retained[1..].chunks_exact(2).enumerate() {
        assert!(
            session.terminal(&current, budget).is_err(),
            "unfinished owner chain"
        );
        let wrapper = session
            .restore_wrapper_checkpoint(&current, &pair[0], budget)
            .unwrap();
        assert_eq!(wrapper.stage(), index);
        assert_eq!(
            session.encode_wrapper_checkpoint(&wrapper, budget).unwrap(),
            pair[0]
        );
        assert!(
            session
                .restore_a_checkpoint(&wrapper, original, budget)
                .is_err(),
            "wrong stage"
        );
        current = session
            .restore_a_checkpoint(&wrapper, &pair[1], budget)
            .unwrap();
        assert_eq!(current.stage(), index + 1);
        assert_eq!(
            session.encode_a_checkpoint(&current, budget).unwrap(),
            pair[1]
        );
    }
    assert_eq!(current.proof(), foreign.proof());
    assert_eq!(current.instances(), foreign.instances());
    assert_eq!(current.pallas_bytes(), foreign.pallas_bytes());
    let terminal = session.terminal(&current, budget).unwrap();
    assert_eq!(terminal.proof, foreign.proof());
    assert!(
        session
            .restore_wrapper_checkpoint(&current, &retained[retained.len() - 2], budget)
            .is_err(),
        "terminal has no W successor"
    );
}
fn checked_layout(stage: &Stage) {
    let public = stage.public();
    let label = stage.continuation.as_ref().map_or(0, |c| c.plan.stage());
    let (known, k) = match synthesize(stage, 16, Some(&public)) {
        Ok(layout) => (layout, 16),
        Err(error) => {
            eprintln!(
                "Archive A{label} k16 synthesis failed {error:?}; k18 is capacity diagnostic only"
            );
            (synthesize(stage, 18, Some(&public)).unwrap(), 18)
        }
    };
    let rows: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect();
    eprintln!(
        "Archive A{label} real owner max_rows={} lanes={rows:?} k16_fit={}",
        rows.iter().max().unwrap(),
        k == 16
    );
    let report = check(&known.cs, &known.tables, CheckMode::Strict).unwrap();
    assert!(
        report.is_satisfied(),
        "Archive A{label} {:?}",
        report.failures().first()
    );
    let unknown = synthesize(&stage.without_witnesses(), k, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(k, 16, "Archive A{label} exceeds the hard production domain");
}
fn reject(stage: &Stage, reason: &str) {
    assert!(
        !check_circuit(stage, 16, &stage.public(), CheckMode::Strict)
            .is_ok_and(|r| r.is_satisfied()),
        "{reason}"
    );
}

// Metadata only; each identity is later checked against a genuinely proved source.
struct StageIdentity {
    binding: iroha_plonk::DescriptorBinding,
    key: VerifyingKey<Eq>,
    wrapper: Option<WKey>,
}

// Derive every actual source identity sequentially, without generating proofs or
// retaining PKs. Each continuation pins the preceding exact W verifier. A reused
// representative W key is insufficient: its constants can change cache placement
// and it does not establish the identity of a later source program.
fn preflight_stage_layouts(first: &Stage) -> Vec<StageIdentity> {
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = common::vesta_params(16);
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let mut w_config =
        KeygenConfigV2::pipa_r(iroha_kagemusha_proof::omega::OmegaPlan::instance_types().to_vec());
    w_config.compress_selectors = false;
    let trivial = AccumulatorT::trivial(&v, MemoryBudget::DEFAULT).unwrap();
    let context = first.plan.context();
    let native_plan = native_plan(first);
    let mut previous: Option<WKey> = None;
    let mut identities = Vec::new();
    for index in 0..context.stage_count() {
        let mut candidate = first.without_witnesses();
        if let Some(wrapper) = &previous {
            candidate.continuation = Some(Continuation {
                plan: SplitPlan::new(context.clone(), index, wrapper.clone(), &p).unwrap(),
                proof: vec![0; wrapper.verifier().proof_length()],
                carried: first.pallas.clone(),
                vesta: trivial.clone(),
            });
        }
        let native = native_plan.source_circuit(index, previous.clone()).unwrap();
        let (layout, fits) = match synthesize(&native, 16, None) {
            Ok(layout) => (layout, true),
            Err(error) => {
                eprintln!("ARCHIVE_PREFLIGHT_FAILURE stage={index} k16_error={error:?}");
                (synthesize(&native, 18, None).unwrap(), false)
            }
        };
        let reference = synthesize(&candidate, if fits { 16 } else { 18 }, None).unwrap();
        assert_eq!(layout.tables.fixed(), reference.tables.fixed());
        assert_eq!(layout.tables.permutation(), reference.tables.permutation());
        assert_eq!(
            layout.tables.advice_assigned(),
            reference.tables.advice_assigned()
        );
        drop(reference);
        let rows: Vec<_> = layout
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect();
        eprintln!(
            "ARCHIVE_LAYOUT_PREFLIGHT stage={index} rows={rows:?} production_k16_fit={fits} sequential_exact_VK=true unknown_witness_only=true proof_qualification=false"
        );
        drop(layout);
        assert!(fits, "Archive A{index} must fit before deriving its key");
        let (binding, key) =
            iroha_plonk::keys::keygen_vk_with_binding_v2(&v, &native, &a_config).unwrap();
        let wrapper = if index + 1 < context.stage_count() {
            let proof_length = iroha_plonk::Protocol::new(binding.descriptor())
                .unwrap()
                .proof_length();
            let circuit = WCircuit::new(
                context,
                index,
                binding.clone(),
                v.clone(),
                vec![key.kagemusha_digest(&binding).unwrap()],
                iroha_kagemusha_proof::omega::OmegaWitness {
                    key: key.clone(),
                    instances: vec![Fp::ZERO; 69],
                    length: u32::try_from(proof_length).unwrap(),
                    proof: vec![0; proof_length],
                    fold: [0; 1120],
                },
            )
            .unwrap()
            .without_witnesses();
            let factory = native_plan.wrapper_source(index, &binding, &key).unwrap();
            let reference = synthesize(&circuit, 16, None).unwrap();
            let actual = synthesize(&factory, 16, None).unwrap();
            assert_eq!(actual.tables.fixed(), reference.tables.fixed());
            assert_eq!(actual.tables.permutation(), reference.tables.permutation());
            assert_eq!(
                actual.tables.advice_assigned(),
                reference.tables.advice_assigned()
            );
            drop((actual, reference));
            for invalid in [context.stage_count() - 1, context.stage_count(), usize::MAX] {
                assert!(native_plan.wrapper_source(invalid, &binding, &key).is_err());
            }
            let (binding, key) =
                iroha_plonk::keys::keygen_vk_with_binding_v2(&p, &factory, &w_config).unwrap();
            Some(WKey::from_artifact(context, index, binding, p.clone(), key).unwrap())
        } else {
            None
        };
        previous.clone_from(&wrapper);
        identities.push(StageIdentity {
            binding,
            key,
            wrapper,
        });
    }
    identities
}

fn prove_chain(source: archive_q::ArchiveSource) {
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = common::vesta_params(16);
    let mut stage = first(source);
    let identities = preflight_stage_layouts(&stage);
    let input = native_inputs(&stage.source);
    let plan = native_plan(&stage);
    let slot = &input.q[2].instances[0];
    assert_eq!(slot.len(), 10);
    let integer = |low: Fq, high: Fq| {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&low.to_repr()[..16]);
        bytes[16..].copy_from_slice(&high.to_repr()[..16]);
        core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
    };
    let proposal = native::PredicateInputs {
        state: input.state,
        own: input.own.clone(),
        retained: input.retained.clone(),
        evidence: input.evidence.clone(),
        signature: iroha_kagemusha_proof::q_signature::SignatureWitness {
            digest: Option::<Fp>::from(Fp::from_repr(slot[0].to_repr())).unwrap(),
            key: [integer(slot[1], slot[2]), integer(slot[3], slot[4])],
            signature: [integer(slot[5], slot[6]), integer(slot[7], slot[8])],
        },
        predecessor_pallas: AccumulatorT::from_bytes(&input.predecessor.pallas).unwrap(),
        predecessor_vesta: AccumulatorT::from_bytes(&input.predecessor.vesta).unwrap(),
        incoming_selector: Some(input.q[0].instances[2][1].to_repr()[0]),
    };
    let derived = plan.propose_nonproof(proposal.clone()).unwrap();
    assert_eq!(derived, [input.results[1], input.results[2]]);
    let mut changed = proposal;
    if let native::Evidence::Receive { credited, .. } = &mut changed.evidence {
        credited[35] ^= 1;
    }
    assert!(
        plan.propose_nonproof(changed).is_err(),
        "Credited cannot change its original Payment binding"
    );
    eprintln!(
        "NATIVE_ARCHIVE_PREDICATES evidence_signature={derived:?} exact_circuit_predicates=true no_synthetic_Q=true"
    );
    let prepared = Arc::new(plan.prepare(input.clone(), MemoryBudget::DEFAULT).unwrap());
    let (first_circuit, first_public) = prepared
        .first_circuit(Fp::from(191), &FoldConfig::default())
        .unwrap();
    compare_native_source(&stage, &first_circuit, &first_public);
    let prover = native::Prover::from_artifacts(
        plan,
        identities
            .iter()
            .map(|i| KeyArtifact::new(i.binding.clone(), i.key.clone()).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        identities
            .iter()
            .filter_map(|i| i.wrapper.as_ref())
            .map(|w| {
                KeyArtifact::new(w.verifier().binding().clone(), w.verifying_key().clone()).unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let layouts = prover.checkpoint_layouts().unwrap();
    assert_eq!(layouts.len(), native::A_STAGE_COUNT + native::W_STAGE_COUNT);
    let session = prover
        .prepare(input.clone(), MemoryBudget::DEFAULT)
        .unwrap();
    let mut prior_native = None;
    let mut retained = Vec::new();
    let mut part = stage.source.part.clone();
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    loop {
        let index = stage.continuation.as_ref().map_or(0, |c| c.plan.stage());
        checked_layout(&stage);
        // The recomputed public digest prevents these mutations from merely
        // failing against a stale public statement. The named owner must bind.
        if index == 0 {
            for slot in 0..3 {
                let mut bad = stage.clone();
                bad.mutate_context = Some((slot, 0));
                reject(&bad, "own source substitution");
            }
        }
        for &q in stage.plan.context().q_partition(index).unwrap() {
            let mut bad = stage.clone();
            bad.omit_q = Some(q);
            reject(&bad, "dropped assigned Q");
        }
        if stage.continuation.is_some() {
            let mut bad = stage.clone();
            bad.continuation.as_mut().unwrap().carried =
                AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
            reject(&bad, "substituted prior Pallas claim");
            let mut bad = stage.clone();
            bad.continuation.as_mut().unwrap().vesta =
                AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
            reject(&bad, "substituted prior W Vesta claim");
        }
        let public = stage.public();
        let key = keygen_pk_v2(&vparams, &stage, &config).unwrap();
        assert_eq!(key.binding(), &identities[index].binding);
        assert_eq!(key.vk().to_bytes(), identities[index].key.to_bytes());
        let original = key.artifact_bytes_v2().unwrap();
        let baseline_key = key;
        let read = iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        assert!(
            prover
                .import_a(index, &original[..original.len() - 1], read)
                .is_err()
        );
        assert!(
            prover
                .import_a((index + 1) % native::A_STAGE_COUNT, &original, read)
                .is_err()
        );
        let key_seal = prover.import_a(index, &original, read).unwrap();
        let key = prover.bind_a(index, &key_seal, None).unwrap();
        drop(original);
        let output = create_proof_owned_with_claim(
            &vparams,
            &baseline_key,
            Witness::from_circuit(&baseline_key, &stage, &public).unwrap(),
            common::recovery(170 + u8::try_from(index).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        drop(baseline_key);
        verify_full(
            &vparams,
            key.binding(),
            key.verifying_key(),
            &public,
            &output.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        output
            .opening
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        eprintln!(
            "Archive A{index} verified actual proof_bytes={}",
            output.proof.len()
        );
        let native = prior_native.as_ref().map_or_else(
            || {
                session
                    .first(
                        &key,
                        Fp::from(191),
                        &FoldConfig::default(),
                        common::recovery(170),
                        ProverConfig::default(),
                    )
                    .unwrap()
            },
            |prior| {
                let salt = Fp::from(229 + index as u64);
                let (circuit, frame) = session
                    .next_circuit(prior, salt, &FoldConfig::default())
                    .unwrap();
                compare_native_source(&stage, &circuit, &frame);
                session
                    .advance(
                        &key,
                        prior,
                        salt,
                        &FoldConfig::default(),
                        common::recovery(170 + u8::try_from(index).unwrap()),
                        ProverConfig::default(),
                    )
                    .unwrap()
            },
        );
        assert_eq!(native.proof(), output.proof);
        assert_eq!(native.instances(), public[0]);
        assert_eq!(native.pallas_bytes(), stage.pallas.to_bytes());
        let encoded = session
            .encode_a_checkpoint(&native, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(encoded.len(), layouts[2 * index].payload_bytes());
        retained.push(encoded);
        if index + 1 == stage.plan.context().stage_count() {
            let terminal = session.terminal(&native, MemoryBudget::DEFAULT).unwrap();
            assert_eq!(terminal.proof, output.proof);
            assert_eq!(terminal.instances, public[0]);
            drop(key_seal);
            replay_native_checkpoints(&prover, input, &retained, &native);
            eprintln!(
                "ARCHIVE_COMPLETE all10A_all9W=true valid={} native_maps=true native_source_and_proof_bytes_equal=true original_PK_import=true all19_canonical_checkpoints_restored=true no_final_omega_admission=true ordinary_finality_fixture=true release_qualified=false",
                stage.source.valid
            );
            break;
        }
        let own =
            FoldInput::from_opening(*output.opening.g(), output.opening.challenges()).unwrap();
        let trivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT)
            .unwrap()
            .as_input();
        let (vfold, vesta) = create_fold(
            &vparams,
            &[part, own, trivial.clone(), trivial],
            Fq::from(220 + index as u64).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        vesta.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
        let wrapper_circuit = WCircuit::new(
            stage.plan.context(),
            index,
            key.binding().clone(),
            vparams.clone(),
            vec![key.verifying_key().kagemusha_digest(key.binding()).unwrap()],
            iroha_kagemusha_proof::omega::OmegaWitness {
                key: key.verifying_key().clone(),
                instances: public[0].clone(),
                length: output.proof.len().try_into().unwrap(),
                proof: output.proof,
                fold: vfold.to_bytes(),
            },
        )
        .unwrap();
        drop(key_seal);
        let (wrapper, key) = WKey::keygen(&wrapper_circuit, &params).unwrap();
        let planned = identities[index].wrapper.as_ref().unwrap();
        assert_eq!(wrapper.verifier().binding(), planned.verifier().binding());
        assert_eq!(
            wrapper.verifying_key().to_bytes(),
            planned.verifying_key().to_bytes()
        );
        let original = key.artifact_bytes_v2().unwrap();
        let baseline_key = key;
        let read = iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: original.len(),
            ..read
        };
        assert!(
            prover
                .import_w(index, &original[..original.len() - 1], read)
                .is_err()
        );
        assert!(
            prover
                .import_w((index + 1) % native::W_STAGE_COUNT, &original, read)
                .is_err()
        );
        let key_seal = prover.import_w(index, &original, read).unwrap();
        let key = prover.bind_w(index, &key_seal, None).unwrap();
        drop(original);
        for wrong in 0..=stage.plan.context().stage_count() {
            if wrong != index + 1 {
                assert!(
                    SplitPlan::new(
                        stage.plan.context().clone(),
                        wrong,
                        wrapper.clone(),
                        &params
                    )
                    .is_err()
                );
            }
        }
        let (x, y) = vesta.g().coordinates().unwrap();
        let wpublic = vec![
            vec![Fq::from_repr(public[0][0].to_repr()).unwrap()],
            vec![x, y],
            vesta
                .challenges()
                .iter()
                .map(|v| Fq::from_repr(v.to_repr()).unwrap())
                .collect(),
        ];
        let output = create_proof_owned_with_claim(
            &params,
            &baseline_key,
            Witness::from_circuit(&baseline_key, &wrapper_circuit, &wpublic).unwrap(),
            common::recovery(180 + u8::try_from(index).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        drop(baseline_key);
        verify_full(
            &params,
            key.binding(),
            key.verifying_key(),
            &wpublic,
            &output.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        output
            .opening
            .decide(&params, MemoryBudget::DEFAULT)
            .unwrap();
        let native_wrapper = session
            .wrapper(
                &key,
                &native,
                Fq::from(220 + index as u64),
                &FoldConfig::default(),
                common::recovery(180 + u8::try_from(index).unwrap()),
                ProverConfig::default(),
            )
            .unwrap();
        assert_eq!(native_wrapper.proof(), output.proof);
        assert_eq!(native_wrapper.vesta_bytes(), vesta.to_bytes());
        let encoded = session
            .encode_wrapper_checkpoint(&native_wrapper, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(encoded.len(), layouts[2 * index + 1].payload_bytes());
        retained.push(encoded);
        prior_native = Some(native_wrapper);
        drop(key_seal);
        eprintln!(
            "Archive W{index} verified actual proof_bytes={}",
            output.proof.len()
        );
        let mut claims = vec![
            stage.pallas.as_input(),
            FoldInput::from_opening(*output.opening.g(), output.opening.challenges()).unwrap(),
        ];
        claims.extend(
            stage
                .plan
                .context()
                .q_partition(index + 1)
                .unwrap()
                .iter()
                .map(|i| stage.source.q[*i].opening.clone()),
        );
        let (fold, pallas) = create_fold(
            &params,
            &claims,
            Fp::from(230 + index as u64).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        pallas.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let continuation = Continuation {
            plan: SplitPlan::new(stage.plan.context().clone(), index + 1, wrapper, &params)
                .unwrap(),
            proof: output.proof,
            carried: stage.pallas.clone(),
            vesta: vesta.clone(),
        };
        stage.continuation = Some(continuation);
        stage.pallas = pallas;
        stage.fold = fold.to_bytes().to_vec();
        part = vesta.as_input();
    }
}

/// Run the retained composition assertions with genuine native Load originals.
pub fn genuine_archive_receive_accepts_and_removes_pending(fixture: compact_catalog::LoadFixture) {
    let source = archive_q::build(
        compact_catalog::compact_payer_send(&fixture),
        archive_q::IncomingOriginal::Valid,
    );
    drop(fixture);
    prove_chain(source);
}
/// Run the retained composition assertions with genuine native Load originals.
pub fn genuine_archive_receive_invalid_proof_retains_adjusted_pending(
    fixture: compact_catalog::LoadFixture,
) {
    let source = archive_q::build(
        compact_catalog::compact_payer_send(&fixture),
        archive_q::IncomingOriginal::CorruptedProof,
    );
    drop(fixture);
    prove_chain(source);
}

/// Run the retained composition assertions with genuine native Load originals.
pub fn genuine_archive_receive_full_envelope_tail_retains_adjusted_pending(
    fixture: compact_catalog::LoadFixture,
) {
    let source = archive_q::build(
        compact_catalog::compact_payer_send(&fixture),
        archive_q::IncomingOriginal::FullEnvelopeTail,
    );
    drop(fixture);
    assert_eq!(source.incoming_sigma.len(), 9_321);
    assert!(!source.valid);
    prove_chain(source);
}
