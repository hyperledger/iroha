//! Fixed full-envelope Archive source owners and authenticated A/W continuations.
//!
//! Receive and Status evidence share the canonical dispatcher. Every proposal is
//! committed across stages and derived by its named owner before terminal closure.

mod proposal;
pub use proposal::PredicateInputs;

use super::{Evidence, INTERNAL_RANGE_BUSES, Prepared, TERMINAL_RANGE_BUSES};
use crate::{
    a_relation::{
        IncomingLineageCells, LineagePublicCells, ProofMessageCells, SigmaBindingCells,
        VestaClaimCells,
        archive::{
            authorization::ArchiveAuthorizationObjects,
            evidence::ArchiveEvidenceSource,
            incoming::ArchiveIncomingObjects,
            maps::ArchivePendingWitness,
            proofs::{ArchiveProofInputs, ArchiveProofSources},
            results::ArchiveResultClaims,
            retained::{ArchiveRetainedPayment, ArchiveRetainedProofs, ArchiveRetainedSources},
            stage::{ArchiveStageInputs, ArchiveStageWitness},
        },
        bind_signature_q, bounded_word,
        context::{
            ContextIncoming, ContextIncomingProof, ContextInputs, ContextPredecessor, ContextState,
        },
        incoming_transport::IncomingTransportPlan,
        native::support,
        schedule::OperationTask,
        split::{self, SplitPlan},
        verify_predecessor, verify_q, verify_sigma,
    },
    admin_sigma::StateWitness,
    operation_relation::{
        incoming_statement::IncomingStatementCells, map_effects::RemoveCells, state::StateCells,
        statement::StatementCells,
    },
    tree::IndexedRemove,
};
use ff::PrimeField;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, poseidon::hash_with_domain};
use iroha_plonk::{
    VerifyingKey,
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value},
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
    AccumulatorT, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::{ModeCells, ledger::Variant},
    verifier::{VerifierChip, VerifierConfig, VerifierKeyCells},
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
pub(super) struct Continuation {
    pub(super) plan: SplitPlan,
    pub(super) proof: Vec<u8>,
    pub(super) carried: AccumulatorT<Ep>,
    pub(super) vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
pub(super) struct Stage {
    pub(super) source: Arc<Prepared>,
    pub(super) continuation: Option<Continuation>,
    pub(super) pallas: AccumulatorT<Ep>,
    pub(super) fold: Vec<u8>,
    pub(super) known: bool,
}
/// Fixed internal/terminal tagged configuration for the complete Archive source.
#[derive(Clone, Debug)]
pub struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Stage {
    // This fixed safe view is only a proposal until the Proofs owner binds it to
    // the active original. All bytes outside it remain in exact context slot13.
    fn status_proof_view(&self) -> Result<Vec<u8>, super::Error> {
        let Evidence::Status { omega, .. } = &self.source.inputs().evidence else {
            return Err(super::Error::Input);
        };
        let count = self
            .source
            .plan()
            .context()
            .operation()
            .omega()
            .ok_or(super::Error::Artifact)?
            .proof_length();
        Ok(original_proof_view(omega, count))
    }
}

// Match IncomingTransportPlan::decode_active's fixed slice, including safe
// padding on short originals. This view deliberately grants no framing verdict.
fn original_proof_view(original: &[u8], proof_length: usize) -> Vec<u8> {
    let mut view = vec![0; proof_length];
    if let Some(proof) = original.get(320..) {
        let count = proof_length.min(proof.len());
        view[..count].copy_from_slice(&proof[..count]);
    }
    view
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
            TERMINAL_RANGE_BUSES
        } else {
            INTERNAL_RANGE_BUSES
        }
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, INTERNAL_RANGE_BUSES)
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
        let prepared = &self.source;
        let s = prepared.inputs();
        let native = prepared.plan();
        let stage_plan = native.stage();
        let plan = native.context();
        let variant = plan.operation().frame().variant();
        let stage = self.continuation.as_ref().map_or(0, |c| c.plan.stage());
        let tasks = plan.operation_tasks(stage).ok_or(Error::Synthesis)?;
        let out = layouter.assign_region(
            || "Archive complete original source owners",
            |mut region| {
                let (old, pred_public) =
                    cells.state(&mut chip, &mut region, &s.state.predecessor)?;
                let (new, next_public) = cells.state(&mut chip, &mut region, &s.state.successor)?;
                let fields = cells.words(&mut chip, &mut region, &s.state.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    variant,
                    &fields,
                )?;
                let incoming_statement = if let Evidence::Receive { statement, .. } = &s.evidence {
                    let fields = cells.words(&mut chip, &mut region, statement)?;
                    let lanes = chip.operation_lanes()?;
                    Some(IncomingStatementCells::constrain(
                        &mut UintChip::new(lanes.glue, lanes.range),
                        lanes.hash,
                        &mut region,
                        Variant::Receive,
                        &fields,
                    )?)
                } else {
                    None
                };
                let q_instances =
                    s.q.iter()
                        .map(|q| {
                            q.instances
                                .iter()
                                .map(|column| {
                                    column
                                        .iter()
                                        .map(|v| cells.scalar(&mut chip, &mut region, *v))
                                        .collect()
                                })
                                .collect()
                        })
                        .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let commitments = prepared
                    .commitments()
                    .iter()
                    .map(|words| words.map(|v| cells.value(v)))
                    .collect::<Vec<_>>();
                let context =
                    plan.assign_archive_object_claims(&mut chip, &mut region, &commitments)?;
                // Preserve the original Receive source allocation order. Status
                // results instead include the incoming opening assigned below.
                let receive_results = if variant == Variant::ArchiveReceive {
                    Some(ArchiveResultClaims::assign(
                        &mut chip,
                        &mut region,
                        stage_plan.results(),
                        s.results.map(|v| cells.value(v)),
                        None,
                    )?)
                } else {
                    None
                };
                let pp = cells.pallas(
                    &mut chip,
                    &mut region,
                    &prepared.predecessor_claims().0.as_input(),
                )?;
                let pv = cells.vesta(&mut chip, &mut region, &prepared.predecessor_claims().1)?;
                let mut status_public = None;
                let mut status_pallas = None;
                let mut status_vesta = None;
                let mut status_opening = None;
                let mut status_messages = None;
                let mut modes = Vec::new();
                let mut corrections = Vec::new();
                let mut vcorrections = Vec::new();
                match &s.evidence {
                    Evidence::Receive { mode, .. } => {
                        let words =
                            cells.words(&mut chip, &mut region, &support::mode_words(*mode))?;
                        modes.push(ModeCells::constrain(
                            chip.uint().glue(),
                            &mut region,
                            &words,
                        )?);
                    }
                    Evidence::Status { witness, .. } => {
                        let fields = cells.words(&mut chip, &mut region, &witness.public)?;
                        let valid = chip
                            .uint()
                            .glue()
                            .boolean(&mut region, cells.value(witness.public_valid))?;
                        status_public = Some(IncomingLineageCells::constrain(
                            &mut chip.uint(),
                            &mut region,
                            &fields,
                            &valid,
                        )?);
                        status_pallas = Some(cells.pallas(
                            &mut chip,
                            &mut region,
                            &witness.pallas.as_input(),
                        )?);
                        status_vesta = Some(cells.vesta(&mut chip, &mut region, &witness.vesta)?);
                        status_opening =
                            Some(cells.pallas(&mut chip, &mut region, &witness.opening)?);
                        let view = self.status_proof_view().map_err(|_| Error::Synthesis)?;
                        status_messages = Some(cells.proof(&mut chip, &mut region, &view)?);
                        for mode in witness.modes {
                            let words =
                                cells.words(&mut chip, &mut region, &support::mode_words(mode))?;
                            modes.push(ModeCells::constrain(
                                chip.uint().glue(),
                                &mut region,
                                &words,
                            )?);
                        }
                        for point in witness.pallas_corrections {
                            corrections.push(
                                chip.witness_point(&mut region, cells.value(Ep::from(point)))?,
                            );
                        }
                        let (x, y) = Option::from(witness.vesta_correction.coordinates())
                            .ok_or(Error::Synthesis)?;
                        vcorrections.push([
                            cells.scalar(&mut chip, &mut region, x)?,
                            cells.scalar(&mut chip, &mut region, y)?,
                        ]);
                    }
                }
                let results = if let Some(results) = receive_results {
                    results
                } else {
                    ArchiveResultClaims::assign(
                        &mut chip,
                        &mut region,
                        stage_plan.results(),
                        s.results.map(|v| cells.value(v)),
                        status_opening.as_ref(),
                    )?
                };
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: incoming_statement.as_ref(),
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
                    incoming: if variant == Variant::ArchiveStatus {
                        Some(ContextIncoming {
                            public: status_public.as_ref().ok_or(Error::Synthesis)?,
                            pallas: status_pallas.as_ref().ok_or(Error::Synthesis)?,
                            vesta: status_vesta.as_ref().ok_or(Error::Synthesis)?,
                            proof: ContextIncomingProof::Messages(
                                status_messages.as_ref().ok_or(Error::Synthesis)?,
                            ),
                        })
                    } else {
                        None
                    },
                    q_instances: &q_instances,
                    objects: &context,
                    modes: &modes,
                    pallas_corrections: &corrections,
                    vesta_corrections: &vcorrections,
                    receive_results: None,
                };
                let own_index = bounded_word(&mut chip, &mut region, &q_instances[0][2][0])?;
                let incoming_index = if variant == Variant::ArchiveReceive {
                    Some(bounded_word(&mut chip, &mut region, &q_instances[0][2][1])?)
                } else {
                    None
                };
                let chunks = |slot| {
                    plan.operation()
                        .sigma
                        .chunk_range(slot)
                        .ok_or(Error::Synthesis)
                };
                let own_chunks = chunks(0)?
                    .map(|i| bounded_word(&mut chip, &mut region, &q_instances[0][0][i]))
                    .collect::<Result<Vec<_>, _>>()?;
                let incoming_chunks = if variant == Variant::ArchiveReceive {
                    Some(
                        chunks(1)?
                            .map(|i| bounded_word(&mut chip, &mut region, &q_instances[0][0][i]))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                } else {
                    None
                };
                let own_sigma = if tasks.contains(&OperationTask::ArchiveOwnProof) {
                    let raw = support::frame(&s.sigma).map_err(|_| Error::BoundsFailure)?;
                    let run = bytes.run(
                        &mut region,
                        &cells.bytes(&raw),
                        &chunk_segments(0, raw.len()),
                        &[SegmentSpec::little(0, 4)],
                    )?;
                    SigmaBindingCells::from_run(
                        &mut chip,
                        &mut region,
                        &statement,
                        own_index,
                        &run,
                    )?
                } else {
                    SigmaBindingCells::from_statement(&statement, own_index, own_chunks)
                };
                let mut incoming_sigma = None;
                let mut transport = None;
                let mut proof_key = None;
                if let Evidence::Receive { sigma, .. } = &s.evidence {
                    let incoming_statement = incoming_statement.as_ref().ok_or(Error::Synthesis)?;
                    let index = incoming_index.ok_or(Error::Synthesis)?;
                    let view = incoming_chunks.ok_or(Error::Synthesis)?;
                    let incoming = if tasks.contains(&OperationTask::ArchiveProofs) {
                        let proof_bytes = plan
                            .operation()
                            .sigma
                            .class(1)
                            .ok_or(Error::Synthesis)?
                            .verifier()
                            .proof_length();
                        let raw = cells.active(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            sigma,
                            plan.object_specs()[13].capacity as usize,
                            &SigmaBindingCells::incoming_segments(proof_bytes)?,
                        )?;
                        SigmaBindingCells::from_incoming_active(
                            &mut chip,
                            &mut region,
                            incoming_statement,
                            index,
                            &raw,
                            proof_bytes,
                        )?
                    } else {
                        SigmaBindingCells::from_incoming(incoming_statement, index, view)
                    };
                    incoming_sigma = Some(incoming);
                } else if let Evidence::Status { omega, .. } = &s.evidence
                    && tasks.contains(&OperationTask::ArchiveProofs)
                {
                    let decoder = IncomingTransportPlan::new(plan.operation())?;
                    let raw = cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        omega,
                        plan.object_specs()[13].capacity as usize,
                        &decoder.active_segments()?,
                    )?;
                    transport = Some(decoder.decode_active(
                        &mut chip,
                        &mut region,
                        &raw,
                        next_public.omega_key_digest(),
                    )?);
                    proof_key =
                        Some(cells.key(&mut chip, &mut region, native.predecessor_key())?);
                }
                let proof_source = if tasks.contains(&OperationTask::ArchiveProofs) {
                    Some(match variant {
                        Variant::ArchiveReceive => ArchiveProofSources::receive(
                            incoming_sigma.as_ref().ok_or(Error::Synthesis)?,
                            13,
                        )?,
                        Variant::ArchiveStatus => ArchiveProofSources::status(
                            transport.as_ref().ok_or(Error::Synthesis)?,
                            13,
                        )?,
                        _ => return Err(Error::Synthesis),
                    })
                } else {
                    None
                };
                let mut sigmas = vec![own_sigma.clone()];
                if let Some(incoming) = incoming_sigma {
                    sigmas.push(incoming);
                }
                let own = if tasks.contains(&OperationTask::ArchiveOwnProof)
                    || tasks.contains(&OperationTask::ArchiveAuthorization)
                {
                    let raw = s.own.each_ref().map(|v| cells.bytes(v));
                    Some(ArchiveAuthorizationObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        variant,
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
                        &s.retained.omega,
                        plan.object_specs()[9].capacity as usize,
                        &[],
                    )?;
                    let sigma = cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &s.retained.sigma,
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
                    let signed = s.retained.signed.each_ref().map(|v| cells.bytes(v));
                    let payment = cells.bytes(&s.retained.payment);
                    let words = cells.words(&mut chip, &mut region, &s.retained.statement)?;
                    Some(ArchiveRetainedPayment::from_committed_proofs(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        native.policy(),
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
                let receipt = match &s.evidence {
                    Evidence::Receive { receipt, .. } | Evidence::Status { receipt, .. } => receipt,
                };
                let incoming = if tasks.contains(&OperationTask::ArchiveEvidence)
                    || tasks.contains(&OperationTask::ArchiveSignatures)
                {
                    let raw = [&s.retained.signed[0], &s.retained.signed[3], receipt]
                        .map(|v| cells.bytes(v));
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
                    let key = cells.key(&mut chip, &mut region, native.predecessor_key())?;
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
                        let signature = bind_signature_q(
                            &mut chip,
                            &mut region,
                            plan.operation(),
                            index,
                            stage_plan.signature_schema(index).ok_or(Error::Synthesis)?,
                            &q,
                        )?;
                        verified.push(signature.verified().clone());
                        if index == 1 {
                            own_signatures = Some(signature);
                        } else {
                            incoming_signatures = Some(signature);
                        }
                    }
                }
                let mut pending: Vec<Option<ArchivePendingWitness>> =
                    std::iter::repeat_with(|| None).take(2).collect();
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
                    let descriptor: [Fp; 7] = s.retained.statement[17..24]
                        .try_into()
                        .map_err(|_| Error::Synthesis)?;
                    pending[index] = Some(ArchivePendingWitness {
                        descriptor: cells.words(&mut chip, &mut region, &descriptor)?,
                        removal: cells.removal(&mut chip, &mut region, &s.removals[index])?,
                    });
                }
                let credited = cells.bytes(match &s.evidence {
                    Evidence::Receive { credited, .. } | Evidence::Status { credited, .. } => {
                        credited
                    }
                });
                let (status_original, opening_original, status_statement) =
                    if let Evidence::Status {
                        status,
                        credit_opening,
                        statement,
                        ..
                    } = &s.evidence
                        && tasks.contains(&OperationTask::ArchiveEvidence)
                    {
                        (
                            Some(cells.bytes(status)),
                            Some(cells.bytes(credit_opening)),
                            Some(cells.words(&mut chip, &mut region, statement)?),
                        )
                    } else {
                        (None, None, None)
                    };
                let proof = if tasks.contains(&OperationTask::ArchiveProofs) {
                    Some(if variant == Variant::ArchiveReceive {
                        ArchiveProofInputs::Receive(&own_sigma)
                    } else {
                        ArchiveProofInputs::Status(proof_key.as_ref().ok_or(Error::Synthesis)?)
                    })
                } else {
                    None
                };
                let evidence = if tasks.contains(&OperationTask::ArchiveEvidence) {
                    Some(if variant == Variant::ArchiveReceive {
                        ArchiveEvidenceSource::Receive {
                            credited: &credited,
                        }
                    } else {
                        ArchiveEvidenceSource::Status {
                            credited: &credited,
                            statement: status_statement.as_ref().ok_or(Error::Synthesis)?,
                            status: status_original.as_ref().ok_or(Error::Synthesis)?,
                            opening: opening_original.as_ref().ok_or(Error::Synthesis)?,
                        }
                    })
                } else {
                    None
                };
                stage_plan.constrain_stage(
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
                        proof,
                        evidence,
                        core_pending: pending[0].as_ref(),
                        lineage_pending: pending[1].as_ref(),
                    },
                )?;
                let fold = cells.proof(&mut chip, &mut region, &self.fold)?;
                if let (Some(c), Some(resumed)) = (&self.continuation, resumed) {
                    let selected = if c.plan.is_terminal() && variant == Variant::ArchiveStatus {
                        Some(results.select_status_incoming(
                            &mut chip,
                            &mut region,
                            plan,
                            u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                            &input,
                        )?)
                    } else {
                        None
                    };
                    let closed = split::close_stage(
                        &mut chip,
                        &mut region,
                        &c.plan,
                        &resumed,
                        None,
                        selected.as_ref().map(|v| &v.0),
                        selected.as_ref().map(|v| &v.1),
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
                        native.pallas(),
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
impl Stage {
    /// Complete immutable source context shared by every fixed stage.
    pub(super) fn context_digest(&self) -> Result<Fp, super::Error> {
        let s = self.source.inputs();
        let native = self.source.plan();
        let mut words = native.context().schema().to_vec();
        words.extend(s.state.statement);
        if let Evidence::Receive { statement, .. } = &s.evidence {
            words.extend(statement);
        }
        let before = &s.state.predecessor;
        let after = &s.state.successor;
        words.extend(before.core);
        words.extend(before.rest);
        words.extend(before.lineage);
        support::push_pallas(&mut words, &self.source.predecessor_claims().0.as_input())?;
        words.extend(support::vesta_words(
            &self.source.predecessor_claims().1.as_input(),
        )?);
        words.extend(after.core);
        words.extend(after.rest);
        words.extend(after.lineage);
        if let Evidence::Status { witness, .. } = &s.evidence {
            words.extend(witness.public);
            words.push(Fp::from(u64::from(witness.public_valid)));
            support::push_pallas(&mut words, &witness.pallas.as_input())?;
            words.extend(support::vesta_words(&witness.vesta.as_input())?);
            let view = self.status_proof_view()?;
            words.push(Fp::from(
                u64::try_from(view.len()).map_err(|_| super::Error::Input)?,
            ));
            for message in view.chunks_exact(32) {
                words.push(Fp::from_u128(u128::from_le_bytes(
                    message[..16].try_into().map_err(|_| super::Error::Input)?,
                )));
                words.push(Fp::from_u128(u128::from_le_bytes(
                    message[16..].try_into().map_err(|_| super::Error::Input)?,
                )));
            }
        }
        // Archive's fixed context schema retains every Q scalar as two foreign
        // limbs, including bounded columns; Receive's separate schema differs.
        for q in &s.q {
            for value in q.instances.iter().flatten() {
                words.extend(foreign_limbs(value).map(Fp::from_u128));
            }
        }
        words.extend(self.source.commitments().iter().flatten().copied());
        match &s.evidence {
            Evidence::Receive { mode, .. } => words.extend(support::mode_words(*mode)),
            Evidence::Status { witness, .. } => {
                for mode in witness.modes {
                    words.extend(support::mode_words(mode));
                }
                for point in witness.pallas_corrections {
                    let (x, y) =
                        Option::<(Fp, Fp)>::from(point.coordinates()).ok_or(super::Error::Input)?;
                    words.extend([x, y]);
                }
                let (x, y) = Option::<(Fq, Fq)>::from(witness.vesta_correction.coordinates())
                    .ok_or(super::Error::Input)?;
                for value in [x, y] {
                    words.extend(foreign_limbs(&value).map(Fp::from_u128));
                }
            }
        }
        Ok(hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words))
    }
    /// Exact internal or terminal frame matched by this fixed source circuit.
    pub(super) fn public(&self) -> Result<Vec<Fp>, super::Error> {
        let native = self.source.plan();
        let root = self.context_digest()?;
        let Some(c) = &self.continuation else {
            return Ok(support::internal_public(
                native.vesta(),
                support::stage_digest(native.context(), 0, root, &self.pallas)?,
                self.source.part(),
            )?);
        };
        if !c.plan.is_terminal() {
            let digest =
                support::stage_digest(native.context(), c.plan.stage(), root, &self.pallas)?;
            return Ok(support::internal_public(
                native.vesta(),
                digest,
                &c.vesta.as_input(),
            )?);
        }
        let mut words = vec![
            support::terminal_digest(
                &self.source.inputs().state.successor.lineage,
                &self.pallas.as_input(),
            )?,
            Fp::from(16),
        ];
        words.extend(support::vesta_words(&c.vesta.as_input())?);
        words.extend(support::vesta_words(
            &self.source.predecessor_claims().1.as_input(),
        )?);
        match &self.source.inputs().evidence {
            Evidence::Receive { .. } => {
                let trivial =
                    AccumulatorT::trivial(native.vesta(), iroha_pasta::msm::MemoryBudget::DEFAULT)
                        .map_err(|_| super::Error::Proof)?;
                let claim = support::vesta_words(&trivial.as_input())?;
                words.extend(&claim);
                words.extend(support::mode_words(
                    crate::q_sigma::native::IncomingMode::Trivial,
                ));
                words.extend(&claim[..4]);
            }
            Evidence::Status { witness, .. } => {
                words.extend(support::vesta_words(&witness.vesta.as_input())?);
                words.extend(support::mode_words(witness.modes[2]));
                let (x, y) = Option::<(Fq, Fq)>::from(witness.vesta_correction.coordinates())
                    .ok_or(super::Error::Input)?;
                for value in [x, y] {
                    words.extend(foreign_limbs(&value).map(Fp::from_u128));
                }
            }
        }
        if words.len() != 69 {
            return Err(super::Error::Input);
        }
        Ok(words)
    }
}

/// Complete fixed-profile Archive A circuit; all semantics use shared owner relations.
#[derive(Clone)]
pub struct StageCircuit {
    pub(super) inner: Stage,
}
impl Circuit<Fp> for StageCircuit {
    type Config = Config;
    type Params = usize;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> usize {
        self.inner.params()
    }
    fn without_witnesses(&self) -> Self {
        Self {
            inner: self.inner.without_witnesses(),
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Stage::configure(meta)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, params: usize) -> Config {
        Stage::configure_with_params(meta, params)
    }
    fn synthesize(&self, config: Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a_relation::{archive::MAX_STATUS_OMEGA_RAW_BYTES, context::ContextObjectSpec};

    #[test]
    fn status_proof_view_is_fixed_and_total_for_every_admitted_original_length() {
        const PROOF_LENGTH: usize = 3712;
        let original: Vec<_> = (0..MAX_STATUS_OMEGA_RAW_BYTES)
            .map(|i| u8::try_from(i % 251 + 1).unwrap())
            .collect();
        for length in 0..=MAX_STATUS_OMEGA_RAW_BYTES {
            let view = original_proof_view(&original[..length], PROOF_LENGTH);
            let available = length.saturating_sub(320).min(PROOF_LENGTH);
            assert_eq!(view.len(), PROOF_LENGTH);
            assert_eq!(&view[..available], &original[320..320 + available]);
            assert!(view[available..].iter().all(|byte| *byte == 0));
        }
        // No original header or claim-tail byte can enter the proof prefix.
        let mut changed = original.clone();
        changed[..320].fill(0);
        changed[320 + PROOF_LENGTH..].fill(0);
        assert_eq!(
            original_proof_view(&original, PROOF_LENGTH),
            original_proof_view(&changed, PROOF_LENGTH)
        );
    }

    #[test]
    fn identical_status_proof_views_do_not_collapse_original_tails_or_lengths() {
        const PROOF_LENGTH: usize = 3712;
        let spec = ContextObjectSpec {
            tag: 14,
            capacity: u32::try_from(MAX_STATUS_OMEGA_RAW_BYTES).unwrap(),
        };
        let original = vec![0x7b; MAX_STATUS_OMEGA_RAW_BYTES];
        let mut different_tail = original.clone();
        different_tail[MAX_STATUS_OMEGA_RAW_BYTES - 1] ^= 1;
        let shorter = &original[..MAX_STATUS_OMEGA_RAW_BYTES - 1];
        let reference = original_proof_view(&original, PROOF_LENGTH);
        // Hold the proposed semantic digest constant: the raw commitment must
        // still distinguish the originals before its owning digest is checked.
        let commitment = support::active_context(spec, Fp::from(17), &original).unwrap();
        for alternative in [different_tail.as_slice(), shorter] {
            assert_eq!(original_proof_view(alternative, PROOF_LENGTH), reference);
            assert_ne!(
                support::active_context(spec, Fp::from(17), alternative).unwrap(),
                commitment
            );
        }
        let over_bound = vec![0; MAX_STATUS_OMEGA_RAW_BYTES + 1];
        assert!(support::active_context(spec, Fp::from(17), &over_bound).is_err());
    }
}
