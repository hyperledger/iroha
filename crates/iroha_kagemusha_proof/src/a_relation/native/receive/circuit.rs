//! Fixed-profile complete Receive A relation, with mandatory digest and result ownership.

use crate::{
    a_relation::{
        IncomingLineageCells, LineagePublicCells, ProofMessageCells, SigmaBindingCells,
        VestaClaimCells,
        context::{
            ContextIncoming, ContextIncomingProof, ContextInputs, ContextPredecessor, ContextState,
        },
        incoming_transport::IncomingTransportPlan,
        receive::{
            ReceiveObjectInputs, ReceiveObjectSources, ReceiveObjects, ReceiveProofDigest,
            ReceiveProofInputs, ReceiveProofSources, ReceiveSignedObjects, ReceiveStageInputs,
            ReceiveStageWitness,
            authorization::{
                ReceiveAuthorizationObjects, ReceiveAuthorizationSources,
                ReceiveSignatureQProjection,
            },
        },
        results::ReceiveResultClaims,
        schedule::OperationTask,
        split::{SplitPlan, close_first, close_stage, resume_context},
        verify_predecessor, verify_q,
    },
    admin_sigma::StateWitness,
    operation_relation::{
        incoming_statement::IncomingStatementCells,
        map_effects::{InsertCells, ReceiveMapWitness},
        state::StateCells,
        statement::StatementCells,
    },
    tree::IndexedInsert,
};
use ff::PrimeField;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine};
use iroha_plonk::{
    VerifyingKey,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
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
    verifier::{VerifierChip, VerifierConfig, VerifierKeyCells, VerifierPlan},
};
use std::sync::Arc;

use super::Source;
mod proposal;
pub use proposal::PredicateInputs;

struct OmegaKeySource {
    representation: Value<Fp>,
    fixed: Vec<Value<Ep>>,
    permutation: Vec<Value<Ep>>,
}
fn omega_key_source(
    plan: &VerifierPlan<Ep>,
    key: &VerifyingKey<Ep>,
    known: bool,
) -> Result<OmegaKeySource, Error> {
    if key.descriptor_digest() != plan.binding().digest() {
        return Err(Error::Synthesis);
    }
    let iroha_plonk::transcript::TranscriptRepr::Base(representation) = *key.transcript_repr()
    else {
        return Err(Error::Synthesis);
    };
    let value = |v| {
        if known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    };
    let points =
        |values: &[iroha_pasta::EpAffine]| values.iter().map(|p| value(Ep::from(*p))).collect();
    Ok(OmegaKeySource {
        representation: if known {
            Value::known(representation)
        } else {
            Value::unknown()
        },
        fixed: points(key.fixed_commitments()),
        permutation: points(key.permutation_commitments()),
    })
}

fn frame(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut framed = u32::try_from(bytes.len())
        .map_err(|_| Error::BoundsFailure)?
        .to_le_bytes()
        .to_vec();
    framed.extend(bytes);
    Ok(framed)
}
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
    fn q_instance(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: Fq,
        ty: InstanceType,
    ) -> Result<ScalarCells<Ep>, Error> {
        if matches!(ty, InstanceType::Bounded | InstanceType::Bits(0..=253)) {
            // A hard Q input of this declared type has an injective native Fp
            // representation. Preserve that checked certificate for downstream
            // context/type checks; never reduce a foreign scalar modulo p.
            let native =
                Option::<Fp>::from(Fp::from_repr(value.to_repr())).ok_or(Error::Synthesis)?;
            let word = chip.uint().glue().witness(region, self.value(native))?;
            ScalarCells::from_native_word(&mut chip.uint(), region, &word)
        } else {
            self.scalar(chip, region, value)
        }
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
        plan: &VerifierPlan<Ep>,
        key: &VerifyingKey<Ep>,
    ) -> Result<VerifierKeyCells<Ep>, Error> {
        let source = omega_key_source(plan, key, self.known)?;
        chip.witness_key(
            region,
            source.representation,
            &source.fixed,
            &source.permutation,
        )
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
    fn insertion(
        self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        witness: &IndexedInsert<Fp>,
    ) -> Result<InsertCells, Error> {
        let leaf = witness.leaf;
        let values = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let mut paths = Vec::new();
        for (index, siblings) in [
            (witness.leaf_slot, witness.leaf_siblings),
            (witness.slot, witness.slot_siblings),
        ] {
            let index = uint
                .glue()
                .witness(region, self.value(Fp::from(u64::from(index))))?;
            let siblings = uint
                .glue()
                .witnesses(region, &siblings.map(|v| self.value(v)))?
                .try_into()
                .map_err(|_| Error::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells {
                leaf: LeafCells::from_words(values),
                path: low,
            },
            slot,
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
    pub(super) source: Arc<Source>,
    pub(super) continuation: Option<Continuation>,
    pub(super) pallas: AccumulatorT<Ep>,
    pub(super) fold: Vec<u8>,
    pub(super) known: bool,
}
/// Fixed native Receive verifier, raw-tape and public-column configuration.
#[derive(Clone, Debug)]
pub struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Circuit<Fp> for Stage {
    type Config = Config;
    type Params = usize;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> usize {
        // Only operation-terminal A keys can enter the uniform tagged3 Omega
        // catalog. Internal tagged4 keys are pinned by their exact W wrapper.
        if self
            .continuation
            .as_ref()
            .is_some_and(|c| c.plan.is_terminal())
        {
            3
        } else {
            4
        }
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, 4)
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
        let source = &self.source;
        let stage = self.continuation.as_ref().map_or(0, |c| c.plan.stage());
        let plan = source.plan.context();
        let tasks = plan.operation_tasks(stage).ok_or(Error::Synthesis)?;
        let out = layouter.assign_region(
            || "genuine Receive fixed owner stage",
            |mut region| {
                let (old, pred_public) =
                    cells.state(&mut chip, &mut region, &source.own.witness.before)?;
                let (new, next_public) =
                    cells.state(&mut chip, &mut region, &source.own.witness.after)?;
                let fields = cells.words(&mut chip, &mut region, &source.own.witness.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    source.variant,
                    &fields,
                )?;
                let incoming_fields = source.own.send.statement;
                let fields = cells.words(&mut chip, &mut region, &incoming_fields)?;
                let lanes = chip.operation_lanes()?;
                let incoming_statement = IncomingStatementCells::constrain(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let q_instances = source
                    .q
                    .iter()
                    .map(|q| {
                        q.instances
                            .iter()
                            .enumerate()
                            .map(|(column, col)| {
                                col.iter()
                                    .map(|v| {
                                        let value = *v;
                                        let ty = *q
                                            .plan
                                            .verifier()
                                            .binding()
                                            .descriptor()
                                            .instance_types
                                            .as_ref()
                                            .and_then(|types| types.get(column))
                                            .ok_or(Error::Synthesis)?;
                                        cells.q_instance(&mut chip, &mut region, value, ty)
                                    })
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let pp = cells.pallas(
                    &mut chip,
                    &mut region,
                    &source.predecessor.pallas.as_input(),
                )?;
                let pv = cells.vesta(&mut chip, &mut region, &source.predecessor.vesta)?;
                let ip = cells.pallas(
                    &mut chip,
                    &mut region,
                    &source.incoming_head.pallas.as_input(),
                )?;
                let iv = cells.vesta(&mut chip, &mut region, &source.incoming_head.vesta)?;
                let original_fields =
                    cells.words(&mut chip, &mut region, &source.incoming_head.state.lineage)?;
                let public_valid = chip
                    .uint()
                    .glue()
                    .boolean(&mut region, cells.value(source.public_valid))?;
                let incoming_public = IncomingLineageCells::constrain(
                    &mut chip.uint(),
                    &mut region,
                    &original_fields,
                    &public_valid,
                )?;
                let modes = (0..4)
                    .map(|index| {
                        let values = source.mode_words(index);
                        let bits = cells.words(&mut chip, &mut region, &values)?;
                        ModeCells::constrain(chip.uint().glue(), &mut region, &bits)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let corrections = source
                    .pallas_corrections
                    .map(|point| chip.witness_point(&mut region, cells.value(Ep::from(point))))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                let (x, y) =
                    Option::from(source.vesta_correction.coordinates()).ok_or(Error::Synthesis)?;
                let vcorrections = [[
                    cells.scalar(&mut chip, &mut region, x)?,
                    cells.scalar(&mut chip, &mut region, y)?,
                ]];
                let exported = source.incoming_head.opening.clone();
                let opening = cells.pallas(&mut chip, &mut region, &exported)?;
                let verdicts = source.results;
                let results = ReceiveResultClaims::assign(
                    chip.uint().glue(),
                    &mut region,
                    plan.receive_results().ok_or(Error::Synthesis)?,
                    verdicts.map(|v| cells.value(v)),
                )?
                .with_opening(&opening)?;
                let proposals = &source.commitments;
                let commitments = proposals
                    .iter()
                    .map(|v| v.map(|v| cells.value(v)))
                    .collect::<Vec<_>>();
                let context =
                    plan.assign_receive_object_claims(&mut chip, &mut region, &commitments)?;
                // Fixed owner predicates derive both selectors from the original
                // Request/Send statement. Reuse the hard Q exports here so this
                // circuit covers every admitted control mask with one schema.
                let own_index =
                    crate::a_relation::bounded_word(&mut chip, &mut region, &q_instances[0][2][0])?;
                let incoming_index =
                    crate::a_relation::bounded_word(&mut chip, &mut region, &q_instances[0][2][1])?;
                let own_chunks = source
                    .own
                    .sigma_plan
                    .chunk_range(0)
                    .ok_or(Error::Synthesis)?
                    .map(|i| {
                        crate::a_relation::bounded_word(
                            &mut chip,
                            &mut region,
                            &q_instances[0][0][i],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let incoming_chunks = source
                    .own
                    .sigma_plan
                    .chunk_range(1)
                    .ok_or(Error::Synthesis)?
                    .map(|i| {
                        crate::a_relation::bounded_word(
                            &mut chip,
                            &mut region,
                            &q_instances[0][0][i],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut own_sigma =
                    SigmaBindingCells::from_statement(&statement, own_index.clone(), own_chunks);
                let mut incoming_sigma = SigmaBindingCells::from_incoming(
                    &incoming_statement,
                    incoming_index.clone(),
                    incoming_chunks,
                );
                if tasks.contains(&OperationTask::ReceiveOwnProof) {
                    let raw = frame(&source.own.sigma)?;
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
                let needs_transport = tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveObjects | OperationTask::ReceiveProofs
                    )
                });
                let needs_digest = tasks.contains(&OperationTask::ReceiveProofDigest);
                let transport_plan = IncomingTransportPlan::new(plan.operation())?;
                let omega_raw = if needs_transport || needs_digest {
                    let segments = if needs_transport {
                        transport_plan.active_segments()?
                    } else {
                        vec![]
                    };
                    Some(cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.incoming,
                        plan.object_specs()[4].capacity as usize,
                        &segments,
                    )?)
                } else {
                    None
                };
                let sigma_raw = if tasks.contains(&OperationTask::ReceiveObjects) || needs_digest {
                    let segments = if tasks.contains(&OperationTask::ReceiveObjects) {
                        SigmaBindingCells::incoming_segments(
                            source
                                .own
                                .sigma_plan
                                .class(1)
                                .ok_or(Error::Synthesis)?
                                .verifier()
                                .proof_length(),
                        )?
                    } else {
                        vec![]
                    };
                    Some(cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.own.incoming_sigma,
                        plan.object_specs()[5].capacity as usize,
                        &segments,
                    )?)
                } else {
                    None
                };
                let transport = if needs_transport {
                    Some(transport_plan.decode_active(
                        &mut chip,
                        &mut region,
                        omega_raw.as_ref().ok_or(Error::Synthesis)?,
                        next_public.omega_key_digest(),
                    )?)
                } else {
                    None
                };
                if tasks.contains(&OperationTask::ReceiveObjects) {
                    incoming_sigma = SigmaBindingCells::from_incoming_active(
                        &mut chip,
                        &mut region,
                        &incoming_statement,
                        incoming_index,
                        sigma_raw.as_ref().ok_or(Error::Synthesis)?,
                        source
                            .own
                            .sigma_plan
                            .class(1)
                            .ok_or(Error::Synthesis)?
                            .verifier()
                            .proof_length(),
                    )?;
                }
                let proof_digest = if needs_digest {
                    Some(ReceiveProofDigest::from_active(
                        &mut chip,
                        &mut region,
                        omega_raw.as_ref().ok_or(Error::Synthesis)?,
                        sigma_raw.as_ref().ok_or(Error::Synthesis)?,
                        context[5].authenticated_digest(),
                    )?)
                } else {
                    None
                };
                let values = source.objects.each_ref().map(|raw| cells.bytes(raw));
                let objects = if tasks.contains(&OperationTask::ReceiveObjects) {
                    Some(ReceiveObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        source.policy,
                        ReceiveObjectSources {
                            request: &values[0],
                            payer: &values[1],
                            receipt: &values[2],
                            payment: &values[3],
                        },
                        ReceiveObjectInputs {
                            own: &statement,
                            receiver: &pred_public,
                            incoming: transport.as_ref().ok_or(Error::Synthesis)?,
                            sigma: &incoming_sigma,
                            consuming_digest: context[4].authenticated_digest(),
                        },
                    )?)
                } else {
                    None
                };
                let signed = if tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveSignatures | OperationTask::ReceiveBlacklist
                    )
                }) {
                    Some(ReceiveSignedObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        [&values[0], &values[1], &values[2]],
                    )?)
                } else {
                    None
                };
                let auth = if tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveAuthorization
                            | OperationTask::ReceiveOwnProof
                            | OperationTask::ReceiveSignatures
                    )
                }) {
                    Some(ReceiveAuthorizationObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        source.variant,
                        ReceiveAuthorizationSources {
                            current: &values[6],
                            certificate: &values[7],
                            receipt: &values[8],
                            quoted: [&values[9], &values[10]],
                        },
                    )?)
                } else {
                    None
                };
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
                    incoming: Some(ContextIncoming {
                        public: &incoming_public,
                        pallas: &ip,
                        vesta: &iv,
                        proof: ContextIncomingProof::ReceiveActive,
                    }),
                    q_instances: &q_instances,
                    objects: &context,
                    modes: &modes,
                    pallas_corrections: &corrections,
                    vesta_corrections: &vcorrections,
                    receive_results: Some(&results),
                };
                let sigma = [own_sigma.clone(), incoming_sigma.clone()];
                let pred = if stage == 0 {
                    let key = cells.key(
                        &mut chip,
                        &mut region,
                        plan.operation().omega().ok_or(Error::Synthesis)?,
                        &source.predecessor.key,
                    )?;
                    let proof = cells.proof(&mut chip, &mut region, &source.predecessor.proof)?;
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
                let mut own_signature = None;
                for index in plan.q_partition(stage).ok_or(Error::Synthesis)? {
                    let proof = cells.proof(&mut chip, &mut region, &source.q[*index].proof)?;
                    let q = verify_q(
                        &mut chip,
                        &mut region,
                        plan.operation(),
                        *index,
                        &q_instances[*index],
                        &proof,
                    )?;
                    if *index == 1 {
                        let slots = crate::a_relation::bind_signature_q(
                            &mut chip,
                            &mut region,
                            plan.operation(),
                            *index,
                            source
                                .plan
                                .signature_schema(*index)
                                .ok_or(Error::Synthesis)?,
                            &q,
                        )?;
                        own_signature = Some(slots);
                    }
                    verified.push(q);
                }
                let proof_sources = transport
                    .as_ref()
                    .map(|transport| {
                        ReceiveProofSources::from_active_omega(transport, &incoming_sigma)
                    })
                    .transpose()?;
                let proof_key = if tasks.contains(&OperationTask::ReceiveProofs) {
                    Some(cells.key(
                        &mut chip,
                        &mut region,
                        plan.operation().omega().ok_or(Error::Synthesis)?,
                        &source.incoming_head.key,
                    )?)
                } else {
                    None
                };
                let nonmembership = if tasks.contains(&OperationTask::ReceiveNonmembership) {
                    Some(
                        cells
                            .insertion(&mut chip.uint(), &mut region, &source.own.witness.consumed)?
                            .low,
                    )
                } else {
                    None
                };
                let blacklist = if tasks.contains(&OperationTask::ReceiveBlacklist) {
                    Some(
                        cells
                            .insertion(
                                &mut chip.uint(),
                                &mut region,
                                &source.own.witness.blacklist,
                            )?
                            .low,
                    )
                } else {
                    None
                };
                let effects = if tasks.iter().any(|task| {
                    matches!(
                        task,
                        OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects
                    )
                }) {
                    let consumed = cells.insertion(
                        &mut chip.uint(),
                        &mut region,
                        &source.own.witness.consumed,
                    )?;
                    let credit = cells.insertion(
                        &mut chip.uint(),
                        &mut region,
                        &source.own.witness.credit,
                    )?;
                    let inserted_key = statement.fields()[17].clone();
                    let inserted_value = chip.hash_words(
                        &mut region,
                        crate::operation_relation::map_effects::CONSUMED_DOMAIN,
                        &[
                            inserted_key.clone(),
                            statement.fields()[20].clone(),
                            statement.fields()[9].clone(),
                        ],
                    )?;
                    let insert = chip
                        .uint()
                        .glue()
                        .boolean(&mut region, cells.value(source.own.witness.insert))?;
                    Some(ReceiveMapWitness {
                        consumed,
                        credit,
                        inserted_key,
                        inserted_value,
                        insert,
                        payment_digest: context[3].authenticated_digest().clone(),
                    })
                } else {
                    None
                };
                let incoming_signature = if tasks.contains(&OperationTask::ReceiveSignatures) {
                    Some(ReceiveSignatureQProjection::from_context(
                        &mut chip,
                        &mut region,
                        plan,
                        u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                        source.policy,
                        &input,
                    )?)
                } else {
                    None
                };
                source.plan.constrain_stage(
                    &mut chip,
                    &mut region,
                    u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                    ReceiveStageInputs {
                        context: &input,
                        proof_digest: proof_digest.as_ref(),
                        objects: objects.as_ref(),
                        signed: signed.as_ref(),
                        authorization: auth.as_ref(),
                        own_sigma: tasks
                            .contains(&OperationTask::ReceiveOwnProof)
                            .then_some(&own_sigma),
                    },
                    ReceiveStageWitness {
                        proofs: if let Some(key) = proof_key.as_ref() {
                            Some(ReceiveProofInputs {
                                sources: proof_sources.as_ref().ok_or(Error::Synthesis)?,
                                omega_key: key,
                                own_sigma: &own_sigma,
                            })
                        } else {
                            None
                        },
                        own_signatures: own_signature.as_ref(),
                        incoming_signatures: incoming_signature.as_ref(),
                        nonmembership: nonmembership.as_ref(),
                        blacklist: blacklist.as_ref(),
                        effects: effects.as_ref(),
                    },
                )?;
                let fold = cells.proof(&mut chip, &mut region, &self.fold)?;
                if let Some(continuation) = &self.continuation {
                    let pallas =
                        cells.pallas(&mut chip, &mut region, &continuation.carried.as_input())?;
                    let vesta = cells.vesta(&mut chip, &mut region, &continuation.vesta)?;
                    let proof = cells.proof(&mut chip, &mut region, &continuation.proof)?;
                    let resumed = resume_context(
                        &mut chip,
                        &mut region,
                        &continuation.plan,
                        &input,
                        &pallas,
                        &vesta,
                        &proof,
                        &sigma,
                    )?;
                    let selected = if continuation.plan.is_terminal() {
                        Some(resumed.select_receive_incoming(
                            &mut chip,
                            &mut region,
                            &continuation.plan,
                        )?)
                    } else {
                        None
                    };
                    let closed = close_stage(
                        &mut chip,
                        &mut region,
                        &continuation.plan,
                        &resumed,
                        None,
                        selected.as_ref().map(|v| &v.0),
                        selected.as_ref().map(|v| &v.1),
                        &verified,
                        &fold,
                    )?;
                    if continuation.plan.is_terminal() {
                        closed.words(&mut chip, &mut region, &next_public)
                    } else {
                        closed.continuation()?.words(&mut chip, &mut region)
                    }
                } else {
                    close_first(
                        &mut chip,
                        &mut region,
                        plan,
                        &input,
                        pred.as_ref(),
                        &verified,
                        &sigma,
                        Some(&fold),
                        &source.params,
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

/// Actual fixed-profile Receive A circuit; its metadata comes only from the installed plan.
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
#[path = "circuit/key_source_tests.rs"]
mod key_source_tests;
