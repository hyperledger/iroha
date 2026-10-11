//! Genuine Unload/Retiring with exact mandatory own authorization and consuming proof bytes.
//! The two-terminal predecessor catalog is a component scope, not the complete
//! release catalog. Every source proof, pending claim and operation task is real.
#![allow(clippy::duplicate_mod)]
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
/// Genuine immutable Bootstrap/Load catalog and its recursive fixtures.
#[path = "compact_catalog.rs"]
pub mod catalog;
mod common;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "a_consuming_recursive/native_load_tests.rs"]
mod native_load_tests;
#[path = "common/native_source_factory_checks.rs"]
mod native_source_factory_checks;
use catalog::{LoadFixture, send_chain::load_outer};
use load_outer::load_chain::bootstrap_outer::bootstrap_chain::SourceProfile;
#[path = "common/unload_objects.rs"]
mod unload_objects;
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, LineagePublicCells, ProofMessageCells, QProofPlan, SigmaBindingCells,
        VestaClaimCells,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        own::ConsumingProofCells,
        schedule::OperationTask,
        split::close_first,
        unload::{UnloadObjects, UnloadProofInputs, UnloadStagePlan, UnloadStageWitness},
        verify_predecessor, verify_sigma,
    },
    admin_sigma::{ConsumingWitness, RetiringCircuit, StateWitness, UnloadCircuit},
    operation_relation::{map_effects::InsertCells, state::StateCells, statement::StatementCells},
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, VerifyingKey, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    imt::{LeafCells, OpeningCells, PathCells},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::sync::Arc;

#[derive(Clone)]
struct Predecessor {
    key: VerifyingKey<Ep>,
    program: VerifierPlan<Ep>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    opening: FoldInput<Ep>,
    vesta: AccumulatorT<Eq>,
}
/// Exact authenticated predecessor projection, independent of its prior operation.
/// This copies no witness into a proof and never creates a loaded balance.
struct Head<'a> {
    state: StateWitness,
    binding: &'a iroha_plonk::DescriptorBinding,
    key: &'a VerifyingKey<Ep>,
    proof: &'a [u8],
    pallas: &'a AccumulatorT<Ep>,
    vesta: &'a AccumulatorT<Eq>,
    opening: &'a FoldInput<Ep>,
}
impl<'a> Head<'a> {
    fn loaded(artifact: &'a load_outer::DiagnosticLoadOmega) -> Self {
        Self {
            state: artifact.source.state,
            binding: &artifact.binding,
            key: &artifact.key,
            proof: &artifact.proof,
            pallas: &artifact.source.pallas,
            vesta: &artifact.vesta,
            opening: &artifact.opening,
        }
    }
}

#[derive(Clone)]
struct Sources {
    maps: Maps,
    objects: [bootstrap_objects::Signed; 3],
    variant: Variant,
    sigma: Vec<u8>,
    omega: Vec<u8>,
    plan: AProofPlan,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    q_openings: Vec<FoldInput<Ep>>,
    signature_schema: iroha_kagemusha_proof::q_signature::QSignaturePlan,
    part: FoldInput<Eq>,
    predecessor: Predecessor,
    params: PinnedParams<Ep>,
}
fn lineage_bytes(
    f: &[Fp; 18],
    proof: &[u8],
    p: &AccumulatorT<Ep>,
    v: &AccumulatorT<Eq>,
) -> Vec<u8> {
    let mut out = 1u16.to_le_bytes().to_vec();
    for i in [1, 2, 3, 4] {
        out.extend(&f[i].to_repr()[..16]);
    }
    out.extend(f[5].to_repr());
    for i in [6, 7] {
        out.extend(&f[i].to_repr()[..16]);
    }
    out.extend(f[8].to_repr());
    out.push(4);
    for i in [10, 9, 12, 11] {
        out.extend(f[i].to_repr()[..16].iter().rev());
    }
    out.extend(&f[13].to_repr()[..13]);
    out.extend(&f[14].to_repr()[..16]);
    out.extend(f[15].to_repr());
    out.extend(f[16].to_repr());
    assert_eq!(out.len(), 320);
    out.extend(proof);
    out.extend(p.to_bytes());
    out.extend(v.to_bytes());
    out
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    out.extend(bytes);
    out
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
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = chip
            .uint()
            .glue()
            .witnesses(region, &witness.core.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &witness.rest.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let state = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &witness.lineage.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let public = LineagePublicCells::constrain(&mut chip.uint(), region, &public)?;
        Ok((state, public))
    }
    pub(crate) fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<InsertCells, Error> {
        let insertion = self.recovery.as_ref().ok_or(Error::Synthesis)?;
        let leaf = insertion.leaf;
        let words = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
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
                .map_err(|_| Error::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells { leaf, path: low },
            slot,
        })
    }
}
fn leaf<C: Circuit<Fp>>(circuit: &C, public: &[Vec<Fp>]) -> (Vec<u8>, iroha_plonk::ProvingKey<Eq>) {
    let params = common::vesta_params(12);
    let key = keygen_pk_v2(
        &params,
        circuit,
        &KeygenConfigV2::pipa_r(UnloadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, public).unwrap(),
        common::recovery(230),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    (proof.proof, key)
}
fn sources(artifact: &Head<'_>, retiring: bool) -> Sources {
    let variant = if retiring {
        Variant::Retiring
    } else {
        Variant::Unload
    };
    assert_eq!(
        artifact.state.lineage[17],
        artifact.key.kagemusha_digest(artifact.binding).unwrap()
    );
    let (witness, recovery) = unload_objects::transition(&artifact.state, retiring);
    let public = [vec![hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &witness.statement,
    )]];
    let (sigma, leaf_key) = if retiring {
        leaf(&RetiringCircuit::new(&witness), &public)
    } else {
        leaf(&UnloadCircuit::new(&witness), &public)
    };
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = common::vesta_params(16);
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(leaf_key.binding().clone(), common::vesta_params(12)).unwrap(),
            vec![(
                if retiring { 15 } else { 13 },
                leaf_key.vk().kagemusha_digest(leaf_key.binding()).unwrap(),
            )],
        )
        .unwrap(),
        None,
        &vparams,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: leaf_key.vk().clone(),
                statement: public[0][0],
                length: sigma.len().try_into().unwrap(),
                proof: sigma.clone(),
            },
            None,
            &vparams,
            Fq::from(71),
            &FoldConfig::default(),
        )
        .unwrap();
    let part = prepared.part().clone();
    let q = QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), 2).unwrap();
    let qproof = q
        .prove(&prepared, common::recovery(231), ProverConfig::default())
        .unwrap();
    let qclaim = accumulate_generator(
        &params,
        q.binding(),
        q.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    qclaim.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let sigma_q = QProofPlan::new(
        VerifierPlan::new(q.binding().clone(), params.clone()).unwrap(),
        q.verifying_key().clone(),
    )
    .unwrap();
    let omega = lineage_bytes(
        &witness.predecessor.lineage,
        artifact.proof,
        artifact.pallas,
        artifact.vesta,
    );
    let (_, certificate, credential) = bootstrap_objects::enrollment();
    assert_eq!(witness.predecessor.core[7], credential.digest());
    let receipt = unload_objects::receipt(&witness, &omega, &sigma);
    let (signature, instances) =
        bootstrap_objects::signatures(&[certificate.clone(), credential.clone(), receipt.clone()]);
    let key = keygen_pk_v2(
        &params,
        &signature,
        &KeygenConfigV2::pipa_r(
            iroha_kagemusha_proof::q_signature::QSignaturePlan::instance_types().to_vec(),
        ),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &signature, &instances).unwrap(),
        common::recovery(232),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    let signature_q = QProofPlan::new(
        VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
        key.vk().clone(),
    )
    .unwrap();
    let predecessor = Predecessor {
        key: artifact.key.clone(),
        program: VerifierPlan::new(artifact.binding.clone(), params.clone()).unwrap(),
        proof: artifact.proof.to_vec(),
        pallas: artifact.pallas.clone(),
        opening: artifact.opening.clone(),
        vesta: artifact.vesta.clone(),
    };
    let plan = AProofPlan::new(
        variant,
        sigma_plan,
        vec![sigma_q, signature_q],
        Some(predecessor.program.clone()),
        &params,
    )
    .unwrap();
    Sources {
        maps: Maps {
            witness,
            recovery,
            known: true,
        },
        objects: [credential, certificate, receipt],
        variant,
        sigma,
        omega,
        plan,
        q_instances: vec![qproof.instances, instances.to_vec()],
        q_proofs: vec![qproof.bytes, proof.proof],
        q_openings: vec![
            FoldInput::from_opening(*qclaim.g(), qclaim.challenges()).unwrap(),
            FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap(),
        ],
        signature_schema: signature.plan().clone(),
        part,
        predecessor,
        params,
    }
}
#[derive(Clone)]
struct First {
    source: Arc<Sources>,
    profile: SourceProfile,
    plan: ContextPlan,
    pallas: AccumulatorT<Ep>,
    fold: Vec<u8>,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl First {
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
    ) -> Result<ScalarCells<Ep>, Error> {
        let [lo, hi] = foreign_limbs(&v);
        let lo = chip.uint().assign::<128>(region, self.value(lo))?;
        let hi = chip.uint().assign::<127>(region, self.value(hi))?;
        ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
    }
    fn pallas(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: &FoldInput<Ep>,
    ) -> Result<FoldInputCells<Ep>, Error> {
        let g = chip.witness_point(region, self.value(Ep::from(*input.g())))?;
        let challenges = input
            .challenges()
            .iter()
            .map(|v| self.scalar(chip, region, *v))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        FoldInputCells::from_normalized(chip, region, 16, g, challenges)
    }
    fn vesta(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: &AccumulatorT<Eq>,
    ) -> Result<VestaClaimCells, Error> {
        let (x, y) = Option::from(input.g().coordinates()).ok_or(Error::Synthesis)?;
        let coordinates = [self.scalar(chip, region, x)?, self.scalar(chip, region, y)?];
        let challenges = chip
            .uint()
            .glue()
            .witnesses(region, &input.challenges().map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        VestaClaimCells::constrain(chip, region, 16, coordinates, challenges)
    }
    fn carrier(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        body: &[u8],
    ) -> Result<ProofMessageCells, Error> {
        let length = u32::try_from(body.len()).map_err(|_| Error::BoundsFailure)?;
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
    ) -> Result<SigmaBindingCells, Error> {
        let length = u32::try_from(self.source.sigma.len()).map_err(|_| Error::BoundsFailure)?;
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
            Fp::from(if self.source.variant == Variant::Unload {
                13
            } else {
                15
            }),
        )?;
        SigmaBindingCells::from_run(chip, region, statement, index, &run)
    }
}
impl First {
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<UnloadObjects, Error> {
        let sources = self
            .source
            .objects
            .each_ref()
            .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        UnloadObjects::decode(chip, bytes, region, sources.each_ref().map(Vec::as_slice))
    }
}

impl Circuit<Fp> for First {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = SourceProfile;
    fn params(&self) -> SourceProfile {
        self.profile
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, SourceProfile::Generic)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, profile: SourceProfile) -> Config {
        let verifier = profile.configure(meta);
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
        let out = layouter.assign_region(
            || "genuine consuming predecessor-first relation",
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
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    self.source.variant,
                    &fields,
                )?;
                let sigma = self.sigma(&mut chip, &mut bytes, &mut region, &statement)?;
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
                    &self.source.predecessor.pallas.as_input(),
                )?;
                let pv = self.vesta(&mut chip, &mut region, &self.source.predecessor.vesta)?;
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
                    return Err(Error::Synthesis);
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
                let omega = frame(&self.source.omega);
                let omega_run = bytes.run(
                    &mut region,
                    &omega.iter().map(|v| self.value(*v)).collect::<Vec<_>>(),
                    &iroha_plonk_gadgets::bytes::chunk_segments(0, omega.len()),
                    &ConsumingProofCells::omega_segments(self.source.predecessor.proof.len())?,
                )?;
                let sigma_tape = frame(&self.source.sigma);
                let sigma_run = bytes.run(
                    &mut region,
                    &sigma_tape
                        .iter()
                        .map(|v| self.value(*v))
                        .collect::<Vec<_>>(),
                    &iroha_plonk_gadgets::bytes::chunk_segments(0, sigma_tape.len()),
                    &[SegmentSpec::little(0, 4)],
                )?;
                let consuming = ConsumingProofCells::from_runs(
                    &mut chip,
                    &mut region,
                    &pred,
                    &sigma,
                    &omega_run,
                    &sigma_run,
                )?;
                UnloadStagePlan::new(self.plan.clone(), load_objects::policy())?.constrain_stage(
                    &mut chip,
                    &mut region,
                    0,
                    &objects,
                    &input,
                    UnloadStageWitness {
                        proof: Some(UnloadProofInputs {
                            proof: &consuming,
                            sigma: &sigma,
                        }),
                        ..UnloadStageWitness::default()
                    },
                )?;
                let mut verified = Vec::new();
                for (index, columns) in q_instances
                    .iter()
                    .enumerate()
                    .take(self.plan.first_q_count())
                {
                    let proof = self.carrier(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &self.source.q_proofs[index],
                    )?;
                    let (q, _) = verify_sigma(
                        &mut chip,
                        &mut region,
                        self.plan.operation(),
                        columns,
                        &proof,
                        core::slice::from_ref(&sigma),
                    )?;
                    verified.push(q);
                }
                let fold = self.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                let first = close_first(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    Some(&pred),
                    &verified,
                    core::slice::from_ref(&sigma),
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
    plan: iroha_kagemusha_proof::a_relation::split::SplitPlan,
    wrapper: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    fold: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    carried: AccumulatorT<Ep>,
    omit_q: Option<usize>,
}
impl Circuit<Fp> for Continuation {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = SourceProfile;
    fn params(&self) -> SourceProfile {
        self.first.profile
    }
    fn without_witnesses(&self) -> Self {
        Self {
            first: self.first.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        First::configure(meta)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, profile: SourceProfile) -> Config {
        First::configure_with_params(meta, profile)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let first = &self.first;
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "Consuming deferred Q continuation",
            |mut region| {
                let mut maps = first.source.maps.clone();
                maps.known = first.known;
                let (old, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.predecessor)?;
                let (new, next_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| first.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    first.source.variant,
                    &fields,
                )?;
                let sigma = first.sigma(&mut chip, &mut bytes, &mut region, &statement)?;
                let objects = first.objects(&mut chip, &mut bytes, &mut region)?;
                let context_objects = objects.context();
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
                    &first.source.predecessor.pallas.as_input(),
                )?;
                let pv = first.vesta(&mut chip, &mut region, &first.source.predecessor.vesta)?;
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
                let cp = first.pallas(&mut chip, &mut region, &self.carried.as_input())?;
                let cv = first.vesta(&mut chip, &mut region, &self.vesta)?;
                let proof = first.carrier(&mut chip, &mut bytes, &mut region, &self.wrapper)?;
                let resumed = iroha_kagemusha_proof::a_relation::split::resume_context(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    &cp,
                    &cv,
                    &proof,
                    core::slice::from_ref(&sigma),
                )?;
                let mut verified = Vec::new();
                for index in first
                    .plan
                    .q_partition(self.plan.stage())
                    .ok_or(Error::Synthesis)?
                    .iter()
                    .copied()
                {
                    let columns = &q_instances[index];
                    if self.omit_q == Some(index) {
                        continue;
                    }
                    let proof = first.carrier(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &first.source.q_proofs[index],
                    )?;
                    let q = if index == 0 {
                        verify_sigma(
                            &mut chip,
                            &mut region,
                            first.plan.operation(),
                            columns,
                            &proof,
                            core::slice::from_ref(&sigma),
                        )?
                        .0
                    } else {
                        let q = iroha_kagemusha_proof::a_relation::verify_q(
                            &mut chip,
                            &mut region,
                            first.plan.operation(),
                            index,
                            columns,
                            &proof,
                        )?;
                        let slots = iroha_kagemusha_proof::a_relation::bind_signature_q(
                            &mut chip,
                            &mut region,
                            first.plan.operation(),
                            index,
                            &first.source.signature_schema,
                            &q,
                        )?;
                        UnloadStagePlan::new(first.plan.clone(), load_objects::policy())?
                            .constrain_stage(
                                &mut chip,
                                &mut region,
                                self.plan.stage(),
                                &objects,
                                &input,
                                UnloadStageWitness {
                                    signatures: Some(&slots),
                                    ..UnloadStageWitness::default()
                                },
                            )?;
                        slots.verified().clone()
                    };
                    verified.push(q);
                }
                if !first
                    .plan
                    .q_partition(self.plan.stage())
                    .ok_or(Error::Synthesis)?
                    .contains(&1)
                {
                    let tasks = first
                        .plan
                        .operation_tasks(self.plan.stage())
                        .ok_or(Error::Synthesis)?;
                    let recovery = if tasks.contains(&OperationTask::UnloadRecovery) {
                        Some(maps.insertion(&mut chip.uint(), &mut region)?)
                    } else {
                        None
                    };
                    UnloadStagePlan::new(first.plan.clone(), load_objects::policy())?
                        .constrain_stage(
                            &mut chip,
                            &mut region,
                            self.plan.stage(),
                            &objects,
                            &input,
                            UnloadStageWitness {
                                recovery: recovery.as_ref(),
                                ..UnloadStageWitness::default()
                            },
                        )?;
                }
                let fold = first.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                let closed = iroha_kagemusha_proof::a_relation::split::close_stage(
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
impl Continuation {
    fn public(&self) -> Vec<Vec<Fp>> {
        if !self.plan.is_terminal() {
            let digest = stage_digest(
                &self.first.plan,
                self.plan.stage(),
                context_digest(&self.first),
                &self.pallas,
            );
            return internal_public(digest, &self.vesta.as_input());
        }
        let mut lineage = self.first.source.maps.witness.successor.lineage.to_vec();
        let (x, y) = self.pallas.g().coordinates().unwrap();
        lineage.extend([x, y]);
        for u in self.pallas.challenges() {
            lineage.extend(foreign_limbs(u).map(Fp::from_u128));
        }
        let digest = hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &lineage);
        let mut out = vec![digest, Fp::from(16)];
        out.extend(vesta_words(&self.vesta.as_input()));
        out.extend(vesta_words(&self.first.source.predecessor.vesta.as_input()));
        let trivial =
            AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
        let words = vesta_words(&trivial.as_input());
        out.extend(&words);
        out.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
        out.extend(&words[..4]);
        assert_eq!(out.len(), 69);
        vec![out]
    }
}
fn stage_digest(plan: &ContextPlan, stage: usize, base: Fp, current: &AccumulatorT<Ep>) -> Fp {
    assert!(stage + 1 < plan.stage_count());
    let mut words = vec![
        Fp::ONE,
        plan.schema()[1],
        Fp::from(u64::try_from(stage + 1).unwrap()),
        base,
    ];
    push_pallas(&mut words, &current.as_input());
    hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
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
/// Genuine authenticated Unload/Retiring terminal artifacts for outer/next-operation tests.
/// The supplied predecessor's catalog/profile provenance is retained unchanged;
/// this fixture does not declare the resulting lineage admitted by a final catalog.
#[derive(Clone)]
#[allow(dead_code)] // Outer and next-operation tests consume all carried artifacts.
pub(crate) struct AuthenticatedConsuming {
    pub(crate) key: VerifyingKey<Eq>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Fp>,
    pub(crate) opening: FoldInput<Eq>,
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) vesta_part: AccumulatorT<Eq>,
    pub(crate) predecessor_vesta: AccumulatorT<Eq>,
    pub(crate) state: iroha_kagemusha_proof::admin_sigma::StateWitness,
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
fn proof_identity(bytes: &[u8]) -> Fp {
    let mut framed = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    framed.extend(bytes);
    let words = framed
        .chunks(31)
        .map(|chunk| {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            Fp::from_repr(repr).unwrap()
        })
        .collect::<Vec<_>>();
    hash_with_domain(u64::from_le_bytes(*b"kgwtstp1"), &words)
}
fn artifact_diagnostics(
    stage: usize,
    key: &iroha_plonk::ProvingKey<Eq>,
    proof: &[u8],
    range_buses: usize,
) {
    eprintln!(
        "CONSUMING_A_ARTIFACT stage={} range_buses={} shape={:?} descriptor_personalized_blake2b={} vk_kgwvkey1={} proof_pbytes_kgwtstp1={} proof_bytes={} diagnostic_only=true",
        stage + 1,
        range_buses,
        iroha_plonk::protocol::Protocol::new(key.binding().descriptor())
            .unwrap()
            .shape(),
        hex(key.binding().digest()),
        hex(&key.vk().kagemusha_digest(key.binding()).unwrap().to_repr()),
        hex(&proof_identity(proof).to_repr()),
        proof.len()
    );
}
fn continue_schedule(
    first: &First,
    first_key: &iroha_plonk::ProvingKey<Eq>,
    first_proof: iroha_plonk::ProverOutput<Eq>,
    first_public: &[Vec<Fp>],
    adversarial: bool,
    native_differential: bool,
) -> Option<AuthenticatedConsuming> {
    use iroha_kagemusha_proof::a_relation::split::{SplitPlan, WCircuit, WKey};
    let params = &first.source.params;
    let vparams = common::vesta_params(16);
    let mut source_key = first_key.clone();
    let mut source_proof = first_proof;
    let mut source_public = first_public.to_vec();
    let mut carried = first.pallas.clone();
    let mut part = first.source.part.clone();
    let mut intermediate_keys = vec![first_key.vk().clone()];
    let mut installed_a = vec![Arc::new(first_key.clone())];
    let mut installed_w = Vec::new();
    let mut originals_a = vec![(source_proof.proof.clone(), carried.to_bytes())];
    let mut originals_w = Vec::new();
    for stage in 1..first.plan.stage_count() {
        let own =
            FoldInput::from_opening(*source_proof.opening.g(), source_proof.opening.challenges())
                .unwrap();
        let trivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT)
            .unwrap()
            .as_input();
        let (vfold, vesta) = create_fold(
            &vparams,
            &[part, own, trivial.clone(), trivial],
            Fq::from(123 + u64::try_from(stage).unwrap()).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        vesta.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
        let witness = iroha_kagemusha_proof::omega::OmegaWitness {
            key: source_key.vk().clone(),
            instances: source_public[0].clone(),
            length: source_proof.proof.len().try_into().unwrap(),
            proof: source_proof.proof,
            fold: vfold.to_bytes(),
        };
        assert!(
            WCircuit::new(
                &first.plan,
                first.plan.stage_count() - 1,
                source_key.binding().clone(),
                vparams.clone(),
                vec![
                    source_key
                        .vk()
                        .kagemusha_digest(source_key.binding())
                        .unwrap()
                ],
                witness.clone()
            )
            .is_err(),
            "terminal A cannot be wrapped as an intermediate stage"
        );
        let circuit = WCircuit::new(
            &first.plan,
            stage - 1,
            source_key.binding().clone(),
            vparams.clone(),
            vec![
                source_key
                    .vk()
                    .kagemusha_digest(source_key.binding())
                    .unwrap(),
            ],
            witness,
        )
        .unwrap();
        let (wkey, wprover) = WKey::keygen(&circuit, params).unwrap();
        installed_w.push(Arc::new(wprover.clone()));
        for wrong_stage in 0..=first.plan.stage_count() {
            if wrong_stage != stage {
                assert!(
                    SplitPlan::new(first.plan.clone(), wrong_stage, wkey.clone(), params).is_err(),
                    "wrong-stage W must not resume at {wrong_stage}"
                );
            }
        }
        let (x, y) = vesta.g().coordinates().unwrap();
        let wpublic = vec![
            vec![Fq::from_repr(source_public[0][0].to_repr()).unwrap()],
            vec![x, y],
            vesta
                .challenges()
                .iter()
                .map(|v| Fq::from_repr(v.to_repr()).unwrap())
                .collect(),
        ];
        let wrapper = create_proof_owned_with_claim(
            params,
            &wprover,
            Witness::from_circuit(&wprover, &circuit, &wpublic).unwrap(),
            common::recovery(196 + u8::try_from(stage).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        let wopening = accumulate_generator(
            params,
            wprover.binding(),
            wprover.vk(),
            &wpublic,
            &wrapper.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        wopening.decide(params, MemoryBudget::DEFAULT).unwrap();
        let indices = first.plan.q_partition(stage).unwrap();
        let mut claims = vec![
            carried.as_input(),
            FoldInput::from_opening(*wopening.g(), wopening.challenges()).unwrap(),
        ];
        claims.extend(indices.iter().map(|i| first.source.q_openings[*i].clone()));
        let salt = Fp::from(124 + u64::try_from(stage).unwrap()).to_repr();
        let (fold, pallas) = create_fold(params, &claims, salt, &FoldConfig::default()).unwrap();
        pallas.decide(params, MemoryBudget::DEFAULT).unwrap();
        originals_w.push((wrapper.proof.clone(), vesta.to_bytes()));
        let continuation = Continuation {
            first: first.clone(),
            plan: SplitPlan::new(first.plan.clone(), stage, wkey, params).unwrap(),
            wrapper: wrapper.proof,
            vesta: vesta.clone(),
            fold: fold.to_bytes().to_vec(),
            pallas: pallas.clone(),
            carried: carried.clone(),
            omit_q: None,
        };
        let public = continuation.public();
        let (assigned, k) = match synthesize(&continuation, 16, Some(&public)) {
            Ok(a) => (a, 16),
            Err(error) => {
                eprintln!(
                    "actual consuming A{} fails k16 {error:?}; diagnostic k18 only",
                    stage + 1
                );
                (synthesize(&continuation, 18, Some(&public)).unwrap(), 18)
            }
        };
        let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{:?}", report.failures().first());
        let unknown = synthesize(&continuation.without_witnesses(), k, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let lanes: Vec<_> = assigned
            .tables
            .advice_assigned()
            .iter()
            .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect();
        eprintln!(
            "genuine consuming A{} hard W+Q{indices:?}+context+fold range_buses={} lanes={lanes:?}, production_k16_fit={}",
            stage + 1,
            first.profile.range_buses(),
            k == 16
        );
        if adversarial {
            if indices.contains(&1) {
                let mut changed = (*first.source).clone();
                let last = changed.objects[2].bytes.len() - 1;
                changed.objects[2].bytes[last] ^= 1;
                let mut cross_receipt = continuation.clone();
                cross_receipt.first.source = Arc::new(changed);
                assert!(
                    !iroha_plonk::check::check_circuit(
                        &cross_receipt,
                        k,
                        &cross_receipt.public(),
                        CheckMode::Strict,
                    )
                    .is_ok_and(|r| r.is_satisfied()),
                    "signature stage cannot substitute context-committed receipt tape"
                );
            }
            for omitted in 0..claims.len() {
                let kept = claims
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != omitted)
                    .map(|(_, c)| c.clone())
                    .collect::<Vec<_>>();
                let (fold, _) = create_fold(params, &kept, salt, &FoldConfig::default()).unwrap();
                let mut bad = continuation.clone();
                bad.fold = fold.to_bytes().to_vec();
                assert!(
                    !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                        .is_ok_and(|r| r.is_satisfied()),
                    "dropped stage{stage} claim{omitted}"
                );
            }
            let mut doubled = claims.clone();
            doubled.push(claims[0].clone());
            let (fold, _) = create_fold(params, &doubled, salt, &FoldConfig::default()).unwrap();
            let mut bad = continuation.clone();
            bad.fold = fold.to_bytes().to_vec();
            assert!(
                !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "double-consumed stage{stage} contextP"
            );
            for index in indices {
                let mut bad = continuation.clone();
                bad.omit_q = Some(*index);
                assert!(
                    !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                        .is_ok_and(|r| r.is_satisfied()),
                    "partial W cannot omit stage{stage} Q{index}"
                );
                let mut source = (*first.source).clone();
                source.q_proofs[*index][0] ^= 1;
                let mut bad = continuation.clone();
                bad.first.source = Arc::new(source);
                assert!(
                    !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                        .is_ok_and(|r| r.is_satisfied()),
                    "wrong deferred proof stage{stage} Q{index}"
                );
            }
            for replace_pallas in [true, false] {
                let mut bad = continuation.clone();
                if replace_pallas {
                    bad.carried = AccumulatorT::trivial(params, MemoryBudget::DEFAULT).unwrap();
                } else {
                    bad.vesta = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
                }
                assert!(
                    !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                        .is_ok_and(|r| r.is_satisfied()),
                    "substituted current P/V obligation at stage{stage}"
                );
            }
        }
        if k != 16 {
            return None;
        }
        let mut cfg = KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]);
        cfg.compress_selectors = false;
        let key = keygen_pk_v2(&vparams, &continuation, &cfg).unwrap();
        assert_eq!(key.binding().descriptor(), first_key.binding().descriptor());
        let proof = create_proof_owned_with_claim(
            &vparams,
            &key,
            Witness::from_circuit(&key, &continuation, &public).unwrap(),
            common::recovery(200 + u8::try_from(stage).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        proof
            .opening
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        eprintln!(
            "actual consuming A{} proof={}B; terminal={}; final Omega/full catalog still pending",
            stage + 1,
            proof.proof.len(),
            continuation.plan.is_terminal()
        );
        artifact_diagnostics(stage, &key, &proof.proof, first.profile.range_buses());
        installed_a.push(Arc::new(key.clone()));
        originals_a.push((proof.proof.clone(), pallas.to_bytes()));
        if continuation.plan.is_terminal() {
            let final_digest = key.vk().kagemusha_digest(key.binding()).unwrap();
            let final_catalog = iroha_kagemusha_proof::omega::OmegaPlan::new(
                key.binding().clone(),
                vparams.clone(),
                vec![final_digest],
            )
            .unwrap();
            assert!(
                final_catalog
                    .clone()
                    .with_key_catalog(vec![key.vk().clone()])
                    .is_ok()
            );
            for internal in &intermediate_keys {
                assert_ne!(
                    internal.kagemusha_digest(key.binding()).unwrap(),
                    final_digest
                );
                assert!(
                    final_catalog
                        .clone()
                        .with_key_catalog(vec![internal.clone()])
                        .is_err(),
                    "terminal-only catalog rejects every intermediate A key"
                );
            }
            if native_differential {
                native_installed_consuming_differential(
                    first,
                    installed_a,
                    installed_w,
                    &originals_a,
                    &originals_w,
                );
            }
            return Some(AuthenticatedConsuming {
                key: key.vk().clone(),
                binding: key.binding().clone(),
                opening: FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges())
                    .unwrap(),
                proof: proof.proof,
                instances: public[0].clone(),
                pallas,
                vesta_part: vesta,
                predecessor_vesta: first.source.predecessor.vesta.clone(),
                state: first.source.maps.witness.successor,
            });
        }
        intermediate_keys.push(key.vk().clone());
        carried = pallas;
        part = vesta.as_input();
        source_key = key;
        source_proof = proof;
        source_public = public;
    }
    None
}
fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) {
    words.push(Fp::from(16));
    let (x, y) = claim.g().coordinates().unwrap();
    words.extend([x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = claim.g().coordinates().unwrap();
    let mut words = vec![];
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}
fn context_digest(first: &First) -> Fp {
    let s = &first.source;
    let mut words = first.plan.schema().to_vec();
    words.extend(s.maps.witness.statement);
    let before = &s.maps.witness.predecessor;
    let after = &s.maps.witness.successor;
    words.extend(before.core);
    words.extend(before.rest);
    words.extend(before.lineage);
    push_pallas(&mut words, &s.predecessor.pallas.as_input());
    words.extend(vesta_words(&s.predecessor.vesta.as_input()));
    words.extend(after.core);
    words.extend(after.rest);
    words.extend(after.lineage);
    for v in s.q_instances.iter().flatten().flatten() {
        words.extend(foreign_limbs(v).map(Fp::from_u128));
    }
    let all = s
        .objects
        .iter()
        .map(|o| o.bytes.clone())
        .collect::<Vec<_>>();
    let kinds = [
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Credential,
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Certificate,
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Receipt,
    ];
    for ((object, spec), kind) in all
        .iter()
        .zip(UnloadObjects::context_specs().unwrap())
        .zip(kinds)
    {
        let mut tape = vec![
            Fp::from(u64::from(spec.tag)),
            Fp::from(u64::from(spec.capacity)),
        ];
        for chunk in frame(object).chunks(31) {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            tape.push(Fp::from_repr(repr).unwrap());
        }
        let end = kind.body_len();
        let mut values = vec![iroha_plonk_gadgets::bytes::p_bytes_native(
            kind.signing_domain(),
            &object[..end],
        )];
        for offset in [16, 0, 48, 32] {
            values.push(Fp::from_u128(u128::from_be_bytes(
                object[end + offset..end + offset + 16].try_into().unwrap(),
            )));
        }
        let digest = hash_with_domain(kind.object_domain(), &values);
        words.extend([
            digest,
            Fp::from(u64::from(spec.capacity)),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
    }
    hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words)
}
fn first_public(first: &First) -> Vec<Vec<Fp>> {
    let mut words = vec![
        stage_digest(&first.plan, 0, context_digest(first), &first.pallas),
        Fp::from(12),
    ];
    words.extend(vesta_words(&first.source.part));
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

/// Run the retained composition assertions with genuine native Load originals.
pub fn compact_loaded_wallet_proves_unload_and_retiring_with_all_owners(fixture: &LoadFixture) {
    let rooted = catalog::compact_payer_load(fixture);
    for retiring in [false, true] {
        run_consuming_from_load(&rooted, retiring, false);
    }
}

fn run_consuming_from_load(
    rooted: &load_outer::DiagnosticLoadOmega,
    retiring: bool,
    native_differential: bool,
) -> AuthenticatedConsuming {
    run_consuming_from_head(&Head::loaded(rooted), retiring, native_differential)
}

fn run_consuming_from_head(
    head: &Head<'_>,
    retiring: bool,
    native_differential: bool,
) -> AuthenticatedConsuming {
    let source = Arc::new(sources(head, retiring));
    let context = ContextPlan::with_schedule(
        source.plan.clone(),
        vec![vec![], vec![], vec![0], vec![1]],
        Some(0),
        UnloadObjects::context_specs().unwrap().to_vec(),
    )
    .unwrap()
    .with_operation_tasks(vec![
        vec![OperationTask::UnloadProof],
        vec![if retiring {
            OperationTask::RetiringState
        } else {
            OperationTask::UnloadRecovery
        }],
        vec![],
        vec![OperationTask::UnloadAuthorization],
    ])
    .unwrap();
    UnloadStagePlan::new(context.clone(), load_objects::policy()).unwrap();
    let profile = SourceProfile::Tagged { buses: 3 };
    let claims = [
        source.predecessor.pallas.as_input(),
        source.predecessor.opening.clone(),
    ];
    let (fold, pallas) = create_fold(
        &source.params,
        &claims,
        Fp::from(122).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    pallas
        .decide(&source.params, MemoryBudget::DEFAULT)
        .unwrap();
    let first = First {
        source: source.clone(),
        profile,
        plan: context,
        pallas,
        fold: fold.to_bytes().to_vec(),
        known: true,
    };
    let public = first_public(&first);
    let (assigned, k) = match synthesize(&first, 16, Some(&public)) {
        Ok(a) => (a, 16),
        Err(error) => {
            eprintln!("Consuming A1 k16 capacity failure {error:?}");
            (synthesize(&first, 18, Some(&public)).unwrap(), 18)
        }
    };
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let lanes = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!(
        "GENUINE_CONSUMING_A1 lanes={lanes:?} production_k16_fit={}",
        k == 16
    );
    assert_eq!(k, 16, "hard capacity cannot be relaxed");
    let mut changed = (*source).clone();
    changed.objects[2].bytes[242] ^= 1; // Receipt field9, original proof digest.
    let mut rebound_receipt = first.clone();
    rebound_receipt.source = Arc::new(changed);
    assert!(
        !iroha_plonk::check::check_circuit(
            &rebound_receipt,
            16,
            &first_public(&rebound_receipt),
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied()),
        "UnloadProof must reject a wrong digest even with a consistently rebound context"
    );
    let unknown = synthesize(&first.without_witnesses(), 16, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let mut cfg = KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]);
    cfg.compress_selectors = false;
    let params = common::vesta_params(16);
    let key = keygen_pk_v2(&params, &first, &cfg).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &first, &public).unwrap(),
        common::recovery(226),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    let output = continue_schedule(&first, &key, proof, &public, true, native_differential)
        .expect("complete consuming schedule must meet k16");
    assert_eq!(output.state.core, source.maps.witness.successor.core);
    assert_eq!(output.state.rest, source.maps.witness.successor.rest);
    assert_eq!(output.state.lineage, source.maps.witness.successor.lineage);
    eprintln!(
        "CONSUMING_COMPLETE_TASK_COMPONENT hard_predecessor=true mandatory_own2V1F=true same_tape_full320=true all_maps=true all_openings=true full_catalog=false release_qualified=false"
    );
    output
}

/// Run the retained composition assertions with genuine native Load originals.
pub fn installed_native_consuming_proves_and_restores_every_stage(fixture: &LoadFixture) {
    let rooted = catalog::compact_payer_load(fixture);
    for retiring in [false, true] {
        run_consuming_from_load(&rooted, retiring, true);
    }
}

#[test]
#[ignore = "genuine compact Bootstrap and all4A/3W Retiring proofs, strict imports and canonical7 fresh-session replay; run optimized"]
fn installed_native_retiring_from_bootstrap_preserves_every_original_and_checkpoint() {
    use iroha_kagemusha_proof::witness::core_index as core;
    let rooted =
        load_outer::load_chain::bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    let before = StateWitness::from(&rooted.source.state);
    assert_eq!(before.core[core::BALANCE], Fp::ZERO);
    assert_eq!(before.lineage[14], Fp::ZERO);
    let head = Head {
        state: before,
        binding: &rooted.binding,
        key: &rooted.key,
        proof: &rooted.proof,
        pallas: &rooted.source.pallas,
        vesta: &rooted.vesta,
        opening: &rooted.opening,
    };
    let retired = run_consuming_from_head(&head, true, true);
    assert_eq!(retired.state.core[core::LIFECYCLE], Fp::from(2));
    assert_eq!(retired.state.core[core::BALANCE], Fp::ZERO);
    for (index, old) in before.core.iter().enumerate() {
        if !matches!(
            index,
            core::SEQUENCE
                | core::STATE_NONCE
                | core::LIFECYCLE
                | core::BURNED_TOTAL
                | core::PENDING_OUTGOING_ROOT
        ) {
            assert_eq!(*old, retired.state.core[index], "unchanged core {index}");
        }
    }
    assert_eq!(retired.state.rest, before.rest);
    assert_eq!(retired.state.core[core::BURNED_TOTAL], before.lineage[14]);
    assert_eq!(
        retired.state.core[core::PENDING_OUTGOING_ROOT],
        before.lineage[15]
    );
    assert_eq!(retired.state.lineage[17], before.lineage[17]);
    eprintln!(
        "BOOTSTRAP_RETIRING_COMPONENT zero_balance_preserved=true genuine_predecessor=true native_original_imports=true canonical7_replay=true final_omega_admitted=false full_catalog=false"
    );
}

fn native_installed_consuming_differential(
    first: &First,
    a: Vec<Arc<iroha_plonk::ProvingKey<Eq>>>,
    w: Vec<Arc<iroha_plonk::ProvingKey<Ep>>>,
    originals_a: &[(Vec<u8>, [u8; 544])],
    originals_w: &[(Vec<u8>, [u8; 544])],
) {
    use iroha_kagemusha_proof::a_relation::{native::consuming as native, own::OwnPolicy};
    use iroha_plonk::cs::{
        CircuitDescriptorV2, CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2,
    };
    assert_eq!(
        first.profile,
        SourceProfile::Tagged {
            buses: native::SOURCE_RANGE_BUSES,
        }
    );
    let source = &first.source;
    let input = native::Inputs {
        state: source.maps.witness,
        sigma: source.sigma.clone(),
        omega: source.omega.clone(),
        objects: core::array::from_fn(|i| source.objects[i].bytes.clone()),
        recovery: source.maps.recovery,
        q: core::array::from_fn(|i| native::QInput {
            proof: source.q_proofs[i].clone(),
            instances: source.q_instances[i].clone(),
        }),
        predecessor: native::PredecessorInput {
            proof: source.predecessor.proof.clone(),
            pallas: source.predecessor.pallas.to_bytes(),
            vesta: source.predecessor.vesta.to_bytes(),
        },
    };
    let plan = native::Plan::new(
        source.plan.clone(),
        load_objects::policy(),
        source.signature_schema.clone(),
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    assert_eq!(plan.context().schema(), first.plan.schema());
    native_source_factory_checks::assert_factories(
        plan.context(),
        &PinnedParams::<Ep>::derive(16).unwrap(),
        &common::vesta_params(16),
        &a.iter()
            .map(|key| {
                iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                    key.binding().clone(),
                    key.vk().clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>(),
        &w.iter()
            .map(|key| {
                iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                    key.binding().clone(),
                    key.vk().clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>(),
        |stage, previous| plan.source_circuit(stage, previous),
        |stage, binding, key| plan.wrapper_source(stage, binding, key),
    );
    let a_originals: [NativeConsumingOriginal; 4] = a
        .iter()
        .map(|key| NativeConsumingOriginal::from_key(key.as_ref()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("exact four A originals"));
    let w_originals: [NativeConsumingOriginal; 3] = w
        .iter()
        .map(|key| NativeConsumingOriginal::from_key(key.as_ref()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("exact three W originals"));
    let config = iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: a_originals
            .iter()
            .chain(&w_originals)
            .map(|original| original.pk.len())
            .max()
            .unwrap(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let install = |plan: native::Plan,
                   a: &[NativeConsumingOriginal; 4],
                   w: &[NativeConsumingOriginal; 3],
                   config|
     -> Result<native::Prover, native::Error> {
        let a_metadata = a
            .iter()
            .map(NativeConsumingOriginal::metadata)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| native::Error::Artifact)?;
        let w_metadata = w
            .iter()
            .map(NativeConsumingOriginal::metadata)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| native::Error::Artifact)?;
        let prover = native::Prover::from_artifacts(plan, a_metadata, w_metadata)?;
        for (stage, original) in a.iter().enumerate() {
            drop(prover.import_a(stage, &original.pk, config)?);
            if let Some(original) = w.get(stage) {
                drop(prover.import_w(stage, &original.pk, config)?);
            }
        }
        Ok(prover)
    };
    let installed = install(plan.clone(), &a_originals, &w_originals, config).unwrap();
    for mutation in 0..13 {
        let mut bad_a = a_originals.clone();
        let mut bad_w = w_originals.clone();
        match mutation {
            0 => bad_a[0].vk.clone_from(&a_originals[3].vk),
            1 => bad_a[0].pk[44 + a_originals[0].vk.len()] ^= 1,
            2 => bad_a[0].pk[44 + a_originals[0].vk.len() + 32] ^= 1,
            3 => bad_a.swap(0, 3),
            4 => bad_w.swap(0, 2),
            5 => {
                bad_a[0].pk.pop();
            }
            6 => bad_w[0].descriptor.clone_from(&a_originals[0].descriptor),
            7 => bad_a.swap(1, 2),
            8 => bad_w[0].vk.clone_from(&w_originals[2].vk),
            9 => bad_w[0].pk[44 + w_originals[0].vk.len()] ^= 1,
            10 => bad_a[3].pk[44 + a_originals[3].vk.len()] ^= 1,
            11 => bad_a[0].pk.push(0),
            _ => bad_w[0].pk[44 + w_originals[0].vk.len() + 32] ^= 1,
        }
        assert!(
            install(plan.clone(), &bad_a, &bad_w, config).is_err(),
            "consuming original mutation{mutation}"
        );
    }
    let descriptor = CircuitDescriptorV2::decode(&a_originals[0].descriptor).unwrap();
    for mutation in 0..6 {
        let mut wrong = descriptor.clone();
        match mutation {
            0 => wrong.instance_types[0] = InstanceType::Field,
            1 => wrong.transcript = TranscriptV2::KagemushaPoseidonRp57,
            2 => wrong.instance_mode = InstanceModeV1::Committed,
            3 => wrong.proof_suffix = ProofSuffixV1::None,
            4 => wrong.instance_lengths[0] = 68,
            _ => wrong.curve = CurveV1::Pallas,
        }
        let mut bad_a = a_originals.clone();
        bad_a[0].descriptor = wrong.encode().unwrap();
        assert!(
            install(plan.clone(), &bad_a, &w_originals, config).is_err(),
            "consuming profile mutation{mutation}"
        );
    }
    let changed_policy = OwnPolicy::new([33, 34], bootstrap_objects::key(23)).unwrap();
    let changed = native::Plan::new(
        source.plan.clone(),
        changed_policy,
        UnloadStagePlan::signature_schema(changed_policy).unwrap(),
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    assert!(install(changed, &a_originals, &w_originals, config).is_err());
    assert!(installed.import_a(4, &a_originals[0].pk, config).is_err());
    assert!(installed.import_w(3, &w_originals[0].pk, config).is_err());
    assert!(
        installed
            .import_a(
                0,
                &a_originals[0].pk,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_bytes: 0,
                    ..config
                }
            )
            .is_err()
    );
    assert!(
        installed
            .import_w(
                0,
                &w_originals[0].pk,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_rows: (1 << 16) - 1,
                    ..config
                }
            )
            .is_err()
    );
    // Test-owned original files survive, but no diagnostic proving polynomials
    // remain during the metadata-only producer's per-stage import/proof replay.
    drop((a, w));
    assert_eq!(installed.descriptors().len(), 7);
    let layouts = installed.checkpoint_layouts().unwrap();
    assert_eq!(layouts.len(), 7);
    let budget = MemoryBudget::DEFAULT;
    let session = installed.prepare(input.clone(), budget).unwrap();
    let unrelated_session = installed.prepare(input.clone(), budget).unwrap();
    let fold = FoldConfig::default();
    let foreign_seal = installed.import_a(1, &a_originals[1].pk, config).unwrap();
    let foreign = installed.bind_a(1, &foreign_seal, None).unwrap();
    assert!(matches!(
        session.first(
            &foreign,
            Fp::from(122),
            &fold,
            common::recovery(226),
            ProverConfig::default()
        ),
        Err(native::Error::Artifact)
    ));
    drop(foreign_seal);
    let key_seal = installed.import_a(0, &a_originals[0].pk, config).unwrap();
    let key = installed.bind_a(0, &key_seal, None).unwrap();
    let generated = session
        .first(
            &key,
            Fp::from(122),
            &fold,
            common::recovery(226),
            ProverConfig::default(),
        )
        .unwrap();
    drop(key_seal);
    assert_eq!(generated.proof(), originals_a[0].0);
    let mut current = session
        .restore_first(originals_a[0].0.clone(), &originals_a[0].1, budget)
        .unwrap();
    let first_payload = session.encode_a_checkpoint(&current, budget).unwrap();
    assert_eq!(first_payload.len(), layouts[0].payload_bytes());
    assert!(
        session
            .restore_first_checkpoint(&first_payload[..first_payload.len() - 1], budget)
            .is_err()
    );
    current = session
        .restore_first_checkpoint(&first_payload, budget)
        .unwrap();
    let mut payloads = vec![first_payload];
    assert_eq!(current.stage(), 0);
    assert_eq!(generated.instances(), current.instances());
    assert_eq!(generated.pallas_bytes(), current.pallas_bytes());
    assert_eq!(current.instances(), first_public(first)[0]);
    assert!(session.terminal(&current, budget).is_err());
    assert!(unrelated_session.terminal(&current, budget).is_err());
    let mut changed = originals_a[0].0.clone();
    changed[0] ^= 1;
    assert!(
        session
            .restore_first(changed, &originals_a[0].1, budget)
            .is_err()
    );
    assert!(
        session
            .restore_first(originals_a[0].0.clone(), &originals_a[0].1[..543], budget)
            .is_err()
    );
    for stage in 0..3 {
        if stage == 0 {
            let foreign_seal = installed.import_w(1, &w_originals[1].pk, config).unwrap();
            let foreign = installed.bind_w(1, &foreign_seal, None).unwrap();
            assert!(matches!(
                session.wrapper(
                    &current,
                    &foreign,
                    Fq::from(124),
                    &fold,
                    common::recovery(197),
                    ProverConfig::default()
                ),
                Err(native::Error::Artifact)
            ));
            drop(foreign_seal);
        }
        let key_seal = installed
            .import_w(stage, &w_originals[stage].pk, config)
            .unwrap();
        let key = installed.bind_w(stage, &key_seal, None).unwrap();
        let generated_w = session
            .wrapper(
                &current,
                &key,
                Fq::from(124 + stage as u64),
                &fold,
                common::recovery(197 + u8::try_from(stage).unwrap()),
                ProverConfig::default(),
            )
            .unwrap();
        drop(key_seal);
        assert_eq!(generated_w.proof(), originals_w[stage].0);
        let restored_w = session
            .restore_wrapper(
                &current,
                originals_w[stage].0.clone(),
                &originals_w[stage].1,
                budget,
            )
            .unwrap();
        let payload = session
            .encode_wrapper_checkpoint(&restored_w, budget)
            .unwrap();
        assert_eq!(payload.len(), layouts[2 * stage + 1].payload_bytes());
        let restored_w = session
            .restore_wrapper_checkpoint(&current, &payload, budget)
            .unwrap();
        payloads.push(payload);
        assert_eq!(generated_w.vesta_bytes(), restored_w.vesta_bytes());
        assert_eq!(generated_w.stage(), stage);
        // Replay the exact original W proof and opening at every continuation.
        if stage == 0 {
            let foreign_seal = installed.import_a(0, &a_originals[0].pk, config).unwrap();
            let foreign = installed.bind_a(0, &foreign_seal, None).unwrap();
            assert!(matches!(
                session.advance(
                    &restored_w,
                    &foreign,
                    Fp::from(125),
                    &fold,
                    common::recovery(201),
                    ProverConfig::default()
                ),
                Err(native::Error::Artifact)
            ));
            drop(foreign_seal);
        }
        let key_seal = installed
            .import_a(stage + 1, &a_originals[stage + 1].pk, config)
            .unwrap();
        let key = installed.bind_a(stage + 1, &key_seal, None).unwrap();
        let generated_a = session
            .advance(
                &restored_w,
                &key,
                Fp::from(125 + stage as u64),
                &fold,
                common::recovery(201 + u8::try_from(stage).unwrap()),
                ProverConfig::default(),
            )
            .unwrap();
        drop(key_seal);
        assert_eq!(generated_a.proof(), originals_a[stage + 1].0);
        let restored_a = session
            .restore_a(
                &restored_w,
                originals_a[stage + 1].0.clone(),
                &originals_a[stage + 1].1,
                budget,
            )
            .unwrap();
        assert_eq!(generated_a.instances(), restored_a.instances());
        assert_eq!(generated_a.pallas_bytes(), restored_a.pallas_bytes());
        assert_eq!(restored_a.stage(), stage + 1);
        assert!(
            unrelated_session
                .restore_a(
                    &restored_w,
                    originals_a[stage + 1].0.clone(),
                    &originals_a[stage + 1].1,
                    budget
                )
                .is_err()
        );
        let mut wrong = originals_w[stage].0.clone();
        wrong[0] ^= 1;
        assert!(
            session
                .restore_wrapper(&current, wrong, &originals_w[stage].1, budget)
                .is_err()
        );
        let mut wrong = originals_a[stage + 1].0.clone();
        wrong[0] ^= 1;
        assert!(
            session
                .restore_a(&restored_w, wrong, &originals_a[stage + 1].1, budget)
                .is_err()
        );
        let payload = session.encode_a_checkpoint(&restored_a, budget).unwrap();
        assert_eq!(payload.len(), layouts[2 * stage + 2].payload_bytes());
        let mut changed = payload.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            session
                .restore_a_checkpoint(&restored_w, &changed, budget)
                .is_err()
        );
        current = session
            .restore_a_checkpoint(&restored_w, &payload, budget)
            .unwrap();
        payloads.push(payload);
    }
    let terminal = session.terminal(&current, budget).unwrap();
    assert_eq!(terminal.instances, current.instances());
    assert_eq!(terminal.pallas.to_bytes(), current.pallas_bytes());
    terminal.pallas.decide(&source.params, budget).unwrap();
    let vparams = common::vesta_params(16);
    terminal.vesta_part.decide(&vparams, budget).unwrap();
    terminal.predecessor_vesta.decide(&vparams, budget).unwrap();
    terminal.opening.decide(&vparams, budget).unwrap();
    assert_eq!(payloads.len(), 7);
    let restarted = installed.prepare(input.clone(), budget).unwrap();
    let mut replayed = restarted
        .restore_first_checkpoint(&payloads[0], budget)
        .unwrap();
    for stage in 0..3 {
        let wrapper = restarted
            .restore_wrapper_checkpoint(&replayed, &payloads[2 * stage + 1], budget)
            .unwrap();
        replayed = restarted
            .restore_a_checkpoint(&wrapper, &payloads[2 * stage + 2], budget)
            .unwrap();
    }
    assert_eq!(replayed.proof(), current.proof());
    assert_eq!(replayed.instances(), current.instances());
    assert_eq!(replayed.pallas_bytes(), current.pallas_bytes());
    let replayed_terminal = restarted.terminal(&replayed, budget).unwrap();
    assert_eq!(replayed_terminal.proof, terminal.proof);
    assert_eq!(replayed_terminal.instances, terminal.instances);
    assert_eq!(replayed_terminal.pallas, terminal.pallas);
    assert_eq!(replayed_terminal.vesta_part, terminal.vesta_part);
    assert_eq!(
        replayed_terminal.predecessor_vesta,
        terminal.predecessor_vesta
    );
    eprintln!(
        "NATIVE_CONSUMING_PARITY metadata_only_producer=true borrowed_stage_PK=true exact_original_proof_bytes=true canonical_fresh_session_replay=true"
    );
    let key_seal = installed.import_w(0, &w_originals[0].pk, config).unwrap();
    let key = installed.bind_w(0, &key_seal, None).unwrap();
    assert!(
        session
            .wrapper(
                &current,
                &key,
                Fq::from(130),
                &fold,
                common::recovery(225),
                ProverConfig::default()
            )
            .is_err()
    );
    for object in 0..3 {
        for offset in [0, input.objects[object].len() - 1] {
            let mut bad = input.clone();
            bad.objects[object][offset] ^= 1;
            assert!(
                installed.prepare(bad, budget).is_err(),
                "own tape {object}/{offset}"
            );
        }
    }
    for mutation in 0..11 {
        let mut bad = input.clone();
        match mutation {
            0 => bad.sigma[0] ^= 1,
            1 => bad.predecessor.proof[0] ^= 1,
            2 => bad.q[1].proof[0] ^= 1,
            3 => bad.state.predecessor.lineage[17] += Fp::ONE,
            4 => {
                bad.recovery = if bad.recovery.is_some() {
                    None
                } else {
                    Some(IndexedInsert {
                        leaf: iroha_kagemusha_proof::tree::IndexedLeaf::default(),
                        leaf_slot: 0,
                        leaf_siblings: [Fp::ZERO; 32],
                        slot: 1,
                        slot_siblings: [Fp::ZERO; 32],
                    })
                }
            }
            5 => bad.predecessor.pallas[0] ^= 1,
            6 => bad.predecessor.vesta[0] ^= 1,
            7 => bad.omega[321] ^= 1,
            8 => bad.q[0].proof[0] ^= 1,
            9 => bad.q[0].instances[2][0] += Fq::ONE,
            _ => {
                bad.objects[2].pop();
            }
        }
        assert!(
            installed.prepare(bad, budget).is_err(),
            "consuming input mutation{mutation}"
        );
    }
}

#[derive(Clone)]
struct NativeConsumingOriginal {
    descriptor: Vec<u8>,
    vk: Vec<u8>,
    pk: Vec<u8>,
}
impl NativeConsumingOriginal {
    fn from_key<C: iroha_pasta::PastaCurve>(key: &iroha_plonk::ProvingKey<C>) -> Self {
        Self {
            descriptor: key.binding().encoded().to_vec(),
            vk: key.vk().to_bytes().to_vec(),
            pk: key.artifact_bytes_v2().unwrap(),
        }
    }
    fn metadata<C: iroha_pasta::PastaCurve>(
        &self,
    ) -> Result<
        iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<C>,
        iroha_kagemusha_proof::a_relation::native::consuming::Error,
    > {
        use iroha_kagemusha_proof::a_relation::native::{artifact::KeyArtifact, consuming::Error};
        let binding = iroha_plonk::DescriptorBinding::decode_v2(&self.descriptor)
            .map_err(|_| Error::Artifact)?;
        let key =
            iroha_plonk::VerifyingKey::read(&self.vk, &binding).map_err(|_| Error::Artifact)?;
        KeyArtifact::new(binding, key).map_err(|_| Error::Artifact)
    }
}
