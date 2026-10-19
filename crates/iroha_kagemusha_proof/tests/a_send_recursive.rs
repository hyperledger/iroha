//! Genuine lean Send after a common-key Bootstrap→Load chain: A1 proves the step
//! relation inline beside the hard predecessor, A2 both map insertions, A3 the own
//! receipt under the predecessor payment key. The two-terminal predecessor catalog is
//! a component scope, not the complete release catalog. Every source proof, pending
//! claim and operation task is real.
#![allow(clippy::duplicate_mod)]
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
/// Genuine common-key Bootstrap/Load predecessor builder.
#[path = "common/proof_fixtures/load_omega.rs"]
pub mod load_outer;
#[path = "common/native_source_factory_checks.rs"]
mod native_source_factory_checks;
use load_outer::{LoadFixture, load_chain::bootstrap_outer::bootstrap_chain::SourceProfile};
/// Genuine Send sigma, inline relation and same-cell state/map components.
#[path = "a_send.rs"]
pub mod send_components;
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    SigmaRelation,
    a_relation::{
        AProofPlan, ProofMessageCells, QProofPlan, VestaClaimCells,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        schedule::OperationTask,
        send::{
            SendAuthorization, SendAuthorizationObjects, SendInputs, SendObjects, SendStagePlan,
            SendStageWitness,
        },
        split::close_first,
        transition::TransitionInputs,
        verify_predecessor,
    },
    circuit::{PrefixMode, RelationShape},
    operation_relation::{map_effects::MapState, statement::StatementCells},
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
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
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
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
#[derive(Clone)]
struct Sources {
    maps: send_components::SendMaps,
    /// The own receipt, the one object the signature Q authenticates.
    own_objects: [bootstrap_objects::Signed; 1],
    /// The Payment carriers the receipt names; Λ consumes neither.
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
fn sources(artifact: &load_outer::DiagnosticLoadOmega) -> Sources {
    use iroha_kagemusha_proof::operation_relation::objects::ObjectKind;
    use iroha_plonk_gadgets::bytes::p_bytes_native;
    assert_eq!(
        artifact.source.state.lineage[17],
        artifact.key.kagemusha_digest(&artifact.binding).unwrap()
    );
    let (witness, sigma) = send_components::genuine_send_sigma(&artifact.source.state);
    let omega = lineage_bytes(
        &witness.before.lineage,
        &artifact.proof,
        &artifact.source.pallas,
        &artifact.vesta,
    );
    let proof_digest = p_bytes_native(
        u64::from_le_bytes(*b"kgwprf_1"),
        &[frame(&omega), frame(&sigma)].concat(),
    );
    let (_, _, credential) = bootstrap_objects::enrollment();
    assert_eq!(credential.bytes, witness.objects[0]);
    let f = &witness.statement;
    let wallet = &witness.before.lineage[6..8];
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[wallet[0], wallet[1], Fp::from(3), f[17]],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(f[3], f[4]));
    body.extend(bootstrap_objects::id(wallet[0], wallet[1]));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&f[9].to_repr()[..16]);
    for word in [
        operation,
        f[14],
        f[15],
        hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, f),
        proof_digest,
    ] {
        body.extend(word.to_repr());
    }
    body.extend(bootstrap_objects::small_id(301, 302));
    body.extend(Fp::ZERO.to_repr());
    let receipt = bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 67);
    // Lean lineage: the credential and certificate are carried by continuity; the own
    // receipt is the only signature leaf, under the predecessor payment key.
    let schema = iroha_kagemusha_proof::q_signature::QSignaturePlan::new(vec![
        iroha_kagemusha_proof::q_signature::SignatureSlot {
            mode: iroha_plonk_gadgets::p256::VerifyMode::Hard,
            key: iroha_kagemusha_proof::q_signature::SignatureKey::Variable,
        },
    ])
    .unwrap();
    let signature = iroha_kagemusha_proof::q_signature::QSignatureCircuit::new(
        schema,
        vec![receipt.signature.clone()],
    )
    .unwrap();
    let instances = signature.instances(&[true]).unwrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
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
        common::fresh_randomness(),
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
        proof: artifact.proof.clone(),
        pallas: artifact.source.pallas.clone(),
        opening: artifact.opening.clone(),
        vesta: artifact.vesta.clone(),
    };
    let plan = AProofPlan::inline(
        Variant::Send,
        vec![signature_q],
        Some(predecessor.program.clone()),
        &params,
    )
    .unwrap();
    // No own sigma verifier: W0 folds the pinned trivial part.
    let part = FoldInput::<Eq>::from_normalized(
        iroha_plonk::transcript::decode_point::<Eq>(
            &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
        )
        .unwrap(),
        16,
        [Fp::ONE; iroha_plonk_recursion::K],
    )
    .unwrap();
    Sources {
        maps: send_components::SendMaps {
            witness,
            known: true,
            stage_plan: None,
            transition: true,
        },
        own_objects: [receipt],
        sigma,
        omega,
        plan,
        q_instances: vec![instances.to_vec()],
        q_proofs: vec![proof.proof],
        q_openings: vec![
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
    fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes,
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
        let g = chip.witness_generator(region, self.value(Ep::from(*input.g())))?;
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
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(input.g());
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
    /// The installed mask-0 relation with absorbed prefixes and its native evaluation.
    fn transition<'a>(
        &'a self,
        native: &'a iroha_kagemusha_proof::witness::NativeStep<Fp>,
    ) -> TransitionInputs<'a> {
        TransitionInputs {
            shape: RelationShape::new(SigmaRelation::SEND, PrefixMode::Absorbed),
            witness: self
                .known
                .then_some((&self.source.maps.witness.step, native)),
        }
    }
}
impl First {
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<
        (
            SendObjects,
            SendAuthorizationObjects,
            Vec<iroha_kagemusha_proof::a_relation::context::ContextObjectCells>,
        ),
        Error,
    > {
        let sources = self
            .source
            .maps
            .witness
            .objects
            .each_ref()
            .map(|o| o.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        let objects =
            SendObjects::decode(chip, bytes, region, sources.each_ref().map(Vec::as_slice))?;
        let sources = self
            .source
            .own_objects
            .each_ref()
            .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
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
                    .map_err(|_| Error::Synthesis)?;
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
                    objects: &context_objects,
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
                // A1 proves the step relation itself beside the hard predecessor.
                let native = maps.witness.step.evaluate(SigmaRelation::SEND);
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
                        transition: Some(self.transition(&native)),
                        ..SendStageWitness::default()
                    },
                )?;
                assert_eq!(self.plan.first_q_count(), 0, "A1 verifies no Q");
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
    plan: iroha_kagemusha_proof::a_relation::split::SplitPlan,
    wrapper: Vec<u8>,
    vesta: AccumulatorT<Eq>,
    fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes,
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
                    .map_err(|_| Error::Synthesis)?;
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
                    objects: &context_objects,
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
                    &[],
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
                    let q = {
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
                                    policy: load_objects::policy(),
                                    signature:
                                        iroha_kagemusha_proof::a_relation::SignatureQContext {
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
                    .ok_or(Error::Synthesis)?
                    .contains(&0)
                {
                    let tasks = first
                        .plan
                        .operation_tasks(self.plan.stage())
                        .ok_or(Error::Synthesis)?;
                    let pending = if tasks.contains(&OperationTask::SendPending) {
                        Some(maps.insertion(
                            &mut chip.uint(),
                            &mut region,
                            &maps.witness.pending,
                        )?)
                    } else {
                        None
                    };
                    let fee = if tasks.contains(&OperationTask::SendFeeAndCarry) {
                        Some(maps.insertion(&mut chip.uint(), &mut region, &maps.witness.fee)?)
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
        let mut lineage = self.first.source.maps.witness.after.lineage.to_vec();
        let (x, y) =
            iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(self.pallas.g());
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
/// Genuine authenticated Send terminal artifacts for outer/next-operation tests.
/// The supplied predecessor's catalog/profile provenance is retained unchanged;
/// this fixture does not declare the resulting lineage admitted by a final catalog.
#[derive(Clone)]
#[allow(dead_code)] // Outer and next-operation tests consume all carried artifacts.
pub(crate) struct AuthenticatedSend {
    pub(crate) key: VerifyingKey<Eq>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Fp>,
    pub(crate) opening: FoldInput<Eq>,
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) vesta_part: AccumulatorT<Eq>,
    pub(crate) predecessor_vesta: AccumulatorT<Eq>,
    pub(crate) state: iroha_kagemusha_proof::admin_sigma::StateWitness,
    /// Exact Send statement, original Credential/Request/Fee and map openings.
    pub(crate) maps: send_components::SendMaps,
    /// Exact own Send sigma bytes the Receipt names; the Payment carries them.
    pub(crate) sigma: Vec<u8>,
    /// Original predecessor Omega transport named by the Receipt and carried by the Payment.
    pub(crate) predecessor_omega: Vec<u8>,
    /// Exact own Send Receipt; the credential and certificate are carried by continuity.
    pub(crate) own_objects: [Vec<u8>; 1],
    /// Complete fixed source task and object schema.
    pub(crate) context: ContextPlan,
    /// Original context digest before the A/W continuation links.
    pub(crate) root_context: Fp,
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
        "SEND_A_ARTIFACT stage={} range_buses={} shape={:?} descriptor_personalized_blake2b={} vk_kgwvkey1={} proof_pbytes_kgwtstp1={} proof_bytes={} diagnostic_only=true",
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
) -> Option<AuthenticatedSend> {
    use iroha_kagemusha_proof::a_relation::split::{SplitPlan, WCircuit, WKey};
    let params = &first.source.params;
    let vparams = common::vesta_params(16);
    let mut source_key = first_key.clone();
    let mut source_proof = first_proof;
    let mut source_public = first_public.to_vec();
    let mut carried = first.pallas.clone();
    let mut intermediate_keys = vec![first_key.vk().clone()];
    let mut installed_a = if native_differential {
        vec![Arc::new(first_key.clone())]
    } else {
        vec![]
    };
    let mut installed_w = Vec::new();
    let mut originals_a = if native_differential {
        vec![(source_proof.proof.clone(), carried.to_bytes())]
    } else {
        vec![]
    };
    let mut originals_w = Vec::new();
    for stage in 1..first.plan.stage_count() {
        let terminal = iroha_plonk_recursion::terminal::TerminalPlan::new(
            source_key.binding().encoded(),
            &[source_key.vk().to_bytes().to_vec()],
            vparams.clone(),
        )
        .unwrap();
        let (vfold, vesta) = terminal
            .read(
                0,
                &source_public,
                &source_proof.proof,
                &FoldConfig::default(),
            )
            .unwrap()
            .create(
                common::public_fixture_tape(123 + u64::try_from(stage).unwrap()),
                &FoldConfig::default(),
            )
            .unwrap();
        vesta.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
        let witness = iroha_kagemusha_proof::omega::OmegaWitness {
            key: source_key.vk().clone(),
            instances: source_public[0].clone(),
            length: source_proof.proof.len().try_into().unwrap(),
            proof: source_proof.proof,
            fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
                vfold.to_private_bytes(),
            ),
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
        if native_differential {
            installed_w.push(Arc::new(wprover.clone()));
        }
        for wrong_stage in 0..=first.plan.stage_count() {
            if wrong_stage != stage {
                assert!(
                    SplitPlan::new(first.plan.clone(), wrong_stage, wkey.clone(), params).is_err(),
                    "wrong-stage W must not resume at {wrong_stage}"
                );
            }
        }
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(vesta.g());
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
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
        if native_differential {
            originals_w.push((wrapper.proof.clone(), vesta.to_bytes()));
        }
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
        let required_count = claims.len();
        let purpose = if stage + 1 == first.plan.stage_count() {
            let filler = AccumulatorT::trivial(params, MemoryBudget::DEFAULT).unwrap();
            while claims.len() < 4 {
                claims.push(filler.as_input());
            }
            iroha_plonk_recursion::FoldPurpose::ATerminal
        } else {
            iroha_plonk_recursion::FoldPurpose::AContinuation
        };
        let (fold, pallas) = create_fold(
            params,
            &claims,
            common::public_fixture_tape(124 + stage as u64),
            purpose,
            &FoldConfig::default(),
        )
        .unwrap();
        pallas.decide(params, MemoryBudget::DEFAULT).unwrap();
        let continuation = Continuation {
            first: first.clone(),
            plan: SplitPlan::new(first.plan.clone(), stage, wkey, params).unwrap(),
            wrapper: wrapper.proof,
            vesta: vesta.clone(),
            fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
                fold.to_private_bytes(),
            ),
            pallas: pallas.clone(),
            carried: carried.clone(),
            omit_q: None,
        };
        let public = continuation.public();
        let (assigned, k) = match synthesize(&continuation, 16, Some(&public)) {
            Ok(a) => (a, 16),
            Err(error) => {
                eprintln!(
                    "actual Send A{} fails k16 {error:?}; diagnostic k18 only",
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
            "genuine Send A{} hard W+Q{indices:?}+context+fold range_buses={} lanes={lanes:?}, production_k16_fit={}",
            stage + 1,
            first.profile.range_buses(),
            k == 16
        );
        if adversarial {
            if indices.contains(&0) {
                let mut changed = (*first.source).clone();
                let last = changed.own_objects[0].bytes.len() - 1;
                changed.own_objects[0].bytes[last] ^= 1;
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
            for omitted in 0..required_count {
                let mut kept = claims.clone();
                kept[omitted] = AccumulatorT::trivial(params, MemoryBudget::DEFAULT)
                    .unwrap()
                    .as_input();
                let (fold, _) = create_fold(
                    params,
                    &kept,
                    common::public_fixture_tape(124 + stage as u64),
                    purpose,
                    &FoldConfig::default(),
                )
                .unwrap();
                let mut bad = continuation.clone();
                bad.fold = iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
                    fold.to_private_bytes(),
                );
                assert!(
                    !iroha_plonk::check::check_circuit(&bad, k, &public, CheckMode::Strict)
                        .is_ok_and(|r| r.is_satisfied()),
                    "dropped stage{stage} claim{omitted}"
                );
            }
            let mut doubled = claims.clone();
            doubled[1] = claims[0].clone();
            let (fold, _) = create_fold(
                params,
                &doubled,
                common::public_fixture_tape(124 + stage as u64),
                purpose,
                &FoldConfig::default(),
            )
            .unwrap();
            let mut bad = continuation.clone();
            bad.fold = iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
                fold.to_private_bytes(),
            );
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
        if native_differential {
            installed_a.push(Arc::new(key.clone()));
        }
        assert_eq!(key.binding().descriptor(), first_key.binding().descriptor());
        let proof = create_proof_owned_with_claim(
            &vparams,
            &key,
            Witness::from_circuit(&key, &continuation, &public).unwrap(),
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
        proof
            .opening
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        eprintln!(
            "actual Send A{} proof={}B; terminal={}; final Omega/full catalog still pending",
            stage + 1,
            proof.proof.len(),
            continuation.plan.is_terminal()
        );
        artifact_diagnostics(stage, &key, &proof.proof, first.profile.range_buses());
        if native_differential {
            originals_a.push((proof.proof.clone(), pallas.to_bytes()));
        }
        if continuation.plan.is_terminal() {
            if native_differential {
                native_installed_send_differential(
                    first,
                    installed_a,
                    installed_w,
                    &originals_a,
                    &originals_w,
                );
            }
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
            return Some(AuthenticatedSend {
                key: key.vk().clone(),
                binding: key.binding().clone(),
                opening: FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges())
                    .unwrap(),
                proof: proof.proof,
                instances: public[0].clone(),
                pallas,
                vesta_part: vesta,
                predecessor_vesta: first.source.predecessor.vesta.clone(),
                state: first.source.maps.witness.after,
                maps: first.source.maps.clone(),
                sigma: first.source.sigma.clone(),
                predecessor_omega: first.source.omega.clone(),
                own_objects: first
                    .source
                    .own_objects
                    .each_ref()
                    .map(|object| object.bytes.clone()),
                context: first.plan.clone(),
                root_context: context_digest(first),
            });
        }
        intermediate_keys.push(key.vk().clone());
        carried = pallas;
        source_key = key;
        source_proof = proof;
        source_public = public;
    }
    None
}
fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) {
    words.push(Fp::from(16));
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(claim.g());
    words.extend([x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(claim.g());
    let mut words = vec![];
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}
fn context_digest(first: &First) -> Fp {
    use iroha_kagemusha_proof::operation_relation::objects::signed_message_native;
    let s = &first.source;
    let mut words = first.plan.schema().to_vec();
    words.extend(s.maps.witness.statement);
    let before = &s.maps.witness.before;
    let after = &s.maps.witness.after;
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
        .maps
        .witness
        .objects
        .iter()
        .cloned()
        .chain(s.own_objects.iter().map(|o| o.bytes.clone()))
        .collect::<Vec<_>>();
    let kinds = [
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Credential,
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Request,
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::FeeSchedule,
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Receipt,
    ];
    for ((object, spec), kind) in all
        .iter()
        .zip(SendStagePlan::context_specs().unwrap())
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
        let mut values = vec![signed_message_native(kind, &object[..end])];
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
        Fp::from(u64::from(first.source.part.source_k())),
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
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn common_key_send_executes_all_authorization_and_map_tasks(fixture: &LoadFixture) {
    let rooted = load_outer::two_terminal_load_omega(fixture);
    run_send_schedule_with_profile(&rooted, SourceProfile::Tagged { buses: 3 });
}

/// Complete controls-off Send with a fixed named profile at all A stages.
/// Catalog construction must rebind the resulting terminal before admission.
#[allow(dead_code)] // Consumed by compact catalog construction.
pub(crate) fn run_send_schedule_with_profile(
    rooted: &load_outer::TwoTerminalLoadOmega,
    profile: SourceProfile,
) -> AuthenticatedSend {
    run_send_from_load(&rooted.artifact, profile, false)
}

/// Complete controls-off Send from a Load artifact with its actual carried key.
/// The caller retains the exact catalog; no two-terminal metadata is inferred.
#[allow(dead_code)] // Consumed by compact catalog construction.
pub(crate) fn run_send_from_load(
    rooted: &load_outer::DiagnosticLoadOmega,
    profile: SourceProfile,
    native_differential: bool,
) -> AuthenticatedSend {
    let source = Arc::new(sources(rooted));
    let context = ContextPlan::with_schedule(
        source.plan.clone(),
        vec![vec![], vec![], vec![0]],
        Some(0),
        SendStagePlan::context_specs().unwrap(),
    )
    .unwrap()
    .with_operation_tasks(vec![
        vec![OperationTask::SendObjects, OperationTask::SendTransition],
        vec![OperationTask::SendPending, OperationTask::SendFeeAndCarry],
        vec![OperationTask::SendAuthorization],
    ])
    .unwrap();
    SendStagePlan::new(context.clone()).unwrap();
    let claims = [
        source.predecessor.pallas.as_input(),
        source.predecessor.opening.clone(),
    ];
    let (fold, pallas) = create_fold(
        &source.params,
        &claims,
        common::public_fixture_tape(122),
        iroha_plonk_recursion::FoldPurpose::AInitial,
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
        fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
            fold.to_private_bytes(),
        ),
        known: true,
    };
    let public = first_public(&first);
    let (assigned, k) = match synthesize(&first, 16, Some(&public)) {
        Ok(a) => (a, 16),
        Err(error) => {
            eprintln!("Send A1 k16 capacity failure {error:?}");
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
        "GENUINE_SEND_A1 lanes={lanes:?} production_k16_fit={}",
        k == 16
    );
    assert_eq!(k, 16, "hard capacity cannot be relaxed");
    // The inline relation: another honest step never proves this statement, even with
    // a consistently rebound context.
    let mut changed = (*source).clone();
    changed.maps.witness.step = iroha_kagemusha_proof::vectors::sample_witness(
        99,
        SigmaRelation::SEND,
        iroha_kagemusha_proof::vectors::Mutation::None,
    );
    let mut foreign_step = first.clone();
    foreign_step.source = Arc::new(changed);
    assert!(
        !iroha_plonk::check::check_circuit(
            &foreign_step,
            16,
            &first_public(&foreign_step),
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied()),
        "A1 must reject a step witness of another statement"
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
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    let output = continue_schedule(&first, &key, proof, &public, true, native_differential)
        .expect("complete Send schedule must meet k16");
    assert_eq!(output.state.core, source.maps.witness.after.core);
    assert_eq!(output.state.rest, source.maps.witness.after.rest);
    assert_eq!(output.state.lineage, source.maps.witness.after.lineage);
    eprintln!(
        "SEND_COMPLETE_TASK_COMPONENT hard_predecessor=true inline_relation=true own_receipt_1V=true all_maps=true all_openings=true full_catalog=false release_qualified=false"
    );
    output
}

fn native_installed_send_differential(
    first: &First,
    a: Vec<Arc<iroha_plonk::ProvingKey<Eq>>>,
    w: Vec<Arc<iroha_plonk::ProvingKey<Ep>>>,
    originals_a: &[(Vec<u8>, [u8; 544])],
    originals_w: &[(Vec<u8>, [u8; 544])],
) {
    use iroha_kagemusha_proof::a_relation::native::send as native;
    assert_eq!(
        first.profile,
        SourceProfile::Tagged {
            buses: native::SOURCE_RANGE_BUSES,
        }
    );
    let source = &first.source;
    let plan = native::Plan::new(
        source.plan.clone(),
        0,
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
    // Only installed metadata is needed for source/key import. No native Inputs,
    // Prepared operation or runtime checkpoint exists at this point.
    let key_originals_a: [NativeSendOriginal; 3] = a
        .iter()
        .map(|key| NativeSendOriginal::from_key(key.as_ref()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("exact three A originals"));
    let key_originals_w: [NativeSendOriginal; 2] = w
        .iter()
        .map(|key| NativeSendOriginal::from_key(key.as_ref()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("exact two W originals"));
    let config = iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: key_originals_a
            .iter()
            .chain(&key_originals_w)
            .map(|original| original.pk.len())
            .max()
            .unwrap(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let install = |plan: native::Plan,
                   a: &[NativeSendOriginal; 3],
                   w: &[NativeSendOriginal; 2],
                   config|
     -> Result<native::Prover, native::Error> {
        let a_metadata = a
            .iter()
            .map(NativeSendOriginal::metadata)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| native::Error::Artifact)?;
        let w_metadata = w
            .iter()
            .map(NativeSendOriginal::metadata)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| native::Error::Artifact)?;
        let prover = native::Prover::from_artifacts(plan, a_metadata, w_metadata)?;
        for (stage, original) in a.iter().enumerate() {
            prover.import_a(stage, &original.pk, config)?;
            if let Some(original) = w.get(stage) {
                prover.import_w(stage, &original.pk, config)?;
            }
        }
        Ok(prover)
    };
    let installed = install(plan.clone(), &key_originals_a, &key_originals_w, config).unwrap();
    assert!(
        installed
            .import_a(3, &key_originals_a[0].pk, config)
            .is_err()
    );
    assert!(
        installed
            .import_w(2, &key_originals_w[0].pk, config)
            .is_err()
    );
    for mutation in 0..12 {
        let mut bad_a = key_originals_a.clone();
        let mut bad_w = key_originals_w.clone();
        match mutation {
            0 => bad_a.swap(0, 2),
            1 => bad_a.swap(1, 2),
            2 => bad_w.swap(0, 1),
            3 => bad_a[0].vk.clone_from(&key_originals_a[2].vk),
            4 => bad_w[0].vk.clone_from(&key_originals_w[1].vk),
            5 => bad_a[0].pk[44 + key_originals_a[0].vk.len()] ^= 1,
            6 => bad_a[0].pk[44 + key_originals_a[0].vk.len() + 32] ^= 1,
            7 => bad_w[0].pk[44 + key_originals_w[0].vk.len()] ^= 1,
            8 => bad_a[2].pk[44 + key_originals_a[2].vk.len()] ^= 1,
            9 => bad_a[0].pk.push(0),
            10 => {
                bad_a[0].pk.pop();
            }
            _ => bad_w[0]
                .descriptor
                .clone_from(&key_originals_a[0].descriptor),
        }
        assert!(
            install(plan.clone(), &bad_a, &bad_w, config).is_err(),
            "installed Send original mutation{mutation}"
        );
    }
    assert!(
        install(
            plan.clone(),
            &key_originals_a,
            &key_originals_w,
            iroha_plonk::keys::pk::artifact::ReadConfig {
                maximum_rows: (1 << 16) - 1,
                ..config
            }
        )
        .is_err()
    );
    assert!(
        install(
            plan.clone(),
            &key_originals_a,
            &key_originals_w,
            iroha_plonk::keys::pk::artifact::ReadConfig {
                maximum_bytes: 0,
                ..config
            }
        )
        .is_err()
    );
    let descriptor =
        iroha_plonk::cs::CircuitDescriptorV2::decode(&key_originals_a[0].descriptor).unwrap();
    for mutation in 0..5 {
        let mut wrong = descriptor.clone();
        match mutation {
            0 => wrong.instance_types[0] = iroha_plonk::cs::InstanceType::Field,
            1 => wrong.transcript = iroha_plonk::cs::TranscriptV2::KagemushaPoseidonRp57,
            2 => wrong.instance_mode = iroha_plonk::cs::InstanceModeV1::Committed,
            3 => wrong.proof_suffix = iroha_plonk::cs::ProofSuffixV1::None,
            _ => wrong.instance_lengths[0] = 68,
        }
        let mut bad_a = key_originals_a.clone();
        bad_a[0].descriptor = wrong.encode().unwrap();
        assert!(
            install(plan.clone(), &bad_a, &key_originals_w, config).is_err(),
            "installed Send profile mutation{mutation}"
        );
    }
    // Lean lineage: Send pins no certificate root; the own receipt binds the provider.
    let changed_plan = native::Plan::new(
        source.plan.clone(),
        0,
        iroha_kagemusha_proof::a_relation::own::OwnPolicy::new(
            [31, 33],
            bootstrap_objects::key(23),
        )
        .unwrap(),
        source.signature_schema.clone(),
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    assert!(
        install(changed_plan, &key_originals_a, &key_originals_w, config).is_err(),
        "installed provider policy must match the original A source"
    );
    let input = native::Inputs {
        state: native::SendState {
            before: source.maps.witness.before,
            after: source.maps.witness.after,
            statement: source.maps.witness.statement,
        },
        step: source.maps.witness.step.clone(),
        objects: core::array::from_fn(|i| {
            if i < 3 {
                source.maps.witness.objects[i].clone()
            } else {
                source.own_objects[i - 3].bytes.clone()
            }
        }),
        pending: source.maps.witness.pending,
        fee: source.maps.witness.fee,
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
    assert_eq!(installed.descriptors().len(), 5);
    let layouts = installed.checkpoint_layouts().unwrap();
    assert_eq!(layouts.len(), 5);
    assert!(
        native::Catalog::new(core::array::from_fn(|_| installed.clone())).is_err(),
        "copies of mask0 do not constitute the complete source catalog"
    );
    let budget = MemoryBudget::DEFAULT;
    let prepared = plan.prepare(input.clone(), budget).unwrap();
    let (actual_first, native_first_public) = prepared
        .first_circuit(common::public_fixture_tape(122), &FoldConfig::default())
        .unwrap();
    // Witness construction compares exact source descriptor, fixed/selector tables
    // and copy mapping against the originals mounted by the installed owner.
    Witness::from_circuit(&a[0], &actual_first, &[native_first_public]).unwrap();
    // Original files remain test-owned; the producer retains only metadata.
    // Release every diagnostic PK before importing one borrowed key per proof.
    drop((a, w));
    let mut session = installed.prepare(input.clone(), budget).unwrap();
    let unrelated_session = installed.prepare(input.clone(), budget).unwrap();
    // D6a (DP §7.4 test 8): a detached session resumes only on the prover instance
    // that prepared it. A clone carries identical installed artifacts and is still
    // another instance.
    let detached = installed
        .prepare(input.clone(), budget)
        .unwrap()
        .into_retained();
    assert!(matches!(
        installed.clone().resume(detached),
        Err(native::Error::Input)
    ));
    let fold = FoldConfig::default();
    let foreign_seal = installed
        .import_a(1, &key_originals_a[1].pk, config)
        .unwrap();
    let foreign = installed.bind_a(1, &foreign_seal, None).unwrap();
    assert!(matches!(
        session.first(
            &foreign,
            common::public_fixture_tape(122),
            &fold,
            common::fresh_randomness(),
            ProverConfig::default()
        ),
        Err(native::Error::Artifact)
    ));
    let key_seal = installed
        .import_a(0, &key_originals_a[0].pk, config)
        .unwrap();
    let key = installed.bind_a(0, &key_seal, None).unwrap();
    let generated = session
        .first(
            &key,
            common::public_fixture_tape(122),
            &fold,
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
    assert_ne!(generated.proof(), originals_a[0].0, "fresh proof attempt");
    let mut current = session
        .restore_first(originals_a[0].0.clone(), &originals_a[0].1, budget)
        .unwrap();
    assert_eq!(current.proof(), originals_a[0].0, "exact retained original");
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
    // T5 (C2 n2): a checkpoint restored under another session of the same prover.
    let foreign_current = unrelated_session
        .restore_first_checkpoint(&payloads[0], budget)
        .unwrap();
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
    for stage in 0..native::W_STAGE_COUNT {
        // D6a: each continuation runs on a session detached and resumed between
        // fold calls; checkpoints restored before detaching keep their source.
        session = installed.resume(session.into_retained()).unwrap();
        // T5 (C2 n2): the resumed session still refuses another session's checkpoint, before
        // any verification.
        assert!(matches!(
            session.encode_a_checkpoint(&foreign_current, budget),
            Err(native::Error::Input)
        ));
        if stage == 0 {
            let foreign_seal = installed
                .import_w(1, &key_originals_w[1].pk, config)
                .unwrap();
            let foreign = installed.bind_w(1, &foreign_seal, None).unwrap();
            assert!(matches!(
                session.wrapper(
                    &current,
                    &foreign,
                    common::public_fixture_tape(124),
                    &fold,
                    common::fresh_randomness(),
                    ProverConfig::default()
                ),
                Err(native::Error::Artifact)
            ));
        }
        let key_seal = installed
            .import_w(stage, &key_originals_w[stage].pk, config)
            .unwrap();
        let key = installed.bind_w(stage, &key_seal, None).unwrap();
        let generated_w = session
            .wrapper(
                &current,
                &key,
                common::public_fixture_tape(124 + stage as u64),
                &fold,
                common::fresh_randomness(),
                ProverConfig::default(),
            )
            .unwrap();
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
        let mut changed = payload.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            session
                .restore_wrapper_checkpoint(&current, &changed, budget)
                .is_err()
        );
        let restored_w = session
            .restore_wrapper_checkpoint(&current, &payload, budget)
            .unwrap();
        payloads.push(payload);
        assert_ne!(
            generated_w.proof(),
            originals_w[stage].0,
            "fresh proof attempt"
        );
        assert_eq!(generated_w.vesta_bytes(), restored_w.vesta_bytes());
        assert_eq!(generated_w.stage(), stage);
        assert_eq!(
            restored_w.proof(),
            originals_w[stage].0,
            "exact retained original"
        );
        // Retain the exact original W opening and proof bytes at every continuation.
        if stage == 0 {
            let foreign_seal = installed
                .import_a(0, &key_originals_a[0].pk, config)
                .unwrap();
            let foreign = installed.bind_a(0, &foreign_seal, None).unwrap();
            assert!(matches!(
                session.advance(
                    &restored_w,
                    &foreign,
                    common::public_fixture_tape(125),
                    &fold,
                    common::fresh_randomness(),
                    ProverConfig::default()
                ),
                Err(native::Error::Artifact)
            ));
        }
        let key_seal = installed
            .import_a(stage + 1, &key_originals_a[stage + 1].pk, config)
            .unwrap();
        let key = installed.bind_a(stage + 1, &key_seal, None).unwrap();
        let generated_a = session
            .advance(
                &restored_w,
                &key,
                common::public_fixture_tape(125 + stage as u64),
                &fold,
                common::fresh_randomness(),
                ProverConfig::default(),
            )
            .unwrap();
        let restored_a = session
            .restore_a(
                &restored_w,
                originals_a[stage + 1].0.clone(),
                &originals_a[stage + 1].1,
                budget,
            )
            .unwrap();
        assert_ne!(
            generated_a.proof(),
            originals_a[stage + 1].0,
            "fresh proof attempt"
        );
        assert_eq!(generated_a.instances(), restored_a.instances());
        assert_eq!(generated_a.pallas_bytes(), restored_a.pallas_bytes());
        assert_eq!(restored_a.stage(), stage + 1);
        assert_eq!(
            restored_a.proof(),
            originals_a[stage + 1].0,
            "exact retained original"
        );
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
    assert_eq!(payloads.len(), 5);
    let restarted = installed.prepare(input.clone(), budget).unwrap();
    let mut replayed = restarted
        .restore_first_checkpoint(&payloads[0], budget)
        .unwrap();
    assert_eq!(
        restarted.encode_a_checkpoint(&replayed, budget).unwrap(),
        payloads[0]
    );
    assert!(
        restarted
            .restore_first_checkpoint(&payloads[2], budget)
            .is_err()
    );
    for stage in 0..native::W_STAGE_COUNT {
        let wrong = (stage + 1) % native::W_STAGE_COUNT;
        assert!(
            restarted
                .restore_wrapper_checkpoint(&replayed, &payloads[2 * wrong + 1], budget)
                .is_err()
        );
        let wrapper = restarted
            .restore_wrapper_checkpoint(&replayed, &payloads[2 * stage + 1], budget)
            .unwrap();
        assert_eq!(
            restarted
                .encode_wrapper_checkpoint(&wrapper, budget)
                .unwrap(),
            payloads[2 * stage + 1]
        );
        assert!(
            restarted
                .restore_a_checkpoint(&wrapper, &payloads[0], budget)
                .is_err()
        );
        replayed = restarted
            .restore_a_checkpoint(&wrapper, &payloads[2 * stage + 2], budget)
            .unwrap();
        assert_eq!(
            restarted.encode_a_checkpoint(&replayed, budget).unwrap(),
            payloads[2 * stage + 2]
        );
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
        "NATIVE_SEND_PARITY metadata_only_producer=true borrowed_stage_PK=true exact_original_proof_bytes=true canonical_fresh_session_replay=true"
    );
    let key_seal = installed
        .import_w(0, &key_originals_w[0].pk, config)
        .unwrap();
    let key = installed.bind_w(0, &key_seal, None).unwrap();
    assert!(
        session
            .wrapper(
                &current,
                &key,
                common::public_fixture_tape(130),
                &fold,
                common::fresh_randomness(),
                ProverConfig::default()
            )
            .is_err()
    );
    for mutation in 0..6 {
        let mut bad = input.clone();
        match mutation {
            // A step witness of another statement never prepares.
            0 => {
                bad.step = iroha_kagemusha_proof::vectors::sample_witness(
                    99,
                    SigmaRelation::SEND,
                    iroha_kagemusha_proof::vectors::Mutation::None,
                );
            }
            1 => bad.predecessor.proof[0] ^= 1,
            2 => bad.q[0].proof[0] ^= 1,
            3 => bad.state.before.lineage[17] += Fp::ONE,
            4 => bad.objects[0][0] ^= 1,
            _ => bad.objects[3][0] ^= 1,
        }
        assert!(
            installed.prepare(bad, budget).is_err(),
            "original mutation{mutation}"
        );
    }
}

#[derive(Clone)]
struct NativeSendOriginal {
    descriptor: Vec<u8>,
    vk: Vec<u8>,
    pk: Vec<u8>,
}
impl NativeSendOriginal {
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
        iroha_kagemusha_proof::a_relation::native::send::Error,
    > {
        use iroha_kagemusha_proof::a_relation::native::{artifact::KeyArtifact, send::Error};
        let binding = iroha_plonk::DescriptorBinding::decode_v2(&self.descriptor)
            .map_err(|_| Error::Artifact)?;
        let key =
            iroha_plonk::VerifyingKey::read(&self.vk, &binding).map_err(|_| Error::Artifact)?;
        KeyArtifact::new(binding, key).map_err(|_| Error::Artifact)
    }
}
