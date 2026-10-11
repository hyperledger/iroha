//! Genuine Send sigma and same-tape ownership, Request, fee and depth32 maps.
//! These component tests do not substitute for the hard predecessor/Q A schedule.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)] // Shared genuine object signing support.
mod bootstrap_objects;
mod common;
#[path = "common/load_objects.rs"]
#[allow(dead_code)] // The component consumes Load state, not its receipt proof.
mod load_objects;
#[path = "common/send_objects.rs"]
mod send_objects;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    SigmaProver, SigmaRelation,
    a_relation::{
        LineagePublicCells, SigmaBindingCells,
        send::{SendInputs, SendObjects, SendStagePlan, SendStageWitness},
    },
    admin_sigma::StateWitness,
    operation_relation::{
        map_effects::{InsertCells, MapState},
        objects::ObjectKind,
        state::StateCells,
        statement::StatementCells,
    },
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Eq, Fp, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::{
        p_bytes_native,
        tape::{BytesChip, BytesConfig},
    },
    imt::{LeafCells, OpeningCells, PathCells},
};
use iroha_plonk_recursion::{
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone)]
pub(crate) struct SendMaps {
    pub(crate) witness: send_objects::SendFixture,
    pub(crate) known: bool,
    pub(crate) stage_plan: Option<SendStagePlan>,
}
#[derive(Clone, Debug)]
pub(crate) struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl SendMaps {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
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
        witness: &IndexedInsert<Fp>,
    ) -> Result<InsertCells, Error> {
        let leaf = witness.leaf;
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
            low: OpeningCells { leaf, path: low },
            slot,
        })
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![
            [
                ObjectKind::Credential,
                ObjectKind::Request,
                ObjectKind::FeeSchedule,
            ]
            .into_iter()
            .zip(&self.witness.objects)
            .map(|(kind, bytes)| {
                let end = kind.body_len();
                let mut fields = vec![p_bytes_native(kind.signing_domain(), &bytes[..end])];
                for offset in [16, 0, 48, 32] {
                    fields.push(Fp::from_u128(u128::from_be_bytes(
                        bytes[end + offset..end + offset + 16].try_into().unwrap(),
                    )));
                }
                hash_with_domain(kind.object_domain(), &fields)
            })
            .collect(),
        ]
    }
}
impl Circuit<Fp> for SendMaps {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign(meta, 5).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(3);
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
            || "Send same tape objects and maps",
            |mut region| {
                let (before, pred) = self.state(&mut chip, &mut region, &self.witness.before)?;
                let (after, next) = self.state(&mut chip, &mut region, &self.witness.after)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                // The actual recursive Q binder derives this selector from the same
                // state. This component only consumes the sigma's statement.
                let index = iroha_kagemusha_proof::a_relation::schedule::constrain_sigma_selector(
                    &mut chip.uint(),
                    &mut region,
                    3,
                    &before.core()[21],
                )?;
                let sigma = SigmaBindingCells::from_statement(&statement, index, vec![]);
                let sources = self
                    .witness
                    .objects
                    .each_ref()
                    .map(|o| o.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
                let objects = SendObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    sources.each_ref().map(Vec::as_slice),
                )?;
                let pending =
                    self.insertion(&mut chip.uint(), &mut region, &self.witness.pending)?;
                let fee = self.insertion(&mut chip.uint(), &mut region, &self.witness.fee)?;
                let input = SendInputs {
                    predecessor: MapState {
                        state: &before,
                        lineage: &pred,
                    },
                    successor: MapState {
                        state: &after,
                        lineage: &next,
                    },
                    sigma: &sigma,
                };
                if let Some(plan) = &self.stage_plan {
                    use iroha_kagemusha_proof::a_relation::schedule::OperationTask;
                    for stage in 0..plan.context().stage_count() {
                        let tasks = plan
                            .context()
                            .operation_tasks(stage)
                            .ok_or(Error::Synthesis)?;
                        plan.constrain_stage(
                            &mut chip,
                            &mut region,
                            stage,
                            &objects,
                            input,
                            SendStageWitness {
                                authorization: None,
                                proof: None,
                                pending: tasks
                                    .contains(&OperationTask::SendPending)
                                    .then_some(&pending),
                                fee: tasks
                                    .contains(&OperationTask::SendFeeAndCarry)
                                    .then_some(&fee),
                            },
                        )?;
                    }
                } else {
                    objects.constrain(&mut chip, &mut region, input, &pending, &fee)?;
                }
                Ok(objects
                    .context()
                    .iter()
                    .map(|o| o.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, value) in out.iter().enumerate() {
            layouter.constrain_instance(value.cell(), config.public, i)?;
        }
        Ok(())
    }
}
fn fixture() -> SendMaps {
    let (bootstrap, _, _) = bootstrap_objects::enrollment();
    let (load, _, _) = load_objects::funded(&bootstrap);
    SendMaps {
        witness: send_objects::from_load(&load.successor),
        known: true,
        stage_plan: None,
    }
}
#[test]
fn genuine_send_sigma_and_same_tape_depth32_maps() {
    let circuit = fixture();
    let shape = common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1));
    let prover = SigmaProver::<Eq>::keygen_with_params(shape, common::vesta_params(12)).unwrap();
    let sigma = prover
        .prove(&circuit.witness.step, common::recovery(221))
        .unwrap();
    let opening = accumulate_generator(
        prover.params(),
        prover.proving_key().binding(),
        prover.proving_key().vk(),
        &[sigma.public.instance()],
        &sigma.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening
        .decide(prover.params(), MemoryBudget::DEFAULT)
        .unwrap();
    let report = check_circuit(&circuit, 16, &circuit.public(), CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report:?}");
    let known = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let lanes: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect();
    eprintln!(
        "actual Send mask0 sigma={}B, five-bus objects/D32 lanes={lanes:?}; hard predecessor/Q closure not in this component",
        sigma.bytes.len()
    );
    for mutation in 0..8 {
        let mut wrong = circuit.clone();
        match mutation {
            0 => wrong.witness.pending.slot_siblings[31] += Fp::ONE,
            1 => wrong.witness.pending.leaf_siblings[0] += Fp::ONE,
            2 => wrong.witness.pending.slot = 0,
            3 => wrong.witness.after.core[16] += Fp::ONE,
            4 => wrong.witness.statement[23] += Fp::ONE,
            5 => wrong.witness.objects[0][98] ^= 1, // Payer account, with recomputed public digest.
            6 => wrong.witness.objects[1][98] ^= 1, // Payer wallet in the Request.
            _ => wrong.witness.objects[1][ObjectKind::Request.body_len()] ^= 1,
        }
        assert!(
            !check_circuit(&wrong, 16, &wrong.public(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "Send mutation{mutation}"
        );
    }
    // A zero held fee digest deliberately permits arbitrary bytes in its fixed
    // total dummy slot, while their exact object commitment remains public.
    let mut unused = circuit;
    unused.witness.objects[2].fill(255);
    assert!(
        check_circuit(&unused, 16, &unused.public(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
fn send_held_fee_cannot_skip_or_replace_either_map_obligation() {
    let (bootstrap, _, _) = bootstrap_objects::enrollment();
    let (load, _, _) = load_objects::funded(&bootstrap);
    let circuit = SendMaps {
        witness: send_objects::with_held_fee(&load.successor),
        known: true,
        stage_plan: None,
    };
    assert!(
        common::check_witness(
            &common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1)),
            &circuit.witness.step
        )
        .is_satisfied()
    );
    let report = check_circuit(&circuit, 16, &circuit.public(), CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report:?}");
    for mutation in 0..7 {
        let mut wrong = circuit.clone();
        match mutation {
            0 => wrong.witness.fee = send_objects::from_load(&load.successor).fee,
            1 => wrong.witness.fee.slot_siblings[31] += Fp::ONE,
            2 => wrong.witness.fee.slot = wrong.witness.fee.leaf_slot,
            3 => wrong.witness.objects[2][ObjectKind::FeeSchedule.body_len()] ^= 1,
            4 => wrong.witness.objects[1][258] ^= 1, // Different historical schedule.
            5 => wrong.witness.after.core[19] = wrong.witness.before.core[19],
            _ => wrong.witness.after.core[17] = wrong.witness.before.core[17],
        }
        assert!(
            !check_circuit(&wrong, 16, &wrong.public(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "Send fee mutation{mutation}"
        );
    }
}

/// Actual own sigma/Q source for the subsequent rooted Send stage-chain tests.
#[allow(dead_code)] // Retained source claims are consumed by the recursive integration next.
pub(crate) struct SendQ {
    pub(crate) witness: send_objects::SendFixture,
    pub(crate) sigma: Vec<u8>,
    pub(crate) sigma_plan: iroha_kagemusha_proof::q_sigma::QSigmaPlan,
    pub(crate) q: iroha_kagemusha_proof::a_relation::QProofPlan,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Vec<iroha_pasta::Fq>>,
    pub(crate) opening: iroha_plonk_recursion::FoldInput<Ep>,
    pub(crate) part: iroha_plonk_recursion::FoldInput<Eq>,
}
#[allow(dead_code)] // Used by the complete Send-chain fixture after catalog rebinding.
pub(crate) fn genuine_send_source(before: &StateWitness) -> SendQ {
    genuine_send_source_with_q_layout(before, None)
}
#[allow(dead_code)] // Used by the complete Send-chain candidate profile.
pub(crate) fn genuine_send_source_with_q_layout(
    before: &StateWitness,
    q_buses: Option<usize>,
) -> SendQ {
    use iroha_kagemusha_proof::{
        a_relation::{QProofPlan, schedule::sigma_selector},
        q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    };
    use iroha_plonk_recursion::{FoldConfig, FoldInput, verifier::VerifierPlan};
    let witness = send_objects::from_load(before);
    let shape = common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1));
    let prover = SigmaProver::<Eq>::keygen_with_params(shape, common::vesta_params(12)).unwrap();
    let proof = prover.prove(&witness.step, common::recovery(221)).unwrap();
    let verifier = prover.verifier();
    let class = SigmaClass::from_verifiers(&[(sigma_selector(3, 0).unwrap(), &verifier)]).unwrap();
    let vparams = common::vesta_params(16);
    let params = iroha_plonk::pcs::ipa::PinnedParams::<Ep>::derive(16).unwrap();
    let sigma_plan = QSigmaPlan::new(class, None, &vparams).unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: prover.proving_key().vk().clone(),
                statement: proof.public.instance()[0],
                length: proof.bytes.len().try_into().unwrap(),
                proof: proof.bytes.clone(),
            },
            None,
            &vparams,
            iroha_pasta::Fq::from(72),
            &FoldConfig::default(),
        )
        .unwrap();
    let part = prepared.part().clone();
    let q = q_buses
        .map_or_else(
            || QSigmaProver::keygen(&prepared, params.clone()),
            |buses| QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), buses),
        )
        .unwrap();
    let qproof = q
        .prove(
            &prepared,
            common::recovery(222),
            iroha_plonk::ProverConfig::default(),
        )
        .unwrap();
    let claim = accumulate_generator(
        &params,
        q.binding(),
        q.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&params, MemoryBudget::DEFAULT).unwrap();
    eprintln!(
        "actual Send mask0 sigma={}B Q={}B sourcek={}",
        proof.bytes.len(),
        qproof.bytes.len(),
        part.source_k()
    );
    SendQ {
        witness,
        sigma: proof.bytes,
        sigma_plan,
        q: QProofPlan::new(
            VerifierPlan::new(q.binding().clone(), params).unwrap(),
            q.verifying_key().clone(),
        )
        .unwrap(),
        proof: qproof.bytes,
        instances: qproof.instances,
        opening: FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap(),
        part,
    }
}
#[test]
#[ignore = "actual Send sigma/Q source plus committed fixed-stage operation plan; run optimized"]
fn genuine_send_q_and_fixed_operation_stages_reject_drop_or_relabel() {
    use iroha_kagemusha_proof::a_relation::{
        AProofPlan, context::ContextPlan, schedule::OperationTask,
    };
    let (bootstrap, _, _) = bootstrap_objects::enrollment();
    let (load, _, _) = load_objects::funded(&bootstrap);
    let source = genuine_send_source(&load.successor);
    let params = iroha_plonk::pcs::ipa::PinnedParams::<Ep>::derive(16).unwrap();
    // Only descriptor metadata is needed to exercise the operation partition.
    // No predecessor proof is constructed or accepted in this component. The
    // complete recursive Send test must use the catalog-bound real Omega key.
    let predecessor = predecessor_frame_metadata(&params);
    // Actual signature-circuit key; no placeholder predecessor or signature proof
    // is accepted by this constructor-only schedule check.
    let (state, cert, cred) = bootstrap_objects::enrollment();
    let receipt = bootstrap_objects::receipt(&state, &source.sigma);
    let (signature, _) = bootstrap_objects::signatures(&[cert, cred, receipt]);
    let signature_key = iroha_plonk::keys::keygen_pk_v2(
        &params,
        &signature,
        &iroha_plonk::keys::KeygenConfigV2::pipa_r(
            iroha_kagemusha_proof::q_signature::QSignaturePlan::instance_types().to_vec(),
        ),
    )
    .unwrap();
    let signature_q = iroha_kagemusha_proof::a_relation::QProofPlan::new(
        iroha_plonk_recursion::verifier::VerifierPlan::new(
            signature_key.binding().clone(),
            params.clone(),
        )
        .unwrap(),
        signature_key.vk().clone(),
    )
    .unwrap();
    let operation = AProofPlan::new(
        Variant::Send,
        source.sigma_plan.clone(),
        vec![source.q.clone(), signature_q],
        Some(predecessor),
        &params,
    )
    .unwrap();
    let context = ContextPlan::with_schedule(
        operation,
        vec![vec![], vec![], vec![], vec![0], vec![1]],
        Some(0),
        SendStagePlan::context_specs().unwrap(),
    )
    .unwrap();
    assert!(
        SendStagePlan::new(context.clone()).is_err(),
        "frame-only metadata has no operation qualification"
    );
    let tasks = vec![
        vec![OperationTask::SendObjects, OperationTask::SendProof],
        vec![OperationTask::SendPending],
        vec![OperationTask::SendFeeAndCarry],
        vec![],
        vec![OperationTask::SendAuthorization],
    ];
    let complete = context.clone().with_operation_tasks(tasks.clone()).unwrap();
    for mutation in 0..3 {
        let mut specs = SendStagePlan::context_specs().unwrap();
        match mutation {
            0 => specs[0].tag = 77,
            1 => specs[1].capacity += 1,
            _ => {
                specs.pop();
            }
        }
        let bad = ContextPlan::with_schedule(
            context.operation().clone(),
            vec![vec![], vec![], vec![], vec![0], vec![1]],
            Some(0),
            specs,
        )
        .unwrap()
        .with_operation_tasks(tasks.clone())
        .unwrap();
        assert!(
            SendStagePlan::new(bad).is_err(),
            "wrong same-tape schema{mutation}"
        );
    }

    assert_ne!(complete.schema(), context.schema());
    let mut moved = tasks.clone();
    moved[0].pop();
    moved[3].push(OperationTask::SendProof);
    assert!(SendStagePlan::new(context.clone().with_operation_tasks(moved).unwrap()).is_err());
    let mut omitted_proof = tasks.clone();
    omitted_proof[0].pop();
    assert!(context.clone().with_operation_tasks(omitted_proof).is_err());
    for omitted in 0..3 {
        let mut drop = tasks.clone();
        drop[omitted].clear();
        assert!(
            context.clone().with_operation_tasks(drop).is_err(),
            "missing operation task{omitted}"
        );
        let mut doubled = tasks.clone();
        doubled[3].push(tasks[omitted][0]);
        assert!(
            context.clone().with_operation_tasks(doubled).is_err(),
            "double operation task{omitted}"
        );
    }
    let mut relabelled = tasks.clone();
    relabelled.swap(1, 2);
    let relabelled = context.with_operation_tasks(relabelled).unwrap();
    assert_ne!(
        complete.schema(),
        relabelled.schema(),
        "operation task stage belongs to D_ctx"
    );
    let checked = SendStagePlan::new(complete).unwrap();
    let circuit = SendMaps {
        witness: source.witness,
        known: true,
        stage_plan: None,
    };
    let missing_auth = SendMaps {
        stage_plan: Some(checked),
        ..circuit.clone()
    };
    assert!(
        check_circuit(&missing_auth, 16, &missing_auth.public(), CheckMode::Strict).is_err(),
        "the mandatory own signature task cannot be omitted"
    );
    let report = check_circuit(&circuit, 16, &circuit.public(), CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report:?}");
    let mut bad = circuit.clone();
    bad.witness.pending.slot_siblings[31] += Fp::ONE;
    assert!(
        !check_circuit(&bad, 16, &bad.public(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

fn predecessor_frame_metadata(
    params: &iroha_plonk::pcs::ipa::PinnedParams<Ep>,
) -> iroha_plonk_recursion::verifier::VerifierPlan<Ep> {
    use iroha_pasta::Fq;
    use iroha_plonk::{
        cs::{Advice, InstanceType},
        keys::{KeygenConfigV2, keygen_pk_v2},
    };
    #[derive(Clone)]
    struct FrameMetadata;
    impl Circuit<Fq> for FrameMetadata {
        type Config = Column<Advice>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let advice = meta.advice_column();
            meta.create_gate("metadata-only boolean", |meta| {
                let a = meta.query_advice(advice, iroha_plonk::cs::Rotation::cur());
                vec![a.clone() * (a - iroha_plonk::cs::Expression::Constant(Fq::ONE))]
            });
            for length in [1, 2, 16] {
                meta.instance_column(length);
            }
            advice
        }
        fn synthesize(&self, _: Self::Config, _: impl Layouter<Fq>) -> Result<(), Error> {
            Ok(())
        }
    }
    let key = keygen_pk_v2(
        params,
        &FrameMetadata,
        &KeygenConfigV2::pipa_r(vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]),
    )
    .unwrap();
    iroha_plonk_recursion::verifier::VerifierPlan::new(key.binding().clone(), params.clone())
        .unwrap()
}
