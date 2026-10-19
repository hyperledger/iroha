//! Genuine Send sigma, the inline step relation on A's lane, and same-tape ownership,
//! Request, fee and depth32 maps. These component tests do not substitute for the hard
//! predecessor/Q A schedule.

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
        LineagePublicCells,
        send::{SendInputs, SendObjects, SendStagePlan, SendStageWitness},
        transition::TransitionInputs,
    },
    admin_sigma::StateWitness,
    circuit::{PrefixMode, RelationShape},
    operation_relation::{
        map_effects::{InsertCells, MapState},
        objects::{ObjectKind, signed_message_native},
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
    bytes::tape::{BytesChip, BytesConfig},
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
    /// Lay out the inline step relation (`SendTransition`) beside the objects and maps.
    pub(crate) transition: bool,
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
                let mut fields = vec![signed_message_native(kind, &bytes[..end])];
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
                    statement: &statement,
                };
                // The installed mask-0 relation; key generation lays it out unknown.
                let native = self.witness.step.evaluate(SigmaRelation::SEND);
                let transition = TransitionInputs {
                    shape: RelationShape::new(SigmaRelation::SEND, PrefixMode::Absorbed),
                    witness: self.known.then_some((&self.witness.step, &native)),
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
                                pending: tasks
                                    .contains(&OperationTask::SendPending)
                                    .then_some(&pending),
                                fee: tasks
                                    .contains(&OperationTask::SendFeeAndCarry)
                                    .then_some(&fee),
                                transition: tasks
                                    .contains(&OperationTask::SendTransition)
                                    .then_some(transition),
                            },
                        )?;
                    }
                } else {
                    objects.constrain(&mut chip, &mut region, input, &pending, &fee)?;
                    if self.transition {
                        transition.constrain(&mut chip, &mut region, &statement)?;
                    }
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
        transition: true,
    }
}
#[test]
fn genuine_send_sigma_and_same_tape_depth32_maps() {
    let circuit = fixture();
    let shape = common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1));
    let prover = SigmaProver::<Eq>::keygen_with_params(shape, common::vesta_params(12)).unwrap();
    let sigma = prover
        .prove(&circuit.witness.step, common::fresh_randomness())
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
    let maps_only = SendMaps {
        transition: false,
        ..circuit.clone()
    };
    let maps_only = synthesize(&maps_only, 16, None).unwrap();
    let rows = |tables: &iroha_plonk::frontend::AssignedTables<Fp>| {
        tables
            .advice_assigned()
            .iter()
            .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .max()
            .unwrap_or(0)
    };
    eprintln!(
        "actual Send mask0 sigma={}B, five-bus objects/D32/inline relation lanes={lanes:?}; \
         rows {} with the relation, {} without; hard predecessor/Q closure not in this component",
        sigma.bytes.len(),
        rows(&known.tables),
        rows(&maps_only.tables),
    );
    for mutation in 0..10 {
        let mut wrong = circuit.clone();
        match mutation {
            0 => wrong.witness.pending.slot_siblings[31] += Fp::ONE,
            1 => wrong.witness.pending.leaf_siblings[0] += Fp::ONE,
            2 => wrong.witness.pending.slot = 0,
            3 => wrong.witness.after.core[16] += Fp::ONE,
            4 => wrong.witness.statement[23] += Fp::ONE,
            5 => wrong.witness.objects[0][98] ^= 1, // Payer account, with recomputed public digest.
            6 => wrong.witness.objects[1][98] ^= 1, // Payer wallet in the Request.
            7 => wrong.witness.objects[1][ObjectKind::Request.body_len()] ^= 1,
            // The inline relation: another honest step does not prove this statement.
            8 => {
                wrong.witness.step = iroha_kagemusha_proof::vectors::sample_witness(
                    99,
                    SigmaRelation::SEND,
                    iroha_kagemusha_proof::vectors::Mutation::None,
                );
            }
            // An overdraft never satisfies the relation, whatever the statement says.
            _ => {
                wrong.witness.step = iroha_kagemusha_proof::vectors::sample_witness(
                    1,
                    SigmaRelation::SEND,
                    iroha_kagemusha_proof::vectors::Mutation::Overdraft,
                );
            }
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
fn a_cancelled_send_sigma_ends_without_a_proof_and_a_live_signal_changes_nothing() {
    fn config(signal: &iroha_pasta::CancellationToken) -> iroha_plonk::ProverConfig<'_> {
        iroha_plonk::ProverConfig {
            cancellation: Some(signal),
            ..iroha_plonk::ProverConfig::default()
        }
    }
    // A wallet's speculative Send proof runs under its review's signal (design §5.1).
    let circuit = fixture();
    let shape = common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1));
    let prover = SigmaProver::<Eq>::keygen_with_params(shape, common::vesta_params(12)).unwrap();
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    let Err(error) = prover.prove_with_config(
        &circuit.witness.step,
        common::fresh_randomness(),
        config(&cancelled),
    ) else {
        panic!("a cancelled signal produced a proof");
    };
    assert!(error.is_cancelled(), "{error:?}");
    let live = iroha_pasta::CancellationToken::new();
    let sigma = prover
        .prove_with_config(
            &circuit.witness.step,
            common::fresh_randomness(),
            config(&live),
        )
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
}

#[test]
fn send_held_fee_cannot_skip_or_replace_either_map_obligation() {
    let (bootstrap, _, _) = bootstrap_objects::enrollment();
    let (load, _, _) = load_objects::funded(&bootstrap);
    let circuit = SendMaps {
        witness: send_objects::with_held_fee(&load.successor),
        known: true,
        stage_plan: None,
        transition: true,
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

/// Actual σ_send for the Payment carrier, without a sigma-Q source: the payer's own
/// lineage proves the relation inline.
#[allow(dead_code)] // Used by the complete Send-chain fixture and the Receive Payment bounds.
pub(crate) fn genuine_send_sigma(before: &StateWitness) -> (send_objects::SendFixture, Vec<u8>) {
    let witness = send_objects::from_load(before);
    let shape = common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1));
    let prover = SigmaProver::<Eq>::keygen_with_params(shape, common::vesta_params(12)).unwrap();
    let proof = prover
        .prove(&witness.step, common::fresh_randomness())
        .unwrap();
    (witness, proof.bytes)
}
#[test]
#[ignore = "actual own-receipt signature key plus committed fixed-stage operation plan; run optimized"]
fn genuine_send_q_and_fixed_operation_stages_reject_drop_or_relabel() {
    use iroha_kagemusha_proof::{
        a_relation::{AProofPlan, context::ContextPlan, schedule::OperationTask},
        q_signature::{QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot},
    };
    use iroha_plonk_gadgets::p256::VerifyMode;
    let (bootstrap, _, _) = bootstrap_objects::enrollment();
    let (load, _, _) = load_objects::funded(&bootstrap);
    let witness = send_objects::from_load(&load.successor);
    let params = iroha_plonk::pcs::ipa::PinnedParams::<Ep>::derive(16).unwrap();
    // Only descriptor metadata is needed to exercise the operation partition.
    // No predecessor proof is constructed or accepted in this component. The
    // complete recursive Send test must use the catalog-bound real Omega key.
    let predecessor = predecessor_frame_metadata(&params);
    // Actual one-slot signature-circuit key for the own receipt, the only leaf of the
    // lean plan; no placeholder signature proof is accepted by this schedule check.
    let (state, _, _) = bootstrap_objects::enrollment();
    let receipt = bootstrap_objects::receipt(&state, &[7; 64]);
    let schema = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let signature = QSignatureCircuit::new(schema, vec![receipt.signature]).unwrap();
    let signature_key = iroha_plonk::keys::keygen_pk_v2(
        &params,
        &signature,
        &iroha_plonk::keys::KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
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
    let operation =
        AProofPlan::inline(Variant::Send, vec![signature_q], Some(predecessor), &params).unwrap();
    let partitions = || vec![vec![], vec![], vec![0]];
    let context = ContextPlan::with_schedule(
        operation,
        partitions(),
        Some(0),
        SendStagePlan::context_specs().unwrap(),
    )
    .unwrap();
    assert!(
        SendStagePlan::new(context.clone()).is_err(),
        "frame-only metadata has no operation qualification"
    );
    let tasks = vec![
        vec![OperationTask::SendObjects, OperationTask::SendTransition],
        vec![OperationTask::SendPending, OperationTask::SendFeeAndCarry],
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
        let bad =
            ContextPlan::with_schedule(context.operation().clone(), partitions(), Some(0), specs)
                .unwrap()
                .with_operation_tasks(tasks.clone())
                .unwrap();
        assert!(
            SendStagePlan::new(bad).is_err(),
            "wrong same-tape schema{mutation}"
        );
    }

    assert_ne!(complete.schema(), context.schema());
    // The inline relation cannot move beside the receipt or be dropped.
    let mut moved = tasks.clone();
    moved[0].pop();
    moved[2].push(OperationTask::SendTransition);
    assert!(SendStagePlan::new(context.clone().with_operation_tasks(moved).unwrap()).is_err());
    let mut omitted_relation = tasks.clone();
    omitted_relation[0].pop();
    assert!(
        context
            .clone()
            .with_operation_tasks(omitted_relation)
            .is_err()
    );
    for (stage, index) in [(0, 0), (1, 0), (1, 1), (2, 0)] {
        let mut drop = tasks.clone();
        let task = drop[stage].remove(index);
        assert!(
            context.clone().with_operation_tasks(drop).is_err(),
            "missing operation task {task:?}"
        );
        let mut doubled = tasks.clone();
        doubled[(stage + 1) % 3].push(task);
        assert!(
            context.clone().with_operation_tasks(doubled).is_err(),
            "double operation task {task:?}"
        );
    }
    let mut relabelled = tasks.clone();
    relabelled.swap(0, 1);
    let relabelled = context.with_operation_tasks(relabelled).unwrap();
    assert_ne!(
        complete.schema(),
        relabelled.schema(),
        "operation task stage belongs to D_ctx"
    );
    assert!(SendStagePlan::new(relabelled).is_err());
    let checked = SendStagePlan::new(complete).unwrap();
    let circuit = SendMaps {
        witness,
        known: true,
        stage_plan: None,
        transition: true,
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
