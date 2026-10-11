//! Fixed Receive task/Q/object metadata, without admitting fixture lineage keys.

use super::*;
use crate::{
    a_relation::{AProofPlan, QProofPlan, receive::tests::recursive_program_fixture},
    q_signature::{QSignatureCircuit, SignatureWitness},
};
use ff::Field;
use iroha_plonk::{
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::p256::native::Affine;
use iroha_plonk_recursion::verifier::VerifierPlan;

fn tasks() -> Vec<Vec<OperationTask>> {
    use OperationTask::*;
    vec![
        vec![ReceiveProofs, ReceiveOwnProof, ReceiveProofDigest],
        vec![ReceiveAuthorization],
        vec![
            ReceiveObjects,
            ReceiveSignatures,
            ReceiveNonmembership,
            ReceiveBlacklist,
            ReceiveConsumedEffects,
            ReceiveCreditEffects,
        ],
        vec![ReceiveEffects],
    ]
}

#[test]
fn stage_plan_pins_all_tapes_signature_slots_and_q_owners() {
    let (base, policy) = recursive_program_fixture();
    assert_eq!(base.q_count(), 1, "unused sigma key is a metadata fixture");
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    for variant in [Variant::Receive, Variant::ReceiveRenewed] {
        let schemas = ReceiveStagePlan::signature_schemas(variant, policy).unwrap();
        let keys = schemas
            .iter()
            .map(|schema| {
                let placeholder = SignatureWitness {
                    digest: Fp::ZERO,
                    key: [Affine::GENERATOR.x, Affine::GENERATOR.y],
                    signature: [[0; 4]; 2],
                };
                // Key generation fixes the real signature relation without making
                // any claim that these unused placeholder signatures are valid.
                let circuit =
                    QSignatureCircuit::new(schema.clone(), vec![placeholder; schema.slots().len()])
                        .unwrap();
                let key = keygen_pk_v2(
                    &params,
                    &circuit,
                    &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
                )
                .unwrap();
                QProofPlan::new(
                    VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
                    key.vk().clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let operation = AProofPlan::new(
            variant,
            base.sigma.clone(),
            vec![base.q(0).unwrap().clone(), keys[0].clone(), keys[1].clone()],
            base.omega().cloned(),
            &params,
        )
        .unwrap();
        exercise_signature_projection(&operation, &schemas[1]);
        let specs = ReceiveStagePlan::context_specs(variant, 8132, 10000).unwrap();
        let context = |operation: AProofPlan, partition, specs| {
            ContextPlan::with_schedule(operation, partition, Some(0), specs)
                .unwrap()
                .with_operation_tasks(tasks())
                .unwrap()
        };
        let partition = vec![vec![0], vec![1], vec![2], vec![]];
        let honest = context(operation.clone(), partition.clone(), specs.clone());
        for (required, duplicate) in [
            OperationTask::ReceiveProofDigest,
            OperationTask::ReceiveConsumedEffects,
            OperationTask::ReceiveCreditEffects,
        ]
        .into_iter()
        .flat_map(|task| [false, true].map(|duplicate| (task, duplicate)))
        {
            let mut incomplete = tasks();
            if duplicate {
                incomplete[1].push(required);
                incomplete[1].sort_unstable();
            } else {
                for group in &mut incomplete {
                    group.retain(|task| *task != required);
                }
            }
            assert!(
                ContextPlan::with_schedule(
                    operation.clone(),
                    partition.clone(),
                    Some(0),
                    specs.clone()
                )
                .unwrap()
                .with_operation_tasks(incomplete)
                .is_err(),
                "every hard digest/map owner must occur exactly once before terminal admission",
            );
        }
        for partition in [
            vec![vec![0], vec![1], vec![], vec![]],
            vec![vec![0], vec![1], vec![2], vec![2]],
        ] {
            assert!(
                ContextPlan::with_schedule(operation.clone(), partition, Some(0), specs.clone())
                    .is_err(),
                "Q2 must be verified exactly once"
            );
        }
        let future = context(
            operation.clone(),
            vec![vec![0], vec![1], vec![], vec![2]],
            specs.clone(),
        );
        assert!(
            ReceiveStagePlan::new(future, policy).is_err(),
            "Signatures cannot project future Q2"
        );
        let split = ContextPlan::with_schedule(
            operation.clone(),
            vec![vec![0], vec![1], vec![2], vec![], vec![]],
            Some(0),
            specs.clone(),
        )
        .unwrap()
        .with_operation_tasks(vec![
            tasks()[0].clone(),
            tasks()[1].clone(),
            vec![],
            tasks()[2].clone(),
            tasks()[3].clone(),
        ])
        .unwrap();
        assert!(
            ReceiveStagePlan::new(split, policy).is_ok(),
            "unique preceding Q2 owner is permitted"
        );
        for required in [
            OperationTask::ReceiveConsumedEffects,
            OperationTask::ReceiveCreditEffects,
        ] {
            let mut wrong = tasks();
            for group in &mut wrong {
                group.retain(|task| *task != required);
            }
            wrong.last_mut().unwrap().push(required);
            let late = ContextPlan::with_schedule(
                operation.clone(),
                partition.clone(),
                Some(0),
                specs.clone(),
            )
            .unwrap()
            .with_operation_tasks(wrong)
            .unwrap();
            assert!(
                ReceiveStagePlan::new(late, policy).is_err(),
                "hard map owner must precede terminal"
            );
        }
        let plan = ReceiveStagePlan::new(honest, policy).unwrap();
        assert_eq!(plan.context().stage_count(), 4);
        assert!(plan.signature_schema(0).is_none());
        assert!(plan.signature_schema(3).is_none());
        assert_eq!(plan.signature_schema(1).unwrap().slots().len(), 3);
        assert_eq!(
            plan.signature_schema(2).unwrap().slots().len(),
            if variant == Variant::Receive { 2 } else { 4 }
        );
        assert_eq!(plan.context().object_specs().len(), 11);
        for mutation in 0..4 {
            let mut wrong = specs.clone();
            match mutation {
                0 => wrong[1].capacity += 1,
                1 => wrong.swap(0, 1),
                2 => {
                    wrong.pop();
                }
                _ => wrong[10].capacity -= 1,
            }
            assert!(
                ReceiveStagePlan::new(context(operation.clone(), partition.clone(), wrong), policy)
                    .is_err(),
                "object schema {mutation}"
            );
        }
        let wrong_owner = context(
            operation.clone(),
            vec![vec![0], vec![2], vec![1], vec![]],
            specs.clone(),
        );
        assert!(ReceiveStagePlan::new(wrong_owner, policy).is_err());
        let wrong_slots = AProofPlan::new(
            variant,
            base.sigma.clone(),
            vec![base.q(0).unwrap().clone(), keys[1].clone(), keys[0].clone()],
            base.omega().cloned(),
            &params,
        )
        .unwrap();
        assert!(ReceiveStagePlan::new(context(wrong_slots, partition, specs), policy).is_err());
    }
}

/// Projection-only constraints: signature truth is supplied here solely to test
/// exact context equality. These metadata keys do not establish Q admission.
#[derive(Clone)]
struct ProjectionBinding {
    original: AProofPlan,
    target: AProofPlan,
    schema: QSignaturePlan,
    values: Vec<Fp>,
    target_values: Vec<Fp>,
    target_index: usize,
    known: bool,
}
impl iroha_plonk::frontend::Circuit<Fp> for ProjectionBinding {
    type Config = iroha_plonk_recursion::verifier::VerifierConfig<Ep>;
    type Params = ();
    type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut iroha_plonk::cs::ConstraintSystem<Fp>) -> Self::Config {
        Self::Config::configure_serialized_foreign_tagged(meta, 4).unwrap()
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl iroha_plonk::frontend::Layouter<Fp>,
    ) -> Result<(), iroha_plonk::frontend::Error> {
        let mut chip = VerifierChip::new(config);
        chip.load_tables(&mut layouter)?;
        layouter.assign_region(
            || "separately verified signature Q projection",
            |mut region| {
                let mut assign = |values: &[Fp]| {
                    values
                        .iter()
                        .map(|v| {
                            let value = if self.known {
                                iroha_plonk::frontend::Value::known(*v)
                            } else {
                                iroha_plonk::frontend::Value::unknown()
                            };
                            let word = chip.uint().glue().witness(&mut region, value)?;
                            iroha_plonk_recursion::codec::ScalarCells::<Ep>::from_native_word(
                                &mut chip.uint(),
                                &mut region,
                                &word,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()
                };
                let original = vec![assign(&self.values)?];
                let target = vec![assign(&self.target_values)?];
                let projection = crate::a_relation::signature::project_signature_q(
                    &mut chip,
                    &mut region,
                    &self.original,
                    2,
                    &self.schema,
                    &original,
                )?;
                projection.bind_context(&mut region, &self.target, self.target_index, &target)
            },
        )
    }
}
impl ProjectionBinding {
    fn accepts(&self) -> bool {
        iroha_plonk::check::check_circuit(self, 16, &[], iroha_plonk::check::CheckMode::Strict)
            .is_ok_and(|result| result.is_satisfied())
    }
}

fn exercise_signature_projection(operation: &AProofPlan, schema: &QSignaturePlan) {
    use ff::PrimeField;
    use iroha_plonk::frontend::{Circuit, synthesize};
    use iroha_plonk_gadgets::ff::Nat;
    let mut values = Vec::new();
    for slot in schema.slots() {
        values.push(Fp::from(41));
        let key = match slot.key {
            crate::q_signature::SignatureKey::Variable => Affine::GENERATOR,
            crate::q_signature::SignatureKey::Fixed(key) => key,
        };
        for words in [key.x, key.y, [17, 19, 23, 29], [31, 37, 41, 43]] {
            let integer = Nat::from_words(words);
            values.extend([
                Fp::from_u128(integer.low_u128()),
                Fp::from_u128(integer.shr(128).low_u128()),
            ]);
        }
        values.push(Fp::ONE);
    }
    let fixture = ProjectionBinding {
        original: operation.clone(),
        target: operation.clone(),
        schema: schema.clone(),
        target_values: values.clone(),
        values,
        target_index: 2,
        known: true,
    };
    assert!(fixture.accepts());
    let known = synthesize(&fixture, 16, None).unwrap();
    let unknown = synthesize(&fixture.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    for index in 0..fixture.values.len() {
        let mut changed = fixture.clone();
        changed.target_values[index] += Fp::ONE;
        assert!(!changed.accepts(), "changed Q2 public limb {index}");
    }
    let mut relabelled = fixture.clone();
    relabelled.target_index = 1;
    assert!(!relabelled.accepts(), "Q2 cannot be relabelled Q1");
    let mut foreign = fixture.clone();
    foreign.target = AProofPlan::new(
        operation.frame().variant(),
        operation.sigma.clone(),
        vec![
            operation.q(0).unwrap().clone(),
            operation.q(2).unwrap().clone(),
            operation.q(1).unwrap().clone(),
        ],
        operation.omega().cloned(),
        operation.q(0).unwrap().verifier().params(),
    )
    .unwrap();
    assert!(
        !foreign.accepts(),
        "same public words cannot cross fixed Q key identity"
    );
    let mut wide = fixture.clone();
    wide.values[1] = Fp::from(2).pow_vartime([128]);
    wide.target_values = wide.values.clone();
    assert!(
        !wide.accepts(),
        "raw Q key limbs retain the exact 128-bit bound"
    );
    for (slot, policy) in schema.slots().iter().enumerate() {
        if policy.mode == iroha_plonk_gadgets::p256::VerifyMode::Hard {
            let mut false_hard = fixture.clone();
            false_hard.values[slot * 10 + 9] = Fp::ZERO;
            false_hard.target_values = false_hard.values.clone();
            assert!(!false_hard.accepts(), "hard signature verdict remains true");
        }
        if matches!(policy.key, crate::q_signature::SignatureKey::Fixed(_)) {
            let mut wrong_root = fixture.clone();
            wrong_root.values[slot * 10 + 1] += Fp::ONE;
            wrong_root.target_values = wrong_root.values.clone();
            assert!(!wrong_root.accepts(), "fixed issuer root cannot be rebound");
        }
        let mut nonboolean = fixture.clone();
        nonboolean.values[slot * 10 + 9] = Fp::from(2);
        nonboolean.target_values = nonboolean.values.clone();
        assert!(
            !nonboolean.accepts(),
            "verdict is boolean before projection binding"
        );
    }
}
