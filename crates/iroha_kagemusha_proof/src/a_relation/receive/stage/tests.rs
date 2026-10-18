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
        vec![ReceiveProofs, ReceiveProofDigest, ReceiveTransition],
        vec![ReceiveAuthorization],
        vec![
            ReceiveObjects,
            ReceiveSignatures,
            ReceiveNonmembership,
            ReceiveConsumedEffects,
            ReceiveCreditEffects,
        ],
        vec![ReceiveEffects],
    ]
}

fn signature_key(schema: &QSignaturePlan, params: &PinnedParams<Ep>) -> QProofPlan {
    let placeholder = SignatureWitness {
        digest: Fp::ZERO,
        key: [Affine::GENERATOR.x, Affine::GENERATOR.y],
        signature: [[0; 4]; 2],
    };
    // Key generation fixes the real signature relation without making any claim
    // that these unused placeholder signatures are valid.
    let circuit =
        QSignatureCircuit::new(schema.clone(), vec![placeholder; schema.slots().len()]).unwrap();
    let key = keygen_pk_v2(
        params,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    QProofPlan::new(
        VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
        key.vk().clone(),
    )
    .unwrap()
}

#[test]
fn stage_plan_pins_all_tapes_signature_slots_and_q_owners() {
    let (base, policy) = recursive_program_fixture();
    assert_eq!(
        base.q_count(),
        1,
        "the incoming-only Q_sigma is a metadata fixture"
    );
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let keys = [Variant::Receive, Variant::ReceiveRenewed].map(|variant| {
        signature_key(
            &ReceiveStagePlan::signature_schema_for(variant, policy).unwrap(),
            &params,
        )
    });
    for (variant, own, other) in [
        (Variant::Receive, &keys[0], &keys[1]),
        (Variant::ReceiveRenewed, &keys[1], &keys[0]),
    ] {
        let schema = ReceiveStagePlan::signature_schema_for(variant, policy).unwrap();
        let operation = |signature: &QProofPlan| {
            AProofPlan::inline_with_incoming(
                variant,
                base.sigma_plan().unwrap().clone(),
                vec![base.q(0).unwrap().clone(), signature.clone()],
                base.omega().cloned(),
                &params,
            )
            .unwrap()
        };
        let operation_with = operation(own);
        exercise_signature_projection(&operation_with, &operation(other), &schema);
        let operation = operation_with;
        let specs = ReceiveStagePlan::context_specs(variant, 8132, 10000).unwrap();
        let context = |operation: AProofPlan, partition, specs| {
            ContextPlan::with_schedule(operation, partition, Some(0), specs)
                .unwrap()
                .with_operation_tasks(tasks())
                .unwrap()
        };
        // Authorization verifies the merged Q1; Signatures projects it later.
        let partition = vec![vec![0], vec![1], vec![], vec![]];
        let honest = context(operation.clone(), partition.clone(), specs.clone());
        for (required, duplicate) in [
            OperationTask::ReceiveProofDigest,
            OperationTask::ReceiveTransition,
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
                "every hard digest/map/transition owner must occur exactly once",
            );
        }
        for partition in [
            vec![vec![0], vec![], vec![], vec![]],
            vec![vec![0], vec![1], vec![1], vec![]],
        ] {
            assert!(
                ContextPlan::with_schedule(operation.clone(), partition, Some(0), specs.clone())
                    .is_err(),
                "Q1 must be verified exactly once"
            );
        }
        let future = context(
            operation.clone(),
            vec![vec![0], vec![], vec![], vec![1]],
            specs.clone(),
        );
        assert!(
            ReceiveStagePlan::new(future, policy).is_err(),
            "Authorization verifies Q1 in its own stage, and Signatures cannot project a future Q1"
        );
        let split = ContextPlan::with_schedule(
            operation.clone(),
            vec![vec![0], vec![1], vec![], vec![], vec![]],
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
            "unique preceding Q1 owner is permitted"
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
        assert!(plan.signature_schema(2).is_none());
        assert_eq!(
            plan.signature_schema(ReceiveStagePlan::SIGNATURE_Q)
                .unwrap()
                .slots()
                .len(),
            if variant == Variant::Receive { 3 } else { 5 }
        );
        assert_eq!(plan.context().object_specs().len(), 9);
        for mutation in 0..4 {
            let mut wrong = specs.clone();
            match mutation {
                0 => wrong[1].capacity += 1,
                1 => wrong.swap(0, 1),
                2 => {
                    wrong.pop();
                }
                _ => wrong[8].capacity -= 1,
            }
            assert!(
                ReceiveStagePlan::new(context(operation.clone(), partition.clone(), wrong), policy)
                    .is_err(),
                "object schema {mutation}"
            );
        }
        let wrong_owner = context(
            operation.clone(),
            vec![vec![0], vec![], vec![1], vec![]],
            specs.clone(),
        );
        assert!(ReceiveStagePlan::new(wrong_owner, policy).is_err());
        let wrong_slots = AProofPlan::inline_with_incoming(
            variant,
            base.sigma_plan().unwrap().clone(),
            vec![base.q(0).unwrap().clone(), other.clone()],
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
                    ReceiveStagePlan::SIGNATURE_Q,
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

// `foreign` differs from `operation` only in its Q1 key.
fn exercise_signature_projection(
    operation: &AProofPlan,
    foreign: &AProofPlan,
    schema: &QSignaturePlan,
) {
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
        target_index: ReceiveStagePlan::SIGNATURE_Q,
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
        assert!(!changed.accepts(), "changed Q1 public limb {index}");
    }
    let mut relabelled = fixture.clone();
    relabelled.target_index = 0;
    assert!(!relabelled.accepts(), "Q1 cannot be relabelled Q0");
    let mut crossed = fixture.clone();
    crossed.target = foreign.clone();
    assert!(
        !crossed.accepts(),
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
