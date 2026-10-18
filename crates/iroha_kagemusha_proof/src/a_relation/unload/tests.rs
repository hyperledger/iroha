//! Fixed task/descriptor rejection tests; metadata keys never authorize lineage.

use super::*;
use crate::a_relation::{AProofPlan, QProofPlan};
use iroha_pasta::{PastaCurve, PastaField};
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::p256::native::Affine;
use iroha_plonk_recursion::verifier::VerifierPlan;
use std::marker::PhantomData;

// These empty programs supply only declared descriptor shapes to rejection
// tests. They are never used for proofs, operation execution or key admission.
#[derive(Clone)]
struct Metadata<F: PastaField> {
    lengths: Vec<usize>,
    marker: PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Metadata<F> {
    type Config = Vec<Column<Instance>>;
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> Self::Params {
        self.lengths.clone()
    }
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        Vec::new()
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        lengths: Self::Params,
    ) -> Self::Config {
        lengths
            .into_iter()
            .map(|n| meta.instance_column(n))
            .collect()
    }
    fn synthesize(&self, _: Self::Config, _: impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

fn program<C: PastaCurve>(
    params: &PinnedParams<C>,
    lengths: Vec<usize>,
    types: Vec<InstanceType>,
) -> (VerifierPlan<C>, iroha_plonk::VerifyingKey<C>) {
    let (binding, key) = keygen_vk_with_binding_v2(
        params,
        &Metadata {
            lengths,
            marker: PhantomData,
        },
        &KeygenConfigV2::pipa_r(types),
    )
    .unwrap();
    (VerifierPlan::new(binding, params.clone()).unwrap(), key)
}

fn operation(variant: Variant, signature_words: usize) -> AProofPlan {
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let (signatures, signature_key) = program(
        &p,
        vec![signature_words],
        QSignaturePlan::instance_types().to_vec(),
    );
    let (omega, _) = program(
        &p,
        vec![1, 2, 16],
        vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ],
    );
    // Lean lineage: no own sigma verifier; the only Q is the own receipt.
    AProofPlan::inline(
        variant,
        vec![QProofPlan::new(signatures, signature_key).unwrap()],
        Some(omega),
        &p,
    )
    .unwrap()
}

fn tasks(variant: Variant) -> Vec<Vec<OperationTask>> {
    vec![
        vec![if variant == Variant::Unload {
            OperationTask::UnloadRecovery
        } else {
            OperationTask::RetiringState
        }],
        vec![OperationTask::UnloadAuthorization],
    ]
}

#[test]
fn unload_and_retiring_require_exact_lean_owner_and_one_own_receipt() {
    let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
    let schema = UnloadStagePlan::signature_schema().unwrap();
    assert_eq!(schema.slots().len(), 1);
    assert_eq!(schema.slots()[0].key, SignatureKey::Variable);
    assert_eq!(schema.slots()[0].mode, VerifyMode::Hard);
    for variant in [Variant::Unload, Variant::Retiring] {
        let operation = operation(variant, schema.instance_length());
        assert!(operation.is_inline());
        let specs = UnloadObjects::context_specs().unwrap().to_vec();
        let context = |operation: AProofPlan, partition, owner, specs| {
            ContextPlan::with_schedule(operation, partition, owner, specs)
                .unwrap()
                .with_operation_tasks(tasks(variant))
                .unwrap()
        };
        let partition = vec![vec![], vec![0]];
        let honest = context(operation.clone(), partition.clone(), Some(0), specs.clone());
        let plan = UnloadStagePlan::new(honest, policy).unwrap();
        assert_eq!(plan.context().stage_count(), 2);
        assert_eq!(plan.context().object_specs(), specs);
        assert_eq!(specs.iter().map(|s| s.tag).collect::<Vec<_>>(), [1]);
        for (spec, kind) in specs.iter().zip(KINDS) {
            assert_eq!(kind, ObjectKind::Receipt);
            assert_eq!(
                usize::try_from(spec.capacity).unwrap(),
                kind.body_len() + 64
            );
        }
        for mutation in 0..4 {
            let mut wrong = specs.clone();
            match mutation {
                0 => wrong[0].capacity += 1,
                1 => wrong[0].tag += 10,
                2 => {
                    wrong.pop();
                }
                _ => wrong.push(specs[0]),
            }
            assert!(
                ContextPlan::with_schedule(operation.clone(), partition.clone(), Some(0), wrong)
                    .and_then(|c| c.with_operation_tasks(tasks(variant)))
                    .map_or(true, |c| UnloadStagePlan::new(c, policy).is_err())
            );
        }
        // The own receipt leaf belongs to A2, never beside the predecessor in A1.
        assert!(
            UnloadStagePlan::new(
                context(
                    operation.clone(),
                    vec![vec![0], vec![]],
                    Some(0),
                    specs.clone()
                ),
                policy
            )
            .is_err()
        );
        // A1 owns no Q, so the hard predecessor must be verified there.
        assert!(
            ContextPlan::with_schedule(
                operation.clone(),
                partition.clone(),
                Some(1),
                specs.clone()
            )
            .is_err()
        );
        for index in 0..2 {
            let mut missing = tasks(variant);
            missing[index].clear();
            assert!(
                ContextPlan::with_schedule(
                    operation.clone(),
                    partition.clone(),
                    Some(0),
                    specs.clone()
                )
                .unwrap()
                .with_operation_tasks(missing)
                .is_err()
            );
            let mut repeated = tasks(variant);
            let duplicate = repeated[index][0];
            repeated[index].push(duplicate);
            assert!(
                ContextPlan::with_schedule(
                    operation.clone(),
                    partition.clone(),
                    Some(0),
                    specs.clone()
                )
                .unwrap()
                .with_operation_tasks(repeated)
                .is_err()
            );
        }
        // Swapped stage owners keep the task set but not the fixed layout.
        let mut swapped = tasks(variant);
        swapped.swap(0, 1);
        assert!(
            ContextPlan::with_schedule(
                operation.clone(),
                partition.clone(),
                Some(0),
                specs.clone()
            )
            .unwrap()
            .with_operation_tasks(swapped)
            .map_or(true, |c| UnloadStagePlan::new(c, policy).is_err())
        );
        let wrong_effect = if variant == Variant::Unload {
            Variant::Retiring
        } else {
            Variant::Unload
        };
        assert!(
            ContextPlan::with_schedule(
                operation.clone(),
                partition.clone(),
                Some(0),
                specs.clone()
            )
            .unwrap()
            .with_operation_tasks(tasks(wrong_effect))
            .is_err()
        );
    }
    let wrong = operation(Variant::Unload, schema.instance_length() - 1);
    let context = ContextPlan::with_schedule(
        wrong,
        vec![vec![], vec![0]],
        Some(0),
        UnloadObjects::context_specs().unwrap().to_vec(),
    )
    .unwrap()
    .with_operation_tasks(tasks(Variant::Unload))
    .unwrap();
    assert!(UnloadStagePlan::new(context, policy).is_err());
}
