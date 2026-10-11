//! Fixed task/descriptor rejection tests; metadata keys never authorize lineage.

use super::*;
use crate::{
    a_relation::{AProofPlan, QProofPlan},
    q_sigma::{QSigmaPlan, SigmaClass},
};
use iroha_pasta::{Eq, Fq, PastaCurve, PastaField};
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
    let v = PinnedParams::<Eq>::derive(16).unwrap();
    let (leaf, _) = program(
        &PinnedParams::<Eq>::derive(12).unwrap(),
        vec![1],
        vec![InstanceType::Bounded],
    );
    let sigma = QSigmaPlan::new(
        SigmaClass::new(leaf, vec![(13, Fq::from(19))]).unwrap(),
        None,
        &v,
    )
    .unwrap();
    let (q, key) = program(
        &p,
        sigma.instance_lengths().to_vec(),
        QSigmaPlan::instance_types().to_vec(),
    );
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
    AProofPlan::new(
        variant,
        sigma,
        vec![
            QProofPlan::new(q, key).unwrap(),
            QProofPlan::new(signatures, signature_key).unwrap(),
        ],
        Some(omega),
        &p,
    )
    .unwrap()
}

fn tasks(variant: Variant) -> Vec<Vec<OperationTask>> {
    vec![
        vec![OperationTask::UnloadProof],
        vec![OperationTask::UnloadAuthorization],
        vec![if variant == Variant::Unload {
            OperationTask::UnloadRecovery
        } else {
            OperationTask::RetiringState
        }],
    ]
}

#[test]
fn unload_and_retiring_require_exact_own_authorization_and_proof_owners() {
    let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
    let schema = UnloadStagePlan::signature_schema(policy).unwrap();
    assert_eq!(schema.slots().len(), 3);
    assert_eq!(schema.slots()[0].key, SignatureKey::Variable);
    assert_eq!(schema.slots()[1].key, SignatureKey::Variable);
    assert_eq!(
        schema.slots()[2].key,
        SignatureKey::Fixed(Affine::GENERATOR)
    );
    assert!(
        schema
            .slots()
            .iter()
            .all(|slot| slot.mode == VerifyMode::Hard)
    );
    for variant in [Variant::Unload, Variant::Retiring] {
        let operation = operation(variant, schema.instance_length());
        let specs = UnloadObjects::context_specs().unwrap().to_vec();
        let context = |operation: AProofPlan, partition, owner, specs| {
            ContextPlan::with_schedule(operation, partition, owner, specs)
                .unwrap()
                .with_operation_tasks(tasks(variant))
                .unwrap()
        };
        let partition = vec![vec![0], vec![1], vec![]];
        let honest = context(operation.clone(), partition.clone(), Some(0), specs.clone());
        let plan = UnloadStagePlan::new(honest, policy).unwrap();
        assert_eq!(plan.context().stage_count(), 3);
        assert_eq!(plan.context().object_specs(), specs);
        assert_eq!(specs.iter().map(|s| s.tag).collect::<Vec<_>>(), [1, 2, 3]);
        for (spec, kind) in specs.iter().zip(KINDS) {
            assert_eq!(
                usize::try_from(spec.capacity).unwrap(),
                kind.body_len() + 64
            );
        }
        for mutation in 0..4 {
            let mut wrong = specs.clone();
            match mutation {
                0 => wrong[0].capacity += 1,
                1 => wrong.swap(0, 1),
                2 => {
                    wrong.pop();
                }
                _ => wrong[2].tag += 10,
            }
            assert!(
                UnloadStagePlan::new(
                    context(operation.clone(), partition.clone(), Some(0), wrong),
                    policy
                )
                .is_err()
            );
        }
        assert!(
            UnloadStagePlan::new(
                context(
                    operation.clone(),
                    vec![vec![1], vec![0], vec![]],
                    Some(0),
                    specs.clone()
                ),
                policy
            )
            .is_err()
        );
        assert!(
            UnloadStagePlan::new(
                context(operation.clone(), partition.clone(), Some(1), specs.clone()),
                policy
            )
            .is_err()
        );
        for index in 0..3 {
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
        vec![vec![0], vec![1], vec![]],
        Some(0),
        UnloadObjects::context_specs().unwrap().to_vec(),
    )
    .unwrap()
    .with_operation_tasks(tasks(Variant::Unload))
    .unwrap();
    assert!(UnloadStagePlan::new(context, policy).is_err());
}
