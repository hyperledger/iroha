//! Bootstrap plan admission and witnessless source ownership.
//!
//! Constructor-only metadata keys exercise the fixed unsplit plan shape and
//! source clones, not an admitted Bootstrap operation or proof.
use super::*;
use crate::{
    a_relation::QProofPlan,
    q_sigma::{QSigmaPlan, SigmaClass},
    q_signature::SignatureSlot,
};
use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::InstanceType,
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
};
use iroha_plonk_gadgets::p256::native::Affine;
use std::marker::PhantomData;

#[derive(Clone)]
struct Metadata<F>(Vec<usize>, PhantomData<F>);
impl<F: PastaField> Circuit<F> for Metadata<F> {
    type Config = ();
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;

    fn params(&self) -> Self::Params {
        self.0.clone()
    }
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) {
        Self::configure_with_params(meta, vec![1]);
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, lengths: Vec<usize>) {
        for length in lengths {
            meta.instance_column(length);
        }
    }
    fn synthesize(&self, (): (), _: impl Layouter<F>) -> Result<(), LayoutError> {
        Ok(())
    }
}

fn signatures(mode: VerifyMode) -> QSignaturePlan {
    QSignaturePlan::new(
        [
            SignatureKey::Variable,
            SignatureKey::Variable,
            SignatureKey::Fixed(Affine::GENERATOR),
        ]
        .into_iter()
        .map(|key| SignatureSlot { mode, key })
        .collect(),
    )
    .unwrap()
}

fn q_plan(pallas: &PinnedParams<Ep>, lengths: Vec<usize>, types: Vec<InstanceType>) -> QProofPlan {
    let (binding, key) = keygen_vk_with_binding_v2(
        pallas,
        &Metadata::<Fq>(lengths, PhantomData),
        &KeygenConfigV2::pipa_r(types),
    )
    .unwrap();
    QProofPlan::new(
        iroha_plonk_recursion::verifier::VerifierPlan::new(binding, pallas.clone()).unwrap(),
        key,
    )
    .unwrap()
}

fn signature_q(pallas: &PinnedParams<Ep>) -> QProofPlan {
    q_plan(
        pallas,
        vec![signatures(VerifyMode::Hard).instance_length()],
        QSignaturePlan::instance_types().to_vec(),
    )
}

fn plan() -> Arc<Plan> {
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let operation = AProofPlan::inline(
        Variant::Bootstrap,
        vec![signature_q(&pallas)],
        None,
        &pallas,
    )
    .unwrap();
    Arc::new(
        Plan::new(
            operation,
            BootstrapPolicy::new([1, 0], Affine::GENERATOR).unwrap(),
            signatures(VerifyMode::Hard),
            pallas,
            vesta,
        )
        .unwrap(),
    )
}

#[test]
fn witnessless_source_clone_shares_plan_and_originals_without_known_values() {
    let plan = plan();
    let mut live = StageCircuit::blank(plan.clone()).unwrap();
    live.known = true;
    let source = live.without_witnesses();
    assert!(!source.known);
    assert!(Arc::ptr_eq(&source.plan, &live.plan));
    assert!(Arc::ptr_eq(&source.original, &live.original));
    drop(source);
    assert!(live.known);
    // The installation factory reconstructs the same dimensions from the plan alone.
    let factory = plan.source_circuit().unwrap();
    assert!(!factory.known);
    let fixed = plan.context().operation().q(0).unwrap();
    assert_eq!(
        factory.original.q[0].proof.len(),
        fixed.verifier().proof_length()
    );
    assert_eq!(
        factory.original.q[0].instances,
        vec![vec![
            Fq::ZERO;
            signatures(VerifyMode::Hard).instance_length()
        ]]
    );
    assert_eq!(plan.context().stage_count(), 1);
}

#[test]
fn plan_admits_only_the_unsplit_single_signature_q_bootstrap() {
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let policy = BootstrapPolicy::new([1, 0], Affine::GENERATOR).unwrap();
    let q = signature_q(&pallas);
    let inline =
        |q: Vec<QProofPlan>| AProofPlan::inline(Variant::Bootstrap, q, None, &pallas).unwrap();
    let admit = |operation, signatures, pallas: &PinnedParams<Ep>| {
        Plan::new(operation, policy, signatures, pallas.clone(), vesta.clone()).err()
    };
    assert_eq!(
        admit(
            inline(vec![q.clone()]),
            signatures(VerifyMode::Hard),
            &pallas
        ),
        None
    );
    // A second Q leaf is not the fixed one-leaf Bootstrap schedule.
    assert_eq!(
        admit(
            inline(vec![q.clone(), q.clone()]),
            signatures(VerifyMode::Hard),
            &pallas
        ),
        Some(Error::Artifact)
    );
    // Every slot stays hard, including the root-fixed certificate.
    assert_eq!(
        admit(
            inline(vec![q.clone()]),
            signatures(VerifyMode::Soft),
            &pallas
        ),
        Some(Error::Artifact)
    );
    // The single Q's public column must be exactly the slot schema.
    let short = q_plan(
        &pallas,
        vec![signatures(VerifyMode::Hard).instance_length() - 1],
        QSignaturePlan::instance_types().to_vec(),
    );
    assert_eq!(
        admit(inline(vec![short]), signatures(VerifyMode::Hard), &pallas),
        Some(Error::Artifact)
    );
    // Only k16 pinned parameters are admitted.
    assert_eq!(
        admit(
            inline(vec![q.clone()]),
            signatures(VerifyMode::Hard),
            &PinnedParams::<Ep>::derive(4).unwrap()
        ),
        Some(Error::Artifact)
    );
    // The retired own-sigma verifier cannot be reinstated on Bootstrap's route.
    let sigma_params = PinnedParams::<Eq>::derive(crate::admin_sigma::BOOTSTRAP_K).unwrap();
    let (binding, key) = keygen_vk_with_binding_v2(
        &sigma_params,
        &Metadata::<Fp>(vec![1], PhantomData),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
    )
    .unwrap();
    let digest = key.kagemusha_digest(&binding).unwrap();
    let sigma = QSigmaPlan::new(
        SigmaClass::new(
            iroha_plonk_recursion::verifier::VerifierPlan::new(binding, sigma_params).unwrap(),
            vec![(0, digest)],
        )
        .unwrap(),
        None,
        &vesta,
    )
    .unwrap();
    let sigma_q = q_plan(
        &pallas,
        sigma.instance_lengths().to_vec(),
        QSigmaPlan::instance_types().to_vec(),
    );
    let own = AProofPlan::new(Variant::Bootstrap, sigma, vec![sigma_q, q], None, &pallas).unwrap();
    assert_eq!(
        admit(own, signatures(VerifyMode::Hard), &pallas),
        Some(Error::Artifact)
    );
}

#[test]
fn preparation_refuses_changed_original_extents_before_any_proof() {
    let plan = plan();
    let blank = plan.source_circuit().unwrap();
    for index in 0..3 {
        let mut changed = (*blank.original).clone();
        changed.objects[index].pop();
        assert_eq!(
            plan.prepare(changed, MemoryBudget::DEFAULT).err(),
            Some(Error::Input),
            "object {index}"
        );
        let mut changed = (*blank.original).clone();
        changed.objects[index].push(0);
        assert_eq!(
            plan.prepare(changed, MemoryBudget::DEFAULT).err(),
            Some(Error::Input),
            "object {index}"
        );
    }
}
