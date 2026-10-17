//! Bootstrap source clones release their private fold allocation.
//!
//! Constructor-only metadata keys and marked bytes exercise ownership, not an
//! admitted Bootstrap operation, proof, or physical memory-erasure guarantee.
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

fn plan_and_wrapper() -> (Arc<Plan>, WKey) {
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
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
    let root = iroha_plonk_gadgets::p256::native::Affine::GENERATOR;
    let signatures = QSignaturePlan::new(
        [
            SignatureKey::Variable,
            SignatureKey::Variable,
            SignatureKey::Fixed(root),
        ]
        .into_iter()
        .map(|key| SignatureSlot {
            mode: VerifyMode::Hard,
            key,
        })
        .collect(),
    )
    .unwrap();
    let mut q = Vec::new();
    for (lengths, types) in [
        (
            sigma.instance_lengths().to_vec(),
            QSigmaPlan::instance_types().to_vec(),
        ),
        (
            vec![signatures.instance_length()],
            QSignaturePlan::instance_types().to_vec(),
        ),
    ] {
        let (binding, key) = keygen_vk_with_binding_v2(
            &pallas,
            &Metadata::<Fq>(lengths, PhantomData),
            &KeygenConfigV2::pipa_r(types),
        )
        .unwrap();
        q.push(
            QProofPlan::new(
                iroha_plonk_recursion::verifier::VerifierPlan::new(binding, pallas.clone())
                    .unwrap(),
                key,
            )
            .unwrap(),
        );
    }
    let operation = AProofPlan::new(Variant::Bootstrap, sigma, q, None, &pallas).unwrap();
    let plan = Arc::new(
        Plan::new(
            operation,
            BootstrapPolicy::new([1, 0], root).unwrap(),
            signatures,
            pallas.clone(),
            vesta,
        )
        .unwrap(),
    );
    let (binding, key) = keygen_vk_with_binding_v2(
        &pallas,
        &Metadata::<Fq>(vec![1, 2, 16], PhantomData),
        &KeygenConfigV2::pipa_r(crate::omega::OmegaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let wrapper = WKey::from_artifact(plan.context(), 0, binding, pallas, key).unwrap();
    (plan, wrapper)
}

#[test]
fn witnessless_terminal_clone_releases_private_fold_without_changing_live_owner() {
    let (plan, wrapper) = plan_and_wrapper();
    let mut live = StageCircuit::blank_terminal(plan.clone(), &wrapper).unwrap();
    let marked = crate::private_fold::PrivateFoldBytes::from_owned(
        iroha_plonk_recursion::PrivateWitnessBytes::try_write::<std::io::Error>(
            iroha_plonk_recursion::FOLD_WITNESS_BYTES,
            |writer| writer.write_all(&[0xa5; iroha_plonk_recursion::FOLD_WITNESS_BYTES]),
        )
        .unwrap(),
    );
    live.known = true;
    let Stage::Last(last) = &mut live.stage else {
        panic!("terminal source");
    };
    last.fold = marked.clone();
    let source = live.without_witnesses();
    assert!(!source.known);
    assert!(Arc::ptr_eq(&source.plan, &live.plan));
    assert!(Arc::ptr_eq(&source.original, &live.original));
    assert!(source.carried.is_none());
    let Stage::Last(source_last) = &source.stage else {
        panic!("terminal preserved");
    };
    let Stage::Last(live_last) = &live.stage else {
        panic!("live terminal preserved");
    };
    assert_eq!(source_last.proof, live_last.proof);
    assert_eq!(source_last.vesta, live_last.vesta);
    assert_eq!(
        source_last.fold.len(),
        iroha_plonk_recursion::FOLD_WITNESS_BYTES
    );
    assert!(source_last.fold.iter().all(|byte| *byte == 0));
    assert_ne!(
        source_last.fold.as_slice().as_ptr(),
        marked.as_slice().as_ptr()
    );
    assert_eq!(
        live_last.fold.as_slice().as_ptr(),
        marked.as_slice().as_ptr()
    );
    assert!(live_last.fold.iter().all(|byte| *byte == 0xa5));
    drop(source);
    assert!(live.known);
    assert_eq!(marked[0], 0xa5);

    let mut first = StageCircuit::blank(plan, Stage::First).unwrap();
    first.known = true;
    let first_source = first.without_witnesses();
    assert!(!first_source.known);
    assert!(matches!(first_source.stage, Stage::First));
    assert!(first.known);
}
