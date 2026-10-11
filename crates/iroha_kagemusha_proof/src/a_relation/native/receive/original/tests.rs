//! Unknown source and sequential original-key intake; no metadata fixture is admitted.

use super::*;
use crate::{q_sigma::SigmaClass, q_signature::QSignaturePlan};
use core::marker::PhantomData;
use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::ConstraintSystem,
    frontend::{Error as CircuitError, Layouter, SimpleFloorPlanner, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
};
use iroha_plonk_gadgets::p256::native::Affine;

// Constructor-only columns: no proofs from these keys certify an operation.
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
    fn synthesize(&self, (): (), _: impl Layouter<F>) -> Result<(), CircuitError> {
        Ok(())
    }
}

fn plan(variant: Variant) -> Plan {
    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = PinnedParams::<Eq>::derive(16).unwrap();
    let sigma_class = |k, selector| {
        let params = PinnedParams::<Eq>::derive(k).unwrap();
        let (binding, key) = keygen_vk_with_binding_v2(
            &params,
            &Metadata::<Fp>(vec![1], PhantomData),
            &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
        )
        .unwrap();
        let digest = key.kagemusha_digest(&binding).unwrap();
        SigmaClass::new(
            VerifierPlan::new(binding, params).unwrap(),
            vec![(selector, digest)],
        )
        .unwrap()
    };
    let sigma = QSigmaPlan::new(sigma_class(12, 10), Some(sigma_class(14, 2)), &v).unwrap();
    let signatures = ReceiveStagePlan::signature_schemas(variant, policy).unwrap();
    let mut q = Vec::new();
    for (lengths, types) in std::iter::once((
        sigma.instance_lengths().to_vec(),
        QSigmaPlan::instance_types().to_vec(),
    ))
    .chain(signatures.iter().map(|schema| {
        (
            vec![schema.instance_length()],
            QSignaturePlan::instance_types().to_vec(),
        )
    })) {
        let (binding, key) = keygen_vk_with_binding_v2(
            &p,
            &Metadata::<Fq>(lengths, PhantomData),
            &KeygenConfigV2::pipa_r(types),
        )
        .unwrap();
        q.push(QProofPlan::new(VerifierPlan::new(binding, p.clone()).unwrap(), key).unwrap());
    }
    let (binding, key) = keygen_vk_with_binding_v2(
        &p,
        &Metadata::<Fq>(vec![1, 2, 16], PhantomData),
        &KeygenConfigV2::pipa_r(vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]),
    )
    .unwrap();
    let omega = VerifierPlan::new(binding, p.clone()).unwrap();
    let operation = AProofPlan::new(variant, sigma, q, Some(omega), &p).unwrap();
    Plan::new(operation, policy, key, p, v).unwrap()
}

#[test]
fn original_bounds_reject_empty_oversized_and_over_domain_inputs() {
    let read = ReadConfig {
        maximum_bytes: 16,
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    assert_eq!(original_bounds(&[], 1 << 16, read), Err(Error::Artifact));
    assert_eq!(
        original_bounds(&[0; 17], 1 << 16, read),
        Err(Error::Artifact)
    );
    assert_eq!(
        original_bounds(&[0; 16], (1 << 16) + 1, read),
        Err(Error::Artifact)
    );
    assert_eq!(original_bounds(&[0; 16], 1 << 16, read), Ok(()));
}

#[test]
fn source_factory_pins_full_domains_and_never_exposes_an_accepted_witness() {
    for variant in [Variant::Receive, Variant::ReceiveRenewed] {
        let plan = plan(variant);
        assert!(plan.source_circuit(1, None).is_err());
        assert!(plan.source_circuit(A_STAGE_COUNT, None).is_err());
        let source = plan.source_circuit(0, None).unwrap();
        assert!(!source.inner.known);
        assert_eq!(source.params(), INTERNAL_RANGE_BUSES);
        let value = &source.inner.source;
        assert_eq!(value.variant, variant);
        assert_eq!(value.plan.context().stage_count(), A_STAGE_COUNT);
        assert_eq!(
            value.plan.context().object_specs()[4].capacity as usize,
            MAX_OMEGA_RAW_BYTES
        );
        assert_eq!(
            value.plan.context().object_specs()[5].capacity as usize,
            MAX_SIGMA_RAW_BYTES
        );
        assert_eq!(value.commitments.len(), 11);
        assert_eq!(
            value.own.sigma.len(),
            plan.context()
                .operation()
                .sigma
                .class(0)
                .unwrap()
                .verifier()
                .proof_length()
        );
        assert_eq!(value.q.len(), 3);
        for (index, q) in value.q.iter().enumerate() {
            let fixed = plan.context().operation().q(index).unwrap().verifier();
            assert_eq!(q.proof.len(), fixed.proof_length());
            assert_eq!(
                q.instances.iter().map(Vec::len).collect::<Vec<_>>(),
                fixed
                    .binding()
                    .descriptor()
                    .instance_lengths
                    .iter()
                    .map(|n| usize::try_from(*n).unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }
}

fn sequential_imports(variant: Variant) {
    let plan = plan(variant);
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let mut w_config = KeygenConfigV2::pipa_r(crate::omega::OmegaPlan::instance_types().to_vec());
    w_config.compress_selectors = false;
    let wrapper_source = |stage: usize, a: &KeyArtifact<Eq>| {
        let length = Protocol::new(a.binding().descriptor())
            .unwrap()
            .proof_length();
        WCircuit::new(
            plan.context(),
            stage,
            a.binding().clone(),
            plan.vesta.clone(),
            vec![a.key().kagemusha_digest(a.binding()).unwrap()],
            OmegaWitness {
                key: a.key().clone(),
                instances: vec![Fp::ZERO; 69],
                proof: vec![0; length],
                length: u32::try_from(length).unwrap(),
                fold: [0; 1120],
            },
        )
        .unwrap()
        .without_witnesses()
    };
    let mut a = Vec::new();
    let mut w = Vec::new();
    let mut wrappers = Vec::new();
    for stage in 0..A_STAGE_COUNT {
        let source = plan
            .source_circuit(stage, wrappers.last().cloned())
            .unwrap();
        assert_eq!(
            source.params(),
            if stage + 1 == A_STAGE_COUNT {
                TERMINAL_RANGE_BUSES
            } else {
                INTERNAL_RANGE_BUSES
            }
        );
        let layout = synthesize(&source, 16, None).unwrap();
        let repeat = synthesize(&source.without_witnesses(), 16, None).unwrap();
        assert_eq!(layout.tables.fixed(), repeat.tables.fixed());
        assert_eq!(layout.tables.permutation(), repeat.tables.permutation());
        assert_eq!(
            layout.tables.advice_assigned(),
            repeat.tables.advice_assigned()
        );
        let rows = layout
            .tables
            .advice_assigned()
            .iter()
            .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .max()
            .unwrap();
        eprintln!(
            "RECEIVE_UNKNOWN_SOURCE variant={variant:?} stage={stage} max_rows={rows} constructor_Q_metadata=true real_workload_qualification=false"
        );
        drop((layout, repeat));
        let (binding, key) = keygen_vk_with_binding_v2(&plan.vesta, &source, &a_config).unwrap();
        let artifact = KeyArtifact::new(binding, key).unwrap();
        if stage < W_STAGE_COUNT {
            let source = wrapper_source(stage, &artifact);
            let (binding, key) =
                keygen_vk_with_binding_v2(&plan.pallas, &source, &w_config).unwrap();
            wrappers.push(
                WKey::from_artifact(
                    plan.context(),
                    stage,
                    binding.clone(),
                    plan.pallas.clone(),
                    key.clone(),
                )
                .unwrap(),
            );
            w.push(KeyArtifact::new(binding, key).unwrap());
        }
        a.push(artifact);
    }
    assert!(plan.source_circuit(0, Some(wrappers[0].clone())).is_err());
    assert!(plan.source_circuit(2, Some(wrappers[0].clone())).is_err());
    let prover = Prover::from_artifacts(
        plan.clone(),
        a.clone().try_into().unwrap(),
        w.try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(prover.checkpoint_layouts().unwrap().len(), 19);
    for stage in 0..A_STAGE_COUNT {
        let source = plan
            .source_circuit(stage, stage.checked_sub(1).map(|i| wrappers[i].clone()))
            .unwrap();
        let pk = keygen_pk_v2(&plan.vesta, &source, &a_config).unwrap();
        assert_eq!(pk.vk().to_bytes(), a[stage].key().to_bytes());
        let original = pk.artifact_bytes_v2().unwrap();
        drop(pk);
        let read = ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        assert!(
            prover
                .import_a(stage, &original[..original.len() - 1], read)
                .is_err()
        );
        assert!(
            prover
                .import_a((stage + 1) % A_STAGE_COUNT, &original, read)
                .is_err()
        );
        let imported_seal = prover.import_a(stage, &original, read).unwrap();
        let imported = prover.bind_a(stage, &imported_seal, None).unwrap();
        assert_eq!(
            imported.verifying_key().to_bytes(),
            a[stage].key().to_bytes()
        );
        drop((imported, original));
        if stage < W_STAGE_COUNT {
            let pk =
                keygen_pk_v2(&plan.pallas, &wrapper_source(stage, &a[stage]), &w_config).unwrap();
            let original = pk.artifact_bytes_v2().unwrap();
            drop(pk);
            let read = ReadConfig {
                maximum_bytes: original.len(),
                ..read
            };
            assert!(
                prover
                    .import_w(stage, &original[..original.len() - 1], read)
                    .is_err()
            );
            assert!(
                prover
                    .import_w((stage + 1) % W_STAGE_COUNT, &original, read)
                    .is_err()
            );
            let imported_seal = prover.import_w(stage, &original, read).unwrap();
            let imported = prover.bind_w(stage, &imported_seal, None).unwrap();
            assert_eq!(
                imported.verifying_key().to_bytes(),
                wrappers[stage].verifying_key().to_bytes()
            );
        }
    }
}

#[test]
#[ignore = "sequential full source/import sweep with constructor Q metadata; no real proof qualification"]
fn ordinary_receive_imports_every_fixed_original_source() {
    sequential_imports(Variant::Receive);
}

#[test]
#[ignore = "sequential full source/import sweep with constructor Q metadata; no real proof qualification"]
fn renewed_receive_imports_every_fixed_original_source() {
    sequential_imports(Variant::ReceiveRenewed);
}

#[path = "source_capacity.rs"]
mod source_capacity;
