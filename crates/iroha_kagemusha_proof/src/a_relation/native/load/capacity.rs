//! Source-layout qualification only. Unknown witnesses create no funded Load.
//!
//! The predecessor key below supplies only the homogeneous metadata needed to
//! reconstruct Load layouts. It cannot authorize a production wallet or funding.

use super::*;
use crate::{
    a_relation::QProofPlan,
    admin_sigma::LoadCircuit,
    q_sigma::{QSigmaCircuit, QSigmaPlan, QSigmaWitness, SigmaClass, SigmaSlotWitness},
    q_signature::{QSignatureCircuit, SignatureSlot, SignatureWitness},
};
use iroha_plonk::{
    frontend::synthesize,
    keys::{KeygenConfigV2, keygen_pk_v2},
};
use iroha_plonk_gadgets::p256::native::Affine;
use iroha_plonk_recursion::verifier::VerifierPlan;

#[derive(Clone)]
struct PredecessorLayout;
impl Circuit<Fq> for PredecessorLayout {
    type Config = [Column<Instance>; 3];
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        [1, 2, 16].map(|length| meta.instance_column(length))
    }
    fn synthesize(&self, _: Self::Config, _: impl Layouter<Fq>) -> Result<(), LayoutError> {
        Ok(())
    }
}

fn original_plan() -> Plan {
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let predecessor = keygen_pk_v2(
        &pallas,
        &PredecessorLayout,
        &KeygenConfigV2::pipa_r(crate::omega::OmegaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let predecessor_key = predecessor.vk().clone();
    let predecessor = VerifierPlan::new(predecessor.binding().clone(), pallas.clone()).unwrap();
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
    };
    let sigma = LoadCircuit::new(&LoadWitness {
        predecessor: state,
        successor: state,
        statement: [Fp::ZERO; 26],
    })
    .without_witnesses();
    let sigma_params = PinnedParams::<Eq>::derive(12).unwrap();
    let sigma_key = keygen_pk_v2(
        &sigma_params,
        &sigma,
        &KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let class = SigmaClass::new(
        VerifierPlan::new(sigma_key.binding().clone(), sigma_params).unwrap(),
        vec![(
            super::super::super::schedule::sigma_selector(2, 0).unwrap(),
            sigma_key
                .vk()
                .kagemusha_digest(sigma_key.binding())
                .unwrap(),
        )],
    )
    .unwrap();
    let sigma_plan = QSigmaPlan::new(class, None, &vesta).unwrap();
    let length = sigma_plan.class(0).unwrap().verifier().proof_length();
    let q_sigma = QSigmaCircuit::new(
        sigma_plan.clone(),
        QSigmaWitness {
            own: SigmaSlotWitness {
                key: sigma_key.vk().clone(),
                statement: Fp::ZERO,
                proof: vec![0; length],
                length: u32::try_from(length).unwrap(),
            },
            incoming: None,
        },
    )
    .unwrap()
    .with_serialized_foreign(2)
    .unwrap()
    .without_witnesses();
    let sigma_q = keygen_pk_v2(
        &pallas,
        &q_sigma,
        &KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let mut q = vec![
        QProofPlan::new(
            VerifierPlan::new(sigma_q.binding().clone(), pallas.clone()).unwrap(),
            sigma_q.vk().clone(),
        )
        .unwrap(),
    ];
    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let signatures = [
        QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        }])
        .unwrap(),
        QSignaturePlan::new(vec![
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Variable,
            },
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Fixed(policy.root),
            },
        ])
        .unwrap(),
    ];
    for schema in &signatures {
        let circuit = QSignatureCircuit::new(
            schema.clone(),
            vec![
                SignatureWitness {
                    digest: Fp::ZERO,
                    key: [[0; 4]; 2],
                    signature: [[0; 4]; 2]
                };
                schema.slots().len()
            ],
        )
        .unwrap()
        .without_witnesses();
        let key = keygen_pk_v2(
            &pallas,
            &circuit,
            &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
        )
        .unwrap();
        q.push(
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), pallas.clone()).unwrap(),
                key.vk().clone(),
            )
            .unwrap(),
        );
    }
    let operation =
        AProofPlan::new(Variant::Load, sigma_plan, q, Some(predecessor), &pallas).unwrap();
    Plan::new(
        operation,
        policy,
        signatures,
        predecessor_key,
        pallas,
        vesta,
    )
    .unwrap()
}

#[test]
#[ignore = "imports all actual Load and wrapper source tables at k16; run optimized explicitly"]
fn four_a_three_w_original_sources_qualify_at_k16() {
    struct Original {
        d: Vec<u8>,
        v: Vec<u8>,
        p: Vec<u8>,
    }
    impl Original {
        fn metadata<C: iroha_pasta::PastaCurve>(&self) -> KeyArtifact<C> {
            let binding = DescriptorBinding::decode_v2(&self.d).unwrap();
            let key = VerifyingKey::read(&self.v, &binding).unwrap();
            KeyArtifact::new(binding, key).unwrap()
        }
    }
    let plan = original_plan();
    assert_eq!(plan.context.stage_count(), 4);
    assert!(plan.source_circuit(A_STAGE_COUNT, None).is_err());
    assert!(plan.source_circuit(usize::MAX, None).is_err());
    assert!(plan.source_circuit(1, None).is_err());
    let mut wrappers: Vec<WKey> = Vec::new();
    let mut a_keys = Vec::new();
    let mut w_keys = Vec::new();
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    for stage in 0..A_STAGE_COUNT {
        let source = plan
            .source_circuit(
                stage,
                stage
                    .checked_sub(1)
                    .map(|previous| wrappers[previous].clone()),
            )
            .unwrap();
        let assigned = synthesize(&source, 16, None).unwrap();
        let rows = assigned
            .tables
            .advice_assigned()
            .iter()
            .filter_map(|c| c.iter().rposition(|assigned| *assigned).map(|i| i + 1))
            .max()
            .unwrap();
        eprintln!("ordinary Load A{} rows={rows}", stage + 1);
        assert!(rows < (1 << 16));
        drop(assigned);
        let key = keygen_pk_v2(&plan.vesta, &source, &a_config).unwrap();
        assert!(
            plan.wrapper_source(A_STAGE_COUNT - 1, key.binding(), key.vk())
                .is_err()
        );
        assert!(
            plan.wrapper_source(usize::MAX, key.binding(), key.vk())
                .is_err()
        );
        if let Some(previous) = wrappers.last() {
            assert!(plan.source_circuit(0, Some(previous.clone())).is_err());
        }
        if stage + 1 < A_STAGE_COUNT {
            let source = plan.wrapper_source(stage, key.binding(), key.vk()).unwrap();
            let (fixed, wrapper) = WKey::keygen(&source, &plan.pallas).unwrap();
            wrappers.push(fixed);
            w_keys.push(wrapper);
        }
        a_keys.push(key);
    }
    let a = a_keys
        .iter()
        .map(|key| Original {
            d: key.binding().encoded().to_vec(),
            v: key.vk().to_bytes().to_vec(),
            p: key.artifact_bytes_v2().unwrap(),
        })
        .collect::<Vec<_>>();
    let w = w_keys
        .iter()
        .map(|key| Original {
            d: key.binding().encoded().to_vec(),
            v: key.vk().to_bytes().to_vec(),
            p: key.artifact_bytes_v2().unwrap(),
        })
        .collect::<Vec<_>>();
    drop((a_keys, w_keys));
    let config = ReadConfig {
        maximum_bytes: a.iter().chain(&w).map(|o| o.p.len()).max().unwrap(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let imported = Prover::from_artifacts(
        plan.clone(),
        core::array::from_fn(|i| a[i].metadata()),
        core::array::from_fn(|i| w[i].metadata()),
    )
    .unwrap();
    let descriptors = imported.descriptors();
    assert_eq!(descriptors.len(), 7);
    // The exported order must retain each exact installed owner, including stages whose
    // descriptors have equal bytes, and finish at A4 without a trailing wrapper.
    for (stage, original) in a.iter().enumerate() {
        assert!(core::ptr::eq(
            descriptors[2 * stage],
            imported.a[stage].binding(),
        ));
        assert_eq!(descriptors[2 * stage].encoded(), original.d.as_slice());
        if let Some(wrapper) = w.get(stage) {
            assert!(core::ptr::eq(
                descriptors[2 * stage + 1],
                imported.w[stage].binding(),
            ));
            assert_eq!(descriptors[2 * stage + 1].encoded(), wrapper.d.as_slice());
        }
    }
    assert_eq!(imported.plan().context().schema(), plan.context().schema());
    for stage in 0..A_STAGE_COUNT {
        let key_seal = imported.import_a(stage, &a[stage].p, config).unwrap();
        let key = imported.bind_a(stage, &key_seal, None).unwrap();
        assert_eq!(key.verifying_key().to_bytes(), a[stage].v);
        drop(key_seal);
        if stage < A_STAGE_COUNT - 1 {
            let key_seal = imported.import_w(stage, &w[stage].p, config).unwrap();
            let key = imported.bind_w(stage, &key_seal, None).unwrap();
            assert_eq!(key.verifying_key().to_bytes(), w[stage].v);
            drop(key_seal);
        }
    }
    assert!(imported.import_a(A_STAGE_COUNT, &a[0].p, config).is_err());
    assert!(
        imported
            .import_w(A_STAGE_COUNT - 1, &w[0].p, config)
            .is_err()
    );
    assert!(imported.import_a(1, &a[0].p, config).is_err());
    assert!(imported.import_w(1, &w[0].p, config).is_err());
    let mut changed = plan;
    changed.policy.provider[0] ^= 1;
    let changed = Prover::from_artifacts(
        changed,
        core::array::from_fn(|i| a[i].metadata()),
        core::array::from_fn(|i| w[i].metadata()),
    )
    .unwrap();
    // Metadata can describe originals, but only source reconstruction can qualify them.
    assert!(changed.import_a(2, &a[2].p, config).is_err());
}
