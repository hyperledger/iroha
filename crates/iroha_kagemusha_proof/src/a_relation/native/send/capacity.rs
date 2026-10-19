//! Source-layout qualification only. Unknown witnesses create no Send.
//!
//! The predecessor key below supplies only the homogeneous metadata needed to
//! reconstruct Send layouts. It cannot authorize a production wallet or a payment.

use super::*;
use crate::{
    a_relation::QProofPlan,
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

fn original_plan(mask: u8) -> Plan {
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
    // Lean lineage: the only Q is the own-receipt signature leaf.
    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let signatures = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let circuit = QSignatureCircuit::new(
        signatures.clone(),
        vec![SignatureWitness {
            digest: Fp::ZERO,
            key: [[0; 4]; 2],
            signature: [[0; 4]; 2],
        }],
    )
    .unwrap()
    .without_witnesses();
    let key = keygen_pk_v2(
        &pallas,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let q = vec![
        QProofPlan::new(
            VerifierPlan::new(key.binding().clone(), pallas.clone()).unwrap(),
            key.vk().clone(),
        )
        .unwrap(),
    ];
    let operation = AProofPlan::inline(Variant::Send, q, Some(predecessor), &pallas).unwrap();
    Plan::new(
        operation,
        mask,
        policy,
        signatures,
        predecessor_key,
        pallas,
        vesta,
    )
    .unwrap()
}

fn rows<F: iroha_pasta::PastaField, C: Circuit<F>>(source: &C) -> usize {
    let assigned = synthesize(source, 16, None).unwrap();
    assigned
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|c| c.iter().rposition(|assigned| *assigned).map(|i| i + 1))
        .max()
        .unwrap()
}

#[test]
#[ignore = "lays out every installed mask's A1 at k16; run optimized explicitly"]
fn every_mask_inline_relation_stage_fits_k16() {
    for mask in 0..4 {
        let plan = original_plan(mask);
        assert_eq!(plan.context.stage_count(), A_STAGE_COUNT);
        let source = plan.source_circuit(0, None).unwrap();
        let a_rows = rows(&source);
        eprintln!(
            "lean Send mask{mask} A1 rows={a_rows} relation_permutations={}",
            plan.shape().permutations()
        );
        // The stand-in predecessor has no fixed, advice or permutation commitments, so
        // A1 here is a lower bound: the two-stage packing passed this check and then
        // overflowed production keygen. The real-Omega bound is the producer
        // compiler's `every_predecessor_stage_fits_k16_against_the_real_omega`.
        assert!(a_rows < 65_529, "mask{mask} A1 exceeds k16");
    }
}

#[test]
#[ignore = "imports all actual Send and wrapper source tables at k16 for masks 0 and 3; run optimized explicitly"]
fn three_a_two_w_original_sources_qualify_at_k16() {
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
    for mask in [0, 3] {
        let plan = original_plan(mask);
        assert!(plan.source_circuit(A_STAGE_COUNT, None).is_err());
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
            let a_rows = rows(&source);
            eprintln!("lean Send mask{mask} A{} rows={a_rows}", stage + 1);
            assert!(a_rows < 65_529);
            let key = keygen_pk_v2(&plan.vesta, &source, &a_config).unwrap();
            assert!(
                plan.wrapper_source(A_STAGE_COUNT - 1, key.binding(), key.vk())
                    .is_err()
            );
            if stage + 1 < A_STAGE_COUNT {
                let source = plan.wrapper_source(stage, key.binding(), key.vk()).unwrap();
                eprintln!("lean Send mask{mask} W{stage} rows={}", rows(&source));
                let (fixed, wrapper) = WKey::keygen(&source, &plan.pallas).unwrap();
                wrappers.push(fixed);
                w_keys.push(wrapper);
            }
            a_keys.push(key);
        }
        let original = |key: &iroha_plonk::ProvingKey<_>| Original {
            d: key.binding().encoded().to_vec(),
            v: key.vk().to_bytes().to_vec(),
            p: key.artifact_bytes_v2().unwrap(),
        };
        let a = a_keys.iter().map(original).collect::<Vec<_>>();
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
        assert_eq!(imported.descriptors().len(), 2 * A_STAGE_COUNT - 1);
        for stage in 0..A_STAGE_COUNT {
            let key_seal = imported.import_a(stage, &a[stage].p, config).unwrap();
            let key = imported.bind_a(stage, &key_seal, None).unwrap();
            assert_eq!(key.verifying_key().to_bytes(), a[stage].v);
            if stage < W_STAGE_COUNT {
                let key_seal = imported.import_w(stage, &w[stage].p, config).unwrap();
                let key = imported.bind_w(stage, &key_seal, None).unwrap();
                assert_eq!(key.verifying_key().to_bytes(), w[stage].v);
            }
        }
        assert!(imported.import_a(A_STAGE_COUNT, &a[0].p, config).is_err());
        assert!(imported.import_w(W_STAGE_COUNT, &w[0].p, config).is_err());
        // Each mask's keys fix its relation: another mask's A1 never imports.
        let other = Prover::from_artifacts(
            original_plan(mask ^ 1),
            core::array::from_fn(|i| a[i].metadata()),
            core::array::from_fn(|i| w[i].metadata()),
        )
        .unwrap();
        assert!(other.import_a(0, &a[0].p, config).is_err());
    }
}
