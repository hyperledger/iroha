//! Source-layout qualification only. Unknown witnesses create no Unload or Retiring.
//!
//! The predecessor and signature Q keys below supply only the homogeneous metadata
//! needed to reconstruct the one-stage consuming layouts. They cannot authorize a
//! production wallet, an Omega catalog or a payout.

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

fn original_plan(variant: Variant) -> Plan {
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
    let signatures = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let circuit = QSignatureCircuit::new(
        signatures.clone(),
        vec![
            SignatureWitness {
                digest: Fp::ZERO,
                key: [[0; 4]; 2],
                signature: [[0; 4]; 2]
            };
            signatures.slots().len()
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
    let q = QProofPlan::new(
        VerifierPlan::new(key.binding().clone(), pallas.clone()).unwrap(),
        key.vk().clone(),
    )
    .unwrap();
    // Lean lineage: one terminal A over the hard predecessor and the single Q.
    let operation = AProofPlan::inline(variant, vec![q], Some(predecessor), &pallas).unwrap();
    Plan::new(
        operation,
        OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap(),
        signatures,
        predecessor_key,
        pallas,
        vesta,
    )
    .unwrap()
}

struct Original {
    descriptor: Vec<u8>,
    verifying_key: Vec<u8>,
    proving_key: Vec<u8>,
}
impl Original {
    fn metadata(&self) -> KeyArtifact<Eq> {
        let binding = DescriptorBinding::decode_v2(&self.descriptor).unwrap();
        let key = VerifyingKey::read(&self.verifying_key, &binding).unwrap();
        KeyArtifact::new(binding, key).unwrap()
    }
}

#[test]
#[ignore = "imports the actual one-stage Unload and Retiring A source tables at k16; run optimized explicitly"]
fn one_terminal_original_sources_qualify_at_k16() {
    let mut installed = Vec::new();
    for variant in [Variant::Unload, Variant::Retiring] {
        let plan = original_plan(variant);
        assert_eq!(plan.context().stage_count(), A_STAGE_COUNT);
        let source = plan.source_circuit().unwrap();
        let assigned = synthesize(&source, 16, None).unwrap();
        let rows = assigned
            .tables
            .advice_assigned()
            .iter()
            .filter_map(|c| c.iter().rposition(|assigned| *assigned).map(|i| i + 1))
            .max()
            .unwrap();
        eprintln!("one-stage {variant:?} A rows={rows}");
        // The stand-in predecessor has no fixed, advice or permutation commitments,
        // so this is a lower bound; the real-Omega bound is the producer compiler's
        // `every_predecessor_stage_fits_k16_against_the_real_omega`.
        assert!(rows < 65_529);
        drop(assigned);
        let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
        config.compress_selectors = false;
        let key = keygen_pk_v2(&plan.vesta, &source, &config).unwrap();
        let original = Original {
            descriptor: key.binding().encoded().to_vec(),
            verifying_key: key.vk().to_bytes().to_vec(),
            proving_key: key.artifact_bytes_v2().unwrap(),
        };
        drop(key);
        installed.push((plan, original));
    }
    let read = ReadConfig {
        maximum_bytes: installed
            .iter()
            .map(|(_, original)| original.proving_key.len())
            .max()
            .unwrap(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    for (index, (plan, original)) in installed.iter().enumerate() {
        let imported = Prover::from_artifacts(plan.clone(), original.metadata()).unwrap();
        assert_eq!(
            imported.descriptors()[0].encoded(),
            original.descriptor.as_slice()
        );
        let [layout] = imported.checkpoint_layouts().unwrap();
        assert_eq!(
            layout.descriptor_digest(),
            imported.descriptors()[0].digest()
        );
        let seal = imported
            .import_terminal(&original.proving_key, read)
            .unwrap();
        let key = imported.bind_terminal(&seal, None).unwrap();
        assert_eq!(key.verifying_key().to_bytes(), original.verifying_key);
        // Unload and Retiring share the source profile and descriptor, but only the
        // exact source of each variant qualifies its own original.
        let (_, other) = &installed[1 - index];
        assert!(imported.import_terminal(&other.proving_key, read).is_err());
        // Metadata can describe the original, but only source reconstruction can
        // qualify it: the receipt binding pins the provider in the source.
        let changed = Plan::new(
            plan.context().operation().clone(),
            OwnPolicy::new([33, 34], Affine::GENERATOR).unwrap(),
            plan.signatures.clone(),
            plan.predecessor_key.clone(),
            plan.pallas.clone(),
            plan.vesta.clone(),
        )
        .unwrap();
        let changed = Prover::from_artifacts(changed, original.metadata()).unwrap();
        assert!(
            changed
                .import_terminal(&original.proving_key, read)
                .is_err()
        );
    }
}
