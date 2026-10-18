//! Source-layout qualification only. Unknown witnesses create no enrolled wallet.
//!
//! The signature Q key below supplies only the fixed 2V1F metadata needed to
//! reconstruct the unsplit Bootstrap A layout. It cannot authorize a production
//! wallet, an Omega catalog or funding.

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

fn original_plan() -> Plan {
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let signatures = QSignaturePlan::new(
        [
            SignatureKey::Variable,
            SignatureKey::Variable,
            SignatureKey::Fixed(Affine::GENERATOR),
        ]
        .into_iter()
        .map(|key| SignatureSlot {
            mode: VerifyMode::Hard,
            key,
        })
        .collect(),
    )
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
    // Lean lineage: one unsplit terminal A over the single hard signature leaf.
    let operation = AProofPlan::inline(Variant::Bootstrap, vec![q], None, &pallas).unwrap();
    Plan::new(
        operation,
        BootstrapPolicy::new([31, 32], Affine::GENERATOR).unwrap(),
        signatures,
        pallas,
        vesta,
    )
    .unwrap()
}

#[test]
#[ignore = "imports the actual unsplit Bootstrap A source tables at k16; run optimized explicitly"]
fn unsplit_terminal_original_source_qualifies_at_k16() {
    let plan = original_plan();
    assert_eq!(plan.context().stage_count(), 1);
    let source = plan.source_circuit().unwrap();
    let assigned = synthesize(&source, 16, None).unwrap();
    let rows = assigned
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|c| c.iter().rposition(|assigned| *assigned).map(|i| i + 1))
        .max()
        .unwrap();
    eprintln!("unsplit Bootstrap A rows={rows}");
    assert!(rows < (1 << 16));
    drop(assigned);
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let key = keygen_pk_v2(&plan.vesta, &source, &config).unwrap();
    let descriptor = key.binding().encoded().to_vec();
    let verifying_key = key.vk().to_bytes().to_vec();
    let original = key.artifact_bytes_v2().unwrap();
    drop(key);
    let metadata = || {
        let binding = DescriptorBinding::decode_v2(&descriptor).unwrap();
        let key = VerifyingKey::read(&verifying_key, &binding).unwrap();
        KeyArtifact::new(binding, key).unwrap()
    };
    let read = ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let imported = Prover::from_artifacts(plan.clone(), metadata()).unwrap();
    assert_eq!(imported.descriptors()[0].encoded(), descriptor.as_slice());
    let [layout] = imported.checkpoint_layouts().unwrap();
    assert_eq!(
        layout.descriptor_digest(),
        imported.descriptors()[0].digest()
    );
    let seal = imported.import_terminal(&original, read).unwrap();
    let key = imported.bind_terminal(&seal, None).unwrap();
    assert_eq!(key.verifying_key().to_bytes(), verifying_key);
    // Metadata can describe the original, but only source reconstruction can qualify it.
    let changed = Plan::new(
        plan.context().operation().clone(),
        BootstrapPolicy::new([33, 34], Affine::GENERATOR).unwrap(),
        plan.signatures.clone(),
        plan.pallas.clone(),
        plan.vesta.clone(),
    )
    .unwrap();
    let changed = Prover::from_artifacts(changed, metadata()).unwrap();
    assert!(changed.import_terminal(&original, read).is_err());
}
