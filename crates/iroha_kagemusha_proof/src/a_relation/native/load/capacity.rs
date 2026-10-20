//! Source-layout qualification only. Unknown witnesses create no funded Load.
//!
//! The predecessor key below supplies only the homogeneous metadata needed to
//! reconstruct Load layouts. It cannot authorize a production wallet or funding.

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
    // Lean lineage: the only Q is the own-receipt signature leaf.
    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let signatures = [QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap()];
    let mut q = Vec::new();
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
    let operation = AProofPlan::inline(Variant::Load, q, Some(predecessor), &pallas).unwrap();
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
#[ignore = "imports the actual single Load A source tables at k16; run optimized explicitly"]
fn single_terminal_original_source_qualifies_at_k16() {
    let plan = original_plan();
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
    eprintln!("single terminal Load A rows={rows}");
    // The stand-in predecessor has no fixed, advice or permutation commitments,
    // so this is a lower bound; the real-Omega bound is the producer compiler's
    // `every_predecessor_stage_fits_k16_against_the_real_omega`.
    assert!(rows < 65_529);
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
    // The one exported descriptor is the exact installed terminal owner.
    let [installed] = imported.descriptors();
    assert!(core::ptr::eq(installed, imported.terminal.binding()));
    assert_eq!(installed.encoded(), descriptor.as_slice());
    let [layout] = imported.checkpoint_layouts().unwrap();
    assert_eq!(layout.descriptor_digest(), installed.digest());
    assert_eq!(imported.plan().context().schema(), plan.context().schema());
    let seal = imported.import_terminal(&original, read).unwrap();
    let key = imported.bind_terminal(&seal, None).unwrap();
    assert_eq!(key.verifying_key().to_bytes(), verifying_key);
    // The retired split layout is refused even with every task once.
    let retired = crate::a_relation::context::ContextPlan::with_schedule(
        plan.context().operation().clone(),
        vec![vec![], vec![0]],
        Some(0),
        plan.context().object_specs().to_vec(),
    )
    .and_then(|context| {
        context.with_operation_tasks(vec![
            vec![crate::a_relation::schedule::OperationTask::LoadRecovery],
            vec![crate::a_relation::schedule::OperationTask::LoadReceipt],
        ])
    });
    assert!(retired.map_or(true, |context| {
        crate::a_relation::load::LoadStagePlan::new(context).is_err()
    }));
    let mut changed = plan;
    changed.policy.provider[0] ^= 1;
    // A valid original of another policy's source never imports into this prover.
    let foreign = keygen_pk_v2(&changed.vesta, &changed.source_circuit().unwrap(), &config)
        .unwrap()
        .artifact_bytes_v2()
        .unwrap();
    assert!(
        imported
            .import_terminal(
                &foreign,
                ReadConfig {
                    maximum_bytes: foreign.len(),
                    ..read
                }
            )
            .is_err()
    );
    let changed = Prover::from_artifacts(changed, metadata()).unwrap();
    // Metadata can describe the original, but only source reconstruction can qualify it.
    assert!(changed.import_terminal(&original, read).is_err());
}
