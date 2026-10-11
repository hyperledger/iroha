//! Genuine Load sigma, ordinary receipt, own signature Q and production-depth recovery.
//! Component checks here do not accept a lineage without the recursive A chain.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)] // Bootstrap and Load share signing helpers; each consumes distinct objects.
pub(crate) mod bootstrap_objects;
mod common;
#[path = "common/load_objects.rs"]
mod load_objects;

include!("common/proof_fixtures/a_load_body.rs");

#[test]
fn load_policy_requires_fixed_nonzero_provider_and_finite_root() {
    use iroha_plonk_gadgets::p256::native::{Affine, P};
    assert!(OwnPolicy::new([3, 4], Affine::GENERATOR).is_ok());
    assert!(OwnPolicy::new([0; 2], Affine::GENERATOR).is_err());
    assert!(OwnPolicy::new([3, 4], Affine { x: P, y: [0; 4] }).is_err());
    let _ = load_objects::policy();
}

#[test]
fn genuine_load_sigma_signed_objects_and_recovery_share_exact_roots() {
    let (circuit, sigma) = fixture();
    assert_eq!(sigma.len(), 3296);
    assert!(
        check_circuit(&circuit, 16, &circuit.public(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let lanes: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect();
    eprintln!(
        "Load actual objects + D32 recovery shared A lanes={lanes:?}; recursive frame and signature Q not in this component"
    );
    for bad in 0..5 {
        let mut wrong = circuit.clone();
        match bad {
            0 => wrong.insertion.slot_siblings[31] += Fp::ONE,
            1 => wrong.insertion.leaf_siblings[0] += Fp::ONE,
            2 => wrong.insertion.slot = 0,
            3 => wrong.witness.statement[17] += Fp::ONE,
            _ => wrong.witness.successor.core[16] += Fp::ONE,
        }
        assert!(
            !check_circuit(&wrong, 16, &wrong.public(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "Load recovery mutation{bad}"
        );
    }
}

#[test]
fn actual_load_signature_q_proves_own_receipt_and_current_enrollment() {
    let (circuit, _) = fixture();
    let (signature, instances) = load_objects::own_signature(circuit.objects[0].signature);
    let (current, current_instances) = load_objects::current_signatures(&[
        circuit.objects[2].signature,
        circuit.objects[1].signature,
    ]);
    let current_report =
        check_circuit(&current, 16, &current_instances, CheckMode::Strict).unwrap();
    assert!(current_report.is_satisfied(), "{current_report:?}");
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let config = KeygenConfigV2::pipa_r(
        iroha_kagemusha_proof::q_signature::QSignaturePlan::instance_types().to_vec(),
    );
    let key = keygen_pk_v2(&params, &signature, &config).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &signature, &instances).unwrap(),
        common::recovery(192),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    for i in 0..instances[0].len() {
        let mut wrong = instances.clone();
        wrong[0][i] += Fq::ONE;
        assert!(
            accumulate_generator(
                &params,
                key.binding(),
                key.vk(),
                &wrong,
                &proof.proof,
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
    }
    eprintln!(
        "actual Load own-receipt 1V Q bytes={}; A must bind opaque slots to object semantics",
        proof.proof.len()
    );
}
