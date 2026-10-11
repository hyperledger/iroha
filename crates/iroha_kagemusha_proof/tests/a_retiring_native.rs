//! Genuine Retiring sigma/signature-Q originals and oversized predecessor rejection.
//!
//! The leaf fixture is a local arithmetic witness, not an admitted loaded head.
//! A complete native Retiring proof/restoration positive must use an authenticated
//! compact folded head with funds; no oversized or synthetic head is admitted here.

#![allow(clippy::duplicate_mod)]

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
/// Genuine Bootstrap/Omega component fixtures shared with the Retiring source.
#[path = "bootstrap_omega.rs"]
pub mod bootstrap_outer;
mod common;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, QProofPlan, native::consuming, own::OwnPolicy, schedule::sigma_selector,
    },
    admin_sigma::{ConsumingWitness, RetiringCircuit, StateWitness},
    operation_relation::{administrative::NULLIFIER_DOMAIN, objects::ObjectKind},
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    q_signature::{QSignatureCircuit, QSignaturePlan},
    witness::{CORE_DOMAIN, REST_DOMAIN, core_index as core},
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    frontend::{Circuit, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::{accumulate_generator, verify_full},
};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::STATEMENT_DOMAIN};
use iroha_plonk_recursion::{FoldConfig, obligation::ledger::Variant, verifier::VerifierPlan};

fn rebind(w: &mut ConsumingWitness) {
    for state in [&mut w.predecessor, &mut w.successor] {
        let mut preimage = state.core.to_vec();
        preimage.push(hash_with_domain(REST_DOMAIN, &state.rest));
        state.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
        state.lineage[1..3].copy_from_slice(&state.core[core::SCHEME..=core::SCHEME + 1]);
        state.lineage[6..8].copy_from_slice(&state.core[core::WALLET..core::WALLET + 2]);
        state.lineage[8] = state.core[core::CREDENTIAL];
        state.lineage[13] = state.core[core::LIFECYCLE]
            + Fp::from(256) * state.core[core::POLICY_EPOCH]
            + Fp::from_u128(1 << 72) * state.core[core::ENABLED_CONTROLS];
    }
    w.statement[3..7].copy_from_slice(&w.successor.core[core::SCHEME..core::ASSET + 2]);
    for (field, index) in [
        (7, core::CREDENTIAL),
        (8, core::LIFECYCLE),
        (9, core::SEQUENCE),
        (10, core::NEXT_LOAD),
    ] {
        w.statement[field] = w.successor.core[index];
    }
    w.statement[12] = w.predecessor.lineage[14];
    w.statement[13] = w.predecessor.lineage[15];
    w.statement[14] = w.predecessor.lineage[5];
    w.statement[15] = w.successor.lineage[5];
}

fn witness(retiring: bool) -> ConsumingWitness {
    let initial = bootstrap_objects::enrollment().0;
    let mut predecessor = StateWitness::from(&initial);
    predecessor.core[core::BALANCE] = Fp::from(100);
    predecessor.core[core::BURNED_TOTAL] = Fp::from(2);
    // Folding may increase burned value and change the pending root without
    // rewriting the previous core. The consuming step must synchronize both.
    predecessor.lineage[14] = Fp::from(10);
    predecessor.lineage[15] = Fp::from(101);
    let mut successor = predecessor;
    successor.core[core::SEQUENCE] += Fp::ONE;
    successor.core[core::STATE_NONCE] += Fp::ONE;
    successor.core[core::BURNED_TOTAL] = predecessor.lineage[14];
    successor.core[core::PENDING_OUTGOING_ROOT] = predecessor.lineage[15];
    let mut statement = initial.statement;
    statement[17..].fill(Fp::ZERO);
    if retiring {
        successor.core[core::LIFECYCLE] = Fp::from(2);
        statement[16] = Fp::from(8);
    } else {
        successor.core[core::BALANCE] = Fp::from(70);
        successor.core[core::NEXT_REDEEM] = Fp::ONE;
        // A must prove this recovery root's exact insertion.
        successor.core[core::LOAD_REDEEM_ROOT] = Fp::from(99);
        statement[16] = Fp::from(6);
        statement[17] = hash_with_domain(
            NULLIFIER_DOMAIN,
            &[
                predecessor.core[core::SCHEME],
                predecessor.core[core::SCHEME + 1],
                predecessor.core[core::WALLET],
                predecessor.core[core::WALLET + 1],
                predecessor.core[core::NEXT_REDEEM],
            ],
        );
        statement[19] = Fp::from(30);
        statement[20] = Fp::from(3);
        statement[21] = Fp::from(43);
    }
    let mut w = ConsumingWitness {
        predecessor,
        successor,
        statement,
    };
    rebind(&mut w);
    w
}

fn frame(raw: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
    out.extend(raw);
    out
}

#[test]
#[ignore = "real k12 Retiring/Q_sigma/hard2V1F Q and complete oversized Bootstrap predecessor rejection; run optimized"]
fn genuine_retiring_sources_reject_an_oversized_predecessor() {
    let budget = MemoryBudget::DEFAULT;
    let witness = witness(true);
    let leaf = RetiringCircuit::new(&witness);
    let public = leaf.instances();
    assert!(
        check_circuit(&leaf, 12, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&leaf, 12, Some(&public)).unwrap();
    let unknown = synthesize(&leaf.without_witnesses(), 12, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let leaf_params = PinnedParams::<Eq>::derive(12).unwrap();
    let leaf_key = keygen_pk_v2(
        &leaf_params,
        &leaf,
        &KeygenConfigV2::pipa_r(RetiringCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let leaf_output = create_proof_owned_with_claim(
        &leaf_params,
        &leaf_key,
        Witness::from_circuit(&leaf_key, &leaf, &public).unwrap(),
        common::recovery(221),
        ProverConfig::default(),
    )
    .unwrap();
    verify_full(
        &leaf_params,
        leaf_key.binding(),
        leaf_key.vk(),
        &public,
        &leaf_output.proof,
        budget,
    )
    .unwrap();
    leaf_output.opening.decide(&leaf_params, budget).unwrap();
    assert!(leaf_output.proof.len() <= 3_456);
    for mutation in 0..2 {
        let mut instances = public.clone();
        let mut proof = leaf_output.proof.clone();
        if mutation == 0 {
            instances[0][0] += Fp::ONE;
        } else {
            proof[0] ^= 1;
        }
        assert!(
            verify_full(
                &leaf_params,
                leaf_key.binding(),
                leaf_key.vk(),
                &instances,
                &proof,
                budget
            )
            .is_err()
        );
    }
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = PinnedParams::<Eq>::derive(16).unwrap();
    let selector = sigma_selector(8, 0).unwrap();
    assert_eq!(selector, 15);
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(leaf_key.binding().clone(), leaf_params).unwrap(),
            vec![(
                selector,
                leaf_key.vk().kagemusha_digest(leaf_key.binding()).unwrap(),
            )],
        )
        .unwrap(),
        None,
        &vparams,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: leaf_key.vk().clone(),
                statement: public[0][0],
                proof: leaf_output.proof.clone(),
                length: leaf_output.proof.len().try_into().unwrap(),
            },
            None,
            &vparams,
            Fq::from(131),
            &FoldConfig::default(),
        )
        .unwrap();
    let q = QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), 4).unwrap();
    let qproof = q
        .prove(&prepared, common::recovery(222), ProverConfig::default())
        .unwrap();
    verify_full(
        &params,
        q.binding(),
        q.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        budget,
    )
    .unwrap();
    let qopening = accumulate_generator(
        &params,
        q.binding(),
        q.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        budget,
    )
    .unwrap();
    qopening.decide(&params, budget).unwrap();
    qproof.part.decide(&vparams, budget).unwrap();
    let mut wrong_selector = qproof.instances.clone();
    wrong_selector[2][0] = Fq::from(15);
    assert!(
        verify_full(
            &params,
            q.binding(),
            q.verifying_key(),
            &wrong_selector,
            &qproof.bytes,
            budget
        )
        .is_err()
    );
    let rooted = bootstrap_outer::rooted_bootstrap_omega(false);
    verify_full(
        &params,
        &rooted.binding,
        &rooted.key,
        &rooted.instances,
        &rooted.proof,
        budget,
    )
    .unwrap();
    rooted.source.pallas.decide(&params, budget).unwrap();
    rooted.vesta.decide(&vparams, budget).unwrap();
    assert!(rooted.proof.len() + 1_088 > consuming::OMEGA_TRANSPORT_CAP);
    // The genuine Bootstrap predecessor is not a funded Unload predecessor.
    // This original is retained solely to prove the actual descriptor-size gate
    // rejects a real outer proof instead of fabricating a compact replacement.
    let (initial, certificate, credential) = bootstrap_objects::enrollment();
    assert_eq!(
        initial.core[core::CREDENTIAL],
        witness.predecessor.core[core::CREDENTIAL]
    );
    // Exact genuine original public320 || proof || both full claims, following
    // the canonical consuming lineage transcript. It is not a funded head.
    let f = rooted.source.state.lineage;
    let mut omega = 1_u16.to_le_bytes().to_vec();
    for i in [1, 2, 3, 4] {
        omega.extend(&f[i].to_repr()[..16]);
    }
    omega.extend(f[5].to_repr());
    for i in [6, 7] {
        omega.extend(&f[i].to_repr()[..16]);
    }
    omega.extend(f[8].to_repr());
    omega.push(4);
    for i in [10, 9, 12, 11] {
        omega.extend(f[i].to_repr()[..16].iter().rev());
    }
    omega.extend(&f[13].to_repr()[..13]);
    omega.extend(&f[14].to_repr()[..16]);
    omega.extend(f[15].to_repr());
    omega.extend(f[16].to_repr());
    assert_eq!(omega.len(), 320);
    omega.extend(&rooted.proof);
    omega.extend(rooted.source.pallas.to_bytes());
    omega.extend(rooted.vesta.to_bytes());
    // The local receipt/signature-Q fixture uses the genuine two-carrier
    // digest domain. Only A1 can bind this to an actually funded predecessor.
    let proof_digest = p_bytes_native(
        u64::from_le_bytes(*b"kgwprf_1"),
        &[frame(&omega), frame(&leaf_output.proof)].concat(),
    );
    let mut body = 1_u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(
        witness.successor.core[1],
        witness.successor.core[2],
    ));
    body.extend(bootstrap_objects::id(
        witness.successor.core[5],
        witness.successor.core[6],
    ));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&witness.statement[9].to_repr()[..16]);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            witness.successor.core[5],
            witness.successor.core[6],
            Fp::from(8),
            Fp::ZERO,
        ],
    );
    for value in [
        operation,
        witness.statement[14],
        witness.statement[15],
        hash_with_domain(STATEMENT_DOMAIN, &witness.statement),
        proof_digest,
    ] {
        body.extend(value.to_repr());
    }
    body.extend(bootstrap_objects::small_id(101, 102));
    body.extend(Fp::ZERO.to_repr());
    let receipt = bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 59);
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    let schema =
        iroha_kagemusha_proof::a_relation::unload::UnloadStagePlan::signature_schema(policy)
            .unwrap();
    let signatures = QSignatureCircuit::new(
        schema.clone(),
        vec![
            receipt.signature,
            credential.signature,
            certificate.signature,
        ],
    )
    .unwrap();
    let instances = signatures.instances(&[true; 3]).unwrap();
    let signature_key = keygen_pk_v2(
        &params,
        &signatures,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let signature_output = create_proof_owned_with_claim(
        &params,
        &signature_key,
        Witness::from_circuit(&signature_key, &signatures, &instances).unwrap(),
        common::recovery(223),
        ProverConfig::default(),
    )
    .unwrap();
    verify_full(
        &params,
        signature_key.binding(),
        signature_key.vk(),
        &instances,
        &signature_output.proof,
        budget,
    )
    .unwrap();
    signature_output.opening.decide(&params, budget).unwrap();
    let mut changed = signature_output.proof.clone();
    changed[0] ^= 1;
    assert!(
        verify_full(
            &params,
            signature_key.binding(),
            signature_key.vk(),
            &instances,
            &changed,
            budget
        )
        .is_err()
    );
    let operation = AProofPlan::new(
        Variant::Retiring,
        sigma_plan,
        vec![
            QProofPlan::new(
                VerifierPlan::new(q.binding().clone(), params.clone()).unwrap(),
                q.verifying_key().clone(),
            )
            .unwrap(),
            QProofPlan::new(
                VerifierPlan::new(signature_key.binding().clone(), params.clone()).unwrap(),
                signature_key.vk().clone(),
            )
            .unwrap(),
        ],
        Some(VerifierPlan::new(rooted.binding.clone(), params.clone()).unwrap()),
        &params,
    )
    .unwrap();
    assert!(matches!(
        consuming::Plan::new(operation, policy, schema, rooted.key, params, vparams),
        Err(consuming::Error::Artifact)
    ));
}
