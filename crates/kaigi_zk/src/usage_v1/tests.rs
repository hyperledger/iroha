//! Host-opening, complete context binding and adversarial final usage witnesses.
use super::*;
use crate::authorization_v1::compute_authorization_v1;
use iroha_pasta::{Eq, msm::MemoryBudget};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::InstanceType,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verifier::verify_full,
};

fn context() -> KaigiUsageContextV1 {
    KaigiUsageContextV1 {
        network_id: array::from_fn(|i| i as u8 + 1),
        call_id: [1, 2, 3, 4, 5, 6],
        host_id: [11, 12, 13, 14, 15, 16],
        pre_roster_root: array::from_fn(|i| i as u8 + 33),
        segment_index: 7,
        duration_ms: 1200,
        billed_gas: 345,
    }
}
fn blinding() -> Scalar {
    Scalar::from(2).pow_vartime([190]) + Scalar::from(987_654_321)
}
fn witness(value: Scalar) -> KaigiAuthorizationWitnessV1 {
    KaigiAuthorizationWitnessV1::take_blinding(&mut value.to_repr()).unwrap()
}
fn raw_circuit(words: [Scalar; CONTEXT_WORDS], secret: Scalar) -> KaigiUsageCircuitV1 {
    KaigiUsageCircuitV1 {
        words: words.map(Some),
        witness: Some(KaigiAuthorizationWitnessV1::unchecked_for_constraint_test(
            secret,
        )),
    }
}
fn raw_instance(words: [Scalar; CONTEXT_WORDS], secret: Scalar) -> [Scalar; 25] {
    let output = compute_words(&words, secret);
    let mut instance = [Scalar::ZERO; 25];
    instance[..23].copy_from_slice(&words);
    instance[23] = output.host_commitment;
    instance[24] = output.usage_commitment;
    instance
}
fn check(circuit: &KaigiUsageCircuitV1, instance: [Scalar; 25]) -> bool {
    check_circuit(
        circuit,
        KAIGI_USAGE_CIRCUIT_K_V1,
        &[instance.to_vec()],
        CheckMode::Strict,
    )
    .expect("fixed domain fits")
    .is_satisfied()
}

#[test]
fn usage_c_and_u_match_independent_poseidon_framing() {
    let reference = |domain: u64, payload: &[Scalar]| {
        let mut frame = vec![Scalar::from(payload.len() as u64)];
        frame.extend_from_slice(payload);
        frame.push(Scalar::ONE);
        if frame.len() % 2 != 0 {
            frame.push(Scalar::ZERO);
        }
        let mut state = [Scalar::ZERO, Scalar::ZERO, Scalar::from(domain)];
        for pair in frame.chunks_exact(2) {
            state[0] += pair[0];
            state[1] += pair[1];
            crate::tests::reference_permute(&mut state);
        }
        state[0]
    };
    let context = context();
    let mut host_payload = context.host_context().words()[..23].to_vec();
    host_payload.push(blinding());
    let c = reference(0x4b41_4947_4956_3143, &host_payload);
    let mut usage_payload = context.words().to_vec();
    usage_payload.extend([c, blinding()]);
    let u = reference(0x4b41_4947_4956_3155, &usage_payload);
    let outputs = compute_usage_v1(&context, &witness(blinding())).unwrap();
    assert_eq!(outputs.host_commitment, c);
    assert_eq!(outputs.usage_commitment, u);
    let hex = outputs.canonical_bytes().map(|bytes| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    // Pinned only after agreement with the separately framed independent permutation.
    assert_eq!(
        hex,
        [
            "53267c7c98f82fcf475aab7997f3eedea5935ab7df7e17e0327ba5fbc4f5980c",
            "4139861c7c35e3315f3b26097fd3b02bd66b4ad5301fa9d8f15cddb5db65d014",
        ]
    );
}

#[test]
fn usage_opens_the_exact_stored_authorization_host_commitment() {
    let context = context();
    let secret = witness(blinding());
    let outputs = compute_usage_v1(&context, &secret).unwrap();
    let host = compute_authorization_v1(&context.host_context(), &secret).unwrap();
    assert_eq!(outputs.host_commitment, host.commitment);
    assert_ne!(outputs.usage_commitment, host.commitment);
    assert_ne!(outputs.usage_commitment, host.authorization);
    assert_eq!(
        outputs.canonical_bytes(),
        [
            outputs.host_commitment.to_repr(),
            outputs.usage_commitment.to_repr()
        ]
    );
    let instance = KaigiUsagePublicInputsV1 { context, outputs }.instance();
    assert!(check(
        &KaigiUsageCircuitV1::new(context, secret).unwrap(),
        instance
    ));
    assert_eq!(KAIGI_USAGE_CIRCUIT_K_V1, 12);
    assert_eq!(ASSIGNED_ROWS, 4037);
    assert!(
        check_circuit(
            &raw_circuit(context.words(), blinding()),
            11,
            &[instance.to_vec()],
            CheckMode::Strict
        )
        .is_err()
    );
    let maximal = KaigiUsageContextV1 {
        network_id: [255; 32],
        pre_roster_root: [255; 32],
        call_id: [GOLDILOCKS_MODULUS_V1 - 1; 6],
        host_id: [GOLDILOCKS_MODULUS_V1 - 1; 6],
        segment_index: u32::MAX,
        duration_ms: u64::MAX,
        billed_gas: u64::MAX,
    }
    .words();
    assert!(check(
        &raw_circuit(maximal, blinding()),
        raw_instance(maximal, blinding())
    ));
}

#[test]
fn every_context_limb_binds_usage_and_only_identity_changes_host_c() {
    let words = context().words();
    let baseline = compute_words(&words, blinding());
    for row in 0..CONTEXT_WORDS {
        let mut changed = words;
        changed[row] += Scalar::ONE;
        let output = compute_words(&changed, blinding());
        assert_ne!(
            output.usage_commitment, baseline.usage_commitment,
            "U row {row}"
        );
        if row < 16 {
            assert_ne!(
                output.host_commitment, baseline.host_commitment,
                "C row {row}"
            );
        } else {
            assert_eq!(
                output.host_commitment, baseline.host_commitment,
                "stable C row {row}"
            );
        }
    }
    let changed_secret = compute_words(&words, blinding() + Scalar::ONE);
    assert_ne!(changed_secret.host_commitment, baseline.host_commitment);
    assert_ne!(changed_secret.usage_commitment, baseline.usage_commitment);
}

#[test]
fn all_25_public_rows_context_witnesses_and_private_blinding_are_constrained() {
    let words = context().words();
    let instance = raw_instance(words, blinding());
    let circuit = raw_circuit(words, blinding());
    for row in 0..25 {
        let mut changed = instance;
        changed[row] += Scalar::ONE;
        assert!(!check(&circuit, changed), "public row {row}");
    }
    for row in 0..CONTEXT_WORDS {
        let mut changed = words;
        changed[row] += Scalar::ONE;
        let mut public = instance;
        public[..23].copy_from_slice(&changed);
        assert!(
            !check(&raw_circuit(changed, blinding()), public),
            "hash relation row {row}"
        );
    }
    assert!(!check(
        &raw_circuit(words, blinding() + Scalar::ONE),
        instance
    ));
}

#[test]
fn correct_hashes_cannot_hide_noncanonical_ranges_or_zero_duration_and_secret() {
    let words = context().words();
    for row in 0..CONTEXT_WORDS {
        let mut changed = words;
        changed[row] = if row == SEGMENT_ROW {
            Scalar::from(u64::from(u32::MAX) + 1)
        } else {
            Scalar::from(u64::MAX) + Scalar::ONE
        };
        assert!(
            !check(
                &raw_circuit(changed, blinding()),
                raw_instance(changed, blinding())
            ),
            "limb bound row {row}"
        );
    }
    for row in 4..16 {
        let mut changed = words;
        changed[row] = Scalar::from(GOLDILOCKS_MODULUS_V1);
        assert!(
            !check(
                &raw_circuit(changed, blinding()),
                raw_instance(changed, blinding())
            ),
            "Goldilocks row {row}"
        );
    }
    let mut zero_duration = words;
    zero_duration[DURATION_ROW] = Scalar::ZERO;
    assert!(!check(
        &raw_circuit(zero_duration, blinding()),
        raw_instance(zero_duration, blinding())
    ));
    assert!(!check(
        &raw_circuit(words, Scalar::ZERO),
        raw_instance(words, Scalar::ZERO)
    ));
}

#[test]
fn usage_rejects_invalid_context_and_keeps_private_witness_redacted_and_owned() {
    let mut bytes = blinding().to_repr();
    let secret = KaigiAuthorizationWitnessV1::take_blinding(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 32]);
    let circuit = KaigiUsageCircuitV1::new(context(), secret.clone()).unwrap();
    assert!(format!("{circuit:?}").contains("KaigiAuthorizationWitnessV1(<redacted>)"));
    drop(circuit);
    assert_eq!(
        compute_usage_v1(&context(), &secret).unwrap(),
        compute_usage_v1(&context(), &witness(blinding())).unwrap()
    );
    let zero = KaigiUsageContextV1 {
        duration_ms: 0,
        ..context()
    };
    assert_eq!(zero.validate(), Err(KaigiUsageErrorV1::ZeroDuration));
    assert_eq!(
        compute_usage_v1(&zero, &secret),
        Err(KaigiUsageErrorV1::ZeroDuration)
    );
    assert_eq!(
        KaigiUsageCircuitV1::new(zero, secret.clone())
            .unwrap_err()
            .to_string(),
        "Kaigi usage duration must be positive"
    );
    for row in 0..12 {
        let mut invalid = context();
        let limb = if row < 6 {
            &mut invalid.call_id[row]
        } else {
            &mut invalid.host_id[row - 6]
        };
        *limb = GOLDILOCKS_MODULUS_V1;
        assert!(invalid.validate().is_err());
        assert!(compute_usage_v1(&invalid, &secret).is_err());
        assert!(KaigiUsageCircuitV1::new(invalid, secret.clone()).is_err());
    }
    for mut invalid in [[0; 32], [255; 32]] {
        assert!(KaigiAuthorizationWitnessV1::take_blinding(&mut invalid).is_err());
        assert_eq!(invalid, [0; 32]);
    }
}

#[test]
fn real_usage_pipa_r_proof_rejects_every_context_and_commitment_replay() {
    let params = PinnedParams::<Eq>::derive(KAIGI_USAGE_CIRCUIT_K_V1).unwrap();
    let pk = keygen_pk_v2(
        &params,
        &KaigiUsageCircuitV1::default(),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Field]),
    )
    .unwrap();
    let words = context().words();
    let instance = raw_instance(words, blinding());
    let witness =
        Witness::from_circuit(&pk, &raw_circuit(words, blinding()), &[instance.to_vec()]).unwrap();
    let proof = create_proof_owned(
        &params,
        &pk,
        witness,
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .unwrap();
    let verify = |statement: &[Scalar]| {
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &[statement.to_vec()],
            &proof,
            MemoryBudget::DEFAULT,
        )
        .is_ok()
    };
    assert!(verify(&instance));
    for row in 0..25 {
        let mut changed = instance;
        changed[row] += Scalar::ONE;
        assert!(!verify(&changed), "usage replay row {row}");
    }
    println!(
        "Kaigi usage final V1: k={}, assigned rows={}, public rows=25, proof bytes={}",
        KAIGI_USAGE_CIRCUIT_K_V1,
        ASSIGNED_ROWS,
        proof.len()
    );
}
