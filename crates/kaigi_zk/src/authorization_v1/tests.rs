//! Adversarial witnesses and real proof coverage for the complete V1 relation.
use super::*;
use iroha_pasta::{Eq, msm::MemoryBudget};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::InstanceType,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verifier::verify_full,
};

fn context(action: KaigiAuthorizationActionV1) -> KaigiAuthorizationContextV1 {
    let host_id = [11, 12, 13, 14, 15, 16];
    let host = matches!(
        action,
        KaigiAuthorizationActionV1::HostCreate | KaigiAuthorizationActionV1::HostEnd
    );
    KaigiAuthorizationContextV1 {
        network_id: array::from_fn(|i| i as u8 + 1),
        call_id: [1, 2, 3, 4, 5, 6],
        host_id,
        subject_id: if host {
            host_id
        } else {
            [21, 22, 23, 24, 25, 26]
        },
        participation_sequence: if host { 0 } else { 7 },
        action,
        pre_roster_root: array::from_fn(|i| i as u8 + 33),
    }
}
fn blinding() -> Scalar {
    // Full-field secret with high limbs; a u64 projection cannot preserve it.
    Scalar::from(2).pow_vartime([190, 0, 0, 0]) + Scalar::from(987_654_321)
}
fn witness(value: Scalar) -> KaigiAuthorizationWitnessV1 {
    KaigiAuthorizationWitnessV1::take_blinding(&mut value.to_repr()).unwrap()
}
fn raw_instance(words: [Scalar; CONTEXT_WORDS], secret: Scalar) -> [Scalar; 31] {
    let outputs = compute_words(&words, secret);
    let mut instance = [Scalar::ZERO; 31];
    instance[..28].copy_from_slice(&words);
    instance[28..].copy_from_slice(&[outputs.commitment, outputs.nullifier, outputs.authorization]);
    instance
}
fn raw_circuit(words: [Scalar; CONTEXT_WORDS], secret: Scalar) -> KaigiAuthorizationCircuitV1 {
    // Bypass checked construction deliberately: the constraints must reject malicious witnesses.
    KaigiAuthorizationCircuitV1 {
        words: words.map(Some),
        witness: Some(KaigiAuthorizationWitnessV1 {
            bytes: Box::new(secret.to_repr()),
        }),
    }
}
fn check(circuit: &KaigiAuthorizationCircuitV1, instance: [Scalar; 31]) -> bool {
    check_circuit(
        circuit,
        KAIGI_AUTHORIZATION_CIRCUIT_K_V1,
        &[instance.to_vec()],
        CheckMode::Strict,
    )
    .expect("fixed domain fits")
    .is_satisfied()
}
fn reject_words(words: [Scalar; CONTEXT_WORDS]) {
    assert!(!check(
        &raw_circuit(words, blinding()),
        raw_instance(words, blinding())
    ));
}

#[test]
fn framed_sponge_matches_independent_poseidon_primitive() {
    let mut captured = include_str!("../../../../fixtures/poseidon/kaigi-framed-rp56.hex").lines();
    for domain in [DOMAIN_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_AUTHORIZATION] {
        for length in 0..=33 {
            let payload: Vec<_> = (0..length)
                .map(|i| blinding() + Scalar::from(i as u64))
                .collect();
            // Separate complete-frame construction and the independent test
            // permutation over captured constants, rather than the circuit round helper.
            let mut frame = vec![Scalar::from(length as u64)];
            frame.extend_from_slice(&payload);
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
            let row: Vec<_> = captured
                .next()
                .expect("captured frame")
                .split_whitespace()
                .collect();
            assert_eq!(row.len(), 3);
            assert_eq!(u64::from_str_radix(row[0], 16).unwrap(), domain);
            assert_eq!(row[1].parse::<usize>().unwrap(), length);
            let expected = Scalar::from_repr(crate::tests::reference::field_bytes(row[2])).unwrap();
            assert_eq!(state[0], expected, "independent reference frame");
            assert_eq!(
                sponge(domain, &payload),
                state[0],
                "domain={domain:x}, length={length}"
            );
        }
    }
    assert!(captured.next().is_none(), "all 102 frames covered");
    let context = context(KaigiAuthorizationActionV1::Join);
    let outputs = compute_authorization_v1(&context, &witness(blinding())).unwrap();
    let hex = outputs.canonical_bytes().map(|bytes| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    // Derived only after the complete-frame implementation above matched the
    // captured independent permutation for all frame lengths.
    assert_eq!(
        hex,
        [
            "3b89d88b663dcfe20558d2a7cf7e0c9eda724fc2eca44b8531f10dcda3e2572f",
            "8ea7a9e034a95dc3af08f4d49bce71c17345b5d8d82e4e776977038b2cbb983d",
            "37781fcab0765cd1663bbc2b9f248bd8c793e1589feb4dfafe9f387bdf459112",
        ]
    );
}

#[test]
fn all_four_roles_satisfy_the_same_fixed_circuit() {
    for action in [
        KaigiAuthorizationActionV1::HostCreate,
        KaigiAuthorizationActionV1::Join,
        KaigiAuthorizationActionV1::Leave,
        KaigiAuthorizationActionV1::HostEnd,
    ] {
        let context = context(action);
        let witness = witness(blinding());
        let outputs = compute_authorization_v1(&context, &witness).unwrap();
        assert!(check(
            &KaigiAuthorizationCircuitV1::new(context, witness).unwrap(),
            KaigiAuthorizationPublicInputsV1 { context, outputs }.instance()
        ));
        assert_eq!(
            outputs.canonical_bytes(),
            [
                outputs.commitment.to_repr(),
                outputs.nullifier.to_repr(),
                outputs.authorization.to_repr()
            ]
        );
    }
}

#[test]
fn stable_commitment_and_deterministic_nullifier_have_exact_dependencies() {
    let join = context(KaigiAuthorizationActionV1::Join);
    let secret = witness(blinding());
    let a = compute_authorization_v1(&join, &secret).unwrap();
    let leave = compute_authorization_v1(
        &KaigiAuthorizationContextV1 {
            action: KaigiAuthorizationActionV1::Leave,
            ..join
        },
        &secret,
    )
    .unwrap();
    assert_eq!(a.commitment, leave.commitment);
    assert_ne!(a.nullifier, leave.nullifier);
    assert_ne!(a.authorization, leave.authorization);
    let root = compute_authorization_v1(
        &KaigiAuthorizationContextV1 {
            pre_roster_root: [255; 32],
            ..join
        },
        &secret,
    )
    .unwrap();
    assert_eq!(a.commitment, root.commitment);
    assert_eq!(a.nullifier, root.nullifier);
    assert_ne!(a.authorization, root.authorization);
    let blind = compute_authorization_v1(&join, &witness(blinding() + Scalar::ONE)).unwrap();
    assert_ne!(a.commitment, blind.commitment);
    assert_eq!(a.nullifier, blind.nullifier);
    assert_ne!(a.authorization, blind.authorization);
    let sequence = compute_authorization_v1(
        &KaigiAuthorizationContextV1 {
            participation_sequence: 8,
            ..join
        },
        &secret,
    )
    .unwrap();
    assert_ne!(a.commitment, sequence.commitment);
    assert_ne!(a.nullifier, sequence.nullifier);
    assert_ne!(a.authorization, sequence.authorization);
    assert_ne!(a.commitment, a.nullifier);
    assert_ne!(a.commitment, a.authorization);
    assert_ne!(a.nullifier, a.authorization);
}

#[test]
fn witness_ingress_clears_caller_bytes_and_owned_storage_is_redacted() {
    let mut bytes = blinding().to_repr();
    let mut secret = KaigiAuthorizationWitnessV1::take_blinding(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 32]);
    assert_eq!(secret.scalar(), blinding());
    assert_eq!(
        format!("{secret:?}"),
        "KaigiAuthorizationWitnessV1(<redacted>)"
    );
    let copy = secret.clone();
    assert_ne!(secret.bytes.as_ptr(), copy.bytes.as_ptr());
    secret.clear();
    assert_eq!(*secret.bytes, [0; 32]);
    assert_eq!(copy.scalar(), blinding());
    assert!(
        format!(
            "{:?}",
            KaigiAuthorizationCircuitV1::new(context(KaigiAuthorizationActionV1::Join), copy)
                .unwrap()
        )
        .contains("<redacted>")
    );
    for mut invalid in [[0; 32], [255; 32]] {
        assert_eq!(
            KaigiAuthorizationWitnessV1::take_blinding(&mut invalid).unwrap_err(),
            KaigiAuthorizationErrorV1::InvalidBlinding
        );
        assert_eq!(invalid, [0; 32]);
    }
    let mut scratch = ScalarSlots([blinding(); 4]);
    zeroize::Zeroize::zeroize(&mut scratch);
    assert_eq!(scratch.0, [Scalar::ZERO; 4]);
}

#[test]
fn typed_context_rejects_unknown_tags_noncanonical_lanes_and_invalid_roles() {
    for tag in 0..4 {
        assert_eq!(
            KaigiAuthorizationActionV1::try_from(tag).unwrap() as u64,
            tag
        );
    }
    for tag in [4, u64::MAX] {
        assert_eq!(
            KaigiAuthorizationActionV1::try_from(tag),
            Err(KaigiAuthorizationErrorV1::UnknownAction(tag))
        );
    }
    for index in 0..18 {
        let mut ctx = context(KaigiAuthorizationActionV1::Join);
        let (role, limbs) = match index / 6 {
            0 => ("call", &mut ctx.call_id),
            1 => ("host", &mut ctx.host_id),
            _ => ("subject", &mut ctx.subject_id),
        };
        limbs[index % 6] = KAIGI_IDENTITY_FIELD_MODULUS_V1;
        let expected = Err(KaigiAuthorizationErrorV1::NoncanonicalIdentityLimb {
            role,
            limb: index % 6,
        });
        assert_eq!(ctx.validate(), expected);
        assert_eq!(
            compute_authorization_v1(&ctx, &witness(blinding())).map(|_| ()),
            expected
        );
        assert_eq!(
            KaigiAuthorizationCircuitV1::new(ctx, witness(blinding())).map(|_| ()),
            expected
        );
    }
    let mut host = context(KaigiAuthorizationActionV1::HostCreate);
    host.subject_id[0] += 1;
    assert_eq!(
        host.validate(),
        Err(KaigiAuthorizationErrorV1::InvalidHostRole)
    );
    host.subject_id = host.host_id;
    host.participation_sequence = 1;
    assert_eq!(
        host.validate(),
        Err(KaigiAuthorizationErrorV1::InvalidHostRole)
    );
    let mut participant = context(KaigiAuthorizationActionV1::Join);
    participant.participation_sequence = 0;
    assert_eq!(
        participant.validate(),
        Err(KaigiAuthorizationErrorV1::InvalidParticipantRole)
    );
    participant.participation_sequence = 1;
    participant.subject_id = participant.host_id;
    assert_eq!(
        participant.validate(),
        Err(KaigiAuthorizationErrorV1::InvalidParticipantRole)
    );
}

#[test]
fn every_public_row_and_private_blinding_is_bound() {
    let words = context(KaigiAuthorizationActionV1::Join).words();
    let instance = raw_instance(words, blinding());
    let circuit = raw_circuit(words, blinding());
    for row in 0..31 {
        let mut changed = instance;
        changed[row] += Scalar::ONE;
        assert!(!check(&circuit, changed), "unbound public row {row}");
    }
    // Mutate both context advice and public rows, retaining C/N/A: hash absorption itself must reject.
    for row in 0..28 {
        let mut changed = words;
        changed[row] += Scalar::ONE;
        let mut public = instance;
        public[..28].copy_from_slice(&changed);
        assert!(
            !check(&raw_circuit(changed, blinding()), public),
            "unabsorbed context row {row}"
        );
    }
    assert!(!check(
        &raw_circuit(words, blinding() + Scalar::ONE),
        instance
    ));
}

#[test]
fn malicious_out_of_range_witnesses_fail_with_consistently_recomputed_hashes() {
    let words = context(KaigiAuthorizationActionV1::Join).words();
    let two64 = Scalar::from(u64::MAX) + Scalar::ONE;
    for row in (0..28).filter(|row| *row != ACTION_ROW) {
        let mut changed = words;
        changed[row] = two64;
        reject_words(changed);
    }
    for row in 4..22 {
        let mut changed = words;
        changed[row] = Scalar::from(KAIGI_IDENTITY_FIELD_MODULUS_V1);
        reject_words(changed);
    }
    let maximal = KaigiAuthorizationContextV1 {
        network_id: [255; 32],
        pre_roster_root: [255; 32],
        participation_sequence: u64::MAX,
        call_id: [KAIGI_IDENTITY_FIELD_MODULUS_V1 - 1; 6],
        host_id: [KAIGI_IDENTITY_FIELD_MODULUS_V1 - 1; 6],
        subject_id: [KAIGI_IDENTITY_FIELD_MODULUS_V1 - 2; 6],
        ..context(KaigiAuthorizationActionV1::Leave)
    }
    .words();
    assert!(check(
        &raw_circuit(maximal, blinding()),
        raw_instance(maximal, blinding())
    ));
}

#[test]
fn malicious_actions_roles_and_zero_blinding_fail_inside_constraints() {
    let join = context(KaigiAuthorizationActionV1::Join).words();
    for tag in [Scalar::from(4), Scalar::from(u64::MAX), -Scalar::ONE] {
        let mut words = join;
        words[ACTION_ROW] = tag;
        reject_words(words);
    }
    for action in [
        KaigiAuthorizationActionV1::HostCreate,
        KaigiAuthorizationActionV1::HostEnd,
    ] {
        let words = context(action).words();
        let mut sequence = words;
        sequence[SEQUENCE_ROW] = Scalar::ONE;
        reject_words(sequence);
        for limb in 0..6 {
            let mut subject = words;
            subject[16 + limb] += Scalar::ONE;
            reject_words(subject);
        }
    }
    for action in [
        KaigiAuthorizationActionV1::Join,
        KaigiAuthorizationActionV1::Leave,
    ] {
        let mut words = context(action).words();
        words[SEQUENCE_ROW] = Scalar::ZERO;
        reject_words(words);
        words = context(action).words();
        let host: [Scalar; 6] = words[10..16].try_into().unwrap();
        words[16..22].copy_from_slice(&host);
        reject_words(words);
    }
    assert!(!check(
        &raw_circuit(join, Scalar::ZERO),
        raw_instance(join, Scalar::ZERO)
    ));
}

#[test]
fn real_pipa_r_proof_roundtrip_rejects_every_changed_public_row() {
    let params = PinnedParams::<Eq>::derive(KAIGI_AUTHORIZATION_CIRCUIT_K_V1).unwrap();
    let pk = keygen_pk_v2(
        &params,
        &KaigiAuthorizationCircuitV1::default(),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Field]),
    )
    .unwrap();
    let words = context(KaigiAuthorizationActionV1::Join).words();
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
    for row in 0..31 {
        let mut changed = instance;
        changed[row] += Scalar::ONE;
        assert!(!verify(&changed), "real proof accepted row {row}");
    }
    println!(
        "Kaigi final V1: k={}, rows={}, IPA proof bytes={}",
        KAIGI_AUTHORIZATION_CIRCUIT_K_V1,
        KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1,
        proof.len()
    );
}
