//! Pure exact-original and homogeneous-frame rejection tests, never an admitted Send.

use super::*;
use iroha_pasta::PastaAffine;
use iroha_plonk_gadgets::bytes::p_bytes_native;

fn original(mask: u8) -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 29],
        rest: [Fp::ZERO; 6],
        lineage: [Fp::ZERO; 18],
    };
    let mut state = SendState {
        before: state,
        after: state,
        statement: [Fp::ZERO; 26],
    };
    state.statement[11] = Fp::from(u64::from(mask));
    state.before.core[21] = Fp::from(u64::from(mask));
    state.after.core[21] = Fp::from(u64::from(mask));
    Inputs {
        state,
        step: crate::vectors::sample_witness(
            u64::from(mask),
            SigmaRelation::send(u32::from(mask)),
            crate::vectors::Mutation::None,
        ),
        objects: core::array::from_fn(|_| vec![]),
        pending: IndexedInsert {
            leaf: crate::tree::IndexedLeaf::default(),
            leaf_slot: 0,
            leaf_siblings: [Fp::ZERO; 32],
            slot: 1,
            slot_siblings: [Fp::ZERO; 32],
        },
        fee: IndexedInsert {
            leaf: crate::tree::IndexedLeaf::default(),
            leaf_slot: 0,
            leaf_siblings: [Fp::ZERO; 32],
            slot: 1,
            slot_siblings: [Fp::ZERO; 32],
        },
        q: [QInput {
            proof: vec![],
            instances: vec![],
        }],
        predecessor: PredecessorInput {
            proof: vec![],
            pallas: [0; 544],
            vesta: [0; 544],
        },
    }
}

#[test]
fn lean_schedule_has_two_or_three_a_by_quota_control_and_the_pinned_trivial_part() {
    assert_eq!(PLAIN_A_STAGE_COUNT, 2);
    assert_eq!(QUOTA_A_STAGE_COUNT, 3);
    assert_eq!(
        (0..4).map(a_stage_count).collect::<Vec<_>>(),
        [2, 3, 2, 3],
        "masks without the quota control pack both map insertions into A1"
    );
    assert_eq!(a_stage_count(4), 2);
    // No own sigma verifier: W0 folds the explicit pinned filler, exactly the words
    // every internal frame already uses for absent Vesta slots.
    let part = trivial_vesta_claim().unwrap();
    assert_eq!(part.source_k(), 16);
    assert_eq!(vesta_words(&part), trivial_vesta_words().unwrap());
    let public = internal_public(Fp::from(5), &part).unwrap();
    assert_eq!(public[1], Fp::from(16));
    assert_eq!(&public[2..22], &public[22..42]);
}

#[test]
fn all_four_signed_originals_bind_body_and_each_raw_signature_limb() {
    // Lean lineage: the certificate is carried by continuity, not re-verified.
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
            ObjectKind::Receipt
        ]
    );
    for kind in object_kinds() {
        let raw = (0..kind.body_len() + 64)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect::<Vec<_>>();
        let digest = object_digest(kind, &raw).unwrap();
        for index in [
            0,
            kind.body_len() - 1,
            kind.body_len(),
            kind.body_len() + 16,
            kind.body_len() + 32,
            kind.body_len() + 48,
        ] {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert_ne!(object_digest(kind, &changed).unwrap(), digest);
        }
        assert!(object_digest(kind, &raw[..raw.len() - 1]).is_err());
    }
}

// Binding-only fixture: the signature-Q public encoder is the independent
// export oracle. There are no actual signatures/proofs or admitted Send here.
fn bound_originals(held_fee: bool) -> (Inputs, OwnPolicy) {
    use iroha_plonk_gadgets::p256::native::{self, Affine};

    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let payment_key = native::mul(&Affine::GENERATOR, &[29, 0, 0, 0]).unwrap();
    let mut input = original(0);
    input.objects = object_kinds().map(|kind| {
        let mut raw = (0..kind.body_len() + 64)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>();
        raw[..2].copy_from_slice(&1_u16.to_le_bytes());
        raw
    });
    let sec1 = |key: Affine| {
        let mut raw = vec![4];
        for coordinate in [key.x, key.y] {
            for word in coordinate.iter().rev() {
                raw.extend(word.to_be_bytes());
            }
        }
        raw
    };
    input.objects[0][130..195].copy_from_slice(&sec1(payment_key));
    for (offset, value) in [(2, 3_u128), (18, 4)] {
        input.objects[0][offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(195, 31_u128), (211, 32)] {
        input.objects[0][offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
    let credential = object_digest(ObjectKind::Credential, &input.objects[0]).unwrap();
    for state in [&mut input.state.before, &mut input.state.after] {
        state.core[1] = Fp::from(3);
        state.core[2] = Fp::from(4);
        state.core[7] = credential;
        state.lineage[8] = credential;
    }
    input.state.before.lineage[6] = Fp::from(5);
    input.state.before.lineage[7] = Fp::from(6);
    for (coordinate, words) in [payment_key.x, payment_key.y].iter().enumerate() {
        input.state.before.lineage[9 + 2 * coordinate] =
            Fp::from_u128(u128::from(words[0]) | (u128::from(words[1]) << 64));
        input.state.before.lineage[10 + 2 * coordinate] =
            Fp::from_u128(u128::from(words[2]) | (u128::from(words[3]) << 64));
    }
    let held = if held_fee {
        object_digest(ObjectKind::FeeSchedule, &input.objects[2]).unwrap()
    } else {
        Fp::ZERO
    };
    input.state.before.rest[2] = held;
    input.objects[1][258..290].copy_from_slice(&held.to_repr());
    let fee = if held_fee { 9_u128 } else { 0 };
    input.objects[1][290..306].copy_from_slice(&fee.to_le_bytes());
    input.state.statement[3] = Fp::from(3);
    input.state.statement[4] = Fp::from(4);
    input.state.statement[7] = credential;
    input.state.statement[9] = Fp::from(10);
    input.state.statement[14] = Fp::from(11);
    input.state.statement[15] = Fp::from(12);
    input.state.statement[16] = Fp::from(3);
    input.state.statement[17] = Fp::from(13);
    // The pattern already gives the Request the credential's payer wallet and account;
    // its signed field terms must be canonical.
    for offset in [210, 314, 354] {
        input.objects[1][offset + 31] = 0;
    }
    input.state.statement[20] = Fp::from_u128(u128::from_le_bytes(
        input.objects[1][194..210].try_into().unwrap(),
    ));
    input.state.statement[22] = Fp::from_u128(fee);
    input.state.statement[23] = object_digest(ObjectKind::Request, &input.objects[1]).unwrap();
    bind_original_receipt(&mut input, policy);
    bind_original_signature_exports(&mut input, policy);
    (input, policy)
}

fn bind_original_receipt(input: &mut Inputs, policy: OwnPolicy) {
    let statement = &input.state.statement;
    let wallet = &input.state.before.lineage[6..8];
    let mut body = 1_u16.to_le_bytes().to_vec();
    for pair in [
        [statement[3], statement[4]],
        [wallet[0], wallet[1]],
        policy.provider.map(Fp::from_u128),
    ] {
        for word in pair {
            body.extend_from_slice(&word.to_repr()[..16]);
        }
    }
    body.extend_from_slice(&statement[9].to_repr()[..16]);
    // The proof digest names the Payment carriers, which Λ does not consume.
    let proof = [79; 97];
    for word in [
        hash_with_domain(
            u64::from_le_bytes(*b"kgwopid1"),
            &[wallet[0], wallet[1], statement[16], statement[17]],
        ),
        statement[14],
        statement[15],
        hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, statement),
        p_bytes_native(u64::from_le_bytes(*b"kgwprf_1"), &proof),
    ] {
        body.extend(word.to_repr());
    }
    body.extend([41; 32]);
    body.extend(Fp::ZERO.to_repr());
    assert_eq!(body.len(), ObjectKind::Receipt.body_len());
    input.objects[3][..body.len()].copy_from_slice(&body);
}

fn bind_original_signature_exports(input: &mut Inputs, policy: OwnPolicy) {
    use crate::q_signature::{QSignatureCircuit, SignatureSlot, SignatureWitness};
    use iroha_plonk_gadgets::p256::native::words_from_be;

    let _ = policy;
    let plan = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let witnesses = [3].map(|index| {
        let kind = object_kinds()[index];
        let raw = &input.objects[index];
        let end = kind.body_len();
        let key = [&input.objects[0][131..163], &input.objects[0][163..195]]
            .map(|bytes| words_from_be(bytes.try_into().unwrap()));
        SignatureWitness {
            digest: signed_message_native(kind, &raw[..end]),
            key,
            signature: core::array::from_fn(|half| {
                core::array::from_fn(|word| {
                    let start = end + half * 32 + (3 - word) * 8;
                    u64::from_be_bytes(raw[start..start + 8].try_into().unwrap())
                })
            }),
        }
    });
    input.q[0].instances = QSignatureCircuit::new(plan, witnesses.to_vec())
        .unwrap()
        .instances(&[true; 1])
        .unwrap()
        .to_vec();
}

#[test]
fn signed_send_original_admission_rejects_every_changed_original_byte() {
    let (source, policy) = bound_originals(true);
    assert_eq!(check_object_tapes(&source, policy), Ok(()));
    for object in 0..source.objects.len() {
        for byte in 0..source.objects[object].len() {
            let mut changed = source.clone();
            changed.objects[object][byte] ^= 1;
            assert_eq!(
                check_object_tapes(&changed, policy),
                Err(Error::Input),
                "object {object}, byte {byte}"
            );
        }
    }
}

#[test]
fn signed_send_original_admission_binds_the_unsigned_request_payer_fields() {
    // The receiver signs only the Request terms, so the payer wallet, account and
    // send ordinal leave the Request digest unchanged and bind separately.
    let (source, policy) = bound_originals(true);
    for offset in [66, 97, 98, 129, 194, 209] {
        let mut changed = source.clone();
        changed.objects[1][offset] ^= 1;
        assert_eq!(
            object_digest(ObjectKind::Request, &changed.objects[1]),
            object_digest(ObjectKind::Request, &source.objects[1])
        );
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "payer byte {offset}"
        );
    }
    let mut changed = source.clone();
    changed.state.statement[20] += Fp::ONE;
    bind_original_receipt(&mut changed, policy);
    bind_original_signature_exports(&mut changed, policy);
    assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
}

#[test]
fn signed_send_original_admission_binds_exact_signature_exports_and_shapes() {
    let (source, policy) = bound_originals(true);
    assert_eq!(check_object_tapes(&source, policy), Ok(()));
    for index in 0..10 {
        let mut changed = source.clone();
        changed.q[0].instances[0][index] += Fq::ONE;
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "export {index}"
        );
    }
    let mut changed = source.clone();
    changed.q[0].instances[0][9] = Fq::ZERO;
    assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    for public in [
        vec![],
        vec![vec![]],
        vec![vec![Fq::ONE; 9]],
        vec![vec![Fq::ONE; 11]],
        vec![vec![Fq::ONE; 10], vec![]],
        vec![source.q[0].instances[0].clone(); 3],
    ] {
        let mut changed = source.clone();
        changed.q[0].instances = public;
        assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    }
    for object in 0..4 {
        for length in [
            0,
            source.objects[object].len() - 1,
            source.objects[object].len() + 1,
        ] {
            let mut changed = source.clone();
            changed.objects[object].resize(length, 0);
            assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
        }
    }
}

#[test]
fn signed_send_original_admission_binds_state_statement_and_receipt_projections() {
    let (source, policy) = bound_originals(true);
    for mutation in 0..12 {
        let mut changed = source.clone();
        match mutation {
            0 => changed.state.before.core[7] += Fp::ONE,
            1 => changed.state.after.core[7] += Fp::ONE,
            2 => changed.state.before.lineage[8] += Fp::ONE,
            3 => changed.state.after.lineage[8] += Fp::ONE,
            4 => changed.state.statement[7] += Fp::ONE,
            5 => changed.state.statement[23] += Fp::ONE,
            6 => changed.state.before.rest[2] += Fp::ONE,
            7 => changed.state.before.lineage[9] += Fp::ONE,
            8 => changed.state.statement[14] += Fp::ONE,
            9 => changed.state.statement[15] += Fp::ONE,
            10 => changed.state.statement[9] += Fp::ONE,
            _ => changed.state.statement[17] += Fp::ONE,
        }
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "binding {mutation}"
        );
    }
    // Re-exporting a changed receipt does not replace its statement binding.
    for offset in [2, 34, 66, 98, 114, 146, 178, 210, 306] {
        let mut changed = source.clone();
        changed.objects[3][offset] ^= 1;
        bind_original_signature_exports(&mut changed, policy);
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "receipt {offset}"
        );
    }
    // The proof digest names the Payment carriers Λ does not consume: any nonzero
    // value under a valid signature is accepted, a zero one never.
    let mut changed = source.clone();
    changed.objects[3][242] ^= 1;
    bind_original_signature_exports(&mut changed, policy);
    assert_eq!(check_object_tapes(&changed, policy), Ok(()));
    for range in [242..274, 274..306] {
        let mut changed = source.clone();
        changed.objects[3][range].fill(0);
        bind_original_signature_exports(&mut changed, policy);
        assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    }
    let mut changed_policy = policy;
    changed_policy.provider[1] += 1;
    assert_eq!(
        check_object_tapes(&source, changed_policy),
        Err(Error::Input)
    );
    // The enrollment root is consulted only at Bootstrap and renewal.
    changed_policy = policy;
    changed_policy.root = policy.root.neg();
    assert_eq!(check_object_tapes(&source, changed_policy), Ok(()));
}

#[test]
fn absent_send_fee_preserves_fixed_dummy_policy_without_admitting_a_charge() {
    let (source, policy) = bound_originals(false);
    assert_eq!(check_object_tapes(&source, policy), Ok(()));
    for byte in 0..source.objects[2].len() {
        let mut changed = source.clone();
        changed.objects[2][byte] ^= 1;
        assert_eq!(
            check_object_tapes(&changed, policy),
            Ok(()),
            "dummy byte {byte}"
        );
    }
    let mut changed = source.clone();
    changed.objects[2].fill(255);
    assert_eq!(check_object_tapes(&changed, policy), Ok(()));
    for offset in [258, 290] {
        let mut changed = source.clone();
        changed.objects[1][offset] = 1;
        changed.state.statement[23] =
            object_digest(ObjectKind::Request, &changed.objects[1]).unwrap();
        bind_original_receipt(&mut changed, policy);
        bind_original_signature_exports(&mut changed, policy);
        assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    }
    let mut changed = source.clone();
    changed.state.statement[22] = Fp::ONE;
    bind_original_receipt(&mut changed, policy);
    bind_original_signature_exports(&mut changed, policy);
    assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    changed = source;
    changed.objects[2].pop();
    assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
}

#[test]
fn final_digest_has_exact52_fields_and_keeps_high_foreign_challenge_limbs() {
    let ep = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let eq = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let mut challenges = [Fq::ONE; K];
    challenges[15] = Fq::from(2).pow_vartime([200]);
    let pallas = FoldInput::from_normalized(ep, 16, challenges).unwrap();
    let fields = core::array::from_fn(|i| Fp::from(i as u64 + 1));
    let digest = terminal_digest(&fields, &pallas).unwrap();
    let (x, y) = Option::<(Fp, Fp)>::from(ep.coordinates()).unwrap();
    let mut expected = fields.to_vec();
    expected.extend([x, y]);
    for challenge in challenges {
        let repr = challenge.to_repr();
        expected.push(Fp::from_u128(u128::from_le_bytes(
            repr[..16].try_into().unwrap(),
        )));
        expected.push(Fp::from_u128(u128::from_le_bytes(
            repr[16..].try_into().unwrap(),
        )));
    }
    assert_eq!(expected.len(), 52);
    assert_eq!(
        digest,
        hash_with_domain(super::super::super::LINEAGE_DOMAIN, &expected)
    );
    challenges[15] = Fq::ONE;
    assert_ne!(
        digest,
        terminal_digest(
            &fields,
            &FoldInput::from_normalized(ep, 16, challenges).unwrap()
        )
        .unwrap()
    );
    let part = FoldInput::from_normalized(eq, 16, [Fp::ONE; K]).unwrap();
    let public = internal_public(digest, &part).unwrap();
    assert_eq!(public.len(), 69);
    assert_eq!(&public[62..65], &[Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(&public[22..42], &public[42..62]);
    assert_eq!(&public[65..69], &public[22..26]);
}

#[test]
fn fixed_controls_off_mask_rejects_each_foreign_control_source() {
    for index in 0..3 {
        let mut input = original(0);
        match index {
            0 => input.state.before.core[21] = Fp::ONE,
            1 => input.state.after.core[21] = Fp::ONE,
            _ => input.state.statement[11] = Fp::ONE,
        }
        assert_eq!(check_mask(&input, 0), Err(Error::Input));
    }
}

#[test]
fn all_four_send_masks_bind_both_states_and_the_statement() {
    for mask in 0..4 {
        let source = original(mask);
        assert_eq!(check_mask(&source, mask), Ok(()));
        for changed in 0..4 {
            if changed != mask {
                assert_eq!(check_mask(&source, changed), Err(Error::Input));
            }
        }
    }
    assert_eq!(check_mask(&original(0), 4), Err(Error::Input));
}

#[test]
fn every_mask_proves_its_own_relation_and_rejects_another_evaluation() {
    for mask in 0..4_u8 {
        let relation = SigmaRelation::send(u32::from(mask));
        let step = crate::vectors::sample_witness::<Fp>(
            u64::from(mask),
            relation,
            crate::vectors::Mutation::None,
        );
        let native = step.evaluate(relation);
        assert!(native.is_honest(), "mask {mask}");
        // The statement prepare compares against is the one A1 asserts field by
        // field; the mask itself is a constant of the installed shape.
        assert_eq!(native.statement[11], Fp::from(u64::from(mask)));
        let overdraft = crate::vectors::sample_witness::<Fp>(
            u64::from(mask),
            relation,
            crate::vectors::Mutation::Overdraft,
        );
        assert!(!overdraft.evaluate(relation).violations.is_empty());
    }
}
#[test]
fn exact_four_object_context_preserves_signed_request_and_total_fee_slot() {
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
            ObjectKind::Receipt
        ]
    );
    for kind in object_kinds() {
        let raw = (0..kind.body_len() + 64)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect::<Vec<_>>();
        let digest = object_digest(kind, &raw).unwrap();
        for i in [
            0,
            kind.body_len() - 1,
            kind.body_len(),
            kind.body_len() + 16,
            kind.body_len() + 32,
            kind.body_len() + 48,
        ] {
            let mut changed = raw.clone();
            changed[i] ^= 1;
            assert_ne!(object_digest(kind, &changed).unwrap(), digest);
        }
        assert!(object_digest(kind, &raw[..raw.len() - 1]).is_err());
    }
}
#[test]
fn original_bounds_reject_missing_oversized_and_over_domain_tables() {
    let config = ReadConfig {
        maximum_bytes: 16,
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    assert_eq!(original_bounds(&[], 1 << 16, config), Err(Error::Artifact));
    assert_eq!(
        original_bounds(&[0; 17], 1 << 16, config),
        Err(Error::Artifact)
    );
    assert_eq!(
        original_bounds(&[0; 16], (1 << 16) + 1, config),
        Err(Error::Artifact)
    );
    assert_eq!(original_bounds(&[0; 16], 1 << 16, config), Ok(()));
    // Passing these bounds alone never parses or admits an original proving key.
}

#[test]
fn identity_generator_claims_preserve_public_word_and_frame_encoding() {
    let p = iroha_plonk::transcript::decode_generator::<Ep>(&[0; 32]).unwrap();
    let v = iroha_plonk::transcript::decode_generator::<Eq>(&[0; 32]).unwrap();
    let p = FoldInput::<Ep>::from_normalized(p, 16, [Fq::ONE; K]).unwrap();
    let v = FoldInput::<Eq>::from_normalized(v, 16, [Fp::ONE; K]).unwrap();
    let mut pwords = Vec::new();
    push_pallas(&mut pwords, &p).unwrap();
    assert_eq!(&pwords[..3], &[Fp::from(16), Fp::ZERO, Fp::ZERO]);
    assert_eq!(pwords.len(), 35);
    let vwords = vesta_words(&v);
    assert_eq!(&vwords[..4], &[Fp::ZERO; 4]);
    assert_eq!(&vwords[4..], &[Fp::ONE; K]);
    let accumulated = AccumulatorT::<Eq>::new(*v.g(), [Fp::ONE; K]).unwrap();
    let public = omega_instances(Fp::from(23), &accumulated).unwrap();
    assert_eq!(public[0], [Fq::from(23)]);
    assert_eq!(public[1], [Fq::ZERO; 2]);
    assert_eq!(public[2], [Fq::ONE; K]);
}
