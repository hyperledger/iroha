//! Pure exact-original and homogeneous-frame rejection tests, never an admitted Send.

use super::*;

fn original(mask: u8) -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
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
    let sigma = (0..64).collect::<Vec<u8>>();
    let mut raw = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    raw.extend(&sigma);
    let statement = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &state.statement,
    );
    let mut bounded = vec![Fq::from_repr(statement.to_repr()).unwrap()];
    bounded.extend(raw.chunks(31).map(|chunk| le_value::<Fq>(chunk).unwrap()));
    bounded.extend([Fq::ONE; K]);
    Inputs {
        state,
        sigma,
        omega: vec![],
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
        q: [
            QInput {
                proof: vec![],
                instances: vec![
                    bounded,
                    vec![],
                    vec![send_selector(mask).unwrap()],
                    vec![Fq::ONE],
                    vec![Fq::from(12)],
                ],
            },
            QInput {
                proof: vec![],
                instances: vec![],
            },
        ],
        predecessor: PredecessorInput {
            proof: vec![],
            pallas: [0; 544],
            vesta: [0; 544],
        },
    }
}

#[test]
fn exact_send_sigma_tape_statement_length_and_selector_are_bound() {
    let source = original(0);
    assert_eq!(check_sigma_tape(&source, 0), Ok(()));
    for mutation in 0..6 {
        let mut bad = source.clone();
        match mutation {
            0 => bad.sigma[40] ^= 1,
            1 => bad.sigma.push(7),
            2 => bad.q[0].instances[0][1] += Fq::ONE,
            3 => bad.q[0].instances[2][0] = Fq::ZERO,
            4 => bad.q[0].instances[2][0] = Fq::from(3),
            _ => bad.state.statement[20] += Fp::ONE,
        }
        assert_eq!(
            check_sigma_tape(&bad, 0),
            Err(Error::Input),
            "mutation{mutation}"
        );
    }
}

#[test]
fn send_q_sigma_normalization_rejects_wrong_selector_source_or_scalar_alias() {
    let mut input = original(0).q[0].clone();
    let point = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let (x, y) = Option::<(Fq, Fq)>::from(point.coordinates()).unwrap();
    input.instances[1] = vec![x, y];
    let n = input.instances[0].len();
    input.instances[0][n - K..n - K + 4].fill(Fq::ZERO);
    assert!(q_sigma_part(&input, 12, 0).is_ok());
    for mutation in 0..6 {
        let mut bad = input.clone();
        match mutation {
            0 => bad.instances[0][n - K] = Fq::ONE,
            1 => bad.instances[0][n - 1] = Fq::ZERO,
            2 => bad.instances[1] = vec![Fq::ZERO, Fq::ZERO],
            3 => bad.instances[3][0] = Fq::ZERO,
            4 => bad.instances[4][0] = Fq::from(16),
            _ => bad.instances[2][0] = Fq::ZERO,
        }
        assert!(q_sigma_part(&bad, 12, 0).is_err(), "mutation{mutation}");
    }
    let p = [
        0x992d_30ed_0000_0001_u64,
        0x2246_98fc_094c_f91b,
        0,
        0x4000_0000_0000_0000,
    ];
    let mut repr = [0; 32];
    for (to, word) in repr.chunks_exact_mut(8).zip(p) {
        to.copy_from_slice(&word.to_le_bytes());
    }
    let mut alias = input;
    alias.instances[0][n - 1] = Fq::from_repr(repr).unwrap();
    assert!(q_sigma_part(&alias, 12, 0).is_err());
}

#[test]
fn all_five_signed_originals_bind_body_and_each_raw_signature_limb() {
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
            ObjectKind::Certificate,
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
    let enrollment_key = native::mul(&Affine::GENERATOR, &[17, 0, 0, 0]).unwrap();
    let mut input = original(0);
    input.omega = vec![79; 97];
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
    for (object, offset, key) in [(0, 130, payment_key), (3, 35, enrollment_key)] {
        input.objects[object][offset..offset + 65].copy_from_slice(&sec1(key));
    }
    input.objects[3][34] = 1;
    for object in [0, 3] {
        for (offset, value) in [(2, 3_u128), (18, 4)] {
            input.objects[object][offset..offset + 16].copy_from_slice(&value.to_le_bytes());
        }
    }
    for (offset, value) in [(195, 31_u128), (211, 32)] {
        input.objects[0][offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
    let certificate = object_digest(ObjectKind::Certificate, &input.objects[3]).unwrap();
    input.objects[0][444..476].copy_from_slice(&certificate.to_repr());
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
    let mut proof = frame(&input.omega).unwrap();
    proof.extend(frame(&input.sigma).unwrap());
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
    input.objects[4][..body.len()].copy_from_slice(&body);
}

fn bind_original_signature_exports(input: &mut Inputs, policy: OwnPolicy) {
    use crate::q_signature::{QSignatureCircuit, SignatureSlot, SignatureWitness};
    use iroha_plonk_gadgets::p256::native::words_from_be;

    let plan = QSignaturePlan::new(vec![
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        },
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        },
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Fixed(policy.root),
        },
    ])
    .unwrap();
    let witnesses = [4, 0, 3].map(|index| {
        let kind = object_kinds()[index];
        let raw = &input.objects[index];
        let end = kind.body_len();
        let key = match index {
            4 => [&input.objects[0][131..163], &input.objects[0][163..195]]
                .map(|bytes| words_from_be(bytes.try_into().unwrap())),
            0 => [&input.objects[3][36..68], &input.objects[3][68..100]]
                .map(|bytes| words_from_be(bytes.try_into().unwrap())),
            _ => [policy.root.x, policy.root.y],
        };
        SignatureWitness {
            digest: p_bytes_native(kind.signing_domain(), &raw[..end]),
            key,
            signature: core::array::from_fn(|half| {
                core::array::from_fn(|word| {
                    let start = end + half * 32 + (3 - word) * 8;
                    u64::from_be_bytes(raw[start..start + 8].try_into().unwrap())
                })
            }),
        }
    });
    input.q[1].instances = QSignatureCircuit::new(plan, witnesses.to_vec())
        .unwrap()
        .instances(&[true; 3])
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
fn signed_send_original_admission_binds_exact_signature_exports_and_shapes() {
    let (source, policy) = bound_originals(true);
    assert_eq!(check_object_tapes(&source, policy), Ok(()));
    for index in 0..30 {
        let mut changed = source.clone();
        changed.q[1].instances[0][index] += Fq::ONE;
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "export {index}"
        );
    }
    for index in [9, 19, 29] {
        let mut changed = source.clone();
        changed.q[1].instances[0][index] = Fq::ZERO;
        assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    }
    let mut swapped = source.clone();
    for index in 0..10 {
        swapped.q[1].instances[0].swap(index, index + 10);
    }
    assert_eq!(check_object_tapes(&swapped, policy), Err(Error::Input));
    for public in [
        vec![],
        vec![vec![]],
        vec![vec![Fq::ONE; 29]],
        vec![vec![Fq::ONE; 31]],
        vec![vec![Fq::ONE; 30], vec![]],
    ] {
        let mut changed = source.clone();
        changed.q[1].instances = public;
        assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    }
    for object in 0..5 {
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
    for mutation in 0..14 {
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
            11 => changed.state.statement[17] += Fp::ONE,
            12 => changed.sigma[0] ^= 1,
            _ => changed.omega[0] ^= 1,
        }
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "binding {mutation}"
        );
    }
    // Re-exporting a changed receipt does not replace its statement/proof binding.
    for offset in [2, 34, 66, 98, 114, 146, 178, 210, 242, 306] {
        let mut changed = source.clone();
        changed.objects[4][offset] ^= 1;
        bind_original_signature_exports(&mut changed, policy);
        assert_eq!(
            check_object_tapes(&changed, policy),
            Err(Error::Input),
            "receipt {offset}"
        );
    }
    let mut changed = source.clone();
    changed.objects[4][274..306].fill(0);
    bind_original_signature_exports(&mut changed, policy);
    assert_eq!(check_object_tapes(&changed, policy), Err(Error::Input));
    let mut changed_policy = policy;
    changed_policy.provider[1] += 1;
    assert_eq!(
        check_object_tapes(&source, changed_policy),
        Err(Error::Input)
    );
    changed_policy = policy;
    changed_policy.root = policy.root.neg();
    assert_eq!(
        check_object_tapes(&source, changed_policy),
        Err(Error::Input)
    );
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
        assert_eq!(check_sigma_tape(&input, 0), Err(Error::Input));
    }
}

#[test]
fn consuming_originals_use_exact_public320_proof_and_two544_claims() {
    let p = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let v = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let p = AccumulatorT::new(p, [Fq::ONE; K]).unwrap();
    let v = AccumulatorT::new(v, [Fp::ONE; K]).unwrap();
    let fields = core::array::from_fn(|i| Fp::from(u64::try_from(i + 1).unwrap()));
    let proof = vec![41; 3712];
    let tape = lineage_bytes(&fields, &proof, &p, &v).unwrap();
    assert_eq!(tape.len(), 320 + 3712 + 1088);
    assert_eq!(tape[0..2], 1_u16.to_le_bytes());
    assert_eq!(tape[162], 4);
    assert_eq!(
        tape[163..179],
        fields[10].to_repr()[..16]
            .iter()
            .copied()
            .rev()
            .collect::<Vec<_>>()
    );
    assert_eq!(tape[320..4032], proof);
    assert_eq!(tape[4032..4576], p.to_bytes());
    assert_eq!(tape[4576..], v.to_bytes());
    let framed = frame(&tape).unwrap();
    assert_eq!(
        framed[..4],
        u32::try_from(tape.len()).unwrap().to_le_bytes()
    );
    assert_eq!(framed[4..], tape);
    for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
        let mut changed = fields;
        changed[index] += Fp::from(2).pow_vartime([128]);
        assert_eq!(lineage_bytes(&changed, &proof, &p, &v), Err(Error::Input));
    }
    let mut changed = fields;
    changed[13] += Fp::from(2).pow_vartime([104]);
    assert_eq!(lineage_bytes(&changed, &proof, &p, &v), Err(Error::Input));
    changed = fields;
    changed[0] = Fp::from(2);
    assert_eq!(lineage_bytes(&changed, &proof, &p, &v), Err(Error::Input));
    // Omega's key identity is checked separately against the exact predecessor VK.
    changed = fields;
    changed[17] += Fp::ONE;
    assert_eq!(lineage_bytes(&changed, &proof, &p, &v).unwrap(), tape);
    for index in [5, 8, 15, 16] {
        changed = fields;
        changed[index] += Fp::ONE;
        assert_ne!(lineage_bytes(&changed, &proof, &p, &v).unwrap(), tape);
    }
}

#[test]
fn all_eight_send_selectors_bind_the_exact_original_sigma_and_statement() {
    for mask in 0..8 {
        let source = original(mask);
        assert_eq!(check_sigma_tape(&source, mask), Ok(()));
        for changed in 0..8 {
            if changed != mask {
                assert_eq!(check_sigma_tape(&source, changed), Err(Error::Input));
            }
        }
        let mut bad = source.clone();
        bad.sigma[40] ^= 1;
        assert_eq!(check_sigma_tape(&bad, mask), Err(Error::Input));
        let mut bad = source.clone();
        bad.state.statement[20] += Fp::ONE;
        assert_eq!(check_sigma_tape(&bad, mask), Err(Error::Input));
    }
}
#[test]
fn both_source_classes_require_exact_challenge_normalization_and_hard_verdict() {
    let eq = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let (x, y) = Option::<(Fq, Fq)>::from(eq.coordinates()).unwrap();
    for k in [12_u32, 14] {
        let mut q = original(0).q[0].clone();
        q.instances[1] = vec![x, y];
        q.instances[4] = vec![Fq::from(u64::from(k))];
        let n = q.instances[0].len();
        q.instances[0][n - K..n - k as usize].fill(Fq::ZERO);
        assert!(q_sigma_part(&q, k, 0).is_ok());
        let mut bad = q.clone();
        bad.instances[0][n - k as usize] = Fq::ZERO;
        assert!(q_sigma_part(&bad, k, 0).is_err());
        let mut bad = q.clone();
        bad.instances[0][n - K] = Fq::ONE;
        assert!(q_sigma_part(&bad, k, 0).is_err());
        let mut bad = q.clone();
        bad.instances[3][0] = Fq::ZERO;
        assert!(q_sigma_part(&bad, k, 0).is_err());
    }
}
#[test]
fn exact_five_object_context_preserves_signed_request_and_total_fee_slot() {
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
            ObjectKind::Certificate,
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
fn consuming_lineage_has_exact320_original_public_bytes_and_both_claims() {
    let ep = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let eq = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let p = AccumulatorT::new(ep, [Fq::ONE; K]).unwrap();
    let v = AccumulatorT::new(eq, [Fp::ONE; K]).unwrap();
    let mut fields = core::array::from_fn(|i| Fp::from(i as u64 + 1));
    fields[0] = Fp::ONE;
    let raw = lineage_bytes(&fields, &[13; 64], &p, &v).unwrap();
    assert_eq!(raw.len(), 320 + 64 + 2 * 544);
    assert_eq!(&raw[320..384], &[13; 64]);
    assert_eq!(&raw[384..928], &p.to_bytes());
    assert_eq!(&raw[928..], &v.to_bytes());
    for i in [1, 6, 9, 13, 14] {
        let mut bad = fields;
        bad[i] = Fp::from(2).pow_vartime([200]);
        assert!(lineage_bytes(&bad, &[13; 64], &p, &v).is_err());
    }
    let framed = frame(&raw).unwrap();
    assert_eq!(
        u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize,
        raw.len()
    );
    assert_eq!(&framed[4..], raw);
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
