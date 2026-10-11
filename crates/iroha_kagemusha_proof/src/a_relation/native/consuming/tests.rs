//! Pure exact-original and homogeneous-frame rejection tests, never an admitted consuming transition.

use super::*;

fn original() -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
    };
    let state = ConsumingWitness {
        predecessor: state,
        successor: state,
        statement: [Fp::ZERO; 26],
    };
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
        recovery: None,
        q: [
            QInput {
                proof: vec![],
                instances: vec![
                    bounded,
                    vec![],
                    vec![Fq::from(13)],
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
fn exact_consuming_sigma_tape_statement_length_and_selector_are_bound() {
    for (variant, selector) in [(Variant::Unload, 13), (Variant::Retiring, 15)] {
        let mut source = original();
        source.q[0].instances[2][0] = Fq::from(selector);
        assert_eq!(check_sigma_tape(&source, variant), Ok(()));
        for mutation in 0..6 {
            let mut bad = source.clone();
            match mutation {
                0 => bad.sigma[40] ^= 1,
                1 => bad.sigma.push(7),
                2 => bad.q[0].instances[0][1] += Fq::ONE,
                3 => bad.q[0].instances[2][0] = Fq::ZERO,
                4 => bad.q[0].instances[2][0] = Fq::from(2),
                _ => bad.state.statement[20] += Fp::ONE,
            }
            assert_eq!(
                check_sigma_tape(&bad, variant),
                Err(Error::Input),
                "mutation{mutation}"
            );
        }
    }
}

#[test]
fn consuming_q_sigma_normalization_rejects_wrong_selector_source_or_scalar_alias() {
    for (variant, selector) in [(Variant::Unload, 13), (Variant::Retiring, 15)] {
        let mut input = original().q[0].clone();
        input.instances[2][0] = Fq::from(selector);
        let point = iroha_plonk::transcript::decode_point::<Eq>(
            &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
        )
        .unwrap();
        let (x, y) = Option::<(Fq, Fq)>::from(point.coordinates()).unwrap();
        input.instances[1] = vec![x, y];
        let n = input.instances[0].len();
        input.instances[0][n - K..n - K + 4].fill(Fq::ZERO);
        assert!(q_sigma_part(&input, 12, variant).is_ok());
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
            assert!(
                q_sigma_part(&bad, 12, variant).is_err(),
                "mutation{mutation}"
            );
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
        assert!(q_sigma_part(&alias, 12, variant).is_err());
    }
}

#[test]
fn all_three_signed_originals_bind_body_and_each_raw_signature_limb() {
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Credential,
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
fn retiring_has_its_own_sigma_selector_and_unrelated_variants_reject() {
    let mut source = original();
    assert_eq!(
        check_sigma_tape(&source, Variant::Retiring),
        Err(Error::Input)
    );
    source.q[0].instances[2][0] = Fq::from(15);
    assert_eq!(check_sigma_tape(&source, Variant::Retiring), Ok(()));
    assert_eq!(
        check_sigma_tape(&source, Variant::Unload),
        Err(Error::Input)
    );
    assert_eq!(
        check_sigma_tape(&source, Variant::Load),
        Err(Error::Artifact)
    );
}

#[test]
fn original_lineage_bytes_bind_every_byte_without_truncating_limbs() {
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
    let mut fields = [Fp::ONE; 18];
    let proof = vec![0x37; 3_712];
    let raw = lineage_bytes(&fields, &proof, &p, &v).unwrap();
    assert_eq!(raw.len(), 320 + proof.len() + 544 + 544);
    assert_eq!(&raw[320..320 + proof.len()], &proof);
    assert_eq!(
        &raw[320 + proof.len()..320 + proof.len() + 544],
        p.to_bytes()
    );
    assert_eq!(&raw[320 + proof.len() + 544..], v.to_bytes());
    let framed = frame(&raw).unwrap();
    assert_eq!(&framed[4..], raw);
    assert_eq!(
        &framed[..4],
        u32::try_from(raw.len()).unwrap().to_le_bytes()
    );
    for (index, width) in [(1, 128), (6, 128), (9, 128), (13, 104), (14, 128)] {
        fields[index] = Fp::from(2).pow_vartime([width]);
        assert_eq!(lineage_bytes(&fields, &proof, &p, &v), Err(Error::Input));
        fields[index] = Fp::ONE;
    }
    fields[0] = Fp::from(2);
    assert_eq!(lineage_bytes(&fields, &proof, &p, &v), Err(Error::Input));
}

#[test]
fn uniform_omega_transport_cap_rejects_generic_profiles_without_a_fallback() {
    assert_eq!(OMEGA_TRANSPORT_CAP, 4_821);
    assert_eq!(check_omega_transport_length(3_712), Ok(()));
    for size in [0, 1, 3_733, 3_744, 11_360 - 1_088, usize::MAX] {
        assert_eq!(
            check_omega_transport_length(size),
            Err(Error::Input),
            "size {size}"
        );
    }
}

#[test]
fn consuming_lineage_tape_preserves_exact_public_and_both_complete_claim_originals() {
    let ep = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let eq = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    // Encoding fixtures, not deciding accumulator witnesses or accepted financial proofs.
    let p = AccumulatorT::new(ep, [Fq::ONE; K]).unwrap();
    let v = AccumulatorT::new(eq, [Fp::ONE; K]).unwrap();
    let mut fields = core::array::from_fn(|i| Fp::from(i as u64 + 1));
    fields[0] = Fp::ONE;
    let proof = (0..64).collect::<Vec<_>>();
    let original = lineage_bytes(&fields, &proof, &p, &v).unwrap();
    assert_eq!(original.len(), 320 + 64 + 2 * 544);
    assert_eq!(&original[..2], &[1, 0]);
    assert_eq!(&original[320..384], proof);
    assert_eq!(&original[384..928], p.to_bytes());
    assert_eq!(&original[928..], v.to_bytes());
    // Exactly the original public transcript; the admitted VK digest is already
    // constrained by the verified predecessor and is not a second copied field.
    assert_eq!(original[162], 4);
    assert_eq!(
        &original[163..179],
        fields[10].to_repr()[..16]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
    );
    for index in 1..17 {
        let mut changed = fields;
        changed[index] += Fp::ONE;
        assert_ne!(
            lineage_bytes(&changed, &proof, &p, &v).unwrap(),
            original,
            "public field {index}"
        );
    }
    let mut changed = proof.clone();
    changed[63] ^= 1;
    assert_ne!(lineage_bytes(&fields, &changed, &p, &v).unwrap(), original);
    let p2 = AccumulatorT::new(ep, [Fq::from(2); K]).unwrap();
    assert_ne!(lineage_bytes(&fields, &proof, &p2, &v).unwrap(), original);
    let v2 = AccumulatorT::new(eq, [Fp::from(2); K]).unwrap();
    assert_ne!(lineage_bytes(&fields, &proof, &p, &v2).unwrap(), original);
    for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
        let mut changed = fields;
        changed[index] = Fp::from(2).pow_vartime([128]);
        assert_eq!(lineage_bytes(&changed, &proof, &p, &v), Err(Error::Input));
    }
    let mut bad = fields;
    bad[13] = Fp::from(2).pow_vartime([104]);
    assert_eq!(lineage_bytes(&bad, &proof, &p, &v), Err(Error::Input));
    bad = fields;
    bad[0] = Fp::from(2);
    assert_eq!(lineage_bytes(&bad, &proof, &p, &v), Err(Error::Input));
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
