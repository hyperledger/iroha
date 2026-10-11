//! Pure exact-original and homogeneous-frame rejection tests, never an admitted Load.

use super::*;

fn original() -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
    };
    let state = LoadWitness {
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
        receipt: [0; LoadReceiptCells::BYTES],
        objects: core::array::from_fn(|_| vec![]),
        insertion: IndexedInsert {
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
                    vec![Fq::ONE],
                    vec![Fq::ONE],
                    vec![Fq::from(12)],
                ],
            },
            QInput {
                proof: vec![],
                instances: vec![],
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
fn exact_load_receipt_tape_matches_bound_statement_digest() {
    let mut source = original();
    // Only byte binding is under test; this synthetic tape grants no native
    // receipt, finality, state-transition or monetary admission authority.
    source.state.statement[17] = p_bytes_native::<Fp>(LoadReceiptCells::DOMAIN, &source.receipt);
    assert_eq!(check_receipt_tape(&source), Ok(()));
    for offset in 0..LoadReceiptCells::BYTES {
        let mut bad = source.clone();
        bad.receipt[offset] ^= 1;
        assert_eq!(check_receipt_tape(&bad), Err(Error::Input), "byte {offset}");
    }
    let mut foreign_domain = source.clone();
    foreign_domain.state.statement[17] =
        p_bytes_native::<Fp>(u64::from_le_bytes(*b"kgwstep1"), &source.receipt);
    assert_eq!(check_receipt_tape(&foreign_domain), Err(Error::Input));
    let mut changed_statement = source;
    changed_statement.state.statement[17] += Fp::ONE;
    assert_eq!(check_receipt_tape(&changed_statement), Err(Error::Input));
}

#[test]
fn exact_load_sigma_tape_statement_length_and_selector_are_bound() {
    let source = original();
    assert_eq!(check_sigma_tape(&source), Ok(()));
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
            check_sigma_tape(&bad),
            Err(Error::Input),
            "mutation{mutation}"
        );
    }
}

#[test]
fn load_q_sigma_normalization_rejects_wrong_selector_source_or_scalar_alias() {
    let mut input = original().q[0].clone();
    let point = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let (x, y) = Option::<(Fq, Fq)>::from(point.coordinates()).unwrap();
    input.instances[1] = vec![x, y];
    let n = input.instances[0].len();
    input.instances[0][n - K..n - K + 4].fill(Fq::ZERO);
    assert!(q_sigma_part(&input, 12).is_ok());
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
        assert!(q_sigma_part(&bad, 12).is_err(), "mutation{mutation}");
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
    assert!(q_sigma_part(&alias, 12).is_err());
}

#[test]
fn all_three_signed_originals_bind_body_and_each_raw_signature_limb() {
    assert_eq!(
        object_kinds(),
        [
            ObjectKind::Receipt,
            ObjectKind::Certificate,
            ObjectKind::Credential
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
fn original_key_bounds_reject_empty_oversized_and_excess_domain() {
    let config = ReadConfig {
        maximum_bytes: 16,
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    assert_eq!(original_bounds(&[1; 16], 1 << 16, config), Ok(()));
    assert_eq!(original_bounds(&[], 1 << 16, config), Err(Error::Artifact));
    assert_eq!(
        original_bounds(&[1; 17], 1 << 16, config),
        Err(Error::Artifact)
    );
    assert_eq!(
        original_bounds(&[1], (1 << 16) + 1, config),
        Err(Error::Artifact)
    );
}

#[test]
fn fourth_checkpoint_is_terminal_and_out_of_range_source_is_rejected() {
    assert_eq!(A_STAGE_COUNT, 4);
    assert_eq!(
        crate::a_relation::schedule::compiled::OperationSchedule::for_variant(Variant::Load)
            .stage_count(),
        A_STAGE_COUNT
    );
    for stage in 0..A_STAGE_COUNT {
        assert_eq!(checkpoint_stage(stage), Ok(()));
    }
    assert_eq!(checkpoint_stage(A_STAGE_COUNT), Err(Error::Input));
    assert_eq!(checkpoint_stage(usize::MAX), Err(Error::Input));
}
