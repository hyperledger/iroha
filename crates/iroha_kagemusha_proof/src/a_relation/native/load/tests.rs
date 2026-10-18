//! Pure exact-original and homogeneous-frame rejection tests, never an admitted Load.

use super::*;
use iroha_pasta::PastaAffine;

fn original() -> Inputs {
    let state = StateWitness {
        core: [Fp::ZERO; 29],
        rest: [Fp::ZERO; 6],
        lineage: [Fp::ZERO; 18],
    };
    let state = LoadWitness {
        predecessor: state,
        successor: state,
        statement: [Fp::ZERO; 26],
    };
    Inputs {
        state,
        receipt: [0; LoadReceiptCells::BYTES],
        objects: core::array::from_fn(|_| vec![]),
        insertion: IndexedInsert {
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
fn lean_load_forwards_the_pinned_trivial_part_without_a_sigma_verifier() {
    // Λ proves the Load transition in A1; the part W0 folds is the pinned trivial claim.
    let part = trivial_vesta_claim().unwrap();
    assert_eq!(part.source_k(), 16);
    assert_eq!(part.challenges(), &[Fp::ONE; K]);
    assert_eq!(
        *part.g(),
        iroha_plonk::transcript::decode_point::<Eq>(
            &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR
        )
        .unwrap()
    );
    assert_eq!(vesta_words(&part), trivial_vesta_words().unwrap());
}

#[test]
fn own_receipt_original_binds_body_and_each_raw_signature_limb() {
    // The credential and certificate are carried by continuity, not re-verified (R10).
    assert_eq!(object_kinds(), [ObjectKind::Receipt]);
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
fn second_checkpoint_is_terminal_and_out_of_range_source_is_rejected() {
    assert_eq!(A_STAGE_COUNT, 2);
    assert_eq!(W_STAGE_COUNT, 1);
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
