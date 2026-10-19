//! Pure exact-original and homogeneous-frame rejection tests, never an admitted consuming transition.

use super::*;
use iroha_pasta::PastaAffine;

#[test]
fn lean_schedule_is_one_terminal_a_owning_q0_and_both_tasks() {
    assert_eq!(A_STAGE_COUNT, 1);
    for (variant, effect) in [
        (Variant::Unload, OperationTask::UnloadRecovery),
        (Variant::Retiring, OperationTask::RetiringState),
    ] {
        let schedule =
            crate::a_relation::schedule::compiled::OperationSchedule::for_variant(variant);
        // No W: the one stage verifies the hard predecessor and the own receipt Q0
        // and proves the transition and the authorization beside them.
        assert_eq!(schedule.stage_count(), A_STAGE_COUNT);
        assert_eq!(schedule.q_partitions(), [vec![0]]);
        assert_eq!(
            schedule.tasks(),
            [vec![effect, OperationTask::UnloadAuthorization]]
        );
    }
}

#[test]
fn terminal_frame_keeps_the_pinned_trivial_part_and_the_predecessor_slot() {
    // No own sigma verifier and no W: the part slot is the explicit pinned filler,
    // exactly the words of the absent incoming slot.
    let part = trivial_vesta_claim().unwrap();
    assert_eq!(part.source_k(), 16);
    assert_eq!(vesta_words(&part), trivial_vesta_words().unwrap());
    let ep = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let pallas = FoldInput::from_normalized(ep, 16, [Fq::ONE; K]).unwrap();
    let predecessor = FoldInput::<Eq>::from_normalized(*part.g(), 16, [Fp::from(3); K]).unwrap();
    let fields = core::array::from_fn(|i| Fp::from(i as u64 + 1));
    let public = terminal_public(&fields, &pallas, &predecessor).unwrap();
    assert_eq!(public.len(), 69);
    assert_eq!(public[0], terminal_digest(&fields, &pallas).unwrap());
    assert_eq!(public[1], Fp::from(16));
    assert_eq!(&public[2..22], trivial_vesta_words().unwrap().as_slice());
    assert_eq!(&public[22..42], vesta_words(&predecessor).as_slice());
    assert_eq!(&public[2..22], &public[42..62]);
    assert_eq!(&public[62..65], &[Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(&public[65..69], &public[2..6]);
    // The folded Pallas claim enters `D_A` only; every other word is fixed by the
    // predecessor obligation and the pinned filler.
    let mut challenges = *pallas.challenges();
    challenges[15] = Fq::from(2).pow_vartime([200]);
    let changed = FoldInput::from_normalized(ep, 16, challenges).unwrap();
    let altered = terminal_public(&fields, &changed, &predecessor).unwrap();
    assert_ne!(altered[0], public[0]);
    assert_eq!(&altered[1..], &public[1..]);
    // A different predecessor obligation changes only its own slot.
    let other = terminal_public(&fields, &pallas, &part).unwrap();
    assert_eq!(other[..22], public[..22]);
    assert_ne!(other[22..42], public[22..42]);
    assert_eq!(other[42..], public[42..]);
    // Only a full k16 fold output can be bound as the Pallas claim.
    let short = FoldInput::<Ep>::from_opening(ep, &[Fq::ONE; 12]).unwrap();
    assert_eq!(
        terminal_public(&fields, &short, &predecessor),
        Err(Error::Input)
    );
}

#[test]
fn own_receipt_original_binds_body_and_each_raw_signature_limb() {
    // Lean lineage: the credential and certificate are carried by continuity.
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
    let predecessor = FoldInput::from_normalized(eq, 16, [Fp::ONE; K]).unwrap();
    let public = terminal_public(&fields, &pallas, &predecessor).unwrap();
    assert_eq!(public.len(), 69);
    assert_eq!(public[0], digest);
    assert_eq!(&public[62..65], &[Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(&public[2..22], &public[42..62]);
    assert_eq!(&public[65..69], &public[2..6]);
}

#[test]
fn uniform_omega_transport_cap_rejects_generic_profiles_without_a_fallback() {
    assert_eq!(OMEGA_TRANSPORT_CAP, 5_086);
    for size in (32..=3_968).step_by(32) {
        assert_eq!(check_omega_transport_length(size), Ok(()), "size {size}");
    }
    assert_eq!(check_omega_transport_length(3_872), Ok(()));
    assert_eq!(check_omega_transport_length(3_904), Ok(()));
    for size in [0, 1, 3_733, 4_000, 11_360 - 1_088, usize::MAX] {
        assert_eq!(
            check_omega_transport_length(size),
            Err(Error::Input),
            "size {size}"
        );
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
    let identity = terminal_public(&[Fp::ZERO; 18], &p, &v).unwrap();
    assert_eq!(identity.len(), 69);
    assert_eq!(&identity[22..42], vwords.as_slice());
    let accumulated = AccumulatorT::<Eq>::new(*v.g(), [Fp::ONE; K]).unwrap();
    let public = omega_instances(Fp::from(23), &accumulated).unwrap();
    assert_eq!(public[0], [Fq::from(23)]);
    assert_eq!(public[1], [Fq::ZERO; 2]);
    assert_eq!(public[2], [Fq::ONE; K]);
}
