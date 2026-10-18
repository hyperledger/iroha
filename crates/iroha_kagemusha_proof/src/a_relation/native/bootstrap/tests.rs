//! Source-frame encodings, original digests and bounds. No fixture is an admitted operation.
use super::*;

#[path = "tests/source_ownership.rs"]
mod source_ownership;

#[test]
fn exact_signed_original_digest_binds_body_and_both_raw_signature_halves() {
    for kind in object_kinds() {
        let bytes = (0..kind.body_len() + 64)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect::<Vec<_>>();
        let digest = object_digest(kind, &bytes).unwrap();
        for index in [
            0,
            kind.body_len() - 1,
            kind.body_len(),
            kind.body_len() + 16,
            kind.body_len() + 32,
            kind.body_len() + 48,
        ] {
            let mut bad = bytes.clone();
            bad[index] ^= 1;
            assert_ne!(object_digest(kind, &bad).unwrap(), digest);
        }
        assert!(object_digest(kind, &bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn homogeneous_frame_binds_high_foreign_challenge_limbs_and_fixed_trivial_slots() {
    let ep = decode_point::<Ep>(&iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR).unwrap();
    let pallas = FoldInput::from_normalized(ep, 16, [Fq::ONE; K]).unwrap();
    let fields = std::array::from_fn(|i| Fp::from(i as u64 + 1));
    let public = frame(&fields, &pallas).unwrap();
    assert_eq!(public.len(), 69);
    // No sigma verifier exists: the part is the pinned trivial Vesta filler at
    // source k16, identical to the absent predecessor and incoming slots.
    let trivial = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    let (x, y) = Option::<(Fq, Fq)>::from(trivial.coordinates()).unwrap();
    let coordinates = [x, y]
        .into_iter()
        .flat_map(|v| foreign_limbs(&v).map(Fp::from_u128))
        .collect::<Vec<_>>();
    assert_eq!(public[1], Fp::from(16));
    for start in [2, 22, 42] {
        assert_eq!(&public[start..start + 4], coordinates.as_slice());
        assert_eq!(&public[start + 4..start + 20], &[Fp::ONE; K]);
    }
    assert_eq!(&public[62..65], &[Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(&public[65..], coordinates.as_slice());
    let mut challenges = *pallas.challenges();
    challenges[15] = Fq::from(2).pow_vartime([200]);
    let changed = FoldInput::from_normalized(ep, 16, challenges).unwrap();
    let altered = frame(&fields, &changed).unwrap();
    assert_ne!(altered[0], public[0]);
    assert_eq!(&altered[1..], &public[1..]);
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
fn identity_and_short_pallas_claims_keep_the_exact_frame_encoding() {
    let p = iroha_plonk::transcript::decode_generator::<Ep>(&[0; 32]).unwrap();
    let p = FoldInput::<Ep>::from_normalized(p, 16, [Fq::ONE; K]).unwrap();
    let mut pwords = Vec::new();
    push_pallas(&mut pwords, &p).unwrap();
    assert_eq!(&pwords[..3], &[Fp::from(16), Fp::ZERO, Fp::ZERO]);
    assert_eq!(pwords.len(), 35);
    let identity = frame(&[Fp::ZERO; 18], &p).unwrap();
    assert_eq!(identity.len(), 69);
    // The forwarded Pallas claim enters D_A only; every Vesta slot is fixed.
    let ep = decode_point::<Ep>(&iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR).unwrap();
    let finite = FoldInput::<Ep>::from_normalized(ep, 16, [Fq::ONE; K]).unwrap();
    let finite = frame(&[Fp::ZERO; 18], &finite).unwrap();
    assert_ne!(identity[0], finite[0]);
    assert_eq!(&identity[1..], &finite[1..]);
    // Only a full k16 Q opening can be forwarded as the Pallas claim.
    let short = FoldInput::<Ep>::from_opening(ep, &[Fq::ONE; 12]).unwrap();
    assert_eq!(frame(&[Fp::ZERO; 18], &short), Err(Error::Input));
}
