//! Bounded DATA controls for native hard-own tape/Q equality; no proof or source admission.

use super::*;

fn source() -> ([Vec<u8>; 3], Vec<Vec<Fq>>, [Fp; 4], [[u64; 4]; 2]) {
    let kinds = [
        ObjectKind::Credential,
        ObjectKind::Certificate,
        ObjectKind::Receipt,
    ];
    let mut tapes = kinds.map(|kind| vec![0; kind.body_len() + 64]);
    for raw in &mut tapes {
        raw[..2].copy_from_slice(&1_u16.to_le_bytes());
    }
    let payment = [3_u128, 5, 7, 11];
    let enrollment = [13_u128, 17, 19, 23];
    tapes[0][130] = 4;
    for (offset, value) in [17, 1, 49, 33].into_iter().zip(payment) {
        tapes[0][130 + offset..130 + offset + 16].copy_from_slice(&value.to_be_bytes());
    }
    tapes[1][34] = 1;
    tapes[1][35] = 4;
    for (offset, value) in [17, 1, 49, 33].into_iter().zip(enrollment) {
        tapes[1][35 + offset..35 + offset + 16].copy_from_slice(&value.to_be_bytes());
    }
    let signatures = [[29_u128, 31, 37, 41], [61, 67, 71, 73], [79, 83, 89, 97]];
    for ((raw, kind), limbs) in tapes.iter_mut().zip(kinds).zip(signatures) {
        for (offset, value) in [16, 0, 48, 32].into_iter().zip(limbs) {
            let start = kind.body_len() + offset;
            raw[start..start + 16].copy_from_slice(&value.to_be_bytes());
        }
    }
    let root = [[43, 0, 47, 0], [53, 0, 59, 0]];
    let mut public = Vec::new();
    for (index, key) in [(2, payment), (0, enrollment), (1, [43, 47, 53, 59])] {
        let digest = p_bytes_native::<Fp>(
            kinds[index].signing_domain(),
            &tapes[index][..kinds[index].body_len()],
        );
        public.push(Fq::from_repr(digest.to_repr()).unwrap());
        public.extend(key.into_iter().map(Fq::from_u128));
        public.extend(signatures[index].into_iter().map(Fq::from_u128));
        public.push(Fq::ONE);
    }
    (tapes, vec![public], payment.map(Fp::from_u128), root)
}

#[test]
fn hard_own_tapes_bind_every_original_body_and_signature() {
    let (tapes, public, payment, root) = source();
    assert_eq!(
        check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &public, payment, root),
        Ok(())
    );
    for object in 0..3 {
        for offset in 0..tapes[object].len() {
            let mut bad = tapes.clone();
            bad[object][offset] ^= 1;
            assert_eq!(
                check_hard_own_tapes(bad.each_ref().map(Vec::as_slice), &public, payment, root),
                Err(Error::Input),
                "object{object}/byte{offset}"
            );
        }
    }
}

#[test]
fn hard_own_tapes_bind_all_q_fields_keys_and_hard_verdicts() {
    let (tapes, public, payment, root) = source();
    for row in 0..30 {
        let mut bad = public.clone();
        bad[0][row] += Fq::ONE;
        assert_eq!(
            check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &bad, payment, root),
            Err(Error::Input),
            "Q row{row}"
        );
    }
    let mut bad = public.clone();
    bad[0][1] = Fq::from_u128(u128::MAX) + Fq::ONE;
    assert_eq!(
        check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &bad, payment, root),
        Err(Error::Input)
    );
    let mut wrong = payment;
    wrong[0] += Fp::ONE;
    assert_eq!(
        check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &public, wrong, root),
        Err(Error::Input)
    );
    let mut wrong = root;
    wrong[1][3] ^= 1;
    assert_eq!(
        check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &public, payment, wrong),
        Err(Error::Input)
    );
}

#[test]
fn hard_own_tapes_refuse_wrong_shapes_without_indexing_short_data() {
    let (tapes, public, payment, root) = source();
    for object in 0..3 {
        for len in [0, 1, tapes[object].len() - 1, tapes[object].len() + 1] {
            let mut bad = tapes.clone();
            bad[object].resize(len, 0);
            assert_eq!(
                check_hard_own_tapes(bad.each_ref().map(Vec::as_slice), &public, payment, root),
                Err(Error::Input)
            );
        }
    }
    for bad in [
        vec![],
        vec![vec![]],
        vec![vec![Fq::ZERO; 29]],
        vec![vec![Fq::ZERO; 31]],
        vec![public[0].clone(), vec![]],
    ] {
        assert_eq!(
            check_hard_own_tapes(tapes.each_ref().map(Vec::as_slice), &bad, payment, root),
            Err(Error::Input)
        );
    }
}

#[test]
fn own_sigma_binds_statement_length_padding_and_all_bytes_for_both_slot_counts() {
    let statement = [Fp::from(7); 26];
    let sigma: Vec<u8> = (0..64).collect();
    let digest = hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, &statement);
    let tape = frame(&sigma).unwrap();
    let chunks: Vec<_> = tape
        .chunks(31)
        .map(|b| le_value::<Fq>(b).unwrap())
        .collect();
    for start in [1, 2] {
        let mut words = vec![Fq::from_repr(digest.to_repr()).unwrap()];
        words.resize(start, Fq::from(99));
        words.extend(&chunks);
        let range = start..start + chunks.len();
        words.extend([Fq::from(123); 20]); // Incoming/part DATA outside the own tape.
        let public = vec![words];
        assert_eq!(
            check_own_sigma_tape(&public, range.clone(), &statement, &sigma),
            Ok(())
        );
        for byte in 0..sigma.len() {
            let mut bad = sigma.clone();
            bad[byte] ^= 1;
            assert_eq!(
                check_own_sigma_tape(&public, range.clone(), &statement, &bad),
                Err(Error::Input)
            );
        }
        for row in range.clone() {
            let mut bad = public.clone();
            bad[0][row] += Fq::ONE;
            assert_eq!(
                check_own_sigma_tape(&bad, range.clone(), &statement, &sigma),
                Err(Error::Input)
            );
        }
        let mut bad = public.clone();
        let mut padded = bad[0][range.end - 1].to_repr();
        padded[6] = 1;
        bad[0][range.end - 1] = Fq::from_repr(padded).unwrap();
        assert_eq!(
            check_own_sigma_tape(&bad, range.clone(), &statement, &sigma),
            Err(Error::Input)
        );
        let mut changed = statement;
        changed[0] += Fp::ONE;
        assert_eq!(
            check_own_sigma_tape(&public, range.clone(), &changed, &sigma),
            Err(Error::Input)
        );
        assert_eq!(
            check_own_sigma_tape(&public, range.clone(), &statement, &sigma[..63]),
            Err(Error::Input)
        );
        let mut soft = public.clone();
        soft[0][range.end] += Fq::ONE;
        if start == 2 {
            soft[0][1] += Fq::ONE;
        }
        assert_eq!(
            check_own_sigma_tape(&soft, range, &statement, &sigma),
            Ok(())
        );
    }
}

#[test]
fn own_sigma_refuses_missing_export_and_wrong_selected_range() {
    assert_eq!(
        check_own_sigma_tape(&[], 1..2, &[Fp::ZERO; 26], &[0; 32]),
        Err(Error::Input)
    );
    assert_eq!(
        check_own_sigma_tape(&[vec![]], 1..2, &[Fp::ZERO; 26], &[0; 32]),
        Err(Error::Input)
    );
    let digest = hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &[Fp::ZERO; 26],
    );
    let words = vec![vec![Fq::from_repr(digest.to_repr()).unwrap()]];
    for range in [0..1, 1..0, 1..4, usize::MAX..usize::MAX] {
        assert_eq!(
            check_own_sigma_tape(&words, range, &[Fp::ZERO; 26], &[0; 32]),
            Err(Error::Input)
        );
    }
}
