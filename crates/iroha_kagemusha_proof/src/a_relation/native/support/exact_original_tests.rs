//! Bounded DATA controls for native hard own-receipt/Q equality; no proof or source admission.

use super::*;

type OwnTapeSource = ([Vec<u8>; 3], Vec<Vec<Fq>>, [Fp; 4], [[u64; 4]; 2]);

// A three-slot leaf whose slot 0 is the own receipt; the credential and
// certificate slots stand in for the other slots of a merged leaf.
fn source() -> OwnTapeSource {
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
fn hard_own_receipt_binds_every_byte_q_field_and_the_carried_payment_key() {
    let (tapes, public, payment, _) = source();
    // The receipt is the first exported slot of the three-slot fixture.
    let receipt = &tapes[2];
    let slot = vec![public[0][..crate::q_signature::SLOT_WORDS].to_vec()];
    assert_eq!(check_hard_own_receipt(receipt, &slot, payment), Ok(()));
    for offset in 0..receipt.len() {
        let mut bad = receipt.clone();
        bad[offset] ^= 1;
        assert_eq!(
            check_hard_own_receipt(&bad, &slot, payment),
            Err(Error::Input),
            "byte{offset}"
        );
    }
    for row in 0..crate::q_signature::SLOT_WORDS {
        let mut bad = slot.clone();
        bad[0][row] += Fq::ONE;
        assert_eq!(
            check_hard_own_receipt(receipt, &bad, payment),
            Err(Error::Input),
            "Q row{row}"
        );
    }
    let mut wrong = payment;
    wrong[3] += Fp::ONE;
    assert_eq!(
        check_hard_own_receipt(receipt, &slot, wrong),
        Err(Error::Input)
    );
    for len in [0, 1, receipt.len() - 1, receipt.len() + 1] {
        let mut bad = receipt.clone();
        bad.resize(len, 0);
        assert_eq!(
            check_hard_own_receipt(&bad, &slot, payment),
            Err(Error::Input)
        );
    }
    // A lean route exports exactly one own slot; the three-slot bundle is refused.
    for bad in [
        vec![],
        vec![vec![]],
        vec![vec![Fq::ZERO; crate::q_signature::SLOT_WORDS - 1]],
        public.clone(),
        vec![slot[0].clone(), vec![]],
    ] {
        assert_eq!(
            check_hard_own_receipt(receipt, &bad, payment),
            Err(Error::Input)
        );
    }
}

#[test]
fn merged_leaf_binds_only_its_hard_own_receipt_slot() {
    let (tapes, public, payment, _) = source();
    let receipt = &tapes[2];
    let words = crate::q_signature::SLOT_WORDS;
    assert_eq!(
        check_hard_own_receipt_slot(receipt, &public, 3, payment),
        Ok(())
    );
    for row in 0..3 * words {
        let mut changed = public.clone();
        changed[0][row] += Fq::ONE;
        // Slot 0 is the hard own receipt; the other slots are incoming soft
        // objects whose bytes and verdicts their circuit owners bind.
        let expected = if row < words {
            Err(Error::Input)
        } else {
            Ok(())
        };
        assert_eq!(
            check_hard_own_receipt_slot(receipt, &changed, 3, payment),
            expected,
            "Q row{row}"
        );
    }
    let mut wrong = payment;
    wrong[0] += Fp::ONE;
    assert_eq!(
        check_hard_own_receipt_slot(receipt, &public, 3, wrong),
        Err(Error::Input)
    );
    for slots in [0, 1, 2, 4, usize::MAX] {
        assert_eq!(
            check_hard_own_receipt_slot(receipt, &public, slots, payment),
            Err(Error::Input),
            "slots{slots}"
        );
    }
    for bad in [vec![], vec![vec![]], vec![public[0].clone(), vec![]]] {
        assert_eq!(
            check_hard_own_receipt_slot(receipt, &bad, 3, payment),
            Err(Error::Input)
        );
    }
}
