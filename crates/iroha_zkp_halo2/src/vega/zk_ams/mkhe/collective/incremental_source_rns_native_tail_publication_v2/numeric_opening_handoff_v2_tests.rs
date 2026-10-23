//! Numeric handoff ownership, exact native digest framing and local resource bounds.

use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy)]
enum OpeningAuthorityBehaviorV2 {
    Success,
    ErrorAfterWrite,
    PanicAfterWrite,
    NonBooleanBit,
}

struct OpeningAuthorityFixtureV2 {
    behavior: OpeningAuthorityBehaviorV2,
    calls: OpeningAuthorityCallsV2,
    clear_calls: Rc<Cell<usize>>,
    retained: Rc<Cell<bool>>,
}

type OpeningAuthorityCallsV2 = Rc<RefCell<Vec<(usize, RnsNativeCrossFieldQuotientOpeningSignV1)>>>;
type OpeningAuthorityFixturePartsV2 = (
    OpeningAuthorityFixtureV2,
    OpeningAuthorityCallsV2,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
);

impl OpeningAuthorityFixtureV2 {
    fn new_v2(behavior: OpeningAuthorityBehaviorV2) -> OpeningAuthorityFixturePartsV2 {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let clear_calls = Rc::new(Cell::new(0));
        let retained = Rc::new(Cell::new(true));
        (
            Self {
                behavior,
                calls: Rc::clone(&calls),
                clear_calls: Rc::clone(&clear_calls),
                retained: Rc::clone(&retained),
            },
            calls,
            clear_calls,
            retained,
        )
    }
}

impl RnsNativeQuotientOpeningAuthorityV2 for OpeningAuthorityFixtureV2 {
    fn fill_next_quotient_opening_v2(
        &mut self,
        relation_ordinal: usize,
        sign: RnsNativeCrossFieldQuotientOpeningSignV1,
        values: &mut [Scalar],
        commitment_mask: &mut Scalar,
        quotient_bits: &mut [Scalar],
    ) -> Result<(), RnsNativeCrossFieldRlweDirectErrorV1> {
        self.calls.borrow_mut().push((relation_ordinal, sign));
        values[0] = Scalar::one();
        *commitment_mask = Scalar::one();
        quotient_bits.fill(Scalar::zero());
        match self.behavior {
            OpeningAuthorityBehaviorV2::Success => Ok(()),
            OpeningAuthorityBehaviorV2::ErrorAfterWrite => {
                Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable)
            }
            OpeningAuthorityBehaviorV2::PanicAfterWrite => panic!("fixture opening panic"),
            OpeningAuthorityBehaviorV2::NonBooleanBit => {
                quotient_bits[0] = Scalar::from_u64(2);
                Ok(())
            }
        }
    }

    fn clear_retained_quotient_openings_v2(&mut self) {
        self.retained.set(false);
        self.clear_calls.set(self.clear_calls.get() + 1);
    }
}

fn opening_destinations_v2() -> (Vec<Scalar>, Scalar, Vec<Scalar>) {
    (
        vec![Scalar::one(); QUOTIENT_OPENING_COORDINATES_V2],
        Scalar::one(),
        vec![Scalar::one(); QUOTIENT_OPENING_BITS_V2],
    )
}

fn destinations_are_zero_v2(values: &[Scalar], mask: Scalar, bits: &[Scalar]) -> bool {
    values.iter().all(|value| value.is_zero())
        && mask.is_zero()
        && bits.iter().all(|bit| bit.is_zero())
}

fn public_fixture_v2() -> RnsNativePublicPolynomialEvaluationV1 {
    let mut ciphertext_c0 = [0_u64; RECORDS_V2];
    let mut ciphertext_c1 = [0_u64; RECORDS_V2];
    for record in 0..RECORDS_V2 {
        ciphertext_c0[record] = record as u64 + 11;
        ciphertext_c1[record] = record as u64 + 101;
    }
    RnsNativePublicPolynomialEvaluationV1 {
        public_a: 7,
        public_b: 9,
        ciphertext_c0,
        ciphertext_c1,
    }
}

fn valid_pair_v2(
    limb: usize,
    point: u64,
    opening_quotient: u64,
) -> RnsNativeQpcsAuthenticatedPairV2 {
    let modulus = ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[limb];
    let factor = mod_add_v2(pow_ring_degree_v2(point, modulus), 1, modulus);
    assert_ne!(factor, 0);
    RnsNativeQpcsAuthenticatedPairV2 {
        product: mod_mul_v2(factor, opening_quotient, modulus),
        opening_quotient,
    }
}

fn mod_pow_test_v2(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mod_mul_v2(result, base, modulus);
        }
        base = mod_mul_v2(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn zero_factor_point_v2(limb: usize) -> u64 {
    let modulus = ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[limb];
    let two_n = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64;
    assert_eq!((modulus - 1) % two_n, 0);
    for base in 2..4_096_u64 {
        let candidate = mod_pow_test_v2(base, (modulus - 1) / two_n, modulus);
        if candidate != 0 && pow_ring_degree_v2(candidate, modulus) == modulus - 1 {
            return candidate;
        }
    }
    panic!("release modulus must expose a bounded 2N-th root")
}

#[test]
fn qpcs_pairs_decode_product_then_opening_quotient_through_new_limbs_v2() {
    let mut bytes = vec![0_u8; QPCS_EVALUATION_BYTES_V2];
    for (limb, repetition, product, quotient) in
        [(38, 0, 0x0102_u64, 0x0304_u64), (39, 4, 0x1112, 0x1314)]
    {
        let relation = limb * REPETITIONS_V2 + repetition;
        let offset = relation * QPCS_PAIR_BYTES_V2;
        bytes[offset..offset + 8].copy_from_slice(&product.to_be_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&quotient.to_be_bytes());
        assert_eq!(
            decode_qpcs_pair_v2(&bytes, limb, repetition),
            Ok(RnsNativeQpcsAuthenticatedPairV2 {
                product,
                opening_quotient: quotient,
            })
        );
    }
    assert_eq!(
        decode_qpcs_pair_v2(&bytes[..bytes.len() - 1], 39, 4),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidCount)
    );
}

#[test]
fn cursor_is_exactly_limb_major_then_repetition_major_v2() {
    let mut cursor = RnsNativeRelationCursorV2::new_v2();
    for relation in 0..RELATIONS_V2 {
        let limb = relation / REPETITIONS_V2;
        let repetition = relation % REPETITIONS_V2;
        assert_eq!(cursor.begin_v2(limb, repetition), Ok(relation));
        if relation >= 190 {
            assert!(limb == 38 || limb == 39);
        }
        cursor.commit_v2();
    }
    assert!(cursor.is_complete_v2());
}

#[test]
fn invalid_order_and_overrun_poison_permanently_v2() {
    let mut skipped = RnsNativeRelationCursorV2::new_v2();
    assert_eq!(
        skipped.begin_v2(0, 1),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidOrder)
    );
    assert_eq!(
        skipped.begin_v2(0, 0),
        Err(RnsNativeNumericOpeningHandoffErrorV2::Poisoned)
    );

    let mut overrun = RnsNativeRelationCursorV2::new_v2();
    for relation in 0..RELATIONS_V2 {
        assert_eq!(
            overrun.begin_v2(relation / REPETITIONS_V2, relation % REPETITIONS_V2),
            Ok(relation)
        );
        overrun.commit_v2();
    }
    assert_eq!(
        overrun.begin_v2(ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1, 0),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidOrder)
    );
    assert_eq!(
        overrun.begin_v2(0, 0),
        Err(RnsNativeNumericOpeningHandoffErrorV2::Poisoned)
    );
}

#[test]
fn quotient_opening_cursor_consumes_exactly_relation_positive_then_negative_v2() {
    let (authority, calls, _, retained) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
    let mut cursor = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    let (mut values, mut mask, mut bits) = opening_destinations_v2();
    for relation in 0..RELATIONS_V2 {
        for sign in [
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            RnsNativeCrossFieldQuotientOpeningSignV1::Negative,
        ] {
            cursor
                .take_next_quotient_opening_v1(relation, sign, &mut values, &mut mask, &mut bits)
                .expect("canonical opening owner");
        }
    }
    let calls = calls.borrow();
    assert_eq!(calls.len(), QUOTIENT_OPENING_OWNERS_V2);
    for (owner, &(relation, sign)) in calls.iter().enumerate() {
        assert_eq!(relation, owner / QUOTIENT_OPENING_SIGNS_V2);
        assert_eq!(
            sign,
            if owner % QUOTIENT_OPENING_SIGNS_V2 == 0 {
                RnsNativeCrossFieldQuotientOpeningSignV1::Positive
            } else {
                RnsNativeCrossFieldQuotientOpeningSignV1::Negative
            }
        );
    }
    drop(calls);
    assert!(retained.get());
    drop(cursor);
    assert!(!retained.get());
}

#[test]
fn quotient_opening_order_faults_and_overrun_poison_permanently_v2() {
    for (relation, sign) in [
        (0, RnsNativeCrossFieldQuotientOpeningSignV1::Negative),
        (1, RnsNativeCrossFieldQuotientOpeningSignV1::Positive),
    ] {
        let (authority, _, clear_calls, _) =
            OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
        let mut cursor = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
        let (mut values, mut mask, mut bits) = opening_destinations_v2();
        assert_eq!(
            cursor
                .take_next_quotient_opening_v1(relation, sign, &mut values, &mut mask, &mut bits,),
            Err(RnsNativeCrossFieldRlweDirectErrorV1::InvalidGeometry)
        );
        assert!(destinations_are_zero_v2(&values, mask, &bits));
        assert_eq!(clear_calls.get(), 1);
        assert_eq!(
            cursor.take_next_quotient_opening_v1(
                0,
                RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
                &mut values,
                &mut mask,
                &mut bits,
            ),
            Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable)
        );
    }

    let (authority, _, _, _) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
    let mut duplicate = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    let (mut values, mut mask, mut bits) = opening_destinations_v2();
    duplicate
        .take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        )
        .expect("first owner");
    assert_eq!(
        duplicate.take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        ),
        Err(RnsNativeCrossFieldRlweDirectErrorV1::InvalidGeometry)
    );

    let (authority, _, _, _) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
    let mut overrun = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    for relation in 0..RELATIONS_V2 {
        for sign in [
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            RnsNativeCrossFieldQuotientOpeningSignV1::Negative,
        ] {
            overrun
                .take_next_quotient_opening_v1(relation, sign, &mut values, &mut mask, &mut bits)
                .expect("opening owner before overrun");
        }
    }
    assert_eq!(
        overrun.take_next_quotient_opening_v1(
            RELATIONS_V2,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        ),
        Err(RnsNativeCrossFieldRlweDirectErrorV1::InvalidGeometry)
    );
}

#[test]
fn quotient_opening_cursor_clears_on_length_bit_provider_error_and_unwind_v2() {
    let (authority, _, clear_calls, _) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
    let mut wrong_length = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    let mut values = vec![Scalar::one(); QUOTIENT_OPENING_COORDINATES_V2 - 1];
    let mut mask = Scalar::one();
    let mut bits = vec![Scalar::one(); QUOTIENT_OPENING_BITS_V2];
    assert_eq!(
        wrong_length.take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        ),
        Err(RnsNativeCrossFieldRlweDirectErrorV1::InvalidGeometry)
    );
    assert!(destinations_are_zero_v2(&values, mask, &bits));
    assert_eq!(clear_calls.get(), 1);

    for (behavior, expected) in [
        (
            OpeningAuthorityBehaviorV2::ErrorAfterWrite,
            RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable,
        ),
        (
            OpeningAuthorityBehaviorV2::NonBooleanBit,
            RnsNativeCrossFieldRlweDirectErrorV1::InvalidScalar,
        ),
    ] {
        let (authority, _, clear_calls, retained) = OpeningAuthorityFixtureV2::new_v2(behavior);
        let mut cursor = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
        let (mut values, mut mask, mut bits) = opening_destinations_v2();
        assert_eq!(
            cursor.take_next_quotient_opening_v1(
                0,
                RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
                &mut values,
                &mut mask,
                &mut bits,
            ),
            Err(expected)
        );
        assert!(destinations_are_zero_v2(&values, mask, &bits));
        assert_eq!(clear_calls.get(), 1);
        assert!(!retained.get());
        assert_eq!(
            cursor.take_next_quotient_opening_v1(
                0,
                RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
                &mut values,
                &mut mask,
                &mut bits,
            ),
            Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable)
        );
    }

    let (authority, _, clear_calls, retained) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::PanicAfterWrite);
    let mut cursor = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    let (mut values, mut mask, mut bits) = opening_destinations_v2();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cursor.take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        );
    }));
    assert!(result.is_err());
    assert!(destinations_are_zero_v2(&values, mask, &bits));
    assert_eq!(clear_calls.get(), 1);
    assert!(!retained.get());
    assert_eq!(
        cursor.take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        ),
        Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable)
    );
}

#[test]
fn dropping_partially_consumed_quotient_cursor_clears_retained_authority_v2() {
    let (authority, _, clear_calls, retained) =
        OpeningAuthorityFixtureV2::new_v2(OpeningAuthorityBehaviorV2::Success);
    let mut cursor = RnsNativeQuotientOpeningCursorV2::test_fixture_v2(authority);
    let (mut values, mut mask, mut bits) = opening_destinations_v2();
    cursor
        .take_next_quotient_opening_v1(
            0,
            RnsNativeCrossFieldQuotientOpeningSignV1::Positive,
            &mut values,
            &mut mask,
            &mut bits,
        )
        .expect("first opening owner");
    assert!(retained.get());
    assert_eq!(clear_calls.get(), 0);
    drop(cursor);
    assert!(!retained.get());
    assert_eq!(clear_calls.get(), 1);
}

#[test]
fn materialization_maps_reader_abc_and_qpcs_ph_without_role_aliasing_v2() {
    let public = public_fixture_v2();
    for limb in [0, 38, 39] {
        let point = 5;
        let pair = valid_pair_v2(limb, point, 17);
        let numeric = materialize_numeric_evaluation_v2(limb, 4, point, public, pair)
            .expect("valid numeric row");
        assert_eq!(numeric.a, point);
        assert_eq!(numeric.public_a, public.public_a);
        assert_eq!(numeric.public_b, public.public_b);
        assert_eq!(numeric.ciphertext_c0, public.ciphertext_c0);
        assert_eq!(numeric.ciphertext_c1, public.ciphertext_c1);
        assert_eq!(numeric.qpcs_product, pair.product);
        assert_eq!(numeric.qpcs_opening_quotient, pair.opening_quotient);
    }
}

#[test]
fn every_numeric_family_is_canonical_and_the_relation_is_checked_v2() {
    let limb = 39;
    let modulus = ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[limb];
    let point = 5;
    let public = public_fixture_v2();
    let pair = valid_pair_v2(limb, point, 23);

    let mut bad = public;
    bad.public_a = modulus;
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, point, bad, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    let mut bad = public;
    bad.public_b = modulus;
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, point, bad, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    let mut bad = public;
    bad.ciphertext_c0[42] = modulus;
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, point, bad, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    let mut bad = public;
    bad.ciphertext_c1[0] = modulus;
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, point, bad, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    assert!(matches!(
        materialize_numeric_evaluation_v2(
            limb,
            0,
            point,
            public,
            RnsNativeQpcsAuthenticatedPairV2 {
                product: modulus,
                opening_quotient: pair.opening_quotient,
            },
        ),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    assert!(matches!(
        materialize_numeric_evaluation_v2(
            limb,
            0,
            point,
            public,
            RnsNativeQpcsAuthenticatedPairV2 {
                product: pair.product,
                opening_quotient: modulus,
            },
        ),
        Err(RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue)
    ));
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, modulus, public, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidPoint)
    ));

    let changed_product = (pair.product + 1) % modulus;
    assert_ne!(changed_product, pair.product);
    assert!(matches!(
        materialize_numeric_evaluation_v2(
            limb,
            0,
            point,
            public,
            RnsNativeQpcsAuthenticatedPairV2 {
                product: changed_product,
                opening_quotient: pair.opening_quotient,
            },
        ),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidRelation)
    ));
}

#[test]
fn zero_factor_is_rejected_and_failed_step_stays_poisoned_v2() {
    let limb = 0;
    let point = zero_factor_point_v2(limb);
    let public = public_fixture_v2();
    let pair = RnsNativeQpcsAuthenticatedPairV2 {
        product: 0,
        opening_quotient: 1,
    };
    let mut cursor = RnsNativeRelationCursorV2::new_v2();
    assert_eq!(cursor.begin_v2(0, 0), Ok(0));
    assert!(matches!(
        materialize_numeric_evaluation_v2(limb, 0, point, public, pair),
        Err(RnsNativeNumericOpeningHandoffErrorV2::ZeroFactor)
    ));
    assert_eq!(
        cursor.begin_v2(0, 0),
        Err(RnsNativeNumericOpeningHandoffErrorV2::Poisoned)
    );
}

#[test]
fn fixed_sizes_and_post_authentication_local_resource_ledger_are_exact_v2() {
    assert_eq!(QUOTIENT_OPENING_OWNERS_V2, 400);
    assert_eq!(QUOTIENT_OPENING_SCALARS_PER_OWNER_V2, 16_488);
    assert_eq!(QUOTIENT_OPENING_BYTES_PER_OWNER_V2, 527_616);
    assert_eq!(QUOTIENT_OPENING_STREAM_SCALARS_V2, 6_595_200);
    assert_eq!(QUOTIENT_OPENING_STREAM_BYTES_V2, 211_046_400);
    assert_eq!(PUBLIC_EVALUATION_BYTES_V2, 704);
    assert_eq!(RETAINED_PUBLIC_EVALUATION_BYTES_V2, 140_800);
    assert_eq!(RETAINED_TRANSCRIPT_OWNER_BYTES_V2, 5_928);
    assert_eq!(RETAINED_COMMITMENT_DIGEST_BYTES_V2, 2_016);
    assert_eq!(
        POST_AUTHENTICATION_RETAINED_PAYLOAD_BYTES_V2,
        RETAINED_PUBLIC_EVALUATION_BYTES_V2 + RETAINED_TRANSCRIPT_OWNER_BYTES_V2 + 2_016
    );
    assert_eq!(POST_AUTHENTICATION_RETAINED_PAYLOAD_BYTES_V2, 148_744);
    assert_eq!(QPCS_EVALUATION_BYTES_V2, 3_200);
    assert_eq!(NUMERIC_DESTINATION_BYTES_V2, 728);
    assert_eq!(CANONICAL_CHECKS_V2, 18_200);
    assert_eq!(RING_POWER_SQUARINGS_V2, 3_400);
    assert_eq!(MODULAR_MULTIPLICATIONS_V2, 3_600);
    assert_eq!(MODULAR_ADDITIONS_V2, 200);
    assert_eq!(POST_AUTHENTICATION_NUMERIC_VALIDATION_WORK_UNITS_V2, 22_000);
    assert_eq!(JOINT_BINDING_FIXED_BYTES_V2, 755);
    assert_eq!(POST_AUTHENTICATION_JOINT_BINDING_HASH_BYTES_V2, 824);
    assert_eq!(POST_AUTHENTICATION_LOCAL_WORK_UNITS_V2, 1_282_944);
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_retained_public_evaluation_bytes,
        140_800
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_retained_transcript_owner_bytes,
        RETAINED_TRANSCRIPT_OWNER_BYTES_V2 as u32
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_retained_commitment_digest_bytes,
        2_016
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_retained_payload_bytes,
        POST_AUTHENTICATION_RETAINED_PAYLOAD_BYTES_V2 as u32
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_commitment_digest_copy_bytes,
        2_016
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_local_work_units,
        POST_AUTHENTICATION_LOCAL_WORK_UNITS_V2 as u32
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_new_authenticated_io_bytes,
        0
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_new_heap_bytes,
        0
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_new_spool_bytes,
        0
    );
    assert_eq!(
        RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2
            .post_authentication_new_wire_bytes,
        0
    );
}

#[test]
fn source_is_settled_but_every_live_and_release_gate_is_closed_v2() {
    const {
        assert!(RNS_NATIVE_NUMERIC_OPENING_HANDOFF_SOURCE_SETTLED_V2);
        assert!(RNS_NATIVE_NUMERIC_OPENING_HANDOFF_CONTRACT_IMPLEMENTED_V2);
        assert!(RNS_NATIVE_NUMERIC_OPENING_HANDOFF_QPCS_JOIN_IMPLEMENTED_V2);
        assert!(RNS_NATIVE_QUOTIENT_OPENING_CURSOR_CONTRACT_IMPLEMENTED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_LIVE_OWNER_INTEGRATED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_SOURCE_PREFLIGHT_INTEGRATED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_COMPLETED_LINEAGE_INTEGRATED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_DIRECT_NUMERIC_SOURCE_INTEGRATED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_DIRECT_OPENINGS_AVAILABLE_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_SINGLE_OWNER_DIRECT_CHRONOLOGY_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_RESOURCE_EVIDENCE_QUALIFIED_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_READINESS_V2);
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_RELEASE_AUTHORIZED_V2);
    }
    assert!(matches!(
        RnsNativeDirectOpeningOwnersUnavailableV2::TestOnly,
        RnsNativeDirectOpeningOwnersUnavailableV2::TestOnly
    ));
}

#[test]
fn production_surface_has_only_the_schedule_free_numeric_cursor_split_v2() {
    fn require_numeric_cursor_v2<T: RnsNativeCrossFieldNumericCursorV1>() {}
    require_numeric_cursor_v2::<RnsNativeQpcsNumericOpeningHandoffV2<'static>>();

    let source = include_str!("numeric_opening_handoff_v2.rs");
    assert!(source.contains("authenticate_rns_native_qpcs_fri_complete_with_schedule_v1("));
    assert!(source.contains("let RnsNativeCompletedQpcsSourceReadV2 {"));
    assert!(source.contains("qpcs: RnsNativeQpcsFriCompleteStageV1<'proof>"));
    assert!(source.contains("*destination = RnsNativeCrossFieldNumericEvaluationV1::default();"));
    assert!(source.contains("let public = *self"));
    assert!(source.contains("decode_qpcs_pair_v2(self.qpcs.evaluations(), limb, repetition)?"));
    assert!(!source.contains("RnsNativeQpcsCompletedLineageV1"));
    assert!(!source.contains("take_completed_qpcs_lineage_v1"));
    assert!(!source.contains("fn into_parts"));
    assert!(source.contains(
        "impl RnsNativeCrossFieldNumericCursorV1 for RnsNativeQpcsNumericOpeningHandoffV2<'_>"
    ));
    assert!(!source.contains("impl RnsNativeCrossFieldAuthoritativeSourceV1 for"));
    assert!(!source.contains("impl RnsNativeCrossFieldAuthenticatedPublicPointSourceV1 for"));
    assert!(!source.contains("impl RnsNativeCrossFieldQuotientOpeningSourceV1 for"));
    let cursor_impl = source
        .split_once(
            "impl RnsNativeCrossFieldNumericCursorV1 for RnsNativeQpcsNumericOpeningHandoffV2<'_>",
        )
        .expect("numeric-only cursor implementation")
        .1
        .split_once("impl<'proof> RnsNativeQpcsNumericOpeningHandoffV2<'proof>")
        .expect("numeric cursor boundary")
        .0;
    assert!(cursor_impl.contains("take_numeric_evaluation_v1"));
    assert!(!cursor_impl.contains("relation_schedule_v1"));
    assert!(!cursor_impl.contains("joint_binding_digest"));
    assert!(!cursor_impl.contains("terminal_transcript_digest"));
    assert!(!cursor_impl.contains("finish_v2"));
    assert!(!source.contains("direct_membership_numeric_join_v2"));
    assert!(!source.contains("verify_rns_native_direct_global_membership_handoff"));
    assert!(!source.contains("numeric_evaluations:"));
    assert!(!source.contains("qpcs_products:"));
    assert!(!source.contains("qpcs_opening_quotients:"));

    let unavailable = source
        .split_once("pub(super) enum RnsNativeDirectOpeningOwnersUnavailableV2")
        .expect("uninhabited direct opening-owner boundary")
        .1
        .split_once("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .expect("uninhabited opening-owner boundary")
        .0;
    for absent_owner in [
        "q_mask_s_commitment_owner: Infallible",
        "message_radix_commitment_owner: Infallible",
        "small_signed_commitment_owner: Infallible",
        "small_negative_magnitude_commitment_owner: Infallible",
        "comparator_final_borrow_commitment_owner: Infallible",
        "positive_quotient_opening_owner: Infallible",
        "negative_quotient_opening_owner: Infallible",
    ] {
        assert!(
            unavailable.contains(absent_owner),
            "opening owner accidentally inhabited: {absent_owner}"
        );
    }
    for absent_spool_surface in [
        "opening_spool",
        "replay_receipt",
        "mask_receipt",
        "take_positive_quotient_owner_v1",
        "take_negative_quotient_owner_v1",
    ] {
        assert!(!source.contains(absent_spool_surface));
    }

    let opening_cursor = source
        .split_once(
            "struct RnsNativeQuotientOpeningCursorV2<A: RnsNativeQuotientOpeningAuthorityV2>",
        )
        .expect("isolated quotient-opening cursor")
        .1
        .split_once("/// Move-only live cursor")
        .expect("quotient-opening cursor boundary")
        .0;
    assert!(opening_cursor.contains("take_next_quotient_opening_v1"));
    assert!(opening_cursor.contains("self.poisoned = true;"));
    assert!(opening_cursor.contains("clear_retained_quotient_openings_v2"));
    assert!(opening_cursor.contains("impl<A: RnsNativeQuotientOpeningAuthorityV2> Drop"));
    for forbidden in [
        "schedule",
        "transcript",
        "lineage",
        "chronology",
        "root",
        "digest",
        "finish",
        "Point",
    ] {
        assert!(
            !opening_cursor.contains(forbidden),
            "isolated opening cursor leaks {forbidden}"
        );
    }
    assert!(!source.contains(
        "impl RnsNativeCrossFieldQuotientOpeningCursorV1 for RnsNativeQpcsNumericOpeningHandoffV2"
    ));
    assert!(!source.contains("impl RnsNativeQuotientOpeningAuthorityV2 for"));
}

#[test]
fn numeric_cursor_error_mapping_is_fail_closed_v2() {
    for invalid_numeric in [
        RnsNativeNumericOpeningHandoffErrorV2::InvalidPoint,
        RnsNativeNumericOpeningHandoffErrorV2::NonCanonicalResidue,
        RnsNativeNumericOpeningHandoffErrorV2::ZeroFactor,
        RnsNativeNumericOpeningHandoffErrorV2::InvalidRelation,
    ] {
        assert_eq!(
            map_direct_numeric_error_v2(invalid_numeric),
            RnsNativeCrossFieldRlweDirectErrorV1::InvalidNumericEvaluation
        );
    }
    for unavailable in [
        RnsNativeNumericOpeningHandoffErrorV2::InvalidCount,
        RnsNativeNumericOpeningHandoffErrorV2::InvalidOrder,
        RnsNativeNumericOpeningHandoffErrorV2::Incomplete,
        RnsNativeNumericOpeningHandoffErrorV2::Poisoned,
    ] {
        assert_eq!(
            map_direct_numeric_error_v2(unavailable),
            RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable
        );
    }
    for invalid_context in [
        RnsNativeNumericOpeningHandoffErrorV2::InvalidContext,
        RnsNativeNumericOpeningHandoffErrorV2::Authentication,
    ] {
        assert_eq!(
            map_direct_numeric_error_v2(invalid_context),
            RnsNativeCrossFieldRlweDirectErrorV1::InvalidContext
        );
    }
    assert_eq!(
        map_direct_numeric_error_v2(RnsNativeNumericOpeningHandoffErrorV2::ArithmeticOverflow),
        RnsNativeCrossFieldRlweDirectErrorV1::ArithmeticOverflow
    );
}

#[test]
fn production_path_does_not_revalidate_owner_graph_or_overclaim_qpcs_work_v2() {
    let source = include_str!("numeric_opening_handoff_v2.rs");
    assert!(!source.contains("owners.validate_v2()"));
    assert!(!source.contains(".validate_v2()"));
    assert!(!source.contains("retained_owner_is_valid_v2"));
    assert!(!source.contains("BTreeMap"));
    assert!(!source.contains("BTreeSet"));
    assert!(!source.contains("TAIL_PLUS_READER_AND_HANDOFF_WORK_UNITS_V2"));
    assert!(source.contains("post-authentication-local-numeric-rendezvous-only"));
    assert!(source.contains("excludes-existing-qpcs-prefix-and-fri-authentication-work"));
    assert!(source.contains("not-end-to-end-resource-accounting"));
    assert!(source.contains("cannot qualify resource evidence"));
    assert!(source.contains("authenticate_rns_native_qpcs_fri_complete_with_schedule_v1("));
    const {
        assert!(!RNS_NATIVE_NUMERIC_OPENING_HANDOFF_RESOURCE_EVIDENCE_QUALIFIED_V2);
    }
}

#[test]
fn transcript_and_authenticated_commitment_arrays_move_with_both_handoff_owners_v2() {
    let source = include_str!("numeric_opening_handoff_v2.rs");
    let input = source
        .split_once("pub(super) struct RnsNativeQpcsNumericVerificationInputV2")
        .expect("typed verifier input")
        .1
        .split_once("impl<'digests, 'proof>")
        .expect("typed input implementation")
        .0;
    assert!(input.contains("transcript: ZkAmsMkheRnsNativeChallengeSeedsV1"));
    assert!(!input.contains("transcript: &"));

    let live = source
        .split_once("pub(super) struct RnsNativeQpcsNumericOpeningHandoffV2<'proof> {")
        .expect("live handoff")
        .1
        .split_once("/// Completed numeric traversal")
        .expect("completed handoff follows live handoff")
        .0;
    let completed = source
        .split_once("pub(super) struct RnsNativeCompletedQpcsNumericOpeningHandoffV2<'proof> {")
        .expect("completed handoff")
        .1
        .split_once("impl RnsNativeCompletedQpcsNumericOpeningHandoffV2")
        .expect("completed handoff implementation")
        .0;
    for owner in [live, completed] {
        assert!(owner.contains("transcript: ZkAmsMkheRnsNativeChallengeSeedsV1"));
        assert!(owner.contains("equation_commitment_digests: [ProofDigestV1; EQUATIONS_V2]"));
        assert!(
            owner.contains(
                "limb_commitment_digests: [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1]"
            )
        );
        assert!(!owner.contains("query_opening_digests"));
    }

    assert!(source.contains(
        "authenticate_rns_native_qpcs_fri_complete_with_schedule_v1(\n        &transcript,"
    ));
    assert!(source.contains("joint_binding_digest_v2(&owners, &read_receipt, &qpcs, &transcript"));
    assert!(source.contains("let equation_commitment_digests = *equation_commitment_digests;"));
    assert!(source.contains("let limb_commitment_digests = *limb_commitment_digests;"));
    assert!(source.contains("transcript: self.transcript"));
    assert!(source.contains("equation_commitment_digests: self.equation_commitment_digests"));
    assert!(source.contains("limb_commitment_digests: self.limb_commitment_digests"));

    for forbidden in [
        "fn transcript_v2(",
        "fn equation_commitment_digests_v2(",
        "fn limb_commitment_digests_v2(",
        "impl Clone for RnsNativeQpcsNumericVerificationInputV2",
        "impl Copy for RnsNativeQpcsNumericVerificationInputV2",
        "impl Clone for RnsNativeQpcsNumericOpeningHandoffV2",
        "impl Copy for RnsNativeQpcsNumericOpeningHandoffV2",
    ] {
        assert!(!source.contains(forbidden));
    }

    let live_impl = source
        .split_once("impl<'proof> RnsNativeQpcsNumericOpeningHandoffV2<'proof> {")
        .expect("live handoff implementation")
        .1
        .split_once("/// Consume the exact completed public read")
        .expect("constructor follows live implementation")
        .0;
    assert!(!live_impl.contains("ZkAmsMkheRnsNativeChallengeSeedsV1"));
    assert!(!live_impl.contains("[[u8; 32]"));
    assert!(!live_impl.contains("[ProofDigestV1;"));

    let completed_impl = source
        .split_once("impl RnsNativeCompletedQpcsNumericOpeningHandoffV2<'_> {")
        .expect("completed handoff implementation")
        .1
        .split_once("fn map_direct_numeric_error_v2(")
        .expect("numeric error mapping follows completed implementation")
        .0;
    assert!(!completed_impl.contains("self.transcript"));
    assert!(!completed_impl.contains("self.equation_commitment_digests"));
    assert!(!completed_impl.contains("self.limb_commitment_digests"));

    let transcript_source = include_str!("../../rns_native_transcript.rs");
    assert!(transcript_source.contains("It intentionally does not implement `Clone`."));
    assert!(!transcript_source.contains("impl Clone for ZkAmsMkheRnsNativeChallengeSeedsV1"));
}

#[test]
fn declaration_and_only_schedule_borrow_api_are_private_and_unique_v2() {
    let tail = include_str!("../incremental_source_rns_native_tail_publication_v2.rs");
    let declaration =
        "incremental_source_rns_native_tail_publication_v2/numeric_opening_handoff_v2.rs";
    assert_eq!(tail.matches(declaration).count(), 1);
    assert!(tail.contains("mod numeric_opening_handoff_v2;"));
    assert!(!tail.contains("pub mod numeric_opening_handoff_v2;"));

    let fri = include_str!("../../rns_native_qpcs_fri_complete.rs");
    let borrow = fri
        .split_once("pub(super) fn relation_schedule_v1(")
        .expect("non-consuming schedule borrow")
        .1
        .split_once("pub(super) fn take_relation_schedule_v1(")
        .expect("borrow precedes existing consuming API")
        .0;
    assert!(borrow.contains("self.relation_schedule"));
    assert!(borrow.contains(".as_ref()"));
    assert!(!borrow.contains(".take()"));
}

#[test]
fn numeric_handoff_frame_uses_exact_native_widths_and_real_primitive_work() {
    let context = RnsNativeProofHashContextV1::canonical().expect("context");
    let parameter = context.parameter_digest();
    let lengths = [
        69, 1, 2, 2, 2, 2, 32, 32, 48, 32, 32, 32, 2, 8, 8, 8, 8, 32, 48, 48, 48, 32, 48, 48, 48,
        48, 48, 48, 8,
    ];
    let mut fields: Vec<Vec<u8>> = lengths
        .into_iter()
        .enumerate()
        .map(|(ordinal, len)| vec![ordinal as u8 + 1; len])
        .collect();
    fields[0] = JOINT_BINDING_DOMAIN_V2.to_vec();
    fields[1] = vec![VERSION_V1];
    fields[17] = parameter.to_vec();
    fields[21] = parameter.to_vec();
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let frame = context
        .frame(
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashPhaseV1::Binding,
            RnsNativeProofHashPositionV1 {
                level: 5,
                index: 0,
                counter: 0,
            },
            &refs,
        )
        .expect("frame");
    let work = RnsNativeProofHashWorkV1::from_frame(&frame).expect("work");
    assert_eq!(frame.word_count(), 248);
    assert_eq!(work.lane_permutations, 744);
    assert_eq!(work.poseidon_rounds, 48_360);
    assert_eq!(work.field_multiplications, 676_296);
    assert_eq!(work.field_additions, 581_808);
    assert_eq!(work, POST_AUTHENTICATION_JOINT_BINDING_WORK_V2);
    let root = hash_joint_binding_v2(parameter, &refs).expect("current frame");
    assert_eq!(root, ProofDigestV1::from_shared(frame.hash()));
    let ledger = &RNS_NATIVE_NUMERIC_OPENING_HANDOFF_POST_AUTHENTICATION_LOCAL_RESOURCE_LEDGER_V2;
    assert_eq!(
        u64::from(ledger.post_authentication_joint_binding_words_per_lane),
        work.words_per_lane
    );
    assert_eq!(
        u64::from(ledger.post_authentication_joint_binding_lane_permutations),
        work.lane_permutations
    );
    assert_eq!(
        u64::from(ledger.post_authentication_joint_binding_poseidon_rounds),
        work.poseidon_rounds
    );
    assert_eq!(
        u64::from(ledger.post_authentication_joint_binding_field_multiplications),
        work.field_multiplications
    );
    assert_eq!(
        u64::from(ledger.post_authentication_joint_binding_field_additions),
        work.field_additions
    );
    assert_eq!(
        u64::from(ledger.post_authentication_local_work_units),
        22_000 + 824 + 2_016 + work.field_multiplications + work.field_additions
    );
    for ordinal in [8, 18, 19, 20, 22, 23, 24, 25, 26, 27] {
        let mut changed = fields.clone();
        changed[ordinal][47] ^= 1;
        let refs: Vec<&[u8]> = changed.iter().map(Vec::as_slice).collect();
        assert_ne!(
            hash_joint_binding_v2(parameter, &refs).expect("changed native sixth lane"),
            root
        );
    }
    let mut retired = fields.clone();
    for ordinal in [8, 18, 19, 20, 22, 23, 24, 25, 26, 27] {
        retired[ordinal].truncate(32);
    }
    let retired_refs: Vec<&[u8]> = retired.iter().map(Vec::as_slice).collect();
    assert!(matches!(
        hash_joint_binding_v2(parameter, &retired_refs),
        Err(RnsNativeNumericOpeningHandoffErrorV2::InvalidCount)
    ));
    let mut retired_version = fields.clone();
    retired_version[1] = vec![2];
    assert!(
        hash_joint_binding_v2(
            parameter,
            &retired_version
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>()
        )
        .is_err()
    );
    let mut foreign = parameter;
    foreign[0] ^= 1;
    assert!(hash_joint_binding_v2(foreign, &refs).is_err());
    let mut extra = fields.clone();
    extra.push(vec![1]);
    assert!(
        hash_joint_binding_v2(
            parameter,
            &extra.iter().map(Vec::as_slice).collect::<Vec<_>>()
        )
        .is_err()
    );
}
