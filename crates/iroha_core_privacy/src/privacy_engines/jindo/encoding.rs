//! CELPC coefficient encoding used by the fixed Jindo profile.
//!
//! 128 coefficient-field values are interleaved across the 1024
//! application-ring coefficients. For slot `i`, coefficients at
//! `i + 128*j` are the eight base-3611623616 digits. Evaluation at
//! `X^128 = 3611623616` recovers the slot modulo `p = 3611623616^8 + 1`.
use super::{
    JINDO_ENCODING_BASE_V1, JINDO_ENCODING_EXPONENT_V1, JINDO_ENCODING_SLOTS_V1,
    JINDO_RING_DEGREE_V1,
    field::JindoFieldElementV1,
    ring::{JINDO_INNER_MODULI_V1, JindoRnsPolynomialV1},
};
/// Deterministically encode at most 128 coefficient-field values.
pub fn encode_coefficient_slots_v1(values: &[JindoFieldElementV1]) -> Option<JindoRnsPolynomialV1> {
    if values.len() > JINDO_ENCODING_SLOTS_V1 {
        return None;
    }
    let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
    for (slot, value) in values.iter().copied().enumerate() {
        let mut limbs = value.to_canonical_limbs();
        for digit in 0..(JINDO_ENCODING_EXPONENT_V1 - 1) {
            let remainder = div_rem_small(&mut limbs, JINDO_ENCODING_BASE_V1);
            coefficients[digit * JINDO_ENCODING_SLOTS_V1 + slot] = i128::from(remainder);
        }
        debug_assert_eq!(limbs[1..], [0; 3]);
        debug_assert!(limbs[0] <= JINDO_ENCODING_BASE_V1);
        coefficients[(JINDO_ENCODING_EXPONENT_V1 - 1) * JINDO_ENCODING_SLOTS_V1 + slot] =
            i128::from(limbs[0]);
    }
    Some(JindoRnsPolynomialV1::from_balanced_coefficients(
        coefficients,
        JINDO_INNER_MODULI_V1,
    ))
}
/// Decode all 128 slots through the Jindo ring homomorphism.
pub fn decode_coefficient_slots_v1(
    polynomial: &JindoRnsPolynomialV1,
) -> [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] {
    let mut values = [JindoFieldElementV1::ZERO; JINDO_ENCODING_SLOTS_V1];
    let base = JindoFieldElementV1::from_u64(JINDO_ENCODING_BASE_V1);
    for slot in 0..JINDO_ENCODING_SLOTS_V1 {
        let mut value = JindoFieldElementV1::ZERO;
        for digit in (0..JINDO_ENCODING_EXPONENT_V1).rev() {
            let coefficient = polynomial.balanced_coefficient(
                digit * JINDO_ENCODING_SLOTS_V1 + slot,
                JINDO_INNER_MODULI_V1,
            );
            value = value * base + JindoFieldElementV1::from_i128(coefficient);
        }
        values[slot] = value;
    }
    values
}
/// Decode an exact balanced integer polynomial without first reducing it
/// modulo the inner commitment modulus.
///
/// Jindo's reference implementation uses an additional ambient CRT prime for the pre-challenge
/// split evaluations. Keeping the exact coefficients in `i128` is equivalent for this fixed profile
/// and makes the no-wrap argument explicit: the reviewed bound is below `2^93`, far inside `i128`.
pub fn decode_exact_coefficient_slots_v1(
    coefficients: &[i128; JINDO_RING_DEGREE_V1],
) -> [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] {
    let mut values = [JindoFieldElementV1::ZERO; JINDO_ENCODING_SLOTS_V1];
    let base = JindoFieldElementV1::from_u64(JINDO_ENCODING_BASE_V1);
    for slot in 0..JINDO_ENCODING_SLOTS_V1 {
        let mut value = JindoFieldElementV1::ZERO;
        for digit in (0..JINDO_ENCODING_EXPONENT_V1).rev() {
            value = value * base
                + JindoFieldElementV1::from_i128(
                    coefficients[digit * JINDO_ENCODING_SLOTS_V1 + slot],
                );
        }
        values[slot] = value;
    }
    values
}
fn div_rem_small(limbs: &mut [u64; 4], divisor: u64) -> u64 {
    let mut remainder = 0_u128;
    for limb in limbs.iter_mut().rev() {
        let numerator = (remainder << 64) | u128::from(*limb);
        *limb = (numerator / u128::from(divisor)) as u64;
        remainder = numerator % u128::from(divisor);
    }
    remainder as u64
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base_division_reconstructs_full_width_values() {
        let original = [
            0xf9a0_ffff_ffff_ffff,
            0x17e8_54be_7764_570e,
            0xc1de_7013_0355_aeec,
            0x4000_0969_b871_277c,
        ];
        let mut quotient = original;
        let mut digits = [0_u64; JINDO_ENCODING_EXPONENT_V1];
        for digit in &mut digits[..JINDO_ENCODING_EXPONENT_V1 - 1] {
            *digit = div_rem_small(&mut quotient, JINDO_ENCODING_BASE_V1);
            assert!(*digit < JINDO_ENCODING_BASE_V1);
        }
        assert_eq!(quotient[1..], [0; 3]);
        digits[JINDO_ENCODING_EXPONENT_V1 - 1] = quotient[0];
        assert!(digits[JINDO_ENCODING_EXPONENT_V1 - 1] <= JINDO_ENCODING_BASE_V1);
        let mut reconstructed = JindoFieldElementV1::ZERO;
        let base = JindoFieldElementV1::from_u64(JINDO_ENCODING_BASE_V1);
        for digit in digits.into_iter().rev() {
            reconstructed = reconstructed * base + JindoFieldElementV1::from_u64(digit);
        }
        assert_eq!(
            reconstructed,
            JindoFieldElementV1::from_canonical_bytes({
                let mut bytes = [0_u8; 32];
                for (chunk, limb) in bytes.chunks_exact_mut(8).zip(original) {
                    chunk.copy_from_slice(&limb.to_le_bytes());
                }
                bytes
            })
            .expect("canonical boundary")
        );
    }
    #[test]
    fn deterministic_encoding_roundtrips_every_slot_and_boundary_value() {
        let values: [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] =
            core::array::from_fn(|i| JindoFieldElementV1::from_u64((i as u64 + 1) * 1_000_003));
        let encoded = encode_coefficient_slots_v1(&values).expect("128 values");
        assert_eq!(decode_coefficient_slots_v1(&encoded), values);
    }
    #[test]
    fn encoder_rejects_more_than_profile_slots() {
        assert!(
            encode_coefficient_slots_v1(&[JindoFieldElementV1::ZERO; JINDO_ENCODING_SLOTS_V1 + 1])
                .is_none()
        );
    }
    #[test]
    fn decoding_is_additively_homomorphic() {
        let left_values: [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] =
            core::array::from_fn(|index| JindoFieldElementV1::from_u64(index as u64 * 17 + 1));
        let right_values: [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] =
            core::array::from_fn(|index| JindoFieldElementV1::from_u64(index as u64 * 31 + 2));
        let mut sum =
            encode_coefficient_slots_v1(&left_values).expect("left deterministic encoding");
        sum.add_assign(
            &encode_coefficient_slots_v1(&right_values).expect("right deterministic encoding"),
            JINDO_INNER_MODULI_V1,
        );
        let expected: [JindoFieldElementV1; JINDO_ENCODING_SLOTS_V1] =
            core::array::from_fn(|index| left_values[index] + right_values[index]);
        assert_eq!(decode_coefficient_slots_v1(&sum), expected);
    }
    #[test]
    fn exact_integer_decoder_matches_rns_when_no_reduction_occurs() {
        let coefficients: [i128; JINDO_RING_DEGREE_V1] =
            core::array::from_fn(|index| (index as i128 % 31) - 15);
        let encoded =
            JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, JINDO_INNER_MODULI_V1);
        assert_eq!(
            decode_exact_coefficient_slots_v1(&coefficients),
            decode_coefficient_slots_v1(&encoded)
        );
    }
}
