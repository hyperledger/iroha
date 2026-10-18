//! Exact integer two-norm accumulation for Jindo verification.
//!
//! The largest squared coefficient sum does not fit `u128`.  This small
//! four-limb accumulator avoids floating point, platform-dependent square
//! roots, saturation, and a new big-integer dependency in consensus code.
use super::{
    JINDO_RING_DEGREE_V1,
    ring::{JindoPrimeModulusV1, JindoRnsPolynomialV1},
};
/// Square of the exact pinned inner-response norm ceiling.
///
/// The ceiling itself is `26_726_985_705_641_897_984`, the exact integer
/// represented by the selected parameter-search binary64 value.
pub const JINDO_RESPONSE_NORM_SQUARED_BOUND_V1: [u64; 4] = [
    0x916f_f826_f100_0000,
    0x1967_4b2b_1d7c_fdc7,
    0x0000_0000_0000_0002,
    0x0000_0000_0000_0000,
];
/// Square of the exact pinned outer-relation norm ceiling.
///
/// The ceiling itself is `4_811_910_842_327_350_272`.
pub const JINDO_DECOMPOSED_NORM_SQUARED_BOUND_V1: [u64; 4] = [
    0x613e_e842_e210_0000,
    0x116b_644b_ffff_ff5b,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct U256([u64; 4]);
impl U256 {
    fn checked_add_square(&mut self, magnitude: u128) -> bool {
        let square = square_u128(magnitude);
        let mut carry = 0_u64;
        for (target, addend) in self.0.iter_mut().zip(square) {
            let sum = u128::from(*target) + u128::from(addend) + u128::from(carry);
            *target = sum as u64;
            carry = (sum >> 64) as u64;
        }
        carry == 0
    }
    fn less_than(self, rhs: [u64; 4]) -> bool {
        for index in (0..4).rev() {
            if self.0[index] != rhs[index] {
                return self.0[index] < rhs[index];
            }
        }
        false
    }
}
fn square_u128(value: u128) -> [u64; 4] {
    let limbs = [value as u64, (value >> 64) as u64];
    let mut product = [0_u64; 4];
    for left_index in 0..2 {
        let mut carry = 0_u64;
        for right_index in 0..2 {
            let index = left_index + right_index;
            let accumulation = u128::from(limbs[left_index]) * u128::from(limbs[right_index])
                + u128::from(product[index])
                + u128::from(carry);
            product[index] = accumulation as u64;
            carry = (accumulation >> 64) as u64;
        }
        let mut index = left_index + 2;
        while carry != 0 {
            debug_assert!(index < product.len());
            let (sum, overflow) = product[index].overflowing_add(carry);
            product[index] = sum;
            carry = u64::from(overflow);
            index += 1;
        }
    }
    product
}
pub fn two_norm_squared_is_below_v1(
    polynomials: &[JindoRnsPolynomialV1],
    moduli: [JindoPrimeModulusV1; 2],
    bound_squared: [u64; 4],
) -> bool {
    let mut sum = U256::default();
    for polynomial in polynomials {
        for coefficient_index in 0..JINDO_RING_DEGREE_V1 {
            let coefficient = polynomial.balanced_coefficient(coefficient_index, moduli);
            if !sum.checked_add_square(coefficient.unsigned_abs()) {
                return false;
            }
        }
    }
    sum.less_than(bound_squared)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::jindo::ring::JINDO_INNER_MODULI_V1;
    #[test]
    fn full_width_squaring_matches_independent_known_answers() {
        for (value, expected) in [
            (0_u128, [0, 0, 0, 0]),
            (1, [1, 0, 0, 0]),
            (
                u128::from(u64::MAX),
                [0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe, 0, 0],
            ),
            (
                u128::MAX,
                [
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0xffff_ffff_ffff_fffe,
                    0xffff_ffff_ffff_ffff,
                ],
            ),
        ] {
            assert_eq!(square_u128(value), expected);
        }
    }
    #[test]
    fn accumulator_detects_overflow_and_strict_boundary() {
        let accumulator = U256(JINDO_RESPONSE_NORM_SQUARED_BOUND_V1);
        assert!(!accumulator.less_than(JINDO_RESPONSE_NORM_SQUARED_BOUND_V1));
        let mut below = JINDO_RESPONSE_NORM_SQUARED_BOUND_V1;
        below[0] -= 1;
        assert!(U256(below).less_than(JINDO_RESPONSE_NORM_SQUARED_BOUND_V1));
        let mut overflow = U256([u64::MAX; 4]);
        assert!(!overflow.checked_add_square(1));
    }
    #[test]
    fn polynomial_norm_uses_balanced_crt_representatives() {
        let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
        coefficients[0] = -3;
        coefficients[1] = 4;
        let polynomial =
            JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, JINDO_INNER_MODULI_V1);
        assert!(two_norm_squared_is_below_v1(
            &[polynomial.clone()],
            JINDO_INNER_MODULI_V1,
            [26, 0, 0, 0]
        ));
        assert!(!two_norm_squared_is_below_v1(
            &[polynomial],
            JINDO_INNER_MODULI_V1,
            [25, 0, 0, 0]
        ));
    }
}
