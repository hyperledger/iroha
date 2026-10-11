//! Fixed-width integers for foreign-field witnesses, bounds and constants.
//!
//! [`Nat`] is a 576-bit integer in nine little-endian 64-bit words. Unsigned
//! values use it directly; signed values (the carries of the fused gate) use
//! it as a two's complement word with wrapping arithmetic. 576 bits cover
//! every quantity the chip handles: products of two operands are below
//! `2^538`, and the carry chain stays below `2^200` in magnitude.
//!
//! Arithmetic that touches witness values is constant time: addition,
//! subtraction, multiplication and shifts by public amounts have no
//! data-dependent branches, [`Nat::div_rem`] is a fixed-length restoring
//! division with masked subtraction, and [`Nat::pow_mod`] is a fixed-length
//! square-and-multiply with masked selection. Moduli, bounds and shift
//! amounts are public.

use core::cmp::Ordering;

use iroha_pasta::PastaField;

/// The number of 64-bit words of a [`Nat`].
pub const NAT_WORDS: usize = 9;

/// The number of bits of a [`Nat`].
pub const NAT_BITS: usize = 64 * NAT_WORDS;

/// A 576-bit integer, little-endian words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nat(pub(crate) [u64; NAT_WORDS]);

impl Default for Nat {
    fn default() -> Self {
        Self::ZERO
    }
}

/// `mask` (all ones or all zeros) selects `a`, otherwise `b`.
const fn select_word(mask: u64, a: u64, b: u64) -> u64 {
    (a & mask) | (b & !mask)
}

impl Nat {
    /// Zero.
    pub const ZERO: Self = Self([0; NAT_WORDS]);
    /// One.
    pub const ONE: Self = Self::from_u64(1);

    /// A small value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let mut words = [0; NAT_WORDS];
        words[0] = value;
        Self(words)
    }

    /// A 128-bit value.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        let mut words = [0; NAT_WORDS];
        // Truncation is the intended split into two words.
        #[allow(clippy::cast_possible_truncation)]
        {
            words[0] = value as u64;
            words[1] = (value >> 64) as u64;
        }
        Self(words)
    }

    /// A 256-bit value from little-endian words.
    #[must_use]
    pub const fn from_words(value: [u64; 4]) -> Self {
        let mut words = [0; NAT_WORDS];
        words[0] = value[0];
        words[1] = value[1];
        words[2] = value[2];
        words[3] = value[3];
        Self(words)
    }

    /// `2^bits` (zero when `bits >= 576`).
    #[must_use]
    pub const fn pow2(bits: usize) -> Self {
        let mut words = [0; NAT_WORDS];
        if bits < NAT_BITS {
            words[bits / 64] = 1 << (bits % 64);
        }
        Self(words)
    }

    /// The little-endian words.
    #[must_use]
    pub const fn words(&self) -> &[u64; NAT_WORDS] {
        &self.0
    }

    /// The low 256 bits as little-endian words.
    #[must_use]
    pub const fn low_words(&self) -> [u64; 4] {
        [self.0[0], self.0[1], self.0[2], self.0[3]]
    }

    /// The low 128 bits.
    #[must_use]
    pub const fn low_u128(&self) -> u128 {
        (self.0[0] as u128) | ((self.0[1] as u128) << 64)
    }

    /// The value as a `u128` when it fits (unsigned reading).
    #[must_use]
    pub fn to_u128(self) -> Option<u128> {
        self.0[2..]
            .iter()
            .all(|word| *word == 0)
            .then(|| self.low_u128())
    }

    /// The value as 256-bit little-endian words when it fits (unsigned).
    #[must_use]
    pub fn to_words(self) -> Option<[u64; 4]> {
        self.0[4..]
            .iter()
            .all(|word| *word == 0)
            .then(|| self.low_words())
    }

    /// Whether the two's complement reading is negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.0[NAT_WORDS - 1] >> 63 == 1
    }

    /// The number of significant bits of the unsigned reading (0 for zero).
    /// Variable time; public values only.
    #[must_use]
    pub fn bits_vartime(&self) -> usize {
        for (index, word) in self.0.iter().enumerate().rev() {
            if *word != 0 {
                return 64 * index + (64 - word.leading_zeros() as usize);
            }
        }
        0
    }

    /// `self + other` modulo `2^576`.
    #[must_use]
    pub fn wrapping_add(&self, other: &Self) -> Self {
        let mut out = [0; NAT_WORDS];
        let mut carry = 0_u64;
        for (index, out) in out.iter_mut().enumerate() {
            let (sum, first) = self.0[index].overflowing_add(other.0[index]);
            let (sum, second) = sum.overflowing_add(carry);
            *out = sum;
            carry = u64::from(first) + u64::from(second);
        }
        Self(out)
    }

    /// `self - other` modulo `2^576`, and whether it borrowed (the unsigned
    /// `self < other`).
    #[must_use]
    pub fn overflowing_sub(&self, other: &Self) -> (Self, bool) {
        let mut out = [0; NAT_WORDS];
        let mut borrow = 0_u64;
        for (index, out) in out.iter_mut().enumerate() {
            let (diff, first) = self.0[index].overflowing_sub(other.0[index]);
            let (diff, second) = diff.overflowing_sub(borrow);
            *out = diff;
            borrow = u64::from(first) | u64::from(second);
        }
        (Self(out), borrow == 1)
    }

    /// `self - other` modulo `2^576`.
    #[must_use]
    pub fn wrapping_sub(&self, other: &Self) -> Self {
        self.overflowing_sub(other).0
    }

    /// `-self` modulo `2^576`.
    #[must_use]
    pub fn wrapping_neg(&self) -> Self {
        Self::ZERO.wrapping_sub(self)
    }

    /// `self * other` modulo `2^576` (schoolbook, constant time).
    #[must_use]
    pub fn wrapping_mul(&self, other: &Self) -> Self {
        let mut out = [0_u64; NAT_WORDS];
        for i in 0..NAT_WORDS {
            let mut carry = 0_u128;
            for j in 0..NAT_WORDS - i {
                let wide =
                    u128::from(self.0[i]) * u128::from(other.0[j]) + u128::from(out[i + j]) + carry;
                // Truncation keeps the low word; the high word carries.
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[i + j] = wide as u64;
                }
                carry = wide >> 64;
            }
        }
        Self(out)
    }

    /// `self << bits` modulo `2^576`.
    #[must_use]
    pub fn shl(&self, bits: usize) -> Self {
        let mut out = [0_u64; NAT_WORDS];
        let words = bits / 64;
        let rem = bits % 64;
        for index in (0..NAT_WORDS).rev() {
            if index < words {
                break;
            }
            let source = index - words;
            let mut value = self.0[source] << rem;
            if rem > 0 && source > 0 {
                value |= self.0[source - 1] >> (64 - rem);
            }
            out[index] = value;
        }
        Self(out)
    }

    /// The logical `self >> bits`.
    #[must_use]
    pub fn shr(&self, bits: usize) -> Self {
        self.shift_right(bits, 0)
    }

    /// The arithmetic (two's complement) `self >> bits`: `floor(self / 2^bits)`
    /// for the signed reading.
    #[must_use]
    pub fn sar(&self, bits: usize) -> Self {
        let fill = 0_u64.wrapping_sub(u64::from(self.is_negative()));
        self.shift_right(bits, fill)
    }

    /// `self >> bits` with `fill` shifted in from the top.
    fn shift_right(&self, bits: usize, fill: u64) -> Self {
        let mut out = [fill; NAT_WORDS];
        let words = bits / 64;
        let rem = bits % 64;
        for (index, out) in out.iter_mut().enumerate() {
            let source = index + words;
            if source >= NAT_WORDS {
                break;
            }
            let low = self.0[source];
            let high = self.0.get(source + 1).copied().unwrap_or(fill);
            *out = if rem == 0 {
                low
            } else {
                (low >> rem) | (high << (64 - rem))
            };
        }
        Self(out)
    }

    /// Bit `index` of the unsigned reading.
    #[must_use]
    pub const fn bit(&self, index: usize) -> bool {
        index < NAT_BITS && (self.0[index / 64] >> (index % 64)) & 1 == 1
    }

    /// The low `bits` bits (`bits <= 128`) as a `u128`.
    #[must_use]
    pub fn low_bits_u128(&self, bits: usize) -> u128 {
        let low = self.low_u128();
        if bits >= 128 {
            low
        } else {
            low & ((1_u128 << bits) - 1)
        }
    }

    /// Constant-time selection: `a` when `choice`, otherwise `b`.
    #[must_use]
    pub fn select(choice: bool, a: &Self, b: &Self) -> Self {
        let mask = 0_u64.wrapping_sub(u64::from(choice));
        let mut out = [0; NAT_WORDS];
        for (index, out) in out.iter_mut().enumerate() {
            *out = select_word(mask, a.0[index], b.0[index]);
        }
        Self(out)
    }

    /// Unsigned comparison (variable time; public values only).
    #[must_use]
    pub fn cmp_vartime(&self, other: &Self) -> Ordering {
        for index in (0..NAT_WORDS).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                order => return order,
            }
        }
        Ordering::Equal
    }

    /// Unsigned `(self / divisor, self mod divisor)` for a nonzero divisor
    /// below `2^575`, or `None` for a zero or oversized divisor.
    ///
    /// Constant time in `self`: a fixed 576-step restoring division whose
    /// subtraction is selected by mask.
    #[must_use]
    pub fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if *divisor == Self::ZERO || divisor.is_negative() {
            return None;
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for index in (0..NAT_BITS).rev() {
            remainder = remainder.shl(1);
            remainder.0[0] |= u64::from(self.bit(index));
            let (difference, borrow) = remainder.overflowing_sub(divisor);
            remainder = Self::select(!borrow, &difference, &remainder);
            quotient.0[index / 64] |= u64::from(!borrow) << (index % 64);
        }
        Some((quotient, remainder))
    }

    /// `self mod modulus`, or `None` for a zero or oversized modulus.
    #[must_use]
    pub fn rem(&self, modulus: &Self) -> Option<Self> {
        self.div_rem(modulus).map(|(_, remainder)| remainder)
    }

    /// `self^exponent mod modulus` for `self < modulus < 2^288`, by a fixed
    /// 288-step square-and-multiply (constant time in `self`; the exponent is
    /// public), or `None` for an invalid modulus.
    #[must_use]
    pub fn pow_mod(&self, exponent: &Self, modulus: &Self) -> Option<Self> {
        if modulus.bits_vartime() > 288 || *modulus == Self::ZERO {
            return None;
        }
        let base = self.rem(modulus)?;
        let mut acc = Self::ONE.rem(modulus)?;
        for index in (0..288).rev() {
            acc = acc.wrapping_mul(&acc).rem(modulus)?;
            let product = acc.wrapping_mul(&base).rem(modulus)?;
            acc = Self::select(exponent.bit(index), &product, &acc);
        }
        Some(acc)
    }

    /// The field element congruent to the unsigned reading.
    #[must_use]
    pub fn to_field<F: PastaField>(self) -> F {
        let radix = F::from_u128(1_u128 << 64);
        self.0
            .iter()
            .rev()
            .fold(F::ZERO, |acc, word| acc * radix + F::from(*word))
    }

    /// The field element congruent to the two's complement reading.
    #[must_use]
    pub fn to_field_signed<F: PastaField>(self) -> F {
        let negative = self.is_negative();
        let magnitude = Self::select(negative, &self.wrapping_neg(), &self);
        let value = magnitude.to_field::<F>();
        // `value (1 - 2 negative)`, without a branch on the sign.
        let sign = F::from(u64::from(negative));
        value - (value + value) * sign
    }

    /// The canonical integer of a field element.
    #[must_use]
    pub fn from_field<F: PastaField>(value: &F) -> Self {
        Self::from_words(value.to_canonical_limbs())
    }
}

#[cfg(test)]
mod tests {
    use ::ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};

    use super::*;

    fn nat(words: &[u64]) -> Nat {
        let mut out = [0; NAT_WORDS];
        out[..words.len()].copy_from_slice(words);
        Nat(out)
    }

    #[test]
    fn constructors_and_views() {
        assert_eq!(Nat::from_u128(u128::MAX).to_u128(), Some(u128::MAX));
        assert_eq!(Nat::pow2(128).to_u128(), None);
        assert_eq!(Nat::pow2(576), Nat::ZERO);
        assert_eq!(Nat::pow2(130).bits_vartime(), 131);
        assert_eq!(Nat::ZERO.bits_vartime(), 0);
        assert_eq!(Nat::from_words([1, 2, 3, 4]).to_words(), Some([1, 2, 3, 4]));
        assert_eq!(Nat::pow2(256).to_words(), None);
        assert_eq!(Nat::from_u64(0b1011).low_bits_u128(2), 0b11);
        assert_eq!(Nat::from_u128(u128::MAX).low_bits_u128(128), u128::MAX);
        assert!(Nat::from_u64(5).bit(2) && !Nat::from_u64(5).bit(1));
        assert!(!Nat::ONE.bit(NAT_BITS));
        assert_eq!(Nat::default(), Nat::ZERO);
        assert_eq!(Nat::ONE.words()[0], 1);
    }

    #[test]
    fn add_sub_mul_wrap_like_u128() {
        let cases = [
            (0_u128, 0_u128),
            (u128::from(u64::MAX), 1),
            (1 << 100, (1 << 100) - 7),
            (0x1234_5678_9abc_def0_1122_3344, 0xffff_0000_ffff),
        ];
        for (a, b) in cases {
            let (na, nb) = (Nat::from_u128(a), Nat::from_u128(b));
            let sum = na.wrapping_add(&nb);
            assert_eq!(sum.wrapping_sub(&nb), na);
            if let Some(expected) = a.checked_add(b) {
                assert_eq!(sum.to_u128(), Some(expected));
            }
            let (difference, borrow) = na.overflowing_sub(&nb);
            assert_eq!(borrow, a < b);
            if a >= b {
                assert_eq!(difference.to_u128(), Some(a - b));
            } else {
                assert!(difference.is_negative());
                assert_eq!(difference.wrapping_neg().to_u128(), Some(b - a));
            }
            if let Some(expected) = a.checked_mul(b) {
                assert_eq!(na.wrapping_mul(&nb).to_u128(), Some(expected));
            }
        }
        // (2^64 - 1)^2 spans two words.
        let max = Nat::from_u64(u64::MAX);
        assert_eq!(
            max.wrapping_mul(&max).to_u128(),
            Some(u128::from(u64::MAX) * u128::from(u64::MAX))
        );
        // Products wrap at 2^576.
        assert_eq!(Nat::pow2(300).wrapping_mul(&Nat::pow2(276)), Nat::ZERO);
        assert_eq!(Nat::pow2(300).wrapping_mul(&Nat::pow2(275)), Nat::pow2(575));
    }

    #[test]
    fn shifts_logical_and_arithmetic() {
        let value = nat(&[0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 7]);
        assert_eq!(value.shl(64).shr(64), value);
        assert_eq!(value.shl(0), value);
        assert_eq!(value.shr(0), value);
        assert_eq!(value.shl(4).shr(4), value);
        assert_eq!(value.shr(130), Nat::from_u64(1));
        assert_eq!(Nat::ONE.shl(575), Nat::pow2(575));
        assert_eq!(Nat::ONE.shl(576), Nat::ZERO);
        assert_eq!(value.shr(576), Nat::ZERO);
        // Arithmetic shift is floor division for negative values.
        let minus_five = Nat::from_u64(5).wrapping_neg();
        assert_eq!(minus_five.sar(1), Nat::from_u64(3).wrapping_neg());
        assert_eq!(minus_five.sar(600), Nat::ONE.wrapping_neg());
        let minus_big = Nat::pow2(200).wrapping_neg();
        assert_eq!(minus_big.sar(87), Nat::pow2(113).wrapping_neg());
        assert_eq!(Nat::pow2(200).sar(87), Nat::pow2(113));
    }

    #[test]
    fn division_matches_u128_and_reconstructs() {
        for (a, b) in [
            (0_u128, 1_u128),
            (17, 5),
            (u128::MAX, 3),
            (u128::MAX, u128::MAX),
            (1 << 127, (1 << 64) + 1),
        ] {
            let (quotient, remainder) = Nat::from_u128(a)
                .div_rem(&Nat::from_u128(b))
                .expect("divisor");
            assert_eq!(quotient.to_u128(), Some(a / b));
            assert_eq!(remainder.to_u128(), Some(a % b));
        }
        let wide = nat(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let divisor = nat(&[9, 0, 0, 1 << 60]);
        let (quotient, remainder) = wide.div_rem(&divisor).expect("divisor");
        assert_eq!(
            quotient.wrapping_mul(&divisor).wrapping_add(&remainder),
            wide
        );
        assert_eq!(remainder.cmp_vartime(&divisor), Ordering::Less);
        assert_eq!(wide.rem(&divisor), Some(remainder));
        assert_eq!(wide.div_rem(&Nat::ZERO), None);
        assert_eq!(wide.div_rem(&Nat::pow2(575)).map(|(q, _)| q), None);
    }

    #[test]
    fn pow_mod_is_fermat_inverse() {
        // p = 2^127 - 1 is prime.
        let p = Nat::from_u128((1 << 127) - 1);
        let a = Nat::from_u128(0x1234_5678_9abc_def0);
        let inverse = a
            .pow_mod(&p.wrapping_sub(&Nat::from_u64(2)), &p)
            .expect("modulus");
        assert_eq!(a.wrapping_mul(&inverse).rem(&p), Some(Nat::ONE));
        assert_eq!(a.pow_mod(&Nat::ZERO, &p), Some(Nat::ONE));
        assert_eq!(a.pow_mod(&Nat::ONE, &Nat::ZERO), None);
        assert_eq!(a.pow_mod(&Nat::ONE, &Nat::pow2(300)), None);
    }

    #[test]
    fn field_conversions() {
        let value = Nat::from_u128(u128::MAX);
        assert_eq!(value.to_field::<Fp>(), Fp::from_u128(u128::MAX));
        assert_eq!(
            Nat::from_u64(9).wrapping_neg().to_field_signed::<Fq>(),
            -Fq::from(9u64)
        );
        assert_eq!(Nat::from_u64(9).to_field_signed::<Fq>(), Fq::from(9u64));
        let minus_one = -Fp::ONE;
        assert_eq!(Nat::from_field(&minus_one).to_field::<Fp>(), minus_one);
        // 2^576 - 1 read unsigned reduces modulo the field order.
        let all_ones = Nat::ZERO.wrapping_sub(&Nat::ONE);
        let expected = Fp::from(2u64).pow_vartime([576]) - Fp::ONE;
        assert_eq!(all_ones.to_field::<Fp>(), expected);
        assert_eq!(all_ones.to_field_signed::<Fp>(), -Fp::ONE);
        assert!(Nat::select(true, &Nat::ONE, &Nat::ZERO) == Nat::ONE);
        assert!(Nat::select(false, &Nat::ONE, &Nat::ZERO) == Nat::ZERO);
    }
}
