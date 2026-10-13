//! Arbitrary-precision non-negative integers for public quantities.
//!
//! A modulus chain of many 50 to 60-bit primes has a product of hundreds or
//! thousands of bits, and so do the noise bounds a scheme derives from it.
//! [`Natural`] holds such values exactly. It is used for public data only:
//! modulus products, level capacities and noise bounds computed from profile
//! constants and the public operation history. Its operations branch on the
//! value and are not constant-time, so no secret-dependent quantity may be
//! stored in it. Residue arithmetic never goes through this type; see
//! [`crate::rns_chain`] for conversion that stays in word residues.
//!
//! The representation is little-endian 64-bit words without a most
//! significant zero word; zero is the empty word list. Every operation is
//! exact: nothing saturates, wraps or rounds unless its name says so.
use std::cmp::Ordering;

/// An exact non-negative integer of any size.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Natural {
    /// Little-endian words, the last one non-zero.
    words: Vec<u64>,
}

impl Natural {
    /// Zero.
    #[must_use]
    pub const fn zero() -> Self {
        Self { words: Vec::new() }
    }

    /// One.
    #[must_use]
    pub fn one() -> Self {
        Self::from_u64(1)
    }

    /// The value of one word.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self::from_words_le(&[value])
    }

    /// The value of a 128-bit integer.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        Self::from_words_le(&[
            crate::modular::low_u64_from_u128(value),
            crate::modular::low_u64_from_u128(value >> 64),
        ])
    }

    /// The value of little-endian words; most significant zero words are dropped.
    #[must_use]
    pub fn from_words_le(words: &[u64]) -> Self {
        let mut value = Self {
            words: words.to_vec(),
        };
        value.normalize();
        value
    }

    /// The exact product of the given words; the empty product is one.
    #[must_use]
    pub fn product_of(factors: &[u64]) -> Self {
        factors
            .iter()
            .fold(Self::one(), |product, &factor| product.mul_u64(factor))
    }

    /// Little-endian words without a most significant zero word; empty for zero.
    #[must_use]
    pub fn words_le(&self) -> &[u64] {
        &self.words
    }

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.words.is_empty()
    }

    /// Number of bits of the value; zero has bit length zero.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.words.last().map_or(0, |top| {
            (self.words.len() - 1) * 64 + (64 - top.leading_zeros() as usize)
        })
    }

    /// The value as one word, when it fits.
    #[must_use]
    pub fn to_u64(&self) -> Option<u64> {
        match self.words.as_slice() {
            [] => Some(0),
            [word] => Some(*word),
            _ => None,
        }
    }

    /// The value as a 128-bit integer, when it fits.
    #[must_use]
    pub fn to_u128(&self) -> Option<u128> {
        match self.words.as_slice() {
            [] => Some(0),
            [low] => Some(u128::from(*low)),
            [low, high] => Some(u128::from(*low) | (u128::from(*high) << 64)),
            _ => None,
        }
    }

    fn normalize(&mut self) {
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
    }

    /// `self + rhs`.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let (long, short) = if self.words.len() >= rhs.words.len() {
            (&self.words, &rhs.words)
        } else {
            (&rhs.words, &self.words)
        };
        let mut words = Vec::with_capacity(long.len() + 1);
        let mut carry = false;
        for (index, &word) in long.iter().enumerate() {
            let addend = short.get(index).copied().unwrap_or(0);
            let (sum, first) = word.overflowing_add(addend);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            words.push(sum);
            carry = first || second;
        }
        if carry {
            words.push(1);
        }
        Self { words }
    }

    /// `self + rhs` for one word.
    #[must_use]
    pub fn add_u64(&self, rhs: u64) -> Self {
        self.add(&Self::from_u64(rhs))
    }

    /// `self - rhs`, or `None` when `rhs > self`.
    #[must_use]
    pub fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        if self < rhs {
            return None;
        }
        let mut words = Vec::with_capacity(self.words.len());
        let mut borrow = false;
        for (index, &word) in self.words.iter().enumerate() {
            let subtrahend = rhs.words.get(index).copied().unwrap_or(0);
            let (difference, first) = word.overflowing_sub(subtrahend);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            words.push(difference);
            borrow = first || second;
        }
        let mut value = Self { words };
        value.normalize();
        Some(value)
    }

    /// `self * rhs` for one word.
    #[must_use]
    pub fn mul_u64(&self, rhs: u64) -> Self {
        if rhs == 0 || self.is_zero() {
            return Self::zero();
        }
        let mut words = Vec::with_capacity(self.words.len() + 1);
        let mut carry = 0_u128;
        for &word in &self.words {
            let product = u128::from(word) * u128::from(rhs) + carry;
            words.push(crate::modular::low_u64_from_u128(product));
            carry = product >> 64;
        }
        if carry != 0 {
            words.push(crate::modular::low_u64_from_u128(carry));
        }
        Self { words }
    }

    /// `self * rhs` by the schoolbook product.
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }
        let mut words = vec![0_u64; self.words.len() + rhs.words.len()];
        for (lhs_index, &lhs_word) in self.words.iter().enumerate() {
            let mut carry = 0_u128;
            for (rhs_index, &rhs_word) in rhs.words.iter().enumerate() {
                let slot = &mut words[lhs_index + rhs_index];
                // (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1, so the sum fits.
                let total = u128::from(lhs_word) * u128::from(rhs_word) + u128::from(*slot) + carry;
                *slot = crate::modular::low_u64_from_u128(total);
                carry = total >> 64;
            }
            words[lhs_index + rhs.words.len()] = crate::modular::low_u64_from_u128(carry);
        }
        let mut value = Self { words };
        value.normalize();
        value
    }

    /// Quotient and remainder of the division by one word.
    ///
    /// Returns `None` when `divisor` is zero.
    #[must_use]
    pub fn div_rem_u64(&self, divisor: u64) -> Option<(Self, u64)> {
        if divisor == 0 {
            return None;
        }
        let mut words = vec![0_u64; self.words.len()];
        let mut remainder = 0_u128;
        for (index, &word) in self.words.iter().enumerate().rev() {
            let numerator = (remainder << 64) | u128::from(word);
            words[index] = crate::modular::low_u64_from_u128(numerator / u128::from(divisor));
            remainder = numerator % u128::from(divisor);
        }
        let mut quotient = Self { words };
        quotient.normalize();
        Some((quotient, crate::modular::low_u64_from_u128(remainder)))
    }

    /// `floor(self / divisor)`, or `None` when `divisor` is zero.
    #[must_use]
    pub fn div_floor_u64(&self, divisor: u64) -> Option<Self> {
        self.div_rem_u64(divisor).map(|(quotient, _)| quotient)
    }

    /// `ceil(self / divisor)`, or `None` when `divisor` is zero.
    #[must_use]
    pub fn div_ceil_u64(&self, divisor: u64) -> Option<Self> {
        self.div_rem_u64(divisor).map(|(quotient, remainder)| {
            if remainder == 0 {
                quotient
            } else {
                quotient.add_u64(1)
            }
        })
    }

    /// `self mod divisor`, or `None` when `divisor` is zero.
    #[must_use]
    pub fn rem_u64(&self, divisor: u64) -> Option<u64> {
        self.div_rem_u64(divisor).map(|(_, remainder)| remainder)
    }

    /// `floor(self / 2)`.
    #[must_use]
    pub fn half_floor(&self) -> Self {
        let mut words = self.words.clone();
        let mut carry = 0_u64;
        for word in words.iter_mut().rev() {
            let next_carry = *word & 1;
            *word = (*word >> 1) | (carry << 63);
            carry = next_carry;
        }
        let mut value = Self { words };
        value.normalize();
        value
    }
}

impl PartialOrd for Natural {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Natural {
    fn cmp(&self, other: &Self) -> Ordering {
        self.words
            .len()
            .cmp(&other.words.len())
            .then_with(|| self.words.iter().rev().cmp(other.words.iter().rev()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn natural(value: u128) -> Natural {
        Natural::from_u128(value)
    }

    #[test]
    fn constructors_normalize_and_round_trip() {
        assert!(Natural::zero().is_zero());
        assert_eq!(Natural::zero().bit_len(), 0);
        assert_eq!(Natural::one().to_u64(), Some(1));
        assert_eq!(Natural::from_u64(0), Natural::zero());
        assert_eq!(Natural::from_words_le(&[5, 0, 0]).words_le(), &[5]);
        assert_eq!(Natural::from_words_le(&[0, 0]), Natural::zero());
        assert_eq!(natural(u128::MAX).to_u128(), Some(u128::MAX));
        assert_eq!(natural(u128::MAX).to_u64(), None);
        assert_eq!(natural(1 << 64).words_le(), &[0, 1]);
        assert_eq!(natural(1 << 64).bit_len(), 65);
        assert_eq!(Natural::from_u64(u64::MAX).bit_len(), 64);
        assert_eq!(Natural::from_words_le(&[1, 2, 3]).to_u128(), None);
        assert_eq!(Natural::default(), Natural::zero());
    }

    #[test]
    fn addition_and_subtraction_carry_across_words() {
        let max = Natural::from_u64(u64::MAX);
        assert_eq!(max.add(&Natural::one()), natural(1 << 64));
        assert_eq!(max.add_u64(1), natural(1 << 64));
        assert_eq!(
            natural(u128::MAX).add(&Natural::one()).words_le(),
            &[0, 0, 1]
        );
        assert_eq!(Natural::zero().add(&max), max);
        assert_eq!(natural(1 << 64).checked_sub(&Natural::one()), Some(max));
        assert_eq!(
            Natural::from_words_le(&[0, 0, 1]).checked_sub(&Natural::one()),
            Some(natural(u128::MAX))
        );
        assert_eq!(Natural::one().checked_sub(&natural(2)), None);
        assert_eq!(natural(7).checked_sub(&natural(7)), Some(Natural::zero()));
    }

    #[test]
    fn products_match_wide_arithmetic() {
        let lhs = 0xFEDC_BA98_7654_3210_u64;
        let rhs = 0x0123_4567_89AB_CDEF_u64;
        assert_eq!(
            Natural::from_u64(lhs).mul_u64(rhs),
            natural(u128::from(lhs) * u128::from(rhs))
        );
        assert_eq!(
            Natural::from_u64(lhs).mul(&Natural::from_u64(rhs)),
            natural(u128::from(lhs) * u128::from(rhs))
        );
        assert_eq!(Natural::from_u64(lhs).mul_u64(0), Natural::zero());
        assert_eq!(Natural::zero().mul(&natural(5)), Natural::zero());
        // (2^128 - 1)^2 = 2^256 - 2^129 + 1.
        let square = natural(u128::MAX).mul(&natural(u128::MAX));
        assert_eq!(square.words_le(), &[1, 0, u64::MAX - 1, u64::MAX]);
        // Multiplication distributes over addition on multi-word operands.
        let a = Natural::from_words_le(&[u64::MAX, 3, 9]);
        let b = Natural::from_words_le(&[7, u64::MAX]);
        let c = Natural::from_words_le(&[u64::MAX, u64::MAX, 1]);
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(Natural::product_of(&[]), Natural::one());
        assert_eq!(
            Natural::product_of(&[u64::MAX, u64::MAX]),
            natural(u128::from(u64::MAX) * u128::from(u64::MAX))
        );
    }

    #[test]
    fn division_by_a_word_is_exact() {
        let value = Natural::from_words_le(&[0x1234, 0xABCD, 0x77]);
        for divisor in [1_u64, 2, 3, 257, u64::MAX, 1 << 63] {
            let (quotient, remainder) = value.div_rem_u64(divisor).expect("non-zero divisor");
            assert!(remainder < divisor);
            assert_eq!(quotient.mul_u64(divisor).add_u64(remainder), value);
            assert_eq!(value.rem_u64(divisor), Some(remainder));
            assert_eq!(value.div_floor_u64(divisor), Some(quotient.clone()));
            let ceil = value.div_ceil_u64(divisor).expect("non-zero divisor");
            assert_eq!(
                ceil,
                if remainder == 0 {
                    quotient
                } else {
                    quotient.add_u64(1)
                }
            );
        }
        assert_eq!(value.div_rem_u64(0), None);
        assert_eq!(value.div_floor_u64(0), None);
        assert_eq!(value.div_ceil_u64(0), None);
        assert_eq!(value.rem_u64(0), None);
        assert_eq!(natural(10).div_ceil_u64(5), Some(natural(2)));
        assert_eq!(natural(11).div_ceil_u64(5), Some(natural(3)));
        assert_eq!(Natural::zero().div_ceil_u64(5), Some(Natural::zero()));
    }

    #[test]
    fn halving_shifts_across_words() {
        assert_eq!(natural(1 << 64).half_floor(), natural(1 << 63));
        assert_eq!(natural(7).half_floor(), natural(3));
        assert_eq!(Natural::one().half_floor(), Natural::zero());
        assert_eq!(Natural::zero().half_floor(), Natural::zero());
        assert_eq!(natural(u128::MAX).half_floor(), natural(u128::MAX >> 1));
    }

    #[test]
    fn ordering_compares_length_then_most_significant_words() {
        let small = Natural::from_words_le(&[u64::MAX]);
        let large = Natural::from_words_le(&[0, 1]);
        assert!(small < large);
        assert!(Natural::from_words_le(&[5, 2]) < Natural::from_words_le(&[1, 3]));
        assert!(Natural::from_words_le(&[5, 3]) > Natural::from_words_le(&[4, 3]));
        assert_eq!(natural(9).cmp(&natural(9)), Ordering::Equal);
        assert_eq!(natural(9).partial_cmp(&natural(10)), Some(Ordering::Less));
        assert!(Natural::zero() < Natural::one());
    }
}
