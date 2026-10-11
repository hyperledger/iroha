//! Constant-time Montgomery arithmetic modulo an odd 256-bit modulus
//! (four 64-bit words, CIOS multiplication): the fast path of
//! [`super::ForeignModulus::fermat_inverse`] and of the P-256 native
//! reference.
//!
//! Every operation on values is constant time in them: fixed-length loops,
//! masked final subtractions and a fixed-length square-and-always-multiply
//! exponentiation with masked selection. Only the modulus (public) is
//! branched on, at construction.

/// `a + b` with the carry out.
const fn add_words(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0_u64; 4];
    let mut carry = 0_u64;
    let mut index = 0;
    while index < 4 {
        let sum = a[index] as u128 + b[index] as u128 + carry as u128;
        // Truncation keeps the low word; the carry is the high bit.
        #[allow(clippy::cast_possible_truncation)]
        {
            out[index] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        index += 1;
    }
    (out, carry)
}

/// `a - b` with the borrow out (1 when `a < b`).
const fn sub_words(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0_u64; 4];
    let mut borrow = 0_u64;
    let mut index = 0;
    while index < 4 {
        let (difference, under_a) = a[index].overflowing_sub(b[index]);
        let (difference, under_b) = difference.overflowing_sub(borrow);
        out[index] = difference;
        borrow = (under_a | under_b) as u64;
        index += 1;
    }
    (out, borrow)
}

/// `mask` (all ones or zeros) selects `a`, otherwise `b`.
const fn select_words(mask: u64, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    [
        (a[0] & mask) | (b[0] & !mask),
        (a[1] & mask) | (b[1] & !mask),
        (a[2] & mask) | (b[2] & !mask),
        (a[3] & mask) | (b[3] & !mask),
    ]
}

/// A Montgomery modulus: odd `m < 2^256` with `-m^-1 mod 2^64` and
/// `R^2 mod m` (`R = 2^256`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontModulus {
    m: [u64; 4],
    inv: u64,
    r2: [u64; 4],
}

impl MontModulus {
    /// The constants of an odd modulus `m > 1`.
    #[must_use]
    pub const fn new(m: [u64; 4]) -> Self {
        // Newton's iteration doubles the correct low bits of `m^-1 mod 2^64`.
        let mut inverse = 1_u64;
        let mut step = 0;
        while step < 6 {
            inverse = inverse.wrapping_mul(2_u64.wrapping_sub(m[0].wrapping_mul(inverse)));
            step += 1;
        }
        // R^2 mod m by 512 modular doublings of 1.
        let mut r2 = [1_u64, 0, 0, 0];
        let mut doubling = 0;
        while doubling < 512 {
            let (sum, carry) = add_words(&r2, &r2);
            let (reduced, borrow) = sub_words(&sum, &m);
            // Subtract when the sum overflowed or is at least m.
            let keep_sum = carry == 0 && borrow == 1;
            r2 = if keep_sum { sum } else { reduced };
            doubling += 1;
        }
        Self {
            m,
            inv: inverse.wrapping_neg(),
            r2,
        }
    }

    /// The modulus.
    #[must_use]
    pub const fn modulus(&self) -> [u64; 4] {
        self.m
    }

    /// `a + b mod m` for `a, b < m` (constant time).
    #[must_use]
    pub fn add(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let (sum, carry) = add_words(a, b);
        let (reduced, borrow) = sub_words(&sum, &self.m);
        // Keep the sum only when it did not overflow and is below m.
        let keep = (carry ^ 1) & borrow;
        select_words(keep.wrapping_neg(), &sum, &reduced)
    }

    /// `a - b mod m` for `a, b < m` (constant time).
    #[must_use]
    pub fn sub(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let (difference, borrow) = sub_words(a, b);
        let (wrapped, _) = add_words(&difference, &self.m);
        select_words(borrow.wrapping_neg(), &wrapped, &difference)
    }

    /// `-a mod m` for `a < m`.
    #[must_use]
    pub fn neg(&self, a: &[u64; 4]) -> [u64; 4] {
        self.sub(&[0; 4], a)
    }

    /// The Montgomery product `a b R^-1 mod m` for `a, b < m` (CIOS,
    /// constant time).
    #[must_use]
    pub fn mont_mul(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let m = &self.m;
        let mut t = [0_u64; 6];
        for b_word in b {
            let mut carry = 0_u128;
            for index in 0..4 {
                let sum = u128::from(t[index]) + u128::from(a[index]) * u128::from(*b_word) + carry;
                #[allow(clippy::cast_possible_truncation)]
                {
                    t[index] = sum as u64;
                }
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            #[allow(clippy::cast_possible_truncation)]
            {
                t[4] = sum as u64;
                t[5] = (sum >> 64) as u64;
            }
            let factor = t[0].wrapping_mul(self.inv);
            let sum = u128::from(t[0]) + u128::from(factor) * u128::from(m[0]);
            let mut carry = sum >> 64;
            for index in 1..4 {
                let sum = u128::from(t[index]) + u128::from(factor) * u128::from(m[index]) + carry;
                #[allow(clippy::cast_possible_truncation)]
                {
                    t[index - 1] = sum as u64;
                }
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            #[allow(clippy::cast_possible_truncation)]
            {
                t[3] = sum as u64;
                t[4] = t[5] + (sum >> 64) as u64;
            }
            t[5] = 0;
        }
        let value = [t[0], t[1], t[2], t[3]];
        let (reduced, borrow) = sub_words(&value, m);
        // The result is below 2m: subtract m unless value < m (and no
        // overflow word).
        let keep = (t[4] ^ 1) & borrow;
        select_words(keep.wrapping_neg(), &value, &reduced)
    }

    /// Converts a canonical value into Montgomery form.
    #[must_use]
    pub fn montgomery_form(&self, a: &[u64; 4]) -> [u64; 4] {
        self.mont_mul(a, &self.r2)
    }

    /// Converts a Montgomery value to its canonical form.
    #[must_use]
    pub fn standard_form(&self, a: &[u64; 4]) -> [u64; 4] {
        self.mont_mul(a, &[1, 0, 0, 0])
    }

    /// `a^e` in Montgomery form for a public exponent (fixed length, always
    /// multiplying: constant time in `a`).
    #[must_use]
    pub fn pow(&self, a: &[u64; 4], exponent: &[u64; 4]) -> [u64; 4] {
        let mut acc = self.montgomery_form(&[1, 0, 0, 0]);
        for bit in (0..256).rev() {
            acc = self.mont_mul(&acc, &acc);
            let product = self.mont_mul(&acc, a);
            let set = (exponent[bit / 64] >> (bit % 64)) & 1;
            acc = select_words(set.wrapping_neg(), &product, &acc);
        }
        acc
    }

    /// The Fermat inverse `a^(m-2)` in Montgomery form (0 for 0); `m` must
    /// be prime.
    #[must_use]
    pub fn invert(&self, a: &[u64; 4]) -> [u64; 4] {
        let (exponent, _) = sub_words(&self.m, &[2, 0, 0, 0]);
        self.pow(a, &exponent)
    }

    /// `a b mod m` for canonical operands (canonical result).
    #[must_use]
    pub fn mul(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        self.mont_mul(&self.montgomery_form(a), b)
    }

    /// `a^-1 mod m` for a canonical operand (0 for 0).
    #[must_use]
    pub fn inverse(&self, a: &[u64; 4]) -> [u64; 4] {
        self.standard_form(&self.invert(&self.montgomery_form(a)))
    }

    /// `a mod m` for any 256-bit `a` when `m > 2^255` (one conditional
    /// subtraction suffices).
    #[must_use]
    pub fn reduce_once(&self, a: &[u64; 4]) -> [u64; 4] {
        let (reduced, borrow) = sub_words(a, &self.m);
        select_words(borrow.wrapping_neg(), a, &reduced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ff::{ForeignModulus, Nat};

    /// A deterministic stream of 256-bit words (splitmix64).
    fn words(seed: &mut u64) -> [u64; 4] {
        core::array::from_fn(|_| {
            *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        })
    }

    #[test]
    fn montgomery_arithmetic_matches_nat_for_every_modulus() {
        let mut seed = 7;
        for modulus in [
            ForeignModulus::PASTA_FP,
            ForeignModulus::PASTA_FQ,
            ForeignModulus::P256_BASE,
            ForeignModulus::P256_ORDER,
        ] {
            let mont = MontModulus::new(modulus.words());
            assert_eq!(mont.modulus(), modulus.words());
            let exponent = modulus.nat().wrapping_sub(&Nat::from_u64(2));
            for _ in 0..16 {
                let a = modulus.reduce(&Nat::from_words(words(&mut seed)));
                let b = modulus.reduce(&Nat::from_words(words(&mut seed)));
                let (aw, bw) = (a.low_words(), b.low_words());
                assert_eq!(mont.mul(&aw, &bw), modulus.mul(&a, &b).low_words());
                assert_eq!(mont.add(&aw, &bw), modulus.add(&a, &b).low_words());
                assert_eq!(mont.sub(&aw, &bw), modulus.sub(&a, &b).low_words());
                assert_eq!(mont.neg(&aw), modulus.sub(&Nat::ZERO, &a).low_words());
                assert_eq!(mont.standard_form(&mont.montgomery_form(&aw)), aw);
                let fermat = a
                    .pow_mod(&exponent, &modulus.nat())
                    .map(|value| value.low_words());
                assert_eq!(Some(mont.inverse(&aw)), fermat);
            }
            assert_eq!(mont.inverse(&[0; 4]), [0; 4]);
            assert_eq!(mont.inverse(&[1, 0, 0, 0]), [1, 0, 0, 0]);
            // Edge operands: m - 1 squared is 1.
            let minus_one = mont.neg(&[1, 0, 0, 0]);
            assert_eq!(mont.mul(&minus_one, &minus_one), [1, 0, 0, 0]);
            assert_eq!(mont.add(&minus_one, &[1, 0, 0, 0]), [0; 4]);
        }
    }

    #[test]
    fn reduce_once_subtracts_at_most_one_modulus() {
        let mont = MontModulus::new(ForeignModulus::P256_ORDER.words());
        let n = mont.modulus();
        assert_eq!(mont.reduce_once(&n), [0; 4]);
        assert_eq!(mont.reduce_once(&[5, 0, 0, 0]), [5, 0, 0, 0]);
        let top = [u64::MAX; 4];
        let expected = Nat::from_words(top)
            .wrapping_sub(&Nat::from_words(n))
            .low_words();
        assert_eq!(mont.reduce_once(&top), expected);
    }
}
