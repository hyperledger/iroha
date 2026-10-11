//! Fixed-width witness arithmetic for the BLS12-381 base field.
//!
//! These routines do not authenticate anything: [`super::field`] constrains
//! their outputs. Arithmetic uses fixed loop bounds, fixed array indices and
//! mask selection; no secret-dependent division or allocation is used.

/// Six little-endian 64-bit limbs. Arithmetic inputs must be below [`MODULUS`].
pub type Fp = [u64; 6];
/// BLS12-381 base-field prime, in little-endian limbs.
pub const MODULUS: Fp = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];
/// Additive identity.
pub const ZERO: Fp = [0; 6];
/// Multiplicative identity.
pub const ONE: Fp = [1, 0, 0, 0, 0, 0];

use crate::cells::low_word;

pub(super) fn subtract_words(a: &Fp, b: &Fp) -> (Fp, [u64; 6]) {
    let mut out = ZERO;
    let mut borrows = [0; 6];
    let mut borrow = 0_u64;
    for i in 0..6 {
        let wide = (1_u128 << 64) + u128::from(a[i]) - u128::from(b[i]) - u128::from(borrow);
        out[i] = low_word(wide);
        borrow = 1 - (wide >> 64) as u64;
        borrows[i] = borrow;
    }
    (out, borrows)
}

/// Whether the integer is a canonical field element.
#[must_use]
pub fn is_canonical(value: &Fp) -> bool {
    subtract_words(value, &MODULUS).1[5] == 1
}

/// Selects `a` for `bit = 1` and `b` for `bit = 0` using a limb mask.
#[must_use]
pub fn select(bit: u64, a: &Fp, b: &Fp) -> Fp {
    let mask = 0_u64.wrapping_sub(bit & 1);
    core::array::from_fn(|i| (a[i] & mask) | (b[i] & !mask))
}

pub(super) fn add_with_quotient(a: &Fp, b: &Fp) -> (Fp, u64) {
    let mut sum = ZERO;
    let mut carry = 0_u128;
    for i in 0..6 {
        let wide = u128::from(a[i]) + u128::from(b[i]) + carry;
        sum[i] = low_word(wide);
        carry = wide >> 64;
    }
    // Canonical inputs have a sum below 2p < 2^382, so no seventh limb.
    let (reduced, borrows) = subtract_words(&sum, &MODULUS);
    let quotient = 1 - borrows[5];
    (select(quotient, &reduced, &sum), quotient)
}

/// Canonical modular sum.
#[must_use]
pub fn add(a: &Fp, b: &Fp) -> Fp {
    add_with_quotient(a, b).0
}

/// Canonical modular difference.
#[must_use]
pub fn sub(a: &Fp, b: &Fp) -> Fp {
    let (difference, borrows) = subtract_words(a, b);
    let mask = 0_u64.wrapping_sub(borrows[5]);
    let mut out = ZERO;
    let mut carry = 0_u128;
    for i in 0..6 {
        let wide = u128::from(difference[i]) + u128::from(MODULUS[i] & mask) + carry;
        out[i] = low_word(wide);
        carry = wide >> 64;
    }
    out
}

/// Canonical additive inverse, including `neg(0) = 0`.
#[must_use]
pub fn neg(a: &Fp) -> Fp {
    sub(&ZERO, a)
}

/// Full 768-bit product; each multiply-accumulate fits exactly in `u128`.
pub(super) fn product(a: &Fp, b: &Fp) -> [u64; 12] {
    let mut out = [0; 12];
    for i in 0..6 {
        let mut carry = 0_u128;
        for j in 0..6 {
            let wide = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = low_word(wide);
            carry = wide >> 64;
        }
        out[i + 6] = low_word(carry);
    }
    out
}

/// Fixed 768-step binary long division. The running remainder is always
/// below p; its shift is below 2p < 2^382 and fits six limbs.
pub(super) fn reduce(wide: &[u64; 12]) -> ([u64; 12], Fp) {
    let mut quotient = [0; 12];
    let mut remainder = ZERO;
    for bit in (0..768).rev() {
        let mut carry = (wide[bit / 64] >> (bit % 64)) & 1;
        for limb in &mut remainder {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        let (difference, borrows) = subtract_words(&remainder, &MODULUS);
        let take = 1 - borrows[5];
        remainder = select(take, &difference, &remainder);
        quotient[bit / 64] |= take << (bit % 64);
    }
    (quotient, remainder)
}

pub(super) fn mul_with_quotient(a: &Fp, b: &Fp) -> (Fp, Fp) {
    let (wide_q, remainder) = reduce(&product(a, b));
    // a,b < p implies floor(ab/p) < p, hence six quotient limbs suffice.
    (remainder, core::array::from_fn(|i| wide_q[i]))
}

/// Canonical modular product.
#[must_use]
pub fn mul(a: &Fp, b: &Fp) -> Fp {
    mul_with_quotient(a, b).0
}

/// Canonical modular square.
#[must_use]
pub fn square(a: &Fp) -> Fp {
    mul(a, a)
}

/// Fermat inverse using a fixed 381-step exponentiation; returns zero for
/// zero. The circuit inversion operation rejects that zero case.
#[must_use]
pub fn invert(a: &Fp) -> Fp {
    let mut exponent = MODULUS;
    exponent[0] -= 2;
    let mut out = ONE;
    for bit in (0..381).rev() {
        let squared = square(&out);
        let multiplied = mul(&squared, a);
        out = select(
            (exponent[bit / 64] >> (bit % 64)) & 1,
            &multiplied,
            &squared,
        );
    }
    out
}

/// Exact signed multiplication carries. Splitting each 128-bit product into
/// halves keeps the fixed-width witness computation below 2^72, even though
/// an unsplit column sum can exceed `u128`.
pub(super) fn multiplication_carries(a: &Fp, b: &Fp, remainder: &Fp, q: &Fp) -> [i128; 13] {
    let mut carries = [0; 13];
    for column in 0..12 {
        let mut low = carries[column];
        let mut high = 0_i128;
        for i in 0..6 {
            if column >= i && column - i < 6 {
                let j = column - i;
                let ab = u128::from(a[i]) * u128::from(b[j]);
                let qp = u128::from(q[i]) * u128::from(MODULUS[j]);
                low += i128::from(low_word(ab)) - i128::from(low_word(qp));
                high += (ab >> 64).cast_signed() - (qp >> 64).cast_signed();
            }
        }
        if column < 6 {
            low -= i128::from(remainder[column]);
        }
        carries[column + 1] = (low >> 64) + high;
    }
    carries
}

pub(super) fn reduction_carries(n: &[u64; 8], r: &Fp, q: &Fp) -> [i128; 13] {
    let mut carries = [0; 13];
    for column in 0..12 {
        let mut low = carries[column];
        let mut high = 0_i128;
        if column < 8 {
            low += i128::from(n[column]);
        }
        if column < 6 {
            low -= i128::from(r[column]);
        }
        for i in 0..6 {
            if column >= i && column - i < 6 {
                let product = u128::from(q[i]) * u128::from(MODULUS[column - i]);
                low -= i128::from(low_word(product));
                high -= (product >> 64).cast_signed();
            }
        }
        carries[column + 1] = (low >> 64) + high;
    }
    carries
}
