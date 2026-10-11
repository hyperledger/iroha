//! Binary extension fields of FAEST v3.0, their embeddings, and binary polynomial
//! multiplication and reduction.
//!
//! # Fields
//!
//! | type | field | reduction polynomial (specification section 3.2) |
//! |---|---|---|
//! | [`Gf8`] | `GF(2^8)` | `x^8 + x^4 + x^3 + x + 1` (the AES polynomial) |
//! | [`Gf128`] | `GF(2^128)` | `x^128 + x^7 + x^2 + x + 1` |
//! | [`Gf192`] | `GF(2^192)` | `x^192 + x^7 + x^2 + x + 1` |
//! | [`Gf256`] | `GF(2^256)` | `x^256 + x^10 + x^5 + x^2 + 1` |
//! | [`Gf384`] | `GF(2^384)` | `x^384 + x^12 + x^3 + x^2 + 1` |
//! | [`Gf576`] | `GF(2^576)` | `x^576 + x^13 + x^4 + x^3 + 1` |
//! | [`Gf768`] | `GF(2^768)` | `x^768 + x^19 + x^17 + x^4 + 1` |
//!
//! # Encoding
//!
//! An element of `GF(2^k)` is `k / 8` bytes in little-endian order: bit `i mod 8`
//! (value `1 << (i mod 8)`) of byte `i / 8` is the coefficient of `x^i`.
//!
//! # Constant time
//!
//! This is the portable implementation; no hardware carry-less multiplier is used.
//! No operation branches on, or indexes memory by, element values. Carry-less
//! multiplication of 64-bit words uses integer multiplication of operands with
//! three-bit holes, so it is constant time wherever the target's 64-bit integer
//! multiplier is, which holds on the 64-bit targets this workspace builds for.
// TODO: add carry-less-multiply instruction paths behind the `accel` feature.

use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign},
};

use thiserror::Error;
use zeroize::Zeroize;

use crate::params::SecurityLevel;

pub mod poly;

/// Errors of field-element decoding and of the binary polynomial helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FieldError {
    /// A byte string does not have the exact length the operation requires.
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Required length in bytes.
        expected: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
    /// A slice of elements does not have the exact length the operation requires.
    #[error("expected {expected} elements, got {actual}")]
    InvalidCount {
        /// Required number of elements.
        expected: usize,
        /// Supplied number of elements.
        actual: usize,
    },
    /// A polynomial was declared with zero coefficients.
    #[error("a polynomial must have at least one coefficient")]
    EmptyPolynomial,
    /// A modulus does not have its declared leading coefficient, or has degree zero.
    #[error("the modulus must have degree at least one with its leading coefficient set")]
    InvalidModulus,
    /// A polynomial degree is outside the supported range.
    #[error("degree {degree} is outside the supported range [1, {max}]")]
    UnsupportedDegree {
        /// Requested degree.
        degree: u32,
        /// Largest supported degree.
        max: u32,
    },
    /// Fewer irreducible polynomials of the requested degree exist than requested.
    #[error("only {available} irreducible polynomials of that degree exist, {requested} requested")]
    NotEnoughIrreducibles {
        /// Number requested.
        requested: usize,
        /// Number that exist.
        available: usize,
    },
}

/// All-ones if the low bit of `bit` is set, zero otherwise.
const fn mask64(bit: u8) -> u64 {
    0u64.wrapping_sub((bit & 1) as u64)
}

/// Low 64 bits of the carry-less product of `x` and `y`.
///
/// Each operand is split into four words holding every fourth bit. In an integer
/// product of two such words at most 16 partial products meet in one four-bit slot;
/// only the slot at bit 60 can reach 16, and its carry leaves the low 64 bits, so
/// the low bit of every slot is the carry-less product bit.
const fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Carry-less product of two 64-bit words as `(low, high)` words.
const fn clmul64(x: u64, y: u64) -> (u64, u64) {
    let low = bmul64(x, y);
    // Reversing both operands reverses the 127-bit product, whose low word then
    // holds product bits 126..=63.
    let high = bmul64(x.reverse_bits(), y.reverse_bits()).reverse_bits() >> 1;
    (low, high)
}

/// Spread the low 32 bits of `x` to the even bit positions of a word.
const fn spread32(x: u64) -> u64 {
    let mut x = x & 0x0000_0000_ffff_ffff;
    x = (x | (x << 16)) & 0x0000_ffff_0000_ffff;
    x = (x | (x << 8)) & 0x00ff_00ff_00ff_00ff;
    x = (x | (x << 4)) & 0x0f0f_0f0f_0f0f_0f0f;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}

/// `out ^= a * b` over `GF(2)[x]`; `out` holds at least `a.len() + b.len()` words.
fn mul_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            let (low, high) = clmul64(x, y);
            out[i + j] ^= low;
            out[i + j + 1] ^= high;
        }
    }
}

/// `out = a^2` over `GF(2)[x]`; `out` holds exactly `2 * a.len()` words.
fn square_limbs(a: &[u64], out: &mut [u64]) {
    for (i, &x) in a.iter().enumerate() {
        out[2 * i] = spread32(x);
        out[2 * i + 1] = spread32(x >> 32);
    }
}

/// Reduce `buf` modulo `x^(64 n) + sum_t x^t` over the low taps `t < 64`, leaving
/// the result in `buf[..n]` and zero above.
fn reduce_limbs(buf: &mut [u64], n: usize, taps: &[u32]) {
    let mut i = buf.len();
    while i > n {
        i -= 1;
        let word = buf[i];
        buf[i] = 0;
        for &tap in taps {
            buf[i - n] ^= word << tap;
            if tap != 0 {
                buf[i - n + 1] ^= word >> (64 - tap);
            }
        }
    }
}

/// A binary extension field `GF(2^k)` with the encoding of the module documentation.
pub trait BinaryField:
    Copy
    + Default
    + Eq
    + fmt::Debug
    + Zeroize
    + Add<Output = Self>
    + AddAssign
    + Mul<Output = Self>
    + MulAssign
{
    /// Extension degree `k`.
    const BITS: usize;
    /// Encoded length `k / 8`.
    const BYTES: usize;
    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;
    /// The little-endian encoding, `[u8; Self::BYTES]`.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Copy + Zeroize;

    /// Decode an element (`ToField` for one element).
    ///
    /// # Errors
    /// Returns [`FieldError::InvalidLength`] unless `bytes` is exactly
    /// [`Self::BYTES`] long.
    fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError>;

    /// Encode the element (`ToBits`).
    fn to_bytes(self) -> Self::Bytes;

    /// Encode the element into `out`.
    ///
    /// # Errors
    /// Returns [`FieldError::InvalidLength`] unless `out` is exactly
    /// [`Self::BYTES`] long.
    fn write_bytes(self, out: &mut [u8]) -> Result<(), FieldError> {
        if out.len() != Self::BYTES {
            return Err(FieldError::InvalidLength {
                expected: Self::BYTES,
                actual: out.len(),
            });
        }
        out.copy_from_slice(self.to_bytes().as_ref());
        Ok(())
    }

    /// Decode a vector of elements (`ToField` for `n` elements).
    ///
    /// # Errors
    /// Returns [`FieldError::InvalidLength`] unless the length of `bytes` is a
    /// multiple of [`Self::BYTES`]; `expected` is then the next multiple.
    fn vec_from_bytes(bytes: &[u8]) -> Result<Vec<Self>, FieldError> {
        if !bytes.len().is_multiple_of(Self::BYTES) {
            return Err(FieldError::InvalidLength {
                expected: bytes.len().next_multiple_of(Self::BYTES),
                actual: bytes.len(),
            });
        }
        bytes
            .chunks_exact(Self::BYTES)
            .map(Self::from_bytes)
            .collect()
    }

    /// The element 0 or 1 selected by the low bit of `bit`.
    fn from_bit(bit: u8) -> Self {
        Self::ONE.mul_bit(bit)
    }

    /// `self` if the low bit of `bit` is set, zero otherwise, without branching.
    #[must_use]
    fn mul_bit(self, bit: u8) -> Self;

    /// `self * x`, where `x` is the field generator.
    #[must_use]
    fn mul_x(self) -> Self;

    /// `self * self`.
    #[must_use]
    fn square(self) -> Self;

    /// The multiplicative inverse of a non-zero element; zero maps to zero.
    ///
    /// Computed as `self^(2^k - 2)` with a fixed sequence of operations.
    #[must_use]
    fn invert_or_zero(self) -> Self {
        // 2^k - 2 = 2 + 4 + ... + 2^(k-1).
        let mut power = self;
        let mut inverse = Self::ONE;
        for _ in 1..Self::BITS {
            power = power.square();
            inverse *= power;
        }
        inverse
    }

    /// Equality that inspects every coefficient regardless of where the operands
    /// differ. [`PartialEq`] of every field type is this comparison.
    fn ct_eq(&self, other: &Self) -> bool;

    /// Whether the element is zero, inspecting every coefficient.
    fn is_zero(&self) -> bool {
        self.ct_eq(&Self::ZERO)
    }
}

/// One of the three `lambda`-bit fields, with the embeddings the protocol uses.
pub trait LambdaField: BinaryField {
    /// The security level whose `lambda` is [`BinaryField::BITS`].
    const LEVEL: SecurityLevel;
    /// The generator `alpha_8` of the subfield `GF(2^8)` (specification Appendix
    /// A.1) and its powers `alpha_8^0 ..= alpha_8^7`.
    const BYTE_COMBINE_BASIS: [Self; 8];
    /// The field `GF(2^{3 lambda})` of the FAEST leaf hash.
    type Tripled: BinaryField;

    /// The element whose low 64 coefficients are the bits of `value`
    /// (`ToField(value || 0^{lambda - 64})`).
    fn from_u64(value: u64) -> Self;

    /// `self * Self::from_u64(value)`.
    #[must_use]
    fn mul_u64(self, value: u64) -> Self;

    /// `ByteCombine` of the bits of `byte`: the image of the `GF(2^8)` element
    /// `byte` under the field embedding that sends its generator to `alpha_8`.
    fn byte_combine_bits(byte: u8) -> Self {
        let mut acc = Self::ZERO;
        for (i, power) in Self::BYTE_COMBINE_BASIS.iter().enumerate() {
            acc += power.mul_bit(byte >> i);
        }
        acc
    }

    /// `ByteCombine` of eight field elements: `sum_i x[i] * alpha_8^i`.
    fn byte_combine(x: &[Self; 8]) -> Self {
        let mut acc = x[0];
        for (element, power) in x.iter().zip(Self::BYTE_COMBINE_BASIS).skip(1) {
            acc += *element * power;
        }
        acc
    }

    /// `self * ByteCombine(byte)`: multiplication by an embedded `GF(2^8)` element.
    #[must_use]
    fn mul_gf8(self, byte: Gf8) -> Self {
        self * Self::byte_combine_bits(byte.to_u8())
    }

    /// `sum_i x[i] * x^i` over the `lambda` elements of `x`.
    ///
    /// # Errors
    /// Returns [`FieldError::InvalidCount`] unless `x` has exactly `lambda` elements.
    fn sum_poly(x: &[Self]) -> Result<Self, FieldError> {
        if x.len() != Self::BITS {
            return Err(FieldError::InvalidCount {
                expected: Self::BITS,
                actual: x.len(),
            });
        }
        let mut acc = Self::ZERO;
        for element in x.iter().rev() {
            acc = acc.mul_x() + *element;
        }
        Ok(acc)
    }

    /// The element of `GF(2^{3 lambda})` with the same low `lambda` coefficients and
    /// zero above (`ToField(self || 0^{2 lambda}, 3 lambda)`).
    fn widen(self) -> Self::Tripled;

    /// `self.widen() * rhs` in `GF(2^{3 lambda})`.
    fn mul_tripled(self, rhs: Self::Tripled) -> Self::Tripled;
}

macro_rules! binary_field {
    (
        $(#[$doc:meta])*
        $name:ident, limbs = $limbs:literal, taps = [$($tap:literal),+]
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Default)]
        pub struct $name([u64; $limbs]);

        impl $name {
            const TAPS: &'static [u32] = &[$($tap),+];
            /// The reduction polynomial without its leading term.
            const LOW: u64 = 0 $(| (1u64 << $tap))+;

            fn reduced(buf: &mut [u64]) -> Self {
                reduce_limbs(buf, $limbs, Self::TAPS);
                let mut limbs = [0u64; $limbs];
                limbs.copy_from_slice(&buf[..$limbs]);
                buf.zeroize();
                Self(limbs)
            }
        }

        impl BinaryField for $name {
            const BITS: usize = $limbs * 64;
            const BYTES: usize = $limbs * 8;
            const ZERO: Self = Self([0; $limbs]);
            const ONE: Self = {
                let mut limbs = [0u64; $limbs];
                limbs[0] = 1;
                Self(limbs)
            };
            type Bytes = [u8; $limbs * 8];

            fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError> {
                if bytes.len() != Self::BYTES {
                    return Err(FieldError::InvalidLength {
                        expected: Self::BYTES,
                        actual: bytes.len(),
                    });
                }
                let mut limbs = [0u64; $limbs];
                for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
                    let mut word = [0u8; 8];
                    word.copy_from_slice(chunk);
                    *limb = u64::from_le_bytes(word);
                    word.zeroize();
                }
                Ok(Self(limbs))
            }

            fn to_bytes(self) -> Self::Bytes {
                let mut bytes = [0u8; $limbs * 8];
                for (chunk, limb) in bytes.chunks_exact_mut(8).zip(self.0) {
                    chunk.copy_from_slice(&limb.to_le_bytes());
                }
                bytes
            }

            fn mul_bit(self, bit: u8) -> Self {
                let mask = mask64(bit);
                Self(self.0.map(|limb| limb & mask))
            }

            fn mul_x(self) -> Self {
                let top = self.0[$limbs - 1] >> 63;
                let mut limbs = [0u64; $limbs];
                let mut carry = 0;
                for (out, limb) in limbs.iter_mut().zip(self.0) {
                    *out = (limb << 1) | carry;
                    carry = limb >> 63;
                }
                limbs[0] ^= Self::LOW & 0u64.wrapping_sub(top);
                Self(limbs)
            }

            fn square(self) -> Self {
                let mut buf = [0u64; 2 * $limbs];
                square_limbs(&self.0, &mut buf);
                Self::reduced(&mut buf)
            }

            fn ct_eq(&self, other: &Self) -> bool {
                let mut diff = 0u64;
                for (a, b) in self.0.iter().zip(other.0) {
                    diff |= a ^ b;
                }
                diff == 0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other)
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                for byte in self.to_bytes() {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl Add for $name {
            type Output = Self;

            #[allow(clippy::suspicious_arithmetic_impl)]
            fn add(mut self, rhs: Self) -> Self {
                self += rhs;
                self
            }
        }

        impl AddAssign for $name {
            #[allow(clippy::suspicious_op_assign_impl)]
            fn add_assign(&mut self, rhs: Self) {
                for (limb, other) in self.0.iter_mut().zip(rhs.0) {
                    *limb ^= other;
                }
            }
        }

        impl Mul for $name {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                let mut buf = [0u64; 2 * $limbs];
                mul_limbs(&self.0, &rhs.0, &mut buf);
                Self::reduced(&mut buf)
            }
        }

        impl MulAssign for $name {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }
    };
}

binary_field!(
    /// `GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)`.
    Gf128, limbs = 2, taps = [7, 2, 1, 0]
);
binary_field!(
    /// `GF(2^192) = GF(2)[x] / (x^192 + x^7 + x^2 + x + 1)`.
    Gf192, limbs = 3, taps = [7, 2, 1, 0]
);
binary_field!(
    /// `GF(2^256) = GF(2)[x] / (x^256 + x^10 + x^5 + x^2 + 1)`.
    Gf256, limbs = 4, taps = [10, 5, 2, 0]
);
binary_field!(
    /// `GF(2^384) = GF(2)[x] / (x^384 + x^12 + x^3 + x^2 + 1)`.
    Gf384, limbs = 6, taps = [12, 3, 2, 0]
);
binary_field!(
    /// `GF(2^576) = GF(2)[x] / (x^576 + x^13 + x^4 + x^3 + 1)`.
    Gf576, limbs = 9, taps = [13, 4, 3, 0]
);
binary_field!(
    /// `GF(2^768) = GF(2)[x] / (x^768 + x^19 + x^17 + x^4 + 1)`.
    Gf768, limbs = 12, taps = [19, 17, 4, 0]
);

macro_rules! lambda_field {
    ($name:ident, $tripled:ident, $level:expr, limbs = $limbs:literal, basis = $basis:expr) => {
        impl LambdaField for $name {
            const LEVEL: SecurityLevel = $level;
            const BYTE_COMBINE_BASIS: [Self; 8] = $basis;
            type Tripled = $tripled;

            fn from_u64(value: u64) -> Self {
                let mut limbs = [0u64; $limbs];
                limbs[0] = value;
                Self(limbs)
            }

            fn mul_u64(self, value: u64) -> Self {
                let mut buf = [0u64; $limbs + 1];
                mul_limbs(&self.0, &[value], &mut buf);
                Self::reduced(&mut buf)
            }

            fn widen(self) -> $tripled {
                let mut limbs = [0u64; 3 * $limbs];
                limbs[..$limbs].copy_from_slice(&self.0);
                $tripled(limbs)
            }

            fn mul_tripled(self, rhs: $tripled) -> $tripled {
                let mut buf = [0u64; 4 * $limbs];
                mul_limbs(&self.0, &rhs.0, &mut buf);
                $tripled::reduced(&mut buf)
            }
        }
    };
}

lambda_field!(
    Gf128,
    Gf384,
    SecurityLevel::L128,
    limbs = 2,
    basis = [
        Self([0x0000_0000_0000_0001, 0x0000_0000_0000_0000]),
        Self([0xa13f_e8ac_5560_ce0d, 0x053d_8555_a997_9a1c]),
        Self([0xec77_59ca_3488_aee1, 0x4cf4_b743_9cbf_bb84]),
        Self([0xbfcf_02ae_3639_46a8, 0x35ad_604f_7d51_d2c6]),
        Self([0x6b83_3048_3c2e_9849, 0x0dcb_3646_40a2_22fe]),
        Self([0x252b_4927_7b1b_82b4, 0x5498_10e1_1a88_dea5]),
        Self([0xc72b_f2ef_2521_ff22, 0xd681_a568_6c0c_1f75]),
        Self([0x7a7a_8e94_e136_f9bc, 0x0950_311a_4fb7_8fe0]),
    ]
);
lambda_field!(
    Gf192,
    Gf576,
    SecurityLevel::L192,
    limbs = 3,
    basis = [
        Self([
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000
        ]),
        Self([
            0xccc8_a3d5_6f38_9763,
            0xe665_d76c_966e_bdea,
            0x310b_c814_0e6b_3662
        ]),
        Self([
            0xb233_619e_7cf4_50bb,
            0x7bf6_1f19_d563_3f26,
            0xda93_3726_d491_db34
        ]),
        Self([
            0x9c6d_2c13_f539_8a0d,
            0x8232_e377_0632_8d19,
            0x0c3b_0d70_3c75_4ef6
        ]),
        Self([
            0xdd20_747c_bd2b_f75d,
            0x7a55_42ab_0058_d22e,
            0x45ec_519c_94bc_1251
        ]),
        Self([
            0xd8d5_0ce2_8ace_2bf8,
            0x0816_8cb7_67de_be84,
            0xd67d_146a_4ba6_7045
        ]),
        Self([
            0x970f_9c76_eed5_e1ba,
            0xf3ea_f7ae_5fd7_2048,
            0x29a6_bd5f_696c_ea43
        ]),
        Self([
            0xf594_5dc2_6506_8571,
            0x6019_fd62_3906_e9d3,
            0xc77c_5654_0f87_c4b0
        ]),
    ]
);
lambda_field!(
    Gf256,
    Gf768,
    SecurityLevel::L256,
    limbs = 4,
    basis = [
        Self([
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000
        ]),
        Self([
            0x9697_8842_0bde_fee7,
            0xbed6_8d38_a047_4e67,
            0xdf22_9845_f8f1_e16a,
            0x04c9_a8cf_20c9_5833
        ]),
        Self([
            0xa95a_f52a_d522_89c1,
            0x2ba5_c48d_2c42_072f,
            0xd14a_0d37_6c00_b0ea,
            0x064e_4d69_9c5b_4af1
        ]),
        Self([
            0x55da_b383_3f80_9d1d,
            0x1771_831e_533b_0f57,
            0xfb96_573f_ad3f_ac10,
            0x6195_e3db_7011_f68d
        ]),
        Self([
            0xde01_0519_b01b_cdd5,
            0x7527_5891_1a30_e3f6,
            0x2a07_78b6_489e_a03f,
            0x56c2_4fd6_4f76_8838
        ]),
        Self([
            0x98c2_f529_e98a_30b6,
            0x1bc4_dbd4_40f1_8482,
            0x2fbe_0994_7d49_a981,
            0x2227_0b6d_7157_4ffc
        ]),
        Self([
            0x9e75_afb9_de44_670b,
            0xaced_66c6_66f1_afbc,
            0xf001_253f_f299_1f7e,
            0xc03d_372f_d1fa_29f3
        ]),
        Self([
            0xba43_b698_b332_e88b,
            0x5237_c4d6_25b8_6f0d,
            0x2f65_2b2a_f4e8_1545,
            0x133e_ea09_d26b_7bb8
        ]),
    ]
);

/// `GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1)`, the AES byte field. Bit `i` of
/// the byte is the coefficient of `x^i`.
#[derive(Clone, Copy, Default)]
pub struct Gf8(u8);

impl Gf8 {
    /// The reduction polynomial without its leading term.
    const LOW: u8 = 0x1b;

    /// The element encoded by `byte`.
    pub const fn new(byte: u8) -> Self {
        Self(byte)
    }

    /// The encoding of the element.
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

impl BinaryField for Gf8 {
    const BITS: usize = 8;
    const BYTES: usize = 1;
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
    type Bytes = [u8; 1];

    fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError> {
        match bytes {
            [byte] => Ok(Self(*byte)),
            _ => Err(FieldError::InvalidLength {
                expected: 1,
                actual: bytes.len(),
            }),
        }
    }

    fn to_bytes(self) -> [u8; 1] {
        [self.0]
    }

    fn mul_bit(self, bit: u8) -> Self {
        Self(self.0 & 0u8.wrapping_sub(bit & 1))
    }

    fn mul_x(self) -> Self {
        Self((self.0 << 1) ^ (Self::LOW & 0u8.wrapping_sub(self.0 >> 7)))
    }

    fn square(self) -> Self {
        self * self
    }

    fn ct_eq(&self, other: &Self) -> bool {
        (self.0 ^ other.0) == 0
    }
}

impl PartialEq for Gf8 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Gf8 {}

impl fmt::Debug for Gf8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gf8({:02x})", self.0)
    }
}

impl Zeroize for Gf8 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Add for Gf8 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for Gf8 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Mul for Gf8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        // Horner over the bits of `rhs`, most significant first.
        let mut acc = Self::ZERO;
        for i in (0..8).rev() {
            acc = acc.mul_x() + self.mul_bit(rhs.0 >> i);
        }
        acc
    }
}

impl MulAssign for Gf8 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 64-bit generator (`SplitMix64`) for test inputs.
    struct SplitMix(u64);

    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn element<F: BinaryField>(&mut self) -> F {
            let bytes: Vec<u8> = (0..F::BYTES)
                .map(|_| self.next().to_le_bytes()[0])
                .collect();
            F::from_bytes(&bytes).expect("exact length")
        }
    }

    /// Bit-serial carry-less product, the reference for `clmul64`.
    fn clmul_reference(x: u64, y: u64) -> (u64, u64) {
        let mut acc = 0u128;
        for i in 0..64 {
            if (y >> i) & 1 == 1 {
                acc ^= u128::from(x) << i;
            }
        }
        let bytes = acc.to_le_bytes();
        let mut low = [0u8; 8];
        let mut high = [0u8; 8];
        low.copy_from_slice(&bytes[..8]);
        high.copy_from_slice(&bytes[8..]);
        (u64::from_le_bytes(low), u64::from_le_bytes(high))
    }

    /// Shift-and-add multiplication through `mul_x`, the reference for `Mul`.
    fn mul_reference<F: BinaryField>(a: F, b: F) -> F {
        let mut acc = F::ZERO;
        for byte in b.to_bytes().as_ref().iter().rev() {
            for i in (0..8).rev() {
                acc = acc.mul_x() + a.mul_bit(byte >> i);
            }
        }
        acc
    }

    #[test]
    fn mask64_selects_on_the_low_bit() {
        assert_eq!(mask64(0), 0);
        assert_eq!(mask64(1), u64::MAX);
        assert_eq!(mask64(2), 0);
        assert_eq!(mask64(3), u64::MAX);
    }

    #[test]
    fn bmul64_and_clmul64_match_the_bit_serial_product() {
        let mut rng = SplitMix(1);
        let edge = [
            0,
            1,
            2,
            u64::MAX,
            1 << 63,
            0x8888_8888_8888_8888,
            0x1111_1111_1111_1111,
            0xffff_ffff_0000_0000,
        ];
        let mut pairs: Vec<(u64, u64)> = Vec::new();
        for x in edge {
            for y in edge {
                pairs.push((x, y));
            }
        }
        for _ in 0..2000 {
            pairs.push((rng.next(), rng.next()));
        }
        for (x, y) in pairs {
            let expected = clmul_reference(x, y);
            assert_eq!(bmul64(x, y), expected.0, "{x:#x} {y:#x}");
            assert_eq!(clmul64(x, y), expected, "{x:#x} {y:#x}");
        }
    }

    #[test]
    fn spread32_interleaves_zero_bits() {
        assert_eq!(spread32(0), 0);
        assert_eq!(spread32(0xffff_ffff), 0x5555_5555_5555_5555);
        assert_eq!(spread32(0xffff_ffff_0000_0000), 0);
        assert_eq!(spread32(0b1011), 0b0100_0101);
        for i in 0..32 {
            assert_eq!(spread32(1 << i), 1 << (2 * i));
        }
    }

    #[test]
    fn limb_helpers_multiply_square_and_reduce() {
        let mut rng = SplitMix(2);
        let a = [rng.next(), rng.next(), rng.next()];
        let b = [rng.next(), rng.next()];
        let mut ab = [0u64; 5];
        mul_limbs(&a, &b, &mut ab);
        let mut ba = [0u64; 5];
        mul_limbs(&b, &a, &mut ba);
        assert_eq!(ab, ba);
        let mut aa = [0u64; 6];
        mul_limbs(&a, &a, &mut aa);
        let mut squared = [0u64; 6];
        square_limbs(&a, &mut squared);
        assert_eq!(aa, squared);

        // x^128 = x^7 + x^2 + x + 1 and x^191 = x^63 * x^128.
        let mut buf = [0, 0, 1, 0];
        reduce_limbs(&mut buf, 2, &[7, 2, 1, 0]);
        assert_eq!(buf, [0x87, 0, 0, 0]);
        let mut buf = [0, 0, 1 << 63, 0];
        reduce_limbs(&mut buf, 2, &[7, 2, 1, 0]);
        assert_eq!(buf, [0x87 << 63, 0x87 >> 1, 0, 0]);
    }

    fn check_axioms<F: BinaryField>(seed: u64) {
        let mut rng = SplitMix(seed);
        assert_eq!(F::BITS, F::BYTES * 8);
        assert_eq!(F::default(), F::ZERO);
        assert!(F::ZERO.is_zero());
        assert!(!F::ONE.is_zero());
        assert_eq!(F::from_bit(0), F::ZERO);
        assert_eq!(F::from_bit(1), F::ONE);
        assert_eq!(F::ONE.to_bytes().as_ref()[0], 1);
        for _ in 0..24 {
            let a: F = rng.element();
            let b: F = rng.element();
            let c: F = rng.element();
            // Additive group of characteristic 2.
            let (sum, swapped) = (a + b, b + a);
            assert_eq!(sum, swapped);
            assert_eq!((a + b) + c, a + (b + c));
            assert_eq!(a + F::ZERO, a);
            assert_eq!(a + a, F::ZERO);
            let mut sum = a;
            sum += b;
            assert_eq!(sum, a + b);
            // Commutative ring.
            let (product, swapped) = (a * b, b * a);
            assert_eq!(product, swapped);
            assert_eq!((a * b) * c, a * (b * c));
            assert_eq!(a * (b + c), a * b + a * c);
            assert_eq!(a * F::ONE, a);
            assert_eq!(a * F::ZERO, F::ZERO);
            let mut product = a;
            product *= b;
            assert_eq!(product, a * b);
            assert_eq!(a * b, mul_reference(a, b));
            // Squaring, doubling, bits.
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b).square(), a.square() + b.square());
            assert_eq!(a.mul_x(), a * F::ONE.mul_x());
            assert_eq!(a.mul_bit(0), F::ZERO);
            assert_eq!(a.mul_bit(1), a);
            assert_eq!(a.mul_bit(0xfe), F::ZERO);
            // Encoding round trip.
            assert_eq!(F::from_bytes(a.to_bytes().as_ref()), Ok(a));
            let mut out = vec![0u8; F::BYTES];
            a.write_bytes(&mut out).expect("exact length");
            assert_eq!(out, a.to_bytes().as_ref());
            // Equality.
            assert!(a.ct_eq(&a));
            assert_eq!(a.ct_eq(&b), a.to_bytes().as_ref() == b.to_bytes().as_ref());
        }
        for _ in 0..3 {
            let a: F = rng.element();
            if !a.is_zero() {
                assert_eq!(a * a.invert_or_zero(), F::ONE);
                assert_eq!(a.invert_or_zero().invert_or_zero(), a);
            }
        }
        assert_eq!(F::ZERO.invert_or_zero(), F::ZERO);
        assert_eq!(F::ONE.invert_or_zero(), F::ONE);
    }

    #[test]
    fn field_axioms_hold_in_every_field() {
        check_axioms::<Gf8>(10);
        check_axioms::<Gf128>(11);
        check_axioms::<Gf192>(12);
        check_axioms::<Gf256>(13);
        check_axioms::<Gf384>(14);
        check_axioms::<Gf576>(15);
        check_axioms::<Gf768>(16);
    }

    /// `x^k` equals the low part of the reduction polynomial.
    fn check_reduction<F: BinaryField>(low: u64) {
        let mut x_to_k = F::ONE;
        for _ in 0..F::BITS {
            x_to_k = x_to_k.mul_x();
        }
        let mut expected = vec![0u8; F::BYTES];
        expected[..F::BYTES.min(8)].copy_from_slice(&low.to_le_bytes()[..F::BYTES.min(8)]);
        assert_eq!(x_to_k.to_bytes().as_ref(), expected);
        // The same through multiplication: x^(k-1) * x.
        let mut top = vec![0u8; F::BYTES];
        top[F::BYTES - 1] = 0x80;
        let top = F::from_bytes(&top).expect("exact length");
        assert_eq!(top * F::ONE.mul_x(), x_to_k);
        assert_eq!(top.mul_x(), x_to_k);
    }

    #[test]
    fn reduction_polynomials_are_those_of_the_specification() {
        check_reduction::<Gf8>(0x1b);
        check_reduction::<Gf128>(0x87);
        check_reduction::<Gf192>(0x87);
        check_reduction::<Gf256>(0x425);
        check_reduction::<Gf384>(0x100d);
        check_reduction::<Gf576>(0x2019);
        check_reduction::<Gf768>(0xa_0011);
    }

    #[test]
    fn decoding_rejects_wrong_lengths() {
        assert_eq!(
            Gf128::from_bytes(&[0; 15]),
            Err(FieldError::InvalidLength {
                expected: 16,
                actual: 15
            })
        );
        assert_eq!(
            Gf192::from_bytes(&[0; 25]),
            Err(FieldError::InvalidLength {
                expected: 24,
                actual: 25
            })
        );
        assert_eq!(
            Gf768::from_bytes(&[]),
            Err(FieldError::InvalidLength {
                expected: 96,
                actual: 0
            })
        );
        assert_eq!(
            Gf8::from_bytes(&[1, 2]),
            Err(FieldError::InvalidLength {
                expected: 1,
                actual: 2
            })
        );
        assert_eq!(
            Gf256::ONE.write_bytes(&mut [0; 31]),
            Err(FieldError::InvalidLength {
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            Gf128::vec_from_bytes(&[0; 33]),
            Err(FieldError::InvalidLength {
                expected: 48,
                actual: 33
            })
        );
        assert_eq!(Gf128::vec_from_bytes(&[]), Ok(Vec::new()));
        let two = Gf128::vec_from_bytes(&[1; 32]).expect("two elements");
        assert_eq!(two.len(), 2);
        assert_eq!(two[0], two[1]);
    }

    #[test]
    fn encoding_is_little_endian_with_bit_i_the_coefficient_of_x_to_the_i() {
        let mut x = Gf128::ONE;
        for i in 0..128 {
            let bytes = x.to_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                let expected = if index == i / 8 { 1u8 << (i % 8) } else { 0 };
                assert_eq!(*byte, expected, "x^{i}");
            }
            x = x.mul_x();
        }
        assert_eq!(format!("{:?}", Gf8::new(0x1b)), "Gf8(1b)");
        assert_eq!(
            format!("{:?}", Gf128::ONE.mul_x()),
            "Gf128(02000000000000000000000000000000)"
        );
    }

    #[test]
    fn gf8_matches_the_aes_field() {
        // FIPS 197 section 4.2: {57} * {83} = {c1}; {57} * {13} = {fe}.
        assert_eq!(Gf8::new(0x57) * Gf8::new(0x83), Gf8::new(0xc1));
        assert_eq!(Gf8::new(0x57) * Gf8::new(0x13), Gf8::new(0xfe));
        assert_eq!(Gf8::new(0x80).mul_x(), Gf8::new(0x1b));
        // {53}^-1 = {ca}.
        assert_eq!(Gf8::new(0x53).invert_or_zero(), Gf8::new(0xca));
        assert_eq!(Gf8::new(0x53).to_u8(), 0x53);
        for byte in 1..=255u8 {
            let a = Gf8::new(byte);
            assert_eq!(a * a.invert_or_zero(), Gf8::ONE);
        }
    }

    fn check_lambda_field<F: LambdaField>(alpha: &[u8], seed: u64) {
        let mut rng = SplitMix(seed);
        assert_eq!(F::LEVEL.bits(), F::BITS);
        assert_eq!(F::Tripled::BITS, 3 * F::BITS);
        // The basis is the powers of the Appendix A.1 generator.
        let alpha = F::from_bytes(alpha).expect("exact length");
        let mut power = F::ONE;
        for expected in F::BYTE_COMBINE_BASIS {
            assert_eq!(expected, power);
            power *= alpha;
        }
        // alpha is a root of the AES polynomial and has order 255.
        let basis = F::BYTE_COMBINE_BASIS;
        assert_eq!(power + basis[4] + basis[3] + basis[1] + F::ONE, F::ZERO);
        let mut order = F::ONE;
        for _ in 0..255 {
            order *= alpha;
        }
        assert_eq!(order, F::ONE);
        // ByteCombine is a field embedding of GF(2^8).
        assert_eq!(F::byte_combine_bits(0), F::ZERO);
        assert_eq!(F::byte_combine_bits(1), F::ONE);
        assert_eq!(F::byte_combine_bits(2), alpha);
        for _ in 0..16 {
            let a = rng.next().to_le_bytes()[0];
            let b = rng.next().to_le_bytes()[0];
            let (ga, gb) = (Gf8::new(a), Gf8::new(b));
            assert_eq!(
                F::byte_combine_bits((ga + gb).to_u8()),
                F::byte_combine_bits(a) + F::byte_combine_bits(b)
            );
            assert_eq!(
                F::byte_combine_bits((ga * gb).to_u8()),
                F::byte_combine_bits(a) * F::byte_combine_bits(b)
            );
            let x: F = rng.element();
            assert_eq!(x.mul_gf8(ga), x * F::byte_combine_bits(a));
            // ByteCombine of embedded bits agrees with ByteCombine of the byte.
            let mut bits = [F::ZERO; 8];
            for (i, bit) in bits.iter_mut().enumerate() {
                *bit = F::from_bit(a >> i);
            }
            assert_eq!(F::byte_combine(&bits), F::byte_combine_bits(a));
        }
        // 64-bit elements.
        for _ in 0..16 {
            let x: F = rng.element();
            let t = rng.next();
            let embedded = F::from_u64(t);
            assert_eq!(&embedded.to_bytes().as_ref()[..8], &t.to_le_bytes());
            assert!(embedded.to_bytes().as_ref()[8..].iter().all(|b| *b == 0));
            assert_eq!(x.mul_u64(t), x * embedded);
        }
        // Widening and the rectangular product.
        for _ in 0..8 {
            let x: F = rng.element();
            let y: F::Tripled = rng.element();
            let wide = x.widen();
            assert_eq!(&wide.to_bytes().as_ref()[..F::BYTES], x.to_bytes().as_ref());
            assert!(wide.to_bytes().as_ref()[F::BYTES..].iter().all(|b| *b == 0));
            assert_eq!(x.mul_tripled(y), wide * y);
        }
        // sum_poly of embedded bits is the element with those bits.
        let x: F = rng.element();
        let bytes = x.to_bytes();
        let bits: Vec<F> = (0..F::BITS)
            .map(|i| F::from_bit(bytes.as_ref()[i / 8] >> (i % 8)))
            .collect();
        assert_eq!(F::sum_poly(&bits), Ok(x));
        assert_eq!(
            F::sum_poly(&bits[1..]),
            Err(FieldError::InvalidCount {
                expected: F::BITS,
                actual: F::BITS - 1
            })
        );
    }

    #[test]
    fn lambda_field_embeddings_match_appendix_a() {
        check_lambda_field::<Gf128>(
            &[
                0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1, 0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85,
                0x3d, 0x05,
            ],
            21,
        );
        check_lambda_field::<Gf192>(
            &[
                0x63, 0x97, 0x38, 0x6f, 0xd5, 0xa3, 0xc8, 0xcc, 0xea, 0xbd, 0x6e, 0x96, 0x6c, 0xd7,
                0x65, 0xe6, 0x62, 0x36, 0x6b, 0x0e, 0x14, 0xc8, 0x0b, 0x31,
            ],
            22,
        );
        check_lambda_field::<Gf256>(
            &[
                0xe7, 0xfe, 0xde, 0x0b, 0x42, 0x88, 0x97, 0x96, 0x67, 0x4e, 0x47, 0xa0, 0x38, 0x8d,
                0xd6, 0xbe, 0x6a, 0xe1, 0xf1, 0xf8, 0x45, 0x98, 0x22, 0xdf, 0x33, 0x58, 0xc9, 0x20,
                0xcf, 0xa8, 0xc9, 0x04,
            ],
            23,
        );
    }

    #[test]
    fn elements_zeroize() {
        let mut a = Gf256::ONE.mul_x();
        a.zeroize();
        assert_eq!(a, Gf256::ZERO);
        let mut b = Gf8::new(7);
        b.zeroize();
        assert_eq!(b, Gf8::ZERO);
    }
}
