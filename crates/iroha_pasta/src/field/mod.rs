//! The Pasta prime fields `Fp` and `Fq`.
//!
//! - `Fp` has modulus `p = 2^254 + 45560315531419706090280762371685220353`;
//!   it is the base field of Pallas and the scalar field of Vesta.
//! - `Fq` has modulus `q = 2^254 + 45560315531506369815346746415080538113`;
//!   it is the base field of Vesta and the scalar field of Pallas.
//!
//! Elements are four little-endian 64-bit limbs in Montgomery form
//! (`a * 2^256 mod m`), always fully reduced. The canonical encoding is the
//! 32-byte little-endian integer, identical to `pasta_curves` 0.5.2; decoding
//! rejects values `>= m`.
//!
//! Timing posture:
//!
//! - addition, subtraction, negation, multiplication, squaring, equality,
//!   selection, encoding and [`ff::Field::invert`] are constant time;
//! - `invert` is Fermat exponentiation by the public exponent `m - 2`;
//! - `*_vartime` functions take time that depends on the value and accept
//!   public data only;
//! - square roots use the table method of `pasta_curves`, see `sqrt`.

pub(crate) mod cios;
pub(crate) mod fp;
pub(crate) mod fq;
mod safegcd;
mod sqrt;

pub use fp::Fp;
pub use fq::Fq;

use ff::{FromUniformBytes, PrimeField, PrimeFieldBits, WithSmallOrderMulGroup};

/// Storage for the canonical 256-bit little-endian field view on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub type PastaReprBits = [u64; 4];

/// Storage for the same canonical 256 bits when `bitvec` does not support `u64`.
#[cfg(not(target_pointer_width = "64"))]
pub type PastaReprBits = [u32; 8];

fn field_bits_repr(limbs: [u64; 4]) -> PastaReprBits {
    #[cfg(target_pointer_width = "64")]
    {
        limbs
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        field_bits_u32(limbs)
    }
}

// Keep the non-64-bit conversion available to host tests as well. Numeric
// low/high words preserve Lsb0 order independently of the machine's byte order.
#[cfg(any(test, not(target_pointer_width = "64")))]
fn field_bits_u32(limbs: [u64; 4]) -> [u32; 8] {
    let mut words = [0; 8];
    for (pair, limb) in words.chunks_exact_mut(2).zip(limbs) {
        let bytes = limb.to_le_bytes();
        pair[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        pair[1] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    }
    words
}

mod sealed {
    /// Seals [`super::PastaField`] to the two Pasta fields.
    pub trait Sealed {}
    impl Sealed for super::Fp {}
    impl Sealed for super::Fq {}
}

/// Operations shared by [`Fp`] and [`Fq`] beyond the `ff` traits.
///
/// The trait is sealed: only the two Pasta fields implement it.
pub trait PastaField:
    sealed::Sealed
    + PrimeField<Repr = [u8; 32]>
    + PrimeFieldBits<ReprBits = PastaReprBits>
    + FromUniformBytes<64>
    + WithSmallOrderMulGroup<3>
    + Ord
    + core::hash::Hash
    + zeroize::Zeroize
{
    /// Returns the canonical integer value as little-endian 64-bit limbs.
    fn to_canonical_limbs(&self) -> [u64; 4];

    /// Decodes canonical little-endian limbs; fails (in constant time) for
    /// values greater than or equal to the modulus.
    fn from_canonical_limbs(limbs: [u64; 4]) -> subtle::CtOption<Self>;

    /// Reduces an arbitrary 256-bit little-endian integer modulo the field
    /// order.
    fn from_raw_reduced(limbs: [u64; 4]) -> Self;

    /// Variable-time inversion for public data; `None` for zero.
    ///
    /// Uses the Bernstein-Yang safegcd algorithm. The result equals
    /// [`ff::Field::invert`] bit for bit, but its running time depends on the
    /// value.
    fn invert_vartime(&self) -> Option<Self>;

    /// Number of significant bits of the canonical value (0 for zero).
    ///
    /// Variable time: the result is a function of the value.
    fn bit_length_vartime(&self) -> u32 {
        let limbs = self.to_canonical_limbs();
        for (i, limb) in limbs.iter().enumerate().rev() {
            if *limb != 0 {
                // i <= 3, so the conversion cannot fail.
                return 64 * u32::try_from(i).unwrap_or(3) + (64 - limb.leading_zeros());
            }
        }
        0
    }
}

/// Inverts every element of `values` in place with one constant-time
/// inversion (Montgomery's trick). Zero elements stay zero.
///
/// Constant time with respect to the values (three multiplications and two
/// selections per element plus one Fermat inversion). Returns the number of
/// elements processed.
pub fn batch_invert<F: PastaField>(values: &mut [F]) -> usize {
    batch_invert_cancellable(values, None).expect("no cancellation signal")
}

/// Inverts a column with the same constant-time field arithmetic and an explicit
/// cancellation signal. A cancelled in-place column must be discarded.
/// # Errors
/// Explicit cancellation after zeroizing the scratch and joining caller tasks.
pub fn batch_invert_cancellable<F: PastaField>(
    values: &mut [F],
    cancellation: Option<&crate::CancellationToken>,
) -> Result<usize, crate::Cancelled> {
    crate::CancellationToken::checkpoint(cancellation)?;
    let mut scratch = zeroize::Zeroizing::new(Vec::with_capacity(values.len()));
    let mut acc = zeroize::Zeroizing::new(F::ONE);
    for (index, v) in values.iter().enumerate() {
        if index % 1024 == 0 {
            crate::CancellationToken::checkpoint(cancellation)?;
        }
        scratch.push(*acc);
        let next = *acc * v;
        *acc = F::conditional_select(&next, &acc, v.is_zero());
    }
    // `acc` is a product of nonzero elements, so it is invertible.
    let mut inv = zeroize::Zeroizing::new(acc.invert().unwrap_or(F::ZERO));
    for (index, (v, prefix)) in values.iter_mut().zip(scratch.iter()).rev().enumerate() {
        if index % 1024 == 0 {
            crate::CancellationToken::checkpoint(cancellation)?;
        }
        let is_zero = v.is_zero();
        let new_v = *inv * prefix;
        let next_inv = *inv * *v;
        *inv = F::conditional_select(&next_inv, &inv, is_zero);
        *v = F::conditional_select(&new_v, v, is_zero);
    }
    crate::CancellationToken::checkpoint(cancellation)?;
    Ok(values.len())
}

/// Inverts every element of `values` in place with one variable-time
/// inversion. Zero elements stay zero. Public data only.
pub fn batch_invert_vartime<F: PastaField>(values: &mut [F]) -> usize {
    let mut scratch = Vec::with_capacity(values.len());
    let mut acc = F::ONE;
    for v in values.iter() {
        scratch.push(acc);
        if !v.is_zero_vartime() {
            acc *= v;
        }
    }
    let mut inv = acc.invert_vartime().unwrap_or(F::ZERO);
    for (v, prefix) in values.iter_mut().zip(scratch.iter()).rev() {
        if v.is_zero_vartime() {
            continue;
        }
        let new_v = inv * prefix;
        inv *= *v;
        *v = new_v;
    }
    values.len()
}

/// Exponentiation by a public 256-bit exponent with a 5-bit sliding window.
///
/// The sequence of operations depends only on `exp`, so the running time is
/// independent of `base`.
pub(crate) fn pow_public_exponent<F: ff::Field>(base: &F, exp: &[u64; 4]) -> F {
    // Odd powers base^1, base^3, ..., base^31.
    let mut table = [*base; 16];
    let sq = base.square();
    for i in 1..16 {
        table[i] = table[i - 1] * sq;
    }
    let bit = |i: usize| -> usize { usize::from((exp[i / 64] >> (i % 64)) & 1 == 1) };
    let mut acc = F::ONE;
    let mut started = false;
    // `next` is one past the highest bit still to process.
    let mut next = 256usize;
    while next > 0 {
        let idx = next - 1;
        if bit(idx) == 0 {
            if started {
                acc = acc.square();
            }
            next -= 1;
            continue;
        }
        // Longest window [j, idx] of at most 5 bits ending in a set bit.
        let mut j = idx.saturating_sub(4);
        while bit(j) == 0 {
            j += 1;
        }
        let mut window = 0usize;
        for k in (j..=idx).rev() {
            window = (window << 1) | bit(k);
            if started {
                acc = acc.square();
            }
        }
        acc = if started {
            acc * table[window >> 1]
        } else {
            table[window >> 1]
        };
        started = true;
        next = j;
    }
    acc
}

/// Implements the shared arithmetic and trait surface of a Pasta field.
///
/// The invoking module must define `MODULUS: cios::Modulus`, `MOD_INFO`,
/// `MODULUS_STR`, `INV_EXP` (`m - 2`), `T_MINUS1_OVER2`, the canonical
/// constants `TWO_INV_RAW`, `ROOT_OF_UNITY_RAW`, `ROOT_OF_UNITY_INV_RAW`,
/// `DELTA_RAW`, `ZETA_RAW`, and `SQRT_HASH` (perfect-hash parameters).
macro_rules! impl_pasta_field {
    ($name:ident) => {
        use core::fmt;
        use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

        use ff::{
            Field, FieldBits, FromUniformBytes, PrimeField, PrimeFieldBits, WithSmallOrderMulGroup,
        };
        use rand_core_06::RngCore;
        use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

        use crate::field::cios;
        use crate::field::sqrt::{SqrtField, SqrtTables};

        #[allow(clippy::should_implement_trait)]
        impl $name {
            /// The additive identity.
            pub const fn zero() -> Self {
                Self([0, 0, 0, 0])
            }

            /// The multiplicative identity.
            pub const fn one() -> Self {
                Self(cios::to_mont(&[1, 0, 0, 0], &MODULUS))
            }

            /// Converts a little-endian 256-bit integer, reducing it modulo the
            /// field order. Usable in constant expressions.
            pub const fn from_raw(val: [u64; 4]) -> Self {
                Self(cios::mont_reduce(cios::mul_wide(&val, &MODULUS.r2), &MODULUS))
            }

            /// Constant-time addition.
            #[inline]
            #[must_use]
            pub const fn add(&self, rhs: &Self) -> Self {
                Self(cios::add(&self.0, &rhs.0, &MODULUS))
            }

            /// Constant-time subtraction.
            #[inline]
            #[must_use]
            pub const fn sub(&self, rhs: &Self) -> Self {
                Self(cios::sub(&self.0, &rhs.0, &MODULUS))
            }

            /// Constant-time negation.
            #[inline]
            #[must_use]
            pub const fn neg(&self) -> Self {
                Self(cios::neg(&self.0, &MODULUS))
            }

            /// Constant-time multiplication.
            #[inline]
            #[must_use]
            pub const fn mul(&self, rhs: &Self) -> Self {
                Self(cios::mont_mul(&self.0, &rhs.0, &MODULUS))
            }

            /// Constant-time squaring.
            #[inline]
            #[must_use]
            pub const fn square(&self) -> Self {
                Self(cios::mont_square(&self.0, &MODULUS))
            }

            /// Constant-time doubling.
            #[inline]
            #[must_use]
            pub const fn double(&self) -> Self {
                self.add(self)
            }

            /// Reduces a little-endian 512-bit integer modulo the field order.
            pub const fn from_u512(limbs: [u64; 8]) -> Self {
                Self(cios::from_u512(&limbs, &MODULUS))
            }

            /// Returns the canonical little-endian limbs.
            #[inline]
            pub const fn to_canonical(self) -> [u64; 4] {
                cios::from_mont(&self.0, &MODULUS)
            }

            /// Variable-time inversion for public data; `None` for zero.
            pub fn invert_vartime(&self) -> Option<Self> {
                if self.is_zero_vartime() {
                    return None;
                }
                // self.0 = a * R; safegcd returns (a R)^-1; multiplying by R^3 in
                // Montgomery form yields a^-1 * R.
                let inv = crate::field::safegcd::invert_var(&self.0, &MOD_INFO);
                Some(Self(cios::mont_mul(&inv, &MODULUS.r3, &MODULUS)))
            }

            fn tables() -> &'static SqrtTables<$name> {
                static TABLES: std::sync::OnceLock<SqrtTables<$name>> = std::sync::OnceLock::new();
                TABLES.get_or_init(|| SqrtTables::new(SQRT_HASH.0, SQRT_HASH.1))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let repr = self.to_repr();
                write!(f, "0x")?;
                for b in repr.iter().rev() {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::zero()
            }
        }

        impl From<bool> for $name {
            fn from(bit: bool) -> Self {
                if bit { Self::one() } else { Self::zero() }
            }
        }

        impl From<u64> for $name {
            fn from(val: u64) -> Self {
                Self(cios::to_mont(&[val, 0, 0, 0], &MODULUS))
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> [u8; 32] {
                value.to_repr()
            }
        }

        impl From<&$name> for [u8; 32] {
            fn from(value: &$name) -> [u8; 32] {
                value.to_repr()
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0[0].ct_eq(&other.0[0])
                    & self.0[1].ct_eq(&other.0[1])
                    & self.0[2].ct_eq(&other.0[2])
                    & self.0[3].ct_eq(&other.0[3])
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl Eq for $name {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                // The Montgomery limbs are unique per value, consistent with Eq.
                self.0.hash(state);
            }
        }

        impl Ord for $name {
            /// Orders by canonical integer value (variable time).
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                let a = self.to_canonical();
                let b = other.to_canonical();
                a.iter().rev().cmp(b.iter().rev())
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self([
                    u64::conditional_select(&a.0[0], &b.0[0], choice),
                    u64::conditional_select(&a.0[1], &b.0[1], choice),
                    u64::conditional_select(&a.0[2], &b.0[2], choice),
                    u64::conditional_select(&a.0[3], &b.0[3], choice),
                ])
            }
        }

        impl zeroize::DefaultIsZeroes for $name {}

        impl Neg for $name {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self {
                $name::neg(&self)
            }
        }

        impl Neg for &$name {
            type Output = $name;
            #[inline]
            fn neg(self) -> $name {
                $name::neg(self)
            }
        }

        crate::field::impl_pasta_field!(@binop $name, Add, add, AddAssign, add_assign);
        crate::field::impl_pasta_field!(@binop $name, Sub, sub, SubAssign, sub_assign);
        crate::field::impl_pasta_field!(@binop $name, Mul, mul, MulAssign, mul_assign);

        impl<T: core::borrow::Borrow<$name>> core::iter::Sum<T> for $name {
            fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
                iter.fold(Self::zero(), |acc, item| acc.add(item.borrow()))
            }
        }

        impl<T: core::borrow::Borrow<$name>> core::iter::Product<T> for $name {
            fn product<I: Iterator<Item = T>>(iter: I) -> Self {
                iter.fold(Self::one(), |acc, item| acc.mul(item.borrow()))
            }
        }

        impl Field for $name {
            const ZERO: Self = Self::zero();
            const ONE: Self = Self::one();

            /// Samples a uniform element by reducing 512 random bits.
            ///
            /// Reads eight `u64` words from `rng`, exactly as `pasta_curves`
            /// does, so a seeded RNG yields identical elements.
            fn random(mut rng: impl RngCore) -> Self {
                let mut limbs = [0u64; 8];
                for limb in &mut limbs {
                    *limb = rng.next_u64();
                }
                Self::from_u512(limbs)
            }

            #[inline]
            fn square(&self) -> Self {
                $name::square(self)
            }

            #[inline]
            fn double(&self) -> Self {
                $name::double(self)
            }

            /// Constant-time Fermat inversion (`self^(m-2)`).
            fn invert(&self) -> CtOption<Self> {
                let inv = crate::field::pow_public_exponent(self, &INV_EXP);
                CtOption::new(inv, !self.is_zero())
            }

            fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
                Self::tables().sqrt_ratio(num, div)
            }

            fn sqrt_alt(&self) -> (Choice, Self) {
                Self::tables().sqrt_alt(self)
            }

            fn sqrt(&self) -> CtOption<Self> {
                let (is_square, res) = Self::tables().sqrt_alt(self);
                CtOption::new(res, is_square)
            }

            fn is_zero_vartime(&self) -> bool {
                self.0 == [0, 0, 0, 0]
            }
        }

        impl PrimeField for $name {
            type Repr = [u8; 32];

            const MODULUS: &'static str = MODULUS_STR;
            const NUM_BITS: u32 = 255;
            const CAPACITY: u32 = 254;
            const TWO_INV: Self = Self::from_raw(TWO_INV_RAW);
            const MULTIPLICATIVE_GENERATOR: Self = Self::from_raw([5, 0, 0, 0]);
            const S: u32 = 32;
            const ROOT_OF_UNITY: Self = Self::from_raw(ROOT_OF_UNITY_RAW);
            const ROOT_OF_UNITY_INV: Self = Self::from_raw(ROOT_OF_UNITY_INV_RAW);
            const DELTA: Self = Self::from_raw(DELTA_RAW);

            fn from_u128(v: u128) -> Self {
                let lo = u64::try_from(v & u128::from(u64::MAX)).unwrap_or(0);
                let hi = u64::try_from(v >> 64).unwrap_or(0);
                Self::from_raw([lo, hi, 0, 0])
            }

            fn from_repr(repr: Self::Repr) -> CtOption<Self> {
                let limbs = crate::field::limbs_from_le_bytes(&repr);
                let is_some = Choice::from(u8::from(cios::lt_modulus(&limbs, &MODULUS)));
                // Converting a non-canonical value is harmless: the result is
                // discarded by the CtOption.
                CtOption::new(Self(cios::to_mont_any(&limbs, &MODULUS)), is_some)
            }

            fn to_repr(&self) -> Self::Repr {
                crate::field::limbs_to_le_bytes(&self.to_canonical())
            }

            fn is_odd(&self) -> Choice {
                Choice::from((self.to_canonical()[0] & 1) as u8)
            }
        }

        impl PrimeFieldBits for $name {
            type ReprBits = crate::field::PastaReprBits;

            fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
                FieldBits::new(crate::field::field_bits_repr(self.to_canonical()))
            }

            fn char_le_bits() -> FieldBits<Self::ReprBits> {
                FieldBits::new(crate::field::field_bits_repr(MODULUS.m))
            }
        }

        impl FromUniformBytes<64> for $name {
            /// Reduces a little-endian 512-bit integer modulo the field order.
            fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
                let mut limbs = [0u64; 8];
                for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
                    let mut word = [0u8; 8];
                    word.copy_from_slice(chunk);
                    *limb = u64::from_le_bytes(word);
                }
                Self::from_u512(limbs)
            }
        }

        impl WithSmallOrderMulGroup<3> for $name {
            const ZETA: Self = Self::from_raw(ZETA_RAW);
        }

        impl SqrtField for $name {
            fn pow_by_t_minus1_over2(&self) -> Self {
                crate::field::pow_public_exponent(self, &T_MINUS1_OVER2)
            }

            fn get_lower_32(&self) -> u32 {
                u32::try_from(self.to_canonical()[0] & u64::from(u32::MAX)).unwrap_or(0)
            }
        }

        impl crate::field::PastaField for $name {
            fn to_canonical_limbs(&self) -> [u64; 4] {
                self.to_canonical()
            }

            fn from_canonical_limbs(limbs: [u64; 4]) -> CtOption<Self> {
                let is_some = Choice::from(u8::from(cios::lt_modulus(&limbs, &MODULUS)));
                CtOption::new(Self(cios::to_mont_any(&limbs, &MODULUS)), is_some)
            }

            fn from_raw_reduced(limbs: [u64; 4]) -> Self {
                Self::from_raw(limbs)
            }

            fn invert_vartime(&self) -> Option<Self> {
                $name::invert_vartime(self)
            }
        }
    };
    (@binop $name:ident, $tr:ident, $method:ident, $tr_assign:ident, $method_assign:ident) => {
        impl $tr<$name> for $name {
            type Output = $name;
            #[inline]
            fn $method(self, rhs: $name) -> $name {
                $name::$method(&self, &rhs)
            }
        }

        impl<'b> $tr<&'b $name> for $name {
            type Output = $name;
            #[inline]
            fn $method(self, rhs: &'b $name) -> $name {
                $name::$method(&self, rhs)
            }
        }

        impl $tr<$name> for &$name {
            type Output = $name;
            #[inline]
            fn $method(self, rhs: $name) -> $name {
                $name::$method(self, &rhs)
            }
        }

        impl<'b> $tr<&'b $name> for &$name {
            type Output = $name;
            #[inline]
            fn $method(self, rhs: &'b $name) -> $name {
                $name::$method(self, rhs)
            }
        }

        impl $tr_assign<$name> for $name {
            #[inline]
            fn $method_assign(&mut self, rhs: $name) {
                *self = $name::$method(self, &rhs);
            }
        }

        impl<'b> $tr_assign<&'b $name> for $name {
            #[inline]
            fn $method_assign(&mut self, rhs: &'b $name) {
                *self = $name::$method(self, rhs);
            }
        }
    };
}

pub(crate) use impl_pasta_field;

/// Reads 32 little-endian bytes as four 64-bit limbs.
pub(crate) fn limbs_from_le_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(word);
    }
    limbs
}

/// Writes four 64-bit limbs as 32 little-endian bytes.
pub(crate) fn limbs_to_le_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter()) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, FieldBits};

    fn check_field_bits<F: PastaField>(modulus: [u64; 4]) {
        let modulus_bytes = limbs_to_le_bytes(&modulus);
        let characteristic = F::char_le_bits();
        let characteristic_u32 = FieldBits::new(field_bits_u32(modulus));
        assert_eq!(characteristic.len(), 256);
        assert_eq!(characteristic_u32.len(), 256);
        for bit in 0..256 {
            let expected = modulus_bytes[bit / 8] & (1 << (bit % 8)) != 0;
            assert_eq!(characteristic[bit], expected, "modulus bit {bit}");
            assert_eq!(characteristic_u32[bit], expected, "u32 modulus bit {bit}");
        }
        assert!(bool::from(F::from_repr(modulus_bytes).is_none()));

        let mut values = vec![F::ZERO, F::ONE, -F::ONE];
        // Every canonical one-hot value, including both sides of all limb
        // boundaries; the noncanonical 2^255 encoding must still be rejected.
        for bit in 0..256 {
            let mut repr = [0; 32];
            repr[bit / 8] = 1 << (bit % 8);
            let decoded = Option::<F>::from(F::from_repr(repr));
            if bit == 255 {
                assert!(decoded.is_none());
            } else {
                let value = decoded.expect("2^0 through 2^254 are canonical");
                assert_eq!(value.to_repr(), repr);
                values.push(value);
            }
        }
        for value in values {
            let repr = value.to_repr();
            let native = value.to_le_bits();
            let words32 = FieldBits::new(field_bits_u32(value.to_canonical_limbs()));
            assert_eq!(native.len(), 256);
            assert_eq!(words32.len(), 256);
            for bit in 0..256 {
                let expected = repr[bit / 8] & (1 << (bit % 8)) != 0;
                assert_eq!(native[bit], expected, "canonical bit {bit}");
                assert_eq!(words32[bit], expected, "u32 canonical bit {bit}");
            }
        }
        let mut minus_one = modulus_bytes;
        // Both Pasta moduli have low byte 1.
        minus_one[0] -= 1;
        assert_eq!((-F::ONE).to_repr(), minus_one);
    }

    #[test]
    fn prime_field_bits_fp_canonical() {
        check_field_bits::<Fp>(fp::MODULUS.m);
    }

    #[test]
    fn prime_field_bits_fq_canonical() {
        check_field_bits::<Fq>(fq::MODULUS.m);
    }

    #[test]
    fn prime_field_bits_u32_all_positions() {
        for selected in 0..256 {
            let mut limbs = [0; 4];
            limbs[selected / 64] = 1 << (selected % 64);
            let bits = FieldBits::new(field_bits_u32(limbs));
            assert_eq!(bits.len(), 256);
            for bit in 0..256 {
                assert_eq!(bits[bit], bit == selected, "selected {selected}, bit {bit}");
            }
        }
    }

    #[test]
    fn limb_byte_round_trip() {
        let limbs = [1u64, 2, 3, 0x0102_0304_0506_0708];
        let bytes = limbs_to_le_bytes(&limbs);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[31], 1);
        assert_eq!(limbs_from_le_bytes(&bytes), limbs);
    }

    #[test]
    fn pow_public_exponent_matches_pow_vartime() {
        let base = Fp::from(7u64);
        for exp in [
            [0u64; 4],
            [1, 0, 0, 0],
            [31, 0, 0, 0],
            [0xdead_beef, 3, 0, 1 << 60],
        ] {
            assert_eq!(pow_public_exponent(&base, &exp), base.pow_vartime(exp));
        }
    }

    #[test]
    fn batch_inversion_skips_zero() {
        let mut v = [Fq::from(3u64), Fq::ZERO, Fq::from(9u64)];
        let mut w = v;
        assert_eq!(batch_invert(&mut v), 3);
        assert_eq!(batch_invert_vartime(&mut w), 3);
        assert_eq!(v, w);
        assert_eq!(v[1], Fq::ZERO);
        assert_eq!(v[0] * Fq::from(3u64), Fq::ONE);
        assert_eq!(v[2] * Fq::from(9u64), Fq::ONE);
    }

    #[test]
    fn bit_length_and_canonical_limbs() {
        assert_eq!(Fp::ZERO.bit_length_vartime(), 0);
        assert_eq!(Fp::ONE.bit_length_vartime(), 1);
        assert_eq!((-Fp::ONE).bit_length_vartime(), 255);
        assert_eq!(
            Fq::from(1u64 << 40).to_canonical_limbs(),
            [1 << 40, 0, 0, 0]
        );
        assert!(bool::from(
            Fp::from_canonical_limbs(fp::MODULUS.m).is_none()
        ));
        assert_eq!(Fp::from_raw_reduced(fp::MODULUS.m), Fp::ZERO);
    }
}
