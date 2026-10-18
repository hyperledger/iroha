#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
//! Deterministic wrapping 32.32 fixed-point arithmetic for Falcon key generation.
use super::super::table_assets::{read_u32_le, read_u64_le};
use core::cmp::Ordering;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::DefaultIsZeroes;
// ========================================================================
// Fixed-point operations
// ========================================================================
// The Fxr type is a fixed-point number, internally represented over 64 bits.
// The integral part is 32 bits, while the fractional part is also 32 bits.
// For an internal 64-bit signed representation x, the represented real
// number is x/2^32.
#[derive(Clone, Copy, Debug, Default, Eq)]
pub struct Fxr(pub(crate) u64);
impl DefaultIsZeroes for Fxr {}
impl Fxr {
    pub(crate) const ZERO: Self = Self::from_i32(0);
    // Convert a signed 32-bit integer to an Fxr value. Since all signed
    // 32-bit integers are representable in the Fxr format, no rounding
    // or truncation is applied.
    #[inline]
    pub(crate) const fn from_i32(j: i32) -> Self {
        let bytes = j.to_le_bytes();
        Self(u64::from_le_bytes([
            0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
    }
    // Get an Fxr value from its internal 64-bit representation. This is
    // used mostly for fixed constants.
    #[inline]
    pub(crate) const fn from_u64_scaled32(x: u64) -> Self {
        Self(x)
    }
    // Round this value to the nearest integer (half-integers round up).
    // If the represented value is at least 2^31 - 0.5, then the rounding
    // overflows and -2^31 is obtained as a result.
    #[inline]
    pub(crate) const fn round(self) -> i32 {
        let v = self.0.wrapping_add(0x8000_0000);
        read_u32_le(&v.to_le_bytes(), 4).cast_signed()
    }
    // Addition (internally, wraps around at 64 bits).
    #[inline]
    pub(crate) fn set_add(&mut self, other: Self) {
        self.0 = self.0.wrapping_add(other.0);
    }
    // Subtraction (internally, wraps around at 64 bits).
    #[inline]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.0 = self.0.wrapping_sub(other.0);
    }
    // Negation (internally, wraps around at 64 bits).
    #[inline]
    pub(crate) fn set_neg(&mut self) {
        self.0 = self.0.wrapping_neg();
    }
    // Multiplication (internally, wraps around at 64 bits).
    #[inline]
    pub(crate) fn set_mul(&mut self, other: Self) {
        // We assume here that 64x64->128 multiplications are constant-time
        // on 64-bit x86, ARMv8 and RISC-V. This is not entirely true,
        // because at least on the 64-bit-aware ARM Cortex A53 and A55, the
        // multiplication completes a bit faster when both operands happen
        // to fit on 32 bits. Small leaks are considered less critical for
        // keygen, because each keygen naturally generates a new key pair,
        // uncorrelated with other key pairs, so that small leaks do not
        // accumulate with repreated experiments for breaking a single key.
        // (This argument does not hold if somebody is using this code to
        // repeatedly regenerate the same key pair, deterministically, from
        // a stored seed.)
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))]
        {
            let z = i128::from(self.0.cast_signed()) * i128::from(other.0.cast_signed());
            self.0 = read_u64_le(&(z >> 32).to_le_bytes(), 0);
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            self.0 = Self::mul_32_bit_limbs(self.0, other.0);
        }
    }
    // The portable production path is also available to unit tests, so the
    // selected native multiply and this exact limb implementation can be
    // checked against the same independent integer oracle.
    #[cfg(any(
        test,
        not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))
    ))]
    #[inline]
    fn mul_32_bit_limbs(left: u64, right: u64) -> u64 {
        let left = left.to_le_bytes();
        let right = right.to_le_bytes();
        let xl = read_u32_le(&left, 0);
        let xh = read_u32_le(&left, 4).cast_signed();
        let yl = read_u32_le(&right, 0);
        let yh = read_u32_le(&right, 4).cast_signed();
        let z0 = (u64::from(xl) * u64::from(yl)) >> 32;
        let z1 = (i64::from(xl) * i64::from(yh)).cast_unsigned();
        let z2 = (i64::from(xh) * i64::from(yl)).cast_unsigned();
        let z3 = u64::from(xh.wrapping_mul(yh).cast_unsigned()) << 32;
        z0.wrapping_add(z1).wrapping_add(z2).wrapping_add(z3)
    }
    // Squaring (internally, wraps around at 64 bits).
    #[inline]
    pub(crate) fn set_sqr(&mut self) {
        let x = *self;
        self.0 = (x * x).0;
    }
    #[inline]
    pub(crate) fn sqr(self) -> Self {
        let mut r = self;
        r.set_sqr();
        r
    }
    // Division by 2^e. Rounding to nearest representable value is
    // applied (rounding up for results which are half-way between two
    // successive representable values). Shift count MUST be less than
    // 64. Shift count MAY be zero (in which case the value is unchanged).
    #[inline]
    pub(crate) fn set_div2e(&mut self, e: u32) {
        let z = self.0.wrapping_add((1u64 << e) >> 1);
        self.0 = (z.cast_signed() >> e).cast_unsigned();
    }
    // Halving: this is equivalent to set_div2e(1).
    #[inline]
    pub(crate) fn set_half(&mut self) {
        self.set_div2e(1);
    }
    // Multiplication by 2^e (internally, wraps around at 64 bits).
    // Shift count MUST be less than 64. Shift count MAY be zero (in which
    // case the value is unchanged).
    #[inline]
    pub(crate) fn set_mul2e(&mut self, e: u32) {
        self.0 <<= e;
    }
    // Division. An internal division algorithm is applied; overflows
    // and similar edge conditions are ignored.
    #[inline]
    pub(crate) fn set_div(&mut self, other: Self) {
        self.0 = Self::inner_div(self.0, other.0);
    }
    // Internal division routine. The steps must be followed exactly in
    // order to obtain reproducible values that match the reference
    // specification, even in case of overflow.
    fn inner_div(numerator: u64, denominator: u64) -> u64 {
        // Get absolute values and signs. We ignore the edge condition
        // of an overflow here; we afterwards assume that numerator and denominator fit
        // on 64 bits.
        let numerator_sign: u64 = (numerator.cast_signed() >> 63).cast_unsigned();
        let numerator = (numerator ^ numerator_sign).wrapping_sub(numerator_sign);
        let denominator_sign: u64 = (denominator.cast_signed() >> 63).cast_unsigned();
        let denominator = (denominator ^ denominator_sign).wrapping_sub(denominator_sign);
        // Do a bit by by division, assuming that the quotient fits. The
        // numerators starts at numerator*2, and is shifted one bit at a time.
        let mut quotient = 0;
        let mut remainder = numerator >> 31;
        for shift in (33..64).rev() {
            let quotient_bit =
                ((remainder.wrapping_sub(denominator).cast_signed() >> 63) + 1).cast_unsigned();
            quotient |= quotient_bit << shift;
            remainder = remainder.wrapping_sub(denominator & quotient_bit.wrapping_neg());
            remainder <<= 1;
            remainder |= (numerator >> (shift - 33)) & 1;
        }
        for shift in (0..33).rev() {
            let quotient_bit =
                ((remainder.wrapping_sub(denominator).cast_signed() >> 63) + 1).cast_unsigned();
            quotient |= quotient_bit << shift;
            remainder = remainder.wrapping_sub(denominator & quotient_bit.wrapping_neg());
            remainder <<= 1;
        }
        // Rounding: if the remainder is at least denominator/2 (scaled), then we
        // add 2^(-32) to the quotient.
        let quotient_bit =
            ((remainder.wrapping_sub(denominator).cast_signed() >> 63) + 1).cast_unsigned();
        quotient = quotient.wrapping_add(quotient_bit);
        // Sign management: if the original numerator and denominator had different signs,
        // then we must negate the quotient.
        let sign = numerator_sign ^ denominator_sign;
        quotient = (quotient ^ sign).wrapping_sub(sign);
        quotient
    }
}
impl Ord for Fxr {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cast_signed().cmp(&other.0.cast_signed())
    }
}
impl PartialOrd for Fxr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Fxr {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Add<Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn add(self, other: Fxr) -> Fxr {
        let mut r = self;
        r.set_add(other);
        r
    }
}
impl Add<&Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn add(self, other: &Fxr) -> Fxr {
        let mut r = self;
        r.set_add(*other);
        r
    }
}
impl Add<Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn add(self, other: Fxr) -> Fxr {
        let mut r = *self;
        r.set_add(other);
        r
    }
}
impl Add<&Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn add(self, other: &Fxr) -> Fxr {
        let mut r = *self;
        r.set_add(*other);
        r
    }
}
impl AddAssign<Fxr> for Fxr {
    #[inline]
    fn add_assign(&mut self, other: Fxr) {
        self.set_add(other);
    }
}
impl AddAssign<&Fxr> for Fxr {
    #[inline]
    fn add_assign(&mut self, other: &Fxr) {
        self.set_add(*other);
    }
}
impl Div<Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn div(self, other: Fxr) -> Fxr {
        let mut r = self;
        r.set_div(other);
        r
    }
}
impl Div<&Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn div(self, other: &Fxr) -> Fxr {
        let mut r = self;
        r.set_div(*other);
        r
    }
}
impl Div<Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn div(self, other: Fxr) -> Fxr {
        let mut r = *self;
        r.set_div(other);
        r
    }
}
impl Div<&Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn div(self, other: &Fxr) -> Fxr {
        let mut r = *self;
        r.set_div(*other);
        r
    }
}
impl DivAssign<Fxr> for Fxr {
    #[inline]
    fn div_assign(&mut self, other: Fxr) {
        self.set_div(other);
    }
}
impl DivAssign<&Fxr> for Fxr {
    #[inline]
    fn div_assign(&mut self, other: &Fxr) {
        self.set_div(*other);
    }
}
impl Mul<Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn mul(self, other: Fxr) -> Fxr {
        let mut r = self;
        r.set_mul(other);
        r
    }
}
impl Mul<&Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn mul(self, other: &Fxr) -> Fxr {
        let mut r = self;
        r.set_mul(*other);
        r
    }
}
impl Mul<Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn mul(self, other: Fxr) -> Fxr {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}
impl Mul<&Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn mul(self, other: &Fxr) -> Fxr {
        let mut r = *self;
        r.set_mul(*other);
        r
    }
}
impl MulAssign<Fxr> for Fxr {
    #[inline]
    fn mul_assign(&mut self, other: Fxr) {
        self.set_mul(other);
    }
}
impl MulAssign<&Fxr> for Fxr {
    #[inline]
    fn mul_assign(&mut self, other: &Fxr) {
        self.set_mul(*other);
    }
}
impl Neg for Fxr {
    type Output = Fxr;
    #[inline]
    fn neg(self) -> Fxr {
        let mut r = self;
        r.set_neg();
        r
    }
}
impl Neg for &Fxr {
    type Output = Fxr;
    #[inline]
    fn neg(self) -> Fxr {
        let mut r = *self;
        r.set_neg();
        r
    }
}
impl Sub<Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn sub(self, other: Fxr) -> Fxr {
        let mut r = self;
        r.set_sub(other);
        r
    }
}
impl Sub<&Fxr> for Fxr {
    type Output = Fxr;
    #[inline]
    fn sub(self, other: &Fxr) -> Fxr {
        let mut r = self;
        r.set_sub(*other);
        r
    }
}
impl Sub<Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn sub(self, other: Fxr) -> Fxr {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}
impl Sub<&Fxr> for &Fxr {
    type Output = Fxr;
    #[inline]
    fn sub(self, other: &Fxr) -> Fxr {
        let mut r = *self;
        r.set_sub(*other);
        r
    }
}
impl SubAssign<Fxr> for Fxr {
    #[inline]
    fn sub_assign(&mut self, other: Fxr) {
        self.set_sub(other);
    }
}
impl SubAssign<&Fxr> for Fxr {
    #[inline]
    fn sub_assign(&mut self, other: &Fxr) {
        self.set_sub(*other);
    }
}
// A wrapper for a complex number, whose real and imaginary parts both use
// fixed-point (Fxr).
#[derive(Clone, Copy, Debug)]
pub struct Fxc {
    pub(crate) re: Fxr,
    pub(crate) im: Fxr,
}
impl Fxc {
    #[inline]
    fn set_add(&mut self, other: &Self) {
        self.re += other.re;
        self.im += other.im;
    }
    #[inline]
    fn set_sub(&mut self, other: &Self) {
        self.re -= other.re;
        self.im -= other.im;
    }
    #[inline]
    fn set_neg(&mut self) {
        self.re.set_neg();
        self.im.set_neg();
    }
    #[inline]
    pub(crate) fn set_half(&mut self) {
        self.re.set_half();
        self.im.set_half();
    }
    #[inline]
    pub(crate) fn half(self) -> Self {
        let mut r = self;
        r.set_half();
        r
    }
    #[inline]
    fn set_mul(&mut self, other: &Self) {
        // We are computing r = (a + i*b)*(c + i*d) with:
        //   z0 = a*c
        //   z1 = b*d
        //   z2 = (a + b)*(c + d)
        //   r = (z0 - z1) + i*(z2 - (z0 + z1))
        // We must follow these formulas to be sure to obtain the same
        // output as the reference code.
        let z0 = self.re * other.re;
        let z1 = self.im * other.im;
        let z2 = (self.re + self.im) * (other.re + other.im);
        self.re = z0 - z1;
        self.im = z2 - (z0 + z1);
    }
    #[inline]
    pub(crate) fn set_conj(&mut self) {
        self.im.set_neg();
    }
    #[inline]
    pub(crate) fn conj(self) -> Self {
        let mut r = self;
        r.set_conj();
        r
    }
}
impl Add<Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn add(self, other: Fxc) -> Fxc {
        let mut r = self;
        r.set_add(&other);
        r
    }
}
impl Add<&Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn add(self, other: &Fxc) -> Fxc {
        let mut r = self;
        r.set_add(other);
        r
    }
}
impl Add<Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn add(self, other: Fxc) -> Fxc {
        let mut r = *self;
        r.set_add(&other);
        r
    }
}
impl Add<&Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn add(self, other: &Fxc) -> Fxc {
        let mut r = *self;
        r.set_add(other);
        r
    }
}
impl AddAssign<Fxc> for Fxc {
    #[inline]
    fn add_assign(&mut self, other: Fxc) {
        self.set_add(&other);
    }
}
impl AddAssign<&Fxc> for Fxc {
    #[inline]
    fn add_assign(&mut self, other: &Fxc) {
        self.set_add(other);
    }
}
impl Mul<Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn mul(self, other: Fxc) -> Fxc {
        let mut r = self;
        r.set_mul(&other);
        r
    }
}
impl Mul<&Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn mul(self, other: &Fxc) -> Fxc {
        let mut r = self;
        r.set_mul(other);
        r
    }
}
impl Mul<Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn mul(self, other: Fxc) -> Fxc {
        let mut r = *self;
        r.set_mul(&other);
        r
    }
}
impl Mul<&Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn mul(self, other: &Fxc) -> Fxc {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}
impl MulAssign<Fxc> for Fxc {
    #[inline]
    fn mul_assign(&mut self, other: Fxc) {
        self.set_mul(&other);
    }
}
impl MulAssign<&Fxc> for Fxc {
    #[inline]
    fn mul_assign(&mut self, other: &Fxc) {
        self.set_mul(other);
    }
}
impl Neg for Fxc {
    type Output = Fxc;
    #[inline]
    fn neg(self) -> Fxc {
        let mut r = self;
        r.set_neg();
        r
    }
}
impl Neg for &Fxc {
    type Output = Fxc;
    #[inline]
    fn neg(self) -> Fxc {
        let mut r = *self;
        r.set_neg();
        r
    }
}
impl Sub<Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn sub(self, other: Fxc) -> Fxc {
        let mut r = self;
        r.set_sub(&other);
        r
    }
}
impl Sub<&Fxc> for Fxc {
    type Output = Fxc;
    #[inline]
    fn sub(self, other: &Fxc) -> Fxc {
        let mut r = self;
        r.set_sub(other);
        r
    }
}
impl Sub<Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn sub(self, other: Fxc) -> Fxc {
        let mut r = *self;
        r.set_sub(&other);
        r
    }
}
impl Sub<&Fxc> for &Fxc {
    type Output = Fxc;
    #[inline]
    fn sub(self, other: &Fxc) -> Fxc {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}
impl SubAssign<Fxc> for Fxc {
    #[inline]
    fn sub_assign(&mut self, other: Fxc) {
        self.set_sub(&other);
    }
}
impl SubAssign<&Fxc> for Fxc {
    #[inline]
    fn sub_assign(&mut self, other: &Fxc) {
        self.set_sub(other);
    }
}
// FFT constants:
//   n = 2^1024
//   w = exp(i*pi/n) (a primitive 2n-th root of 1)
//   w_j = w^(2*j+1) for j = 0..n-1 (n-th roots of -1)
//   rev() = bit reversal over 10 bits
//   GM_TAB[rev(j)] contains w_j
const GM_TAB_BYTES: &[u8; 16_384] = include_bytes!("../assets/kgen_fxp_gm_u64le_v1.bin");
const fn decode_gm_tab(bytes: &[u8; 16_384]) -> [Fxc; 1024] {
    let mut table = [Fxc {
        re: Fxr(0),
        im: Fxr(0),
    }; 1024];
    let mut index = 0;
    while index < table.len() {
        let offset = index * 16;
        table[index] = Fxc {
            re: Fxr(read_u64_le(bytes, offset)),
            im: Fxr(read_u64_le(bytes, offset + 8)),
        };
        index += 1;
    }
    table
}
pub const GM_TAB: [Fxc; 1024] = decode_gm_tab(GM_TAB_BYTES);
// ========================================================================

#[cfg(test)]
mod tests {
    use super::{Fxc, Fxr};
    use zeroize::Zeroize;

    const SCALE: i128 = 1_i128 << 32;
    const MODULUS: i128 = 1_i128 << 64;
    const BOUNDARIES: [u64; 16] = [
        0,
        1,
        2,
        0x0000_0000_7fff_ffff,
        0x0000_0000_8000_0000,
        0x0000_0000_ffff_ffff,
        0x0000_0001_0000_0000,
        0x0000_0001_0000_0001,
        0x7fff_ffff_7fff_ffff,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_0000_0000,
        0xffff_ffff_7fff_ffff,
        0xffff_ffff_8000_0000,
        0xffff_ffff_ffff_fffe,
        u64::MAX,
    ];

    // Independent integer oracles use arithmetic modulo 2^64 and Euclidean
    // division, not the production byte extraction, shifts or limb schedule.
    fn integer_value(raw: u64) -> i128 {
        let value = i128::from(raw);
        if value >= MODULUS / 2 {
            value - MODULUS
        } else {
            value
        }
    }

    fn wrapped(value: i128) -> u64 {
        u64::try_from(value.rem_euclid(MODULUS)).expect("residue fits u64")
    }

    fn product(left: u64, right: u64) -> u64 {
        wrapped((integer_value(left) * integer_value(right)).div_euclid(SCALE))
    }

    fn real_bits(value: Fxr) -> u64 {
        value.0
    }

    fn complex_bits(value: Fxc) -> (u64, u64) {
        (value.re.0, value.im.0)
    }

    // Exercise every existing owned/borrowed operator implementation explicitly
    // without relying on an expression's automatic operator selection.
    macro_rules! check_binary_variants {
        ($ty:ty, $bits:ident, $trait:ident, $method:ident, $assign:ident, $assign_method:ident,
         $left:expr, $right:expr, $expected:expr) => {{
            let left = $left;
            let right = $right;
            let expected = $expected;
            assert_eq!(
                $bits(<$ty as core::ops::$trait<$ty>>::$method(left, right)),
                expected,
            );
            assert_eq!(
                $bits(<$ty as core::ops::$trait<&$ty>>::$method(left, &right)),
                expected,
            );
            assert_eq!(
                $bits(<&$ty as core::ops::$trait<$ty>>::$method(&left, right)),
                expected,
            );
            assert_eq!(
                $bits(<&$ty as core::ops::$trait<&$ty>>::$method(&left, &right)),
                expected,
            );
            let mut assigned = left;
            <$ty as core::ops::$assign<$ty>>::$assign_method(&mut assigned, right);
            assert_eq!($bits(assigned), expected);
            let mut assigned = left;
            <$ty as core::ops::$assign<&$ty>>::$assign_method(&mut assigned, &right);
            assert_eq!($bits(assigned), expected);
        }};
    }

    #[test]
    fn integer_construction_rounding_and_ordering_keep_signed_boundaries() {
        const MINIMUM: Fxr = Fxr::from_i32(i32::MIN);
        const WRAPPED_ROUND: i32 = Fxr::from_u64_scaled32(0x7fff_ffff_8000_0000).round();
        assert_eq!(MINIMUM.0, 0x8000_0000_0000_0000);
        assert_eq!(WRAPPED_ROUND, i32::MIN);
        assert_eq!(Fxr::default(), Fxr::ZERO);
        for integer in [i32::MIN, i32::MIN + 1, -2, -1, 0, 1, 2, i32::MAX] {
            let value = Fxr::from_i32(integer);
            assert_eq!(value.0, wrapped(i128::from(integer) * SCALE));
            assert_eq!(value.round(), integer);
        }
        for (raw, expected) in [
            (0x0000_0000_7fff_ffff, 0),
            (0x0000_0000_8000_0000, 1),
            (0xffff_ffff_8000_0000, 0),
            (0xffff_fffe_8000_0000, -1),
            (0x7fff_ffff_7fff_ffff, i32::MAX),
            (0x7fff_ffff_8000_0000, i32::MIN),
        ] {
            assert_eq!(Fxr(raw).round(), expected);
        }
        for raw in BOUNDARIES {
            let rounded = integer_value(wrapped(integer_value(raw) + SCALE / 2)).div_euclid(SCALE);
            assert_eq!(Fxr(raw).round(), i32::try_from(rounded).unwrap());
            for other in BOUNDARIES {
                let expected = integer_value(raw).cmp(&integer_value(other));
                assert_eq!(Fxr(raw).cmp(&Fxr(other)), expected);
                assert_eq!(Fxr(raw).partial_cmp(&Fxr(other)), Some(expected));
                assert_eq!(Fxr(raw) == Fxr(other), raw == other);
            }
            let mut value = Fxr(raw);
            value.zeroize();
            assert_eq!(value, Fxr::ZERO);
        }
    }

    #[test]
    fn wrapping_scalar_operators_match_integer_oracle_and_portable_multiply() {
        for left in BOUNDARIES {
            let negated = wrapped(-integer_value(left));
            assert_eq!(<Fxr as core::ops::Neg>::neg(Fxr(left)).0, negated);
            assert_eq!(<&Fxr as core::ops::Neg>::neg(&Fxr(left)).0, negated);
            assert_eq!(Fxr(left).sqr().0, product(left, left));
            let mut squared = Fxr(left);
            squared.set_sqr();
            assert_eq!(squared.0, product(left, left));
            for right in BOUNDARIES {
                check_binary_variants!(
                    Fxr,
                    real_bits,
                    Add,
                    add,
                    AddAssign,
                    add_assign,
                    Fxr(left),
                    Fxr(right),
                    wrapped(integer_value(left) + integer_value(right))
                );
                check_binary_variants!(
                    Fxr,
                    real_bits,
                    Sub,
                    sub,
                    SubAssign,
                    sub_assign,
                    Fxr(left),
                    Fxr(right),
                    wrapped(integer_value(left) - integer_value(right))
                );
                let expected = product(left, right);
                check_binary_variants!(
                    Fxr,
                    real_bits,
                    Mul,
                    mul,
                    MulAssign,
                    mul_assign,
                    Fxr(left),
                    Fxr(right),
                    expected
                );
                assert_eq!(Fxr::mul_32_bit_limbs(left, right), expected);
            }
        }
    }

    #[test]
    fn power_of_two_scaling_preserves_rounding_and_wrapping_at_every_shift() {
        for raw in BOUNDARIES {
            for exponent in 0..64_u32 {
                let divisor = 1_i128 << exponent;
                let rounded =
                    integer_value(wrapped(integer_value(raw) + divisor / 2)).div_euclid(divisor);
                let mut divided = Fxr(raw);
                divided.set_div2e(exponent);
                assert_eq!(divided.0, wrapped(rounded));
                let mut multiplied = Fxr(raw);
                multiplied.set_mul2e(exponent);
                assert_eq!(multiplied.0, wrapped(integer_value(raw) * divisor));
            }
            let mut halved = Fxr(raw);
            halved.set_half();
            let expected = integer_value(wrapped(integer_value(raw) + 1)).div_euclid(2);
            assert_eq!(halved.0, wrapped(expected));
        }
    }

    #[test]
    fn division_preserves_signed_halfway_rounding_and_representational_overflow() {
        let numerators = [i64::MIN, -(1_i64 << 40), -1, 0, 1, 1_i64 << 40, i64::MAX];
        let denominators = [
            -(1_i64 << 62),
            -(3_i64 << 32),
            -(2_i64 << 32),
            -(1_i64 << 32),
            1_i64 << 32,
            2_i64 << 32,
            3_i64 << 32,
            1_i64 << 62,
        ];
        for numerator in numerators {
            for denominator in denominators {
                let scaled = i128::from(numerator).abs() * SCALE;
                let magnitude = i128::from(denominator).abs();
                let quotient = scaled / magnitude;
                let remainder = scaled % magnitude;
                let rounded = quotient + i128::from(2 * remainder >= magnitude);
                assert!(rounded <= MODULUS / 2);
                let signed = if numerator.is_negative() ^ denominator.is_negative() {
                    -rounded
                } else {
                    rounded
                };
                check_binary_variants!(
                    Fxr,
                    real_bits,
                    Div,
                    div,
                    DivAssign,
                    div_assign,
                    Fxr(numerator.cast_unsigned()),
                    Fxr(denominator.cast_unsigned()),
                    wrapped(signed)
                );
            }
        }
        assert_eq!((Fxr(1) / Fxr(2_u64 << 32)).0, 1);
        assert_eq!((Fxr(u64::MAX) / Fxr(2_u64 << 32)).0, u64::MAX);
        assert_eq!(
            (Fxr(i64::MIN.cast_unsigned()) / Fxr::from_i32(-1)).0,
            1_u64 << 63
        );
    }

    #[test]
    fn complex_operators_preserve_three_product_rounding_schedule() {
        let left = Fxc {
            re: Fxr(1),
            im: Fxr(1),
        };
        let right = Fxc {
            re: Fxr(1_u64 << 31),
            im: Fxr(1_u64 << 31),
        };
        // Each separate cross product would truncate to zero. The required
        // three-product schedule instead retains exactly two fractional units.
        check_binary_variants!(
            Fxc,
            complex_bits,
            Mul,
            mul,
            MulAssign,
            mul_assign,
            left,
            right,
            (0, 2)
        );
        check_binary_variants!(
            Fxc,
            complex_bits,
            Add,
            add,
            AddAssign,
            add_assign,
            left,
            right,
            (0x8000_0001, 0x8000_0001)
        );
        check_binary_variants!(
            Fxc,
            complex_bits,
            Sub,
            sub,
            SubAssign,
            sub_assign,
            left,
            right,
            (0xffff_ffff_8000_0001, 0xffff_ffff_8000_0001)
        );
        assert_eq!(
            complex_bits(<Fxc as core::ops::Neg>::neg(left)),
            (u64::MAX, u64::MAX)
        );
        assert_eq!(
            complex_bits(<&Fxc as core::ops::Neg>::neg(&left)),
            (u64::MAX, u64::MAX)
        );
        assert_eq!(complex_bits(left.conj()), (1, u64::MAX));
        let mixed = Fxc {
            re: Fxr(1),
            im: Fxr((-3_i64).cast_unsigned()),
        };
        assert_eq!(complex_bits(mixed.half()), (1, u64::MAX));
        let mut mutable = mixed;
        mutable.set_half();
        assert_eq!(complex_bits(mutable), (1, u64::MAX));
        mutable.set_conj();
        assert_eq!(complex_bits(mutable), (1, 1));
    }
}
