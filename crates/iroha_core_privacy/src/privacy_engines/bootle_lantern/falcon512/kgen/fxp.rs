#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::table_assets::read_u64_le;
use core::cmp::Ordering;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::DefaultIsZeroes;
// ========================================================================
// Fixed-point operations
// ========================================================================
// The FXR type is a fixed-point number, internally represented over 64 bits.
// The integral part is 32 bits, while the fractional part is also 32 bits.
// For an internal 64-bit signed representation x, the represented real
// number is x/2^32.
#[derive(Clone, Copy, Debug, Eq)]
pub(crate) struct FXR(pub(crate) u64);
impl Default for FXR {
    fn default() -> Self {
        Self(0)
    }
}
impl DefaultIsZeroes for FXR {}
impl FXR {
    pub(crate) const ZERO: Self = Self::from_i32(0);
    // Convert a signed 32-bit integer to an FXR value. Since all signed
    // 32-bit integers are representable in the FXR format, no rounding
    // or truncation is applied.
    #[inline(always)]
    pub(crate) const fn from_i32(j: i32) -> Self {
        Self(((j as u32) as u64) << 32)
    }
    // Get an FXR value from its internal 64-bit representation. This is
    // used mostly for fixed constants.
    #[inline(always)]
    pub(crate) const fn from_u64_scaled32(x: u64) -> Self {
        Self(x)
    }
    // Round this value to the nearest integer (half-integers round up).
    // If the represented value is at least 2^31 - 0.5, then the rounding
    // overflows and -2^31 is obtained as a result.
    #[inline(always)]
    pub(crate) const fn round(self) -> i32 {
        let v = self.0.wrapping_add(0x8000_0000);
        ((v as i64) >> 32) as i32
    }
    // Addition (internally, wraps around at 64 bits).
    #[inline(always)]
    pub(crate) fn set_add(&mut self, other: Self) {
        self.0 = self.0.wrapping_add(other.0);
    }
    // Subtraction (internally, wraps around at 64 bits).
    #[inline(always)]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.0 = self.0.wrapping_sub(other.0);
    }
    // Negation (internally, wraps around at 64 bits).
    #[inline(always)]
    pub(crate) fn set_neg(&mut self) {
        self.0 = self.0.wrapping_neg();
    }
    // Multiplication (internally, wraps around at 64 bits).
    #[inline(always)]
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
            let z = ((self.0 as i64) as i128) * ((other.0 as i64) as i128);
            self.0 = (z >> 32) as u64;
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            let xl = self.0 as u32;
            let xh = (self.0 >> 32) as i32;
            let yl = other.0 as u32;
            let yh = (other.0 >> 32) as i32;
            let z0 = ((xl as u64) * (yl as u64)) >> 32;
            let z1 = ((xl as i64) * (yh as i64)) as u64;
            let z2 = ((xh as i64) * (yl as i64)) as u64;
            let z3 = (xh.wrapping_mul(yh) as u32 as u64) << 32;
            self.0 = z0.wrapping_add(z1).wrapping_add(z2).wrapping_add(z3);
        }
    }
    // Squaring (internally, wraps around at 64 bits).
    #[inline(always)]
    pub(crate) fn set_sqr(&mut self) {
        let x = *self;
        self.0 = (x * x).0;
    }
    #[inline(always)]
    pub(crate) fn sqr(self) -> Self {
        let mut r = self;
        r.set_sqr();
        r
    }
    // Division by 2^e. Rounding to nearest representable value is
    // applied (rounding up for results which are half-way between two
    // successive representable values). Shift count MUST be less than
    // 64. Shift count MAY be zero (in which case the value is unchanged).
    #[inline(always)]
    pub(crate) fn set_div2e(&mut self, e: u32) {
        let z = self.0.wrapping_add((1u64 << e) >> 1);
        self.0 = ((z as i64) >> e) as u64;
    }
    // Halving: this is equivalent to set_div2e(1).
    #[inline(always)]
    pub(crate) fn set_half(&mut self) {
        self.set_div2e(1);
    }
    // Multiplication by 2^e (internally, wraps around at 64 bits).
    // Shift count MUST be less than 64. Shift count MAY be zero (in which
    // case the value is unchanged).
    #[inline(always)]
    pub(crate) fn set_mul2e(&mut self, e: u32) {
        self.0 <<= e;
    }
    // Division. An internal division algorithm is applied; overflows
    // and similar edge conditions are ignored.
    #[inline(always)]
    pub(crate) fn set_div(&mut self, other: Self) {
        self.0 = Self::inner_div(self.0, other.0);
    }
    // Internal division routine. The steps must be followed exactly in
    // order to obtain reproducible values that match the reference
    // specification, even in case of overflow.
    fn inner_div(x: u64, y: u64) -> u64 {
        // Get absolute values and signs. We ignore the edge condition
        // of an overflow here; we afterwards assume that x and y fit
        // on 64 bits.
        let sx: u64 = ((x as i64) >> 63) as u64;
        let x = (x ^ sx).wrapping_sub(sx);
        let sy: u64 = ((y as i64) >> 63) as u64;
        let y = (y ^ sy).wrapping_sub(sy);
        // Do a bit by by division, assuming that the quotient fits. The
        // numerators starts at x*2, and is shifted one bit at a time.
        let mut q = 0;
        let mut num = x >> 31;
        for i in (33..64).rev() {
            let b = (((num.wrapping_sub(y) as i64) >> 63) + 1) as u64;
            q |= b << i;
            num = num.wrapping_sub(y & b.wrapping_neg());
            num <<= 1;
            num |= (x >> (i - 33)) & 1;
        }
        for i in (0..33).rev() {
            let b = (((num.wrapping_sub(y) as i64) >> 63) + 1) as u64;
            q |= b << i;
            num = num.wrapping_sub(y & b.wrapping_neg());
            num <<= 1;
        }
        // Rounding: if the remainder is at least y/2 (scaled), then we
        // add 2^(-32) to the quotient.
        let b = (((num.wrapping_sub(y) as i64) >> 63) + 1) as u64;
        q = q.wrapping_add(b);
        // Sign management: if the original x and y had different signs,
        // then we must negate the quotient.
        let s = sx ^ sy;
        q = (q ^ s).wrapping_sub(s);
        q
    }
}
impl Ord for FXR {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0 as i64).cmp(&(other.0 as i64))
    }
}
impl PartialOrd for FXR {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for FXR {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Add<FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn add(self, other: FXR) -> FXR {
        let mut r = self;
        r.set_add(other);
        r
    }
}
impl Add<&FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn add(self, other: &FXR) -> FXR {
        let mut r = self;
        r.set_add(*other);
        r
    }
}
impl Add<FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn add(self, other: FXR) -> FXR {
        let mut r = *self;
        r.set_add(other);
        r
    }
}
impl Add<&FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn add(self, other: &FXR) -> FXR {
        let mut r = *self;
        r.set_add(*other);
        r
    }
}
impl AddAssign<FXR> for FXR {
    #[inline(always)]
    fn add_assign(&mut self, other: FXR) {
        self.set_add(other);
    }
}
impl AddAssign<&FXR> for FXR {
    #[inline(always)]
    fn add_assign(&mut self, other: &FXR) {
        self.set_add(*other);
    }
}
impl Div<FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn div(self, other: FXR) -> FXR {
        let mut r = self;
        r.set_div(other);
        r
    }
}
impl Div<&FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn div(self, other: &FXR) -> FXR {
        let mut r = self;
        r.set_div(*other);
        r
    }
}
impl Div<FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn div(self, other: FXR) -> FXR {
        let mut r = *self;
        r.set_div(other);
        r
    }
}
impl Div<&FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn div(self, other: &FXR) -> FXR {
        let mut r = *self;
        r.set_div(*other);
        r
    }
}
impl DivAssign<FXR> for FXR {
    #[inline(always)]
    fn div_assign(&mut self, other: FXR) {
        self.set_div(other);
    }
}
impl DivAssign<&FXR> for FXR {
    #[inline(always)]
    fn div_assign(&mut self, other: &FXR) {
        self.set_div(*other);
    }
}
impl Mul<FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn mul(self, other: FXR) -> FXR {
        let mut r = self;
        r.set_mul(other);
        r
    }
}
impl Mul<&FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn mul(self, other: &FXR) -> FXR {
        let mut r = self;
        r.set_mul(*other);
        r
    }
}
impl Mul<FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn mul(self, other: FXR) -> FXR {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}
impl Mul<&FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn mul(self, other: &FXR) -> FXR {
        let mut r = *self;
        r.set_mul(*other);
        r
    }
}
impl MulAssign<FXR> for FXR {
    #[inline(always)]
    fn mul_assign(&mut self, other: FXR) {
        self.set_mul(other);
    }
}
impl MulAssign<&FXR> for FXR {
    #[inline(always)]
    fn mul_assign(&mut self, other: &FXR) {
        self.set_mul(*other);
    }
}
impl Neg for FXR {
    type Output = FXR;
    #[inline(always)]
    fn neg(self) -> FXR {
        let mut r = self;
        r.set_neg();
        r
    }
}
impl Neg for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn neg(self) -> FXR {
        let mut r = *self;
        r.set_neg();
        r
    }
}
impl Sub<FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn sub(self, other: FXR) -> FXR {
        let mut r = self;
        r.set_sub(other);
        r
    }
}
impl Sub<&FXR> for FXR {
    type Output = FXR;
    #[inline(always)]
    fn sub(self, other: &FXR) -> FXR {
        let mut r = self;
        r.set_sub(*other);
        r
    }
}
impl Sub<FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn sub(self, other: FXR) -> FXR {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}
impl Sub<&FXR> for &FXR {
    type Output = FXR;
    #[inline(always)]
    fn sub(self, other: &FXR) -> FXR {
        let mut r = *self;
        r.set_sub(*other);
        r
    }
}
impl SubAssign<FXR> for FXR {
    #[inline(always)]
    fn sub_assign(&mut self, other: FXR) {
        self.set_sub(other);
    }
}
impl SubAssign<&FXR> for FXR {
    #[inline(always)]
    fn sub_assign(&mut self, other: &FXR) {
        self.set_sub(*other);
    }
}
// A wrapper for a complex number, whose real and imaginary parts both use
// fixed-point (FXR).
#[derive(Clone, Copy, Debug)]
pub(crate) struct FXC {
    pub(crate) re: FXR,
    pub(crate) im: FXR,
}
impl FXC {
    #[inline(always)]
    fn set_add(&mut self, other: &Self) {
        self.re += other.re;
        self.im += other.im;
    }
    #[inline(always)]
    fn set_sub(&mut self, other: &Self) {
        self.re -= other.re;
        self.im -= other.im;
    }
    #[inline(always)]
    fn set_neg(&mut self) {
        self.re.set_neg();
        self.im.set_neg();
    }
    #[inline(always)]
    pub(crate) fn set_half(&mut self) {
        self.re.set_half();
        self.im.set_half();
    }
    #[inline(always)]
    pub(crate) fn half(self) -> Self {
        let mut r = self;
        r.set_half();
        r
    }
    #[inline(always)]
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
    #[inline(always)]
    pub(crate) fn set_conj(&mut self) {
        self.im.set_neg();
    }
    #[inline(always)]
    pub(crate) fn conj(self) -> Self {
        let mut r = self;
        r.set_conj();
        r
    }
}
impl Add<FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn add(self, other: FXC) -> FXC {
        let mut r = self;
        r.set_add(&other);
        r
    }
}
impl Add<&FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn add(self, other: &FXC) -> FXC {
        let mut r = self;
        r.set_add(other);
        r
    }
}
impl Add<FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn add(self, other: FXC) -> FXC {
        let mut r = *self;
        r.set_add(&other);
        r
    }
}
impl Add<&FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn add(self, other: &FXC) -> FXC {
        let mut r = *self;
        r.set_add(other);
        r
    }
}
impl AddAssign<FXC> for FXC {
    #[inline(always)]
    fn add_assign(&mut self, other: FXC) {
        self.set_add(&other);
    }
}
impl AddAssign<&FXC> for FXC {
    #[inline(always)]
    fn add_assign(&mut self, other: &FXC) {
        self.set_add(other);
    }
}
impl Mul<FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn mul(self, other: FXC) -> FXC {
        let mut r = self;
        r.set_mul(&other);
        r
    }
}
impl Mul<&FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn mul(self, other: &FXC) -> FXC {
        let mut r = self;
        r.set_mul(other);
        r
    }
}
impl Mul<FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn mul(self, other: FXC) -> FXC {
        let mut r = *self;
        r.set_mul(&other);
        r
    }
}
impl Mul<&FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn mul(self, other: &FXC) -> FXC {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}
impl MulAssign<FXC> for FXC {
    #[inline(always)]
    fn mul_assign(&mut self, other: FXC) {
        self.set_mul(&other);
    }
}
impl MulAssign<&FXC> for FXC {
    #[inline(always)]
    fn mul_assign(&mut self, other: &FXC) {
        self.set_mul(other);
    }
}
impl Neg for FXC {
    type Output = FXC;
    #[inline(always)]
    fn neg(self) -> FXC {
        let mut r = self;
        r.set_neg();
        r
    }
}
impl Neg for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn neg(self) -> FXC {
        let mut r = *self;
        r.set_neg();
        r
    }
}
impl Sub<FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn sub(self, other: FXC) -> FXC {
        let mut r = self;
        r.set_sub(&other);
        r
    }
}
impl Sub<&FXC> for FXC {
    type Output = FXC;
    #[inline(always)]
    fn sub(self, other: &FXC) -> FXC {
        let mut r = self;
        r.set_sub(other);
        r
    }
}
impl Sub<FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn sub(self, other: FXC) -> FXC {
        let mut r = *self;
        r.set_sub(&other);
        r
    }
}
impl Sub<&FXC> for &FXC {
    type Output = FXC;
    #[inline(always)]
    fn sub(self, other: &FXC) -> FXC {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}
impl SubAssign<FXC> for FXC {
    #[inline(always)]
    fn sub_assign(&mut self, other: FXC) {
        self.set_sub(&other);
    }
}
impl SubAssign<&FXC> for FXC {
    #[inline(always)]
    fn sub_assign(&mut self, other: &FXC) {
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
const fn decode_gm_tab(bytes: &[u8; 16_384]) -> [FXC; 1024] {
    let mut table = [FXC {
        re: FXR(0),
        im: FXR(0),
    }; 1024];
    let mut index = 0;
    while index < table.len() {
        let offset = index * 16;
        table[index] = FXC {
            re: FXR(read_u64_le(bytes, offset)),
            im: FXR(read_u64_le(bytes, offset + 8)),
        };
        index += 1;
    }
    table
}
pub(crate) const GM_TAB: [FXC; 1024] = decode_gm_tab(GM_TAB_BYTES);
// ========================================================================
