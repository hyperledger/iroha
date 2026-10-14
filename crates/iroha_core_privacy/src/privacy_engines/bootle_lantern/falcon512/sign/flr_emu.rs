#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// ========================================================================
// Floating-point operations: emulated
// ========================================================================
// This file implements the FLR type for IEEE-754:2008 operations, with
// the requirements listed in flr.rs (in particular, there is no support
// for denormals, infinites or NaNs). The implementation uses only integer
// operations and strives to be constant-time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FLR(u64);
// lzcnt_nz(x) returns the number of leading zeros in the value x, assuming
// that it is non-zero.
// On x86 and x86-64, the bsr or lzcnt opcodes will be used (bsr does not
// support an operand equal to zero, but if the operand is non-zero then
// the conditional test will never leak information). On aarch64, the clz
// opcode will be used.
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
))]
#[inline(always)]
const fn lzcnt_nz(x: u64) -> u32 {
    // We need the "or 1" so that we do not hit the case x == 0, which
    // is non-constant-time on x86 without the lzcnt opcode.
    (x | 1).leading_zeros()
}
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
)))]
// This implementation computes the number of leading zeros with a
// dichotomic search.
const fn lzcnt_nz(x: u64) -> u32 {
    // Input: x != 0, len(x) <= 2*n
    // Output: y, c2
    //     y = x or (x >> n) such that y != 0, len(y) <= n
    //     c2 = c if len(x) > n, or c + n if len(x) <= n
    #[inline(always)]
    const fn step(x: u32, n: u32, c: u32) -> (u32, u32) {
        let y = x >> n;
        let m = ((y.wrapping_sub(1) as i32) >> n) as u32;
        (y | (m & x), c + (n & (m as u32)))
    }
    let y = x >> 32;
    let m = (y.wrapping_sub(1) >> 32) as u32;
    let x = (y as u32) | (m & (x as u32));
    let c = m & 32;
    let (x, c) = step(x, 16, c);
    let (x, c) = step(x, 8, c);
    let (x, c) = step(x, 4, c);
    let (x, c) = step(x, 2, c);
    // At this point, x != 0 and len(x) <= 2, i.e. x \in {1, 2, 3}.
    // We return c is x >= 2, or c + 1 if x = 1.
    c + (1 - (x >> 1))
}
// Given m and e, return m*2^n and e-n for an integer n such that
// 2^63 <= m*2^n < 2^64. If m = 0 then this returns (0, e-63).
const fn norm64(m: u64, e: i32) -> (u64, i32) {
    let c = lzcnt_nz(m | 1);
    (ulsh(m, c), e - (c as i32))
}
// Shifts by a 64-bit value, with a possibly secret shift count. We
// assume the presence of a barrel shifter, so that the shift count
// remains secret. On 64-bit architectures, we can make that
// assumption for all shift counts from 0 to 63, but on a 32-bit
// system, a 64-bit shift will typically invoke a subroutine which
// may be non-constant-time (this has been observed on 32-bit ARM
// and PowerPC, though it depends on the compiler). We use the ursh,
// irsh and ulsh functions to implement such shifts (irsh is an
// arithmetic right shift; ursh and ulsh are logical shifts).
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[inline(always)]
const fn ursh(x: u64, c: u32) -> u64 {
    x >> c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline(always)]
const fn ursh(x: u64, n: u32) -> u64 {
    let x = x ^ ((x ^ (x >> 32)) & ((n >> 5) as u64).wrapping_neg());
    x >> (n & 31)
}
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[inline(always)]
const fn ulsh(x: u64, c: u32) -> u64 {
    x << c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline(always)]
const fn ulsh(x: u64, n: u32) -> u64 {
    let x = x ^ ((x ^ (x << 32)) & ((n >> 5) as u64).wrapping_neg());
    x << (n & 31)
}
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[inline(always)]
const fn irsh(x: i64, c: u32) -> i64 {
    x >> c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline(always)]
const fn irsh(x: i64, n: u32) -> i64 {
    let x = x ^ ((x ^ (x >> 32)) & ((n >> 5) as i64).wrapping_neg());
    x >> (n & 31)
}
// Convenient constant for a 63-bit mask.
const M63: u64 = 0x7FFF_FFFF_FFFF_FFFF;
// Convenient constant for a 52-bit mask.
const M52: u64 = 0x000F_FFFF_FFFF_FFFF;
impl FLR {
    // IMPLEMENTATION NOTES
    // ====================
    //
    // We emulate strict IEEE-754 rules, including the packing of values
    // into 64-bit words. In order to compute the rounding properly, we
    // use two guard bits, one of which being "sticky":
    //
    //   Intermediate values are kept over 55 bits, in the [2^54, 2^55-1]
    //   range (i.e. two extra bits compared to the final output).
    //
    //   Least significant bit of the 55-bit value is set to 1 if any of
    //   the lower bits (which were dropped) was non-zero. This is what
    //   makes that bit "sticky". The sticky bit tracks whether the result
    //   was exactly the 55-bit value, or was in fact slightly higher.
    //
    // When rounding a 55-bit value with a sticky bit, the value is
    // is right-shifted by 2, but we must then add 1 if the low three
    // bits of the 55-bit value were 011, 110 or 111. The addition of 1
    // may trigger a carry that will yield 2^53 at the end; this is
    // actually correct because that will indirectly increment the exponent,
    // which is exactly what we want. In other words, given s, e and m such
    // that:
    //    s = 0 or 1
    //    m is in [2^54, 2^55-1]
    //    The value is (-1)^s*m*2^e
    // then we round and assemble them with:
    //    (s << 63) + ((e + 1076) << 52) + (m >> 2) + cc
    // where cc = 1 if the low three bits of m are 011, 110 or 111, or
    // cc = 0 otherwise. Note that the high bit of the shifted m is here
    // added to the "e" field, which is why we encode e + 1076 and not
    // e + 1077.
    //
    // cc can be computed as:
    //    cc = (0xC8 >> (m & 7)) & 1
    // or also:
    //    z = (m & (m >> 1))
    //    cc = (z | (z >> 1)) & 1
    // This function makes a new value out of the provided sign bit s,
    // exponent e, and mantissa. Rules:
    //    Only the low bit of s is used (0 or 1), the upper bits are ignored.
    //    For a non-zero value:
    //       2^54 <= m < 2^55, low bit is sticky
    //       value is (-1)^s * 2^e * m and is appropriately rounded
    //       no exponent overflow occurs
    //    For a zero value:
    //       m = 0
    //       e = -1076
    #[inline(always)]
    const fn make(s: u64, e: i32, m: u64) -> Self {
        let cc = (0xC8u64 >> ((m as u32) & 7)) & 1;
        Self((s << 63) + (((e + 1076) as u64) << 52) + (m >> 2) + cc)
    }
    // This function is similar to make(), but it sets e to the right value
    // (-1076) in case m = 0. m MUST be either 0 or in the [2^54,2^55-1]
    // range. Exponent e MUST NOT trigger a value overflow.
    #[inline(always)]
    const fn make_z(s: u64, e: i32, m: u64) -> Self {
        let t = ((m >> 54) as u32).wrapping_neg();
        let e = ((e + 1076) as u32) & t;
        let cc = (0xC8u64 >> ((m as u32) & 7)) & 1;
        Self((s << 63) + ((e as u64) << 52) + (m >> 2) + cc)
    }
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self::from_i64(1);
    #[inline(always)]
    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    // Convert a signed 64-bit integer to an FLR value.
    // Source value j must be in [-(2^63-1),+(2^63-1)] (i.e. -2^63 is
    // not allowed).
    #[inline(always)]
    pub(crate) const fn from_i64(j: i64) -> Self {
        Self::scaled(j, 0)
    }
    // Convert a signed 32-bit integer to an FLR value.
    // The complete 32-bit range is allowed, and the conversion is always
    // exact (the original integer can be recovered exactly).
    #[inline(always)]
    pub(crate) const fn from_i32(j: i32) -> Self {
        Self::scaled(j as i64, 0)
    }
    // For integer j in [-(2^63-1),+(2^63-1)] and integer sc, return
    // j*2^sc as a floating-point value. Input j = -2^63 is forbidden.
    // In the rest of the implementation, this function is called
    // _directly_ only for compile-time constant evaluation, and as such
    // does not need to be efficient or constant-time, except if it is
    // also used for conversion from integers (from_i32(), from_i64()),
    // since these functions are used with runtime secret values.
    #[inline(always)]
    pub(crate) const fn scaled(j: i64, sc: i32) -> Self {
        // Extract sign bit and get absolute value.
        let s = (j >> 63) as u64;
        let j = ((j as u64) ^ s).wrapping_sub(s);
        // For now we suppose that i != 0. We normalize it to [2^63,2^64-1]
        // and adjust the exponent in consequence.
        let (m, e) = norm64(j, sc + 9);
        // Divide m by 2^9 to get it in [2^54, 2^55-1]. If any of the
        // dropped bits is 1, then the least significant bit of the output
        // should be 1 (sticky bit).
        let m = (m | ((m & 0x1FF) + 0x1FF)) >> 9;
        // At this point, either m = 0, or m is in [2^54, 2^55-1]. We can
        // use make_z(), which will adjust the exponent in case m = 0.
        Self::make_z(s, e, m)
    }
    // Return self / 2.
    #[inline]
    pub(crate) fn half(self) -> Self {
        // We subtract 1 from the exponent, unless it is already the
        // minimal exponent, i.e. the value is 0. In that case, the
        // subtraction borrow spills into the sign bit, hence we can
        // detect that case by checking if it flipped the sign bit.
        let x = self.0;
        let y = x.wrapping_sub(1u64 << 52);
        Self(y.wrapping_add(((x ^ y) >> 11) & (1u64 << 52)))
    }
    // Multiply this value by 2^63.
    #[inline]
    pub(crate) fn mul2p63(self) -> Self {
        // As in double(), we add 63 to the exponent, unless the value
        // was zero.
        let x = self.0;
        let d = ((x & 0x7FF0_0000_0000_0000) + 0x7FF0_0000_0000_0000) as i64;
        let d = ((d >> 11) as u64) & (63u64 << 52);
        Self(x.wrapping_add(d))
    }
    // Divide all values in the provided slice with 2^e, for e in the
    // 1 to 9 range (inclusive). The value of e is not considered secret.
    // This is a helper function used in the implementation of the FFT
    // and included in the FLR API because different implementations might
    // do it very differently.
    pub(crate) fn slice_div2e(f: &mut [FLR], e: u32) {
        // In the emulated implementation, division by 2^e is done by
        // subtracting e from the exponent; we must just take care not to
        // do that with zero. If the exponent subtraction overflows, then
        // a borrow will spill into the sign and switch it.
        let ee = (e as u64) << 52;
        for i in 0..f.len() {
            let x = f[i].0;
            let y = x.wrapping_sub(ee);
            let ov = (((x ^ y) as i64) >> 11) as u64;
            f[i] = Self(y.wrapping_add(ov & ee));
        }
    }
    // Round this value to the nearest integer; the source must be in the
    // [-(2^63-1), +(2^63-1)] range.
    #[inline]
    pub(crate) fn rint(self) -> i64 {
        // Shifted mantissa to be in the [2^62,2^63-1] range (with the top
        // bit set).
        let m = ((self.0 << 10) | (1u64 << 62)) & M63;
        // Get the right-shift amount for the extracted mantissa.
        let e = 1085 - (((self.0 >> 52) as i32) & 0x7FF);
        // If the right-shift count is 64 or more, then the value will
        // round to zero. Note that this also handles the case of a
        // source value equal to zero, since its exponent field then
        // encodes (virtually) the value -1023.
        let m = m & ((((e - 64) as i64) >> 14) as u64);
        let e = (e & 63) as u32;
        // We need to apply rounding. Looking at the e+1 least significant
        // bits of m, denoted hmxxx (h = bit 2^e, m = bit 2^(e-1),
        // xxx = e-1 lowest bits), we need to add 1 to the shifted value
        // (m >> e) if either of the following situations arises:
        //    h = 1 and m = 1
        //    m = 1 and xxx != 0
        // z <- low e+1 bits of m (in top positions)
        let z = ulsh(m, 63 - e);
        // y has bit 61 set if xxx != 0.
        let y = ((z & 0x3FFF_FFFF_FFFF_FFFF) + 0x3FFF_FFFF_FFFF_FFFF) >> 1;
        let lo = (z | y) >> 61;
        let cc = (0xC8 >> (lo as u32)) & 1;
        // Do the shift + rounding.
        let x = ursh(m, e) + cc;
        // We have the rounded absolute value, we must apply the sign.
        let s = ((self.0 as i64) >> 63) as u64;
        (x ^ s).wrapping_sub(s) as i64
    }
    // Round this value to the largest integer not greater than the value
    // (i.e. round toward -infinity). The source must be in the
    // [-(2^63-1), +(2^63-1)] range.
    #[inline]
    pub(crate) fn floor(self) -> i64 {
        // We extract the mantissa just as in rint(), but we apply the
        // sign bit to it. We can then do the right shift over the signed
        // value; the integer shift rules will apply the proper rounding.
        let m = ((self.0 << 10) | (1u64 << 62)) & M63;
        let s = (self.0 as i64) >> 63;
        let x = ((m as i64) ^ s).wrapping_sub(s);
        // Get the right-shift amount for the extracted mantissa.
        let e = 1085 - (((self.0 >> 52) as i32) & 0x7FF);
        // If the right-shift count is 64 or more, then the value should
        // round to either 0 or -1, depending on the sign bit. If the
        // value is "minus zero" then we round it to -1 (arguably, this
        // is the correct behaviour). Since the extracted mantissa was
        // assumed to be in [-(2^63-1),+(2^63-1)], we only have to set
        // the shift count to 63 in that case (since the rounding is
        // just dropping some bits, there is no carry to account for).
        let e = ((e | ((63 - e) >> 16)) as u32) & 63;
        irsh(x, e)
    }
    // Round this value toward zero. The source must be in the
    // [-(2^63-1), +(2^63-1)] range.
    #[inline]
    pub(crate) fn trunc(self) -> i64 {
        // We extract the mantissa just as in rint(). We do the shift
        // with the unsigned mantissa, dropping the low bits; the sign
        // is applied afterwards. As in floor(), we can handle large
        // shift counts by simply saturating the count at 63.
        let m = ((self.0 << 10) | (1u64 << 62)) & M63;
        let e = 1085 - (((self.0 >> 52) as i32) & 0x7FF);
        let e = ((e | ((63 - e) >> 16)) as u32) & 63;
        let x = ursh(m, e);
        let s = (self.0 as i64) >> 63;
        ((x as i64) ^ s).wrapping_sub(s)
    }
    // Addition.
    #[inline]
    pub(crate) fn set_add(&mut self, other: Self) {
        // Get both operands as x and y, and such that x has the greater
        // absolute value of the two. If x and y have the same absolute
        // value and different signs, when we want x to be the positive
        // value. This guarantees the following:
        //   - Exponent of y is not greater than exponent of x.
        //   - Result has the sign of x.
        // The special case for identical absolute values is for adding
        // z with -z for some value z. Indeed, if abs(x) = abs(y), then
        // the following situations may happen:
        //    x > 0, y = x    -> result is positive
        //    x < 0, y = x    -> result is negative
        //    x > 0, y = -x   -> result is +0
        //    x < 0, y = -x   -> result is +0   (*)
        //    x = +0, y = +0  -> result is +0
        //    x = +0, y = -0  -> result is +0
        //    x = -0, y = +0  -> result is +0   (*)
        //    x = -0, y = -0  -> result is -0
        // Enforcing a swap when absolute values are equal but the sign of
        // x is 1 (negative) avoids the two situations tagged '(*)' above.
        // For all other situations, the result indeed has the sign of x.
        //
        // Note that for positive values, the numerical order of encoded
        // exponent||mantissa values matches the order of the encoded
        // values.
        let (x, y) = (self.0, other.0);
        let za = (x & M63).wrapping_sub(y & M63);
        // Since all values here remain far from infinites and NaNs,
        // neither x nor y may have an "all ones" exponent, hence
        // |za| < 2^63 - 2^52 (assuming za in signed interpretation).
        // Thus, "za-1" can yield a top non-zero bit only if za = 0.
        let za = za | (za.wrapping_sub(1) & x);
        let m = (x ^ y) & (((za as i64) >> 63) as u64);
        let (x, y) = (x ^ m, y ^ m);
        // Extract sign bits, exponents and mantissas. The mantissas are
        // scaled up to [2^55,2^56-1] and the exponent is unbiased. If
        // an operand is 0, then its mantissa is set to 0 at this step,
        // and its unbiased exponent is -1078.
        let ex = (x >> 52) as u32;
        let sx = ex >> 11;
        let ex = ex & 0x7FF;
        let xu = ((x & M52) << 3) | ((((ex + 0x7FF) >> 11) as u64) << 55);
        let ex = (ex as i32) - 1078;
        let ey = (y >> 52) as u32;
        let sy = ey >> 11;
        let ey = ey & 0x7FF;
        let yu = ((y & M52) << 3) | ((((ey + 0x7FF) >> 11) as u64) << 55);
        let ey = (ey as i32) - 1078;
        // x has the larger exponent; hence, we only need to right-shift y.
        // If the shift count is larger than 59 bits then we clamp the
        // value to zero.
        let n = ex - ey;
        let yu = yu & ((((n - 60) >> 16) as i64) as u64);
        let n = (n as u32) & 63;
        // Right-shift y by n bits; the lowest bit of yu is sticky.
        let m = ulsh(1, n) - 1;
        let yu = ursh(yu | ((yu & m) + m), n);
        // We now add or subtract the mantissas, depending on the sign bits.
        let dm = ((sx ^ sy) as u64).wrapping_neg();
        let zu = xu.wrapping_add(yu.wrapping_sub((yu << 1) & dm));
        // The result may be smaller than abs(x), or slightly larger,
        // though no more than twice larger. We first normalize it to
        // [2^63, 2^64-1] (keeping track of the exponent), then shrink
        // it down to [2^54, 2^55-1] (with the lsb being sticky).
        let (zu, ez) = norm64(zu, ex);
        let zu = (zu | ((zu & 0x1FF) + 0x1FF)) >> 9;
        let ez = ez + 9;
        // As explained above, we only have to use the sign of x at this
        // point.
        *self = Self::make_z(sx as u64, ez, zu);
    }
    // Subtraction.
    #[inline(always)]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.set_add(Self(other.0 ^ (1u64 << 63)));
    }
    // Negation.
    #[inline(always)]
    pub(crate) fn set_neg(&mut self) {
        self.0 ^= 1u64 << 63;
    }
    // Multiplication.
    #[inline]
    pub(crate) fn set_mul(&mut self, other: Self) {
        // Extract absolute values of mantissas, assuming non-zero
        // operands, and multiply them together.
        let xu = (self.0 & M52) | (1u64 << 52);
        let yu = (other.0 & M52) | (1u64 << 52);
        // Compute the mantissa product.
        // We do not use a 64x64->128 product because:
        //  - On some 64-bit platforms this is not constant-time (e.g.
        //    ARM Cortex-A53 and A55 CPUs).
        //  - On 32-bit platforms this might be done with a software
        //    routine that shortcuts cases when operands fit on 32 bits.
        //
        // Result will fit on 106 bits. We get it over three variables
        // z0:z1:zu, in base 2^25 (zu is 64-bit and can use up to 56 bits).
        let (x0, x1) = ((xu as u32) & 0x01FF_FFFF, (xu >> 25) as u32);
        let (y0, y1) = ((yu as u32) & 0x01FF_FFFF, (yu >> 25) as u32);
        let w = (x0 as u64) * (y0 as u64);
        let (z0, z1) = ((w as u32) & 0x01FF_FFFF, (w >> 25) as u32);
        let w = (x1 as u64) * (y0 as u64);
        let (z1, h) = (z1 + ((w as u32) & 0x01FF_FFFF), (w >> 25) as u32);
        let w = (x0 as u64) * (y1 as u64);
        let (z1, h) = (z1 + ((w as u32) & 0x01FF_FFFF), h + ((w >> 25) as u32));
        let w = (x1 as u64) * (y1 as u64);
        let zu = w + ((h + (z1 >> 25)) as u64);
        let z1 = z1 & 0x01FF_FFFF;
        // We have 2^104 <= z < 2^106. We first scale it down to the
        // [2^54, 2^56-1] range with the lowest bit being sticky. This means
        // keeping zu and simply dropping z0 and z1, except that if z0 and
        // z1 are not both zero, then the lowest bit of zu must be set to 1.
        let zu = zu | ((((z0 | z1) + 0x01FF_FFFF) >> 25) as u64);
        // We normalize the value to [2^54, 2^55-1] by right-shifting it
        // by 1 bit if its top bit is 1. We must take care to maintain the
        // stickiness of the least significant bit, and also remember whether
        // we did that extra shift.
        let es = ((zu >> 55) as u32) & 1;
        let zu = (zu >> es) | (zu & 1);
        // Aggregate scaling factor:
        //  - Each source exponent is biased by 1023.
        //  - Integral mantissas are scaled by 2^52, hence an extra 52
        //    bias for each exponent.
        //  - However, we right-shifted z by 50 + es.
        // In total, we must add the exponents, then subtract 2*(1023 + 52),
        // then add 50 + es.
        let ex = ((self.0 >> 52) as i32) & 0x7FF;
        let ey = ((other.0 >> 52) as i32) & 0x7FF;
        let e = ex + ey - 2100 + (es as i32);
        // Sign bit is the XOR of the operand sign bits.
        let s = (self.0 ^ other.0) >> 63;
        // Corrective action for zeros: if either of the operands is zero,
        // then the computations above are wrong, and we must clear the
        // mantissa and set the exponent to the right value in that case.
        // Note that since we assume in all the implementation that we
        // never overflow the exponent, we do not have to fix the exponent
        // in other non-zero cases.
        let dz = ((ex - 1) | (ey - 1)) >> 16;
        let e = e ^ (dz & (e ^ -1076));
        let zu = zu & !((dz as i64) as u64);
        *self = Self::make(s, e, zu);
    }
    // Squaring.
    #[inline(always)]
    pub(crate) fn square(self) -> Self {
        self * self
    }
    // Division.
    pub(crate) fn set_div(&mut self, other: Self) {
        // Extract mantissas (unsigned).
        let mut xu = (self.0 & M52) | (1u64 << 52);
        let yu = (other.0 & M52) | (1u64 << 52);
        // Perform bit-by-bit division of xu by yu; we run it for 55 bits.
        let mut q = 0;
        for _ in 0..55 {
            let b = (xu.wrapping_sub(yu) >> 63).wrapping_sub(1);
            xu -= b & yu;
            q |= b & 1;
            xu <<= 1;
            q <<= 1;
        }
        // 55-bit quotient is in q, with an extra multiplication by 2.
        // Set the lowest bit to 1 if xu is non-zero at this point (this
        // is the sticky bit).
        q |= (xu | xu.wrapping_neg()) >> 63;
        // Quotient is at most 2^56-1, but cannot be lower than 2^54, since
        // both operands to the loop were in [2^52, 2^53-1]. We have
        // a situation similar to that of set_mul(); we make an extra
        // right shift if necessary, keeping track in es whether we did it.
        let es = ((q >> 55) as u32) & 1;
        q = (q >> es) | (q & 1);
        // Aggregate scaling factor:
        //  - Each source exponent is biased by 1023, with an extra 52 for
        //    considering the mantissas as integers; these two bias
        //    cancel out each other.
        //  - The quotient was produced with a 55-bit scaling, but we may
        //    have removed one bit from that.
        // In total, we must subtract the exponents, then subtract 55,
        // then add es.
        let ex = ((self.0 >> 52) as i32) & 0x7FF;
        let ey = ((other.0 >> 52) as i32) & 0x7FF;
        let e = ex - ey - 55 + (es as i32);
        // Sign bit is the XOR of the operand sign bits.
        let s = (self.0 ^ other.0) >> 63;
        // Corrective action for zeros: if x was zero, then the above
        // computation is wrong and we must clamp q to 0, e to -1076,
        // and s to zero. We do not care about cases where y = 0 since
        // that would yield an infinite (or a NaN), and we assumed that
        // this never happens.
        let dz = (ex - 1) >> 16;
        let e = e ^ (dz & (e ^ -1076));
        let dm = !((dz as i64) as u64);
        let s = s & dm;
        q &= dm;
        *self = Self::make(s, e, q);
    }
    // Square root.
    pub(crate) fn sqrt(self) -> Self {
        // Extract exponent and mantissa. By assumption, the operand is
        // non-negative, hence we can ignore that the sign bit (we must
        // still mask it out because sqrt() can be applied to -0.0).
        // We want the "true" exponent corresponding to a mantissa in
        // the [1,2[ range.
        let mut xu = (self.0 & M52) | (1u64 << 52);
        let ex = ((self.0 >> 52) as u32) & 0x7FF;
        let mut e = (ex as i32) - 1023;
        // If the exponent is odd, then we double the mantissa and subtract
        // 1 from the exponent. We can then halve the exponent to account for
        // the square root operation.
        xu += ((-(e & 1) as i64) as u64) & xu;
        e >>= 1;
        // Double the mantissa.
        xu <<= 1;
        // The mantissa is now an integer in the [2^53,2^55-1] range. It
        // represents an value between 1 (inclusive) and 4 (exclusive) in
        // a fixed point notation (53 fractional bits). We compute the
        // square root bit by bit.
        let mut q = 0;
        let mut s = 0;
        let mut r = 1u64 << 53;
        for _ in 0..54 {
            let t = s + r;
            let b = (xu.wrapping_sub(t) >> 63).wrapping_sub(1);
            s += (r << 1) & b;
            xu -= t & b;
            q += r & b;
            xu <<= 1;
            r >>= 1;
        }
        // Now q is a rounded-low 54-bit value, with a leading 1, 52
        // fractional digits, and an additional guard bit. We add an
        // extra sticky bit to account for what remains of the operand.
        q <<= 1;
        q |= (xu | xu.wrapping_neg()) >> 63;
        // Result q is in the [2^54,2^55-1] range; we bias the exponent
        // by 54 bits (the value e at that point contains the "true"
        // exponent, but q is now considered an integer).
        e -= 54;
        // If the source value was zero, then we computed the square root
        // of 2^53 and set the exponent to -512, both of which are
        // incorrect; we clean this up here.
        q &= (((ex + 0x7FF) >> 11) as u64).wrapping_neg();
        Self::make_z(0, e, q)
    }
    // Compute 2^63*ccs*exp(-self), rounded to an integer. This function
    // assumes that 0 <= self < log(2) and 0 <= ccs <= 1; it returns a value
    // in [0,2^63] (low values are possible only if ccs is very small).
    pub(crate) fn expm_p63(self, ccs: Self) -> u64 {
        // The polynomial approximation of exp(-x) is from FACCT:
        //   https://eprint.iacr.org/2018/1234
        // Specifically, the values are extracted from the implementation
        // referenced by FACCT, available at:
        //   https://github.com/raykzhao/gaussian
        let mut y = Self::EXPM_COEFFS[0];
        let z = (self.mul2p63().trunc() as u64) << 1;
        let (z0, z1) = (z as u32, (z >> 32) as u32);
        for i in 1..Self::EXPM_COEFFS.len() {
            // Compute z*y over 128 bits, but keep only the top 64 bits.
            // We stick to 32-bit multiplications for the same reasons
            // as in set_mul().
            let (y0, y1) = (y as u32, (y >> 32) as u32);
            let f = (z0 as u64) * (y0 as u64);
            let a = (z0 as u64) * (y1 as u64) + (f >> 32);
            let b = (z1 as u64) * (y0 as u64);
            let c = (a >> 32)
                + (b >> 32)
                + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
                + (z1 as u64) * (y1 as u64);
            y = Self::EXPM_COEFFS[i].wrapping_sub(c);
        }
        // The scaling factor must be applied at the end. Since y is now
        // in fixed-point notation, we have to convert the factor to the
        // same format, and we do an extra integer multiplication.
        let z = (ccs.mul2p63().trunc() as u64) << 1;
        let (z0, z1) = (z as u32, (z >> 32) as u32);
        let (y0, y1) = (y as u32, (y >> 32) as u32);
        let f = (z0 as u64) * (y0 as u64);
        let a = (z0 as u64) * (y1 as u64) + (f >> 32);
        let b = (z1 as u64) * (y0 as u64);
        let y = (a >> 32)
            + (b >> 32)
            + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
            + (z1 as u64) * (y1 as u64);
        y
    }
    pub(crate) const EXPM_COEFFS: [u64; 13] = [
        0x0000_0004_7411_83A3,
        0x0000_0036_548C_FC06,
        0x0000_024F_DCBF_140A,
        0x0000_171D_939D_E045,
        0x0000_D00C_F58F_6F84,
        0x0006_8068_1CF7_96E3,
        0x002D_82D8_305B_0FEA,
        0x0111_1111_0E06_6FD0,
        0x0555_5555_5507_0F00,
        0x1555_5555_5581_FF00,
        0x4000_0000_0002_B400,
        0x7FFF_FFFF_FFFF_4800,
        0x8000_0000_0000_0000,
    ];
}
