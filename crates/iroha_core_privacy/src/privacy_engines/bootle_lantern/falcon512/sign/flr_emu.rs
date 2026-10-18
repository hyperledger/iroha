#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
//! Integer-only binary64 arithmetic on Falcon signing's finite supported domain.
use super::super::super::table_assets::read_u32_le;

// Explicit low-word extraction preserves modulo-2^32 limb arithmetic.
#[inline]
const fn low_u32(word: u64) -> u32 {
    read_u32_le(&word.to_le_bytes(), 0)
}
// ========================================================================
// Floating-point operations: emulated
// ========================================================================
// This file implements the Flr type for IEEE-754:2008 operations, with
// the requirements listed in flr.rs (in particular, there is no support
// for denormals, infinites or NaNs). The implementation uses only integer
// operations and strives to be constant-time.
#[derive(Clone, Copy, Debug)]
pub struct Flr(u64);
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
#[inline]
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
#[inline]
const fn lzcnt_nz(x: u64) -> u32 {
    lzcnt_nz_portable(x)
}
#[cfg(any(
    test,
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec"
    ))
))]
// This implementation computes the number of leading zeros with a
// dichotomic search.
const fn lzcnt_nz_portable(x: u64) -> u32 {
    // Input: x != 0, len(x) <= 2*n
    // Output: y, c2
    //     y = x or (x >> n) such that y != 0, len(y) <= n
    //     c2 = c if len(x) > n, or c + n if len(x) <= n
    #[inline]
    const fn step(value: u32, shift: u32, count: u32) -> (u32, u32) {
        let upper = value >> shift;
        let mask = (upper.wrapping_sub(1).cast_signed() >> shift).cast_unsigned();
        (upper | (mask & value), count + (shift & mask))
    }
    let y = x >> 32;
    let m = low_u32(y.wrapping_sub(1) >> 32);
    let x = low_u32(y) | (m & low_u32(x));
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
    (ulsh(m, c), e - c.cast_signed())
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
#[inline]
const fn ursh(x: u64, c: u32) -> u64 {
    x >> c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline]
const fn ursh(x: u64, n: u32) -> u64 {
    ursh_portable(x, n)
}
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
const fn ursh_portable(x: u64, n: u32) -> u64 {
    let x = x ^ ((x ^ (x >> 32)) & ((n >> 5) as u64).wrapping_neg());
    x >> (n & 31)
}
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[inline]
const fn ulsh(x: u64, c: u32) -> u64 {
    x << c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline]
const fn ulsh(x: u64, n: u32) -> u64 {
    ulsh_portable(x, n)
}
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
const fn ulsh_portable(x: u64, n: u32) -> u64 {
    let x = x ^ ((x ^ (x << 32)) & ((n >> 5) as u64).wrapping_neg());
    x << (n & 31)
}
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
))]
#[inline]
const fn irsh(x: i64, c: u32) -> i64 {
    x >> c
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "riscv64"
)))]
#[inline]
const fn irsh(x: i64, n: u32) -> i64 {
    irsh_portable(x, n)
}
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
const fn irsh_portable(x: i64, n: u32) -> i64 {
    let x = x ^ ((x ^ (x >> 32)) & ((n >> 5) as i64).wrapping_neg());
    x >> (n & 31)
}
// Convenient constant for a 63-bit mask.
const M63: u64 = 0x7FFF_FFFF_FFFF_FFFF;
// Convenient constant for a 52-bit mask.
const M52: u64 = 0x000F_FFFF_FFFF_FFFF;
impl Flr {
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
    #[inline]
    const fn make(s: u64, e: i32, m: u64) -> Self {
        let cc = (0xC8u64 >> (low_u32(m) & 7)) & 1;
        Self((s << 63) + (((e + 1076) as i64).cast_unsigned() << 52) + (m >> 2) + cc)
    }
    // This function is similar to make(), but it sets e to the right value
    // (-1076) in case m = 0. m MUST be either 0 or in the [2^54,2^55-1]
    // range. Exponent e MUST NOT trigger a value overflow.
    #[inline]
    const fn make_z(s: u64, e: i32, m: u64) -> Self {
        let t = low_u32(m >> 54).wrapping_neg();
        let e = (e + 1076).cast_unsigned() & t;
        let cc = (0xC8u64 >> (low_u32(m) & 7)) & 1;
        Self((s << 63) + ((e as u64) << 52) + (m >> 2) + cc)
    }
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self::from_i64(1);
    #[inline]
    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    // Convert a signed 64-bit integer to an Flr value.
    // Source value j must be in [-(2^63-1),+(2^63-1)] (i.e. -2^63 is
    // not allowed).
    #[inline]
    pub(crate) const fn from_i64(j: i64) -> Self {
        Self::scaled(j, 0)
    }
    // Convert a signed 32-bit integer to an Flr value.
    // The complete 32-bit range is allowed, and the conversion is always
    // exact (the original integer can be recovered exactly).
    #[inline]
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
    #[inline]
    pub(crate) const fn scaled(j: i64, sc: i32) -> Self {
        // Extract sign bit and get absolute value.
        let s = (j >> 63).cast_unsigned();
        let j = (j.cast_unsigned() ^ s).wrapping_sub(s);
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
        let d = ((x & 0x7FF0_0000_0000_0000) + 0x7FF0_0000_0000_0000).cast_signed();
        let d = (d >> 11).cast_unsigned() & (63u64 << 52);
        Self(x.wrapping_add(d))
    }
    // Divide all values in the provided slice with 2^e, for e in the
    // 1 to 9 range (inclusive). The value of e is not considered secret.
    // This is a helper function used in the implementation of the FFT
    // and included in the Flr API because different implementations might
    // do it very differently.
    pub(crate) fn slice_div2e(f: &mut [Flr], e: u32) {
        // In the emulated implementation, division by 2^e is done by
        // subtracting e from the exponent; we must just take care not to
        // do that with zero. If the exponent subtraction overflows, then
        // a borrow will spill into the sign and switch it.
        let ee = u64::from(e) << 52;
        for value in f {
            let x = value.0;
            let y = x.wrapping_sub(ee);
            let ov = ((x ^ y).cast_signed() >> 11).cast_unsigned();
            *value = Self(y.wrapping_add(ov & ee));
        }
    }
    // Round this value to the nearest integer; the source must be in the
    // [-(2^63-1), +(2^63-1)] range.
    #[inline]
    pub(crate) fn rint(self) -> i64 {
        // Shifted mantissa to be in the [2^62,2^63-1] range (with the top
        // bit set).
        let mantissa = ((self.0 << 10) | (1u64 << 62)) & M63;
        // Get the right-shift amount for the extracted mantissa.
        let shift = 1085 - (low_u32(self.0 >> 52).cast_signed() & 0x7FF);
        // If the right-shift count is 64 or more, then the value will
        // round to zero. Note that this also handles the case of a
        // source value equal to zero, since its exponent field then
        // encodes (virtually) the value -1023.
        let mantissa = mantissa & (i64::from(shift - 64) >> 14).cast_unsigned();
        let shift = (shift & 63).cast_unsigned();
        // We need to apply rounding. Looking at the shift+1 least significant
        // bits of mantissa, denoted hmxxx (h = bit 2^shift, mantissa = bit 2^(shift-1),
        // xxx = shift-1 lowest bits), we need to add 1 to the shifted value
        // (mantissa >> shift) if either of the following situations arises:
        //    h = 1 and mantissa = 1
        //    mantissa = 1 and xxx != 0
        // discarded <- low shift+1 bits of mantissa (in top positions)
        let discarded = ulsh(mantissa, 63 - shift);
        // sticky has bit 61 set if xxx != 0.
        let sticky = ((discarded & 0x3FFF_FFFF_FFFF_FFFF) + 0x3FFF_FFFF_FFFF_FFFF) >> 1;
        let lo = (discarded | sticky) >> 61;
        let cc = (0xC8 >> low_u32(lo)) & 1;
        // Do the shift + rounding.
        let rounded = ursh(mantissa, shift) + cc;
        // We have the rounded absolute value, we must apply the sign.
        let sign = (self.0.cast_signed() >> 63).cast_unsigned();
        (rounded ^ sign).wrapping_sub(sign).cast_signed()
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
        let s = self.0.cast_signed() >> 63;
        let x = (m.cast_signed() ^ s).wrapping_sub(s);
        // Get the right-shift amount for the extracted mantissa.
        let e = 1085 - (low_u32(self.0 >> 52).cast_signed() & 0x7FF);
        // If the right-shift count is 64 or more, then the value should
        // round to either 0 or -1, depending on the sign bit. If the
        // value is "minus zero" then we round it to -1 (arguably, this
        // is the correct behaviour). Since the extracted mantissa was
        // assumed to be in [-(2^63-1),+(2^63-1)], we only have to set
        // the shift count to 63 in that case (since the rounding is
        // just dropping some bits, there is no carry to account for).
        let e = (e | ((63 - e) >> 16)).cast_unsigned() & 63;
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
        let e = 1085 - (low_u32(self.0 >> 52).cast_signed() & 0x7FF);
        let e = (e | ((63 - e) >> 16)).cast_unsigned() & 63;
        let x = ursh(m, e);
        let s = self.0.cast_signed() >> 63;
        (x.cast_signed() ^ s).wrapping_sub(s)
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
        let m = (x ^ y) & (za.cast_signed() >> 63).cast_unsigned();
        let (x, y) = (x ^ m, y ^ m);
        // Extract sign bits, exponents and mantissas. The mantissas are
        // scaled up to [2^55,2^56-1] and the exponent is unbiased. If
        // an operand is 0, then its mantissa is set to 0 at this step,
        // and its unbiased exponent is -1078.
        let ex = low_u32(x >> 52);
        let sx = ex >> 11;
        let ex = ex & 0x7FF;
        let xu = ((x & M52) << 3) | (u64::from((ex + 0x7FF) >> 11) << 55);
        let ex = ex.cast_signed() - 1078;
        let ey = low_u32(y >> 52);
        let sy = ey >> 11;
        let ey = ey & 0x7FF;
        let yu = ((y & M52) << 3) | (u64::from((ey + 0x7FF) >> 11) << 55);
        let ey = ey.cast_signed() - 1078;
        // x has the larger exponent; hence, we only need to right-shift y.
        // If the shift count is larger than 59 bits then we clamp the
        // value to zero.
        let n = ex - ey;
        let yu = yu & i64::from((n - 60) >> 16).cast_unsigned();
        let n = n.cast_unsigned() & 63;
        // Right-shift y by n bits; the lowest bit of yu is sticky.
        let m = ulsh(1, n) - 1;
        let yu = ursh(yu | ((yu & m) + m), n);
        // We now add or subtract the mantissas, depending on the sign bits.
        let dm = u64::from(sx ^ sy).wrapping_neg();
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
        *self = Self::make_z(u64::from(sx), ez, zu);
    }
    // Subtraction.
    #[inline]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.set_add(Self(other.0 ^ (1u64 << 63)));
    }
    // Negation.
    #[inline]
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
        let (x0, x1) = (low_u32(xu) & 0x01FF_FFFF, low_u32(xu >> 25));
        let (y0, y1) = (low_u32(yu) & 0x01FF_FFFF, low_u32(yu >> 25));
        let w = u64::from(x0) * u64::from(y0);
        let (z0, z1) = (low_u32(w) & 0x01FF_FFFF, low_u32(w >> 25));
        let w = u64::from(x1) * u64::from(y0);
        let (z1, h) = (z1 + (low_u32(w) & 0x01FF_FFFF), low_u32(w >> 25));
        let w = u64::from(x0) * u64::from(y1);
        let (z1, h) = (z1 + (low_u32(w) & 0x01FF_FFFF), h + (low_u32(w >> 25)));
        let w = u64::from(x1) * u64::from(y1);
        let zu = w + u64::from(h + (z1 >> 25));
        let z1 = z1 & 0x01FF_FFFF;
        // We have 2^104 <= z < 2^106. We first scale it down to the
        // [2^54, 2^56-1] range with the lowest bit being sticky. This means
        // keeping zu and simply dropping z0 and z1, except that if z0 and
        // z1 are not both zero, then the lowest bit of zu must be set to 1.
        let zu = zu | u64::from(((z0 | z1) + 0x01FF_FFFF) >> 25);
        // We normalize the value to [2^54, 2^55-1] by right-shifting it
        // by 1 bit if its top bit is 1. We must take care to maintain the
        // stickiness of the least significant bit, and also remember whether
        // we did that extra shift.
        let es = low_u32(zu >> 55) & 1;
        let zu = (zu >> es) | (zu & 1);
        // Aggregate scaling factor:
        //  - Each source exponent is biased by 1023.
        //  - Integral mantissas are scaled by 2^52, hence an extra 52
        //    bias for each exponent.
        //  - However, we right-shifted z by 50 + es.
        // In total, we must add the exponents, then subtract 2*(1023 + 52),
        // then add 50 + es.
        let ex = low_u32(self.0 >> 52).cast_signed() & 0x7FF;
        let ey = low_u32(other.0 >> 52).cast_signed() & 0x7FF;
        let e = ex + ey - 2100 + es.cast_signed();
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
        let zu = zu & !i64::from(dz).cast_unsigned();
        *self = Self::make(s, e, zu);
    }
    // Squaring.
    #[inline]
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
        let es = low_u32(q >> 55) & 1;
        q = (q >> es) | (q & 1);
        // Aggregate scaling factor:
        //  - Each source exponent is biased by 1023, with an extra 52 for
        //    considering the mantissas as integers; these two bias
        //    cancel out each other.
        //  - The quotient was produced with a 55-bit scaling, but we may
        //    have removed one bit from that.
        // In total, we must subtract the exponents, then subtract 55,
        // then add es.
        let ex = low_u32(self.0 >> 52).cast_signed() & 0x7FF;
        let ey = low_u32(other.0 >> 52).cast_signed() & 0x7FF;
        let e = ex - ey - 55 + es.cast_signed();
        // Sign bit is the XOR of the operand sign bits.
        let s = (self.0 ^ other.0) >> 63;
        // Corrective action for zeros: if x was zero, then the above
        // computation is wrong and we must clamp q to 0, e to -1076,
        // and s to zero. We do not care about cases where y = 0 since
        // that would yield an infinite (or a NaN), and we assumed that
        // this never happens.
        let dz = (ex - 1) >> 16;
        let e = e ^ (dz & (e ^ -1076));
        let dm = !i64::from(dz).cast_unsigned();
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
        let ex = low_u32(self.0 >> 52) & 0x7FF;
        let mut exponent = ex.cast_signed() - 1023;
        // If the exponent is odd, then we double the mantissa and subtract
        // 1 from the exponent. We can then halve the exponent to account for
        // the square root operation.
        xu += i64::from(-(exponent & 1)).cast_unsigned() & xu;
        exponent >>= 1;
        // Double the mantissa.
        xu <<= 1;
        // The mantissa is now an integer in the [2^53,2^55-1] range. It
        // represents an value between 1 (inclusive) and 4 (exclusive) in
        // a fixed point notation (53 fractional bits). We compute the
        // square root bit by bit.
        let mut root = 0;
        let mut accumulated = 0;
        let mut bit = 1u64 << 53;
        for _ in 0..54 {
            let trial = accumulated + bit;
            let accepted = (xu.wrapping_sub(trial) >> 63).wrapping_sub(1);
            accumulated += (bit << 1) & accepted;
            xu -= trial & accepted;
            root += bit & accepted;
            xu <<= 1;
            bit >>= 1;
        }
        // Now root is a rounded-low 54-bit value, with a leading 1, 52
        // fractional digits, and an additional guard bit. We add an
        // extra sticky bit to account for what remains of the operand.
        root <<= 1;
        root |= (xu | xu.wrapping_neg()) >> 63;
        // Result root is in the [2^54,2^55-1] range; we bias the exponent
        // by 54 bits (the value exponent at that point contains the "true"
        // exponent, but root is now considered an integer).
        exponent -= 54;
        // If the source value was zero, then we computed the square root
        // of 2^53 and set the exponent to -512, both of which are
        // incorrect; we clean this up here.
        root &= u64::from((ex + 0x7FF) >> 11).wrapping_neg();
        Self::make_z(0, exponent, root)
    }
    // Compute 2^63*ccs*exp(-self), rounded to an integer. This function
    // assumes that 0 <= self < log(2) and 0 <= ccs <= 1; it returns a value
    // in [0,2^63] (low values are possible only if ccs is very small).
    // Unit scale returns the unscaled polynomial, including 2^63 at self=0.
    // Either sign of a zero scale returns zero.
    pub(crate) fn expm_p63(self, ccs: Self) -> u64 {
        // The polynomial approximation of exp(-x) is from FACCT:
        //   https://eprint.iacr.org/2018/1234
        // Specifically, the values are extracted from the implementation
        // referenced by FACCT, available at:
        //   https://github.com/raykzhao/gaussian
        let mut accumulator = Self::EXPM_COEFFS[0];
        let multiplier = self.mul2p63().trunc().cast_unsigned() << 1;
        let (z0, z1) = (low_u32(multiplier), low_u32(multiplier >> 32));
        for coefficient_index in 1..Self::EXPM_COEFFS.len() {
            // Compute multiplier*accumulator over 128 bits, but keep only the top 64 bits.
            // We stick to 32-bit multiplications for the same reasons
            // as in set_mul().
            let (y0, y1) = (low_u32(accumulator), low_u32(accumulator >> 32));
            let low_product = u64::from(z0) * u64::from(y0);
            let cross_low = u64::from(z0) * u64::from(y1) + (low_product >> 32);
            let cross_high = u64::from(z1) * u64::from(y0);
            let high_product = (cross_low >> 32)
                + (cross_high >> 32)
                + ((u64::from(low_u32(cross_low)) + u64::from(low_u32(cross_high))) >> 32)
                + u64::from(z1) * u64::from(y1);
            accumulator = Self::EXPM_COEFFS[coefficient_index].wrapping_sub(high_product);
        }
        // The scaling factor must be applied at the end. Since accumulator is now
        // in fixed-point notation, we have to convert the factor to the
        // same format, and we do an extra integer multiplication.
        // At ccs=1, ccs*2^63 is outside trunc's signed input domain and
        // Q64 cannot represent the unit factor. Mask that factor to zero
        // before conversion, then select the original polynomial below.
        // Every nonunit factor retains its original conversion and rounding.
        let unit_difference = ccs.0 ^ Self::ONE.0;
        let unit_mask = ((unit_difference | unit_difference.wrapping_neg()) >> 63).wrapping_sub(1);
        let converted_factor = Self(ccs.0 & !unit_mask);
        let multiplier = converted_factor.mul2p63().trunc().cast_unsigned() << 1;
        let (z0, z1) = (low_u32(multiplier), low_u32(multiplier >> 32));
        let (y0, y1) = (low_u32(accumulator), low_u32(accumulator >> 32));
        let low_product = u64::from(z0) * u64::from(y0);
        let cross_low = u64::from(z0) * u64::from(y1) + (low_product >> 32);
        let cross_high = u64::from(z1) * u64::from(y0);
        let scaled = (cross_low >> 32)
            + (cross_high >> 32)
            + ((u64::from(low_u32(cross_low)) + u64::from(low_u32(cross_high))) >> 32)
            + u64::from(z1) * u64::from(y1);
        (accumulator & unit_mask) | (scaled & !unit_mask)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_extraction_normalization_and_portable_shifts_preserve_all_bits() {
        assert_eq!(low_u32(0xFEDC_BA98_7654_3210), 0x7654_3210);
        assert_eq!(low_u32(u64::MAX), u32::MAX);
        assert_eq!(norm64(0, 7), (0, -56));
        for bit in 0..64 {
            let word = 1u64 << bit;
            let leading = 63 - bit;
            assert_eq!(lzcnt_nz(word), leading);
            assert_eq!(lzcnt_nz_portable(word), leading);
            assert_eq!(norm64(word, 0), (1u64 << 63, -leading.cast_signed()));
        }
        for word in [0, 1, 0xFEDC_BA98_7654_3210, 1u64 << 63, u64::MAX] {
            for shift in 0..64 {
                assert_eq!(ursh(word, shift), word >> shift);
                assert_eq!(ursh_portable(word, shift), word >> shift);
                assert_eq!(ulsh(word, shift), word << shift);
                assert_eq!(ulsh_portable(word, shift), word << shift);
                assert_eq!(irsh(word.cast_signed(), shift), word.cast_signed() >> shift);
                assert_eq!(
                    irsh_portable(word.cast_signed(), shift),
                    word.cast_signed() >> shift
                );
            }
        }
    }

    #[test]
    fn integer_construction_and_rounding_preserve_ties_and_signed_zero_contracts() {
        const NEGATIVE_THREE_HALVES: Flr = Flr::scaled(-3, -1);
        const TIE_TO_EVEN: Flr = Flr::from_i64((1i64 << 53) + 1);
        const RAW_ONE: Flr = Flr::from_bits(0x3FF0_0000_0000_0000);
        assert_eq!(NEGATIVE_THREE_HALVES.0, (-1.5f64).to_bits());
        assert_eq!(TIE_TO_EVEN.0, 0x4340_0000_0000_0000);
        assert_eq!(RAW_ONE.0, Flr::ONE.0);
        assert_eq!(Flr::from_i64(i64::MAX).0, 0x43E0_0000_0000_0000);
        assert_eq!(Flr::from_i64(-i64::MAX).0, 0xC3E0_0000_0000_0000);
        for integer in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(Flr::from_i32(integer).0, f64::from(integer).to_bits());
            assert_eq!(Flr::from_i32(integer).rint(), i64::from(integer));
        }
        // floor(-0) deliberately returns -1 in this internal backend. Division
        // and sqrt have their own zero-sign rules, covered below.
        for (value, nearest, floor, truncated) in [
            (-2.5f64, -2, -3, -2),
            (-1.5, -2, -2, -1),
            (-0.5, 0, -1, 0),
            (-0.0, 0, -1, 0),
            (0.0, 0, 0, 0),
            (0.5, 0, 0, 0),
            (1.5, 2, 1, 1),
            (2.5, 2, 2, 2),
        ] {
            let value = Flr::from_bits(value.to_bits());
            assert_eq!(value.rint(), nearest);
            assert_eq!(value.floor(), floor);
            assert_eq!(value.trunc(), truncated);
        }
        assert_eq!(Flr::from_bits(0x3FDF_FFFF_FFFF_FFFF).rint(), 0);
        assert_eq!(Flr::from_bits(0x3FE0_0000_0000_0001).rint(), 1);
        assert_eq!(Flr::from_bits(0xBFDF_FFFF_FFFF_FFFF).rint(), 0);
        assert_eq!(Flr::from_bits(0xBFE0_0000_0000_0001).rint(), -1);
    }

    #[test]
    fn arithmetic_matches_binary64_rounding_on_supported_finite_values() {
        // Inputs and all nonzero outputs remain normal and inside Falcon's
        // documented magnitude bounds. No subnormal, NaN or infinity is used.
        let values = [
            0.0f64,
            -0.0,
            0.5,
            -0.5,
            1.0,
            -1.0,
            1.5,
            -1.5,
            f64::from_bits(0x3FEF_FFFF_FFFF_FFFF),
            f64::from_bits(0x3FF0_0000_0000_0001),
            f64::from_bits(0x3DF0_0000_0000_0000),
            f64::from_bits(0x4190_0000_0000_0000),
        ];
        for left in values {
            let encoded_left = Flr::from_bits(left.to_bits());
            assert_eq!((-encoded_left).0, (-left).to_bits());
            assert_eq!(encoded_left.square().0, (left * left).to_bits());
            for right in values {
                let encoded_right = Flr::from_bits(right.to_bits());
                assert_eq!((encoded_left + encoded_right).0, (left + right).to_bits());
                assert_eq!((encoded_left - encoded_right).0, (left - right).to_bits());
                assert_eq!((encoded_left * encoded_right).0, (left * right).to_bits());
                if right.to_bits() & M63 != 0 {
                    // set_div intentionally clears the sign of a zero numerator.
                    let expected = if left.to_bits() & M63 == 0 {
                        0
                    } else {
                        (left / right).to_bits()
                    };
                    assert_eq!((encoded_left / encoded_right).0, expected);
                }
            }
        }
        let smallest = Flr::scaled(1, -476);
        assert_eq!((smallest + smallest).0, Flr::scaled(1, -475).0);
        assert_eq!((smallest * Flr::ONE).0, smallest.0);
        assert_eq!((smallest / Flr::ONE).0, smallest.0);
    }

    #[test]
    fn exponent_scaling_and_square_root_preserve_exact_bits() {
        let values = [
            0.0f64,
            -0.0,
            0.5,
            -0.5,
            1.0,
            -1.0,
            1.5,
            -1.5,
            f64::from_bits(0x3FF0_0000_0000_0001),
        ];
        for value in values {
            let encoded = Flr::from_bits(value.to_bits());
            assert_eq!(encoded.half().0, (value * 0.5).to_bits());
            assert_eq!(
                encoded.mul2p63().0,
                (value * f64::from_bits(0x43E0_0000_0000_0000)).to_bits()
            );
        }
        for exponent in 1..=9 {
            let mut encoded = values.map(|value| Flr::from_bits(value.to_bits()));
            Flr::slice_div2e(&mut encoded, exponent);
            let divisor = f64::from(1u32 << exponent);
            for (actual, value) in encoded.into_iter().zip(values) {
                assert_eq!(actual.0, (value / divisor).to_bits());
            }
        }
        for value in [
            0.0f64,
            0.5,
            1.0,
            2.0,
            3.0,
            4.0,
            f64::from_bits(0x2230_0000_0000_0000),
        ] {
            assert_eq!(
                Flr::from_bits(value.to_bits()).sqrt().0,
                value.sqrt().to_bits()
            );
        }
        // The emulated square root intentionally maps both zero signs to +0.
        assert_eq!(Flr::from_bits((-0.0f64).to_bits()).sqrt().0, 0);
    }

    #[test]
    fn exponential_limb_products_match_independent_wide_integer_oracle() {
        // These exact Q64 pairs do not use the conversion under test. The unit
        // scale endpoint has a separate correctness review; this parity control
        // covers the existing represented interval below one, including its
        // immediately adjacent binary64 value.
        for (value, multiplier) in [
            (0.0f64, 0u64),
            (0.125, 1u64 << 61),
            (0.25, 1u64 << 62),
            (0.5, 1u64 << 63),
        ] {
            let mut expected = Flr::EXPM_COEFFS[0];
            for coefficient in &Flr::EXPM_COEFFS[1..] {
                let high_product =
                    u64::try_from((u128::from(multiplier) * u128::from(expected)) >> 64).unwrap();
                expected = coefficient.wrapping_sub(high_product);
            }
            for (factor, factor_q64) in [
                (0.0f64, 0u64),
                (0.125, 1u64 << 61),
                (0.5, 1u64 << 63),
                (0.75, 3u64 << 62),
                (f64::from_bits(0x3FEF_FFFF_FFFF_FFFF), u64::MAX - 2047),
            ] {
                let scaled =
                    u64::try_from((u128::from(factor_q64) * u128::from(expected)) >> 64).unwrap();
                assert_eq!(
                    Flr::from_bits(value.to_bits()).expm_p63(Flr::from_bits(factor.to_bits())),
                    scaled
                );
            }
        }
    }
    #[test]
    fn exponential_unit_scale_returns_full_zero_residual_probability() {
        assert_eq!(Flr::ZERO.expm_p63(Flr::ONE), 1u64 << 63);
        assert_eq!(Flr::from_bits(1u64 << 63).expm_p63(Flr::ONE), 1u64 << 63);
    }

    #[test]
    fn exponential_unit_scale_retains_nonzero_residual_polynomial() {
        // At self=1/2, its exact Q64 value is 2^63. Wide integer products
        // independently evaluate the fixed polynomial, without Flr conversion
        // or the production 32-bit-limb multiplication.
        let mut expected = Flr::EXPM_COEFFS[0];
        for coefficient in &Flr::EXPM_COEFFS[1..] {
            let high_product = u64::try_from(((1u128 << 63) * u128::from(expected)) >> 64).unwrap();
            expected = coefficient.wrapping_sub(high_product);
        }
        assert!(expected > (1u64 << 62));
        assert!(expected < (1u64 << 63));
        let actual = Flr::scaled(1, -1).expm_p63(Flr::ONE);
        assert_eq!(actual, expected);
        // This is the exact sampler threshold transformation at residual 1/2.
        assert_eq!((actual << 1).wrapping_sub(1), (expected << 1) - 1);
        assert!((actual << 1).wrapping_sub(1) < u64::MAX);
    }

    #[test]
    fn exponential_nonunit_scales_preserve_tiny_odd_units_and_zero_signs() {
        for zero in [Flr::ZERO, Flr::from_bits(1u64 << 63)] {
            assert_eq!(Flr::scaled(1, -1).expm_p63(zero), 0);
        }
        for units in [1i64, 2, 3, 5, 7, (1i64 << 53) - 1] {
            let factor = Flr::scaled(units, -63);
            assert_eq!(Flr::ZERO.expm_p63(factor), u64::try_from(units).unwrap());
            let mut polynomial = Flr::EXPM_COEFFS[0];
            for coefficient in &Flr::EXPM_COEFFS[1..] {
                polynomial = coefficient.wrapping_sub(polynomial >> 1);
            }
            let expected =
                u64::try_from((u128::try_from(units).unwrap() * u128::from(polynomial)) >> 63)
                    .unwrap();
            assert_eq!(Flr::scaled(1, -1).expm_p63(factor), expected);
        }
        assert_eq!(Flr::ZERO.expm_p63(Flr::scaled(1, -64)), 0);
        assert_eq!(Flr::ZERO.expm_p63(Flr::scaled(1, -476)), 0);
    }
}
