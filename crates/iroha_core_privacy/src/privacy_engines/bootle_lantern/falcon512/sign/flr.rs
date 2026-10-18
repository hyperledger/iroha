#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::DefaultIsZeroes;
// ========================================================================
// Floating-point operations
// ========================================================================
// The Flr type represents an IEEE-754:2008 'binary64' value, or more
// specifically a subset of such values.
//
//    A value is conceptually the packing of three binary field in a
//    64-bit word, equal to:
//        s*2^64 + e*2^52 + m
//    with:
//      field  size  meaning
//        s      1   sign bit (0 = positive, 1 = negative)
//        e     11   encoded exponent
//        m     52   encoded mantissa
//    If e = 0 then the value is either a zero or a denormal. If e = 2047
//    then the value is either an infinite or a NaN (not-a-number). In all
//    other cases (1 <= e <= 2046), the represented real number is equal to:
//        (-1)^s * 2^(e - 1023) * (1 + m/2^52)
//
//    In FN-DSA, denormals, infinites and NaNs are not used, and need not
//    be supported. It has been demonstrated that all non-zero values
//    are in [2^(−476), 2^27*(2^52 + 605182448294568)] (in absolute value),
//    thus the exponent field e is always in the [547, 1102] range, except
//    for zero. See: https://eprint.iacr.org/2024/321
//
//    There are nominally two zeros, a positive zero and a negative
//    zero, depending on the sign bit.
//
//    Flr values are meant for in-memory use only; the packing into a
//    64-bit word and then conversion to bytes is meant only for test
//    purposes. Nevertheless, each Flr instance should strive to use
//    relatively little RAM, for better performance.
//
//    All implemented operations should follow the strict IEEE-754 rules,
//    with rounding policy roundTiesToEven:
//      - The operation is (conceptually) computed with infinite precision.
//      - The result is rounded to the nearest representable value.
//      - If the result is not representable exactly, and the two nearest
//        representable values are equidistant from the result, then the
//        "even" representable value (the one for which the m field is an
//        even integer) is used.
//    These rules leave no room for ambiguousness, i.e. for every operation
//    there is a single correctly rounded output. Note also that rounding
//    of the absolute value yields the same result as taking the absolute
//    value of the rounding, i.e. we can round mantissas independently of
//    the sign bit.
//
//    The rounding rules imply that additions and multiplications are
//    not associative. The order of operations thus matters for full
//    reproducibility, and should not be changed. Similarly, if
//    computations are internally performed with a higher precision,
//    rounding should still be enforced after each operation; a
//    fused-multiply-add operation, if supported by a hardware platform,
//    shall not be used. Moreover, operations are over secret values and
//    thus should take care not to leak information through
//    side-channels, in particular timing.
#[path = "flr_emu.rs"]
mod backend;
pub use backend::Flr;
impl Default for Flr {
    fn default() -> Self {
        Flr::ZERO
    }
}
impl DefaultIsZeroes for Flr {}
impl Add<Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn add(self, other: Flr) -> Flr {
        let mut r = self;
        r.set_add(other);
        r
    }
}
impl Add<&Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn add(self, other: &Flr) -> Flr {
        let mut r = self;
        r.set_add(*other);
        r
    }
}
impl Add<Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn add(self, other: Flr) -> Flr {
        let mut r = *self;
        r.set_add(other);
        r
    }
}
impl Add<&Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn add(self, other: &Flr) -> Flr {
        let mut r = *self;
        r.set_add(*other);
        r
    }
}
impl AddAssign<Flr> for Flr {
    #[inline]
    fn add_assign(&mut self, other: Flr) {
        self.set_add(other);
    }
}
impl AddAssign<&Flr> for Flr {
    #[inline]
    fn add_assign(&mut self, other: &Flr) {
        self.set_add(*other);
    }
}
impl Div<Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn div(self, other: Flr) -> Flr {
        let mut r = self;
        r.set_div(other);
        r
    }
}
impl Div<&Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn div(self, other: &Flr) -> Flr {
        let mut r = self;
        r.set_div(*other);
        r
    }
}
impl Div<Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn div(self, other: Flr) -> Flr {
        let mut r = *self;
        r.set_div(other);
        r
    }
}
impl Div<&Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn div(self, other: &Flr) -> Flr {
        let mut r = *self;
        r.set_div(*other);
        r
    }
}
impl DivAssign<Flr> for Flr {
    #[inline]
    fn div_assign(&mut self, other: Flr) {
        self.set_div(other);
    }
}
impl DivAssign<&Flr> for Flr {
    #[inline]
    fn div_assign(&mut self, other: &Flr) {
        self.set_div(*other);
    }
}
impl Mul<Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn mul(self, other: Flr) -> Flr {
        let mut r = self;
        r.set_mul(other);
        r
    }
}
impl Mul<&Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn mul(self, other: &Flr) -> Flr {
        let mut r = self;
        r.set_mul(*other);
        r
    }
}
impl Mul<Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn mul(self, other: Flr) -> Flr {
        let mut r = *self;
        r.set_mul(other);
        r
    }
}
impl Mul<&Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn mul(self, other: &Flr) -> Flr {
        let mut r = *self;
        r.set_mul(*other);
        r
    }
}
impl MulAssign<Flr> for Flr {
    #[inline]
    fn mul_assign(&mut self, other: Flr) {
        self.set_mul(other);
    }
}
impl MulAssign<&Flr> for Flr {
    #[inline]
    fn mul_assign(&mut self, other: &Flr) {
        self.set_mul(*other);
    }
}
impl Neg for Flr {
    type Output = Flr;
    #[inline]
    fn neg(self) -> Flr {
        let mut r = self;
        r.set_neg();
        r
    }
}
impl Neg for &Flr {
    type Output = Flr;
    #[inline]
    fn neg(self) -> Flr {
        let mut r = *self;
        r.set_neg();
        r
    }
}
impl Sub<Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn sub(self, other: Flr) -> Flr {
        let mut r = self;
        r.set_sub(other);
        r
    }
}
impl Sub<&Flr> for Flr {
    type Output = Flr;
    #[inline]
    fn sub(self, other: &Flr) -> Flr {
        let mut r = self;
        r.set_sub(*other);
        r
    }
}
impl Sub<Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn sub(self, other: Flr) -> Flr {
        let mut r = *self;
        r.set_sub(other);
        r
    }
}
impl Sub<&Flr> for &Flr {
    type Output = Flr;
    #[inline]
    fn sub(self, other: &Flr) -> Flr {
        let mut r = *self;
        r.set_sub(*other);
        r
    }
}
impl SubAssign<Flr> for Flr {
    #[inline]
    fn sub_assign(&mut self, other: Flr) {
        self.set_sub(other);
    }
}
impl SubAssign<&Flr> for Flr {
    #[inline]
    fn sub_assign(&mut self, other: &Flr) {
        self.set_sub(*other);
    }
}
