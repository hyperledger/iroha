//! The Pallas and Vesta curves.
//!
//! Both curves are `y^2 = x^3 + 5` over the Pasta fields and have prime order:
//!
//! - Pallas (`Ep`, `EpAffine`) is defined over `Fp` and has order `q`, so its
//!   scalars are `Fq`;
//! - Vesta (`Eq`, `EqAffine`) is defined over `Fq` and has order `p`, so its
//!   scalars are `Fp`.
//!
//! # Representation
//!
//! Projective points use homogeneous coordinates `(X : Y : Z)` with
//! `x = X / Z`, `y = Y / Z`; the identity is `(0 : 1 : 0)`. Group operations
//! use the complete formulas of Renes, Costello and Batina (IACR ePrint
//! 2015/1060, algorithms 7, 8 and 9 for `a = 0`): they are correct for every
//! input pair, including the identity, equal points and opposite points, and
//! they have no branches. Kernels that need more speed (MSM buckets, folding,
//! parameter generation) use batch-affine arithmetic and handle the exceptional
//! cases explicitly; see [`crate::msm`] and [`crate::fold`].
//!
//! Affine points store `(x, y)`; the identity is stored as `(0, 0)`, which is
//! not on the curve (`0 != 5`), exactly as in `pasta_curves`.
//!
//! # Encoding
//!
//! The compressed encoding is the 32-byte little-endian `x` with the parity of
//! `y` in bit 255; the identity encodes as 32 zero bytes. It is byte-identical
//! to `pasta_curves` 0.5.2. Decoding rejects non-canonical `x`, `x` values
//! without a curve point, and the all-zero `x` with the sign bit set (unless it
//! decodes to a point).
//!
//! # Timing posture
//!
//! Addition, doubling, negation, selection, equality and scalar multiplication
//! through `*` are constant time. `mul_vartime`, point decompression (table
//! square roots) and the hash-to-curve map are for public inputs only.

mod batch;
pub(crate) mod endo;
pub mod hash_to_curve;
pub mod pallas;
pub mod vesta;

pub(crate) use batch::normalize_vartime_into;
pub use batch::{batch_mul_vartime, batch_normalize, batch_normalize_vartime};
pub use endo::GlvDecomposition;
pub use hash_to_curve::HashToCurveError;
pub use pallas::{Ep, EpAffine};
pub use vesta::{Eq, EqAffine};

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use group::prime::{PrimeCurve, PrimeCurveAffine};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::{field::PastaField, poseidon::PoseidonField};

mod sealed {
    /// Seals the curve traits to Pallas and Vesta.
    pub trait Sealed {}
    impl Sealed for super::Ep {}
    impl Sealed for super::Eq {}
    impl Sealed for super::EpAffine {}
    impl Sealed for super::EqAffine {}

    /// Capability token of the unchecked affine constructor.
    ///
    /// The type is unnameable outside the crate and its field is private, so
    /// safe code outside `iroha_pasta` cannot produce a value and call
    /// `PastaAffine::from_xy_unchecked`.
    #[derive(Clone, Copy, Debug)]
    pub struct Internal(());

    /// The only value of [`Internal`].
    pub(super) const INTERNAL: Internal = Internal(());
}

/// Builds an affine point from coordinates without checking the curve
/// equation.
///
/// Crate-internal: kernels only pass coordinates they computed with the group
/// law from on-curve inputs. Public callers use [`PastaAffine::from_xy`].
#[inline]
pub(crate) fn affine_unchecked<A: PastaAffine>(x: A::Base, y: A::Base) -> A {
    A::from_xy_unchecked(x, y, sealed::INTERNAL)
}

/// A Pasta curve point in projective form (Pallas [`Ep`] or Vesta [`Eq`](struct@Eq)).
///
/// Sealed. Generic prover kernels take this bound.
pub trait PastaCurve:
    sealed::Sealed
    + PrimeCurve<Affine = <Self as PastaCurve>::AffineExt>
    + group::Group<Scalar = <Self as PastaCurve>::ScalarExt>
    + group::GroupEncoding<Repr = [u8; 32]>
    + Default
    + ConditionallySelectable
    + ConstantTimeEq
    + From<<Self as PastaCurve>::AffineExt>
    + Debug
    + zeroize::Zeroize
{
    /// The base field, with its pinned RP57 Poseidon parameters.
    type Base: PastaField + PoseidonField;
    /// The scalar field (the group order), with pinned RP57 parameters.
    type ScalarExt: PastaField + PoseidonField;
    /// The affine form.
    type AffineExt: PastaAffine<
            CurveExt = Self,
            Base = <Self as PastaCurve>::Base,
            ScalarExt = <Self as PastaCurve>::ScalarExt,
        >;

    /// Curve identifier used by hash-to-curve (`"pallas"` or `"vesta"`).
    const CURVE_ID: &'static str;

    /// Applies the endomorphism `(x, y) -> (beta * x, y)`, which equals
    /// multiplication by `ScalarExt::ZETA`.
    #[must_use]
    fn endo(&self) -> Self;

    /// Hashes `message` to a curve point under `domain_prefix`, exactly as
    /// `pasta_curves::arithmetic::CurveExt::hash_to_curve` does.
    ///
    /// The map is a random oracle into the group (simplified SWU onto an
    /// isogenous curve, then a 3-isogeny). It is for public inputs only: the
    /// square root uses value-indexed table lookups.
    ///
    /// # Errors
    ///
    /// [`HashToCurveError::DomainTooLong`] when the domain separation tag
    /// would exceed 255 bytes; [`HashToCurveError::OffCurve`] if the result
    /// failed the curve check (an internal error; the map fails closed).
    fn hash_to_curve(domain_prefix: &str, message: &[u8]) -> Result<Self, HashToCurveError>;

    /// Returns the homogeneous projective coordinates `(X, Y, Z)`.
    fn projective_coordinates(&self) -> (Self::Base, Self::Base, Self::Base);

    /// Builds a point from homogeneous projective coordinates, checking that it
    /// is on the curve (`Z = 0` requires `X = 0` and `Y != 0`).
    fn from_projective_coordinates(x: Self::Base, y: Self::Base, z: Self::Base) -> CtOption<Self>;

    /// Variable-time scalar multiplication (GLV with wNAF) for public scalars.
    #[must_use]
    fn mul_vartime(&self, scalar: &Self::ScalarExt) -> Self;

    /// Splits `k = s1 * k1 + s2 * k2 * ZETA` with `|k1|, |k2| < 2^128` for the
    /// GLV method (variable time; public scalars).
    ///
    /// Returns `None` only if the lattice bound were violated, which the
    /// Pasta constants exclude; callers keep a non-GLV fallback regardless.
    fn glv_decompose(k: &Self::ScalarExt) -> Option<GlvDecomposition>;

    /// Returns true when the point satisfies the curve equation.
    fn is_on_curve(&self) -> Choice;

    /// The curve constant `b = 5`.
    fn b() -> Self::Base;
}

/// A Pasta curve point in affine form ([`EpAffine`] or [`EqAffine`]).
///
/// Sealed. The identity is represented as `(0, 0)`.
pub trait PastaAffine:
    sealed::Sealed
    + PrimeCurveAffine<
        Scalar = <Self as PastaAffine>::ScalarExt,
        Curve = <Self as PastaAffine>::CurveExt,
    > + group::GroupEncoding<Repr = [u8; 32]>
    + Default
    + ConditionallySelectable
    + ConstantTimeEq
    + zeroize::Zeroize
    + From<<Self as PastaAffine>::CurveExt>
    + Add<Output = <Self as PastaAffine>::CurveExt>
    + Sub<Output = <Self as PastaAffine>::CurveExt>
    + Neg<Output = Self>
    + Mul<<Self as PastaAffine>::ScalarExt, Output = <Self as PastaAffine>::CurveExt>
{
    /// The base field.
    type Base: PastaField + PoseidonField;
    /// The scalar field.
    type ScalarExt: PastaField + PoseidonField;
    /// The projective form.
    type CurveExt: PastaCurve<
            AffineExt = Self,
            Base = <Self as PastaAffine>::Base,
            ScalarExt = <Self as PastaAffine>::ScalarExt,
        >;

    /// Returns `(x, y)`, or nothing for the identity.
    fn coordinates(&self) -> CtOption<(Self::Base, Self::Base)>;

    /// The stored `x` coordinate (zero for the identity).
    fn x(&self) -> Self::Base;

    /// The stored `y` coordinate (zero for the identity).
    fn y(&self) -> Self::Base;

    /// Builds a point from affine coordinates, failing if it is not on the
    /// curve. `(0, 0)` yields the identity.
    fn from_xy(x: Self::Base, y: Self::Base) -> CtOption<Self>;

    /// Returns true when the point is on the curve or is the identity.
    fn is_on_curve(&self) -> Choice;

    /// Builds a point without checking the curve equation.
    ///
    /// Crate-internal: safe code can only produce the token argument inside
    /// `iroha_pasta`, so code outside the crate cannot build off-curve points
    /// (the batch-affine kernels never re-check curve membership). Use
    /// [`PastaAffine::from_xy`].
    #[doc(hidden)]
    fn from_xy_unchecked(x: Self::Base, y: Self::Base, token: sealed::Internal) -> Self;

    /// The base-field cube root of unity `beta` with
    /// `(beta * x, y) = [ScalarExt::ZETA] (x, y)` (a public curve constant).
    fn endo_beta() -> Self::Base;
}

/// Implements the projective and affine types of one Pasta curve.
///
/// Expects in scope: the base field `$base`, the scalar field `$scalar`, and
/// the constants `CURVE_ID` and `ENDO_BETA_RAW`.
macro_rules! impl_pasta_curve {
    ($name:ident, $affine:ident, $base:ident, $scalar:ident) => {
        use core::fmt;
        use core::iter::Sum;
        use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

        use ff::{Field, PrimeField};
        use group::cofactor::{CofactorCurve, CofactorGroup};
        use group::prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup};
        use group::{Curve as _, Group, GroupEncoding};
        use rand_core_06::RngCore;
        use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

        use crate::curve::{HashToCurveError, PastaAffine, PastaCurve};

        /// Projective point in homogeneous coordinates `(X : Y : Z)`.
        #[derive(Clone, Copy)]
        pub struct $name {
            pub(crate) x: $base,
            pub(crate) y: $base,
            pub(crate) z: $base,
        }

        /// Affine point `(x, y)`; the identity is `(0, 0)`.
        #[derive(Clone, Copy)]
        pub struct $affine {
            pub(crate) x: $base,
            pub(crate) y: $base,
        }

        /// The curve constant `b = 5`.
        const B: $base = $base::from_raw([5, 0, 0, 0]);

        /// The base-field cube root of unity for the endomorphism.
        const ENDO_BETA: $base = $base::from_raw(ENDO_BETA_RAW);

        /// `3 * b = 15` times `v`, by additions.
        #[inline(always)]
        fn mul_by_3b(v: &$base) -> $base {
            let v2 = v.double();
            let v4 = v2.double();
            let v8 = v4.double();
            let v16 = v8.double();
            v16.sub(v)
        }

        impl $name {
            /// The identity `(0 : 1 : 0)`.
            pub const fn identity_const() -> Self {
                Self {
                    x: $base::zero(),
                    y: $base::one(),
                    z: $base::zero(),
                }
            }

            /// Complete doubling (RCB16 algorithm 9, `a = 0`).
            #[inline]
            #[must_use]
            pub fn double_complete(&self) -> Self {
                let t0 = self.y.square();
                let z3 = t0.double();
                let z3 = z3.double();
                let z3 = z3.double();
                let t1 = self.y.mul(&self.z);
                let t2 = self.z.square();
                let t2 = mul_by_3b(&t2);
                let x3 = t2.mul(&z3);
                let y3 = t0.add(&t2);
                let z3 = t1.mul(&z3);
                let t1 = t2.double();
                let t2 = t1.add(&t2);
                let t0 = t0.sub(&t2);
                let y3 = t0.mul(&y3);
                let y3 = x3.add(&y3);
                let t1 = self.x.mul(&self.y);
                let x3 = t0.mul(&t1);
                let x3 = x3.double();
                Self {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            }

            /// Complete addition (RCB16 algorithm 7, `a = 0`).
            #[inline]
            #[must_use]
            pub fn add_complete(&self, rhs: &Self) -> Self {
                let t0 = self.x.mul(&rhs.x);
                let t1 = self.y.mul(&rhs.y);
                let t2 = self.z.mul(&rhs.z);
                let t3 = self.x.add(&self.y);
                let t4 = rhs.x.add(&rhs.y);
                let t3 = t3.mul(&t4);
                let t4 = t0.add(&t1);
                let t3 = t3.sub(&t4);
                let t4 = self.y.add(&self.z);
                let x3 = rhs.y.add(&rhs.z);
                let t4 = t4.mul(&x3);
                let x3 = t1.add(&t2);
                let t4 = t4.sub(&x3);
                let x3 = self.x.add(&self.z);
                let y3 = rhs.x.add(&rhs.z);
                let x3 = x3.mul(&y3);
                let y3 = t0.add(&t2);
                let y3 = x3.sub(&y3);
                let x3 = t0.double();
                let t0 = x3.add(&t0);
                let t2 = mul_by_3b(&t2);
                let z3 = t1.add(&t2);
                let t1 = t1.sub(&t2);
                let y3 = mul_by_3b(&y3);
                let x3 = t4.mul(&y3);
                let t2 = t3.mul(&t1);
                let x3 = t2.sub(&x3);
                let y3 = y3.mul(&t0);
                let t1 = t1.mul(&z3);
                let y3 = t1.add(&y3);
                let t0 = t0.mul(&t3);
                let z3 = z3.mul(&t4);
                let z3 = z3.add(&t0);
                Self {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            }

            /// Complete mixed addition (RCB16 algorithm 8, `a = 0`).
            ///
            /// The affine identity `(0, 0)` is handled by a constant-time
            /// selection, since the formula assumes `Z2 = 1`.
            #[inline]
            #[must_use]
            pub fn add_mixed(&self, rhs: &$affine) -> Self {
                let t0 = self.x.mul(&rhs.x);
                let t1 = self.y.mul(&rhs.y);
                let t3 = rhs.x.add(&rhs.y);
                let t4 = self.x.add(&self.y);
                let t3 = t3.mul(&t4);
                let t4 = t0.add(&t1);
                let t3 = t3.sub(&t4);
                let t4 = rhs.y.mul(&self.z);
                let t4 = t4.add(&self.y);
                let y3 = rhs.x.mul(&self.z);
                let y3 = y3.add(&self.x);
                let x3 = t0.double();
                let t0 = x3.add(&t0);
                let t2 = mul_by_3b(&self.z);
                let z3 = t1.add(&t2);
                let t1 = t1.sub(&t2);
                let y3 = mul_by_3b(&y3);
                let x3 = t4.mul(&y3);
                let t2 = t3.mul(&t1);
                let x3 = t2.sub(&x3);
                let y3 = y3.mul(&t0);
                let t1 = t1.mul(&z3);
                let y3 = t1.add(&y3);
                let t0 = t0.mul(&t3);
                let z3 = z3.mul(&t4);
                let z3 = z3.add(&t0);
                let sum = Self {
                    x: x3,
                    y: y3,
                    z: z3,
                };
                Self::conditional_select(&sum, self, rhs.is_identity())
            }

            /// Constant-time scalar multiplication with a 4-bit fixed window.
            fn mul_ct(&self, scalar: &$scalar) -> Self {
                let mut table = [Self::identity_const(); 16];
                for i in 1..16 {
                    table[i] = table[i - 1].add_complete(self);
                }
                let mut repr = scalar.to_repr();
                let mut acc = Self::identity_const();
                for byte_index in (0..32).rev() {
                    let byte = repr[byte_index];
                    for nibble in [byte >> 4, byte & 0x0F] {
                        acc = acc.double_complete();
                        acc = acc.double_complete();
                        acc = acc.double_complete();
                        acc = acc.double_complete();
                        let mut entry = Self::identity_const();
                        for (i, candidate) in (0u8..).zip(table.iter()) {
                            entry.conditional_assign(candidate, i.ct_eq(&nibble));
                        }
                        acc = acc.add_complete(&entry);
                    }
                }
                zeroize::Zeroize::zeroize(&mut repr);
                acc
            }

            /// Returns true when the point satisfies `Y^2 Z = X^3 + b Z^3`.
            fn is_on_curve_projective(&self) -> Choice {
                let lhs = self.y.square().mul(&self.z);
                let rhs = self
                    .x
                    .square()
                    .mul(&self.x)
                    .add(&B.mul(&self.z.square().mul(&self.z)));
                let identity_ok = self.x.is_zero() & !self.y.is_zero();
                (lhs.ct_eq(&rhs) & !self.z.is_zero()) | (self.z.is_zero() & identity_ok)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.to_affine(), f)
            }
        }

        impl fmt::Debug for $affine {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if bool::from(self.is_identity()) {
                    write!(f, "Infinity")
                } else {
                    write!(f, "({:?}, {:?})", self.x, self.y)
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::identity_const()
            }
        }

        impl Default for $affine {
            fn default() -> Self {
                Self {
                    x: $base::zero(),
                    y: $base::zero(),
                }
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                // (X1 : Y1 : Z1) = (X2 : Y2 : Z2) iff X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1;
                // the identity (0 : Y : 0) only matches itself under these tests.
                let x1 = self.x.mul(&other.z);
                let x2 = other.x.mul(&self.z);
                let y1 = self.y.mul(&other.z);
                let y2 = other.y.mul(&self.z);
                let both_identity = self.z.is_zero() & other.z.is_zero();
                both_identity
                    | (x1.ct_eq(&x2) & y1.ct_eq(&y2) & !(self.z.is_zero() ^ other.z.is_zero()))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl core::cmp::Eq for $name {}

        impl ConstantTimeEq for $affine {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
            }
        }

        impl PartialEq for $affine {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl core::cmp::Eq for $affine {}

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self {
                    x: $base::conditional_select(&a.x, &b.x, choice),
                    y: $base::conditional_select(&a.y, &b.y, choice),
                    z: $base::conditional_select(&a.z, &b.z, choice),
                }
            }
        }

        impl ConditionallySelectable for $affine {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self {
                    x: $base::conditional_select(&a.x, &b.x, choice),
                    y: $base::conditional_select(&a.y, &b.y, choice),
                }
            }
        }

        impl zeroize::DefaultIsZeroes for $name {}
        impl zeroize::DefaultIsZeroes for $affine {}

        impl Neg for $name {
            type Output = $name;
            fn neg(self) -> $name {
                $name {
                    x: self.x,
                    y: self.y.neg(),
                    z: self.z,
                }
            }
        }

        impl Neg for &$name {
            type Output = $name;
            fn neg(self) -> $name {
                -*self
            }
        }

        impl Neg for $affine {
            type Output = $affine;
            fn neg(self) -> $affine {
                $affine {
                    x: self.x,
                    y: self.y.neg(),
                }
            }
        }

        impl Neg for &$affine {
            type Output = $affine;
            fn neg(self) -> $affine {
                -*self
            }
        }

        crate::curve::impl_curve_binop!($name, $name, $name, Add, add, |a: &$name, b: &$name| a
            .add_complete(b));
        crate::curve::impl_curve_binop!($name, $name, $name, Sub, sub, |a: &$name, b: &$name| a
            .add_complete(&-b));
        crate::curve::impl_curve_binop!(
            $name,
            $affine,
            $name,
            Add,
            add,
            |a: &$name, b: &$affine| a.add_mixed(b)
        );
        crate::curve::impl_curve_binop!(
            $name,
            $affine,
            $name,
            Sub,
            sub,
            |a: &$name, b: &$affine| a.add_mixed(&-b)
        );
        crate::curve::impl_curve_binop!(
            $affine,
            $affine,
            $name,
            Add,
            add,
            |a: &$affine, b: &$affine| a.to_curve().add_mixed(b)
        );
        crate::curve::impl_curve_binop!(
            $affine,
            $affine,
            $name,
            Sub,
            sub,
            |a: &$affine, b: &$affine| a.to_curve().add_mixed(&-b)
        );
        crate::curve::impl_curve_binop!(
            $affine,
            $name,
            $name,
            Add,
            add,
            |a: &$affine, b: &$name| b.add_mixed(a)
        );
        crate::curve::impl_curve_binop!(
            $affine,
            $name,
            $name,
            Sub,
            sub,
            |a: &$affine, b: &$name| (-b).add_mixed(a)
        );
        crate::curve::impl_curve_binop!(
            $name,
            $scalar,
            $name,
            Mul,
            mul,
            |a: &$name, b: &$scalar| a.mul_ct(b)
        );
        crate::curve::impl_curve_binop!(
            $affine,
            $scalar,
            $name,
            Mul,
            mul,
            |a: &$affine, b: &$scalar| a.to_curve().mul_ct(b)
        );
        crate::curve::impl_curve_assign!($name, $name, AddAssign, add_assign, Add, add);
        crate::curve::impl_curve_assign!($name, $name, SubAssign, sub_assign, Sub, sub);
        crate::curve::impl_curve_assign!($name, $affine, AddAssign, add_assign, Add, add);
        crate::curve::impl_curve_assign!($name, $affine, SubAssign, sub_assign, Sub, sub);
        crate::curve::impl_curve_assign!($name, $scalar, MulAssign, mul_assign, Mul, mul);

        impl<T: core::borrow::Borrow<$name>> Sum<T> for $name {
            fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
                iter.fold(Self::identity_const(), |acc, item| {
                    acc.add_complete(item.borrow())
                })
            }
        }

        impl Group for $name {
            type Scalar = $scalar;

            /// Samples a uniformly random point, consuming the RNG exactly as
            /// `pasta_curves` does (a random `x`, then one `u32` for the sign).
            fn random(mut rng: impl RngCore) -> Self {
                loop {
                    let x = $base::random(&mut rng);
                    let ysign = (rng.next_u32() % 2) as u8;
                    let x3 = x.square().mul(&x);
                    let y = (x3.add(&B)).sqrt();
                    if let Some(y) = Option::<$base>::from(y) {
                        let sign = y.is_odd().unwrap_u8();
                        let y = if ysign ^ sign == 0 { y } else { y.neg() };
                        break $affine { x, y }.to_curve();
                    }
                }
            }

            fn identity() -> Self {
                Self::identity_const()
            }

            fn generator() -> Self {
                <$affine as PrimeCurveAffine>::generator().to_curve()
            }

            fn is_identity(&self) -> Choice {
                self.z.is_zero()
            }

            fn double(&self) -> Self {
                self.double_complete()
            }
        }

        impl group::WnafGroup for $name {
            fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
                const RECOMMENDATIONS: [usize; 12] =
                    [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];
                let mut ret = 4;
                for r in &RECOMMENDATIONS {
                    if num_scalars > *r {
                        ret += 1;
                    } else {
                        break;
                    }
                }
                ret
            }
        }

        impl group::Curve for $name {
            type AffineRepr = $affine;

            fn batch_normalize(p: &[Self], q: &mut [Self::AffineRepr]) {
                crate::curve::batch::normalize_into(p, q);
            }

            fn to_affine(&self) -> $affine {
                let zinv = self.z.invert().unwrap_or($base::zero());
                let p = $affine {
                    x: self.x.mul(&zinv),
                    y: self.y.mul(&zinv),
                };
                $affine::conditional_select(&p, &$affine::default(), self.z.is_zero())
            }
        }

        impl PrimeGroup for $name {}

        impl PrimeCurve for $name {
            type Affine = $affine;
        }

        impl CofactorGroup for $name {
            type Subgroup = $name;

            fn clear_cofactor(&self) -> Self {
                *self
            }

            fn into_subgroup(self) -> CtOption<Self> {
                CtOption::new(self, Choice::from(1))
            }

            fn is_torsion_free(&self) -> Choice {
                Choice::from(1)
            }
        }

        impl CofactorCurve for $name {
            type Affine = $affine;
        }

        impl GroupEncoding for $name {
            type Repr = [u8; 32];

            fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
                $affine::from_bytes(bytes).map(|p| p.to_curve())
            }

            fn from_bytes_unchecked(bytes: &[u8; 32]) -> CtOption<Self> {
                Self::from_bytes(bytes)
            }

            fn to_bytes(&self) -> [u8; 32] {
                self.to_affine().to_bytes()
            }
        }

        impl GroupEncoding for $affine {
            type Repr = [u8; 32];

            /// Decodes a compressed point; rejects non-canonical `x` and `x`
            /// values without a curve point.
            fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
                let mut tmp = *bytes;
                let ysign = Choice::from(tmp[31] >> 7);
                tmp[31] &= 0b0111_1111;
                $base::from_repr(tmp).and_then(|x| {
                    CtOption::new(Self::default(), x.is_zero() & !ysign).or_else(|| {
                        let x3 = x.square().mul(&x);
                        x3.add(&B).sqrt().and_then(|y| {
                            let sign = y.is_odd();
                            let y = $base::conditional_select(&y, &y.neg(), ysign ^ sign);
                            CtOption::new($affine { x, y }, Choice::from(1))
                        })
                    })
                })
            }

            fn from_bytes_unchecked(bytes: &[u8; 32]) -> CtOption<Self> {
                Self::from_bytes(bytes)
            }

            fn to_bytes(&self) -> [u8; 32] {
                let mut xbytes = self.x.to_repr();
                let sign = self.y.is_odd().unwrap_u8() << 7;
                xbytes[31] |= sign;
                // The identity (0, 0) already encodes as zero bytes.
                xbytes
            }
        }

        impl PrimeCurveAffine for $affine {
            type Scalar = $scalar;
            type Curve = $name;

            fn identity() -> Self {
                Self::default()
            }

            fn generator() -> Self {
                // (-1, 2): (-1)^3 + 5 = 4 = 2^2.
                $affine {
                    x: $base::one().neg(),
                    y: $base::from_raw([2, 0, 0, 0]),
                }
            }

            fn is_identity(&self) -> Choice {
                self.x.is_zero() & self.y.is_zero()
            }

            fn to_curve(&self) -> $name {
                let id = self.is_identity();
                $name {
                    x: self.x,
                    y: $base::conditional_select(&self.y, &$base::one(), id),
                    z: $base::conditional_select(&$base::one(), &$base::zero(), id),
                }
            }
        }

        impl group::cofactor::CofactorCurveAffine for $affine {
            type Scalar = $scalar;
            type Curve = $name;

            fn identity() -> Self {
                <Self as PrimeCurveAffine>::identity()
            }

            fn generator() -> Self {
                <Self as PrimeCurveAffine>::generator()
            }

            fn is_identity(&self) -> Choice {
                <Self as PrimeCurveAffine>::is_identity(self)
            }

            fn to_curve(&self) -> $name {
                <Self as PrimeCurveAffine>::to_curve(self)
            }
        }

        impl From<$affine> for $name {
            fn from(p: $affine) -> $name {
                p.to_curve()
            }
        }

        impl From<&$affine> for $name {
            fn from(p: &$affine) -> $name {
                p.to_curve()
            }
        }

        impl From<$name> for $affine {
            fn from(p: $name) -> $affine {
                p.to_affine()
            }
        }

        impl From<&$name> for $affine {
            fn from(p: &$name) -> $affine {
                p.to_affine()
            }
        }

        impl PastaCurve for $name {
            type Base = $base;
            type ScalarExt = $scalar;
            type AffineExt = $affine;

            const CURVE_ID: &'static str = CURVE_ID;

            fn endo(&self) -> Self {
                $name {
                    x: self.x.mul(&ENDO_BETA),
                    y: self.y,
                    z: self.z,
                }
            }

            fn hash_to_curve(
                domain_prefix: &str,
                message: &[u8],
            ) -> Result<Self, HashToCurveError> {
                crate::curve::hash_to_curve::hash_to_curve::<$name>(domain_prefix, message)
            }

            fn projective_coordinates(&self) -> ($base, $base, $base) {
                (self.x, self.y, self.z)
            }

            fn from_projective_coordinates(x: $base, y: $base, z: $base) -> CtOption<Self> {
                let p = $name { x, y, z };
                CtOption::new(p, p.is_on_curve_projective())
            }

            fn mul_vartime(&self, scalar: &$scalar) -> Self {
                crate::curve::endo::mul_vartime(self, scalar)
            }

            fn glv_decompose(k: &$scalar) -> Option<crate::curve::GlvDecomposition> {
                crate::curve::endo::decompose::<$name>(k)
            }

            fn is_on_curve(&self) -> Choice {
                self.is_on_curve_projective()
            }

            fn b() -> $base {
                B
            }
        }

        impl PastaAffine for $affine {
            type Base = $base;
            type ScalarExt = $scalar;
            type CurveExt = $name;

            fn coordinates(&self) -> CtOption<($base, $base)> {
                CtOption::new((self.x, self.y), !self.is_identity())
            }

            fn x(&self) -> $base {
                self.x
            }

            fn y(&self) -> $base {
                self.y
            }

            fn from_xy(x: $base, y: $base) -> CtOption<Self> {
                let p = $affine { x, y };
                CtOption::new(p, PastaAffine::is_on_curve(&p))
            }

            fn is_on_curve(&self) -> Choice {
                let lhs = self.y.square();
                let rhs = self.x.square().mul(&self.x).add(&B);
                lhs.ct_eq(&rhs) | self.is_identity()
            }

            fn from_xy_unchecked(
                x: $base,
                y: $base,
                _token: crate::curve::sealed::Internal,
            ) -> Self {
                $affine { x, y }
            }

            fn endo_beta() -> $base {
                ENDO_BETA
            }
        }
    };
}

pub(crate) use impl_pasta_curve;

/// Implements a binary operator for all owned/borrowed operand combinations.
macro_rules! impl_curve_binop {
    ($lhs:ty, $rhs:ty, $out:ty, $tr:ident, $method:ident, $f:expr) => {
        impl $tr<$rhs> for $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: $rhs) -> $out {
                ($f)(&self, &rhs)
            }
        }

        impl<'b> $tr<&'b $rhs> for $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: &'b $rhs) -> $out {
                ($f)(&self, rhs)
            }
        }

        impl $tr<$rhs> for &$lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: $rhs) -> $out {
                ($f)(self, &rhs)
            }
        }

        impl<'b> $tr<&'b $rhs> for &$lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: &'b $rhs) -> $out {
                ($f)(self, rhs)
            }
        }
    };
}

pub(crate) use impl_curve_binop;

/// Implements an assigning operator from the corresponding binary operator.
macro_rules! impl_curve_assign {
    ($lhs:ty, $rhs:ty, $tr:ident, $method:ident, $op_tr:ident, $op:ident) => {
        impl $tr<$rhs> for $lhs {
            #[inline]
            fn $method(&mut self, rhs: $rhs) {
                *self = $op_tr::$op(&*self, &rhs);
            }
        }

        impl<'b> $tr<&'b $rhs> for $lhs {
            #[inline]
            fn $method(&mut self, rhs: &'b $rhs) {
                *self = $op_tr::$op(&*self, rhs);
            }
        }
    };
}

pub(crate) use impl_curve_assign;

#[cfg(test)]
mod tests {
    #![allow(clippy::many_single_char_names)]

    use super::*;
    use ff::{Field, WithSmallOrderMulGroup};
    use group::{Curve, Group, GroupEncoding};

    fn generic_checks<C: PastaCurve>()
    where
        C::AffineExt: EndoBetaMul,
    {
        let g = C::generator();
        let two = g.double();
        assert_eq!(two, g + g);
        let h = g;
        assert_eq!(g - h, C::identity());
        assert_eq!(g + C::identity(), g);
        assert_eq!((two - g).to_affine(), g.to_affine());
        let s = C::ScalarExt::from(1_234_567_u64);
        assert_eq!(g * s, g.mul_vartime(&s));
        let encoded = (g * s).to_bytes();
        assert_eq!(C::from_bytes(&encoded).unwrap(), g * s);
        assert!(bool::from(PastaCurve::is_on_curve(&(g * s))));
        assert_eq!(g.endo(), g * C::ScalarExt::ZETA);
        let aff = g.to_affine();
        assert_eq!(aff + aff, two);
        assert_eq!(C::AffineExt::from_xy(aff.x(), aff.y()).unwrap(), aff);
        assert!(bool::from(
            C::AffineExt::from_xy(aff.x(), aff.x()).is_none()
        ));
        let (x, y, z) = (g * s).projective_coordinates();
        assert_eq!(C::from_projective_coordinates(x, y, z).unwrap(), g * s);
        assert_eq!(C::b(), C::Base::from(5u64));
        assert_eq!(aff.endo_beta_mul(), g.endo().to_affine());
    }

    trait EndoBetaMul: PastaAffine {
        fn endo_beta_mul(&self) -> Self {
            affine_unchecked::<Self>(self.x() * Self::endo_beta(), self.y())
        }
    }
    impl EndoBetaMul for EpAffine {}
    impl EndoBetaMul for EqAffine {}

    #[test]
    fn group_law_and_encoding_pallas() {
        generic_checks::<Ep>();
    }

    #[test]
    fn group_law_and_encoding_vesta() {
        generic_checks::<Eq>();
    }

    #[test]
    fn unchecked_constructor_is_crate_internal_and_unvalidated() {
        // Inside the crate the token builds any coordinates; `from_xy`
        // rejects the same off-curve pair.
        let one = crate::Fp::ONE;
        let off_curve = affine_unchecked::<EpAffine>(one, one);
        assert_eq!((off_curve.x(), off_curve.y()), (one, one));
        assert!(!bool::from(PastaAffine::is_on_curve(&off_curve)));
        assert!(bool::from(EpAffine::from_xy(one, one).is_none()));
        let g = EqAffine::generator();
        assert_eq!(affine_unchecked::<EqAffine>(g.x(), g.y()), g);
    }

    #[test]
    fn identity_edge_cases() {
        let id = EpAffine::identity();
        assert_eq!(id.to_bytes(), [0u8; 32]);
        assert!(bool::from(
            EpAffine::from_bytes(&[0u8; 32]).unwrap().is_identity()
        ));
        assert_eq!(Ep::identity().to_affine(), id);
        assert_eq!(Ep::identity().double(), Ep::identity());
        assert_eq!(Ep::generator() + id, Ep::generator());
        assert_eq!(Ep::generator() * crate::Fq::ZERO, Ep::identity());
        assert!(bool::from(
            <EpAffine as PastaAffine>::coordinates(&id).is_none()
        ));
        let mut bytes = [0u8; 32];
        bytes[31] = 0x80;
        // x = 0 with the sign bit set: 5 is not a square in Fp.
        assert!(bool::from(EpAffine::from_bytes(&bytes).is_none()));
    }
}
