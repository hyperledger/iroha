//! Complete affine arithmetic on the BLS12-381 G1 and G2 curves.
//!
//! Points have canonical coordinates and an explicit infinity bit. Infinity has
//! the unique representation `(0, 0, true)`; finite points satisfy their curve
//! equation. Addition covers identity, doubling and inverse pairs using
//! constrained case bits and a nonzero selected denominator. No exceptional
//! slope is accepted as an unconstrained native result.
//!
//! An on-curve value is **not** a subgroup-checked public key or signature.
//! Subgroup membership, nonidentity, canonical compressed bytes and the BLS
//! verification relation must be established separately by the consuming proof.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

use super::{
    extension::{Fp2, Fp2Value},
    field::{Bls381Chip, Bls381Value},
    native,
};
use crate::Bit;

/// Prime-order scalar modulus, little-endian, for subgroup multiplication.
/// Checking `[r]P = O` is required in addition to the on-curve relation.
pub const SUBGROUP_ORDER: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

// The same complete group law applies over both fields. This macro keeps the
// exception and identity constraints identical for the two curve groups.
macro_rules! affine_curve {
    ($native:ident, $point:ident, $scalar:ty, $value:ident,
     $assign:ident, $identity:ident, $add:ident, $neg:ident, $select:ident, $step:ident,
     $assert_equal:ident, $assert_nonidentity:ident,
     $fassign:ident, $fconst:ident, $fadd:ident, $fsub:ident, $fmul:ident,
     $fsquare:ident, $fneg:ident, $finvert:ident, $fselect:ident, $fzero:ident, $fequal:ident, $fassert:ident,
     $zero:expr, $one:expr, $b:expr) => {
        /// Native affine witness; assignment constrains all fields.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $native {
            /// Canonical x coordinate, zero for infinity.
            pub x: $scalar,
            /// Canonical y coordinate, zero for infinity.
            pub y: $scalar,
            /// Whether this is the group identity.
            pub infinity: bool,
        }
        /// Constrained on-curve affine point; no subgroup claim is implied.
        #[derive(Clone, Debug)]
        pub struct $point<F: PastaField> {
            x: $value<F>,
            y: $value<F>,
            infinity: Bit<F>,
        }
        impl<F: PastaField> $point<F> {
            /// Canonical x coordinate; zero at infinity.
            pub const fn x(&self) -> &$value<F> {
                &self.x
            }
            /// Canonical y coordinate; zero at infinity.
            pub const fn y(&self) -> &$value<F> {
                &self.y
            }
            /// Constrained identity bit.
            pub const fn infinity(&self) -> &Bit<F> {
                &self.infinity
            }
            /// Native witness, not a validation capability.
            pub fn value(&self) -> Value<$native> {
                self.x
                    .value()
                    .zip(self.y.value())
                    .zip(self.infinity.value())
                    .map(|((x, y), infinity)| $native { x, y, infinity })
            }
        }
        impl<F: PastaField> Bls381Chip<'_, F> {
            /// Assign canonical coordinates and enforce the full curve/identity relation.
            /// # Errors
            /// Returns layout errors; malformed coordinates or infinity are unsatisfiable.
            pub fn $assign(
                &mut self,
                region: &mut Region<'_, F>,
                value: Value<$native>,
            ) -> Result<$point<F>, Error> {
                let x = self.$fassign(region, value.map(|p| p.x))?;
                let y = self.$fassign(region, value.map(|p| p.y))?;
                let infinity = self.glue().boolean(region, value.map(|p| p.infinity))?;
                let xx = self.$fsquare(region, &x)?;
                let xxx = self.$fmul(region, &xx, &x)?;
                let b = self.$fconst(region, $b)?;
                let rhs = self.$fadd(region, &xxx, &b)?;
                let yy = self.$fsquare(region, &y)?;
                let on_curve = self.$fequal(region, &rhs, &yy)?;
                let finite = self.glue().not(region, &infinity)?;
                let off_curve = self.glue().not(region, &on_curve)?;
                let invalid_finite = self.glue().and(region, &finite, &off_curve)?;
                self.glue()
                    .enforce_constant(region, invalid_finite.word(), F::ZERO)?;
                let x_zero = self.$fzero(region, &x)?;
                let y_zero = self.$fzero(region, &y)?;
                let both_zero = self.glue().and(region, &x_zero, &y_zero)?;
                let nonzero = self.glue().not(region, &both_zero)?;
                let invalid_infinity = self.glue().and(region, &infinity, &nonzero)?;
                self.glue()
                    .enforce_constant(region, invalid_infinity.word(), F::ZERO)?;
                Ok($point { x, y, infinity })
            }
            /// Circuit-fixed canonical identity.
            /// # Errors
            /// Returns layout errors.
            pub fn $identity(&mut self, region: &mut Region<'_, F>) -> Result<$point<F>, Error> {
                let zero = self.$fconst(region, $zero)?;
                let infinity = self.glue().constant(region, F::ONE)?;
                Ok($point {
                    x: zero.clone(),
                    y: zero,
                    infinity: Bit::new(infinity),
                })
            }
            /// Select `a` when the constrained bit is one, otherwise `b`.
            /// # Errors
            /// Returns layout errors.
            pub fn $select(
                &mut self,
                region: &mut Region<'_, F>,
                bit: &Bit<F>,
                a: &$point<F>,
                b: &$point<F>,
            ) -> Result<$point<F>, Error> {
                let x = self.$fselect(region, bit, &a.x, &b.x)?;
                let y = self.$fselect(region, bit, &a.y, &b.y)?;
                // A selection of bits by a bit is itself a bit.
                let infinity = Bit::new(self.glue().select(
                    region,
                    bit,
                    a.infinity.word(),
                    b.infinity.word(),
                )?);
                Ok($point { x, y, infinity })
            }
            /// Complete group negation, including the canonical identity.
            /// # Errors
            /// Returns layout errors.
            pub fn $neg(
                &mut self,
                region: &mut Region<'_, F>,
                a: &$point<F>,
            ) -> Result<$point<F>, Error> {
                Ok($point {
                    x: a.x.clone(),
                    y: self.$fneg(region, &a.y)?,
                    infinity: a.infinity.clone(),
                })
            }
            /// Complete group addition over canonical on-curve inputs.
            /// # Errors
            /// Returns layout errors.
            pub fn $add(
                &mut self,
                region: &mut Region<'_, F>,
                a: &$point<F>,
                b: &$point<F>,
            ) -> Result<$point<F>, Error> {
                let same_x = self.$fequal(region, &a.x, &b.x)?;
                let same_y = self.$fequal(region, &a.y, &b.y)?;
                let y_zero = self.$fzero(region, &a.y)?;
                let y_nonzero = self.glue().not(region, &y_zero)?;
                let same_point = self.glue().and(region, &same_x, &same_y)?;
                let doubling = self.glue().and(region, &same_point, &y_nonzero)?;
                let different_x = self.glue().not(region, &same_x)?;
                let no_double = self.glue().not(region, &doubling)?;
                let exceptional = self.glue().and(region, &same_x, &no_double)?;
                let ordinary = self.glue().not(region, &exceptional)?;
                // Both slopes are laid out, then selected by an algebraic bit.
                let dx = self.$fsub(region, &b.x, &a.x)?;
                let dy = self.$fsub(region, &b.y, &a.y)?;
                let xx = self.$fsquare(region, &a.x)?;
                let twice_xx = self.$fadd(region, &xx, &xx)?;
                let thrice_xx = self.$fadd(region, &twice_xx, &xx)?;
                let twice_y = self.$fadd(region, &a.y, &a.y)?;
                let numerator = self.$fselect(region, &different_x, &dy, &thrice_xx)?;
                let denominator = self.$fselect(region, &different_x, &dx, &twice_y)?;
                let one = self.$fconst(region, $one)?;
                // At inverse pairs, y=0 doubling or O+O the group output is O.
                // The selected denominator is one, avoiding a false inverse of zero.
                let safe_denominator = self.$fselect(region, &ordinary, &denominator, &one)?;
                let inverse = self.$finvert(region, &safe_denominator)?;
                let slope = self.$fmul(region, &numerator, &inverse)?;
                let slope_squared = self.$fsquare(region, &slope)?;
                let x = self.$fsub(region, &slope_squared, &a.x)?;
                let x = self.$fsub(region, &x, &b.x)?;
                let x_distance = self.$fsub(region, &a.x, &x)?;
                let y = self.$fmul(region, &slope, &x_distance)?;
                let y = self.$fsub(region, &y, &a.y)?;
                let zero = self.$fconst(region, $zero)?;
                let x = self.$fselect(region, &ordinary, &x, &zero)?;
                let y = self.$fselect(region, &ordinary, &y, &zero)?;
                let calculated = $point {
                    x,
                    y,
                    infinity: exceptional,
                };
                let with_right_identity = self.$select(region, &b.infinity, a, &calculated)?;
                self.$select(region, &a.infinity, b, &with_right_identity)
            }
            /// One constrained left-to-right scalar step: `2*acc + bit*base`.
            /// The caller binds the exact scalar bits, initial identity, and final
            /// point across recursive chunks; this operation alone grants no
            /// subgroup membership.
            /// # Errors
            /// Returns layout errors.
            pub fn $step(
                &mut self,
                region: &mut Region<'_, F>,
                acc: &$point<F>,
                base: &$point<F>,
                bit: &Bit<F>,
            ) -> Result<$point<F>, Error> {
                let doubled = self.$add(region, acc, acc)?;
                let added = self.$add(region, &doubled, base)?;
                self.$select(region, bit, &added, &doubled)
            }
            /// Bind equality of coordinates and identity bits.
            /// # Errors
            /// Returns layout errors; unequal points are unsatisfiable.
            pub fn $assert_equal(
                region: &mut Region<'_, F>,
                a: &$point<F>,
                b: &$point<F>,
            ) -> Result<(), Error> {
                Self::$fassert(region, &a.x, &b.x)?;
                Self::$fassert(region, &a.y, &b.y)?;
                crate::arith::GlueChip::assert_equal(region, a.infinity.word(), b.infinity.word())
            }
            /// Exclude the group identity; this does not check subgroup membership.
            /// # Errors
            /// Returns layout errors; infinity is unsatisfiable.
            pub fn $assert_nonidentity(
                &mut self,
                region: &mut Region<'_, F>,
                a: &$point<F>,
            ) -> Result<(), Error> {
                self.glue()
                    .enforce_constant(region, a.infinity.word(), F::ZERO)
            }
        }
    };
}

affine_curve!(
    G1AffineWitness,
    G1Value,
    native::Fp,
    Bls381Value,
    assign_g1,
    identity_g1,
    add_g1,
    neg_g1,
    select_g1,
    scalar_step_g1,
    assert_equal_g1,
    assert_nonidentity_g1,
    assign,
    constant,
    add,
    sub,
    mul,
    square,
    neg,
    invert,
    select,
    is_zero,
    is_equal,
    assert_equal,
    native::ZERO,
    native::ONE,
    [4, 0, 0, 0, 0, 0]
);
affine_curve!(
    G2AffineWitness,
    G2Value,
    Fp2,
    Fp2Value,
    assign_g2,
    identity_g2,
    add_g2,
    neg_g2,
    select_g2,
    scalar_step_g2,
    assert_equal_g2,
    assert_nonidentity_g2,
    assign_fp2,
    constant_fp2,
    add_fp2,
    sub_fp2,
    mul_fp2,
    square_fp2,
    neg_fp2,
    invert_fp2,
    select_fp2,
    is_zero_fp2,
    is_equal_fp2,
    assert_equal_fp2,
    [native::ZERO; 2],
    [native::ONE, native::ZERO],
    [[4, 0, 0, 0, 0, 0]; 2]
);

#[cfg(test)]
#[path = "curve_tests.rs"]
mod tests;

impl<F: PastaField> Bls381Chip<'_, F> {
    /// Bind already assigned G2 coordinates and identity bit to a freshly
    /// checked curve point. This does not establish subgroup membership.
    /// # Errors
    /// Returns layout errors; malformed curve or identity values are unsatisfiable.
    pub fn bind_g2_coordinates(
        &mut self,
        region: &mut Region<'_, F>,
        x: &Fp2Value<F>,
        y: &Fp2Value<F>,
        infinity: &Bit<F>,
    ) -> Result<G2Value<F>, Error> {
        let witness = x
            .value()
            .zip(y.value())
            .zip(infinity.value())
            .map(|((x, y), infinity)| G2AffineWitness { x, y, infinity });
        let result = self.assign_g2(region, witness)?;
        Self::assert_equal_fp2(region, x, result.x())?;
        Self::assert_equal_fp2(region, y, result.y())?;
        crate::arith::GlueChip::assert_equal(region, infinity.word(), result.infinity().word())?;
        Ok(result)
    }
}

impl<F: PastaField> Bls381Chip<'_, F> {
    /// Untwist–Frobenius–twist endomorphism ψ on G2, including infinity.
    /// This arithmetic map does not establish `[x]P=ψ(P)` or subgroup membership.
    /// # Errors
    /// Returns layout errors.
    pub fn psi_g2(
        &mut self,
        region: &mut Region<'_, F>,
        p: &G2Value<F>,
    ) -> Result<G2Value<F>, Error> {
        let x = self.conjugate_fp2(region, p.x())?;
        let y = self.conjugate_fp2(region, p.y())?;
        let cx = self.constant_fp2(
            region,
            [
                [
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ],
                [
                    0x8bfd_0000_0000_aaad,
                    0x4094_27eb_4f49_fffd,
                    0x897d_2965_0fb8_5f9b,
                    0xaa0d_857d_8975_9ad4,
                    0xec02_4086_63d4_de85,
                    0x1a01_11ea_397f_e699,
                ],
            ],
        )?;
        let cy = self.constant_fp2(
            region,
            [
                [
                    0xf1ee_7b04_121b_dea2,
                    0x3044_66cf_3e67_fa0a,
                    0xef39_6489_f61e_b45e,
                    0x1c3d_edd9_30b1_cf60,
                    0xe2e9_c448_d77a_2cd9,
                    0x1352_03e6_0180_a68e,
                ],
                [
                    0xc810_84fb_ede3_cc09,
                    0xee67_992f_72ec_05f4,
                    0x77f7_6e17_0092_41c5,
                    0x4839_5dab_c2d3_435e,
                    0x6831_e36d_6bd1_7ffe,
                    0x06af_0e04_37ff_400b,
                ],
            ],
        )?;
        let x = self.mul_fp2(region, &x, &cx)?;
        let y = self.mul_fp2(region, &y, &cy)?;
        self.bind_g2_coordinates(region, &x, &y, p.infinity())
    }
    /// Twice-composed ψ using its fixed x coefficient and y negation.
    /// # Errors
    /// Returns layout errors.
    pub fn psi2_g2(
        &mut self,
        region: &mut Region<'_, F>,
        p: &G2Value<F>,
    ) -> Result<G2Value<F>, Error> {
        let cx = self.constant(
            region,
            [
                0x8bfd_0000_0000_aaac,
                0x4094_27eb_4f49_fffd,
                0x897d_2965_0fb8_5f9b,
                0xaa0d_857d_8975_9ad4,
                0xec02_4086_63d4_de85,
                0x1a01_11ea_397f_e699,
            ],
        )?;
        let x = self.mul_fp2_by_fp(region, p.x(), &cx)?;
        let y = self.neg_fp2(region, p.y())?;
        self.bind_g2_coordinates(region, &x, &y, p.infinity())
    }
}

/// Fixed native G2 scalar programs for recursively linked arithmetic steps.
#[path = "curve/programs.rs"]
pub mod programs;

impl<F: PastaField> Bls381Chip<'_, F> {
    /// G1 cube-root endomorphism φ(x,y)=(βx,y), including infinity.
    /// This does not itself establish prime-subgroup membership.
    /// # Errors
    /// Returns layout errors.
    pub fn phi_g1(
        &mut self,
        region: &mut Region<'_, F>,
        p: &G1Value<F>,
    ) -> Result<G1Value<F>, Error> {
        let beta = self.constant(
            region,
            [
                0x2e01_ffff_fffe_fffe,
                0xde17_d813_620a_0002,
                0xddb3_a93b_e6f8_9688,
                0xba69_c607_6a0f_77ea,
                0x5f19_672f_df76_ce51,
                0x0000_0000_0000_0000,
            ],
        )?;
        Ok(G1Value {
            x: self.mul(region, p.x(), &beta)?,
            y: p.y().clone(),
            infinity: p.infinity().clone(),
        })
    }
}
/// Exact native G1 subgroup arithmetic and fixed-point guard schedule.
#[path = "curve/g1_program.rs"]
pub mod g1_program;
