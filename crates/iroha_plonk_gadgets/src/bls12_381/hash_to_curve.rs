//! Exact SWU and three-isogeny stages of native W3f BLS12-381 hashing.
//!
//! Input Fp2 elements must come from the exact W3f XMD/hash-to-field transcript.
//! The two mapped outputs must subsequently be added and the native effective
//! cofactor cleared. Mapping one arbitrary Fp2 value does not authenticate a
//! message or yield a prime-subgroup signature point by itself.

use super::{
    curve::G2Value,
    extension::{Fp2, Fp2Value},
    field::{Bls381Chip, Bls381Value},
    native as base,
};
use crate::{Bit, arith::GlueChip};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};
#[path = "hash_to_curve/constants.rs"]
mod constants;
#[path = "hash_to_curve/native.rs"]
mod native;
use constants::*;

/// A point on the fixed isogenous curve `y²=x³+240u*x+1012(1+u)`.
#[derive(Clone, Debug)]
pub struct SwuG2Value<F: PastaField> {
    x: Fp2Value<F>,
    y: Fp2Value<F>,
}
impl<F: PastaField> SwuG2Value<F> {
    /// Canonical affine x coordinate.
    pub const fn x(&self) -> &Fp2Value<F> {
        &self.x
    }
    /// Canonical affine y coordinate.
    pub const fn y(&self) -> &Fp2Value<F> {
        &self.y
    }
}
impl<F: PastaField> Bls381Chip<'_, F> {
    /// The least significant bit of a canonical base-field integer.
    /// # Errors
    /// Returns layout errors.
    pub fn parity_bls_fp(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
    ) -> Result<Bit<F>, Error> {
        let bit = self
            .glue()
            .boolean(region, a.value().map(|x| x[0] & 1 == 1))?;
        let half = self.range().witness_range_checked(
            region,
            a.value().map(|x| F::from(x[0] >> 1)),
            63,
        )?;
        let reconstructed = self.glue().linear(
            region,
            &[(F::from(2_u64), &half), (F::ONE, bit.word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &reconstructed, &a.limbs()[0])?;
        Ok(bit)
    }
    /// Native arkworks SWU parity: parity of the first nonzero Fp coefficient.
    /// # Errors
    /// Returns layout errors.
    pub fn parity_bls_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Bit<F>, Error> {
        let first = self.parity_bls_fp(region, &a.coefficients()[0])?;
        let second = self.parity_bls_fp(region, &a.coefficients()[1])?;
        let first_zero = self.is_zero(region, &a.coefficients()[0])?;
        Ok(Bit::new(self.glue().select(
            region,
            &first_zero,
            second.word(),
            first.word(),
        )?))
    }
    /// Assign a continuation on the fixed isogenous curve. The caller must bind
    /// these coordinates to its prior SWU proof before treating them as a hash.
    /// # Errors
    /// Returns layout errors; off-curve coordinates are unsatisfiable.
    pub fn assign_swu_g2(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<[Fp2; 2]>,
    ) -> Result<SwuG2Value<F>, Error> {
        let x = self.assign_fp2(region, value.map(|x| x[0]))?;
        let y = self.assign_fp2(region, value.map(|x| x[1]))?;
        let a = self.constant_fp2(region, [base::ZERO, [240, 0, 0, 0, 0, 0]])?;
        let b = self.constant_fp2(region, [[1012, 0, 0, 0, 0, 0]; 2])?;
        let xx = self.square_fp2(region, &x)?;
        let xxx = self.mul_fp2(region, &xx, &x)?;
        let ax = self.mul_fp2(region, &a, &x)?;
        let rhs = self.add_fp2(region, &xxx, &ax)?;
        let rhs = self.add_fp2(region, &rhs, &b)?;
        let yy = self.square_fp2(region, &y)?;
        Self::assert_equal_fp2(region, &rhs, &yy)?;
        Ok(SwuG2Value { x, y })
    }
    /// Constrain the exact native SWU map, including exceptional denominator,
    /// square/nonsquare selection and final parity normalization.
    /// # Errors
    /// Returns layout errors.
    pub fn map_to_swu_g2(
        &mut self,
        region: &mut Region<'_, F>,
        input: &Fp2Value<F>,
    ) -> Result<SwuG2Value<F>, Error> {
        let a = self.constant_fp2(region, [base::ZERO, [240, 0, 0, 0, 0, 0]])?;
        let b = self.constant_fp2(region, [[1012, 0, 0, 0, 0, 0]; 2])?;
        let zeta = self.constant_fp2(region, ZETA)?;
        let one = self.constant_fp2(region, [base::ONE, base::ZERO])?;
        let u_squared = self.square_fp2(region, input)?;
        let zeta_u2 = self.mul_fp2(region, &zeta, &u_squared)?;
        let ta = self.square_fp2(region, &zeta_u2)?;
        let ta = self.add_fp2(region, &ta, &zeta_u2)?;
        let ta_one = self.add_fp2(region, &ta, &one)?;
        let num_x1 = self.mul_fp2(region, &b, &ta_one)?;
        let ta_zero = self.is_zero_fp2(region, &ta)?;
        let minus_ta = self.neg_fp2(region, &ta)?;
        let div_factor = self.select_fp2(region, &ta_zero, &zeta, &minus_ta)?;
        let div = self.mul_fp2(region, &a, &div_factor)?;
        let div_inverse = self.invert_fp2(region, &div)?;
        let x1 = self.mul_fp2(region, &num_x1, &div_inverse)?;
        let xx = self.square_fp2(region, &x1)?;
        let xxx = self.mul_fp2(region, &xx, &x1)?;
        let ax = self.mul_fp2(region, &a, &x1)?;
        let gx1 = self.add_fp2(region, &xxx, &ax)?;
        let gx1 = self.add_fp2(region, &gx1, &b)?;
        let sqrt_witness = gx1.value().map(|g| {
            // ark's Legendre::is_qr is false for zero. Both roots are zero then,
            // so explicitly preserve that branch in constraints below.
            if g != [base::ZERO; 2]
                && let Some(root) = native::sqrt(&g)
            {
                return (true, root);
            }
            (
                false,
                native::sqrt(&native::mul(&ZETA, &g)).unwrap_or([base::ZERO; 2]),
            )
        });
        let square = self.glue().boolean(region, sqrt_witness.map(|x| x.0))?;
        let y1 = self.assign_fp2(region, sqrt_witness.map(|x| x.1))?;
        let gx1_zero = self.is_zero_fp2(region, &gx1)?;
        let invalid_zero_branch = self.glue().and(region, &gx1_zero, &square)?;
        self.glue()
            .enforce_constant(region, invalid_zero_branch.word(), F::ZERO)?;
        let zeta_gx1 = self.mul_fp2(region, &zeta, &gx1)?;
        let radicand = self.select_fp2(region, &square, &gx1, &zeta_gx1)?;
        let y1_squared = self.square_fp2(region, &y1)?;
        Self::assert_equal_fp2(region, &radicand, &y1_squared)?;
        // Since fixed ZETA is a nonsquare, the constrained root uniquely selects
        // the native residue branch for every nonzero gx1.
        let x2 = self.mul_fp2(region, &zeta_u2, &x1)?;
        let y2_factor = self.mul_fp2(region, &zeta_u2, input)?;
        let y2 = self.mul_fp2(region, &y2_factor, &y1)?;
        let x = self.select_fp2(region, &square, &x1, &x2)?;
        let y = self.select_fp2(region, &square, &y1, &y2)?;
        let input_parity = self.parity_bls_fp2(region, input)?;
        let y_parity = self.parity_bls_fp2(region, &y)?;
        let parity_equal = self
            .glue()
            .is_equal(region, input_parity.word(), y_parity.word())?;
        let negative_y = self.neg_fp2(region, &y)?;
        let y = self.select_fp2(region, &parity_equal, &y, &negative_y)?;
        Ok(SwuG2Value { x, y })
    }
    fn isogeny_polynomial(
        &mut self,
        region: &mut Region<'_, F>,
        x: &Fp2Value<F>,
        coefficients: &[Fp2],
    ) -> Result<Fp2Value<F>, Error> {
        let mut acc = self.constant_fp2(region, [base::ZERO; 2])?;
        for coefficient in coefficients.iter().rev() {
            let product = self.mul_fp2(region, &acc, x)?;
            let coefficient = self.constant_fp2(region, *coefficient)?;
            acc = self.add_fp2(region, &product, &coefficient)?;
        }
        Ok(acc)
    }
    /// Constrain the fixed native three-isogeny from the SWU curve to G2.
    /// # Errors
    /// Returns layout errors; zero rational denominators are unsatisfiable.
    pub fn isogeny_to_g2(
        &mut self,
        region: &mut Region<'_, F>,
        point: &SwuG2Value<F>,
    ) -> Result<G2Value<F>, Error> {
        let xn = self.isogeny_polynomial(region, &point.x, &X_MAP_NUMERATOR)?;
        let xd = self.isogeny_polynomial(region, &point.x, &X_MAP_DENOMINATOR)?;
        let yn = self.isogeny_polynomial(region, &point.x, &Y_MAP_NUMERATOR)?;
        let yd = self.isogeny_polynomial(region, &point.x, &Y_MAP_DENOMINATOR)?;
        let xd_inverse = self.invert_fp2(region, &xd)?;
        let yd_inverse = self.invert_fp2(region, &yd)?;
        let x = self.mul_fp2(region, &xn, &xd_inverse)?;
        let y = self.mul_fp2(region, &yn, &point.y)?;
        let y = self.mul_fp2(region, &y, &yd_inverse)?;
        let finite = Bit::new(self.glue().constant(region, F::ZERO)?);
        self.bind_g2_coordinates(region, &x, &y, &finite)
    }
}

#[cfg(test)]
#[path = "hash_to_curve/tests.rs"]
mod tests;
