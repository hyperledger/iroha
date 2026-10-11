//! Constrained BLS12-381 extension tower over canonical base-field cells.
//!
//! The tower is `Fp2 = Fp[u]/(u² + 1)`, `Fp6 = Fp2[v]/(v³ - (1 + u))`,
//! and `Fp12 = Fp6[w]/(w² - v)`. Every coefficient is a canonical base-field
//! value. Arithmetic composes the integer-constrained base chip; no extension
//! result is accepted from a native verifier. Inversion rejects zero through
//! the final base-field inverse relation.
//!
//! These are arithmetic primitives, not a signature or finality verifier.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

use super::{
    field::{Bls381Chip, Bls381Value},
    native,
};
use crate::Bit;
#[path = "frobenius_constants.rs"]
mod frobenius_constants;
use frobenius_constants::*;

/// Native coefficient order `c0 + c1 u` for an Fp2 witness.
pub type Fp2 = [native::Fp; 2];
/// Native coefficient order `c0 + c1 v + c2 v²` for an Fp6 witness.
pub type Fp6 = [Fp2; 3];
/// Native coefficient order `c0 + c1 w` for an Fp12 witness.
pub type Fp12 = [Fp6; 2];

/// Two canonical base-field coefficients of an Fp2 element.
#[derive(Clone, Debug)]
pub struct Fp2Value<F: PastaField> {
    coefficients: [Bls381Value<F>; 2],
}
impl<F: PastaField> Fp2Value<F> {
    /// Compose existing constrained coefficients in the order `c0 + c1 u`.
    pub const fn from_coefficients(coefficients: [Bls381Value<F>; 2]) -> Self {
        Self { coefficients }
    }
    /// Borrow both canonical coefficients.
    pub const fn coefficients(&self) -> &[Bls381Value<F>; 2] {
        &self.coefficients
    }
    /// Native witness value; this accessor grants no verification authority.
    pub fn value(&self) -> Value<Fp2> {
        self.coefficients[0]
            .value()
            .zip(self.coefficients[1].value())
            .map(|(a, b)| [a, b])
    }
}

/// Three Fp2 coefficients of an Fp6 element.
#[derive(Clone, Debug)]
pub struct Fp6Value<F: PastaField> {
    coefficients: [Fp2Value<F>; 3],
}
impl<F: PastaField> Fp6Value<F> {
    /// Compose existing constrained coefficients in ascending powers of `v`.
    pub const fn from_coefficients(coefficients: [Fp2Value<F>; 3]) -> Self {
        Self { coefficients }
    }
    /// Borrow all three coefficients.
    pub const fn coefficients(&self) -> &[Fp2Value<F>; 3] {
        &self.coefficients
    }
    /// Native witness value; this accessor grants no verification authority.
    pub fn value(&self) -> Value<Fp6> {
        self.coefficients[0]
            .value()
            .zip(self.coefficients[1].value())
            .zip(self.coefficients[2].value())
            .map(|((a, b), c)| [a, b, c])
    }
}

/// Two Fp6 coefficients of an Fp12 element.
#[derive(Clone, Debug)]
pub struct Fp12Value<F: PastaField> {
    coefficients: [Fp6Value<F>; 2],
}
impl<F: PastaField> Fp12Value<F> {
    /// Compose existing constrained coefficients in the order `c0 + c1 w`.
    pub const fn from_coefficients(coefficients: [Fp6Value<F>; 2]) -> Self {
        Self { coefficients }
    }
    /// Borrow both coefficients.
    pub const fn coefficients(&self) -> &[Fp6Value<F>; 2] {
        &self.coefficients
    }
    /// Native witness value; this accessor grants no verification authority.
    pub fn value(&self) -> Value<Fp12> {
        self.coefficients[0]
            .value()
            .zip(self.coefficients[1].value())
            .map(|(a, b)| [a, b])
    }
}

impl<F: PastaField> Bls381Chip<'_, F> {
    /// Constrain a circuit-fixed Frobenius power over Fp2.
    /// # Errors
    /// Returns layout errors.
    pub fn frobenius_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        power: usize,
    ) -> Result<Fp2Value<F>, Error> {
        if power.is_multiple_of(2) {
            Ok(a.clone())
        } else {
            self.conjugate_fp2(region, a)
        }
    }
    /// Constrain a circuit-fixed Frobenius power over Fp6.
    /// # Errors
    /// Returns layout errors.
    pub fn frobenius_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
        power: usize,
    ) -> Result<Fp6Value<F>, Error> {
        let c0 = self.frobenius_fp2(region, &a.coefficients[0], power)?;
        let c1 = self.frobenius_fp2(region, &a.coefficients[1], power)?;
        let c2 = self.frobenius_fp2(region, &a.coefficients[2], power)?;
        let factor1 = self.constant_fp2(region, FROBENIUS_COEFF_FP6_C1[power % 6])?;
        let factor2 = self.constant_fp2(region, FROBENIUS_COEFF_FP6_C2[power % 6])?;
        Ok(Fp6Value::from_coefficients([
            c0,
            self.mul_fp2(region, &c1, &factor1)?,
            self.mul_fp2(region, &c2, &factor2)?,
        ]))
    }
    /// Constrain a circuit-fixed Frobenius power over Fp12.
    /// # Errors
    /// Returns layout errors.
    pub fn frobenius_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
        power: usize,
    ) -> Result<Fp12Value<F>, Error> {
        let c0 = self.frobenius_fp6(region, &a.coefficients[0], power)?;
        let c1 = self.frobenius_fp6(region, &a.coefficients[1], power)?;
        let factor = self.constant_fp2(region, FROBENIUS_COEFF_FP12_C1[power % 12])?;
        let c1 = Fp6Value::from_coefficients([
            self.mul_fp2(region, &c1.coefficients[0], &factor)?,
            self.mul_fp2(region, &c1.coefficients[1], &factor)?,
            self.mul_fp2(region, &c1.coefficients[2], &factor)?,
        ]);
        Ok(Fp12Value::from_coefficients([c0, c1]))
    }

    /// Assign and range-check both canonical Fp2 coefficients.
    /// # Errors
    /// Returns assignment or range-layout errors; noncanonical values are unsatisfiable.
    pub fn assign_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<Fp2>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.assign(region, value.map(|x| x[0]))?,
            self.assign(region, value.map(|x| x[1]))?,
        ]))
    }
    /// Bind a circuit-constant Fp2 element.
    /// # Errors
    /// Returns invalid constant or layout errors.
    pub fn constant_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        value: Fp2,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.constant(region, value[0])?,
            self.constant(region, value[1])?,
        ]))
    }
    /// Constrain Fp2 addition.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn add_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.add(region, &a.coefficients[0], &b.coefficients[0])?,
            self.add(region, &a.coefficients[1], &b.coefficients[1])?,
        ]))
    }
    /// Constrain Fp2 subtraction.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn sub_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.sub(region, &a.coefficients[0], &b.coefficients[0])?,
            self.sub(region, &a.coefficients[1], &b.coefficients[1])?,
        ]))
    }
    /// Constrain Fp2 negation.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn neg_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.neg(region, &a.coefficients[0])?,
            self.neg(region, &a.coefficients[1])?,
        ]))
    }
    /// Constrain the Fp2 Frobenius map `c0 - c1 u`.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn conjugate_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            a.coefficients[0].clone(),
            self.neg(region, &a.coefficients[1])?,
        ]))
    }
    /// Constrain Fp2 multiplication with three base-field products.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        let aa = self.mul(region, &a.coefficients[0], &b.coefficients[0])?;
        let bb = self.mul(region, &a.coefficients[1], &b.coefficients[1])?;
        let sa = self.add(region, &a.coefficients[0], &a.coefficients[1])?;
        let sb = self.add(region, &b.coefficients[0], &b.coefficients[1])?;
        let cross = self.mul(region, &sa, &sb)?;
        let cross = self.sub(region, &cross, &aa)?;
        let cross = self.sub(region, &cross, &bb)?;
        Ok(Fp2Value::from_coefficients([
            self.sub(region, &aa, &bb)?,
            cross,
        ]))
    }
    /// Constrain Fp2 squaring with two base-field products.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn square_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        let sum = self.add(region, &a.coefficients[0], &a.coefficients[1])?;
        let difference = self.sub(region, &a.coefficients[0], &a.coefficients[1])?;
        let real = self.mul(region, &sum, &difference)?;
        let cross = self.mul(region, &a.coefficients[0], &a.coefficients[1])?;
        Ok(Fp2Value::from_coefficients([
            real,
            self.add(region, &cross, &cross)?,
        ]))
    }
    /// Multiply by the Fp6 defining nonresidue `1 + u`.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp2_nonresidue(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.sub(region, &a.coefficients[0], &a.coefficients[1])?,
            self.add(region, &a.coefficients[0], &a.coefficients[1])?,
        ]))
    }
    /// Multiply both coefficients by one constrained base-field element.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp2_by_fp(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.mul(region, &a.coefficients[0], b)?,
            self.mul(region, &a.coefficients[1], b)?,
        ]))
    }
    /// Constrain a nonzero Fp2 inverse through its base-field norm.
    /// # Errors
    /// Returns base-field layout errors; zero has no satisfying inverse.
    pub fn invert_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        let aa = self.square(region, &a.coefficients[0])?;
        let bb = self.square(region, &a.coefficients[1])?;
        let norm = self.add(region, &aa, &bb)?;
        let inverse = self.invert(region, &norm)?;
        let real = self.mul(region, &a.coefficients[0], &inverse)?;
        let imaginary = self.mul(region, &a.coefficients[1], &inverse)?;
        Ok(Fp2Value::from_coefficients([
            real,
            self.neg(region, &imaginary)?,
        ]))
    }
    /// Select `a` when the constrained bit is one, otherwise `b`.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn select_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        bit: &Bit<F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<Fp2Value<F>, Error> {
        Ok(Fp2Value::from_coefficients([
            self.select(region, bit, &a.coefficients[0], &b.coefficients[0])?,
            self.select(region, bit, &a.coefficients[1], &b.coefficients[1])?,
        ]))
    }
    /// Constrain whether both coefficients are zero.
    /// # Errors
    /// Returns base-field or glue layout errors.
    pub fn is_zero_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
    ) -> Result<Bit<F>, Error> {
        let real = self.is_zero(region, &a.coefficients[0])?;
        let imaginary = self.is_zero(region, &a.coefficients[1])?;
        self.glue().and(region, &real, &imaginary)
    }
    /// Constrain equality of both canonical coefficients.
    /// # Errors
    /// Returns base-field or glue layout errors.
    pub fn is_equal_fp2(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<Bit<F>, Error> {
        let real = self.is_equal(region, &a.coefficients[0], &b.coefficients[0])?;
        let imaginary = self.is_equal(region, &a.coefficients[1], &b.coefficients[1])?;
        self.glue().and(region, &real, &imaginary)
    }
    /// Require equality of both canonical coefficients.
    /// # Errors
    /// Returns copy-constraint errors; unequal values are unsatisfiable.
    pub fn assert_equal_fp2(
        region: &mut Region<'_, F>,
        a: &Fp2Value<F>,
        b: &Fp2Value<F>,
    ) -> Result<(), Error> {
        Self::assert_equal(region, &a.coefficients[0], &b.coefficients[0])?;
        Self::assert_equal(region, &a.coefficients[1], &b.coefficients[1])
    }
    /// Assign all six canonical Fp6 base coefficients.
    /// # Errors
    /// Returns assignment or range-layout errors.
    pub fn assign_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        value: &Value<Fp6>,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.assign_fp2(region, value.as_ref().map(|x| x[0]))?,
            self.assign_fp2(region, value.as_ref().map(|x| x[1]))?,
            self.assign_fp2(region, value.as_ref().map(|x| x[2]))?,
        ]))
    }
    /// Bind a circuit-constant Fp6 element.
    /// # Errors
    /// Returns constant or layout errors.
    pub fn constant_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        value: &Fp6,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.constant_fp2(region, value[0])?,
            self.constant_fp2(region, value[1])?,
            self.constant_fp2(region, value[2])?,
        ]))
    }
    /// Constrain Fp6 addition.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn add_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
        b: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.add_fp2(region, &a.coefficients[0], &b.coefficients[0])?,
            self.add_fp2(region, &a.coefficients[1], &b.coefficients[1])?,
            self.add_fp2(region, &a.coefficients[2], &b.coefficients[2])?,
        ]))
    }
    /// Constrain Fp6 subtraction.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn sub_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
        b: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.sub_fp2(region, &a.coefficients[0], &b.coefficients[0])?,
            self.sub_fp2(region, &a.coefficients[1], &b.coefficients[1])?,
            self.sub_fp2(region, &a.coefficients[2], &b.coefficients[2])?,
        ]))
    }
    /// Constrain Fp6 negation.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn neg_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.neg_fp2(region, &a.coefficients[0])?,
            self.neg_fp2(region, &a.coefficients[1])?,
            self.neg_fp2(region, &a.coefficients[2])?,
        ]))
    }
    /// Multiply by the Fp12 defining nonresidue `v`.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp6_nonresidue(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        Ok(Fp6Value::from_coefficients([
            self.mul_fp2_nonresidue(region, &a.coefficients[2])?,
            a.coefficients[0].clone(),
            a.coefficients[1].clone(),
        ]))
    }
    /// Constrain Fp6 multiplication using six Fp2 products.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
        b: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        let v0 = self.mul_fp2(region, &a.coefficients[0], &b.coefficients[0])?;
        let v1 = self.mul_fp2(region, &a.coefficients[1], &b.coefficients[1])?;
        let v2 = self.mul_fp2(region, &a.coefficients[2], &b.coefficients[2])?;
        let a12 = self.add_fp2(region, &a.coefficients[1], &a.coefficients[2])?;
        let b12 = self.add_fp2(region, &b.coefficients[1], &b.coefficients[2])?;
        let c0 = self.mul_fp2(region, &a12, &b12)?;
        let c0 = self.sub_fp2(region, &c0, &v1)?;
        let c0 = self.sub_fp2(region, &c0, &v2)?;
        let c0 = self.mul_fp2_nonresidue(region, &c0)?;
        let c0 = self.add_fp2(region, &v0, &c0)?;
        let a01 = self.add_fp2(region, &a.coefficients[0], &a.coefficients[1])?;
        let b01 = self.add_fp2(region, &b.coefficients[0], &b.coefficients[1])?;
        let c1 = self.mul_fp2(region, &a01, &b01)?;
        let c1 = self.sub_fp2(region, &c1, &v0)?;
        let c1 = self.sub_fp2(region, &c1, &v1)?;
        let v2_nonresidue = self.mul_fp2_nonresidue(region, &v2)?;
        let c1 = self.add_fp2(region, &c1, &v2_nonresidue)?;
        let a02 = self.add_fp2(region, &a.coefficients[0], &a.coefficients[2])?;
        let b02 = self.add_fp2(region, &b.coefficients[0], &b.coefficients[2])?;
        let c2 = self.mul_fp2(region, &a02, &b02)?;
        let c2 = self.sub_fp2(region, &c2, &v0)?;
        let c2 = self.sub_fp2(region, &c2, &v2)?;
        let c2 = self.add_fp2(region, &c2, &v1)?;
        Ok(Fp6Value::from_coefficients([c0, c1, c2]))
    }
    /// Constrain Fp6 squaring.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn square_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        let s0 = self.square_fp2(region, &a.coefficients[0])?;
        let s1 = self.mul_fp2(region, &a.coefficients[0], &a.coefficients[1])?;
        let s1 = self.add_fp2(region, &s1, &s1)?;
        let s2 = self.sub_fp2(region, &a.coefficients[0], &a.coefficients[1])?;
        let s2 = self.add_fp2(region, &s2, &a.coefficients[2])?;
        let s2 = self.square_fp2(region, &s2)?;
        let s3 = self.mul_fp2(region, &a.coefficients[1], &a.coefficients[2])?;
        let s3 = self.add_fp2(region, &s3, &s3)?;
        let s4 = self.square_fp2(region, &a.coefficients[2])?;
        let c0 = self.mul_fp2_nonresidue(region, &s3)?;
        let c0 = self.add_fp2(region, &s0, &c0)?;
        let c1 = self.mul_fp2_nonresidue(region, &s4)?;
        let c1 = self.add_fp2(region, &s1, &c1)?;
        let c2 = self.add_fp2(region, &s1, &s2)?;
        let c2 = self.add_fp2(region, &c2, &s3)?;
        let c2 = self.sub_fp2(region, &c2, &s0)?;
        let c2 = self.sub_fp2(region, &c2, &s4)?;
        Ok(Fp6Value::from_coefficients([c0, c1, c2]))
    }
    /// Constrain a nonzero Fp6 inverse through its Fp2 norm.
    /// # Errors
    /// Returns layout errors; zero has no satisfying inverse.
    pub fn invert_fp6(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
    ) -> Result<Fp6Value<F>, Error> {
        let a0_squared = self.square_fp2(region, &a.coefficients[0])?;
        let a1a2 = self.mul_fp2(region, &a.coefficients[1], &a.coefficients[2])?;
        let a1a2 = self.mul_fp2_nonresidue(region, &a1a2)?;
        let t0 = self.sub_fp2(region, &a0_squared, &a1a2)?;
        let a2_squared = self.square_fp2(region, &a.coefficients[2])?;
        let a2_squared = self.mul_fp2_nonresidue(region, &a2_squared)?;
        let a0a1 = self.mul_fp2(region, &a.coefficients[0], &a.coefficients[1])?;
        let t1 = self.sub_fp2(region, &a2_squared, &a0a1)?;
        let a1_squared = self.square_fp2(region, &a.coefficients[1])?;
        let a0a2 = self.mul_fp2(region, &a.coefficients[0], &a.coefficients[2])?;
        let t2 = self.sub_fp2(region, &a1_squared, &a0a2)?;
        let d0 = self.mul_fp2(region, &a.coefficients[0], &t0)?;
        let d1 = self.mul_fp2(region, &a.coefficients[2], &t1)?;
        let d2 = self.mul_fp2(region, &a.coefficients[1], &t2)?;
        let d12 = self.add_fp2(region, &d1, &d2)?;
        let d12 = self.mul_fp2_nonresidue(region, &d12)?;
        let denominator = self.add_fp2(region, &d0, &d12)?;
        let inverse = self.invert_fp2(region, &denominator)?;
        Ok(Fp6Value::from_coefficients([
            self.mul_fp2(region, &t0, &inverse)?,
            self.mul_fp2(region, &t1, &inverse)?,
            self.mul_fp2(region, &t2, &inverse)?,
        ]))
    }
    /// Require equality of all canonical Fp6 coefficients.
    /// # Errors
    /// Returns copy-constraint errors; unequal values are unsatisfiable.
    pub fn assert_equal_fp6(
        region: &mut Region<'_, F>,
        a: &Fp6Value<F>,
        b: &Fp6Value<F>,
    ) -> Result<(), Error> {
        for (a, b) in a.coefficients.iter().zip(&b.coefficients) {
            Self::assert_equal_fp2(region, a, b)?;
        }
        Ok(())
    }
    /// Assign all twelve canonical Fp12 base coefficients.
    /// # Errors
    /// Returns assignment or range-layout errors.
    pub fn assign_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        value: &Value<Fp12>,
    ) -> Result<Fp12Value<F>, Error> {
        Ok(Fp12Value::from_coefficients([
            self.assign_fp6(region, &value.as_ref().map(|x| x[0]))?,
            self.assign_fp6(region, &value.as_ref().map(|x| x[1]))?,
        ]))
    }
    /// Bind a circuit-constant Fp12 element.
    /// # Errors
    /// Returns constant or layout errors.
    pub fn constant_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        value: &Fp12,
    ) -> Result<Fp12Value<F>, Error> {
        Ok(Fp12Value::from_coefficients([
            self.constant_fp6(region, &value[0])?,
            self.constant_fp6(region, &value[1])?,
        ]))
    }
    /// Constrain Fp12 multiplication using three Fp6 products.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn mul_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
        b: &Fp12Value<F>,
    ) -> Result<Fp12Value<F>, Error> {
        let aa = self.mul_fp6(region, &a.coefficients[0], &b.coefficients[0])?;
        let bb = self.mul_fp6(region, &a.coefficients[1], &b.coefficients[1])?;
        let sa = self.add_fp6(region, &a.coefficients[0], &a.coefficients[1])?;
        let sb = self.add_fp6(region, &b.coefficients[0], &b.coefficients[1])?;
        let cross = self.mul_fp6(region, &sa, &sb)?;
        let cross = self.sub_fp6(region, &cross, &aa)?;
        let cross = self.sub_fp6(region, &cross, &bb)?;
        let bb_nonresidue = self.mul_fp6_nonresidue(region, &bb)?;
        let real = self.add_fp6(region, &aa, &bb_nonresidue)?;
        Ok(Fp12Value::from_coefficients([real, cross]))
    }
    /// Constrain Fp12 squaring.
    /// # Errors
    /// Returns base-field layout errors.
    pub fn square_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
    ) -> Result<Fp12Value<F>, Error> {
        let ab = self.mul_fp6(region, &a.coefficients[0], &a.coefficients[1])?;
        let sum = self.add_fp6(region, &a.coefficients[0], &a.coefficients[1])?;
        let vb = self.mul_fp6_nonresidue(region, &a.coefficients[1])?;
        let a_vb = self.add_fp6(region, &a.coefficients[0], &vb)?;
        let real = self.mul_fp6(region, &sum, &a_vb)?;
        let real = self.sub_fp6(region, &real, &ab)?;
        let vab = self.mul_fp6_nonresidue(region, &ab)?;
        let real = self.sub_fp6(region, &real, &vab)?;
        let imaginary = self.add_fp6(region, &ab, &ab)?;
        Ok(Fp12Value::from_coefficients([real, imaginary]))
    }
    /// Constrain Fp12 conjugation `c0 - c1 w` (the sixth Frobenius power).
    /// # Errors
    /// Returns base-field layout errors.
    pub fn conjugate_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
    ) -> Result<Fp12Value<F>, Error> {
        Ok(Fp12Value::from_coefficients([
            a.coefficients[0].clone(),
            self.neg_fp6(region, &a.coefficients[1])?,
        ]))
    }
    /// Constrain a nonzero Fp12 inverse through its Fp6 norm.
    /// # Errors
    /// Returns layout errors; zero has no satisfying inverse.
    pub fn invert_fp12(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
    ) -> Result<Fp12Value<F>, Error> {
        let aa = self.square_fp6(region, &a.coefficients[0])?;
        let bb = self.square_fp6(region, &a.coefficients[1])?;
        let bb = self.mul_fp6_nonresidue(region, &bb)?;
        let denominator = self.sub_fp6(region, &aa, &bb)?;
        let inverse = self.invert_fp6(region, &denominator)?;
        let real = self.mul_fp6(region, &a.coefficients[0], &inverse)?;
        let imaginary = self.mul_fp6(region, &a.coefficients[1], &inverse)?;
        Ok(Fp12Value::from_coefficients([
            real,
            self.neg_fp6(region, &imaginary)?,
        ]))
    }
    /// Require equality of all twelve canonical base-field coefficients.
    /// # Errors
    /// Returns copy-constraint errors; unequal values are unsatisfiable.
    pub fn assert_equal_fp12(
        region: &mut Region<'_, F>,
        a: &Fp12Value<F>,
        b: &Fp12Value<F>,
    ) -> Result<(), Error> {
        Self::assert_equal_fp6(region, &a.coefficients[0], &b.coefficients[0])?;
        Self::assert_equal_fp6(region, &a.coefficients[1], &b.coefficients[1])
    }
}

#[cfg(test)]
#[path = "extension_tests.rs"]
mod tests;
