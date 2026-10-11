//! In-circuit P-256 arithmetic on the FF-CRT chip: limb-wise linear
//! combinations with automatic padding, soft (bit-valued) tests and the
//! affine group operations of the verifier.
//!
//! # Linear combinations
//!
//! [`Arith::lin`] computes `sum c_j v_j + k` for small signed integer
//! coefficients limb by limb on the glue chip (one row per limb for up to
//! three terms). Negative terms are offset by the smallest multiple `K` of
//! the modulus whose limbs dominate them ([`ForeignModulus::padding`]), so
//! every result limb is a nonnegative integer below its tracked bound; an
//! operand is reduced first when the result would leave the operand
//! envelope. The result is congruent to the combination.
//!
//! # Soft tests
//!
//! - [`Arith::is_zero_mod`]: `[v = 0 (mod m)]` for any value, with a witness
//!   `w'`, a bit `z`, `w = z ? 1 : w'` and one multiplication whose result
//!   must be exactly `(1 - z, 0, 0)`: `z = 1` forces `v = 0 (mod m)`,
//!   `z = 0` forces `v w' = 1 (mod m)`, so `z` is unique.
//! - [`Arith::soft_le`]: `[x <= M]` for a proper `x` and a constant
//!   `M < 2^256`: a proper witness `d` with `x + d = M + 2^256 (1 - c)`
//!   checked limb-wise with one boolean carry (all sums below `2^176`, so
//!   the field equations are integer equations). `d < 2^256` makes `c`
//!   unique.
//! - [`Arith::is_nonzero`]: `[x != 0]` for a proper `x` (its limbs are its
//!   unique representation).
//!
//! # Group operations
//!
//! Points are affine with coordinates modulo `p` in any form. The
//! incomplete operations ([`Arith::double`], [`Arith::add`],
//! [`Arith::double_add`]) are sound wherever their denominators are
//! nonzero (each slope is then determined) and are used only where the
//! scalar structure proves that (module documentation of
//! [`super`]). [`Arith::complete_add`] handles the identity, equal and
//! opposite inputs with two soft zero tests; the identity carries the
//! generator's coordinates as a default.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

use super::native::{self, B, GX, GY, MontModulus};
use crate::{
    arith::GlueChip,
    cells::{Bit, Word},
    ff::{
        FfChip, FfValue, ForeignModulus, Form, LIMB_BITS, LIMBS, Nat, PROPER_BOUNDS, to_limbs,
        value_bound, within_envelope,
    },
};

/// Canonical constant values cached per chip (cells are global, so one
/// constant serves every later operation).
#[derive(Clone, Debug, Default)]
pub struct Constants<F: PastaField> {
    entries: Vec<(ForeignModulus, [u64; 4], FfValue<F>)>,
}

/// An affine P-256 point other than the identity, coordinates modulo `p`.
#[derive(Clone, Debug)]
pub struct P256Point<F: PastaField> {
    x: FfValue<F>,
    y: FfValue<F>,
}

impl<F: PastaField> P256Point<F> {
    /// Wraps coordinates that the caller proved on the curve (or derived
    /// from such points by the group law).
    pub(crate) const fn new(x: FfValue<F>, y: FfValue<F>) -> Self {
        Self { x, y }
    }

    /// `x` (any form).
    #[must_use]
    pub const fn x(&self) -> &FfValue<F> {
        &self.x
    }

    /// `y` (any form).
    #[must_use]
    pub const fn y(&self) -> &FfValue<F> {
        &self.y
    }
}

/// A point that may be the identity: the identity bit (`None` when the
/// point is known not to be the identity) and, for the identity, the
/// generator's coordinates.
#[derive(Clone, Debug)]
pub struct MaybePoint<F: PastaField> {
    point: P256Point<F>,
    identity: Option<Bit<F>>,
}

impl<F: PastaField> MaybePoint<F> {
    /// A point known not to be the identity.
    pub(crate) const fn known(point: P256Point<F>) -> Self {
        Self {
            point,
            identity: None,
        }
    }

    /// The coordinates (the generator's when this is the identity).
    #[must_use]
    pub const fn point(&self) -> &P256Point<F> {
        &self.point
    }

    /// The identity bit (`None`: never the identity).
    #[must_use]
    pub const fn identity(&self) -> Option<&Bit<F>> {
        self.identity.as_ref()
    }
}

/// `p - k` for a small `k` (the canonical residue of `-k`).
fn minus_words(modulus: &MontModulus, value: &[u64; 4]) -> [u64; 4] {
    modulus.neg(value)
}

/// `c` as a field element.
fn coefficient<F: PastaField>(c: i64) -> F {
    let magnitude = F::from(c.unsigned_abs());
    if c < 0 { -magnitude } else { magnitude }
}

/// The Montgomery constants of a P-256 modulus.
fn mont_of(modulus: ForeignModulus) -> Option<&'static MontModulus> {
    if modulus == ForeignModulus::P256_BASE {
        Some(&native::BASE)
    } else if modulus == ForeignModulus::P256_ORDER {
        Some(&native::ORDER)
    } else {
        None
    }
}

/// The inverse of a residue (0 for 0), constant time.
fn inverse_words(modulus: ForeignModulus, residue: &Nat) -> [u64; 4] {
    let words = residue.low_words();
    mont_of(modulus).map_or_else(
        || modulus.fermat_inverse(residue).low_words(),
        |mont| mont.inverse(&words),
    )
}

/// The arithmetic context: the foreign-field and glue chips and the
/// constant cache.
#[derive(Debug)]
pub struct Arith<'a, F: PastaField> {
    /// The foreign-field chip.
    pub ff: &'a mut FfChip<F>,
    /// The glue chip.
    pub glue: &'a mut GlueChip<F>,
    /// The constant cache.
    pub constants: &'a mut Constants<F>,
}

/// The padding and result bounds of a linear combination, or `None` when a
/// bound overflows or no padding exists.
fn lin_bounds(
    coefficients: &[i64],
    values: &[FfValue<impl PastaField>],
    modulus: ForeignModulus,
    constant: &[u128; LIMBS],
) -> Option<([u128; LIMBS], [u128; LIMBS])> {
    let mut floors = [0_u128; LIMBS];
    let mut positive = [0_u128; LIMBS];
    for (c, value) in coefficients.iter().zip(values) {
        let magnitude = u128::from(c.unsigned_abs());
        for (index, bound) in value.bounds().iter().enumerate() {
            let term = bound.checked_mul(magnitude)?;
            if *c < 0 {
                floors[index] = floors[index].checked_add(term)?;
            } else {
                positive[index] = positive[index].checked_add(term)?;
            }
        }
    }
    let padding = if floors == [0; LIMBS] {
        [0; LIMBS]
    } else {
        modulus.padding(&floors)?.1
    };
    let mut constants = [0_u128; LIMBS];
    let mut bounds = [0_u128; LIMBS];
    for index in 0..LIMBS {
        constants[index] = padding[index].checked_add(constant[index])?;
        bounds[index] = positive[index].checked_add(constants[index])?;
    }
    Some((constants, bounds))
}

impl<F: PastaField> Arith<'_, F> {
    /// A canonical constant (cached).
    ///
    /// # Errors
    ///
    /// As [`FfChip::constant`].
    pub fn constant(
        &mut self,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
        value: &[u64; 4],
    ) -> Result<FfValue<F>, Error> {
        if let Some((_, _, cached)) = self
            .constants
            .entries
            .iter()
            .find(|(m, words, _)| *m == modulus && words == value)
        {
            return Ok(cached.clone());
        }
        let created = self
            .ff
            .constant(self.glue, region, modulus, &Nat::from_words(*value))?;
        self.constants
            .entries
            .push((modulus, *value, created.clone()));
        Ok(created)
    }

    /// `sum c_j v_j + constant` (congruent, bounded form); `constant < m`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for no terms, mixed moduli or a combination no
    /// reduction brings into the envelope, and [`Error`] from the layout.
    pub fn lin(
        &mut self,
        region: &mut Region<'_, F>,
        terms: &[(i64, &FfValue<F>)],
        constant: &[u64; 4],
    ) -> Result<FfValue<F>, Error> {
        let Some((_, first)) = terms.first() else {
            return Err(Error::Synthesis);
        };
        let modulus = first.modulus();
        if terms.iter().any(|(_, value)| value.modulus() != modulus) {
            return Err(Error::Synthesis);
        }
        if terms.len() == 1 && terms[0].0 == 1 && native::words_is_zero(constant) {
            return Ok(terms[0].1.clone());
        }
        let constant_limbs = to_limbs(&Nat::from_words(*constant)).ok_or(Error::Synthesis)?;
        let coefficients: Vec<i64> = terms.iter().map(|(c, _)| *c).collect();
        let mut values: Vec<FfValue<F>> = terms.iter().map(|(_, value)| (*value).clone()).collect();
        for _ in 0..=values.len() {
            if let Some((constants, bounds)) =
                lin_bounds(&coefficients, &values, modulus, &constant_limbs)
                && within_envelope(&bounds)
            {
                return self.emit(region, &coefficients, &values, constants, bounds);
            }
            // Reduce the non-proper term with the largest contribution.
            let candidate = values
                .iter()
                .zip(&coefficients)
                .enumerate()
                .filter(|(_, (value, _))| value.form() < Form::Proper)
                .max_by(|(_, (a, ca)), (_, (b, cb))| {
                    let weight = |value: &FfValue<F>, c: i64| {
                        value_bound(&value.bounds()).wrapping_mul(&Nat::from_u64(c.unsigned_abs()))
                    };
                    weight(a, **ca).cmp_vartime(&weight(b, **cb))
                })
                .map(|(index, _)| index);
            let Some(index) = candidate else {
                return Err(Error::Synthesis);
            };
            values[index] = self.ff.reduce(region, &values[index])?;
        }
        Err(Error::Synthesis)
    }

    /// Lays out the limb rows of a checked linear combination.
    fn emit(
        &mut self,
        region: &mut Region<'_, F>,
        coefficients: &[i64],
        values: &[FfValue<F>],
        constants: [u128; LIMBS],
        bounds: [u128; LIMBS],
    ) -> Result<FfValue<F>, Error> {
        let modulus = values.first().ok_or(Error::Synthesis)?.modulus();
        let mut words = Vec::with_capacity(LIMBS);
        for (index, constant) in constants.iter().enumerate() {
            let terms: Vec<(F, &Word<F>)> = coefficients
                .iter()
                .zip(values)
                .map(|(c, value)| (coefficient::<F>(*c), &value.limbs()[index]))
                .collect();
            words.push(self.linear_chain(region, &terms, F::from_u128(*constant))?);
        }
        let words: [Word<F>; LIMBS] = words.try_into().map_err(|_| Error::Synthesis)?;
        Ok(FfValue::from_parts(words, bounds, modulus, Form::Bounded))
    }

    /// `sum c_j w_j + k` over any number of terms: three per glue row, then
    /// two more per row on the running total.
    fn linear_chain(
        &mut self,
        region: &mut Region<'_, F>,
        terms: &[(F, &Word<F>)],
        constant: F,
    ) -> Result<Word<F>, Error> {
        let (head, mut rest) = terms.split_at(terms.len().min(3));
        let mut total = self.glue.linear(region, head, constant)?;
        while !rest.is_empty() {
            let (next, tail) = rest.split_at(rest.len().min(2));
            let mut row: Vec<(F, &Word<F>)> = vec![(F::ONE, &total)];
            row.extend_from_slice(next);
            total = self.glue.linear(region, &row, F::ZERO)?;
            rest = tail;
        }
        Ok(total)
    }

    /// `bit ? a : b` (limb-wise).
    ///
    /// # Errors
    ///
    /// As [`FfChip::select`].
    pub fn select(
        &mut self,
        region: &mut Region<'_, F>,
        bit: &Bit<F>,
        a: &FfValue<F>,
        b: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.ff.select(self.glue, region, bit, a, b)
    }

    /// `bit ? a : b` for bits (a bit).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn select_bit(
        &mut self,
        region: &mut Region<'_, F>,
        bit: &Bit<F>,
        a: &Bit<F>,
        b: &Bit<F>,
    ) -> Result<Bit<F>, Error> {
        // A selection between bits is a bit.
        self.glue
            .select(region, bit, a.word(), b.word())
            .map(Bit::new)
    }

    /// `[v = 0 (mod m)]` for any value `v` (module documentation).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn is_zero_mod(
        &mut self,
        region: &mut Region<'_, F>,
        v: &FfValue<F>,
    ) -> Result<Bit<F>, Error> {
        let modulus = v.modulus();
        let residue = v.residue();
        // The OR of the words is zero exactly for the zero residue (no
        // early exit on the secret words).
        let zero = residue.map(|residue| {
            residue
                .low_words()
                .iter()
                .fold(0_u64, |acc, word| acc | word)
                == 0
        });
        let inverse = residue.map(|residue| inverse_words(modulus, &residue));
        self.is_zero_mod_witnessed(region, v, zero, inverse)
    }

    /// [`Self::is_zero_mod`] with the prover's bit `zero` and inverse
    /// witness `inverse` (the honest values come from
    /// [`Self::is_zero_mod`]; adversarial tests pass others, which must be
    /// unsatisfiable).
    pub(crate) fn is_zero_mod_witnessed(
        &mut self,
        region: &mut Region<'_, F>,
        v: &FfValue<F>,
        zero: Value<bool>,
        inverse: Value<[u64; 4]>,
    ) -> Result<Bit<F>, Error> {
        let modulus = v.modulus();
        let w_free = self.ff.witness(region, modulus, inverse)?;
        let bit = self.glue.boolean(region, zero)?;
        let one = self.constant(region, modulus, &[1, 0, 0, 0])?;
        let w = self.select(region, &bit, &one, &w_free)?;
        let product = self.ff.mul(region, v, &w)?;
        let [c0, c1, c2] = product.limbs();
        let low = self
            .glue
            .linear(region, &[(F::ONE, c0), (F::ONE, bit.word())], -F::ONE)?;
        region.constrain_constant(low.cell(), F::ZERO)?;
        region.constrain_constant(c1.cell(), F::ZERO)?;
        region.constrain_constant(c2.cell(), F::ZERO)?;
        Ok(bit)
    }

    /// `[x <= bound]` for a proper `x` and a constant `bound < 2^256`
    /// (module documentation).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `x` is not proper, and [`Error`] from the
    /// layout.
    pub fn soft_le(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        bound: &[u64; 4],
    ) -> Result<Bit<F>, Error> {
        if x.form() < Form::Proper || x.bounds().iter().zip(PROPER_BOUNDS).any(|(b, p)| *b > p) {
            return Err(Error::Synthesis);
        }
        let bound_nat = Nat::from_words(*bound);
        let integer = x.integer();
        // d = (bound - x) mod 2^256; the subtraction borrows iff x > bound.
        let difference = integer.map(|x| bound_nat.overflowing_sub(&x));
        let d_words = difference.map(|(d, _)| d.low_words());
        let c_value = difference.map(|(_, borrow)| !borrow);
        // The carry of the low two limbs: bit 174 of `x mod 2^174 + d mod 2^174`.
        let low = |value: &Nat| value.wrapping_sub(&value.shr(2 * LIMB_BITS).shl(2 * LIMB_BITS));
        let carry = integer.zip(d_words).map(|(x, d)| {
            low(&x)
                .wrapping_add(&low(&Nat::from_words(d)))
                .bit(2 * LIMB_BITS)
        });
        self.soft_le_witnessed(region, x, bound, d_words, carry, c_value)
    }

    /// [`Self::soft_le`] with the prover's difference `d`, low carry `k1`
    /// and verdict `c` (the honest values come from [`Self::soft_le`];
    /// adversarial tests pass others, which must be unsatisfiable unless
    /// they are the honest ones).
    pub(crate) fn soft_le_witnessed(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        bound: &[u64; 4],
        d_words: Value<[u64; 4]>,
        carry: Value<bool>,
        c_value: Value<bool>,
    ) -> Result<Bit<F>, Error> {
        if x.form() < Form::Proper || x.bounds().iter().zip(PROPER_BOUNDS).any(|(b, p)| *b > p) {
            return Err(Error::Synthesis);
        }
        let modulus = x.modulus();
        let limits = to_limbs(&Nat::from_words(*bound)).ok_or(Error::Synthesis)?;
        let difference = self.ff.witness(region, modulus, d_words)?;
        let carry = self.glue.boolean(region, carry)?;
        let verdict = self.glue.boolean(region, c_value)?;
        let [x0, x1, x2] = x.limbs();
        let [d0, d1, d2] = difference.limbs();
        let radix = F::from_u128(1 << LIMB_BITS);
        let radix2 = radix * radix;
        let low_bound = F::from_u128(limits[0]) + F::from_u128(limits[1]) * radix;
        // x_0 + d_0 + B (x_1 + d_1) = M_low + B^2 k_1.
        let partial =
            self.glue
                .linear(region, &[(F::ONE, x0), (F::ONE, d0), (radix, x1)], F::ZERO)?;
        let low_check = self.glue.linear(
            region,
            &[(F::ONE, &partial), (radix, d1), (-radix2, carry.word())],
            -low_bound,
        )?;
        region.constrain_constant(low_check.cell(), F::ZERO)?;
        // x_2 + d_2 + k_1 = M_2 + 2^82 (1 - c).
        let top_sum = self.glue.linear(
            region,
            &[(F::ONE, x2), (F::ONE, d2), (F::ONE, carry.word())],
            F::ZERO,
        )?;
        let top = F::from_u128(1 << (256 - 2 * LIMB_BITS));
        let top_check = self.glue.linear(
            region,
            &[(F::ONE, &top_sum), (top, verdict.word())],
            -(F::from_u128(limits[2]) + top),
        )?;
        region.constrain_constant(top_check.cell(), F::ZERO)?;
        Ok(verdict)
    }

    /// `[x != 0]` for a proper `x`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `x` is not proper, and [`Error`] from the
    /// layout.
    pub fn is_nonzero(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
    ) -> Result<Bit<F>, Error> {
        if x.form() < Form::Proper || x.bounds().iter().zip(PROPER_BOUNDS).any(|(b, p)| *b > p) {
            return Err(Error::Synthesis);
        }
        let [x0, x1, x2] = x.limbs();
        let radix = F::from_u128(1 << LIMB_BITS);
        let low = self
            .glue
            .linear(region, &[(F::ONE, x0), (radix, x1)], F::ZERO)?;
        let low_zero = self.glue.is_zero(region, &low)?;
        let top_zero = self.glue.is_zero(region, x2)?;
        let zero = self.glue.and(region, &low_zero, &top_zero)?;
        self.glue.not(region, &zero)
    }

    /// The canonical residue of `v`: a reduction (unless proper) and a
    /// canonical comparison.
    ///
    /// # Errors
    ///
    /// As [`FfChip::assert_canonical`].
    pub fn canonical(
        &mut self,
        region: &mut Region<'_, F>,
        v: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.ff.assert_canonical(region, v)
    }

    /// The bounds `sum c_j v_j` would get (without laying it out).
    fn predict(terms: &[(i64, &FfValue<F>)]) -> Option<[u128; LIMBS]> {
        let (_, first) = terms.first()?;
        let coefficients: Vec<i64> = terms.iter().map(|(c, _)| *c).collect();
        let values: Vec<FfValue<F>> = terms.iter().map(|(_, value)| (*value).clone()).collect();
        lin_bounds(&coefficients, &values, first.modulus(), &[0; LIMBS]).map(|(_, bounds)| bounds)
    }

    /// `v`, reduced when `v^2` is not an admissible product.
    fn admit_square(
        &mut self,
        region: &mut Region<'_, F>,
        v: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        if FfChip::<F>::mul_admissible(v.modulus(), &v.bounds(), &v.bounds()) {
            Ok(v.clone())
        } else {
            self.ff.reduce(region, v)
        }
    }

    /// Whether `sum c_j v_j` is an admissible divisor.
    fn divisor_admissible(terms: &[(i64, &FfValue<F>)]) -> bool {
        let Some((_, first)) = terms.first() else {
            return false;
        };
        Self::predict(terms)
            .is_some_and(|bounds| FfChip::<F>::div_admissible(first.modulus(), &[1, 0, 0], &bounds))
    }

    /// Whether `factor (sum c_j v_j)` is an admissible product.
    fn factor_admissible(factor: &FfValue<F>, terms: &[(i64, &FfValue<F>)]) -> bool {
        Self::predict(terms).is_some_and(|bounds| {
            FfChip::<F>::mul_admissible(factor.modulus(), &factor.bounds(), &bounds)
        })
    }

    /// `v` reduced unless the predicate holds for it.
    fn admit(
        &mut self,
        region: &mut Region<'_, F>,
        v: &FfValue<F>,
        holds: impl Fn(&FfValue<F>) -> bool,
    ) -> Result<FfValue<F>, Error> {
        if holds(v) {
            Ok(v.clone())
        } else {
            self.ff.reduce(region, v)
        }
    }

    /// `2 P` (incomplete: `P` must not be the identity; P-256 has no point
    /// with `y = 0`).
    ///
    /// Inputs are reduced only where an operation would be inadmissible
    /// (and the reduced values are reused), so the coordinates stay below
    /// the admissible bounds along a chain.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn double(
        &mut self,
        region: &mut Region<'_, F>,
        point: &P256Point<F>,
    ) -> Result<P256Point<F>, Error> {
        let x = self.admit_square(region, &point.x)?;
        let y = self.admit(region, &point.y, |y| Self::divisor_admissible(&[(2, y)]))?;
        let xx = self.ff.square(region, &x)?;
        let minus_three = minus_words(&native::BASE, &[3, 0, 0, 0]);
        let numerator = self.lin(region, &[(3, &xx)], &minus_three)?;
        let denominator = self.lin(region, &[(2, &y)], &[0; 4])?;
        let slope = self.ff.div(region, &numerator, &denominator)?;
        self.chord_output(region, &slope, &x, &x, &y)
    }

    /// The output of a slope `slope` through `(x1, y1)` and a second point
    /// with `x2`: `x3 = slope^2 - x1 - x2`, `y3 = slope (x1 - x3) - y1`.
    /// `x3` is reduced when `slope (x1 - x3)` would not be admissible.
    fn chord_output(
        &mut self,
        region: &mut Region<'_, F>,
        slope: &FfValue<F>,
        x1: &FfValue<F>,
        x2: &FfValue<F>,
        y1: &FfValue<F>,
    ) -> Result<P256Point<F>, Error> {
        let squared = self.ff.square(region, slope)?;
        let x3 = self.lin(region, &[(1, &squared), (-1, x1), (-1, x2)], &[0; 4])?;
        let x3 = self.admit(region, &x3, |x3| {
            Self::factor_admissible(slope, &[(1, x1), (-1, x3)])
        })?;
        let run = self.lin(region, &[(1, x1), (-1, &x3)], &[0; 4])?;
        let rise = self.ff.mul(region, slope, &run)?;
        let y3 = self.lin(region, &[(1, &rise), (-1, y1)], &[0; 4])?;
        Ok(P256Point::new(x3, y3))
    }

    /// `P + Q` (incomplete: `x_P != x_Q`).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn add(
        &mut self,
        region: &mut Region<'_, F>,
        p: &P256Point<F>,
        q: &P256Point<F>,
    ) -> Result<P256Point<F>, Error> {
        let x1 = self.admit(region, &p.x, |x1| {
            Self::divisor_admissible(&[(1, &q.x), (-1, x1)])
        })?;
        let x2 = self.admit(region, &q.x, |x2| {
            Self::divisor_admissible(&[(1, x2), (-1, &x1)])
        })?;
        let rise = self.lin(region, &[(1, &q.y), (-1, &p.y)], &[0; 4])?;
        let run = self.lin(region, &[(1, &x2), (-1, &x1)], &[0; 4])?;
        let slope = self.ff.div(region, &rise, &run)?;
        self.chord_output(region, &slope, &x1, &x2, &p.y)
    }

    /// `2 P + R` as `(P + R) + P` without the `y` of `P + R`
    /// (Eisentraeger-Lauter-Montgomery; incomplete: `P != +-R` and
    /// `P + R != +-P`).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn double_add(
        &mut self,
        region: &mut Region<'_, F>,
        p: &P256Point<F>,
        r: &P256Point<F>,
    ) -> Result<P256Point<F>, Error> {
        let xp = self.admit(region, &p.x, |xp| {
            Self::divisor_admissible(&[(1, &r.x), (-1, xp)])
        })?;
        let xr = self.admit(region, &r.x, |xr| {
            Self::divisor_admissible(&[(1, xr), (-1, &xp)])
        })?;
        let rise = self.lin(region, &[(1, &r.y), (-1, &p.y)], &[0; 4])?;
        let run = self.lin(region, &[(1, &xr), (-1, &xp)], &[0; 4])?;
        let slope = self.ff.div(region, &rise, &run)?;
        let squared = self.ff.square(region, &slope)?;
        let x3 = self.lin(region, &[(1, &squared), (-1, &xp), (-1, &xr)], &[0; 4])?;
        let x3 = self.admit(region, &x3, |x3| {
            Self::divisor_admissible(&[(1, x3), (-1, &xp)])
        })?;
        let gap = self.lin(region, &[(1, &x3), (-1, &xp)], &[0; 4])?;
        let t = self.ff.div(region, &p.y, &gap)?;
        let second = self.lin(region, &[(-1, &slope), (-2, &t)], &[0; 4])?;
        self.chord_output(region, &second, &xp, &x3, &p.y)
    }

    /// `P + Q` for any points, including the identity, equal and opposite
    /// inputs.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn complete_add(
        &mut self,
        region: &mut Region<'_, F>,
        p: &MaybePoint<F>,
        q: &MaybePoint<F>,
    ) -> Result<MaybePoint<F>, Error> {
        let (x1, y1) = (&p.point.x, &p.point.y);
        let (x2, y2) = (&q.point.x, &q.point.y);
        let dx = self.lin(region, &[(1, x2), (-1, x1)], &[0; 4])?;
        let dy = self.lin(region, &[(1, y2), (-1, y1)], &[0; 4])?;
        let equal_x = self.is_zero_mod(region, &dx)?;
        let equal_y = self.is_zero_mod(region, &dy)?;
        let xx = self.ff.square(region, x1)?;
        let minus_three = minus_words(&native::BASE, &[3, 0, 0, 0]);
        let tangent_numerator = self.lin(region, &[(3, &xx)], &minus_three)?;
        let tangent_denominator = self.lin(region, &[(2, y1)], &[0; 4])?;
        let numerator = self.select(region, &equal_x, &tangent_numerator, &dy)?;
        let denominator = self.select(region, &equal_x, &tangent_denominator, &dx)?;
        let slope = self.ff.div(region, &numerator, &denominator)?;
        let sum = self.chord_output(region, &slope, x1, x2, y1)?;
        // Opposite points (equal x, different y) sum to the identity.
        let different_y = self.glue.not(region, &equal_y)?;
        let opposite = self.glue.and(region, &equal_x, &different_y)?;
        let gx = self.constant(region, ForeignModulus::P256_BASE, &GX)?;
        let gy = self.constant(region, ForeignModulus::P256_BASE, &GY)?;
        let mut x = self.select(region, &opposite, &gx, &sum.x)?;
        let mut y = self.select(region, &opposite, &gy, &sum.y)?;
        let mut identity = opposite;
        if let Some(q_identity) = &q.identity {
            // P + O = P (P's flag: 0 here; the P = O case is handled next).
            x = self.select(region, q_identity, x1, &x)?;
            y = self.select(region, q_identity, y1, &y)?;
            let not_q = self.glue.not(region, q_identity)?;
            identity = self.glue.and(region, &not_q, &identity)?;
        }
        if let Some(p_identity) = &p.identity {
            // O + Q = Q, with Q's flag.
            x = self.select(region, p_identity, x2, &x)?;
            y = self.select(region, p_identity, y2, &y)?;
            identity = if let Some(q_identity) = &q.identity {
                self.select_bit(region, p_identity, q_identity, &identity)?
            } else {
                let not_p = self.glue.not(region, p_identity)?;
                self.glue.and(region, &not_p, &identity)?
            };
        }
        Ok(MaybePoint {
            point: P256Point::new(x, y),
            identity: Some(identity),
        })
    }

    /// `[y^2 = x^3 - 3 x + b (mod p)]`.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn on_curve(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        y: &FfValue<F>,
    ) -> Result<Bit<F>, Error> {
        let yy = self.ff.square(region, y)?;
        let xx = self.ff.square(region, x)?;
        let xxx = self.ff.mul(region, &xx, x)?;
        let minus_b = native::BASE.neg(&B);
        let difference = self.lin(region, &[(1, &yy), (-1, &xxx), (3, x)], &minus_b)?;
        self.is_zero_mod(region, &difference)
    }
}
