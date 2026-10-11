//! GLV variable-base multiplication: the split check, the chain, Horner
//! chains and multi-scalar multiplication (layout and soundness argument in
//! the module documentation of [`crate::ecc`]).

use ff::PrimeField;
use iroha_pasta::{PastaCurve, PastaField};
use iroha_plonk::frontend::{Error, Region, Value};

use super::{
    AssignedPoint, EccChip, GLV_CHAIN_ROWS, GLV_GUARDED_CHAIN_ROWS, GLV_SPLIT_ROWS,
    NonIdentityPoint,
    native::{
        ChainWitness, GLV_B2_HIGH_PREFIX, GLV_INCOMPLETE_ITERATIONS, GLV_ITERATIONS, GlvHalves,
        chain_witness, glv_halves, scalar_from_limbs, split_witness,
    },
};
use crate::{
    cells::{U128, Uint, Word},
    range::RunningSumChip,
    statement::ForeignScalar,
};

/// Range-check widths of the split's own cells: `h0`, `h1`, `u_lo`, `u_hi`
/// and `v + 2^67`.
pub(super) const SPLIT_RANGES: [usize; 5] = [8, 119, 64, 66, 68];

/// A scalar given as limbs `W = lo + 2^128 hi` with `lo < 2^128` and
/// `hi < 2^127` (their range checks are carried by the types); every
/// multiplication reads it modulo the curve order `r`.
///
/// The canonical encodings of spec S6 ([`ForeignScalar`]) convert into it:
/// a foreign scalar (`W < r`) or the canonical limbs of a word of the
/// circuit field (`W < p_N`, so `W mod r` is the PIPA-R challenge map).
#[derive(Clone, Copy, Debug)]
pub struct ScalarLimbs<'a, F: PastaField> {
    lo: &'a U128<F>,
    hi: &'a Uint<F, 127>,
}

impl<'a, F: PastaField> ScalarLimbs<'a, F> {
    /// The scalar `lo + 2^128 hi`.
    #[must_use]
    pub const fn new(lo: &'a U128<F>, hi: &'a Uint<F, 127>) -> Self {
        Self { lo, hi }
    }

    /// The low limb.
    #[must_use]
    pub const fn lo(&self) -> &'a U128<F> {
        self.lo
    }

    /// The high limb.
    #[must_use]
    pub const fn hi(&self) -> &'a Uint<F, 127> {
        self.hi
    }

    /// The limbs `[lo, hi]`.
    #[must_use]
    pub fn value(&self) -> Value<[u128; 2]> {
        self.lo
            .value()
            .zip(self.hi.value())
            .map(|(lo, hi)| [lo, hi])
    }
}

impl<'a, F: PastaField> From<&'a ForeignScalar<F>> for ScalarLimbs<'a, F> {
    fn from(scalar: &'a ForeignScalar<F>) -> Self {
        Self::new(scalar.lo(), scalar.hi())
    }
}

/// A checked GLV split of a scalar, reusable by further multiplications
/// with the same scalar ([`EccChip::mul_with`]).
///
/// It exists only once a chain consumed it: the ranges of `B1`, `B2` and
/// `floor(B2 / 2^63)` that the split check relies on come from that chain's
/// running sums, and every later chain copies the same cells.
#[derive(Clone, Debug)]
pub struct GlvScalar<F: PastaField> {
    f1: Word<F>,
    b1: Word<F>,
    f2: Word<F>,
    b2: Word<F>,
    b2_high: Word<F>,
    halves: Value<GlvHalves>,
}

impl<F: PastaField> GlvScalar<F> {
    /// The split (`B1, f1, B2, f2`).
    #[must_use]
    pub fn halves(&self) -> Value<GlvHalves> {
        self.halves
    }

    /// The digit words `B1, B2` (for inventory and tests).
    #[must_use]
    pub const fn digit_words(&self) -> [&Word<F>; 2] {
        [&self.b1, &self.b2]
    }
}

/// A multiplication's result and its checked split.
pub type MulOutput<F> = (AssignedPoint<F>, GlvScalar<F>);

/// One term `(W_i, P_i)` of [`EccChip::msm`].
pub type MsmTerm<'a, F> = (ScalarLimbs<'a, F>, &'a AssignedPoint<F>);

/// A chain's result and the cells its split links to.
type ChainOutput<F> = (AssignedPoint<F>, ChainLinks<F>);

/// The chain cells a split links to.
#[derive(Debug)]
struct ChainLinks<F: PastaField> {
    f1: Word<F>,
    b1: Word<F>,
    f2: Word<F>,
    b2: Word<F>,
    b2_high: Word<F>,
}

/// A boolean as a field element.
fn bit_field<F: PastaField>(bit: bool) -> F {
    if bit { F::ONE } else { F::ZERO }
}

/// The honest split of a scalar given as limbs.
fn honest_halves<C: PastaCurve>(
    scalar: ScalarLimbs<'_, C::Base>,
) -> Result<Value<GlvHalves>, Error> {
    let halves = scalar
        .value()
        .map(|limbs| glv_halves::<C>(&scalar_from_limbs(limbs)));
    halves.error_if_known_and(Option::is_none)?;
    Ok(halves.and_then(|halves| halves.map_or_else(Value::unknown, Value::known)))
}

impl<C: PastaCurve> EccChip<C> {
    /// `[W mod r] P` for an input that may be the identity (guarded: the
    /// generator is multiplied and the result replaced by `O`). Returns the
    /// result and the checked split for [`Self::mul_with`].
    ///
    /// Lays out the split check (three rows and five range checks on
    /// `range`) and one guarded chain.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout; [`Error::Synthesis`] if the native split
    /// failed (excluded by the lattice constants).
    pub fn mul(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        scalar: ScalarLimbs<'_, C::Base>,
        point: &AssignedPoint<C::Base>,
    ) -> Result<MulOutput<C::Base>, Error> {
        let halves = honest_halves::<C>(scalar)?;
        self.mul_split(region, range, scalar, point, true, halves)
    }

    /// `[W mod r] P` for a non-identity input (no guard).
    ///
    /// # Errors
    ///
    /// As [`Self::mul`].
    pub fn mul_non_identity(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        scalar: ScalarLimbs<'_, C::Base>,
        point: &NonIdentityPoint<C::Base>,
    ) -> Result<MulOutput<C::Base>, Error> {
        let halves = honest_halves::<C>(scalar)?;
        self.mul_split(region, range, scalar, point.point(), false, halves)
    }

    /// `[W mod r] P` reusing the split of an earlier multiplication by the
    /// same scalar (guarded input; one chain, no split rows).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn mul_with(
        &mut self,
        region: &mut Region<'_, C::Base>,
        scalar: &GlvScalar<C::Base>,
        point: &AssignedPoint<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let (out, links) = self.chain(region, point, true, scalar.halves)?;
        Self::link(region, scalar, &links)?;
        Ok(out)
    }

    /// [`Self::mul_with`] for a non-identity input (no guard).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn mul_non_identity_with(
        &mut self,
        region: &mut Region<'_, C::Base>,
        scalar: &GlvScalar<C::Base>,
        point: &NonIdentityPoint<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let (out, links) = self.chain(region, point.point(), false, scalar.halves)?;
        Self::link(region, scalar, &links)?;
        Ok(out)
    }

    /// The identity-guarded Horner chain `sum_i x^i P_i`
    /// (`P_{n-1}` first): `acc = [x] acc + P_i` with guarded multiplications
    /// sharing one split and complete joins, each read in place.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for no points, and [`Error`] from the layout.
    pub fn horner(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        x: ScalarLimbs<'_, C::Base>,
        points: &[AssignedPoint<C::Base>],
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let (last, rest) = points.split_last().ok_or(Error::Synthesis)?;
        let mut acc = last.clone();
        let mut split: Option<GlvScalar<C::Base>> = None;
        for point in rest.iter().rev() {
            let product = if let Some(split) = &split {
                self.mul_with(region, split, &acc)?
            } else {
                let (product, checked) = self.mul(region, range, x, &acc)?;
                split = Some(checked);
                product
            };
            acc = self.add(region, point, &product)?;
        }
        Ok(acc)
    }

    /// `sum_i [W_i mod r] P_i` with guarded multiplications and complete
    /// additions (the identity for no terms).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn msm(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        terms: &[MsmTerm<'_, C::Base>],
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let mut acc: Option<AssignedPoint<C::Base>> = None;
        for (scalar, point) in terms {
            let (product, _) = self.mul(region, range, *scalar, point)?;
            acc = Some(match acc {
                Some(acc) => self.add(region, &acc, &product)?,
                None => product,
            });
        }
        acc.map_or_else(|| self.constant_point(region, &C::identity()), Ok)
    }

    /// The split check and one chain with the given split (honest, or forced
    /// by tests). The split rows go first unless the input is the pending
    /// result, so the chain's result stays pending for a following join.
    pub(super) fn mul_split(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        scalar: ScalarLimbs<'_, C::Base>,
        point: &AssignedPoint<C::Base>,
        guarded: bool,
        halves: Value<GlvHalves>,
    ) -> Result<MulOutput<C::Base>, Error> {
        if self.is_pending(point) {
            let (out, links) = self.chain(region, point, guarded, halves)?;
            let split = self.split(region, range, scalar, halves)?;
            Self::link(region, &split, &links)?;
            Ok((out, split))
        } else {
            let split = self.split(region, range, scalar, halves)?;
            let (out, links) = self.chain(region, point, guarded, halves)?;
            Self::link(region, &split, &links)?;
            Ok((out, split))
        }
    }

    /// Copy-constrains a chain's digit cells to a split.
    fn link(
        region: &mut Region<'_, C::Base>,
        split: &GlvScalar<C::Base>,
        links: &ChainLinks<C::Base>,
    ) -> Result<(), Error> {
        for (left, right) in [
            (&split.f1, &links.f1),
            (&split.b1, &links.b1),
            (&split.f2, &links.f2),
            (&split.b2, &links.b2),
            (&split.b2_high, &links.b2_high),
        ] {
            region.constrain_equal(left.cell(), right.cell())?;
        }
        Ok(())
    }

    /// The split check: three rows of `a0..a3` and range checks of `h0`,
    /// `h1`, `u_lo`, `u_hi` and `v + 2^67`.
    fn split(
        &mut self,
        region: &mut Region<'_, C::Base>,
        range: &mut RunningSumChip<C::Base>,
        scalar: ScalarLimbs<'_, C::Base>,
        halves: Value<GlvHalves>,
    ) -> Result<GlvScalar<C::Base>, Error> {
        let (start, _) = self.begin(GLV_SPLIT_ROWS, None)?;
        let witness = scalar
            .value()
            .zip(halves)
            .map(|(limbs, halves)| split_witness::<C>(limbs, &halves));
        let middle = start + 1;
        let last = start + 2;
        self.config.selectors.split.enable(region, middle)?;
        let f1 = self.assign(region, 0, start, halves.map(|h| bit_field(h.f1)))?;
        let b1 = self.assign(region, 1, start, halves.map(|h| C::Base::from_u128(h.b1)))?;
        let f2 = self.assign(region, 2, start, halves.map(|h| bit_field(h.f2)))?;
        let b2 = self.assign(region, 3, start, halves.map(|h| C::Base::from_u128(h.b2)))?;
        let b2_high = self.assign(region, 0, middle, witness.map(|w| w.b2_high))?;
        self.copy(region, scalar.lo.word(), 1, middle)?;
        self.copy(region, scalar.hi.word(), 2, middle)?;
        let h0 = self.assign(region, 3, middle, witness.map(|w| w.h0))?;
        let h1 = self.assign(region, 0, last, witness.map(|w| w.h1))?;
        let u_low = self.assign(region, 1, last, witness.map(|w| w.u_low))?;
        let u_high = self.assign(region, 2, last, witness.map(|w| w.u_high))?;
        let v_shifted = self.assign(region, 3, last, witness.map(|w| w.v_shifted))?;
        for (word, bits) in [&h0, &h1, &u_low, &u_high, &v_shifted]
            .into_iter()
            .zip(SPLIT_RANGES)
        {
            range.range_check(region, word, bits)?;
        }
        Ok(GlvScalar {
            f1,
            b1,
            f2,
            b2,
            b2_high,
            halves,
        })
    }

    /// One chain (module documentation, "Layout") from its first row: init,
    /// incomplete iterations, complete iterations, correction and the
    /// guarded output. Returns the result (pending) and the digit cells.
    fn chain(
        &mut self,
        region: &mut Region<'_, C::Base>,
        input: &AssignedPoint<C::Base>,
        guarded: bool,
        halves: Value<GlvHalves>,
    ) -> Result<ChainOutput<C::Base>, Error> {
        let witness = input
            .value()
            .zip(halves)
            .map(|(input, halves)| chain_witness::<C>(input, &halves));
        witness.error_if_known_and(Option::is_none)?;
        let witness: Value<ChainWitness<C::Base>> =
            witness.and_then(|witness| witness.map_or_else(Value::unknown, Value::known));
        let w = witness.as_ref();
        let rows = if guarded {
            GLV_GUARDED_CHAIN_ROWS
        } else {
            GLV_CHAIN_ROWS
        };
        let (start, in_place) = self.begin(rows + 1, Some(input))?;
        let selectors = self.config.selectors;
        // Init row.
        if guarded {
            selectors.init_guarded.enable(region, start)?;
        } else {
            selectors.init.enable(region, start)?;
        }
        if !in_place {
            self.copy_point(region, input, 2, start)?;
        }
        self.assign(region, 4, start, w.map(|w| w.lambda_double))?;
        self.assign(region, 5, start, w.map(|w| w.lambda_minus))?;
        let is_identity = if guarded {
            let bit = self.assign(region, 0, start, w.map(|w| bit_field(w.is_identity)))?;
            self.assign(region, 1, start, w.map(|w| w.inverse))?;
            Some(bit)
        } else {
            None
        };
        // Iteration rows `start + 1 + j`, `j = 0..=128`.
        let mut handoff = None;
        let mut tail_points = Vec::with_capacity(GLV_ITERATIONS - GLV_INCOMPLETE_ITERATIONS);
        let mut digits = None;
        let mut b2_high = None;
        for j in 0..=GLV_ITERATIONS {
            let row = start + 1 + j;
            let y1 = self.assign(region, 2, row, w.map(|w| w.running[0][j]))?;
            let y2 = self.assign(region, 3, row, w.map(|w| w.running[1][j]))?;
            self.assign(region, 6, row, w.map(|w| w.base.0))?;
            self.assign(region, 7, row, w.map(|w| w.base.1))?;
            self.assign(region, 8, row, w.map(|w| w.minus.0))?;
            self.assign(region, 9, row, w.map(|w| w.minus.1))?;
            if j <= GLV_INCOMPLETE_ITERATIONS {
                let acc = self.assign_point(region, 0, row, w.map(|w| w.acc[j]))?;
                if j == GLV_INCOMPLETE_ITERATIONS {
                    handoff = Some(acc);
                }
            } else {
                let index = j - GLV_INCOMPLETE_ITERATIONS - 1;
                tail_points.push(self.assign_point(
                    region,
                    0,
                    row,
                    w.map(|w| w.tail_points[index]),
                )?);
            }
            if j < GLV_INCOMPLETE_ITERATIONS {
                selectors.incomplete.enable(region, row)?;
                self.assign(region, 4, row, w.map(|w| w.lambdas[j].0))?;
                self.assign(region, 5, row, w.map(|w| w.lambdas[j].1))?;
            } else if j < GLV_ITERATIONS {
                selectors.select.enable(region, row)?;
            } else {
                selectors.tail.enable(region, row)?;
                digits = Some((y1.clone(), y2.clone()));
            }
            if j == GLV_B2_HIGH_PREFIX {
                b2_high = Some(y2);
            }
        }
        let (Some(handoff), Some((b1, b2)), Some(b2_high)) = (handoff, digits, b2_high) else {
            return Err(Error::Synthesis);
        };
        // Correction row: `-E` and the low bits.
        let correction_row = start + GLV_ITERATIONS + 2;
        let minus_e = self.assign_point(region, 0, correction_row, w.map(|w| w.minus_e))?;
        let f1 = self.assign(region, 2, correction_row, halves.map(|h| bit_field(h.f1)))?;
        let f2 = self.assign(region, 3, correction_row, halves.map(|h| bit_field(h.f2)))?;
        // Complete additions: `acc + T_124`, `acc + R`, then per iteration
        // `T_j + acc` and `acc + R` with the accumulator in place, then
        // `-E + acc`.
        let mut row = correction_row + 1;
        let add = |index: usize| w.map(move |w| w.adds[index]);
        self.copy_point(region, &handoff, 0, row)?;
        let first = tail_points.first().ok_or(Error::Synthesis)?;
        self.copy_point(region, first, 2, row)?;
        self.add_cells(region, row, add(0))?;
        row += 1;
        self.copy_point(region, &handoff, 0, row)?;
        let mut acc = self.add_cells(region, row, add(1))?;
        row += 1;
        for (iteration, point) in tail_points.iter().enumerate().skip(1) {
            self.copy_point(region, point, 0, row)?;
            self.add_cells(region, row, add(2 * iteration))?;
            row += 1;
            self.copy_point(region, &acc, 0, row)?;
            acc = self.add_cells(region, row, add(2 * iteration + 1))?;
            row += 1;
        }
        self.copy_point(region, &minus_e, 0, row)?;
        let mut out = self.add_cells(region, row, add(2 * tail_points.len()))?;
        row += 1;
        if let Some(is_identity) = is_identity {
            selectors.guard_out.enable(region, row)?;
            self.copy(region, &is_identity, 0, row)?;
            out = self.assign_point(region, 2, row + 1, w.map(|w| w.output))?;
            row += 1;
        }
        if row != start + rows {
            return Err(Error::Synthesis);
        }
        self.pending = Some(row);
        Ok((
            out,
            ChainLinks {
                f1,
                b1,
                f2,
                b2,
                b2_high,
            },
        ))
    }
}
