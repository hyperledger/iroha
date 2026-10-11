//! The Pasta ECC chip: native elliptic-curve arithmetic for in-circuit PIPA
//! verifiers, Pallas in an `Fp` circuit ([`PallasChip`], the A circuits) and
//! Vesta in an `Fq` circuit ([`VestaChip`], the Q and Ω circuits), following
//! the PIPA-R §9.3 rules of the Λ/Ω design (`specs/kagemusha_lambda_omega_v1.md`
//! §7 C7, §9 and the M3 gate G3.5).
//!
//! # Operations
//!
//! - points: [`EccChip::witness_point`] and [`EccChip::constrain_point`]
//!   (on the curve or the identity), [`EccChip::witness_non_identity`] and
//!   [`EccChip::constrain_non_identity`] (on the curve), constants, equality,
//!   and through the glue chip negation, selection and the identity test;
//! - [`EccChip::add`] and [`EccChip::sum`]: complete addition (identity,
//!   equal and opposite inputs included);
//! - [`EccChip::mul`] / [`EccChip::mul_non_identity`]: GLV variable-base
//!   multiplication `[W mod r] P` of a scalar given as limbs
//!   `W = lo + 2^128 hi` ([`ScalarLimbs`]); [`EccChip::mul_with`] reuses
//!   the checked split ([`GlvScalar`]) of an earlier multiplication;
//! - [`EccChip::horner`]: the identity-guarded Horner chain
//!   `sum_i x^i P_i` with complete joins, and [`EccChip::msm`];
//! - [`EccChip::fixed_base_mul`]: 3-bit fixed-base windows with a complete
//!   final window ([`FixedBase`]).
//!
//! # Point encoding
//!
//! A point is two cells `(x, y)`; the identity is `(0, 0)`. `5` is not a
//! square in either Pasta field, so no curve point has `x = 0` and `x = 0`
//! identifies the identity. An [`AssignedPoint`] is constrained on the curve
//! or `(0, 0)` (`(y^2 - x^3 - 5) x = (y^2 - x^3 - 5) y = 0`); a
//! [`NonIdentityPoint`] is constrained on the curve. Both curves have prime
//! order, so every on-curve point is in the group.
//!
//! # Complete addition
//!
//! The halo2 book's complete addition (Orchard) on one row
//! `[x_p, y_p, x_q, y_q, lambda, alpha, beta, gamma, delta]` with the sum in
//! columns `a2, a3` of the next row, plus constraints pinning every inverse
//! witness and the slope in every case (so every cell is determined):
//! `alpha = inv0(x_q - x_p)`, `beta = inv0(x_p)`, `gamma = inv0(x_q)`,
//! `delta = inv0(y_q + y_p)` when `x_q = x_p` (else 0), `lambda = 0` for
//! `O + O`. Degree 6.
//!
//! # GLV multiplication
//!
//! The scalar `W` (any integer below `2^255`) is split as
//! `W = (2^128 + K1) + zeta (2^128 + K2) (mod r)` with `K_j = 2 B_j + f_j`,
//! `B_j < 2^128` and bits `f_j`, so the signed halves `k_j = K_j - 2^128`
//! satisfy `-2^128 <= k_j < 2^128` (the honest split uses the Babai GLV
//! decomposition of `W - 2^129 (1 + zeta)`, `|k_j| < 2^127 + 2^126`).
//! `phi(x, y) = (beta x, y) = [zeta] (x, y)`.
//!
//! The chain starts at `acc_0 = [2] S+` with `S+ = P + phi(P) =
//! (beta^2 x_P, -y_P)` (the fixed top digits `(+1, +1)`), and iteration
//! `j = 0..127` computes `acc_{j+1} = (acc_j + T_j) + acc_j` with
//! `T_j = d1 P + d2 phi(P)`, `d_i = 2 b_i - 1` for the bits of `B1, B2`
//! (most significant first), so `T_j` is one of `+-S+`, `+-S-` with
//! `S- = P - phi(P)`. After 128 iterations the accumulator is
//! `[(2^128 + 2 B1 + 1) + zeta (2^128 + 2 B2 + 1)] P`; the complete
//! correction `-E = -((1 - f1) P + (1 - f2) phi(P))` gives
//! `[(2^128 + K1) + zeta (2^128 + K2)] P = [W] P`.
//!
//! **Exceptional cases.** Write `acc_j = [a_j] P + [b_j] phi(P)`. Then
//! `a_0 = b_0 = 2` and, for any digits, `a_j, b_j` lie in
//! `[2^j + 1, 3 2^j - 1]` for `j >= 1`. An incomplete addition at iteration
//! `j` is exceptional only if `acc_j = +-T_j` or `2 acc_j + T_j = O`, i.e. if
//! the nonzero vector `(a_j -+ d1, b_j -+ d2)` (sup-norm at most `3 2^j`) or
//! `(2 a_j + d1, 2 b_j + d2)` (sup-norm at most `6 2^j - 1`) lies in the GLV
//! lattice `{(x, y) : x + zeta y = 0 (mod r)}`. Its sup-norm minimum is
//! `2^126.21` for both Pasta scalar fields (`native::GLV_INCOMPLETE_ITERATIONS`
//! and the KAT `glv_lattice_sup_norm_minimum_pallas_vesta`), so iterations
//! `j <= 123` are exception-free for every base `P != O` and every digit
//! sequence: incomplete addition there is sound (each slope is determined)
//! and complete. Iterations `124..=127` and the correction use complete
//! addition. This is Orchard's incomplete-addition argument lifted to GLV;
//! the initial `2 S+` and `S-` are exception-free because `y_P != 0` and
//! `x_P != 0`.
//!
//! **Scalar split.** One gate checks the integer identity
//! `X = K1 + zeta K2 + C1 - W - u r = 0` with `C1 = C0 + r`,
//! `C0 = 2^128 (1 + zeta) mod r` and a witness `u = u_lo + 2^64 u_hi`
//! (`u_lo < 2^64`, `u_hi < 2^66`): modulo the circuit modulus `p_N`, and
//! modulo `2^136` through the low limbs `K2 = K2_lo + 2^64 B2_hi`
//! (`B2_hi = floor(B2 / 2^63)`), `hi = h0 + 2^8 h1` (`h0 < 2^8`,
//! `h1 < 2^119`) and a carry `v` (`v + 2^67 < 2^68`). The mod-`2^136` sum
//! stays below `2^205 < p_N` in magnitude, so it holds over the integers;
//! `|X| < 2^387 < p_N 2^136 / 2`, so the two residues give `X = 0`. The
//! ranges of `B1`, `B2` and `B2_hi` come from the chain's running sums,
//! which every chain consuming the split copies (a [`GlvScalar`] exists only
//! after its first chain), and those of `lo`, `hi` from [`ScalarLimbs`].
//!
//! **Identity guard.** [`EccChip::mul`] accepts an input that may be `O`:
//! the init row computes `is_id = [x = 0]`, multiplies the generator instead
//! and the output row replaces the result by `O`.
//!
//! # Layout
//!
//! Ten advice columns `a0..a9`; `a0..a3` are equality-enabled and every copy
//! lands there. Rotations: `a0..a3` at `-1, 0, 1`, `a4, a5` at `0`, `a6..a9`
//! at `0, 1`. Rows of one multiplication, relative to its first row `s`:
//!
//! | rows | content |
//! | --- | --- |
//! | `s` | init: `[is_id, inv, x_in, y_in, lambda_2P, lambda_S-]` |
//! | `s+1 ..= s+124` | incomplete iterations `[x_A, y_A, Y1, Y2, lambda_1, lambda_2, x_P, y_P, x_-, y_-]` |
//! | `s+125 ..= s+128` | complete iterations' digit points (`T_j` lands in `a0, a1` of the next row) |
//! | `s+129` | `[T_127, B1, B2, x_P, y_P, ...]` and the correction gate |
//! | `s+130` | `[-E, f1, f2]` |
//! | `s+131 ..= s+139` | nine complete additions |
//! | `s+140` | result in `a2, a3` (guarded: the guard gate, result at `s+141`) |
//!
//! `Y1, Y2` are the running sums `floor(B / 2^(128 - j))` (bits
//! `Y_{j+1} - 2 Y_j`). A result occupies only `a2, a3` of its row; an
//! addition or multiplication whose input is the previous result starts on
//! that row and reads it in place (Horner chains need no copies). The split
//! check takes three rows of `a0..a3` and 29 range-check rows at 15-bit
//! limbs. Fixed-base multiplication uses 16 fixed columns (configured by
//! [`EccConfig::configure_with_fixed_base`]): a 2-row scalar link, 85 window
//! rows `[A_x, A_y, z, b0, b1, lambda]` and one complete addition.
//!
//! # Determinism and timing
//!
//! Layouts and witnesses are pure functions of the inputs (exact field
//! arithmetic, no environment variables, no `unsafe`), identical on every
//! architecture. Witness generation branches on scalar digits and on the
//! cases of the group law: the chip is for public data (the in-circuit
//! verifier's challenges and commitments), like the `*_vartime` routines of
//! [`iroha_pasta`].

mod fixed_base;
mod gates;
mod glv;
pub mod native;
#[cfg(test)]
mod tests;

use core::{fmt, marker::PhantomData};

use ff::Field;
use iroha_pasta::{Ep, Eq, PastaCurve, PastaField};
use iroha_plonk::{
    cs::{Advice, Any, Column, ConstraintSystem},
    frontend::{Cell, Error, Region, Value},
};

pub use fixed_base::FixedBase;
pub use gates::FixedBaseColumns;
pub use glv::{GlvScalar, ScalarLimbs};

use crate::{
    arith::GlueChip,
    cells::{Bit, RowCursor, Word, assign_constant, assign_word, copy_word, known},
};
use gates::Selectors;
use native::{AddWitness, Coordinates, complete_add_witness, coordinates};

/// Advice columns of the chip.
pub const ECC_ADVICE_COLUMNS: usize = 10;

/// Equality-enabled advice columns (`a0..a3`).
pub const ECC_EQUALITY_COLUMNS: usize = 4;

/// Fixed coefficient columns of the fixed-base windows.
pub const ECC_FIXED_BASE_COLUMNS: usize = 16;

/// Rows of a GLV multiplication from its first row to its result row (the
/// result row, which holds only `a2, a3`, excluded).
pub const GLV_CHAIN_ROWS: usize = 140;

/// Rows of an identity-guarded GLV multiplication (result row excluded).
pub const GLV_GUARDED_CHAIN_ROWS: usize = 141;

/// Rows of the split check (columns `a0..a3`).
pub const GLV_SPLIT_ROWS: usize = 3;

/// Rows of a fixed-base multiplication (result row excluded).
pub const FIXED_BASE_ROWS: usize = 2 + native::FIXED_BASE_WINDOWS + 1;

/// Pallas arithmetic in an `Fp` circuit.
pub type PallasChip = EccChip<Ep>;

/// Vesta arithmetic in an `Fq` circuit.
pub type VestaChip = EccChip<Eq>;

/// A point constrained to the curve or the identity `(0, 0)`.
#[derive(Clone, Debug)]
pub struct AssignedPoint<F: PastaField> {
    x: Word<F>,
    y: Word<F>,
}

impl<F: PastaField> AssignedPoint<F> {
    /// Wraps cells whose curve-or-identity constraint is laid out.
    pub(crate) const fn new(x: Word<F>, y: Word<F>) -> Self {
        Self { x, y }
    }

    /// The `x` cell.
    #[must_use]
    pub const fn x(&self) -> &Word<F> {
        &self.x
    }

    /// The `y` cell.
    #[must_use]
    pub const fn y(&self) -> &Word<F> {
        &self.y
    }

    /// The coordinates (`(0, 0)` for the identity).
    #[must_use]
    pub fn value(&self) -> Value<Coordinates<F>> {
        self.x.value().zip(self.y.value())
    }

    /// The cells `(x, y)`.
    fn cells(&self) -> (Cell, Cell) {
        (self.x.cell(), self.y.cell())
    }
}

/// A point constrained to the curve (never the identity).
#[derive(Clone, Debug)]
pub struct NonIdentityPoint<F: PastaField>(AssignedPoint<F>);

impl<F: PastaField> NonIdentityPoint<F> {
    /// The `x` cell.
    #[must_use]
    pub const fn x(&self) -> &Word<F> {
        &self.0.x
    }

    /// The `y` cell.
    #[must_use]
    pub const fn y(&self) -> &Word<F> {
        &self.0.y
    }

    /// The coordinates.
    #[must_use]
    pub fn value(&self) -> Value<Coordinates<F>> {
        self.0.value()
    }

    /// The point as an [`AssignedPoint`] (the same cells).
    #[must_use]
    pub const fn point(&self) -> &AssignedPoint<F> {
        &self.0
    }
}

impl<F: PastaField> From<NonIdentityPoint<F>> for AssignedPoint<F> {
    fn from(point: NonIdentityPoint<F>) -> Self {
        point.0
    }
}

/// Columns and selectors of the ECC chip for the curve `C`.
#[derive(Clone, Copy)]
pub struct EccConfig<C: PastaCurve> {
    advice: [Column<Advice>; ECC_ADVICE_COLUMNS],
    selectors: Selectors,
    fixed_base: Option<FixedBaseColumns>,
    _curve: PhantomData<fn() -> C>,
}

impl<C: PastaCurve> fmt::Debug for EccConfig<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccConfig")
            .field("curve", &C::CURVE_ID)
            .field("advice", &self.advice)
            .field("selectors", &self.selectors)
            .field("fixed_base", &self.fixed_base)
            .finish()
    }
}

impl<C: PastaCurve> EccConfig<C> {
    /// Configures the variable-base gates on `advice` (`a0..a3` are made
    /// equality-enabled).
    ///
    /// Constants ([`EccChip::constant_point`]) need a constants column, which
    /// [`crate::GlueConfig`] enables.
    pub fn configure(
        meta: &mut ConstraintSystem<C::Base>,
        advice: [Column<Advice>; ECC_ADVICE_COLUMNS],
    ) -> Self {
        for column in &advice[..ECC_EQUALITY_COLUMNS] {
            meta.enable_equality(*column);
        }
        let selectors = gates::configure_variable_base::<C>(meta, advice);
        Self {
            advice,
            selectors,
            fixed_base: None,
            _curve: PhantomData,
        }
    }

    /// Configures complete variable-base arithmetic in the compact fixed ECC
    /// phase. The shared phase/payload enables raise the maximum degree to nine;
    /// row ownership must be disjoint from other users of `phases`.
    pub fn configure_phased(
        meta: &mut ConstraintSystem<C::Base>,
        advice: [Column<Advice>; ECC_ADVICE_COLUMNS],
        phases: crate::phase::PhaseColumns,
    ) -> Self {
        for column in &advice[..ECC_EQUALITY_COLUMNS] {
            meta.enable_equality(*column);
        }
        let selectors = gates::configure_variable_base_phased::<C>(meta, advice, phases);
        Self {
            advice,
            selectors,
            fixed_base: None,
            _curve: PhantomData,
        }
    }

    /// [`Self::configure`] plus the fixed-base gates and their 16 fixed
    /// coefficient columns.
    pub fn configure_with_fixed_base(
        meta: &mut ConstraintSystem<C::Base>,
        advice: [Column<Advice>; ECC_ADVICE_COLUMNS],
    ) -> Self {
        let mut config = Self::configure(meta, advice);
        config.fixed_base = Some(gates::configure_fixed_base(meta, advice));
        config
    }

    /// The advice columns `a0..a9`.
    #[must_use]
    pub const fn advice(&self) -> [Column<Advice>; ECC_ADVICE_COLUMNS] {
        self.advice
    }

    /// Whether the fixed-base gates are configured.
    #[must_use]
    pub const fn has_fixed_base(&self) -> bool {
        self.fixed_base.is_some()
    }
}

/// The ECC chip: its configuration and a row cursor over its columns.
pub struct EccChip<C: PastaCurve> {
    config: EccConfig<C>,
    rows: RowCursor,
    /// The row whose `a2, a3` hold the last result (and nothing else).
    pending: Option<usize>,
    constant_source: Option<crate::GlueChip<C::Base>>,
}

impl<C: PastaCurve> fmt::Debug for EccChip<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccChip")
            .field("config", &self.config)
            .field("rows", &self.rows)
            .field("pending", &self.pending)
            .field("constant_source", &self.constant_source)
            .finish()
    }
}

impl<C: PastaCurve> EccChip<C> {
    /// A chip whose first row is 0.
    #[must_use]
    pub const fn new(config: &EccConfig<C>) -> Self {
        Self::starting_at(config, 0)
    }

    /// A chip whose first row is `row` (to share the columns with other
    /// users above it).
    #[must_use]
    pub const fn starting_at(config: &EccConfig<C>, row: usize) -> Self {
        Self::with_cursor(config, RowCursor::starting_at(row))
    }

    /// Uses a caller-reserved interval disjoint from other shared-column owners.
    #[must_use]
    pub const fn with_cursor(config: &EccConfig<C>, rows: RowCursor) -> Self {
        Self {
            config: *config,
            rows,
            pending: None,
            constant_source: None,
        }
    }

    /// Routes fixed points through a caller's constrained arithmetic lane.
    /// Its shared cursor must reserve rows disjoint from the ECC lane.
    ///
    /// # Errors
    /// The source is not a bounded shared coefficient-only lane on the same
    /// four copy ports.
    pub fn with_constant_source(mut self, source: crate::GlueChip<C::Base>) -> Result<Self, Error> {
        if !source.coefficient_source_for(&self.config.advice[..4]) {
            return Err(Error::Synthesis);
        }
        self.constant_source = Some(source);
        Ok(self)
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &EccConfig<C> {
        &self.config
    }

    /// The first row not used yet.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.rows.next_row()
    }

    /// The cell of column `a{column}` at `row`.
    fn cell_at(&self, column: usize, row: usize) -> Cell {
        Cell {
            row_offset: row,
            column: Column::<Any>::from(self.config.advice[column]),
        }
    }

    /// Whether `point` is the pending result (in `a2, a3` of the pending
    /// row).
    fn is_pending(&self, point: &AssignedPoint<C::Base>) -> bool {
        self.pending
            .is_some_and(|row| point.cells() == (self.cell_at(2, row), self.cell_at(3, row)))
    }

    /// Reserves `rows` rows (the result row of the operation included) and
    /// returns the first, starting on the pending row when `input` is the
    /// pending result (`true`: it is read in place).
    fn begin(
        &mut self,
        rows: usize,
        input: Option<&AssignedPoint<C::Base>>,
    ) -> Result<(usize, bool), Error> {
        if let (Some(row), Some(point)) = (self.pending, input)
            && self.is_pending(point)
        {
            self.pending = None;
            self.rows
                .take(rows.checked_sub(1).ok_or(Error::Synthesis)?)?;
            return Ok((row, true));
        }
        self.pending = None;
        Ok((self.rows.take(rows)?, false))
    }

    /// Assigns `value` to `a{column}` at `row`.
    fn assign(
        &self,
        region: &mut Region<'_, C::Base>,
        column: usize,
        row: usize,
        value: Value<C::Base>,
    ) -> Result<Word<C::Base>, Error> {
        assign_word(region, self.config.advice[column], row, value)
    }

    /// Copies `word` into `a{column}` at `row`.
    fn copy(
        &self,
        region: &mut Region<'_, C::Base>,
        word: &Word<C::Base>,
        column: usize,
        row: usize,
    ) -> Result<Word<C::Base>, Error> {
        copy_word(region, word, self.config.advice[column], row)
    }

    /// Assigns the coordinates of a point value to `a{column}, a{column+1}`.
    fn assign_point(
        &self,
        region: &mut Region<'_, C::Base>,
        column: usize,
        row: usize,
        value: Value<Coordinates<C::Base>>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let (x, y) = value.unzip();
        Ok(AssignedPoint::new(
            self.assign(region, column, row, x)?,
            self.assign(region, column + 1, row, y)?,
        ))
    }

    /// Copies a point into `a{column}, a{column+1}` at `row`.
    fn copy_point(
        &self,
        region: &mut Region<'_, C::Base>,
        point: &AssignedPoint<C::Base>,
        column: usize,
        row: usize,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        Ok(AssignedPoint::new(
            self.copy(region, &point.x, column, row)?,
            self.copy(region, &point.y, column + 1, row)?,
        ))
    }

    /// Witnesses a point on the curve or the identity (one row).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn witness_point(
        &mut self,
        region: &mut Region<'_, C::Base>,
        value: Value<C>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let row = self.begin(1, None)?.0;
        self.config.selectors.point[0].enable(region, row)?;
        self.assign_point(region, 0, row, value.map(|point| coordinates(&point)))
    }

    /// Witnesses points on the curve or the identity, two per row.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn witness_points(
        &mut self,
        region: &mut Region<'_, C::Base>,
        values: &[Value<C>],
    ) -> Result<Vec<AssignedPoint<C::Base>>, Error> {
        let mut out = Vec::with_capacity(values.len());
        for pair in values.chunks(2) {
            let row = self.begin(1, None)?.0;
            for (half, value) in pair.iter().enumerate() {
                self.config.selectors.point[half].enable(region, row)?;
                out.push(self.assign_point(
                    region,
                    2 * half,
                    row,
                    value.map(|point| coordinates(&point)),
                )?);
            }
        }
        Ok(out)
    }

    /// Witnesses a point on the curve (an identity value has no satisfying
    /// assignment).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn witness_non_identity(
        &mut self,
        region: &mut Region<'_, C::Base>,
        value: Value<C>,
    ) -> Result<NonIdentityPoint<C::Base>, Error> {
        let row = self.begin(1, None)?.0;
        self.config.selectors.curve[0].enable(region, row)?;
        self.assign_point(region, 0, row, value.map(|point| coordinates(&point)))
            .map(NonIdentityPoint)
    }

    /// Constrains coordinates computed elsewhere (for example decoded proof
    /// commitments) to the curve or the identity, returning them as a point
    /// (copies in one row).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn constrain_point(
        &mut self,
        region: &mut Region<'_, C::Base>,
        x: &Word<C::Base>,
        y: &Word<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let row = self.begin(1, None)?.0;
        self.config.selectors.point[0].enable(region, row)?;
        self.copy_point(region, &AssignedPoint::new(x.clone(), y.clone()), 0, row)
    }

    /// Constrains coordinates computed elsewhere to the curve (never the
    /// identity).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn constrain_non_identity(
        &mut self,
        region: &mut Region<'_, C::Base>,
        x: &Word<C::Base>,
        y: &Word<C::Base>,
    ) -> Result<NonIdentityPoint<C::Base>, Error> {
        let row = self.begin(1, None)?.0;
        self.config.selectors.curve[0].enable(region, row)?;
        self.copy_point(region, &AssignedPoint::new(x.clone(), y.clone()), 0, row)
            .map(NonIdentityPoint)
    }

    /// A constant point (pinned through the constants column; the identity
    /// is `(0, 0)`).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout, including a missing constants column.
    pub fn constant_point(
        &mut self,
        region: &mut Region<'_, C::Base>,
        point: &C,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let row = self.begin(1, None)?.0;
        let (x, y) = coordinates(point);
        if let Some(source) = &mut self.constant_source {
            let x = source.constant(region, x)?;
            let y = source.constant(region, y)?;
            return Ok(AssignedPoint::new(
                copy_word(region, &x, self.config.advice[0], row)?,
                copy_word(region, &y, self.config.advice[1], row)?,
            ));
        }
        Ok(AssignedPoint::new(
            assign_constant(region, self.config.advice[0], row, x)?,
            assign_constant(region, self.config.advice[1], row, y)?,
        ))
    }

    /// Constrains `p = q` (copy constraints; no row).
    ///
    /// # Errors
    ///
    /// [`Error`] from the copies.
    pub fn assert_equal(
        region: &mut Region<'_, C::Base>,
        p: &AssignedPoint<C::Base>,
        q: &AssignedPoint<C::Base>,
    ) -> Result<(), Error> {
        region.constrain_equal(p.x.cell(), q.x.cell())?;
        region.constrain_equal(p.y.cell(), q.y.cell())
    }

    /// Lays out the witness cells of a complete addition at `row` (whose
    /// inputs the caller placed in `a0..a3`) and its result in `a2, a3` of
    /// `row + 1`.
    fn add_cells(
        &self,
        region: &mut Region<'_, C::Base>,
        row: usize,
        witness: Value<AddWitness<C::Base>>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        self.config.selectors.add.enable(region, row)?;
        let fields = [
            witness.map(|w| w.lambda),
            witness.map(|w| w.alpha),
            witness.map(|w| w.beta),
            witness.map(|w| w.gamma),
            witness.map(|w| w.delta),
        ];
        for (offset, value) in fields.into_iter().enumerate() {
            self.assign(region, 4 + offset, row, value)?;
        }
        let next = row.checked_add(1).ok_or(Error::BoundsFailure)?;
        self.assign_point(region, 2, next, witness.map(|w| w.output))
    }

    /// One complete addition at `row`: copies `p` into `a0, a1` and `q`
    /// into `a2, a3` (unless `q` is already there), witness cells, result at
    /// `row + 1`.
    fn add_at(
        &self,
        region: &mut Region<'_, C::Base>,
        row: usize,
        p: &AssignedPoint<C::Base>,
        q: &AssignedPoint<C::Base>,
        q_in_place: bool,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let witness = p
            .value()
            .zip(q.value())
            .map(|(p, q)| complete_add_witness(p, q));
        self.copy_point(region, p, 0, row)?;
        if !q_in_place {
            self.copy_point(region, q, 2, row)?;
        }
        self.add_cells(region, row, witness)
    }

    /// `p + q` by complete addition (identity, equal and opposite inputs
    /// included). A pending previous result is read in place.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn add(
        &mut self,
        region: &mut Region<'_, C::Base>,
        p: &AssignedPoint<C::Base>,
        q: &AssignedPoint<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        // Addition commutes: put a pending input in the in-place slot.
        let (p, q) = if !self.is_pending(q) && self.is_pending(p) {
            (q, p)
        } else {
            (p, q)
        };
        let (row, in_place) = self.begin(2, Some(q))?;
        let out = self.add_at(region, row, p, q, in_place)?;
        self.pending = Some(row + 1);
        Ok(out)
    }

    /// `sum_i points_i` by complete additions (the identity for no
    /// points).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn sum(
        &mut self,
        region: &mut Region<'_, C::Base>,
        points: &[AssignedPoint<C::Base>],
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let Some((first, rest)) = points.split_first() else {
            return self.constant_point(region, &C::identity());
        };
        let mut acc = first.clone();
        for point in rest {
            acc = self.add(region, &acc, point)?;
        }
        Ok(acc)
    }

    /// `-p` (one glue row; `x` is shared).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn neg(
        glue: &mut GlueChip<C::Base>,
        region: &mut Region<'_, C::Base>,
        p: &AssignedPoint<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let y = glue.linear(region, &[(-C::Base::ONE, &p.y)], C::Base::ZERO)?;
        Ok(AssignedPoint::new(p.x.clone(), y))
    }

    /// `[p = O]` (one glue row: `x = 0` identifies the identity).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn is_identity(
        glue: &mut GlueChip<C::Base>,
        region: &mut Region<'_, C::Base>,
        p: &AssignedPoint<C::Base>,
    ) -> Result<Bit<C::Base>, Error> {
        glue.is_zero(region, &p.x)
    }

    /// `bit ? p : q` (two glue rows).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn select(
        glue: &mut GlueChip<C::Base>,
        region: &mut Region<'_, C::Base>,
        bit: &Bit<C::Base>,
        p: &AssignedPoint<C::Base>,
        q: &AssignedPoint<C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let x = glue.select(region, bit, &p.x, &q.x)?;
        let y = glue.select(region, bit, &p.y, &q.y)?;
        Ok(AssignedPoint::new(x, y))
    }

    /// Constrains `p != O` (one glue row: `x` has an inverse) and returns it
    /// as a [`NonIdentityPoint`].
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn assert_non_identity(
        glue: &mut GlueChip<C::Base>,
        region: &mut Region<'_, C::Base>,
        p: &AssignedPoint<C::Base>,
    ) -> Result<NonIdentityPoint<C::Base>, Error> {
        glue.assert_nonzero(region, &p.x)?;
        Ok(NonIdentityPoint(p.clone()))
    }
}

/// The native point of an assigned point's known value (`None` while
/// unknown or off the curve).
#[must_use]
pub fn point_value<C: PastaCurve>(point: &AssignedPoint<C::Base>) -> Option<C> {
    known(&point.value()).and_then(native::point::<C>)
}
