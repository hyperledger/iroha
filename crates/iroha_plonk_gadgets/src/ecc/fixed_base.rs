//! Fixed-base multiplication with 3-bit windows and a complete final window.
//!
//! The scalar `W = lo + 2^128 hi < 2^255` is cut into 85 windows
//! `k_i in [0, 8)` (bits `b0, b1` witnessed, `b2` derived from the running
//! sum `z_i = 8 z_{i+1} + k_i`, `z_85 = 0`). Window `i < 84` adds
//! `T_i = [(k_i + 2) 8^i] B` and window 84 adds
//! `[k_84 8^84 - 2 sum_{j<84} 8^j] B`, so the sum is `[W] B`. The window
//! points' coordinates are multilinear in `b0, b1, b2` with coefficients in
//! 16 fixed columns (degree 3 in the bits).
//!
//! `A_1 = T_0` and `A_{i+1} = A_i + T_i` by incomplete addition for
//! `i = 1..=83`: the multiple of `A_i` lies in `[2 (8^i - 1) / 7,
//! 9 (8^i - 1) / 7]`, below the multiple of `T_i` (`>= 2 8^i`), and their sum
//! is below `11 8^83 < 2^253 < r`, so `A_i != +-T_i` for every digit
//! sequence. The last window uses complete addition.
//!
//! The running sum is tied to the limbs by `hi = 2 z_43 + h0` (`h0` a bit)
//! and `z_0 - 2^129 z_43 = lo + 2^128 h0`: both sides are below `2^130`, so
//! `sum_i k_i 8^i = lo + 2^128 hi` as integers.

use core::fmt;

use iroha_pasta::PastaCurve;
use iroha_plonk::frontend::{Error, Region, Value};

use super::ScalarLimbs;
use super::{
    AssignedPoint, EccChip, FIXED_BASE_ROWS,
    native::{
        FIXED_BASE_LINK_WINDOW, FIXED_BASE_WINDOWS, FixedBaseTable, FixedBaseWitness,
        fixed_base_table, fixed_base_witness,
    },
};

/// A fixed base with its window table (computed once per base).
pub struct FixedBase<C: PastaCurve> {
    point: C,
    table: FixedBaseTable<C::Base>,
}

impl<C: PastaCurve> Clone for FixedBase<C> {
    fn clone(&self) -> Self {
        Self {
            point: self.point,
            table: self.table.clone(),
        }
    }
}

impl<C: PastaCurve> fmt::Debug for FixedBase<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedBase")
            .field("point", &self.point)
            .finish_non_exhaustive()
    }
}

impl<C: PastaCurve> FixedBase<C> {
    /// The table of `point` (`None` for the identity).
    #[must_use]
    pub fn new(point: &C) -> Option<Self> {
        fixed_base_table(point).map(|table| Self {
            point: *point,
            table,
        })
    }

    /// The base.
    #[must_use]
    pub const fn point(&self) -> &C {
        &self.point
    }

    /// The window table.
    #[must_use]
    pub const fn table(&self) -> &FixedBaseTable<C::Base> {
        &self.table
    }
}

/// A boolean as a field element.
fn bit_field<F: ff::Field>(bit: bool) -> F {
    if bit { F::ONE } else { F::ZERO }
}

impl<C: PastaCurve> EccChip<C> {
    /// `[W mod r] B` for a fixed base `B` (layout in the module
    /// documentation).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when the chip was configured without the
    /// fixed-base gates, and [`Error`] from the layout.
    pub fn fixed_base_mul(
        &mut self,
        region: &mut Region<'_, C::Base>,
        base: &FixedBase<C>,
        scalar: ScalarLimbs<'_, C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let columns = self.config.fixed_base.ok_or(Error::Synthesis)?;
        let witness = scalar
            .value()
            .map(|limbs| fixed_base_witness(&base.table, limbs));
        witness.error_if_known_and(Option::is_none)?;
        let witness: Value<FixedBaseWitness<C::Base>> =
            witness.and_then(|witness| witness.map_or_else(Value::unknown, Value::known));
        let w = witness.as_ref();
        let (start, _) = self.begin(FIXED_BASE_ROWS + 1, None)?;
        // The scalar link (two rows).
        columns.link.enable(region, start)?;
        let z_0 = self.assign(region, 0, start, w.map(|w| w.running[0]))?;
        let z_43 = self.assign(
            region,
            1,
            start,
            w.map(|w| w.running[FIXED_BASE_LINK_WINDOW]),
        )?;
        self.copy(region, scalar.lo().word(), 2, start)?;
        self.copy(region, scalar.hi().word(), 3, start)?;
        self.assign(region, 0, start + 1, w.map(|w| bit_field(w.h0)))?;
        // The windows.
        let last = FIXED_BASE_WINDOWS - 1;
        for (window, (x_coefficients, y_coefficients)) in base
            .table
            .x_coefficients
            .iter()
            .zip(&base.table.y_coefficients)
            .enumerate()
        {
            let row = start + 2 + window;
            let z = self.assign(region, 2, row, w.map(|w| w.running[window]))?;
            self.assign(
                region,
                3,
                row,
                w.map(|w| bit_field(w.windows[window] & 1 == 1)),
            )?;
            self.assign(
                region,
                4,
                row,
                w.map(|w| bit_field(w.windows[window] & 2 == 2)),
            )?;
            for ((x_column, y_column), (x, y)) in columns
                .x
                .iter()
                .zip(&columns.y)
                .zip(x_coefficients.iter().zip(y_coefficients))
            {
                region.assign_fixed(*x_column, row, *x)?;
                region.assign_fixed(*y_column, row, *y)?;
            }
            if window == 0 {
                columns.first.enable(region, row)?;
                region.constrain_equal(z.cell(), z_0.cell())?;
            } else {
                self.assign_point(region, 0, row, w.map(|w| w.acc[window - 1]))?;
                if window < last {
                    columns.incomplete.enable(region, row)?;
                    self.assign(region, 5, row, w.map(|w| w.lambdas[window - 1]))?;
                } else {
                    columns.last.enable(region, row)?;
                }
            }
            if window == FIXED_BASE_LINK_WINDOW {
                region.constrain_equal(z.cell(), z_43.cell())?;
            }
        }
        // The complete final addition `A_84 + T_84`.
        let add_row = start + 2 + FIXED_BASE_WINDOWS;
        self.assign_point(region, 0, add_row, w.map(|w| w.acc[last - 1]))?;
        let last_point = w.map(|w| {
            base.table
                .points
                .get(last)
                .and_then(|row| row.get(w.windows[last]))
                .copied()
                .unwrap_or_default()
        });
        self.assign_point(region, 2, add_row, last_point)?;
        let out = self.add_cells(region, add_row, w.map(|w| w.last))?;
        self.pending = Some(add_row + 1);
        Ok(out)
    }
}
