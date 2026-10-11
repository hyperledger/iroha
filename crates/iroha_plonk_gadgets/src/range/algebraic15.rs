//! One-row algebraic 15-bit range checks for a shared arithmetic lane.
//!
//! Seven base-four digits and one top bit reconstruct the copied input:
//! `x = sum d_i 4^i`, with `d_0..d_6` in `0..4` and `d_7` in `0..2`.
//! Each small digit is constrained by its root polynomial, not a lookup.
//! Thus the right side is an integer below `2^15`, far below either circuit
//! modulus, and equality gives exactly that range. Nine advice columns are
//! queried only at the current row; only the input column needs equality.
//! The maximum gate degree is five including its selector.
//!
//! This component can move checks off a single shared lookup bus onto idle
//! arithmetic rows. It does not establish that a complete wrapper's shared
//! schedule or proof-size budget fits; that requires the composed descriptor.

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Rotation},
    frontend::{Error, Region, Value},
};

use crate::{
    RowCursor, Uint, Word,
    cells::{assign_word, copy_word},
    phase::{Enable, PhaseColumns},
};

/// Input plus eight base-four digits (the last is a bit).
pub const WIDTH: usize = 9;

/// Algebraic range columns that may share a separately scheduled ECC lane.
#[derive(Clone, Copy, Debug)]
pub struct Algebraic15Config {
    columns: [Column<Advice>; WIDTH],
    enabled: Enable,
}

impl Algebraic15Config {
    /// Configures the input's copy port and degree-five root constraints.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; WIDTH],
    ) -> Self {
        let enabled = meta.selector().into();
        Self::configure_enable(meta, columns, enabled)
    }

    /// Shares the ECC phase's low-degree point-code payload. Combined gates
    /// have degree nine; this row interval must be disjoint from ECC rows.
    pub fn configure_phased<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; WIDTH],
        phases: PhaseColumns,
    ) -> Self {
        Self::configure_enable(meta, columns, phases.enable(1, Some((0, 3, 3))))
    }

    fn configure_enable<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; WIDTH],
        enabled: Enable,
    ) -> Self {
        meta.enable_equality(columns[0]);
        meta.create_gate("algebraic 15-bit range", |cells| {
            let q = enabled.query(cells);
            let value = cells.query_advice(columns[0], Rotation::cur());
            let digits = columns[1..]
                .iter()
                .map(|column| cells.query_advice(*column, Rotation::cur()))
                .collect::<Vec<_>>();
            let mut constraints = Vec::with_capacity(WIDTH);
            let mut reconstructed = Expression::Constant(F::ZERO);
            for (i, digit) in digits.iter().enumerate() {
                let roots = if i == 7 { 2 } else { 4 };
                let product = (0..roots).fold(Expression::Constant(F::ONE), |product, root| {
                    product * (digit.clone() - Expression::Constant(F::from(root)))
                });
                constraints.push(("small digit", q.clone() * product));
                reconstructed = reconstructed + digit.clone() * F::from(1_u64 << (2 * i));
            }
            constraints.push(("integer recomposition", q * (value - reconstructed)));
            constraints
        });
        Self { columns, enabled }
    }
}

/// A cursor over structurally reserved arithmetic rows; no table is loaded.
#[derive(Clone, Copy, Debug)]
pub struct Algebraic15Chip {
    config: Algebraic15Config,
    rows: RowCursor,
}

impl Algebraic15Chip {
    /// Uses rows from a caller-owned disjoint interval.
    #[must_use]
    pub const fn with_cursor(config: Algebraic15Config, rows: RowCursor) -> Self {
        Self { config, rows }
    }

    /// First unused row of the reserved interval.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.rows.next_row()
    }

    /// Assigns and constrains one 15-bit value. An out-of-range field value
    /// produces unsatisfied constraints, rather than a truncated accepted value.
    ///
    /// # Errors
    /// The reserved row interval is exhausted or assignment fails.
    pub fn assign<F: PastaField>(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<F>,
    ) -> Result<Uint<F, 15>, Error> {
        let row = self.rows.take(1)?;
        let word = assign_word(region, self.config.columns[0], row, value)?;
        self.decompose(region, row, value)?;
        Ok(Uint::new(word))
    }

    /// Checks the exact copied input cell using one arithmetic row.
    ///
    /// # Errors
    /// The reserved row interval is exhausted or assignment/copy fails.
    pub fn range_check<F: PastaField>(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Word<F>,
    ) -> Result<Uint<F, 15>, Error> {
        let row = self.rows.take(1)?;
        let copied = copy_word(region, word, self.config.columns[0], row)?;
        self.decompose(region, row, word.value())?;
        Ok(Uint::new(copied))
    }

    fn decompose<F: PastaField>(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        for (index, column) in self.config.columns[1..].iter().enumerate() {
            let digit = value.map(|v| {
                let mask = if index == 7 { 1 } else { 3 };
                F::from((v.to_canonical_limbs()[0] >> (2 * index)) & mask)
            });
            // These internal digits are linked by relative-row constraints;
            // they need no permutation/copy port.
            region.assign_advice(*column, row, digit)?;
        }
        self.config.enabled.enable(region, row)
    }
}

#[cfg(test)]
mod tests;
