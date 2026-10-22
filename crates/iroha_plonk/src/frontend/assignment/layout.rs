//! Occupancy capture with ordinary assignment checks and no copy-cycle output.

use iroha_pasta::{CancellationToken, PastaField};

use super::{Assembly, Assigned, Assignment, Error, Value};
use crate::cs::{Advice, Any, Column, ConstraintSystem, Fixed, Instance, Selector};

/// Fixed values and occupancy from layout-only synthesis.
///
/// This type has no witness, constraint system or permutation, and cannot be
/// converted into ordinary assigned tables or used as a keygen/prover input.
#[derive(Debug)]
pub struct LayoutTables<F: PastaField> {
    fixed: Vec<Vec<F>>,
    fixed_assigned: Vec<Vec<bool>>,
    advice_assigned: Vec<Vec<bool>>,
}

impl<F: PastaField> LayoutTables<F> {
    /// Resolved fixed values, including zero for unassigned cells.
    #[must_use]
    pub fn fixed(&self) -> &[Vec<F>] {
        &self.fixed
    }

    /// Whether each fixed cell was assigned.
    #[must_use]
    pub fn fixed_assigned(&self) -> &[Vec<bool>] {
        &self.fixed_assigned
    }

    /// Whether each advice cell was assigned, even with an unknown value.
    #[must_use]
    pub fn advice_assigned(&self) -> &[Vec<bool>] {
        &self.advice_assigned
    }
}

/// Private sink: the wrapped assembly cannot escape as ordinary tables.
pub(in crate::frontend) struct LayoutAssembly<F: PastaField>(Assembly<F>);

impl<F: PastaField> LayoutAssembly<F> {
    pub(in crate::frontend) fn new(
        cs: &ConstraintSystem<F>,
        k: u32,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, Error> {
        // Keep constructor checks, including columns * n overflow. The normal
        // permutation stays in its lazy identity representation.
        Assembly::new_cancellable(cs, k, None, cancellation).map(Self)
    }

    pub(in crate::frontend) fn finish(mut self) -> Result<LayoutTables<F>, Error> {
        self.0.finish_assignments()?;
        Ok(LayoutTables {
            fixed: self.0.fixed,
            fixed_assigned: self.0.fixed_assigned,
            advice_assigned: self.0.advice_assigned,
        })
    }
}

impl<F: PastaField> Assignment<F> for LayoutAssembly<F> {
    fn enter_region(&mut self, name: String) -> Result<(), Error> {
        self.0.enter_region(name)
    }

    fn exit_region(&mut self) -> Result<(), Error> {
        self.0.exit_region()
    }

    fn annotate_column(&mut self, name: String, column: Column<Any>) {
        self.0.annotate_column(name, column)
    }

    fn enable_selector(&mut self, selector: Selector, row: usize) -> Result<(), Error> {
        self.0.enable_selector(selector, row)
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<F>, Error> {
        self.0.query_instance(column, row)
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.0.assign_advice(column, row, value)
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: Assigned<F>,
    ) -> Result<(), Error> {
        self.0.assign_fixed(column, row, value)
    }

    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error> {
        self.0.expect_fixed(column, row, value)
    }

    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.0.reserve_advice(column, row)
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.0.fill_from_row(column, from_row, value)
    }

    fn push_namespace(&mut self, name: String) {
        self.0.push_namespace(name)
    }

    fn pop_namespace(&mut self) {
        self.0.pop_namespace()
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        self.0
            .check_copy(left_column, left_row, right_column, right_row)?;
        self.0
            .permutation
            .checked_copy_cells(left_column, left_row, right_column, right_row)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
