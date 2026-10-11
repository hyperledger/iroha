//! Regions, tables, layouters and the [`SimpleFloorPlanner`].
//!
//! The layout equals the halo2-axiom `SimpleFloorPlanner`, which the vendored
//! goldens and the Kaigi and `SoraFS` circuits use, so the fixed columns,
//! selectors and copy cycles (and therefore the verifying-key bytes) are
//! reproduced:
//!
//! - every region starts at row 0: region offsets are absolute rows;
//! - constants constrained in a region are assigned after the region, in
//!   order, into the first constants column at the next free row of that
//!   column (counted across regions), each followed by the copy
//!   `(constants column, row) == (cell)`;
//! - a table assigns its cells at their offsets, requires every table column
//!   to be assigned on rows `0..len` with one common `len`, then fills rows
//!   `len..u` of each column with its row-0 value, and reserves the columns;
//! - `copy_advice` assigns first and then copies `(new cell) == (old cell)`.
//!
//! Copy argument order matters: it decides union-find ties in the permutation.

use std::collections::BTreeMap;

use core::{fmt, marker::PhantomData};

use iroha_pasta::PastaField;

use super::{
    assignment::{Assignment, Error, TableError},
    circuit::Circuit,
    value::{Assigned, Value},
};
use crate::cs::{Advice, Any, Column, Fixed, Instance, Selector, TableColumn};

/// A cell of the circuit: a column and an absolute row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cell {
    /// The row (regions start at row 0, so offsets are absolute).
    pub row_offset: usize,
    /// The column.
    pub column: Column<Any>,
}

/// An assigned cell with its value.
#[derive(Clone, Debug)]
pub struct AssignedCell<V, F> {
    value: Value<V>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<V, F> AssignedCell<V, F> {
    /// Wraps a cell and its value.
    pub const fn new(value: Value<V>, cell: Cell) -> Self {
        Self {
            value,
            cell,
            _marker: PhantomData,
        }
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> Value<&V> {
        self.value.as_ref()
    }

    /// The cell.
    #[must_use]
    pub const fn cell(&self) -> Cell {
        self.cell
    }

    /// The row.
    #[must_use]
    pub const fn row_offset(&self) -> usize {
        self.cell.row_offset
    }

    /// The column.
    #[must_use]
    pub const fn column(&self) -> &Column<Any> {
        &self.cell.column
    }
}

impl<V, F: PastaField> AssignedCell<V, F>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    /// The value as an [`Assigned`] field value.
    #[must_use]
    pub fn value_field(&self) -> Value<Assigned<F>> {
        self.value.as_ref().map(Into::into)
    }

    /// Assigns this value into `column` at `offset` and constrains the new
    /// cell to equal this one (in that copy order, as halo2-axiom does).
    ///
    /// # Errors
    ///
    /// [`Error`] from the assignment or the copy.
    pub fn copy_advice(
        &self,
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        offset: usize,
    ) -> Result<Self, Error>
    where
        V: Clone,
    {
        let assigned = region.assign_advice(column, offset, self.value_field())?;
        region.constrain_equal(assigned.cell(), self.cell)?;
        Ok(Self::new(self.value.clone(), assigned.cell()))
    }
}

impl<F: PastaField> AssignedCell<Assigned<F>, F> {
    /// Evaluates the fraction.
    #[must_use]
    pub fn evaluate(self) -> AssignedCell<F, F> {
        AssignedCell::new(self.value.evaluate(), self.cell)
    }
}

/// The region backend a [`Region`] writes to.
pub trait RegionLayouter<F: PastaField> {
    /// Enables `selector` at `offset`.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn enable_selector(
        &mut self,
        annotation: &dyn Fn() -> String,
        selector: &Selector,
        offset: usize,
    ) -> Result<(), Error>;

    /// Names a column within the region.
    fn name_column(&mut self, annotation: &dyn Fn() -> String, column: Column<Any>);

    /// Assigns an advice cell.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        to: Value<Assigned<F>>,
    ) -> Result<Cell, Error>;

    /// Assigns a constant to an advice cell and constrains it.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn assign_advice_from_constant(
        &mut self,
        annotation: &dyn Fn() -> String,
        column: Column<Advice>,
        offset: usize,
        constant: Assigned<F>,
    ) -> Result<Cell, Error>;

    /// Copies an instance cell into an advice cell.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn assign_advice_from_instance(
        &mut self,
        annotation: &dyn Fn() -> String,
        instance: Column<Instance>,
        row: usize,
        advice: Column<Advice>,
        offset: usize,
    ) -> Result<(Cell, Value<F>), Error>;

    /// The value of an instance cell.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn instance_value(&mut self, instance: Column<Instance>, row: usize)
    -> Result<Value<F>, Error>;

    /// Assigns a fixed cell.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        offset: usize,
        to: Assigned<F>,
    ) -> Result<Cell, Error>;

    /// Guard a fixed cell against existing or future conflicting writes.
    /// # Errors
    /// Any backend bounds or layout conflict error.
    fn expect_fixed(&mut self, column: Column<Fixed>, offset: usize, value: F)
    -> Result<(), Error>;
    /// Reserve one advice cell for exactly one future assignment.
    /// # Errors
    /// Any backend bounds or layout conflict error.
    fn reserve_advice(&mut self, column: Column<Advice>, offset: usize) -> Result<(), Error>;

    /// Constrains `cell` to a constant (assigned after the region).
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn constrain_constant(&mut self, cell: Cell, constant: Assigned<F>) -> Result<(), Error>;

    /// Constrains two cells to be equal.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    fn constrain_equal(&mut self, left: Cell, right: Cell) -> Result<(), Error>;
}

/// A region of the circuit, as seen by chips.
pub struct Region<'r, F: PastaField> {
    region: &'r mut dyn RegionLayouter<F>,
}

impl<F: PastaField> fmt::Debug for Region<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Region")
    }
}

impl<'r, F: PastaField> From<&'r mut dyn RegionLayouter<F>> for Region<'r, F> {
    fn from(region: &'r mut dyn RegionLayouter<F>) -> Self {
        Self { region }
    }
}

impl<F: PastaField> Region<'_, F> {
    /// Enables `selector` at `offset`.
    ///
    /// # Errors
    ///
    /// [`Error`] when the row or selector is out of range.
    pub fn enable_selector<A, AR>(
        &mut self,
        annotation: A,
        selector: &Selector,
        offset: usize,
    ) -> Result<(), Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .enable_selector(&|| annotation().into(), selector, offset)
    }

    /// Names a column within this region.
    pub fn name_column<A, AR, T>(&mut self, annotation: A, column: T)
    where
        A: Fn() -> AR,
        AR: Into<String>,
        T: Into<Column<Any>>,
    {
        self.region
            .name_column(&|| annotation().into(), column.into());
    }

    /// Assigns an advice cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range or the value is unknown while
    /// proving.
    pub fn assign_advice(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        to: Value<impl Into<Assigned<F>>>,
    ) -> Result<AssignedCell<Assigned<F>, F>, Error> {
        let value = to.map(Into::into);
        let cell = self.region.assign_advice(column, offset, value)?;
        Ok(AssignedCell::new(value, cell))
    }

    /// Assigns a constant to an advice cell and constrains it to that constant
    /// through the constants column.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range.
    pub fn assign_advice_from_constant<VR, A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        offset: usize,
        constant: VR,
    ) -> Result<AssignedCell<VR, F>, Error>
    where
        for<'vr> Assigned<F>: From<&'vr VR>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let cell = self.region.assign_advice_from_constant(
            &|| annotation().into(),
            column,
            offset,
            (&constant).into(),
        )?;
        Ok(AssignedCell::new(Value::known(constant), cell))
    }

    /// Assigns the instance value at `row` to an advice cell and copies it.
    ///
    /// # Errors
    ///
    /// [`Error`] when a cell is out of range.
    pub fn assign_advice_from_instance<A, AR>(
        &mut self,
        annotation: A,
        instance: Column<Instance>,
        row: usize,
        advice: Column<Advice>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let (cell, value) = self.region.assign_advice_from_instance(
            &|| annotation().into(),
            instance,
            row,
            advice,
            offset,
        )?;
        Ok(AssignedCell::new(value, cell))
    }

    /// The value of an instance cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range.
    pub fn instance_value(
        &mut self,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<Value<F>, Error> {
        self.region.instance_value(instance, row)
    }

    /// Assigns a fixed cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range.
    pub fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        offset: usize,
        to: impl Into<Assigned<F>>,
    ) -> Result<Cell, Error> {
        self.region.assign_fixed(column, offset, to.into())
    }

    /// Requires the existing, future and final fixed value to match exactly.
    /// This synthesis guard adds no circuit query or polynomial.
    /// # Errors
    /// Out-of-range cells or conflicting fixed metadata.
    pub fn expect_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: F,
    ) -> Result<(), Error> {
        self.region.expect_fixed(column, row, value)
    }
    /// Reserves an unassigned advice cell for exactly one subsequent write.
    /// The guard is structural and also applies to unknown witnesses.
    /// # Errors
    /// Out-of-range, already assigned/reserved, duplicate or missing writes.
    pub fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.region.reserve_advice(column, row)
    }

    /// Constrains `cell` to equal `constant`.
    ///
    /// # Errors
    ///
    /// [`Error`] from the backend.
    pub fn constrain_constant(
        &mut self,
        cell: Cell,
        constant: impl Into<Assigned<F>>,
    ) -> Result<(), Error> {
        self.region.constrain_constant(cell, constant.into())
    }

    /// Constrains two cells to be equal.
    ///
    /// # Errors
    ///
    /// [`Error`] when a column is not equality-enabled or a cell is out of
    /// range.
    pub fn constrain_equal(&mut self, left: Cell, right: Cell) -> Result<(), Error> {
        self.region.constrain_equal(left, right)
    }
}

impl Selector {
    /// Enables this selector at `offset` in `region`.
    ///
    /// # Errors
    ///
    /// [`Error`] when the row is out of range.
    pub fn enable<F: PastaField>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        region.enable_selector(String::new, self, offset)
    }
}

/// The table backend a [`Table`] writes to.
pub trait TableLayouter<F: PastaField> {
    /// Assigns a table cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the column holds another table, row 0 is assigned
    /// twice, or the value is unknown.
    fn assign_cell(
        &mut self,
        annotation: &dyn Fn() -> String,
        column: TableColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Value<Assigned<F>>,
    ) -> Result<(), Error>;
}

/// A lookup table being loaded.
pub struct Table<'r, F: PastaField> {
    table: &'r mut dyn TableLayouter<F>,
}

impl<F: PastaField> fmt::Debug for Table<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Table")
    }
}

impl<'r, F: PastaField> From<&'r mut dyn TableLayouter<F>> for Table<'r, F> {
    fn from(table: &'r mut dyn TableLayouter<F>) -> Self {
        Self { table }
    }
}

impl<F: PastaField> Table<'_, F> {
    /// Assigns a table cell.
    ///
    /// # Errors
    ///
    /// See [`TableLayouter::assign_cell`].
    pub fn assign_cell<V, VR, A, AR>(
        &mut self,
        annotation: A,
        column: TableColumn,
        offset: usize,
        mut to: V,
    ) -> Result<(), Error>
    where
        V: FnMut() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.table
            .assign_cell(&|| annotation().into(), column, offset, &mut || {
                to().map(Into::into)
            })
    }
}

/// Lays regions and tables out on the circuit.
pub trait Layouter<F: PastaField> {
    /// The root layouter (namespaces forward to it).
    type Root: Layouter<F>;

    /// Assigns a region.
    ///
    /// # Errors
    ///
    /// [`Error`] from `assignment` or the backend.
    fn assign_region<A, AR, N, NR>(&mut self, name: N, assignment: A) -> Result<AR, Error>
    where
        A: FnOnce(Region<'_, F>) -> Result<AR, Error>,
        N: Fn() -> NR,
        NR: Into<String>;

    /// Loads a lookup table.
    ///
    /// # Errors
    ///
    /// [`Error`] from `assignment`, a [`TableError`] or the backend.
    fn assign_table<A, N, NR>(&mut self, name: N, assignment: A) -> Result<(), Error>
    where
        A: FnMut(Table<'_, F>) -> Result<(), Error>,
        N: Fn() -> NR,
        NR: Into<String>;

    /// Constrains `cell` to equal instance `column` at `row`.
    ///
    /// # Errors
    ///
    /// [`Error`] when a column is not equality-enabled or a cell is out of
    /// range.
    fn constrain_instance(
        &mut self,
        cell: Cell,
        column: Column<Instance>,
        row: usize,
    ) -> Result<(), Error>;

    /// The root layouter.
    fn get_root(&mut self) -> &mut Self::Root;

    /// Enters a namespace.
    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR;

    /// Leaves the innermost namespace.
    fn pop_namespace(&mut self, gadget_name: Option<String>);

    /// A layouter that names everything inside the namespace `name_fn`.
    fn namespace<NR, N>(&mut self, name_fn: N) -> NamespacedLayouter<'_, F, Self::Root>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.get_root().push_namespace(name_fn);
        NamespacedLayouter(self.get_root(), PhantomData)
    }
}

/// A layouter inside a namespace; the namespace ends when it is dropped.
#[derive(Debug)]
pub struct NamespacedLayouter<'a, F: PastaField, L: Layouter<F>>(&'a mut L, PhantomData<F>);

impl<'a, F: PastaField, L: Layouter<F> + 'a> Layouter<F> for NamespacedLayouter<'a, F, L> {
    type Root = L::Root;

    fn assign_region<A, AR, N, NR>(&mut self, name: N, assignment: A) -> Result<AR, Error>
    where
        A: FnOnce(Region<'_, F>) -> Result<AR, Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.0.assign_region(name, assignment)
    }

    fn assign_table<A, N, NR>(&mut self, name: N, assignment: A) -> Result<(), Error>
    where
        A: FnMut(Table<'_, F>) -> Result<(), Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.0.assign_table(name, assignment)
    }

    fn constrain_instance(
        &mut self,
        cell: Cell,
        column: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        self.0.constrain_instance(cell, column, row)
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self.0.get_root()
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.get_root().push_namespace(name_fn);
    }

    fn pop_namespace(&mut self, gadget_name: Option<String>) {
        self.get_root().pop_namespace(gadget_name);
    }
}

impl<'a, F: PastaField, L: Layouter<F> + 'a> Drop for NamespacedLayouter<'a, F, L> {
    fn drop(&mut self) {
        self.get_root().pop_namespace(None);
    }
}

/// A floor planner: synthesizes a circuit into an [`Assignment`] backend.
pub trait FloorPlanner {
    /// Synthesizes `circuit` with `config`; `constants` are the constraint
    /// system's constants columns.
    ///
    /// # Errors
    ///
    /// [`Error`] from the circuit or the backend.
    fn synthesize<F: PastaField, CS: Assignment<F>, C: Circuit<F>>(
        cs: &mut CS,
        circuit: &C,
        config: C::Config,
        constants: Vec<Column<Fixed>>,
    ) -> Result<(), Error>;
}

/// The halo2-axiom `SimpleFloorPlanner`: every region starts at row 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SimpleFloorPlanner;

impl FloorPlanner for SimpleFloorPlanner {
    fn synthesize<F: PastaField, CS: Assignment<F>, C: Circuit<F>>(
        cs: &mut CS,
        circuit: &C,
        config: C::Config,
        constants: Vec<Column<Fixed>>,
    ) -> Result<(), Error> {
        let layouter = SingleChipLayouter::new(cs, constants);
        circuit.synthesize(config, layouter)
    }
}

/// The layouter of [`SimpleFloorPlanner`].
pub struct SingleChipLayouter<'a, F: PastaField, CS: Assignment<F>> {
    cs: &'a mut CS,
    constants: Vec<Column<Fixed>>,
    /// The next free row of each constants column.
    next_constant_row: BTreeMap<Column<Fixed>, usize>,
    /// Columns that already hold a table.
    table_columns: Vec<TableColumn>,
    _marker: PhantomData<F>,
}

impl<F: PastaField, CS: Assignment<F>> fmt::Debug for SingleChipLayouter<'_, F, CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleChipLayouter")
            .field("constants", &self.constants)
            .field("next_constant_row", &self.next_constant_row)
            .field("table_columns", &self.table_columns)
            .finish_non_exhaustive()
    }
}

impl<'a, F: PastaField, CS: Assignment<F>> SingleChipLayouter<'a, F, CS> {
    /// A layouter writing into `cs`.
    pub const fn new(cs: &'a mut CS, constants: Vec<Column<Fixed>>) -> Self {
        Self {
            cs,
            constants,
            next_constant_row: BTreeMap::new(),
            table_columns: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<'a, F: PastaField, CS: Assignment<F> + 'a> Layouter<F> for SingleChipLayouter<'a, F, CS> {
    type Root = Self;

    fn assign_region<A, AR, N, NR>(&mut self, name: N, assignment: A) -> Result<AR, Error>
    where
        A: FnOnce(Region<'_, F>) -> Result<AR, Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.cs.enter_region(name().into())?;
        let mut region = SingleChipLayouterRegion {
            cs: &mut *self.cs,
            constants: Vec::new(),
        };
        let result = {
            let region: &mut dyn RegionLayouter<F> = &mut region;
            assignment(region.into())
        }?;
        let constants_to_assign = region.constants;
        self.cs.exit_region()?;

        // Constants go, in order, into the first constants column.
        match self.constants.first() {
            None => {
                if !constants_to_assign.is_empty() {
                    return Err(Error::NotEnoughColumnsForConstants);
                }
            }
            Some(&constants_column) => {
                let next_row = self.next_constant_row.entry(constants_column).or_insert(0);
                for (constant, cell) in constants_to_assign {
                    self.cs
                        .assign_fixed(constants_column, *next_row, constant)?;
                    self.cs.copy(
                        constants_column.into(),
                        *next_row,
                        cell.column,
                        cell.row_offset,
                    )?;
                    *next_row = next_row.checked_add(1).ok_or(Error::BoundsFailure)?;
                }
            }
        }
        Ok(result)
    }

    fn assign_table<A, N, NR>(&mut self, name: N, mut assignment: A) -> Result<(), Error>
    where
        A: FnMut(Table<'_, F>) -> Result<(), Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.cs.enter_region(name().into())?;
        let mut table = SimpleTableLayouter {
            cs: &mut *self.cs,
            used_columns: &self.table_columns,
            default_and_assigned: BTreeMap::new(),
        };
        {
            let table: &mut dyn TableLayouter<F> = &mut table;
            assignment(table.into())
        }?;
        let default_and_assigned = table.default_and_assigned;
        self.cs.exit_region()?;

        let first_unused = compute_table_lengths(&default_and_assigned)?;
        self.table_columns
            .extend(default_and_assigned.keys().copied());
        for (column, (default, _)) in default_and_assigned {
            let default = default.ok_or(TableError::ColumnNotAssigned(column))?;
            self.cs
                .fill_from_row(column.inner(), first_unused, default)?;
        }
        Ok(())
    }

    fn constrain_instance(
        &mut self,
        cell: Cell,
        column: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        self.cs
            .copy(cell.column, cell.row_offset, column.into(), row)
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.push_namespace(name_fn().into());
    }

    fn pop_namespace(&mut self, _gadget_name: Option<String>) {
        self.cs.pop_namespace();
    }
}

/// The region of [`SingleChipLayouter`]: offsets are absolute rows.
struct SingleChipLayouterRegion<'r, F: PastaField, CS: Assignment<F>> {
    cs: &'r mut CS,
    /// Constants to assign after the region, with the cells they constrain.
    constants: Vec<(Assigned<F>, Cell)>,
}

impl<F: PastaField, CS: Assignment<F>> RegionLayouter<F> for SingleChipLayouterRegion<'_, F, CS> {
    fn enable_selector(
        &mut self,
        _annotation: &dyn Fn() -> String,
        selector: &Selector,
        offset: usize,
    ) -> Result<(), Error> {
        self.cs.enable_selector(*selector, offset)
    }

    fn name_column(&mut self, annotation: &dyn Fn() -> String, column: Column<Any>) {
        self.cs.annotate_column(annotation(), column);
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        to: Value<Assigned<F>>,
    ) -> Result<Cell, Error> {
        self.cs.assign_advice(column, offset, to)?;
        Ok(Cell {
            row_offset: offset,
            column: column.into(),
        })
    }

    fn assign_advice_from_constant(
        &mut self,
        _annotation: &dyn Fn() -> String,
        column: Column<Advice>,
        offset: usize,
        constant: Assigned<F>,
    ) -> Result<Cell, Error> {
        let cell = self.assign_advice(column, offset, Value::known(constant))?;
        self.constrain_constant(cell, constant)?;
        Ok(cell)
    }

    fn assign_advice_from_instance(
        &mut self,
        _annotation: &dyn Fn() -> String,
        instance: Column<Instance>,
        row: usize,
        advice: Column<Advice>,
        offset: usize,
    ) -> Result<(Cell, Value<F>), Error> {
        let value = self.cs.query_instance(instance, row)?;
        let cell = self.assign_advice(advice, offset, value.map(Assigned::Trivial))?;
        self.cs
            .copy(cell.column, cell.row_offset, instance.into(), row)?;
        Ok((cell, value))
    }

    fn instance_value(
        &mut self,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<Value<F>, Error> {
        self.cs.query_instance(instance, row)
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        offset: usize,
        to: Assigned<F>,
    ) -> Result<Cell, Error> {
        self.cs.assign_fixed(column, offset, to)?;
        Ok(Cell {
            row_offset: offset,
            column: column.into(),
        })
    }

    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error> {
        self.cs.expect_fixed(column, row, value)
    }
    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.cs.reserve_advice(column, row)
    }

    fn constrain_constant(&mut self, cell: Cell, constant: Assigned<F>) -> Result<(), Error> {
        self.constants.push((constant, cell));
        Ok(())
    }

    fn constrain_equal(&mut self, left: Cell, right: Cell) -> Result<(), Error> {
        self.cs
            .copy(left.column, left.row_offset, right.column, right.row_offset)
    }
}

/// The row-0 value of a table column (once assigned) and which rows are
/// assigned.
type TableColumnState<F> = (Option<Value<Assigned<F>>>, Vec<bool>);

/// The table layouter of [`SingleChipLayouter`].
struct SimpleTableLayouter<'r, 'a, F: PastaField, CS: Assignment<F>> {
    cs: &'a mut CS,
    used_columns: &'r [TableColumn],
    default_and_assigned: BTreeMap<TableColumn, TableColumnState<F>>,
}

impl<F: PastaField, CS: Assignment<F>> TableLayouter<F> for SimpleTableLayouter<'_, '_, F, CS> {
    fn assign_cell(
        &mut self,
        _annotation: &dyn Fn() -> String,
        column: TableColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Value<Assigned<F>>,
    ) -> Result<(), Error> {
        if self.used_columns.contains(&column) {
            return Err(TableError::UsedColumn(column).into());
        }
        let value = to();
        self.cs
            .assign_fixed(column.inner(), offset, value.assign()?)?;
        let entry = self.default_and_assigned.entry(column).or_default();
        match (entry.0.is_none(), offset) {
            (true, 0) => entry.0 = Some(value),
            (false, 0) => return Err(TableError::OverwriteDefault(column).into()),
            _ => {}
        }
        if entry.1.len() <= offset {
            entry.1.resize(offset + 1, false);
        }
        entry.1[offset] = true;
        Ok(())
    }
}

/// The common length of the table columns, all of which must be assigned on
/// every row up to it.
fn compute_table_lengths<F>(
    default_and_assigned: &BTreeMap<TableColumn, TableColumnState<F>>,
) -> Result<usize, Error> {
    let mut common: Option<usize> = None;
    for (column, (default, assigned)) in default_and_assigned {
        if default.is_none() || assigned.is_empty() || !assigned.iter().all(|row| *row) {
            return Err(TableError::ColumnNotAssigned(*column).into());
        }
        match common {
            None => common = Some(assigned.len()),
            Some(expected) if expected != assigned.len() => {
                return Err(TableError::UnevenColumnLengths {
                    column: *column,
                    length: assigned.len(),
                    expected,
                }
                .into());
            }
            Some(_) => {}
        }
    }
    Ok(common.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;

    use super::*;
    use crate::{
        cs::{ConstraintSystem, Rotation},
        frontend::Assembly,
    };

    /// One advice column, one instance column of length 2, equality on both.
    fn instance_cs() -> (
        ConstraintSystem<Fp>,
        Column<Advice>,
        Column<Instance>,
        Selector,
    ) {
        let mut cs = ConstraintSystem::new();
        let advice = cs.advice_column();
        let instance = cs.instance_column(2);
        cs.enable_equality(advice);
        cs.enable_equality(instance);
        let selector = cs.selector();
        cs.create_gate("g", |meta| {
            let s = meta.query_selector(selector);
            vec![s * meta.query_advice(advice, Rotation::cur())]
        });
        (cs, advice, instance, selector)
    }

    #[test]
    fn assigned_cell_accessors() {
        let cell = Cell {
            row_offset: 4,
            column: Column::new(1, Any::Advice),
        };
        let assigned = AssignedCell::<Assigned<Fp>, Fp>::new(
            Value::known(Assigned::Rational(Fp::ONE, Fp::from(2))),
            cell,
        );
        assert_eq!(assigned.cell(), cell);
        assert_eq!(assigned.row_offset(), 4);
        assert_eq!(*assigned.column(), Column::new(1, Any::Advice));
        assert!(assigned.value().is_known());
        assert_eq!(
            assigned.value_field().evaluate(),
            Value::known(Fp::from(2).invert().unwrap())
        );
        let evaluated = assigned.evaluate();
        assert_eq!(
            evaluated.value().copied(),
            Value::known(Fp::from(2).invert().unwrap())
        );
    }

    #[test]
    fn instance_helpers_copy_and_read() {
        let (cs, advice, instance, selector) = instance_cs();
        let mut assembly =
            Assembly::new(&cs, 4, Some(&[vec![Fp::from(3), Fp::from(4)]])).expect("assembly");
        {
            let mut layouter = SingleChipLayouter::new(&mut assembly, Vec::new());
            layouter
                .assign_region(
                    || "instance",
                    |mut region| {
                        selector.enable(&mut region, 1)?;
                        region.name_column(|| "advice", advice);
                        assert_eq!(
                            region.instance_value(instance, 1)?,
                            Value::known(Fp::from(4))
                        );
                        let copied =
                            region.assign_advice_from_instance(|| "pub", instance, 0, advice, 2)?;
                        assert_eq!(copied.value().copied(), Value::known(Fp::from(3)));
                        assert_eq!(copied.row_offset(), 2);
                        assert!(region.instance_value(instance, 2).is_err());
                        Ok(())
                    },
                )
                .expect("region");
            assert!(format!("{layouter:?}").contains("SingleChipLayouter"));
        }
        let tables = assembly.finish().expect("finish");
        // The advice cell (2) and instance cell (0) share a cycle.
        let advice_position = cs.permutation().position(advice.into()).expect("eq");
        let instance_position = cs.permutation().position(instance.into()).expect("eq");
        assert_eq!(
            tables.permutation().mapping(advice_position, 2),
            Some((instance_position, 0))
        );
        assert!(tables.selectors()[0][1]);
        assert_eq!(tables.advice().expect("witness")[0][2], Fp::from(3));
    }

    #[test]
    fn nested_namespaces_forward_to_the_root() {
        let (cs, advice, ..) = instance_cs();
        let mut assembly = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ONE]])).expect("new");
        {
            let mut layouter = SingleChipLayouter::new(&mut assembly, Vec::new());
            let mut outer = layouter.namespace(|| "outer");
            {
                let mut inner = outer.namespace(|| "inner");
                inner
                    .assign_region(
                        || "r",
                        |mut region| {
                            region.assign_advice(advice, 0, Value::known(Fp::ONE))?;
                            Ok(())
                        },
                    )
                    .expect("region");
                inner.push_namespace(|| "extra");
                inner.pop_namespace(None);
            }
            outer
                .assign_table(|| "no table", |_| Ok(()))
                .expect("empty table");
            assert!(format!("{outer:?}").contains("NamespacedLayouter"));
        }
        let tables = assembly.finish().expect("finish");
        let names: Vec<&str> = tables.regions().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["outer::inner::r", "outer::no table"]);
    }

    #[test]
    fn region_and_table_debug_and_empty_tables() {
        assert_eq!(compute_table_lengths::<Fp>(&BTreeMap::new()), Ok(0));
        let (cs, advice, ..) = instance_cs();
        let mut assembly = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ONE]])).expect("new");
        let mut layouter = SingleChipLayouter::new(&mut assembly, Vec::new());
        layouter
            .assign_region(
                || "debug",
                |mut region| {
                    assert_eq!(format!("{region:?}"), "Region");
                    let cell = region.assign_fixed(Column::new(0, Fixed), 0, Fp::ONE);
                    assert_eq!(cell, Err(Error::BoundsFailure), "no fixed columns");
                    region.assign_advice(advice, 0, Value::known(Fp::ONE))?;
                    Ok(())
                },
            )
            .expect("region");
        layouter
            .assign_table(
                || "t",
                |table| {
                    assert_eq!(format!("{table:?}"), "Table");
                    Ok(())
                },
            )
            .expect("table");
    }
}
