//! The synthesis sink: the [`Assignment`] trait that floor planners drive,
//! and [`Assembly`], which records fixed values, selector activations, copy
//! constraints and (when proving) the witness.
//!
//! [`Assembly`] enforces the halo2 keygen rules without panicking: every
//! assignment, selector and copy must land in the usable rows
//! `0..2^k - b - 1`, copied columns must be equality-enabled, and instance
//! cells must lie within the column's declared exact length. Fractions
//! ([`Assigned::Rational`]) are batch-inverted when the assembly is finished:
//! fixed values (public) with the variable-time inversion, advice values
//! (secret) with the constant-time one.

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use iroha_pasta::{
    PastaField,
    field::{batch_invert, batch_invert_vartime},
};

use super::value::{Assigned, Value};
use crate::cs::{
    Advice, Any, Column, ConstraintSystem, CsError, Fixed, Instance, PermutationAssembly,
    PermutationError, Selector, TableColumn,
};

/// A lookup table could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// A table column was not assigned on every row up to its length.
    ColumnNotAssigned(TableColumn),
    /// Two table columns of one table have different lengths.
    UnevenColumnLengths {
        /// The column whose length differs.
        column: TableColumn,
        /// Its length.
        length: usize,
        /// The length of the earlier columns.
        expected: usize,
    },
    /// The column already holds a table.
    UsedColumn(TableColumn),
    /// Row 0 (the default value) was assigned twice.
    OverwriteDefault(TableColumn),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ColumnNotAssigned(column) => write!(
                f,
                "table column {} is not assigned on every row",
                column.inner().index()
            ),
            Self::UnevenColumnLengths {
                column,
                length,
                expected,
            } => write!(
                f,
                "table column {} has length {length}, expected {expected}",
                column.inner().index()
            ),
            Self::UsedColumn(column) => {
                write!(
                    f,
                    "table column {} already holds a table",
                    column.inner().index()
                )
            }
            Self::OverwriteDefault(column) => write!(
                f,
                "the default value of table column {} was assigned twice",
                column.inner().index()
            ),
        }
    }
}

/// A synthesis error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The caller cancelled synthesis before completing its assignment.
    Cancelled,
    /// A value needed during synthesis is unknown (a witness value while
    /// proving, a fixed or table value at any time), or a circuit reported a
    /// synthesis failure.
    Synthesis,
    /// `2^k` rows do not fit the circuit.
    NotEnoughRowsAvailable {
        /// The requested `k`.
        current_k: u32,
    },
    /// A row outside the usable rows.
    RowOutOfRange {
        /// The row.
        row: usize,
        /// The number of usable rows.
        usable_rows: usize,
    },
    /// The supplied instance columns do not have the declared shape.
    InstanceShape {
        /// The column whose length differs, or `None` for the column count.
        column: Option<usize>,
        /// The declared count or length.
        expected: usize,
        /// The supplied count or length.
        found: usize,
    },
    /// An instance row beyond the column's declared length.
    InstanceRowOutOfRange {
        /// The instance column.
        column: usize,
        /// The row.
        row: usize,
        /// The declared length.
        length: usize,
    },
    /// A column or selector index outside the constraint system.
    BoundsFailure,
    /// A guarded fixed value or exclusively reserved advice cell conflicts.
    LayoutConflict {
        /// Conflicting physical column.
        column: Column<Any>,
        /// Absolute row.
        row: usize,
    },
    /// A copy names a column that is not equality-enabled.
    ColumnNotInPermutation(Column<Any>),
    /// The circuit constrains constants but no column was enabled for them.
    NotEnoughColumnsForConstants,
    /// A lookup table could not be loaded.
    Table(TableError),
    /// The constraint system is invalid.
    ConstraintSystem(Box<CsError>),
    /// Regions were nested, or exited without being entered.
    RegionNesting,
    /// The operation needs witness tables, but these come from key generation.
    WitnessRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("synthesis cancelled"),
            Self::LayoutConflict { column, row } => {
                write!(f, "layout conflict at {column:?}, row {row}")
            }
            Self::Synthesis => f.write_str("a required value is unknown or synthesis failed"),
            Self::NotEnoughRowsAvailable { current_k } => {
                write!(f, "k = {current_k} does not provide enough rows")
            }
            Self::RowOutOfRange { row, usable_rows } => {
                write!(f, "row {row} is outside the {usable_rows} usable rows")
            }
            Self::InstanceShape {
                column: None,
                expected,
                found,
            } => write!(f, "{found} instance columns supplied, {expected} declared"),
            Self::InstanceShape {
                column: Some(column),
                expected,
                found,
            } => write!(
                f,
                "instance column {column} has {found} values, {expected} declared"
            ),
            Self::InstanceRowOutOfRange {
                column,
                row,
                length,
            } => write!(
                f,
                "instance column {column} row {row} is beyond its length {length}"
            ),
            Self::BoundsFailure => f.write_str("a column or selector index is out of range"),
            Self::ColumnNotInPermutation(column) => write!(
                f,
                "{:?} column {} is not equality-enabled",
                column.column_type(),
                column.index()
            ),
            Self::NotEnoughColumnsForConstants => {
                f.write_str("constants are constrained but no constants column is enabled")
            }
            Self::Table(error) => error.fmt(f),
            Self::ConstraintSystem(error) => error.fmt(f),
            Self::RegionNesting => f.write_str("regions were nested or exited without entry"),
            Self::WitnessRequired => f.write_str("witness tables are required"),
        }
    }
}

impl std::error::Error for Error {}
impl From<iroha_pasta::Cancelled> for Error {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<TableError> for Error {
    fn from(error: TableError) -> Self {
        Self::Table(error)
    }
}

impl From<CsError> for Error {
    fn from(error: CsError) -> Self {
        match error {
            CsError::Cancelled => Self::Cancelled,
            CsError::NotEnoughRows { k, .. } => Self::NotEnoughRowsAvailable { current_k: k },
            other => Self::ConstraintSystem(Box::new(other)),
        }
    }
}

impl From<PermutationError> for Error {
    fn from(error: PermutationError) -> Self {
        match error {
            PermutationError::ColumnNotInPermutation(column) => {
                Self::ColumnNotInPermutation(column)
            }
            PermutationError::RowOutOfBounds { .. } | PermutationError::TooManyCells => {
                Self::BoundsFailure
            }
        }
    }
}

/// The backend a floor planner writes a circuit into.
pub trait Assignment<F: PastaField> {
    /// Opens a region.
    ///
    /// # Errors
    ///
    /// [`Error::RegionNesting`] when a region is already open.
    fn enter_region(&mut self, name: String) -> Result<(), Error>;

    /// Closes the open region.
    ///
    /// # Errors
    ///
    /// [`Error::RegionNesting`] when no region is open.
    fn exit_region(&mut self) -> Result<(), Error>;

    /// Names a column for diagnostics.
    fn annotate_column(&mut self, name: String, column: Column<Any>);

    /// Enables `selector` on `row`.
    ///
    /// # Errors
    ///
    /// [`Error`] when the row or selector is out of range.
    fn enable_selector(&mut self, selector: Selector, row: usize) -> Result<(), Error>;

    /// The instance value at `row` (unknown during key generation).
    ///
    /// # Errors
    ///
    /// [`Error`] when the row is beyond the column's declared length.
    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<F>, Error>;

    /// Assigns an advice cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range, or the value is unknown while
    /// proving.
    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error>;

    /// Assigns a fixed cell.
    ///
    /// # Errors
    ///
    /// [`Error`] when the cell is out of range.
    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: Assigned<F>,
    ) -> Result<(), Error>;

    /// Requires this fixed cell's existing, future and final value to match.
    /// This is a synthesis guard, not an additional polynomial constraint.
    /// # Errors
    /// Out-of-range cells or a conflicting fixed assignment.
    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error>;

    /// Reserves one currently unassigned advice cell for exactly one write.
    /// Reservations apply to unknown-witness synthesis too.
    /// # Errors
    /// Out-of-range, already assigned or already reserved cells.
    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error>;

    /// Constrains two cells to be equal.
    ///
    /// # Errors
    ///
    /// [`Error`] when a column is not equality-enabled or a cell is out of
    /// range.
    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error>;

    /// Assigns `value` to every usable row of `column` from `from_row` on.
    ///
    /// # Errors
    ///
    /// [`Error`] when `from_row` is out of range or the value is unknown.
    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error>;

    /// Enters a namespace (region names get its prefix).
    fn push_namespace(&mut self, name: String);

    /// Leaves the innermost namespace.
    fn pop_namespace(&mut self);
}

/// A region recorded for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionRecord {
    /// The region name, prefixed by its namespaces.
    pub name: String,
    /// For each column the region assigned, the first and last row.
    pub extents: BTreeMap<Column<Any>, (usize, usize)>,
}

impl RegionRecord {
    /// Whether the region assigned `column` at a row range containing `row`.
    #[must_use]
    pub fn covers(&self, column: Column<Any>, row: usize) -> bool {
        self.extents
            .get(&column)
            .is_some_and(|(first, last)| (*first..=*last).contains(&row))
    }

    /// Widens the extent of `column` to include `row`.
    fn touch(&mut self, column: Column<Any>, row: usize) {
        self.extents
            .entry(column)
            .and_modify(|(first, last)| {
                *first = (*first).min(row);
                *last = (*last).max(row);
            })
            .or_insert((row, row));
    }
}

/// A fraction waiting for batch inversion.
#[derive(Clone, Debug)]
struct PendingFraction<F: PastaField> {
    numerator: F,
    denominator: F,
}
impl<F: PastaField> Drop for PendingFraction<F> {
    fn drop(&mut self) {
        self.numerator.zeroize();
        self.denominator.zeroize();
    }
}

/// Records one synthesis run.
#[derive(Clone, Debug)]
pub struct Assembly<F: PastaField> {
    cancellation: Option<iroha_pasta::CancellationToken>,
    k: u32,
    n: usize,
    usable_rows: usize,
    instance_lengths: Vec<usize>,
    instance: Option<Vec<Vec<F>>>,
    fixed: Vec<Vec<F>>,
    fixed_assigned: Vec<Vec<bool>>,
    fixed_pending: BTreeMap<(usize, usize), PendingFraction<F>>,
    fixed_expectations: BTreeMap<(usize, usize), F>,
    advice_reservations: BTreeSet<(usize, usize)>,
    advice: Option<crate::secret::SecretColumns<F>>,
    advice_assigned: Vec<Vec<bool>>,
    advice_pending: BTreeMap<(usize, usize), PendingFraction<F>>,
    selectors: Vec<Vec<bool>>,
    permutation: PermutationAssembly,
    regions: Vec<RegionRecord>,
    current_region: Option<RegionRecord>,
    namespaces: Vec<String>,
}

impl<F: PastaField> Assembly<F> {
    /// An empty assembly for `cs` at `k`.
    ///
    /// With `instances = None` it records key-generation data only (advice
    /// values are ignored and instance values are unknown); with
    /// `Some(instances)` it records the witness, and every instance column
    /// must have exactly its declared length.
    ///
    /// # Errors
    ///
    /// [`Error`] when the constraint system is invalid, `k` is too small, or
    /// the instances have the wrong shape.
    pub fn new(
        cs: &ConstraintSystem<F>,
        k: u32,
        instances: Option<&[Vec<F>]>,
    ) -> Result<Self, Error> {
        cs.check()?;
        let usable_rows = cs.usable_rows(k)?;
        let n = crate::cs::domain_size(k).ok_or(Error::NotEnoughRowsAvailable { current_k: k })?;
        let instance = match instances {
            None => None,
            Some(columns) => {
                let declared = cs.instance_lengths();
                if columns.len() != declared.len() {
                    return Err(Error::InstanceShape {
                        column: None,
                        expected: declared.len(),
                        found: columns.len(),
                    });
                }
                for (column, (values, length)) in columns.iter().zip(declared).enumerate() {
                    if values.len() != *length {
                        return Err(Error::InstanceShape {
                            column: Some(column),
                            expected: *length,
                            found: values.len(),
                        });
                    }
                }
                Some(columns.to_vec())
            }
        };
        let advice = instance.as_ref().map(|_| {
            crate::secret::SecretColumns::new(vec![vec![F::ZERO; n]; cs.num_advice_columns()])
        });
        Ok(Self {
            cancellation: None,
            k,
            n,
            usable_rows,
            instance_lengths: cs.instance_lengths().to_vec(),
            instance,
            fixed: vec![vec![F::ZERO; n]; cs.num_fixed_columns()],
            fixed_assigned: vec![vec![false; n]; cs.num_fixed_columns()],
            fixed_pending: BTreeMap::new(),
            fixed_expectations: BTreeMap::new(),
            advice_reservations: BTreeSet::new(),
            advice,
            advice_assigned: vec![vec![false; n]; cs.num_advice_columns()],
            advice_pending: BTreeMap::new(),
            selectors: vec![vec![false; n]; cs.num_selectors()],
            permutation: PermutationAssembly::new(n, cs.permutation())?,
            regions: Vec::new(),
            current_region: None,
            namespaces: Vec::new(),
        })
    }

    /// Creates a synthesis sink bound to one caller cancellation signal.
    ///
    /// # Errors
    /// As [`Self::new`], or [`Error::Cancelled`].
    pub fn new_cancellable(
        cs: &ConstraintSystem<F>,
        k: u32,
        instances: Option<&[Vec<F>]>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let mut result = Self::new(cs, k, instances)?;
        result.cancellation = cancellation.cloned();
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(result)
    }

    /// Whether this assembly records a witness.
    #[must_use]
    pub const fn is_witness(&self) -> bool {
        self.instance.is_some()
    }

    /// Checks that `row` is usable.
    fn check_row(&self, row: usize) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(self.cancellation.as_ref())?;
        if row < self.usable_rows {
            Ok(())
        } else {
            Err(Error::RowOutOfRange {
                row,
                usable_rows: self.usable_rows,
            })
        }
    }

    /// Checks that an instance cell lies within its column's length.
    fn check_instance_row(&self, column: usize, row: usize) -> Result<(), Error> {
        let length = *self
            .instance_lengths
            .get(column)
            .ok_or(Error::BoundsFailure)?;
        if row < length {
            Ok(())
        } else {
            Err(Error::InstanceRowOutOfRange {
                column,
                row,
                length,
            })
        }
    }

    /// Records a cell in the open region.
    fn touch(&mut self, column: Column<Any>, row: usize) {
        if let Some(region) = self.current_region.as_mut() {
            region.touch(column, row);
        }
    }

    /// Batch-inverts pending fractions and returns the finished tables.
    ///
    /// # Errors
    ///
    /// [`Error::RegionNesting`] when a region is still open.
    pub fn finish(mut self) -> Result<AssignedTables<F>, Error> {
        iroha_pasta::CancellationToken::checkpoint(self.cancellation.as_ref())?;
        if self.current_region.is_some() {
            return Err(Error::RegionNesting);
        }
        resolve_fractions(&mut self.fixed, &self.fixed_pending, true);
        for (&(column, row), expected) in &self.fixed_expectations {
            if !self.fixed_assigned[column][row] || self.fixed[column][row] != *expected {
                return Err(Error::LayoutConflict {
                    column: Column::new(column, Any::Fixed),
                    row,
                });
            }
        }
        for &(column, row) in &self.advice_reservations {
            if !self.advice_assigned[column][row] {
                return Err(Error::LayoutConflict {
                    column: Column::new(column, Any::Advice),
                    row,
                });
            }
        }
        if let Some(advice) = self.advice.as_mut() {
            resolve_fractions(advice, &self.advice_pending, false);
        }
        iroha_pasta::CancellationToken::checkpoint(self.cancellation.as_ref())?;
        Ok(AssignedTables {
            k: self.k,
            n: self.n,
            usable_rows: self.usable_rows,
            instance_lengths: self.instance_lengths,
            instance: self.instance,
            fixed: self.fixed,
            fixed_assigned: self.fixed_assigned,
            advice: self.advice,
            advice_assigned: self.advice_assigned,
            selectors: self.selectors,
            permutation: self.permutation,
            regions: self.regions,
        })
    }
}

/// Writes `numerator / denominator` (zero for a zero denominator) into every
/// pending cell, with one batch inversion.
fn resolve_fractions<F: PastaField>(
    columns: &mut [Vec<F>],
    pending: &BTreeMap<(usize, usize), PendingFraction<F>>,
    public: bool,
) {
    let mut denominators =
        crate::secret::SecretPolynomial::new(pending.values().map(|f| f.denominator).collect());
    if public {
        batch_invert_vartime(&mut denominators);
    } else {
        batch_invert(&mut denominators);
    }
    for (((column, row), fraction), inverse) in pending.iter().zip(denominators.iter()) {
        if let Some(cell) = columns.get_mut(*column).and_then(|c| c.get_mut(*row)) {
            *cell = fraction.numerator * inverse;
        }
    }
}

/// Stores an assigned value, deferring fractions to batch inversion.
fn store<F: PastaField>(
    columns: &mut [Vec<F>],
    pending: &mut BTreeMap<(usize, usize), PendingFraction<F>>,
    column: usize,
    row: usize,
    value: Assigned<F>,
) -> Result<(), Error> {
    let cell = columns
        .get_mut(column)
        .and_then(|c| c.get_mut(row))
        .ok_or(Error::BoundsFailure)?;
    match value {
        Assigned::Zero => {
            *cell = F::ZERO;
            pending.remove(&(column, row));
        }
        Assigned::Trivial(value) => {
            *cell = value;
            pending.remove(&(column, row));
        }
        Assigned::Rational(numerator, denominator) => {
            *cell = F::ZERO;
            pending.insert(
                (column, row),
                PendingFraction {
                    numerator,
                    denominator,
                },
            );
        }
    }
    Ok(())
}

/// Marks a cell assigned.
fn mark(flags: &mut [Vec<bool>], column: usize, row: usize) -> Result<(), Error> {
    let flag = flags
        .get_mut(column)
        .and_then(|c| c.get_mut(row))
        .ok_or(Error::BoundsFailure)?;
    *flag = true;
    Ok(())
}

impl<F: PastaField> Assignment<F> for Assembly<F> {
    fn enter_region(&mut self, name: String) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(self.cancellation.as_ref())?;
        if self.current_region.is_some() {
            return Err(Error::RegionNesting);
        }
        let name = if self.namespaces.is_empty() {
            name
        } else if name.is_empty() {
            self.namespaces.join("::")
        } else {
            format!("{}::{name}", self.namespaces.join("::"))
        };
        self.current_region = Some(RegionRecord {
            name,
            extents: BTreeMap::new(),
        });
        Ok(())
    }

    fn exit_region(&mut self) -> Result<(), Error> {
        let region = self.current_region.take().ok_or(Error::RegionNesting)?;
        self.regions.push(region);
        Ok(())
    }

    fn annotate_column(&mut self, _name: String, _column: Column<Any>) {
        // Column names live in the constraint system; regions carry no
        // per-region column names in this backend.
    }

    fn enable_selector(&mut self, selector: Selector, row: usize) -> Result<(), Error> {
        self.check_row(row)?;
        let rows = self
            .selectors
            .get_mut(selector.index())
            .ok_or(Error::BoundsFailure)?;
        rows[row] = true;
        Ok(())
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<F>, Error> {
        self.check_row(row)?;
        self.check_instance_row(column.index(), row)?;
        Ok(self
            .instance
            .as_ref()
            .map_or_else(Value::unknown, |columns| {
                Value::known(columns[column.index()][row])
            }))
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.check_row(row)?;
        if self.advice_reservations.contains(&(column.index(), row))
            && self.advice_assigned[column.index()][row]
        {
            return Err(Error::LayoutConflict {
                column: column.into(),
                row,
            });
        }
        mark(&mut self.advice_assigned, column.index(), row)?;
        if let Some(advice) = self.advice.as_mut() {
            store(
                advice,
                &mut self.advice_pending,
                column.index(),
                row,
                value.assign()?,
            )?;
        }
        self.touch(column.into(), row);
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        value: Assigned<F>,
    ) -> Result<(), Error> {
        self.check_row(row)?;
        if self
            .fixed_expectations
            .get(&(column.index(), row))
            .is_some_and(|expected| *expected != value.evaluate())
        {
            return Err(Error::LayoutConflict {
                column: column.into(),
                row,
            });
        }
        mark(&mut self.fixed_assigned, column.index(), row)?;
        store(
            &mut self.fixed,
            &mut self.fixed_pending,
            column.index(),
            row,
            value,
        )?;
        self.touch(column.into(), row);
        Ok(())
    }

    fn expect_fixed(&mut self, column: Column<Fixed>, row: usize, value: F) -> Result<(), Error> {
        self.check_row(row)?;
        let index = column.index();
        let assigned = self.fixed_assigned.get(index).ok_or(Error::BoundsFailure)?[row];
        let current = self
            .fixed_pending
            .get(&(index, row))
            .map_or(self.fixed[index][row], |fraction| {
                Assigned::Rational(fraction.numerator, fraction.denominator).evaluate()
            });
        if assigned && current != value
            || self
                .fixed_expectations
                .get(&(index, row))
                .is_some_and(|expected| *expected != value)
        {
            return Err(Error::LayoutConflict {
                column: column.into(),
                row,
            });
        }
        self.fixed_expectations.insert((index, row), value);
        Ok(())
    }

    fn reserve_advice(&mut self, column: Column<Advice>, row: usize) -> Result<(), Error> {
        self.check_row(row)?;
        let assigned = self
            .advice_assigned
            .get(column.index())
            .ok_or(Error::BoundsFailure)?[row];
        if assigned || !self.advice_reservations.insert((column.index(), row)) {
            return Err(Error::LayoutConflict {
                column: column.into(),
                row,
            });
        }
        Ok(())
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        self.check_row(left_row)?;
        self.check_row(right_row)?;
        for (column, row) in [(left_column, left_row), (right_column, right_row)] {
            if *column.column_type() == Any::Instance {
                self.check_instance_row(column.index(), row)?;
            }
        }
        self.permutation
            .copy(left_column, left_row, right_column, right_row)?;
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        value: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.check_row(from_row)?;
        let value = value.assign()?;
        for row in from_row..self.usable_rows {
            self.assign_fixed(column, row, value)?;
        }
        Ok(())
    }

    fn push_namespace(&mut self, name: String) {
        self.namespaces.push(name);
    }

    fn pop_namespace(&mut self) {
        self.namespaces.pop();
    }
}

/// The tables of a finished synthesis run.
#[derive(Clone, Debug)]
pub struct AssignedTables<F: PastaField> {
    k: u32,
    n: usize,
    usable_rows: usize,
    instance_lengths: Vec<usize>,
    instance: Option<Vec<Vec<F>>>,
    fixed: Vec<Vec<F>>,
    fixed_assigned: Vec<Vec<bool>>,
    advice: Option<crate::secret::SecretColumns<F>>,
    advice_assigned: Vec<Vec<bool>>,
    selectors: Vec<Vec<bool>>,
    permutation: PermutationAssembly,
    regions: Vec<RegionRecord>,
}

impl<F: PastaField> AssignedTables<F> {
    /// `log2` of the domain size.
    #[must_use]
    pub const fn k(&self) -> u32 {
        self.k
    }

    /// The domain size `2^k`.
    #[must_use]
    pub const fn n(&self) -> usize {
        self.n
    }

    /// The usable rows `2^k - b - 1`.
    #[must_use]
    pub const fn usable_rows(&self) -> usize {
        self.usable_rows
    }

    /// The declared instance lengths.
    #[must_use]
    pub fn instance_lengths(&self) -> &[usize] {
        &self.instance_lengths
    }

    /// The instance values (`None` for key generation).
    #[must_use]
    pub fn instance(&self) -> Option<&[Vec<F>]> {
        self.instance.as_deref()
    }

    /// Fixed values per column (unassigned cells are zero).
    #[must_use]
    pub fn fixed(&self) -> &[Vec<F>] {
        &self.fixed
    }

    /// Whether each fixed cell was assigned.
    #[must_use]
    pub fn fixed_assigned(&self) -> &[Vec<bool>] {
        &self.fixed_assigned
    }

    /// Advice values per column (`None` for key generation; unassigned cells
    /// are zero).
    #[must_use]
    pub fn advice(&self) -> Option<&[Vec<F>]> {
        self.advice.as_ref().map(|advice| advice.as_slice())
    }

    /// Moves the advice values out (`None` for key generation or when they
    /// were already taken), so a prover can own the secret witness without
    /// leaving an unzeroized copy behind.
    pub fn take_advice(&mut self) -> Option<Vec<Vec<F>>> {
        self.advice
            .take()
            .map(crate::secret::SecretColumns::into_vec)
    }

    /// Moves the public key-generation inputs out and releases synthesis
    /// bookkeeping before FFTs, commitments and proving-key caches are built.
    pub(crate) fn into_keygen_parts(self) -> (Vec<Vec<F>>, Vec<Vec<bool>>, PermutationAssembly) {
        (self.fixed, self.selectors, self.permutation)
    }

    /// Whether each advice cell was assigned.
    #[must_use]
    pub fn advice_assigned(&self) -> &[Vec<bool>] {
        &self.advice_assigned
    }

    /// Selector activations per selector and row.
    #[must_use]
    pub fn selectors(&self) -> &[Vec<bool>] {
        &self.selectors
    }

    /// The copy constraints.
    #[must_use]
    pub const fn permutation(&self) -> &PermutationAssembly {
        &self.permutation
    }

    /// The regions in synthesis order.
    #[must_use]
    pub fn regions(&self) -> &[RegionRecord] {
        &self.regions
    }

    /// The first region that assigned `column` around `row`.
    #[must_use]
    pub fn region_of(&self, column: Column<Any>, row: usize) -> Option<(usize, &str)> {
        self.regions
            .iter()
            .enumerate()
            .find(|(_, region)| region.covers(column, row))
            .map(|(index, region)| (index, region.name.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;

    use super::*;
    use crate::cs::Rotation;

    fn small_cs() -> (
        ConstraintSystem<Fp>,
        Column<Advice>,
        Column<Fixed>,
        Column<Instance>,
    ) {
        let mut cs = ConstraintSystem::<Fp>::new();
        let a = cs.advice_column();
        let f = cs.fixed_column();
        let i = cs.instance_column(2);
        cs.enable_equality(a);
        cs.enable_equality(i);
        let s = cs.selector();
        cs.create_gate("g", |meta| {
            let s = meta.query_selector(s);
            let a = meta.query_advice(a, Rotation::cur());
            vec![s * a]
        });
        (cs, a, f, i)
    }

    #[test]
    fn new_checks_shapes() {
        let (cs, ..) = small_cs();
        assert!(Assembly::new(&cs, 4, None).is_ok());
        assert_eq!(
            Assembly::new(&cs, 2, None).unwrap_err(),
            Error::NotEnoughRowsAvailable { current_k: 2 }
        );
        assert_eq!(
            Assembly::new(&cs, 4, Some(&[])).unwrap_err(),
            Error::InstanceShape {
                column: None,
                expected: 1,
                found: 0
            }
        );
        assert_eq!(
            Assembly::new(&cs, 4, Some(&[vec![Fp::ONE]])).unwrap_err(),
            Error::InstanceShape {
                column: Some(0),
                expected: 2,
                found: 1
            }
        );
        let witness = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ZERO]])).expect("shape");
        assert!(witness.is_witness());
    }

    #[test]
    fn rows_beyond_usable_are_rejected() {
        let (cs, a, f, i) = small_cs();
        let mut assembly = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ZERO]])).expect("new");
        // n = 16, b = 5, usable = 10.
        let out = Error::RowOutOfRange {
            row: 10,
            usable_rows: 10,
        };
        assert_eq!(
            assembly.assign_advice(a, 10, Value::known(Assigned::Zero)),
            Err(out.clone())
        );
        assert_eq!(
            assembly.assign_fixed(f, 10, Assigned::Zero),
            Err(out.clone())
        );
        assert_eq!(
            assembly.enable_selector(Selector::new(0, true), 10),
            Err(out.clone())
        );
        assert_eq!(assembly.copy(a.into(), 0, a.into(), 10), Err(out.clone()));
        assert_eq!(
            assembly.fill_from_row(f, 10, Value::known(Assigned::Zero)),
            Err(out)
        );
        assert_eq!(
            assembly.enable_selector(Selector::new(5, true), 0),
            Err(Error::BoundsFailure)
        );
        assert_eq!(
            assembly.copy(a.into(), 0, f.into(), 0),
            Err(Error::ColumnNotInPermutation(f.into()))
        );
        assert_eq!(
            assembly.query_instance(i, 2),
            Err(Error::InstanceRowOutOfRange {
                column: 0,
                row: 2,
                length: 2
            })
        );
        assert_eq!(
            assembly.copy(a.into(), 0, i.into(), 3),
            Err(Error::InstanceRowOutOfRange {
                column: 0,
                row: 3,
                length: 2
            })
        );
        assert_eq!(assembly.query_instance(i, 0), Ok(Value::known(Fp::ONE)));
    }

    #[test]
    fn witness_and_keygen_modes() {
        let (cs, a, f, i) = small_cs();
        let mut keygen = Assembly::new(&cs, 4, None).expect("new");
        keygen
            .assign_advice(a, 0, Value::unknown())
            .expect("keygen ignores advice values");
        assert!(!keygen.query_instance(i, 1).expect("in range").is_known());
        keygen
            .assign_fixed(f, 1, Assigned::Trivial(Fp::from(5)))
            .expect("fixed");
        let tables = keygen.finish().expect("finish");
        assert!(tables.advice().is_none() && tables.instance().is_none());
        assert_eq!(tables.fixed()[0][1], Fp::from(5));
        assert!(tables.advice_assigned()[0][0]);
        let fixed_ptr = tables.fixed()[0].as_ptr();
        let selector_ptr = tables.selectors().as_ptr();
        let copy_digest = tables.permutation().mapping_digest();
        let (fixed, selectors, permutation) = tables.into_keygen_parts();
        assert_eq!(fixed[0].as_ptr(), fixed_ptr);
        assert_eq!(selectors.as_ptr(), selector_ptr);
        assert_eq!(permutation.mapping_digest(), copy_digest);
        assert_eq!(fixed[0][1], Fp::from(5));

        let mut witness = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ZERO]])).expect("new");
        assert_eq!(
            witness.assign_advice(a, 0, Value::unknown()),
            Err(Error::Synthesis)
        );
        witness
            .assign_advice(a, 1, Value::known(Assigned::Rational(Fp::ONE, Fp::from(4))))
            .expect("fraction");
        witness
            .assign_advice(a, 2, Value::known(Assigned::Rational(Fp::ONE, Fp::from(4))))
            .expect("fraction");
        witness
            .assign_advice(a, 2, Value::known(Assigned::Trivial(Fp::from(7))))
            .expect("overwrite");
        witness
            .assign_fixed(f, 0, Assigned::Rational(Fp::from(3), Fp::ZERO))
            .expect("zero denominator");
        let tables = witness.finish().expect("finish");
        let advice = tables.advice().expect("witness");
        assert_eq!(advice[0][1], Fp::from(4).invert().unwrap());
        assert_eq!(advice[0][2], Fp::from(7), "a later trivial value wins");
        assert_eq!(tables.fixed()[0][0], Fp::ZERO);
        assert_eq!(
            tables.instance().expect("witness")[0],
            vec![Fp::ONE, Fp::ZERO]
        );
        assert_eq!((tables.k(), tables.n(), tables.usable_rows()), (4, 16, 10));
        assert_eq!(tables.instance_lengths(), &[2]);
        assert!(tables.fixed_assigned()[0][0] && !tables.fixed_assigned()[0][1]);
        // The advice moves out once; nothing is left behind.
        let mut tables = tables;
        let taken = tables.take_advice().expect("witness advice");
        assert_eq!(taken[0][2], Fp::from(7));
        assert!(tables.advice().is_none());
        assert!(tables.take_advice().is_none());
    }

    #[test]
    fn regions_namespaces_and_fill() {
        let (cs, a, f, _) = small_cs();
        let mut assembly = Assembly::new(&cs, 4, Some(&[vec![Fp::ONE, Fp::ZERO]])).expect("new");
        assert_eq!(assembly.exit_region(), Err(Error::RegionNesting));
        assembly.push_namespace("chip".into());
        assembly.enter_region("rows".into()).expect("enter");
        assert_eq!(
            assembly.enter_region("nested".into()),
            Err(Error::RegionNesting)
        );
        assembly
            .assign_advice(a, 3, Value::known(Assigned::Trivial(Fp::ONE)))
            .expect("advice");
        assembly
            .assign_advice(a, 5, Value::known(Assigned::Trivial(Fp::ONE)))
            .expect("advice");
        assembly
            .enable_selector(Selector::new(0, true), 3)
            .expect("selector");
        assembly.annotate_column("a".into(), a.into());
        assembly.exit_region().expect("exit");
        assembly.enter_region(String::new()).expect("enter");
        assembly
            .fill_from_row(f, 7, Value::known(Assigned::Trivial(Fp::from(9))))
            .expect("fill");
        assert_eq!(
            assembly.fill_from_row(f, 0, Value::unknown()),
            Err(Error::Synthesis)
        );
        let unfinished = assembly.clone();
        assert_eq!(unfinished.finish().unwrap_err(), Error::RegionNesting);
        assembly.exit_region().expect("exit");
        assembly.pop_namespace();
        let tables = assembly.finish().expect("finish");
        assert_eq!(tables.regions()[0].name, "chip::rows");
        assert_eq!(tables.regions()[1].name, "chip");
        assert_eq!(tables.region_of(a.into(), 4), Some((0, "chip::rows")));
        assert_eq!(tables.region_of(a.into(), 6), None);
        assert_eq!(tables.region_of(f.into(), 9), Some((1, "chip")));
        assert!(tables.selectors()[0][3]);
        assert_eq!(tables.fixed()[0][7..10], [Fp::from(9); 3]);
        assert_eq!(
            tables.fixed()[0][10],
            Fp::ZERO,
            "fills stop at the usable rows"
        );
        assert!(tables.permutation().is_identity());
    }

    #[test]
    fn guarded_fixed_values_check_prior_future_final_and_bounds() {
        let (cs, _, fixed, _) = small_cs();
        for prior in [false, true] {
            let mut assembly = Assembly::new(&cs, 4, None).unwrap();
            if prior {
                assembly.assign_fixed(fixed, 0, Fp::ONE.into()).unwrap();
            }
            assembly.expect_fixed(fixed, 0, Fp::ONE).unwrap();
            assembly.expect_fixed(fixed, 0, Fp::ONE).unwrap();
            assert!(assembly.expect_fixed(fixed, 0, Fp::ZERO).is_err());
            assert!(assembly.assign_fixed(fixed, 0, Fp::ZERO.into()).is_err());
            assembly
                .assign_fixed(fixed, 0, Assigned::Rational(Fp::from(2), Fp::from(2)))
                .unwrap();
            assembly.finish().unwrap();
        }
        let mut wrong = Assembly::new(&cs, 4, None).unwrap();
        wrong.assign_fixed(fixed, 0, Fp::ONE.into()).unwrap();
        assert!(wrong.expect_fixed(fixed, 0, Fp::ZERO).is_err());
        for expected in [Fp::ZERO, Fp::ONE] {
            let mut missing = Assembly::new(&cs, 4, None).unwrap();
            missing.expect_fixed(fixed, 0, expected).unwrap();
            assert!(matches!(
                missing.finish(),
                Err(Error::LayoutConflict { .. })
            ));
        }
        let mut bounds = Assembly::new(&cs, 4, None).unwrap();
        assert!(
            bounds
                .expect_fixed(fixed, cs.usable_rows(4).unwrap(), Fp::ONE)
                .is_err()
        );
        assert!(
            bounds
                .expect_fixed(Column::new(99, Fixed), 0, Fp::ONE)
                .is_err()
        );
    }

    #[test]
    fn reserved_advice_rejects_collisions_and_missing_known_or_unknown_writes() {
        let (cs, advice, _, _) = small_cs();
        let instances = [vec![Fp::ZERO, Fp::ZERO]];
        for known in [false, true] {
            let input = known.then_some(instances.as_slice());
            let value = if known {
                Value::known(Fp::ONE.into())
            } else {
                Value::unknown()
            };
            let mut assembly = Assembly::new(&cs, 4, input).unwrap();
            assembly.reserve_advice(advice, 0).unwrap();
            assert!(assembly.reserve_advice(advice, 0).is_err());
            assembly.assign_advice(advice, 0, value).unwrap();
            assert!(assembly.assign_advice(advice, 0, value).is_err());
            assembly.finish().unwrap();
            let mut prior = Assembly::new(&cs, 4, input).unwrap();
            prior.assign_advice(advice, 0, value).unwrap();
            assert!(prior.reserve_advice(advice, 0).is_err());
            let mut missing = Assembly::new(&cs, 4, input).unwrap();
            missing.reserve_advice(advice, 0).unwrap();
            assert!(matches!(
                missing.finish(),
                Err(Error::LayoutConflict { .. })
            ));
        }
        let mut bounds = Assembly::new(&cs, 4, None).unwrap();
        assert!(
            bounds
                .reserve_advice(advice, cs.usable_rows(4).unwrap())
                .is_err()
        );
        assert!(bounds.reserve_advice(Column::new(99, Advice), 0).is_err());
    }

    #[test]
    fn errors_display() {
        let table = TableColumn::new(Column::new(0, Fixed));
        let errors = [
            Error::Synthesis,
            Error::NotEnoughRowsAvailable { current_k: 1 },
            Error::RowOutOfRange {
                row: 1,
                usable_rows: 0,
            },
            Error::InstanceShape {
                column: None,
                expected: 1,
                found: 0,
            },
            Error::InstanceShape {
                column: Some(0),
                expected: 1,
                found: 0,
            },
            Error::InstanceRowOutOfRange {
                column: 0,
                row: 1,
                length: 1,
            },
            Error::BoundsFailure,
            Error::ColumnNotInPermutation(Column::new(0, Any::Advice)),
            Error::NotEnoughColumnsForConstants,
            Error::Table(TableError::ColumnNotAssigned(table)),
            Error::Table(TableError::UnevenColumnLengths {
                column: table,
                length: 1,
                expected: 2,
            }),
            Error::Table(TableError::UsedColumn(table)),
            Error::Table(TableError::OverwriteDefault(table)),
            Error::ConstraintSystem(Box::new(CsError::Overflow)),
            Error::RegionNesting,
            Error::WitnessRequired,
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(
            Error::from(PermutationError::TooManyCells),
            Error::BoundsFailure
        );
        assert_eq!(
            Error::from(CsError::EmptyGate { gate: "g".into() }),
            Error::ConstraintSystem(Box::new(CsError::EmptyGate { gate: "g".into() }))
        );
    }
}
