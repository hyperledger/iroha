//! The constraint checker: halo2's `MockProver`, stricter, with cell-level
//! diagnostics (spec section 15, "Constraint checker").
//!
//! The checker is a naive interpreter over the **uncompressed source
//! expressions** of the constraint system: virtual selectors are read from
//! the recorded activations, and no selector compression, common
//! subexpression elimination or compiled evaluator is involved, so a lowering
//! bug cannot hide behind the same bug on the proving side.
//!
//! What it checks, on the tables of one synthesis run:
//!
//! - **Gates** on every row `0..n`, including `l_last` and the blinding rows,
//!   where the prover's advice values are random: each polynomial must
//!   evaluate to zero.
//! - **Lookups** on the usable rows `0..u`: each input tuple must equal some
//!   table tuple of a usable row.
//! - **Copies**: every cell of a copy cycle holds the same value and, in
//!   [`CheckMode::Strict`], was assigned.
//!
//! A queried cell is *poison* when the constraint must not depend on it:
//!
//! - an advice cell at or beyond row `u` ([`CellIssue::BeyondUsableRows`]);
//! - any cell whose query wraps around the domain boundary
//!   ([`CellIssue::Wrapped`]);
//! - in strict mode, an advice cell that was never assigned
//!   ([`CellIssue::Unassigned`]).
//!
//! Poison propagates through every operation except multiplication by an
//! exact zero, as in `MockProver`, so a disabled constraint may read poison but
//! an enabled one may not. Fixed cells and instance cells beyond the declared
//! length are verifier-known zeros, not poison. [`CheckMode::Halo2Compatible`]
//! reads unassigned advice cells in the usable rows as zero, which is what the
//! halo2-axiom `MockProver` does.
//!
//! The checker is single-threaded and deterministic; failures are reported in
//! gate, lookup and copy order.

use std::collections::BTreeSet;

use core::fmt;

use iroha_pasta::PastaField;

use crate::{
    cs::{
        AdviceQuery, Any, Column, ConstraintSystem, Expression, ExpressionEvaluator, FixedQuery,
        InstanceQuery, Rotation, Selector,
    },
    frontend::{AssignedTables, Circuit, Error, synthesize},
};

/// How unassigned advice cells in the usable rows are read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CheckMode {
    /// They are poison: a constraint that depends on one fails (default).
    #[default]
    Strict,
    /// They read as zero, as in the halo2-axiom `MockProver`.
    Halo2Compatible,
}

/// Why a queried cell is poison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellIssue {
    /// An advice cell that was never assigned (strict mode).
    Unassigned,
    /// An advice cell at or beyond the usable rows (`l_last` and the blinding
    /// rows hold prover randomness).
    BeyondUsableRows,
    /// The query wraps around the domain boundary.
    Wrapped,
}

/// A cell read while evaluating a failing constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueriedCell<F> {
    /// The column.
    pub column: Column<Any>,
    /// The query rotation.
    pub rotation: Rotation,
    /// The row read (`(row + rotation) mod n`).
    pub row: usize,
    /// The value read (zero for a poison cell).
    pub value: F,
    /// Why the cell is poison, if it is.
    pub issue: Option<CellIssue>,
}

/// Where a failure happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// The row at which the constraint was evaluated.
    pub row: usize,
    /// The first region that assigned a cell the constraint read there, as
    /// `(index, name)`.
    pub region: Option<(usize, String)>,
}

/// One unsatisfied constraint, lookup or copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckFailure<F> {
    /// A gate polynomial evaluated to a nonzero value.
    ConstraintNotSatisfied {
        /// The gate index.
        gate: usize,
        /// The gate name.
        gate_name: String,
        /// The polynomial index within the gate.
        constraint: usize,
        /// The polynomial name.
        constraint_name: String,
        /// Where it failed.
        location: Location,
        /// The nonzero value.
        value: F,
        /// The cells the polynomial read.
        cells: Vec<QueriedCell<F>>,
    },
    /// A gate polynomial depends on a poison cell.
    ConstraintPoisoned {
        /// The gate index.
        gate: usize,
        /// The gate name.
        gate_name: String,
        /// The polynomial index within the gate.
        constraint: usize,
        /// The polynomial name.
        constraint_name: String,
        /// Where it failed.
        location: Location,
        /// The cells the polynomial read; poison cells carry their issue.
        cells: Vec<QueriedCell<F>>,
    },
    /// An input tuple is not in the table.
    LookupInputMissing {
        /// The lookup index.
        lookup: usize,
        /// The lookup name.
        name: String,
        /// Where it failed.
        location: Location,
        /// The input tuple.
        input: Vec<F>,
        /// The cells the inputs read.
        cells: Vec<QueriedCell<F>>,
    },
    /// An input or table tuple depends on a poison cell.
    LookupPoisoned {
        /// The lookup index.
        lookup: usize,
        /// The lookup name.
        name: String,
        /// Whether the table side (rather than the input side) is poison.
        table: bool,
        /// Where it failed.
        location: Location,
        /// The cells read; poison cells carry their issue.
        cells: Vec<QueriedCell<F>>,
    },
    /// A copied cell was never assigned (strict mode).
    CopyUnassigned {
        /// The column.
        column: Column<Any>,
        /// The row.
        row: usize,
    },
    /// Two cells of one copy cycle differ.
    CopyMismatch {
        /// The first cell's column.
        left: Column<Any>,
        /// The first cell's row.
        left_row: usize,
        /// The first cell's value.
        left_value: F,
        /// The next cell of the cycle: its column.
        right: Column<Any>,
        /// Its row.
        right_row: usize,
        /// Its value.
        right_value: F,
    },
}

/// Formats `column` as `A3`, `F0` or `I1`.
fn column_label(column: Column<Any>) -> String {
    let kind = match column.column_type() {
        Any::Advice => 'A',
        Any::Fixed => 'F',
        Any::Instance => 'I',
    };
    format!("{kind}{}", column.index())
}

/// Formats the queried cells.
fn cells_label<F: fmt::Debug>(cells: &[QueriedCell<F>]) -> String {
    cells
        .iter()
        .map(|cell| {
            let base = format!(
                "{}[{:+}]@{}",
                column_label(cell.column),
                cell.rotation.0,
                cell.row
            );
            cell.issue.map_or_else(
                || format!("{base} = {:?}", cell.value),
                |issue| format!("{base} {issue:?}"),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "row {}", self.row)?;
        if let Some((index, name)) = &self.region {
            write!(f, " (region {index} `{name}`)")?;
        }
        Ok(())
    }
}

impl<F: fmt::Debug> fmt::Display for CheckFailure<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstraintNotSatisfied {
                gate,
                gate_name,
                constraint,
                constraint_name,
                location,
                value,
                cells,
            } => write!(
                f,
                "gate {gate} `{gate_name}` constraint {constraint} `{constraint_name}` is \
                 {value:?} at {location}; cells: {}",
                cells_label(cells)
            ),
            Self::ConstraintPoisoned {
                gate,
                gate_name,
                constraint,
                constraint_name,
                location,
                cells,
            } => write!(
                f,
                "gate {gate} `{gate_name}` constraint {constraint} `{constraint_name}` depends on \
                 a poison cell at {location}; cells: {}",
                cells_label(cells)
            ),
            Self::LookupInputMissing {
                lookup,
                name,
                location,
                input,
                cells,
            } => write!(
                f,
                "lookup {lookup} `{name}` input {input:?} at {location} is not in the table; \
                 cells: {}",
                cells_label(cells)
            ),
            Self::LookupPoisoned {
                lookup,
                name,
                table,
                location,
                cells,
            } => write!(
                f,
                "lookup {lookup} `{name}` {} depends on a poison cell at {location}; cells: {}",
                if *table { "table" } else { "input" },
                cells_label(cells)
            ),
            Self::CopyUnassigned { column, row } => write!(
                f,
                "copied cell {}@{row} was never assigned",
                column_label(*column)
            ),
            Self::CopyMismatch {
                left,
                left_row,
                left_value,
                right,
                right_row,
                right_value,
            } => write!(
                f,
                "copy {}@{left_row} = {left_value:?} differs from {}@{right_row} = {right_value:?}",
                column_label(*left),
                column_label(*right)
            ),
        }
    }
}

/// The result of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport<F> {
    failures: Vec<CheckFailure<F>>,
}

impl<F> CheckReport<F> {
    /// Whether every constraint, lookup and copy holds.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        self.failures.is_empty()
    }

    /// The failures in gate, lookup and copy order.
    #[must_use]
    pub fn failures(&self) -> &[CheckFailure<F>] {
        &self.failures
    }

    /// `Ok(())` when satisfied, the failures otherwise.
    ///
    /// # Errors
    ///
    /// The failures.
    pub fn into_result(self) -> Result<(), Vec<CheckFailure<F>>> {
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(self.failures)
        }
    }
}

impl<F: fmt::Debug> fmt::Display for CheckReport<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failures.is_empty() {
            return f.write_str("all constraints are satisfied");
        }
        for failure in &self.failures {
            writeln!(f, "{failure}")?;
        }
        Ok(())
    }
}

/// A value that is either a field element or poison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val<F> {
    Real(F),
    Poison,
}

/// The witness tables the checker reads.
struct Witness<'a, F: PastaField> {
    n: usize,
    usable: usize,
    mode: CheckMode,
    fixed: &'a [Vec<F>],
    advice: &'a [Vec<F>],
    advice_assigned: &'a [Vec<bool>],
    instance: &'a [Vec<F>],
    selectors: &'a [Vec<bool>],
    tables: &'a AssignedTables<F>,
}

impl<F: PastaField> Witness<'_, F> {
    /// Reads `column` at `row + rotation`: the target row, the value and the
    /// poison reason.
    fn read(
        &self,
        column: Column<Any>,
        rotation: Rotation,
        row: usize,
    ) -> (usize, F, Option<CellIssue>) {
        let (target, wrapped) = rotate(row, rotation, self.n);
        if wrapped {
            return (target, F::ZERO, Some(CellIssue::Wrapped));
        }
        let index = column.index();
        match column.column_type() {
            Any::Fixed => (target, self.fixed[index][target], None),
            Any::Instance => (
                target,
                self.instance[index].get(target).copied().unwrap_or(F::ZERO),
                None,
            ),
            Any::Advice => {
                if target >= self.usable {
                    (target, F::ZERO, Some(CellIssue::BeyondUsableRows))
                } else if self.mode == CheckMode::Strict && !self.advice_assigned[index][target] {
                    (target, F::ZERO, Some(CellIssue::Unassigned))
                } else {
                    (target, self.advice[index][target], None)
                }
            }
        }
    }

    /// The cells `expressions` read at `row`, in query order without repeats.
    fn queried_cells<'e>(
        &self,
        expressions: impl IntoIterator<Item = &'e Expression<F>>,
        row: usize,
    ) -> Vec<QueriedCell<F>>
    where
        F: 'e,
    {
        let mut seen = BTreeSet::new();
        let mut cells = Vec::new();
        for expression in expressions {
            expression.for_each_query(&mut |query| {
                if seen.insert((query.column, query.rotation)) {
                    let (target, value, issue) = self.read(query.column, query.rotation, row);
                    cells.push(QueriedCell {
                        column: query.column,
                        rotation: query.rotation,
                        row: target,
                        value,
                        issue,
                    });
                }
            });
        }
        cells
    }

    /// The location of a failure at `row` reading `cells`.
    fn locate(&self, row: usize, cells: &[QueriedCell<F>]) -> Location {
        let region = cells
            .iter()
            .filter(|cell| cell.issue != Some(CellIssue::Wrapped))
            .find_map(|cell| self.tables.region_of(cell.column, cell.row))
            .map(|(index, name)| (index, name.to_owned()));
        Location { row, region }
    }
}

/// `(row + rotation) mod n` and whether the query crosses the domain
/// boundary. `n <= 2^28` and `|rotation| < 2^31`, so the arithmetic fits an
/// `i64`.
fn rotate(row: usize, rotation: Rotation, n: usize) -> (usize, bool) {
    let n = i64::try_from(n).unwrap_or(i64::MAX).max(1);
    let target = i64::try_from(row)
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(rotation.0));
    let wrapped = !(0..n).contains(&target);
    (usize::try_from(target.rem_euclid(n)).unwrap_or(0), wrapped)
}

/// Evaluates an expression at one row with poison semantics.
struct RowEvaluator<'w, 'a, F: PastaField> {
    witness: &'w Witness<'a, F>,
    row: usize,
}

impl<F: PastaField> RowEvaluator<'_, '_, F> {
    /// A leaf value.
    fn leaf(&self, column: Column<Any>, rotation: Rotation) -> Val<F> {
        match self.witness.read(column, rotation, self.row) {
            (_, value, None) => Val::Real(value),
            (_, _, Some(_)) => Val::Poison,
        }
    }
}

impl<F: PastaField> ExpressionEvaluator<F> for RowEvaluator<'_, '_, F> {
    type Output = Val<F>;

    fn constant(&mut self, value: &F) -> Val<F> {
        Val::Real(*value)
    }

    fn selector(&mut self, selector: Selector) -> Val<F> {
        let active = self
            .witness
            .selectors
            .get(selector.index())
            .and_then(|rows| rows.get(self.row))
            .copied()
            .unwrap_or(false);
        Val::Real(if active { F::ONE } else { F::ZERO })
    }

    fn fixed(&mut self, query: FixedQuery) -> Val<F> {
        self.leaf(Column::new(query.column_index, Any::Fixed), query.rotation)
    }

    fn advice(&mut self, query: AdviceQuery) -> Val<F> {
        self.leaf(Column::new(query.column_index, Any::Advice), query.rotation)
    }

    fn instance(&mut self, query: InstanceQuery) -> Val<F> {
        self.leaf(
            Column::new(query.column_index, Any::Instance),
            query.rotation,
        )
    }

    fn negated(&mut self, value: Val<F>) -> Val<F> {
        match value {
            Val::Real(value) => Val::Real(-value),
            Val::Poison => Val::Poison,
        }
    }

    fn sum(&mut self, left: Val<F>, right: Val<F>) -> Val<F> {
        match (left, right) {
            (Val::Real(left), Val::Real(right)) => Val::Real(left + right),
            _ => Val::Poison,
        }
    }

    fn product(&mut self, left: Val<F>, right: Val<F>) -> Val<F> {
        match (left, right) {
            (Val::Real(left), Val::Real(right)) => Val::Real(left * right),
            // Poison times an exact zero is unconstrained, not poison.
            (Val::Real(zero), Val::Poison) | (Val::Poison, Val::Real(zero))
                if zero.is_zero_vartime() =>
            {
                Val::Real(F::ZERO)
            }
            _ => Val::Poison,
        }
    }

    fn scaled(&mut self, value: Val<F>, factor: &F) -> Val<F> {
        match value {
            Val::Real(value) => Val::Real(value * factor),
            Val::Poison if factor.is_zero_vartime() => Val::Real(F::ZERO),
            Val::Poison => Val::Poison,
        }
    }
}

/// Evaluates a tuple of expressions at `row`; `None` when any is poison.
fn evaluate_tuple<F: PastaField>(
    witness: &Witness<'_, F>,
    expressions: &[Expression<F>],
    row: usize,
) -> Option<Vec<F>> {
    expressions
        .iter()
        .map(
            |expression| match expression.evaluate(&mut RowEvaluator { witness, row }) {
                Val::Real(value) => Some(value),
                Val::Poison => None,
            },
        )
        .collect()
}

/// Checks `tables` (a witness run) against the uncompressed `cs`.
///
/// # Errors
///
/// [`Error::WitnessRequired`] for key-generation tables,
/// [`Error::BoundsFailure`] when the tables do not match `cs` (for example a
/// finalized constraint system), and the recorded configuration error.
pub fn check<F: PastaField>(
    cs: &ConstraintSystem<F>,
    tables: &AssignedTables<F>,
    mode: CheckMode,
) -> Result<CheckReport<F>, Error> {
    cs.check()?;
    let (Some(advice), Some(instance)) = (tables.advice(), tables.instance()) else {
        return Err(Error::WitnessRequired);
    };
    let n = tables.n();
    let shapes_match = tables.fixed().len() == cs.num_fixed_columns()
        && advice.len() == cs.num_advice_columns()
        && tables.advice_assigned().len() == cs.num_advice_columns()
        && instance.len() == cs.num_instance_columns()
        && tables.selectors().len() == cs.num_selectors()
        && tables.permutation().columns() == cs.permutation().columns()
        && tables
            .fixed()
            .iter()
            .chain(advice)
            .all(|column| column.len() == n)
        && tables
            .selectors()
            .iter()
            .chain(tables.advice_assigned())
            .all(|column| column.len() == n);
    if !shapes_match {
        return Err(Error::BoundsFailure);
    }
    let witness = Witness {
        n,
        usable: tables.usable_rows(),
        mode,
        fixed: tables.fixed(),
        advice,
        advice_assigned: tables.advice_assigned(),
        instance,
        selectors: tables.selectors(),
        tables,
    };
    let mut failures = Vec::new();
    check_gates(cs, &witness, &mut failures);
    check_lookups(cs, &witness, &mut failures);
    check_copies(&witness, &mut failures);
    Ok(CheckReport { failures })
}

/// Gates: every polynomial vanishes on every row of the domain.
fn check_gates<F: PastaField>(
    cs: &ConstraintSystem<F>,
    witness: &Witness<'_, F>,
    failures: &mut Vec<CheckFailure<F>>,
) {
    for (gate_index, gate) in cs.gates().iter().enumerate() {
        for (poly_index, poly) in gate.polynomials().iter().enumerate() {
            for row in 0..witness.n {
                let value = poly.evaluate(&mut RowEvaluator { witness, row });
                if matches!(value, Val::Real(v) if v.is_zero_vartime()) {
                    continue;
                }
                let cells = witness.queried_cells([poly], row);
                let location = witness.locate(row, &cells);
                let gate_name = gate.name().to_owned();
                let constraint_name = gate.constraint_name(poly_index).to_owned();
                failures.push(match value {
                    Val::Real(value) => CheckFailure::ConstraintNotSatisfied {
                        gate: gate_index,
                        gate_name,
                        constraint: poly_index,
                        constraint_name,
                        location,
                        value,
                        cells,
                    },
                    Val::Poison => CheckFailure::ConstraintPoisoned {
                        gate: gate_index,
                        gate_name,
                        constraint: poly_index,
                        constraint_name,
                        location,
                        cells,
                    },
                });
            }
        }
    }
}

/// Lookups: every usable input tuple is a usable table tuple.
fn check_lookups<F: PastaField>(
    cs: &ConstraintSystem<F>,
    witness: &Witness<'_, F>,
    failures: &mut Vec<CheckFailure<F>>,
) {
    for (lookup_index, lookup) in cs.lookups().iter().enumerate() {
        let mut table = BTreeSet::new();
        for row in 0..witness.usable {
            if let Some(tuple) = evaluate_tuple(witness, lookup.table_expressions(), row) {
                table.insert(tuple);
            } else {
                let cells = witness.queried_cells(lookup.table_expressions(), row);
                failures.push(CheckFailure::LookupPoisoned {
                    lookup: lookup_index,
                    name: lookup.name().to_owned(),
                    table: true,
                    location: witness.locate(row, &cells),
                    cells,
                });
            }
        }
        for row in 0..witness.usable {
            let input = evaluate_tuple(witness, lookup.input_expressions(), row);
            if input.as_ref().is_some_and(|tuple| table.contains(tuple)) {
                continue;
            }
            let cells = witness.queried_cells(lookup.input_expressions(), row);
            let location = witness.locate(row, &cells);
            failures.push(match input {
                Some(input) => CheckFailure::LookupInputMissing {
                    lookup: lookup_index,
                    name: lookup.name().to_owned(),
                    location,
                    input,
                    cells,
                },
                None => CheckFailure::LookupPoisoned {
                    lookup: lookup_index,
                    name: lookup.name().to_owned(),
                    table: false,
                    location,
                    cells,
                },
            });
        }
    }
}

/// The value of a copied cell and whether it was assigned.
fn copied_value<F: PastaField>(
    witness: &Witness<'_, F>,
    column: Column<Any>,
    row: usize,
) -> (F, bool) {
    let index = column.index();
    match column.column_type() {
        Any::Advice => (
            witness.advice[index][row],
            witness.advice_assigned[index][row],
        ),
        Any::Fixed => (
            witness.fixed[index][row],
            witness.tables.fixed_assigned()[index][row],
        ),
        Any::Instance => witness.instance[index]
            .get(row)
            .map_or((F::ZERO, false), |value| (*value, true)),
    }
}

/// Copies: every cell of a cycle equals its successor and was assigned.
fn check_copies<F: PastaField>(witness: &Witness<'_, F>, failures: &mut Vec<CheckFailure<F>>) {
    let permutation = witness.tables.permutation();
    let columns = permutation.columns();
    for (position, column) in columns.iter().enumerate() {
        for row in 0..witness.n {
            let Some((next_position, next_row)) = permutation.mapping(position, row) else {
                continue;
            };
            if (next_position, next_row) == (position, row) {
                continue;
            }
            let Some(next_column) = columns.get(next_position) else {
                continue;
            };
            let (value, assigned) = copied_value(witness, *column, row);
            if !assigned && witness.mode == CheckMode::Strict {
                failures.push(CheckFailure::CopyUnassigned {
                    column: *column,
                    row,
                });
            }
            let (next_value, _) = copied_value(witness, *next_column, next_row);
            if value != next_value {
                failures.push(CheckFailure::CopyMismatch {
                    left: *column,
                    left_row: row,
                    left_value: value,
                    right: *next_column,
                    right_row: next_row,
                    right_value: next_value,
                });
            }
        }
    }
}

/// Synthesizes `circuit` with `instances` at `k` and checks it.
///
/// # Errors
///
/// [`Error`] from synthesis; see also [`check`].
pub fn check_circuit<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    instances: &[Vec<F>],
    mode: CheckMode,
) -> Result<CheckReport<F>, Error> {
    let synthesized = synthesize(circuit, k, Some(instances))?;
    check(&synthesized.cs, &synthesized.tables, mode)
}

#[cfg(test)]
mod tests;
