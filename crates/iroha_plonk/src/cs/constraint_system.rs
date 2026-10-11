//! The constraint system: columns, interned queries, gates, lookups, the
//! permutation argument and selectors.
//!
//! [`ConstraintSystem`] mirrors halo2-axiom's `ConstraintSystem` for one
//! advice phase:
//!
//! - Queries are interned per kind in first-use order. `VirtualCells::query_*`
//!   interns when called; queries built from `Column::cur()` and friends are
//!   interned when the gate or lookup is created, in left-to-right expression
//!   order. `lookup` interns each table column before its input expression,
//!   `lookup_any` the input before the table. `enable_equality` interns
//!   `(column, 0)`. The order fixes the descriptor, the proof layout and the
//!   verifying key, so it equals halo2's.
//! - The degree is `max(3, lookup degrees, gate degrees, minimum_degree)` and
//!   the blinding factors are `max(3, max advice queries per column) + 2`.
//! - Every instance column declares its exact length (spec S4).
//!
//! `configure` code calls the builder methods without error handling, as in
//! halo2. Instead of panicking, a misuse (a simple selector in a sum, an empty
//! gate or lookup, ...) is recorded and reported by [`ConstraintSystem::check`]
//! and by every finalizing step.

use std::collections::BTreeMap;

use core::fmt;

use iroha_pasta::PastaField;

use super::{
    expression::{
        Advice, Any, Column, Expression, Fixed, FixedQuery, Instance, Rotation, Selector,
        SelectorReplacementError, SimpleSelectorMisuse, TableColumn,
    },
    gate::{Constraint, Gate, VirtualCell},
    lookup::LookupArgument,
    permutation::PermutationArgument,
    selector_compression::{self, CompressionError, SelectorDescription},
};

/// Largest supported `k` (spec section 1).
pub const MAX_K: u32 = 28;

/// A constraint-system configuration or finalization error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsError {
    /// The caller cancelled constraint-system finalization.
    Cancelled,
    /// A simple selector was used outside the allowed positions.
    SimpleSelector {
        /// The gate or lookup name.
        context: String,
        /// The violated rule.
        misuse: SimpleSelectorMisuse,
    },
    /// A gate has no polynomial.
    EmptyGate {
        /// The gate name.
        gate: String,
    },
    /// A lookup has no input/table pair.
    EmptyLookup {
        /// The lookup name.
        lookup: String,
    },
    /// The selector activation table has the wrong number of selectors.
    SelectorCount {
        /// Selectors in the constraint system.
        expected: usize,
        /// Activation vectors supplied.
        found: usize,
    },
    /// Selector compression failed.
    Compression(CompressionError),
    /// A selector has no replacement (internal invariant).
    SelectorReplacement(SelectorReplacementError),
    /// The constraint system needs more rows than `2^k` provides, or `k` is
    /// outside `1..=28`.
    NotEnoughRows {
        /// The requested `k`.
        k: u32,
        /// The minimum number of rows.
        minimum_rows: usize,
    },
    /// An instance column is longer than the usable rows.
    InstanceTooLong {
        /// The instance column.
        column: usize,
        /// Its declared length.
        length: usize,
        /// The usable rows at this `k`.
        usable_rows: usize,
    },
    /// A size computation overflowed.
    Overflow,
}

impl fmt::Display for CsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("constraint-system finalization cancelled"),
            Self::SimpleSelector { context, misuse } => write!(f, "{context}: {misuse}"),
            Self::EmptyGate { gate } => write!(f, "gate `{gate}` has no constraint"),
            Self::EmptyLookup { lookup } => write!(f, "lookup `{lookup}` has no input"),
            Self::SelectorCount { expected, found } => write!(
                f,
                "{found} selector activation vectors supplied for {expected} selectors"
            ),
            Self::Compression(error) => write!(f, "selector compression: {error}"),
            Self::SelectorReplacement(error) => error.fmt(f),
            Self::NotEnoughRows { k, minimum_rows } => write!(
                f,
                "k = {k} does not provide the {minimum_rows} rows the circuit needs"
            ),
            Self::InstanceTooLong {
                column,
                length,
                usable_rows,
            } => write!(
                f,
                "instance column {column} has length {length}, above the {usable_rows} usable rows"
            ),
            Self::Overflow => f.write_str("size arithmetic overflowed"),
        }
    }
}

impl std::error::Error for CsError {}
impl From<iroha_pasta::Cancelled> for CsError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<CompressionError> for CsError {
    fn from(error: CompressionError) -> Self {
        if matches!(error, CompressionError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Compression(error)
        }
    }
}

impl From<SelectorReplacementError> for CsError {
    fn from(error: SelectorReplacementError) -> Self {
        Self::SelectorReplacement(error)
    }
}

/// The description of a circuit's constraints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstraintSystem<F> {
    num_fixed_columns: usize,
    num_advice_columns: usize,
    instance_lengths: Vec<usize>,
    selectors: Vec<Selector>,
    gates: Vec<Gate<F>>,
    advice_queries: Vec<(Column<Advice>, Rotation)>,
    num_advice_queries: Vec<usize>,
    instance_queries: Vec<(Column<Instance>, Rotation)>,
    fixed_queries: Vec<(Column<Fixed>, Rotation)>,
    advice_query_indices: BTreeMap<(usize, i32), usize>,
    instance_query_indices: BTreeMap<(usize, i32), usize>,
    fixed_query_indices: BTreeMap<(usize, i32), usize>,
    permutation: PermutationArgument,
    lookups: Vec<LookupArgument<F>>,
    constants: Vec<Column<Fixed>>,
    minimum_degree: Option<usize>,
    annotations: BTreeMap<Column<Any>, String>,
    error: Option<CsError>,
}

impl<F: PastaField> ConstraintSystem<F> {
    /// An empty constraint system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_fixed_columns: 0,
            num_advice_columns: 0,
            instance_lengths: Vec::new(),
            selectors: Vec::new(),
            gates: Vec::new(),
            advice_queries: Vec::new(),
            num_advice_queries: Vec::new(),
            instance_queries: Vec::new(),
            fixed_queries: Vec::new(),
            advice_query_indices: BTreeMap::new(),
            instance_query_indices: BTreeMap::new(),
            fixed_query_indices: BTreeMap::new(),
            permutation: PermutationArgument::new(),
            lookups: Vec::new(),
            constants: Vec::new(),
            minimum_degree: None,
            annotations: BTreeMap::new(),
            error: None,
        }
    }

    /// Records the first configuration error.
    fn record_error(&mut self, error: CsError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// The first configuration error, if any.
    ///
    /// # Errors
    ///
    /// The recorded [`CsError`].
    pub fn check(&self) -> Result<(), CsError> {
        self.error.clone().map_or(Ok(()), Err)
    }

    /// Allocates a fixed column.
    pub fn fixed_column(&mut self) -> Column<Fixed> {
        let column = Column::new(self.num_fixed_columns, Fixed);
        self.num_fixed_columns += 1;
        column
    }

    /// Allocates an advice column.
    pub fn advice_column(&mut self) -> Column<Advice> {
        let column = Column::new(self.num_advice_columns, Advice);
        self.num_advice_columns += 1;
        self.num_advice_queries.push(0);
        column
    }

    /// Allocates an instance column holding exactly `length` public values.
    ///
    /// The length is part of the circuit descriptor; provers and verifiers
    /// reject any other length (spec S4).
    pub fn instance_column(&mut self, length: usize) -> Column<Instance> {
        let column = Column::new(self.instance_lengths.len(), Instance);
        self.instance_lengths.push(length);
        column
    }

    /// Allocates a fixed column for a lookup table.
    pub fn lookup_table_column(&mut self) -> TableColumn {
        TableColumn::new(self.fixed_column())
    }

    /// Allocates a simple selector.
    pub fn selector(&mut self) -> Selector {
        let selector = Selector::new(self.selectors.len(), true);
        self.selectors.push(selector);
        selector
    }

    /// Allocates a complex selector.
    pub fn complex_selector(&mut self) -> Selector {
        let selector = Selector::new(self.selectors.len(), false);
        self.selectors.push(selector);
        selector
    }

    /// Names a column for diagnostics.
    pub fn annotate_column<C: Into<Column<Any>>>(&mut self, column: C, name: impl Into<String>) {
        self.annotations.insert(column.into(), name.into());
    }

    /// Names a lookup table column for diagnostics.
    pub fn annotate_lookup_column(&mut self, column: TableColumn, name: impl Into<String>) {
        self.annotate_column(column.inner(), name);
    }

    /// Interns `(column, rotation)` among the fixed queries.
    pub(crate) fn query_fixed_index(&mut self, column: Column<Fixed>, at: Rotation) -> usize {
        let key = (column.index(), at.0);
        if let Some(index) = self.fixed_query_indices.get(&key) {
            return *index;
        }
        let index = self.fixed_queries.len();
        self.fixed_queries.push((column, at));
        self.fixed_query_indices.insert(key, index);
        index
    }

    /// Interns `(column, rotation)` among the advice queries.
    pub(crate) fn query_advice_index(&mut self, column: Column<Advice>, at: Rotation) -> usize {
        let key = (column.index(), at.0);
        if let Some(index) = self.advice_query_indices.get(&key) {
            return *index;
        }
        let index = self.advice_queries.len();
        self.advice_queries.push((column, at));
        self.advice_query_indices.insert(key, index);
        if let Some(count) = self.num_advice_queries.get_mut(column.index()) {
            *count += 1;
        }
        index
    }

    /// Interns `(column, rotation)` among the instance queries.
    pub(crate) fn query_instance_index(&mut self, column: Column<Instance>, at: Rotation) -> usize {
        let key = (column.index(), at.0);
        if let Some(index) = self.instance_query_indices.get(&key) {
            return *index;
        }
        let index = self.instance_queries.len();
        self.instance_queries.push((column, at));
        self.instance_query_indices.insert(key, index);
        index
    }

    /// Interns `(column, rotation)` among the queries of its kind.
    pub(crate) fn query_any_index(&mut self, column: Column<Any>, at: Rotation) -> usize {
        match column.column_type() {
            Any::Advice => self.query_advice_index(Column::new(column.index(), Advice), at),
            Any::Fixed => self.query_fixed_index(Column::new(column.index(), Fixed), at),
            Any::Instance => self.query_instance_index(Column::new(column.index(), Instance), at),
        }
    }

    /// Interns every query of `expression` in evaluation order and returns the
    /// cells and selectors it reads.
    fn intern_expression(
        &mut self,
        expression: &Expression<F>,
        cells: &mut Vec<VirtualCell>,
        selectors: &mut Vec<Selector>,
    ) {
        expression.for_each_query(&mut |query| {
            self.query_any_index(query.column, query.rotation);
            let cell = VirtualCell {
                column: query.column,
                rotation: query.rotation,
            };
            if !cells.contains(&cell) {
                cells.push(cell);
            }
        });
        expression.for_each_selector(&mut |selector| {
            if !selectors.contains(&selector) {
                selectors.push(selector);
            }
        });
    }

    /// The query index of `(column, rotation)` if it is interned.
    #[must_use]
    pub fn query_index(&self, column: Column<Any>, rotation: Rotation) -> Option<usize> {
        let key = (column.index(), rotation.0);
        match column.column_type() {
            Any::Advice => self.advice_query_indices.get(&key),
            Any::Fixed => self.fixed_query_indices.get(&key),
            Any::Instance => self.instance_query_indices.get(&key),
        }
        .copied()
    }

    /// Enables copy constraints on `column` (and interns `(column, 0)`).
    pub fn enable_equality<C: Into<Column<Any>>>(&mut self, column: C) {
        let column = column.into();
        self.query_any_index(column, Rotation::cur());
        self.permutation.add_column(column);
    }

    /// Makes `column` available for global constants; it is equality-enabled.
    pub fn enable_constant(&mut self, column: Column<Fixed>) {
        if !self.constants.contains(&column) {
            self.constants.push(column);
            self.enable_equality(column);
        }
    }

    /// Raises the circuit degree to at least `degree`.
    pub fn set_minimum_degree(&mut self, degree: usize) {
        self.minimum_degree = Some(degree);
    }

    /// Adds a gate whose polynomials `constraints` returns.
    ///
    /// A gate with no polynomial, or a polynomial breaking the simple-selector
    /// rules, records an error instead of being added.
    pub fn create_gate<C, I>(
        &mut self,
        name: impl AsRef<str>,
        constraints: impl FnOnce(&mut VirtualCells<'_, F>) -> I,
    ) where
        C: Into<Constraint<F>>,
        I: IntoIterator<Item = C>,
    {
        let name = name.as_ref().to_owned();
        let mut cells = VirtualCells::new(self);
        let constraints: Vec<Constraint<F>> = constraints(&mut cells)
            .into_iter()
            .map(Into::into)
            .collect();
        let VirtualCells {
            queried_selectors: mut selectors,
            queried_cells: mut queried,
            ..
        } = cells;
        let mut names = Vec::with_capacity(constraints.len());
        let mut polys = Vec::with_capacity(constraints.len());
        for constraint in constraints {
            let (constraint_name, poly) = constraint.into_parts();
            if let Err(misuse) = poly.simple_selector() {
                self.record_error(CsError::SimpleSelector {
                    context: format!("gate `{name}`"),
                    misuse,
                });
                return;
            }
            self.intern_expression(&poly, &mut queried, &mut selectors);
            names.push(constraint_name);
            polys.push(poly);
        }
        if polys.is_empty() {
            self.record_error(CsError::EmptyGate { gate: name });
            return;
        }
        self.gates
            .push(Gate::new(name, names, polys, selectors, queried));
    }

    /// Adds a lookup of input expressions into table columns.
    ///
    /// Each table column's rotation-0 query is interned before its input
    /// expression, as in halo2. Returns the lookup index.
    pub fn lookup(
        &mut self,
        name: impl AsRef<str>,
        table_map: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<(Expression<F>, TableColumn)>,
    ) -> usize {
        let name = name.as_ref().to_owned();
        let mut cells = VirtualCells::new(self);
        let pairs = table_map(&mut cells);
        let mut resolved = Vec::with_capacity(pairs.len());
        for (input, table) in pairs {
            if input.contains_simple_selector() {
                cells.meta.record_error(CsError::SimpleSelector {
                    context: format!("lookup `{name}`"),
                    misuse: SimpleSelectorMisuse::InLookup,
                });
            }
            let table = cells.query_fixed(table.inner(), Rotation::cur());
            cells.intern(&input);
            resolved.push((input, table));
        }
        self.push_lookup(name, resolved)
    }

    /// Adds a lookup of input expressions into table expressions.
    ///
    /// Each input expression's queries are interned before its table's.
    /// Returns the lookup index.
    pub fn lookup_any(
        &mut self,
        name: impl AsRef<str>,
        table_map: impl FnOnce(&mut VirtualCells<'_, F>) -> Vec<(Expression<F>, Expression<F>)>,
    ) -> usize {
        let name = name.as_ref().to_owned();
        let mut cells = VirtualCells::new(self);
        let pairs = table_map(&mut cells);
        for (input, table) in &pairs {
            if input.contains_simple_selector() || table.contains_simple_selector() {
                cells.meta.record_error(CsError::SimpleSelector {
                    context: format!("lookup `{name}`"),
                    misuse: SimpleSelectorMisuse::InLookup,
                });
            }
            cells.intern(input);
            cells.intern(table);
        }
        self.push_lookup(name, pairs)
    }

    /// Appends a lookup after its queries are interned.
    fn push_lookup(&mut self, name: String, pairs: Vec<(Expression<F>, Expression<F>)>) -> usize {
        if pairs.is_empty() {
            self.record_error(CsError::EmptyLookup {
                lookup: name.clone(),
            });
        }
        let index = self.lookups.len();
        self.lookups.push(LookupArgument::new(name, pairs));
        index
    }

    /// The circuit degree `max(3, lookup degrees, gate degrees, minimum)`.
    #[must_use]
    pub fn degree(&self) -> usize {
        let mut degree = PermutationArgument::REQUIRED_DEGREE;
        degree = degree.max(
            self.lookups
                .iter()
                .map(LookupArgument::required_degree)
                .max()
                .unwrap_or(1),
        );
        degree = degree.max(
            self.gates
                .iter()
                .flat_map(|gate| gate.polynomials().iter().map(Expression::degree))
                .max()
                .unwrap_or(0),
        );
        degree.max(self.minimum_degree.unwrap_or(1))
    }

    /// The blinding factors `b = max(3, max advice queries per column) + 2`
    /// (the inner maximum is 1 without advice columns).
    #[must_use]
    pub fn blinding_factors(&self) -> usize {
        let factors = self.num_advice_queries.iter().copied().max().unwrap_or(1);
        factors.max(3).saturating_add(2)
    }

    /// The minimum domain size `b + 3`.
    #[must_use]
    pub fn minimum_rows(&self) -> usize {
        self.blinding_factors().saturating_add(3)
    }

    /// The usable rows `u = 2^k - b - 1` at `k`.
    ///
    /// # Errors
    ///
    /// [`CsError::NotEnoughRows`] when `k` is outside `1..=28` or `2^k` is below
    /// the minimum rows; [`CsError::InstanceTooLong`] when an instance column
    /// does not fit the usable rows.
    pub fn usable_rows(&self, k: u32) -> Result<usize, CsError> {
        let minimum_rows = self.minimum_rows();
        let n = domain_size(k).ok_or(CsError::NotEnoughRows { k, minimum_rows })?;
        if n < minimum_rows {
            return Err(CsError::NotEnoughRows { k, minimum_rows });
        }
        let usable = n - (self.blinding_factors() + 1);
        for (column, length) in self.instance_lengths.iter().enumerate() {
            if *length > usable {
                return Err(CsError::InstanceTooLong {
                    column,
                    length: *length,
                    usable_rows: usable,
                });
            }
        }
        Ok(usable)
    }

    /// For each selector, the maximum degree of a gate polynomial whose
    /// simple selector it is (0 for complex and unused selectors).
    #[must_use]
    pub fn selector_degrees(&self) -> Vec<usize> {
        let mut degrees = vec![0; self.selectors.len()];
        for poly in self.gates.iter().flat_map(Gate::polynomials) {
            if let Ok(Some(selector)) = poly.simple_selector()
                && let Some(degree) = degrees.get_mut(selector.index())
            {
                *degree = (*degree).max(poly.degree());
            }
        }
        degrees
    }

    /// Number of fixed columns.
    #[must_use]
    pub const fn num_fixed_columns(&self) -> usize {
        self.num_fixed_columns
    }

    /// Number of advice columns.
    #[must_use]
    pub const fn num_advice_columns(&self) -> usize {
        self.num_advice_columns
    }

    /// Number of instance columns.
    #[must_use]
    pub fn num_instance_columns(&self) -> usize {
        self.instance_lengths.len()
    }

    /// The declared length of every instance column.
    #[must_use]
    pub fn instance_lengths(&self) -> &[usize] {
        &self.instance_lengths
    }

    /// Number of selectors.
    #[must_use]
    pub fn num_selectors(&self) -> usize {
        self.selectors.len()
    }

    /// The selectors in allocation order.
    #[must_use]
    pub fn selectors(&self) -> &[Selector] {
        &self.selectors
    }

    /// The gates.
    #[must_use]
    pub fn gates(&self) -> &[Gate<F>] {
        &self.gates
    }

    /// The advice queries in interning order.
    #[must_use]
    pub fn advice_queries(&self) -> &[(Column<Advice>, Rotation)] {
        &self.advice_queries
    }

    /// The number of distinct queries of each advice column.
    #[must_use]
    pub fn num_advice_queries(&self) -> &[usize] {
        &self.num_advice_queries
    }

    /// The instance queries in interning order.
    #[must_use]
    pub fn instance_queries(&self) -> &[(Column<Instance>, Rotation)] {
        &self.instance_queries
    }

    /// The fixed queries in interning order.
    #[must_use]
    pub fn fixed_queries(&self) -> &[(Column<Fixed>, Rotation)] {
        &self.fixed_queries
    }

    /// The permutation argument.
    #[must_use]
    pub const fn permutation(&self) -> &PermutationArgument {
        &self.permutation
    }

    /// The lookups.
    #[must_use]
    pub fn lookups(&self) -> &[LookupArgument<F>] {
        &self.lookups
    }

    /// The constants columns, in `enable_constant` order.
    #[must_use]
    pub fn constants(&self) -> &[Column<Fixed>] {
        &self.constants
    }

    /// The minimum degree, if set.
    #[must_use]
    pub const fn minimum_degree(&self) -> Option<usize> {
        self.minimum_degree
    }

    /// The diagnostic name of `column`, if annotated.
    #[must_use]
    pub fn annotation(&self, column: Column<Any>) -> Option<&str> {
        self.annotations.get(&column).map(String::as_str)
    }

    /// Replaces the selectors with fixed columns by halo2 selector
    /// compression (`compress_selectors = true`).
    ///
    /// `activations[s][row]` says whether selector `s` is enabled on `row`;
    /// every vector has `2^k` entries.
    ///
    /// # Errors
    ///
    /// The recorded configuration error, a wrong activation count or a
    /// compression error.
    pub fn compress_selectors(
        self,
        activations: &[Vec<bool>],
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        self.compress_selectors_cancellable(activations, None)
    }

    fn compress_selectors_cancellable(
        mut self,
        activations: &[Vec<bool>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        self.check()?;
        self.check_activation_count(activations)?;
        let degrees = self.selector_degrees();
        let max_degree = self.degree();
        let first_column = self.num_fixed_columns;
        let descriptions: Vec<SelectorDescription<'_>> = activations
            .iter()
            .zip(&degrees)
            .enumerate()
            .map(|(selector, (rows, max_degree))| SelectorDescription {
                selector,
                activations: rows,
                max_degree: *max_degree,
            })
            .collect();
        let mut new_columns = Vec::new();
        let (columns, assignments) = selector_compression::process_cancellable(
            &descriptions,
            max_degree,
            || {
                let column = self.fixed_column();
                new_columns.push(column);
                self.query_fixed_index(column, Rotation::cur());
                Expression::Fixed(FixedQuery {
                    column_index: column.index(),
                    rotation: Rotation::cur(),
                })
            },
            cancellation,
        )?;
        let mut replacements = vec![Expression::Constant(F::ZERO); self.selectors.len()];
        let mut entries = vec![
            SelectorPlanEntry {
                max_degree: 0,
                combination: 0,
                root: 0,
            };
            self.selectors.len()
        ];
        for assignment in assignments {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            let Some(slot) = entries.get_mut(assignment.selector) else {
                return Err(CsError::Overflow);
            };
            *slot = SelectorPlanEntry {
                max_degree: degrees[assignment.selector],
                combination: assignment.combination_index,
                root: assignment.root,
            };
            replacements[assignment.selector] = assignment.expression;
        }
        let selector_map = entries
            .iter()
            .map(|entry| {
                new_columns
                    .get(entry.combination)
                    .copied()
                    .ok_or(CsError::Overflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.replace_selectors(&replacements, cancellation)?;
        Ok(FinalizedConstraintSystem {
            cs: self,
            selector_columns: columns,
            plan: SelectorPlan {
                compress: true,
                first_column,
                entries,
                selector_map,
            },
        })
    }

    /// Replaces every selector with its own fixed column, in selector order,
    /// holding 1 on active rows (`compress_selectors = false`). As in halo2,
    /// the finalized constraint system then reports no selectors; the plan
    /// keeps one entry per original selector.
    ///
    /// # Errors
    ///
    /// The recorded configuration error or a wrong activation count.
    pub fn directly_convert_selectors_to_fixed(
        self,
        activations: &[Vec<bool>],
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        self.directly_convert_selectors_to_fixed_cancellable(activations, None)
    }

    fn directly_convert_selectors_to_fixed_cancellable(
        mut self,
        activations: &[Vec<bool>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        self.check()?;
        self.check_activation_count(activations)?;
        let degrees = self.selector_degrees();
        let first_column = self.num_fixed_columns;
        let mut columns = Vec::with_capacity(activations.len());
        let mut replacements = Vec::with_capacity(activations.len());
        let mut selector_map = Vec::with_capacity(activations.len());
        let mut entries = Vec::with_capacity(activations.len());
        for (selector, rows) in activations.iter().enumerate() {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            columns.push(
                rows.iter()
                    .enumerate()
                    .map(|(index, active)| {
                        if index % 1024 == 0 {
                            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                        }
                        Ok(if *active { F::ONE } else { F::ZERO })
                    })
                    .collect::<Result<Vec<_>, CsError>>()?,
            );
            let column = self.fixed_column();
            self.query_fixed_index(column, Rotation::cur());
            replacements.push(Expression::Fixed(FixedQuery {
                column_index: column.index(),
                rotation: Rotation::cur(),
            }));
            selector_map.push(column);
            entries.push(SelectorPlanEntry {
                max_degree: degrees[selector],
                combination: selector,
                root: 1,
            });
        }
        self.replace_selectors(&replacements, cancellation)?;
        self.selectors.clear();
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(FinalizedConstraintSystem {
            cs: self,
            selector_columns: columns,
            plan: SelectorPlan {
                compress: false,
                first_column,
                entries,
                selector_map,
            },
        })
    }

    /// Finalizes with or without selector compression.
    ///
    /// # Errors
    ///
    /// See [`Self::compress_selectors`].
    pub fn finalize(
        self,
        activations: &[Vec<bool>],
        compress: bool,
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        self.finalize_cancellable(activations, compress, None)
    }

    /// Finalize exact selector columns with bounded cancellation checkpoints.
    ///
    /// # Errors
    /// As [`Self::finalize`], or [`CsError::Cancelled`].
    pub fn finalize_cancellable(
        self,
        activations: &[Vec<bool>],
        compress: bool,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FinalizedConstraintSystem<F>, CsError> {
        if compress {
            self.compress_selectors_cancellable(activations, cancellation)
        } else {
            self.directly_convert_selectors_to_fixed_cancellable(activations, cancellation)
        }
    }

    /// Checks that one activation vector per selector was supplied.
    fn check_activation_count(&self, activations: &[Vec<bool>]) -> Result<(), CsError> {
        if activations.len() == self.selectors.len() {
            Ok(())
        } else {
            Err(CsError::SelectorCount {
                expected: self.selectors.len(),
                found: activations.len(),
            })
        }
    }

    /// Substitutes selectors in every gate and lookup expression.
    fn replace_selectors(
        &mut self,
        replacements: &[Expression<F>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), CsError> {
        for gate in &mut self.gates {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            let polys = gate
                .polynomials()
                .iter()
                .map(|poly| {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                    Ok(poly.replace_selectors(replacements)?)
                })
                .collect::<Result<Vec<_>, CsError>>()?;
            gate.set_polynomials(polys);
        }
        for lookup in &mut self.lookups {
            let (inputs, tables) = lookup.expressions_mut();
            for expression in inputs.iter_mut().chain(tables.iter_mut()) {
                iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                *expression = expression.replace_selectors(replacements)?;
            }
        }
        Ok(())
    }
}

/// `2^k` for `1 <= k <= 28`.
#[must_use]
pub fn domain_size(k: u32) -> Option<usize> {
    if (1..=MAX_K).contains(&k) {
        1_usize.checked_shl(k)
    } else {
        None
    }
}

/// One selector's place in the selector plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorPlanEntry {
    /// The selector's gate degree (0 for complex and unused selectors).
    pub max_degree: usize,
    /// The combination; its fixed column is `first_column + combination`.
    pub combination: usize,
    /// The 1-based root the selector's rows hold in the combination column
    /// (1 without compression).
    pub root: usize,
}

/// How selectors were turned into fixed columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorPlan {
    /// Whether selector compression ran.
    pub compress: bool,
    /// The first selector fixed column (the number of fixed columns
    /// `configure` allocated).
    pub first_column: usize,
    /// One entry per original selector.
    pub entries: Vec<SelectorPlanEntry>,
    /// The fixed column of each original selector.
    pub selector_map: Vec<Column<Fixed>>,
}

impl SelectorPlan {
    /// Number of selector fixed columns.
    #[must_use]
    pub fn num_columns(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.combination.saturating_add(1))
            .max()
            .unwrap_or(0)
    }
}

/// A constraint system whose selectors are fixed columns, ready for key
/// generation and the circuit descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedConstraintSystem<F> {
    cs: ConstraintSystem<F>,
    selector_columns: Vec<Vec<F>>,
    plan: SelectorPlan,
}

impl<F> FinalizedConstraintSystem<F> {
    /// The constraint system after substitution (no selector nodes remain).
    #[must_use]
    pub const fn constraint_system(&self) -> &ConstraintSystem<F> {
        &self.cs
    }

    /// The values of the selector fixed columns, in column order.
    #[must_use]
    pub fn selector_columns(&self) -> &[Vec<F>] {
        &self.selector_columns
    }

    /// The selector plan.
    #[must_use]
    pub const fn selector_plan(&self) -> &SelectorPlan {
        &self.plan
    }

    /// Splits into the constraint system, the selector columns and the plan.
    #[must_use]
    pub fn into_parts(self) -> (ConstraintSystem<F>, Vec<Vec<F>>, SelectorPlan) {
        (self.cs, self.selector_columns, self.plan)
    }
}

/// Query access while building a gate or lookup.
///
/// `query_*` interns the query immediately, as halo2's `VirtualCells` does.
#[derive(Debug)]
pub struct VirtualCells<'a, F> {
    meta: &'a mut ConstraintSystem<F>,
    queried_selectors: Vec<Selector>,
    queried_cells: Vec<VirtualCell>,
}

impl<'a, F: PastaField> VirtualCells<'a, F> {
    /// Starts collecting queries for one gate or lookup.
    fn new(meta: &'a mut ConstraintSystem<F>) -> Self {
        Self {
            meta,
            queried_selectors: Vec::new(),
            queried_cells: Vec::new(),
        }
    }

    /// Interns the queries of `expression` without recording cells.
    fn intern(&mut self, expression: &Expression<F>) {
        expression.for_each_query(&mut |query| {
            self.meta.query_any_index(query.column, query.rotation);
        });
    }

    /// Queries `selector` at the current row.
    pub fn query_selector(&mut self, selector: Selector) -> Expression<F> {
        self.queried_selectors.push(selector);
        Expression::Selector(selector)
    }

    /// Queries a fixed column.
    pub fn query_fixed(&mut self, column: Column<Fixed>, at: Rotation) -> Expression<F> {
        self.queried_cells.push((column, at).into());
        self.meta.query_fixed_index(column, at);
        column.query_cell(at)
    }

    /// Queries an advice column.
    pub fn query_advice(&mut self, column: Column<Advice>, at: Rotation) -> Expression<F> {
        self.queried_cells.push((column, at).into());
        self.meta.query_advice_index(column, at);
        column.query_cell(at)
    }

    /// Queries an instance column.
    pub fn query_instance(&mut self, column: Column<Instance>, at: Rotation) -> Expression<F> {
        self.queried_cells.push((column, at).into());
        self.meta.query_instance_index(column, at);
        column.query_cell(at)
    }

    /// Queries a column of any kind.
    pub fn query_any<C: Into<Column<Any>>>(&mut self, column: C, at: Rotation) -> Expression<F> {
        let column = column.into();
        match column.column_type() {
            Any::Advice => self.query_advice(Column::new(column.index(), Advice), at),
            Any::Fixed => self.query_fixed(Column::new(column.index(), Fixed), at),
            Any::Instance => self.query_instance(Column::new(column.index(), Instance), at),
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;

    use super::*;

    #[test]
    fn query_interning_follows_halo2_order() {
        let mut cs = ConstraintSystem::<Fp>::new();
        let a = cs.advice_column();
        let b = cs.advice_column();
        let f = cs.fixed_column();
        let i = cs.instance_column(2);
        // Immediate interning of b, then post-closure interning of a.next and f.
        cs.create_gate("g", |meta| {
            let b_cur = meta.query_advice(b, Rotation::cur());
            vec![b_cur * a.next::<Fp>() + f.cur::<Fp>()]
        });
        cs.enable_equality(a);
        cs.enable_equality(i);
        cs.create_gate("again", |meta| {
            let a_next = meta.query_advice(a, Rotation::next());
            vec![a_next]
        });
        assert_eq!(
            cs.advice_queries(),
            &[
                (b, Rotation::cur()),
                (a, Rotation::next()),
                (a, Rotation::cur())
            ]
        );
        assert_eq!(cs.num_advice_queries(), &[2, 1]);
        assert_eq!(cs.fixed_queries(), &[(f, Rotation::cur())]);
        assert_eq!(cs.instance_queries(), &[(i, Rotation::cur())]);
        assert_eq!(cs.query_index(a.into(), Rotation::cur()), Some(2));
        assert_eq!(cs.query_index(a.into(), Rotation::prev()), None);
        assert_eq!(cs.query_index(f.into(), Rotation::cur()), Some(0));
        assert_eq!(cs.query_index(i.into(), Rotation::cur()), Some(0));
        assert_eq!(cs.gates()[0].queried_cells().len(), 3);
        assert_eq!(cs.blinding_factors(), 5);
        assert_eq!(cs.minimum_rows(), 8);
    }

    #[test]
    fn lookup_interns_table_before_input_and_lookup_any_input_first() {
        let mut cs = ConstraintSystem::<Fp>::new();
        let f0 = cs.fixed_column();
        let table = cs.lookup_table_column();
        let a = cs.advice_column();
        cs.lookup("l", |_| vec![(f0.cur::<Fp>() * a.cur::<Fp>(), table)]);
        assert_eq!(
            cs.fixed_queries(),
            &[(table.inner(), Rotation::cur()), (f0, Rotation::cur())]
        );
        let mut any = ConstraintSystem::<Fp>::new();
        let f0 = any.fixed_column();
        let f1 = any.fixed_column();
        any.lookup_any("l", |_| vec![(f0.cur::<Fp>(), f1.cur::<Fp>())]);
        assert_eq!(
            any.fixed_queries(),
            &[(f0, Rotation::cur()), (f1, Rotation::cur())]
        );
        assert_eq!(any.lookups()[0].width(), 1);
    }

    #[test]
    fn misuse_is_recorded_not_panicking() {
        let mut cs = ConstraintSystem::<Fp>::new();
        let a = cs.advice_column();
        let s = cs.selector();
        cs.create_gate("bad", |meta| {
            vec![meta.query_selector(s) + meta.query_advice(a, Rotation::cur())]
        });
        assert!(cs.gates().is_empty());
        assert!(matches!(cs.check(), Err(CsError::SimpleSelector { .. })));

        let mut cs = ConstraintSystem::<Fp>::new();
        cs.create_gate("empty", |_| Vec::<Expression<Fp>>::new());
        assert_eq!(
            cs.check(),
            Err(CsError::EmptyGate {
                gate: "empty".to_owned()
            })
        );

        let mut cs = ConstraintSystem::<Fp>::new();
        let s = cs.selector();
        let table = cs.lookup_table_column();
        cs.lookup("sel", |meta| vec![(meta.query_selector(s), table)]);
        assert!(matches!(
            cs.check(),
            Err(CsError::SimpleSelector {
                misuse: SimpleSelectorMisuse::InLookup,
                ..
            })
        ));

        let mut cs = ConstraintSystem::<Fp>::new();
        cs.lookup_any("empty", |_| vec![]);
        assert!(matches!(cs.check(), Err(CsError::EmptyLookup { .. })));
        // The first error wins.
        cs.create_gate("empty", |_| Vec::<Expression<Fp>>::new());
        assert!(matches!(cs.check(), Err(CsError::EmptyLookup { .. })));
        assert!(cs.clone().compress_selectors(&[]).is_err());
        assert!(cs.directly_convert_selectors_to_fixed(&[]).is_err());
    }

    #[test]
    fn degree_and_rows() {
        let mut cs = ConstraintSystem::<Fp>::new();
        assert_eq!(cs.degree(), 3);
        assert_eq!(cs.blinding_factors(), 5);
        let a = cs.advice_column();
        let table = cs.lookup_table_column();
        cs.lookup("l", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            vec![(a.clone() * a, table)]
        });
        assert_eq!(cs.degree(), 5);
        cs.set_minimum_degree(7);
        assert_eq!(cs.degree(), 7);
        assert_eq!(cs.minimum_degree(), Some(7));
        cs.create_gate("deep", |meta| {
            let a0 = meta.query_advice(a, Rotation::cur());
            let a1 = meta.query_advice(a, Rotation::next());
            let a2 = meta.query_advice(a, Rotation(2));
            let a3 = meta.query_advice(a, Rotation(-1));
            vec![a0.clone() * a1 * a2 * a3 * a0.clone() * a0.clone() * a0.clone() * a0]
        });
        assert_eq!(cs.degree(), 8);
        assert_eq!(cs.blinding_factors(), 6);
        assert_eq!(cs.usable_rows(4), Ok(16 - 7));
        assert_eq!(
            cs.usable_rows(3),
            Err(CsError::NotEnoughRows {
                k: 3,
                minimum_rows: 9
            })
        );
        assert!(matches!(
            cs.usable_rows(0),
            Err(CsError::NotEnoughRows { k: 0, .. })
        ));
        assert!(cs.usable_rows(29).is_err());
        cs.instance_column(10);
        assert_eq!(
            cs.usable_rows(4),
            Err(CsError::InstanceTooLong {
                column: 0,
                length: 10,
                usable_rows: 9
            })
        );
        assert_eq!(domain_size(28), Some(1 << 28));
        assert_eq!(domain_size(0), None);
    }

    fn selector_circuit() -> (ConstraintSystem<Fp>, [Selector; 3]) {
        let mut cs = ConstraintSystem::<Fp>::new();
        let a = cs.advice_column();
        let f = cs.fixed_column();
        let s0 = cs.selector();
        let s1 = cs.selector();
        let c = cs.complex_selector();
        cs.create_gate("s0", |meta| {
            let s0 = meta.query_selector(s0);
            let a = meta.query_advice(a, Rotation::cur());
            vec![s0 * a.clone() * a]
        });
        cs.create_gate("s1", |meta| {
            let s1 = meta.query_selector(s1);
            let a = meta.query_advice(a, Rotation::cur());
            vec![s1 * (a - Expression::Constant(Fp::ONE))]
        });
        let table = cs.lookup_table_column();
        cs.lookup("c", |meta| {
            let c = meta.query_selector(c);
            let fixed = meta.query_fixed(f, Rotation::cur());
            vec![(c * fixed, table)]
        });
        (cs, [s0, s1, c])
    }

    #[test]
    fn compression_substitutes_and_records_the_plan() {
        let (cs, [s0, s1, c]) = selector_circuit();
        assert_eq!(cs.selector_degrees(), vec![3, 2, 0]);
        let n = 16;
        let activations: Vec<Vec<bool>> = (0..3)
            .map(|s| (0..n).map(|row| row % 3 == s && row < 9).collect())
            .collect();
        let first = cs.num_fixed_columns();
        let degree = cs.degree();
        let finalized = cs.compress_selectors(&activations).expect("compress");
        let plan = finalized.selector_plan();
        assert!(plan.compress);
        assert_eq!(plan.first_column, first);
        // Complex selector c first (combination 0), then s0 and s1 together.
        assert_eq!(plan.entries[c.index()].combination, 0);
        assert_eq!(plan.entries[s0.index()].combination, 1);
        assert_eq!(plan.entries[s1.index()].combination, 1);
        assert_eq!(plan.entries[s0.index()].root, 1);
        assert_eq!(plan.entries[s1.index()].root, 2);
        assert_eq!(plan.num_columns(), 2);
        assert_eq!(plan.selector_map[s1.index()], Column::new(first + 1, Fixed));
        let cs = finalized.constraint_system();
        assert_eq!(cs.degree(), degree, "compression keeps the degree");
        assert_eq!(cs.num_fixed_columns(), first + 2);
        for gate in cs.gates() {
            for poly in gate.polynomials() {
                let mut selectors = 0;
                poly.for_each_selector(&mut |_| selectors += 1);
                assert_eq!(selectors, 0);
            }
        }
        assert_eq!(finalized.selector_columns().len(), 2);
        assert_eq!(finalized.selector_columns()[1][1], Fp::from(2));
        let (cs, columns, plan) = finalized.into_parts();
        assert_eq!(columns.len(), plan.num_columns());
        assert!(cs.check().is_ok());
    }

    #[test]
    fn direct_conversion_gives_one_column_per_selector() {
        let (cs, _) = selector_circuit();
        let activations = vec![vec![true, false, false, false]; 3];
        let first = cs.num_fixed_columns();
        let finalized = cs.finalize(&activations, false).expect("direct");
        let plan = finalized.selector_plan();
        assert!(!plan.compress);
        for (s, entry) in plan.entries.iter().enumerate() {
            assert_eq!((entry.combination, entry.root), (s, 1));
            assert_eq!(plan.selector_map[s], Column::new(first + s, Fixed));
        }
        assert_eq!(finalized.selector_columns()[0][0], Fp::ONE);
        assert_eq!(finalized.selector_columns()[0][1], Fp::ZERO);
        let fixed = finalized.constraint_system().fixed_queries();
        assert_eq!(
            fixed[fixed.len() - 1],
            (Column::new(first + 2, Fixed), Rotation::cur())
        );
        assert_eq!(
            finalized.constraint_system().num_selectors(),
            0,
            "as in halo2"
        );
    }

    #[test]
    fn activation_count_is_checked() {
        let (cs, _) = selector_circuit();
        assert_eq!(
            cs.clone().compress_selectors(&[]),
            Err(CsError::SelectorCount {
                expected: 3,
                found: 0
            })
        );
        let short = vec![vec![false; 4], vec![false; 4], vec![false; 3]];
        assert!(matches!(
            cs.finalize(&short, true),
            Err(CsError::Compression(
                CompressionError::ActivationLength { .. }
            ))
        ));
    }

    #[test]
    fn constants_and_annotations() {
        let mut cs = ConstraintSystem::<Fp>::new();
        let f = cs.fixed_column();
        cs.enable_constant(f);
        cs.enable_constant(f);
        assert_eq!(cs.constants(), &[f]);
        assert_eq!(cs.permutation().columns(), &[Column::<Any>::from(f)]);
        cs.annotate_column(f, "constants");
        let table = cs.lookup_table_column();
        cs.annotate_lookup_column(table, "table");
        assert_eq!(cs.annotation(f.into()), Some("constants"));
        assert_eq!(cs.annotation(table.inner().into()), Some("table"));
        assert_eq!(cs.annotation(Column::new(0, Any::Advice)), None);
        assert_eq!(cs.num_selectors(), 0);
        assert!(cs.selectors().is_empty());
        assert_eq!(cs.num_instance_columns(), 0);
        assert!(cs.instance_lengths().is_empty());
        assert_eq!(cs.num_advice_columns(), 0);
    }

    #[test]
    fn errors_display() {
        let errors = [
            CsError::SimpleSelector {
                context: "gate".into(),
                misuse: SimpleSelectorMisuse::InSum,
            },
            CsError::EmptyGate { gate: "g".into() },
            CsError::EmptyLookup { lookup: "l".into() },
            CsError::SelectorCount {
                expected: 1,
                found: 0,
            },
            CsError::Compression(CompressionError::DegreeExceedsCircuit {
                selector: 0,
                degree: 9,
                max_degree: 3,
            }),
            CsError::SelectorReplacement(SelectorReplacementError {
                selector: Selector::new(0, true),
            }),
            CsError::NotEnoughRows {
                k: 2,
                minimum_rows: 8,
            },
            CsError::InstanceTooLong {
                column: 0,
                length: 9,
                usable_rows: 2,
            },
            CsError::Overflow,
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
