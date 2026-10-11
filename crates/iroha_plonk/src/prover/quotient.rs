//! The quotient polynomial on exact cosets, and the compiled evaluator.
//!
//! # The compiled evaluator
//!
//! [`CompiledExpressions`] compiles the postfix gate and lookup expressions
//! of the descriptor (the bytes that are hashed, spec section 4) into one
//! expression DAG: every node is hash-consed, so a subexpression shared by
//! several gates or lookups, or repeated inside one, is evaluated once per
//! row. Nodes are stored in topological order and evaluated into scratch for
//! four adjacent rows when the shared scratch budget admits the extra lanes;
//! otherwise the evaluator uses one row. A query reads its column at `(row + rotation)
//! mod n` of whatever domain the columns are given on: the base domain for
//! the lookup compression, a quotient coset for `h`.
//!
//! It is the third evaluator of the same constraints, independent of the
//! constraint checker (a naive interpreter of the uncompressed source
//! expressions) and of the verifier (an explicit-stack interpreter of the
//! descriptor expressions on evaluations); the tests compare them.
//!
//! # The quotient
//!
//! On each of the `d - 1` quotient cosets ([`crate::keys::QuotientDomain`])
//! the numerator is folded over the constraints in the spec section 2 order
//! with `y`:
//!
//! 1. every gate polynomial;
//! 2. the permutation: `l_0 (1 - z_0)`, `l_last (z_l^2 - z_l)`, the set links
//!    `l_0 (z_s - z_{s-1}(omega^{-(b+1)} X))` and, per set,
//!    `l_active (z_s(omega X) prod (v + beta sigma + gamma) - z_s prod (v +
//!    beta DELTA^j X + gamma))`;
//! 3. per lookup the five halo2 constraints.
//!
//! The numerator is multiplied by `(s_c^n - 1)^-1`, the constant value of
//! `1 / (X^n - 1)` on coset `c`, and the `d - 1` coset vectors are recombined
//! into the `(d - 1) n` coefficients of `h` with a small Vandermonde solve.
//! For a satisfying witness this is the vendored `h` exactly.
//!
//! The shared expression DAG is evaluated once per row, retaining one
//! `(A + beta)(S + gamma)` numerator column per lookup. A single triple of
//! committed lookup cosets is then reused in lookup order, appending the five
//! constraints to each row's Horner accumulator without changing its powers
//! of `y`. Only `L` numerator columns remain live between the stages;
//! the lookup triple reuses dead gate-stage cosets. With `B` owned gate-stage
//! cosets, their combined allocation is `max(B, 3) + L` for `L > 0`,
//! plus the shared powers column. Cached key cosets are never overwritten.
//!
//! Rows are independent, so the rows of a coset are split across the
//! caller's Rayon pool; every row's arithmetic is the same at any pool size.

use crate::secret::{SecretColumns, SecretPolynomial};
use iroha_pasta::CancellationToken;
use std::{borrow::Cow, collections::BTreeMap};

use ff::Field;
#[cfg(test)]
use iroha_pasta::fft::FftDomain;
use iroha_pasta::{PastaCurve, PastaField, fft::CosetFftPlan};
use rayon::prelude::*;

use super::{Challenges, ProverError};
use crate::{
    cs::{
        DescriptorError, DescriptorRule, ProtocolDescriptor,
        descriptor::{ColumnKindV1, ExprNodeV1, ExprV1, MAX_EXPRESSION_STACK, QueryV1},
    },
    keys::{CosetPolynomial, KeyError, ProvingKey},
    protocol::{ConstraintFilter, ConstraintTerm, LookupConstraint, Protocol, ProtocolError},
    transcript::decode_scalar,
};

/// Rows per parallel task; results do not depend on it.
const ROWS_PER_TASK: usize = 1 << 8;

mod evaluation;
use evaluation::{EvaluatedRow, TilePlan};

mod gate_fold;
use gate_fold::GateFold;

mod workspace;
pub use workspace::{QuotientWorkspace, WorkspaceError};

/// One node of the compiled DAG; operands index earlier nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Node<F> {
    Constant(F),
    Fixed(u32),
    Advice(u32),
    Instance(u32),
    Negated(u32),
    Doubled(u32),
    Squared(u32),
    Sum(u32, u32),
    Product(u32, u32),
    Scaled(u32, F),
}

/// The roots of one lookup's input and table expressions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CompiledLookup {
    inputs: Vec<u32>,
    tables: Vec<u32>,
}

/// The gate and lookup expressions of a descriptor compiled into one
/// hash-consed DAG (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledExpressions<F> {
    nodes: Vec<Node<F>>,
    gates: Vec<u32>,
    lookups: Vec<CompiledLookup>,
    fixed_queries: Vec<QueryV1>,
    advice_queries: Vec<QueryV1>,
    instance_queries: Vec<QueryV1>,
}

/// Hash-consing state of a compilation.
struct Builder<'a, F> {
    nodes: Vec<Node<F>>,
    index: BTreeMap<Node<F>, u32>,
    descriptor: &'a ProtocolDescriptor,
}

/// The descriptor rule-6 error.
fn malformed() -> DescriptorError {
    DescriptorError::Invalid(DescriptorRule::Expression)
}

impl<F: PastaField> Builder<'_, F> {
    /// The index of `node`, adding it if new.
    fn intern(&mut self, node: Node<F>) -> Result<u32, DescriptorError> {
        // Normalize only exact field identities. The descriptor, gate order,
        // challenge order and resulting polynomial remain unchanged. These
        // choices depend exclusively on public circuit structure.
        let node = match node {
            Node::Negated(operand) => match self.nodes[operand as usize] {
                Node::Constant(value) => Node::Constant(-value),
                Node::Negated(inner) => return Ok(inner),
                _ => Node::Negated(operand),
            },
            Node::Scaled(operand, factor) => {
                if bool::from(factor.is_zero()) {
                    Node::Constant(F::ZERO)
                } else if factor == F::ONE {
                    return Ok(operand);
                } else if factor == -F::ONE {
                    return self.intern(Node::Negated(operand));
                } else if let Node::Constant(value) = self.nodes[operand as usize] {
                    Node::Constant(value * factor)
                } else if factor == F::from(2) {
                    Node::Doubled(operand)
                } else {
                    Node::Scaled(operand, factor)
                }
            }
            Node::Sum(left, right) => match (self.nodes[left as usize], self.nodes[right as usize])
            {
                (Node::Constant(a), Node::Constant(b)) => Node::Constant(a + b),
                (Node::Constant(value), _) if bool::from(value.is_zero()) => return Ok(right),
                (_, Node::Constant(value)) if bool::from(value.is_zero()) => return Ok(left),
                _ if left == right => Node::Doubled(left),
                _ => Node::Sum(left.min(right), left.max(right)),
            },
            Node::Product(left, right) => {
                match (self.nodes[left as usize], self.nodes[right as usize]) {
                    (Node::Constant(a), Node::Constant(b)) => Node::Constant(a * b),
                    (Node::Constant(factor), _) => return self.intern(Node::Scaled(right, factor)),
                    (_, Node::Constant(factor)) => return self.intern(Node::Scaled(left, factor)),
                    _ if left == right => Node::Squared(left),
                    _ => Node::Product(left.min(right), left.max(right)),
                }
            }
            other => other,
        };
        if let Some(index) = self.index.get(&node) {
            return Ok(*index);
        }
        let index = u32::try_from(self.nodes.len()).map_err(|_| malformed())?;
        self.nodes.push(node);
        self.index.insert(node, index);
        Ok(index)
    }

    /// A query leaf after checking its index.
    fn query(&mut self, index: u32, table: usize, node: Node<F>) -> Result<u32, DescriptorError> {
        if usize::try_from(index).map_or(true, |index| index >= table) {
            return Err(malformed());
        }
        self.intern(node)
    }

    /// Compiles one postfix expression and returns its root.
    fn expression(&mut self, expression: &ExprV1) -> Result<u32, DescriptorError> {
        let mut stack: Vec<u32> = Vec::new();
        for node in expression {
            let index = match *node {
                ExprNodeV1::Constant(bytes) => {
                    let value = decode_scalar::<F>(&bytes).map_err(|_| malformed())?;
                    self.intern(Node::Constant(value))?
                }
                ExprNodeV1::Fixed(index) => {
                    let table = self.descriptor.fixed_queries.len();
                    self.query(index, table, Node::Fixed(index))?
                }
                ExprNodeV1::Advice(index) => {
                    let table = self.descriptor.advice_queries.len();
                    self.query(index, table, Node::Advice(index))?
                }
                ExprNodeV1::Instance(index) => {
                    let table = self.descriptor.instance_queries.len();
                    self.query(index, table, Node::Instance(index))?
                }
                ExprNodeV1::Negated => {
                    let operand = stack.pop().ok_or_else(malformed)?;
                    self.intern(Node::Negated(operand))?
                }
                ExprNodeV1::Scaled(bytes) => {
                    let factor = decode_scalar::<F>(&bytes).map_err(|_| malformed())?;
                    let operand = stack.pop().ok_or_else(malformed)?;
                    self.intern(Node::Scaled(operand, factor))?
                }
                ExprNodeV1::Sum | ExprNodeV1::Product => {
                    let right = stack.pop().ok_or_else(malformed)?;
                    let left = stack.pop().ok_or_else(malformed)?;
                    self.intern(if matches!(node, ExprNodeV1::Sum) {
                        Node::Sum(left, right)
                    } else {
                        Node::Product(left, right)
                    })?
                }
            };
            stack.push(index);
            if stack.len() > MAX_EXPRESSION_STACK {
                return Err(malformed());
            }
        }
        match stack.as_slice() {
            [root] => Ok(*root),
            _ => Err(malformed()),
        }
    }
}

/// One lookup's compressed input `A` and table `S` on every row.
pub type CompressedLookup<F> = (Vec<F>, Vec<F>);

/// Borrows every column as a slice.
fn slices<F>(columns: &[Vec<F>]) -> Vec<&[F]> {
    columns.iter().map(Vec::as_slice).collect()
}

/// `rotation mod n` as a row offset.
fn rotation_offset(rotation: i32, n: usize) -> Result<usize, ProtocolError> {
    let n = i64::try_from(n).map_err(|_| ProtocolError::Overflow)?;
    usize::try_from(i64::from(rotation).rem_euclid(n)).map_err(|_| ProtocolError::Overflow)
}

/// Columns bound to the query tables: per query, its column slice and its
/// rotation offset.
struct BoundColumns<'a, F> {
    fixed: Vec<(&'a [F], usize)>,
    advice: Vec<(&'a [F], usize)>,
    instance: Vec<(&'a [F], usize)>,
    mask: usize,
}

/// Binds one query table to its columns, checking every length.
fn bind_table<'a, F>(
    queries: &[QueryV1],
    columns: &[&'a [F]],
    n: usize,
) -> Result<Vec<(&'a [F], usize)>, ProverError> {
    queries
        .iter()
        .map(|query| {
            let column = usize::try_from(query.column)
                .ok()
                .and_then(|column| columns.get(column))
                .filter(|column| column.len() == n)
                .ok_or(ProverError::Key(KeyError::CosetIndex))?;
            Ok((*column, rotation_offset(query.rotation, n)?))
        })
        .collect()
}

impl<F: PastaField> CompiledExpressions<F> {
    /// Compiles the lookup expressions of `descriptor`, and its gate
    /// polynomials when `include_gates` is set.
    ///
    /// # Errors
    ///
    /// Rule 6 ([`DescriptorRule::Expression`]) for a malformed expression;
    /// validated descriptors always compile.
    pub fn compile(
        descriptor: &ProtocolDescriptor,
        include_gates: bool,
    ) -> Result<Self, DescriptorError> {
        let mut builder = Builder {
            nodes: Vec::new(),
            index: BTreeMap::new(),
            descriptor,
        };
        let mut gates = Vec::new();
        if include_gates {
            for poly in descriptor.gates.iter().flatten() {
                gates.push(builder.expression(poly)?);
            }
        }
        let lookups = descriptor
            .lookups
            .iter()
            .map(|lookup| {
                Ok(CompiledLookup {
                    inputs: lookup
                        .inputs
                        .iter()
                        .map(|input| builder.expression(input))
                        .collect::<Result<_, DescriptorError>>()?,
                    tables: lookup
                        .tables
                        .iter()
                        .map(|table| builder.expression(table))
                        .collect::<Result<_, DescriptorError>>()?,
                })
            })
            .collect::<Result<Vec<_>, DescriptorError>>()?;
        Ok(Self {
            nodes: builder.nodes,
            gates,
            lookups,
            fixed_queries: descriptor.fixed_queries.clone(),
            advice_queries: descriptor.advice_queries.clone(),
            instance_queries: descriptor.instance_queries.clone(),
        })
    }

    /// The number of distinct DAG nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The number of compiled gate polynomials.
    #[must_use]
    pub fn gate_count(&self) -> usize {
        self.gates.len()
    }

    /// Binds every query to its column (all `n` rows long).
    fn bind<'a>(
        &self,
        fixed: &[&'a [F]],
        advice: &[&'a [F]],
        instance: &[&'a [F]],
        n: usize,
    ) -> Result<BoundColumns<'a, F>, ProverError> {
        if !n.is_power_of_two() {
            return Err(ProverError::Protocol(ProtocolError::Overflow));
        }
        Ok(BoundColumns {
            fixed: bind_table(&self.fixed_queries, fixed, n)?,
            advice: bind_table(&self.advice_queries, advice, n)?,
            instance: bind_table(&self.instance_queries, instance, n)?,
            mask: n - 1,
        })
    }

    /// Evaluates every node at `row` into `scratch` (`node_count` long).
    fn evaluate_row(&self, columns: &BoundColumns<'_, F>, row: usize, scratch: &mut [F]) {
        let read = |(values, offset): (&[F], usize)| values[(row + offset) & columns.mask];
        for (index, node) in self.nodes.iter().enumerate() {
            scratch[index] = match *node {
                Node::Constant(value) => value,
                Node::Fixed(query) => read(columns.fixed[query as usize]),
                Node::Advice(query) => read(columns.advice[query as usize]),
                Node::Instance(query) => read(columns.instance[query as usize]),
                Node::Negated(operand) => -scratch[operand as usize],
                Node::Doubled(operand) => scratch[operand as usize].double(),
                Node::Squared(operand) => scratch[operand as usize].square(),
                Node::Sum(left, right) => scratch[left as usize] + scratch[right as usize],
                Node::Product(left, right) => scratch[left as usize] * scratch[right as usize],
                Node::Scaled(operand, factor) => scratch[operand as usize] * factor,
            };
        }
    }

    /// `fold(acc * theta + value)` over `roots`.
    fn compress(roots: &[u32], scratch: EvaluatedRow<'_, F>, theta: F) -> F {
        let Some((first, rest)) = roots.split_first() else {
            return F::ZERO;
        };
        // The initial zero term contributes nothing; width-one lookups are reads.
        rest.iter().fold(scratch[*first as usize], |acc, root| {
            acc * theta + scratch[*root as usize]
        })
    }

    /// Evaluates `width` outputs per row on the base domain into `width`
    /// column vectors of `n` rows (no row-major staging buffer).
    fn evaluate_columns(
        &self,
        columns: &BoundColumns<'_, F>,
        n: usize,
        width: usize,
        emit: impl Fn(EvaluatedRow<'_, F>, &mut [F]) + Sync,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<Vec<F>> {
        let mut outputs = vec![vec![F::ZERO; n]; width];
        let mut tasks: Vec<Vec<&mut [F]>> = (0..n.div_ceil(ROWS_PER_TASK))
            .map(|_| Vec::with_capacity(width))
            .collect();
        for output in &mut outputs {
            for (task, chunk) in tasks.iter_mut().zip(output.chunks_mut(ROWS_PER_TASK)) {
                task.push(chunk);
            }
        }
        let plan = TilePlan::new::<F>(self.nodes.len(), n);
        tasks
            .into_par_iter()
            .enumerate()
            .for_each(|(task, mut chunks)| {
                if CancellationToken::checkpoint(cancellation).is_err() {
                    return;
                }
                let start = task * ROWS_PER_TASK;
                let rows = chunks.first().map_or(0, |chunk| chunk.len());
                let mut scratch =
                    SecretPolynomial::new(vec![F::ZERO; self.nodes.len() * plan.width]);
                let mut row_out = SecretPolynomial::new(vec![F::ZERO; width]);
                for offset in (0..rows).step_by(plan.width) {
                    self.evaluate_tile(columns, start + offset, plan.width, &mut scratch);
                    for lane in 0..plan.width {
                        emit(EvaluatedRow::new(&scratch, plan.width, lane), &mut row_out);
                        for (chunk, value) in chunks.iter_mut().zip(row_out.iter()) {
                            chunk[offset + lane] = *value;
                        }
                    }
                }
            });
        drop(plan);
        outputs
    }

    /// The compressed input `A` and table `S` of every lookup on every row of
    /// the base domain (`theta`-folded, rotations wrapping modulo `n`).
    ///
    /// # Errors
    ///
    /// [`ProverError::Key`] when a column is missing or not `n` rows long.
    pub fn compress_lookups(
        &self,
        fixed: &[Vec<F>],
        advice: &[Vec<F>],
        instance: &[Vec<F>],
        theta: F,
        n: usize,
    ) -> Result<Vec<CompressedLookup<F>>, ProverError> {
        self.compress_lookups_cancellable(fixed, advice, instance, theta, n, None)
    }

    /// Compresses lookup inputs with cooperative cancellation.
    ///
    /// # Errors
    /// As [`Self::compress_lookups`], or [`ProverError::Cancelled`].
    pub fn compress_lookups_cancellable(
        &self,
        fixed: &[Vec<F>],
        advice: &[Vec<F>],
        instance: &[Vec<F>],
        theta: F,
        n: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Vec<CompressedLookup<F>>, ProverError> {
        CancellationToken::checkpoint(cancellation)?;
        let (fixed, advice, instance) = (slices(fixed), slices(advice), slices(instance));
        let columns = self.bind(&fixed, &advice, &instance, n)?;
        let width = self.lookups.len() * 2;
        let outputs = self.evaluate_columns(
            &columns,
            n,
            width,
            |scratch, row_out| {
                for (lookup, pair) in self.lookups.iter().zip(row_out.chunks_mut(2)) {
                    pair[0] = Self::compress(&lookup.inputs, scratch, theta);
                    pair[1] = Self::compress(&lookup.tables, scratch, theta);
                }
            },
            cancellation,
        );
        if let Err(error) = CancellationToken::checkpoint(cancellation) {
            let mut outputs = outputs;
            outputs
                .iter_mut()
                .flatten()
                .for_each(crate::secret::wipe_one);
            return Err(error.into());
        }
        let mut outputs = outputs.into_iter();
        let mut compressed = Vec::with_capacity(self.lookups.len());
        while let (Some(input), Some(table)) = (outputs.next(), outputs.next()) {
            compressed.push((input, table));
        }
        Ok(compressed)
    }

    /// The value of every compiled gate polynomial on every row of the base
    /// domain (rotations wrapping modulo `n`), one vector per polynomial in
    /// descriptor order. Differential tests compare it with the constraint
    /// checker and with direct evaluation of the finalized constraint system.
    ///
    /// # Errors
    ///
    /// [`ProverError::Key`] when a column is missing or not `n` rows long.
    pub fn gate_values(
        &self,
        fixed: &[Vec<F>],
        advice: &[Vec<F>],
        instance: &[Vec<F>],
        n: usize,
    ) -> Result<Vec<Vec<F>>, ProverError> {
        let (fixed, advice, instance) = (slices(fixed), slices(advice), slices(instance));
        let columns = self.bind(&fixed, &advice, &instance, n)?;
        Ok(self.evaluate_columns(
            &columns,
            n,
            self.gates.len(),
            |scratch, row_out| {
                for (root, value) in self.gates.iter().zip(row_out.iter_mut()) {
                    *value = scratch[*root as usize];
                }
            },
            None,
        ))
    }
}

/// One lookup's committed polynomials in coefficient form.
pub(super) struct LookupPolys<'a, F> {
    /// The product `z`.
    pub(super) product: &'a [F],
    /// The permuted input `A'`.
    pub(super) input: &'a [F],
    /// The permuted table `S'`.
    pub(super) table: &'a [F],
}

/// The witness polynomials the quotient reads, in coefficient form.
pub(super) struct QuotientInputs<'a, F> {
    /// The advice columns.
    pub(super) advice: &'a [Vec<F>],
    /// The instance columns.
    pub(super) instance: &'a [Vec<F>],
    /// The permutation products `z_s`.
    pub(super) permutation_products: Vec<&'a [F]>,
    /// The lookups.
    pub(super) lookups: Vec<LookupPolys<'a, F>>,
}

/// Key evaluations either borrow the eager cache or reuse caller storage.
enum KeyCoset<'a, F> {
    Cached(&'a [F]),
    Workspace(&'a mut [F]),
}

impl<F> AsRef<[F]> for KeyCoset<'_, F> {
    fn as_ref(&self) -> &[F] {
        match self {
            Self::Cached(values) => values,
            Self::Workspace(values) => values,
        }
    }
}

fn next_column<'a, F>(
    columns: &mut impl Iterator<Item = &'a mut [F]>,
) -> Result<&'a mut [F], KeyError> {
    columns.next().ok_or(KeyError::CosetIndex)
}

fn initial_key_cosets<'a, C: PastaCurve>(
    pk: &'a ProvingKey<C>,
    coefficients: &[Vec<C::ScalarExt>],
    polynomial: impl Fn(usize) -> CosetPolynomial,
    columns: &mut impl Iterator<Item = &'a mut [C::ScalarExt]>,
) -> Result<Vec<KeyCoset<'a, C::ScalarExt>>, KeyError> {
    let values = coefficients
        .iter()
        .enumerate()
        .map(|(index, _)| {
            if pk.has_coset_cache() {
                match pk.coset_values(polynomial(index), 0)? {
                    Cow::Borrowed(values) => Ok(KeyCoset::Cached(values)),
                    Cow::Owned(_) => Err(KeyError::CosetIndex),
                }
            } else {
                Ok(KeyCoset::Workspace(next_column(columns)?))
            }
        })
        .collect::<Result<Vec<_>, KeyError>>()?;
    Ok(values)
}

/// Exact field-buffer count, excluding eagerly cached key polynomials.
pub(super) fn workspace_elements<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
) -> Result<usize, ProtocolError> {
    let shape = protocol.shape();
    let key_columns = if pk.has_coset_cache() {
        0
    } else {
        shape
            .num_fixed
            .checked_add(shape.permutation_columns)
            .ok_or(ProtocolError::Overflow)?
    };
    // Gate-stage cosets are dead before the lookup stage, so the streamed
    // product/input/table triple reuses their first three owned columns. Only
    // a shortfall is allocated when fewer than three such columns exist.
    // Numerators and the FFT powers remain separate throughout both stages.
    // Eager fixed-only keys without lookups retain no workspace storage.
    let transformed = key_columns
        .checked_add(shape.num_advice)
        .and_then(|v| v.checked_add(shape.num_instance))
        .and_then(|v| v.checked_add(shape.permutation_sets))
        .ok_or(ProtocolError::Overflow)?;
    let transformed = transformed.max(if shape.lookups == 0 { 0 } else { 3 });
    transformed
        .checked_add(shape.lookups)
        .and_then(|v| v.checked_add(usize::from(transformed != 0)))
        .and_then(|v| v.checked_mul(shape.n))
        .ok_or(ProtocolError::Overflow)
}

/// Reuses a coset buffer for the next evaluation of the same polynomial.
#[cfg(test)]
fn evaluate_into<F: PastaField>(
    domain: &FftDomain<F>,
    coefficients: &[F],
    shift: F,
    values: &mut [F],
) -> Result<(), KeyError> {
    if values.len() != coefficients.len() {
        return Err(KeyError::Shape {
            what: "coset coefficients",
            expected: values.len(),
            actual: coefficients.len(),
        });
    }
    values.copy_from_slice(coefficients);
    domain.coset_fft(values, shift)?;
    Ok(())
}

/// Transforms immutable coefficient batches directly into disjoint columns.
/// Only slice metadata is allocated; field storage belongs to the workspace.
fn evaluate_many<F: PastaField>(
    plan: Option<&CosetFftPlan<'_, '_, F>>,
    coefficients: &[impl AsRef<[F]> + Sync],
    values: &mut [&mut [F]],
    cancellation: Option<&CancellationToken>,
) -> Result<(), KeyError> {
    CancellationToken::checkpoint(cancellation)?;
    if coefficients.len() != values.len() {
        return Err(KeyError::Shape {
            what: "coset columns",
            expected: values.len(),
            actual: coefficients.len(),
        });
    }
    for (values, coefficients) in values.iter().zip(coefficients) {
        if coefficients.as_ref().len() != values.len() {
            return Err(KeyError::Shape {
                what: "coset coefficients",
                expected: values.len(),
                actual: coefficients.as_ref().len(),
            });
        }
    }
    if values.is_empty() {
        return Ok(());
    }
    // An owned transform is never admitted without its accounted plan.
    let plan = plan.ok_or(KeyError::CosetIndex)?;
    plan.fft_many_from_cancellable(coefficients, values, cancellation)?;
    Ok(())
}

/// Updates owned key-polynomial buffers in place, or changes the borrowed
/// slice when the key already caches every coset.
fn refresh_key_cosets<'a, C: PastaCurve>(
    pk: &'a ProvingKey<C>,
    coefficients: &[Vec<C::ScalarExt>],
    values: &mut [KeyCoset<'a, C::ScalarExt>],
    polynomial: impl Fn(usize) -> CosetPolynomial,
    coset: usize,
    plan: Option<&CosetFftPlan<'_, '_, C::ScalarExt>>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), KeyError> {
    CancellationToken::checkpoint(cancellation)?;
    if coset >= pk.quotient_domain().pieces() {
        return Err(KeyError::CosetIndex);
    }
    let mut owned = Vec::with_capacity(values.len());
    let mut owned_coefficients = Vec::with_capacity(values.len());
    for (index, (values, coefficients)) in values.iter_mut().zip(coefficients).enumerate() {
        match values {
            KeyCoset::Workspace(values) => {
                owned.push(&mut **values);
                owned_coefficients.push(coefficients.as_slice());
            }
            KeyCoset::Cached(values) => {
                *values = match pk.coset_values(polynomial(index), coset)? {
                    Cow::Borrowed(values) => values,
                    Cow::Owned(_) => return Err(KeyError::CosetIndex),
                };
            }
        }
    }
    evaluate_many(plan, &owned_coefficients, &mut owned, cancellation)?;
    Ok(())
}

/// Computes the `(d - 1) n` coefficients of `h` (see the module
/// documentation). `filter` is [`AllTerms`](crate::protocol::AllTerms) for
/// every real proof (inlined away); the malicious-prover tests omit the
/// terms a forged witness violates, so that the forged `h` is a polynomial.
///
/// # Errors
///
/// [`ProverError::Key`] for a missing polynomial or coset,
/// [`ProverError::Fft`] on a transform failure.
#[cfg(test)]
pub(super) fn evaluate<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    compiled: &CompiledExpressions<C::ScalarExt>,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
) -> Result<Vec<C::ScalarExt>, ProverError> {
    evaluate_cancellable(pk, protocol, compiled, inputs, challenges, filter, None)
}

pub(super) fn evaluate_cancellable<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    compiled: &CompiledExpressions<C::ScalarExt>,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<C::ScalarExt>, ProverError> {
    CancellationToken::checkpoint(cancellation)?;
    let bytes = workspace_elements(pk, protocol)?
        .checked_mul(size_of::<C::ScalarExt>())
        .ok_or(ProtocolError::Overflow)?;
    let mut workspace = QuotientWorkspace::new(bytes);
    evaluate_with_workspace_cancellable(
        pk,
        protocol,
        compiled,
        inputs,
        challenges,
        filter,
        &mut workspace,
        cancellation,
    )
}

/// The same quotient evaluator using an exclusively borrowed reusable buffer.
#[cfg(test)]
pub(super) fn evaluate_with_workspace<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    compiled: &CompiledExpressions<C::ScalarExt>,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
    workspace: &mut QuotientWorkspace<C::ScalarExt>,
) -> Result<Vec<C::ScalarExt>, ProverError> {
    evaluate_with_workspace_cancellable(
        pk, protocol, compiled, inputs, challenges, filter, workspace, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_with_workspace_cancellable<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    compiled: &CompiledExpressions<C::ScalarExt>,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
    workspace: &mut QuotientWorkspace<C::ScalarExt>,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<C::ScalarExt>, ProverError> {
    CancellationToken::checkpoint(cancellation)?;
    let shape = protocol.shape();
    let n = shape.n;
    let domain = pk.domain();
    let quotient = pk.quotient_domain();
    let omega = domain.omega();
    let mask = n - 1;
    let last_offset = rotation_offset(shape.last_rotation()?, n)?;
    let Challenges {
        theta,
        beta,
        gamma,
        y,
    } = challenges;
    let gate_fold = GateFold::new(y);
    let one = C::ScalarExt::ONE;
    let delta = <C::ScalarExt as ff::PrimeField>::DELTA;
    let mut cosets = SecretColumns::new(Vec::with_capacity(shape.quotient_pieces));
    let elements = workspace_elements(pk, protocol)?;
    let count = elements / n;
    let lease = workspace.lease(n, count).map_err(ProverError::Workspace)?;
    let mut columns = lease.columns.iter_mut().take(count).map(AsMut::as_mut);
    let mut powers = if count == 0 {
        None
    } else {
        Some(next_column(&mut columns)?)
    };
    let mut fixed = initial_key_cosets(pk, pk.fixed_polys(), CosetPolynomial::Fixed, &mut columns)?;
    let mut sigma = initial_key_cosets(
        pk,
        pk.permutation_polys(),
        CosetPolynomial::Permutation,
        &mut columns,
    )?;
    let mut advice = (0..shape.num_advice)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    let mut instance = (0..shape.num_instance)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    let mut products = (0..shape.permutation_sets)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    let mut lookup_numerators = (0..shape.lookups)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    // The remaining columns are exactly the shortfall after reusing owned
    // gate-stage cosets. Most circuits need none; tiny eager keys may need all
    // three. Every buffer still belongs to the same zeroizing workspace lease.
    let mut lookup_spill: Vec<_> = columns.collect();
    if inputs.lookups.len() != shape.lookups {
        return Err(KeyError::Shape {
            what: "quotient lookups",
            expected: shape.lookups,
            actual: inputs.lookups.len(),
        }
        .into());
    }
    for coset in 0..shape.quotient_pieces {
        CancellationToken::checkpoint(cancellation)?;
        let shift = quotient.shift(coset).ok_or(KeyError::CosetIndex)?;
        let plan = powers
            .as_deref_mut()
            .map(|powers| domain.coset_plan_cancellable(powers, shift, cancellation))
            .transpose()?;
        {
            // Refresh coset zero too: allocation above performs no owned FFT.
            refresh_key_cosets(
                pk,
                pk.fixed_polys(),
                &mut fixed,
                CosetPolynomial::Fixed,
                coset,
                plan.as_ref(),
                cancellation,
            )?;
            refresh_key_cosets(
                pk,
                pk.permutation_polys(),
                &mut sigma,
                CosetPolynomial::Permutation,
                coset,
                plan.as_ref(),
                cancellation,
            )?;
        }
        let masks = pk.coset_masks(coset)?;
        let (l0, l_last, l_active) = (
            masks.l0.as_slice(),
            masks.l_last.as_slice(),
            masks.l_active.as_slice(),
        );
        evaluate_many(plan.as_ref(), inputs.advice, &mut advice, cancellation)?;
        evaluate_many(plan.as_ref(), inputs.instance, &mut instance, cancellation)?;
        evaluate_many(
            plan.as_ref(),
            &inputs.permutation_products,
            &mut products,
            cancellation,
        )?;
        let fixed_refs: Vec<&[C::ScalarExt]> = fixed.iter().map(AsRef::as_ref).collect();
        let advice_refs: Vec<&[C::ScalarExt]> = advice.iter().map(|values| &**values).collect();
        let instance_refs: Vec<&[C::ScalarExt]> = instance.iter().map(|values| &**values).collect();
        let sigma_refs: Vec<&[C::ScalarExt]> = sigma.iter().map(AsRef::as_ref).collect();
        let bound = compiled.bind(&fixed_refs, &advice_refs, &instance_refs, n)?;
        let permutation_columns = protocol
            .permutation_columns()
            .iter()
            .map(|column| {
                let table = match column.kind {
                    ColumnKindV1::Advice => &advice_refs,
                    ColumnKindV1::Fixed => &fixed_refs,
                    ColumnKindV1::Instance => &instance_refs,
                };
                table
                    .get(column.column)
                    .copied()
                    .filter(|values| values.len() == n)
                    .ok_or(KeyError::CosetIndex)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if sigma_refs.iter().any(|values| values.len() != n)
            || products.iter().any(|values| values.len() != n)
            || [l0, l_last, l_active]
                .iter()
                .any(|values| values.len() != n)
        {
            return Err(KeyError::CosetIndex.into());
        }
        let mut values = SecretPolynomial::new(vec![C::ScalarExt::ZERO; n]);
        // Evaluate the shared expression DAG once per row. Retain only
        // (A + beta)(S + gamma) for each lookup; its three committed cosets
        // are streamed below after the gates and permutation have folded.
        let mut numerator_tasks: Vec<Vec<&mut [C::ScalarExt]>> = (0..n.div_ceil(ROWS_PER_TASK))
            .map(|_| Vec::with_capacity(shape.lookups))
            .collect();
        for numerator in &mut lookup_numerators {
            for (task, chunk) in numerator_tasks
                .iter_mut()
                .zip(numerator.chunks_mut(ROWS_PER_TASK))
            {
                task.push(chunk);
            }
        }
        let tile_plan = TilePlan::new::<C::ScalarExt>(compiled.nodes.len(), n);
        values
            .par_chunks_mut(ROWS_PER_TASK)
            .zip(numerator_tasks.into_par_iter())
            .enumerate()
            .for_each(|(task, (out, mut numerators))| {
                if CancellationToken::checkpoint(cancellation).is_err() {
                    return;
                }
                let start = task * ROWS_PER_TASK;
                let mut scratch = SecretPolynomial::new(vec![
                    C::ScalarExt::ZERO;
                    compiled.nodes.len() * tile_plan.width
                ]);
                let mut x_row = shift * omega.pow_vartime([start as u64]);
                for (tile, out) in out.chunks_mut(tile_plan.width).enumerate() {
                    let offset = tile * tile_plan.width;
                    compiled.evaluate_tile(&bound, start + offset, tile_plan.width, &mut scratch);
                    for (lane, out) in out.iter_mut().enumerate() {
                        let offset = offset + lane;
                        let row = start + offset;
                        let r_next = (row + 1) & mask;
                        let scratch = EvaluatedRow::new(&scratch, tile_plan.width, lane);
                        let mut value = gate_fold.evaluate(&compiled.gates, scratch, filter);
                        // Every term is computed; a filtered term adds zero but
                        // keeps its power of y.
                        let mut push = |term: ConstraintTerm, contribution: C::ScalarExt| {
                            value = value * y
                                + if filter.keeps(term) {
                                    contribution
                                } else {
                                    C::ScalarExt::ZERO
                                };
                        };
                        if let (Some(first), Some(last)) = (products.first(), products.last()) {
                            let r_last = (row + last_offset) & mask;
                            push(
                                ConstraintTerm::PermutationFirst,
                                (one - first[row]) * l0[row],
                            );
                            push(
                                ConstraintTerm::PermutationLast,
                                (last[row].square() - last[row]) * l_last[row],
                            );
                            for (index, pair) in products.windows(2).enumerate() {
                                push(
                                    ConstraintTerm::PermutationLink { set: index + 1 },
                                    (pair[1][row] - pair[0][r_last]) * l0[row],
                                );
                            }
                            let mut current_delta = beta * x_row;
                            for (set_index, ((set, set_columns), set_sigma)) in products
                                .iter()
                                .zip(permutation_columns.chunks(shape.chunk_len))
                                .zip(sigma_refs.chunks(shape.chunk_len))
                                .enumerate()
                            {
                                let mut left = set[r_next];
                                for (column, sigma) in set_columns.iter().zip(set_sigma) {
                                    left *= column[row] + beta * sigma[row] + gamma;
                                }
                                let mut right = set[row];
                                for column in set_columns {
                                    right *= column[row] + current_delta + gamma;
                                    current_delta *= delta;
                                }
                                push(
                                    ConstraintTerm::PermutationProduct { set: set_index },
                                    (left - right) * l_active[row],
                                );
                            }
                        }
                        for (lookup, numerator) in compiled.lookups.iter().zip(&mut numerators) {
                            let compressed_input =
                                CompiledExpressions::compress(&lookup.inputs, scratch, theta);
                            let compressed_table =
                                CompiledExpressions::compress(&lookup.tables, scratch, theta);
                            numerator[offset] =
                                (compressed_input + beta) * (compressed_table + gamma);
                        }
                        *out = value;
                        x_row *= omega;
                    }
                }
            });
        drop(tile_plan);
        CancellationToken::checkpoint(cancellation)?;
        // Gate/permutation evaluation has joined every row task. Its cosets
        // are now dead; only lookup numerators, masks, powers and `values` are
        // needed below. End all shared views before overwriting owned cosets.
        drop((
            bound,
            permutation_columns,
            fixed_refs,
            advice_refs,
            instance_refs,
            sigma_refs,
        ));
        if shape.lookups != 0 {
            let mut lookup_columns = fixed
                .iter_mut()
                .chain(sigma.iter_mut())
                .filter_map(|column| match column {
                    KeyCoset::Cached(_) => None,
                    KeyCoset::Workspace(values) => Some(&mut **values),
                })
                .chain(advice.iter_mut().map(|values| &mut **values))
                .chain(instance.iter_mut().map(|values| &mut **values))
                .chain(products.iter_mut().map(|values| &mut **values))
                .chain(lookup_spill.iter_mut().map(|values| &mut **values));
            let [product, input, table] = [
                next_column(&mut lookup_columns)?,
                next_column(&mut lookup_columns)?,
                next_column(&mut lookup_columns)?,
            ];
            for (index, (lookup, numerator)) in
                inputs.lookups.iter().zip(&lookup_numerators).enumerate()
            {
                evaluate_many(
                    plan.as_ref(),
                    &[lookup.product, lookup.input, lookup.table],
                    &mut [&mut *product, &mut *input, &mut *table],
                    cancellation,
                )?;
                values
                    .par_chunks_mut(ROWS_PER_TASK)
                    .enumerate()
                    .for_each(|(task, out)| {
                        if CancellationToken::checkpoint(cancellation).is_err() {
                            return;
                        }
                        let start = task * ROWS_PER_TASK;
                        for (offset, value) in out.iter_mut().enumerate() {
                            let row = start + offset;
                            let r_next = (row + 1) & mask;
                            let r_prev = (row + mask) & mask;
                            let a_minus_s = input[row] - table[row];
                            let mut push = |part, contribution: C::ScalarExt| {
                                let term = ConstraintTerm::Lookup {
                                    lookup: index,
                                    part,
                                };
                                *value = *value * y
                                    + if filter.keeps(term) {
                                        contribution
                                    } else {
                                        C::ScalarExt::ZERO
                                    };
                            };
                            push(LookupConstraint::First, (one - product[row]) * l0[row]);
                            push(
                                LookupConstraint::Last,
                                (product[row].square() - product[row]) * l_last[row],
                            );
                            push(
                                LookupConstraint::Product,
                                (product[r_next] * (input[row] + beta) * (table[row] + gamma)
                                    - product[row] * numerator[row])
                                    * l_active[row],
                            );
                            push(LookupConstraint::Start, a_minus_s * l0[row]);
                            push(
                                LookupConstraint::Step,
                                a_minus_s * (input[row] - input[r_prev]) * l_active[row],
                            );
                        }
                    });
            }
        }
        CancellationToken::checkpoint(cancellation)?;
        let inverse = quotient
            .vanishing_inverse(coset)
            .ok_or(KeyError::CosetIndex)?;
        values.par_iter_mut().for_each(|value| *value *= inverse);
        cosets.push(values.into_vec());
    }
    // Recombination needs only the accumulated numerator cosets.
    drop((
        fixed,
        sigma,
        advice,
        instance,
        products,
        lookup_numerators,
        lookup_spill,
    ));
    drop(lease);
    CancellationToken::checkpoint(cancellation)?;
    Ok(quotient.recombine_cancellable(domain, cosets.into_vec(), cancellation)?)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tile_experiment;
