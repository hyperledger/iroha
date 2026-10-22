//! The same quotient in passes that bound the coset columns held at once.
//!
//! The fused evaluator ([`super::evaluate_inner`]) transforms every fixed, `sigma`, advice,
//! instance and product column onto a coset before one row pass over every term. Here the
//! terms, in their canonical order (gate polynomials, the permutation's first, last and link
//! terms, the product rule of each set), and then the lookup numerators are cut into
//! contiguous passes whose columns fit the caller's count; a single term that reads more
//! columns gets a pass of its own. A pass transforms only the columns it reads, evaluates its
//! `k` terms on every row and folds them into the running value as `value * y^k + H`, where
//! `H` is the Horner fold of exactly those terms. Instance columns stay transformed for the
//! whole coset, and the lookup stage is the fused evaluator's.
//!
//! The arithmetic is exact and every term keeps its power of `y`, so `h`, and the proof bytes,
//! equal the fused evaluator's for every split. A column consecutive passes read stays in its
//! slot; one read again after its slot was reused is transformed again, so fewer columns cost
//! coset FFTs, never correctness.

use core::ops::Range;
use std::{borrow::Cow, collections::BTreeSet};

use ff::Field;
use iroha_pasta::{CancellationToken, PastaCurve};
use rayon::prelude::*;

use super::{
    Challenges, CompiledExpressions, ConstraintFilter, ConstraintTerm, EvaluatedRow, GateFold,
    GatePlan, ProverError, QuotientInputs, QuotientWorkspace, ROWS_PER_TASK, TilePlan,
    evaluate_instance_many, evaluate_many, fold_lookups, malformed, next_column, rotation_offset,
};
use crate::{
    cs::{
        ProtocolDescriptor,
        descriptor::{ColumnKindV1, ExprNodeV1, ExprV1, QueryV1},
    },
    keys::{CosetPolynomial, KeyError, ProvingKey},
    protocol::{Protocol, ProtocolError, Shape},
    prover::advice::InstanceColumns,
    secret::{SecretColumns, SecretPolynomial},
};

/// A column one pass transforms onto the coset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Column {
    Fixed(usize),
    Sigma(usize),
    Advice(usize),
    Product(usize),
}

/// One canonical term, or one lookup numerator.
#[derive(Clone, Copy, Debug)]
enum Item {
    Gate(usize),
    /// The permutation's first, last and link terms.
    Head,
    Set(usize),
    Lookup(usize),
}

/// The contiguous terms one pass folds and the columns they read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Pass {
    gates: Range<usize>,
    head: bool,
    sets: Range<usize>,
    lookups: Range<usize>,
    columns: Vec<Column>,
}

fn extend(range: &mut Range<usize>, index: usize) {
    if range.end <= range.start {
        *range = index..index + 1;
    } else {
        range.end = index + 1;
    }
}

impl Pass {
    fn add(&mut self, item: Item) {
        match item {
            Item::Gate(index) => extend(&mut self.gates, index),
            Item::Head => self.head = true,
            Item::Set(set) => extend(&mut self.sets, set),
            Item::Lookup(index) => extend(&mut self.lookups, index),
        }
    }

    /// Canonical terms in this pass (lookup numerators are not terms).
    fn terms(&self, shape: &Shape) -> usize {
        // First, last and one link per further set.
        let head = if self.head {
            shape.permutation_sets + 1
        } else {
            0
        };
        self.gates.len() + head + self.sets.len()
    }
}

/// The column of query `index` in `queries`.
fn query_column(queries: &[QueryV1], index: u32) -> Result<usize, ProverError> {
    usize::try_from(index)
        .ok()
        .and_then(|index| queries.get(index))
        .and_then(|query| usize::try_from(query.column).ok())
        .ok_or_else(|| malformed().into())
}

/// Adds the fixed and advice columns `expression` reads to `read`.
fn read_columns(
    descriptor: &ProtocolDescriptor,
    expression: &ExprV1,
    read: &mut BTreeSet<Column>,
) -> Result<(), ProverError> {
    for node in expression {
        match *node {
            ExprNodeV1::Fixed(index) => {
                read.insert(Column::Fixed(query_column(
                    &descriptor.fixed_queries,
                    index,
                )?));
            }
            ExprNodeV1::Advice(index) => {
                read.insert(Column::Advice(query_column(
                    &descriptor.advice_queries,
                    index,
                )?));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Cuts the canonical terms, then the lookup numerators, into contiguous passes of at most
/// `limit` columns each (see the module documentation). A key that caches its cosets lends
/// its fixed and `sigma` columns, so they occupy no pass column.
fn plan(
    descriptor: &ProtocolDescriptor,
    protocol: &Protocol,
    limit: usize,
    cached: bool,
) -> Result<Vec<Pass>, ProverError> {
    let shape = protocol.shape();
    let mut items = Vec::new();
    for (index, poly) in descriptor.gates.iter().flatten().enumerate() {
        let mut read = BTreeSet::new();
        read_columns(descriptor, poly, &mut read)?;
        items.push((Item::Gate(index), read));
    }
    if shape.permutation_sets != 0 {
        let products = (0..shape.permutation_sets).map(Column::Product).collect();
        items.push((Item::Head, products));
        for (set, columns) in protocol
            .permutation_columns()
            .chunks(shape.chunk_len)
            .enumerate()
        {
            let mut read = BTreeSet::from([Column::Product(set)]);
            for (offset, column) in columns.iter().enumerate() {
                read.insert(Column::Sigma(set * shape.chunk_len + offset));
                match column.kind {
                    ColumnKindV1::Advice => read.insert(Column::Advice(column.column)),
                    ColumnKindV1::Fixed => read.insert(Column::Fixed(column.column)),
                    ColumnKindV1::Instance => false,
                };
            }
            items.push((Item::Set(set), read));
        }
    }
    for (index, lookup) in descriptor.lookups.iter().enumerate() {
        let mut read = BTreeSet::new();
        for expression in lookup.inputs.iter().chain(&lookup.tables) {
            read_columns(descriptor, expression, &mut read)?;
        }
        items.push((Item::Lookup(index), read));
    }
    if cached {
        for (_, read) in &mut items {
            read.retain(|column| matches!(column, Column::Advice(_) | Column::Product(_)));
        }
    }
    let mut passes = Vec::new();
    let mut open: Option<(Pass, BTreeSet<Column>)> = None;
    for (item, read) in items {
        if let Some((pass, columns)) = open.take() {
            if columns.union(&read).count() > limit {
                passes.push(Pass {
                    columns: columns.into_iter().collect(),
                    ..pass
                });
            } else {
                open = Some((pass, columns));
            }
        }
        let (pass, columns) = open.get_or_insert_with(Default::default);
        pass.add(item);
        columns.extend(read);
    }
    if let Some((pass, columns)) = open {
        passes.push(Pass {
            columns: columns.into_iter().collect(),
            ..pass
        });
    }
    Ok(passes)
}

/// Field buffers of one bounded evaluation: the coset powers, the widest pass (at least the
/// lookup triple), the instance columns and one numerator per lookup.
fn workspace_columns(passes: &[Pass], shape: &Shape) -> Result<usize, ProtocolError> {
    let widest = passes
        .iter()
        .map(|pass| pass.columns.len())
        .max()
        .unwrap_or(0)
        .max(if shape.lookups == 0 { 0 } else { 3 });
    widest
        .checked_add(1)
        .and_then(|columns| columns.checked_add(shape.num_instance))
        .and_then(|columns| columns.checked_add(shape.lookups))
        .ok_or(ProtocolError::Overflow)
}

/// Exact field-buffer elements [`evaluate_cancellable`] leases for at most `limit` columns
/// per pass.
///
/// # Errors
///
/// A malformed descriptor expression or an overflowing shape.
pub(in crate::prover) fn workspace_elements<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    limit: usize,
) -> Result<usize, ProverError> {
    let passes = plan(
        pk.binding().descriptor(),
        protocol,
        limit,
        pk.has_coset_cache(),
    )?;
    let shape = protocol.shape();
    Ok(workspace_columns(&passes, shape)?
        .checked_mul(shape.n)
        .ok_or(ProtocolError::Overflow)?)
}

/// Field columns, each `n` elements, that the quotient of `descriptor` holds at once in passes
/// of at most `limit` coset columns with a key that keeps no coset cache: the coset powers, the
/// widest pass (at least a lookup triple), the instance columns and one numerator per lookup.
///
/// # Errors
///
/// A malformed descriptor expression or an overflowing shape.
pub fn bounded_quotient_columns(
    descriptor: &ProtocolDescriptor,
    limit: usize,
) -> Result<usize, ProverError> {
    let protocol = Protocol::new(descriptor)?;
    let passes = plan(descriptor, &protocol, limit, false)?;
    Ok(workspace_columns(&passes, protocol.shape())?)
}

/// Renumbers a pass's gate polynomials into the descriptor's flattened order.
struct PassFilter<'a, T> {
    inner: &'a T,
    first_gate: usize,
}

impl<T: ConstraintFilter> ConstraintFilter for PassFilter<'_, T> {
    #[inline]
    fn keeps(&self, term: ConstraintTerm) -> bool {
        self.inner.keeps(match term {
            ConstraintTerm::Gate { polynomial } => ConstraintTerm::Gate {
                polynomial: polynomial + self.first_gate,
            },
            other => other,
        })
    }
}

/// One permutation set's coset columns in a pass: `z_s`, its equality columns and their
/// `sigma`.
struct SetColumns<'a, F> {
    product: &'a [F],
    equality: Vec<&'a [F]>,
    sigma: Vec<&'a [F]>,
}

/// The coefficients of a key polynomial, or its cached coset.
fn key_coset<'a, C: PastaCurve>(
    pk: &'a ProvingKey<C>,
    polynomial: CosetPolynomial,
    coset: usize,
) -> Result<&'a [C::ScalarExt], KeyError> {
    match pk.coset_values(polynomial, coset)? {
        Cow::Borrowed(values) => Ok(values),
        Cow::Owned(_) => Err(KeyError::CosetIndex),
    }
}

fn view<'a, F>(columns: &[Option<&'a [F]>], index: usize) -> Result<&'a [F], KeyError> {
    columns
        .get(index)
        .copied()
        .flatten()
        .ok_or(KeyError::CosetIndex)
}

/// Computes the `(d - 1) n` coefficients of `h` in passes of at most `limit` coset columns
/// (see the module documentation); equal to the fused evaluator's for the same inputs.
///
/// # Errors
///
/// [`ProverError::Key`] for a missing polynomial or coset, [`ProverError::Workspace`] when
/// a supplied workspace is too small, [`ProverError::Fft`] on a transform failure, and
/// cancellation.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(in crate::prover) fn evaluate_cancellable<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    instances: Option<&InstanceColumns<C::ScalarExt>>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
    limit: usize,
    workspace: Option<&mut QuotientWorkspace<C::ScalarExt>>,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<C::ScalarExt>, ProverError> {
    CancellationToken::checkpoint(cancellation)?;
    let descriptor = pk.binding().descriptor();
    let shape = protocol.shape();
    let n = shape.n;
    if inputs.lookups.len() != shape.lookups {
        return Err(KeyError::Shape {
            what: "quotient lookups",
            expected: shape.lookups,
            actual: inputs.lookups.len(),
        }
        .into());
    }
    let cached = pk.has_coset_cache();
    let passes = plan(descriptor, protocol, limit, cached)?;
    let compiled = passes
        .iter()
        .map(|pass| {
            CompiledExpressions::compile_selected(
                descriptor,
                pass.gates.clone(),
                pass.lookups.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let gate_plans: Vec<_> = compiled.iter().map(GatePlan::new).collect();
    let count = workspace_columns(&passes, shape)?;
    let mut owned;
    let workspace = if let Some(workspace) = workspace {
        workspace
    } else {
        let bytes = count
            .checked_mul(n)
            .and_then(|elements| elements.checked_mul(size_of::<C::ScalarExt>()))
            .ok_or(ProtocolError::Overflow)?;
        owned = QuotientWorkspace::new(bytes);
        &mut owned
    };
    let lease = workspace.lease(n, count).map_err(ProverError::Workspace)?;
    let mut columns = lease.columns.iter_mut().take(count).map(AsMut::as_mut);
    let powers = next_column(&mut columns)?;
    let widest = count - 1 - shape.num_instance - shape.lookups;
    let mut slots = (0..widest)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    let mut instance = (0..shape.num_instance)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;
    let mut numerators = (0..shape.lookups)
        .map(|_| next_column(&mut columns))
        .collect::<Result<Vec<_>, _>>()?;

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
    let chunk = u64::try_from(shape.chunk_len).map_err(|_| ProtocolError::Overflow)?;
    // `delta^(chunk s)`: set `s` continues the fused recurrence at its first column.
    let set_deltas: Vec<_> = (0..shape.permutation_sets)
        .scan(one, |power, _| {
            let current = *power;
            *power *= delta.pow_vartime([chunk]);
            Some(current)
        })
        .collect();
    let folds = passes
        .iter()
        .map(|pass| {
            u64::try_from(pass.terms(shape))
                .map(|terms| y.pow_vartime([terms]))
                .map_err(|_| ProtocolError::Overflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let permutation_columns = protocol.permutation_columns();
    let mut cosets = SecretColumns::new(Vec::with_capacity(shape.quotient_pieces));
    for coset in 0..shape.quotient_pieces {
        CancellationToken::checkpoint(cancellation)?;
        let shift = quotient.shift(coset).ok_or(KeyError::CosetIndex)?;
        let plan = domain.coset_plan_cancellable(&mut *powers, shift, cancellation)?;
        let masks = pk.coset_masks(coset)?;
        let (l0, l_last, l_active) = (
            masks.l0.as_slice(),
            masks.l_last.as_slice(),
            masks.l_active.as_slice(),
        );
        evaluate_instance_many(
            Some(&plan),
            inputs.instance,
            instances,
            l0,
            &mut instance,
            cancellation,
        )?;
        let instance_refs: Vec<&[C::ScalarExt]> = instance.iter().map(|values| &**values).collect();
        // A caching key lends every fixed and `sigma` coset; otherwise passes transform them.
        let (cached_fixed, cached_sigma) = if cached {
            (
                (0..shape.num_fixed)
                    .map(|index| key_coset(pk, CosetPolynomial::Fixed(index), coset).map(Some))
                    .collect::<Result<Vec<_>, _>>()?,
                (0..shape.permutation_columns)
                    .map(|index| {
                        key_coset(pk, CosetPolynomial::Permutation(index), coset).map(Some)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            (
                vec![None; shape.num_fixed],
                vec![None; shape.permutation_columns],
            )
        };
        let permutation_shift = if shape.permutation_sets == 0 {
            shift
        } else {
            beta * shift
        };
        let mut values = SecretPolynomial::new(vec![C::ScalarExt::ZERO; n]);
        // Which column each slot holds on this coset.
        let mut resident: Vec<Option<Column>> = vec![None; slots.len()];
        for (index, pass) in passes.iter().enumerate() {
            CancellationToken::checkpoint(cancellation)?;
            {
                // Columns an earlier pass of this coset left in a slot stay; the others go
                // into slots whose column this pass does not read.
                let mut missing: Vec<Column> = pass
                    .columns
                    .iter()
                    .filter(|column| !resident.contains(&Some(**column)))
                    .copied()
                    .collect();
                let mut coefficients = Vec::with_capacity(missing.len());
                let mut outputs = Vec::with_capacity(missing.len());
                for (slot, held) in slots.iter_mut().zip(resident.iter_mut()) {
                    if held.is_some_and(|column| pass.columns.binary_search(&column).is_ok()) {
                        continue;
                    }
                    let Some(column) = missing.pop() else {
                        break;
                    };
                    let source = match column {
                        Column::Fixed(index) => pk.fixed_polys().get(index).map(Vec::as_slice),
                        Column::Sigma(index) => {
                            pk.permutation_polys().get(index).map(Vec::as_slice)
                        }
                        Column::Advice(index) => inputs.advice.get(index).map(Vec::as_slice),
                        Column::Product(index) => inputs.permutation_products.get(index).copied(),
                    }
                    .ok_or(KeyError::CosetIndex)?;
                    *held = Some(column);
                    coefficients.push(source);
                    outputs.push(&mut **slot);
                }
                if !missing.is_empty() {
                    return Err(KeyError::CosetIndex.into());
                }
                evaluate_many(Some(&plan), &coefficients, &mut outputs, cancellation)?;
            }
            let mut fixed = cached_fixed.clone();
            let mut advice = vec![None; shape.num_advice];
            let mut sigma = cached_sigma.clone();
            let mut products = vec![None; shape.permutation_sets];
            for (slot, held) in slots.iter().zip(&resident) {
                let Some(column) = *held else {
                    continue;
                };
                let (table, index, values) = match column {
                    Column::Fixed(index) => (&mut fixed, index, &**slot),
                    Column::Sigma(index) => (&mut sigma, index, &**slot),
                    Column::Advice(index) => (&mut advice, index, &**slot),
                    Column::Product(index) => (&mut products, index, &**slot),
                };
                *table.get_mut(index).ok_or(KeyError::CosetIndex)? = Some(values);
            }
            let gate_plan = &gate_plans[index];
            let pass_compiled = gate_plan.compiled();
            let bound = pass_compiled.bind_read(&fixed, &advice, &instance_refs, n)?;
            let head = if pass.head {
                (0..shape.permutation_sets)
                    .map(|set| view(&products, set))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            let sets = pass
                .sets
                .clone()
                .map(|set| {
                    let start = set * shape.chunk_len;
                    let end = (start + shape.chunk_len).min(permutation_columns.len());
                    let equality = permutation_columns
                        .get(start..end)
                        .ok_or(KeyError::CosetIndex)?
                        .iter()
                        .map(|column| match column.kind {
                            ColumnKindV1::Advice => view(&advice, column.column),
                            ColumnKindV1::Fixed => view(&fixed, column.column),
                            ColumnKindV1::Instance => instance_refs
                                .get(column.column)
                                .copied()
                                .ok_or(KeyError::CosetIndex),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(SetColumns {
                        product: view(&products, set)?,
                        equality,
                        sigma: (start..end)
                            .map(|column| view(&sigma, column))
                            .collect::<Result<Vec<_>, _>>()?,
                    })
                })
                .collect::<Result<Vec<_>, KeyError>>()?;
            if head
                .iter()
                .chain(sets.iter().flat_map(|set| {
                    core::iter::once(&set.product)
                        .chain(&set.equality)
                        .chain(&set.sigma)
                }))
                .chain(&[l0, l_last, l_active])
                .any(|values| values.len() != n)
            {
                return Err(KeyError::CosetIndex.into());
            }
            let mut numerator_tasks: Vec<Vec<&mut [C::ScalarExt]>> = (0..n.div_ceil(ROWS_PER_TASK))
                .map(|_| Vec::with_capacity(pass.lookups.len()))
                .collect();
            for numerator in numerators
                .get_mut(pass.lookups.clone())
                .ok_or(KeyError::CosetIndex)?
            {
                for (task, chunk) in numerator_tasks
                    .iter_mut()
                    .zip(numerator.chunks_mut(ROWS_PER_TASK))
                {
                    task.push(chunk);
                }
            }
            let pass_filter = PassFilter {
                inner: filter,
                first_gate: pass.gates.start,
            };
            let fold = folds[index];
            let folds_terms = pass.terms(shape) != 0;
            let tile_plan = TilePlan::new::<C::ScalarExt>(pass_compiled.nodes.len(), n);
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
                        pass_compiled.nodes.len()
                            * tile_plan.width
                    ]);
                    let mut permutation_x_row =
                        permutation_shift * omega.pow_vartime([start as u64]);
                    for (tile, out) in out.chunks_mut(tile_plan.width).enumerate() {
                        let offset = tile * tile_plan.width;
                        pass_compiled.evaluate_tile(
                            &bound,
                            start + offset,
                            tile_plan.width,
                            &mut scratch,
                        );
                        for (lane, out) in out.iter_mut().enumerate() {
                            let offset = offset + lane;
                            let row = start + offset;
                            let r_next = (row + 1) & mask;
                            let scratch = EvaluatedRow::new(&scratch, tile_plan.width, lane);
                            let mut value = if pass.gates.is_empty() {
                                C::ScalarExt::ZERO
                            } else {
                                gate_plan.evaluate(&gate_fold, scratch, &pass_filter)
                            };
                            // Every term is computed; a filtered term adds zero but keeps
                            // its power of y.
                            let mut push = |term: ConstraintTerm, contribution: C::ScalarExt| {
                                value = value * y
                                    + if filter.keeps(term) {
                                        contribution
                                    } else {
                                        C::ScalarExt::ZERO
                                    };
                            };
                            if let (Some(first), Some(last)) = (head.first(), head.last()) {
                                let r_last = (row + last_offset) & mask;
                                push(
                                    ConstraintTerm::PermutationFirst,
                                    (one - first[row]) * l0[row],
                                );
                                push(
                                    ConstraintTerm::PermutationLast,
                                    (last[row] - one) * l_last[row],
                                );
                                for (index, pair) in head.windows(2).enumerate() {
                                    push(
                                        ConstraintTerm::PermutationLink { set: index + 1 },
                                        (pair[1][row] - pair[0][r_last]) * l0[row],
                                    );
                                }
                            }
                            for (set_index, set) in pass.sets.clone().zip(&sets) {
                                let mut current_delta = permutation_x_row * set_deltas[set_index];
                                let mut left = set.product[r_next];
                                for (column, sigma) in set.equality.iter().zip(&set.sigma) {
                                    left *=
                                        crate::norm_factor(column[row] + beta * sigma[row] + gamma);
                                }
                                let mut right = set.product[row];
                                for column in &set.equality {
                                    right *=
                                        crate::norm_factor(column[row] + current_delta + gamma);
                                    current_delta *= delta;
                                }
                                push(
                                    ConstraintTerm::PermutationProduct { set: set_index },
                                    (left - right) * l_active[row],
                                );
                            }
                            for (lookup, numerator) in
                                pass_compiled.lookups.iter().zip(&mut numerators)
                            {
                                let compressed_input =
                                    CompiledExpressions::compress(&lookup.inputs, scratch, theta);
                                let compressed_table =
                                    CompiledExpressions::compress(&lookup.tables, scratch, theta);
                                numerator[offset] = crate::norm_factor(compressed_input + beta)
                                    * crate::norm_factor(compressed_table + gamma);
                            }
                            if folds_terms {
                                *out = *out * fold + value;
                            }
                            permutation_x_row *= omega;
                        }
                    }
                });
            drop(tile_plan);
            CancellationToken::checkpoint(cancellation)?;
        }
        drop(instance_refs);
        if shape.lookups != 0 {
            fold_lookups(
                slots.iter_mut().map(|values| &mut **values),
                &inputs.lookups,
                &numerators,
                [l0, l_last, l_active],
                [beta, gamma, y],
                Some(&plan),
                filter,
                &mut values[..],
                cancellation,
            )?;
        }
        CancellationToken::checkpoint(cancellation)?;
        let inverse = quotient
            .vanishing_inverse(coset)
            .ok_or(KeyError::CosetIndex)?;
        values.par_iter_mut().for_each(|value| *value *= inverse);
        cosets.push(values.into_vec());
    }
    // Recombination needs only the accumulated numerator cosets.
    drop((slots, instance, numerators));
    drop(lease);
    CancellationToken::checkpoint(cancellation)?;
    Ok(quotient.recombine_cancellable(domain, cosets.into_vec(), cancellation)?)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Ep;

    use super::*;
    use crate::{
        keys::{CosetCachePolicy, keygen_pk},
        test_circuits::{CHOICES, Lookups, Permutations, keygen_config, setup},
    };

    fn check<Ci: crate::frontend::Circuit<iroha_pasta::Fq>>(circuit: &Ci) {
        let params = setup::<Ep, _>(circuit, CHOICES[0]).params;
        for policy in [CosetCachePolicy::Eager, CosetCachePolicy::OnDemand] {
            let mut config = keygen_config(CHOICES[0]);
            config.coset_cache = policy;
            let pk = keygen_pk(&params, circuit, &config).unwrap();
            let descriptor = pk.binding().descriptor();
            let protocol = Protocol::new(descriptor).unwrap();
            let shape = protocol.shape();
            let gates = descriptor.gates.iter().flatten().count();
            let cached = pk.has_coset_cache();
            for limit in [0, 1, 2, 3, 5, 8, usize::MAX] {
                let passes = plan(descriptor, &protocol, limit, cached).unwrap();
                // Contiguous passes cover every term once, in canonical order.
                let mut next = (0, false, 0, 0);
                for pass in &passes {
                    assert!(pass.gates.is_empty() || pass.gates.start == next.0);
                    if !pass.gates.is_empty() {
                        assert!(
                            !next.1 && next.2 == 0 && next.3 == 0,
                            "gate after later terms"
                        );
                        next.0 = pass.gates.end;
                    }
                    if pass.head {
                        assert!(next.0 == gates && !next.1 && next.2 == 0);
                        next.1 = true;
                    }
                    if !pass.sets.is_empty() {
                        assert!(next.1 && pass.sets.start == next.2 && next.3 == 0);
                        next.2 = pass.sets.end;
                    }
                    if !pass.lookups.is_empty() {
                        assert_eq!(pass.lookups.start, next.3);
                        next.3 = pass.lookups.end;
                    }
                    let items = pass.gates.len()
                        + usize::from(pass.head)
                        + pass.sets.len()
                        + pass.lookups.len();
                    assert!(items > 0);
                    assert!(
                        pass.columns.len() <= limit || items == 1,
                        "limit {limit}: {pass:?}"
                    );
                    assert!(pass.columns.windows(2).all(|pair| pair[0] < pair[1]));
                    if cached {
                        assert!(pass.columns.iter().all(|column| matches!(
                            column,
                            Column::Advice(_) | Column::Product(_)
                        )));
                    }
                }
                assert_eq!(
                    next,
                    (
                        gates,
                        shape.permutation_sets != 0,
                        shape.permutation_sets,
                        shape.lookups
                    )
                );
                if limit == usize::MAX {
                    assert_eq!(passes.len(), 1);
                }
            }
        }
    }

    #[test]
    fn passes_cover_every_term_once_in_order_within_the_limit() {
        check(&Permutations {
            rows: 10,
            tamper: None,
        });
        check(&Lookups {
            rows: 9,
            tamper: None,
            out_of_range: false,
            offset: 0,
        });
    }
}
