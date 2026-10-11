//! Streaming-schedule parity against the separately retained row-wise fold.
//!
//! This test oracle materializes all three cosets for every lookup and folds
//! every constraint inside each row, independently of the production schedule.

use super::*;
use crate::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation},
    frontend::{Error, Layouter, SimpleFloorPlanner, Value},
    keys::{CosetCachePolicy, keygen_pk},
    pcs::ipa::PinnedParams,
    protocol::AllTerms,
};

type LookupCoset<'a, F> = [&'a mut [F]; 3];

fn row_wise_reference<C: PastaCurve>(
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    compiled: &CompiledExpressions<C::ScalarExt>,
    inputs: &QuotientInputs<'_, C::ScalarExt>,
    challenges: Challenges<C::ScalarExt>,
    filter: &(impl ConstraintFilter + Sync),
) -> Result<Vec<C::ScalarExt>, ProverError> {
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
    let one = C::ScalarExt::ONE;
    let delta = <C::ScalarExt as ff::PrimeField>::DELTA;
    let mut cosets = Vec::with_capacity(shape.quotient_pieces);
    let key_columns = if pk.has_coset_cache() {
        0
    } else {
        shape.num_fixed + shape.permutation_columns
    };
    let count = key_columns
        + shape.num_advice
        + shape.num_instance
        + shape.permutation_sets
        + 3 * shape.lookups;
    let mut storage = vec![vec![C::ScalarExt::ZERO; n]; count];
    let mut columns = storage.iter_mut().map(Vec::as_mut_slice);
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
    let mut lookups: Vec<LookupCoset<'_, C::ScalarExt>> = (0..shape.lookups)
        .map(|_| {
            Ok([
                next_column(&mut columns)?,
                next_column(&mut columns)?,
                next_column(&mut columns)?,
            ])
        })
        .collect::<Result<_, KeyError>>()?;
    for coset in 0..shape.quotient_pieces {
        let shift = quotient.shift(coset).ok_or(KeyError::CosetIndex)?;
        {
            reference_refresh_key_cosets(
                pk,
                pk.fixed_polys(),
                &mut fixed,
                CosetPolynomial::Fixed,
                coset,
            )?;
            reference_refresh_key_cosets(
                pk,
                pk.permutation_polys(),
                &mut sigma,
                CosetPolynomial::Permutation,
                coset,
            )?;
        }
        let masks = pk.coset_masks(coset)?;
        let (l0, l_last, l_active) = (
            masks.l0.as_slice(),
            masks.l_last.as_slice(),
            masks.l_active.as_slice(),
        );
        advice
            .par_iter_mut()
            .zip(inputs.advice)
            .try_for_each(|(values, poly)| evaluate_into(domain, poly, shift, values))?;
        instance
            .par_iter_mut()
            .zip(inputs.instance)
            .try_for_each(|(values, poly)| evaluate_into(domain, poly, shift, values))?;
        products
            .par_iter_mut()
            .zip(&inputs.permutation_products)
            .try_for_each(|(values, poly)| evaluate_into(domain, poly, shift, values))?;
        for ([product, input, table], lookup) in lookups.iter_mut().zip(&inputs.lookups) {
            evaluate_into(domain, lookup.product, shift, product)?;
            evaluate_into(domain, lookup.input, shift, input)?;
            evaluate_into(domain, lookup.table, shift, table)?;
        }
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
        let mut values = vec![C::ScalarExt::ZERO; n];
        values
            .par_chunks_mut(ROWS_PER_TASK)
            .enumerate()
            .for_each(|(task, out)| {
                let start = task * ROWS_PER_TASK;
                let mut scratch = vec![C::ScalarExt::ZERO; compiled.nodes.len()];
                let mut x_row = shift * omega.pow_vartime([start as u64]);
                for (offset, out) in out.iter_mut().enumerate() {
                    let row = start + offset;
                    let r_next = (row + 1) & mask;
                    let r_prev = (row + mask) & mask;
                    compiled.evaluate_row(&bound, row, &mut scratch);
                    let mut value = C::ScalarExt::ZERO;
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
                    for (polynomial, root) in compiled.gates.iter().enumerate() {
                        push(ConstraintTerm::Gate { polynomial }, scratch[*root as usize]);
                    }
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
                    for (index, (lookup, [product, input, table])) in
                        compiled.lookups.iter().zip(&lookups).enumerate()
                    {
                        let compressed_input = CompiledExpressions::compress(
                            &lookup.inputs,
                            EvaluatedRow::new(&scratch, 1, 0),
                            theta,
                        );
                        let compressed_table = CompiledExpressions::compress(
                            &lookup.tables,
                            EvaluatedRow::new(&scratch, 1, 0),
                            theta,
                        );
                        let table_value = (compressed_input + beta) * (compressed_table + gamma);
                        let a_minus_s = input[row] - table[row];
                        let term = |part| ConstraintTerm::Lookup {
                            lookup: index,
                            part,
                        };
                        push(
                            term(LookupConstraint::First),
                            (one - product[row]) * l0[row],
                        );
                        push(
                            term(LookupConstraint::Last),
                            (product[row].square() - product[row]) * l_last[row],
                        );
                        push(
                            term(LookupConstraint::Product),
                            (product[r_next] * (input[row] + beta) * (table[row] + gamma)
                                - product[row] * table_value)
                                * l_active[row],
                        );
                        push(term(LookupConstraint::Start), a_minus_s * l0[row]);
                        push(
                            term(LookupConstraint::Step),
                            a_minus_s * (input[row] - input[r_prev]) * l_active[row],
                        );
                    }
                    *out = value;
                    x_row *= omega;
                }
            });
        let inverse = quotient
            .vanishing_inverse(coset)
            .ok_or(KeyError::CosetIndex)?;
        values.par_iter_mut().for_each(|value| *value *= inverse);
        cosets.push(values);
    }
    // Recombination needs only the accumulated numerator cosets.
    drop((fixed, sigma, advice, instance, products, lookups));
    Ok(quotient.recombine(domain, cosets)?)
}

/// Gate rotations, multiple permutation sets and a variable lookup count.
#[derive(Clone, Copy)]
struct ScheduledLookups(usize);

impl<F: PastaField> Circuit<F> for ScheduledLookups {
    type Config = (Vec<Column<Advice>>, Column<Fixed>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;

    fn without_witnesses(&self) -> Self {
        *self
    }
    fn params(&self) -> usize {
        self.0
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, 0)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, count: usize) -> Self::Config {
        let advice: Vec<_> = (0..8).map(|_| meta.advice_column()).collect();
        let fixed = meta.fixed_column();
        for column in &advice {
            meta.enable_equality(*column);
        }
        meta.enable_equality(fixed);
        meta.create_gate("rotations", |cells| {
            let previous = cells.query_advice(advice[0], Rotation::prev());
            let current = cells.query_advice(advice[1], Rotation::cur());
            let next = cells.query_advice(advice[2], Rotation::next());
            let fixed = cells.query_fixed(fixed, Rotation::cur());
            vec![
                previous * current - next,
                fixed * cells.query_advice(advice[3], Rotation::cur()),
            ]
        });
        for lookup in 0..count {
            meta.lookup_any("rotated lookup", |cells| {
                let input = cells.query_advice(advice[lookup % advice.len()], Rotation::prev());
                let next =
                    cells.query_advice(advice[(lookup + 1) % advice.len()], Rotation::next());
                let table = cells.query_fixed(fixed, Rotation::cur());
                vec![
                    (input, table.clone()),
                    (
                        next,
                        table + Expression::Constant(F::from(lookup as u64 + 1)),
                    ),
                ]
            });
        }
        (advice, fixed)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed values",
            |mut region| {
                for row in 0..8 {
                    region.assign_fixed(config.1, row, F::from(row as u64 + 2))?;
                }
                Ok(())
            },
        )
    }
}

struct OmitTerm(Option<ConstraintTerm>);
impl ConstraintFilter for OmitTerm {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        self.0 != Some(term)
    }
}

fn streamed_parity<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(K).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(6241);
    for lookup_count in [0, 1, 2, 5] {
        let circuit = ScheduledLookups(lookup_count);
        for policy in [CosetCachePolicy::Eager, CosetCachePolicy::OnDemand] {
            let mut config = crate::test_circuits::keygen_config(CHOICES[0]);
            config.coset_cache = policy;
            let pk = keygen_pk(&params, &circuit, &config).unwrap();
            let protocol = Protocol::new(pk.binding().descriptor()).unwrap();
            let shape = protocol.shape();
            assert_eq!(shape.lookups, lookup_count);
            assert!(shape.permutation_sets > 1);
            let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).unwrap();
            let mut columns = |count: usize| -> Vec<Vec<C::ScalarExt>> {
                (0..count)
                    .map(|_| {
                        (0..shape.n)
                            .map(|_| C::ScalarExt::random(&mut rng))
                            .collect()
                    })
                    .collect()
            };
            let advice = columns(shape.num_advice);
            let instance = columns(shape.num_instance);
            let products = columns(shape.permutation_sets);
            let lookup_polys = columns(3 * lookup_count);
            let inputs = QuotientInputs {
                advice: &advice,
                instance: &instance,
                permutation_products: products.iter().map(Vec::as_slice).collect(),
                lookups: lookup_polys
                    .chunks_exact(3)
                    .map(|c| LookupPolys {
                        product: &c[0],
                        input: &c[1],
                        table: &c[2],
                    })
                    .collect(),
            };
            let challenges = Challenges {
                theta: C::ScalarExt::from(3),
                beta: C::ScalarExt::from(5),
                gamma: C::ScalarExt::from(7),
                y: C::ScalarExt::from(11),
            };
            let elements = workspace_elements(&pk, &protocol).unwrap();
            let base = if pk.has_coset_cache() {
                0
            } else {
                shape.num_fixed + shape.permutation_columns
            } + shape.num_advice
                + shape.num_instance
                + shape.permutation_sets;
            assert_eq!(
                elements / shape.n - base,
                usize::from(base != 0 || lookup_count != 0)
                    + if lookup_count == 0 {
                        0
                    } else {
                        lookup_count + 3_usize.saturating_sub(base)
                    }
            );
            let mut omissions = vec![
                None,
                Some(ConstraintTerm::Gate { polynomial: 0 }),
                Some(ConstraintTerm::PermutationLink { set: 1 }),
            ];
            if lookup_count > 0 {
                for part in [
                    LookupConstraint::First,
                    LookupConstraint::Last,
                    LookupConstraint::Product,
                    LookupConstraint::Start,
                    LookupConstraint::Step,
                ] {
                    omissions.push(Some(ConstraintTerm::Lookup {
                        lookup: lookup_count - 1,
                        part,
                    }));
                }
            }
            let mut workspace = QuotientWorkspace::new(elements * size_of::<C::ScalarExt>());
            for omission in omissions {
                let filter = OmitTerm(omission);
                let expected =
                    row_wise_reference(&pk, &protocol, &compiled, &inputs, challenges, &filter)
                        .unwrap();
                for workers in [1, 4] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    let actual = pool
                        .install(|| {
                            evaluate_with_workspace(
                                &pk,
                                &protocol,
                                &compiled,
                                &inputs,
                                challenges,
                                &filter,
                                &mut workspace,
                            )
                        })
                        .unwrap();
                    assert_eq!(
                        actual, expected,
                        "L={lookup_count}, workers={workers}, omitted={omission:?}"
                    );
                    assert!(workspace.is_zeroized());
                    assert_eq!(workspace.allocated_bytes(), workspace.maximum_bytes());
                }
            }
            if lookup_count > 0 {
                let mut malformed = QuotientInputs {
                    advice: inputs.advice,
                    instance: inputs.instance,
                    permutation_products: inputs.permutation_products.clone(),
                    lookups: inputs
                        .lookups
                        .iter()
                        .map(|l| LookupPolys {
                            product: l.product,
                            input: l.input,
                            table: l.table,
                        })
                        .collect(),
                };
                malformed.lookups[lookup_count - 1].input = &lookup_polys[0][..shape.n - 1];
                assert!(matches!(
                    evaluate_with_workspace(
                        &pk,
                        &protocol,
                        &compiled,
                        &malformed,
                        challenges,
                        &AllTerms,
                        &mut workspace
                    ),
                    Err(ProverError::Key(KeyError::Shape {
                        what: "coset coefficients",
                        ..
                    }))
                ));
                assert!(workspace.is_zeroized());
                malformed.lookups.pop();
                assert!(matches!(
                    evaluate_with_workspace(
                        &pk,
                        &protocol,
                        &compiled,
                        &malformed,
                        challenges,
                        &AllTerms,
                        &mut workspace
                    ),
                    Err(ProverError::Key(KeyError::Shape {
                        what: "quotient lookups",
                        ..
                    }))
                ));
                assert!(workspace.is_zeroized());
                let expected =
                    row_wise_reference(&pk, &protocol, &compiled, &inputs, challenges, &AllTerms)
                        .unwrap();
                assert_eq!(
                    evaluate_with_workspace(
                        &pk,
                        &protocol,
                        &compiled,
                        &inputs,
                        challenges,
                        &AllTerms,
                        &mut workspace
                    )
                    .unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn streamed_lookup_cosets_match_row_wise_reference_on_both_fields() {
    streamed_parity::<Ep>();
    streamed_parity::<Eq>();
}

/// The original rotated gates, permutation sets and two lookups, followed by
/// enough distinct quadratic gate polynomials to cross eight-term boundaries.
#[derive(Clone, Copy)]
struct GateFoldBoundary(usize);

impl<F: PastaField> Circuit<F> for GateFoldBoundary {
    type Config = (Vec<Column<Advice>>, Column<Fixed>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn params(&self) -> usize {
        self.0
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, 7)
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, gate_count: usize) -> Self::Config {
        assert!(gate_count >= 2);
        let (advice, fixed) = <ScheduledLookups as Circuit<F>>::configure_with_params(meta, 2);
        for polynomial in 2..gate_count {
            meta.create_gate("gate fold boundary", |cells| {
                let previous =
                    cells.query_advice(advice[(3 * polynomial) % advice.len()], Rotation::prev());
                let current = cells
                    .query_advice(advice[(3 * polynomial + 1) % advice.len()], Rotation::cur());
                let next = cells.query_advice(
                    advice[(3 * polynomial + 2) % advice.len()],
                    Rotation::next(),
                );
                let fixed = cells.query_fixed(fixed, Rotation::cur());
                vec![previous * current + next * F::from(polynomial as u64 + 1) - fixed]
            });
        }
        (advice, fixed)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        <ScheduledLookups as Circuit<F>>::synthesize(&ScheduledLookups(2), config, layouter)
    }
}

/// Read-only filters can omit a whole group or terms from several fold stages.
struct OmitTerms(Vec<ConstraintTerm>);

impl ConstraintFilter for OmitTerms {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        !self.0.contains(&term)
    }
}

fn gate_fold_boundary_parity<C: PastaCurve>() {
    // Four row tasks make the worker comparison exercise the parallel gate
    // stage as well as the parallel column transforms (the old fixture is k6).
    const BOUNDARY_K: u32 = 10;
    let params = PinnedParams::<C>::derive(BOUNDARY_K).unwrap();
    let pools: Vec<_> = [1, 4]
        .into_iter()
        .map(|workers| {
            (
                workers,
                rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap(),
            )
        })
        .collect();
    let mut rng = ChaCha20Rng::seed_from_u64(6243);
    for gate_count in [7, 8, 9, 15, 16, 17] {
        for policy in [CosetCachePolicy::Eager, CosetCachePolicy::OnDemand] {
            let mut config = crate::test_circuits::keygen_config(CHOICES[0]);
            config.coset_cache = policy;
            let pk = keygen_pk(&params, &GateFoldBoundary(gate_count), &config).unwrap();
            let protocol = Protocol::new(pk.binding().descriptor()).unwrap();
            let shape = protocol.shape();
            assert_eq!(shape.n, 4 * ROWS_PER_TASK);
            assert_eq!(shape.lookups, 2);
            assert!(shape.permutation_sets > 1);
            let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).unwrap();
            assert_eq!(compiled.gates.len(), gate_count);
            let mut columns = |count: usize| -> Vec<Vec<C::ScalarExt>> {
                (0..count)
                    .map(|_| {
                        (0..shape.n)
                            .map(|_| C::ScalarExt::random(&mut rng))
                            .collect()
                    })
                    .collect()
            };
            let advice = columns(shape.num_advice);
            let instance = columns(shape.num_instance);
            let products = columns(shape.permutation_sets);
            let lookup_polys = columns(3 * shape.lookups);
            let inputs = QuotientInputs {
                advice: &advice,
                instance: &instance,
                permutation_products: products.iter().map(Vec::as_slice).collect(),
                lookups: lookup_polys
                    .chunks_exact(3)
                    .map(|column| LookupPolys {
                        product: &column[0],
                        input: &column[1],
                        table: &column[2],
                    })
                    .collect(),
            };
            // Unlike zero or one, this challenge exposes inserted or missing
            // Horner positions at a full-group/remainder/permutation boundary.
            let challenges = Challenges {
                theta: C::ScalarExt::from(3),
                beta: C::ScalarExt::from(5),
                gamma: C::ScalarExt::from(7),
                y: C::ScalarExt::from(11),
            };
            let unfiltered =
                row_wise_reference(&pk, &protocol, &compiled, &inputs, challenges, &AllTerms)
                    .unwrap();
            let mut omissions = vec![Vec::new()];
            let mut gate_indices: Vec<_> = [0, 7, 8, 15, 16, gate_count - 1]
                .into_iter()
                .filter(|index| *index < gate_count)
                .collect();
            gate_indices.sort_unstable();
            gate_indices.dedup();
            omissions.extend(
                gate_indices
                    .into_iter()
                    .map(|polynomial| vec![ConstraintTerm::Gate { polynomial }]),
            );
            omissions.extend([
                vec![ConstraintTerm::PermutationFirst],
                vec![ConstraintTerm::PermutationLink { set: 1 }],
                vec![ConstraintTerm::Lookup {
                    lookup: 0,
                    part: LookupConstraint::Product,
                }],
                vec![ConstraintTerm::Lookup {
                    lookup: 1,
                    part: LookupConstraint::Step,
                }],
                vec![
                    ConstraintTerm::Gate {
                        polynomial: gate_count - 1,
                    },
                    ConstraintTerm::PermutationLast,
                    ConstraintTerm::Lookup {
                        lookup: 1,
                        part: LookupConstraint::Product,
                    },
                ],
            ]);
            if gate_count >= 16 {
                // This entire group contributes zero, but must still multiply
                // the preceding nonzero group by y^8 before any tail terms.
                omissions.push(
                    (8..16)
                        .map(|polynomial| ConstraintTerm::Gate { polynomial })
                        .collect(),
                );
            }
            let elements = workspace_elements(&pk, &protocol).unwrap();
            let mut workspace = QuotientWorkspace::new(elements * size_of::<C::ScalarExt>());
            for omitted in omissions {
                let filter = OmitTerms(omitted);
                let expected = if filter.0.is_empty() {
                    unfiltered.clone()
                } else {
                    let expected =
                        row_wise_reference(&pk, &protocol, &compiled, &inputs, challenges, &filter)
                            .unwrap();
                    assert_ne!(
                        expected, unfiltered,
                        "vacuous filter: G={gate_count}, cache={policy:?}, omitted={:?}",
                        filter.0
                    );
                    expected
                };
                for (workers, pool) in &pools {
                    let actual = pool
                        .install(|| {
                            evaluate_with_workspace(
                                &pk,
                                &protocol,
                                &compiled,
                                &inputs,
                                challenges,
                                &filter,
                                &mut workspace,
                            )
                        })
                        .unwrap();
                    assert_eq!(
                        actual, expected,
                        "G={gate_count}, cache={policy:?}, workers={workers}, omitted={:?}",
                        filter.0
                    );
                    assert!(workspace.is_zeroized());
                    assert_eq!(workspace.allocated_bytes(), workspace.maximum_bytes());
                }
            }
        }
    }
}

#[test]
fn gate_group_boundaries_match_full_quotient_on_both_fields() {
    gate_fold_boundary_parity::<Ep>();
    gate_fold_boundary_parity::<Eq>();
}

/// Independent key-coset oracle: one geometric transform per owned column.
fn reference_refresh_key_cosets<'a, C: PastaCurve>(
    pk: &'a ProvingKey<C>,
    coefficients: &[Vec<C::ScalarExt>],
    values: &mut [KeyCoset<'a, C::ScalarExt>],
    polynomial: impl Fn(usize) -> CosetPolynomial,
    coset: usize,
) -> Result<(), KeyError> {
    let shift = pk
        .quotient_domain()
        .shift(coset)
        .ok_or(KeyError::CosetIndex)?;
    for (index, (values, coefficients)) in values.iter_mut().zip(coefficients).enumerate() {
        match values {
            KeyCoset::Workspace(values) => evaluate_into(pk.domain(), coefficients, shift, values)?,
            KeyCoset::Cached(values) => {
                *values = match pk.coset_values(polynomial(index), coset)? {
                    Cow::Borrowed(values) => values,
                    Cow::Owned(_) => return Err(KeyError::CosetIndex),
                };
            }
        }
    }
    Ok(())
}

/// Lookup-only keys with zero through three reusable gate-stage columns.
#[derive(Clone, Copy)]
struct SmallLookup(usize);

impl<F: PastaField> Circuit<F> for SmallLookup {
    type Config = (Vec<Column<Advice>>, Column<Fixed>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;

    fn without_witnesses(&self) -> Self {
        *self
    }
    fn params(&self) -> usize {
        self.0
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, 0)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, count: usize) -> Self::Config {
        let advice: Vec<_> = (0..count).map(|_| meta.advice_column()).collect();
        let fixed = meta.fixed_column();
        meta.lookup_any("small lookup", |cells| {
            let table = cells.query_fixed(fixed, Rotation::cur());
            if advice.is_empty() {
                vec![(table.clone(), table)]
            } else {
                advice
                    .iter()
                    .map(|column| (cells.query_advice(*column, Rotation::cur()), table.clone()))
                    .collect()
            }
        });
        (advice, fixed)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "zero lookup values",
            |mut region| {
                for row in 0..8 {
                    region.assign_fixed(config.1, row, F::ZERO)?;
                    for column in &config.0 {
                        region.assign_advice(*column, row, Value::known(F::ZERO))?;
                    }
                }
                Ok(())
            },
        )
    }
}

struct CancelLookup<'a>(&'a CancellationToken);
impl ConstraintFilter for CancelLookup<'_> {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        if matches!(term, ConstraintTerm::Lookup { .. }) {
            self.0.cancel();
        }
        true
    }
}
struct PanicLookup;
impl ConstraintFilter for PanicLookup {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        assert!(
            !matches!(term, ConstraintTerm::Lookup { .. }),
            "injected lookup unwind"
        );
        true
    }
}

#[test]
fn tiny_lookup_scratch_shortfall_reuse_and_failures_both_fields() {
    fn check<C: PastaCurve>() {
        let params = PinnedParams::<C>::derive(K).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(6242);
        for advice_count in 0..=3 {
            for policy in [CosetCachePolicy::Eager, CosetCachePolicy::OnDemand] {
                let mut config = crate::test_circuits::keygen_config(CHOICES[0]);
                config.coset_cache = policy;
                let pk = keygen_pk(&params, &SmallLookup(advice_count), &config).unwrap();
                let protocol = Protocol::new(pk.binding().descriptor()).unwrap();
                let shape = protocol.shape();
                assert_eq!(shape.num_advice, advice_count);
                assert_eq!(shape.permutation_sets, 0);
                assert_eq!(shape.num_instance, 0);
                assert_eq!(shape.lookups, 1);
                assert_eq!(shape.num_fixed, 1);
                let base = advice_count + usize::from(policy == CosetCachePolicy::OnDemand);
                let required_columns = base.max(3) + 2; // one numerator and one powers column
                let elements = workspace_elements(&pk, &protocol).unwrap();
                assert_eq!(elements, required_columns * shape.n);
                let compiled =
                    CompiledExpressions::compile(pk.binding().descriptor(), true).unwrap();
                let mut columns = |count| {
                    (0..count)
                        .map(|_| {
                            (0..shape.n)
                                .map(|_| C::ScalarExt::random(&mut rng))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                };
                let advice = columns(advice_count);
                let lookup = columns(3);
                let inputs = QuotientInputs {
                    advice: &advice,
                    instance: &[],
                    permutation_products: Vec::new(),
                    lookups: vec![LookupPolys {
                        product: &lookup[0],
                        input: &lookup[1],
                        table: &lookup[2],
                    }],
                };
                let challenges = Challenges {
                    theta: C::ScalarExt::from(3),
                    beta: C::ScalarExt::from(5),
                    gamma: C::ScalarExt::from(7),
                    y: C::ScalarExt::from(11),
                };
                let expected =
                    row_wise_reference(&pk, &protocol, &compiled, &inputs, challenges, &AllTerms)
                        .unwrap();
                let mut workspace = QuotientWorkspace::new(elements * size_of::<C::ScalarExt>());
                let addresses = workspace
                    .lease(shape.n, required_columns)
                    .unwrap()
                    .columns
                    .iter()
                    .map(|c| c.as_ptr())
                    .collect::<Vec<_>>();
                for workers in [1, 4] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    let evaluate = |workspace: &mut QuotientWorkspace<C::ScalarExt>| {
                        evaluate_with_workspace(
                            &pk, &protocol, &compiled, &inputs, challenges, &AllTerms, workspace,
                        )
                    };
                    assert_eq!(pool.install(|| evaluate(&mut workspace)).unwrap(), expected);
                    assert!(workspace.is_zeroized());
                    assert_eq!(workspace.allocated_bytes(), workspace.maximum_bytes());
                    let token = CancellationToken::new();
                    let cancelled = pool.install(|| {
                        evaluate_with_workspace_cancellable(
                            &pk,
                            &protocol,
                            &compiled,
                            &inputs,
                            challenges,
                            &CancelLookup(&token),
                            &mut workspace,
                            Some(&token),
                        )
                    });
                    assert!(matches!(cancelled, Err(ProverError::Cancelled)));
                    assert!(workspace.is_zeroized());
                    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        pool.install(|| {
                            evaluate_with_workspace(
                                &pk,
                                &protocol,
                                &compiled,
                                &inputs,
                                challenges,
                                &PanicLookup,
                                &mut workspace,
                            )
                        })
                    }));
                    assert!(unwind.is_err());
                    assert!(workspace.is_zeroized());
                    assert_eq!(pool.install(|| evaluate(&mut workspace)).unwrap(), expected);
                    let retained = workspace
                        .lease(shape.n, required_columns)
                        .unwrap()
                        .columns
                        .iter()
                        .map(|c| c.as_ptr())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        retained, addresses,
                        "same shape retains exactly the same allocations"
                    );
                }
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}
