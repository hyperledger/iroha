//! The compiled evaluator against two independent evaluators: direct tree
//! evaluation of the finalized constraint system (exact values), and the
//! constraint checker over the uncompressed source expressions (which rows
//! fail), on honest, tampered and random assignments.

use std::collections::BTreeSet;

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, PastaField};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::*;
use crate::{
    check::{CheckFailure, CheckMode, check},
    cs::{
        AdviceQuery, Expression, ExpressionEvaluator, FixedQuery, InstanceQuery, Selector,
        descriptor::ExprNodeV1,
    },
    frontend::{Circuit, synthesize},
    test_circuits::{Arithmetic, CHOICES, K, Lookups, Permutations, setup},
};

#[test]
fn coset_evaluation_reuses_storage_and_matches_the_allocating_reference() {
    fn check<F: PastaField>() {
        let domain = FftDomain::<F>::new(4).expect("domain");
        let quotient = crate::keys::QuotientDomain::<F>::new(4, 6).expect("quotient");
        let coefficients: Vec<F> = (0..domain.n()).map(|i| F::from(i as u64 + 1)).collect();
        let mut values = coefficients.clone();
        let address = values.as_ptr();
        for coset in 0..quotient.pieces() {
            let expected = quotient
                .evaluate(&domain, &coefficients, coset)
                .expect("reference");
            evaluate_into(
                &domain,
                &coefficients,
                quotient.shift(coset).unwrap(),
                &mut values,
            )
            .expect("reuse");
            assert_eq!(values, expected);
            assert_eq!(values.as_ptr(), address);
        }
        assert!(matches!(
            evaluate_into(&domain, &coefficients[..3], F::ONE, &mut values),
            Err(KeyError::Shape {
                what: "coset coefficients",
                ..
            })
        ));
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn batched_coset_coefficients_validate_before_copying() {
    fn check<F: PastaField>() {
        let domain = FftDomain::<F>::new(3).unwrap();
        let mut powers = vec![F::ZERO; domain.n()];
        let plan = domain.coset_plan(&mut powers, F::ONE).unwrap();
        let coefficients = vec![vec![F::ONE; 8], vec![F::from(2); 8]];
        let mut values = vec![vec![F::ZERO; 8]; 2];
        let before = values.clone();
        let mut columns: Vec<_> = values.iter_mut().map(Vec::as_mut_slice).collect();
        assert!(matches!(
            evaluate_many(Some(&plan), &coefficients[..1], &mut columns, None),
            Err(KeyError::Shape {
                what: "coset columns",
                ..
            })
        ));
        assert_eq!(values, before);
        let mut malformed = coefficients.clone();
        malformed[1].pop();
        let mut columns: Vec<_> = values.iter_mut().map(Vec::as_mut_slice).collect();
        assert!(matches!(
            evaluate_many(Some(&plan), &malformed, &mut columns, None),
            Err(KeyError::Shape {
                what: "coset coefficients",
                ..
            })
        ));
        assert_eq!(values, before);
        let mut columns: Vec<_> = values.iter_mut().map(Vec::as_mut_slice).collect();
        assert_eq!(
            evaluate_many(None, &coefficients, &mut columns, None),
            Err(KeyError::CosetIndex)
        );
        assert_eq!(values, before);
        let mut columns: Vec<_> = values.iter_mut().map(Vec::as_mut_slice).collect();
        evaluate_many(Some(&plan), &coefficients, &mut columns, None).unwrap();
        for (actual, mut expected) in values.into_iter().zip(coefficients) {
            domain.coset_fft(&mut expected, F::ONE).unwrap();
            assert_eq!(actual, expected);
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn key_cosets_keep_owned_allocations_or_borrow_each_cached_coset() {
    fn check<C: PastaCurve>() {
        let circuit = Arithmetic {
            start: 3,
            rows: 12,
            tamper: None,
        };
        let setup = setup::<C, _>(&circuit, CHOICES[0]);
        for policy in [
            crate::keys::CosetCachePolicy::Eager,
            crate::keys::CosetCachePolicy::OnDemand,
        ] {
            let mut config = crate::test_circuits::keygen_config(CHOICES[0]);
            config.coset_cache = policy;
            let pk = crate::keys::keygen_pk(&setup.params, &circuit, &config).expect("keygen");
            let fixed: fn(usize) -> CosetPolynomial = CosetPolynomial::Fixed;
            let permutation: fn(usize) -> CosetPolynomial = CosetPolynomial::Permutation;
            for (coefficients, polynomial) in [
                (pk.fixed_polys(), fixed),
                (pk.permutation_polys(), permutation),
            ] {
                let elements = if pk.has_coset_cache() {
                    0
                } else {
                    coefficients.len() * pk.domain().n()
                };
                let mut workspace = QuotientWorkspace::new(elements * size_of::<C::ScalarExt>());
                let count = elements / pk.domain().n();
                let lease = workspace.lease(pk.domain().n(), count).unwrap();
                let mut columns = lease.columns.iter_mut().take(count).map(AsMut::as_mut);
                let mut values =
                    initial_key_cosets(&pk, coefficients, polynomial, &mut columns).unwrap();
                let addresses: Vec<_> = values
                    .iter()
                    .map(|column| column.as_ref().as_ptr())
                    .collect();
                let mut powers = vec![C::ScalarExt::ZERO; pk.domain().n()];
                for coset in 0..pk.quotient_domain().pieces() {
                    let plan = pk
                        .domain()
                        .coset_plan(&mut powers, pk.quotient_domain().shift(coset).unwrap())
                        .unwrap();
                    refresh_key_cosets(
                        &pk,
                        coefficients,
                        &mut values,
                        polynomial,
                        coset,
                        Some(&plan),
                        None,
                    )
                    .expect("refresh");
                    for (index, column) in values.iter().enumerate() {
                        let reference = pk
                            .coset_values(polynomial(index), coset)
                            .expect("reference");
                        assert_eq!(column.as_ref(), reference.as_ref());
                        match policy {
                            crate::keys::CosetCachePolicy::Eager => {
                                assert!(matches!(column, KeyCoset::Cached(_)));
                                assert_eq!(column.as_ref().as_ptr(), reference.as_ptr());
                            }
                            crate::keys::CosetCachePolicy::OnDemand => {
                                assert!(matches!(column, KeyCoset::Workspace(_)));
                                assert_eq!(column.as_ref().as_ptr(), addresses[index]);
                            }
                        }
                    }
                }
                assert_eq!(
                    refresh_key_cosets(
                        &pk,
                        coefficients,
                        &mut values,
                        polynomial,
                        pk.quotient_domain().pieces(),
                        None,
                        None,
                    ),
                    Err(KeyError::CosetIndex)
                );
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn evaluator_error_zeroizes_workspace_and_allows_reuse() {
    fn check<C: PastaCurve>() {
        let circuit = Arithmetic {
            start: 3,
            rows: 12,
            tamper: None,
        };
        let setup = setup::<C, _>(&circuit, CHOICES[0]);
        let mut config = crate::test_circuits::keygen_config(CHOICES[0]);
        config.coset_cache = crate::keys::CosetCachePolicy::OnDemand;
        let pk = crate::keys::keygen_pk(&setup.params, &circuit, &config).unwrap();
        let protocol = Protocol::new(pk.binding().descriptor()).unwrap();
        let shape = protocol.shape();
        let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).unwrap();
        let elements = workspace_elements(&pk, &protocol).unwrap();
        let mut workspace = QuotientWorkspace::new(elements * size_of::<C::ScalarExt>());
        let mut advice = vec![vec![C::ScalarExt::ONE; shape.n]; shape.num_advice];
        advice[0].pop();
        let instances = vec![vec![C::ScalarExt::ZERO; shape.n]; shape.num_instance];
        let products = vec![vec![C::ScalarExt::ONE; shape.n]; shape.permutation_sets];
        let inputs = QuotientInputs {
            advice: &advice,
            instance: &instances,
            permutation_products: products.iter().map(Vec::as_slice).collect(),
            lookups: Vec::new(),
        };
        let result = evaluate_with_workspace(
            &pk,
            &protocol,
            &compiled,
            &inputs,
            Challenges {
                theta: C::ScalarExt::ONE,
                beta: C::ScalarExt::ONE,
                gamma: C::ScalarExt::ONE,
                y: C::ScalarExt::ONE,
            },
            &crate::protocol::AllTerms,
            &mut workspace,
        );
        assert!(matches!(
            result,
            Err(ProverError::Key(KeyError::Shape {
                what: "coset coefficients",
                ..
            }))
        ));
        assert_eq!(workspace.allocated_bytes(), workspace.maximum_bytes());
        assert!(workspace.is_zeroized());
        let lease = workspace.lease(shape.n, elements / shape.n).unwrap();
        assert!(
            lease
                .columns
                .iter()
                .all(|column| column.iter().all(|value| *value == C::ScalarExt::ZERO))
        );
    }
    check::<Ep>();
    check::<Eq>();
}

/// Direct evaluation of a finalized expression on one row of evaluation-form
/// columns, rotations wrapping modulo `n`.
struct RowEvaluator<'a, F> {
    fixed: &'a [Vec<F>],
    advice: &'a [Vec<F>],
    instance: &'a [Vec<F>],
    row: usize,
}

impl<F: PastaField> RowEvaluator<'_, F> {
    fn read(&self, columns: &[Vec<F>], column: usize, rotation: i32) -> F {
        let n = i64::try_from(columns[column].len()).expect("small");
        let row = i64::try_from(self.row).expect("small") + i64::from(rotation);
        columns[column][usize::try_from(row.rem_euclid(n)).expect("in range")]
    }
}

impl<F: PastaField> ExpressionEvaluator<F> for RowEvaluator<'_, F> {
    type Output = F;

    fn constant(&mut self, value: &F) -> F {
        *value
    }

    fn selector(&mut self, _selector: Selector) -> F {
        unreachable!("finalized constraint systems have no virtual selectors")
    }

    fn fixed(&mut self, query: FixedQuery) -> F {
        self.read(self.fixed, query.column_index, query.rotation.0)
    }

    fn advice(&mut self, query: AdviceQuery) -> F {
        self.read(self.advice, query.column_index, query.rotation.0)
    }

    fn instance(&mut self, query: InstanceQuery) -> F {
        self.read(self.instance, query.column_index, query.rotation.0)
    }

    fn negated(&mut self, value: F) -> F {
        -value
    }

    fn sum(&mut self, left: F, right: F) -> F {
        left + right
    }

    fn product(&mut self, left: F, right: F) -> F {
        left * right
    }

    fn scaled(&mut self, value: F, factor: &F) -> F {
        value * factor
    }
}

/// Evaluation-form tables of one synthesis run: fixed (with selector
/// columns), advice and zero-padded instance columns.
struct Tables<F> {
    fixed: Vec<Vec<F>>,
    advice: Vec<Vec<F>>,
    instance: Vec<Vec<F>>,
}

fn tables<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    pk: &ProvingKey<C>,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
) -> Tables<C::ScalarExt> {
    let n = pk.binding().n();
    let synthesized = synthesize(circuit, K, Some(instances)).expect("synthesis");
    Tables {
        fixed: pk.fixed_values().to_vec(),
        advice: synthesized.tables.advice().expect("witness").to_vec(),
        instance: instances
            .iter()
            .map(|column| {
                let mut padded = column.clone();
                padded.resize(n, C::ScalarExt::ZERO);
                padded
            })
            .collect(),
    }
}

/// Compiled gate values equal direct evaluation of the finalized gates, on
/// `tables` and on a random replacement of every column.
fn compiled_matches_direct<C: PastaCurve>(pk: &ProvingKey<C>, tables: &Tables<C::ScalarExt>) {
    let n = pk.binding().n();
    let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).expect("compile");
    let cs = pk.constraint_system().constraint_system();
    let polys: Vec<&Expression<C::ScalarExt>> = cs
        .gates()
        .iter()
        .flat_map(crate::cs::Gate::polynomials)
        .collect();
    assert_eq!(compiled.gate_count(), polys.len());
    let mut rng = ChaCha20Rng::seed_from_u64(n as u64);
    let random = |columns: &[Vec<C::ScalarExt>], rng: &mut ChaCha20Rng| {
        columns
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|_| C::ScalarExt::random(&mut *rng))
                    .collect()
            })
            .collect::<Vec<Vec<_>>>()
    };
    let randomized = Tables {
        fixed: random(&tables.fixed, &mut rng),
        advice: random(&tables.advice, &mut rng),
        instance: random(&tables.instance, &mut rng),
    };
    for tables in [tables, &randomized] {
        let values = compiled
            .gate_values(&tables.fixed, &tables.advice, &tables.instance, n)
            .expect("gate values");
        for (poly, compiled_values) in polys.iter().zip(&values) {
            for (row, value) in compiled_values.iter().enumerate() {
                let mut direct = RowEvaluator {
                    fixed: &tables.fixed,
                    advice: &tables.advice,
                    instance: &tables.instance,
                    row,
                };
                assert_eq!(*value, poly.evaluate(&mut direct), "row {row}");
            }
        }
    }
}

#[test]
fn the_compiled_evaluator_matches_direct_evaluation() {
    let arithmetic = Arithmetic {
        start: 2,
        rows: 9,
        tamper: Some(3),
    };
    for choice in [CHOICES[0], CHOICES[2]] {
        let fixture = setup::<Ep, _>(&arithmetic, choice);
        let columns = tables(&fixture.pk, &arithmetic, &arithmetic.instances::<Fq>());
        compiled_matches_direct(&fixture.pk, &columns);
    }
    let lookups = Lookups {
        rows: 7,
        tamper: Some(2),
        out_of_range: false,
        offset: 1,
    };
    let fixture = setup::<Eq, _>(&lookups, CHOICES[1]);
    compiled_matches_direct(&fixture.pk, &tables(&fixture.pk, &lookups, &[]));
    let permutations = Permutations {
        rows: 5,
        tamper: None,
    };
    let fixture = setup::<Eq, _>(&permutations, CHOICES[3]);
    let columns = tables(&fixture.pk, &permutations, &permutations.instances::<Fp>());
    compiled_matches_direct(&fixture.pk, &columns);
}

/// The `(gate polynomial, row)` pairs where the compiled values are nonzero
/// equal the gate failures the checker reports on the uncompressed source.
fn compiled_agrees_with_checker<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    pk: &ProvingKey<C>,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
) -> usize {
    let n = pk.binding().n();
    let synthesized = synthesize(circuit, K, Some(instances)).expect("synthesis");
    let report = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    let offsets: Vec<usize> = synthesized
        .cs
        .gates()
        .iter()
        .scan(0, |offset, gate| {
            let start = *offset;
            *offset += gate.polynomials().len();
            Some(start)
        })
        .collect();
    let expected: BTreeSet<(usize, usize)> = report
        .failures()
        .iter()
        .filter_map(|failure| match failure {
            CheckFailure::ConstraintNotSatisfied {
                gate,
                constraint,
                location,
                ..
            } => Some((offsets[*gate] + constraint, location.row)),
            _ => None,
        })
        .collect();
    let tables = tables(pk, circuit, instances);
    let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).expect("compile");
    let values = compiled
        .gate_values(&tables.fixed, &tables.advice, &tables.instance, n)
        .expect("gate values");
    let found: BTreeSet<(usize, usize)> = values
        .iter()
        .enumerate()
        .flat_map(|(poly, rows)| {
            rows.iter()
                .enumerate()
                .filter(|(_, value)| !bool::from(value.is_zero()))
                .map(move |(row, _)| (poly, row))
        })
        .collect();
    assert_eq!(found, expected);
    found.len()
}

#[test]
fn the_compiled_evaluator_agrees_with_the_constraint_checker() {
    let setup_arithmetic = setup::<Ep, _>(
        &Arithmetic {
            start: 2,
            rows: 9,
            tamper: None,
        },
        CHOICES[0],
    );
    let mut failures = 0;
    for tamper in [None, Some(0), Some(4), Some(8)] {
        let circuit = Arithmetic {
            start: 2,
            rows: 9,
            tamper,
        };
        failures += compiled_agrees_with_checker(
            &setup_arithmetic.pk,
            &circuit,
            &circuit.instances::<Fq>(),
        );
    }
    assert!(failures > 0, "the tampered rows must fail some gate");
    let honest = Lookups {
        rows: 7,
        tamper: None,
        out_of_range: false,
        offset: 0,
    };
    let lookups = setup::<Eq, _>(&honest, CHOICES[2]);
    for tamper in [None, Some(5)] {
        let circuit = Lookups { tamper, ..honest };
        compiled_agrees_with_checker(&lookups.pk, &circuit, &[]);
    }
}

#[test]
fn hash_consing_shares_subexpressions() {
    let setup = setup::<Ep, _>(
        &Lookups {
            rows: 3,
            tamper: None,
            out_of_range: false,
            offset: 0,
        },
        CHOICES[0],
    );
    let descriptor = setup.pk.binding().descriptor();
    let compiled = CompiledExpressions::<Fq>::compile(descriptor, true).expect("compile");
    let lookups_only = CompiledExpressions::<Fq>::compile(descriptor, false).expect("compile");
    assert_eq!(lookups_only.gate_count(), 0);
    assert!(lookups_only.node_count() < compiled.node_count());
    // Duplicating every gate adds roots but no nodes.
    let mut doubled = descriptor.clone();
    doubled.gates = [doubled.gates.clone(), doubled.gates].concat();
    let twice = CompiledExpressions::<Fq>::compile(&doubled, true).expect("compile");
    assert_eq!(twice.node_count(), compiled.node_count());
    assert_eq!(twice.gate_count(), 2 * compiled.gate_count());
    // The two lookups share the selector query and `x`.
    let total_nodes: usize = descriptor
        .lookups
        .iter()
        .flat_map(|lookup| lookup.inputs.iter().chain(&lookup.tables))
        .map(Vec::len)
        .sum();
    assert!(lookups_only.node_count() < total_nodes);
}

#[test]
fn malformed_expressions_do_not_compile() {
    let setup = setup::<Ep, _>(
        &Arithmetic {
            start: 1,
            rows: 3,
            tamper: None,
        },
        CHOICES[0],
    );
    let descriptor = setup.pk.binding().descriptor();
    let malformed = |nodes: Vec<ExprNodeV1>| {
        let mut edited = descriptor.clone();
        edited.gates[0][0] = nodes;
        CompiledExpressions::<Fq>::compile(&edited, true).err()
    };
    let expected = Some(DescriptorError::Invalid(DescriptorRule::Expression));
    assert_eq!(malformed(vec![ExprNodeV1::Sum]), expected);
    assert_eq!(malformed(vec![ExprNodeV1::Advice(99)]), expected);
    assert_eq!(malformed(vec![ExprNodeV1::Constant([0xff; 32])]), expected);
    assert_eq!(
        malformed(vec![ExprNodeV1::Advice(0), ExprNodeV1::Advice(0)]),
        expected
    );
    assert_eq!(malformed(vec![ExprNodeV1::Negated]), expected);
    assert_eq!(malformed(vec![]), expected);
    assert_eq!(rotation_offset(-1, 8), Ok(7));
    assert_eq!(rotation_offset(9, 8), Ok(1));
}

#[test]
fn normalized_dag_preserves_field_identities_and_shares_commuted_terms() {
    fn check<F: PastaField>(descriptor: &ProtocolDescriptor) {
        let constant = |value: F| ExprNodeV1::Constant(value.to_repr());
        let input = ExprNodeV1::Advice(0);
        let mut builder = Builder::<F> {
            nodes: Vec::new(),
            index: BTreeMap::new(),
            descriptor,
        };
        let expressions = vec![
            vec![input, constant(F::ZERO), ExprNodeV1::Sum],
            vec![constant(F::ZERO), input, ExprNodeV1::Sum],
            vec![input, constant(F::ONE), ExprNodeV1::Product],
            vec![constant(F::ZERO), input, ExprNodeV1::Product],
            vec![input, ExprNodeV1::Negated, ExprNodeV1::Negated],
            vec![input, ExprNodeV1::Scaled((-F::ONE).to_repr())],
            vec![input, input, ExprNodeV1::Sum],
            vec![input, ExprNodeV1::Scaled(F::from(2).to_repr())],
            vec![input, input, ExprNodeV1::Product],
            vec![
                constant(F::from(3)),
                constant(F::from(7)),
                ExprNodeV1::Product,
            ],
            vec![input, constant(F::from(3)), ExprNodeV1::Sum],
            vec![constant(F::from(3)), input, ExprNodeV1::Sum],
            vec![input, input, ExprNodeV1::Negated, ExprNodeV1::Product],
            vec![input, ExprNodeV1::Negated, input, ExprNodeV1::Product],
        ];
        let roots: Vec<_> = expressions
            .iter()
            .map(|expression| builder.expression(expression).unwrap())
            .collect();
        assert_eq!(roots[0], roots[1]);
        assert_eq!(roots[0], roots[2]);
        assert_eq!(roots[0], roots[4]);
        assert_eq!(roots[6], roots[7]);
        assert_eq!(roots[10], roots[11]);
        assert_eq!(roots[12], roots[13]);
        assert!(matches!(builder.nodes[roots[6] as usize], Node::Doubled(_)));
        assert!(matches!(builder.nodes[roots[8] as usize], Node::Squared(_)));
        let evaluator = CompiledExpressions {
            nodes: builder.nodes,
            gates: roots.clone(),
            lookups: vec![],
            fixed_queries: vec![],
            advice_queries: vec![],
            instance_queries: vec![],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(98123);
        let values: Vec<_> = [F::ZERO, F::ONE, -F::ONE]
            .into_iter()
            .chain((0..125).map(|_| F::random(&mut rng)))
            .collect();
        let bound = BoundColumns {
            fixed: vec![],
            advice: vec![(&values, 0)],
            instance: vec![],
            mask: 127,
        };
        let mut scratch = vec![F::ZERO; evaluator.nodes.len()];
        for (row, value) in values.iter().enumerate() {
            evaluator.evaluate_row(&bound, row, &mut scratch);
            let expected = [
                *value,
                *value,
                *value,
                F::ZERO,
                *value,
                -*value,
                *value + value,
                *value + value,
                *value * value,
                F::from(21),
                *value + F::from(3),
                *value + F::from(3),
                -(*value * value),
                -(*value * value),
            ];
            for (&root, expected) in roots.iter().zip(expected) {
                assert_eq!(scratch[root as usize], expected);
            }
        }
    }
    let fixture = setup::<Ep, _>(
        &Arithmetic {
            start: 1,
            rows: 3,
            tamper: None,
        },
        CHOICES[0],
    );
    check::<Fp>(fixture.pk.binding().descriptor());
    check::<Fq>(fixture.pk.binding().descriptor());
}

// Preserve the old zero-seeded definition independently of the optimized helper.
// Public root order includes repetition and noncontiguous indices; both scalar
// and four-lane row views must read precisely the selected lane.
fn check_seeded_lookup_compression<F: PastaField>() {
    let roots = [15_u32, 0, 7, 3, 12, 3, 1, 14, 2, 6, 5, 4, 11, 10, 9, 8];
    let mut rng = ChaCha20Rng::from_seed([83; 32]);
    for stride in [1, 4] {
        for _ in 0..16 {
            let mut values: Vec<F> = (0..16 * stride).map(|_| F::random(&mut rng)).collect();
            values[0] = F::ZERO;
            values[stride] = F::ONE;
            values[2 * stride] = -F::ONE;
            for theta in [F::ZERO, F::ONE, -F::ONE, F::random(&mut rng)] {
                for lane in 0..stride {
                    let row = EvaluatedRow::new(&values, stride, lane);
                    for width in [0, 1, 2, 3, 8, 16] {
                        let selected = &roots[..width];
                        let expected = selected.iter().fold(F::ZERO, |acc, root| {
                            acc * theta + values[*root as usize * stride + lane]
                        });
                        assert_eq!(
                            CompiledExpressions::<F>::compress(selected, row, theta),
                            expected,
                            "width={width}, stride={stride}, lane={lane}",
                        );
                    }
                    assert_eq!(CompiledExpressions::<F>::compress(&[], row, theta), F::ZERO);
                    assert_eq!(
                        CompiledExpressions::<F>::compress(&[0], row, theta),
                        values[lane],
                    );
                }
            }
        }
    }
}

#[test]
fn seeded_lookup_compression_preserves_fp_values_and_root_order() {
    check_seeded_lookup_compression::<Fp>();
}

#[test]
fn seeded_lookup_compression_preserves_fq_values_and_root_order() {
    check_seeded_lookup_compression::<Fq>();
}

#[test]
fn lookup_compression_matches_direct_folding() {
    let circuit = Lookups {
        rows: 6,
        tamper: Some(1),
        out_of_range: false,
        offset: 3,
    };
    let setup = setup::<Eq, _>(&circuit, CHOICES[3]);
    let tables = tables(&setup.pk, &circuit, &[]);
    let n = setup.pk.binding().n();
    let theta = Fp::from(1_000_003);
    let compiled = CompiledExpressions::<Fp>::compile(setup.pk.binding().descriptor(), false)
        .expect("compile");
    let compressed = compiled
        .compress_lookups(&tables.fixed, &tables.advice, &tables.instance, theta, n)
        .expect("compress");
    let cs = setup.pk.constraint_system().constraint_system();
    assert_eq!(compressed.len(), cs.lookups().len());
    for (lookup, (inputs, table_values)) in cs.lookups().iter().zip(&compressed) {
        for row in 0..n {
            let fold = |expressions: &[Expression<Fp>]| {
                expressions.iter().fold(Fp::ZERO, |acc, expression| {
                    let mut direct = RowEvaluator {
                        fixed: &tables.fixed,
                        advice: &tables.advice,
                        instance: &tables.instance,
                        row,
                    };
                    acc * theta + expression.evaluate(&mut direct)
                })
            };
            assert_eq!(inputs[row], fold(lookup.input_expressions()));
            assert_eq!(table_values[row], fold(lookup.table_expressions()));
        }
    }
    // Columns of the wrong length are refused.
    assert!(
        compiled
            .compress_lookups(&tables.fixed, &vec![vec![Fp::ZERO; 3]; 2], &[], theta, n)
            .is_err()
    );
}

#[path = "streamed_tests.rs"]
mod streamed;
