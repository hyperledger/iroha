//! Both-field arithmetic, root ordering and bounded scratch-admission regressions.

use super::*;
use crate::secret::SecretPolynomial;
use ff::Field as _;
use iroha_pasta::{Fp, Fq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

fn expressions<F: PastaField>() -> CompiledExpressions<F> {
    CompiledExpressions {
        nodes: vec![
            Node::Constant(F::from(9)),
            Node::Fixed(0),
            Node::Fixed(1),
            Node::Advice(0),
            Node::Instance(0),
            Node::Negated(2),
            Node::Doubled(3),
            Node::Squared(4),
            Node::Sum(5, 6),
            Node::Product(7, 8),
            Node::Scaled(9, -F::from(17)),
            Node::Sum(0, 10),
        ],
        gates: (0..12).collect(),
        lookups: Vec::new(),
        fixed_queries: Vec::new(),
        advice_queries: Vec::new(),
        instance_queries: Vec::new(),
    }
}

fn check_nodes<F: PastaField>() {
    let expressions = expressions::<F>();
    let mut rng = ChaCha20Rng::from_seed([0x7a; 32]);
    for n in [1, 2, 4, 8, 256, 512] {
        let values = SecretPolynomial::new((0..n).map(|_| F::random(&mut rng)).collect());
        let columns = BoundColumns {
            fixed: vec![(&values, 0), (&values, n - 1)],
            advice: vec![(&values, 1 & (n - 1))],
            instance: vec![(&values, n.wrapping_sub(2) & (n - 1))],
            mask: n - 1,
        };
        for width in [1, TILE_ROWS] {
            let mut tiled = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len() * width]);
            let mut scalar = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len()]);
            // Start at every row, including tiles crossing the rotation wrap.
            for row in 0..n {
                expressions.evaluate_tile(&columns, row, width, &mut tiled);
                for lane in 0..width {
                    expressions.evaluate_row(&columns, row + lane, &mut scalar);
                    let view = EvaluatedRow::new(&tiled, width, lane);
                    for (node, expected) in scalar.iter().enumerate() {
                        assert_eq!(view[node], *expected);
                    }
                    let roots = [11, 4, 0, 11, 6];
                    let expected = roots.iter().fold(F::ZERO, |value, &root| {
                        value * F::from(23) + scalar[root as usize]
                    });
                    assert_eq!(
                        CompiledExpressions::compress(&roots, view, F::from(23)),
                        expected,
                    );
                }
            }
        }
    }
}

#[test]
fn tiled_nodes_and_ordered_roots_match_scalar_on_both_fields() {
    check_nodes::<Fp>();
    check_nodes::<Fq>();
}

fn check_columns<F: PastaField>() {
    let expressions = expressions::<F>();
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
            assert_eq!(rayon::current_num_threads(), workers);
            for n in [1, 2, 4, 256, 512] {
                let values: Vec<_> = (0..n).map(|i| F::from(i as u64 + 1)).collect();
                let columns = BoundColumns {
                    fixed: vec![(&values, 0), (&values, n - 1)],
                    advice: vec![(&values, 1 & (n - 1))],
                    instance: vec![(&values, n.wrapping_sub(2) & (n - 1))],
                    mask: n - 1,
                };
                let roots = [11, 0, 9];
                let outputs = expressions.evaluate_columns(
                    &columns,
                    n,
                    roots.len(),
                    |row, out| {
                        for (value, root) in out.iter_mut().zip(roots) {
                            *value = row[root];
                        }
                    },
                    None,
                );
                let mut scratch = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len()]);
                for row in 0..n {
                    expressions.evaluate_row(&columns, row, &mut scratch);
                    for (output, root) in outputs.iter().zip(roots) {
                        assert_eq!(output[row], scratch[root]);
                    }
                }
            }
        });
    }
}

#[test]
fn column_dispatch_matches_scalar_on_one_and_four_workers() {
    check_columns::<Fp>();
    check_columns::<Fq>();
}

#[test]
fn scratch_expansion_planning_checks_overflow_workers_and_ceiling() {
    assert_eq!(expansion_bytes::<Fp>(23, 512, 4), Some(23 * 3 * 2 * 32));
    assert_eq!(expansion_bytes::<Fq>(23, 256, 4), Some(23 * 3 * 32));
    for (nodes, rows, workers) in [
        (0, 4, 1),
        (23, 2, 1),
        (23, 4, 0),
        (usize::MAX, 4, 1),
        (EXPANSION_LIMIT, 4, 1),
    ] {
        assert_eq!(expansion_bytes::<Fp>(nodes, rows, workers), None);
    }
    let nodes = EXPANSION_LIMIT / (3 * 32);
    assert!(expansion_bytes::<Fp>(nodes, 4, 1).is_some());
    assert_eq!(expansion_bytes::<Fp>(nodes + 1, 4, 1), None);
}

#[test]
fn contended_plan_falls_back_without_waiting_or_leaking() {
    let budget = SharedMemoryBudget::new(0);
    let plan = TilePlan::with_budget::<Fp>(12, 512, 4, &budget);
    assert_eq!(plan.width, 1);
    assert!(matches!(
        plan,
        TilePlan {
            _reservation: None,
            ..
        }
    ));
    assert_eq!(budget.in_use_bytes(), 0);
    drop(plan);
    assert_eq!(budget.in_use_bytes(), 0);
}

#[test]
fn reservation_releases_after_normal_return_and_unwind() {
    let budget = SharedMemoryBudget::new(EXPANSION_LIMIT);
    {
        let plan = TilePlan::with_budget::<Fq>(12, 512, 4, &budget);
        // Other proof tests may occupy the process ceiling; either admitted
        // tiling or immediate scalar fallback is a valid concurrent result.
        assert_eq!(
            budget.in_use_bytes(),
            if plan.width == TILE_ROWS {
                12 * 3 * 2 * 32
            } else {
                0
            }
        );
    }
    assert_eq!(budget.in_use_bytes(), 0);
    let result = std::panic::catch_unwind(|| {
        let _plan = TilePlan::with_budget::<Fq>(12, 512, 4, &budget);
        let _scratch = SecretPolynomial::new(vec![Fq::ONE; 12 * TILE_ROWS]);
        panic!("injected kernel unwind");
    });
    assert!(result.is_err());
    assert_eq!(budget.in_use_bytes(), 0);
}
