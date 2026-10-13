//! Fixed-factor planning versus the original scalar DAG and serial gate fold.

use std::cell::RefCell;

use super::*;
use crate::{
    prover::quotient::{BoundColumns, CompiledLookup},
    secret::SecretPolynomial,
};
use iroha_pasta::{Fp, Fq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

struct RecordedMask {
    bits: u64,
    visited: RefCell<Vec<usize>>,
}

impl ConstraintFilter for RecordedMask {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        let ConstraintTerm::Gate { polynomial } = term else {
            panic!("gate plan visited a non-gate term");
        };
        self.visited.borrow_mut().push(polynomial);
        (self.bits >> polynomial) & 1 != 0
    }
}

/// Every opcode, rotated fixed/advice/instance sources, repeated factors and
/// protected root consumers. Groups use a compound fixed-only factor; the
/// same factor crosses each chunk boundary and the unmodified tail.
fn fixture<F: PastaField>(count: usize) -> CompiledExpressions<F> {
    let mut expressions = CompiledExpressions {
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
            Node::Product(1, 5),
        ],
        gates: Vec::new(),
        lookups: Vec::new(),
        fixed_queries: Vec::new(),
        advice_queries: Vec::new(),
        instance_queries: Vec::new(),
    };
    for polynomial in 0..count {
        let inner = u32::try_from(expressions.nodes.len()).unwrap();
        expressions
            .nodes
            .push(Node::Scaled(11, F::from(polynomial as u64 + 2)));
        let root = u32::try_from(expressions.nodes.len()).unwrap();
        expressions.nodes.push(Node::Product(12, inner));
        expressions.gates.push(root);
    }
    if count >= 8 {
        // Root 2 is used directly by a lookup. Root 3 is used by another
        // retained DAG node. Root 5 is a repeated gate. None may disappear.
        let lookup_child = u32::try_from(expressions.nodes.len()).unwrap();
        expressions.nodes.push(Node::Sum(expressions.gates[3], 11));
        expressions.lookups.push(CompiledLookup {
            inputs: vec![expressions.gates[2], lookup_child, 9],
            tables: vec![12, expressions.gates[2]],
        });
        expressions.gates[6] = expressions.gates[5];
    }
    expressions
}

fn check<F: PastaField>() {
    const N: usize = 16;
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let column = SecretPolynomial::new((0..N).map(|_| F::random(&mut rng)).collect());
    let columns = BoundColumns {
        fixed: vec![(&column, 0), (&column, N - 1)],
        advice: vec![(&column, 1)],
        instance: vec![(&column, N - 2)],
        mask: N - 1,
    };
    let mut masks = vec![0, u64::MAX, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555];
    for _ in 0..12 {
        use rand_core_06::RngCore as _;
        masks.push(rng.next_u64());
    }
    for count in [0, 7, 8, 9, 15, 16, 17, 23, 24, 25] {
        let expressions = fixture::<F>(count);
        let before = expressions.clone();
        let plan = GatePlan::new(&expressions);
        assert_eq!(expressions, before, "ordinary evaluator remains unchanged");
        if count >= 8 {
            assert!(
                plan.compact.is_some(),
                "fixture must take the factored path"
            );
            assert!(plan.compiled().node_count() < expressions.node_count());
            assert_eq!(plan.roots.len(), count);
            assert_eq!(plan.chunks.len(), count / GROUP);
        } else {
            assert!(core::ptr::eq(plan.compiled(), &raw const expressions));
        }
        for width in [1, 4] {
            let mut compact =
                SecretPolynomial::new(vec![F::ZERO; plan.compiled().nodes.len() * width]);
            let mut original = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len()]);
            // Every starting row exercises wrapping reads, including the final
            // tile straddling the end of the input domain.
            for row in 0..N {
                plan.compiled()
                    .evaluate_tile(&columns, row, width, &mut compact);
                for lane in 0..width {
                    expressions.evaluate_row(&columns, row + lane, &mut original);
                    let actual = EvaluatedRow::new(&compact, width, lane);
                    let expected = EvaluatedRow::new(&original, 1, 0);
                    for (left, right) in plan.compiled().lookups.iter().zip(&expressions.lookups) {
                        for (a, b) in [(&left.inputs, &right.inputs), (&left.tables, &right.tables)]
                        {
                            assert_eq!(
                                CompiledExpressions::compress(a, actual, F::from(23)),
                                CompiledExpressions::compress(b, expected, F::from(23)),
                            );
                        }
                    }
                    for y in [F::ZERO, F::ONE, -F::ONE, F::from(19)] {
                        let fold = GateFold::new(y);
                        for &bits in &masks {
                            let filter = RecordedMask {
                                bits,
                                visited: RefCell::new(Vec::new()),
                            };
                            let expected = expressions.gates.iter().enumerate().fold(
                                F::ZERO,
                                |acc, (polynomial, &root)| {
                                    acc * y
                                        + if (bits >> polynomial) & 1 != 0 {
                                            original[root as usize]
                                        } else {
                                            F::ZERO
                                        }
                                },
                            );
                            assert_eq!(
                                plan.evaluate(&fold, actual, &filter),
                                expected,
                                "count={count}, row={row}, width={width}, lane={lane}, y={y:?}, mask={bits}"
                            );
                            assert_eq!(*filter.visited.borrow(), (0..count).collect::<Vec<_>>());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn factored_gates_preserve_filters_rotations_and_consumers_in_fp() {
    check::<Fp>();
}

#[test]
fn factored_gates_preserve_filters_rotations_and_consumers_in_fq() {
    check::<Fq>();
}

#[test]
fn planning_keeps_chunk_boundaries_tail_and_shared_roots() {
    let expressions = fixture::<Fp>(19);
    let plan = GatePlan::new(&expressions);
    assert!(plan.compact.is_some());
    assert_eq!(plan.chunks.len(), 2);
    // The repeated pair at positions 0,1 is removable. Positions 2,3 have
    // lookup/node consumers; 5,6 repeat a root. Their isolated neighbors stay
    // ordinary. The whole second chunk has one common factor.
    assert_eq!(plan.chunks[0].len(), 2);
    assert_eq!(plan.chunks[0][0].end, 2);
    assert!(plan.chunks[0][0].factor.is_some());
    assert_eq!(plan.chunks[0][1].end, 8);
    assert!(plan.chunks[0][1].factor.is_none());
    assert_eq!(plan.chunks[1].len(), 1);
    assert_eq!(plan.chunks[1][0].end, 8);
    assert!(plan.chunks[1][0].factor.is_some());
    assert_eq!(plan.roots[GROUP * 2..].len(), 3);
    for root in &plan.roots[GROUP * 2..] {
        assert!(matches!(
            plan.compiled().nodes[*root as usize],
            Node::Product(_, _)
        ));
    }
    // Ten grouped products disappear; one originally unused product and its inner (the
    // replaced repeated gate 6) are also unreachable from all retained roots.
    assert_eq!(expressions.node_count() - plan.compiled().node_count(), 12);
    assert_eq!(plan.compiled().lookups[0].inputs[0], plan.roots[2]);
    assert!(matches!(
        plan.compiled().nodes[plan.roots[3] as usize],
        Node::Product(_, _)
    ));
    assert_eq!(plan.roots[5], plan.roots[6]);
}

#[test]
fn ungrouped_and_lookup_only_plans_borrow_the_original_evaluator() {
    let mut expressions = fixture::<Fq>(19);
    let root = expressions.gates[0];
    expressions.gates.fill(root);
    let plan = GatePlan::new(&expressions);
    assert!(plan.compact.is_none());
    assert!(core::ptr::eq(plan.compiled(), &raw const expressions));
    expressions.gates.clear();
    let plan = GatePlan::new(&expressions);
    assert!(plan.compact.is_none());
    assert!(core::ptr::eq(plan.compiled(), &raw const expressions));
}
