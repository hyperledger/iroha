//! Exact port of halo2 selector compression (`compress_selectors::plan` and
//! `process` in vendor/halo2-axiom), spec section 2.
//!
//! The plan fixes how many fixed columns selectors occupy and in which order,
//! so it determines the fixed commitments and therefore the verifying-key
//! bytes. Every step, including iteration order and tie-breaking, follows the
//! vendored code:
//!
//! 1. each selector with `max_degree = 0` (complex or unused) becomes a
//!    singleton combination, in index order;
//! 2. simple selectors `i` and `j < i` exclude each other when they share an
//!    active row;
//! 3. each simple selector not yet added, in index order, starts a combination
//!    with `t = deg - 1`, then scans later simple selectors in order: stop when
//!    `t + |comb| == D`; skip a selector that is added, excluded by a member, or
//!    would need `max(t, deg - 1) + |comb| + 1 > D`; otherwise add it.
//!
//! Member `j` (1-based) of combination `c` is assigned root `j`: the
//! combination column holds `j` on that member's rows, and the member's
//! selector is replaced by `q * prod_{r != j} (r - q)`, built left to right as
//! `Product(acc, Sum(Constant(r), Negated(q)))`.

use core::fmt;

use iroha_pasta::PastaField;

use super::expression::Expression;

/// A selector and the rows it is active on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorDescription<'a> {
    /// The selector index.
    pub selector: usize,
    /// Activation per row; every description has the same length.
    pub activations: &'a [bool],
    /// The maximum degree of a gate polynomial whose simple selector this is
    /// (0 for complex and unused selectors).
    pub max_degree: usize,
}

/// Where a selector went and what replaces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorAssignment<F> {
    /// The selector index.
    pub selector: usize,
    /// The combination (new fixed column, in creation order).
    pub combination_index: usize,
    /// The 1-based root this selector's rows hold in the combination column.
    pub root: usize,
    /// The expression substituted for the selector.
    pub expression: Expression<F>,
}

/// Selector compression could not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionError {
    /// The caller cancelled selector finalization.
    Cancelled,
    /// A selector's activation vector differs in length from the first one.
    ActivationLength {
        /// The selector index.
        selector: usize,
        /// The length of the first activation vector.
        expected: usize,
        /// This selector's length.
        found: usize,
    },
    /// A simple selector's gate degree exceeds the circuit degree.
    DegreeExceedsCircuit {
        /// The selector index.
        selector: usize,
        /// The selector's gate degree.
        degree: usize,
        /// The circuit degree.
        max_degree: usize,
    },
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("selector compression cancelled"),
            Self::ActivationLength {
                selector,
                expected,
                found,
            } => write!(
                f,
                "selector {selector} has {found} activation rows, expected {expected}"
            ),
            Self::DegreeExceedsCircuit {
                selector,
                degree,
                max_degree,
            } => write!(
                f,
                "selector {selector} gates degree {degree}, above the circuit degree {max_degree}"
            ),
        }
    }
}

impl std::error::Error for CompressionError {}
impl From<iroha_pasta::Cancelled> for CompressionError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

/// The combination plan: each inner vector lists indices into `selectors`
/// in member order.
///
/// # Errors
///
/// [`CompressionError`] on unequal activation lengths or a selector degree
/// above `max_degree` (the vendored code asserts both).
pub fn plan(
    selectors: &[SelectorDescription<'_>],
    max_degree: usize,
) -> Result<Vec<Vec<usize>>, CompressionError> {
    plan_cancellable(selectors, max_degree, None)
}

/// Plan selectors with bounded scans of activation rows.
///
/// # Errors
/// As [`plan`], or [`CompressionError::Cancelled`].
pub fn plan_cancellable(
    selectors: &[SelectorDescription<'_>],
    max_degree: usize,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<Vec<Vec<usize>>, CompressionError> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let Some(first) = selectors.first() else {
        return Ok(Vec::new());
    };
    let n = first.activations.len();
    for selector in selectors {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        if selector.activations.len() != n {
            return Err(CompressionError::ActivationLength {
                selector: selector.selector,
                expected: n,
                found: selector.activations.len(),
            });
        }
    }

    // Complex (and unused) selectors cannot share a column.
    let mut combinations: Vec<Vec<usize>> = selectors
        .iter()
        .enumerate()
        .filter(|(_, selector)| selector.max_degree == 0)
        .map(|(index, _)| vec![index])
        .collect();
    let simple: Vec<usize> = selectors
        .iter()
        .enumerate()
        .filter_map(|(index, selector)| (selector.max_degree != 0).then_some(index))
        .collect();

    // Lower-triangular exclusion matrix: two selectors active on one row
    // cannot share a fixed column.
    let mut exclusion: Vec<Vec<bool>> = (0..simple.len())
        .map(|i| {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            Ok(vec![false; i])
        })
        .collect::<Result<_, CompressionError>>()?;
    for (i, &selector_index) in simple.iter().enumerate() {
        let rows = selectors[selector_index].activations;
        for (j, &other_index) in simple.iter().enumerate().take(i) {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            for (index, (left, right)) in rows
                .iter()
                .zip(selectors[other_index].activations)
                .enumerate()
            {
                if index % 1024 == 0 {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                }
                if *left && *right {
                    exclusion[i][j] = true;
                    break;
                }
            }
        }
    }

    let mut added = vec![false; simple.len()];
    for (i, &selector_index) in simple.iter().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        if added[i] {
            continue;
        }
        added[i] = true;
        let selector = &selectors[selector_index];
        if selector.max_degree > max_degree {
            return Err(CompressionError::DegreeExceedsCircuit {
                selector: selector.selector,
                degree: selector.max_degree,
                max_degree,
            });
        }
        // The virtual selector's own degree is replaced by the combination.
        let mut d = selector.max_degree - 1;
        let mut combination = vec![selector_index];
        let mut combination_added = vec![i];

        'candidates: for (j, &candidate_index) in simple.iter().enumerate().skip(i + 1) {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            if d + combination.len() == max_degree {
                break 'candidates;
            }
            if added[j] {
                continue 'candidates;
            }
            for &member in &combination_added {
                if exclusion[j][member] {
                    continue 'candidates;
                }
            }
            let candidate = &selectors[candidate_index];
            let new_d = d.max(candidate.max_degree - 1);
            if new_d + combination.len() + 1 > max_degree {
                continue 'candidates;
            }
            d = new_d;
            combination.push(candidate_index);
            combination_added.push(j);
            added[j] = true;
        }
        combinations.push(combination);
    }
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(combinations)
}

/// The output of [`process`]: the combination columns and the assignments.
pub type ProcessOutput<F> = (Vec<Vec<F>>, Vec<SelectorAssignment<F>>);

/// Runs the plan, allocating one fixed column per combination through
/// `allocate_fixed_column` (which returns the column's rotation-0 query), and
/// returns each combination column's values and every selector's assignment
/// in combination/member order.
///
/// # Errors
///
/// See [`plan`].
pub fn process<F: PastaField>(
    selectors: &[SelectorDescription<'_>],
    max_degree: usize,
    allocate_fixed_column: impl FnMut() -> Expression<F>,
) -> Result<ProcessOutput<F>, CompressionError> {
    process_cancellable(selectors, max_degree, allocate_fixed_column, None)
}

/// Finalize selector columns with caller-owned cancellation.
///
/// # Errors
/// As [`process`], or [`CompressionError::Cancelled`].
pub fn process_cancellable<F: PastaField>(
    selectors: &[SelectorDescription<'_>],
    max_degree: usize,
    mut allocate_fixed_column: impl FnMut() -> Expression<F>,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<ProcessOutput<F>, CompressionError> {
    let combinations = plan_cancellable(selectors, max_degree, cancellation)?;
    let n = selectors
        .first()
        .map_or(0, |selector| selector.activations.len());
    let mut columns = Vec::with_capacity(combinations.len());
    let mut assignments = Vec::with_capacity(selectors.len());
    for (combination_index, combination) in combinations.iter().enumerate() {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let mut column = vec![F::ZERO; n];
        let query = allocate_fixed_column();
        let mut assigned_root = F::ONE;
        for (member, &selector_index) in combination.iter().enumerate() {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            let selector = &selectors[selector_index];
            // q * prod_{r != assigned_root} (r - q), in root order.
            let mut expression = query.clone();
            let mut root = F::ONE;
            for _ in 0..combination.len() {
                if root != assigned_root {
                    expression = expression * (Expression::Constant(root) - query.clone());
                }
                root += F::ONE;
            }
            // Members of one combination are disjoint, so no row is written twice.
            for (index, (value, active)) in column.iter_mut().zip(selector.activations).enumerate()
            {
                if index % 1024 == 0 {
                    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
                }
                if *active {
                    *value = assigned_root;
                }
            }
            assigned_root += F::ONE;
            assignments.push(SelectorAssignment {
                selector: selector.selector,
                combination_index,
                root: member + 1,
                expression,
            });
        }
        columns.push(column);
    }
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok((columns, assignments))
}

#[cfg(test)]
mod tests {

    #[test]
    fn cancellation_during_selector_allocation_returns_no_partial_columns() {
        use iroha_pasta::CancellationToken;
        let rows = rows(&[&[0, 2], &[1, 3]], 4096);
        let selectors = describe(&rows, &[2, 2]);
        let token = CancellationToken::new();
        let mut allocated = 0;
        let result = process_cancellable::<Fp>(
            &selectors,
            4,
            || {
                allocated += 1;
                token.cancel();
                Expression::Constant(Fp::ONE)
            },
            Some(&token),
        );
        assert_eq!(allocated, 1);
        assert_eq!(result, Err(CompressionError::Cancelled));
        assert_eq!(
            plan_cancellable(&selectors, 4, Some(&token)),
            Err(CompressionError::Cancelled)
        );
        let fresh = CancellationToken::new();
        assert_eq!(
            process_cancellable::<Fp>(
                &selectors,
                4,
                || Expression::Constant(Fp::ONE),
                Some(&fresh)
            ),
            process::<Fp>(&selectors, 4, || Expression::Constant(Fp::ONE)),
        );
    }

    use ff::Field;
    use iroha_pasta::Fp;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::{RngCore, SeedableRng};

    use super::*;
    use crate::cs::expression::{Column, Fixed};

    fn describe<'a>(rows: &'a [Vec<bool>], degrees: &[usize]) -> Vec<SelectorDescription<'a>> {
        rows.iter()
            .zip(degrees)
            .enumerate()
            .map(
                |(selector, (activations, max_degree))| SelectorDescription {
                    selector,
                    activations,
                    max_degree: *max_degree,
                },
            )
            .collect()
    }

    fn rows(pattern: &[&[usize]], n: usize) -> Vec<Vec<bool>> {
        pattern
            .iter()
            .map(|active| (0..n).map(|row| active.contains(&row)).collect())
            .collect()
    }

    #[test]
    fn empty_plan() {
        assert_eq!(plan(&[], 3), Ok(vec![]));
        let (columns, assignments) =
            process::<Fp>(&[], 3, || Expression::Constant(Fp::ZERO)).expect("empty");
        assert!(columns.is_empty() && assignments.is_empty());
    }

    #[test]
    fn complex_selectors_come_first_as_singletons() {
        let rows = rows(&[&[0], &[1], &[2], &[3]], 4);
        // Selectors 1 and 3 are complex (degree 0).
        let selectors = describe(&rows, &[2, 0, 2, 0]);
        assert_eq!(plan(&selectors, 4), Ok(vec![vec![1], vec![3], vec![0, 2]]));
    }

    #[test]
    fn overlapping_selectors_never_share() {
        let rows = rows(&[&[0, 1], &[1, 2], &[3]], 4);
        let selectors = describe(&rows, &[1, 1, 1]);
        // 0 and 1 overlap on row 1; 0 and 2 combine; 1 starts its own.
        assert_eq!(plan(&selectors, 5), Ok(vec![vec![0, 2], vec![1]]));
    }

    #[test]
    fn degree_budget_bounds_combinations() {
        let rows = rows(&[&[0], &[1], &[2], &[3]], 4);
        // Degree-3 gates in a degree-4 circuit: t = 2, so 2 members at most.
        let selectors = describe(&rows, &[3, 3, 3, 3]);
        assert_eq!(plan(&selectors, 4), Ok(vec![vec![0, 1], vec![2, 3]]));
        // A degree-4 selector stays alone: t + 1 = D.
        let selectors = describe(&rows, &[4, 1, 1, 1]);
        assert_eq!(plan(&selectors, 4), Ok(vec![vec![0], vec![1, 2, 3]]));
        // A later high-degree candidate is skipped, not a stop.
        let selectors = describe(&rows, &[1, 4, 1, 1]);
        assert_eq!(plan(&selectors, 4), Ok(vec![vec![0, 2, 3], vec![1]]));
    }

    #[test]
    fn plan_errors() {
        let mut rows = rows(&[&[0], &[1]], 4);
        rows[1].pop();
        let selectors = describe(&rows, &[1, 1]);
        assert_eq!(
            plan(&selectors, 3),
            Err(CompressionError::ActivationLength {
                selector: 1,
                expected: 4,
                found: 3
            })
        );
        let rows = super::tests::rows(&[&[0]], 4);
        let selectors = describe(&rows, &[5]);
        let error = plan(&selectors, 4).expect_err("degree too high");
        assert_eq!(
            error,
            CompressionError::DegreeExceedsCircuit {
                selector: 0,
                degree: 5,
                max_degree: 4
            }
        );
        assert!(!error.to_string().is_empty());
        assert!(
            !CompressionError::ActivationLength {
                selector: 0,
                expected: 1,
                found: 2
            }
            .to_string()
            .is_empty()
        );
    }

    #[test]
    fn process_assigns_roots_and_expressions() {
        let rows = rows(&[&[0], &[1], &[2]], 4);
        let selectors = describe(&rows, &[1, 1, 1]);
        let mut next_column = 10;
        let (columns, assignments) = process::<Fp>(&selectors, 4, || {
            let column = Column::new(next_column, Fixed).cur();
            next_column += 1;
            column
        })
        .expect("plan");
        assert_eq!(next_column, 11, "one combination");
        assert_eq!(
            columns,
            vec![vec![Fp::from(1), Fp::from(2), Fp::from(3), Fp::ZERO]]
        );
        let q = Column::new(10, Fixed).cur::<Fp>();
        let factor = |root: u64| Expression::Constant(Fp::from(root)) - q.clone();
        let expected = [
            q.clone() * factor(2) * factor(3),
            q.clone() * factor(1) * factor(3),
            q.clone() * factor(1) * factor(2),
        ];
        for (index, assignment) in assignments.iter().enumerate() {
            assert_eq!(assignment.selector, index);
            assert_eq!(assignment.combination_index, 0);
            assert_eq!(assignment.root, index + 1);
            assert_eq!(assignment.expression, expected[index]);
        }
    }

    /// Evaluates a substituted selector expression at a column value.
    fn evaluate(expression: &Expression<Fp>, q: Fp) -> Fp {
        match expression {
            Expression::Constant(c) => *c,
            Expression::Fixed(_) => q,
            Expression::Negated(inner) => -evaluate(inner, q),
            Expression::Sum(a, b) => evaluate(a, q) + evaluate(b, q),
            Expression::Product(a, b) => evaluate(a, q) * evaluate(b, q),
            other => panic!("unexpected node {other:?}"),
        }
    }

    #[test]
    fn substituted_selectors_vanish_exactly_off_their_rows() {
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        for _ in 0..50 {
            let n = 16;
            let count = 1 + (rng.next_u32() % 6) as usize;
            let rows: Vec<Vec<bool>> = (0..count)
                .map(|_| (0..n).map(|_| rng.next_u32() % 4 == 0).collect())
                .collect();
            let degrees: Vec<usize> = (0..count).map(|_| (rng.next_u32() % 4) as usize).collect();
            let max_degree = 4;
            let selectors = describe(&rows, &degrees);
            let mut allocated = 0;
            let (columns, assignments) = process::<Fp>(&selectors, max_degree, || {
                allocated += 1;
                Column::new(allocated - 1, Fixed).cur()
            })
            .expect("plan");
            assert_eq!(columns.len(), allocated);
            assert_eq!(assignments.len(), count);
            for assignment in &assignments {
                let column = &columns[assignment.combination_index];
                assert!(assignment.expression.degree() <= max_degree);
                for row in 0..n {
                    let value = evaluate(&assignment.expression, column[row]);
                    assert_eq!(
                        value.is_zero_vartime(),
                        !rows[assignment.selector][row],
                        "selector {} row {row}",
                        assignment.selector
                    );
                }
            }
        }
    }
}
