//! Algebraically identical gate Horner folding in fixed groups of eight.
//!
//! Challenge powers are public and shared across rows. Grouping exposes independent
//! field products without changing gate exponents, filtered positions or proof bytes.

use super::{
    CompiledExpressions, ConstraintFilter, ConstraintTerm, EvaluatedRow, Node, PastaField,
};

const GROUP: usize = 8;

/// Public challenge powers; no witness values are retained between rows.
pub(super) struct GateFold<F> {
    powers: [F; GROUP + 1],
}

impl<F: PastaField> GateFold<F> {
    pub(super) fn new(y: F) -> Self {
        let mut powers = [F::ONE; GROUP + 1];
        for index in 1..powers.len() {
            powers[index] = powers[index - 1] * y;
        }
        Self { powers }
    }

    /// Fold the same ordered gate terms as the serial Horner recurrence.
    pub(super) fn evaluate(
        &self,
        roots: &[u32],
        values: EvaluatedRow<'_, F>,
        filter: &impl ConstraintFilter,
    ) -> F {
        let mut value = F::ZERO;
        let mut groups = roots.chunks_exact(GROUP);
        for (group, roots) in groups.by_ref().enumerate() {
            let mut sum = F::ZERO;
            for (offset, root) in roots.iter().enumerate() {
                // Read every root, including omitted constraints, just as the
                // original caller evaluated the contribution before filtering.
                let contribution = values[*root as usize];
                let contribution = if filter.keeps(ConstraintTerm::Gate {
                    polynomial: group * GROUP + offset,
                }) {
                    contribution
                } else {
                    F::ZERO
                };
                sum += if offset + 1 == GROUP {
                    contribution
                } else {
                    contribution * self.powers[GROUP - 1 - offset]
                };
            }
            value = value * self.powers[GROUP] + sum;
        }
        let remaining = groups.remainder();
        let start = roots.len() - remaining.len();
        for (offset, root) in remaining.iter().enumerate() {
            let contribution = values[*root as usize];
            value = value * self.powers[1]
                + if filter.keeps(ConstraintTerm::Gate {
                    polynomial: start + offset,
                }) {
                    contribution
                } else {
                    F::ZERO
                };
        }
        value
    }
}

#[cfg(test)]
mod tests;

/// Consecutive contributions inside one original eight-root chunk. A common
/// fixed factor is applied once after the weighted inner contributions.
struct GateRun {
    end: usize,
    factor: Option<u32>,
}

/// Quotient-only live DAG and gate schedule. The public per-gate evaluator and
/// lookup-only compilation retain the original DAG and roots. The optional
/// compact representation is selected once per row, never once per DAG node.
pub(super) struct GatePlan<'a, F> {
    original: &'a CompiledExpressions<F>,
    compact: Option<CompiledExpressions<F>>,
    // Roots name the inner operand of factored gates and the complete value of
    // every other gate. A tail is never factored or regrouped.
    roots: Vec<u32>,
    chunks: Vec<Vec<GateRun>>,
}

fn operands<F>(node: &Node<F>, mut visit: impl FnMut(u32)) {
    match *node {
        Node::Negated(a) | Node::Doubled(a) | Node::Squared(a) | Node::Scaled(a, _) => visit(a),
        Node::Sum(a, b) | Node::Product(a, b) => {
            visit(a);
            visit(b);
        }
        Node::Constant(_) | Node::Fixed(_) | Node::Advice(_) | Node::Instance(_) => {}
    }
}

fn remap_node<F: Copy>(node: Node<F>, remap: &[u32]) -> Node<F> {
    match node {
        Node::Negated(a) => Node::Negated(remap[a as usize]),
        Node::Doubled(a) => Node::Doubled(remap[a as usize]),
        Node::Squared(a) => Node::Squared(remap[a as usize]),
        Node::Scaled(a, factor) => Node::Scaled(remap[a as usize], factor),
        Node::Sum(a, b) => Node::Sum(remap[a as usize], remap[b as usize]),
        Node::Product(a, b) => Node::Product(remap[a as usize], remap[b as usize]),
        other => other,
    }
}

impl<'a, F: PastaField> GatePlan<'a, F> {
    pub(super) fn new(original: &'a CompiledExpressions<F>) -> Self {
        let mut plan = Self {
            original,
            compact: None,
            roots: Vec::new(),
            chunks: Vec::new(),
        };
        if original.gates.len() < GROUP {
            return plan;
        }
        let mut fixed = vec![false; original.nodes.len()];
        let mut shared = vec![false; original.nodes.len()];
        for (index, node) in original.nodes.iter().enumerate() {
            let mut public = !matches!(node, Node::Advice(_) | Node::Instance(_));
            operands(node, |operand| {
                public &= fixed[operand as usize];
                shared[operand as usize] = true;
            });
            fixed[index] = public;
        }
        for lookup in &original.lookups {
            for &root in lookup.inputs.iter().chain(&lookup.tables) {
                shared[root as usize] = true;
            }
        }
        let mut seen = vec![false; original.nodes.len()];
        for &root in &original.gates {
            if seen[root as usize] {
                shared[root as usize] = true;
            }
            seen[root as usize] = true;
        }
        // Only factor a product that can actually disappear from the live DAG.
        // Roots consumed by another gate, lookup or node stay ordinary.
        let candidate = |root: u32| {
            if shared[root as usize] {
                return None;
            }
            let Node::Product(a, b) = original.nodes[root as usize] else {
                return None;
            };
            match (fixed[a as usize], fixed[b as usize]) {
                (true, false) => Some((a, b)),
                (false, true) => Some((b, a)),
                _ => None,
            }
        };
        plan.roots.clone_from(&original.gates);
        let mut any = false;
        for (group, roots) in original.gates.chunks_exact(GROUP).enumerate() {
            let mut runs = Vec::new();
            let mut start = 0;
            while start < GROUP {
                let mut end = start + 1;
                let factor = candidate(roots[start]).and_then(|(factor, _)| {
                    while end < GROUP
                        && candidate(roots[end]).is_some_and(|(other, _)| other == factor)
                    {
                        end += 1;
                    }
                    (end - start >= 2).then_some(factor)
                });
                if factor.is_some() {
                    for (offset, &root) in roots.iter().enumerate().take(end).skip(start) {
                        // All members passed the same candidate check above.
                        plan.roots[group * GROUP + offset] = candidate(root)
                            .expect("planned factor run contains only candidate products")
                            .1;
                    }
                    any = true;
                }
                // Merge adjacent ordinary terms into one dispatch. Runtime
                // branching is per public run, not per node or contribution.
                if factor.is_none()
                    && let Some(GateRun {
                        end: previous,
                        factor: None,
                    }) = runs.last_mut()
                {
                    *previous = end;
                } else {
                    runs.push(GateRun { end, factor });
                }
                start = end;
            }
            plan.chunks.push(runs);
        }
        if !any {
            plan.roots.clear();
            plan.chunks.clear();
            return plan;
        }
        let mut live = vec![false; original.nodes.len()];
        for &root in &plan.roots {
            live[root as usize] = true;
        }
        for run in plan.chunks.iter().flatten() {
            if let Some(factor) = run.factor {
                live[factor as usize] = true;
            }
        }
        for lookup in &original.lookups {
            for &root in lookup.inputs.iter().chain(&lookup.tables) {
                live[root as usize] = true;
            }
        }
        // All operands precede their consumer. A reverse walk retains the
        // transitive closure of every gate input, factor, tail and lookup root.
        for index in (0..original.nodes.len()).rev() {
            if live[index] {
                operands(&original.nodes[index], |operand| {
                    live[operand as usize] = true
                });
            }
        }
        let mut remap = vec![u32::MAX; original.nodes.len()];
        let mut nodes = Vec::with_capacity(live.iter().filter(|&&value| value).count());
        for (index, &node) in original.nodes.iter().enumerate() {
            if live[index] {
                remap[index] = u32::try_from(nodes.len())
                    .expect("compact DAG cannot exceed original u32 indices");
                nodes.push(remap_node(node, &remap));
            }
        }
        for root in &mut plan.roots {
            *root = remap[*root as usize];
        }
        for run in plan.chunks.iter_mut().flatten() {
            if let Some(factor) = &mut run.factor {
                *factor = remap[*factor as usize];
            }
        }
        let mut lookups = original.lookups.clone();
        for lookup in &mut lookups {
            for root in lookup.inputs.iter_mut().chain(&mut lookup.tables) {
                *root = remap[*root as usize];
            }
        }
        // Gate roots belong to this plan, so the private compact evaluator is
        // deliberately not a complete per-gate evaluator.
        plan.compact = Some(CompiledExpressions {
            nodes,
            gates: Vec::new(),
            lookups,
            fixed_queries: original.fixed_queries.clone(),
            advice_queries: original.advice_queries.clone(),
            instance_queries: original.instance_queries.clone(),
        });
        plan
    }

    pub(super) fn compiled(&self) -> &CompiledExpressions<F> {
        self.compact.as_ref().unwrap_or(self.original)
    }

    pub(super) fn evaluate(
        &self,
        fold: &GateFold<F>,
        values: EvaluatedRow<'_, F>,
        filter: &impl ConstraintFilter,
    ) -> F {
        if self.compact.is_none() {
            return fold.evaluate(&self.original.gates, values, filter);
        }
        let mut value = F::ZERO;
        for (group, runs) in self.chunks.iter().enumerate() {
            let mut sum = F::ZERO;
            let mut start = 0;
            for run in runs {
                let mut weighted = F::ZERO;
                for offset in start..run.end {
                    let polynomial = group * GROUP + offset;
                    let contribution = values[self.roots[polynomial] as usize];
                    let contribution = if filter.keeps(ConstraintTerm::Gate { polynomial }) {
                        contribution
                    } else {
                        F::ZERO
                    };
                    weighted += if offset + 1 == GROUP {
                        contribution
                    } else {
                        contribution * fold.powers[GROUP - 1 - offset]
                    };
                }
                sum += run
                    .factor
                    .map_or(weighted, |factor| values[factor as usize] * weighted);
                start = run.end;
            }
            value = value * fold.powers[GROUP] + sum;
        }
        let start = self.chunks.len() * GROUP;
        for (offset, &root) in self.roots[start..].iter().enumerate() {
            let contribution = values[root as usize];
            value = value * fold.powers[1]
                + if filter.keeps(ConstraintTerm::Gate {
                    polynomial: start + offset,
                }) {
                    contribution
                } else {
                    F::ZERO
                };
        }
        value
    }
}

#[cfg(test)]
mod factor_tests;
