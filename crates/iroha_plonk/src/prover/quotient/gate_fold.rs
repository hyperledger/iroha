//! Algebraically identical gate Horner folding in fixed groups of eight.
//!
//! Challenge powers are public and shared across rows. Grouping exposes independent
//! field products without changing gate exponents, filtered positions or proof bytes.

use super::{ConstraintFilter, ConstraintTerm, EvaluatedRow, PastaField};

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
