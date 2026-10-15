//! halo2 permuted lookup arguments (spec section 2, "Lookup").
//!
//! A lookup requires that, on every usable row, the tuple of input
//! expressions equals the tuple of table expressions on some usable row. The
//! prover commits the permuted columns `A'`, `S'` and the product `z`; this
//! module holds the argument description only.

use super::expression::Expression;

/// A lookup of input expressions into table expressions of equal width.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupArgument<F> {
    name: String,
    input_expressions: Vec<Expression<F>>,
    table_expressions: Vec<Expression<F>>,
}

impl<F> LookupArgument<F> {
    /// Creates a lookup from `(input, table)` pairs.
    pub fn new(name: impl AsRef<str>, table_map: Vec<(Expression<F>, Expression<F>)>) -> Self {
        let (input_expressions, table_expressions) = table_map.into_iter().unzip();
        Self {
            name: name.as_ref().to_owned(),
            input_expressions,
            table_expressions,
        }
    }

    /// The lookup name (diagnostics only).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The input expressions `a_0..a_{w-1}`.
    #[must_use]
    pub fn input_expressions(&self) -> &[Expression<F>] {
        &self.input_expressions
    }

    /// The table expressions `s_0..s_{w-1}`.
    #[must_use]
    pub fn table_expressions(&self) -> &[Expression<F>] {
        &self.table_expressions
    }

    /// The width `w` (number of input/table pairs).
    #[must_use]
    pub fn width(&self) -> usize {
        self.input_expressions.len()
    }

    /// The degree the lookup constraints need:
    /// `max(6, 2 + 2 max(1, deg a) + 2 max(1, deg s))`.
    #[must_use]
    pub fn required_degree(&self) -> usize {
        let input_degree = self
            .input_expressions
            .iter()
            .map(Expression::degree)
            .fold(1, usize::max);
        let table_degree = self
            .table_expressions
            .iter()
            .map(Expression::degree)
            .fold(1, usize::max);
        6.max(
            input_degree
                .saturating_add(table_degree)
                .saturating_mul(2)
                .saturating_add(2),
        )
    }

    /// Mutable access for selector substitution.
    pub(crate) fn expressions_mut(&mut self) -> (&mut Vec<Expression<F>>, &mut Vec<Expression<F>>) {
        (&mut self.input_expressions, &mut self.table_expressions)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;

    use super::*;
    use crate::cs::expression::{Advice, Column, Fixed};

    #[test]
    fn required_degree_accounts_for_norm_factors() {
        let a = Column::new(0, Advice).cur::<Fp>();
        let t = Column::new(0, Fixed).cur::<Fp>();
        let simple = LookupArgument::new("simple", vec![(a.clone(), t.clone())]);
        assert_eq!(simple.required_degree(), 6);
        assert_eq!(simple.width(), 1);
        assert_eq!(simple.name(), "simple");
        let quadratic = LookupArgument::new(
            "quadratic",
            vec![
                (a.clone() * a.clone(), t.clone()),
                (a.clone(), t.clone() * t.clone()),
            ],
        );
        assert_eq!(quadratic.required_degree(), 10);
        assert_eq!(quadratic.input_expressions().len(), 2);
        assert_eq!(quadratic.table_expressions()[1], t.clone() * t);
        let constant = LookupArgument::new(
            "constant",
            vec![(Expression::Constant(Fp::ONE), Expression::Constant(Fp::ONE))],
        );
        assert_eq!(constant.required_degree(), 6);
    }

    #[test]
    fn expressions_mut_allows_substitution() {
        let a = Column::new(0, Advice).cur::<Fp>();
        let mut lookup = LookupArgument::new("l", vec![(a.clone(), a)]);
        let (inputs, tables) = lookup.expressions_mut();
        inputs[0] = Expression::Constant(Fp::ZERO);
        tables[0] = Expression::Constant(Fp::ONE);
        assert_eq!(
            lookup.input_expressions()[0],
            Expression::Constant(Fp::ZERO)
        );
        assert_eq!(lookup.table_expressions()[0], Expression::Constant(Fp::ONE));
    }
}
