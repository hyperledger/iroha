//! Scalar PLONK relation evaluation from the engine's S11 tables.

use super::*;
use iroha_plonk::{
    cs::{
        ProtocolDescriptor,
        descriptor::{ColumnKindV1, ExprNodeV1, ExprV1},
    },
    protocol::{ConstraintTerm, LookupAt, LookupConstraint, PermutationAt},
};

// Only unsigned products are deferred. Negation materializes its operand,
// then uses the ordinary bounded subtraction path; no signed CRT admission
// or distribution across a product of sums is inferred.
enum PendingTerm<C: PastaCurve> {
    Value(Scalar<C>),
    Product(Scalar<C>, Scalar<C>),
}

struct Evaluations<'a, C: PastaCurve> {
    read: &'a Read<C>,
    instances: &'a [Scalar<C>],
    first: Scalar<C>,
    last: Scalar<C>,
    active: Scalar<C>,
    x: Scalar<C>,
    theta: Scalar<C>,
    beta: Scalar<C>,
    gamma: Scalar<C>,
}

impl<C: PastaCurve> VerifierChip<C> {
    fn expression(
        &mut self,
        region: &mut Region<'_, C::Base>,
        expression: &ExprV1,
        read: &Read<C>,
        instances: &[Scalar<C>],
    ) -> Result<Scalar<C>, Error> {
        if self.arithmetic.ff.config().is_none() {
            return self.expression_batched(region, expression, read, instances);
        }
        let mut stack = Vec::new();
        for node in expression {
            let value = match node {
                ExprNodeV1::Constant(bytes) => self.constant(
                    region,
                    Option::from(C::ScalarExt::from_repr(*bytes)).ok_or(Error::Synthesis)?,
                )?,
                ExprNodeV1::Fixed(index) => {
                    read.scalar(ProofMessage::FixedEval(*index as usize))?
                }
                ExprNodeV1::Advice(index) => {
                    read.scalar(ProofMessage::AdviceEval(*index as usize))?
                }
                ExprNodeV1::Instance(index) => instances
                    .get(*index as usize)
                    .ok_or(Error::Synthesis)?
                    .clone(),
                ExprNodeV1::Negated => {
                    let value = stack.pop().ok_or(Error::Synthesis)?;
                    self.neg(region, &value)?
                }
                ExprNodeV1::Sum | ExprNodeV1::Product => {
                    let right = stack.pop().ok_or(Error::Synthesis)?;
                    let left = stack.pop().ok_or(Error::Synthesis)?;
                    if matches!(node, ExprNodeV1::Sum) {
                        self.add(region, &left, &right)?
                    } else {
                        self.mul(region, &left, &right)?
                    }
                }
                ExprNodeV1::Scaled(bytes) => {
                    let value = stack.pop().ok_or(Error::Synthesis)?;
                    let scalar = self.constant(
                        region,
                        Option::from(C::ScalarExt::from_repr(*bytes)).ok_or(Error::Synthesis)?,
                    )?;
                    self.mul(region, &value, &scalar)?
                }
            };
            stack.push(value);
        }
        if stack.len() != 1 {
            return Err(Error::Synthesis);
        }
        stack.pop().ok_or(Error::Synthesis)
    }
    fn materialize_terms(
        &mut self,
        region: &mut Region<'_, C::Base>,
        terms: Vec<PendingTerm<C>>,
    ) -> Result<Scalar<C>, Error> {
        let mut sum = self.constant(region, C::ScalarExt::ZERO)?;
        let mut products = Vec::new();
        for term in terms {
            match term {
                PendingTerm::Value(value) => sum = self.add(region, &sum, &value)?,
                PendingTerm::Product(left, right) => products.push((left, right)),
            }
        }
        for chunk in products.chunks(8) {
            let pairs = chunk
                .iter()
                .map(|(left, right)| (left, right))
                .collect::<Vec<_>>();
            let value = self.arithmetic.dot(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                region,
                &pairs,
            )?;
            sum = self.add(region, &sum, &value)?;
        }
        Ok(sum)
    }

    fn expression_batched(
        &mut self,
        region: &mut Region<'_, C::Base>,
        expression: &ExprV1,
        read: &Read<C>,
        instances: &[Scalar<C>],
    ) -> Result<Scalar<C>, Error> {
        let mut stack: Vec<Vec<PendingTerm<C>>> = Vec::new();
        for node in expression {
            let terms = match node {
                ExprNodeV1::Constant(bytes) => vec![PendingTerm::Value(self.constant(
                    region,
                    Option::from(C::ScalarExt::from_repr(*bytes)).ok_or(Error::Synthesis)?,
                )?)],
                ExprNodeV1::Fixed(index) => vec![PendingTerm::Value(
                    read.scalar(ProofMessage::FixedEval(*index as usize))?,
                )],
                ExprNodeV1::Advice(index) => vec![PendingTerm::Value(
                    read.scalar(ProofMessage::AdviceEval(*index as usize))?,
                )],
                ExprNodeV1::Instance(index) => vec![PendingTerm::Value(
                    instances
                        .get(*index as usize)
                        .ok_or(Error::Synthesis)?
                        .clone(),
                )],
                ExprNodeV1::Sum => {
                    let right = stack.pop().ok_or(Error::Synthesis)?;
                    let mut left = stack.pop().ok_or(Error::Synthesis)?;
                    left.extend(right);
                    left
                }
                ExprNodeV1::Product => {
                    let right = stack.pop().ok_or(Error::Synthesis)?;
                    let left = stack.pop().ok_or(Error::Synthesis)?;
                    let left = self.materialize_terms(region, left)?;
                    let right = self.materialize_terms(region, right)?;
                    vec![PendingTerm::Product(left, right)]
                }
                ExprNodeV1::Negated => {
                    let terms = stack.pop().ok_or(Error::Synthesis)?;
                    let value = self.materialize_terms(region, terms)?;
                    vec![PendingTerm::Value(self.neg(region, &value)?)]
                }
                ExprNodeV1::Scaled(bytes) => {
                    let terms = stack.pop().ok_or(Error::Synthesis)?;
                    let value = self.materialize_terms(region, terms)?;
                    let scale = self.constant(
                        region,
                        Option::from(C::ScalarExt::from_repr(*bytes)).ok_or(Error::Synthesis)?,
                    )?;
                    vec![PendingTerm::Product(value, scale)]
                }
            };
            stack.push(terms);
        }
        if stack.len() != 1 {
            return Err(Error::Synthesis);
        }
        self.materialize_terms(region, stack.pop().ok_or(Error::Synthesis)?)
    }

    fn compress(
        &mut self,
        region: &mut Region<'_, C::Base>,
        expressions: &[ExprV1],
        evals: &Evaluations<'_, C>,
    ) -> Result<Scalar<C>, Error> {
        let mut out = self.constant(region, C::ScalarExt::ZERO)?;
        for expression in expressions {
            let value = self.expression(region, expression, evals.read, evals.instances)?;
            out = self.mul(region, &out, &evals.theta)?;
            out = self.add(region, &out, &value)?;
        }
        Ok(out)
    }
    fn column(
        read: &Read<C>,
        instances: &[Scalar<C>],
        kind: ColumnKindV1,
        index: usize,
    ) -> Result<Scalar<C>, Error> {
        match kind {
            ColumnKindV1::Advice => read.scalar(ProofMessage::AdviceEval(index)),
            ColumnKindV1::Fixed => read.scalar(ProofMessage::FixedEval(index)),
            ColumnKindV1::Instance => instances.get(index).cloned().ok_or(Error::Synthesis),
        }
    }
    fn term(
        &mut self,
        region: &mut Region<'_, C::Base>,
        descriptor: &ProtocolDescriptor,
        protocol: &Protocol,
        evals: &Evaluations<'_, C>,
        term: ConstraintTerm,
    ) -> Result<Scalar<C>, Error> {
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let perm = |set, at| evals.read.scalar(ProofMessage::PermutationEval { set, at });
        match term {
            ConstraintTerm::Gate { polynomial } => {
                let expression = descriptor
                    .gates
                    .iter()
                    .flatten()
                    .nth(polynomial)
                    .ok_or(Error::Synthesis)?;
                self.expression(region, expression, evals.read, evals.instances)
            }
            ConstraintTerm::PermutationFirst => {
                let difference = self.sub(region, &one, &perm(0, PermutationAt::Current)?)?;
                self.mul(region, &evals.first, &difference)
            }
            ConstraintTerm::PermutationLast => {
                let last = perm(
                    protocol.shape().permutation_sets - 1,
                    PermutationAt::Current,
                )?;
                let square = self.mul(region, &last, &last)?;
                let difference = self.sub(region, &square, &last)?;
                self.mul(region, &evals.last, &difference)
            }
            ConstraintTerm::PermutationLink { set } => {
                let difference = self.sub(
                    region,
                    &perm(set, PermutationAt::Current)?,
                    &perm(set - 1, PermutationAt::Last)?,
                )?;
                self.mul(region, &evals.first, &difference)
            }
            ConstraintTerm::PermutationProduct { set } => {
                let chunk = protocol.shape().chunk_len;
                let first = set * chunk;
                let columns = protocol
                    .permutation_columns()
                    .chunks(chunk)
                    .nth(set)
                    .ok_or(Error::Synthesis)?;
                let delta_power =
                    self.constant(region, C::ScalarExt::DELTA.pow_vartime([first as u64]))?;
                let mut delta = self.mul(region, &evals.beta, &evals.x)?;
                delta = self.mul(region, &delta, &delta_power)?;
                let delta_step = self.constant(region, C::ScalarExt::DELTA)?;
                let mut left = perm(set, PermutationAt::Next)?;
                let mut right = perm(set, PermutationAt::Current)?;
                for (offset, column) in columns.iter().enumerate() {
                    let value =
                        Self::column(evals.read, evals.instances, column.kind, column.query)?;
                    let sigma = evals.read.scalar(ProofMessage::SigmaEval(first + offset))?;
                    let beta_sigma = self.mul(region, &evals.beta, &sigma)?;
                    let left_factor = self.add(region, &value, &beta_sigma)?;
                    let left_factor = self.add(region, &left_factor, &evals.gamma)?;
                    left = self.mul(region, &left, &left_factor)?;
                    let right_factor = self.add(region, &value, &delta)?;
                    let right_factor = self.add(region, &right_factor, &evals.gamma)?;
                    right = self.mul(region, &right, &right_factor)?;
                    delta = self.mul(region, &delta, &delta_step)?;
                }
                let difference = self.sub(region, &left, &right)?;
                self.mul(region, &difference, &evals.active)
            }
            ConstraintTerm::Lookup { lookup, part } => {
                let value = |at| evals.read.scalar(ProofMessage::LookupEval { lookup, at });
                let product = value(LookupAt::Product)?;
                let input = value(LookupAt::Input)?;
                let table = value(LookupAt::Table)?;
                match part {
                    LookupConstraint::First => {
                        let difference = self.sub(region, &one, &product)?;
                        self.mul(region, &evals.first, &difference)
                    }
                    LookupConstraint::Last => {
                        let square = self.mul(region, &product, &product)?;
                        let difference = self.sub(region, &square, &product)?;
                        self.mul(region, &evals.last, &difference)
                    }
                    LookupConstraint::Product => {
                        let argument = descriptor.lookups.get(lookup).ok_or(Error::Synthesis)?;
                        let original_input = self.compress(region, &argument.inputs, evals)?;
                        let original_table = self.compress(region, &argument.tables, evals)?;
                        let input_factor = self.add(region, &input, &evals.beta)?;
                        let table_factor = self.add(region, &table, &evals.gamma)?;
                        let left =
                            self.mul(region, &value(LookupAt::ProductNext)?, &input_factor)?;
                        let left = self.mul(region, &left, &table_factor)?;
                        let input_factor = self.add(region, &original_input, &evals.beta)?;
                        let table_factor = self.add(region, &original_table, &evals.gamma)?;
                        let right = self.mul(region, &product, &input_factor)?;
                        let right = self.mul(region, &right, &table_factor)?;
                        let difference = self.sub(region, &left, &right)?;
                        self.mul(region, &difference, &evals.active)
                    }
                    LookupConstraint::Start => {
                        let difference = self.sub(region, &input, &table)?;
                        self.mul(region, &difference, &evals.first)
                    }
                    LookupConstraint::Step => {
                        let left = self.sub(region, &input, &table)?;
                        let right = self.sub(region, &input, &value(LookupAt::InputPrevious)?)?;
                        let difference = self.mul(region, &left, &right)?;
                        self.mul(region, &difference, &evals.active)
                    }
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn lagrange_weight(
        &mut self,
        region: &mut Region<'_, C::Base>,
        k: u32,
        index: usize,
        x: &Scalar<C>,
        vanishing_nonzero: &Bit<C::Base>,
        cache: &mut std::collections::BTreeMap<usize, Scalar<C>>,
    ) -> Result<Scalar<C>, Error> {
        if let Some(value) = cache.get(&index) {
            return Ok(value.clone());
        }
        let omega = iroha_plonk::protocol::omega::<C::ScalarExt>(k).ok_or(Error::Synthesis)?;
        let power = self.constant(region, omega.pow_vartime([index as u64]))?;
        let denominator = self.sub(region, x, &power)?;
        // The caller binds guard = [x^n != 1]. Every omega^i is an nth
        // root of unity, so a true guard proves this denominator nonzero.
        // A false guard forces inverse=0, making even 0/0 total while the
        // global verifier verdict remains false. This narrowly replaces
        // repeated canonical zero tests, not the generic inverse predicate.
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let zero = self.constant(region, C::ScalarExt::ZERO)?;
        let numerator = self.arithmetic.select(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            vanishing_nonzero,
            &one,
            &zero,
        )?;
        let inverse = self.arithmetic.ff.div(region, &numerator, &denominator)?;
        for limb in inverse.limbs() {
            let selected =
                self.glue
                    .select_constant(region, vanishing_nonzero, limb, C::Base::ZERO)?;
            GlueChip::assert_equal(region, limb, &selected)?;
        }
        let value = self.mul(region, &power, &inverse)?;
        cache.insert(index, value.clone());
        Ok(value)
    }
    pub(super) fn constraint_evaluations(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &VerifierPlan<C>,
        read: &Read<C>,
        instance_values: &[Vec<Scalar<C>>],
        valid: &mut Bit<C::Base>,
    ) -> Result<(Vec<Scalar<C>>, Scalar<C>), Error> {
        let protocol = &plan.protocol;
        let shape = protocol.shape();
        let descriptor = plan.binding.descriptor();
        let x = read.challenge(Challenge::X)?;
        let xn = self.pow(region, &x, shape.n as u64)?;
        let nonzero = self.nonzero(region, &x)?;
        self.combine(region, valid, &nonzero)?;
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let denominator = self.sub(region, &xn, &one)?;
        let (vanishing_inverse, vanishing_nonzero) = self.arithmetic.inverse(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &denominator,
        )?;
        self.combine(region, valid, &vanishing_nonzero)?;
        // L_i(x) = common * omega^i/(x-omega^i). The denominator validity
        // guard follows from the separately checked x^n-1 nonzero bit. Its
        // false branch forces all weights to zero and the verdict false.
        let inv_n = self.constant(
            region,
            C::ScalarExt::TWO_INV.pow_vartime([u64::from(shape.k)]),
        )?;
        let common = self.mul(region, &denominator, &inv_n)?;
        let mut basis = std::collections::BTreeMap::new();
        let mut instances = Vec::new();
        for query in &descriptor.instance_queries {
            let mut pairs = Vec::new();
            for (row, input) in instance_values
                .get(query.column as usize)
                .ok_or(Error::Synthesis)?
                .iter()
                .enumerate()
            {
                let index = usize::try_from(
                    (i64::try_from(row).map_err(|_| Error::BoundsFailure)?
                        - i64::from(query.rotation))
                    .rem_euclid(i64::try_from(shape.n).map_err(|_| Error::BoundsFailure)?),
                )
                .map_err(|_| Error::BoundsFailure)?;
                let weight = self.lagrange_weight(
                    region,
                    shape.k,
                    index,
                    &x,
                    &vanishing_nonzero,
                    &mut basis,
                )?;
                pairs.push((input.clone(), weight));
            }
            let mut value = self.constant(region, C::ScalarExt::ZERO)?;
            for chunk in pairs.chunks(8) {
                let pairs = chunk
                    .iter()
                    .map(|(input, weight)| (input, weight))
                    .collect::<Vec<_>>();
                let contribution = self.arithmetic.dot(
                    &mut UintChip::new(&mut self.glue, &mut self.range),
                    region,
                    &pairs,
                )?;
                value = self.add(region, &value, &contribution)?;
            }
            instances.push(self.mul(region, &common, &value)?);
        }
        let first = self.lagrange_weight(region, shape.k, 0, &x, &vanishing_nonzero, &mut basis)?;
        let first = self.mul(region, &common, &first)?;
        let last = self.lagrange_weight(
            region,
            shape.k,
            shape.usable_rows,
            &x,
            &vanishing_nonzero,
            &mut basis,
        )?;
        let last = self.mul(region, &common, &last)?;
        let mut blind = self.constant(region, C::ScalarExt::ZERO)?;
        for index in shape.usable_rows + 1..shape.n {
            let value =
                self.lagrange_weight(region, shape.k, index, &x, &vanishing_nonzero, &mut basis)?;
            blind = self.add(region, &blind, &value)?;
        }
        let blind = self.mul(region, &common, &blind)?;
        let masked = self.add(region, &last, &blind)?;
        let active = self.sub(region, &one, &masked)?;
        let evals = Evaluations {
            read,
            instances: &instances,
            first,
            last,
            active,
            x,
            theta: read.challenge(Challenge::Theta)?,
            beta: read.challenge(Challenge::Beta)?,
            gamma: read.challenge(Challenge::Gamma)?,
        };
        let y = read.challenge(Challenge::Y)?;
        let mut terms = Vec::new();
        for term in protocol.constraint_terms() {
            terms.push(self.term(region, descriptor, protocol, &evals, *term)?);
        }
        let expected = self.horner(region, &terms, &y)?;
        let expected_h = self.mul(region, &expected, &vanishing_inverse)?;
        let mut evaluations = Vec::new();
        for index in 0..shape.advice_queries {
            evaluations.push(read.scalar(ProofMessage::AdviceEval(index))?);
        }
        for set in 0..shape.permutation_sets {
            for at in [PermutationAt::Current, PermutationAt::Next] {
                evaluations.push(read.scalar(ProofMessage::PermutationEval { set, at })?);
            }
        }
        for set in (0..shape.permutation_sets).rev().skip(1) {
            evaluations.push(read.scalar(ProofMessage::PermutationEval {
                set,
                at: PermutationAt::Last,
            })?);
        }
        for lookup in 0..shape.lookups {
            for at in [
                LookupAt::Product,
                LookupAt::Input,
                LookupAt::Table,
                LookupAt::InputPrevious,
                LookupAt::ProductNext,
            ] {
                evaluations.push(read.scalar(ProofMessage::LookupEval { lookup, at })?);
            }
        }
        for index in 0..shape.fixed_queries {
            evaluations.push(read.scalar(ProofMessage::FixedEval(index))?);
        }
        for index in 0..shape.permutation_columns {
            evaluations.push(read.scalar(ProofMessage::SigmaEval(index))?);
        }
        evaluations.push(expected_h);
        evaluations.push(read.scalar(ProofMessage::RandomEval)?);
        Ok((evaluations, xn))
    }
}

#[cfg(test)]
mod tests;
