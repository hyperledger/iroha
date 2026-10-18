//! Static-slot multiopen and complete succinct IPA equation.

use super::*;
use iroha_plonk::{
    pcs::multiopen::{PlannedQuery, SlotKind},
    protocol::RoundSide,
};

impl<C: PastaCurve> VerifierChip<C> {
    fn identity(
        &mut self,
        region: &mut Region<'_, C::Base>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        self.ecc.constant_point(region, &C::identity())
    }
    fn add_scaled(
        &mut self,
        region: &mut Region<'_, C::Base>,
        sum: &AssignedPoint<C::Base>,
        point: &AssignedPoint<C::Base>,
        scalar: &Scalar<C>,
    ) -> Result<AssignedPoint<C::Base>, Error> {
        let scaled = self.scale_point(region, point, scalar)?;
        self.ecc.add(region, sum, &scaled)
    }
    // This helper consumes the private transcript reader, whose X is the
    // constrained nonzero map. It must not accept an arbitrary scalar X.
    fn rotated_opening_points(
        &mut self,
        region: &mut Region<'_, C::Base>,
        read: &Read<C>,
        k: u32,
        rotations: &[i32],
        valid: &mut Bit<C::Base>,
    ) -> Result<Vec<Scalar<C>>, Error> {
        let x = read.challenge(Challenge::X)?;
        let omega = iroha_plonk::protocol::omega::<C::ScalarExt>(k).ok_or(Error::Synthesis)?;
        let omega_inverse = Option::<C::ScalarExt>::from(omega.invert()).ok_or(Error::Synthesis)?;
        let factors = rotations
            .iter()
            .map(|rotation| {
                if *rotation >= 0 { omega } else { omega_inverse }
                    .pow_vartime([u64::from(rotation.unsigned_abs())])
            })
            .collect::<Vec<_>>();
        let mut points = Vec::with_capacity(factors.len());
        for factor in &factors {
            let factor = self.constant(region, *factor)?;
            points.push(self.mul(region, &x, &factor)?);
        }
        // Equality is checked on actual field coefficients, so negative and
        // congruent rotations (r and r + 2^k) retain the same collision verdict.
        // Every point above is constrained to nonzero X times its coefficient;
        // therefore two points coincide exactly when their coefficients do.
        let distinct = factors
            .iter()
            .enumerate()
            .all(|(i, factor)| factors[..i].iter().all(|other| factor != other));
        let distinct_cell = self.glue.boolean(region, Value::known(distinct))?;
        self.glue.enforce_constant(
            region,
            distinct_cell.word(),
            C::Base::from(u64::from(distinct)),
        )?;
        self.combine(region, valid, &distinct_cell)?;
        Ok(points)
    }
    fn interpolate(
        &mut self,
        region: &mut Region<'_, C::Base>,
        points: &[Scalar<C>],
        values: &[Scalar<C>],
        x: &Scalar<C>,
        valid: &mut Bit<C::Base>,
    ) -> Result<Scalar<C>, Error> {
        let mut out = self.constant(region, C::ScalarExt::ZERO)?;
        for (j, point) in points.iter().enumerate() {
            let mut numerator = self.constant(region, C::ScalarExt::ONE)?;
            let mut denominator = numerator.clone();
            for (m, other) in points.iter().enumerate() {
                if j == m {
                    continue;
                }
                let difference = self.sub(region, x, other)?;
                numerator = self.mul(region, &numerator, &difference)?;
                let difference = self.sub(region, point, other)?;
                denominator = self.mul(region, &denominator, &difference)?;
            }
            let inverse = self.inverse(region, &denominator, valid)?;
            let contribution = self.mul(region, &numerator, &inverse)?;
            let contribution = self.mul(region, &contribution, &values[j])?;
            out = self.add(region, &out, &contribution)?;
        }
        Ok(out)
    }
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::many_single_char_names
    )]
    pub(super) fn opening_equation(
        &mut self,
        region: &mut Region<'_, C::Base>,
        plan: &VerifierPlan<C>,
        key: &VerifierKeyCells<C>,
        read: &Read<C>,
        evaluations: &[Scalar<C>],
        xn: &Scalar<C>,
        valid: &mut Bit<C::Base>,
    ) -> Result<Bit<C::Base>, Error> {
        let opening = plan.protocol.plan();
        if evaluations.len() != opening.queries().len() {
            return Err(Error::Synthesis);
        }
        let points =
            self.rotated_opening_points(region, read, plan.params.k(), opening.rotations(), valid)?;
        let zero = self.constant(region, C::ScalarExt::ZERO)?;
        let one = self.constant(region, C::ScalarExt::ONE)?;
        let mut slot_evals: Vec<Vec<Scalar<C>>> = opening
            .slots()
            .iter()
            .map(|slot| vec![zero.clone(); slot.points.len()])
            .collect();
        for (index, (query, evaluation)) in opening.queries().iter().zip(evaluations).enumerate() {
            match *query {
                PlannedQuery::First { slot, position } => {
                    slot_evals[slot][position] = evaluation.clone()
                }
                PlannedQuery::Repeat { of } => {
                    if of >= index {
                        return Err(Error::Synthesis);
                    }
                    let equal = self.arithmetic.equal(
                        &mut UintChip::new(&mut self.glue, &mut self.range),
                        region,
                        &evaluations[of],
                        evaluation,
                    )?;
                    self.combine(region, valid, &equal)?;
                }
            }
        }
        let mut h = self.identity(region)?;
        for (step, index) in (0..plan.protocol.shape().quotient_pieces).rev().enumerate() {
            let piece = read.point(ProofMessage::QuotientPiece(index))?;
            h = if step == 0 {
                // The initial accumulator is the circuit-fixed identity.
                piece
            } else {
                let scaled = self.scale_point(region, &h, xn)?;
                self.ecc.add(region, &scaled, &piece)?
            };
        }
        let x1 = read.challenge(Challenge::X1)?;
        let x2 = read.challenge(Challenge::X2)?;
        let x3 = read.challenge(Challenge::X3)?;
        let x4 = read.challenge(Challenge::X4)?;
        let identity = self.identity(region)?;
        let mut commitments = vec![identity; opening.sets().len()];
        let mut initialized = vec![false; opening.sets().len()];
        let mut set_values: Vec<Vec<Vec<Scalar<C>>>> = opening
            .sets()
            .iter()
            .map(|set| vec![Vec::new(); set.len()])
            .collect();
        // Each static set is a Horner fold in original slot order: the first
        // slot has the highest x1 exponent, exactly as the native reverse MSM.
        for (index, slot) in opening.slots().iter().enumerate() {
            let at = slot.slot.index as usize;
            let point = match slot.slot.kind {
                SlotKind::Instance => return Err(Error::Synthesis),
                SlotKind::Advice => read.point(ProofMessage::AdviceCommitment(at))?,
                SlotKind::Fixed => key.fixed.get(at).ok_or(Error::Synthesis)?.point().clone(),
                SlotKind::PermutationSigma => key
                    .permutation
                    .get(at)
                    .ok_or(Error::Synthesis)?
                    .point()
                    .clone(),
                SlotKind::PermutationProduct => read.point(ProofMessage::PermutationProduct(at))?,
                SlotKind::LookupProduct => read.point(ProofMessage::LookupProduct(at))?,
                SlotKind::LookupPermutedInput => {
                    read.point(ProofMessage::LookupPermutedInput(at))?
                }
                SlotKind::LookupPermutedTable => {
                    read.point(ProofMessage::LookupPermutedTable(at))?
                }
                SlotKind::Vanishing => h.clone(),
                SlotKind::Random => read.point(ProofMessage::Random)?,
            };
            commitments[slot.set] = if initialized[slot.set] {
                let scaled = self.scale_point(region, &commitments[slot.set], &x1)?;
                self.ecc.add(region, &scaled, &point)?
            } else {
                // Static source-slot order, independent of commitment values.
                initialized[slot.set] = true;
                point
            };
            for (values, evaluation) in set_values[slot.set].iter_mut().zip(&slot_evals[index]) {
                values.push(evaluation.clone());
            }
        }
        let set_evals = set_values
            .iter()
            .map(|set| {
                set.iter()
                    .map(|values| self.horner(region, values, &x1))
                    .collect::<Result<Vec<_>, Error>>()
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut value = zero;
        let mut q_evals = Vec::new();
        for (index, set) in opening.sets().iter().enumerate() {
            let set_points: Vec<_> = set.iter().map(|at| points[*at].clone()).collect();
            let mut denominator = one.clone();
            for point in &set_points {
                let difference = self.sub(region, &x3, point)?;
                denominator = self.mul(region, &denominator, &difference)?;
            }
            // Reader-owned X3 is square/nonquartic, while every rotated
            // reader-owned X is nonsquare (all admitted roots are fourth
            // powers). Thus this product is nonzero for every transcript.
            // Keep its complete multiplicative inverse equation.
            let inverse = self.arithmetic.ff.inverse(region, &denominator)?;
            let interpolated =
                self.interpolate(region, &set_points, &set_evals[index], &x3, valid)?;
            let q_eval = read.scalar(ProofMessage::PointSetEval(index))?;
            let difference = self.sub(region, &q_eval, &interpolated)?;
            let contribution = self.mul(region, &difference, &inverse)?;
            value = self.mul(region, &value, &x2)?;
            value = self.add(region, &value, &contribution)?;
            q_evals.push(q_eval);
        }
        let mut combined = read.point(ProofMessage::MultiopenQuotient)?;
        for (commitment, q_eval) in commitments.iter().zip(&q_evals) {
            combined = self.scale_point(region, &combined, &x4)?;
            combined = self.ecc.add(region, &combined, commitment)?;
            value = self.mul(region, &value, &x4)?;
            value = self.add(region, &value, q_eval)?;
        }
        // Xi is the reader-owned canonical nz challenge.
        // P + xi*S + sum(u^-1 L + u R) - v*g0 - c*b*z*U - f*W - c*G.
        combined = self.add_scaled(
            region,
            &combined,
            &read.point(ProofMessage::IpaCommitment)?,
            &read.challenge(Challenge::Xi)?,
        )?;
        let mut b = one.clone();
        let mut power = x3;
        for round in (0..plan.params.k() as usize).rev() {
            let challenge = read.challenge(Challenge::Round(round))?;
            // The private reader constrained this exact actual round to nz(a).
            // Keep generic denominator inverses guarded; this path cannot be zero.
            let inverse = self.arithmetic.ff.inverse(region, &challenge)?;
            let left = read.point(ProofMessage::IpaRound {
                round,
                side: RoundSide::Left,
            })?;
            let right = read.point(ProofMessage::IpaRound {
                round,
                side: RoundSide::Right,
            })?;
            combined = self.add_scaled(region, &combined, &left, &inverse)?;
            combined = self.add_scaled(region, &combined, &right, &challenge)?;
            let term = self.mul(region, &challenge, &power)?;
            let term = self.add(region, &one, &term)?;
            b = self.mul(region, &b, &term)?;
            if round != 0 {
                power = self.mul(region, &power, &power)?;
            }
        }
        // X3 is the exact reader-owned square/nonquartic map, outside H.
        let c = read.scalar(ProofMessage::IpaC)?;
        let f = read.scalar(ProofMessage::IpaF)?;
        let mut u_scalar = self.mul(region, &c, &b)?;
        u_scalar = self.mul(region, &u_scalar, &read.challenge(Challenge::ZetaIpa)?)?;
        for (scalar, base) in [
            (value, plan.params.params().g()[0]),
            (u_scalar, plan.params.params().u()),
            (f, plan.params.params().w()),
        ] {
            let scalar = self.neg(region, &scalar)?;
            let base = self.ecc.constant_point(region, &base.to_curve())?;
            combined = self.add_scaled(region, &combined, &base, &scalar)?;
        }
        let neg_c = self.neg(region, &c)?;
        let suffix = read.suffix.as_ref().ok_or(Error::Synthesis)?;
        combined = self.add_scaled(region, &combined, suffix.point(), &neg_c)?;
        EccChip::<C>::is_identity(&mut self.glue, region, &combined)
    }
}

#[cfg(test)]
mod tests;
