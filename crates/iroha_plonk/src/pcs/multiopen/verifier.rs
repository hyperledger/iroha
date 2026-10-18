//! The multiopen verifier (vendored `poly/ipa/multiopen/verifier.rs` with
//! static grouping).

use ff::Field;
use iroha_pasta::PastaCurve;

use super::{MultiopenError, OpeningPlan, PlannedQuery, ShapeItem};
use crate::{
    pcs::ipa::{
        commit::Msm,
        verifier::{PendingOpening, read_opening},
    },
    transcript::TranscriptRead,
};

/// The value at `x` of the polynomial of degree `< points.len()` through
/// `(points[j], evals[j])` (Lagrange form; the points are distinct).
pub(crate) fn interpolate_at<F: Field>(points: &[F], evals: &[F], x: F) -> F {
    let mut total = F::ZERO;
    for (j, (point_j, eval_j)) in points.iter().zip(evals).enumerate() {
        let mut numerator = F::ONE;
        let mut denominator = F::ONE;
        for (m, point_m) in points.iter().enumerate() {
            if m != j {
                numerator *= x - point_m;
                denominator *= *point_j - point_m;
            }
        }
        // Distinct points make every denominator invertible.
        total += *eval_j * numerator * denominator.invert().unwrap_or(F::ZERO);
    }
    total
}

/// Reads a multiopen proof for `plan` and returns the pending IPA opening.
///
/// - `points`: the opening point of each plan rotation (distinct);
/// - `commitments`: the commitment of each plan slot, as a linear combination
///   of points (for example `sum_i x^{n i} H_i` for the quotient);
/// - `evaluations`: the claimed evaluation of each query, in query order;
/// - `k`: `log2(n)` of the opened polynomials.
///
/// The caller accepts the returned opening with
/// [`PendingOpening::verify_full`] or turns it into an accumulator with
/// [`PendingOpening::accumulate`] (which is not an acceptance).
///
/// # Errors
///
/// [`MultiopenError::Shape`] or [`MultiopenError::PointCollision`] for inputs
/// that do not match the plan; [`MultiopenError::ConflictingEvaluations`] when
/// a repeated query claims a different evaluation (S3);
/// [`MultiopenError::DegenerateChallenge`] when `x_3` is in the polynomial domain or is an opening point;
/// [`MultiopenError::Ipa`] for transcript and IPA failures.
pub fn verify<C, T>(
    plan: &OpeningPlan,
    points: &[C::ScalarExt],
    commitments: &[Msm<C>],
    evaluations: &[C::ScalarExt],
    k: u32,
    transcript: &mut T,
) -> Result<PendingOpening<C>, MultiopenError>
where
    C: PastaCurve,
    T: TranscriptRead<C> + ?Sized,
{
    plan.check_points(points)?;
    OpeningPlan::check_len(ShapeItem::Slots, plan.slots().len(), commitments.len())?;
    OpeningPlan::check_len(
        ShapeItem::Evaluations,
        plan.queries().len(),
        evaluations.len(),
    )?;

    // Each slot's evaluations, ordered like its sorted points. A repeat must
    // be bit-identical to the first query (S3); it is never an overwrite.
    let mut slot_evals: Vec<Vec<C::ScalarExt>> = plan
        .slots()
        .iter()
        .map(|slot| vec![C::ScalarExt::ZERO; slot.points.len()])
        .collect();
    for (index, (query, eval)) in plan.queries().iter().zip(evaluations).enumerate() {
        match *query {
            PlannedQuery::First { slot, position } => slot_evals[slot][position] = *eval,
            PlannedQuery::Repeat { of } => {
                if evaluations[of] != *eval {
                    return Err(MultiopenError::ConflictingEvaluations { query: index });
                }
            }
        }
    }

    let x_1 = transcript.squeeze_challenge();
    let x_2 = transcript.squeeze_challenge();

    // Compress each set's slots with powers of x_1, walking the slots in
    // reverse so the first slot of a set carries the highest power.
    let sets = plan.sets();
    let mut set_commitments: Vec<(Msm<C>, C::ScalarExt)> =
        vec![(Msm::new(), C::ScalarExt::ONE); sets.len()];
    let mut set_evals: Vec<Vec<C::ScalarExt>> = sets
        .iter()
        .map(|set| vec![C::ScalarExt::ZERO; set.len()])
        .collect();
    for (slot_index, slot) in plan.slots().iter().enumerate().rev() {
        let (commitment, power) = &mut set_commitments[slot.set];
        let mut scaled = commitments[slot_index].clone();
        scaled.scale(power);
        commitment.add_msm(&scaled);
        for (total, eval) in set_evals[slot.set].iter_mut().zip(&slot_evals[slot_index]) {
            *total += *eval * *power;
        }
        *power *= x_1;
    }

    let q_prime = transcript.read_point()?;
    let x_3 = crate::transcript::pipa_r::multiopening_challenge(transcript.squeeze_challenge());
    super::regularity::validate_challenge(k, x_3, points)?;
    let mut q_evals = Vec::with_capacity(sets.len());
    for _ in sets {
        q_evals.push(transcript.read_scalar()?);
    }

    let mut msm_eval = C::ScalarExt::ZERO;
    for ((set, evals), q_eval) in sets.iter().zip(&set_evals).zip(&q_evals) {
        let set_points: Vec<C::ScalarExt> = set.iter().map(|index| points[*index]).collect();
        let mut denominator = C::ScalarExt::ONE;
        for point in &set_points {
            denominator *= x_3 - point;
        }
        let inverse = Option::<C::ScalarExt>::from(denominator.invert())
            .ok_or(MultiopenError::DegenerateChallenge)?;
        let r_eval = interpolate_at(&set_points, evals, x_3);
        msm_eval = msm_eval * x_2 + (*q_eval - r_eval) * inverse;
    }

    let x_4 = transcript.squeeze_challenge();
    let mut combined = Msm::from_point(q_prime);
    let mut value = msm_eval;
    for ((commitment, _), q_eval) in set_commitments.iter().zip(&q_evals) {
        combined.scale(&x_4);
        combined.add_msm(commitment);
        value = value * x_4 + q_eval;
    }
    Ok(read_opening(k, combined, transcript, &x_3, &value)?)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Fq;

    use super::*;

    #[test]
    fn interpolation_matches_the_polynomial() {
        // p(X) = 3 + 2X + X^2 through three points.
        let p = |x: Fq| Fq::from(3) + Fq::from(2) * x + x.square();
        let points = [Fq::from(1), Fq::from(4), Fq::from(9)];
        let evals: Vec<Fq> = points.iter().map(|x| p(*x)).collect();
        for x in [Fq::from(0), Fq::from(5), Fq::from(100)] {
            assert_eq!(interpolate_at(&points, &evals, x), p(x));
        }
        assert_eq!(
            interpolate_at(&[Fq::from(2)], &[Fq::from(7)], Fq::from(5)),
            Fq::from(7)
        );
    }
}
