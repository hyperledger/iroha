//! The multiopen prover (vendored `poly/ipa/multiopen/prover.rs` with static
//! grouping).
//!
//! Each set polynomial `q_t` is rebuilt when it is needed (three passes), as
//! in the vendored prover, so memory does not grow with the number of sets.
//! RNG draws: the `q'` blind, then the IPA's (`BlindingScheduleV1` items 7
//! and 8).

use crate::secret::SecretPolynomial;
use ff::Field;
use iroha_pasta::CancellationToken;
use iroha_pasta::{PastaCurve, msm::MemoryBudget, params::ParamsIpa};
use rand_core_06::{CryptoRng, RngCore};
use rayon::prelude::*;

use super::{MultiopenError, OpeningPlan, ShapeItem};
use crate::{
    pcs::ipa::{
        commit::{Secrecy, commit_cancellable},
        evaluate_polynomial,
        prover::create_proof_with_claim_cancellable as ipa_create_proof,
    },
    transcript::TranscriptWrite,
};

/// A slot's polynomial: `n` coefficients and the blind of its commitment.
#[derive(Clone, Copy, Debug)]
pub struct SlotPolynomial<'a, F> {
    /// The coefficients (exactly `n`).
    pub coeffs: &'a [F],
    /// The commitment blind.
    pub blind: F,
}

/// `acc <- acc * challenge + addend`, coefficient-wise.
#[cfg(test)]
fn fold_into<F: Field>(acc: &mut [F], challenge: F, addend: &[F]) {
    fold_into_cancellable(acc, challenge, addend, None).unwrap();
}
fn fold_into_cancellable<F: Field>(
    acc: &mut [F],
    challenge: F,
    addend: &[F],
    cancellation: Option<&CancellationToken>,
) -> Result<(), iroha_pasta::Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    if acc.len().min(addend.len()) >= 4096 && rayon::current_num_threads() > 1 {
        acc.par_chunks_mut(1024)
            .zip(addend.par_chunks(1024))
            .for_each(|(acc, addend)| {
                if !cancellation.is_some_and(CancellationToken::is_cancelled) {
                    fold_serial(acc, challenge, addend);
                }
            });
    } else {
        for (acc, addend) in acc.chunks_mut(1024).zip(addend.chunks(1024)) {
            CancellationToken::checkpoint(cancellation)?;
            fold_serial(acc, challenge, addend);
        }
    }
    CancellationToken::checkpoint(cancellation)
}

/// One sequential coefficient block; each coefficient keeps its Horner order.
fn fold_serial<F: Field>(acc: &mut [F], challenge: F, addend: &[F]) {
    for (value, add) in acc.iter_mut().zip(addend) {
        *value = *value * challenge + add;
    }
}

/// Divides by `X - point` in place, dropping the remainder (the vendored
/// Kate-division recurrence); the result has one coefficient fewer.
pub(crate) fn divide_by_linear<F: iroha_pasta::PastaField>(values: &mut Vec<F>, point: F) {
    let Some(mut original) = values.last().copied() else {
        return;
    };
    let b = -point;
    let mut carry = F::ZERO;
    for index in (0..values.len() - 1).rev() {
        let next_original = values[index];
        let lead = original - carry;
        values[index] = lead;
        carry = lead * b;
        original = next_original;
    }
    if let Some(last) = values.last_mut() {
        last.zeroize();
    }
    values.pop();
}

/// The set polynomial `q_t = sum_{slots in t} x_1^e p_slot` (Horner in slot
/// order) and its blind.
fn reconstruct_cancellable<F: iroha_pasta::PastaField>(
    plan: &OpeningPlan,
    polys: &[SlotPolynomial<'_, F>],
    set: usize,
    x_1: F,
    n: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(Vec<F>, F), iroha_pasta::Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    let mut q = SecretPolynomial::new(vec![F::ZERO; n]);
    let matching = || {
        plan.slots()
            .iter()
            .zip(polys)
            .filter(|(slot, _)| slot.set == set)
            .map(|(_, poly)| poly)
    };
    if n >= 4096 && rayon::current_num_threads() > 1 {
        // One parallel launch per set, not per slot. Each task walks the
        // original slot order over its disjoint coefficient block. The
        // three reconstruction passes still retain only one set polynomial.
        q.par_chunks_mut(1024)
            .enumerate()
            .for_each(|(chunk, values)| {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return;
                }
                let start = chunk * 1024;
                let end = start + values.len();
                for poly in matching() {
                    if cancellation.is_some_and(CancellationToken::is_cancelled) {
                        return;
                    }
                    fold_serial(values, x_1, &poly.coeffs[start..end]);
                }
            });
    } else {
        for poly in matching() {
            fold_into_cancellable(&mut q, x_1, poly.coeffs, cancellation)?;
        }
    }
    let blind = matching().fold(F::ZERO, |blind, poly| blind * x_1 + poly.blind);
    CancellationToken::checkpoint(cancellation)?;
    Ok((q.into_vec(), blind))
}

#[cfg(test)]
fn reconstruct<F: iroha_pasta::PastaField>(
    plan: &OpeningPlan,
    polys: &[SlotPolynomial<'_, F>],
    set: usize,
    x_1: F,
    n: usize,
) -> (Vec<F>, F) {
    reconstruct_cancellable(plan, polys, set, x_1, n, None).unwrap()
}

/// Writes a multiopen proof for `plan` and returns the folded generator of
/// the final IPA.
///
/// - `points`: the opening point of each plan rotation (distinct);
/// - `polys`: each plan slot's polynomial (exactly `n` coefficients) and
///   blind.
///
/// # Errors
///
/// [`MultiopenError::Shape`] or [`MultiopenError::PointCollision`] for inputs
/// that do not match the plan; [`MultiopenError::Ipa`] for MSM, transcript
/// or IPA failures.
pub fn create_proof<C, T, R>(
    params: &ParamsIpa<C>,
    plan: &OpeningPlan,
    points: &[C::ScalarExt],
    polys: &[SlotPolynomial<'_, C::ScalarExt>],
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
) -> Result<C::AffineExt, MultiopenError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    Ok(*create_proof_with_claim(params, plan, points, polys, rng, transcript, budget)?.g())
}

/// Creates the same opening and returns its generator obligation.
///
/// # Errors
/// As [`create_proof`], including a degenerate folded generator.
pub fn create_proof_with_claim<C, T, R>(
    params: &ParamsIpa<C>,
    plan: &OpeningPlan,
    points: &[C::ScalarExt],
    polys: &[SlotPolynomial<'_, C::ScalarExt>],
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, MultiopenError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    create_proof_with_claim_cancellable(params, plan, points, polys, rng, transcript, budget, None)
}

/// Creates an opening with cooperative cancellation and no partial claim.
/// On cancellation, discard the mutated transcript and random stream. Retry
/// with freshly initialized owners and the original witness; a cancelled
/// transcript is never a proof or a resumable transcript prefix.
///
/// # Errors
/// As [`create_proof_with_claim`], or cancellation after kernel tasks join.
#[allow(clippy::too_many_arguments)]
pub fn create_proof_with_claim_cancellable<C, T, R>(
    params: &ParamsIpa<C>,
    plan: &OpeningPlan,
    points: &[C::ScalarExt],
    polys: &[SlotPolynomial<'_, C::ScalarExt>],
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, MultiopenError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    CancellationToken::checkpoint(cancellation)?;
    let n = params.n();
    plan.check_points(points)?;
    OpeningPlan::check_len(ShapeItem::Slots, plan.slots().len(), polys.len())?;
    for poly in polys {
        OpeningPlan::check_len(ShapeItem::Coefficients, n, poly.coeffs.len())?;
    }

    let x_1 = transcript.squeeze_challenge();
    let x_2 = transcript.squeeze_challenge();

    // q' = sum_t x_2^{n_s-1-t} floor(q_t / prod_{p in t} (X - p)).
    let mut q_prime = SecretPolynomial::new(vec![C::ScalarExt::ZERO; n]);
    for (set, set_points) in plan.sets().iter().enumerate() {
        CancellationToken::checkpoint(cancellation)?;
        let (q, _) = reconstruct_cancellable(plan, polys, set, x_1, n, cancellation)?;
        let mut q = SecretPolynomial::new(q);
        for point in set_points {
            divide_by_linear(&mut q, points[*point]);
        }
        q.resize(n, C::ScalarExt::ZERO);
        fold_into_cancellable(&mut q_prime, x_2, &q, cancellation)?;
    }
    let q_prime_blind = C::ScalarExt::random(&mut *rng);
    let q_prime_commitment = commit_cancellable(
        params,
        &q_prime,
        &q_prime_blind,
        Secrecy::Secret,
        budget,
        cancellation,
    )
    .map_err(|error| MultiopenError::from(crate::pcs::ipa::IpaError::from(error)))?
    .to_affine();
    transcript.write_point(&q_prime_commitment)?;

    let x_3 = transcript.squeeze_challenge();
    for set in 0..plan.sets().len() {
        CancellationToken::checkpoint(cancellation)?;
        let (q, _) = reconstruct_cancellable(plan, polys, set, x_1, n, cancellation)?;
        let q = SecretPolynomial::new(q);
        transcript.write_scalar(&evaluate_polynomial(&q, x_3));
    }

    let x_4 = transcript.squeeze_challenge();
    let mut p_blind = q_prime_blind;
    for set in 0..plan.sets().len() {
        CancellationToken::checkpoint(cancellation)?;
        let (q, blind) = reconstruct_cancellable(plan, polys, set, x_1, n, cancellation)?;
        let q = SecretPolynomial::new(q);
        fold_into_cancellable(&mut q_prime, x_4, &q, cancellation)?;
        p_blind = p_blind * x_4 + blind;
    }
    Ok(ipa_create_proof(
        params,
        rng,
        transcript,
        &q_prime,
        &p_blind,
        &x_3,
        budget,
        cancellation,
    )?)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn linear_division_drops_the_remainder() {
        // (X^2 + 3X + 5) = (X - 2)(X + 5) + 15.
        let mut values = vec![Fq::from(5), Fq::from(3), Fq::ONE];
        divide_by_linear(&mut values, Fq::from(2));
        assert_eq!(values, vec![Fq::from(5), Fq::ONE]);
        let mut empty: Vec<Fq> = Vec::new();
        divide_by_linear(&mut empty, Fq::ONE);
        assert!(empty.is_empty());
        let mut constant = vec![Fq::from(9)];
        divide_by_linear(&mut constant, Fq::ONE);
        assert!(constant.is_empty());
    }

    #[test]
    fn fold_into_is_horner() {
        let mut acc = vec![Fq::from(1), Fq::from(2)];
        fold_into(&mut acc, Fq::from(10), &[Fq::from(3), Fq::from(4)]);
        assert_eq!(acc, vec![Fq::from(13), Fq::from(24)]);
    }

    fn check_blocked_folding<F: iroha_pasta::PastaField + From<u64>>() {
        use super::super::{OpeningQuery, Slot, SlotKind};

        let slot = |index| Slot::new(SlotKind::Advice, index);
        let query = |index, rotation| OpeningQuery::new(slot(index), rotation);
        let plan = OpeningPlan::new(&[
            query(0, 0),
            query(1, 0),
            query(2, 1),
            query(3, 0),
            query(0, 1),
            query(3, 1),
        ])
        .unwrap();
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            for n in [0, 1, 4095, 4096, 65_537] {
                let columns: Vec<Vec<F>> = (0..4_u64)
                    .map(|column| {
                        (0..n)
                            .map(|row| F::from((column + 1) * (row as u64 + 3)).square())
                            .collect()
                    })
                    .collect();
                let polys: Vec<_> = columns
                    .iter()
                    .enumerate()
                    .map(|(slot, coeffs)| SlotPolynomial {
                        coeffs,
                        blind: F::from(slot as u64 + 9),
                    })
                    .collect();
                for challenge in [F::ZERO, F::ONE, -F::ONE, F::from(123)] {
                    for set in 0..=plan.sets().len() {
                        let mut expected = vec![F::ZERO; n];
                        let mut blind = F::ZERO;
                        for (slot, poly) in plan.slots().iter().zip(&polys) {
                            if slot.set == set {
                                for (out, value) in expected.iter_mut().zip(poly.coeffs) {
                                    *out = *out * challenge + value;
                                }
                                blind = blind * challenge + poly.blind;
                            }
                        }
                        assert_eq!(
                            pool.install(|| reconstruct(&plan, &polys, set, challenge, n)),
                            (expected, blind)
                        );
                    }
                    // The primitive retains zip semantics even for a short
                    // addend; trailing accumulator entries stay untouched.
                    for addend_len in [n, n.saturating_sub(7)] {
                        let mut actual = columns[0].clone();
                        let mut expected = actual.clone();
                        let addend = &columns[1][..addend_len];
                        for (out, value) in expected.iter_mut().zip(addend) {
                            *out = *out * challenge + value;
                        }
                        pool.install(|| fold_into(&mut actual, challenge, addend));
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn blocked_folding_preserves_slot_order_and_blinds_on_both_fields() {
        check_blocked_folding::<Fp>();
        check_blocked_folding::<Fq>();
    }
}
