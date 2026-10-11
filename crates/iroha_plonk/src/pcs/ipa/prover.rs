//! The IPA opening prover (vendored `poly/ipa/commitment/prover.rs`).
//!
//! For a polynomial `p` of `n = 2^k` coefficients committed with blind `r`,
//! and an opening point `x`, the prover:
//!
//! 1. draws `s` (`n` coefficients) and subtracts `s(x)` from `s_0`, so
//!    `s(x) = 0`; draws the blind of `S = Commit(s)`; writes `S`;
//! 2. squeezes `xi` and `z`;
//! 3. opens `p' = p + xi s - p'(x)` (so `p'(x) = 0`) with blind
//!    `r + xi r_s`;
//! 4. for each of `k` rounds writes `L_j = <p'_hi, G'_lo> + <p'_hi, b_lo> z U +
//!    l_j W` and `R_j = <p'_lo, G'_hi> + <p'_lo, b_hi> z U + r_j W`, squeezes
//!    `u_j`, and folds `p'_lo += u_j^-1 p'_hi`, `b_lo += u_j b_hi`,
//!    `G'_lo += u_j G'_hi` (with [`iroha_pasta::fold`]);
//! 5. writes `c = p'_0` and the synthetic blind `f`.
//!
//! It returns the folded generator `G'_0`, so a `FoldedGenerator` proof suffix
//! costs no extra MSM.
//!
//! RNG draws follow `BlindingScheduleV1` item 8 (spec section 10): the `n`
//! coefficients of `s`, its blind, then `l_j` and `r_j` per round.

use crate::secret::SecretPolynomial;
use ff::Field;
use group::prime::PrimeCurveAffine;
use iroha_pasta::CancellationToken;
use iroha_pasta::{
    PastaCurve,
    fold::fold_generators_cancellable,
    msm::{MemoryBudget, SharedMemoryBudget, msm_secret_cancellable},
    params::ParamsIpa,
};
use rand_core_06::{CryptoRng, RngCore};

use super::{
    IpaError,
    commit::{Secrecy, commit_cancellable},
    evaluate_polynomial, inner_product,
};
use crate::transcript::TranscriptWrite;

/// Writes an opening proof of `poly` (exactly `n` coefficients, committed with
/// `blind`) at `x` and returns the folded generator `G'_0`.
///
/// The transcript must already have absorbed the commitment, the point and
/// the claimed value (the multiopen does this).
///
/// # Errors
///
/// [`IpaError::LengthMismatch`] unless `poly.len() == n`;
/// [`IpaError::ZeroChallenge`] if a round challenge is zero (probability
/// about `k / 2^254`); [`IpaError::Msm`] when an MSM does not fit `budget`;
/// [`IpaError::Transcript`] if a written point is the identity (negligible).
// The single-letter names follow the BGH19 and spec section 9.2 notation.
#[allow(clippy::many_single_char_names)]
pub fn create_proof<C, T, R>(
    params: &ParamsIpa<C>,
    rng: &mut R,
    transcript: &mut T,
    poly: &[C::ScalarExt],
    blind: &C::ScalarExt,
    x: &C::ScalarExt,
    budget: MemoryBudget,
) -> Result<C::AffineExt, IpaError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    Ok(*create_proof_with_claim(params, rng, transcript, poly, blind, x, budget)?.g())
}

/// Creates the same opening and returns its generator obligation.
///
/// # Errors
/// As [`create_proof`], including a degenerate folded generator.
// The names follow the BGH19 equations, as in `create_proof`.
#[allow(clippy::many_single_char_names)]
pub fn create_proof_with_claim<C, T, R>(
    params: &ParamsIpa<C>,
    rng: &mut R,
    transcript: &mut T,
    poly: &[C::ScalarExt],
    blind: &C::ScalarExt,
    x: &C::ScalarExt,
    budget: MemoryBudget,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, IpaError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    create_proof_with_claim_cancellable(params, rng, transcript, poly, blind, x, budget, None)
}

/// Creates an opening with cooperative cancellation and no partial claim.
/// On cancellation, discard the mutated transcript and random stream. Retry
/// with freshly initialized owners and the original witness; a cancelled
/// transcript is never a proof or a resumable transcript prefix.
///
/// # Errors
/// As [`create_proof_with_claim`], or cancellation after kernel tasks join.
#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
pub fn create_proof_with_claim_cancellable<C, T, R>(
    params: &ParamsIpa<C>,
    rng: &mut R,
    transcript: &mut T,
    poly: &[C::ScalarExt],
    blind: &C::ScalarExt,
    x: &C::ScalarExt,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, IpaError>
where
    C: PastaCurve,
    T: TranscriptWrite<C> + ?Sized,
    R: RngCore + CryptoRng,
{
    CancellationToken::checkpoint(cancellation)?;
    let n = params.n();
    if poly.len() != n {
        return Err(IpaError::LengthMismatch {
            expected: n,
            actual: poly.len(),
        });
    }

    // A random polynomial with a root at x.
    let mut s_poly =
        SecretPolynomial::new((0..n).map(|_| C::ScalarExt::random(&mut *rng)).collect());
    let s_at_x = evaluate_polynomial(&s_poly, *x);
    s_poly[0] -= s_at_x;
    let s_blind = C::ScalarExt::random(&mut *rng);
    let s_commitment = commit_cancellable(
        params,
        &s_poly,
        &s_blind,
        Secrecy::Secret,
        budget,
        cancellation,
    )?
    .to_affine();
    transcript.write_point(&s_commitment)?;

    let xi = transcript.squeeze_challenge();
    let z = transcript.squeeze_challenge();

    // p' = p + xi s - p'(x), so p'(x) = 0.
    let mut p_prime =
        SecretPolynomial::new(s_poly.iter().zip(poly).map(|(s, p)| *s * xi + p).collect());
    let v = evaluate_polynomial(&p_prime, *x);
    p_prime[0] -= v;
    let mut f = s_blind * xi + blind;

    let mut b: Vec<C::ScalarExt> = Vec::with_capacity(n);
    let mut power = C::ScalarExt::ONE;
    for _ in 0..n {
        b.push(power);
        power *= x;
    }

    let mut challenges = Vec::with_capacity(params.k() as usize);
    let mut g_prime = params.g().to_vec();
    let u_base = params.u().to_curve();
    let w_base = params.w().to_curve();
    for round in 0..params.k() as usize {
        CancellationToken::checkpoint(cancellation)?;
        let half = n >> (round + 1);
        let value_l = inner_product(&p_prime[half..2 * half], &b[..half]);
        let value_r = inner_product(&p_prime[..half], &b[half..2 * half]);
        let l_randomness = C::ScalarExt::random(&mut *rng);
        let r_randomness = C::ScalarExt::random(&mut *rng);
        let l_j = (msm_secret_cancellable::<C>(
            &p_prime[half..2 * half],
            &g_prime[..half],
            budget,
            &SharedMemoryBudget::process_default(),
            cancellation,
        )? + u_base * (value_l * z)
            + w_base * l_randomness)
            .to_affine();
        let r_j = (msm_secret_cancellable::<C>(
            &p_prime[..half],
            &g_prime[half..2 * half],
            budget,
            &SharedMemoryBudget::process_default(),
            cancellation,
        )? + u_base * (value_r * z)
            + w_base * r_randomness)
            .to_affine();
        transcript.write_point(&l_j)?;
        transcript.write_point(&r_j)?;

        let u_j = transcript.squeeze_challenge();
        challenges.push(u_j);
        let u_j_inv =
            Option::<C::ScalarExt>::from(u_j.invert()).ok_or(IpaError::ZeroChallenge { round })?;

        let (p_lo, p_hi) = p_prime.split_at_mut(half);
        for (lo, hi) in p_lo.iter_mut().zip(p_hi.iter()) {
            *lo += *hi * u_j_inv;
        }
        let (b_lo, b_hi) = b.split_at_mut(half);
        for (lo, hi) in b_lo.iter_mut().zip(b_hi.iter()) {
            *lo += *hi * u_j;
        }
        p_prime.truncate(half);
        b.truncate(half);
        fold_generators_cancellable::<C>(&mut g_prime[..2 * half], &u_j, cancellation)?;
        g_prime.truncate(half);

        f += l_randomness * u_j_inv;
        f += r_randomness * u_j;
    }

    CancellationToken::checkpoint(cancellation)?;
    transcript.write_scalar(&p_prime[0]);
    transcript.write_scalar(&f);
    crate::pcs::ipa::GeneratorClaim::new(params.k(), g_prime[0], challenges)
}

#[cfg(test)]
mod tests {
    use group::Curve;
    use iroha_pasta::{Ep, Fq};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    use super::*;
    use crate::{
        pcs::ipa::fold_scalars,
        transcript::{Blake2bHash, Transcript, TranscriptWriter},
    };

    #[test]
    fn proof_layout_and_folded_generator() {
        let params = ParamsIpa::<Ep>::new(3).expect("k = 3");
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let poly: Vec<Fq> = (0..8).map(|_| Fq::random(&mut rng)).collect();
        let mut transcript = TranscriptWriter::<Ep, _>::new(Blake2bHash::new());
        let g0 = create_proof(
            &params,
            &mut rng,
            &mut transcript,
            &poly,
            &Fq::from(5),
            &Fq::from(9),
            MemoryBudget::DEFAULT,
        )
        .expect("proof");
        // S, then L/R per round, then c and f.
        assert_eq!(transcript.proof().len(), 32 * (1 + 2 * 3 + 2));
        // The folded generator is <s(u), g> for the transcript's challenges;
        // replay them from the proof.
        let proof = transcript.finish();
        let mut replay = TranscriptWriter::<Ep, _>::new(Blake2bHash::new());
        let decode = |i: usize| {
            crate::transcript::decode_point::<Ep>(
                &proof[32 * i..32 * (i + 1)].try_into().expect("32"),
            )
            .expect("point")
        };
        replay.write_point(&decode(0)).expect("S");
        let _xi = replay.squeeze_challenge();
        let _z = replay.squeeze_challenge();
        let mut u = Vec::new();
        for round in 0..3 {
            replay.write_point(&decode(1 + 2 * round)).expect("L");
            replay.write_point(&decode(2 + 2 * round)).expect("R");
            u.push(replay.squeeze_challenge());
        }
        let s = fold_scalars(&u, Fq::ONE);
        let expected = iroha_pasta::msm::msm_naive::<Ep>(&s, params.g()).to_affine();
        assert_eq!(g0, expected);

        let mut wrong = TranscriptWriter::<Ep, _>::new(Blake2bHash::new());
        assert_eq!(
            create_proof(
                &params,
                &mut rng,
                &mut wrong,
                &poly[..7],
                &Fq::ONE,
                &Fq::ONE,
                MemoryBudget::DEFAULT
            ),
            Err(IpaError::LengthMismatch {
                expected: 8,
                actual: 7
            })
        );
    }
}
