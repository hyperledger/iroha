//! The IPA opening verifier (vendored `poly/ipa/commitment/verifier.rs` and
//! `GuardIPA`).
//!
//! [`read_opening`] reads `S`, the `k` rounds and `c`, `f`, rejecting a zero
//! round challenge, and returns a [`PendingOpening`]: the left-hand side
//!
//! ```text
//! P' + sum_j (u_j^-1 L_j + u_j R_j) - c b(x) z U - f W,   P' = P - v g_0 + xi S
//! ```
//!
//! without the `- c G'_0` term. A pending opening is not an acceptance:
//!
//! - [`PendingOpening::verify_full`] computes `G'_0 = <s(u), g>` (an MSM of
//!   size `2^k`) and accepts iff the equation holds, also requiring a supplied
//!   `FoldedGenerator` suffix to equal `G'_0`;
//! - [`PendingOpening::accumulate`] checks the equation with a claimed `G`
//!   (an MSM whose size does not depend on `n`) and returns a
//!   [`PendingAccumulator`], which only `decide` or `batch_decide` accept.
//!
//! # Why `accumulate` is not a verification
//!
//! The claimed `G` is read after every challenge, including the round
//! challenges, `c` and `f`, and it is not absorbed. A prover that writes
//! arbitrary well-formed messages for a false statement can therefore pick
//! `c != 0` and `f` and solve the equation for
//! `G = c^-1 (P' + sum_j (u_j^-1 L_j + u_j R_j) - c b(x) z U - f W)`, and
//! [`PendingOpening::accumulate`] returns `Ok`. Its `Ok` only says that the
//! proof decoded and that the equation holds *for the claimed `G`*; the claim
//! `G = <s(u), g>` is what carries the soundness, and only deciding it
//! (`decide`, `batch_decide` or [`PendingOpening::verify_full`]) accepts.

use ff::{BatchInvert, Field};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};

use super::{
    GeneratorClaim, IpaError, PinnedParams,
    accumulator::PendingAccumulator,
    commit::{Msm, msm_complete},
    fold_evaluation, fold_scalars,
};
use crate::transcript::TranscriptRead;

/// The verifier's state after reading an opening proof (see the module
/// documentation). It is not an acceptance.
#[must_use = "a pending opening is not an acceptance; verify it"]
#[derive(Clone, Debug)]
pub struct PendingOpening<C: PastaCurve> {
    k: u32,
    /// `P + xi S + sum_j (u_j^-1 L_j + u_j R_j)`.
    msm: Msm<C>,
    /// The scalar of `g_0` (`-v`).
    g0_scalar: C::ScalarExt,
    /// The scalar of `U` (`-c b(x) z`).
    u_scalar: C::ScalarExt,
    /// The scalar of `W` (`-f`).
    w_scalar: C::ScalarExt,
    /// `-c`.
    neg_c: C::ScalarExt,
    /// The round challenges `u_0..u_{k-1}`.
    challenges: Vec<C::ScalarExt>,
}

/// Reads an opening of the commitment `commitment` (a linear combination of
/// points) at `x` to the value `v`, for `2^k` coefficients.
///
/// # Errors
///
/// [`IpaError::Transcript`] for a truncated or non-canonical proof message;
/// [`IpaError::ZeroChallenge`] if a round challenge is zero.
// The single-letter names follow the BGH19 and spec section 9.2 notation.
#[allow(clippy::many_single_char_names)]
pub fn read_opening<C, T>(
    k: u32,
    commitment: Msm<C>,
    transcript: &mut T,
    x: &C::ScalarExt,
    v: &C::ScalarExt,
) -> Result<PendingOpening<C>, IpaError>
where
    C: PastaCurve,
    T: TranscriptRead<C> + ?Sized,
{
    let mut msm = commitment;
    let s_commitment = transcript.read_point()?;
    let xi = transcript.squeeze_challenge();
    msm.push(xi, s_commitment);
    let z = transcript.squeeze_challenge();

    let rounds = k as usize;
    let mut points = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let l_j = transcript.read_point()?;
        let r_j = transcript.read_point()?;
        let u_j = transcript.squeeze_challenge();
        if bool::from(u_j.is_zero()) {
            return Err(IpaError::ZeroChallenge { round });
        }
        points.push((l_j, r_j));
        challenges.push(u_j);
    }
    let mut inverses = challenges.clone();
    inverses.iter_mut().batch_invert();
    for ((l_j, r_j), (u_j, u_j_inv)) in points.iter().zip(challenges.iter().zip(&inverses)) {
        msm.push(*u_j_inv, *l_j);
        msm.push(*u_j, *r_j);
    }

    let c = transcript.read_scalar()?;
    let f = transcript.read_scalar()?;
    let b = fold_evaluation(*x, &challenges);
    Ok(PendingOpening {
        k,
        msm,
        g0_scalar: -*v,
        u_scalar: -(c * b * z),
        w_scalar: -f,
        neg_c: -c,
        challenges,
    })
}

impl<C: PastaCurve> PendingOpening<C> {
    /// `log2` of the opened length.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The round challenges `u_0..u_{k-1}`.
    #[must_use]
    pub fn challenges(&self) -> &[C::ScalarExt] {
        &self.challenges
    }

    /// `G'_0 = <s(u), g[0..2^k)>`.
    ///
    /// # Errors
    ///
    /// [`IpaError::ParamsTooSmall`] when the parameters have fewer than
    /// `2^k` generators.
    pub fn folded_generator(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
    ) -> Result<C::AffineExt, IpaError> {
        self.folded_generator_cancellable(params, budget, None)
    }

    /// Runs complete verification arithmetic with an explicit cancellation signal.
    ///
    /// # Errors
    /// As the corresponding verification operation, or [`IpaError::Cancelled`].
    pub fn folded_generator_cancellable(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<C::AffineExt, IpaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        params.require_k(self.k)?;
        let s = fold_scalars(&self.challenges, C::ScalarExt::ONE);
        let g = &params.params().g()[..s.len()];
        Ok(super::commit::msm_complete_cancellable::<C>(
            &s,
            g,
            budget,
            &iroha_pasta::msm::SharedMemoryBudget::process_default(),
            cancellation,
        )?
        .to_affine())
    }

    /// The left-hand side with `g` standing for `G'_0`.
    fn left_hand_side(
        &self,
        params: &PinnedParams<C>,
        g: &C::AffineExt,
        budget: MemoryBudget,
    ) -> C {
        let p = params.params();
        let mut msm = self.msm.clone();
        msm.push(self.g0_scalar, p.g()[0]);
        msm.push(self.u_scalar, p.u());
        msm.push(self.w_scalar, p.w());
        msm.push(self.neg_c, *g);
        msm.evaluate(budget)
    }

    /// The left-hand side with `G'_0` left symbolic, for batch verification:
    /// every term except `-c G'_0` as one combination, then `-c` and the
    /// round challenges. The caller adds `-c <s(u), g>` through one merged
    /// `g` MSM.
    pub(crate) fn into_batch_terms(
        self,
        params: &PinnedParams<C>,
    ) -> (Msm<C>, C::ScalarExt, Vec<C::ScalarExt>) {
        let p = params.params();
        let mut msm = self.msm;
        msm.push(self.g0_scalar, p.g()[0]);
        msm.push(self.u_scalar, p.u());
        msm.push(self.w_scalar, p.w());
        (msm, self.neg_c, self.challenges)
    }

    /// Full verification: accepts iff the equation holds with
    /// `G'_0 = <s(u), g>`. A supplied `FoldedGenerator` suffix must equal
    /// `G'_0`.
    ///
    /// # Errors
    ///
    /// [`IpaError::ParamsTooSmall`], [`IpaError::FoldedGeneratorMismatch`] or
    /// [`IpaError::OpeningFailed`].
    pub fn verify_full(
        self,
        params: &PinnedParams<C>,
        suffix: Option<&C::AffineExt>,
        budget: MemoryBudget,
    ) -> Result<(), IpaError> {
        self.verify_full_cancellable(params, suffix, budget, None)
    }

    /// Runs complete verification arithmetic with an explicit cancellation signal.
    ///
    /// # Errors
    /// As the corresponding verification operation, or [`IpaError::Cancelled`].
    pub fn verify_full_cancellable(
        self,
        params: &PinnedParams<C>,
        suffix: Option<&C::AffineExt>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), IpaError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let folded = self.folded_generator_cancellable(params, budget, cancellation)?;
        if suffix.is_some_and(|claimed| *claimed != folded) {
            return Err(IpaError::FoldedGeneratorMismatch);
        }
        let identity = bool::from(self.left_hand_side(params, &folded, budget).is_identity());
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        if identity {
            Ok(())
        } else {
            Err(IpaError::OpeningFailed)
        }
    }

    /// Turns the opening into the pending accumulator `(transcript_repr, k,
    /// G, u)` after checking the equation with the claimed folded generator
    /// `folded` in place of `G'_0`. The MSM size does not depend on `n`.
    ///
    /// `Ok` is **not** an acceptance and carries no evidence about the
    /// statement: `folded` comes after every challenge, so a prover can solve
    /// the equation for it for any statement (see the module documentation).
    /// Only deciding the returned accumulator (`decide`, `batch_decide`)
    /// accepts.
    ///
    /// `transcript_repr` binds the accumulator to its proof (spec section
    /// 11); the PLONK verifier passes the proof's value.
    ///
    /// # Errors
    ///
    /// [`IpaError::ParamsTooSmall`] or [`IpaError::OpeningFailed`] (an
    /// identity `folded` fails the equation's precondition and is rejected
    /// the same way).
    pub fn accumulate(
        self,
        params: &PinnedParams<C>,
        folded: &C::AffineExt,
        transcript_repr: &C::ScalarExt,
        budget: MemoryBudget,
    ) -> Result<PendingAccumulator<C>, IpaError> {
        self.check_claim(params, folded, budget)?;
        Ok(PendingAccumulator::new(
            *transcript_repr,
            self.k,
            *folded,
            self.challenges,
        ))
    }
    /// Checks the succinct equation against a claimed generator, without
    /// treating that claim as decided.
    ///
    /// # Errors
    /// Insufficient parameters, an identity claim or a failed succinct equation.
    pub fn check_claim(
        &self,
        params: &PinnedParams<C>,
        folded: &C::AffineExt,
        budget: MemoryBudget,
    ) -> Result<(), IpaError> {
        params.require_k(self.k)?;
        if bool::from(folded.is_identity())
            || !bool::from(self.left_hand_side(params, folded, budget).is_identity())
        {
            return Err(IpaError::OpeningFailed);
        }
        Ok(())
    }

    /// Checks the equation and returns its undecided generator obligation.
    ///
    /// # Errors
    /// Insufficient parameters, an identity claim or a failed succinct equation.
    pub fn into_generator_claim(
        self,
        params: &PinnedParams<C>,
        folded: &C::AffineExt,
        budget: MemoryBudget,
    ) -> Result<GeneratorClaim<C>, IpaError> {
        self.check_claim(params, folded, budget)?;
        GeneratorClaim::new(self.k, *folded, self.challenges)
    }
}

/// The folded generator of `challenges` against `params` without a pending
/// opening (tests and accumulator decisions).
pub(crate) fn folded_generator_of<C: PastaCurve>(
    params: &PinnedParams<C>,
    challenges: &[C::ScalarExt],
    budget: MemoryBudget,
) -> C {
    let s = fold_scalars(challenges, C::ScalarExt::ONE);
    msm_complete::<C>(&s, &params.params().g()[..s.len()], budget)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Ep, EpAffine, Eq, Fp, Fq};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    use super::*;
    use crate::{
        pcs::ipa::{
            commit::{Secrecy, commit},
            evaluate_polynomial,
            prover::create_proof,
        },
        transcript::{
            Blake2bHash, PoseidonHash, Transcript, TranscriptError, TranscriptHash,
            TranscriptReader, TranscriptWriter,
        },
    };

    /// A committed random polynomial, its opening proof at a random point and
    /// the returned folded generator.
    struct Opening<C: PastaCurve> {
        commitment: C::AffineExt,
        x: C::ScalarExt,
        v: C::ScalarExt,
        proof: Vec<u8>,
        folded: C::AffineExt,
    }

    /// Absorbs the opening statement as the multiopen would.
    fn absorb_statement<C: PastaCurve, T: Transcript<C>>(t: &mut T, opening: &Opening<C>) {
        t.common_point(&opening.commitment).expect("finite");
        t.common_scalar(&opening.x);
        t.common_scalar(&opening.v);
    }

    fn open<C: PastaCurve, H: TranscriptHash<C>>(
        params: &PinnedParams<C>,
        seed: u64,
        hash: H,
    ) -> Opening<C> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let n = params.params().n();
        let poly: Vec<C::ScalarExt> = (0..n).map(|_| C::ScalarExt::random(&mut rng)).collect();
        let blind = C::ScalarExt::random(&mut rng);
        let commitment = commit(
            params.params(),
            &poly,
            &blind,
            Secrecy::Secret,
            MemoryBudget::DEFAULT,
        )
        .expect("commit")
        .to_affine();
        let x = C::ScalarExt::random(&mut rng);
        let v = evaluate_polynomial(&poly, x);
        let mut opening = Opening {
            commitment,
            x,
            v,
            proof: Vec::new(),
            folded: C::AffineExt::default(),
        };
        let mut transcript = TranscriptWriter::<C, H>::new(hash);
        absorb_statement(&mut transcript, &opening);
        opening.folded = create_proof(
            params.params(),
            &mut rng,
            &mut transcript,
            &poly,
            &blind,
            &x,
            MemoryBudget::DEFAULT,
        )
        .expect("proof");
        opening.proof = transcript.finish();
        opening
    }

    fn read<C: PastaCurve, H: TranscriptHash<C>>(
        params: &PinnedParams<C>,
        opening: &Opening<C>,
        proof: &[u8],
        hash: H,
    ) -> Result<PendingOpening<C>, IpaError> {
        let mut transcript = TranscriptReader::<C, H>::new(hash, proof);
        absorb_statement(&mut transcript, opening);
        let pending = read_opening(
            params.k(),
            Msm::from_point(opening.commitment),
            &mut transcript,
            &opening.x,
            &opening.v,
        )?;
        transcript.finish()?;
        Ok(pending)
    }

    fn round_trip<C: PastaCurve, H: TranscriptHash<C>>(k: u32, fresh: impl Fn() -> H) {
        let params = PinnedParams::<C>::derive(k).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let opening = open(&params, u64::from(k), fresh());
        let pending = read(&params, &opening, &opening.proof, fresh()).expect("read");
        assert_eq!(pending.k(), k);
        assert_eq!(pending.challenges().len(), k as usize);
        assert_eq!(
            pending.folded_generator(&params, budget),
            Ok(opening.folded)
        );
        assert_eq!(
            folded_generator_of(&params, pending.challenges(), budget).to_affine(),
            opening.folded
        );
        pending
            .clone()
            .verify_full(&params, None, budget)
            .expect("full");
        pending
            .clone()
            .verify_full(&params, Some(&opening.folded), budget)
            .expect("full with suffix");
        let repr = C::ScalarExt::from(77);
        let accumulator = pending
            .clone()
            .accumulate(&params, &opening.folded, &repr, budget)
            .expect("succinct");
        accumulator.decide(&params, budget).expect("decide");

        // A wrong suffix, a substituted G and a wrong value are rejected.
        let other = params.params().g()[1];
        assert_eq!(
            pending.clone().verify_full(&params, Some(&other), budget),
            Err(IpaError::FoldedGeneratorMismatch)
        );
        assert_eq!(
            pending
                .clone()
                .accumulate(&params, &other, &repr, budget)
                .err(),
            Some(IpaError::OpeningFailed)
        );
        assert_eq!(
            pending
                .accumulate(&params, &C::AffineExt::identity(), &repr, budget)
                .err(),
            Some(IpaError::OpeningFailed)
        );
        let mut wrong_value = opening.clone_shallow();
        wrong_value.v += C::ScalarExt::ONE;
        let pending = read(&params, &wrong_value, &opening.proof, fresh()).expect("decodes");
        assert_eq!(
            pending.verify_full(&params, None, budget),
            Err(IpaError::OpeningFailed)
        );
        let mut wrong_point = opening.clone_shallow();
        wrong_point.commitment = params.params().g()[0];
        let pending = read(&params, &wrong_point, &opening.proof, fresh()).expect("decodes");
        assert_eq!(
            pending.verify_full(&params, None, budget),
            Err(IpaError::OpeningFailed)
        );
    }

    impl<C: PastaCurve> Opening<C> {
        fn clone_shallow(&self) -> Self {
            Self {
                commitment: self.commitment,
                x: self.x,
                v: self.v,
                proof: self.proof.clone(),
                folded: self.folded,
            }
        }
    }

    #[test]
    fn open_and_verify_round_trips() {
        for k in 1..=5 {
            round_trip::<Ep, _>(k, Blake2bHash::<Ep>::new);
            round_trip::<Eq, _>(k, Blake2bHash::<Eq>::new);
        }
        round_trip::<Ep, _>(4, PoseidonHash::<Ep>::new);
        round_trip::<Eq, _>(4, PoseidonHash::<Eq>::new);
    }

    #[test]
    fn every_tampered_message_is_rejected() {
        let k = 3;
        let params = PinnedParams::<Eq>::derive(k).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let opening = open(&params, 9, Blake2bHash::<Eq>::new());
        let messages = opening.proof.len() / 32;
        assert_eq!(messages, 1 + 2 * k as usize + 2);
        for message in 0..messages {
            for bit in [0_usize, 9, 200] {
                let mut proof = opening.proof.clone();
                proof[32 * message + bit / 8] ^= 1 << (bit % 8);
                let verdict = read(&params, &opening, &proof, Blake2bHash::<Eq>::new())
                    .and_then(|pending| pending.verify_full(&params, None, budget));
                assert!(verdict.is_err(), "message {message} bit {bit} accepted");
            }
        }
        // Truncation and trailing bytes are transcript errors.
        let short = &opening.proof[..opening.proof.len() - 1];
        assert_eq!(
            read(&params, &opening, short, Blake2bHash::<Eq>::new()).err(),
            Some(IpaError::Transcript(TranscriptError::ProofTruncated))
        );
        let mut long = opening.proof.clone();
        long.extend_from_slice(&[0; 32]);
        assert_eq!(
            read(&params, &opening, &long, Blake2bHash::<Eq>::new()).err(),
            Some(IpaError::Transcript(TranscriptError::TrailingBytes {
                remaining: 32
            }))
        );
        // Non-canonical c (the scalar modulus) is rejected while decoding.
        let mut proof = opening.proof.clone();
        let c_offset = 32 * (messages - 2);
        proof[c_offset..c_offset + 32]
            .copy_from_slice(&crate::cs::descriptor::modulus_le_bytes::<Fp>());
        assert_eq!(
            read(&params, &opening, &proof, Blake2bHash::<Eq>::new()).err(),
            Some(IpaError::Transcript(TranscriptError::NonCanonicalScalar))
        );
        // The verifier's MSM falls back instead of rejecting under a zero budget.
        let pending =
            read(&params, &opening, &opening.proof, Blake2bHash::<Eq>::new()).expect("read");
        assert_eq!(
            pending.verify_full(&params, None, MemoryBudget::new(0)),
            Ok(())
        );
    }

    #[test]
    fn params_smaller_than_the_opening_are_refused() {
        let params = PinnedParams::<Ep>::derive(3).expect("params");
        let small = PinnedParams::<Ep>::derive(2).expect("params");
        let opening = open(&params, 3, Blake2bHash::<Ep>::new());
        let pending =
            read(&params, &opening, &opening.proof, Blake2bHash::<Ep>::new()).expect("read");
        assert_eq!(
            pending
                .clone()
                .verify_full(&small, None, MemoryBudget::DEFAULT),
            Err(IpaError::ParamsTooSmall {
                needed: 3,
                available: 2
            })
        );
        assert_eq!(
            pending
                .accumulate(&small, &opening.folded, &Fq::ONE, MemoryBudget::DEFAULT)
                .err(),
            Some(IpaError::ParamsTooSmall {
                needed: 3,
                available: 2
            })
        );
        // Larger parameters share the prefix of g and accept.
        let large = PinnedParams::<Ep>::derive(5).expect("params");
        let pending =
            read(&params, &opening, &opening.proof, Blake2bHash::<Ep>::new()).expect("read");
        assert_eq!(
            pending.verify_full(&large, None, MemoryBudget::DEFAULT),
            Ok(())
        );
    }

    /// A transcript whose challenges are all zero (an injected degenerate
    /// challenge, spec section 15).
    struct ZeroChallenges;

    impl Transcript<Ep> for ZeroChallenges {
        fn squeeze_challenge(&mut self) -> Fq {
            Fq::ZERO
        }
        fn common_point(&mut self, _point: &EpAffine) -> Result<(), TranscriptError> {
            Ok(())
        }
        fn common_scalar(&mut self, _scalar: &Fq) {}
    }

    impl TranscriptRead<Ep> for ZeroChallenges {
        fn read_point(&mut self) -> Result<EpAffine, TranscriptError> {
            Ok(EpAffine::generator())
        }
        fn read_scalar(&mut self) -> Result<Fq, TranscriptError> {
            Ok(Fq::ONE)
        }
    }

    #[test]
    fn zero_round_challenge_is_a_typed_rejection() {
        assert_eq!(
            read_opening(
                2,
                Msm::<Ep>::from_point(EpAffine::generator()),
                &mut ZeroChallenges,
                &Fq::ONE,
                &Fq::ONE
            )
            .err(),
            Some(IpaError::ZeroChallenge { round: 0 })
        );
    }
}
