//! The BGH19 inner-product argument over [`iroha_pasta::params::ParamsIpa`]
//! (spec section 9.2), following the vendored `poly/ipa/commitment`.
//!
//! - [`commit`]: Pedersen-style vector commitments
//!   `sum_i a_i G_i + blind * W`, and [`commit::Msm`], the linear combination
//!   of points a verifier accumulates;
//! - [`prover`]: [`prover::create_proof`] writes `S`, the `L_j`/`R_j` rounds,
//!   `c` and `f`, and returns the folded generator `G'_0`;
//! - [`verifier`]: [`verifier::read_opening`] reads an opening into a
//!   [`verifier::PendingOpening`], which [`verifier::PendingOpening::verify_full`]
//!   accepts or [`verifier::PendingOpening::accumulate`] turns into a
//!   pending accumulator;
//! - [`accumulator`]: [`accumulator::PendingAccumulator`] (`AccumulatorV1`),
//!   `decide` and the deterministic `batch_decide` (spec section 11).
//!
//! # Trust in parameters (S5)
//!
//! Verification takes [`PinnedParams`]: parameters that were either derived
//! here from the transparent setup or loaded from bytes whose SHA-256 equals
//! the pinned `PINNED_PARAMS_V1[(curve, k)]` entry, which covers
//! `g_lagrange`. Signatures over parameter artifacts never authorize verifier
//! inputs.
//!
//! # Determinism
//!
//! Challenges come from the transcript, prover randomness from the caller's
//! RNG in the `BlindingScheduleV1` order, and every MSM is exact group
//! arithmetic: outputs do not depend on the Rayon pool size. Verifier MSMs
//! that do not fit their memory budget fall back to a slower path; a budget
//! never rejects a valid proof (S10).

use core::fmt;

use ff::Field;
use iroha_pasta::{
    PastaCurve, PastaField,
    msm::MsmError,
    params::{ParamsError, ParamsIpa},
};
use sha2::{Digest, Sha256};

use crate::{
    cs::{CurveV1, descriptor::pinned_params_digest},
    transcript::TranscriptError,
};

pub mod accumulator;
pub mod claim;
pub use claim::GeneratorClaim;
pub mod commit;
pub mod prover;
pub mod verifier;

/// An IPA operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpaError {
    /// The caller cancelled this operation; it has no completed proof result.
    Cancelled,
    /// Reading or writing the transcript failed.
    Transcript(TranscriptError),
    /// A vector has the wrong length.
    LengthMismatch {
        /// The required length.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// The parameters are smaller than the opening.
    ParamsTooSmall {
        /// The `k` the opening needs.
        needed: u32,
        /// The `k` of the parameters.
        available: u32,
    },
    /// A round challenge `u_j` is zero (spec section 8, step 8).
    ZeroChallenge {
        /// The round.
        round: usize,
    },
    /// The opening equation does not hold.
    OpeningFailed,
    /// The `FoldedGenerator` suffix is not `<s(u), g>`.
    FoldedGeneratorMismatch,
    /// A prover MSM failed (budget or size).
    Msm(MsmError),
}

impl IpaError {
    /// Whether this failure is cooperative cancellation, never an invalid proof.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::Msm(error) => matches!(error, MsmError::Cancelled),
            _ => false,
        }
    }
}

impl fmt::Display for IpaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::Transcript(error) => write!(f, "transcript: {error}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "vector has {actual} entries, expected {expected}")
            }
            Self::ParamsTooSmall { needed, available } => {
                write!(f, "opening needs k = {needed}, params have k = {available}")
            }
            Self::ZeroChallenge { round } => write!(f, "IPA challenge of round {round} is zero"),
            Self::OpeningFailed => f.write_str("the IPA opening equation does not hold"),
            Self::FoldedGeneratorMismatch => {
                f.write_str("the folded generator suffix is not <s(u), g>")
            }
            Self::Msm(error) => write!(f, "MSM: {error}"),
        }
    }
}

impl std::error::Error for IpaError {}

impl From<iroha_pasta::Cancelled> for IpaError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<TranscriptError> for IpaError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<MsmError> for IpaError {
    fn from(error: MsmError) -> Self {
        if matches!(error, MsmError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Msm(error)
        }
    }
}

/// Parameters could not be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsTrustError {
    /// The curve is not a descriptor curve.
    UnknownCurve,
    /// The bytes are shorter than the `k` header.
    MissingHeader,
    /// No digest is pinned for this curve and `k`; derive the parameters.
    Unpinned {
        /// The curve.
        curve: CurveV1,
        /// The `k` of the encoding.
        k: u32,
    },
    /// SHA-256 of the bytes is not the pinned digest.
    DigestMismatch {
        /// The curve.
        curve: CurveV1,
        /// The `k` of the encoding.
        k: u32,
    },
    /// Derivation or decoding failed.
    Params(ParamsError),
}

impl fmt::Display for ParamsTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCurve => f.write_str("unknown curve"),
            Self::MissingHeader => f.write_str("params bytes lack the k header"),
            Self::Unpinned { curve, k } => {
                write!(f, "no params digest is pinned for {curve:?} at k = {k}")
            }
            Self::DigestMismatch { curve, k } => {
                write!(
                    f,
                    "params bytes for {curve:?} at k = {k} do not match the pinned digest"
                )
            }
            Self::Params(error) => write!(f, "params: {error}"),
        }
    }
}

impl std::error::Error for ParamsTrustError {}

impl From<ParamsError> for ParamsTrustError {
    fn from(error: ParamsError) -> Self {
        Self::Params(error)
    }
}

/// IPA parameters a verifier may trust (S5): derived from the transparent
/// setup, or decoded from bytes that hash to the pinned digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedParams<C: PastaCurve> {
    params: ParamsIpa<C>,
    curve: CurveV1,
}

impl<C: PastaCurve> PinnedParams<C> {
    /// Derives the parameters for `2^k` generators (`hash_to_curve` with the
    /// `Halo2-Parameters` domain and `g_lagrange` by group IFFT).
    ///
    /// # Errors
    ///
    /// [`ParamsTrustError::Params`] when `k` is unsupported or the
    /// derivation fails; [`ParamsTrustError::UnknownCurve`] never occurs for
    /// the Pasta curves.
    pub fn derive(k: u32) -> Result<Self, ParamsTrustError> {
        let curve = super::curve_v1::<C>().ok_or(ParamsTrustError::UnknownCurve)?;
        Ok(Self {
            params: ParamsIpa::new(k)?,
            curve,
        })
    }

    /// Accepts parameter bytes only if their SHA-256 equals the pinned digest
    /// for this curve and the encoded `k`.
    ///
    /// # Errors
    ///
    /// [`ParamsTrustError::Unpinned`] when no digest is pinned for `k`
    /// (derive instead), [`ParamsTrustError::DigestMismatch`] for any other
    /// bytes, [`ParamsTrustError::MissingHeader`] or
    /// [`ParamsTrustError::Params`] for undecodable input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParamsTrustError> {
        let curve = super::curve_v1::<C>().ok_or(ParamsTrustError::UnknownCurve)?;
        let header: [u8; 4] = bytes
            .get(..4)
            .and_then(|head| head.try_into().ok())
            .ok_or(ParamsTrustError::MissingHeader)?;
        let k = u32::from_le_bytes(header);
        let pinned =
            pinned_params_digest(curve, k).ok_or(ParamsTrustError::Unpinned { curve, k })?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != pinned {
            return Err(ParamsTrustError::DigestMismatch { curve, k });
        }
        Ok(Self {
            params: ParamsIpa::from_bytes(bytes)?,
            curve,
        })
    }

    /// The parameters.
    #[must_use]
    pub fn params(&self) -> &ParamsIpa<C> {
        &self.params
    }

    /// `log2` of the number of generators.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.params.k()
    }

    /// The descriptor curve.
    #[must_use]
    pub fn curve(&self) -> CurveV1 {
        self.curve
    }

    /// SHA-256 of the parameter bytes (the `params_digest` of spec section 3).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.params.to_bytes()).into()
    }

    /// Requires at least `2^k` generators.
    ///
    /// # Errors
    ///
    /// [`IpaError::ParamsTooSmall`] otherwise.
    pub fn require_k(&self, k: u32) -> Result<(), IpaError> {
        if k <= self.k() {
            Ok(())
        } else {
            Err(IpaError::ParamsTooSmall {
                needed: k,
                available: self.k(),
            })
        }
    }
}

/// The coefficients of `g(X) = prod_{i<k} (1 + u_{k-1-i} X^{2^i})`, scaled by
/// `init`: `s_i = init * prod_j u_j^{bit_{k-1-j}(i)}` (`u_0` pairs with the
/// top index bit). The folded generator is `G'_0 = <s, g>`.
#[must_use]
pub fn fold_scalars<F: Field>(challenges: &[F], init: F) -> Vec<F> {
    let mut values = vec![F::ZERO; 1_usize << challenges.len()];
    values[0] = init;
    for (round, challenge) in challenges.iter().rev().enumerate() {
        let len = 1_usize << round;
        let (left, right) = values.split_at_mut(len);
        for (out, value) in right[..len].iter_mut().zip(left.iter()) {
            *out = *value * challenge;
        }
    }
    values
}

/// `b(x) = prod_{i<k} (1 + u_{k-1-i} x^{2^i})`.
#[must_use]
pub fn fold_evaluation<F: Field>(x: F, challenges: &[F]) -> F {
    let mut acc = F::ONE;
    let mut power = x;
    for challenge in challenges.iter().rev() {
        acc *= F::ONE + *challenge * power;
        power = power.square();
    }
    acc
}

/// `<a, b>`.
pub(crate) fn inner_product<F: PastaField>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::ZERO, |acc, (x, y)| acc + *x * y)
}

/// Evaluates a coefficient-form polynomial at `x` with Horner leaves.
///
/// Large inputs split into a fixed tree on the caller's Rayon pool. Each
/// node combines `low(x) + x^low.len() high(x)` in that order; scheduling
/// cannot change the result. The tree needs only bounded stack temporaries,
/// not a coefficient copy or a parallel reduction buffer.
#[must_use]
pub fn evaluate_polynomial<F: Field>(coeffs: &[F], x: F) -> F {
    if coeffs.len() >= 8192 && rayon::current_num_threads() > 1 {
        let (low, high) = coeffs.split_at(coeffs.len() / 2);
        let power = x.pow_vartime([low.len() as u64]);
        let (low, high) = rayon::join(
            || evaluate_polynomial(low, x),
            || evaluate_polynomial(high, x),
        );
        return low + power * high;
    }
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Ep, Eq, Fp, Fq};

    use super::*;

    fn check_polynomial_evaluation<F: Field + From<u64>>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            for len in [0_usize, 1, 8191, 8192, 8193, 65_537] {
                let coeffs: Vec<F> = (0..len)
                    .map(|i| F::from(i as u64 + 3).square() - F::from(7))
                    .collect();
                for point in [F::ZERO, F::ONE, -F::ONE, F::from(17)] {
                    let expected = coeffs
                        .iter()
                        .rev()
                        .fold(F::ZERO, |value, coeff| value * point + coeff);
                    assert_eq!(
                        pool.install(|| evaluate_polynomial(&coeffs, point)),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn polynomial_evaluation_tree_matches_horner_on_both_fields() {
        check_polynomial_evaluation::<Fp>();
        check_polynomial_evaluation::<Fq>();
    }

    #[test]
    fn fold_scalars_expand_the_product() {
        let u = [Fq::from(3), Fq::from(5), Fq::from(7)];
        let s = fold_scalars(&u, Fq::ONE);
        assert_eq!(s.len(), 8);
        for (i, value) in s.iter().enumerate() {
            let mut expected = Fq::ONE;
            for (j, challenge) in u.iter().enumerate() {
                if (i >> (u.len() - 1 - j)) & 1 == 1 {
                    expected *= challenge;
                }
            }
            assert_eq!(*value, expected, "index {i}");
        }
        assert_eq!(fold_scalars::<Fq>(&[], Fq::from(9)), vec![Fq::from(9)]);
        // b(x) = <s, (1, x, x^2, ...)>.
        let x = Fq::from(11);
        let powers: Vec<Fq> = (0..8_u64).map(|i| x.pow_vartime([i])).collect();
        assert_eq!(fold_evaluation(x, &u), inner_product(&s, &powers));
        assert_eq!(
            evaluate_polynomial(&powers[..3], Fq::from(2)),
            Fq::ONE + x * Fq::from(2) + x.square() * Fq::from(4)
        );
    }

    /// DEV-08 (spec section 14): verifiers accept only derived parameters or bytes matching the
    /// pinned digest; the vendored verifier trusts any parameters.
    #[test]
    fn pinned_params_accept_only_pinned_bytes() {
        let derived = PinnedParams::<Ep>::derive(6).expect("derive k = 6");
        assert_eq!(derived.curve(), CurveV1::Pallas);
        assert_eq!(
            Some(derived.digest()),
            pinned_params_digest(CurveV1::Pallas, 6)
        );
        let bytes = derived.params().to_bytes();
        assert_eq!(PinnedParams::<Ep>::from_bytes(&bytes), Ok(derived.clone()));
        // The same bytes are not Vesta parameters.
        assert_eq!(
            PinnedParams::<Eq>::from_bytes(&bytes),
            Err(ParamsTrustError::DigestMismatch {
                curve: CurveV1::Vesta,
                k: 6
            })
        );
        // Any change, g_lagrange included, is a mismatch.
        let mut tampered = bytes.clone();
        let last_lagrange = 4 + 64 * 64 - 1;
        tampered[last_lagrange] ^= 1;
        assert_eq!(
            PinnedParams::<Ep>::from_bytes(&tampered),
            Err(ParamsTrustError::DigestMismatch {
                curve: CurveV1::Pallas,
                k: 6
            })
        );
        let small = PinnedParams::<Ep>::derive(3).expect("derive k = 3");
        assert_eq!(
            PinnedParams::<Ep>::from_bytes(&small.params().to_bytes()),
            Err(ParamsTrustError::Unpinned {
                curve: CurveV1::Pallas,
                k: 3
            })
        );
        assert_eq!(
            PinnedParams::<Ep>::from_bytes(&[1, 2]),
            Err(ParamsTrustError::MissingHeader)
        );
        assert_eq!(small.require_k(3), Ok(()));
        assert_eq!(
            small.require_k(4),
            Err(IpaError::ParamsTooSmall {
                needed: 4,
                available: 3
            })
        );
    }

    #[test]
    fn error_messages_are_descriptive() {
        assert!(
            IpaError::ZeroChallenge { round: 2 }
                .to_string()
                .contains("round 2")
        );
        assert!(
            ParamsTrustError::Unpinned {
                curve: CurveV1::Vesta,
                k: 30
            }
            .to_string()
            .contains("k = 30")
        );
        assert_eq!(
            IpaError::from(TranscriptError::ProofTruncated),
            IpaError::Transcript(TranscriptError::ProofTruncated)
        );
    }
}
