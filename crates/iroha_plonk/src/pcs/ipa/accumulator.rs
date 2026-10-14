//! IPA accumulators (spec section 11): the `AccumulatorV1` encoding, `decide`
//! and the deterministic `batch_decide`.
//!
//! A succinct verification leaves the claim `G = <s(u), g[0..2^k)>` open. A
//! [`PendingAccumulator`] carries that claim. It is `#[must_use]` and is never
//! an acceptance: only [`PendingAccumulator::decide`] and [`batch_decide`]
//! (and the full verifier) accept, and both consume their input.
//!
//! # Encoding
//!
//! ```text
//! AccumulatorV1 = transcript_repr (32) || u8 curve || u8 k || G (32) || u_0..u_{k-1} (32 each)
//! ```
//!
//! `66 + 32k` bytes; the curve byte is [`CURVE_BYTE_PALLAS`] or
//! [`CURVE_BYTE_VESTA`]; `1 <= k <= 28`. Decoding is canonical: every scalar
//! is below the modulus, `G` is a canonical non-identity point, every
//! `u_j != 0`, and no bytes follow.
//!
//! # Deterministic batch weights
//!
//! The vendored `AccumulatorStrategy` scales by `OsRng`; PIPA-v1 derives the
//! weights from every item after all items are fixed:
//!
//! ```text
//! I_i   = BLAKE2b(64, "PIPA-v1-BatchItm", kind || body)
//! seed  = BLAKE2b(64, "PIPA-v1-BatchWgt", u64_le(N) || I_0 || ... || I_{N-1})
//! rho_0 = 1
//! rho_i = F::from_uniform_bytes(BLAKE2b(64, "PIPA-v1-BatchWgt", seed || u64_le(i)))
//! ```
//!
//! An accumulator item has kind [`BATCH_KIND_ACCUMULATOR`] and its
//! `AccumulatorV1` bytes as body; a full proof has kind [`BATCH_KIND_PROOF`]
//! and the body of [`proof_item_body`]. `batch_decide` accepts iff
//! `sum_i rho_i (G_i - <s(u^i), g>) = O`, with one merged `g` MSM. Because the
//! weights hash `G_i` and `u^i` of every item, an adversary cannot pick
//! invalid accumulators whose errors cancel. If any weight is zero (probability
//! about `N / 2^254`), every item is decided individually.

use core::fmt;

use ff::{Field, FromUniformBytes, PrimeField};
use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget};

use super::{IpaError, PinnedParams, commit::msm_complete, fold_scalars, verifier};
use crate::{
    cs::{CurveV1, constraint_system::MAX_K, descriptor::blake2b_personal},
    pcs::curve_v1,
    transcript::{
        MESSAGE_BYTES, Transcript, TranscriptError, decode_point, decode_scalar, encode_point,
    },
};

/// Bytes of an `AccumulatorV1` before the challenges.
pub const ACCUMULATOR_V1_HEADER_BYTES: usize = 66;
/// The curve byte of Pallas.
pub const CURVE_BYTE_PALLAS: u8 = 0;
/// The curve byte of Vesta.
pub const CURVE_BYTE_VESTA: u8 = 1;
/// `BLAKE2b` personalization of a batch item digest.
pub const BATCH_ITEM_PERSONA: &[u8; 16] = b"PIPA-v1-BatchItm";
/// `BLAKE2b` personalization of the batch seed and weights.
pub const BATCH_WEIGHT_PERSONA: &[u8; 16] = b"PIPA-v1-BatchWgt";
/// Batch item kind of a full proof.
pub const BATCH_KIND_PROOF: u8 = 0x00;
/// Batch item kind of an accumulator.
pub const BATCH_KIND_ACCUMULATOR: u8 = 0x01;

/// An accumulator could not be decoded or was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccumulatorError {
    /// The encoding has the wrong length.
    Length {
        /// The length implied by the header (or the header length).
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// `k` is outside `1..=28`.
    UnsupportedK {
        /// The encoded `k`.
        k: u8,
    },
    /// The curve byte does not name this curve.
    CurveMismatch {
        /// This curve's byte.
        expected: u8,
        /// The encoded byte.
        found: u8,
    },
    /// A scalar or point failed canonical decoding.
    Encoding(TranscriptError),
    /// A challenge `u_j` is zero.
    ZeroChallenge {
        /// The round.
        round: usize,
    },
    /// The parameters are smaller than the accumulator.
    ParamsTooSmall {
        /// The `k` needed.
        needed: u32,
        /// The `k` of the parameters.
        available: u32,
    },
    /// `G != <s(u), g>`.
    Rejected,
    /// The weighted batch equation does not hold.
    BatchRejected,
    /// An item of an individually decided batch was rejected.
    RejectedItem {
        /// The item index.
        index: usize,
    },
}

impl fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "accumulator has {actual} bytes, expected {expected}")
            }
            Self::UnsupportedK { k } => write!(f, "unsupported accumulator k = {k}"),
            Self::CurveMismatch { expected, found } => {
                write!(f, "accumulator curve byte {found}, expected {expected}")
            }
            Self::Encoding(error) => write!(f, "accumulator encoding: {error}"),
            Self::ZeroChallenge { round } => write!(f, "accumulator challenge {round} is zero"),
            Self::ParamsTooSmall { needed, available } => {
                write!(
                    f,
                    "accumulator needs k = {needed}, params have k = {available}"
                )
            }
            Self::Rejected => f.write_str("the accumulator does not decide"),
            Self::BatchRejected => f.write_str("the accumulator batch does not decide"),
            Self::RejectedItem { index } => write!(f, "batch item {index} does not decide"),
        }
    }
}

impl std::error::Error for AccumulatorError {}

impl From<TranscriptError> for AccumulatorError {
    fn from(error: TranscriptError) -> Self {
        Self::Encoding(error)
    }
}

impl From<IpaError> for AccumulatorError {
    fn from(error: IpaError) -> Self {
        match error {
            IpaError::ParamsTooSmall { needed, available } => {
                Self::ParamsTooSmall { needed, available }
            }
            IpaError::Transcript(error) => Self::Encoding(error),
            IpaError::ZeroChallenge { round } => Self::ZeroChallenge { round },
            _ => Self::Rejected,
        }
    }
}

/// The curve byte of `C`.
fn curve_byte<C: PastaCurve>() -> u8 {
    match curve_v1::<C>() {
        Some(CurveV1::Vesta) => CURVE_BYTE_VESTA,
        _ => CURVE_BYTE_PALLAS,
    }
}

/// An undecided accumulator `(transcript_repr, k, G, u)`.
#[must_use = "a pending accumulator is not an acceptance; decide it"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAccumulator<C: PastaCurve> {
    transcript_repr: C::ScalarExt,
    k: u32,
    g: C::AffineExt,
    challenges: Vec<C::ScalarExt>,
}

impl<C: PastaCurve> PendingAccumulator<C> {
    /// Built by succinct verification.
    pub(crate) fn new(
        transcript_repr: C::ScalarExt,
        k: u32,
        g: C::AffineExt,
        challenges: Vec<C::ScalarExt>,
    ) -> Self {
        debug_assert_eq!(challenges.len(), k as usize);
        Self {
            transcript_repr,
            k,
            g,
            challenges,
        }
    }

    /// The `transcript_repr` of the proof the accumulator came from.
    #[must_use]
    pub fn transcript_repr(&self) -> &C::ScalarExt {
        &self.transcript_repr
    }

    /// `log2` of the generator count.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The claimed folded generator `G`.
    #[must_use]
    pub fn g(&self) -> &C::AffineExt {
        &self.g
    }

    /// The challenges `u_0..u_{k-1}`.
    #[must_use]
    pub fn challenges(&self) -> &[C::ScalarExt] {
        &self.challenges
    }

    /// The `AccumulatorV1` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(ACCUMULATOR_V1_HEADER_BYTES + MESSAGE_BYTES * self.challenges.len());
        bytes.extend_from_slice(&self.transcript_repr.to_repr());
        bytes.push(curve_byte::<C>());
        // `k <= MAX_K = 28` for every value this type holds.
        bytes.push(u8::try_from(self.k).unwrap_or(u8::MAX));
        bytes.extend_from_slice(&encode_point::<C>(&self.g));
        for challenge in &self.challenges {
            bytes.extend_from_slice(&challenge.to_repr());
        }
        bytes
    }

    /// Decodes an `AccumulatorV1` canonically.
    ///
    /// # Errors
    ///
    /// [`AccumulatorError::Length`], [`AccumulatorError::UnsupportedK`],
    /// [`AccumulatorError::CurveMismatch`], [`AccumulatorError::Encoding`]
    /// (non-canonical scalars, an invalid or identity `G`) or
    /// [`AccumulatorError::ZeroChallenge`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccumulatorError> {
        let header = bytes
            .get(..ACCUMULATOR_V1_HEADER_BYTES)
            .ok_or(AccumulatorError::Length {
                expected: ACCUMULATOR_V1_HEADER_BYTES,
                actual: bytes.len(),
            })?;
        let message = |offset: usize| -> [u8; MESSAGE_BYTES] {
            let mut out = [0_u8; MESSAGE_BYTES];
            out.copy_from_slice(&bytes[offset..offset + MESSAGE_BYTES]);
            out
        };
        let curve = header[32];
        if curve != curve_byte::<C>() {
            return Err(AccumulatorError::CurveMismatch {
                expected: curve_byte::<C>(),
                found: curve,
            });
        }
        let k = header[33];
        if k == 0 || u32::from(k) > MAX_K {
            return Err(AccumulatorError::UnsupportedK { k });
        }
        let expected = ACCUMULATOR_V1_HEADER_BYTES + MESSAGE_BYTES * usize::from(k);
        if bytes.len() != expected {
            return Err(AccumulatorError::Length {
                expected,
                actual: bytes.len(),
            });
        }
        let transcript_repr = decode_scalar::<C::ScalarExt>(&message(0))?;
        let g = decode_point::<C>(&message(34))?;
        let mut challenges = Vec::with_capacity(usize::from(k));
        for round in 0..usize::from(k) {
            let challenge = decode_scalar::<C::ScalarExt>(&message(
                ACCUMULATOR_V1_HEADER_BYTES + MESSAGE_BYTES * round,
            ))?;
            if bool::from(challenge.is_zero()) {
                return Err(AccumulatorError::ZeroChallenge { round });
            }
            challenges.push(challenge);
        }
        Ok(Self {
            transcript_repr,
            k: u32::from(k),
            g,
            challenges,
        })
    }

    /// Absorbs `transcript_repr`, `G` and every `u_j`, which a consumer must
    /// do before any challenge that depends on them (spec section 11).
    ///
    /// # Errors
    ///
    /// [`TranscriptError::IdentityPoint`] never occurs for a decoded or
    /// verified accumulator (`G != O`).
    pub fn absorb_into<T: Transcript<C> + ?Sized>(
        &self,
        transcript: &mut T,
    ) -> Result<(), TranscriptError> {
        transcript.common_scalar(&self.transcript_repr);
        transcript.common_point(&self.g)?;
        for challenge in &self.challenges {
            transcript.common_scalar(challenge);
        }
        Ok(())
    }

    /// Accepts iff `G = <s(u), g[0..2^k)>`.
    ///
    /// # Errors
    ///
    /// [`AccumulatorError::ParamsTooSmall`] or [`AccumulatorError::Rejected`].
    pub fn decide(
        self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
    ) -> Result<(), AccumulatorError> {
        crate::verification_counters::record_decide();
        params.require_k(self.k)?;
        let expected = verifier::folded_generator_of(params, &self.challenges, budget);
        if expected.to_affine() == self.g {
            Ok(())
        } else {
            Err(AccumulatorError::Rejected)
        }
    }
}

/// `I = BLAKE2b(64, "PIPA-v1-BatchItm", kind || body)`.
#[must_use]
pub fn batch_item_digest(kind: u8, body: &[u8]) -> [u8; 64] {
    blake2b_personal::<64>(BATCH_ITEM_PERSONA, &[&[kind], body])
}

/// The deterministic batch weights of items with digests `items`:
/// `rho_0 = 1`, `rho_i = F::from_uniform_bytes(BLAKE2b(64, "PIPA-v1-BatchWgt",
/// seed || u64_le(i)))`.
#[must_use]
pub fn batch_weights<F: PastaField>(items: &[[u8; 64]]) -> Vec<F> {
    let count = u64::try_from(items.len()).unwrap_or(u64::MAX).to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(items.len() + 1);
    parts.push(&count);
    parts.extend(items.iter().map(<[u8; 64]>::as_slice));
    let seed = blake2b_personal::<64>(BATCH_WEIGHT_PERSONA, &parts);
    (0..items.len())
        .map(|i| {
            if i == 0 {
                F::ONE
            } else {
                let index = u64::try_from(i).unwrap_or(u64::MAX).to_le_bytes();
                let wide = blake2b_personal::<64>(BATCH_WEIGHT_PERSONA, &[&seed, &index]);
                <F as FromUniformBytes<64>>::from_uniform_bytes(&wide)
            }
        })
        .collect()
}

/// The batch body of a full proof (kind [`BATCH_KIND_PROOF`]):
/// `descriptor_digest || transcript_repr || u32_le(columns)`, then
/// `u32_le(len) || values` per instance column (32-byte canonical scalars),
/// then `u64_le(len) || proof`.
///
/// # Errors
///
/// [`AccumulatorError::Length`] when a count does not fit its field.
pub fn proof_item_body<F: PrimeField<Repr = [u8; 32]>>(
    descriptor_digest: &[u8; 32],
    transcript_repr: &F,
    instances: &[Vec<F>],
    proof: &[u8],
) -> Result<Vec<u8>, AccumulatorError> {
    let too_long = |actual: usize| AccumulatorError::Length {
        expected: u32::MAX as usize,
        actual,
    };
    let mut body = Vec::new();
    body.extend_from_slice(descriptor_digest);
    body.extend_from_slice(&transcript_repr.to_repr());
    let columns = u32::try_from(instances.len()).map_err(|_| too_long(instances.len()))?;
    body.extend_from_slice(&columns.to_le_bytes());
    for column in instances {
        let length = u32::try_from(column.len()).map_err(|_| too_long(column.len()))?;
        body.extend_from_slice(&length.to_le_bytes());
        for value in column {
            body.extend_from_slice(&value.to_repr());
        }
    }
    let proof_length = u64::try_from(proof.len()).map_err(|_| too_long(proof.len()))?;
    body.extend_from_slice(&proof_length.to_le_bytes());
    body.extend_from_slice(proof);
    Ok(body)
}

/// Decides every accumulator at once with the deterministic weights.
///
/// Accumulators may mix values of `k`; `params` must cover the largest (the
/// generators of smaller `k` are a prefix). An empty batch claims nothing and
/// is accepted.
///
/// # Errors
///
/// [`AccumulatorError::ParamsTooSmall`], [`AccumulatorError::BatchRejected`],
/// or [`AccumulatorError::RejectedItem`] when a zero weight forced individual
/// decisions.
pub fn batch_decide<C: PastaCurve>(
    accumulators: Vec<PendingAccumulator<C>>,
    params: &PinnedParams<C>,
    budget: MemoryBudget,
) -> Result<(), AccumulatorError> {
    crate::verification_counters::record_batch();
    let digests: Vec<[u8; 64]> = accumulators
        .iter()
        .map(|accumulator| batch_item_digest(BATCH_KIND_ACCUMULATOR, &accumulator.to_bytes()))
        .collect();
    let weights = batch_weights::<C::ScalarExt>(&digests);
    decide_weighted(accumulators, &weights, params, budget)
}

/// `batch_decide` with explicit weights (one per accumulator).
fn decide_weighted<C: PastaCurve>(
    accumulators: Vec<PendingAccumulator<C>>,
    weights: &[C::ScalarExt],
    params: &PinnedParams<C>,
    budget: MemoryBudget,
) -> Result<(), AccumulatorError> {
    debug_assert_eq!(accumulators.len(), weights.len());
    let Some(max_k) = accumulators.iter().map(PendingAccumulator::k).max() else {
        return Ok(());
    };
    params.require_k(max_k)?;
    if weights.iter().any(|weight| bool::from(weight.is_zero())) {
        for (index, accumulator) in accumulators.into_iter().enumerate() {
            accumulator
                .decide(params, budget)
                .map_err(|_| AccumulatorError::RejectedItem { index })?;
        }
        return Ok(());
    }
    let g = params.params().g();
    let mut combined = vec![C::ScalarExt::ZERO; 1_usize << max_k];
    let mut scalars = Vec::with_capacity(combined.len() + accumulators.len());
    let mut bases = Vec::with_capacity(combined.len() + accumulators.len());
    for (accumulator, weight) in accumulators.iter().zip(weights) {
        let s = fold_scalars(&accumulator.challenges, *weight);
        for (total, value) in combined.iter_mut().zip(&s) {
            *total += value;
        }
        scalars.push(*weight);
        bases.push(accumulator.g);
    }
    scalars.extend(combined.iter().map(|value| -*value));
    bases.extend_from_slice(&g[..combined.len()]);
    crate::verification_counters::record_generator_msm(combined.len());
    if bool::from(msm_complete::<C>(&scalars, &bases, budget).is_identity()) {
        Ok(())
    } else {
        Err(AccumulatorError::BatchRejected)
    }
}

/// An accumulator for arbitrary nonzero challenges with `G = <s(u), g>`
/// (tests of decide and batch decide).
#[cfg(test)]
pub(crate) fn honest_accumulator<C: PastaCurve>(
    params: &PinnedParams<C>,
    challenges: Vec<C::ScalarExt>,
    transcript_repr: C::ScalarExt,
) -> PendingAccumulator<C> {
    let k = u32::try_from(challenges.len()).expect("k fits u32");
    let g = verifier::folded_generator_of(params, &challenges, MemoryBudget::DEFAULT).to_affine();
    PendingAccumulator::new(transcript_repr, k, g, challenges)
}

#[cfg(test)]
mod tests {
    use group::{Curve, prime::PrimeCurveAffine};
    use iroha_pasta::{Ep, Eq, Fp, Fq};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    use super::*;
    use crate::transcript::{Blake2bHash, TranscriptWriter};

    fn random_challenges<F: PastaField>(k: usize, rng: &mut ChaCha20Rng) -> Vec<F> {
        (0..k).map(|_| F::random(&mut *rng)).collect()
    }

    #[test]
    fn encoding_round_trips_and_rejects_malformed_bytes() {
        let params = PinnedParams::<Eq>::derive(3).expect("params");
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let accumulator =
            honest_accumulator(&params, random_challenges::<Fp>(3, &mut rng), Fp::from(42));
        let bytes = accumulator.to_bytes();
        assert_eq!(bytes.len(), 66 + 32 * 3);
        assert_eq!(bytes[32], CURVE_BYTE_VESTA);
        assert_eq!(bytes[33], 3);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bytes),
            Ok(accumulator.clone())
        );

        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bytes[..65]),
            Err(AccumulatorError::Length {
                expected: 66,
                actual: 65
            })
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&long),
            Err(AccumulatorError::Length {
                expected: 162,
                actual: 163
            })
        );
        assert_eq!(
            PendingAccumulator::<Ep>::from_bytes(&bytes),
            Err(AccumulatorError::CurveMismatch {
                expected: CURVE_BYTE_PALLAS,
                found: CURVE_BYTE_VESTA
            })
        );
        for k in [0_u8, 29] {
            let mut bad = bytes.clone();
            bad[33] = k;
            assert_eq!(
                PendingAccumulator::<Eq>::from_bytes(&bad),
                Err(AccumulatorError::UnsupportedK { k })
            );
        }
        let modulus = crate::cs::descriptor::modulus_le_bytes::<Fp>();
        let mut bad = bytes.clone();
        bad[..32].copy_from_slice(&modulus);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bad),
            Err(AccumulatorError::Encoding(
                TranscriptError::NonCanonicalScalar
            ))
        );
        let mut bad = bytes.clone();
        bad[34..66].fill(0);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bad),
            Err(AccumulatorError::Encoding(TranscriptError::IdentityPoint))
        );
        let mut bad = bytes.clone();
        bad[34..66].fill(0);
        bad[34] = 2;
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bad),
            Err(AccumulatorError::Encoding(TranscriptError::InvalidPoint))
        );
        let mut bad = bytes.clone();
        bad[66 + 32..66 + 64].fill(0);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bad),
            Err(AccumulatorError::ZeroChallenge { round: 1 })
        );
        let mut bad = bytes;
        bad[66..98].copy_from_slice(&modulus);
        assert_eq!(
            PendingAccumulator::<Eq>::from_bytes(&bad),
            Err(AccumulatorError::Encoding(
                TranscriptError::NonCanonicalScalar
            ))
        );
    }

    #[test]
    fn decide_accepts_only_the_folded_generator() {
        let params = PinnedParams::<Ep>::derive(4).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let accumulator =
            honest_accumulator(&params, random_challenges::<Fq>(4, &mut rng), Fq::ONE);
        assert_eq!(accumulator.clone().decide(&params, budget), Ok(()));
        // G substituted after its challenges were fixed.
        let mut substituted = accumulator.clone();
        substituted.g = (substituted.g.to_curve() + params.params().g()[0]).to_affine();
        assert_eq!(
            substituted.decide(&params, budget),
            Err(AccumulatorError::Rejected)
        );
        let small = PinnedParams::<Ep>::derive(3).expect("params");
        assert_eq!(
            accumulator.clone().decide(&small, budget),
            Err(AccumulatorError::ParamsTooSmall {
                needed: 4,
                available: 3
            })
        );
        // Larger parameters decide through the shared prefix of g.
        let large = PinnedParams::<Ep>::derive(6).expect("params");
        assert_eq!(accumulator.decide(&large, budget), Ok(()));
    }

    #[test]
    fn absorption_binds_every_field() {
        let params = PinnedParams::<Ep>::derive(2).expect("params");
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let accumulator =
            honest_accumulator(&params, random_challenges::<Fq>(2, &mut rng), Fq::from(9));
        let challenge = |accumulator: &PendingAccumulator<Ep>| {
            let mut transcript = TranscriptWriter::<Ep, _>::new(Blake2bHash::new());
            accumulator.absorb_into(&mut transcript).expect("finite G");
            transcript.squeeze_challenge()
        };
        let base = challenge(&accumulator);
        let mut other = accumulator.clone();
        other.transcript_repr += Fq::ONE;
        assert_ne!(challenge(&other), base);
        let mut other = accumulator.clone();
        other.challenges.swap(0, 1);
        assert_ne!(challenge(&other), base);
        let mut other = accumulator;
        other.g = params.params().g()[0];
        assert_ne!(challenge(&other), base);
    }

    #[test]
    fn weights_are_deterministic_and_bind_every_item() {
        let a = batch_item_digest(BATCH_KIND_ACCUMULATOR, b"a");
        let b = batch_item_digest(BATCH_KIND_ACCUMULATOR, b"b");
        assert_ne!(a, batch_item_digest(BATCH_KIND_PROOF, b"a"));
        let weights = batch_weights::<Fq>(&[a, b]);
        assert_eq!(weights[0], Fq::ONE);
        assert_eq!(weights, batch_weights::<Fq>(&[a, b]));
        // Changing an earlier item changes later weights; so does the order.
        assert_ne!(batch_weights::<Fq>(&[b, b])[1], weights[1]);
        assert_ne!(batch_weights::<Fq>(&[b, a])[1], weights[1]);
        assert_ne!(batch_weights::<Fq>(&[a, b, a])[1], weights[1]);
        assert!(batch_weights::<Fq>(&[]).is_empty());
    }

    #[test]
    fn proof_item_body_layout() {
        let body = proof_item_body(&[7; 32], &Fq::from(2), &[vec![Fq::ONE], vec![]], &[9, 9])
            .expect("body");
        let mut expected = vec![7_u8; 32];
        expected.extend_from_slice(&Fq::from(2).to_repr());
        expected.extend_from_slice(&2_u32.to_le_bytes());
        expected.extend_from_slice(&1_u32.to_le_bytes());
        expected.extend_from_slice(&Fq::ONE.to_repr());
        expected.extend_from_slice(&0_u32.to_le_bytes());
        expected.extend_from_slice(&2_u64.to_le_bytes());
        expected.extend_from_slice(&[9, 9]);
        assert_eq!(body, expected);
        // Moving a value between columns changes the body.
        let moved = proof_item_body(&[7; 32], &Fq::from(2), &[vec![], vec![Fq::ONE]], &[9, 9])
            .expect("body");
        assert_ne!(body, moved);
    }

    #[test]
    fn batch_decide_accepts_honest_mixed_k_batches() {
        let params = PinnedParams::<Ep>::derive(5).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let batch: Vec<_> = [2_usize, 5, 3, 5]
            .iter()
            .map(|k| {
                honest_accumulator(
                    &params,
                    random_challenges::<Fq>(*k, &mut rng),
                    Fq::from(*k as u64),
                )
            })
            .collect();
        assert_eq!(batch_decide(batch.clone(), &params, budget), Ok(()));
        assert_eq!(batch_decide(Vec::new(), &params, budget), Ok(()));
        let small = PinnedParams::<Ep>::derive(4).expect("params");
        assert_eq!(
            batch_decide(batch.clone(), &small, budget),
            Err(AccumulatorError::ParamsTooSmall {
                needed: 5,
                available: 4
            })
        );
        // One substituted G rejects the batch.
        let mut bad = batch;
        bad[2].g = params.params().g()[3];
        assert_eq!(
            batch_decide(bad, &params, budget),
            Err(AccumulatorError::BatchRejected)
        );
    }

    /// DEV-09 (spec section 14): batch weights are derived deterministically from every item
    /// instead of `OsRng`, and still reject cancelling errors.
    #[test]
    fn cancelling_errors_are_rejected_under_derived_weights() {
        // MV4: two invalid accumulators whose errors cancel under equal
        // (per-accumulator) weights must still be rejected.
        let params = PinnedParams::<Eq>::derive(3).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let first = honest_accumulator(&params, random_challenges::<Fp>(3, &mut rng), Fp::ONE);
        let second = honest_accumulator(&params, random_challenges::<Fp>(3, &mut rng), Fp::ONE);
        let delta = params.params().g()[5].to_curve();
        let mut bad_first = first;
        bad_first.g = (bad_first.g.to_curve() + delta).to_affine();
        let mut bad_second = second;
        bad_second.g = (bad_second.g.to_curve() - delta).to_affine();
        let batch = vec![bad_first, bad_second];
        // Equal weights (the mutation) would accept.
        assert_eq!(
            decide_weighted(batch.clone(), &[Fp::ONE, Fp::ONE], &params, budget),
            Ok(())
        );
        assert_eq!(
            batch_decide(batch, &params, budget),
            Err(AccumulatorError::BatchRejected)
        );
    }

    #[test]
    fn swapped_histories_are_rejected() {
        let params = PinnedParams::<Ep>::derive(3).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut first = honest_accumulator(&params, random_challenges::<Fq>(3, &mut rng), Fq::ONE);
        let mut second = honest_accumulator(&params, random_challenges::<Fq>(3, &mut rng), Fq::ONE);
        core::mem::swap(&mut first.challenges, &mut second.challenges);
        assert_eq!(
            first.clone().decide(&params, budget),
            Err(AccumulatorError::Rejected)
        );
        assert_eq!(
            batch_decide(vec![first, second], &params, budget),
            Err(AccumulatorError::BatchRejected)
        );
    }

    #[test]
    fn a_zero_weight_falls_back_to_individual_decisions() {
        let params = PinnedParams::<Ep>::derive(2).expect("params");
        let budget = MemoryBudget::DEFAULT;
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let good = honest_accumulator(&params, random_challenges::<Fq>(2, &mut rng), Fq::ONE);
        let mut bad = honest_accumulator(&params, random_challenges::<Fq>(2, &mut rng), Fq::ONE);
        bad.g = params.params().g()[0];
        // With a zero weight the bad item would vanish from the sum; the
        // fallback decides it individually.
        assert_eq!(
            decide_weighted(
                vec![good.clone(), bad],
                &[Fq::ONE, Fq::ZERO],
                &params,
                budget
            ),
            Err(AccumulatorError::RejectedItem { index: 1 })
        );
        assert_eq!(
            decide_weighted(
                vec![good.clone(), good],
                &[Fq::ONE, Fq::ZERO],
                &params,
                budget
            ),
            Ok(())
        );
    }

    #[test]
    fn errors_map_and_display() {
        assert_eq!(
            AccumulatorError::from(IpaError::ParamsTooSmall {
                needed: 2,
                available: 1
            }),
            AccumulatorError::ParamsTooSmall {
                needed: 2,
                available: 1
            }
        );
        assert_eq!(
            AccumulatorError::from(IpaError::OpeningFailed),
            AccumulatorError::Rejected
        );
        assert!(
            AccumulatorError::RejectedItem { index: 4 }
                .to_string()
                .contains('4')
        );
    }
}
