//! Canonical accumulator claims and explicit, checked fold-slot construction.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};
use iroha_plonk::{
    pcs::ipa::{PinnedParams, commit::msm_complete_cancellable, fold_scalars},
    transcript::{decode_point, decode_scalar, encode_point},
};

use crate::{ACCUMULATOR_BYTES, Error, K, K_U32};

/// A canonical transported claim, never an acceptance on its own.
#[must_use = "a canonical accumulator is undecided; call decide"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorT<C: PastaCurve> {
    g: C::AffineExt,
    challenges: [C::ScalarExt; K],
}

impl<C: PastaCurve> AccumulatorT<C> {
    /// Checks that G is finite and all sixteen challenges are nonzero.
    ///
    /// # Errors
    /// Identity G or a zero challenge is rejected.
    pub fn new(g: C::AffineExt, challenges: [C::ScalarExt; K]) -> Result<Self, Error> {
        let input = FoldInput::<C>::from_normalized(g, K_U32, challenges)?;
        Ok(Self {
            g: input.g,
            challenges: input.challenges,
        })
    }

    /// Decodes exactly `G || u[0..16]` for the statically selected curve.
    ///
    /// # Errors
    /// Wrong length, noncanonical/identity G, noncanonical scalars or zero challenges.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ACCUMULATOR_BYTES {
            return Err(Error::Length {
                expected: ACCUMULATOR_BYTES,
                actual: bytes.len(),
            });
        }
        let g = decode_point::<C>(&message(bytes, 0)?)?;
        let mut challenges = [C::ScalarExt::ZERO; K];
        for (round, challenge) in challenges.iter_mut().enumerate() {
            *challenge = decode_scalar(&message(bytes, (round + 1) * 32)?)?;
        }
        Self::new(g, challenges)
    }

    /// The exact fixed-width accumulator encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ACCUMULATOR_BYTES] {
        let mut bytes = [0; ACCUMULATOR_BYTES];
        bytes[..32].copy_from_slice(&encode_point::<C>(&self.g));
        for (chunk, challenge) in bytes[32..].chunks_exact_mut(32).zip(self.challenges) {
            chunk.copy_from_slice(&challenge.to_repr());
        }
        bytes
    }

    /// The claimed folded generator.
    #[must_use]
    pub const fn g(&self) -> &C::AffineExt {
        &self.g
    }

    /// The checked, nonzero, transcript-ordered challenge vector.
    #[must_use]
    pub const fn challenges(&self) -> &[C::ScalarExt; K] {
        &self.challenges
    }

    /// An explicit source-k16 fold input retaining the undecided obligation.
    pub fn as_input(&self) -> FoldInput<C> {
        FoldInput {
            g: self.g,
            source_k: K_U32,
            challenges: self.challenges,
        }
    }

    /// Accepts only when G is the complete-kernel commitment to `s(u)`.
    ///
    /// # Errors
    /// Insufficient pinned parameters or an undecidable claim.
    pub fn decide(&self, params: &PinnedParams<C>, budget: MemoryBudget) -> Result<(), Error> {
        self.decide_cancellable(params, budget, None)
    }
    /// Decide with an explicit operation signal; cancellation has no verdict.
    /// # Errors
    /// As [`Self::decide`], or cancellation.
    pub fn decide_cancellable(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        self.as_input()
            .decide_cancellable(params, budget, cancellation)
    }

    /// Constructs the pinned trivial claim `(sum g_i, [1;16])` explicitly.
    ///
    /// # Errors
    /// Insufficient pinned parameters or an identity commitment.
    pub fn trivial(params: &PinnedParams<C>, budget: MemoryBudget) -> Result<Self, Error> {
        Self::trivial_cancellable(params, budget, None)
    }
    /// Construct the pinned trivial claim with an explicit operation signal.
    /// # Errors
    /// As [`Self::trivial`], or cooperative cancellation.
    pub fn trivial_cancellable(
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let challenges = [C::ScalarExt::ONE; K];
        let g = expected_generator(params, &challenges, budget, cancellation)?;
        Self::new(g, challenges)
    }
}

/// A canonical source claim and its checked zero-prefix padding to k16.
///
/// Construction checks syntax and normalization, not the deferred equation.
/// It does not authorize an Accept slot in a consuming circuit.
#[must_use = "a fold input retains an obligation; fold and decide it"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldInput<C: PastaCurve> {
    g: C::AffineExt,
    source_k: u32,
    challenges: [C::ScalarExt; K],
}

impl<C: PastaCurve> FoldInput<C> {
    /// Checks a source opening with one to sixteen nonzero challenges, then
    /// adds the required leading zero prefix. G must be finite.
    ///
    /// # Errors
    /// Unsupported source k, identity G or a zero source challenge.
    pub fn from_opening(g: C::AffineExt, source: &[C::ScalarExt]) -> Result<Self, Error> {
        if source.is_empty() || source.len() > K {
            return Err(Error::SourceK);
        }
        let mut challenges = [C::ScalarExt::ZERO; K];
        challenges[K - source.len()..].copy_from_slice(source);
        Self::from_normalized(
            g,
            u32::try_from(source.len()).map_err(|_| Error::SourceK)?,
            challenges,
        )
    }

    /// Checks an already normalized vector: exactly `16-k` leading zeros
    /// followed by k nonzero values. Interior or suffix zeros are forbidden.
    ///
    /// # Errors
    /// Unsupported k, identity G, malformed padding or a zero real challenge.
    pub fn from_normalized(
        g: C::AffineExt,
        source_k: u32,
        challenges: [C::ScalarExt; K],
    ) -> Result<Self, Error> {
        if !(1..=K_U32).contains(&source_k) {
            return Err(Error::SourceK);
        }
        if bool::from(g.is_identity()) {
            return Err(Error::Encoding(
                iroha_plonk::transcript::TranscriptError::IdentityPoint,
            ));
        }
        let prefix = K - source_k as usize;
        if challenges[..prefix]
            .iter()
            .any(|value| !bool::from(value.is_zero()))
        {
            return Err(Error::Padding);
        }
        for (round, value) in challenges.iter().enumerate().skip(prefix) {
            if bool::from(value.is_zero()) {
                return Err(Error::ZeroChallenge { round });
            }
        }
        Ok(Self {
            g,
            source_k,
            challenges,
        })
    }

    /// The finite claimed generator.
    #[must_use]
    pub const fn g(&self) -> &C::AffineExt {
        &self.g
    }

    /// The source proof's k, included in the fold transcript.
    #[must_use]
    pub const fn source_k(&self) -> u32 {
        self.source_k
    }

    /// The exact normalized sixteen-element vector included in the transcript.
    #[must_use]
    pub const fn challenges(&self) -> &[C::ScalarExt; K] {
        &self.challenges
    }

    /// Decides the source prefix with an independent complete MSM kernel.
    ///
    /// # Errors
    /// Insufficient pinned parameters or an undecidable source claim.
    pub fn decide(&self, params: &PinnedParams<C>, budget: MemoryBudget) -> Result<(), Error> {
        self.decide_cancellable(params, budget, None)
    }
    /// Decide with an explicit operation signal; cancellation has no verdict.
    /// # Errors
    /// As [`Self::decide`], or cancellation.
    pub fn decide_cancellable(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let source = &self.challenges[K - self.source_k as usize..];
        if expected_generator(params, source, budget, cancellation)? == self.g {
            Ok(())
        } else {
            Err(Error::Undecidable)
        }
    }

    /// Computes and checks a correction with the same source k and challenges.
    /// Returns an error if the original already decides. This only supplies
    /// the witness; the consuming circuit must authorize Corrected mode.
    ///
    /// # Errors
    /// Insufficient parameters, an identity replacement or an already deciding original.
    pub fn corrected(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
    ) -> Result<CorrectedInput<C>, Error> {
        self.corrected_cancellable(params, budget, None)
    }
    /// Correct with an explicit signal; cancellation never proves invalidity.
    /// # Errors
    /// As [`Self::corrected`], or cancellation.
    pub fn corrected_cancellable(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<CorrectedInput<C>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let source = &self.challenges[K - self.source_k as usize..];
        let corrected = expected_generator(params, source, budget, cancellation)?;
        if corrected == self.g {
            return Err(Error::NotCorrected);
        }
        Ok(CorrectedInput {
            original: self.clone(),
            replacement: Self::from_normalized(corrected, self.source_k, self.challenges)?,
        })
    }
}

/// A checked correction retaining both commitments for the consuming relation.
#[must_use = "the consuming relation must bind the original and corrected claims"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectedInput<C: PastaCurve> {
    original: FoldInput<C>,
    replacement: FoldInput<C>,
}

impl<C: PastaCurve> CorrectedInput<C> {
    /// The original, independently established undecidable claim.
    pub const fn original(&self) -> &FoldInput<C> {
        &self.original
    }

    /// The deciding replacement with identical k and challenges and distinct G.
    pub const fn replacement(&self) -> &FoldInput<C> {
        &self.replacement
    }
}

fn expected_generator<C: PastaCurve>(
    params: &PinnedParams<C>,
    challenges: &[C::ScalarExt],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<C::AffineExt, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    params
        .require_k(u32::try_from(challenges.len()).map_err(|_| Error::SourceK)?)
        .map_err(Error::Parameters)?;
    let coefficients = fold_scalars(challenges, C::ScalarExt::ONE);
    let generators = params
        .params()
        .g()
        .get(..coefficients.len())
        .ok_or(Error::SourceK)?;
    Ok(msm_complete_cancellable::<C>(
        &coefficients,
        generators,
        budget,
        &iroha_pasta::msm::SharedMemoryBudget::process_default(),
        cancellation,
    )?
    .to_affine())
}

pub fn message(bytes: &[u8], offset: usize) -> Result<[u8; 32], Error> {
    bytes
        .get(offset..offset + 32)
        .and_then(|value| value.try_into().ok())
        .ok_or(Error::Encoding(
            iroha_plonk::transcript::TranscriptError::ProofTruncated,
        ))
}
