//! A pending generator equality, independent of descriptor/transcript provenance,
//! and the decided own opening of a fully verified proof.
//!
//! Recursive statements bind provenance through their obligation ledger and VK
//! checks. A [`GeneratorClaim`] alone is never a proof or an acceptance verdict.

use super::{IpaError, PinnedParams};
use ff::Field;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};

/// The undecided equality `G = <s(u), g[0..2^k)>`.
#[must_use = "a generator claim must be decided or folded into another decided claim"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratorClaim<C: PastaCurve> {
    k: u32,
    g: C::AffineExt,
    challenges: Vec<C::ScalarExt>,
}
impl<C: PastaCurve> GeneratorClaim<C> {
    /// Clears this claim when held inside a private succinct-frame owner.
    pub(crate) fn clear_private_owner(&mut self) {
        fn field<F: iroha_pasta::PastaField>(value: &mut F) {
            value.zeroize();
        }
        fn point<A: iroha_pasta::PastaAffine>(value: &mut A) {
            value.zeroize();
        }
        point(&mut self.g);
        for value in &mut self.challenges {
            field(value);
        }
    }

    pub(crate) fn new(
        k: u32,
        g: C::AffineExt,
        challenges: Vec<C::ScalarExt>,
    ) -> Result<Self, IpaError> {
        if challenges.len() != k as usize {
            return Err(IpaError::OpeningFailed);
        }
        for (round, value) in challenges.iter().enumerate() {
            if bool::from(value.is_zero()) {
                return Err(IpaError::ZeroChallenge { round });
            }
        }
        Ok(Self { k, g, challenges })
    }
    /// The number of IPA rounds.
    #[must_use]
    pub const fn k(&self) -> u32 {
        self.k
    }
    /// The claimed folded generator.
    #[must_use]
    pub const fn g(&self) -> &C::AffineExt {
        &self.g
    }
    /// The nonzero IPA challenges in top-index-bit order.
    #[must_use]
    pub fn challenges(&self) -> &[C::ScalarExt] {
        &self.challenges
    }
    /// Decides the generator equality using complete curve arithmetic.
    ///
    /// # Errors
    /// Insufficient parameters or a false generator claim.
    pub fn decide(&self, params: &PinnedParams<C>, budget: MemoryBudget) -> Result<(), IpaError> {
        self.decide_cancellable(params, budget, None)
    }
    /// Decides with explicit cooperative cancellation and no partial verdict.
    ///
    /// # Errors
    /// As [`Self::decide`], or [`IpaError::Cancelled`].
    pub fn decide_cancellable(
        &self,
        params: &PinnedParams<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), IpaError> {
        crate::verification_counters::record_decide();
        // `k` is the challenge count (checked at construction), so the owner's
        // decide checks cancellation, then this claim's `k`, then the equality.
        params.decide_folded_generator_cancellable(&self.challenges, &self.g, budget, cancellation)
    }
}

/// The own opening `G = <s(u), g[0..2^k)>` of a proof that production full
/// verification accepted, read from the same proof bytes in the same call.
///
/// Production full verification constructs this value only after the opening
/// equation held with the decided `G`. It may be retained for exact-input reuse
/// by [`crate::verifier::verify_full_opening_cancellable`]; it is not a transported
/// or prover-supplied claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOpening<C: PastaCurve> {
    k: u32,
    g: C::AffineExt,
    challenges: Vec<C::ScalarExt>,
}
impl<C: PastaCurve> VerifiedOpening<C> {
    pub(crate) fn new(k: u32, g: C::AffineExt, challenges: Vec<C::ScalarExt>) -> Self {
        Self { k, g, challenges }
    }
    /// The number of IPA rounds.
    #[must_use]
    pub const fn k(&self) -> u32 {
        self.k
    }
    /// The decided folded generator.
    #[must_use]
    pub const fn g(&self) -> &C::AffineExt {
        &self.g
    }
    /// The IPA challenges in top-index-bit order.
    #[must_use]
    pub fn challenges(&self) -> &[C::ScalarExt] {
        &self.challenges
    }
    /// Whether `claim` is exactly this opening: the same `k`, `G` and every challenge.
    #[must_use]
    pub fn matches(&self, claim: &GeneratorClaim<C>) -> bool {
        self.k == claim.k && self.g == claim.g && self.challenges == claim.challenges
    }
}
