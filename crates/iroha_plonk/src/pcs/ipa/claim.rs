//! A pending generator equality, independent of descriptor/transcript provenance.
//!
//! Recursive statements bind provenance through their obligation ledger and VK
//! checks. This value alone is never a proof or an acceptance verdict.

use super::{IpaError, PinnedParams, fold_scalars};
use ff::Field;
use group::prime::PrimeCurveAffine;
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
    pub(crate) fn new(
        k: u32,
        g: C::AffineExt,
        challenges: Vec<C::ScalarExt>,
    ) -> Result<Self, IpaError> {
        if challenges.len() != k as usize || bool::from(g.is_identity()) {
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
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        params.require_k(self.k)?;
        let s = fold_scalars(&self.challenges, C::ScalarExt::ONE);
        let expected = super::commit::msm_complete_cancellable::<C>(
            &s,
            &params.params().g()[..s.len()],
            budget,
            &iroha_pasta::msm::SharedMemoryBudget::process_default(),
            cancellation,
        )?
        .to_affine();
        if expected == self.g {
            Ok(())
        } else {
            Err(IpaError::OpeningFailed)
        }
    }
}
