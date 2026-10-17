//! Runtime-only coordinator for authorized Parliament timelock release.

use std::sync::Arc;

use iroha_data_model::governance::types::BallotAttemptId;
#[cfg(test)]
use iroha_data_model::isi::governance::{
    ParliamentFinalizeOpenedBallotV1, ParliamentLifecycleTransitionV1,
    ParliamentTleFinalReleaseSignatureV1,
};
use thiserror::Error;

use crate::state::StateReadOnly;

use super::{
    AuthorizedTleReleaseContextV1, TlePartialReleaseShareV1, TlePartialReleaseSignerV1,
    TleReleaseAuthorizationErrorV1, authorize_parliament_tle_release_v1,
};

/// Runtime-only coordinator for one node's Parliament TLE signing share.
///
/// The coordinator deliberately has no serialization or `Debug` implementation.
/// It owns only an optional process-local reference to the deployment signer;
/// the private share remains inside that signer. Operational callers submit a
/// [`BallotAttemptId`] and committed state view rather than a caller-selected
/// release identity. Core constructs the opaque authorization before the signer
/// is invoked.
#[derive(Clone, Default)]
pub struct TleReleaseCoordinatorV1 {
    signer: Option<Arc<dyn TlePartialReleaseSignerV1>>,
}

impl TleReleaseCoordinatorV1 {
    /// Construct a fail-closed coordinator without a release-share signer.
    #[must_use]
    pub const fn without_signer() -> Self {
        Self { signer: None }
    }

    /// Attach a deployment-owned runtime signer.
    ///
    /// The signer object is not exposed again and must keep all private DKG
    /// material behind its own isolated or zeroizing process boundary.
    #[must_use]
    pub fn from_signer(signer: Arc<dyn TlePartialReleaseSignerV1>) -> Self {
        Self {
            signer: Some(signer),
        }
    }

    /// Return whether this process has a deployment-owned signer attached.
    ///
    /// This reveals no key-session, participant, or secret-share metadata.
    #[must_use]
    pub const fn signer_is_available(&self) -> bool {
        self.signer.is_some()
    }

    /// Authorize and request this node's proof-carrying partial release.
    ///
    /// Core reads one committed view, joins and revalidates all Parliament and
    /// timed-OVN bindings, and constructs the opaque authorization before this
    /// method enters the deployment signer. The returned public partial is then
    /// independently verified against that authorization.
    ///
    /// An HTTP or RPC adapter exposing this method must additionally authenticate
    /// and rate-limit the operator. It must accept only `ballot_attempt_id`; it
    /// must not accept a reconstructed identity, finalized height, transcript,
    /// participant index, or secret material from the request.
    ///
    /// # Errors
    ///
    /// Returns a closed, payload-free error when Core rejects the committed
    /// release state, no signer is installed, the signer fails, or the signer's
    /// public output does not verify.
    pub fn request_partial_release(
        &self,
        state: &impl StateReadOnly,
        ballot_attempt_id: BallotAttemptId,
    ) -> Result<TlePartialReleaseShareV1, TleReleaseCoordinatorErrorV1> {
        let context = authorize_parliament_tle_release_v1(state, ballot_attempt_id)?;
        self.request_authorized_partial_release(&context)
    }

    /// Request and independently verify a share for an opaque Core authorization.
    ///
    /// This narrower method supports trusted in-process adapters that already
    /// called [`authorize_parliament_tle_release_v1`]. External code cannot
    /// construct the authorization type directly.
    ///
    /// # Errors
    ///
    /// Returns a closed, payload-free error when the signer is unavailable,
    /// fails, or returns a share that does not verify against the exact context.
    pub fn request_authorized_partial_release(
        &self,
        context: &AuthorizedTleReleaseContextV1,
    ) -> Result<TlePartialReleaseShareV1, TleReleaseCoordinatorErrorV1> {
        let signer = self
            .signer
            .as_ref()
            .ok_or(TleReleaseCoordinatorErrorV1::SignerUnavailable)?;
        // Provider diagnostics are deliberately discarded. An external adapter
        // is not trusted to keep its error text free of handles or secret metadata.
        let partial = signer
            .sign_partial_release(context)
            .map_err(|_| TleReleaseCoordinatorErrorV1::SignerFailed)?;
        context
            .session()
            .verify_partial_release(context.identity(), context.finalized_height(), &partial)
            .map_err(|_| TleReleaseCoordinatorErrorV1::InvalidSignerOutput)?;
        Ok(partial)
    }

    #[cfg(test)]
    /// Canonically combine public partials for one Core-authorized ballot.
    ///
    /// Input order is not trusted. The coordinator sorts by the frozen one-based
    /// participant index, rejects duplicate seats, verifies every supplied proof,
    /// combines the canonical set, and final-verifies the unique group signature.
    /// It returns the existing Parliament transition payload; transaction signing,
    /// authority checks, replay protection, and state mutation remain on the
    /// ordinary authenticated instruction path.
    ///
    /// # Errors
    ///
    /// Returns a closed, payload-free error when the subset is duplicated,
    /// insufficient, oversized, malformed, or cross-bound.
    pub fn combine_authorized_partial_releases(
        &self,
        context: &AuthorizedTleReleaseContextV1,
        partials: &[TlePartialReleaseShareV1],
    ) -> Result<ParliamentLifecycleTransitionV1, TleReleaseCoordinatorErrorV1> {
        let mut canonical = partials.to_vec();
        canonical.sort_by_key(|partial| partial.participant_index);
        if canonical
            .windows(2)
            .any(|pair| pair[0].participant_index == pair[1].participant_index)
        {
            return Err(TleReleaseCoordinatorErrorV1::InvalidPartialSet);
        }
        let final_release = context
            .session()
            .combine_partial_releases(context.identity(), context.finalized_height(), &canonical)
            .map_err(|_| TleReleaseCoordinatorErrorV1::InvalidPartialSet)?;
        context
            .session()
            .verify_final_release(
                context.identity(),
                context.finalized_height(),
                &final_release,
            )
            .map_err(|_| TleReleaseCoordinatorErrorV1::InvalidFinalRelease)?;

        Ok(ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
            ParliamentFinalizeOpenedBallotV1 {
                ballot_attempt_id: context.ballot_attempt_id(),
                final_release: ParliamentTleFinalReleaseSignatureV1 {
                    key_session_id: final_release.key_session_id,
                    identity_digest: final_release.identity_digest,
                    signature: final_release.signature,
                },
            },
        ))
    }
}

/// Closed, payload-free failure classes for runtime TLE release coordination.
///
/// Signer-provided strings and cryptographic input bytes are intentionally not
/// retained, serialized, or exposed through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleReleaseCoordinatorErrorV1 {
    /// Core rejected the committed Parliament release state.
    #[error("Core did not authorize the Parliament TLE release")]
    Authorization(#[from] TleReleaseAuthorizationErrorV1),
    /// No deployment-owned signer was attached to this node.
    #[error("Parliament TLE partial-release signer is unavailable")]
    SignerUnavailable,
    /// The deployment signer could not produce a share.
    #[error("Parliament TLE partial-release signer failed")]
    SignerFailed,
    /// The deployment signer returned public material that failed verification.
    #[error("Parliament TLE partial-release signer returned invalid output")]
    InvalidSignerOutput,
    /// The public partial set was noncanonical, invalid, or cross-bound.
    #[error("Parliament TLE partial-release set is invalid")]
    InvalidPartialSet,
    /// The combined final release failed independent verification.
    #[error("Parliament TLE final release is invalid")]
    InvalidFinalRelease,
}
