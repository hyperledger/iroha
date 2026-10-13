//! Adaptive threshold-BLS verification for Parliament timelock release.
//!
//! A [`TleKeySessionId`] names the long-lived, independently generated TLE
//! threshold key. It is deliberately distinct from the per-ballot
//! `governance::TleSessionId`. The persisted state in this module contains only
//! public DKG broadcasts, verification shares, transcript bindings, and public
//! release signatures. Dealer polynomials, recipient contributions, aggregate
//! signing shares, and proof nonces have no serializable representation here.
//!
//! Release shares are admitted only for the exact [`TleReleaseIdentityV1`] and
//! only after its target finalized height. Combining a canonical threshold
//! subset produces the unique standard BLS group signature; no signer bitmap
//! enters the final release record.
//!
//! “Adaptive” names the three-scalar Das--Ren protocol profile. It does not
//! assert a generic or standard-assumption adaptive-security theorem; the
//! precise model, cumulative corruption bound, lack of proactive refresh, and
//! 2026 key-uniqueness caveat are documented by
//! [`iroha_crypto::threshold_bls`].

use iroha_crypto::{
    threshold_bls::{AdaptiveThresholdBlsSecretShare, TleReleasePurpose},
    tle::TleReleaseIdentityV1,
};
pub(crate) use iroha_data_model::governance::types::TleKeySessionId;
use iroha_data_model::governance::types::{
    BallotAttemptId, BallotAttemptStatusV1, GovernanceAttemptId, GovernanceAttemptStatusV1,
};
use mv::storage::StorageReadOnly;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    governance::timed_ovn::{
        TimedOvnEvidenceError, TimedOvnLifecycleStateV1, TimedOvnReleaseIdentityPublicV1,
    },
    state::{StateReadOnly, WorldReadOnly as _},
};

mod casting;
mod custody;
#[cfg(feature = "test-network-parliament-signers")]
#[doc(hidden)]
pub mod parliament_test_network_signer;
mod runtime;
pub(crate) use casting::derive_parliament_timed_ovn_casting_snapshot_v1;
pub use casting::{
    AuthorizedTimedOvnCastingContextV1, authorize_parliament_timed_ovn_casting_context_v1,
};
pub use custody::{RuntimeTleReleaseShareCustodyV1, TleReleaseShareCustodyErrorV1};
#[cfg(test)]
pub(crate) use iroha_core_timed_ovn::casting::{
    ParliamentTimedOvnCastingPhaseV1, TimedOvnCastingAuthorizationErrorV1,
};
pub use runtime::{TleReleaseCoordinatorErrorV1, TleReleaseCoordinatorV1};

pub(crate) use iroha_core_timed_ovn::tle::*;

/// Constructor-authenticated authorization for one committed TLE release share.
///
/// Callers cannot construct this type directly. Core issues it only for a
/// replay-valid, sealed timed-OVN corpus whose Parliament ballot has already
/// consumed its release beacon and entered `Opening`. The current finalized
/// height must also be within the ballot's inclusive opening window.
#[derive(Debug, Clone)]
pub struct AuthorizedTleReleaseContextV1 {
    ballot_attempt_id: BallotAttemptId,
    opening_deadline_height: u64,
    finalized_height: u64,
    public_release_identity: TimedOvnReleaseIdentityPublicV1,
    identity: TleReleaseIdentityV1,
    session: ValidatedTleKeySessionV1,
}

impl AuthorizedTleReleaseContextV1 {
    /// Return the exact committed ballot attempt authorized for release.
    #[must_use]
    pub const fn ballot_attempt_id(&self) -> BallotAttemptId {
        self.ballot_attempt_id
    }

    /// Return the finalized height at which Core authorized the share.
    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Return the inclusive last height at which opening may complete.
    #[must_use]
    pub const fn opening_deadline_height(&self) -> u64 {
        self.opening_deadline_height
    }

    /// Borrow the bounded public release identity stored with timed-OVN evidence.
    #[must_use]
    pub const fn public_release_identity(&self) -> &TimedOvnReleaseIdentityPublicV1 {
        &self.public_release_identity
    }

    /// Borrow the fully reconstructed threshold-signing identity.
    #[must_use]
    pub const fn identity(&self) -> &TleReleaseIdentityV1 {
        &self.identity
    }

    /// Borrow the proof-revalidated public threshold-key session.
    #[must_use]
    pub const fn session(&self) -> &ValidatedTleKeySessionV1 {
        &self.session
    }

    /// Build the exact public-only request sent to an authenticated runtime broker.
    ///
    /// This is the only production constructor for the broker projection. The
    /// returned data is not itself an authorization capability; the broker must
    /// scope admission to the authenticated daemon connection and revalidate it
    /// before entering a projected signer.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the fixed V1 application payload width or
    /// identity digest cannot be reproduced from this Core authorization.
    pub fn broker_projection_v1(
        &self,
    ) -> Result<AuthorizedTleReleaseProjectionV1, TleReleaseProjectionErrorV1> {
        let identity_payload: [u8; TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1] = self
            .identity
            .payload_bytes()
            .try_into()
            .map_err(|_| TleReleaseProjectionErrorV1::IdentityPayloadMismatch)?;
        let identity_digest = self
            .session
            .validate_release_identity(&self.identity, self.finalized_height)?;
        Ok(AuthorizedTleReleaseProjectionV1 {
            version: TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1,
            ballot_attempt_id: self.ballot_attempt_id,
            opening_deadline_height: self.opening_deadline_height,
            finalized_height: self.finalized_height,
            key_session: self.session.public_state().clone(),
            public_release_identity: self.public_release_identity,
            identity_payload,
            identity_digest,
        })
    }
}

/// Authorize a TLE release from one point-in-time committed state view.
///
/// This is the only public constructor for [`AuthorizedTleReleaseContextV1`].
/// It joins the exact Parliament attempt, ballot, timed-OVN lifecycle, and TLE
/// transcript and then replays all public cryptographic evidence. In
/// particular, an `AwaitingRelease` ballot is not enough: the committed release
/// beacon must already have advanced it to `Opening`.
///
/// # Errors
///
/// Returns [`TleReleaseAuthorizationErrorV1`] when any state component is
/// absent, terminal, early, expired, malformed, or cross-bound.
pub fn authorize_parliament_tle_release_v1(
    state: &impl StateReadOnly,
    ballot_attempt_id: BallotAttemptId,
) -> Result<AuthorizedTleReleaseContextV1, TleReleaseAuthorizationErrorV1> {
    let finalized_height = u64::try_from(state.height())
        .map_err(|_| TleReleaseAuthorizationErrorV1::HeightOverflow)?;
    let world = state.world();
    let lifecycle = world
        .timed_ovn_evidence()
        .get(&ballot_attempt_id)
        .ok_or(TleReleaseAuthorizationErrorV1::MissingTimedOvnEvidence)?;
    if lifecycle.ballot_attempt_id() != *ballot_attempt_id.as_bytes() {
        return Err(TleReleaseAuthorizationErrorV1::BindingMismatch);
    }
    let TimedOvnLifecycleStateV1::Sealed(sealed) = lifecycle else {
        return Err(TleReleaseAuthorizationErrorV1::TimedOvnNotSealed);
    };
    let key_session_id = lifecycle.tle_key_session_id();
    let session = world
        .tle_key_sessions()
        .get(&key_session_id)
        .cloned()
        .ok_or(TleReleaseAuthorizationErrorV1::MissingKeySession)?
        .validate()?;
    let validated_evidence = sealed.clone().validate(&session)?;
    let identity = *validated_evidence.release_identity();
    let public_release_identity = sealed.release_identity;

    let governance_attempt_id = GovernanceAttemptId::new(lifecycle.session().governance_attempt_id);
    let attempt = world
        .parliament_attempts()
        .get(&governance_attempt_id)
        .ok_or(TleReleaseAuthorizationErrorV1::MissingGovernanceAttempt)?;
    attempt
        .validate()
        .map_err(|_| TleReleaseAuthorizationErrorV1::InvalidParliamentState)?;
    if attempt.attempt().status != GovernanceAttemptStatusV1::Active {
        return Err(TleReleaseAuthorizationErrorV1::GovernanceAttemptNotActive);
    }
    let ballot = attempt
        .ballot(&ballot_attempt_id)
        .ok_or(TleReleaseAuthorizationErrorV1::MissingBallot)?;
    if ballot.attempt().status != BallotAttemptStatusV1::Opening {
        return Err(TleReleaseAuthorizationErrorV1::BallotNotOpening);
    }

    let target_height = lifecycle.target_finalized_height();
    if attempt.proposal_content_id().as_bytes() != &lifecycle.session().proposal_content_id
        || ballot.attempt().body_instance_id.as_bytes() != &lifecycle.session().body_instance_id
        || ballot.tle_key_session_id() != Some(key_session_id)
        || ballot.release_height() != Some(target_height)
        || identity.governance_attempt_id() != governance_attempt_id.as_bytes()
        || identity.body_instance_id() != ballot.attempt().body_instance_id.as_bytes()
        || identity.ballot_attempt_id() != ballot_attempt_id.as_bytes()
        || identity.target_finalized_height() != target_height
    {
        return Err(TleReleaseAuthorizationErrorV1::BindingMismatch);
    }
    if finalized_height < target_height {
        return Err(TleReleaseAuthorizationErrorV1::ReleaseHeightNotReached);
    }
    let opening_deadline_height = ballot.opening_deadline_height();
    if finalized_height > opening_deadline_height {
        return Err(TleReleaseAuthorizationErrorV1::OpeningDeadlinePassed);
    }
    session.validate_release_identity(&identity, finalized_height)?;

    Ok(AuthorizedTleReleaseContextV1 {
        ballot_attempt_id,
        opening_deadline_height,
        finalized_height,
        public_release_identity,
        identity,
        session,
    })
}

/// Fail-closed reasons Core could not authorize a runtime TLE release share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleReleaseAuthorizationErrorV1 {
    /// The committed state height cannot be represented by the v1 wire type.
    #[error("committed state height does not fit the TLE release protocol")]
    HeightOverflow,
    /// No public timed-OVN lifecycle exists for the requested ballot.
    #[error("timed-OVN evidence is missing for the ballot")]
    MissingTimedOvnEvidence,
    /// The timed-OVN lifecycle has not reached its complete sealed corpus.
    #[error("timed-OVN evidence is not sealed for release")]
    TimedOvnNotSealed,
    /// The referenced public TLE key transcript is absent.
    #[error("TLE key session is missing")]
    MissingKeySession,
    /// The embedded governance attempt is absent.
    #[error("Parliament governance attempt is missing")]
    MissingGovernanceAttempt,
    /// The embedded ballot attempt is absent from its governance attempt.
    #[error("Parliament ballot attempt is missing")]
    MissingBallot,
    /// The reducer state failed its complete deterministic invariant check.
    #[error("Parliament reducer state is invalid")]
    InvalidParliamentState,
    /// The governance attempt is terminal rather than active.
    #[error("Parliament governance attempt is not active")]
    GovernanceAttemptNotActive,
    /// The release beacon has not advanced this ballot into `Opening`.
    #[error("Parliament ballot is not in the opening phase")]
    BallotNotOpening,
    /// Two committed objects disagree on an immutable release binding.
    #[error("Parliament TLE release state has inconsistent bindings")]
    BindingMismatch,
    /// The target finalized height has not yet been reached.
    #[error("TLE release target finalized height has not been reached")]
    ReleaseHeightNotReached,
    /// The inclusive aggregate-opening deadline has elapsed.
    #[error("Parliament aggregate-opening deadline has passed")]
    OpeningDeadlinePassed,
    /// The public threshold-key transcript is malformed or inconsistent.
    #[error(transparent)]
    KeySession(#[from] TleReleaseAdapterError),
    /// The sealed timed-OVN corpus does not replay exactly.
    #[error(transparent)]
    TimedOvn(#[from] TimedOvnEvidenceError),
}

/// Runtime-only owner capable of producing one authorized adaptive TLE release share.
///
/// Implementations are injected by the deployment's secure runtime boundary.
/// Accepting only [`AuthorizedTleReleaseContextV1`] keeps caller-supplied
/// identities outside the signing boundary and prevents a node from becoming
/// a generic threshold-BLS signing oracle. Private DKG components must never
/// enter configuration, World state, logs, or wire DTOs.
///
/// A production provider may own multiple retiring and active key-session
/// shares. It must select only by the authorized context's exact
/// `key_session_id` and retain every retiring share through the last committed
/// ballot opening deadline that references it. The single-session
/// [`InMemoryTlePartialReleaseSignerV1`] is only a software adapter and test
/// provider, not a global key-rotation policy.
pub trait TlePartialReleaseSignerV1: Send + Sync {
    /// Attest non-secret custody for one exact public session and participant seat.
    ///
    /// Implementations must perform a live lookup in the same custody object later
    /// used by [`Self::sign_partial_release`]; constructing an attestation from
    /// public state alone is not proof of custody.
    ///
    /// # Errors
    ///
    /// Returns a closed capability error when the provider cannot perform the
    /// lookup or does not own the exact session and seat.
    fn attest_partial_release_capability(
        &self,
        session: &ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1>;

    /// Sign the exact Core-authorized committed future identity.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic when the requested key session is not
    /// owned by this provider, the target height has not been finalized, or
    /// the secure runtime cannot produce a valid share.
    fn sign_partial_release(
        &self,
        context: &AuthorizedTleReleaseContextV1,
    ) -> Result<TlePartialReleaseShareV1, String>;
}

/// Non-secret readiness attestation for one runtime provider's exact TLE share.
///
/// The fields identify only public transcript material and a public one-based
/// committee seat. Callers must exact-match the returned value against their
/// committed session and expected local seat. The value is intentionally not
/// serializable as a ledger object; broker adapters use their own authenticated
/// runtime wire envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlePartialReleaseCapabilityAttestationV1 {
    key_session_id: TleKeySessionId,
    transcript_hash: [u8; 32],
    participant_index: u16,
}

impl TlePartialReleaseCapabilityAttestationV1 {
    /// Construct the exact public attestation expected for a validated session seat.
    ///
    /// # Errors
    ///
    /// Returns [`TlePartialReleaseCapabilityErrorV1::InvalidRequest`] when the
    /// one-based seat does not exist in the validated public transcript.
    pub fn for_validated_session(
        session: &ValidatedTleKeySessionV1,
        participant_index: u16,
    ) -> Result<Self, TlePartialReleaseCapabilityErrorV1> {
        if !session
            .public_state()
            .public_shares
            .iter()
            .any(|share| share.index == participant_index)
        {
            return Err(TlePartialReleaseCapabilityErrorV1::InvalidRequest);
        }
        Ok(Self {
            key_session_id: session.public_state().key_session_id,
            transcript_hash: session.public_state().transcript_hash,
            participant_index,
        })
    }

    /// Return the exact public key-session identifier.
    #[must_use]
    pub const fn key_session_id(self) -> TleKeySessionId {
        self.key_session_id
    }

    /// Return the exact validated public-transcript hash.
    #[must_use]
    pub const fn transcript_hash(self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Return the exact one-based participant seat.
    #[must_use]
    pub const fn participant_index(self) -> u16 {
        self.participant_index
    }

    /// Return whether this attestation exactly matches a committed session seat.
    #[must_use]
    pub fn matches(self, session: &ValidatedTleKeySessionV1, participant_index: u16) -> bool {
        self.key_session_id == session.public_state().key_session_id
            && self.transcript_hash == session.public_state().transcript_hash
            && self.participant_index == participant_index
    }
}

/// Closed failure classes for non-signing Parliament TLE custody attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TlePartialReleaseCapabilityErrorV1 {
    /// The secure runtime or authenticated lookup is temporarily unavailable.
    #[error("Parliament TLE release capability attestation is unavailable")]
    Unavailable,
    /// The provider does not own the exact requested session and participant seat.
    #[error("Parliament TLE release capability is not owned")]
    NotOwned,
    /// The requested one-based participant seat is absent from the public transcript.
    #[error("Parliament TLE release capability request is invalid")]
    InvalidRequest,
}

/// Runtime broker backend capable of signing one revalidated public projection.
///
/// This is a deliberately separate surface from [`TlePartialReleaseSignerV1`].
/// A [`ValidatedTleReleaseProjectionV1`] proves only that its public transcript,
/// identity, and height bindings are internally valid; it does not prove that
/// the request came from committed state. Implementations must therefore be
/// reachable only through an authenticated broker session scoped to an Iroha
/// daemon. The daemon must independently verify every returned public share.
pub trait TleProjectedPartialReleaseSignerV1: Send + Sync {
    /// Sign the exact public statement revalidated at the broker boundary.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic when the requested key session is not
    /// owned, the height binding is invalid, or the secure runtime cannot
    /// produce a valid proof-carrying share.
    fn sign_projected_partial_release(
        &self,
        projection: &ValidatedTleReleaseProjectionV1,
    ) -> Result<TlePartialReleaseShareV1, String>;
}

/// Process-local zeroizing software owner for one adaptive TLE signing share.
///
/// This adapter is for deployments whose secure runtime unwraps a share into
/// process memory. It deliberately has no `Clone`, `Debug`, byte export, or
/// serialization implementation. In-process deployment-owned providers implement
/// [`TlePartialReleaseSignerV1`] directly; backends reached through the
/// authenticated runtime broker implement
/// [`TleProjectedPartialReleaseSignerV1`].
pub struct InMemoryTlePartialReleaseSignerV1 {
    session: ValidatedTleKeySessionV1,
    share: AdaptiveThresholdBlsSecretShare<TleReleasePurpose>,
}

impl InMemoryTlePartialReleaseSignerV1 {
    /// Move one validated adaptive share into the live signer.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the share belongs to another public
    /// session or transcript.
    pub fn from_validated_share(
        session: ValidatedTleKeySessionV1,
        share: AdaptiveThresholdBlsSecretShare<TleReleasePurpose>,
    ) -> Result<Self, TleReleaseAdapterError> {
        let mut hasher = Sha256::new();
        hasher.update(b"iroha.parliament.tle-release.runtime-share-import.v1\0");
        hasher.update(session.public_state().key_session_id.as_bytes());
        hasher.update(session.public_state().transcript_hash);
        let import_challenge: [u8; 32] = hasher.finalize().into();
        let partial = share.sign_payload(session.transcript(), &import_challenge)?;
        session
            .transcript()
            .verify_partial_signature(&import_challenge, &partial)?;
        Ok(Self { session, share })
    }

    /// Import three sealed scalar components and consume their zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns an adapter error if the public transcript or secret share does
    /// not match the frozen participant seat.
    pub fn from_components(
        public_state: TleKeySessionPublicStateV1,
        participant_index: u16,
        components: Zeroizing<[[u8; 32]; 3]>,
    ) -> Result<Self, TleReleaseAdapterError> {
        let session = public_state.validate()?;
        let share = AdaptiveThresholdBlsSecretShare::from_components(
            session.transcript(),
            participant_index,
            components[0],
            components[1],
            components[2],
        )?;
        Self::from_validated_share(session, share)
    }

    /// Return the one-based frozen DKG participant seat.
    #[must_use]
    pub const fn participant_index(&self) -> u16 {
        self.share.index()
    }

    /// Return the exact public key-session identifier owned by this adapter.
    ///
    /// This exposes only the already-public transcript identifier. The share,
    /// participant inventory, and scalar components remain inaccessible.
    #[must_use]
    pub const fn key_session_id(&self) -> TleKeySessionId {
        self.session.public_state().key_session_id
    }

    fn sign_validated_release(
        &self,
        session: &ValidatedTleKeySessionV1,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
    ) -> Result<TlePartialReleaseShareV1, String> {
        if session.public_state() != self.session.public_state() {
            return Err("requested TLE key session does not match the sealed share".to_owned());
        }
        session
            .validate_release_identity(identity, finalized_height)
            .map_err(|error| format!("TLE release identity rejected: {error}"))?;
        let partial = self
            .share
            .sign_payload(self.session.transcript(), &identity.payload_bytes())
            .map_err(|error| format!("adaptive TLE partial signing failed: {error}"))?;
        session
            .encode_partial_release(identity, finalized_height, &partial)
            .map_err(|error| format!("adaptive TLE partial validation failed: {error}"))
    }
}

impl TlePartialReleaseSignerV1 for InMemoryTlePartialReleaseSignerV1 {
    fn attest_partial_release_capability(
        &self,
        session: &ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1> {
        if session.public_state() != self.session.public_state()
            || expected_participant_index != self.share.index()
        {
            return Err(TlePartialReleaseCapabilityErrorV1::NotOwned);
        }
        TlePartialReleaseCapabilityAttestationV1::for_validated_session(
            session,
            expected_participant_index,
        )
    }

    fn sign_partial_release(
        &self,
        context: &AuthorizedTleReleaseContextV1,
    ) -> Result<TlePartialReleaseShareV1, String> {
        self.sign_validated_release(
            context.session(),
            context.identity(),
            context.finalized_height(),
        )
    }
}

impl TleProjectedPartialReleaseSignerV1 for InMemoryTlePartialReleaseSignerV1 {
    fn sign_projected_partial_release(
        &self,
        projection: &ValidatedTleReleaseProjectionV1,
    ) -> Result<TlePartialReleaseShareV1, String> {
        self.sign_validated_release(
            projection.session(),
            projection.identity(),
            projection.finalized_height(),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        governance::{
            parliament::ParliamentAttemptStateV1,
            timed_ovn::{TimedOvnSessionPublicV1, timed_ovn_parameter_hash_v1},
        },
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, TLE_KEY_SESSION_SINGLETON_KEY, World},
    };
    use iroha_crypto::{
        Hash, HashOf,
        threshold_bls::AdaptiveThresholdBlsSecretShare,
        timed_ovn::{TimedOvnChoiceV1, TimedOvnRegistrationSecretV1},
    };
    use iroha_data_model::{
        block::BlockHeader,
        governance::types::{
            BeaconPulseId, ParliamentAggregateTallyV1, parliament_ballot_participant_hash_v1,
        },
    };
    use norito::codec::{DecodeAll as _, Encode as _};
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::sync::Arc;

    use super::*;
    pub(crate) use iroha_core_timed_ovn::tle::test_fixtures::*;

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the authorized release context owns the supplied identity"
    )]
    fn authorized_context(
        session: ValidatedTleKeySessionV1,
        identity: TleReleaseIdentityV1,
        finalized_height: u64,
    ) -> AuthorizedTleReleaseContextV1 {
        AuthorizedTleReleaseContextV1 {
            ballot_attempt_id: BallotAttemptId::new(binding(12)),
            opening_deadline_height: 110,
            finalized_height,
            public_release_identity: TimedOvnReleaseIdentityPublicV1 {
                tle_key_session_id: session.public_state().key_session_id,
                governance_attempt_id: binding(10),
                body_instance_id: binding(11),
                ballot_attempt_id: binding(12),
                survivor_corpus_root: binding(13),
                no_recovery_root: binding(14),
                target_finalized_height: 100,
                parameter_hash: binding(15),
            },
            identity,
            session,
        }
    }

    struct ReleaseAuthorizationFixture {
        tle_key: ValidatedTleKeySessionV1,
        registration_attempt: ParliamentAttemptStateV1,
        opening_attempt: ParliamentAttemptStateV1,
        lifecycle: TimedOvnLifecycleStateV1,
        ballot_attempt_id: BallotAttemptId,
        registration_opened_at_height: u64,
        release_height: u64,
        opening_deadline_height: u64,
    }

    fn release_authorization_fixture() -> ReleaseAuthorizationFixture {
        release_authorization_fixture_with_proposal_binding(None)
    }

    fn release_authorization_fixture_with_proposal_binding(
        proposal_content_id: Option<[u8; 32]>,
    ) -> ReleaseAuthorizationFixture {
        const PROPOSAL_TAG: u8 = 0x71;
        const KEY_SESSION_TAG: u8 = 0x72;
        const REGISTRATION_OPENED_AT_HEIGHT: u64 = 27;

        let tle_fixture = fixture_for_binding(
            binding(1),
            KEY_SESSION_TAG,
            binding(KEY_SESSION_TAG.wrapping_add(1)),
        );
        let tle_key = tle_fixture.validated;
        let mut opening_attempt =
            crate::governance::parliament::tests::active_timed_ovn_reservation_attempt_fixture_v1(
                PROPOSAL_TAG,
                KEY_SESSION_TAG,
                REGISTRATION_OPENED_AT_HEIGHT,
            );
        let (
            ballot_attempt_id,
            body_instance_id,
            release_beacon_session_id,
            registration_close_height,
            survivor_freeze_height,
            commitment_close_height,
            release_height,
            opening_deadline_height,
        ) = {
            let (_, ballot) = opening_attempt
                .ballot_attempts()
                .next()
                .expect("reservation fixture has one ballot");
            (
                ballot.attempt().id,
                ballot.attempt().body_instance_id,
                ballot
                    .release_beacon_session_id()
                    .expect("fixture release beacon session"),
                ballot.registration_close_height(),
                ballot.survivor_freeze_height(),
                ballot.commitment_close_height(),
                ballot.release_height().expect("fixture release height"),
                ballot.opening_deadline_height(),
            )
        };
        let registration_attempt = opening_attempt.clone();
        assert_eq!(
            tle_key.public_state().key_session_id,
            opening_attempt
                .ballot(&ballot_attempt_id)
                .and_then(|ballot| ballot.tle_key_session_id())
                .expect("fixture ballot TLE key session")
        );

        let governance_attempt_id = opening_attempt.attempt().id;
        let session = TimedOvnSessionPublicV1 {
            network_id: tle_key.public_state().network_id,
            proposal_content_id: proposal_content_id
                .unwrap_or_else(|| *opening_attempt.proposal_content_id().as_bytes()),
            governance_attempt_id: *governance_attempt_id.as_bytes(),
            body_instance_id: *body_instance_id.as_bytes(),
            ballot_attempt_id: *ballot_attempt_id.as_bytes(),
            parameter_hash: timed_ovn_parameter_hash_v1(),
            tle_key_session_id: tle_key.public_state().key_session_id,
            tle_key_transcript_hash: tle_key.public_state().transcript_hash,
            tle_master_public_key: *tle_key.master_public_key().as_bytes(),
        };
        let crypto_session = session.rebuild(&tle_key).expect("timed-OVN session");
        let mut rng = StdRng::from_seed([0x74; 32]);
        let mut registrations = opening_attempt
            .body(&body_instance_id)
            .expect("fixture ballot body")
            .assignments()
            .iter()
            .map(|assignment| {
                parliament_ballot_participant_hash_v1(ballot_attempt_id, &assignment.member)
            })
            .map(|participant_hash| {
                let (secret, registration) = TimedOvnRegistrationSecretV1::generate_with_rng(
                    &crypto_session,
                    participant_hash,
                    &mut rng,
                )
                .expect("timed-OVN registration");
                (participant_hash, secret, registration.to_bytes())
            })
            .collect::<Vec<_>>();
        registrations.sort_unstable_by_key(|(participant_hash, _, _)| *participant_hash);

        let mut lifecycle = TimedOvnLifecycleStateV1::open_registration(
            session,
            REGISTRATION_OPENED_AT_HEIGHT,
            release_height,
            &tle_key,
        )
        .expect("open timed-OVN registration");
        for (participant_hash, _, registration) in &registrations {
            lifecycle = lifecycle
                .register_participant(*participant_hash, registration.clone(), &tle_key)
                .expect("register timed-OVN participant");
        }
        lifecycle = lifecycle
            .close_registration(&tle_key)
            .expect("close timed-OVN registration");
        lifecycle = lifecycle
            .freeze_survivors(&tle_key)
            .expect("freeze timed-OVN survivors");
        let TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) = &lifecycle else {
            unreachable!("survivor freeze returns the frozen phase");
        };
        let prepared = frozen
            .validate(&tle_key)
            .expect("validate frozen timed-OVN survivors");
        let ballots = registrations
            .iter()
            .map(|(_, secret, _)| {
                secret
                    .cast_ballot_with_rng(
                        prepared.survivor_roster(),
                        TimedOvnChoiceV1::Aye,
                        &mut rng,
                    )
                    .expect("cast timed-OVN ballot")
                    .to_bytes()
            })
            .collect();
        lifecycle = lifecycle
            .seal_ballots(ballots, &tle_key)
            .expect("seal timed-OVN corpus");
        lifecycle
            .validate(&tle_key)
            .expect("sealed timed-OVN evidence replays");
        let (reducer_binding, _) = lifecycle
            .validated_parliament_reducer_binding(&tle_key)
            .expect("derive Parliament reducer binding");

        opening_attempt
            .close_ballot_registration(
                governance_attempt_id,
                ballot_attempt_id,
                reducer_binding
                    .registration_root
                    .expect("registration root"),
                reducer_binding
                    .registered_voters
                    .expect("registered voter count"),
                registration_close_height,
            )
            .expect("close Parliament registration");
        opening_attempt
            .freeze_ballot_survivors(
                governance_attempt_id,
                ballot_attempt_id,
                reducer_binding.dropout_root.expect("dropout root"),
                reducer_binding.survivor_root.expect("survivor root"),
                reducer_binding.survivors.expect("survivor count"),
                reducer_binding.no_recovery_root.expect("no-recovery root"),
                survivor_freeze_height,
            )
            .expect("freeze Parliament survivors");
        opening_attempt
            .freeze_timed_ovn_corpus(
                governance_attempt_id,
                ballot_attempt_id,
                reducer_binding.corpus_root.expect("corpus root"),
                reducer_binding.survivor_root.expect("survivor root"),
                reducer_binding
                    .accepted_ballots
                    .expect("accepted ballot count"),
                reducer_binding
                    .timed_commitment_root
                    .expect("timed commitment root"),
                commitment_close_height,
            )
            .expect("freeze Parliament timed-OVN corpus");
        opening_attempt
            .begin_ballot_opening_batch(
                governance_attempt_id,
                vec![ballot_attempt_id],
                release_beacon_session_id,
                release_height,
                release_height,
                BeaconPulseId::new(binding(0xF1)),
            )
            .expect("open Parliament ballot");
        opening_attempt
            .validate()
            .expect("opening Parliament attempt is canonical");

        ReleaseAuthorizationFixture {
            tle_key,
            registration_attempt,
            opening_attempt,
            lifecycle,
            ballot_attempt_id,
            registration_opened_at_height: REGISTRATION_OPENED_AT_HEIGHT,
            release_height,
            opening_deadline_height,
        }
    }

    fn release_authorization_state(
        attempt: ParliamentAttemptStateV1,
        ballot_attempt_id: BallotAttemptId,
        lifecycle: TimedOvnLifecycleStateV1,
        key_session: Option<TleKeySessionPublicStateV1>,
        finalized_height: u64,
    ) -> State {
        let mut world = World::new();
        world
            .parliament_attempts
            .insert(attempt.attempt().id, attempt);
        world
            .timed_ovn_evidence
            .insert(ballot_attempt_id, lifecycle);
        if let Some(key_session) = key_session {
            world
                .tle_key_sessions
                .insert(key_session.key_session_id, key_session);
        }
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        for height in 0..finalized_height {
            state.push_block_hash_for_testing(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::new(height.to_be_bytes()),
            ));
        }
        state
    }

    fn runtime_signer(
        fixture: &Fixture,
        participant_index: u16,
    ) -> InMemoryTlePartialReleaseSignerV1 {
        let parameters = *fixture.validated.transcript().parameters();
        let private_shares = fixture
            .dealer_secrets
            .iter()
            .zip(&fixture.dealers)
            .map(|(secret, dealer)| {
                secret
                    .private_share(&parameters, dealer, participant_index)
                    .expect("private contribution")
            })
            .collect::<Vec<_>>();
        let signing_share = AdaptiveThresholdBlsSecretShare::from_dealer_shares(
            fixture.validated.transcript(),
            &private_shares,
        )
        .expect("signing share");
        InMemoryTlePartialReleaseSignerV1::from_validated_share(
            fixture.validated.clone(),
            signing_share,
        )
        .expect("runtime signer")
    }

    #[test]
    fn runtime_signer_accepts_only_an_authorized_context_and_rechecks_height() {
        let fixture = fixture();
        let identity = identity(fixture.session);
        let signer = runtime_signer(&fixture, 1);
        assert_eq!(signer.participant_index(), 1);

        let attestation = signer
            .attest_partial_release_capability(&fixture.validated, 1)
            .expect("exact imported share must attest its public session and seat");
        assert!(attestation.matches(&fixture.validated, 1));
        assert_eq!(
            attestation.key_session_id(),
            fixture.validated.public_state().key_session_id
        );
        assert_eq!(
            attestation.transcript_hash(),
            fixture.validated.public_state().transcript_hash
        );
        assert_eq!(attestation.participant_index(), 1);
        assert_eq!(
            signer.attest_partial_release_capability(&fixture.validated, 2),
            Err(TlePartialReleaseCapabilityErrorV1::NotOwned)
        );
        let other = fixture_for_key(0x91);
        assert_eq!(
            signer.attest_partial_release_capability(&other.validated, 1),
            Err(TlePartialReleaseCapabilityErrorV1::NotOwned)
        );

        let early_context = authorized_context(fixture.validated.clone(), identity, 99);
        let early = signer
            .sign_partial_release(&early_context)
            .expect_err("runtime signer must reject a pre-target release");
        assert!(early.contains("target finalized height"));

        let context = authorized_context(fixture.validated.clone(), identity, 100);
        let partial = signer
            .sign_partial_release(&context)
            .expect("target-height partial release");
        assert_eq!(partial.participant_index, 1);
        fixture
            .validated
            .verify_partial_release(&identity, 100, &partial)
            .expect("runtime signer output re-verifies independently");
    }

    #[test]
    fn authenticated_broker_projection_roundtrips_and_signs_after_revalidation() {
        let fixture = fixture();
        let release_identity = identity(fixture.session);
        let context = authorized_context(fixture.validated.clone(), release_identity, 100);
        let projection = context
            .broker_projection_v1()
            .expect("opaque Core context projects to bounded public wire data");
        assert_eq!(
            projection.identity_payload.len(),
            TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1
        );
        let encoded = projection.encode();
        let decoded = AuthorizedTleReleaseProjectionV1::decode_all(&mut encoded.as_slice())
            .expect("decode broker projection");
        let validated = decoded
            .validate()
            .expect("revalidate exact public transcript and release statement");

        let signer = runtime_signer(&fixture, 1);
        let partial = signer
            .sign_projected_partial_release(&validated)
            .expect("authenticated broker backend signs validated projection");
        assert_eq!(partial.participant_index, 1);
        context
            .session()
            .verify_partial_release(context.identity(), context.finalized_height(), &partial)
            .expect("daemon independently verifies broker output");

        let other = fixture_for_key(22);
        let other_context =
            authorized_context(other.validated.clone(), identity(other.session), 100);
        let other_projection = other_context
            .broker_projection_v1()
            .expect("project another valid key session")
            .validate()
            .expect("validate another key session projection");
        let error = signer
            .sign_projected_partial_release(&other_projection)
            .expect_err("one-session signer must reject a valid cross-session request");
        assert!(error.contains("does not match the sealed share"));
    }

    #[test]
    fn authenticated_broker_projection_rejects_tampered_public_bindings() {
        let fixture = fixture();
        let identity = identity(fixture.session);
        let context = authorized_context(fixture.validated, identity, 100);
        let projection = context
            .broker_projection_v1()
            .expect("valid base projection");

        let mut wrong_ballot = projection.clone();
        wrong_ballot.ballot_attempt_id = BallotAttemptId::new(binding(99));
        assert_eq!(
            wrong_ballot.validate().expect_err("ballot substitution"),
            TleReleaseProjectionErrorV1::BindingMismatch
        );

        let mut wrong_payload = projection.clone();
        wrong_payload.identity_payload[0] ^= 1;
        assert_eq!(
            wrong_payload.validate().expect_err("payload substitution"),
            TleReleaseProjectionErrorV1::IdentityPayloadMismatch
        );

        let mut wrong_digest = projection.clone();
        wrong_digest.identity_digest[0] ^= 1;
        assert_eq!(
            wrong_digest.validate().expect_err("digest substitution"),
            TleReleaseProjectionErrorV1::IdentityDigestMismatch
        );

        let mut expired = projection;
        expired.finalized_height = expired.opening_deadline_height.saturating_add(1);
        assert_eq!(
            expired.validate().expect_err("expired projection"),
            TleReleaseProjectionErrorV1::InvalidHeightWindow
        );
    }

    #[test]
    fn coordinator_fails_closed_without_a_signer_and_reverifies_positive_output() {
        let fixture = fixture();
        let identity = identity(fixture.session);
        let context = authorized_context(fixture.validated.clone(), identity, 100);

        let absent = TleReleaseCoordinatorV1::without_signer();
        assert!(!absent.signer_is_available());
        assert_eq!(
            absent.request_authorized_partial_release(&context),
            Err(TleReleaseCoordinatorErrorV1::SignerUnavailable)
        );

        let coordinator =
            TleReleaseCoordinatorV1::from_signer(Arc::new(runtime_signer(&fixture, 1)));
        assert!(coordinator.signer_is_available());
        let partial = coordinator
            .request_authorized_partial_release(&context)
            .expect("independently verified runtime partial");
        assert_eq!(partial.participant_index, 1);
        context
            .session()
            .verify_partial_release(context.identity(), context.finalized_height(), &partial)
            .expect("coordinator output must reverify outside the signer");
    }

    #[test]
    fn runtime_custody_selects_multiple_sessions_and_retires_unreferenced_share() {
        let first = fixture_for_key(2);
        let second = fixture_for_key(22);
        let first_context =
            authorized_context(first.validated.clone(), identity(first.session), 100);
        let second_context =
            authorized_context(second.validated.clone(), identity(second.session), 100);
        let custody = Arc::new(RuntimeTleReleaseShareCustodyV1::new());
        custody
            .insert_validated_share(runtime_signer(&first, 1))
            .expect("insert first live session");
        custody
            .insert_validated_share(runtime_signer(&second, 2))
            .expect("insert rotating session");
        assert_eq!(
            custody.insert_validated_share(runtime_signer(&second, 2)),
            Err(TleReleaseShareCustodyErrorV1::SessionAlreadyPresent)
        );
        assert!(
            custody
                .attest_partial_release_capability(&first.validated, 1)
                .expect("custody attests the exact first session seat")
                .matches(&first.validated, 1)
        );
        assert!(
            custody
                .attest_partial_release_capability(&second.validated, 2)
                .expect("custody attests the exact rotating session seat")
                .matches(&second.validated, 2)
        );
        assert_eq!(
            custody.attest_partial_release_capability(&second.validated, 1),
            Err(TlePartialReleaseCapabilityErrorV1::NotOwned)
        );

        let signer: Arc<dyn TlePartialReleaseSignerV1> = custody.clone();
        let coordinator = TleReleaseCoordinatorV1::from_signer(signer);
        assert_eq!(
            coordinator
                .request_authorized_partial_release(&first_context)
                .expect("first session partial")
                .participant_index,
            1
        );
        assert_eq!(
            coordinator
                .request_authorized_partial_release(&second_context)
                .expect("second session partial")
                .participant_index,
            2
        );
        let projected_second = second_context
            .broker_projection_v1()
            .expect("project second session")
            .validate()
            .expect("validate second-session broker projection");
        assert_eq!(
            custody
                .sign_projected_partial_release(&projected_second)
                .expect("custody selects the projected key session")
                .participant_index,
            2
        );

        let first_key_session_id = first.validated.public_state().key_session_id;
        let second_key_session_id = second.validated.public_state().key_session_id;
        let mut world = World::new();
        world
            .tle_key_sessions
            .insert(first_key_session_id, first.validated.public_state().clone());
        world.tle_key_sessions.insert(
            second_key_session_id,
            second.validated.public_state().clone(),
        );
        world.tle_key_session_lifecycles.insert(
            second_key_session_id,
            TleKeySessionLifecycleV1::new(second_key_session_id, 1, 100, 1)
                .expect("active custody fixture lifecycle"),
        );
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, second_key_session_id);
        world
            .rebuild_governance_read_indexes_for_testing()
            .expect("rebuild active TLE selection interval");
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        custody
            .retire_session(&state.query_view(), first_key_session_id)
            .expect("unreferenced session retires and zeroizes");
        assert_eq!(
            coordinator.request_authorized_partial_release(&first_context),
            Err(TleReleaseCoordinatorErrorV1::SignerFailed)
        );
        coordinator
            .request_authorized_partial_release(&second_context)
            .expect("unretired rotating session remains available");
        assert_eq!(
            custody.retire_session(&state.query_view(), second_key_session_id),
            Err(TleReleaseShareCustodyErrorV1::SessionStillRequired)
        );
        assert_eq!(
            custody.retire_session(&state.query_view(), first_key_session_id),
            Err(TleReleaseShareCustodyErrorV1::SessionNotPresent)
        );
    }

    #[test]
    fn runtime_custody_rejects_retirement_through_max_committed_retry_deadline() {
        use crate::state::WorldReadOnly as _;

        let retiring = fixture_for_key(32);
        let successor = fixture_for_key(42);
        let retiring_id = retiring.validated.public_state().key_session_id;
        let successor_id = successor.validated.public_state().key_session_id;
        let custody = RuntimeTleReleaseShareCustodyV1::new();
        custody
            .insert_validated_share(runtime_signer(&retiring, 1))
            .expect("insert retiring runtime share");

        let retaining_attempt =
            crate::governance::parliament::tests::tle_key_session_retention_attempt_fixture_v1(
                retiring_id,
            );
        let attempt_id = retaining_attempt.attempt().id;
        let mut world = World::new();
        world
            .tle_key_sessions
            .insert(retiring_id, retiring.validated.public_state().clone());
        world
            .tle_key_sessions
            .insert(successor_id, successor.validated.public_state().clone());
        world.tle_key_session_lifecycles.insert(
            successor_id,
            TleKeySessionLifecycleV1::new(successor_id, 1, 100, 1)
                .expect("active successor lifecycle"),
        );
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, successor_id);
        world
            .parliament_attempts
            .insert(attempt_id, retaining_attempt);
        world
            .rebuild_governance_read_indexes_for_testing()
            .expect("rebuild the committed TLE retention index");
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.query_view();
        assert_eq!(
            view.world()
                .tle_key_session_retention_deadline_v1(retiring_id),
            Some(62)
        );
        assert_eq!(
            custody.retire_session(&view, retiring_id),
            Err(TleReleaseShareCustodyErrorV1::SessionStillRequired)
        );
    }

    #[test]
    fn runtime_custody_rejects_invalid_component_import_without_inventory_output() {
        let fixture = fixture();
        let custody = RuntimeTleReleaseShareCustodyV1::new();
        assert_eq!(
            custody.import_components(
                fixture.validated.public_state().clone(),
                1,
                Zeroizing::new([[0; 32]; 3]),
            ),
            Err(TleReleaseShareCustodyErrorV1::InvalidShare)
        );

        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert_eq!(
            custody.import_committed_components(
                &state.query_view(),
                fixture.validated.public_state().key_session_id,
                1,
                Zeroizing::new([[0; 32]; 3]),
            ),
            Err(TleReleaseShareCustodyErrorV1::SessionNotCommitted)
        );
    }

    #[test]
    fn coordinator_canonicalizes_partials_into_the_existing_finalize_transition() {
        use iroha_data_model::isi::governance::ParliamentLifecycleTransitionV1;

        let fixture = fixture();
        let identity = identity(fixture.session);
        let context = authorized_context(fixture.validated.clone(), identity, 100);
        let first = TleReleaseCoordinatorV1::from_signer(Arc::new(runtime_signer(&fixture, 1)))
            .request_authorized_partial_release(&context)
            .expect("first partial");
        let second = TleReleaseCoordinatorV1::from_signer(Arc::new(runtime_signer(&fixture, 2)))
            .request_authorized_partial_release(&context)
            .expect("second partial");
        let coordinator = TleReleaseCoordinatorV1::without_signer();

        let transition = coordinator
            .combine_authorized_partial_releases(&context, &[second.clone(), first.clone()])
            .expect("canonical final release transition");
        let ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(payload) = transition else {
            panic!("coordinator must emit only FinalizeOpenedBallot")
        };
        assert_eq!(payload.ballot_attempt_id, context.ballot_attempt_id());
        let final_release = TleFinalReleaseSignatureV1 {
            key_session_id: payload.final_release.key_session_id,
            identity_digest: payload.final_release.identity_digest,
            signature: payload.final_release.signature,
        };
        context
            .session()
            .verify_final_release(
                context.identity(),
                context.finalized_height(),
                &final_release,
            )
            .expect("combined transition must carry the unique final signature");

        assert_eq!(
            coordinator.combine_authorized_partial_releases(&context, &[first.clone(), first]),
            Err(TleReleaseCoordinatorErrorV1::InvalidPartialSet)
        );
    }

    #[test]
    fn coordinator_discards_signer_diagnostics_and_invalid_public_output() {
        struct FailingSigner;

        impl TlePartialReleaseSignerV1 for FailingSigner {
            fn attest_partial_release_capability(
                &self,
                _session: &ValidatedTleKeySessionV1,
                _expected_participant_index: u16,
            ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1>
            {
                Err(TlePartialReleaseCapabilityErrorV1::NotOwned)
            }

            fn sign_partial_release(
                &self,
                _context: &AuthorizedTleReleaseContextV1,
            ) -> Result<TlePartialReleaseShareV1, String> {
                Err("secret-provider-handle-and-share-metadata".to_owned())
            }
        }

        struct InvalidSigner(TlePartialReleaseShareV1);

        impl TlePartialReleaseSignerV1 for InvalidSigner {
            fn attest_partial_release_capability(
                &self,
                _session: &ValidatedTleKeySessionV1,
                _expected_participant_index: u16,
            ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1>
            {
                Err(TlePartialReleaseCapabilityErrorV1::NotOwned)
            }

            fn sign_partial_release(
                &self,
                _context: &AuthorizedTleReleaseContextV1,
            ) -> Result<TlePartialReleaseShareV1, String> {
                Ok(self.0.clone())
            }
        }

        let fixture = fixture();
        let identity = identity(fixture.session);
        let context = authorized_context(fixture.validated.clone(), identity, 100);
        let failing = TleReleaseCoordinatorV1::from_signer(Arc::new(FailingSigner));
        let error = failing
            .request_authorized_partial_release(&context)
            .expect_err("provider failure must stay closed");
        assert_eq!(error, TleReleaseCoordinatorErrorV1::SignerFailed);
        assert!(!error.to_string().contains("secret-provider"));

        let mut partial = runtime_signer(&fixture, 1)
            .sign_partial_release(&context)
            .expect("valid base partial");
        partial.sigma[0] ^= 1;
        let invalid = TleReleaseCoordinatorV1::from_signer(Arc::new(InvalidSigner(partial)));
        assert_eq!(
            invalid.request_authorized_partial_release(&context),
            Err(TleReleaseCoordinatorErrorV1::InvalidSignerOutput)
        );
    }

    #[test]
    fn release_authorization_accepts_exact_committed_opening_state() {
        let fixture = release_authorization_fixture();
        let state = release_authorization_state(
            fixture.opening_attempt.clone(),
            fixture.ballot_attempt_id,
            fixture.lifecycle.clone(),
            Some(fixture.tle_key.public_state().clone()),
            fixture.release_height,
        );
        let context =
            authorize_parliament_tle_release_v1(&state.query_view(), fixture.ballot_attempt_id)
                .expect("exact sealed opening state authorizes one release context");
        assert_eq!(context.ballot_attempt_id(), fixture.ballot_attempt_id);
        assert_eq!(context.finalized_height(), fixture.release_height);
        assert_eq!(
            context.opening_deadline_height(),
            fixture.opening_deadline_height
        );
        assert_eq!(
            context.session().public_state(),
            fixture.tle_key.public_state()
        );
    }

    #[test]
    fn release_authorization_rejects_unsealed_and_invalid_key_state() {
        let fixture = release_authorization_fixture();
        let TimedOvnLifecycleStateV1::Sealed(sealed) = &fixture.lifecycle else {
            unreachable!("authorization fixture retains sealed evidence");
        };
        let unsealed = TimedOvnLifecycleStateV1::open_registration(
            sealed.session,
            fixture.registration_opened_at_height,
            fixture.release_height,
            &fixture.tle_key,
        )
        .expect("reconstruct registration-open state");
        let unsealed_state = release_authorization_state(
            fixture.opening_attempt.clone(),
            fixture.ballot_attempt_id,
            unsealed,
            Some(fixture.tle_key.public_state().clone()),
            fixture.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &unsealed_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("unsealed evidence must not authorize a release share"),
            TleReleaseAuthorizationErrorV1::TimedOvnNotSealed
        );

        let missing_state = release_authorization_state(
            fixture.opening_attempt.clone(),
            fixture.ballot_attempt_id,
            fixture.lifecycle.clone(),
            None,
            fixture.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &missing_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("missing public key session must fail closed"),
            TleReleaseAuthorizationErrorV1::MissingKeySession
        );

        let mut malformed_key_session = fixture.tle_key.public_state().clone();
        malformed_key_session.version = malformed_key_session.version.wrapping_add(1);
        let malformed_state = release_authorization_state(
            fixture.opening_attempt,
            fixture.ballot_attempt_id,
            fixture.lifecycle,
            Some(malformed_key_session),
            fixture.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &malformed_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("malformed public key session must fail closed"),
            TleReleaseAuthorizationErrorV1::KeySession(TleReleaseAdapterError::UnsupportedVersion)
        );
    }

    #[test]
    fn release_authorization_rejects_inactive_or_non_opening_attempts() {
        let fixture = release_authorization_fixture();
        let non_opening_state = release_authorization_state(
            fixture.registration_attempt,
            fixture.ballot_attempt_id,
            fixture.lifecycle.clone(),
            Some(fixture.tle_key.public_state().clone()),
            fixture.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &non_opening_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("a registered ballot must not authorize release"),
            TleReleaseAuthorizationErrorV1::BallotNotOpening
        );

        let mut inactive_attempt = fixture.opening_attempt;
        let governance_attempt_id = inactive_attempt.attempt().id;
        let ballot = inactive_attempt
            .ballot(&fixture.ballot_attempt_id)
            .expect("opening ballot");
        let tle_session_id = ballot.tle_session_id().expect("sealed TLE session");
        let original_seats = ballot.attempt().original_seats;
        let (reducer_binding, _) = fixture
            .lifecycle
            .validated_parliament_reducer_binding(&fixture.tle_key)
            .expect("sealed reducer binding");
        let accepted_ballots = reducer_binding
            .accepted_ballots
            .expect("sealed accepted-ballot count");
        inactive_attempt
            .finalize_opened_ballot(
                governance_attempt_id,
                fixture.ballot_attempt_id,
                reducer_binding.corpus_root.expect("sealed corpus root"),
                reducer_binding
                    .no_recovery_root
                    .expect("sealed no-recovery root"),
                tle_session_id,
                binding(0xF2),
                reducer_binding.survivors.expect("sealed survivor count"),
                ParliamentAggregateTallyV1 {
                    original_seats,
                    accepted_ballots,
                    aye: accepted_ballots,
                    nay: 0,
                    abstain: 0,
                },
                original_seats,
                fixture.release_height,
            )
            .expect("finalize unanimous fixture ballot");
        inactive_attempt
            .construct_certificate(
                governance_attempt_id,
                fixture.release_height,
                fixture.release_height + 2,
            )
            .expect("certify completed fixture attempt");
        inactive_attempt
            .validate()
            .expect("certified fixture attempt remains canonical");
        let inactive_state = release_authorization_state(
            inactive_attempt,
            fixture.ballot_attempt_id,
            fixture.lifecycle,
            Some(fixture.tle_key.public_state().clone()),
            fixture.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &inactive_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("a certified governance attempt must not authorize release"),
            TleReleaseAuthorizationErrorV1::GovernanceAttemptNotActive
        );
    }

    #[test]
    fn release_authorization_rejects_cross_binding_and_outside_opening_window() {
        let cross_bound = release_authorization_fixture_with_proposal_binding(Some(binding(0xFE)));
        let TimedOvnLifecycleStateV1::Sealed(cross_bound_evidence) = &cross_bound.lifecycle else {
            unreachable!("authorization fixture retains sealed evidence");
        };
        assert_ne!(
            cross_bound.opening_attempt.proposal_content_id().as_bytes(),
            &cross_bound_evidence.session.proposal_content_id
        );
        let cross_bound_state = release_authorization_state(
            cross_bound.opening_attempt,
            cross_bound.ballot_attempt_id,
            cross_bound.lifecycle,
            Some(cross_bound.tle_key.public_state().clone()),
            cross_bound.release_height,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &cross_bound_state.query_view(),
                cross_bound.ballot_attempt_id,
            )
            .expect_err("cross-bound proposal state must fail closed"),
            TleReleaseAuthorizationErrorV1::BindingMismatch
        );

        let fixture = release_authorization_fixture();
        let early_state = release_authorization_state(
            fixture.opening_attempt.clone(),
            fixture.ballot_attempt_id,
            fixture.lifecycle.clone(),
            Some(fixture.tle_key.public_state().clone()),
            fixture.release_height - 1,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &early_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("pre-target state must fail closed"),
            TleReleaseAuthorizationErrorV1::ReleaseHeightNotReached
        );

        let deadline_state = release_authorization_state(
            fixture.opening_attempt.clone(),
            fixture.ballot_attempt_id,
            fixture.lifecycle.clone(),
            Some(fixture.tle_key.public_state().clone()),
            fixture.opening_deadline_height,
        );
        let at_deadline = authorize_parliament_tle_release_v1(
            &deadline_state.query_view(),
            fixture.ballot_attempt_id,
        )
        .expect("opening deadline is inclusive");
        assert_eq!(
            at_deadline.finalized_height(),
            fixture.opening_deadline_height
        );

        let expired_state = release_authorization_state(
            fixture.opening_attempt,
            fixture.ballot_attempt_id,
            fixture.lifecycle,
            Some(fixture.tle_key.public_state().clone()),
            fixture.opening_deadline_height + 1,
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &expired_state.query_view(),
                fixture.ballot_attempt_id,
            )
            .expect_err("post-deadline state must fail closed"),
            TleReleaseAuthorizationErrorV1::OpeningDeadlinePassed
        );
    }

    #[test]
    fn release_authorization_rejects_an_uncommitted_ballot() {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert_eq!(
            authorize_parliament_tle_release_v1(
                &state.query_view(),
                BallotAttemptId::new(binding(12)),
            )
            .expect_err("an arbitrary ballot must not reach the signer"),
            TleReleaseAuthorizationErrorV1::MissingTimedOvnEvidence
        );
    }
}
