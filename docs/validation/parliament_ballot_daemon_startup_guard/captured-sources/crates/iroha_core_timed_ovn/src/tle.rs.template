//! Public TLE key-session transcripts and release verification.

use crate::evidence::TimedOvnReleaseIdentityPublicV1;
use arrayvec::ArrayVec;
use iroha_crypto::{
    threshold_bls::{
        AdaptiveThresholdBlsParameters, AdaptiveThresholdBlsPublicTranscript,
        DasRenDealerCommitment, DasRenPartialSignature, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1,
        ThresholdBlsError, ThresholdBlsSession, ThresholdBlsSignature, TleReleasePurpose,
        ValidatedDealerCommitment,
    },
    tle::{TleError, TleIdentitySecretKeyV1, TleMasterPublicKey, TleReleaseIdentityV1},
};
use iroha_data_model::governance::types::{BallotAttemptId, TleKeySessionId};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    derive::{JsonDeserialize, JsonSerialize},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Fixed version of the public TLE key-session adapter.
pub const TLE_KEY_SESSION_ADAPTER_VERSION_V1: u16 = 1;
/// Fixed version of the consensus-enforced TLE key-session lifecycle record.
pub const TLE_KEY_SESSION_LIFECYCLE_VERSION_V1: u16 = 1;
/// Fixed version of the authenticated-broker public release projection.
pub const TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1: u16 = 1;
/// Exact byte length of the V1 application identity payload.
pub const TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1: usize = 243;

/// Closed failures for one persisted TLE key-session lifecycle record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleKeySessionLifecycleValidationErrorV1 {
    /// The record does not use the sole first-release version.
    #[error("unsupported TLE key-session lifecycle version")]
    UnsupportedVersion,
    /// The session identifier is the all-zero sentinel.
    #[error("TLE key-session lifecycle uses the zero session identifier")]
    ZeroKeySessionId,
    /// Activation, expiry, or rotation bounds are empty or inverted.
    #[error("TLE key-session lifecycle height bounds are invalid")]
    InvalidHeightBounds,
    /// A lifecycle head already records its one certified closure.
    #[error("TLE key-session lifecycle selection is already closed")]
    SelectionAlreadyClosed,
    /// The configured fresh-ballot budget is zero.
    #[error("TLE key-session lifecycle fresh-ballot budget is zero")]
    ZeroFreshBallotBudget,
    /// The persisted use counter exceeds the immutable session ceiling.
    #[error("TLE key-session lifecycle fresh-ballot counter exceeds its ceiling")]
    FreshBallotBudgetExceeded,
}

/// Consensus-enforced lifecycle metadata for one adaptive TLE public key.
///
/// This record is deliberately separate from [`TleKeySessionPublicStateV1`]:
/// rotation policy and use accounting therefore do not alter the public DKG
/// transcript or the key-session identifier. Heights are inclusive. A
/// rotation committed at height `H` shortens its predecessor through `H` and
/// makes the successor selectable beginning at `H + 1`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::tle_release::TleKeySessionLifecycleV1")]
pub struct TleKeySessionLifecycleV1 {
    /// Fixed lifecycle-record version.
    pub version: u16,
    /// Exact public key session governed by this record.
    pub key_session_id: TleKeySessionId,
    /// First finalized height at which a new ballot may select this session.
    pub activation_height: u64,
    /// Last finalized height allowed by the immutable lifetime policy.
    pub expiry_height: u64,
    /// Last finalized height before expiry or a certified rotation cutover.
    pub selectable_through_height: u64,
    /// Height through which a certified rotation or retirement kept this session selectable.
    ///
    /// `None` identifies the unique open lifecycle head. Keeping this marker
    /// separately from `selectable_through_height` makes the active-head state
    /// reconstructible even when a session is closed at or after its natural
    /// expiry, where shortening the interval alone would be ambiguous.
    #[norito(required)]
    pub selection_closed_at_height: Option<u64>,
    /// Number of committed fresh ballot attempts that selected this session.
    pub fresh_ballot_uses: u32,
    /// Immutable ceiling on committed fresh ballot attempts for this session.
    pub max_fresh_ballot_uses: u32,
}

impl TleKeySessionLifecycleV1 {
    /// Construct the initial lifecycle record for a newly installed session.
    ///
    /// # Errors
    ///
    /// Fails closed for a zero identifier, empty policy bound, or height
    /// overflow.
    pub fn new(
        key_session_id: TleKeySessionId,
        activation_height: u64,
        lifetime_blocks: u64,
        max_fresh_ballot_uses: u32,
    ) -> Result<Self, TleKeySessionLifecycleValidationErrorV1> {
        if key_session_id.as_bytes() == &[0; 32] {
            return Err(TleKeySessionLifecycleValidationErrorV1::ZeroKeySessionId);
        }
        if activation_height == 0 || lifetime_blocks == 0 {
            return Err(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds);
        }
        if max_fresh_ballot_uses == 0 {
            return Err(TleKeySessionLifecycleValidationErrorV1::ZeroFreshBallotBudget);
        }
        let expiry_height = activation_height
            .checked_add(lifetime_blocks - 1)
            .ok_or(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds)?;
        Ok(Self {
            version: TLE_KEY_SESSION_LIFECYCLE_VERSION_V1,
            key_session_id,
            activation_height,
            expiry_height,
            selectable_through_height: expiry_height,
            selection_closed_at_height: None,
            fresh_ballot_uses: 0,
            max_fresh_ballot_uses,
        })
    }

    /// Validate all persisted identity, height, and use-counter invariants.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unsupported version, zero identity,
    /// inverted height interval, zero budget, or over-ceiling counter.
    pub fn validate(self) -> Result<Self, TleKeySessionLifecycleValidationErrorV1> {
        if self.version != TLE_KEY_SESSION_LIFECYCLE_VERSION_V1 {
            return Err(TleKeySessionLifecycleValidationErrorV1::UnsupportedVersion);
        }
        if self.key_session_id.as_bytes() == &[0; 32] {
            return Err(TleKeySessionLifecycleValidationErrorV1::ZeroKeySessionId);
        }
        if self.activation_height == 0
            || self.expiry_height < self.activation_height
            || self.selectable_through_height < self.activation_height
            || self.selectable_through_height > self.expiry_height
        {
            return Err(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds);
        }
        match self.selection_closed_at_height {
            None if self.selectable_through_height != self.expiry_height => {
                return Err(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds);
            }
            Some(closed_at_height)
                if closed_at_height < self.activation_height
                    || self.selectable_through_height
                        != self.expiry_height.min(closed_at_height) =>
            {
                return Err(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds);
            }
            None | Some(_) => {}
        }
        if self.max_fresh_ballot_uses == 0 {
            return Err(TleKeySessionLifecycleValidationErrorV1::ZeroFreshBallotBudget);
        }
        if self.fresh_ballot_uses > self.max_fresh_ballot_uses {
            return Err(TleKeySessionLifecycleValidationErrorV1::FreshBallotBudgetExceeded);
        }
        Ok(self)
    }

    /// Return whether a fresh ballot may select this session at `height`.
    #[must_use]
    pub fn permits_fresh_ballot_at(self, height: u64) -> bool {
        self.validate().is_ok()
            && (self.activation_height..=self.selectable_through_height).contains(&height)
            && self.fresh_ballot_uses < self.max_fresh_ballot_uses
    }

    /// Shorten new-ballot selection through the certified rotation height.
    ///
    /// Already committed ballots retain the separate public session and
    /// roster records; this method only closes future selection.
    pub fn cut_over_after(
        &mut self,
        height: u64,
    ) -> Result<(), TleKeySessionLifecycleValidationErrorV1> {
        self.validate()?;
        if height < self.activation_height {
            return Err(TleKeySessionLifecycleValidationErrorV1::InvalidHeightBounds);
        }
        if self.selection_closed_at_height.is_some() {
            return Err(TleKeySessionLifecycleValidationErrorV1::SelectionAlreadyClosed);
        }
        self.selectable_through_height = self.selectable_through_height.min(height);
        self.selection_closed_at_height = Some(height);
        self.validate()?;
        Ok(())
    }

    /// Return whether a certified rotation or retirement closed this lifecycle head.
    #[must_use]
    pub const fn selection_is_closed(self) -> bool {
        self.selection_closed_at_height.is_some()
    }

    /// Consume exactly one fresh-ballot use at an eligible finalized height.
    pub fn consume_fresh_ballot(
        &mut self,
        height: u64,
    ) -> Result<(), TleKeySessionLifecycleValidationErrorV1> {
        if !self.permits_fresh_ballot_at(height) {
            return Err(TleKeySessionLifecycleValidationErrorV1::FreshBallotBudgetExceeded);
        }
        self.fresh_ballot_uses = self
            .fresh_ballot_uses
            .checked_add(1)
            .ok_or(TleKeySessionLifecycleValidationErrorV1::FreshBallotBudgetExceeded)?;
        self.validate()?;
        Ok(())
    }
}

/// Public coefficient commitments and constant-term proof for one qualified dealer.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::TleAdaptiveDealerCommitmentV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
#[norito(decode_fields)]
pub struct TleAdaptiveDealerCommitmentV1 {
    /// Canonical one-based dealer index.
    pub dealer_index: u16,
    /// Exact degree-`f` triple-generator coefficient commitments.
    pub coefficient_commitments: Vec<[u8; 96]>,
    /// Schnorr commitment proving knowledge of the unblinded constant term.
    pub constant_pok_commitment: [u8; 96],
    /// Canonical big-endian Schnorr response scalar.
    pub constant_pok_response: [u8; 32],
}

impl TleAdaptiveDealerCommitmentV1 {
    fn from_validated(dealer: &ValidatedDealerCommitment<TleReleasePurpose>) -> Self {
        Self {
            dealer_index: dealer.dealer_index(),
            coefficient_commitments: dealer
                .coefficients()
                .iter()
                .map(|coefficient| *coefficient.as_bytes())
                .collect(),
            constant_pok_commitment: *dealer.constant_proof().commitment_bytes(),
            constant_pok_response: *dealer.constant_proof().response_bytes(),
        }
    }
}

/// One public composite verification share in a finalized adaptive TLE transcript.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::TleAdaptivePublicShareV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(decode_fields)]
pub struct TleAdaptivePublicShareV1 {
    /// Canonical one-based participant index.
    pub index: u16,
    /// Purpose- and roster-bound canonical seat digest.
    pub participant_hash: [u8; 32],
    /// Canonical compressed composite commitment `g^s h^r v^u`.
    pub public_key_share: [u8; 96],
}

/// Canonical, public-only state for one finalized adaptive TLE key session.
///
/// The qualified dealer commitments are retained so a restart can reconstruct
/// and revalidate the complete cryptographic transcript instead of trusting
/// cached public-key bytes.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::tle_release::TleKeySessionPublicStateV1")]
#[norito(decode_fields)]
pub struct TleKeySessionPublicStateV1 {
    /// Fixed adapter version.
    pub version: u16,
    /// Long-lived, purpose-distinct TLE threshold key identifier.
    pub key_session_id: TleKeySessionId,
    /// Canonical network/genesis binding.
    pub network_id: [u8; 32],
    /// Hash of the exact ordered threshold committee roster.
    pub roster_hash: [u8; 32],
    /// Exact `3f + 1` committee size.
    pub committee_size: u16,
    /// Exact `f + 1` release threshold.
    pub threshold: u16,
    /// Purpose- and session-derived independent Pedersen generator `h`.
    pub generator_h: [u8; 96],
    /// Purpose- and session-derived independent Pedersen generator `v`.
    pub generator_v: [u8; 96],
    /// Strictly increasing qualified dealer indices.
    pub qualified_dealers: Vec<u16>,
    /// Proof-validated public broadcasts aligned exactly with `qualified_dealers`.
    pub qualified_dealer_commitments: Vec<TleAdaptiveDealerCommitmentV1>,
    /// Consensus event hash binding complaints, responses, and qualification.
    pub dkg_event_hash: [u8; 32],
    /// Standard-generator aggregate group public key.
    pub group_public_key: [u8; 96],
    /// Complete canonical sequence of composite participant verification shares.
    pub public_shares: Vec<TleAdaptivePublicShareV1>,
    /// Commitment to the complete verified adaptive transcript.
    pub transcript_hash: [u8; 32],
}

impl TleKeySessionPublicStateV1 {
    /// Reconstruct and cryptographically validate this public-only state.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for a wrong version, malformed DKG
    /// proof, noncanonical qualified set, or any cached transcript mismatch.
    pub fn validate(self) -> Result<ValidatedTleKeySessionV1, TleReleaseAdapterError> {
        ValidatedTleKeySessionV1::from_public_state(self)
    }
}

/// Runtime-validated adaptive TLE key session.
///
/// This value is deliberately not serializable. Persistence uses
/// [`TleKeySessionPublicStateV1`] and reconstructs this authenticated runtime
/// object by replaying every public proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTleKeySessionV1 {
    state: TleKeySessionPublicStateV1,
    transcript: AdaptiveThresholdBlsPublicTranscript<TleReleasePurpose>,
}

impl ValidatedTleKeySessionV1 {
    /// Finalize a canonical qualified-dealer set into public-only state.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for malformed session bindings,
    /// insufficient or reordered dealers, or a failed adaptive transcript.
    pub fn from_qualified_dealers(
        session: ThresholdBlsSession<TleReleasePurpose>,
        validated_dealers: &[ValidatedDealerCommitment<TleReleasePurpose>],
        qualified_dealers: &[u16],
        dkg_event_hash: [u8; 32],
    ) -> Result<Self, TleReleaseAdapterError> {
        let parameters = AdaptiveThresholdBlsParameters::derive(&session)?;
        let transcript = AdaptiveThresholdBlsPublicTranscript::from_qualified_dealers(
            &parameters,
            validated_dealers,
            qualified_dealers,
            dkg_event_hash,
        )?;
        transcript.ensure_adaptive_protocol_ready()?;
        let key_session_id = TleKeySessionId::new(*session.session_id());
        let state = TleKeySessionPublicStateV1 {
            version: TLE_KEY_SESSION_ADAPTER_VERSION_V1,
            key_session_id,
            network_id: *session.network_id(),
            roster_hash: *session.roster_hash(),
            committee_size: session.committee_size(),
            threshold: session.threshold(),
            generator_h: *parameters.h_bytes(),
            generator_v: *parameters.v_bytes(),
            qualified_dealers: qualified_dealers.to_vec(),
            qualified_dealer_commitments: validated_dealers
                .iter()
                .map(TleAdaptiveDealerCommitmentV1::from_validated)
                .collect(),
            dkg_event_hash,
            group_public_key: *transcript.group_public_key().as_bytes(),
            public_shares: transcript
                .public_shares()
                .iter()
                .map(|share| TleAdaptivePublicShareV1 {
                    index: share.index(),
                    participant_hash: *share.participant_hash(),
                    public_key_share: *share.as_bytes(),
                })
                .collect(),
            transcript_hash: *transcript.transcript_hash(),
        };
        Ok(Self { state, transcript })
    }

    fn from_public_state(
        state: TleKeySessionPublicStateV1,
    ) -> Result<Self, TleReleaseAdapterError> {
        if state.version != TLE_KEY_SESSION_ADAPTER_VERSION_V1 {
            return Err(TleReleaseAdapterError::UnsupportedVersion);
        }
        if is_zero(state.key_session_id.as_bytes()) {
            return Err(TleReleaseAdapterError::ZeroKeySessionId);
        }
        let key_session_id = state.key_session_id;
        let session = ThresholdBlsSession::<TleReleasePurpose>::new(
            state.network_id,
            key_session_id.into_bytes(),
            state.roster_hash,
            state.committee_size,
            state.threshold,
        )?;
        let parameters = AdaptiveThresholdBlsParameters::derive(&session)?;
        if state.generator_h != *parameters.h_bytes() || state.generator_v != *parameters.v_bytes()
        {
            return Err(TleReleaseAdapterError::GeneratorMismatch);
        }
        if state.qualified_dealers.len() != state.qualified_dealer_commitments.len() {
            return Err(TleReleaseAdapterError::TranscriptMismatch);
        }
        // The crypto session already seals the exact 3f + 1 profile at at most
        // 31 seats. Retain proof-validated dealers inline rather than allocating
        // a second graph while importing a prepaid public transcript.
        let mut validated_dealers =
            ArrayVec::<_, { THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize }>::new();
        for (dealer, qualified_index) in state
            .qualified_dealer_commitments
            .iter()
            .zip(&state.qualified_dealers)
        {
            if dealer.dealer_index != *qualified_index {
                return Err(ThresholdBlsError::NonCanonicalQualifiedSet.into());
            }
            let validated = DasRenDealerCommitment::verify(
                &parameters,
                dealer.dealer_index,
                &dealer.coefficient_commitments,
                dealer.constant_pok_commitment,
                dealer.constant_pok_response,
            )?;
            validated_dealers
                .try_push(validated)
                .map_err(|_| ThresholdBlsError::NonCanonicalQualifiedSet)?;
        }
        let transcript = AdaptiveThresholdBlsPublicTranscript::from_qualified_dealers(
            &parameters,
            &validated_dealers,
            &state.qualified_dealers,
            state.dkg_event_hash,
        )?;
        transcript.ensure_adaptive_protocol_ready()?;
        let reconstructed_shares =
            transcript
                .public_shares()
                .iter()
                .map(|share| TleAdaptivePublicShareV1 {
                    index: share.index(),
                    participant_hash: *share.participant_hash(),
                    public_key_share: *share.as_bytes(),
                });
        if state.group_public_key != *transcript.group_public_key().as_bytes()
            || !state.public_shares.iter().copied().eq(reconstructed_shares)
            || state.transcript_hash != *transcript.transcript_hash()
            || state.dkg_event_hash != *transcript.dkg_event_hash()
        {
            return Err(TleReleaseAdapterError::TranscriptMismatch);
        }
        Ok(Self { state, transcript })
    }

    /// Borrow the canonical public-only persistence state.
    #[must_use]
    pub const fn public_state(&self) -> &TleKeySessionPublicStateV1 {
        &self.state
    }

    /// Borrow the verified adaptive cryptographic transcript.
    #[must_use]
    pub const fn transcript(&self) -> &AdaptiveThresholdBlsPublicTranscript<TleReleasePurpose> {
        &self.transcript
    }

    /// Return the typed threshold-release master public key.
    #[must_use]
    pub const fn master_public_key(&self) -> TleMasterPublicKey {
        TleMasterPublicKey::from_threshold_key(*self.transcript.group_public_key())
    }

    /// Convert and verify one locally produced adaptive partial release.
    ///
    /// The returned record contains public proof material only. Consensus must
    /// still authenticate the sender-to-index mapping before admitting it.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for an early release, wrong identity,
    /// transcript mismatch, or invalid partial proof.
    pub fn encode_partial_release(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        partial: &DasRenPartialSignature<TleReleasePurpose>,
    ) -> Result<TlePartialReleaseShareV1, TleReleaseAdapterError> {
        let identity_digest = self.validate_release_identity(identity, finalized_height)?;
        self.transcript
            .verify_partial_signature(&identity.payload_bytes(), partial)?;
        let (z_s, z_r, z_u) = partial.response_bytes();
        Ok(TlePartialReleaseShareV1 {
            key_session_id: self.state.key_session_id,
            identity_digest,
            participant_index: partial.index(),
            sigma: *partial.sigma_bytes(),
            proof_x: *partial.proof_x_bytes(),
            proof_y: *partial.proof_y_bytes(),
            z_s: *z_s,
            z_r: *z_r,
            z_u: *z_u,
        })
    }

    /// Parse and verify one public partial release for the exact future identity.
    ///
    /// Sender authentication and the sender-to-participant-index mapping remain
    /// consensus responsibilities; this method verifies the cryptographic seat.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for an early/wrong release, malformed
    /// point or scalar, replayed session, or failed adaptive proof.
    pub fn verify_partial_release(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        record: &TlePartialReleaseShareV1,
    ) -> Result<VerifiedTlePartialReleaseShareV1, TleReleaseAdapterError> {
        let identity_digest = self.validate_release_identity(identity, finalized_height)?;
        if record.key_session_id != self.state.key_session_id
            || record.identity_digest != identity_digest
        {
            return Err(TleReleaseAdapterError::ReleaseBindingMismatch);
        }
        let partial = DasRenPartialSignature::from_bytes(
            self.state.key_session_id.into_bytes(),
            record.participant_index,
            record.sigma,
            record.proof_x,
            record.proof_y,
            record.z_s,
            record.z_r,
            record.z_u,
        )?;
        self.transcript
            .verify_partial_signature(&identity.payload_bytes(), &partial)?;
        Ok(VerifiedTlePartialReleaseShareV1 {
            record: record.clone(),
            transcript_hash: self.state.transcript_hash,
            partial,
        })
    }

    /// Verify and combine canonical public partial-release records.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for an invalid share or a subset that
    /// is insufficient, duplicated, reordered, or bound to another identity.
    pub fn combine_partial_releases(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        records: &[TlePartialReleaseShareV1],
    ) -> Result<TleFinalReleaseSignatureV1, TleReleaseAdapterError> {
        let verified = records
            .iter()
            .map(|record| self.verify_partial_release(identity, finalized_height, record))
            .collect::<Result<Vec<_>, _>>()?;
        self.combine_verified_partial_releases(identity, finalized_height, &verified)
    }

    /// Combine already verified shares and final-verify the unique release signature.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for a cross-transcript wrapper,
    /// insufficient/noncanonical subset, or invalid final BLS signature.
    pub fn combine_verified_partial_releases(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        shares: &[VerifiedTlePartialReleaseShareV1],
    ) -> Result<TleFinalReleaseSignatureV1, TleReleaseAdapterError> {
        let identity_digest = self.validate_release_identity(identity, finalized_height)?;
        for share in shares {
            if share.transcript_hash != self.state.transcript_hash
                || share.record.key_session_id != self.state.key_session_id
                || share.record.identity_digest != identity_digest
            {
                return Err(TleReleaseAdapterError::ReleaseBindingMismatch);
            }
        }
        let partials = shares.iter().map(|share| share.partial).collect::<Vec<_>>();
        let signature = self
            .transcript
            .combine_partial_signatures(&identity.payload_bytes(), &partials)?;
        let record = TleFinalReleaseSignatureV1 {
            key_session_id: self.state.key_session_id,
            identity_digest,
            signature: *signature.as_bytes(),
        };
        self.verify_final_release(identity, finalized_height, &record)?;
        Ok(record)
    }

    /// Verify a public final release against the exact future identity.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] for an early/wrong release,
    /// malformed signature, or failed final pairing verification.
    pub fn verify_final_release(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        record: &TleFinalReleaseSignatureV1,
    ) -> Result<(), TleReleaseAdapterError> {
        let identity_digest = self.validate_release_identity(identity, finalized_height)?;
        if record.key_session_id != self.state.key_session_id
            || record.identity_digest != identity_digest
        {
            return Err(TleReleaseAdapterError::ReleaseBindingMismatch);
        }
        let signature = ThresholdBlsSignature::<TleReleasePurpose>::from_bytes(
            self.state.key_session_id.into_bytes(),
            &record.signature,
        )?;
        self.transcript
            .verify_final_signature(&identity.payload_bytes(), &signature)?;
        // Reuse the TLE identity-key verifier as a second typed binding check.
        // The zeroizing owner is immediately dropped; persistence retains only
        // the public final signature record.
        let release_key = TleIdentitySecretKeyV1::from_threshold_signature(
            self.master_public_key(),
            identity,
            &record.signature,
        )?;
        drop(release_key);
        Ok(())
    }

    /// Construct the zeroizing release key used by the folded aggregate opener.
    ///
    /// The returned runtime value has no serialization API. Callers must not
    /// persist or log it; the canonical persisted artifact is `record`.
    ///
    /// # Errors
    ///
    /// Returns [`TleReleaseAdapterError`] unless the target height has been
    /// finalized and the exact public final signature verifies.
    pub fn release_key_for_opening(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
        record: &TleFinalReleaseSignatureV1,
    ) -> Result<TleIdentitySecretKeyV1, TleReleaseAdapterError> {
        self.verify_final_release(identity, finalized_height, record)?;
        Ok(TleIdentitySecretKeyV1::from_threshold_signature(
            self.master_public_key(),
            identity,
            &record.signature,
        )?)
    }

    /// Verify the exact threshold session and finalized release height, returning its digest.
    ///
    /// # Errors
    /// Rejects a mismatched key/session or a release before its finalized target height.
    #[doc(hidden)]
    pub fn validate_release_identity(
        &self,
        identity: &TleReleaseIdentityV1,
        finalized_height: u64,
    ) -> Result<[u8; 32], TleReleaseAdapterError> {
        if identity.session() != self.transcript.session()
            || identity.session().session_id() != self.state.key_session_id.as_bytes()
        {
            return Err(TleReleaseAdapterError::ReleaseBindingMismatch);
        }
        if finalized_height < identity.target_finalized_height() {
            return Err(TleReleaseAdapterError::ReleaseHeightNotReached);
        }
        Ok(Sha256::digest(identity.release_message()?).into())
    }
}

/// Public-only wire projection of one Core-authorized TLE release.
///
/// This type carries no secret material, provider handle, or signing
/// capability. It exists solely so an authenticated local runtime broker can
/// revalidate the exact public session and release statement supplied by the
/// daemon. Cryptographic validation does **not** prove that a projection came
/// from committed state; broker transport must admit it only from the scoped
/// daemon session, and the daemon must construct it through
/// `iroha_core::tle_release::AuthorizedTleReleaseContextV1::broker_projection_v1`.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::AuthorizedTleReleaseProjectionV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct AuthorizedTleReleaseProjectionV1 {
    /// Fixed projection layout version.
    pub version: u16,
    /// Exact ballot attempt authorized by Core.
    pub ballot_attempt_id: BallotAttemptId,
    /// Inclusive final height of the aggregate-opening window.
    pub opening_deadline_height: u64,
    /// Finalized height observed by the authorizing committed view.
    pub finalized_height: u64,
    /// Complete proof-carrying public threshold-key transcript.
    pub key_session: TleKeySessionPublicStateV1,
    /// Frozen public timed-OVN release identity.
    pub public_release_identity: TimedOvnReleaseIdentityPublicV1,
    /// Exact fixed-size application identity payload.
    pub identity_payload: [u8; TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1],
    /// SHA-256 of the exact threshold-session-framed release message.
    pub identity_digest: [u8; 32],
}

impl AuthorizedTleReleaseProjectionV1 {
    /// Reconstruct and validate every public cryptographic and height binding.
    ///
    /// The result is intentionally distinct from
    /// `AuthorizedTleReleaseContextV1`. A valid wire projection is not a Core
    /// authorization capability and cannot be converted into one.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a wrong version, malformed public DKG state,
    /// inconsistent identity, invalid height window, payload mismatch, or
    /// digest mismatch.
    pub fn validate(self) -> Result<ValidatedTleReleaseProjectionV1, TleReleaseProjectionErrorV1> {
        if self.version != TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1 {
            return Err(TleReleaseProjectionErrorV1::UnsupportedVersion);
        }
        if self
            .ballot_attempt_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || self.ballot_attempt_id.as_bytes() != &self.public_release_identity.ballot_attempt_id
            || self.key_session.key_session_id != self.public_release_identity.tle_key_session_id
        {
            return Err(TleReleaseProjectionErrorV1::BindingMismatch);
        }
        if self.finalized_height < self.public_release_identity.target_finalized_height
            || self.finalized_height > self.opening_deadline_height
            || self.opening_deadline_height < self.public_release_identity.target_finalized_height
        {
            return Err(TleReleaseProjectionErrorV1::InvalidHeightWindow);
        }

        let session = self.key_session.clone().validate()?;
        let identity = TleReleaseIdentityV1::new(
            *session.transcript().session(),
            self.public_release_identity.governance_attempt_id,
            self.public_release_identity.body_instance_id,
            self.public_release_identity.ballot_attempt_id,
            self.public_release_identity.survivor_corpus_root,
            self.public_release_identity.no_recovery_root,
            self.public_release_identity.target_finalized_height,
            self.public_release_identity.parameter_hash,
        )?;
        let expected_payload: [u8; TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1] = identity
            .payload_bytes()
            .try_into()
            .map_err(|_| TleReleaseProjectionErrorV1::IdentityPayloadMismatch)?;
        if self.identity_payload != expected_payload {
            return Err(TleReleaseProjectionErrorV1::IdentityPayloadMismatch);
        }
        let identity_digest =
            session.validate_release_identity(&identity, self.finalized_height)?;
        if self.identity_digest != identity_digest {
            return Err(TleReleaseProjectionErrorV1::IdentityDigestMismatch);
        }
        Ok(ValidatedTleReleaseProjectionV1 {
            projection: self,
            session,
            identity,
        })
    }
}

/// Revalidated public statement admitted by an authenticated runtime broker.
///
/// The value has no serialization implementation and is not a substitute for
/// Core's opaque committed-state authorization.
#[derive(Debug, Clone)]
pub struct ValidatedTleReleaseProjectionV1 {
    projection: AuthorizedTleReleaseProjectionV1,
    session: ValidatedTleKeySessionV1,
    identity: TleReleaseIdentityV1,
}

impl ValidatedTleReleaseProjectionV1 {
    /// Borrow the complete validated public projection.
    #[must_use]
    pub const fn projection(&self) -> &AuthorizedTleReleaseProjectionV1 {
        &self.projection
    }

    /// Borrow the reconstructed, proof-validated public key session.
    #[must_use]
    pub const fn session(&self) -> &ValidatedTleKeySessionV1 {
        &self.session
    }

    /// Borrow the exact reconstructed threshold release identity.
    #[must_use]
    pub const fn identity(&self) -> &TleReleaseIdentityV1 {
        &self.identity
    }

    /// Return the finalized height carried by the authenticated broker request.
    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.projection.finalized_height
    }
}

/// Closed failures while validating a public authenticated-broker projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleReleaseProjectionErrorV1 {
    /// The broker projection used an unsupported layout version.
    #[error("unsupported Parliament TLE release projection version")]
    UnsupportedVersion,
    /// Public key-session, ballot, or release-identity bindings disagreed.
    #[error("Parliament TLE release projection binding mismatch")]
    BindingMismatch,
    /// The target, observed, and opening-deadline heights were inconsistent.
    #[error("Parliament TLE release projection height window is invalid")]
    InvalidHeightWindow,
    /// The transmitted fixed-size application payload was not canonical.
    #[error("Parliament TLE release projection identity payload mismatch")]
    IdentityPayloadMismatch,
    /// The transmitted threshold-framed identity digest was not canonical.
    #[error("Parliament TLE release projection identity digest mismatch")]
    IdentityDigestMismatch,
    /// Public key-session or release-identity cryptography was invalid.
    #[error(transparent)]
    Release(#[from] TleReleaseAdapterError),
    /// The typed release identity was invalid.
    #[error(transparent)]
    Identity(#[from] TleError),
}

/// Public adaptive partial release and representation proof.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::TlePartialReleaseShareV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
pub struct TlePartialReleaseShareV1 {
    /// Long-lived TLE key session.
    pub key_session_id: TleKeySessionId,
    /// SHA-256 of the exact typed future release message.
    pub identity_digest: [u8; 32],
    /// Canonical one-based threshold participant index.
    pub participant_index: u16,
    /// Canonical adaptive partial signature in G1.
    pub sigma: [u8; 48],
    /// Triple-generator representation-proof commitment in G2.
    pub proof_x: [u8; 96],
    /// Message-representation proof commitment in G1.
    pub proof_y: [u8; 48],
    /// Standard-generator proof response.
    pub z_s: [u8; 32],
    /// `h`/independent-message proof response.
    pub z_r: [u8; 32],
    /// `v` proof response.
    pub z_u: [u8; 32],
}

/// Constructor-authenticated partial release wrapper.
///
/// Every field is public proof material, but the wrapper is intentionally not
/// serializable: wire input must pass [`ValidatedTleKeySessionV1::verify_partial_release`]
/// after each restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTlePartialReleaseShareV1 {
    record: TlePartialReleaseShareV1,
    transcript_hash: [u8; 32],
    partial: DasRenPartialSignature<TleReleasePurpose>,
}

impl VerifiedTlePartialReleaseShareV1 {
    /// Borrow the canonical public wire record.
    #[must_use]
    pub const fn record(&self) -> &TlePartialReleaseShareV1 {
        &self.record
    }
}

/// Unique public final threshold release signature for one future identity.
///
/// No reconstruction subset or signer bitmap is serialized.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::TleFinalReleaseSignatureV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
)]
pub struct TleFinalReleaseSignatureV1 {
    /// Long-lived TLE key session.
    pub key_session_id: TleKeySessionId,
    /// SHA-256 of the exact typed future release message.
    pub identity_digest: [u8; 32],
    /// Canonical standard BLS group signature in G1.
    pub signature: [u8; 48],
}

/// Errors returned by the public TLE release adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TleReleaseAdapterError {
    /// A decoded public state advertised another adapter version.
    #[error("unsupported TLE key-session adapter version")]
    UnsupportedVersion,
    /// The long-lived key-session identifier was the all-zero placeholder.
    #[error("TLE key-session identifier must be non-zero")]
    ZeroKeySessionId,
    /// Persisted independent generators did not match deterministic derivation.
    #[error("TLE key-session adaptive generators do not match the typed session")]
    GeneratorMismatch,
    /// Cached public fields did not reconstruct to the committed transcript.
    #[error("TLE key-session public transcript mismatch")]
    TranscriptMismatch,
    /// A partial or final release was bound to another key session or identity.
    #[error("TLE release is bound to another key session or future identity")]
    ReleaseBindingMismatch,
    /// The identity's target finalized height has not yet been reached.
    #[error("TLE release target finalized height has not been reached")]
    ReleaseHeightNotReached,
    /// Adaptive threshold-BLS validation failed.
    #[error(transparent)]
    Threshold(#[from] ThresholdBlsError),
    /// Timelock identity validation failed.
    #[error(transparent)]
    Tle(#[from] TleError),
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Deterministic fixture construction, excluded from shipping builds.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;
