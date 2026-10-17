//! Replay-validated public casting archives, independent of the validator state.

use crate::evidence::{
    PreparedTimedOvnAttemptV1, TimedOvnEvidenceError, TimedOvnLifecyclePhaseV1,
    TimedOvnReleaseIdentityPublicV1, TimedOvnSessionPublicV1,
    rebuild_casting_registration_context_v1,
};
use crate::tle::{TleKeySessionPublicStateV1, TleReleaseAdapterError, ValidatedTleKeySessionV1};
use iroha_crypto::timed_ovn::TimedOvnSessionV1;
use iroha_data_model::governance::types::{
    BallotAttemptId, BodyInstanceId, GovernanceAttemptId, ProposalContentId,
};
use iroha_data_model::parliament_casting::{
    PARLIAMENT_TIMED_OVN_CASTING_COMMITMENT_VERSION_V1, ParliamentTimedOvnCastingContextBindingV1,
    ParliamentTimedOvnCastingPhaseV1 as CompactCastingPhaseV1,
    ParliamentTimedOvnRegistrationCorpusCommitmentV1, ParliamentTimedOvnReleaseBindingV1,
};
use norito::{NoritoDeserialize, NoritoSerialize};
use thiserror::Error;

/// Fixed canonical archive version for a public timed-OVN casting context.
pub const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1: u16 = 1;
/// Maximum complete Norito frame accepted for a V1 casting-context archive.
///
/// The four-mebibyte bound covers the protocol maximum of 1,000 exact
/// 3,624-byte registration records, 1,000 survivor identifiers, and the
/// complete proof-carrying 31-seat adaptive TLE transcript.
pub const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1: usize = 4 * 1024 * 1024;

/// Cast-capable prefix phases represented in the public wallet archive.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tle_release::casting::ParliamentTimedOvnCastingPhaseV1")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum ParliamentTimedOvnCastingPhaseV1 {
    /// Authenticated participant registrations are still accumulating.
    Registered,
    /// Registration is immutable and authenticated dropouts may accumulate.
    RegistrationClosed,
    /// The exact survivor subsequence and future release identity are frozen.
    SurvivorsFrozen,
}

impl TryFrom<TimedOvnLifecyclePhaseV1> for ParliamentTimedOvnCastingPhaseV1 {
    type Error = TimedOvnCastingAuthorizationErrorV1;

    fn try_from(value: TimedOvnLifecyclePhaseV1) -> Result<Self, Self::Error> {
        match value {
            TimedOvnLifecyclePhaseV1::Registered => Ok(Self::Registered),
            TimedOvnLifecyclePhaseV1::RegistrationClosed => Ok(Self::RegistrationClosed),
            TimedOvnLifecyclePhaseV1::SurvivorsFrozen => Ok(Self::SurvivorsFrozen),
            TimedOvnLifecyclePhaseV1::Sealed | TimedOvnLifecyclePhaseV1::Released => {
                Err(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Internal snapshot projection used by the Core state adapter.
#[doc(hidden)]
pub fn validate_casting_phase_window_v1(
    phase: ParliamentTimedOvnCastingPhaseV1,
    current_height: u64,
    registered_at_height: u64,
    registration_close_height: u64,
    survivor_freeze_height: u64,
    commitment_close_height: u64,
    release_height: u64,
) -> Result<(), TimedOvnCastingAuthorizationErrorV1> {
    if !(registered_at_height < registration_close_height
        && registration_close_height < survivor_freeze_height
        && survivor_freeze_height < commitment_close_height
        && commitment_close_height < release_height)
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule);
    }
    let inside_window = match phase {
        ParliamentTimedOvnCastingPhaseV1::Registered => {
            current_height >= registered_at_height && current_height < registration_close_height
        }
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
            current_height >= registration_close_height && current_height < survivor_freeze_height
        }
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => {
            current_height >= survivor_freeze_height && current_height < commitment_close_height
        }
    };
    if !inside_window {
        return Err(TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive);
    }
    Ok(())
}

/// Canonical public-only archive for restarting a timed-OVN wallet operation.
///
/// The archive contains no dropout decisions, masked ballots, release shares,
/// aggregate openings, account identifiers, or secret material. It is a public
/// snapshot, not an authorization capability: Core constructs it only after
/// replay-validating one committed state view inside the exact phase window,
/// while every eventual ledger mutation is authorized again against the
/// containing block. Phase deadlines are deliberately not duplicated in this
/// V1 archive: independent archive validation proves the recorded snapshot,
/// not that an older snapshot remains fresh at a later chain height.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::tle_release::casting::ParliamentTimedOvnCastingContextArchiveV1"
)]
pub struct ParliamentTimedOvnCastingContextArchiveV1 {
    version: u16,
    finalized_height: u64,
    phase: ParliamentTimedOvnCastingPhaseV1,
    session: TimedOvnSessionPublicV1,
    registration_opened_at_finalized_height: u64,
    target_finalized_height: u64,
    tle_key_session: TleKeySessionPublicStateV1,
    registration_records: Vec<Vec<u8>>,
    survivor_participant_hashes: Option<Vec<[u8; 32]>>,
    release_identity: Option<TimedOvnReleaseIdentityPublicV1>,
}

impl ParliamentTimedOvnCastingContextArchiveV1 {
    /// Assemble the public data from a state snapshot; this grants no authorization.
    /// Every consumer must replay-validate the resulting archive before use.
    #[doc(hidden)]
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_snapshot_parts_v1(
        finalized_height: u64,
        phase: ParliamentTimedOvnCastingPhaseV1,
        session: TimedOvnSessionPublicV1,
        registration_opened_at_finalized_height: u64,
        target_finalized_height: u64,
        tle_key_session: TleKeySessionPublicStateV1,
        registration_records: Vec<Vec<u8>>,
        survivor_participant_hashes: Option<Vec<[u8; 32]>>,
        release_identity: Option<TimedOvnReleaseIdentityPublicV1>,
    ) -> Self {
        Self {
            version: PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1,
            finalized_height,
            phase,
            session,
            registration_opened_at_finalized_height,
            target_finalized_height,
            tle_key_session,
            registration_records,
            survivor_participant_hashes,
            release_identity,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Construct and fully replay-validate a canonical public archive.
    ///
    /// The phase determines whether survivor and release fields must be absent
    /// or present; caller-supplied optional fields never bypass that check.
    ///
    /// # Errors
    /// Returns a closed error for an incoherent phase, invalid height schedule,
    /// oversized frame, malformed proof corpus, or mismatched TLE/session/release
    /// binding.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_parts_v1(
        finalized_height: u64,
        phase: ParliamentTimedOvnCastingPhaseV1,
        session: TimedOvnSessionPublicV1,
        registration_opened_at_finalized_height: u64,
        target_finalized_height: u64,
        tle_key_session: TleKeySessionPublicStateV1,
        registration_records: Vec<Vec<u8>>,
        survivor_participant_hashes: Option<Vec<[u8; 32]>>,
        release_identity: Option<TimedOvnReleaseIdentityPublicV1>,
    ) -> Result<Self, TimedOvnCastingArchiveValidationErrorV1> {
        let archive = Self {
            version: PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1,
            finalized_height,
            phase,
            session,
            registration_opened_at_finalized_height,
            target_finalized_height,
            tle_key_session,
            registration_records,
            survivor_participant_hashes,
            release_identity,
        };
        archive.validate_v1()?;
        Ok(archive)
    }

    /// Return the fixed archive layout version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Return the finalized height of the authorizing state snapshot.
    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Return the exact committed casting lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> ParliamentTimedOvnCastingPhaseV1 {
        self.phase
    }

    /// Borrow the immutable timed-OVN session bindings.
    #[must_use]
    pub const fn session(&self) -> &TimedOvnSessionPublicV1 {
        &self.session
    }

    /// Return the immutable finalized height at which registration opened.
    #[must_use]
    pub const fn registration_opened_at_finalized_height(&self) -> u64 {
        self.registration_opened_at_finalized_height
    }

    /// Return the immutable first finalized height permitting release.
    #[must_use]
    pub const fn target_finalized_height(&self) -> u64 {
        self.target_finalized_height
    }

    /// Borrow the complete proof-validated public TLE session.
    #[must_use]
    pub const fn tle_key_session(&self) -> &TleKeySessionPublicStateV1 {
        &self.tle_key_session
    }

    /// Borrow the exact canonical registration-record corpus.
    #[must_use]
    pub fn registration_records(&self) -> &[Vec<u8>] {
        &self.registration_records
    }

    /// Borrow the frozen survivor subsequence, present only after survivor freeze.
    #[must_use]
    pub fn survivor_participant_hashes(&self) -> Option<&[[u8; 32]]> {
        self.survivor_participant_hashes.as_deref()
    }

    /// Borrow the exact future release identity, present only after survivor freeze.
    #[must_use]
    pub const fn release_identity(&self) -> Option<&TimedOvnReleaseIdentityPublicV1> {
        self.release_identity.as_ref()
    }

    /// Replay-validate the complete public archive into nonserializable runtime objects.
    ///
    /// # Errors
    /// Returns a closed error for a wrong version, oversized canonical frame,
    /// incoherent phase fields, invalid height schedule, malformed public DKG,
    /// invalid registration proof, or mismatched survivor/release binding.
    pub fn validate_v1(
        &self,
    ) -> Result<
        ValidatedParliamentTimedOvnCastingContextArchiveV1,
        TimedOvnCastingArchiveValidationErrorV1,
    > {
        self.to_canonical_bytes_v1()?;
        if self.version != PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1 {
            return Err(TimedOvnCastingArchiveValidationErrorV1::UnsupportedVersion);
        }
        if self.registration_opened_at_finalized_height == 0
            || self.registration_opened_at_finalized_height > self.finalized_height
            || self.target_finalized_height <= self.registration_opened_at_finalized_height
        {
            return Err(TimedOvnCastingArchiveValidationErrorV1::InvalidHeightSchedule);
        }
        let frozen_fields_are_coherent = match self.phase {
            ParliamentTimedOvnCastingPhaseV1::Registered
            | ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
                self.survivor_participant_hashes.is_none() && self.release_identity.is_none()
            }
            ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => {
                self.survivor_participant_hashes.is_some() && self.release_identity.is_some()
            }
        };
        if !frozen_fields_are_coherent {
            return Err(TimedOvnCastingArchiveValidationErrorV1::PhaseFieldMismatch);
        }

        let tle_key_session = self.tle_key_session.clone().validate()?;
        if self.session.network_id != tle_key_session.public_state().network_id {
            return Err(TimedOvnCastingArchiveValidationErrorV1::SessionBindingMismatch);
        }
        let (timed_ovn_session, registration_roster) = rebuild_casting_registration_context_v1(
            &self.session,
            &self.registration_records,
            &tle_key_session,
        )?;
        if self.phase != ParliamentTimedOvnCastingPhaseV1::Registered
            && registration_roster.is_none()
        {
            return Err(TimedOvnCastingArchiveValidationErrorV1::PhaseFieldMismatch);
        }

        let prepared_attempt = match (
            self.phase,
            self.survivor_participant_hashes.as_deref(),
            self.release_identity,
        ) {
            (
                ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen,
                Some(survivors),
                Some(release_identity),
            ) => Some(PreparedTimedOvnAttemptV1::from_records(
                self.session,
                &self.registration_records,
                survivors,
                release_identity,
                &tle_key_session,
            )?),
            (ParliamentTimedOvnCastingPhaseV1::Registered, None, None)
            | (ParliamentTimedOvnCastingPhaseV1::RegistrationClosed, None, None) => None,
            _ => return Err(TimedOvnCastingArchiveValidationErrorV1::PhaseFieldMismatch),
        };
        if self.release_identity.is_some_and(|identity| {
            identity.target_finalized_height != self.target_finalized_height
        }) {
            return Err(TimedOvnCastingArchiveValidationErrorV1::SessionBindingMismatch);
        }

        Ok(ValidatedParliamentTimedOvnCastingContextArchiveV1 {
            archive: self.clone(),
            tle_key_session,
            timed_ovn_session,
            prepared_attempt,
        })
    }

    /// Encode one complete canonical, header-framed Norito archive.
    ///
    /// # Errors
    /// Returns an encoding error if the canonical frame exceeds the fixed V1
    /// limit or serialization/allocation fails.
    pub fn to_canonical_bytes_v1(&self) -> Result<Vec<u8>, norito::core::BoundedEncodeError> {
        norito::core::to_bytes_bounded(
            self,
            PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1,
        )
    }
}

/// Nonserializable runtime result of replay-validating a casting-context archive.
#[derive(Debug, Clone)]
pub struct ValidatedParliamentTimedOvnCastingContextArchiveV1 {
    archive: ParliamentTimedOvnCastingContextArchiveV1,
    tle_key_session: ValidatedTleKeySessionV1,
    timed_ovn_session: TimedOvnSessionV1,
    prepared_attempt: Option<PreparedTimedOvnAttemptV1>,
}

impl ValidatedParliamentTimedOvnCastingContextArchiveV1 {
    /// Borrow the exact public archive that was replay-validated.
    #[must_use]
    pub const fn archive(&self) -> &ParliamentTimedOvnCastingContextArchiveV1 {
        &self.archive
    }

    /// Borrow the reconstructed proof-validated public TLE session.
    #[must_use]
    pub const fn tle_key_session(&self) -> &ValidatedTleKeySessionV1 {
        &self.tle_key_session
    }

    /// Borrow the exact reconstructed timed-OVN session.
    #[must_use]
    pub const fn timed_ovn_session(&self) -> &TimedOvnSessionV1 {
        &self.timed_ovn_session
    }

    /// Borrow the prepared survivor roster and release identity after freeze.
    #[must_use]
    pub const fn prepared_attempt(&self) -> Option<&PreparedTimedOvnAttemptV1> {
        self.prepared_attempt.as_ref()
    }

    /// Recompute the compact context leaf from this fully replay-validated archive.
    ///
    /// The three reducer deadlines are supplied by the consensus-authenticated
    /// compact leaf. Every other field, including the exact registration corpus,
    /// survivor/dropout roots, release identity, and TLE transcript binding, is
    /// recomputed from the archive before equality with that authenticated leaf
    /// may be accepted.
    pub fn compact_binding_v1(
        &self,
        registration_close_height: u64,
        survivor_freeze_height: u64,
        commitment_close_height: u64,
    ) -> Result<ParliamentTimedOvnCastingContextBindingV1, TimedOvnCastingArchiveValidationErrorV1>
    {
        let archive = &self.archive;
        validate_casting_phase_window_v1(
            archive.phase,
            archive.finalized_height,
            archive.registration_opened_at_finalized_height,
            registration_close_height,
            survivor_freeze_height,
            commitment_close_height,
            archive.target_finalized_height,
        )
        .map_err(|_| TimedOvnCastingArchiveValidationErrorV1::InvalidHeightSchedule)?;
        let registration_corpus = ParliamentTimedOvnRegistrationCorpusCommitmentV1::from_records(
            &archive.registration_records,
        )
        .ok_or(TimedOvnCastingArchiveValidationErrorV1::InvalidHeightSchedule)?;
        let (survivor_count, dropout_root, release_identity) = match (
            archive.phase,
            archive.survivor_participant_hashes.as_deref(),
            archive.release_identity,
        ) {
            (ParliamentTimedOvnCastingPhaseV1::Registered, None, None)
            | (ParliamentTimedOvnCastingPhaseV1::RegistrationClosed, None, None) => {
                (None, None, None)
            }
            (ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen, Some(survivors), Some(release)) => {
                let roots = crate::evidence::derive_timed_ovn_roots_v1(
                    &archive.session,
                    &archive.registration_records,
                    survivors,
                    &self.tle_key_session,
                )?;
                let count = u32::try_from(survivors.len())
                    .map_err(|_| TimedOvnCastingArchiveValidationErrorV1::PhaseFieldMismatch)?;
                (
                    Some(count),
                    Some(roots.dropout_root),
                    Some(compact_release_binding_v1(release)),
                )
            }
            _ => return Err(TimedOvnCastingArchiveValidationErrorV1::PhaseFieldMismatch),
        };
        let binding = ParliamentTimedOvnCastingContextBindingV1 {
            version: PARLIAMENT_TIMED_OVN_CASTING_COMMITMENT_VERSION_V1,
            evaluated_height: archive.finalized_height,
            phase: compact_casting_phase_v1(archive.phase),
            network_id: archive.session.network_id,
            proposal_content_id: ProposalContentId::new(archive.session.proposal_content_id),
            governance_attempt_id: GovernanceAttemptId::new(archive.session.governance_attempt_id),
            body_instance_id: BodyInstanceId::new(archive.session.body_instance_id),
            ballot_attempt_id: BallotAttemptId::new(archive.session.ballot_attempt_id),
            parameter_hash: archive.session.parameter_hash,
            tle_key_session_id: archive.session.tle_key_session_id,
            tle_key_transcript_hash: archive.session.tle_key_transcript_hash,
            tle_master_public_key: archive.session.tle_master_public_key,
            registration_opened_at_finalized_height: archive
                .registration_opened_at_finalized_height,
            registration_close_height,
            survivor_freeze_height,
            commitment_close_height,
            target_finalized_height: archive.target_finalized_height,
            registration_corpus,
            survivor_count,
            dropout_root,
            release_identity,
        };
        if !binding.is_valid() {
            return Err(TimedOvnCastingArchiveValidationErrorV1::InvalidHeightSchedule);
        }
        Ok(binding)
    }

    /// Return whether this archive recomputes the exact authenticated compact leaf.
    #[must_use]
    pub fn matches_compact_binding_v1(
        &self,
        binding: &ParliamentTimedOvnCastingContextBindingV1,
    ) -> bool {
        self.compact_binding_v1(
            binding.registration_close_height,
            binding.survivor_freeze_height,
            binding.commitment_close_height,
        )
        .is_ok_and(|recomputed| recomputed == *binding)
    }
}

/// Internal snapshot projection used by the Core state adapter.
#[doc(hidden)]
pub const fn compact_casting_phase_v1(
    phase: ParliamentTimedOvnCastingPhaseV1,
) -> CompactCastingPhaseV1 {
    match phase {
        ParliamentTimedOvnCastingPhaseV1::Registered => CompactCastingPhaseV1::Registered,
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
            CompactCastingPhaseV1::RegistrationClosed
        }
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => CompactCastingPhaseV1::SurvivorsFrozen,
    }
}

/// Internal snapshot projection used by the Core state adapter.
#[doc(hidden)]
pub const fn compact_release_binding_v1(
    release: TimedOvnReleaseIdentityPublicV1,
) -> ParliamentTimedOvnReleaseBindingV1 {
    ParliamentTimedOvnReleaseBindingV1 {
        tle_key_session_id: release.tle_key_session_id,
        governance_attempt_id: GovernanceAttemptId::new(release.governance_attempt_id),
        body_instance_id: BodyInstanceId::new(release.body_instance_id),
        ballot_attempt_id: BallotAttemptId::new(release.ballot_attempt_id),
        survivor_corpus_root: release.survivor_corpus_root,
        no_recovery_root: release.no_recovery_root,
        target_finalized_height: release.target_finalized_height,
        parameter_hash: release.parameter_hash,
    }
}

/// Closed failures while authorizing a public timed-OVN casting context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimedOvnCastingAuthorizationErrorV1 {
    /// The committed height cannot be represented by the V1 archive.
    #[error("committed state height does not fit the timed-OVN casting protocol")]
    HeightOverflow,
    /// No public timed-OVN lifecycle exists for the requested ballot.
    #[error("timed-OVN evidence is missing for the ballot")]
    MissingTimedOvnEvidence,
    /// The referenced complete public TLE transcript is absent.
    #[error("TLE key session is missing")]
    MissingKeySession,
    /// The lifecycle's governance attempt is absent.
    #[error("Parliament governance attempt is missing")]
    MissingGovernanceAttempt,
    /// The lifecycle's ballot is absent from its governance attempt.
    #[error("Parliament ballot attempt is missing")]
    MissingBallot,
    /// The lifecycle's body is absent from its governance attempt.
    #[error("Parliament body instance is missing")]
    MissingBody,
    /// The complete reducer snapshot did not validate.
    #[error("Parliament reducer state is invalid")]
    InvalidParliamentState,
    /// The persisted ballot deadlines are not one strictly increasing schedule.
    #[error("Parliament timed-OVN casting phase schedule is invalid")]
    InvalidPhaseSchedule,
    /// The state snapshot height is outside the exact half-open lifecycle window.
    #[error("Parliament timed-OVN casting phase is not active at the finalized height")]
    PhaseWindowInactive,
    /// The containing governance attempt is terminal.
    #[error("Parliament governance attempt is not active")]
    GovernanceAttemptNotActive,
    /// The bound body is not currently balloting.
    #[error("Parliament body is not in its balloting phase")]
    BodyNotBalloting,
    /// The bound body uses public finding rather than hidden binding.
    #[error("Parliament body does not use a hidden-binding ballot")]
    BodyNotHiddenBinding,
    /// The ballot or body is not the exact active reducer selection.
    #[error("Parliament ballot is not the active ballot for its body")]
    BallotNotActive,
    /// The timed-OVN lifecycle is sealed or released and no longer cast-capable.
    #[error("timed-OVN lifecycle is no longer in a casting phase")]
    PhaseNotCastable,
    /// Reducer ballot status and timed-OVN lifecycle phase disagreed.
    #[error("Parliament ballot and timed-OVN casting phases disagree")]
    PhaseBindingMismatch,
    /// Two committed objects disagreed on an immutable session or schedule binding.
    #[error("Parliament timed-OVN casting state has inconsistent bindings")]
    BindingMismatch,
    /// Public TLE transcript validation failed.
    #[error(transparent)]
    KeySession(#[from] TleReleaseAdapterError),
    /// Timed-OVN lifecycle replay validation failed.
    #[error(transparent)]
    TimedOvn(#[from] TimedOvnEvidenceError),
}

/// Closed failures while replay-validating a public casting-context archive.
#[derive(Debug, Error)]
pub enum TimedOvnCastingArchiveValidationErrorV1 {
    /// The archive advertised another layout version.
    #[error("unsupported Parliament timed-OVN casting archive version")]
    UnsupportedVersion,
    /// Registration-open, snapshot, and release-target heights are inconsistent.
    #[error("Parliament timed-OVN casting archive height schedule is invalid")]
    InvalidHeightSchedule,
    /// Phase-dependent survivor or release fields are missing or unexpectedly present.
    #[error("Parliament timed-OVN casting archive phase fields are inconsistent")]
    PhaseFieldMismatch,
    /// Public TLE, timed-OVN session, target, or release bindings disagree.
    #[error("Parliament timed-OVN casting archive session binding mismatch")]
    SessionBindingMismatch,
    /// The complete canonical Norito frame exceeded its bound or failed to encode.
    #[error(transparent)]
    Encoding(#[from] norito::core::BoundedEncodeError),
    /// Public TLE transcript validation failed.
    #[error(transparent)]
    KeySession(#[from] TleReleaseAdapterError),
    /// Timed-OVN session, registration, survivor, or release replay failed.
    #[error(transparent)]
    TimedOvn(#[from] TimedOvnEvidenceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_parts_preserve_public_data_and_require_replay_validation() {
        let key = crate::tle::test_fixtures::fixture().validated;
        let public_key = key.public_state().clone();
        let session = TimedOvnSessionPublicV1 {
            network_id: public_key.network_id,
            proposal_content_id: [10; 32],
            governance_attempt_id: [11; 32],
            body_instance_id: [12; 32],
            ballot_attempt_id: [13; 32],
            parameter_hash: crate::evidence::timed_ovn_parameter_hash_v1(),
            tle_key_session_id: public_key.key_session_id,
            tle_key_transcript_hash: public_key.transcript_hash,
            tle_master_public_key: *key.master_public_key().as_bytes(),
        };
        let invalid_registration = vec![vec![1, 2, 3]];
        let archive = ParliamentTimedOvnCastingContextArchiveV1::from_snapshot_parts_v1(
            20,
            ParliamentTimedOvnCastingPhaseV1::Registered,
            session,
            10,
            50,
            public_key.clone(),
            invalid_registration.clone(),
            None,
            None,
        );
        assert_eq!(
            archive.version(),
            PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1
        );
        assert_eq!(archive.finalized_height(), 20);
        assert_eq!(
            archive.phase(),
            ParliamentTimedOvnCastingPhaseV1::Registered
        );
        assert_eq!(archive.session(), &session);
        assert_eq!(archive.registration_opened_at_finalized_height(), 10);
        assert_eq!(archive.target_finalized_height(), 50);
        assert_eq!(archive.tle_key_session(), &public_key);
        assert_eq!(archive.registration_records(), invalid_registration);
        assert_eq!(archive.survivor_participant_hashes(), None);
        assert_eq!(archive.release_identity(), None);
        assert!(archive.validate_v1().is_err());
    }

    const REGISTERED_AT: u64 = 10;
    const REGISTRATION_CLOSE: u64 = 20;
    const SURVIVOR_FREEZE: u64 = 30;
    const COMMITMENT_CLOSE: u64 = 40;
    const RELEASE: u64 = 50;

    fn validate(
        phase: ParliamentTimedOvnCastingPhaseV1,
        height: u64,
    ) -> Result<(), TimedOvnCastingAuthorizationErrorV1> {
        validate_casting_phase_window_v1(
            phase,
            height,
            REGISTERED_AT,
            REGISTRATION_CLOSE,
            SURVIVOR_FREEZE,
            COMMITMENT_CLOSE,
            RELEASE,
        )
    }

    #[test]
    fn casting_phase_windows_are_exact_and_half_open() {
        for (phase, start, end) in [
            (
                ParliamentTimedOvnCastingPhaseV1::Registered,
                REGISTERED_AT,
                REGISTRATION_CLOSE,
            ),
            (
                ParliamentTimedOvnCastingPhaseV1::RegistrationClosed,
                REGISTRATION_CLOSE,
                SURVIVOR_FREEZE,
            ),
            (
                ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen,
                SURVIVOR_FREEZE,
                COMMITMENT_CLOSE,
            ),
        ] {
            assert_eq!(validate(phase, start), Ok(()));
            assert_eq!(validate(phase, end - 1), Ok(()));
            assert_eq!(
                validate(phase, start - 1),
                Err(TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive)
            );
            assert_eq!(
                validate(phase, end),
                Err(TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive)
            );
        }
    }

    #[test]
    fn casting_phase_window_rejects_nonmonotone_schedules() {
        for schedule in [
            (10, 10, 30, 40, 50),
            (10, 20, 20, 40, 50),
            (10, 20, 30, 30, 50),
            (10, 20, 30, 40, 40),
            (40, 30, 20, 10, 50),
        ] {
            assert_eq!(
                validate_casting_phase_window_v1(
                    ParliamentTimedOvnCastingPhaseV1::Registered,
                    schedule.0,
                    schedule.0,
                    schedule.1,
                    schedule.2,
                    schedule.3,
                    schedule.4,
                ),
                Err(TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule)
            );
        }
    }
}
