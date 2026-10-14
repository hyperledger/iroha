//! Replay-validated public context for Parliament timed-OVN wallet operations.

use iroha_data_model::governance::types::{
    BallotAttemptId, BallotAttemptStatusV1, BodyInstanceId, BodyInstanceStatusV1,
    GovernanceAttemptId, GovernanceAttemptStatusV1, ProposalContentId, TleSessionId,
};
use iroha_data_model::parliament_casting::{
    PARLIAMENT_TIMED_OVN_CASTING_COMMITMENT_VERSION_V1, ParliamentTimedOvnCastingContextBindingV1,
    ParliamentTimedOvnCastingSnapshotCommitmentV1,
};
use mv::storage::StorageReadOnly;

use super::ValidatedTleKeySessionV1;
use crate::{
    governance::{
        parliament::{ParliamentDecisionModeV1, ParliamentReducerErrorV1},
        timed_ovn::{
            TimedOvnLifecycleStateV1, TimedOvnReleaseIdentityPublicV1, TimedOvnSessionPublicV1,
        },
    },
    state::{ParliamentTimedOvnCastingCandidateV1, StateReadOnly, WorldReadOnly as _},
};

use iroha_core_timed_ovn::casting::*;

/// Constructor-authenticated, replay-validated timed-OVN casting context.
///
/// This value is deliberately not serializable. Use [`Self::archive_v1`] for
/// the canonical public-only wallet archive. Construction also proves that the
/// containing finalized height lies inside the reducer's exact phase window;
/// that freshness property is point-in-time and is not carried as an offline
/// authorization capability by the archive.
#[derive(Debug, Clone)]
pub struct AuthorizedTimedOvnCastingContextV1 {
    finalized_height: u64,
    phase: ParliamentTimedOvnCastingPhaseV1,
    session: TimedOvnSessionPublicV1,
    registration_opened_at_finalized_height: u64,
    target_finalized_height: u64,
    tle_key_session: ValidatedTleKeySessionV1,
    registration_records: Vec<Vec<u8>>,
    survivor_participant_hashes: Option<Vec<[u8; 32]>>,
    release_identity: Option<TimedOvnReleaseIdentityPublicV1>,
}

impl AuthorizedTimedOvnCastingContextV1 {
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

    /// Borrow the proof-revalidated public TLE key session.
    #[must_use]
    pub const fn tle_key_session(&self) -> &ValidatedTleKeySessionV1 {
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

    /// Project the validated context into its canonical public-only archive.
    #[must_use]
    pub fn archive_v1(&self) -> ParliamentTimedOvnCastingContextArchiveV1 {
        ParliamentTimedOvnCastingContextArchiveV1::from_snapshot_parts_v1(
            self.finalized_height,
            self.phase,
            self.session,
            self.registration_opened_at_finalized_height,
            self.target_finalized_height,
            self.tle_key_session.public_state().clone(),
            self.registration_records.clone(),
            self.survivor_participant_hashes.clone(),
            self.release_identity,
        )
    }
}

/// Derive the exact bounded authorized casting-context set and its root at one height.
///
/// This path deliberately reads the transition-maintained registration-corpus
/// commitment instead of reparsing response-sized registration records. Full
/// corpus replay remains mandatory at every lifecycle transition and during
/// world-state restore.
pub(crate) fn derive_parliament_timed_ovn_casting_snapshot_v1(
    world: &impl crate::state::WorldReadOnly,
    evaluated_height: u64,
) -> Result<
    (
        ParliamentTimedOvnCastingSnapshotCommitmentV1,
        Vec<ParliamentTimedOvnCastingContextBindingV1>,
    ),
    TimedOvnCastingAuthorizationErrorV1,
> {
    let mut bindings = Vec::new();
    for (
        ballot_attempt_id,
        governance_attempt_id,
        valid_from_height,
        valid_until_height_exclusive,
    ) in world.parliament_timed_ovn_casting_candidates()
    {
        let candidate = ParliamentTimedOvnCastingCandidateV1 {
            governance_attempt_id,
            valid_from_height,
            valid_until_height_exclusive,
        };
        if evaluated_height < candidate.valid_from_height
            || evaluated_height >= candidate.valid_until_height_exclusive
        {
            continue;
        }
        let lifecycle = world
            .timed_ovn_evidence()
            .get(&ballot_attempt_id)
            .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingTimedOvnEvidence)?;
        let binding = compact_binding_from_world_v1(
            world,
            evaluated_height,
            ballot_attempt_id,
            &candidate,
            lifecycle,
        )?
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
        bindings.push(binding);
    }
    bindings.sort_by_key(|binding| binding.ballot_attempt_id);
    let snapshot = ParliamentTimedOvnCastingSnapshotCommitmentV1::from_ordered_bindings(
        evaluated_height,
        &bindings,
    )
    .map_err(|_| TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    Ok((snapshot, bindings))
}

fn compact_binding_from_world_v1(
    world: &impl crate::state::WorldReadOnly,
    evaluated_height: u64,
    ballot_attempt_id: BallotAttemptId,
    candidate: &ParliamentTimedOvnCastingCandidateV1,
    lifecycle: &TimedOvnLifecycleStateV1,
) -> Result<Option<ParliamentTimedOvnCastingContextBindingV1>, TimedOvnCastingAuthorizationErrorV1>
{
    let phase = match ParliamentTimedOvnCastingPhaseV1::try_from(lifecycle.phase()) {
        Ok(phase) => phase,
        Err(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable) => return Ok(None),
        Err(error) => return Err(error),
    };
    if lifecycle.ballot_attempt_id() != *ballot_attempt_id.as_bytes() {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let session = *lifecycle.session();
    let governance_attempt_id = GovernanceAttemptId::new(session.governance_attempt_id);
    if candidate.governance_attempt_id != governance_attempt_id {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let attempt = world
        .parliament_attempts()
        .get(&governance_attempt_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingGovernanceAttempt)?;
    attempt.validate().map_err(|error| match error {
        ParliamentReducerErrorV1::InvalidBallotSchedule => {
            TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule
        }
        _ => TimedOvnCastingAuthorizationErrorV1::InvalidParliamentState,
    })?;
    if attempt.attempt().status != GovernanceAttemptStatusV1::Active {
        return Ok(None);
    }
    let ballot = attempt
        .ballot(&ballot_attempt_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingBallot)?;
    let body_instance_id = BodyInstanceId::new(session.body_instance_id);
    let body = attempt
        .body(&body_instance_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingBody)?;
    if body.instance().status != BodyInstanceStatusV1::Balloting {
        return Ok(None);
    }
    let required_body = attempt
        .required_bodies()
        .iter()
        .find(|required| required.body == body.instance().body)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    if required_body.decision_mode != ParliamentDecisionModeV1::HiddenBindingBallot {
        return Err(TimedOvnCastingAuthorizationErrorV1::BodyNotHiddenBinding);
    }
    if attempt
        .sealed_body_for_role(body.instance().body)
        .is_none_or(|active| active.instance().id != body_instance_id)
        || attempt
            .active_ballot_for_body(&body_instance_id)
            .is_none_or(|active| active.attempt().id != ballot_attempt_id)
    {
        return Ok(None);
    }
    let expected_ballot_status = match phase {
        ParliamentTimedOvnCastingPhaseV1::Registered => BallotAttemptStatusV1::Registration,
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
            BallotAttemptStatusV1::SurvivorFreeze
        }
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => BallotAttemptStatusV1::TimedCommitment,
    };
    if ballot.attempt().status != expected_ballot_status {
        return Err(TimedOvnCastingAuthorizationErrorV1::PhaseBindingMismatch);
    }
    let (expected_valid_from_height, expected_valid_until_height_exclusive) = match phase {
        ParliamentTimedOvnCastingPhaseV1::Registered => (
            ballot.registered_at_height(),
            ballot.registration_close_height(),
        ),
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => (
            ballot.registration_close_height(),
            ballot.survivor_freeze_height(),
        ),
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => (
            ballot.survivor_freeze_height(),
            ballot.commitment_close_height(),
        ),
    };
    if candidate.valid_from_height != expected_valid_from_height
        || candidate.valid_until_height_exclusive != expected_valid_until_height_exclusive
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let registration_opened_at_finalized_height = lifecycle
        .registration_opened_at_finalized_height()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    match validate_casting_phase_window_v1(
        phase,
        evaluated_height,
        ballot.registered_at_height(),
        ballot.registration_close_height(),
        ballot.survivor_freeze_height(),
        ballot.commitment_close_height(),
        lifecycle.target_finalized_height(),
    ) {
        Ok(()) => {}
        Err(TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive) => return Ok(None),
        Err(error) => return Err(error),
    }
    let key_session_id = lifecycle.tle_key_session_id();
    let tle_key_session = world
        .tle_key_sessions()
        .get(&key_session_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingKeySession)?;
    let release_beacon_session_id = ballot
        .release_beacon_session_id()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    let expected_tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        key_session_id,
        release_beacon_session_id,
        lifecycle.target_finalized_height(),
    );
    if attempt.proposal_content_id().as_bytes() != &session.proposal_content_id
        || body.instance().governance_attempt_id != governance_attempt_id
        || ballot.attempt().body_instance_id != body_instance_id
        || ballot.tle_key_session_id() != Some(key_session_id)
        || ballot.tle_session_id() != Some(expected_tle_session_id)
        || ballot.release_height() != Some(lifecycle.target_finalized_height())
        || registration_opened_at_finalized_height != ballot.registered_at_height()
        || session.network_id != tle_key_session.network_id
        || session.tle_key_session_id != tle_key_session.key_session_id
        || session.tle_key_transcript_hash != tle_key_session.transcript_hash
        || session.tle_master_public_key != tle_key_session.group_public_key
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let registration_corpus = *lifecycle
        .castable_registration_corpus_commitment()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable)?;
    if usize::try_from(registration_corpus.record_count).ok()
        != Some(lifecycle.registration_records().len())
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let (survivor_count, dropout_root, release_identity) = match lifecycle {
        TimedOvnLifecycleStateV1::Registered(_)
        | TimedOvnLifecycleStateV1::RegistrationClosed(_) => (None, None, None),
        TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) => (
            Some(
                u32::try_from(frozen.survivor_participant_hashes().len())
                    .map_err(|_| TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?,
            ),
            Some(*frozen.dropout_root()),
            Some(compact_release_binding_v1(*frozen.release_identity())),
        ),
        TimedOvnLifecycleStateV1::CorpusOpen(open) => (
            Some(
                u32::try_from(open.frozen().survivor_participant_hashes().len())
                    .map_err(|_| TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?,
            ),
            Some(*open.frozen().dropout_root()),
            Some(compact_release_binding_v1(
                *open.frozen().release_identity(),
            )),
        ),
        TimedOvnLifecycleStateV1::Sealed(_) | TimedOvnLifecycleStateV1::Released(_) => {
            return Ok(None);
        }
    };
    let binding = ParliamentTimedOvnCastingContextBindingV1 {
        version: PARLIAMENT_TIMED_OVN_CASTING_COMMITMENT_VERSION_V1,
        evaluated_height,
        phase: compact_casting_phase_v1(phase),
        network_id: session.network_id,
        proposal_content_id: ProposalContentId::new(session.proposal_content_id),
        governance_attempt_id,
        body_instance_id,
        ballot_attempt_id,
        parameter_hash: session.parameter_hash,
        tle_key_session_id: session.tle_key_session_id,
        tle_key_transcript_hash: session.tle_key_transcript_hash,
        tle_master_public_key: session.tle_master_public_key,
        registration_opened_at_finalized_height,
        registration_close_height: ballot.registration_close_height(),
        survivor_freeze_height: ballot.survivor_freeze_height(),
        commitment_close_height: ballot.commitment_close_height(),
        target_finalized_height: lifecycle.target_finalized_height(),
        registration_corpus,
        survivor_count,
        dropout_root,
        release_identity,
    };
    if !binding.is_valid() {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    Ok(Some(binding))
}

/// Authorize and replay-validate one public timed-OVN casting context.
///
/// The function takes one point-in-time state view and joins the active
/// governance attempt, exact active hidden-binding body and ballot, timed-OVN
/// lifecycle, and complete public TLE transcript. Only the three pre-seal
/// phases are admitted, and the finalized state height must lie in the exact
/// half-open reducer window for that phase. No masked ballot, dropout decision,
/// release share, opening, account label, or secret is returned.
///
/// # Errors
/// Returns a closed error for missing, terminal, post-seal, malformed,
/// out-of-window, or cross-bound committed state.
pub fn authorize_parliament_timed_ovn_casting_context_v1(
    state: &impl StateReadOnly,
    ballot_attempt_id: BallotAttemptId,
) -> Result<AuthorizedTimedOvnCastingContextV1, TimedOvnCastingAuthorizationErrorV1> {
    let finalized_height = u64::try_from(state.height())
        .map_err(|_| TimedOvnCastingAuthorizationErrorV1::HeightOverflow)?;
    let world = state.world();
    let lifecycle = world
        .timed_ovn_evidence()
        .get(&ballot_attempt_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingTimedOvnEvidence)?;
    if lifecycle.ballot_attempt_id() != *ballot_attempt_id.as_bytes() {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }
    let phase = ParliamentTimedOvnCastingPhaseV1::try_from(lifecycle.phase())?;

    let session = *lifecycle.session();
    let governance_attempt_id = GovernanceAttemptId::new(session.governance_attempt_id);
    let attempt = world
        .parliament_attempts()
        .get(&governance_attempt_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingGovernanceAttempt)?;
    attempt.validate().map_err(|error| match error {
        ParliamentReducerErrorV1::InvalidBallotSchedule => {
            TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule
        }
        _ => TimedOvnCastingAuthorizationErrorV1::InvalidParliamentState,
    })?;
    if attempt.attempt().status != GovernanceAttemptStatusV1::Active {
        return Err(TimedOvnCastingAuthorizationErrorV1::GovernanceAttemptNotActive);
    }

    let ballot = attempt
        .ballot(&ballot_attempt_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingBallot)?;
    let body_instance_id = BodyInstanceId::new(session.body_instance_id);
    let body = attempt
        .body(&body_instance_id)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingBody)?;
    if body.instance().status != BodyInstanceStatusV1::Balloting {
        return Err(TimedOvnCastingAuthorizationErrorV1::BodyNotBalloting);
    }
    let required_body = attempt
        .required_bodies()
        .iter()
        .find(|required| required.body == body.instance().body)
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    if required_body.decision_mode != ParliamentDecisionModeV1::HiddenBindingBallot {
        return Err(TimedOvnCastingAuthorizationErrorV1::BodyNotHiddenBinding);
    }
    if attempt
        .sealed_body_for_role(body.instance().body)
        .is_none_or(|active| active.instance().id != body_instance_id)
        || attempt
            .active_ballot_for_body(&body_instance_id)
            .is_none_or(|active| active.attempt().id != ballot_attempt_id)
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::BallotNotActive);
    }

    let expected_ballot_status = match phase {
        ParliamentTimedOvnCastingPhaseV1::Registered => BallotAttemptStatusV1::Registration,
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
            BallotAttemptStatusV1::SurvivorFreeze
        }
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => BallotAttemptStatusV1::TimedCommitment,
    };
    if ballot.attempt().status != expected_ballot_status {
        return Err(TimedOvnCastingAuthorizationErrorV1::PhaseBindingMismatch);
    }

    let target_finalized_height = lifecycle.target_finalized_height();
    let registration_opened_at_finalized_height = lifecycle
        .registration_opened_at_finalized_height()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    validate_casting_phase_window_v1(
        phase,
        finalized_height,
        ballot.registered_at_height(),
        ballot.registration_close_height(),
        ballot.survivor_freeze_height(),
        ballot.commitment_close_height(),
        target_finalized_height,
    )?;
    // Reject stale reads before replaying the public DKG and registration proofs.
    let key_session_id = lifecycle.tle_key_session_id();
    let tle_key_session = world
        .tle_key_sessions()
        .get(&key_session_id)
        .cloned()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::MissingKeySession)?
        .validate()?;
    lifecycle.validate(&tle_key_session)?;
    let release_beacon_session_id = ballot
        .release_beacon_session_id()
        .ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?;
    let expected_tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        key_session_id,
        release_beacon_session_id,
        target_finalized_height,
    );
    if attempt.proposal_content_id().as_bytes() != &session.proposal_content_id
        || body.instance().governance_attempt_id != governance_attempt_id
        || ballot.attempt().body_instance_id != body_instance_id
        || ballot.tle_key_session_id() != Some(key_session_id)
        || ballot.tle_session_id() != Some(expected_tle_session_id)
        || ballot.release_height() != Some(target_finalized_height)
        || registration_opened_at_finalized_height != ballot.registered_at_height()
        || registration_opened_at_finalized_height > finalized_height
        || session.network_id != tle_key_session.public_state().network_id
    {
        return Err(TimedOvnCastingAuthorizationErrorV1::BindingMismatch);
    }

    let (survivor_participant_hashes, release_identity) = match lifecycle {
        TimedOvnLifecycleStateV1::Registered(_)
        | TimedOvnLifecycleStateV1::RegistrationClosed(_) => (None, None),
        TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) => (
            Some(frozen.survivor_participant_hashes().to_vec()),
            Some(*frozen.release_identity()),
        ),
        TimedOvnLifecycleStateV1::CorpusOpen(open) => (
            Some(open.frozen().survivor_participant_hashes().to_vec()),
            Some(*open.frozen().release_identity()),
        ),
        TimedOvnLifecycleStateV1::Sealed(_) | TimedOvnLifecycleStateV1::Released(_) => {
            return Err(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable);
        }
    };

    Ok(AuthorizedTimedOvnCastingContextV1 {
        finalized_height,
        phase,
        session,
        registration_opened_at_finalized_height,
        target_finalized_height,
        tle_key_session,
        registration_records: lifecycle.registration_records().to_vec(),
        survivor_participant_hashes,
        release_identity,
    })
}
