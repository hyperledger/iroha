//! Canonical instruction surface for attempt-based SORA Parliament governance.
//!
//! The two instructions in this module deliberately separate immutable proposal
//! admission from reducer transitions.  Core derives block-local heights and
//! verifies authority, world-state bindings, sortition proofs, timed-OVN proofs,
//! and threshold-beacon material before applying a transition.  Consequently,
//! callers cannot supply an execution height through this wire surface.

use std::{cmp::Ordering, vec::Vec};

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

pub use crate::governance::types::{
    PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1, PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1,
    PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1,
    parliament_timed_ovn_required_chunk_blocks_v1,
};

use crate::{
    governance::types::{
        AssignmentId, BallotAttemptId, BeaconPulseId, BeaconSessionId, BodyElectionAttemptId,
        BodyInstanceId, DeliberationPhaseV1, GovernanceAttemptId, GovernanceAttemptStatusV1,
        GovernanceAttemptV1, GovernanceExpectedHeadV1, GovernanceStageV1,
        MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1, MAX_PARLIAMENT_BALLOT_RETRIES_V1,
        MAX_PARLIAMENT_SORTITION_RETRIES_V1, ParliamentBody, ProposalKind, RiskTierV1,
        SortitionRequestId, SortitionRequestV1, TleKeySessionId, TleSessionId,
    },
    seal,
};

/// Number of distinct Parliament body roles and the maximum atomic sortition batch width.
pub const MAX_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_V1: usize = 10;

/// Create one retryable Parliament attempt for exact immutable proposal content.
///
/// The instruction carries no caller-selected attempt identifier, status, stage,
/// policy version, effect hash, compare-and-set head, or body pipeline.  Core
/// derives those consensus bindings from the proposal and committed world state.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::CreateParliamentGovernanceAttemptV1"
)]
pub struct CreateParliamentGovernanceAttemptV1 {
    /// Exact typed proposal whose fingerprint is shared by every retry.
    pub proposal: ProposalKind,
    /// Zero-based end-to-end retry sequence for this proposal content.
    pub attempt_sequence: u32,
}

impl CreateParliamentGovernanceAttemptV1 {
    /// Stable path-independent identifier used by the instruction registry.
    pub const WIRE_ID: &'static str = "iroha.governance.parliament.attempt.create.v1";

    /// Derive the immutable proposal-content identifier.
    #[must_use]
    pub fn proposal_content_id(&self) -> crate::governance::types::ProposalContentId {
        crate::governance::types::ProposalContentId::derive_v1(&self.proposal)
    }

    /// Derive the only valid attempt identifier for this proposal and retry.
    #[must_use]
    pub fn governance_attempt_id(&self) -> GovernanceAttemptId {
        GovernanceAttemptId::derive_v1(self.proposal_content_id(), self.attempt_sequence)
    }

    /// Build the canonical initial reducer snapshot using a policy-derived risk tier.
    ///
    /// Core remains responsible for deriving and freezing every other immutable
    /// reducer binding from committed state.
    #[must_use]
    pub fn canonical_attempt(&self, risk_tier: RiskTierV1) -> GovernanceAttemptV1 {
        GovernanceAttemptV1 {
            id: self.governance_attempt_id(),
            proposal_content_id: self.proposal_content_id(),
            sequence: self.attempt_sequence,
            risk_tier,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        }
    }
}

impl PartialOrd for CreateParliamentGovernanceAttemptV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.encode().cmp(&other.encode()))
    }
}

impl seal::Instruction for CreateParliamentGovernanceAttemptV1 {}

/// Payload for a monotonic risk escalation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::governance::parliament::ParliamentEscalateRiskV1")]
pub struct ParliamentEscalateRiskV1 {
    /// Strictly nondecreasing policy-derived risk tier.
    pub target: RiskTierV1,
}

/// One immutable request entry in an atomic future-pulse sortition batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentSortitionRequestRegistrationV1"
)]
pub struct ParliamentSortitionRequestRegistrationV1 {
    /// Zero-based retry sequence for this body election.
    pub sequence: u32,
    /// Complete canonical future-pulse request.
    pub request: SortitionRequestV1,
}

/// Payload registering one atomic future-pulse sortition batch.
///
/// Core derives the complete canonical candidate snapshot from authoritative
/// citizenship state once in the containing block; callers never retransmit
/// it. The initial batch contains every initially required body. A generation
/// awaiting its pulse is never retried or redrawn: it waits for the pulse of
/// exactly its frozen slot. Before any pulse is consumed, only a hidden-capacity
/// failure of the full initial generation retries, atomically. After any pulse
/// has been consumed, a no-roster retry
/// contains exactly every body whose active generation ended without a roster,
/// and a Confirmation Jury draw contains exactly one fresh request.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRegisterSortitionRequestV1"
)]
pub struct ParliamentRegisterSortitionRequestV1 {
    /// Canonically body-ordered requests sharing one candidate snapshot and pulse slot.
    pub requests: Vec<ParliamentSortitionRequestRegistrationV1>,
}

/// Payload consuming one finalized threshold-beacon pulse batch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentConsumeSortitionPulseBatchV1"
)]
pub struct ParliamentConsumeSortitionPulseBatchV1 {
    /// Strictly ordered complete request identifiers for the pulse slot.
    pub request_ids: Vec<SortitionRequestId>,
    /// Threshold-beacon key session producing the pulse.
    pub beacon_session_id: BeaconSessionId,
    /// Exact finalized height committed by every request in the batch.
    pub pulse_height: u64,
    /// Content identifier of the finalized pulse.
    pub pulse_id: BeaconPulseId,
}

/// Payload beginning invitation acceptance after a deterministic draw.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentBeginInvitationAcceptanceV1"
)]
pub struct ParliamentBeginInvitationAcceptanceV1 {
    /// Election attempt whose finalized-pulse draw completed.
    pub election_attempt_id: BodyElectionAttemptId,
}

/// Payload terminally recording an election whose invitation window closed
/// without a viable roster. It never applies to an election awaiting its pulse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFailBodyElectionNoRosterV1"
)]
pub struct ParliamentFailBodyElectionNoRosterV1 {
    /// Election attempt that failed.
    pub election_attempt_id: BodyElectionAttemptId,
}

/// A candidate's response to one canonical Parliament invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "decision", content = "details", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
#[repr(u8)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentInvitationDecisionV1"
)]
pub enum ParliamentInvitationDecisionV1 {
    /// Accept the offered Parliament assignment.
    #[codec(index = 0)]
    Accept,
    /// Decline the offered Parliament assignment.
    #[codec(index = 1)]
    Decline,
}

/// Payload recording one authority-bound invitation response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRecordInvitationResponseV1"
)]
pub struct ParliamentRecordInvitationResponseV1 {
    /// Election attempt whose ranked invitation is being answered.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Parliament body copied from and rechecked against the election request.
    pub body: ParliamentBody,
    /// Accept or decline decision by the transaction authority.
    ///
    /// The member identity and assignment identifier are deliberately absent:
    /// Core derives both from the authenticated transaction authority.
    pub decision: ParliamentInvitationDecisionV1,
}

/// Payload triggering deterministic sealing of a canonical Parliament roster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::governance::parliament::ParliamentSealBodyRosterV1")]
pub struct ParliamentSealBodyRosterV1 {
    /// Election whose ranked, authority-bound responses determine the roster.
    ///
    /// Core derives the exact assignments, roster root, and body-instance ID;
    /// none can be selected by the transition submitter.
    pub election_attempt_id: BodyElectionAttemptId,
}

/// Payload advancing one sealed body by exactly one deliberation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentAdvanceBodyPhaseV1"
)]
pub struct ParliamentAdvanceBodyPhaseV1 {
    /// Body instance being advanced.
    pub body_instance_id: BodyInstanceId,
    /// Exact next deliberation phase.
    pub target: DeliberationPhaseV1,
}

/// Payload excluding one absent assignment from the current attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRecordAttemptAbsenceV1"
)]
pub struct ParliamentRecordAttemptAbsenceV1 {
    /// Body instance whose transaction-authority member declares their own absence.
    pub body_instance_id: BodyInstanceId,
    /// Canonical assignment owned by the transaction authority and excluded from
    /// this attempt only.
    pub assignment_id: AssignmentId,
}

/// Payload endorsing one public nonbinding Parliament finding under the
/// transaction authority's exact seated assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentEndorsePublicFindingV1"
)]
pub struct ParliamentEndorsePublicFindingV1 {
    /// Body instance contributing the finding.
    pub body_instance_id: BodyInstanceId,
    /// Root of the complete evidence, deliberation, and dissent record.
    pub result_root: [u8; 32],
}

/// Payload triggering objective expiry of one public-finding endorsement window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFailPublicFindingNoResultV1"
)]
pub struct ParliamentFailPublicFindingNoResultV1 {
    /// Public body whose frozen endorsement deadline has elapsed.
    pub body_instance_id: BodyInstanceId,
}

/// Payload registering a fresh private timed-OVN ballot attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRegisterBallotAttemptV1"
)]
pub struct ParliamentRegisterBallotAttemptV1 {
    /// Binding body instance receiving the private ballot.
    pub body_instance_id: BodyInstanceId,
    /// Identifier derived from the body instance and retry sequence.
    pub ballot_attempt_id: BallotAttemptId,
    /// Zero-based ballot retry sequence within the body instance.
    pub sequence: u32,
    /// Dedicated threshold timelock-encryption session.
    pub tle_session_id: TleSessionId,
    /// Long-lived threshold-BLS key session dedicated to TLE release signatures.
    pub tle_key_session_id: TleKeySessionId,
    /// Threshold-beacon key session committed for release timing.
    pub release_beacon_session_id: BeaconSessionId,
    /// Strictly future finalized height committed for release.
    pub release_height: u64,
}

/// Payload registering one seated member's proof-validated timed-OVN keys.
///
/// The member identity is deliberately absent. Core derives it from the
/// authenticated transaction authority and requires the record's participant
/// hash to bind that account to this exact ballot attempt.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRegisterBallotParticipantV1"
)]
pub struct ParliamentRegisterBallotParticipantV1 {
    /// Ballot attempt accepting the authenticated member registration.
    pub ballot_attempt_id: BallotAttemptId,
    /// Exact canonical 3,624-byte timed-OVN registration record.
    pub registration_record: Vec<u8>,
}

/// Payload closing the member-authenticated timed-OVN registration window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentCloseBallotRegistrationV1"
)]
pub struct ParliamentCloseBallotRegistrationV1 {
    /// Ballot attempt whose registration closes.
    pub ballot_attempt_id: BallotAttemptId,
}

/// Payload recording one registered seated member's authenticated dropout.
///
/// Core derives the participant hash from the transaction authority; neither a
/// Parliament manager nor the caller can name or exclude another participant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentRecordBallotDropoutV1"
)]
pub struct ParliamentRecordBallotDropoutV1 {
    /// Ballot attempt from which the authenticated member withdraws.
    pub ballot_attempt_id: BallotAttemptId,
}

/// Payload freezing the exact nonempty survivor subset derived by Core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFreezeBallotSurvivorsV1"
)]
pub struct ParliamentFreezeBallotSurvivorsV1 {
    /// Ballot attempt whose survivor set becomes immutable.
    pub ballot_attempt_id: BallotAttemptId,
}

/// Payload appending the exact next timed-OVN ciphertext and one-hot-proof chunk.
///
/// This is a permissionless progress transition. Core derives the starting
/// survivor offset from committed state and accepts only proof-valid contiguous
/// records, so the relayer cannot select or rewrite the corpus.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFreezeTimedOvnCorpusV1"
)]
pub struct ParliamentFreezeTimedOvnCorpusV1 {
    /// Ballot attempt whose next contiguous corpus chunk is appended.
    pub ballot_attempt_id: BallotAttemptId,
    /// One nonempty chunk of exact canonical 2,858-byte timed-OVN ballot records.
    ///
    /// The chunk contains at most
    /// [`crate::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1`] records. Core derives
    /// its starting survivor offset from committed state, verifies every proof,
    /// and advances a replay-checkable rolling aggregate. The final chunk must
    /// complete exact survivor coverage and causes automatic corpus sealing
    /// within the configured commitment window.
    pub ballot_records: Vec<Vec<u8>>,
}

/// Payload consuming one finalized release pulse for a complete ballot batch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentBeginBallotOpeningBatchV1"
)]
pub struct ParliamentBeginBallotOpeningBatchV1 {
    /// Strictly ordered complete ballot attempts for the release slot.
    pub ballot_attempt_ids: Vec<BallotAttemptId>,
    /// Threshold-beacon key session committed by every ballot.
    pub release_beacon_session_id: BeaconSessionId,
    /// Exact committed release height.
    pub release_height: u64,
    /// Content identifier of the finalized release pulse.
    pub pulse_id: BeaconPulseId,
}

/// Payload triggering Core derivation of an objectively expired ballot phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFailBallotNoResultV1"
)]
pub struct ParliamentFailBallotNoResultV1 {
    /// Ballot attempt that failed.
    pub ballot_attempt_id: BallotAttemptId,
}

/// Canonical public final threshold release record for one future TLE identity.
///
/// This schema DTO mirrors Core's verified release record without making the
/// data model depend on non-schema cryptographic runtime types. Core must
/// reconstruct the exact future identity and verify every field and pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentTleFinalReleaseSignatureV1"
)]
pub struct ParliamentTleFinalReleaseSignatureV1 {
    /// Long-lived TLE key session producing the final signature.
    pub key_session_id: TleKeySessionId,
    /// SHA-256 of the exact Core-reconstructed future release identity.
    pub identity_digest: [u8; 32],
    /// Canonical standard BLS12-381 G1 threshold release signature.
    pub signature: [u8; 48],
}

/// Payload finalizing an aggregate-only timed-OVN opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentFinalizeOpenedBallotV1"
)]
pub struct ParliamentFinalizeOpenedBallotV1 {
    /// Ballot attempt whose complete survivor aggregate is opened.
    pub ballot_attempt_id: BallotAttemptId,
    /// Exact public threshold release record verified and replayed by Core.
    pub final_release: ParliamentTleFinalReleaseSignatureV1,
}

/// Consensus-derived audit payload recording compare-and-set supersession.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentAutomaticSupersededV1"
)]
pub struct ParliamentAutomaticSupersededV1 {
    /// Different committed head observed when execution became due.
    pub observed_head: GovernanceExpectedHeadV1,
}

/// Consensus-derived audit payload for an atomically rolled-back effect failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentAutomaticExecutionFailedV1"
)]
pub struct ParliamentAutomaticExecutionFailedV1 {
    /// Exact certified effect preimage hash.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub effect_preimage_hash: [u8; 32],
    /// Certificate-and-height-derived execution failure root.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub failure_root: [u8; 32],
}

/// Consensus-derived outcome of executing one due Parliament certificate.
///
/// This is an event-audit payload, not a submit-able lifecycle transition. Core
/// constructs it only at the certificate's exact due block after comparing the
/// retained expected head and atomically applying the certified effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "outcome", content = "details", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentAutomaticExecutionOutcomeV1"
)]
pub enum ParliamentAutomaticExecutionOutcomeV1 {
    /// The exact certified effect enacted successfully.
    #[codec(index = 0)]
    Enacted,
    /// A different compare-and-set head was authoritative at the due height.
    #[codec(index = 1)]
    Superseded(ParliamentAutomaticSupersededV1),
    /// The exact certified effect failed and all partial writes were discarded.
    #[codec(index = 2)]
    ExecutionFailed(ParliamentAutomaticExecutionFailedV1),
}

/// One closed, versioned transition accepted by the Parliament attempt reducer.
///
/// Heights representing when a transition executes are intentionally absent:
/// Core supplies the containing block height.  Future sortition and release
/// heights remain explicit because they are immutable precommitments.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "transition", content = "payload", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentLifecycleTransitionV1"
)]
pub enum ParliamentLifecycleTransitionV1 {
    /// Escalate the attempt's risk tier before Policy Jury sortition is frozen.
    #[codec(index = 0)]
    EscalateRisk(ParliamentEscalateRiskV1),
    /// Finish qualification and enter the first required Parliament body.
    #[codec(index = 1)]
    CompleteQualification,
    /// Register one atomic immutable request batch for a future beacon pulse.
    #[codec(index = 2)]
    RegisterSortitionRequest(ParliamentRegisterSortitionRequestV1),
    /// Consume a finalized threshold-beacon pulse for a complete request batch.
    #[codec(index = 3)]
    ConsumeSortitionPulseBatch(ParliamentConsumeSortitionPulseBatchV1),
    /// Derive the deterministic draw plan and begin invitation acceptance.
    #[codec(index = 4)]
    BeginInvitationAcceptance(ParliamentBeginInvitationAcceptanceV1),
    /// Terminally record an election whose invitation window closed without a viable roster
    /// (never an election awaiting its pulse).
    #[codec(index = 5)]
    FailBodyElectionNoRoster(ParliamentFailBodyElectionNoRosterV1),
    /// Seal a nonempty canonical roster into a body instance.
    #[codec(index = 6)]
    SealBodyRoster(ParliamentSealBodyRosterV1),
    /// Advance one sealed body by exactly one deliberation phase.
    #[codec(index = 7)]
    AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1),
    /// Record one member-authenticated self-absence without changing original quorum.
    #[codec(index = 8)]
    RecordAttemptAbsence(ParliamentRecordAttemptAbsenceV1),
    /// Record one seated member's endorsement of a public nonbinding finding.
    #[codec(index = 9)]
    EndorsePublicFinding(ParliamentEndorsePublicFindingV1),
    /// Register a fresh private timed-OVN ballot attempt.
    #[codec(index = 10)]
    RegisterBallotAttempt(ParliamentRegisterBallotAttemptV1),
    /// Close proof-validated OVN registration from its exact canonical corpus.
    #[codec(index = 11)]
    CloseBallotRegistration(ParliamentCloseBallotRegistrationV1),
    /// Freeze the nonempty survivor roster before accepting ballots.
    #[codec(index = 12)]
    FreezeBallotSurvivors(ParliamentFreezeBallotSurvivorsV1),
    /// Append the next bounded timed-OVN ciphertext and one-hot-proof corpus chunk.
    #[codec(index = 13)]
    FreezeTimedOvnCorpus(ParliamentFreezeTimedOvnCorpusV1),
    /// Consume one finalized release pulse for a complete ballot batch.
    #[codec(index = 14)]
    BeginBallotOpeningBatch(ParliamentBeginBallotOpeningBatchV1),
    /// Terminally record an objectively expired ballot phase.
    #[codec(index = 15)]
    FailBallotNoResult(ParliamentFailBallotNoResultV1),
    /// Finalize an aggregate-only timed-OVN opening and binding-body result.
    #[codec(index = 16)]
    FinalizeOpenedBallot(ParliamentFinalizeOpenedBallotV1),
    /// Record one authenticated candidate's invitation response.
    #[codec(index = 17)]
    RecordInvitationResponse(ParliamentRecordInvitationResponseV1),
    /// Register one exact seated member's authenticated timed-OVN keys.
    #[codec(index = 18)]
    RegisterBallotParticipant(ParliamentRegisterBallotParticipantV1),
    /// Record one registered seated member's authenticated dropout.
    #[codec(index = 19)]
    RecordBallotDropout(ParliamentRecordBallotDropoutV1),
    /// Terminally record expiry of a public-finding endorsement window.
    #[codec(index = 20)]
    FailPublicFindingNoResult(ParliamentFailPublicFindingNoResultV1),
    /// Register the first complete sortition generation using consensus-derived inputs.
    ///
    /// The enclosing attempt is the only caller-supplied binding. Core derives
    /// all initially required bodies, sequence-zero election identifiers, the
    /// canonical eligible citizen snapshot, configured seat counts, containing
    /// execution height, and the attempt's exact future logical-beacon slot.
    /// This intent cannot select members or request a retry generation.
    #[codec(index = 21)]
    RegisterInitialSortition,
}

/// Bounded audit classification for a Parliament lifecycle transition.
///
/// Public-transition kinds and consensus-only execution outcomes share this
/// event classification. Its indices are independent from
/// [`ParliamentLifecycleTransitionV1`] and never carry registration or ballot
/// corpora.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "kind", content = "details", deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
#[repr(u8)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::ParliamentLifecycleTransitionKindV1"
)]
pub enum ParliamentLifecycleTransitionKindV1 {
    /// Risk escalation.
    #[codec(index = 0)]
    EscalateRisk,
    /// Qualification completion.
    #[codec(index = 1)]
    CompleteQualification,
    /// Sortition-request registration.
    #[codec(index = 2)]
    RegisterSortitionRequest,
    /// Sortition-pulse batch consumption.
    #[codec(index = 3)]
    ConsumeSortitionPulseBatch,
    /// Invitation-acceptance start.
    #[codec(index = 4)]
    BeginInvitationAcceptance,
    /// Terminal election failure after invitations closed without a viable roster.
    #[codec(index = 5)]
    FailBodyElectionNoRoster,
    /// Canonical body-roster sealing.
    #[codec(index = 6)]
    SealBodyRoster,
    /// Body deliberation phase advancement.
    #[codec(index = 7)]
    AdvanceBodyPhase,
    /// Member-authenticated attempt-scoped self-absence recording.
    #[codec(index = 8)]
    RecordAttemptAbsence,
    /// Authority-bound public-finding endorsement.
    #[codec(index = 9)]
    EndorsePublicFinding,
    /// Ballot-attempt registration.
    #[codec(index = 10)]
    RegisterBallotAttempt,
    /// Timed-OVN registration closure.
    #[codec(index = 11)]
    CloseBallotRegistration,
    /// Survivor-roster freezing.
    #[codec(index = 12)]
    FreezeBallotSurvivors,
    /// Timed-OVN ballot corpus freezing.
    #[codec(index = 13)]
    FreezeTimedOvnCorpus,
    /// Release-pulse batch consumption.
    #[codec(index = 14)]
    BeginBallotOpeningBatch,
    /// Terminal ballot failure without a result.
    #[codec(index = 15)]
    FailBallotNoResult,
    /// Aggregate-only ballot finalization.
    #[codec(index = 16)]
    FinalizeOpenedBallot,
    /// Successful certified enactment.
    #[codec(index = 17)]
    MarkEnacted,
    /// Compare-and-set supersession.
    #[codec(index = 18)]
    MarkSuperseded,
    /// Deterministic certified-effect execution failure.
    #[codec(index = 19)]
    MarkExecutionFailed,
    /// Authority-bound invitation response.
    #[codec(index = 20)]
    RecordInvitationResponse,
    /// Authority-bound timed-OVN registration.
    #[codec(index = 21)]
    RegisterBallotParticipant,
    /// Authority-bound pre-ballot dropout.
    #[codec(index = 22)]
    RecordBallotDropout,
    /// Objective public-finding endorsement-window expiry.
    #[codec(index = 23)]
    FailPublicFindingNoResult,
    /// Initial sortition registration with all selection inputs derived by consensus.
    #[codec(index = 24)]
    RegisterInitialSortition,
}

/// Domain separating the digest of an exact Parliament lifecycle transition.
pub const PARLIAMENT_LIFECYCLE_TRANSITION_DIGEST_V1: &[u8] =
    b"iroha.governance.parliament.lifecycle_transition.digest.v1";

/// Domain separating the digest of a consensus-derived execution outcome.
pub const PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOME_DIGEST_V1: &[u8] =
    b"iroha.governance.parliament.automatic_execution_outcome.digest.v1";

impl ParliamentLifecycleTransitionV1 {
    /// Reject an inert or cross-attempt transition before stateful execution.
    ///
    /// # Errors
    ///
    /// Returns a stable message when the enclosing attempt is zero, an embedded
    /// sortition request names another attempt, or [`Self::validate_static`]
    /// rejects the payload.
    pub fn validate_static_for_attempt(
        &self,
        governance_attempt_id: GovernanceAttemptId,
    ) -> Result<(), &'static str> {
        require_nonzero_id(
            governance_attempt_id.as_bytes(),
            "governance attempt id must be non-zero",
        )?;
        if let Self::RegisterSortitionRequest(payload) = self
            && payload
                .requests
                .iter()
                .any(|entry| entry.request.governance_attempt_id != governance_attempt_id)
        {
            return Err(
                "sortition request governance attempt id does not match the enclosing attempt",
            );
        }
        self.validate_static()
    }

    /// Reject state-independent malformed or unbounded transition payloads.
    ///
    /// This validation is suitable for untrusted API requests and instruction
    /// preflight. Authority, current phase, finalized height, candidate corpus,
    /// and cryptographic proof checks remain consensus responsibilities because
    /// they require authoritative world state.
    ///
    /// # Errors
    ///
    /// Returns a stable message when an identifier, commitment, height, derived
    /// binding, batch, or fixed-width cryptographic record is structurally invalid.
    pub fn validate_static(&self) -> Result<(), &'static str> {
        match self {
            Self::EscalateRisk(_)
            | Self::CompleteQualification
            | Self::RegisterInitialSortition => {}
            Self::RegisterSortitionRequest(payload) => {
                if payload.requests.is_empty()
                    || payload.requests.len() > MAX_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_V1
                {
                    return Err("sortition request batch must be nonempty and bounded");
                }
                if payload
                    .requests
                    .windows(2)
                    .any(|pair| pair[0].request.body >= pair[1].request.body)
                {
                    return Err("sortition request batch must be strictly body-ordered");
                }
                let first = &payload.requests[0].request;
                for entry in &payload.requests {
                    if entry.sequence > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                        return Err("sortition retry sequence exceeds the protocol maximum");
                    }
                    // An empty canonical intent carries the immutable bindings Core needs
                    // to record typed hidden-electorate capacity evidence. Core still
                    // authenticates the live snapshot and decision mode before mutation.
                    if entry.request.validate_capacity_intent(None).is_err() {
                        return Err("sortition request is structurally invalid");
                    }
                    if entry.request.body_election_attempt_id
                        != BodyElectionAttemptId::derive_v1(
                            entry.request.governance_attempt_id,
                            entry.request.body,
                            entry.sequence,
                        )
                    {
                        return Err("sortition election attempt id is not canonical");
                    }
                    if entry.request.governance_attempt_id != first.governance_attempt_id
                        || entry.request.candidate_count != first.candidate_count
                        || entry.request.request_height != first.request_height
                        || entry.request.pulse_height != first.pulse_height
                        || entry.request.beacon_session_id != first.beacon_session_id
                    {
                        return Err("sortition request batch does not share immutable bindings");
                    }
                }
            }
            Self::ConsumeSortitionPulseBatch(payload) => {
                if !strictly_ordered_nonempty_bounded(
                    &payload.request_ids,
                    MAX_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_V1,
                ) {
                    return Err("sortition request batch must be nonempty, bounded, and ordered");
                }
                if payload
                    .request_ids
                    .iter()
                    .any(|id| bytes_are_zero(id.as_bytes()))
                    || bytes_are_zero(payload.beacon_session_id.as_bytes())
                    || payload.pulse_height == 0
                    || bytes_are_zero(payload.pulse_id.as_bytes())
                {
                    return Err("sortition pulse batch bindings must be non-zero");
                }
            }
            Self::BeginInvitationAcceptance(payload) => {
                require_nonzero_id(
                    payload.election_attempt_id.as_bytes(),
                    "body-election attempt id must be non-zero",
                )?;
            }
            Self::FailBodyElectionNoRoster(payload) => {
                require_nonzero_id(
                    payload.election_attempt_id.as_bytes(),
                    "body-election attempt id must be non-zero",
                )?;
            }
            Self::SealBodyRoster(payload) => {
                require_nonzero_id(
                    payload.election_attempt_id.as_bytes(),
                    "body-election attempt id must be non-zero",
                )?;
            }
            Self::AdvanceBodyPhase(payload) => {
                require_nonzero_id(
                    payload.body_instance_id.as_bytes(),
                    "body instance id must be non-zero",
                )?;
            }
            Self::RecordAttemptAbsence(payload) => {
                require_nonzero_id(
                    payload.body_instance_id.as_bytes(),
                    "body instance id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.assignment_id.as_bytes(),
                    "assignment id must be non-zero",
                )?;
            }
            Self::EndorsePublicFinding(payload) => {
                require_nonzero_id(
                    payload.body_instance_id.as_bytes(),
                    "body instance id must be non-zero",
                )?;
                require_nonzero_id(&payload.result_root, "public finding root must be non-zero")?;
            }
            Self::FailPublicFindingNoResult(payload) => {
                require_nonzero_id(
                    payload.body_instance_id.as_bytes(),
                    "body instance id must be non-zero",
                )?;
            }
            Self::RegisterBallotAttempt(payload) => {
                require_nonzero_id(
                    payload.body_instance_id.as_bytes(),
                    "body instance id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.tle_session_id.as_bytes(),
                    "TLE session id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.tle_key_session_id.as_bytes(),
                    "TLE key session id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.release_beacon_session_id.as_bytes(),
                    "release beacon session id must be non-zero",
                )?;
                if payload.release_height == 0 {
                    return Err("ballot release height must be non-zero");
                }
                if payload.sequence > MAX_PARLIAMENT_BALLOT_RETRIES_V1 {
                    return Err("ballot retry sequence exceeds the protocol maximum");
                }
                if payload.ballot_attempt_id
                    != BallotAttemptId::derive_v1(payload.body_instance_id, payload.sequence)
                {
                    return Err("ballot attempt id is not canonical");
                }
                if payload.tle_session_id
                    != TleSessionId::derive_v1(
                        payload.ballot_attempt_id,
                        payload.tle_key_session_id,
                        payload.release_beacon_session_id,
                        payload.release_height,
                    )
                {
                    return Err("TLE session id is not canonical");
                }
            }
            Self::RegisterBallotParticipant(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
                if payload.registration_record.len()
                    != PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1
                {
                    return Err("timed-OVN registration record has the wrong canonical width");
                }
            }
            Self::CloseBallotRegistration(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
            }
            Self::RecordBallotDropout(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
            }
            Self::FreezeBallotSurvivors(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
            }
            Self::FreezeTimedOvnCorpus(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
                if payload.ballot_records.is_empty()
                    || payload.ballot_records.len()
                        > PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1
                    || payload
                        .ballot_records
                        .iter()
                        .any(|record| record.len() != PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1)
                {
                    return Err("timed-OVN ballot chunk violates its count or record-width bound");
                }
            }
            Self::BeginBallotOpeningBatch(payload) => {
                let maximum = usize::try_from(MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1)
                    .expect("the V1 ballot corpus bound fits usize");
                if !strictly_ordered_nonempty_bounded(&payload.ballot_attempt_ids, maximum) {
                    return Err("ballot opening batch must be nonempty, bounded, and ordered");
                }
                if payload
                    .ballot_attempt_ids
                    .iter()
                    .any(|id| bytes_are_zero(id.as_bytes()))
                    || bytes_are_zero(payload.release_beacon_session_id.as_bytes())
                    || payload.release_height == 0
                    || bytes_are_zero(payload.pulse_id.as_bytes())
                {
                    return Err("ballot opening batch bindings must be non-zero");
                }
            }
            Self::FailBallotNoResult(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
            }
            Self::FinalizeOpenedBallot(payload) => {
                require_nonzero_id(
                    payload.ballot_attempt_id.as_bytes(),
                    "ballot attempt id must be non-zero",
                )?;
                require_nonzero_id(
                    payload.final_release.key_session_id.as_bytes(),
                    "TLE key session id must be non-zero",
                )?;
                require_nonzero_id(
                    &payload.final_release.identity_digest,
                    "release identity digest must be non-zero",
                )?;
                if bytes_are_zero(&payload.final_release.signature) {
                    return Err("release signature must be non-zero");
                }
            }
            Self::RecordInvitationResponse(payload) => {
                require_nonzero_id(
                    payload.election_attempt_id.as_bytes(),
                    "body-election attempt id must be non-zero",
                )?;
            }
        }
        Ok(())
    }

    /// Return the bounded audit classification for this transition.
    #[must_use]
    pub const fn kind(&self) -> ParliamentLifecycleTransitionKindV1 {
        match self {
            Self::EscalateRisk(_) => ParliamentLifecycleTransitionKindV1::EscalateRisk,
            Self::CompleteQualification => {
                ParliamentLifecycleTransitionKindV1::CompleteQualification
            }
            Self::RegisterInitialSortition => {
                ParliamentLifecycleTransitionKindV1::RegisterInitialSortition
            }
            Self::RegisterSortitionRequest(_) => {
                ParliamentLifecycleTransitionKindV1::RegisterSortitionRequest
            }
            Self::ConsumeSortitionPulseBatch(_) => {
                ParliamentLifecycleTransitionKindV1::ConsumeSortitionPulseBatch
            }
            Self::BeginInvitationAcceptance(_) => {
                ParliamentLifecycleTransitionKindV1::BeginInvitationAcceptance
            }
            Self::FailBodyElectionNoRoster(_) => {
                ParliamentLifecycleTransitionKindV1::FailBodyElectionNoRoster
            }
            Self::SealBodyRoster(_) => ParliamentLifecycleTransitionKindV1::SealBodyRoster,
            Self::AdvanceBodyPhase(_) => ParliamentLifecycleTransitionKindV1::AdvanceBodyPhase,
            Self::RecordAttemptAbsence(_) => {
                ParliamentLifecycleTransitionKindV1::RecordAttemptAbsence
            }
            Self::EndorsePublicFinding(_) => {
                ParliamentLifecycleTransitionKindV1::EndorsePublicFinding
            }
            Self::RegisterBallotAttempt(_) => {
                ParliamentLifecycleTransitionKindV1::RegisterBallotAttempt
            }
            Self::CloseBallotRegistration(_) => {
                ParliamentLifecycleTransitionKindV1::CloseBallotRegistration
            }
            Self::FreezeBallotSurvivors(_) => {
                ParliamentLifecycleTransitionKindV1::FreezeBallotSurvivors
            }
            Self::FreezeTimedOvnCorpus(_) => {
                ParliamentLifecycleTransitionKindV1::FreezeTimedOvnCorpus
            }
            Self::BeginBallotOpeningBatch(_) => {
                ParliamentLifecycleTransitionKindV1::BeginBallotOpeningBatch
            }
            Self::FailBallotNoResult(_) => ParliamentLifecycleTransitionKindV1::FailBallotNoResult,
            Self::FinalizeOpenedBallot(_) => {
                ParliamentLifecycleTransitionKindV1::FinalizeOpenedBallot
            }
            Self::RecordInvitationResponse(_) => {
                ParliamentLifecycleTransitionKindV1::RecordInvitationResponse
            }
            Self::RegisterBallotParticipant(_) => {
                ParliamentLifecycleTransitionKindV1::RegisterBallotParticipant
            }
            Self::RecordBallotDropout(_) => {
                ParliamentLifecycleTransitionKindV1::RecordBallotDropout
            }
            Self::FailPublicFindingNoResult(_) => {
                ParliamentLifecycleTransitionKindV1::FailPublicFindingNoResult
            }
        }
    }

    /// Derive a domain-separated digest of the exact transition and evidence.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        crate::governance_fingerprint::fingerprint(PARLIAMENT_LIFECYCLE_TRANSITION_DIGEST_V1, self)
    }
}

fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn require_nonzero_id(bytes: &[u8; 32], message: &'static str) -> Result<(), &'static str> {
    if bytes_are_zero(bytes) {
        Err(message)
    } else {
        Ok(())
    }
}

fn strictly_ordered_nonempty_bounded<T: Ord>(items: &[T], maximum: usize) -> bool {
    !items.is_empty() && items.len() <= maximum && items.windows(2).all(|pair| pair[0] < pair[1])
}

impl ParliamentAutomaticExecutionOutcomeV1 {
    /// Return the bounded lifecycle-event classification for this automatic outcome.
    #[must_use]
    pub const fn kind(self) -> ParliamentLifecycleTransitionKindV1 {
        match self {
            Self::Enacted => ParliamentLifecycleTransitionKindV1::MarkEnacted,
            Self::Superseded(_) => ParliamentLifecycleTransitionKindV1::MarkSuperseded,
            Self::ExecutionFailed(_) => ParliamentLifecycleTransitionKindV1::MarkExecutionFailed,
        }
    }

    /// Derive a domain-separated digest of the exact automatic execution outcome.
    #[must_use]
    pub fn digest_v1(self) -> [u8; 32] {
        crate::governance_fingerprint::fingerprint(
            PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOME_DIGEST_V1,
            &self,
        )
    }
}

/// Submit one transition for an existing Parliament governance attempt.
///
/// A member's own invitation response, absence declaration, public-finding
/// endorsement, timed-OVN registration, or dropout is bound to the signed
/// authority. Deterministic ballot checkpoints, exact-next proof-valid corpus
/// chunks, release, failure, and aggregate finalization variants are
/// permissionless liveness triggers. Core requires the exact
/// `CanManageParliament` permission for every remaining management transition.
/// None of these callers can select a consensus result: the containing finalized
/// block supplies order and height, and Core derives or revalidates every state,
/// corpus, pulse, proof, and result binding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::isi::governance::parliament::SubmitParliamentLifecycleTransitionV1"
)]
pub struct SubmitParliamentLifecycleTransitionV1 {
    /// Attempt whose reducer must consume the transition.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Exact closed transition payload.
    pub transition: ParliamentLifecycleTransitionV1,
}

impl SubmitParliamentLifecycleTransitionV1 {
    /// Stable path-independent identifier used by the instruction registry.
    pub const WIRE_ID: &'static str = "iroha.governance.parliament.transition.submit.v1";

    /// Reject state-independent malformed or cross-attempt transition payloads.
    ///
    /// # Errors
    ///
    /// Returns a stable message when the outer attempt is inert, an embedded
    /// sortition request names another attempt, or the transition payload is
    /// structurally invalid.
    pub fn validate_static(&self) -> Result<(), &'static str> {
        self.transition
            .validate_static_for_attempt(self.governance_attempt_id)
    }
}

impl seal::Instruction for SubmitParliamentLifecycleTransitionV1 {}

fn decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}

impl<'a> norito::core::DecodeFromSlice<'a> for CreateParliamentGovernanceAttemptV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = decode_flags();
        let mut offset = 0;
        let proposal = crate::isi::decode_aos_canonical_field::<ProposalKind>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let attempt_sequence = crate::isi::decode_aos_canonical_field::<u32>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                proposal,
                attempt_sequence,
            },
            offset,
        ))
    }
}

impl<'a> norito::core::DecodeFromSlice<'a> for SubmitParliamentLifecycleTransitionV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = decode_flags();
        let mut offset = 0;
        let governance_attempt_id = crate::isi::decode_aos_canonical_field::<GovernanceAttemptId>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let transition = crate::isi::decode_aos_canonical_field::<ParliamentLifecycleTransitionV1>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                governance_attempt_id,
                transition,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::AccountId,
        governance::types::{
            AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ParliamentBody,
            ParliamentSeatAssignmentV1, ProposalContentId, parliament_candidate_root_v1,
            parliament_roster_root_v1,
        },
        isi::test_support::{assert_registry_decodes, assert_slice_roundtrip},
        smart_contract::ContractAddress,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use norito::{codec::DecodeAll as _, core::DecodeFromSlice, json};

    fn proposal() -> ProposalKind {
        ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: account(0x10),
            contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse::<ContractAddress>()
                .expect("parse Parliament instruction fixture contract address"),
            code_hash: ContractCodeHash::new([0x11; 32]),
            abi_hash: ContractAbiHash::new([0x22; 32]),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        })
    }

    fn transition(
        transition: ParliamentLifecycleTransitionV1,
    ) -> SubmitParliamentLifecycleTransitionV1 {
        SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: GovernanceAttemptId::new([0x33; 32]),
            transition,
        }
    }

    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked Parliament instruction fixture account");
        AccountId::new(key_pair.public_key().clone())
    }

    #[test]
    fn attempt_creation_derives_only_canonical_identifiers_and_initial_state() {
        let instruction = CreateParliamentGovernanceAttemptV1 {
            proposal: proposal(),
            attempt_sequence: 3,
        };
        let proposal_content_id = ProposalContentId::derive_v1(&instruction.proposal);
        assert_eq!(instruction.proposal_content_id(), proposal_content_id);
        assert_eq!(
            instruction.governance_attempt_id(),
            GovernanceAttemptId::derive_v1(proposal_content_id, 3)
        );
        let attempt = instruction.canonical_attempt(RiskTierV1::Constitutional);
        assert!(attempt.has_canonical_id());
        assert_eq!(attempt.stage, GovernanceStageV1::Qualification);
        assert_eq!(attempt.status, GovernanceAttemptStatusV1::Active);
        assert_eq!(attempt.risk_tier, RiskTierV1::Constitutional);
        assert_slice_roundtrip(instruction);
    }

    #[test]
    fn lifecycle_transition_instruction_roundtrips_every_variant() {
        let beacon_session_id = BeaconSessionId::new([0x44; 32]);
        let pulse_id = BeaconPulseId::new([0x45; 32]);
        let tle_key_session_id = TleKeySessionId::new([0x47; 32]);
        let governance_attempt_id = GovernanceAttemptId::new([0x33; 32]);
        let candidate_snapshot = vec![account(1)];
        let election_attempt_id = BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            ParliamentBody::RulesCommittee,
            0,
        );
        let request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            ParliamentBody::RulesCommittee,
            parliament_candidate_root_v1(
                governance_attempt_id,
                ParliamentBody::RulesCommittee,
                &candidate_snapshot,
            ),
            1,
            1,
            10,
            20,
            beacon_session_id,
            None,
        )
        .expect("construct canonical Parliament instruction sortition fixture");
        let seated_member = account(2);
        let assignments = vec![ParliamentSeatAssignmentV1 {
            assignment_id: AssignmentId::derive_v1(election_attempt_id, &seated_member),
            member: seated_member,
        }];
        let assignment_id = assignments[0].assignment_id;
        let roster_root = parliament_roster_root_v1(election_attempt_id, &assignments);
        let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
        let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, 0);
        let tle_session_id =
            TleSessionId::derive_v1(ballot_attempt_id, tle_key_session_id, beacon_session_id, 40);
        let variants = vec![
            ParliamentLifecycleTransitionV1::EscalateRisk(ParliamentEscalateRiskV1 {
                target: RiskTierV1::Constitutional,
            }),
            ParliamentLifecycleTransitionV1::CompleteQualification,
            ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                ParliamentRegisterSortitionRequestV1 {
                    requests: vec![ParliamentSortitionRequestRegistrationV1 {
                        sequence: 0,
                        request,
                    }],
                },
            ),
            ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
                ParliamentConsumeSortitionPulseBatchV1 {
                    request_ids: vec![request.id],
                    beacon_session_id,
                    pulse_height: 20,
                    pulse_id,
                },
            ),
            ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id,
                },
            ),
            ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(
                ParliamentFailBodyElectionNoRosterV1 {
                    election_attempt_id,
                },
            ),
            ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                election_attempt_id,
            }),
            ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                body_instance_id,
                target: DeliberationPhaseV1::Evidence,
            }),
            ParliamentLifecycleTransitionV1::RecordAttemptAbsence(
                ParliamentRecordAttemptAbsenceV1 {
                    body_instance_id,
                    assignment_id,
                },
            ),
            ParliamentLifecycleTransitionV1::EndorsePublicFinding(
                ParliamentEndorsePublicFindingV1 {
                    body_instance_id,
                    result_root: [0x53; 32],
                },
            ),
            ParliamentLifecycleTransitionV1::RegisterBallotAttempt(
                ParliamentRegisterBallotAttemptV1 {
                    body_instance_id,
                    ballot_attempt_id,
                    sequence: 0,
                    tle_session_id,
                    tle_key_session_id,
                    release_beacon_session_id: beacon_session_id,
                    release_height: 40,
                },
            ),
            ParliamentLifecycleTransitionV1::CloseBallotRegistration(
                ParliamentCloseBallotRegistrationV1 { ballot_attempt_id },
            ),
            ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(
                ParliamentFreezeBallotSurvivorsV1 { ballot_attempt_id },
            ),
            ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                ParliamentFreezeTimedOvnCorpusV1 {
                    ballot_attempt_id,
                    ballot_records: vec![vec![0x58; 2_858]],
                },
            ),
            ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
                ParliamentBeginBallotOpeningBatchV1 {
                    ballot_attempt_ids: vec![ballot_attempt_id],
                    release_beacon_session_id: beacon_session_id,
                    release_height: 40,
                    pulse_id,
                },
            ),
            ParliamentLifecycleTransitionV1::FailBallotNoResult(ParliamentFailBallotNoResultV1 {
                ballot_attempt_id,
            }),
            ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                ParliamentFinalizeOpenedBallotV1 {
                    ballot_attempt_id,
                    final_release: ParliamentTleFinalReleaseSignatureV1 {
                        key_session_id: tle_key_session_id,
                        identity_digest: [0x5B; 32],
                        signature: [0x5C; 48],
                    },
                },
            ),
            ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                ParliamentRecordInvitationResponseV1 {
                    election_attempt_id,
                    body: ParliamentBody::RulesCommittee,
                    decision: ParliamentInvitationDecisionV1::Accept,
                },
            ),
            ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                ParliamentRegisterBallotParticipantV1 {
                    ballot_attempt_id,
                    registration_record: vec![0x60; 3_624],
                },
            ),
            ParliamentLifecycleTransitionV1::RecordBallotDropout(ParliamentRecordBallotDropoutV1 {
                ballot_attempt_id,
            }),
            ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
                ParliamentFailPublicFindingNoResultV1 { body_instance_id },
            ),
            ParliamentLifecycleTransitionV1::RegisterInitialSortition,
        ];
        for (expected_index, variant) in variants.into_iter().enumerate() {
            let kind = variant.kind();
            variant
                .validate_static()
                .unwrap_or_else(|error| panic!("valid {kind:?} transition rejected: {error}"));
            assert_eq!(
                variant.encode()[0],
                u8::try_from(expected_index).expect("V1 transition index fits u8")
            );
            assert_ne!(kind.encode(), Vec::<u8>::new());
            assert_ne!(variant.digest_v1(), [0; 32]);
            let instruction = transition(variant);
            instruction
                .validate_static()
                .unwrap_or_else(|error| panic!("valid {kind:?} instruction rejected: {error}"));
            assert_slice_roundtrip(instruction.clone());
            let encoded_json = json::to_vec(&instruction)
                .expect("encode Parliament lifecycle instruction JSON fixture");
            let decoded_json: SubmitParliamentLifecycleTransitionV1 =
                json::from_slice(&encoded_json)
                    .expect("decode Parliament lifecycle instruction JSON fixture");
            assert_eq!(decoded_json, instruction);
        }
    }

    #[test]
    fn initial_sortition_intent_has_only_the_enclosing_attempt_binding() {
        let intent = ParliamentLifecycleTransitionV1::RegisterInitialSortition;
        let instruction = transition(intent.clone());
        instruction
            .validate_static()
            .expect("nonzero outer attempt is sufficient for static initial intent");
        assert_eq!(intent.encode(), 21_u32.to_le_bytes());
        assert_eq!(
            intent.kind(),
            ParliamentLifecycleTransitionKindV1::RegisterInitialSortition
        );
        assert_eq!(intent.kind().encode(), 24_u32.to_le_bytes());
        assert_slice_roundtrip(instruction.clone());
        let value = json::to_value(&instruction).expect("initial intent JSON");
        let object = value.as_object().expect("instruction object");
        assert_eq!(object.len(), 2);
        let tagged = object
            .get("transition")
            .and_then(json::Value::as_object)
            .expect("tagged initial transition");
        assert_eq!(
            tagged.len(),
            2,
            "initial intent must have only its tag and null content field"
        );
        assert_eq!(
            tagged.get("payload"),
            Some(&json::Value::Null),
            "initial intent must have no caller-selected payload"
        );
        assert_eq!(
            tagged.get("transition").and_then(json::Value::as_str),
            Some("RegisterInitialSortition")
        );
        assert_ne!(
            intent.digest_v1(),
            ParliamentLifecycleTransitionV1::CompleteQualification.digest_v1()
        );
        let mut zero = instruction;
        zero.governance_attempt_id = GovernanceAttemptId::new([0; 32]);
        assert!(zero.validate_static().is_err());
    }

    #[test]
    fn initial_sortition_json_rejects_caller_selection_and_schedule_fields() {
        let instruction = transition(ParliamentLifecycleTransitionV1::RegisterInitialSortition);
        let original = json::to_value(&instruction).expect("initial intent JSON");
        for field in [
            "candidates",
            "candidate_root",
            "candidate_count",
            "target_seats",
            "request_height",
            "pulse_height",
            "beacon_session_id",
            "body",
            "body_election_attempt_id",
            "sequence",
        ] {
            let mut changed = original.clone();
            changed
                .as_object_mut()
                .and_then(|object| object.get_mut("transition"))
                .and_then(json::Value::as_object_mut)
                .expect("tagged initial transition")
                .insert(
                    field.to_owned(),
                    json::Value::String("caller selected".to_owned()),
                );
            assert!(
                json::from_value::<SubmitParliamentLifecycleTransitionV1>(changed).is_err(),
                "initial intent must reject caller field {field}"
            );
        }
        let mut payload = original;
        payload
            .as_object_mut()
            .and_then(|object| object.get_mut("transition"))
            .and_then(json::Value::as_object_mut)
            .expect("tagged initial transition")
            .insert("payload".to_owned(), norito::json!({"candidate_count": 1}));
        assert!(
            json::from_value::<SubmitParliamentLifecycleTransitionV1>(payload).is_err(),
            "a payloadless initial intent must reject a caller selection payload"
        );
    }

    #[test]
    fn zero_candidate_sortition_intent_reaches_consensus_capacity_validation() {
        let governance_attempt_id = GovernanceAttemptId::new([0x71; 32]);
        let body = ParliamentBody::PolicyJury;
        let body_election_attempt_id =
            BodyElectionAttemptId::derive_v1(governance_attempt_id, body, 0);
        let candidates = Vec::new();
        let mut request = SortitionRequestV1 {
            id: SortitionRequestId::new([0; 32]),
            governance_attempt_id,
            body_election_attempt_id,
            body,
            candidate_root: parliament_candidate_root_v1(governance_attempt_id, body, &candidates),
            candidate_count: 0,
            target_seats: 3,
            request_height: 10,
            pulse_height: 15,
            beacon_session_id: BeaconSessionId::new([0x72; 32]),
        };
        request.id = request.canonical_id();
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                ParliamentRegisterSortitionRequestV1 {
                    requests: vec![ParliamentSortitionRequestRegistrationV1 {
                        sequence: 0,
                        request,
                    }],
                },
            )
            .validate_static(),
            Ok(()),
            "an empty canonical snapshot is a capacity intent that Core must classify against consensus state"
        );
    }

    #[test]
    fn lifecycle_transition_static_validation_rejects_impossible_payloads() {
        let body_instance_id = BodyInstanceId::new([0x32; 32]);
        let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, 0);
        let tle_key_session_id = TleKeySessionId::new([0x34; 32]);
        let beacon_session_id = BeaconSessionId::new([0x35; 32]);
        let release_height = 40;
        let tle_session_id = TleSessionId::derive_v1(
            ballot_attempt_id,
            tle_key_session_id,
            beacon_session_id,
            release_height,
        );
        let pulse_id = BeaconPulseId::new([0x36; 32]);

        assert_eq!(
            SubmitParliamentLifecycleTransitionV1 {
                governance_attempt_id: GovernanceAttemptId::new([0; 32]),
                transition: ParliamentLifecycleTransitionV1::CompleteQualification,
            }
            .validate_static(),
            Err("governance attempt id must be non-zero")
        );

        let invalid = vec![
            (
                "empty sortition registration batch",
                ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                    ParliamentRegisterSortitionRequestV1 {
                        requests: Vec::new(),
                    },
                ),
            ),
            (
                "zero sortition pulse height",
                ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
                    ParliamentConsumeSortitionPulseBatchV1 {
                        request_ids: vec![SortitionRequestId::new([0x37; 32])],
                        beacon_session_id,
                        pulse_height: 0,
                        pulse_id,
                    },
                ),
            ),
            (
                "zero invitation election",
                ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                    ParliamentBeginInvitationAcceptanceV1 {
                        election_attempt_id: BodyElectionAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero failed election",
                ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(
                    ParliamentFailBodyElectionNoRosterV1 {
                        election_attempt_id: BodyElectionAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero sealed election",
                ParliamentLifecycleTransitionV1::SealBodyRoster(ParliamentSealBodyRosterV1 {
                    election_attempt_id: BodyElectionAttemptId::new([0; 32]),
                }),
            ),
            (
                "zero phase body",
                ParliamentLifecycleTransitionV1::AdvanceBodyPhase(ParliamentAdvanceBodyPhaseV1 {
                    body_instance_id: BodyInstanceId::new([0; 32]),
                    target: DeliberationPhaseV1::Evidence,
                }),
            ),
            (
                "zero absence assignment",
                ParliamentLifecycleTransitionV1::RecordAttemptAbsence(
                    ParliamentRecordAttemptAbsenceV1 {
                        body_instance_id,
                        assignment_id: AssignmentId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero public finding root",
                ParliamentLifecycleTransitionV1::EndorsePublicFinding(
                    ParliamentEndorsePublicFindingV1 {
                        body_instance_id,
                        result_root: [0; 32],
                    },
                ),
            ),
            (
                "zero ballot release height",
                ParliamentLifecycleTransitionV1::RegisterBallotAttempt(
                    ParliamentRegisterBallotAttemptV1 {
                        body_instance_id,
                        ballot_attempt_id,
                        sequence: 0,
                        tle_session_id,
                        tle_key_session_id,
                        release_beacon_session_id: beacon_session_id,
                        release_height: 0,
                    },
                ),
            ),
            (
                "wrong registration record width",
                ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                    ParliamentRegisterBallotParticipantV1 {
                        ballot_attempt_id,
                        registration_record: vec![0; 1],
                    },
                ),
            ),
            (
                "zero close ballot",
                ParliamentLifecycleTransitionV1::CloseBallotRegistration(
                    ParliamentCloseBallotRegistrationV1 {
                        ballot_attempt_id: BallotAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero dropout ballot",
                ParliamentLifecycleTransitionV1::RecordBallotDropout(
                    ParliamentRecordBallotDropoutV1 {
                        ballot_attempt_id: BallotAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero survivor ballot",
                ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(
                    ParliamentFreezeBallotSurvivorsV1 {
                        ballot_attempt_id: BallotAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "empty timed-OVN corpus chunk",
                ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                    ParliamentFreezeTimedOvnCorpusV1 {
                        ballot_attempt_id,
                        ballot_records: Vec::new(),
                    },
                ),
            ),
            (
                "zero ballot opening height",
                ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
                    ParliamentBeginBallotOpeningBatchV1 {
                        ballot_attempt_ids: vec![ballot_attempt_id],
                        release_beacon_session_id: beacon_session_id,
                        release_height: 0,
                        pulse_id,
                    },
                ),
            ),
            (
                "zero failed ballot",
                ParliamentLifecycleTransitionV1::FailBallotNoResult(
                    ParliamentFailBallotNoResultV1 {
                        ballot_attempt_id: BallotAttemptId::new([0; 32]),
                    },
                ),
            ),
            (
                "zero final release digest",
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: ParliamentTleFinalReleaseSignatureV1 {
                            key_session_id: tle_key_session_id,
                            identity_digest: [0; 32],
                            signature: [0x38; 48],
                        },
                    },
                ),
            ),
            (
                "zero final release signature",
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: ParliamentTleFinalReleaseSignatureV1 {
                            key_session_id: tle_key_session_id,
                            identity_digest: [0x38; 32],
                            signature: [0; 48],
                        },
                    },
                ),
            ),
            (
                "zero invitation response election",
                ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                    ParliamentRecordInvitationResponseV1 {
                        election_attempt_id: BodyElectionAttemptId::new([0; 32]),
                        body: ParliamentBody::RulesCommittee,
                        decision: ParliamentInvitationDecisionV1::Accept,
                    },
                ),
            ),
            (
                "zero public-finding failure body",
                ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
                    ParliamentFailPublicFindingNoResultV1 {
                        body_instance_id: BodyInstanceId::new([0; 32]),
                    },
                ),
            ),
        ];
        for (name, transition) in invalid {
            assert!(
                transition.validate_static().is_err(),
                "invalid transition was accepted: {name}"
            );
        }

        let over_limit_sequence = MAX_PARLIAMENT_BALLOT_RETRIES_V1 + 1;
        let over_limit_ballot = BallotAttemptId::derive_v1(body_instance_id, over_limit_sequence);
        let over_limit_tle = TleSessionId::derive_v1(
            over_limit_ballot,
            tle_key_session_id,
            beacon_session_id,
            release_height,
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterBallotAttempt(
                ParliamentRegisterBallotAttemptV1 {
                    body_instance_id,
                    ballot_attempt_id: over_limit_ballot,
                    sequence: over_limit_sequence,
                    tle_session_id: over_limit_tle,
                    tle_key_session_id,
                    release_beacon_session_id: beacon_session_id,
                    release_height,
                },
            )
            .validate_static(),
            Err("ballot retry sequence exceeds the protocol maximum")
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterBallotAttempt(
                ParliamentRegisterBallotAttemptV1 {
                    body_instance_id,
                    ballot_attempt_id: BallotAttemptId::new([0x39; 32]),
                    sequence: 0,
                    tle_session_id,
                    tle_key_session_id,
                    release_beacon_session_id: beacon_session_id,
                    release_height,
                },
            )
            .validate_static(),
            Err("ballot attempt id is not canonical")
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterBallotAttempt(
                ParliamentRegisterBallotAttemptV1 {
                    body_instance_id,
                    ballot_attempt_id,
                    sequence: 0,
                    tle_session_id: TleSessionId::new([0x3A; 32]),
                    tle_key_session_id,
                    release_beacon_session_id: beacon_session_id,
                    release_height,
                },
            )
            .validate_static(),
            Err("TLE session id is not canonical")
        );

        let governance_attempt_id = GovernanceAttemptId::new([0x3B; 32]);
        let sortition_sequence = MAX_PARLIAMENT_SORTITION_RETRIES_V1 + 1;
        let sortition_election_id = BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            ParliamentBody::RulesCommittee,
            sortition_sequence,
        );
        let sortition_request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            sortition_election_id,
            ParliamentBody::RulesCommittee,
            [0x3C; 32],
            1,
            1,
            10,
            20,
            beacon_session_id,
            None,
        )
        .expect("construct structurally valid over-limit sortition request");
        let sortition_registration = ParliamentSortitionRequestRegistrationV1 {
            sequence: sortition_sequence,
            request: sortition_request,
        };
        assert_eq!(
            SubmitParliamentLifecycleTransitionV1 {
                governance_attempt_id: GovernanceAttemptId::new([0x3E; 32]),
                transition: ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                    ParliamentRegisterSortitionRequestV1 {
                        requests: vec![sortition_registration],
                    },
                ),
            }
            .validate_static(),
            Err("sortition request governance attempt id does not match the enclosing attempt")
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                ParliamentRegisterSortitionRequestV1 {
                    requests: vec![sortition_registration],
                },
            )
            .validate_static(),
            Err("sortition retry sequence exceeds the protocol maximum")
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::RegisterSortitionRequest(
                ParliamentRegisterSortitionRequestV1 {
                    requests: vec![
                        sortition_registration;
                        MAX_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_V1 + 1
                    ],
                },
            )
            .validate_static(),
            Err("sortition request batch must be nonempty and bounded")
        );

        let duplicate_ballots = ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(
            ParliamentBeginBallotOpeningBatchV1 {
                ballot_attempt_ids: vec![ballot_attempt_id, ballot_attempt_id],
                release_beacon_session_id: beacon_session_id,
                release_height,
                pulse_id,
            },
        );
        assert_eq!(
            duplicate_ballots.validate_static(),
            Err("ballot opening batch must be nonempty, bounded, and ordered")
        );
        assert_eq!(
            ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
                ParliamentConsumeSortitionPulseBatchV1 {
                    request_ids: vec![
                        SortitionRequestId::new([0x3D; 32]),
                        SortitionRequestId::new([0x3D; 32]),
                    ],
                    beacon_session_id,
                    pulse_height: 20,
                    pulse_id,
                },
            )
            .validate_static(),
            Err("sortition request batch must be nonempty, bounded, and ordered")
        );
    }

    #[test]
    fn automatic_execution_outcomes_are_audit_only_and_domain_separated() {
        let outcomes = [
            ParliamentAutomaticExecutionOutcomeV1::Enacted,
            ParliamentAutomaticExecutionOutcomeV1::Superseded(ParliamentAutomaticSupersededV1 {
                observed_head: GovernanceExpectedHeadV1::Absent(
                    crate::governance::types::GovernanceExpectedHeadAbsentV1 {
                        subject_id: [0x5D; 32],
                    },
                ),
            }),
            ParliamentAutomaticExecutionOutcomeV1::ExecutionFailed(
                ParliamentAutomaticExecutionFailedV1 {
                    effect_preimage_hash: [0x5E; 32],
                    failure_root: [0x5F; 32],
                },
            ),
        ];
        let expected_kinds = [
            ParliamentLifecycleTransitionKindV1::MarkEnacted,
            ParliamentLifecycleTransitionKindV1::MarkSuperseded,
            ParliamentLifecycleTransitionKindV1::MarkExecutionFailed,
        ];
        for ((expected_index, outcome), expected_kind) in
            outcomes.into_iter().enumerate().zip(expected_kinds)
        {
            assert_eq!(
                outcome.encode()[0],
                u8::try_from(expected_index).expect("V1 outcome index fits u8")
            );
            assert_eq!(outcome.kind(), expected_kind);
            assert_eq!(
                outcome.digest_v1(),
                crate::governance_fingerprint::fingerprint(
                    PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOME_DIGEST_V1,
                    &outcome,
                )
            );
            assert_ne!(
                outcome.digest_v1(),
                crate::governance_fingerprint::fingerprint(
                    PARLIAMENT_LIFECYCLE_TRANSITION_DIGEST_V1,
                    &outcome,
                )
            );
            let encoded = outcome.encode();
            let decoded =
                ParliamentAutomaticExecutionOutcomeV1::decode_all(&mut encoded.as_slice())
                    .expect("decode automatic execution outcome");
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn lifecycle_json_rejects_unknown_fields_aliases_and_transition_tags() {
        let instruction = transition(ParliamentLifecycleTransitionV1::CompleteQualification);
        let value = json::to_value(&instruction).expect("render lifecycle JSON fixture");

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .expect("lifecycle request object")
            .insert(
                "private_key".to_owned(),
                json::Value::String("secret".to_owned()),
            );
        assert!(
            json::from_value::<SubmitParliamentLifecycleTransitionV1>(unknown).is_err(),
            "unknown signing-material field must fail"
        );

        let mut alias = value.clone();
        let alias_object = alias.as_object_mut().expect("lifecycle request object");
        let attempt_id = alias_object
            .remove("governance_attempt_id")
            .expect("canonical governance_attempt_id field");
        alias_object.insert("governanceAttemptId".to_owned(), attempt_id);
        assert!(
            json::from_value::<SubmitParliamentLifecycleTransitionV1>(alias).is_err(),
            "camel-case alias must fail"
        );

        let mut unknown_tag = value;
        let transition = unknown_tag
            .as_object_mut()
            .and_then(|object| object.get_mut("transition"))
            .and_then(json::Value::as_object_mut)
            .expect("tagged transition object");
        transition.insert(
            "transition".to_owned(),
            json::Value::String("PlainBallotFallback".to_owned()),
        );
        assert!(
            json::from_value::<SubmitParliamentLifecycleTransitionV1>(unknown_tag).is_err(),
            "unknown or plaintext transition tag must fail"
        );
    }

    #[test]
    fn default_registry_decodes_parliament_instruction_wire_ids() {
        let registry = crate::isi::registry::default();
        assert_registry_decodes(
            &registry,
            CreateParliamentGovernanceAttemptV1::WIRE_ID,
            CreateParliamentGovernanceAttemptV1 {
                proposal: proposal(),
                attempt_sequence: 0,
            },
        );
        assert_registry_decodes(
            &registry,
            SubmitParliamentLifecycleTransitionV1::WIRE_ID,
            transition(ParliamentLifecycleTransitionV1::CompleteQualification),
        );
    }

    #[test]
    fn lifecycle_digest_is_domain_separated_and_commits_to_all_private_evidence() {
        let ballot_attempt_id = BallotAttemptId::new([0x61; 32]);
        let domain_probe = ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
            ParliamentRegisterBallotParticipantV1 {
                ballot_attempt_id,
                registration_record: vec![0x62; 3_624],
            },
        );
        assert_eq!(
            domain_probe.digest_v1(),
            crate::governance_fingerprint::fingerprint(
                PARLIAMENT_LIFECYCLE_TRANSITION_DIGEST_V1,
                &domain_probe,
            )
        );
        assert_ne!(
            domain_probe.digest_v1(),
            crate::governance_fingerprint::fingerprint(
                b"iroha.governance.parliament.lifecycle_transition.other.v1",
                &domain_probe,
            )
        );

        let final_release =
            |key_byte, digest_byte, signature_byte| ParliamentTleFinalReleaseSignatureV1 {
                key_session_id: TleKeySessionId::new([key_byte; 32]),
                identity_digest: [digest_byte; 32],
                signature: [signature_byte; 48],
            };
        let pairs = vec![
            (
                ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
                    ParliamentFailPublicFindingNoResultV1 {
                        body_instance_id: BodyInstanceId::new([0x60; 32]),
                    },
                ),
                ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(
                    ParliamentFailPublicFindingNoResultV1 {
                        body_instance_id: BodyInstanceId::new([0x61; 32]),
                    },
                ),
            ),
            (
                ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                    ParliamentRegisterBallotParticipantV1 {
                        ballot_attempt_id,
                        registration_record: vec![0x62; 3_624],
                    },
                ),
                ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                    ParliamentRegisterBallotParticipantV1 {
                        ballot_attempt_id,
                        registration_record: vec![0x63; 3_624],
                    },
                ),
            ),
            (
                ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                    ParliamentFreezeTimedOvnCorpusV1 {
                        ballot_attempt_id,
                        ballot_records: vec![vec![0x66; 2_858]],
                    },
                ),
                ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                    ParliamentFreezeTimedOvnCorpusV1 {
                        ballot_attempt_id,
                        ballot_records: vec![vec![0x67; 2_858]],
                    },
                ),
            ),
            (
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x68, 0x69, 0x6A),
                    },
                ),
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x68, 0x69, 0x6B),
                    },
                ),
            ),
            (
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x68, 0x69, 0x6A),
                    },
                ),
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x68, 0x6C, 0x6A),
                    },
                ),
            ),
            (
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x68, 0x69, 0x6A),
                    },
                ),
                ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(
                    ParliamentFinalizeOpenedBallotV1 {
                        ballot_attempt_id,
                        final_release: final_release(0x6D, 0x69, 0x6A),
                    },
                ),
            ),
        ];
        for (first, second) in pairs {
            assert_eq!(first.kind(), second.kind());
            assert_ne!(first.digest_v1(), second.digest_v1());
        }
    }

    #[test]
    fn slice_decoder_rejects_trailing_bytes() {
        let instruction = transition(ParliamentLifecycleTransitionV1::CompleteQualification);
        let mut encoded = instruction.encode();
        encoded.push(0);
        assert!(
            SubmitParliamentLifecycleTransitionV1::decode_from_slice(&encoded).is_err(),
            "instruction decoder must fully consume the canonical payload"
        );
    }
}

#[cfg(test)]
mod captured_parliament_schema_tests;
