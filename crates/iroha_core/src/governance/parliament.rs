//! Deterministic, fail-closed reducer for one SORA Parliament governance attempt.
//!
//! The reducer owns the consensus-relevant lifecycle links between an immutable
//! proposal, future-beacon sortition, sealed body instances, private OVN ballot
//! attempts, certification, and enactment.  Cryptographic verification happens
//! before a transition is submitted; this module makes the verified bindings
//! immutable and rejects replay, stage skipping, and cross-attempt substitution.
//!
//! There is deliberately no plaintext ballot or manual-opening transition.  A
//! missed phase deadline or objectively absent finalized release pulse produces
//! `NoResult`; retry requires a fresh ballot attempt and a fresh TLE session.
//! Every fresh roster/pulse generation and every replacement timed-OVN session
//! spends one proposal-wide redraw unit. Exact transport retransmission retains
//! its committed randomness and therefore cannot spend another unit.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use iroha_config::parameters::actual::{Governance, ParliamentTimedOvn};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    governance::types::{
        AssignmentId, BallotAttemptId, BallotAttemptStatusV1, BeaconPulseId, BeaconSessionId,
        BodyElectionAttemptId, BodyElectionAttemptStatusV1, BodyInstanceId, BodyInstanceStatusV1,
        DeliberationPhaseV1, GovernanceAttemptId, GovernanceAttemptStatusV1, GovernanceAttemptV1,
        GovernanceCertificateV1, GovernanceExpectedHeadV1, GovernanceStageV1,
        MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1, MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1,
        MAX_PARLIAMENT_BALLOT_RETRIES_V1, MAX_PARLIAMENT_BODY_TARGET_SEATS_V1,
        MAX_PARLIAMENT_CANDIDATE_SNAPSHOT_BYTES_V1, MAX_PARLIAMENT_CITIZENS_V1,
        MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1, MAX_PARLIAMENT_SORTITION_RETRIES_V1,
        MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1, ParliamentAggregateOutcomeV1,
        ParliamentAggregateTallyV1, ParliamentBallotAttemptV1,
        ParliamentBallotCertificateBindingV1, ParliamentBallotFailureKindV1, ParliamentBody,
        ParliamentBodyCertificateBindingV1, ParliamentBodyInstanceV1, ParliamentNoResultKindV1,
        ParliamentPublicFindingCertificateBindingV1, ParliamentSeatAssignmentV1, ProposalContentId,
        ProposalKind, RiskTierV1, SortitionRequestId, SortitionRequestV1, TleKeySessionId,
        TleSessionId, parliament_assignment_plan_root_v1, parliament_ballot_failure_root_v1,
        parliament_ballot_result_root_v1, parliament_candidate_root_v1,
        parliament_execution_failure_root_v1, parliament_public_finding_endorsement_root_v1,
        parliament_quorum_seats_v1, parliament_roster_root_v1,
        parliament_timed_ovn_required_chunk_blocks_v1,
    },
    isi::governance::ParliamentSortitionRequestRegistrationV1,
};
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};

pub(crate) use iroha_data_model::governance::types::PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1;

use super::{
    draw::{body_committee_size, derive_attempt_body_plan_v1},
    timed_ovn::TimedOvnParliamentReducerBindingV1,
};

/// Proposal-wide ceiling for adversarially selectable fresh randomness, defined once by
/// the data model.
pub(crate) use iroha_data_model::parameter::parliament_lifecycle::MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;

// V1 deliberately keeps the redraw ceiling equal to the outer governance retry ceiling
// instead of exposing an independently tunable consensus bound.
const _: () =
    assert!(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 == MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1);

pub(crate) fn hidden_ballot_population_meets_anonymity_floor_v1(count: usize) -> bool {
    u32::try_from(count).is_ok_and(|count| count >= MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
}

/// Enumerate every canonical attempt identity available to one V1 proposal.
///
/// Runtime consumers use this bounded keyspace instead of scanning the global
/// Parliament attempt map. Restore validation still scans the complete map so
/// that it can reject arbitrary corrupt or non-canonical keys.
pub fn canonical_governance_attempt_ids_v1(
    proposal_content_id: ProposalContentId,
) -> impl DoubleEndedIterator<Item = GovernanceAttemptId> {
    (0..=MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1)
        .map(move |sequence| GovernanceAttemptId::derive_v1(proposal_content_id, sequence))
}

/// A reducible entity named by [`ParliamentReducerErrorV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParliamentReducerEntityV1 {
    /// The end-to-end governance attempt.
    GovernanceAttempt,
    /// An immutable future-pulse sortition request.
    SortitionRequest,
    /// A retryable body-election attempt.
    BodyElection,
    /// A sealed Parliament body instance.
    BodyInstance,
    /// A retryable private ballot attempt.
    BallotAttempt,
    /// The automatic governance certificate.
    Certificate,
}

/// Fail-closed errors returned by the Parliament attempt reducer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParliamentReducerErrorV1 {
    /// An operation named a different end-to-end attempt.
    AttemptBindingMismatch,
    /// A certificate named different immutable proposal content.
    ProposalBindingMismatch,
    /// The attempt is terminal or is not active for the requested operation.
    AttemptNotActive,
    /// The canonical framed attempt state exceeds or cannot satisfy the hard V1 byte bound.
    AttemptStateSizeLimitExceeded,
    /// A derived per-member attempt-reference count overflowed its fixed integer domain.
    MemberReferenceCountOverflow,
    /// A derived per-member attempt-reference row disagreed with authoritative attempt state.
    MemberReferenceProjectionMismatch,
    /// A derived Parliament status or stage count overflowed its fixed integer domain.
    AttemptCountOverflow,
    /// Derived Parliament status and stage counts disagree with authoritative attempt state.
    AttemptCountProjectionMismatch,
    /// The attempt names a Parliament policy version other than the sole first-release version.
    UnsupportedPolicyVersion,
    /// The requested risk tier is below the already accepted tier.
    RiskDowngrade,
    /// Repeating the current risk tier is a replay, not an escalation.
    RiskEscalationReplay,
    /// Risk became immutable when Policy Jury sortition was requested.
    RiskTierLocked,
    /// The supplied required-body pipeline is not canonical V1 order.
    InvalidRequiredBodyPipeline,
    /// The operation was submitted at the wrong governance stage.
    WrongGovernanceStage {
        /// Stage required by the operation.
        expected: GovernanceStageV1,
        /// Stage currently occupied by the attempt.
        actual: GovernanceStageV1,
    },
    /// An object named a body other than the current required body.
    WrongParliamentBody,
    /// An entity identifier is zero or already registered.
    DuplicateOrZeroIdentifier(ParliamentReducerEntityV1),
    /// The named entity does not exist in this attempt.
    UnknownEntity(ParliamentReducerEntityV1),
    /// The entity is not in the one lifecycle state accepted by the operation.
    InvalidLifecycleTransition(ParliamentReducerEntityV1),
    /// A retry sequence was not exactly zero or the predecessor plus one.
    RetrySequenceMismatch,
    /// An end-to-end governance attempt exceeded the hard V1 retry ceiling.
    GovernanceAttemptRetryLimitExceeded,
    /// Fresh sortition or timed-OVN retries exhausted the proposal-wide V1 redraw budget.
    RandomnessRedrawLimitExceeded,
    /// A successor attempt did not inherit the exact cumulative redraw count.
    RandomnessRedrawLineageMismatch,
    /// A body election attempted to exceed the hard V1 retry ceiling.
    SortitionRetryLimitExceeded,
    /// A timed-OVN ballot's reserved heavy-work windows overlap another active ballot.
    TimedOvnResourceScheduleConflict,
    /// A timed-OVN ballot would exceed the global cast-capable context ceiling.
    TooManyConcurrentCastingContexts,
    /// A request disagreed with its governance- or election-attempt binding.
    ImmutableBindingMismatch,
    /// A commitment root was zero.
    ZeroCommitmentRoot,
    /// A later transition supplied a root different from the frozen root.
    CommitmentRootMismatch,
    /// A future pulse did not match the immutable request.
    PulseBindingMismatch,
    /// A sortition schedule is invalid: a zero frozen delay, a frozen epoch length below
    /// three, or a request slot that is not the first consensus-native pulse height derived
    /// from the frozen delay, the frozen epoch length and the attempt's earlier generations.
    InvalidSortitionPulseSchedule,
    /// A beacon pulse identifier or session-height slot was already consumed.
    BeaconPulseAlreadyConsumed,
    /// A finalized beacon pulse contradicts a transcript that would classify its slot as absent.
    BeaconPulseAlreadyAvailable,
    /// A TLE session was already bound to another ballot attempt.
    TleSessionAlreadyConsumed,
    /// The roster was empty, oversized, non-canonical, or internally duplicated.
    InvalidRoster,
    /// The stored assignment plan does not match the deterministic future-beacon draw.
    InvalidAssignmentPlan,
    /// The responding account was not selected as a primary or alternate.
    UnknownInvitation,
    /// The selected account already submitted its immutable response.
    InvitationResponseReplay,
    /// Invitation acceptance was opened with an invalid block-height window.
    InvalidInvitationWindow,
    /// An invitation response arrived after the immutable response window.
    InvitationWindowClosed,
    /// A roster or no-roster result was requested before the response window closed.
    InvitationWindowStillOpen,
    /// A candidate snapshot was empty, noncanonical, too small for a hidden ballot, or mismatched.
    InvalidCandidateSnapshot,
    /// The Confirmation Jury reused a Policy Jury member.
    ConfirmationJuryNotFresh,
    /// The transition used a public finding for a binding body, or vice versa.
    DecisionModeMismatch,
    /// The frozen public-finding endorsement schedule is zero, overflows, or changed.
    InvalidPublicFindingSchedule,
    /// An endorsement arrived after the inclusive public-finding deadline.
    PublicFindingWindowClosed,
    /// Public-finding expiry was requested no later than its inclusive deadline.
    PublicFindingWindowStillOpen,
    /// Persisted public-finding no-result evidence does not match reducer state.
    PublicFindingFailureKindMismatch,
    /// A ballot count exceeded a frozen registration, survivor, or seat bound.
    InvalidBallotCount,
    /// The transaction authority does not own a nonexcluded seat in this ballot body.
    UnauthorizedBallotParticipant,
    /// The transaction authority does not own the assignment declaring absence.
    UnauthorizedBodyMember,
    /// A later ballot transition attempted to change the accepted corpus.
    AcceptedCorpusMutation,
    /// The release height was not strictly after the timed seal height.
    ReleaseHeightNotFuture,
    /// The immutable timed-ballot phase schedule is invalid or changed mid-attempt.
    InvalidBallotSchedule,
    /// A certified terminal transition did not execute at its exact due height.
    WrongEnactmentHeight,
    /// A consensus transition did not execute at its immutable phase boundary.
    WrongBallotPhaseHeight,
    /// The requested retry exceeds the policy frozen for this lifecycle.
    BallotRetryLimitExceeded,
    /// The no-result reason does not match the ballot phase or its deadline.
    BallotFailureKindMismatch,
    /// Opening was requested before the committed release height.
    ReleaseHeightNotReached,
    /// The aggregate tally was malformed.
    InvalidTally,
    /// A final opening did not cover the complete frozen survivor set.
    IncompleteOpening,
    /// A required final body binding is absent or inconsistent.
    IncompleteCertificate,
    /// Certification was not atomic with the final result, or enactment was not later.
    InvalidCertificateHeight,
    /// Persisted reducer state records an action after the restored ledger height.
    FuturePersistedHeight,
    /// A supplied certificate or effect binding differs from reducer state.
    CertificateBindingMismatch,
    /// Supersession was reported without an actual compare-and-set head change.
    ExpectedHeadUnchanged,
    /// The reported superseding head is malformed or names another governed subject.
    InvalidSupersedingHead,
}

impl fmt::Display for ParliamentReducerErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttemptBindingMismatch => f.write_str("governance attempt binding mismatch"),
            Self::ProposalBindingMismatch => f.write_str("proposal content binding mismatch"),
            Self::AttemptNotActive => f.write_str("governance attempt is not active"),
            Self::AttemptStateSizeLimitExceeded => {
                f.write_str("Parliament attempt state exceeds the V1 encoded-size limit")
            }
            Self::MemberReferenceCountOverflow => {
                f.write_str("Parliament member-reference count exceeds the fixed integer limit")
            }
            Self::MemberReferenceProjectionMismatch => {
                f.write_str("Parliament member-reference projection disagrees with attempt state")
            }
            Self::AttemptCountOverflow => {
                f.write_str("Parliament attempt count exceeds the fixed integer limit")
            }
            Self::AttemptCountProjectionMismatch => {
                f.write_str("Parliament attempt-count projection disagrees with attempt state")
            }
            Self::UnsupportedPolicyVersion => {
                f.write_str("unsupported Parliament governance policy version")
            }
            Self::RiskDowngrade => f.write_str("governance risk may only escalate"),
            Self::RiskEscalationReplay => f.write_str("risk escalation replays the current tier"),
            Self::RiskTierLocked => {
                f.write_str("governance risk is locked by Policy Jury sortition")
            }
            Self::InvalidRequiredBodyPipeline => {
                f.write_str("required Parliament body pipeline is not canonical")
            }
            Self::WrongGovernanceStage { expected, actual } => {
                write!(
                    f,
                    "expected governance stage {expected:?}, found {actual:?}"
                )
            }
            Self::WrongParliamentBody => f.write_str("wrong Parliament body for current stage"),
            Self::DuplicateOrZeroIdentifier(entity) => {
                write!(f, "duplicate or zero {entity:?} identifier")
            }
            Self::UnknownEntity(entity) => write!(f, "unknown {entity:?}"),
            Self::InvalidLifecycleTransition(entity) => {
                write!(f, "invalid or replayed {entity:?} lifecycle transition")
            }
            Self::RetrySequenceMismatch => f.write_str("retry sequence mismatch"),
            Self::GovernanceAttemptRetryLimitExceeded => {
                f.write_str("Parliament governance-attempt retry limit exceeded")
            }
            Self::RandomnessRedrawLimitExceeded => {
                f.write_str("Parliament proposal randomness-redraw budget exhausted")
            }
            Self::RandomnessRedrawLineageMismatch => {
                f.write_str("Parliament proposal randomness-redraw lineage mismatch")
            }
            Self::SortitionRetryLimitExceeded => {
                f.write_str("Parliament sortition retry limit exceeded")
            }
            Self::TimedOvnResourceScheduleConflict => f.write_str(
                "Parliament timed-OVN resource schedule conflicts with an active ballot",
            ),
            Self::TooManyConcurrentCastingContexts => {
                f.write_str("too many concurrent Parliament timed-OVN casting contexts")
            }
            Self::ImmutableBindingMismatch => f.write_str("immutable binding mismatch"),
            Self::ZeroCommitmentRoot => f.write_str("commitment root must not be zero"),
            Self::CommitmentRootMismatch => f.write_str("frozen commitment root mismatch"),
            Self::PulseBindingMismatch => f.write_str("future beacon pulse binding mismatch"),
            Self::InvalidSortitionPulseSchedule => {
                f.write_str("invalid deterministic Parliament sortition pulse schedule")
            }
            Self::BeaconPulseAlreadyConsumed => f.write_str("beacon pulse already consumed"),
            Self::BeaconPulseAlreadyAvailable => {
                f.write_str("beacon pulse is already finalized for the unavailable slot")
            }
            Self::TleSessionAlreadyConsumed => f.write_str("TLE session already consumed"),
            Self::InvalidRoster => f.write_str("invalid or non-canonical Parliament roster"),
            Self::InvalidAssignmentPlan => {
                f.write_str("invalid deterministic Parliament assignment plan")
            }
            Self::UnknownInvitation => f.write_str("account has no invitation in this election"),
            Self::InvitationResponseReplay => {
                f.write_str("Parliament invitation response already recorded")
            }
            Self::InvalidInvitationWindow => {
                f.write_str("invalid Parliament invitation response window")
            }
            Self::InvitationWindowClosed => {
                f.write_str("Parliament invitation response window is closed")
            }
            Self::InvitationWindowStillOpen => {
                f.write_str("Parliament invitation response window is still open")
            }
            Self::InvalidCandidateSnapshot => {
                f.write_str("invalid, undersized, or mismatched Parliament candidate snapshot")
            }
            Self::ConfirmationJuryNotFresh => {
                f.write_str("Confirmation Jury is not disjoint from Policy Jury")
            }
            Self::DecisionModeMismatch => f.write_str("body decision mode mismatch"),
            Self::InvalidPublicFindingSchedule => {
                f.write_str("invalid public-finding endorsement schedule")
            }
            Self::PublicFindingWindowClosed => {
                f.write_str("public-finding endorsement window is closed")
            }
            Self::PublicFindingWindowStillOpen => {
                f.write_str("public-finding endorsement window is still open")
            }
            Self::PublicFindingFailureKindMismatch => {
                f.write_str("public-finding no-result evidence does not match reducer state")
            }
            Self::InvalidBallotCount => f.write_str("ballot count exceeds a frozen bound"),
            Self::UnauthorizedBallotParticipant => {
                f.write_str("account is not a nonexcluded member of this ballot body")
            }
            Self::UnauthorizedBodyMember => {
                f.write_str("account does not own this Parliament body assignment")
            }
            Self::AcceptedCorpusMutation => f.write_str("accepted ballot corpus is immutable"),
            Self::ReleaseHeightNotFuture => {
                f.write_str("ballot release height must be strictly future")
            }
            Self::InvalidBallotSchedule => f.write_str("invalid timed-ballot phase schedule"),
            Self::WrongEnactmentHeight => {
                f.write_str("certified governance effect must execute at its exact due height")
            }
            Self::WrongBallotPhaseHeight => {
                f.write_str("timed-ballot transition is outside its immutable phase boundary")
            }
            Self::BallotRetryLimitExceeded => f.write_str("private ballot retry limit exceeded"),
            Self::BallotFailureKindMismatch => {
                f.write_str("private ballot failure reason does not match its phase or deadline")
            }
            Self::ReleaseHeightNotReached => f.write_str("ballot release height not reached"),
            Self::InvalidTally => f.write_str("invalid private-ballot aggregate tally"),
            Self::IncompleteOpening => f.write_str("opening does not cover every survivor"),
            Self::IncompleteCertificate => f.write_str("governance certificate is incomplete"),
            Self::InvalidCertificateHeight => f.write_str(
                "certification must equal the final result height and precede enactment",
            ),
            Self::FuturePersistedHeight => {
                f.write_str("persisted Parliament action is ahead of the restored ledger height")
            }
            Self::CertificateBindingMismatch => {
                f.write_str("governance certificate binding mismatch")
            }
            Self::ExpectedHeadUnchanged => {
                f.write_str("supersession requires a changed compare-and-set head")
            }
            Self::InvalidSupersedingHead => {
                f.write_str("superseding head is invalid for the governed subject")
            }
        }
    }
}

impl std::error::Error for ParliamentReducerErrorV1 {}

/// Whether a body emits a public nonbinding finding or a private binding ballot.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentDecisionModeV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(tag = "mode", content = "details", deny_unknown_fields)]
pub enum ParliamentDecisionModeV1 {
    /// Public evidence and deliberation end in a nonbinding finding.
    PublicFinding,
    /// The body must use the private OVN/TLE ballot lifecycle.
    HiddenBindingBallot,
}

/// One body required by the attempt's immutable policy pipeline.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::RequiredParliamentBodyV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
)]
pub struct RequiredParliamentBodyV1 {
    /// Body role that must be completed.
    pub body: ParliamentBody,
    /// Decision protocol required for the body.
    pub decision_mode: ParliamentDecisionModeV1,
}

const CONTRACT_LIFECYCLE_REQUIRED_BODIES_V1: &[ParliamentBody] = &[
    ParliamentBody::RulesCommittee,
    ParliamentBody::AgendaCouncil,
    ParliamentBody::InterestPanel,
    ParliamentBody::ReviewPanel,
    ParliamentBody::OversightCommittee,
    ParliamentBody::PolicyJury,
];

const SCCP_ROUTE_GOVERNANCE_REQUIRED_BODIES_V1: &[ParliamentBody] = &[
    ParliamentBody::RulesCommittee,
    ParliamentBody::AgendaCouncil,
    ParliamentBody::InterestPanel,
    ParliamentBody::ReviewPanel,
    ParliamentBody::CoordinationCouncil,
    ParliamentBody::FmaCommittee,
    ParliamentBody::OversightCommittee,
    ParliamentBody::PolicyJury,
];

const VALIDATION_FEE_REQUIRED_BODIES_V1: &[ParliamentBody] = &[
    ParliamentBody::RulesCommittee,
    ParliamentBody::AgendaCouncil,
    ParliamentBody::InterestPanel,
    ParliamentBody::ReviewPanel,
    ParliamentBody::CoordinationCouncil,
    ParliamentBody::MpcCommittee,
    ParliamentBody::FmaCommittee,
    ParliamentBody::OversightCommittee,
    ParliamentBody::PolicyJury,
];

/// Derive the immutable initial risk and body pipeline for one typed proposal.
///
/// A reducer may subsequently raise the risk tier and append the dynamically
/// required Confirmation Jury, but neither operation may weaken this base
/// policy.
#[must_use]
pub(crate) fn parliament_attempt_policy_v1(
    proposal: &ProposalKind,
) -> (RiskTierV1, Vec<RequiredParliamentBodyV1>) {
    let bodies: &[ParliamentBody] = match proposal {
        ProposalKind::DeployContract(_)
        | ProposalKind::ContractLifecycleGovernance(_)
        | ProposalKind::ContractEmergencyHold(_) => CONTRACT_LIFECYCLE_REQUIRED_BODIES_V1,
        ProposalKind::SccpRouteGovernance(_) => SCCP_ROUTE_GOVERNANCE_REQUIRED_BODIES_V1,
        ProposalKind::ValidationFeePolicy(_) | ProposalKind::ValidationFeePayoutLifecycle(_) => {
            VALIDATION_FEE_REQUIRED_BODIES_V1
        }
        ProposalKind::RuntimeUpgrade(_)
        | ProposalKind::MusubiRegistryGovernance(_)
        | ProposalKind::SorafsProviderGovernance(_)
        | ProposalKind::GlobalDataTriggerPermissionGovernance(_) => &[
            ParliamentBody::RulesCommittee,
            ParliamentBody::AgendaCouncil,
            ParliamentBody::InterestPanel,
            ParliamentBody::ReviewPanel,
            ParliamentBody::CoordinationCouncil,
            ParliamentBody::OversightCommittee,
            ParliamentBody::PolicyJury,
        ],
    };
    let risk_tier = match proposal {
        ProposalKind::DeployContract(_) | ProposalKind::ContractLifecycleGovernance(_) => {
            RiskTierV1::Standard
        }
        ProposalKind::ContractEmergencyHold(_) => RiskTierV1::Emergency,
        _ => RiskTierV1::Constitutional,
    };
    let requirements = bodies
        .iter()
        .copied()
        .map(|body| RequiredParliamentBodyV1 {
            body,
            decision_mode: if body == ParliamentBody::PolicyJury {
                ParliamentDecisionModeV1::HiddenBindingBallot
            } else {
                ParliamentDecisionModeV1::PublicFinding
            },
        })
        .collect();
    (risk_tier, requirements)
}

/// The single reducer object allowed to consume a finalized beacon pulse.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentPulseConsumerV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, JsonSerialize, JsonDeserialize,
)]
#[norito(tag = "consumer", content = "bindings", deny_unknown_fields)]
enum ParliamentPulseConsumerV1 {
    /// A canonical simultaneous future-pulse sortition batch.
    SortitionBatch(Vec<SortitionRequestId>),
    /// A canonical simultaneous timed private-ballot opening batch.
    BallotBatch(Vec<BallotAttemptId>),
}

/// One globally unique threshold-beacon output slot.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentPulseSlotV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
struct ParliamentPulseSlotV1 {
    beacon_session_id: BeaconSessionId,
    height: u64,
}

impl ParliamentPulseSlotV1 {
    const fn new(beacon_session_id: BeaconSessionId, height: u64) -> Self {
        Self {
            beacon_session_id,
            height,
        }
    }

    fn canonical_json_key(&self) -> String {
        format!(
            "{}:{}",
            hex::encode(self.beacon_session_id.as_bytes()),
            self.height
        )
    }

    fn from_canonical_json_key(encoded: &str) -> Result<Self, norito::json::Error> {
        // A fixed-size session hash and a u64 height never require key-sized scratch.
        if !(66..=85).contains(&encoded.len()) {
            return Err(norito::json::Error::Message(
                "Parliament pulse-slot key must contain 64 session digits and 1–20 height digits"
                    .into(),
            ));
        }
        let (session_hex, height_text) = encoded.split_once(':').ok_or_else(|| {
            norito::json::Error::Message(
                "Parliament pulse-slot key must contain one session/height separator".into(),
            )
        })?;
        let beacon_session_id =
            <BeaconSessionId as norito::json::JsonObjectKeyOwned>::from_json_key_text(session_hex)?;
        if height_text.is_empty()
            || !height_text.bytes().all(|byte| byte.is_ascii_digit())
            || (height_text.len() > 1 && height_text.starts_with('0'))
        {
            return Err(norito::json::Error::Message(
                "Parliament pulse-slot height must use canonical decimal".into(),
            ));
        }
        let height = height_text.parse::<u64>().map_err(|error| {
            norito::json::Error::Message(format!("invalid Parliament pulse-slot height: {error}"))
        })?;
        Ok(Self::new(beacon_session_id, height))
    }
}

impl norito::json::JsonSerialize for ParliamentPulseSlotV1 {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_json_string(&self.canonical_json_key(), out);
    }

    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(&self.canonical_json_key(), out)
    }
}

impl norito::json::JsonDeserialize for ParliamentPulseSlotV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let encoded = <String as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        Self::from_canonical_json_key(&encoded)
    }
}

impl norito::json::JsonObjectKey for ParliamentPulseSlotV1 {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        norito::json::JsonObjectKey::visit_json_key_text(&self.beacon_session_id, &mut visitor)?;
        visitor(":")?;
        norito::json::JsonObjectKey::visit_json_key_text(&self.height, visitor)
    }
}
impl norito::json::JsonObjectKeyOwned for ParliamentPulseSlotV1 {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        Self::from_canonical_json_key(key)
    }
}

/// Reducer-owned state for one body-election attempt.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentElectionFailureKindV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(tag = "failure", content = "details", deny_unknown_fields)]
pub enum ParliamentElectionFailureKindV1 {
    /// The invitation window closed without one accepted eligible assignment.
    EmptyAcceptedRoster,
    /// A hidden-ballot body retained only one accepted assignment at close.
    InsufficientHiddenBallotRoster,
}

/// Reducer-owned evidence that a manager-requested hidden-body sortition could
/// not create an ordinary future-pulse request from the live electorate.
///
/// Unlike [`ParliamentElectionStateV1`], this record never contains an invalid
/// [`SortitionRequestV1`]. It freezes the exact empty or singleton candidate
/// snapshot and the otherwise canonical request intent before any beacon slot
/// is reserved or consumed.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentSortitionCapacityFailureV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct ParliamentSortitionCapacityFailureV1 {
    body_election_attempt_id: BodyElectionAttemptId,
    body: ParliamentBody,
    sequence: u32,
    request_intent_id: SortitionRequestId,
    candidate_snapshot: Vec<AccountId>,
    candidate_root: [u8; 32],
    target_seats: u32,
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
    status: BodyElectionAttemptStatusV1,
    failure_height: u64,
}

impl ParliamentSortitionCapacityFailureV1 {
    /// Return the body-election generation that could not form a request.
    #[must_use]
    pub const fn body_election_attempt_id(&self) -> BodyElectionAttemptId {
        self.body_election_attempt_id
    }

    /// Return the Parliament body whose sortition generation was blocked.
    #[must_use]
    pub const fn body(&self) -> ParliamentBody {
        self.body
    }

    /// Return the zero-based bounded sortition generation.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Return the number of live body-specific candidates frozen in evidence.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidate_snapshot.len()
    }

    /// Return the terminal or superseded status of this failed generation.
    #[must_use]
    pub const fn status(&self) -> BodyElectionAttemptStatusV1 {
        self.status
    }

    /// Return the containing height at which Core observed insufficient capacity.
    #[must_use]
    pub const fn failure_height(&self) -> u64 {
        self.failure_height
    }
}

/// Reducer-owned state for one body-election attempt.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentElectionStateV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct ParliamentElectionStateV1 {
    attempt: iroha_data_model::governance::types::BodyElectionAttemptV1,
    candidate_snapshot_index: u32,
    pulse_id: Option<BeaconPulseId>,
    pulse_output: Option<[u8; 32]>,
    assignment_root: Option<[u8; 32]>,
    primary_assignments: Vec<ParliamentSeatAssignmentV1>,
    alternate_assignments: Vec<ParliamentSeatAssignmentV1>,
    cross_body_assignment_cap: Option<u32>,
    invitation_opened_at_height: Option<u64>,
    invitation_close_height: Option<u64>,
    accepted_assignments: BTreeSet<AssignmentId>,
    declined_assignments: BTreeSet<AssignmentId>,
    failure_kind: Option<ParliamentElectionFailureKindV1>,
    failure_height: Option<u64>,
}

impl ParliamentElectionStateV1 {
    /// Return the canonical data-model election snapshot.
    #[must_use]
    pub const fn attempt(&self) -> &iroha_data_model::governance::types::BodyElectionAttemptV1 {
        &self.attempt
    }

    /// Return the consumed pulse identifier, when drawing has begun.
    #[must_use]
    pub const fn pulse_id(&self) -> Option<BeaconPulseId> {
        self.pulse_id
    }

    /// Return the exact finalized beacon output used by the deterministic draw.
    #[must_use]
    pub const fn pulse_output(&self) -> Option<[u8; 32]> {
        self.pulse_output
    }

    /// Return the frozen assignment root, when invitations have begun.
    #[must_use]
    pub const fn assignment_root(&self) -> Option<[u8; 32]> {
        self.assignment_root
    }

    /// Return primary assignments in deterministic invitation rank order.
    #[must_use]
    pub fn primary_assignments(&self) -> &[ParliamentSeatAssignmentV1] {
        &self.primary_assignments
    }

    /// Return alternate assignments in deterministic replacement rank order.
    #[must_use]
    pub fn alternate_assignments(&self) -> &[ParliamentSeatAssignmentV1] {
        &self.alternate_assignments
    }

    /// Return the cross-body concentration cap used by the simultaneous draw.
    #[must_use]
    pub const fn cross_body_assignment_cap(&self) -> Option<u32> {
        self.cross_body_assignment_cap
    }

    /// Return the last height at which an invited citizen may respond.
    #[must_use]
    pub const fn invitation_close_height(&self) -> Option<u64> {
        self.invitation_close_height
    }

    /// Return immutable accepted assignment identifiers.
    #[must_use]
    pub const fn accepted_assignments(&self) -> &BTreeSet<AssignmentId> {
        &self.accepted_assignments
    }

    /// Return immutable declined assignment identifiers.
    #[must_use]
    pub const fn declined_assignments(&self) -> &BTreeSet<AssignmentId> {
        &self.declined_assignments
    }
}

/// Reducer-owned state for one sealed body instance.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentBodyStateV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct ParliamentBodyStateV1 {
    instance: ParliamentBodyInstanceV1,
    roster_root: [u8; 32],
    assignments: Vec<ParliamentSeatAssignmentV1>,
    excluded_assignments: BTreeSet<AssignmentId>,
    public_finding_endorsements: BTreeMap<AssignmentId, [u8; 32]>,
    public_finding_opened_at_height: Option<u64>,
    public_finding_phase_blocks: Option<u64>,
    public_finding_deadline_height: Option<u64>,
    public_finding_no_result_kind: Option<ParliamentNoResultKindV1>,
    public_finding_no_result_height: Option<u64>,
    public_finding_binding: Option<ParliamentPublicFindingCertificateBindingV1>,
    result_root: Option<[u8; 32]>,
    result_height: Option<u64>,
    ballot_binding: Option<ParliamentBallotCertificateBindingV1>,
}

impl ParliamentBodyStateV1 {
    /// Return the canonical body-instance snapshot.
    #[must_use]
    pub const fn instance(&self) -> &ParliamentBodyInstanceV1 {
        &self.instance
    }

    /// Return the immutable ordered roster root.
    #[must_use]
    pub const fn roster_root(&self) -> [u8; 32] {
        self.roster_root
    }

    /// Return the canonical sealed seat assignments.
    #[must_use]
    pub fn assignments(&self) -> &[ParliamentSeatAssignmentV1] {
        &self.assignments
    }

    /// Return attempt-local absence exclusions.
    #[must_use]
    pub const fn excluded_assignments(&self) -> &BTreeSet<AssignmentId> {
        &self.excluded_assignments
    }

    /// Return authority-authenticated public-finding endorsements by assignment.
    #[must_use]
    pub const fn public_finding_endorsements(&self) -> &BTreeMap<AssignmentId, [u8; 32]> {
        &self.public_finding_endorsements
    }

    /// Return the height opening the public-finding endorsement window.
    #[must_use]
    pub const fn public_finding_opened_at_height(&self) -> Option<u64> {
        self.public_finding_opened_at_height
    }

    /// Return the frozen public-finding endorsement span in blocks.
    #[must_use]
    pub const fn public_finding_phase_blocks(&self) -> Option<u64> {
        self.public_finding_phase_blocks
    }

    /// Return the inclusive frozen public-finding endorsement deadline.
    #[must_use]
    pub const fn public_finding_deadline_height(&self) -> Option<u64> {
        self.public_finding_deadline_height
    }

    /// Return the objective public-finding no-result class, when terminal.
    #[must_use]
    pub const fn public_finding_no_result_kind(&self) -> Option<ParliamentNoResultKindV1> {
        self.public_finding_no_result_kind
    }

    /// Return the containing height that made the public finding terminal.
    #[must_use]
    pub const fn public_finding_no_result_height(&self) -> Option<u64> {
        self.public_finding_no_result_height
    }

    /// Return the final public result root, when the body has completed.
    #[must_use]
    pub const fn result_root(&self) -> Option<[u8; 32]> {
        self.result_root
    }

    /// Return the height at which the body result became immutable.
    #[must_use]
    pub const fn result_height(&self) -> Option<u64> {
        self.result_height
    }
}

/// Reducer-owned transcript bindings for one private ballot attempt.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentBallotStateV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct ParliamentBallotStateV1 {
    attempt: ParliamentBallotAttemptV1,
    registration_root: Option<[u8; 32]>,
    registered_voters: Option<u32>,
    corpus_root: Option<[u8; 32]>,
    accepted_ballots: Option<u32>,
    dropout_root: Option<[u8; 32]>,
    survivor_root: Option<[u8; 32]>,
    survivors: Option<u32>,
    no_recovery_root: Option<[u8; 32]>,
    tle_session_id: Option<TleSessionId>,
    tle_key_session_id: Option<TleKeySessionId>,
    release_beacon_session_id: Option<BeaconSessionId>,
    registered_at_height: u64,
    registration_phase_blocks: u64,
    survivor_freeze_phase_blocks: u64,
    commitment_phase_blocks: u64,
    release_delay_blocks: u64,
    opening_phase_blocks: u64,
    max_ballot_retries: u32,
    max_corpus_entries: u32,
    registration_close_height: u64,
    survivor_freeze_height: u64,
    commitment_close_height: u64,
    registration_closed_at_height: Option<u64>,
    survivors_frozen_at_height: Option<u64>,
    commitment_closed_at_height: Option<u64>,
    timed_commitment_root: Option<[u8; 32]>,
    release_height: Option<u64>,
    opening_deadline_height: u64,
    release_pulse_id: Option<BeaconPulseId>,
    opening_height: Option<u64>,
    opening_root: Option<[u8; 32]>,
    tally: Option<ParliamentAggregateTallyV1>,
    outcome: Option<ParliamentAggregateOutcomeV1>,
    failure_root: Option<[u8; 32]>,
    failure_kind: Option<ParliamentBallotFailureKindV1>,
    failure_height: Option<u64>,
    eligible_confirmation_candidates: Option<u32>,
}

impl ParliamentBallotStateV1 {
    /// Return the canonical ballot-attempt snapshot.
    #[must_use]
    pub const fn attempt(&self) -> &ParliamentBallotAttemptV1 {
        &self.attempt
    }

    /// Return the frozen accepted corpus root, when commitments have closed.
    #[must_use]
    pub const fn corpus_root(&self) -> Option<[u8; 32]> {
        self.corpus_root
    }

    /// Return the accepted ballot count, when commitments have closed.
    #[must_use]
    pub const fn accepted_ballots(&self) -> Option<u32> {
        self.accepted_ballots
    }

    /// Return the frozen authenticated registration count after registration closes.
    #[must_use]
    pub const fn registered_voters(&self) -> Option<u32> {
        self.registered_voters
    }

    /// Return the dedicated TLE session, once the timed seal is complete.
    #[must_use]
    pub const fn tle_session_id(&self) -> Option<TleSessionId> {
        self.tle_session_id
    }

    /// Return the finalized adaptive TLE key session bound to this ballot.
    #[must_use]
    pub const fn tle_key_session_id(&self) -> Option<TleKeySessionId> {
        self.tle_key_session_id
    }

    /// Return the threshold-beacon session committed for release.
    #[must_use]
    pub const fn release_beacon_session_id(&self) -> Option<BeaconSessionId> {
        self.release_beacon_session_id
    }

    /// Return the committed release height, once the timed seal is complete.
    #[must_use]
    pub const fn release_height(&self) -> Option<u64> {
        self.release_height
    }

    /// Return the immutable height that opened registration for this ballot.
    #[must_use]
    pub const fn registered_at_height(&self) -> u64 {
        self.registered_at_height
    }

    /// Return the exact height that closes authenticated registration.
    #[must_use]
    pub(crate) const fn registration_close_height(&self) -> u64 {
        self.registration_close_height
    }

    /// Return the exact height that freezes the survivor subsequence.
    #[must_use]
    pub(crate) const fn survivor_freeze_height(&self) -> u64 {
        self.survivor_freeze_height
    }

    /// Return the exact height that freezes the masked-ballot corpus.
    #[must_use]
    pub(crate) const fn commitment_close_height(&self) -> u64 {
        self.commitment_close_height
    }

    /// Return the immutable last height at which aggregate opening may complete.
    #[must_use]
    pub const fn opening_deadline_height(&self) -> u64 {
        self.opening_deadline_height
    }

    /// Return the Core-derived terminal failure class, when present.
    #[must_use]
    pub const fn failure_kind(&self) -> Option<ParliamentBallotFailureKindV1> {
        self.failure_kind
    }

    /// Return the containing height of the Core-derived terminal failure.
    #[must_use]
    pub const fn failure_height(&self) -> Option<u64> {
        self.failure_height
    }

    /// Return the Core-derived fresh Confirmation Jury capacity at terminal opening.
    #[must_use]
    pub const fn eligible_confirmation_candidates(&self) -> Option<u32> {
        self.eligible_confirmation_candidates
    }
}

/// Deterministic aggregate state for one immutable proposal attempt.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::governance::parliament::ParliamentAttemptStateV1")]
pub struct ParliamentAttemptStateV1 {
    attempt: GovernanceAttemptV1,
    /// Proposal-wide redraw units consumed before this attempt was created.
    ///
    /// This cumulative prefix prevents a terminal attempt from resetting the
    /// grinding budget. The attempt's own usage is derived from its immutable
    /// sortition generations and ballot-attempt sequence, so transport retries
    /// over an existing request/session never increment it.
    randomness_redraws_before_attempt: u32,
    policy_version: u64,
    sortition_pulse_delay_blocks: u64,
    /// Consensus-native `NPoS` epoch length frozen at attempt creation.
    ///
    /// Native beacon pulse heights are exactly `{ h : (h + 1) % L == 0 }`. Every sortition
    /// slot of this attempt is derived from this frozen value, never from live parameters.
    sortition_pulse_epoch_length_blocks: u64,
    effect_preimage_hash: [u8; 32],
    expected_head: GovernanceExpectedHeadV1,
    required_bodies: Vec<RequiredParliamentBodyV1>,
    risk_locked: bool,
    candidate_snapshots: Vec<Vec<AccountId>>,
    elections: BTreeMap<BodyElectionAttemptId, ParliamentElectionStateV1>,
    active_elections: BTreeMap<ParliamentBody, BodyElectionAttemptId>,
    sortition_capacity_failures:
        BTreeMap<BodyElectionAttemptId, ParliamentSortitionCapacityFailureV1>,
    active_sortition_capacity_failures: BTreeMap<ParliamentBody, BodyElectionAttemptId>,
    bodies: BTreeMap<BodyInstanceId, ParliamentBodyStateV1>,
    active_bodies: BTreeMap<ParliamentBody, BodyInstanceId>,
    ballots: BTreeMap<BallotAttemptId, ParliamentBallotStateV1>,
    active_ballots: BTreeMap<BodyInstanceId, BallotAttemptId>,
    body_bindings: BTreeMap<ParliamentBody, ParliamentBodyCertificateBindingV1>,
    used_pulse_ids: BTreeMap<BeaconPulseId, ParliamentPulseConsumerV1>,
    used_pulse_slots: BTreeMap<ParliamentPulseSlotV1, BeaconPulseId>,
    used_tle_sessions: BTreeMap<TleSessionId, BallotAttemptId>,
    certificate: Option<GovernanceCertificateV1>,
    terminal_height: Option<u64>,
    superseding_head: Option<GovernanceExpectedHeadV1>,
    execution_failure_root: Option<[u8; 32]>,
}

/// Smallest consensus-native `NPoS` epoch length a sortition schedule can be frozen with.
pub const MIN_PARLIAMENT_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS_V1: u64 = 3;

/// Return the first consensus-native beacon pulse height at or after `earliest`.
///
/// On an `NPoS` chain with epoch length `epoch_length_blocks` the native pulse heights are
/// exactly `{ h : (h + 1) % epoch_length_blocks == 0 }`. The result is the least such
/// `h >= earliest`.
///
/// Returns `None` when `earliest` is zero, when `epoch_length_blocks` is below the `NPoS`
/// minimum of three blocks, or when the slot or its successor height does not fit `u64`.
/// The arithmetic is checked and never saturates.
#[must_use]
pub const fn aligned_sortition_pulse_height_v1(
    earliest: u64,
    epoch_length_blocks: u64,
) -> Option<u64> {
    if earliest == 0 || epoch_length_blocks < MIN_PARLIAMENT_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS_V1
    {
        return None;
    }
    let lead = epoch_length_blocks - 1 - earliest % epoch_length_blocks;
    let Some(height) = earliest.checked_add(lead) else {
        return None;
    };
    if height.checked_add(1).is_none() {
        return None;
    }
    Some(height)
}

fn root_is_zero(root: &[u8; 32]) -> bool {
    root.iter().all(|byte| *byte == 0)
}

fn candidate_snapshot_fits_resource_bounds_v1(candidate_snapshot: &[AccountId]) -> bool {
    if candidate_snapshot.len()
        > usize::try_from(MAX_PARLIAMENT_CITIZENS_V1)
            .expect("the V1 Parliament citizen cap fits usize")
    {
        return false;
    }
    let canonical_flags = norito::core::default_encode_flags();
    let _canonical_flags = norito::core::DecodeFlagsGuard::enter(canonical_flags);
    candidate_snapshot
        .iter()
        .try_fold(norito::core::seq_len_prefix_len(0), |bytes, candidate| {
            norito::core::encoded_payload_len(candidate)
                .ok()
                .and_then(|candidate_bytes| {
                    bytes
                        .checked_add(norito::core::len_prefix_len_with_flags(
                            candidate_bytes,
                            canonical_flags,
                        ))?
                        .checked_add(candidate_bytes)
                })
                .filter(|next| *next <= MAX_PARLIAMENT_CANDIDATE_SNAPSHOT_BYTES_V1)
        })
        .is_some()
}

fn election_awaiting_pulse_shape_is_empty(election: &ParliamentElectionStateV1) -> bool {
    election.pulse_id.is_none()
        && election.pulse_output.is_none()
        && election.assignment_root.is_none()
        && election.primary_assignments.is_empty()
        && election.alternate_assignments.is_empty()
        && election.cross_body_assignment_cap.is_none()
        && election.invitation_opened_at_height.is_none()
        && election.invitation_close_height.is_none()
        && election.accepted_assignments.is_empty()
        && election.declined_assignments.is_empty()
}

fn expected_head_is_valid(expected_head: GovernanceExpectedHeadV1) -> bool {
    match expected_head {
        GovernanceExpectedHeadV1::Absent(head) => !root_is_zero(&head.subject_id),
        GovernanceExpectedHeadV1::Present(head) => {
            !root_is_zero(&head.subject_id) && head.version != 0 && !root_is_zero(&head.head_root)
        }
    }
}

fn expected_head_subject(expected_head: GovernanceExpectedHeadV1) -> [u8; 32] {
    match expected_head {
        GovernanceExpectedHeadV1::Absent(head) => head.subject_id,
        GovernanceExpectedHeadV1::Present(head) => head.subject_id,
    }
}

fn timed_ballot_schedule(
    registered_at_height: u64,
    policy: ParliamentTimedOvn,
) -> Result<(u64, u64, u64, u64, u64), ParliamentReducerErrorV1> {
    let minimum_registration_phase_blocks = u64::from(policy.max_corpus_entries)
        .checked_add(1)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    let minimum_survivor_freeze_phase_blocks = u64::from(policy.max_corpus_entries);
    if registered_at_height == 0
        || policy.registration_phase_blocks == 0
        || policy.survivor_freeze_phase_blocks == 0
        || policy.commitment_phase_blocks == 0
        || policy.release_delay_blocks == 0
        || policy.opening_phase_blocks == 0
        || policy.max_ballot_retries > MAX_PARLIAMENT_BALLOT_RETRIES_V1
        || !(MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1..=MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1)
            .contains(&policy.max_corpus_entries)
        || policy.registration_phase_blocks < minimum_registration_phase_blocks
        || policy.survivor_freeze_phase_blocks < minimum_survivor_freeze_phase_blocks
        || policy.commitment_phase_blocks
            < parliament_timed_ovn_required_chunk_blocks_v1(policy.max_corpus_entries)
    {
        return Err(ParliamentReducerErrorV1::InvalidBallotSchedule);
    }
    let registration_close_height = registered_at_height
        .checked_add(policy.registration_phase_blocks)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    let survivor_freeze_height = registration_close_height
        .checked_add(policy.survivor_freeze_phase_blocks)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    let commitment_close_height = survivor_freeze_height
        .checked_add(policy.commitment_phase_blocks)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    let release_height = commitment_close_height
        .checked_add(policy.release_delay_blocks)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    let opening_deadline_height = release_height
        .checked_add(policy.opening_phase_blocks)
        .ok_or(ParliamentReducerErrorV1::InvalidBallotSchedule)?;
    Ok((
        registration_close_height,
        survivor_freeze_height,
        commitment_close_height,
        release_height,
        opening_deadline_height,
    ))
}

fn ballot_policy_matches(ballot: &ParliamentBallotStateV1, policy: ParliamentTimedOvn) -> bool {
    ballot.registration_phase_blocks == policy.registration_phase_blocks
        && ballot.survivor_freeze_phase_blocks == policy.survivor_freeze_phase_blocks
        && ballot.commitment_phase_blocks == policy.commitment_phase_blocks
        && ballot.release_delay_blocks == policy.release_delay_blocks
        && ballot.opening_phase_blocks == policy.opening_phase_blocks
        && ballot.max_ballot_retries == policy.max_ballot_retries
        && ballot.max_corpus_entries == policy.max_corpus_entries
}

fn ballot_policy(ballot: &ParliamentBallotStateV1) -> ParliamentTimedOvn {
    ParliamentTimedOvn {
        registration_phase_blocks: ballot.registration_phase_blocks,
        survivor_freeze_phase_blocks: ballot.survivor_freeze_phase_blocks,
        commitment_phase_blocks: ballot.commitment_phase_blocks,
        release_delay_blocks: ballot.release_delay_blocks,
        opening_phase_blocks: ballot.opening_phase_blocks,
        max_ballot_retries: ballot.max_ballot_retries,
        max_corpus_entries: ballot.max_corpus_entries,
    }
}

fn timed_commitment_height_is_in_window(ballot: &ParliamentBallotStateV1, height: u64) -> bool {
    height > ballot.survivor_freeze_height && height <= ballot.commitment_close_height
}

fn timed_commitment_completed_in_window(ballot: &ParliamentBallotStateV1) -> bool {
    ballot
        .commitment_closed_at_height
        .is_some_and(|height| timed_commitment_height_is_in_window(ballot, height))
}

fn classify_ballot_failure(
    ballot: &ParliamentBallotStateV1,
    release_pulse_available: bool,
    current_height: u64,
) -> Option<ParliamentBallotFailureKindV1> {
    match ballot.attempt.status {
        BallotAttemptStatusV1::Registration
            if current_height > ballot.registration_close_height =>
        {
            Some(ParliamentBallotFailureKindV1::RegistrationDeadlineExpired)
        }
        BallotAttemptStatusV1::SurvivorFreeze
            if ballot.registration_closed_at_height == Some(ballot.registration_close_height)
                && current_height > ballot.survivor_freeze_height =>
        {
            Some(ParliamentBallotFailureKindV1::SurvivorDeadlineExpired)
        }
        BallotAttemptStatusV1::TimedCommitment
            if ballot.survivors_frozen_at_height == Some(ballot.survivor_freeze_height)
                && current_height > ballot.commitment_close_height =>
        {
            Some(ParliamentBallotFailureKindV1::CommitmentDeadlineExpired)
        }
        BallotAttemptStatusV1::AwaitingRelease
            if timed_commitment_completed_in_window(ballot)
                && current_height > ballot.opening_deadline_height =>
        {
            Some(ParliamentBallotFailureKindV1::OpeningDeadlineExpired)
        }
        // Governance-local outcome: the release slot was never consensus demand, so a
        // release height without a native pulse ends the ballot here and nowhere else.
        // TODO: retire with the timed-OVN ballot path
        // (specs/parliament_private_ballot_design.md 12.2 step 4).
        BallotAttemptStatusV1::AwaitingRelease
            if timed_commitment_completed_in_window(ballot)
                && !release_pulse_available
                && ballot
                    .release_height
                    .is_some_and(|release_height| current_height > release_height) =>
        {
            Some(ParliamentBallotFailureKindV1::ReleasePulseUnavailable)
        }
        BallotAttemptStatusV1::Opening if current_height > ballot.opening_deadline_height => {
            Some(ParliamentBallotFailureKindV1::OpeningDeadlineExpired)
        }
        _ => None,
    }
}

fn ballot_failure_matches_state(
    governance_attempt_id: GovernanceAttemptId,
    ballot_attempt_id: BallotAttemptId,
    ballot: &ParliamentBallotStateV1,
    body_role: ParliamentBody,
) -> bool {
    let Some(failure_kind) = ballot.failure_kind else {
        return false;
    };
    let Some(failure_height) = ballot.failure_height else {
        return false;
    };
    if ballot.failure_root
        != Some(parliament_ballot_failure_root_v1(
            governance_attempt_id,
            ballot_attempt_id,
            failure_kind,
            failure_height,
        ))
    {
        return false;
    }
    if !matches!(
        failure_kind,
        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable
            | ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted
    ) && (ballot.opening_root.is_some()
        || ballot.tally.is_some()
        || ballot.outcome.is_some()
        || ballot.eligible_confirmation_candidates.is_some())
    {
        return false;
    }

    let registration_frozen = ballot.registration_root.is_some()
        && ballot.registered_voters.is_some()
        && ballot.registration_closed_at_height == Some(ballot.registration_close_height);
    let survivors_frozen = registration_frozen
        && ballot.dropout_root.is_some()
        && ballot.survivor_root.is_some()
        && ballot
            .survivors
            .is_some_and(|survivors| survivors >= MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
        && ballot.no_recovery_root.is_some()
        && ballot.survivors_frozen_at_height == Some(ballot.survivor_freeze_height);
    let corpus_frozen = survivors_frozen
        && ballot.corpus_root.is_some()
        && ballot
            .accepted_ballots
            .is_some_and(|accepted| accepted >= MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
        && ballot.timed_commitment_root.is_some()
        && timed_commitment_completed_in_window(ballot);

    match failure_kind {
        ParliamentBallotFailureKindV1::RegistrationDeadlineExpired => {
            failure_height > ballot.registration_close_height
                && ballot.registration_root.is_none()
                && ballot.registered_voters.is_none()
                && ballot.registration_closed_at_height.is_none()
                && ballot.dropout_root.is_none()
                && ballot.survivor_root.is_none()
                && ballot.survivors.is_none()
                && ballot.no_recovery_root.is_none()
                && ballot.survivors_frozen_at_height.is_none()
                && ballot.corpus_root.is_none()
                && ballot.accepted_ballots.is_none()
                && ballot.timed_commitment_root.is_none()
                && ballot.commitment_closed_at_height.is_none()
                && ballot.release_pulse_id.is_none()
                && ballot.opening_height.is_none()
        }
        ParliamentBallotFailureKindV1::SurvivorDeadlineExpired => {
            failure_height > ballot.survivor_freeze_height
                && registration_frozen
                && ballot.dropout_root.is_none()
                && ballot.survivor_root.is_none()
                && ballot.survivors.is_none()
                && ballot.no_recovery_root.is_none()
                && ballot.survivors_frozen_at_height.is_none()
                && ballot.corpus_root.is_none()
                && ballot.accepted_ballots.is_none()
                && ballot.timed_commitment_root.is_none()
                && ballot.commitment_closed_at_height.is_none()
                && ballot.release_pulse_id.is_none()
                && ballot.opening_height.is_none()
        }
        ParliamentBallotFailureKindV1::CommitmentDeadlineExpired => {
            failure_height > ballot.commitment_close_height
                && survivors_frozen
                && ballot.corpus_root.is_none()
                && ballot.accepted_ballots.is_none()
                && ballot.timed_commitment_root.is_none()
                && ballot.commitment_closed_at_height.is_none()
                && ballot.release_pulse_id.is_none()
                && ballot.opening_height.is_none()
        }
        ParliamentBallotFailureKindV1::ReleasePulseUnavailable => {
            corpus_frozen
                && ballot
                    .release_height
                    .is_some_and(|release_height| failure_height > release_height)
                && failure_height <= ballot.opening_deadline_height
                && ballot.release_pulse_id.is_none()
                && ballot.opening_height.is_none()
        }
        ParliamentBallotFailureKindV1::OpeningDeadlineExpired => {
            corpus_frozen
                && failure_height > ballot.opening_deadline_height
                && match (ballot.release_pulse_id, ballot.opening_height) {
                    (None, None) => true,
                    (Some(_), Some(opening_height)) => {
                        ballot
                            .release_height
                            .is_some_and(|release_height| opening_height >= release_height)
                            && opening_height <= ballot.opening_deadline_height
                    }
                    _ => false,
                }
        }
        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable
        | ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted => {
            let Some(opening_height) = ballot.opening_height else {
                return false;
            };
            let Some(tally) = ballot.tally else {
                return false;
            };
            body_role == ParliamentBody::PolicyJury
                && corpus_frozen
                && ballot.release_pulse_id.is_some()
                && ballot.opening_root.is_some()
                && ballot
                    .release_height
                    .is_some_and(|release_height| opening_height >= release_height)
                && opening_height <= ballot.opening_deadline_height
                && failure_height >= opening_height
                && failure_height <= ballot.opening_deadline_height
                && ballot
                    .eligible_confirmation_candidates
                    .is_some_and(|count| match failure_kind {
                        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable => {
                            count < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                        }
                        ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted => {
                            count >= MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
                        }
                        _ => unreachable!("matched post-opening failure kind"),
                    })
                && tally.original_seats == ballot.attempt.original_seats
                && Some(tally.accepted_ballots) == ballot.accepted_ballots
                && Some(tally.accepted_ballots) == ballot.survivors
                && tally.validate().is_ok()
                && tally.decision() == Ok(ParliamentAggregateOutcomeV1::Approved)
                && tally.requires_confirmation() == Ok(true)
                && ballot.outcome == Some(ParliamentAggregateOutcomeV1::Approved)
        }
    }
}

fn accepted_roster(
    election: &ParliamentElectionStateV1,
) -> Result<Vec<ParliamentSeatAssignmentV1>, ParliamentReducerErrorV1> {
    let target = usize::try_from(election.attempt.request.target_seats)
        .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
    let mut assignments: Vec<_> = election
        .primary_assignments
        .iter()
        .chain(&election.alternate_assignments)
        .filter(|assignment| {
            election
                .accepted_assignments
                .contains(&assignment.assignment_id)
        })
        .take(target)
        .cloned()
        .collect();
    assignments.sort_unstable_by_key(|assignment| assignment.assignment_id);
    Ok(assignments)
}

fn public_finding_quorum_is_unreachable(
    body: &ParliamentBodyStateV1,
) -> Result<bool, ParliamentReducerErrorV1> {
    let quorum = usize::try_from(parliament_quorum_seats_v1(body.instance.original_seats))
        .map_err(|_| ParliamentReducerErrorV1::InvalidRoster)?;
    let eligible = body
        .assignments
        .len()
        .checked_sub(body.excluded_assignments.len())
        .ok_or(ParliamentReducerErrorV1::InvalidRoster)?;
    let remaining = eligible
        .checked_sub(body.public_finding_endorsements.len())
        .ok_or(ParliamentReducerErrorV1::InvalidRoster)?;
    let mut endorsements_by_root = BTreeMap::<[u8; 32], usize>::new();
    for result_root in body.public_finding_endorsements.values() {
        *endorsements_by_root.entry(*result_root).or_default() += 1;
    }
    let strongest_existing_root = endorsements_by_root.values().copied().max().unwrap_or(0);
    Ok(strongest_existing_root.saturating_add(remaining) < quorum)
}

fn stage_for_body(body: ParliamentBody) -> GovernanceStageV1 {
    match body {
        ParliamentBody::RulesCommittee => GovernanceStageV1::Rules,
        ParliamentBody::AgendaCouncil => GovernanceStageV1::Agenda,
        ParliamentBody::InterestPanel => GovernanceStageV1::Interest,
        ParliamentBody::ReviewPanel => GovernanceStageV1::Review,
        ParliamentBody::CoordinationCouncil => GovernanceStageV1::Coordination,
        ParliamentBody::MpcCommittee => GovernanceStageV1::Mpc,
        ParliamentBody::FmaCommittee => GovernanceStageV1::Fma,
        ParliamentBody::OversightCommittee => GovernanceStageV1::Oversight,
        ParliamentBody::PolicyJury => GovernanceStageV1::PolicyJury,
        ParliamentBody::ConfirmationJury => GovernanceStageV1::ConfirmationJury,
    }
}

fn next_deliberation_phase(phase: DeliberationPhaseV1) -> Option<DeliberationPhaseV1> {
    match phase {
        DeliberationPhaseV1::Orientation => Some(DeliberationPhaseV1::Evidence),
        DeliberationPhaseV1::Evidence => Some(DeliberationPhaseV1::Questions),
        DeliberationPhaseV1::Questions => Some(DeliberationPhaseV1::Responses),
        DeliberationPhaseV1::Responses => Some(DeliberationPhaseV1::Deliberation),
        DeliberationPhaseV1::Deliberation => Some(DeliberationPhaseV1::Reflection),
        DeliberationPhaseV1::Reflection => Some(DeliberationPhaseV1::Vote),
        DeliberationPhaseV1::Vote => None,
    }
}

fn required_pipeline_is_canonical(required: &[RequiredParliamentBodyV1]) -> bool {
    if required.is_empty()
        || required.last().map(|entry| entry.body) != Some(ParliamentBody::PolicyJury)
    {
        return false;
    }
    let mut previous_stage = None;
    for entry in required {
        if entry.body == ParliamentBody::ConfirmationJury {
            return false;
        }
        let stage = stage_for_body(entry.body);
        if previous_stage.is_some_and(|previous| previous >= stage) {
            return false;
        }
        let expected_mode = if entry.body == ParliamentBody::PolicyJury {
            ParliamentDecisionModeV1::HiddenBindingBallot
        } else {
            ParliamentDecisionModeV1::PublicFinding
        };
        if entry.decision_mode != expected_mode {
            return false;
        }
        previous_stage = Some(stage);
    }
    true
}

fn persisted_pipeline_is_canonical(required: &[RequiredParliamentBodyV1]) -> bool {
    match required.last() {
        Some(RequiredParliamentBodyV1 {
            body: ParliamentBody::ConfirmationJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        }) => required_pipeline_is_canonical(&required[..required.len() - 1]),
        _ => required_pipeline_is_canonical(required),
    }
}

impl ParliamentAttemptStateV1 {
    /// Construct a reducer for one immutable governance attempt.
    ///
    /// The initial snapshot must be active at `Qualification`. The required
    /// bodies must be strictly ordered by the V1 pipeline, end in a private
    /// Policy Jury, and omit the dynamically required Confirmation Jury.
    ///
    /// `sortition_pulse_delay_blocks` (at least one) and
    /// `sortition_pulse_epoch_length_blocks` (the consensus-native `NPoS` epoch length, at
    /// least three) are frozen for the whole attempt: every sortition slot is the first
    /// native pulse height derived from them and the attempt's own generation history.
    ///
    /// # Errors
    /// Returns an error for zero immutable bindings, an unsupported policy
    /// version, an invalid sortition pulse schedule, a noninitial attempt, or a
    /// noncanonical required-body pipeline.
    pub fn try_new(
        attempt: GovernanceAttemptV1,
        policy_version: u64,
        sortition_pulse_delay_blocks: u64,
        sortition_pulse_epoch_length_blocks: u64,
        effect_preimage_hash: [u8; 32],
        expected_head: GovernanceExpectedHeadV1,
        required_bodies: Vec<RequiredParliamentBodyV1>,
    ) -> Result<Self, ParliamentReducerErrorV1> {
        Self::try_new_with_randomness_redraws_before_attempt(
            attempt,
            0,
            policy_version,
            sortition_pulse_delay_blocks,
            sortition_pulse_epoch_length_blocks,
            effect_preimage_hash,
            expected_head,
            required_bodies,
        )
    }

    /// Construct an attempt with the exact proposal-wide redraw prefix inherited
    /// from its terminal predecessor.
    ///
    /// Production attempt creation uses this constructor. Keeping the prefix in
    /// the persisted reducer state makes nested retry exhaustion deterministic
    /// across restart and prevents a successor governance attempt from resetting
    /// its proposal's randomness budget.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::try_new`], plus a redraw-limit error
    /// when the inherited prefix is already outside the V1 protocol bound.
    pub(crate) fn try_new_with_randomness_redraws_before_attempt(
        attempt: GovernanceAttemptV1,
        randomness_redraws_before_attempt: u32,
        policy_version: u64,
        sortition_pulse_delay_blocks: u64,
        sortition_pulse_epoch_length_blocks: u64,
        effect_preimage_hash: [u8; 32],
        expected_head: GovernanceExpectedHeadV1,
        required_bodies: Vec<RequiredParliamentBodyV1>,
    ) -> Result<Self, ParliamentReducerErrorV1> {
        if attempt.id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
                ParliamentReducerEntityV1::GovernanceAttempt,
            ));
        }
        if !attempt.has_canonical_id() {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if attempt.sequence > MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 {
            return Err(ParliamentReducerErrorV1::GovernanceAttemptRetryLimitExceeded);
        }
        if randomness_redraws_before_attempt > MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
            || (attempt.sequence > 0
                && randomness_redraws_before_attempt >= MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1)
        {
            return Err(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded);
        }
        if attempt
            .proposal_content_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || root_is_zero(&effect_preimage_hash)
            || !expected_head_is_valid(expected_head)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        if policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 {
            return Err(ParliamentReducerErrorV1::UnsupportedPolicyVersion);
        }
        if sortition_pulse_delay_blocks == 0
            || sortition_pulse_epoch_length_blocks
                < MIN_PARLIAMENT_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS_V1
        {
            return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
        }
        if attempt.status != GovernanceAttemptStatusV1::Active
            || attempt.stage != GovernanceStageV1::Qualification
        {
            return Err(ParliamentReducerErrorV1::AttemptNotActive);
        }
        if !required_pipeline_is_canonical(&required_bodies) {
            return Err(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline);
        }
        Ok(Self {
            attempt,
            randomness_redraws_before_attempt,
            policy_version,
            sortition_pulse_delay_blocks,
            sortition_pulse_epoch_length_blocks,
            effect_preimage_hash,
            expected_head,
            required_bodies,
            risk_locked: false,
            candidate_snapshots: Vec::new(),
            elections: BTreeMap::new(),
            active_elections: BTreeMap::new(),
            sortition_capacity_failures: BTreeMap::new(),
            active_sortition_capacity_failures: BTreeMap::new(),
            bodies: BTreeMap::new(),
            active_bodies: BTreeMap::new(),
            ballots: BTreeMap::new(),
            active_ballots: BTreeMap::new(),
            body_bindings: BTreeMap::new(),
            used_pulse_ids: BTreeMap::new(),
            used_pulse_slots: BTreeMap::new(),
            used_tle_sessions: BTreeMap::new(),
            certificate: None,
            terminal_height: None,
            superseding_head: None,
            execution_failure_root: None,
        })
    }

    /// Return the canonical governance-attempt snapshot.
    #[must_use]
    pub const fn attempt(&self) -> &GovernanceAttemptV1 {
        &self.attempt
    }

    fn sortition_generation_slots_v1(&self) -> BTreeSet<ParliamentPulseSlotV1> {
        self.elections
            .values()
            .map(|election| {
                ParliamentPulseSlotV1::new(
                    election.attempt.request.beacon_session_id,
                    election.attempt.request.pulse_height,
                )
            })
            .chain(self.sortition_capacity_failures.values().map(|failure| {
                ParliamentPulseSlotV1::new(failure.beacon_session_id, failure.pulse_height)
            }))
            .collect()
    }

    /// Return every sortition generation as `(slot, request_height)`: one entry per
    /// election and per capacity-failure record, exactly the records that
    /// [`Self::sortition_generation_slots_v1`] covers.
    fn sortition_generation_requests_v1(
        &self,
    ) -> impl Iterator<Item = (ParliamentPulseSlotV1, u64)> + '_ {
        self.elections
            .values()
            .map(|election| {
                let request = election.attempt.request;
                (
                    ParliamentPulseSlotV1::new(request.beacon_session_id, request.pulse_height),
                    request.request_height,
                )
            })
            .chain(self.sortition_capacity_failures.values().map(|failure| {
                (
                    ParliamentPulseSlotV1::new(failure.beacon_session_id, failure.pulse_height),
                    failure.request_height,
                )
            }))
    }

    /// Derive one generation slot from frozen attempt fields: the first consensus-native
    /// pulse height at or after both `request_height + sortition_pulse_delay_blocks` and
    /// the height after `previous_generation_height`.
    ///
    /// Returns `None` only when a `u64` addition overflows: both frozen fields were
    /// validated at construction.
    fn derived_sortition_generation_pulse_height_v1(
        &self,
        request_height: u64,
        previous_generation_height: Option<u64>,
    ) -> Option<u64> {
        let delayed = request_height.checked_add(self.sortition_pulse_delay_blocks)?;
        let earliest = match previous_generation_height {
            Some(previous) => delayed.max(previous.checked_add(1)?),
            None => delayed,
        };
        aligned_sortition_pulse_height_v1(earliest, self.sortition_pulse_epoch_length_blocks)
    }

    /// Return the pulse slot height of a NEW sortition generation registered at
    /// `request_height` on `beacon_session_id`.
    ///
    /// The slot is the first consensus-native pulse height (`(h + 1) % L == 0` for the
    /// frozen epoch length `L`) that is at least `request_height` plus the frozen delay and
    /// strictly above every slot an earlier generation of this attempt holds on that
    /// beacon session, whether that generation is an election or a capacity-failure
    /// record. A retry inside the epoch window of an unconsumed generation therefore
    /// targets the next boundary instead of colliding with it. The derivation reads only
    /// frozen attempt fields and the attempt's own generation history.
    ///
    /// Returns `None` only when a `u64` addition overflows.
    #[must_use]
    pub(crate) fn next_sortition_generation_pulse_height_v1(
        &self,
        request_height: u64,
        beacon_session_id: BeaconSessionId,
    ) -> Option<u64> {
        let previous = self
            .sortition_generation_requests_v1()
            .filter_map(|(slot, _)| {
                (slot.beacon_session_id == beacon_session_id).then_some(slot.height)
            })
            .max();
        self.derived_sortition_generation_pulse_height_v1(request_height, previous)
    }

    /// Check that `pulse_height` is the exact slot of the generation registered at
    /// `request_height`.
    ///
    /// One generation batch registers its requests one at a time, so the claimed slot may
    /// already hold the batch's earlier requests. Those must share `request_height`; every
    /// other generation slot of the beacon session must lie strictly below the claim, and
    /// the claim must equal the slot derived from them.
    fn ensure_sortition_generation_pulse_height_v1(
        &self,
        request_height: u64,
        pulse_height: u64,
        beacon_session_id: BeaconSessionId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let mut previous = None::<u64>;
        for (slot, generation_request_height) in self.sortition_generation_requests_v1() {
            if slot.beacon_session_id != beacon_session_id {
                continue;
            }
            match slot.height.cmp(&pulse_height) {
                core::cmp::Ordering::Less => {
                    previous = Some(previous.map_or(slot.height, |max| max.max(slot.height)));
                }
                core::cmp::Ordering::Equal if generation_request_height == request_height => {}
                core::cmp::Ordering::Equal | core::cmp::Ordering::Greater => {
                    return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
                }
            }
        }
        if self.derived_sortition_generation_pulse_height_v1(request_height, previous)
            != Some(pulse_height)
        {
            return Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);
        }
        Ok(())
    }

    /// Return every generation slot that persisted state cannot have reached.
    ///
    /// This is the exact recheck of the registration rule from frozen attempt fields only.
    /// Elections and capacity-failure records are grouped by slot; one group is one
    /// generation and shares one request height. With the groups of a beacon session in
    /// ascending slot order, each slot must equal the first consensus-native pulse height
    /// at or after `request_height + sortition_pulse_delay_blocks` and after the previous
    /// group's slot. Registration order is also rechecked: a retry of one body holds a
    /// strictly higher slot than every earlier sequence of that body on the same session.
    fn invalid_sortition_generation_slots_v1(&self) -> BTreeSet<ParliamentPulseSlotV1> {
        let mut generations = BTreeMap::<ParliamentPulseSlotV1, u64>::new();
        let mut invalid = BTreeSet::new();
        for (slot, request_height) in self.sortition_generation_requests_v1() {
            if *generations.entry(slot).or_insert(request_height) != request_height {
                invalid.insert(slot);
            }
        }
        let mut previous = None::<ParliamentPulseSlotV1>;
        for (slot, request_height) in &generations {
            let previous_height = previous
                .filter(|previous| previous.beacon_session_id == slot.beacon_session_id)
                .map(|previous| previous.height);
            if self.derived_sortition_generation_pulse_height_v1(*request_height, previous_height)
                != Some(slot.height)
            {
                invalid.insert(*slot);
            }
            previous = Some(*slot);
        }
        let sequence_slots: BTreeMap<(ParliamentBody, u32), ParliamentPulseSlotV1> = self
            .elections
            .values()
            .map(|election| {
                let request = election.attempt.request;
                (
                    (request.body, election.attempt.sequence),
                    ParliamentPulseSlotV1::new(request.beacon_session_id, request.pulse_height),
                )
            })
            .chain(self.sortition_capacity_failures.values().map(|failure| {
                (
                    (failure.body, failure.sequence),
                    ParliamentPulseSlotV1::new(failure.beacon_session_id, failure.pulse_height),
                )
            }))
            .collect();
        let mut previous = None::<(ParliamentBody, ParliamentPulseSlotV1)>;
        for ((body, _), slot) in &sequence_slots {
            if previous.is_some_and(|(previous_body, previous_slot)| {
                previous_body == *body
                    && previous_slot.beacon_session_id == slot.beacon_session_id
                    && previous_slot.height >= slot.height
            }) {
                invalid.insert(*slot);
            }
            previous = Some((*body, *slot));
        }
        invalid
    }

    /// Return the cumulative proposal-wide count of adversarially selectable
    /// randomness redraws after this attempt's current transcript.
    ///
    /// The first attempt's first simultaneous sortition slot is the baseline,
    /// not a redraw. Every later fresh sortition slot (including a successor
    /// attempt's first slot and a Confirmation Jury slot) and every ballot
    /// attempt after sequence zero consumes one unit. Reducer continuations and
    /// exact transport retransmissions create neither object and consume none.
    ///
    /// # Errors
    /// Returns an error if counting overflows or exceeds the V1 proposal-wide
    /// ceiling.
    pub(crate) fn randomness_redraws_used_v1(&self) -> Result<u32, ParliamentReducerErrorV1> {
        let sortition_generations = u32::try_from(self.sortition_generation_slots_v1().len())
            .map_err(|_| ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded)?;
        let baseline_generations =
            u32::from(self.attempt.sequence == 0 && sortition_generations > 0);
        let sortition_redraws = sortition_generations
            .checked_sub(baseline_generations)
            .ok_or(ParliamentReducerErrorV1::RandomnessRedrawLineageMismatch)?;
        let ballot_redraws = u32::try_from(
            self.ballots
                .values()
                .filter(|ballot| ballot.attempt.sequence > 0)
                .count(),
        )
        .map_err(|_| ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded)?;
        let used = self
            .randomness_redraws_before_attempt
            .checked_add(sortition_redraws)
            .and_then(|used| used.checked_add(ballot_redraws))
            .ok_or(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded)?;
        if used > MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 {
            return Err(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded);
        }
        Ok(used)
    }

    fn ensure_sortition_generation_redraw_available_v1(
        &self,
        beacon_session_id: BeaconSessionId,
        pulse_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let slot = ParliamentPulseSlotV1::new(beacon_session_id, pulse_height);
        let generations = self.sortition_generation_slots_v1();
        if generations.contains(&slot)
            || (self.attempt.sequence == 0 && generations.is_empty())
            || self.randomness_redraws_used_v1()? < MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
        {
            return Ok(());
        }
        Err(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded)
    }

    fn ensure_ballot_redraw_available_v1(
        &self,
        sequence: u32,
    ) -> Result<(), ParliamentReducerErrorV1> {
        if sequence == 0
            || self.randomness_redraws_used_v1()? < MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
        {
            return Ok(());
        }
        Err(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded)
    }

    /// Return the distinct accounts referenced by this attempt and the subset
    /// whose citizenship bonds it currently retains.
    ///
    /// Candidate snapshots are transient: they reference accounts only while
    /// the containing governance attempt remains active and their inner draw is
    /// still live. Sealed body assignments are immutable audit references for
    /// every later attempt status. Bond retention additionally ends once the
    /// attempt is neither active nor certified.
    #[must_use]
    pub(crate) fn parliament_member_reference_sets_v1(
        &self,
    ) -> (BTreeSet<AccountId>, BTreeSet<AccountId>) {
        let mut referenced = BTreeSet::new();
        if self.attempt.status == GovernanceAttemptStatusV1::Active {
            for election in self.elections.values().filter(|election| {
                matches!(
                    election.attempt.status,
                    BodyElectionAttemptStatusV1::AwaitingPulse
                        | BodyElectionAttemptStatusV1::Drawing
                        | BodyElectionAttemptStatusV1::AcceptingInvitations
                )
            }) {
                if let Ok(index) = usize::try_from(election.candidate_snapshot_index)
                    && let Some(snapshot) = self.candidate_snapshots.get(index)
                {
                    referenced.extend(snapshot.iter().cloned());
                }
            }
            for failure in self
                .active_sortition_capacity_failures
                .values()
                .filter_map(|id| self.sortition_capacity_failures.get(id))
                .filter(|failure| {
                    failure.status == BodyElectionAttemptStatusV1::NoRoster
                        && failure.sequence < MAX_PARLIAMENT_SORTITION_RETRIES_V1
                })
            {
                referenced.extend(failure.candidate_snapshot.iter().cloned());
            }
        }
        referenced.extend(self.bodies.values().flat_map(|body| {
            body.assignments()
                .iter()
                .map(|assignment| assignment.member.clone())
        }));
        let bond_retaining = matches!(
            self.attempt.status,
            GovernanceAttemptStatusV1::Active | GovernanceAttemptStatusV1::Certified
        )
        .then(|| referenced.clone())
        .unwrap_or_default();
        (referenced, bond_retaining)
    }

    /// Return whether this attempt references `member` through a currently
    /// live draw or an immutable sealed Parliament seat.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn references_parliament_member(&self, member: &AccountId) -> bool {
        self.parliament_member_reference_sets_v1()
            .0
            .contains(member)
    }

    /// Return whether an active attempt still retains `member`'s citizenship bond.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn retains_citizenship_bond(&self, member: &AccountId) -> bool {
        self.parliament_member_reference_sets_v1()
            .1
            .contains(member)
    }

    /// Return the immutable proposal content identifier.
    #[must_use]
    pub const fn proposal_content_id(&self) -> ProposalContentId {
        self.attempt.proposal_content_id
    }

    /// Return the policy version frozen for the attempt.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Return the minimum future-beacon delay frozen for every sortition request.
    #[must_use]
    pub const fn sortition_pulse_delay_blocks(&self) -> u64 {
        self.sortition_pulse_delay_blocks
    }

    /// Return the consensus-native `NPoS` epoch length frozen for every sortition slot.
    #[must_use]
    pub const fn sortition_pulse_epoch_length_blocks(&self) -> u64 {
        self.sortition_pulse_epoch_length_blocks
    }

    /// Return the ordered body requirements, including dynamic confirmation.
    #[must_use]
    pub fn required_bodies(&self) -> &[RequiredParliamentBodyV1] {
        &self.required_bodies
    }

    /// Admit the payloadless initial-sortition intent exactly once after qualification.
    ///
    /// A caller cannot use this intent to redraw a failed or already consumed
    /// generation. Explicit retries retain their ordinary predecessor, slot,
    /// eligibility and proposal-wide randomness-budget checks.
    pub(crate) fn ensure_initial_sortition_ready_v1(
        &self,
        governance_attempt_id: GovernanceAttemptId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let first = self
            .required_bodies
            .first()
            .ok_or(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline)?;
        self.ensure_stage(stage_for_body(first.body))?;
        if !self.elections.is_empty()
            || !self.sortition_capacity_failures.is_empty()
            || !self.used_pulse_ids.is_empty()
            || !self.used_pulse_slots.is_empty()
            || !self.bodies.is_empty()
            || !self.body_bindings.is_empty()
        {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyElection,
            ));
        }
        Ok(())
    }

    /// Validate immutable attempt bindings against their retained typed proposal.
    ///
    /// This check is required after persistence restore and again immediately
    /// before due execution. It accepts only upward risk escalation and the
    /// reducer-validated dynamic Confirmation Jury; all base proposal policy,
    /// effect, identity, and compare-and-set subject bindings remain exact.
    ///
    /// # Errors
    /// Returns an error when any proposal-derived binding was weakened or
    /// substituted.
    pub fn validate_proposal_bindings_v1(
        &self,
        proposal: &ProposalKind,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let expected_proposal_content_id = ProposalContentId::new(proposal.fingerprint());
        let expected_effect_preimage_hash = proposal.effect_preimage_hash_v1();
        let expected_subject = proposal
            .governed_subject_id_v1()
            .map_err(|_| ParliamentReducerErrorV1::ProposalBindingMismatch)?;
        let observed_subject = match self.expected_head {
            GovernanceExpectedHeadV1::Absent(head) => head.subject_id,
            GovernanceExpectedHeadV1::Present(head) => head.subject_id,
        };
        let (base_risk_tier, base_required_bodies) = parliament_attempt_policy_v1(proposal);
        let persisted_base =
            self.required_bodies
                .last()
                .map_or(self.required_bodies.as_slice(), |last| {
                    if last.body == ParliamentBody::ConfirmationJury {
                        &self.required_bodies[..self.required_bodies.len() - 1]
                    } else {
                        self.required_bodies.as_slice()
                    }
                });

        if self.attempt.proposal_content_id != expected_proposal_content_id
            || self.policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1
            || self.effect_preimage_hash != expected_effect_preimage_hash
            || observed_subject != expected_subject
            || !base_risk_tier.can_escalate_to(self.attempt.risk_tier)
            || persisted_base != base_required_bodies
        {
            return Err(ParliamentReducerErrorV1::ProposalBindingMismatch);
        }
        Ok(())
    }

    /// Return a registered body-election attempt.
    #[must_use]
    pub fn election(&self, id: &BodyElectionAttemptId) -> Option<&ParliamentElectionStateV1> {
        self.elections.get(id)
    }

    /// Return typed pre-request evidence for an undersized hidden electorate.
    #[must_use]
    pub fn sortition_capacity_failure(
        &self,
        id: &BodyElectionAttemptId,
    ) -> Option<&ParliamentSortitionCapacityFailureV1> {
        self.sortition_capacity_failures.get(id)
    }

    /// Return a sealed body instance.
    #[must_use]
    pub fn body(&self, id: &BodyInstanceId) -> Option<&ParliamentBodyStateV1> {
        self.bodies.get(id)
    }

    /// Return the active sealed body instance for an exact Parliament role.
    ///
    /// This is used to derive the disjoint Confirmation Jury candidate set
    /// from the immutable Policy Jury roster without exposing mutable maps.
    #[must_use]
    pub fn sealed_body_for_role(&self, body: ParliamentBody) -> Option<&ParliamentBodyStateV1> {
        self.active_bodies
            .get(&body)
            .and_then(|body_instance_id| self.bodies.get(body_instance_id))
    }

    /// Return a private ballot attempt.
    #[must_use]
    pub fn ballot(&self, id: &BallotAttemptId) -> Option<&ParliamentBallotStateV1> {
        self.ballots.get(id)
    }

    /// Return the complete immutable reducer projection that must agree with
    /// replayed timed-OVN lifecycle evidence during snapshot restoration.
    #[must_use]
    pub(crate) fn timed_ovn_reducer_binding(
        &self,
        id: &BallotAttemptId,
    ) -> Option<TimedOvnParliamentReducerBindingV1> {
        let ballot = self.ballots.get(id)?;
        Some(TimedOvnParliamentReducerBindingV1 {
            proposal_content_id: *self.attempt.proposal_content_id.as_bytes(),
            governance_attempt_id: *self.attempt.id.as_bytes(),
            body_instance_id: *ballot.attempt.body_instance_id.as_bytes(),
            ballot_attempt_id: *ballot.attempt.id.as_bytes(),
            tle_key_session_id: ballot.tle_key_session_id,
            registration_opened_at_finalized_height: ballot
                .corpus_root
                .is_none()
                .then_some(ballot.registered_at_height),
            release_height: ballot.release_height,
            registration_root: ballot.registration_root,
            registered_voters: ballot.registered_voters,
            dropout_root: ballot.dropout_root,
            survivor_root: ballot.survivor_root,
            survivors: ballot.survivors,
            no_recovery_root: ballot.no_recovery_root,
            corpus_root: ballot.corpus_root,
            accepted_ballots: ballot.accepted_ballots,
            timed_commitment_root: ballot.timed_commitment_root,
            opening_root: ballot.opening_root,
            tally_counts: ballot
                .tally
                .map(|tally| [tally.aye, tally.nay, tally.abstain]),
        })
    }

    /// Return whether replayed timed-OVN evidence matches every reducer-owned
    /// field that the lifecycle duplicates.
    #[must_use]
    pub(crate) fn timed_ovn_reducer_binding_matches(
        &self,
        id: &BallotAttemptId,
        replayed: &TimedOvnParliamentReducerBindingV1,
    ) -> bool {
        self.timed_ovn_reducer_binding(id).as_ref() == Some(replayed)
    }

    /// Return the latest private ballot attempt bound to one exact body instance.
    ///
    /// The returned state exposes only bounded lifecycle getters. Timed-OVN
    /// registrations, masked ballot records, shares, and individual openings
    /// remain outside this reducer projection.
    #[must_use]
    pub fn active_ballot_for_body(
        &self,
        body_instance_id: &BodyInstanceId,
    ) -> Option<&ParliamentBallotStateV1> {
        self.active_ballots
            .get(body_instance_id)
            .and_then(|ballot_attempt_id| self.ballots.get(ballot_attempt_id))
    }

    /// Validate one seated authority's timed-OVN registration window.
    ///
    /// # Errors
    /// Returns an error unless the exact ballot is in registration, the
    /// containing height precedes the immutable close boundary, and `member`
    /// owns a nonexcluded seat in the bound body instance.
    pub(crate) fn validate_ballot_registration_member(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        member: &AccountId,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.validate_ballot_member_action(
            governance_attempt_id,
            ballot_attempt_id,
            member,
            current_height,
            BallotAttemptStatusV1::Registration,
        )
    }

    /// Validate one registered authority's pre-freeze dropout window.
    ///
    /// # Errors
    /// Returns an error unless registration is closed, the immutable survivor
    /// boundary has not arrived, and `member` owns a nonexcluded seat in the
    /// exact body instance. Cryptographic lifecycle validation separately
    /// requires that this member registered and has not already withdrawn.
    pub(crate) fn validate_ballot_dropout_member(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        member: &AccountId,
        current_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.validate_ballot_member_action(
            governance_attempt_id,
            ballot_attempt_id,
            member,
            current_height,
            BallotAttemptStatusV1::SurvivorFreeze,
        )
    }

    fn validate_ballot_member_action(
        &self,
        governance_attempt_id: GovernanceAttemptId,
        ballot_attempt_id: BallotAttemptId,
        member: &AccountId,
        current_height: u64,
        expected_status: BallotAttemptStatusV1,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        let ballot =
            self.ballots
                .get(&ballot_attempt_id)
                .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                    ParliamentReducerEntityV1::BallotAttempt,
                ))?;
        if ballot.attempt.status != expected_status {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BallotAttempt,
            ));
        }
        let inside_window = match expected_status {
            BallotAttemptStatusV1::Registration => {
                current_height >= ballot.registered_at_height
                    && current_height < ballot.registration_close_height
            }
            BallotAttemptStatusV1::SurvivorFreeze => {
                current_height >= ballot.registration_close_height
                    && current_height < ballot.survivor_freeze_height
            }
            _ => false,
        };
        if !inside_window {
            return Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight);
        }
        let body = self.bodies.get(&ballot.attempt.body_instance_id).ok_or(
            ParliamentReducerErrorV1::UnknownEntity(ParliamentReducerEntityV1::BodyInstance),
        )?;
        if body.instance.governance_attempt_id != governance_attempt_id
            || self.active_ballots.get(&body.instance.id) != Some(&ballot_attempt_id)
        {
            return Err(ParliamentReducerErrorV1::ImmutableBindingMismatch);
        }
        let assignment = body
            .assignments
            .iter()
            .find(|assignment| &assignment.member == member)
            .ok_or(ParliamentReducerErrorV1::UnauthorizedBallotParticipant)?;
        if body
            .excluded_assignments
            .contains(&assignment.assignment_id)
        {
            return Err(ParliamentReducerErrorV1::UnauthorizedBallotParticipant);
        }
        Ok(())
    }

    /// Iterate every canonical ballot-attempt entry for persistence validation.
    pub(crate) fn ballot_attempts(
        &self,
    ) -> impl ExactSizeIterator<Item = (&BallotAttemptId, &ParliamentBallotStateV1)> {
        self.ballots.iter()
    }

    /// Return this attempt's maximum committed opening deadline per TLE key session.
    ///
    /// Historical retries remain included: a share is retained through every
    /// deadline ever committed for this attempt, even when a later retry
    /// superseded the corresponding ballot. World state folds these bounded,
    /// deterministic contributions into its snapshot-skipped retention index.
    #[must_use]
    pub(crate) fn tle_key_session_retention_contributions_v1(
        &self,
    ) -> BTreeMap<TleKeySessionId, u64> {
        let mut contributions = BTreeMap::<TleKeySessionId, u64>::new();
        for ballot in self.ballots.values() {
            let Some(key_session_id) = ballot.tle_key_session_id else {
                continue;
            };
            contributions
                .entry(key_session_id)
                .and_modify(|deadline| {
                    *deadline = (*deadline).max(ballot.opening_deadline_height);
                })
                .or_insert(ballot.opening_deadline_height);
        }
        contributions
    }

    /// Return whether a live reducer object awaits the exact beacon slot.
    ///
    /// A sortition request awaits the pulse of its frozen slot for as long as it
    /// takes: nothing else moves it out of `AwaitingPulse`. A timed ballot awaits
    /// its frozen release slot from registration until it consumes the pulse or
    /// becomes terminal. Neither wait creates a consensus obligation.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn requires_beacon_pulse_at(
        &self,
        beacon_session_id: BeaconSessionId,
        height: u64,
    ) -> bool {
        if self.attempt.status != GovernanceAttemptStatusV1::Active {
            return false;
        }
        self.elections.values().any(|election| {
            election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse
                && election.attempt.request.beacon_session_id == beacon_session_id
                && election.attempt.request.pulse_height == height
        }) || self.ballots.values().any(|ballot| {
            matches!(
                ballot.attempt.status,
                BallotAttemptStatusV1::Registration
                    | BallotAttemptStatusV1::SurvivorFreeze
                    | BallotAttemptStatusV1::TimedCommitment
                    | BallotAttemptStatusV1::AwaitingRelease
            ) && ballot.release_beacon_session_id == Some(beacon_session_id)
                && ballot.release_height == Some(height)
                && ballot.release_pulse_id.is_none()
        })
    }

    /// Return every beacon slot a live object of this attempt awaits.
    ///
    /// Sortition `AwaitingPulse` slots plus timed-OVN release slots. The
    /// deduplicated set maintains the governance-local World read index
    /// `parliament_required_beacon_pulse_slots`. It creates no consensus
    /// obligation: a slot without a native pulse simply stays awaited
    /// (sortition) or ends `ReleasePulseUnavailable` (timed-OVN ballot).
    /// TODO: rename and re-scope with the governance due-item iterator when
    /// timed-OVN is retired (specs/parliament_private_ballot_design.md 12.2 step 4).
    #[must_use]
    pub(crate) fn required_beacon_pulse_slots_v1(&self) -> BTreeSet<(BeaconSessionId, u64)> {
        if self.attempt.status != GovernanceAttemptStatusV1::Active {
            return BTreeSet::new();
        }
        self.elections
            .values()
            .filter_map(|election| {
                (election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse).then_some((
                    election.attempt.request.beacon_session_id,
                    election.attempt.request.pulse_height,
                ))
            })
            .chain(self.ballots.values().filter_map(|ballot| {
                if !matches!(
                    ballot.attempt.status,
                    BallotAttemptStatusV1::Registration
                        | BallotAttemptStatusV1::SurvivorFreeze
                        | BallotAttemptStatusV1::TimedCommitment
                        | BallotAttemptStatusV1::AwaitingRelease
                ) || ballot.release_pulse_id.is_some()
                {
                    return None;
                }
                Some((ballot.release_beacon_session_id?, ballot.release_height?))
            }))
            .collect()
    }

    /// Return every timed-OVN release slot a ballot terminally classified as absent.
    ///
    /// Only the timed-OVN ballot path classifies a slot: it ends
    /// `ReleasePulseUnavailable` through its governance-local path when no native
    /// pulse sits at exactly `release_height`. A sortition election has no such
    /// classification; it waits for the pulse of its exact frozen slot. The set
    /// feeds one governance-internal integrity check on the attempt write and
    /// never constrains a consensus pulse.
    /// TODO: delete with the timed-OVN ballot path
    /// (specs/parliament_private_ballot_design.md 12.2 step 4).
    #[must_use]
    pub(crate) fn unavailable_release_pulse_slots_v1(&self) -> BTreeSet<(BeaconSessionId, u64)> {
        self.ballots
            .values()
            .filter_map(|ballot| {
                if ballot.failure_kind
                    != Some(ParliamentBallotFailureKindV1::ReleasePulseUnavailable)
                {
                    return None;
                }
                Some((ballot.release_beacon_session_id?, ballot.release_height?))
            })
            .collect()
    }

    /// Return whether a timed-OVN ballot terminally classified an exact release slot as absent.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn classifies_release_pulse_unavailable_at(
        &self,
        beacon_session_id: BeaconSessionId,
        height: u64,
    ) -> bool {
        self.ballots.values().any(|ballot| {
            ballot.failure_kind == Some(ParliamentBallotFailureKindV1::ReleasePulseUnavailable)
                && ballot.release_beacon_session_id == Some(beacon_session_id)
                && ballot.release_height == Some(height)
        })
    }

    /// Return the constructed certificate after certification.
    #[must_use]
    pub const fn certificate(&self) -> Option<&GovernanceCertificateV1> {
        self.certificate.as_ref()
    }

    /// Return the exact scheduled height while this attempt awaits enactment.
    #[must_use]
    pub(crate) fn certified_enactment_height_v1(&self) -> Option<u64> {
        if !matches!(self.attempt.status, GovernanceAttemptStatusV1::Certified) {
            return None;
        }
        self.certificate
            .as_ref()
            .map(|certificate| certificate.enact_at_height)
    }

    /// Return the original compare-and-set head frozen into this attempt.
    #[must_use]
    pub(crate) const fn expected_head(&self) -> GovernanceExpectedHeadV1 {
        self.expected_head
    }

    /// Return the committed height of a terminal enactment outcome.
    #[must_use]
    pub const fn terminal_height(&self) -> Option<u64> {
        self.terminal_height
    }

    /// Return the observed compare-and-set head that superseded this certificate.
    #[must_use]
    pub const fn superseding_head(&self) -> Option<GovernanceExpectedHeadV1> {
        self.superseding_head
    }

    /// Return the deterministic execution-failure transcript root, when present.
    #[must_use]
    pub const fn execution_failure_root(&self) -> Option<[u8; 32]> {
        self.execution_failure_root
    }

    /// Validate all realized lifecycle chronology against a restored committed height.
    ///
    /// A still-certified effect must remain strictly future. Conversely, a
    /// terminal execution outcome and the certificate that authorized it may
    /// not claim heights beyond the restored ledger boundary. Persisted
    /// elections, bodies, ballots, and consumed pulses likewise cannot record
    /// actions from future blocks, and the atomic pre-certificate transient is
    /// never a valid restart state.
    ///
    /// # Errors
    /// Returns an error when persisted lifecycle chronology is impossible at
    /// `restored_height`.
    pub(crate) fn validate_restored_height_v1(
        &self,
        restored_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let missing_certificate_at_persisted_stage = self.certificate.is_none()
            && matches!(
                self.attempt.stage,
                GovernanceStageV1::Certification | GovernanceStageV1::Enactment
            );
        if let Some(certificate) = self.certificate.as_ref() {
            if certificate.certified_at_height > restored_height {
                return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
            }
            match self.attempt.status {
                GovernanceAttemptStatusV1::Certified
                    if certificate.enact_at_height <= restored_height =>
                {
                    return Err(ParliamentReducerErrorV1::WrongEnactmentHeight);
                }
                GovernanceAttemptStatusV1::Enacted
                | GovernanceAttemptStatusV1::Superseded
                | GovernanceAttemptStatusV1::ExecutionFailed
                    if certificate.enact_at_height > restored_height =>
                {
                    return Err(ParliamentReducerErrorV1::InvalidCertificateHeight);
                }
                _ => {}
            }
        }

        let future_election_height = self.elections.values().any(|election| {
            let request = election.attempt.request;
            let terminal_outcome_is_future = matches!(
                election.attempt.status,
                BodyElectionAttemptStatusV1::Sealed
                    | BodyElectionAttemptStatusV1::NoRoster
                    | BodyElectionAttemptStatusV1::Superseded
            ) && election
                .invitation_close_height
                .is_some_and(|height| height >= restored_height);
            request.request_height > restored_height
                || (election.pulse_id.is_some() && request.pulse_height > restored_height)
                || election
                    .invitation_opened_at_height
                    .is_some_and(|height| height > restored_height)
                || election
                    .failure_height
                    .is_some_and(|height| height > restored_height)
                || terminal_outcome_is_future
        });
        let future_sortition_capacity_failure =
            self.sortition_capacity_failures.values().any(|failure| {
                failure.request_height > restored_height || failure.failure_height > restored_height
            });
        let future_body_height = self.bodies.values().any(|body| {
            body.result_height
                .is_some_and(|height| height > restored_height)
                || body
                    .public_finding_opened_at_height
                    .is_some_and(|height| height > restored_height)
                || body
                    .public_finding_no_result_height
                    .is_some_and(|height| height > restored_height)
        });
        let future_ballot_height = self.ballots.values().any(|ballot| {
            ballot.registered_at_height > restored_height
                || ballot
                    .registration_closed_at_height
                    .is_some_and(|height| height > restored_height)
                || ballot
                    .survivors_frozen_at_height
                    .is_some_and(|height| height > restored_height)
                || ballot
                    .commitment_closed_at_height
                    .is_some_and(|height| height > restored_height)
                || ballot
                    .opening_height
                    .is_some_and(|height| height > restored_height)
                || ballot
                    .failure_height
                    .is_some_and(|height| height > restored_height)
        });
        let future_consumed_pulse = self
            .used_pulse_slots
            .keys()
            .any(|slot| slot.height > restored_height);
        if future_election_height
            || future_sortition_capacity_failure
            || future_body_height
            || future_ballot_height
            || future_consumed_pulse
        {
            return Err(ParliamentReducerErrorV1::FuturePersistedHeight);
        }
        if missing_certificate_at_persisted_stage {
            return Err(ParliamentReducerErrorV1::IncompleteCertificate);
        }
        Ok(())
    }

    fn ensure_attempt(
        &self,
        governance_attempt_id: GovernanceAttemptId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        if governance_attempt_id != self.attempt.id {
            return Err(ParliamentReducerErrorV1::AttemptBindingMismatch);
        }
        Ok(())
    }

    fn ensure_active(
        &self,
        governance_attempt_id: GovernanceAttemptId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_attempt(governance_attempt_id)?;
        if self.attempt.status != GovernanceAttemptStatusV1::Active {
            return Err(ParliamentReducerErrorV1::AttemptNotActive);
        }
        Ok(())
    }

    fn ensure_stage(&self, expected: GovernanceStageV1) -> Result<(), ParliamentReducerErrorV1> {
        if self.attempt.stage != expected {
            return Err(ParliamentReducerErrorV1::WrongGovernanceStage {
                expected,
                actual: self.attempt.stage,
            });
        }
        Ok(())
    }

    fn requirement_for_body(
        &self,
        body: ParliamentBody,
    ) -> Result<RequiredParliamentBodyV1, ParliamentReducerErrorV1> {
        self.required_bodies
            .iter()
            .copied()
            .find(|entry| entry.body == body)
            .ok_or(ParliamentReducerErrorV1::WrongParliamentBody)
    }

    fn ensure_current_body(
        &self,
        body: ParliamentBody,
    ) -> Result<RequiredParliamentBodyV1, ParliamentReducerErrorV1> {
        let requirement = self.requirement_for_body(body)?;
        self.ensure_stage(stage_for_body(body))?;
        Ok(requirement)
    }

    fn ensure_draw_eligible_body(
        &self,
        body: ParliamentBody,
    ) -> Result<RequiredParliamentBodyV1, ParliamentReducerErrorV1> {
        let requirement = self.requirement_for_body(body)?;
        let body_stage = stage_for_body(body);
        if self.attempt.stage != GovernanceStageV1::Qualification && self.attempt.stage > body_stage
        {
            return Err(ParliamentReducerErrorV1::WrongGovernanceStage {
                expected: body_stage,
                actual: self.attempt.stage,
            });
        }
        if self.body_bindings.contains_key(&body) {
            return Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance,
            ));
        }
        Ok(requirement)
    }

    fn advance_after_body(&mut self, body: ParliamentBody) -> Result<(), ParliamentReducerErrorV1> {
        let index = self
            .required_bodies
            .iter()
            .position(|entry| entry.body == body)
            .ok_or(ParliamentReducerErrorV1::WrongParliamentBody)?;
        self.attempt.stage = self
            .required_bodies
            .get(index + 1)
            .map_or(GovernanceStageV1::Certification, |next| {
                stage_for_body(next.body)
            });
        Ok(())
    }

    /// Escalate the risk tier before Policy Jury sortition locks it.
    ///
    /// # Errors
    /// Returns an error for a downgrade, replay, terminal attempt, or escalation
    /// after the first Policy Jury request.
    pub fn escalate_risk(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
        target: RiskTierV1,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        if self.risk_locked {
            return Err(ParliamentReducerErrorV1::RiskTierLocked);
        }
        if target == self.attempt.risk_tier {
            return Err(ParliamentReducerErrorV1::RiskEscalationReplay);
        }
        if !self.attempt.risk_tier.can_escalate_to(target) {
            return Err(ParliamentReducerErrorV1::RiskDowngrade);
        }
        self.attempt.risk_tier = target;
        Ok(())
    }

    /// Finish qualification and enter the first policy-required body stage.
    ///
    /// # Errors
    /// Returns an error for a wrong attempt, replay, terminal state, or skipped stage.
    pub fn complete_qualification(
        &mut self,
        governance_attempt_id: GovernanceAttemptId,
    ) -> Result<(), ParliamentReducerErrorV1> {
        self.ensure_active(governance_attempt_id)?;
        self.ensure_stage(GovernanceStageV1::Qualification)?;
        let first = self
            .required_bodies
            .first()
            .ok_or(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline)?;
        self.attempt.stage = stage_for_body(first.body);
        Ok(())
    }
}

/// Validate the cumulative randomness-redraw prefix across one proposal's
/// complete, sequence-ordered attempt history.
///
/// # Errors
/// Returns an error when attempt sequences are not exactly contiguous from
/// zero, a successor does not inherit its predecessor's exact terminal count,
/// proposals are mixed, or any attempt exceeds the V1 cumulative ceiling.
pub fn validate_parliament_randomness_redraw_lineage_v1<I, A>(
    attempts: I,
) -> Result<(), ParliamentReducerErrorV1>
where
    I: IntoIterator<Item = A>,
    A: core::borrow::Borrow<ParliamentAttemptStateV1>,
{
    let mut attempts = attempts.into_iter().collect::<Vec<_>>();
    attempts.sort_unstable_by_key(|attempt| attempt.borrow().attempt.sequence);
    let Some(first) = attempts.first() else {
        return Ok(());
    };
    let first = first.borrow();
    let proposal_content_id = first.proposal_content_id();
    let mut expected_prefix = 0;
    let mut expected_sequence = 0;
    for attempt in attempts {
        let attempt = attempt.borrow();
        if attempt.proposal_content_id() != proposal_content_id
            || attempt.randomness_redraws_before_attempt != expected_prefix
        {
            return Err(ParliamentReducerErrorV1::RandomnessRedrawLineageMismatch);
        }
        if attempt.attempt.sequence != expected_sequence {
            return Err(ParliamentReducerErrorV1::RetrySequenceMismatch);
        }
        if attempt.attempt.sequence > 0
            && attempt.randomness_redraws_before_attempt >= MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
        {
            return Err(ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded);
        }
        expected_prefix = attempt.randomness_redraws_used_v1()?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ParliamentReducerErrorV1::RetrySequenceMismatch)?;
    }
    Ok(())
}

include!("parliament/reducer_sortition.rs");
include!("parliament/reducer_deliberation.rs");
include!("parliament/reducer_ballot.rs");
include!("parliament/reducer_validation.rs");
include!("parliament/fixture_helpers.rs");

#[path = "parliament/planner.rs"]
mod planner;
pub use planner::{
    ParliamentDriverPlanV1, ParliamentExactTransitionV1, ParliamentPlanWorldV1, WorldPlanInputsV1,
    plan_parliament_attempt_v1,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use iroha_crypto::{
        Algorithm, Hash, HashOf, KeyPair,
        threshold_bls::{
            AdaptiveThresholdBlsParameters, AdaptiveThresholdBlsSecretShare, DasRenDealerSecret,
            ThresholdBlsSession, TleReleasePurpose,
        },
        timed_ovn::{TimedOvnChoiceV1, TimedOvnRegistrationSecretV1},
    };
    use iroha_data_model::{
        asset::AssetDefinitionId,
        block::BlockHeader,
        governance::types::{
            AbiVersion, ContractAbiHash, ContractCodeHash, ContractEmergencyHoldProposalV1,
            DeployContractProposal, GovernanceExpectedHeadAbsentV1,
            ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
            parliament_ballot_participant_hash_v1,
        },
        validation_fee::{
            VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            ValidationFeeChargingMode, ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1,
            initial_validation_fee_amount,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        governance::timed_ovn::{
            TimedOvnLifecyclePhaseV1, TimedOvnLifecycleStateV1, TimedOvnSessionPublicV1,
            timed_ovn_parameter_hash_v1,
        },
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
        tle_release::{
            ParliamentTimedOvnCastingPhaseV1, TimedOvnCastingAuthorizationErrorV1,
            TleKeySessionLifecycleV1, TleKeySessionPublicStateV1, ValidatedTleKeySessionV1,
            authorize_parliament_timed_ovn_casting_context_v1,
            derive_parliament_timed_ovn_casting_snapshot_v1,
        },
    };

    #[test]
    fn canonical_governance_attempt_id_keyspace_is_exact_and_bounded() {
        let proposal_content_id = ProposalContentId::new([0xA7; 32]);
        let ids = canonical_governance_attempt_ids_v1(proposal_content_id).collect::<Vec<_>>();
        assert_eq!(
            ids.len(),
            usize::try_from(MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1)
                .expect("the V1 retry ceiling fits usize")
                + 1
        );
        for (sequence, id) in ids.iter().enumerate() {
            let sequence = u32::try_from(sequence).expect("the bounded sequence fits u32");
            assert_eq!(
                *id,
                GovernanceAttemptId::derive_v1(proposal_content_id, sequence)
            );
        }
    }

    include!("parliament/tests/fixtures.rs");
    include!("parliament/tests/sortition.rs");
    include!("parliament/tests/sortition_slot.rs");
    include!("parliament/tests/ballot.rs");
    include!("parliament/tests/certificate.rs");
    include!("parliament/tests/planner.rs");
}
