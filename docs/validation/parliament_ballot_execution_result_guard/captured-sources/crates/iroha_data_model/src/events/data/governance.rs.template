//! Governance lifecycle events for the data event stream.
pub use self::model::*;
use super::*;
use iroha_data_model_derive::model;
#[model]
mod model {
    use super::*;
    use crate::{
        governance::types::{
            GovernanceAttemptId, GovernanceCertificateId, GovernanceExpectedHeadV1,
            ParliamentNoResultKindV1, ProposalContentId, RiskTierV1,
        },
        isi::governance::{
            ParliamentAutomaticExecutionOutcomeV1, ParliamentLifecycleTransitionKindV1,
        },
    };
    use iroha_primitives::numeric::Quantity;
    /// Governance lifecycle events.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        iroha_data_model_derive::EventSet,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
    )]
    #[event_set(
        schema_name = "iroha_data_model::events::data::governance::model::GovernanceEventSet"
    )]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::events::data::governance::model::GovernanceEvent")]
    pub enum GovernanceEvent {
        /// A governance proposal was submitted.
        ProposalSubmitted(GovernanceProposalSubmitted),
        /// A typed governance proposal was rejected by Parliament.
        ProposalRejected(GovernanceProposalRejected),
        /// A governance token lock was created for a referendum.
        LockCreated(GovernanceLockCreated),
        /// A governance token lock was extended (expiry increased and/or amount increased) for a referendum.
        LockExtended(GovernanceLockExtended),
        /// A governance proposal was enacted.
        ProposalEnacted(GovernanceProposalEnacted),
        /// A ballot was accepted for a referendum (mode-specific fields may be hidden).
        BallotAccepted(GovernanceBallotAccepted),
        /// A ballot was rejected for a referendum (non-consensus; best-effort)
        BallotRejected(GovernanceBallotRejected),
        /// A referendum was opened for voting (status becomes Open).
        ReferendumOpened(GovernanceReferendumOpened),
        /// A standalone referendum voting window was closed.
        ReferendumClosed(GovernanceReferendumClosed),
        /// A governance lock expired and was unlocked.
        LockUnlocked(GovernanceLockUnlocked),
        /// A canonical attempt was created from immutable proposal content.
        ParliamentAttemptCreated(GovernanceParliamentAttemptCreated),
        /// One typed reducer transition was accepted and applied.
        ParliamentLifecycleTransitionApplied(GovernanceParliamentLifecycleTransitionApplied),
        /// A current-roster QC installed, rotated, or retired a threshold key session.
        ThresholdKeyLifecycleApplied(GovernanceThresholdKeyLifecycleAppliedV1),
        /// A governance lock was slashed (partial or full) for a referendum.
        LockSlashed(GovernanceLockSlashed),
        /// A governance lock received restitution after appeal.
        LockRestituted(GovernanceLockRestituted),
        /// A citizenship bond was registered.
        CitizenRegistered(GovernanceCitizenRegistered),
        /// A citizenship bond was withdrawn and the citizen was removed.
        CitizenRevoked(GovernanceCitizenRevoked),
        /// A standalone governance referendum reached an exact final decision.
        ReferendumDecided(GovernanceReferendumDecided),
    }

    /// Public audit record for one QC-authorized threshold-key lifecycle action.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceThresholdKeyLifecycleAppliedV1"
    )]
    pub struct GovernanceThresholdKeyLifecycleAppliedV1 {
        /// Exact lifecycle action authenticated by the current validator roster.
        pub action: crate::isi::consensus_keys::ThresholdKeyLifecycleActionV1,
        /// Exact threshold-key session identifier.
        pub session_id: [u8; 32],
        /// Exact finalized DKG transcript commitment.
        pub transcript_hash: [u8; 32],
        /// Committed height at which the lifecycle action took effect.
        pub effective_height: u64,
    }
    /// Proposal submitted payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceProposalSubmitted"
    )]
    pub struct GovernanceProposalSubmitted {
        /// Deterministic proposal id (blake2b‑32 of content fields)
        pub id: [u8; 32],
        /// Proposer account id
        pub proposer: crate::account::AccountId,
        /// Canonical public contract address targeted by the proposal when applicable.
        pub contract_address: Option<crate::smart_contract::ContractAddress>,
    }
    /// Lock created payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceLockCreated"
    )]
    pub struct GovernanceLockCreated {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voter account id
        pub owner: crate::account::AccountId,
        /// Locked amount
        pub amount: Quantity,
        /// Expiry height (inclusive)
        pub expiry_height: u64,
    }
    /// Lock extended payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceLockExtended"
    )]
    pub struct GovernanceLockExtended {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voter account id
        pub owner: crate::account::AccountId,
        /// New locked amount (after extension)
        pub amount: Quantity,
        /// New expiry height (inclusive)
        pub expiry_height: u64,
    }
    /// Proposal enacted payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceProposalEnacted"
    )]
    pub struct GovernanceProposalEnacted {
        /// Deterministic proposal id
        pub id: [u8; 32],
    }
    /// Proposal rejected payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceProposalRejected"
    )]
    pub struct GovernanceProposalRejected {
        /// Deterministic proposal id
        pub id: [u8; 32],
    }
    /// Ballot mode (ZK or Plain)
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceBallotMode"
    )]
    pub enum GovernanceBallotMode {
        /// Zero-knowledge ballot (direction and owner hidden)
        #[default]
        Zk,
        /// Transparent, quadratic-weighted ballot
        Plain,
    }
    /// Ballot accepted payload
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceBallotAccepted"
    )]
    pub struct GovernanceBallotAccepted {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voting mode (ZK/Plain)
        pub mode: GovernanceBallotMode,
        /// Optional weight when available (e.g., Plain mode); None for ZK ballots.
        pub weight: Option<u128>,
    }
    /// Ballot rejected payload
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceBallotRejected"
    )]
    pub struct GovernanceBallotRejected {
        /// Referendum identifier
        pub referendum_id: String,
        /// Free-form reason (stable messages preferred)
        pub reason: String,
    }
    /// Reason for slashing or restituting a governance bond.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceSlashReason"
    )]
    pub enum GovernanceSlashReason {
        /// Duplicate/second ballot detected for the same referendum.
        DoubleVote,
        /// Proof or ballot deemed ineligible (e.g., stale eligibility root).
        IneligibleProof,
        /// Malicious or invalid submission (proof/metadata mismatch).
        Misconduct,
        /// Manual slashing triggered by an operator.
        #[default]
        Manual,
        /// Restitution granted after appeal or correction.
        Restitution,
    }
    /// Referendum opened payload
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceReferendumOpened"
    )]
    pub struct GovernanceReferendumOpened {
        /// Referendum identifier
        pub id: String,
        /// Enactment window start height (inclusive)
        pub h_start: u64,
        /// Enactment window end height (inclusive)
        pub h_end: u64,
    }
    /// Referendum closed payload
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceReferendumClosed"
    )]
    pub struct GovernanceReferendumClosed {
        /// Referendum identifier
        pub id: String,
        /// Block height at which the referendum was closed
        pub at_height: u64,
    }
    /// Lock unlocked payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceLockUnlocked"
    )]
    pub struct GovernanceLockUnlocked {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voter account id
        pub owner: crate::account::AccountId,
        /// Amount unlocked
        pub amount: Quantity,
    }
    /// Lock slashed payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceLockSlashed"
    )]
    pub struct GovernanceLockSlashed {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voter account id
        pub owner: crate::account::AccountId,
        /// Exact amount slashed from the lock.
        pub amount: Quantity,
        /// Reason for slashing (typed; use `Manual` for human-only reasons).
        pub reason: GovernanceSlashReason,
        /// Account that now custodians the slashed funds (may equal the escrow).
        pub destination: crate::account::AccountId,
        /// Free-form note attached to the slash decision.
        pub note: String,
    }
    /// Lock restitution payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceLockRestituted"
    )]
    pub struct GovernanceLockRestituted {
        /// Referendum identifier
        pub referendum_id: String,
        /// Voter account id
        pub owner: crate::account::AccountId,
        /// Exact amount restored to the lock.
        pub amount: Quantity,
        /// Reason being rectified/appealed.
        pub reason: GovernanceSlashReason,
        /// Free-form note attached to the restitution decision.
        pub note: String,
    }
    /// Citizen registry entry created.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceCitizenRegistered"
    )]
    pub struct GovernanceCitizenRegistered {
        /// Account receiving citizenship.
        pub owner: crate::account::AccountId,
        /// Bonded amount held in escrow.
        pub amount: Quantity,
    }
    /// Citizen registry entry removed (bond returned).
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceCitizenRevoked"
    )]
    pub struct GovernanceCitizenRevoked {
        /// Account removed from the registry.
        pub owner: crate::account::AccountId,
        /// Amount returned from escrow.
        pub amount: Quantity,
    }
    /// Canonical creation of one retryable end-to-end Parliament attempt.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceParliamentAttemptCreated"
    )]
    pub struct GovernanceParliamentAttemptCreated {
        /// Immutable proposal content shared by every retry.
        pub proposal_content_id: ProposalContentId,
        /// Canonical identifier derived from content and retry sequence.
        pub governance_attempt_id: GovernanceAttemptId,
        /// Zero-based retry sequence for the proposal content.
        pub attempt_sequence: u32,
        /// Policy-derived initial risk tier.
        pub risk_tier: RiskTierV1,
        /// Governance policy version frozen for the attempt.
        pub policy_version: u64,
        /// Hash of the exact deterministic effect preimage.
        pub effect_preimage_hash: [u8; 32],
        /// Compare-and-set head frozen when the attempt was created.
        pub expected_head: GovernanceExpectedHeadV1,
        /// Block height creating the attempt.
        pub at_height: u64,
    }
    /// Bounded audit record for one accepted Parliament reducer command or
    /// consensus-derived certificate-execution outcome.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceParliamentLifecycleTransitionApplied"
    )]
    pub struct GovernanceParliamentLifecycleTransitionApplied {
        /// Immutable proposal content being processed.
        pub proposal_content_id: ProposalContentId,
        /// Retry attempt that consumed the transition.
        pub governance_attempt_id: GovernanceAttemptId,
        /// Stable bounded classification of the public transition or automatic outcome.
        pub transition_kind: ParliamentLifecycleTransitionKindV1,
        /// Core-derived bounded no-result class, present only when a body terminalizes without a result.
        pub no_result_kind: Option<ParliamentNoResultKindV1>,
        /// Typed consensus-owned terminal outcome, absent for submitted transitions.
        pub automatic_outcome: Option<ParliamentAutomaticExecutionOutcomeV1>,
        /// Domain-separated digest of the submitted transition or automatic outcome.
        ///
        /// A no-result transition carries no caller-selected failure class; its
        /// separate `no_result_kind` field records that Core-derived evidence.
        pub transition_digest: [u8; 32],
        /// Certificate produced by this transition, when applicable.
        pub certificate_id: Option<GovernanceCertificateId>,
        /// Block height applying the transition.
        pub at_height: u64,
    }
    /// Exact decision for one standalone governance referendum.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        iroha_schema::IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_data_model::events::data::governance::model::GovernanceReferendumDecided"
    )]
    pub struct GovernanceReferendumDecided {
        /// Original standalone referendum selector, without normalization.
        pub referendum_id: String,
        /// Exact accumulated approval weight.
        pub approve: u128,
        /// Exact accumulated rejection weight.
        pub reject: u128,
        /// Exact accumulated abstention weight.
        pub abstain: u128,
        /// Whether the configured turnout and approval thresholds were met.
        pub approved: bool,
    }
}

impl_json_via_norito_bytes!(
    GovernanceEvent,
    GovernanceProposalSubmitted,
    GovernanceLockCreated,
    GovernanceLockExtended,
    GovernanceProposalEnacted,
    GovernanceProposalRejected,
    GovernanceBallotMode,
    GovernanceBallotAccepted,
    GovernanceBallotRejected,
    GovernanceReferendumOpened,
    GovernanceReferendumClosed,
    GovernanceLockUnlocked,
    GovernanceParliamentAttemptCreated,
    GovernanceParliamentLifecycleTransitionApplied,
    GovernanceThresholdKeyLifecycleAppliedV1,
    GovernanceSlashReason,
    GovernanceLockSlashed,
    GovernanceLockRestituted,
    GovernanceCitizenRegistered,
    GovernanceCitizenRevoked,
    GovernanceReferendumDecided,
);
/// Prelude exports
pub mod prelude {
    pub use super::{
        GovernanceBallotAccepted, GovernanceBallotMode, GovernanceBallotRejected,
        GovernanceCitizenRegistered, GovernanceCitizenRevoked, GovernanceEvent,
        GovernanceLockCreated, GovernanceLockExtended, GovernanceLockRestituted,
        GovernanceLockSlashed, GovernanceLockUnlocked, GovernanceParliamentAttemptCreated,
        GovernanceParliamentLifecycleTransitionApplied, GovernanceProposalEnacted,
        GovernanceProposalRejected, GovernanceProposalSubmitted, GovernanceReferendumClosed,
        GovernanceReferendumDecided, GovernanceReferendumOpened, GovernanceSlashReason,
        GovernanceThresholdKeyLifecycleAppliedV1,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::types::{
        BallotAttemptId, GovernanceAttemptId, GovernanceCertificateId,
        GovernanceExpectedHeadAbsentV1, GovernanceExpectedHeadV1, ParliamentNoResultKindV1,
        ProposalContentId, RiskTierV1,
    };
    use crate::isi::governance::{
        ParliamentAutomaticExecutionFailedV1, ParliamentAutomaticExecutionOutcomeV1,
        ParliamentCloseBallotRegistrationV1, ParliamentLifecycleTransitionKindV1,
        ParliamentLifecycleTransitionV1,
    };

    fn assert_roundtrip(event: &GovernanceEvent) {
        let bytes = norito::to_bytes(event).expect("encode canonical governance event");
        let decoded = norito::decode_from_bytes::<GovernanceEvent>(&bytes)
            .expect("decode canonical governance event");
        assert_eq!(&decoded, event);
    }

    #[test]
    fn standalone_referendum_decision_roundtrips_exact_identity_and_tally() {
        let event = GovernanceEvent::ReferendumDecided(GovernanceReferendumDecided {
            referendum_id: "0XAbCd-referendum".to_owned(),
            approve: u128::MAX,
            reject: u128::from(u64::MAX) + 1,
            abstain: 17,
            approved: true,
        });
        assert_eq!(
            event.encode().get(..4),
            Some(17_u32.to_le_bytes().as_slice()),
            "the standalone decision event must use its canonical first-release enum tag"
        );
        assert_roundtrip(&event);
    }

    #[test]
    fn parliament_v1_lifecycle_events_roundtrip() {
        let proposal_content_id = ProposalContentId::new([0x11; 32]);
        let governance_attempt_id = GovernanceAttemptId::new([0x12; 32]);
        assert_roundtrip(&GovernanceEvent::ParliamentAttemptCreated(
            GovernanceParliamentAttemptCreated {
                proposal_content_id,
                governance_attempt_id,
                attempt_sequence: 0,
                risk_tier: RiskTierV1::Standard,
                policy_version: 1,
                effect_preimage_hash: [0x15; 32],
                expected_head: GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                    subject_id: [0x16; 32],
                }),
                at_height: 99,
            },
        ));
        assert_roundtrip(&GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id,
                governance_attempt_id,
                transition_kind: ParliamentLifecycleTransitionKindV1::CompleteQualification,
                no_result_kind: None,
                automatic_outcome: None,
                transition_digest: ParliamentLifecycleTransitionV1::CompleteQualification
                    .digest_v1(),
                certificate_id: None,
                at_height: 100,
            },
        ));
        assert_roundtrip(&GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id,
                governance_attempt_id,
                transition_kind: ParliamentLifecycleTransitionKindV1::FailPublicFindingNoResult,
                no_result_kind: Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired),
                automatic_outcome: None,
                transition_digest: [0x19; 32],
                certificate_id: None,
                at_height: 101,
            },
        ));
        assert_roundtrip(&GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id,
                governance_attempt_id,
                transition_kind: ParliamentLifecycleTransitionKindV1::FailBallotNoResult,
                no_result_kind: Some(ParliamentNoResultKindV1::BallotOpeningDeadlineExpired),
                automatic_outcome: None,
                transition_digest: [0x20; 32],
                certificate_id: None,
                at_height: 101,
            },
        ));
        let automatic_outcome = ParliamentAutomaticExecutionOutcomeV1::ExecutionFailed(
            ParliamentAutomaticExecutionFailedV1 {
                effect_preimage_hash: [0x21; 32],
                failure_root: [0x22; 32],
            },
        );
        assert_roundtrip(&GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id,
                governance_attempt_id,
                transition_kind: automatic_outcome.kind(),
                no_result_kind: None,
                automatic_outcome: Some(automatic_outcome),
                transition_digest: automatic_outcome.digest_v1(),
                certificate_id: Some(GovernanceCertificateId::new([0x23; 32])),
                at_height: 102,
            },
        ));
    }

    #[test]
    fn parliament_lifecycle_audit_event_never_embeds_transition_evidence() {
        let proposal_content_id = ProposalContentId::new([0x17; 32]);
        let governance_attempt_id = GovernanceAttemptId::new([0x18; 32]);
        let transition = ParliamentLifecycleTransitionV1::CloseBallotRegistration(
            ParliamentCloseBallotRegistrationV1 {
                ballot_attempt_id: BallotAttemptId::new([0x19; 32]),
            },
        );
        let event = GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id,
                governance_attempt_id,
                transition_kind: transition.kind(),
                no_result_kind: None,
                automatic_outcome: None,
                transition_digest: transition.digest_v1(),
                certificate_id: None,
                at_height: 103,
            },
        );
        let encoded = norito::to_bytes(&event).expect("encode bounded lifecycle audit event");
        assert!(
            encoded.len() < 512,
            "audit event must not duplicate evidence"
        );
        assert_roundtrip(&event);
    }

    #[test]
    fn threshold_key_lifecycle_event_roundtrips() {
        assert_roundtrip(&GovernanceEvent::ThresholdKeyLifecycleApplied(
            GovernanceThresholdKeyLifecycleAppliedV1 {
                action: crate::isi::consensus_keys::ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
                session_id: [0x31; 32],
                transcript_hash: [0x32; 32],
                effective_height: 41,
            },
        ));
    }

    #[test]
    fn governance_event_schema_excludes_unreachable_surfaces() {
        let removed_variants = [
            ["Proposal", "Approved"].concat(),
            ["Parliament", "Approval", "Recorded"].concat(),
            ["Parliament", "Attempt", "Transitioned"].concat(),
            ["Parliament", "Body", "Transitioned"].concat(),
            ["Parliament", "Ballot", "Transitioned"].concat(),
            ["Parliament", "Concentration", "Warning"].concat(),
            ["Parliament", "Aggregate", "Finalized"].concat(),
            ["Parliament", "Certificate", "Issued"].concat(),
        ];
        let removed_payloads = removed_variants
            .iter()
            .map(|variant| ["Governance", variant.as_str()].concat())
            .collect::<Vec<_>>();

        let schema = <GovernanceEvent as iroha_schema::IntoSchema>::schema();
        let metadata = schema
            .get::<GovernanceEvent>()
            .expect("governance event schema entry");
        let iroha_schema::Metadata::Enum(event_metadata) = metadata else {
            panic!("governance event schema must remain an enum");
        };
        assert!(event_metadata.variants.iter().all(|variant| {
            removed_variants
                .iter()
                .all(|removed| variant.tag != removed.as_str())
        }));
        assert!(schema.iter().all(|(_, entry)| {
            removed_payloads
                .iter()
                .all(|removed| entry.type_name != removed.as_str())
        }));
    }

    #[test]
    fn parliament_event_schema_excludes_per_voter_plaintext() {
        let retired_variant = ["Parliament", "Ballot", "Recorded"].concat();
        let retired_payload = ["Governance", retired_variant.as_str()].concat();
        let retired_decision = ["Parliament", "Decision"].concat();
        let retired_decision_declaration = ["pub enum ", retired_decision.as_str(), " {"].concat();

        let event_source = include_str!("governance.rs");
        let instruction_source = include_str!("../../isi/governance.rs");
        assert!(!event_source.contains(&retired_variant));
        assert!(!event_source.contains(&retired_payload));
        assert!(!instruction_source.contains(&retired_decision_declaration));

        let schema = <GovernanceEvent as iroha_schema::IntoSchema>::schema();
        let metadata = schema
            .get::<GovernanceEvent>()
            .expect("governance event schema entry");
        let iroha_schema::Metadata::Enum(event_metadata) = metadata else {
            panic!("governance event schema must remain an enum");
        };
        assert!(
            event_metadata
                .variants
                .iter()
                .all(|variant| variant.tag != retired_variant)
        );
        assert!(schema.iter().all(|(_, entry)| {
            entry.type_name != retired_payload && entry.type_name != retired_decision
        }));
    }
}

#[cfg(test)]
mod captured_event_boundary_identity_tests;
