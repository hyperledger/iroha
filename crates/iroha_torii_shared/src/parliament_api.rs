//! Public DTOs for authenticated SORA Parliament draft and read routes.
//!
//! Draft responses contain canonical framed instruction payloads for local
//! signing. Read responses expose a stable typed summary and the complete
//! canonical reducer payload, so independent auditors can retain the exact
//! state even while reducer internals evolve within the first release.

use iroha_data_model::governance::types::{
    BodyInstanceId, BodyInstanceStatusV1, GovernanceAttemptId, GovernanceAttemptV1,
    GovernanceCertificateV1, GovernanceExpectedHeadV1, ParliamentBody, ParliamentNoResultKindV1,
    ProposalContentId, ProposalKind,
};
use iroha_data_model::isi::governance::{
    ParliamentLifecycleTransitionKindV1, ParliamentLifecycleTransitionV1,
};
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};

/// Current Parliament draft/read API layout.
pub const PARLIAMENT_API_VERSION_V1: u16 = 1;

/// Strict request for one locally signed governance-attempt creation.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentAttemptDraftRequestV1")]
pub struct ParliamentAttemptDraftRequestV1 {
    /// Request layout version; must equal one.
    pub version: u16,
    /// Exact immutable proposal content shared by every retry.
    pub proposal: ProposalKind,
    /// Zero-based end-to-end retry sequence for the proposal content.
    pub attempt_sequence: u32,
}

/// One canonical instruction skeleton returned for local signing.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentInstructionDraftV1")]
pub struct ParliamentInstructionDraftV1 {
    /// Stable instruction registry identifier.
    pub wire_id: String,
    /// Lowercase hexadecimal canonical framed Norito payload.
    pub payload_hex: String,
}

/// Bound response for one governance-attempt creation draft.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentAttemptDraftResponseV1")]
pub struct ParliamentAttemptDraftResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Identifier derived from the exact proposal content.
    pub proposal_content_id: ProposalContentId,
    /// Identifier derived from proposal content and retry sequence.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Exactly one canonical creation instruction.
    pub tx_instructions: Vec<ParliamentInstructionDraftV1>,
}

/// Strict request for one locally signed Parliament lifecycle transition.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTransitionDraftRequestV1")]
pub struct ParliamentTransitionDraftRequestV1 {
    /// Request layout version; must equal one.
    pub version: u16,
    /// Existing attempt that must consume the transition.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Exact closed lifecycle transition.
    pub transition: ParliamentLifecycleTransitionV1,
}

impl ParliamentTransitionDraftRequestV1 {
    /// Enforce the canonical state-independent transition invariants.
    ///
    /// Stateful authority, phase, height, roster, proof, and certificate checks
    /// remain consensus responsibilities when the locally signed instruction is
    /// executed.
    ///
    /// # Errors
    /// Returns a stable message when an untrusted draft exceeds a first-release
    /// bound or contains a structurally impossible commitment.
    pub fn validate_static(&self) -> Result<(), &'static str> {
        if self.version != PARLIAMENT_API_VERSION_V1 {
            return Err("unsupported Parliament transition draft version");
        }
        self.transition
            .validate_static_for_attempt(self.governance_attempt_id)
    }
}

/// Bound response for one Parliament lifecycle-transition draft.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTransitionDraftResponseV1")]
pub struct ParliamentTransitionDraftResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Exact attempt named by the request and instruction.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Bounded classification of the exact transition.
    pub transition_kind: ParliamentLifecycleTransitionKindV1,
    /// Domain-separated digest of the complete transition evidence.
    pub transition_digest: [u8; 32],
    /// Exactly one canonical transition instruction.
    pub tx_instructions: Vec<ParliamentInstructionDraftV1>,
}

/// Public decision protocol assigned to one required Parliament body.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(tag = "mode", content = "details", deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentDecisionModeProjectionV1")]
pub enum ParliamentDecisionModeProjectionV1 {
    /// Public deliberation ending in a nonbinding finding.
    PublicFinding,
    /// Mandatory private binding ballot.
    HiddenBindingBallot,
}

/// Stable projection of one ordered body requirement.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::RequiredParliamentBodyProjectionV1")]
pub struct RequiredParliamentBodyProjectionV1 {
    /// Parliament body role.
    pub body: ParliamentBody,
    /// Decision protocol frozen for the role.
    pub decision_mode: ParliamentDecisionModeProjectionV1,
}

/// Public lifecycle and immutable deadline facts for one ordered Parliament body.
///
/// Private ballot material and plaintext votes remain outside this projection;
/// the terminal no-result class and height are safe audit facts.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentBodyStateProjectionV1")]
pub struct ParliamentBodyStateProjectionV1 {
    /// Parliament role in the attempt's exact required-body pipeline.
    pub body: ParliamentBody,
    /// Active sealed body instance, once sortition and invitations complete.
    pub body_instance_id: Option<BodyInstanceId>,
    /// Current public lifecycle state of the sealed instance.
    pub status: Option<BodyInstanceStatusV1>,
    /// Height that opened a public-finding endorsement window.
    pub public_finding_opened_at_height: Option<u64>,
    /// Immutable nonzero public-finding endorsement span in blocks.
    pub public_finding_phase_blocks: Option<u64>,
    /// Inclusive immutable public-finding endorsement deadline.
    pub public_finding_deadline_height: Option<u64>,
    /// Core-derived closed no-result class, when the body ended without a result.
    pub no_result_kind: Option<ParliamentNoResultKindV1>,
    /// Containing finalized height that made the no-result state terminal.
    pub no_result_height: Option<u64>,
}

/// Exact authenticated read projection for one Parliament attempt.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentAttemptReadResponseV1")]
pub struct ParliamentAttemptReadResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Committed height observed atomically with the state projection.
    pub current_height: u64,
    /// Canonical attempt lifecycle summary.
    pub attempt: GovernanceAttemptV1,
    /// Governance policy version frozen at admission.
    pub policy_version: u64,
    /// Exact ordered required-body pipeline.
    pub required_bodies: Vec<RequiredParliamentBodyProjectionV1>,
    /// Ordered public lifecycle/deadline projection for every required body.
    pub body_states: Vec<ParliamentBodyStateProjectionV1>,
    /// Complete governance certificate, once automatically constructed.
    pub certificate: Option<GovernanceCertificateV1>,
    /// Height of the terminal execution outcome, when present.
    pub terminal_height: Option<u64>,
    /// Deterministic root of a rollback-isolated execution failure, when present.
    pub execution_failure_root: Option<[u8; 32]>,
    /// Compare-and-set head that superseded the certificate, when present.
    pub superseding_head: Option<GovernanceExpectedHeadV1>,
    /// Lowercase hexadecimal canonical Norito bytes of the complete reducer state.
    pub state_payload_hex: String,
}

/// One Parliament transition valid at exactly one height.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentExactTransitionProjectionV1")]
pub struct ParliamentExactTransitionProjectionV1 {
    /// The only height at which the transition executes.
    pub height: u64,
    /// The transition.
    pub transition: ParliamentLifecycleTransitionV1,
}

/// Driver plan of one Parliament attempt (`specs/sccp.md` §4.14.5 item 4).
///
/// Core derives it from one committed query view by trial-applying every permissionless
/// transition to the reducer, so it is advice for a driver, never authority: consensus rechecks
/// every submitted transition.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentAttemptPlanResponseV1")]
pub struct ParliamentAttemptPlanResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Planned attempt.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Committed height the plan was derived from.
    pub current_height: u64,
    /// Next native candidate height used for this advice; inclusion is not reserved.
    pub execution_height: u64,
    /// Transitions the reducer accepts at `execution_height`, in submission order.
    pub due: Vec<ParliamentLifecycleTransitionV1>,
    /// Transitions valid at exactly one future height, ascending by height.
    pub exact: Vec<ParliamentExactTransitionProjectionV1>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_catalog::runtime_governance as gov_routes;
    use iroha_data_model::governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal,
        MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
    };
    use iroha_data_model::smart_contract::ContractAddress;
    use norito::json;

    fn proposal_operator() -> iroha_data_model::account::AccountId {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x10; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("derive checked Parliament API fixture operator");
        iroha_data_model::account::AccountId::new(key_pair.public_key().clone())
    }

    fn request() -> ParliamentAttemptDraftRequestV1 {
        ParliamentAttemptDraftRequestV1 {
            version: PARLIAMENT_API_VERSION_V1,
            proposal: ProposalKind::DeployContract(DeployContractProposal {
                proposal_operator: proposal_operator(),
                contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                    .parse::<ContractAddress>()
                    .expect("parse Parliament API fixture address"),
                code_hash: ContractCodeHash::new([0x11; 32]),
                abi_hash: ContractAbiHash::new([0x22; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            attempt_sequence: 3,
        }
    }

    fn transition_request(
        transition: ParliamentLifecycleTransitionV1,
    ) -> ParliamentTransitionDraftRequestV1 {
        ParliamentTransitionDraftRequestV1 {
            version: PARLIAMENT_API_VERSION_V1,
            governance_attempt_id: GovernanceAttemptId::new([0x33; 32]),
            transition,
        }
    }

    #[test]
    fn attempt_draft_request_roundtrips_json_and_norito() {
        let request = request();
        let json = json::to_vec(&request).expect("encode Parliament request JSON");
        let decoded_json: ParliamentAttemptDraftRequestV1 =
            json::from_slice(&json).expect("decode Parliament request JSON");
        assert_eq!(decoded_json, request);

        let bytes = norito::to_bytes(&request).expect("encode Parliament request Norito");
        let decoded = norito::decode_from_bytes::<ParliamentAttemptDraftRequestV1>(&bytes)
            .expect("decode Parliament request Norito");
        assert_eq!(decoded, request);
    }

    #[test]
    fn attempt_draft_request_rejects_unknown_fields_and_aliases() {
        let value = json::to_value(&request()).expect("render Parliament request JSON");
        let mut unknown = value.clone();
        unknown.as_object_mut().expect("request object").insert(
            "private_key".to_owned(),
            json::Value::String("secret".to_owned()),
        );
        assert!(json::from_value::<ParliamentAttemptDraftRequestV1>(unknown).is_err());

        let mut alias = value;
        let object = alias.as_object_mut().expect("request object");
        let sequence = object
            .remove("attempt_sequence")
            .expect("canonical sequence field");
        object.insert("attemptSequence".to_owned(), sequence);
        assert!(json::from_value::<ParliamentAttemptDraftRequestV1>(alias).is_err());
    }

    #[test]
    fn transition_draft_request_roundtrips_json_and_norito() {
        let request = transition_request(ParliamentLifecycleTransitionV1::CompleteQualification);
        request.validate_static().expect("valid transition request");
        let encoded_json = json::to_vec(&request).expect("encode transition request JSON");
        let decoded_json: ParliamentTransitionDraftRequestV1 =
            json::from_slice(&encoded_json).expect("decode transition request JSON");
        assert_eq!(decoded_json, request);

        let bytes = norito::to_bytes(&request).expect("encode transition request Norito");
        let decoded = norito::decode_from_bytes::<ParliamentTransitionDraftRequestV1>(&bytes)
            .expect("decode transition request Norito");
        assert_eq!(decoded, request);
    }

    #[test]
    fn transition_draft_json_rejects_consensus_owned_tags() {
        let request = transition_request(ParliamentLifecycleTransitionV1::CompleteQualification);
        let base = json::to_value(&request).expect("render transition draft JSON");
        for tag in [
            "ConstructCertificate",
            "MarkEnacted",
            "MarkSuperseded",
            "MarkExecutionFailed",
        ] {
            let mut rejected = base.clone();
            let transition = rejected
                .as_object_mut()
                .and_then(|object| object.get_mut("transition"))
                .and_then(json::Value::as_object_mut)
                .expect("tagged transition object");
            transition.insert("transition".to_owned(), json::Value::String(tag.to_owned()));
            transition.insert("payload".to_owned(), norito::json!({}));
            assert!(
                json::from_value::<ParliamentTransitionDraftRequestV1>(rejected).is_err(),
                "removed public transition tag `{tag}` must fail JSON decoding"
            );
        }
    }

    #[test]
    fn transition_draft_request_rejects_unknown_fields_aliases_and_versions() {
        let request = transition_request(ParliamentLifecycleTransitionV1::CompleteQualification);
        let value = json::to_value(&request).expect("render transition request JSON");

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .expect("transition request object")
            .insert(
                "authority".to_owned(),
                json::Value::String("alias".to_owned()),
            );
        assert!(json::from_value::<ParliamentTransitionDraftRequestV1>(unknown).is_err());

        let mut alias = value;
        let object = alias.as_object_mut().expect("transition request object");
        let attempt_id = object
            .remove("governance_attempt_id")
            .expect("canonical attempt id");
        object.insert("governanceAttemptId".to_owned(), attempt_id);
        assert!(json::from_value::<ParliamentTransitionDraftRequestV1>(alias).is_err());

        let mut wrong_version = request;
        wrong_version.version = 2;
        assert_eq!(
            wrong_version.validate_static(),
            Err("unsupported Parliament transition draft version")
        );

        let zero_election =
            transition_request(ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(
                iroha_data_model::isi::governance::ParliamentBeginInvitationAcceptanceV1 {
                    election_attempt_id:
                        iroha_data_model::governance::types::BodyElectionAttemptId::new([0; 32]),
                },
            ));
        assert_eq!(
            zero_election.validate_static(),
            Err("body-election attempt id must be non-zero")
        );
    }

    #[test]
    fn shared_sdk_fixture_pins_routes_norito_indices_json_tags_and_result_roots() {
        use norito::codec::Encode;

        let fixture: json::Value = json::from_slice(include_bytes!(
            "../../../fixtures/governance/parliament_api_v1.json"
        ))
        .expect("decode shared Parliament API fixture");
        assert_eq!(
            fixture.get("schema").and_then(json::Value::as_str),
            Some("iroha.governance.parliament.api_fixture.v1")
        );
        assert_eq!(
            fixture.get("api_version").and_then(json::Value::as_u64),
            Some(u64::from(PARLIAMENT_API_VERSION_V1))
        );

        let routes = fixture
            .get("routes")
            .and_then(json::Value::as_object)
            .expect("fixture routes");
        assert_eq!(
            routes.get("attempt_draft").and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_ATTEMPT_DRAFT.path())
        );
        assert_eq!(
            routes.get("attempt_read").and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_ATTEMPT_READ.path())
        );
        assert_eq!(
            routes.get("transition_draft").and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TRANSITION_DRAFT.path())
        );
        let limits = fixture
            .get("limits")
            .and_then(json::Value::as_object)
            .expect("fixture limits");
        assert_eq!(
            limits
                .get("governance_attempt_sequence_max")
                .and_then(json::Value::as_u64),
            Some(u64::from(MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1))
        );

        let expected_public = [
            (0, "EscalateRisk", true, 0),
            (1, "CompleteQualification", false, 1),
            (2, "RegisterSortitionRequest", true, 2),
            (3, "ConsumeSortitionPulseBatch", true, 3),
            (4, "BeginInvitationAcceptance", true, 4),
            (5, "FailBodyElectionNoRoster", true, 5),
            (6, "SealBodyRoster", true, 6),
            (7, "AdvanceBodyPhase", true, 7),
            (8, "RecordAttemptAbsence", true, 8),
            (9, "EndorsePublicFinding", true, 9),
            (10, "RegisterBallotAttempt", true, 10),
            (11, "CloseBallotRegistration", true, 11),
            (12, "FreezeBallotSurvivors", true, 12),
            (13, "FreezeTimedOvnCorpus", true, 13),
            (14, "BeginBallotOpeningBatch", true, 14),
            (15, "FailBallotNoResult", true, 15),
            (16, "FinalizeOpenedBallot", true, 16),
            (17, "RecordInvitationResponse", true, 20),
            (18, "RegisterBallotParticipant", true, 21),
            (19, "RecordBallotDropout", true, 22),
            (20, "FailPublicFindingNoResult", true, 23),
            (21, "RegisterInitialSortition", false, 24),
        ];
        let public = fixture
            .get("public_transitions")
            .and_then(json::Value::as_array)
            .expect("public transition inventory");
        assert_eq!(public.len(), expected_public.len());
        for (entry, (index, tag, payload_required, kind_index)) in
            public.iter().zip(expected_public)
        {
            let expected_prefix = format!("{index:02x}");
            assert_eq!(
                entry.get("norito_index").and_then(json::Value::as_u64),
                Some(index)
            );
            assert_eq!(
                entry.get("norito_prefix_hex").and_then(json::Value::as_str),
                Some(expected_prefix.as_str())
            );
            assert_eq!(
                entry.get("json_tag").and_then(json::Value::as_str),
                Some(tag)
            );
            assert_eq!(
                entry.get("json_payload").and_then(json::Value::as_str),
                Some(if payload_required {
                    "required"
                } else {
                    "forbidden"
                })
            );
            assert_eq!(
                entry.get("event_kind_index").and_then(json::Value::as_u64),
                Some(kind_index)
            );
        }

        let kinds = [
            ParliamentLifecycleTransitionKindV1::EscalateRisk,
            ParliamentLifecycleTransitionKindV1::CompleteQualification,
            ParliamentLifecycleTransitionKindV1::RegisterSortitionRequest,
            ParliamentLifecycleTransitionKindV1::ConsumeSortitionPulseBatch,
            ParliamentLifecycleTransitionKindV1::BeginInvitationAcceptance,
            ParliamentLifecycleTransitionKindV1::FailBodyElectionNoRoster,
            ParliamentLifecycleTransitionKindV1::SealBodyRoster,
            ParliamentLifecycleTransitionKindV1::AdvanceBodyPhase,
            ParliamentLifecycleTransitionKindV1::RecordAttemptAbsence,
            ParliamentLifecycleTransitionKindV1::EndorsePublicFinding,
            ParliamentLifecycleTransitionKindV1::RegisterBallotAttempt,
            ParliamentLifecycleTransitionKindV1::CloseBallotRegistration,
            ParliamentLifecycleTransitionKindV1::FreezeBallotSurvivors,
            ParliamentLifecycleTransitionKindV1::FreezeTimedOvnCorpus,
            ParliamentLifecycleTransitionKindV1::BeginBallotOpeningBatch,
            ParliamentLifecycleTransitionKindV1::FailBallotNoResult,
            ParliamentLifecycleTransitionKindV1::FinalizeOpenedBallot,
            ParliamentLifecycleTransitionKindV1::MarkEnacted,
            ParliamentLifecycleTransitionKindV1::MarkSuperseded,
            ParliamentLifecycleTransitionKindV1::MarkExecutionFailed,
            ParliamentLifecycleTransitionKindV1::RecordInvitationResponse,
            ParliamentLifecycleTransitionKindV1::RegisterBallotParticipant,
            ParliamentLifecycleTransitionKindV1::RecordBallotDropout,
            ParliamentLifecycleTransitionKindV1::FailPublicFindingNoResult,
            ParliamentLifecycleTransitionKindV1::RegisterInitialSortition,
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            assert_eq!(
                kind.encode()[0],
                u8::try_from(index).expect("kind index fits u8")
            );
        }

        let no_result_kinds = [
            ParliamentNoResultKindV1::PublicFindingQuorumUnreachable,
            ParliamentNoResultKindV1::PublicFindingDeadlineExpired,
            ParliamentNoResultKindV1::BallotRegistrationDeadlineExpired,
            ParliamentNoResultKindV1::BallotSurvivorDeadlineExpired,
            ParliamentNoResultKindV1::BallotCommitmentDeadlineExpired,
            ParliamentNoResultKindV1::BallotReleasePulseUnavailable,
            ParliamentNoResultKindV1::BallotOpeningDeadlineExpired,
            ParliamentNoResultKindV1::SortitionRetriesExhausted,
            ParliamentNoResultKindV1::ConfirmationJuryCapacityUnavailable,
            ParliamentNoResultKindV1::RandomnessRedrawBudgetExhausted,
        ];
        let fixture_no_result_kinds = fixture
            .get("no_result_kinds")
            .and_then(json::Value::as_array)
            .expect("closed no-result inventory");
        assert_eq!(fixture_no_result_kinds.len(), no_result_kinds.len());
        for (index, (entry, kind)) in fixture_no_result_kinds
            .iter()
            .zip(no_result_kinds)
            .enumerate()
        {
            assert_eq!(
                kind.encode(),
                u32::try_from(index)
                    .expect("no-result index fits u32")
                    .to_le_bytes()
            );
            assert_eq!(
                entry.get("norito_index").and_then(json::Value::as_u64),
                Some(u64::try_from(index).expect("index fits u64"))
            );
        }

        let body_state = fixture
            .get("attempt_read_body_state")
            .and_then(json::Value::as_object)
            .expect("body-state projection fixture");
        assert_eq!(
            body_state
                .get("json_fields")
                .and_then(json::Value::as_array)
                .map(Vec::len),
            Some(8)
        );
        assert_eq!(
            body_state
                .get("deadline_semantics")
                .and_then(json::Value::as_str),
            Some("inclusive")
        );
        let expected_outcomes = [
            (0, "Enacted", false, "MarkEnacted", 17),
            (1, "Superseded", true, "MarkSuperseded", 18),
            (2, "ExecutionFailed", true, "MarkExecutionFailed", 19),
        ];
        let outcomes = fixture
            .get("automatic_execution_outcomes")
            .and_then(json::Value::as_array)
            .expect("automatic outcome inventory");
        assert_eq!(outcomes.len(), expected_outcomes.len());
        for (entry, (index, tag, payload_required, kind, kind_index)) in
            outcomes.iter().zip(expected_outcomes)
        {
            assert_eq!(
                entry.get("norito_index").and_then(json::Value::as_u64),
                Some(index)
            );
            assert_eq!(
                entry.get("json_tag").and_then(json::Value::as_str),
                Some(tag)
            );
            assert_eq!(
                entry.get("json_payload").and_then(json::Value::as_str),
                Some(if payload_required {
                    "required"
                } else {
                    "forbidden"
                })
            );
            assert_eq!(
                entry.get("event_kind").and_then(json::Value::as_str),
                Some(kind)
            );
            assert_eq!(
                entry.get("event_kind_index").and_then(json::Value::as_u64),
                Some(kind_index)
            );
        }

        let roots = fixture
            .get("certificate_result_roots")
            .and_then(json::Value::as_array)
            .expect("certificate result root inventory");
        assert_eq!(roots.len(), 6);
        for root in roots {
            assert_eq!(root.get("bytes").and_then(json::Value::as_u64), Some(32));
            assert_eq!(
                root.get("zero_forbidden").and_then(json::Value::as_bool),
                Some(true)
            );
        }
        let endorsement_root = roots
            .iter()
            .find(|root| {
                root.get("name").and_then(json::Value::as_str)
                    == Some("public_finding_endorsement_root")
            })
            .expect("public finding endorsement root fixture");
        let endorsement_preimage = endorsement_root
            .get("preimage")
            .and_then(json::Value::as_array)
            .expect("public finding endorsement preimage");
        let expected_endorsement_preimage = [
            "governance_attempt_id",
            "body_instance_id",
            "result_root",
            "endorsing_assignments",
        ];
        assert_eq!(
            endorsement_preimage.len(),
            expected_endorsement_preimage.len()
        );
        for (field, expected) in endorsement_preimage
            .iter()
            .zip(expected_endorsement_preimage)
        {
            assert_eq!(field.as_str(), Some(expected));
        }

        let binding = fixture
            .get("certificate_body_binding")
            .and_then(json::Value::as_object)
            .expect("certificate body binding fixture");
        let expected_fields = [
            "body_instance_id",
            "election_attempt_id",
            "election_attempt_sequence",
            "sortition_request_id",
            "sortition_request",
            "body",
            "original_seats",
            "beacon_session_id",
            "beacon_pulse_id",
            "roster_root",
            "assignment_root",
            "result_root",
            "result_height",
            "public_finding",
            "ballot",
        ];
        let field_order = binding
            .get("norito_field_order")
            .and_then(json::Value::as_array)
            .expect("certificate body Norito field order");
        assert_eq!(field_order.len(), expected_fields.len());
        for (field, expected) in field_order.iter().zip(expected_fields) {
            assert_eq!(field.as_str(), Some(expected));
        }
        let public = binding
            .get("public_nonbinding_body")
            .and_then(json::Value::as_object)
            .expect("public finding certificate binding fixture");
        assert_eq!(
            public.get("quorum").and_then(json::Value::as_str),
            Some("ceil(2 * original_seats / 3)")
        );
        assert_eq!(
            public
                .get("endorsing_assignments")
                .and_then(json::Value::as_str),
            Some("strictly increasing distinct nonzero assignment ids")
        );
        assert_eq!(
            public.get("endorsements").and_then(json::Value::as_str),
            Some("endorsing_assignments.length == quorum")
        );
        let private = binding
            .get("private_jury")
            .and_then(json::Value::as_object)
            .expect("private jury certificate binding fixture");
        assert_eq!(
            private.get("public_finding").and_then(json::Value::as_str),
            Some("forbidden")
        );
        assert_eq!(
            private.get("original_seats").and_then(json::Value::as_str),
            Some("ballot.tally.original_seats")
        );
    }
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentAttemptDraftRequestV1,
        >("iroha_torii_shared::parliament_api::ParliamentAttemptDraftRequestV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentAttemptDraftResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentAttemptDraftResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentAttemptReadResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentAttemptReadResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentBodyStateProjectionV1,
        >("iroha_torii_shared::parliament_api::ParliamentBodyStateProjectionV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentDecisionModeProjectionV1,
        >("iroha_torii_shared::parliament_api::ParliamentDecisionModeProjectionV1");
        crate::captured_identity_tests::assert_bidirectional::<super::ParliamentInstructionDraftV1>(
            "iroha_torii_shared::parliament_api::ParliamentInstructionDraftV1",
        );
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTransitionDraftRequestV1,
        >("iroha_torii_shared::parliament_api::ParliamentTransitionDraftRequestV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTransitionDraftResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentTransitionDraftResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::RequiredParliamentBodyProjectionV1,
        >("iroha_torii_shared::parliament_api::RequiredParliamentBodyProjectionV1");
    }
}
