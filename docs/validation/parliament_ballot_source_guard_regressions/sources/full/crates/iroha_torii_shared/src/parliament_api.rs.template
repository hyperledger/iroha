//! Public DTOs for authenticated SORA Parliament draft and read routes.
//!
//! Draft responses contain canonical framed instruction payloads for local
//! signing. Read responses expose a stable typed summary and the complete
//! canonical reducer payload, so independent auditors can retain the exact
//! state even while reducer internals evolve within the first release.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_crypto::Hash;
use iroha_data_model::isi::governance::{
    PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1, ParliamentLifecycleTransitionKindV1,
    ParliamentLifecycleTransitionV1,
};
use iroha_data_model::{
    NetworkId,
    governance::types::{
        BallotAttemptId, BallotAttemptStatusV1, BodyInstanceId, BodyInstanceStatusV1,
        GovernanceAttemptId, GovernanceAttemptV1, GovernanceCertificateV1,
        GovernanceExpectedHeadV1, MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1, ParliamentBody,
        ParliamentNoResultKindV1, ProposalContentId, ProposalKind, TleKeySessionId,
    },
    parliament_casting::{
        ParliamentTimedOvnCastingContextBindingV1,
        ParliamentTimedOvnCastingContextMembershipProofV1, ParliamentTimedOvnCastingWitnessProofV1,
    },
    sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityProof, verify_checkpoint_page,
    },
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
    /// Mandatory private timed-OVN binding ballot.
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
/// Private ballot records, shares, and plaintext votes remain outside this
/// projection; the terminal no-result class and height are safe audit facts.
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
    /// Safe progress for the active private timed-OVN ballot, when one exists.
    pub timed_ovn_progress: Option<ParliamentTimedOvnProgressProjectionV1>,
}

/// Public offset and lifecycle binding for one active private timed-OVN ballot.
///
/// This projection deliberately exposes only aggregate counts. It never
/// includes participant identifiers, registration or ballot records, roots,
/// shares, individual openings, or secret material.
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
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnProgressProjectionV1"
)]
pub struct ParliamentTimedOvnProgressProjectionV1 {
    /// Exact active ballot-attempt identifier.
    pub ballot_attempt_id: BallotAttemptId,
    /// Reducer-owned lifecycle status for the active ballot.
    pub status: BallotAttemptStatusV1,
    /// Exact frozen survivor count after survivor freeze, otherwise absent.
    pub frozen_survivor_count: Option<u32>,
    /// Proof-verified contiguous ballot prefix, or absent before survivor freeze.
    pub accepted_ballot_prefix_count: Option<u32>,
}

impl ParliamentTimedOvnProgressProjectionV1 {
    /// Validate the public count/status shape without inspecting private evidence.
    ///
    /// # Errors
    /// Returns a stable error when the active identifier is zero, count options
    /// disagree, a count exceeds the first-release corpus bound, or the prefix
    /// is not phase-consistent.
    pub fn validate_static(&self) -> Result<(), &'static str> {
        if self
            .ballot_attempt_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err("timed-OVN progress ballot attempt id must be non-zero");
        }
        match (
            self.frozen_survivor_count,
            self.accepted_ballot_prefix_count,
        ) {
            (None, None) => match self.status {
                BallotAttemptStatusV1::Registration
                | BallotAttemptStatusV1::SurvivorFreeze
                | BallotAttemptStatusV1::NoResult
                | BallotAttemptStatusV1::Superseded => Ok(()),
                _ => Err("timed-OVN progress must expose counts after survivor freeze"),
            },
            (Some(survivors), Some(prefix)) => {
                if survivors == 0
                    || survivors > MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1
                    || prefix > survivors
                {
                    return Err("timed-OVN progress counts violate the frozen corpus bound");
                }
                match self.status {
                    BallotAttemptStatusV1::TimedCommitment if prefix < survivors => Ok(()),
                    BallotAttemptStatusV1::AwaitingRelease
                    | BallotAttemptStatusV1::Opening
                    | BallotAttemptStatusV1::Finalized
                        if prefix == survivors =>
                    {
                        Ok(())
                    }
                    BallotAttemptStatusV1::NoResult | BallotAttemptStatusV1::Superseded => Ok(()),
                    _ => Err("timed-OVN progress prefix is inconsistent with ballot status"),
                }
            }
            _ => Err("timed-OVN progress survivor and prefix counts must appear together"),
        }
    }
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
    /// Ballots whose masked-ballot corpus a relayer freezes.
    pub relay_ballots: Vec<BallotAttemptId>,
    /// Ballots waiting for the combined TLE final release.
    pub finalize_ballots: Vec<BallotAttemptId>,
}

/// Maximum exact adaptive TLE committee size admitted by the first-release profile.
pub const PARLIAMENT_TLE_MAX_COMMITTEE_SIZE_V1: usize = 31;

/// Exact canonical application-identity payload width for Parliament TLE release.
pub const PARLIAMENT_TLE_RELEASE_IDENTITY_PAYLOAD_BYTES_V1: usize = 243;

/// Maximum complete canonical Norito frame for one public timed-OVN casting context.
pub const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1: usize = 4 * 1024 * 1024;

/// Maximum padded-standard-base64 width of one casting-context archive.
pub const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BASE64_BYTES_V1: usize =
    PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1.div_ceil(3) * 4;

/// Current consensus-authenticated casting-proof request and response layout.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1: u16 = 1;

/// Stable public Norito schema name for one casting-proof request.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1: &str =
    "iroha.torii.v1.parliament.timed_ovn_casting_proof.request";

/// Lowercase hash of [`PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1`]
/// under the Norito V1 type-name schema domain.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1: &str =
    "adccf322a5fcf43040e20bea238f55f3";

/// Stable public Norito schema name for one casting-proof response.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1: &str =
    "iroha.torii.v1.parliament.timed_ovn_casting_proof.response";

/// Lowercase hash of [`PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1`]
/// under the Norito V1 type-name schema domain.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1: &str =
    "46d29299272433b1299646bee722bd11";

/// Exact byte width of every canonical V1 casting-proof request frame.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1: usize = 52;

/// Exact Norito header flags for the compact-length casting-proof request.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1: u8 = 0x02;

/// Payload alignment advertised by the canonical V1 request layout.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1: usize = 8;

/// Header padding required by the canonical V1 request layout.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1: usize = 0;

/// Maximum consecutive finality proofs, including the caller-pinned checkpoint.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_PROOFS_V1: usize = 64;

/// Maximum canonical bytes occupied by one bounded finality page.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_CHAIN_BYTES_V1: usize = 3 * 1024 * 1024;

/// Defensive maximum for one complete consensus-authenticated casting response.
pub const PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_RESPONSE_BYTES_V1: usize = 8 * 1024 * 1024;

/// Select the farthest consecutive finality tip that fits one promotion page.
#[must_use]
pub fn parliament_timed_ovn_casting_proof_page_tip(
    trusted_checkpoint_height: u64,
    observed_ledger_tip_height: u64,
) -> Option<u64> {
    if trusted_checkpoint_height == 0 || trusted_checkpoint_height > observed_ledger_tip_height {
        return None;
    }
    let span = u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_PROOFS_V1 - 1)
        .expect("Parliament casting finality proof bound fits u64");
    Some(observed_ledger_tip_height.min(trusted_checkpoint_height.saturating_add(span)))
}

/// Request one bounded checkpoint-to-tip casting-proof page.
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
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingProofRequestV1",
    frame = "iroha.torii.v1.parliament.timed_ovn_casting_proof.request"
)]
pub struct ParliamentTimedOvnCastingProofRequestV1 {
    /// Request layout version.
    pub version: u16,
    /// Height of the externally trusted checkpoint that must begin the chain.
    pub trusted_checkpoint_height: u64,
}

/// Consensus-authenticated casting archive or one bounded checkpoint-promotion page.
///
/// Intermediate pages deliberately omit every casting field. Only a terminal
/// page (`more_available == false`) contains the archive, its archive-derived
/// compact binding, application-Merkle membership, and fixed ordinary-write
/// witness. A wallet must independently select the network id and complete native
/// checkpoint, verify this response, and rederive the compact binding
/// from the fully replay-validated archive before it touches secret seed bytes.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingProofResponseV1",
    frame = "iroha.torii.v1.parliament.timed_ovn_casting_proof.response"
)]
pub struct ParliamentTimedOvnCastingProofResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Canonical framed Core casting archive, present only at the observed tip.
    #[norito(required)]
    pub casting_context_archive: Option<Vec<u8>>,
    /// Compact archive-derived leaf committed by the evaluated block.
    #[norito(required)]
    pub casting_context_binding: Option<ParliamentTimedOvnCastingContextBindingV1>,
    /// Application-Merkle membership proof for `casting_context_binding`.
    #[norito(required)]
    pub context_membership_proof: Option<ParliamentTimedOvnCastingContextMembershipProofV1>,
    /// Fixed synthetic ordinary-write proof for the committed context-set root.
    #[norito(required)]
    pub casting_witness: Option<ParliamentTimedOvnCastingWitnessProofV1>,
    /// Consecutive finality proofs beginning at the caller's checkpoint.
    pub finality_chain: Vec<SumeragiFinalityProof>,
    /// Native decision digest at the evaluated tip; the verified checkpoint supplies promotion authority.
    pub evaluated_context_id: Hash,
    /// Height whose post-execution casting state was evaluated.
    pub evaluated_block_height: u64,
    /// Canonical lowercase hash of the evaluated committed block.
    pub evaluated_block_hash: String,
    /// Ledger tip observed when this bounded page was assembled.
    pub observed_ledger_tip_height: u64,
    /// Whether another checkpoint-promotion request is required.
    pub more_available: bool,
}

/// Cast-capable public phase of one Parliament timed-OVN ballot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, NoritoDeserialize, NoritoSerialize, norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingPhaseProjectionV1"
)]
pub enum ParliamentTimedOvnCastingPhaseProjectionV1 {
    /// Authenticated participant registrations are still accumulating.
    Registered,
    /// Registration is immutable and authenticated dropouts may accumulate.
    RegistrationClosed,
    /// The exact survivor subsequence and future release identity are frozen.
    SurvivorsFrozen,
}

impl norito::json::FastJsonWrite for ParliamentTimedOvnCastingPhaseProjectionV1 {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            Self::Registered => "Registered",
            Self::RegistrationClosed => "RegistrationClosed",
            Self::SurvivorsFrozen => "SurvivorsFrozen",
        };
        norito::json::write_json_string(label, out);
    }
}

impl norito::json::JsonDeserialize for ParliamentTimedOvnCastingPhaseProjectionV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        match parser.parse_string()?.as_str() {
            "Registered" => Ok(Self::Registered),
            "RegistrationClosed" => Ok(Self::RegistrationClosed),
            "SurvivorsFrozen" => Ok(Self::SurvivorsFrozen),
            other => Err(norito::json::Error::InvalidField {
                field: "phase".to_owned(),
                message: format!("unknown Parliament timed-OVN casting phase `{other}`"),
            }),
        }
    }
}

/// Immutable public bindings for one timed-OVN wallet session.
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
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnSessionProjectionV1")]
pub struct ParliamentTimedOvnSessionProjectionV1 {
    /// Canonical network/genesis binding.
    pub network_id: [u8; 32],
    /// Content identifier of the proposal being decided.
    pub proposal_content_id: ProposalContentId,
    /// Governance lifecycle-attempt binding.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Governed-body instance binding.
    pub body_instance_id: BodyInstanceId,
    /// Retryable ballot-attempt binding.
    pub ballot_attempt_id: BallotAttemptId,
    /// Commitment to the exact ballot/proof parameter profile.
    pub parameter_hash: [u8; 32],
    /// Long-lived TLE threshold-key session binding.
    pub tle_key_session_id: TleKeySessionId,
    /// Complete proof-validated adaptive TLE transcript binding.
    pub tle_key_transcript_hash: [u8; 32],
    /// Canonical compressed TLE threshold group public key in G2.
    pub tle_master_public_key: [u8; 96],
}

/// Public coefficient commitments and constant-term proof for one qualified dealer.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTleAdaptiveDealerCommitmentV1"
)]
pub struct ParliamentTleAdaptiveDealerCommitmentV1 {
    /// Canonical one-based dealer index.
    pub dealer_index: u16,
    /// Exact degree-`f` triple-generator coefficient commitments.
    pub coefficient_commitments: Vec<[u8; 96]>,
    /// Schnorr commitment proving knowledge of the unblinded constant term.
    pub constant_pok_commitment: [u8; 96],
    /// Canonical big-endian Schnorr response scalar.
    pub constant_pok_response: [u8; 32],
}

/// One public composite verification share in a finalized adaptive TLE transcript.
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
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTleAdaptivePublicShareV1")]
pub struct ParliamentTleAdaptivePublicShareV1 {
    /// Canonical one-based participant index.
    pub index: u16,
    /// Purpose- and roster-bound canonical seat digest.
    pub participant_hash: [u8; 32],
    /// Canonical compressed composite commitment `g^s h^r v^u`.
    pub public_key_share: [u8; 96],
}

/// Complete bounded public state for one proof-revalidated adaptive TLE session.
///
/// This projection intentionally mirrors every public field required to replay
/// the DKG transcript and independently verify partial releases. It contains no
/// dealer polynomial, aggregate signing share, proof nonce, or other secret.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTleKeySessionBindingV1")]
pub struct ParliamentTleKeySessionBindingV1 {
    /// Fixed public-state adapter version; must equal one.
    pub version: u16,
    /// Long-lived purpose-distinct TLE key-session identifier.
    pub key_session_id: TleKeySessionId,
    /// Canonical network/genesis binding.
    pub network_id: [u8; 32],
    /// Hash of the exact ordered threshold committee roster.
    pub roster_hash: [u8; 32],
    /// Exact `3f + 1` threshold committee size.
    pub committee_size: u16,
    /// Exact `f + 1` release threshold.
    pub threshold: u16,
    /// Purpose- and session-derived independent Pedersen generator `h`.
    pub generator_h: [u8; 96],
    /// Purpose- and session-derived independent Pedersen generator `v`.
    pub generator_v: [u8; 96],
    /// Strictly increasing qualified dealer indices.
    pub qualified_dealers: Vec<u16>,
    /// Proof-carrying public broadcasts aligned exactly with the qualified indices.
    pub qualified_dealer_commitments: Vec<ParliamentTleAdaptiveDealerCommitmentV1>,
    /// Consensus event hash binding DKG complaints, responses, and qualification.
    pub dkg_event_hash: [u8; 32],
    /// Canonical standard-generator aggregate public key.
    pub group_public_key: [u8; 96],
    /// Complete canonical sequence of composite participant verification shares.
    pub public_shares: Vec<ParliamentTleAdaptivePublicShareV1>,
    /// Commitment to the complete proof-validated adaptive transcript.
    pub transcript_hash: [u8; 32],
}

impl ParliamentTleKeySessionBindingV1 {
    /// Validate the complete bounded public transcript shape.
    ///
    /// This is a client-side structural gate. Core additionally replays every
    /// dealer proof and group equation before serving the projection.
    ///
    /// # Errors
    /// Returns a stable message for a wrong version, zero binding, invalid
    /// `3f + 1`/`f + 1` profile, reordered dealer set, or incomplete share set.
    pub fn validate_static(&self) -> Result<(), &'static str> {
        if self.version != PARLIAMENT_API_VERSION_V1 {
            return Err("unsupported Parliament TLE key-session version");
        }
        if is_zero(self.key_session_id.as_bytes())
            || is_zero(&self.network_id)
            || is_zero(&self.roster_hash)
            || is_zero(&self.generator_h)
            || is_zero(&self.generator_v)
            || is_zero(&self.dkg_event_hash)
            || is_zero(&self.group_public_key)
            || is_zero(&self.transcript_hash)
        {
            return Err("Parliament TLE key session contains a zero public binding");
        }
        let committee_size = usize::from(self.committee_size);
        let threshold = usize::from(self.threshold);
        if !(4..=PARLIAMENT_TLE_MAX_COMMITTEE_SIZE_V1).contains(&committee_size)
            || !(2..=11).contains(&threshold)
            || !(committee_size - 1).is_multiple_of(3)
            || threshold != (committee_size - 1) / 3 + 1
        {
            return Err("Parliament TLE committee is not an exact 3f+1/f+1 profile");
        }
        if self.qualified_dealers.len() < threshold
            || self.qualified_dealers.len() > committee_size
            || self.qualified_dealers.len() != self.qualified_dealer_commitments.len()
        {
            return Err("Parliament TLE qualified dealer set violates its exact bound");
        }
        let mut previous = 0_u16;
        for (dealer_index, commitment) in self
            .qualified_dealers
            .iter()
            .copied()
            .zip(&self.qualified_dealer_commitments)
        {
            if dealer_index <= previous
                || usize::from(dealer_index) > committee_size
                || commitment.dealer_index != dealer_index
                || commitment.coefficient_commitments.len() != threshold
                || commitment
                    .coefficient_commitments
                    .iter()
                    .any(|coefficient| is_zero(coefficient))
                || is_zero(&commitment.constant_pok_commitment)
            {
                return Err("Parliament TLE dealer transcript is not canonical");
            }
            previous = dealer_index;
        }
        if self.public_shares.len() != committee_size {
            return Err("Parliament TLE public shares do not cover the complete committee");
        }
        for (offset, share) in self.public_shares.iter().enumerate() {
            if usize::from(share.index) != offset + 1
                || is_zero(&share.participant_hash)
                || is_zero(&share.public_key_share)
            {
                return Err("Parliament TLE public shares are not the exact one-based sequence");
            }
        }
        Ok(())
    }
}

/// Public proof-carrying adaptive partial release returned by one signer node.
///
/// Every field is independently verifiable against the release context's full
/// public transcript. No secret share, proof nonce, or provider metadata is
/// represented by this DTO.
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
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTlePartialReleaseShareV1")]
pub struct ParliamentTlePartialReleaseShareV1 {
    /// Long-lived TLE key-session binding.
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

impl ParliamentTlePartialReleaseShareV1 {
    /// Validate public widths and bind this partial to one fetched release context.
    ///
    /// Core/CLI coordinators must additionally verify the proof equations before
    /// combining partials.
    ///
    /// # Errors
    /// Returns a stable message for a cross-session binding, invalid participant
    /// index, or inert public group element.
    pub fn validate_against(
        &self,
        context: &ParliamentTleReleaseContextResponseV1,
    ) -> Result<(), &'static str> {
        if self.key_session_id != context.tle_key_session.key_session_id
            || self.identity_digest != context.identity_digest
        {
            return Err("Parliament TLE partial differs from the authorized release context");
        }
        if self.participant_index == 0
            || self.participant_index > context.tle_key_session.committee_size
        {
            return Err("Parliament TLE partial participant index is outside the committee");
        }
        if is_zero(&self.sigma) || is_zero(&self.proof_x) || is_zero(&self.proof_y) {
            return Err("Parliament TLE partial contains an inert public proof element");
        }
        Ok(())
    }
}

/// Frozen public identity authorized for one timed-OVN aggregate release.
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
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnReleaseIdentityProjectionV1"
)]
pub struct ParliamentTimedOvnReleaseIdentityProjectionV1 {
    /// Long-lived TLE threshold key-session binding.
    pub tle_key_session_id: TleKeySessionId,
    /// Governance lifecycle-attempt binding.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Governed-body instance binding.
    pub body_instance_id: BodyInstanceId,
    /// Retryable ballot-attempt binding.
    pub ballot_attempt_id: BallotAttemptId,
    /// Replay-derived root of the exact frozen survivor corpus.
    pub survivor_corpus_root: [u8; 32],
    /// Replay-derived sentinel committing to no post-freeze recovery path.
    pub no_recovery_root: [u8; 32],
    /// First finalized height at which release is permitted.
    pub target_finalized_height: u64,
    /// Commitment to the exact ballot/proof parameter profile.
    pub parameter_hash: [u8; 32],
}

/// Replay-validated public preparation context for secret-local wallet operations.
///
/// The explicit fields support strict clients and human inspection. The
/// canonical archive is the single native-wallet input and contains the same
/// public state as one bounded, header-framed Norito value. Neither projection
/// contains masked ballots, dropout decisions, shares, openings, account
/// labels, or secret material.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingContextResponseV1"
)]
pub struct ParliamentTimedOvnCastingContextResponseV1 {
    /// Response and archive layout version; must equal one.
    pub version: u16,
    /// Committed finalized height used for Core authorization.
    pub current_height: u64,
    /// Exact cast-capable lifecycle phase.
    pub phase: ParliamentTimedOvnCastingPhaseProjectionV1,
    /// Immutable timed-OVN wallet-session bindings.
    pub session: ParliamentTimedOvnSessionProjectionV1,
    /// Finalized height at which authenticated registration opened.
    pub registration_opened_at_finalized_height: u64,
    /// Immutable first finalized height permitting TLE release.
    pub target_finalized_height: u64,
    /// Complete proof-revalidated public threshold transcript.
    pub tle_key_session: ParliamentTleKeySessionBindingV1,
    /// Ordered canonical registration-record corpus as exact lowercase hex.
    pub registration_records_hex: Vec<String>,
    /// Exact frozen survivor participant hashes, present only after survivor freeze.
    pub survivor_participant_hashes: Option<Vec<[u8; 32]>>,
    /// Exact frozen future release identity, present only after survivor freeze.
    pub release_identity: Option<ParliamentTimedOvnReleaseIdentityProjectionV1>,
    /// Padded-standard-base64 canonical framed `ParliamentTimedOvnCastingContextArchiveV1`.
    pub archive_norito_base64: String,
}

impl ParliamentTimedOvnCastingContextResponseV1 {
    /// Strictly validate all JSON-visible bindings and the bounded canonical base64 envelope.
    ///
    /// Native wallets must additionally decode and replay the canonical Norito
    /// archive before using it for proof generation. Core has already replayed
    /// the committed lifecycle and TLE transcript before serving this response.
    ///
    /// # Errors
    /// Returns a stable message for unsupported, oversized, noncanonical,
    /// cross-bound, or phase-inconsistent public state.
    pub fn validate_for_ballot(
        &self,
        expected_ballot_attempt_id: BallotAttemptId,
    ) -> Result<(), &'static str> {
        if self.version != PARLIAMENT_API_VERSION_V1 || self.current_height == 0 {
            return Err("unsupported Parliament timed-OVN casting-context version or height");
        }
        if is_zero(expected_ballot_attempt_id.as_bytes())
            || self.session.ballot_attempt_id != expected_ballot_attempt_id
            || is_zero(&self.session.network_id)
            || is_zero(self.session.proposal_content_id.as_bytes())
            || is_zero(self.session.governance_attempt_id.as_bytes())
            || is_zero(self.session.body_instance_id.as_bytes())
            || is_zero(&self.session.parameter_hash)
            || is_zero(self.session.tle_key_session_id.as_bytes())
            || is_zero(&self.session.tle_key_transcript_hash)
            || is_zero(&self.session.tle_master_public_key)
            || self.registration_opened_at_finalized_height == 0
            || self.registration_opened_at_finalized_height > self.current_height
            || self.target_finalized_height <= self.registration_opened_at_finalized_height
        {
            return Err("Parliament timed-OVN casting context has inconsistent session bindings");
        }
        self.tle_key_session.validate_static()?;
        if self.session.tle_key_session_id != self.tle_key_session.key_session_id
            || self.session.tle_key_transcript_hash != self.tle_key_session.transcript_hash
            || self.session.tle_master_public_key != self.tle_key_session.group_public_key
        {
            return Err("Parliament timed-OVN session differs from its public TLE transcript");
        }
        let max_corpus_entries = usize::try_from(MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1)
            .expect("V1 Parliament corpus bound fits usize");
        if self.registration_records_hex.len() > max_corpus_entries {
            return Err("Parliament timed-OVN registration corpus exceeds the protocol bound");
        }
        let mut registrations = std::collections::BTreeSet::new();
        for record in &self.registration_records_hex {
            if record.len() != PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 * 2
                || !record
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                || !registrations.insert(record)
            {
                return Err("Parliament timed-OVN registration corpus is not exact canonical hex");
            }
        }
        if self.phase != ParliamentTimedOvnCastingPhaseProjectionV1::Registered
            && self.registration_records_hex.is_empty()
        {
            return Err("closed Parliament timed-OVN registration corpus must be nonempty");
        }

        match self.phase {
            ParliamentTimedOvnCastingPhaseProjectionV1::Registered
            | ParliamentTimedOvnCastingPhaseProjectionV1::RegistrationClosed => {
                if self.survivor_participant_hashes.is_some() || self.release_identity.is_some() {
                    return Err("pre-freeze Parliament casting context exposes frozen state");
                }
            }
            ParliamentTimedOvnCastingPhaseProjectionV1::SurvivorsFrozen => {
                let survivors = self.survivor_participant_hashes.as_deref().ok_or(
                    "survivor-frozen Parliament casting context is missing survivor hashes",
                )?;
                let release_identity = self.release_identity.as_ref().ok_or(
                    "survivor-frozen Parliament casting context is missing release identity",
                )?;
                if survivors.is_empty()
                    || survivors.len() > self.registration_records_hex.len()
                    || survivors.len() > max_corpus_entries
                {
                    return Err("Parliament timed-OVN survivor corpus exceeds registration bounds");
                }
                let mut canonical_survivors = std::collections::BTreeSet::new();
                if survivors
                    .iter()
                    .any(|hash| is_zero(hash) || !canonical_survivors.insert(*hash))
                {
                    return Err("Parliament timed-OVN survivor hashes are zero or duplicated");
                }
                if release_identity.tle_key_session_id != self.session.tle_key_session_id
                    || release_identity.governance_attempt_id != self.session.governance_attempt_id
                    || release_identity.body_instance_id != self.session.body_instance_id
                    || release_identity.ballot_attempt_id != self.session.ballot_attempt_id
                    || release_identity.target_finalized_height != self.target_finalized_height
                    || release_identity.parameter_hash != self.session.parameter_hash
                    || is_zero(&release_identity.survivor_corpus_root)
                    || is_zero(&release_identity.no_recovery_root)
                {
                    return Err(
                        "Parliament timed-OVN frozen release identity has inconsistent bindings",
                    );
                }
            }
        }

        if self.archive_norito_base64.is_empty()
            || self.archive_norito_base64.len()
                > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BASE64_BYTES_V1
        {
            return Err("Parliament timed-OVN casting archive exceeds its base64 bound");
        }
        let archive = BASE64_STANDARD
            .decode(self.archive_norito_base64.as_bytes())
            .map_err(|_| "Parliament timed-OVN casting archive is invalid base64")?;
        if archive.is_empty()
            || archive.len() > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1
            || BASE64_STANDARD.encode(&archive) != self.archive_norito_base64
        {
            return Err("Parliament timed-OVN casting archive is not canonical padded base64");
        }
        Ok(())
    }
}

impl ParliamentTimedOvnCastingProofResponseV1 {
    /// Verify the checkpoint-to-tip finality page and, on the terminal page,
    /// the fixed ordinary write plus application-Merkle membership.
    ///
    /// This portable layer cannot decode Core's casting archive type. A wallet
    /// must additionally decode/replay `casting_context_archive`, rederive its
    /// compact binding, and require byte-for-byte equality with the binding
    /// returned here before using any secret seed.
    ///
    /// # Errors
    /// Returns a stable explanation for a malformed page, mismatched external
    /// trust anchor, invalid finality, invalid witness, or wrong ballot leaf.
    pub fn verify_consensus_page_against(
        &self,
        network_id: NetworkId,
        trusted_checkpoint: &SumeragiFinalityCheckpoint,
        expected_ballot_attempt_id: BallotAttemptId,
    ) -> Result<
        (
            Option<&ParliamentTimedOvnCastingContextBindingV1>,
            SumeragiFinalityCheckpoint,
        ),
        String,
    > {
        if self.version != PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1
            || trusted_checkpoint.height() == 0
            || self.evaluated_block_height == 0
            || self.observed_ledger_tip_height < self.evaluated_block_height
            || self.more_available
                != (self.evaluated_block_height < self.observed_ledger_tip_height)
        {
            return Err(
                "unsupported Parliament casting proof version or invalid trust anchor".into(),
            );
        }
        parliament_casting_require_canonical_hash(
            "Parliament casting network id",
            network_id.as_bytes(),
        )?;
        if expected_ballot_attempt_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err("expected Parliament casting ballot id is zero".into());
        }
        let evaluated_block_hash = parliament_casting_exact_lower_hex_32(
            "evaluated_block_hash",
            &self.evaluated_block_hash,
        )?;
        parliament_casting_require_canonical_hash(
            "evaluated Parliament casting block hash",
            &evaluated_block_hash,
        )?;
        require_casting_finality_chain_count(&self.finality_chain)?;
        let page = verify_checkpoint_page(
            network_id,
            trusted_checkpoint,
            &self.finality_chain,
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_PROOFS_V1,
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_CHAIN_BYTES_V1,
        )
        .map_err(|error| format!("native finality page failed: {error}"))?;
        let evaluated = page.tip();
        if evaluated.height() != self.evaluated_block_height
            || evaluated.header().hash().as_ref() != &evaluated_block_hash
            || self.evaluated_context_id != evaluated.context_id()
        {
            return Err(
                "native finality page tip does not match the evaluated application block".into(),
            );
        }
        // The verified page already validated the complete native result commitment.
        // Application witnesses below stay bound to that same authenticated tip.
        let casting_fields = (
            self.casting_context_archive.as_ref(),
            self.casting_context_binding.as_ref(),
            self.context_membership_proof.as_ref(),
            self.casting_witness.as_ref(),
        );
        if self.more_available {
            if !matches!(casting_fields, (None, None, None, None)) {
                return Err("checkpoint-promotion page unexpectedly contains casting state".into());
            }
            return Ok((None, page.into_checkpoint()));
        }
        let (Some(archive), Some(binding), Some(membership), Some(witness)) = casting_fields else {
            return Err("terminal Parliament casting proof is incomplete".into());
        };
        if archive.is_empty()
            || archive.len() > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1
        {
            return Err("terminal Parliament casting archive exceeds its byte bound".into());
        }
        if binding.evaluated_height != evaluated.height()
            || binding.network_id != *network_id.as_bytes()
            || binding.ballot_attempt_id != expected_ballot_attempt_id
            || !binding.is_valid()
        {
            return Err(
                "Parliament casting binding differs from the expected ballot or block".into(),
            );
        }
        if !witness.verify(evaluated.execution().ordinary_writes_root) {
            return Err("Parliament casting synthetic ordinary-write proof is invalid".into());
        }
        let snapshot = witness.commitment()?;
        if snapshot.evaluated_height != evaluated.height() {
            return Err("Parliament casting snapshot height differs from finality".into());
        }
        if !membership.verify(binding, &snapshot) {
            return Err("Parliament casting context membership proof is invalid".into());
        }
        Ok((Some(binding), page.into_checkpoint()))
    }
}

fn require_casting_finality_chain_count(proofs: &[SumeragiFinalityProof]) -> Result<(), String> {
    if proofs.is_empty() || proofs.len() > PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_PROOFS_V1
    {
        return Err("Parliament casting finality chain is empty or exceeds 64 proofs".into());
    }
    Ok(())
}

fn parliament_casting_exact_lower_hex_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{label} is invalid hexadecimal"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly 32 bytes"))
}

fn parliament_casting_require_canonical_hash(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if value.iter().all(|byte| *byte == 0) || value[31] & 1 == 0 {
        return Err(format!("{label} is not a canonical Iroha hash"));
    }
    Ok(())
}

/// Constructor-authenticated public context for one Parliament TLE release.
///
/// This response exists only while the committed ballot is `Opening`, its
/// sealed timed-OVN corpus replays successfully, the target height has arrived,
/// and the inclusive opening deadline has not passed. It never includes
/// registrations, masked ballots, secret shares, partial releases, or openings.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::parliament_api::ParliamentTleReleaseContextResponseV1")]
pub struct ParliamentTleReleaseContextResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Committed finalized height used for Core authorization.
    pub current_height: u64,
    /// Exact ballot attempt authorized for threshold release.
    pub ballot_attempt_id: BallotAttemptId,
    /// Governance attempt bound into the release identity.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Body instance bound into the release identity.
    pub body_instance_id: BodyInstanceId,
    /// Committed ballot lifecycle status; always `Opening` for an authorized response.
    pub status: BallotAttemptStatusV1,
    /// First finalized height permitted to release the aggregate.
    pub release_height: u64,
    /// Inclusive last finalized height at which aggregate opening may complete.
    pub opening_deadline_height: u64,
    /// Proof-revalidated public threshold-transcript binding.
    pub tle_key_session: ParliamentTleKeySessionBindingV1,
    /// Exact frozen timed-OVN future release identity.
    pub release_identity: ParliamentTimedOvnReleaseIdentityProjectionV1,
    /// SHA-256 of the exact threshold-session-framed release message.
    pub identity_digest: [u8; 32],
    /// Lowercase hexadecimal canonical application identity payload.
    pub identity_payload_hex: String,
}

impl ParliamentTleReleaseContextResponseV1 {
    /// Strictly validate a release projection against the requested ballot id.
    ///
    /// This reproduces the exact identity payload and threshold-session message
    /// digest in addition to validating the full bounded transcript shape.
    /// Core remains authoritative for committed-state authorization and the DKG
    /// proof equations.
    ///
    /// # Errors
    /// Returns a stable message for any unsupported, noncanonical, cross-bound,
    /// out-of-window, or digest-inconsistent response.
    pub fn validate_for_ballot(
        &self,
        expected_ballot_attempt_id: BallotAttemptId,
    ) -> Result<(), &'static str> {
        use sha2::{Digest as _, Sha256};

        if self.version != PARLIAMENT_API_VERSION_V1 {
            return Err("unsupported Parliament TLE release-context version");
        }
        if is_zero(expected_ballot_attempt_id.as_bytes())
            || self.ballot_attempt_id != expected_ballot_attempt_id
        {
            return Err("Parliament TLE release context differs from the requested ballot");
        }
        if self.status != BallotAttemptStatusV1::Opening {
            return Err("Parliament TLE release context is not in Opening");
        }
        if self.current_height == 0
            || self.release_height == 0
            || self.opening_deadline_height == 0
            || self.current_height < self.release_height
            || self.current_height > self.opening_deadline_height
            || self.opening_deadline_height < self.release_height
        {
            return Err("Parliament TLE release context is outside its inclusive height window");
        }
        self.tle_key_session.validate_static()?;
        let identity = &self.release_identity;
        if is_zero(self.governance_attempt_id.as_bytes())
            || is_zero(self.body_instance_id.as_bytes())
            || identity.tle_key_session_id != self.tle_key_session.key_session_id
            || identity.governance_attempt_id != self.governance_attempt_id
            || identity.body_instance_id != self.body_instance_id
            || identity.ballot_attempt_id != self.ballot_attempt_id
            || identity.target_finalized_height != self.release_height
            || is_zero(&identity.survivor_corpus_root)
            || is_zero(&identity.no_recovery_root)
            || is_zero(&identity.parameter_hash)
        {
            return Err("Parliament TLE release identity has inconsistent public bindings");
        }
        if self.identity_payload_hex.len() != PARLIAMENT_TLE_RELEASE_IDENTITY_PAYLOAD_BYTES_V1 * 2
            || !self
                .identity_payload_hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("Parliament TLE release identity payload is not canonical lowercase hex");
        }
        let payload = hex::decode(&self.identity_payload_hex)
            .map_err(|_| "Parliament TLE release identity payload is invalid hex")?;
        validate_release_identity_payload(self, &payload)?;

        let mut message = Vec::with_capacity(128 + payload.len());
        message.extend_from_slice(b"iroha.threshold-bls.message.v1\0");
        message.extend_from_slice(b"iroha.threshold-bls.session.v1\0");
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.push(2);
        message.extend_from_slice(&self.tle_key_session.network_id);
        message.extend_from_slice(self.tle_key_session.key_session_id.as_bytes());
        message.extend_from_slice(&self.tle_key_session.roster_hash);
        message.extend_from_slice(&self.tle_key_session.committee_size.to_be_bytes());
        message.extend_from_slice(&self.tle_key_session.threshold.to_be_bytes());
        message.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| "Parliament TLE release identity payload is too large")?
                .to_be_bytes(),
        );
        message.extend_from_slice(&payload);
        let expected_digest: [u8; 32] = Sha256::digest(&message).into();
        if self.identity_digest != expected_digest {
            return Err("Parliament TLE release identity digest is not canonical");
        }
        Ok(())
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn validate_release_identity_payload(
    context: &ParliamentTleReleaseContextResponseV1,
    payload: &[u8],
) -> Result<(), &'static str> {
    const DOMAIN: &[u8] = b"iroha.parliament.tle.identity-payload.v1\0";
    if payload.len() != PARLIAMENT_TLE_RELEASE_IDENTITY_PAYLOAD_BYTES_V1
        || !payload.starts_with(DOMAIN)
    {
        return Err("Parliament TLE release identity payload has the wrong domain or width");
    }
    let identity = &context.release_identity;
    let mut offset = DOMAIN.len();
    if payload[offset..offset + 2] != 1_u16.to_be_bytes() {
        return Err("Parliament TLE release identity payload has the wrong version");
    }
    offset += 2;
    for expected in [
        context.governance_attempt_id.as_bytes(),
        context.body_instance_id.as_bytes(),
        context.ballot_attempt_id.as_bytes(),
        &identity.survivor_corpus_root,
        &identity.no_recovery_root,
    ] {
        if payload[offset..offset + 32] != expected[..] {
            return Err("Parliament TLE release identity payload has a mismatched binding");
        }
        offset += 32;
    }
    if payload[offset..offset + 8] != context.release_height.to_be_bytes() {
        return Err("Parliament TLE release identity payload has a mismatched release height");
    }
    offset += 8;
    if payload[offset..offset + 32] != identity.parameter_hash {
        return Err("Parliament TLE release identity payload has a mismatched parameter hash");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_catalog::runtime_governance as gov_routes;
    use iroha_data_model::governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal,
        MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
    };
    use iroha_data_model::isi::governance::{
        PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
        PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1,
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

    #[test]
    fn casting_proof_page_tip_is_bounded_and_checkpoint_inclusive() {
        assert_eq!(parliament_timed_ovn_casting_proof_page_tip(0, 10), None);
        assert_eq!(parliament_timed_ovn_casting_proof_page_tip(11, 10), None);
        assert_eq!(parliament_timed_ovn_casting_proof_page_tip(7, 7), Some(7));
        assert_eq!(
            parliament_timed_ovn_casting_proof_page_tip(7, 1_000),
            Some(70)
        );
    }

    #[test]
    fn casting_proof_schema_hashes_and_frames_are_golden() {
        let request_hash = norito::core::schema_hash_for_name(
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1,
        );
        assert_eq!(
            hex::encode(request_hash),
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<ParliamentTimedOvnCastingProofRequestV1>(),
            request_hash
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<ParliamentTimedOvnCastingProofRequestV1>(),
            request_hash
        );
        let request = ParliamentTimedOvnCastingProofRequestV1 {
            version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
            trusted_checkpoint_height: 17,
        };
        let request_bytes = norito::to_bytes(&request).expect("encode casting proof request");
        assert_eq!(
            request_bytes.len(),
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1
        );
        assert_eq!(
            hex::encode(&request_bytes),
            "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000dfab61022cefc29f02020100081100000000000000"
        );

        let response_hash = norito::core::schema_hash_for_name(
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1,
        );
        assert_eq!(
            hex::encode(response_hash),
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<ParliamentTimedOvnCastingProofResponseV1>(),
            response_hash
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<ParliamentTimedOvnCastingProofResponseV1>(),
            response_hash
        );
        let response = ParliamentTimedOvnCastingProofResponseV1 {
            version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
            casting_context_archive: None,
            casting_context_binding: None,
            context_membership_proof: None,
            casting_witness: None,
            finality_chain: Vec::new(),
            evaluated_context_id: Hash::prehashed([3; 32]),
            evaluated_block_height: 17,
            evaluated_block_hash: hex::encode([5; 32]),
            observed_ledger_tip_height: 17,
            more_available: false,
        };
        let response_bytes = norito::to_bytes(&response).expect("encode casting proof response");
        assert_eq!(
            hex::encode(&response_bytes[..22]),
            "4e525430000046d29299272433b1299646bee722bd11"
        );
    }

    #[test]
    fn casting_proof_request_roundtrips_and_empty_chain_fails_closed() {
        let request = ParliamentTimedOvnCastingProofRequestV1 {
            version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
            trusted_checkpoint_height: 17,
        };
        let encoded = norito::to_bytes(&request).expect("encode casting proof request");
        assert_eq!(
            norito::decode_from_bytes::<ParliamentTimedOvnCastingProofRequestV1>(&encoded)
                .expect("decode casting proof request"),
            request
        );
        assert_eq!(
            require_casting_finality_chain_count(&[]).unwrap_err(),
            "Parliament casting finality chain is empty or exceeds 64 proofs"
        );
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
    fn timed_ovn_progress_enforces_phase_consistent_prefixes() {
        let ballot_attempt_id = BallotAttemptId::new([0x42; 32]);
        let mut progress = ParliamentTimedOvnProgressProjectionV1 {
            ballot_attempt_id,
            status: BallotAttemptStatusV1::Registration,
            frozen_survivor_count: None,
            accepted_ballot_prefix_count: None,
        };
        assert_eq!(progress.validate_static(), Ok(()));

        progress.status = BallotAttemptStatusV1::TimedCommitment;
        progress.frozen_survivor_count = Some(3);
        progress.accepted_ballot_prefix_count = Some(0);
        assert_eq!(progress.validate_static(), Ok(()));
        progress.accepted_ballot_prefix_count = Some(2);
        assert_eq!(progress.validate_static(), Ok(()));
        progress.accepted_ballot_prefix_count = Some(3);
        assert!(progress.validate_static().is_err());

        progress.status = BallotAttemptStatusV1::AwaitingRelease;
        assert_eq!(progress.validate_static(), Ok(()));
        progress.accepted_ballot_prefix_count = Some(2);
        assert!(progress.validate_static().is_err());
        progress.accepted_ballot_prefix_count = None;
        assert!(progress.validate_static().is_err());

        progress.status = BallotAttemptStatusV1::NoResult;
        progress.frozen_survivor_count = None;
        assert_eq!(progress.validate_static(), Ok(()));
    }

    #[test]
    fn timed_ovn_progress_rejects_unknown_json_fields() {
        let progress = ParliamentTimedOvnProgressProjectionV1 {
            ballot_attempt_id: BallotAttemptId::new([0x42; 32]),
            status: BallotAttemptStatusV1::TimedCommitment,
            frozen_survivor_count: Some(3),
            accepted_ballot_prefix_count: Some(1),
        };
        let mut value = json::to_value(&progress).expect("render timed-OVN progress JSON");
        value
            .as_object_mut()
            .expect("timed-OVN progress object")
            .insert("ballot_records".to_owned(), json::Value::Array(Vec::new()));
        assert!(json::from_value::<ParliamentTimedOvnProgressProjectionV1>(value).is_err());
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
    fn transition_static_bounds_cover_authenticated_registration_and_ballot_corpus() {
        use iroha_data_model::isi::governance::{
            ParliamentFreezeTimedOvnCorpusV1, ParliamentRegisterBallotParticipantV1,
        };

        let ballot_attempt_id =
            iroha_data_model::governance::types::BallotAttemptId::new([0x44; 32]);
        let registration = |len| {
            transition_request(ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                ParliamentRegisterBallotParticipantV1 {
                    ballot_attempt_id,
                    registration_record: vec![0x55; len],
                },
            ))
        };
        assert!(
            registration(PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1)
                .validate_static()
                .is_ok()
        );
        assert!(
            registration(PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 - 1)
                .validate_static()
                .is_err()
        );

        let corpus = |records: Vec<Vec<u8>>| {
            transition_request(ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                ParliamentFreezeTimedOvnCorpusV1 {
                    ballot_attempt_id,
                    ballot_records: records,
                },
            ))
        };
        assert!(
            corpus(vec![vec![
                0x66;
                PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1
            ]])
            .validate_static()
            .is_ok()
        );
        assert!(
            corpus(vec![
                vec![0x66; PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1];
                PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1
            ])
            .validate_static()
            .is_ok()
        );
        assert!(corpus(Vec::new()).validate_static().is_err());
        assert!(
            corpus(vec![vec![
                0x66;
                PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1 - 1
            ]])
            .validate_static()
            .is_err()
        );
        assert!(
            corpus(vec![
                vec![0x66; PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1];
                PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1 + 1
            ])
            .validate_static()
            .is_err()
        );
    }

    fn tle_release_context_fixture() -> ParliamentTleReleaseContextResponseV1 {
        use sha2::{Digest as _, Sha256};

        let ballot_attempt_id = BallotAttemptId::new([0x33; 32]);
        let governance_attempt_id = GovernanceAttemptId::new([0x11; 32]);
        let body_instance_id = BodyInstanceId::new([0x22; 32]);
        let key_session_id = TleKeySessionId::new([0x44; 32]);
        let tle_key_session = ParliamentTleKeySessionBindingV1 {
            version: PARLIAMENT_API_VERSION_V1,
            key_session_id,
            network_id: [0x45; 32],
            roster_hash: [0x46; 32],
            committee_size: 4,
            threshold: 2,
            generator_h: [0x47; 96],
            generator_v: [0x48; 96],
            qualified_dealers: vec![1, 2],
            qualified_dealer_commitments: vec![
                ParliamentTleAdaptiveDealerCommitmentV1 {
                    dealer_index: 1,
                    coefficient_commitments: vec![[0x49; 96], [0x4A; 96]],
                    constant_pok_commitment: [0x4B; 96],
                    constant_pok_response: [0x4C; 32],
                },
                ParliamentTleAdaptiveDealerCommitmentV1 {
                    dealer_index: 2,
                    coefficient_commitments: vec![[0x4D; 96], [0x4E; 96]],
                    constant_pok_commitment: [0x4F; 96],
                    constant_pok_response: [0x50; 32],
                },
            ],
            dkg_event_hash: [0x51; 32],
            group_public_key: [0x52; 96],
            public_shares: (1_u16..=4)
                .map(|index| ParliamentTleAdaptivePublicShareV1 {
                    index,
                    participant_hash: [u8::try_from(index).expect("small index") + 0x52; 32],
                    public_key_share: [u8::try_from(index).expect("small index") + 0x62; 96],
                })
                .collect(),
            transcript_hash: [0x53; 32],
        };
        let release_identity = ParliamentTimedOvnReleaseIdentityProjectionV1 {
            tle_key_session_id: key_session_id,
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            survivor_corpus_root: [0x54; 32],
            no_recovery_root: [0x55; 32],
            target_finalized_height: 90,
            parameter_hash: [0x56; 32],
        };
        let mut identity_payload = Vec::new();
        identity_payload.extend_from_slice(b"iroha.parliament.tle.identity-payload.v1\0");
        identity_payload.extend_from_slice(&1_u16.to_be_bytes());
        identity_payload.extend_from_slice(governance_attempt_id.as_bytes());
        identity_payload.extend_from_slice(body_instance_id.as_bytes());
        identity_payload.extend_from_slice(ballot_attempt_id.as_bytes());
        identity_payload.extend_from_slice(&release_identity.survivor_corpus_root);
        identity_payload.extend_from_slice(&release_identity.no_recovery_root);
        identity_payload.extend_from_slice(&release_identity.target_finalized_height.to_be_bytes());
        identity_payload.extend_from_slice(&release_identity.parameter_hash);
        assert_eq!(
            identity_payload.len(),
            PARLIAMENT_TLE_RELEASE_IDENTITY_PAYLOAD_BYTES_V1
        );

        let mut release_message = Vec::new();
        release_message.extend_from_slice(b"iroha.threshold-bls.message.v1\0");
        release_message.extend_from_slice(b"iroha.threshold-bls.session.v1\0");
        release_message.extend_from_slice(&1_u16.to_be_bytes());
        release_message.push(2);
        release_message.extend_from_slice(&tle_key_session.network_id);
        release_message.extend_from_slice(tle_key_session.key_session_id.as_bytes());
        release_message.extend_from_slice(&tle_key_session.roster_hash);
        release_message.extend_from_slice(&tle_key_session.committee_size.to_be_bytes());
        release_message.extend_from_slice(&tle_key_session.threshold.to_be_bytes());
        release_message.extend_from_slice(
            &u32::try_from(identity_payload.len())
                .expect("identity width fits u32")
                .to_be_bytes(),
        );
        release_message.extend_from_slice(&identity_payload);

        ParliamentTleReleaseContextResponseV1 {
            version: PARLIAMENT_API_VERSION_V1,
            current_height: 100,
            ballot_attempt_id,
            governance_attempt_id,
            body_instance_id,
            status: BallotAttemptStatusV1::Opening,
            release_height: 90,
            opening_deadline_height: 110,
            tle_key_session,
            release_identity,
            identity_digest: Sha256::digest(release_message).into(),
            identity_payload_hex: hex::encode(identity_payload),
        }
    }

    #[test]
    fn tle_release_context_and_partial_are_strictly_cross_bound() {
        let context = tle_release_context_fixture();
        context
            .validate_for_ballot(context.ballot_attempt_id)
            .expect("strict release-context fixture");

        let mut partial = ParliamentTlePartialReleaseShareV1 {
            key_session_id: context.tle_key_session.key_session_id,
            identity_digest: context.identity_digest,
            participant_index: 2,
            sigma: [0x71; 48],
            proof_x: [0x72; 96],
            proof_y: [0x73; 48],
            z_s: [0x74; 32],
            z_r: [0x75; 32],
            z_u: [0x76; 32],
        };
        partial
            .validate_against(&context)
            .expect("bound public partial");
        partial.participant_index = 5;
        assert!(partial.validate_against(&context).is_err());

        let mut incomplete = context.clone();
        incomplete.tle_key_session.public_shares.pop();
        assert!(
            incomplete
                .validate_for_ballot(incomplete.ballot_attempt_id)
                .is_err()
        );
        let mut wrong_payload = context;
        wrong_payload.identity_payload_hex.replace_range(0..2, "00");
        assert!(
            wrong_payload
                .validate_for_ballot(wrong_payload.ballot_attempt_id)
                .is_err()
        );
    }

    #[test]
    fn timed_ovn_casting_context_enforces_phase_corpus_and_archive_bounds() {
        let release = tle_release_context_fixture();
        let ballot_attempt_id = release.ballot_attempt_id;
        let mut context = ParliamentTimedOvnCastingContextResponseV1 {
            version: PARLIAMENT_API_VERSION_V1,
            current_height: 60,
            phase: ParliamentTimedOvnCastingPhaseProjectionV1::Registered,
            session: ParliamentTimedOvnSessionProjectionV1 {
                network_id: release.tle_key_session.network_id,
                proposal_content_id: ProposalContentId::new([0x10; 32]),
                governance_attempt_id: release.governance_attempt_id,
                body_instance_id: release.body_instance_id,
                ballot_attempt_id,
                parameter_hash: release.release_identity.parameter_hash,
                tle_key_session_id: release.tle_key_session.key_session_id,
                tle_key_transcript_hash: release.tle_key_session.transcript_hash,
                tle_master_public_key: release.tle_key_session.group_public_key,
            },
            registration_opened_at_finalized_height: 50,
            target_finalized_height: 90,
            tle_key_session: release.tle_key_session,
            registration_records_hex: vec![hex::encode(vec![
                0x81;
                PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1
            ])],
            survivor_participant_hashes: None,
            release_identity: None,
            archive_norito_base64: BASE64_STANDARD.encode(b"NRT0"),
        };
        context
            .validate_for_ballot(ballot_attempt_id)
            .expect("strict pre-freeze casting context");

        let mut empty_closed = context.clone();
        empty_closed.phase = ParliamentTimedOvnCastingPhaseProjectionV1::RegistrationClosed;
        empty_closed.registration_records_hex.clear();
        assert!(empty_closed.validate_for_ballot(ballot_attempt_id).is_err());

        context.phase = ParliamentTimedOvnCastingPhaseProjectionV1::SurvivorsFrozen;
        assert!(context.validate_for_ballot(ballot_attempt_id).is_err());
        context.phase = ParliamentTimedOvnCastingPhaseProjectionV1::Registered;
        context.registration_records_hex[0].pop();
        assert!(context.validate_for_ballot(ballot_attempt_id).is_err());

        let mut value = json::to_value(&context).expect("render casting-context JSON");
        value
            .as_object_mut()
            .expect("casting-context object")
            .insert("unexpected".to_owned(), json::Value::Bool(true));
        assert!(json::from_value::<ParliamentTimedOvnCastingContextResponseV1>(value).is_err());
        assert!(
            json::from_str::<ParliamentTimedOvnCastingPhaseProjectionV1>("\"registered\"").is_err()
        );
    }

    #[test]
    fn full_state_payload_bound_is_not_smaller_than_private_corpus_bound() {
        const {
            assert!(
                iroha_data_model::governance::types::MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1
                    >= 1_000 * (3_624 + 2_858)
            );
        }
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
            routes
                .get("timed_ovn_casting_context_read")
                .and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ.path())
        );
        assert_eq!(
            routes
                .get("timed_ovn_casting_proof")
                .and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TIMED_OVN_CASTING_PROOF.path())
        );
        assert_eq!(
            routes
                .get("tle_release_context_read")
                .and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TLE_RELEASE_CONTEXT_READ.path())
        );
        assert_eq!(
            routes
                .get("tle_partial_release")
                .and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TLE_PARTIAL_RELEASE.path())
        );
        assert_eq!(
            routes.get("transition_draft").and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TRANSITION_DRAFT.path())
        );
        let native_wallet = fixture
            .get("timed_ovn_native_wallet")
            .and_then(json::Value::as_object)
            .expect("fixture native timed-OVN wallet contract");
        assert_eq!(
            native_wallet
                .get("bridge_abi")
                .and_then(json::Value::as_u64),
            Some(24)
        );
        assert_eq!(
            native_wallet
                .get("sole_input_schema")
                .and_then(json::Value::as_str),
            Some("ParliamentTimedOvnCastingProofResponseV1")
        );
        assert_eq!(
            native_wallet
                .get("request_norito_schema")
                .and_then(json::Value::as_str),
            Some(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1)
        );
        assert_eq!(
            native_wallet
                .get("response_norito_schema")
                .and_then(json::Value::as_str),
            Some(PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1)
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_request_schema_hash_hex")
                .and_then(json::Value::as_str),
            Some(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1)
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_response_schema_hash_hex")
                .and_then(json::Value::as_str),
            Some(PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1)
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_request_version")
                .and_then(json::Value::as_u64),
            Some(u64::from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1))
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_request_flags")
                .and_then(json::Value::as_u64),
            Some(u64::from(
                PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1
            ))
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_request_payload_alignment")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1)
                    .expect("request alignment fits u64")
            )
        );
        assert_eq!(
            native_wallet
                .get("casting_proof_request_padding_bytes")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1)
                    .expect("request padding fits u64")
            )
        );
        let request_golden = native_wallet
            .get("casting_proof_request_golden")
            .and_then(json::Value::as_object)
            .expect("fixture casting-proof request golden");
        assert_eq!(
            request_golden
                .get("trusted_checkpoint_height")
                .and_then(json::Value::as_u64),
            Some(17)
        );
        assert_eq!(
            request_golden
                .get("payload_hex")
                .and_then(json::Value::as_str),
            Some("020100081100000000000000")
        );
        assert_eq!(
            request_golden
                .get("frame_hex")
                .and_then(json::Value::as_str),
            Some(
                "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000dfab61022cefc29f02020100081100000000000000"
            )
        );
        assert_eq!(
            request_golden
                .get("frame_bytes")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1)
                    .expect("request width fits u64")
            )
        );
        assert_eq!(
            native_wallet.get("route").and_then(json::Value::as_str),
            Some(gov_routes::GOV_PARLIAMENT_TIMED_OVN_CASTING_PROOF.path())
        );
        let trust_anchor = native_wallet
            .get("required_external_trust_anchor")
            .and_then(json::Value::as_array)
            .expect("fixture native timed-OVN trust anchor");
        assert_eq!(
            trust_anchor
                .iter()
                .map(|field| field.as_str().expect("trust-anchor field"))
                .collect::<Vec<_>>(),
            [
                "network_id",
                "trusted_checkpoint_height",
                "trusted_checkpoint_context_id",
                "expected_ballot_attempt_id",
            ]
        );
        let verification_order = native_wallet
            .get("verification_order")
            .and_then(json::Value::as_array)
            .expect("fixture native timed-OVN verification order");
        assert_eq!(
            verification_order
                .iter()
                .map(|gate| gate.as_str().expect("verification gate"))
                .collect::<Vec<_>>(),
            [
                "canonical_response",
                "checkpoint_finality_chain",
                "page_shape",
                "checkpoint_promotion",
                "terminal_fixed_ordinary_write_witness_if_present",
                "terminal_casting_context_membership_if_present",
                "terminal_canonical_core_archive_if_present",
                "terminal_core_archive_replay_if_present",
                "terminal_exact_compact_binding_if_present",
                "seed_access_terminal_only",
            ]
        );
        assert_eq!(
            native_wallet
                .get("intermediate_page_secret_access")
                .and_then(json::Value::as_str),
            Some("forbidden")
        );
        assert_eq!(
            native_wallet
                .get("archive_only_wallet_input")
                .and_then(json::Value::as_str),
            Some("forbidden")
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
        assert_eq!(
            limits
                .get("timed_ovn_casting_proof_request_bytes")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1)
                    .expect("proof request bound fits u64")
            )
        );
        assert_eq!(
            limits
                .get("timed_ovn_casting_proof_response_bytes")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_RESPONSE_BYTES_V1)
                    .expect("proof response bound fits u64")
            )
        );
        assert_eq!(
            limits
                .get("timed_ovn_casting_proof_finality_entries")
                .and_then(json::Value::as_u64),
            Some(
                u64::try_from(PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_PROOFS_V1)
                    .expect("proof finality bound fits u64")
            )
        );
        assert_eq!(
            limits
                .get("timed_ovn_casting_proof_page_result_bytes")
                .and_then(json::Value::as_u64),
            Some(41)
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
            Some(9)
        );
        assert_eq!(
            body_state
                .get("deadline_semantics")
                .and_then(json::Value::as_str),
            Some("inclusive")
        );
        let progress = fixture
            .get("timed_ovn_progress")
            .and_then(json::Value::as_object)
            .expect("timed-OVN progress projection fixture");
        assert_eq!(
            progress
                .get("json_fields")
                .and_then(json::Value::as_array)
                .map(Vec::len),
            Some(4)
        );
        assert_eq!(
            progress.get("corpus_open").and_then(json::Value::as_str),
            Some(
                "accepted_ballot_prefix_count is the proof-verified next contiguous offset and is strictly less than frozen_survivor_count"
            )
        );
        let release_context = fixture
            .get("tle_release_context")
            .and_then(json::Value::as_object)
            .expect("TLE release-context fixture");
        assert_eq!(
            release_context
                .get("authorized_status")
                .and_then(json::Value::as_str),
            Some("Opening")
        );
        assert_eq!(
            release_context
                .get("forbidden_fields")
                .and_then(json::Value::as_array)
                .map(Vec::len),
            Some(7)
        );
        assert_eq!(
            release_context
                .get("transcript_public_state_fields")
                .and_then(json::Value::as_array)
                .map(Vec::len),
            Some(14)
        );
        let partial_release = fixture
            .get("tle_partial_release")
            .and_then(json::Value::as_object)
            .expect("TLE partial-release fixture");
        assert_eq!(
            partial_release
                .get("response_fields")
                .and_then(json::Value::as_array)
                .map(Vec::len),
            Some(9)
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
            super::ParliamentTimedOvnCastingContextResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingContextResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnCastingPhaseProjectionV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingPhaseProjectionV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnCastingProofRequestV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingProofRequestV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnCastingProofResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingProofResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnProgressProjectionV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnProgressProjectionV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnReleaseIdentityProjectionV1,
        >(
            "iroha_torii_shared::parliament_api::ParliamentTimedOvnReleaseIdentityProjectionV1"
        );
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTimedOvnSessionProjectionV1,
        >("iroha_torii_shared::parliament_api::ParliamentTimedOvnSessionProjectionV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTleAdaptiveDealerCommitmentV1,
        >("iroha_torii_shared::parliament_api::ParliamentTleAdaptiveDealerCommitmentV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTleAdaptivePublicShareV1,
        >("iroha_torii_shared::parliament_api::ParliamentTleAdaptivePublicShareV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTleKeySessionBindingV1,
        >("iroha_torii_shared::parliament_api::ParliamentTleKeySessionBindingV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTlePartialReleaseShareV1,
        >("iroha_torii_shared::parliament_api::ParliamentTlePartialReleaseShareV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::ParliamentTleReleaseContextResponseV1,
        >("iroha_torii_shared::parliament_api::ParliamentTleReleaseContextResponseV1");
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
