//! App-facing governance API.
#![allow(unexpected_cfgs)]
//!
//! This module hosts minimal DTOs and handlers for governance endpoints described in `gov.md` and
//! `specs/contract_deployment.md`. Handlers validate inputs and build instruction skeletons for
//! callers to submit through the locally signed transaction pipeline. Draft request schemas that
//! previously exposed server-side signing inputs are strict and no longer admit private signing
//! material.
//!
//! Notes
//! - JSON parsing uses Norito's serde wrappers via the `NoritoJson` extractor.
//! - Keep responses stable and explicit; map input errors to 400.
use crate::{
    JsonBody, NoritoBody, NoritoJson, NoritoJsonWithBytes,
    json_macros::{JsonDeserialize, JsonSerialize},
    routing::{MaybeTelemetry, parse_account_literal_with_state},
};
use base64::Engine as _;
use iroha_core::governance::parliament::ParliamentBallotStateV1;
use iroha_core::governance::parliament::ParliamentDecisionModeV1;
use iroha_core::kura::Kura;
use iroha_core::state::StateReadOnly;
use iroha_core::state::WorldReadOnly;
use iroha_core_timed_ovn::evidence::TimedOvnLifecycleStateV1;
use iroha_data_model::{
    governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal,
        MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1, MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
        ParliamentNoResultKindV1, ProposalContentId, ProposalKind, SccpRouteGovernanceProposal,
    },
    ministry::{AgendaProposalRecordV1, AgendaProposalV1},
    smart_contract::manifest::{EntryPointKind, ManifestProvenance},
};
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::governance_proposal_api::{
    DeployContractProposalDraftRequestV1, DeployContractProposalDraftResponseV1,
    GovernanceProposalInstructionDraftV1, SccpRouteGovernanceProposalDraftRequestV1,
    SccpRouteGovernanceProposalDraftResponseV1,
};
use iroha_torii_shared::parliament_api::{
    PARLIAMENT_API_VERSION_V1, PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_CHAIN_BYTES_V1,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_RESPONSE_BYTES_V1,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1, ParliamentAttemptDraftRequestV1,
    ParliamentAttemptDraftResponseV1, ParliamentAttemptPlanResponseV1,
    ParliamentAttemptReadResponseV1, ParliamentBodyStateProjectionV1,
    ParliamentDecisionModeProjectionV1, ParliamentExactTransitionProjectionV1,
    ParliamentInstructionDraftV1, ParliamentTimedOvnCastingContextResponseV1,
    ParliamentTimedOvnCastingPhaseProjectionV1, ParliamentTimedOvnCastingProofRequestV1,
    ParliamentTimedOvnCastingProofResponseV1, ParliamentTimedOvnProgressProjectionV1,
    ParliamentTimedOvnReleaseIdentityProjectionV1, ParliamentTimedOvnSessionProjectionV1,
    ParliamentTleAdaptiveDealerCommitmentV1, ParliamentTleAdaptivePublicShareV1,
    ParliamentTleKeySessionBindingV1, ParliamentTleReleaseContextResponseV1,
    ParliamentTransitionDraftRequestV1, ParliamentTransitionDraftResponseV1,
    RequiredParliamentBodyProjectionV1, parliament_timed_ovn_casting_proof_page_tip,
};
use mv::storage::StorageReadOnly;
use norito::{
    derive::{NoritoDeserialize, NoritoSerialize},
    json,
};
const CONTEXT_GOV_BALLOT_ZK_V1_AUTHORITY: &str = "/v1/gov/ballots/zk-v1#authority";
const CONTEXT_GOV_BALLOT_ZK_V1_BALLOT_PROOF_AUTHORITY: &str =
    "/v1/gov/ballots/zk-v1/ballot-proof#authority";
const CONTEXT_GOV_BALLOT_PLAIN_AUTHORITY: &str = "/v1/gov/ballots/plain#authority";
const CONTEXT_GOV_BALLOT_PLAIN_OWNER: &str = "/v1/gov/ballots/plain#owner";
const CONTEXT_GOV_PROTECTED_AUTHORITY: &str = "/v1/gov/protected-namespaces#authority";
const CONTEXT_MINISTRY_AGENDA_DRAFT_AUTHORITY: &str =
    "/v1/ministry/agenda/proposals/draft#authority";
#[cfg(test)]
use core::str::FromStr;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::Arc;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::MinistryAgendaProposalDraftDto")]
#[derive(Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
/// Request body for drafting a Ministry agenda proposal submission transaction.

pub struct MinistryAgendaProposalDraftDto {
    /// Agenda proposal payload that will be submitted on-chain.
    pub proposal: AgendaProposalV1,
    /// Canonical I105 account id that will sign the transaction.
    pub authority: String,
}
#[derive(Debug, JsonSerialize)]
/// Draft response for a Ministry agenda proposal submission.
pub struct MinistryAgendaProposalDraftResponse {
    /// Whether the draft generation succeeded.
    pub ok: bool,
    /// Stable agenda proposal identifier.
    pub agenda_proposal_id: String,
    /// Canonical I105 authority used for transaction construction.
    pub authority: String,
    /// Single-instruction transaction skeleton for wallets/clients that want an instruction preview.
    pub tx_instructions: Vec<TxInstr>,
    /// Base64-encoded canonical `TransactionPayload` bytes for Connect `SignRequestTx`.
    pub signable_transaction_b64: String,
}
#[derive(Debug, JsonSerialize)]
/// Lookup response for submitted Ministry agenda proposals.
pub struct MinistryAgendaProposalGetResponse {
    /// Whether the proposal record exists in committed state.
    pub found: bool,
    /// Persisted proposal record when found.
    pub record: Option<AgendaProposalRecordV1>,
}
#[derive(Debug)]
/// Result of drafting a Ministry agenda proposal transaction.
pub enum MinistryAgendaProposalDraftOutcome {
    /// Draft created successfully.
    Draft(MinistryAgendaProposalDraftResponse),
    /// Proposal id already exists in committed state.
    Duplicate(MinistryAgendaProposalGetResponse),
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::PlainBallotDto")]
#[derive(Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
/// Request body for submitting a plain (non-ZK) quadratic ballot.

pub struct PlainBallotDto {
    /// Authority as canonical I105 or on-chain account alias.
    pub authority: String,
    /// Exact genesis-derived network to build the transaction skeleton for.
    pub network_id: iroha_data_model::NetworkId,
    /// Referendum identifier whose plain ballot is being drafted.
    pub referendum_id: String,
    /// Owner as canonical I105 or on-chain account alias.
    pub owner: String,
    /// Exact non-negative token quantity.
    pub amount: Quantity,
    /// Canonical unsigned decimal block duration.
    pub duration_blocks: String,
    /// One of: "Aye" | "Nay" | "Abstain"
    pub direction: String,
}
impl norito::core::SerializePayload for PlainBallotDto {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let value = norito::json::to_value(self)
            .map_err(|err| norito::core::Error::Message(err.to_string()))?;
        let json = norito::json::to_string(&value)
            .map_err(|err| norito::core::Error::Message(err.to_string()))?;
        <String as norito::core::SerializePayload>::serialize(&json, writer)
    }
}
impl<'de> norito::core::DeserializePayload<'de> for PlainBallotDto {
    fn try_deserialize(
        archived: &'de norito::core::Archived<PlainBallotDto>,
    ) -> Result<Self, norito::core::Error> {
        let archived_json: &norito::core::Archived<String> = archived.cast();
        let json = <String as norito::core::DeserializePayload>::try_deserialize(archived_json)?;
        norito::json::from_str(&json).map_err(|err| norito::core::Error::Message(err.to_string()))
    }
    fn deserialize(archived: &'de norito::core::Archived<PlainBallotDto>) -> Self {
        Self::try_deserialize(archived).expect("PlainBallotDto should deserialize from JSON string")
    }
}
/// Successful result of drafting an unsigned standalone ballot transaction.
#[derive(Debug, JsonSerialize)]
pub struct BallotDraftResponse {
    /// Confirms that Torii constructed, but did not submit, the transaction draft.
    pub drafted: bool,
    /// Single instruction skeleton for the caller to place in a locally signed transaction.
    pub tx_instructions: Vec<TxInstr>,
}
fn ballot_input_error(reason: impl Into<String>) -> crate::Error {
    crate::routing::conversion_error(reason.into())
}
fn lock_hints_incomplete(owner: bool, amount: bool, duration: bool) -> bool {
    let any = owner || amount || duration;
    any && !(owner && amount && duration)
}
fn validate_optional_ballot_direction(direction: Option<&str>) -> Result<(), String> {
    if direction.is_some_and(|value| !matches!(value, "Aye" | "Nay" | "Abstain")) {
        return Err("direction must be Aye, Nay, or Abstain".to_owned());
    }
    Ok(())
}
fn reject_zk_public_input_aliases(map: &json::Map) -> Result<(), String> {
    reject_zk_public_input_key(map, "durationBlocks", "duration_blocks")?;
    reject_zk_public_input_key(map, "root_hint_hex", "root_hint")?;
    reject_zk_public_input_key(map, "rootHintHex", "root_hint")?;
    reject_zk_public_input_key(map, "rootHint", "root_hint")?;
    reject_zk_public_input_key(map, "nullifier_hex", "nullifier")?;
    reject_zk_public_input_key(map, "nullifierHex", "nullifier")?;
    Ok(())
}
fn ensure_owner_canonical(owner: &str) -> Result<(), String> {
    let canonical = iroha_data_model::account::AccountId::canonicalize(owner)
        .map_err(|_| "owner must use canonical I105 account id form".to_string())?;
    if canonical != owner {
        return Err("owner must use canonical I105 account id form".to_string());
    }
    Ok(())
}
fn reject_zk_public_input_owner(map: &json::Map) -> Result<(), String> {
    let Some(value) = map.get("owner") else {
        return Ok(());
    };
    if matches!(value, json::Value::Null) {
        return Ok(());
    }
    let owner = value
        .as_str()
        .ok_or_else(|| "owner must be a canonical I105 account id".to_string())?;
    ensure_owner_canonical(owner)
}
fn reject_zk_public_input_key(map: &json::Map, key: &str, canonical: &str) -> Result<(), String> {
    if map.contains_key(key) {
        return Err(format!(
            "public inputs must use {canonical} (unsupported key {key})"
        ));
    }
    Ok(())
}
fn reject_zk_v1_aliases_from_raw(raw: &[u8]) -> Result<(), String> {
    let Ok(value) = json::from_slice::<json::Value>(raw) else {
        return Ok(());
    };
    let json::Value::Object(map) = value else {
        return Ok(());
    };
    reject_zk_public_input_aliases(&map)?;
    Ok(())
}
fn reject_zk_v1_ballotproof_aliases_from_raw(raw: &[u8]) -> Result<(), String> {
    let Ok(value) = json::from_slice::<json::Value>(raw) else {
        return Ok(());
    };
    let json::Value::Object(map) = value else {
        return Ok(());
    };
    let Some(json::Value::Object(ballot)) = map.get("ballot") else {
        return Ok(());
    };
    reject_zk_public_input_aliases(ballot)?;
    reject_zk_public_input_owner(ballot)?;
    Ok(())
}
fn canonicalize_hex32_value(raw: &str) -> Option<String> {
    let without_scheme = if let Some((scheme, rest)) = raw.split_once(':') {
        if scheme.eq_ignore_ascii_case("blake2b32") {
            rest
        } else {
            return None;
        }
    } else {
        raw
    };
    let body = without_scheme
        .strip_prefix("0x")
        .or_else(|| without_scheme.strip_prefix("0X"))
        .unwrap_or(without_scheme);
    if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}
fn validate_exact_nonempty_token(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!(
            "{field} must be a non-empty token without whitespace or control characters"
        ));
    }
    Ok(())
}
fn validate_governance_selector_v1(field: &str, value: &str) -> Result<(), String> {
    if !iroha_data_model::governance::is_valid_governance_selector_v1(value) {
        return Err(format!(
            "{field} must match {}",
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN
        ));
    }
    Ok(())
}

fn is_stored_typed_proposal_fingerprint(world: &impl WorldReadOnly, selector: &str) -> bool {
    let Some(proposal_id) =
        iroha_data_model::governance::decode_governance_proposal_selector_alias_v1(selector)
    else {
        return false;
    };
    world.governance_proposals().get(&proposal_id).is_some()
}

fn reject_typed_proposal_ballot_selector(
    world: &impl WorldReadOnly,
    selector: &str,
) -> Result<(), String> {
    if is_stored_typed_proposal_fingerprint(world, selector) {
        return Err(
            "typed proposal fingerprints use the authenticated Parliament lifecycle, not standalone referendum ballots"
                .to_owned(),
        );
    }
    Ok(())
}
fn parse_exact_lower_hex32_path(field: &str, value: &str) -> Result<[u8; 32], crate::Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(crate::routing::conversion_error(format!(
            "{field} must be exact lowercase 32-byte hex"
        )));
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded).map_err(|_| {
        crate::routing::conversion_error(format!("{field} must be exact lowercase 32-byte hex"))
    })?;
    Ok(decoded)
}
fn require_exact_governance_path_token(field: &str, value: &str) -> Result<(), crate::Error> {
    validate_governance_selector_v1(field, value)
        .map_err(|message| crate::routing::conversion_error(message.into()))
}
fn parse_canonical_u64_decimal(field: &str, value: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{field} must be a canonical unsigned decimal integer"
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} is outside the unsigned 64-bit integer range"))
}
// -------- ZK Ballot V1 DTO --------
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::ZkBallotV1Dto")]
#[derive(Debug, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
/// Request body for submitting a ZK ballot using BallotProof-style fields.

pub struct ZkBallotV1Dto {
    /// Authority submitting the ballot (AccountId string)
    pub authority: String,
    /// Exact genesis-derived network to build the transaction skeleton for.
    pub network_id: iroha_data_model::NetworkId,
    pub election_id: String,
    /// Backend tag for the proof (e.g., halo2/ipa)
    pub backend: String,
    /// Base64-encoded envelope bytes (ZK1 or H2* container)
    pub envelope_b64: String,
    /// Optional eligibility root hint (hex-32, 0x allowed)
    #[norito(default)]
    pub root_hint: Option<String>,
    /// Optional owner account id (for lock hints when the circuit commits owner)
    #[norito(default)]
    pub owner: Option<String>,
    /// Optional exact lock amount hint.
    #[norito(default)]
    pub amount: Option<Quantity>,
    /// Optional lock duration hint in blocks.
    #[norito(default)]
    pub duration_blocks: Option<u64>,
    /// Optional direction hint ("Aye" | "Nay" | "Abstain").
    #[norito(default)]
    pub direction: Option<String>,
    /// Optional nullifier hint (hex-32, 0x allowed)
    #[norito(default)]
    pub nullifier: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::ZkBallotV1BallotProofDto")]
#[derive(Debug, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
/// Request body that carries a BallotProof directly along with transaction context.

pub struct ZkBallotV1BallotProofDto {
    pub authority: String,
    /// Exact genesis-derived network to build the transaction skeleton for.
    pub network_id: iroha_data_model::NetworkId,
    pub election_id: String,
    pub ballot: iroha_data_model::isi::governance::BallotProof,
}
/// POST /v1/gov/ballots/zk-v1 — accept BallotProof-like DTO and build an instruction skeleton.
///
/// The request schema excludes private signing material; callers submit locally signed transactions.
///
/// # Errors
/// Returns `crate::Error::Query` for a foreign network, invalid authority, or invalid ballot
/// fields. No transaction is submitted by this endpoint.
pub async fn handle_gov_ballot_zk_v1(
    state: Arc<iroha_core::state::State>,
    authenticated_account: &iroha_data_model::account::AccountId,
    telemetry: MaybeTelemetry,
    NoritoJsonWithBytes { value: body, raw }: NoritoJsonWithBytes<ZkBallotV1Dto>,
) -> Result<JsonBody<BallotDraftResponse>, crate::Error> {
    ensure_network_id_matches(state.as_ref(), &body.network_id)?;
    let authority_id = parse_authority_literal(
        state.as_ref(),
        body.authority.as_str(),
        &telemetry,
        CONTEXT_GOV_BALLOT_ZK_V1_AUTHORITY,
    )?;
    ensure_authenticated_authority(authenticated_account, &authority_id)?;
    reject_zk_v1_aliases_from_raw(raw.as_ref()).map_err(ballot_input_error)?;
    validate_exact_nonempty_token("backend", &body.backend).map_err(ballot_input_error)?;
    validate_governance_selector_v1("election_id", &body.election_id)
        .map_err(ballot_input_error)?;
    reject_typed_proposal_ballot_selector(&state.world_view(), &body.election_id)
        .map_err(ballot_input_error)?;
    let proof_envelope = base64::engine::general_purpose::STANDARD
        .decode(body.envelope_b64.as_bytes())
        .map_err(|_| ballot_input_error("envelope_b64 must be non-empty canonical base64"))?;
    if proof_envelope.is_empty()
        || base64::engine::general_purpose::STANDARD.encode(&proof_envelope) != body.envelope_b64
    {
        return Err(ballot_input_error(
            "envelope_b64 must be non-empty canonical base64",
        ));
    }
    let has_owner = body.owner.is_some();
    let has_amount = body.amount.is_some();
    let has_duration = body.duration_blocks.is_some();
    if lock_hints_incomplete(has_owner, has_amount, has_duration) {
        return Err(ballot_input_error(
            "lock hints must include owner, amount, duration_blocks",
        ));
    }
    if let Some(owner) = &body.owner {
        ensure_owner_canonical(owner).map_err(ballot_input_error)?;
        if owner != &authority_id.to_string() {
            return Err(ballot_input_error("owner must equal authority"));
        }
    }
    validate_optional_ballot_direction(body.direction.as_deref()).map_err(ballot_input_error)?;
    // Build public inputs JSON object with optional hints
    let mut pub_map = norito::json::Map::new();
    if let Some(rh) = &body.root_hint {
        let Some(canonical) = canonicalize_hex32_value(rh) else {
            return Err(ballot_input_error("root_hint must be 32-byte hex"));
        };
        pub_map.insert("root_hint".into(), norito::json::Value::from(canonical));
    }
    if let Some(owner) = &body.owner {
        pub_map.insert("owner".into(), norito::json::Value::from(owner.clone()));
    }
    if let Some(amount) = &body.amount {
        pub_map.insert(
            "amount".into(),
            norito::json::Value::from(amount.to_string()),
        );
    }
    if let Some(duration_blocks) = body.duration_blocks {
        pub_map.insert(
            "duration_blocks".into(),
            norito::json::Value::from(duration_blocks),
        );
    }
    if let Some(direction) = &body.direction {
        pub_map.insert(
            "direction".into(),
            norito::json::Value::from(direction.clone()),
        );
    }
    if let Some(nullifier) = &body.nullifier {
        let Some(canonical) = canonicalize_hex32_value(nullifier) else {
            return Err(ballot_input_error("nullifier must be 32-byte hex"));
        };
        pub_map.insert("nullifier".into(), norito::json::Value::from(canonical));
    }
    let public_inputs_json = norito::json::to_json(&norito::json::Value::Object(pub_map))
        .unwrap_or_else(|_| "{}".into());
    // Convert to CastZkBallot skeleton
    let instr = iroha_data_model::isi::governance::CastZkBallot {
        election_id: body.election_id,
        proof_b64: body.envelope_b64,
        public_inputs_json,
    };
    let tx_instructions = vec![tx_instr_from_box(instr.into())];
    Ok(JsonBody(BallotDraftResponse {
        drafted: true,
        tx_instructions,
    }))
}
/// POST /v1/gov/ballots/zk-v1/ballot-proof — accept BallotProof JSON and build instruction skeleton.
///
/// The request schema excludes private signing material; callers submit locally signed transactions.
///
/// # Errors
/// Returns `crate::Error::Query` for a foreign network, invalid authority, or invalid ballot
/// fields. No transaction is submitted by this endpoint.
pub async fn handle_gov_ballot_zk_v1_ballotproof(
    state: Arc<iroha_core::state::State>,
    authenticated_account: &iroha_data_model::account::AccountId,
    telemetry: MaybeTelemetry,
    NoritoJsonWithBytes { value: body, raw }: NoritoJsonWithBytes<ZkBallotV1BallotProofDto>,
) -> Result<JsonBody<BallotDraftResponse>, crate::Error> {
    ensure_network_id_matches(state.as_ref(), &body.network_id)?;
    let authority_id = parse_authority_literal(
        state.as_ref(),
        body.authority.as_str(),
        &telemetry,
        CONTEXT_GOV_BALLOT_ZK_V1_BALLOT_PROOF_AUTHORITY,
    )?;
    ensure_authenticated_authority(authenticated_account, &authority_id)?;
    reject_zk_v1_ballotproof_aliases_from_raw(raw.as_ref()).map_err(ballot_input_error)?;
    validate_exact_nonempty_token("backend", &body.ballot.backend).map_err(ballot_input_error)?;
    validate_governance_selector_v1("election_id", &body.election_id)
        .map_err(ballot_input_error)?;
    reject_typed_proposal_ballot_selector(&state.world_view(), &body.election_id)
        .map_err(ballot_input_error)?;
    if body.ballot.envelope_bytes.is_empty() {
        return Err(ballot_input_error(
            "ballot.envelope_bytes must not be empty",
        ));
    }
    let has_owner = body.ballot.owner.is_some();
    let has_amount = body.ballot.amount.is_some();
    let has_duration = body.ballot.duration_blocks.is_some();
    if lock_hints_incomplete(has_owner, has_amount, has_duration) {
        return Err(ballot_input_error(
            "lock hints must include owner, amount, duration_blocks",
        ));
    }
    if body
        .ballot
        .owner
        .as_ref()
        .is_some_and(|owner| owner != &authority_id)
    {
        return Err(ballot_input_error("owner must equal authority"));
    }
    validate_optional_ballot_direction(body.ballot.direction.as_deref())
        .map_err(ballot_input_error)?;
    // Build public inputs JSON from optional hints in BallotProof
    let mut pub_map = norito::json::Map::new();
    if let Some(rh) = &body.ballot.root_hint {
        pub_map.insert(
            "root_hint".into(),
            norito::json::Value::from(hex::encode(rh)),
        );
    }
    if let Some(owner) = &body.ballot.owner {
        pub_map.insert("owner".into(), norito::json::Value::from(owner.to_string()));
    }
    if let Some(amount) = &body.ballot.amount {
        pub_map.insert(
            "amount".into(),
            norito::json::Value::from(amount.to_string()),
        );
    }
    if let Some(duration_blocks) = body.ballot.duration_blocks {
        pub_map.insert(
            "duration_blocks".into(),
            norito::json::Value::from(duration_blocks),
        );
    }
    if let Some(direction) = &body.ballot.direction {
        pub_map.insert(
            "direction".into(),
            norito::json::Value::from(direction.clone()),
        );
    }
    if let Some(nullifier) = &body.ballot.nullifier {
        pub_map.insert(
            "nullifier".into(),
            norito::json::Value::from(hex::encode(nullifier)),
        );
    }
    let public_inputs_json = norito::json::to_json(&norito::json::Value::Object(pub_map))
        .unwrap_or_else(|_| "{}".into());
    // Re-encode envelope_bytes as base64 for CastZkBallot
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&body.ballot.envelope_bytes);
    let instr = iroha_data_model::isi::governance::CastZkBallot {
        election_id: body.election_id,
        proof_b64,
        public_inputs_json,
    };
    let tx_instructions = vec![tx_instr_from_box(instr.into())];
    Ok(JsonBody(BallotDraftResponse {
        drafted: true,
        tx_instructions,
    }))
}
/// Citizenship status response for an account.
#[derive(Debug, JsonSerialize)]
pub struct CitizenStatusResponse {
    pub account_id: String,
    pub is_citizen: bool,
    pub amount: Option<String>,
    pub bonded_height: Option<String>,
}
/// Exact citizen registry count response.
#[derive(Debug, JsonSerialize)]
pub struct CitizenCountResponse {
    pub total: String,
}
/// Stable schema identifier for the strict governance readiness projection.
pub const GOVERNANCE_CAPABILITIES_SCHEMA_V1: &str = "iroha.governance.capabilities.v1";
/// Current strict governance readiness projection version.
pub const GOVERNANCE_CAPABILITIES_VERSION_V1: u16 = 1;
/// Configured target sizes for all ten SORA Parliament bodies.
#[derive(Debug, Clone, JsonSerialize)]
pub struct GovernanceTargetBodySizesV1 {
    /// Rules Committee target seats.
    pub rules_committee: String,
    /// Agenda Council target seats.
    pub agenda_council: String,
    /// Interest Panel target seats.
    pub interest_panel: String,
    /// Review Panel target seats.
    pub review_panel: String,
    /// Coordination Council target seats.
    pub coordination_council: String,
    /// Monetary Policy Committee target seats.
    pub mpc_committee: String,
    /// Financial Markets Authority Committee target seats.
    pub fma_committee: String,
    /// Oversight Committee target seats.
    pub oversight_committee: String,
    /// Policy Jury target seats.
    pub policy_jury: String,
    /// Maximum Confirmation Jury target seats.
    pub confirmation_jury: String,
}
/// Public fail-closed governance configuration and route projection.
#[derive(Debug, JsonSerialize)]
pub struct GovernanceCapabilitiesV1 {
    /// Stable projection schema identifier.
    pub schema: String,
    /// Projection layout version.
    pub version: u16,
    /// Exact genesis-derived network identity.
    pub network_id: iroha_data_model::NetworkId,
    /// Latest committed block height.
    pub current_height: String,
    /// I105 network prefix used by this chain.
    pub network_prefix: String,
    /// Active IVM ABI version.
    pub abi_version: String,
    /// Data-model compatibility version.
    pub data_model_version: String,
    /// Exact configured governance approval mode.
    pub approval_mode: String,
    /// Mandatory private binding-ballot protocol.
    pub private_ballot_protocol: String,
    /// Whether every binding Parliament ballot is private and timed-opened.
    pub mandatory_private_ballots: bool,
    /// Whether proposal-backed referendum ballot routes may replace Parliament.
    pub proposal_backed_referendum_ballots_supported: bool,
    /// Whether explicitly standalone PLAIN referenda retain their separate route.
    pub standalone_plain_ballots_supported: bool,
    /// Whether explicitly standalone ZK referenda retain their separate route.
    pub standalone_zk_ballots_supported: bool,
    /// Citizenship bond asset.
    pub citizenship_asset_id: String,
    /// Exact citizenship bond as a decimal string.
    pub citizenship_bond_amount: String,
    /// Account that custodies citizenship bonds.
    pub citizenship_escrow_account: String,
    /// Citizen ballot bond asset.
    pub voting_asset_id: String,
    /// Exact minimum citizen ballot bond as a decimal string.
    pub min_bond_amount: String,
    /// Account that custodies citizen ballot bonds.
    pub bond_escrow_account: String,
    /// Certification-to-enactment delay in blocks.
    pub min_enactment_delay: String,
    /// Invitation-response window in blocks.
    pub invitation_phase_blocks: String,
    /// Timed-OVN proof-registration window in blocks.
    pub registration_phase_blocks: String,
    /// Timed-OVN authenticated-dropout/survivor window in blocks.
    pub survivor_freeze_phase_blocks: String,
    /// Timed-OVN masked-ballot commitment window in blocks.
    pub commitment_phase_blocks: String,
    /// Delay from commitment close to threshold release in blocks.
    pub release_delay_blocks: String,
    /// Timed-OVN aggregate-opening window in blocks.
    pub opening_phase_blocks: String,
    /// Retry attempts permitted after the initial private ballot.
    pub max_ballot_retries: String,
    /// Hard participant/corpus entry bound.
    pub max_corpus_entries: String,
    /// Configured targets; actual proposal rosters are capped by eligible citizens.
    pub target_body_sizes: GovernanceTargetBodySizesV1,
    /// Typed proposal kinds supported by the first release.
    pub supported_proposal_kinds: Vec<String>,
    /// Canonical public governance routes supported by the node.
    pub supported_routes: Vec<String>,
}
const GOVERNANCE_APPROVAL_MODE_V1: &str = "PARLIAMENT_ATTEMPT_TIMED_OVN_V1";
const GOVERNANCE_SUPPORTED_PROPOSAL_KINDS_V1: [&str; 10] = [
    "DEPLOY_CONTRACT",
    "RUNTIME_UPGRADE",
    "SCCP_ROUTE_GOVERNANCE",
    "VALIDATION_FEE_POLICY",
    "VALIDATION_FEE_PAYOUT_LIFECYCLE",
    "MUSUBI_REGISTRY_GOVERNANCE",
    "SORAFS_PROVIDER_GOVERNANCE",
    "CONTRACT_LIFECYCLE_GOVERNANCE",
    "CONTRACT_EMERGENCY_HOLD",
    "GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE",
];
/// GET `/v1/gov/capabilities` — return strict public governance readiness.
///
/// # Errors
/// Returns an internal query error before a committed genesis block exists.
pub async fn handle_gov_capabilities(
    state: Arc<iroha_core::state::State>,
) -> Result<JsonBody<GovernanceCapabilitiesV1>, crate::Error> {
    if state.committed_height() == 0 {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::InternalError(
                "governance capabilities are unavailable before committed genesis".into(),
            ),
        ));
    }
    let gov = state.governance_snapshot();
    let world = state.world_view();
    Ok(JsonBody(GovernanceCapabilitiesV1 {
        schema: GOVERNANCE_CAPABILITIES_SCHEMA_V1.to_owned(),
        version: GOVERNANCE_CAPABILITIES_VERSION_V1,
        network_id: *state.network_id_ref(),
        current_height: u64::try_from(state.committed_height())
            .unwrap_or(u64::MAX)
            .to_string(),
        network_prefix: iroha_data_model::account::address::chain_discriminant().to_string(),
        abi_version: world.abi_version().to_string(),
        data_model_version: iroha_data_model::DATA_MODEL_VERSION.to_string(),
        approval_mode: GOVERNANCE_APPROVAL_MODE_V1.to_owned(),
        private_ballot_protocol: "TIMED_OVN_TLE_THRESHOLD_BLS_V1".to_owned(),
        mandatory_private_ballots: true,
        proposal_backed_referendum_ballots_supported: false,
        standalone_plain_ballots_supported: gov.plain_voting_enabled,
        standalone_zk_ballots_supported: true,
        citizenship_asset_id: gov.citizenship_asset_id.to_string(),
        citizenship_bond_amount: gov.citizenship_bond_amount.to_string(),
        citizenship_escrow_account: gov.citizenship_escrow_account.to_string(),
        voting_asset_id: gov.voting_asset_id.to_string(),
        min_bond_amount: gov.min_bond_amount.to_string(),
        bond_escrow_account: gov.bond_escrow_account.to_string(),
        min_enactment_delay: gov.min_enactment_delay.to_string(),
        invitation_phase_blocks: gov.parliament_invitation_phase_blocks.to_string(),
        registration_phase_blocks: gov
            .parliament_timed_ovn
            .registration_phase_blocks
            .to_string(),
        survivor_freeze_phase_blocks: gov
            .parliament_timed_ovn
            .survivor_freeze_phase_blocks
            .to_string(),
        commitment_phase_blocks: gov.parliament_timed_ovn.commitment_phase_blocks.to_string(),
        release_delay_blocks: gov.parliament_timed_ovn.release_delay_blocks.to_string(),
        opening_phase_blocks: gov.parliament_timed_ovn.opening_phase_blocks.to_string(),
        max_ballot_retries: gov.parliament_timed_ovn.max_ballot_retries.to_string(),
        max_corpus_entries: gov.parliament_timed_ovn.max_corpus_entries.to_string(),
        target_body_sizes: GovernanceTargetBodySizesV1 {
            rules_committee: gov.rules_committee_size.to_string(),
            agenda_council: gov.agenda_council_size.to_string(),
            interest_panel: gov.interest_panel_size.to_string(),
            review_panel: gov.review_panel_size.to_string(),
            coordination_council: gov.coordination_council_size.to_string(),
            mpc_committee: gov.mpc_committee_size.to_string(),
            fma_committee: gov.fma_committee_size.to_string(),
            oversight_committee: gov.oversight_committee_size.to_string(),
            policy_jury: gov.policy_jury_size.to_string(),
            confirmation_jury: gov.confirmation_jury_size.to_string(),
        },
        supported_proposal_kinds: GOVERNANCE_SUPPORTED_PROPOSAL_KINDS_V1
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect(),
        supported_routes: vec![
            "/v1/gov/capabilities".to_owned(),
            "/v1/gov/citizens/draft".to_owned(),
            "/v1/gov/parliament/attempts/draft".to_owned(),
            "/v1/gov/parliament/attempts/{governance_attempt_id}".to_owned(),
            "/v1/gov/parliament/attempts/{governance_attempt_id}/plan".to_owned(),
            "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context".to_owned(),
            "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof".to_owned(),
            "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context".to_owned(),
            "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release".to_owned(),
            "/v1/gov/parliament/transitions/draft".to_owned(),
            "/v1/gov/ballots/plain".to_owned(),
            "/v1/gov/ballots/zk-v1".to_owned(),
            "/v1/gov/ballots/zk-v1/ballot-proof".to_owned(),
            "/v1/validation-fee/proposals".to_owned(),
            "/v1/validation-fee/proposals/{proposal_id}".to_owned(),
            "/v1/validation-fee/proposals/draft".to_owned(),
        ],
    }))
}

/// POST `/v1/gov/parliament/attempts/draft` — draft one canonical attempt creation.
///
/// Authentication is enforced by the route wrapper. The response is bound to
/// the exact proposal and retry sequence and contains no signing material.
///
/// # Errors
/// Returns a conversion error for an unsupported request version, an attempt
/// sequence above the V1 retry ceiling, or a proposal containing a public JSON
/// integer that is not exactly representable by every SDK.
pub async fn handle_gov_parliament_attempt_draft(
    NoritoJson(body): NoritoJson<ParliamentAttemptDraftRequestV1>,
) -> Result<JsonBody<ParliamentAttemptDraftResponseV1>, crate::Error> {
    if body.version != PARLIAMENT_API_VERSION_V1 {
        return Err(crate::routing::conversion_error(format!(
            "unsupported Parliament attempt draft version {}; expected {}",
            body.version, PARLIAMENT_API_VERSION_V1
        )));
    }
    if body.attempt_sequence > MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 {
        return Err(crate::routing::conversion_error(format!(
            "Parliament attempt sequence exceeds the V1 retry limit {}",
            MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1
        )));
    }
    if let Some(reason) = body.proposal.first_release_exact_json_u64_invariant_error() {
        return Err(crate::routing::conversion_error(reason.to_owned()));
    }
    let instruction = iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1 {
        proposal: body.proposal,
        attempt_sequence: body.attempt_sequence,
    };
    let proposal_content_id = instruction.proposal_content_id();
    let governance_attempt_id = instruction.governance_attempt_id();
    let draft = tx_instr_from_box(instruction.into());
    Ok(JsonBody(ParliamentAttemptDraftResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        proposal_content_id,
        governance_attempt_id,
        tx_instructions: vec![ParliamentInstructionDraftV1 {
            wire_id: draft.wire_id,
            payload_hex: draft.payload_hex,
        }],
    }))
}

/// POST `/v1/gov/parliament/transitions/draft` — draft one closed transition.
///
/// The state-independent request bounds are checked before framing. Consensus
/// still rechecks authority, state, phase, height, proof, roster, and
/// certificate bindings when the locally signed instruction executes.
///
/// # Errors
/// Returns a conversion error for an unsupported version or invalid static
/// bound.
pub async fn handle_gov_parliament_transition_draft(
    NoritoJson(body): NoritoJson<ParliamentTransitionDraftRequestV1>,
) -> Result<JsonBody<ParliamentTransitionDraftResponseV1>, crate::Error> {
    body.validate_static()
        .map_err(|reason| crate::routing::conversion_error(reason.to_owned()))?;
    let transition_kind = body.transition.kind();
    let transition_digest = body.transition.digest_v1();
    let governance_attempt_id = body.governance_attempt_id;
    let instruction = iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1 {
        governance_attempt_id,
        transition: body.transition,
    };
    let draft = tx_instr_from_box(instruction.into());
    Ok(JsonBody(ParliamentTransitionDraftResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        governance_attempt_id,
        transition_kind,
        transition_digest,
        tx_instructions: vec![ParliamentInstructionDraftV1 {
            wire_id: draft.wire_id,
            payload_hex: draft.payload_hex,
        }],
    }))
}

/// GET `/v1/gov/parliament/attempts/{governance_attempt_id}/plan` — driver plan of one attempt.
///
/// Core trial-applies every permissionless progress transition to the reducer over one committed
/// query view (`specs/sccp.md` §4.14.5 item 4). The plan is advice for a driver; consensus
/// rechecks every submitted transition.
///
/// # Errors
/// Returns a conversion error for a noncanonical identifier or a missing attempt.
pub async fn handle_gov_parliament_attempt_plan(
    state: Arc<iroha_core::state::State>,
    governance_attempt_id: String,
) -> Result<JsonBody<ParliamentAttemptPlanResponseV1>, crate::Error> {
    let governance_attempt_id = governance_attempt_id
        .parse::<iroha_data_model::governance::types::GovernanceAttemptId>()
        .map_err(|_| {
            crate::routing::conversion_error(
                "governance_attempt_id must be exactly 64 lowercase hexadecimal characters"
                    .to_owned(),
            )
        })?;
    let governance = state.governance_snapshot();
    let view = state.query_view();
    let (current_height, execution_height, plan) =
        iroha_core::governance::parliament::plan_parliament_attempt_v1(
            &view,
            state.network_id_ref(),
            &governance,
            governance_attempt_id,
        )
        .ok_or_else(|| {
            crate::routing::conversion_error("Parliament governance attempt was not found".into())
        })?;
    Ok(JsonBody(ParliamentAttemptPlanResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        governance_attempt_id,
        current_height,
        execution_height,
        due: plan.due,
        exact: plan
            .exact
            .into_iter()
            .map(|exact| ParliamentExactTransitionProjectionV1 {
                height: exact.height,
                transition: exact.transition,
            })
            .collect(),
        relay_ballots: plan.relay_ballots,
        finalize_ballots: plan.finalize_ballots,
    }))
}

/// GET `/v1/gov/parliament/attempts/{governance_attempt_id}` — read one attempt.
///
/// The typed summary and complete reducer bytes come from one committed query
/// view. The payload is canonical Norito and never includes secret DKG shares,
/// plaintext ballots, or a recovery fallback.
///
/// # Errors
/// Returns a conversion error for a noncanonical identifier, a missing attempt,
/// or a reducer payload exceeding the defensive response bound.
pub async fn handle_gov_parliament_attempt_read(
    state: Arc<iroha_core::state::State>,
    governance_attempt_id: String,
) -> Result<JsonBody<ParliamentAttemptReadResponseV1>, crate::Error> {
    let governance_attempt_id = governance_attempt_id
        .parse::<iroha_data_model::governance::types::GovernanceAttemptId>()
        .map_err(|_| {
            crate::routing::conversion_error(
                "governance_attempt_id must be exactly 64 lowercase hexadecimal characters"
                    .to_owned(),
            )
        })?;
    if governance_attempt_id
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(crate::routing::conversion_error(
            "governance_attempt_id must be non-zero".to_owned(),
        ));
    }
    let view = state.query_view();
    let attempt = view
        .world()
        .parliament_attempts()
        .get(&governance_attempt_id)
        .ok_or_else(|| {
            crate::routing::conversion_error("Parliament governance attempt was not found".into())
        })?;
    let state_payload = norito::core::to_bytes_bounded(
        attempt,
        MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1,
    )
    .map_err(|_| {
        crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
            "Parliament attempt projection exceeds or violates the first-release framed Norito bound"
                .into(),
        ))
    })?;
    let required_bodies = attempt
        .required_bodies()
        .iter()
        .map(|entry| RequiredParliamentBodyProjectionV1 {
            body: entry.body,
            decision_mode: match entry.decision_mode {
                ParliamentDecisionModeV1::PublicFinding => {
                    ParliamentDecisionModeProjectionV1::PublicFinding
                }
                ParliamentDecisionModeV1::HiddenBindingBallot => {
                    ParliamentDecisionModeProjectionV1::HiddenBindingBallot
                }
            },
        })
        .collect::<Vec<_>>();
    let body_states = attempt
        .required_bodies()
        .iter()
        .map(|entry| {
            let state = attempt.sealed_body_for_role(entry.body);
            let ballot = state.and_then(|body| attempt.active_ballot_for_body(&body.instance().id));
            let no_result_kind = state
                .and_then(iroha_core::governance::parliament::ParliamentBodyStateV1::public_finding_no_result_kind)
                .or_else(|| {
                    ballot
                        .and_then(iroha_core::governance::parliament::ParliamentBallotStateV1::failure_kind)
                        .map(ParliamentNoResultKindV1::from)
                });
            let no_result_height = state
                .and_then(iroha_core::governance::parliament::ParliamentBodyStateV1::public_finding_no_result_height)
                .or_else(|| {
                    ballot.and_then(
                        iroha_core::governance::parliament::ParliamentBallotStateV1::failure_height,
                    )
                });
            let timed_ovn_progress = ballot
                .map(|ballot| {
                    let ballot_attempt_id = ballot.attempt().id;
                    let lifecycle = view
                        .world()
                        .timed_ovn_evidence()
                        .get(&ballot_attempt_id)
                        .ok_or_else(|| {
                            parliament_attempt_projection_error(
                                "active Parliament ballot has no timed-OVN lifecycle",
                            )
                        })?;
                    project_parliament_timed_ovn_progress_v1(ballot, lifecycle)
                })
                .transpose()?;
            Ok(ParliamentBodyStateProjectionV1 {
                body: entry.body,
                body_instance_id: state.map(|body| body.instance().id),
                status: state.map(|body| body.instance().status),
                public_finding_opened_at_height: state
                    .and_then(iroha_core::governance::parliament::ParliamentBodyStateV1::public_finding_opened_at_height),
                public_finding_phase_blocks: state
                    .and_then(iroha_core::governance::parliament::ParliamentBodyStateV1::public_finding_phase_blocks),
                public_finding_deadline_height: state
                    .and_then(iroha_core::governance::parliament::ParliamentBodyStateV1::public_finding_deadline_height),
                no_result_kind,
                no_result_height,
                timed_ovn_progress,
            })
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    Ok(JsonBody(ParliamentAttemptReadResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        current_height: u64::try_from(view.height()).unwrap_or(u64::MAX),
        attempt: attempt.attempt().clone(),
        policy_version: attempt.policy_version(),
        required_bodies,
        body_states,
        certificate: attempt.certificate().cloned(),
        terminal_height: attempt.terminal_height(),
        execution_failure_root: attempt.execution_failure_root(),
        superseding_head: attempt.superseding_head(),
        state_payload_hex: hex::encode(state_payload),
    }))
}

fn parliament_attempt_projection_error(message: &'static str) -> crate::Error {
    crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
        message.into(),
    ))
}

fn project_parliament_timed_ovn_progress_v1(
    ballot: &ParliamentBallotStateV1,
    lifecycle: &TimedOvnLifecycleStateV1,
) -> Result<ParliamentTimedOvnProgressProjectionV1, crate::Error> {
    let ballot_attempt_id = ballot.attempt().id;
    if lifecycle.ballot_attempt_id() != *ballot_attempt_id.as_bytes() {
        return Err(parliament_attempt_projection_error(
            "active Parliament ballot and timed-OVN lifecycle identifiers disagree",
        ));
    }
    let survivor_count = match lifecycle {
        TimedOvnLifecycleStateV1::Registered(_)
        | TimedOvnLifecycleStateV1::RegistrationClosed(_) => None,
        TimedOvnLifecycleStateV1::SurvivorsFrozen(state) => {
            Some(state.survivor_participant_hashes().len())
        }
        TimedOvnLifecycleStateV1::CorpusOpen(state) => {
            Some(state.frozen().survivor_participant_hashes().len())
        }
        TimedOvnLifecycleStateV1::Sealed(state) => Some(state.survivor_participant_hashes.len()),
        TimedOvnLifecycleStateV1::Released(state) => {
            Some(state.sealed.survivor_participant_hashes.len())
        }
    }
    .map(|count| {
        u32::try_from(count).map_err(|_| {
            parliament_attempt_projection_error(
                "timed-OVN frozen survivor count exceeds the public projection width",
            )
        })
    })
    .transpose()?;
    let projection = ParliamentTimedOvnProgressProjectionV1 {
        ballot_attempt_id,
        status: ballot.attempt().status,
        frozen_survivor_count: survivor_count,
        accepted_ballot_prefix_count: lifecycle.accepted_ballot_prefix_count(),
    };
    projection.validate_static().map_err(|_| {
        parliament_attempt_projection_error(
            "active Parliament ballot has phase-inconsistent timed-OVN progress",
        )
    })?;
    Ok(projection)
}

fn project_parliament_tle_key_session_v1(
    session: &iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1,
) -> ParliamentTleKeySessionBindingV1 {
    ParliamentTleKeySessionBindingV1 {
        version: session.version,
        key_session_id: session.key_session_id,
        network_id: session.network_id,
        roster_hash: session.roster_hash,
        committee_size: session.committee_size,
        threshold: session.threshold,
        generator_h: session.generator_h,
        generator_v: session.generator_v,
        qualified_dealers: session.qualified_dealers.clone(),
        qualified_dealer_commitments: session
            .qualified_dealer_commitments
            .iter()
            .map(|dealer| ParliamentTleAdaptiveDealerCommitmentV1 {
                dealer_index: dealer.dealer_index,
                coefficient_commitments: dealer.coefficient_commitments.clone(),
                constant_pok_commitment: dealer.constant_pok_commitment,
                constant_pok_response: dealer.constant_pok_response,
            })
            .collect(),
        dkg_event_hash: session.dkg_event_hash,
        group_public_key: session.group_public_key,
        public_shares: session
            .public_shares
            .iter()
            .map(|share| ParliamentTleAdaptivePublicShareV1 {
                index: share.index,
                participant_hash: share.participant_hash,
                public_key_share: share.public_key_share,
            })
            .collect(),
        transcript_hash: session.transcript_hash,
    }
}

fn project_parliament_timed_ovn_release_identity_v1(
    identity: &iroha_core_timed_ovn::evidence::TimedOvnReleaseIdentityPublicV1,
) -> ParliamentTimedOvnReleaseIdentityProjectionV1 {
    use iroha_data_model::governance::types::{
        BallotAttemptId, BodyInstanceId, GovernanceAttemptId,
    };

    ParliamentTimedOvnReleaseIdentityProjectionV1 {
        tle_key_session_id: identity.tle_key_session_id,
        governance_attempt_id: GovernanceAttemptId::new(identity.governance_attempt_id),
        body_instance_id: BodyInstanceId::new(identity.body_instance_id),
        ballot_attempt_id: BallotAttemptId::new(identity.ballot_attempt_id),
        survivor_corpus_root: identity.survivor_corpus_root,
        no_recovery_root: identity.no_recovery_root,
        target_finalized_height: identity.target_finalized_height,
        parameter_hash: identity.parameter_hash,
    }
}

/// GET `/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context`.
///
/// Core admits only the three pre-seal timed-OVN phases and replays the exact
/// lifecycle and complete public TLE transcript before this projection is
/// built. This node-local projection is diagnostic only and is never sufficient
/// native-wallet or seed-unsealing input. Wallets consume the finality-bound
/// casting-proof route, verify an externally pinned consensus chain, and replay
/// its archive before touching secret material.
///
/// # Errors
/// Returns a conversion error for a noncanonical identifier or unavailable,
/// terminal, cross-bound, or replay-invalid committed state.
pub fn handle_gov_parliament_timed_ovn_casting_context_read(
    state: Arc<iroha_core::state::State>,
    ballot_attempt_id: String,
) -> Result<JsonBody<ParliamentTimedOvnCastingContextResponseV1>, crate::Error> {
    use base64::Engine as _;
    use iroha_core_timed_ovn::casting::ParliamentTimedOvnCastingPhaseV1;
    use iroha_data_model::governance::types::{
        BallotAttemptId, BodyInstanceId, GovernanceAttemptId, ProposalContentId,
    };

    let ballot_attempt_id = ballot_attempt_id.parse::<BallotAttemptId>().map_err(|_| {
        crate::routing::conversion_error(
            "ballot_attempt_id must be exactly 64 lowercase hexadecimal characters".to_owned(),
        )
    })?;
    if ballot_attempt_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(crate::routing::conversion_error(
            "ballot_attempt_id must be non-zero".to_owned(),
        ));
    }

    let view = state.query_view();
    let context = iroha_core::tle_release::authorize_parliament_timed_ovn_casting_context_v1(
        &view,
        ballot_attempt_id,
    )
    .map_err(|error| {
        crate::routing::conversion_error(format!(
            "Parliament timed-OVN casting context is not authorized: {error}"
        ))
    })?;
    let archive = context.archive_v1();
    let archive_bytes = archive.to_canonical_bytes_v1().map_err(|error| {
        crate::Error::Query(iroha_data_model::ValidationFail::InternalError(format!(
            "authorized Parliament timed-OVN casting archive could not be framed: {error}"
        )))
    })?;
    let session = context.session();
    let phase = match context.phase() {
        ParliamentTimedOvnCastingPhaseV1::Registered => {
            ParliamentTimedOvnCastingPhaseProjectionV1::Registered
        }
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
            ParliamentTimedOvnCastingPhaseProjectionV1::RegistrationClosed
        }
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => {
            ParliamentTimedOvnCastingPhaseProjectionV1::SurvivorsFrozen
        }
    };
    let response = ParliamentTimedOvnCastingContextResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        current_height: context.finalized_height(),
        phase,
        session: ParliamentTimedOvnSessionProjectionV1 {
            network_id: session.network_id,
            proposal_content_id: ProposalContentId::new(session.proposal_content_id),
            governance_attempt_id: GovernanceAttemptId::new(session.governance_attempt_id),
            body_instance_id: BodyInstanceId::new(session.body_instance_id),
            ballot_attempt_id: BallotAttemptId::new(session.ballot_attempt_id),
            parameter_hash: session.parameter_hash,
            tle_key_session_id: session.tle_key_session_id,
            tle_key_transcript_hash: session.tle_key_transcript_hash,
            tle_master_public_key: session.tle_master_public_key,
        },
        registration_opened_at_finalized_height: context.registration_opened_at_finalized_height(),
        target_finalized_height: context.target_finalized_height(),
        tle_key_session: project_parliament_tle_key_session_v1(
            context.tle_key_session().public_state(),
        ),
        registration_records_hex: context
            .registration_records()
            .iter()
            .map(hex::encode)
            .collect(),
        survivor_participant_hashes: context.survivor_participant_hashes().map(<[_]>::to_vec),
        release_identity: context
            .release_identity()
            .map(project_parliament_timed_ovn_release_identity_v1),
        archive_norito_base64: base64::engine::general_purpose::STANDARD.encode(archive_bytes),
    };
    response
        .validate_for_ballot(ballot_attempt_id)
        .map_err(|reason| {
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
                reason.into(),
            ))
        })?;
    Ok(JsonBody(response))
}

/// POST `/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof`.
///
/// A bounded intermediate page carries only consecutive finality proofs for
/// durable checkpoint promotion. The terminal page additionally carries the
/// replay-validated public archive, its exact compact binding, membership in
/// the per-block casting root, and the fixed ordinary-write witness.
///
/// # Errors
/// Returns a conversion error for an invalid request/identifier and a stable
/// service error when finalized proof material is unavailable or inconsistent.
pub fn handle_gov_parliament_timed_ovn_casting_proof(
    state: Arc<iroha_core::state::State>,
    kura: Arc<Kura>,
    ballot_attempt_id: String,
    request: ParliamentTimedOvnCastingProofRequestV1,
) -> Result<NoritoBody<ParliamentTimedOvnCastingProofResponseV1>, crate::Error> {
    use iroha_data_model::governance::types::BallotAttemptId;

    let inconsistent = |message: String| crate::Error::AppServiceUnavailable {
        code: "parliament_timed_ovn_casting_proof_inconsistent",
        message,
    };
    if request.version != PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1
        || request.trusted_checkpoint_height == 0
    {
        return Err(crate::routing::conversion_error(
            "Parliament casting proof version or checkpoint height is invalid".to_owned(),
        ));
    }
    let ballot_attempt_id = ballot_attempt_id.parse::<BallotAttemptId>().map_err(|_| {
        crate::routing::conversion_error(
            "ballot_attempt_id must be exactly 64 lowercase hexadecimal characters".to_owned(),
        )
    })?;
    if ballot_attempt_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(crate::routing::conversion_error(
            "ballot_attempt_id must be non-zero".to_owned(),
        ));
    }

    let state_view = state.query_view();
    let observed_ledger_tip_height = u64::try_from(state_view.height()).map_err(|_| {
        inconsistent("ledger height does not fit the Parliament casting proof".to_owned())
    })?;
    if request.trusted_checkpoint_height > observed_ledger_tip_height {
        return Err(crate::routing::conversion_error(
            "trusted checkpoint is newer than the observed ledger tip".to_owned(),
        ));
    }
    let evaluated_height = parliament_timed_ovn_casting_proof_page_tip(
        request.trusted_checkpoint_height,
        observed_ledger_tip_height,
    )
    .ok_or_else(|| {
        crate::routing::conversion_error(
            "trusted checkpoint cannot begin a Parliament casting finality page".to_owned(),
        )
    })?;

    let terminal_archive = if evaluated_height == observed_ledger_tip_height {
        let authorized =
            iroha_core::tle_release::authorize_parliament_timed_ovn_casting_context_v1(
                &state_view,
                ballot_attempt_id,
            )
            .map_err(|error| {
                crate::routing::conversion_error(format!(
                    "Parliament timed-OVN casting context is not authorized: {error}"
                ))
            })?;
        let archive = authorized.archive_v1();
        let archive_bytes = archive.to_canonical_bytes_v1().map_err(|error| {
            inconsistent(format!(
                "authorized Parliament casting archive could not be framed: {error}"
            ))
        })?;
        Some((archive, archive_bytes))
    } else {
        None
    };
    let proof_view = state_view;
    if !std::ptr::eq(kura.as_ref(), proof_view.kura()) {
        return Err(inconsistent(
            "casting proof storage differs from the selected State".to_owned(),
        ));
    }

    let terminal_fields = if let Some((archive, archive_bytes)) = terminal_archive {
        let proof = iroha_core::query::native_receipts::parliament_casting_proof(
            &proof_view,
            evaluated_height,
            ballot_attempt_id,
        )
        .map_err(|error| {
            inconsistent(format!(
                "evaluated Parliament casting proof is invalid: {error}"
            ))
        })?
        .ok_or_else(|| {
            inconsistent(
                "authorized ballot has no retained finalized casting membership proof".to_owned(),
            )
        })?;
        let validated_archive = archive.validate_v1().map_err(|error| {
            inconsistent(format!(
                "authorized Parliament casting archive failed replay: {error}"
            ))
        })?;
        if !validated_archive.matches_compact_binding_v1(&proof.binding) {
            return Err(inconsistent(
                "authorized casting archive differs from its finalized compact binding".to_owned(),
            ));
        }
        (
            Some(archive_bytes),
            Some(proof.binding),
            Some(proof.membership_proof),
            Some(proof.snapshot_witness),
        )
    } else {
        (None, None, None, None)
    };

    let proof_count = evaluated_height
        .checked_sub(request.trusted_checkpoint_height)
        .and_then(|gap| gap.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| {
            crate::routing::conversion_error(
                "trusted checkpoint is newer than the evaluated casting block".to_owned(),
            )
        })?;
    let chain = iroha_core::sumeragi::certified_chain::CertifiedChain::new(&proof_view)
        .map_err(|error| inconsistent(format!("native finality source is unavailable: {error}")))?;
    let mut finality_chain = Vec::with_capacity(proof_count);
    for height in request.trusted_checkpoint_height..=evaluated_height {
        finality_chain.push(
            iroha_core::sumeragi::finality::build_proof(&proof_view, height).map_err(|error| {
                inconsistent(format!(
                    "Parliament casting finality proof at height {height} is unavailable: {error}"
                ))
            })?,
        );
    }
    let finality_encoded_bytes =
        norito::core::encoded_frame_len(&finality_chain).map_err(|error| {
            inconsistent(format!(
                "Parliament casting finality chain cannot be encoded: {error}"
            ))
        })?;
    if finality_encoded_bytes > PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_FINALITY_CHAIN_BYTES_V1 {
        return Err(crate::Error::AppConflict {
            code: "parliament_timed_ovn_casting_finality_page_too_large",
            message: "The bounded Parliament casting finality page exceeds its byte budget."
                .to_owned(),
        });
    }
    let evaluated = finality_chain
        .last()
        .ok_or_else(|| inconsistent("Parliament casting finality chain is empty".to_owned()))?;
    let evaluated_native = chain.committed(evaluated_height).map_err(|error| {
        inconsistent(format!(
            "evaluated native commitment is unavailable: {error}"
        ))
    })?;
    let evaluated_context_id = iroha_crypto::Hash::from(evaluated_native.id().0);
    let evaluated_block_hash = evaluated.block_header.hash();
    let response = ParliamentTimedOvnCastingProofResponseV1 {
        version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
        casting_context_archive: terminal_fields.0,
        casting_context_binding: terminal_fields.1,
        context_membership_proof: terminal_fields.2,
        casting_witness: terminal_fields.3,
        finality_chain,
        evaluated_context_id,
        evaluated_block_height: evaluated_height,
        evaluated_block_hash: hex::encode(evaluated_block_hash.as_ref()),
        observed_ledger_tip_height,
        more_available: evaluated_height < observed_ledger_tip_height,
    };
    let checkpoint = iroha_core::sumeragi::finality::build_checkpoint(
        &proof_view,
        request.trusted_checkpoint_height,
    )
    .map_err(|error| inconsistent(format!("trusted native prefix is unavailable: {error}")))?;
    response
        .verify_consensus_page_against(checkpoint.network_id(), &checkpoint, ballot_attempt_id)
        .map_err(|error| inconsistent(format!("constructed casting proof failed: {error}")))?;
    let response_encoded_bytes = norito::core::encoded_frame_len(&response).map_err(|error| {
        inconsistent(format!(
            "Parliament casting proof response cannot be encoded: {error}"
        ))
    })?;
    if response_encoded_bytes > PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_RESPONSE_BYTES_V1 {
        return Err(crate::Error::AppConflict {
            code: "parliament_timed_ovn_casting_proof_too_large",
            message: "The Parliament casting proof exceeds its response byte budget.".to_owned(),
        });
    }
    Ok(NoritoBody(response))
}

/// GET `/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context`.
///
/// Core returns a context only for a replay-valid sealed timed-OVN corpus whose
/// committed ballot is already `Opening`, whose release height has arrived,
/// and whose inclusive opening deadline has not passed. The response contains
/// public transcript and identity bindings only; it excludes every corpus,
/// share, secret, and individual opening.
///
/// # Errors
/// Returns a conversion error for a noncanonical identifier or when Core does
/// not authorize release from the point-in-time committed query view.
pub fn handle_gov_parliament_tle_release_context_read(
    state: Arc<iroha_core::state::State>,
    ballot_attempt_id: String,
) -> Result<JsonBody<ParliamentTleReleaseContextResponseV1>, crate::Error> {
    use iroha_data_model::governance::types::{
        BallotAttemptId, BallotAttemptStatusV1, BodyInstanceId, GovernanceAttemptId,
    };
    use sha2::{Digest as _, Sha256};

    let ballot_attempt_id = ballot_attempt_id.parse::<BallotAttemptId>().map_err(|_| {
        crate::routing::conversion_error(
            "ballot_attempt_id must be exactly 64 lowercase hexadecimal characters".to_owned(),
        )
    })?;
    if ballot_attempt_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(crate::routing::conversion_error(
            "ballot_attempt_id must be non-zero".to_owned(),
        ));
    }

    let view = state.query_view();
    let context =
        iroha_core::tle_release::authorize_parliament_tle_release_v1(&view, ballot_attempt_id)
            .map_err(|error| {
                crate::routing::conversion_error(format!(
                    "Parliament TLE release context is not authorized: {error}"
                ))
            })?;
    let release_identity = context.public_release_identity();
    let session = context.session().public_state();
    let identity_payload = context.identity().payload_bytes();
    let identity_digest: [u8; 32] =
        Sha256::digest(context.identity().release_message().map_err(|error| {
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(format!(
                "authorized Parliament TLE release message could not be framed: {error}"
            )))
        })?)
        .into();

    let response = ParliamentTleReleaseContextResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        current_height: context.finalized_height(),
        ballot_attempt_id,
        governance_attempt_id: GovernanceAttemptId::new(release_identity.governance_attempt_id),
        body_instance_id: BodyInstanceId::new(release_identity.body_instance_id),
        status: BallotAttemptStatusV1::Opening,
        release_height: release_identity.target_finalized_height,
        opening_deadline_height: context.opening_deadline_height(),
        tle_key_session: project_parliament_tle_key_session_v1(session),
        release_identity: project_parliament_timed_ovn_release_identity_v1(release_identity),
        identity_digest,
        identity_payload_hex: hex::encode(identity_payload),
    };
    response
        .validate_for_ballot(ballot_attempt_id)
        .map_err(|reason| {
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
                reason.into(),
            ))
        })?;
    Ok(JsonBody(response))
}
/// Strict citizen registration draft request.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::CitizenDraftRequestV1")]
#[derive(Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]

pub struct CitizenDraftRequestV1 {
    /// Request layout version.
    pub version: u16,
    /// Canonical citizen account that will sign the resulting instruction.
    pub owner: iroha_data_model::account::AccountId,
}
/// Exact native citizen registration draft.
#[derive(Debug, JsonSerialize)]
pub struct CitizenDraftResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Canonical citizen account.
    pub owner: iroha_data_model::account::AccountId,
    /// Exact configured bond as a decimal string.
    pub amount: String,
    /// Exactly one canonical `RegisterCitizen` instruction.
    pub tx_instructions: Vec<TxInstr>,
}
/// POST `/v1/gov/citizens/draft` — build the exact configured citizenship instruction.
///
/// # Errors
/// Returns a conversion error for unsupported request versions.
pub async fn handle_gov_citizen_draft(
    state: Arc<iroha_core::state::State>,
    NoritoJson(body): NoritoJson<CitizenDraftRequestV1>,
) -> Result<JsonBody<CitizenDraftResponseV1>, crate::Error> {
    if body.version != GOVERNANCE_CAPABILITIES_VERSION_V1 {
        return Err(crate::routing::conversion_error(
            "unsupported governance citizen draft version".into(),
        ));
    }
    let amount = state.governance_snapshot().citizenship_bond_amount;
    let instruction = iroha_data_model::isi::governance::RegisterCitizen {
        owner: body.owner.clone(),
        amount: amount.clone(),
    };
    Ok(JsonBody(CitizenDraftResponseV1 {
        version: GOVERNANCE_CAPABILITIES_VERSION_V1,
        owner: body.owner,
        amount: amount.to_string(),
        tx_instructions: vec![tx_instr_from_box(instruction.into())],
    }))
}
/// GET /v1/gov/citizens — return the exact citizenship registry count.
///
/// # Errors
/// This handler never returns an error; an empty registry is represented as `total = 0`.
pub async fn handle_gov_citizen_count(
    state: Arc<iroha_core::state::State>,
) -> Result<JsonBody<CitizenCountResponse>, crate::Error> {
    let world = state.world_view();
    Ok(JsonBody(CitizenCountResponse {
        total: world.citizens().len().to_string(),
    }))
}
/// GET /v1/gov/citizens/{account_id} — read the citizenship registry entry for an account.
///
/// # Errors
/// Returns a conversion error when the account id path segment is invalid.
pub async fn handle_gov_citizen_status(
    state: Arc<iroha_core::state::State>,
    account_id: axum::extract::Path<String>,
    telemetry: MaybeTelemetry,
) -> Result<JsonBody<CitizenStatusResponse>, crate::Error> {
    let (account, canonical_account_id) = parse_account_literal_with_state(
        state.as_ref(),
        &account_id.0,
        &telemetry,
        "/v1/gov/citizens/{account_id}",
    )
    .map_err(|err| {
        crate::routing::conversion_error(format!("invalid account_id: {}", err.reason()))
    })?;
    let world = state.world_view();
    let record = world.citizens().get(&account).cloned();
    Ok(JsonBody(CitizenStatusResponse {
        account_id: canonical_account_id.to_string(),
        is_citizen: record.is_some(),
        amount: record.as_ref().map(|record| record.amount.to_string()),
        bonded_height: record
            .as_ref()
            .map(|record| record.bonded_height.to_string()),
    }))
}
// --- Unlock sweep stats (operator/audit) ---
/// Response with lock/unlock statistics.
#[derive(Copy, Clone, Debug, JsonSerialize)]
pub struct UnlockStatsResponse {
    /// Current committed State height.
    pub height_current: u64,
    /// Number of locks that would be expired at current height across all referenda
    pub expired_locks_now: u64,
    /// Number of referenda that have at least one expired lock
    pub referenda_with_expired: u64,
    /// Height at which expired locks were last swept and persisted
    pub last_sweep_height: u64,
}
/// Compute and return aggregate unlock statistics for governance locks.
///
/// # Errors
/// This handler never returns an error; the response always reflects the current view snapshot.
pub async fn handle_gov_unlock_stats(
    state: Arc<iroha_core::state::State>,
) -> Result<JsonBody<UnlockStatsResponse>, crate::Error> {
    let view = state.query_view();
    let snapshot = *view.world().governance_unlock_stats();
    let last_sweep_height = *view.world().governance_last_unlock_sweep_height();
    Ok(JsonBody(UnlockStatsResponse {
        height_current: u64::try_from(view.height()).unwrap_or(u64::MAX),
        expired_locks_now: snapshot.expired_locks_now,
        referenda_with_expired: snapshot.referenda_with_expired,
        last_sweep_height,
    }))
}
#[derive(Debug, JsonSerialize)]
/// Instruction skeleton item for client-side signing.
///
/// `wire_id` identifies the instruction on the wire; `payload_hex` carries
/// the Norito-encoded payload as lowercase hex without `0x`.
pub struct TxInstr {
    pub wire_id: String,
    pub payload_hex: String,
}
fn tx_instr_from_box(boxed: iroha_data_model::isi::InstructionBox) -> TxInstr {
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(&boxed)
        .expect("governance skeleton must contain a registered instruction");
    TxInstr {
        wire_id: wire_id.to_owned(),
        payload_hex: hex::encode(framed),
    }
}
fn ensure_network_id_matches(
    state: &iroha_core::state::State,
    provided: &iroha_data_model::NetworkId,
) -> Result<(), crate::Error> {
    if state.network_id_ref() != provided {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "governance ballot targets a different network".to_owned(),
            ),
        ));
    }
    Ok(())
}
fn ensure_authenticated_authority(
    authenticated_account: &iroha_data_model::account::AccountId,
    authority: &iroha_data_model::account::AccountId,
) -> Result<(), crate::Error> {
    if authenticated_account != authority {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "authenticated account must equal the governance ballot authority".to_owned(),
            ),
        ));
    }
    Ok(())
}
fn parse_account_literal_from_state(
    state: &iroha_core::state::State,
    raw: &str,
    telemetry: &MaybeTelemetry,
    context: &'static str,
) -> Result<iroha_data_model::account::AccountId, iroha_model_base::error::ParseError> {
    parse_account_literal_with_state(state, raw, telemetry, context)
        .map(|(account_id, _)| account_id)
}
fn parse_authority_literal(
    state: &iroha_core::state::State,
    raw: &str,
    telemetry: &MaybeTelemetry,
    context: &'static str,
) -> Result<iroha_data_model::account::AccountId, crate::Error> {
    parse_account_literal_from_state(state, raw, telemetry, context).map_err(|err| {
        crate::routing::conversion_error(format!("invalid authority: {}", err.reason()))
    })
}
fn parse_canonical_authority_literal(
    state: &iroha_core::state::State,
    raw: &str,
    telemetry: &MaybeTelemetry,
    context: &'static str,
) -> Result<iroha_data_model::account::AccountId, crate::Error> {
    let canonical = iroha_data_model::account::AccountId::canonicalize(raw).map_err(|_| {
        crate::routing::conversion_error("authority must use canonical I105 account id form".into())
    })?;
    if canonical != raw {
        return Err(crate::routing::conversion_error(
            "authority must use canonical I105 account id form".into(),
        ));
    }
    parse_authority_literal(state, raw, telemetry, context)
}
fn instruction_skeleton_for_propose(
    instr: &iroha_data_model::isi::governance::ProposeDeployContract,
) -> [GovernanceProposalInstructionDraftV1; 1] {
    let boxed: iroha_data_model::isi::InstructionBox = instr.clone().into();
    [governance_proposal_instruction_draft(boxed)]
}
fn instruction_skeleton_for_sccp_route_governance_propose(
    instr: &iroha_data_model::isi::governance::ProposeSccpRouteGovernance,
) -> [GovernanceProposalInstructionDraftV1; 1] {
    let boxed: iroha_data_model::isi::InstructionBox = instr.clone().into();
    [governance_proposal_instruction_draft(boxed)]
}
fn governance_proposal_instruction_draft(
    boxed: iroha_data_model::isi::InstructionBox,
) -> GovernanceProposalInstructionDraftV1 {
    let TxInstr {
        wire_id,
        payload_hex,
    } = tx_instr_from_box(boxed);
    GovernanceProposalInstructionDraftV1 {
        wire_id,
        payload_hex,
    }
}
fn build_signable_transaction_b64(
    network_id: &iroha_data_model::NetworkId,
    authority: &iroha_data_model::account::AccountId,
    instructions: Vec<iroha_data_model::isi::InstructionBox>,
) -> String {
    let builder = iroha_data_model::transaction::signed::TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    base64::engine::general_purpose::STANDARD.encode(builder.encode_payload())
}
fn deploy_contract_proposal_kind(
    proposal_operator: &iroha_data_model::account::AccountId,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    code_hash: &[u8; 32],
    abi_hash: &[u8; 32],
    manifest_provenance: Option<ManifestProvenance>,
) -> ProposalKind {
    ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: proposal_operator.clone(),
        contract_address: contract_address.clone(),
        code_hash: ContractCodeHash::new(*code_hash),
        abi_hash: ContractAbiHash::new(*abi_hash),
        abi_version: AbiVersion::new(1),
        manifest_provenance,
    })
}
fn sccp_route_governance_proposal_kind(
    proposal: &iroha_data_model::sccp::governance::SccpGovernanceProposalV1,
) -> ProposalKind {
    ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(proposal.clone()),
    })
}
fn resolve_governance_contract_target(
    state: &iroha_core::state::State,
    contract_address: Option<&iroha_data_model::smart_contract::ContractAddress>,
    contract_alias: Option<&iroha_data_model::smart_contract::ContractAlias>,
) -> Result<iroha_data_model::smart_contract::ContractAddress, crate::Error> {
    match (contract_address, contract_alias) {
        (Some(_), Some(_)) => Err(crate::Error::Query(
            iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "exactly one of contract_address or contract_alias must be provided".into(),
                ),
            ),
        )),
        (Some(contract_address), None) => Ok(contract_address.clone()),
        (None, Some(contract_alias)) => {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            state
                .world_view()
                .contract_address_by_alias_at(contract_alias, now_ms)
                .ok_or_else(|| {
                    crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::NotFound,
                    ))
                })
        }
        (None, None) => Err(crate::Error::Query(
            iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "provide exactly one contract target via contract_address or contract_alias"
                        .into(),
                ),
            ),
        )),
    }
}
#[derive(Debug, JsonSerialize)]
/// Response payload for GET /v1/gov/proposals/{id}
pub struct ProposalGetResponse {
    /// Whether the proposal exists.
    pub found: bool,
    #[norito(skip_serializing_if = "Option::is_none")]
    /// Proposal record if found.
    pub proposal: Option<iroha_core::state::GovernanceProposalRecord>,
}
#[derive(Debug, JsonSerialize)]
/// Response payload for GET /v1/gov/locks/{rid}
pub struct LocksGetResponse {
    /// Whether locks exist for the given referendum id.
    pub found: bool,
    /// Referendum id echoed.
    pub referendum_id: String,
    #[norito(skip_serializing_if = "Option::is_none")]
    /// Locks record, when present.
    pub locks: Option<iroha_core::state::GovernanceLocksForReferendum>,
}
/// Response payload for GET /v1/gov/referenda/{id} Response payload for referendum lookup by id.
#[derive(Clone, Debug, JsonSerialize)]
pub struct ReferendumGetResponse {
    /// Whether the referendum exists.
    pub found: bool,
    #[norito(skip_serializing_if = "Option::is_none")]
    /// Referendum record if found.
    pub referendum: Option<iroha_core::state::GovernanceReferendumRecord>,
}
#[derive(Debug, JsonSerialize)]
/// Response payload for GET /v1/gov/tally/{id}
pub struct TallyGetResponse {
    /// Referendum id.
    pub referendum_id: String,
    /// Committed block height whose state was used for the tally.
    pub evaluated_block_height: u64,
    /// Committed block hash whose state was used for the tally.
    pub evaluated_block_hash: String,
    /// Approve votes.
    pub approve: u128,
    /// Reject votes.
    pub reject: u128,
    /// Abstain votes.
    pub abstain: u128,
}
/// Handler for fetching a proposal record by hex id.
///
/// # Errors
/// Returns `crate::Error::Query` unless the identifier is exact lowercase 32-byte hex.
pub async fn handle_gov_get_proposal(
    state: Arc<iroha_core::state::State>,
    id: axum::extract::Path<String>,
) -> Result<JsonBody<ProposalGetResponse>, crate::Error> {
    let id_arr = parse_exact_lower_hex32_path("proposal id", &id.0)?;
    let world = state.world_view();
    let found = world.governance_proposals().get(&id_arr).cloned();
    Ok(JsonBody(ProposalGetResponse {
        found: found.is_some(),
        proposal: found,
    }))
}
/// Handler for fetching governance locks by referendum id.
///
/// # Errors
/// Returns a conversion error for a noncanonical referendum token. Missing locks are reported
/// with `found = false`.
pub async fn handle_gov_get_locks(
    state: Arc<iroha_core::state::State>,
    rid: axum::extract::Path<String>,
) -> Result<JsonBody<LocksGetResponse>, crate::Error> {
    let ref_id = rid.0;
    require_exact_governance_path_token("referendum id", &ref_id)?;
    let world = state.world_view();
    reject_typed_proposal_ballot_selector(&world, &ref_id)
        .map_err(crate::routing::conversion_error)?;
    let found = world.governance_locks().get(&ref_id).cloned();
    Ok(JsonBody(LocksGetResponse {
        found: found.is_some(),
        referendum_id: ref_id,
        locks: found,
    }))
}
/// Handler for fetching a referendum by id.
///
/// # Errors
/// Returns a conversion error for a noncanonical referendum token. Missing referenda are returned
/// with `found = false`.
pub async fn handle_gov_get_referendum(
    state: Arc<iroha_core::state::State>,
    id: axum::extract::Path<String>,
) -> Result<JsonBody<ReferendumGetResponse>, crate::Error> {
    let rid = id.0;
    require_exact_governance_path_token("referendum id", &rid)?;
    let world = state.world_view();
    reject_typed_proposal_ballot_selector(&world, &rid)
        .map_err(crate::routing::conversion_error)?;
    let found = world.governance_referenda().get(&rid).cloned();
    Ok(JsonBody(ReferendumGetResponse {
        found: found.is_some(),
        referendum: found,
    }))
}
/// Handler for computing a referendum tally summary.
///
/// # Errors
/// Returns a conversion error if an exact quadratic weight or tally exceeds
/// the fixed consensus tally domain, a PLAIN lock carries an invalid direction,
/// or the selector is the fingerprint of a stored typed proposal. Typed proposals
/// use the authenticated Parliament attempt-read API. Missing referenda return `NotFound`.
pub async fn handle_gov_get_tally(
    state: Arc<iroha_core::state::State>,
    id: axum::extract::Path<String>,
) -> Result<JsonBody<TallyGetResponse>, crate::Error> {
    let rid = id.0;
    require_exact_governance_path_token("referendum id", &rid)?;
    let view = state.query_view();
    governance_tally_from_view(&view, rid).map(JsonBody)
}

// The projection accepts only one captured owner, so a later commit cannot mix
// the corpus, selector authority, cutoff height or reported block identity.
fn governance_tally_from_view(
    view: &iroha_core::state::StateQueryView<'_>,
    rid: String,
) -> Result<TallyGetResponse, crate::Error> {
    let world = view.world();
    reject_typed_proposal_ballot_selector(world, &rid).map_err(crate::routing::conversion_error)?;
    let referendum = world
        .governance_referenda()
        .get(&rid)
        .cloned()
        .ok_or_else(|| {
            crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            ))
        })?;
    let evaluated_block_height = u64::try_from(view.height()).map_err(|_| {
        crate::routing::conversion_error("governance snapshot height exceeds u64".to_owned())
    })?;
    let evaluated_block_hash = match view.latest_block_hash() {
        Some(hash) => hex::encode(hash.as_ref()),
        None if evaluated_block_height == 0 => hex::encode([0_u8; 32]),
        None => {
            return Err(crate::Error::Query(
                iroha_data_model::ValidationFail::InternalError(
                    "governance snapshot height has no committed block hash".to_owned(),
                ),
            ));
        }
    };
    referendum
        .validate_context()
        .map_err(|message| crate::routing::conversion_error(message.into()))?;
    // Project the current standalone referendum tally without mutating state.
    let mut approve: u128 = 0;
    let mut reject: u128 = 0;
    let mut abstain: u128 = 0;
    match referendum.mode {
        iroha_core::state::GovernanceReferendumMode::Plain => {
            [approve, reject, abstain] = iroha_core::state::plain_governance_tally(
                &referendum,
                world.governance_locks().get(&rid),
                evaluated_block_height,
            )
            .map_err(|message| crate::routing::conversion_error(message.into()))?;
        }
        iroha_core::state::GovernanceReferendumMode::Zk => {
            if let Some(e) = world.elections().get(&rid) {
                if e.finalized && e.tally.len() >= 2 {
                    approve = e.tally[0];
                    reject = e.tally[1];
                    abstain = e.tally.get(2).copied().unwrap_or(0);
                }
            }
        }
    }
    Ok(TallyGetResponse {
        referendum_id: rid,
        evaluated_block_height,
        evaluated_block_hash,
        approve,
        reject,
        abstain,
    })
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::gov::ProtectedNamespacesDto")]
#[derive(Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize)]
#[norito(deny_unknown_fields)]
/// Request body for applying protected namespaces parameter.

pub struct ProtectedNamespacesDto {
    /// Namespaces to protect (e.g., `["apps", "system"]`).
    pub namespaces: Vec<String>,
    /// Optional canonical I105 account id used to build a signable transaction payload.
    #[norito(default)]
    pub authority: Option<String>,
}
#[derive(Debug, JsonSerialize)]
/// Response to drafting a protected namespaces parameter transaction.
pub struct ProtectedNamespacesApplyResponse {
    pub ok: bool,
    pub namespace_count: usize,
    pub submitted: bool,
    pub tx_instructions: Vec<TxInstr>,
    pub signable_transaction_b64: Option<String>,
}
/// POST /v1/gov/protected-namespaces — draft a custom-parameter transaction.
///
/// # Errors
/// Returns `crate::Error::Query` when the namespaces cannot be serialized into
/// the custom parameter or the optional authority cannot be resolved.
pub async fn handle_gov_protected_set(
    state: Arc<iroha_core::state::State>,
    telemetry: MaybeTelemetry,
    NoritoJson(body): NoritoJson<ProtectedNamespacesDto>,
) -> Result<JsonBody<ProtectedNamespacesApplyResponse>, crate::Error> {
    use iroha_data_model::parameter::{CustomParameterId, Parameter, custom::CustomParameter};
    use std::str::FromStr as _;
    let namespaces = body.namespaces;
    iroha_core::smartcontracts::code::validate_protected_contract_namespaces(&namespaces)
        .map_err(|error| crate::routing::conversion_error(error.to_string()))?;
    let namespace_count = namespaces.len();
    let name = iroha_model_base::name::Name::from_str("gov_protected_namespaces").map_err(|e| {
        crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
            e.to_string(),
        ))
    })?;
    let id = CustomParameterId(name);
    // Convert Vec<String> -> Vec<&str> to satisfy Json's From<Vec<T>> bound
    let json_array = norito::json::native::Value::Array(
        namespaces
            .into_iter()
            .map(norito::json::native::Value::from)
            .collect(),
    );
    let json = iroha_primitives::json::Json::from(json_array);
    let custom = CustomParameter::new(id, json);
    let isi = iroha_data_model::isi::SetParameter::new(Parameter::Custom(custom));
    let instruction: iroha_data_model::isi::InstructionBox = isi.into();
    let tx_instructions = vec![tx_instr_from_box(instruction.clone())];
    let signable_transaction_b64 = if let Some(authority) = body.authority.as_deref() {
        let authority_id = parse_canonical_authority_literal(
            state.as_ref(),
            authority,
            &telemetry,
            CONTEXT_GOV_PROTECTED_AUTHORITY,
        )?;
        Some(build_signable_transaction_b64(
            state.network_id_ref(),
            &authority_id,
            vec![instruction],
        ))
    } else {
        None
    };
    Ok(JsonBody(ProtectedNamespacesApplyResponse {
        ok: true,
        namespace_count,
        submitted: false,
        tx_instructions,
        signable_transaction_b64,
    }))
}
#[derive(Debug, JsonSerialize)]
/// Response for reading protected namespaces parameter
pub struct ProtectedNamespacesGetResponse {
    /// Whether the parameter is set.
    pub found: bool,
    /// List of protected namespaces.
    pub namespaces: Vec<String>,
}
/// GET /v1/gov/protected-namespaces — read current setting from custom parameters.
///
/// # Errors
/// Returns an internal query error when a present on-chain policy is malformed. Absent parameters
/// yield `found = false`.
pub async fn handle_gov_protected_get(
    state: Arc<iroha_core::state::State>,
) -> Result<JsonBody<ProtectedNamespacesGetResponse>, crate::Error> {
    let world = state.world_view();
    let params = world.parameters();
    let policy = iroha_core::smartcontracts::code::protected_contract_namespaces(params).map_err(
        |error| {
            crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
                error.to_string(),
            ))
        },
    )?;
    let found = policy.is_some();
    let namespaces = policy.unwrap_or_default();
    Ok(JsonBody(ProtectedNamespacesGetResponse {
        found,
        namespaces,
    }))
}
#[derive(Debug, JsonSerialize)]
/// JSON projection of a retained Parliament emergency hold.
pub struct GovernedContractEmergencyHoldV1 {
    /// Lowercase incident-evidence digest.
    pub incident_digest_hex: String,
    /// Lowercase proposal content identifier.
    pub proposal_content_id_hex: String,
    /// Lowercase governance-attempt identifier.
    pub governance_attempt_id_hex: String,
    /// Human-readable containment reason.
    pub reason: String,
    /// Block at which containment was imposed.
    pub imposed_at_height: u64,
    /// First block at which execution is permitted again.
    pub expires_at_height: u64,
}
#[derive(Debug, JsonSerialize)]
/// Stable app-facing projection of the canonical contract lifecycle record.
pub struct GovernedContractLifecycleV1 {
    /// Exact persisted lifecycle schema version.
    pub version: u16,
    /// Immutable deployment kind: `direct` or `parliament`.
    pub origin: String,
    /// Direct deployer or Parliament proposer recorded as immutable provenance.
    pub origin_account: String,
    /// Parliament proposal content identifier, when governance deployed the contract.
    pub origin_proposal_content_id_hex: Option<String>,
    /// Parliament attempt identifier, when governance deployed the contract.
    pub origin_governance_attempt_id_hex: Option<String>,
    /// Canonical account id or the literal `parliament` for the current owner.
    pub owner: String,
    /// Canonical account id or `parliament` for an outstanding ownership offer.
    pub pending_owner: Option<String>,
    /// Whether an account owner has delegated activation and deactivation to Parliament.
    pub parliament_delegated: bool,
    /// Lowercase active artifact hash, or `None` while the contract is inactive.
    pub active_code_hash_hex: Option<String>,
    /// Non-zero compare-and-swap revision.
    pub revision: u64,
    /// Retained emergency-hold record, including after expiry.
    pub emergency_hold: Option<GovernedContractEmergencyHoldV1>,
}
fn governed_contract_owner_label(
    owner: &iroha_data_model::smart_contract::ContractLifecycleOwnerV1,
) -> String {
    match owner {
        iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(account) => {
            account.to_string()
        }
        iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Parliament => {
            "parliament".to_owned()
        }
    }
}
impl From<&iroha_data_model::smart_contract::ContractLifecycleControlV1>
    for GovernedContractLifecycleV1
{
    fn from(lifecycle: &iroha_data_model::smart_contract::ContractLifecycleControlV1) -> Self {
        use iroha_data_model::smart_contract::{
            ContractDeploymentOriginV1, ContractParliamentDelegationV1,
        };
        let (
            origin,
            origin_account,
            origin_proposal_content_id_hex,
            origin_governance_attempt_id_hex,
        ) = match &lifecycle.origin {
            ContractDeploymentOriginV1::Direct(origin) => {
                ("direct".to_owned(), origin.deployer.to_string(), None, None)
            }
            ContractDeploymentOriginV1::Parliament(origin) => (
                "parliament".to_owned(),
                origin.proposer.to_string(),
                Some(hex::encode(origin.proposal_content_id)),
                Some(hex::encode(origin.governance_attempt_id)),
            ),
        };
        let emergency_hold =
            lifecycle
                .emergency_hold
                .as_ref()
                .map(|hold| GovernedContractEmergencyHoldV1 {
                    incident_digest_hex: hex::encode(hold.incident_digest),
                    proposal_content_id_hex: hex::encode(hold.proposal_content_id),
                    governance_attempt_id_hex: hex::encode(hold.governance_attempt_id),
                    reason: hold.reason.clone(),
                    imposed_at_height: hold.imposed_at_height,
                    expires_at_height: hold.expires_at_height,
                });
        Self {
            version: lifecycle.version,
            origin,
            origin_account,
            origin_proposal_content_id_hex,
            origin_governance_attempt_id_hex,
            owner: governed_contract_owner_label(&lifecycle.owner),
            pending_owner: lifecycle
                .pending_owner
                .as_ref()
                .map(governed_contract_owner_label),
            parliament_delegated: lifecycle.parliament_delegation
                == ContractParliamentDelegationV1::Lifecycle,
            active_code_hash_hex: lifecycle
                .active_code_hash
                .map(<[u8; 32]>::from)
                .map(hex::encode),
            revision: lifecycle.revision,
            emergency_hold,
        }
    }
}
#[derive(Debug, JsonSerialize)]
/// Response for reading governance-managed contract binding state by canonical address.
pub struct GovernedContractResponse {
    /// Whether a lifecycle record exists for this address, including inactive contracts.
    pub found: bool,
    /// Canonical public contract address queried.
    pub contract_address: iroha_data_model::smart_contract::ContractAddress,
    /// Consensus-persisted non-signing account authority retained for this lifecycle.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub contract_subject_account: Option<String>,
    /// Dataspace alias derived from the contract address, when known.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub dataspace: Option<String>,
    /// Whether code is currently active at this address.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Complete revisioned ownership, delegation, active-code, and hold record.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<GovernedContractLifecycleV1>,
    /// Whether the retained emergency hold contains execution at the queried height.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub emergency_hold_active: Option<bool>,
    /// Active code hash bound to the contract address, when present.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub code_hash_hex: Option<String>,
    /// Authenticated ABI hash embedded in the exact active artifact.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub abi_hash_hex: Option<String>,
    /// Sorted, unique transaction and read-only entrypoints exposed to applications.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub public_entrypoints: Option<Vec<String>>,
}
fn governed_contract_invariant(message: impl Into<String>) -> crate::Error {
    crate::Error::Query(iroha_data_model::ValidationFail::InternalError(
        message.into(),
    ))
}
/// Verify retained provenance with scratch funded by the original State execution pool.
fn verify_governed_contract_manifest_signature(
    manifest: &iroha_data_model::smart_contract::manifest::ContractManifest,
    budget: &iroha_allocation::AllocationBudget,
    max_frame_bytes: usize,
) -> Result<(), iroha_core::execution_attempt::ExecutionAttemptError<String>> {
    use iroha_core::execution_attempt::ExecutionAttemptError;
    use ivm::error::ExecutionDeferral;
    use norito::core::{BoundedEncodeError, DecodeBudgetContext};

    let provenance = manifest.provenance.as_ref().ok_or_else(|| {
        ExecutionAttemptError::Rejected("active contract manifest has no signed provenance".into())
    })?;
    // A current frame ceiling limits this read's scratch without declaring retained content invalid.
    let max_frame_bytes = max_frame_bytes.min(budget.limit_bytes());
    let mut counter = budget
        .try_reserve(DecodeBudgetContext::allocation_layout())
        .map_err(|original| ExecutionAttemptError::Deferred(original.into()))?;
    let context = DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        &mut counter,
    )
    .map_err(|error| {
        let reason = match error {
            iroha_allocation::PrepaidSharedError::Allocator { .. } => {
                ExecutionDeferral::AllocationUnavailable
            }
            iroha_allocation::PrepaidSharedError::Reservation(_) => {
                ExecutionDeferral::ActiveMemoryCapacity
            }
        };
        ExecutionAttemptError::Deferred(reason.into())
    })?;
    // Classify the original codec error before the caller's live scopes retire.
    let encode_error = |error: BoundedEncodeError| match error {
        BoundedEncodeError::Serialization(error) => {
            if matches!(&error, norito::Error::AllocationFailed { .. }) {
                ExecutionAttemptError::Deferred(ExecutionDeferral::AllocationUnavailable.into())
            } else if norito::core::decode_error_matches_active_limits(&error) {
                ExecutionAttemptError::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into())
            } else {
                ExecutionAttemptError::Rejected(format!(
                    "active contract manifest signing payload encoding failed: {error}"
                ))
            }
        }
        BoundedEncodeError::AllocationFailed { .. } => {
            ExecutionAttemptError::Deferred(ExecutionDeferral::AllocationUnavailable.into())
        }
        BoundedEncodeError::FrameTooLarge { .. } => {
            ExecutionAttemptError::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into())
        }
    };
    let frame_bytes = context.with(|| {
        norito::canonical_frame_len(&manifest.signature_payload())
            .map_err(BoundedEncodeError::from)
            .map_err(&encode_error)
    })?;
    if frame_bytes > max_frame_bytes {
        return Err(ExecutionAttemptError::Deferred(
            ExecutionDeferral::ActiveMemoryCapacity.into(),
        ));
    }
    let frame = budget
        .try_reserve_bytes(frame_bytes)
        .map_err(|original| ExecutionAttemptError::Deferred(original.into()))?;
    let payload = context.with(|| {
        manifest
            .signature_payload_bytes(&context, max_frame_bytes)
            .map_err(&encode_error)
    })?;
    let result = provenance
        .signature
        .verify(&provenance.signer, &payload)
        .map_err(|_| {
            ExecutionAttemptError::Rejected("active contract manifest provenance is invalid".into())
        });
    // Physical output retires before its grant, on successful and failed verification alike.
    drop(payload);
    drop(frame);
    result
}

fn is_canonical_public_entrypoint_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}
/// GET /v1/gov/contracts/{contract_address} — read a retained governance contract lifecycle.
///
/// Missing addresses return the closed missing shape. Found addresses return the complete retained
/// lifecycle even while inactive; only active records perform independent artifact, manifest, ABI,
/// subject-binding, and public-entrypoint verification.
///
/// # Errors
/// Returns `crate::Error::Query` when the contract address is malformed or the dataspace alias
/// encoded in the address is unknown to the current node. Manifest-frame resource refusals
/// preserve the query budget failure under the caller's original physical allocation owner.
pub async fn handle_gov_contract_get(
    state: Arc<iroha_core::state::State>,
    contract_address: axum::extract::Path<String>,
    allocation_context: &norito::core::DecodeBudgetContext,
) -> Result<JsonBody<GovernedContractResponse>, crate::Error> {
    let contract_address: iroha_data_model::smart_contract::ContractAddress =
        contract_address.0.parse().map_err(|err| {
            crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                    "invalid contract_address: {err}"
                )),
            ))
        })?;
    let dataspace_id = contract_address.dataspace_id().map_err(|err| {
        crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                "invalid contract_address dataspace: {err}"
            )),
        ))
    })?;
    let dataspace = state
        .nexus_snapshot()
        .dataspace_catalog
        .by_id(dataspace_id)
        .map(|entry| entry.alias.clone())
        .ok_or_else(|| {
            crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound,
            ))
        })?;
    let view = state.view();
    let lifecycle =
        iroha_core::smartcontracts::code::fetch_contract_lifecycle(view.world(), &contract_address)
            .map_err(governed_contract_invariant)?;
    let Some((contract_subject, lifecycle)) = lifecycle else {
        return Ok(JsonBody(GovernedContractResponse {
            found: false,
            contract_address,
            contract_subject_account: None,
            dataspace: Some(dataspace),
            active: None,
            lifecycle: None,
            emergency_hold_active: None,
            code_hash_hex: None,
            abi_hash_hex: None,
            public_entrypoints: None,
        }));
    };
    let emergency_hold_active = lifecycle
        .is_held_at(u64::try_from(view.height()).expect("supported state heights fit in u64"));
    let Some(active_code_hash) = lifecycle.active_code_hash else {
        return Ok(JsonBody(GovernedContractResponse {
            found: true,
            contract_address,
            contract_subject_account: Some(contract_subject.to_string()),
            dataspace: Some(dataspace),
            active: Some(false),
            lifecycle: Some((&lifecycle).into()),
            emergency_hold_active: Some(emergency_hold_active),
            code_hash_hex: None,
            abi_hash_hex: None,
            public_entrypoints: None,
        }));
    };
    let record =
        iroha_core::smartcontracts::code::fetch_bound_contract_record(&view, &contract_address)
            .map_err(|error| match error {
                iroha_core::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                    governed_contract_invariant(error.to_string())
                }
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
                    crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
                    ))
                }
            })?
            .ok_or_else(|| {
                governed_contract_invariant(
                    "active contract has incomplete code, manifest, alias, or subject bindings",
                )
            })?;
    if record.contract_address != contract_address || record.code_hash != active_code_hash {
        return Err(governed_contract_invariant(
            "active contract record disagrees with its world-state binding",
        ));
    }
    let verified = ivm::verify_contract_artifact(&record.code_bytes).map_err(|error| {
        governed_contract_invariant(format!(
            "active contract artifact failed independent verification: {error}"
        ))
    })?;
    let manifest_code_hash = record
        .manifest
        .code_hash
        .ok_or_else(|| governed_contract_invariant("active contract manifest has no code_hash"))?;
    let manifest_abi_hash = record
        .manifest
        .abi_hash
        .ok_or_else(|| governed_contract_invariant("active contract manifest has no abi_hash"))?;
    if verified.code_hash != active_code_hash || manifest_code_hash != active_code_hash {
        return Err(governed_contract_invariant(
            "active contract code hash does not match its stored artifact and manifest",
        ));
    }
    if verified.abi_hash != manifest_abi_hash
        || !record.manifest.same_signed_content(&verified.manifest)
    {
        return Err(governed_contract_invariant(
            "active contract manifest does not match its authenticated artifact metadata",
        ));
    }
    let max_frame_bytes = usize::try_from(
        view.world()
            .parameters()
            .transaction
            .ivm_bytecode_size
            .get(),
    )
    .map_err(|_| {
        crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
        ))
    })?;
    allocation_context
        .with(|| {
            verify_governed_contract_manifest_signature(
                &record.manifest,
                &state.ivm_execution_budget(),
                max_frame_bytes,
            )
        })
        .map_err(|error| match error {
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(message) => {
                governed_contract_invariant(message)
            }
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
                crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
                ))
            }
        })?;
    let code_hash_bytes: [u8; 32] = active_code_hash.into();
    let abi_hash_bytes: [u8; 32] = manifest_abi_hash.into();
    if code_hash_bytes.iter().all(|byte| *byte == 0) || abi_hash_bytes.iter().all(|byte| *byte == 0)
    {
        return Err(governed_contract_invariant(
            "active contract exposes an invalid all-zero code or ABI hash",
        ));
    }
    let mut public_entrypoints = verified
        .manifest
        .entrypoints
        .as_ref()
        .ok_or_else(|| governed_contract_invariant("active contract has no entrypoint manifest"))?
        .iter()
        .filter(|entrypoint| {
            matches!(
                entrypoint.kind,
                EntryPointKind::Kotoage | EntryPointKind::View
            )
        })
        .map(|entrypoint| entrypoint.name.clone())
        .collect::<Vec<_>>();
    if public_entrypoints.is_empty()
        || public_entrypoints
            .iter()
            .any(|name| !is_canonical_public_entrypoint_name(name))
    {
        return Err(governed_contract_invariant(
            "active contract has no canonical public entrypoints",
        ));
    }
    public_entrypoints.sort();
    if public_entrypoints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(governed_contract_invariant(
            "active contract advertises duplicate public entrypoints",
        ));
    }
    Ok(JsonBody(GovernedContractResponse {
        found: true,
        contract_address,
        contract_subject_account: Some(record.contract_subject.to_string()),
        dataspace: Some(dataspace),
        active: Some(true),
        lifecycle: Some((&lifecycle).into()),
        emergency_hold_active: Some(emergency_hold_active),
        code_hash_hex: Some(hex::encode(code_hash_bytes)),
        abi_hash_hex: Some(hex::encode(abi_hash_bytes)),
        public_entrypoints: Some(public_entrypoints),
    }))
}
/// POST /v1/gov/proposals/deploy-contract — build a proposal id and instruction skeleton.
///
/// Callers submit the returned instruction in a locally signed transaction.
///
/// # Errors
/// Returns `crate::Error::Query` when the contract target, hashes, or ABI version fails
/// validation.
pub async fn handle_gov_propose_deploy(
    state: Arc<iroha_core::state::State>,
    NoritoJson(body): NoritoJson<DeployContractProposalDraftRequestV1>,
) -> Result<JsonBody<DeployContractProposalDraftResponseV1>, crate::Error> {
    use iroha_data_model::isi::governance as gov;
    let contract_address = resolve_governance_contract_target(
        &state,
        body.contract_address.as_ref(),
        body.contract_alias.as_ref(),
    )?;
    if body.abi_version != AbiVersion::new(1) {
        return Err(crate::routing::conversion_error(format!(
            "unsupported abi_version: {}",
            body.abi_version
        )));
    }
    let code_hash_bytes = body.code_hash.into_bytes();
    let abi_hash_bytes = body.abi_hash.into_bytes();
    let expected_abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    if abi_hash_bytes != expected_abi_hash {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                    "abi_hash does not match canonical hash for abi_version {}",
                    body.abi_version
                )),
            ),
        ));
    }
    let instr = gov::ProposeDeployContract {
        contract_address: contract_address.clone(),
        code_hash: body.code_hash,
        abi_hash: body.abi_hash,
        abi_version: body.abi_version,
        manifest_provenance: body.manifest_provenance.clone(),
    };
    let proposal_id = ProposalContentId::new(
        deploy_contract_proposal_kind(
            &body.proposal_operator,
            &instr.contract_address,
            &code_hash_bytes,
            &abi_hash_bytes,
            instr.manifest_provenance.clone(),
        )
        .fingerprint(),
    );
    Ok(JsonBody(DeployContractProposalDraftResponseV1 {
        proposal_id,
        tx_instructions: instruction_skeleton_for_propose(&instr),
    }))
}
/// POST /v1/gov/proposals/sccp-route-governance — build a proposal id and instruction skeleton.
///
/// The request carries one complete `SccpGovernanceProposalV1` (`specs/sccp.md` §4.14.3). The
/// draft is rejected unless the proposal passes every state-independent Propose check against
/// the node's live `NetworkId` and every `u64` is exact in JSON. The request schema excludes
/// private signing material; callers submit locally signed transactions after building the
/// draft instructions.
///
/// # Errors
/// Returns `crate::Error::Query` (HTTP 400) when the proposal fails static validation.
pub async fn handle_gov_propose_sccp_route_governance(
    state: Arc<iroha_core::state::State>,
    NoritoJson(body): NoritoJson<SccpRouteGovernanceProposalDraftRequestV1>,
) -> Result<JsonBody<SccpRouteGovernanceProposalDraftResponseV1>, crate::Error> {
    use iroha_data_model::isi::governance as gov;
    let proposal = body.proposal;
    proposal
        .validate_static(state.network_id_ref())
        .map_err(|error| {
            crate::routing::conversion_error(format!("invalid SCCP governance proposal: {error}"))
        })?;
    if let Some(reason) = proposal.first_json_u64_violation() {
        return Err(crate::routing::conversion_error(reason.to_owned()));
    }
    let proposal_id =
        ProposalContentId::new(sccp_route_governance_proposal_kind(&proposal).fingerprint());
    let instr = gov::ProposeSccpRouteGovernance { proposal };
    Ok(JsonBody(SccpRouteGovernanceProposalDraftResponseV1 {
        proposal_id,
        tx_instructions: instruction_skeleton_for_sccp_route_governance_propose(&instr),
    }))
}
/// POST /v1/ministry/agenda/proposals/draft — build a detached-signature-ready Ministry submission transaction.
///
/// Returns a duplicate summary with HTTP 409 semantics when the proposal id already exists in committed
/// state; callers must submit the resulting signed transaction through the normal Torii `/v1/pipeline/transactions`
/// route.
pub async fn handle_ministry_agenda_proposal_draft(
    state: Arc<iroha_core::state::State>,
    telemetry: MaybeTelemetry,
    NoritoJson(body): NoritoJson<MinistryAgendaProposalDraftDto>,
) -> Result<MinistryAgendaProposalDraftOutcome, crate::Error> {
    body.proposal.validate().map_err(|err| {
        crate::routing::conversion_error(format!("invalid agenda proposal: {err}"))
    })?;
    let authority_id = parse_canonical_authority_literal(
        state.as_ref(),
        body.authority.as_str(),
        &telemetry,
        CONTEXT_MINISTRY_AGENDA_DRAFT_AUTHORITY,
    )?;
    if let Some(existing) = state
        .world_view()
        .ministry_agenda_proposals()
        .get(&body.proposal.proposal_id)
        .cloned()
    {
        return Ok(MinistryAgendaProposalDraftOutcome::Duplicate(
            MinistryAgendaProposalGetResponse {
                found: true,
                record: Some(existing),
            },
        ));
    }
    let instr = iroha_data_model::isi::ministry::SubmitAgendaProposal {
        proposal: body.proposal.clone(),
    };
    let tx_instructions = vec![tx_instr_from_box(instr.clone().into())];
    let signable_transaction_b64 = build_signable_transaction_b64(
        state.network_id_ref(),
        &authority_id,
        vec![iroha_data_model::isi::InstructionBox::from(instr)],
    );
    Ok(MinistryAgendaProposalDraftOutcome::Draft(
        MinistryAgendaProposalDraftResponse {
            ok: true,
            agenda_proposal_id: body.proposal.proposal_id,
            authority: authority_id.to_string(),
            tx_instructions,
            signable_transaction_b64,
        },
    ))
}
/// GET /v1/ministry/agenda/proposals/{proposal_id} — fetch a submitted Ministry agenda proposal record.
pub async fn handle_ministry_agenda_proposal_get(
    state: Arc<iroha_core::state::State>,
    proposal_id: axum::extract::Path<String>,
) -> Result<JsonBody<MinistryAgendaProposalGetResponse>, crate::Error> {
    let proposal_id = proposal_id.0;
    if !iroha_data_model::ministry::is_valid_agenda_proposal_id(&proposal_id) {
        return Err(crate::routing::conversion_error(
            "proposal_id must follow the exact AC-YYYY-### format".into(),
        ));
    }
    let record = state
        .world_view()
        .ministry_agenda_proposals()
        .get(&proposal_id)
        .cloned();
    Ok(JsonBody(MinistryAgendaProposalGetResponse {
        found: record.is_some(),
        record,
    }))
}
/// POST /v1/gov/ballots/plain — accept a plain quadratic ballot and build an instruction skeleton.
///
/// The request schema excludes private signing material; callers submit locally signed transactions.
///
/// # Errors
/// Returns `crate::Error::Query` when the ballot fields fail validation (direction, authority,
/// owner, amount parsing, or exact network mismatch).
pub async fn handle_gov_ballot_plain_with_policy(
    state: Arc<iroha_core::state::State>,
    authenticated_account: &iroha_data_model::account::AccountId,
    NoritoJson(body): NoritoJson<PlainBallotDto>,
    telemetry: MaybeTelemetry,
) -> Result<JsonBody<BallotDraftResponse>, crate::Error> {
    ensure_network_id_matches(state.as_ref(), &body.network_id)?;
    let authority_id = parse_account_literal_from_state(
        state.as_ref(),
        body.authority.as_str(),
        &telemetry,
        CONTEXT_GOV_BALLOT_PLAIN_AUTHORITY,
    )
    .map_err(|err| {
        crate::routing::conversion_error(format!("invalid authority: {}", err.reason()))
    })?;
    ensure_authenticated_authority(authenticated_account, &authority_id)?;
    validate_governance_selector_v1("referendum_id", &body.referendum_id)
        .map_err(|message| crate::routing::conversion_error(message.into()))?;
    reject_typed_proposal_ballot_selector(&state.world_view(), &body.referendum_id)
        .map_err(|message| crate::routing::conversion_error(message.into()))?;
    // Basic shape validations
    if !(body.direction == "Aye" || body.direction == "Nay" || body.direction == "Abstain") {
        return Err(crate::routing::conversion_error("invalid direction".into()));
    }
    // Parse authority and owner; require equality for plain ballots
    let owner = parse_account_literal_from_state(
        state.as_ref(),
        body.owner.as_str(),
        &telemetry,
        CONTEXT_GOV_BALLOT_PLAIN_OWNER,
    )
    .map_err(|err| crate::routing::conversion_error(format!("invalid owner: {}", err.reason())))?;
    if owner != authority_id {
        return Err(crate::routing::conversion_error(
            "authority must equal owner".into(),
        ));
    }
    let duration_blocks = parse_canonical_u64_decimal("duration_blocks", &body.duration_blocks)
        .map_err(crate::routing::conversion_error)?;
    let instr = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: body.referendum_id,
        owner,
        amount: body.amount,
        duration_blocks,
        direction: match body.direction.as_str() {
            "Aye" => 0,
            "Nay" => 1,
            _ => 2,
        },
    };
    let tx_instructions = vec![tx_instr_from_box(instr.into())];
    Ok(JsonBody(BallotDraftResponse {
        drafted: true,
        tx_instructions,
    }))
}
#[cfg(test)]
mod tests;
