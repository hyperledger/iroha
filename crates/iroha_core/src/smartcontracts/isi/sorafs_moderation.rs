//! Authoritative SoraFS moderation commit/reveal ledger handlers.
use super::*;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::{
    smartcontracts::ValidSingularQuery,
    smartcontracts::isi::sorafs_pop_registry::{
        read_active_publications, read_pinned_publications,
    },
    state::{StateBlock, StateStorageAdmissionError, StateTransaction, WorldReadOnly},
};
#[cfg(test)]
use iroha_data_model::sorafs::moderation_ledger::{
    MODERATION_CHALLENGE_BOND_AMOUNT_V1, MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
    MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    events::data::sorafs::{
        SorafsGatewayEvent, SorafsModerationLedgerEvent, SorafsModerationLedgerEventKind,
    },
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            AcceptSorafsModerationJurorAssignment, ActivateSorafsModerationCase,
            ExpireSorafsModerationChallenge, FinalizeSorafsModerationCase,
            FinalizeSorafsModerationSortition, RaiseSorafsModerationChallenge,
            RegisterSorafsModerationJurorEligibility, ResolveSorafsModerationChallenge,
            SetSorafsModerationPolicy, SubmitSorafsModerationAppeal, SubmitSorafsModerationCommit,
            SubmitSorafsModerationReveal,
        },
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsModerationAppeal, FindSorafsModerationCase, FindSorafsModerationChallenge,
            FindSorafsModerationCommit, FindSorafsModerationEvents,
            FindSorafsModerationJurorEligibility, FindSorafsModerationNoShow,
            FindSorafsModerationOutcome, FindSorafsModerationPolicy, FindSorafsModerationReveal,
            FindSorafsModerationSnapshot, FindSorafsModerationStatus,
        },
    },
    sorafs::{
        moderation::{
            SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1, SoraFsModerationBallotCommitV1,
            SoraFsModerationBallotContextV1, SoraFsModerationBallotRevealV1,
            SoraFsModerationVoteChoice,
        },
        moderation_ledger::{
            MODERATION_FINALIZED_SNAPSHOT_VERSION_V1, MODERATION_LEDGER_MAX_NONCE_BYTES_V1,
            MODERATION_LEDGER_MAX_PANEL_SIZE_V1,
            MODERATION_LEDGER_MAX_PENDING_SORTITION_ANCHORS_V1,
            MODERATION_LEDGER_MAX_REASON_BYTES_V1, MODERATION_LEDGER_MAX_WAITLIST_SIZE_V1,
            MODERATION_QUERY_MAX_CASES_V1, MODERATION_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            MODERATION_QUERY_MAX_EVENTS_V1, MODERATION_QUERY_MAX_SNAPSHOT_BYTES_V1,
            ModerationAppealRecordV1, ModerationAppealStatusV1, ModerationCaseRecordV1,
            ModerationCaseSpecV1, ModerationCaseStatusV1, ModerationChallengeBondV1,
            ModerationChallengeDecisionV1, ModerationChallengeRecordV1, ModerationCommitRecordV1,
            ModerationFinalizedAppealViewV1, ModerationFinalizedCaseViewV1,
            ModerationFinalizedCursorV1, ModerationFinalizedEventPageV1,
            ModerationFinalizedEventV1, ModerationFinalizedLedgerSnapshotV1,
            ModerationJurorEligibilityClassV1, ModerationJurorEligibilityRecordV1,
            ModerationJurorReplacementV1, ModerationLedgerPolicyRecord, ModerationLedgerPolicyV1,
            ModerationLedgerStatusV1, ModerationNoShowKindV1, ModerationNoShowRecordV1,
            ModerationOutcomeKindV1, ModerationOutcomeRecordV1, ModerationPanelSelectionV1,
            ModerationPoPRegistrySnapshotV1, ModerationRevealRecordV1, ModerationSortitionAnchorV1,
            ModerationSortitionError, ModerationVoteCountsV1,
            is_canonical_moderation_identifier_v1, sorafs_moderation_panel_roster_hash_v1,
            sorafs_moderation_pop_challenge_v1, sorafs_moderation_pop_presentation_binding_v1,
            sorafs_moderation_pop_verifier_context_v1, sorafs_moderation_select_panel_v1,
            sorafs_moderation_sortition_digest_v1, sorafs_moderation_sortition_seed_v1,
        },
    },
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity, RoundingMode};
use mv::storage::StorageReadOnly;
#[cfg(test)]
use norito::decode_from_bytes_with_limits;
use norito::{DecodeLimits, decode_canonical_with_limits};
use sorafs_manifest::pop_credentials::{
    POP_MEMBERSHIP_PROOF_MAX_BYTES_V1, PopEligibilityClassV1, PopMembershipProofV1,
    verify_pop_membership_proof_v1,
};
use std::{collections::BTreeSet, str::FromStr, sync::OnceLock};
const POLICY_STATE_KEY: &str = "sorafs_moderation_policy_v1";
const STATUS_STATE_KEY: &str = "sorafs_moderation_status_v1";
const APPEAL_STATE_KEY_PREFIX: &str = "sorafs_moderation_appeal_v1_";
const APPEAL_DEPOSIT_STATE_KEY_PREFIX: &str = "sorafs_moderation_appeal_deposit_v1_";
const APPEAL_PROOF_TOKEN_STATE_KEY_PREFIX: &str = "sorafs_moderation_appeal_proof_token_v1_";
const SORTITION_ANCHOR_SCHEDULE_STATE_KEY: &str = "sorafs_moderation_anchor_schedule_v1";
const ELIGIBILITY_STATE_KEY_PREFIX: &str = "sorafs_moderation_eligibility_v1_";
const NULLIFIER_STATE_KEY_PREFIX: &str = "sorafs_moderation_pop_nullifier_v1_";
const CASE_STATE_KEY_PREFIX: &str = "sorafs_moderation_case_v1_";
const COMMIT_STATE_KEY_PREFIX: &str = "sorafs_moderation_commit_v1_";
const REVEAL_STATE_KEY_PREFIX: &str = "sorafs_moderation_reveal_v1_";
const CHALLENGE_STATE_KEY_PREFIX: &str = "sorafs_moderation_challenge_v1_";
const OUTCOME_STATE_KEY_PREFIX: &str = "sorafs_moderation_outcome_v1_";
const NO_SHOW_STATE_KEY_PREFIX: &str = "sorafs_moderation_no_show_v1_";
const EVENT_STATE_KEY_PREFIX: &str = "sorafs_moderation_event_v1_";
const EVENT_JOURNAL_HEAD_STATE_KEY: &str = "sorafs_moderation_event_head_v1";
const CASE_KEY_DOMAIN_V1: &[u8] = b"sorafs.moderation.case-state-key.v1";
const JUROR_KEY_DOMAIN_V1: &[u8] = b"sorafs.moderation.juror-state-key.v1";
const CHALLENGE_KEY_DOMAIN_V1: &[u8] = b"sorafs.moderation.challenge-state-key.v1";
const NULLIFIER_KEY_DOMAIN_V1: &[u8] = b"sorafs.moderation.pop-nullifier-state-key.v1";
const APPEAL_DEPOSIT_KEY_DOMAIN_V1: &[u8] = b"sorafs.moderation.appeal-deposit-state-key.v1";
const APPEAL_PROOF_TOKEN_KEY_DOMAIN_V1: &[u8] =
    b"sorafs.moderation.appeal-proof-token-state-key.v1";
const PROOF_DIGEST_DOMAIN_V1: &[u8] = b"sorafs.moderation.pop-proof-payload.v1";
const STATE_MAX_BYTES: usize = 512 * 1024;
const PAYLOAD_MAX_BYTES: usize = 64 * 1024;
// Persisted records embed canonical instruction payloads as byte sequences, so
// their sequence limit must admit every payload accepted by `decode_payload`.
const STATE_LIMITS: DecodeLimits = DecodeLimits::new(
    PAYLOAD_MAX_BYTES,
    STATE_MAX_BYTES,
    4_096,
    2 * STATE_MAX_BYTES,
    64,
);
const PAYLOAD_LIMITS: DecodeLimits =
    DecodeLimits::new(256, PAYLOAD_MAX_BYTES, 2_048, 2 * PAYLOAD_MAX_BYTES, 64);
const PROOF_LIMITS: DecodeLimits = DecodeLimits::new(
    POP_MEMBERSHIP_PROOF_MAX_BYTES_V1,
    POP_MEMBERSHIP_PROOF_MAX_BYTES_V1 + 32 * 1024,
    4_096,
    2 * (POP_MEMBERSHIP_PROOF_MAX_BYTES_V1 + 32 * 1024),
    64,
);
const MANAGE_PERMISSION: &str = "CanManageSorafsModeration";
const MODERATION_QUERY_MAX_SNAPSHOT_RECORDS_V1: usize = 65_536;
const MODERATION_SORTITION_ANCHOR_SCHEDULE_VERSION_V1: u16 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One exact leg of a retained moderation challenge bond settlement.
pub(in crate::smartcontracts::isi) enum ModerationChallengeBondSettlementLeg {
    /// Return bond principal to its challenger.
    Refund,
    /// Retain the policy-fixed slash in governance custody.
    Slash,
}
#[derive(Debug)]
/// Closed purpose carried by a one-shot moderation challenge bond movement.
pub(in crate::smartcontracts::isi) enum VerifiedModerationChallengeBondPurpose {
    /// Voluntarily lock the submitting challenger's bond.
    Funding {
        /// Exact submitting challenger.
        authority: AccountId,
        /// Moderation case identifier.
        case_id: String,
        /// Ballot round identifier.
        round_id: String,
        /// Challenge identifier.
        challenge_id: String,
    },
    /// Settle a retained challenge bond according to its decision.
    Settlement {
        /// Moderation case identifier.
        case_id: String,
        /// Ballot round identifier.
        round_id: String,
        /// Challenge identifier.
        challenge_id: String,
        /// Decision fixing the allowed settlement split.
        decision: ModerationChallengeDecisionV1,
        /// Exact settlement leg.
        leg: ModerationChallengeBondSettlementLeg,
    },
}
#[derive(Debug)]
/// Non-reusable proof that moderation admission selected one exact balance movement.
pub(in crate::smartcontracts::isi) struct VerifiedModerationChallengeBondMovement {
    purpose: VerifiedModerationChallengeBondPurpose,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
}
impl VerifiedModerationChallengeBondMovement {
    fn funding(
        authority: AccountId,
        case_id: String,
        round_id: String,
        challenge_id: String,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose: VerifiedModerationChallengeBondPurpose::Funding {
                authority,
                case_id,
                round_id,
                challenge_id,
            },
            source_id,
            destination_id,
            amount,
        }
    }
    fn settlement(
        case_id: String,
        round_id: String,
        challenge_id: String,
        decision: ModerationChallengeDecisionV1,
        leg: ModerationChallengeBondSettlementLeg,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose: VerifiedModerationChallengeBondPurpose::Settlement {
                case_id,
                round_id,
                challenge_id,
                decision,
                leg,
            },
            source_id,
            destination_id,
            amount,
        }
    }
    /// Consume this proof into its checked movement components.
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        VerifiedModerationChallengeBondPurpose,
        AssetId,
        AssetId,
        Quantity,
    ) {
        (
            self.purpose,
            self.source_id,
            self.destination_id,
            self.amount,
        )
    }
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::AppealDepositBindingStateV1"
)]
struct AppealDepositBindingStateV1 {
    deposit_lock_digest: [u8; 32],
    case_id: String,
    round_id: String,
    intake_digest: [u8; 32],
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::AppealProofTokenBindingStateV1"
)]
struct AppealProofTokenBindingStateV1 {
    proof_token_digest: [u8; 32],
    case_id: String,
    round_id: String,
    intake_digest: [u8; 32],
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationSortitionAnchorScheduleEntryV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, norito::NoritoSerialize, norito::NoritoDeserialize)]
struct ModerationSortitionAnchorScheduleEntryV1 {
    registration_deadline_unix_ms: u64,
    case_id: String,
    round_id: String,
    intake_digest: [u8; 32],
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationSortitionAnchorScheduleV1"
)]
struct ModerationSortitionAnchorScheduleV1 {
    version: u16,
    entries: Vec<ModerationSortitionAnchorScheduleEntryV1>,
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationPersistedEventV1"
)]
struct ModerationPersistedEventV1 {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    event: SorafsModerationLedgerEvent,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sorafs_moderation::ModerationEventJournalHeadV1"
)]
struct ModerationEventJournalHeadV1 {
    last_sequence: u64,
    last_target_block_height: u64,
    last_event_index: u32,
}
fn invalid_parameter(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn corrupt_state(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
fn corrupt_stored_payload(error: InstructionExecutionError) -> InstructionExecutionError {
    match error {
        error @ InstructionExecutionError::Query(_) => error,
        error => corrupt_state(error.to_string()),
    }
}
fn require_manage_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if state_transaction._curr_block.is_genesis() {
        return Ok(());
    }
    let required = iroha_data_model::permission::Permission::from(
        iroha_executor_data_model::permission::sorafs::CanManageSorafsModeration,
    );
    let direct = state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.iter().any(|candidate| candidate == &required));
    let role = state_transaction
        .world
        .account_roles_iter(authority)
        .filter_map(|role_id| state_transaction.world.roles.get(role_id))
        .any(|role| role.permissions().any(|candidate| candidate == &required));
    let permitted = direct || role;
    if permitted {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "permission {MANAGE_PERMISSION} required for authoritative SoraFS moderation operation"
        )))
    }
}
fn block_time_ms(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms();
    if now == 0 {
        return Err(invalid_parameter(
            "authoritative moderation operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn ceil_unix_ms_to_epoch(unix_ms: u64) -> Result<u64, InstructionExecutionError> {
    unix_ms
        .checked_add(999)
        .map(|value| value / 1_000)
        .ok_or_else(|| corrupt_state("moderation millisecond deadline overflows epoch rounding"))
}
fn active_pop_snapshot(
    state_transaction: &StateTransaction<'_, '_>,
    now: u64,
) -> Result<
    (
        ModerationPoPRegistrySnapshotV1,
        super::sorafs_pop_registry::ActivePopPublicationsV1,
    ),
    InstructionExecutionError,
> {
    let active = read_active_publications(state_transaction.world())?.ok_or_else(|| {
        invalid_parameter("active SoraFS PoP root and revocation publication are required")
    })?;
    let registry_audit_head = active.status.audit_head.ok_or_else(|| {
        corrupt_state("active PoP registry status is missing its audit-chain head")
    })?;
    let snapshot = ModerationPoPRegistrySnapshotV1 {
        issuer_policy_digest: active.issuer_policy_digest,
        commitment_root: active.root.root_digest,
        commitment_tree_version: active.root.tree_version,
        revocation_root: active.revocations.revocation_root,
        revocation_list_version: active.revocations.list_version,
        registry_audit_sequence: active.status.audit_sequence,
        registry_audit_head,
        captured_at_unix_ms: now,
    };
    snapshot.validate().map_err(|error| {
        corrupt_state(format!("active PoP registry snapshot is invalid: {error}"))
    })?;
    Ok((snapshot, active))
}
fn require_pinned_pop_snapshot(
    state_transaction: &StateTransaction<'_, '_>,
    snapshot: &ModerationPoPRegistrySnapshotV1,
) -> Result<super::sorafs_pop_registry::PinnedPopPublicationsV1, InstructionExecutionError> {
    read_pinned_publications(
        state_transaction.world(),
        snapshot.issuer_policy_digest,
        snapshot.commitment_root,
        snapshot.commitment_tree_version,
        snapshot.revocation_root,
        snapshot.revocation_list_version,
        snapshot.registry_audit_sequence,
        snapshot.registry_audit_head,
    )
}
fn eligibility_class(class: PopEligibilityClassV1) -> ModerationJurorEligibilityClassV1 {
    match class {
        PopEligibilityClassV1::General => ModerationJurorEligibilityClassV1::General,
        PopEligibilityClassV1::Regional => ModerationJurorEligibilityClassV1::Regional,
        PopEligibilityClassV1::Expert => ModerationJurorEligibilityClassV1::Expert,
        PopEligibilityClassV1::Emergency => ModerationJurorEligibilityClassV1::Emergency,
        PopEligibilityClassV1::Observer => ModerationJurorEligibilityClassV1::Observer,
    }
}
fn policy_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| StatePath::from_str(POLICY_STATE_KEY).expect("static state key is valid"))
}
fn status_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| StatePath::from_str(STATUS_STATE_KEY).expect("static state key is valid"))
}
fn sortition_anchor_schedule_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(SORTITION_ANCHOR_SCHEDULE_STATE_KEY).expect("static state key is valid")
    })
}
fn event_journal_head_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(EVENT_JOURNAL_HEAD_STATE_KEY).expect("static state key is valid")
    })
}
fn event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{EVENT_STATE_KEY_PREFIX}{sequence:016x}"))
        .expect("static prefix plus fixed-width lowercase hex is a valid state key")
}
fn digest_key(prefix: &str, digest: [u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static prefix plus lowercase hex is a valid state key")
}
fn update_string(hasher: &mut blake3::Hasher, value: &str) {
    let length = u64::try_from(value.len()).expect("state-key material length fits u64");
    hasher.update(&length.to_le_bytes());
    hasher.update(value.as_bytes());
}
fn validate_lookup_identifiers(
    case_id: &str,
    round_id: &str,
) -> Result<(), InstructionExecutionError> {
    for (field, value) in [("case_id", case_id), ("round_id", round_id)] {
        if !is_canonical_moderation_identifier_v1(value) {
            return Err(invalid_parameter(format!(
                "invalid moderation {field} identifier"
            )));
        }
    }
    Ok(())
}
fn validate_challenge_reason(reason: &str) -> Result<(), InstructionExecutionError> {
    if reason.trim().is_empty()
        || reason != reason.trim()
        || reason.len() > MODERATION_LEDGER_MAX_REASON_BYTES_V1
        || reason.chars().any(char::is_control)
    {
        return Err(invalid_parameter(
            "moderation challenge reason is empty, padded, contains control characters, or is too long",
        ));
    }
    Ok(())
}
fn lock_moderation_challenge_bond(
    state_transaction: &mut StateTransaction<'_, '_>,
    policy: &ModerationLedgerPolicyV1,
    authority: &AccountId,
    case_id: &str,
    round_id: &str,
    challenge_id: &str,
) -> Result<ModerationChallengeBondV1, InstructionExecutionError> {
    let asset_definition_id = policy.challenge_voting_asset_id.clone();
    let escrow_account = policy.challenge_escrow_account.clone();
    let slash_receiver_account = policy.challenge_slash_receiver_account.clone();
    if authority == &escrow_account || authority == &slash_receiver_account {
        return Err(invalid_parameter(
            "moderation bond custody accounts cannot submit public challenges",
        ));
    }
    state_transaction
        .world
        .account(&escrow_account)
        .map_err(InstructionExecutionError::Find)?;
    state_transaction
        .world
        .account(&slash_receiver_account)
        .map_err(InstructionExecutionError::Find)?;
    let numeric_spec = state_transaction
        .numeric_spec_for(&asset_definition_id)
        .map_err(InstructionExecutionError::Find)?;
    let amount = policy.challenge_bond_amount.clone();
    let slash_amount = moderation_challenge_rejected_slash_amount(
        &amount,
        numeric_spec,
        policy.challenge_rejected_slash_bps,
    )?;
    let refund_amount = amount
        .checked_sub(&slash_amount)
        .map_err(|_| corrupt_state("moderation challenge bond refund underflow"))?;
    for settlement_amount in [&amount, &slash_amount, &refund_amount] {
        crate::smartcontracts::isi::asset::isi::assert_numeric_spec_with(
            settlement_amount.as_numeric(),
            numeric_spec,
        )
        .map_err(InstructionExecutionError::from)?;
    }
    let source_id = AssetId::new(asset_definition_id.clone(), authority.clone());
    let destination_id = AssetId::new(asset_definition_id.clone(), escrow_account.clone());
    let movement = VerifiedModerationChallengeBondMovement::funding(
        authority.clone(),
        case_id.to_owned(),
        round_id.to_owned(),
        challenge_id.to_owned(),
        source_id,
        destination_id,
        amount.clone(),
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_moderation_challenge_bond_movement(
        state_transaction,
        movement,
    )?;
    Ok(ModerationChallengeBondV1 {
        asset_definition_id,
        amount,
        escrow_account,
        slash_receiver_account,
        refunded_amount: Quantity::zero(),
        slashed_amount: Quantity::zero(),
        settled_at_unix_ms: None,
    })
}
fn settle_moderation_challenge_bond(
    state_transaction: &mut StateTransaction<'_, '_>,
    policy: &ModerationLedgerPolicyV1,
    record: &mut ModerationChallengeRecordV1,
    decision: ModerationChallengeDecisionV1,
    settled_at_unix_ms: u64,
) -> Result<(), InstructionExecutionError> {
    if record.bond.settled_at_unix_ms.is_some() {
        return Err(corrupt_state(
            "moderation challenge bond was settled before its decision",
        ));
    }
    let slash_amount = if decision == ModerationChallengeDecisionV1::Rejected {
        let numeric_spec = state_transaction
            .numeric_spec_for(&record.bond.asset_definition_id)
            .map_err(InstructionExecutionError::Find)?;
        moderation_challenge_rejected_slash_amount(
            &record.bond.amount,
            numeric_spec,
            policy.challenge_rejected_slash_bps,
        )?
    } else {
        Quantity::zero()
    };
    let refund_amount = record
        .bond
        .amount
        .checked_sub(&slash_amount)
        .map_err(|_| corrupt_state("moderation challenge bond settlement underflow"))?;
    let source_id = AssetId::new(
        record.bond.asset_definition_id.clone(),
        record.bond.escrow_account.clone(),
    );
    // The record remains pending between the refund and slash legs of a
    // rejected settlement. Preflight the complete aggregate liability once;
    // the exact typed legs below then execute atomically in the outer state
    // transaction without granting generic governance movements an exemption.
    ensure_moderation_bond_custody_fully_backed(state_transaction.world(), &source_id)?;
    if !refund_amount.is_zero() {
        let destination_id = AssetId::new(
            record.bond.asset_definition_id.clone(),
            record.challenger.clone(),
        );
        let movement = VerifiedModerationChallengeBondMovement::settlement(
            record.case_id.clone(),
            record.round_id.clone(),
            record.challenge_id.clone(),
            decision,
            ModerationChallengeBondSettlementLeg::Refund,
            source_id.clone(),
            destination_id,
            refund_amount.clone(),
        );
        crate::smartcontracts::isi::asset::isi::execute_verified_moderation_challenge_bond_movement(
            state_transaction,
            movement,
        )?;
    }
    if !slash_amount.is_zero() {
        let destination_id = AssetId::new(
            record.bond.asset_definition_id.clone(),
            record.bond.slash_receiver_account.clone(),
        );
        let movement = VerifiedModerationChallengeBondMovement::settlement(
            record.case_id.clone(),
            record.round_id.clone(),
            record.challenge_id.clone(),
            decision,
            ModerationChallengeBondSettlementLeg::Slash,
            source_id,
            destination_id,
            slash_amount.clone(),
        );
        crate::smartcontracts::isi::asset::isi::execute_verified_moderation_challenge_bond_movement(
            state_transaction,
            movement,
        )?;
    }
    record.bond.refunded_amount = refund_amount;
    record.bond.slashed_amount = slash_amount;
    record.bond.settled_at_unix_ms = Some(settled_at_unix_ms);
    Ok(())
}
fn case_digest(case_id: &str, round_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CASE_KEY_DOMAIN_V1);
    update_string(&mut hasher, case_id);
    update_string(&mut hasher, round_id);
    *hasher.finalize().as_bytes()
}
fn juror_digest(case_id: &str, round_id: &str, juror: &AccountId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JUROR_KEY_DOMAIN_V1);
    update_string(&mut hasher, case_id);
    update_string(&mut hasher, round_id);
    update_string(&mut hasher, &juror.to_string());
    *hasher.finalize().as_bytes()
}
fn challenge_digest(case_id: &str, round_id: &str, challenge_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHALLENGE_KEY_DOMAIN_V1);
    update_string(&mut hasher, case_id);
    update_string(&mut hasher, round_id);
    update_string(&mut hasher, challenge_id);
    *hasher.finalize().as_bytes()
}
fn nullifier_digest(nullifier: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NULLIFIER_KEY_DOMAIN_V1);
    hasher.update(&nullifier);
    *hasher.finalize().as_bytes()
}
fn appeal_deposit_digest(deposit_lock_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APPEAL_DEPOSIT_KEY_DOMAIN_V1);
    hasher.update(&deposit_lock_digest);
    *hasher.finalize().as_bytes()
}
fn appeal_proof_token_digest(proof_token_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APPEAL_PROOF_TOKEN_KEY_DOMAIN_V1);
    hasher.update(&proof_token_digest);
    *hasher.finalize().as_bytes()
}
fn appeal_key(case_id: &str, round_id: &str) -> StatePath {
    digest_key(APPEAL_STATE_KEY_PREFIX, case_digest(case_id, round_id))
}
fn eligibility_key(case_id: &str, round_id: &str, juror: &AccountId) -> StatePath {
    digest_key(
        ELIGIBILITY_STATE_KEY_PREFIX,
        juror_digest(case_id, round_id, juror),
    )
}
fn nullifier_key(nullifier: [u8; 32]) -> StatePath {
    digest_key(NULLIFIER_STATE_KEY_PREFIX, nullifier_digest(nullifier))
}
fn appeal_deposit_key(deposit_lock_digest: [u8; 32]) -> StatePath {
    digest_key(
        APPEAL_DEPOSIT_STATE_KEY_PREFIX,
        appeal_deposit_digest(deposit_lock_digest),
    )
}
fn appeal_proof_token_key(proof_token_digest: [u8; 32]) -> StatePath {
    digest_key(
        APPEAL_PROOF_TOKEN_STATE_KEY_PREFIX,
        appeal_proof_token_digest(proof_token_digest),
    )
}
fn case_key(case_id: &str, round_id: &str) -> StatePath {
    digest_key(CASE_STATE_KEY_PREFIX, case_digest(case_id, round_id))
}
fn commit_key(case_id: &str, round_id: &str, juror: &AccountId) -> StatePath {
    digest_key(
        COMMIT_STATE_KEY_PREFIX,
        juror_digest(case_id, round_id, juror),
    )
}
fn reveal_key(case_id: &str, round_id: &str, juror: &AccountId) -> StatePath {
    digest_key(
        REVEAL_STATE_KEY_PREFIX,
        juror_digest(case_id, round_id, juror),
    )
}
fn challenge_key(case_id: &str, round_id: &str, challenge_id: &str) -> StatePath {
    digest_key(
        CHALLENGE_STATE_KEY_PREFIX,
        challenge_digest(case_id, round_id, challenge_id),
    )
}
fn outcome_key(case_id: &str, round_id: &str) -> StatePath {
    digest_key(OUTCOME_STATE_KEY_PREFIX, case_digest(case_id, round_id))
}
fn no_show_key(case_id: &str, round_id: &str, juror: &AccountId) -> StatePath {
    digest_key(
        NO_SHOW_STATE_KEY_PREFIX,
        juror_digest(case_id, round_id, juror),
    )
}
fn encode_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    norito::encode_canonical(value)
        .map_err(|error| corrupt_state(format!("failed to encode {label}: {error}")))
}
fn encode_payload<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    norito::encode_canonical(value)
        .map_err(|error| invalid_parameter(format!("failed to canonicalize {label}: {error}")))
}
fn decode_state_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_state_with_current(bytes, label, Some(current))
}
fn decode_state_with_current<T>(
    bytes: &[u8],
    label: &str,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} state exceeds {STATE_MAX_BYTES} bytes"
        )));
    }
    let limits = match current.as_deref() {
        Some(current) => current.decode_limits(bytes.len(), STATE_LIMITS),
        None => crate::smartcontracts::isi::query::singular_query_decode_limits(
            bytes.len(),
            STATE_LIMITS,
        ),
    }
    .map_err(InstructionExecutionError::Query)?;
    let (value, allocation_bytes) = if current.is_some() {
        let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
            decode_canonical_with_limits::<T>(bytes, limits)
        });
        (value, Some(usage.total_allocated_bytes()))
    } else {
        (decode_canonical_with_limits::<T>(bytes, limits), None)
    };
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else if matches!(error, norito::Error::NonCanonicalEncoding) {
            corrupt_state(format!("{label} state is not exact canonical Norito"))
        } else {
            corrupt_state(format!("failed to decode {label}: {error}"))
        }
    })?;
    if let (Some(current), Some(allocation_bytes)) = (current, allocation_bytes) {
        current
            .add_nested(allocation_bytes)
            .map_err(InstructionExecutionError::Query)?;
    }
    Ok(value)
}
fn decode_payload<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_payload_with_current(bytes, label, None)
}
fn decode_payload_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_payload_with_current(bytes, label, Some(current))
}
fn decode_payload_with_current<T>(
    bytes: &[u8],
    label: &str,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.is_empty() || bytes.len() > PAYLOAD_MAX_BYTES {
        return Err(invalid_parameter(format!(
            "{label} payload length {} is outside 1..={PAYLOAD_MAX_BYTES}",
            bytes.len()
        )));
    }
    let limits = match current.as_deref() {
        Some(current) => current.decode_limits(bytes.len(), PAYLOAD_LIMITS),
        None => crate::smartcontracts::isi::query::singular_query_decode_limits(
            bytes.len(),
            PAYLOAD_LIMITS,
        ),
    }
    .map_err(InstructionExecutionError::Query)?;
    let (value, allocation_bytes) = if current.is_some() {
        let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
            decode_canonical_with_limits::<T>(bytes, limits)
        });
        (value, Some(usage.total_allocated_bytes()))
    } else {
        (decode_canonical_with_limits::<T>(bytes, limits), None)
    };
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            return InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit);
        }
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            invalid_parameter(format!("{label} payload is not exact canonical Norito"))
        } else {
            invalid_parameter(format!("invalid canonical {label} payload: {error}"))
        }
    })?;
    if let (Some(current), Some(allocation_bytes)) = (current, allocation_bytes) {
        current
            .add_nested(allocation_bytes)
            .map_err(InstructionExecutionError::Query)?;
    }
    Ok(value)
}
fn validate_persisted_event(
    record: &ModerationPersistedEventV1,
    expected_sequence: u64,
) -> Result<(), InstructionExecutionError> {
    if record.sequence == 0
        || record.sequence != expected_sequence
        || record.target_block_height == 0
        || record.event.occurred_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation event journal metadata is inconsistent",
        ));
    }
    let identifiers_valid = match record.event.kind {
        SorafsModerationLedgerEventKind::PolicyActivated => {
            record.event.case_id.is_none() && record.event.round_id.is_none()
        }
        _ => record
            .event
            .case_id
            .as_deref()
            .zip(record.event.round_id.as_deref())
            .is_some_and(|(case_id, round_id)| {
                is_canonical_moderation_identifier_v1(case_id)
                    && is_canonical_moderation_identifier_v1(round_id)
            }),
    };
    if !identifiers_valid {
        return Err(corrupt_state(
            "stored moderation event journal identifiers are inconsistent",
        ));
    }
    Ok(())
}
fn read_persisted_event(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<ModerationPersistedEventV1>, InstructionExecutionError> {
    read_persisted_event_with_current(world, sequence, None)
}
fn read_persisted_event_for_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationPersistedEventV1>, InstructionExecutionError> {
    read_persisted_event_with_current(world, sequence, Some(current))
}
fn read_persisted_event_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationPersistedEventV1>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_state(
            "moderation event journal sequence zero is invalid",
        ));
    }
    let key = event_key(sequence);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: ModerationPersistedEventV1 =
        decode_state_with_current(bytes, "moderation committed event", current)?;
    validate_persisted_event(&record, sequence)?;
    Ok(Some(record))
}
fn read_event_journal_head(
    world: &impl WorldReadOnly,
) -> Result<Option<ModerationEventJournalHeadV1>, InstructionExecutionError> {
    read_event_journal_head_with_current(world, None)
}
fn read_event_journal_head_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationEventJournalHeadV1>, InstructionExecutionError> {
    read_event_journal_head_with_current(world, Some(current))
}
fn read_event_journal_head_with_current(
    world: &impl WorldReadOnly,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationEventJournalHeadV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(event_journal_head_key()) else {
        return Ok(None);
    };
    let head: ModerationEventJournalHeadV1 = decode_state_with_current(
        bytes,
        "moderation event journal head",
        current.as_deref_mut(),
    )?;
    if head.last_sequence == 0 || head.last_target_block_height == 0 {
        return Err(corrupt_state(
            "stored moderation event journal head is invalid",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let last =
        read_persisted_event_with_current(world, head.last_sequence, transient_current.as_mut())?
            .ok_or_else(|| corrupt_state("moderation event journal head has no terminal record"))?;
    if last.target_block_height != head.last_target_block_height
        || last.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "stored moderation event journal head disagrees with its terminal record",
        ));
    }
    Ok(Some(head))
}
fn ensure_no_event_after_head(
    world: &impl WorldReadOnly,
    head: Option<ModerationEventJournalHeadV1>,
) -> Result<(), InstructionExecutionError> {
    let prefix_start =
        StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid");
    let first_event_key = world
        .smart_contract_state()
        .range(prefix_start..)
        .next()
        .and_then(|(key, _)| {
            key.to_string()
                .starts_with(EVENT_STATE_KEY_PREFIX)
                .then_some(key)
        });
    match (head, first_event_key) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(corrupt_state(
                "moderation event journal contains records without a head",
            ));
        }
        (Some(_), Some(key)) if *key == event_key(1) => {}
        (Some(_), _) => {
            return Err(corrupt_state(
                "moderation event journal does not begin at sequence one",
            ));
        }
    }
    let start = head.map_or_else(
        || StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid"),
        |head| event_key(head.last_sequence),
    );
    for (key, _) in world.smart_contract_state().range(start..) {
        let rendered = key.to_string();
        if !rendered.starts_with(EVENT_STATE_KEY_PREFIX) {
            break;
        }
        if head.is_some_and(|head| *key == event_key(head.last_sequence)) {
            continue;
        }
        return Err(corrupt_state(
            "moderation event journal contains a record beyond its head",
        ));
    }
    Ok(())
}
fn decode_membership_proof(
    bytes: &[u8],
) -> Result<PopMembershipProofV1, InstructionExecutionError> {
    let maximum = POP_MEMBERSHIP_PROOF_MAX_BYTES_V1 + 32 * 1024;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid_parameter(format!(
            "moderation PoP membership proof length {} is outside 1..={maximum}",
            bytes.len()
        )));
    }
    decode_canonical_with_limits::<PopMembershipProofV1>(bytes, PROOF_LIMITS).map_err(|error| {
        if matches!(&error, norito::Error::NonCanonicalEncoding) {
            invalid_parameter("moderation PoP membership proof is not exact canonical Norito")
        } else {
            invalid_parameter(format!(
                "invalid canonical moderation PoP membership proof: {error}"
            ))
        }
    })
}
fn read_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<ModerationLedgerPolicyRecord>, InstructionExecutionError> {
    read_policy_with_current(world, None)
}

/// Return the first live moderation reference that prevents account deletion.
///
/// Active policy custody, live pre-activation appeal actors and pinned custody,
/// custody pinned by an open case, and all parties to an unsettled challenge
/// must remain registered until no future moderation transition can name them.
/// Persisted state is decoded canonically and malformed records fail the
/// deletion closed.
pub(crate) fn retained_moderation_account_reference(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<Option<String>, InstructionExecutionError> {
    if let Some(record) = read_policy(world)? {
        if &record.policy.challenge_escrow_account == account {
            return Ok(Some("active policy challenge escrow".to_owned()));
        }
        if &record.policy.challenge_slash_receiver_account == account {
            return Ok(Some("active policy challenge slash receiver".to_owned()));
        }
    }

    let appeal_start = StatePath::from_str(APPEAL_STATE_KEY_PREFIX)
        .expect("static moderation appeal prefix is valid");
    for (key, payload) in world.smart_contract_state().range(appeal_start..) {
        if !key.as_ref().starts_with(APPEAL_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: ModerationAppealRecordV1 =
            decode_state_with_current(payload, "moderation appeal", None)?;
        if appeal_key(&candidate.intake.case_id, &candidate.intake.round_id) != *key {
            return Err(corrupt_state(
                "retained moderation appeal key does not match its record",
            ));
        }
        let appeal = read_appeal(world, &candidate.intake.case_id, &candidate.intake.round_id)?
            .ok_or_else(|| corrupt_state("retained moderation appeal disappeared during read"))?;
        if appeal != candidate {
            return Err(corrupt_state(
                "retained moderation appeal changed during read",
            ));
        }
        if !matches!(
            appeal.status,
            ModerationAppealStatusV1::RegisteringJurors
                | ModerationAppealStatusV1::AwaitingAcceptance
        ) {
            continue;
        }
        let label = if &appeal.submitted_by == account {
            Some("appellant")
        } else if &appeal.policy.challenge_escrow_account == account {
            Some("policy challenge escrow")
        } else if &appeal.policy.challenge_slash_receiver_account == account {
            Some("policy challenge slash receiver")
        } else if appeal.intake.exclusions.contains(account) {
            Some("excluded account")
        } else if appeal.eligible_jurors.contains(account) {
            Some("eligible juror")
        } else {
            None
        };
        if let Some(label) = label {
            return Ok(Some(format!(
                "pre-activation appeal `{}` round `{}` {label}",
                appeal.intake.case_id, appeal.intake.round_id
            )));
        }
    }

    let case_start =
        StatePath::from_str(CASE_STATE_KEY_PREFIX).expect("static moderation case prefix is valid");
    for (key, payload) in world.smart_contract_state().range(case_start..) {
        if !key.as_ref().starts_with(CASE_STATE_KEY_PREFIX) {
            break;
        }
        let case: ModerationCaseRecordV1 =
            decode_state_with_current(payload, "moderation case", None)?;
        if case_key(&case.spec.context.case_id, &case.spec.round_id) != *key {
            return Err(corrupt_state(
                "retained moderation case key does not match its record",
            ));
        }
        if case.status == ModerationCaseStatusV1::Open {
            if &case.policy.challenge_escrow_account == account {
                return Ok(Some(format!(
                    "open case `{}` round `{}` challenge escrow",
                    case.spec.context.case_id, case.spec.round_id
                )));
            }
            if &case.policy.challenge_slash_receiver_account == account {
                return Ok(Some(format!(
                    "open case `{}` round `{}` challenge slash receiver",
                    case.spec.context.case_id, case.spec.round_id
                )));
            }
        }
    }

    let challenge_start = StatePath::from_str(CHALLENGE_STATE_KEY_PREFIX)
        .expect("static moderation challenge prefix is valid");
    for (key, payload) in world.smart_contract_state().range(challenge_start..) {
        if !key.as_ref().starts_with(CHALLENGE_STATE_KEY_PREFIX) {
            break;
        }
        let challenge: ModerationChallengeRecordV1 =
            decode_state_with_current(payload, "moderation challenge", None)?;
        if challenge_key(
            &challenge.case_id,
            &challenge.round_id,
            &challenge.challenge_id,
        ) != *key
        {
            return Err(corrupt_state(
                "retained moderation challenge key does not match its record",
            ));
        }
        let pending_decision = challenge.decision.is_none();
        let pending_settlement = challenge.bond.settled_at_unix_ms.is_none();
        if pending_decision != pending_settlement {
            return Err(corrupt_state(
                "moderation challenge decision and bond settlement disagree",
            ));
        }
        if !pending_decision {
            continue;
        }
        let label = if &challenge.challenger == account {
            Some("challenger")
        } else if &challenge.bond.escrow_account == account {
            Some("bond escrow")
        } else if &challenge.bond.slash_receiver_account == account {
            Some("bond slash receiver")
        } else {
            None
        };
        if let Some(label) = label {
            return Ok(Some(format!(
                "pending challenge `{}` for case `{}` round `{}` {label}",
                challenge.challenge_id, challenge.case_id, challenge.round_id
            )));
        }
    }
    Ok(None)
}

/// Return the first moderation reference retaining one asset definition.
pub(crate) fn retained_moderation_asset_definition_reference(
    world: &impl WorldReadOnly,
    asset_definition_id: &AssetDefinitionId,
) -> Result<Option<String>, InstructionExecutionError> {
    retained_moderation_asset_definition_reference_in(
        world,
        &BTreeSet::from([asset_definition_id.clone()]),
    )
    .map(|reference| reference.map(|(_, label)| label))
}

/// Return the first moderation reference retaining any definition in `candidates`.
///
/// This scans each durable moderation family at most once so domain teardown
/// cannot amplify the check by the number of definitions it would cascade.
pub(crate) fn retained_moderation_asset_definition_reference_in(
    world: &impl WorldReadOnly,
    candidates: &BTreeSet<AssetDefinitionId>,
) -> Result<Option<(AssetDefinitionId, String)>, InstructionExecutionError> {
    if candidates.is_empty() {
        return Ok(None);
    }
    if let Some(record) = read_policy(world)?
        && candidates.contains(&record.policy.challenge_voting_asset_id)
    {
        return Ok(Some((
            record.policy.challenge_voting_asset_id,
            "active policy challenge voting asset".to_owned(),
        )));
    }

    let appeal_start = StatePath::from_str(APPEAL_STATE_KEY_PREFIX)
        .expect("static moderation appeal prefix is valid");
    for (key, payload) in world.smart_contract_state().range(appeal_start..) {
        if !key.as_ref().starts_with(APPEAL_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: ModerationAppealRecordV1 =
            decode_state_with_current(payload, "moderation appeal", None)?;
        if appeal_key(&candidate.intake.case_id, &candidate.intake.round_id) != *key {
            return Err(corrupt_state(
                "retained moderation appeal key does not match its record",
            ));
        }
        let appeal = read_appeal(world, &candidate.intake.case_id, &candidate.intake.round_id)?
            .ok_or_else(|| corrupt_state("retained moderation appeal disappeared during read"))?;
        if appeal != candidate {
            return Err(corrupt_state(
                "retained moderation appeal changed during read",
            ));
        }
        if candidates.contains(&appeal.policy.challenge_voting_asset_id) {
            let retained_definition = appeal.policy.challenge_voting_asset_id.clone();
            return Ok(Some((
                retained_definition,
                format!(
                    "appeal `{}` round `{}` immutable policy challenge voting asset",
                    appeal.intake.case_id, appeal.intake.round_id
                ),
            )));
        }
    }

    let case_start =
        StatePath::from_str(CASE_STATE_KEY_PREFIX).expect("static moderation case prefix is valid");
    for (key, payload) in world.smart_contract_state().range(case_start..) {
        if !key.as_ref().starts_with(CASE_STATE_KEY_PREFIX) {
            break;
        }
        let case: ModerationCaseRecordV1 =
            decode_state_with_current(payload, "moderation case", None)?;
        if case_key(&case.spec.context.case_id, &case.spec.round_id) != *key {
            return Err(corrupt_state(
                "retained moderation case key does not match its record",
            ));
        }
        if case.status == ModerationCaseStatusV1::Open
            && candidates.contains(&case.policy.challenge_voting_asset_id)
        {
            return Ok(Some((
                case.policy.challenge_voting_asset_id,
                format!(
                    "open case `{}` round `{}` challenge voting asset",
                    case.spec.context.case_id, case.spec.round_id
                ),
            )));
        }
    }

    let challenge_start = StatePath::from_str(CHALLENGE_STATE_KEY_PREFIX)
        .expect("static moderation challenge prefix is valid");
    for (key, payload) in world.smart_contract_state().range(challenge_start..) {
        if !key.as_ref().starts_with(CHALLENGE_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: ModerationChallengeRecordV1 =
            decode_state_with_current(payload, "moderation challenge", None)?;
        if challenge_key(
            &candidate.case_id,
            &candidate.round_id,
            &candidate.challenge_id,
        ) != *key
        {
            return Err(corrupt_state(
                "retained moderation challenge key does not match its record",
            ));
        }
        let challenge = read_challenge(
            world,
            &candidate.case_id,
            &candidate.round_id,
            &candidate.challenge_id,
        )?
        .ok_or_else(|| corrupt_state("retained moderation challenge disappeared during read"))?;
        if challenge != candidate {
            return Err(corrupt_state(
                "retained moderation challenge changed during read",
            ));
        }
        if candidates.contains(&challenge.bond.asset_definition_id) {
            let settlement = if challenge.bond.settled_at_unix_ms.is_some() {
                "settled"
            } else {
                "pending"
            };
            return Ok(Some((
                challenge.bond.asset_definition_id,
                format!(
                    "{settlement} challenge `{}` for case `{}` round `{}` bond asset",
                    challenge.challenge_id, challenge.case_id, challenge.round_id
                ),
            )));
        }
    }
    Ok(None)
}

/// Install a valid active-policy asset reference for unregister guard tests.
#[cfg(test)]
pub(crate) fn seed_moderation_policy_asset_reference_for_test(
    world: &mut crate::state::WorldTransaction<'_, '_>,
    asset_definition_id: AssetDefinitionId,
    custody_account: AccountId,
    activated_by: AccountId,
) -> Result<(), InstructionExecutionError> {
    let policy = ModerationLedgerPolicyV1 {
        version: iroha_data_model::sorafs::moderation_ledger::MODERATION_LEDGER_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        challenge_voting_asset_id: asset_definition_id,
        challenge_bond_amount: Quantity::from(MODERATION_CHALLENGE_BOND_AMOUNT_V1),
        challenge_escrow_account: custody_account.clone(),
        challenge_slash_receiver_account: custody_account,
        challenge_rejected_slash_bps: MODERATION_CHALLENGE_REJECTED_SLASH_BPS_V1,
        challenge_resolution_grace_ms: MODERATION_CHALLENGE_RESOLUTION_GRACE_MS_V1,
        max_panel_size: 8,
        max_candidate_pool_size: 32,
        max_waitlist_size: 8,
        max_exclusions_per_case: 16,
        max_total_window_ms: 90_000_000,
        max_challenges_per_case: 2,
        missing_commit_penalty_points: 11,
        unrevealed_commit_penalty_points: 23,
    };
    policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid test moderation policy: {error}")))?;
    let record = ModerationLedgerPolicyRecord {
        policy_digest: policy
            .digest()
            .map_err(|error| corrupt_state(format!("failed to digest test policy: {error}")))?,
        policy,
        activated_at_unix_ms: 1,
        activated_by,
    };
    world.smart_contract_state.insert(
        policy_key().clone(),
        encode_state(&record, "test moderation policy")?,
    );
    Ok(())
}

/// Sum every unsettled moderation bond pinned to one exact custody balance.
///
/// Challenge records retain the policy revision that admitted them, so this
/// deliberately scans the durable records instead of consulting the current
/// moderation policy. Every candidate is re-read through the authoritative
/// validator; malformed, mis-keyed, or internally inconsistent state fails
/// closed rather than undercounting custody liabilities.
pub(in crate::smartcontracts::isi) fn unsettled_moderation_bond_liability(
    world: &impl WorldReadOnly,
    custody_asset: &AssetId,
) -> Result<Quantity, InstructionExecutionError> {
    let challenge_start = StatePath::from_str(CHALLENGE_STATE_KEY_PREFIX)
        .expect("static moderation challenge prefix is valid");
    let mut liability = Quantity::zero();
    for (key, payload) in world.smart_contract_state().range(challenge_start..) {
        if !key.as_ref().starts_with(CHALLENGE_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: ModerationChallengeRecordV1 =
            decode_state_with_current(payload, "moderation challenge", None)?;
        if challenge_key(
            &candidate.case_id,
            &candidate.round_id,
            &candidate.challenge_id,
        ) != *key
        {
            return Err(corrupt_state(
                "moderation challenge custody key does not match its record",
            ));
        }
        let record = read_challenge(
            world,
            &candidate.case_id,
            &candidate.round_id,
            &candidate.challenge_id,
        )?
        .ok_or_else(|| {
            corrupt_state("moderation challenge disappeared during custody validation")
        })?;
        if record != candidate {
            return Err(corrupt_state(
                "moderation challenge changed during custody validation",
            ));
        }
        if record.bond.settled_at_unix_ms.is_none()
            && record.bond.asset_definition_id == *custody_asset.definition()
            && record.bond.escrow_account == *custody_asset.account()
        {
            liability = liability
                .checked_add(&record.bond.amount)
                .map_err(|_| corrupt_state("moderation challenge bond liability overflow"))?;
        }
    }
    Ok(liability)
}

/// Reject a debit whose resulting balance would undercollateralize moderation bonds.
pub(in crate::smartcontracts::isi) fn ensure_moderation_bond_reserve_after_debit(
    world: &impl WorldReadOnly,
    custody_asset: &AssetId,
    balance_after: &Quantity,
) -> Result<(), InstructionExecutionError> {
    let liability = unsettled_moderation_bond_liability(world, custody_asset)?;
    if balance_after < &liability {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "moderation challenge custody {custody_asset} must retain unsettled bond liability {liability}; debit would leave {balance_after}"
            )
            .into(),
        ));
    }
    Ok(())
}

/// Verify that custody fully backs all bonds before an exact settlement starts.
fn ensure_moderation_bond_custody_fully_backed(
    world: &impl WorldReadOnly,
    custody_asset: &AssetId,
) -> Result<(), InstructionExecutionError> {
    let balance = world
        .assets()
        .get(custody_asset)
        .map(|value| value.as_ref().clone())
        .unwrap_or_else(Quantity::zero);
    ensure_moderation_bond_reserve_after_debit(world, custody_asset, &balance)
}
fn read_policy_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationLedgerPolicyRecord>, InstructionExecutionError> {
    read_policy_with_current(world, Some(current))
}
fn read_policy_with_current(
    world: &impl WorldReadOnly,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationLedgerPolicyRecord>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(policy_key()) else {
        return Ok(None);
    };
    let record: ModerationLedgerPolicyRecord =
        decode_state_with_current(bytes, "moderation policy", current)?;
    record
        .policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored moderation policy: {error}")))?;
    let digest = record
        .policy
        .digest()
        .map_err(|error| corrupt_state(format!("failed to digest stored policy: {error}")))?;
    if digest != record.policy_digest
        || record.policy_digest == [0; 32]
        || record.activated_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation policy provenance is inconsistent",
        ));
    }
    Ok(Some(record))
}
fn empty_sortition_anchor_schedule() -> ModerationSortitionAnchorScheduleV1 {
    ModerationSortitionAnchorScheduleV1 {
        version: MODERATION_SORTITION_ANCHOR_SCHEDULE_VERSION_V1,
        entries: Vec::new(),
    }
}
fn validate_sortition_anchor_schedule(
    schedule: &ModerationSortitionAnchorScheduleV1,
) -> Result<(), InstructionExecutionError> {
    if schedule.version != MODERATION_SORTITION_ANCHOR_SCHEDULE_VERSION_V1 {
        return Err(corrupt_state(format!(
            "unsupported moderation sortition-anchor schedule version {}",
            schedule.version
        )));
    }
    if schedule.entries.len() > MODERATION_LEDGER_MAX_PENDING_SORTITION_ANCHORS_V1 {
        return Err(corrupt_state(format!(
            "moderation sortition-anchor schedule exceeds the hard bound of {MODERATION_LEDGER_MAX_PENDING_SORTITION_ANCHORS_V1}"
        )));
    }
    let mut previous: Option<(u64, String, String)> = None;
    let mut scopes = std::collections::BTreeSet::new();
    for entry in &schedule.entries {
        if entry.registration_deadline_unix_ms == 0
            || entry.intake_digest == [0; 32]
            || !is_canonical_moderation_identifier_v1(&entry.case_id)
            || !is_canonical_moderation_identifier_v1(&entry.round_id)
        {
            return Err(corrupt_state(
                "moderation sortition-anchor schedule contains an invalid entry",
            ));
        }
        let key = (
            entry.registration_deadline_unix_ms,
            entry.case_id.clone(),
            entry.round_id.clone(),
        );
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(corrupt_state(
                "moderation sortition-anchor schedule is duplicated or not canonically ordered",
            ));
        }
        if !scopes.insert((entry.case_id.clone(), entry.round_id.clone())) {
            return Err(corrupt_state(
                "moderation sortition-anchor schedule repeats an appeal scope",
            ));
        }
        previous = Some(key);
    }
    Ok(())
}
fn read_sortition_anchor_schedule(
    world: &impl WorldReadOnly,
) -> Result<ModerationSortitionAnchorScheduleV1, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(sortition_anchor_schedule_key())
    else {
        return Ok(empty_sortition_anchor_schedule());
    };
    let schedule: ModerationSortitionAnchorScheduleV1 =
        decode_state_with_current(bytes, "moderation sortition-anchor schedule", None)?;
    validate_sortition_anchor_schedule(&schedule)?;
    Ok(schedule)
}
fn encode_sortition_anchor_schedule(
    schedule: &ModerationSortitionAnchorScheduleV1,
) -> Result<Vec<u8>, InstructionExecutionError> {
    validate_sortition_anchor_schedule(schedule)?;
    let encoded = encode_state(schedule, "moderation sortition-anchor schedule")?;
    if encoded.len() > STATE_MAX_BYTES {
        return Err(invalid_parameter(format!(
            "moderation sortition-anchor schedule encoded state exceeds {STATE_MAX_BYTES} bytes"
        )));
    }
    Ok(encoded)
}
fn insert_sortition_anchor_schedule_entry(
    schedule: &mut ModerationSortitionAnchorScheduleV1,
    entry: ModerationSortitionAnchorScheduleEntryV1,
) -> Result<(), InstructionExecutionError> {
    if schedule.entries.len() >= MODERATION_LEDGER_MAX_PENDING_SORTITION_ANCHORS_V1 {
        return Err(invalid_parameter(format!(
            "moderation sortition-anchor schedule reached the hard bound of {MODERATION_LEDGER_MAX_PENDING_SORTITION_ANCHORS_V1}"
        )));
    }
    if schedule
        .entries
        .iter()
        .any(|candidate| candidate.case_id == entry.case_id && candidate.round_id == entry.round_id)
    {
        return Err(corrupt_state(
            "moderation sortition-anchor schedule already contains the appeal",
        ));
    }
    let key = (
        entry.registration_deadline_unix_ms,
        entry.case_id.as_str(),
        entry.round_id.as_str(),
    );
    let position = schedule
        .entries
        .binary_search_by(|candidate| {
            (
                candidate.registration_deadline_unix_ms,
                candidate.case_id.as_str(),
                candidate.round_id.as_str(),
            )
                .cmp(&key)
        })
        .unwrap_or_else(|position| position);
    schedule.entries.insert(position, entry);
    Ok(())
}
/// Pin the exact first consensus block after each due registration deadline.
///
/// This bounded start-of-block transition runs before ordinary entrypoints. The consensus header
/// hash excludes execution results, so committing the anchor in world state is non-circular and
/// replay-stable. An anchored appeal is removed from the schedule exactly once.
///
/// # Errors
///
/// Separates local transaction admission from invalid authenticated moderation state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SortitionAnchorPinError {
    /// The original finite World owner could not open a transaction locally.
    #[error(transparent)]
    Storage(#[from] StateStorageAdmissionError),
    /// The bounded schedule or indexed appeal is invalid.
    #[error(transparent)]
    Instruction(#[from] InstructionExecutionError),
}
pub(crate) fn pin_due_sortition_anchors_v1(
    state_block: &mut StateBlock<'_>,
) -> Result<usize, SortitionAnchorPinError> {
    let mut transaction = state_block.try_transaction()?;
    let mut schedule = read_sortition_anchor_schedule(transaction.world())?;
    if schedule.entries.is_empty() {
        return Ok(0);
    }
    let now = block_time_ms(&transaction)?;
    let due_count = schedule
        .entries
        .partition_point(|entry| entry.registration_deadline_unix_ms < now);
    if due_count == 0 {
        return Ok(0);
    }
    let block_height = transaction._curr_block.height().get();
    let block_hash = *transaction._curr_block.hash().as_ref();
    if block_hash == [0; 32] {
        return Err(corrupt_state(
            "moderation sortition anchor resolved a zero consensus block hash",
        )
        .into());
    }
    let due = schedule.entries.drain(..due_count).collect::<Vec<_>>();
    for entry in &due {
        let mut appeal = required_appeal(transaction.world(), &entry.case_id, &entry.round_id)?;
        if appeal.status != ModerationAppealStatusV1::RegisteringJurors
            || appeal.sortition_anchor.is_some()
            || appeal.intake.registration_deadline_unix_ms != entry.registration_deadline_unix_ms
            || appeal.intake_digest != entry.intake_digest
        {
            return Err(corrupt_state(
                "moderation sortition-anchor schedule disagrees with its indexed appeal",
            )
            .into());
        }
        appeal.sortition_anchor = Some(ModerationSortitionAnchorV1 {
            block_height,
            block_hash,
            block_timestamp_unix_ms: now,
        });
        let encoded = encode_state(&appeal, "moderation appeal with pinned sortition anchor")?;
        transaction
            .world
            .smart_contract_state
            .insert(appeal_key(&entry.case_id, &entry.round_id), encoded);
    }
    if schedule.entries.is_empty() {
        transaction
            .world
            .smart_contract_state
            .remove(sortition_anchor_schedule_key().clone());
    } else {
        let encoded_schedule = encode_sortition_anchor_schedule(&schedule)?;
        transaction
            .world
            .smart_contract_state
            .insert(sortition_anchor_schedule_key().clone(), encoded_schedule);
    }
    transaction.apply();
    Ok(due_count)
}
/// Validate every persisted moderation policy, appeal, anchor schedule, and case.
///
/// Moderation records live in the otherwise opaque smart-contract state map. Snapshot decoding
/// therefore cannot rely on the world serializer to decode these values. Startup calls this
/// validator explicitly so pre-cut layouts fail before the node serves requests.
///
/// # Errors
///
/// Returns an execution error when retained state does not decode and validate as the canonical
/// first-release V1 schema, including exact correspondence between unanchored registering appeals
/// and the bounded anchor schedule.
pub(crate) fn validate_persisted_moderation_schema_v1(
    world: &impl WorldReadOnly,
) -> Result<(), InstructionExecutionError> {
    let policy_present = read_policy(world)?.is_some();
    let mut expected_schedule = std::collections::BTreeMap::new();
    let appeal_start = StatePath::from_str(APPEAL_STATE_KEY_PREFIX)
        .expect("static moderation appeal prefix is valid");
    let mut appeal_present = false;
    for (key, payload) in world.smart_contract_state().range(appeal_start..) {
        if !key.as_ref().starts_with(APPEAL_STATE_KEY_PREFIX) {
            break;
        }
        appeal_present = true;
        let candidate: ModerationAppealRecordV1 =
            decode_state_with_current(payload, "moderation appeal", None)?;
        if appeal_key(&candidate.intake.case_id, &candidate.intake.round_id) != *key {
            return Err(corrupt_state(
                "persisted moderation appeal key does not match its V1 record",
            ));
        }
        let restored = read_appeal(world, &candidate.intake.case_id, &candidate.intake.round_id)?
            .ok_or_else(|| {
            corrupt_state("persisted moderation appeal disappeared during validation")
        })?;
        if restored != candidate {
            return Err(corrupt_state(
                "persisted moderation appeal changed during validation",
            ));
        }
        if candidate.status == ModerationAppealStatusV1::RegisteringJurors
            && candidate.sortition_anchor.is_none()
        {
            expected_schedule.insert(
                (
                    candidate.intake.case_id.clone(),
                    candidate.intake.round_id.clone(),
                ),
                (
                    candidate.intake.registration_deadline_unix_ms,
                    candidate.intake_digest,
                ),
            );
        }
    }
    let schedule = read_sortition_anchor_schedule(world)?;
    let actual_schedule = schedule
        .entries
        .iter()
        .map(|entry| {
            (
                (entry.case_id.clone(), entry.round_id.clone()),
                (entry.registration_deadline_unix_ms, entry.intake_digest),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if actual_schedule != expected_schedule {
        return Err(corrupt_state(
            "moderation sortition-anchor schedule does not exactly index unanchored registering appeals",
        ));
    }
    let start =
        StatePath::from_str(CASE_STATE_KEY_PREFIX).expect("static moderation case prefix is valid");
    let mut case_present = false;
    for (key, payload) in world.smart_contract_state().range(start..) {
        if !key.as_ref().starts_with(CASE_STATE_KEY_PREFIX) {
            break;
        }
        case_present = true;
        let candidate: ModerationCaseRecordV1 =
            decode_state_with_current(payload, "moderation case", None)?;
        if case_key(&candidate.spec.context.case_id, &candidate.spec.round_id) != *key {
            return Err(corrupt_state(
                "persisted moderation case key does not match its V1 record",
            ));
        }
        let restored = read_case(
            world,
            &candidate.spec.context.case_id,
            &candidate.spec.round_id,
        )?
        .ok_or_else(|| corrupt_state("persisted moderation case disappeared during validation"))?;
        if restored != candidate {
            return Err(corrupt_state(
                "persisted moderation case changed during validation",
            ));
        }
    }
    if (appeal_present || case_present) && !policy_present {
        return Err(corrupt_state(
            "persisted moderation appeals and cases require an active V1 policy",
        ));
    }
    Ok(())
}
/// Bind every restored moderation sortition anchor to the committed hash journal.
///
/// Snapshot restoration calls this after decoding the world and its exact block-hash prefix.
/// Live execution performs the same check before sortition, but failing during restore avoids
/// serving an internally inconsistent first-release snapshot.
///
/// # Errors
///
/// Returns an invariant error if an anchored appeal names a missing height or a hash other than
/// the hash committed at that one-based height.
pub(crate) fn validate_persisted_moderation_anchor_history_v1(
    world: &impl WorldReadOnly,
    committed_block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
) -> Result<(), InstructionExecutionError> {
    let appeal_start = StatePath::from_str(APPEAL_STATE_KEY_PREFIX)
        .expect("static moderation appeal prefix is valid");
    for (key, payload) in world.smart_contract_state().range(appeal_start..) {
        if !key.as_ref().starts_with(APPEAL_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: ModerationAppealRecordV1 =
            decode_state_with_current(payload, "moderation appeal", None)?;
        let Some(anchor) = candidate.sortition_anchor else {
            continue;
        };
        let zero_based_height = anchor
            .block_height
            .checked_sub(1)
            .ok_or_else(|| corrupt_state("persisted moderation sortition-anchor height is zero"))?;
        let anchor_index = usize::try_from(zero_based_height).map_err(|_| {
            corrupt_state("persisted moderation sortition-anchor height exceeds index bounds")
        })?;
        let committed_hash = committed_block_hashes
            .hash_at(anchor_index)
            .map(|hash| *hash.as_ref())
            .ok_or_else(|| {
                corrupt_state(format!(
                    "persisted moderation sortition anchor for `{}` round `{}` names missing committed height {}",
                    candidate.intake.case_id, candidate.intake.round_id, anchor.block_height
                ))
            })?;
        if committed_hash != anchor.block_hash {
            return Err(corrupt_state(format!(
                "persisted moderation sortition anchor for `{}` round `{}` differs from committed block history at height {}",
                candidate.intake.case_id, candidate.intake.round_id, anchor.block_height
            )));
        }
    }
    Ok(())
}
fn read_status(
    world: &impl WorldReadOnly,
) -> Result<Option<ModerationLedgerStatusV1>, InstructionExecutionError> {
    read_status_with_current(world, None)
}
fn read_status_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationLedgerStatusV1>, InstructionExecutionError> {
    read_status_with_current(world, Some(current))
}
fn read_status_with_current(
    world: &impl WorldReadOnly,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationLedgerStatusV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(status_key()) else {
        return Ok(None);
    };
    let status: ModerationLedgerStatusV1 =
        decode_state_with_current(bytes, "moderation status", current)?;
    if status.updated_at_unix_ms == 0
        || status.finalized_cases != status.outcomes
        || status.panel_selections > status.appeal_intakes
        || status.failed_panel_formations > status.appeal_intakes
        || status.assignment_acceptances > status.eligibility_proofs
        || status.failover_replacements > status.eligibility_proofs
        || status
            .open_cases
            .checked_add(status.finalized_cases)
            .is_none()
    {
        return Err(corrupt_state("stored moderation status is invalid"));
    }
    Ok(Some(status))
}
fn status_for_mutation(
    world: &impl WorldReadOnly,
    now: u64,
) -> Result<ModerationLedgerStatusV1, InstructionExecutionError> {
    let status = read_status(world)?
        .ok_or_else(|| corrupt_state("moderation policy exists without ledger status"))?;
    if now < status.updated_at_unix_ms {
        return Err(invalid_parameter(format!(
            "moderation ledger block-time rollback: {now} precedes {}",
            status.updated_at_unix_ms
        )));
    }
    Ok(status)
}
fn canonical_account_list(accounts: &[AccountId]) -> bool {
    let mut previous: Option<String> = None;
    accounts.iter().all(|account| {
        let current = account.to_string();
        let valid = previous.as_ref().is_none_or(|value| value < &current);
        previous = Some(current);
        valid
    })
}
fn unique_account_list(accounts: &[AccountId]) -> bool {
    accounts
        .iter()
        .enumerate()
        .all(|(index, account)| accounts[..index].iter().all(|previous| previous != account))
}
fn canonical_identifier_list(values: &[String]) -> bool {
    let mut previous: Option<&str> = None;
    values.iter().all(|value| {
        let valid = is_canonical_moderation_identifier_v1(value)
            && previous.is_none_or(|candidate| candidate < value.as_str());
        previous = Some(value);
        valid
    })
}
fn read_appeal(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
) -> Result<Option<ModerationAppealRecordV1>, InstructionExecutionError> {
    read_appeal_with_current(world, case_id, round_id, None)
}
fn read_appeal_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationAppealRecordV1>, InstructionExecutionError> {
    read_appeal_with_current(world, case_id, round_id, Some(current))
}
fn read_appeal_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationAppealRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&appeal_key(case_id, round_id))
    else {
        return Ok(None);
    };
    let record: ModerationAppealRecordV1 =
        decode_state_with_current(bytes, "moderation appeal", current)?;
    record
        .intake
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored moderation appeal: {error}")))?;
    record
        .policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored appeal policy: {error}")))?;
    record.pop_snapshot.validate().map_err(|error| {
        corrupt_state(format!("invalid stored moderation PoP snapshot: {error}"))
    })?;
    let intake_digest = record.intake.digest().map_err(|error| {
        corrupt_state(format!(
            "failed to digest stored moderation appeal: {error}"
        ))
    })?;
    let snapshot_digest = record.pop_snapshot.digest().map_err(|error| {
        corrupt_state(format!(
            "failed to digest stored moderation PoP snapshot: {error}"
        ))
    })?;
    let sortition_anchor_valid = record.sortition_anchor.as_ref().is_none_or(|anchor| {
        anchor.block_height != 0
            && anchor.block_hash != [0; 32]
            && anchor.block_timestamp_unix_ms > record.intake.registration_deadline_unix_ms
    });
    if record.intake.case_id != case_id
        || record.intake.round_id != round_id
        || record.intake.appellant != record.submitted_by
        || record.intake_digest != intake_digest
        || record.pop_snapshot_digest != snapshot_digest
        || record.intake.policy_digest
            != record.policy.digest().map_err(|error| {
                corrupt_state(format!("failed to digest appeal policy: {error}"))
            })?
        || record.submitted_at_unix_ms == 0
        || record.submitted_at_unix_ms != record.pop_snapshot.captured_at_unix_ms
        || record.submitted_at_unix_ms >= record.intake.registration_deadline_unix_ms
        || !sortition_anchor_valid
        || record.eligible_jurors.len() > usize::from(record.policy.max_candidate_pool_size)
        || !canonical_account_list(&record.eligible_jurors)
        || !canonical_account_list(&record.accepted_jurors)
        || record.eligible_jurors.iter().any(|juror| {
            record
                .intake
                .exclusions
                .binary_search_by(|candidate| candidate.to_string().cmp(&juror.to_string()))
                .is_ok()
        })
        || record
            .accepted_jurors
            .iter()
            .any(|juror| !record.eligible_jurors.contains(juror))
    {
        return Err(corrupt_state(
            "stored moderation appeal metadata is inconsistent",
        ));
    }
    if let Some(selection) = &record.selection {
        if selection.randomness_anchor == [0; 32]
            || record.sortition_anchor.as_ref().is_none_or(|anchor| {
                selection.randomness_anchor != anchor.block_hash
                    || selection.selected_at_unix_ms < anchor.block_timestamp_unix_ms
            })
            || selection.seed_digest == [0; 32]
            || selection.seed_digest
                != sorafs_moderation_sortition_seed_v1(
                    record.intake_digest,
                    record.pop_snapshot_digest,
                    selection.randomness_anchor,
                )
            || selection.jurors.len() != usize::from(record.intake.panel_size)
            || selection.waitlist.len() > usize::from(record.intake.waitlist_size)
            || !unique_account_list(&selection.jurors)
            || !unique_account_list(&selection.waitlist)
            || selection
                .jurors
                .iter()
                .any(|juror| selection.waitlist.contains(juror))
            || selection
                .jurors
                .iter()
                .chain(selection.waitlist.iter())
                .any(|juror| !record.eligible_jurors.contains(juror))
            || selection.selected_at_unix_ms <= record.intake.registration_deadline_unix_ms
            || selection.selected_at_unix_ms > record.intake.acceptance_deadline_unix_ms
            || selection.sortition_digest
                != sorafs_moderation_sortition_digest_v1(
                    record.pop_snapshot_digest,
                    selection.seed_digest,
                    &selection.jurors,
                    &selection.waitlist,
                    record.intake.quorum,
                )
            || record
                .accepted_jurors
                .iter()
                .any(|juror| !selection.jurors.contains(juror))
        {
            return Err(corrupt_state(
                "stored moderation panel selection is inconsistent",
            ));
        }
    } else if !record.accepted_jurors.is_empty() || !record.replacements.is_empty() {
        return Err(corrupt_state(
            "stored moderation appeal has assignment state without sortition",
        ));
    }
    if record
        .replacements
        .iter()
        .enumerate()
        .any(|(index, replacement)| {
            replacement.absent_juror == replacement.replacement_juror
                || record.replacements[..index].iter().any(|previous| {
                    previous.absent_juror == replacement.absent_juror
                        || previous.replacement_juror == replacement.replacement_juror
                })
                || record.selection.as_ref().is_none_or(|selection| {
                    !selection.jurors.contains(&replacement.absent_juror)
                        || !selection.waitlist.contains(&replacement.replacement_juror)
                })
        })
    {
        return Err(corrupt_state(
            "stored moderation failover replacements are inconsistent",
        ));
    }
    let (replacements_match_expected, failover_exhausted) = record.selection.as_ref().map_or_else(
        || (record.replacements.is_empty(), false),
        |selection| {
            let missing_primaries = selection
                .jurors
                .iter()
                .filter(|juror| !record.accepted_jurors.contains(juror));
            let missing_count = missing_primaries.clone().count();
            let expected_count = missing_count.min(selection.waitlist.len());
            let replacements_match = record.replacements.len() == expected_count
                && missing_primaries
                    .zip(selection.waitlist.iter())
                    .zip(record.replacements.iter())
                    .all(|((absent, replacement), recorded)| {
                        recorded.absent_juror == *absent
                            && recorded.replacement_juror == *replacement
                    });
            (replacements_match, missing_count > selection.waitlist.len())
        },
    );
    let lifecycle_valid = match record.status {
        ModerationAppealStatusV1::RegisteringJurors => {
            record.selection.is_none()
                && record.accepted_jurors.is_empty()
                && record.replacements.is_empty()
                && record.activated_at_unix_ms.is_none()
                && record.finalized_at_unix_ms.is_none()
        }
        ModerationAppealStatusV1::AwaitingAcceptance => {
            record.selection.is_some()
                && record.replacements.is_empty()
                && record.activated_at_unix_ms.is_none()
                && record.finalized_at_unix_ms.is_none()
        }
        ModerationAppealStatusV1::BallotOpen => {
            record.selection.is_some()
                && !failover_exhausted
                && replacements_match_expected
                && record.activated_at_unix_ms.is_some_and(|time| {
                    time > record.intake.acceptance_deadline_unix_ms
                        && time < record.intake.commit_deadline_unix_ms
                })
                && record.finalized_at_unix_ms.is_none()
        }
        ModerationAppealStatusV1::InsufficientEligiblePool => {
            record.selection.is_none()
                && record.sortition_anchor.is_some()
                && record.activated_at_unix_ms.is_none()
                && record.finalized_at_unix_ms.is_none()
        }
        ModerationAppealStatusV1::FailoverExhausted => {
            record.selection.is_some()
                && failover_exhausted
                && replacements_match_expected
                && record.activated_at_unix_ms.is_none()
                && record.finalized_at_unix_ms.is_none()
        }
        ModerationAppealStatusV1::Finalized => {
            record.selection.is_some()
                && !failover_exhausted
                && replacements_match_expected
                && record.activated_at_unix_ms.is_some()
                && record.finalized_at_unix_ms.is_some_and(|time| {
                    time > record.intake.reveal_deadline_unix_ms
                        && record
                            .activated_at_unix_ms
                            .is_some_and(|opened| time > opened)
                })
        }
    };
    if !lifecycle_valid {
        return Err(corrupt_state(
            "stored moderation appeal lifecycle is inconsistent",
        ));
    }
    Ok(Some(record))
}
fn required_appeal(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
) -> Result<ModerationAppealRecordV1, InstructionExecutionError> {
    read_appeal(world, case_id, round_id)?.ok_or_else(|| {
        invalid_parameter(format!(
            "moderation appeal `{case_id}` round `{round_id}` does not exist"
        ))
    })
}
fn read_appeal_deposit_binding(
    world: &impl WorldReadOnly,
    deposit_lock_digest: [u8; 32],
) -> Result<Option<AppealDepositBindingStateV1>, InstructionExecutionError> {
    read_appeal_deposit_binding_with_current(world, deposit_lock_digest, None)
}
fn read_appeal_deposit_binding_for_current(
    world: &impl WorldReadOnly,
    deposit_lock_digest: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<AppealDepositBindingStateV1>, InstructionExecutionError> {
    read_appeal_deposit_binding_with_current(world, deposit_lock_digest, Some(current))
}
fn read_appeal_deposit_binding_with_current(
    world: &impl WorldReadOnly,
    deposit_lock_digest: [u8; 32],
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<AppealDepositBindingStateV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&appeal_deposit_key(deposit_lock_digest))
    else {
        return Ok(None);
    };
    let binding: AppealDepositBindingStateV1 = decode_state_with_current(
        bytes,
        "moderation appeal deposit binding",
        current.as_deref_mut(),
    )?;
    if binding.deposit_lock_digest != deposit_lock_digest
        || binding.intake_digest == [0; 32]
        || validate_lookup_identifiers(&binding.case_id, &binding.round_id).is_err()
    {
        return Err(corrupt_state(
            "stored moderation appeal deposit binding is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let primary = read_appeal_with_current(
        world,
        &binding.case_id,
        &binding.round_id,
        transient_current.as_mut(),
    )?
    .ok_or_else(|| corrupt_state("moderation appeal deposit binding has no appeal"))?;
    if primary.intake_digest != binding.intake_digest
        || primary.intake.appeal_deposit_lock_digest != deposit_lock_digest
    {
        return Err(corrupt_state(
            "moderation appeal deposit binding disagrees with its appeal",
        ));
    }
    Ok(Some(binding))
}
fn read_appeal_proof_token_binding(
    world: &impl WorldReadOnly,
    proof_token_digest: [u8; 32],
) -> Result<Option<AppealProofTokenBindingStateV1>, InstructionExecutionError> {
    read_appeal_proof_token_binding_with_current(world, proof_token_digest, None)
}
fn read_appeal_proof_token_binding_for_current(
    world: &impl WorldReadOnly,
    proof_token_digest: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<AppealProofTokenBindingStateV1>, InstructionExecutionError> {
    read_appeal_proof_token_binding_with_current(world, proof_token_digest, Some(current))
}
fn read_appeal_proof_token_binding_with_current(
    world: &impl WorldReadOnly,
    proof_token_digest: [u8; 32],
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<AppealProofTokenBindingStateV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&appeal_proof_token_key(proof_token_digest))
    else {
        return Ok(None);
    };
    let binding: AppealProofTokenBindingStateV1 = decode_state_with_current(
        bytes,
        "moderation appeal proof-token binding",
        current.as_deref_mut(),
    )?;
    if binding.proof_token_digest != proof_token_digest
        || binding.intake_digest == [0; 32]
        || validate_lookup_identifiers(&binding.case_id, &binding.round_id).is_err()
    {
        return Err(corrupt_state(
            "stored moderation appeal proof-token binding is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let primary = read_appeal_with_current(
        world,
        &binding.case_id,
        &binding.round_id,
        transient_current.as_mut(),
    )?
    .ok_or_else(|| corrupt_state("moderation appeal proof-token binding has no appeal"))?;
    if primary.intake_digest != binding.intake_digest
        || primary.intake.proof_token_digest != proof_token_digest
    {
        return Err(corrupt_state(
            "moderation appeal proof-token binding disagrees with its appeal",
        ));
    }
    Ok(Some(binding))
}
fn read_eligibility(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    read_eligibility_with_current(world, case_id, round_id, juror, None)
}
fn read_eligibility_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    read_eligibility_with_current(world, case_id, round_id, juror, Some(current))
}
fn read_eligibility_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&eligibility_key(case_id, round_id, juror))
    else {
        return Ok(None);
    };
    let record: ModerationJurorEligibilityRecordV1 = decode_state_with_current(
        bytes,
        "moderation juror eligibility",
        current.as_deref_mut(),
    )?;
    if record.case_id != case_id
        || record.round_id != round_id
        || &record.juror != juror
        || record.eligibility_class == ModerationJurorEligibilityClassV1::Observer
        || record.proof_digest == [0; 32]
        || record.nullifier == [0; 32]
        || record.pop_snapshot_digest == [0; 32]
        || record.credential_expires_at_epoch == 0
        || record.registered_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation juror eligibility is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let appeal = read_appeal_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("moderation eligibility has no appeal"))?;
    let reveal_deadline_epoch = ceil_unix_ms_to_epoch(appeal.intake.reveal_deadline_unix_ms)?;
    if record.pop_snapshot_digest != appeal.pop_snapshot_digest
        || !appeal.eligible_jurors.contains(juror)
        || record.registered_at_unix_ms < appeal.submitted_at_unix_ms
        || record.registered_at_unix_ms > appeal.intake.registration_deadline_unix_ms
        || record.credential_expires_at_epoch <= reveal_deadline_epoch
    {
        return Err(corrupt_state(
            "stored moderation eligibility does not match its appeal",
        ));
    }
    Ok(Some(record))
}
fn read_nullifier(
    world: &impl WorldReadOnly,
    nullifier: [u8; 32],
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    read_nullifier_with_current(world, nullifier, None)
}
fn read_nullifier_for_current(
    world: &impl WorldReadOnly,
    nullifier: [u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    read_nullifier_with_current(world, nullifier, Some(current))
}
fn read_nullifier_with_current(
    world: &impl WorldReadOnly,
    nullifier: [u8; 32],
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationJurorEligibilityRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&nullifier_key(nullifier)) else {
        return Ok(None);
    };
    let record: ModerationJurorEligibilityRecordV1 =
        decode_state_with_current(bytes, "moderation PoP nullifier", current.as_deref_mut())?;
    if record.nullifier != nullifier {
        return Err(corrupt_state(
            "stored moderation PoP nullifier key is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let primary = read_eligibility_with_current(
        world,
        &record.case_id,
        &record.round_id,
        &record.juror,
        transient_current.as_mut(),
    )?
    .ok_or_else(|| corrupt_state("moderation PoP nullifier has no eligibility record"))?;
    if primary != record {
        return Err(corrupt_state(
            "moderation PoP nullifier disagrees with eligibility record",
        ));
    }
    Ok(Some(record))
}
pub(in crate::smartcontracts::isi) fn read_case(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
) -> Result<Option<ModerationCaseRecordV1>, InstructionExecutionError> {
    read_case_with_current(world, case_id, round_id, None)
}
fn read_case_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationCaseRecordV1>, InstructionExecutionError> {
    read_case_with_current(world, case_id, round_id, Some(current))
}
fn read_case_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationCaseRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&case_key(case_id, round_id))
    else {
        return Ok(None);
    };
    let record: ModerationCaseRecordV1 =
        decode_state_with_current(bytes, "moderation case", current.as_deref_mut())?;
    record
        .spec
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored moderation case: {error}")))?;
    record
        .policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored case policy: {error}")))?;
    let digest = record
        .policy
        .digest()
        .map_err(|error| corrupt_state(format!("failed to digest stored case policy: {error}")))?;
    let roster_size = u32::try_from(record.spec.jurors.len())
        .map_err(|_| corrupt_state("stored moderation roster length does not fit u32"))?;
    let challenge_id_count = u32::try_from(record.challenge_ids.len())
        .map_err(|_| corrupt_state("stored moderation challenge-id count does not fit u32"))?;
    let total_window = record
        .spec
        .reveal_deadline_unix_ms
        .checked_sub(record.opened_at_unix_ms)
        .ok_or_else(|| corrupt_state("stored moderation case reveal deadline precedes opening"))?;
    if record.spec.context.case_id != case_id
        || record.spec.round_id != round_id
        || record.spec.policy_digest != digest
        || record.opened_at_unix_ms == 0
        || record.opened_at_unix_ms >= record.spec.commit_deadline_unix_ms
        || total_window > record.policy.max_total_window_ms
        || record.spec.jurors.len() > usize::from(record.policy.max_panel_size)
        || record.commitment_count > roster_size
        || record.reveal_count > record.commitment_count
        || record.challenge_count > u32::from(record.policy.max_challenges_per_case)
        || record.challenge_count != challenge_id_count
        || !canonical_identifier_list(&record.challenge_ids)
        || record.pending_challenge_count > record.challenge_count
        || record.accepted_challenge_count > record.challenge_count
        || record.expired_challenge_count > record.challenge_count
        || record
            .pending_challenge_count
            .checked_add(record.accepted_challenge_count)
            .and_then(|count| count.checked_add(record.expired_challenge_count))
            .is_none_or(|resolved_or_pending| resolved_or_pending > record.challenge_count)
    {
        return Err(corrupt_state(
            "stored moderation case metadata is inconsistent",
        ));
    }
    match record.status {
        ModerationCaseStatusV1::Open if record.accepted_challenge_count == 0 => {}
        ModerationCaseStatusV1::Challenged if record.accepted_challenge_count > 0 => {}
        ModerationCaseStatusV1::Finalized => {}
        _ => {
            return Err(corrupt_state(
                "stored moderation case status/challenge state is inconsistent",
            ));
        }
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let outcome = read_outcome_with_current(world, case_id, round_id, transient_current.as_mut())?;
    match (record.status, outcome) {
        (ModerationCaseStatusV1::Finalized, Some(outcome))
            if outcome.quorum == record.spec.quorum
                && outcome.finalized_at_unix_ms > record.spec.reveal_deadline_unix_ms
                && outcome.votes_total <= roster_size
                && outcome.votes_total == record.reveal_count
                && record.pending_challenge_count == 0
                && matches!(outcome.kind, ModerationOutcomeKindV1::Challenged)
                    == (record.accepted_challenge_count > 0)
                && (matches!(outcome.kind, ModerationOutcomeKindV1::Challenged)
                    && outcome.no_show_count == 0
                    || !matches!(outcome.kind, ModerationOutcomeKindV1::Challenged)
                        && roster_size.checked_sub(outcome.votes_total)
                            == Some(outcome.no_show_count)) => {}
        (ModerationCaseStatusV1::Open | ModerationCaseStatusV1::Challenged, None) => {}
        _ => {
            return Err(corrupt_state(
                "stored moderation case and terminal outcome are inconsistent",
            ));
        }
    }
    Ok(Some(record))
}
fn read_commit(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
) -> Result<Option<ModerationCommitRecordV1>, InstructionExecutionError> {
    read_commit_with_current(world, case_id, round_id, juror, None)
}
fn read_commit_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationCommitRecordV1>, InstructionExecutionError> {
    read_commit_with_current(world, case_id, round_id, juror, Some(current))
}
fn read_commit_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationCommitRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&commit_key(case_id, round_id, juror))
    else {
        return Ok(None);
    };
    let record: ModerationCommitRecordV1 =
        decode_state_with_current(bytes, "moderation commit", current.as_deref_mut())?;
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let commit: SoraFsModerationBallotCommitV1 = match transient_current.as_mut() {
        Some(current) => decode_payload_for_current(
            &record.canonical_commit,
            "stored moderation commit",
            current,
        ),
        None => decode_payload(&record.canonical_commit, "stored moderation commit"),
    }
    .map_err(corrupt_stored_payload)?;
    commit
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored moderation commit: {error}")))?;
    if record.case_id != case_id
        || record.round_id != round_id
        || &record.juror != juror
        || commit.context.case_id != case_id
        || commit.round_id != round_id
        || commit.juror_id != juror.to_string()
        || commit.committed_at_unix_ms != record.accepted_at_unix_ms
        || record.accepted_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation commitment provenance is inconsistent",
        ));
    }
    let case = read_case_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("stored moderation commitment has no authoritative case"))?;
    if commit.context != case.spec.context
        || !case.spec.jurors.iter().any(|candidate| candidate == juror)
        || record.accepted_at_unix_ms < case.opened_at_unix_ms
        || record.accepted_at_unix_ms > case.spec.commit_deadline_unix_ms
    {
        return Err(corrupt_state(
            "stored moderation commitment does not match authoritative case state",
        ));
    }
    Ok(Some(record))
}
fn read_reveal(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
) -> Result<Option<ModerationRevealRecordV1>, InstructionExecutionError> {
    read_reveal_with_current(world, case_id, round_id, juror, None)
}
fn read_reveal_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationRevealRecordV1>, InstructionExecutionError> {
    read_reveal_with_current(world, case_id, round_id, juror, Some(current))
}
fn read_reveal_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationRevealRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&reveal_key(case_id, round_id, juror))
    else {
        return Ok(None);
    };
    let record: ModerationRevealRecordV1 =
        decode_state_with_current(bytes, "moderation reveal", current.as_deref_mut())?;
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let reveal: SoraFsModerationBallotRevealV1 = match transient_current.as_mut() {
        Some(current) => decode_payload_for_current(
            &record.canonical_reveal,
            "stored moderation reveal",
            current,
        ),
        None => decode_payload(&record.canonical_reveal, "stored moderation reveal"),
    }
    .map_err(corrupt_stored_payload)?;
    reveal
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored moderation reveal: {error}")))?;
    if record.case_id != case_id
        || record.round_id != round_id
        || &record.juror != juror
        || reveal.context.case_id != case_id
        || reveal.round_id != round_id
        || reveal.juror_id != juror.to_string()
        || reveal.revealed_at_unix_ms != record.accepted_at_unix_ms
        || record.accepted_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation reveal provenance is inconsistent",
        ));
    }
    let case = read_case_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("stored moderation reveal has no authoritative case"))?;
    let mut commit_current = moderation_transient_current(transient_current.as_ref())?;
    let commit_record =
        read_commit_with_current(world, case_id, round_id, juror, commit_current.as_mut())?
            .ok_or_else(|| corrupt_state("stored moderation reveal has no commitment"))?;
    let commit: SoraFsModerationBallotCommitV1 = match commit_current.as_mut() {
        Some(current) => decode_payload_for_current(
            &commit_record.canonical_commit,
            "stored moderation commit",
            current,
        ),
        None => decode_payload(&commit_record.canonical_commit, "stored moderation commit"),
    }
    .map_err(corrupt_stored_payload)?;
    if reveal.context != case.spec.context
        || !case.spec.jurors.iter().any(|candidate| candidate == juror)
        || record.accepted_at_unix_ms <= case.spec.challenge_resolution_deadline_unix_ms
        || record.accepted_at_unix_ms > case.spec.reveal_deadline_unix_ms
        || commit.verify_reveal(&reveal).is_err()
    {
        return Err(corrupt_state(
            "stored moderation reveal does not match authoritative case state",
        ));
    }
    Ok(Some(record))
}
/// Read and validate one retained moderation challenge.
pub(in crate::smartcontracts::isi) fn read_challenge(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    challenge_id: &str,
) -> Result<Option<ModerationChallengeRecordV1>, InstructionExecutionError> {
    read_challenge_with_current(world, case_id, round_id, challenge_id, None)
}
/// Compute the exact deterministic slash for a rejected challenge bond.
pub(in crate::smartcontracts::isi) fn moderation_challenge_rejected_slash_amount(
    amount: &Quantity,
    numeric_spec: NumericSpec,
    rejected_slash_bps: u16,
) -> Result<Quantity, InstructionExecutionError> {
    amount
        .try_mul_div_decimal_round(
            &Numeric::from(u64::from(rejected_slash_bps)),
            &Numeric::from(10_000_u64),
            numeric_spec.scale().unwrap_or(amount.scale()),
            RoundingMode::TowardZero,
        )
        .map_err(|_| corrupt_state("moderation challenge bond slash amount overflow"))
}
fn read_challenge_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    challenge_id: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationChallengeRecordV1>, InstructionExecutionError> {
    read_challenge_with_current(world, case_id, round_id, challenge_id, Some(current))
}
fn read_challenge_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    challenge_id: &str,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationChallengeRecordV1>, InstructionExecutionError> {
    let Some(bytes) =
        world
            .smart_contract_state()
            .get(&challenge_key(case_id, round_id, challenge_id))
    else {
        return Ok(None);
    };
    let record: ModerationChallengeRecordV1 =
        decode_state_with_current(bytes, "moderation challenge", current.as_deref_mut())?;
    if record.case_id != case_id
        || record.round_id != round_id
        || record.challenge_id != challenge_id
        || !is_canonical_moderation_identifier_v1(&record.challenge_id)
        || record.evidence_digest == [0; 32]
        || record.raised_at_unix_ms == 0
        || record.reason.trim().is_empty()
        || record.reason != record.reason.trim()
        || record.reason.len() > MODERATION_LEDGER_MAX_REASON_BYTES_V1
        || record.reason.chars().any(char::is_control)
        || record.kind.requires_target_juror() && record.target_juror.is_none()
    {
        return Err(corrupt_state(
            "stored moderation challenge metadata is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let case = read_case_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("stored moderation challenge has no authoritative case"))?;
    if record.raised_at_unix_ms <= case.spec.commit_deadline_unix_ms
        || record.raised_at_unix_ms > case.spec.challenge_submission_deadline_unix_ms
        || record.bond.asset_definition_id != case.policy.challenge_voting_asset_id
        || record.bond.amount != case.policy.challenge_bond_amount
        || record.bond.escrow_account != case.policy.challenge_escrow_account
        || record.bond.slash_receiver_account != case.policy.challenge_slash_receiver_account
        || case
            .challenge_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(challenge_id))
            .is_err()
        || record
            .target_juror
            .as_ref()
            .is_some_and(|target| !case.spec.jurors.iter().any(|juror| juror == target))
    {
        return Err(corrupt_state(
            "stored moderation challenge does not match authoritative case state",
        ));
    }
    let zero = Quantity::zero();
    let numeric_spec = world
        .asset_definition(&record.bond.asset_definition_id)
        .map_err(InstructionExecutionError::Find)?
        .spec();
    let rejected_slash = moderation_challenge_rejected_slash_amount(
        &record.bond.amount,
        numeric_spec,
        case.policy.challenge_rejected_slash_bps,
    )?;
    let rejected_refund = record
        .bond
        .amount
        .checked_sub(&rejected_slash)
        .map_err(|_| corrupt_state("stored moderation challenge bond settlement underflow"))?;
    let resolution_valid = match (
        record.decision,
        record.resolved_by.as_ref(),
        record.resolved_at_unix_ms,
    ) {
        (None, None, None) => {
            record.bond.refunded_amount == zero
                && record.bond.slashed_amount == zero
                && record.bond.settled_at_unix_ms.is_none()
        }
        (Some(ModerationChallengeDecisionV1::Accepted), Some(_), Some(resolved_at)) => {
            resolved_at >= record.raised_at_unix_ms
                && resolved_at <= case.spec.challenge_resolution_deadline_unix_ms
                && record.bond.refunded_amount == record.bond.amount
                && record.bond.slashed_amount == zero
                && record.bond.settled_at_unix_ms == Some(resolved_at)
        }
        (Some(ModerationChallengeDecisionV1::Rejected), Some(_), Some(resolved_at)) => {
            resolved_at >= record.raised_at_unix_ms
                && resolved_at <= case.spec.challenge_resolution_deadline_unix_ms
                && record.bond.refunded_amount == rejected_refund
                && record.bond.slashed_amount == rejected_slash
                && record.bond.settled_at_unix_ms == Some(resolved_at)
        }
        (Some(ModerationChallengeDecisionV1::Expired), Some(_), Some(resolved_at)) => {
            resolved_at > case.spec.challenge_resolution_deadline_unix_ms
                && record.bond.refunded_amount == record.bond.amount
                && record.bond.slashed_amount == zero
                && record.bond.settled_at_unix_ms == Some(resolved_at)
        }
        _ => false,
    };
    if !resolution_valid {
        return Err(corrupt_state(
            "stored moderation challenge resolution is inconsistent",
        ));
    }
    Ok(Some(record))
}
fn read_outcome(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
) -> Result<Option<ModerationOutcomeRecordV1>, InstructionExecutionError> {
    read_outcome_with_current(world, case_id, round_id, None)
}
fn read_outcome_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationOutcomeRecordV1>, InstructionExecutionError> {
    read_outcome_with_current(world, case_id, round_id, Some(current))
}
fn read_outcome_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationOutcomeRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&outcome_key(case_id, round_id))
    else {
        return Ok(None);
    };
    let record: ModerationOutcomeRecordV1 =
        decode_state_with_current(bytes, "moderation outcome", current)?;
    let kind_consistent = match record.kind {
        ModerationOutcomeKindV1::Decided(choice) => {
            record.votes_total >= u32::from(record.quorum)
                && record.counts.winning_choice() == Some(choice)
        }
        ModerationOutcomeKindV1::Contested => {
            record.votes_total >= u32::from(record.quorum)
                && record.counts.winning_choice().is_none()
        }
        ModerationOutcomeKindV1::QuorumNotMet => record.votes_total < u32::from(record.quorum),
        ModerationOutcomeKindV1::Challenged => record.votes_total == 0 && record.no_show_count == 0,
    };
    if record.case_id != case_id
        || record.round_id != round_id
        || record.finalized_at_unix_ms == 0
        || record.quorum == 0
        || record.counts.checked_total() != Some(record.votes_total)
        || !kind_consistent
    {
        return Err(corrupt_state(
            "stored moderation outcome metadata is inconsistent",
        ));
    }
    Ok(Some(record))
}
#[allow(clippy::too_many_lines)]
fn read_no_show(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
) -> Result<Option<ModerationNoShowRecordV1>, InstructionExecutionError> {
    read_no_show_with_current(world, case_id, round_id, juror, None)
}
fn read_no_show_for_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ModerationNoShowRecordV1>, InstructionExecutionError> {
    read_no_show_with_current(world, case_id, round_id, juror, Some(current))
}
fn read_no_show_with_current(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
    juror: &AccountId,
    mut current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ModerationNoShowRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&no_show_key(case_id, round_id, juror))
    else {
        return Ok(None);
    };
    let record: ModerationNoShowRecordV1 =
        decode_state_with_current(bytes, "moderation no-show", current.as_deref_mut())?;
    if record.case_id != case_id
        || record.round_id != round_id
        || &record.juror != juror
        || record.penalty_points == 0
        || record.policy_digest == [0; 32]
        || record.recorded_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored moderation no-show metadata is inconsistent",
        ));
    }
    let mut transient_current = moderation_transient_current(current.as_deref())?;
    let case = read_case_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("stored moderation no-show has no authoritative case"))?;
    let outcome = read_outcome_with_current(world, case_id, round_id, transient_current.as_mut())?
        .ok_or_else(|| corrupt_state("stored moderation no-show has no terminal outcome"))?;
    let expected_penalty = match record.kind {
        ModerationNoShowKindV1::MissingCommit => case.policy.missing_commit_penalty_points,
        ModerationNoShowKindV1::UnrevealedCommit => case.policy.unrevealed_commit_penalty_points,
    };
    let mut ballot_current = moderation_transient_current(transient_current.as_ref())?;
    let has_commit =
        read_commit_with_current(world, case_id, round_id, juror, ballot_current.as_mut())?
            .is_some();
    let mut ballot_current = moderation_transient_current(transient_current.as_ref())?;
    let has_reveal =
        read_reveal_with_current(world, case_id, round_id, juror, ballot_current.as_mut())?
            .is_some();
    if case.status != ModerationCaseStatusV1::Finalized
        || !case.spec.jurors.iter().any(|candidate| candidate == juror)
        || outcome.no_show_count == 0
        || matches!(outcome.kind, ModerationOutcomeKindV1::Challenged)
        || record.policy_digest != case.spec.policy_digest
        || record.penalty_points != expected_penalty
        || has_reveal
        || matches!(record.kind, ModerationNoShowKindV1::MissingCommit) && has_commit
        || matches!(record.kind, ModerationNoShowKindV1::UnrevealedCommit) && !has_commit
    {
        return Err(corrupt_state(
            "stored moderation no-show does not match authoritative ballot state",
        ));
    }
    Ok(Some(record))
}
fn required_case(
    world: &impl WorldReadOnly,
    case_id: &str,
    round_id: &str,
) -> Result<ModerationCaseRecordV1, InstructionExecutionError> {
    read_case(world, case_id, round_id)?.ok_or_else(|| {
        invalid_parameter(format!(
            "moderation case `{case_id}` round `{round_id}` does not exist"
        ))
    })
}
fn ensure_case_open(case: &ModerationCaseRecordV1) -> Result<(), InstructionExecutionError> {
    if case.status == ModerationCaseStatusV1::Open {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "moderation case `{}` round `{}` is not open",
            case.spec.context.case_id, case.spec.round_id
        )))
    }
}
fn ensure_juror(
    case: &ModerationCaseRecordV1,
    juror: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if case.spec.jurors.iter().any(|candidate| candidate == juror) {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "account {juror} is not an eligible juror for moderation case `{}` round `{}`",
            case.spec.context.case_id, case.spec.round_id
        )))
    }
}
fn checked_inc(value: u64, label: &str) -> Result<u64, InstructionExecutionError> {
    value
        .checked_add(1)
        .ok_or_else(|| corrupt_state(format!("moderation {label} counter overflow")))
}
fn checked_add(value: u64, addend: u64, label: &str) -> Result<u64, InstructionExecutionError> {
    value
        .checked_add(addend)
        .ok_or_else(|| corrupt_state(format!("moderation {label} counter overflow")))
}
fn encode_status(status: &ModerationLedgerStatusV1) -> Result<Vec<u8>, InstructionExecutionError> {
    encode_state(status, "moderation status")
}
fn emit_moderation_ledger_event(
    state_transaction: &mut StateTransaction<'_, '_>,
    kind: SorafsModerationLedgerEventKind,
    case_id: Option<&str>,
    round_id: Option<&str>,
    authority: &AccountId,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    let committed_parent_height = u64::try_from(state_transaction.block_hashes().len())
        .map_err(|_| corrupt_state("committed moderation parent height does not fit into u64"))?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_state("moderation event target block height overflow"))?;
    let executing_block_height = state_transaction._curr_block.height().get();
    if target_block_height != executing_block_height {
        return Err(corrupt_state(format!(
            "moderation event target height {target_block_height} does not match executing block height {executing_block_height}"
        )));
    }
    let event = SorafsModerationLedgerEvent {
        kind,
        case_id: case_id.map(str::to_owned),
        round_id: round_id.map(str::to_owned),
        authority: authority.clone(),
        occurred_at_unix_ms: now,
    };
    let head = read_event_journal_head(state_transaction.world())?;
    ensure_no_event_after_head(state_transaction.world(), head)?;
    let (sequence, event_index) = match head {
        Some(head) => {
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("moderation event sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("moderation event block index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_state(
                        "moderation event target height regressed behind the journal head",
                    ));
                }
            };
            (sequence, event_index)
        }
        None => {
            let policy = read_policy(state_transaction.world())?
                .ok_or_else(|| corrupt_state("first moderation event has no active policy"))?;
            let status = read_status(state_transaction.world())?
                .ok_or_else(|| corrupt_state("first moderation event has no ledger status"))?;
            let counters_empty = status.appeal_intakes == 0
                && status.eligibility_proofs == 0
                && status.panel_selections == 0
                && status.assignment_acceptances == 0
                && status.failover_replacements == 0
                && status.failed_panel_formations == 0
                && status.open_cases == 0
                && status.finalized_cases == 0
                && status.commitments == 0
                && status.reveals == 0
                && status.challenges == 0
                && status.outcomes == 0
                && status.no_shows == 0;
            if kind != SorafsModerationLedgerEventKind::PolicyActivated
                || case_id.is_some()
                || round_id.is_some()
                || policy.policy.revision != 1
                || !counters_empty
            {
                return Err(corrupt_state(
                    "moderation event journal must begin with the initial policy activation",
                ));
            }
            (1, 0)
        }
    };
    let key = event_key(sequence);
    if state_transaction
        .world
        .smart_contract_state
        .get(&key)
        .is_some()
    {
        return Err(corrupt_state(
            "moderation event journal sequence already exists",
        ));
    }
    let record = ModerationPersistedEventV1 {
        sequence,
        target_block_height,
        event_index,
        event: event.clone(),
    };
    validate_persisted_event(&record, sequence)?;
    let next_head = ModerationEventJournalHeadV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    let encoded_record = encode_state(&record, "moderation committed event")?;
    let encoded_head = encode_state(&next_head, "moderation event journal head")?;
    state_transaction
        .world
        .smart_contract_state
        .insert(key, encoded_record);
    state_transaction
        .world
        .smart_contract_state
        .insert(event_journal_head_key().clone(), encoded_head);
    state_transaction
        .world
        .emit_events(Some(SorafsGatewayEvent::ModerationLedger(event)));
    Ok(())
}
impl Execute for SetSorafsModerationPolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_manage_permission(state_transaction, authority)?;
        self.policy.validate().map_err(|error| {
            invalid_parameter(format!("invalid SoraFS moderation policy: {error}"))
        })?;
        if self.policy.challenge_voting_asset_id != state_transaction.gov.voting_asset_id
            || self.policy.challenge_escrow_account != state_transaction.gov.bond_escrow_account
            || self.policy.challenge_slash_receiver_account
                != state_transaction.gov.slash_receiver_account
        {
            return Err(invalid_parameter(
                "moderation challenge policy must match the consensus governance voting asset and custody accounts",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let digest = self.policy.digest().map_err(|error| {
            invalid_parameter(format!("failed to digest moderation policy: {error}"))
        })?;
        let current = read_policy(state_transaction.world())?;
        let mut status = match current.as_ref() {
            None => {
                if self.policy.revision != 1 || self.policy.predecessor_policy_digest.is_some() {
                    return Err(invalid_parameter(
                        "first moderation policy must be revision one without a predecessor",
                    ));
                }
                if read_status(state_transaction.world())?.is_some() {
                    return Err(corrupt_state(
                        "moderation status exists without an active policy",
                    ));
                }
                ModerationLedgerStatusV1 {
                    updated_at_unix_ms: now,
                    ..ModerationLedgerStatusV1::default()
                }
            }
            Some(current) => {
                let status = status_for_mutation(state_transaction.world(), now)?;
                let expected_revision = current
                    .policy
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("moderation policy revision overflow"))?;
                if self.policy.revision != expected_revision {
                    return Err(invalid_parameter(format!(
                        "moderation policy revision {} must follow active revision {}",
                        self.policy.revision, current.policy.revision
                    )));
                }
                if self.policy.predecessor_policy_digest != Some(current.policy_digest) {
                    return Err(invalid_parameter(
                        "moderation policy predecessor does not match the active digest",
                    ));
                }
                status
            }
        };
        status.updated_at_unix_ms = now;
        let record = ModerationLedgerPolicyRecord {
            policy: self.policy,
            policy_digest: digest,
            activated_at_unix_ms: now,
            activated_by: authority.clone(),
        };
        let encoded_policy = encode_state(&record, "moderation policy")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(policy_key().clone(), encoded_policy);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::PolicyActivated,
            None,
            None,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for SubmitSorafsModerationAppeal {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        self.intake.validate().map_err(|error| {
            invalid_parameter(format!("invalid SoraFS moderation appeal intake: {error}"))
        })?;
        if &self.intake.appellant != authority {
            return Err(invalid_parameter(
                "moderation appeal appellant must equal the transaction authority",
            ));
        }
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "moderation appeal appellant account is not registered",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let policy = read_policy(state_transaction.world())?.ok_or_else(|| {
            invalid_parameter("authoritative moderation policy is not configured")
        })?;
        if self.intake.policy_digest != policy.policy_digest {
            return Err(invalid_parameter(
                "moderation appeal policy digest does not match the active policy",
            ));
        }
        if self.intake.panel_size > policy.policy.max_panel_size
            || self.intake.waitlist_size > policy.policy.max_waitlist_size
            || self.intake.exclusions.len() > usize::from(policy.policy.max_exclusions_per_case)
        {
            return Err(invalid_parameter(
                "moderation appeal panel, waitlist, or exclusion bounds exceed active policy",
            ));
        }
        if now >= self.intake.registration_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation appeal registration deadline must be later than intake",
            ));
        }
        let total_window = self
            .intake
            .reveal_deadline_unix_ms
            .checked_sub(now)
            .ok_or_else(|| invalid_parameter("moderation appeal reveal deadline is in the past"))?;
        if total_window > policy.policy.max_total_window_ms {
            return Err(invalid_parameter(format!(
                "moderation appeal total window {total_window} ms exceeds active policy limit {} ms",
                policy.policy.max_total_window_ms
            )));
        }
        if read_appeal(
            state_transaction.world(),
            &self.intake.case_id,
            &self.intake.round_id,
        )?
        .is_some()
            || read_case(
                state_transaction.world(),
                &self.intake.case_id,
                &self.intake.round_id,
            )?
            .is_some()
            || read_outcome(
                state_transaction.world(),
                &self.intake.case_id,
                &self.intake.round_id,
            )?
            .is_some()
        {
            return Err(invalid_parameter(format!(
                "moderation appeal `{}` round `{}` already exists",
                self.intake.case_id, self.intake.round_id
            )));
        }
        if read_appeal_deposit_binding(
            state_transaction.world(),
            self.intake.appeal_deposit_lock_digest,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "moderation appeal deposit lock was already consumed by another intake",
            ));
        }
        if read_appeal_proof_token_binding(
            state_transaction.world(),
            self.intake.proof_token_digest,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "moderation appeal proof token was already consumed by another intake",
            ));
        }
        let (pop_snapshot, _) = active_pop_snapshot(state_transaction, now)?;
        let pop_snapshot_digest = pop_snapshot.digest().map_err(|error| {
            invalid_parameter(format!("failed to digest active PoP snapshot: {error}"))
        })?;
        let intake_digest = self.intake.digest().map_err(|error| {
            invalid_parameter(format!(
                "failed to digest moderation appeal intake: {error}"
            ))
        })?;
        let mut anchor_schedule = read_sortition_anchor_schedule(state_transaction.world())?;
        insert_sortition_anchor_schedule_entry(
            &mut anchor_schedule,
            ModerationSortitionAnchorScheduleEntryV1 {
                registration_deadline_unix_ms: self.intake.registration_deadline_unix_ms,
                case_id: self.intake.case_id.clone(),
                round_id: self.intake.round_id.clone(),
                intake_digest,
            },
        )?;
        let record = ModerationAppealRecordV1 {
            intake: self.intake,
            intake_digest,
            policy: policy.policy,
            pop_snapshot,
            pop_snapshot_digest,
            status: ModerationAppealStatusV1::RegisteringJurors,
            submitted_by: authority.clone(),
            submitted_at_unix_ms: now,
            eligible_jurors: Vec::new(),
            sortition_anchor: None,
            selection: None,
            accepted_jurors: Vec::new(),
            replacements: Vec::new(),
            activated_at_unix_ms: None,
            finalized_at_unix_ms: None,
        };
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.appeal_intakes = checked_inc(status.appeal_intakes, "appeal-intake")?;
        status.updated_at_unix_ms = now;
        let key = appeal_key(&record.intake.case_id, &record.intake.round_id);
        let encoded_record = encode_state(&record, "moderation appeal")?;
        let deposit_binding = AppealDepositBindingStateV1 {
            deposit_lock_digest: record.intake.appeal_deposit_lock_digest,
            case_id: record.intake.case_id.clone(),
            round_id: record.intake.round_id.clone(),
            intake_digest: record.intake_digest,
        };
        let encoded_deposit_binding =
            encode_state(&deposit_binding, "moderation appeal deposit binding")?;
        let proof_token_binding = AppealProofTokenBindingStateV1 {
            proof_token_digest: record.intake.proof_token_digest,
            case_id: record.intake.case_id.clone(),
            round_id: record.intake.round_id.clone(),
            intake_digest: record.intake_digest,
        };
        let encoded_proof_token_binding = encode_state(
            &proof_token_binding,
            "moderation appeal proof-token binding",
        )?;
        let encoded_status = encode_status(&status)?;
        let encoded_anchor_schedule = encode_sortition_anchor_schedule(&anchor_schedule)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(key, encoded_record);
        state_transaction.world.smart_contract_state.insert(
            appeal_deposit_key(deposit_binding.deposit_lock_digest),
            encoded_deposit_binding,
        );
        state_transaction.world.smart_contract_state.insert(
            appeal_proof_token_key(proof_token_binding.proof_token_digest),
            encoded_proof_token_binding,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        state_transaction.world.smart_contract_state.insert(
            sortition_anchor_schedule_key().clone(),
            encoded_anchor_schedule,
        );
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::AppealSubmitted,
            Some(&record.intake.case_id),
            Some(&record.intake.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for RegisterSorafsModerationJurorEligibility {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "moderation juror eligibility authority is not a registered account",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::RegisteringJurors {
            return Err(invalid_parameter(
                "moderation juror eligibility registration is not in the registration phase",
            ));
        }
        if now > appeal.intake.registration_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation juror eligibility registration window is closed",
            ));
        }
        if appeal.eligible_jurors.len() >= usize::from(appeal.policy.max_candidate_pool_size) {
            return Err(invalid_parameter(
                "moderation juror candidate pool reached the active policy bound",
            ));
        }
        if appeal
            .intake
            .exclusions
            .binary_search_by(|candidate| candidate.to_string().cmp(&authority.to_string()))
            .is_ok()
        {
            return Err(invalid_parameter(
                "moderation juror is excluded by the immutable conflict list",
            ));
        }
        if read_eligibility(
            state_transaction.world(),
            &self.case_id,
            &self.round_id,
            authority,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "moderation juror eligibility was already registered",
            ));
        }
        let pinned = require_pinned_pop_snapshot(state_transaction, &appeal.pop_snapshot)?;
        let proof = decode_membership_proof(&self.membership_proof_payload)?;
        if read_nullifier(state_transaction.world(), proof.nullifier)?.is_some() {
            return Err(invalid_parameter(
                "moderation juror PoP membership proof nullifier was already consumed",
            ));
        }
        let now_epoch = now / 1_000;
        let challenge =
            sorafs_moderation_pop_challenge_v1(appeal.intake_digest, appeal.pop_snapshot_digest);
        let verifier_context = sorafs_moderation_pop_verifier_context_v1(appeal.intake_digest);
        let presentation_binding =
            sorafs_moderation_pop_presentation_binding_v1(appeal.intake_digest, authority)
                .map_err(|error| {
                    invalid_parameter(format!("moderation juror binding encoding failed: {error}"))
                })?;
        verify_pop_membership_proof_v1(
            &proof,
            &pinned.root,
            &pinned.revocations,
            sorafs_manifest::pop_credentials::PopMembershipPresentationV1 {
                challenge_digest: challenge,
                verifier_context: &verifier_context,
                presentation_binding_digest: presentation_binding,
            },
            now_epoch,
            &[],
        )
        .map_err(|error| {
            invalid_parameter(format!(
                "moderation juror PoP membership proof failed: {error}"
            ))
        })?;
        let class = eligibility_class(proof.eligibility_class);
        if class == ModerationJurorEligibilityClassV1::Observer {
            return Err(invalid_parameter(
                "observer-only PoP credentials cannot enter a moderation voting panel",
            ));
        }
        let reveal_deadline_epoch = ceil_unix_ms_to_epoch(appeal.intake.reveal_deadline_unix_ms)?;
        if proof.expires_at_epoch <= reveal_deadline_epoch {
            return Err(invalid_parameter(
                "moderation juror PoP credential expires before the reveal deadline",
            ));
        }
        let mut proof_hasher = blake3::Hasher::new();
        proof_hasher.update(PROOF_DIGEST_DOMAIN_V1);
        proof_hasher.update(&self.membership_proof_payload);
        let record = ModerationJurorEligibilityRecordV1 {
            case_id: self.case_id,
            round_id: self.round_id,
            juror: authority.clone(),
            eligibility_class: class,
            proof_digest: *proof_hasher.finalize().as_bytes(),
            nullifier: proof.nullifier,
            pop_snapshot_digest: appeal.pop_snapshot_digest,
            credential_expires_at_epoch: proof.expires_at_epoch,
            registered_at_unix_ms: now,
        };
        let account = authority.to_string();
        let position = appeal
            .eligible_jurors
            .binary_search_by(|candidate| candidate.to_string().cmp(&account))
            .unwrap_or_else(|position| position);
        appeal.eligible_jurors.insert(position, authority.clone());
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.eligibility_proofs = checked_inc(status.eligibility_proofs, "eligibility-proof")?;
        status.updated_at_unix_ms = now;
        let encoded_record = encode_state(&record, "moderation juror eligibility")?;
        let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
        let encoded_status = encode_status(&status)?;
        state_transaction.world.smart_contract_state.insert(
            eligibility_key(&record.case_id, &record.round_id, authority),
            encoded_record.clone(),
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(nullifier_key(record.nullifier), encoded_record);
        state_transaction.world.smart_contract_state.insert(
            appeal_key(&record.case_id, &record.round_id),
            encoded_appeal,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::EligibilityRegistered,
            Some(&record.case_id),
            Some(&record.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for FinalizeSorafsModerationSortition {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_manage_permission(state_transaction, authority)?;
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        if self.proposed_jurors.len() > usize::from(MODERATION_LEDGER_MAX_PANEL_SIZE_V1)
            || self.proposed_waitlist.len() > usize::from(MODERATION_LEDGER_MAX_WAITLIST_SIZE_V1)
        {
            return Err(invalid_parameter(
                "proposed moderation roster or waitlist exceeds hard bounds",
            ));
        }
        if self.citizen_snapshot_digest == [0; 32] || self.randomness_anchor == [0; 32] {
            return Err(invalid_parameter(
                "moderation sortition snapshot and randomness anchors must be non-zero",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::RegisteringJurors {
            return Err(invalid_parameter(
                "moderation appeal sortition is not in the registration phase",
            ));
        }
        if authority == &appeal.intake.appellant {
            return Err(invalid_parameter(
                "moderation appeal appellant cannot finalize its own panel sortition",
            ));
        }
        if now <= appeal.intake.registration_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation appeal registration must close before sortition",
            ));
        }
        if now > appeal.intake.acceptance_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation appeal sortition missed the acceptance window",
            ));
        }
        if self.citizen_snapshot_digest != appeal.pop_snapshot_digest {
            return Err(invalid_parameter(
                "moderation sortition citizen snapshot digest does not match the admitted appeal",
            ));
        }
        require_pinned_pop_snapshot(state_transaction, &appeal.pop_snapshot)?;
        let mut candidates = Vec::with_capacity(appeal.eligible_jurors.len());
        for juror in &appeal.eligible_jurors {
            candidates.push(
                read_eligibility(
                    state_transaction.world(),
                    &self.case_id,
                    &self.round_id,
                    juror,
                )?
                .ok_or_else(|| {
                    corrupt_state("appeal candidate index references missing eligibility")
                })?,
            );
        }
        let anchor = appeal.sortition_anchor.ok_or_else(|| {
            invalid_parameter(
                "moderation sortition anchor has not reached committed post-registration state",
            )
        })?;
        let executing_height = state_transaction._curr_block.height().get();
        if executing_height <= anchor.block_height {
            return Err(invalid_parameter(
                "moderation sortition must execute after its pinned anchor block commits",
            ));
        }
        let anchor_index =
            usize::try_from(anchor.block_height.saturating_sub(1)).map_err(|_| {
                corrupt_state("moderation sortition anchor height exceeds local index bounds")
            })?;
        let committed_anchor = state_transaction
            .block_hashes()
            .get(anchor_index)
            .map(|hash| *hash.as_ref())
            .ok_or_else(|| {
                corrupt_state(
                    "moderation sortition anchor height is absent from committed block history",
                )
            })?;
        if committed_anchor != anchor.block_hash {
            return Err(corrupt_state(
                "moderation sortition anchor differs from committed block history",
            ));
        }
        if self.randomness_anchor != anchor.block_hash {
            return Err(invalid_parameter(
                "moderation sortition randomness anchor does not match the consensus-pinned first post-registration block",
            ));
        }
        let randomness_anchor = anchor.block_hash;
        let selection = sorafs_moderation_select_panel_v1(
            appeal.intake_digest,
            appeal.pop_snapshot_digest,
            randomness_anchor,
            &candidates,
            appeal.intake.panel_size,
            appeal.intake.waitlist_size,
            appeal.intake.quorum,
        );
        let (jurors, waitlist, seed_digest, sortition_digest) = match selection {
            Ok(selection) => selection,
            Err(ModerationSortitionError::InsufficientEligiblePool { .. }) => {
                if !self.proposed_jurors.is_empty() || !self.proposed_waitlist.is_empty() {
                    return Err(invalid_parameter(
                        "insufficient moderation pool cannot accept a proposed roster",
                    ));
                }
                appeal.status = ModerationAppealStatusV1::InsufficientEligiblePool;
                let mut status = status_for_mutation(state_transaction.world(), now)?;
                status.failed_panel_formations =
                    checked_inc(status.failed_panel_formations, "failed-panel-formation")?;
                status.updated_at_unix_ms = now;
                let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
                let encoded_status = encode_status(&status)?;
                state_transaction
                    .world
                    .smart_contract_state
                    .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
                state_transaction
                    .world
                    .smart_contract_state
                    .insert(status_key().clone(), encoded_status);
                emit_moderation_ledger_event(
                    state_transaction,
                    SorafsModerationLedgerEventKind::SortitionFailed,
                    Some(&self.case_id),
                    Some(&self.round_id),
                    authority,
                    now,
                )?;
                return Ok(());
            }
            Err(error) => {
                return Err(corrupt_state(format!(
                    "stored moderation eligibility cannot be sorted: {error}"
                )));
            }
        };
        if !unique_account_list(&self.proposed_jurors)
            || !unique_account_list(&self.proposed_waitlist)
            || self
                .proposed_jurors
                .iter()
                .any(|juror| self.proposed_waitlist.contains(juror))
            || self.proposed_jurors != jurors
            || self.proposed_waitlist != waitlist
        {
            return Err(invalid_parameter(
                "proposed moderation roster is duplicated, biased, or differs from deterministic sortition",
            ));
        }
        appeal.selection = Some(ModerationPanelSelectionV1 {
            randomness_anchor,
            seed_digest,
            jurors,
            waitlist,
            sortition_digest,
            selected_at_unix_ms: now,
            selected_by: authority.clone(),
        });
        appeal.status = ModerationAppealStatusV1::AwaitingAcceptance;
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.panel_selections = checked_inc(status.panel_selections, "panel-selection")?;
        status.updated_at_unix_ms = now;
        let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::SortitionFinalized,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for AcceptSorafsModerationJurorAssignment {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        let now = block_time_ms(state_transaction)?;
        let mut appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::AwaitingAcceptance {
            return Err(invalid_parameter(
                "moderation juror assignment is not in the acceptance phase",
            ));
        }
        if now > appeal.intake.acceptance_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation juror assignment acceptance window is closed",
            ));
        }
        require_pinned_pop_snapshot(state_transaction, &appeal.pop_snapshot)?;
        let selection = appeal
            .selection
            .as_ref()
            .ok_or_else(|| corrupt_state("acceptance-phase appeal has no panel selection"))?;
        if self.sortition_digest != selection.sortition_digest {
            return Err(invalid_parameter(
                "moderation assignment sortition digest mismatch",
            ));
        }
        if !selection.jurors.contains(authority) {
            return Err(invalid_parameter(
                "only a selected primary juror can accept this assignment",
            ));
        }
        let account = authority.to_string();
        let position = match appeal
            .accepted_jurors
            .binary_search_by(|candidate| candidate.to_string().cmp(&account))
        {
            Ok(_) => {
                return Err(invalid_parameter(
                    "moderation juror assignment was already accepted",
                ));
            }
            Err(position) => position,
        };
        appeal.accepted_jurors.insert(position, authority.clone());
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.assignment_acceptances =
            checked_inc(status.assignment_acceptances, "assignment-acceptance")?;
        status.updated_at_unix_ms = now;
        let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::AssignmentAccepted,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for ActivateSorafsModerationCase {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_manage_permission(state_transaction, authority)?;
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        let now = block_time_ms(state_transaction)?;
        let mut appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::AwaitingAcceptance {
            return Err(invalid_parameter(
                "moderation case activation is not in the acceptance phase",
            ));
        }
        if now <= appeal.intake.acceptance_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation assignment acceptance must close before activation",
            ));
        }
        if now >= appeal.intake.commit_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation case activation missed the commit window",
            ));
        }
        require_pinned_pop_snapshot(state_transaction, &appeal.pop_snapshot)?;
        let selection = appeal
            .selection
            .as_ref()
            .ok_or_else(|| corrupt_state("activation-phase appeal has no panel selection"))?;
        if self.sortition_digest != selection.sortition_digest {
            return Err(invalid_parameter(
                "moderation activation sortition digest mismatch",
            ));
        }
        if read_case(state_transaction.world(), &self.case_id, &self.round_id)?.is_some() {
            return Err(corrupt_state(
                "moderation ballot exists before appeal activation",
            ));
        }
        let mut waitlist = selection.waitlist.iter();
        let mut jurors = Vec::with_capacity(selection.jurors.len());
        let mut replacements = Vec::new();
        for primary in &selection.jurors {
            if appeal.accepted_jurors.contains(primary) {
                jurors.push(primary.clone());
                continue;
            }
            let Some(replacement) = waitlist.next() else {
                appeal.status = ModerationAppealStatusV1::FailoverExhausted;
                appeal.replacements = replacements;
                let mut status = status_for_mutation(state_transaction.world(), now)?;
                status.failed_panel_formations =
                    checked_inc(status.failed_panel_formations, "failed-panel-formation")?;
                status.updated_at_unix_ms = now;
                let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
                let encoded_status = encode_status(&status)?;
                state_transaction
                    .world
                    .smart_contract_state
                    .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
                state_transaction
                    .world
                    .smart_contract_state
                    .insert(status_key().clone(), encoded_status);
                emit_moderation_ledger_event(
                    state_transaction,
                    SorafsModerationLedgerEventKind::CaseActivationFailed,
                    Some(&self.case_id),
                    Some(&self.round_id),
                    authority,
                    now,
                )?;
                return Ok(());
            };
            jurors.push(replacement.clone());
            replacements.push(ModerationJurorReplacementV1 {
                absent_juror: primary.clone(),
                replacement_juror: replacement.clone(),
            });
        }
        if !unique_account_list(&jurors) || jurors.len() != usize::from(appeal.intake.panel_size) {
            return Err(corrupt_state(
                "deterministic moderation failover produced an invalid roster",
            ));
        }
        let context = SoraFsModerationBallotContextV1 {
            version: SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
            case_id: appeal.intake.case_id.clone(),
            evidence_bundle_digest: appeal.intake.evidence_bundle_digest,
            appeal_finance_config_version: appeal.intake.appeal_finance_config_version.clone(),
            panel_roster_hash: sorafs_moderation_panel_roster_hash_v1(
                &jurors,
                appeal.intake.quorum,
            ),
            policy_reference: appeal.intake.policy_reference.clone(),
            evidence_uri: appeal.intake.evidence_uri.clone(),
        };
        let spec = ModerationCaseSpecV1 {
            version: iroha_data_model::sorafs::moderation_ledger::MODERATION_LEDGER_CASE_VERSION_V1,
            context,
            round_id: appeal.intake.round_id.clone(),
            jurors,
            quorum: appeal.intake.quorum,
            commit_deadline_unix_ms: appeal.intake.commit_deadline_unix_ms,
            challenge_submission_deadline_unix_ms: appeal
                .intake
                .challenge_submission_deadline_unix_ms,
            challenge_resolution_deadline_unix_ms: appeal
                .intake
                .challenge_resolution_deadline_unix_ms,
            reveal_deadline_unix_ms: appeal.intake.reveal_deadline_unix_ms,
            policy_digest: appeal.intake.policy_digest,
        };
        spec.validate().map_err(|error| {
            corrupt_state(format!("deterministic moderation case is invalid: {error}"))
        })?;
        let case = ModerationCaseRecordV1 {
            spec,
            policy: appeal.policy.clone(),
            status: ModerationCaseStatusV1::Open,
            opened_at_unix_ms: now,
            opened_by: authority.clone(),
            commitment_count: 0,
            reveal_count: 0,
            challenge_count: 0,
            challenge_ids: Vec::new(),
            pending_challenge_count: 0,
            accepted_challenge_count: 0,
            expired_challenge_count: 0,
        };
        appeal.status = ModerationAppealStatusV1::BallotOpen;
        appeal.replacements = replacements;
        appeal.activated_at_unix_ms = Some(now);
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.open_cases = checked_inc(status.open_cases, "open-case")?;
        let replacement_count = u64::try_from(appeal.replacements.len())
            .map_err(|_| corrupt_state("moderation failover replacement count does not fit u64"))?;
        status.failover_replacements = checked_add(
            status.failover_replacements,
            replacement_count,
            "failover-replacement",
        )?;
        status.updated_at_unix_ms = now;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key(&self.case_id, &self.round_id), encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::CaseActivated,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for SubmitSorafsModerationCommit {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let mut commit: SoraFsModerationBallotCommitV1 =
            decode_payload(&self.commit_payload, "moderation commit")?;
        commit.validate().map_err(|error| {
            invalid_parameter(format!("invalid moderation commitment: {error}"))
        })?;
        if commit.commitment_blake2b_256 == [0; 32] {
            return Err(invalid_parameter(
                "moderation commitment digest must be non-zero",
            ));
        }
        if commit.juror_id != authority.to_string() {
            return Err(invalid_parameter(
                "moderation commitment juror must equal the transaction authority",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut case = required_case(
            state_transaction.world(),
            &commit.context.case_id,
            &commit.round_id,
        )?;
        ensure_case_open(&case)?;
        ensure_juror(&case, authority)?;
        if commit.context != case.spec.context {
            return Err(invalid_parameter(
                "moderation commitment context does not match the authoritative case",
            ));
        }
        if now > case.spec.commit_deadline_unix_ms {
            return Err(invalid_parameter(format!(
                "moderation commitment phase closed at {}",
                case.spec.commit_deadline_unix_ms
            )));
        }
        if read_commit(
            state_transaction.world(),
            &commit.context.case_id,
            &commit.round_id,
            authority,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "duplicate moderation commitment for this juror and round",
            ));
        }
        commit.committed_at_unix_ms = now;
        let canonical_commit = encode_payload(&commit, "moderation commit")?;
        let record = ModerationCommitRecordV1 {
            case_id: commit.context.case_id.clone(),
            round_id: commit.round_id.clone(),
            juror: authority.clone(),
            canonical_commit,
            accepted_at_unix_ms: now,
        };
        case.commitment_count = case
            .commitment_count
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation case commitment counter overflow"))?;
        let roster_size = u32::try_from(case.spec.jurors.len())
            .map_err(|_| corrupt_state("moderation roster length does not fit u32"))?;
        if case.commitment_count > roster_size {
            return Err(corrupt_state(
                "moderation case commitment counter exceeds roster",
            ));
        }
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.commitments = checked_inc(status.commitments, "commitment")?;
        status.updated_at_unix_ms = now;
        let record_key = commit_key(&record.case_id, &record.round_id, authority);
        let case_key = case_key(&record.case_id, &record.round_id);
        let encoded_record = encode_state(&record, "moderation commit")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(record_key, encoded_record);
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key, encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::CommitAccepted,
            Some(&record.case_id),
            Some(&record.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for RaiseSorafsModerationChallenge {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        if !is_canonical_moderation_identifier_v1(&self.challenge_id) {
            return Err(invalid_parameter(
                "moderation challenge challenge_id is not bounded canonical ASCII",
            ));
        }
        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(invalid_parameter(
                "moderation challenger authority is not a registered account",
            ));
        }
        if self.evidence_digest == [0; 32] {
            return Err(invalid_parameter(
                "moderation challenge evidence digest must be non-zero",
            ));
        }
        validate_challenge_reason(&self.reason)?;
        if self.kind.requires_target_juror() && self.target_juror.is_none() {
            return Err(invalid_parameter(
                "juror-scoped moderation challenge requires target_juror",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut case = required_case(state_transaction.world(), &self.case_id, &self.round_id)?;
        ensure_case_open(&case)?;
        if now <= case.spec.commit_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation challenge phase has not opened",
            ));
        }
        if now > case.spec.challenge_submission_deadline_unix_ms {
            return Err(invalid_parameter("moderation challenge phase is closed"));
        }
        if case.reveal_count != 0 {
            return Err(corrupt_state(
                "moderation case has reveals before challenge phase closure",
            ));
        }
        if let Some(target) = self.target_juror.as_ref() {
            ensure_juror(&case, target)?;
        }
        if read_challenge(
            state_transaction.world(),
            &self.case_id,
            &self.round_id,
            &self.challenge_id,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "duplicate moderation challenge id for this case and round",
            ));
        }
        for existing_id in &case.challenge_ids {
            let existing = read_challenge(
                state_transaction.world(),
                &self.case_id,
                &self.round_id,
                existing_id,
            )?
            .ok_or_else(|| {
                corrupt_state("moderation case challenge index references a missing record")
            })?;
            if existing.challenger == *authority {
                return Err(invalid_parameter(
                    "moderation challenger already submitted a challenge for this case and round",
                ));
            }
            if existing.evidence_digest == self.evidence_digest {
                return Err(invalid_parameter(
                    "duplicate moderation challenge evidence for this case and round",
                ));
            }
        }
        if case.challenge_count >= u32::from(case.policy.max_challenges_per_case) {
            return Err(invalid_parameter(format!(
                "moderation case reached active policy challenge limit {}",
                case.policy.max_challenges_per_case
            )));
        }
        case.challenge_count = case
            .challenge_count
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation case challenge counter overflow"))?;
        let challenge_position = case
            .challenge_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(&self.challenge_id))
            .map_or_else(
                |position| position,
                |_| unreachable!("duplicate challenge record check keeps id index unique"),
            );
        case.challenge_ids
            .insert(challenge_position, self.challenge_id.clone());
        case.pending_challenge_count = case
            .pending_challenge_count
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation pending-challenge counter overflow"))?;
        let bond = lock_moderation_challenge_bond(
            state_transaction,
            &case.policy,
            authority,
            &self.case_id,
            &self.round_id,
            &self.challenge_id,
        )?;
        let record = ModerationChallengeRecordV1 {
            case_id: self.case_id,
            round_id: self.round_id,
            challenge_id: self.challenge_id,
            challenger: authority.clone(),
            kind: self.kind,
            target_juror: self.target_juror,
            evidence_digest: self.evidence_digest,
            reason: self.reason,
            raised_at_unix_ms: now,
            bond,
            decision: None,
            resolved_by: None,
            resolved_at_unix_ms: None,
        };
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.challenges = checked_inc(status.challenges, "challenge")?;
        status.updated_at_unix_ms = now;
        let record_key = challenge_key(&record.case_id, &record.round_id, &record.challenge_id);
        let case_key = case_key(&record.case_id, &record.round_id);
        let encoded_record = encode_state(&record, "moderation challenge")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(record_key, encoded_record);
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key, encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::ChallengeRaised,
            Some(&record.case_id),
            Some(&record.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for ResolveSorafsModerationChallenge {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_manage_permission(state_transaction, authority)?;
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        if !is_canonical_moderation_identifier_v1(&self.challenge_id) {
            return Err(invalid_parameter(
                "moderation challenge challenge_id is not bounded canonical ASCII",
            ));
        }
        if self.decision == ModerationChallengeDecisionV1::Expired {
            return Err(invalid_parameter(
                "expired moderation challenges are derived after the resolution grace",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::BallotOpen {
            return Err(invalid_parameter(
                "moderation appeal is not in the open-ballot phase",
            ));
        }
        let mut case = required_case(state_transaction.world(), &self.case_id, &self.round_id)?;
        if case.status == ModerationCaseStatusV1::Finalized {
            return Err(invalid_parameter(
                "finalized moderation case cannot resolve challenges",
            ));
        }
        if now > case.spec.challenge_resolution_deadline_unix_ms {
            return Err(invalid_parameter(
                "moderation challenge resolution window is closed",
            ));
        }
        if case.reveal_count != 0 {
            return Err(invalid_parameter(
                "moderation challenge cannot be resolved after reveals were accepted",
            ));
        }
        let mut record = read_challenge(
            state_transaction.world(),
            &self.case_id,
            &self.round_id,
            &self.challenge_id,
        )?
        .ok_or_else(|| invalid_parameter("moderation challenge does not exist"))?;
        if record.decision.is_some() {
            return Err(invalid_parameter(
                "moderation challenge is already resolved",
            ));
        }
        case.pending_challenge_count = case
            .pending_challenge_count
            .checked_sub(1)
            .ok_or_else(|| corrupt_state("moderation pending-challenge counter underflow"))?;
        if self.decision == ModerationChallengeDecisionV1::Accepted {
            case.accepted_challenge_count = case
                .accepted_challenge_count
                .checked_add(1)
                .ok_or_else(|| corrupt_state("moderation accepted-challenge counter overflow"))?;
            case.status = ModerationCaseStatusV1::Challenged;
        }
        settle_moderation_challenge_bond(
            state_transaction,
            &case.policy,
            &mut record,
            self.decision,
            now,
        )?;
        record.decision = Some(self.decision);
        record.resolved_by = Some(authority.clone());
        record.resolved_at_unix_ms = Some(now);
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.updated_at_unix_ms = now;
        let encoded_record = encode_state(&record, "moderation challenge")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_status = encode_status(&status)?;
        state_transaction.world.smart_contract_state.insert(
            challenge_key(&self.case_id, &self.round_id, &self.challenge_id),
            encoded_record,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key(&self.case_id, &self.round_id), encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::ChallengeResolved,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
fn expire_pending_moderation_challenge(
    state_transaction: &mut StateTransaction<'_, '_>,
    case: &mut ModerationCaseRecordV1,
    mut record: ModerationChallengeRecordV1,
    authority: &AccountId,
    now: u64,
) -> Result<ModerationChallengeRecordV1, InstructionExecutionError> {
    if now <= case.spec.challenge_resolution_deadline_unix_ms {
        return Err(invalid_parameter(
            "moderation challenge resolution grace has not elapsed",
        ));
    }
    if record.decision.is_some() {
        return Err(invalid_parameter(
            "only a pending moderation challenge may expire",
        ));
    }
    case.pending_challenge_count = case
        .pending_challenge_count
        .checked_sub(1)
        .ok_or_else(|| corrupt_state("moderation pending-challenge counter underflow"))?;
    case.expired_challenge_count = case
        .expired_challenge_count
        .checked_add(1)
        .ok_or_else(|| corrupt_state("moderation expired-challenge counter overflow"))?;
    settle_moderation_challenge_bond(
        state_transaction,
        &case.policy,
        &mut record,
        ModerationChallengeDecisionV1::Expired,
        now,
    )?;
    record.decision = Some(ModerationChallengeDecisionV1::Expired);
    record.resolved_by = Some(authority.clone());
    record.resolved_at_unix_ms = Some(now);
    Ok(record)
}
impl Execute for ExpireSorafsModerationChallenge {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        if !is_canonical_moderation_identifier_v1(&self.challenge_id) {
            return Err(invalid_parameter(
                "moderation challenge challenge_id is not bounded canonical ASCII",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut case = required_case(state_transaction.world(), &self.case_id, &self.round_id)?;
        let record = read_challenge(
            state_transaction.world(),
            &self.case_id,
            &self.round_id,
            &self.challenge_id,
        )?
        .ok_or_else(|| invalid_parameter("moderation challenge does not exist"))?;
        match record.decision {
            Some(ModerationChallengeDecisionV1::Expired) => return Ok(()),
            Some(_) => {
                return Err(invalid_parameter(
                    "resolved moderation challenge cannot be expired",
                ));
            }
            None => {}
        }
        if case.status == ModerationCaseStatusV1::Finalized {
            return Err(corrupt_state(
                "finalized moderation case retains a pending challenge",
            ));
        }
        let record = expire_pending_moderation_challenge(
            state_transaction,
            &mut case,
            record,
            authority,
            now,
        )?;
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.updated_at_unix_ms = now;
        let encoded_record = encode_state(&record, "expired moderation challenge")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_status = encode_status(&status)?;
        state_transaction.world.smart_contract_state.insert(
            challenge_key(&self.case_id, &self.round_id, &self.challenge_id),
            encoded_record,
        );
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key(&self.case_id, &self.round_id), encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::ChallengeResolved,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for SubmitSorafsModerationReveal {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let mut reveal: SoraFsModerationBallotRevealV1 =
            decode_payload(&self.reveal_payload, "moderation reveal")?;
        reveal
            .validate()
            .map_err(|error| invalid_parameter(format!("invalid moderation reveal: {error}")))?;
        if reveal.nonce.len() > MODERATION_LEDGER_MAX_NONCE_BYTES_V1 {
            return Err(invalid_parameter(format!(
                "moderation reveal nonce exceeds {MODERATION_LEDGER_MAX_NONCE_BYTES_V1} bytes"
            )));
        }
        if reveal.juror_id != authority.to_string() {
            return Err(invalid_parameter(
                "moderation reveal juror must equal the transaction authority",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let mut case = required_case(
            state_transaction.world(),
            &reveal.context.case_id,
            &reveal.round_id,
        )?;
        ensure_case_open(&case)?;
        ensure_juror(&case, authority)?;
        if reveal.context != case.spec.context {
            return Err(invalid_parameter(
                "moderation reveal context does not match the authoritative case",
            ));
        }
        if now <= case.spec.challenge_resolution_deadline_unix_ms {
            return Err(invalid_parameter("moderation reveal phase has not opened"));
        }
        if now > case.spec.reveal_deadline_unix_ms {
            return Err(invalid_parameter("moderation reveal phase is closed"));
        }
        if case.accepted_challenge_count != 0 {
            return Err(invalid_parameter(
                "accepted moderation challenge blocks reveals",
            ));
        }
        let commit_record = read_commit(
            state_transaction.world(),
            &reveal.context.case_id,
            &reveal.round_id,
            authority,
        )?
        .ok_or_else(|| invalid_parameter("moderation reveal has no accepted commitment"))?;
        if read_reveal(
            state_transaction.world(),
            &reveal.context.case_id,
            &reveal.round_id,
            authority,
        )?
        .is_some()
        {
            return Err(invalid_parameter(
                "duplicate moderation reveal for this juror and round",
            ));
        }
        let commit: SoraFsModerationBallotCommitV1 =
            decode_payload(&commit_record.canonical_commit, "stored moderation commit")
                .map_err(|error| corrupt_state(error.to_string()))?;
        commit.verify_reveal(&reveal).map_err(|error| {
            invalid_parameter(format!(
                "moderation reveal does not match commitment: {error}"
            ))
        })?;
        reveal.revealed_at_unix_ms = now;
        let canonical_reveal = encode_payload(&reveal, "moderation reveal")?;
        let record = ModerationRevealRecordV1 {
            case_id: reveal.context.case_id.clone(),
            round_id: reveal.round_id.clone(),
            juror: authority.clone(),
            canonical_reveal,
            accepted_at_unix_ms: now,
        };
        case.reveal_count = case
            .reveal_count
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation case reveal counter overflow"))?;
        if case.reveal_count > case.commitment_count {
            return Err(corrupt_state(
                "moderation case reveal counter exceeds commitments",
            ));
        }
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.reveals = checked_inc(status.reveals, "reveal")?;
        status.updated_at_unix_ms = now;
        let record_key = reveal_key(&record.case_id, &record.round_id, authority);
        let case_key = case_key(&record.case_id, &record.round_id);
        let encoded_record = encode_state(&record, "moderation reveal")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_status = encode_status(&status)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(record_key, encoded_record);
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key, encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::RevealAccepted,
            Some(&record.case_id),
            Some(&record.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
fn increment_choice(
    counts: &mut ModerationVoteCountsV1,
    choice: SoraFsModerationVoteChoice,
) -> Result<(), InstructionExecutionError> {
    let counter = match choice {
        SoraFsModerationVoteChoice::Uphold => &mut counts.uphold,
        SoraFsModerationVoteChoice::Overturn => &mut counts.overturn,
        SoraFsModerationVoteChoice::Modify => &mut counts.modify,
        SoraFsModerationVoteChoice::Escalate => &mut counts.escalate,
    };
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| corrupt_state("moderation vote counter overflow"))?;
    Ok(())
}
impl Execute for FinalizeSorafsModerationCase {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_manage_permission(state_transaction, authority)?;
        validate_lookup_identifiers(&self.case_id, &self.round_id)?;
        let now = block_time_ms(state_transaction)?;
        let mut appeal = required_appeal(state_transaction.world(), &self.case_id, &self.round_id)?;
        if appeal.status != ModerationAppealStatusV1::BallotOpen {
            return Err(invalid_parameter(
                "moderation appeal is not in the open-ballot phase",
            ));
        }
        let mut case = required_case(state_transaction.world(), &self.case_id, &self.round_id)?;
        if case.status == ModerationCaseStatusV1::Finalized
            || read_outcome(state_transaction.world(), &self.case_id, &self.round_id)?.is_some()
        {
            return Err(invalid_parameter("moderation case is already finalized"));
        }
        if now <= case.spec.reveal_deadline_unix_ms {
            return Err(invalid_parameter(format!(
                "moderation case cannot finalize until after reveal deadline {}",
                case.spec.reveal_deadline_unix_ms
            )));
        }
        if case.pending_challenge_count != 0 {
            for challenge_id in case.challenge_ids.clone() {
                let challenge = read_challenge(
                    state_transaction.world(),
                    &self.case_id,
                    &self.round_id,
                    &challenge_id,
                )?
                .ok_or_else(|| {
                    corrupt_state("moderation case challenge index references a missing record")
                })?;
                if challenge.decision.is_some() {
                    continue;
                }
                let challenge = expire_pending_moderation_challenge(
                    state_transaction,
                    &mut case,
                    challenge,
                    authority,
                    now,
                )?;
                // Stage each successful expiry in the transaction overlay
                // before settling the next indexed challenge. Aggregate bond
                // liability then observes the prior record as settled, while
                // any later failure still discards every staged record and
                // balance movement with the enclosing transaction.
                let encoded_challenge = encode_state(&challenge, "expired moderation challenge")?;
                state_transaction.world.smart_contract_state.insert(
                    challenge_key(&self.case_id, &self.round_id, &challenge_id),
                    encoded_challenge,
                );
            }
            if case.pending_challenge_count != 0 {
                return Err(corrupt_state(
                    "moderation pending-challenge counter disagrees with indexed records",
                ));
            }
        }
        let challenged = case.accepted_challenge_count != 0;
        let mut counts = ModerationVoteCountsV1::default();
        let mut no_shows = Vec::new();
        if !challenged {
            for juror in &case.spec.jurors {
                if let Some(reveal_record) = read_reveal(
                    state_transaction.world(),
                    &self.case_id,
                    &self.round_id,
                    juror,
                )? {
                    let reveal: SoraFsModerationBallotRevealV1 =
                        decode_payload(&reveal_record.canonical_reveal, "stored moderation reveal")
                            .map_err(|error| corrupt_state(error.to_string()))?;
                    increment_choice(&mut counts, reveal.choice)?;
                    continue;
                }
                let (kind, penalty_points) = if read_commit(
                    state_transaction.world(),
                    &self.case_id,
                    &self.round_id,
                    juror,
                )?
                .is_some()
                {
                    (
                        ModerationNoShowKindV1::UnrevealedCommit,
                        case.policy.unrevealed_commit_penalty_points,
                    )
                } else {
                    (
                        ModerationNoShowKindV1::MissingCommit,
                        case.policy.missing_commit_penalty_points,
                    )
                };
                no_shows.push(ModerationNoShowRecordV1 {
                    case_id: self.case_id.clone(),
                    round_id: self.round_id.clone(),
                    juror: juror.clone(),
                    kind,
                    penalty_points,
                    policy_digest: case.spec.policy_digest,
                    recorded_at_unix_ms: now,
                });
            }
        }
        let votes_total = counts
            .checked_total()
            .ok_or_else(|| corrupt_state("moderation vote-total overflow"))?;
        if votes_total != case.reveal_count {
            return Err(corrupt_state(format!(
                "moderation case reveal counter {} does not match stored reveal total {votes_total}",
                case.reveal_count
            )));
        }
        let kind = if challenged {
            if votes_total != 0 || !no_shows.is_empty() {
                return Err(corrupt_state(
                    "challenged moderation case unexpectedly contains tally material",
                ));
            }
            ModerationOutcomeKindV1::Challenged
        } else if votes_total < u32::from(case.spec.quorum) {
            ModerationOutcomeKindV1::QuorumNotMet
        } else if let Some(choice) = counts.winning_choice() {
            ModerationOutcomeKindV1::Decided(choice)
        } else {
            ModerationOutcomeKindV1::Contested
        };
        let no_show_count = u32::try_from(no_shows.len())
            .map_err(|_| corrupt_state("moderation no-show count does not fit u32"))?;
        let outcome = ModerationOutcomeRecordV1 {
            case_id: self.case_id.clone(),
            round_id: self.round_id.clone(),
            kind,
            counts,
            votes_total,
            quorum: case.spec.quorum,
            no_show_count,
            finalized_at_unix_ms: now,
            finalized_by: authority.clone(),
        };
        case.status = ModerationCaseStatusV1::Finalized;
        appeal.status = ModerationAppealStatusV1::Finalized;
        appeal.finalized_at_unix_ms = Some(now);
        let mut status = status_for_mutation(state_transaction.world(), now)?;
        status.open_cases = status
            .open_cases
            .checked_sub(1)
            .ok_or_else(|| corrupt_state("moderation open-case counter underflow"))?;
        status.finalized_cases = checked_inc(status.finalized_cases, "finalized-case")?;
        status.outcomes = checked_inc(status.outcomes, "outcome")?;
        status.no_shows = checked_add(status.no_shows, u64::from(no_show_count), "no-show")?;
        status.updated_at_unix_ms = now;
        let encoded_outcome = encode_state(&outcome, "moderation outcome")?;
        let encoded_case = encode_state(&case, "moderation case")?;
        let encoded_appeal = encode_state(&appeal, "moderation appeal")?;
        let encoded_status = encode_status(&status)?;
        let mut encoded_no_shows = Vec::with_capacity(no_shows.len());
        for no_show in &no_shows {
            if read_no_show(
                state_transaction.world(),
                &self.case_id,
                &self.round_id,
                &no_show.juror,
            )?
            .is_some()
            {
                return Err(corrupt_state(
                    "moderation no-show record exists before case finalization",
                ));
            }
            encoded_no_shows.push((
                no_show_key(&self.case_id, &self.round_id, &no_show.juror),
                encode_state(no_show, "moderation no-show")?,
            ));
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(outcome_key(&self.case_id, &self.round_id), encoded_outcome);
        state_transaction
            .world
            .smart_contract_state
            .insert(case_key(&self.case_id, &self.round_id), encoded_case);
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(&self.case_id, &self.round_id), encoded_appeal);
        for (key, encoded) in encoded_no_shows {
            state_transaction
                .world
                .smart_contract_state
                .insert(key, encoded);
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_moderation_ledger_event(
            state_transaction,
            SorafsModerationLedgerEventKind::CaseFinalized,
            Some(&self.case_id),
            Some(&self.round_id),
            authority,
            now,
        )?;
        Ok(())
    }
}
#[derive(Default)]
struct ModerationSnapshotReadBudget {
    records: usize,
    encoded_bytes: usize,
}
impl ModerationSnapshotReadBudget {
    fn charge(&mut self, key: &StatePath, payload: &[u8]) -> Result<(), InstructionExecutionError> {
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation snapshot record counter overflow"))?;
        if self.records > MODERATION_QUERY_MAX_SNAPSHOT_RECORDS_V1 {
            return Err(corrupt_state(format!(
                "moderation snapshot exceeds {MODERATION_QUERY_MAX_SNAPSHOT_RECORDS_V1} stored records"
            )));
        }
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(key.to_string().len())
            .and_then(|total| total.checked_add(payload.len()))
            .ok_or_else(|| corrupt_state("moderation snapshot byte counter overflow"))?;
        let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(
            MODERATION_QUERY_MAX_SNAPSHOT_BYTES_V1,
        );
        if self.encoded_bytes > maximum {
            return Err(corrupt_state(format!(
                "moderation snapshot source state exceeds {maximum} bytes"
            )));
        }
        Ok(())
    }
}
fn charge_existing_snapshot_state(
    world: &impl WorldReadOnly,
    key: &StatePath,
    budget: &mut ModerationSnapshotReadBudget,
) -> Result<(), InstructionExecutionError> {
    if let Some(payload) = world.smart_contract_state().get(key) {
        budget.charge(key, payload)?;
    }
    Ok(())
}
fn moderation_transient_current(
    retained: Option<&crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<
    Option<crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
    InstructionExecutionError,
> {
    retained
        .map(|current| {
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
                current.resident_bytes(),
            )
        })
        .transpose()
        .map_err(InstructionExecutionError::Query)
}
fn reset_moderation_current(
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    resident_bytes: usize,
) -> Result<(), InstructionExecutionError> {
    *current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(resident_bytes)
            .map_err(InstructionExecutionError::Query)?;
    Ok(())
}
fn scan_moderation_state_prefix<T>(
    world: &impl WorldReadOnly,
    prefix: &'static str,
    label: &'static str,
    budget: &mut ModerationSnapshotReadBudget,
    retained_base_bytes: usize,
    mut validate: impl FnMut(
        &StatePath,
        T,
        &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    ) -> Result<T, InstructionExecutionError>,
) -> Result<crate::smartcontracts::isi::query::SingularQueryRetainedVec<T>, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let start = StatePath::from_str(prefix).expect("static moderation state prefix is valid");
    let mut record_count = 0usize;
    for (key, _) in world.smart_contract_state().range(start.clone()..) {
        if !key.as_ref().starts_with(prefix) {
            break;
        }
        record_count = record_count
            .checked_add(1)
            .ok_or_else(|| corrupt_state("moderation snapshot record count overflow"))?;
        if record_count > MODERATION_QUERY_MAX_SNAPSHOT_RECORDS_V1 {
            return Err(corrupt_state(format!(
                "moderation snapshot exceeds {MODERATION_QUERY_MAX_SNAPSHOT_RECORDS_V1} stored records"
            )));
        }
    }
    let mut records =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(record_count)?;
    for (key, payload) in world.smart_contract_state().range(start..) {
        if !key.as_ref().starts_with(prefix) {
            break;
        }
        budget.charge(key, payload)?;
        let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            retained_base_bytes,
        )
        .map_err(InstructionExecutionError::Query)?;
        let candidate = decode_state_for_current(payload, label, &mut current)?;
        records
            .try_push(validate(key, candidate, &mut current)?)
            .map_err(InstructionExecutionError::Query)?;
    }
    Ok(records.into_retained_vec())
}
fn resolve_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<ModerationFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion(
            "finalized moderation height does not fit into u64".to_owned(),
        )
    })?;
    let hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "finalized moderation queries require at least one committed block".to_owned(),
            )
        })?;
    if height == 0 || hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized moderation query anchor is invalid".to_owned(),
        ));
    }
    Ok(ModerationFinalizedCursorV1 {
        height,
        block_hash: hash,
    })
}
fn resolve_committed_event(
    state_ro: &impl crate::state::StateReadOnly,
    record: ModerationPersistedEventV1,
) -> Result<ModerationFinalizedEventV1, QueryExecutionFail> {
    let hash_index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "moderation event target height cannot index finalized block hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(hash_index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "moderation event sequence {} targets non-finalized block height {}",
                record.sequence, record.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "moderation event sequence {} resolved a zero block hash",
            record.sequence
        )));
    }
    Ok(ModerationFinalizedEventV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
        event: record.event,
    })
}
fn checked_snapshot_limits(
    query: &FindSorafsModerationSnapshot,
) -> Result<(usize, usize), QueryExecutionFail> {
    if !(1..=MODERATION_QUERY_MAX_CASES_V1).contains(&query.max_cases) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS moderation snapshot max_cases {} is outside 1..={MODERATION_QUERY_MAX_CASES_V1}",
            query.max_cases
        )));
    }
    if !(1..=MODERATION_QUERY_MAX_EVENTS_V1).contains(&query.max_events) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS moderation snapshot max_events {} is outside 1..={MODERATION_QUERY_MAX_EVENTS_V1}",
            query.max_events
        )));
    }
    let max_cases = usize::try_from(query.max_cases).map_err(|_| {
        QueryExecutionFail::Conversion("SoraFS moderation max_cases conversion failed".to_owned())
    })?;
    let max_events = usize::try_from(query.max_events).map_err(|_| {
        QueryExecutionFail::Conversion("SoraFS moderation max_events conversion failed".to_owned())
    })?;
    Ok((max_cases, max_events))
}
fn checked_event_page_limit(limit: u32) -> Result<usize, QueryExecutionFail> {
    if !(1..=MODERATION_QUERY_MAX_EVENTS_V1).contains(&limit) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS moderation event limit {limit} is outside 1..={MODERATION_QUERY_MAX_EVENTS_V1}"
        )));
    }
    usize::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion("SoraFS moderation event limit conversion failed".to_owned())
    })
}
#[derive(Clone, Copy)]
struct ModerationQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
}
impl From<&ModerationPersistedEventV1> for ModerationQueryEventPosition {
    fn from(record: &ModerationPersistedEventV1) -> Self {
        Self {
            sequence: record.sequence,
            target_block_height: record.target_block_height,
            event_index: record.event_index,
        }
    }
}
fn validate_query_event_successor(
    previous: Option<ModerationQueryEventPosition>,
    current: &ModerationPersistedEventV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1 && current.event_index == 0)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "moderation event journal does not begin at sequence one and block index zero"
                        .to_owned(),
                )
            });
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(QueryExecutionFail::Conversion(
            "moderation event journal sequence is not contiguous".to_owned(),
        ));
    }
    match current
        .target_block_height
        .cmp(&previous.target_block_height)
    {
        core::cmp::Ordering::Less => Err(QueryExecutionFail::Conversion(
            "moderation event journal block height regressed".to_owned(),
        )),
        core::cmp::Ordering::Equal
            if previous
                .event_index
                .checked_add(1)
                .is_some_and(|next| current.event_index == next) =>
        {
            Ok(())
        }
        core::cmp::Ordering::Equal => Err(QueryExecutionFail::Conversion(
            "moderation event journal block index is not contiguous".to_owned(),
        )),
        core::cmp::Ordering::Greater if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Greater => Err(QueryExecutionFail::Conversion(
            "moderation event journal did not reset its block index".to_owned(),
        )),
    }
}
fn read_event_sequence(
    state_ro: &impl crate::state::StateReadOnly,
    sequence: u64,
    previous: Option<ModerationQueryEventPosition>,
    retained_base_bytes: usize,
) -> Result<(ModerationQueryEventPosition, ModerationFinalizedEventV1), QueryExecutionFail> {
    let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
        retained_base_bytes,
    )?;
    let record = read_persisted_event_for_current(state_ro.world(), sequence, &mut current)
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "moderation event journal is missing sequence {sequence}"
            ))
        })?;
    validate_query_event_successor(previous, &record)?;
    let position = ModerationQueryEventPosition::from(&record);
    let resolved = resolve_committed_event(state_ro, record)?;
    Ok((position, resolved))
}
fn latest_committed_events(
    state_ro: &impl crate::state::StateReadOnly,
    head: Option<ModerationEventJournalHeadV1>,
    limit: usize,
    budget: &mut ModerationSnapshotReadBudget,
    retained_base_bytes: usize,
) -> Result<Vec<ModerationFinalizedEventV1>, QueryExecutionFail> {
    let Some(head) = head else {
        return Ok(Vec::new());
    };
    let limit_u64 = u64::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion(
            "moderation snapshot event limit does not fit into u64".to_owned(),
        )
    })?;
    let start = head
        .last_sequence
        .saturating_sub(limit_u64.saturating_sub(1))
        .max(1);
    let mut previous = if start > 1 {
        let predecessor_sequence = start - 1;
        charge_existing_snapshot_state(state_ro.world(), &event_key(predecessor_sequence), budget)
            .map_err(query_failure)?;
        let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            retained_base_bytes,
        )?;
        Some(ModerationQueryEventPosition::from(
            &read_persisted_event_for_current(
                state_ro.world(),
                predecessor_sequence,
                &mut current,
            )
                .map_err(query_failure)?
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(format!(
                        "moderation event journal is missing predecessor sequence {predecessor_sequence}"
                    ))
                })?,
        ))
    } else {
        None
    };
    let capacity = usize::try_from(head.last_sequence - start + 1).map_err(|_| {
        QueryExecutionFail::Conversion(
            "moderation snapshot event count does not fit into usize".to_owned(),
        )
    })?;
    let mut events = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(capacity)?;
    for sequence in start..=head.last_sequence {
        charge_existing_snapshot_state(state_ro.world(), &event_key(sequence), budget)
            .map_err(query_failure)?;
        let (position, resolved) =
            read_event_sequence(state_ro, sequence, previous, retained_base_bytes)?;
        previous = Some(position);
        events.try_push(resolved)?;
    }
    events.into_vec()
}
fn query_moderation_event_page(
    query: &FindSorafsModerationEvents,
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<ModerationFinalizedEventPageV1, QueryExecutionFail> {
    let limit = checked_event_page_limit(query.limit)?;
    let page_bytes_limit = crate::smartcontracts::isi::query::singular_query_frame_limit(
        MODERATION_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let finalized_cursor = resolve_finalized_cursor(state_ro)?;
    if query.expected_finalized_cursor != finalized_cursor {
        return Err(QueryExecutionFail::Expired);
    }
    let mut head_current =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
    let head = read_event_journal_head_for_current(state_ro.world(), &mut head_current)
        .map_err(query_failure)?;
    ensure_no_event_after_head(state_ro.world(), head).map_err(query_failure)?;
    let mut previous = match query.after {
        Some(after) => {
            let head = head.ok_or(QueryExecutionFail::Expired)?;
            if after.sequence == 0 || after.sequence > head.last_sequence {
                return Err(QueryExecutionFail::Expired);
            }
            let predecessor_record = if after.sequence == 1 {
                None
            } else {
                let predecessor_sequence = after.sequence - 1;
                Some(
                    read_persisted_event(state_ro.world(), predecessor_sequence)
                        .map_err(query_failure)?
                        .ok_or_else(|| {
                            QueryExecutionFail::Conversion(format!(
                                "moderation event journal is missing predecessor sequence {predecessor_sequence}"
                            ))
                        })?,
                )
            };
            let predecessor = predecessor_record
                .as_ref()
                .map(ModerationQueryEventPosition::from);
            drop(predecessor_record);
            let record = read_persisted_event(state_ro.world(), after.sequence)
                .map_err(query_failure)?
                .ok_or(QueryExecutionFail::Expired)?;
            validate_query_event_successor(predecessor, &record)?;
            let position = ModerationQueryEventPosition::from(&record);
            let resolved = resolve_committed_event(state_ro, record)?;
            if resolved.cursor() != after {
                return Err(QueryExecutionFail::Expired);
            }
            Some(position)
        }
        None => None,
    };
    let start = query
        .after
        .map_or(Some(1), |after| after.sequence.checked_add(1));
    let last_sequence = head.map_or(0, |head| head.last_sequence);
    let mut events = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let mut encoded_event_bytes = 0usize;
    let mut sequence = start;
    while let Some(current_sequence) = sequence {
        if current_sequence > last_sequence || events.len() >= limit {
            break;
        }
        let (position, resolved) = read_event_sequence(state_ro, current_sequence, previous, 0)?;
        encoded_event_bytes = encoded_event_bytes
            .checked_add(norito::canonical_frame_len(&resolved).map_err(|error| {
                QueryExecutionFail::Conversion(format!(
                    "failed to size committed moderation event: {error}"
                ))
            })?)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "committed moderation event page byte counter overflow".to_owned(),
                )
            })?;
        if encoded_event_bytes > page_bytes_limit {
            return Err(QueryExecutionFail::Conversion(format!(
                "committed moderation event page exceeds {page_bytes_limit} bytes"
            )));
        }
        previous = Some(position);
        events.try_push(resolved)?;
        sequence = current_sequence.checked_add(1);
    }
    let has_more = events
        .last()
        .is_some_and(|event| event.sequence < last_sequence);
    let next_after = has_more.then(|| {
        events
            .last()
            .expect("has_more requires a non-empty moderation event page")
            .cursor()
    });
    let page = ModerationFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    let encoded_len = norito::canonical_frame_len(&page).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "failed to size committed moderation event page: {error}"
        ))
    })?;
    if encoded_len > page_bytes_limit {
        return Err(QueryExecutionFail::Conversion(format!(
            "committed moderation event page encodes to {encoded_len} bytes, above {page_bytes_limit}"
        )));
    }
    Ok(page)
}
fn count_as_u64(count: usize, label: &str) -> Result<u64, QueryExecutionFail> {
    u64::try_from(count).map_err(|_| {
        QueryExecutionFail::Conversion(format!(
            "moderation snapshot {label} count does not fit into u64"
        ))
    })
}
fn sum_lengths_as_u64(
    counts: impl IntoIterator<Item = usize>,
    label: &str,
) -> Result<u64, QueryExecutionFail> {
    counts.into_iter().try_fold(0u64, |total, count| {
        let count = count_as_u64(count, label)?;
        total.checked_add(count).ok_or_else(|| {
            QueryExecutionFail::Conversion(format!("moderation snapshot {label} count overflow"))
        })
    })
}
#[allow(clippy::too_many_lines)]
fn query_moderation_snapshot(
    query: &FindSorafsModerationSnapshot,
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<ModerationFinalizedLedgerSnapshotV1, QueryExecutionFail> {
    let (max_cases, max_events) = checked_snapshot_limits(query)?;
    let finalized_cursor = resolve_finalized_cursor(state_ro)?;
    let finalized_at_unix_ms = state_ro.query_ledger_time_ms();
    if finalized_at_unix_ms == 0 {
        return Err(QueryExecutionFail::Conversion(
            "finalized moderation snapshot state anchor has no ledger time".to_owned(),
        ));
    }
    let world = state_ro.world();
    let mut budget = ModerationSnapshotReadBudget::default();
    charge_existing_snapshot_state(world, policy_key(), &mut budget).map_err(query_failure)?;
    charge_existing_snapshot_state(world, status_key(), &mut budget).map_err(query_failure)?;
    charge_existing_snapshot_state(world, event_journal_head_key(), &mut budget)
        .map_err(query_failure)?;
    let mut retained_base =
        crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
    let policy = read_policy_for_current(world, &mut retained_base).map_err(query_failure)?;
    let status = read_status_for_current(world, &mut retained_base).map_err(query_failure)?;
    let retained_base_bytes = retained_base.resident_bytes();
    let mut head_current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
        retained_base_bytes,
    )?;
    let head =
        read_event_journal_head_for_current(world, &mut head_current).map_err(query_failure)?;
    ensure_no_event_after_head(world, head).map_err(query_failure)?;
    let mut appeals: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationAppealRecordV1,
    > = scan_moderation_state_prefix(
        world,
        APPEAL_STATE_KEY_PREFIX,
        "moderation appeal",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationAppealRecordV1, current| {
            if appeal_key(&candidate.intake.case_id, &candidate.intake.round_id) != *key {
                return Err(corrupt_state(
                    "authoritative moderation appeal key does not match its record",
                ));
            }
            let candidate_resident_bytes = current.resident_bytes();
            let record = read_appeal_for_current(
                world,
                &candidate.intake.case_id,
                &candidate.intake.round_id,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation appeal disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation appeal changed during snapshot read",
                ));
            }
            let deposit_lock_digest = record.intake.appeal_deposit_lock_digest;
            let proof_token_digest = record.intake.proof_token_digest;
            drop(record);
            reset_moderation_current(current, candidate_resident_bytes)?;
            read_appeal_deposit_binding_for_current(world, deposit_lock_digest, current)?
                .ok_or_else(|| {
                    corrupt_state("authoritative moderation appeal has no deposit binding")
                })?;
            reset_moderation_current(current, candidate_resident_bytes)?;
            read_appeal_proof_token_binding_for_current(world, proof_token_digest, current)?
                .ok_or_else(|| {
                    corrupt_state("authoritative moderation appeal has no proof-token binding")
                })?;
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let deposit_bindings: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        AppealDepositBindingStateV1,
    > = scan_moderation_state_prefix(
        world,
        APPEAL_DEPOSIT_STATE_KEY_PREFIX,
        "moderation appeal deposit binding",
        &mut budget,
        retained_base_bytes,
        |key, candidate: AppealDepositBindingStateV1, current| {
            if appeal_deposit_key(candidate.deposit_lock_digest) != *key {
                return Err(corrupt_state(
                    "authoritative moderation appeal deposit key does not match its binding",
                ));
            }
            let record = read_appeal_deposit_binding_for_current(
                world,
                candidate.deposit_lock_digest,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state(
                    "authoritative moderation appeal deposit disappeared during snapshot read",
                )
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation appeal deposit changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let proof_token_bindings: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        AppealProofTokenBindingStateV1,
    > = scan_moderation_state_prefix(
        world,
        APPEAL_PROOF_TOKEN_STATE_KEY_PREFIX,
        "moderation appeal proof-token binding",
        &mut budget,
        retained_base_bytes,
        |key, candidate: AppealProofTokenBindingStateV1, current| {
            if appeal_proof_token_key(candidate.proof_token_digest) != *key {
                return Err(corrupt_state(
                    "authoritative moderation appeal proof-token key does not match its binding",
                ));
            }
            let record = read_appeal_proof_token_binding_for_current(
                world,
                candidate.proof_token_digest,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state(
                    "authoritative moderation appeal proof-token disappeared during snapshot read",
                )
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation appeal proof-token changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let mut eligibilities: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationJurorEligibilityRecordV1,
    > = scan_moderation_state_prefix(
        world,
        ELIGIBILITY_STATE_KEY_PREFIX,
        "moderation juror eligibility",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationJurorEligibilityRecordV1, current| {
            if eligibility_key(&candidate.case_id, &candidate.round_id, &candidate.juror) != *key {
                return Err(corrupt_state(
                    "authoritative moderation eligibility key does not match its record",
                ));
            }
            let candidate_resident_bytes = current.resident_bytes();
            let record = read_eligibility_for_current(
                world,
                &candidate.case_id,
                &candidate.round_id,
                &candidate.juror,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state(
                    "authoritative moderation eligibility disappeared during snapshot read",
                )
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation eligibility changed during snapshot read",
                ));
            }
            let nullifier_digest = record.nullifier;
            drop(record);
            reset_moderation_current(current, candidate_resident_bytes)?;
            let nullifier = read_nullifier_for_current(world, nullifier_digest, current)?
                .ok_or_else(|| {
                    corrupt_state("authoritative moderation eligibility has no nullifier binding")
                })?;
            if nullifier != candidate {
                return Err(corrupt_state(
                    "authoritative moderation eligibility disagrees with its nullifier binding",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let nullifier_bindings: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationJurorEligibilityRecordV1,
    > = scan_moderation_state_prefix(
        world,
        NULLIFIER_STATE_KEY_PREFIX,
        "moderation PoP nullifier",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationJurorEligibilityRecordV1, current| {
            if nullifier_key(candidate.nullifier) != *key {
                return Err(corrupt_state(
                    "authoritative moderation nullifier key does not match its record",
                ));
            }
            let record = read_nullifier_for_current(world, candidate.nullifier, current)?
                .ok_or_else(|| {
                    corrupt_state(
                        "authoritative moderation nullifier disappeared during snapshot read",
                    )
                })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation nullifier changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let mut cases: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationCaseRecordV1,
    > = scan_moderation_state_prefix(
        world,
        CASE_STATE_KEY_PREFIX,
        "moderation case",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationCaseRecordV1, current| {
            if case_key(&candidate.spec.context.case_id, &candidate.spec.round_id) != *key {
                return Err(corrupt_state(
                    "authoritative moderation case key does not match its record",
                ));
            }
            let record = read_case_for_current(
                world,
                &candidate.spec.context.case_id,
                &candidate.spec.round_id,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation case disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation case changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let commits: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationCommitRecordV1,
    > = scan_moderation_state_prefix(
        world,
        COMMIT_STATE_KEY_PREFIX,
        "moderation commit",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationCommitRecordV1, current| {
            if commit_key(&candidate.case_id, &candidate.round_id, &candidate.juror) != *key {
                return Err(corrupt_state(
                    "authoritative moderation commit key does not match its record",
                ));
            }
            let record = read_commit_for_current(
                world,
                &candidate.case_id,
                &candidate.round_id,
                &candidate.juror,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation commit disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation commit changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let reveals: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationRevealRecordV1,
    > = scan_moderation_state_prefix(
        world,
        REVEAL_STATE_KEY_PREFIX,
        "moderation reveal",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationRevealRecordV1, current| {
            if reveal_key(&candidate.case_id, &candidate.round_id, &candidate.juror) != *key {
                return Err(corrupt_state(
                    "authoritative moderation reveal key does not match its record",
                ));
            }
            let record = read_reveal_for_current(
                world,
                &candidate.case_id,
                &candidate.round_id,
                &candidate.juror,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation reveal disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation reveal changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let challenges: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationChallengeRecordV1,
    > = scan_moderation_state_prefix(
        world,
        CHALLENGE_STATE_KEY_PREFIX,
        "moderation challenge",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationChallengeRecordV1, current| {
            if challenge_key(
                &candidate.case_id,
                &candidate.round_id,
                &candidate.challenge_id,
            ) != *key
            {
                return Err(corrupt_state(
                    "authoritative moderation challenge key does not match its record",
                ));
            }
            let record = read_challenge_for_current(
                world,
                &candidate.case_id,
                &candidate.round_id,
                &candidate.challenge_id,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation challenge disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation challenge changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let outcomes: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationOutcomeRecordV1,
    > = scan_moderation_state_prefix(
        world,
        OUTCOME_STATE_KEY_PREFIX,
        "moderation outcome",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationOutcomeRecordV1, current| {
            if outcome_key(&candidate.case_id, &candidate.round_id) != *key {
                return Err(corrupt_state(
                    "authoritative moderation outcome key does not match its record",
                ));
            }
            let record =
                read_outcome_for_current(world, &candidate.case_id, &candidate.round_id, current)?
                    .ok_or_else(|| {
                        corrupt_state(
                            "authoritative moderation outcome disappeared during snapshot read",
                        )
                    })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation outcome changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    let no_shows: crate::smartcontracts::isi::query::SingularQueryRetainedVec<
        ModerationNoShowRecordV1,
    > = scan_moderation_state_prefix(
        world,
        NO_SHOW_STATE_KEY_PREFIX,
        "moderation no-show",
        &mut budget,
        retained_base_bytes,
        |key, candidate: ModerationNoShowRecordV1, current| {
            if no_show_key(&candidate.case_id, &candidate.round_id, &candidate.juror) != *key {
                return Err(corrupt_state(
                    "authoritative moderation no-show key does not match its record",
                ));
            }
            let record = read_no_show_for_current(
                world,
                &candidate.case_id,
                &candidate.round_id,
                &candidate.juror,
                current,
            )?
            .ok_or_else(|| {
                corrupt_state("authoritative moderation no-show disappeared during snapshot read")
            })?;
            if record != candidate {
                return Err(corrupt_state(
                    "authoritative moderation no-show changed during snapshot read",
                ));
            }
            Ok(candidate)
        },
    )
    .map_err(query_failure)?;
    if appeals.len() > max_cases || cases.len() > max_cases {
        return Err(QueryExecutionFail::Conversion(format!(
            "complete moderation projection contains {} appeals and {} cases, exceeding requested max_cases {max_cases}",
            appeals.len(),
            cases.len()
        )));
    }
    let primary_records_present = !appeals.is_empty()
        || !eligibilities.is_empty()
        || !cases.is_empty()
        || !commits.is_empty()
        || !reveals.is_empty()
        || !challenges.is_empty()
        || !outcomes.is_empty()
        || !no_shows.is_empty();
    let index_records_present = !deposit_bindings.is_empty()
        || !proof_token_bindings.is_empty()
        || !nullifier_bindings.is_empty();
    match (&policy, &status) {
        (None, None) if !primary_records_present && !index_records_present && head.is_none() => {}
        (Some(_), Some(_)) if head.is_some() => {}
        (None, None) => {
            return Err(QueryExecutionFail::Conversion(
                "uninitialized moderation ledger contains authoritative records".to_owned(),
            ));
        }
        _ => {
            return Err(QueryExecutionFail::Conversion(
                "authoritative moderation policy, status, and event journal are inconsistent"
                    .to_owned(),
            ));
        }
    }
    drop(deposit_bindings);
    drop(proof_token_bindings);
    drop(nullifier_bindings);
    appeals.sort_by(|left, right| {
        (left.intake.case_id.as_str(), left.intake.round_id.as_str()).cmp(&(
            right.intake.case_id.as_str(),
            right.intake.round_id.as_str(),
        ))
    });
    if appeals.windows(2).any(|window| {
        window[0].intake.case_id == window[1].intake.case_id
            && window[0].intake.round_id == window[1].intake.round_id
    }) {
        return Err(QueryExecutionFail::Conversion(
            "moderation snapshot contains duplicate appeal identities".to_owned(),
        ));
    }
    cases.sort_by(|left, right| {
        (
            left.spec.context.case_id.as_str(),
            left.spec.round_id.as_str(),
        )
            .cmp(&(
                right.spec.context.case_id.as_str(),
                right.spec.round_id.as_str(),
            ))
    });
    if cases.windows(2).any(|window| {
        window[0].spec.context.case_id == window[1].spec.context.case_id
            && window[0].spec.round_id == window[1].spec.round_id
    }) {
        return Err(QueryExecutionFail::Conversion(
            "moderation snapshot contains duplicate case identities".to_owned(),
        ));
    }
    if cases.iter().any(|case| {
        let target = (
            case.spec.context.case_id.as_str(),
            case.spec.round_id.as_str(),
        );
        appeals
            .binary_search_by(|appeal| {
                (
                    appeal.intake.case_id.as_str(),
                    appeal.intake.round_id.as_str(),
                )
                    .cmp(&target)
            })
            .is_err()
    }) || appeals.iter().any(|appeal| {
        matches!(
            appeal.status,
            ModerationAppealStatusV1::BallotOpen | ModerationAppealStatusV1::Finalized
        ) && {
            let target = (
                appeal.intake.case_id.as_str(),
                appeal.intake.round_id.as_str(),
            );
            cases
                .binary_search_by(|case| {
                    (
                        case.spec.context.case_id.as_str(),
                        case.spec.round_id.as_str(),
                    )
                        .cmp(&target)
                })
                .is_err()
        }
    }) {
        return Err(QueryExecutionFail::Conversion(
            "moderation appeal and activated-case projections disagree".to_owned(),
        ));
    }
    let eligibility_count = eligibilities.len();
    let commit_count = commits.len();
    let reveal_count = reveals.len();
    let challenge_count = challenges.len();
    let outcome_count = outcomes.len();
    let no_show_count = no_shows.len();
    let appeal_count = appeals.len();
    let panel_selection_count = appeals
        .iter()
        .filter(|appeal| appeal.selection.is_some())
        .count();
    let assignment_acceptance_count = sum_lengths_as_u64(
        appeals.iter().map(|appeal| appeal.accepted_jurors.len()),
        "assignment acceptance",
    )?;
    let failover_replacement_count = sum_lengths_as_u64(
        appeals.iter().map(|appeal| appeal.replacements.len()),
        "failover replacement",
    )?;
    let failed_panel_formation_count = appeals
        .iter()
        .filter(|appeal| {
            matches!(
                appeal.status,
                ModerationAppealStatusV1::InsufficientEligiblePool
                    | ModerationAppealStatusV1::FailoverExhausted
            )
        })
        .count();
    let open_case_count = cases
        .iter()
        .filter(|case| {
            matches!(
                case.status,
                ModerationCaseStatusV1::Open | ModerationCaseStatusV1::Challenged
            )
        })
        .count();
    let finalized_case_count = cases
        .iter()
        .filter(|case| case.status == ModerationCaseStatusV1::Finalized)
        .count();
    eligibilities.sort_by(|left, right| {
        (left.case_id.as_str(), left.round_id.as_str(), &left.juror).cmp(&(
            right.case_id.as_str(),
            right.round_id.as_str(),
            &right.juror,
        ))
    });
    let mut eligibility_records = eligibilities.into_iter();
    let appeal_count_for_capacity = appeals.len();
    let mut appeal_views =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(appeal_count_for_capacity)?;
    let mut appeals = appeals.into_iter();
    while let Some((appeal, appeal_allocation_bytes)) = appeals.next_with_allocation_charge()? {
        let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            retained_base_bytes
                .checked_add(appeal_allocation_bytes)
                .ok_or(QueryExecutionFail::CapacityLimit)?,
        )?;
        let target = (
            appeal.intake.case_id.as_str(),
            appeal.intake.round_id.as_str(),
        );
        if eligibility_records
            .as_slice()
            .first()
            .is_some_and(|record| (record.case_id.as_str(), record.round_id.as_str()) < target)
        {
            return Err(QueryExecutionFail::Conversion(
                "moderation snapshot contains orphan eligibility records".to_owned(),
            ));
        }
        let eligibility_count = eligibility_records
            .as_slice()
            .iter()
            .take_while(|record| (record.case_id.as_str(), record.round_id.as_str()) == target)
            .count();
        let mut eligibility = current.vec_with_capacity(eligibility_count)?;
        for _ in 0..eligibility_count {
            let (record, allocation_bytes) = eligibility_records
                .next_with_allocation_charge()?
                .expect("counted moderation eligibility remains available");
            current.add_nested(allocation_bytes)?;
            eligibility.push(record)?;
        }
        appeal_views.try_push(ModerationFinalizedAppealViewV1 {
            appeal,
            eligibility: eligibility.into_vec(),
        })?;
    }
    if !eligibility_records.as_slice().is_empty() {
        return Err(QueryExecutionFail::Conversion(
            "moderation snapshot contains orphan eligibility records".to_owned(),
        ));
    }
    let mut commits = commits;
    commits.sort_by(|left, right| {
        (left.case_id.as_str(), left.round_id.as_str(), &left.juror).cmp(&(
            right.case_id.as_str(),
            right.round_id.as_str(),
            &right.juror,
        ))
    });
    let mut reveals = reveals;
    reveals.sort_by(|left, right| {
        (left.case_id.as_str(), left.round_id.as_str(), &left.juror).cmp(&(
            right.case_id.as_str(),
            right.round_id.as_str(),
            &right.juror,
        ))
    });
    let mut challenges = challenges;
    challenges.sort_by(|left, right| {
        (
            left.case_id.as_str(),
            left.round_id.as_str(),
            &left.challenge_id,
        )
            .cmp(&(
                right.case_id.as_str(),
                right.round_id.as_str(),
                &right.challenge_id,
            ))
    });
    let mut outcomes = outcomes;
    outcomes.sort_by(|left, right| {
        (left.case_id.as_str(), left.round_id.as_str())
            .cmp(&(right.case_id.as_str(), right.round_id.as_str()))
    });
    if outcomes.windows(2).any(|window| {
        window[0].case_id == window[1].case_id && window[0].round_id == window[1].round_id
    }) {
        return Err(QueryExecutionFail::Conversion(
            "moderation snapshot contains duplicate terminal outcomes".to_owned(),
        ));
    }
    let mut no_shows = no_shows;
    no_shows.sort_by(|left, right| {
        (left.case_id.as_str(), left.round_id.as_str(), &left.juror).cmp(&(
            right.case_id.as_str(),
            right.round_id.as_str(),
            &right.juror,
        ))
    });
    let mut commits = commits.into_iter();
    let mut reveals = reveals.into_iter();
    let mut challenges = challenges.into_iter();
    let mut outcomes = outcomes.into_iter();
    let mut no_shows = no_shows.into_iter();
    macro_rules! take_case_records {
        ($records:ident, $target:expr, $current:ident) => {{
            let target = $target;
            if $records
                .as_slice()
                .first()
                .is_some_and(|record| (record.case_id.as_str(), record.round_id.as_str()) < target)
            {
                return Err(QueryExecutionFail::Conversion(
                    "moderation snapshot contains orphan case subrecords".to_owned(),
                ));
            }
            let count = $records
                .as_slice()
                .iter()
                .take_while(|record| (record.case_id.as_str(), record.round_id.as_str()) == target)
                .count();
            let mut group = $current.vec_with_capacity(count)?;
            for _ in 0..count {
                let (record, allocation_bytes) = $records
                    .next_with_allocation_charge()?
                    .expect("counted moderation case record remains available");
                $current.add_nested(allocation_bytes)?;
                group.push(record)?;
            }
            group.into_vec()
        }};
    }
    let case_count_for_capacity = cases.len();
    let mut case_views =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(case_count_for_capacity)?;
    let mut cases = cases.into_iter();
    while let Some((case, case_allocation_bytes)) = cases.next_with_allocation_charge()? {
        let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            retained_base_bytes
                .checked_add(case_allocation_bytes)
                .ok_or(QueryExecutionFail::CapacityLimit)?,
        )?;
        let target = (
            case.spec.context.case_id.as_str(),
            case.spec.round_id.as_str(),
        );
        let case_commits = take_case_records!(commits, target, current);
        let case_reveals = take_case_records!(reveals, target, current);
        let case_challenges = take_case_records!(challenges, target, current);
        let case_no_shows = take_case_records!(no_shows, target, current);
        let outcome = match outcomes.as_slice().first() {
            Some(record) if (record.case_id.as_str(), record.round_id.as_str()) < target => {
                return Err(QueryExecutionFail::Conversion(
                    "moderation snapshot contains orphan case subrecords".to_owned(),
                ));
            }
            Some(record) if (record.case_id.as_str(), record.round_id.as_str()) == target => {
                let (outcome, allocation_bytes) = outcomes
                    .next_with_allocation_charge()?
                    .expect("matched moderation outcome remains available");
                current.add_nested(allocation_bytes)?;
                Some(outcome)
            }
            Some(_) | None => None,
        };
        case_views.try_push(ModerationFinalizedCaseViewV1 {
            case,
            commits: case_commits,
            reveals: case_reveals,
            challenges: case_challenges,
            outcome,
            no_shows: case_no_shows,
        })?;
    }
    if !commits.as_slice().is_empty()
        || !reveals.as_slice().is_empty()
        || !challenges.as_slice().is_empty()
        || !outcomes.as_slice().is_empty()
        || !no_shows.as_slice().is_empty()
    {
        return Err(QueryExecutionFail::Conversion(
            "moderation snapshot contains orphan case subrecords".to_owned(),
        ));
    }
    if let Some(status) = status {
        let expected = ModerationLedgerStatusV1 {
            appeal_intakes: count_as_u64(appeal_count, "appeal")?,
            eligibility_proofs: count_as_u64(eligibility_count, "eligibility")?,
            panel_selections: count_as_u64(panel_selection_count, "panel selection")?,
            assignment_acceptances: assignment_acceptance_count,
            failover_replacements: failover_replacement_count,
            failed_panel_formations: count_as_u64(
                failed_panel_formation_count,
                "failed panel formation",
            )?,
            open_cases: count_as_u64(open_case_count, "open case")?,
            finalized_cases: count_as_u64(finalized_case_count, "finalized case")?,
            commitments: count_as_u64(commit_count, "commitment")?,
            reveals: count_as_u64(reveal_count, "reveal")?,
            challenges: count_as_u64(challenge_count, "challenge")?,
            outcomes: count_as_u64(outcome_count, "outcome")?,
            no_shows: count_as_u64(no_show_count, "no-show")?,
            updated_at_unix_ms: status.updated_at_unix_ms,
        };
        if status != expected {
            return Err(QueryExecutionFail::Conversion(
                "moderation status counters disagree with the complete ledger projection"
                    .to_owned(),
            ));
        }
        let head = head.expect("initialized moderation ledger requires an event journal head");
        let mut current = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(
            retained_base_bytes,
        )?;
        let latest_event =
            read_persisted_event_for_current(world, head.last_sequence, &mut current)
                .map_err(query_failure)?
                .expect("validated moderation event head has a terminal record");
        if latest_event.event.occurred_at_unix_ms != status.updated_at_unix_ms {
            return Err(QueryExecutionFail::Conversion(
                "moderation event journal timestamp disagrees with ledger status".to_owned(),
            ));
        }
    }
    let events =
        latest_committed_events(state_ro, head, max_events, &mut budget, retained_base_bytes)?;
    let snapshot = ModerationFinalizedLedgerSnapshotV1 {
        version: MODERATION_FINALIZED_SNAPSHOT_VERSION_V1,
        finalized_height: finalized_cursor.height,
        finalized_block_hash: finalized_cursor.block_hash,
        finalized_at_unix_ms,
        policy,
        status,
        appeals: appeal_views.into_vec()?,
        cases: case_views.into_vec()?,
        events,
    };
    let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(
        MODERATION_QUERY_MAX_SNAPSHOT_BYTES_V1,
    );
    let encoded_len = norito::canonical_frame_len(&snapshot).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "failed to size finalized moderation snapshot: {error}"
        ))
    })?;
    if encoded_len > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "finalized moderation snapshot encodes to {encoded_len} bytes, above {maximum}"
        )));
    }
    Ok(snapshot)
}
impl ValidSingularQuery for FindSorafsModerationPolicy {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationLedgerPolicyRecord, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_policy_for_current(state_ro.world(), &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsModerationPolicy))
    }
}
impl ValidSingularQuery for FindSorafsModerationAppeal {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationAppealRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_appeal_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationAppeal(format!(
                "{} round {}",
                self.case_id, self.round_id
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationJurorEligibility {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationJurorEligibilityRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_eligibility_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &self.juror,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationJurorEligibility(format!(
                "{} round {} juror {}",
                self.case_id, self.round_id, self.juror
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationCase {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationCaseRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_case_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationCase(format!(
                "{} round {}",
                self.case_id, self.round_id
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationCommit {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationCommitRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_commit_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &self.juror,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationCommit(format!(
                "{} round {} juror {}",
                self.case_id, self.round_id, self.juror
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationReveal {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationRevealRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_reveal_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &self.juror,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationReveal(format!(
                "{} round {} juror {}",
                self.case_id, self.round_id, self.juror
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationChallenge {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationChallengeRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_challenge_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &self.challenge_id,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationChallenge(format!(
                "{} for {} round {}",
                self.challenge_id, self.case_id, self.round_id
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationOutcome {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationOutcomeRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_outcome_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationOutcome(format!(
                "{} round {}",
                self.case_id, self.round_id
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationNoShow {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationNoShowRecordV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        read_no_show_for_current(
            state_ro.world(),
            &self.case_id,
            &self.round_id,
            &self.juror,
            &mut current,
        )
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Find(FindError::SorafsModerationNoShow(format!(
                "{} round {} juror {}",
                self.case_id, self.round_id, self.juror
            )))
        })
    }
}
impl ValidSingularQuery for FindSorafsModerationStatus {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationLedgerStatusV1, QueryExecutionFail> {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        let policy =
            read_policy_for_current(state_ro.world(), &mut current).map_err(query_failure)?;
        let status =
            read_status_for_current(state_ro.world(), &mut current).map_err(query_failure)?;
        match (policy, status) {
            (Some(_), Some(status)) => Ok(status),
            (None, None) => Err(QueryExecutionFail::Find(FindError::SorafsModerationStatus)),
            _ => Err(QueryExecutionFail::Conversion(
                "authoritative SoraFS moderation policy/status state is inconsistent".to_owned(),
            )),
        }
    }
}
impl ValidSingularQuery for FindSorafsModerationSnapshot {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationFinalizedLedgerSnapshotV1, QueryExecutionFail> {
        query_moderation_snapshot(self, state_ro)
    }
}
impl ValidSingularQuery for FindSorafsModerationEvents {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ModerationFinalizedEventPageV1, QueryExecutionFail> {
        query_moderation_event_page(self, state_ro)
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    include!("sorafs_moderation_setup_and_commit_tests.rs");
    include!("sorafs_moderation_challenge_and_intake_tests.rs");
    include!("sorafs/moderation_schema_identity_tests.rs");
}

#[cfg(test)]
#[path = "sorafs_moderation/canonical_state_tests.rs"]
mod canonical_state_tests;
