//! Authoritative native SoraFS reputation journal.
//!
//! Every policy, event, idempotency index, and source head is stored inside
//! consensus-owned `smart_contract_state`.  This uses the same checkpointed,
//! state-root-covered storage path as the other first-release SoraFS ledgers;
//! no daemon database is authoritative.
use super::*;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::smartcontracts::isi::helpers::transaction_account_has_permission as has_permission;
use crate::{
    smartcontracts::ValidSingularQuery,
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    account::AccountId,
    events::data::sorafs::{
        SorafsGatewayEvent, SorafsReputationJournalEntryCommittedV1, SorafsReputationJournalEvent,
        SorafsReputationJournalPolicyActivatedV1,
    },
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            AppendSorafsPorReputationJournalEntry, AppendSorafsStreamTokenReputationJournalEntry,
            ResolveSorafsCapacityDispute, SetSorafsReputationJournalAuthorityPolicy,
        },
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsReputationJournalAuthorityPolicy, FindSorafsReputationJournalEventBySourceId,
            FindSorafsReputationJournalEvents,
        },
    },
    sorafs::{
        capacity::{
            CapacityDisputeRecord, CapacityDisputeResolution, CapacityDisputeStatus, ProviderId,
        },
        reputation::{
            ProviderDisputeEventV1, ProviderDisputeKindV1, ProviderDisputeResolutionV1,
            ProviderDisputeStatusV1, REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1, ReputationJournalAuthorityPolicyRecordV1,
            ReputationJournalCommittedEventRecordV1, ReputationJournalEntryV1,
            ReputationJournalEventIdV1, ReputationJournalFinalizedCursorV1,
            ReputationJournalFinalizedEventCursorV1, ReputationJournalFinalizedEventPageV1,
            ReputationJournalFinalizedEventV1, ReputationJournalPayloadV1,
            ReputationJournalSourceHeadV1, ReputationJournalSourceIdV1,
            ReputationJournalSourceKindV1, ReputationJournalValidationError,
        },
    },
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::{DecodeLimits, decode_from_bytes_with_limits};
use std::{str::FromStr, sync::OnceLock};
pub(crate) mod stream_token_delivery;

const ACTIVE_POLICY_STATE_KEY: &str = "sorafs_reputation_policy_active_v1";
const POLICY_HISTORY_STATE_KEY_PREFIX: &str = "sorafs_reputation_policy_history_v1_";
const JOURNAL_HEAD_STATE_KEY: &str = "sorafs_reputation_journal_head_v1";
const EVENT_STATE_KEY_PREFIX: &str = "sorafs_reputation_event_v1_";
const EVENT_ID_STATE_KEY_PREFIX: &str = "sorafs_reputation_event_id_v1_";
const SOURCE_HEAD_STATE_KEY_PREFIX: &str = "sorafs_reputation_source_head_v1_";
const CAN_MANAGE_POLICY: &str = "CanManageSorafsReputationJournalPolicy";
const CAN_RECORD_ENTRY: &str = "CanRecordSorafsReputationJournal";
const CAN_RESOLVE_DISPUTE: &str = "CanResolveSorafsCapacityDispute";
const STATE_MAX_BYTES: usize = 128 * 1024;
const REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1: usize = 1_024;
const STATE_LIMITS: DecodeLimits = DecodeLimits::new(
    STATE_MAX_BYTES,
    STATE_MAX_BYTES,
    2 * STATE_MAX_BYTES,
    STATE_MAX_BYTES * 2,
    64,
);
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
    name = "iroha_core::smartcontracts::isi::sorafs_reputation::ReputationJournalHeadStateV1"
)]
struct ReputationJournalHeadStateV1 {
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
fn encode_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    let bytes = norito::to_bytes(value)
        .map_err(|error| corrupt_state(format!("failed to encode {label}: {error}")))?;
    if bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} encodes to {} bytes; maximum is {STATE_MAX_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}
fn decode_state<T>(bytes: &[u8], label: &str) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    decode_state_with_current(bytes, label, None)
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
            decode_from_bytes_with_limits::<T>(bytes, limits)
        });
        (value, Some(usage.total_allocated_bytes()))
    } else {
        (decode_from_bytes_with_limits::<T>(bytes, limits), None)
    };
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else {
            corrupt_state(format!("failed to decode {label}: {error}"))
        }
    })?;
    norito::verify_exact_frame(&value, bytes).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            corrupt_state(format!("{label} state is not exact canonical Norito"))
        } else {
            corrupt_state(format!("failed to encode {label}: {error}"))
        }
    })?;
    if let (Some(current), Some(allocation_bytes)) = (current, allocation_bytes) {
        current
            .add_nested(allocation_bytes)
            .map_err(InstructionExecutionError::Query)?;
    }
    Ok(value)
}
fn reputation_current_from_resident(
    resident_bytes: usize,
) -> Result<
    crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    InstructionExecutionError,
> {
    crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(resident_bytes)
        .map_err(InstructionExecutionError::Query)
}
fn reset_reputation_current(
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    resident_bytes: usize,
) -> Result<(), InstructionExecutionError> {
    *current = reputation_current_from_resident(resident_bytes)?;
    Ok(())
}
fn active_policy_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(ACTIVE_POLICY_STATE_KEY).expect("static reputation policy key is valid")
    })
}
fn journal_head_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(JOURNAL_HEAD_STATE_KEY).expect("static reputation head key is valid")
    })
}
fn digest_key(prefix: &str, digest: &[u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static prefix plus lowercase hex is a valid state key")
}
fn policy_history_key(digest: &[u8; 32]) -> StatePath {
    digest_key(POLICY_HISTORY_STATE_KEY_PREFIX, digest)
}
fn event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{EVENT_STATE_KEY_PREFIX}{sequence:016x}"))
        .expect("static event prefix plus fixed-width lowercase hex is a valid state key")
}
fn event_id_key(event_id: ReputationJournalEventIdV1) -> StatePath {
    digest_key(EVENT_ID_STATE_KEY_PREFIX, event_id.as_bytes())
}
fn source_head_key(source_id: ReputationJournalSourceIdV1) -> StatePath {
    digest_key(SOURCE_HEAD_STATE_KEY_PREFIX, source_id.as_bytes())
}
fn state_prefix_has_any(world: &impl WorldReadOnly, prefix: &str) -> bool {
    let start = StatePath::from_str(prefix).expect("static state prefix is valid");
    world
        .smart_contract_state()
        .range(start..)
        .next()
        .is_some_and(|(key, _)| key.to_string().starts_with(prefix))
}
fn require_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> Result<(), InstructionExecutionError> {
    if state_transaction.world.accounts.get(authority).is_none() {
        return Err(invalid_parameter(
            "authoritative SoraFS reputation operation requires a registered transaction authority",
        ));
    }
    if has_permission(state_transaction, authority, permission) {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "permission {permission} is required for authoritative SoraFS reputation operation"
        )))
    }
}
fn block_time_ms(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let timestamp = state_transaction.block_unix_timestamp_ms();
    if timestamp == 0 || timestamp == u64::MAX {
        return Err(invalid_parameter(
            "authoritative reputation operations require a finite non-zero block timestamp",
        ));
    }
    Ok(timestamp)
}
fn read_policy_history(
    world: &impl WorldReadOnly,
    digest: &[u8; 32],
) -> Result<Option<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    read_policy_history_with_current(world, digest, None)
}
fn read_policy_history_for_current(
    world: &impl WorldReadOnly,
    digest: &[u8; 32],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    read_policy_history_with_current(world, digest, Some(current))
}
fn read_policy_history_with_current(
    world: &impl WorldReadOnly,
    digest: &[u8; 32],
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&policy_history_key(digest))
    else {
        return Ok(None);
    };
    let record: ReputationJournalAuthorityPolicyRecordV1 = match current {
        Some(current) => {
            decode_state_for_current(bytes, "reputation recorder-policy history", current)
        }
        None => decode_state(bytes, "reputation recorder-policy history"),
    }?;
    record.validate().map_err(|error| {
        corrupt_state(format!(
            "stored reputation recorder-policy history is invalid: {error}"
        ))
    })?;
    if usize::try_from(record.policy.revision)
        .ok()
        .is_none_or(|revision| revision > REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1)
    {
        return Err(corrupt_state(
            "reputation recorder-policy revision exceeds the V1 history bound",
        ));
    }
    if &record.policy_digest != digest {
        return Err(corrupt_state(
            "reputation recorder-policy history key does not match its digest",
        ));
    }
    Ok(Some(record))
}
fn validate_policy_predecessor(
    world: &impl WorldReadOnly,
    record: &ReputationJournalAuthorityPolicyRecordV1,
) -> Result<(), InstructionExecutionError> {
    let Some(predecessor_digest) = record.policy.predecessor_policy_digest else {
        if record.policy.revision == 1 {
            return Ok(());
        }
        return Err(corrupt_state(
            "reputation recorder policy is missing its predecessor digest",
        ));
    };
    let predecessor = read_policy_history(world, &predecessor_digest)?.ok_or_else(|| {
        corrupt_state("reputation recorder policy predecessor is missing from immutable history")
    })?;
    if predecessor.policy.revision.checked_add(1) != Some(record.policy.revision)
        || predecessor.activated_at_unix_ms > record.activated_at_unix_ms
    {
        return Err(corrupt_state(
            "reputation recorder policy predecessor revision or activation order is invalid",
        ));
    }
    Ok(())
}
fn validate_policy_predecessor_for_current(
    world: &impl WorldReadOnly,
    record: &ReputationJournalAuthorityPolicyRecordV1,
    retained: &crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<(), InstructionExecutionError> {
    let Some(predecessor_digest) = record.policy.predecessor_policy_digest else {
        if record.policy.revision == 1 {
            return Ok(());
        }
        return Err(corrupt_state(
            "reputation recorder policy is missing its predecessor digest",
        ));
    };
    let mut transient = reputation_current_from_resident(retained.resident_bytes())?;
    let predecessor = read_policy_history_for_current(world, &predecessor_digest, &mut transient)?
        .ok_or_else(|| {
            corrupt_state(
                "reputation recorder policy predecessor is missing from immutable history",
            )
        })?;
    if predecessor.policy.revision.checked_add(1) != Some(record.policy.revision)
        || predecessor.activated_at_unix_ms > record.activated_at_unix_ms
    {
        return Err(corrupt_state(
            "reputation recorder policy predecessor revision or activation order is invalid",
        ));
    }
    Ok(())
}
fn read_active_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(active_policy_key()) else {
        if state_prefix_has_any(world, POLICY_HISTORY_STATE_KEY_PREFIX) {
            return Err(corrupt_state(
                "reputation recorder-policy history exists without an active policy",
            ));
        }
        return Ok(None);
    };
    let record: ReputationJournalAuthorityPolicyRecordV1 =
        decode_state(bytes, "active reputation recorder policy")?;
    record.validate().map_err(|error| {
        corrupt_state(format!(
            "stored active reputation recorder policy is invalid: {error}"
        ))
    })?;
    let history = read_policy_history(world, &record.policy_digest)?.ok_or_else(|| {
        corrupt_state("active reputation recorder policy is missing immutable history")
    })?;
    if history != record {
        return Err(corrupt_state(
            "active reputation recorder policy differs from immutable history",
        ));
    }
    validate_policy_predecessor(world, &record)?;
    Ok(Some(record))
}
fn read_active_policy_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(active_policy_key()) else {
        if state_prefix_has_any(world, POLICY_HISTORY_STATE_KEY_PREFIX) {
            return Err(corrupt_state(
                "reputation recorder-policy history exists without an active policy",
            ));
        }
        return Ok(None);
    };
    let record: ReputationJournalAuthorityPolicyRecordV1 =
        decode_state_for_current(bytes, "active reputation recorder policy", current)?;
    record.validate().map_err(|error| {
        corrupt_state(format!(
            "stored active reputation recorder policy is invalid: {error}"
        ))
    })?;
    let mut history_current = reputation_current_from_resident(current.resident_bytes())?;
    let history =
        read_policy_history_for_current(world, &record.policy_digest, &mut history_current)?
            .ok_or_else(|| {
                corrupt_state("active reputation recorder policy is missing immutable history")
            })?;
    if history != record {
        return Err(corrupt_state(
            "active reputation recorder policy differs from immutable history",
        ));
    }
    drop(history);
    validate_policy_predecessor_for_current(world, &record, current)?;
    Ok(Some(record))
}
/// Return the complete active recorder-policy predecessor chain in ascending
/// revision order from one immutable world view.
///
/// This is a crate-internal capture primitive for the finalized reputation archive. It never
/// substitutes current state for the supplied view and fails closed when the active record, any
/// predecessor artifact, or the direct revision/digest/activation ordering is malformed.
/// `maximum_records` is a hard allocation and traversal bound.
pub(crate) fn read_reputation_authority_policy_history(
    world: &impl WorldReadOnly,
    maximum_records: usize,
) -> Result<Vec<ReputationJournalAuthorityPolicyRecordV1>, InstructionExecutionError> {
    if maximum_records == 0
        || maximum_records > REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1
    {
        return Err(invalid_parameter(
            "reputation recorder-policy history bound must be within the V1 revision ceiling",
        ));
    }
    let mut current = read_active_policy(world)?
        .ok_or_else(|| invalid_parameter("SoraFS reputation recorder policy is not configured"))?;
    let mut descending = Vec::new();
    loop {
        if descending.len() >= maximum_records {
            return Err(corrupt_state(
                "reputation recorder-policy history exceeds the finalized capture bound",
            ));
        }
        validate_policy_predecessor(world, &current)?;
        let revision = current.policy.revision;
        let predecessor_digest = current.policy.predecessor_policy_digest;
        descending.push(current);
        match (revision, predecessor_digest) {
            (1, None) => break,
            (1, Some(_)) => {
                return Err(corrupt_state(
                    "first reputation recorder policy unexpectedly has a predecessor",
                ));
            }
            (_, None) => {
                return Err(corrupt_state(
                    "reputation recorder-policy history ended before revision one",
                ));
            }
            (_, Some(predecessor_digest)) => {
                let predecessor =
                    read_policy_history(world, &predecessor_digest)?.ok_or_else(|| {
                        corrupt_state(
                            "reputation recorder-policy predecessor is missing from immutable history",
                        )
                    })?;
                let successor = descending.last().ok_or_else(|| {
                    corrupt_state("reputation recorder-policy traversal lost its current successor")
                })?;
                if predecessor.policy.revision.checked_add(1) != Some(successor.policy.revision)
                    || successor.policy.predecessor_policy_digest != Some(predecessor.policy_digest)
                    || predecessor.activated_at_unix_ms > successor.activated_at_unix_ms
                {
                    return Err(corrupt_state(
                        "reputation recorder-policy history is skipped, substituted, or non-monotonic",
                    ));
                }
                current = predecessor;
            }
        }
    }
    descending.reverse();
    Ok(descending)
}
fn read_policy_at_source_time(
    world: &impl WorldReadOnly,
    active: ReputationJournalAuthorityPolicyRecordV1,
    policy_digest: [u8; 32],
    source_time_unix_ms: u64,
) -> Result<ReputationJournalAuthorityPolicyRecordV1, InstructionExecutionError> {
    let requested = read_policy_history(world, &policy_digest)?.ok_or_else(|| {
        invalid_parameter("reputation entry references unknown recorder-policy history")
    })?;
    if requested.policy.revision > active.policy.revision {
        return Err(invalid_parameter(
            "reputation entry references a recorder policy newer than the active policy",
        ));
    }
    let mut cursor = active;
    let mut successor_activated_at = None;
    let mut traversed = 0usize;
    loop {
        if traversed >= REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1 {
            return Err(corrupt_state(
                "reputation recorder-policy lineage exceeds the V1 history bound",
            ));
        }
        traversed += 1;
        validate_policy_predecessor(world, &cursor)?;
        if cursor.policy.revision == requested.policy.revision {
            if cursor != requested {
                return Err(corrupt_state(
                    "reputation recorder-policy history is not on the active predecessor chain",
                ));
            }
            if source_time_unix_ms < cursor.activated_at_unix_ms
                || successor_activated_at
                    .is_some_and(|activated_at| source_time_unix_ms >= activated_at)
            {
                return Err(invalid_parameter(
                    "reputation source observation falls outside its recorder-policy activation interval",
                ));
            }
            return Ok(cursor);
        }
        let predecessor_digest = cursor.policy.predecessor_policy_digest.ok_or_else(|| {
            corrupt_state(
                "active reputation recorder-policy lineage ended before the requested revision",
            )
        })?;
        successor_activated_at = Some(cursor.activated_at_unix_ms);
        cursor = read_policy_history(world, &predecessor_digest)?.ok_or_else(|| {
            corrupt_state("active reputation recorder-policy predecessor history is missing")
        })?;
    }
}
fn read_policy_at_source_time_for_current(
    world: &impl WorldReadOnly,
    active: ReputationJournalAuthorityPolicyRecordV1,
    policy_digest: [u8; 32],
    source_time_unix_ms: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
    retained_base_bytes: usize,
) -> Result<ReputationJournalAuthorityPolicyRecordV1, InstructionExecutionError> {
    let mut cursor = active;
    let mut cursor_allocation = current
        .resident_bytes()
        .checked_sub(retained_base_bytes)
        .ok_or(QueryExecutionFail::CapacityLimit)
        .map_err(InstructionExecutionError::Query)?;
    let mut successor_activated_at = None;
    let mut traversed = 0usize;
    loop {
        if traversed >= REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1 {
            return Err(corrupt_state(
                "reputation recorder-policy lineage exceeds the V1 history bound",
            ));
        }
        traversed += 1;
        let predecessor = match cursor.policy.predecessor_policy_digest {
            Some(predecessor_digest) => {
                let before = current.resident_bytes();
                let predecessor =
                    read_policy_history_for_current(world, &predecessor_digest, current)?
                        .ok_or_else(|| {
                            corrupt_state(
                                "active reputation recorder-policy predecessor history is missing",
                            )
                        })?;
                let predecessor_allocation = current
                    .resident_bytes()
                    .checked_sub(before)
                    .ok_or(QueryExecutionFail::CapacityLimit)
                    .map_err(InstructionExecutionError::Query)?;
                if predecessor.policy.revision.checked_add(1) != Some(cursor.policy.revision)
                    || cursor.policy.predecessor_policy_digest != Some(predecessor.policy_digest)
                    || predecessor.activated_at_unix_ms > cursor.activated_at_unix_ms
                {
                    return Err(corrupt_state(
                        "reputation recorder-policy predecessor revision or activation order is invalid",
                    ));
                }
                Some((predecessor, predecessor_allocation))
            }
            None if cursor.policy.revision == 1 => None,
            None => {
                return Err(corrupt_state(
                    "reputation recorder policy is missing its predecessor digest",
                ));
            }
        };
        if cursor.policy_digest == policy_digest {
            if source_time_unix_ms < cursor.activated_at_unix_ms
                || successor_activated_at
                    .is_some_and(|activated_at| source_time_unix_ms >= activated_at)
            {
                return Err(invalid_parameter(
                    "reputation source observation falls outside its recorder-policy activation interval",
                ));
            }
            drop(predecessor);
            let retained = retained_base_bytes
                .checked_add(cursor_allocation)
                .ok_or(QueryExecutionFail::CapacityLimit)
                .map_err(InstructionExecutionError::Query)?;
            reset_reputation_current(current, retained)?;
            return Ok(cursor);
        }
        let Some((predecessor, predecessor_allocation)) = predecessor else {
            return Err(invalid_parameter(
                "reputation entry references unknown recorder-policy history",
            ));
        };
        successor_activated_at = Some(cursor.activated_at_unix_ms);
        drop(cursor);
        let retained = retained_base_bytes
            .checked_add(predecessor_allocation)
            .ok_or(QueryExecutionFail::CapacityLimit)
            .map_err(InstructionExecutionError::Query)?;
        reset_reputation_current(current, retained)?;
        cursor = predecessor;
        cursor_allocation = predecessor_allocation;
    }
}
fn read_journal_head(
    world: &impl WorldReadOnly,
) -> Result<Option<ReputationJournalHeadStateV1>, InstructionExecutionError> {
    read_journal_head_with_current(world, None)
}
fn read_journal_head_for_current(
    world: &impl WorldReadOnly,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ReputationJournalHeadStateV1>, InstructionExecutionError> {
    read_journal_head_with_current(world, Some(current))
}
fn read_journal_head_with_current(
    world: &impl WorldReadOnly,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ReputationJournalHeadStateV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(journal_head_key()) else {
        if state_prefix_has_any(world, EVENT_STATE_KEY_PREFIX)
            || state_prefix_has_any(world, EVENT_ID_STATE_KEY_PREFIX)
            || state_prefix_has_any(world, SOURCE_HEAD_STATE_KEY_PREFIX)
        {
            return Err(corrupt_state(
                "reputation journal indexes exist without a journal head",
            ));
        }
        return Ok(None);
    };
    let head: ReputationJournalHeadStateV1 = match current {
        Some(current) => decode_state_for_current(bytes, "reputation journal head", current),
        None => decode_state(bytes, "reputation journal head"),
    }?;
    if head.last_sequence == 0 || head.last_target_block_height == 0 {
        return Err(corrupt_state("stored reputation journal head is inert"));
    }
    Ok(Some(head))
}
fn read_event(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<ReputationJournalCommittedEventRecordV1>, InstructionExecutionError> {
    read_event_with_current(world, sequence, None)
}
fn read_event_for_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ReputationJournalCommittedEventRecordV1>, InstructionExecutionError> {
    read_event_with_current(world, sequence, Some(current))
}
fn read_event_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ReputationJournalCommittedEventRecordV1>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_state(
            "reputation journal sequence zero cannot be read",
        ));
    }
    let Some(bytes) = world.smart_contract_state().get(&event_key(sequence)) else {
        return Ok(None);
    };
    let record: ReputationJournalCommittedEventRecordV1 = match current {
        Some(current) => decode_state_for_current(bytes, "reputation committed event", current),
        None => decode_state(bytes, "reputation committed event"),
    }?;
    record
        .validate()
        .map_err(|error| corrupt_state(format!("stored reputation event is invalid: {error}")))?;
    if record.sequence != sequence {
        return Err(corrupt_state(
            "reputation event key does not match its global sequence",
        ));
    }
    Ok(Some(record))
}
fn read_event_id_sequence(
    world: &impl WorldReadOnly,
    event_id: ReputationJournalEventIdV1,
) -> Result<Option<u64>, InstructionExecutionError> {
    read_event_id_sequence_with_current(world, event_id, None)
}
fn read_event_id_sequence_for_current(
    world: &impl WorldReadOnly,
    event_id: ReputationJournalEventIdV1,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<u64>, InstructionExecutionError> {
    read_event_id_sequence_with_current(world, event_id, Some(current))
}
fn read_event_id_sequence_with_current(
    world: &impl WorldReadOnly,
    event_id: ReputationJournalEventIdV1,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<u64>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&event_id_key(event_id)) else {
        return Ok(None);
    };
    let sequence: u64 = match current {
        Some(current) => decode_state_for_current(bytes, "reputation event-id index", current),
        None => decode_state(bytes, "reputation event-id index"),
    }?;
    if sequence == 0 {
        return Err(corrupt_state(
            "reputation event-id index points to sequence zero",
        ));
    }
    Ok(Some(sequence))
}
fn read_source_head(
    world: &impl WorldReadOnly,
    source_id: ReputationJournalSourceIdV1,
) -> Result<Option<ReputationJournalSourceHeadV1>, InstructionExecutionError> {
    read_source_head_with_current(world, source_id, None)
}
fn read_source_head_for_current(
    world: &impl WorldReadOnly,
    source_id: ReputationJournalSourceIdV1,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<Option<ReputationJournalSourceHeadV1>, InstructionExecutionError> {
    read_source_head_with_current(world, source_id, Some(current))
}
fn read_source_head_with_current(
    world: &impl WorldReadOnly,
    source_id: ReputationJournalSourceIdV1,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<Option<ReputationJournalSourceHeadV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&source_head_key(source_id))
    else {
        return Ok(None);
    };
    let head: ReputationJournalSourceHeadV1 = match current {
        Some(current) => decode_state_for_current(bytes, "reputation source head", current),
        None => decode_state(bytes, "reputation source head"),
    }?;
    head.validate().map_err(|error| {
        corrupt_state(format!("stored reputation source head is invalid: {error}"))
    })?;
    Ok(Some(head))
}
fn validate_provider_binding(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
) -> Result<(), InstructionExecutionError> {
    if world.capacity_declarations().get(&provider_id).is_none() {
        return Err(invalid_parameter(format!(
            "reputation entry references unknown capacity provider {}",
            hex::encode(provider_id.as_bytes())
        )));
    }
    let Some(owner) = world.provider_owners().get(&provider_id) else {
        return Err(invalid_parameter(format!(
            "reputation entry references provider {} without an owner binding",
            hex::encode(provider_id.as_bytes())
        )));
    };
    if world.accounts().get(owner).is_none() {
        return Err(corrupt_state(format!(
            "reputation entry references provider {} whose owner account is missing",
            hex::encode(provider_id.as_bytes())
        )));
    }
    Ok(())
}
fn validate_event_successor(
    previous: Option<&ReputationJournalCommittedEventRecordV1>,
    current: &ReputationJournalCommittedEventRecordV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1 || current.event_index != 0 {
            return Err(corrupt_state(
                "reputation journal must begin at sequence one and block index zero",
            ));
        }
        return Ok(());
    };
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or_else(|| corrupt_state("reputation journal sequence overflow"))?;
    if current.sequence != expected_sequence {
        return Err(corrupt_state(
            "reputation journal sequence is not globally contiguous",
        ));
    }
    if current.recorded_at_unix_ms < previous.recorded_at_unix_ms {
        return Err(corrupt_state(
            "reputation journal committing timestamps are reordered",
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous.event_index.checked_add(1) == Some(current.event_index) =>
        {
            Ok(())
        }
        _ => Err(corrupt_state(
            "reputation journal block height or event index is not contiguous",
        )),
    }
}
fn validate_event_intrinsic_indexes(
    world: &impl WorldReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
) -> Result<(), InstructionExecutionError> {
    let active = read_active_policy(world)?.ok_or_else(|| {
        corrupt_state("reputation event exists without an active recorder policy")
    })?;
    let policy = read_policy_at_source_time(
        world,
        active,
        record.entry.authority_policy_digest,
        record.entry.source_time_unix_ms,
    )
    .map_err(|error| {
        if matches!(
            &error,
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        ) {
            error
        } else {
            corrupt_state(format!(
                "reputation event violates recorder-policy activation history: {error}"
            ))
        }
    })?;
    record
        .entry
        .validate_at_commit(&policy.policy, record.recorded_at_unix_ms)
        .map_err(|error| {
            corrupt_state(format!(
                "reputation event violates its immutable recorder policy: {error}"
            ))
        })?;
    let indexed_sequence = read_event_id_sequence(world, record.entry.event_id)?
        .ok_or_else(|| corrupt_state("reputation event is missing its event-id index"))?;
    if indexed_sequence != record.sequence {
        return Err(corrupt_state(
            "reputation event-id index points to another sequence",
        ));
    }
    Ok(())
}
fn validate_event_intrinsic_indexes_for_current(
    world: &impl WorldReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
    retained: &crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<(), InstructionExecutionError> {
    let retained_base_bytes = retained.resident_bytes();
    let mut transient = reputation_current_from_resident(retained_base_bytes)?;
    let active = read_active_policy_for_current(world, &mut transient)?.ok_or_else(|| {
        corrupt_state("reputation event exists without an active recorder policy")
    })?;
    let policy = read_policy_at_source_time_for_current(
        world,
        active,
        record.entry.authority_policy_digest,
        record.entry.source_time_unix_ms,
        &mut transient,
        retained_base_bytes,
    )
    .map_err(|error| {
        if matches!(
            &error,
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        ) {
            error
        } else {
            corrupt_state(format!(
                "reputation event violates recorder-policy activation history: {error}"
            ))
        }
    })?;
    record
        .entry
        .validate_at_commit(&policy.policy, record.recorded_at_unix_ms)
        .map_err(|error| {
            corrupt_state(format!(
                "reputation event violates its immutable recorder policy: {error}"
            ))
        })?;
    drop(policy);
    reset_reputation_current(&mut transient, retained_base_bytes)?;
    let indexed_sequence =
        read_event_id_sequence_for_current(world, record.entry.event_id, &mut transient)?
            .ok_or_else(|| corrupt_state("reputation event is missing its event-id index"))?;
    if indexed_sequence != record.sequence {
        return Err(corrupt_state(
            "reputation event-id index points to another sequence",
        ));
    }
    Ok(())
}
fn validate_provider_dispute_revision_edge(
    predecessor: &ReputationJournalCommittedEventRecordV1,
    successor: &ReputationJournalCommittedEventRecordV1,
) -> Result<(), InstructionExecutionError> {
    let (
        ReputationJournalPayloadV1::ProviderDispute(opened),
        ReputationJournalPayloadV1::ProviderDispute(resolved),
    ) = (&predecessor.entry.payload, &successor.entry.payload)
    else {
        return Err(corrupt_state(
            "reputation source revision edge crosses payload families",
        ));
    };
    if predecessor.sequence >= successor.sequence
        || predecessor.target_block_height > successor.target_block_height
        || (predecessor.target_block_height == successor.target_block_height
            && predecessor.event_index >= successor.event_index)
        || predecessor.recorded_at_unix_ms > successor.recorded_at_unix_ms
        || predecessor.entry.source_id != successor.entry.source_id
        || predecessor.entry.provider_id != successor.entry.provider_id
        || predecessor.entry.source_revision != 1
        || successor.entry.source_revision != 2
        || successor.entry.predecessor_event_id != Some(predecessor.entry.event_id)
        || opened.dispute_id != resolved.dispute_id
        || opened.kind != resolved.kind
        || opened.evidence_digest != resolved.evidence_digest
        || opened.submitted_at_unix_ms != resolved.submitted_at_unix_ms
        || !matches!(&opened.status, ProviderDisputeStatusV1::Opened)
        || !matches!(&resolved.status, ProviderDisputeStatusV1::Resolved(_))
    {
        return Err(corrupt_state(
            "reputation provider-dispute revision edge is missing or substituted",
        ));
    }
    Ok(())
}
fn read_source_predecessor(
    world: &impl WorldReadOnly,
    event_id: ReputationJournalEventIdV1,
) -> Result<ReputationJournalCommittedEventRecordV1, InstructionExecutionError> {
    let sequence = read_event_id_sequence(world, event_id)?.ok_or_else(|| {
        corrupt_state("reputation source predecessor is missing its event-id index")
    })?;
    let predecessor = read_event(world, sequence)?
        .ok_or_else(|| corrupt_state("reputation source predecessor event is missing"))?;
    if predecessor.entry.event_id != event_id {
        return Err(corrupt_state(
            "reputation source predecessor index resolves another event",
        ));
    }
    Ok(predecessor)
}
fn read_source_predecessor_for_current(
    world: &impl WorldReadOnly,
    event_id: ReputationJournalEventIdV1,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<ReputationJournalCommittedEventRecordV1, InstructionExecutionError> {
    let sequence =
        read_event_id_sequence_for_current(world, event_id, current)?.ok_or_else(|| {
            corrupt_state("reputation source predecessor is missing its event-id index")
        })?;
    let predecessor = read_event_for_current(world, sequence, current)?
        .ok_or_else(|| corrupt_state("reputation source predecessor event is missing"))?;
    if predecessor.entry.event_id != event_id {
        return Err(corrupt_state(
            "reputation source predecessor index resolves another event",
        ));
    }
    Ok(predecessor)
}
fn validate_event_indexes(
    world: &impl WorldReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
) -> Result<(), InstructionExecutionError> {
    validate_event_intrinsic_indexes(world, record)?;
    let source_head = read_source_head(world, record.entry.source_id)?
        .ok_or_else(|| corrupt_state("reputation event is missing its source head"))?;
    if source_head.source_kind != record.entry.source_kind()
        || source_head.sequence < record.sequence
        || source_head.source_revision < record.entry.source_revision
    {
        return Err(corrupt_state(
            "reputation source head regresses behind a committed event",
        ));
    }
    if source_head.sequence == record.sequence {
        if source_head.source_revision != record.entry.source_revision
            || source_head.event_id != record.entry.event_id
        {
            return Err(corrupt_state(
                "reputation source head does not identify its latest event",
            ));
        }
        if record.entry.source_revision == 2 {
            let predecessor_event_id = record.entry.predecessor_event_id.ok_or_else(|| {
                corrupt_state("reputation source revision two has no predecessor event id")
            })?;
            let predecessor = read_source_predecessor(world, predecessor_event_id)?;
            validate_event_intrinsic_indexes(world, &predecessor)?;
            validate_provider_dispute_revision_edge(&predecessor, record)?;
        }
    } else {
        let terminal = read_event(world, source_head.sequence)?.ok_or_else(|| {
            corrupt_state("reputation source head points to a missing terminal event")
        })?;
        if terminal.entry.source_id != record.entry.source_id
            || terminal.entry.provider_id != record.entry.provider_id
            || source_head.source_kind != terminal.entry.source_kind()
            || source_head.source_revision != terminal.entry.source_revision
            || source_head.event_id != terminal.entry.event_id
        {
            return Err(corrupt_state(
                "reputation source head does not form an exact predecessor chain",
            ));
        }
        validate_event_intrinsic_indexes(world, &terminal)?;
        validate_provider_dispute_revision_edge(record, &terminal)?;
    }
    Ok(())
}
fn validate_event_indexes_for_current(
    world: &impl WorldReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
    retained: &crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<(), InstructionExecutionError> {
    validate_event_intrinsic_indexes_for_current(world, record, retained)?;
    let mut transient = reputation_current_from_resident(retained.resident_bytes())?;
    let source_head = read_source_head_for_current(world, record.entry.source_id, &mut transient)?
        .ok_or_else(|| corrupt_state("reputation event is missing its source head"))?;
    if source_head.source_kind != record.entry.source_kind()
        || source_head.sequence < record.sequence
        || source_head.source_revision < record.entry.source_revision
    {
        return Err(corrupt_state(
            "reputation source head regresses behind a committed event",
        ));
    }
    if source_head.sequence == record.sequence {
        if source_head.source_revision != record.entry.source_revision
            || source_head.event_id != record.entry.event_id
        {
            return Err(corrupt_state(
                "reputation source head does not identify its latest event",
            ));
        }
        if record.entry.source_revision == 2 {
            let predecessor_event_id = record.entry.predecessor_event_id.ok_or_else(|| {
                corrupt_state("reputation source revision two has no predecessor event id")
            })?;
            let predecessor =
                read_source_predecessor_for_current(world, predecessor_event_id, &mut transient)?;
            validate_event_intrinsic_indexes_for_current(world, &predecessor, &transient)?;
            validate_provider_dispute_revision_edge(&predecessor, record)?;
        }
    } else {
        let terminal = read_event_for_current(world, source_head.sequence, &mut transient)?
            .ok_or_else(|| {
                corrupt_state("reputation source head points to a missing terminal event")
            })?;
        if terminal.entry.source_id != record.entry.source_id
            || terminal.entry.provider_id != record.entry.provider_id
            || source_head.source_kind != terminal.entry.source_kind()
            || source_head.source_revision != terminal.entry.source_revision
            || source_head.event_id != terminal.entry.event_id
        {
            return Err(corrupt_state(
                "reputation source head does not form an exact predecessor chain",
            ));
        }
        validate_event_intrinsic_indexes_for_current(world, &terminal, &transient)?;
        validate_provider_dispute_revision_edge(record, &terminal)?;
    }
    Ok(())
}
fn ensure_no_event_after_head(
    world: &impl WorldReadOnly,
    head: Option<ReputationJournalHeadStateV1>,
) -> Result<(), InstructionExecutionError> {
    let prefix = StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid");
    let first = world
        .smart_contract_state()
        .range(prefix..)
        .next()
        .and_then(|(key, _)| {
            key.to_string()
                .starts_with(EVENT_STATE_KEY_PREFIX)
                .then_some(key)
        });
    let head = match (head, first) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(corrupt_state(
                "reputation journal contains events without a journal head",
            ));
        }
        (Some(head), Some(key)) if key == &event_key(1) => head,
        (Some(_), _) => {
            return Err(corrupt_state(
                "reputation journal does not begin at global sequence one",
            ));
        }
    };
    let terminal_key = event_key(head.last_sequence);
    for (key, _) in world.smart_contract_state().range(terminal_key.clone()..) {
        if !key.to_string().starts_with(EVENT_STATE_KEY_PREFIX) {
            break;
        }
        if key == &terminal_key {
            continue;
        }
        return Err(corrupt_state(
            "reputation event exists beyond the journal head",
        ));
    }
    Ok(())
}
fn validate_journal_head(
    world: &impl WorldReadOnly,
) -> Result<Option<ReputationJournalHeadStateV1>, InstructionExecutionError> {
    // The journal and its immutable policy history are one authoritative
    // state machine; neither may remain usable after losing the active policy.
    read_active_policy(world)?;
    let head = read_journal_head(world)?;
    ensure_no_event_after_head(world, head)?;
    let Some(head) = head else {
        return Ok(None);
    };
    let terminal = read_event(world, head.last_sequence)?
        .ok_or_else(|| corrupt_state("reputation journal head points to a missing event"))?;
    if terminal.target_block_height != head.last_target_block_height
        || terminal.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "reputation journal head differs from its terminal event",
        ));
    }
    let predecessor = if terminal.sequence == 1 {
        None
    } else {
        let predecessor_sequence = terminal.sequence - 1;
        let predecessor = read_event(world, predecessor_sequence)?.ok_or_else(|| {
            corrupt_state(format!(
                "reputation journal terminal event is missing predecessor sequence {predecessor_sequence}"
            ))
        })?;
        validate_event_indexes(world, &predecessor)?;
        Some(predecessor)
    };
    validate_event_successor(predecessor.as_ref(), &terminal)?;
    validate_event_indexes(world, &terminal)?;
    Ok(Some(head))
}
fn validate_journal_head_for_query(
    world: &impl WorldReadOnly,
) -> Result<Option<ReputationJournalHeadStateV1>, InstructionExecutionError> {
    // Prove the policy machine independently, then release it before journal
    // validation. Neither output retains policy state.
    let mut policy_current = reputation_current_from_resident(0)?;
    read_active_policy_for_current(world, &mut policy_current)?;
    let mut head_current = reputation_current_from_resident(0)?;
    let head = read_journal_head_for_current(world, &mut head_current)?;
    ensure_no_event_after_head(world, head)?;
    let Some(head) = head else {
        return Ok(None);
    };
    let mut terminal_current = reputation_current_from_resident(head_current.resident_bytes())?;
    let terminal = read_event_for_current(world, head.last_sequence, &mut terminal_current)?
        .ok_or_else(|| corrupt_state("reputation journal head points to a missing event"))?;
    if terminal.target_block_height != head.last_target_block_height
        || terminal.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "reputation journal head differs from its terminal event",
        ));
    }
    if terminal.sequence == 1 {
        validate_event_successor(None, &terminal)?;
    } else {
        let predecessor_sequence = terminal.sequence - 1;
        let mut predecessor_current =
            reputation_current_from_resident(terminal_current.resident_bytes())?;
        let predecessor =
            read_event_for_current(world, predecessor_sequence, &mut predecessor_current)?
                .ok_or_else(|| {
                    corrupt_state(format!(
                        "reputation journal terminal event is missing predecessor sequence {predecessor_sequence}"
                    ))
                })?;
        validate_event_indexes_for_current(world, &predecessor, &predecessor_current)?;
        validate_event_successor(Some(&predecessor), &terminal)?;
    }
    validate_event_indexes_for_current(world, &terminal, &terminal_current)?;
    Ok(Some(head))
}
fn exact_entry_replay(
    world: &impl WorldReadOnly,
    entry: &ReputationJournalEntryV1,
) -> Result<Option<u64>, InstructionExecutionError> {
    let journal_head = validate_journal_head(world)?;
    let indexed = read_event_id_sequence(world, entry.event_id)?;
    let source_head = read_source_head(world, entry.source_id)?;
    match indexed {
        Some(sequence) => {
            if journal_head.is_none_or(|head| sequence > head.last_sequence) {
                return Err(corrupt_state(
                    "reputation event-id index points beyond the journal head",
                ));
            }
            let record = read_event(world, sequence)?.ok_or_else(|| {
                corrupt_state("reputation event-id index points to a missing event")
            })?;
            if &record.entry != entry {
                return Err(corrupt_state(
                    "reputation event-id index aliases different canonical content",
                ));
            }
            validate_event_indexes(world, &record)?;
            Ok(Some(sequence))
        }
        None => {
            if source_head.is_some() {
                return Err(invalid_parameter(
                    "reputation source revision is already occupied by different content",
                ));
            }
            Ok(None)
        }
    }
}
fn validate_new_source_revision(
    world: &impl WorldReadOnly,
    entry: &ReputationJournalEntryV1,
) -> Result<(), InstructionExecutionError> {
    if read_event_id_sequence(world, entry.event_id)?.is_some() {
        return Err(corrupt_state(
            "new reputation entry unexpectedly has an event-id index",
        ));
    }
    match (
        entry.source_revision,
        read_source_head(world, entry.source_id)?,
    ) {
        (1, None) => Ok(()),
        (1, Some(_)) => Err(invalid_parameter(
            "reputation source revision one is already occupied",
        )),
        (2, Some(head))
            if head.source_kind == entry.source_kind()
                && head.source_revision == 1
                && entry.predecessor_event_id == Some(head.event_id) =>
        {
            let predecessor = read_event(world, head.sequence)?.ok_or_else(|| {
                corrupt_state("reputation source head points to a missing predecessor")
            })?;
            if predecessor.entry.event_id != head.event_id
                || predecessor.entry.source_id != entry.source_id
                || predecessor.entry.provider_id != entry.provider_id
            {
                return Err(corrupt_state(
                    "reputation source predecessor binding is corrupt",
                ));
            }
            Ok(())
        }
        (2, Some(_)) => Err(invalid_parameter(
            "reputation revision two does not extend the exact source head",
        )),
        (2, None) => Err(invalid_parameter(
            "reputation revision two is missing its committed predecessor",
        )),
        _ => Err(invalid_parameter(
            "reputation source revision is outside the first-release lifecycle",
        )),
    }
}
fn validate_entry_commit_context(
    world: &impl WorldReadOnly,
    entry: &ReputationJournalEntryV1,
    recorded_at_unix_ms: u64,
) -> Result<(), InstructionExecutionError> {
    let active = read_active_policy(world)?
        .ok_or_else(|| invalid_parameter("SoraFS reputation recorder policy is not configured"))?;
    if active.activated_at_unix_ms > recorded_at_unix_ms {
        return Err(corrupt_state(
            "active reputation policy activation is later than the executing block",
        ));
    }
    let policy = read_policy_at_source_time(
        world,
        active,
        entry.authority_policy_digest,
        entry.source_time_unix_ms,
    )?;
    entry
        .validate_at_commit(&policy.policy, recorded_at_unix_ms)
        .map_err(|error| {
            invalid_parameter(format!(
                "reputation entry does not match its source-time recorder policy: {error}"
            ))
        })
}
struct PreparedReputationAppend {
    sequence: u64,
    writes: Vec<(StatePath, Vec<u8>)>,
    event: SorafsReputationJournalEntryCommittedV1,
}
impl PreparedReputationAppend {
    fn publish(self, tx: &mut StateTransaction<'_, '_>) {
        for (key, bytes) in self.writes {
            tx.world.smart_contract_state.insert(key, bytes);
        }
        tx.world
            .emit_events(Some(SorafsGatewayEvent::ReputationJournal(
                SorafsReputationJournalEvent::EntryCommitted(self.event),
            )));
    }
}
fn append_validated_entry(
    tx: &mut StateTransaction<'_, '_>,
    entry: ReputationJournalEntryV1,
) -> Result<u64, InstructionExecutionError> {
    let prepared = prepare_validated_entry(tx, entry)?;
    let sequence = prepared.sequence;
    prepared.publish(tx);
    Ok(sequence)
}
fn prepare_validated_entry(
    state_transaction: &StateTransaction<'_, '_>,
    entry: ReputationJournalEntryV1,
) -> Result<PreparedReputationAppend, InstructionExecutionError> {
    let recorded_at_unix_ms = block_time_ms(state_transaction)?;
    validate_entry_commit_context(state_transaction.world(), &entry, recorded_at_unix_ms)?;
    validate_new_source_revision(state_transaction.world(), &entry)?;
    let head = validate_journal_head(state_transaction.world())?;
    let committed_parent_height = u64::try_from(state_transaction.block_hashes().len())
        .map_err(|_| corrupt_state("committed reputation parent height does not fit into u64"))?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_state("reputation event target block height overflow"))?;
    if target_block_height != state_transaction._curr_block.height().get() {
        return Err(corrupt_state(
            "reputation event target height differs from the executing block",
        ));
    }
    let (sequence, event_index, previous) = match head {
        None => (1, 0, None),
        Some(head) => {
            let previous =
                read_event(state_transaction.world(), head.last_sequence)?.ok_or_else(|| {
                    corrupt_state("reputation journal head points to a missing event")
                })?;
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("reputation journal sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("reputation block event-index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_state(
                        "reputation event target height regressed behind the journal head",
                    ));
                }
            };
            (sequence, event_index, Some(previous))
        }
    };
    let record = ReputationJournalCommittedEventRecordV1 {
        sequence,
        target_block_height,
        event_index,
        recorded_at_unix_ms,
        entry: entry.clone(),
    };
    record
        .validate()
        .map_err(|error| invalid_parameter(format!("invalid reputation journal entry: {error}")))?;
    validate_event_successor(previous.as_ref(), &record)?;
    let next_source_head = ReputationJournalSourceHeadV1 {
        source_kind: entry.source_kind(),
        source_revision: entry.source_revision,
        event_id: entry.event_id,
        sequence,
    };
    next_source_head
        .validate()
        .map_err(|error| corrupt_state(format!("invalid next reputation source head: {error}")))?;
    let next_head = ReputationJournalHeadStateV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    let event_bytes = encode_state(&record, "reputation committed event")?;
    let event_id_bytes = encode_state(&sequence, "reputation event-id index")?;
    let source_head_bytes = encode_state(&next_source_head, "reputation source head")?;
    let journal_head_bytes = encode_state(&next_head, "reputation journal head")?;
    if state_transaction
        .world
        .smart_contract_state
        .get(&event_key(sequence))
        .is_some()
        || state_transaction
            .world
            .smart_contract_state
            .get(&event_id_key(entry.event_id))
            .is_some()
    {
        return Err(corrupt_state(
            "reputation append would overwrite an authoritative event index",
        ));
    }
    let event = SorafsReputationJournalEntryCommittedV1 {
        sequence,
        event_id: entry.event_id,
        source_id: entry.source_id,
        source_kind: entry.source_kind(),
        source_revision: entry.source_revision,
        provider_id: entry.provider_id,
        policy_digest: entry.authority_policy_digest,
        authority: entry.recorded_by.clone(),
        source_time_unix_ms: entry.source_time_unix_ms,
        recorded_at_unix_ms,
    };
    Ok(PreparedReputationAppend {
        sequence,
        writes: vec![
            (event_key(sequence), event_bytes),
            (event_id_key(entry.event_id), event_id_bytes),
            (source_head_key(entry.source_id), source_head_bytes),
            (journal_head_key().clone(), journal_head_bytes),
        ],
        event,
    })
}

fn validate_new_entry(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    entry: &ReputationJournalEntryV1,
    expected_kind: ReputationJournalSourceKindV1,
) -> Result<(), InstructionExecutionError> {
    let now = block_time_ms(state_transaction)?;
    if entry.source_kind() != expected_kind {
        return Err(invalid_parameter(format!(
            "reputation instruction accepts only {expected_kind:?} entries"
        )));
    }
    validate_entry_commit_context(state_transaction.world(), entry, now)?;
    if &entry.recorded_by != authority {
        return Err(invalid_parameter(
            "reputation entry recorded_by must equal the transaction authority",
        ));
    }
    validate_provider_binding(state_transaction.world(), entry.provider_id)
}
fn execute_standalone_append(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    entry: ReputationJournalEntryV1,
    expected_kind: ReputationJournalSourceKindV1,
) -> Result<(), InstructionExecutionError> {
    if expected_kind == ReputationJournalSourceKindV1::StreamToken {
        return Err(invalid_parameter(
            "stream-token append requires its native source delivery owner",
        ));
    }
    require_permission(state_transaction, authority, CAN_RECORD_ENTRY)?;
    entry.validate().map_err(|error| {
        invalid_parameter(format!("invalid canonical reputation entry: {error}"))
    })?;
    if entry.source_kind() != expected_kind {
        return Err(invalid_parameter(format!(
            "reputation instruction accepts only {expected_kind:?} entries"
        )));
    }
    if exact_entry_replay(state_transaction.world(), &entry)?.is_some() {
        if &entry.recorded_by != authority {
            return Err(invalid_parameter(
                "idempotent reputation replay authority differs from recorded_by",
            ));
        }
        return Ok(());
    }
    validate_new_entry(state_transaction, authority, &entry, expected_kind)?;
    append_validated_entry(state_transaction, entry)?;
    Ok(())
}
fn provider_dispute_kind(kind: u8) -> Result<ProviderDisputeKindV1, InstructionExecutionError> {
    match kind {
        1 => Ok(ProviderDisputeKindV1::ReplicationShortfall),
        2 => Ok(ProviderDisputeKindV1::UptimeBreach),
        3 => Ok(ProviderDisputeKindV1::ProofFailure),
        4 => Ok(ProviderDisputeKindV1::FeeDispute),
        255 => Ok(ProviderDisputeKindV1::Other),
        _ => Err(invalid_parameter(format!(
            "capacity dispute kind {kind} is outside the canonical V1 vocabulary"
        ))),
    }
}
fn opened_dispute_entry(
    world: &impl WorldReadOnly,
    record: &CapacityDisputeRecord,
) -> Result<Option<ReputationJournalEntryV1>, InstructionExecutionError> {
    let source_id = ReputationJournalSourceIdV1::for_provider_dispute(record.dispute_id);
    let Some(source_head) = read_source_head(world, source_id)? else {
        return Ok(None);
    };
    let latest = read_event(world, source_head.sequence)?
        .ok_or_else(|| corrupt_state("provider-dispute source head points to a missing event"))?;
    let opened = if latest.entry.source_revision == 1 {
        latest
    } else if latest.entry.source_revision == 2 {
        let predecessor = latest.entry.predecessor_event_id.ok_or_else(|| {
            corrupt_state("resolved provider dispute has no predecessor event id")
        })?;
        let sequence = read_event_id_sequence(world, predecessor)?.ok_or_else(|| {
            corrupt_state("resolved provider dispute predecessor has no event-id index")
        })?;
        read_event(world, sequence)?.ok_or_else(|| {
            corrupt_state("resolved provider dispute predecessor event is missing")
        })?
    } else {
        return Err(corrupt_state(
            "provider-dispute source head has an unsupported revision",
        ));
    };
    validate_event_indexes(world, &opened)?;
    let ReputationJournalPayloadV1::ProviderDispute(dispute) = &opened.entry.payload else {
        return Err(corrupt_state(
            "provider-dispute source head points to another source family",
        ));
    };
    if opened.entry.source_revision != 1
        || opened.entry.provider_id != record.provider_id
        || dispute.dispute_id != record.dispute_id
        || dispute.kind != provider_dispute_kind(record.kind)?
        || dispute.evidence_digest != record.evidence.digest
        || dispute.submitted_at_unix_ms / 1_000 != record.submitted_epoch
        || !matches!(&dispute.status, ProviderDisputeStatusV1::Opened)
    {
        return Err(corrupt_state(
            "capacity dispute differs from its authoritative opened journal entry",
        ));
    }
    match (&record.status, source_head.source_revision) {
        (CapacityDisputeStatus::Pending, 1) => {}
        (CapacityDisputeStatus::Resolved(resolution), 2) => {
            let terminal = read_event(world, source_head.sequence)?.ok_or_else(|| {
                corrupt_state("resolved capacity dispute is missing its terminal journal event")
            })?;
            validate_event_indexes(world, &terminal)?;
            let ReputationJournalPayloadV1::ProviderDispute(terminal_payload) =
                &terminal.entry.payload
            else {
                return Err(corrupt_state(
                    "capacity-dispute terminal source has another payload family",
                ));
            };
            if terminal_payload.dispute_id != dispute.dispute_id
                || terminal_payload.kind != dispute.kind
                || terminal_payload.evidence_digest != dispute.evidence_digest
                || terminal_payload.submitted_at_unix_ms != dispute.submitted_at_unix_ms
            {
                return Err(corrupt_state(
                    "capacity-dispute terminal revision changes immutable opened material",
                ));
            }
            let ProviderDisputeStatusV1::Resolved(journal_resolution) = &terminal_payload.status
            else {
                return Err(corrupt_state(
                    "capacity-dispute terminal revision is not resolved",
                ));
            };
            if journal_resolution.outcome != resolution.outcome
                || journal_resolution.resolved_at_unix_ms / 1_000 != resolution.resolved_epoch
                || journal_resolution.rationale != resolution.notes
            {
                return Err(corrupt_state(
                    "capacity-dispute terminal journal differs from authoritative lifecycle state",
                ));
            }
        }
        _ => {
            return Err(corrupt_state(
                "capacity-dispute lifecycle and reputation source revision disagree",
            ));
        }
    }
    Ok(Some(opened.entry))
}
/// Validate an exact `RegisterCapacityDispute` replay against the already committed journal
/// lifecycle without manufacturing missing authoritative state.
pub(super) fn validate_capacity_dispute_opened_replay(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    record: &CapacityDisputeRecord,
) -> Result<(), InstructionExecutionError> {
    validate_journal_head(state_transaction.world())?;
    let opened = opened_dispute_entry(state_transaction.world(), record)?.ok_or_else(|| {
        corrupt_state(
            "existing capacity dispute is missing its authoritative opened journal revision",
        )
    })?;
    if &opened.recorded_by != authority {
        return Err(invalid_parameter(
            "idempotent capacity-dispute replay authority differs from the committed recorder",
        ));
    }
    Ok(())
}
/// Append the `Opened` reputation revision atomically with a new authoritative
/// `RegisterCapacityDispute` record.
pub(super) fn append_capacity_dispute_opened(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    record: &CapacityDisputeRecord,
) -> Result<(), InstructionExecutionError> {
    validate_journal_head(state_transaction.world())?;
    if opened_dispute_entry(state_transaction.world(), record)?.is_some() {
        return Err(corrupt_state(
            "capacity-dispute journal source exists before authoritative record insertion",
        ));
    }
    if !matches!(&record.status, CapacityDisputeStatus::Pending) {
        return Err(corrupt_state(
            "terminal capacity dispute is missing its authoritative opened journal revision",
        ));
    }
    let now = block_time_ms(state_transaction)?;
    if record.submitted_epoch != now / 1_000 {
        return Err(invalid_parameter(
            "capacity-dispute submitted_epoch must identify the exact committing block second",
        ));
    }
    let policy = read_active_policy(state_transaction.world())?
        .ok_or_else(|| invalid_parameter("SoraFS reputation recorder policy is not configured"))?;
    if &policy.policy.dispute_recorder_authority != authority {
        return Err(invalid_parameter(
            "capacity dispute transaction authority is not the governed dispute recorder",
        ));
    }
    validate_provider_binding(state_transaction.world(), record.provider_id)?;
    let entry = ReputationJournalEntryV1::try_new(
        record.provider_id,
        policy.policy_digest,
        authority.clone(),
        now,
        None,
        ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
            dispute_id: record.dispute_id,
            kind: provider_dispute_kind(record.kind)?,
            evidence_digest: record.evidence.digest,
            submitted_at_unix_ms: now,
            status: ProviderDisputeStatusV1::Opened,
        }),
    )
    .map_err(|error| {
        invalid_parameter(format!(
            "capacity dispute cannot form a canonical reputation entry: {error}"
        ))
    })?;
    append_validated_entry(state_transaction, entry)?;
    Ok(())
}
fn resolved_dispute_replay_matches(
    world: &impl WorldReadOnly,
    opened: &ReputationJournalEntryV1,
    instruction: &ResolveSorafsCapacityDispute,
    authority: &AccountId,
) -> Result<bool, InstructionExecutionError> {
    let source_head = read_source_head(world, opened.source_id)?
        .ok_or_else(|| corrupt_state("opened capacity dispute is missing its source head"))?;
    if source_head.source_revision == 1 {
        return Ok(false);
    }
    if source_head.source_revision != 2 {
        return Err(corrupt_state(
            "capacity-dispute reputation source exceeded its terminal revision",
        ));
    }
    let terminal = read_event(world, source_head.sequence)?.ok_or_else(|| {
        corrupt_state("resolved capacity-dispute source head points to a missing event")
    })?;
    validate_event_indexes(world, &terminal)?;
    let ReputationJournalPayloadV1::ProviderDispute(dispute) = &terminal.entry.payload else {
        return Err(corrupt_state(
            "resolved capacity-dispute source points to another source family",
        ));
    };
    let ProviderDisputeStatusV1::Resolved(resolution) = &dispute.status else {
        return Err(corrupt_state(
            "capacity-dispute revision two is not terminal",
        ));
    };
    Ok(terminal.entry.predecessor_event_id == Some(opened.event_id)
        && &terminal.entry.recorded_by == authority
        && terminal.entry.authority_policy_digest == instruction.expected_authority_policy_digest
        && resolution.outcome == instruction.outcome
        && resolution.decision_digest == instruction.decision_digest
        && resolution.rationale == instruction.rationale)
}
impl Execute for SetSorafsReputationJournalAuthorityPolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let origin = state_transaction
            .current_direct_reputation_policy_origin
            .take()
            .ok_or_else(|| {
                invalid_parameter("recorder policy requires exact direct signed source custody")
            })?;
        if &origin.execution().authority != authority
            || origin.execution().recorded_at_unix_ms != block_time_ms(state_transaction)?
        {
            return Err(invalid_parameter("recorder policy source custody mismatch"));
        }
        require_permission(state_transaction, authority, CAN_MANAGE_POLICY)?;
        let journal_head = validate_journal_head(state_transaction.world())?;
        self.policy.validate().map_err(|error| {
            invalid_parameter(format!("invalid reputation recorder policy: {error}"))
        })?;
        if usize::try_from(self.policy.revision)
            .ok()
            .is_none_or(|revision| revision > REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1)
        {
            return Err(invalid_parameter(
                "reputation recorder-policy revision exceeds the V1 history bound",
            ));
        }
        let policy_digest = self.policy.canonical_digest().map_err(|error| {
            invalid_parameter(format!("invalid reputation recorder policy: {error}"))
        })?;
        let current = read_active_policy(state_transaction.world())?;
        if let Some(existing) = read_policy_history(state_transaction.world(), &policy_digest)? {
            validate_policy_predecessor(state_transaction.world(), &existing)?;
            // The first commit owns the activation timestamp. A later exact
            // policy/authority replay must not manufacture another revision.
            if existing.policy == self.policy && &existing.activated_by == authority {
                return Ok(());
            }
            return Err(corrupt_state(
                "reputation recorder-policy history aliases different activation content",
            ));
        }
        for (label, recorder) in [
            ("PoR", &self.policy.por_recorder_authority),
            ("capacity-dispute", &self.policy.dispute_recorder_authority),
            ("stream-token", &self.policy.token_recorder_authority),
        ] {
            if state_transaction.world.accounts.get(recorder).is_none() {
                return Err(invalid_parameter(format!(
                    "{label} reputation recorder is not a registered account"
                )));
            }
        }
        let now = block_time_ms(state_transaction)?;
        let candidate = ReputationJournalAuthorityPolicyRecordV1::try_new(
            self.policy,
            authority.clone(),
            now,
            origin,
        )
        .map_err(|error| {
            invalid_parameter(format!(
                "invalid reputation recorder-policy activation: {error}"
            ))
        })?;
        if candidate.policy_digest != policy_digest {
            return Err(corrupt_state(
                "reputation recorder policy digest changed during canonical activation",
            ));
        }
        match current {
            None => {
                if candidate.policy.revision != 1
                    || candidate.policy.predecessor_policy_digest.is_some()
                {
                    return Err(invalid_parameter(
                        "first reputation recorder policy must be revision one without a predecessor",
                    ));
                }
            }
            Some(current) => {
                let expected_revision = current
                    .policy
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("reputation policy revision overflow"))?;
                if candidate.policy.revision != expected_revision {
                    return Err(invalid_parameter(format!(
                        "reputation policy revision {} must exactly follow active revision {}",
                        candidate.policy.revision, current.policy.revision
                    )));
                }
                if candidate.policy.predecessor_policy_digest != Some(current.policy_digest) {
                    return Err(invalid_parameter(
                        "reputation policy predecessor does not match the active policy digest",
                    ));
                }
            }
        }
        validate_policy_predecessor(state_transaction.world(), &candidate)?;
        if let Some(head) = journal_head {
            let terminal =
                read_event(state_transaction.world(), head.last_sequence)?.ok_or_else(|| {
                    corrupt_state("reputation journal head points to a missing event")
                })?;
            // Validated event times never decrease, and every source time is at most its
            // record time. This one terminal bound protects all retained policy intervals.
            if now <= terminal.recorded_at_unix_ms {
                return Err(invalid_parameter(
                    "reputation policy activation must follow every retained event commit time",
                ));
            }
        }
        if stream_token_delivery::source_time_watermark(state_transaction.world())?
            .is_some_and(|watermark| now <= watermark)
        {
            return Err(invalid_parameter(
                "reputation policy activation must follow every native delivery source time",
            ));
        }
        let encoded = encode_state(&candidate, "reputation recorder-policy activation")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(active_policy_key().clone(), encoded.clone());
        state_transaction
            .world
            .smart_contract_state
            .insert(policy_history_key(&candidate.policy_digest), encoded);
        state_transaction
            .world
            .emit_events(Some(SorafsGatewayEvent::ReputationJournal(
                SorafsReputationJournalEvent::PolicyActivated(
                    SorafsReputationJournalPolicyActivatedV1 {
                        policy_digest: candidate.policy_digest,
                        revision: candidate.policy.revision,
                        authority: authority.clone(),
                        occurred_at_unix_ms: now,
                    },
                ),
            )));
        Ok(())
    }
}
impl Execute for AppendSorafsPorReputationJournalEntry {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        execute_standalone_append(
            state_transaction,
            authority,
            self.entry,
            ReputationJournalSourceKindV1::Por,
        )
    }
}
impl Execute for AppendSorafsStreamTokenReputationJournalEntry {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        stream_token_delivery::execute_append(tx, authority, self.entry)
    }
}

impl Execute for ResolveSorafsCapacityDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_permission(state_transaction, authority, CAN_RESOLVE_DISPUTE)?;
        validate_journal_head(state_transaction.world())?;
        if self.decision_digest == [0; 32] {
            return Err(invalid_parameter(
                "capacity-dispute decision digest must be non-zero",
            ));
        }
        let record = state_transaction
            .world
            .capacity_disputes
            .get(&self.dispute_id)
            .cloned()
            .ok_or_else(|| {
                invalid_parameter(format!(
                    "capacity dispute {} is not registered",
                    hex::encode(self.dispute_id.as_bytes())
                ))
            })?;
        let opened =
            opened_dispute_entry(state_transaction.world(), &record)?.ok_or_else(|| {
                corrupt_state("capacity dispute has no authoritative opened reputation entry")
            })?;
        if matches!(&record.status, CapacityDisputeStatus::Resolved(_)) {
            if resolved_dispute_replay_matches(
                state_transaction.world(),
                &opened,
                &self,
                authority,
            )? {
                return Ok(());
            }
            return Err(invalid_parameter(
                "capacity dispute already has a different terminal decision",
            ));
        }
        let now = block_time_ms(state_transaction)?;
        let policy = read_active_policy(state_transaction.world())?.ok_or_else(|| {
            invalid_parameter("SoraFS reputation recorder policy is not configured")
        })?;
        if self.expected_authority_policy_digest != policy.policy_digest {
            return Err(invalid_parameter(
                "capacity-dispute resolution expected policy digest is stale",
            ));
        }
        if &policy.policy.dispute_recorder_authority != authority {
            return Err(invalid_parameter(
                "capacity-dispute resolution authority is not the governed dispute recorder",
            ));
        }
        let ReputationJournalPayloadV1::ProviderDispute(opened_payload) = &opened.payload else {
            return Err(corrupt_state(
                "capacity dispute opened entry has another source payload",
            ));
        };
        let terminal_entry = ReputationJournalEntryV1::try_new(
            record.provider_id,
            policy.policy_digest,
            authority.clone(),
            now,
            Some(opened.event_id),
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: record.dispute_id,
                kind: opened_payload.kind,
                evidence_digest: opened_payload.evidence_digest,
                submitted_at_unix_ms: opened_payload.submitted_at_unix_ms,
                status: ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
                    outcome: self.outcome,
                    resolved_at_unix_ms: now,
                    decision_digest: self.decision_digest,
                    rationale: self.rationale.clone(),
                }),
            }),
        )
        .map_err(|error| {
            invalid_parameter(format!(
                "invalid capacity-dispute terminal reputation entry: {error}"
            ))
        })?;
        validate_new_entry(
            state_transaction,
            authority,
            &terminal_entry,
            ReputationJournalSourceKindV1::ProviderDispute,
        )?;
        let resolved_epoch = now / 1_000;
        if resolved_epoch == 0 {
            return Err(invalid_parameter(
                "capacity-dispute resolution epoch must be non-zero",
            ));
        }
        let mut updated = record;
        updated.status = CapacityDisputeStatus::Resolved(CapacityDisputeResolution {
            resolved_epoch,
            outcome: self.outcome,
            notes: self.rationale,
        });
        append_validated_entry(state_transaction, terminal_entry)?;
        state_transaction
            .world
            .capacity_disputes
            .insert(self.dispute_id, updated);
        Ok(())
    }
}
fn checked_query_limit(limit: u32) -> Result<usize, QueryExecutionFail> {
    let limit = usize::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion(
            "reputation journal query limit does not fit into usize".to_owned(),
        )
    })?;
    if limit == 0 || limit > REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1 {
        return Err(QueryExecutionFail::Conversion(format!(
            "reputation journal query limit must be within 1..={REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1}"
        )));
    }
    Ok(limit)
}
fn finalized_cursor(
    state_ro: &impl StateReadOnly,
) -> Result<ReputationJournalFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion(
            "finalized reputation height does not fit into u64".to_owned(),
        )
    })?;
    let block_hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reputation journal queries require a finalized state anchor".to_owned(),
            )
        })?;
    let finalized_at_unix_ms = state_ro.query_ledger_time_ms();
    if height == 0
        || block_hash == [0; 32]
        || finalized_at_unix_ms == 0
        || finalized_at_unix_ms == u64::MAX
        || state_ro.latest_block_hash().map(|hash| *hash.as_ref()) != Some(block_hash)
    {
        return Err(QueryExecutionFail::Conversion(
            "finalized reputation Kura block does not match the immutable state anchor".to_owned(),
        ));
    }
    Ok(ReputationJournalFinalizedCursorV1 {
        height,
        block_hash,
        finalized_at_unix_ms,
    })
}
fn resolved_event_cursor(
    state_ro: &impl StateReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
) -> Result<ReputationJournalFinalizedEventCursorV1, QueryExecutionFail> {
    let index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reputation event target height cannot index finalized hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "reputation event {} targets non-finalized height {}",
                record.sequence, record.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "reputation event {} resolves a zero block hash",
            record.sequence
        )));
    }
    Ok(ReputationJournalFinalizedEventCursorV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
    })
}
fn into_finalized_event(
    state_ro: &impl StateReadOnly,
    record: ReputationJournalCommittedEventRecordV1,
) -> Result<ReputationJournalFinalizedEventV1, QueryExecutionFail> {
    let index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reputation event target height cannot index finalized hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "reputation event {} targets non-finalized height {}",
                record.sequence, record.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "reputation event {} resolves a zero block hash",
            record.sequence
        )));
    }
    Ok(ReputationJournalFinalizedEventV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        entry: record.entry,
    })
}
#[derive(Clone, Copy)]
struct ReputationQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    recorded_at_unix_ms: u64,
}
impl From<&ReputationJournalCommittedEventRecordV1> for ReputationQueryEventPosition {
    fn from(record: &ReputationJournalCommittedEventRecordV1) -> Self {
        Self {
            sequence: record.sequence,
            target_block_height: record.target_block_height,
            event_index: record.event_index,
            recorded_at_unix_ms: record.recorded_at_unix_ms,
        }
    }
}
fn validate_query_event_successor(
    previous: Option<ReputationQueryEventPosition>,
    current: &ReputationJournalCommittedEventRecordV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1 && current.event_index == 0)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reputation journal must begin at sequence one and block index zero".to_owned(),
                )
            });
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(QueryExecutionFail::Conversion(
            "reputation journal sequence is not globally contiguous".to_owned(),
        ));
    }
    if current.recorded_at_unix_ms < previous.recorded_at_unix_ms {
        return Err(QueryExecutionFail::Conversion(
            "reputation journal committing timestamps are reordered".to_owned(),
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous.event_index.checked_add(1) == Some(current.event_index) =>
        {
            Ok(())
        }
        _ => Err(QueryExecutionFail::Conversion(
            "reputation journal block height or event index is not contiguous".to_owned(),
        )),
    }
}
fn load_cursor_event(
    state_ro: &impl StateReadOnly,
    cursor: ReputationJournalFinalizedEventCursorV1,
) -> Result<ReputationQueryEventPosition, QueryExecutionFail> {
    cursor
        .validate()
        .map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
    let mut current = reputation_current_from_resident(0).map_err(query_failure)?;
    let record = read_event_for_current(state_ro.world(), cursor.sequence, &mut current)
        .map_err(query_failure)?
        .ok_or(QueryExecutionFail::Expired)?;
    if cursor.sequence == 1 {
        validate_event_successor(None, &record).map_err(query_failure)?;
    } else {
        let sequence = cursor.sequence - 1;
        let mut predecessor_current =
            reputation_current_from_resident(current.resident_bytes()).map_err(query_failure)?;
        let predecessor =
            read_event_for_current(state_ro.world(), sequence, &mut predecessor_current)
                .map_err(query_failure)?
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(format!(
                        "reputation journal is missing cursor predecessor sequence {sequence}"
                    ))
                })?;
        validate_event_indexes_for_current(state_ro.world(), &predecessor, &predecessor_current)
            .map_err(query_failure)?;
        validate_event_successor(Some(&predecessor), &record).map_err(query_failure)?;
    }
    validate_event_indexes_for_current(state_ro.world(), &record, &current)
        .map_err(query_failure)?;
    if resolved_event_cursor(state_ro, &record)? != cursor {
        return Err(QueryExecutionFail::Expired);
    }
    Ok(ReputationQueryEventPosition::from(&record))
}
fn validate_selected_event_neighbors(
    state_ro: &impl StateReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
    journal_head: ReputationJournalHeadStateV1,
    finalized_cursor: ReputationJournalFinalizedCursorV1,
    retained: &crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<(), QueryExecutionFail> {
    let world = state_ro.world();
    if record.sequence > journal_head.last_sequence {
        return Err(QueryExecutionFail::Conversion(
            "reputation source head points beyond the journal head".to_owned(),
        ));
    }
    if record.sequence == 1 {
        validate_event_successor(None, record).map_err(query_failure)?;
    } else {
        let predecessor_sequence = record.sequence - 1;
        let mut predecessor_current =
            reputation_current_from_resident(retained.resident_bytes()).map_err(query_failure)?;
        let predecessor = read_event_for_current(
            world,
            predecessor_sequence,
            &mut predecessor_current,
        )
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "reputation journal is missing selected-event predecessor sequence {predecessor_sequence}"
                ))
            })?;
        validate_event_indexes_for_current(world, &predecessor, &predecessor_current)
            .map_err(query_failure)?;
        validate_record_at_finalized_cursor(state_ro, &predecessor, finalized_cursor)?;
        validate_event_successor(Some(&predecessor), record).map_err(query_failure)?;
    }
    if record.sequence < journal_head.last_sequence {
        let successor_sequence = record.sequence.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reputation selected-event successor sequence overflow".to_owned(),
            )
        })?;
        let mut successor_current =
            reputation_current_from_resident(retained.resident_bytes()).map_err(query_failure)?;
        let successor = read_event_for_current(world, successor_sequence, &mut successor_current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "reputation journal is missing selected-event successor sequence {successor_sequence}"
                ))
        })?;
        validate_event_indexes_for_current(world, &successor, &successor_current)
            .map_err(query_failure)?;
        validate_event_successor(Some(record), &successor).map_err(query_failure)?;
        validate_record_at_finalized_cursor(state_ro, &successor, finalized_cursor)?;
    }
    Ok(())
}
fn validate_selected_source_predecessor(
    state_ro: &impl StateReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
    finalized_cursor: ReputationJournalFinalizedCursorV1,
    retained: &crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<(), QueryExecutionFail> {
    let Some(predecessor_event_id) = record.entry.predecessor_event_id else {
        return Ok(());
    };
    let mut predecessor_current =
        reputation_current_from_resident(retained.resident_bytes()).map_err(query_failure)?;
    let predecessor = read_source_predecessor_for_current(
        state_ro.world(),
        predecessor_event_id,
        &mut predecessor_current,
    )
    .map_err(query_failure)?;
    validate_event_intrinsic_indexes_for_current(
        state_ro.world(),
        &predecessor,
        &predecessor_current,
    )
    .map_err(query_failure)?;
    validate_provider_dispute_revision_edge(&predecessor, record).map_err(query_failure)?;
    validate_record_at_finalized_cursor(state_ro, &predecessor, finalized_cursor)?;
    // Both records resolve through this same immutable finalized-hash view.
    // Comparing their persisted positions therefore avoids materializing a
    // second entry-bearing finalized event beside the decoded predecessor.
    let strictly_precedes = predecessor.sequence < record.sequence
        && (predecessor.target_block_height < record.target_block_height
            || (predecessor.target_block_height == record.target_block_height
                && predecessor.event_index < record.event_index));
    if !strictly_precedes {
        return Err(QueryExecutionFail::Conversion(
            "reputation source predecessor does not strictly precede its selected revision"
                .to_owned(),
        ));
    }
    Ok(())
}
fn validate_record_at_finalized_cursor(
    state_ro: &impl StateReadOnly,
    record: &ReputationJournalCommittedEventRecordV1,
    finalized_cursor: ReputationJournalFinalizedCursorV1,
) -> Result<(), QueryExecutionFail> {
    let event_cursor = resolved_event_cursor(state_ro, record)?;
    let invalid = |error: ReputationJournalValidationError| {
        QueryExecutionFail::Conversion(format!(
            "finalized reputation event is invalid at the selected view: {error}"
        ))
    };
    finalized_cursor.validate().map_err(invalid)?;
    event_cursor.validate().map_err(invalid)?;
    record.validate().map_err(invalid)?;
    if event_cursor.block_height > finalized_cursor.height {
        return Err(invalid(
            ReputationJournalValidationError::EventBeyondFinality,
        ));
    }
    let at_finalized_height = event_cursor.block_height == finalized_cursor.height;
    if at_finalized_height && event_cursor.block_hash != finalized_cursor.block_hash {
        return Err(invalid(
            ReputationJournalValidationError::FinalizedBlockHashMismatch,
        ));
    }
    if record.recorded_at_unix_ms > finalized_cursor.finalized_at_unix_ms {
        return Err(invalid(
            ReputationJournalValidationError::EventAfterFinalizedTimestamp,
        ));
    }
    Ok(())
}
fn validate_finalized_journal_terminal(
    state_ro: &impl StateReadOnly,
    journal_head: ReputationJournalHeadStateV1,
    finalized_cursor: ReputationJournalFinalizedCursorV1,
) -> Result<(), QueryExecutionFail> {
    let mut current = reputation_current_from_resident(0).map_err(query_failure)?;
    let terminal =
        read_event_for_current(state_ro.world(), journal_head.last_sequence, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reputation journal head points to a missing terminal event".to_owned(),
                )
            })?;
    if terminal.target_block_height != journal_head.last_target_block_height
        || terminal.event_index != journal_head.last_event_index
    {
        return Err(QueryExecutionFail::Conversion(
            "reputation journal head differs from its terminal event".to_owned(),
        ));
    }
    validate_event_indexes_for_current(state_ro.world(), &terminal, &current)
        .map_err(query_failure)?;
    validate_record_at_finalized_cursor(state_ro, &terminal, finalized_cursor)?;
    Ok(())
}
fn query_event_by_source_id(
    query: &FindSorafsReputationJournalEventBySourceId,
    state_ro: &impl StateReadOnly,
) -> Result<ReputationJournalFinalizedEventV1, QueryExecutionFail> {
    let source_id = query.source_id();
    if source_id == ReputationJournalSourceIdV1::ZERO {
        return Err(QueryExecutionFail::Conversion(
            "reputation source identifier must be non-zero".to_owned(),
        ));
    }
    let actual_finalized_cursor = finalized_cursor(state_ro)?;
    if query
        .expected_finalized_cursor()
        .is_some_and(|expected| expected != actual_finalized_cursor)
    {
        return Err(QueryExecutionFail::Expired);
    }
    let journal_head = validate_journal_head_for_query(state_ro.world()).map_err(query_failure)?;
    if let Some(journal_head) = journal_head {
        validate_finalized_journal_terminal(state_ro, journal_head, actual_finalized_cursor)?;
    }
    let mut current = reputation_current_from_resident(0).map_err(query_failure)?;
    let source_head = read_source_head_for_current(state_ro.world(), source_id, &mut current)
        .map_err(query_failure)?;
    let Some(source_head) = source_head else {
        return Err(QueryExecutionFail::Find(
            FindError::SorafsReputationJournalEvent(source_id),
        ));
    };
    let journal_head = journal_head.ok_or_else(|| {
        QueryExecutionFail::Conversion(
            "reputation source head exists without a journal head".to_owned(),
        )
    })?;
    let record = read_event_for_current(state_ro.world(), source_head.sequence, &mut current)
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reputation source head points to a missing event".to_owned(),
            )
        })?;
    if record.entry.source_id != source_id
        || record.entry.source_kind() != source_head.source_kind
        || record.entry.source_revision != source_head.source_revision
        || record.entry.event_id != source_head.event_id
        || record.sequence != source_head.sequence
    {
        return Err(QueryExecutionFail::Conversion(
            "reputation source head differs from its indexed event".to_owned(),
        ));
    }
    validate_event_indexes_for_current(state_ro.world(), &record, &current)
        .map_err(query_failure)?;
    validate_selected_event_neighbors(
        state_ro,
        &record,
        journal_head,
        actual_finalized_cursor,
        &current,
    )?;
    validate_selected_source_predecessor(state_ro, &record, actual_finalized_cursor, &current)?;
    validate_record_at_finalized_cursor(state_ro, &record, actual_finalized_cursor)?;
    into_finalized_event(state_ro, record)
}
fn query_event_page(
    query: &FindSorafsReputationJournalEvents,
    state_ro: &impl StateReadOnly,
) -> Result<ReputationJournalFinalizedEventPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let finalized_cursor = finalized_cursor(state_ro)?;
    if query
        .expected_finalized_cursor
        .is_some_and(|expected| expected != finalized_cursor)
    {
        return Err(QueryExecutionFail::Expired);
    }
    let head = validate_journal_head_for_query(state_ro.world()).map_err(query_failure)?;
    let Some(head) = head else {
        if query.after.is_some() {
            return Err(QueryExecutionFail::Expired);
        }
        let page = ReputationJournalFinalizedEventPageV1 {
            finalized_cursor,
            events: Vec::new(),
            has_more: false,
            next_after: None,
        };
        page.validate_after(query.after)
            .map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
        return Ok(page);
    };
    let mut head_current = reputation_current_from_resident(0).map_err(query_failure)?;
    let head_record =
        read_event_for_current(state_ro.world(), head.last_sequence, &mut head_current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reputation journal head points to a missing event".to_owned(),
                )
            })?;
    if head_record.target_block_height != head.last_target_block_height
        || head_record.event_index != head.last_event_index
    {
        return Err(QueryExecutionFail::Conversion(
            "reputation journal head differs from its terminal event".to_owned(),
        ));
    }
    validate_event_indexes_for_current(state_ro.world(), &head_record, &head_current)
        .map_err(query_failure)?;
    validate_record_at_finalized_cursor(state_ro, &head_record, finalized_cursor)?;
    drop(head_record);
    let mut previous = query
        .after
        .map(|cursor| load_cursor_event(state_ro, cursor))
        .transpose()?;
    let start_sequence = query.after.map_or(Ok(1), |cursor| {
        cursor.sequence.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion("reputation query cursor overflow".to_owned())
        })
    })?;
    if start_sequence > head.last_sequence.saturating_add(1) {
        return Err(QueryExecutionFail::Expired);
    }
    let mut events = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let page_bytes_limit = crate::smartcontracts::isi::query::singular_query_frame_limit(
        REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let payload_budget = page_bytes_limit.saturating_sub(4 * 1_024);
    let mut encoded_event_bytes = 0usize;
    let mut sequence = start_sequence;
    while sequence <= head.last_sequence && events.len() < limit {
        let mut current = reputation_current_from_resident(0).map_err(query_failure)?;
        let record = read_event_for_current(state_ro.world(), sequence, &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "reputation journal is missing sequence {sequence}"
                ))
            })?;
        validate_query_event_successor(previous, &record)?;
        validate_event_indexes_for_current(state_ro.world(), &record, &current)
            .map_err(query_failure)?;
        let position = ReputationQueryEventPosition::from(&record);
        let resolved = into_finalized_event(state_ro, record)?;
        let resolved_bytes = norito::canonical_frame_len(&resolved).map_err(|error| {
            QueryExecutionFail::Conversion(format!(
                "failed to size finalized reputation event: {error}"
            ))
        })?;
        let next_event_bytes =
            encoded_event_bytes
                .checked_add(resolved_bytes)
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "reputation event-page byte counter overflow".to_owned(),
                    )
                })?;
        if next_event_bytes > payload_budget {
            if events.is_empty() {
                return Err(QueryExecutionFail::Conversion(format!(
                    "one reputation event cannot fit within the {page_bytes_limit}-byte page budget"
                )));
            }
            break;
        }
        encoded_event_bytes = next_event_bytes;
        events.try_push(resolved)?;
        previous = Some(position);
        sequence = sequence.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion("reputation journal sequence overflow".to_owned())
        })?;
    }
    let has_more = sequence <= head.last_sequence;
    let next_after = has_more.then(|| {
        events
            .last()
            .expect("a continuing reputation page must contain an event")
            .cursor()
    });
    let page = ReputationJournalFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    page.validate_after(query.after)
        .map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
    let encoded_len = norito::canonical_frame_len(&page).map_err(|error| {
        QueryExecutionFail::Conversion(format!("failed to size reputation event page: {error}"))
    })?;
    if encoded_len > page_bytes_limit {
        return Err(QueryExecutionFail::Conversion(format!(
            "reputation event page has {encoded_len} bytes; maximum is {page_bytes_limit}"
        )));
    }
    Ok(page)
}
impl ValidSingularQuery for FindSorafsReputationJournalAuthorityPolicy {
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<ReputationJournalAuthorityPolicyRecordV1, QueryExecutionFail> {
        let mut current = reputation_current_from_resident(0).map_err(query_failure)?;
        read_active_policy_for_current(state_ro.world(), &mut current)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsReputationJournalAuthorityPolicy)
            })
    }
}
impl ValidSingularQuery for FindSorafsReputationJournalEventBySourceId {
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<ReputationJournalFinalizedEventV1, QueryExecutionFail> {
        query_event_by_source_id(self, state_ro)
    }
}
impl ValidSingularQuery for FindSorafsReputationJournalEvents {
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<ReputationJournalFinalizedEventPageV1, QueryExecutionFail> {
        query_event_page(self, state_ro)
    }
}
#[cfg(test)]
pub(crate) mod tests {
    include!("sorafs_reputation/schema_identity_tests.rs");
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
    use iroha_data_model::{
        IntoKeyValue, Registrable,
        account::Account,
        block::{BlockHeader, builder::BlockBuilder},
        events::data::DataEvent,
        isi::{Grant, InstructionBox},
        permission::Permissions,
        sorafs::{
            capacity::CapacityDeclarationRecord,
            reputation::{
                PorTerminalOutcomeV1, PorTerminalStatusV1,
                REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1, ReputationJournalAuthorityPolicyV1,
                StreamTokenValidationOutcomeV1, StreamTokenValidationStatusV1,
            },
        },
        transaction::{
            SignedTransaction, TransactionEntrypoint, error::TransactionRejectionReason,
        },
    };
    use iroha_executor_data_model::permission::sorafs::{
        CanManageSorafsReputationJournalPolicy, CanRecordSorafsReputationJournal,
        CanResolveSorafsCapacityDispute,
    };
    use iroha_model_base::metadata::Metadata;
    const TEST_NOW_MS: u64 = 1_700_000_000_000;
    fn keypair(seed: u8) -> KeyPair {
        let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
            .expect("valid deterministic test key");
        KeyPair::from_private_key(private).expect("derive deterministic test keypair")
    }
    fn account(keypair: &KeyPair) -> AccountId {
        AccountId::new(keypair.public_key().clone())
    }
    fn policy(authority: &AccountId) -> ReputationJournalAuthorityPolicyV1 {
        ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: authority.clone(),
            dispute_recorder_authority: authority.clone(),
            token_recorder_authority: authority.clone(),
            stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 24 * 60 * 60 * 1_000,
        }
    }
    fn token_entry(
        authority: &AccountId,
        provider_id: ProviderId,
        policy_digest: [u8; 32],
        unique: u8,
    ) -> ReputationJournalEntryV1 {
        token_entry_at(authority, provider_id, policy_digest, unique, TEST_NOW_MS)
    }
    fn token_entry_at(
        authority: &AccountId,
        provider_id: ProviderId,
        policy_digest: [u8; 32],
        unique: u8,
        source_time_unix_ms: u64,
    ) -> ReputationJournalEntryV1 {
        ReputationJournalEntryV1::try_new(
            provider_id,
            policy_digest,
            authority.clone(),
            source_time_unix_ms,
            None,
            ReputationJournalPayloadV1::StreamTokenValidation(StreamTokenValidationOutcomeV1 {
                binding: iroha_data_model::sorafs::reputation::StreamTokenValidationBindingV1 {
                    gateway_id: [unique; 32],
                    gateway_sequence: 1,
                    request_context_digest: [unique.wrapping_add(1); 32],
                },
                token_body_digest: Some([unique.wrapping_add(2); 32]),
                token_key_version: Some(1),
                validated_at_unix_ms: source_time_unix_ms,
                status: StreamTokenValidationStatusV1::Accepted,
            }),
        )
        .expect("canonical token reputation entry")
    }
    fn por_entry_at(
        authority: &AccountId,
        provider_id: ProviderId,
        policy_digest: [u8; 32],
        unique: u8,
        source_time_unix_ms: u64,
    ) -> ReputationJournalEntryV1 {
        ReputationJournalEntryV1::try_new(
            provider_id,
            policy_digest,
            authority.clone(),
            source_time_unix_ms,
            None,
            ReputationJournalPayloadV1::PorTerminal(PorTerminalOutcomeV1 {
                challenge_id: [unique; 32],
                manifest_digest: [0x41; 32],
                epoch_id: 7,
                drand_round: 11,
                forced: false,
                sample_count: 4,
                failed_samples: 0,
                issued_at_unix_ms: source_time_unix_ms - 2_000,
                deadline_at_unix_ms: source_time_unix_ms - 500,
                responded_at_unix_ms: Some(source_time_unix_ms - 750),
                decided_at_unix_ms: source_time_unix_ms,
                proof_digest: Some([0x42; 32]),
                repair_task_id: None,
                verifier_latency_ms: Some(17),
                status: PorTerminalStatusV1::Verified,
            }),
        )
        .expect("canonical PoR reputation entry")
    }
    fn reputation_world() -> (World, AccountId, AccountId, ProviderId) {
        let authority = account(&keypair(1));
        let other = account(&keypair(2));
        let provider_id = ProviderId::new([0x31; 32]);
        let mut world = World::new();
        for account_id in [&authority, &other] {
            let (id, value) = Account::new(account_id.clone())
                .build(&authority)
                .into_key_value();
            world.accounts.insert(id, value);
        }
        let mut authority_permissions = Permissions::new();
        authority_permissions.insert(Permission::from(CanManageSorafsReputationJournalPolicy));
        authority_permissions.insert(Permission::from(CanRecordSorafsReputationJournal));
        authority_permissions.insert(Permission::from(CanResolveSorafsCapacityDispute));
        world
            .account_permissions
            .insert(authority.clone(), authority_permissions);
        let mut other_permissions = Permissions::new();
        other_permissions.insert(Permission::from(CanRecordSorafsReputationJournal));
        world
            .account_permissions
            .insert(other.clone(), other_permissions);
        world.provider_owners.insert(provider_id, authority.clone());
        world.capacity_declarations.insert(
            provider_id,
            CapacityDeclarationRecord::new(
                provider_id,
                vec![0x01],
                1,
                1,
                1,
                2,
                Metadata::default(),
            ),
        );
        (world, authority, other, provider_id)
    }

    /// Synthetic World preimages for isolated index/time/dispute tests only. This helper never
    /// executes SetPolicy, creates executor custody, or supplies a native authenticated proof.
    pub(crate) fn seed_policy_preimage(
        tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        policy: ReputationJournalAuthorityPolicyV1,
    ) -> Result<(), InstructionExecutionError> {
        let now = block_time_ms(tx)?;
        let record = ReputationJournalAuthorityPolicyRecordV1::try_new(
            policy,
            authority.clone(),
            now,
            iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
                iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
                    height: tx._curr_block.height().get().max(2),
                    transaction_hash: *iroha_crypto::Hash::new(b"synthetic private journal policy preimage").as_ref(),
                    entry_index: 0,
                    instruction_index: 0,
                    recorded_at_unix_ms: now,
                    authority: authority.clone(),
                },
            ),
        ).map_err(|error| invalid_parameter(error.to_string()))?;
        let bytes = encode_state(&record, "synthetic private journal policy preimage")?;
        tx.world
            .smart_contract_state
            .insert(active_policy_key().clone(), bytes.clone());
        tx.world
            .smart_contract_state
            .insert(policy_history_key(&record.policy_digest), bytes);
        Ok(())
    }
    fn state_with_reputation_accounts() -> (State, AccountId, AccountId, ProviderId) {
        let (world, authority, other, provider_id) = reputation_world();
        (
            State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            ),
            authority,
            other,
            provider_id,
        )
    }
    fn certified_reputation_chain() -> (CertifiedTestChain, AccountId, AccountId, ProviderId) {
        let (mut world, authority, other, provider_id) = reputation_world();
        // Test accounts/provider exist before genesis; capabilities come from its signed ISIs.
        world
            .account_permissions
            .insert(authority.clone(), Permissions::new());
        world
            .account_permissions
            .insert(other.clone(), Permissions::new());
        let mut config = TestChainConfig::new(world, TEST_NOW_MS - 1_000_000);
        config.genesis_instructions = vec![
            Grant::account_permission(
                Permission::from(CanManageSorafsReputationJournalPolicy),
                authority.clone(),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanRecordSorafsReputationJournal),
                authority.clone(),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanResolveSorafsCapacityDispute),
                authority.clone(),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanRecordSorafsReputationJournal),
                other.clone(),
            )
            .into(),
        ];
        let chain = CertifiedTestChain::start(config)
            .map_err(|failure| failure.error)
            .expect("genuine signed four-validator genesis and capability grants");
        (chain, authority, other, provider_id)
    }
    /// Execute every instruction in its own signed envelope, preserving the sole-SetPolicy fence.
    fn commit_reputation_instructions(
        chain: &mut CertifiedTestChain,
        now: u64,
        instructions: Vec<(u8, InstructionBox)>,
    ) -> Vec<Result<(), TransactionRejectionReason>> {
        let signed: Vec<SignedTransaction> = instructions
            .into_iter()
            .enumerate()
            .map(|(index, (seed, instruction))| {
                chain.sign(
                    &keypair(seed),
                    [instruction],
                    now - 1 - u64::try_from(index).unwrap(),
                )
            })
            .collect();
        let hashes: Vec<_> = signed
            .iter()
            .cloned()
            .map(|tx| TransactionEntrypoint::External(tx).hash())
            .collect();
        let expected = chain.commit_at(now, signed);
        let committed = chain.committed(chain.height());
        assert_eq!(
            committed.block_time_ms(),
            now,
            "fixture never rebases source/cutover time"
        );
        let block = committed.block();
        let results: Vec<_> = hashes
            .iter()
            .map(|hash| {
                let (index, _) = block
                    .network_entrypoints()
                    .enumerate()
                    .find(|(_, entry)| entry.hash() == *hash)
                    .expect("exact signed fixture transaction");
                block
                    .network_output_at(u32::try_from(index).unwrap())
                    .expect("committed exact output")
                    .1
                    .result
                    .0
                    .clone()
                    .map(|_| ())
            })
            .collect();
        assert_eq!(
            results.iter().map(Result::is_ok).collect::<Vec<_>>(),
            expected
        );
        results
    }
    fn commit_reputation_instruction(
        chain: &mut CertifiedTestChain,
        now: u64,
        seed: u8,
        instruction: impl Into<InstructionBox>,
    ) -> Result<(), TransactionRejectionReason> {
        commit_reputation_instructions(chain, now, vec![(seed, instruction.into())]).remove(0)
    }
    fn assert_instruction_message(error: &TransactionRejectionReason, expected: &str) {
        assert!(
            matches!(error,
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::InstructionFailed(
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message))))
            if message.contains(expected)),
            "{error:?}"
        );
    }
    fn inspect_journal_overlay(
        chain: &CertifiedTestChain,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>),
    ) {
        let view = chain.state().view();
        let header = BlockHeader::new(
            (chain.height() + 1).try_into().unwrap(),
            view.latest_block_hash(),
            None,
            chain.committed(chain.height()).block_time_ms() + 1_000,
            0,
        );
        drop(view);
        let mut block = chain.state().block(header);
        let mut transaction = block.transaction();
        operation(&mut transaction);
        // Deliberately discard corruption. No fixture overlay is published into the signed chain.
    }
    // Isolated journal/index preimages and cursor bookkeeping only: this helper supplies no
    // quorum certificate, executor-origin custody, or authenticated native proof.
    fn transact_test(
        state: &mut State,
        height: u64,
        timestamp_ms: u64,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
    ) -> Result<(), InstructionExecutionError> {
        let header = BlockHeader::new(
            height.try_into().expect("nonzero height"),
            state.view().latest_block_hash(),
            None,
            timestamp_ms,
            0,
        );
        let mut block = state.block(header.clone());
        let mut transaction = block.transaction();
        operation(&mut transaction)?;
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit reputation test block");
        let block_signer = keypair(0xFE);
        // The overlay above applies the fixture operation directly. Its empty persisted
        // block still needs an explicit execution result before Kura can index it.
        let signed_block = BlockBuilder::new(header)
            .try_build_with_signature(0, block_signer.private_key())
            .expect("build executed reputation Kura fixture block");
        let block_hash = signed_block.hash();
        let committed_header = signed_block.header().clone();
        state
            .kura()
            .store_block(crate::block::reserve_block_for_tests().initialize(signed_block))
            .expect("store reputation Kura fixture block");
        state.push_block_hash_for_testing(block_hash);
        state.update_latest_block_header_cache_for_tests(committed_header);
        let view = state.view();
        assert_eq!(view.latest_block_hash(), Some(block_hash));
        assert_eq!(
            view.authenticated_query_ledger_time_ms(),
            Some(timestamp_ms)
        );
        Ok(())
    }
    // Corrupt only the query overlay: retain its independently captured finalized time,
    // so exact-cursor admission cannot mask the event/index mutation being exercised.
    fn finalized_query_fixture_block(
        state: &State,
        cursor: ReputationJournalFinalizedCursorV1,
    ) -> crate::state::StateBlock<'_> {
        let header = BlockHeader::new(
            (cursor.height + 1)
                .try_into()
                .expect("nonzero next fixture height"),
            state.view().latest_block_hash(),
            None,
            cursor.finalized_at_unix_ms,
            0,
        );
        let block = state.block(header);
        assert_eq!(
            finalized_cursor(&block).expect("exact fixture cursor before mutation"),
            cursor
        );
        block
    }
    fn state_with_finalized_por_events(
        unique_values: &[u8],
    ) -> (
        State,
        Vec<ReputationJournalEntryV1>,
        ReputationJournalFinalizedCursorV1,
    ) {
        assert!(
            !unique_values.is_empty(),
            "finalized PoR fixture needs at least one event"
        );
        let (mut state, authority, _other, provider_id) = state_with_reputation_accounts();
        let recorder_policy = policy(&authority);
        let policy_digest = recorder_policy
            .canonical_digest()
            .expect("recorder policy digest");
        transact_test(&mut state, 1, TEST_NOW_MS, |transaction| {
            seed_policy_preimage(transaction, &authority, recorder_policy)
        })
        .expect("activate reputation recorder policy");
        let mut entries = Vec::with_capacity(unique_values.len());
        for (index, unique) in unique_values.iter().copied().enumerate() {
            let offset = u64::try_from(index)
                .expect("fixture event index fits u64")
                .checked_add(1)
                .expect("fixture timestamp offset");
            let timestamp_ms = TEST_NOW_MS
                .checked_add(offset.saturating_mul(1_000))
                .expect("fixture timestamp");
            let entry = por_entry_at(&authority, provider_id, policy_digest, unique, timestamp_ms);
            transact_test(&mut state, offset + 1, timestamp_ms, |transaction| {
                AppendSorafsPorReputationJournalEntry::new(entry.clone())
                    .execute(&authority, transaction)
            })
            .expect("commit finalized PoR reputation event");
            entries.push(entry);
        }
        let finalized_cursor =
            finalized_cursor(&state.view()).expect("resolve finalized reputation cursor");
        (state, entries, finalized_cursor)
    }
    fn state_with_finalized_por_event() -> (
        State,
        ReputationJournalEntryV1,
        ReputationJournalFinalizedCursorV1,
    ) {
        let (state, mut entries, finalized_cursor) = state_with_finalized_por_events(&[0x91]);
        let entry = entries.pop().expect("one finalized PoR fixture event");
        (state, entry, finalized_cursor)
    }
    fn state_with_finalized_resolved_dispute() -> (
        State,
        ReputationJournalEntryV1,
        ReputationJournalEntryV1,
        ReputationJournalFinalizedCursorV1,
    ) {
        let (mut state, authority, _other, provider_id) = state_with_reputation_accounts();
        let recorder_policy = policy(&authority);
        let policy_digest = recorder_policy
            .canonical_digest()
            .expect("recorder policy digest");
        let dispute_id = iroha_data_model::sorafs::capacity::CapacityDisputeId::new([0xB1; 32]);
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider_id,
            [0xB2; 32],
            None,
            2,
            TEST_NOW_MS / 1_000,
            "bounded source-query dispute".to_owned(),
            Some("restore source lifecycle".to_owned()),
            iroha_data_model::sorafs::capacity::CapacityDisputeEvidence {
                digest: [0xB3; 32],
                media_type: Some("application/norito".to_owned()),
                uri: None,
                size_bytes: Some(128),
            },
            vec![0xB4],
        );
        transact_test(&mut state, 1, TEST_NOW_MS, |transaction| {
            seed_policy_preimage(transaction, &authority, recorder_policy)?;
            append_capacity_dispute_opened(transaction, &authority, &record)?;
            transaction
                .world
                .capacity_disputes
                .insert(dispute_id, record);
            Ok(())
        })
        .expect("commit opened dispute");
        transact_test(&mut state, 2, TEST_NOW_MS + 1_000, |transaction| {
            ResolveSorafsCapacityDispute::new(
                dispute_id,
                policy_digest,
                iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Upheld,
                [0xB5; 32],
                Some("bounded lifecycle confirmed".to_owned()),
            )
            .execute(&authority, transaction)
        })
        .expect("commit resolved dispute");
        let view = state.view();
        let opened = read_event(view.world(), 1)
            .expect("read opened dispute event")
            .expect("opened dispute event")
            .entry;
        let resolved = read_event(view.world(), 2)
            .expect("read resolved dispute event")
            .expect("resolved dispute event")
            .entry;
        let finalized_cursor =
            finalized_cursor(&view).expect("resolve finalized reputation cursor");
        drop(view);
        (state, opened, resolved, finalized_cursor)
    }
    fn state_with_finalized_interleaved_resolved_dispute() -> (
        State,
        ReputationJournalEntryV1,
        ReputationJournalFinalizedCursorV1,
    ) {
        let (mut state, authority, _other, provider_id) = state_with_reputation_accounts();
        let recorder_policy = policy(&authority);
        let policy_digest = recorder_policy
            .canonical_digest()
            .expect("recorder policy digest");
        let dispute_id = iroha_data_model::sorafs::capacity::CapacityDisputeId::new([0xC1; 32]);
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider_id,
            [0xC2; 32],
            None,
            3,
            TEST_NOW_MS / 1_000,
            "interleaved source-query dispute".to_owned(),
            Some("prove source predecessor finality".to_owned()),
            iroha_data_model::sorafs::capacity::CapacityDisputeEvidence {
                digest: [0xC3; 32],
                media_type: Some("application/norito".to_owned()),
                uri: None,
                size_bytes: Some(128),
            },
            vec![0xC4],
        );
        transact_test(&mut state, 1, TEST_NOW_MS, |transaction| {
            seed_policy_preimage(transaction, &authority, recorder_policy)?;
            append_capacity_dispute_opened(transaction, &authority, &record)?;
            transaction
                .world
                .capacity_disputes
                .insert(dispute_id, record);
            Ok(())
        })
        .expect("commit opened interleaved dispute");
        let unrelated = por_entry_at(
            &authority,
            provider_id,
            policy_digest,
            0xC5,
            TEST_NOW_MS + 1_000,
        );
        transact_test(&mut state, 2, TEST_NOW_MS + 1_000, |transaction| {
            AppendSorafsPorReputationJournalEntry::new(unrelated).execute(&authority, transaction)
        })
        .expect("commit unrelated interleaved reputation event");
        transact_test(&mut state, 3, TEST_NOW_MS + 2_000, |transaction| {
            ResolveSorafsCapacityDispute::new(
                dispute_id,
                policy_digest,
                iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Upheld,
                [0xC6; 32],
                Some("interleaved lifecycle confirmed".to_owned()),
            )
            .execute(&authority, transaction)
        })
        .expect("commit resolved interleaved dispute");
        let view = state.view();
        let resolved = read_event(view.world(), 3)
            .expect("read interleaved resolved dispute event")
            .expect("interleaved resolved dispute event")
            .entry;
        let finalized_cursor =
            finalized_cursor(&view).expect("resolve interleaved finalized reputation cursor");
        drop(view);
        (state, resolved, finalized_cursor)
    }
    fn replace_resolved_dispute_entry(
        transaction: &mut StateTransaction<'_, '_>,
        entry: ReputationJournalEntryV1,
    ) -> ReputationJournalCommittedEventRecordV1 {
        let mut terminal = read_event(transaction.world(), 2)
            .expect("read resolved dispute record")
            .expect("resolved dispute record");
        transaction
            .world
            .smart_contract_state
            .remove(event_id_key(terminal.entry.event_id));
        terminal.entry = entry;
        transaction.world.smart_contract_state.insert(
            event_id_key(terminal.entry.event_id),
            encode_state(&terminal.sequence, "forged dispute event-id index")
                .expect("encode forged dispute event-id index"),
        );
        transaction.world.smart_contract_state.insert(
            source_head_key(terminal.entry.source_id),
            encode_state(
                &ReputationJournalSourceHeadV1 {
                    source_kind: terminal.entry.source_kind(),
                    source_revision: terminal.entry.source_revision,
                    event_id: terminal.entry.event_id,
                    sequence: terminal.sequence,
                },
                "forged resolved dispute source head",
            )
            .expect("encode forged dispute source head"),
        );
        transaction.world.smart_contract_state.insert(
            event_key(terminal.sequence),
            encode_state(&terminal, "forged resolved dispute event")
                .expect("encode forged resolved dispute event"),
        );
        terminal
    }
    #[test]
    fn synthetic_policy_preimage_never_authorizes_setter_execution() {
        let (state, authority, _other, _provider) = state_with_reputation_accounts();
        let header = BlockHeader::new(1_u64.try_into().unwrap(), None, None, TEST_NOW_MS, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let policy = policy(&authority);
        seed_policy_preimage(&mut transaction, &authority, policy.clone()).unwrap();
        let before: Vec<_> = transaction
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let events = transaction.world.internal_event_buf.len();
        let error = SetSorafsReputationJournalAuthorityPolicy::new(policy)
            .execute(&authority, &mut transaction)
            .expect_err("a synthetic retained row cannot create direct signed source custody");
        assert!(
            matches!(&error, InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message))
            if message == "recorder policy requires exact direct signed source custody")
        );
        let after: Vec<_> = transaction
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(after, before);
        assert_eq!(transaction.world.internal_event_buf.len(), events);
    }
    #[test]
    fn event_keys_preserve_global_sequence_order() {
        assert!(event_key(1) < event_key(2));
        assert!(event_key(u64::MAX - 1) < event_key(u64::MAX));
    }
    #[test]
    fn capacity_dispute_kind_mapping_is_closed() {
        assert_eq!(
            provider_dispute_kind(1).expect("known kind"),
            ProviderDisputeKindV1::ReplicationShortfall
        );
        assert_eq!(
            provider_dispute_kind(255).expect("known kind"),
            ProviderDisputeKindV1::Other
        );
        assert!(provider_dispute_kind(0).is_err());
        assert!(provider_dispute_kind(5).is_err());
    }
    #[test]
    fn authority_policy_query_returns_precise_absence_error() {
        let (state, _authority, _other, _provider_id) = state_with_reputation_accounts();
        let view = state.view();
        assert_eq!(
            FindSorafsReputationJournalAuthorityPolicy.execute(&view),
            Err(QueryExecutionFail::Find(
                FindError::SorafsReputationJournalAuthorityPolicy
            ))
        );
    }
    #[test]
    fn source_query_resolves_the_finalized_indexed_event() {
        let (state, entry, finalized_cursor) = state_with_finalized_por_event();
        let event = FindSorafsReputationJournalEventBySourceId::new(
            entry.source_id,
            Some(finalized_cursor),
        )
        .execute(&state.view())
        .expect("resolve finalized reputation event by source");
        assert_eq!(event.sequence, 1);
        assert_eq!(event.block_height, 2);
        assert_eq!(event.entry, entry);
        assert_eq!(event.block_hash, finalized_cursor.block_hash);
    }
    #[test]
    fn finalized_cursor_uses_the_latest_kura_header_timestamp() {
        let (mut state, _entry, event_cursor) = state_with_finalized_por_event();
        let later_finalized_at_unix_ms = TEST_NOW_MS + 9_000;
        transact_test(
            &mut state,
            event_cursor.height + 1,
            later_finalized_at_unix_ms,
            |_transaction| Ok(()),
        )
        .expect("commit later empty Kura block");
        let view = state.view();
        let latest_block = view
            .latest_block()
            .expect("completed original State read")
            .expect("latest Kura block");
        let cursor = finalized_cursor(&view).expect("resolve finalized cursor");
        assert_eq!(
            cursor.finalized_at_unix_ms,
            latest_block.header().creation_time_ms
        );
        assert_eq!(cursor.finalized_at_unix_ms, later_finalized_at_unix_ms);
        assert_ne!(
            cursor.finalized_at_unix_ms,
            event_cursor.finalized_at_unix_ms
        );
    }
    #[test]
    fn source_query_returns_precise_absence_error() {
        let (state, _entry, finalized_cursor) = state_with_finalized_por_event();
        let absent_source = ReputationJournalSourceIdV1([0xE1; 32]);
        let query =
            FindSorafsReputationJournalEventBySourceId::new(absent_source, Some(finalized_cursor));
        assert_eq!(
            query.execute(&state.view()),
            Err(QueryExecutionFail::Find(
                FindError::SorafsReputationJournalEvent(absent_source)
            ))
        );
    }
    #[test]
    fn source_query_rejects_a_stale_finalized_cursor() {
        let (state, entry, mut stale_cursor) = state_with_finalized_por_event();
        stale_cursor.block_hash[0] ^= 0xFF;
        let query =
            FindSorafsReputationJournalEventBySourceId::new(entry.source_id, Some(stale_cursor));
        assert_eq!(
            query.execute(&state.view()),
            Err(QueryExecutionFail::Expired)
        );
    }
    #[test]
    fn source_query_rejects_a_corrupt_source_index() {
        let (state, entry, finalized_cursor) = state_with_finalized_por_event();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let forged_source_head = ReputationJournalSourceHeadV1 {
            source_kind: entry.source_kind(),
            source_revision: entry.source_revision,
            event_id: ReputationJournalEventIdV1([0xF1; 32]),
            sequence: 1,
        };
        transaction.world.smart_contract_state.insert(
            source_head_key(entry.source_id),
            encode_state(&forged_source_head, "forged reputation source head")
                .expect("encode forged source head"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            entry.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("corrupt source index must fail closed");
        assert!(
            matches!(
                error,
                QueryExecutionFail::Conversion(ref message)
                    if message.contains("source head")
            ),
            "unexpected corrupt-index error: {error}"
        );
    }
    #[test]
    fn source_query_returns_clean_absence_from_an_empty_finalized_journal() {
        let (mut state, _authority, _other, _provider_id) = state_with_reputation_accounts();
        transact_test(&mut state, 1, TEST_NOW_MS, |_transaction| Ok(()))
            .expect("commit empty finalized block");
        let absent_source = ReputationJournalSourceIdV1([0xE2; 32]);
        let query = FindSorafsReputationJournalEventBySourceId::new(absent_source, None);
        assert_eq!(
            query.execute(&state.view()),
            Err(QueryExecutionFail::Find(
                FindError::SorafsReputationJournalEvent(absent_source)
            ))
        );
    }
    #[test]
    fn source_query_rejects_zero_source_identity() {
        let (mut state, _authority, _other, _provider_id) = state_with_reputation_accounts();
        transact_test(&mut state, 1, TEST_NOW_MS, |_transaction| Ok(()))
            .expect("commit empty finalized block");
        let error = FindSorafsReputationJournalEventBySourceId::new(
            ReputationJournalSourceIdV1::ZERO,
            None,
        )
        .execute(&state.view())
        .expect_err("zero source identity must fail");
        assert!(matches!(error, QueryExecutionFail::Conversion(_)));
    }
    #[test]
    fn source_query_validates_the_global_head_before_reporting_absence() {
        let (state, entry, finalized_cursor) = state_with_finalized_por_event();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        transaction
            .world
            .smart_contract_state
            .remove(source_head_key(entry.source_id));
        let absent_source = ReputationJournalSourceIdV1([0xE3; 32]);
        let error =
            FindSorafsReputationJournalEventBySourceId::new(absent_source, Some(finalized_cursor))
                .execute(&transaction)
                .expect_err("corrupt journal must not report clean source absence");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("missing its source head")
        ));
    }
    #[test]
    fn source_query_rejects_a_missing_event_id_index() {
        let (state, entry, finalized_cursor) = state_with_finalized_por_event();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        transaction
            .world
            .smart_contract_state
            .remove(event_id_key(entry.event_id));
        let error = FindSorafsReputationJournalEventBySourceId::new(
            entry.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("missing event-id index must fail closed");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("missing its event-id index")
        ));
    }
    #[test]
    fn source_query_rejects_an_event_recorded_after_finality() {
        let (state, entry, finalized_cursor) = state_with_finalized_por_event();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut record = read_event(transaction.world(), 1)
            .expect("read selected event")
            .expect("selected event");
        record.recorded_at_unix_ms = finalized_cursor.finalized_at_unix_ms + 1;
        transaction.world.smart_contract_state.insert(
            event_key(1),
            encode_state(&record, "future reputation event").expect("encode future event"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            entry.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("event timestamp after finality must fail");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("timestamp lies after finalized time")
        ));
    }
    #[test]
    fn source_query_resolves_a_historical_event_with_bounded_neighbors() {
        let (state, entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93]);
        let selected = &entries[1];
        let event = FindSorafsReputationJournalEventBySourceId::new(selected.source_id, None)
            .execute(&state.view())
            .expect("resolve historical source with later unrelated events");
        assert_eq!(event.sequence, 2);
        assert_eq!(event.entry, *selected);
        assert_eq!(finalized_cursor.height, 4);
    }
    #[test]
    fn source_query_rejects_a_selected_successor_beyond_finality() {
        let (state, entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93, 0x94, 0x95]);
        let selected = &entries[1];
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut successor = read_event(transaction.world(), 3)
            .expect("read selected-event successor")
            .expect("selected-event successor");
        successor.target_block_height = finalized_cursor.height + 1;
        transaction.world.smart_contract_state.insert(
            event_key(3),
            encode_state(&successor, "future selected-event successor")
                .expect("encode future selected-event successor"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            selected.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("selected successor beyond finality must fail");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("targets non-finalized height")
        ));
    }
    #[test]
    fn source_query_rejects_a_selected_successor_after_finalized_time() {
        let (state, entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93, 0x94, 0x95]);
        let selected = &entries[1];
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut successor = read_event(transaction.world(), 3)
            .expect("read selected-event successor")
            .expect("selected-event successor");
        successor.recorded_at_unix_ms = finalized_cursor.finalized_at_unix_ms + 1;
        transaction.world.smart_contract_state.insert(
            event_key(3),
            encode_state(&successor, "late selected-event successor")
                .expect("encode late selected-event successor"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            selected.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("selected successor after finalized time must fail");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("timestamp lies after finalized time")
        ));
    }
    #[test]
    fn source_query_rejects_a_corrupt_selected_predecessor_edge() {
        let (state, entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93]);
        let selected = &entries[1];
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut record = read_event(transaction.world(), 2)
            .expect("read selected event")
            .expect("selected event");
        record.event_index = 1;
        transaction.world.smart_contract_state.insert(
            event_key(2),
            encode_state(&record, "misindexed reputation event").expect("encode misindexed event"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            selected.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("corrupt selected predecessor edge must fail");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("block height or event index is not contiguous")
        ));
    }
    #[test]
    fn source_query_rejects_a_global_terminal_beyond_finality() {
        let (state, entries, finalized_cursor) = state_with_finalized_por_events(&[0x91, 0x92]);
        let selected = &entries[0];
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut terminal = read_event(transaction.world(), 2)
            .expect("read terminal event")
            .expect("terminal event");
        terminal.target_block_height = finalized_cursor.height + 1;
        transaction.world.smart_contract_state.insert(
            event_key(2),
            encode_state(&terminal, "future terminal reputation event")
                .expect("encode future terminal"),
        );
        let mut journal_head = read_journal_head(transaction.world())
            .expect("read journal head")
            .expect("journal head");
        journal_head.last_target_block_height = terminal.target_block_height;
        transaction.world.smart_contract_state.insert(
            journal_head_key().clone(),
            encode_state(&journal_head, "future reputation journal head")
                .expect("encode future head"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            selected.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("future global terminal must fail closed");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("targets non-finalized height")
        ));
    }
    #[test]
    fn absent_source_query_rejects_a_global_terminal_beyond_finality() {
        let (state, _entries, finalized_cursor) = state_with_finalized_por_events(&[0x91, 0x92]);
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut terminal = read_event(transaction.world(), 2)
            .expect("read terminal event")
            .expect("terminal event");
        terminal.target_block_height = finalized_cursor.height + 1;
        transaction.world.smart_contract_state.insert(
            event_key(2),
            encode_state(&terminal, "future terminal reputation event")
                .expect("encode future terminal"),
        );
        let mut journal_head = read_journal_head(transaction.world())
            .expect("read journal head")
            .expect("journal head");
        journal_head.last_target_block_height = terminal.target_block_height;
        transaction.world.smart_contract_state.insert(
            journal_head_key().clone(),
            encode_state(&journal_head, "future reputation journal head")
                .expect("encode future head"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            ReputationJournalSourceIdV1([0xE4; 32]),
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("future global terminal must preclude authoritative absence");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("targets non-finalized height")
        ));
    }
    #[test]
    fn early_event_page_rejects_a_global_terminal_beyond_finality() {
        let (state, _entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93]);
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut terminal = read_event(transaction.world(), 3)
            .expect("read global terminal")
            .expect("global terminal");
        terminal.target_block_height = finalized_cursor.height + 1;
        transaction.world.smart_contract_state.insert(
            event_key(3),
            encode_state(&terminal, "future page terminal").expect("encode future page terminal"),
        );
        let mut journal_head = read_journal_head(transaction.world())
            .expect("read journal head")
            .expect("journal head");
        journal_head.last_target_block_height = terminal.target_block_height;
        transaction.world.smart_contract_state.insert(
            journal_head_key().clone(),
            encode_state(&journal_head, "future page journal head")
                .expect("encode future page journal head"),
        );
        let error = FindSorafsReputationJournalEvents::new(Some(finalized_cursor), None, 1)
            .execute(&transaction)
            .expect_err("early page must validate the global terminal height");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("targets non-finalized height")
        ));
    }
    #[test]
    fn early_event_page_rejects_a_global_terminal_after_finalized_time() {
        let (state, _entries, finalized_cursor) =
            state_with_finalized_por_events(&[0x91, 0x92, 0x93]);
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut terminal = read_event(transaction.world(), 3)
            .expect("read global terminal")
            .expect("global terminal");
        terminal.recorded_at_unix_ms = finalized_cursor.finalized_at_unix_ms + 1;
        transaction.world.smart_contract_state.insert(
            event_key(3),
            encode_state(&terminal, "late page terminal").expect("encode late page terminal"),
        );
        let error = FindSorafsReputationJournalEvents::new(Some(finalized_cursor), None, 1)
            .execute(&transaction)
            .expect_err("early page must validate the global terminal timestamp");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("timestamp lies after finalized time")
        ));
    }
    #[test]
    fn source_query_returns_the_latest_resolved_dispute_revision() {
        let (state, opened, resolved, finalized_cursor) = state_with_finalized_resolved_dispute();
        let event = FindSorafsReputationJournalEventBySourceId::new(
            resolved.source_id,
            Some(finalized_cursor),
        )
        .execute(&state.view())
        .expect("resolve latest dispute source revision");
        assert_eq!(event.sequence, 2);
        assert_eq!(event.entry, resolved);
        assert_eq!(event.entry.source_revision, 2);
        assert_eq!(
            event.entry.predecessor_event_id,
            Some(opened.event_id),
            "resolved revision must bind the exact opened event"
        );
    }
    #[test]
    fn source_query_rejects_a_nonadjacent_future_dispute_predecessor() {
        let (state, resolved, finalized_cursor) =
            state_with_finalized_interleaved_resolved_dispute();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut opened = read_event(transaction.world(), 1)
            .expect("read interleaved opened dispute")
            .expect("interleaved opened dispute");
        opened.target_block_height = finalized_cursor.height + 1;
        transaction.world.smart_contract_state.insert(
            event_key(opened.sequence),
            encode_state(&opened, "future interleaved dispute predecessor")
                .expect("encode future interleaved dispute predecessor"),
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            resolved.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("future nonadjacent source predecessor must fail closed");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(ref message)
                if message.contains("revision edge")
                    || message.contains("strictly precede")
                    || message.contains("non-finalized height")
        ));
    }
    #[test]
    fn source_query_rejects_a_resolved_dispute_with_missing_predecessor() {
        let (state, _opened, resolved, finalized_cursor) = state_with_finalized_resolved_dispute();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let missing_predecessor = ReputationJournalEventIdV1([0xD1; 32]);
        let forged_entry = ReputationJournalEntryV1::try_new(
            resolved.provider_id,
            resolved.authority_policy_digest,
            resolved.recorded_by.clone(),
            resolved.source_time_unix_ms,
            Some(missing_predecessor),
            resolved.payload.clone(),
        )
        .expect("canonical forged resolved dispute entry");
        let terminal = replace_resolved_dispute_entry(&mut transaction, forged_entry);
        let direct_error = validate_event_indexes(transaction.world(), &terminal)
            .expect_err("missing lifecycle predecessor must fail intrinsic source validation");
        assert!(
            direct_error
                .to_string()
                .contains("predecessor is missing its event-id index")
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            resolved.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("query must reject a missing dispute predecessor");
        assert!(matches!(error, QueryExecutionFail::Conversion(_)));
    }
    #[test]
    fn source_query_rejects_substituted_dispute_revision_material() {
        let (state, opened, resolved, finalized_cursor) = state_with_finalized_resolved_dispute();
        let mut block = finalized_query_fixture_block(&state, finalized_cursor);
        let mut transaction = block.transaction();
        let mut substituted_payload = resolved.payload.clone();
        let ReputationJournalPayloadV1::ProviderDispute(dispute) = &mut substituted_payload else {
            panic!("resolved fixture must carry a provider dispute");
        };
        dispute.evidence_digest = [0xD2; 32];
        let forged_entry = ReputationJournalEntryV1::try_new(
            resolved.provider_id,
            resolved.authority_policy_digest,
            resolved.recorded_by.clone(),
            resolved.source_time_unix_ms,
            Some(opened.event_id),
            substituted_payload,
        )
        .expect("canonical substituted resolved dispute entry");
        let terminal = replace_resolved_dispute_entry(&mut transaction, forged_entry);
        let direct_error = validate_event_indexes(transaction.world(), &terminal)
            .expect_err("substituted immutable dispute material must fail lifecycle validation");
        assert!(
            direct_error
                .to_string()
                .contains("revision edge is missing or substituted")
        );
        let error = FindSorafsReputationJournalEventBySourceId::new(
            resolved.source_id,
            Some(finalized_cursor),
        )
        .execute(&transaction)
        .expect_err("query must reject substituted dispute lifecycle material");
        assert!(matches!(error, QueryExecutionFail::Conversion(_)));
    }
    #[test]
    fn recorder_policy_rejects_history_beyond_the_v1_revision_bound() {
        let (mut chain, authority, _other, _provider_id) = certified_reputation_chain();
        let maximum_revision = u64::try_from(REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1)
            .expect("V1 policy-history bound fits u64");
        let mut over_limit = policy(&authority);
        over_limit.revision = maximum_revision + 1;
        over_limit.predecessor_policy_digest = Some([0xA5; 32]);
        let error = commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(over_limit),
        )
        .expect_err("policy revision beyond the hard history bound must fail");
        assert_instruction_message(&error, "exceeds the V1 history bound");
        assert!(
            read_active_policy(chain.state().view().world())
                .unwrap()
                .is_none()
        );
        assert!(
            read_reputation_authority_policy_history(
                chain.state().view().world(),
                REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1 + 1
            )
            .is_err(),
            "finalized history capture must reject a traversal bound above the same ceiling"
        );
    }

    #[test]
    fn source_time_policy_lookup_accepts_the_exact_v1_revision_bound() {
        let (state, authority, _other, _provider_id) = state_with_reputation_accounts();
        let header = BlockHeader::new(
            1_u64.try_into().expect("nonzero height"),
            None,
            None,
            TEST_NOW_MS
                + u64::try_from(REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1)
                    .expect("V1 policy-history bound fits u64"),
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let mut predecessor_policy_digest = None;
        let mut first = None;
        let mut active = None;
        // Pure bounded-history reader preimages, never executor or finalized-proof authority.
        for revision in 1..=REPUTATION_JOURNAL_MAX_AUTHORITY_POLICY_REVISIONS_V1 {
            let revision = u64::try_from(revision).expect("policy revision fits u64");
            let mut candidate = policy(&authority);
            candidate.revision = revision;
            candidate.predecessor_policy_digest = predecessor_policy_digest;
            let record = ReputationJournalAuthorityPolicyRecordV1::try_new(candidate,
(authority.clone()).clone(),
TEST_NOW_MS + revision,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: TEST_NOW_MS + revision, authority: (authority.clone()).clone(),
    }))
            .expect("construct bounded authority-policy record");
            transaction.world.smart_contract_state.insert(
                policy_history_key(&record.policy_digest),
                encode_state(&record, "bounded reputation recorder-policy history")
                    .expect("encode bounded authority-policy record"),
            );
            first.get_or_insert_with(|| record.clone());
            predecessor_policy_digest = Some(record.policy_digest);
            active = Some(record);
        }
        let first = first.expect("revision-one record");
        let active = active.expect("active bounded policy");
        transaction.world.smart_contract_state.insert(
            active_policy_key().clone(),
            encode_state(&active, "active bounded reputation recorder policy")
                .expect("encode active bounded authority-policy record"),
        );
        assert_eq!(
            read_policy_at_source_time(
                transaction.world(),
                active,
                first.policy_digest,
                first.activated_at_unix_ms,
            )
            .expect("traverse the exact V1 policy-history bound"),
            first
        );
    }
    #[test]
    fn recorder_policy_rotation_is_strict_and_historical_replay_is_idempotent() {
        let (mut chain, authority, _other, _provider_id) = certified_reputation_chain();
        let first = policy(&authority);
        let first_digest = first.canonical_digest().expect("first policy digest");
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(first.clone()),
        )
        .expect("activate first recorder policy through signed execution");
        let first_record = FindSorafsReputationJournalAuthorityPolicy
            .execute(&chain.state().view())
            .expect("query first active recorder policy");
        assert_eq!(first_record.policy, first);
        assert_eq!(first_record.policy_digest, first_digest);
        assert_eq!(first_record.activated_by, authority);
        assert_eq!(first_record.activated_at_unix_ms, TEST_NOW_MS);
        let mut second = first.clone();
        second.revision = 2;
        second.predecessor_policy_digest = Some(first_digest);
        let second_digest = second.canonical_digest().expect("second policy digest");
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS + 1_000,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(second),
        )
        .expect("activate exact successor policy");
        let second_record = FindSorafsReputationJournalAuthorityPolicy
            .execute(&chain.state().view())
            .expect("query rotated active recorder policy");
        assert_eq!(second_record.policy.revision, 2);
        assert_eq!(second_record.policy_digest, second_digest);
        assert_eq!(
            second_record.policy.predecessor_policy_digest,
            Some(first_digest)
        );
        assert_eq!(
            read_reputation_authority_policy_history(chain.state().view().world(), 2)
                .expect("read exact bounded policy history"),
            vec![first_record.clone(), second_record.clone()]
        );
        assert!(
            read_reputation_authority_policy_history(chain.state().view().world(), 1).is_err(),
            "an undersized immutable-history bound must fail closed"
        );
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS + 2_000,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(first),
        )
        .expect("historical exact replay is idempotent");
        let mut fork = policy(&authority);
        fork.revision = 3;
        fork.predecessor_policy_digest = Some([0x99; 32]);
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS + 3_000,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(fork),
        )
        .expect_err("policy fork must fail closed");
        assert_eq!(
            read_active_policy(chain.state().view().world())
                .expect("active policy after rejected fork")
                .expect("active policy")
                .policy_digest,
            second_digest
        );
    }

    #[test]
    fn por_append_uses_source_time_policy_across_rotation_and_replay() {
        let (mut chain, authority, _other, provider_id) = certified_reputation_chain();
        let first = policy(&authority);
        let first_digest = first.canonical_digest().expect("first policy digest");
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(first.clone()),
        )
        .expect("activate first recorder policy");
        let queued_before_rotation = por_entry_at(
            &authority,
            provider_id,
            first_digest,
            0x61,
            TEST_NOW_MS + 1_000,
        );
        let mut successor = first;
        successor.revision = 2;
        successor.predecessor_policy_digest = Some(first_digest);
        let successor_digest = successor
            .canonical_digest()
            .expect("successor policy digest");
        commit_reputation_instruction(
            &mut chain,
            TEST_NOW_MS + 2_000,
            1,
            SetSorafsReputationJournalAuthorityPolicy::new(successor),
        )
        .expect("rotate recorder policy");
        let results = commit_reputation_instructions(
            &mut chain,
            TEST_NOW_MS + 3_000,
            vec![
                (
                    1,
                    AppendSorafsPorReputationJournalEntry::new(queued_before_rotation.clone())
                        .into(),
                ),
                (
                    1,
                    AppendSorafsPorReputationJournalEntry::new(queued_before_rotation).into(),
                ),
            ],
        );
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        {
            let view = chain.state().view();
            assert_eq!(
                read_journal_head(view.world())
                    .unwrap()
                    .unwrap()
                    .last_sequence,
                1,
                "an exact crash replay must remain idempotent after policy rotation"
            );
            let retained = read_event(view.world(), 1)
                .unwrap()
                .expect("retained historical PoR entry");
            validate_event_indexes(view.world(), &retained).unwrap();
        }
        let superseded = por_entry_at(
            &authority,
            provider_id,
            first_digest,
            0x62,
            TEST_NOW_MS + 2_000,
        );
        let current = por_entry_at(
            &authority,
            provider_id,
            successor_digest,
            0x63,
            TEST_NOW_MS + 2_500,
        );
        let results = commit_reputation_instructions(
            &mut chain,
            TEST_NOW_MS + 4_000,
            vec![
                (
                    1,
                    AppendSorafsPorReputationJournalEntry::new(superseded).into(),
                ),
                (
                    1,
                    AppendSorafsPorReputationJournalEntry::new(current).into(),
                ),
            ],
        );
        assert_instruction_message(
            results[0]
                .as_ref()
                .expect_err("cutover belongs to successor"),
            "outside its recorder-policy activation interval",
        );
        assert!(results[1].is_ok(), "{:?}", results[1]);
        assert_eq!(
            read_journal_head(chain.state().view().world())
                .unwrap()
                .unwrap()
                .last_sequence,
            2
        );
    }

    #[test]
    fn query_limit_rejects_zero_and_resource_bombs() {
        assert!(checked_query_limit(0).is_err());
        assert_eq!(checked_query_limit(1).expect("minimum"), 1);
        assert_eq!(
            checked_query_limit(
                u32::try_from(REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1).expect("bound fits")
            )
            .expect("maximum"),
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1
        );
        assert!(
            checked_query_limit(
                u32::try_from(REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1 + 1).expect("bound fits")
            )
            .is_err()
        );
    }
    #[test]
    fn journal_successor_rejects_gaps_reordering_and_bad_block_indexes() {
        let account = AccountId::new(iroha_crypto::KeyPair::random().public_key().clone());
        let policy = iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyV1 {
            version: 1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account.clone(),
            dispute_recorder_authority: account.clone(),
            token_recorder_authority: account.clone(),
            stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 24 * 60 * 60 * 1_000,
        };
        let digest = policy.canonical_digest().expect("policy digest");
        let payload = ReputationJournalPayloadV1::StreamTokenValidation(
            iroha_data_model::sorafs::reputation::StreamTokenValidationOutcomeV1 {
                binding: iroha_data_model::sorafs::reputation::StreamTokenValidationBindingV1 {
                    gateway_id: [0x11; 32],
                    gateway_sequence: 1,
                    request_context_digest: [0x22; 32],
                },
                token_body_digest: Some([0x33; 32]),
                token_key_version: Some(1),
                validated_at_unix_ms: 1_000,
                status:
                    iroha_data_model::sorafs::reputation::StreamTokenValidationStatusV1::Accepted,
            },
        );
        let entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x44; 32]),
            digest,
            account,
            1_000,
            None,
            payload,
        )
        .expect("canonical entry");
        let first = ReputationJournalCommittedEventRecordV1 {
            sequence: 1,
            target_block_height: 2,
            event_index: 0,
            recorded_at_unix_ms: 1_100,
            entry: entry.clone(),
        };
        assert!(validate_event_successor(None, &first).is_ok());
        let mut gap = first.clone();
        gap.sequence = 3;
        gap.target_block_height = 3;
        assert!(validate_event_successor(Some(&first), &gap).is_err());
        let mut bad_index = first.clone();
        bad_index.sequence = 2;
        bad_index.event_index = 2;
        assert!(validate_event_successor(Some(&first), &bad_index).is_err());
        let mut next_block = first.clone();
        next_block.sequence = 2;
        next_block.target_block_height = 3;
        next_block.event_index = 0;
        assert!(validate_event_successor(Some(&first), &next_block).is_ok());
    }
    include!("sorafs_reputation/policy_rotation_tests.rs");
    #[test]
    fn asynchronous_source_time_is_bound_while_commit_time_is_authoritative() {
        let (mut state, authority, _other, provider_id) = state_with_reputation_accounts();
        let mut journal_policy = policy(&authority);
        journal_policy.max_source_age_ms = 1_500;
        let policy_digest = journal_policy
            .canonical_digest()
            .expect("canonical recorder policy");
        transact_test(&mut state, 1, TEST_NOW_MS, |transaction| {
            seed_policy_preimage(transaction, &authority, journal_policy)
        })
        .expect("activate recorder policy");
        let source_time_unix_ms = TEST_NOW_MS + 250;
        let recorded_at_unix_ms = TEST_NOW_MS + 1_000;
        let entry = por_entry_at(
            &authority,
            provider_id,
            policy_digest,
            0x81,
            source_time_unix_ms,
        );
        transact_test(&mut state, 2, recorded_at_unix_ms, |transaction| {
            AppendSorafsPorReputationJournalEntry::new(entry.clone())
                .execute(&authority, transaction)?;
            let record = read_event(transaction.world(), 1)?
                .ok_or_else(|| corrupt_state("missing asynchronous reputation event"))?;
            assert_eq!(record.entry.source_time_unix_ms, source_time_unix_ms);
            assert_eq!(record.recorded_at_unix_ms, recorded_at_unix_ms);
            let emitted = transaction
                .world
                .internal_event_buf
                .iter()
                .find_map(|event| match event.as_ref() {
                    DataEvent::Sorafs(SorafsGatewayEvent::ReputationJournal(
                        SorafsReputationJournalEvent::EntryCommitted(committed),
                    )) if committed.event_id == entry.event_id => Some(committed),
                    _ => None,
                })
                .expect("typed committed event");
            assert_eq!(emitted.source_time_unix_ms, source_time_unix_ms);
            assert_eq!(emitted.recorded_at_unix_ms, recorded_at_unix_ms);
            Ok(())
        })
        .expect("commit delayed but fresh source observation");
        let future = por_entry_at(
            &authority,
            provider_id,
            policy_digest,
            0x82,
            TEST_NOW_MS + 2_001,
        );
        transact_test(&mut state, 3, TEST_NOW_MS + 2_000, |transaction| {
            let error = AppendSorafsPorReputationJournalEntry::new(future)
                .execute(&authority, transaction)
                .expect_err("future source observation must fail closed");
            assert!(
                matches!(&error,
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message)
                    ) if message.contains("after authoritative commit time")
                ),
                "{error:?}"
            );
            Ok(())
        })
        .expect("commit block after rejecting future source observation");
        let outdated = por_entry_at(&authority, provider_id, policy_digest, 0x83, TEST_NOW_MS);
        transact_test(&mut state, 4, TEST_NOW_MS + 3_000, |transaction| {
            let error = AppendSorafsPorReputationJournalEntry::new(outdated)
                .execute(&authority, transaction)
                .expect_err("stale source observation must fail closed");
            assert!(
                matches!(&error,
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message)
                    ) if message.contains("exceeds 1500ms")
                ),
                "{error:?}"
            );
            Ok(())
        })
        .expect("commit block after rejecting stale source observation");
        let view = state.view();
        let page = FindSorafsReputationJournalEvents::new(None, None, 8)
            .execute(&view)
            .expect("query finalized reputation event");
        assert_eq!(page.events.len(), 1);
        assert_eq!(
            page.events[0].entry.source_time_unix_ms,
            source_time_unix_ms
        );
        assert_eq!(page.events[0].recorded_at_unix_ms, recorded_at_unix_ms);
    }
    #[test]
    fn capacity_dispute_resolution_is_atomic_terminal_and_replay_safe() {
        let (mut state, authority, _other, provider_id) = state_with_reputation_accounts();
        let policy = policy(&authority);
        let policy_digest = policy.canonical_digest().expect("policy digest");
        let dispute_id = iroha_data_model::sorafs::capacity::CapacityDisputeId::new([0x71; 32]);
        let record = CapacityDisputeRecord::new_pending(
            dispute_id,
            provider_id,
            [0x72; 32],
            None,
            2,
            TEST_NOW_MS / 1_000,
            "governed uptime dispute".to_owned(),
            Some("restore service".to_owned()),
            iroha_data_model::sorafs::capacity::CapacityDisputeEvidence {
                digest: [0x73; 32],
                media_type: Some("application/norito".to_owned()),
                uri: None,
                size_bytes: Some(128),
            },
            vec![0x74],
        );
        transact_test(&mut state, 1, TEST_NOW_MS, |transaction| {
            seed_policy_preimage(transaction, &authority, policy)?;
            validate_capacity_dispute_opened_replay(transaction, &authority, &record)
                .expect_err("an existing dispute without its opened journal must fail closed");
            assert!(
                read_journal_head(transaction.world())
                    .expect("read journal after rejected incomplete replay")
                    .is_none(),
                "replay validation must not backfill missing authoritative state"
            );
            let mut stale_record = record.clone();
            stale_record.submitted_epoch = stale_record.submitted_epoch.saturating_add(1);
            append_capacity_dispute_opened(transaction, &authority, &stale_record)
                .expect_err("dispute intake time must bind to the committing block");
            assert!(
                read_journal_head(transaction.world())
                    .expect("read journal after rejected dispute")
                    .is_none(),
                "rejected dispute intake must not advance the journal"
            );
            append_capacity_dispute_opened(transaction, &authority, &record)?;
            transaction
                .world
                .capacity_disputes
                .insert(dispute_id, record);
            Ok(())
        })
        .expect("commit opened dispute");
        let resolution = ResolveSorafsCapacityDispute::new(
            dispute_id,
            policy_digest,
            iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Upheld,
            [0x75; 32],
            Some("evidence confirmed".to_owned()),
        );
        transact_test(&mut state, 2, TEST_NOW_MS + 1_000, |transaction| {
            resolution.clone().execute(&authority, transaction)
        })
        .expect("commit terminal dispute decision");
        {
            let view = state.view();
            let first_page = FindSorafsReputationJournalEvents::new(None, None, 1)
                .execute(&view)
                .expect("query first finalized reputation page");
            assert_eq!(first_page.events.len(), 1);
            assert!(first_page.has_more);
            let next_after = first_page.next_after.expect("continuation cursor");
            let second_page = FindSorafsReputationJournalEvents::new(
                Some(first_page.finalized_cursor),
                Some(next_after),
                1,
            )
            .execute(&view)
            .expect("query terminal finalized reputation page");
            assert_eq!(second_page.events.len(), 1);
            assert_eq!(second_page.events[0].sequence, 2);
            assert!(!second_page.has_more);
            assert!(second_page.next_after.is_none());
        }
        let header = BlockHeader::new(
            3_u64.try_into().expect("nonzero height"),
            None,
            None,
            TEST_NOW_MS + 2_000,
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let rotated_policy = ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 2,
            predecessor_policy_digest: Some(policy_digest),
            por_recorder_authority: authority.clone(),
            dispute_recorder_authority: authority.clone(),
            token_recorder_authority: authority.clone(),
            stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 24 * 60 * 60 * 1_000,
        };
        seed_policy_preimage(&mut transaction, &authority, rotated_policy)
            .expect("rotate dispute recorder policy before delayed replay");
        let stored = transaction
            .world
            .capacity_disputes
            .get(&dispute_id)
            .expect("resolved dispute");
        assert!(matches!(
            &stored.status,
            CapacityDisputeStatus::Resolved(resolved)
                if resolved.outcome
                    == iroha_data_model::sorafs::capacity::CapacityDisputeOutcome::Upheld
        ));
        let source_id = ReputationJournalSourceIdV1::for_provider_dispute(dispute_id);
        let source_head = read_source_head(transaction.world(), source_id)
            .expect("read source head")
            .expect("source head");
        assert_eq!(source_head.source_revision, 2);
        assert_eq!(source_head.sequence, 2);
        resolution
            .execute(&authority, &mut transaction)
            .expect("delayed exact resolution replay is idempotent");
        assert_eq!(
            read_journal_head(transaction.world())
                .expect("read journal head")
                .expect("journal head")
                .last_sequence,
            2
        );
    }
}

#[cfg(test)]
mod journal_frame_identity_tests {
    use super::*;

    #[test]
    fn reputation_head_frame_roundtrips_through_bounded_storage_codec() {
        let head = ReputationJournalHeadStateV1 {
            last_sequence: 5,
            last_target_block_height: 10,
            last_event_index: 1,
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &head,
            "iroha_core::smartcontracts::isi::sorafs_reputation::ReputationJournalHeadStateV1",
        );
        let bytes =
            encode_state(&head, "reputation journal head").expect("production state writer");
        assert_eq!(
            decode_state::<ReputationJournalHeadStateV1>(&bytes, "reputation journal head")
                .expect("bounded production state reader"),
            head
        );
        let mut wrong_owner = bytes;
        wrong_owner[6] ^= 1;
        assert!(
            decode_state::<ReputationJournalHeadStateV1>(&wrong_owner, "reputation journal head")
                .is_err()
        );
    }
}
