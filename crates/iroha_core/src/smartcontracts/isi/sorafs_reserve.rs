//! Chain-authoritative SoraFS reserve, rent, credit, and appeal handlers.
use super::*;
use crate::smartcontracts::ValidSingularQuery;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::smartcontracts::isi::helpers::transaction_account_has_permission as has_permission;
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    asset::AssetId,
    events::data::sorafs::{
        SorafsGatewayEvent, SorafsReserveLedgerEvent, SorafsReserveLedgerEventKind,
    },
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            AdvanceSorafsReserveLifecycle, ChargeSorafsReserveRent, DecideSorafsReserveAppeal,
            DecideSorafsReserveMovement, DrawSorafsReserveCredit, RegisterSorafsReserveAccount,
            RepaySorafsReserveCredit, RequestSorafsReserveMovement, SetSorafsReservePolicy,
            SubmitSorafsReserveAppeal,
        },
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsReserveAppealById, FindSorafsReserveAppeals, FindSorafsReserveEvents,
            FindSorafsReserveMovementById, FindSorafsReserveMovements, FindSorafsReservePolicy,
            FindSorafsReserveProviderById, FindSorafsReserveProviders,
        },
    },
    sorafs::{
        capacity::ProviderId,
        pricing::ProviderCreditRecord,
        reserve::{
            RESERVE_COMMITTED_EVENT_MAX_BYTES_V1, RESERVE_MAX_REASON_BYTES_V1,
            RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1, RESERVE_QUERY_MAX_ITEMS_V1,
            RESERVE_RENT_BILLING_PERIOD_SECONDS_V1, RESERVE_RENT_MAX_BILLING_PERIODS_V1,
            ReserveAppealPageV1, ReserveAppealRecordV1, ReserveAppealStatusV1,
            ReserveAuthorityPolicyRecordV1, ReserveAuthorityPolicyV1, ReserveFinalizedCursorV1,
            ReserveFinalizedEventPageV1, ReserveFinalizedEventV1, ReserveLifecycleStage,
            ReserveMovementKindV1, ReserveMovementPageV1, ReserveMovementRecordV1,
            ReserveMovementStatusV1, ReserveProviderAccountPageV1, ReserveProviderAccountV1,
            ReserveTier,
            history::{
                RESERVE_PROVIDER_STATE_KEY_PREFIX_V1, RESERVE_STATE_KEY_PREFIX_V1,
                ReserveEventJournalHeadV1, ReserveStateV1, STATE_LIMITS, STATE_MAX_BYTES,
                is_reserve_state_key, reserve_provider_key, reserve_state_key,
            },
        },
    },
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::decode_canonical_with_limits;
use sorafs_manifest::deal::XorQuantity;
use std::str::FromStr;
const MOVEMENT_STATE_KEY_PREFIX: &str = "sorafs_reserve_movement_v1_";
const APPEAL_STATE_KEY_PREFIX: &str = "sorafs_reserve_appeal_v1_";
const EVENT_STATE_KEY_PREFIX: &str = "sorafs_reserve_event_v1_";
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sorafs_reserve::ReservePersistedEventV1")]
struct ReservePersistedEventV1 {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    event: SorafsReserveLedgerEvent,
}
/// Non-reusable proof that the reserve state machine approved one exact
/// provider withdrawal from protocol custody.
pub(in crate::smartcontracts::isi) struct VerifiedSorafsReserveWithdrawal {
    provider_id: ProviderId,
    movement_id: [u8; 32],
    policy_digest: [u8; 32],
    expected_provider_revision: u64,
    decision_authority: AccountId,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
}
impl VerifiedSorafsReserveWithdrawal {
    fn new(
        provider_id: ProviderId,
        movement_id: [u8; 32],
        policy_digest: [u8; 32],
        expected_provider_revision: u64,
        decision_authority: AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            provider_id,
            movement_id,
            policy_digest,
            expected_provider_revision,
            decision_authority,
            source_id,
            destination_id,
            amount,
        }
    }
    /// Consume the proof into the exact retained-state and balance binding.
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        ProviderId,
        [u8; 32],
        [u8; 32],
        u64,
        AccountId,
        AssetId,
        AssetId,
        Quantity,
    ) {
        (
            self.provider_id,
            self.movement_id,
            self.policy_digest,
            self.expected_provider_revision,
            self.decision_authority,
            self.source_id,
            self.destination_id,
            self.amount,
        )
    }
}
fn invalid_parameter(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn corrupt_state(message: impl Into<String>) -> InstructionExecutionError {
    InstructionExecutionError::InvariantViolation(message.into().into())
}
#[allow(clippy::too_many_arguments)]
fn emit_reserve_event(
    state_transaction: &mut StateTransaction<'_, '_>,
    kind: SorafsReserveLedgerEventKind,
    provider_id: ProviderId,
    operation_id: Option<[u8; 32]>,
    policy_digest: [u8; 32],
    provider_revision: u64,
    authority: &AccountId,
    now_unix: u64,
) -> Result<(), InstructionExecutionError> {
    if kind == SorafsReserveLedgerEventKind::PolicyActivated {
        return Err(corrupt_state(
            "provider-specific reserve event cannot use the policy activation kind",
        ));
    }
    let account = read_provider(state_transaction.world(), provider_id)?.ok_or_else(|| {
        corrupt_state("provider-specific reserve event has no authoritative provider after-state")
    })?;
    if account.policy_digest != policy_digest
        || account.revision != provider_revision
        || account.updated_at_unix != now_unix
    {
        return Err(corrupt_state(
            "provider-specific reserve event does not match authoritative provider after-state",
        ));
    }
    let occurred_at_unix_ms = now_unix
        .checked_mul(1_000)
        .ok_or_else(|| corrupt_state("reserve event timestamp overflow"))?;
    let event = SorafsReserveLedgerEvent {
        kind,
        provider_id: Some(provider_id),
        operation_id,
        policy_digest,
        provider_revision,
        resulting_lifecycle_stage: Some(account.lifecycle_stage),
        authority: authority.clone(),
        occurred_at_unix_ms,
    };
    append_reserve_event_journal(state_transaction, &event, None)?;
    state_transaction
        .world
        .emit_events(Some(SorafsGatewayEvent::ReserveLedger(event)));
    Ok(())
}
fn emit_reserve_policy_activation(
    state_transaction: &mut StateTransaction<'_, '_>,
    policy: ReserveAuthorityPolicyRecordV1,
    authority: &AccountId,
    now_unix: u64,
) -> Result<(), InstructionExecutionError> {
    let occurred_at_unix_ms = now_unix
        .checked_mul(1_000)
        .ok_or_else(|| corrupt_state("reserve event timestamp overflow"))?;
    let event = SorafsReserveLedgerEvent {
        kind: SorafsReserveLedgerEventKind::PolicyActivated,
        provider_id: None,
        operation_id: None,
        policy_digest: policy.policy_digest,
        provider_revision: 0,
        resulting_lifecycle_stage: None,
        authority: authority.clone(),
        occurred_at_unix_ms,
    };
    append_reserve_event_journal(state_transaction, &event, Some(policy))?;
    state_transaction
        .world
        .emit_events(Some(SorafsGatewayEvent::ReserveLedger(event)));
    Ok(())
}
fn require_governance(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if has_permission(state_transaction, authority, "CanSetSorafsReservePolicy") {
        Ok(())
    } else {
        Err(invalid_parameter(
            "CanSetSorafsReservePolicy is required for authoritative reserve governance",
        ))
    }
}
fn digest_key(prefix: &str, digest: [u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static prefix plus lowercase hex is a valid state key")
}
fn movement_key(movement_id: [u8; 32]) -> StatePath {
    digest_key(MOVEMENT_STATE_KEY_PREFIX, movement_id)
}
fn appeal_key(appeal_id: [u8; 32]) -> StatePath {
    digest_key(APPEAL_STATE_KEY_PREFIX, appeal_id)
}
fn event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{EVENT_STATE_KEY_PREFIX}{sequence:016x}"))
        .expect("static prefix plus fixed-width lowercase hex is a valid state key")
}
fn encode_state<T: norito::core::NoritoSerialize>(
    value: &T,
    label: &str,
) -> Result<Vec<u8>, InstructionExecutionError> {
    norito::encode_canonical(value)
        .map_err(|error| corrupt_state(format!("failed to encode {label}: {error}")))
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
fn validate_persisted_event(
    record: &ReservePersistedEventV1,
    expected_sequence: u64,
) -> Result<(), InstructionExecutionError> {
    if record.sequence == 0
        || record.sequence != expected_sequence
        || record.target_block_height == 0
        || record.event.occurred_at_unix_ms == 0
        || record.event.policy_digest == [0; 32]
        || record
            .event
            .provider_id
            .is_some_and(|provider_id| provider_id.as_bytes() == &[0; 32])
        || record.event.operation_id == Some([0; 32])
    {
        return Err(corrupt_state(
            "stored reserve event cursor or payload metadata is invalid",
        ));
    }
    let shape_is_valid = match record.event.kind {
        SorafsReserveLedgerEventKind::PolicyActivated => {
            record.event.provider_id.is_none()
                && record.event.operation_id.is_none()
                && record.event.provider_revision == 0
                && record.event.resulting_lifecycle_stage.is_none()
        }
        SorafsReserveLedgerEventKind::ProviderRegistered => {
            record.event.provider_id.is_some()
                && record.event.operation_id.is_none()
                && record.event.provider_revision == 1
                && record.event.resulting_lifecycle_stage.is_some()
        }
        SorafsReserveLedgerEventKind::MovementRequested
        | SorafsReserveLedgerEventKind::MovementApproved
        | SorafsReserveLedgerEventKind::MovementRejected
        | SorafsReserveLedgerEventKind::AppealSubmitted
        | SorafsReserveLedgerEventKind::AppealAccepted
        | SorafsReserveLedgerEventKind::AppealRejected => {
            record.event.provider_id.is_some()
                && record.event.operation_id.is_some()
                && record.event.provider_revision > 0
                && record.event.resulting_lifecycle_stage.is_some()
        }
        SorafsReserveLedgerEventKind::RentCharged
        | SorafsReserveLedgerEventKind::LifecycleAdvanced
        | SorafsReserveLedgerEventKind::CreditDrawn
        | SorafsReserveLedgerEventKind::CreditRepaid => {
            record.event.provider_id.is_some()
                && record.event.operation_id.is_none()
                && record.event.provider_revision > 0
                && record.event.resulting_lifecycle_stage.is_some()
        }
    };
    if !shape_is_valid {
        return Err(corrupt_state(
            "stored reserve event payload shape is invalid",
        ));
    }
    Ok(())
}
fn validate_event_successor(
    previous: Option<&ReservePersistedEventV1>,
    current: &ReservePersistedEventV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1 || current.event_index != 0 {
            return Err(corrupt_state(
                "reserve event journal does not begin at sequence one and block index zero",
            ));
        }
        return Ok(());
    };
    if previous
        .sequence
        .checked_add(1)
        .is_none_or(|next| current.sequence != next)
    {
        return Err(corrupt_state(
            "reserve event journal sequence is not contiguous",
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous
                .event_index
                .checked_add(1)
                .is_some_and(|next| current.event_index == next) =>
        {
            Ok(())
        }
        _ => Err(corrupt_state(
            "reserve event journal block height/index ordering is invalid",
        )),
    }
}
fn read_persisted_event(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<ReservePersistedEventV1>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_state("reserve event sequence zero cannot be read"));
    }
    let Some(bytes) = world.smart_contract_state().get(&event_key(sequence)) else {
        return Ok(None);
    };
    decode_persisted_event(bytes, sequence).map(Some)
}
fn decode_persisted_event(
    bytes: &[u8],
    sequence: u64,
) -> Result<ReservePersistedEventV1, InstructionExecutionError> {
    decode_persisted_event_with_current(bytes, sequence, None)
}
fn decode_persisted_event_for_current(
    bytes: &[u8],
    sequence: u64,
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<ReservePersistedEventV1, InstructionExecutionError> {
    decode_persisted_event_with_current(bytes, sequence, Some(current))
}
fn decode_persisted_event_with_current(
    bytes: &[u8],
    sequence: u64,
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<ReservePersistedEventV1, InstructionExecutionError> {
    if bytes.len() > RESERVE_COMMITTED_EVENT_MAX_BYTES_V1 {
        return Err(corrupt_state(format!(
            "reserve committed event exceeds {RESERVE_COMMITTED_EVENT_MAX_BYTES_V1} bytes"
        )));
    }
    let record: ReservePersistedEventV1 = match current {
        Some(current) => decode_state_for_current(bytes, "reserve committed event", current)?,
        None => decode_state(bytes, "reserve committed event")?,
    };
    validate_persisted_event(&record, sequence)?;
    Ok(record)
}
fn validate_event_journal_head(
    world: &impl WorldReadOnly,
    head: ReserveEventJournalHeadV1,
) -> Result<(), InstructionExecutionError> {
    let record = read_persisted_event(world, head.last_sequence)?
        .ok_or_else(|| corrupt_state("reserve event journal head references a missing event"))?;
    if record.target_block_height != head.last_target_block_height
        || record.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "reserve event journal head does not match its terminal event",
        ));
    }
    let predecessor = if head.last_sequence == 1 {
        None
    } else {
        let predecessor_sequence = head.last_sequence - 1;
        Some(
            read_persisted_event(world, predecessor_sequence)?.ok_or_else(|| {
                corrupt_state(format!(
                    "reserve event journal is missing terminal predecessor sequence {predecessor_sequence}"
                ))
            })?,
        )
    };
    validate_event_successor(predecessor.as_ref(), &record)?;
    Ok(())
}
fn ensure_reserve_namespace_empty(
    world: &impl WorldReadOnly,
) -> Result<(), InstructionExecutionError> {
    let prefix =
        StatePath::from_str(RESERVE_STATE_KEY_PREFIX_V1).expect("static reserve prefix is valid");
    if world
        .smart_contract_state()
        .range(prefix..)
        .next()
        .is_some_and(|(key, _)| is_reserve_state_key(key.as_ref()))
    {
        return Err(corrupt_state(
            "initial reserve activation requires an empty reserve state namespace",
        ));
    }
    Ok(())
}
fn ensure_no_event_after_head(
    world: &impl WorldReadOnly,
    head: Option<ReserveEventJournalHeadV1>,
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
                "reserve event journal contains records without a head",
            ));
        }
        (Some(_), Some(key)) if *key == event_key(1) => {}
        (Some(_), _) => {
            return Err(corrupt_state(
                "reserve event journal does not begin at sequence one",
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
            "reserve event journal contains a record beyond its head",
        ));
    }
    Ok(())
}
fn append_reserve_event_journal(
    state_transaction: &mut StateTransaction<'_, '_>,
    event: &SorafsReserveLedgerEvent,
    next_policy: Option<ReserveAuthorityPolicyRecordV1>,
) -> Result<(), InstructionExecutionError> {
    let committed_parent_height = u64::try_from(state_transaction.block_hashes().len())
        .map_err(|_| corrupt_state("committed reserve parent height does not fit into u64"))?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_state("reserve event target block height overflow"))?;
    let executing_block_height = state_transaction._curr_block.height().get();
    if target_block_height != executing_block_height {
        return Err(corrupt_state(format!(
            "reserve event target height {target_block_height} does not match executing block height {executing_block_height}"
        )));
    }
    let current_state = read_reserve_state(state_transaction.world())?;
    let head = current_state.as_ref().map(|state| state.journal_head);
    ensure_no_event_after_head(state_transaction.world(), head)?;
    let (sequence, event_index) = match head {
        Some(head) => {
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("reserve event sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("reserve event block index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_state(
                        "reserve event target height regressed behind the journal head",
                    ));
                }
            };
            (sequence, event_index)
        }
        None => {
            ensure_reserve_namespace_empty(state_transaction.world())?;
            let policy = next_policy.as_ref().ok_or_else(|| {
                corrupt_state("first reserve event has no initial policy activation")
            })?;
            if event.kind != SorafsReserveLedgerEventKind::PolicyActivated
                || event.provider_id.is_some()
                || event.operation_id.is_some()
                || event.provider_revision != 0
                || event.resulting_lifecycle_stage.is_some()
                || policy.policy.revision != 1
                || policy.policy_digest != event.policy_digest
            {
                return Err(corrupt_state(
                    "reserve event journal must begin with initial policy activation",
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
            "reserve event journal sequence already exists",
        ));
    }
    let record = ReservePersistedEventV1 {
        sequence,
        target_block_height,
        event_index,
        event: event.clone(),
    };
    validate_persisted_event(&record, sequence)?;
    let previous = if sequence == 1 {
        None
    } else {
        read_persisted_event(state_transaction.world(), sequence - 1)?
    };
    validate_event_successor(previous.as_ref(), &record)?;
    let encoded_record = encode_state(&record, "reserve committed event")?;
    if encoded_record.len() > RESERVE_COMMITTED_EVENT_MAX_BYTES_V1 {
        return Err(corrupt_state(format!(
            "encoded reserve committed event exceeds {RESERVE_COMMITTED_EVENT_MAX_BYTES_V1} bytes"
        )));
    }
    let next_head = ReserveEventJournalHeadV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    let policy = match (current_state, next_policy) {
        (None, Some(policy)) => policy,
        (Some(_), Some(policy)) if event.kind == SorafsReserveLedgerEventKind::PolicyActivated => {
            policy
        }
        (Some(state), None) if event.kind != SorafsReserveLedgerEventKind::PolicyActivated => {
            state.policy
        }
        _ => {
            return Err(corrupt_state(
                "reserve policy transition does not match the journal event kind",
            ));
        }
    };
    let next_state = ReserveStateV1 {
        policy,
        journal_head: next_head,
    };
    let encoded_state = encode_state(&next_state, "reserve state")?;
    state_transaction
        .world
        .smart_contract_state
        .insert(key, encoded_record);
    state_transaction
        .world
        .smart_contract_state
        .insert(reserve_state_key().clone(), encoded_state);
    Ok(())
}
fn now_unix(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms() / 1_000;
    if now == 0 {
        return Err(invalid_parameter(
            "authoritative reserve operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn read_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<ReserveAuthorityPolicyRecordV1>, InstructionExecutionError> {
    Ok(read_reserve_state(world)?.map(|state| state.policy))
}
/// Return whether `asset_id` is the exact asset held by active SoraFS reserve custody.
pub(super) fn is_reserve_custody_asset(
    world: &impl WorldReadOnly,
    asset_id: &AssetId,
) -> Result<bool, InstructionExecutionError> {
    Ok(read_policy(world)?.is_some_and(|record| {
        record.policy.asset_definition == *asset_id.definition()
            && record.policy.custody_account == *asset_id.account()
    }))
}
/// Return whether `account_id` is the active SoraFS reserve custody account.
pub(super) fn is_reserve_custody_account(
    world: &impl WorldReadOnly,
    account_id: &AccountId,
) -> Result<bool, InstructionExecutionError> {
    Ok(read_policy(world)?.is_some_and(|record| record.policy.custody_account == *account_id))
}
/// Return whether `definition_id` backs the active SoraFS reserve ledger.
pub(super) fn is_reserve_asset_definition(
    world: &impl WorldReadOnly,
    definition_id: &iroha_data_model::asset::AssetDefinitionId,
) -> Result<bool, InstructionExecutionError> {
    Ok(read_policy(world)?.is_some_and(|record| record.policy.asset_definition == *definition_id))
}
/// Revalidate a sealed withdrawal against the still-pending authoritative
/// movement and provider records immediately before custody is debited.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_verified_reserve_withdrawal(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    movement_id: [u8; 32],
    policy_digest: [u8; 32],
    expected_provider_revision: u64,
    decision_authority: &AccountId,
    source_id: &AssetId,
    destination_id: &AssetId,
    amount: &Quantity,
) -> Result<(), InstructionExecutionError> {
    let policy = read_policy(world)?
        .ok_or_else(|| corrupt_state("verified reserve withdrawal has no active policy"))?;
    if policy.policy_digest != policy_digest
        || policy.policy.decision_authority != *decision_authority
        || policy.policy.asset_definition != *source_id.definition()
        || policy.policy.custody_account != *source_id.account()
    {
        return Err(corrupt_state(
            "verified reserve withdrawal does not match active policy custody",
        ));
    }
    let account = read_provider(world, provider_id)?
        .ok_or_else(|| corrupt_state("verified reserve withdrawal has no provider account"))?;
    if account.policy_digest != policy_digest
        || account.revision != expected_provider_revision
        || destination_id.definition() != source_id.definition()
        || account.terms.provider_account != *destination_id.account()
    {
        return Err(corrupt_state(
            "verified reserve withdrawal does not match the provider revision and owner",
        ));
    }
    let movement = read_movement(world, movement_id)?
        .ok_or_else(|| corrupt_state("verified reserve withdrawal has no retained movement"))?;
    if movement.provider_id != provider_id
        || movement.policy_digest != policy_digest
        || movement.kind != ReserveMovementKindV1::Withdrawal
        || movement.status != ReserveMovementStatusV1::Pending
        || movement.amount.as_quantity() != amount
    {
        return Err(corrupt_state(
            "verified reserve withdrawal does not match the pending retained movement",
        ));
    }
    Ok(())
}
fn read_reserve_state(
    world: &impl WorldReadOnly,
) -> Result<Option<ReserveStateV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(reserve_state_key()) else {
        return Ok(None);
    };
    let state = decode_reserve_state(bytes)?;
    validate_event_journal_head(world, state.journal_head)?;
    Ok(Some(state))
}
fn decode_reserve_state(bytes: &[u8]) -> Result<ReserveStateV1, InstructionExecutionError> {
    decode_reserve_state_with_current(bytes, None)
}
fn decode_reserve_state_for_current(
    bytes: &[u8],
    current: &mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation,
) -> Result<ReserveStateV1, InstructionExecutionError> {
    decode_reserve_state_with_current(bytes, Some(current))
}
fn decode_reserve_state_with_current(
    bytes: &[u8],
    current: Option<&mut crate::smartcontracts::isi::query::SingularQueryCurrentAllocation>,
) -> Result<ReserveStateV1, InstructionExecutionError> {
    let state: ReserveStateV1 = match current {
        Some(current) => decode_state_for_current(bytes, "reserve state", current)?,
        None => decode_state(bytes, "reserve state")?,
    };
    state
        .validate()
        .map_err(|error| corrupt_state(error.to_string()))?;
    Ok(state)
}
fn active_policy(
    state_transaction: &StateTransaction<'_, '_>,
    expected_digest: [u8; 32],
) -> Result<(ReserveAuthorityPolicyRecordV1, u64), InstructionExecutionError> {
    let now = now_unix(state_transaction)?;
    let record = read_policy(state_transaction.world())?
        .ok_or_else(|| invalid_parameter("SoraFS reserve policy is not configured"))?;
    if record.policy_digest != expected_digest {
        return Err(invalid_parameter(format!(
            "reserve policy digest mismatch: supplied {}, active {}",
            hex::encode(expected_digest),
            hex::encode(record.policy_digest)
        )));
    }
    if record.activated_at_unix > now {
        return Err(corrupt_state(
            "stored reserve policy activation is later than the current block",
        ));
    }
    Ok((record, now))
}
fn require_operations_authority(
    authority: &AccountId,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<(), InstructionExecutionError> {
    if authority == &policy.policy.operations_authority {
        Ok(())
    } else {
        Err(invalid_parameter(
            "reserve transaction authority is not the exact governed operations account",
        ))
    }
}
fn require_decision_authority(
    authority: &AccountId,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<(), InstructionExecutionError> {
    if authority == &policy.policy.decision_authority {
        Ok(())
    } else {
        Err(invalid_parameter(
            "reserve transaction authority is not the exact governed decision account",
        ))
    }
}
fn registered_provider_owner(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
) -> Result<AccountId, InstructionExecutionError> {
    world
        .provider_owners()
        .get(&provider_id)
        .cloned()
        .ok_or_else(|| invalid_parameter(format!("unknown SoraFS provider {provider_id}")))
}
fn credit_cap(
    policy: &ReserveAuthorityPolicyV1,
    terms: &iroha_data_model::sorafs::reserve::ReserveProviderTermsV1,
) -> Result<XorQuantity, InstructionExecutionError> {
    let quote = policy
        .economics
        .quote(
            terms.storage_class,
            terms.capacity_gib,
            terms.duration,
            terms.tier,
            XorQuantity::zero(),
        )
        .map_err(|error| invalid_parameter(format!("invalid reserve account terms: {error}")))?;
    Ok(quote.credit_line_cap.map_or_else(XorQuantity::zero, |cap| {
        XorQuantity::min(&cap, &policy.max_provider_debt)
    }))
}
/// Read one canonical authoritative reserve-provider account by exact registry id.
pub(super) fn read_provider(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
) -> Result<Option<ReserveProviderAccountV1>, InstructionExecutionError> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&reserve_provider_key(provider_id))
    else {
        return Ok(None);
    };
    decode_provider_record(bytes, provider_id).map(Some)
}
fn total_reserved_custody(
    world: &impl WorldReadOnly,
) -> Result<XorQuantity, InstructionExecutionError> {
    let start = StatePath::from_str(RESERVE_PROVIDER_STATE_KEY_PREFIX_V1)
        .expect("static provider prefix is valid");
    let mut total = XorQuantity::zero();
    for (key, payload) in world.smart_contract_state().range(start..) {
        if !key
            .to_string()
            .starts_with(RESERVE_PROVIDER_STATE_KEY_PREFIX_V1)
        {
            break;
        }
        let candidate: ReserveProviderAccountV1 =
            decode_state(payload, "reserve provider account")?;
        let provider_id = candidate.terms.provider_id;
        if reserve_provider_key(provider_id) != *key {
            return Err(corrupt_state(
                "authoritative reserve provider key does not match its account",
            ));
        }
        let account = decode_provider_record(payload, provider_id)?;
        total = total
            .checked_add(&account.reserve_balance)
            .map_err(|error| corrupt_state(format!("reserve custody total overflow: {error}")))?;
    }
    Ok(total)
}
/// Resolve collateral that is backed by the native owner-funded reserve flow.
///
/// The returned balance is not an administrator-authored credit projection.
/// It is the provider's reserve partition minus any outstanding treasury-funded
/// credit principal. Native custody must also cover the sum of every provider
/// partition, preventing the same custody balance from backing multiple bonds.
pub(super) fn verified_provider_bond(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    expected_owner: &AccountId,
    committed_capacity_gib: u64,
) -> Result<XorQuantity, InstructionExecutionError> {
    let policy = read_policy(world)?
        .ok_or_else(|| invalid_parameter("SoraFS reserve policy is not configured"))?;
    let account = read_provider(world, provider_id)?.ok_or_else(|| {
        invalid_parameter(format!(
            "provider {provider_id} has no owner-funded reserve account"
        ))
    })?;
    if account.terms.provider_account != *expected_owner {
        return Err(invalid_parameter(format!(
            "provider {provider_id} reserve account is bound to {}, not the governed owner {expected_owner}",
            account.terms.provider_account
        )));
    }
    if account.terms.capacity_gib < committed_capacity_gib {
        return Err(invalid_parameter(format!(
            "provider {provider_id} reserve account covers {} GiB, below the declared {committed_capacity_gib} GiB",
            account.terms.capacity_gib
        )));
    }
    let custody_balance =
        provider_spendable_balance(world, &policy.policy, &policy.policy.custody_account)?;
    let reserved_custody = total_reserved_custody(world)?;
    if custody_balance < reserved_custody {
        return Err(corrupt_state(format!(
            "aggregate provider reserve partitions exceed the native custody asset balance while verifying provider {provider_id}"
        )));
    }
    account
        .reserve_balance
        .checked_sub(&account.debt_principal)
        .map_err(|error| {
            corrupt_state(format!(
                "provider {provider_id} owner-funded reserve underflow: {error}"
            ))
        })
}
fn credit_after_verified_reserve_withdrawal(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    current_reserve: &XorQuantity,
    remaining_reserve: &XorQuantity,
    debt_principal: &XorQuantity,
) -> Result<Option<ProviderCreditRecord>, InstructionExecutionError> {
    let Some(mut credit) = world.provider_credit_ledger().get(&provider_id).cloned() else {
        return Ok(None);
    };
    let current_owner_funded = current_reserve
        .checked_sub(debt_principal)
        .map_err(|error| {
            corrupt_state(format!(
                "provider {provider_id} owner-funded reserve underflow before withdrawal: {error}"
            ))
        })?;
    let bonded = XorQuantity::try_from_quantity(credit.bonded.clone()).map_err(|error| {
        corrupt_state(format!(
            "provider {provider_id} bonded credit projection is invalid: {error}"
        ))
    })?;
    let slashed = XorQuantity::try_from_quantity(credit.slashed.clone()).map_err(|error| {
        corrupt_state(format!(
            "provider {provider_id} slash-lien projection is invalid: {error}"
        ))
    })?;
    let committed = bonded.checked_add(&slashed).map_err(|error| {
        corrupt_state(format!(
            "provider {provider_id} custody commitment overflow: {error}"
        ))
    })?;
    if committed > current_owner_funded {
        return Err(corrupt_state(format!(
            "provider {provider_id} bonded-plus-slashed credit commitment exceeds native reserve custody"
        )));
    }
    let remaining_owner_funded = remaining_reserve.checked_sub(debt_principal).map_err(
        |error| {
            invalid_parameter(format!(
                "provider {provider_id} withdrawal would consume treasury-funded principal: {error}"
            ))
        },
    )?;
    let next_bonded = remaining_owner_funded.checked_sub(&slashed).map_err(|_| {
        invalid_parameter(format!(
            "provider {provider_id} withdrawal would release custody subject to a slash lien"
        ))
    })?;
    if next_bonded.as_quantity() < &credit.required_bond {
        return Err(invalid_parameter(format!(
            "provider {provider_id} withdrawal would reduce unslashed bond {} below required {}",
            next_bonded.as_quantity(),
            credit.required_bond
        )));
    }
    if let Some(record) = world.capacity_declarations().get(&provider_id) {
        let declaration = super::sorafs::decode_capacity_declaration_payload(&record.declaration)
            .map_err(|error| {
            corrupt_state(format!(
                "provider {provider_id} capacity declaration payload is invalid: {error}"
            ))
        })?;
        let declared_stake = declaration.stake.stake_amount.as_quantity();
        if next_bonded.as_quantity() < declared_stake {
            return Err(invalid_parameter(format!(
                "provider {provider_id} withdrawal would reduce unslashed bond {} below declared stake {declared_stake}",
                next_bonded.as_quantity(),
            )));
        }
    }
    credit.bonded = next_bonded.into_quantity();
    Ok(Some(credit))
}
#[cfg(test)]
pub(super) fn seed_verified_provider_bond_for_test(
    state_transaction: &mut StateTransaction<'_, '_>,
    provider_id: ProviderId,
    owner: &AccountId,
    capacity_gib: u64,
    bonded: iroha_primitives::numeric::Quantity,
) -> Result<(), InstructionExecutionError> {
    use iroha_data_model::{IntoKeyValue, account::Account, asset::Asset};
    let policy = if let Some(policy) = read_policy(state_transaction.world())? {
        policy
    } else {
        let custody_account = AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha:sorafs:test-reserve-custody:v1",
            &[],
        ));
        if state_transaction
            .world
            .accounts()
            .get(&custody_account)
            .is_none()
        {
            let account = Account::new(custody_account.clone()).build(&custody_account);
            let (account_id, account) = account.into_key_value();
            state_transaction.world.accounts.insert(account_id, account);
        }
        let treasury_account = owner.clone();
        let policy = ReserveAuthorityPolicyV1 {
            version: iroha_data_model::sorafs::reserve::RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: iroha_data_model::sorafs::reserve::ReservePolicyV1::default(),
            asset_definition: state_transaction.gov.sorafs_pin_fee_asset_id.clone(),
            custody_account,
            treasury_account,
            operations_authority: owner.clone(),
            decision_authority: owner.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000)
                .expect("bounded test reserve debt"),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        };
        let policy_digest = policy.digest().map_err(|error| {
            corrupt_state(format!("test reserve policy digest failed: {error}"))
        })?;
        let record = ReserveAuthorityPolicyRecordV1 {
            policy,
            policy_digest,
            activated_by: owner.clone(),
            activated_at_unix: 1,
        };
        emit_reserve_policy_activation(state_transaction, record.clone(), owner, 1)?;
        record
    };
    if policy.policy.custody_account == *owner {
        return Err(corrupt_state(
            "test reserve provider owner must differ from protocol custody",
        ));
    }
    let reserve_balance = XorQuantity::try_from_quantity(bonded)
        .map_err(|error| corrupt_state(format!("test reserve bond is invalid: {error}")))?;
    let account = ReserveProviderAccountV1 {
        terms: iroha_data_model::sorafs::reserve::ReserveProviderTermsV1 {
            provider_id,
            provider_account: owner.clone(),
            tier: ReserveTier::TierA,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
            duration: iroha_data_model::sorafs::reserve::ReserveDuration::Monthly,
            capacity_gib,
        },
        policy_digest: policy.policy_digest,
        revision: 1,
        reserve_balance: reserve_balance.clone(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::zero(),
        lifecycle_stage: ReserveLifecycleStage::Active,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    };
    state_transaction.world.smart_contract_state.insert(
        reserve_provider_key(provider_id),
        encode_state(&account, "test reserve provider account")?,
    );
    let custody_asset_id = AssetId::of(
        policy.policy.asset_definition,
        policy.policy.custody_account,
    );
    let current = state_transaction
        .world
        .assets
        .get(&custody_asset_id)
        .map_or_else(iroha_primitives::numeric::Quantity::zero, |value| {
            value.as_ref().clone()
        });
    let next = current
        .checked_add(reserve_balance.as_quantity())
        .map_err(|error| corrupt_state(format!("test reserve custody overflow: {error}")))?;
    let (asset_id, asset) = Asset::new(custody_asset_id, next).into_key_value();
    state_transaction.world.assets.insert(asset_id, asset);
    Ok(())
}
fn decode_provider_record(
    bytes: &[u8],
    provider_id: ProviderId,
) -> Result<ReserveProviderAccountV1, InstructionExecutionError> {
    let account: ReserveProviderAccountV1 = decode_state(bytes, "reserve provider account")?;
    validate_provider_record(account, provider_id)
}
fn validate_provider_record(
    account: ReserveProviderAccountV1,
    provider_id: ProviderId,
) -> Result<ReserveProviderAccountV1, InstructionExecutionError> {
    // Preserve this layer's error type and charged decode owner. The model owns only
    // the exact existing structural predicate; no additional decoding occurs here.
    iroha_data_model::sorafs::reserve::history::validate_provider_record(&account, provider_id)
        .map_err(|_| corrupt_state("stored reserve provider account is inconsistent"))?;
    Ok(account)
}

fn ensure_apr_rotation_has_no_debt(
    world: &impl WorldReadOnly,
    current: &ReserveAuthorityPolicyV1,
    next: &ReserveAuthorityPolicyV1,
) -> Result<(), InstructionExecutionError> {
    let apr_changed = [ReserveTier::TierA, ReserveTier::TierB, ReserveTier::TierC]
        .into_iter()
        .try_fold(false, |changed, tier| {
            let current_apr = current
                .economics
                .tier_configuration(tier)
                .map_err(|error| corrupt_state(format!("invalid active reserve tier: {error}")))?
                .interest_apr_bps;
            let next_apr = next
                .economics
                .tier_configuration(tier)
                .map_err(|error| invalid_parameter(format!("invalid next reserve tier: {error}")))?
                .interest_apr_bps;
            Ok::<_, InstructionExecutionError>(changed || current_apr != next_apr)
        })?;
    if !apr_changed {
        return Ok(());
    }
    let start = StatePath::from_str(RESERVE_PROVIDER_STATE_KEY_PREFIX_V1)
        .expect("static provider prefix is valid");
    for (key, payload) in world.smart_contract_state().range(start..) {
        if !key
            .to_string()
            .starts_with(RESERVE_PROVIDER_STATE_KEY_PREFIX_V1)
        {
            break;
        }
        let candidate: ReserveProviderAccountV1 =
            decode_state(payload, "reserve provider account")?;
        if reserve_provider_key(candidate.terms.provider_id) != *key {
            return Err(corrupt_state(
                "authoritative reserve provider key does not match its account",
            ));
        }
        let account = read_provider(world, candidate.terms.provider_id)?.ok_or_else(|| {
            corrupt_state("authoritative reserve provider disappeared during policy validation")
        })?;
        if !account
            .total_debt()
            .map_err(|error| corrupt_state(format!("invalid provider debt: {error}")))?
            .is_zero()
        {
            return Err(invalid_parameter(
                "reserve APR changes require all provider debt and accrued interest to be settled",
            ));
        }
    }
    Ok(())
}
fn provider_for_policy(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<ReserveProviderAccountV1, InstructionExecutionError> {
    let mut account = read_provider(world, provider_id)?
        .ok_or_else(|| invalid_parameter(format!("reserve account for {provider_id} not found")))?;
    let governed_cap = credit_cap(&policy.policy, &account.terms)?;
    account.credit_cap = if account.debt_principal > governed_cap {
        account.debt_principal.clone()
    } else {
        governed_cap
    };
    if account.policy_digest != policy.policy_digest {
        account.policy_digest = policy.policy_digest;
    }
    Ok(account)
}
fn ensure_revision(
    account: &ReserveProviderAccountV1,
    expected: u64,
) -> Result<(), InstructionExecutionError> {
    if account.revision == expected {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "reserve provider revision conflict: expected {expected}, current {}",
            account.revision
        )))
    }
}
fn ensure_provider_timestamp(
    account: &ReserveProviderAccountV1,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    if now >= account.updated_at_unix {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "reserve block timestamp {now} predates provider update {}",
            account.updated_at_unix
        )))
    }
}
fn advance_provider_revision(
    account: &mut ReserveProviderAccountV1,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    ensure_provider_timestamp(account, now)?;
    if account.rent_charged_through_unix > now || account.interest_accrued_at_unix > now {
        return Err(corrupt_state(
            "reserve provider anchors cannot exceed the next update timestamp",
        ));
    }
    let next_revision = account
        .revision
        .checked_add(1)
        .ok_or_else(|| corrupt_state("reserve provider revision overflow"))?;
    account.revision = next_revision;
    account.updated_at_unix = now;
    Ok(())
}
fn accrue_interest(
    account: &mut ReserveProviderAccountV1,
    policy: &ReserveAuthorityPolicyV1,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    let tier = policy
        .economics
        .tier_configuration(account.terms.tier)
        .map_err(|error| corrupt_state(format!("invalid active reserve tier: {error}")))?;
    account
        .accrue_interest(tier.interest_apr_bps, now)
        .map_err(|error| invalid_parameter(format!("reserve interest accrual failed: {error}")))?;
    Ok(())
}
fn read_movement(
    world: &impl WorldReadOnly,
    movement_id: [u8; 32],
) -> Result<Option<ReserveMovementRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&movement_key(movement_id)) else {
        return Ok(None);
    };
    decode_movement_record(bytes, movement_id).map(Some)
}
fn decode_movement_record(
    bytes: &[u8],
    movement_id: [u8; 32],
) -> Result<ReserveMovementRecordV1, InstructionExecutionError> {
    let record: ReserveMovementRecordV1 = decode_state(bytes, "reserve movement")?;
    validate_movement_record(record, movement_id)
}
fn validate_movement_record(
    record: ReserveMovementRecordV1,
    movement_id: [u8; 32],
) -> Result<ReserveMovementRecordV1, InstructionExecutionError> {
    let terminal_fields = record.decided_by.is_some()
        && record.decided_at_unix.is_some()
        && record.rationale.is_some();
    if record.movement_id != movement_id
        || record.movement_id == [0; 32]
        || record.amount.is_zero()
        || record.expected_provider_revision == 0
        || record.policy_digest == [0; 32]
        || record.requested_at_unix == 0
        || match record.status {
            ReserveMovementStatusV1::Pending => {
                record.decided_by.is_some()
                    || record.decided_at_unix.is_some()
                    || record.rationale.is_some()
            }
            ReserveMovementStatusV1::Approved | ReserveMovementStatusV1::Rejected => {
                !terminal_fields
            }
        }
    {
        return Err(corrupt_state("stored reserve movement is inconsistent"));
    }
    Ok(record)
}
fn read_appeal(
    world: &impl WorldReadOnly,
    appeal_id: [u8; 32],
) -> Result<Option<ReserveAppealRecordV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(&appeal_key(appeal_id)) else {
        return Ok(None);
    };
    decode_appeal_record(bytes, appeal_id).map(Some)
}
fn decode_appeal_record(
    bytes: &[u8],
    appeal_id: [u8; 32],
) -> Result<ReserveAppealRecordV1, InstructionExecutionError> {
    let record: ReserveAppealRecordV1 = decode_state(bytes, "reserve appeal")?;
    validate_appeal_record(record, appeal_id)
}
fn validate_appeal_record(
    record: ReserveAppealRecordV1,
    appeal_id: [u8; 32],
) -> Result<ReserveAppealRecordV1, InstructionExecutionError> {
    let terminal_fields = record.decided_by.is_some()
        && record.decided_at_unix.is_some()
        && record.rationale.is_some();
    if record.appeal_id != appeal_id
        || record.appeal_id == [0; 32]
        || record.reason.is_empty()
        || record.reason.len() > RESERVE_MAX_REASON_BYTES_V1
        || record.expected_provider_revision == 0
        || record.submitted_at_unix == 0
        || match record.status {
            ReserveAppealStatusV1::Pending => {
                record.decided_by.is_some()
                    || record.decided_at_unix.is_some()
                    || record.rationale.is_some()
            }
            ReserveAppealStatusV1::Accepted | ReserveAppealStatusV1::Rejected => !terminal_fields,
        }
    {
        return Err(corrupt_state("stored reserve appeal is inconsistent"));
    }
    Ok(record)
}
fn transfer(
    state_transaction: &mut StateTransaction<'_, '_>,
    policy: &ReserveAuthorityPolicyV1,
    source: &AccountId,
    destination: &AccountId,
    amount: &XorQuantity,
) -> Result<(), InstructionExecutionError> {
    super::asset::isi::execute_user_numeric_asset_transfer(
        state_transaction,
        source,
        AssetId::of(policy.asset_definition.clone(), source.clone()),
        destination.clone(),
        amount.clone().into_quantity(),
    )
    .map_err(|error| invalid_parameter(format!("reserve custody transfer failed: {error}")))
}
fn provider_spendable_balance(
    world: &impl WorldReadOnly,
    policy: &ReserveAuthorityPolicyV1,
    provider: &AccountId,
) -> Result<XorQuantity, InstructionExecutionError> {
    let asset_id = AssetId::of(policy.asset_definition.clone(), provider.clone());
    world.assets().get(&asset_id).map_or_else(
        || Ok(XorQuantity::zero()),
        |value| {
            XorQuantity::try_from_quantity(value.as_ref().clone()).map_err(|error| {
                corrupt_state(format!(
                    "stored reserve provider spendable balance is invalid: {error}"
                ))
            })
        },
    )
}
impl Execute for SetSorafsReservePolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_governance(state_transaction, authority)?;
        self.policy
            .validate()
            .map_err(|error| invalid_parameter(format!("invalid reserve policy: {error}")))?;
        state_transaction
            .world
            .account(&self.policy.custody_account)?;
        state_transaction
            .world
            .account(&self.policy.treasury_account)?;
        state_transaction
            .world
            .asset_definition(&self.policy.asset_definition)?;
        let now = now_unix(state_transaction)?;
        let digest = self.policy.digest().map_err(|error| {
            invalid_parameter(format!("failed to digest reserve policy: {error}"))
        })?;
        match read_policy(state_transaction.world())? {
            None => {
                if self.policy.revision != 1 || self.policy.predecessor_policy_digest.is_some() {
                    return Err(invalid_parameter(
                        "first reserve policy must be revision one without a predecessor",
                    ));
                }
            }
            Some(current) => {
                if now < current.activated_at_unix {
                    return Err(invalid_parameter(format!(
                        "reserve policy activation timestamp {now} predates active policy activation {}",
                        current.activated_at_unix
                    )));
                }
                let expected = current
                    .policy
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("reserve policy revision overflow"))?;
                if self.policy.revision != expected
                    || self.policy.predecessor_policy_digest != Some(current.policy_digest)
                {
                    return Err(invalid_parameter(
                        "reserve policy must exactly extend the active revision and digest",
                    ));
                }
                ensure_apr_rotation_has_no_debt(
                    state_transaction.world(),
                    &current.policy,
                    &self.policy,
                )?;
                if self.policy.asset_definition != current.policy.asset_definition
                    || self.policy.custody_account != current.policy.custody_account
                    || self.policy.treasury_account != current.policy.treasury_account
                {
                    return Err(invalid_parameter(
                        "reserve asset and custody accounts are immutable after activation",
                    ));
                }
            }
        }
        let record = ReserveAuthorityPolicyRecordV1 {
            policy: self.policy,
            policy_digest: digest,
            activated_by: authority.clone(),
            activated_at_unix: now,
        };
        emit_reserve_policy_activation(state_transaction, record, authority, now)?;
        Ok(())
    }
}
impl Execute for RegisterSorafsReserveAccount {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_operations_authority(authority, &policy)?;
        if self.terms.capacity_gib == 0 {
            return Err(invalid_parameter(
                "reserve account capacity must be non-zero",
            ));
        }
        if self.terms.provider_account == policy.policy.custody_account {
            return Err(invalid_parameter(
                "reserve provider account must differ from protocol custody",
            ));
        }
        let owner = registered_provider_owner(state_transaction.world(), self.terms.provider_id)?;
        if owner.subject_id() != self.terms.provider_account.subject_id() {
            return Err(invalid_parameter(
                "reserve account provider does not match the registry owner",
            ));
        }
        if read_provider(state_transaction.world(), self.terms.provider_id)?.is_some() {
            return Err(invalid_parameter(
                "reserve provider account is already registered",
            ));
        }
        let account = ReserveProviderAccountV1 {
            credit_cap: credit_cap(&policy.policy, &self.terms)?,
            terms: self.terms,
            policy_digest: policy.policy_digest,
            revision: 1,
            reserve_balance: XorQuantity::zero(),
            debt_principal: XorQuantity::zero(),
            accrued_interest: XorQuantity::zero(),
            lifecycle_stage: ReserveLifecycleStage::Warning,
            days_past_due: 0,
            pending_movements: 0,
            open_appeals: 0,
            rent_charged_through_unix: now,
            interest_accrued_at_unix: now,
            updated_at_unix: now,
        };
        let encoded = encode_state(&account, "reserve provider account")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(account.terms.provider_id), encoded);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::ProviderRegistered,
            account.terms.provider_id,
            None,
            account.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for RequestSorafsReserveMovement {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        if self.movement_id == [0; 32] || self.amount.is_zero() {
            return Err(invalid_parameter(
                "reserve movement id and amount must be non-zero",
            ));
        }
        if read_movement(state_transaction.world(), self.movement_id)?.is_some() {
            return Err(invalid_parameter("reserve movement id is already recorded"));
        }
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        if account.terms.provider_account.subject_id() != authority.subject_id() {
            return Err(invalid_parameter(
                "reserve movement authority is not the provider account",
            ));
        }
        ensure_revision(&account, self.expected_provider_revision)?;
        if account.pending_movements >= policy.policy.max_pending_movements_per_provider {
            return Err(invalid_parameter(
                "reserve provider reached the pending-movement ceiling",
            ));
        }
        account.pending_movements = account
            .pending_movements
            .checked_add(1)
            .ok_or_else(|| corrupt_state("reserve pending-movement counter overflow"))?;
        advance_provider_revision(&mut account, now)?;
        let record = ReserveMovementRecordV1 {
            movement_id: self.movement_id,
            provider_id: self.provider_id,
            kind: self.kind,
            amount: self.amount,
            requested_by: authority.clone(),
            expected_provider_revision: self.expected_provider_revision,
            policy_digest: policy.policy_digest,
            status: ReserveMovementStatusV1::Pending,
            requested_at_unix: now,
            decided_by: None,
            decided_at_unix: None,
            rationale: None,
        };
        let encoded_account = encode_state(&account, "reserve provider account")?;
        let encoded_record = encode_state(&record, "reserve movement")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded_account);
        state_transaction
            .world
            .smart_contract_state
            .insert(movement_key(self.movement_id), encoded_record);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::MovementRequested,
            self.provider_id,
            Some(self.movement_id),
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for DecideSorafsReserveMovement {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.rationale.is_empty() || self.rationale.len() > RESERVE_MAX_REASON_BYTES_V1 {
            return Err(invalid_parameter(
                "reserve movement rationale is empty or oversized",
            ));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_decision_authority(authority, &policy)?;
        let mut movement = read_movement(state_transaction.world(), self.movement_id)?
            .ok_or_else(|| invalid_parameter("reserve movement not found"))?;
        if movement.status != ReserveMovementStatusV1::Pending {
            return Err(invalid_parameter("reserve movement is already decided"));
        }
        let mut account =
            provider_for_policy(state_transaction.world(), movement.provider_id, &policy)?;
        ensure_revision(&account, self.expected_provider_revision)?;
        accrue_interest(&mut account, &policy.policy, now)?;
        account.pending_movements = account
            .pending_movements
            .checked_sub(1)
            .ok_or_else(|| corrupt_state("reserve pending-movement counter underflow"))?;
        let mut updated_credit = None;
        if self.approve {
            match movement.kind {
                ReserveMovementKindV1::TopUp => {
                    account.reserve_balance = account
                        .reserve_balance
                        .checked_add(&movement.amount)
                        .map_err(|error| {
                            invalid_parameter(format!("reserve balance overflow: {error}"))
                        })?;
                }
                ReserveMovementKindV1::Withdrawal => {
                    if !account
                        .total_debt()
                        .map_err(|error| {
                            invalid_parameter(format!("invalid provider debt: {error}"))
                        })?
                        .is_zero()
                    {
                        return Err(invalid_parameter(
                            "reserve withdrawal is forbidden while provider debt is outstanding",
                        ));
                    }
                    let remaining = account
                        .reserve_balance
                        .checked_sub(&movement.amount)
                        .map_err(|_| {
                            invalid_parameter("reserve withdrawal exceeds provider partition")
                        })?;
                    let quote = policy
                        .policy
                        .economics
                        .quote(
                            account.terms.storage_class,
                            account.terms.capacity_gib,
                            account.terms.duration,
                            account.terms.tier,
                            remaining.clone(),
                        )
                        .map_err(|error| {
                            invalid_parameter(format!("reserve withdrawal quote failed: {error}"))
                        })?;
                    if !quote
                        .ledger_projection()
                        .map_err(|error| {
                            invalid_parameter(format!(
                                "reserve withdrawal projection failed: {error}"
                            ))
                        })?
                        .meets_underwriting
                    {
                        return Err(invalid_parameter(
                            "reserve withdrawal would breach underwriting",
                        ));
                    }
                    updated_credit = credit_after_verified_reserve_withdrawal(
                        state_transaction.world(),
                        movement.provider_id,
                        &account.reserve_balance,
                        &remaining,
                        &account.debt_principal,
                    )?;
                    account.reserve_balance = remaining;
                }
            }
        }
        advance_provider_revision(&mut account, now)?;
        movement.status = if self.approve {
            ReserveMovementStatusV1::Approved
        } else {
            ReserveMovementStatusV1::Rejected
        };
        movement.decided_by = Some(authority.clone());
        movement.decided_at_unix = Some(now);
        movement.rationale = Some(self.rationale);
        let encoded_account = encode_state(&account, "reserve provider account")?;
        let encoded_movement = encode_state(&movement, "reserve movement")?;
        if self.approve {
            match movement.kind {
                ReserveMovementKindV1::TopUp => transfer(
                    state_transaction,
                    &policy.policy,
                    &account.terms.provider_account,
                    &policy.policy.custody_account,
                    &movement.amount,
                )?,
                ReserveMovementKindV1::Withdrawal => {
                    let source_id = AssetId::of(
                        policy.policy.asset_definition.clone(),
                        policy.policy.custody_account.clone(),
                    );
                    let destination_id = AssetId::of(
                        policy.policy.asset_definition.clone(),
                        account.terms.provider_account.clone(),
                    );
                    let authorization = VerifiedSorafsReserveWithdrawal::new(
                        movement.provider_id,
                        movement.movement_id,
                        policy.policy_digest,
                        self.expected_provider_revision,
                        authority.clone(),
                        source_id,
                        destination_id,
                        movement.amount.clone().into_quantity(),
                    );
                    super::asset::isi::execute_verified_sorafs_reserve_withdrawal(
                        state_transaction,
                        authorization,
                    )?;
                }
            }
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(movement.provider_id), encoded_account);
        state_transaction
            .world
            .smart_contract_state
            .insert(movement_key(movement.movement_id), encoded_movement);
        if let Some(credit) = updated_credit {
            state_transaction
                .world
                .provider_credit_ledger
                .insert(movement.provider_id, credit);
        }
        emit_reserve_event(
            state_transaction,
            if movement.status == ReserveMovementStatusV1::Approved {
                SorafsReserveLedgerEventKind::MovementApproved
            } else {
                SorafsReserveLedgerEventKind::MovementRejected
            },
            movement.provider_id,
            Some(movement.movement_id),
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for ChargeSorafsReserveRent {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if !(1..=RESERVE_RENT_MAX_BILLING_PERIODS_V1).contains(&self.billing_periods) {
            return Err(invalid_parameter(
                "reserve rent billing periods exceed the native V1 bound",
            ));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_operations_authority(authority, &policy)?;
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        ensure_revision(&account, self.expected_provider_revision)?;
        ensure_provider_timestamp(&account, now)?;
        let due_periods = account.rent_periods_due_at(now).map_err(|error| {
            invalid_parameter(format!("reserve rent anchor is invalid: {error}"))
        })?;
        if u64::from(self.billing_periods) > due_periods {
            return Err(invalid_parameter(format!(
                "reserve rent charge requests {} periods but only {due_periods} are due",
                self.billing_periods
            )));
        }
        let anchor_advance = RESERVE_RENT_BILLING_PERIOD_SECONDS_V1
            .checked_mul(u64::from(self.billing_periods))
            .ok_or_else(|| corrupt_state("reserve rent anchor multiplication overflow"))?;
        let next_rent_anchor = account
            .rent_charged_through_unix
            .checked_add(anchor_advance)
            .ok_or_else(|| corrupt_state("reserve rent anchor overflow"))?;
        if next_rent_anchor > now {
            return Err(corrupt_state(
                "reserve rent charge would advance beyond the current block",
            ));
        }
        accrue_interest(&mut account, &policy.policy, now)?;
        let quote = policy
            .policy
            .economics
            .quote(
                account.terms.storage_class,
                account.terms.capacity_gib,
                account.terms.duration,
                account.terms.tier,
                account.reserve_balance.clone(),
            )
            .map_err(|error| invalid_parameter(format!("reserve rent quote failed: {error}")))?;
        let rent = quote
            .effective_rent
            .checked_mul_u64(u64::from(self.billing_periods))
            .map_err(|error| invalid_parameter(format!("reserve rent overflow: {error}")))?;
        account.days_past_due = 0;
        account.lifecycle_stage = if quote
            .ledger_projection()
            .map_err(|error| invalid_parameter(format!("reserve projection failed: {error}")))?
            .needs_top_up_alert
        {
            ReserveLifecycleStage::Warning
        } else {
            ReserveLifecycleStage::Active
        };
        account.rent_charged_through_unix = next_rent_anchor;
        advance_provider_revision(&mut account, now)?;
        let encoded = encode_state(&account, "reserve provider account")?;
        if !rent.is_zero() {
            transfer(
                state_transaction,
                &policy.policy,
                &account.terms.provider_account,
                &policy.policy.treasury_account,
                &rent,
            )?;
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::RentCharged,
            self.provider_id,
            None,
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for AdvanceSorafsReserveLifecycle {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_operations_authority(authority, &policy)?;
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        ensure_revision(&account, self.expected_provider_revision)?;
        ensure_provider_timestamp(&account, now)?;
        let derived_days_past_due = account.rent_days_past_due_at(now).map_err(|error| {
            invalid_parameter(format!("reserve lifecycle rent anchor is invalid: {error}"))
        })?;
        if self.days_past_due != derived_days_past_due {
            return Err(invalid_parameter(format!(
                "reserve lifecycle days must equal authoritative rent aging: supplied {}, expected {derived_days_past_due}",
                self.days_past_due
            )));
        }
        let quote = policy
            .policy
            .economics
            .quote(
                account.terms.storage_class,
                account.terms.capacity_gib,
                account.terms.duration,
                account.terms.tier,
                account.reserve_balance.clone(),
            )
            .map_err(|error| {
                invalid_parameter(format!("reserve lifecycle quote failed: {error}"))
            })?;
        let periods_due = account.rent_periods_due_at(now).map_err(|error| {
            invalid_parameter(format!("reserve lifecycle rent anchor is invalid: {error}"))
        })?;
        if periods_due != 0 {
            let spendable_balance = provider_spendable_balance(
                state_transaction.world(),
                &policy.policy,
                &account.terms.provider_account,
            )?;
            if quote.effective_rent.is_zero() || spendable_balance >= quote.effective_rent {
                return Err(invalid_parameter(
                    "reserve lifecycle cannot age while one whole rent period is affordable",
                ));
            }
        }
        let projection = quote
            .lifecycle_projection(
                self.days_past_due,
                policy.policy.grace_period_days,
                policy.policy.default_after_days,
            )
            .map_err(|error| {
                invalid_parameter(format!("reserve lifecycle projection failed: {error}"))
            })?;
        if account.lifecycle_stage == projection.stage
            && account.days_past_due == derived_days_past_due
        {
            return Err(invalid_parameter(
                "reserve lifecycle transition would not change authoritative state",
            ));
        }
        accrue_interest(&mut account, &policy.policy, now)?;
        account.lifecycle_stage = projection.stage;
        account.days_past_due = derived_days_past_due;
        advance_provider_revision(&mut account, now)?;
        let encoded = encode_state(&account, "reserve provider account")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::LifecycleAdvanced,
            self.provider_id,
            None,
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for DrawSorafsReserveCredit {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.amount.is_zero() {
            return Err(invalid_parameter("reserve credit draw must be non-zero"));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_operations_authority(authority, &policy)?;
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        ensure_revision(&account, self.expected_provider_revision)?;
        accrue_interest(&mut account, &policy.policy, now)?;
        if self.amount
            > account
                .available_credit()
                .map_err(|error| invalid_parameter(format!("invalid provider credit: {error}")))?
        {
            return Err(invalid_parameter(
                "reserve credit draw exceeds the provider credit cap",
            ));
        }
        account.debt_principal = account
            .debt_principal
            .checked_add(&self.amount)
            .map_err(|error| invalid_parameter(format!("reserve debt overflow: {error}")))?;
        account.reserve_balance = account
            .reserve_balance
            .checked_add(&self.amount)
            .map_err(|error| invalid_parameter(format!("reserve balance overflow: {error}")))?;
        advance_provider_revision(&mut account, now)?;
        let encoded = encode_state(&account, "reserve provider account")?;
        transfer(
            state_transaction,
            &policy.policy,
            &policy.policy.treasury_account,
            &policy.policy.custody_account,
            &self.amount,
        )?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::CreditDrawn,
            self.provider_id,
            None,
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for RepaySorafsReserveCredit {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.amount.is_zero() {
            return Err(invalid_parameter(
                "reserve credit repayment must be non-zero",
            ));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        if account.terms.provider_account.subject_id() != authority.subject_id() {
            return Err(invalid_parameter(
                "reserve credit repayment authority is not the provider account",
            ));
        }
        ensure_revision(&account, self.expected_provider_revision)?;
        accrue_interest(&mut account, &policy.policy, now)?;
        let total_debt = account
            .total_debt()
            .map_err(|error| invalid_parameter(format!("invalid reserve debt: {error}")))?;
        if self.amount > total_debt {
            return Err(invalid_parameter(
                "reserve credit repayment exceeds total debt",
            ));
        }
        let interest_payment = XorQuantity::min(&self.amount, &account.accrued_interest);
        account.accrued_interest = account
            .accrued_interest
            .checked_sub(&interest_payment)
            .map_err(|error| corrupt_state(format!("reserve interest underflow: {error}")))?;
        let principal_payment = self
            .amount
            .checked_sub(&interest_payment)
            .map_err(|error| corrupt_state(format!("reserve repayment underflow: {error}")))?;
        account.debt_principal = account
            .debt_principal
            .checked_sub(&principal_payment)
            .map_err(|error| corrupt_state(format!("reserve principal underflow: {error}")))?;
        let governed_cap = credit_cap(&policy.policy, &account.terms)?;
        account.credit_cap = if account.debt_principal > governed_cap {
            account.debt_principal.clone()
        } else {
            governed_cap
        };
        advance_provider_revision(&mut account, now)?;
        let encoded = encode_state(&account, "reserve provider account")?;
        transfer(
            state_transaction,
            &policy.policy,
            &account.terms.provider_account,
            &policy.policy.treasury_account,
            &self.amount,
        )?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::CreditRepaid,
            self.provider_id,
            None,
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for SubmitSorafsReserveAppeal {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        if self.appeal_id == [0; 32]
            || self.reason.is_empty()
            || self.reason.len() > RESERVE_MAX_REASON_BYTES_V1
            || self.evidence_digest == Some([0; 32])
        {
            return Err(invalid_parameter(
                "reserve appeal id, reason, or evidence digest is invalid",
            ));
        }
        if read_appeal(state_transaction.world(), self.appeal_id)?.is_some() {
            return Err(invalid_parameter("reserve appeal id is already recorded"));
        }
        let mut account =
            provider_for_policy(state_transaction.world(), self.provider_id, &policy)?;
        if account.terms.provider_account.subject_id() != authority.subject_id() {
            return Err(invalid_parameter(
                "reserve appeal authority is not the provider account",
            ));
        }
        ensure_revision(&account, self.expected_provider_revision)?;
        if account.open_appeals >= policy.policy.max_open_appeals_per_provider {
            return Err(invalid_parameter(
                "reserve provider reached the open-appeal ceiling",
            ));
        }
        account.open_appeals = account
            .open_appeals
            .checked_add(1)
            .ok_or_else(|| corrupt_state("reserve open-appeal counter overflow"))?;
        advance_provider_revision(&mut account, now)?;
        let appeal = ReserveAppealRecordV1 {
            appeal_id: self.appeal_id,
            provider_id: self.provider_id,
            submitted_by: authority.clone(),
            requested_stage: self.requested_stage,
            reason: self.reason,
            evidence_digest: self.evidence_digest,
            expected_provider_revision: self.expected_provider_revision,
            status: ReserveAppealStatusV1::Pending,
            submitted_at_unix: now,
            decided_by: None,
            decided_at_unix: None,
            rationale: None,
        };
        let encoded_account = encode_state(&account, "reserve provider account")?;
        let encoded_appeal = encode_state(&appeal, "reserve appeal")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(self.provider_id), encoded_account);
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(self.appeal_id), encoded_appeal);
        emit_reserve_event(
            state_transaction,
            SorafsReserveLedgerEventKind::AppealSubmitted,
            self.provider_id,
            Some(self.appeal_id),
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for DecideSorafsReserveAppeal {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if self.rationale.is_empty() || self.rationale.len() > RESERVE_MAX_REASON_BYTES_V1 {
            return Err(invalid_parameter(
                "reserve appeal rationale is empty or oversized",
            ));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_decision_authority(authority, &policy)?;
        let mut appeal = read_appeal(state_transaction.world(), self.appeal_id)?
            .ok_or_else(|| invalid_parameter("reserve appeal not found"))?;
        if appeal.status != ReserveAppealStatusV1::Pending {
            return Err(invalid_parameter("reserve appeal is already decided"));
        }
        let mut account =
            provider_for_policy(state_transaction.world(), appeal.provider_id, &policy)?;
        ensure_revision(&account, self.expected_provider_revision)?;
        account.open_appeals = account
            .open_appeals
            .checked_sub(1)
            .ok_or_else(|| corrupt_state("reserve open-appeal counter underflow"))?;
        if self.accept {
            account.lifecycle_stage = appeal.requested_stage;
        }
        advance_provider_revision(&mut account, now)?;
        appeal.status = if self.accept {
            ReserveAppealStatusV1::Accepted
        } else {
            ReserveAppealStatusV1::Rejected
        };
        appeal.decided_by = Some(authority.clone());
        appeal.decided_at_unix = Some(now);
        appeal.rationale = Some(self.rationale);
        let encoded_account = encode_state(&account, "reserve provider account")?;
        let encoded_appeal = encode_state(&appeal, "reserve appeal")?;
        state_transaction
            .world
            .smart_contract_state
            .insert(reserve_provider_key(appeal.provider_id), encoded_account);
        state_transaction
            .world
            .smart_contract_state
            .insert(appeal_key(appeal.appeal_id), encoded_appeal);
        emit_reserve_event(
            state_transaction,
            if appeal.status == ReserveAppealStatusV1::Accepted {
                SorafsReserveLedgerEventKind::AppealAccepted
            } else {
                SorafsReserveLedgerEventKind::AppealRejected
            },
            appeal.provider_id,
            Some(appeal.appeal_id),
            policy.policy_digest,
            account.revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
const RESERVE_QUERY_MAX_EVENT_READ_BYTES_V1: usize = RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1 * 4;
const RESERVE_QUERY_MAX_EVENT_STORAGE_PROBES_V1: u32 = RESERVE_QUERY_MAX_ITEMS_V1 * 2 + 24;
const RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1: usize = 1_024;
const RESERVE_QUERY_MAX_EVENT_TOTAL_KEY_BYTES_V1: usize = 128 * 1_024;
const RESERVE_QUERY_MAX_RECORD_BYTES_V1: usize = 64 * 1_024;
#[derive(Debug, Default)]
struct ReserveEventQueryBudgetV1 {
    storage_probes: u32,
    key_bytes: usize,
    read_bytes: usize,
}
impl ReserveEventQueryBudgetV1 {
    fn inspect_storage_probe(
        &mut self,
        probe_key_bytes: usize,
        returned_key_bytes: Option<usize>,
        encoded_value_bytes: usize,
    ) -> Result<(), QueryExecutionFail> {
        if probe_key_bytes > RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1
            || returned_key_bytes
                .is_some_and(|bytes| bytes > RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1)
        {
            return Err(QueryExecutionFail::Conversion(format!(
                "reserve committed-event query probe key exceeds {RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1} bytes"
            )));
        }
        self.storage_probes = self.storage_probes.checked_add(1).ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve committed-event query storage-probe counter overflow".to_owned(),
            )
        })?;
        self.key_bytes = self
            .key_bytes
            .checked_add(probe_key_bytes)
            .and_then(|bytes| bytes.checked_add(returned_key_bytes.unwrap_or(0)))
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reserve committed-event query key-byte counter overflow".to_owned(),
                )
            })?;
        self.read_bytes = self
            .read_bytes
            .checked_add(encoded_value_bytes)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reserve committed-event query read-byte counter overflow".to_owned(),
                )
            })?;
        if self.storage_probes > RESERVE_QUERY_MAX_EVENT_STORAGE_PROBES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "reserve committed-event query exceeds {RESERVE_QUERY_MAX_EVENT_STORAGE_PROBES_V1} storage probes"
            )));
        }
        if self.key_bytes > RESERVE_QUERY_MAX_EVENT_TOTAL_KEY_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "reserve committed-event query exceeds {RESERVE_QUERY_MAX_EVENT_TOTAL_KEY_BYTES_V1} probed key bytes"
            )));
        }
        if self.read_bytes > RESERVE_QUERY_MAX_EVENT_READ_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "reserve committed-event query exceeds {RESERVE_QUERY_MAX_EVENT_READ_BYTES_V1} encoded read bytes"
            )));
        }
        Ok(())
    }
    fn inspect_direct_read(
        &mut self,
        key: &StatePath,
        encoded_value_bytes: usize,
    ) -> Result<(), QueryExecutionFail> {
        self.inspect_storage_probe(key.as_ref().len(), None, encoded_value_bytes)
    }
    fn inspect_finalized_hash_read(
        &mut self,
        encoded_value_bytes: usize,
    ) -> Result<(), QueryExecutionFail> {
        self.inspect_storage_probe(core::mem::size_of::<u64>(), None, encoded_value_bytes)
    }
    fn inspect_finalized_hash_metadata(&mut self) -> Result<(), QueryExecutionFail> {
        self.inspect_storage_probe(
            "finalized_block_hashes".len(),
            None,
            core::mem::size_of::<u64>(),
        )
    }
    fn inspect_range_read(
        &mut self,
        probe_key: &StatePath,
        result: Option<(&StatePath, usize)>,
    ) -> Result<(), QueryExecutionFail> {
        self.inspect_storage_probe(
            probe_key.as_ref().len(),
            result.map(|(key, _)| key.as_ref().len()),
            result.map_or(0, |(_, bytes)| bytes),
        )
    }
}
fn read_policy_for_query(
    world: &impl WorldReadOnly,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<Option<ReserveAuthorityPolicyRecordV1>, QueryExecutionFail> {
    let key = reserve_state_key();
    let bytes = world.smart_contract_state().get(key);
    budget.inspect_direct_read(key, bytes.map_or(0, |bytes| bytes.len()))?;
    bytes
        .map(|bytes| {
            let mut current =
                crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)
                    .map_err(InstructionExecutionError::Query)?;
            decode_reserve_state_for_current(bytes, &mut current).map(|state| state.policy)
        })
        .transpose()
        .map_err(query_failure)
}
fn checked_query_limit(limit: u32) -> Result<usize, QueryExecutionFail> {
    if !(1..=RESERVE_QUERY_MAX_ITEMS_V1).contains(&limit) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS reserve event query limit {limit} is outside 1..={RESERVE_QUERY_MAX_ITEMS_V1}"
        )));
    }
    usize::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion(
            "SoraFS reserve event query limit conversion failed".to_owned(),
        )
    })
}
fn resolve_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<ReserveFinalizedCursorV1, QueryExecutionFail> {
    let block_hashes = state_ro.block_hashes();
    budget.inspect_finalized_hash_metadata()?;
    let height = u64::try_from(block_hashes.len()).map_err(|_| {
        QueryExecutionFail::Conversion("finalized reserve height does not fit into u64".to_owned())
    })?;
    let terminal_hash = block_hashes.last();
    budget.inspect_finalized_hash_read(terminal_hash.map_or(0, |_| 32))?;
    let block_hash = terminal_hash.map(|hash| *hash.as_ref()).ok_or_else(|| {
        QueryExecutionFail::Conversion(
            "finalized reserve queries require at least one committed block".to_owned(),
        )
    })?;
    if height == 0 || block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized reserve query anchor is invalid".to_owned(),
        ));
    }
    Ok(ReserveFinalizedCursorV1 { height, block_hash })
}
fn resolve_query_finalized_cursor(
    expected: Option<ReserveFinalizedCursorV1>,
    state_ro: &impl crate::state::StateReadOnly,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<ReserveFinalizedCursorV1, QueryExecutionFail> {
    let actual = resolve_finalized_cursor(state_ro, budget)?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(QueryExecutionFail::Expired);
    }
    Ok(actual)
}
fn read_persisted_event_for_query(
    world: &impl WorldReadOnly,
    sequence: u64,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<Option<ReservePersistedEventV1>, QueryExecutionFail> {
    if sequence == 0 {
        return Err(query_failure(
            "reserve event sequence zero cannot be queried".into(),
        ));
    }
    let key = event_key(sequence);
    let bytes = world.smart_contract_state().get(&key);
    budget.inspect_direct_read(&key, bytes.map_or(0, |bytes| bytes.len()))?;
    bytes
        .map(|bytes| {
            let mut current =
                crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)
                    .map_err(InstructionExecutionError::Query)?;
            decode_persisted_event_for_current(bytes, sequence, &mut current)
        })
        .transpose()
        .map_err(query_failure)
}
fn read_event_journal_head_for_query(
    world: &impl WorldReadOnly,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<Option<ReserveEventJournalHeadV1>, QueryExecutionFail> {
    let key = reserve_state_key();
    let bytes = world.smart_contract_state().get(key);
    budget.inspect_direct_read(key, bytes.map_or(0, |bytes| bytes.len()))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let head = {
        let mut current =
            crate::smartcontracts::isi::query::SingularQueryCurrentAllocation::new(0)?;
        decode_reserve_state_for_current(bytes, &mut current)
            .map_err(query_failure)?
            .journal_head
    };
    let record =
        read_persisted_event_for_query(world, head.last_sequence, budget)?.ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve event journal head references a missing event".to_owned(),
            )
        })?;
    if record.target_block_height != head.last_target_block_height
        || record.event_index != head.last_event_index
    {
        return Err(QueryExecutionFail::Conversion(
            "reserve event journal head does not match its terminal event".to_owned(),
        ));
    }
    let terminal_position = ReserveQueryEventPosition::from(&record);
    drop(record);
    let predecessor_position = if head.last_sequence == 1 {
        None
    } else {
        let predecessor_sequence = head.last_sequence - 1;
        let predecessor = read_persisted_event_for_query(world, predecessor_sequence, budget)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "reserve event journal is missing terminal predecessor sequence {predecessor_sequence}"
                ))
            })?;
        Some(ReserveQueryEventPosition::from(&predecessor))
    };
    let record =
        read_persisted_event_for_query(world, head.last_sequence, budget)?.ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve event journal terminal record disappeared during validation".to_owned(),
            )
        })?;
    if ReserveQueryEventPosition::from(&record) != terminal_position {
        return Err(QueryExecutionFail::Conversion(
            "reserve event journal terminal identity changed during validation".to_owned(),
        ));
    }
    validate_query_event_successor(predecessor_position, &record)?;
    Ok(Some(head))
}
fn ensure_no_event_after_head_for_query(
    world: &impl WorldReadOnly,
    head: ReserveEventJournalHeadV1,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<(), QueryExecutionFail> {
    let prefix_start =
        StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid");
    let mut first_iter = world.smart_contract_state().range(prefix_start.clone()..);
    let first = first_iter.next();
    budget.inspect_range_read(&prefix_start, first.map(|(key, value)| (key, value.len())))?;
    let Some((first_key, _)) = first else {
        return Err(query_failure(
            "reserve event journal head exists without event records".into(),
        ));
    };
    if !first_key.as_ref().starts_with(EVENT_STATE_KEY_PREFIX) || *first_key != event_key(1) {
        return Err(query_failure(
            "reserve event journal does not begin at sequence one".into(),
        ));
    }
    let terminal_key = event_key(head.last_sequence);
    let mut tail_iter = world.smart_contract_state().range(terminal_key.clone()..);
    let mut probe_key = terminal_key.clone();
    loop {
        let next = tail_iter.next();
        budget.inspect_range_read(&probe_key, next.map(|(key, value)| (key, value.len())))?;
        let Some((key, _)) = next else {
            break;
        };
        if *key == terminal_key {
            probe_key = key.clone();
            continue;
        }
        if key.as_ref().starts_with(EVENT_STATE_KEY_PREFIX) {
            return Err(query_failure(
                "reserve event journal contains a record beyond its head".into(),
            ));
        }
        break;
    }
    Ok(())
}
fn resolve_committed_event(
    state_ro: &impl crate::state::StateReadOnly,
    record: ReservePersistedEventV1,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<ReserveFinalizedEventV1, QueryExecutionFail> {
    let hash_index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve event target height cannot index finalized block hashes".to_owned(),
            )
        })?;
    let hash = state_ro.block_hashes().get(hash_index);
    budget.inspect_finalized_hash_read(hash.map_or(0, |_| 32))?;
    let block_hash = hash.map(|hash| *hash.as_ref()).ok_or_else(|| {
        QueryExecutionFail::Conversion(format!(
            "reserve event sequence {} targets non-finalized block height {}",
            record.sequence, record.target_block_height
        ))
    })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "reserve event sequence {} resolved a zero block hash",
            record.sequence
        )));
    }
    Ok(ReserveFinalizedEventV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
        event: record.event,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReserveQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
}
impl From<&ReservePersistedEventV1> for ReserveQueryEventPosition {
    fn from(record: &ReservePersistedEventV1) -> Self {
        Self {
            sequence: record.sequence,
            target_block_height: record.target_block_height,
            event_index: record.event_index,
        }
    }
}
fn validate_query_event_successor(
    previous: Option<ReserveQueryEventPosition>,
    current: &ReservePersistedEventV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1 && current.event_index == 0)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "reserve event journal does not begin at sequence one and block index zero"
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
            "reserve event journal sequence is not contiguous".to_owned(),
        ));
    }
    match previous
        .target_block_height
        .cmp(&current.target_block_height)
    {
        core::cmp::Ordering::Less if current.event_index == 0 => Ok(()),
        core::cmp::Ordering::Equal
            if previous
                .event_index
                .checked_add(1)
                .is_some_and(|next| current.event_index == next) =>
        {
            Ok(())
        }
        _ => Err(QueryExecutionFail::Conversion(
            "reserve event journal block height/index ordering is invalid".to_owned(),
        )),
    }
}
fn query_reserve_event_page(
    query: &FindSorafsReserveEvents,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: ReserveFinalizedCursorV1,
    budget: &mut ReserveEventQueryBudgetV1,
) -> Result<ReserveFinalizedEventPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let page_bytes_limit = crate::smartcontracts::isi::query::singular_query_frame_limit(
        RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let world = state_ro.world();
    if read_policy_for_query(world, budget)?.is_none() {
        return Err(QueryExecutionFail::Find(FindError::SorafsReservePolicy));
    }
    let head = read_event_journal_head_for_query(world, budget)?.ok_or_else(|| {
        QueryExecutionFail::Conversion(
            "active reserve state has no committed-event journal".to_owned(),
        )
    })?;
    let first = read_persisted_event_for_query(world, 1, budget)?.ok_or_else(|| {
        QueryExecutionFail::Conversion(
            "reserve event journal is missing initial policy activation".to_owned(),
        )
    })?;
    validate_event_successor(None, &first).map_err(query_failure)?;
    if first.event.kind != SorafsReserveLedgerEventKind::PolicyActivated {
        return Err(QueryExecutionFail::Conversion(
            "reserve event journal does not begin with policy activation".to_owned(),
        ));
    }
    resolve_committed_event(state_ro, first, budget)?;
    let terminal =
        read_persisted_event_for_query(world, head.last_sequence, budget)?.ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve event journal terminal record disappeared during read".to_owned(),
            )
        })?;
    resolve_committed_event(state_ro, terminal, budget)?;
    ensure_no_event_after_head_for_query(world, head, budget)?;
    let mut previous = match query.after {
        Some(after) => {
            if after.sequence == 0 || after.sequence > head.last_sequence {
                return Err(QueryExecutionFail::Expired);
            }
            let predecessor_record = if after.sequence == 1 {
                None
            } else {
                let predecessor_sequence = after.sequence - 1;
                Some(
                    read_persisted_event_for_query(
                        world,
                        predecessor_sequence,
                        budget,
                    )?
                    .ok_or_else(|| {
                        QueryExecutionFail::Conversion(format!(
                            "reserve event journal is missing predecessor sequence {predecessor_sequence}"
                        ))
                    })?,
                )
            };
            let predecessor = predecessor_record
                .as_ref()
                .map(ReserveQueryEventPosition::from);
            drop(predecessor_record);
            let record = read_persisted_event_for_query(world, after.sequence, budget)?
                .ok_or(QueryExecutionFail::Expired)?;
            validate_query_event_successor(predecessor, &record)?;
            let position = ReserveQueryEventPosition::from(&record);
            let resolved = resolve_committed_event(state_ro, record, budget)?;
            if resolved.cursor() != after {
                return Err(QueryExecutionFail::Expired);
            }
            Some(position)
        }
        None => None,
    };
    let mut sequence = query
        .after
        .map_or(Some(1), |after| after.sequence.checked_add(1));
    let mut events = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let mut encoded_event_bytes = 0usize;
    while let Some(current_sequence) = sequence {
        if current_sequence > head.last_sequence || events.len() >= limit {
            break;
        }
        let record =
            read_persisted_event_for_query(world, current_sequence, budget)?.ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "reserve event journal is missing sequence {current_sequence}"
                ))
            })?;
        validate_query_event_successor(previous, &record)?;
        let position = ReserveQueryEventPosition::from(&record);
        let resolved = resolve_committed_event(state_ro, record, budget)?;
        encoded_event_bytes = encoded_event_bytes
            .checked_add(norito::canonical_frame_len(&resolved).map_err(|error| {
                QueryExecutionFail::Conversion(format!(
                    "failed to size committed reserve event: {error}"
                ))
            })?)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "committed reserve event page byte counter overflow".to_owned(),
                )
            })?;
        if encoded_event_bytes > page_bytes_limit {
            return Err(QueryExecutionFail::Conversion(format!(
                "committed reserve event page exceeds {page_bytes_limit} bytes"
            )));
        }
        previous = Some(position);
        events.try_push(resolved)?;
        sequence = current_sequence.checked_add(1);
    }
    let has_more = events
        .last()
        .is_some_and(|event| event.sequence < head.last_sequence);
    let next_after = has_more.then(|| {
        events
            .last()
            .expect("has_more requires a non-empty reserve event page")
            .cursor()
    });
    let page = ReserveFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    let encoded_len = norito::canonical_frame_len(&page).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "failed to size committed reserve event page: {error}"
        ))
    })?;
    if encoded_len > page_bytes_limit {
        return Err(QueryExecutionFail::Conversion(format!(
            "committed reserve event page encodes to {encoded_len} bytes, above {page_bytes_limit}"
        )));
    }
    Ok(page)
}
fn scan_reserve_records<T>(
    world: &impl WorldReadOnly,
    prefix: &str,
    start: StatePath,
    limit: usize,
    budget: &mut ReserveEventQueryBudgetV1,
    mut decode: impl FnMut(&StatePath, &[u8]) -> Result<Option<T>, QueryExecutionFail>,
) -> Result<(Vec<T>, bool), QueryExecutionFail>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    let mut records = crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(limit)?;
    let mut has_more = false;
    let mut probe_key = start.clone();
    let mut iter = world.smart_contract_state().range(start..);
    loop {
        let next = iter.next();
        budget.inspect_range_read(&probe_key, next.map(|(key, payload)| (key, payload.len())))?;
        let Some((key, payload)) = next else {
            break;
        };
        probe_key = key.clone();
        if !key.as_ref().starts_with(prefix) {
            break;
        }
        if payload.len() > RESERVE_QUERY_MAX_RECORD_BYTES_V1 {
            return Err(QueryExecutionFail::Conversion(format!(
                "authoritative reserve record exceeds {RESERVE_QUERY_MAX_RECORD_BYTES_V1} bytes"
            )));
        }
        if let Some(record) = decode(key, payload)? {
            if records.len() == limit {
                has_more = true;
                break;
            }
            records.try_push(record)?;
        }
    }
    Ok((records.into_vec()?, has_more))
}
fn checked_page_records<T, I: Copy>(
    records: Vec<T>,
    has_more: bool,
    id: impl Fn(&T) -> I,
) -> Result<(Vec<T>, bool, Option<I>), QueryExecutionFail> {
    let next_after = if has_more {
        Some(id(records.last().ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "reserve record page continuation invariant failed".to_owned(),
            )
        })?))
    } else {
        None
    };
    Ok((records, has_more, next_after))
}
fn validate_encoded_record_page<T: norito::core::NoritoSerialize>(
    page: &T,
) -> Result<(), QueryExecutionFail> {
    let maximum = crate::smartcontracts::isi::query::singular_query_frame_limit(
        RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let encoded_len = norito::canonical_frame_len(page).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "failed to size authoritative reserve record page: {error}"
        ))
    })?;
    if encoded_len > maximum {
        return Err(QueryExecutionFail::Conversion(format!(
            "authoritative reserve record page encodes to {encoded_len} bytes, above {maximum}"
        )));
    }
    Ok(())
}
impl ValidSingularQuery for FindSorafsReservePolicy {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveAuthorityPolicyRecordV1, QueryExecutionFail> {
        let mut budget = ReserveEventQueryBudgetV1::default();
        read_event_journal_head_for_query(state_ro.world(), &mut budget)?;
        read_policy_for_query(state_ro.world(), &mut budget)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsReservePolicy))
    }
}
impl ValidSingularQuery for FindSorafsReserveProviderById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveProviderAccountV1, QueryExecutionFail> {
        read_provider(state_ro.world(), self.provider_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsReserveProvider(self.provider_id))
            })
    }
}
impl ValidSingularQuery for FindSorafsReserveMovementById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveMovementRecordV1, QueryExecutionFail> {
        read_movement(state_ro.world(), self.movement_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsReserveMovement(self.movement_id))
            })
    }
}
impl ValidSingularQuery for FindSorafsReserveAppealById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveAppealRecordV1, QueryExecutionFail> {
        read_appeal(state_ro.world(), self.appeal_id)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsReserveAppeal(self.appeal_id)))
    }
}
impl ValidSingularQuery for FindSorafsReserveProviders {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveProviderAccountPageV1, QueryExecutionFail> {
        let limit = checked_query_limit(self.limit)?;
        let mut budget = ReserveEventQueryBudgetV1::default();
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro, &mut budget)?;
        let world = state_ro.world();
        if read_policy_for_query(world, &mut budget)?.is_none() {
            return Err(QueryExecutionFail::Find(FindError::SorafsReservePolicy));
        }
        let after = self.after_provider_id;
        let start = after.map_or_else(
            || {
                StatePath::from_str(RESERVE_PROVIDER_STATE_KEY_PREFIX_V1)
                    .expect("static provider prefix is valid")
            },
            reserve_provider_key,
        );
        let (accounts, has_more) = scan_reserve_records(
            world,
            RESERVE_PROVIDER_STATE_KEY_PREFIX_V1,
            start,
            limit,
            &mut budget,
            |key, payload| {
                let candidate: ReserveProviderAccountV1 =
                    decode_state(payload, "reserve provider account").map_err(query_failure)?;
                let provider_id = candidate.terms.provider_id;
                if reserve_provider_key(provider_id) != *key {
                    return Err(QueryExecutionFail::Conversion(
                        "authoritative reserve provider key does not match its account".to_owned(),
                    ));
                }
                let account =
                    validate_provider_record(candidate, provider_id).map_err(query_failure)?;
                Ok(after
                    .is_none_or(|cursor| provider_id > cursor)
                    .then_some(account))
            },
        )?;
        let (accounts, has_more, next_after) =
            checked_page_records(accounts, has_more, |account| account.terms.provider_id)?;
        let page = ReserveProviderAccountPageV1 {
            finalized_cursor,
            accounts,
            has_more,
            next_after,
        };
        validate_encoded_record_page(&page)?;
        Ok(page)
    }
}
impl ValidSingularQuery for FindSorafsReserveMovements {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveMovementPageV1, QueryExecutionFail> {
        let limit = checked_query_limit(self.limit)?;
        let mut budget = ReserveEventQueryBudgetV1::default();
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro, &mut budget)?;
        let world = state_ro.world();
        if read_policy_for_query(world, &mut budget)?.is_none() {
            return Err(QueryExecutionFail::Find(FindError::SorafsReservePolicy));
        }
        let after = self.after_movement_id;
        let start = after.map_or_else(
            || {
                StatePath::from_str(MOVEMENT_STATE_KEY_PREFIX)
                    .expect("static movement prefix is valid")
            },
            movement_key,
        );
        let (movements, has_more) = scan_reserve_records(
            world,
            MOVEMENT_STATE_KEY_PREFIX,
            start,
            limit,
            &mut budget,
            |key, payload| {
                let candidate: ReserveMovementRecordV1 =
                    decode_state(payload, "reserve movement").map_err(query_failure)?;
                let movement_id = candidate.movement_id;
                if movement_key(movement_id) != *key {
                    return Err(QueryExecutionFail::Conversion(
                        "authoritative reserve movement key does not match its record".to_owned(),
                    ));
                }
                let movement =
                    validate_movement_record(candidate, movement_id).map_err(query_failure)?;
                Ok(after
                    .is_none_or(|cursor| movement_id > cursor)
                    .then_some(movement))
            },
        )?;
        let (movements, has_more, next_after) =
            checked_page_records(movements, has_more, |movement| movement.movement_id)?;
        let page = ReserveMovementPageV1 {
            finalized_cursor,
            movements,
            has_more,
            next_after,
        };
        validate_encoded_record_page(&page)?;
        Ok(page)
    }
}
impl ValidSingularQuery for FindSorafsReserveAppeals {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveAppealPageV1, QueryExecutionFail> {
        let limit = checked_query_limit(self.limit)?;
        let mut budget = ReserveEventQueryBudgetV1::default();
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro, &mut budget)?;
        let world = state_ro.world();
        if read_policy_for_query(world, &mut budget)?.is_none() {
            return Err(QueryExecutionFail::Find(FindError::SorafsReservePolicy));
        }
        let after = self.after_appeal_id;
        let start = after.map_or_else(
            || StatePath::from_str(APPEAL_STATE_KEY_PREFIX).expect("static appeal prefix is valid"),
            appeal_key,
        );
        let (appeals, has_more) = scan_reserve_records(
            world,
            APPEAL_STATE_KEY_PREFIX,
            start,
            limit,
            &mut budget,
            |key, payload| {
                let candidate: ReserveAppealRecordV1 =
                    decode_state(payload, "reserve appeal").map_err(query_failure)?;
                let appeal_id = candidate.appeal_id;
                if appeal_key(appeal_id) != *key {
                    return Err(QueryExecutionFail::Conversion(
                        "authoritative reserve appeal key does not match its record".to_owned(),
                    ));
                }
                let appeal = validate_appeal_record(candidate, appeal_id).map_err(query_failure)?;
                Ok(after
                    .is_none_or(|cursor| appeal_id > cursor)
                    .then_some(appeal))
            },
        )?;
        let (appeals, has_more, next_after) =
            checked_page_records(appeals, has_more, |appeal| appeal.appeal_id)?;
        let page = ReserveAppealPageV1 {
            finalized_cursor,
            appeals,
            has_more,
            next_after,
        };
        validate_encoded_record_page(&page)?;
        Ok(page)
    }
}
impl ValidSingularQuery for FindSorafsReserveEvents {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<ReserveFinalizedEventPageV1, QueryExecutionFail> {
        let mut budget = ReserveEventQueryBudgetV1::default();
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro, &mut budget)?;
        query_reserve_event_page(self, state_ro, finalized_cursor, &mut budget)
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "sorafs_reserve/canonical_state_tests.rs"]
mod canonical_state_tests;
