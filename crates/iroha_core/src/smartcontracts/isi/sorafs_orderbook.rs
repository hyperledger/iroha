//! Authoritative SoraFS orderbook policy and signed-payload ledger handlers.
use super::*;
use crate::smartcontracts::ValidSingularQuery;
use crate::smartcontracts::isi::helpers::instruction_error_as_query_failure as query_failure;
use crate::smartcontracts::isi::helpers::transaction_account_has_permission as has_permission;
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    account::AccountId,
    events::data::sorafs::{
        SorafsGatewayEvent, SorafsOrderbookLedgerEvent, SorafsOrderbookLedgerEventKind,
    },
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::{
            CancelSorafsOrderbookOrder, MaintainSorafsOrderbook, MatchSorafsOrderbook,
            RecordSorafsOrderbookSettlementReceipt, SetSorafsOrderbookPolicy,
            SubmitSorafsOrderbookOrder,
        },
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsOrderbookCancellationByOrderId, FindSorafsOrderbookChannelById,
            FindSorafsOrderbookChannels, FindSorafsOrderbookEvents, FindSorafsOrderbookOrderById,
            FindSorafsOrderbookOrders, FindSorafsOrderbookPolicy, FindSorafsOrderbookReceiptById,
            FindSorafsOrderbookReceipts, FindSorafsOrderbookStatus, FindSorafsOrderbookTradeById,
            FindSorafsOrderbookTrades,
        },
    },
    sorafs::{
        capacity::ProviderId,
        orderbook::{
            ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1, ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1,
            ORDERBOOK_MAX_OPEN_ORDERS_V1, ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1,
            ORDERBOOK_MAX_RECEIPTS_PER_CHANNEL_V1, ORDERBOOK_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            ORDERBOOK_QUERY_MAX_INSPECTED_RECORDS_V1, ORDERBOOK_QUERY_MAX_ITEMS_V1,
            ORDERBOOK_QUERY_MAX_READ_BYTES_V1, OrderbookAdmissionPolicyRecord,
            OrderbookBidEscrowBindingV1, OrderbookCancellationRecord, OrderbookFinalizedCursorV1,
            OrderbookFinalizedEventPageV1, OrderbookFinalizedEventV1, OrderbookLedgerStatusV1,
            OrderbookOrderPageV1, OrderbookOrderRecord, OrderbookOrderStatusV1,
            OrderbookOwnerNonceRecord, OrderbookSettlementChannelPageV1,
            OrderbookSettlementChannelRecord, OrderbookSettlementChannelStatusV1,
            OrderbookSettlementIndexRecord, OrderbookSettlementRangeRecord,
            OrderbookSettlementReceiptPageV1, OrderbookSettlementReceiptRecord,
            OrderbookTradePageV1, OrderbookTradeRecord, orderbook_order_escrow_id,
            orderbook_settlement_escrow_id,
        },
        reserve::ReserveLifecycleStage,
    },
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::DecodeLimits;
use sorafs_manifest::{
    XorQuantity,
    orderbook::{
        BYTES_PER_GIB, ORDERBOOK_PAYLOAD_DECODE_LIMITS_V1, OrderCancelReasonV1, OrderRequestV1,
        OrderSideV1, OrderTierV1, OrderbookPayloadDecodeError, OrderbookSignatureV1, TradeEventV1,
        bid_order_escrow_requirement_v1, decode_order_cancel_v1_with_limits,
        decode_order_request_v1_with_limits, decode_settlement_receipt_v1_with_limits,
        decode_trade_event_v1_with_limits, derive_orderbook_settlement_channel_id_v1,
        derive_orderbook_trade_id_v1, deterministic_settlement_split_v1, match_orders_v1,
        trade_escrow_requirement_v1, trade_fee_requirement_v1, verify_order_cancel_signature_v1,
        verify_order_request_signature_v1, verify_settlement_receipt_signature_v1,
    },
    provider_advert::SignatureAlgorithm,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::OnceLock,
};
mod orderbook_current_memory;
const POLICY_STATE_KEY: &str = "sorafs_orderbook_policy_v1";
const STATUS_STATE_KEY: &str = "sorafs_orderbook_status_v1";
const ORDER_STATE_KEY_PREFIX: &str = "sorafs_orderbook_order_v1_";
const NONCE_STATE_KEY_PREFIX: &str = "sorafs_orderbook_nonce_v1_";
const RECEIPT_STATE_KEY_PREFIX: &str = "sorafs_orderbook_receipt_v1_";
const RECEIPT_INDEX_KEY_PREFIX: &str = "sorafs_orderbook_receipt_index_v1_";
const TRADE_STATE_KEY_PREFIX: &str = "sorafs_orderbook_trade_v1_";
const CHANNEL_STATE_KEY_PREFIX: &str = "sorafs_orderbook_channel_v1_";
const EVENT_STATE_KEY_PREFIX: &str = "sorafs_orderbook_event_v1_";
const EVENT_JOURNAL_HEAD_STATE_KEY: &str = "sorafs_orderbook_event_head_v1";
const NONCE_KEY_DOMAIN_V1: &[u8] = b"sorafs.orderbook.owner-nonce-state.v1";
const STATE_MAX_BYTES: usize = 2 * 1024 * 1024;
const STATE_LIMITS: DecodeLimits = DecodeLimits::new(
    ORDERBOOK_MAX_RECEIPTS_PER_CHANNEL_V1 as usize,
    STATE_MAX_BYTES,
    ORDERBOOK_MAX_RECEIPTS_PER_CHANNEL_V1 as usize * 8,
    STATE_MAX_BYTES * 2,
    64,
);
type OrderbookQueryCurrent = crate::smartcontracts::isi::query::SingularQueryCurrentAllocation;
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
    name = "iroha_core::smartcontracts::isi::sorafs_orderbook::OrderbookPersistedEventV1"
)]
struct OrderbookPersistedEventV1 {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
    event: SorafsOrderbookLedgerEvent,
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
    name = "iroha_core::smartcontracts::isi::sorafs_orderbook::OrderbookEventJournalHeadV1"
)]
struct OrderbookEventJournalHeadV1 {
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
#[allow(clippy::too_many_arguments)]
fn emit_orderbook_event(
    state_transaction: &mut StateTransaction<'_, '_>,
    kind: SorafsOrderbookLedgerEventKind,
    order_id: Option<[u8; 32]>,
    trade_id: Option<[u8; 32]>,
    channel_id: Option<[u8; 32]>,
    receipt_id: Option<[u8; 32]>,
    provider_id: Option<ProviderId>,
    book_revision: u64,
    authority: &AccountId,
    now_unix: u64,
) -> Result<(), InstructionExecutionError> {
    let committed_parent_height = u64::try_from(state_transaction.block_hashes().len())
        .map_err(|_| corrupt_state("committed orderbook parent height does not fit into u64"))?;
    let target_block_height = committed_parent_height
        .checked_add(1)
        .ok_or_else(|| corrupt_state("orderbook event target block height overflow"))?;
    let executing_block_height = state_transaction._curr_block.height().get();
    if target_block_height != executing_block_height {
        return Err(corrupt_state(format!(
            "orderbook event target height {target_block_height} does not match executing block height {executing_block_height}"
        )));
    }
    let occurred_at_unix_ms = now_unix
        .checked_mul(1_000)
        .ok_or_else(|| corrupt_state("orderbook event timestamp overflow"))?;
    let event = SorafsOrderbookLedgerEvent {
        kind,
        order_id,
        trade_id,
        channel_id,
        receipt_id,
        provider_id,
        book_revision,
        authority: authority.clone(),
        occurred_at_unix_ms,
    };
    let head = read_event_journal_head(state_transaction.world())?;
    ensure_no_event_after_head(state_transaction.world(), head)?;
    let (sequence, event_index) = match head {
        Some(head) => {
            let sequence = head
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("orderbook event sequence overflow"))?;
            let event_index = match head.last_target_block_height.cmp(&target_block_height) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => head
                    .last_event_index
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("orderbook event block index overflow"))?,
                core::cmp::Ordering::Greater => {
                    return Err(corrupt_state(
                        "orderbook event target height regressed behind the journal head",
                    ));
                }
            };
            (sequence, event_index)
        }
        None => {
            let policy = read_policy(state_transaction.world())?
                .ok_or_else(|| corrupt_state("first orderbook event has no active policy"))?;
            let status = read_status(state_transaction.world())?
                .ok_or_else(|| corrupt_state("first orderbook event has no ledger status"))?;
            let counters_empty = status.open_orders == 0
                && status.partially_filled_orders == 0
                && status.filled_orders == 0
                && status.cancelled_orders == 0
                && status.expired_orders == 0
                && status.provider_revoked_orders == 0
                && status.trades == 0
                && status.settlement_receipts == 0
                && status.settlement_channels == 0
                && status.open_settlement_channels == 0
                && status.book_revision == 0
                && status.last_match_scan_book_revision == 0
                && status.next_admission_sequence == 1
                && status.next_trade_sequence == 1;
            if kind != SorafsOrderbookLedgerEventKind::PolicyActivated
                || order_id.is_some()
                || trade_id.is_some()
                || channel_id.is_some()
                || receipt_id.is_some()
                || provider_id.is_some()
                || policy.policy.revision != 1
                || !counters_empty
            {
                return Err(corrupt_state(
                    "orderbook event journal must begin with initial policy activation",
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
            "orderbook event journal sequence already exists",
        ));
    }
    let record = OrderbookPersistedEventV1 {
        sequence,
        target_block_height,
        event_index,
        event: event.clone(),
    };
    validate_persisted_event(&record, sequence)?;
    let next_head = OrderbookEventJournalHeadV1 {
        last_sequence: sequence,
        last_target_block_height: target_block_height,
        last_event_index: event_index,
    };
    let encoded_record = encode_state(&record, "orderbook committed event")?;
    let encoded_head = encode_state(&next_head, "orderbook event journal head")?;
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
        .emit_events(Some(SorafsGatewayEvent::OrderbookLedger(event)));
    Ok(())
}
fn require_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> Result<(), InstructionExecutionError> {
    if has_permission(state_transaction, authority, permission) {
        Ok(())
    } else {
        Err(invalid_parameter(format!(
            "permission {permission} required for authoritative SoraFS orderbook operation"
        )))
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
fn digest_key(prefix: &str, digest: [u8; 32]) -> StatePath {
    StatePath::from_str(&format!("{prefix}{}", hex::encode(digest)))
        .expect("static prefix plus lowercase hex is a valid state key")
}
fn order_key(order_id: [u8; 32]) -> StatePath {
    digest_key(ORDER_STATE_KEY_PREFIX, order_id)
}
fn receipt_key(receipt_id: [u8; 32]) -> StatePath {
    digest_key(RECEIPT_STATE_KEY_PREFIX, receipt_id)
}
fn receipt_index_key(channel_id: [u8; 32]) -> StatePath {
    digest_key(RECEIPT_INDEX_KEY_PREFIX, channel_id)
}
fn trade_key(trade_id: [u8; 32]) -> StatePath {
    digest_key(TRADE_STATE_KEY_PREFIX, trade_id)
}
fn channel_key(channel_id: [u8; 32]) -> StatePath {
    digest_key(CHANNEL_STATE_KEY_PREFIX, channel_id)
}
fn parse_query_digest_key(
    key: &StatePath,
    prefix: &str,
    label: &str,
) -> Result<[u8; 32], QueryExecutionFail> {
    let suffix = key
        .as_ref()
        .strip_prefix(prefix)
        .filter(|suffix| suffix.len() == 64)
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "authoritative orderbook {label} key has an invalid digest suffix"
            ))
        })?;
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(suffix, &mut digest).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "authoritative orderbook {label} key has invalid hex: {error}"
        ))
    })?;
    Ok(digest)
}
fn event_key(sequence: u64) -> StatePath {
    StatePath::from_str(&format!("{EVENT_STATE_KEY_PREFIX}{sequence:016x}"))
        .expect("static prefix plus fixed-width lowercase hex is a valid state key")
}
fn event_journal_head_key() -> &'static StatePath {
    static KEY: OnceLock<StatePath> = OnceLock::new();
    KEY.get_or_init(|| {
        StatePath::from_str(EVENT_JOURNAL_HEAD_STATE_KEY).expect("static state key is valid")
    })
}
fn nonce_key(owner: &AccountId) -> Result<StatePath, InstructionExecutionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NONCE_KEY_DOMAIN_V1);
    norito::core::write_canonical_to_writer(owner, &mut hasher).map_err(|error| {
        corrupt_state(format!("failed to encode orderbook nonce owner: {error}"))
    })?;
    Ok(digest_key(
        NONCE_STATE_KEY_PREFIX,
        *hasher.finalize().as_bytes(),
    ))
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
    decode_state_measured(bytes, label).map(|(value, _)| value)
}
fn decode_orderbook_payload<T>(
    bytes: &[u8],
    decode: impl FnOnce(&[u8], DecodeLimits) -> Result<T, OrderbookPayloadDecodeError>,
    legacy_error: impl FnOnce(OrderbookPayloadDecodeError) -> InstructionExecutionError,
) -> Result<T, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    decode_orderbook_payload_for_current(bytes, &mut current, decode, legacy_error)
}
fn decode_orderbook_payload_for_current<T>(
    bytes: &[u8],
    current: &mut OrderbookQueryCurrent,
    decode: impl FnOnce(&[u8], DecodeLimits) -> Result<T, OrderbookPayloadDecodeError>,
    legacy_error: impl FnOnce(OrderbookPayloadDecodeError) -> InstructionExecutionError,
) -> Result<T, InstructionExecutionError> {
    let limits = current
        .decode_limits(bytes.len(), ORDERBOOK_PAYLOAD_DECODE_LIMITS_V1)
        .map_err(InstructionExecutionError::Query)?;
    let (value, usage) =
        norito::core::with_decode_limits_measured(limits, || decode(bytes, limits));
    let value = value.map_err(|error| {
        if crate::smartcontracts::isi::query::singular_query_limits_active()
            && error.is_decode_resource_limit()
        {
            InstructionExecutionError::Query(QueryExecutionFail::CapacityLimit)
        } else {
            legacy_error(error)
        }
    })?;
    current
        .add_nested(usage.total_allocated_bytes())
        .map_err(InstructionExecutionError::Query)?;
    Ok(value)
}
fn decode_state_measured<T>(
    bytes: &[u8],
    label: &str,
) -> Result<(T, usize), InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    ensure_state_size(bytes, label)?;
    let limits =
        crate::smartcontracts::isi::query::singular_query_decode_limits(bytes.len(), STATE_LIMITS)
            .map_err(InstructionExecutionError::Query)?;
    decode_state_with_limits(bytes, label, limits)
}
fn decode_state_for_current<T>(
    bytes: &[u8],
    label: &str,
    current: &mut OrderbookQueryCurrent,
) -> Result<T, InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    ensure_state_size(bytes, label)?;
    let limits = current
        .decode_limits(bytes.len(), STATE_LIMITS)
        .map_err(InstructionExecutionError::Query)?;
    let (value, allocated) = decode_state_with_limits(bytes, label, limits)?;
    current
        .add_nested(allocated)
        .map_err(InstructionExecutionError::Query)?;
    Ok(value)
}
fn decode_state_with_limits<T>(
    bytes: &[u8],
    label: &str,
    limits: DecodeLimits,
) -> Result<(T, usize), InstructionExecutionError>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let (value, usage) = norito::core::with_decode_limits_measured(limits, || {
        norito::decode_canonical_with_limits::<T>(bytes, limits)
    });
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
    Ok((value, usage.total_allocated_bytes()))
}
fn ensure_state_size(bytes: &[u8], label: &str) -> Result<(), InstructionExecutionError> {
    if bytes.len() > STATE_MAX_BYTES {
        return Err(corrupt_state(format!(
            "{label} state exceeds {STATE_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}
fn validate_persisted_event(
    record: &OrderbookPersistedEventV1,
    expected_sequence: u64,
) -> Result<(), InstructionExecutionError> {
    if record.sequence == 0
        || record.sequence != expected_sequence
        || record.target_block_height == 0
        || record.event.occurred_at_unix_ms == 0
    {
        return Err(corrupt_state(
            "stored orderbook event cursor metadata is invalid",
        ));
    }
    for (label, digest) in [
        ("order", record.event.order_id),
        ("trade", record.event.trade_id),
        ("channel", record.event.channel_id),
        ("receipt", record.event.receipt_id),
    ] {
        if digest == Some([0; 32]) {
            return Err(corrupt_state(format!(
                "stored orderbook event has a zero {label} identifier"
            )));
        }
    }
    if record
        .event
        .provider_id
        .is_some_and(|provider_id| provider_id.as_bytes() == &[0; 32])
    {
        return Err(corrupt_state(
            "stored orderbook event has a zero provider identifier",
        ));
    }
    let shape_is_valid = match record.event.kind {
        SorafsOrderbookLedgerEventKind::PolicyActivated => {
            record.event.order_id.is_none()
                && record.event.trade_id.is_none()
                && record.event.channel_id.is_none()
                && record.event.receipt_id.is_none()
                && record.event.provider_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderAdmitted => {
            record.event.order_id.is_some()
                && record.event.trade_id.is_none()
                && record.event.channel_id.is_none()
                && record.event.receipt_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderCancelled
        | SorafsOrderbookLedgerEventKind::OrderExpired => {
            record.event.order_id.is_some()
                && record.event.trade_id.is_none()
                && record.event.channel_id.is_none()
                && record.event.receipt_id.is_none()
                && record.event.provider_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderProviderRevoked => {
            record.event.order_id.is_some()
                && record.event.trade_id.is_none()
                && record.event.channel_id.is_none()
                && record.event.receipt_id.is_none()
                && record.event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::TradeMatched => {
            record.event.order_id.is_some()
                && record.event.trade_id.is_some()
                && record.event.channel_id.is_some()
                && record.event.receipt_id.is_none()
                && record.event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::ChannelExpired => {
            record.event.order_id.is_none()
                && record.event.trade_id.is_some()
                && record.event.channel_id.is_some()
                && record.event.receipt_id.is_none()
                && record.event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::ReceiptRecorded => {
            record.event.order_id.is_none()
                && record.event.trade_id.is_some()
                && record.event.channel_id.is_some()
                && record.event.receipt_id.is_some()
                && record.event.provider_id.is_some()
        }
    };
    if !shape_is_valid {
        return Err(corrupt_state(
            "stored orderbook event payload shape is invalid",
        ));
    }
    Ok(())
}
fn validate_event_successor(
    previous: Option<&OrderbookPersistedEventV1>,
    current: &OrderbookPersistedEventV1,
) -> Result<(), InstructionExecutionError> {
    let Some(previous) = previous else {
        if current.sequence != 1 || current.event_index != 0 {
            return Err(corrupt_state(
                "orderbook event journal does not begin at sequence one and block index zero",
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
            "orderbook event journal sequence is not contiguous",
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
            "orderbook event journal block height/index ordering is invalid",
        )),
    }
}
fn read_persisted_event(
    world: &impl WorldReadOnly,
    sequence: u64,
) -> Result<Option<OrderbookPersistedEventV1>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    read_persisted_event_with_current(world, sequence, &mut current)
}
fn read_persisted_event_with_current(
    world: &impl WorldReadOnly,
    sequence: u64,
    current: &mut OrderbookQueryCurrent,
) -> Result<Option<OrderbookPersistedEventV1>, InstructionExecutionError> {
    if sequence == 0 {
        return Err(corrupt_state(
            "orderbook event sequence zero cannot be read",
        ));
    }
    let Some(bytes) = world.smart_contract_state().get(&event_key(sequence)) else {
        return Ok(None);
    };
    let record: OrderbookPersistedEventV1 =
        decode_state_for_current(bytes, "orderbook committed event", current)?;
    validate_persisted_event(&record, sequence)?;
    Ok(Some(record))
}
fn read_event_journal_head(
    world: &impl WorldReadOnly,
) -> Result<Option<OrderbookEventJournalHeadV1>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let Some(bytes) = world.smart_contract_state().get(event_journal_head_key()) else {
        return Ok(None);
    };
    let head: OrderbookEventJournalHeadV1 =
        decode_state_for_current(bytes, "orderbook event journal head", &mut current)?;
    if head.last_sequence == 0 || head.last_target_block_height == 0 {
        return Err(corrupt_state(
            "stored orderbook event journal head is invalid",
        ));
    }
    let record = read_persisted_event_with_current(world, head.last_sequence, &mut current)?
        .ok_or_else(|| corrupt_state("orderbook event journal head references a missing event"))?;
    if record.target_block_height != head.last_target_block_height
        || record.event_index != head.last_event_index
    {
        return Err(corrupt_state(
            "orderbook event journal head does not match its terminal event",
        ));
    }
    let predecessor = if head.last_sequence == 1 {
        None
    } else {
        let predecessor_sequence = head.last_sequence - 1;
        Some(
            read_persisted_event_with_current(world, predecessor_sequence, &mut current)?
                .ok_or_else(|| {
                    corrupt_state(format!(
                        "orderbook event journal is missing terminal predecessor sequence {predecessor_sequence}"
                    ))
                })?,
        )
    };
    validate_event_successor(predecessor.as_ref(), &record)?;
    Ok(Some(head))
}
fn ensure_no_event_after_head(
    world: &impl WorldReadOnly,
    head: Option<OrderbookEventJournalHeadV1>,
) -> Result<(), InstructionExecutionError> {
    let prefix_start =
        StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid");
    let first_event_key = world
        .smart_contract_state()
        .range(prefix_start..)
        .next()
        .and_then(|(key, _)| {
            key.as_ref()
                .starts_with(EVENT_STATE_KEY_PREFIX)
                .then_some(key)
        });
    match (head, first_event_key) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(corrupt_state(
                "orderbook event journal contains records without a head",
            ));
        }
        (Some(_), Some(key)) if *key == event_key(1) => {}
        (Some(_), _) => {
            return Err(corrupt_state(
                "orderbook event journal does not begin at sequence one",
            ));
        }
    }
    let start = head.map_or_else(
        || StatePath::from_str(EVENT_STATE_KEY_PREFIX).expect("static event prefix is valid"),
        |head| event_key(head.last_sequence),
    );
    for (key, _) in world.smart_contract_state().range(start..) {
        if !key.as_ref().starts_with(EVENT_STATE_KEY_PREFIX) {
            break;
        }
        if head.is_some_and(|head| *key == event_key(head.last_sequence)) {
            continue;
        }
        return Err(corrupt_state(
            "orderbook event journal contains a record beyond its head",
        ));
    }
    Ok(())
}
fn block_time_unix(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<u64, InstructionExecutionError> {
    let now = state_transaction.block_unix_timestamp_ms() / 1_000;
    if now == 0 {
        return Err(invalid_parameter(
            "authoritative orderbook operations require a non-zero block timestamp",
        ));
    }
    Ok(now)
}
fn read_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<OrderbookAdmissionPolicyRecord>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(policy_key()) else {
        return Ok(None);
    };
    let record: OrderbookAdmissionPolicyRecord = decode_state(bytes, "orderbook policy")?;
    record
        .policy
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored orderbook policy: {error}")))?;
    let expected = record
        .policy
        .digest()
        .map_err(|error| corrupt_state(format!("failed to digest stored policy: {error}")))?;
    if expected != record.policy_digest || record.activated_at_unix == 0 {
        return Err(corrupt_state(
            "stored orderbook policy digest or activation timestamp is invalid",
        ));
    }
    Ok(Some(record))
}
fn read_status(
    world: &impl WorldReadOnly,
) -> Result<Option<OrderbookLedgerStatusV1>, InstructionExecutionError> {
    let Some(bytes) = world.smart_contract_state().get(status_key()) else {
        return Ok(None);
    };
    let status: OrderbookLedgerStatusV1 = decode_state(bytes, "orderbook ledger status")?;
    if status.updated_at_unix == 0
        || status.next_admission_sequence == 0
        || status.next_trade_sequence == 0
        || status.last_match_scan_book_revision > status.book_revision
        || status.open_settlement_channels > status.settlement_channels
        || status.open_settlement_channels > u64::from(ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1)
        || status
            .open_orders
            .checked_add(status.partially_filled_orders)
            .and_then(|count| count.checked_add(status.filled_orders))
            .and_then(|count| count.checked_add(status.cancelled_orders))
            .and_then(|count| count.checked_add(status.expired_orders))
            .and_then(|count| count.checked_add(status.provider_revoked_orders))
            .is_none()
    {
        return Err(corrupt_state(
            "stored orderbook ledger status counters or timestamp are invalid",
        ));
    }
    Ok(Some(status))
}
fn active_status(
    state_transaction: &StateTransaction<'_, '_>,
    now: u64,
) -> Result<OrderbookLedgerStatusV1, InstructionExecutionError> {
    let status = read_status(state_transaction.world())?
        .ok_or_else(|| corrupt_state("active orderbook policy has no ledger status record"))?;
    if status.updated_at_unix > now {
        return Err(corrupt_state(
            "stored orderbook ledger status is later than the current block",
        ));
    }
    Ok(status)
}
fn encode_status(status: &OrderbookLedgerStatusV1) -> Result<Vec<u8>, InstructionExecutionError> {
    encode_state(status, "orderbook ledger status")
}
fn active_order_count(status: &OrderbookLedgerStatusV1) -> Result<u64, InstructionExecutionError> {
    status
        .open_orders
        .checked_add(status.partially_filled_orders)
        .ok_or_else(|| corrupt_state("orderbook active-order counter overflow"))
}
fn advance_book_revision(
    status: &mut OrderbookLedgerStatusV1,
) -> Result<u64, InstructionExecutionError> {
    status.book_revision = status
        .book_revision
        .checked_add(1)
        .ok_or_else(|| corrupt_state("orderbook book revision overflow"))?;
    Ok(status.book_revision)
}
fn active_policy(
    state_transaction: &StateTransaction<'_, '_>,
    supplied_digest: [u8; 32],
) -> Result<(OrderbookAdmissionPolicyRecord, u64), InstructionExecutionError> {
    let now = block_time_unix(state_transaction)?;
    let record = read_policy(state_transaction.world())?
        .ok_or_else(|| invalid_parameter("SoraFS orderbook admission policy is not configured"))?;
    if record.activated_at_unix > now {
        return Err(corrupt_state(
            "stored orderbook policy activation is later than the current block",
        ));
    }
    if supplied_digest != record.policy_digest {
        return Err(invalid_parameter(format!(
            "orderbook policy digest mismatch: supplied {}, active {}",
            hex::encode(supplied_digest),
            hex::encode(record.policy_digest)
        )));
    }
    Ok((record, now))
}
fn require_governed_orderbook_authority(
    authority: &AccountId,
    governed_authority: &AccountId,
    role: &str,
) -> Result<(), InstructionExecutionError> {
    if authority != governed_authority {
        return Err(invalid_parameter(format!(
            "orderbook {role} authority {authority} does not match governed authority {governed_authority}"
        )));
    }
    Ok(())
}
fn canonical_owner(
    owner_bytes: &[u8],
    authority: &AccountId,
) -> Result<AccountId, InstructionExecutionError> {
    let literal = core::str::from_utf8(owner_bytes)
        .map_err(|_| invalid_parameter("orderbook owner account must be canonical UTF-8 I105"))?;
    let parsed = AccountId::parse_encoded(literal).map_err(|error| {
        invalid_parameter(format!(
            "invalid orderbook owner account: {}",
            error.code_str()
        ))
    })?;
    if parsed.to_string().as_bytes() != owner_bytes {
        return Err(invalid_parameter(
            "orderbook owner account must be exact canonical I105 bytes",
        ));
    }
    let owner = parsed;
    if owner.subject_id() != authority.subject_id() {
        return Err(invalid_parameter(format!(
            "orderbook owner {owner} does not match transaction authority {authority}"
        )));
    }
    Ok(owner)
}
fn ensure_payload_signer(
    authority: &AccountId,
    signature: &OrderbookSignatureV1,
) -> Result<(), InstructionExecutionError> {
    if signature.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(invalid_parameter(
            "orderbook payload signer must use Ed25519",
        ));
    }
    let public_key = authority.try_signatory().ok_or_else(|| {
        invalid_parameter(
            "first-release orderbook payload admission requires a single-signatory account",
        )
    })?;
    let (algorithm, payload) = public_key
        .try_to_bytes()
        .map_err(|error| invalid_parameter(format!("invalid authority public key: {error}")))?;
    if algorithm != Algorithm::Ed25519 || payload != signature.public_key.as_slice() {
        return Err(invalid_parameter(
            "embedded orderbook payload signer does not match the transaction authority",
        ));
    }
    Ok(())
}
fn read_nonce(
    world: &impl WorldReadOnly,
    owner: &AccountId,
) -> Result<Option<OrderbookOwnerNonceRecord>, InstructionExecutionError> {
    let key = nonce_key(owner)?;
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: OrderbookOwnerNonceRecord = decode_state(bytes, "orderbook owner nonce")?;
    if record.owner.subject_id() != owner.subject_id() || record.highest_nonce == 0 {
        return Err(corrupt_state(
            "stored orderbook owner nonce has an invalid owner or zero high-water",
        ));
    }
    Ok(Some(record))
}
fn ensure_nonce_advances(
    world: &impl WorldReadOnly,
    owner: &AccountId,
    nonce: u64,
) -> Result<(), InstructionExecutionError> {
    if let Some(current) = read_nonce(world, owner)?
        && nonce <= current.highest_nonce
    {
        return Err(invalid_parameter(format!(
            "orderbook nonce {nonce} is stale or replayed; highest committed nonce is {}",
            current.highest_nonce
        )));
    }
    Ok(())
}
fn write_nonce(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    nonce: u64,
) -> Result<(), InstructionExecutionError> {
    let record = OrderbookOwnerNonceRecord {
        owner: owner.clone(),
        highest_nonce: nonce,
    };
    let encoded = encode_state(&record, "orderbook owner nonce")?;
    state_transaction
        .world
        .smart_contract_state
        .insert(nonce_key(owner)?, encoded);
    Ok(())
}
fn read_order(
    world: &impl WorldReadOnly,
    order_id: [u8; 32],
) -> Result<Option<OrderbookOrderRecord>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let key = order_key(order_id);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: OrderbookOrderRecord =
        decode_state_for_current(bytes, "orderbook order", &mut current)?;
    let record_resident_bytes = current.resident_bytes();
    if record.order_id != order_id
        || record.order_id == [0; 32]
        || record.admitted_policy_digest == [0; 32]
        || record.admitted_at_unix == 0
        || record.admission_sequence == 0
        || record.updated_at_unix < record.admitted_at_unix
    {
        return Err(corrupt_state("stored orderbook order metadata is invalid"));
    }
    let order = decode_orderbook_payload_for_current(
        &record.canonical_order,
        &mut current,
        decode_order_request_v1_with_limits,
        |error| corrupt_state(format!("invalid stored order payload: {error}")),
    )?;
    verify_order_request_signature_v1(&order)
        .map_err(|error| corrupt_state(format!("invalid stored order signature: {error}")))?;
    ensure_payload_signer(&record.owner, &order.signature).map_err(|error| {
        corrupt_state(format!(
            "stored order signer does not match its authoritative owner: {error}"
        ))
    })?;
    if order.expiry_unix <= record.admitted_at_unix {
        return Err(corrupt_state(
            "stored order expiry is not later than its admission timestamp",
        ));
    }
    core::str::from_utf8(&order.owner_account)
        .map_err(|_| corrupt_state("stored order owner is not UTF-8"))?;
    if !orderbook_current_memory::owner_literal_matches_for_current(
        &record.owner,
        &order.owner_account,
        &mut current,
    )? || order.order_id != record.order_id
    {
        return Err(corrupt_state(
            "stored order payload does not match authoritative order metadata",
        ));
    }
    match (
        &order.side,
        &record.bid_escrow,
        record.provider_id,
        order.provider_id,
    ) {
        (OrderSideV1::Bid, Some(binding), None, None)
            if binding.escrow_id == orderbook_order_escrow_id(order.order_id)
                && !binding.initial_xor_locked.is_zero() => {}
        (OrderSideV1::Ask, None, Some(provider_id), Some(signed_provider_id))
            if provider_id.as_bytes() == &signed_provider_id => {}
        _ => {
            return Err(corrupt_state(
                "stored orderbook custody/provider binding does not match its signed order",
            ));
        }
    }
    let no_cancel = record.canonical_cancel.is_none()
        && record.cancelled_at_unix.is_none()
        && record.cancelled_policy_digest.is_none();
    let lifecycle_is_consistent = match record.status {
        OrderbookOrderStatusV1::Open => no_cancel && record.remaining_gib == order.quantity_gib,
        OrderbookOrderStatusV1::PartiallyFilled => {
            no_cancel && record.remaining_gib > 0 && record.remaining_gib < order.quantity_gib
        }
        OrderbookOrderStatusV1::Filled => no_cancel && record.remaining_gib == 0,
        OrderbookOrderStatusV1::Cancelled => {
            record.remaining_gib > 0
                && record.remaining_gib <= order.quantity_gib
                && record.canonical_cancel.is_some()
                && record.cancelled_at_unix.is_some()
                && record
                    .cancelled_policy_digest
                    .is_some_and(|digest| digest != [0; 32])
        }
        OrderbookOrderStatusV1::Expired => {
            no_cancel
                && record.remaining_gib > 0
                && record.remaining_gib <= order.quantity_gib
                && record.updated_at_unix >= order.expiry_unix
        }
        OrderbookOrderStatusV1::ProviderRevoked => {
            no_cancel
                && order.side == OrderSideV1::Ask
                && record.remaining_gib > 0
                && record.remaining_gib <= order.quantity_gib
        }
    };
    if !lifecycle_is_consistent {
        return Err(corrupt_state(
            "stored orderbook order lifecycle state is inconsistent",
        ));
    }
    let order_nonce = order.nonce;
    drop(order);
    current = OrderbookQueryCurrent::new(record_resident_bytes)
        .map_err(InstructionExecutionError::Query)?;
    if let Some(canonical_cancel) = record.canonical_cancel.as_ref() {
        let cancel = decode_orderbook_payload_for_current(
            canonical_cancel,
            &mut current,
            decode_order_cancel_v1_with_limits,
            |error| corrupt_state(format!("invalid stored cancellation: {error}")),
        )?;
        verify_order_cancel_signature_v1(&cancel).map_err(|error| {
            corrupt_state(format!("invalid stored cancellation signature: {error}"))
        })?;
        ensure_payload_signer(&record.owner, &cancel.signature).map_err(|error| {
            corrupt_state(format!(
                "stored cancellation signer does not match its authoritative owner: {error}"
            ))
        })?;
        core::str::from_utf8(&cancel.owner_account)
            .map_err(|_| corrupt_state("stored cancellation owner is not UTF-8"))?;
        if !orderbook_current_memory::owner_literal_matches_for_current(
            &record.owner,
            &cancel.owner_account,
            &mut current,
        )? || cancel.order_id != record.order_id
            || cancel.nonce <= order_nonce
            || record
                .cancelled_at_unix
                .is_none_or(|cancelled_at| cancelled_at < record.admitted_at_unix)
        {
            return Err(corrupt_state(
                "stored cancellation does not match authoritative order metadata",
            ));
        }
    }
    Ok(Some(record))
}
fn validate_order_policy(
    order: &OrderRequestV1,
    policy: &OrderbookAdmissionPolicyRecord,
    now: u64,
) -> Result<(), InstructionExecutionError> {
    if policy.policy.paused {
        return Err(invalid_parameter(
            "new SoraFS orderbook submissions are paused by governance",
        ));
    }
    if order.remaining_gib != order.quantity_gib {
        return Err(invalid_parameter(
            "new order submission must start with remaining_gib equal to quantity_gib",
        ));
    }
    if order.quantity_gib < policy.policy.min_order_gib
        || order.quantity_gib > policy.policy.max_order_gib
    {
        return Err(invalid_parameter(format!(
            "order quantity {} is outside governed bounds {}..={} GiB",
            order.quantity_gib, policy.policy.min_order_gib, policy.policy.max_order_gib
        )));
    }
    let price_tick = XorQuantity::try_from_micro(u128::from(policy.policy.price_tick_micro_xor))
        .map_err(|error| {
            invalid_parameter(format!("invalid governed order price tick: {error}"))
        })?;
    let price_is_aligned = order
        .price_per_gib
        .as_quantity()
        .try_div_decimal_exact(price_tick.as_quantity().as_numeric())
        .is_ok_and(|quotient| quotient.scale() == 0);
    if !price_is_aligned {
        return Err(invalid_parameter(format!(
            "order price {} is not aligned to governed tick {} micro-XOR",
            order.price_per_gib, policy.policy.price_tick_micro_xor
        )));
    }
    if order.maker_fee_bps > policy.policy.max_maker_fee_bps
        || order.taker_fee_bps > policy.policy.max_taker_fee_bps
    {
        return Err(invalid_parameter(
            "order maker or taker fee exceeds the active governance policy",
        ));
    }
    let lifetime = order
        .expiry_unix
        .checked_sub(now)
        .filter(|lifetime| *lifetime > 0)
        .ok_or_else(|| invalid_parameter("order is expired at ledger admission"))?;
    if lifetime > policy.policy.max_order_lifetime_secs {
        return Err(invalid_parameter(format!(
            "order lifetime {lifetime} seconds exceeds governed maximum {}",
            policy.policy.max_order_lifetime_secs
        )));
    }
    Ok(())
}
fn provider_binding_is_current(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    owner: &AccountId,
) -> bool {
    world
        .provider_owners()
        .get(&provider_id)
        .is_some_and(|registered| registered.subject_id() == owner.subject_id())
}
fn provider_advert_is_eligible(
    world: &impl WorldReadOnly,
    provider_id: ProviderId,
    owner: &AccountId,
) -> bool {
    provider_binding_is_current(world, provider_id, owner)
        && matches!(
            super::sorafs_reserve::read_provider(world, provider_id),
            Ok(Some(account))
                if account.terms.provider_account.subject_id() == owner.subject_id()
                    && account.lifecycle_stage != ReserveLifecycleStage::Default
        )
}
fn read_trade(
    world: &impl WorldReadOnly,
    trade_id: [u8; 32],
) -> Result<Option<OrderbookTradeRecord>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    read_trade_with_current(world, trade_id, &mut current)
}
fn read_trade_with_current(
    world: &impl WorldReadOnly,
    trade_id: [u8; 32],
    current: &mut OrderbookQueryCurrent,
) -> Result<Option<OrderbookTradeRecord>, InstructionExecutionError> {
    let key = trade_key(trade_id);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: OrderbookTradeRecord = decode_state_for_current(bytes, "orderbook trade", current)?;
    let record_resident_bytes = current.resident_bytes();
    if record.trade_id != trade_id
        || record.trade_id == [0; 32]
        || record.maker_order_id == [0; 32]
        || record.taker_order_id == [0; 32]
        || record.maker_order_id == record.taker_order_id
        || record.trade_sequence == 0
        || record.channel_id == [0; 32]
        || record.book_revision == 0
        || record.recorded_at_unix == 0
    {
        return Err(corrupt_state("stored orderbook trade metadata is invalid"));
    }
    let trade = decode_orderbook_payload_for_current(
        &record.canonical_trade,
        current,
        decode_trade_event_v1_with_limits,
        |error| corrupt_state(format!("invalid stored orderbook trade: {error}")),
    )?;
    trade
        .validate()
        .map_err(|error| corrupt_state(format!("invalid stored orderbook trade: {error}")))?;
    let expected_channel = derive_orderbook_settlement_channel_id_v1(&trade).map_err(|error| {
        corrupt_state(format!("failed to derive stored trade channel: {error}"))
    })?;
    if trade.trade_id != record.trade_id
        || trade.maker_order_id != record.maker_order_id
        || trade.taker_order_id != record.taker_order_id
        || expected_channel != record.channel_id
        || trade.timestamp_unix != record.recorded_at_unix
    {
        return Err(corrupt_state(
            "stored orderbook trade payload does not match authoritative metadata",
        ));
    }
    drop(trade);
    *current = OrderbookQueryCurrent::new(record_resident_bytes)
        .map_err(InstructionExecutionError::Query)?;
    Ok(Some(record))
}
fn read_channel(
    world: &impl WorldReadOnly,
    channel_id: [u8; 32],
) -> Result<Option<OrderbookSettlementChannelRecord>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let key = channel_key(channel_id);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let record: OrderbookSettlementChannelRecord =
        decode_state_for_current(bytes, "orderbook settlement channel", &mut current)?;
    let lifecycle_is_consistent = match record.status {
        OrderbookSettlementChannelStatusV1::Open => {
            record.remaining_bytes > 0 && !record.remaining_xor_locked.is_zero()
        }
        OrderbookSettlementChannelStatusV1::Closed => {
            record.remaining_bytes == 0
                && record.remaining_xor_locked.is_zero()
                && record.remaining_fee_xor_locked.is_zero()
        }
        OrderbookSettlementChannelStatusV1::Expired => {
            record.remaining_bytes > 0
                && record.remaining_xor_locked.is_zero()
                && record.remaining_fee_xor_locked.is_zero()
        }
    };
    if record.channel_id != channel_id
        || record.channel_id == [0; 32]
        || record.trade_id == [0; 32]
        || record.total_bytes == 0
        || record.remaining_bytes > record.total_bytes
        || record.initial_xor_locked.is_zero()
        || record.remaining_xor_locked > record.initial_xor_locked
        || record.initial_fee_xor_locked > record.initial_xor_locked
        || record.remaining_fee_xor_locked > record.initial_fee_xor_locked
        || record.remaining_fee_xor_locked > record.remaining_xor_locked
        || record.opened_at_unix == 0
        || record.expires_at_unix <= record.opened_at_unix
        || record.updated_at_unix < record.opened_at_unix
        || !lifecycle_is_consistent
    {
        return Err(corrupt_state(
            "stored orderbook settlement channel is inconsistent",
        ));
    }
    let trade = read_trade_with_current(world, record.trade_id, &mut current)?
        .ok_or_else(|| corrupt_state("stored orderbook channel references a missing trade"))?;
    if trade.channel_id != record.channel_id {
        return Err(corrupt_state(
            "stored orderbook channel does not match its trade",
        ));
    }
    let trade_payload = decode_orderbook_payload_for_current(
        &trade.canonical_trade,
        &mut current,
        decode_trade_event_v1_with_limits,
        |error| {
            corrupt_state(format!(
                "invalid stored orderbook channel trade payload: {error}"
            ))
        },
    )?;
    let expected_total_bytes = trade_payload
        .filled_gib
        .checked_mul(BYTES_PER_GIB)
        .ok_or_else(|| corrupt_state("stored orderbook channel byte capacity overflow"))?;
    let expected_initial = trade_escrow_requirement_v1(&trade_payload).map_err(|error| {
        corrupt_state(format!(
            "failed to derive stored channel custody from its trade: {error}"
        ))
    })?;
    let expected_fee = trade_fee_requirement_v1(&trade_payload).map_err(|error| {
        corrupt_state(format!(
            "failed to derive stored channel fee custody from its trade: {error}"
        ))
    })?;
    if record.total_bytes != expected_total_bytes
        || record.initial_xor_locked != expected_initial
        || record.initial_fee_xor_locked != expected_fee
    {
        return Err(corrupt_state(
            "stored orderbook channel economics do not match its immutable trade",
        ));
    }
    drop(trade_payload);
    drop(trade);
    Ok(Some(record))
}
fn read_receipt(
    world: &impl WorldReadOnly,
    receipt_id: [u8; 32],
) -> Result<Option<OrderbookSettlementReceiptRecord>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let key = receipt_key(receipt_id);
    let decode_record = |current: &mut OrderbookQueryCurrent| {
        let Some(bytes) = world.smart_contract_state().get(&key) else {
            return Ok(None);
        };
        decode_state_for_current(bytes, "orderbook settlement receipt", current).map(Some)
    };
    let Some(record): Option<OrderbookSettlementReceiptRecord> = decode_record(&mut current)?
    else {
        return Ok(None);
    };
    if record.receipt_id != receipt_id
        || record.receipt_id == [0; 32]
        || record.channel_id == [0; 32]
        || record.trade_id == [0; 32]
        || record.admitted_policy_digest == [0; 32]
        || record.admitted_at_unix == 0
    {
        return Err(corrupt_state(
            "stored orderbook settlement receipt metadata is invalid",
        ));
    }
    let receipt = decode_orderbook_payload_for_current(
        &record.canonical_receipt,
        &mut current,
        decode_settlement_receipt_v1_with_limits,
        |error| corrupt_state(format!("invalid stored settlement receipt: {error}")),
    )?;
    verify_settlement_receipt_signature_v1(&receipt).map_err(|error| {
        corrupt_state(format!(
            "invalid stored settlement receipt signature: {error}"
        ))
    })?;
    if receipt.receipt_id != record.receipt_id
        || receipt.channel_id != record.channel_id
        || receipt.trade_id != record.trade_id
    {
        return Err(corrupt_state(
            "stored settlement receipt payload does not match authoritative metadata",
        ));
    }
    let channel_id = record.channel_id;
    let trade_id = record.trade_id;
    let receipt_range = receipt.range;
    let receipt_issued_at_unix = receipt.issued_at_unix;
    let signer_public_key: [u8; 32] = receipt
        .settlement_signature
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_state("stored settlement receipt signer key is not Ed25519-sized"))?;
    // Only compact, protocol-fixed receipt facts are needed by the related-state
    // checks below. Release both decoded source values before reading a channel
    // or its potentially large receipt index.
    drop(receipt);
    drop(record);
    current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let channel = read_channel(world, channel_id)?
        .ok_or_else(|| corrupt_state("stored settlement receipt references a missing channel"))?;
    let provider_key = channel.provider.try_signatory().ok_or_else(|| {
        corrupt_state("stored settlement channel provider is not a single-signatory account")
    })?;
    let (provider_algorithm, provider_public_key) = provider_key
        .try_to_bytes()
        .map_err(|error| corrupt_state(format!("invalid channel provider public key: {error}")))?;
    if provider_algorithm != Algorithm::Ed25519
        || provider_public_key != signer_public_key.as_slice()
    {
        return Err(corrupt_state(
            "stored settlement signer does not match its channel provider",
        ));
    }
    drop(channel);
    let index = read_receipt_index(world, channel_id)?.ok_or_else(|| {
        corrupt_state("stored settlement receipt has no authoritative channel index")
    })?;
    let indexed_range = index
        .ranges
        .iter()
        .find(|range| range.receipt_id == receipt_id)
        .copied()
        .ok_or_else(|| {
            corrupt_state("stored settlement receipt is absent from its channel index")
        })?;
    if index.trade_id != trade_id
        || indexed_range.start != receipt_range.start
        || indexed_range.end != receipt_range.end
        || indexed_range.issued_at_unix != receipt_issued_at_unix
    {
        return Err(corrupt_state(
            "stored settlement receipt does not match its channel index",
        ));
    }
    drop(index);
    let record = decode_record(&mut current)?.ok_or_else(|| {
        corrupt_state("stored settlement receipt disappeared during its immutable read")
    })?;
    Ok(Some(record))
}
fn validate_receipt_index(
    index: &OrderbookSettlementIndexRecord,
    channel_id: [u8; 32],
) -> Result<(), InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    validate_receipt_index_with_current(index, channel_id, &mut current)
}
fn validate_receipt_index_with_current(
    index: &OrderbookSettlementIndexRecord,
    channel_id: [u8; 32],
    current: &mut OrderbookQueryCurrent,
) -> Result<(), InstructionExecutionError> {
    if index.channel_id != channel_id
        || index.channel_id == [0; 32]
        || index.trade_id == [0; 32]
        || index.ranges.is_empty()
        || index.ranges.len() > ORDERBOOK_MAX_RECEIPTS_PER_CHANNEL_V1 as usize
    {
        return Err(corrupt_state(
            "stored orderbook receipt index header is invalid",
        ));
    }
    let mut receipt_ids = current
        .vec_with_capacity::<[u8; 32]>(index.ranges.len())
        .map_err(InstructionExecutionError::Query)?;
    let mut previous: Option<&OrderbookSettlementRangeRecord> = None;
    for range in &index.ranges {
        if range.receipt_id == [0; 32]
            || range.start >= range.end
            || range.issued_at_unix == 0
            || previous.is_some_and(|prior| {
                (prior.start, prior.end, prior.receipt_id)
                    >= (range.start, range.end, range.receipt_id)
                    || prior.end > range.start
            })
        {
            return Err(corrupt_state(
                "stored orderbook receipt index is unsorted, overlapping, or malformed",
            ));
        }
        receipt_ids
            .push(range.receipt_id)
            .map_err(InstructionExecutionError::Query)?;
        previous = Some(range);
    }
    let mut receipt_ids = receipt_ids.into_vec();
    receipt_ids.sort_unstable();
    if receipt_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(corrupt_state(
            "stored orderbook receipt index is unsorted, overlapping, or malformed",
        ));
    }
    Ok(())
}
fn read_receipt_index(
    world: &impl WorldReadOnly,
    channel_id: [u8; 32],
) -> Result<Option<OrderbookSettlementIndexRecord>, InstructionExecutionError> {
    let mut current = OrderbookQueryCurrent::new(0).map_err(InstructionExecutionError::Query)?;
    let key = receipt_index_key(channel_id);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let index: OrderbookSettlementIndexRecord =
        decode_state_for_current(bytes, "orderbook settlement receipt index", &mut current)?;
    validate_receipt_index_with_current(&index, channel_id, &mut current)?;
    Ok(Some(index))
}
#[derive(Clone)]
struct WorkingLedgerOrder {
    record: OrderbookOrderRecord,
    order: OrderRequestV1,
}
struct PlannedFill {
    trade: TradeEventV1,
    trade_record: OrderbookTradeRecord,
    channel: OrderbookSettlementChannelRecord,
    bid_order_id: [u8; 32],
    escrow_amount: Quantity,
}
fn load_active_orders(
    world: &impl WorldReadOnly,
) -> Result<Vec<WorkingLedgerOrder>, InstructionExecutionError> {
    let start = StatePath::from_str(ORDER_STATE_KEY_PREFIX).expect("static state prefix is valid");
    let mut active = Vec::new();
    let mut sequences = BTreeSet::new();
    for (key, payload) in world.smart_contract_state().range(start..) {
        if !key.to_string().starts_with(ORDER_STATE_KEY_PREFIX) {
            break;
        }
        let candidate: OrderbookOrderRecord = decode_state(payload, "orderbook order")?;
        if order_key(candidate.order_id) != *key {
            return Err(corrupt_state(
                "authoritative orderbook order key does not match its record",
            ));
        }
        let record = read_order(world, candidate.order_id)?.ok_or_else(|| {
            corrupt_state("authoritative orderbook order disappeared during matching read")
        })?;
        if !matches!(
            record.status,
            OrderbookOrderStatusV1::Open | OrderbookOrderStatusV1::PartiallyFilled
        ) {
            continue;
        }
        if !sequences.insert(record.admission_sequence) {
            return Err(corrupt_state(
                "authoritative orderbook contains duplicate admission sequences",
            ));
        }
        let mut order = decode_orderbook_payload(
            &record.canonical_order,
            decode_order_request_v1_with_limits,
            |error| corrupt_state(format!("invalid stored order: {error}")),
        )?;
        order.remaining_gib = record.remaining_gib;
        active.push(WorkingLedgerOrder { record, order });
        if active.len() > ORDERBOOK_MAX_OPEN_ORDERS_V1 as usize {
            return Err(corrupt_state(
                "authoritative orderbook exceeds its open-order ceiling",
            ));
        }
    }
    Ok(active)
}
fn best_crossing_pair(
    orders: &[WorkingLedgerOrder],
    excluded_order_ids: &BTreeSet<[u8; 32]>,
    now: u64,
) -> Option<(usize, usize)> {
    best_crossing_pair_with_work(
        orders,
        excluded_order_ids,
        now,
        &mut MatchCandidateWorkV1::default(),
    )
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MatchCandidateWorkV1 {
    order_filter_visits: usize,
    bid_sort_comparisons: usize,
    ask_sort_comparisons: usize,
    alternative_ask_visits: usize,
    bid_candidate_visits: usize,
}
fn best_crossing_pair_with_work(
    orders: &[WorkingLedgerOrder],
    excluded_order_ids: &BTreeSet<[u8; 32]>,
    now: u64,
    work: &mut MatchCandidateWorkV1,
) -> Option<(usize, usize)> {
    for tier in [OrderTierV1::Hot, OrderTierV1::Warm, OrderTierV1::Archive] {
        let mut bids = Vec::new();
        let mut asks = Vec::new();
        for (index, entry) in orders.iter().enumerate() {
            work.order_filter_visits = work.order_filter_visits.saturating_add(1);
            if entry.order.tier != tier
                || now >= entry.order.expiry_unix
                || entry.record.remaining_gib == 0
                || excluded_order_ids.contains(&entry.record.order_id)
            {
                continue;
            }
            match entry.order.side {
                OrderSideV1::Bid => bids.push(index),
                OrderSideV1::Ask => asks.push(index),
            }
        }
        bids.sort_by(|lhs, rhs| {
            work.bid_sort_comparisons = work.bid_sort_comparisons.saturating_add(1);
            orders[*rhs]
                .order
                .price_per_gib
                .cmp(&orders[*lhs].order.price_per_gib)
                .then_with(|| {
                    orders[*lhs]
                        .record
                        .admission_sequence
                        .cmp(&orders[*rhs].record.admission_sequence)
                })
                .then_with(|| {
                    orders[*lhs]
                        .record
                        .order_id
                        .cmp(&orders[*rhs].record.order_id)
                })
        });
        asks.sort_by(|lhs, rhs| {
            work.ask_sort_comparisons = work.ask_sort_comparisons.saturating_add(1);
            orders[*lhs]
                .order
                .price_per_gib
                .cmp(&orders[*rhs].order.price_per_gib)
                .then_with(|| {
                    orders[*lhs]
                        .record
                        .admission_sequence
                        .cmp(&orders[*rhs].record.admission_sequence)
                })
                .then_with(|| {
                    orders[*lhs]
                        .record
                        .order_id
                        .cmp(&orders[*rhs].record.order_id)
                })
        });
        let Some(first_ask) = asks.first().copied() else {
            continue;
        };
        let first_ask_owner = orders[first_ask].record.owner.subject_id();
        let alternative_ask = asks.iter().copied().skip(1).find(|ask| {
            work.alternative_ask_visits = work.alternative_ask_visits.saturating_add(1);
            orders[*ask].record.owner.subject_id() != first_ask_owner
        });
        for bid in bids {
            work.bid_candidate_visits = work.bid_candidate_visits.saturating_add(1);
            if orders[bid].order.price_per_gib < orders[first_ask].order.price_per_gib {
                // Bids are descending and the first ask is the global minimum,
                // so this proves no later bid can cross in this tier.
                break;
            }
            let ask = if orders[bid].record.owner.subject_id() == first_ask_owner {
                let Some(alternative_ask) = alternative_ask else {
                    continue;
                };
                alternative_ask
            } else {
                first_ask
            };
            if orders[bid].order.price_per_gib >= orders[ask].order.price_per_gib {
                return Some((bid, ask));
            }
        }
    }
    None
}
fn transition_filled_order(
    entry: &mut WorkingLedgerOrder,
    remaining_gib: u64,
    now: u64,
    status: &mut OrderbookLedgerStatusV1,
) -> Result<(), InstructionExecutionError> {
    match entry.record.status {
        OrderbookOrderStatusV1::Open => {
            status.open_orders = status
                .open_orders
                .checked_sub(1)
                .ok_or_else(|| corrupt_state("orderbook open-order counter underflow"))?;
        }
        OrderbookOrderStatusV1::PartiallyFilled => {
            status.partially_filled_orders = status
                .partially_filled_orders
                .checked_sub(1)
                .ok_or_else(|| corrupt_state("orderbook partial-order counter underflow"))?;
        }
        _ => {
            return Err(corrupt_state(
                "non-active order selected for authoritative fill",
            ));
        }
    }
    entry.order.remaining_gib = remaining_gib;
    entry.record.remaining_gib = remaining_gib;
    entry.record.updated_at_unix = now;
    if remaining_gib == 0 {
        entry.record.status = OrderbookOrderStatusV1::Filled;
        status.filled_orders = status
            .filled_orders
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook filled-order counter overflow"))?;
    } else {
        entry.record.status = OrderbookOrderStatusV1::PartiallyFilled;
        status.partially_filled_orders = status
            .partially_filled_orders
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook partial-order counter overflow"))?;
    }
    Ok(())
}
fn validate_fill_custody(
    state_transaction: &StateTransaction<'_, '_>,
    orders: &[WorkingLedgerOrder],
    fills: &[PlannedFill],
) -> Result<(), InstructionExecutionError> {
    let mut totals = BTreeMap::<iroha_data_model::escrow::EscrowId, Quantity>::new();
    for fill in fills {
        let parent_id = orderbook_order_escrow_id(fill.bid_order_id);
        let child_id = orderbook_settlement_escrow_id(fill.channel.channel_id);
        if state_transaction
            .world
            .asset_escrows
            .get(&child_id)
            .is_some()
        {
            return Err(corrupt_state(
                "derived orderbook settlement channel custody already exists",
            ));
        }
        if super::escrow::is_orderbook_channel_lock(state_transaction.world(), &child_id)? {
            return Err(corrupt_state(
                "derived orderbook settlement channel custody marker already exists",
            ));
        }
        if super::escrow::is_orderbook_order_lock(state_transaction.world(), &child_id)? {
            return Err(corrupt_state(
                "derived orderbook settlement channel id already marks order custody",
            ));
        }
        let bid = orders
            .iter()
            .find(|entry| entry.record.order_id == fill.bid_order_id)
            .ok_or_else(|| corrupt_state("planned fill bid disappeared from active orders"))?;
        let binding = bid
            .record
            .bid_escrow
            .as_ref()
            .ok_or_else(|| corrupt_state("planned fill bid has no custody binding"))?;
        let expires_at_ms = bid
            .order
            .expiry_unix
            .checked_mul(1_000)
            .ok_or_else(|| corrupt_state("bid order custody expiry overflow"))?;
        super::escrow::validate_active_orderbook_order_asset_lock(
            state_transaction,
            &parent_id,
            &bid.record.owner,
            &binding.asset_definition,
            &binding.initial_xor_locked.clone().into_quantity(),
            expires_at_ms,
        )
        .map_err(|error| {
            corrupt_state(format!(
                "bid order {} custody invariant failed: {error}",
                hex::encode(fill.bid_order_id)
            ))
        })?;
        let total = totals.entry(parent_id).or_insert_with(Quantity::zero);
        *total = total
            .checked_add(&fill.escrow_amount)
            .map_err(|_| invalid_parameter("aggregate orderbook channel custody overflow"))?;
    }
    for (parent_id, total) in totals {
        let parent = state_transaction
            .world
            .asset_escrows
            .get(&parent_id)
            .ok_or_else(|| corrupt_state("validated bid order custody disappeared"))?;
        if total > parent.remaining_amount {
            return Err(corrupt_state(
                "deterministic fills exceed authoritative remaining bid custody",
            ));
        }
    }
    Ok(())
}
fn validate_active_order_bindings(
    state_transaction: &StateTransaction<'_, '_>,
    orders: &[WorkingLedgerOrder],
) -> Result<(), InstructionExecutionError> {
    for entry in orders {
        match entry.order.side {
            OrderSideV1::Bid => {
                let binding = entry
                    .record
                    .bid_escrow
                    .as_ref()
                    .ok_or_else(|| corrupt_state("active bid has no custody binding"))?;
                let expires_at_ms = entry
                    .order
                    .expiry_unix
                    .checked_mul(1_000)
                    .ok_or_else(|| corrupt_state("bid order custody expiry overflow"))?;
                super::escrow::validate_active_orderbook_order_asset_lock(
                    state_transaction,
                    &binding.escrow_id,
                    &entry.record.owner,
                    &binding.asset_definition,
                    &binding.initial_xor_locked.clone().into_quantity(),
                    expires_at_ms,
                )
                .map_err(|error| {
                    corrupt_state(format!(
                        "active bid {} custody invariant failed: {error}",
                        hex::encode(entry.record.order_id)
                    ))
                })?;
            }
            OrderSideV1::Ask => {
                let provider_id = entry
                    .record
                    .provider_id
                    .ok_or_else(|| corrupt_state("active ask has no admitted provider binding"))?;
                if !provider_advert_is_eligible(
                    state_transaction.world(),
                    provider_id,
                    &entry.record.owner,
                ) {
                    return Err(invalid_parameter(format!(
                        "active ask {} provider binding is revoked; run orderbook maintenance",
                        hex::encode(entry.record.order_id)
                    )));
                }
            }
        }
    }
    Ok(())
}
impl Execute for SetSorafsOrderbookPolicy {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        require_permission(state_transaction, authority, "CanSetSorafsPricing")?;
        self.policy.validate().map_err(|error| {
            invalid_parameter(format!("invalid SoraFS orderbook policy: {error}"))
        })?;
        let now = block_time_unix(state_transaction)?;
        let digest = self.policy.digest().map_err(|error| {
            invalid_parameter(format!("failed to digest orderbook policy: {error}"))
        })?;
        let current_policy = read_policy(state_transaction.world())?;
        let initial_status = match current_policy.as_ref() {
            None => {
                if self.policy.revision != 1 || self.policy.predecessor_policy_digest.is_some() {
                    return Err(invalid_parameter(
                        "first orderbook policy must be revision one without a predecessor",
                    ));
                }
                if read_status(state_transaction.world())?.is_some() {
                    return Err(corrupt_state(
                        "orderbook ledger status exists without an active policy",
                    ));
                }
                Some(OrderbookLedgerStatusV1 {
                    open_orders: 0,
                    partially_filled_orders: 0,
                    filled_orders: 0,
                    cancelled_orders: 0,
                    expired_orders: 0,
                    provider_revoked_orders: 0,
                    trades: 0,
                    settlement_receipts: 0,
                    settlement_channels: 0,
                    open_settlement_channels: 0,
                    book_revision: 0,
                    last_match_scan_book_revision: 0,
                    next_admission_sequence: 1,
                    next_trade_sequence: 1,
                    updated_at_unix: now,
                })
            }
            Some(current) => {
                active_status(state_transaction, now)?;
                let expected_revision =
                    current.policy.revision.checked_add(1).ok_or_else(|| {
                        corrupt_state("stored orderbook policy revision overflowed")
                    })?;
                if self.policy.revision != expected_revision {
                    return Err(invalid_parameter(format!(
                        "orderbook policy revision {} must exactly follow active revision {}",
                        self.policy.revision, current.policy.revision
                    )));
                }
                if self.policy.predecessor_policy_digest != Some(current.policy_digest) {
                    return Err(invalid_parameter(
                        "orderbook policy predecessor does not match the active policy digest",
                    ));
                }
                if self.policy.market_id != current.policy.market_id {
                    return Err(invalid_parameter(
                        "orderbook market id is immutable after first activation",
                    ));
                }
                None
            }
        };
        let record = OrderbookAdmissionPolicyRecord {
            policy: self.policy,
            policy_digest: digest,
            activated_at_unix: now,
            activated_by: authority.clone(),
        };
        let book_revision = match initial_status.as_ref() {
            Some(status) => status.book_revision,
            None => active_status(state_transaction, now)?.book_revision,
        };
        let encoded = encode_state(&record, "orderbook policy")?;
        let encoded_status = initial_status.as_ref().map(encode_status).transpose()?;
        state_transaction
            .world
            .smart_contract_state
            .insert(policy_key().clone(), encoded);
        if let Some(encoded_status) = encoded_status {
            state_transaction
                .world
                .smart_contract_state
                .insert(status_key().clone(), encoded_status);
        }
        emit_orderbook_event(
            state_transaction,
            SorafsOrderbookLedgerEventKind::PolicyActivated,
            None,
            None,
            None,
            None,
            None,
            book_revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for SubmitSorafsOrderbookOrder {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let order = decode_orderbook_payload(
            &self.order_payload,
            decode_order_request_v1_with_limits,
            |error| {
                invalid_parameter(format!(
                    "invalid canonical orderbook order payload: {error}"
                ))
            },
        )?;
        verify_order_request_signature_v1(&order)
            .map_err(|error| invalid_parameter(format!("invalid order signature: {error}")))?;
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        validate_order_policy(&order, &policy, now)?;
        let owner = canonical_owner(&order.owner_account, authority)?;
        ensure_payload_signer(authority, &order.signature)?;
        let event_provider_id = order.provider_id.map(ProviderId::new);
        if let Some(provider_id) = event_provider_id {
            if !provider_binding_is_current(state_transaction.world(), provider_id, &owner) {
                return Err(invalid_parameter(format!(
                    "ask order exact provider binding {} is not registered to its owner",
                    hex::encode(provider_id.as_bytes())
                )));
            }
            let reserve_account =
                super::sorafs_reserve::read_provider(state_transaction.world(), provider_id)?
                    .ok_or_else(|| {
                        invalid_parameter(format!(
                            "ask order provider {} has no authoritative reserve account",
                            hex::encode(provider_id.as_bytes())
                        ))
                    })?;
            if reserve_account.terms.provider_account.subject_id() != owner.subject_id() {
                return Err(corrupt_state(
                    "ask order provider registry owner diverges from authoritative reserve account",
                ));
            }
            if reserve_account.lifecycle_stage == ReserveLifecycleStage::Default {
                return Err(invalid_parameter(format!(
                    "ask order provider {} is in reserve default and cannot advertise",
                    hex::encode(provider_id.as_bytes())
                )));
            }
        }
        let bid_escrow = if order.side == OrderSideV1::Bid {
            let escrow_id = orderbook_order_escrow_id(order.order_id);
            if super::escrow::is_orderbook_order_lock(state_transaction.world(), &escrow_id)
                .map_err(|error| {
                    corrupt_state(format!("failed to inspect bid custody marker: {error}"))
                })?
            {
                return Err(invalid_parameter(
                    "deterministic orderbook bid custody marker already exists",
                ));
            }
            let initial_xor_locked = bid_order_escrow_requirement_v1(
                &order,
                policy.policy.max_maker_fee_bps,
                policy.policy.max_taker_fee_bps,
            )
            .map_err(|error| {
                invalid_parameter(format!("failed to derive full bid custody: {error}"))
            })?;
            Some(OrderbookBidEscrowBindingV1 {
                escrow_id,
                asset_definition: state_transaction.gov.sorafs_pin_fee_asset_id.clone(),
                initial_xor_locked,
            })
        } else {
            None
        };
        if read_order(state_transaction.world(), order.order_id)?.is_some() {
            return Err(invalid_parameter(format!(
                "order {} is already recorded",
                hex::encode(order.order_id)
            )));
        }
        ensure_nonce_advances(state_transaction.world(), &owner, order.nonce)?;
        let mut status = active_status(state_transaction, now)?;
        if active_order_count(&status)? >= u64::from(ORDERBOOK_MAX_OPEN_ORDERS_V1) {
            return Err(invalid_parameter(format!(
                "authoritative orderbook reached its {} active-order ceiling",
                ORDERBOOK_MAX_OPEN_ORDERS_V1
            )));
        }
        let admission_sequence = status.next_admission_sequence;
        status.next_admission_sequence = status
            .next_admission_sequence
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook admission sequence overflow"))?;
        advance_book_revision(&mut status)?;
        status.open_orders = status
            .open_orders
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook open-order counter overflow"))?;
        status.updated_at_unix = now;
        let record = OrderbookOrderRecord {
            order_id: order.order_id,
            owner: owner.clone(),
            canonical_order: self.order_payload,
            admitted_policy_digest: policy.policy_digest,
            admitted_at_unix: now,
            admission_sequence,
            remaining_gib: order.quantity_gib,
            bid_escrow: bid_escrow.clone(),
            provider_id: event_provider_id,
            status: OrderbookOrderStatusV1::Open,
            updated_at_unix: now,
            canonical_cancel: None,
            cancelled_at_unix: None,
            cancelled_policy_digest: None,
        };
        let encoded = encode_state(&record, "orderbook order")?;
        let encoded_status = encode_status(&status)?;
        if let Some(binding) = bid_escrow {
            let expires_at_ms = order
                .expiry_unix
                .checked_mul(1_000)
                .ok_or_else(|| invalid_parameter("bid custody expiry overflow"))?;
            super::escrow::open_orderbook_order_asset_lock(
                state_transaction,
                binding.escrow_id.clone(),
                &owner,
                binding.asset_definition,
                binding.initial_xor_locked.clone().into_quantity(),
                expires_at_ms,
            )
            .map_err(|error| {
                invalid_parameter(format!("failed to fund atomic bid custody: {error}"))
            })?;
        }
        write_nonce(state_transaction, &owner, order.nonce)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(order_key(order.order_id), encoded);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_orderbook_event(
            state_transaction,
            SorafsOrderbookLedgerEventKind::OrderAdmitted,
            Some(order.order_id),
            None,
            None,
            None,
            event_provider_id,
            status.book_revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for CancelSorafsOrderbookOrder {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let cancel = decode_orderbook_payload(
            &self.cancel_payload,
            decode_order_cancel_v1_with_limits,
            |error| {
                invalid_parameter(format!(
                    "invalid canonical order cancellation payload: {error}"
                ))
            },
        )?;
        verify_order_cancel_signature_v1(&cancel).map_err(|error| {
            invalid_parameter(format!("invalid cancellation signature: {error}"))
        })?;
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        let owner = canonical_owner(&cancel.owner_account, authority)?;
        ensure_payload_signer(authority, &cancel.signature)?;
        let mut record =
            read_order(state_transaction.world(), cancel.order_id)?.ok_or_else(|| {
                invalid_parameter(format!("unknown order {}", hex::encode(cancel.order_id)))
            })?;
        if record.owner.subject_id() != owner.subject_id() {
            return Err(invalid_parameter(
                "order cancellation owner does not match stored order owner",
            ));
        }
        if !matches!(
            record.status,
            OrderbookOrderStatusV1::Open | OrderbookOrderStatusV1::PartiallyFilled
        ) {
            return Err(invalid_parameter("order is not cancellable"));
        }
        ensure_nonce_advances(state_transaction.world(), &owner, cancel.nonce)?;
        match cancel.reason {
            OrderCancelReasonV1::Expired => {
                return Err(invalid_parameter(
                    "expired orders must be retired by authoritative orderbook maintenance",
                ));
            }
            OrderCancelReasonV1::Governance
                if !has_permission(state_transaction, authority, "CanSetSorafsPricing") =>
            {
                return Err(invalid_parameter(
                    "governance cancellation reason requires CanSetSorafsPricing",
                ));
            }
            _ => {}
        }
        let mut status = active_status(state_transaction, now)?;
        match record.status {
            OrderbookOrderStatusV1::Open => {
                status.open_orders = status
                    .open_orders
                    .checked_sub(1)
                    .ok_or_else(|| corrupt_state("orderbook open-order counter underflow"))?;
            }
            OrderbookOrderStatusV1::PartiallyFilled => {
                status.partially_filled_orders = status
                    .partially_filled_orders
                    .checked_sub(1)
                    .ok_or_else(|| corrupt_state("orderbook partial-order counter underflow"))?;
            }
            _ => unreachable!("cancellable status checked above"),
        }
        status.cancelled_orders = status
            .cancelled_orders
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook cancelled-order counter overflow"))?;
        advance_book_revision(&mut status)?;
        status.updated_at_unix = now;
        record.status = OrderbookOrderStatusV1::Cancelled;
        record.updated_at_unix = now;
        record.canonical_cancel = Some(self.cancel_payload);
        record.cancelled_at_unix = Some(now);
        record.cancelled_policy_digest = Some(policy.policy_digest);
        let encoded = encode_state(&record, "orderbook order")?;
        let encoded_status = encode_status(&status)?;
        if let Some(binding) = record.bid_escrow.as_ref() {
            let signed_order = decode_orderbook_payload(
                &record.canonical_order,
                decode_order_request_v1_with_limits,
                |error| corrupt_state(format!("failed to decode cancellable stored bid: {error}")),
            )?;
            let expires_at_ms = signed_order
                .expiry_unix
                .checked_mul(1_000)
                .ok_or_else(|| corrupt_state("cancelled bid custody expiry overflow"))?;
            super::escrow::cancel_orderbook_order_asset_lock(
                state_transaction,
                &binding.escrow_id,
                &owner,
                &binding.asset_definition,
                &binding.initial_xor_locked.clone().into_quantity(),
                expires_at_ms,
            )
            .map_err(|error| {
                corrupt_state(format!("failed to refund cancelled bid custody: {error}"))
            })?;
        }
        write_nonce(state_transaction, &owner, cancel.nonce)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(order_key(cancel.order_id), encoded);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_orderbook_event(
            state_transaction,
            SorafsOrderbookLedgerEventKind::OrderCancelled,
            Some(cancel.order_id),
            None,
            None,
            None,
            None,
            status.book_revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
impl Execute for MatchSorafsOrderbook {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if !(1..=ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1).contains(&self.max_fills) {
            return Err(invalid_parameter(format!(
                "orderbook max_fills {} is outside 1..={ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1}",
                self.max_fills
            )));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_governed_orderbook_authority(
            authority,
            &policy.policy.matcher_authority,
            "matcher",
        )?;
        let mut status = active_status(state_transaction, now)?;
        if self.expected_book_revision != status.book_revision {
            return Err(invalid_parameter(format!(
                "orderbook revision conflict: expected {}, current {}",
                self.expected_book_revision, status.book_revision
            )));
        }
        if status.last_match_scan_book_revision == self.expected_book_revision {
            return Err(invalid_parameter(format!(
                "orderbook revision {} already has an exhaustive match scan",
                self.expected_book_revision
            )));
        }
        let planned_revision = status
            .book_revision
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook book revision overflow"))?;
        let mut orders = load_active_orders(state_transaction.world())?;
        if active_order_count(&status)? != orders.len() as u64 {
            return Err(corrupt_state(
                "orderbook active-order counters do not match authoritative records",
            ));
        }
        validate_active_order_bindings(state_transaction, &orders)?;
        let mut fills = Vec::new();
        let mut changed_orders = BTreeSet::new();
        let excluded_order_ids = BTreeSet::new();
        let mut reserved_custody = BTreeMap::<iroha_data_model::escrow::EscrowId, Quantity>::new();
        let mut scan_exhausted = false;
        while fills.len() < self.max_fills as usize {
            let Some((bid_index, ask_index)) =
                best_crossing_pair(&orders, &excluded_order_ids, now)
            else {
                scan_exhausted = true;
                break;
            };
            let bid_before = orders[bid_index].clone();
            let ask_before = orders[ask_index].clone();
            let maker_is_bid =
                bid_before.record.admission_sequence < ask_before.record.admission_sequence;
            let (maker, taker) = if maker_is_bid {
                (&bid_before.order, &ask_before.order)
            } else {
                (&ask_before.order, &bid_before.order)
            };
            let trade_sequence = status.next_trade_sequence;
            let trade_id = derive_orderbook_trade_id_v1(trade_sequence, maker, taker, now);
            if read_trade(state_transaction.world(), trade_id)?.is_some() {
                return Err(corrupt_state(
                    "derived authoritative orderbook trade id already exists",
                ));
            }
            let outcome = match_orders_v1(maker, taker, trade_id, now).map_err(|error| {
                corrupt_state(format!(
                    "validated authoritative orders failed deterministic matching: {error}"
                ))
            })?;
            let channel_id =
                derive_orderbook_settlement_channel_id_v1(&outcome.trade).map_err(|error| {
                    corrupt_state(format!("failed to derive settlement channel: {error}"))
                })?;
            if read_channel(state_transaction.world(), channel_id)?.is_some() {
                return Err(corrupt_state(
                    "derived authoritative settlement channel already exists",
                ));
            }
            let provider_id = ask_before
                .record
                .provider_id
                .ok_or_else(|| corrupt_state("matched ask has no admitted provider binding"))?;
            if !provider_advert_is_eligible(
                state_transaction.world(),
                provider_id,
                &ask_before.record.owner,
            ) {
                return Err(invalid_parameter(format!(
                    "matched ask {} provider binding is revoked; run orderbook maintenance",
                    hex::encode(ask_before.record.order_id)
                )));
            }
            let total_bytes = outcome
                .trade
                .filled_gib
                .checked_mul(BYTES_PER_GIB)
                .ok_or_else(|| invalid_parameter("orderbook channel byte count overflow"))?;
            let escrow = trade_escrow_requirement_v1(&outcome.trade).map_err(|error| {
                invalid_parameter(format!(
                    "invalid orderbook trade escrow requirement: {error}"
                ))
            })?;
            let fee_escrow = trade_fee_requirement_v1(&outcome.trade).map_err(|error| {
                invalid_parameter(format!("invalid orderbook trade fee requirement: {error}"))
            })?;
            let expires_at_unix = bid_before
                .order
                .expiry_unix
                .min(ask_before.order.expiry_unix);
            let expires_at_ms = expires_at_unix
                .checked_mul(1_000)
                .ok_or_else(|| invalid_parameter("orderbook channel expiry overflow"))?;
            if expires_at_ms <= state_transaction.block_unix_timestamp_ms() {
                return Err(corrupt_state(
                    "expired order selected for authoritative matching",
                ));
            }
            let escrow_amount = escrow.clone().into_quantity();
            let parent_id = orderbook_order_escrow_id(bid_before.record.order_id);
            let next_reserved = reserved_custody
                .get(&parent_id)
                .cloned()
                .unwrap_or_else(Quantity::zero)
                .checked_add(&escrow_amount)
                .map_err(|_| invalid_parameter("aggregate orderbook channel custody overflow"))?;
            let parent_remaining = state_transaction
                .world
                .asset_escrows
                .get(&parent_id)
                .map(|parent| parent.remaining_amount.clone())
                .ok_or_else(|| corrupt_state("validated bid custody disappeared during match"))?;
            if next_reserved > parent_remaining {
                return Err(corrupt_state(
                    "deterministic fills exceed conservative bid custody",
                ));
            }
            reserved_custody.insert(parent_id, next_reserved);
            let (bid_remaining, ask_remaining) = if maker_is_bid {
                (outcome.maker_remaining_gib, outcome.taker_remaining_gib)
            } else {
                (outcome.taker_remaining_gib, outcome.maker_remaining_gib)
            };
            if bid_index < ask_index {
                let (left, right) = orders.split_at_mut(ask_index);
                transition_filled_order(&mut left[bid_index], bid_remaining, now, &mut status)?;
                transition_filled_order(&mut right[0], ask_remaining, now, &mut status)?;
            } else {
                let (left, right) = orders.split_at_mut(bid_index);
                transition_filled_order(&mut right[0], bid_remaining, now, &mut status)?;
                transition_filled_order(&mut left[ask_index], ask_remaining, now, &mut status)?;
            }
            changed_orders.insert(bid_before.record.order_id);
            changed_orders.insert(ask_before.record.order_id);
            status.next_trade_sequence = status
                .next_trade_sequence
                .checked_add(1)
                .ok_or_else(|| corrupt_state("orderbook trade sequence overflow"))?;
            status.trades = status
                .trades
                .checked_add(1)
                .ok_or_else(|| corrupt_state("orderbook trade counter overflow"))?;
            status.settlement_channels = status
                .settlement_channels
                .checked_add(1)
                .ok_or_else(|| corrupt_state("orderbook channel counter overflow"))?;
            status.open_settlement_channels = status
                .open_settlement_channels
                .checked_add(1)
                .ok_or_else(|| corrupt_state("orderbook open-channel counter overflow"))?;
            if status.open_settlement_channels
                > u64::from(ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1)
            {
                return Err(invalid_parameter(
                    "orderbook open settlement-channel ceiling reached",
                ));
            }
            let canonical_trade = encode_state(&outcome.trade, "orderbook trade payload")?;
            let trade_record = OrderbookTradeRecord {
                trade_id: outcome.trade.trade_id,
                maker_order_id: outcome.trade.maker_order_id,
                taker_order_id: outcome.trade.taker_order_id,
                trade_sequence,
                canonical_trade,
                channel_id,
                book_revision: planned_revision,
                recorded_at_unix: now,
            };
            let channel = OrderbookSettlementChannelRecord {
                channel_id,
                trade_id: outcome.trade.trade_id,
                buyer: bid_before.record.owner.clone(),
                provider: ask_before.record.owner.clone(),
                provider_id,
                settlement_authority: policy.policy.settlement_authority.clone(),
                total_bytes,
                remaining_bytes: total_bytes,
                initial_xor_locked: escrow.clone(),
                remaining_xor_locked: escrow.clone(),
                initial_fee_xor_locked: fee_escrow.clone(),
                remaining_fee_xor_locked: fee_escrow,
                status: OrderbookSettlementChannelStatusV1::Open,
                opened_at_unix: now,
                expires_at_unix,
                updated_at_unix: now,
            };
            fills.push(PlannedFill {
                trade: outcome.trade,
                trade_record,
                channel,
                bid_order_id: bid_before.record.order_id,
                escrow_amount,
            });
        }
        if fills.is_empty() {
            if !scan_exhausted {
                return Err(corrupt_state(
                    "bounded orderbook matcher stopped without a fill or exhaustive scan",
                ));
            }
            status.last_match_scan_book_revision = status.book_revision;
            status.updated_at_unix = now;
            let encoded_status = encode_status(&status)?;
            state_transaction
                .world
                .smart_contract_state
                .insert(status_key().clone(), encoded_status);
            return Ok(());
        }
        status.book_revision = planned_revision;
        if scan_exhausted {
            status.last_match_scan_book_revision = planned_revision;
        }
        status.updated_at_unix = now;
        if active_order_count(&status)?
            != orders
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.record.status,
                        OrderbookOrderStatusV1::Open | OrderbookOrderStatusV1::PartiallyFilled
                    )
                })
                .count() as u64
        {
            return Err(corrupt_state(
                "deterministic fill transition produced inconsistent active counters",
            ));
        }
        validate_fill_custody(state_transaction, &orders, &fills)?;
        let mut encoded_records = Vec::new();
        for order_id in &changed_orders {
            let record = orders
                .iter()
                .find(|entry| &entry.record.order_id == order_id)
                .ok_or_else(|| corrupt_state("changed order disappeared from match plan"))?;
            encoded_records.push((
                order_key(*order_id),
                encode_state(&record.record, "orderbook order")?,
            ));
        }
        for fill in &fills {
            encoded_records.push((
                trade_key(fill.trade.trade_id),
                encode_state(&fill.trade_record, "orderbook trade")?,
            ));
            encoded_records.push((
                channel_key(fill.channel.channel_id),
                encode_state(&fill.channel, "orderbook settlement channel")?,
            ));
        }
        let encoded_status = encode_status(&status)?;
        for fill in &fills {
            super::escrow::partition_orderbook_asset_lock(
                state_transaction,
                &orderbook_order_escrow_id(fill.bid_order_id),
                orderbook_settlement_escrow_id(fill.channel.channel_id),
                fill.channel.provider.clone(),
                fill.channel.settlement_authority.clone(),
                fill.escrow_amount.clone(),
                fill.channel
                    .expires_at_unix
                    .checked_mul(1_000)
                    .ok_or_else(|| corrupt_state("encoded channel expiry overflow"))?,
            )
            .map_err(|error| {
                invalid_parameter(format!("orderbook custody partition failed: {error}"))
            })?;
        }
        for entry in orders.iter().filter(|entry| {
            entry.order.side == OrderSideV1::Bid
                && entry.record.status == OrderbookOrderStatusV1::Filled
                && changed_orders.contains(&entry.record.order_id)
        }) {
            let binding = entry
                .record
                .bid_escrow
                .as_ref()
                .ok_or_else(|| corrupt_state("filled bid has no custody binding"))?;
            let expires_at_ms = entry
                .order
                .expiry_unix
                .checked_mul(1_000)
                .ok_or_else(|| corrupt_state("filled bid custody expiry overflow"))?;
            super::escrow::close_filled_orderbook_order_asset_lock(
                state_transaction,
                &binding.escrow_id,
                &entry.record.owner,
                &binding.asset_definition,
                &binding.initial_xor_locked.clone().into_quantity(),
                expires_at_ms,
            )
            .map_err(|error| {
                corrupt_state(format!(
                    "failed to close filled bid {} custody: {error}",
                    hex::encode(entry.record.order_id)
                ))
            })?;
        }
        for (key, encoded) in encoded_records {
            state_transaction
                .world
                .smart_contract_state
                .insert(key, encoded);
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        for fill in &fills {
            emit_orderbook_event(
                state_transaction,
                SorafsOrderbookLedgerEventKind::TradeMatched,
                Some(fill.bid_order_id),
                Some(fill.trade.trade_id),
                Some(fill.channel.channel_id),
                None,
                Some(fill.channel.provider_id),
                status.book_revision,
                authority,
                now,
            )?;
        }
        Ok(())
    }
}
impl Execute for MaintainSorafsOrderbook {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        if !(1..=ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1).contains(&self.max_items) {
            return Err(invalid_parameter(format!(
                "orderbook maintenance max_items {} is outside 1..={ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1}",
                self.max_items
            )));
        }
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        require_governed_orderbook_authority(
            authority,
            &policy.policy.matcher_authority,
            "matcher",
        )?;
        let mut status = active_status(state_transaction, now)?;
        if self.expected_book_revision != status.book_revision {
            return Err(invalid_parameter(format!(
                "orderbook revision conflict: expected {}, current {}",
                self.expected_book_revision, status.book_revision
            )));
        }
        let mut remaining_budget = self.max_items as usize;
        let mut expired_orders = Vec::new();
        let mut provider_revoked_orders = Vec::new();
        for mut entry in load_active_orders(state_transaction.world())? {
            if remaining_budget == 0 {
                break;
            }
            let provider_revoked = entry.order.side == OrderSideV1::Ask
                && entry.record.provider_id.is_some_and(|provider_id| {
                    !provider_advert_is_eligible(
                        state_transaction.world(),
                        provider_id,
                        &entry.record.owner,
                    )
                });
            let expired = now >= entry.order.expiry_unix;
            if !provider_revoked && !expired {
                continue;
            }
            match entry.record.status {
                OrderbookOrderStatusV1::Open => {
                    status.open_orders = status
                        .open_orders
                        .checked_sub(1)
                        .ok_or_else(|| corrupt_state("orderbook open-order counter underflow"))?;
                }
                OrderbookOrderStatusV1::PartiallyFilled => {
                    status.partially_filled_orders = status
                        .partially_filled_orders
                        .checked_sub(1)
                        .ok_or_else(|| {
                            corrupt_state("orderbook partial-order counter underflow")
                        })?;
                }
                _ => unreachable!("active-order loader returned a terminal order"),
            }
            entry.record.updated_at_unix = now;
            if provider_revoked {
                status.provider_revoked_orders = status
                    .provider_revoked_orders
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("orderbook provider-revoked counter overflow"))?;
                entry.record.status = OrderbookOrderStatusV1::ProviderRevoked;
                provider_revoked_orders.push(entry.record);
            } else {
                status.expired_orders = status
                    .expired_orders
                    .checked_add(1)
                    .ok_or_else(|| corrupt_state("orderbook expired-order counter overflow"))?;
                entry.record.status = OrderbookOrderStatusV1::Expired;
                expired_orders.push(entry.record);
            }
            remaining_budget -= 1;
        }
        let channel_start =
            StatePath::from_str(CHANNEL_STATE_KEY_PREFIX).expect("static state prefix is valid");
        let mut expired_channels = Vec::new();
        if remaining_budget > 0 {
            for (key, payload) in state_transaction
                .world
                .smart_contract_state()
                .range(channel_start..)
            {
                if !key.to_string().starts_with(CHANNEL_STATE_KEY_PREFIX) {
                    break;
                }
                let candidate: OrderbookSettlementChannelRecord =
                    decode_state(payload, "orderbook settlement channel")?;
                let mut channel = read_channel(state_transaction.world(), candidate.channel_id)?
                    .ok_or_else(|| {
                        corrupt_state(
                            "authoritative settlement channel disappeared during maintenance",
                        )
                    })?;
                if channel_key(channel.channel_id) != *key
                    || channel.status != OrderbookSettlementChannelStatusV1::Open
                    || now < channel.expires_at_unix
                {
                    continue;
                }
                let escrow_id = orderbook_settlement_escrow_id(channel.channel_id);
                if !super::escrow::is_orderbook_channel_lock(state_transaction.world(), &escrow_id)?
                {
                    return Err(corrupt_state(
                        "expired settlement channel has no authoritative custody marker",
                    ));
                }
                let escrow = state_transaction
                    .world
                    .asset_escrows
                    .get(&escrow_id)
                    .ok_or_else(|| {
                        corrupt_state("expired settlement channel has no native custody")
                    })?;
                let expected_expiry_ms = channel
                    .expires_at_unix
                    .checked_mul(1_000)
                    .ok_or_else(|| corrupt_state("settlement channel custody expiry overflow"))?;
                let custody_matches = escrow.id == escrow_id
                    && escrow.asset_definition == state_transaction.gov.sorafs_pin_fee_asset_id
                    && escrow.seller.subject_id() == channel.buyer.subject_id()
                    && escrow
                        .buyer
                        .as_ref()
                        .is_some_and(|buyer| buyer.subject_id() == channel.provider.subject_id())
                    && escrow.release_authority.as_ref() == Some(&channel.settlement_authority)
                    && escrow.amount == channel.initial_xor_locked.clone().into_quantity()
                    && escrow.expires_at_ms == Some(expected_expiry_ms);
                if !custody_matches {
                    return Err(corrupt_state(
                        "expired settlement channel custody binding is inconsistent",
                    ));
                }
                if escrow.status != iroha_data_model::escrow::AssetEscrowStatus::Locked
                    || escrow.closed_at_ms.is_some()
                    || escrow.remaining_amount
                        != channel.remaining_xor_locked.clone().into_quantity()
                {
                    return Err(corrupt_state(
                        "expired settlement channel custody is not an active exact refund",
                    ));
                }
                channel.status = OrderbookSettlementChannelStatusV1::Expired;
                channel.remaining_xor_locked = XorQuantity::zero();
                channel.remaining_fee_xor_locked = XorQuantity::zero();
                channel.updated_at_unix = now;
                status.open_settlement_channels = status
                    .open_settlement_channels
                    .checked_sub(1)
                    .ok_or_else(|| corrupt_state("orderbook open-channel counter underflow"))?;
                expired_channels.push(channel);
                remaining_budget -= 1;
                if remaining_budget == 0 {
                    break;
                }
            }
        }
        if expired_orders.is_empty()
            && provider_revoked_orders.is_empty()
            && expired_channels.is_empty()
        {
            return Ok(());
        }
        advance_book_revision(&mut status)?;
        status.updated_at_unix = now;
        let mut encoded_records = Vec::with_capacity(
            expired_orders.len() + provider_revoked_orders.len() + expired_channels.len(),
        );
        for record in expired_orders.iter().chain(&provider_revoked_orders) {
            encoded_records.push((
                order_key(record.order_id),
                encode_state(record, "orderbook order")?,
            ));
        }
        for channel in &expired_channels {
            encoded_records.push((
                channel_key(channel.channel_id),
                encode_state(channel, "orderbook settlement channel")?,
            ));
        }
        let encoded_status = encode_status(&status)?;
        for record in &expired_orders {
            if let Some(binding) = record.bid_escrow.as_ref() {
                let signed_order = decode_orderbook_payload(
                    &record.canonical_order,
                    decode_order_request_v1_with_limits,
                    |error| corrupt_state(format!("failed to decode expiring stored bid: {error}")),
                )?;
                let expires_at_ms = signed_order
                    .expiry_unix
                    .checked_mul(1_000)
                    .ok_or_else(|| corrupt_state("expired bid custody expiry overflow"))?;
                super::escrow::expire_orderbook_order_asset_lock(
                    state_transaction,
                    &binding.escrow_id,
                    &record.owner,
                    &binding.asset_definition,
                    &binding.initial_xor_locked.clone().into_quantity(),
                    expires_at_ms,
                )
                .map_err(|error| {
                    corrupt_state(format!("failed to refund expired bid custody: {error}"))
                })?;
            }
        }
        for channel in &expired_channels {
            super::escrow::expire_orderbook_channel_asset_lock(
                state_transaction,
                &orderbook_settlement_escrow_id(channel.channel_id),
            )
            .map_err(|error| {
                corrupt_state(format!(
                    "failed to refund expired settlement custody: {error}"
                ))
            })?;
        }
        for (key, encoded) in encoded_records {
            state_transaction
                .world
                .smart_contract_state
                .insert(key, encoded);
        }
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        for record in &expired_orders {
            emit_orderbook_event(
                state_transaction,
                SorafsOrderbookLedgerEventKind::OrderExpired,
                Some(record.order_id),
                None,
                None,
                None,
                None,
                status.book_revision,
                authority,
                now,
            )?;
        }
        for record in &provider_revoked_orders {
            emit_orderbook_event(
                state_transaction,
                SorafsOrderbookLedgerEventKind::OrderProviderRevoked,
                Some(record.order_id),
                None,
                None,
                None,
                record.provider_id,
                status.book_revision,
                authority,
                now,
            )?;
        }
        for channel in &expired_channels {
            emit_orderbook_event(
                state_transaction,
                SorafsOrderbookLedgerEventKind::ChannelExpired,
                None,
                Some(channel.trade_id),
                Some(channel.channel_id),
                None,
                Some(channel.provider_id),
                status.book_revision,
                authority,
                now,
            )?;
        }
        Ok(())
    }
}
impl Execute for RecordSorafsOrderbookSettlementReceipt {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let receipt = decode_orderbook_payload(
            &self.receipt_payload,
            decode_settlement_receipt_v1_with_limits,
            |error| invalid_parameter(format!("invalid canonical settlement receipt: {error}")),
        )?;
        verify_settlement_receipt_signature_v1(&receipt).map_err(|error| {
            invalid_parameter(format!("invalid settlement receipt signature: {error}"))
        })?;
        let (policy, now) = active_policy(state_transaction, self.policy_digest)?;
        let mut channel = read_channel(state_transaction.world(), receipt.channel_id)?
            .ok_or_else(|| invalid_parameter("settlement receipt references an unknown channel"))?;
        // Receipt transactions are deliberately relayable. The provider
        // signature authorizes delivery, while the immutable channel authority
        // authorizes native custody release. Policy rotation only affects newly
        // opened channels; an existing channel retains its original release
        // authority until it closes or expires.
        if channel.status != OrderbookSettlementChannelStatusV1::Open {
            return Err(invalid_parameter("settlement receipt channel is not open"));
        }
        if receipt.trade_id != channel.trade_id {
            return Err(invalid_parameter(
                "settlement receipt trade does not match its authoritative channel",
            ));
        }
        if now >= channel.expires_at_unix || receipt.issued_at_unix >= channel.expires_at_unix {
            return Err(invalid_parameter("settlement receipt channel is expired"));
        }
        ensure_payload_signer(&channel.provider, &receipt.settlement_signature)?;
        if receipt.bytes_delivered > policy.policy.max_receipt_bytes {
            return Err(invalid_parameter(format!(
                "settlement receipt covers {} bytes; governed maximum is {}",
                receipt.bytes_delivered, policy.policy.max_receipt_bytes
            )));
        }
        if receipt.issued_at_unix > now {
            let skew = receipt.issued_at_unix - now;
            if skew > policy.policy.max_clock_skew_secs {
                return Err(invalid_parameter(format!(
                    "settlement receipt is {skew} seconds in the future"
                )));
            }
        } else {
            let age = now - receipt.issued_at_unix;
            if age > policy.policy.max_receipt_age_secs {
                return Err(invalid_parameter(format!(
                    "settlement receipt age {age} exceeds governed maximum {} seconds",
                    policy.policy.max_receipt_age_secs
                )));
            }
        }
        if read_receipt(state_transaction.world(), receipt.receipt_id)?.is_some() {
            return Err(invalid_parameter(format!(
                "settlement receipt {} is already recorded",
                hex::encode(receipt.receipt_id)
            )));
        }
        if receipt.range.end > channel.total_bytes
            || receipt.bytes_delivered > channel.remaining_bytes
        {
            return Err(invalid_parameter(
                "settlement receipt exceeds remaining authoritative channel bytes",
            ));
        }
        let expected_split = deterministic_settlement_split_v1(
            &channel.remaining_xor_locked,
            &channel.remaining_fee_xor_locked,
            receipt.bytes_delivered,
            channel.remaining_bytes,
        )
        .map_err(|error| {
            invalid_parameter(format!(
                "failed to derive authoritative settlement split: {error}"
            ))
        })?;
        if receipt.xor_debited != expected_split.xor_debited
            || receipt.provider_credit != expected_split.provider_credit
            || receipt.fee_amount != expected_split.fee_amount
        {
            return Err(invalid_parameter(format!(
                "settlement receipt split ({}, {}, {}) does not equal deterministic channel split ({}, {}, {})",
                receipt.xor_debited,
                receipt.provider_credit,
                receipt.fee_amount,
                expected_split.xor_debited,
                expected_split.provider_credit,
                expected_split.fee_amount,
            )));
        }
        let existing_index = read_receipt_index(state_transaction.world(), receipt.channel_id)?;
        let mut index = existing_index.unwrap_or_else(|| OrderbookSettlementIndexRecord {
            channel_id: receipt.channel_id,
            trade_id: receipt.trade_id,
            ranges: Vec::new(),
        });
        if index.trade_id != receipt.trade_id {
            return Err(invalid_parameter(
                "settlement receipt trade does not match the channel replay index",
            ));
        }
        if index.ranges.len() >= policy.policy.max_receipts_per_channel as usize {
            return Err(invalid_parameter(
                "settlement channel reached the governed receipt-count ceiling",
            ));
        }
        if let Some(existing) = index.ranges.iter().find(|existing| {
            receipt.range.start < existing.end && existing.start < receipt.range.end
        }) {
            return Err(invalid_parameter(format!(
                "settlement receipt range overlaps receipt {}",
                hex::encode(existing.receipt_id)
            )));
        }
        index.ranges.push(OrderbookSettlementRangeRecord {
            receipt_id: receipt.receipt_id,
            start: receipt.range.start,
            end: receipt.range.end,
            issued_at_unix: receipt.issued_at_unix,
        });
        index
            .ranges
            .sort_by_key(|range| (range.start, range.end, range.receipt_id));
        validate_receipt_index(&index, receipt.channel_id)?;
        let record = OrderbookSettlementReceiptRecord {
            receipt_id: receipt.receipt_id,
            channel_id: receipt.channel_id,
            trade_id: receipt.trade_id,
            canonical_receipt: self.receipt_payload,
            admitted_policy_digest: policy.policy_digest,
            admitted_at_unix: now,
            recorded_by: authority.clone(),
        };
        let encoded_record = encode_state(&record, "orderbook settlement receipt")?;
        let encoded_index = encode_state(&index, "orderbook settlement receipt index")?;
        let mut status = active_status(state_transaction, now)?;
        status.settlement_receipts = status
            .settlement_receipts
            .checked_add(1)
            .ok_or_else(|| corrupt_state("orderbook settlement-receipt counter overflow"))?;
        channel.remaining_bytes = channel
            .remaining_bytes
            .checked_sub(receipt.bytes_delivered)
            .ok_or_else(|| corrupt_state("settlement channel byte counter underflow"))?;
        channel.remaining_xor_locked = channel
            .remaining_xor_locked
            .checked_sub(&receipt.xor_debited)
            .map_err(|error| {
                corrupt_state(format!("settlement channel escrow underflow: {error}"))
            })?;
        channel.remaining_fee_xor_locked = channel
            .remaining_fee_xor_locked
            .checked_sub(&receipt.fee_amount)
            .map_err(|error| {
                corrupt_state(format!("settlement channel fee-custody underflow: {error}"))
            })?;
        channel.updated_at_unix = now;
        if channel.remaining_bytes == 0 {
            if !channel.remaining_xor_locked.is_zero()
                || !channel.remaining_fee_xor_locked.is_zero()
            {
                return Err(corrupt_state(
                    "final deterministic receipt did not consume all channel and fee custody",
                ));
            }
            channel.status = OrderbookSettlementChannelStatusV1::Closed;
            status.open_settlement_channels = status
                .open_settlement_channels
                .checked_sub(1)
                .ok_or_else(|| corrupt_state("orderbook open-channel counter underflow"))?;
        }
        status.updated_at_unix = now;
        let encoded_status = encode_status(&status)?;
        let encoded_channel = encode_state(&channel, "orderbook settlement channel")?;
        let escrow_id = orderbook_settlement_escrow_id(receipt.channel_id);
        let escrow = state_transaction
            .world
            .asset_escrows
            .get(&escrow_id)
            .cloned()
            .ok_or_else(|| {
                invalid_parameter(
                    "settlement receipt channel has no funded authoritative asset lock",
                )
            })?;
        if escrow.asset_definition != state_transaction.gov.sorafs_pin_fee_asset_id {
            return Err(invalid_parameter(
                "settlement asset lock does not use the configured SoraFS XOR fee asset",
            ));
        }
        let expected_expiry_ms = channel
            .expires_at_unix
            .checked_mul(1_000)
            .ok_or_else(|| corrupt_state("settlement channel custody expiry overflow"))?;
        let provider = escrow.buyer.as_ref().ok_or_else(|| {
            invalid_parameter("settlement asset lock has no provider destination")
        })?;
        if escrow.id != escrow_id
            || escrow.amount != channel.initial_xor_locked.clone().into_quantity()
            || escrow.expires_at_ms != Some(expected_expiry_ms)
            || provider.subject_id() != channel.provider.subject_id()
            || escrow.seller.subject_id() != channel.buyer.subject_id()
            || escrow.release_authority.as_ref() != Some(&channel.settlement_authority)
            || escrow.remaining_amount
                != channel
                    .remaining_xor_locked
                    .checked_add(&receipt.xor_debited)
                    .map_err(|error| {
                        corrupt_state(format!(
                            "failed to reconstruct pre-receipt channel custody: {error}"
                        ))
                    })?
                    .into_quantity()
        {
            return Err(invalid_parameter(
                "settlement asset lock does not match authoritative channel custody",
            ));
        }
        if !provider_binding_is_current(
            state_transaction.world(),
            channel.provider_id,
            &channel.provider,
        ) {
            return Err(invalid_parameter(
                "settlement channel's exact governed provider binding is no longer active",
            ));
        }
        let fee_recipient = state_transaction
            .gov
            .sorafs_pin_fee_treasury_account
            .clone();
        super::escrow::settle_orderbook_asset_lock(
            state_transaction,
            &escrow_id,
            &channel.settlement_authority,
            &fee_recipient,
            receipt.provider_credit.clone().into_quantity(),
            receipt.fee_amount.clone().into_quantity(),
        )
        .map_err(|error| {
            invalid_parameter(format!("settlement asset-lock mutation failed: {error}"))
        })?;
        state_transaction
            .world
            .smart_contract_state
            .insert(receipt_index_key(receipt.channel_id), encoded_index);
        state_transaction
            .world
            .smart_contract_state
            .insert(receipt_key(receipt.receipt_id), encoded_record);
        state_transaction
            .world
            .smart_contract_state
            .insert(channel_key(receipt.channel_id), encoded_channel);
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encoded_status);
        emit_orderbook_event(
            state_transaction,
            SorafsOrderbookLedgerEventKind::ReceiptRecorded,
            None,
            Some(receipt.trade_id),
            Some(receipt.channel_id),
            Some(receipt.receipt_id),
            Some(channel.provider_id),
            status.book_revision,
            authority,
            now,
        )?;
        Ok(())
    }
}
fn ensure_orderbook_query_state(world: &impl WorldReadOnly) -> Result<(), QueryExecutionFail> {
    let policy = read_policy(world).map_err(query_failure)?;
    let status = read_status(world).map_err(query_failure)?;
    match (policy, status) {
        (Some(_), Some(_)) => Ok(()),
        (None, None) => Err(QueryExecutionFail::Find(FindError::SorafsOrderbookPolicy)),
        _ => Err(QueryExecutionFail::Conversion(
            "authoritative SoraFS orderbook policy/status state is inconsistent".to_owned(),
        )),
    }
}
fn checked_query_limit(limit: u32) -> Result<usize, QueryExecutionFail> {
    if !(1..=ORDERBOOK_QUERY_MAX_ITEMS_V1).contains(&limit) {
        return Err(QueryExecutionFail::Conversion(format!(
            "SoraFS orderbook query limit {limit} is outside 1..={ORDERBOOK_QUERY_MAX_ITEMS_V1}"
        )));
    }
    usize::try_from(limit).map_err(|_| {
        QueryExecutionFail::Conversion("SoraFS orderbook query limit conversion failed".to_owned())
    })
}
#[derive(Clone, Copy, Debug)]
struct OrderbookQueryScanLimitsV1 {
    max_inspected_records: u32,
    max_read_bytes: usize,
}
const ORDERBOOK_QUERY_SCAN_LIMITS_V1: OrderbookQueryScanLimitsV1 = OrderbookQueryScanLimitsV1 {
    max_inspected_records: ORDERBOOK_QUERY_MAX_INSPECTED_RECORDS_V1,
    max_read_bytes: ORDERBOOK_QUERY_MAX_READ_BYTES_V1,
};
#[derive(Debug)]
struct OrderbookQueryScanBudgetV1 {
    limits: OrderbookQueryScanLimitsV1,
    inspected_records: u32,
    read_bytes: usize,
}
impl OrderbookQueryScanBudgetV1 {
    const fn new(limits: OrderbookQueryScanLimitsV1) -> Self {
        Self {
            limits,
            inspected_records: 0,
            read_bytes: 0,
        }
    }
    fn inspect(&mut self, payload_len: usize, page_label: &str) -> Result<(), QueryExecutionFail> {
        let inspected_records = self
            .inspected_records
            .checked_add(1)
            .filter(|count| *count <= self.limits.max_inspected_records)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "SoraFS orderbook {page_label} query exceeded inspected-record budget {}",
                    self.limits.max_inspected_records
                ))
            })?;
        let read_bytes = self
            .read_bytes
            .checked_add(payload_len)
            .filter(|bytes| *bytes <= self.limits.max_read_bytes)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(format!(
                    "SoraFS orderbook {page_label} query exceeded encoded-read-byte budget {}",
                    self.limits.max_read_bytes
                ))
            })?;
        self.inspected_records = inspected_records;
        self.read_bytes = read_bytes;
        Ok(())
    }
}
fn resolve_finalized_cursor(
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<OrderbookFinalizedCursorV1, QueryExecutionFail> {
    let height = u64::try_from(state_ro.block_hashes().len()).map_err(|_| {
        QueryExecutionFail::Conversion(
            "finalized orderbook height does not fit into u64".to_owned(),
        )
    })?;
    let block_hash = state_ro
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "finalized orderbook queries require at least one committed block".to_owned(),
            )
        })?;
    if height == 0 || block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(
            "finalized orderbook query anchor is invalid".to_owned(),
        ));
    }
    Ok(OrderbookFinalizedCursorV1 { height, block_hash })
}
fn resolve_query_finalized_cursor(
    expected: Option<OrderbookFinalizedCursorV1>,
    state_ro: &impl crate::state::StateReadOnly,
) -> Result<OrderbookFinalizedCursorV1, QueryExecutionFail> {
    let actual = resolve_finalized_cursor(state_ro)?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(QueryExecutionFail::Expired);
    }
    Ok(actual)
}
fn resolve_committed_event(
    state_ro: &impl crate::state::StateReadOnly,
    record: OrderbookPersistedEventV1,
) -> Result<OrderbookFinalizedEventV1, QueryExecutionFail> {
    let hash_index = record
        .target_block_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "orderbook event target height cannot index finalized block hashes".to_owned(),
            )
        })?;
    let block_hash = state_ro
        .block_hashes()
        .get(hash_index)
        .map(|hash| *hash.as_ref())
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "orderbook event sequence {} targets non-finalized block height {}",
                record.sequence, record.target_block_height
            ))
        })?;
    if block_hash == [0; 32] {
        return Err(QueryExecutionFail::Conversion(format!(
            "orderbook event sequence {} resolved a zero block hash",
            record.sequence
        )));
    }
    Ok(OrderbookFinalizedEventV1 {
        sequence: record.sequence,
        block_height: record.target_block_height,
        block_hash,
        event_index: record.event_index,
        event: record.event,
    })
}
#[derive(Clone, Copy)]
struct OrderbookQueryEventPosition {
    sequence: u64,
    target_block_height: u64,
    event_index: u32,
}
impl From<&OrderbookPersistedEventV1> for OrderbookQueryEventPosition {
    fn from(record: &OrderbookPersistedEventV1) -> Self {
        Self {
            sequence: record.sequence,
            target_block_height: record.target_block_height,
            event_index: record.event_index,
        }
    }
}
fn validate_query_event_successor(
    previous: Option<OrderbookQueryEventPosition>,
    current: &OrderbookPersistedEventV1,
) -> Result<(), QueryExecutionFail> {
    let Some(previous) = previous else {
        return (current.sequence == 1 && current.event_index == 0)
            .then_some(())
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "orderbook event journal does not begin at sequence one and block index zero"
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
            "orderbook event journal sequence is not contiguous".to_owned(),
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
            "orderbook event journal block height/index ordering is invalid".to_owned(),
        )),
    }
}
fn read_event_sequence(
    state_ro: &impl crate::state::StateReadOnly,
    sequence: u64,
    previous: Option<OrderbookQueryEventPosition>,
) -> Result<(OrderbookQueryEventPosition, OrderbookFinalizedEventV1), QueryExecutionFail> {
    let record = read_persisted_event(state_ro.world(), sequence)
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(format!(
                "orderbook event journal is missing sequence {sequence}"
            ))
        })?;
    validate_query_event_successor(previous, &record)?;
    let position = OrderbookQueryEventPosition::from(&record);
    let resolved = resolve_committed_event(state_ro, record)?;
    Ok((position, resolved))
}
fn query_order_page(
    query: &FindSorafsOrderbookOrders,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<OrderbookOrderPageV1, QueryExecutionFail> {
    let mut scan_budget = OrderbookQueryScanBudgetV1::new(ORDERBOOK_QUERY_SCAN_LIMITS_V1);
    query_order_page_with_budget(query, state_ro, finalized_cursor, &mut scan_budget)
}
fn query_order_page_with_budget(
    query: &FindSorafsOrderbookOrders,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    scan_budget: &mut OrderbookQueryScanBudgetV1,
) -> Result<OrderbookOrderPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let world = state_ro.world();
    let start_order_id = query.after_order_id.unwrap_or([0; 32]);
    let mut selected_count = 0usize;
    let mut has_more = false;
    // Validate and filter before reserving the retained output. Recursive order
    // validation owns the stored record and one protocol-bounded signed payload;
    // retaining an already populated D-sized builder beside them would create a
    // third independently admitted resident phase.
    for (key, payload) in world
        .smart_contract_state()
        .range(order_key(start_order_id)..)
    {
        if !key.as_ref().starts_with(ORDER_STATE_KEY_PREFIX) {
            break;
        }
        scan_budget.inspect(payload.len(), "order page")?;
        let order_id = parse_query_digest_key(key, ORDER_STATE_KEY_PREFIX, "order")?;
        if query
            .after_order_id
            .is_some_and(|cursor| order_id <= cursor)
        {
            continue;
        }
        let record = read_order(world, order_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "authoritative orderbook order disappeared during read".to_owned(),
                )
            })?;
        if query.status.is_some_and(|status| record.status != status) {
            continue;
        }
        if selected_count == limit {
            drop(record);
            has_more = true;
            break;
        }
        selected_count += 1;
        drop(record);
    }
    let mut orders =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(selected_count)?;
    if selected_count != 0 {
        for (key, payload) in world
            .smart_contract_state()
            .range(order_key(start_order_id)..)
        {
            if !key.as_ref().starts_with(ORDER_STATE_KEY_PREFIX) {
                break;
            }
            let order_id = parse_query_digest_key(key, ORDER_STATE_KEY_PREFIX, "order")?;
            if query
                .after_order_id
                .is_some_and(|cursor| order_id <= cursor)
            {
                continue;
            }
            // The immutable first pass fully validated these exact bytes. This
            // second pass performs only the canonical state decode needed to
            // materialize the selected output beside the retained builder.
            let record: OrderbookOrderRecord =
                decode_state(payload, "orderbook order").map_err(query_failure)?;
            if query.status.is_some_and(|status| record.status != status) {
                continue;
            }
            orders.try_push(record)?;
            if orders.len() == selected_count {
                break;
            }
        }
    }
    if orders.len() != selected_count {
        return Err(QueryExecutionFail::Conversion(
            "immutable orderbook order page changed between validation and materialization"
                .to_owned(),
        ));
    }
    let next_after_order_id = if has_more {
        Some(
            orders
                .last()
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "orderbook page cursor invariant failed".to_owned(),
                    )
                })?
                .order_id,
        )
    } else {
        None
    };
    Ok(OrderbookOrderPageV1 {
        finalized_cursor,
        orders: orders.into_vec()?,
        has_more,
        next_after_order_id,
    })
}
fn query_receipt_page(
    query: &FindSorafsOrderbookReceipts,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<OrderbookSettlementReceiptPageV1, QueryExecutionFail> {
    let mut scan_budget = OrderbookQueryScanBudgetV1::new(ORDERBOOK_QUERY_SCAN_LIMITS_V1);
    query_receipt_page_with_budget(query, state_ro, finalized_cursor, &mut scan_budget)
}
fn query_receipt_page_with_budget(
    query: &FindSorafsOrderbookReceipts,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    scan_budget: &mut OrderbookQueryScanBudgetV1,
) -> Result<OrderbookSettlementReceiptPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let world = state_ro.world();
    let start_receipt_id = query.after_receipt_id.unwrap_or([0; 32]);
    let mut selected_count = 0usize;
    let mut has_more = false;
    for (key, payload) in world
        .smart_contract_state()
        .range(receipt_key(start_receipt_id)..)
    {
        if !key.as_ref().starts_with(RECEIPT_STATE_KEY_PREFIX) {
            break;
        }
        scan_budget.inspect(payload.len(), "receipt page")?;
        let receipt_id = parse_query_digest_key(key, RECEIPT_STATE_KEY_PREFIX, "receipt")?;
        if query
            .after_receipt_id
            .is_some_and(|cursor| receipt_id <= cursor)
        {
            continue;
        }
        let record = read_receipt(world, receipt_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "authoritative orderbook receipt disappeared during read".to_owned(),
                )
            })?;
        if query
            .channel_id
            .is_some_and(|channel_id| record.channel_id != channel_id)
        {
            continue;
        }
        if selected_count == limit {
            drop(record);
            has_more = true;
            break;
        }
        selected_count += 1;
        drop(record);
    }
    let mut receipts =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(selected_count)?;
    if selected_count != 0 {
        for (key, payload) in world
            .smart_contract_state()
            .range(receipt_key(start_receipt_id)..)
        {
            if !key.as_ref().starts_with(RECEIPT_STATE_KEY_PREFIX) {
                break;
            }
            let receipt_id = parse_query_digest_key(key, RECEIPT_STATE_KEY_PREFIX, "receipt")?;
            if query
                .after_receipt_id
                .is_some_and(|cursor| receipt_id <= cursor)
            {
                continue;
            }
            let record: OrderbookSettlementReceiptRecord =
                decode_state(payload, "orderbook settlement receipt").map_err(query_failure)?;
            if query
                .channel_id
                .is_some_and(|channel_id| record.channel_id != channel_id)
            {
                continue;
            }
            receipts.try_push(record)?;
            if receipts.len() == selected_count {
                break;
            }
        }
    }
    if receipts.len() != selected_count {
        return Err(QueryExecutionFail::Conversion(
            "immutable orderbook receipt page changed between validation and materialization"
                .to_owned(),
        ));
    }
    let next_after_receipt_id = if has_more {
        Some(
            receipts
                .last()
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "orderbook receipt-page cursor invariant failed".to_owned(),
                    )
                })?
                .receipt_id,
        )
    } else {
        None
    };
    Ok(OrderbookSettlementReceiptPageV1 {
        finalized_cursor,
        receipts: receipts.into_vec()?,
        has_more,
        next_after_receipt_id,
    })
}
fn query_trade_page(
    query: &FindSorafsOrderbookTrades,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<OrderbookTradePageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let world = state_ro.world();
    let start_trade_id = query.after_trade_id.unwrap_or([0; 32]);
    let mut selected_count = 0usize;
    let mut has_more = false;
    for (key, _payload) in world
        .smart_contract_state()
        .range(trade_key(start_trade_id)..)
    {
        if !key.as_ref().starts_with(TRADE_STATE_KEY_PREFIX) {
            break;
        }
        let trade_id = parse_query_digest_key(key, TRADE_STATE_KEY_PREFIX, "trade")?;
        if query
            .after_trade_id
            .is_some_and(|cursor| trade_id <= cursor)
        {
            continue;
        }
        let record = read_trade(world, trade_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "authoritative orderbook trade disappeared during read".to_owned(),
                )
            })?;
        if selected_count == limit {
            drop(record);
            has_more = true;
            break;
        }
        selected_count += 1;
        drop(record);
    }
    let mut trades =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(selected_count)?;
    if selected_count != 0 {
        for (key, payload) in world
            .smart_contract_state()
            .range(trade_key(start_trade_id)..)
        {
            if !key.as_ref().starts_with(TRADE_STATE_KEY_PREFIX) {
                break;
            }
            let trade_id = parse_query_digest_key(key, TRADE_STATE_KEY_PREFIX, "trade")?;
            if query
                .after_trade_id
                .is_some_and(|cursor| trade_id <= cursor)
            {
                continue;
            }
            let record: OrderbookTradeRecord =
                decode_state(payload, "orderbook trade").map_err(query_failure)?;
            trades.try_push(record)?;
            if trades.len() == selected_count {
                break;
            }
        }
    }
    if trades.len() != selected_count {
        return Err(QueryExecutionFail::Conversion(
            "immutable orderbook trade page changed between validation and materialization"
                .to_owned(),
        ));
    }
    let next_after_trade_id = if has_more {
        Some(
            trades
                .last()
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "orderbook trade-page cursor invariant failed".to_owned(),
                    )
                })?
                .trade_id,
        )
    } else {
        None
    };
    Ok(OrderbookTradePageV1 {
        finalized_cursor,
        trades: trades.into_vec()?,
        has_more,
        next_after_trade_id,
    })
}
fn query_channel_page(
    query: &FindSorafsOrderbookChannels,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<OrderbookSettlementChannelPageV1, QueryExecutionFail> {
    let mut scan_budget = OrderbookQueryScanBudgetV1::new(ORDERBOOK_QUERY_SCAN_LIMITS_V1);
    query_channel_page_with_budget(query, state_ro, finalized_cursor, &mut scan_budget)
}
fn query_channel_page_with_budget(
    query: &FindSorafsOrderbookChannels,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    scan_budget: &mut OrderbookQueryScanBudgetV1,
) -> Result<OrderbookSettlementChannelPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let world = state_ro.world();
    let start_channel_id = query.after_channel_id.unwrap_or([0; 32]);
    let mut selected_count = 0usize;
    let mut has_more = false;
    for (key, payload) in world
        .smart_contract_state()
        .range(channel_key(start_channel_id)..)
    {
        if !key.as_ref().starts_with(CHANNEL_STATE_KEY_PREFIX) {
            break;
        }
        scan_budget.inspect(payload.len(), "channel page")?;
        let channel_id = parse_query_digest_key(key, CHANNEL_STATE_KEY_PREFIX, "channel")?;
        if query
            .after_channel_id
            .is_some_and(|cursor| channel_id <= cursor)
        {
            continue;
        }
        let record = read_channel(world, channel_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "authoritative orderbook channel disappeared during read".to_owned(),
                )
            })?;
        if query.status.is_some_and(|status| record.status != status) {
            continue;
        }
        if selected_count == limit {
            drop(record);
            has_more = true;
            break;
        }
        selected_count += 1;
        drop(record);
    }
    let mut channels =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(selected_count)?;
    if selected_count != 0 {
        for (key, payload) in world
            .smart_contract_state()
            .range(channel_key(start_channel_id)..)
        {
            if !key.as_ref().starts_with(CHANNEL_STATE_KEY_PREFIX) {
                break;
            }
            let channel_id = parse_query_digest_key(key, CHANNEL_STATE_KEY_PREFIX, "channel")?;
            if query
                .after_channel_id
                .is_some_and(|cursor| channel_id <= cursor)
            {
                continue;
            }
            let record: OrderbookSettlementChannelRecord =
                decode_state(payload, "orderbook settlement channel").map_err(query_failure)?;
            if query.status.is_some_and(|status| record.status != status) {
                continue;
            }
            channels.try_push(record)?;
            if channels.len() == selected_count {
                break;
            }
        }
    }
    if channels.len() != selected_count {
        return Err(QueryExecutionFail::Conversion(
            "immutable orderbook channel page changed between validation and materialization"
                .to_owned(),
        ));
    }
    let next_after_channel_id = if has_more {
        Some(
            channels
                .last()
                .ok_or_else(|| {
                    QueryExecutionFail::Conversion(
                        "orderbook channel-page cursor invariant failed".to_owned(),
                    )
                })?
                .channel_id,
        )
    } else {
        None
    };
    Ok(OrderbookSettlementChannelPageV1 {
        finalized_cursor,
        channels: channels.into_vec()?,
        has_more,
        next_after_channel_id,
    })
}
fn query_event_page(
    query: &FindSorafsOrderbookEvents,
    state_ro: &impl crate::state::StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<OrderbookFinalizedEventPageV1, QueryExecutionFail> {
    let limit = checked_query_limit(query.limit)?;
    let page_bytes_limit = crate::smartcontracts::isi::query::singular_query_frame_limit(
        ORDERBOOK_QUERY_MAX_EVENT_PAGE_BYTES_V1,
    );
    let head = read_event_journal_head(state_ro.world())
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "active orderbook state has no committed-event journal".to_owned(),
            )
        })?;
    let terminal = read_persisted_event(state_ro.world(), head.last_sequence)
        .map_err(query_failure)?
        .ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "orderbook event journal terminal record disappeared during read".to_owned(),
            )
        })?;
    resolve_committed_event(state_ro, terminal)?;
    let head = Some(head);
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
                                "orderbook event journal is missing predecessor sequence {predecessor_sequence}"
                            ))
                        })?,
                )
            };
            let predecessor = predecessor_record
                .as_ref()
                .map(OrderbookQueryEventPosition::from);
            drop(predecessor_record);
            let record = read_persisted_event(state_ro.world(), after.sequence)
                .map_err(query_failure)?
                .ok_or(QueryExecutionFail::Expired)?;
            validate_query_event_successor(predecessor, &record)?;
            let position = OrderbookQueryEventPosition::from(&record);
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
    let available = start
        .filter(|start| *start <= last_sequence)
        .map_or(0, |start| {
            last_sequence.saturating_sub(start).saturating_add(1)
        });
    let event_capacity = usize::try_from(available.min(u64::from(query.limit))).map_err(|_| {
        QueryExecutionFail::Conversion(
            "orderbook event page capacity does not fit the platform address space".to_owned(),
        )
    })?;
    let mut events =
        crate::smartcontracts::isi::query::SingularQueryVecBuilder::new(event_capacity)?;
    let mut encoded_event_bytes = 0usize;
    let mut sequence = start;
    while let Some(current_sequence) = sequence {
        if current_sequence > last_sequence || events.len() >= limit {
            break;
        }
        let (position, resolved) = read_event_sequence(state_ro, current_sequence, previous)?;
        encoded_event_bytes = encoded_event_bytes
            .checked_add(norito::canonical_frame_len(&resolved).map_err(|error| {
                QueryExecutionFail::Conversion(format!(
                    "failed to size committed orderbook event: {error}"
                ))
            })?)
            .ok_or_else(|| {
                QueryExecutionFail::Conversion(
                    "committed orderbook event page byte counter overflow".to_owned(),
                )
            })?;
        if encoded_event_bytes > page_bytes_limit {
            return Err(QueryExecutionFail::Conversion(format!(
                "committed orderbook event page exceeds {page_bytes_limit} bytes"
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
            .expect("has_more requires a non-empty orderbook event page")
            .cursor()
    });
    let page = OrderbookFinalizedEventPageV1 {
        finalized_cursor,
        events: events.into_vec()?,
        has_more,
        next_after,
    };
    let encoded_len = norito::canonical_frame_len(&page).map_err(|error| {
        QueryExecutionFail::Conversion(format!(
            "failed to size committed orderbook event page: {error}"
        ))
    })?;
    if encoded_len > page_bytes_limit {
        return Err(QueryExecutionFail::Conversion(format!(
            "committed orderbook event page encodes to {encoded_len} bytes, above {page_bytes_limit}"
        )));
    }
    Ok(page)
}
impl ValidSingularQuery for FindSorafsOrderbookPolicy {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookAdmissionPolicyRecord, QueryExecutionFail> {
        read_policy(state_ro.world())
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsOrderbookPolicy))
    }
}
impl ValidSingularQuery for FindSorafsOrderbookOrderById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookOrderRecord, QueryExecutionFail> {
        read_order(state_ro.world(), self.order_id)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsOrderbookOrder(self.order_id)))
    }
}
impl ValidSingularQuery for FindSorafsOrderbookCancellationByOrderId {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookCancellationRecord, QueryExecutionFail> {
        let order = read_order(state_ro.world(), self.order_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsOrderbookCancellation(self.order_id))
            })?;
        if order.status != OrderbookOrderStatusV1::Cancelled {
            return Err(QueryExecutionFail::Conversion(format!(
                "authoritative SoraFS orderbook order {} is not cancelled",
                hex::encode(self.order_id)
            )));
        }
        let (Some(canonical_cancel), Some(cancelled_at_unix), Some(cancelled_policy_digest)) = (
            order.canonical_cancel,
            order.cancelled_at_unix,
            order.cancelled_policy_digest,
        ) else {
            return Err(QueryExecutionFail::Conversion(
                "authoritative SoraFS cancellation state is inconsistent".to_owned(),
            ));
        };
        Ok(OrderbookCancellationRecord {
            order_id: order.order_id,
            owner: order.owner,
            canonical_cancel,
            cancelled_at_unix,
            cancelled_policy_digest,
        })
    }
}
impl ValidSingularQuery for FindSorafsOrderbookReceiptById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookSettlementReceiptRecord, QueryExecutionFail> {
        read_receipt(state_ro.world(), self.receipt_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsOrderbookReceipt(self.receipt_id))
            })
    }
}
impl ValidSingularQuery for FindSorafsOrderbookTradeById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookTradeRecord, QueryExecutionFail> {
        read_trade(state_ro.world(), self.trade_id)
            .map_err(query_failure)?
            .ok_or_else(|| QueryExecutionFail::Find(FindError::SorafsOrderbookTrade(self.trade_id)))
    }
}
impl ValidSingularQuery for FindSorafsOrderbookChannelById {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookSettlementChannelRecord, QueryExecutionFail> {
        read_channel(state_ro.world(), self.channel_id)
            .map_err(query_failure)?
            .ok_or_else(|| {
                QueryExecutionFail::Find(FindError::SorafsOrderbookChannel(self.channel_id))
            })
    }
}
impl ValidSingularQuery for FindSorafsOrderbookStatus {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookLedgerStatusV1, QueryExecutionFail> {
        let policy = read_policy(state_ro.world()).map_err(query_failure)?;
        let status = read_status(state_ro.world()).map_err(query_failure)?;
        match (policy, status) {
            (Some(_), Some(status)) => Ok(status),
            (None, None) => Err(QueryExecutionFail::Find(FindError::SorafsOrderbookStatus)),
            _ => Err(QueryExecutionFail::Conversion(
                "authoritative SoraFS orderbook policy/status state is inconsistent".to_owned(),
            )),
        }
    }
}
impl ValidSingularQuery for FindSorafsOrderbookOrders {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookOrderPageV1, QueryExecutionFail> {
        ensure_orderbook_query_state(state_ro.world())?;
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_order_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsOrderbookReceipts {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookSettlementReceiptPageV1, QueryExecutionFail> {
        ensure_orderbook_query_state(state_ro.world())?;
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_receipt_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsOrderbookTrades {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookTradePageV1, QueryExecutionFail> {
        ensure_orderbook_query_state(state_ro.world())?;
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_trade_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsOrderbookChannels {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookSettlementChannelPageV1, QueryExecutionFail> {
        ensure_orderbook_query_state(state_ro.world())?;
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_channel_page(self, state_ro, finalized_cursor)
    }
}
impl ValidSingularQuery for FindSorafsOrderbookEvents {
    fn execute(
        &self,
        state_ro: &impl crate::state::StateReadOnly,
    ) -> Result<OrderbookFinalizedEventPageV1, QueryExecutionFail> {
        ensure_orderbook_query_state(state_ro.world())?;
        let finalized_cursor =
            resolve_query_finalized_cursor(self.expected_finalized_cursor, state_ro)?;
        query_event_page(self, state_ro, finalized_cursor)
    }
}
#[cfg(test)]
mod tests {
    include!("sorafs_orderbook/schema_identity_tests.rs");
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Hash, KeyPair, PrivateKey, Signature};
    use iroha_data_model::{
        IntoKeyValue, Registrable,
        account::{Account, AccountId},
        asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
        block::BlockHeader,
        domain::Domain,
        isi::{
            escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock},
            sorafs::{
                AdvanceSorafsReserveLifecycle, DecideSorafsReserveAppeal,
                RegisterSorafsReserveAccount, SetSorafsReservePolicy, SubmitSorafsReserveAppeal,
            },
        },
        permission::{Permission, Permissions},
        sorafs::{
            capacity::ProviderId,
            orderbook::{
                ORDERBOOK_ADMISSION_POLICY_VERSION_V1, OrderbookAdmissionPolicyV1,
                OrderbookOrderStatusV1, orderbook_order_escrow_id, orderbook_settlement_escrow_id,
            },
            pin_registry::StorageClass,
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, RESERVE_RENT_BILLING_PERIOD_SECONDS_V1,
                ReserveAuthorityPolicyV1, ReserveDuration, ReserveLifecycleStage, ReservePolicyV1,
                ReserveProviderTermsV1, ReserveTier,
            },
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::{bigint::BigInt, json::Json, numeric::Quantity};
    use sorafs_manifest::{
        XorQuantity,
        orderbook::{
            ByteRangeV1, ORDERBOOK_CANCEL_VERSION_V1, ORDERBOOK_ORDER_VERSION_V1,
            ORDERBOOK_TRADE_EVENT_VERSION_V1, OrderCancelReasonV1, OrderCancelV1, OrderRequestV1,
            OrderSideV1, OrderTierV1, OrderbookSignatureV1, SETTLEMENT_RECEIPT_VERSION_V1,
            SettlementReceiptV1, derive_orderbook_order_id_v1, order_cancel_signature_digest_v1,
            order_request_signature_digest_v1, settlement_receipt_signature_digest_v1,
        },
        provider_advert::SignatureAlgorithm,
    };
    pub(super) const NOW: u64 = 10_000;
    // Ten micro-XOR per byte keeps the small, exact-range receipt fixtures nonzero.
    const TEST_TRADE_LOCK_MICRO: u128 = 10 * BYTES_PER_GIB as u128;
    pub(super) fn keypair(seed: u8) -> KeyPair {
        let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
            .expect("valid deterministic Ed25519 seed");
        KeyPair::from_private_key(private).expect("derive deterministic keypair")
    }
    pub(super) fn account(keypair: &KeyPair) -> AccountId {
        AccountId::new(keypair.public_key().clone())
    }
    fn empty_signature(keypair: &KeyPair) -> OrderbookSignatureV1 {
        let (_, public_key) = keypair
            .public_key()
            .try_to_bytes()
            .expect("valid fixture public key");
        OrderbookSignatureV1 {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: public_key.to_vec(),
            signature: Vec::new(),
        }
    }
    fn sign_digest(keypair: &KeyPair, digest: [u8; 32]) -> Vec<u8> {
        Signature::try_new(keypair.private_key(), &digest)
            .expect("sign fixture digest")
            .payload()
            .to_vec()
    }
    fn xor_micro(value: u128) -> XorQuantity {
        XorQuantity::try_from_micro(value).expect("micro-XOR fixture fits exact XOR quantity")
    }
    fn sign_order(mut order: OrderRequestV1, keypair: &KeyPair) -> OrderRequestV1 {
        order.signature = empty_signature(keypair);
        let digest = order_request_signature_digest_v1(&order).expect("digest order");
        order.signature.signature = sign_digest(keypair, digest);
        verify_order_request_signature_v1(&order).expect("signed order verifies");
        order
    }
    fn sign_cancel(mut cancel: OrderCancelV1, keypair: &KeyPair) -> OrderCancelV1 {
        cancel.signature = empty_signature(keypair);
        let digest = order_cancel_signature_digest_v1(&cancel).expect("digest cancellation");
        cancel.signature.signature = sign_digest(keypair, digest);
        verify_order_cancel_signature_v1(&cancel).expect("signed cancellation verifies");
        cancel
    }
    fn sign_receipt(mut receipt: SettlementReceiptV1, keypair: &KeyPair) -> SettlementReceiptV1 {
        receipt.settlement_signature = empty_signature(keypair);
        let digest = settlement_receipt_signature_digest_v1(&receipt).expect("digest receipt");
        receipt.settlement_signature.signature = sign_digest(keypair, digest);
        verify_settlement_receipt_signature_v1(&receipt).expect("signed receipt verifies");
        receipt
    }
    fn policy() -> OrderbookAdmissionPolicyV1 {
        OrderbookAdmissionPolicyV1 {
            version: ORDERBOOK_ADMISSION_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            market_id: [0xA5; 32],
            matcher_authority: account(&keypair(0xA1)),
            settlement_authority: account(&keypair(0xA2)),
            paused: false,
            min_order_gib: 2,
            max_order_gib: 1_024,
            price_tick_micro_xor: 10,
            max_maker_fee_bps: 100,
            max_taker_fee_bps: 200,
            max_order_lifetime_secs: 3_600,
            max_receipt_age_secs: 300,
            max_clock_skew_secs: 5,
            max_receipt_bytes: 1_024,
            max_receipts_per_channel: 2,
        }
    }
    fn order(keypair: &KeyPair, nonce: u64) -> OrderRequestV1 {
        let owner_account = account(keypair).to_string().into_bytes();
        sign_order(
            OrderRequestV1 {
                version: ORDERBOOK_ORDER_VERSION_V1,
                order_id: derive_orderbook_order_id_v1(&owner_account, nonce),
                side: OrderSideV1::Bid,
                tier: OrderTierV1::Hot,
                price_per_gib: xor_micro(100),
                quantity_gib: 10,
                remaining_gib: 10,
                owner_account,
                provider_id: None,
                expiry_unix: NOW + 100,
                nonce,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                signature: empty_signature(keypair),
            },
            keypair,
        )
    }
    fn ask_order(
        keypair: &KeyPair,
        nonce: u64,
        price_micro: u128,
        quantity_gib: u64,
    ) -> OrderRequestV1 {
        let mut ask = order(keypair, nonce);
        ask.side = OrderSideV1::Ask;
        ask.price_per_gib = xor_micro(price_micro);
        ask.quantity_gib = quantity_gib;
        ask.remaining_gib = quantity_gib;
        ask.provider_id = Some([0x72; 32]);
        sign_order(ask, keypair)
    }
    fn working_order(
        order: OrderRequestV1,
        owner: &AccountId,
        sequence: u64,
    ) -> WorkingLedgerOrder {
        WorkingLedgerOrder {
            record: OrderbookOrderRecord {
                order_id: order.order_id,
                owner: owner.clone(),
                canonical_order: encode(&order),
                admitted_policy_digest: [0xA5; 32],
                admitted_at_unix: NOW - 1,
                admission_sequence: sequence,
                remaining_gib: order.remaining_gib,
                bid_escrow: None,
                provider_id: order.provider_id.map(ProviderId::new),
                status: OrderbookOrderStatusV1::Open,
                updated_at_unix: NOW - 1,
                canonical_cancel: None,
                cancelled_at_unix: None,
                cancelled_policy_digest: None,
            },
            order,
        }
    }
    fn cancel(keypair: &KeyPair, order_id: [u8; 32], nonce: u64) -> OrderCancelV1 {
        sign_cancel(
            OrderCancelV1 {
                version: ORDERBOOK_CANCEL_VERSION_V1,
                order_id,
                owner_account: account(keypair).to_string().into_bytes(),
                reason: OrderCancelReasonV1::OwnerRequested,
                nonce,
                signature: empty_signature(keypair),
            },
            keypair,
        )
    }
    fn test_trade(trade_id: [u8; 32]) -> TradeEventV1 {
        TradeEventV1 {
            version: ORDERBOOK_TRADE_EVENT_VERSION_V1,
            trade_id,
            maker_order_id: [trade_id[0].wrapping_add(1); 32],
            taker_order_id: [trade_id[0].wrapping_add(2); 32],
            tier: OrderTierV1::Hot,
            price_per_gib: xor_micro(TEST_TRADE_LOCK_MICRO),
            filled_gib: 1,
            maker_fee: XorQuantity::zero(),
            taker_fee: XorQuantity::zero(),
            timestamp_unix: NOW - 2,
        }
    }
    pub(super) fn receipt(
        keypair: &KeyPair,
        receipt_id: u8,
        _channel_id: u8,
        trade_id: u8,
        start: u64,
        end: u64,
    ) -> SettlementReceiptV1 {
        let length = end - start;
        let trade = test_trade([trade_id; 32]);
        let mut remaining_xor = trade_escrow_requirement_v1(&trade).expect("fixture trade escrow");
        let mut remaining_fee = trade_fee_requirement_v1(&trade).expect("fixture trade fee");
        let mut remaining_bytes = BYTES_PER_GIB;
        let mut prefix = start;
        while prefix > 0 {
            let delivered = prefix.min(10);
            let split = deterministic_settlement_split_v1(
                &remaining_xor,
                &remaining_fee,
                delivered,
                remaining_bytes,
            )
            .expect("fixture prefix split");
            remaining_xor = remaining_xor
                .checked_sub(&split.xor_debited)
                .expect("fixture prefix debit");
            remaining_fee = remaining_fee
                .checked_sub(&split.fee_amount)
                .expect("fixture prefix fee");
            remaining_bytes -= delivered;
            prefix -= delivered;
        }
        let split = deterministic_settlement_split_v1(
            &remaining_xor,
            &remaining_fee,
            length,
            remaining_bytes,
        )
        .expect("fixture receipt split");
        sign_receipt(
            SettlementReceiptV1 {
                version: SETTLEMENT_RECEIPT_VERSION_V1,
                receipt_id: [receipt_id; 32],
                channel_id: derive_orderbook_settlement_channel_id_v1(&trade)
                    .expect("derive fixture channel"),
                trade_id: trade.trade_id,
                range: ByteRangeV1 { start, end },
                chunk_hash: [0xC1; 32],
                bytes_delivered: length,
                xor_debited: split.xor_debited,
                provider_credit: split.provider_credit,
                fee_amount: split.fee_amount,
                issued_at_unix: NOW - 1,
                settlement_signature: empty_signature(keypair),
            },
            keypair,
        )
    }
    fn block_header_at(height: u64, now_unix: u64) -> BlockHeader {
        BlockHeader::new(
            height.try_into().expect("nonzero fixture block height"),
            None,
            None,
            now_unix * 1_000,
            0,
        )
    }
    pub(super) fn block_header() -> BlockHeader {
        block_header_at(1, NOW)
    }
    pub(super) fn transact(
        state: &mut State,
        height: u64,
        now_unix: u64,
        operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
    ) -> Result<(), InstructionExecutionError> {
        let header = block_header_at(height, now_unix);
        let mut block = state.block(header.clone());
        // Local journal fixture only: retain a bounded direct execution slot before
        // custody changes. This World-only commit does not publish a Network carrier.
        let mut transaction = block.transaction_for_callback_testing();
        operation(&mut transaction)?;
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit orderbook test block");
        state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&header));
        Ok(())
    }
    pub(super) fn state_with_accounts(keypairs: &[&KeyPair]) -> State {
        let authority = account(keypairs[0]);
        let asset_definition = settlement_asset_definition();
        let domain =
            Domain::new(DomainId::try_new("sorafs", "universal").expect("settlement domain"))
                .build(&authority);
        let definition = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let accounts = keypairs
            .iter()
            .map(|keypair| {
                let id = account(keypair);
                Account::new(id.clone()).build(&id)
            })
            .collect::<Vec<_>>();
        let assets = keypairs
            .iter()
            .map(|keypair| {
                Asset::new(
                    AssetId::of(asset_definition.clone(), account(keypair)),
                    micro_quantity(1_000_000_000),
                )
            })
            .collect::<Vec<_>>();
        let mut world = World::with_assets([domain], accounts, [definition], assets, []);
        let mut permissions = Permissions::new();
        permissions.insert(Permission::new(
            "CanSetSorafsPricing".to_owned(),
            Json::new(()),
        ));
        world.account_permissions.insert(authority, permissions);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.gov.sorafs_pin_fee_asset_id = asset_definition;
        state
    }
    fn settlement_asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("sorafs", "universal").expect("settlement domain"),
            "xor".parse().expect("settlement asset name"),
        )
    }
    fn micro_quantity(micro: u128) -> Quantity {
        XorQuantity::try_from_micro(micro)
            .expect("micro-XOR fixture is a valid quantity")
            .into_quantity()
    }
    pub(super) fn state_with_settlement_accounts(
        settlement: &KeyPair,
        buyer: &KeyPair,
        provider: &KeyPair,
        treasury: &KeyPair,
        buyer_balance_micro: u128,
    ) -> State {
        let settlement_id = account(settlement);
        let buyer_id = account(buyer);
        let provider_id = account(provider);
        let treasury_id = account(treasury);
        let asset_definition = settlement_asset_definition();
        let domain =
            Domain::new(DomainId::try_new("sorafs", "universal").expect("settlement domain"))
                .build(&buyer_id);
        let definition = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&buyer_id);
        let buyer_asset = Asset::new(
            AssetId::of(asset_definition.clone(), buyer_id.clone()),
            micro_quantity(buyer_balance_micro),
        );
        let mut world = World::with_assets(
            [domain],
            [
                Account::new(settlement_id.clone()).build(&settlement_id),
                Account::new(buyer_id.clone()).build(&buyer_id),
                Account::new(provider_id.clone()).build(&provider_id),
                Account::new(treasury_id.clone()).build(&treasury_id),
            ],
            [definition],
            [buyer_asset],
            [],
        );
        let mut permissions = Permissions::new();
        permissions.insert(Permission::new(
            "CanSetSorafsPricing".to_owned(),
            Json::new(()),
        ));
        world.account_permissions.insert(settlement_id, permissions);
        let mut state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.gov.sorafs_pin_fee_asset_id = asset_definition;
        state.gov.sorafs_pin_fee_treasury_account = treasury_id;
        state
    }
    fn open_settlement_lock(
        state_transaction: &mut StateTransaction<'_, '_>,
        buyer: &AccountId,
        provider: &AccountId,
        settlement: &AccountId,
        receipt: &SettlementReceiptV1,
    ) {
        let escrow_id = orderbook_settlement_escrow_id(receipt.channel_id);
        let parent_id = orderbook_order_escrow_id(receipt.trade_id);
        let amount = trade_escrow_requirement_v1(&test_trade(receipt.trade_id))
            .expect("fixture trade escrow")
            .into_quantity();
        let expires_at_ms = (NOW + 100) * 1_000;
        crate::smartcontracts::isi::escrow::open_orderbook_order_asset_lock(
            state_transaction,
            parent_id,
            buyer,
            settlement_asset_definition(),
            amount.clone(),
            expires_at_ms,
        )
        .expect("open native orderbook parent lock");
        crate::smartcontracts::isi::escrow::partition_orderbook_asset_lock(
            state_transaction,
            &parent_id,
            escrow_id,
            provider.clone(),
            settlement.clone(),
            amount.clone(),
            expires_at_ms,
        )
        .expect("partition funded settlement lock");
        crate::smartcontracts::isi::escrow::close_filled_orderbook_order_asset_lock(
            state_transaction,
            &parent_id,
            buyer,
            &settlement_asset_definition(),
            &amount,
            expires_at_ms,
        )
        .expect("close fully partitioned test parent");
        seed_settlement_channel(state_transaction, buyer, provider, settlement, receipt);
    }
    pub(super) fn seed_settlement_channel(
        state_transaction: &mut StateTransaction<'_, '_>,
        buyer: &AccountId,
        provider: &AccountId,
        settlement: &AccountId,
        receipt: &SettlementReceiptV1,
    ) {
        state_transaction
            .world
            .provider_owners
            .insert(ProviderId::new([0x71; 32]), provider.clone());
        let trade = test_trade(receipt.trade_id);
        assert_eq!(
            derive_orderbook_settlement_channel_id_v1(&trade).expect("derive fixture channel"),
            receipt.channel_id
        );
        let trade_record = OrderbookTradeRecord {
            trade_id: trade.trade_id,
            maker_order_id: trade.maker_order_id,
            taker_order_id: trade.taker_order_id,
            trade_sequence: 1,
            canonical_trade: encode(&trade),
            channel_id: receipt.channel_id,
            book_revision: 1,
            recorded_at_unix: trade.timestamp_unix,
        };
        let locked = trade_escrow_requirement_v1(&trade).expect("fixture trade escrow");
        let fee = trade_fee_requirement_v1(&trade).expect("fixture trade fee");
        let channel = OrderbookSettlementChannelRecord {
            channel_id: receipt.channel_id,
            trade_id: receipt.trade_id,
            buyer: buyer.clone(),
            provider: provider.clone(),
            provider_id: ProviderId::new([0x71; 32]),
            settlement_authority: settlement.clone(),
            total_bytes: BYTES_PER_GIB,
            remaining_bytes: BYTES_PER_GIB,
            initial_xor_locked: locked.clone(),
            remaining_xor_locked: locked,
            initial_fee_xor_locked: fee.clone(),
            remaining_fee_xor_locked: fee,
            status: OrderbookSettlementChannelStatusV1::Open,
            opened_at_unix: NOW - 2,
            expires_at_unix: NOW + 100,
            updated_at_unix: NOW - 2,
        };
        state_transaction
            .world
            .smart_contract_state
            .insert(trade_key(receipt.trade_id), encode(&trade_record));
        state_transaction
            .world
            .smart_contract_state
            .insert(channel_key(receipt.channel_id), encode(&channel));
        let mut status = read_status(state_transaction.world())
            .expect("read orderbook status")
            .expect("active policy status");
        status.trades = 1;
        status.settlement_channels = 1;
        status.open_settlement_channels = 1;
        status.book_revision = 1;
        status.next_trade_sequence = 2;
        status.updated_at_unix = NOW;
        state_transaction
            .world
            .smart_contract_state
            .insert(status_key().clone(), encode(&status));
    }
    fn asset_balance(
        state_transaction: &StateTransaction<'_, '_>,
        account: &AccountId,
    ) -> Quantity {
        state_transaction
            .world
            .assets
            .get(&AssetId::of(settlement_asset_definition(), account.clone()))
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }
    fn assert_no_receipt_status_mutation(state_transaction: &StateTransaction<'_, '_>) {
        let status = read_status(state_transaction.world())
            .expect("read orderbook status")
            .expect("active policy status");
        assert_eq!(status.settlement_receipts, 0);
        assert_eq!(status.settlement_channels, 1);
        assert_eq!(status.open_settlement_channels, 1);
    }
    fn assert_order_status(
        state_transaction: &StateTransaction<'_, '_>,
        open_orders: u64,
        cancelled_orders: u64,
    ) {
        let status = read_status(state_transaction.world())
            .expect("read orderbook status")
            .expect("active policy status");
        assert_eq!(status.open_orders, open_orders);
        assert_eq!(status.cancelled_orders, cancelled_orders);
    }
    pub(super) fn activate_policy(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
    ) -> [u8; 32] {
        let mut policy = policy();
        policy.matcher_authority = authority.clone();
        policy.settlement_authority = authority.clone();
        let digest = policy.digest().expect("digest policy");
        SetSorafsOrderbookPolicy::new(policy)
            .execute(authority, state_transaction)
            .expect("activate policy");
        digest
    }
    fn orderbook_reserve_policy(
        authority: &AccountId,
        custody: AccountId,
        treasury: AccountId,
    ) -> ReserveAuthorityPolicyV1 {
        ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: settlement_asset_definition(),
            custody_account: custody,
            treasury_account: treasury,
            operations_authority: authority.clone(),
            decision_authority: authority.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: xor_micro(1_000_000_000),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        }
    }
    fn activate_reserve_account(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        provider_id: ProviderId,
        provider: &AccountId,
    ) -> [u8; 32] {
        state_transaction
            .world
            .account_permissions
            .get_mut(authority)
            .expect("orderbook governance permissions")
            .insert(Permission::new(
                "CanSetSorafsReservePolicy".to_owned(),
                Json::new(()),
            ));
        let reserve_policy = orderbook_reserve_policy(
            authority,
            authority.clone(),
            state_transaction
                .gov
                .sorafs_pin_fee_treasury_account
                .clone(),
        );
        let policy_digest = reserve_policy.digest().expect("reserve policy digest");
        SetSorafsReservePolicy::new(reserve_policy)
            .execute(authority, state_transaction)
            .expect("activate reserve policy");
        RegisterSorafsReserveAccount::new(
            ReserveProviderTermsV1 {
                provider_id,
                provider_account: provider.clone(),
                tier: ReserveTier::TierA,
                storage_class: StorageClass::Hot,
                duration: ReserveDuration::Monthly,
                capacity_gib: 10,
            },
            policy_digest,
        )
        .execute(authority, state_transaction)
        .expect("register authoritative reserve account");
        policy_digest
    }
    struct TwoFillMatchFixture {
        policy_digest: [u8; 32],
        order_ids: [[u8; 32]; 4],
        parent_ids: [iroha_data_model::escrow::EscrowId; 2],
        trade_ids: [[u8; 32]; 2],
        channel_ids: [[u8; 32]; 2],
    }
    struct TwoFillMatchSnapshot {
        status: OrderbookLedgerStatusV1,
        orders: [OrderbookOrderRecord; 4],
        parents: [iroha_data_model::escrow::AssetEscrowRecord; 2],
        custody_balances: [Quantity; 2],
    }
    fn seed_two_fill_match(
        state_transaction: &mut StateTransaction<'_, '_>,
        settlement_id: &AccountId,
        buyer_id: &AccountId,
        provider_id: &AccountId,
        buyer: &KeyPair,
        provider: &KeyPair,
    ) -> TwoFillMatchFixture {
        let policy_digest = activate_policy(state_transaction, settlement_id);
        state_transaction
            .world
            .provider_owners
            .insert(ProviderId::new([0x72; 32]), provider_id.clone());
        activate_reserve_account(
            state_transaction,
            settlement_id,
            ProviderId::new([0x72; 32]),
            provider_id,
        );
        let mut bid_one = order(buyer, 1);
        bid_one.quantity_gib = 5;
        bid_one.remaining_gib = 5;
        let bid_one = sign_order(bid_one, buyer);
        let mut bid_two = order(buyer, 2);
        bid_two.quantity_gib = 5;
        bid_two.remaining_gib = 5;
        let bid_two = sign_order(bid_two, buyer);
        let ask_one = ask_order(provider, 1, 90, 5);
        let ask_two = ask_order(provider, 2, 90, 5);
        SubmitSorafsOrderbookOrder::new(encode(&bid_one), policy_digest)
            .execute(buyer_id, state_transaction)
            .expect("admit first bid");
        SubmitSorafsOrderbookOrder::new(encode(&bid_two), policy_digest)
            .execute(buyer_id, state_transaction)
            .expect("admit second bid");
        SubmitSorafsOrderbookOrder::new(encode(&ask_one), policy_digest)
            .execute(provider_id, state_transaction)
            .expect("admit first ask");
        SubmitSorafsOrderbookOrder::new(encode(&ask_two), policy_digest)
            .execute(provider_id, state_transaction)
            .expect("admit second ask");
        let parent_one = orderbook_order_escrow_id(bid_one.order_id);
        let parent_two = orderbook_order_escrow_id(bid_two.order_id);
        let trade_one_id = derive_orderbook_trade_id_v1(1, &bid_one, &ask_one, NOW);
        let trade_one = match_orders_v1(&bid_one, &ask_one, trade_one_id, NOW)
            .expect("derive first deterministic fill")
            .trade;
        let trade_two_id = derive_orderbook_trade_id_v1(2, &bid_two, &ask_two, NOW);
        let trade_two = match_orders_v1(&bid_two, &ask_two, trade_two_id, NOW)
            .expect("derive second deterministic fill")
            .trade;
        let channel_one = derive_orderbook_settlement_channel_id_v1(&trade_one)
            .expect("derive first deterministic channel");
        let channel_two = derive_orderbook_settlement_channel_id_v1(&trade_two)
            .expect("derive second deterministic channel");
        TwoFillMatchFixture {
            policy_digest,
            order_ids: [
                bid_one.order_id,
                bid_two.order_id,
                ask_one.order_id,
                ask_two.order_id,
            ],
            parent_ids: [parent_one, parent_two],
            trade_ids: [trade_one_id, trade_two_id],
            channel_ids: [channel_one, channel_two],
        }
    }
    fn snapshot_two_fill_match(
        state_transaction: &StateTransaction<'_, '_>,
        fixture: &TwoFillMatchFixture,
    ) -> TwoFillMatchSnapshot {
        TwoFillMatchSnapshot {
            status: read_status(state_transaction.world())
                .expect("read two-fill status")
                .expect("active two-fill status"),
            orders: core::array::from_fn(|index| {
                read_order(state_transaction.world(), fixture.order_ids[index])
                    .expect("read two-fill order")
                    .expect("stored two-fill order")
            }),
            parents: core::array::from_fn(|index| {
                state_transaction
                    .world
                    .asset_escrows
                    .get(&fixture.parent_ids[index])
                    .expect("stored two-fill parent custody")
                    .clone()
            }),
            custody_balances: core::array::from_fn(|index| {
                let custody = &state_transaction
                    .world
                    .asset_escrows
                    .get(&fixture.parent_ids[index])
                    .expect("stored two-fill parent custody")
                    .custody;
                asset_balance(state_transaction, custody)
            }),
        }
    }
    fn assert_two_fill_match_unchanged(
        state_transaction: &StateTransaction<'_, '_>,
        fixture: &TwoFillMatchFixture,
        before: &TwoFillMatchSnapshot,
        expected_markers: [bool; 2],
    ) {
        assert_eq!(
            read_status(state_transaction.world())
                .expect("read unchanged two-fill status")
                .expect("active unchanged two-fill status"),
            before.status
        );
        for (index, order_id) in fixture.order_ids.iter().enumerate() {
            assert_eq!(
                read_order(state_transaction.world(), *order_id)
                    .expect("read unchanged two-fill order")
                    .expect("stored unchanged two-fill order"),
                before.orders[index]
            );
        }
        for (index, parent_id) in fixture.parent_ids.iter().enumerate() {
            let parent = state_transaction
                .world
                .asset_escrows
                .get(parent_id)
                .expect("unchanged two-fill parent custody");
            assert_eq!(parent, &before.parents[index]);
            assert_eq!(
                asset_balance(state_transaction, &parent.custody),
                before.custody_balances[index]
            );
        }
        for index in 0..2 {
            assert!(
                read_trade(state_transaction.world(), fixture.trade_ids[index])
                    .expect("read absent two-fill trade")
                    .is_none()
            );
            assert!(
                read_channel(state_transaction.world(), fixture.channel_ids[index])
                    .expect("read absent two-fill channel")
                    .is_none()
            );
            let child_id = orderbook_settlement_escrow_id(fixture.channel_ids[index]);
            assert!(
                state_transaction
                    .world
                    .asset_escrows
                    .get(&child_id)
                    .is_none()
            );
            assert_eq!(
                crate::smartcontracts::isi::escrow::is_orderbook_channel_lock(
                    state_transaction.world(),
                    &child_id,
                )
                .expect("read two-fill channel marker"),
                expected_markers[index]
            );
        }
    }
    fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
        norito::to_bytes(value).expect("encode canonical fixture")
    }
    include!("sorafs/orderbook_policy_tests.rs");
    #[test]
    fn policy_activation_rejects_missing_permission_without_state_mutation() {
        let operator = keypair(0x12);
        let authority = account(&operator);
        let state = state_with_accounts(&[&operator]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        stx.world
            .account_permissions
            .get_mut(&authority)
            .expect("permissions")
            .retain(|permission| permission.name() != "CanSetSorafsPricing");
        assert!(
            SetSorafsOrderbookPolicy::new(policy())
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(read_policy(stx.world()).expect("read policy").is_none());
    }
    #[test]
    fn orderbook_numeric_custody_requires_original_retained_component_source() {
        let buyer = keypair(0xE1);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer]);
        let candidate = order(&buyer, 1);
        let initial_balance;
        {
            let mut block = state.block(block_header());
            let mut stx = block.transaction();
            let policy_digest = activate_policy(&mut stx, &authority);
            initial_balance = asset_balance(&stx, &authority);
            let error = SubmitSorafsOrderbookOrder::new(encode(&candidate), policy_digest)
                .execute(&authority, &mut stx)
                .expect_err("unretained component input cannot fund bid custody");
            let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                reason,
            )) = &error
            else {
                panic!("unexpected source refusal: {error:?}");
            };
            assert!(
                reason.contains("protocol source has no authenticated mandatory owner"),
                "source refusal: {error:?}"
            );
            assert_eq!(asset_balance(&stx, &authority), initial_balance);
            assert!(
                read_order(stx.world(), candidate.order_id)
                    .expect("read refused order")
                    .is_none()
            );
            assert!(
                read_nonce(stx.world(), &authority)
                    .expect("read refused nonce")
                    .is_none()
            );
            assert!(
                stx.world
                    .asset_escrows
                    .get(&orderbook_order_escrow_id(candidate.order_id))
                    .is_none()
            );
        }
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        SubmitSorafsOrderbookOrder::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .expect("the same signed order uses its original bounded component slot");
        let required = bid_order_escrow_requirement_v1(
            &candidate,
            policy().max_maker_fee_bps,
            policy().max_taker_fee_bps,
        )
        .expect("derive original bid custody");
        assert_eq!(
            asset_balance(&stx, &authority),
            initial_balance
                .checked_sub(&required.into_quantity())
                .expect("exact custody debit")
        );
        assert_eq!(
            read_nonce(stx.world(), &authority)
                .expect("read admitted nonce")
                .expect("admitted nonce")
                .highest_nonce,
            candidate.nonce
        );
        assert_eq!(
            read_order(stx.world(), candidate.order_id)
                .expect("read admitted order")
                .expect("admitted order")
                .canonical_order,
            encode(&candidate)
        );
    }
    #[test]
    fn signed_order_submission_persists_authoritative_record_and_nonce() {
        let buyer = keypair(0x21);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let order = order(&buyer, 1);
        let initial_balance = asset_balance(&stx, &authority);
        let required = bid_order_escrow_requirement_v1(
            &order,
            policy().max_maker_fee_bps,
            policy().max_taker_fee_bps,
        )
        .expect("derive full-order bid custody");
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .expect("submit order");
        let stored = read_order(stx.world(), order.order_id)
            .expect("read order")
            .expect("stored order");
        assert_eq!(stored.owner, authority);
        assert_eq!(stored.status, OrderbookOrderStatusV1::Open);
        assert_eq!(stored.admitted_policy_digest, policy_digest);
        let binding = stored.bid_escrow.expect("bid custody binding");
        assert_eq!(binding.escrow_id, orderbook_order_escrow_id(order.order_id));
        assert_eq!(binding.asset_definition, settlement_asset_definition());
        assert_eq!(binding.initial_xor_locked, required);
        let escrow = stx
            .world
            .asset_escrows
            .get(&binding.escrow_id)
            .expect("funded bid custody");
        assert_eq!(escrow.amount, required.clone().into_quantity());
        assert_eq!(escrow.remaining_amount, required.clone().into_quantity());
        assert_eq!(
            asset_balance(&stx, &escrow.custody),
            required.clone().into_quantity()
        );
        assert_eq!(
            asset_balance(&stx, &authority),
            initial_balance
                .checked_sub(&required.into_quantity())
                .expect("buyer lock subtraction")
        );
        assert!(
            crate::smartcontracts::isi::escrow::is_orderbook_order_lock(
                stx.world(),
                &binding.escrow_id,
            )
            .expect("read bid custody marker")
        );
        assert_eq!(
            read_nonce(stx.world(), &authority)
                .expect("read nonce")
                .expect("stored nonce")
                .highest_nonce,
            1
        );
    }
    #[test]
    fn underfunded_bid_admission_is_atomic() {
        let settlement = keypair(0x1B);
        let buyer = keypair(0x1C);
        let provider = keypair(0x1D);
        let treasury = keypair(0x1E);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 1_000);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &settlement_id);
        let bid = order(&buyer, 1);
        let escrow_id = orderbook_order_escrow_id(bid.order_id);
        let initial_balance = asset_balance(&stx, &buyer_id);
        SubmitSorafsOrderbookOrder::new(encode(&bid), policy_digest)
            .execute(&buyer_id, &mut stx)
            .expect_err("full gross plus conservative fees exceed the buyer balance");
        assert_eq!(asset_balance(&stx, &buyer_id), initial_balance);
        assert!(stx.world.asset_escrows.get(&escrow_id).is_none());
        assert!(
            !crate::smartcontracts::isi::escrow::is_orderbook_order_lock(stx.world(), &escrow_id,)
                .expect("read absent bid marker")
        );
        assert!(
            read_order(stx.world(), bid.order_id)
                .expect("read absent bid")
                .is_none()
        );
        assert!(
            read_nonce(stx.world(), &buyer_id)
                .expect("read absent nonce")
                .is_none()
        );
        assert_order_status(&stx, 0, 0);
    }
    #[test]
    fn order_rejects_malformed_noncanonical_and_oversized_payloads_atomically() {
        let buyer = keypair(0x22);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let order = order(&buyer, 1);
        let mut noncanonical = encode(&order);
        noncanonical.push(0);
        for payload in [vec![0xFF; 32], noncanonical, vec![0; 64 * 1024 + 1]] {
            assert!(
                SubmitSorafsOrderbookOrder::new(payload, policy_digest)
                    .execute(&authority, &mut stx)
                    .is_err()
            );
            assert!(
                read_order(stx.world(), order.order_id)
                    .expect("read order")
                    .is_none()
            );
            assert!(
                read_nonce(stx.world(), &authority)
                    .expect("read nonce")
                    .is_none()
            );
        }
    }
    #[test]
    fn order_policy_failures_do_not_advance_nonce() {
        let buyer = keypair(0x23);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let base = order(&buyer, 1);
        let mut candidates = Vec::new();
        let mut candidate = base.clone();
        candidate.remaining_gib = 9;
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.quantity_gib = 1;
        candidate.remaining_gib = 1;
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.price_per_gib = xor_micro(101);
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.price_per_gib = "0.000100001"
            .parse()
            .expect("canonical sub-micro XOR fixture");
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.maker_fee_bps = 101;
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.expiry_unix = NOW;
        candidates.push(candidate);
        let mut candidate = base.clone();
        candidate.expiry_unix = NOW + policy().max_order_lifetime_secs + 1;
        candidates.push(candidate);
        for candidate in candidates {
            let candidate = sign_order(candidate, &buyer);
            assert!(
                SubmitSorafsOrderbookOrder::new(encode(&candidate), policy_digest)
                    .execute(&authority, &mut stx)
                    .is_err()
            );
            assert!(
                read_order(stx.world(), base.order_id)
                    .expect("read order")
                    .is_none()
            );
            assert!(
                read_nonce(stx.world(), &authority)
                    .expect("read nonce")
                    .is_none()
            );
        }
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&base), [0x99; 32])
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(
            read_nonce(stx.world(), &authority)
                .expect("read nonce")
                .is_none()
        );
        assert_order_status(&stx, 0, 0);
    }
    #[test]
    fn order_rejects_wrong_owner_signer_and_tampering_atomically() {
        let buyer = keypair(0x24);
        let attacker = keypair(0x25);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer, &attacker]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let base = order(&buyer, 1);
        let wrong_signer = sign_order(base.clone(), &attacker);
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&wrong_signer), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let wrong_owner = order(&attacker, 1);
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&wrong_owner), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let mut tampered = base.clone();
        tampered.quantity_gib += 1;
        tampered.remaining_gib += 1;
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&tampered), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(
            read_nonce(stx.world(), &authority)
                .expect("read nonce")
                .is_none()
        );
        assert!(
            read_order(stx.world(), base.order_id)
                .expect("read order")
                .is_none()
        );
    }
    #[test]
    fn ask_admission_requires_non_default_reserve_while_bids_remain_unaffected() {
        let settlement = keypair(0x26);
        let buyer = keypair(0x27);
        let provider = keypair(0x28);
        let treasury = keypair(0x29);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_account = account(&provider);
        let provider_id = ProviderId::new([0x72; 32]);
        let mut state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut orderbook_policy_digest = [0; 32];
        let mut reserve_policy_digest = [0; 32];
        transact(&mut state, 1, NOW, |transaction| {
            orderbook_policy_digest = activate_policy(transaction, &settlement_id);
            transaction
                .world
                .provider_owners
                .insert(provider_id, provider_account.clone());
            let ask_without_reserve = ask_order(&provider, 1, 90, 5);
            assert!(
                SubmitSorafsOrderbookOrder::new(
                    encode(&ask_without_reserve),
                    orderbook_policy_digest,
                )
                .execute(&provider_account, transaction)
                .is_err(),
                "registry ownership alone cannot replace an authoritative reserve account"
            );
            reserve_policy_digest = activate_reserve_account(
                transaction,
                &settlement_id,
                provider_id,
                &provider_account,
            );
            Ok(())
        })
        .expect("configure authoritative orderbook and reserve state");
        let default_at = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1 + 31 * 86_400;
        transact(&mut state, 2, default_at, |transaction| {
            AdvanceSorafsReserveLifecycle::new(provider_id, 1, 31, reserve_policy_digest)
                .execute(&settlement_id, transaction)?;
            let mut ask = ask_order(&provider, 1, 90, 5);
            ask.expiry_unix = default_at + 100;
            let ask = sign_order(ask, &provider);
            assert!(
                SubmitSorafsOrderbookOrder::new(encode(&ask), orderbook_policy_digest)
                    .execute(&provider_account, transaction)
                    .is_err(),
                "reserve Default disables new asks"
            );
            let mut bid = order(&buyer, 1);
            bid.expiry_unix = default_at + 100;
            let bid = sign_order(bid, &buyer);
            SubmitSorafsOrderbookOrder::new(encode(&bid), orderbook_policy_digest)
                .execute(&buyer_id, transaction)
                .expect("bid admission is independent of provider reserve state");
            SubmitSorafsReserveAppeal::new(
                [0x81; 32],
                provider_id,
                2,
                ReserveLifecycleStage::Active,
                "restore advert eligibility".to_owned(),
                Some([0x82; 32]),
                reserve_policy_digest,
            )
            .execute(&provider_account, transaction)?;
            DecideSorafsReserveAppeal::new(
                [0x81; 32],
                3,
                reserve_policy_digest,
                true,
                "reserve evidence accepted".to_owned(),
            )
            .execute(&settlement_id, transaction)?;
            assert_eq!(
                super::super::sorafs_reserve::read_provider(transaction.world(), provider_id)?
                    .expect("reserve provider")
                    .lifecycle_stage,
                ReserveLifecycleStage::Active
            );
            SubmitSorafsOrderbookOrder::new(encode(&ask), orderbook_policy_digest)
                .execute(&provider_account, transaction)
                .expect("accepted lifecycle appeal restores new-ask eligibility");
            Ok(())
        })
        .expect("default, bid, and accepted-appeal admission transitions");
    }
    #[test]
    fn order_replay_and_nonce_rollback_are_rejected() {
        let buyer = keypair(0x27);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let first = order(&buyer, 1);
        SubmitSorafsOrderbookOrder::new(encode(&first), policy_digest)
            .execute(&authority, &mut stx)
            .expect("first order");
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&first), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let third = order(&buyer, 3);
        SubmitSorafsOrderbookOrder::new(encode(&third), policy_digest)
            .execute(&authority, &mut stx)
            .expect("higher nonce order");
        let second = order(&buyer, 2);
        assert!(
            SubmitSorafsOrderbookOrder::new(encode(&second), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(
            read_order(stx.world(), second.order_id)
                .expect("read order")
                .is_none()
        );
        assert_eq!(
            read_nonce(stx.world(), &authority)
                .expect("read nonce")
                .expect("nonce")
                .highest_nonce,
            3
        );
    }
    #[test]
    fn typed_order_queries_return_policy_cancellation_status_and_cursor_pages() {
        let buyer = keypair(0x28);
        let authority = account(&buyer);
        let mut state = state_with_accounts(&[&buyer]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let first = order(&buyer, 1);
        let second = order(&buyer, 2);
        let third = order(&buyer, 3);
        for candidate in [&first, &second, &third] {
            SubmitSorafsOrderbookOrder::new(encode(candidate), policy_digest)
                .execute(&authority, &mut stx)
                .expect("submit query fixture order");
        }
        let cancellation = cancel(&buyer, second.order_id, 4);
        CancelSorafsOrderbookOrder::new(encode(&cancellation), policy_digest)
            .execute(&authority, &mut stx)
            .expect("cancel query fixture order");
        let found_policy = FindSorafsOrderbookPolicy
            .execute(&stx)
            .expect("query active policy");
        assert_eq!(found_policy.policy_digest, policy_digest);
        let found_order = FindSorafsOrderbookOrderById::new(first.order_id)
            .execute(&stx)
            .expect("query order by id");
        assert_eq!(found_order.order_id, first.order_id);
        let found_cancellation = FindSorafsOrderbookCancellationByOrderId::new(second.order_id)
            .execute(&stx)
            .expect("query cancellation by order id");
        assert_eq!(found_cancellation.canonical_cancel, encode(&cancellation));
        assert_eq!(found_cancellation.cancelled_policy_digest, policy_digest);
        assert!(
            FindSorafsOrderbookCancellationByOrderId::new(first.order_id)
                .execute(&stx)
                .is_err(),
            "an open order must not be exposed as a cancellation"
        );
        let status = FindSorafsOrderbookStatus
            .execute(&stx)
            .expect("query orderbook status");
        assert_eq!(status.open_orders, 2);
        assert_eq!(status.cancelled_orders, 1);
        assert_eq!(status.settlement_receipts, 0);
        assert_eq!(status.settlement_channels, 0);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit order query fixture");
        state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&block_header()));
        let view = state.view();
        let first_page = FindSorafsOrderbookOrders::new(None, None, None, 2)
            .execute(&view)
            .expect("query first order page");
        assert_eq!(first_page.finalized_cursor.height, 1);
        assert_eq!(first_page.orders.len(), 2);
        assert!(first_page.has_more);
        let finalized_cursor = first_page.finalized_cursor;
        let cursor = first_page.next_after_order_id.expect("next cursor");
        let second_page =
            FindSorafsOrderbookOrders::new(Some(finalized_cursor), None, Some(cursor), 2)
                .execute(&view)
                .expect("query second order page");
        assert_eq!(second_page.finalized_cursor, finalized_cursor);
        assert_eq!(second_page.orders.len(), 1);
        assert!(!second_page.has_more);
        assert!(second_page.next_after_order_id.is_none());
        let mut returned_ids = first_page
            .orders
            .iter()
            .chain(&second_page.orders)
            .map(|record| record.order_id)
            .collect::<Vec<_>>();
        assert!(returned_ids.windows(2).all(|ids| ids[0] < ids[1]));
        returned_ids.sort_unstable();
        let mut expected_ids = vec![first.order_id, second.order_id, third.order_id];
        expected_ids.sort_unstable();
        assert_eq!(returned_ids, expected_ids);
        let cancelled_page = FindSorafsOrderbookOrders::new(
            Some(finalized_cursor),
            Some(OrderbookOrderStatusV1::Cancelled),
            None,
            10,
        )
        .execute(&view)
        .expect("query cancelled order page");
        assert_eq!(cancelled_page.orders.len(), 1);
        assert_eq!(cancelled_page.orders[0].order_id, second.order_id);
        let mut stale_cursor = finalized_cursor;
        stale_cursor.block_hash[0] ^= 0xFF;
        assert_eq!(
            FindSorafsOrderbookOrders::new(Some(stale_cursor), None, None, 1).execute(&view),
            Err(QueryExecutionFail::Expired)
        );
        let first_events = FindSorafsOrderbookEvents::new(Some(finalized_cursor), None, 2)
            .execute(&view)
            .expect("query first committed-event page");
        assert_eq!(first_events.finalized_cursor, finalized_cursor);
        assert_eq!(first_events.events.len(), 2);
        assert!(first_events.has_more);
        for (index, event) in first_events.events.iter().enumerate() {
            assert_eq!(
                event.sequence,
                u64::try_from(index + 1).expect("small index")
            );
            assert_eq!(event.block_height, 1);
            assert_eq!(event.block_hash, finalized_cursor.block_hash);
            assert_eq!(
                event.event_index,
                u32::try_from(index).expect("small index")
            );
        }
        let event_cursor = first_events.next_after.expect("event continuation cursor");
        let second_events =
            FindSorafsOrderbookEvents::new(Some(finalized_cursor), Some(event_cursor), 10)
                .execute(&view)
                .expect("query second committed-event page");
        assert_eq!(second_events.events.len(), 3);
        assert!(!second_events.has_more);
        assert_eq!(
            second_events
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert!(
            second_events
                .events
                .iter()
                .enumerate()
                .all(|(offset, event)| {
                    event.block_height == 1
                        && event.block_hash == finalized_cursor.block_hash
                        && event.event_index
                            == u32::try_from(offset + 2).expect("small event index")
                })
        );
        let mut tampered_event_cursor = event_cursor;
        tampered_event_cursor.event_index += 1;
        assert_eq!(
            FindSorafsOrderbookEvents::new(Some(finalized_cursor), Some(tampered_event_cursor), 1,)
                .execute(&view),
            Err(QueryExecutionFail::Expired)
        );
    }
    include!("sorafs_orderbook/schema_preserved_tests.rs");
    #[test]
    fn committed_event_queries_fail_closed_on_corrupt_journals() {
        let operator = keypair(0x2B);
        let authority = account(&operator);
        let mut missing_head = state_with_accounts(&[&operator]);
        transact(&mut missing_head, 1, NOW, |transaction| {
            activate_policy(transaction, &authority);
            transaction
                .world
                .smart_contract_state
                .remove(event_journal_head_key().clone());
            Ok(())
        })
        .expect("commit missing-head fixture");
        assert!(matches!(
            FindSorafsOrderbookEvents::new(None, None, 10).execute(&missing_head.view()),
            Err(QueryExecutionFail::Conversion(_))
        ));
        let mut malformed_event = state_with_accounts(&[&operator]);
        transact(&mut malformed_event, 1, NOW, |transaction| {
            activate_policy(transaction, &authority);
            transaction
                .world
                .smart_contract_state
                .insert(event_key(1), vec![0xFF; 16]);
            Ok(())
        })
        .expect("commit malformed-event fixture");
        assert!(matches!(
            FindSorafsOrderbookEvents::new(None, None, 10).execute(&malformed_event.view()),
            Err(QueryExecutionFail::Conversion(_))
        ));
        let mut orphan_event = state_with_accounts(&[&operator]);
        transact(&mut orphan_event, 1, NOW, |transaction| {
            activate_policy(transaction, &authority);
            let mut orphan = read_persisted_event(transaction.world(), 1)
                .expect("read initial event")
                .expect("initial event exists");
            orphan.sequence = 2;
            orphan.event_index = 1;
            transaction
                .world
                .smart_contract_state
                .insert(event_key(2), encode(&orphan));
            Ok(())
        })
        .expect("commit orphan-event fixture");
        assert!(matches!(
            FindSorafsOrderbookEvents::new(None, None, 10).execute(&orphan_event.view()),
            Err(QueryExecutionFail::Conversion(_))
        ));
        let mut missing_middle = state_with_accounts(&[&operator]);
        let mut policy_digest = [0; 32];
        transact(&mut missing_middle, 1, NOW, |transaction| {
            policy_digest = activate_policy(transaction, &authority);
            Ok(())
        })
        .expect("commit missing-middle policy");
        let first = order(&operator, 1);
        let second = order(&operator, 2);
        transact(&mut missing_middle, 2, NOW + 1, |transaction| {
            SubmitSorafsOrderbookOrder::new(encode(&first), policy_digest)
                .execute(&authority, transaction)?;
            SubmitSorafsOrderbookOrder::new(encode(&second), policy_digest)
                .execute(&authority, transaction)?;
            transaction.world.smart_contract_state.remove(event_key(2));
            Ok(())
        })
        .expect("commit missing-middle fixture");
        assert!(matches!(
            FindSorafsOrderbookEvents::new(None, None, 10).execute(&missing_middle.view()),
            Err(QueryExecutionFail::Conversion(_))
        ));
    }
    include!("sorafs/orderbook_nonce_tests.rs");
    #[test]
    fn cancellation_rejects_unknown_wrong_owner_wrong_policy_and_stale_nonce() {
        let buyer = keypair(0x32);
        let attacker = keypair(0x33);
        let authority = account(&buyer);
        let state = state_with_accounts(&[&buyer, &attacker]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &authority);
        let order = order(&buyer, 2);
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .expect("order");
        let unknown = cancel(&buyer, [0xFE; 32], 3);
        assert!(
            CancelSorafsOrderbookOrder::new(encode(&unknown), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let wrong_owner = cancel(&attacker, order.order_id, 3);
        assert!(
            CancelSorafsOrderbookOrder::new(encode(&wrong_owner), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let stale = cancel(&buyer, order.order_id, 1);
        assert!(
            CancelSorafsOrderbookOrder::new(encode(&stale), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let valid = cancel(&buyer, order.order_id, 3);
        assert!(
            CancelSorafsOrderbookOrder::new(encode(&valid), [0xDD; 32])
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert_eq!(
            read_order(stx.world(), order.order_id)
                .expect("read order")
                .expect("order")
                .status,
            OrderbookOrderStatusV1::Open
        );
        assert_eq!(
            read_nonce(stx.world(), &authority)
                .expect("read nonce")
                .expect("nonce")
                .highest_nonce,
            2
        );
        assert_order_status(&stx, 1, 0);
    }
    #[test]
    fn candidate_scan_is_linear_and_sorting_is_n_log_n_for_adversarial_same_owner_books() {
        let owner = keypair(0x31);
        let other = keypair(0x32);
        let owner_id = account(&owner);
        let other_id = account(&other);
        let mut orders = Vec::with_capacity(ORDERBOOK_MAX_OPEN_ORDERS_V1 as usize);
        let ask_count = 2_048_u64;
        let self_bid_count = 2_047_u64;
        for offset in 0..ask_count {
            orders.push(working_order(
                ask_order(&owner, offset + 1, 100, 1),
                &owner_id,
                offset + 1,
            ));
        }
        for offset in 0..self_bid_count {
            let mut bid = order(&owner, ask_count + offset + 1);
            bid.price_per_gib = xor_micro(200);
            let bid = sign_order(bid, &owner);
            orders.push(working_order(bid, &owner_id, ask_count + offset + 1));
        }
        let excluded = BTreeSet::new();
        let mut no_match_work = MatchCandidateWorkV1::default();
        assert_eq!(
            best_crossing_pair_with_work(&orders, &excluded, NOW, &mut no_match_work),
            None,
            "a same-owner-only crossing book is exhaustively proven ineligible"
        );
        assert!(
            no_match_work.order_filter_visits <= orders.len() * 3,
            "each tier may inspect each order once"
        );
        assert!(
            no_match_work.alternative_ask_visits <= ask_count as usize,
            "the alternative ask is precomputed once"
        );
        assert!(
            no_match_work.bid_candidate_visits <= self_bid_count as usize,
            "each sorted bid is considered once"
        );
        assert!(
            no_match_work
                .bid_sort_comparisons
                .saturating_add(no_match_work.ask_sort_comparisons)
                <= orders.len() * 32,
            "sorting comparisons stay within an O(N log N) ceiling at the admitted V1 book bound"
        );
        let mut external_bid = order(&other, 1);
        external_bid.price_per_gib = xor_micro(200);
        let external_bid = sign_order(external_bid, &other);
        orders.push(working_order(
            external_bid,
            &other_id,
            ask_count + self_bid_count + 1,
        ));
        assert_eq!(orders.len(), ORDERBOOK_MAX_OPEN_ORDERS_V1 as usize);
        let mut match_work = MatchCandidateWorkV1::default();
        let (bid, ask) = best_crossing_pair_with_work(&orders, &excluded, NOW, &mut match_work)
            .expect("the unrelated final bid crosses the first ask");
        assert_eq!(orders[bid].record.owner, other_id);
        assert_eq!(orders[ask].record.owner, owner_id);
        assert!(
            match_work.order_filter_visits
                + match_work.alternative_ask_visits
                + match_work.bid_candidate_visits
                <= orders.len() * 3,
            "candidate work remains linear at the maximum admitted book size"
        );
        assert!(
            match_work
                .bid_sort_comparisons
                .saturating_add(match_work.ask_sort_comparisons)
                <= orders.len() * 32,
            "sorting comparisons stay within an O(N log N) ceiling at the admitted V1 book bound"
        );
    }
    #[test]
    fn zero_fill_match_seals_the_unchanged_revision_and_rejects_replay() {
        let settlement = keypair(0x27);
        let buyer = keypair(0x28);
        let provider = keypair(0x29);
        let treasury = keypair(0x2A);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x2B; Hash::LENGTH]));
        let policy_digest = activate_policy(&mut stx, &settlement_id);
        stx.world
            .provider_owners
            .insert(ProviderId::new([0x72; 32]), provider_id.clone());
        activate_reserve_account(
            &mut stx,
            &settlement_id,
            ProviderId::new([0x72; 32]),
            &provider_id,
        );
        let bid = order(&buyer, 1);
        let ask = ask_order(&provider, 1, 110, 5);
        SubmitSorafsOrderbookOrder::new(encode(&bid), policy_digest)
            .execute(&buyer_id, &mut stx)
            .expect("admit non-crossing bid");
        SubmitSorafsOrderbookOrder::new(encode(&ask), policy_digest)
            .execute(&provider_id, &mut stx)
            .expect("admit non-crossing ask");
        MatchSorafsOrderbook::new(policy_digest, 2, 1)
            .execute(&settlement_id, &mut stx)
            .expect("complete exhaustive no-fill scan");
        let sealed = read_status(stx.world())
            .expect("read status")
            .expect("status");
        assert_eq!(sealed.book_revision, 2);
        assert_eq!(sealed.last_match_scan_book_revision, 2);
        assert_eq!(sealed.trades, 0);
        assert!(
            MatchSorafsOrderbook::new(policy_digest, 2, 1)
                .execute(&settlement_id, &mut stx)
                .is_err(),
            "the exact unchanged revision may be exhaustively scanned only once"
        );
    }
    #[test]
    fn matching_seals_only_when_exhausted_below_the_fill_cap() {
        let settlement = keypair(0x2C);
        let buyer = keypair(0x2D);
        let provider = keypair(0x2E);
        let treasury = keypair(0x2F);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let capped_state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut capped_block = capped_state.block(block_header());
        let mut capped =
            capped_block.transaction_for_fastpq_testing(Hash::prehashed([0x30; Hash::LENGTH]));
        let capped_fixture = seed_two_fill_match(
            &mut capped,
            &settlement_id,
            &buyer_id,
            &provider_id,
            &buyer,
            &provider,
        );
        MatchSorafsOrderbook::new(capped_fixture.policy_digest, 4, 1)
            .execute(&settlement_id, &mut capped)
            .expect("execute exactly one capped fill");
        let capped_status = read_status(capped.world())
            .expect("read capped status")
            .expect("capped status");
        assert_eq!(capped_status.book_revision, 5);
        assert_eq!(capped_status.last_match_scan_book_revision, 0);
        assert_eq!(capped_status.trades, 1);
        let exhausted_state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut exhausted_block = exhausted_state.block(block_header());
        let mut exhausted =
            exhausted_block.transaction_for_fastpq_testing(Hash::prehashed([0x31; Hash::LENGTH]));
        let exhausted_fixture = seed_two_fill_match(
            &mut exhausted,
            &settlement_id,
            &buyer_id,
            &provider_id,
            &buyer,
            &provider,
        );
        MatchSorafsOrderbook::new(exhausted_fixture.policy_digest, 4, 4)
            .execute(&settlement_id, &mut exhausted)
            .expect("fill the crossing book below the cap and prove exhaustion");
        let exhausted_status = read_status(exhausted.world())
            .expect("read exhausted status")
            .expect("exhausted status");
        assert_eq!(exhausted_status.book_revision, 5);
        assert_eq!(exhausted_status.last_match_scan_book_revision, 5);
        assert_eq!(exhausted_status.trades, 2);
        for parent_id in exhausted_fixture.parent_ids {
            let parent = exhausted
                .world
                .asset_escrows
                .get(&parent_id)
                .expect("closed fully filled bid custody");
            assert_eq!(
                parent.status,
                iroha_data_model::escrow::AssetEscrowStatus::DrawnDown
            );
            assert_eq!(parent.remaining_amount, Quantity::zero());
            assert_eq!(
                asset_balance(&exhausted, &parent.custody),
                Quantity::zero(),
                "conservative limit-price/fee surplus is refunded on the final fill"
            );
        }
    }
    #[test]
    fn matching_is_price_time_deterministic_revisioned_and_custody_backed() {
        let settlement = keypair(0x34);
        let buyer = keypair(0x35);
        let provider = keypair(0x36);
        let treasury = keypair(0x37);
        let attacker = keypair(0x38);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let attacker_id = account(&attacker);
        let mut state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let (attacker_key, attacker_value) = Account::new(attacker_id.clone())
            .build(&attacker_id)
            .into_key_value();
        state.world.accounts.insert(attacker_key, attacker_value);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x90; Hash::LENGTH]));
        let policy_digest = activate_policy(&mut stx, &settlement_id);
        stx.world
            .provider_owners
            .insert(ProviderId::new([0x72; 32]), provider_id.clone());
        activate_reserve_account(
            &mut stx,
            &settlement_id,
            ProviderId::new([0x72; 32]),
            &provider_id,
        );
        stx.world
            .provider_owners
            .insert(ProviderId::new([0x73; 32]), provider_id.clone());
        stx.world
            .provider_owners
            .remove(ProviderId::new([0x73; 32]));
        assert!(
            provider_binding_is_current(stx.world(), ProviderId::new([0x72; 32]), &provider_id,),
            "removing another id owned by the same provider must not revoke the exact ask binding"
        );
        assert!(
            !provider_binding_is_current(stx.world(), ProviderId::new([0x73; 32]), &provider_id,),
            "provider identity is selected by exact id, never an owner-wide lookup"
        );
        let bid = order(&buyer, 1);
        let revoked_ask = ask_order(&provider, 1, 90, 5);
        SubmitSorafsOrderbookOrder::new(encode(&bid), policy_digest)
            .execute(&buyer_id, &mut stx)
            .expect("admit bid");
        SubmitSorafsOrderbookOrder::new(encode(&revoked_ask), policy_digest)
            .execute(&provider_id, &mut stx)
            .expect("admit ask");
        let before_match = read_status(stx.world())
            .expect("read status")
            .expect("status");
        assert!(
            MatchSorafsOrderbook::new(policy_digest, before_match.book_revision, 1)
                .execute(&attacker_id, &mut stx)
                .is_err(),
            "an account outside the governed matcher role must be rejected"
        );
        assert_eq!(
            read_status(stx.world())
                .expect("read status after unauthorized match")
                .expect("status"),
            before_match
        );
        stx.world
            .provider_owners
            .remove(ProviderId::new([0x72; 32]));
        let revoked_match = MatchSorafsOrderbook::new(policy_digest, 2, 1)
            .execute(&settlement_id, &mut stx)
            .expect_err("revoked exact ask binding blocks matching until maintenance");
        assert!(
            matches!(&revoked_match, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("run orderbook maintenance")),
            "unexpected revoked-provider match error: {revoked_match}"
        );
        assert_eq!(
            read_status(stx.world())
                .expect("read status")
                .expect("status"),
            before_match
        );
        MaintainSorafsOrderbook::new(policy_digest, 2, 1)
            .execute(&settlement_id, &mut stx)
            .expect("retire the exact revoked ask binding");
        assert_eq!(
            read_order(stx.world(), revoked_ask.order_id)
                .expect("read provider-revoked ask")
                .expect("provider-revoked ask")
                .status,
            OrderbookOrderStatusV1::ProviderRevoked
        );
        let revocation_event = read_persisted_event(stx.world(), 4)
            .expect("read provider-revocation event")
            .expect("provider-revocation event");
        assert_eq!(
            revocation_event.event.kind,
            SorafsOrderbookLedgerEventKind::OrderProviderRevoked
        );
        assert_eq!(revocation_event.event.order_id, Some(revoked_ask.order_id));
        assert_eq!(
            revocation_event.event.provider_id,
            Some(ProviderId::new([0x72; 32]))
        );
        stx.world
            .provider_owners
            .insert(ProviderId::new([0x72; 32]), provider_id.clone());
        assert_eq!(
            read_order(stx.world(), revoked_ask.order_id)
                .expect("read stale ask after provider re-registration")
                .expect("stale ask remains terminal")
                .status,
            OrderbookOrderStatusV1::ProviderRevoked,
            "provider re-registration must not resurrect an admitted stale ask"
        );
        let ask = ask_order(&provider, 2, 90, 5);
        SubmitSorafsOrderbookOrder::new(encode(&ask), policy_digest)
            .execute(&provider_id, &mut stx)
            .expect("admit ask with a fresh exact provider binding");
        let parent_id = orderbook_order_escrow_id(bid.order_id);
        MatchSorafsOrderbook::new(policy_digest, 4, 1)
            .execute(&settlement_id, &mut stx)
            .expect("match crossing orders");
        let stored_bid = read_order(stx.world(), bid.order_id)
            .expect("read bid")
            .expect("stored bid");
        let stored_ask = read_order(stx.world(), ask.order_id)
            .expect("read ask")
            .expect("stored ask");
        assert_eq!(stored_bid.status, OrderbookOrderStatusV1::PartiallyFilled);
        assert_eq!(stored_bid.remaining_gib, 5);
        assert_eq!(stored_ask.status, OrderbookOrderStatusV1::Filled);
        assert_eq!(stored_ask.remaining_gib, 0);
        let trade_id = derive_orderbook_trade_id_v1(1, &bid, &ask, NOW);
        let trade = FindSorafsOrderbookTradeById::new(trade_id)
            .execute(&stx)
            .expect("query trade");
        let channel = FindSorafsOrderbookChannelById::new(trade.channel_id)
            .execute(&stx)
            .expect("query channel");
        assert_eq!(channel.buyer, buyer_id);
        assert_eq!(channel.provider, provider_id);
        assert_eq!(channel.provider_id, ProviderId::new([0x72; 32]));
        assert_eq!(&channel.settlement_authority, &settlement_id);
        assert_eq!(channel.remaining_bytes, 5 * BYTES_PER_GIB);
        stx.world
            .provider_owners
            .remove(ProviderId::new([0x72; 32]));
        assert_eq!(
            FindSorafsOrderbookChannelById::new(channel.channel_id)
                .execute(&stx)
                .expect("channel remains authoritative after provider unregister"),
            channel
        );
        let child_id = orderbook_settlement_escrow_id(channel.channel_id);
        let child = stx
            .world
            .asset_escrows
            .get(&child_id)
            .expect("channel custody");
        let child_remaining = child.remaining_amount.clone();
        assert_eq!(
            child_remaining,
            channel.remaining_xor_locked.clone().into_quantity()
        );
        let parent = stx
            .world
            .asset_escrows
            .get(&parent_id)
            .expect("remaining bid custody");
        let parent_remaining = parent.remaining_amount.clone();
        let initial_parent = stored_bid
            .bid_escrow
            .as_ref()
            .expect("stored bid custody binding")
            .initial_xor_locked
            .clone()
            .into_quantity();
        assert_eq!(
            parent.remaining_amount,
            initial_parent
                .checked_sub(&child_remaining)
                .expect("parent remainder")
        );
        assert!(
            CancelAssetLock::new(child_id, child_remaining.clone())
                .execute(&buyer_id, &mut stx)
                .is_err(),
            "buyer cannot bypass authoritative settlement by cancelling channel custody"
        );
        assert!(
            DrawdownAssetLock::new(child_id, child_remaining.clone(), child_remaining)
                .execute(&settlement_id, &mut stx)
                .is_err(),
            "matcher cannot bypass authoritative receipt settlement with generic drawdown"
        );
        assert!(
            ExpireAssetLock::new(child_id)
                .execute(&attacker_id, &mut stx)
                .is_err(),
            "an arbitrary caller cannot bypass channel maintenance with generic expiry"
        );
        assert!(
            CancelAssetLock::new(parent_id, parent_remaining.clone())
                .execute(&buyer_id, &mut stx)
                .is_err(),
            "buyer cannot bypass order cancellation by cancelling parent custody directly"
        );
        assert!(
            DrawdownAssetLock::new(parent_id, parent_remaining.clone(), parent_remaining)
                .execute(&settlement_id, &mut stx)
                .is_err(),
            "matcher cannot draw down the remaining parent custody directly"
        );
        assert!(
            ExpireAssetLock::new(parent_id)
                .execute(&attacker_id, &mut stx)
                .is_err(),
            "an arbitrary caller cannot bypass order maintenance with generic expiry"
        );
        let status = read_status(stx.world())
            .expect("read status")
            .expect("status");
        assert_eq!(status.book_revision, 5);
        assert_eq!(status.partially_filled_orders, 1);
        assert_eq!(status.filled_orders, 1);
        assert_eq!(status.provider_revoked_orders, 1);
        assert_eq!(status.trades, 1);
        assert_eq!(status.open_settlement_channels, 1);
        assert!(
            MatchSorafsOrderbook::new(policy_digest, 4, 1)
                .execute(&settlement_id, &mut stx)
                .is_err(),
            "a stale matcher revision must fail closed"
        );
        assert_eq!(
            read_status(stx.world())
                .expect("read status")
                .expect("status"),
            status
        );
        let active_policy = read_policy(stx.world())
            .expect("read active policy")
            .expect("active policy");
        let mut rotated = active_policy.policy.clone();
        rotated.revision = rotated
            .revision
            .checked_add(1)
            .expect("fixture policy revision");
        rotated.predecessor_policy_digest = Some(active_policy.policy_digest);
        rotated.settlement_authority = attacker_id.clone();
        let rotated_digest = rotated.digest().expect("rotated policy digest");
        let expected_rotated_policy = rotated.clone();
        SetSorafsOrderbookPolicy::new(rotated)
            .execute(&settlement_id, &mut stx)
            .expect("settlement authority rotation affects only newly opened channels");
        let rotated_record = read_policy(stx.world())
            .expect("read rotated active policy")
            .expect("active policy");
        assert_eq!(rotated_record.policy, expected_rotated_policy);
        assert_eq!(rotated_record.policy_digest, rotated_digest);
        assert_eq!(rotated_record.activated_at_unix, NOW);
        assert_eq!(rotated_record.activated_by, settlement_id);
        assert_eq!(
            FindSorafsOrderbookChannelById::new(channel.channel_id)
                .execute(&stx)
                .expect("existing channel survives authority rotation")
                .settlement_authority,
            channel.settlement_authority,
            "existing channels retain their immutable custody authority"
        );
    }
    #[test]
    fn reserve_default_terminalizes_open_ask_once_and_appeal_requires_a_new_ask() {
        let settlement = keypair(0xB2);
        let buyer = keypair(0xB3);
        let provider = keypair(0xB4);
        let treasury = keypair(0xB5);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_account = account(&provider);
        let provider_id = ProviderId::new([0x72; 32]);
        let state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB6; Hash::LENGTH]));
        let policy_digest = activate_policy(&mut stx, &settlement_id);
        stx.world
            .provider_owners
            .insert(provider_id, provider_account.clone());
        let reserve_digest =
            activate_reserve_account(&mut stx, &settlement_id, provider_id, &provider_account);
        let stale_ask = ask_order(&provider, 1, 90, 5);
        SubmitSorafsOrderbookOrder::new(encode(&stale_ask), policy_digest)
            .execute(&provider_account, &mut stx)
            .expect("non-default provider admits ask");
        SubmitSorafsReserveAppeal::new(
            [0xB7; 32],
            provider_id,
            1,
            ReserveLifecycleStage::Default,
            "enter governed default".to_owned(),
            Some([0xB8; 32]),
            reserve_digest,
        )
        .execute(&provider_account, &mut stx)
        .expect("submit default transition appeal");
        DecideSorafsReserveAppeal::new(
            [0xB7; 32],
            2,
            reserve_digest,
            true,
            "default evidence accepted".to_owned(),
        )
        .execute(&settlement_id, &mut stx)
        .expect("accept default transition");
        let bid = order(&buyer, 1);
        SubmitSorafsOrderbookOrder::new(encode(&bid), policy_digest)
            .execute(&buyer_id, &mut stx)
            .expect("admit crossing bid");
        let bid_escrow_id = orderbook_order_escrow_id(bid.order_id);
        let locked_before = stx
            .world
            .asset_escrows
            .get(&bid_escrow_id)
            .expect("bid custody")
            .clone();
        let custody_balance_before = asset_balance(&stx, &locked_before.custody);
        assert!(
            MatchSorafsOrderbook::new(policy_digest, 2, 1)
                .execute(&settlement_id, &mut stx)
                .is_err(),
            "a crossing ask whose provider entered reserve Default must never trade"
        );
        assert_eq!(
            read_status(stx.world())
                .expect("read pre-maintenance status")
                .expect("status")
                .trades,
            0
        );
        MaintainSorafsOrderbook::new(policy_digest, 2, 1)
            .execute(&settlement_id, &mut stx)
            .expect("terminalize the now-ineligible ask");
        let terminal = read_order(stx.world(), stale_ask.order_id)
            .expect("read terminal ask")
            .expect("terminal ask");
        assert_eq!(terminal.status, OrderbookOrderStatusV1::ProviderRevoked);
        let status_after_terminal = read_status(stx.world())
            .expect("read terminal status")
            .expect("terminal status");
        assert_eq!(status_after_terminal.book_revision, 3);
        assert_eq!(status_after_terminal.provider_revoked_orders, 1);
        assert_eq!(
            read_persisted_event(stx.world(), 4)
                .expect("read revocation event")
                .expect("revocation event")
                .event
                .kind,
            SorafsOrderbookLedgerEventKind::OrderProviderRevoked
        );
        MaintainSorafsOrderbook::new(policy_digest, 3, 1)
            .execute(&settlement_id, &mut stx)
            .expect("idempotent retry has no additional eligible work");
        assert_eq!(
            read_status(stx.world())
                .expect("read retry status")
                .expect("retry status"),
            status_after_terminal
        );
        assert!(
            read_persisted_event(stx.world(), 5)
                .expect("read absent duplicate event")
                .is_none(),
            "maintenance retry must not duplicate provider-revocation events"
        );
        assert_eq!(
            stx.world
                .asset_escrows
                .get(&bid_escrow_id)
                .expect("unchanged bid custody"),
            &locked_before
        );
        assert_eq!(
            asset_balance(&stx, &locked_before.custody),
            custody_balance_before,
            "failed matching and maintenance retry must not refund or duplicate bid custody"
        );
        SubmitSorafsReserveAppeal::new(
            [0xB9; 32],
            provider_id,
            3,
            ReserveLifecycleStage::Active,
            "restore advert eligibility".to_owned(),
            Some([0xBA; 32]),
            reserve_digest,
        )
        .execute(&provider_account, &mut stx)
        .expect("submit restoration appeal");
        DecideSorafsReserveAppeal::new(
            [0xB9; 32],
            4,
            reserve_digest,
            true,
            "restoration evidence accepted".to_owned(),
        )
        .execute(&settlement_id, &mut stx)
        .expect("accept restoration appeal");
        assert_eq!(
            read_order(stx.world(), stale_ask.order_id)
                .expect("read stale ask")
                .expect("stale ask")
                .status,
            OrderbookOrderStatusV1::ProviderRevoked,
            "reserve recovery never resurrects a terminal order"
        );
        let fresh_ask = ask_order(&provider, 2, 90, 5);
        SubmitSorafsOrderbookOrder::new(encode(&fresh_ask), policy_digest)
            .execute(&provider_account, &mut stx)
            .expect("restored provider must submit a fresh ask");
        MatchSorafsOrderbook::new(policy_digest, 4, 2)
            .execute(&settlement_id, &mut stx)
            .expect("fresh ask can trade after reserve restoration");
        assert_eq!(
            read_status(stx.world())
                .expect("read final status")
                .expect("final status")
                .trades,
            1
        );
    }
    #[test]
    fn matching_rejects_divergent_parent_custody_before_any_multi_fill_mutation() {
        let settlement = keypair(0xA8);
        let buyer = keypair(0xA9);
        let provider = keypair(0xAA);
        let treasury = keypair(0xAB);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xAC; Hash::LENGTH]));
        let fixture = seed_two_fill_match(
            &mut stx,
            &settlement_id,
            &buyer_id,
            &provider_id,
            &buyer,
            &provider,
        );
        let second_parent = stx
            .world
            .asset_escrows
            .get(&fixture.parent_ids[1])
            .expect("second parent custody")
            .clone();
        let poisoned_asset = Asset::new(
            AssetId::of(
                second_parent.asset_definition.clone(),
                second_parent.custody.clone(),
            ),
            micro_quantity(1),
        );
        let (poisoned_asset_id, poisoned_asset_value) = poisoned_asset.into_key_value();
        stx.world
            .assets
            .insert(poisoned_asset_id, poisoned_asset_value);
        let before = snapshot_two_fill_match(&stx, &fixture);
        let error = MatchSorafsOrderbook::new(fixture.policy_digest, 4, 2)
            .execute(&settlement_id, &mut stx)
            .expect_err("divergent second custody must reject the entire two-fill batch");
        assert!(
            error
                .to_string()
                .contains("native orderbook custody balance does not match its asset-lock record"),
            "unexpected custody-divergence error: {error}"
        );
        assert_two_fill_match_unchanged(&stx, &fixture, &before, [false, false]);
    }
    #[test]
    fn matching_rejects_late_channel_marker_before_any_multi_fill_mutation() {
        let settlement = keypair(0xAD);
        let buyer = keypair(0xAE);
        let provider = keypair(0xAF);
        let treasury = keypair(0xB0);
        let settlement_id = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 100_000);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB1; Hash::LENGTH]));
        let fixture = seed_two_fill_match(
            &mut stx,
            &settlement_id,
            &buyer_id,
            &provider_id,
            &buyer,
            &provider,
        );
        let second_child = orderbook_settlement_escrow_id(fixture.channel_ids[1]);
        crate::smartcontracts::isi::escrow::mark_orderbook_channel_lock(&mut stx, &second_child)
            .expect("seed a late conflicting channel marker");
        let before = snapshot_two_fill_match(&stx, &fixture);
        let error = MatchSorafsOrderbook::new(fixture.policy_digest, 4, 2)
            .execute(&settlement_id, &mut stx)
            .expect_err("late second marker must reject the entire two-fill batch");
        assert!(
            error
                .to_string()
                .contains("derived orderbook settlement channel custody marker already exists"),
            "unexpected duplicate-marker error: {error}"
        );
        assert_two_fill_match_unchanged(&stx, &fixture, &before, [false, true]);
    }
    #[test]
    fn maintenance_expires_signed_orders_with_bounded_revision_cas() {
        let operator = keypair(0x38);
        let buyer = keypair(0x39);
        let attacker = keypair(0x3A);
        let operator_id = account(&operator);
        let buyer_id = account(&buyer);
        let attacker_id = account(&attacker);
        let state = state_with_accounts(&[&operator, &buyer, &attacker]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_callback_testing();
        let policy_digest = activate_policy(&mut stx, &operator_id);
        let mut expired = order(&buyer, 1);
        expired.expiry_unix = NOW;
        let expired = sign_order(expired, &buyer);
        let initial_xor_locked = bid_order_escrow_requirement_v1(
            &expired,
            policy().max_maker_fee_bps,
            policy().max_taker_fee_bps,
        )
        .expect("derive expired bid custody");
        let binding = OrderbookBidEscrowBindingV1 {
            escrow_id: orderbook_order_escrow_id(expired.order_id),
            asset_definition: settlement_asset_definition(),
            initial_xor_locked: initial_xor_locked.clone(),
        };
        crate::smartcontracts::isi::escrow::open_orderbook_order_asset_lock(
            &mut stx,
            binding.escrow_id,
            &buyer_id,
            binding.asset_definition.clone(),
            initial_xor_locked.into_quantity(),
            NOW * 1_000,
        )
        .expect("seed expired bid custody");
        let record = OrderbookOrderRecord {
            order_id: expired.order_id,
            owner: buyer_id,
            canonical_order: encode(&expired),
            admitted_policy_digest: policy_digest,
            admitted_at_unix: NOW - 1,
            admission_sequence: 1,
            remaining_gib: expired.quantity_gib,
            bid_escrow: Some(binding),
            provider_id: None,
            status: OrderbookOrderStatusV1::Open,
            updated_at_unix: NOW - 1,
            canonical_cancel: None,
            cancelled_at_unix: None,
            cancelled_policy_digest: None,
        };
        stx.world
            .smart_contract_state
            .insert(order_key(expired.order_id), encode(&record));
        let mut status = read_status(stx.world())
            .expect("read status")
            .expect("status");
        status.open_orders = 1;
        status.book_revision = 1;
        status.next_admission_sequence = 2;
        stx.world
            .smart_contract_state
            .insert(status_key().clone(), encode(&status));
        assert!(
            MaintainSorafsOrderbook::new(policy_digest, 1, 1)
                .execute(&attacker_id, &mut stx)
                .is_err(),
            "an account outside the governed matcher role must not maintain the book"
        );
        assert_eq!(
            read_order(stx.world(), expired.order_id)
                .expect("read order after unauthorized maintenance")
                .expect("order"),
            record
        );
        assert_eq!(
            read_status(stx.world())
                .expect("read status after unauthorized maintenance")
                .expect("status"),
            status
        );
        assert!(
            MaintainSorafsOrderbook::new(policy_digest, 1, 0)
                .execute(&operator_id, &mut stx)
                .is_err(),
            "zero maintenance budget must be rejected"
        );
        MaintainSorafsOrderbook::new(policy_digest, 1, 1)
            .execute(&operator_id, &mut stx)
            .expect("expire order");
        let stored = read_order(stx.world(), expired.order_id)
            .expect("read expired order")
            .expect("expired order");
        assert_eq!(stored.status, OrderbookOrderStatusV1::Expired);
        let status = read_status(stx.world())
            .expect("read status")
            .expect("status");
        assert_eq!(status.open_orders, 0);
        assert_eq!(status.expired_orders, 1);
        assert_eq!(status.book_revision, 2);
        assert!(
            MaintainSorafsOrderbook::new(policy_digest, 1, 1)
                .execute(&operator_id, &mut stx)
                .is_err(),
            "a stale maintenance revision must be rejected"
        );
    }
    #[test]
    fn receipt_recording_is_bounded_non_overlapping_and_replay_safe() {
        let settlement = keypair(0x41);
        let buyer = keypair(0x42);
        let provider = keypair(0x43);
        let treasury = keypair(0x44);
        let authority = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let treasury_id = account(&treasury);
        let mut state = state_with_settlement_accounts(
            &settlement,
            &buyer,
            &provider,
            &treasury,
            TEST_TRADE_LOCK_MICRO,
        );
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA1; Hash::LENGTH]));
        let policy_digest = activate_policy(&mut stx, &authority);
        let first = receipt(&provider, 1, 9, 8, 0, 10);
        assert_eq!(first.xor_debited, xor_micro(100));
        open_settlement_lock(&mut stx, &buyer_id, &provider_id, &authority, &first);
        RecordSorafsOrderbookSettlementReceipt::new(encode(&first), policy_digest)
            .execute(&authority, &mut stx)
            .expect("first receipt");
        assert!(
            read_receipt(stx.world(), first.receipt_id)
                .expect("read receipt")
                .is_some()
        );
        assert_eq!(
            asset_balance(&stx, &provider_id),
            first.provider_credit.clone().into_quantity()
        );
        assert_eq!(
            asset_balance(&stx, &treasury_id),
            first.fee_amount.clone().into_quantity()
        );
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&first), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let overlap = receipt(&provider, 2, 9, 8, 5, 15);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&overlap), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let wrong_trade = receipt(&provider, 3, 9, 7, 10, 20);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&wrong_trade), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert_eq!(
            asset_balance(&stx, &provider_id),
            first.provider_credit.clone().into_quantity()
        );
        assert_eq!(
            asset_balance(&stx, &treasury_id),
            first.fee_amount.clone().into_quantity()
        );
        let second = receipt(&provider, 4, 9, 8, 10, 20);
        RecordSorafsOrderbookSettlementReceipt::new(encode(&second), policy_digest)
            .execute(&authority, &mut stx)
            .expect("second receipt");
        assert_eq!(
            asset_balance(&stx, &provider_id),
            first
                .provider_credit
                .clone()
                .into_quantity()
                .checked_add(&second.provider_credit.clone().into_quantity())
                .expect("fixture provider credits fit")
        );
        assert_eq!(
            asset_balance(&stx, &treasury_id),
            first
                .fee_amount
                .clone()
                .into_quantity()
                .checked_add(&second.fee_amount.clone().into_quantity())
                .expect("fixture fees fit")
        );
        let third = receipt(&provider, 5, 9, 8, 20, 30);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&third), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let index = read_receipt_index(stx.world(), first.channel_id)
            .expect("read index")
            .expect("index");
        assert_eq!(index.ranges.len(), 2);
        assert_eq!(index.ranges[0].receipt_id, first.receipt_id);
        assert_eq!(index.ranges[1].receipt_id, second.receipt_id);
        assert!(
            read_receipt(stx.world(), third.receipt_id)
                .expect("read receipt")
                .is_none()
        );
        let escrow = stx
            .world
            .asset_escrows
            .get(&orderbook_settlement_escrow_id(first.channel_id))
            .expect("settlement lock");
        let expected_remaining = micro_quantity(TEST_TRADE_LOCK_MICRO)
            .checked_sub(&first.xor_debited.clone().into_quantity())
            .and_then(|remaining| {
                remaining.checked_sub(&second.xor_debited.clone().into_quantity())
            })
            .expect("fixture channel debits fit");
        assert_eq!(escrow.remaining_amount, expected_remaining);
        assert_eq!(asset_balance(&stx, &escrow.custody), expected_remaining);
        let queried = FindSorafsOrderbookReceiptById::new(first.receipt_id)
            .execute(&stx)
            .expect("query receipt by id");
        assert_eq!(queried.receipt_id, first.receipt_id);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit receipt query fixture");
        state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&block_header()));
        let view = state.view();
        let first_page = FindSorafsOrderbookReceipts::new(None, Some(first.channel_id), None, 1)
            .execute(&view)
            .expect("query first receipt page");
        assert_eq!(first_page.receipts.len(), 1);
        assert!(first_page.has_more);
        let finalized_cursor = first_page.finalized_cursor;
        let second_page = FindSorafsOrderbookReceipts::new(
            Some(finalized_cursor),
            Some(first.channel_id),
            first_page.next_after_receipt_id,
            1,
        )
        .execute(&view)
        .expect("query second receipt page");
        assert_eq!(second_page.finalized_cursor, finalized_cursor);
        assert_eq!(second_page.receipts.len(), 1);
        assert!(!second_page.has_more);
        let trades = FindSorafsOrderbookTrades::new(Some(finalized_cursor), None, 10)
            .execute(&view)
            .expect("query committed trade page");
        assert_eq!(trades.trades.len(), 1);
        assert_eq!(trades.trades[0].trade_id, first.trade_id);
        let channels = FindSorafsOrderbookChannels::new(Some(finalized_cursor), None, None, 10)
            .execute(&view)
            .expect("query committed channel page");
        assert_eq!(channels.channels.len(), 1);
        assert_eq!(channels.channels[0].channel_id, first.channel_id);
        let status = FindSorafsOrderbookStatus
            .execute(&view)
            .expect("query receipt counters");
        assert_eq!(status.settlement_receipts, 2);
        assert_eq!(status.settlement_channels, 1);
    }
    #[test]
    fn trade_and_channel_queries_are_bounded_filtered_and_cursor_stable() {
        let settlement = keypair(0x4A);
        let buyer = keypair(0x4B);
        let provider = keypair(0x4C);
        let treasury = keypair(0x4D);
        let authority = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let mut state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 0);
        let first = receipt(&provider, 1, 1, 8, 0, 10);
        let second = receipt(&provider, 2, 2, 9, 0, 10);
        transact(&mut state, 1, NOW, |transaction| {
            activate_policy(transaction, &authority);
            seed_settlement_channel(transaction, &buyer_id, &provider_id, &authority, &first);
            seed_settlement_channel(transaction, &buyer_id, &provider_id, &authority, &second);
            let mut status = read_status(transaction.world())
                .expect("read fixture status")
                .expect("configured status");
            status.trades = 2;
            status.settlement_channels = 2;
            status.open_settlement_channels = 2;
            transaction
                .world
                .smart_contract_state
                .insert(status_key().clone(), encode(&status));
            Ok(())
        })
        .expect("commit trade/channel query fixture");
        let view = state.view();
        let first_trades = FindSorafsOrderbookTrades::new(None, None, 1)
            .execute(&view)
            .expect("query first trade page");
        assert_eq!(first_trades.trades.len(), 1);
        assert!(first_trades.has_more);
        let anchor = first_trades.finalized_cursor;
        let second_trades =
            FindSorafsOrderbookTrades::new(Some(anchor), first_trades.next_after_trade_id, 1)
                .execute(&view)
                .expect("query second trade page");
        assert_eq!(second_trades.trades.len(), 1);
        assert!(!second_trades.has_more);
        let mut trade_ids = first_trades
            .trades
            .iter()
            .chain(&second_trades.trades)
            .map(|trade| trade.trade_id)
            .collect::<Vec<_>>();
        trade_ids.sort_unstable();
        assert_eq!(trade_ids, vec![first.trade_id, second.trade_id]);
        let first_channels = FindSorafsOrderbookChannels::new(
            Some(anchor),
            Some(OrderbookSettlementChannelStatusV1::Open),
            None,
            1,
        )
        .execute(&view)
        .expect("query first open-channel page");
        assert_eq!(first_channels.channels.len(), 1);
        assert!(first_channels.has_more);
        let second_channels = FindSorafsOrderbookChannels::new(
            Some(anchor),
            Some(OrderbookSettlementChannelStatusV1::Open),
            first_channels.next_after_channel_id,
            1,
        )
        .execute(&view)
        .expect("query second open-channel page");
        assert_eq!(second_channels.channels.len(), 1);
        assert!(!second_channels.has_more);
        assert!(
            FindSorafsOrderbookChannels::new(
                Some(anchor),
                Some(OrderbookSettlementChannelStatusV1::Closed),
                None,
                10,
            )
            .execute(&view)
            .expect("query closed-channel filter")
            .channels
            .is_empty()
        );
    }
    #[test]
    fn receipt_rejects_policy_signer_time_and_canonical_abuse_but_accepts_untrusted_relayer() {
        let settlement = keypair(0x45);
        let attacker = keypair(0x46);
        let buyer = keypair(0x47);
        let provider = keypair(0x48);
        let treasury = keypair(0x49);
        let relayer = keypair(0x4A);
        let authority = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let treasury_id = account(&treasury);
        let relayer_id = account(&relayer);
        let mut state = state_with_settlement_accounts(
            &settlement,
            &buyer,
            &provider,
            &treasury,
            TEST_TRADE_LOCK_MICRO,
        );
        let attacker_id = account(&attacker);
        let (attacker_key, attacker_value) = Account::new(attacker_id.clone())
            .build(&attacker_id)
            .into_key_value();
        state.world.accounts.insert(attacker_key, attacker_value);
        let (relayer_key, relayer_value) = Account::new(relayer_id.clone())
            .build(&relayer_id)
            .into_key_value();
        state.world.accounts.insert(relayer_key, relayer_value);
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA2; Hash::LENGTH]));
        let policy_digest = activate_policy(&mut stx, &authority);
        let base = receipt(&provider, 1, 6, 7, 0, 10);
        open_settlement_lock(&mut stx, &buyer_id, &provider_id, &authority, &base);
        let mut noncanonical = encode(&base);
        noncanonical.push(0);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(noncanonical, policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&base), [0x99; 32])
                .execute(&authority, &mut stx)
                .is_err()
        );
        let wrong_signer = sign_receipt(base.clone(), &attacker);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&wrong_signer), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let mut stale = base.clone();
        stale.issued_at_unix = NOW - policy().max_receipt_age_secs - 1;
        let stale = sign_receipt(stale, &provider);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&stale), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        let mut future = base.clone();
        future.issued_at_unix = NOW + policy().max_clock_skew_secs + 1;
        let future = sign_receipt(future, &provider);
        assert!(
            RecordSorafsOrderbookSettlementReceipt::new(encode(&future), policy_digest)
                .execute(&authority, &mut stx)
                .is_err()
        );
        assert!(
            read_receipt(stx.world(), base.receipt_id)
                .expect("read receipt")
                .is_none()
        );
        assert!(
            read_receipt_index(stx.world(), base.channel_id)
                .expect("read index")
                .is_none()
        );
        assert_eq!(asset_balance(&stx, &provider_id), Quantity::zero());
        assert_eq!(asset_balance(&stx, &treasury_id), Quantity::zero());
        let escrow = stx
            .world
            .asset_escrows
            .get(&orderbook_settlement_escrow_id(base.channel_id))
            .expect("settlement lock");
        assert_eq!(
            escrow.remaining_amount,
            micro_quantity(TEST_TRADE_LOCK_MICRO)
        );
        assert_eq!(
            asset_balance(&stx, &escrow.custody),
            micro_quantity(TEST_TRADE_LOCK_MICRO)
        );
        assert_no_receipt_status_mutation(&stx);
        let active_policy = read_policy(stx.world())
            .expect("read active policy")
            .expect("active policy");
        let mut rotated = active_policy.policy;
        rotated.revision += 1;
        rotated.predecessor_policy_digest = Some(active_policy.policy_digest);
        rotated.settlement_authority = attacker_id;
        let rotated_digest = rotated.digest().expect("rotated policy digest");
        SetSorafsOrderbookPolicy::new(rotated)
            .execute(&authority, &mut stx)
            .expect("rotate authority while the immutable channel remains open");
        RecordSorafsOrderbookSettlementReceipt::new(encode(&base), rotated_digest)
            .execute(&relayer_id, &mut stx)
            .expect("an unrelated outer relayer may submit the provider-signed receipt");
        let recorded = read_receipt(stx.world(), base.receipt_id)
            .expect("read relayed receipt")
            .expect("relayed receipt committed");
        assert_eq!(
            recorded.recorded_by, relayer_id,
            "audit attribution preserves the actually committed outer relayer"
        );
        assert_eq!(
            asset_balance(&stx, &provider_id),
            base.provider_credit.clone().into_quantity()
        );
        assert_eq!(
            asset_balance(&stx, &treasury_id),
            base.fee_amount.clone().into_quantity()
        );
    }
    include!("sorafs/orderbook_tail_tests.rs");
}
