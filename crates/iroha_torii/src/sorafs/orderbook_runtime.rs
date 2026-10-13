//! Supervised Torii runtime for durable native SoraFS orderbook transactions.
//!
//! The durable `sorafs_node` forwarder is the only local delivery state. Policy, book status,
//! channels, receipts, and transaction outcomes are read from one immutable finalized ledger view.
//! Signing and submission are separate boundaries: an injected qualified runtime signer sees only an
//! exact fee-quoted payload, and only strict durable Torii ingress can expose the resulting signed
//! transaction.

use super::orderbook_worker::{
    OrderbookEnvelopeReconciliationV1, OrderbookFinalizedSnapshotV1, OrderbookGenerationSnapshotV1,
    OrderbookMaintenanceDueV1, OrderbookWorkerActionV1, plan_orderbook_generation,
    plan_orderbook_worker_action, reconcile_orderbook_semantics,
};
use super::{pending_evidence_blocks_absence_retry, retained_transaction_digest};
use crate::{SharedAppState, SoraFsOrderbookTransactionSigner};
use axum::http::StatusCode;
use blake3::hash as blake3_hash;
use iroha_core::{
    smartcontracts::ValidSingularQuery,
    state::{
        BlockHashRead, StateReadOnly, StateReadOnlyWithTransactions, TransactionsReadOnly,
        WorldReadOnly,
    },
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::BlockHeader,
    events::data::sorafs::SorafsOrderbookLedgerEventKind,
    isi::InstructionBox,
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsOrderbookChannelById, FindSorafsOrderbookChannels, FindSorafsOrderbookEvents,
            FindSorafsOrderbookOrders, FindSorafsOrderbookPolicy, FindSorafsOrderbookReceiptById,
            FindSorafsOrderbookStatus, FindSorafsReserveProviderById,
        },
    },
    sorafs::{
        orderbook::{
            ORDERBOOK_MAX_OPEN_ORDERS_V1, ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1,
            ORDERBOOK_QUERY_MAX_ITEMS_V1, OrderbookFinalizedCursorV1,
            OrderbookFinalizedEventCursorV1, OrderbookFinalizedEventPageV1,
            OrderbookLedgerStatusV1, OrderbookOrderPageV1, OrderbookOrderStatusV1,
            OrderbookSettlementChannelPageV1, OrderbookSettlementChannelStatusV1,
        },
        reserve::ReserveLifecycleStage,
    },
    transaction::{Executable, SignedTransaction, TransactionBuilder},
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::{debug, warn};
use mv::storage::StorageReadOnly;
use sorafs_manifest::orderbook::{
    OrderSideV1, OrderTierV1, decode_order_request_v1, decode_settlement_receipt_v1,
};
use sorafs_node::{
    config::OrderbookWorkerPolicy,
    orderbook_transaction_forwarder::{
        ORDERBOOK_TRANSACTION_FORWARDER_MAX_SCAN_ITEMS_V1,
        ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1, OrderbookOperationV1,
        OrderbookTransactionDeliveryStateV1, OrderbookTransactionEnqueueResultV1,
        OrderbookTransactionPendingV1, OrderbookTransactionSigningRequestV1,
        validate_orderbook_pending_delivery_v1, validate_orderbook_reconciliation_material_v1,
    },
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
const ORDERBOOK_TELEMETRY_MAX_EVENTS_PER_SCAN_V1: usize = 1_024;
const ORDERBOOK_TELEMETRY_MAX_ORDERS_V1: usize = ORDERBOOK_MAX_OPEN_ORDERS_V1 as usize;
const ORDERBOOK_TELEMETRY_MAX_CHANNELS_V1: usize =
    ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1 as usize;
const ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1: usize = 8;
const ORDERBOOK_TELEMETRY_TIER_COUNT_V1: usize = 3;
const ORDERBOOK_TELEMETRY_SIDE_COUNT_V1: usize = 2;
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SorafsOrderbookTransactionForwarderCursorV1 {
    after_sequence: Option<u64>,
    telemetry: SorafsOrderbookFinalizedTelemetryProjectionV1,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SorafsOrderbookTransactionForwarderScanV1 {
    generated: usize,
    generation_replayed: usize,
    generation_deferred: usize,
    scanned: usize,
    finalized: usize,
    signed: usize,
    submitted: usize,
    deferred: usize,
    conflicted: usize,
    rejected: usize,
    telemetry_published: usize,
    telemetry_catching_up: usize,
    telemetry_failed: usize,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SorafsOrderbookFinalizedTelemetryProjectionV1 {
    after_event: Option<OrderbookFinalizedEventCursorV1>,
    event_counts: [u64; ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1],
    published_event_counts: [u64; ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1],
    last_event_book_revision: u64,
    last_event_occurred_at_unix_ms: u64,
    last_book_revision_advanced_at_unix_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SorafsOrderbookFinalizedMetricsV1 {
    finalized_cursor: OrderbookFinalizedCursorV1,
    finalized_at_unix: u64,
    event_count_deltas: [u64; ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1],
    open_depth_gib: [[u64; ORDERBOOK_TELEMETRY_SIDE_COUNT_V1]; ORDERBOOK_TELEMETRY_TIER_COUNT_V1],
    matcher_lag_seconds: u64,
    settlement_backlog: u64,
    oldest_settlement_age_seconds: u64,
    escrow_runway_seconds: u64,
    book_revision: u64,
    matcher_scan_book_revision: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsOrderbookFinalizedTelemetryRefreshV1 {
    Published,
    CatchingUp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsOrderbookFinalizedTelemetryErrorV1 {
    TelemetryUnavailable,
    FinalizedViewUnavailable,
    QueryFailed,
    InvalidEventPage,
    InvalidOrderPage,
    InvalidChannelPage,
    ArithmeticOverflow,
    OrderCapacityExceeded,
    ChannelCapacityExceeded,
    ProjectionMismatch,
}
impl SorafsOrderbookFinalizedTelemetryErrorV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::TelemetryUnavailable => "telemetry_unavailable",
            Self::FinalizedViewUnavailable => "finalized_view_unavailable",
            Self::QueryFailed => "query_failed",
            Self::InvalidEventPage => "invalid_event_page",
            Self::InvalidOrderPage => "invalid_order_page",
            Self::InvalidChannelPage => "invalid_channel_page",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::OrderCapacityExceeded => "order_capacity_exceeded",
            Self::ChannelCapacityExceeded => "channel_capacity_exceeded",
            Self::ProjectionMismatch => "projection_mismatch",
        }
    }
}
/// Orderbook supervision uses one role-activation predicate.
///
/// Provider storage keeps durable drain/reconciliation active even when new orderbook generation is
/// disabled. When both storage and generation are disabled, no worker is started and therefore no
/// external progress occurs. Opening the local [`sorafs_node::NodeHandle`] may still normalize an
/// interrupted signer-only claim from `Signing` to `Ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OrderbookWorkerSupervisionV1 {
    generation_enabled: bool,
    role_active: bool,
}
const fn orderbook_worker_supervision(
    storage_enabled: bool,
    generation_enabled: bool,
) -> OrderbookWorkerSupervisionV1 {
    OrderbookWorkerSupervisionV1 {
        generation_enabled,
        role_active: storage_enabled || generation_enabled,
    }
}
fn spawn_orderbook_worker_when_active<T>(
    supervision: OrderbookWorkerSupervisionV1,
    spawn: impl FnOnce() -> T,
) -> Option<T> {
    if !supervision.role_active {
        return None;
    }
    Some(spawn())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderbookCommittedExternalOutcomeV1 {
    Applied,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderbookAuthoritativeTransactionOutcomeV1 {
    Absent,
    Applied,
    Rejected,
    Unavailable,
}
#[derive(Debug)]
struct OrderbookFinalizedObservationV1 {
    snapshot: OrderbookFinalizedSnapshotV1,
    transaction_outcome: Option<OrderbookAuthoritativeTransactionOutcomeV1>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderbookTransactionSubmissionDispositionV1 {
    Submitted,
    DefinitelyNotSubmitted,
    Rejected,
    Ambiguous,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderbookTransactionSubmissionResultV1 {
    Submitted,
    Rejected,
    Deferred,
}
fn classify_orderbook_transaction_submission(
    error: &iroha_core::queue::Error,
) -> OrderbookTransactionSubmissionDispositionV1 {
    match error {
        iroha_core::queue::Error::InBlockchain | iroha_core::queue::Error::IsInQueue => {
            OrderbookTransactionSubmissionDispositionV1::Submitted
        }
        iroha_core::queue::Error::Expired
        | iroha_core::queue::Error::TransactionDomainMismatch(_) => {
            OrderbookTransactionSubmissionDispositionV1::Rejected
        }
        _ => OrderbookTransactionSubmissionDispositionV1::DefinitelyNotSubmitted,
    }
}
fn classify_orderbook_envelope(
    retained_digest: Option<[u8; 32]>,
    signed_transaction_bytes: Option<&[u8]>,
    finalized_cursor: OrderbookFinalizedCursorV1,
    outcome: OrderbookAuthoritativeTransactionOutcomeV1,
    delivery_evidence_blocks_absence_retry: bool,
) -> OrderbookEnvelopeReconciliationV1 {
    if finalized_cursor.height == 0 || finalized_cursor.block_hash == [0; 32] {
        return OrderbookEnvelopeReconciliationV1::Unavailable;
    }
    let Some(transaction_digest) =
        retained_transaction_digest(retained_digest, signed_transaction_bytes)
    else {
        return OrderbookEnvelopeReconciliationV1::Unavailable;
    };
    match outcome {
        OrderbookAuthoritativeTransactionOutcomeV1::Applied => {
            OrderbookEnvelopeReconciliationV1::Applied {
                transaction_digest,
                finalized_cursor,
            }
        }
        OrderbookAuthoritativeTransactionOutcomeV1::Rejected => {
            OrderbookEnvelopeReconciliationV1::Rejected {
                transaction_digest,
                finalized_cursor,
            }
        }
        OrderbookAuthoritativeTransactionOutcomeV1::Absent
            if delivery_evidence_blocks_absence_retry =>
        {
            OrderbookEnvelopeReconciliationV1::Pending {
                transaction_digest,
                finalized_cursor,
            }
        }
        OrderbookAuthoritativeTransactionOutcomeV1::Absent => {
            OrderbookEnvelopeReconciliationV1::Absent {
                transaction_digest,
                finalized_cursor,
            }
        }
        OrderbookAuthoritativeTransactionOutcomeV1::Unavailable => {
            OrderbookEnvelopeReconciliationV1::Unavailable
        }
    }
}
fn classify_exact_orderbook_entrypoint_outcome(
    expected_hash: &HashOf<SignedTransaction>,
    block_available: bool,
    results: impl IntoIterator<
        Item = (
            HashOf<SignedTransaction>,
            OrderbookCommittedExternalOutcomeV1,
        ),
    >,
) -> OrderbookAuthoritativeTransactionOutcomeV1 {
    if !block_available {
        return OrderbookAuthoritativeTransactionOutcomeV1::Unavailable;
    }
    let mut exact = results
        .into_iter()
        .filter_map(|(hash, outcome)| (&hash == expected_hash).then_some(outcome));
    let Some(outcome) = exact.next() else {
        return OrderbookAuthoritativeTransactionOutcomeV1::Unavailable;
    };
    if exact.next().is_some() {
        // A transaction hash must have exactly one external entrypoint result.
        return OrderbookAuthoritativeTransactionOutcomeV1::Unavailable;
    }
    match outcome {
        OrderbookCommittedExternalOutcomeV1::Applied => {
            OrderbookAuthoritativeTransactionOutcomeV1::Applied
        }
        OrderbookCommittedExternalOutcomeV1::Rejected => {
            OrderbookAuthoritativeTransactionOutcomeV1::Rejected
        }
    }
}
fn inspect_indexed_orderbook_transaction(
    state: &iroha_core::state::State,
    transaction_hash: &HashOf<SignedTransaction>,
    block_height: NonZeroUsize,
    expected_block_hash: HashOf<BlockHeader>,
) -> OrderbookAuthoritativeTransactionOutcomeV1 {
    let Ok((_header, outcome)) = crate::canonical_history::exact_external_outcome(
        state,
        block_height,
        expected_block_hash,
        transaction_hash,
    ) else {
        return OrderbookAuthoritativeTransactionOutcomeV1::Unavailable;
    };
    classify_exact_orderbook_entrypoint_outcome(
        transaction_hash,
        true,
        outcome.map(|applied| {
            (
                *transaction_hash,
                if applied {
                    OrderbookCommittedExternalOutcomeV1::Applied
                } else {
                    OrderbookCommittedExternalOutcomeV1::Rejected
                },
            )
        }),
    )
}
fn orderbook_finalized_cursor_from_view(
    view: &impl StateReadOnly,
) -> Option<OrderbookFinalizedCursorV1> {
    u64::try_from(view.block_hashes().len())
        .ok()
        .zip(view.block_hashes().last())
        .map(|(height, hash)| OrderbookFinalizedCursorV1 {
            height,
            block_hash: *hash.as_ref(),
        })
        .filter(|cursor| cursor.height != 0 && cursor.block_hash != [0; 32])
}
fn current_orderbook_finalized_cursor(
    state: &SharedAppState,
) -> Option<OrderbookFinalizedCursorV1> {
    let view = state.state.query_view();
    orderbook_finalized_cursor_from_view(&view)
}
fn orderbook_finalized_tip_from_view(
    view: &impl StateReadOnly,
) -> Option<(OrderbookFinalizedCursorV1, u64)> {
    let finalized_cursor = orderbook_finalized_cursor_from_view(view)?;
    let finalized_at_unix = view
        .authenticated_query_ledger_time_ms()?
        .checked_div(1_000)
        .filter(|timestamp| *timestamp != 0)?;
    Some((finalized_cursor, finalized_at_unix))
}
const fn orderbook_telemetry_event_kind_index(kind: SorafsOrderbookLedgerEventKind) -> usize {
    match kind {
        SorafsOrderbookLedgerEventKind::PolicyActivated => 0,
        SorafsOrderbookLedgerEventKind::OrderAdmitted => 1,
        SorafsOrderbookLedgerEventKind::OrderCancelled => 2,
        SorafsOrderbookLedgerEventKind::TradeMatched => 3,
        SorafsOrderbookLedgerEventKind::OrderExpired => 4,
        SorafsOrderbookLedgerEventKind::OrderProviderRevoked => 5,
        SorafsOrderbookLedgerEventKind::ChannelExpired => 6,
        SorafsOrderbookLedgerEventKind::ReceiptRecorded => 7,
    }
}
const fn orderbook_telemetry_tier_index(tier: OrderTierV1) -> usize {
    match tier {
        OrderTierV1::Hot => 0,
        OrderTierV1::Warm => 1,
        OrderTierV1::Archive => 2,
    }
}
const fn orderbook_telemetry_side_index(side: OrderSideV1) -> usize {
    match side {
        OrderSideV1::Bid => 0,
        OrderSideV1::Ask => 1,
    }
}
fn orderbook_telemetry_event_shape_is_valid(
    event: &iroha_data_model::events::data::sorafs::SorafsOrderbookLedgerEvent,
) -> bool {
    if event.occurred_at_unix_ms == 0
        || [
            event.order_id,
            event.trade_id,
            event.channel_id,
            event.receipt_id,
        ]
        .into_iter()
        .flatten()
        .any(|identifier| identifier == [0; 32])
        || event
            .provider_id
            .is_some_and(|provider_id| provider_id.as_bytes() == &[0; 32])
    {
        return false;
    }
    match event.kind {
        SorafsOrderbookLedgerEventKind::PolicyActivated => {
            event.order_id.is_none()
                && event.trade_id.is_none()
                && event.channel_id.is_none()
                && event.receipt_id.is_none()
                && event.provider_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderAdmitted => {
            event.order_id.is_some()
                && event.trade_id.is_none()
                && event.channel_id.is_none()
                && event.receipt_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderCancelled
        | SorafsOrderbookLedgerEventKind::OrderExpired => {
            event.order_id.is_some()
                && event.trade_id.is_none()
                && event.channel_id.is_none()
                && event.receipt_id.is_none()
                && event.provider_id.is_none()
        }
        SorafsOrderbookLedgerEventKind::OrderProviderRevoked => {
            event.order_id.is_some()
                && event.trade_id.is_none()
                && event.channel_id.is_none()
                && event.receipt_id.is_none()
                && event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::TradeMatched => {
            event.order_id.is_some()
                && event.trade_id.is_some()
                && event.channel_id.is_some()
                && event.receipt_id.is_none()
                && event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::ChannelExpired => {
            event.order_id.is_none()
                && event.trade_id.is_some()
                && event.channel_id.is_some()
                && event.receipt_id.is_none()
                && event.provider_id.is_some()
        }
        SorafsOrderbookLedgerEventKind::ReceiptRecorded => {
            event.order_id.is_none()
                && event.trade_id.is_some()
                && event.channel_id.is_some()
                && event.receipt_id.is_some()
                && event.provider_id.is_some()
        }
    }
}
fn orderbook_telemetry_event_cursor_is_successor(
    previous: Option<OrderbookFinalizedEventCursorV1>,
    current: OrderbookFinalizedEventCursorV1,
) -> bool {
    if current.sequence == 0
        || current.block_height == 0
        || current.block_hash == [0; 32]
        || previous.map_or(1, |cursor| cursor.sequence.checked_add(1).unwrap_or(0))
            != current.sequence
    {
        return false;
    }
    let Some(previous) = previous else {
        return current.sequence == 1 && current.event_index == 0;
    };
    match previous.block_height.cmp(&current.block_height) {
        std::cmp::Ordering::Less => current.event_index == 0,
        std::cmp::Ordering::Equal => {
            previous.block_hash == current.block_hash
                && previous
                    .event_index
                    .checked_add(1)
                    .is_some_and(|index| index == current.event_index)
        }
        std::cmp::Ordering::Greater => false,
    }
}
fn apply_orderbook_finalized_telemetry_event_page(
    projection: &mut SorafsOrderbookFinalizedTelemetryProjectionV1,
    page: &OrderbookFinalizedEventPageV1,
    expected_finalized_cursor: OrderbookFinalizedCursorV1,
) -> Result<(), SorafsOrderbookFinalizedTelemetryErrorV1> {
    if page.finalized_cursor != expected_finalized_cursor
        || page.events.len()
            > usize::try_from(ORDERBOOK_QUERY_MAX_ITEMS_V1)
                .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        || (page.has_more && page.events.is_empty())
        || page.has_more != page.next_after.is_some()
        || page.next_after.is_some_and(|cursor| {
            page.events
                .last()
                .map(iroha_data_model::sorafs::orderbook::OrderbookFinalizedEventV1::cursor)
                != Some(cursor)
        })
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage);
    }
    let mut next = *projection;
    for record in &page.events {
        let cursor = record.cursor();
        if record.block_height > expected_finalized_cursor.height
            || !orderbook_telemetry_event_cursor_is_successor(next.after_event, cursor)
            || !orderbook_telemetry_event_shape_is_valid(&record.event)
            || record.event.book_revision < next.last_event_book_revision
            || record.event.occurred_at_unix_ms < next.last_event_occurred_at_unix_ms
        {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage);
        }
        let kind_index = orderbook_telemetry_event_kind_index(record.event.kind);
        next.event_counts[kind_index] = next.event_counts[kind_index]
            .checked_add(1)
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        next.after_event = Some(cursor);
        if record.event.book_revision > next.last_event_book_revision {
            next.last_book_revision_advanced_at_unix_ms = record.event.occurred_at_unix_ms;
        }
        next.last_event_book_revision = record.event.book_revision;
        next.last_event_occurred_at_unix_ms = record.event.occurred_at_unix_ms;
    }
    *projection = next;
    Ok(())
}
fn orderbook_telemetry_event_block_hashes_are_finalized(
    block_hashes: &(impl BlockHashRead + ?Sized),
    page: &OrderbookFinalizedEventPageV1,
) -> bool {
    page.events.iter().all(|record| {
        record
            .block_height
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| block_hashes.hash_at(index))
            .is_some_and(|hash| hash.as_ref() == &record.block_hash)
    })
}
fn consume_orderbook_finalized_telemetry_events(
    view: &impl StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    projection: &mut SorafsOrderbookFinalizedTelemetryProjectionV1,
) -> Result<bool, SorafsOrderbookFinalizedTelemetryErrorV1> {
    let mut processed = 0_usize;
    loop {
        let remaining = ORDERBOOK_TELEMETRY_MAX_EVENTS_PER_SCAN_V1
            .checked_sub(processed)
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if remaining == 0 {
            return Ok(false);
        }
        let limit = u32::try_from(remaining)
            .unwrap_or(u32::MAX)
            .min(ORDERBOOK_QUERY_MAX_ITEMS_V1);
        let page =
            FindSorafsOrderbookEvents::new(Some(finalized_cursor), projection.after_event, limit)
                .execute(view)
                .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::QueryFailed)?;
        let page_len = page.events.len();
        if !orderbook_telemetry_event_block_hashes_are_finalized(view.block_hashes(), &page) {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage);
        }
        apply_orderbook_finalized_telemetry_event_page(projection, &page, finalized_cursor)?;
        processed = processed
            .checked_add(page_len)
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if !page.has_more {
            return Ok(true);
        }
    }
}
fn validate_orderbook_telemetry_order_page(
    page: &OrderbookOrderPageV1,
    expected_finalized_cursor: OrderbookFinalizedCursorV1,
    finalized_at_unix: u64,
    expected_status: OrderbookOrderStatusV1,
    after_order_id: Option<[u8; 32]>,
) -> Result<(), SorafsOrderbookFinalizedTelemetryErrorV1> {
    if page.finalized_cursor != expected_finalized_cursor
        || page.orders.len()
            > usize::try_from(ORDERBOOK_QUERY_MAX_ITEMS_V1)
                .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        || (page.has_more && page.orders.is_empty())
        || page.has_more != page.next_after_order_id.is_some()
        || page
            .next_after_order_id
            .is_some_and(|cursor| page.orders.last().map(|record| record.order_id) != Some(cursor))
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage);
    }
    let mut previous = after_order_id;
    for record in &page.orders {
        if previous.is_some_and(|cursor| record.order_id <= cursor)
            || record.order_id == [0; 32]
            || record.admitted_policy_digest == [0; 32]
            || record.status != expected_status
            || record.remaining_gib == 0
            || record.admitted_at_unix == 0
            || record.admission_sequence == 0
            || record.admitted_at_unix > finalized_at_unix
            || record.updated_at_unix < record.admitted_at_unix
            || record.updated_at_unix > finalized_at_unix
            || record.canonical_cancel.is_some()
            || record.cancelled_at_unix.is_some()
            || record.cancelled_policy_digest.is_some()
        {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage);
        }
        previous = Some(record.order_id);
    }
    Ok(())
}
fn validate_orderbook_telemetry_channel_page(
    page: &OrderbookSettlementChannelPageV1,
    expected_finalized_cursor: OrderbookFinalizedCursorV1,
    finalized_at_unix: u64,
    after_channel_id: Option<[u8; 32]>,
) -> Result<(), SorafsOrderbookFinalizedTelemetryErrorV1> {
    if page.finalized_cursor != expected_finalized_cursor
        || page.channels.len()
            > usize::try_from(ORDERBOOK_QUERY_MAX_ITEMS_V1)
                .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        || (page.has_more && page.channels.is_empty())
        || page.has_more != page.next_after_channel_id.is_some()
        || page.next_after_channel_id.is_some_and(|cursor| {
            page.channels.last().map(|record| record.channel_id) != Some(cursor)
        })
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidChannelPage);
    }
    let mut previous = after_channel_id;
    for record in &page.channels {
        if previous.is_some_and(|cursor| record.channel_id <= cursor)
            || record.channel_id == [0; 32]
            || record.trade_id == [0; 32]
            || record.provider_id.as_bytes() == &[0; 32]
            || record.status != OrderbookSettlementChannelStatusV1::Open
            || record.remaining_bytes == 0
            || record.remaining_bytes > record.total_bytes
            || record.opened_at_unix == 0
            || record.opened_at_unix > finalized_at_unix
            || record.expires_at_unix < record.opened_at_unix
            || record.updated_at_unix < record.opened_at_unix
            || record.updated_at_unix > finalized_at_unix
        {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidChannelPage);
        }
        previous = Some(record.channel_id);
    }
    Ok(())
}
fn collect_orderbook_finalized_metrics(
    view: &impl StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    finalized_at_unix: u64,
    projection: &SorafsOrderbookFinalizedTelemetryProjectionV1,
) -> Result<SorafsOrderbookFinalizedMetricsV1, SorafsOrderbookFinalizedTelemetryErrorV1> {
    let status = FindSorafsOrderbookStatus
        .execute(view)
        .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::QueryFailed)?;
    if status.last_match_scan_book_revision > status.book_revision
        || status.updated_at_unix == 0
        || status.updated_at_unix > finalized_at_unix
        || projection.last_event_book_revision > status.book_revision
        || projection.last_event_occurred_at_unix_ms / 1_000 > finalized_at_unix
        || projection.last_book_revision_advanced_at_unix_ms / 1_000 > finalized_at_unix
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch);
    }
    let mut open_depth_gib =
        [[0_u64; ORDERBOOK_TELEMETRY_SIDE_COUNT_V1]; ORDERBOOK_TELEMETRY_TIER_COUNT_V1];
    let mut inspected_orders = 0_usize;
    for lifecycle in [
        OrderbookOrderStatusV1::Open,
        OrderbookOrderStatusV1::PartiallyFilled,
    ] {
        let mut after_order_id = None;
        loop {
            let page = FindSorafsOrderbookOrders::new(
                Some(finalized_cursor),
                Some(lifecycle),
                after_order_id,
                ORDERBOOK_QUERY_MAX_ITEMS_V1,
            )
            .execute(view)
            .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::QueryFailed)?;
            validate_orderbook_telemetry_order_page(
                &page,
                finalized_cursor,
                finalized_at_unix,
                lifecycle,
                after_order_id,
            )?;
            inspected_orders = inspected_orders
                .checked_add(page.orders.len())
                .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            if inspected_orders > ORDERBOOK_TELEMETRY_MAX_ORDERS_V1
                || (inspected_orders == ORDERBOOK_TELEMETRY_MAX_ORDERS_V1 && page.has_more)
            {
                return Err(SorafsOrderbookFinalizedTelemetryErrorV1::OrderCapacityExceeded);
            }
            for record in &page.orders {
                let order = decode_order_request_v1(&record.canonical_order)
                    .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage)?;
                order
                    .validate()
                    .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage)?;
                let quantity_exceeds_order = record.remaining_gib > order.quantity_gib;
                if order.order_id != record.order_id
                    || quantity_exceeds_order
                    || order.provider_id
                        != record
                            .provider_id
                            .map(|provider_id| *provider_id.as_bytes())
                    || matches!(
                        (order.side, record.bid_escrow.is_some()),
                        (OrderSideV1::Bid, false) | (OrderSideV1::Ask, true)
                    )
                {
                    return Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage);
                }
                let tier = orderbook_telemetry_tier_index(order.tier);
                let side = orderbook_telemetry_side_index(order.side);
                open_depth_gib[tier][side] = open_depth_gib[tier][side]
                    .checked_add(record.remaining_gib)
                    .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            }
            if !page.has_more {
                break;
            }
            after_order_id = page.next_after_order_id;
        }
    }
    let active_order_count = status
        .open_orders
        .checked_add(status.partially_filled_orders)
        .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
    if u64::try_from(inspected_orders)
        .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        != active_order_count
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch);
    }
    let mut after_channel_id = None;
    let mut inspected_channels = 0_usize;
    let mut oldest_opened_at_unix = None::<u64>;
    let mut earliest_expiry_unix = None::<u64>;
    loop {
        let page = FindSorafsOrderbookChannels::new(
            Some(finalized_cursor),
            Some(OrderbookSettlementChannelStatusV1::Open),
            after_channel_id,
            ORDERBOOK_QUERY_MAX_ITEMS_V1,
        )
        .execute(view)
        .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::QueryFailed)?;
        validate_orderbook_telemetry_channel_page(
            &page,
            finalized_cursor,
            finalized_at_unix,
            after_channel_id,
        )?;
        inspected_channels = inspected_channels
            .checked_add(page.channels.len())
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if inspected_channels > ORDERBOOK_TELEMETRY_MAX_CHANNELS_V1
            || (inspected_channels == ORDERBOOK_TELEMETRY_MAX_CHANNELS_V1 && page.has_more)
        {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ChannelCapacityExceeded);
        }
        for channel in &page.channels {
            oldest_opened_at_unix = Some(
                oldest_opened_at_unix.map_or(channel.opened_at_unix, |current| {
                    current.min(channel.opened_at_unix)
                }),
            );
            earliest_expiry_unix = Some(
                earliest_expiry_unix.map_or(channel.expires_at_unix, |current| {
                    current.min(channel.expires_at_unix)
                }),
            );
        }
        if !page.has_more {
            break;
        }
        after_channel_id = page.next_after_channel_id;
    }
    let settlement_backlog = u64::try_from(inspected_channels)
        .map_err(|_| SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
    if settlement_backlog != status.open_settlement_channels
        || status.open_settlement_channels > status.settlement_channels
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch);
    }
    let admitted_orders = status
        .open_orders
        .checked_add(status.partially_filled_orders)
        .and_then(|value| value.checked_add(status.filled_orders))
        .and_then(|value| value.checked_add(status.cancelled_orders))
        .and_then(|value| value.checked_add(status.expired_orders))
        .and_then(|value| value.checked_add(status.provider_revoked_orders))
        .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
    let expected_next_admission_sequence = admitted_orders
        .checked_add(1)
        .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
    let expected_next_trade_sequence = status
        .trades
        .checked_add(1)
        .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
    let event_count = projection
        .event_counts
        .iter()
        .try_fold(0_u64, |total, value| total.checked_add(*value));
    if event_count.ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        != projection.after_event.map_or(0, |cursor| cursor.sequence)
        || projection.event_counts[1] != admitted_orders
        || projection.event_counts[2] != status.cancelled_orders
        || projection.event_counts[3] != status.trades
        || projection.event_counts[3] != status.settlement_channels
        || projection.event_counts[4] != status.expired_orders
        || projection.event_counts[5] != status.provider_revoked_orders
        || projection.event_counts[7] != status.settlement_receipts
        || status.next_admission_sequence != expected_next_admission_sequence
        || status.next_trade_sequence != expected_next_trade_sequence
    {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch);
    }
    let mut event_count_deltas = [0_u64; ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1];
    for (index, delta) in event_count_deltas.iter_mut().enumerate() {
        *delta = projection.event_counts[index]
            .checked_sub(projection.published_event_counts[index])
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch)?;
    }
    let matcher_lag_seconds = if status.last_match_scan_book_revision == status.book_revision {
        0
    } else {
        if projection.last_book_revision_advanced_at_unix_ms == 0 {
            return Err(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch);
        }
        finalized_at_unix
            .checked_sub(projection.last_book_revision_advanced_at_unix_ms / 1_000)
            .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::ProjectionMismatch)?
    };
    let oldest_settlement_age_seconds =
        oldest_opened_at_unix.map_or(0, |opened_at| finalized_at_unix.saturating_sub(opened_at));
    let escrow_runway_seconds =
        earliest_expiry_unix.map_or(0, |expiry| expiry.saturating_sub(finalized_at_unix));
    Ok(SorafsOrderbookFinalizedMetricsV1 {
        finalized_cursor,
        finalized_at_unix,
        event_count_deltas,
        open_depth_gib,
        matcher_lag_seconds,
        settlement_backlog,
        oldest_settlement_age_seconds,
        escrow_runway_seconds,
        book_revision: status.book_revision,
        matcher_scan_book_revision: status.last_match_scan_book_revision,
    })
}
fn refresh_sorafs_orderbook_finalized_telemetry(
    state: &SharedAppState,
    projection: &mut SorafsOrderbookFinalizedTelemetryProjectionV1,
) -> Result<SorafsOrderbookFinalizedTelemetryRefreshV1, SorafsOrderbookFinalizedTelemetryErrorV1> {
    let view = state.state.view();
    let (finalized_cursor, finalized_at_unix) = orderbook_finalized_tip_from_view(&view)
        .ok_or(SorafsOrderbookFinalizedTelemetryErrorV1::FinalizedViewUnavailable)?;
    if !consume_orderbook_finalized_telemetry_events(&view, finalized_cursor, projection)? {
        state.telemetry.with_metrics(
            iroha_core::telemetry::Telemetry::mark_sorafs_orderbook_finalized_projection_unready,
        );
        return Ok(SorafsOrderbookFinalizedTelemetryRefreshV1::CatchingUp);
    }
    let finalized_metrics = collect_orderbook_finalized_metrics(
        &view,
        finalized_cursor,
        finalized_at_unix,
        projection,
    )?;
    let published = state
        .telemetry
        .with_metrics(|metrics| {
            if !metrics.is_enabled() {
                return false;
            }
            metrics.record_sorafs_orderbook_finalized_projection(
                finalized_metrics.finalized_cursor.height,
                finalized_metrics.finalized_at_unix,
                finalized_metrics.event_count_deltas,
                finalized_metrics.open_depth_gib,
                finalized_metrics.matcher_lag_seconds,
                finalized_metrics.settlement_backlog,
                finalized_metrics.oldest_settlement_age_seconds,
                finalized_metrics.escrow_runway_seconds,
                finalized_metrics.book_revision,
                finalized_metrics.matcher_scan_book_revision,
            );
            true
        })
        .unwrap_or(false);
    if !published {
        return Err(SorafsOrderbookFinalizedTelemetryErrorV1::TelemetryUnavailable);
    }
    projection.published_event_counts = projection.event_counts;
    Ok(SorafsOrderbookFinalizedTelemetryRefreshV1::Published)
}
fn orderbook_maintenance_due_in_view(
    view: &impl StateReadOnly,
    finalized_cursor: OrderbookFinalizedCursorV1,
    status: &OrderbookLedgerStatusV1,
    finalized_at_unix: u64,
) -> Result<OrderbookMaintenanceDueV1, ()> {
    let active_orders = status
        .open_orders
        .checked_add(status.partially_filled_orders)
        .ok_or(())?;
    if active_orders > u64::from(ORDERBOOK_MAX_OPEN_ORDERS_V1)
        || status.open_settlement_channels > u64::from(ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1)
    {
        return Ok(OrderbookMaintenanceDueV1::Unknown);
    }
    let mut inspected_orders = 0_u64;
    for lifecycle in [
        OrderbookOrderStatusV1::Open,
        OrderbookOrderStatusV1::PartiallyFilled,
    ] {
        let mut after = None;
        loop {
            let page = FindSorafsOrderbookOrders::new(
                Some(finalized_cursor),
                Some(lifecycle),
                after,
                ORDERBOOK_QUERY_MAX_ITEMS_V1,
            )
            .execute(view)
            .map_err(|_| ())?;
            if page.finalized_cursor != finalized_cursor {
                return Err(());
            }
            for record in &page.orders {
                inspected_orders = inspected_orders.checked_add(1).ok_or(())?;
                let order = decode_order_request_v1(&record.canonical_order).map_err(|_| ())?;
                let provider_revoked = order.side == OrderSideV1::Ask
                    && record.provider_id.is_none_or(|provider_id| {
                        view.world().provider_owners().get(&provider_id) != Some(&record.owner)
                            || !FindSorafsReserveProviderById::new(provider_id)
                                .execute(view)
                                .is_ok_and(|account| {
                                    account.terms.provider_account.subject_id()
                                        == record.owner.subject_id()
                                        && account.lifecycle_stage != ReserveLifecycleStage::Default
                                })
                    });
                if finalized_at_unix >= order.expiry_unix || provider_revoked {
                    return Ok(OrderbookMaintenanceDueV1::Due);
                }
            }
            match (page.has_more, page.next_after_order_id) {
                (true, Some(next)) => after = Some(next),
                (false, None) => break,
                _ => return Err(()),
            }
        }
    }
    if inspected_orders != active_orders {
        return Ok(OrderbookMaintenanceDueV1::Unknown);
    }
    let mut inspected_channels = 0_u64;
    let mut after = None;
    loop {
        let page = FindSorafsOrderbookChannels::new(
            Some(finalized_cursor),
            Some(OrderbookSettlementChannelStatusV1::Open),
            after,
            ORDERBOOK_QUERY_MAX_ITEMS_V1,
        )
        .execute(view)
        .map_err(|_| ())?;
        if page.finalized_cursor != finalized_cursor {
            return Err(());
        }
        for channel in &page.channels {
            inspected_channels = inspected_channels.checked_add(1).ok_or(())?;
            if finalized_at_unix >= channel.expires_at_unix {
                return Ok(OrderbookMaintenanceDueV1::Due);
            }
        }
        match (page.has_more, page.next_after_channel_id) {
            (true, Some(next)) => after = Some(next),
            (false, None) => break,
            _ => return Err(()),
        }
    }
    if inspected_channels != status.open_settlement_channels {
        return Ok(OrderbookMaintenanceDueV1::Unknown);
    }
    Ok(OrderbookMaintenanceDueV1::NotDue)
}
fn generated_orderbook_operation_in_one_finalized_view(
    state: &SharedAppState,
    policy: OrderbookWorkerPolicy,
) -> Result<
    Option<(
        OrderbookOperationV1,
        sorafs_node::orderbook_transaction_forwarder::OrderbookTransactionContextV1,
    )>,
    (),
> {
    let view = state.state.view();
    let (finalized_cursor, finalized_at_unix) =
        orderbook_finalized_tip_from_view(&view).ok_or(())?;
    let policy_record = FindSorafsOrderbookPolicy.execute(&view).map_err(|_| ())?;
    if policy_record.activated_at_unix == 0 || policy_record.activated_at_unix > finalized_at_unix {
        return Err(());
    }
    let status = FindSorafsOrderbookStatus.execute(&view).map_err(|_| ())?;
    let maintenance_due =
        orderbook_maintenance_due_in_view(&view, finalized_cursor, &status, finalized_at_unix)?;
    let snapshot = OrderbookGenerationSnapshotV1 {
        finalized_cursor,
        finalized_at_unix,
        policy_record: policy_record.clone(),
        status: status.clone(),
        maintenance_due,
    };
    let operation = plan_orderbook_generation(
        &snapshot,
        policy.match_batch_limit(),
        policy.maintenance_batch_limit(),
    )
    .map_err(|_| ())?;
    Ok(operation.map(|operation| {
        (
            operation,
            sorafs_node::orderbook_transaction_forwarder::OrderbookTransactionContextV1 {
                network_id: *state.state.network_id_ref(),
                policy_record,
                book_revision: status.book_revision,
                finalized_cursor,
            },
        )
    }))
}
fn receipt_identity(
    retained: &OrderbookTransactionSigningRequestV1,
) -> Option<([u8; 32], [u8; 32])> {
    let OrderbookOperationV1::SettlementReceipt(instruction) = &retained.operation else {
        return None;
    };
    let receipt = decode_settlement_receipt_v1(instruction.receipt_payload()).ok()?;
    Some((receipt.receipt_id, receipt.channel_id))
}
fn orderbook_snapshot_in_view(
    view: &impl StateReadOnly,
    delivery: &OrderbookTransactionPendingV1,
    retained: &OrderbookTransactionSigningRequestV1,
) -> Option<OrderbookFinalizedSnapshotV1> {
    let (finalized_cursor, finalized_at_unix) = orderbook_finalized_tip_from_view(view)?;
    let baseline_block_hash = delivery
        .baseline_finalized_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .and_then(|index| view.block_hashes().get(index))
        .map(|hash| *hash.as_ref());
    let policy_record = match FindSorafsOrderbookPolicy.execute(view) {
        Ok(record) => Some(record),
        Err(QueryExecutionFail::Find(FindError::SorafsOrderbookPolicy)) => None,
        Err(_) => return None,
    };
    let status = match FindSorafsOrderbookStatus.execute(view) {
        Ok(status) => Some(status),
        Err(QueryExecutionFail::Find(FindError::SorafsOrderbookStatus)) => None,
        Err(_) => return None,
    };
    let (settlement_receipt, settlement_channel) =
        if let Some((receipt_id, channel_id)) = receipt_identity(retained) {
            let receipt = match FindSorafsOrderbookReceiptById::new(receipt_id).execute(view) {
                Ok(receipt) => Some(receipt),
                Err(QueryExecutionFail::Find(FindError::SorafsOrderbookReceipt(missing)))
                    if missing == receipt_id =>
                {
                    None
                }
                Err(_) => return None,
            };
            let channel = match FindSorafsOrderbookChannelById::new(channel_id).execute(view) {
                Ok(channel) => Some(channel),
                Err(QueryExecutionFail::Find(FindError::SorafsOrderbookChannel(missing)))
                    if missing == channel_id =>
                {
                    None
                }
                Err(_) => return None,
            };
            (receipt, channel)
        } else {
            (None, None)
        };
    Some(OrderbookFinalizedSnapshotV1 {
        finalized_cursor,
        finalized_at_unix,
        baseline_block_hash,
        policy_record,
        status,
        settlement_receipt,
        settlement_channel,
    })
}
fn observe_orderbook_transaction_in_one_finalized_view(
    state: &SharedAppState,
    delivery: &OrderbookTransactionPendingV1,
    retained: &OrderbookTransactionSigningRequestV1,
    transaction_hash: Option<&HashOf<SignedTransaction>>,
) -> Option<OrderbookFinalizedObservationV1> {
    let view = state.state.view();
    let snapshot = orderbook_snapshot_in_view(&view, delivery, retained)?;
    // Capture all economic state and the exact indexed carrier in one view.
    // Historical authentication owns no World read lock.
    let indexed = transaction_hash.map(|hash| {
        let input = iroha_core::tx::external_entrypoint_hash_from_signed_hash(*hash);
        let height = view.transactions().get(&input);
        let carrier = height.and_then(|height| {
            view.block_hashes()
                .get(height.get() - 1)
                .copied()
                .map(|hash| (height, hash))
        });
        (input, height, carrier)
    });
    drop(view);
    let transaction_outcome = transaction_hash
        .zip(indexed)
        .map(|(hash, (_, height, carrier))| match (height, carrier) {
            (None, _) => OrderbookAuthoritativeTransactionOutcomeV1::Absent,
            (Some(_), None) => OrderbookAuthoritativeTransactionOutcomeV1::Unavailable,
            (Some(_), Some((height, expected))) => {
                inspect_indexed_orderbook_transaction(&state.state, hash, height, expected)
            }
        });
    let current = state.state.view();
    let cursor_height = usize::try_from(snapshot.finalized_cursor.height).ok()?;
    if current
        .block_hashes()
        .get(cursor_height.checked_sub(1)?)
        .map(|hash| *hash.as_ref())
        != Some(snapshot.finalized_cursor.block_hash)
        || indexed.is_some_and(|(input, height, _)| current.transactions().get(&input) != height)
    {
        return None;
    }
    Some(OrderbookFinalizedObservationV1 {
        snapshot,
        transaction_outcome,
    })
}
fn decode_exact_orderbook_signed_transaction(
    bytes: &[u8],
    request: &OrderbookTransactionSigningRequestV1,
) -> Option<SignedTransaction> {
    if bytes.is_empty() || bytes.len() > ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1 {
        return None;
    }
    norito::core::from_bytes_view(bytes).ok()?;
    let total_elements = bytes.len().checked_mul(8)?;
    let total_allocated_bytes = bytes.len().checked_mul(20)?.checked_add(512 * 1024)?;
    let limits = norito::DecodeLimits::new(
        ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1,
        ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1,
        total_elements,
        total_allocated_bytes,
        128,
    );
    let transaction =
        norito::decode_from_bytes_with_limits::<SignedTransaction>(bytes, limits).ok()?;
    if norito::to_bytes(&transaction).ok()?.as_slice() != bytes
        || transaction.verify_signature().is_err()
        || transaction.network_id() != Some(&request.network_id)
        || transaction.authority() != &request.authority
    {
        return None;
    }
    let expected_instruction = InstructionBox::from(request.operation.clone());
    match transaction.instructions() {
        Executable::Instructions(instructions)
            if instructions.len() == 1 && instructions.first() == Some(&expected_instruction) =>
        {
            Some(transaction)
        }
        _ => None,
    }
}
/// Start orderbook generation and durable drain/reconciliation when the role is active.
///
/// Storage enablement keeps the role active for restart recovery even when
/// `orderbook_worker.enabled` suppresses generation of new matcher or
/// maintenance operations. When both controls are disabled, retained entries
/// make zero external progress because no task is spawned. Opening the local
/// node may still release interrupted signer-only claims back to `Ready`.
pub fn spawn_sorafs_orderbook_transaction_forwarder_worker(
    state: SharedAppState,
    shutdown_signal: ShutdownSignal,
) -> Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>> {
    let policy = state.sorafs_node.config().orderbook_worker_policy();
    let supervision =
        orderbook_worker_supervision(state.sorafs_node.config().enabled(), policy.enabled());
    let worker = spawn_orderbook_worker_when_active(supervision, move || {
        if !supervision.generation_enabled {
            debug!(
                "SoraFS orderbook generation is disabled; storage-enabled durable drain and finalized reconciliation remain active"
            );
        }
        if state.sorafs_orderbook_transaction_signer.is_none() {
            warn!(
                "active SoraFS orderbook forwarder has no runtime signer; signing remains deferred"
            );
        }
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(policy.scan_interval());
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut cursor = SorafsOrderbookTransactionForwarderCursorV1::default();
            loop {
                tokio::select! {
                    biased;
                    () = shutdown_signal.receive() => {
                        return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    }
                    _ = interval.tick() => {
                        if shutdown_signal.is_sent() {
                            return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                        }
                        let scan =
                            run_sorafs_orderbook_transaction_forwarder_scan(&state, &mut cursor).await;
                        if scan.generated != 0
                            || scan.generation_replayed != 0
                            || scan.generation_deferred != 0
                            || scan.scanned != 0
                            || scan.telemetry_published != 0
                            || scan.telemetry_catching_up != 0
                            || scan.telemetry_failed != 0
                        {
                            debug!(
                                generated = scan.generated,
                                generation_replayed = scan.generation_replayed,
                                generation_deferred = scan.generation_deferred,
                                scanned = scan.scanned,
                                finalized = scan.finalized,
                                signed = scan.signed,
                                submitted = scan.submitted,
                                deferred = scan.deferred,
                                conflicted = scan.conflicted,
                                rejected = scan.rejected,
                                telemetry_published = scan.telemetry_published,
                                telemetry_catching_up = scan.telemetry_catching_up,
                                telemetry_failed = scan.telemetry_failed,
                                generation_enabled = supervision.generation_enabled,
                                "processed durable native SoraFS orderbook transactions"
                            );
                        }
                    }
                }
            }
        })
    });
    if worker.is_none() {
        debug!(
            "SoraFS orderbook worker is paused because storage and generation are disabled; no external work was started"
        );
    }
    worker
}
pub async fn run_sorafs_orderbook_transaction_forwarder_scan(
    state: &SharedAppState,
    cursor: &mut SorafsOrderbookTransactionForwarderCursorV1,
) -> SorafsOrderbookTransactionForwarderScanV1 {
    let mut scan = SorafsOrderbookTransactionForwarderScanV1::default();
    if state.telemetry.allows_metrics()
        && state
            .telemetry
            .telemetry()
            .is_some_and(iroha_core::telemetry::Telemetry::is_enabled)
    {
        match refresh_sorafs_orderbook_finalized_telemetry(state, &mut cursor.telemetry) {
            Ok(SorafsOrderbookFinalizedTelemetryRefreshV1::Published) => {
                scan.telemetry_published = 1;
            }
            Ok(SorafsOrderbookFinalizedTelemetryRefreshV1::CatchingUp) => {
                scan.telemetry_catching_up = 1;
            }
            Err(error) => {
                scan.telemetry_failed = 1;
                state.telemetry.with_metrics(|metrics| {
                    metrics.record_sorafs_orderbook_finalized_projection_failure(error.label())
                });
                warn!(
                    reason = error.label(),
                    "failed to publish finalized SoraFS orderbook telemetry"
                );
            }
        }
    }
    let policy = state.sorafs_node.config().orderbook_worker_policy();
    if policy.enabled() {
        match generated_orderbook_operation_in_one_finalized_view(state, policy) {
            Ok(Some((operation, context))) => {
                match state
                    .sorafs_node
                    .enqueue_orderbook_transaction(operation, &context)
                {
                    Ok(OrderbookTransactionEnqueueResultV1::Inserted { .. }) => {
                        scan.generated = scan.generated.saturating_add(1);
                    }
                    Ok(OrderbookTransactionEnqueueResultV1::Existing { .. }) => {
                        scan.generation_replayed = scan.generation_replayed.saturating_add(1);
                    }
                    Err(_) => {
                        scan.generation_deferred = scan.generation_deferred.saturating_add(1);
                        warn!("failed to durably enqueue generated native SoraFS orderbook work");
                    }
                }
            }
            Ok(None) => {}
            Err(()) => {
                scan.generation_deferred = scan.generation_deferred.saturating_add(1);
                warn!(
                    "failed to derive native SoraFS orderbook work from one finalized ledger view"
                );
            }
        }
    }
    let scan_limit = ORDERBOOK_TRANSACTION_FORWARDER_MAX_SCAN_ITEMS_V1;
    let pending = match state
        .sorafs_node
        .pending_orderbook_transactions_after(cursor.after_sequence, scan_limit)
    {
        Ok(pending) => pending,
        Err(_) => {
            warn!("failed to load durable native SoraFS orderbook transactions");
            return scan;
        }
    };
    for delivery in pending {
        cursor.after_sequence = Some(delivery.sequence);
        scan.scanned = scan.scanned.saturating_add(1);
        if validate_orderbook_pending_delivery_v1(&delivery).is_err() {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!("durable native SoraFS orderbook delivery failed validation");
            continue;
        }
        let retained = match state
            .sorafs_node
            .orderbook_transaction_operation_for_reconciliation(delivery.operation_id)
        {
            Ok(retained)
                if retained.operation_id == delivery.operation_id
                    && retained.network_id == delivery.network_id
                    && retained.authority == delivery.authority
                    && validate_orderbook_reconciliation_material_v1(&delivery, &retained)
                        .is_ok() =>
            {
                retained
            }
            Ok(_) | Err(_) => {
                scan.deferred = scan.deferred.saturating_add(1);
                warn!("failed to read exact native SoraFS orderbook semantics");
                continue;
            }
        };
        if retained.network_id != *state.state.network_id_ref() {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!("durable native SoraFS orderbook delivery belongs to another network");
            continue;
        }
        let exact_transaction = match delivery.signed_transaction_bytes.as_deref() {
            Some(bytes) => {
                if retained_transaction_digest(delivery.transaction_digest, Some(bytes)).is_none() {
                    scan.deferred = scan.deferred.saturating_add(1);
                    warn!("durable native SoraFS orderbook transaction digest is invalid");
                    continue;
                }
                let Some(transaction) = decode_exact_orderbook_signed_transaction(bytes, &retained)
                else {
                    scan.deferred = scan.deferred.saturating_add(1);
                    warn!("durable native SoraFS orderbook transaction bytes failed validation");
                    continue;
                };
                Some(transaction)
            }
            None => None,
        };
        let exact_transaction_hash = exact_transaction.as_ref().map(SignedTransaction::hash);
        let delivery_evidence_before = exact_transaction_hash.as_ref().is_some_and(|hash| {
            let queue_pending = state.queue.contains_pending_hash(
                iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
                &state.state,
            );
            let cache_kind = state
                .pipeline_status_cache
                .lookup(hash)
                .map(|entry| entry.kind);
            pending_evidence_blocks_absence_retry(queue_pending, cache_kind)
        });
        let Some(observation) = observe_orderbook_transaction_in_one_finalized_view(
            state,
            &delivery,
            &retained,
            exact_transaction_hash.as_ref(),
        ) else {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!("authoritative SoraFS orderbook observation failed");
            continue;
        };
        let semantics = reconcile_orderbook_semantics(
            state.state.network_id_ref(),
            &delivery,
            &retained,
            &observation.snapshot,
        );
        let delivery_evidence_after = exact_transaction_hash.as_ref().is_some_and(|hash| {
            let queue_pending = state.queue.contains_pending_hash(
                iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
                &state.state,
            );
            let cache_kind = state
                .pipeline_status_cache
                .lookup(hash)
                .map(|entry| entry.kind);
            pending_evidence_blocks_absence_retry(queue_pending, cache_kind)
        });
        let envelope = match observation.transaction_outcome {
            Some(outcome) => classify_orderbook_envelope(
                delivery.transaction_digest,
                delivery.signed_transaction_bytes.as_deref(),
                observation.snapshot.finalized_cursor,
                outcome,
                delivery_evidence_before || delivery_evidence_after,
            ),
            None => OrderbookEnvelopeReconciliationV1::NotSigned,
        };
        let signer_authority = state
            .sorafs_orderbook_transaction_signer
            .as_ref()
            .map(|signer| signer.authority());
        let action = plan_orderbook_worker_action(
            state.state.network_id_ref(),
            signer_authority.as_ref(),
            &delivery,
            envelope,
            semantics,
        );
        apply_orderbook_worker_action(
            state,
            &delivery,
            &retained,
            exact_transaction,
            action,
            &mut scan,
        )
        .await;
    }
    scan
}
async fn apply_orderbook_worker_action(
    state: &SharedAppState,
    delivery: &OrderbookTransactionPendingV1,
    retained: &OrderbookTransactionSigningRequestV1,
    exact_transaction: Option<SignedTransaction>,
    action: OrderbookWorkerActionV1,
    scan: &mut SorafsOrderbookTransactionForwarderScanV1,
) {
    match action {
        OrderbookWorkerActionV1::FinalizeExact {
            transaction_digest,
            finalized_cursor,
        } => match state.sorafs_node.mark_orderbook_transaction_finalized(
            delivery.operation_id,
            transaction_digest,
            finalized_cursor,
        ) {
            Ok(()) => scan.finalized = scan.finalized.saturating_add(1),
            Err(_) => scan.deferred = scan.deferred.saturating_add(1),
        },
        OrderbookWorkerActionV1::FinalizeSemantic { finalized_cursor } => {
            match state
                .sorafs_node
                .mark_orderbook_transaction_semantic_finalized(
                    delivery.operation_id,
                    finalized_cursor,
                ) {
                Ok(()) => scan.finalized = scan.finalized.saturating_add(1),
                Err(_) => scan.deferred = scan.deferred.saturating_add(1),
            }
        }
        OrderbookWorkerActionV1::DeadLetterConflict { finalized_cursor } => {
            match state
                .sorafs_node
                .mark_orderbook_transaction_finalized_conflict(
                    delivery.operation_id,
                    finalized_cursor,
                ) {
                Ok(()) => scan.conflicted = scan.conflicted.saturating_add(1),
                Err(_) => scan.deferred = scan.deferred.saturating_add(1),
            }
        }
        OrderbookWorkerActionV1::MarkFinalizedAbsent { finalized_cursor } => {
            if state
                .sorafs_node
                .mark_orderbook_transaction_finalized_absent(
                    delivery.operation_id,
                    finalized_cursor,
                )
                .is_err()
            {
                warn!(
                    "failed to checkpoint authoritative absence for a native SoraFS orderbook transaction"
                );
            }
            scan.deferred = scan.deferred.saturating_add(1);
        }
        OrderbookWorkerActionV1::AdoptExactPending => {
            let transitioned = if delivery.state == OrderbookTransactionDeliveryStateV1::Signed {
                state
                    .sorafs_node
                    .begin_orderbook_transaction_submission(delivery.operation_id)
                    .is_ok_and(|bytes| {
                        delivery
                            .signed_transaction_bytes
                            .as_deref()
                            .is_some_and(|expected| bytes.as_slice() == expected)
                    })
            } else {
                true
            };
            if transitioned
                && state
                    .sorafs_node
                    .mark_orderbook_transaction_submitted(delivery.operation_id)
                    .is_ok()
            {
                scan.submitted = scan.submitted.saturating_add(1);
            } else {
                scan.deferred = scan.deferred.saturating_add(1);
            }
        }
        OrderbookWorkerActionV1::MarkTransactionRejected { finalized_cursor } => {
            let transitioned = if delivery.state == OrderbookTransactionDeliveryStateV1::Signed {
                state
                    .sorafs_node
                    .begin_orderbook_transaction_submission(delivery.operation_id)
                    .is_ok_and(|bytes| {
                        delivery
                            .signed_transaction_bytes
                            .as_deref()
                            .is_some_and(|expected| bytes.as_slice() == expected)
                    })
            } else {
                true
            };
            if transitioned
                && state
                    .sorafs_node
                    .mark_orderbook_transaction_rejected(delivery.operation_id, finalized_cursor)
                    .is_ok()
            {
                scan.rejected = scan.rejected.saturating_add(1);
            } else {
                scan.deferred = scan.deferred.saturating_add(1);
            }
        }
        OrderbookWorkerActionV1::ClaimForSigning => {
            let Some(signer) = state.sorafs_orderbook_transaction_signer.clone() else {
                scan.deferred = scan.deferred.saturating_add(1);
                return;
            };
            let claimed = match state
                .sorafs_node
                .claim_orderbook_transaction_for_signing(delivery.operation_id)
            {
                Ok(claimed) if claimed == *retained => claimed,
                Ok(_) | Err(_) => {
                    let _ = state
                        .sorafs_node
                        .release_orderbook_transaction_signing_claim(delivery.operation_id);
                    scan.deferred = scan.deferred.saturating_add(1);
                    return;
                }
            };
            let Some((transaction, transaction_bytes)) =
                sign_sorafs_orderbook_transaction(state, signer, &claimed).await
            else {
                let _ = state
                    .sorafs_node
                    .release_orderbook_transaction_signing_claim(delivery.operation_id);
                scan.deferred = scan.deferred.saturating_add(1);
                return;
            };
            match state
                .sorafs_node
                .store_signed_orderbook_transaction(delivery.operation_id, &transaction_bytes)
            {
                Ok(transaction_digest)
                    if transaction_digest == *blake3_hash(&transaction_bytes).as_bytes() =>
                {
                    scan.signed = scan.signed.saturating_add(1);
                }
                Ok(_) | Err(_) => {
                    let _ = state
                        .sorafs_node
                        .release_orderbook_transaction_signing_claim(delivery.operation_id);
                    scan.deferred = scan.deferred.saturating_add(1);
                    return;
                }
            }
            match submit_sorafs_orderbook_transaction(
                state,
                delivery.operation_id,
                transaction_bytes,
                transaction,
            )
            .await
            {
                OrderbookTransactionSubmissionResultV1::Submitted => {
                    scan.submitted = scan.submitted.saturating_add(1);
                }
                OrderbookTransactionSubmissionResultV1::Rejected => {
                    scan.rejected = scan.rejected.saturating_add(1);
                }
                OrderbookTransactionSubmissionResultV1::Deferred => {
                    scan.deferred = scan.deferred.saturating_add(1);
                }
            }
        }
        OrderbookWorkerActionV1::SubmitSignedBytes => {
            let (Some(transaction), Some(transaction_bytes)) =
                (exact_transaction, delivery.signed_transaction_bytes.clone())
            else {
                scan.deferred = scan.deferred.saturating_add(1);
                return;
            };
            match submit_sorafs_orderbook_transaction(
                state,
                delivery.operation_id,
                transaction_bytes,
                transaction,
            )
            .await
            {
                OrderbookTransactionSubmissionResultV1::Submitted => {
                    scan.submitted = scan.submitted.saturating_add(1);
                }
                OrderbookTransactionSubmissionResultV1::Rejected => {
                    scan.rejected = scan.rejected.saturating_add(1);
                }
                OrderbookTransactionSubmissionResultV1::Deferred => {
                    scan.deferred = scan.deferred.saturating_add(1);
                }
            }
        }
        OrderbookWorkerActionV1::Defer(_) => {
            scan.deferred = scan.deferred.saturating_add(1);
        }
    }
}
async fn sign_sorafs_orderbook_transaction(
    state: &SharedAppState,
    signer: Arc<dyn SoraFsOrderbookTransactionSigner>,
    request: &OrderbookTransactionSigningRequestV1,
) -> Option<(SignedTransaction, Vec<u8>)> {
    if signer.authority() != request.authority
        || request.network_id != *state.state.network_id_ref()
    {
        return None;
    }
    let mut builder = TransactionBuilder::new(
        request.network_id,
        request.authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([InstructionBox::from(request.operation.clone())]);
    builder.set_ttl(Duration::from_secs(300));
    let mut payload = builder.into_payload().ok()?;
    payload.fee_payment = crate::quote_internal_fee_payment(state, &payload).ok()?;
    let expected_payload = payload.clone();
    let transaction = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || signer.sign(payload)),
    )
    .await
    .ok()?
    .ok()?;
    if transaction.payload() != &expected_payload {
        return None;
    }
    let bytes = norito::to_bytes(&transaction).ok()?;
    if bytes.len() > ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1
        || decode_exact_orderbook_signed_transaction(&bytes, request).is_none()
    {
        return None;
    }
    Some((transaction, bytes))
}
async fn submit_sorafs_orderbook_transaction(
    state: &SharedAppState,
    operation_id: [u8; 32],
    transaction_bytes: Vec<u8>,
    transaction: SignedTransaction,
) -> OrderbookTransactionSubmissionResultV1 {
    if transaction.network_id() != Some(state.state.network_id_ref()) {
        return OrderbookTransactionSubmissionResultV1::Deferred;
    }
    let accepted = match crate::routing::accept_transaction_for_ingress(
        state.state.clone(),
        transaction.clone(),
        &state.telemetry,
    ) {
        Ok(accepted) => accepted,
        Err(_) => {
            let exact = state
                .sorafs_node
                .begin_orderbook_transaction_submission(operation_id);
            if !exact
                .as_ref()
                .is_ok_and(|bytes| bytes == &transaction_bytes)
            {
                return OrderbookTransactionSubmissionResultV1::Deferred;
            }
            let Some(finalized_cursor) = current_orderbook_finalized_cursor(state) else {
                return OrderbookTransactionSubmissionResultV1::Deferred;
            };
            return if state
                .sorafs_node
                .mark_orderbook_transaction_rejected(operation_id, finalized_cursor)
                .is_ok()
            {
                OrderbookTransactionSubmissionResultV1::Rejected
            } else {
                OrderbookTransactionSubmissionResultV1::Deferred
            };
        }
    };
    let routing_plan = match state
        .queue
        .route_plan_with_state(&accepted, state.state.as_ref())
    {
        Ok(plan) => plan,
        Err(_) => return OrderbookTransactionSubmissionResultV1::Deferred,
    };
    let routing_decision = routing_plan.coordinator_route();
    let exact_transaction_bytes = match state
        .sorafs_node
        .begin_orderbook_transaction_submission(operation_id)
    {
        Ok(bytes) => bytes,
        Err(_) => return OrderbookTransactionSubmissionResultV1::Deferred,
    };
    if exact_transaction_bytes != transaction_bytes {
        return OrderbookTransactionSubmissionResultV1::Deferred;
    }
    let disposition = if crate::should_execute_route_locally(state.as_ref(), routing_decision) {
        match crate::routing::push_accepted_transaction_for_ingress_with_routing_plan(
            state.queue.clone(),
            state.state.clone(),
            accepted,
            Some(routing_plan),
        ) {
            Ok(_) => OrderbookTransactionSubmissionDispositionV1::Submitted,
            Err(crate::Error::PushIntoQueue { source, .. }) => {
                classify_orderbook_transaction_submission(source.as_ref())
            }
            Err(_) => OrderbookTransactionSubmissionDispositionV1::Ambiguous,
        }
    } else {
        let response = crate::execute_torii_transaction_via_proxy(
            state,
            accepted,
            routing_plan,
            true,
            crate::utils::ResponseFormat::Norito,
        )
        .await;
        if response.status() == StatusCode::ACCEPTED {
            OrderbookTransactionSubmissionDispositionV1::Submitted
        } else {
            OrderbookTransactionSubmissionDispositionV1::Ambiguous
        }
    };
    match disposition {
        OrderbookTransactionSubmissionDispositionV1::Submitted => {
            if state
                .sorafs_node
                .mark_orderbook_transaction_submitted(operation_id)
                .is_ok()
            {
                OrderbookTransactionSubmissionResultV1::Submitted
            } else {
                OrderbookTransactionSubmissionResultV1::Deferred
            }
        }
        OrderbookTransactionSubmissionDispositionV1::DefinitelyNotSubmitted => {
            let _ = state
                .sorafs_node
                .mark_orderbook_transaction_not_submitted(operation_id);
            OrderbookTransactionSubmissionResultV1::Deferred
        }
        OrderbookTransactionSubmissionDispositionV1::Rejected => {
            let Some(finalized_cursor) = current_orderbook_finalized_cursor(state) else {
                return OrderbookTransactionSubmissionResultV1::Deferred;
            };
            if state
                .sorafs_node
                .mark_orderbook_transaction_rejected(operation_id, finalized_cursor)
                .is_ok()
            {
                OrderbookTransactionSubmissionResultV1::Rejected
            } else {
                OrderbookTransactionSubmissionResultV1::Deferred
            }
        }
        OrderbookTransactionSubmissionDispositionV1::Ambiguous => {
            OrderbookTransactionSubmissionResultV1::Deferred
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId, events::data::sorafs::SorafsOrderbookLedgerEvent,
        sorafs::orderbook::OrderbookFinalizedEventV1,
    };
    fn cursor(height: u64, seed: u8) -> OrderbookFinalizedCursorV1 {
        OrderbookFinalizedCursorV1 {
            height,
            block_hash: [seed; 32],
        }
    }
    fn transaction_hash(seed: u8) -> HashOf<SignedTransaction> {
        HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32]))
    }
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed.max(1); 32], Algorithm::Ed25519)
            .expect("deterministic account");
        AccountId::new(keypair.public_key().clone())
    }
    fn finalized_event(
        sequence: u64,
        block_height: u64,
        event_index: u32,
        kind: SorafsOrderbookLedgerEventKind,
    ) -> OrderbookFinalizedEventV1 {
        let (order_id, trade_id, channel_id, receipt_id, provider_id) = match kind {
            SorafsOrderbookLedgerEventKind::PolicyActivated => (None, None, None, None, None),
            SorafsOrderbookLedgerEventKind::OrderAdmitted => {
                (Some([0x11; 32]), None, None, None, None)
            }
            _ => panic!("test helper only needs policy and admission events"),
        };
        OrderbookFinalizedEventV1 {
            sequence,
            block_height,
            block_hash: [u8::try_from(block_height).unwrap_or(0xFF); 32],
            event_index,
            event: SorafsOrderbookLedgerEvent {
                kind,
                order_id,
                trade_id,
                channel_id,
                receipt_id,
                provider_id,
                book_revision: u64::from(kind != SorafsOrderbookLedgerEventKind::PolicyActivated),
                authority: account(7),
                occurred_at_unix_ms: block_height.saturating_mul(1_000),
            },
        }
    }
    #[test]
    fn queue_domain_mismatch_is_permanent_orderbook_runtime_rejection() {
        assert_eq!(
            classify_orderbook_transaction_submission(
                &iroha_core::queue::Error::TransactionDomainMismatch(
                    iroha_data_model::isi::error::Mismatch {
                        expected: iroha_data_model::transaction::TransactionDomain::Network(
                            iroha_data_model::NetworkId::from_genesis_hash(
                                iroha_crypto::HashOf::from_untyped_unchecked(
                                    iroha_crypto::Hash::prehashed([0xD2; 32])
                                )
                            )
                        ),
                        actual: iroha_data_model::transaction::TransactionDomain::Genesis,
                    },
                )
            ),
            OrderbookTransactionSubmissionDispositionV1::Rejected
        );
        assert_eq!(
            classify_orderbook_transaction_submission(&iroha_core::queue::Error::Full),
            OrderbookTransactionSubmissionDispositionV1::DefinitelyNotSubmitted
        );
        assert_eq!(
            classify_orderbook_transaction_submission(&iroha_core::queue::Error::IsInQueue),
            OrderbookTransactionSubmissionDispositionV1::Submitted
        );
    }
    #[test]
    fn orderbook_supervision_uses_storage_or_generation_activation() {
        for (storage_enabled, generation_enabled, role_active) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(
                orderbook_worker_supervision(storage_enabled, generation_enabled),
                OrderbookWorkerSupervisionV1 {
                    generation_enabled,
                    role_active,
                }
            );
        }
    }
    #[test]
    fn disabled_orderbook_supervision_does_not_invoke_spawn_adapter() {
        let spawn_count = std::cell::Cell::new(0_u32);
        assert!(
            spawn_orderbook_worker_when_active(orderbook_worker_supervision(false, false), || {
                spawn_count.set(spawn_count.get() + 1);
            })
            .is_none()
        );
        assert_eq!(spawn_count.get(), 0);
        assert!(
            spawn_orderbook_worker_when_active(orderbook_worker_supervision(true, false), || {
                spawn_count.set(spawn_count.get() + 1);
            })
            .is_some()
        );
        assert_eq!(spawn_count.get(), 1);
    }
    #[test]
    fn delivery_pending_or_committed_evidence_blocks_absence_retry() {
        assert!(pending_evidence_blocks_absence_retry(true, None));
        for kind in [
            crate::PipelineStatusKind::Queued,
            crate::PipelineStatusKind::Approved,
            crate::PipelineStatusKind::Committed,
            crate::PipelineStatusKind::Applied,
        ] {
            assert!(pending_evidence_blocks_absence_retry(false, Some(kind),));
        }
        assert!(!pending_evidence_blocks_absence_retry(false, None,));
    }
    #[test]
    fn finalized_entrypoint_lookup_requires_exactly_one_result() {
        let expected = transaction_hash(1);
        let other = transaction_hash(2);
        assert_eq!(
            classify_exact_orderbook_entrypoint_outcome(
                &expected,
                true,
                [(other, OrderbookCommittedExternalOutcomeV1::Applied)],
            ),
            OrderbookAuthoritativeTransactionOutcomeV1::Unavailable,
        );
        assert_eq!(
            classify_exact_orderbook_entrypoint_outcome(
                &expected,
                true,
                [
                    (
                        expected.clone(),
                        OrderbookCommittedExternalOutcomeV1::Applied,
                    ),
                    (expected, OrderbookCommittedExternalOutcomeV1::Applied),
                ],
            ),
            OrderbookAuthoritativeTransactionOutcomeV1::Unavailable,
        );
    }
    #[test]
    fn envelope_absence_retries_only_without_delivery_evidence() {
        let bytes = [0xA5; 32];
        let digest = *blake3_hash(&bytes).as_bytes();
        assert!(matches!(
            classify_orderbook_envelope(
                Some(digest),
                Some(&bytes),
                cursor(7, 7),
                OrderbookAuthoritativeTransactionOutcomeV1::Absent,
                true,
            ),
            OrderbookEnvelopeReconciliationV1::Pending { .. }
        ));
        assert!(matches!(
            classify_orderbook_envelope(
                Some(digest),
                Some(&bytes),
                cursor(7, 7),
                OrderbookAuthoritativeTransactionOutcomeV1::Absent,
                false,
            ),
            OrderbookEnvelopeReconciliationV1::Absent { .. }
        ));
    }
    #[test]
    fn finalized_telemetry_event_pages_reject_gaps_atomically() {
        let finalized_cursor = cursor(4, 4);
        let first = finalized_event(1, 1, 0, SorafsOrderbookLedgerEventKind::PolicyActivated);
        let first_cursor = first.cursor();
        let first_page = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![first],
            has_more: true,
            next_after: Some(first_cursor),
        };
        let mut projection = SorafsOrderbookFinalizedTelemetryProjectionV1::default();
        apply_orderbook_finalized_telemetry_event_page(
            &mut projection,
            &first_page,
            finalized_cursor,
        )
        .expect("initial finalized event");
        let before_gap = projection;
        let gap_page = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_event(
                3,
                2,
                0,
                SorafsOrderbookLedgerEventKind::OrderAdmitted,
            )],
            has_more: false,
            next_after: None,
        };
        assert_eq!(
            apply_orderbook_finalized_telemetry_event_page(
                &mut projection,
                &gap_page,
                finalized_cursor,
            ),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage)
        );
        assert_eq!(
            projection, before_gap,
            "a rejected page must not partially advance the projection"
        );
    }
    #[test]
    fn finalized_telemetry_rejects_incomplete_empty_pages_and_bad_block_indices() {
        let finalized_cursor = cursor(4, 4);
        let impossible_cursor = OrderbookFinalizedEventCursorV1 {
            sequence: 1,
            block_height: 1,
            block_hash: [1; 32],
            event_index: 0,
        };
        let incomplete = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: Vec::new(),
            has_more: true,
            next_after: Some(impossible_cursor),
        };
        let mut projection = SorafsOrderbookFinalizedTelemetryProjectionV1::default();
        assert_eq!(
            apply_orderbook_finalized_telemetry_event_page(
                &mut projection,
                &incomplete,
                finalized_cursor,
            ),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage)
        );
        let bad_index = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_event(
                1,
                1,
                1,
                SorafsOrderbookLedgerEventKind::PolicyActivated,
            )],
            has_more: false,
            next_after: None,
        };
        assert_eq!(
            apply_orderbook_finalized_telemetry_event_page(
                &mut projection,
                &bad_index,
                finalized_cursor,
            ),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidEventPage)
        );
        assert_eq!(
            projection,
            SorafsOrderbookFinalizedTelemetryProjectionV1::default()
        );
    }
    #[test]
    fn finalized_telemetry_rejects_event_hashes_outside_the_finalized_journal() {
        let finalized_cursor = cursor(4, 4);
        let block_hashes: Vec<HashOf<BlockHeader>> = (1_u8..=4)
            .map(|seed| HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32])))
            .collect();
        let expected_event_hash = *block_hashes[1].as_ref();
        let mut page = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_event(
                1,
                2,
                0,
                SorafsOrderbookLedgerEventKind::PolicyActivated,
            )],
            has_more: false,
            next_after: None,
        };
        page.events[0].block_hash = expected_event_hash;
        assert!(orderbook_telemetry_event_block_hashes_are_finalized(
            &block_hashes,
            &page
        ));
        page.events[0].block_hash = [0xA5; 32];
        assert!(!orderbook_telemetry_event_block_hashes_are_finalized(
            &block_hashes,
            &page
        ));
        let journal = iroha_core::state::BlockHashes::new(block_hashes);
        let captured = journal.view();
        page.events[0].block_hash = expected_event_hash;
        assert!(orderbook_telemetry_event_block_hashes_are_finalized(
            &captured, &page
        ));
        page.events[0].block_height = 0;
        assert!(!orderbook_telemetry_event_block_hashes_are_finalized(
            &captured, &page
        ));
        page.events[0].block_height = 5;
        assert!(!orderbook_telemetry_event_block_hashes_are_finalized(
            &captured, &page
        ));
    }
    #[test]
    fn finalized_telemetry_matcher_clock_tracks_book_mutations_only() {
        let finalized_cursor = cursor(4, 4);
        let mut later_policy =
            finalized_event(3, 3, 0, SorafsOrderbookLedgerEventKind::PolicyActivated);
        later_policy.event.book_revision = 1;
        let page = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![
                finalized_event(1, 1, 0, SorafsOrderbookLedgerEventKind::PolicyActivated),
                finalized_event(2, 2, 0, SorafsOrderbookLedgerEventKind::OrderAdmitted),
                later_policy,
            ],
            has_more: false,
            next_after: None,
        };
        let mut projection = SorafsOrderbookFinalizedTelemetryProjectionV1::default();
        apply_orderbook_finalized_telemetry_event_page(&mut projection, &page, finalized_cursor)
            .expect("valid finalized event history");
        assert_eq!(projection.last_event_occurred_at_unix_ms, 3_000);
        assert_eq!(projection.last_book_revision_advanced_at_unix_ms, 2_000);
    }
    #[test]
    fn finalized_telemetry_event_overflow_fails_without_partial_publish() {
        let finalized_cursor = cursor(4, 4);
        let mut projection = SorafsOrderbookFinalizedTelemetryProjectionV1 {
            after_event: Some(OrderbookFinalizedEventCursorV1 {
                sequence: 1,
                block_height: 1,
                block_hash: [1; 32],
                event_index: 0,
            }),
            event_counts: [0, u64::MAX, 0, 0, 0, 0, 0, 0],
            published_event_counts: [0; ORDERBOOK_TELEMETRY_EVENT_KIND_COUNT_V1],
            last_event_book_revision: 0,
            last_event_occurred_at_unix_ms: 1_000,
            last_book_revision_advanced_at_unix_ms: 0,
        };
        let before = projection;
        let page = OrderbookFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_event(
                2,
                2,
                0,
                SorafsOrderbookLedgerEventKind::OrderAdmitted,
            )],
            has_more: false,
            next_after: None,
        };
        assert_eq!(
            apply_orderbook_finalized_telemetry_event_page(
                &mut projection,
                &page,
                finalized_cursor,
            ),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::ArithmeticOverflow)
        );
        assert_eq!(projection, before);
    }
    #[test]
    fn finalized_telemetry_rejects_incomplete_order_and_channel_pages() {
        let finalized_cursor = cursor(4, 4);
        let order_page = OrderbookOrderPageV1 {
            finalized_cursor,
            orders: Vec::new(),
            has_more: true,
            next_after_order_id: Some([1; 32]),
        };
        assert_eq!(
            validate_orderbook_telemetry_order_page(
                &order_page,
                finalized_cursor,
                4,
                OrderbookOrderStatusV1::Open,
                None,
            ),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidOrderPage)
        );
        let channel_page = OrderbookSettlementChannelPageV1 {
            finalized_cursor,
            channels: Vec::new(),
            has_more: true,
            next_after_channel_id: Some([1; 32]),
        };
        assert_eq!(
            validate_orderbook_telemetry_channel_page(&channel_page, finalized_cursor, 4, None,),
            Err(SorafsOrderbookFinalizedTelemetryErrorV1::InvalidChannelPage)
        );
    }
}
