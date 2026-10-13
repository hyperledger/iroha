//! Supervised Torii runtime for durable native SoraFS reserve/rent transactions.
//!
//! The durable [`sorafs_node::reserve_transaction_forwarder`] is the only local delivery state.
//! Reserve policy, provider state, movements, appeals, and transaction outcomes are read from one
//! immutable finalized ledger view. Signing and submission are deliberately separate boundaries: an
//! injected qualified runtime signer sees only an exact fee-quoted payload, while only Torii's strict
//! durable ingress can expose the resulting signed transaction.

use super::reserve_worker::{
    ReserveEnvelopeReconciliationV1, ReserveFinalizedSnapshotV1, ReserveWorkerActionV1,
    plan_reserve_worker_action, reconcile_reserve_semantics,
};
use crate::{SharedAppState, SoraFsReserveTransactionSigner};
use axum::http::StatusCode;
use blake3::hash as blake3_hash;
use iroha_core::{
    smartcontracts::ValidSingularQuery,
    state::{StateReadOnly, StateReadOnlyWithTransactions, TransactionsReadOnly, WorldReadOnly},
    telemetry::SorafsReserveFinalizedProjection,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    asset::AssetId,
    block::BlockHeader,
    events::data::sorafs::SorafsReserveLedgerEventKind,
    isi::{
        InstructionBox,
        sorafs::{AdvanceSorafsReserveLifecycle, ChargeSorafsReserveRent},
    },
    query::{
        error::{FindError, QueryExecutionFail},
        sorafs::prelude::{
            FindSorafsReserveAppealById, FindSorafsReserveEvents, FindSorafsReserveMovementById,
            FindSorafsReservePolicy, FindSorafsReserveProviderById, FindSorafsReserveProviders,
        },
    },
    sorafs::{
        capacity::ProviderId,
        reserve::{
            RESERVE_QUERY_MAX_ITEMS_V1, RESERVE_RENT_MAX_BILLING_PERIODS_V1,
            ReserveAuthorityPolicyRecordV1, ReserveFinalizedCursorV1,
            ReserveFinalizedEventCursorV1, ReserveFinalizedEventPageV1, ReserveLifecycleStage,
            ReserveProviderAccountV1,
        },
    },
    transaction::{Executable, SignedTransaction, TransactionBuilder},
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::{debug, warn};
use iroha_primitives::numeric::{Numeric, RoundingMode};
use mv::storage::StorageReadOnly;
use sorafs_manifest::deal::XorQuantity;
use sorafs_node::{
    config::ReserveWorkerPolicy,
    reserve_transaction_forwarder::{
        RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1, ReserveOperationV1,
        ReserveTransactionContextV1, ReserveTransactionDeliveryStateV1,
        ReserveTransactionEnqueueResultV1, ReserveTransactionPendingV1,
        ReserveTransactionProjectionV1, ReserveTransactionReconciliationV1,
        ReserveTransactionSigningRequestV1, validate_reserve_pending_delivery_v1,
        validate_reserve_reconciliation_material_v1,
    },
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
const RESERVE_TELEMETRY_MAX_EVENTS_PER_SCAN_V1: usize = 1_024;
const RESERVE_TELEMETRY_MAX_PROVIDERS_V1: usize = 4_096;
const RESERVE_LIFECYCLE_STAGE_COUNT_V1: usize = 5;
const RESERVE_MOVEMENT_STATUS_COUNT_V1: usize = 3;
const RESERVE_RECONCILED_STATUS_COUNT_V1: usize = 2;
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SorafsReserveTransactionForwarderCursorV1 {
    after_sequence: Option<u64>,
    after_provider_id: Option<ProviderId>,
    telemetry: SorafsReserveFinalizedTelemetryProjectionV1,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SorafsReserveTransactionForwarderScanV1 {
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
struct SorafsReserveFinalizedTelemetryProjectionV1 {
    after_event: Option<ReserveFinalizedEventCursorV1>,
    custody_counts: [u64; RESERVE_MOVEMENT_STATUS_COUNT_V1],
    reconciled_counts: [u64; RESERVE_RECONCILED_STATUS_COUNT_V1],
    open_appeals: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SorafsReserveFinalizedProviderMetricsV1 {
    finalized_cursor: ReserveFinalizedCursorV1,
    lifecycle_stage_counts: [u64; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
    credit_principal_micro_xor: [u128; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
    credit_shortfall_micro_xor: [u128; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
    accrued_interest_micro_xor: [u128; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
    pending_movements: u64,
    open_appeals: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsReserveFinalizedTelemetryRefreshV1 {
    Published,
    CatchingUp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsReserveFinalizedTelemetryErrorV1 {
    FinalizedViewUnavailable,
    QueryFailed,
    InvalidEventPage,
    InvalidProviderPage,
    ArithmeticOverflow,
    ProviderCapacityExceeded,
    ProjectionMismatch,
}
impl SorafsReserveFinalizedTelemetryErrorV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::FinalizedViewUnavailable => "finalized_view_unavailable",
            Self::QueryFailed => "query_failed",
            Self::InvalidEventPage => "invalid_event_page",
            Self::InvalidProviderPage => "invalid_provider_page",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::ProviderCapacityExceeded => "provider_capacity_exceeded",
            Self::ProjectionMismatch => "projection_mismatch",
        }
    }
}
/// Reserve supervision uses one role-activation predicate.
///
/// Provider storage keeps durable drain/reconciliation active even when new reserve generation is
/// disabled. When both storage and generation are disabled, no worker is started and therefore no
/// external progress occurs. Opening the local [`sorafs_node::NodeHandle`] may still normalize an
/// interrupted signer-only claim from `Signing` to `Ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReserveWorkerSupervisionV1 {
    generation_enabled: bool,
    role_active: bool,
}
const fn reserve_worker_supervision(
    storage_enabled: bool,
    generation_enabled: bool,
) -> ReserveWorkerSupervisionV1 {
    ReserveWorkerSupervisionV1 {
        generation_enabled,
        role_active: storage_enabled || generation_enabled,
    }
}
fn spawn_reserve_worker_when_active<T>(
    supervision: ReserveWorkerSupervisionV1,
    spawn: impl FnOnce() -> T,
) -> Option<T> {
    if !supervision.role_active {
        return None;
    }
    Some(spawn())
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReserveGeneratedCandidateV1 {
    operation: ReserveOperationV1,
    context: ReserveTransactionContextV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReserveGenerationBatchV1 {
    candidates: Vec<ReserveGeneratedCandidateV1>,
    next_after_provider_id: Option<ProviderId>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveGenerationErrorV1 {
    FinalizedViewUnavailable,
    InvalidFinalizedTimestamp,
    InvalidProviderTimestamp,
    InvalidPolicyOrQuote,
    InvalidSpendableBalance,
    ArithmeticOverflow,
}
fn plan_generated_reserve_operation(
    policy_record: &ReserveAuthorityPolicyRecordV1,
    account: &ReserveProviderAccountV1,
    spendable_balance: &XorQuantity,
    finalized_at_unix: u64,
) -> Result<Option<ReserveOperationV1>, ReserveGenerationErrorV1> {
    if finalized_at_unix < account.updated_at_unix {
        return Err(ReserveGenerationErrorV1::InvalidProviderTimestamp);
    }
    let periods_due = account
        .rent_periods_due_at(finalized_at_unix)
        .map_err(|_| ReserveGenerationErrorV1::InvalidProviderTimestamp)?;
    let quote = policy_record
        .policy
        .economics
        .quote(
            account.terms.storage_class,
            account.terms.capacity_gib,
            account.terms.duration,
            account.terms.tier,
            account.reserve_balance.clone(),
        )
        .map_err(|_| ReserveGenerationErrorV1::InvalidPolicyOrQuote)?;
    if periods_due != 0 {
        let maximum_periods = u64::from(RESERVE_RENT_MAX_BILLING_PERIODS_V1);
        let candidate_periods = u16::try_from(periods_due.min(maximum_periods))
            .map_err(|_| ReserveGenerationErrorV1::ArithmeticOverflow)?;
        let mut affordable_periods = None;
        for billing_periods in (1..=candidate_periods).rev() {
            let total_rent = quote
                .effective_rent
                .checked_mul_u64(u64::from(billing_periods))
                .map_err(|_| ReserveGenerationErrorV1::ArithmeticOverflow)?;
            if &total_rent <= spendable_balance {
                affordable_periods = Some(billing_periods);
                break;
            }
        }
        if let Some(billing_periods) = affordable_periods {
            return Ok(Some(ReserveOperationV1::ChargeRent(
                ChargeSorafsReserveRent::new(
                    account.terms.provider_id,
                    account.revision,
                    billing_periods,
                    policy_record.policy_digest,
                ),
            )));
        }
    }
    let days_past_due = account
        .rent_days_past_due_at(finalized_at_unix)
        .map_err(|_| ReserveGenerationErrorV1::InvalidProviderTimestamp)?;
    let projection = quote
        .lifecycle_projection(
            days_past_due,
            policy_record.policy.grace_period_days,
            policy_record.policy.default_after_days,
        )
        .map_err(|_| ReserveGenerationErrorV1::InvalidPolicyOrQuote)?;
    if account.days_past_due == days_past_due && account.lifecycle_stage == projection.stage {
        return Ok(None);
    }
    Ok(Some(ReserveOperationV1::AdvanceLifecycle(
        AdvanceSorafsReserveLifecycle::new(
            account.terms.provider_id,
            account.revision,
            days_past_due,
            policy_record.policy_digest,
        ),
    )))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveCommittedExternalOutcomeV1 {
    Applied,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveAuthoritativeTransactionOutcomeV1 {
    Absent,
    Applied,
    Rejected,
    Unavailable,
}
#[derive(Debug)]
struct ReserveFinalizedObservationV1 {
    snapshot: ReserveFinalizedSnapshotV1,
    transaction_outcome: Option<ReserveAuthoritativeTransactionOutcomeV1>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveTransactionSubmissionDispositionV1 {
    Submitted,
    DefinitelyNotSubmitted,
    Rejected,
    Ambiguous,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveTransactionSubmissionResultV1 {
    Submitted,
    Rejected,
    Deferred,
}
fn classify_local_reserve_transaction_submission(
    error: &iroha_core::queue::Error,
) -> ReserveTransactionSubmissionDispositionV1 {
    match error {
        iroha_core::queue::Error::InBlockchain | iroha_core::queue::Error::IsInQueue => {
            ReserveTransactionSubmissionDispositionV1::Submitted
        }
        iroha_core::queue::Error::Expired
        | iroha_core::queue::Error::TransactionDomainMismatch(_) => {
            ReserveTransactionSubmissionDispositionV1::Rejected
        }
        _ => ReserveTransactionSubmissionDispositionV1::DefinitelyNotSubmitted,
    }
}
fn classify_reserve_envelope(
    retained_digest: Option<[u8; 32]>,
    signed_transaction_bytes: Option<&[u8]>,
    finalized_cursor: ReserveFinalizedCursorV1,
    outcome: ReserveAuthoritativeTransactionOutcomeV1,
    local_evidence_blocks_absence_retry: bool,
) -> ReserveEnvelopeReconciliationV1 {
    if finalized_cursor.height == 0 || finalized_cursor.block_hash == [0; 32] {
        return ReserveEnvelopeReconciliationV1::Unavailable;
    }
    let Some(transaction_digest) =
        super::retained_transaction_digest(retained_digest, signed_transaction_bytes)
    else {
        return ReserveEnvelopeReconciliationV1::Unavailable;
    };
    match outcome {
        ReserveAuthoritativeTransactionOutcomeV1::Applied => {
            ReserveEnvelopeReconciliationV1::Applied {
                transaction_digest,
                finalized_cursor,
            }
        }
        ReserveAuthoritativeTransactionOutcomeV1::Rejected => {
            ReserveEnvelopeReconciliationV1::Rejected {
                transaction_digest,
                finalized_cursor,
            }
        }
        ReserveAuthoritativeTransactionOutcomeV1::Absent if local_evidence_blocks_absence_retry => {
            ReserveEnvelopeReconciliationV1::Pending {
                transaction_digest,
                finalized_cursor,
            }
        }
        ReserveAuthoritativeTransactionOutcomeV1::Absent => {
            ReserveEnvelopeReconciliationV1::Absent {
                transaction_digest,
                finalized_cursor,
            }
        }
        ReserveAuthoritativeTransactionOutcomeV1::Unavailable => {
            ReserveEnvelopeReconciliationV1::Unavailable
        }
    }
}
fn classify_exact_reserve_entrypoint_outcome(
    expected_hash: &HashOf<SignedTransaction>,
    block_available: bool,
    results: impl IntoIterator<Item = (HashOf<SignedTransaction>, ReserveCommittedExternalOutcomeV1)>,
) -> ReserveAuthoritativeTransactionOutcomeV1 {
    if !block_available {
        return ReserveAuthoritativeTransactionOutcomeV1::Unavailable;
    }
    let mut exact = results
        .into_iter()
        .filter_map(|(hash, outcome)| (&hash == expected_hash).then_some(outcome));
    let Some(outcome) = exact.next() else {
        return ReserveAuthoritativeTransactionOutcomeV1::Unavailable;
    };
    if exact.next().is_some() {
        return ReserveAuthoritativeTransactionOutcomeV1::Unavailable;
    }
    match outcome {
        ReserveCommittedExternalOutcomeV1::Applied => {
            ReserveAuthoritativeTransactionOutcomeV1::Applied
        }
        ReserveCommittedExternalOutcomeV1::Rejected => {
            ReserveAuthoritativeTransactionOutcomeV1::Rejected
        }
    }
}
fn inspect_indexed_reserve_transaction(
    state: &iroha_core::state::State,
    transaction_hash: &HashOf<SignedTransaction>,
    block_height: NonZeroUsize,
    expected_block_hash: HashOf<BlockHeader>,
) -> ReserveAuthoritativeTransactionOutcomeV1 {
    let Ok((_header, outcome)) = crate::canonical_history::exact_external_outcome(
        state,
        block_height,
        expected_block_hash,
        transaction_hash,
    ) else {
        return ReserveAuthoritativeTransactionOutcomeV1::Unavailable;
    };
    classify_exact_reserve_entrypoint_outcome(
        transaction_hash,
        true,
        outcome.map(|applied| {
            (
                *transaction_hash,
                if applied {
                    ReserveCommittedExternalOutcomeV1::Applied
                } else {
                    ReserveCommittedExternalOutcomeV1::Rejected
                },
            )
        }),
    )
}
pub(super) fn reserve_finalized_cursor_from_view(
    view: &impl StateReadOnly,
) -> Option<ReserveFinalizedCursorV1> {
    u64::try_from(view.block_hashes().len())
        .ok()
        .zip(view.block_hashes().last())
        .map(|(height, hash)| ReserveFinalizedCursorV1 {
            height,
            block_hash: *hash.as_ref(),
        })
        .filter(|cursor| cursor.height != 0 && cursor.block_hash != [0; 32])
}
fn current_reserve_finalized_cursor(state: &SharedAppState) -> Option<ReserveFinalizedCursorV1> {
    let view = state.state.query_view();
    reserve_finalized_cursor_from_view(&view)
}
const fn reserve_lifecycle_stage_index(stage: ReserveLifecycleStage) -> usize {
    match stage {
        ReserveLifecycleStage::Active => 0,
        ReserveLifecycleStage::Warning => 1,
        ReserveLifecycleStage::Grace => 2,
        ReserveLifecycleStage::Delinquent => 3,
        ReserveLifecycleStage::Default => 4,
    }
}
fn reserve_quantity_to_metric_micro_xor(
    amount: &XorQuantity,
) -> Result<u128, SorafsReserveFinalizedTelemetryErrorV1> {
    amount
        .as_quantity()
        .try_mul_decimal(&Numeric::from(1_000_000_u64))
        .and_then(|scaled| {
            scaled.as_numeric().try_decimal_div_round(
                &Numeric::from(1_u64),
                0,
                RoundingMode::TowardZero,
            )
        })
        .ok()
        .and_then(|scaled| scaled.try_mantissa_u128())
        .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)
}
fn reserve_telemetry_event_shape_is_valid(
    event: &iroha_data_model::events::data::sorafs::SorafsReserveLedgerEvent,
) -> bool {
    if event.policy_digest == [0; 32] || event.occurred_at_unix_ms == 0 {
        return false;
    }
    match event.kind {
        SorafsReserveLedgerEventKind::PolicyActivated => {
            event.provider_id.is_none()
                && event.operation_id.is_none()
                && event.provider_revision == 0
                && event.resulting_lifecycle_stage.is_none()
        }
        SorafsReserveLedgerEventKind::ProviderRegistered => {
            event.provider_id.is_some()
                && event.operation_id.is_none()
                && event.provider_revision == 1
                && event.resulting_lifecycle_stage.is_some()
        }
        SorafsReserveLedgerEventKind::MovementRequested
        | SorafsReserveLedgerEventKind::MovementApproved
        | SorafsReserveLedgerEventKind::MovementRejected
        | SorafsReserveLedgerEventKind::AppealSubmitted
        | SorafsReserveLedgerEventKind::AppealAccepted
        | SorafsReserveLedgerEventKind::AppealRejected => {
            event.provider_id.is_some()
                && event
                    .operation_id
                    .is_some_and(|operation_id| operation_id != [0; 32])
                && event.provider_revision > 0
                && event.resulting_lifecycle_stage.is_some()
        }
        SorafsReserveLedgerEventKind::RentCharged
        | SorafsReserveLedgerEventKind::LifecycleAdvanced
        | SorafsReserveLedgerEventKind::CreditDrawn
        | SorafsReserveLedgerEventKind::CreditRepaid => {
            event.provider_id.is_some()
                && event.operation_id.is_none()
                && event.provider_revision > 0
                && event.resulting_lifecycle_stage.is_some()
        }
    }
}
fn reserve_telemetry_event_cursor_is_successor(
    previous: Option<ReserveFinalizedEventCursorV1>,
    current: ReserveFinalizedEventCursorV1,
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
fn apply_reserve_finalized_telemetry_event_page(
    projection: &mut SorafsReserveFinalizedTelemetryProjectionV1,
    page: &ReserveFinalizedEventPageV1,
    expected_finalized_cursor: ReserveFinalizedCursorV1,
) -> Result<(), SorafsReserveFinalizedTelemetryErrorV1> {
    if page.finalized_cursor != expected_finalized_cursor
        || page.events.len()
            > usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1)
                .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?
        || (page.has_more && page.events.is_empty())
        || page.has_more != page.next_after.is_some()
        || page.next_after.is_some_and(|cursor| {
            page.events
                .last()
                .map(iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1::cursor)
                != Some(cursor)
        })
    {
        return Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidEventPage);
    }
    let mut next = *projection;
    for record in &page.events {
        let cursor = record.cursor();
        if record.block_height > expected_finalized_cursor.height
            || !reserve_telemetry_event_cursor_is_successor(next.after_event, cursor)
            || !reserve_telemetry_event_shape_is_valid(&record.event)
        {
            return Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidEventPage);
        }
        match record.event.kind {
            SorafsReserveLedgerEventKind::MovementRequested => {
                next.custody_counts[0] = next.custody_counts[0]
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            }
            SorafsReserveLedgerEventKind::MovementApproved => {
                next.custody_counts[0] = next.custody_counts[0]
                    .checked_sub(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ProjectionMismatch)?;
                next.custody_counts[1] = next.custody_counts[1]
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
                next.reconciled_counts[0] = next.reconciled_counts[0]
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            }
            SorafsReserveLedgerEventKind::MovementRejected => {
                next.custody_counts[0] = next.custody_counts[0]
                    .checked_sub(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ProjectionMismatch)?;
                next.custody_counts[2] = next.custody_counts[2]
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
                next.reconciled_counts[1] = next.reconciled_counts[1]
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            }
            SorafsReserveLedgerEventKind::AppealSubmitted => {
                next.open_appeals = next
                    .open_appeals
                    .checked_add(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            }
            SorafsReserveLedgerEventKind::AppealAccepted
            | SorafsReserveLedgerEventKind::AppealRejected => {
                next.open_appeals = next
                    .open_appeals
                    .checked_sub(1)
                    .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ProjectionMismatch)?;
            }
            SorafsReserveLedgerEventKind::PolicyActivated
            | SorafsReserveLedgerEventKind::ProviderRegistered
            | SorafsReserveLedgerEventKind::RentCharged
            | SorafsReserveLedgerEventKind::LifecycleAdvanced
            | SorafsReserveLedgerEventKind::CreditDrawn
            | SorafsReserveLedgerEventKind::CreditRepaid => {}
        }
        next.after_event = Some(cursor);
    }
    *projection = next;
    Ok(())
}
fn consume_reserve_finalized_telemetry_events(
    view: &impl StateReadOnly,
    finalized_cursor: ReserveFinalizedCursorV1,
    projection: &mut SorafsReserveFinalizedTelemetryProjectionV1,
) -> Result<bool, SorafsReserveFinalizedTelemetryErrorV1> {
    let mut processed = 0_usize;
    loop {
        let remaining = RESERVE_TELEMETRY_MAX_EVENTS_PER_SCAN_V1
            .checked_sub(processed)
            .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if remaining == 0 {
            return Ok(false);
        }
        let limit = u32::try_from(remaining)
            .unwrap_or(u32::MAX)
            .min(RESERVE_QUERY_MAX_ITEMS_V1);
        let page =
            FindSorafsReserveEvents::new(Some(finalized_cursor), projection.after_event, limit)
                .execute(view)
                .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::QueryFailed)?;
        let page_len = page.events.len();
        apply_reserve_finalized_telemetry_event_page(projection, &page, finalized_cursor)?;
        processed = processed
            .checked_add(page_len)
            .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if !page.has_more {
            return Ok(true);
        }
    }
}
fn collect_reserve_finalized_provider_metrics(
    view: &impl StateReadOnly,
    finalized_cursor: ReserveFinalizedCursorV1,
) -> Result<SorafsReserveFinalizedProviderMetricsV1, SorafsReserveFinalizedTelemetryErrorV1> {
    let mut metrics = SorafsReserveFinalizedProviderMetricsV1 {
        finalized_cursor,
        lifecycle_stage_counts: [0; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
        credit_principal_micro_xor: [0; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
        credit_shortfall_micro_xor: [0; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
        accrued_interest_micro_xor: [0; RESERVE_LIFECYCLE_STAGE_COUNT_V1],
        pending_movements: 0,
        open_appeals: 0,
    };
    let mut after_provider_id = None;
    let mut provider_count = 0_usize;
    loop {
        let page = FindSorafsReserveProviders::new(
            Some(finalized_cursor),
            after_provider_id,
            RESERVE_QUERY_MAX_ITEMS_V1,
        )
        .execute(view)
        .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::QueryFailed)?;
        if page.finalized_cursor != finalized_cursor
            || page.accounts.len()
                > usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1)
                    .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?
            || (page.has_more && page.accounts.is_empty())
            || page.has_more != page.next_after.is_some()
            || page.next_after.is_some_and(|cursor| {
                page.accounts
                    .last()
                    .map(|account| account.terms.provider_id)
                    != Some(cursor)
            })
        {
            return Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidProviderPage);
        }
        provider_count = provider_count
            .checked_add(page.accounts.len())
            .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        if provider_count > RESERVE_TELEMETRY_MAX_PROVIDERS_V1
            || (provider_count == RESERVE_TELEMETRY_MAX_PROVIDERS_V1 && page.has_more)
        {
            return Err(SorafsReserveFinalizedTelemetryErrorV1::ProviderCapacityExceeded);
        }
        let mut previous_provider_id = after_provider_id;
        for account in &page.accounts {
            let provider_id = account.terms.provider_id;
            if previous_provider_id.is_some_and(|previous| provider_id <= previous) {
                return Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidProviderPage);
            }
            previous_provider_id = Some(provider_id);
            let stage = reserve_lifecycle_stage_index(account.lifecycle_stage);
            metrics.lifecycle_stage_counts[stage] = metrics.lifecycle_stage_counts[stage]
                .checked_add(1)
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            let credit_principal = reserve_quantity_to_metric_micro_xor(&account.debt_principal)?;
            let accrued_interest = reserve_quantity_to_metric_micro_xor(&account.accrued_interest)?;
            let total_debt = account
                .total_debt()
                .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            let credit_shortfall = if total_debt > account.credit_cap {
                total_debt
                    .checked_sub(&account.credit_cap)
                    .map_err(|_| SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?
            } else {
                XorQuantity::zero()
            };
            let credit_shortfall = reserve_quantity_to_metric_micro_xor(&credit_shortfall)?;
            metrics.credit_principal_micro_xor[stage] = metrics.credit_principal_micro_xor[stage]
                .checked_add(credit_principal)
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            metrics.credit_shortfall_micro_xor[stage] = metrics.credit_shortfall_micro_xor[stage]
                .checked_add(credit_shortfall)
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            metrics.accrued_interest_micro_xor[stage] = metrics.accrued_interest_micro_xor[stage]
                .checked_add(accrued_interest)
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            metrics.pending_movements = metrics
                .pending_movements
                .checked_add(u64::from(account.pending_movements))
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
            metrics.open_appeals = metrics
                .open_appeals
                .checked_add(u64::from(account.open_appeals))
                .ok_or(SorafsReserveFinalizedTelemetryErrorV1::ArithmeticOverflow)?;
        }
        if !page.has_more {
            return Ok(metrics);
        }
        after_provider_id = page.next_after;
    }
}
fn refresh_sorafs_reserve_finalized_telemetry(
    state: &SharedAppState,
    projection: &mut SorafsReserveFinalizedTelemetryProjectionV1,
) -> Result<SorafsReserveFinalizedTelemetryRefreshV1, SorafsReserveFinalizedTelemetryErrorV1> {
    let view = state.state.view();
    let finalized_cursor = reserve_finalized_cursor_from_view(&view)
        .ok_or(SorafsReserveFinalizedTelemetryErrorV1::FinalizedViewUnavailable)?;
    if !consume_reserve_finalized_telemetry_events(&view, finalized_cursor, projection)? {
        state.telemetry.with_metrics(
            iroha_core::telemetry::Telemetry::mark_sorafs_reserve_finalized_projection_unready,
        );
        return Ok(SorafsReserveFinalizedTelemetryRefreshV1::CatchingUp);
    }
    let provider_metrics = collect_reserve_finalized_provider_metrics(&view, finalized_cursor)?;
    if provider_metrics.pending_movements != projection.custody_counts[0]
        || provider_metrics.open_appeals != projection.open_appeals
    {
        return Err(SorafsReserveFinalizedTelemetryErrorV1::ProjectionMismatch);
    }
    state.telemetry.with_metrics(|metrics| {
        metrics.record_sorafs_reserve_finalized_projection(&SorafsReserveFinalizedProjection {
            finalized_height: provider_metrics.finalized_cursor.height,
            lifecycle_stage_counts: provider_metrics.lifecycle_stage_counts,
            credit_principal_micro_xor: provider_metrics.credit_principal_micro_xor,
            credit_shortfall_micro_xor: provider_metrics.credit_shortfall_micro_xor,
            accrued_interest_micro_xor: provider_metrics.accrued_interest_micro_xor,
            open_appeals: projection.open_appeals,
            custody_counts: projection.custody_counts,
            chain_reconciled_counts: projection.reconciled_counts,
        });
    });
    Ok(SorafsReserveFinalizedTelemetryRefreshV1::Published)
}
fn collect_generated_reserve_operations_in_one_finalized_view(
    state: &SharedAppState,
    after_provider_id: Option<ProviderId>,
    policy: ReserveWorkerPolicy,
) -> Result<ReserveGenerationBatchV1, ReserveGenerationErrorV1> {
    let view = state.state.view();
    let finalized_cursor = reserve_finalized_cursor_from_view(&view)
        .ok_or(ReserveGenerationErrorV1::FinalizedViewUnavailable)?;
    let finalized_at_unix = view
        .authenticated_query_ledger_time_ms()
        .ok_or(ReserveGenerationErrorV1::FinalizedViewUnavailable)?
        / 1_000;
    if finalized_at_unix == 0 {
        return Err(ReserveGenerationErrorV1::InvalidFinalizedTimestamp);
    }
    let policy_record = FindSorafsReservePolicy::new()
        .execute(&view)
        .map_err(|_| ReserveGenerationErrorV1::InvalidPolicyOrQuote)?;
    let policy_digest = policy_record
        .policy
        .digest()
        .map_err(|_| ReserveGenerationErrorV1::InvalidPolicyOrQuote)?;
    if policy_digest == [0; 32]
        || policy_digest != policy_record.policy_digest
        || policy_record.activated_at_unix == 0
        || policy_record.activated_at_unix > finalized_at_unix
    {
        return Err(ReserveGenerationErrorV1::InvalidPolicyOrQuote);
    }
    let query_hard_limit = usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1)
        .map_err(|_| ReserveGenerationErrorV1::ArithmeticOverflow)?;
    let query_limit = u32::try_from(policy.scan_batch_limit().min(query_hard_limit))
        .map_err(|_| ReserveGenerationErrorV1::ArithmeticOverflow)?;
    let page =
        FindSorafsReserveProviders::new(Some(finalized_cursor), after_provider_id, query_limit)
            .execute(&view)
            .map_err(|_| ReserveGenerationErrorV1::FinalizedViewUnavailable)?;
    if page.finalized_cursor != finalized_cursor {
        return Err(ReserveGenerationErrorV1::FinalizedViewUnavailable);
    }
    let next_after_provider_id = match (page.has_more, page.next_after) {
        (true, Some(next_after)) => Some(next_after),
        (false, None) => None,
        _ => return Err(ReserveGenerationErrorV1::FinalizedViewUnavailable),
    };
    let mut candidates = Vec::with_capacity(page.accounts.len());
    for account in page.accounts {
        let asset_id = AssetId::of(
            policy_record.policy.asset_definition.clone(),
            account.terms.provider_account.clone(),
        );
        let spendable_balance = view.world().assets().get(&asset_id).map_or_else(
            || Ok(XorQuantity::zero()),
            |value| {
                XorQuantity::try_from_quantity(value.as_ref().clone())
                    .map_err(|_| ReserveGenerationErrorV1::InvalidSpendableBalance)
            },
        )?;
        let Some(operation) = plan_generated_reserve_operation(
            &policy_record,
            &account,
            &spendable_balance,
            finalized_at_unix,
        )?
        else {
            continue;
        };
        candidates.push(ReserveGeneratedCandidateV1 {
            operation,
            context: ReserveTransactionContextV1 {
                network_id: *state.state.network_id_ref(),
                chain_id: state.chain_id.as_ref().clone(),
                policy_record: policy_record.clone(),
                projection: ReserveTransactionProjectionV1::Provider { account },
                finalized_cursor,
            },
        });
    }
    Ok(ReserveGenerationBatchV1 {
        candidates,
        next_after_provider_id,
    })
}
fn reserve_provider_id(retained: &ReserveTransactionReconciliationV1) -> Option<ProviderId> {
    retained
        .request
        .operation
        .provider_id()
        .or(match &retained.projection {
            ReserveTransactionProjectionV1::Registration { .. } => None,
            ReserveTransactionProjectionV1::Provider { account }
            | ReserveTransactionProjectionV1::MovementDecision { account, .. }
            | ReserveTransactionProjectionV1::AppealDecision { account, .. } => {
                Some(account.terms.provider_id)
            }
        })
}
fn reserve_movement_id(retained: &ReserveTransactionReconciliationV1) -> Option<[u8; 32]> {
    match &retained.request.operation {
        ReserveOperationV1::RequestMovement(instruction) => Some(*instruction.movement_id()),
        ReserveOperationV1::DecideMovement(instruction) => Some(*instruction.movement_id()),
        ReserveOperationV1::RegisterProvider(_)
        | ReserveOperationV1::ChargeRent(_)
        | ReserveOperationV1::AdvanceLifecycle(_)
        | ReserveOperationV1::DrawCredit(_)
        | ReserveOperationV1::RepayCredit(_)
        | ReserveOperationV1::SubmitAppeal(_)
        | ReserveOperationV1::DecideAppeal(_) => None,
    }
}
fn reserve_appeal_id(retained: &ReserveTransactionReconciliationV1) -> Option<[u8; 32]> {
    match &retained.request.operation {
        ReserveOperationV1::SubmitAppeal(instruction) => Some(*instruction.appeal_id()),
        ReserveOperationV1::DecideAppeal(instruction) => Some(*instruction.appeal_id()),
        ReserveOperationV1::RegisterProvider(_)
        | ReserveOperationV1::RequestMovement(_)
        | ReserveOperationV1::DecideMovement(_)
        | ReserveOperationV1::ChargeRent(_)
        | ReserveOperationV1::AdvanceLifecycle(_)
        | ReserveOperationV1::DrawCredit(_)
        | ReserveOperationV1::RepayCredit(_) => None,
    }
}
fn reserve_snapshot_in_view(
    view: &impl StateReadOnly,
    delivery: &ReserveTransactionPendingV1,
    retained: &ReserveTransactionReconciliationV1,
) -> Option<ReserveFinalizedSnapshotV1> {
    let finalized_cursor = reserve_finalized_cursor_from_view(view)?;
    let baseline_block_hash = delivery
        .baseline_finalized_height
        .checked_sub(1)
        .and_then(|height| usize::try_from(height).ok())
        .and_then(|index| view.block_hashes().get(index))
        .map(|hash| *hash.as_ref());
    let policy_record = match FindSorafsReservePolicy::new().execute(view) {
        Ok(record) => Some(record),
        Err(QueryExecutionFail::Find(FindError::SorafsReservePolicy)) => None,
        Err(_) => return None,
    };
    let provider_id = reserve_provider_id(retained)?;
    let provider = match FindSorafsReserveProviderById::new(provider_id).execute(view) {
        Ok(provider) => Some(provider),
        Err(QueryExecutionFail::Find(FindError::SorafsReserveProvider(missing)))
            if missing == provider_id =>
        {
            None
        }
        Err(_) => return None,
    };
    let provider_owner = matches!(
        &retained.request.operation,
        ReserveOperationV1::RegisterProvider(_)
    )
    .then(|| view.world().provider_owners().get(&provider_id).cloned())
    .flatten();
    let movement = if let Some(movement_id) = reserve_movement_id(retained) {
        match FindSorafsReserveMovementById::new(movement_id).execute(view) {
            Ok(movement) => Some(movement),
            Err(QueryExecutionFail::Find(FindError::SorafsReserveMovement(missing)))
                if missing == movement_id =>
            {
                None
            }
            Err(_) => return None,
        }
    } else {
        None
    };
    let appeal = if let Some(appeal_id) = reserve_appeal_id(retained) {
        match FindSorafsReserveAppealById::new(appeal_id).execute(view) {
            Ok(appeal) => Some(appeal),
            Err(QueryExecutionFail::Find(FindError::SorafsReserveAppeal(missing)))
                if missing == appeal_id =>
            {
                None
            }
            Err(_) => return None,
        }
    } else {
        None
    };
    Some(ReserveFinalizedSnapshotV1 {
        finalized_cursor,
        baseline_block_hash,
        policy_record,
        provider_owner,
        provider,
        movement,
        appeal,
    })
}
fn observe_reserve_transaction_in_one_finalized_view(
    state: &SharedAppState,
    delivery: &ReserveTransactionPendingV1,
    retained: &ReserveTransactionReconciliationV1,
    transaction_hash: Option<&HashOf<SignedTransaction>>,
) -> Option<ReserveFinalizedObservationV1> {
    let view = state.state.view();
    let snapshot = reserve_snapshot_in_view(&view, delivery, retained)?;
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
            (None, _) => ReserveAuthoritativeTransactionOutcomeV1::Absent,
            (Some(_), None) => ReserveAuthoritativeTransactionOutcomeV1::Unavailable,
            (Some(_), Some((height, expected))) => {
                inspect_indexed_reserve_transaction(&state.state, hash, height, expected)
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
    Some(ReserveFinalizedObservationV1 {
        snapshot,
        transaction_outcome,
    })
}
fn decode_exact_reserve_signed_transaction(
    bytes: &[u8],
    request: &ReserveTransactionSigningRequestV1,
) -> Option<SignedTransaction> {
    if bytes.is_empty() || bytes.len() > RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1 {
        return None;
    }
    norito::core::from_bytes_view(bytes).ok()?;
    let total_elements = bytes.len().checked_mul(8)?;
    let total_allocated_bytes = bytes.len().checked_mul(20)?.checked_add(512 * 1024)?;
    let limits = norito::DecodeLimits::new(
        RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1,
        RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1,
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
/// Start reserve generation and durable drain/reconciliation when the role is active.
///
/// Storage enablement keeps the role active for restart recovery even when `reserve_worker.enabled`
/// suppresses generation of new worker-owned operations. When both controls are disabled, retained
/// entries stay durable but make zero external progress because no task is spawned. Opening the
/// local node may still release interrupted signer-only claims back to `Ready`.
pub fn spawn_sorafs_reserve_transaction_forwarder_worker(
    state: SharedAppState,
    shutdown_signal: ShutdownSignal,
) -> Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>> {
    let policy = state.sorafs_node.config().reserve_worker_policy();
    let supervision =
        reserve_worker_supervision(state.sorafs_node.config().enabled(), policy.enabled());
    let worker = spawn_reserve_worker_when_active(supervision, move || {
        if !supervision.generation_enabled {
            debug!(
                "SoraFS reserve/rent generation is disabled; storage-enabled durable drain and finalized reconciliation remain active"
            );
        }
        if state.sorafs_reserve_transaction_signer.is_none() {
            warn!(
                "active SoraFS reserve/rent forwarder has no runtime signer; signing remains deferred"
            );
        }
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(policy.scan_interval());
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut cursor = SorafsReserveTransactionForwarderCursorV1::default();
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
                            run_sorafs_reserve_transaction_forwarder_scan(&state, &mut cursor).await;
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
                                "processed durable native SoraFS reserve/rent transactions"
                            );
                        }
                    }
                }
            }
        })
    });
    if worker.is_none() {
        debug!(
            "SoraFS reserve/rent worker is paused because storage and generation are disabled; no external work was started"
        );
    }
    worker
}
pub async fn run_sorafs_reserve_transaction_forwarder_scan(
    state: &SharedAppState,
    cursor: &mut SorafsReserveTransactionForwarderCursorV1,
) -> SorafsReserveTransactionForwarderScanV1 {
    let mut scan = SorafsReserveTransactionForwarderScanV1::default();
    if state.telemetry.allows_metrics() {
        match refresh_sorafs_reserve_finalized_telemetry(state, &mut cursor.telemetry) {
            Ok(SorafsReserveFinalizedTelemetryRefreshV1::Published) => {
                scan.telemetry_published = 1;
            }
            Ok(SorafsReserveFinalizedTelemetryRefreshV1::CatchingUp) => {
                scan.telemetry_catching_up = 1;
            }
            Err(error) => {
                scan.telemetry_failed = 1;
                state.telemetry.with_metrics(|metrics| {
                    metrics.record_sorafs_reserve_finalized_projection_failure()
                });
                warn!(
                    reason = error.label(),
                    "failed to publish finalized SoraFS reserve/rent telemetry"
                );
            }
        }
    }
    let policy = state.sorafs_node.config().reserve_worker_policy();
    if policy.enabled() {
        match collect_generated_reserve_operations_in_one_finalized_view(
            state,
            cursor.after_provider_id,
            policy,
        ) {
            Ok(batch) => {
                cursor.after_provider_id = batch.next_after_provider_id;
                for candidate in batch.candidates {
                    match state
                        .sorafs_node
                        .enqueue_reserve_transaction(candidate.operation, &candidate.context)
                    {
                        Ok(ReserveTransactionEnqueueResultV1::Inserted { .. }) => {
                            scan.generated = scan.generated.saturating_add(1);
                        }
                        Ok(ReserveTransactionEnqueueResultV1::Existing { .. }) => {
                            scan.generation_replayed = scan.generation_replayed.saturating_add(1);
                        }
                        Err(_) => {
                            scan.generation_deferred = scan.generation_deferred.saturating_add(1);
                            warn!(
                                "failed to durably enqueue generated native SoraFS reserve/rent work"
                            );
                        }
                    }
                }
            }
            Err(_) => {
                scan.generation_deferred = scan.generation_deferred.saturating_add(1);
                warn!(
                    "failed to derive native SoraFS reserve/rent work from one finalized ledger view"
                );
            }
        }
    }
    let pending = match state
        .sorafs_node
        .pending_reserve_transactions_after(cursor.after_sequence, policy.scan_batch_limit())
    {
        Ok(pending) => pending,
        Err(_) => {
            warn!("failed to load durable native SoraFS reserve/rent transactions");
            return scan;
        }
    };
    for delivery in pending {
        cursor.after_sequence = Some(delivery.sequence);
        scan.scanned = scan.scanned.saturating_add(1);
        if validate_reserve_pending_delivery_v1(&delivery).is_err() {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!("durable native SoraFS reserve/rent delivery failed validation");
            continue;
        }
        let retained = match state
            .sorafs_node
            .reserve_transaction_operation_for_reconciliation(delivery.operation_id)
        {
            Ok(retained)
                if retained.request.operation_id == delivery.operation_id
                    && retained.request.network_id == delivery.network_id
                    && retained.request.chain_id == delivery.chain_id
                    && retained.request.authority == delivery.authority
                    && validate_reserve_reconciliation_material_v1(&delivery, &retained)
                        .is_ok() =>
            {
                retained
            }
            Ok(_) | Err(_) => {
                scan.deferred = scan.deferred.saturating_add(1);
                warn!("failed to read exact native SoraFS reserve/rent semantics");
                continue;
            }
        };
        if retained.request.network_id != *state.state.network_id_ref()
            || retained.request.chain_id != *state.chain_id
        {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!(
                "durable native SoraFS reserve/rent delivery belongs to another network or business chain"
            );
            continue;
        }
        let exact_transaction = match delivery.signed_transaction_bytes.as_deref() {
            Some(bytes) => {
                if super::retained_transaction_digest(delivery.transaction_digest, Some(bytes))
                    .is_none()
                {
                    scan.deferred = scan.deferred.saturating_add(1);
                    warn!("durable native SoraFS reserve/rent transaction digest is invalid");
                    continue;
                }
                let Some(transaction) =
                    decode_exact_reserve_signed_transaction(bytes, &retained.request)
                else {
                    scan.deferred = scan.deferred.saturating_add(1);
                    warn!("durable native SoraFS reserve/rent transaction bytes failed validation");
                    continue;
                };
                Some(transaction)
            }
            None => None,
        };
        let exact_transaction_hash = exact_transaction.as_ref().map(SignedTransaction::hash);
        let local_evidence_before = exact_transaction_hash.as_ref().is_some_and(|hash| {
            let queue_pending = state.queue.contains_pending_hash(
                iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
                &state.state,
            );
            let cache_kind = state
                .pipeline_status_cache
                .lookup(hash)
                .map(|entry| entry.kind);
            super::pending_evidence_blocks_absence_retry(queue_pending, cache_kind)
        });
        let Some(observation) = observe_reserve_transaction_in_one_finalized_view(
            state,
            &delivery,
            &retained,
            exact_transaction_hash.as_ref(),
        ) else {
            scan.deferred = scan.deferred.saturating_add(1);
            warn!("authoritative SoraFS reserve/rent observation failed");
            continue;
        };
        let semantics = reconcile_reserve_semantics(
            state.chain_id.as_ref(),
            &delivery,
            &retained,
            &observation.snapshot,
        );
        let local_evidence_after = exact_transaction_hash.as_ref().is_some_and(|hash| {
            let queue_pending = state.queue.contains_pending_hash(
                iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
                &state.state,
            );
            let cache_kind = state
                .pipeline_status_cache
                .lookup(hash)
                .map(|entry| entry.kind);
            super::pending_evidence_blocks_absence_retry(queue_pending, cache_kind)
        });
        let envelope = match observation.transaction_outcome {
            Some(outcome) => classify_reserve_envelope(
                delivery.transaction_digest,
                delivery.signed_transaction_bytes.as_deref(),
                observation.snapshot.finalized_cursor,
                outcome,
                local_evidence_before || local_evidence_after,
            ),
            None => ReserveEnvelopeReconciliationV1::NotSigned,
        };
        let signer_authority = state
            .sorafs_reserve_transaction_signer
            .as_ref()
            .map(|signer| signer.authority());
        let action = plan_reserve_worker_action(
            state.chain_id.as_ref(),
            signer_authority.as_ref(),
            &delivery,
            envelope,
            semantics,
        );
        match action {
            ReserveWorkerActionV1::FinalizeExact {
                transaction_digest,
                finalized_cursor,
            } => match state.sorafs_node.mark_reserve_transaction_finalized(
                delivery.operation_id,
                transaction_digest,
                finalized_cursor,
            ) {
                Ok(()) => scan.finalized = scan.finalized.saturating_add(1),
                Err(_) => scan.deferred = scan.deferred.saturating_add(1),
            },
            ReserveWorkerActionV1::FinalizeSemantic { finalized_cursor } => {
                match state
                    .sorafs_node
                    .mark_reserve_transaction_semantic_finalized(
                        delivery.operation_id,
                        finalized_cursor,
                    ) {
                    Ok(()) => scan.finalized = scan.finalized.saturating_add(1),
                    Err(_) => scan.deferred = scan.deferred.saturating_add(1),
                }
            }
            ReserveWorkerActionV1::DeadLetterConflict { finalized_cursor } => {
                match state
                    .sorafs_node
                    .mark_reserve_transaction_finalized_conflict(
                        delivery.operation_id,
                        finalized_cursor,
                    ) {
                    Ok(()) => scan.conflicted = scan.conflicted.saturating_add(1),
                    Err(_) => scan.deferred = scan.deferred.saturating_add(1),
                }
            }
            ReserveWorkerActionV1::MarkFinalizedAbsent { finalized_cursor } => {
                if state
                    .sorafs_node
                    .mark_reserve_transaction_finalized_absent(
                        delivery.operation_id,
                        finalized_cursor,
                    )
                    .is_err()
                {
                    warn!(
                        "failed to checkpoint authoritative absence for a native SoraFS reserve/rent transaction"
                    );
                }
                scan.deferred = scan.deferred.saturating_add(1);
            }
            ReserveWorkerActionV1::AdoptExactPending => {
                let transitioned = if delivery.state == ReserveTransactionDeliveryStateV1::Signed {
                    state
                        .sorafs_node
                        .begin_reserve_transaction_submission(delivery.operation_id)
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
                        .mark_reserve_transaction_submitted(delivery.operation_id)
                        .is_ok()
                {
                    scan.submitted = scan.submitted.saturating_add(1);
                } else {
                    scan.deferred = scan.deferred.saturating_add(1);
                }
            }
            ReserveWorkerActionV1::MarkTransactionRejected { finalized_cursor } => {
                let transitioned = if delivery.state == ReserveTransactionDeliveryStateV1::Signed {
                    state
                        .sorafs_node
                        .begin_reserve_transaction_submission(delivery.operation_id)
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
                        .mark_reserve_transaction_rejected(delivery.operation_id, finalized_cursor)
                        .is_ok()
                {
                    scan.rejected = scan.rejected.saturating_add(1);
                } else {
                    scan.deferred = scan.deferred.saturating_add(1);
                }
            }
            ReserveWorkerActionV1::ClaimForSigning => {
                let Some(signer) = state.sorafs_reserve_transaction_signer.clone() else {
                    scan.deferred = scan.deferred.saturating_add(1);
                    continue;
                };
                let claimed = match state
                    .sorafs_node
                    .claim_reserve_transaction_for_signing(delivery.operation_id)
                {
                    Ok(claimed) if claimed == retained.request => claimed,
                    Ok(_) | Err(_) => {
                        let _ = state
                            .sorafs_node
                            .release_reserve_transaction_signing_claim(delivery.operation_id);
                        scan.deferred = scan.deferred.saturating_add(1);
                        continue;
                    }
                };
                let Some((transaction, transaction_bytes)) =
                    sign_sorafs_reserve_transaction(state, signer, &claimed).await
                else {
                    let _ = state
                        .sorafs_node
                        .release_reserve_transaction_signing_claim(delivery.operation_id);
                    scan.deferred = scan.deferred.saturating_add(1);
                    continue;
                };
                match state
                    .sorafs_node
                    .store_signed_reserve_transaction(delivery.operation_id, &transaction_bytes)
                {
                    Ok(transaction_digest)
                        if transaction_digest == *blake3_hash(&transaction_bytes).as_bytes() =>
                    {
                        scan.signed = scan.signed.saturating_add(1);
                    }
                    Ok(_) | Err(_) => {
                        let _ = state
                            .sorafs_node
                            .release_reserve_transaction_signing_claim(delivery.operation_id);
                        scan.deferred = scan.deferred.saturating_add(1);
                        continue;
                    }
                }
                match submit_sorafs_reserve_transaction(
                    state,
                    delivery.operation_id,
                    transaction_bytes,
                    transaction,
                )
                .await
                {
                    ReserveTransactionSubmissionResultV1::Submitted => {
                        scan.submitted = scan.submitted.saturating_add(1);
                    }
                    ReserveTransactionSubmissionResultV1::Rejected => {
                        scan.rejected = scan.rejected.saturating_add(1);
                    }
                    ReserveTransactionSubmissionResultV1::Deferred => {
                        scan.deferred = scan.deferred.saturating_add(1);
                    }
                }
            }
            ReserveWorkerActionV1::SubmitSignedBytes => {
                let (Some(transaction), Some(transaction_bytes)) =
                    (exact_transaction, delivery.signed_transaction_bytes)
                else {
                    scan.deferred = scan.deferred.saturating_add(1);
                    continue;
                };
                match submit_sorafs_reserve_transaction(
                    state,
                    delivery.operation_id,
                    transaction_bytes,
                    transaction,
                )
                .await
                {
                    ReserveTransactionSubmissionResultV1::Submitted => {
                        scan.submitted = scan.submitted.saturating_add(1);
                    }
                    ReserveTransactionSubmissionResultV1::Rejected => {
                        scan.rejected = scan.rejected.saturating_add(1);
                    }
                    ReserveTransactionSubmissionResultV1::Deferred => {
                        scan.deferred = scan.deferred.saturating_add(1);
                    }
                }
            }
            ReserveWorkerActionV1::Defer(_) => {
                scan.deferred = scan.deferred.saturating_add(1);
            }
        }
    }
    scan
}
async fn sign_sorafs_reserve_transaction(
    state: &SharedAppState,
    signer: Arc<dyn SoraFsReserveTransactionSigner>,
    request: &ReserveTransactionSigningRequestV1,
) -> Option<(SignedTransaction, Vec<u8>)> {
    if signer.authority() != request.authority
        || request.network_id != *state.state.network_id_ref()
        || request.chain_id != *state.chain_id
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
    if bytes.len() > RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1
        || decode_exact_reserve_signed_transaction(&bytes, request).is_none()
    {
        return None;
    }
    Some((transaction, bytes))
}
async fn submit_sorafs_reserve_transaction(
    state: &SharedAppState,
    operation_id: [u8; 32],
    transaction_bytes: Vec<u8>,
    transaction: SignedTransaction,
) -> ReserveTransactionSubmissionResultV1 {
    if transaction.network_id() != Some(state.state.network_id_ref()) {
        return ReserveTransactionSubmissionResultV1::Deferred;
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
                .begin_reserve_transaction_submission(operation_id);
            if !exact
                .as_ref()
                .is_ok_and(|bytes| bytes == &transaction_bytes)
            {
                return ReserveTransactionSubmissionResultV1::Deferred;
            }
            let Some(finalized_cursor) = current_reserve_finalized_cursor(state) else {
                return ReserveTransactionSubmissionResultV1::Deferred;
            };
            return if state
                .sorafs_node
                .mark_reserve_transaction_rejected(operation_id, finalized_cursor)
                .is_ok()
            {
                ReserveTransactionSubmissionResultV1::Rejected
            } else {
                ReserveTransactionSubmissionResultV1::Deferred
            };
        }
    };
    let routing_plan = match state
        .queue
        .route_plan_with_state(&accepted, state.state.as_ref())
    {
        Ok(plan) => plan,
        Err(_) => return ReserveTransactionSubmissionResultV1::Deferred,
    };
    let routing_decision = routing_plan.coordinator_route();
    let exact_transaction_bytes = match state
        .sorafs_node
        .begin_reserve_transaction_submission(operation_id)
    {
        Ok(bytes) => bytes,
        Err(_) => return ReserveTransactionSubmissionResultV1::Deferred,
    };
    if exact_transaction_bytes != transaction_bytes {
        return ReserveTransactionSubmissionResultV1::Deferred;
    }
    let disposition = if crate::should_execute_route_locally(state.as_ref(), routing_decision) {
        match crate::routing::push_accepted_transaction_for_ingress_with_routing_plan(
            state.queue.clone(),
            state.state.clone(),
            accepted,
            Some(routing_plan),
        ) {
            Ok(_) => ReserveTransactionSubmissionDispositionV1::Submitted,
            Err(crate::Error::PushIntoQueue { source, .. }) => {
                classify_local_reserve_transaction_submission(source.as_ref())
            }
            Err(_) => ReserveTransactionSubmissionDispositionV1::Ambiguous,
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
            ReserveTransactionSubmissionDispositionV1::Submitted
        } else {
            ReserveTransactionSubmissionDispositionV1::Ambiguous
        }
    };
    match disposition {
        ReserveTransactionSubmissionDispositionV1::Submitted => {
            if state
                .sorafs_node
                .mark_reserve_transaction_submitted(operation_id)
                .is_ok()
            {
                ReserveTransactionSubmissionResultV1::Submitted
            } else {
                ReserveTransactionSubmissionResultV1::Deferred
            }
        }
        ReserveTransactionSubmissionDispositionV1::DefinitelyNotSubmitted => {
            let _ = state
                .sorafs_node
                .mark_reserve_transaction_not_submitted(operation_id);
            ReserveTransactionSubmissionResultV1::Deferred
        }
        ReserveTransactionSubmissionDispositionV1::Rejected => {
            let Some(finalized_cursor) = current_reserve_finalized_cursor(state) else {
                return ReserveTransactionSubmissionResultV1::Deferred;
            };
            if state
                .sorafs_node
                .mark_reserve_transaction_rejected(operation_id, finalized_cursor)
                .is_ok()
            {
                ReserveTransactionSubmissionResultV1::Rejected
            } else {
                ReserveTransactionSubmissionResultV1::Deferred
            }
        }
        ReserveTransactionSubmissionDispositionV1::Ambiguous => {
            ReserveTransactionSubmissionResultV1::Deferred
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PrivateKey};
    use iroha_data_model::{
        account::AccountId,
        asset::AssetDefinitionId,
        sorafs::{
            pin_registry::StorageClass,
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, RESERVE_RENT_BILLING_PERIOD_SECONDS_V1,
                ReserveAuthorityPolicyV1, ReserveDuration, ReserveLifecycleStage, ReservePolicyV1,
                ReserveProviderTermsV1, ReserveTier,
            },
        },
        transaction::SignedTransaction,
    };
    use iroha_model_base::domain::DomainId;
    fn cursor(height: u64, seed: u8) -> ReserveFinalizedCursorV1 {
        ReserveFinalizedCursorV1 {
            height,
            block_hash: [seed; 32],
        }
    }
    fn transaction_hash(seed: u8) -> HashOf<SignedTransaction> {
        HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32]))
    }
    fn finalized_reserve_event(
        sequence: u64,
        block_height: u64,
        event_index: u32,
        kind: SorafsReserveLedgerEventKind,
    ) -> iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1 {
        use iroha_data_model::events::data::sorafs::SorafsReserveLedgerEvent;
        let policy_event = kind == SorafsReserveLedgerEventKind::PolicyActivated;
        let provider_registration = kind == SorafsReserveLedgerEventKind::ProviderRegistered;
        let operation_event = matches!(
            kind,
            SorafsReserveLedgerEventKind::MovementRequested
                | SorafsReserveLedgerEventKind::MovementApproved
                | SorafsReserveLedgerEventKind::MovementRejected
                | SorafsReserveLedgerEventKind::AppealSubmitted
                | SorafsReserveLedgerEventKind::AppealAccepted
                | SorafsReserveLedgerEventKind::AppealRejected
        );
        iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1 {
            sequence,
            block_height,
            block_hash: [u8::try_from(block_height).unwrap_or(u8::MAX); 32],
            event_index,
            event: SorafsReserveLedgerEvent {
                kind,
                provider_id: (!policy_event).then(|| ProviderId::new([0xA1; 32])),
                operation_id: operation_event.then(|| {
                    let mut operation_id = [0xB1; 32];
                    operation_id[..8].copy_from_slice(&sequence.to_be_bytes());
                    operation_id
                }),
                policy_digest: [0xC1; 32],
                provider_revision: if policy_event {
                    0
                } else if provider_registration {
                    1
                } else {
                    sequence
                },
                resulting_lifecycle_stage: (!policy_event).then_some(ReserveLifecycleStage::Active),
                authority: account(0xD1),
                occurred_at_unix_ms: sequence.saturating_mul(1_000),
            },
        }
    }
    fn account(seed: u8) -> AccountId {
        let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
            .expect("valid deterministic Ed25519 seed");
        let keypair =
            KeyPair::from_private_key(private).expect("derive deterministic account keypair");
        AccountId::new(keypair.public_key().clone())
    }
    fn policy_record(
        revision: u64,
        predecessor_policy_digest: Option<[u8; 32]>,
    ) -> ReserveAuthorityPolicyRecordV1 {
        let policy = ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision,
            predecessor_policy_digest,
            economics: ReservePolicyV1::default(),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("reserve", "universal").expect("reserve domain"),
                "xor".parse().expect("reserve asset"),
            ),
            custody_account: account(0x31),
            treasury_account: account(0x32),
            operations_authority: account(0x33),
            decision_authority: account(0x34),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000)
                .expect("maximum provider debt"),
            max_pending_movements_per_provider: 8,
            max_open_appeals_per_provider: 4,
        };
        let policy_digest = policy.digest().expect("reserve policy digest");
        ReserveAuthorityPolicyRecordV1 {
            policy,
            policy_digest,
            activated_by: account(0x35),
            activated_at_unix: 1,
        }
    }
    fn provider_account(
        policy_digest: [u8; 32],
        revision: u64,
        rent_charged_through_unix: u64,
    ) -> ReserveProviderAccountV1 {
        ReserveProviderAccountV1 {
            terms: ReserveProviderTermsV1 {
                provider_id: ProviderId::new([0x41; 32]),
                provider_account: account(0x42),
                tier: ReserveTier::TierA,
                storage_class: StorageClass::Hot,
                duration: ReserveDuration::Monthly,
                capacity_gib: 10,
            },
            policy_digest,
            revision,
            reserve_balance: XorQuantity::zero(),
            debt_principal: XorQuantity::zero(),
            accrued_interest: XorQuantity::zero(),
            credit_cap: XorQuantity::try_from_micro(1_000_000_000).expect("provider credit cap"),
            lifecycle_stage: ReserveLifecycleStage::Warning,
            days_past_due: 0,
            pending_movements: 0,
            open_appeals: 0,
            rent_charged_through_unix,
            interest_accrued_at_unix: rent_charged_through_unix,
            updated_at_unix: rent_charged_through_unix,
        }
    }
    fn period_rent(
        policy: &ReserveAuthorityPolicyRecordV1,
        account: &ReserveProviderAccountV1,
    ) -> XorQuantity {
        policy
            .policy
            .economics
            .quote(
                account.terms.storage_class,
                account.terms.capacity_gib,
                account.terms.duration,
                account.terms.tier,
                account.reserve_balance.clone(),
            )
            .expect("reserve rent quote")
            .effective_rent
    }
    fn charged_periods(operation: &ReserveOperationV1) -> Option<u16> {
        match operation {
            ReserveOperationV1::ChargeRent(instruction) => Some(*instruction.billing_periods()),
            _ => None,
        }
    }
    #[test]
    fn queue_domain_mismatch_is_permanent_reserve_runtime_rejection() {
        assert_eq!(
            classify_local_reserve_transaction_submission(
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
            ReserveTransactionSubmissionDispositionV1::Rejected
        );
        assert_eq!(
            classify_local_reserve_transaction_submission(&iroha_core::queue::Error::Full),
            ReserveTransactionSubmissionDispositionV1::DefinitelyNotSubmitted
        );
        assert_eq!(
            classify_local_reserve_transaction_submission(&iroha_core::queue::Error::IsInQueue),
            ReserveTransactionSubmissionDispositionV1::Submitted
        );
    }
    #[test]
    fn generation_chooses_largest_affordable_batch_and_replays_same_tip_identically() {
        let first = policy_record(1, None);
        let account = provider_account(first.policy_digest, 7, 100);
        let rent = period_rent(&first, &account);
        let finalized_at =
            account.rent_charged_through_unix + 20 * RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
        let seven_periods = rent
            .checked_mul_u64(7)
            .expect("seven-period spendable balance");
        let partially_affordable =
            plan_generated_reserve_operation(&first, &account, &seven_periods, finalized_at)
                .expect("partially affordable generation")
                .expect("rent work is due");
        assert_eq!(charged_periods(&partially_affordable), Some(7));
        assert_eq!(
            plan_generated_reserve_operation(&first, &account, &seven_periods, finalized_at,)
                .expect("same-tip replay")
                .expect("same operation remains due"),
            partially_affordable,
            "same finalized inputs must generate byte-identical semantics"
        );
        let abundant = rent
            .checked_mul_u64(20)
            .expect("abundant spendable balance");
        let capped = plan_generated_reserve_operation(&first, &account, &abundant, finalized_at)
            .expect("bounded generation")
            .expect("rent work is due");
        assert_eq!(
            charged_periods(&capped),
            Some(RESERVE_RENT_MAX_BILLING_PERIODS_V1)
        );
        let rotated = policy_record(2, Some(first.policy_digest));
        let rotated_operation =
            plan_generated_reserve_operation(&rotated, &account, &seven_periods, finalized_at)
                .expect("active policy rotation is valid")
                .expect("rotated rent work is due");
        let ReserveOperationV1::ChargeRent(rotated_charge) = rotated_operation else {
            panic!("an affordable rotated operation must charge rent");
        };
        assert_eq!(*rotated_charge.policy_digest(), rotated.policy_digest);
        assert_ne!(*rotated_charge.policy_digest(), account.policy_digest);
    }
    #[test]
    fn generation_catches_up_across_multiple_bounded_affordable_batches() {
        let policy = policy_record(1, None);
        let mut account = provider_account(policy.policy_digest, 1, 500);
        let rent = period_rent(&policy, &account);
        let finalized_at =
            account.rent_charged_through_unix + 30 * RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
        let mut spendable = rent
            .checked_mul_u64(15)
            .expect("fifteen-period spendable balance");
        let first = plan_generated_reserve_operation(&policy, &account, &spendable, finalized_at)
            .expect("first catchup generation")
            .expect("first catchup batch");
        assert_eq!(
            charged_periods(&first),
            Some(RESERVE_RENT_MAX_BILLING_PERIODS_V1)
        );
        account.rent_charged_through_unix +=
            u64::from(RESERVE_RENT_MAX_BILLING_PERIODS_V1) * RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
        account.revision += 1;
        account.updated_at_unix = finalized_at;
        account.interest_accrued_at_unix = finalized_at;
        spendable = spendable
            .checked_sub(
                &rent
                    .checked_mul_u64(u64::from(RESERVE_RENT_MAX_BILLING_PERIODS_V1))
                    .expect("first catchup rent"),
            )
            .expect("remaining exact spendable balance");
        let second = plan_generated_reserve_operation(&policy, &account, &spendable, finalized_at)
            .expect("second catchup generation")
            .expect("second catchup batch");
        assert_eq!(charged_periods(&second), Some(3));
        let exact_account = provider_account(
            policy.policy_digest,
            9,
            finalized_at - RESERVE_RENT_BILLING_PERIOD_SECONDS_V1,
        );
        let exact = plan_generated_reserve_operation(&policy, &exact_account, &rent, finalized_at)
            .expect("exact-balance generation")
            .expect("one exact-balance period is due");
        assert_eq!(charged_periods(&exact), Some(1));
    }
    #[test]
    fn generation_uses_exact_boundary_age_and_avoids_lifecycle_revision_churn() {
        let policy = policy_record(1, None);
        let mut account = provider_account(policy.policy_digest, 1, 700);
        let exact_boundary =
            account.rent_charged_through_unix + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
        assert_eq!(
            plan_generated_reserve_operation(
                &policy,
                &account,
                &XorQuantity::zero(),
                exact_boundary,
            )
            .expect("exact boundary generation"),
            None,
            "day zero and an unchanged warning stage must not churn the revision"
        );
        let one_day_overdue = exact_boundary + 86_400;
        let lifecycle = plan_generated_reserve_operation(
            &policy,
            &account,
            &XorQuantity::zero(),
            one_day_overdue,
        )
        .expect("overdue generation")
        .expect("changed overdue state requires lifecycle work");
        let ReserveOperationV1::AdvanceLifecycle(advance) = lifecycle else {
            panic!("no affordable period must select lifecycle work");
        };
        assert_eq!(*advance.days_past_due(), 1);
        assert_eq!(*advance.policy_digest(), policy.policy_digest);
        account.days_past_due = 1;
        account.lifecycle_stage = ReserveLifecycleStage::Grace;
        account.updated_at_unix = one_day_overdue;
        assert_eq!(
            plan_generated_reserve_operation(
                &policy,
                &account,
                &XorQuantity::zero(),
                one_day_overdue,
            )
            .expect("same-tip lifecycle replay"),
            None
        );
        assert_eq!(
            plan_generated_reserve_operation(
                &policy,
                &account,
                &XorQuantity::zero(),
                one_day_overdue - 1,
            )
            .expect_err("a finalized timestamp cannot regress provider state"),
            ReserveGenerationErrorV1::InvalidProviderTimestamp
        );
    }
    #[test]
    fn generation_converges_day_zero_custody_changes_and_charges_zero_rent() {
        let policy = policy_record(1, None);
        let mut topped_up = provider_account(policy.policy_digest, 1, 900);
        let reserve_requirement = policy
            .policy
            .economics
            .quote(
                topped_up.terms.storage_class,
                topped_up.terms.capacity_gib,
                topped_up.terms.duration,
                topped_up.terms.tier,
                XorQuantity::zero(),
            )
            .expect("baseline reserve quote")
            .reserve_requirement;
        topped_up.reserve_balance = reserve_requirement;
        let before_first_due =
            topped_up.rent_charged_through_unix + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1 - 1;
        let topup_recovery = plan_generated_reserve_operation(
            &policy,
            &topped_up,
            &XorQuantity::zero(),
            before_first_due,
        )
        .expect("top-up convergence")
        .expect("a sufficient top-up changes warning to active");
        let ReserveOperationV1::AdvanceLifecycle(advance_active) = topup_recovery else {
            panic!("a pre-due top-up must converge lifecycle state");
        };
        assert_eq!(*advance_active.days_past_due(), 0);
        let mut withdrawn = topped_up.clone();
        withdrawn.reserve_balance = XorQuantity::zero();
        withdrawn.lifecycle_stage = ReserveLifecycleStage::Active;
        let withdrawal_warning = plan_generated_reserve_operation(
            &policy,
            &withdrawn,
            &XorQuantity::zero(),
            before_first_due,
        )
        .expect("withdrawal convergence")
        .expect("a pre-due reserve shortfall changes active to warning");
        let ReserveOperationV1::AdvanceLifecycle(advance_warning) = withdrawal_warning else {
            panic!("a pre-due withdrawal must converge lifecycle state");
        };
        assert_eq!(*advance_warning.days_past_due(), 0);
        let exact_boundary =
            topped_up.rent_charged_through_unix + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
        let zero_rent = plan_generated_reserve_operation(
            &policy,
            &topped_up,
            &XorQuantity::zero(),
            exact_boundary,
        )
        .expect("zero-rent generation")
        .expect("a zero-rent period still advances the ledger anchor");
        assert_eq!(charged_periods(&zero_rent), Some(1));
        let mut uncovered = withdrawn;
        uncovered.terms.tier = ReserveTier::TierC;
        let default_operation = plan_generated_reserve_operation(
            &policy,
            &uncovered,
            &XorQuantity::zero(),
            exact_boundary + 86_400,
        )
        .expect("uncovered lifecycle generation")
        .expect("uncovered overdue rent changes lifecycle");
        let ReserveOperationV1::AdvanceLifecycle(advance_default) = default_operation else {
            panic!("an uncovered tier-C provider must advance lifecycle");
        };
        assert_eq!(*advance_default.days_past_due(), 1);
        assert_eq!(
            policy
                .policy
                .economics
                .quote(
                    uncovered.terms.storage_class,
                    uncovered.terms.capacity_gib,
                    uncovered.terms.duration,
                    uncovered.terms.tier,
                    uncovered.reserve_balance,
                )
                .expect("uncovered tier-C quote")
                .lifecycle_projection(
                    1,
                    policy.policy.grace_period_days,
                    policy.policy.default_after_days,
                )
                .expect("uncovered tier-C lifecycle")
                .stage,
            ReserveLifecycleStage::Default
        );
    }
    #[test]
    fn exact_applied_rejected_pending_and_absence_repeat_retained_digest_and_cursor() {
        let bytes = [0x51, 0x52, 0x53];
        let digest = *blake3_hash(&bytes).as_bytes();
        let finalized_cursor = cursor(12, 0x61);
        assert_eq!(
            classify_reserve_envelope(
                Some(digest),
                Some(&bytes),
                finalized_cursor,
                ReserveAuthoritativeTransactionOutcomeV1::Applied,
                false,
            ),
            ReserveEnvelopeReconciliationV1::Applied {
                transaction_digest: digest,
                finalized_cursor,
            }
        );
        assert_eq!(
            classify_reserve_envelope(
                Some(digest),
                Some(&bytes),
                finalized_cursor,
                ReserveAuthoritativeTransactionOutcomeV1::Rejected,
                false,
            ),
            ReserveEnvelopeReconciliationV1::Rejected {
                transaction_digest: digest,
                finalized_cursor,
            }
        );
        assert_eq!(
            classify_reserve_envelope(
                Some(digest),
                Some(&bytes),
                finalized_cursor,
                ReserveAuthoritativeTransactionOutcomeV1::Absent,
                true,
            ),
            ReserveEnvelopeReconciliationV1::Pending {
                transaction_digest: digest,
                finalized_cursor,
            }
        );
        assert_eq!(
            classify_reserve_envelope(
                Some(digest),
                Some(&bytes),
                finalized_cursor,
                ReserveAuthoritativeTransactionOutcomeV1::Absent,
                false,
            ),
            ReserveEnvelopeReconciliationV1::Absent {
                transaction_digest: digest,
                finalized_cursor,
            }
        );
    }
    #[test]
    fn exact_observation_fails_closed_on_missing_duplicate_or_unavailable_entrypoints() {
        let expected = transaction_hash(0x71);
        assert_eq!(
            classify_exact_reserve_entrypoint_outcome(
                &expected,
                true,
                [(
                    transaction_hash(0x72),
                    ReserveCommittedExternalOutcomeV1::Applied
                )]
            ),
            ReserveAuthoritativeTransactionOutcomeV1::Unavailable
        );
        assert_eq!(
            classify_exact_reserve_entrypoint_outcome(
                &expected,
                true,
                [
                    (expected.clone(), ReserveCommittedExternalOutcomeV1::Applied),
                    (
                        expected.clone(),
                        ReserveCommittedExternalOutcomeV1::Rejected
                    ),
                ]
            ),
            ReserveAuthoritativeTransactionOutcomeV1::Unavailable
        );
        assert_eq!(
            classify_exact_reserve_entrypoint_outcome(
                &expected,
                false,
                [(expected, ReserveCommittedExternalOutcomeV1::Applied)]
            ),
            ReserveAuthoritativeTransactionOutcomeV1::Unavailable
        );
    }
    #[test]
    fn stale_cursor_and_mismatched_digest_never_create_authoritative_absence() {
        let bytes = [0x81, 0x82, 0x83];
        let digest = *blake3_hash(&bytes).as_bytes();
        assert_eq!(
            classify_reserve_envelope(
                Some([0x84; 32]),
                Some(&bytes),
                cursor(12, 0x85),
                ReserveAuthoritativeTransactionOutcomeV1::Absent,
                false,
            ),
            ReserveEnvelopeReconciliationV1::Unavailable
        );
        assert_eq!(
            classify_reserve_envelope(
                Some(digest),
                Some(&bytes),
                ReserveFinalizedCursorV1 {
                    height: 0,
                    block_hash: [0; 32],
                },
                ReserveAuthoritativeTransactionOutcomeV1::Absent,
                false,
            ),
            ReserveEnvelopeReconciliationV1::Unavailable
        );
    }
    #[test]
    fn finalized_telemetry_projection_rebuilds_across_pages_without_payload_labels() {
        let finalized_cursor = cursor(3, 0xF1);
        let first_events = vec![
            finalized_reserve_event(1, 1, 0, SorafsReserveLedgerEventKind::PolicyActivated),
            finalized_reserve_event(2, 1, 1, SorafsReserveLedgerEventKind::ProviderRegistered),
            finalized_reserve_event(3, 2, 0, SorafsReserveLedgerEventKind::MovementRequested),
        ];
        let first_after = first_events
            .last()
            .map(iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1::cursor);
        let first = ReserveFinalizedEventPageV1 {
            finalized_cursor,
            events: first_events,
            has_more: true,
            next_after: first_after,
        };
        let second = ReserveFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![
                finalized_reserve_event(4, 2, 1, SorafsReserveLedgerEventKind::MovementApproved),
                finalized_reserve_event(5, 3, 0, SorafsReserveLedgerEventKind::AppealSubmitted),
                finalized_reserve_event(6, 3, 1, SorafsReserveLedgerEventKind::AppealRejected),
            ],
            has_more: false,
            next_after: None,
        };
        let mut projection = SorafsReserveFinalizedTelemetryProjectionV1::default();
        apply_reserve_finalized_telemetry_event_page(&mut projection, &first, finalized_cursor)
            .expect("first finalized event page");
        assert_eq!(projection.custody_counts, [1, 0, 0]);
        assert_eq!(projection.open_appeals, 0);
        apply_reserve_finalized_telemetry_event_page(&mut projection, &second, finalized_cursor)
            .expect("second finalized event page");
        assert_eq!(
            projection.after_event,
            second
                .events
                .last()
                .map(iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1::cursor)
        );
        assert_eq!(projection.custody_counts, [0, 1, 0]);
        assert_eq!(projection.reconciled_counts, [1, 0]);
        assert_eq!(projection.open_appeals, 0);
    }
    #[test]
    fn finalized_telemetry_page_failure_is_atomic_for_gaps_and_terminal_underflow() {
        let finalized_cursor = cursor(2, 0xF2);
        let mut projection = SorafsReserveFinalizedTelemetryProjectionV1::default();
        let gap = ReserveFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_reserve_event(
                2,
                1,
                0,
                SorafsReserveLedgerEventKind::MovementRequested,
            )],
            has_more: false,
            next_after: None,
        };
        assert_eq!(
            apply_reserve_finalized_telemetry_event_page(&mut projection, &gap, finalized_cursor,),
            Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidEventPage)
        );
        assert_eq!(
            projection,
            SorafsReserveFinalizedTelemetryProjectionV1::default()
        );
        let terminal_without_request = ReserveFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![finalized_reserve_event(
                1,
                1,
                0,
                SorafsReserveLedgerEventKind::MovementRejected,
            )],
            has_more: false,
            next_after: None,
        };
        assert_eq!(
            apply_reserve_finalized_telemetry_event_page(
                &mut projection,
                &terminal_without_request,
                finalized_cursor,
            ),
            Err(SorafsReserveFinalizedTelemetryErrorV1::ProjectionMismatch)
        );
        assert_eq!(
            projection,
            SorafsReserveFinalizedTelemetryProjectionV1::default()
        );
    }
    #[test]
    fn finalized_telemetry_rejects_malformed_continuation_shape() {
        let finalized_cursor = cursor(1, 0xF3);
        let event = finalized_reserve_event(1, 1, 0, SorafsReserveLedgerEventKind::PolicyActivated);
        let page = ReserveFinalizedEventPageV1 {
            finalized_cursor,
            events: vec![event],
            has_more: true,
            next_after: None,
        };
        let mut projection = SorafsReserveFinalizedTelemetryProjectionV1::default();
        assert_eq!(
            apply_reserve_finalized_telemetry_event_page(&mut projection, &page, finalized_cursor,),
            Err(SorafsReserveFinalizedTelemetryErrorV1::InvalidEventPage)
        );
        assert_eq!(
            projection,
            SorafsReserveFinalizedTelemetryProjectionV1::default()
        );
    }
    #[test]
    fn reserve_metric_projection_truncates_sub_micro_precision_deterministically() {
        use iroha_primitives::numeric::Quantity;
        let one_nano = XorQuantity::try_from_quantity(
            Quantity::from_canonical_numeric(Numeric::new(1, 9))
                .expect("one nano-XOR is canonical"),
        )
        .expect("one nano-XOR is within the exact XOR scale");
        let one_micro = XorQuantity::try_from_micro(1).expect("one micro-XOR");
        assert_eq!(reserve_quantity_to_metric_micro_xor(&one_nano), Ok(0));
        assert_eq!(reserve_quantity_to_metric_micro_xor(&one_micro), Ok(1));
    }
    #[test]
    fn reserve_supervision_uses_storage_or_generation_activation() {
        for (storage_enabled, generation_enabled, role_active) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(
                reserve_worker_supervision(storage_enabled, generation_enabled),
                ReserveWorkerSupervisionV1 {
                    generation_enabled,
                    role_active,
                }
            );
        }
    }
    #[test]
    fn disabled_reserve_supervision_does_not_invoke_spawn_adapter() {
        let spawn_count = std::cell::Cell::new(0_u32);
        assert!(
            spawn_reserve_worker_when_active(reserve_worker_supervision(false, false), || {
                spawn_count.set(spawn_count.get() + 1);
            })
            .is_none()
        );
        assert_eq!(spawn_count.get(), 0);
        assert!(
            spawn_reserve_worker_when_active(reserve_worker_supervision(true, false), || {
                spawn_count.set(spawn_count.get() + 1);
            })
            .is_some()
        );
        assert_eq!(spawn_count.get(), 1);
    }
    #[test]
    fn local_queue_dispositions_preserve_strict_submitter_boundaries() {
        assert_eq!(
            classify_local_reserve_transaction_submission(&iroha_core::queue::Error::Full),
            ReserveTransactionSubmissionDispositionV1::DefinitelyNotSubmitted
        );
        assert_eq!(
            classify_local_reserve_transaction_submission(
                &iroha_core::queue::Error::AdmissionInvariant {
                    reason: "admission index unavailable".to_owned()
                }
            ),
            ReserveTransactionSubmissionDispositionV1::DefinitelyNotSubmitted
        );
        assert_eq!(
            classify_local_reserve_transaction_submission(&iroha_core::queue::Error::IsInQueue),
            ReserveTransactionSubmissionDispositionV1::Submitted
        );
        assert_eq!(
            classify_local_reserve_transaction_submission(&iroha_core::queue::Error::Expired),
            ReserveTransactionSubmissionDispositionV1::Rejected
        );
    }
}
