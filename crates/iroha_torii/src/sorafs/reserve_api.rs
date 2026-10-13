//! Chain-authoritative SoraFS reserve/rent HTTP boundary.
//!
//! V1 deliberately has no process-local reserve model. Mutation routes accept one exact
//! caller-signed native instruction and forward that transaction to strict durable ingress. Read
//! routes execute typed queries against one immutable finalized view and expose the resulting
//! cursor with every page or singular record.

use crate::{
    JsonBody, SharedAppState,
    routing::MaybeTelemetry,
    utils::extractors::{ExtractAccept, JsonOrNoritoVersioned},
};
use axum::{
    extract::{
        Extension, Path, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, Sse},
    },
};
use futures::{SinkExt, StreamExt, stream};
use iroha_core::{smartcontracts::ValidSingularQuery, state::StateReadOnly};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::{
        DecideSorafsReserveAppeal, DecideSorafsReserveMovement, DrawSorafsReserveCredit,
        RepaySorafsReserveCredit, RequestSorafsReserveMovement, SubmitSorafsReserveAppeal,
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
        reserve::{
            RESERVE_QUERY_MAX_ITEMS_V1, ReserveAuthorityPolicyRecordV1, ReserveFinalizedCursorV1,
            ReserveFinalizedEventCursorV1, ReserveFinalizedEventPageV1, ReserveFinalizedEventV1,
            ReserveMovementKindV1, ReserveMovementStatusV1, ReserveProviderAccountV1,
        },
    },
    transaction::{Executable, SignedTransaction},
};
use iroha_logger::{debug, warn};
use norito::json;
use sorafs_node::reserve_transaction_forwarder::RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1;
use std::{collections::VecDeque, convert::Infallible, future::Future, time::Duration};
/// Exact TTL used by every caller- and worker-signed reserve V1 transaction.
const RESERVE_TRANSACTION_TTL_V1: Duration = Duration::from_secs(300);
const RESERVE_DEFAULT_PAGE_LIMIT_V1: u32 = 100;
const RESERVE_EVENT_POLL_INTERVAL_V1: Duration = Duration::from_secs(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReserveCommandRouteV1 {
    RequestMovement(ReserveMovementKindV1),
    DecideMovement([u8; 32]),
    DrawCredit,
    RepayCredit,
    SubmitAppeal,
    DecideAppeal([u8; 32]),
}
async fn observe_reserve_api_response<F>(
    telemetry: MaybeTelemetry,
    route: &'static str,
    response: F,
) -> Response
where
    F: Future<Output = Response>,
{
    let response = response.await;
    let result = match response.status() {
        StatusCode::ACCEPTED => "accepted",
        status if status.is_success() || status == StatusCode::SWITCHING_PROTOCOLS => "ok",
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::TOO_MANY_REQUESTS => "too_many_requests",
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => "unavailable",
        _ => "error",
    };
    telemetry.with_metrics(|metrics| {
        metrics.record_sorafs_reserve_service_request(route, result);
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            metrics.inc_sorafs_reserve_service_rate_limit(route, "ingress");
        }
    });
    response
}
#[derive(Debug, Default)]
struct ReservePageQueryV1 {
    expected_finalized_height: Option<u64>,
    expected_finalized_block_hash: Option<[u8; 32]>,
    after_id: Option<[u8; 32]>,
    limit: Option<u32>,
}
#[derive(Debug, Default)]
struct ReserveAnchorQueryV1 {
    expected_finalized_height: Option<u64>,
    expected_finalized_block_hash: Option<[u8; 32]>,
}
#[derive(Debug, Default)]
struct ReserveEventQueryV1 {
    expected_finalized_height: Option<u64>,
    expected_finalized_block_hash: Option<[u8; 32]>,
    after_sequence: Option<u64>,
    after_block_height: Option<u64>,
    after_block_hash: Option<[u8; 32]>,
    after_event_index: Option<u32>,
    limit: Option<u32>,
}
impl ReserveAnchorQueryV1 {
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn parse(raw: Option<&str>) -> Result<Self, Response> {
        let mut query = Self::default();
        walk_query(raw, |key, value| match key {
            "expected_finalized_height" => {
                parse_unique_u64(&mut query.expected_finalized_height, key, value)
            }
            "expected_finalized_block_hash_hex" => {
                parse_unique_hex(&mut query.expected_finalized_block_hash, key, value, true)
            }
            _ => Err(format!(
                "unknown finalized SoraFS reserve anchor parameter `{key}`"
            )),
        })?;
        validate_finalized_cursor_pair(
            query.expected_finalized_height,
            query.expected_finalized_block_hash,
        )?;
        Ok(query)
    }
    fn expected_finalized_cursor(&self) -> Option<ReserveFinalizedCursorV1> {
        self.expected_finalized_height
            .zip(self.expected_finalized_block_hash)
            .map(|(height, block_hash)| ReserveFinalizedCursorV1 { height, block_hash })
    }
}
impl ReservePageQueryV1 {
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn parse(raw: Option<&str>, after_parameter: &str) -> Result<Self, Response> {
        let mut query = Self::default();
        walk_query(raw, |key, value| match key {
            "limit" => parse_unique_u32(&mut query.limit, key, value),
            "expected_finalized_height" => {
                parse_unique_u64(&mut query.expected_finalized_height, key, value)
            }
            "expected_finalized_block_hash_hex" => {
                parse_unique_hex(&mut query.expected_finalized_block_hash, key, value, true)
            }
            key if key == after_parameter => {
                parse_unique_hex(&mut query.after_id, key, value, true)
            }
            _ => Err(format!(
                "unknown finalized SoraFS reserve query parameter `{key}`"
            )),
        })?;
        validate_finalized_cursor_pair(
            query.expected_finalized_height,
            query.expected_finalized_block_hash,
        )?;
        if query
            .limit
            .is_some_and(|limit| !(1..=RESERVE_QUERY_MAX_ITEMS_V1).contains(&limit))
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "SoraFS reserve query limit must be within 1..={RESERVE_QUERY_MAX_ITEMS_V1}"
                ),
            ));
        }
        Ok(query)
    }
    fn expected_finalized_cursor(&self) -> Option<ReserveFinalizedCursorV1> {
        self.expected_finalized_height
            .zip(self.expected_finalized_block_hash)
            .map(|(height, block_hash)| ReserveFinalizedCursorV1 { height, block_hash })
    }
    fn limit(&self) -> u32 {
        self.limit
            .unwrap_or(RESERVE_DEFAULT_PAGE_LIMIT_V1)
            .clamp(1, RESERVE_QUERY_MAX_ITEMS_V1)
    }
}
impl ReserveEventQueryV1 {
    #[expect(
        clippy::result_large_err,
        reason = "HTTP rejections retain the complete Axum response at this transport boundary."
    )]
    fn parse(raw: Option<&str>) -> Result<Self, Response> {
        let mut query = Self::default();
        walk_query(raw, |key, value| match key {
            "limit" => parse_unique_u32(&mut query.limit, key, value),
            "expected_finalized_height" => {
                parse_unique_u64(&mut query.expected_finalized_height, key, value)
            }
            "expected_finalized_block_hash_hex" => {
                parse_unique_hex(&mut query.expected_finalized_block_hash, key, value, true)
            }
            "after_sequence" => parse_unique_u64(&mut query.after_sequence, key, value),
            "after_block_height" => parse_unique_u64(&mut query.after_block_height, key, value),
            "after_block_hash_hex" => {
                parse_unique_hex(&mut query.after_block_hash, key, value, true)
            }
            "after_event_index" => parse_unique_u32(&mut query.after_event_index, key, value),
            _ => Err(format!(
                "unknown finalized SoraFS reserve event query parameter `{key}`"
            )),
        })?;
        validate_finalized_cursor_pair(
            query.expected_finalized_height,
            query.expected_finalized_block_hash,
        )?;
        if query
            .limit
            .is_some_and(|limit| !(1..=RESERVE_QUERY_MAX_ITEMS_V1).contains(&limit))
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "SoraFS reserve event query limit must be within 1..={RESERVE_QUERY_MAX_ITEMS_V1}"
                ),
            ));
        }
        let cursor_parts = [
            query.after_sequence.is_some(),
            query.after_block_height.is_some(),
            query.after_block_hash.is_some(),
            query.after_event_index.is_some(),
        ];
        if cursor_parts.iter().any(|present| *present)
            && !cursor_parts.iter().all(|present| *present)
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "complete finalized SoraFS reserve event cursor is required",
            ));
        }
        if query.after_sequence == Some(0) || query.after_block_height == Some(0) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "SoraFS reserve event cursor sequence and block height must be non-zero",
            ));
        }
        Ok(query)
    }
    fn expected_finalized_cursor(&self) -> Option<ReserveFinalizedCursorV1> {
        self.expected_finalized_height
            .zip(self.expected_finalized_block_hash)
            .map(|(height, block_hash)| ReserveFinalizedCursorV1 { height, block_hash })
    }
    fn after(&self) -> Option<ReserveFinalizedEventCursorV1> {
        Some(ReserveFinalizedEventCursorV1 {
            sequence: self.after_sequence?,
            block_height: self.after_block_height?,
            block_hash: self.after_block_hash?,
            event_index: self.after_event_index?,
        })
    }
    fn limit(&self) -> u32 {
        self.limit
            .unwrap_or(RESERVE_DEFAULT_PAGE_LIMIT_V1)
            .clamp(1, RESERVE_QUERY_MAX_ITEMS_V1)
    }
}
pub async fn handle_post_sorafs_reserve_top_up(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "top_up", async move {
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp),
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_withdrawal(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "withdrawal", async move {
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::Withdrawal),
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_movement_decision(
    State(state): State<SharedAppState>,
    Path(movement_id_hex): Path<String>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "movement_decision", async move {
        let movement_id = match parse_nonzero_hex(&movement_id_hex, "movement_id_hex") {
            Ok(movement_id) => movement_id,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, error),
        };
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::DecideMovement(movement_id),
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_credit_draw(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "credit_draw", async move {
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::DrawCredit,
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_credit_repay(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "credit_repay", async move {
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::RepayCredit,
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_appeal(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "appeal", async move {
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::SubmitAppeal,
        )
        .await
    })
    .await
}
pub async fn handle_post_sorafs_reserve_appeal_decision(
    State(state): State<SharedAppState>,
    Path(appeal_id_hex): Path<String>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    JsonOrNoritoVersioned(transaction): JsonOrNoritoVersioned<SignedTransaction>,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "appeal_decision", async move {
        let appeal_id = match parse_nonzero_hex(&appeal_id_hex, "appeal_id_hex") {
            Ok(appeal_id) => appeal_id,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, error),
        };
        submit_reserve_signed_transaction(
            state,
            headers,
            accept,
            transaction,
            ReserveCommandRouteV1::DecideAppeal(appeal_id),
        )
        .await
    })
    .await
}
async fn submit_reserve_signed_transaction(
    state: SharedAppState,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
    transaction: SignedTransaction,
    route: ReserveCommandRouteV1,
) -> Response {
    if !state.sorafs_node.is_enabled() {
        return feature_disabled();
    }
    if let Err(response) = validate_reserve_signed_transaction(&state, &transaction, route) {
        return response;
    }
    match Box::pin(crate::submit_signed_transaction_for_ingress(
        state,
        headers,
        accept,
        transaction,
    ))
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_reserve_signed_transaction(
    state: &SharedAppState,
    transaction: &SignedTransaction,
    route: ReserveCommandRouteV1,
) -> Result<(), Response> {
    validate_reserve_signed_envelope_and_route(state.state.network_id_ref(), transaction, route)?;
    let view = state.state.query_view();
    let policy = FindSorafsReservePolicy::new()
        .execute(&view)
        .map_err(reserve_query_error_response)?;
    let authority = transaction.authority();
    match route {
        ReserveCommandRouteV1::RequestMovement(expected_kind) => {
            let request = one_instruction::<RequestSorafsReserveMovement>(transaction)?;
            if request.kind != expected_kind {
                return Err(route_mismatch(route));
            }
            let account = FindSorafsReserveProviderById::new(request.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_provider_authority(authority, &account)?;
            require_current_provider_binding(
                request.expected_provider_revision,
                request.policy_digest,
                &account,
                &policy,
            )
        }
        ReserveCommandRouteV1::DecideMovement(path_movement_id) => {
            let decision = one_instruction::<DecideSorafsReserveMovement>(transaction)?;
            if decision.movement_id != path_movement_id {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "SoraFS reserve movement decision does not match the route identifier",
                ));
            }
            require_subject(authority, &policy.policy.decision_authority, "decision")?;
            let movement = FindSorafsReserveMovementById::new(decision.movement_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            if movement.status != ReserveMovementStatusV1::Pending {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "SoraFS reserve movement is already terminal",
                ));
            }
            let account = FindSorafsReserveProviderById::new(movement.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_current_provider_binding(
                decision.expected_provider_revision,
                decision.policy_digest,
                &account,
                &policy,
            )
        }
        ReserveCommandRouteV1::DrawCredit => {
            let draw = one_instruction::<DrawSorafsReserveCredit>(transaction)?;
            require_subject(authority, &policy.policy.operations_authority, "operations")?;
            let account = FindSorafsReserveProviderById::new(draw.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_current_provider_binding(
                draw.expected_provider_revision,
                draw.policy_digest,
                &account,
                &policy,
            )
        }
        ReserveCommandRouteV1::RepayCredit => {
            let repayment = one_instruction::<RepaySorafsReserveCredit>(transaction)?;
            let account = FindSorafsReserveProviderById::new(repayment.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_provider_authority(authority, &account)?;
            require_current_provider_binding(
                repayment.expected_provider_revision,
                repayment.policy_digest,
                &account,
                &policy,
            )
        }
        ReserveCommandRouteV1::SubmitAppeal => {
            let appeal = one_instruction::<SubmitSorafsReserveAppeal>(transaction)?;
            let account = FindSorafsReserveProviderById::new(appeal.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_provider_authority(authority, &account)?;
            require_current_provider_binding(
                appeal.expected_provider_revision,
                appeal.policy_digest,
                &account,
                &policy,
            )
        }
        ReserveCommandRouteV1::DecideAppeal(path_appeal_id) => {
            let decision = one_instruction::<DecideSorafsReserveAppeal>(transaction)?;
            if decision.appeal_id != path_appeal_id {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "SoraFS reserve appeal decision does not match the route identifier",
                ));
            }
            require_subject(authority, &policy.policy.decision_authority, "decision")?;
            let appeal = FindSorafsReserveAppealById::new(decision.appeal_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            if appeal.status != iroha_data_model::sorafs::reserve::ReserveAppealStatusV1::Pending {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "SoraFS reserve appeal is already terminal",
                ));
            }
            let account = FindSorafsReserveProviderById::new(appeal.provider_id)
                .execute(&view)
                .map_err(reserve_query_error_response)?;
            require_current_provider_binding(
                decision.expected_provider_revision,
                decision.policy_digest,
                &account,
                &policy,
            )
        }
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_reserve_signed_envelope_and_route(
    expected_network: &iroha_data_model::NetworkId,
    transaction: &SignedTransaction,
    route: ReserveCommandRouteV1,
) -> Result<(), Response> {
    if transaction.network_id() != Some(expected_network) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "SoraFS reserve transaction network does not match this peer",
        ));
    }
    transaction.verify_signature().map_err(|_| {
        json_error(
            StatusCode::FORBIDDEN,
            "SoraFS reserve transaction signature or authority binding is invalid",
        )
    })?;

    if transaction.creation_time().is_zero()
        || transaction.time_to_live() != Some(RESERVE_TRANSACTION_TTL_V1)
        || transaction.nonce().is_some()
        || !transaction.metadata().is_empty()
        || transaction.fee_payment_intent().validate().is_err()
        || transaction.attachments().is_some()
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "SoraFS reserve transaction violates the exact V1 signed-envelope policy",
        ));
    }
    let canonical = norito::to_bytes(transaction).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "failed to encode canonical SoraFS reserve transaction",
        )
    })?;
    if canonical.len() > RESERVE_TRANSACTION_MAX_CANONICAL_BYTES_V1 {
        return Err(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SoraFS reserve transaction exceeds the canonical V1 byte bound",
        ));
    }
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(route_mismatch(route));
    };
    if instructions.len() != 1 {
        return Err(route_mismatch(route));
    }
    let matches_route = match route {
        ReserveCommandRouteV1::RequestMovement(expected_kind) => instructions[0]
            .as_any()
            .downcast_ref::<RequestSorafsReserveMovement>()
            .is_some_and(|request| request.kind == expected_kind),
        ReserveCommandRouteV1::DecideMovement(path_id) => instructions[0]
            .as_any()
            .downcast_ref::<DecideSorafsReserveMovement>()
            .is_some_and(|decision| decision.movement_id == path_id),
        ReserveCommandRouteV1::DrawCredit => instructions[0]
            .as_any()
            .downcast_ref::<DrawSorafsReserveCredit>()
            .is_some(),
        ReserveCommandRouteV1::RepayCredit => instructions[0]
            .as_any()
            .downcast_ref::<RepaySorafsReserveCredit>()
            .is_some(),
        ReserveCommandRouteV1::SubmitAppeal => instructions[0]
            .as_any()
            .downcast_ref::<SubmitSorafsReserveAppeal>()
            .is_some(),
        ReserveCommandRouteV1::DecideAppeal(path_id) => instructions[0]
            .as_any()
            .downcast_ref::<DecideSorafsReserveAppeal>()
            .is_some_and(|decision| decision.appeal_id == path_id),
    };
    if matches_route {
        Ok(())
    } else {
        Err(route_mismatch(route))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn one_instruction<T: 'static>(transaction: &SignedTransaction) -> Result<&T, Response> {
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "SoraFS reserve transaction must contain one native instruction",
        ));
    };
    instructions
        .first()
        .and_then(|instruction| instruction.as_any().downcast_ref::<T>())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "SoraFS reserve transaction instruction type changed after validation",
            )
        })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_current_provider_binding(
    expected_revision: u64,
    policy_digest: [u8; 32],
    account: &ReserveProviderAccountV1,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<(), Response> {
    if expected_revision != account.revision
        || policy_digest != policy.policy_digest
        || account.policy_digest != policy.policy_digest
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "SoraFS reserve transaction is stale against finalized provider or policy state",
        ));
    }
    Ok(())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_provider_authority(
    authority: &AccountId,
    account: &ReserveProviderAccountV1,
) -> Result<(), Response> {
    require_subject(authority, &account.terms.provider_account, "provider")
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_subject(
    actual: &AccountId,
    expected: &AccountId,
    authority_kind: &str,
) -> Result<(), Response> {
    if actual.subject_id() == expected.subject_id() {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::FORBIDDEN,
            format!("SoraFS reserve transaction authority is not the governed {authority_kind}"),
        ))
    }
}
fn route_mismatch(route: ReserveCommandRouteV1) -> Response {
    let expected = match route {
        ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp) => {
            "RequestSorafsReserveMovement::TopUp"
        }
        ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::Withdrawal) => {
            "RequestSorafsReserveMovement::Withdrawal"
        }
        ReserveCommandRouteV1::DecideMovement(_) => "DecideSorafsReserveMovement",
        ReserveCommandRouteV1::DrawCredit => "DrawSorafsReserveCredit",
        ReserveCommandRouteV1::RepayCredit => "RepaySorafsReserveCredit",
        ReserveCommandRouteV1::SubmitAppeal => "SubmitSorafsReserveAppeal",
        ReserveCommandRouteV1::DecideAppeal(_) => "DecideSorafsReserveAppeal",
    };
    json_error(
        StatusCode::BAD_REQUEST,
        format!("SoraFS reserve route requires exactly one `{expected}` native instruction"),
    )
}
pub async fn handle_get_sorafs_reserve_policy(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "policy", async move {
        let account = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReserveAnchorQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let cursor = match require_expected_cursor(&view, query.expected_finalized_cursor()) {
            Ok(cursor) => cursor,
            Err(response) => return response,
        };
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&account, &policy) {
            return response;
        }
        anchored_record_response(cursor, "policy", &policy)
    })
    .await
}
pub async fn handle_get_sorafs_reserve_providers(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "providers", async move {
        let account = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReservePageQueryV1::parse(raw_query.as_deref(), "after_provider_id_hex") {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&account, &policy) {
            return response;
        }
        match FindSorafsReserveProviders::new(
            query.expected_finalized_cursor(),
            query.after_id.map(ProviderId::new),
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => crate::JsonBody(page).into_response(),
            Err(error) => reserve_query_error_response(error),
        }
    })
    .await
}
pub async fn handle_get_sorafs_reserve_provider(
    State(state): State<SharedAppState>,
    Path(provider_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "provider", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let provider_id = match parse_nonzero_hex(&provider_id_hex, "provider_id_hex") {
            Ok(provider_id) => ProviderId::new(provider_id),
            Err(error) => return json_error(StatusCode::BAD_REQUEST, error),
        };
        let query = match ReserveAnchorQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let cursor = match require_expected_cursor(&view, query.expected_finalized_cursor()) {
            Ok(cursor) => cursor,
            Err(response) => return response,
        };
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        let provider = match FindSorafsReserveProviderById::new(provider_id).execute(&view) {
            Ok(provider) => provider,
            Err(error) => return reserve_query_error_response(error),
        };
        if caller.subject_id() != provider.terms.provider_account.subject_id()
            && require_reserve_operator(&caller, &policy).is_err()
        {
            return json_error(
                StatusCode::FORBIDDEN,
                "SoraFS reserve provider state is visible only to its provider or governed services",
            );
        }
        anchored_record_response(cursor, "provider", &provider)
    })
    .await
}
pub async fn handle_get_sorafs_reserve_movements(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "movements", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReservePageQueryV1::parse(raw_query.as_deref(), "after_movement_id_hex") {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&caller, &policy) {
            return response;
        }
        match FindSorafsReserveMovements::new(
            query.expected_finalized_cursor(),
            query.after_id,
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => crate::JsonBody(page).into_response(),
            Err(error) => reserve_query_error_response(error),
        }
    })
    .await
}
pub async fn handle_get_sorafs_reserve_movement(
    State(state): State<SharedAppState>,
    Path(movement_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "movement", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let movement_id = match parse_nonzero_hex(&movement_id_hex, "movement_id_hex") {
            Ok(movement_id) => movement_id,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, error),
        };
        let query = match ReserveAnchorQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let cursor = match require_expected_cursor(&view, query.expected_finalized_cursor()) {
            Ok(cursor) => cursor,
            Err(response) => return response,
        };
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        let movement = match FindSorafsReserveMovementById::new(movement_id).execute(&view) {
            Ok(movement) => movement,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) =
            require_provider_or_operator_for_id(&view, &caller, movement.provider_id, &policy)
        {
            return response;
        }
        anchored_record_response(cursor, "movement", &movement)
    })
    .await
}
pub async fn handle_get_sorafs_reserve_appeals(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "appeals", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReservePageQueryV1::parse(raw_query.as_deref(), "after_appeal_id_hex") {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&caller, &policy) {
            return response;
        }
        match FindSorafsReserveAppeals::new(
            query.expected_finalized_cursor(),
            query.after_id,
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => crate::JsonBody(page).into_response(),
            Err(error) => reserve_query_error_response(error),
        }
    })
    .await
}
pub async fn handle_get_sorafs_reserve_appeal(
    State(state): State<SharedAppState>,
    Path(appeal_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "appeal_detail", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let appeal_id = match parse_nonzero_hex(&appeal_id_hex, "appeal_id_hex") {
            Ok(appeal_id) => appeal_id,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, error),
        };
        let query = match ReserveAnchorQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let cursor = match require_expected_cursor(&view, query.expected_finalized_cursor()) {
            Ok(cursor) => cursor,
            Err(response) => return response,
        };
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        let appeal = match FindSorafsReserveAppealById::new(appeal_id).execute(&view) {
            Ok(appeal) => appeal,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) =
            require_provider_or_operator_for_id(&view, &caller, appeal.provider_id, &policy)
        {
            return response;
        }
        anchored_record_response(cursor, "appeal", &appeal)
    })
    .await
}
pub async fn handle_get_sorafs_reserve_events(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "events", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReserveEventQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&caller, &policy) {
            return response;
        }
        match FindSorafsReserveEvents::new(
            query.expected_finalized_cursor(),
            query.after(),
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => crate::JsonBody(page).into_response(),
            Err(error) => reserve_query_error_response(error),
        }
    })
    .await
}
pub async fn handle_get_sorafs_reserve_events_stream(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "events_stream", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReserveEventQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&caller, &policy) {
            return response;
        }
        let initial = match FindSorafsReserveEvents::new(
            query.expected_finalized_cursor(),
            query.after(),
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => page,
            Err(error) => return reserve_query_error_response(error),
        };
        drop(view);
        Sse::new(reserve_event_stream(
            state,
            caller,
            initial,
            query.after(),
            query.limit(),
        ))
        .into_response()
    })
    .await
}
pub async fn handle_get_sorafs_reserve_events_ws(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    preauth_guard: Option<Extension<crate::PreAuthGuardHandoff>>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    ws: WebSocketUpgrade,
) -> Response {
    let telemetry = state.telemetry.clone();
    observe_reserve_api_response(telemetry, "events_ws", async move {
        let caller = match authenticate_reserve_read(&state, &headers, &method, &uri) {
            Ok(account) => account,
            Err(response) => return response,
        };
        let query = match ReserveEventQueryV1::parse(raw_query.as_deref()) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let view = state.state.query_view();
        let policy = match FindSorafsReservePolicy::new().execute(&view) {
            Ok(policy) => policy,
            Err(error) => return reserve_query_error_response(error),
        };
        if let Err(response) = require_reserve_operator(&caller, &policy) {
            return response;
        }
        let initial = match FindSorafsReserveEvents::new(
            query.expected_finalized_cursor(),
            query.after(),
            query.limit(),
        )
        .execute(&view)
        {
            Ok(page) => page,
            Err(error) => return reserve_query_error_response(error),
        };
        drop(view);
        let preauth_guard = crate::take_preauth_upgrade_guard(preauth_guard);
        let shutdown = state.shutdown_signal.clone();
        ws.on_upgrade(move |socket| async move {
            let _ = crate::panic_recovery::catch_async_recoverable(async move {
                let _preauth_guard = preauth_guard;
                let stream = reserve_event_websocket(
                    socket,
                    state,
                    caller,
                    initial,
                    query.after(),
                    query.limit(),
                );
                let result = tokio::select! {
                    () = shutdown.receive() => return,
                    result = stream => result,
                };
                if let Err(error) = result {
                    debug!(%error, "SoraFS reserve finalized-event WebSocket closed");
                }
            })
            .await;
        })
        .into_response()
    })
    .await
}
fn query_reserve_events(
    state: &SharedAppState,
    caller: &AccountId,
    expected: Option<ReserveFinalizedCursorV1>,
    after: Option<ReserveFinalizedEventCursorV1>,
    limit: u32,
) -> Result<ReserveFinalizedEventPageV1, String> {
    let view = state.state.query_view();
    let policy = FindSorafsReservePolicy::new()
        .execute(&view)
        .map_err(|error| reserve_query_public_message(&error))?;
    if !is_reserve_operator(caller, &policy) {
        return Err("SoraFS reserve stream authorization is no longer valid".to_owned());
    }
    FindSorafsReserveEvents::new(expected, after, limit)
        .execute(&view)
        .map_err(|error| reserve_query_public_message(&error))
}
fn revalidate_reserve_stream_operator(
    state: &SharedAppState,
    caller: &AccountId,
) -> Result<(), String> {
    let view = state.state.query_view();
    let policy = FindSorafsReservePolicy::new()
        .execute(&view)
        .map_err(|error| reserve_query_public_message(&error))?;
    if is_reserve_operator(caller, &policy) {
        Ok(())
    } else {
        Err("SoraFS reserve stream authorization is no longer valid".to_owned())
    }
}
fn reserve_event_stream(
    state: SharedAppState,
    caller: AccountId,
    initial: ReserveFinalizedEventPageV1,
    initial_after: Option<ReserveFinalizedEventCursorV1>,
    limit: u32,
) -> impl futures::Stream<Item = Result<SseEvent, Infallible>> {
    reserve_event_frame_stream(state, caller, initial, initial_after, limit).map(|frame| {
        Ok(match frame {
            ReserveEventStreamFrameV1::Event(event) => reserve_sse_event(&event),
            ReserveEventStreamFrameV1::TerminalError(error) => {
                SseEvent::default().event("error").data(error)
            }
        })
    })
}
#[derive(Debug, PartialEq, Eq)]
enum ReserveEventStreamFrameV1 {
    Event(ReserveFinalizedEventV1),
    TerminalError(String),
}
fn reserve_event_frame_stream(
    state: SharedAppState,
    caller: AccountId,
    initial: ReserveFinalizedEventPageV1,
    initial_after: Option<ReserveFinalizedEventCursorV1>,
    limit: u32,
) -> impl futures::Stream<Item = ReserveEventStreamFrameV1> {
    struct PollState {
        state: SharedAppState,
        caller: AccountId,
        pending: VecDeque<ReserveFinalizedEventV1>,
        after: Option<ReserveFinalizedEventCursorV1>,
        limit: u32,
        terminal: bool,
    }
    let after = reserve_event_resume_cursor(&initial.events, initial_after);
    stream::unfold(
        PollState {
            state,
            caller,
            pending: initial.events.into_iter().collect(),
            after,
            limit,
            terminal: false,
        },
        |mut poll| async move {
            loop {
                if let Some(event) = poll.pending.pop_front() {
                    if let Err(error) =
                        revalidate_reserve_stream_operator(&poll.state, &poll.caller)
                    {
                        poll.terminal = true;
                        return Some((ReserveEventStreamFrameV1::TerminalError(error), poll));
                    }
                    return Some((ReserveEventStreamFrameV1::Event(event), poll));
                }
                if poll.terminal {
                    return None;
                }
                tokio::time::sleep(RESERVE_EVENT_POLL_INTERVAL_V1).await;
                match query_reserve_events(&poll.state, &poll.caller, None, poll.after, poll.limit)
                {
                    Ok(page) => {
                        if let Some(after) = page
                            .events
                            .last()
                            .map(iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1::cursor)
                        {
                            poll.after = Some(after);
                        }
                        poll.pending.extend(page.events);
                    }
                    Err(message) => {
                        poll.terminal = true;
                        return Some((ReserveEventStreamFrameV1::TerminalError(message), poll));
                    }
                }
            }
        },
    )
}
async fn reserve_event_websocket(
    socket: WebSocket,
    state: SharedAppState,
    caller: AccountId,
    initial: ReserveFinalizedEventPageV1,
    initial_after: Option<ReserveFinalizedEventCursorV1>,
    limit: u32,
) -> Result<(), String> {
    let (sender, receiver) = socket.split();
    reserve_event_websocket_io(
        sender,
        receiver,
        state,
        caller,
        initial,
        initial_after,
        limit,
    )
    .await
}
async fn reserve_event_websocket_io<S, R, SendError, ReceiveError>(
    mut sender: S,
    mut receiver: R,
    state: SharedAppState,
    caller: AccountId,
    initial: ReserveFinalizedEventPageV1,
    initial_after: Option<ReserveFinalizedEventCursorV1>,
    limit: u32,
) -> Result<(), String>
where
    S: futures::Sink<WsMessage, Error = SendError> + Unpin,
    R: futures::Stream<Item = Result<WsMessage, ReceiveError>> + Unpin,
    SendError: std::fmt::Display,
    ReceiveError: std::fmt::Display,
{
    let mut after = reserve_event_resume_cursor(&initial.events, initial_after);
    for event in initial.events {
        revalidate_reserve_stream_operator(&state, &caller)?;
        sender
            .send(WsMessage::Text(reserve_event_json(&event)?.into()))
            .await
            .map_err(|error| error.to_string())?;
    }
    loop {
        tokio::select! {
            inbound = receiver.next() => {
                match inbound {
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(()),
                    Some(Err(error)) => return Err(error.to_string()),
                    Some(Ok(_)) => {}
                }
            }
            () = tokio::time::sleep(RESERVE_EVENT_POLL_INTERVAL_V1) => {
                let page = query_reserve_events(&state, &caller, None, after, limit)?;
                if let Some(next) = page.events.last().map(iroha_data_model::sorafs::reserve::ReserveFinalizedEventV1::cursor) {
                    after = Some(next);
                }
                for event in page.events {
                    revalidate_reserve_stream_operator(&state, &caller)?;
                    sender
                        .send(WsMessage::Text(reserve_event_json(&event)?.into()))
                        .await
                        .map_err(|error| error.to_string())?;
                }
            }
        }
    }
}
fn reserve_sse_event(event: &ReserveFinalizedEventV1) -> SseEvent {
    match reserve_event_json(event) {
        Ok(json) => SseEvent::default()
            .event("reserve_finalized")
            .id(event.sequence.to_string())
            .data(json),
        Err(error) => SseEvent::default().event("error").data(error),
    }
}
fn reserve_event_json(event: &ReserveFinalizedEventV1) -> Result<String, String> {
    json::to_json(event)
        .map_err(|error| format!("failed to encode finalized SoraFS reserve event: {error}"))
}
fn reserve_event_resume_cursor(
    events: &[ReserveFinalizedEventV1],
    initial_after: Option<ReserveFinalizedEventCursorV1>,
) -> Option<ReserveFinalizedEventCursorV1> {
    events
        .last()
        .map(ReserveFinalizedEventV1::cursor)
        .or(initial_after)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn authenticate_reserve_read(
    state: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<AccountId, Response> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(state) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error.into_response());
            }
        };

    match crate::app_auth::verify_canonical_network_request(
        &state.state,
        state.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts {
            method,
            uri,
            body: &[],
        },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => {
            if !state.sorafs_node.is_enabled() {
                return Err(feature_disabled());
            }
            Ok(verified.account)
        }
        Ok(None) => Err(json_error(
            StatusCode::UNAUTHORIZED,
            "SoraFS reserve reads require X-Iroha canonical request authentication",
        )),
        Err(error) => {
            warn!(
                ?error,
                "SoraFS reserve canonical read authentication rejected"
            );
            Err(json_error(
                StatusCode::UNAUTHORIZED,
                "invalid SoraFS reserve read authentication",
            ))
        }
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_reserve_operator(
    caller: &AccountId,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<(), Response> {
    if is_reserve_operator(caller, policy) {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::FORBIDDEN,
            "SoraFS reserve collection reads require a governed reserve service authority",
        ))
    }
}
fn is_reserve_operator(caller: &AccountId, policy: &ReserveAuthorityPolicyRecordV1) -> bool {
    caller.subject_id() == policy.policy.operations_authority.subject_id()
        || caller.subject_id() == policy.policy.decision_authority.subject_id()
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_provider_or_operator_for_id(
    view: &impl StateReadOnly,
    caller: &AccountId,
    provider_id: ProviderId,
    policy: &ReserveAuthorityPolicyRecordV1,
) -> Result<(), Response> {
    if require_reserve_operator(caller, policy).is_ok() {
        return Ok(());
    }
    let provider = FindSorafsReserveProviderById::new(provider_id)
        .execute(view)
        .map_err(reserve_query_error_response)?;
    if caller.subject_id() == provider.terms.provider_account.subject_id() {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::FORBIDDEN,
            "SoraFS reserve record is visible only to its provider or governed services",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_expected_cursor(
    view: &impl StateReadOnly,
    expected: Option<ReserveFinalizedCursorV1>,
) -> Result<ReserveFinalizedCursorV1, Response> {
    let actual =
        super::reserve_runtime::reserve_finalized_cursor_from_view(view).ok_or_else(|| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authoritative finalized SoraFS reserve state is unavailable",
            )
        })?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(json_error(
            StatusCode::CONFLICT,
            "SoraFS reserve finalized cursor is stale; restart from the latest committed anchor",
        ));
    }
    Ok(actual)
}
fn anchored_record_response<T: norito::json::JsonSerialize>(
    cursor: ReserveFinalizedCursorV1,
    field: &str,
    record: &T,
) -> Response {
    let cursor = match json::to_value(&cursor) {
        Ok(cursor) => cursor,
        Err(error) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to encode finalized SoraFS reserve cursor: {error}"),
            );
        }
    };
    let record = match json::to_value(record) {
        Ok(record) => record,
        Err(error) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to encode finalized SoraFS reserve record: {error}"),
            );
        }
    };
    JsonBody(crate::json_object(vec![
        crate::json_entry("schema", "sorafs.reserve.finalized_record.v1"),
        crate::json_entry("finalized_cursor", cursor),
        crate::json_entry(field, record),
    ]))
    .into_response()
}
fn reserve_query_error_response(error: QueryExecutionFail) -> Response {
    let status = match error {
        QueryExecutionFail::Find(
            FindError::SorafsReservePolicy
            | FindError::SorafsReserveProvider(_)
            | FindError::SorafsReserveMovement(_)
            | FindError::SorafsReserveAppeal(_),
        ) => StatusCode::NOT_FOUND,
        QueryExecutionFail::Expired | QueryExecutionFail::CursorMismatch => StatusCode::CONFLICT,
        QueryExecutionFail::Conversion(_)
        | QueryExecutionFail::FetchSizeTooBig
        | QueryExecutionFail::InvalidSingularParameters => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    if status.is_server_error() {
        warn!(
            ?error,
            "authoritative finalized SoraFS reserve query failed"
        );
    }
    json_error(status, reserve_query_public_message(&error))
}
fn reserve_query_public_message(error: &QueryExecutionFail) -> String {
    match error {
        QueryExecutionFail::Find(
            FindError::SorafsReservePolicy
            | FindError::SorafsReserveProvider(_)
            | FindError::SorafsReserveMovement(_)
            | FindError::SorafsReserveAppeal(_),
        ) => "authoritative SoraFS reserve record was not found".to_owned(),
        QueryExecutionFail::Expired | QueryExecutionFail::CursorMismatch => {
            "SoraFS reserve finalized cursor is stale; restart from the latest committed anchor"
                .to_owned()
        }
        QueryExecutionFail::Conversion(_)
        | QueryExecutionFail::FetchSizeTooBig
        | QueryExecutionFail::InvalidSingularParameters => {
            "invalid finalized SoraFS reserve query".to_owned()
        }
        _ => "authoritative finalized SoraFS reserve state is unavailable".to_owned(),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn walk_query(
    raw: Option<&str>,
    mut visit: impl FnMut(&str, &str) -> Result<(), String>,
) -> Result<(), Response> {
    let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
        return Ok(());
    };
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "empty SoraFS reserve query component",
            ));
        }
        let (raw_key, raw_value) = pair.split_once('=').ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "SoraFS reserve query component must contain `=`",
            )
        })?;
        let key = urlencoding::decode(raw_key)
            .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid reserve query key"))?;
        let value = urlencoding::decode(raw_value)
            .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid reserve query value"))?;
        visit(key.as_ref(), value.as_ref())
            .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    }
    Ok(())
}
fn parse_unique_u64(target: &mut Option<u64>, name: &str, raw: &str) -> Result<(), String> {
    if target.is_some() || raw.is_empty() {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must appear once with a value"
        ));
    }
    let value = raw.parse::<u64>().map_err(|_| {
        format!("SoraFS reserve query parameter `{name}` must be an unsigned integer")
    })?;
    if value.to_string() != raw {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must use canonical decimal encoding"
        ));
    }
    *target = Some(value);
    Ok(())
}
fn parse_unique_u32(target: &mut Option<u32>, name: &str, raw: &str) -> Result<(), String> {
    if target.is_some() || raw.is_empty() {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must appear once with a value"
        ));
    }
    let value = raw.parse::<u32>().map_err(|_| {
        format!("SoraFS reserve query parameter `{name}` must be an unsigned integer")
    })?;
    if value.to_string() != raw {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must use canonical decimal encoding"
        ));
    }
    *target = Some(value);
    Ok(())
}
fn parse_unique_hex(
    target: &mut Option<[u8; 32]>,
    name: &str,
    raw: &str,
    nonzero: bool,
) -> Result<(), String> {
    if target.is_some() || raw.is_empty() {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must appear once with a value"
        ));
    }
    let value = parse_hex(raw, name)?;
    if nonzero && value == [0; 32] {
        return Err(format!(
            "SoraFS reserve query parameter `{name}` must not be zero"
        ));
    }
    *target = Some(value);
    Ok(())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_finalized_cursor_pair(
    height: Option<u64>,
    block_hash: Option<[u8; 32]>,
) -> Result<(), Response> {
    if height.is_some() != block_hash.is_some() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "complete finalized SoraFS reserve cursor is required",
        ));
    }
    if height == Some(0) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "finalized SoraFS reserve cursor height must be non-zero",
        ));
    }
    Ok(())
}
fn parse_nonzero_hex(raw: &str, name: &str) -> Result<[u8; 32], String> {
    let value = parse_hex(raw, name)?;
    if value == [0; 32] {
        return Err(format!("SoraFS reserve `{name}` must not be zero"));
    }
    Ok(value)
}
fn parse_hex(raw: &str, name: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64
        || raw
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "SoraFS reserve `{name}` must be 64 lowercase hexadecimal characters"
        ));
    }
    let bytes = hex::decode(raw)
        .map_err(|_| format!("SoraFS reserve `{name}` is not valid hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| format!("SoraFS reserve `{name}` must decode to 32 bytes"))
}
fn feature_disabled() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "SoraFS reserve API is not enabled on this node",
    )
}
fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        JsonBody(crate::json_object(vec![
            crate::json_entry("error", status.canonical_reason().unwrap_or("error")),
            crate::json_entry("message", message.into()),
        ])),
    )
        .into_response()
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures::{Sink, channel::mpsc, task::AtomicWaker};
    use iroha_core::state::World;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId, Registrable,
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
        block::BlockHeader,
        domain::Domain,
        isi::{
            InstructionBox,
            sorafs::{RequestSorafsReserveMovement, SetSorafsReservePolicy},
        },
        permission::{Permission, Permissions},
        sorafs::{
            capacity::ProviderId,
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1,
                ReserveMovementKindV1, ReservePolicyV1,
            },
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;
    use sorafs_manifest::deal::XorQuantity;
    use std::{
        num::NonZeroU32,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };
    #[test]
    fn reserve_auth_rejects_foreign_exact_network_before_feature_disclosure() {
        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let method = Method::GET;
        let uri: Uri = "/v1/sorafs/reserve/policy"
            .parse()
            .expect("reserve policy URI");
        let (state, headers) = crate::tests_runtime_handlers::foreign_network_signed_app_fixture(
            &method,
            &uri,
            &[],
            0xD4,
            0xE4,
        );
        let response = authenticate_reserve_read(&state, &headers, &method, &uri)
            .expect_err("foreign-network reserve authorization must fail closed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    fn signed_transaction(
        network_id: &NetworkId,
        instruction: InstructionBox,
        mutate: impl FnOnce(TransactionBuilder) -> TransactionBuilder,
    ) -> SignedTransaction {
        signed_transactions(network_id, vec![instruction], mutate)
    }
    fn signed_transactions(
        network_id: &NetworkId,
        instructions: Vec<InstructionBox>,
        mutate: impl FnOnce(TransactionBuilder) -> TransactionBuilder,
    ) -> SignedTransaction {
        let key_pair =
            KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::Ed25519).expect("test key");
        let authority = AccountId::new(key_pair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            *network_id,
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_ttl(RESERVE_TRANSACTION_TTL_V1);
        mutate(builder)
            .with_instructions(instructions)
            .sign(key_pair.private_key())
    }
    fn reserve_test_network_id(marker: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([marker; Hash::LENGTH]),
        ))
    }
    fn movement(kind: ReserveMovementKindV1) -> InstructionBox {
        RequestSorafsReserveMovement::new(
            [0x11; 32],
            ProviderId::new([0x22; 32]),
            kind,
            "1".parse::<XorQuantity>().expect("quantity"),
            7,
            [0x33; 32],
        )
        .into()
    }
    fn reserve_test_account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("reserve stream account key");
        AccountId::new(key_pair.public_key().clone())
    }
    fn reserve_test_asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("reserve", "universal").expect("reserve domain"),
            "xor".parse().expect("reserve asset name"),
        )
    }
    fn reserve_stream_test_app(
        governance: &AccountId,
        custody: &AccountId,
        treasury: &AccountId,
        caller: &AccountId,
        replacement: &AccountId,
    ) -> (
        SharedAppState,
        iroha_core::sumeragi::test_chain::CertifiedTestChain,
    ) {
        let definition_id = reserve_test_asset_definition();
        let domain =
            Domain::new(DomainId::try_new("reserve", "universal").expect("reserve domain"))
                .build(governance);
        let definition = AssetDefinition::numeric(
            definition_id,
            "XOR".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(governance);
        let mut world = World::with_assets(
            [domain],
            [
                Account::new(governance.clone()).build(governance),
                Account::new(custody.clone()).build(governance),
                Account::new(treasury.clone()).build(governance),
                Account::new(caller.clone()).build(governance),
                Account::new(replacement.clone()).build(governance),
            ],
            [definition],
            [],
            [],
        );
        let mut permissions = Permissions::new();
        permissions.insert(Permission::new(
            "CanSetSorafsReservePolicy".to_owned(),
            Json::new(()),
        ));
        world
            .account_permissions_mut_for_testing()
            .insert(governance.clone(), permissions);
        let config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("reserve original genesis");
        let mut app =
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(World::default());
        let inner = Arc::get_mut(&mut app).expect("unique reserve fixture app");
        inner.chain_id = Arc::new(chain.state().chain_id_ref().clone());
        inner.state = Arc::clone(chain.state());
        inner.kura = Arc::clone(chain.kura());
        (app, chain)
    }
    fn reserve_stream_policy(
        revision: u64,
        predecessor_policy_digest: Option<[u8; 32]>,
        custody: &AccountId,
        treasury: &AccountId,
        operator: &AccountId,
    ) -> ReserveAuthorityPolicyV1 {
        ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision,
            predecessor_policy_digest,
            economics: ReservePolicyV1::default(),
            asset_definition: reserve_test_asset_definition(),
            custody_account: custody.clone(),
            treasury_account: treasury.clone(),
            operations_authority: operator.clone(),
            decision_authority: operator.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: "1".parse::<XorQuantity>().expect("reserve debt cap"),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        }
    }
    fn commit_reserve_stream_policies(
        chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
        governance: &AccountId,
        policies: impl IntoIterator<Item = ReserveAuthorityPolicyV1>,
        now_unix: u64,
    ) {
        let key = KeyPair::try_from_seed(vec![0xB1; 32], Algorithm::Ed25519)
            .expect("reserve governance key");
        assert_eq!(governance, &AccountId::new(key.public_key().clone()));
        let time_ms = now_unix.checked_mul(1_000).expect("reserve test time");
        let transaction = chain.sign(
            &key,
            policies
                .into_iter()
                .map(|policy| SetSorafsReservePolicy::new(policy).into()),
            time_ms - 1,
        );
        assert_eq!(
            chain.commit_at(time_ms, vec![transaction]),
            [true],
            "original signed reserve policy instructions execute and finalize"
        );
    }
    struct FirstFrameFlushGateSink {
        output: mpsc::UnboundedSender<WsMessage>,
        release_first_flush: Arc<AtomicBool>,
        flush_waker: Arc<AtomicWaker>,
        sent: usize,
        first_flush_pending: bool,
    }
    impl Sink<WsMessage> for FirstFrameFlushGateSink {
        type Error = String;
        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
            let this = self.get_mut();
            this.output
                .unbounded_send(item)
                .map_err(|error| error.to_string())?;
            this.sent = this.sent.checked_add(1).expect("test frame count");
            if this.sent == 1 {
                this.first_flush_pending = true;
            }
            Ok(())
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let this = self.get_mut();
            if this.first_flush_pending && !this.release_first_flush.load(Ordering::Acquire) {
                this.flush_waker.register(context.waker());
                if !this.release_first_flush.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
            }
            this.first_flush_pending = false;
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(context)
        }
    }
    #[test]
    fn signed_boundary_rejects_wrong_route_network_and_noncanonical_envelope_fields() {
        let network_id = reserve_test_network_id(0xA1);
        let withdrawal = signed_transaction(
            &network_id,
            movement(ReserveMovementKindV1::Withdrawal),
            |builder| builder,
        );
        assert_eq!(
            validate_reserve_signed_envelope_and_route(
                &network_id,
                &withdrawal,
                ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp),
            )
            .expect_err("wrong route")
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            validate_reserve_signed_envelope_and_route(
                &reserve_test_network_id(0xA2),
                &withdrawal,
                ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::Withdrawal),
            )
            .expect_err("wrong network")
            .status(),
            StatusCode::BAD_REQUEST
        );
        let nonce = signed_transaction(
            &network_id,
            movement(ReserveMovementKindV1::TopUp),
            |mut builder| {
                builder.set_nonce(NonZeroU32::new(1).expect("nonce"));
                builder
            },
        );
        assert_eq!(
            validate_reserve_signed_envelope_and_route(
                &network_id,
                &nonce,
                ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp),
            )
            .expect_err("nonce")
            .status(),
            StatusCode::BAD_REQUEST
        );
        let mut forbidden_metadata = Metadata::default();
        forbidden_metadata.insert("forbidden".parse().expect("metadata key"), true);
        let metadata = signed_transaction(
            &network_id,
            movement(ReserveMovementKindV1::TopUp),
            |builder| builder.with_metadata(forbidden_metadata),
        );
        assert_eq!(
            validate_reserve_signed_envelope_and_route(
                &network_id,
                &metadata,
                ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp),
            )
            .expect_err("metadata")
            .status(),
            StatusCode::BAD_REQUEST
        );
        let multiple = signed_transactions(
            &network_id,
            vec![
                movement(ReserveMovementKindV1::TopUp),
                movement(ReserveMovementKindV1::TopUp),
            ],
            |builder| builder,
        );
        assert_eq!(
            validate_reserve_signed_envelope_and_route(
                &network_id,
                &multiple,
                ReserveCommandRouteV1::RequestMovement(ReserveMovementKindV1::TopUp),
            )
            .expect_err("multiple instructions")
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn finalized_query_parser_rejects_duplicates_partial_cursors_and_noncanonical_hex() {
        assert!(ReserveAnchorQueryV1::parse(Some("limit=1")).is_err());
        assert!(
            ReservePageQueryV1::parse(Some("limit=1&limit=2"), "after_provider_id_hex").is_err()
        );
        assert!(
            ReservePageQueryV1::parse(Some("expected_finalized_height=1"), "after_provider_id_hex")
                .is_err()
        );
        assert!(
            ReservePageQueryV1::parse(
                Some(
                    "expected_finalized_height=1&expected_finalized_block_hash_hex=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                ),
                "after_provider_id_hex"
            )
            .is_err()
        );
        assert!(ReserveEventQueryV1::parse(Some("after_sequence=1")).is_err());
        assert!(
            ReserveEventQueryV1::parse(Some(
                "after_sequence=1&after_block_height=1&after_block_hash_hex=0000000000000000000000000000000000000000000000000000000000000000&after_event_index=0"
            ))
            .is_err()
        );
    }
    #[test]
    fn empty_initial_event_page_preserves_exclusive_resume_cursor() {
        let after = ReserveFinalizedEventCursorV1 {
            sequence: 9,
            block_height: 7,
            block_hash: [0xA9; 32],
            event_index: 2,
        };
        assert_eq!(reserve_event_resume_cursor(&[], Some(after)), Some(after));
    }
    #[tokio::test]
    async fn policy_rotation_revokes_buffered_and_future_sse_and_websocket_events() {
        const AUTHORIZATION_REVOKED: &str =
            "SoraFS reserve stream authorization is no longer valid";
        let governance = reserve_test_account(0xB1);
        let custody = reserve_test_account(0xB2);
        let treasury = reserve_test_account(0xB3);
        let caller = reserve_test_account(0xB4);
        let replacement = reserve_test_account(0xB5);
        let (state, mut chain) =
            reserve_stream_test_app(&governance, &custody, &treasury, &caller, &replacement);
        let first = reserve_stream_policy(1, None, &custody, &treasury, &caller);
        let first_digest = first.digest().expect("first reserve policy digest");
        let second = reserve_stream_policy(2, Some(first_digest), &custody, &treasury, &caller);
        let second_digest = second.digest().expect("second reserve policy digest");
        commit_reserve_stream_policies(&mut chain, &governance, [first, second], 10);
        let buffered = query_reserve_events(&state, &caller, None, None, 100)
            .expect("authorized initial reserve page");
        assert_eq!(buffered.events.len(), 2, "two frames must be buffered");
        let buffered_after = buffered
            .events
            .last()
            .map(ReserveFinalizedEventV1::cursor)
            .expect("buffered cursor");
        let future = query_reserve_events(&state, &caller, None, Some(buffered_after), 100)
            .expect("authorized empty continuation page");
        assert!(future.events.is_empty());
        let buffered_sse = reserve_event_frame_stream(
            Arc::clone(&state),
            caller.clone(),
            buffered.clone(),
            None,
            100,
        );
        futures::pin_mut!(buffered_sse);
        assert!(matches!(
            buffered_sse.next().await,
            Some(ReserveEventStreamFrameV1::Event(event)) if event.sequence == 1
        ));
        let future_sse = reserve_event_frame_stream(
            Arc::clone(&state),
            caller.clone(),
            future.clone(),
            Some(buffered_after),
            100,
        );
        futures::pin_mut!(future_sse);
        let (buffered_ws_output, mut buffered_ws_frames) = mpsc::unbounded();
        let release_first_flush = Arc::new(AtomicBool::new(false));
        let flush_waker = Arc::new(AtomicWaker::new());
        let buffered_ws = tokio::spawn(reserve_event_websocket_io(
            FirstFrameFlushGateSink {
                output: buffered_ws_output,
                release_first_flush: Arc::clone(&release_first_flush),
                flush_waker: Arc::clone(&flush_waker),
                sent: 0,
                first_flush_pending: false,
            },
            stream::pending::<Result<WsMessage, String>>(),
            Arc::clone(&state),
            caller.clone(),
            buffered,
            None,
            100,
        ));
        let first_ws_frame =
            tokio::time::timeout(Duration::from_secs(1), buffered_ws_frames.next())
                .await
                .expect("first buffered WebSocket frame timeout")
                .expect("first buffered WebSocket frame");
        assert!(matches!(first_ws_frame, WsMessage::Text(_)));
        let (future_ws_output, mut future_ws_frames) = mpsc::unbounded();
        let future_ws = tokio::spawn(reserve_event_websocket_io(
            future_ws_output,
            stream::pending::<Result<WsMessage, String>>(),
            Arc::clone(&state),
            caller.clone(),
            future,
            Some(buffered_after),
            100,
        ));
        tokio::task::yield_now().await;
        let third =
            reserve_stream_policy(3, Some(second_digest), &custody, &treasury, &replacement);
        commit_reserve_stream_policies(&mut chain, &governance, [third], 11);
        let replacement_page =
            query_reserve_events(&state, &replacement, None, Some(buffered_after), 100)
                .expect("replacement authority sees finalized post-rotation event");
        assert_eq!(
            replacement_page
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3],
            "the policy rotation event must exist as a future frame"
        );
        assert_eq!(
            buffered_sse.next().await,
            Some(ReserveEventStreamFrameV1::TerminalError(
                AUTHORIZATION_REVOKED.to_owned()
            )),
            "SSE must suppress its second already-buffered event"
        );
        assert!(buffered_sse.next().await.is_none());
        release_first_flush.store(true, Ordering::Release);
        flush_waker.wake();
        let buffered_ws_error = tokio::time::timeout(Duration::from_secs(1), buffered_ws)
            .await
            .expect("buffered WebSocket revocation timeout")
            .expect("buffered WebSocket task")
            .expect_err("buffered WebSocket must close after revocation");
        assert_eq!(buffered_ws_error, AUTHORIZATION_REVOKED);
        assert!(
            buffered_ws_frames.next().await.is_none(),
            "WebSocket must suppress its second already-buffered event"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), future_sse.next())
                .await
                .expect("future SSE revocation timeout"),
            Some(ReserveEventStreamFrameV1::TerminalError(
                AUTHORIZATION_REVOKED.to_owned()
            )),
            "SSE must suppress events finalized after revocation"
        );
        assert!(future_sse.next().await.is_none());
        let future_ws_error = tokio::time::timeout(Duration::from_secs(2), future_ws)
            .await
            .expect("future WebSocket revocation timeout")
            .expect("future WebSocket task")
            .expect_err("future WebSocket must close after revocation");
        assert_eq!(future_ws_error, AUTHORIZATION_REVOKED);
        assert!(
            future_ws_frames.next().await.is_none(),
            "WebSocket must suppress events finalized after revocation"
        );
    }
}
