//! Authenticated V1 control surface for the durable gateway-compliance controller.
//!
//! The HTTP boundary owns no feed, ACME, or signing credentials. Every request is bound to the
//! exact method, URI, and canonical JSON bytes through Torii's canonical account-signature
//! authentication, and the caller must hold the governed `sorafs_gateway_compliance_operator` role.
//! Catalog, gateway acknowledgement, and rollback signatures are verified again by the controller
//! before any durable transition commits.

use super::gateway::{
    GatewayComplianceCheckpointV1, GatewayComplianceController, GatewayComplianceError,
    GatewayComplianceHistoryRecordV1, GatewayComplianceMutationBindingV1,
    GatewayComplianceMutationResultV1,
};
use crate::{JsonBody, SharedAppState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use iroha_core::state::WorldReadOnly;
use iroha_data_model::role::RoleId;
use iroha_logger::warn;
use iroha_torii_shared::sorafs_gateway_compliance_api::{
    GATEWAY_COMPLIANCE_ACTION_SCHEMA_V1, GATEWAY_COMPLIANCE_ERROR_SCHEMA_V1,
    GATEWAY_COMPLIANCE_IDEMPOTENCY_KEY_HEADER as IDEMPOTENCY_KEY_HEADER,
    GATEWAY_COMPLIANCE_STATUS_SCHEMA_V1, GatewayComplianceActionResponseV1,
    GatewayComplianceCatalogStatusV1, GatewayComplianceErrorResponseV1,
    GatewayComplianceLatestActionStatusV1, GatewayCompliancePromoteExpectationV1,
    GatewayComplianceStatusResponseV1, decode_lower_hex_32, request_idempotency_binding,
};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogV1, GatewayComplianceRollbackV1,
    MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
};
use std::{
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};
const GATEWAY_COMPLIANCE_OPERATOR_ROLE: &str = "sorafs_gateway_compliance_operator";
const MAX_GATEWAY_COMPLIANCE_BLOCKING_OPERATIONS: usize = 16;
static GATEWAY_COMPLIANCE_OPERATOR_ROLE_ID: LazyLock<RoleId> = LazyLock::new(|| {
    GATEWAY_COMPLIANCE_OPERATOR_ROLE
        .parse()
        .expect("SoraFS gateway compliance operator role id is valid")
});
static GATEWAY_COMPLIANCE_BLOCKING_PERMITS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| {
        Arc::new(tokio::sync::Semaphore::new(
            MAX_GATEWAY_COMPLIANCE_BLOCKING_OPERATIONS,
        ))
    });
/// Fetch one configured feed through the runtime-injected authenticated
/// address-pinned transport. The returned document is normalized and bounded;
/// this route never promotes it or signs a catalog.
pub async fn handle_get_sorafs_gateway_compliance_feed(
    State(state): State<SharedAppState>,
    Path(feed_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response = handle_get_sorafs_gateway_compliance_feed_inner(
        State(state),
        Path(feed_id),
        headers,
        method,
        uri,
    )
    .await;
    observe_gateway_compliance_control_response(&observation_state, "feed", response).await
}
async fn handle_get_sorafs_gateway_compliance_feed_inner(
    State(state): State<SharedAppState>,
    Path(feed_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &[])
    {
        return response;
    }
    let (controller, transport) = match gateway_compliance_runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let result = match run_gateway_compliance_blocking(move || {
        controller.fetch_feed(&feed_id, transport.as_ref())
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(feed) => no_store_response(JsonBody(feed).into_response()),
        Err(error) => gateway_compliance_error_response(error),
    }
}
/// Return a bounded, payload-free projection of the durable controller checkpoint. Catalog rules,
/// signatures, signer identities, feed paths, and acknowledgement bodies never cross this boundary.
pub async fn handle_get_sorafs_gateway_compliance_status(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response =
        handle_get_sorafs_gateway_compliance_status_inner(State(state), headers, method, uri).await;
    observe_gateway_compliance_control_response(&observation_state, "status", response).await
}
async fn handle_get_sorafs_gateway_compliance_status_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &[])
    {
        return response;
    }
    let controller = match gateway_compliance_controller(&state) {
        Ok(controller) => controller,
        Err(response) => return response,
    };
    let observed_at_unix = match current_unix_second() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let result = match run_gateway_compliance_blocking(move || controller.checkpoint()).await {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(checkpoint) => {
            record_gateway_compliance_checkpoint_snapshot(&state, &checkpoint, observed_at_unix);
            match status_response(&checkpoint, observed_at_unix) {
                Ok(status) => no_store_response(JsonBody(status).into_response()),
                Err(error) => gateway_compliance_error_response(error),
            }
        }
        Err(error) => gateway_compliance_error_response(error),
    }
}
/// Durably stage one exact canonical threshold-signed catalog.
pub async fn handle_post_sorafs_gateway_compliance_stage(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response =
        handle_post_sorafs_gateway_compliance_stage_inner(State(state), headers, method, uri, body)
            .await;
    observe_gateway_compliance_control_response(&observation_state, "stage", response).await
}
async fn handle_post_sorafs_gateway_compliance_stage_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &body)
    {
        return response;
    }
    if let Err(response) = require_mutation_uri_without_query(&uri) {
        return response;
    }
    if let Err(response) = validate_gateway_compliance_body_headers(&headers, &body) {
        return response;
    }
    let catalog = match decode_canonical_catalog(&body) {
        Ok(catalog) => catalog,
        Err(response) => return response,
    };
    let binding = match require_request_idempotency_binding(&headers, "stage", &uri, &body) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let controller = match gateway_compliance_controller(&state) {
        Ok(controller) => controller,
        Err(response) => return response,
    };
    let observed_at_unix = match current_unix_second() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let result = match run_gateway_compliance_blocking(move || {
        stage_catalog_adapter(controller.as_ref(), catalog, observed_at_unix, binding)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => action_response(StatusCode::ACCEPTED, "stage", result, binding.key_digest),
        Err(error) => gateway_compliance_error_response(error),
    }
}
/// Durably record one exact canonical signed regional-gateway acknowledgement.
pub async fn handle_post_sorafs_gateway_compliance_acknowledge(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response = handle_post_sorafs_gateway_compliance_acknowledge_inner(
        State(state),
        headers,
        method,
        uri,
        body,
    )
    .await;
    observe_gateway_compliance_control_response(&observation_state, "acknowledge", response).await
}
async fn handle_post_sorafs_gateway_compliance_acknowledge_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &body)
    {
        return response;
    }
    if let Err(response) = require_mutation_uri_without_query(&uri) {
        return response;
    }
    if let Err(response) = validate_gateway_compliance_body_headers(&headers, &body) {
        return response;
    }
    let acknowledgement = match decode_canonical_acknowledgement(&body) {
        Ok(acknowledgement) => acknowledgement,
        Err(response) => return response,
    };
    let binding = match require_request_idempotency_binding(&headers, "acknowledge", &uri, &body) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let controller = match gateway_compliance_controller(&state) {
        Ok(controller) => controller,
        Err(response) => return response,
    };
    let observed_at_unix = match current_unix_second() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let result = match run_gateway_compliance_blocking(move || {
        acknowledge_adapter(
            controller.as_ref(),
            acknowledgement,
            observed_at_unix,
            binding,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => action_response(
            StatusCode::ACCEPTED,
            "acknowledge",
            result,
            binding.key_digest,
        ),
        Err(error) => gateway_compliance_error_response(error),
    }
}
/// Atomically promote the staged catalog after the signed regional-gateway
/// acknowledgement quorum has committed.
pub async fn handle_post_sorafs_gateway_compliance_promote(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response = handle_post_sorafs_gateway_compliance_promote_inner(
        State(state),
        headers,
        method,
        uri,
        body,
    )
    .await;
    observe_gateway_compliance_control_response(&observation_state, "promote", response).await
}
async fn handle_post_sorafs_gateway_compliance_promote_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &body)
    {
        return response;
    }
    if !body.is_empty() {
        return gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "non_empty_promote_body",
            "gateway compliance promotion requires an empty signed request body",
        );
    }
    let expectation = match decode_canonical_promote_expectation(&uri) {
        Ok(expectation) => expectation,
        Err(response) => return response,
    };
    let binding = match require_request_idempotency_binding(&headers, "promote", &uri, &body) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let controller = match gateway_compliance_controller(&state) {
        Ok(controller) => controller,
        Err(response) => return response,
    };
    let observed_at_unix = match current_unix_second() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let result = match run_gateway_compliance_blocking(move || {
        promote_adapter(controller.as_ref(), expectation, observed_at_unix, binding)
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => action_response(StatusCode::OK, "promote", result, binding.key_digest),
        Err(error) => gateway_compliance_error_response(error),
    }
}
/// Atomically roll the serving pointer back to the last-known-good catalog
/// after verifying the exact threshold-signed rollback authorization.
pub async fn handle_post_sorafs_gateway_compliance_rollback(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let observation_state = Arc::clone(&state);
    let response = handle_post_sorafs_gateway_compliance_rollback_inner(
        State(state),
        headers,
        method,
        uri,
        body,
    )
    .await;
    observe_gateway_compliance_control_response(&observation_state, "rollback", response).await
}
async fn handle_post_sorafs_gateway_compliance_rollback_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if let Err(response) =
        authorize_gateway_compliance_request(&state, &headers, &method, &uri, &body)
    {
        return response;
    }
    if let Err(response) = require_mutation_uri_without_query(&uri) {
        return response;
    }
    if let Err(response) = validate_gateway_compliance_body_headers(&headers, &body) {
        return response;
    }
    let rollback = match decode_canonical_rollback(&body) {
        Ok(rollback) => rollback,
        Err(response) => return response,
    };
    let binding = match require_operation_idempotency_binding(
        &headers,
        rollback.payload.operation_id,
        "rollback",
        &uri,
        &body,
    ) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let controller = match gateway_compliance_controller(&state) {
        Ok(controller) => controller,
        Err(response) => return response,
    };
    let observed_at_unix = match current_unix_second() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let worker_controller = Arc::clone(&controller);
    let worker_rollback = rollback.clone();
    let result = match run_gateway_compliance_blocking(move || {
        rollback_adapter(
            worker_controller.as_ref(),
            &worker_rollback,
            observed_at_unix,
            binding,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match result {
        Ok(result) => action_response(StatusCode::OK, "rollback", result, binding.key_digest),
        Err(error) => gateway_compliance_error_response(error),
    }
}
async fn observe_gateway_compliance_control_response(
    state: &SharedAppState,
    operation: &'static str,
    response: Response,
) -> Response {
    let status = response.status();
    state.telemetry.with_metrics(|metrics| {
        metrics.record_sorafs_gateway_compliance_request(
            operation,
            gateway_compliance_control_outcome(status),
        );
        if !status.is_success() {
            metrics.record_sorafs_gateway_compliance_failure(
                "control",
                gateway_compliance_control_failure_class(status),
            );
        }
    });
    if status.is_success() && matches!(operation, "promote" | "rollback") {
        refresh_gateway_compliance_control_snapshot(state).await;
    }
    response
}
fn gateway_compliance_control_outcome(status: StatusCode) -> &'static str {
    match status {
        status if status.is_success() => "success",
        StatusCode::UNAUTHORIZED => "authentication_failed",
        StatusCode::FORBIDDEN => "authorization_failed",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        status if status.is_client_error() => "invalid_request",
        _ => "internal_error",
    }
}
fn gateway_compliance_control_failure_class(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "authentication",
        StatusCode::FORBIDDEN => "authorization",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::BAD_GATEWAY => "upstream",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        status if status.is_client_error() => "invalid_request",
        _ => "internal",
    }
}
async fn refresh_gateway_compliance_control_snapshot(state: &SharedAppState) {
    if !state.telemetry.allows_metrics() {
        return;
    }
    let observed_at_unix = match current_unix_second() {
        Ok(observed_at_unix) => observed_at_unix,
        Err(response) => {
            record_gateway_compliance_snapshot_failure(
                state,
                gateway_compliance_control_failure_class(response.status()),
            );
            return;
        }
    };
    let Some(controller) = state.sorafs_gateway_compliance_controller.clone() else {
        record_gateway_compliance_snapshot_failure(state, "unavailable");
        return;
    };
    let result = run_gateway_compliance_blocking(move || controller.checkpoint()).await;
    match result {
        Ok(Ok(checkpoint)) => {
            record_gateway_compliance_checkpoint_snapshot(state, &checkpoint, observed_at_unix);
        }
        Ok(Err(error)) => {
            record_gateway_compliance_snapshot_failure(
                state,
                gateway_compliance_snapshot_error_class(&error),
            );
        }
        Err(response) => {
            record_gateway_compliance_snapshot_failure(
                state,
                gateway_compliance_control_failure_class(response.status()),
            );
        }
    }
}
fn record_gateway_compliance_checkpoint_snapshot(
    state: &SharedAppState,
    checkpoint: &GatewayComplianceCheckpointV1,
    observed_at_unix: u64,
) {
    let (sequence, valid_until_unix, ready) =
        gateway_compliance_checkpoint_snapshot(checkpoint, observed_at_unix);
    state.telemetry.with_metrics(|metrics| {
        metrics.record_sorafs_gateway_compliance_serving_catalog(sequence, valid_until_unix, ready);
    });
}
fn gateway_compliance_checkpoint_snapshot(
    checkpoint: &GatewayComplianceCheckpointV1,
    observed_at_unix: u64,
) -> (Option<u64>, Option<u64>, bool) {
    let serving = checkpoint.serving.as_ref();
    let ready = serving.is_some_and(|catalog| {
        catalog.payload.generated_at_unix <= observed_at_unix
            && observed_at_unix < catalog.payload.valid_until_unix
    });
    (
        serving.map(|catalog| catalog.payload.sequence),
        serving.map(|catalog| catalog.payload.valid_until_unix),
        ready,
    )
}
fn record_gateway_compliance_snapshot_failure(state: &SharedAppState, class: &'static str) {
    state.telemetry.with_metrics(|metrics| {
        metrics.mark_sorafs_gateway_compliance_unready();
        metrics.record_sorafs_gateway_compliance_failure("control", class);
    });
}
fn gateway_compliance_snapshot_error_class(error: &GatewayComplianceError) -> &'static str {
    match error {
        GatewayComplianceError::CatalogNotFresh => "expired_catalog",
        GatewayComplianceError::NoServingCatalog => "unavailable",
        GatewayComplianceError::Persistence(_)
        | GatewayComplianceError::InvalidCheckpoint(_)
        | GatewayComplianceError::LeaseHeld
        | GatewayComplianceError::CheckpointConflict
        | GatewayComplianceError::StatePoisoned => "persistence",
        _ => "internal",
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn gateway_compliance_runtime(
    state: &SharedAppState,
) -> Result<
    (
        Arc<GatewayComplianceController>,
        Arc<dyn super::gateway::GatewayComplianceFeedTransport>,
    ),
    Response,
> {
    let controller = gateway_compliance_controller(state)?;
    let transport = state
        .sorafs_gateway_compliance_feed_transport
        .clone()
        .ok_or_else(gateway_compliance_unavailable)?;
    Ok((controller, transport))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn gateway_compliance_controller(
    state: &SharedAppState,
) -> Result<Arc<GatewayComplianceController>, Response> {
    state
        .sorafs_gateway_compliance_controller
        .clone()
        .ok_or_else(gateway_compliance_unavailable)
}
async fn run_gateway_compliance_blocking<T, F>(operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = Arc::clone(&GATEWAY_COMPLIANCE_BLOCKING_PERMITS)
        .acquire_owned()
        .await
        .map_err(|_| gateway_compliance_worker_unavailable())?;
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        move || {
            let _permit = permit;
            operation()
        },
    ))
    .await
    .map_err(|_| {
        warn!("gateway compliance blocking worker failed");
        gateway_compliance_worker_unavailable()
    })
}
fn gateway_compliance_worker_unavailable() -> Response {
    gateway_compliance_request_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "controller_worker_unavailable",
        "the bounded gateway compliance worker is unavailable",
    )
}
fn stage_catalog_adapter(
    controller: &GatewayComplianceController,
    catalog: GatewayComplianceCatalogV1,
    observed_at_unix: u64,
    binding: GatewayComplianceMutationBindingV1,
) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
    controller.stage_catalog(catalog, observed_at_unix, binding)
}
fn acknowledge_adapter(
    controller: &GatewayComplianceController,
    acknowledgement: GatewayComplianceAcknowledgementV1,
    observed_at_unix: u64,
    binding: GatewayComplianceMutationBindingV1,
) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
    controller.acknowledge(acknowledgement, observed_at_unix, binding)
}
fn promote_adapter(
    controller: &GatewayComplianceController,
    expectation: GatewayCompliancePromoteExpectationV1,
    observed_at_unix: u64,
    binding: GatewayComplianceMutationBindingV1,
) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
    controller.promote(
        expectation.catalog_digest,
        expectation.sequence,
        observed_at_unix,
        binding,
    )
}
fn rollback_adapter(
    controller: &GatewayComplianceController,
    rollback: &GatewayComplianceRollbackV1,
    observed_at_unix: u64,
    binding: GatewayComplianceMutationBindingV1,
) -> Result<GatewayComplianceMutationResultV1, GatewayComplianceError> {
    controller.rollback(rollback, observed_at_unix, binding)
}
fn gateway_compliance_unavailable() -> Response {
    gateway_compliance_request_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "controller_unavailable",
        "the governed SoraFS gateway compliance controller is not enabled",
    )
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn authorize_gateway_compliance_request(
    state: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<(), Response> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(state) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error.into_response());
            }
        };

    let verified = match crate::app_auth::verify_canonical_network_request(
        &state.state,
        state.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => verified,
        Ok(None) => {
            return Err(gateway_compliance_request_error(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "SoraFS gateway compliance control requires X-Iroha canonical request authentication",
            ));
        }
        Err(_) => {
            warn!("SoraFS gateway compliance canonical request authentication rejected");
            return Err(gateway_compliance_request_error(
                StatusCode::UNAUTHORIZED,
                "authentication_invalid",
                "invalid SoraFS gateway compliance request authentication",
            ));
        }
    };
    let world = state.state.world_view();
    if world
        .account_roles_iter(&verified.account)
        .any(|role| role == &*GATEWAY_COMPLIANCE_OPERATOR_ROLE_ID)
    {
        Ok(())
    } else {
        Err(gateway_compliance_request_error(
            StatusCode::FORBIDDEN,
            "operator_role_required",
            "SoraFS gateway compliance control requires the governed operator role",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_gateway_compliance_body_headers(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Response> {
    crate::utils::canonical_json_request_content_type(headers).map_err(no_store_response)?;
    if body.is_empty() {
        return Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "body_required",
            "a canonical JSON gateway compliance payload is required",
        ));
    }
    if body.len() > MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1 {
        return Err(gateway_compliance_request_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "the gateway compliance payload exceeds the V1 byte bound",
        ));
    }
    Ok(())
}
fn status_response(
    checkpoint: &GatewayComplianceCheckpointV1,
    observed_at_unix: u64,
) -> Result<GatewayComplianceStatusResponseV1, GatewayComplianceError> {
    let acknowledgement_count =
        u64::try_from(checkpoint.acknowledgements.len()).unwrap_or(u64::MAX);
    let accepted_acknowledgement_count = u64::try_from(
        checkpoint
            .acknowledgements
            .iter()
            .filter(|acknowledgement| acknowledgement.payload.accepted)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let rejected_acknowledgement_count =
        acknowledgement_count.saturating_sub(accepted_acknowledgement_count);
    let (_, _, serving_ready) =
        gateway_compliance_checkpoint_snapshot(checkpoint, observed_at_unix);
    Ok(GatewayComplianceStatusResponseV1 {
        schema: GATEWAY_COMPLIANCE_STATUS_SCHEMA_V1.to_owned(),
        checkpoint_version: checkpoint.version,
        policy_digest_hex: hex::encode(checkpoint.policy_digest),
        observed_at_unix,
        serving_ready,
        chain_head: checkpoint
            .chain_head
            .as_ref()
            .map(catalog_status)
            .transpose()?,
        serving: checkpoint
            .serving
            .as_ref()
            .map(catalog_status)
            .transpose()?,
        previous_serving: checkpoint
            .previous_serving
            .as_ref()
            .map(catalog_status)
            .transpose()?,
        candidate: checkpoint
            .candidate
            .as_ref()
            .map(catalog_status)
            .transpose()?,
        acknowledgement_count,
        accepted_acknowledgement_count,
        rejected_acknowledgement_count,
        history_count: u64::try_from(checkpoint.history.len()).unwrap_or(u64::MAX),
        idempotency_record_count: u64::try_from(checkpoint.idempotency_records.len())
            .unwrap_or(u64::MAX),
        latest_action: checkpoint.history.last().map(latest_action_status),
    })
}
fn catalog_status(
    catalog: &GatewayComplianceCatalogV1,
) -> Result<GatewayComplianceCatalogStatusV1, GatewayComplianceError> {
    Ok(GatewayComplianceCatalogStatusV1 {
        digest_hex: hex::encode(catalog.payload.catalog_digest()?),
        sequence: catalog.payload.sequence,
        generated_at_unix: catalog.payload.generated_at_unix,
        valid_until_unix: catalog.payload.valid_until_unix,
    })
}
fn latest_action_status(
    record: &GatewayComplianceHistoryRecordV1,
) -> GatewayComplianceLatestActionStatusV1 {
    GatewayComplianceLatestActionStatusV1 {
        operation_id_hex: hex::encode(record.operation_id),
        action: record.action.clone(),
        previous_serving_digest_hex: record.previous_serving_digest.map(hex::encode),
        serving_digest_hex: hex::encode(record.serving_digest),
        recorded_at_unix: record.recorded_at_unix,
        reason_code: record.reason_code.clone(),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_mutation_uri_without_query(uri: &Uri) -> Result<(), Response> {
    if uri.query().is_none() {
        Ok(())
    } else {
        Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "unexpected_query",
            "this gateway compliance mutation does not accept query parameters",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_canonical_promote_expectation(
    uri: &Uri,
) -> Result<GatewayCompliancePromoteExpectationV1, Response> {
    let query = uri.query().ok_or_else(|| {
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "promotion_expectation_missing",
            "gateway compliance promotion requires an exact catalog digest and sequence",
        )
    })?;
    GatewayCompliancePromoteExpectationV1::parse_query(query)
        .map_err(|_| non_canonical_promote_expectation())
}
fn non_canonical_promote_expectation() -> Response {
    gateway_compliance_request_error(
        StatusCode::BAD_REQUEST,
        "promotion_expectation_invalid",
        "the promotion expectation must use exact canonical digest and sequence syntax",
    )
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_request_idempotency_binding(
    headers: &HeaderMap,
    action: &'static str,
    uri: &Uri,
    body: &[u8],
) -> Result<GatewayComplianceMutationBindingV1, Response> {
    let request_digest = request_idempotency_binding(
        action,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |value| value.as_str()),
        body,
    );
    let key_digest = require_exact_idempotency_key(headers, request_digest)?;
    Ok(GatewayComplianceMutationBindingV1 {
        key_digest,
        request_digest,
    })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_operation_idempotency_binding(
    headers: &HeaderMap,
    operation_id: [u8; 32],
    action: &'static str,
    uri: &Uri,
    body: &[u8],
) -> Result<GatewayComplianceMutationBindingV1, Response> {
    if operation_id.iter().all(|byte| *byte == 0) {
        return Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "operation_id_invalid",
            "the signed gateway compliance operation id must be non-zero",
        ));
    }
    let key_digest = require_exact_idempotency_key(headers, operation_id)?;
    Ok(GatewayComplianceMutationBindingV1 {
        key_digest,
        request_digest: request_idempotency_binding(
            action,
            uri.path_and_query()
                .map_or_else(|| uri.path(), |value| value.as_str()),
            body,
        ),
    })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_exact_idempotency_key(
    headers: &HeaderMap,
    expected: [u8; 32],
) -> Result<[u8; 32], Response> {
    let actual = validated_idempotency_key(headers)?;
    if actual != expected {
        return Err(gateway_compliance_request_error(
            StatusCode::CONFLICT,
            "idempotency_key_conflict",
            "Idempotency-Key does not match the canonical signed operation binding",
        ));
    }
    Ok(actual)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validated_idempotency_key(headers: &HeaderMap) -> Result<[u8; 32], Response> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(raw) = values.next() else {
        return Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_missing",
            "gateway compliance mutations require exactly one Idempotency-Key header",
        ));
    };
    if values.next().is_some() {
        return Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_invalid",
            "gateway compliance mutations require exactly one Idempotency-Key header",
        ));
    }
    let key = raw.to_str().map_err(|_| {
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_invalid",
            "Idempotency-Key must be lowercase hexadecimal ASCII",
        )
    })?;
    if key.len() != 64
        || key.bytes().any(|byte| !byte.is_ascii_hexdigit())
        || key.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_invalid",
            "Idempotency-Key must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    decode_lower_hex_32(key).ok_or_else(|| {
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_invalid",
            "Idempotency-Key must be exactly 64 lowercase hexadecimal characters",
        )
    })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_canonical_catalog(body: &[u8]) -> Result<GatewayComplianceCatalogV1, Response> {
    let value: GatewayComplianceCatalogV1 = norito::json::from_slice(body).map_err(|_| {
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "catalog_invalid",
            "invalid canonical gateway compliance catalog JSON",
        )
    })?;
    require_exact_canonical_json(body, &value, "catalog")?;
    Ok(value)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_canonical_acknowledgement(
    body: &[u8],
) -> Result<GatewayComplianceAcknowledgementV1, Response> {
    let value: GatewayComplianceAcknowledgementV1 =
        norito::json::from_slice(body).map_err(|_| {
            gateway_compliance_request_error(
                StatusCode::BAD_REQUEST,
                "acknowledgement_invalid",
                "invalid canonical gateway compliance acknowledgement JSON",
            )
        })?;
    require_exact_canonical_json(body, &value, "acknowledgement")?;
    Ok(value)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_canonical_rollback(body: &[u8]) -> Result<GatewayComplianceRollbackV1, Response> {
    let value: GatewayComplianceRollbackV1 = norito::json::from_slice(body).map_err(|_| {
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "rollback_invalid",
            "invalid canonical gateway compliance rollback JSON",
        )
    })?;
    require_exact_canonical_json(body, &value, "rollback")?;
    Ok(value)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_exact_canonical_json<T>(
    body: &[u8],
    value: &T,
    label: &'static str,
) -> Result<(), Response>
where
    T: norito::json::JsonSerialize,
{
    let canonical = norito::json::to_vec(value).map_err(|_| {
        warn!(label, "failed to re-encode gateway compliance request");
        gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "canonical_encoding_failed",
            "the gateway compliance payload cannot be represented canonically",
        )
    })?;
    if canonical == body {
        Ok(())
    } else {
        Err(gateway_compliance_request_error(
            StatusCode::BAD_REQUEST,
            "non_canonical_json",
            "the gateway compliance payload must use exact canonical Norito JSON bytes",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn current_unix_second() -> Result<u64, Response> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            warn!("system clock is before the Unix epoch for gateway compliance control");
            gateway_compliance_request_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "clock_unavailable",
                "the gateway compliance control clock is unavailable",
            )
        })
}
fn action_response(
    status: StatusCode,
    action: &'static str,
    result: GatewayComplianceMutationResultV1,
    idempotency_key: [u8; 32],
) -> Response {
    no_store_response(
        (
            status,
            JsonBody(GatewayComplianceActionResponseV1 {
                schema: GATEWAY_COMPLIANCE_ACTION_SCHEMA_V1.to_owned(),
                action: action.to_owned(),
                catalog_digest_hex: hex::encode(result.catalog_digest),
                idempotency_key: hex::encode(idempotency_key),
                operation_timestamp_unix: result.recorded_at_unix,
            }),
        )
            .into_response(),
    )
}
fn gateway_compliance_request_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    no_store_response(
        (
            status,
            JsonBody(GatewayComplianceErrorResponseV1 {
                schema: GATEWAY_COMPLIANCE_ERROR_SCHEMA_V1.to_owned(),
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        )
            .into_response(),
    )
}
fn no_store_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
}
fn gateway_compliance_error_response(error: GatewayComplianceError) -> Response {
    use GatewayComplianceError::{
        CatalogEquivocation, CatalogNotFresh, CheckpointConflict, Decompression, DnsRebinding,
        DuplicateSigner, Encoding, FeedTransportNotQualified, FeedTransportOperationFailed,
        FeedTransportStale, FeedTransportSubstituted, FeedTransportTestMarked,
        FeedTransportUnavailable, FeedTransportUnqualified, FetchTimeout, GatewayEquivocation,
        GatewayQuorumNotMet, HistoryFull, IdempotencyConflict, IdempotencyRegistryFull,
        InvalidAcknowledgement, InvalidCatalog, InvalidCheckpoint, InvalidFeed, InvalidPolicy,
        InvalidPredecessor, InvalidRollback, InvalidSignature, LeaseHeld, MissingRequiredFeed,
        MutationTimeInvalid, NoLastKnownGood, NoServingCatalog, NoStagedCatalog, NonCanonical,
        NonPublicAddress, Persistence, PolicyDigestMismatch, PromotionTargetMismatch, QuorumNotMet,
        ResourceLimit, RevokedSigner, RollbackTargetMismatch, SequenceOverflow, StatePoisoned,
        TimeOverflow, TooManyRedirects, TrustPinMismatch, UnknownFeed, UnsafeAddressSet, UnsafeUrl,
        UntrustedSigner,
    };
    let (status, code, message) = match &error {
        UnknownFeed(_) => (
            StatusCode::NOT_FOUND,
            "feed_not_found",
            "the configured gateway compliance feed does not exist",
        ),
        NoServingCatalog | NoLastKnownGood | NoStagedCatalog => (
            StatusCode::CONFLICT,
            "controller_state_conflict",
            "the gateway compliance controller is not in the required state",
        ),
        CatalogEquivocation { .. }
        | GatewayEquivocation(_)
        | IdempotencyConflict
        | InvalidPredecessor
        | PromotionTargetMismatch
        | RollbackTargetMismatch
        | HistoryFull
        | GatewayQuorumNotMet { .. } => (
            StatusCode::CONFLICT,
            "transition_rejected",
            "the gateway compliance transition conflicts with durable state",
        ),
        IdempotencyRegistryFull => (
            StatusCode::SERVICE_UNAVAILABLE,
            "idempotency_capacity_exhausted",
            "the durable gateway compliance idempotency registry requires operator archival",
        ),
        MutationTimeInvalid => (
            StatusCode::SERVICE_UNAVAILABLE,
            "controller_clock_rejected",
            "the gateway compliance controller rejected a zero or regressed operation clock",
        ),
        FeedTransportNotQualified
        | FeedTransportUnavailable
        | FeedTransportUnqualified
        | FeedTransportOperationFailed
        | FeedTransportSubstituted
        | FeedTransportStale
        | FeedTransportTestMarked => (
            StatusCode::SERVICE_UNAVAILABLE,
            "feed_transport_unavailable",
            "the authenticated gateway compliance feed transport is unavailable",
        ),
        LeaseHeld => (
            StatusCode::SERVICE_UNAVAILABLE,
            "checkpoint_lease_held",
            "the gateway compliance checkpoint is owned by another active controller",
        ),
        CheckpointConflict => (
            StatusCode::SERVICE_UNAVAILABLE,
            "checkpoint_conflict",
            "the gateway compliance checkpoint changed and the controller is unavailable",
        ),
        DuplicateSigner(_)
        | UntrustedSigner(_)
        | RevokedSigner(_)
        | InvalidSignature { .. }
        | QuorumNotMet { .. } => (
            StatusCode::FORBIDDEN,
            "signature_policy_rejected",
            "the gateway compliance signature policy rejected the payload",
        ),
        ResourceLimit { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "resource_limit",
            "the gateway compliance payload exceeds a governed V1 bound",
        ),
        UnsafeUrl(_)
        | UnsafeAddressSet { .. }
        | NonPublicAddress
        | DnsRebinding
        | TrustPinMismatch
        | TooManyRedirects
        | FetchTimeout
        | Decompression(_) => (
            StatusCode::BAD_GATEWAY,
            "feed_transport_rejected",
            "the authenticated gateway compliance feed transport failed closed",
        ),
        Persistence(_) | StatePoisoned | InvalidCheckpoint(_) | Encoding(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "controller_unavailable",
            "the durable gateway compliance controller is unavailable",
        ),
        InvalidPolicy(_)
        | InvalidCatalog(_)
        | InvalidFeed(_)
        | NonCanonical(_)
        | PolicyDigestMismatch
        | CatalogNotFresh
        | InvalidAcknowledgement(_)
        | InvalidRollback(_)
        | MissingRequiredFeed(_)
        | SequenceOverflow
        | TimeOverflow => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "payload_rejected",
            "the gateway compliance payload is invalid for the active policy",
        ),
    };
    warn!(
        response_code = code,
        response_status = status.as_u16(),
        "gateway compliance control operation rejected"
    );
    gateway_compliance_request_error(status, code, message)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sorafs::gateway::{
        GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1, GatewayComplianceIdempotencyRecordV1,
        GatewayComplianceMutationKindV1,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use sorafs_manifest::gateway_compliance::{
        GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1, GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
        GatewayComplianceCatalogApprovalV1, GatewayComplianceCatalogPayloadV1,
    };
    #[test]
    fn gateway_compliance_auth_rejects_foreign_exact_network() {
        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let method = Method::POST;
        let uri: Uri = "/v1/sorafs/gateway/compliance/catalog"
            .parse()
            .expect("gateway compliance URI");
        let body = b"{}";
        let (state, headers) = crate::tests_runtime_handlers::foreign_network_signed_app_fixture(
            &method, &uri, body, 0xD2, 0xE2,
        );
        let response = authorize_gateway_compliance_request(&state, &headers, &method, &uri, body)
            .expect_err("foreign-network gateway authorization must fail closed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    fn signed_catalog() -> GatewayComplianceCatalogV1 {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let payload = GatewayComplianceCatalogPayloadV1 {
            version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
            sequence: 1,
            predecessor_digest: None,
            policy_digest: [0xA5; 32],
            generated_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_003_600,
            source_anchors: Vec::new(),
            baseline_rules: Vec::new(),
            appeal_overrides: Vec::new(),
            legal_safety_holds: Vec::new(),
            toggles: Vec::new(),
        };
        let digest = payload.signing_digest().expect("catalog signing digest");
        GatewayComplianceCatalogV1 {
            payload,
            approvals: vec![GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "catalog-a".to_owned(),
                signature: signing_key.sign(&digest).to_bytes(),
            }],
        }
    }
    #[test]
    fn catalog_body_requires_exact_canonical_json_bytes() {
        let catalog = signed_catalog();
        let canonical = norito::json::to_vec(&catalog).expect("canonical catalog JSON");
        assert_eq!(
            decode_canonical_catalog(&canonical)
                .expect("canonical request")
                .payload,
            catalog.payload
        );
        let mut padded = canonical;
        padded.push(b'\n');
        assert!(decode_canonical_catalog(&padded).is_err());
    }
    #[test]
    fn shared_protocol_failures_keep_runtime_http_classes() {
        use sorafs_manifest::gateway_compliance::GatewayComplianceProtocolError;
        for (protocol, status, variant) in [
            (
                GatewayComplianceProtocolError::CatalogNotFresh,
                StatusCode::UNPROCESSABLE_ENTITY,
                "CatalogNotFresh",
            ),
            (
                GatewayComplianceProtocolError::InvalidSignature {
                    signer_id: "catalog-a".into(),
                    reason: "signature rejected".into(),
                },
                StatusCode::FORBIDDEN,
                "InvalidSignature",
            ),
            (
                GatewayComplianceProtocolError::QuorumNotMet {
                    found: 1,
                    required: 2,
                },
                StatusCode::FORBIDDEN,
                "QuorumNotMet",
            ),
            (
                GatewayComplianceProtocolError::InvalidPredecessor,
                StatusCode::CONFLICT,
                "InvalidPredecessor",
            ),
            (
                GatewayComplianceProtocolError::ResourceLimit {
                    resource: "canonical encoded bytes",
                    found: 17,
                    maximum: 16,
                },
                StatusCode::PAYLOAD_TOO_LARGE,
                "ResourceLimit",
            ),
        ] {
            let message = protocol.to_string();
            let exact = format!("{protocol:?}");
            let runtime = GatewayComplianceError::from(protocol);
            assert_eq!(runtime.to_string(), message);
            assert_eq!(format!("{runtime:?}"), exact);
            assert!(exact.starts_with(variant));
            assert_eq!(gateway_compliance_error_response(runtime).status(), status);
        }
    }

    #[test]
    fn controller_errors_map_to_fail_closed_http_classes() {
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::UnknownFeed(
                "missing".to_owned()
            ))
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::DnsRebinding).status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::IdempotencyConflict).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::LeaseHeld).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::CheckpointConflict).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::FeedTransportSubstituted)
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::FeedTransportUnqualified)
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            gateway_compliance_error_response(GatewayComplianceError::FeedTransportOperationFailed)
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let signature_response =
            gateway_compliance_error_response(GatewayComplianceError::InvalidSignature {
                signer_id: "catalog-a".to_owned(),
                reason: "invalid".to_owned(),
            });
        assert_eq!(signature_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            signature_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store, max-age=0"))
        );
    }
    #[test]
    fn control_response_metrics_use_closed_status_vocabularies() {
        assert_eq!(
            gateway_compliance_control_outcome(StatusCode::ACCEPTED),
            "success"
        );
        for (status, outcome, failure_class) in [
            (
                StatusCode::UNAUTHORIZED,
                "authentication_failed",
                "authentication",
            ),
            (
                StatusCode::FORBIDDEN,
                "authorization_failed",
                "authorization",
            ),
            (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid_request",
            ),
            (StatusCode::NOT_FOUND, "not_found", "not_found"),
            (StatusCode::CONFLICT, "conflict", "conflict"),
            (StatusCode::BAD_GATEWAY, "unavailable", "upstream"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "unavailable",
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal",
            ),
        ] {
            assert_eq!(gateway_compliance_control_outcome(status), outcome);
            assert_eq!(
                gateway_compliance_control_failure_class(status),
                failure_class
            );
        }
    }
    #[test]
    fn status_projection_never_serializes_catalog_or_signature_payloads() {
        let catalog = signed_catalog();
        let catalog_digest = catalog.payload.catalog_digest().expect("catalog digest");
        let checkpoint = GatewayComplianceCheckpointV1 {
            version: GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1,
            revision: 1,
            policy_digest: [0xA5; 32],
            chain_head: Some(catalog.clone()),
            serving: Some(catalog.clone()),
            previous_serving: None,
            candidate: None,
            acknowledgements: Vec::new(),
            history: vec![GatewayComplianceHistoryRecordV1 {
                operation_id: [0x42; 32],
                previous_serving_digest: None,
                serving_digest: catalog_digest,
                recorded_at_unix: 1_700_000_010,
                action: "promotion".to_owned(),
                reason_code: "gateway-quorum".to_owned(),
            }],
            idempotency_records: vec![GatewayComplianceIdempotencyRecordV1 {
                key_digest: [0x42; 32],
                request_digest: [0x43; 32],
                operation: GatewayComplianceMutationKindV1::Promote,
                catalog_digest,
                recorded_at_unix: 1_700_000_010,
            }],
        };
        let status =
            status_response(&checkpoint, 1_700_000_020).expect("redacted status projection");
        status
            .validate()
            .expect("canonical shared status projection");
        let json = norito::json::to_string(&status).expect("status JSON");
        let decoded: GatewayComplianceStatusResponseV1 = norito::json::from_str(&json).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, status);
        assert!(
            json.len() < 4_096,
            "status projection must remain tightly bounded"
        );
        assert!(json.contains("\"serving_ready\":true"));
        assert!(json.contains(&hex::encode(catalog_digest)));
        for forbidden in [
            "\"approvals\"",
            "\"signature\"",
            "\"signer_id\"",
            "catalog-a",
            "\"source_anchors\"",
            "\"baseline_rules\"",
            "\"appeal_overrides\"",
            "\"legal_safety_holds\"",
            "\"toggles\"",
            "\"acknowledgements\"",
            "\"idempotency_records\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "redacted status leaked forbidden field `{forbidden}`: {json}"
            );
        }
    }
    #[test]
    fn status_readiness_is_false_before_generation_and_at_expiry() {
        let catalog = signed_catalog();
        let mut checkpoint = GatewayComplianceCheckpointV1 {
            version: GATEWAY_COMPLIANCE_CHECKPOINT_VERSION_V1,
            revision: 0,
            policy_digest: [0xA5; 32],
            chain_head: Some(catalog.clone()),
            serving: Some(catalog),
            previous_serving: None,
            candidate: None,
            acknowledgements: Vec::new(),
            history: Vec::new(),
            idempotency_records: Vec::new(),
        };
        assert_eq!(
            gateway_compliance_checkpoint_snapshot(&checkpoint, 1_700_000_000),
            (Some(1), Some(1_700_003_600), true)
        );
        assert!(
            !status_response(&checkpoint, 1_699_999_999)
                .expect("status before generation")
                .serving_ready
        );
        assert!(
            !status_response(&checkpoint, 1_700_003_600)
                .expect("status at exclusive expiry")
                .serving_ready
        );
        assert_eq!(
            gateway_compliance_checkpoint_snapshot(&checkpoint, 1_700_003_600),
            (Some(1), Some(1_700_003_600), false)
        );
        for observed in [1_699_999_999, 1_700_000_000, 1_700_003_599, 1_700_003_600] {
            status_response(&checkpoint, observed)
                .unwrap()
                .validate()
                .unwrap();
        }
        checkpoint.serving = None;
        status_response(&checkpoint, 1_700_000_020)
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            gateway_compliance_checkpoint_snapshot(&checkpoint, 1_700_000_020),
            (None, None, false)
        );
    }
    #[test]
    fn idempotency_key_is_exact_lower_hex_and_unique() {
        let uri: Uri = "/v1/sorafs/gateway/compliance/stage"
            .parse()
            .expect("stage URI");
        let body = b"{\"catalog\":\"fixture\"}";
        let expected = hex::encode(request_idempotency_binding(
            "stage",
            uri.path_and_query()
                .map_or_else(|| uri.path(), |value| value.as_str()),
            body,
        ));
        let mut headers = HeaderMap::new();
        assert!(validated_idempotency_key(&headers).is_err());
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&expected).expect("idempotency header"),
        );
        let binding = require_request_idempotency_binding(&headers, "stage", &uri, body)
            .expect("matching binding");
        assert_eq!(hex::encode(binding.key_digest), expected);
        assert_eq!(binding.key_digest, binding.request_digest);
        headers.append(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&expected).expect("duplicate idempotency header"),
        );
        assert!(validated_idempotency_key(&headers).is_err());
        headers.remove(IDEMPOTENCY_KEY_HEADER);
        for malformed in [
            "11",
            "111111111111111111111111111111111111111111111111111111111111111g",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            headers.insert(
                IDEMPOTENCY_KEY_HEADER,
                HeaderValue::from_str(malformed).expect("malformed ASCII fixture"),
            );
            assert!(validated_idempotency_key(&headers).is_err());
        }
    }
    #[test]
    fn request_binding_rejects_key_reuse_for_changed_signed_material() {
        let uri: Uri = "/v1/sorafs/gateway/compliance/stage"
            .parse()
            .expect("stage URI");
        let original = b"{\"catalog\":1}";
        let changed = b"{\"catalog\":2}";
        let key = hex::encode(request_idempotency_binding(
            "stage",
            uri.path_and_query()
                .map_or_else(|| uri.path(), |value| value.as_str()),
            original,
        ));
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&key).expect("idempotency header"),
        );
        assert!(require_request_idempotency_binding(&headers, "stage", &uri, original).is_ok());
        let response = require_request_idempotency_binding(&headers, "stage", &uri, changed)
            .expect_err("same key must reject a different canonical body");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store, max-age=0"))
        );
        assert_ne!(
            request_idempotency_binding(
                "stage",
                uri.path_and_query()
                    .map_or_else(|| uri.path(), |value| value.as_str()),
                original
            ),
            request_idempotency_binding(
                "acknowledge",
                uri.path_and_query()
                    .map_or_else(|| uri.path(), |value| value.as_str()),
                original
            )
        );
    }
    #[test]
    fn promotion_expectation_has_one_canonical_signed_uri_shape() {
        let digest = "ab".repeat(32);
        let canonical: Uri = format!(
            "/v1/sorafs/gateway/compliance/promote?expected_catalog_digest={digest}&expected_sequence=7"
        )
        .parse()
        .expect("canonical promotion URI");
        assert_eq!(
            decode_canonical_promote_expectation(&canonical)
                .expect("canonical promotion expectation"),
            GatewayCompliancePromoteExpectationV1 {
                catalog_digest: [0xAB; 32],
                sequence: 7,
            }
        );
        for invalid in [
            "/v1/sorafs/gateway/compliance/promote".to_owned(),
            format!(
                "/v1/sorafs/gateway/compliance/promote?expected_sequence=7&expected_catalog_digest={digest}"
            ),
            format!(
                "/v1/sorafs/gateway/compliance/promote?expected_catalog_digest={digest}&expected_sequence=07"
            ),
            format!(
                "/v1/sorafs/gateway/compliance/promote?expected_catalog_digest={}&expected_sequence=7",
                "AB".repeat(32)
            ),
            format!(
                "/v1/sorafs/gateway/compliance/promote?expected_catalog_digest={digest}&expected_sequence=7&expected_sequence=8"
            ),
        ] {
            let uri: Uri = invalid.parse().expect("syntactically valid invalid URI");
            let response = decode_canonical_promote_expectation(&uri)
                .expect_err("non-canonical promotion expectation must fail");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(CACHE_CONTROL),
                Some(&HeaderValue::from_static("private, no-store, max-age=0"))
            );
        }
    }
    #[test]
    fn rollback_idempotency_key_must_equal_signed_operation_id() {
        let operation_id = [0x5C; 32];
        let expected = hex::encode(operation_id);
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&expected).expect("operation id header"),
        );
        let uri: Uri = "/v1/sorafs/gateway/compliance/rollback"
            .parse()
            .expect("rollback URI");
        let binding =
            require_operation_idempotency_binding(&headers, operation_id, "rollback", &uri, b"{}")
                .expect("matching operation id");
        assert_eq!(hex::encode(binding.key_digest), expected);
        assert_eq!(
            require_operation_idempotency_binding(&headers, [0x5D; 32], "rollback", &uri, b"{}",)
                .expect_err("mismatched operation id")
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            require_operation_idempotency_binding(&headers, [0; 32], "rollback", &uri, b"{}",)
                .expect_err("zero operation id")
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn every_local_response_constructor_applies_private_no_store() {
        let responses = [
            action_response(
                StatusCode::OK,
                "promote",
                GatewayComplianceMutationResultV1 {
                    catalog_digest: [0x11; 32],
                    recorded_at_unix: 1_700_000_000,
                },
                [0x11; 32],
            ),
            gateway_compliance_request_error(StatusCode::BAD_REQUEST, "fixture", "fixture"),
            gateway_compliance_error_response(GatewayComplianceError::IdempotencyConflict),
        ];
        for response in responses {
            assert_eq!(
                response.headers().get(CACHE_CONTROL),
                Some(&HeaderValue::from_static("private, no-store, max-age=0"))
            );
        }
    }
    #[tokio::test]
    async fn blocking_worker_panic_is_contained_as_service_unavailable() {
        let response = run_gateway_compliance_blocking(|| -> () {
            panic!("synthetic request-owned worker panic");
        })
        .await
        .expect_err("panicking worker must fail the request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
