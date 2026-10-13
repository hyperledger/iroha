//! Bounded archive-manager read of the exact live daemon's retained signed attestation.
use crate::SharedAppState;
use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use iroha_core::query::provider_attestation_inventory::{
    ProviderAttestationInventoryReadErrorV1, authorize_provider_attestation_inventory_read_v1,
};
use iroha_data_model::musubi::{
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1, MusubiProviderBundleAttestationKeyV1,
};
use sorafs_node::MusubiProviderAttestationInventoryScopeV1;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE: usize = MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1;
fn limits(bytes: usize) -> Option<norito::DecodeLimits> {
    // Leave one maximum response outside the prepaid physical-work allowance.
    let work = bytes.checked_sub(MAX_RESPONSE)?;
    if work == 0 {
        return None;
    }
    let frame = work.min(iroha_data_model::sumeragi::finality::NATIVE_FINALITY_MAX_BLOCK_BYTES);
    Some(norito::DecodeLimits::new(frame, frame, work, work, 128))
}
fn now() -> Result<u64, StatusCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
fn authorization(error: ProviderAttestationInventoryReadErrorV1) -> StatusCode {
    match error {
        ProviderAttestationInventoryReadErrorV1::Rejected => StatusCode::FORBIDDEN,
        ProviderAttestationInventoryReadErrorV1::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub async fn read_attestation(
    State(state): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    body: Bytes,
) -> Response {
    let permit = match crate::acquire_query_admission(state.as_ref(), true).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let bytes = state.query_fanout_working_set_bytes;
    let Some(limits) = limits(bytes) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(memory) = u64::try_from(bytes)
        .ok()
        .and_then(|bytes| state.query_fanout_inflight.try_acquire_parts([bytes]))
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let memory = crate::QueryFanoutMemoryReservation::new(memory);
    let budget = iroha_allocation::AllocationBudget::new(bytes);
    let runtime = tokio::runtime::Handle::current();
    let deadline = Instant::now() + Duration::from_secs(15);
    let task = crate::panic_recovery::spawn_blocking_recoverable(move || {
        // Physical work retains admission even if the HTTP future is cancelled.
        let _permit = permit;
        let _work = budget
            .try_reserve_bytes(bytes - MAX_RESPONSE)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        norito::with_decode_limits_scope(
            limits,
            || -> Result<Option<crate::native_projection_response::EncodedBody>, StatusCode> {
                let key: MusubiProviderBundleAttestationKeyV1 =
                    norito::decode_canonical_with_limits(
                        &body,
                        norito::DecodeLimits::new(4096, 4096, 4096, 16384, 16),
                    )
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                key.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
                if state.sorafs_node.capacity_provider_id() != Some(key.provider_id) {
                    return Err(StatusCode::FORBIDDEN);
                }
                let inventory = state
                    .sorafs_provider_attestation_inventory
                    .as_ref()
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                let authorize = |attestation| {
                    authorize_provider_attestation_inventory_read_v1(
                        &state.state.view(),
                        &verified.account,
                        key,
                        attestation,
                        now()?,
                    )
                    .map_err(authorization)
                };
                authorize(None)?;
                let scope = MusubiProviderAttestationInventoryScopeV1 {
                    network_id: *state.state.network_id_ref(),
                    archive_id: key.archive_id,
                    replication_order: key.replication_order,
                };
                // The HTTP join is deadline-bounded, but this physical worker must retain
                // its query-memory reservation until the native blocking read actually ends.
                // Cancelling an inner timeout would detach that read from its prepaid owner.
                let readback = runtime
                    .block_on(inventory.get(&scope, key))
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if Instant::now() >= deadline {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                let Some(readback) = readback else {
                    authorize(None)?;
                    return Ok(None);
                };
                let item = readback.item();
                if item.scope() != &scope || item.key() != key {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                item.validate()
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                authorize(Some(item.attestation()))?;
                let mut body = crate::native_projection_response::encode(
                    item.attestation(),
                    crate::ResponseFormat::Norito,
                    MAX_RESPONSE,
                    &budget,
                    crate::native_projection_response::capacity,
                )
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if Instant::now() >= deadline {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                body.memory = Some(memory);
                Ok(Some(body))
            },
        )
    });
    match tokio::time::timeout_at(
        deadline.into(),
        crate::panic_recovery::join_recoverable(task),
    )
    .await
    {
        Ok(Ok(Ok(Some(body)))) => {
            let mut response = Response::new(axum::body::Body::from(Bytes::from_owner(body)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/x-norito"),
            );
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("private, no-store"),
            );
            response
        }
        Ok(Ok(Ok(None))) => (
            StatusCode::NO_CONTENT,
            [(axum::http::header::CACHE_CONTROL, "private, no-store")],
        )
            .into_response(),
        Ok(Ok(Err(status))) => {
            (status, "native provider attestation read rejected").into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "native provider attestation read unavailable",
        )
            .into_response(),
    }
}

#[cfg(all(test, feature = "app_api"))]
mod tests;
