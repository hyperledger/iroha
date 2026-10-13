//! Canonically authenticated, finalized-lease-bound single-chunk repair transport.

use crate::SharedAppState;
use axum::{
    Extension,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use iroha_core::query::repair_source::authorize_repair_source_v1;
use iroha_data_model::sorafs::repair_source::{
    REPAIR_SOURCE_REQUEST_MAX_BYTES_V1, RepairSourceRequestV1,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> Result<u64, StatusCode> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .as_millis(),
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

pub async fn read_chunk(
    State(state): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    body: Bytes,
) -> Response {
    // The canonical body-authentication middleware has already consumed the nonce.
    let authority = verified.account;
    let permit = match crate::acquire_query_admission(state.as_ref(), true).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let result = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            let _permit = permit;
            let limit = REPAIR_SOURCE_REQUEST_MAX_BYTES_V1;
            let request: RepairSourceRequestV1 = norito::decode_canonical_with_limits(
                &body,
                norito::DecodeLimits::new(limit, limit, limit, limit * 4, 16),
            )
            .map_err(|_| StatusCode::BAD_REQUEST)?;
            if state
                .sorafs_node
                .capacity_provider_id()
                .map(|id| *id.as_bytes())
                != Some(request.source_provider)
            {
                return Err(StatusCode::FORBIDDEN);
            }
            authorize_repair_source_v1(&state.state.view(), &authority, &request, now_ms()?)
                .map_err(|_| StatusCode::FORBIDDEN)?;
            let storage = state
                .sorafs_node
                .storage()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            let manifest_id = hex::encode(request.manifest_digest);
            let record = storage
                .chunk_by_digest(&manifest_id, &request.chunk_digest)
                .map_err(|_| StatusCode::NOT_FOUND)?;
            if record.length != request.chunk_length {
                return Err(StatusCode::CONFLICT);
            }
            let bytes = storage
                .read_chunk(&manifest_id, &request.chunk_digest)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            authorize_repair_source_v1(&state.state.view(), &authority, &request, now_ms()?)
                .map_err(|_| StatusCode::FORBIDDEN)?;
            Ok::<_, StatusCode>(bytes)
        }),
    )
    .await;
    match result {
        Ok(Ok(bytes)) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                (axum::http::header::CACHE_CONTROL, "private, no-store"),
            ],
            bytes,
        )
            .into_response(),
        Ok(Err(code)) => (code, "repair source request rejected").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "repair source unavailable").into_response(),
    }
}
