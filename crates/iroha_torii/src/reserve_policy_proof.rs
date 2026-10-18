//! Account-authenticated reserve policy facts at one native certified World cut.
//!
//! This works before service activation and proves neither initial activation eligibility
//! nor authority to spend, enroll a provider or enable a runtime.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    account::AccountId,
    sorafs::reserve::proof::{MAX_RESERVE_POLICY_PROOF_BYTES_V1, ReservePolicyProofRefV1},
    sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityLimits,
    },
};

const ROUTE: &str = "/v1/sorafs/reserve/policy/{height}";

fn height_selector(value: &str) -> Result<u64, Error> {
    value
        .parse::<u64>()
        .ok()
        .filter(|height| *height >= 2 && height.to_string() == value)
        .ok_or_else(|| {
            conversion_error("height must be a canonical non-genesis decimal u64".into())
        })
}

fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "reserve_policy_proof_unavailable",
        message: "Current certified reserve policy proof is unavailable.".into(),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn manager(
    app: &SharedAppState,
    headers: &HeaderMap,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
) -> Result<AccountId, AxResponse> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(app) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error.into_response());
            }
        };

    let deny = || {
        (
            StatusCode::UNAUTHORIZED,
            "Reserve policy proof requires canonical account authentication",
        )
            .into_response()
    };
    match crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts {
            method,
            uri,
            body: &[],
        },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => Ok(verified.account),
        Ok(None) | Err(_) => Err(deny()),
    }
}

pub async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<String>,
    headers: HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    let height = height_selector(&height)?;
    let manager = match manager(&app, &headers, &method, &uri) {
        Ok(manager) => manager,
        Err(response) => return Ok(response),
    };
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([
            u64::try_from(bytes).map_err(|_| crate::native_projection_response::capacity())?
        ])
        .ok_or_else(crate::native_projection_response::capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_RESERVE_POLICY_PROOF_BYTES_V1);
    let state = app.state.clone();
    let response = routing::run_admitted_blocking(
        admission,
        "reserve policy proof worker failed",
        move || {
            let capacity = crate::native_projection_response::capacity;
            let unit = bytes / 8;
            let limits = NativeFinalityLimits {
                block_bytes: unit.min(NATIVE_FINALITY_MAX_BLOCK_BYTES),
                journal_bytes: (unit * 2).min(NATIVE_FINALITY_MAX_JOURNAL_BYTES),
                block_count: 8,
                allocated_bytes: unit * 4,
            };
            let decode_limits = limits.decode_limits().map_err(|_| capacity())?;
            let _source_charge = budget
                .try_reserve_bytes(limits.journal_bytes + limits.allocated_bytes)
                .map_err(|_| capacity())?;
            let view = state.view();
            let tip = norito::core::with_decode_limits_scope(decode_limits, || {
                crate::native_projection_response::current_global_tip(
                    &view,
                    height,
                    limits,
                    unavailable,
                )
            })?;
            drop(view);
            let mut body = state
                .with_native_reserve_policy_snapshot_v1(
                    &tip,
                    &manager,
                    &budget,
                    |world, permissions, current| {
                        let payload = ReservePolicyProofRefV1::new(world, permissions, current);
                        crate::native_projection_response::encode(
                            &payload, format, maximum, &budget,
                        )
                        .map_err(|_| "reserve policy proof encoding refused".to_owned())
                    },
                )
                .map_err(|_| unavailable())?;
            body.memory = Some(memory);
            let mut response = AxResponse::new(Body::from(Bytes::from_owner(body)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(match format {
                    ResponseFormat::Norito => "application/x-norito",
                    ResponseFormat::Json => "application/json",
                }),
            );
            Ok(response)
        },
    )
    .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_policy_height_is_canonical_non_genesis_and_full_width() {
        assert_eq!(height_selector("2").unwrap(), 2);
        assert_eq!(height_selector(&u64::MAX.to_string()).unwrap(), u64::MAX);
        for invalid in ["0", "1", "02", "+2", " 2", "18446744073709551616"] {
            assert!(height_selector(invalid).is_err());
        }
    }

    #[test]
    fn reserve_policy_proof_rejects_missing_or_bare_account_authentication() {
        let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            false,
        );
        let uri = "/v1/sorafs/reserve/policy/2".parse().unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            manager(&app, &headers, &axum::http::Method::GET, &uri)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert("X-Iroha-Account", HeaderValue::from_static("untrusted"));
        assert_eq!(
            manager(&app, &headers, &axum::http::Method::GET, &uri)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
