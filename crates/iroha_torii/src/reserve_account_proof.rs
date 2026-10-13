//! Canonically signed operations-account reads of native reserve partition facts.
//!
//! This works before service activation and proves no collateral, credit, provider
//! admission, original registration inclusion or authority to enable a runtime.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    account::AccountId,
    sorafs::capacity::ProviderId,
    sorafs::reserve::account_proof::{
        MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1, ReserveAccountProofRefV1,
    },
    sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityLimits,
    },
};

const ROUTE: &str = "/v1/sorafs/reserve/providers/{provider_id}/proof/{height}";

fn selectors(provider: &str, height: &str) -> Result<(ProviderId, u64), Error> {
    let mut bytes = [0_u8; 32];
    if provider.len() != 64
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex::decode_to_slice(provider, &mut bytes).is_err()
        || bytes == [0; 32]
    {
        return Err(conversion_error(
            "provider_id must be canonical nonzero lowercase 32-byte hex".into(),
        ));
    }
    let height = height
        .parse::<u64>()
        .ok()
        .filter(|number| *number >= 2 && number.to_string() == height)
        .ok_or_else(|| {
            conversion_error("height must be a canonical non-genesis decimal u64".into())
        })?;
    Ok((ProviderId::new(bytes), height))
}

fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "reserve_account_proof_unavailable",
        message: "Current certified reserve account proof is unavailable.".into(),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn operator(
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
            "Reserve account proof requires canonical account authentication",
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
    axum::extract::Path((provider, height)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    let (provider, height) = selectors(&provider, &height)?;
    let operator = match operator(&app, &headers, &method, &uri) {
        Ok(operator) => operator,
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
        .min(MAX_RESERVE_ACCOUNT_PROOF_BYTES_V1);
    let state = app.state.clone();
    let response = routing::run_admitted_blocking(
        admission,
        "reserve account proof worker failed",
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
            let mut body = norito::core::with_decode_limits_scope(decode_limits, || {
                let tip = crate::native_projection_response::current_global_tip(
                    &view,
                    height,
                    limits,
                    unavailable,
                )?;
                drop(view);
                state
                    .with_native_reserve_account_snapshot_v1(
                        &tip,
                        &operator,
                        provider,
                        &budget,
                        |world, owner, policy, current, credit, capacity, pricing| {
                            let payload = ReserveAccountProofRefV1::new(
                                world, owner, policy, current, credit, capacity, pricing,
                            );
                            crate::native_projection_response::encode(
                                &payload,
                                format,
                                maximum,
                                &budget,
                                unavailable,
                            )
                            .map_err(|_| "reserve account proof encoding refused".to_owned())
                        },
                    )
                    .map_err(|_| unavailable())
            })?;
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
    fn reserve_account_selectors_are_canonical_and_full_width() {
        let provider = "ab".repeat(32);
        assert_eq!(
            selectors(&provider, &u64::MAX.to_string()).unwrap(),
            (ProviderId::new([0xab; 32]), u64::MAX)
        );
        for invalid in ["0", "1", "02", "+2", " 2", "18446744073709551616"] {
            assert!(selectors(&provider, invalid).is_err());
        }
        for invalid in [
            "00".repeat(32),
            "AB".repeat(32),
            "ab".repeat(31),
            "ab".repeat(33),
            "gg".repeat(32),
        ] {
            assert!(selectors(&invalid, "2").is_err());
        }
    }

    #[test]
    fn reserve_account_requires_canonical_operator_authentication() {
        let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            false,
        );
        let uri = format!("/v1/sorafs/reserve/providers/{}/proof/2", "ab".repeat(32))
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            operator(&app, &headers, &axum::http::Method::GET, &uri)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert("X-Iroha-Account", HeaderValue::from_static("untrusted"));
        assert_eq!(
            operator(&app, &headers, &axum::http::Method::GET, &uri)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
