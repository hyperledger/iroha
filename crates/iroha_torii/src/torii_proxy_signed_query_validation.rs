#[cfg(feature = "connect")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxySignedQueryReplayScope {
    Client,
    RouteScanDeferred,
}
#[cfg(feature = "connect")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_verified_proxy_signed_query(
    query_bytes: &[u8],
    request_kind: &'static str,
    admission: &routing::SignedQueryAdmission,
    limits: norito::DecodeLimits,
    replay_scope: ProxySignedQueryReplayScope,
) -> Result<iroha_data_model::query::QueryRequestWithAuthority, Response> {
    let decode = || {
        <SignedQuery as iroha_version::codec::DecodeVersioned>::decode_all_versioned(query_bytes)
    };
    let query = norito::with_decode_limits_scope(limits, decode).map_err(|error| {
        let resource_limit = error.is_decode_resource_limit();
        torii_proxy_error_response(
            if resource_limit {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            },
            if resource_limit {
                "query_capacity_exceeded"
            } else {
                "invalid_proxy_request"
            },
            if resource_limit {
                "proxied signed-query decoding exceeded its admitted memory envelope"
            } else {
                match request_kind {
                    "proxied route-scan" => {
                        "failed to decode the exact proxied route-scan signed query"
                    }
                    "Nexus fanout" => "failed to decode the exact Nexus fanout signed query",
                    _ => "failed to decode the exact proxied signed query",
                }
            },
        )
    })?;
    match replay_scope {
        ProxySignedQueryReplayScope::Client => {
            routing::verify_signed_query_request(query, admission)
        }
        ProxySignedQueryReplayScope::RouteScanDeferred => {
            routing::authenticate_signed_query_route_scan_request(query, admission)
        }
    }
    .map_err(IntoResponse::into_response)
}
#[cfg(feature = "connect")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn reject_proxy_client_continuation(
    request: &iroha_data_model::query::QueryRequestWithAuthority,
    request_kind: &'static str,
) -> Result<(), Response> {
    if matches!(
        &request.request,
        iroha_data_model::query::QueryRequest::Continue(_)
    ) {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "query_unsupported",
            format!("{request_kind} does not accept client-provided continuations"),
        ));
    }
    Ok(())
}
#[cfg(feature = "connect")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_proxy_signed_query_route(
    authority: &AccountId,
    authorized_routes: &[RoutingDecision],
    expected_route: RoutingDecision,
) -> Result<(), Response> {
    if authorized_routes.contains(&expected_route) {
        Ok(())
    } else {
        Err(torii_signed_query_permission_denied_response(authority, 1))
    }
}
