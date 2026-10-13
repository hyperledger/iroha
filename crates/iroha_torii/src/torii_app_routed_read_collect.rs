// Bounded collection and decode helpers for application routed reads.
/// Retain a fixed aggregate failure instead of a skipped route's transport body.
///
/// A proxied response owns its memory reservation until its body is dropped.
/// Keeping that response while fetching the next route can exhaust the same
/// one-slot proxy pool indefinitely. Skipped-route diagnostics are recorded by
/// the caller before this boundary; upstream bodies, headers, extensions and
/// their reservations are discarded without polling or copying them.
#[cfg(feature = "app_api")]
fn summarize_skipped_torii_route_response(response: Response) -> Response {
    let (status, code, message) = if torii_response_has_reject_code(&response, "permission_denied")
    {
        (
            StatusCode::FORBIDDEN,
            "permission_denied",
            "dataspace access is denied",
        )
    } else if response.status() == StatusCode::NOT_FOUND {
        (
            StatusCode::NOT_FOUND,
            "not_found",
            "no dataspace returned a matching result",
        )
    } else if torii_response_has_reject_code(&response, "route_unavailable") {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
            "authoritative dataspace route is unavailable",
        )
    } else {
        // Errors which stop collection, including capacity, authorization and
        // malformed-response failures, must never become skippable failures.
        return response;
    };
    drop(response);
    torii_proxy_error_response(status, code, message)
}

#[cfg(feature = "app_api")]
#[derive(Debug)]
struct ToriiFanoutJsonPayloads {
    payloads: Vec<Value>,
    diagnostics: ToriiFanoutDiagnostics,
    budget: ToriiRoutedReadMemoryBudget,
}
#[cfg(feature = "app_api")]
#[derive(Debug)]
struct ToriiFanoutRoutedJsonPayloads {
    payloads: Vec<(RoutingDecision, Value)>,
    diagnostics: ToriiFanoutDiagnostics,
    budget: ToriiRoutedReadMemoryBudget,
}
/// Decode one bounded authoritative-absence envelope; callers bind its code and selector.
#[cfg(feature = "app_api")]
async fn decode_torii_scoped_absence_response(
    response: Response,
    maximum: usize,
) -> Result<ErrorEnvelope, Response> {
    let invalid = || {
        torii_proxy_error_response(
            StatusCode::BAD_GATEWAY,
            "invalid_proxy_response",
            "scoped absence requires an exact HTTP 404 JSON ErrorEnvelope",
        )
    };
    if response.status() != StatusCode::NOT_FOUND {
        return Err(invalid());
    }
    let mut content_types = response
        .headers()
        .get_all(axum::http::header::CONTENT_TYPE)
        .iter();
    let valid_media = content_types
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
        && content_types.next().is_none();
    if !valid_media {
        return Err(invalid());
    }
    let bytes = axum::body::to_bytes(response.into_body(), maximum.min(4096))
        .await
        .map_err(|_| invalid())?;
    let (decoded, _) = norito::core::with_decode_limits_measured(
        norito::canonical_decode_limits(bytes.len()),
        || norito::json::from_slice::<ErrorEnvelope>(&bytes),
    );
    decoded.map_err(|_| invalid())
}
#[cfg(feature = "app_api")]
async fn collect_torii_pipeline_status_json_payloads<F, Fut>(
    routes: &[RoutingDecision],
    hash: &HashOf<SignedTransaction>,
    working_set_bytes: usize,
    max_body_bytes: usize,
    mut fetch: F,
) -> Result<ToriiFanoutJsonPayloads, Response>
where
    F: FnMut(RoutingDecision) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut unavailable = false;
    let mut budget = ToriiRoutedReadMemoryBudget::new(working_set_bytes, max_body_bytes)?;
    let mut payloads = budget.try_retained_vec(routes.len())?;
    let expected_hash = hash.to_string();
    for route in routes {
        diagnostics.record_attempt();
        let response = fetch(*route).await;
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            if let Err(response) = validate_pipeline_status_absence_response(
                response,
                hash,
                PipelineStatusReadScope::Global,
                max_body_bytes,
            )
            .await
            {
                return Err(with_torii_fanout_headers(response, diagnostics));
            }
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            unavailable = true;
            drop(response);
            continue;
        }
        if response.status() != StatusCode::OK {
            diagnostics.record_skipped_response(&response);
            return Err(with_torii_fanout_headers(response, diagnostics));
        }
        let payload = match torii_json_body_value(response, &mut budget).await {
            Ok(payload) => payload,
            Err(response) => return Err(with_torii_fanout_headers(response, diagnostics)),
        };
        if payload.get("hash").and_then(Value::as_str) != Some(expected_hash.as_str())
            || payload.get("scope").and_then(Value::as_str) != Some("global")
        {
            return Err(with_torii_fanout_headers(
                torii_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "invalid_proxy_response",
                    "pipeline status differs from the exact requested hash and global scope",
                ),
                diagnostics,
            ));
        }
        diagnostics.record_success();
        budget.push_retained(&mut payloads, payload)?;
    }
    if payloads.is_empty() {
        let response = if unavailable || routes.is_empty() {
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "global pipeline status absence cannot be established while a targeted route is unavailable",
            )
        } else {
            pipeline_status_not_found_response(
                hash,
                PipelineStatusReadScope::Global,
                ResponseFormat::Json,
            )
        };
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    // Known positives preserve the supported merge; only absence requires every route.
    Ok(ToriiFanoutJsonPayloads {
        payloads,
        diagnostics,
        budget,
    })
}
#[cfg(feature = "app_api")]
async fn collect_torii_singleton_json_payloads<F, Fut>(
    routes: &[RoutingDecision],
    working_set_bytes: usize,
    max_body_bytes: usize,
    mut fetch: F,
) -> Result<ToriiFanoutJsonPayloads, Response>
where
    F: FnMut(RoutingDecision) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut budget = ToriiRoutedReadMemoryBudget::new(working_set_bytes, max_body_bytes)?;
    let mut payloads = budget.try_retained_vec(routes.len())?;
    for route in routes {
        diagnostics.record_attempt();
        let response = fetch(*route).await;
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            last_not_found = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            last_route_unavailable = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        match torii_json_body_value(response, &mut budget).await {
            Ok(payload) => {
                diagnostics.record_success();
                budget.push_retained(&mut payloads, payload)?;
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return Err(with_torii_fanout_headers(response, diagnostics));
            }
        }
    }
    if payloads.is_empty() {
        let response = last_not_found.unwrap_or_else(|| {
            last_route_unavailable.unwrap_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "no dataspace returned a matching result",
                )
            })
        });
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    Ok(ToriiFanoutJsonPayloads {
        payloads,
        diagnostics,
        budget,
    })
}
#[cfg(feature = "app_api")]
async fn collect_torii_routed_list_json_payloads<F, Fut>(
    routes: &[RoutingDecision],
    working_set_bytes: usize,
    max_body_bytes: usize,
    mut fetch: F,
) -> Result<ToriiFanoutRoutedJsonPayloads, Response>
where
    F: FnMut(RoutingDecision) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut budget = ToriiRoutedReadMemoryBudget::new(working_set_bytes, max_body_bytes)?;
    let mut payloads = budget.try_retained_vec(routes.len())?;
    for route in routes {
        diagnostics.record_attempt();
        let response = fetch(*route).await;
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            last_not_found = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            last_route_unavailable = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        match torii_json_body_value(response, &mut budget).await {
            Ok(payload) => {
                diagnostics.record_success();
                budget.push_retained(&mut payloads, (*route, payload))?;
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return Err(with_torii_fanout_headers(response, diagnostics));
            }
        }
    }
    if payloads.is_empty() {
        let response = last_not_found.unwrap_or_else(|| {
            last_route_unavailable.unwrap_or_else(|| {
                torii_proxy_error_response(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "no dataspace returned a matching result",
                )
            })
        });
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    Ok(ToriiFanoutRoutedJsonPayloads {
        payloads,
        diagnostics,
        budget,
    })
}
#[cfg(feature = "app_api")]
async fn collect_torii_alias_json_payloads<F, Fut>(
    routes: &[RoutingDecision],
    denied_routes: usize,
    permission_denied_message: &'static str,
    working_set_bytes: usize,
    max_body_bytes: usize,
    mut fetch: F,
) -> Result<ToriiFanoutJsonPayloads, Response>
where
    F: FnMut(RoutingDecision) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut last_permission_denied = None;
    let mut budget = ToriiRoutedReadMemoryBudget::new(working_set_bytes, max_body_bytes)?;
    let mut payloads = budget.try_retained_vec(routes.len())?;
    for _ in 0..denied_routes {
        diagnostics.record_denied();
    }
    if routes.is_empty() {
        let response = if diagnostics.denied_routes > 0 {
            torii_alias_permission_denied_response(permission_denied_message)
        } else {
            torii_proxy_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "no visible dataspace returned a matching alias",
            )
        };
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    for route in routes {
        diagnostics.record_attempt();
        let response = fetch(*route).await;
        if torii_response_has_reject_code(&response, "permission_denied") {
            diagnostics.record_denied();
            last_permission_denied = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            last_not_found = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            last_route_unavailable = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        match torii_json_body_value(response, &mut budget).await {
            Ok(payload) => {
                diagnostics.record_success();
                budget.push_retained(&mut payloads, payload)?;
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return Err(with_torii_fanout_headers(response, diagnostics));
            }
        }
    }
    if payloads.is_empty() {
        let response = last_permission_denied.unwrap_or_else(|| {
            if diagnostics.denied_routes > 0 {
                torii_alias_permission_denied_response(permission_denied_message)
            } else {
                last_not_found.unwrap_or_else(|| {
                    last_route_unavailable.unwrap_or_else(|| {
                        torii_proxy_error_response(
                            StatusCode::NOT_FOUND,
                            "not_found",
                            "no dataspace returned a matching result",
                        )
                    })
                })
            }
        });
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    Ok(ToriiFanoutJsonPayloads {
        payloads,
        diagnostics,
        budget,
    })
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn filter_permission_opened_alias_lookup_payload(
    app: &SharedAppState,
    caller: &AccountId,
    mut payload: Value,
) -> Result<Value, Response> {
    let state_view = app.state.view();
    let world = state_view.world();
    let object = payload.as_object_mut().ok_or_else(|| {
        torii_internal_json_error("alias by-account response must be a JSON object")
    })?;
    let items = object
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            torii_internal_json_error("alias by-account response must include an `items` array")
        })?;
    let mut malformed_item = false;
    let mut operational_error = None;
    items.retain(|item| {
        if operational_error.is_some() {
            return false;
        }
        let Some(alias_literal) = item
            .as_object()
            .and_then(|object| object.get("alias"))
            .and_then(Value::as_str)
        else {
            malformed_item = true;
            return false;
        };
        match parse_exact_account_alias_label_with_live_state(app, alias_literal) {
            Ok(alias) => match torii_authority_can_resolve_resolved_account_alias(
                world,
                caller,
                &alias.resolved,
            ) {
                Ok(allowed) => allowed,
                Err(error) => {
                    operational_error = Some(error);
                    false
                }
            },
            Err(
                error @ Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
                )),
            ) => {
                operational_error = Some(error);
                false
            }
            Err(error) => {
                iroha_logger::warn!(alias = %alias_literal, ?error,
                    "Torii alias-by-account permission filter dropped malformed alias literal");
                false
            }
        }
    });
    if let Some(error) = operational_error {
        return Err(error.into_response());
    }
    if malformed_item {
        return Err(torii_internal_json_error(
            "alias by-account items must include string `alias`",
        ));
    }
    let total = u64::try_from(items.len()).map_err(|_| {
        torii_internal_json_error(
            "permission-filtered alias lookup result count does not fit in u64",
        )
    })?;
    let total_value = object.get_mut("total").ok_or_else(|| {
        torii_internal_json_error("alias by-account response must include `total`")
    })?;
    *total_value = Value::from(total);
    Ok(payload)
}
#[cfg(feature = "app_api")]
async fn collect_torii_alias_lookup_json_payloads<F, Fut>(
    app: &SharedAppState,
    routes: &[ToriiAliasLookupRouteAccess],
    (denied_routes, permission_denied_message): (usize, &'static str),
    caller: Option<&AccountId>,
    request: &routing::AliasLookupByAccountRequestDto,
    (working_set_bytes, max_body_bytes): (usize, usize),
    mut fetch: F,
) -> Result<ToriiFanoutJsonPayloads, Response>
where
    F: FnMut(RoutingDecision) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut last_permission_denied = None;
    let mut budget = ToriiRoutedReadMemoryBudget::new(working_set_bytes, max_body_bytes)?;
    let mut payloads = budget.try_retained_vec(routes.len())?;
    for _ in 0..denied_routes {
        diagnostics.record_denied();
    }
    if routes.is_empty() {
        let response = if diagnostics.denied_routes > 0 {
            torii_alias_permission_denied_response(permission_denied_message)
        } else {
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "no authoritative dataspace route was queried for the alias lookup",
            )
        };
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    for route in routes {
        diagnostics.record_attempt();
        let response = fetch(route.route).await;
        if torii_response_has_reject_code(&response, "permission_denied") {
            diagnostics.record_denied();
            last_permission_denied = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            let envelope = decode_torii_scoped_absence_response(
                response,
                iroha_torii_shared::aliases::ACCOUNT_ALIAS_ABSENCE_MAX_BYTES,
            )
            .await
            .map_err(|response| with_torii_fanout_headers(response, diagnostics))?;
            let matches = envelope.code()
                == iroha_torii_shared::aliases::ACCOUNT_ALIASES_BY_ACCOUNT_NOT_FOUND_CODE
                && envelope
                    .details
                    .as_ref()
                    .and_then(|details| details.account_aliases_by_account_not_found.as_ref())
                    .is_some_and(|absence| {
                        absence.matches_selector(
                            &request.account_id,
                            request.dataspace.as_deref(),
                            request.domain.as_deref(),
                        )
                    });
            if !matches {
                return Err(with_torii_fanout_headers(
                    torii_proxy_error_response(
                        StatusCode::BAD_GATEWAY,
                        "invalid_proxy_response",
                        "alias absence does not bind the requested account and scope",
                    ),
                    diagnostics,
                ));
            }
            // Do not retain an upstream response or its memory reservation between routes.
            last_not_found = Some(account_aliases_by_account_not_found_response(request));
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            last_route_unavailable = Some(summarize_skipped_torii_route_response(response));
            continue;
        }
        match torii_json_body_value(response, &mut budget).await {
            Ok(payload) => {
                let payload = if route.filter_by_permission {
                    match caller {
                        Some(caller) => {
                            filter_permission_opened_alias_lookup_payload(app, caller, payload)?
                        }
                        None => payload,
                    }
                } else {
                    payload
                };
                diagnostics.record_success();
                budget.push_retained(&mut payloads, payload)?;
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return Err(with_torii_fanout_headers(response, diagnostics));
            }
        }
    }
    if payloads.is_empty() {
        let response = last_permission_denied.unwrap_or_else(|| {
            if diagnostics.denied_routes > 0 {
                torii_alias_permission_denied_response(permission_denied_message)
            } else {
                last_route_unavailable.unwrap_or_else(|| {
                    last_not_found.unwrap_or_else(|| {
                        torii_proxy_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "route_unavailable",
                            "no authoritative dataspace route completed the alias lookup",
                        )
                    })
                })
            }
        });
        return Err(with_torii_fanout_headers(response, diagnostics));
    }
    Ok(ToriiFanoutJsonPayloads {
        payloads,
        diagnostics,
        budget,
    })
}
#[cfg(feature = "app_api")]
async fn bound_torii_single_route_response(
    response: Response,
    response_format: ToriiProxyResponseFormatV1,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    let body_limit = if status.is_success() {
        budget.route_body_limit()
    } else {
        budget.final_body_limit()
    };
    let body = axum::body::to_bytes(body, body_limit)
        .await
        .map_err(|_| torii_routed_read_body_response())?;
    if !status.is_success() {
        parts.headers.remove(axum::http::header::CONTENT_LENGTH);
        return Ok(Response::from_parts(parts, Body::from(body)));
    }
    match response_format {
        ToriiProxyResponseFormatV1::Json => {
            let plan = budget.decode_plan(body.len())?;
            let profile = budget.json_profile(&body, plan)?;
            let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
                norito::json::from_slice::<Value>(&body)
            });
            let value = value.map_err(torii_routed_read_json_decode_response)?;
            budget.verify_json_value_usage(profile, usage)?;
            budget.retain_decode_usage(usage)?;
            drop(body);
            let canonical = budget.json_body(&value)?;
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            parts.headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Ok(Response::from_parts(
                parts,
                Body::from(Bytes::from(canonical)),
            ))
        }
        ToriiProxyResponseFormatV1::Norito => {
            let header = norito::core::Header::read(std::io::Cursor::new(body.as_ref()))
                .map_err(torii_routed_read_norito_decode_response)?;
            if header.compression != norito::Compression::None
                || header.flags != norito::default_encode_flags()
            {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "route_unavailable",
                    "proxied Norito response used a non-canonical layout",
                ));
            }
            torii_routed_read_ensure(
                "single-route Norito response",
                body.len(),
                budget.final_body_limit(),
            )?;
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            Ok(Response::from_parts(parts, Body::from(body)))
        }
    }
}
#[cfg(feature = "app_api")]
async fn torii_json_body_value(
    response: Response,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<Value, Response> {
    let status = response.status();
    if !status.is_success() {
        return Err(response);
    }
    let body = axum::body::to_bytes(response.into_body(), budget.route_body_limit())
        .await
        .map_err(|_| torii_routed_read_body_response())?;
    let plan = budget.decode_plan(body.len())?;
    let profile = budget.json_profile(&body, plan)?;
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::json::from_slice::<Value>(&body)
    });
    let value = value.map_err(torii_routed_read_json_decode_response)?;
    budget.verify_json_value_usage(profile, usage)?;
    budget.retain_decode_usage(usage)?;
    drop(body);
    let canonical = norito::json::to_json_bounded_boxed(&value, plan.canonical_limit_bytes)
        .map_err(|_| torii_routed_read_json_encode_response())?;
    drop(canonical);
    Ok(value)
}
#[cfg(feature = "app_api")]
async fn torii_json_body<T>(
    response: Response,
    _label: &str,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<ToriiBoundedNoritoPayload<T>, Response>
where
    T: norito::json::JsonDeserializeOwned + norito::core::NoritoSerialize,
{
    let status = response.status();
    if !status.is_success() {
        return Err(response);
    }
    let body = axum::body::to_bytes(response.into_body(), budget.route_body_limit())
        .await
        .map_err(|_| torii_routed_read_body_response())?;
    let plan = budget.decode_plan(body.len())?;
    budget.json_profile(&body, plan)?;
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::json::from_slice::<T>(&body)
    });
    let value = value.map_err(torii_routed_read_json_decode_response)?;
    budget.retain_decode_usage(usage)?;
    drop(body);
    let canonical_bytes = norito::core::to_bytes_bounded(&value, plan.canonical_limit_bytes)
        .map_err(|_| torii_routed_read_norito_encode_response())?;
    budget.retain_canonical_capacity(canonical_bytes.capacity())?;
    Ok(ToriiBoundedNoritoPayload {
        value,
        canonical_bytes,
    })
}
#[cfg(feature = "app_api")]
async fn torii_norito_body<T>(
    response: Response,
    _label: &str,
    budget: &mut ToriiRoutedReadMemoryBudget,
) -> Result<ToriiBoundedNoritoPayload<T>, Response>
where
    T: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    let status = response.status();
    if !status.is_success() {
        return Err(response);
    }
    let body = axum::body::to_bytes(response.into_body(), budget.route_body_limit())
        .await
        .map_err(|_| torii_routed_read_body_response())?;
    let plan = budget.decode_plan(body.len())?;
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::decode_from_bytes_with_limits::<T>(&body, plan.limits)
    });
    let value = value.map_err(torii_routed_read_norito_decode_response)?;
    budget.retain_decode_usage(usage)?;
    drop(body);
    let canonical_bytes = norito::core::to_bytes_bounded(&value, plan.canonical_limit_bytes)
        .map_err(|_| torii_routed_read_norito_encode_response())?;
    budget.retain_canonical_capacity(canonical_bytes.capacity())?;
    Ok(ToriiBoundedNoritoPayload {
        value,
        canonical_bytes,
    })
}
