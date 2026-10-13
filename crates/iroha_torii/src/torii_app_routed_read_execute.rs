/// Exact endpoint, path, query and body forwarded together to every selected route.
#[cfg(feature = "app_api")]
struct ToriiReadPayload {
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    body: Vec<u8>,
}

// Routed-read execution under one shared fanout reservation. Source-bounded
// local producer seams remain intentionally incremental and inventoried.
#[cfg(feature = "app_api")]
fn merge_with_torii_fanout_headers<F>(diagnostics: ToriiFanoutDiagnostics, merge: F) -> Response
where
    F: FnOnce() -> Result<Response, Response>,
{
    match merge() {
        Ok(response) | Err(response) => with_torii_fanout_headers(response, diagnostics),
    }
}
#[cfg(feature = "app_api")]
async fn resolve_torii_proof_record_for_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    proof_id: String,
) -> Result<
    (
        ProofRecord,
        ToriiFanoutDiagnostics,
        &'static str,
        QueryFanoutMemoryReservation,
    ),
    Response,
> {
    let reservation = try_acquire_query_fanout_memory(app)?;
    match COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            reservation.clone(),
            resolve_torii_proof_record_for_supported_routes(app, routes, proof_id),
        )
        .await
    {
        Ok((record, diagnostics, routed_by)) => Ok((record, diagnostics, routed_by, reservation)),
        Err(response) => Err(hold_query_fanout_memory_in_response_body(
            response,
            reservation,
        )),
    }
}
#[cfg(feature = "app_api")]
async fn resolve_torii_proof_record_for_supported_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    proof_id: String,
) -> Result<(ProofRecord, ToriiFanoutDiagnostics, &'static str), Response> {
    if routes.is_empty() {
        return Err(with_torii_fanout_headers(
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "no Nexus dataspace routes are configured",
            ),
            ToriiFanoutDiagnostics::default(),
        ));
    }
    let routed_by = routed_by_for_routes(app, &routes);
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut budget = torii_local_routed_read_budget(app)?;
    let payload_capacity = routes
        .len()
        .checked_add(1)
        .ok_or_else(torii_routed_read_accounting_response)?;
    let mut payloads = budget.try_retained_vec(payload_capacity)?;
    let parsed_proof_id = proof_id
        .parse::<iroha_data_model::proof::ProofId>()
        .map_err(|error| {
            torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_proof_id",
                format!("failed to parse proof id `{proof_id}`: {error}"),
            )
        })?;
    if let Some(payload) =
        torii_bounded_local_proof_record_payload(app, &parsed_proof_id, &mut budget)?
    {
        budget.push_retained(&mut payloads, payload)?;
    }
    for route in &routes {
        diagnostics.record_attempt();
        let mut request = torii_read_request(
            ToriiReadEndpointV1::ProofRecordGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            *route,
            vec![proof_id.clone()],
            None,
            Vec::new(),
        );
        // The bounded merge decodes a canonical ProofRecord archive. Request
        // that same representation from both local and remote route producers.
        request.response_format = ToriiProxyResponseFormatV1::Norito;
        let response = execute_torii_read_for_route(app, *route, request, None).await;
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
        match torii_norito_body::<ProofRecord>(response, "proof record response", &mut budget).await
        {
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
    budget.begin_typed_merge();
    budget.admit_merge_btree::<Vec<u8>, ProofRecord>(1, payloads.len())?;
    let mut unique_payloads = BTreeMap::<Vec<u8>, ProofRecord>::new();
    for payload in payloads {
        unique_payloads
            .entry(payload.canonical_bytes)
            .or_insert(payload.value);
    }
    match unique_payloads.len() {
        1 => Ok((
            unique_payloads
                .into_values()
                .next()
                .expect("singleton map length should be one"),
            diagnostics,
            routed_by,
        )),
        _ => Err(with_torii_fanout_headers(
            torii_proxy_error_response(
                StatusCode::CONFLICT,
                "route_conflict",
                "multiple dataspaces returned conflicting singleton results",
            ),
            diagnostics,
        )),
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_trusted_internal_read_response<T>(
    payloads: Vec<ToriiBoundedNoritoPayload<T>>,
    format: ResponseFormat,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response>
where
    T: JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    budget.begin_typed_merge();
    budget.admit_merge_btree::<Vec<u8>, T>(1, payloads.len())?;
    let mut unique_payloads = BTreeMap::<Vec<u8>, T>::new();
    for payload in payloads {
        unique_payloads
            .entry(payload.canonical_bytes)
            .or_insert(payload.value);
    }
    match unique_payloads.len() {
        0 => Err(trusted_internal_read_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no target-account route returned the exact resource",
            format,
        )),
        1 => {
            let (canonical_bytes, payload) = unique_payloads
                .into_iter()
                .next()
                .expect("singleton map length should be one");
            let mut response = match format {
                ResponseFormat::Norito => Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
                    )
                    .body(Body::from(canonical_bytes))
                    .expect("build preflighted trusted routed-read response"),
                ResponseFormat::Json => {
                    drop(canonical_bytes);
                    budget.json_response(&payload)?
                }
            };
            insert_routed_by_header(&mut response, routed_by);
            Ok(response)
        }
        _ => Err(trusted_internal_read_error_response(
            StatusCode::CONFLICT,
            "route_conflict",
            "target-account routes returned conflicting exact resources",
            format,
        )),
    }
}
#[cfg(feature = "app_api")]
async fn execute_torii_trusted_internal_read_for_resolved_routes<T>(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    format: ResponseFormat,
    response_label: &'static str,
) -> Response
where
    T: JsonSerialize
        + for<'de> norito::core::NoritoDeserialize<'de>
        + norito::core::NoritoSerialize
        + 'static,
{
    execute_torii_trusted_internal_read_for_supported_routes::<T>(
        app,
        routes,
        endpoint,
        path_args,
        query_string,
        format,
        response_label,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_trusted_internal_read_for_supported_routes<T>(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    format: ResponseFormat,
    response_label: &'static str,
) -> Response
where
    T: JsonSerialize
        + for<'de> norito::core::NoritoDeserialize<'de>
        + norito::core::NoritoSerialize
        + 'static,
{
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(reservation) => reservation,
        Err(response) => return response,
    };
    let admission = ToriiRoutedReadMemoryBudget::from_envelope(
        match reservation.admitted_envelope(app) {
            Ok(envelope) => envelope,
            Err(response) => {
                return hold_query_fanout_memory_in_response_body(response, reservation);
            }
        },
        app.torii_proxy_max_response_bytes,
    );
    let empty_body: Vec<u8> = Vec::new();
    let request_bytes = match torii_routed_read_request_bytes(
        &path_args,
        path_args.capacity(),
        query_string.as_ref(),
        empty_body.capacity(),
    ) {
        Ok(bytes) => bytes,
        Err(response) => {
            return hold_query_fanout_memory_in_response_body(response, reservation);
        }
    };
    if let Err(response) = admission.admit_request_bytes(request_bytes) {
        return hold_query_fanout_memory_in_response_body(response, reservation);
    }
    let response = COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            reservation.clone(),
            execute_torii_trusted_internal_read_for_resolved_routes_admitted::<T>(
                app,
                routes,
                endpoint,
                path_args,
                query_string,
                format,
                response_label,
            ),
        )
        .await;
    hold_query_fanout_memory_in_response_body(response, reservation)
}
#[cfg(feature = "app_api")]
async fn execute_torii_trusted_internal_read_for_resolved_routes_admitted<T>(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    format: ResponseFormat,
    response_label: &'static str,
) -> Response
where
    T: JsonSerialize
        + for<'de> norito::core::NoritoDeserialize<'de>
        + norito::core::NoritoSerialize
        + 'static,
{
    if routes.is_empty() {
        return with_torii_fanout_headers(
            trusted_internal_read_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "no target-account dataspace routes are configured",
                format,
            ),
            ToriiFanoutDiagnostics::default(),
        );
    }
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut saw_not_found = false;
    let mut saw_route_unavailable = false;
    let mut budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    let mut payloads = match budget.try_retained_vec(routes.len()) {
        Ok(payloads) => payloads,
        Err(response) => return response,
    };
    for route in &routes {
        diagnostics.record_attempt();
        let mut request = torii_read_request(
            endpoint,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            *route,
            path_args.clone(),
            query_string.clone(),
            Vec::new(),
        );
        request.response_format = ToriiProxyResponseFormatV1::Norito;
        let response = execute_torii_read_for_route(app, *route, request, None).await;
        if response.status() == StatusCode::NOT_FOUND {
            diagnostics.record_skipped_response(&response);
            saw_not_found = true;
            continue;
        }
        if torii_response_has_reject_code(&response, "route_unavailable") {
            diagnostics.record_skipped_response(&response);
            saw_route_unavailable = true;
            continue;
        }
        match torii_norito_body::<T>(response, response_label, &mut budget).await {
            Ok(payload) => {
                diagnostics.record_success();
                if let Err(response) = budget.push_retained(&mut payloads, payload) {
                    return with_torii_fanout_headers(response, diagnostics);
                }
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return with_torii_fanout_headers(response, diagnostics);
            }
        }
    }
    if payloads.is_empty() {
        let response = if saw_not_found {
            trusted_internal_read_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "no target-account route returned the exact resource",
                format,
            )
        } else if saw_route_unavailable {
            trusted_internal_read_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "no target-account route was available",
                format,
            )
        } else {
            trusted_internal_read_error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "no target-account route returned the exact resource",
                format,
            )
        };
        return with_torii_fanout_headers(response, diagnostics);
    }
    merge_with_torii_fanout_headers(diagnostics, || {
        merged_trusted_internal_read_response(
            payloads,
            format,
            routed_by_for_routes(app, &routes),
            budget,
        )
    })
}
#[cfg(feature = "app_api")]
async fn execute_torii_internal_account_read_for_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    canonical_account_id: String,
    format: ResponseFormat,
) -> Response {
    execute_torii_trusted_internal_read_for_resolved_routes::<InternalAccountReadResponse>(
        app,
        routes,
        ToriiReadEndpointV1::InternalAccountGet,
        vec![canonical_account_id],
        None,
        format,
        "trusted internal account response",
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_internal_account_transaction_read_for_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    canonical_account_id: String,
    canonical_entrypoint_hash: String,
    format: ResponseFormat,
) -> Response {
    execute_torii_trusted_internal_read_for_resolved_routes::<
        iroha_data_model::query::CommittedTransaction,
    >(
        app,
        routes,
        ToriiReadEndpointV1::InternalAccountTransactionGet,
        vec![canonical_account_id, canonical_entrypoint_hash],
        None,
        format,
        "trusted internal committed transaction response",
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_internal_account_asset_read_for_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    canonical_account_id: String,
    canonical_asset_definition_id: String,
    canonical_scope: String,
    format: ResponseFormat,
) -> Response {
    let query_string = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("scope", &canonical_scope);
        serializer.finish()
    };
    execute_torii_trusted_internal_read_for_resolved_routes::<Asset>(
        app,
        routes,
        ToriiReadEndpointV1::InternalAccountAssetGet,
        vec![canonical_account_id, canonical_asset_definition_id],
        Some(query_string),
        format,
        "trusted internal account asset response",
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_account_read_for_resolved_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    canonical_account_id: String,
    format: ResponseFormat,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Response {
    if routes.is_empty() {
        return with_torii_fanout_headers(
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "no Nexus dataspace routes are configured",
            ),
            ToriiFanoutDiagnostics::default(),
        );
    }
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    let mut last_not_found = None;
    let mut last_route_unavailable = None;
    let mut budget = match torii_local_routed_read_budget(app) {
        Ok(budget) => budget,
        Err(response) => return response,
    };
    let mut payloads = match budget.try_retained_vec(routes.len()) {
        Ok(payloads) => payloads,
        Err(response) => return response,
    };
    for route in &routes {
        diagnostics.record_attempt();
        let response = execute_torii_read_for_route(
            app,
            *route,
            torii_read_request(
                ToriiReadEndpointV1::AccountGet,
                route_scope.clone(),
                *route,
                vec![canonical_account_id.clone()],
                None,
                Vec::new(),
            ),
            proxy_memory.clone(),
        )
        .await;
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
        match torii_json_body::<AccountReadResponse>(response, "account get response", &mut budget)
            .await
        {
            Ok(payload) => {
                diagnostics.record_success();
                if let Err(response) = budget.push_retained(&mut payloads, payload) {
                    return with_torii_fanout_headers(response, diagnostics);
                }
            }
            Err(response) => {
                diagnostics.record_skipped_response(&response);
                return with_torii_fanout_headers(response, diagnostics);
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
        return with_torii_fanout_headers(response, diagnostics);
    }
    merge_with_torii_fanout_headers(diagnostics, || {
        merged_account_read_response(payloads, format, routed_by_for_routes(app, &routes), budget)
    })
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_fanout_for_resolved_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    merge: ToriiReadFanoutMergeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    response_format: ToriiProxyResponseFormatV1,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Response {
    execute_torii_read_for_supported_resolved_routes(
        app,
        routes,
        route_scope,
        merge,
        crate::ToriiReadPayload {
            endpoint,
            path_args,
            query_string,
            body,
        },
        response_format,
        proxy_memory,
    )
    .await
}
/// Execute an authenticated incoming Read request inside one complete fanout
/// working-set reservation.
///
/// The request representation is admitted before route execution. The local response is then
/// collected and canonicalized under the same envelope, and the permit moves into the returned body
/// so transport buffering cannot release it early.
#[cfg(feature = "app_api")]
async fn execute_incoming_torii_read_request_locally_bounded(
    app: &SharedAppState,
    read_request: ToriiReadProxyRequestV1,
    routing_decision: RoutingDecision,
) -> Response {
    execute_torii_read_request_locally(app, read_request, routing_decision, "proxy").await
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_request_locally(
    app: &SharedAppState,
    read_request: ToriiReadProxyRequestV1,
    routing_decision: RoutingDecision,
    routed_by: &'static str,
) -> Response {
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(reservation) => reservation,
        Err(response) => return response,
    };
    let mut budget = ToriiRoutedReadMemoryBudget::from_envelope(
        match reservation.admitted_envelope(app) {
            Ok(envelope) => envelope,
            Err(response) => {
                return hold_query_fanout_memory_in_response_body(response, reservation);
            }
        },
        app.torii_proxy_max_response_bytes,
    );
    let request_bytes = match torii_routed_read_request_bytes(
        &read_request.path_args,
        read_request.path_args.capacity(),
        read_request.query_string.as_ref(),
        read_request.body.capacity(),
    ) {
        Ok(bytes) => bytes,
        Err(response) => {
            return hold_query_fanout_memory_in_response_body(response, reservation);
        }
    };
    if let Err(response) = budget.admit_request_bytes(request_bytes) {
        return hold_query_fanout_memory_in_response_body(response, reservation);
    }
    let response_format = read_request.response_format;
    let response = COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            reservation.clone(),
            execute_torii_read_request_locally_admitted(
                app,
                read_request,
                routing_decision,
                routed_by,
            ),
        )
        .await;
    let response =
        match bound_torii_single_route_response(response, response_format, &mut budget).await {
            Ok(response) | Err(response) => response,
        };
    hold_query_fanout_memory_in_response_body(response, reservation)
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_for_supported_resolved_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    merge: ToriiReadFanoutMergeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    response_format: ToriiProxyResponseFormatV1,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Response {
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(reservation) => reservation,
        Err(response) => return response,
    };
    let admission = ToriiRoutedReadMemoryBudget::from_envelope(
        match reservation.admitted_envelope(app) {
            Ok(envelope) => envelope,
            Err(response) => {
                return hold_query_fanout_memory_in_response_body(response, reservation);
            }
        },
        app.torii_proxy_max_response_bytes,
    );
    let request_bytes = match torii_routed_read_request_bytes(
        &path_args,
        path_args.capacity(),
        query_string.as_ref(),
        body.capacity(),
    ) {
        Ok(bytes) => bytes,
        Err(response) => {
            return hold_query_fanout_memory_in_response_body(response, reservation);
        }
    };
    if let Err(response) = admission.admit_request_bytes(request_bytes) {
        return hold_query_fanout_memory_in_response_body(response, reservation);
    }
    let response = COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            reservation.clone(),
            execute_torii_read_fanout_for_resolved_routes_admitted(
                app,
                routes,
                route_scope,
                merge,
                crate::ToriiReadPayload {
                    endpoint,
                    path_args,
                    query_string,
                    body,
                },
                response_format,
                proxy_memory,
            ),
        )
        .await;
    hold_query_fanout_memory_in_response_body(response, reservation)
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_fanout_for_resolved_routes_admitted(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    merge: ToriiReadFanoutMergeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    response_format: ToriiProxyResponseFormatV1,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Response {
    if let Some(target) = collection_target_for_read(endpoint, &path_args) {
        let plan = match torii_routed_read_request_decode_plan(app) {
            Ok(plan) => plan,
            Err(response) => return response,
        };
        let query =
            match decode_routed_collection_query(plan, endpoint, query_string.as_deref(), &body) {
                Ok(query) => query,
                Err(response) => return response,
            };
        let (query, _, _reservation) = match prepare_collection_forward(app, &target, query) {
            Ok(prepared) => prepared,
            Err(error) => return error.into_response(),
        };
        let Some(route) = collection_execution_route(app.as_ref(), &routes) else {
            return empty_collection_page_response(
                routed_by_for_routes(app, &[]),
                query.include_total,
            );
        };
        return execute_torii_read_for_route(
            app,
            route,
            torii_read_request(endpoint, route_scope, route, path_args, query_string, body),
            proxy_memory,
        )
        .await;
    }
    match merge {
        ToriiReadFanoutMergeV1::List => {
            match execute_torii_fanout_json_payloads_resolved_routes(
                app,
                routes,
                route_scope,
                crate::ToriiReadPayload {
                    endpoint,
                    path_args,
                    query_string,
                    body,
                },
                proxy_memory,
            )
            .await
            {
                Ok((payloads, diagnostics, routed_by, budget)) => {
                    merge_with_torii_fanout_headers(diagnostics, || {
                        merged_list_response(payloads, endpoint, routed_by, budget)
                    })
                }
                Err(response) => response,
            }
        }
        ToriiReadFanoutMergeV1::Singleton => {
            if routes.is_empty() {
                return with_torii_fanout_headers(
                    torii_proxy_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "route_unavailable",
                        "no Nexus dataspace routes are configured",
                    ),
                    ToriiFanoutDiagnostics::default(),
                );
            }
            if matches!(endpoint, ToriiReadEndpointV1::PipelineTransactionStatusGet) {
                let decode_plan = match torii_routed_read_request_decode_plan(app) {
                    Ok(plan) => plan,
                    Err(response) => return response,
                };
                let query = match decode_torii_proxy_string_query::<PipelineStatusQuery>(
                    decode_plan,
                    query_string.as_deref(),
                ) {
                    Ok(query) => query,
                    Err(response) => return response,
                };
                let hash = match query
                    .hash
                    .as_deref()
                    .ok_or_else(|| conversion_error("missing hash query parameter".to_owned()))
                    .and_then(parse_signed_transaction_hash)
                {
                    Ok(hash) => hash,
                    Err(error) => return error.into_response(),
                };
                if !matches!(
                    parse_pipeline_status_scope(query.scope.as_deref()),
                    Ok(PipelineStatusReadScope::Global)
                ) {
                    return conversion_error(
                        "pipeline status fanout requires global scope".to_owned(),
                    )
                    .into_response();
                }
                let collected = match collect_torii_pipeline_status_json_payloads(
                    &routes,
                    &hash,
                    match current_routed_read_memory_envelope(app) {
                        Ok(envelope) => envelope.working_set_bytes,
                        Err(response) => return response,
                    },
                    app.torii_proxy_max_response_bytes,
                    |route| {
                        execute_torii_read_for_route(
                            app,
                            route,
                            torii_read_request(
                                endpoint,
                                route_scope.clone(),
                                route,
                                path_args.clone(),
                                query_string.clone(),
                                body.clone(),
                            ),
                            proxy_memory.clone(),
                        )
                    },
                )
                .await
                {
                    Ok(collected) => collected,
                    Err(response) => return response,
                };
                return merge_with_torii_fanout_headers(collected.diagnostics, || {
                    merged_pipeline_status_response(
                        collected.payloads,
                        routed_by_for_routes(app, &routes),
                        collected.budget,
                    )
                });
            }
            let collected = match collect_torii_singleton_json_payloads(
                &routes,
                match current_routed_read_memory_envelope(app) {
                    Ok(envelope) => envelope.working_set_bytes,
                    Err(response) => return response,
                },
                app.torii_proxy_max_response_bytes,
                |route| {
                    execute_torii_read_for_route(
                        app,
                        route,
                        torii_read_request(
                            endpoint,
                            route_scope.clone(),
                            route,
                            path_args.clone(),
                            query_string.clone(),
                            body.clone(),
                        ),
                        proxy_memory.clone(),
                    )
                },
            )
            .await
            {
                Ok(payloads) => payloads,
                Err(response) => return response,
            };
            merge_with_torii_fanout_headers(collected.diagnostics, || {
                merged_singleton_response(
                    collected.payloads,
                    routed_by_for_routes(app, &routes),
                    collected.budget,
                )
            })
        }
        ToriiReadFanoutMergeV1::Account => {
            let Some(canonical_account_id) = path_args.first().cloned() else {
                return torii_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_proxy_request",
                    "missing proxied path argument `account_id`",
                );
            };
            execute_torii_account_read_for_resolved_routes(
                app,
                routes,
                route_scope,
                canonical_account_id,
                response_format_from_torii_proxy(response_format),
                proxy_memory,
            )
            .await
        }
        ToriiReadFanoutMergeV1::Portfolio => {
            match execute_torii_fanout_json_payloads_resolved_routes(
                app,
                routes,
                route_scope,
                crate::ToriiReadPayload {
                    endpoint,
                    path_args,
                    query_string,
                    body,
                },
                proxy_memory,
            )
            .await
            {
                Ok((payloads, diagnostics, routed_by, budget)) => {
                    merge_with_torii_fanout_headers(diagnostics, || {
                        merged_portfolio_response(payloads, routed_by, budget)
                    })
                }
                Err(response) => response,
            }
        }
        ToriiReadFanoutMergeV1::DataspaceSummary => {
            match execute_torii_fanout_json_payloads_resolved_routes(
                app,
                routes,
                route_scope,
                crate::ToriiReadPayload {
                    endpoint,
                    path_args,
                    query_string,
                    body,
                },
                proxy_memory,
            )
            .await
            {
                Ok((payloads, diagnostics, routed_by, budget)) => {
                    merge_with_torii_fanout_headers(diagnostics, || {
                        merged_dataspace_summary_response(payloads, routed_by, budget)
                    })
                }
                Err(response) => response,
            }
        }
        ToriiReadFanoutMergeV1::SpaceDirectoryBindings => {
            match execute_torii_fanout_json_payloads_resolved_routes(
                app,
                routes,
                route_scope,
                crate::ToriiReadPayload {
                    endpoint,
                    path_args,
                    query_string,
                    body,
                },
                proxy_memory,
            )
            .await
            {
                Ok((payloads, diagnostics, routed_by, budget)) => {
                    merge_with_torii_fanout_headers(diagnostics, || {
                        merged_space_directory_bindings_response(payloads, routed_by, budget)
                    })
                }
                Err(response) => response,
            }
        }
    }
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_fanout_proxy_request(
    app: &SharedAppState,
    request: ToriiReadFanoutProxyRequestV1,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Response {
    let routes = match torii_fanout_scope_routes(app.as_ref(), &request.route_scope) {
        Ok(routes) => routes,
        Err(response) => return response,
    };
    execute_torii_read_fanout_for_resolved_routes(
        app,
        routes,
        request.route_scope,
        request.merge,
        crate::ToriiReadPayload {
            endpoint: request.endpoint,
            path_args: request.path_args,
            query_string: request.query_string,
            body: request.body,
        },
        request.response_format,
        proxy_memory,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_fanout_via_nexus(
    app: &SharedAppState,
    route_scope: ToriiFanoutRouteScopeV1,
    merge: ToriiReadFanoutMergeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    response_format: ToriiProxyResponseFormatV1,
) -> Response {
    let routes = match torii_fanout_scope_routes(app.as_ref(), &route_scope) {
        Ok(routes) => routes,
        Err(response) => return response,
    };
    execute_torii_read_via_nexus_for_supported_routes(
        app,
        routes,
        route_scope,
        merge,
        crate::ToriiReadPayload {
            endpoint,
            path_args,
            query_string,
            body,
        },
        response_format,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_read_via_nexus_for_supported_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    merge: ToriiReadFanoutMergeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    response_format: ToriiProxyResponseFormatV1,
) -> Response {
    if routes.len() <= 1 {
        return execute_torii_read_fanout_for_resolved_routes(
            app,
            routes,
            route_scope,
            merge,
            crate::ToriiReadPayload {
                endpoint,
                path_args,
                query_string,
                body,
            },
            response_format,
            None,
        )
        .await;
    }
    let request = torii_read_fanout_request(
        endpoint,
        route_scope,
        merge,
        path_args,
        query_string,
        body,
        response_format,
    );
    let nexus_route = match torii_nexus_route(app.as_ref()) {
        Ok(route) => route,
        Err(response) => return response,
    };
    if should_execute_route_locally(app.as_ref(), nexus_route) {
        return execute_torii_read_fanout_proxy_request(app, request, None).await;
    }
    execute_torii_proxy_request_with_fallback(
        app,
        nexus_route,
        ToriiProxyRequestKindV1::ReadFanout(request),
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_public_pipeline_status_fanout(
    app: &SharedAppState,
    query_string: Option<String>,
) -> Response {
    // Pipeline status is a closed, redacted public projection. Unlike data-bearing singleton
    // reads, its route contract deliberately spans every dataspace without a caller identity.
    execute_torii_read_fanout_via_nexus(
        app,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        ToriiReadFanoutMergeV1::Singleton,
        crate::ToriiReadPayload {
            endpoint: ToriiReadEndpointV1::PipelineTransactionStatusGet,
            path_args: Vec::new(),
            query_string,
            body: Vec::new(),
        },
        ToriiProxyResponseFormatV1::Json,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_visible_fanout_singleton_read(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    body: Vec<u8>,
) -> Response {
    execute_torii_read_fanout_via_nexus(
        app,
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: caller.map(ToString::to_string),
        },
        ToriiReadFanoutMergeV1::Singleton,
        crate::ToriiReadPayload {
            endpoint,
            path_args,
            query_string,
            body,
        },
        ToriiProxyResponseFormatV1::Json,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_singleton_read_for_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    query_string: Option<String>,
    body: Vec<u8>,
) -> Response {
    if routes.len() > 1 {
        execute_torii_read_fanout_via_nexus(
            app,
            route_scope,
            ToriiReadFanoutMergeV1::Singleton,
            crate::ToriiReadPayload {
                endpoint,
                path_args,
                query_string,
                body,
            },
            ToriiProxyResponseFormatV1::Json,
        )
        .await
    } else {
        execute_torii_read_fanout_for_resolved_routes(
            app,
            routes,
            route_scope,
            ToriiReadFanoutMergeV1::Singleton,
            crate::ToriiReadPayload {
                endpoint,
                path_args,
                query_string,
                body,
            },
            ToriiProxyResponseFormatV1::Json,
            None,
        )
        .await
    }
}
#[cfg(feature = "app_api")]
async fn execute_torii_account_read_for_routes_scoped(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    canonical_account_id: String,
    format: ResponseFormat,
) -> Response {
    if routes.len() > 1 {
        execute_torii_read_fanout_via_nexus(
            app,
            route_scope,
            ToriiReadFanoutMergeV1::Account,
            crate::ToriiReadPayload {
                endpoint: ToriiReadEndpointV1::AccountGet,
                path_args: vec![canonical_account_id],
                query_string: None,
                body: Vec::new(),
            },
            torii_proxy_response_format(format),
        )
        .await
    } else {
        execute_torii_read_fanout_for_resolved_routes(
            app,
            routes,
            route_scope,
            ToriiReadFanoutMergeV1::Account,
            crate::ToriiReadPayload {
                endpoint: ToriiReadEndpointV1::AccountGet,
                path_args: vec![canonical_account_id],
                query_string: None,
                body: Vec::new(),
            },
            torii_proxy_response_format(format),
            None,
        )
        .await
    }
}
#[cfg(feature = "app_api")]
async fn execute_torii_visible_fanout_portfolio_read(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    uaid_literal: String,
    query_string: Option<String>,
) -> Response {
    execute_torii_read_fanout_via_nexus(
        app,
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: caller.map(ToString::to_string),
        },
        ToriiReadFanoutMergeV1::Portfolio,
        crate::ToriiReadPayload {
            endpoint: ToriiReadEndpointV1::AccountsPortfolio,
            path_args: vec![uaid_literal],
            query_string,
            body: Vec::new(),
        },
        ToriiProxyResponseFormatV1::Json,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_visible_fanout_dataspace_summary_read(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    account_literal: String,
    query_string: Option<String>,
) -> Response {
    execute_torii_read_fanout_via_nexus(
        app,
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: caller.map(ToString::to_string),
        },
        ToriiReadFanoutMergeV1::DataspaceSummary,
        crate::ToriiReadPayload {
            endpoint: ToriiReadEndpointV1::NexusDataspacesAccountSummary,
            path_args: vec![account_literal],
            query_string,
            body: Vec::new(),
        },
        ToriiProxyResponseFormatV1::Json,
    )
    .await
}
#[cfg(feature = "app_api")]
async fn execute_torii_visible_fanout_space_directory_bindings_read(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    uaid_literal: String,
    query_string: Option<String>,
) -> Response {
    execute_torii_read_fanout_via_nexus(
        app,
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: caller.map(ToString::to_string),
        },
        ToriiReadFanoutMergeV1::SpaceDirectoryBindings,
        crate::ToriiReadPayload {
            endpoint: ToriiReadEndpointV1::SpaceDirectoryBindingsGet,
            path_args: vec![uaid_literal],
            query_string,
            body: Vec::new(),
        },
        ToriiProxyResponseFormatV1::Json,
    )
    .await
}
