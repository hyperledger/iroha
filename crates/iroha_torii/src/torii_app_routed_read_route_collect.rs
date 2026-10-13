#[cfg(feature = "app_api")]
async fn execute_torii_fanout_json_payloads_resolved_routes(
    app: &SharedAppState,
    routes: Vec<RoutingDecision>,
    route_scope: ToriiFanoutRouteScopeV1,
    ToriiReadPayload {
        endpoint,
        path_args,
        query_string,
        body,
    }: ToriiReadPayload,
    proxy_memory: Option<ToriiProxyMemoryReservation>,
) -> Result<
    (
        Vec<Value>,
        ToriiFanoutDiagnostics,
        &'static str,
        ToriiRoutedReadMemoryBudget,
    ),
    Response,
> {
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
    let collected = collect_torii_routed_list_json_payloads(
        &routes,
        current_routed_read_memory_envelope(app)?.working_set_bytes,
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
    .await?;
    let ToriiFanoutRoutedJsonPayloads {
        payloads,
        diagnostics,
        mut budget,
    } = collected;
    if endpoint == ToriiReadEndpointV1::AccountAssetsQuery && diagnostics.failed_routes() != 0 {
        return Err(with_torii_fanout_headers(
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "incomplete_account_assets",
                "account-assets query requires every authoritative target route",
            ),
            diagnostics,
        ));
    }
    let payloads =
        filter_non_authoritative_global_portfolio_rows(app.as_ref(), endpoint, payloads)?;
    let mut values = budget.try_retained_vec(payloads.len())?;
    for (_, payload) in payloads {
        budget.push_retained(&mut values, payload)?;
    }
    Ok((values, diagnostics, routed_by, budget))
}
