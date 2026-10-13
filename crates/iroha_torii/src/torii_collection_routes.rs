// Collection reads (`specs/torii/collection_queries.md`).
//
// The ingress handler decodes one `ListQuery` (GET parameters or POST body),
// validates it and canonicalises account literals, then executes it once, on
// one route, as the JSON body of the collection's `*Query` endpoint. On a
// global root every route reads the same World under the caller's visibility
// (dataspaces are routing labels over one global block), so one execution
// answers the whole read: totals and aggregates are exact and no route
// repeats another's scan. The executing node applies `select` itself.
#[cfg(feature = "app_api")]
use iroha_torii_shared::list_query::ListQuery;

#[cfg(feature = "app_api")]
tokio::task_local! {
    /// The same owner follows a collection coordinator into its local worker.
    static COLLECTION_READ_MEMORY_RESERVATION: QueryFanoutMemoryReservation;
}

#[cfg(feature = "app_api")]
fn current_collection_read_memory_reservation(
    app: &SharedAppState,
) -> Option<QueryFanoutMemoryReservation> {
    COLLECTION_READ_MEMORY_RESERVATION
        .try_with(Clone::clone)
        .ok()
        .filter(|reservation| reservation.belongs_to(app))
}

#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn current_routed_read_memory_envelope(
    app: &SharedAppState,
) -> Result<QueryFanoutMemoryEnvelope, Response> {
    if let Ok(envelope) = COLLECTION_READ_MEMORY_RESERVATION
        .try_with(|reservation| reservation.admitted_envelope(app))
    {
        return envelope;
    }
    if let Ok(envelope) = APP_ROUTED_READ_HTTP_ADMISSION
        .try_with(|admission| admission.reservation.admitted_envelope(app))
    {
        return envelope;
    }
    Err(torii_proxy_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "query_memory_owner_missing",
        "Collection execution requires its admitted query memory owner.",
    ))
}

/// Largest accepted `GET` collection query string.
#[cfg(feature = "app_api")]
const COLLECTION_QUERY_MAX_RAW_BYTES: usize = 64 * 1024;

/// Collection behind a routed read endpoint.
#[cfg(feature = "app_api")]
fn collection_target_for_read(
    endpoint: ToriiReadEndpointV1,
    path_args: &[String],
) -> Option<routing::collection_sources::CollectionTarget> {
    use routing::collection_sources::CollectionTarget as T;
    let first = || path_args.first().cloned().unwrap_or_default();
    Some(match endpoint {
        ToriiReadEndpointV1::DomainsList | ToriiReadEndpointV1::DomainsQuery => T::Domains,
        ToriiReadEndpointV1::AccountsList | ToriiReadEndpointV1::AccountsQuery => T::Accounts,
        ToriiReadEndpointV1::AssetDefinitionsList | ToriiReadEndpointV1::AssetDefinitionsQuery => {
            T::AssetDefinitions
        }
        ToriiReadEndpointV1::NftsList | ToriiReadEndpointV1::NftsQuery => T::Nfts,
        ToriiReadEndpointV1::RwasList | ToriiReadEndpointV1::RwasQuery => T::Rwas,
        ToriiReadEndpointV1::AccountAssetsGet | ToriiReadEndpointV1::AccountAssetsQuery => {
            T::AccountAssets(first())
        }
        ToriiReadEndpointV1::AssetHoldersGet | ToriiReadEndpointV1::AssetHoldersQuery => {
            T::AssetHolders(first())
        }
        ToriiReadEndpointV1::AccountTransactionsGet
        | ToriiReadEndpointV1::AccountTransactionsQuery => T::AccountTransactions(first()),
        ToriiReadEndpointV1::TransactionsQuery => T::Transactions,
        ToriiReadEndpointV1::AccountHistoryGet | ToriiReadEndpointV1::AccountHistoryQuery => {
            T::AccountHistory(first())
        }
        ToriiReadEndpointV1::AccountPermissionsGet
        | ToriiReadEndpointV1::AccountPermissionsQuery => T::AccountPermissions(first()),
        ToriiReadEndpointV1::SpaceDirectoryManifestsGet
        | ToriiReadEndpointV1::UaidManifestsQuery => T::UaidManifests(first()),
        _ => return None,
    })
}

/// Decode `GET` collection parameters with ordinary RFC 3986 percent-decoding.
#[cfg(feature = "app_api")]
fn list_query_from_query_string(query: Option<&str>) -> Result<ListQuery, Error> {
    let raw = query.unwrap_or_default();
    if raw.len() > COLLECTION_QUERY_MAX_RAW_BYTES {
        return Err(collections::CollectionError::new(
            "invalid_query",
            "query",
            format!(
                "query strings must not exceed {} bytes; use POST …/query for large filters",
                COLLECTION_QUERY_MAX_RAW_BYTES
            ),
        )
        .into());
    }
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    // Match the shared text/JSON grammar: C0 controls must be escaped inside
    // literals, while DEL and C1 may appear literally. Tabs and line breaks
    // are also legal between tokens in a multiline filter.
    if let Some((key, _)) = pairs.iter().find(|(key, value)| {
        key.chars().any(char::is_control)
            || value
                .chars()
                .any(|ch| ch < '\u{20}' && !matches!(ch, '\t' | '\n' | '\r'))
    }) {
        return Err(collections::CollectionError::new(
            "invalid_query",
            "query",
            format!(
                "parameter `{key}` contains C0 control characters other than tabs and line breaks"
            ),
        )
        .into());
    }
    ListQuery::from_query_pairs(pairs).map_err(|err| collections::CollectionError::from(err).into())
}

/// Decode a `POST …/query` body.
#[cfg(feature = "app_api")]
fn list_query_from_json(body: norito::json::Value) -> Result<ListQuery, Error> {
    ListQuery::from_json_value(body).map_err(|err| collections::CollectionError::from(err).into())
}

/// Canonical forwarded body for a validated query.
#[cfg(feature = "app_api")]
fn collection_query_body(
    query: &ListQuery,
    bytes: collections::memory::BytePolicy,
) -> Result<Vec<u8>, Error> {
    norito::json::to_json_bounded_boxed(query, bytes.source_frame_bytes)
        .map(<[u8]>::into_vec)
        .map_err(|_| collections::memory::capacity("forwarded query").into())
}

/// Validate and canonicalise a collection query at the ingress node.
#[cfg(feature = "app_api")]
fn prepare_collection_forward(
    app: &SharedAppState,
    target: &routing::collection_sources::CollectionTarget,
    mut query: ListQuery,
) -> Result<(ListQuery, Vec<u8>, QueryFanoutMemoryReservation), Error> {
    let reservation = try_acquire_query_fanout_memory(app)
        .map_err(|_| collections::memory::capacity("working set"))?;
    let envelope = reservation
        .admitted_envelope(app)
        .map_err(|_| collections::memory::capacity("working set"))?;
    let telemetry = app.telemetry_handle();
    routing::collection_sources::canonicalize_collection_query(
        app.state.as_ref(),
        target,
        &mut query,
        &telemetry,
    )?;
    let mut limits = routing::collection_sources::collection_limits();
    limits.bytes = collections::memory::BytePolicy::for_admitted_read(
        envelope,
        app.torii_proxy_max_response_bytes,
    );
    collections::prepare(target.spec(), target.scope(), &query, &limits)?;
    let body = collection_query_body(&query, limits.bytes)?;
    Ok((query, body, reservation))
}

/// Execute a validated collection read under the caller's visible routes.
#[cfg(feature = "app_api")]
async fn forward_visible_collection_read(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    endpoint: ToriiReadEndpointV1,
    target: routing::collection_sources::CollectionTarget,
    path_args: Vec<String>,
    query: ListQuery,
) -> Result<Response, Error> {
    let (query, body, reservation) = prepare_collection_forward(app, &target, query)?;
    let routes = torii_visible_account_read_routes(app.as_ref(), caller);
    let Some(route) = collection_execution_route(app.as_ref(), &routes) else {
        return Ok(empty_collection_page_response(
            routed_by_for_routes(app, &[]),
            query.include_total,
        ));
    };
    let scope = ToriiFanoutRouteScopeV1::VisibleAccount {
        caller_account_id: caller.map(ToString::to_string),
    };
    Ok(
        execute_collection_on_route(app, route, scope, endpoint, path_args, body, reservation)
            .await,
    )
}

/// The one route a collection read executes on.
///
/// Every route of a global root reads the same World under the read's scope,
/// so the choice only decides where the read runs: preferably on this node,
/// and on a route without a public upstream, whose answer could not use the
/// caller's credentials.
#[cfg(feature = "app_api")]
fn collection_execution_route(
    app: &AppState,
    routes: &[RoutingDecision],
) -> Option<RoutingDecision> {
    routes.iter().copied().min_by_key(|route| {
        (
            app.public_dataspace_upstreams
                .contains_key(&route.dataspace_id),
            !should_execute_route_locally(app, *route),
            route.dataspace_id,
            route.lane_id,
        )
    })
}

/// Execute one collection read on `route` with the read's `scope`.
#[cfg(feature = "app_api")]
async fn execute_collection_on_route(
    app: &SharedAppState,
    route: RoutingDecision,
    scope: ToriiFanoutRouteScopeV1,
    endpoint: ToriiReadEndpointV1,
    path_args: Vec<String>,
    body: Vec<u8>,
    reservation: QueryFanoutMemoryReservation,
) -> Response {
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
        &path_args,
        path_args.capacity(),
        None,
        body.capacity(),
    ) {
        Ok(bytes) => bytes,
        Err(response) => return hold_query_fanout_memory_in_response_body(response, reservation),
    };
    if let Err(response) = budget.admit_request_bytes(request_bytes) {
        return hold_query_fanout_memory_in_response_body(response, reservation);
    }
    let request = torii_read_request(endpoint, scope, route, path_args, None, body);
    let response = COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            reservation.clone(),
            execute_torii_read_for_route(app, route, request, None),
        )
        .await;
    let response = match bound_torii_single_route_response(
        response,
        ToriiProxyResponseFormatV1::Json,
        &mut budget,
    )
    .await
    {
        Ok(response) | Err(response) => response,
    };
    hold_query_fanout_memory_in_response_body(response, reservation)
}

/// Page size used to price a collection read for rate limiting.
#[cfg(feature = "app_api")]
fn collection_page_limit(query: &ListQuery) -> u64 {
    let limits = routing::collection_sources::collection_limits();
    u64::from(
        query
            .limit
            .unwrap_or(limits.default_limit)
            .clamp(1, limits.max_limit),
    )
}

/// An empty page for reads with no authoritative route.
#[cfg(feature = "app_api")]
fn empty_collection_page_response(routed_by: &'static str, include_total: bool) -> Response {
    let page = iroha_torii_shared::list_query::Page::<norito::json::Value> {
        items: Vec::new(),
        next_cursor: None,
        total: include_total.then_some(0),
    };
    let body = norito::json::to_json(&page).expect("an empty collection page is valid JSON");
    let mut response = Response::new(axum::body::Body::from(body));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    insert_routed_by_header(&mut response, routed_by);
    response
}

/// Decode the query carried by a routed collection request.
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_routed_collection_query(
    plan: ToriiRoutedReadRequestDecodePlan,
    endpoint: ToriiReadEndpointV1,
    query_string: Option<&str>,
    body: &[u8],
) -> Result<ListQuery, Response> {
    let is_get = matches!(
        endpoint,
        ToriiReadEndpointV1::DomainsList
            | ToriiReadEndpointV1::AccountsList
            | ToriiReadEndpointV1::AssetDefinitionsList
            | ToriiReadEndpointV1::NftsList
            | ToriiReadEndpointV1::RwasList
            | ToriiReadEndpointV1::AccountAssetsGet
            | ToriiReadEndpointV1::AssetHoldersGet
            | ToriiReadEndpointV1::AccountTransactionsGet
            | ToriiReadEndpointV1::AccountHistoryGet
            | ToriiReadEndpointV1::AccountPermissionsGet
            | ToriiReadEndpointV1::SpaceDirectoryManifestsGet
    );
    if is_get {
        return list_query_from_query_string(query_string).map_err(IntoResponse::into_response);
    }
    let value =
        decode_torii_proxy_json_body::<norito::json::Value>(plan, body, "collection query body")?;
    list_query_from_json(value).map_err(IntoResponse::into_response)
}

/// Execute a routed collection read on this node and apply its `select`.
#[cfg(feature = "app_api")]
async fn execute_routed_collection_read(
    app: &SharedAppState,
    request: &ToriiReadProxyRequestV1,
    plan: ToriiRoutedReadRequestDecodePlan,
    routing_decision: RoutingDecision,
    routed_by: &'static str,
    target: routing::collection_sources::CollectionTarget,
    visibility: &routing::DataspaceReadVisibility,
) -> Response {
    let query = match decode_routed_collection_query(
        plan,
        request.endpoint,
        request.query_string.as_deref(),
        &request.body,
    ) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let telemetry = app.telemetry_handle();
    let result = routing::collection_sources::execute_collection_response(
        Some(app),
        &app.state,
        &target,
        query,
        &telemetry,
        visibility,
    )
    .await;
    finish_torii_read_result(result, routing_decision, routed_by)
}

/// Execute a collection read served by this node alone (no fan-out).
#[cfg(feature = "app_api")]
async fn execute_direct_collection_read(
    app: &SharedAppState,
    target: routing::collection_sources::CollectionTarget,
    query: ListQuery,
) -> Result<Response, Error> {
    execute_scoped_direct_collection_read(
        app,
        target,
        query,
        routing::DataspaceReadVisibility::new(std::collections::BTreeSet::new(), true),
    )
    .await
}

#[cfg(feature = "app_api")]
async fn execute_scoped_direct_collection_read(
    app: &SharedAppState,
    target: routing::collection_sources::CollectionTarget,
    query: ListQuery,
    visibility: routing::DataspaceReadVisibility,
) -> Result<Response, Error> {
    let reservation = match try_acquire_query_fanout_memory(app) {
        Ok(reservation) => reservation,
        Err(response) => return Ok(response),
    };
    let telemetry = app.telemetry_handle();
    let result = COLLECTION_READ_MEMORY_RESERVATION
        .scope(reservation.clone(), async {
            routing::collection_sources::execute_collection_response(
                Some(app),
                &app.state,
                &target,
                query,
                &telemetry,
                &visibility,
            )
            .await
        })
        .await;
    Ok(hold_query_fanout_memory_in_response_body(
        result.unwrap_or_else(IntoResponse::into_response),
        reservation,
    ))
}
