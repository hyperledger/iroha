// Bounded merge helpers for application routed reads.
#[cfg(feature = "app_api")]
fn parse_asset_definition_item_literal(literal: &str) -> Option<AssetDefinitionId> {
    literal
        .parse::<AssetDefinitionId>()
        .ok()
        .or_else(|| AssetDefinitionId::parse_address_literal(literal).ok())
}
#[cfg(feature = "app_api")]
fn asset_row_home_dataspace_id(
    app: &AppState,
    object: &norito::json::Map,
) -> Result<Option<DataSpaceId>, Error> {
    if let Some(alias_literal) = object
        .get("asset_alias")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|literal| !literal.is_empty())
        && let Ok(alias) = alias_literal.parse::<AssetDefinitionAlias>()
    {
        return dataspace_id_for_alias_segment(app, alias.dataspace_segment());
    }
    for key in ["asset_definition_id", "asset"] {
        if let Some(definition_id) = object
            .get(key)
            .and_then(Value::as_str)
            .and_then(parse_asset_definition_item_literal)
        {
            return asset_definition_home_dataspace_id(app, &definition_id);
        }
    }
    for key in ["asset_id", "asset"] {
        if let Some(asset_id) = object
            .get(key)
            .and_then(Value::as_str)
            .and_then(|literal| AssetId::parse_literal(literal).ok())
        {
            return asset_definition_home_dataspace_id(app, asset_id.definition());
        }
    }
    Ok(None)
}
#[cfg(feature = "app_api")]
fn asset_row_has_global_scope(object: &norito::json::Map) -> bool {
    if let Some(scope) = object.get("scope").and_then(Value::as_str) {
        return scope == "global";
    }
    for key in ["asset_id", "asset"] {
        if let Some(asset_id) = object
            .get(key)
            .and_then(Value::as_str)
            .and_then(|literal| AssetId::parse_literal(literal).ok())
        {
            return matches!(asset_id.scope(), AssetBalanceScope::Global);
        }
    }
    false
}
#[cfg(feature = "app_api")]
fn route_is_public_or_universal(app: &AppState, route: RoutingDecision) -> bool {
    if route.dataspace_id == DataSpaceId::UNIVERSAL {
        return true;
    }
    app.state
        .view()
        .nexus()
        .lane_catalog
        .lanes()
        .iter()
        .any(|lane| {
            lane.dataspace_id == route.dataspace_id
                && lane.visibility == iroha_data_model::nexus::LaneVisibility::Public
        })
}
/// Whether `route` serves this asset item. A global-scope balance is visible
/// on every route but served only by its definition's home dataspace (or a
/// public route when the home is unknown), so each item has one route.
#[cfg(feature = "app_api")]
fn should_keep_authoritative_global_item(
    app: &AppState,
    route: RoutingDecision,
    item: &Value,
) -> Result<bool, Error> {
    let Some(row) = item.as_object() else {
        return Ok(true);
    };
    if !asset_row_has_global_scope(row) {
        return Ok(true);
    }
    if let Some(home_dataspace_id) = asset_row_home_dataspace_id(app, row)? {
        return Ok(home_dataspace_id == route.dataspace_id);
    }
    Ok(route_is_public_or_universal(app, route))
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn filter_non_authoritative_global_portfolio_rows(
    app: &AppState,
    endpoint: ToriiReadEndpointV1,
    payloads: Vec<(RoutingDecision, Value)>,
) -> Result<Vec<(RoutingDecision, Value)>, Response> {
    if !matches!(endpoint, ToriiReadEndpointV1::AccountsPortfolio) {
        return Ok(payloads);
    }
    let mut payloads = payloads;
    for (route, payload) in &mut payloads {
        let Some(object) = payload.as_object_mut() else {
            return Err(torii_internal_json_error(
                "expected JSON object payload while filtering portfolio response",
            ));
        };
        let Some(dataspaces) = object.get_mut("dataspaces").and_then(Value::as_array_mut) else {
            return Err(torii_internal_json_error(
                "expected `dataspaces` array while filtering portfolio response",
            ));
        };
        let mut total_accounts = 0_u64;
        let mut total_positions = 0_u64;
        for dataspace in dataspaces {
            let Some(dataspace_object) = dataspace.as_object_mut() else {
                return Err(torii_internal_json_error(
                    "portfolio dataspace rows must be JSON objects",
                ));
            };
            let Some(accounts) = dataspace_object
                .get_mut("accounts")
                .and_then(Value::as_array_mut)
            else {
                return Err(torii_internal_json_error(
                    "portfolio dataspace rows must include `accounts`",
                ));
            };
            for account in accounts {
                let Some(account_object) = account.as_object_mut() else {
                    return Err(torii_internal_json_error(
                        "portfolio account rows must be JSON objects",
                    ));
                };
                let Some(assets) = account_object
                    .get_mut("assets")
                    .and_then(Value::as_array_mut)
                else {
                    return Err(torii_internal_json_error(
                        "portfolio account rows must include `assets`",
                    ));
                };
                let mut refusal = None;
                assets.retain(|asset| {
                    if refusal.is_some() {
                        return true;
                    }
                    let keep = match should_keep_authoritative_global_item(app, *route, asset) {
                        Ok(keep) => keep,
                        Err(error) => {
                            refusal = Some(error);
                            return true;
                        }
                    };
                    if !keep {
                        let asset_literal = asset
                            .as_object()
                            .and_then(|object| {
                                object
                                    .get("asset_id")
                                    .or_else(|| object.get("asset"))
                                    .or_else(|| object.get("asset_definition_id"))
                            })
                            .and_then(Value::as_str)
                            .unwrap_or("<unknown>");
                        iroha_logger::debug!(
                            dataspace_id = %route.dataspace_id,
                            asset = asset_literal,
                            "suppressing non-authoritative global asset row from portfolio merge"
                        );
                    }
                    keep
                });
                if let Some(error) = refusal {
                    return Err(error_response_with_format(error, ResponseFormat::Json));
                }
                total_accounts = total_accounts.saturating_add(1);
                total_positions =
                    total_positions.saturating_add(u64::try_from(assets.len()).unwrap_or(u64::MAX));
            }
        }
        let Some(totals) = object.get_mut("totals").and_then(Value::as_object_mut) else {
            return Err(torii_internal_json_error(
                "expected `totals` object while filtering portfolio response",
            ));
        };
        let Some(accounts_total) = totals.get_mut("accounts") else {
            return Err(torii_internal_json_error(
                "portfolio totals must include `accounts`",
            ));
        };
        *accounts_total = Value::from(total_accounts);
        let Some(positions_total) = totals.get_mut("positions") else {
            return Err(torii_internal_json_error(
                "portfolio totals must include `positions`",
            ));
        };
        *positions_total = Value::from(total_positions);
    }
    Ok(payloads)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn list_items_from_payload<'a>(
    payload: &'a Value,
    context: &'static str,
) -> Result<&'a [Value], Response> {
    if let Some(items) = payload
        .as_object()
        .and_then(|obj| obj.get("items"))
        .and_then(Value::as_array)
    {
        return Ok(items);
    }
    Err(torii_internal_json_error(context))
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn list_items_from_owned_payload(
    payload: Value,
    context: &'static str,
) -> Result<Vec<Value>, Response> {
    match payload {
        Value::Object(mut object) => match object.remove("items") {
            Some(Value::Array(items)) => Ok(items),
            _ => Err(torii_internal_json_error(context)),
        },
        _ => Err(torii_internal_json_error(context)),
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_list_response(
    payloads: Vec<Value>,
    _endpoint: ToriiReadEndpointV1,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let item_count = payloads.iter().try_fold(0_usize, |count, payload| {
        count
            .checked_add(
                list_items_from_payload(
                    payload,
                    "expected JSON object with `items` while merging list response",
                )?
                .len(),
            )
            .ok_or_else(torii_routed_read_accounting_response)
    })?;
    budget.admit_merge_btree::<Vec<u8>, ()>(1, item_count)?;
    let mut seen = BTreeSet::<Vec<u8>>::new();
    let mut merged_items = budget.try_merge_vec(item_count)?;
    for payload in payloads {
        let payload_items = list_items_from_owned_payload(
            payload,
            "expected JSON object with `items` while merging list response",
        )?;
        for item in payload_items {
            let key = budget.canonical_json_candidate(&item)?;
            if seen.contains(&key) {
                continue;
            }
            budget.retain_canonical_capacity(key.capacity())?;
            seen.insert(key);
            merged_items.push(item);
        }
    }
    drop(seen);
    budget.admit_merge_btree::<String, Value>(1, 2)?;
    budget.admit_merge_allocation("total".len() + "items".len())?;
    let mut root = norito::json::Map::new();
    root.insert("total".into(), Value::from(merged_items.len() as u64));
    root.insert("items".into(), Value::Array(merged_items));
    let root = Value::Object(root);
    let mut response = budget.json_response(&root)?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_account_read_response(
    payloads: Vec<ToriiBoundedNoritoPayload<AccountReadResponse>>,
    format: ResponseFormat,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_typed_merge();
    budget.admit_merge_btree::<Vec<u8>, AccountReadResponse>(1, payloads.len())?;
    let mut unique_payloads = BTreeMap::<Vec<u8>, AccountReadResponse>::new();
    for payload in payloads {
        unique_payloads
            .entry(payload.canonical_bytes)
            .or_insert(payload.value);
    }
    match unique_payloads.len() {
        0 => Err(torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no dataspace returned a matching result",
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
                    .expect("build preflighted account-read response"),
                ResponseFormat::Json => {
                    drop(canonical_bytes);
                    budget.json_response(&payload)?
                }
            };
            insert_routed_by_header(&mut response, routed_by);
            Ok(response)
        }
        _ => Err(torii_proxy_error_response(
            StatusCode::CONFLICT,
            "route_conflict",
            "multiple dataspaces returned conflicting singleton results",
        )),
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_singleton_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    budget.admit_merge_btree::<Vec<u8>, Value>(1, payloads.len())?;
    let mut unique_payloads = BTreeMap::<Vec<u8>, Value>::new();
    for payload in payloads {
        let canonical = budget.canonical_json_candidate(&payload)?;
        if unique_payloads.contains_key(&canonical) {
            continue;
        }
        budget.retain_canonical_capacity(canonical.capacity())?;
        unique_payloads.insert(canonical, payload);
    }
    match unique_payloads.len() {
        0 => Err(torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no dataspace returned a matching result",
        )),
        1 => {
            let payload = unique_payloads
                .into_values()
                .next()
                .expect("singleton map length should be one");
            let mut response = budget.json_response(&payload)?;
            insert_routed_by_header(&mut response, routed_by);
            Ok(response)
        }
        _ => Err(torii_proxy_error_response(
            StatusCode::CONFLICT,
            "route_conflict",
            "multiple dataspaces returned conflicting singleton results",
        )),
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn pipeline_status_payload_rank(payload: &Value) -> Result<u8, Response> {
    let kind = payload
        .as_object()
        .and_then(|object| object.get("status"))
        .and_then(Value::as_object)
        .and_then(|status| status.get("kind"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            torii_internal_json_error("routed pipeline status must include string `status.kind`")
        })?;
    match kind {
        "Queued" => Ok(0),
        "Approved" => Ok(1),
        "Expired" => Ok(2),
        "Rejected" => Ok(3),
        "Committed" => Ok(4),
        "Applied" => Ok(5),
        _ => Err(torii_internal_json_error(
            "routed pipeline status contained an unknown status kind",
        )),
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn pipeline_status_payload_tie_break(payload: &Value) -> Result<(u8, u64), Response> {
    let object = payload.as_object().ok_or_else(|| {
        torii_internal_json_error("routed pipeline status payload must be a JSON object")
    })?;
    if object.get("scope").and_then(Value::as_str) != Some("global") {
        return Err(torii_internal_json_error(
            "routed pipeline status scope must be exact `global`",
        ));
    }
    let resolved_from = object
        .get("resolved_from")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            torii_internal_json_error("routed pipeline status must include string `resolved_from`")
        })?;
    let source_rank = match resolved_from {
        "state" => 3,
        "cache" => 2,
        "queue" => 1,
        _ => {
            return Err(torii_internal_json_error(
                "routed pipeline status contained an unknown resolution source",
            ));
        }
    };
    let block_height = object
        .get("status")
        .and_then(Value::as_object)
        .and_then(|status| status.get("block_height"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Ok((source_rank, block_height))
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn pipeline_status_payload_hash(payload: &Value) -> Result<&str, Response> {
    payload
        .as_object()
        .and_then(|object| object.get("hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            torii_internal_json_error("routed pipeline status must include string `hash`")
        })
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_pipeline_status_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    let mut budget = budget;
    budget.begin_json_merge();
    let mut best: Option<(Value, u8, (u8, u64))> = None;
    for payload in payloads {
        let rank = pipeline_status_payload_rank(&payload)?;
        let tie_break = pipeline_status_payload_tie_break(&payload)?;
        // Validate every candidate before it can become `best`; otherwise a malformed first
        // payload survives until the next comparison and turns the merge into a panic.
        let _ = pipeline_status_payload_hash(&payload)?;
        match best.as_ref() {
            None => best = Some((payload, rank, tie_break)),
            Some((current, current_rank, current_tie_break)) => {
                let payload_hash = pipeline_status_payload_hash(&payload)?;
                let current_hash = pipeline_status_payload_hash(current)?;
                if payload_hash != current_hash {
                    return Err(torii_proxy_error_response(
                        StatusCode::CONFLICT,
                        "route_conflict",
                        "multiple dataspaces returned pipeline statuses for different hashes",
                    ));
                }
                // Resolution authority is primary: a state observation must not lose to a
                // semantically later but non-authoritative cache hint. Within one source class,
                // prefer the later status and then the greater carrier height.
                if tie_break.0 > current_tie_break.0
                    || (tie_break.0 == current_tie_break.0
                        && (rank > *current_rank
                            || (rank == *current_rank && tie_break.1 > current_tie_break.1)))
                {
                    best = Some((payload, rank, tie_break));
                }
            }
        }
    }
    let Some((payload, _, _)) = best else {
        return Err(torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no dataspace returned a matching result",
        ));
    };
    let mut response = budget.json_response(&payload)?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn authorize_alias_resolve_index_payloads(
    app: &SharedAppState,
    caller: Option<&AccountId>,
    mut payloads: Vec<Value>,
) -> Result<Vec<Value>, Response> {
    let public_dataspaces = torii_public_dataspace_ids(app.as_ref());
    let mut index = 0;
    while index < payloads.len() {
        let payload = &payloads[index];
        let alias_literal = payload
            .as_object()
            .and_then(|object| object.get("alias"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                torii_internal_json_error("routed alias-index response must include string `alias`")
            })?;
        let alias = parse_exact_account_alias_label_with_live_state(app, alias_literal).map_err(
            |error| {
                if matches!(
                    &error,
                    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
                    ))
                ) {
                    return error.into_response();
                }
                torii_proxy_error_response(
                    StatusCode::CONFLICT,
                    "route_conflict",
                    "a routed alias-index response contained a non-canonical alias",
                )
            },
        )?;
        if public_dataspaces.contains(&alias.label.dataspace) {
            index += 1;
            continue;
        }
        let Some(caller) = caller else {
            payloads.remove(index);
            continue;
        };
        if !torii_authority_can_resolve_resolved_account_alias(
            app.state.view().world(),
            caller,
            &alias.resolved,
        )
        .map_err(IntoResponse::into_response)?
        {
            return Err(torii_alias_permission_denied_response(
                "exact account-alias resolve permission is required for the returned alias-index binding",
            ));
        }
        index += 1;
    }
    Ok(payloads)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_alias_resolve_index_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    source: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let mut selected: Option<Value> = None;
    for payload in payloads {
        let object = payload.as_object().ok_or_else(|| {
            torii_internal_json_error("routed alias-index response must be a JSON object")
        })?;
        let index = object.get("index").and_then(Value::as_u64).ok_or_else(|| {
            torii_internal_json_error("routed alias-index response must include u64 `index`")
        })?;
        let alias = object.get("alias").and_then(Value::as_str).ok_or_else(|| {
            torii_internal_json_error("routed alias-index response must include string `alias`")
        })?;
        let account_id = object
            .get("account_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                torii_internal_json_error(
                    "routed alias-index response must include string `account_id`",
                )
            })?;
        if let Some(existing) = selected.as_ref() {
            let existing = existing
                .as_object()
                .expect("selected alias-index payload was already validated");
            if existing.get("index").and_then(Value::as_u64) != Some(index)
                || existing.get("alias").and_then(Value::as_str) != Some(alias)
                || existing.get("account_id").and_then(Value::as_str) != Some(account_id)
            {
                return Err(torii_proxy_error_response(
                    StatusCode::CONFLICT,
                    "route_conflict",
                    "multiple dataspaces returned conflicting alias-index bindings",
                ));
            }
        } else {
            selected = Some(payload);
        }
    }
    let Some(mut payload) = selected else {
        return Err(torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no dataspace returned a matching result",
        ));
    };
    let object = payload
        .as_object_mut()
        .expect("selected alias-index payload was already validated");
    budget.admit_merge_allocation(source.len())?;
    if let Some(value) = object.get_mut("source") {
        *value = Value::from(source);
    } else {
        // Inserting into a full root can allocate one sibling and a new root.
        budget.admit_merge_btree::<String, Value>(2, 2)?;
        budget.admit_merge_allocation("source".len())?;
        object.insert("source".to_owned(), Value::from(source));
    }
    let mut response = budget.json_response(&payload)?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_alias_lookup_by_account_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    source: &'static str,
    denied_routes: usize,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let item_count = payloads.iter().try_fold(0_usize, |count, payload| {
        let items = payload
            .as_object()
            .and_then(|object| object.get("items"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                torii_internal_json_error(
                    "routed alias by-account response must include an `items` array",
                )
            })?;
        count
            .checked_add(items.len())
            .ok_or_else(torii_routed_read_accounting_response)
    })?;
    budget.admit_merge_btree::<Vec<u8>, ()>(1, item_count)?;
    let mut merged_items = budget.try_merge_vec(item_count)?;
    let mut account_id: Option<Value> = None;
    let mut seen = BTreeSet::<Vec<u8>>::new();
    for payload in payloads {
        let Value::Object(mut object) = payload else {
            return Err(torii_internal_json_error(
                "routed alias by-account response must be a JSON object",
            ));
        };
        let candidate_account_id = object.remove("account_id").ok_or_else(|| {
            torii_internal_json_error("routed alias by-account response must include `account_id`")
        })?;
        if candidate_account_id.as_str().is_none() {
            return Err(torii_internal_json_error(
                "routed alias by-account `account_id` must be a string",
            ));
        }
        match &account_id {
            Some(existing) if existing != &candidate_account_id => {
                return Err(torii_proxy_error_response(
                    StatusCode::CONFLICT,
                    "route_conflict",
                    "multiple dataspaces returned conflicting alias-account roots",
                ));
            }
            None => account_id = Some(candidate_account_id),
            Some(_) => {}
        }
        let items = match object.remove("items") {
            Some(Value::Array(items)) => items,
            _ => {
                return Err(torii_internal_json_error(
                    "routed alias by-account response must include an `items` array",
                ));
            }
        };
        for mut item in items {
            let item_object = item.as_object_mut().ok_or_else(|| {
                torii_internal_json_error("routed alias by-account items must be JSON objects")
            })?;
            for key in item_object.keys() {
                if !matches!(
                    key.as_str(),
                    "alias" | "dataspace" | "domain" | "is_primary"
                ) {
                    return Err(torii_internal_json_error(
                        "routed alias by-account item contained an unknown field",
                    ));
                }
            }
            if item_object.get("alias").and_then(Value::as_str).is_none()
                || item_object
                    .get("dataspace")
                    .and_then(Value::as_str)
                    .is_none()
                || item_object
                    .get("is_primary")
                    .and_then(Value::as_bool)
                    .is_none()
            {
                return Err(torii_internal_json_error(
                    "routed alias by-account item has invalid required fields",
                ));
            }
            match item_object.get("domain") {
                None | Some(Value::Null) => {
                    item_object.remove("domain");
                }
                Some(value) if value.as_str().is_some() => {}
                Some(_) => {
                    return Err(torii_internal_json_error(
                        "routed alias by-account item `domain` must be a string or null",
                    ));
                }
            }
            let key = budget.canonical_json_candidate(&item)?;
            if seen.contains(&key) {
                continue;
            }
            budget.retain_canonical_capacity(key.capacity())?;
            seen.insert(key);
            merged_items.push(item);
        }
    }
    if merged_items.is_empty() && denied_routes > 0 {
        return Err(torii_alias_permission_denied_response(
            "one or more dataspace routes denied the alias-by-account lookup and no allowed route returned aliases",
        ));
    }
    if merged_items.len() > EXACT_ALIAS_LOOKUP_MAX_ITEMS {
        return Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))
        .into_response());
    }
    merged_items.sort_by(|left, right| {
        let left = left
            .as_object()
            .expect("merged alias item was already validated");
        let right = right
            .as_object()
            .expect("merged alias item was already validated");
        left.get("alias")
            .and_then(Value::as_str)
            .cmp(&right.get("alias").and_then(Value::as_str))
            .then_with(|| {
                left.get("dataspace")
                    .and_then(Value::as_str)
                    .cmp(&right.get("dataspace").and_then(Value::as_str))
            })
            .then_with(|| {
                left.get("domain")
                    .and_then(Value::as_str)
                    .cmp(&right.get("domain").and_then(Value::as_str))
            })
            .then_with(|| {
                right
                    .get("is_primary")
                    .and_then(Value::as_bool)
                    .cmp(&left.get("is_primary").and_then(Value::as_bool))
            })
    });
    drop(seen);
    budget.admit_merge_btree::<String, Value>(1, 4)?;
    budget.admit_merge_allocation(
        "account_id".len() + "total".len() + "items".len() + "source".len() + source.len(),
    )?;
    let mut root = norito::json::Map::new();
    root.insert(
        "account_id".to_owned(),
        account_id.unwrap_or_else(|| Value::String(String::new())),
    );
    root.insert(
        "total".to_owned(),
        Value::from(u64::try_from(merged_items.len()).unwrap_or(u64::MAX)),
    );
    root.insert("items".to_owned(), Value::Array(merged_items));
    root.insert("source".to_owned(), Value::from(source));
    let mut response = budget.json_response(&Value::Object(root))?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_space_directory_bindings_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let (row_count, account_count) =
        payloads
            .iter()
            .try_fold((0_usize, 0_usize), |(rows_seen, accounts_seen), payload| {
                let rows = payload
                    .as_object()
                    .and_then(|object| object.get("dataspaces"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        torii_internal_json_error(
                            "expected `dataspaces` array while merging space-directory bindings",
                        )
                    })?;
                let rows_seen = rows_seen
                    .checked_add(rows.len())
                    .ok_or_else(torii_routed_read_accounting_response)?;
                let accounts_seen = rows.iter().try_fold(accounts_seen, |count, row| {
                    let accounts = row
                        .as_object()
                        .and_then(|object| object.get("accounts"))
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            torii_internal_json_error(
                                "space-directory binding rows must include `accounts`",
                            )
                        })?;
                    count
                        .checked_add(accounts.len())
                        .ok_or_else(torii_routed_read_accounting_response)
                })?;
                Ok((rows_seen, accounts_seen))
            })?;
    budget.admit_merge_btree::<u64, (Option<String>, BTreeSet<String>)>(1, row_count)?;
    budget.admit_merge_btree::<String, ()>(row_count, account_count)?;
    let mut uaid: Option<String> = None;
    let mut dataspaces = BTreeMap::<u64, (Option<String>, BTreeSet<String>)>::new();
    for payload in payloads {
        let Value::Object(mut object) = payload else {
            return Err(torii_internal_json_error(
                "expected JSON object payload while merging space-directory bindings",
            ));
        };
        if let Some(Value::String(value)) = object.remove("uaid") {
            match &uaid {
                Some(existing) if existing != &value => {
                    return Err(torii_proxy_error_response(
                        StatusCode::CONFLICT,
                        "route_conflict",
                        "multiple dataspaces returned conflicting UAID bindings roots",
                    ));
                }
                None => uaid = Some(value),
                Some(_) => {}
            }
        }
        let rows = match object.remove("dataspaces") {
            Some(Value::Array(rows)) => rows,
            _ => {
                return Err(torii_internal_json_error(
                    "expected `dataspaces` array while merging space-directory bindings",
                ));
            }
        };
        for row in rows {
            let Value::Object(mut row) = row else {
                return Err(torii_internal_json_error(
                    "space-directory binding rows must be JSON objects",
                ));
            };
            let dataspace_id = row
                .remove("dataspace_id")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    torii_internal_json_error(
                        "space-directory binding rows must include `dataspace_id`",
                    )
                })?;
            let alias = match row.remove("dataspace_alias") {
                Some(Value::String(alias)) => Some(alias),
                None | Some(Value::Null) => None,
                Some(_) => {
                    return Err(torii_internal_json_error(
                        "space-directory binding `dataspace_alias` must be a string or null",
                    ));
                }
            };
            let accounts = match row.remove("accounts") {
                Some(Value::Array(accounts)) => accounts,
                _ => {
                    return Err(torii_internal_json_error(
                        "space-directory binding rows must include `accounts`",
                    ));
                }
            };
            let entry = dataspaces
                .entry(dataspace_id)
                .or_insert_with(|| (None, BTreeSet::new()));
            if entry.0.is_none() {
                entry.0 = alias;
            }
            for account in accounts {
                let Value::String(account_literal) = account else {
                    return Err(torii_internal_json_error(
                        "space-directory binding accounts must be strings",
                    ));
                };
                entry.1.insert(account_literal);
            }
        }
    }
    let dataspace_count = dataspaces.len();
    let output_map_count = dataspace_count
        .checked_add(1)
        .ok_or_else(torii_routed_read_accounting_response)?;
    let output_map_entries = dataspace_count
        .checked_mul(3)
        .and_then(|entries| entries.checked_add(2))
        .ok_or_else(torii_routed_read_accounting_response)?;
    budget.admit_merge_btree::<String, Value>(output_map_count, output_map_entries)?;
    let fixed_key_bytes = dataspace_count
        .checked_mul("dataspace_id".len() + "dataspace_alias".len() + "accounts".len())
        .and_then(|bytes| bytes.checked_add("uaid".len() + "dataspaces".len()))
        .ok_or_else(torii_routed_read_accounting_response)?;
    budget.admit_merge_allocation(fixed_key_bytes)?;
    let mut rows = budget.try_merge_vec(dataspace_count)?;
    for (dataspace_id, (alias, accounts)) in dataspaces {
        let mut account_values = budget.try_merge_vec(accounts.len())?;
        account_values.extend(accounts.into_iter().map(Value::from));
        let mut row = norito::json::Map::new();
        row.insert("dataspace_id".to_owned(), Value::from(dataspace_id));
        row.insert(
            "dataspace_alias".to_owned(),
            alias.map(Value::from).unwrap_or(Value::Null),
        );
        row.insert("accounts".to_owned(), Value::Array(account_values));
        rows.push(Value::Object(row));
    }
    let mut root = norito::json::Map::new();
    root.insert(
        "uaid".to_owned(),
        uaid.map(Value::from)
            .unwrap_or(Value::String(String::new())),
    );
    root.insert("dataspaces".to_owned(), Value::Array(rows));
    let mut response = budget.json_response(&Value::Object(root))?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(all(test, feature = "app_api"))]
mod routed_read_merge_regression_tests {
    use super::*;

    const TEST_BODY_BYTES: usize = 1024 * 1024;

    fn test_budget() -> ToriiRoutedReadMemoryBudget {
        ToriiRoutedReadMemoryBudget::new(
            routed_read_working_set_for_phase(TEST_BODY_BYTES),
            TEST_BODY_BYTES,
        )
        .expect("routed-read merge test memory envelope should fit")
    }

    #[tokio::test]
    async fn dataspace_summary_merge_preserves_portfolios_and_rejects_retired_consensus() {
        let shard = |id: u64, positions: u64, active: bool| {
            norito::json!({
                "account": "alice",
                "account_id": "alice",
                "uaid": "test-uaid",
                "totals": {},
                "dataspaces": [{
                    "dataspace_id": id,
                    "dataspace_alias": null,
                    "accounts": ["alice"],
                    "portfolio": {"accounts": 1, "positions": positions},
                    "manifest": {"present": true, "active": active}
                }]
            })
        };
        let response = merged_dataspace_summary_response(
            vec![shard(7, 2, true), shard(9, 3, false)],
            "proxy",
            test_budget(),
        )
        .expect("current portfolio summaries merge");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("summary response body");
        let merged: Value = norito::json::from_slice(&body).expect("summary JSON");
        assert_eq!(merged["account"], Value::from("alice"));
        assert_eq!(merged["account_id"], Value::from("alice"));
        assert_eq!(merged["uaid"], Value::from("test-uaid"));
        assert_eq!(
            merged["totals"],
            norito::json!({
                "dataspaces": 2, "accounts_bound": 1, "portfolio_accounts": 2,
                "portfolio_positions": 5, "manifests_total": 2, "manifests_active": 1
            })
        );
        assert_eq!(merged["dataspaces"][0]["dataspace_id"], Value::from(7));
        assert_eq!(merged["dataspaces"][1]["dataspace_id"], Value::from(9));
        assert!(
            merged["dataspaces"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row.get("consensus").is_none())
        );

        for key in [
            "consensus_entries",
            "consensus_tx_count",
            "consensus_chunks_total",
            "consensus_rbc_bytes_total",
            "consensus_teu_total",
        ] {
            let mut retired = shard(7, 2, true);
            retired
                .as_object_mut()
                .unwrap()
                .get_mut("totals")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), Value::from(0));
            let response = merged_dataspace_summary_response(vec![retired], "proxy", test_budget())
                .expect_err("even zero retired totals are not the current protocol");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        for value in [Value::Null, norito::json!({})] {
            let mut retired = shard(7, 2, true);
            retired
                .as_object_mut()
                .unwrap()
                .get_mut("dataspaces")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()
                .insert("consensus".into(), value);
            let response = merged_dataspace_summary_response(vec![retired], "proxy", test_budget())
                .expect_err("retired commitment projection is rejected");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    #[test]
    fn pipeline_status_merge_rejects_a_missing_hash_in_every_position() {
        let missing_hash = norito::json!({
            "status": {"kind": "Queued"},
            "resolved_from": "queue"
        });
        let valid = norito::json!({
            "hash": "abc",
            "status": {"kind": "Applied", "block_height": 7},
            "resolved_from": "state"
        });

        for payloads in [
            vec![missing_hash.clone(), valid.clone()],
            vec![missing_hash.clone()],
            vec![valid, missing_hash],
        ] {
            let response = merged_pipeline_status_response(payloads, "proxy", test_budget())
                .expect_err("a pipeline status without a hash must be rejected");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                response
                    .headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("invalid_proxy_response")
            );
        }
    }

    #[test]
    fn pipeline_status_merge_rejects_inexact_routing_metadata() {
        for (scope, resolved_from) in [("global", "legacy"), ("local", "state")] {
            let response = merged_pipeline_status_response(
                vec![norito::json!({
                    "hash": "abc",
                    "status": {"kind": "Applied", "block_height": 7},
                    "scope": scope,
                    "resolved_from": resolved_from
                })],
                "proxy",
                test_budget(),
            )
            .expect_err("inexact pipeline routing metadata must fail closed");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_portfolio_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let row_count = payloads.iter().try_fold(0_usize, |count, payload| {
        let rows = payload
            .as_object()
            .and_then(|object| object.get("dataspaces"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                torii_internal_json_error(
                    "expected `dataspaces` array while merging portfolio response",
                )
            })?;
        count
            .checked_add(rows.len())
            .ok_or_else(torii_routed_read_accounting_response)
    })?;
    budget.admit_merge_btree::<u64, Value>(1, row_count)?;
    let mut uaid: Option<String> = None;
    let mut dataspaces = BTreeMap::<u64, Value>::new();
    for payload in payloads {
        let Value::Object(mut object) = payload else {
            return Err(torii_internal_json_error(
                "expected JSON object payload while merging portfolio response",
            ));
        };
        if uaid.is_none() {
            uaid = match object.remove("uaid") {
                Some(Value::String(value)) => Some(value),
                _ => None,
            };
        }
        let rows = match object.remove("dataspaces") {
            Some(Value::Array(rows)) => rows,
            _ => {
                return Err(torii_internal_json_error(
                    "expected `dataspaces` array while merging portfolio response",
                ));
            }
        };
        for row in rows {
            let Some(dataspace_id) = row.get("dataspace_id").and_then(Value::as_u64) else {
                return Err(torii_internal_json_error(
                    "portfolio dataspace rows must include `dataspace_id`",
                ));
            };
            dataspaces.entry(dataspace_id).or_insert(row);
        }
    }
    let mut total_accounts = 0u64;
    let mut total_positions = 0u64;
    for row in dataspaces.values() {
        let account_count = row
            .get("accounts")
            .and_then(Value::as_array)
            .map(|accounts| accounts.len() as u64)
            .unwrap_or(0);
        total_accounts = total_accounts.saturating_add(account_count);
        let position_count = row
            .get("accounts")
            .and_then(Value::as_array)
            .map(|accounts| {
                accounts
                    .iter()
                    .map(|account| {
                        account
                            .get("assets")
                            .and_then(Value::as_array)
                            .map(|assets| assets.len() as u64)
                            .unwrap_or(0)
                    })
                    .sum::<u64>()
            })
            .unwrap_or(0);
        total_positions = total_positions.saturating_add(position_count);
    }
    budget.admit_merge_btree::<String, Value>(2, 5)?;
    budget.admit_merge_allocation(
        "accounts".len() + "positions".len() + "uaid".len() + "totals".len() + "dataspaces".len(),
    )?;
    let mut totals = norito::json::Map::new();
    totals.insert("accounts".into(), Value::from(total_accounts));
    totals.insert("positions".into(), Value::from(total_positions));
    let mut merged_dataspaces = budget.try_merge_vec(dataspaces.len())?;
    merged_dataspaces.extend(dataspaces.into_values());
    let mut root = norito::json::Map::new();
    root.insert("uaid".into(), uaid.map(Value::from).unwrap_or(Value::Null));
    root.insert("totals".into(), Value::Object(totals));
    root.insert("dataspaces".into(), Value::Array(merged_dataspaces));
    let mut response = budget.json_response(&Value::Object(root))?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
#[cfg(feature = "app_api")]
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn merged_dataspace_summary_response(
    payloads: Vec<Value>,
    routed_by: &'static str,
    mut budget: ToriiRoutedReadMemoryBudget,
) -> Result<Response, Response> {
    budget.begin_json_merge();
    let (row_count, account_count, account_bytes) = payloads.iter().try_fold(
        (0_usize, 0_usize, 0_usize),
        |(rows_seen, accounts_seen, account_bytes), payload| {
            if payload
                .get("totals")
                .and_then(Value::as_object)
                .is_some_and(|totals| totals.keys().any(|key| key.starts_with("consensus_")))
            {
                return Err(torii_internal_json_error(
                    "dataspace summaries must not contain retired consensus totals",
                ));
            }
            let rows = payload
                .as_object()
                .and_then(|object| object.get("dataspaces"))
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    torii_internal_json_error(
                        "expected `dataspaces` array while merging dataspace summary response",
                    )
                })?;
            let rows_seen = rows_seen
                .checked_add(rows.len())
                .ok_or_else(torii_routed_read_accounting_response)?;
            let (accounts_seen, account_bytes) = rows.iter().try_fold(
                (accounts_seen, account_bytes),
                |(count, bytes), row| {
                    if row.get("consensus").is_some() {
                        return Err(torii_internal_json_error(
                            "dataspace summary rows must not contain retired consensus commitments",
                        ));
                    }
                    let Some(accounts) = row.get("accounts").and_then(Value::as_array) else {
                        return Ok((count, bytes));
                    };
                    let count = count
                        .checked_add(accounts.len())
                        .ok_or_else(torii_routed_read_accounting_response)?;
                    let bytes = accounts.iter().try_fold(bytes, |bytes, account| {
                        let account = account.as_str().ok_or_else(|| {
                            torii_internal_json_error(
                                "dataspace summary account bindings must be strings",
                            )
                        })?;
                        bytes
                            .checked_add(account.len())
                            .ok_or_else(torii_routed_read_accounting_response)
                    })?;
                    Ok((count, bytes))
                },
            )?;
            Ok((rows_seen, accounts_seen, account_bytes))
        },
    )?;
    budget.admit_merge_btree::<u64, Value>(1, row_count)?;
    budget.admit_merge_btree::<String, ()>(1, account_count)?;
    budget.admit_merge_allocation(account_bytes)?;
    let mut account_literal: Option<String> = None;
    let mut account_id: Option<String> = None;
    let mut uaid: Option<Value> = None;
    let mut dataspaces = BTreeMap::<u64, Value>::new();
    let mut unique_accounts = BTreeSet::<String>::new();
    let mut portfolio_accounts_total = 0u64;
    let mut portfolio_positions_total = 0u64;
    let mut manifests_total = 0u64;
    let mut manifests_active = 0u64;
    for payload in payloads {
        let Value::Object(mut object) = payload else {
            return Err(torii_internal_json_error(
                "expected JSON object payload while merging dataspace summary response",
            ));
        };
        if account_literal.is_none() {
            account_literal = match object.remove("account") {
                Some(Value::String(value)) => Some(value),
                _ => None,
            };
        }
        if account_id.is_none() {
            account_id = match object.remove("account_id") {
                Some(Value::String(value)) => Some(value),
                _ => None,
            };
        }
        if uaid.is_none() {
            uaid = object.remove("uaid");
        }
        let rows = match object.remove("dataspaces") {
            Some(Value::Array(rows)) => rows,
            _ => {
                return Err(torii_internal_json_error(
                    "expected `dataspaces` array while merging dataspace summary response",
                ));
            }
        };
        for row in rows {
            let Some(dataspace_id) = row.get("dataspace_id").and_then(Value::as_u64) else {
                return Err(torii_internal_json_error(
                    "dataspace summary rows must include `dataspace_id`",
                ));
            };
            if let std::collections::btree_map::Entry::Occupied(mut e) =
                dataspaces.entry(dataspace_id)
            {
                e.insert(row);
                continue;
            }
            if let Some(accounts) = row.get("accounts").and_then(Value::as_array) {
                for account in accounts {
                    if let Some(account) = account.as_str() {
                        unique_accounts.insert(account.to_owned());
                    }
                }
            }
            let portfolio = row.get("portfolio").and_then(Value::as_object);
            portfolio_accounts_total = portfolio_accounts_total.saturating_add(
                portfolio
                    .and_then(|portfolio| portfolio.get("accounts"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
            portfolio_positions_total = portfolio_positions_total.saturating_add(
                portfolio
                    .and_then(|portfolio| portfolio.get("positions"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
            let manifest = row.get("manifest").and_then(Value::as_object);
            if manifest
                .and_then(|manifest| manifest.get("present"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                manifests_total = manifests_total.saturating_add(1);
            }
            if manifest
                .and_then(|manifest| manifest.get("active"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                manifests_active = manifests_active.saturating_add(1);
            }
            dataspaces.insert(dataspace_id, row);
        }
    }
    let accounts_bound = unique_accounts.len();
    drop(unique_accounts);
    let fixed_key_bytes = [
        "dataspaces",
        "accounts_bound",
        "portfolio_accounts",
        "portfolio_positions",
        "manifests_total",
        "manifests_active",
        "account",
        "account_id",
        "uaid",
        "totals",
        "dataspaces",
    ]
    .into_iter()
    .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))
    .ok_or_else(torii_routed_read_accounting_response)?;
    budget.admit_merge_btree::<String, Value>(2, 11)?;
    budget.admit_merge_allocation(fixed_key_bytes)?;
    let mut totals = norito::json::Map::new();
    totals.insert("dataspaces".into(), Value::from(dataspaces.len() as u64));
    totals.insert("accounts_bound".into(), Value::from(accounts_bound as u64));
    totals.insert(
        "portfolio_accounts".into(),
        Value::from(portfolio_accounts_total),
    );
    totals.insert(
        "portfolio_positions".into(),
        Value::from(portfolio_positions_total),
    );
    totals.insert("manifests_total".into(), Value::from(manifests_total));
    totals.insert("manifests_active".into(), Value::from(manifests_active));
    let mut merged_dataspaces = budget.try_merge_vec(dataspaces.len())?;
    merged_dataspaces.extend(dataspaces.into_values());
    let mut root = norito::json::Map::new();
    root.insert(
        "account".into(),
        account_literal.map(Value::from).unwrap_or(Value::Null),
    );
    root.insert(
        "account_id".into(),
        account_id.map(Value::from).unwrap_or(Value::Null),
    );
    root.insert("uaid".into(), uaid.unwrap_or(Value::Null));
    root.insert("totals".into(), Value::Object(totals));
    root.insert("dataspaces".into(), Value::Array(merged_dataspaces));
    let mut response = budget.json_response(&Value::Object(root))?;
    insert_routed_by_header(&mut response, routed_by);
    Ok(response)
}
